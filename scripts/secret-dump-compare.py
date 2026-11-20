#!/usr/bin/env python3
"""Everyday-command comparison for secret value reads (cadence-hooks#1662).

cadence-ecosystem ADR-0046 rule 4: a change to guard code is scored against
everyday commands at head versus a base binary before anything else. This
script runs every Bash command below through the secret hooks on both
binaries and reads each verdict as ALLOW, ASK or BLOCK:

- scripts/testdata/confirm-tier-commands.txt: everyday commands, which must
  not move;
- scripts/testdata/secret-value-commands.txt: secret-value shapes, each
  classed P (the value lands in the output), C (the value goes to a consumer),
  Q (nothing reaches the output) or L (a stated limit: a later or remote
  command the guard does not read prints it), plus A lines that accept a move
  on a named everyday row, each with a one-line reason.

The rules:

1. the only moves allowed are to BLOCK on head, by guard-secret-dump: from ASK
   or ALLOW on a P row, or from ASK on an everyday row an A line names. Any
   other move fails, on any row and any hook, an --extra row included;
2. every P row blocks on head (the change is complete), and every A line
   names an everyday row that moved (no stale acceptance);
3. the run produced at least one move and one ASK on head (a run that could
   not have gone red is not evidence; printed as NOT EVIDENCE).

`--extra FILE` adds one command per line, scored like an everyday row with no
acceptance possible, and reported by shape only (every word but bare flags and
tool names becomes `X`; a short flag keeps only its letter) and with no hook
output on an error: use it for commands taken from session history, which may
name real items.

Hooks only judge a payload; nothing is executed and nothing touches the
network. The hooks run with HOME, TMPDIR and the metrics directory inside a
fresh temp directory and no inherited `CADENCE_*` or `CLAUDE_*` variable.

Usage, from the repository root:

    python3 -I scripts/secret-dump-compare.py BASE_BINARY HEAD_BINARY [--extra FILE]

Exit status: 0 when the rules hold; 1 when one fails; 2 on a harness error.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVERYDAY = HERE / "testdata" / "confirm-tier-commands.txt"
SHAPES = HERE / "testdata" / "secret-value-commands.txt"
HOOKS = [
    ["cadence", "guard-secret-dump"],
    ["cadence", "prevent-secret-leaks"],
    ["guardrails", "guard-op-vault-scan"],
    ["guardrails", "guard-sops-decrypt"],
]
MOVING_HOOK = "guard-secret-dump"
CLASSES = {"P", "C", "Q", "L"}
ACCEPT = "A"
REASON = " ## "
# Flags shape() keeps verbatim: one short letter, or a long name of letters and
# dashes. A longer single-dash word may carry a glued value (`-uadmin`).
FLAG = re.compile(r"-[A-Za-z]|--[A-Za-z][A-Za-z-]*")


class HarnessError(Exception):
    pass


def rows(path: Path, classed: bool) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not classed:
            out.append(("E", line))
            continue
        cls, _, command = line.partition(" ")
        if cls == ACCEPT:
            continue
        if cls not in CLASSES or not command:
            raise HarnessError(f"unclassed row in {path.name}: {line!r}")
        # `⏎` spells a newline, so a classed row can hold a heredoc.
        out.append((cls, command.replace("⏎", "\n")))
    return out


def accepted(path: Path) -> dict[str, str]:
    """The A lines: everyday command -> its one-line reason."""
    out = {}
    for line in path.read_text().splitlines():
        cls, _, rest = line.partition(" ")
        if cls != ACCEPT:
            continue
        command, sep, reason = rest.partition(REASON)
        if not sep or not command.strip() or not reason.strip():
            raise HarnessError(f"A line needs `<command>{REASON}<reason>`: {line!r}")
        out[command.strip()] = reason.strip()
    return out


def verdict(
    binary: str, hook: list[str], command: str, cwd: Path, env: dict[str, str], private: bool
) -> str:
    payload = {
        "session_id": "secret-dump-compare",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }
    p = subprocess.run(
        [binary, *hook],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=60,
    )
    if p.returncode == 2:
        return "BLOCK"
    # A hook's own text can quote the command, so an --extra row's error
    # carries no output at all.
    if p.returncode != 0:
        detail = "(hidden for an --extra row)" if private else repr(p.stderr[:300])
        raise HarnessError(f"exit {p.returncode} from {hook}: {detail}")
    out = p.stdout.decode(errors="replace").strip()
    if not out:
        return "ALLOW"
    try:
        decision = json.loads(out).get("hookSpecificOutput", {}).get("permissionDecision")
    except json.JSONDecodeError as e:
        detail = "(hidden for an --extra row)" if private else repr(out[:200])
        raise HarnessError(f"non-JSON stdout from {hook}: {detail}") from e
    return "ASK" if decision == "ask" else "ALLOW"


def shape(command: str) -> str:
    """A command with every word that is not a flag or a shell operator
    replaced by `X`, so a row from session history can be read for its shape
    without its item names or values."""
    keep = {"op", "read", "item", "get", "security", "echo", "printf", "eval", "sh", "bash"}
    out = []
    for word in command.split():
        bare = word.strip("\"'`$()")
        password_read = bare.startswith("find-") and bare.endswith("-password")
        if not any(c.isalnum() for c in word) or password_read or bare in keep:
            out.append(word)
        elif FLAG.fullmatch(word):
            out.append(word)
        elif word.startswith("--"):
            out.append("--X")
        elif word.startswith("-") and len(word) > 1:
            # A short flag with its value glued on (`-pHunter2`): keep the flag.
            out.append(word[:2] + "X")
        else:
            out.append("X")
    return " ".join(out)


def hook_env(root: Path, name: str) -> dict[str, str]:
    keep = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("CADENCE_", "CLAUDE_")) and k not in ("HOME", "TMPDIR")
    }
    for sub in ("home", "tmpdir", f"metrics-{name}"):
        (root / sub).mkdir(exist_ok=True)
    return keep | {
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmpdir"),
        "CADENCE_METRICS_DIR": str(root / f"metrics-{name}"),
    }


def compare(base_bin: str, head_bin: str, extra: Path | None, root: Path) -> int:
    work = root / "work"
    work.mkdir()
    corpus = rows(EVERYDAY, False) + rows(SHAPES, True)
    if extra is not None:
        corpus += [("X", c) for _, c in rows(extra, False)]
    accepts = accepted(SHAPES)
    envs = {name: hook_env(root, name) for name in ("base", "head")}
    counts: dict[str, int] = {}
    failures: list[str] = []
    moved: list[str] = []
    passed_to_block: list[str] = []
    accepted_moves: list[str] = []
    used_accepts: set[str] = set()
    head_asks = 0
    for n, (cls, command) in enumerate(corpus, 1):
        shown = f"extra row {n}" if cls == "X" else command
        for hook in HOOKS:
            b = verdict(base_bin, hook, command, work, envs["base"], cls == "X")
            h = verdict(head_bin, hook, command, work, envs["head"], cls == "X")
            counts[cls] = counts.get(cls, 0) + 1
            head_asks += h == "ASK"
            name = hook[1]
            if cls == "P" and name == MOVING_HOOK and h != "BLOCK":
                failures.append(f"P row does not block on head ({h}): {shown}")
            if b == h:
                continue
            line = f"{name}: {b} -> {h} [{cls}] {shown if cls != 'X' else shape(command)}"
            if (cls, name, b, h) == ("P", MOVING_HOOK, "ASK", "BLOCK"):
                moved.append(line)
            elif (cls, name, b, h) == ("P", MOVING_HOOK, "ALLOW", "BLOCK"):
                passed_to_block.append(line)
            elif cls == "E" and command in accepts and (name, b, h) == (MOVING_HOOK, "ASK", "BLOCK"):
                used_accepts.add(command)
                accepted_moves.append(f"{line}  ({accepts[command]})")
            else:
                failures.append(f"unwanted move: {line}")
    for command in sorted(set(accepts) - used_accepts):
        failures.append(f"A line names a row that did not move: {command}")
    rows_by_class = {cls: counts[cls] // len(HOOKS) for cls in sorted(counts)}
    print(f"rows by class: {rows_by_class} x {len(HOOKS)} hooks")
    for title, lines in (
        ("ASK -> BLOCK on printed rows", moved),
        ("ALLOW -> BLOCK on printed rows", passed_to_block),
        ("accepted moves on everyday rows", accepted_moves),
    ):
        print(f"{title} ({len(lines)}):")
        for line in lines:
            print(f"  {line}")
    if failures:
        print(f"FAILED ({len(failures)}):")
        for line in failures:
            print(f"  {line}")
        return 1
    if not (moved or passed_to_block) or not head_asks:
        print("NOT EVIDENCE: no move to BLOCK, or no ASK left on head")
        return 1
    if accepted_moves:
        print(
            "OK: every move is to BLOCK by guard-secret-dump, on a printed-value row "
            f"or one of {len(accepted_moves)} accepted everyday rows"
        )
    else:
        print("OK: every move is to BLOCK by guard-secret-dump on a printed-value row")
    return 0


def main(argv: list[str]) -> int:
    extra = None
    if "--extra" in argv:
        i = argv.index("--extra")
        if i + 1 >= len(argv):
            print(__doc__)
            return 2
        extra = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2 :]
    if len(argv) != 2:
        print(__doc__)
        return 2
    base_bin, head_bin = (str(Path(a).resolve()) for a in argv)
    for binary in (base_bin, head_bin):
        if not os.access(binary, os.X_OK):
            raise HarnessError(f"{binary} is not an executable (build it first)")
    root = Path(tempfile.mkdtemp(prefix="secret-dump-compare-"))
    try:
        return compare(base_bin, head_bin, extra, root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (HarnessError, subprocess.TimeoutExpired) as e:
        print(f"harness error: {e}", file=sys.stderr)
        sys.exit(2)
