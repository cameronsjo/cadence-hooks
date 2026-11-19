#!/usr/bin/env python3
"""Everyday-command comparison for the confirm tier (cadence-hooks#1658).

cadence-ecosystem ADR-0046 rule 4: a change to guard code is scored against
everyday commands at head versus a base binary before anything else. This
script runs every payload through the touched hooks on both binaries, as two
tool calls of one session per binary, and holds two rules:

- first attempt: base and head agree on every row (any move either way fails);
- second attempt: the only move allowed is BLOCK on base to ALLOW on head, on
  a row the base also blocked first time, and only for the confirm-tier
  guards (enforce-worktree, guard-op-vault-scan, guard-held-close).

The payloads are the Bash commands in scripts/testdata/confirm-tier-commands.txt
(each run from a primary checkout and from a linked worktree) plus Edit and
Write calls on a fixed set of paths. Hooks only judge a payload; nothing is
executed, and nothing touches the network. The script builds its own scratch
repository (a primary checkout and one linked worktree) in WORKDIR (default
~/.cache/cadence-hooks/confirm-tier-compare). It deletes and recreates WORKDIR
only when WORKDIR is new or holds the `.confirm-tier-compare` sentinel an
earlier run wrote; any other existing directory is refused. WORKDIR must not
sit under a temp root or a `.claude` directory: enforce-worktree exempts both,
so every row there would be an allow on both binaries and prove nothing.

Usage, from the repository root:

    git worktree add ../cadence-hooks-base origin/main
    cargo build --bin cadence-hooks --manifest-path ../cadence-hooks-base/Cargo.toml
    cargo build --bin cadence-hooks
    python3 -I scripts/confirm-tier-compare.py \\
        ../cadence-hooks-base/target/debug/cadence-hooks target/debug/cadence-hooks

Exit status: 0 when both rules hold; 1 when one fails, or when the run
produced no block or no confirmed pass (printed as NOT EVIDENCE); 2 on a
harness error.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

CONFIRM_HOOKS = {"enforce-worktree", "guard-op-vault-scan", "guard-held-close"}
COMMANDS = Path(__file__).resolve().parent / "testdata" / "confirm-tier-commands.txt"
DEFAULT_WORKDIR = Path.home() / ".cache" / "cadence-hooks" / "confirm-tier-compare"
HELD_LEDGER = "cameronsjo/cadence-ecosystem#354 cameronsjo/cadence#107\n"
ORIGIN = "https://github.com/cameronsjo/cadence-ecosystem.git"
EXEMPT_ROOTS = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
SENTINEL = ".confirm-tier-compare"
# enforce-worktree's snooze marker and its provenance sidecar, in the common dir.
SNOOZE_PREFIX = "enforce-worktree-snoozed-until"


class HarnessError(Exception):
    pass


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def check_workdir(work: Path) -> None:
    resolved = str(work.resolve())
    tmpdir = os.environ.get("TMPDIR", "").rstrip("/")
    roots = EXEMPT_ROOTS + ((tmpdir,) if tmpdir else ())
    if any(resolved == r or resolved.startswith(r + "/") for r in roots):
        raise HarnessError(f"WORKDIR {resolved} is under a temp root, which enforce-worktree exempts")
    if ".claude" in work.resolve().parts:
        raise HarnessError(f"WORKDIR {resolved} is under a .claude directory, which enforce-worktree exempts")


def setup(work: Path) -> tuple[Path, Path, Path]:
    # Delete only a directory this script made: one that holds its sentinel.
    if work.exists():
        if not (work / SENTINEL).is_file():
            raise HarnessError(
                f"WORKDIR {work} exists and was not made by this script (no {SENTINEL}); "
                "pass a new path or remove it yourself"
            )
        shutil.rmtree(work)
    work.mkdir(parents=True)
    (work / SENTINEL).write_text("scratch dir of scripts/confirm-tier-compare.py\n")
    primary = work / "primary"
    primary.mkdir()
    git(primary, "init", "-q", "-b", "main")
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    git(primary, "remote", "add", "origin", ORIGIN)
    (primary / "README.md").write_text("x\n")
    git(primary, "add", "README.md")
    git(primary, "commit", "-q", "-m", "init")
    wt = work / "wt"
    git(primary, "worktree", "add", "-q", "-b", "feat", str(wt))
    ledger = work / "held.txt"
    ledger.write_text(HELD_LEDGER)
    return primary, wt, ledger


def commands() -> list[str]:
    lines = COMMANDS.read_text().splitlines()
    return [line for line in lines if line.strip() and not line.startswith("#")]


def edits(primary: Path, wt: Path) -> list[tuple[Path, str, dict[str, str]]]:
    targets = (
        primary / "src.rs",
        primary / "README.md",
        primary / ".claude" / "notes.md",
        primary / "docs" / "plans" / "p.md",
        wt / "src.rs",
        wt / "README.md",
        primary / ".env",
        wt / "config.toml",
    )
    out = []
    for cwd in (primary, wt):
        for target in targets:
            for tool in ("Edit", "Write"):
                ti = {"file_path": str(target)}
                if tool == "Edit":
                    ti.update({"old_string": "x", "new_string": "y"})
                else:
                    ti["content"] = "y\n"
                out.append((cwd, tool, ti))
    return out


def verdict(binary: str, hook_args: list[str], payload: dict, env: dict[str, str]) -> str:
    p = subprocess.run(
        [binary, *hook_args],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
        timeout=60,
    )
    if p.returncode not in (0, 2):
        raise HarnessError(f"exit {p.returncode} from {binary} {hook_args}: {p.stderr[:300]!r}")
    return "BLOCK" if p.returncode == 2 else "ALLOW"


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    base_bin, head_bin = argv[0], argv[1]
    work = Path(argv[2]) if len(argv) == 3 else DEFAULT_WORKDIR
    for binary in (base_bin, head_bin):
        if not os.access(binary, os.X_OK):
            raise HarnessError(f"{binary} is not an executable (build it first)")
    check_workdir(work)
    primary, wt, ledger = setup(work)
    # No inherited CADENCE_* switch may exempt a guard, and every marker and
    # ledger row lands in the scratch dir, never the real metrics.
    clean = {k: v for k, v in os.environ.items() if not k.startswith("CADENCE_")}
    envs = {
        name: clean
        | {
            "CADENCE_MARKER_DIR": str(work / f"markers-{name}"),
            "CADENCE_METRICS_DIR": str(work / f"metrics-{name}"),
        }
        for name in ("base", "head")
    }
    bash_hooks = [
        ("enforce-worktree", ["guardrails", "enforce-worktree"]),
        ("guard-op-vault-scan", ["guardrails", "guard-op-vault-scan"]),
        ("guard-held-close", ["cadence", "guard-held-close", "--ledger", str(ledger)]),
        ("git-safety", ["cadence", "git-safety"]),
        ("prevent-secret-writes", ["cadence", "prevent-secret-writes"]),
    ]
    edit_hooks = [bash_hooks[0], bash_hooks[4]]
    cases = [(cwd, "Bash", {"command": c}, bash_hooks) for cwd in (primary, wt) for c in commands()]
    cases += [(cwd, tool, ti, edit_hooks) for cwd, tool, ti in edits(primary, wt)]

    rows = blocks_on_base = 0
    first_moves: list[str] = []
    confirm_passes: list[str] = []
    other_moves: list[str] = []
    snooze_dir = primary / ".git" / "cadence-hooks"
    for i, (cwd, tool, ti, hooks) in enumerate(cases):
        for hook, args in hooks:
            rows += 1
            verdicts = {}
            for name, binary in (("base", base_bin), ("head", head_bin)):
                session = f"cmp-{i}-{hook}"
                verdicts[name] = [
                    verdict(
                        binary,
                        args,
                        {
                            "hook_event_name": "PreToolUse",
                            "session_id": session,
                            "tool_use_id": f"{session}-{call}",
                            "tool_name": tool,
                            "tool_input": ti,
                            "cwd": str(cwd),
                        },
                        envs[name],
                    )
                    for call in ("call-1", "call-2")
                ]
                # A confirmed enforce-worktree pass arms the checkout-wide
                # snooze, which the next run would read: clear it every time.
                for snooze in snooze_dir.glob(f"{SNOOZE_PREFIX}*"):
                    snooze.unlink()
            (b1, b2), (h1, h2) = verdicts["base"], verdicts["head"]
            label = f"{hook} | {tool} | {ti.get('command', ti.get('file_path'))} | cwd={cwd.name}"
            blocks_on_base += b1 == "BLOCK"
            if b1 != h1:
                first_moves.append(f"{b1}->{h1}  {label}")
            if b2 != h2:
                move = f"{b2}->{h2}  {label}"
                confirmed = (b1, b2, h2) == ("BLOCK", "BLOCK", "ALLOW") and hook in CONFIRM_HOOKS
                (confirm_passes if confirmed else other_moves).append(move)

    print(f"cases={len(cases)} rows={rows} blocks_on_base_first_attempt={blocks_on_base}")
    for title, moves in (
        ("first-attempt moves", first_moves),
        ("second-attempt BLOCK->ALLOW on a confirm-tier guard", confirm_passes),
        ("second-attempt moves outside that", other_moves),
    ):
        print(f"{title}: {len(moves)}")
        for move in moves:
            print("  " + move)
    if blocks_on_base == 0 or not confirm_passes:
        print("NOT EVIDENCE: the run produced no block or no confirmed pass")
        return 1
    return 0 if not first_moves and not other_moves else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (HarnessError, subprocess.CalledProcessError) as e:
        print(f"harness error: {e}", file=sys.stderr)
        sys.exit(2)
