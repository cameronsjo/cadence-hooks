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
executed, and nothing touches the network.

Hermetic: everything happens in a fresh temp directory with a neutral name,
removed at the end (`--keep` leaves it and prints its path). Setup runs `git`
with no global or system config, hooks off and signing off, under a throwaway
identity. The hooks run with HOME, TMPDIR, the marker and the metrics
directories all inside the temp directory, no inherited `CADENCE_*` or
`CLAUDE_*` variable, and no global or system git config. TMPDIR points at a
subdirectory that holds no repository, because enforce-worktree exempts any
repo under `$TMPDIR` and every row there would prove nothing; for the same
reason the script refuses a temp root under `/tmp` (set TMPDIR to another
directory first).

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
import tempfile
from pathlib import Path

CONFIRM_HOOKS = {"enforce-worktree", "guard-op-vault-scan", "guard-held-close"}
COMMANDS = Path(__file__).resolve().parent / "testdata" / "confirm-tier-commands.txt"
HELD_LEDGER = "cameronsjo/cadence-ecosystem#354 cameronsjo/cadence#107\n"
ORIGIN = "https://github.com/cameronsjo/cadence-ecosystem.git"
# Path components a guard treats specially: `.claude` exempts enforce-worktree,
# `cadence-hooks` exempts the secret guards' content checks.
SPECIAL_COMPONENTS = {".claude", "cadence-hooks"}
SHARED_TMP = ("/tmp", "/private/tmp")
# enforce-worktree's snooze marker and its provenance sidecar, in the common dir.
SNOOZE_PREFIX = "enforce-worktree-snoozed-until"
# No global or system git config reaches setup or the hooks.
GIT_ISOLATION = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
GIT = [
    "git",
    "-c", "core.hooksPath=/dev/null",
    "-c", "commit.gpgsign=false",
    "-c", "tag.gpgsign=false",
    "-c", "user.name=confirm-tier-compare",
    "-c", "user.email=compare@example.invalid",
]


class HarnessError(Exception):
    pass


def git(cwd: Path, *args: str) -> None:
    # An inherited GIT_DIR or GIT_WORK_TREE would point setup at another repo.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | GIT_ISOLATION
    subprocess.run([*GIT, "-C", str(cwd), *args], check=True, capture_output=True, env=env)


def check_root(root: Path) -> None:
    resolved = root.resolve()
    if SPECIAL_COMPONENTS & set(resolved.parts):
        raise HarnessError(f"temp root {resolved} has a path component a guard treats specially")
    text = str(resolved)
    if any(text == r or text.startswith(r + "/") for r in SHARED_TMP):
        raise HarnessError(
            f"temp root {resolved} is under /tmp, which enforce-worktree exempts; "
            "set TMPDIR to another directory"
        )


def setup(root: Path) -> tuple[Path, Path, Path]:
    primary = root / "primary"
    primary.mkdir()
    git(primary, "init", "-q", "-b", "main")
    git(primary, "remote", "add", "origin", ORIGIN)
    (primary / "README.md").write_text("x\n")
    git(primary, "add", "README.md")
    git(primary, "commit", "-q", "-m", "init")
    wt = root / "wt"
    git(primary, "worktree", "add", "-q", "-b", "feat", str(wt))
    ledger = root / "held.txt"
    ledger.write_text(HELD_LEDGER)
    for sub in ("home", "tmpdir"):
        (root / sub).mkdir()
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


def hook_env(root: Path, name: str) -> dict[str, str]:
    keep = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("CADENCE_", "CLAUDE_", "GIT_")) and k not in ("HOME", "TMPDIR")
    }
    return keep | GIT_ISOLATION | {
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmpdir"),
        "CADENCE_MARKER_DIR": str(root / f"markers-{name}"),
        "CADENCE_METRICS_DIR": str(root / f"metrics-{name}"),
    }


def compare(base_bin: str, head_bin: str, root: Path) -> int:
    primary, wt, ledger = setup(root)
    envs = {name: hook_env(root, name) for name in ("base", "head")}
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


def main(argv: list[str]) -> int:
    keep = "--keep" in argv
    args = [a for a in argv if a != "--keep"]
    if len(args) != 2:
        print(__doc__)
        return 2
    base_bin, head_bin = (str(Path(a).resolve()) for a in args)
    for binary in (base_bin, head_bin):
        if not os.access(binary, os.X_OK):
            raise HarnessError(f"{binary} is not an executable (build it first)")
    root = Path(tempfile.mkdtemp(prefix="confirm-tier-compare-"))
    try:
        check_root(root)
        return compare(base_bin, head_bin, root)
    finally:
        if keep:
            print(f"kept {root}", file=sys.stderr)
        else:
            # A cleanup failure must not replace the run's own result.
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (HarnessError, subprocess.CalledProcessError) as e:
        print(f"harness error: {e}", file=sys.stderr)
        sys.exit(2)
