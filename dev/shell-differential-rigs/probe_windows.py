#!/usr/bin/env python3
"""Probe Windows/escaped git spellings against enforce-worktree from a real primary."""
import glob, json, os, subprocess

PRIMARY = sorted(glob.glob("$HOME/wt/ch-diff-fixtures/run-*/primary"))[-1]
BIN = "$HOME/wt/wt-ch-pr1/target/debug/cadence-hooks"
STRIP = ["CADENCE_ALLOW_MAIN", "CADENCE_NO_ENFORCE_WORKTREE", "CADENCE_BYPASS",
         "CADENCE_KILL_SWITCH", "CADENCE_DISABLE"]

cases = [
    "git commit -m x",                                     # positive control
    "git.exe commit -m x",
    "C:/tools/git.exe commit -m x",
    "C:\\tools\\git.exe commit -m x",
    "/c/git/cmd/git.exe commit -m x",
    '"/c/Program Files/Git/cmd/git.exe" commit -m x',
    "/c/Program\\ Files/Git/cmd/git.exe commit -m x",
    "\\npm install",
    "\\cargo add serde",
    "\\sed -i '' s/a/b/ f.txt",
]
env = {k: v for k, v in os.environ.items() if k not in STRIP}
for c in cases:
    payload = {"tool_name": "Bash", "tool_input": {"command": c}, "cwd": PRIMARY}
    r = subprocess.run([BIN, "guardrails", "enforce-worktree"],
                       input=json.dumps(payload), capture_output=True, text=True, env=env)
    out = (r.stdout + r.stderr).strip()
    kind = "BLOCK" if r.returncode == 2 else ("NUDGE" if out else "ALLOW")
    print(f"{c:52} => {kind}")
