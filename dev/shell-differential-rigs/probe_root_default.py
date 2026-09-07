#!/usr/bin/env python3
"""Positive-control probe for cadence#667 site 1: reconstruct-journey.py's
--root default. Points CLAUDE_CONFIG_DIR at a temp dir with a fake transcript,
and HOME at a DIFFERENT temp dir with no transcript there. If --root's default
resolves via CLAUDE_CONFIG_DIR, the transcript is found (exit 0). If it
hardcodes ~/.claude, it is not found (exit 2) even though the transcript
genuinely exists under the resolved config dir.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = "$HOME/wt/wt-cad667/plugins/cadence/skills/outro/scripts/reconstruct-journey.py"

with tempfile.TemporaryDirectory() as fake_home, tempfile.TemporaryDirectory() as fake_cfg:
    cwd = "/Users/probe/project"
    sid = "00000000-0000-0000-0000-0000000000ab"
    slug = cwd.replace("/", "-").replace(".", "-")
    transcript_dir = Path(fake_cfg) / "projects" / slug
    transcript_dir.mkdir(parents=True)
    transcript = transcript_dir / f"{sid}.jsonl"
    transcript.write_text(
        '{"timestamp":"2026-07-27T10:00:00Z","cwd":"%s","sessionId":"%s"}\n' % (cwd, sid),
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["HOME"] = fake_home  # $HOME/.claude/projects has NOTHING under it
    env["CLAUDE_CONFIG_DIR"] = fake_cfg  # the transcript genuinely lives here
    env.pop("CADENCE_METRICS_DIR", None)

    proc = subprocess.run(
        [sys.executable, SCRIPT, "--session-id", sid, "--cwd", cwd, "--no-chain"],
        env=env, capture_output=True, text=True,
    )
    print("exit code:", proc.returncode)
    print("--- stderr ---")
    print(proc.stderr)
    if proc.returncode == 0:
        print("RESULT: transcript FOUND via CLAUDE_CONFIG_DIR resolution (fix present)")
    else:
        print("RESULT: transcript NOT found — --root defaulted to the wrong location (bug present)")
