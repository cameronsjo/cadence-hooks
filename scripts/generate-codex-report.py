#!/usr/bin/env python3
"""Join the binary registry, compatibility policy, plugin hooks, and evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "codex-compatibility.json"
DEFAULT_OUTPUT = ROOT / "docs" / "codex-compatibility-report.json"


def command_ref(command: str) -> tuple[str, str] | None:
    match = re.search(
        r"run-cadence-hooks\.sh(?:\\?\"|\s)+\s*([a-z-]+)\s+([a-z0-9-]+)",
        command,
    )
    if not match:
        if "obsidian-trash-guard.sh" in command:
            return "obsidian", "trash-guard"
        return None
    return match.group(1), match.group(2)


def plugin_wiring(workspace: Path) -> dict[tuple[str, str], list[dict]]:
    wiring: dict[tuple[str, str], list[dict]] = {}
    for path in sorted((workspace / "cadence" / "plugins").glob("*/hooks/hooks.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        plugin = path.parents[1].name
        for event, groups in payload.get("hooks", {}).items():
            for group in groups:
                for hook in group.get("hooks", []):
                    command = hook.get("command", "")
                    ref = command_ref(command)
                    if not ref:
                        continue
                    wiring.setdefault(ref, []).append(
                        {
                            "plugin": plugin,
                            "event": event,
                            "matcher": group.get("matcher", "*"),
                            "if": hook.get("if"),
                            "commandHash": hashlib.sha256(
                                command.encode("utf-8")
                            ).hexdigest(),
                        }
                    )
    return wiring


def build(binary: Path, workspace: Path) -> dict:
    if not binary.is_file():
        raise SystemExit(
            f"cadence-hooks binary not found at {binary}; run `cargo build` first"
        )
    try:
        completed = subprocess.run(
            [str(binary), "manifest", "--format", "json"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            f"`{binary} manifest --format json` failed with status {error.returncode}"
        ) from error
    except OSError as error:
        raise SystemExit(
            f"could not execute cadence-hooks binary at {binary}: {error}"
        ) from error
    registry = json.loads(completed.stdout)
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    wiring = plugin_wiring(workspace)
    hooks = []
    for row in registry["hooks"]:
        override = policy["hookOverrides"].get(row["name"], {})
        hooks.append(
            {
                **row,
                "status": override.get("status", policy["defaultHookStatus"]),
                "applicable": override.get("applicable", True),
                "evidence": override.get("evidence", "tests/hook_registration_audit.rs"),
                "wiring": wiring.get((row["plugin"], row["name"]), []),
            }
        )
    return {
        "schemaVersion": 1,
        "binaryVersion": registry["binaryVersion"],
        "minimumCodexVersion": policy["minimumCodexVersion"],
        "privacy": {
            "rawHookInputsPersisted": False,
            "commandBodiesPersisted": False,
            "diagnosticFields": ["schema identifiers", "field names", "sha256 hashes"],
        },
        "capabilities": policy["capabilities"],
        "hooks": hooks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "target" / "debug" / "cadence-hooks"
    )
    parser.add_argument(
        "--workspace", type=Path, default=ROOT.parent
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--stdout", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(
        build(args.binary.resolve(), args.workspace.resolve()),
        indent=2,
        ensure_ascii=False,
    ) + "\n"
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != rendered:
            print("Codex compatibility report is stale", file=sys.stderr)
            return 1
        return 0
    if args.stdout:
        print(rendered, end="")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
