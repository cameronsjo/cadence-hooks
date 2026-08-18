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


def _without_wiring(text: str) -> str:
    """The report with every `wiring` array dropped, for comparison only.

    Returns the input unchanged when it does not parse, so a corrupt
    checked-in report still fails the comparison rather than passing it.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return text
    for hook in doc.get("hooks", []):
        hook.pop("wiring", None)
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _wiring_is_empty(text: str) -> bool:
    """True when every hook in `text` renders an empty `wiring` array.

    The check exemption below rests on a claim — "this run could not determine
    wiring, so wiring is the one field it must not compare". The normal-write
    guard uses the same rendered-output fact to prevent an absent or unusable
    plugin estate from replacing known wiring with empty arrays. Unparsable
    output is not empty wiring either.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return False
    return all(not hook.get("wiring") for hook in doc.get("hooks", []))


def _plugins_with_wiring(text: str) -> set[str]:
    """The set of plugin names carrying at least one wiring entry in `text`.

    Unparsable text returns an empty set, so the shortfall-guard comparison
    that consumes this simply skips (fail-open per ADR-0001) rather than
    treating a corrupt render as a wipe of every plugin's wiring.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return set()
    plugins: set[str] = set()
    for hook in doc.get("hooks", []):
        for entry in hook.get("wiring", []):
            plugin = entry.get("plugin")
            if plugin:
                plugins.add(plugin)
    return plugins


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
    parser.add_argument(
        "--retired-plugin",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Plugin name to exempt from the partial-wipe shortfall check "
            "(repeatable) — the escape hatch for a genuinely retired plugin "
            "whose wiring is expected to disappear."
        ),
    )
    args = parser.parse_args()
    rendered = json.dumps(
        build(args.binary.resolve(), args.workspace.resolve()),
        indent=2,
        ensure_ascii=False,
    ) + "\n"
    if args.check:
        if not args.output.exists():
            print("Codex compatibility report is missing", file=sys.stderr)
            return 1
        checked_in = args.output.read_text(encoding="utf-8")
        if checked_in == rendered:
            return 0
        # `wiring` is derived from the plugin repo's hooks.json files, which live
        # in a SEPARATE, private checkout beside this one. CI has no sibling, so
        # plugin_wiring() legitimately comes back empty there and every wiring
        # array renders as []. Comparing those would fail by construction on
        # every CI run and say "stale", which reads as a drifted report rather
        # than an absent input. So when the workspace is unavailable, compare
        # everything the binary itself determines — statuses, evidence,
        # capabilities, the hook set — and exempt only the field CI cannot know.
        # The directory test says the input was absent; `_wiring_is_empty` says
        # this run produced nothing for the field. Both must hold, so a RENDERED
        # wiring array cannot ride through the exemption.
        #
        # Today the second test cannot fail when the first passes:
        # plugin_wiring() globs the same directory the first test checks, so an
        # absent sibling makes empty wiring a certainty. It is kept as a
        # drift-guard — if those two path computations ever diverge (a refactor,
        # a different glob root), the exemption stops applying instead of
        # silently widening.
        #
        # What this does NOT buy: a hand-edited `wiring` in the CHECKED-IN report
        # still passes on CI, because CI has no sibling to compare it against.
        # That gap is structural — the plugin repo is private — and the success
        # message says so rather than implying the field was verified.
        if (
            not (args.workspace.resolve() / "cadence" / "plugins").is_dir()
            and _wiring_is_empty(rendered)
        ):
            if _without_wiring(checked_in) == _without_wiring(rendered):
                print(
                    "Codex compatibility report is fresh "
                    "(wiring unverified: no plugin checkout beside this repo)",
                    file=sys.stderr,
                )
                return 0
        print("Codex compatibility report is stale", file=sys.stderr)
        return 1
    if args.stdout:
        print(rendered, end="")
        return 0
    if _wiring_is_empty(rendered):
        plugins_path = args.workspace.resolve() / "cadence" / "plugins"
        print(
            "Codex compatibility report not written: "
            f"no recognized plugin wiring rendered from {plugins_path}; "
            "pass --workspace with a workspace containing cadence/plugins",
            file=sys.stderr,
        )
        return 1
    if args.output.exists():
        checked_in = args.output.read_text(encoding="utf-8")
        missing = (
            _plugins_with_wiring(checked_in)
            - _plugins_with_wiring(rendered)
            - set(args.retired_plugin)
        )
        if missing:
            print(
                "Codex compatibility report not written: "
                f"{', '.join(sorted(missing))} had wiring in the checked-in report "
                "but none in this render; pass --retired-plugin NAME for each "
                "plugin genuinely retired, or fix the workspace/plugin checkout",
                file=sys.stderr,
            )
            return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
