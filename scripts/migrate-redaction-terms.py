#!/usr/bin/env python3
"""Convert the legacy redaction terms .txt into the structured redaction.toml.

One-time migration for the identity tier (cadence-hooks#561). Reads
``~/.config/cadence/redaction-terms.txt`` and writes ``redaction.toml`` beside
it.

Three properties this script exists to guarantee:

1. **Explicit ids.** The legacy format derived a term's "T-code" from its line
   position, so re-sorting the file silently renumbered every term and left
   older issues citing codes that had moved. The emitted TOML carries the
   position-derived code as an authored ``id``, freezing today's numbering as
   the permanent one.

2. **It never prints a term.** Progress output is counts and ids only. A
   migration log that echoes the deny-list defeats the deny-list.

3. **It never deletes the source.** The original stays in place until the new
   file is proven (operator's ruling, 2026-08-03); ``--remove-legacy`` is the
   separate, deliberate second step.

Refuses to overwrite an existing redaction.toml — re-running is safe.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

# Collisions the 2026-08-03 estate sweep proved real: the term is also an
# ordinary English word or an unrelated proper noun in a known context. Keyed by
# the position-derived id. Deliberately a small, reviewed table rather than
# something inferred from the legacy file's free-prose `# allow:` comments —
# those are triage notes for humans, and parsing them into enforcement would be
# guessing at what a sentence meant.
KNOWN_ALLOWS: dict[str, list[dict[str, str]]] = {
    "T8": [{"path": "scripts/test_retrofit_plan_store.py"}],
}


def default_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "cadence"
    return Path.home() / ".config" / "cadence"


def toml_escape(s: str) -> str:
    """Escape for a TOML basic string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def parse_legacy(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (terms, notes).

    ``terms`` is [(id, term)] with the id derived from 1-based position among
    non-comment, non-blank lines — the legacy T-code convention, frozen here.
    ``notes`` collects the file's comment lines so they can ride along as TOML
    comments rather than being silently dropped.
    """
    terms: list[tuple[str, str]] = []
    notes: list[str] = []
    n = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            notes.append(line.lstrip("#").strip())
            continue
        n += 1
        terms.append((f"T{n}", line))
    return terms, notes


def render(terms: list[tuple[str, str]], notes: list[str]) -> str:
    out: list[str] = [
        "# cadence redaction — identity tier term source",
        "#",
        "# Migrated from redaction-terms.txt. Ids are AUTHORED and permanent:",
        "# they were derived from line position once, at migration, and must not",
        "# be renumbered again — existing issues and the leak ledger cite them.",
        "# Adding a term means adding a NEW id, never reusing or shifting one.",
        "#",
        "# mode: 'enforce' (default) blocks; 'warn' only reports.",
        "",
        "version = 1",
        'mode = "enforce"',
        "",
    ]
    if notes:
        out.append("# --- notes carried from the legacy file ---")
        out.extend(f"# {n}" for n in notes)
        out.append("")

    for tid, term in terms:
        out.append("[[terms]]")
        out.append(f'id = "{tid}"')
        out.append(f'term = "{toml_escape(term)}"')
        for allow in KNOWN_ALLOWS.get(tid, []):
            out.append("[[terms.allow]]")
            for k, v in allow.items():
                out.append(f'{k} = "{toml_escape(v)}"')
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-dir", type=Path, default=None)
    ap.add_argument(
        "--remove-legacy",
        action="store_true",
        help="delete the .txt AFTER verifying the .toml parses to the same term count",
    )
    args = ap.parse_args()

    cfg = args.config_dir or default_config_dir()
    legacy = cfg / "redaction-terms.txt"
    target = cfg / "redaction.toml"

    if args.remove_legacy:
        if not target.exists():
            print("FAIL: no redaction.toml to verify against", file=sys.stderr)
            return 1
        if not legacy.exists():
            print("OK: legacy file already gone")
            return 0
        legacy_terms, _ = parse_legacy(legacy)
        # Verify by count, not by content: reading both into memory to diff
        # would be the one place this script holds every term twice.
        body = target.read_text(encoding="utf-8")
        migrated = body.count("[[terms]]")
        if migrated != len(legacy_terms):
            print(
                f"FAIL: term count differs (legacy {len(legacy_terms)}, toml {migrated}) "
                "— not removing anything",
                file=sys.stderr,
            )
            return 1
        legacy.unlink()
        print(f"OK: removed legacy file; {migrated} terms live in redaction.toml")
        return 0

    if not legacy.is_file():
        print(f"FAIL: no legacy file at {legacy}", file=sys.stderr)
        return 1
    if target.exists():
        print(
            f"FAIL: {target} already exists — refusing to overwrite. "
            "Delete it first if you mean to regenerate.",
            file=sys.stderr,
        )
        return 1

    terms, notes = parse_legacy(legacy)
    if not terms:
        print("FAIL: legacy file has no terms", file=sys.stderr)
        return 1

    # Write 0600 from the start — never a window where the file is world-readable.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render(terms, notes))

    allow_count = sum(len(v) for k, v in KNOWN_ALLOWS.items() if any(t == k for t, _ in terms))
    print(f"OK: wrote {target} — {len(terms)} terms, {allow_count} allow entr(ies), mode=enforce")
    print(f"    ids: {', '.join(t for t, _ in terms)}")
    print("    legacy file left in place; verify, then re-run with --remove-legacy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
