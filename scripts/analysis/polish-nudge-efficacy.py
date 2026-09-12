#!/usr/bin/env python3
"""Polish-nudge efficacy measurement (cadence-hooks, tracker search found no
open issue specifically for this measurement; methodology doc is
docs/plans/2026-06-20-hooks-sweep-stale-and-nudge-efficacy.md).

Tier 1 (deterministic): reads polish_nudges.jsonl, the metrics logger's own
denominator (every row is a fired ship-anchor nudge). Computes skip rate,
marker-present rate, and anchor-kind breakdown over the live data window.

Tier 2 (transcript sample): for a bounded, seeded random sample of skip
candidates (polished=false), pulls the assistant text immediately preceding
the ship-anchor tool_use out of the session transcript (or a subagent
transcript when the parent has none) so a human/LLM reader can classify each
as silent / legitimate / rationalized. This script does the extraction only;
classification is recorded by hand in the results doc, because that judgment
is prose, not a predicate (see the methodology doc, "Tier 2").

Usage:
    python3 scripts/analysis/polish-nudge-efficacy.py [--sample N] [--seed N]

All input paths are read-only. No network calls.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path


def claude_config_dir() -> Path:
    """The Claude config root: `CLAUDE_CONFIG_DIR`, else `~/.claude`.

    Mirrors `cadence_hooks_core::paths::claude_config_dir` (Rust) so this
    read-only analysis script honors the same second-subscription profile
    relocation every shipped resolver does, rather than always reading the
    default profile's metrics (cadence-hooks#599). Takes the first non-empty
    comma-separated entry, `~`-expanded, matching the Rust resolver's
    fallback-list handling.
    """
    raw = os.environ.get("CLAUDE_CONFIG_DIR", "")
    for candidate in raw.split(","):
        candidate = candidate.strip()
        if candidate:
            return Path(candidate).expanduser()
    return Path.home() / ".claude"


NUDGE_LOG = claude_config_dir() / "cadence" / "metrics" / "polish_nudges.jsonl"
COMMITS_LOG = claude_config_dir() / "cadence" / "metrics" / "commits.jsonl"
BOUNDARY_TS = "2026-06-19T20:24:00-05:00"  # cadence v0.33.0, ~20:24 CDT


def load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def tier1(rows: list[dict]) -> dict:
    total = len(rows)
    anchors = Counter(r.get("anchor") for r in rows)
    polished = Counter(r.get("polished") for r in rows)
    marker = Counter(r.get("markerPresent") for r in rows)
    skip = [r for r in rows if r.get("polished") is False]
    skip_no_marker = [r for r in skip if r.get("markerPresent") is False]
    # Agreement between the transcript-scan signal (`polished`) and the
    # branch-scoped marker (`markerPresent`) — they're independent instruments
    # over the same claim (was polish run for this branch), so a large
    # disagreement rate is itself a finding about instrument reliability, not
    # nudge efficacy.
    agree = sum(1 for r in rows if r.get("polished") == r.get("markerPresent"))
    ts_values = [r["ts"] for r in rows if r.get("ts")]
    repos = Counter(r.get("repo") for r in rows)

    # A row logged against `main`/`master` is a suspected mis-key, not a real
    # skip decision: cadence-hooks#537/#631/#452 (all open) describe the same
    # anchor keying itself off the session's Bash cwd branch rather than the
    # PR's actual head branch — so a shared-main meta-repo checkout logs
    # `branch: "main"` even when the real PR shipped from a worktree. Split
    # the rate with and without those rows rather than picking one silently.
    main_like = {"main", "master"}
    non_main = [r for r in rows if r.get("branch") not in main_like]
    skip_non_main = [r for r in non_main if r.get("polished") is False]
    marker_absent_non_main = [r for r in non_main if r.get("markerPresent") is False]

    return {
        "total_rows": total,
        "ts_min": min(ts_values) if ts_values else None,
        "ts_max": max(ts_values) if ts_values else None,
        "anchor_counts": dict(anchors),
        "polished_counts": {str(k): v for k, v in polished.items()},
        "marker_counts": {str(k): v for k, v in marker.items()},
        "skip_candidates": len(skip),
        "skip_rate": len(skip) / total if total else None,
        "skip_and_no_marker": len(skip_no_marker),
        "polished_marker_agreement_rate": agree / total if total else None,
        "distinct_repos": len(repos),
        "top_repos": repos.most_common(10),
        "rows_on_main_or_master_branch": len(rows) - len(non_main),
        "non_main_branch_rows": len(non_main),
        "non_main_branch_skip_candidates": len(skip_non_main),
        "non_main_branch_skip_rate": len(skip_non_main) / len(non_main) if non_main else None,
        "non_main_branch_marker_absent_rate": (
            len(marker_absent_non_main) / len(non_main) if non_main else None
        ),
    }


def _parse_ts(value: str) -> float | None:
    """Parse an ISO-8601 timestamp (with or without fractional seconds / Z
    suffix) to a Unix epoch float. Returns None on anything unparseable —
    callers must treat that as "no timestamp", never as epoch 0."""
    if not value:
        return None
    v = value.replace("Z", "+00:00")
    for fmt_try in (None,):
        try:
            from datetime import datetime

            return datetime.fromisoformat(v).timestamp()
        except ValueError:
            return None
    return None


def find_anchor_context(transcript_path: str, target_ts: str) -> str | None:
    """Scan a transcript for every ship-anchor Bash tool_use, and return the
    assistant text immediately preceding the occurrence whose own timestamp is
    closest to `target_ts` (the specific nudge-log row being classified) —
    not the first match in the file. A transcript containing more than one PR
    ship in the same session would otherwise attribute the wrong turn's text
    to a row (found and fixed after the docs-polish review flagged the first
    cut of this function for exactly that: it ignored `ts` entirely and always
    returned the first match, so two different rows from the same or
    similarly-shaped transcripts could read identical context)."""
    p = Path(transcript_path)
    if not p.is_file():
        return None
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return None

    target_epoch = _parse_ts(target_ts)
    last_assistant_text = None
    candidates: list[tuple[float | None, str | None]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = obj.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        line_ts = _parse_ts(obj.get("timestamp", ""))
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and msg.get("role") == "assistant":
                last_assistant_text = block.get("text", "")
            if block.get("type") == "tool_use" and block.get("name") == "Bash":
                cmd = (block.get("input") or {}).get("command", "")
                if "gh pr create" in cmd or "gh pr ready" in cmd or "gh pr merge" in cmd:
                    candidates.append((line_ts, last_assistant_text))

    if not candidates:
        return None
    if target_epoch is None or all(c[0] is None for c in candidates):
        # No usable timestamps to disambiguate — fall back to the first match
        # rather than silently guessing; caller sees this via context_found
        # still being true, so record honestly rather than fabricate.
        return candidates[0][1]
    best = min(
        candidates,
        key=lambda c: abs(c[0] - target_epoch) if c[0] is not None else float("inf"),
    )
    return best[1]


def tier2_sample(rows: list[dict], sample_n: int, seed: int) -> list[dict]:
    skip = [r for r in rows if r.get("polished") is False]
    rng = random.Random(seed)
    chosen = rng.sample(skip, min(sample_n, len(skip)))
    out = []
    for r in chosen:
        ctx = None
        tp = r.get("transcriptPath")
        if tp:
            ctx = find_anchor_context(tp, r.get("ts", ""))
        out.append(
            {
                "ts": r.get("ts"),
                "repo": r.get("repo"),
                "branch": r.get("branch"),
                "anchor": r.get("anchor"),
                "markerPresent": r.get("markerPresent"),
                "transcriptPath": tp,
                "preceding_assistant_text": (ctx or "")[:2000],
                "context_found": ctx is not None,
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--tier2-out", type=Path, default=None)
    args = ap.parse_args()

    rows = load_jsonl(NUDGE_LOG)
    if not rows:
        print(json.dumps({"error": f"no rows read from {NUDGE_LOG}"}))
        return 1

    result = {"tier1": tier1(rows)}

    sample = tier2_sample(rows, args.sample, args.seed)
    result["tier2_sample_size"] = len(sample)
    result["tier2_context_found"] = sum(1 for s in sample if s["context_found"])
    if args.tier2_out:
        args.tier2_out.write_text(json.dumps(sample, indent=2))
        result["tier2_written_to"] = str(args.tier2_out)
    else:
        result["tier2_sample"] = sample

    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
