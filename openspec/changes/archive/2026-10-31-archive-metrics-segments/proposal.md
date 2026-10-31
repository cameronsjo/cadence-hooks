## Why

Size-based rotation (cameronsjo/cadence-hooks#1585) keeps every generation of a ledger as a dated segment, but nothing ages segments out, so the metrics directory grows without bound and every reader globs more files each month. Old rows are what the ledgers exist to answer questions about, so aging out must compress, never drop. The `denials` ledger also carries rows from test and probe runs (no UUID `sessionId`) that skew every count. Tracked in cameronsjo/cadence-hooks#1590.

## What Changes

- New CLI action `cadence-hooks metrics rotate`: under an exclusive non-blocking `flock` on `state/rotate.lock`, moves every segment past its retention window (by segment stamp: `denials` 90 days, every other ledger 180 days; `commits`, `sessions`, `plan-links` are never dropped and archive at 180 days like the rest) into `archive/<ledger>.<YYYY-MM>.jsonl.gz`. No row is ever dropped.
- Before a `denials` segment is archived, its per-(day, hook, repo, decision) counts are appended to `rollups/denials-daily.jsonl`, each row naming the segment, and a segment already rolled up is skipped.
- Every move is protected by `state/rotate-manifest.json` (segment, archive, row count, sha256, archive length before). The archive grows by a new gzip member written to a temp file with the old bytes and renamed over it; the segment is deleted only after the archive is fsynced and its new member verified. The next run first finishes or rolls back a leftover manifest and never appends a segment twice.
- The run also removes `state/subagents/<session>/`, `state/bypass/<session>/` and `state/commits/<session>/` dirs whose newest entry is older than 7 days (sessions that never reached SessionEnd), never following a symlink.
- `state/rotate.last-success` is written only after a complete run. Failures are `metrics_rotate_failed` rows in `failopen.jsonl`; the CLI exits 1.
- `metrics rotate --quarantine-test-rows [--dry-run]`: moves `denials` rows whose `sessionId` is not a UUID into `archive/denials.testrows.jsonl.gz`, moving the live file aside first under the rotation `flock`, rewriting each affected segment under its own name through a temp file, and recording `state/quarantine-<date>.json`.
- New CLI action `cadence-hooks metrics cat <ledger> [--since] [--include-test-rows]`: prints archives, then segments, then the live file, printing a half-moved segment once.
- `metrics log-session-start` runs the archive once per UTC day within a 2 s budget and fails open, so no new hooks.json entry is needed.
- `doctor` warns when the last complete run is more than 3 days old (or absent while segments exist), and when `archive/` plus `rollups/` exceed 500 MiB.
- `CADENCE_BYPASS=1` does not stop `metrics rotate` or `metrics cat`.

## Impact

- Code: new `crates/metrics/src/rotate.rs` and `crates/metrics/src/ledger_cat.rs`; `crates/metrics/src/common.rs` (segment-name split, forced live rotation), `crates/metrics/src/log_session_start.rs`, `crates/metrics/src/log_failopen.rs`, `src/main.rs`, `src/doctor.rs`.
- Dependencies: `flate2` (pure-Rust `miniz_oxide` backend), `gethostname` and `sha2` in the metrics crate.
- Readers outside this repo that read segments directly no longer see archived rows; they read them with `metrics cat`.
