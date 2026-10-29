## Why

The `<metrics_dir>/*.jsonl` ledgers only ever grew. `subagents.jsonl` and `denials.jsonl` reached tens of MiB, and `doctor` could only warn that the ledgers were "append-only with no rotation" (cameronsjo/cadence#2074, cameronsjo/cadence-hooks#425).

## What Changes

- Every ledger write that finds its ledger at or past a size cap renames it to `<name>.jsonl.1`, replacing any older `.1`, and appends to a fresh file. The cap is `CADENCE_METRICS_MAX_BYTES` bytes, 16 MiB by default; `0` turns rotation off and an unparsable value keeps the default. Unix only.
- The rotator takes a non-blocking `flock` on the live file and renames only when the path still names the inode it holds, so concurrent hooks neither lose a row nor rename a fresh ledger over `.1`.
- A rotation error never fails a hook. It is recorded as a `ledger_rotate_failed` row in `failopen.jsonl`, except for `failopen.jsonl` itself, and the row is still appended.
- The in-repo readers of the ledgers read `.1` and then the live file: `doctor`'s fail-open and sweep counts, the SessionStart fail-open disclosure and bypass summary, `log-commit`'s per-session cost marker, `log-session`'s commit count and `persist-plan-approval`'s `plan-links.jsonl` lookup.
- `doctor`'s large-ledger warning (64 MiB) says why the ledger is still large (rotation off, past the cap, or the cap set higher) instead of claiming there is no rotation.

Surfaces: every metrics logger, `doctor`, the SessionStart bypass summary and `persist-plan-approval`. No hooks.json change in cameronsjo/cadence. Readers outside this repo (the usage census in the cadence monorepo's `tend` skill) still read only the live file until they are updated.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `metrics`: "Ledgers rotate past a size cap" is added.

## Impact

`crates/metrics/src/common.rs`, `crates/metrics/src/log_failopen.rs`, the readers in `crates/metrics` and `crates/session/src/persist_plan.rs`, `src/doctor.rs`, `docs/configuration.md`, `CHANGELOG.md`.
