## Why

The third review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found four problems:

- The first SessionStart after an upgrade archived `denials` segments, test rows included, before `--quarantine-test-rows` could run, and the quarantine cannot reach archived rows.
- The damaged-archive message told the operator to move the archive aside, which also hid its intact rows from `metrics cat`.
- `cat` treated an unreadable `archive/` as empty, gave read errors without a path, and failed outright without write access to `state/`.
- A forged `quarantine` manifest could name another ledger's segment.

## What Changes

- No `denials` segment is archived until a `state/quarantine-*.json` record exists. Waiting segments make the run partial, and the CLI prints one line naming `--quarantine-test-rows`. The quarantine writes its record on every real run, even one that moved nothing.
- The damaged-archive error and `cat`'s stderr line give salvage commands that keep the intact members and drop a partial last row.
- `cat` reports an unreadable `archive/` as an error naming it, names the file in every read error, and reads unlocked with a stderr note when the lock file cannot be opened or created.
- Recovery accepts an `archive` manifest only for its segment's own monthly archive, and a `quarantine` manifest only for a `denials` segment and the test-row archive.

## Impact

- Code: `crates/metrics/src/rotate.rs`, `crates/metrics/src/ledger_cat.rs`, `src/main.rs` (help text), tests.
