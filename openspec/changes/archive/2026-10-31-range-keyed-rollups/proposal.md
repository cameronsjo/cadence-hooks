## Why

The eighth review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found two problems:

- An old torn segment whose fragment was finished after the archive read blocked every later run with "found a split row", and `metrics cat` printed those rows twice.
- Rollup idempotence keyed on a content hash double-counted after a crash plus a content change: 5 counted for 3 archived rows.

## What Changes

- When an archive closed a torn last row with a newline, recovery accepts the prefix. The bytes after it stay in the segment as their own fragment, which a later run archives.
- Rollup rows record the moved byte range (`movedSha256`, `movedLen`). A retry or a second move rolls up only the rows past a recorded range that is a prefix of the bytes moved. A row with no range means the segment was rolled up in full.
- A modification time more than a day in the future counts as old for the torn-row hold.

## Impact

- Code: `crates/metrics/src/rotate.rs`, tests.
