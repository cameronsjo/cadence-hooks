## ADDED Requirements

### Requirement: Ledgers rotate past a size cap
A ledger write that finds its `<metrics_dir>/*.jsonl` ledger at or past the cap SHALL rename it to `<name>.jsonl.1`, replacing any older `.1`, and append to a fresh file with mode `0600`. The cap is `CADENCE_METRICS_MAX_BYTES` bytes, 16 MiB by default; `0` turns rotation off and an empty or unparsable value keeps the default. The rotator MUST take a non-blocking `flock` on the live file and rename only when the path still names the file it holds, so concurrent writers lose no row and never rename a fresh ledger over `.1`. A rotation error MUST NOT fail or block the hook: it is recorded as a `ledger_rotate_failed` row in `failopen.jsonl` (never for `failopen.jsonl` itself) and the row is still appended. Rotation is Unix only. A reader that wants history SHALL read `.1` and then the live file.

#### Scenario: Ledger at the cap
- **WHEN** `denials.jsonl` holds at least the cap and a denial row is written
- **THEN** the old content is in `denials.jsonl.1`, `denials.jsonl` holds only the new row, and both files are mode `0600`

#### Scenario: Older generation replaced
- **WHEN** `denials.jsonl.1` already exists and `denials.jsonl` rotates
- **THEN** `denials.jsonl.1` holds the rotated content only

#### Scenario: Rotation off
- **WHEN** `CADENCE_METRICS_MAX_BYTES=0` and a ledger is far past 16 MiB
- **THEN** the row is appended and no `.1` file appears

#### Scenario: Rotation fails
- **WHEN** the rename cannot happen (a directory occupies `.1`)
- **THEN** the hook exits 0 as usual, the row is appended to the live ledger, and `failopen.jsonl` gains a `ledger_rotate_failed` row naming the ledger

#### Scenario: A writer holding the old file
- **WHEN** a process opened the ledger before another rotated it and then finds it past the cap
- **THEN** it does not rename the fresh ledger over `.1` and appends to the live file

#### Scenario: Concurrent writers across a rotation
- **WHEN** eight writers append 250 rows each and the ledger crosses the cap once
- **THEN** every row is in `.1` or the live file exactly once, and every line parses
