## MODIFIED Requirements

### Requirement: Ledgers rotate past a size cap
A ledger write that finds its `<metrics_dir>/*.jsonl` ledger at or past the cap SHALL move it to `<name>.<YYYYMMDDTHHMMSSZ>-<NNN>.jsonl` beside it (`<NNN>` counts earlier rotations that second) and append to a fresh `0600` file. The move MUST NOT replace an existing file. The cap is `CADENCE_METRICS_MAX_BYTES` bytes (16 MiB default; `0` is off; empty, unparsable or under 1 MiB keeps the default). Unix only. A history reader SHALL read segments in name order, then the live file.

#### Scenario: Ledger at the cap
- **WHEN** `denials.jsonl` holds at least the cap and a denial row is written
- **THEN** the old content is in one `denials.<stamp>-000.jsonl` segment, `denials.jsonl` holds only the new row, and both files are mode `0600`

#### Scenario: Every generation kept
- **WHEN** `denials.jsonl` rotates three times within one second
- **THEN** three segments exist (`<stamp>-000`, `<stamp>-001`, `<stamp>-002`), each holding its own generation, and reading the ledger returns every row oldest first

#### Scenario: Older generation replaced
- **WHEN** a segment from an earlier rotation exists and `denials.jsonl` rotates again
- **THEN** the earlier segment is unchanged (no generation is ever replaced) and a new segment holds the rotated content

#### Scenario: Segment name already taken
- **WHEN** a file already exists at the segment name a rotation would use
- **THEN** that file is unchanged and the rotation uses the next sequence number

#### Scenario: Rotation off
- **WHEN** `CADENCE_METRICS_MAX_BYTES=0` and a ledger is far past 16 MiB
- **THEN** the row is appended and no segment appears

### Requirement: Rotation is safe for concurrent writers and never blocks a hook
The rotator MUST take a non-blocking `flock` on the live file and move it only when the path still names the file it holds, so concurrent writers lose no row and never rotate a fresh ledger out from under a newer generation. A rotation error MUST NOT fail or block the hook: it is recorded as a `ledger_rotate_failed` row in `failopen.jsonl` (never for `failopen.jsonl` itself) and the row is still appended.

#### Scenario: Rotation fails
- **WHEN** the move cannot happen (every segment name for the stamp is taken)
- **THEN** the hook exits 0 as usual, the row is appended to the live ledger, and `failopen.jsonl` gains a `ledger_rotate_failed` row naming the ledger

#### Scenario: A writer holding the old file
- **WHEN** a process opened the ledger before another rotated it and then finds it past the cap
- **THEN** it does not move the fresh ledger aside, and appends to the live file

#### Scenario: Concurrent writers across a rotation
- **WHEN** eight writers append 250 rows each and the ledger crosses the cap several times
- **THEN** every row is in a segment or the live file exactly once, and every line parses
