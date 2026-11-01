## MODIFIED Requirements

### Requirement: Only whole rows move
A move SHALL hold back a last row with no newline only while its segment changed within the last minute; an older segment's last row SHALL move with the rest, closed with a newline. A pending move whose moved prefix ends mid-row and has bytes after it MUST be unproven. A writer still holding the file open after the move re-reads it loses what it writes after that; only the quarantine's freshly moved live file is exposed, within its grace wait.

#### Scenario: Last row half written
- **WHEN** a fresh segment is read while its last row is half written, and the writer appends the rest by path before the move re-reads it
- **THEN** the row is whole, parses, and is stored in exactly one place

#### Scenario: Old segment ends mid-row
- **WHEN** a segment past retention, unchanged for over a minute, ends in a fragment with no newline
- **THEN** one run archives it whole, the segment is gone, and `metrics cat` prints the fragment once

### Requirement: Denial rollups
Before archiving rows of a `denials` segment, `metrics rotate` SHALL append to `rollups/denials-daily.jsonl` one row per (day, hook, repo, decision) with its `count`, the `segment` name and `movedSha256` (the moved bytes' hash), in one write. A (segment, moved bytes) pair already rolled up MUST NOT be rolled up again.

#### Scenario: Killed after the rollup
- **WHEN** a run stops after appending a segment's rollup rows and `metrics rotate` runs again
- **THEN** the segment is archived and its rows are counted in the rollup once

#### Scenario: One segment moved twice
- **WHEN** a move leaves a row appended during it in the segment, and a later run archives that row
- **THEN** the rollup counts equal the rows archived
