## MODIFIED Requirements

### Requirement: Only whole rows move
A move SHALL hold back a last row with no newline only while its segment changed within the last minute (or over a day in the future); an older segment's last row SHALL move with the rest, closed with a newline, and bytes appended after that read SHALL stay as their own fragment. A quarantine whose moved prefix ends mid-row and has bytes after it MUST be unproven. A writer still holding the file open after the move re-reads it loses its later writes.

#### Scenario: Last row half written
- **WHEN** a fresh segment is read while its last row is half written, and the writer appends the rest by path before the move re-reads it
- **THEN** the row is whole, parses, and is stored in exactly one place

#### Scenario: Old segment ends mid-row
- **WHEN** a segment past retention, unchanged for over a minute, ends in a fragment with no newline
- **THEN** one run archives it whole, the segment is gone, and `metrics cat` prints the fragment once

#### Scenario: Old fragment finished after the read
- **WHEN** the writer of an old segment's fragment appends its end after the move read the segment
- **THEN** the run completes, the archive holds the fragment as read, the end stays in the segment as its own fragment, and `metrics cat` prints each once

### Requirement: Denial rollups
Before archiving rows of a `denials` segment, `metrics rotate` SHALL append to `rollups/denials-daily.jsonl` one row per (day, hook, repo, decision) with its `count`, the `segment` name and the moved byte range (`movedSha256`, `movedLen`), in one write. Only rows past a recorded range that is a prefix of the bytes moved SHALL be rolled up; a row with no range covers the whole segment.

#### Scenario: Killed after the rollup
- **WHEN** a run stops after appending a segment's rollup rows and `metrics rotate` runs again
- **THEN** the segment is archived and its rows are counted in the rollup once

#### Scenario: One segment moved twice
- **WHEN** a move leaves a row appended during it in the segment, and a later run archives that row
- **THEN** the rollup counts equal the rows archived

#### Scenario: Killed after the rollup, then appended to
- **WHEN** a run stops after the rollup, a row is appended to the segment, and `metrics rotate` runs again
- **THEN** the rollup counts equal the rows archived
