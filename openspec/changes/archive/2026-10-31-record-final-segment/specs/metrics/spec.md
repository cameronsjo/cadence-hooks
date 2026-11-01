## ADDED Requirements

### Requirement: A rewritten segment is recorded first
Before a move replaces or empties a segment that keeps bytes, the manifest SHALL record the sha256 and length of exactly what the segment will hold, durably. A segment equal to that record SHALL read as finished, so a crash after the rewrite never blocks a later run. Both forward moves SHALL finish through the same judgement as recovery, re-reading the segment.

#### Scenario: Killed inside recovery
- **WHEN** recovery of a move with a late append is killed after recording, after the temp file, or after the rewrite
- **THEN** `metrics cat` prints every row once, and the next run finishes and clears the manifest

### Requirement: Only whole rows move
A move SHALL take only the bytes up to the segment's last newline; a torn last row stays in the segment. A pending move whose moved prefix ends mid-row and has bytes after it MUST be unproven.

#### Scenario: Last row half written
- **WHEN** a segment is read while its last row is half written, and the writer finishes the row during the move
- **THEN** the row is whole, parses, and is stored in exactly one place
