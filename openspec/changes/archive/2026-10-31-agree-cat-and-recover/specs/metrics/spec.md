## MODIFIED Requirements

### Requirement: Recovery checks what a manifest names
Recovery and `metrics cat` SHALL share one judgement of a leftover manifest. An `archive` manifest must name its segment's own month, and its member must decode to the segment's first `source_len` bytes. A `quarantine` manifest must name a `denials` segment and the test-row archive, and its member must be exactly those bytes' test rows. An unproven manifest MUST change nothing on disk, and `cat` SHALL print that segment as it is.

#### Scenario: Forged quarantine manifest
- **WHEN** a `quarantine` manifest names a `sessions` segment and the test-row archive
- **THEN** the run exits 1 and the segment is byte-identical

#### Scenario: Tail is another segment's content
- **WHEN** an `archive` manifest's archive tail decodes to rows that are not its segment's
- **THEN** the run exits 1, the segment is byte-identical, and `metrics cat` prints its rows once

#### Scenario: Unrelated test-row member
- **WHEN** a `quarantine` manifest on a `denials` segment points at a test-row member holding other rows
- **THEN** the run exits 1, no row is stripped, and `metrics cat` prints every row of the segment

## ADDED Requirements

### Requirement: Rows appended after an archive read stay
When a proven move's segment has grown past `source_len`, recovery SHALL leave only the appended bytes in the segment (after the kept rows for a quarantine) and clear the manifest. Before that, `metrics cat` SHALL print the archived member and only the appended bytes.

#### Scenario: Append after the archive rename
- **WHEN** a run stops after renaming the new archive, a row is appended to the segment, and `metrics rotate` runs again
- **THEN** the manifest is cleared, the appended row is kept, and every row is stored and printed once

### Requirement: No salvage commands for names that display differently
When a damaged archive's name or directory changes under `display_safe`, the message MUST give no commands and SHALL say to rename the file to a plain name by hand.

#### Scenario: Zero-width character in the name
- **WHEN** a damaged archive's name holds U+200B
- **THEN** the displayed message holds no `mv` command and names the rename-by-hand step
