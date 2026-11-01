## MODIFIED Requirements

### Requirement: A damaged archive is never appended to
Before growing an archive, `metrics rotate` and `--quarantine-test-rows` SHALL decode it to the end. When that fails, the move MUST fail with a `metrics_rotate_failed` row naming the archive, the source segment MUST stay, and the archive MUST be left byte-identical. The message SHALL give commands that save the intact members under the archive's name, quote every path as one word, and stop without moving anything when `<name>.damaged` exists.

#### Scenario: Truncated monthly archive
- **WHEN** `archive/denials.2026-07.jsonl.gz` ends in a truncated member and a July segment is past its window
- **THEN** the run exits 1, the segment and the archive are unchanged, and no manifest is left

#### Scenario: Salvage
- **WHEN** the operator runs the commands the message gives and then `metrics rotate`
- **THEN** every row of the intact members is kept, no partial row is, and the segment is archived

#### Scenario: Hostile name
- **WHEN** the archive name holds a quote, a `$(…)` substitution, a space and a leading `-`
- **THEN** the commands parse, run nothing from the name, and write only inside the archive directory

#### Scenario: Second salvage
- **WHEN** the commands run again while `<name>.damaged` exists
- **THEN** they exit non-zero and the first `.damaged` copy is byte-identical

### Requirement: Recovery checks what a manifest names
Recovery and `metrics cat` SHALL accept an `archive` manifest only when its archive is the monthly archive of its segment's own stamp, and a `quarantine` manifest only when its segment is a `denials` segment and its archive is `denials.testrows.jsonl.gz`. Recovery SHALL delete an archived segment only when the segment's own bytes match what the archive tail decodes to. A manifest that fails either check MUST change nothing on disk.

#### Scenario: Forged quarantine manifest
- **WHEN** a `quarantine` manifest names a `sessions` segment and the test-row archive
- **THEN** the run exits 1 and the segment is byte-identical

#### Scenario: Tail is another segment's content
- **WHEN** an `archive` manifest's archive tail decodes to rows that are not its segment's
- **THEN** the run exits 1 and the segment is byte-identical
