## MODIFIED Requirements

### Requirement: Test-row quarantine
`metrics rotate --quarantine-test-rows` SHALL move `denials` rows whose `sessionId` is absent, null or not a UUID out of the live file and its segments into `archive/denials.testrows.jsonl.gz`, where `cat --include-test-rows` still reads them. It MUST move the live file aside first under the rotation `flock`, rewrite each segment under its own name through a temp file, and use the manifest discipline. Every real run SHALL write `state/quarantine-<date>.json`. `--dry-run` changes nothing.

#### Scenario: Quarantine run
- **WHEN** the live file and two segments hold three non-UUID rows among UUID rows
- **THEN** the three rows are in the test-row archive, the UUID rows stay in their segments, and the record names the host, per-file counts and source sha256

#### Scenario: Dry run
- **WHEN** `--quarantine-test-rows --dry-run` runs
- **THEN** it prints the counts and every file is byte-identical

#### Scenario: Concurrent appender
- **WHEN** hooks append denial rows while the quarantine runs
- **THEN** every appended row is stored exactly once, and a second run moves nothing it already moved

#### Scenario: Nothing to move
- **WHEN** a quarantine run finds no test rows
- **THEN** it still writes its record

### Requirement: A damaged archive is never appended to
Before growing an archive, `metrics rotate` and `--quarantine-test-rows` SHALL decode it to the end. When that fails, the move MUST fail with a `metrics_rotate_failed` row naming the archive, the source segment MUST stay, and the archive MUST be left byte-identical. The message SHALL give commands that save the archive's intact members under its own name.

#### Scenario: Truncated monthly archive
- **WHEN** `archive/denials.2026-07.jsonl.gz` ends in a truncated member and a July segment is past its window
- **THEN** the run exits 1, the segment and the archive are unchanged, and no manifest is left

#### Scenario: Salvage
- **WHEN** the operator runs the commands the message gives and then `metrics rotate`
- **THEN** every row of the intact members is kept, no partial row is, and the segment is archived

## ADDED Requirements

### Requirement: Denials archive waits for the quarantine
`metrics rotate` MUST NOT archive a `denials` segment until a `state/quarantine-*.json` record exists. Such segments SHALL count as waiting: the run is partial, writes no `state/rotate.last-success`, and the CLI prints one line naming `--quarantine-test-rows`. Other ledgers archive as usual.

#### Scenario: Before and after the quarantine
- **WHEN** a `denials` segment and a `commits` segment are past their windows and no quarantine record exists
- **THEN** only the `commits` segment is archived; after a quarantine run, the next run archives the `denials` segment

### Requirement: Cat reports read failures
`metrics cat` SHALL treat only an absent `archive/` as empty; any other error listing it MUST fail naming the directory. Every read error SHALL name its file. When the lock file cannot be opened or created for lack of permission or a read-only filesystem, `cat` SHALL print a stderr note and read unlocked.

#### Scenario: Unreadable archive directory
- **WHEN** `archive/` cannot be listed
- **THEN** `metrics cat` exits 1 naming `archive/`

#### Scenario: Read-only state directory
- **WHEN** `state/` is not writable and holds no lock file
- **THEN** `metrics cat` prints every row

### Requirement: Recovery checks what a manifest names
Recovery and `metrics cat` SHALL accept an `archive` manifest only when its archive is the monthly archive of its segment's ledger, and a `quarantine` manifest only when its segment is a `denials` segment and its archive is `denials.testrows.jsonl.gz`. A manifest that fails this MUST change nothing on disk.

#### Scenario: Forged quarantine manifest
- **WHEN** a `quarantine` manifest names a `sessions` segment and the test-row archive
- **THEN** the run exits 1 and the segment is byte-identical
