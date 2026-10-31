## ADDED Requirements

### Requirement: Segments past retention are archived, never dropped
`cadence-hooks metrics rotate` SHALL move every rotated segment older than its window (by segment stamp: `denials` 90 days; every other ledger 180 days, the never-dropped `commits`, `sessions` and `plan-links` included) into `archive/<ledger>.<YYYY-MM>.jsonl.gz`, the month of the stamp. It MUST NOT drop a row or touch a live `*.jsonl` file. It SHALL hold an exclusive non-blocking `flock` on `state/rotate.lock`; a run that loses it prints a skip line and exits 0.

#### Scenario: Window boundaries
- **WHEN** `denials` segments stamped 89 and 91 days ago and `commits` segments stamped 179 and 181 days ago exist
- **THEN** only the 91-day and 181-day segments move to their monthly archives, and the row multiset across archives and segments is unchanged

#### Scenario: Second run
- **WHEN** `metrics rotate` runs again with nothing new past its window
- **THEN** it archives nothing and every archive and rollup is byte-identical

#### Scenario: Lock held
- **WHEN** another run holds `state/rotate.lock`
- **THEN** the run changes nothing and exits 0

### Requirement: Archive moves survive a crash
Before each move `metrics rotate` SHALL write `state/rotate-manifest.json` naming the segment, archive, row count, sha256 and archive length. The archive MUST grow only by a temp file holding its old bytes plus a new gzip member, fsynced and renamed over it. The segment SHALL be deleted only after that member decodes to its bytes, then the manifest. A run SHALL first finish or roll back a leftover manifest and MUST NOT archive a segment twice.

#### Scenario: Killed after the archive rename
- **WHEN** a run stops after renaming the new archive and before deleting the segment, and `metrics rotate` runs again
- **THEN** the segment is deleted without a second append, and every row is stored exactly once

#### Scenario: Killed before the archive rename
- **WHEN** a run stops after writing the manifest or the temp archive
- **THEN** the next run removes the temp file and manifest, archives the segment once, and loses no row

### Requirement: Denial rollups
Before archiving a `denials` segment, `metrics rotate` SHALL append to `rollups/denials-daily.jsonl` one row per (day, hook, repo, decision) with its `count` and the `segment` name, in one write. A segment already named by a rollup row MUST NOT be rolled up again.

#### Scenario: Killed after the rollup
- **WHEN** a run stops after appending a segment's rollup rows and `metrics rotate` runs again
- **THEN** the segment is archived and its rows are counted in the rollup once

### Requirement: Stale per-session state is swept
`metrics rotate` SHALL remove `state/subagents/<session>/`, `state/bypass/<session>/` and `state/commits/<session>/` when the newest entry inside is older than 7 days. It MUST only remove real directories whose name passes the session-id check, under parents that are real directories, and MUST NOT follow a symlink.

#### Scenario: A session that never ended
- **WHEN** `state/subagents/<id>/` was last written 8 days ago and `state/subagents/<other>/` 6 days ago
- **THEN** the first is removed and the second stays

#### Scenario: Symlinked state
- **WHEN** `state/bypass/<id>` or `state/commits` is a symlink to a directory with old entries
- **THEN** nothing the symlink points at is removed

### Requirement: Rotate success marker, failures and file modes
`metrics rotate` SHALL write the UTC time to `state/rotate.last-success` only after a complete run. Any failure SHALL append a `metrics_rotate_failed` row to `failopen.jsonl` and exit 1. Files it creates MUST be `0600` and directories `0700`, opened without following a symlink; a symlinked `archive/`, `rollups/` or `state/` is a failure, never written through.

#### Scenario: Symlinked archive directory
- **WHEN** `archive/` is a symlink and a segment is past its window
- **THEN** the run exits 1, `failopen.jsonl` gains a `metrics_rotate_failed` row, and nothing is written through the symlink

### Requirement: Daily archive at SessionStart
`metrics log-session-start` SHALL run the archive at most once per UTC day (`state/rotate.day`), stopping between segments after 2 seconds and leaving the rest for the next day. A run cut short MUST NOT write `state/rotate.last-success`. It MUST fail open: a failure is a `failopen.jsonl` row and never changes the hook's exit.

#### Scenario: Second session the same day
- **WHEN** a second session starts on the same UTC day
- **THEN** no archive run happens

### Requirement: Test-row quarantine
`metrics rotate --quarantine-test-rows` SHALL move `denials` rows whose `sessionId` is absent, null or not a UUID out of the live file and its segments into `archive/denials.testrows.jsonl.gz`. It MUST move the live file aside first under the rotation `flock`, rewrite each segment under its own name through a temp file, use the manifest discipline, and write `state/quarantine-<date>.json`. `--dry-run` changes nothing.

#### Scenario: Quarantine run
- **WHEN** the live file and two segments hold three non-UUID rows among UUID rows
- **THEN** the three rows are in the test-row archive, the UUID rows stay in their segments, and the record names the host, per-file counts and source sha256

#### Scenario: Dry run
- **WHEN** `--quarantine-test-rows --dry-run` runs
- **THEN** it prints the counts and every file is byte-identical

#### Scenario: Concurrent appender
- **WHEN** hooks append denial rows while the quarantine runs
- **THEN** every appended row is stored exactly once, and a second run moves nothing it already moved

### Requirement: Ledger cat
`cadence-hooks metrics cat <ledger>` SHALL print the ledger's monthly archives in month order, then its segments in name order, then the live file, one row per line. A segment whose bytes a leftover manifest shows already archived MUST print once. `--since` keeps rows whose `ts` is at or after it. `--include-test-rows` prepends the test-row archive for `denials`. A name other than letters, digits, `-` and `_` exits 2.

#### Scenario: History in order
- **WHEN** a ledger has two monthly archives, two segments and a live file
- **THEN** `metrics cat` prints the January archive, the February archive, the segments, then the live rows

#### Scenario: Half-done move
- **WHEN** a crash left a manifest whose archive already holds its segment
- **THEN** `metrics cat` prints that segment's rows once
