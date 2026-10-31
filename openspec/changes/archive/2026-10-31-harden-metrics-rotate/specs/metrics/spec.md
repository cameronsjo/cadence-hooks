## MODIFIED Requirements

### Requirement: Daily archive at SessionStart
`metrics log-session-start` SHALL run the archive at most once per UTC day. It writes `state/rotate.day` before the run, so a failed or skipped run waits for the next day. It SHALL stop between segments after 2 seconds and skip segments over 8 MiB, leaving both for a later run. A run that stops early or skips a segment MUST NOT write `state/rotate.last-success`. It MUST fail open: a failure is a `failopen.jsonl` row and never changes the hook's exit.

#### Scenario: Second session the same day
- **WHEN** a second session starts on the same UTC day
- **THEN** no archive run happens

#### Scenario: A segment over the bound
- **WHEN** the SessionStart run finds a 9 MiB segment past its window beside a small one
- **THEN** the small one is archived, the large one stays for `metrics rotate`, and `state/rotate.last-success` is not written

## ADDED Requirements

### Requirement: A damaged archive is never appended to
Before growing an archive, `metrics rotate` and `--quarantine-test-rows` SHALL decode it to the end. When that fails, the move MUST fail with a `metrics_rotate_failed` row naming the archive, the source segment MUST stay, and the archive MUST be left byte-identical.

#### Scenario: Truncated monthly archive
- **WHEN** `archive/denials.2026-07.jsonl.gz` ends in a truncated member and a July segment is past its window
- **THEN** the run exits 1, the segment and the archive are unchanged, and no manifest is left

### Requirement: Cat reads under the rotate lock
`metrics cat` SHALL hold a shared `flock` on `state/rotate.lock` for its whole read, waiting for a running move to finish. A rotate that starts while it reads SHALL find the exclusive lock unavailable and skip, so no row prints twice or goes missing.

#### Scenario: Rotate starts mid-read
- **WHEN** a rotate starts while `metrics cat` is printing an archive and a segment of that month is past its window
- **THEN** the rotate skips and `metrics cat` prints every row once

### Requirement: Rotate runs only on Unix
Off Unix, `metrics rotate` and `--quarantine-test-rows` SHALL exit 1 with a message and change nothing, and the SessionStart run SHALL do nothing, until a run lock exists there.

#### Scenario: Windows
- **WHEN** `metrics rotate` runs on Windows
- **THEN** it exits 1 and no file under the metrics directory changes
