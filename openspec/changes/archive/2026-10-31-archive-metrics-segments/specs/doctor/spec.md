## MODIFIED Requirements

### Requirement: Telemetry and environment checks
In default mode without `--root`, `doctor` SHALL warn about: stale or flatlined telemetry; fail-open telemetry over its thresholds in the last 7 days; slow hooks found in session logs; a metrics ledger of 64 MiB or more; a last `metrics rotate` success over 3 days old (or none with segments); archives over 500 MiB; a working or Claude config directory inside a cloud-synced tree; and inert `Bash(...)` rows in `permissions.deny` or `permissions.ask` of the user and project settings files.

#### Scenario: Oversized ledger
- **WHEN** a `*.jsonl` file in the metrics directory is 64 MiB
- **THEN** `doctor` warns about it and deletes nothing

#### Scenario: Archive not running
- **WHEN** `state/rotate.last-success` is 4 days old
- **THEN** `doctor` warns and names the `metrics_rotate_failed` rows to read
