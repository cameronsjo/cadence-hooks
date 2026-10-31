## MODIFIED Requirements

### Requirement: Blanket bypass
When `CADENCE_BYPASS` is exactly `1`, every hook subcommand SHALL exit 0 before reading stdin, print `all enforcement bypassed (CADENCE_BYPASS=1)` to stderr, and append a `global_bypass` row to `bypasses.jsonl`. Any other value MUST NOT bypass. The exemption MUST go by subcommand position, not by any argument: the CLI commands and the `guardrails enforcement-status` hook MUST still run.

#### Scenario: Bypassed guard
- **WHEN** `CADENCE_BYPASS=1` and `cadence git-safety` receives `git reset --hard`
- **THEN** it exits 0 and stderr carries the bypass line

#### Scenario: Truthy but not 1
- **WHEN** `CADENCE_BYPASS=yes` and `cadence git-safety` receives `git reset --hard`
- **THEN** it blocks

#### Scenario: Exempt commands
- **WHEN** `CADENCE_BYPASS=1` and `list`, `manifest`, `configure`, `doctor`, `try`, `migrate-config`, `session declare|status|plans|timer` or `metrics grade|price|rotate|cat` runs
- **THEN** it runs normally

#### Scenario: Argument that names a CLI command
- **WHEN** `CADENCE_BYPASS=1` and `cadence-hooks metrics log-commit --prices try` runs
- **THEN** it is bypassed, because `try` is not in the subcommand position
