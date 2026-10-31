## MODIFIED Requirements

### Requirement: Blanket bypass
`CADENCE_BYPASS` set to exactly `1` SHALL skip every enforcement hook, protected ones included, except `enforcement-status`. CLI and diagnostic commands (`list`, `manifest`, `configure`, `doctor`, `try`, `migrate-config`, `session declare|status|plans|timer`, `metrics grade|price|rotate|cat`) MUST keep working under it. Each skipped invocation SHALL print one stderr line naming the switch.

#### Scenario: Bypassed guard
- **WHEN** `CADENCE_BYPASS=1` and a command runs `git reset --hard`
- **THEN** `git-safety` does not run and the command is not blocked
