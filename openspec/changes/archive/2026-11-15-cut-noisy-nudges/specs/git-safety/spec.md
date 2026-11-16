## REMOVED Requirements

### Requirement: Unseen execution nudges
**Reason**: The note fired on every script run and named no concrete action, which cadence-ecosystem ADR-0046 rule 3 forbids (cameronsjo/cadence-hooks#1443).
**Migration**: None. "Commands the guard cannot read are allowed silently" replaces it.

## ADDED Requirements

### Requirement: Commands the guard cannot read are allowed silently
When a command runs text `git-safety` cannot read (a script file, a sourced script, an `eval` of text built at run time, or a command named by a substitution) and no segment it does read blocks or nudges, the hook SHALL exit 0 with no output. A block or nudge from a segment it reads MUST still apply.

#### Scenario: Script run
- **WHEN** a Bash command is `bash x.sh` or `eval "$CMD"`
- **THEN** the hook exits 0 with no output

#### Scenario: Script beside a destructive git command
- **WHEN** a Bash command is `bash x.sh && git reset --hard`
- **THEN** the hook blocks
