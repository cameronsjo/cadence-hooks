## MODIFIED Requirements

### Requirement: Selective disable
`CADENCE_DISABLE` SHALL be read per invocation as a comma-separated list of exact hook names. A named hook that is not protected MUST exit 0 before reading stdin, print `'<hook>' disabled via CADENCE_DISABLE` to stderr, and append a `global_disable` row to `bypasses.jsonl`. A named protected guard MUST still run and SHALL print `refusing to disable protected guard '<hook>'` to stderr.

#### Scenario: Protected guard keeps running
- **WHEN** `CADENCE_DISABLE=git-safety` and `cadence git-safety` receives `git reset --hard`
- **THEN** stderr carries the refusal line and the exit status is 2

#### Scenario: Advisory hook switched off
- **WHEN** `CADENCE_DISABLE=warn-main-branch` and `guardrails warn-main-branch` runs
- **THEN** it exits 0 without reading stdin and `bypasses.jsonl` gains a `global_disable` row

#### Scenario: The protected set
- **WHEN** `CADENCE_DISABLE` names `prevent-secret-leaks`, `prevent-secret-writes`, `prevent-secret-push`, `redact-external-content`, `git-safety`, `guard-gh-dangerous`, `guard-gh-write`, `guard-op-vault-scan`, `guard-sops-decrypt`, `guard-runbook-scrub`, `guard-browser-device`, `guard-dotfiles`, `guard-read-model`, `trash-guard` or `enforcement-status`
- **THEN** that hook still runs
