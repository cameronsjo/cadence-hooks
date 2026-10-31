## MODIFIED Requirements

### Requirement: Main-by-design and kill-switch exemptions
`enforce-worktree` SHALL allow when `CADENCE_ALLOW_MAIN` is truthy (`1`, `true`, `yes`) in the process environment, which exempts every repo the session touches, or in the target repo's own `.claude/settings.local.json` or `.claude/settings.json` `env` block, or when `CADENCE_NO_ENFORCE_WORKTREE` is truthy. The first such allow on a would-block target per session, working-directory repo and agent SHALL be recorded as a `used` row in `bypasses.jsonl`.

#### Scenario: Main-by-design repo
- **WHEN** the target repo's `.claude/settings.json` has `"env": {"CADENCE_ALLOW_MAIN": "true"}` and a commit lands in its primary
- **THEN** the hook exits 0 and a bypass `used` row is recorded
