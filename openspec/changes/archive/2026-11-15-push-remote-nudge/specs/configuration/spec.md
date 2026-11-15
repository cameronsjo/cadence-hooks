## MODIFIED Requirements

### Requirement: Unset owner allowlist
When `CADENCE_ALLOWED_OWNERS` names no owner, the gh-write guard SHALL block owner-checked operations with a message saying the allowlist is not configured, and the push guard SHALL allow with no output. `cadence-hooks configure guardrails` SHALL write `CADENCE_ALLOWED_OWNERS` (and optionally `CADENCE_ALLOWED_REPOS`) into the `env` block of the user settings file (`$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`), never a project file, migrating legacy `GIT_GUARDRAILS_ALLOWED_*` keys forward.

#### Scenario: Fresh machine push
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and a `git push` reaches `guard-push-remote`
- **THEN** the push is allowed with no output, and, when the user settings file exists, `cadence-hooks doctor` warns that the allowlist is unset
