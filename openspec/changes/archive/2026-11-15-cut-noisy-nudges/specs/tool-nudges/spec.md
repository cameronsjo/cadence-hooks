## REMOVED Requirements

### Requirement: Bare curl with custom headers nudges
**Reason**: The nudge told the model that `curl` is aliased to `curlie` without checking, and in Claude Code's shells no such alias exists (cameronsjo/cadence-hooks#1443).
**Migration**: None. `warn-curl-alias` stays as a retired subcommand that exits 0 with no output.

### Requirement: Aliased tool output piped into a parser nudges
**Reason**: The nudge told the model that `cat`, `ls`, `du`, `df` or `top` is aliased to a replacement without checking, and in Claude Code's shells no such alias exists (cameronsjo/cadence-hooks#1443).
**Migration**: None. `warn-alias-parsing` stays as a retired subcommand that exits 0 with no output.

### Requirement: Advisory tool nudges are suppressible per repo
**Reason**: It named the retired `warn-curl-alias` and `warn-alias-parsing` hooks and used the curl nudge as its example, which no longer fires (cameronsjo/cadence-hooks#1443).
**Migration**: None. "Advisory tool nudges can be silenced per repo" replaces it with the same rule for the remaining hooks.

## ADDED Requirements

### Requirement: Retired alias hooks exit silently
`warn-curl-alias` and `warn-alias-parsing` SHALL exit 0 with no output on every input, so plugin wiring that still names them prints nothing and blocks nothing.

#### Scenario: Old wiring calls a retired hook
- **WHEN** `cadence-hooks guardrails warn-alias-parsing` runs on `ls | grep config`, or `cadence-hooks guardrails warn-curl-alias` runs on `curl -H 'Accept: application/json' https://api.example.com`
- **THEN** the hook exits 0 with no output

### Requirement: Advisory tool nudges can be silenced per repo
Nudges from `warn-cron-datetime`, `warn-chezmoi-apply`, `warn-agent-dispatch`, `warn-recommended-option`, and `warn-empty-answers` SHALL be silenceable by the repository's `.claude/cadence.json` `nudges` map. The other five hooks in this capability MUST NOT be, and suppression MUST never turn a block into an allow. Every hook here SHALL run unchanged in a cloud session.

#### Scenario: Repo silences the cron nudge
- **WHEN** the repo's `.claude/cadence.json` has `"nudges": {"warn-cron-datetime": {"suppress": true}}` and a `CronCreate` call runs
- **THEN** the hook allows silently

#### Scenario: Repo cannot silence the device gate
- **WHEN** the repo's `nudges` map names `guard-browser-device`
- **THEN** the first Claude-in-Chrome call of a session is still blocked
