## Purpose
Issue guards are the Bash hooks that police how issues are graded, closed, routed and written: `cadence-hooks guardrails guard-critical-grade`, `cadence-hooks cadence guard-held-close`, `cadence-hooks guardrails warn-issue-tracker` and `cadence-hooks guardrails warn-inline-body`. Two block; two only nudge.

## ADDED Requirements

### Requirement: Critical grades are human-only
`guard-critical-grade` (PreToolUse, Bash) SHALL block (exit 2, `critical-grade: this command applies`) a `gh` command that applies `impact:critical` or `likelihood:critical`, matched case-insensitively. It MUST read only label-carrying inputs: `--label`/`-l`/`--add-label` on `gh issue|pr create|edit`, and `labels` fields on a `gh api` write to an issue or PR endpoint. The reason SHALL say to file at `impact:high`/`likelihood:high` and ask the operator to apply Critical.

#### Scenario: Adding a Critical label
- **WHEN** the command is `gh issue edit 12 --add-label impact:high,likelihood:critical`
- **THEN** the hook exits 2 naming the label and the `impact:high` / `likelihood:high` fix

#### Scenario: Combined flags and API writes
- **WHEN** the command is `gh issue create -wl impact:critical`, `gh -R o/r issue edit 12 --add-label impact:critical`, or `gh pr create --label impact:critical --fill`
- **THEN** the hook exits 2

#### Scenario: API label write
- **WHEN** the command is `gh api repos/o/r/issues/12/labels -f 'labels[]=impact:critical'`
- **THEN** the hook exits 2

### Requirement: Label commands that are not a Critical grade
`guard-critical-grade` SHALL allow every command that does not apply a Critical grade: removing the label (`--remove-label`, `gh api -X DELETE .../labels/impact:critical`), creating the label itself (`gh label create impact:critical`), listing or filtering by it, a non-Critical label, and the label name appearing in a title, body, comment, `echo`, `grep` or commit message.

#### Scenario: Ordinary labeling
- **WHEN** the command is `gh issue create --title t --label kind:bug --label impact:high`
- **THEN** the hook exits 0 with no output

#### Scenario: Label named in prose
- **WHEN** the command is `gh issue comment 12 --body 'impact:critical is human-only'`
- **THEN** the hook allows

### Requirement: Unreadable label value
`guard-critical-grade` SHALL treat a label value the shell computes (`$X`, `$(...)`, backticks) or a `gh api` label body it cannot read (`--input -`, a missing `--input` file) on an applying command as a possible Critical grade and block, with a reason saying the guard cannot tell and asking for the label to be named literally.

#### Scenario: Computed label
- **WHEN** the command is `gh issue edit 12 --add-label "impact:crit$X"`
- **THEN** the hook exits 2 and the reason says to name the label literally

### Requirement: The operator's ruling
`guard-critical-grade` SHALL allow a Critical grade when `CADENCE_ALLOW_CRITICAL_GRADE=1` is set in the hook process environment, and SHALL record that allow as a bypass. The ruling MUST be read from the process environment only: an inline `CADENCE_ALLOW_CRITICAL_GRADE=1 gh ...` prefix or an `export` earlier in the same command MUST still block, and the block reason SHALL say so.

#### Scenario: Inline ruling
- **WHEN** the command is `CADENCE_ALLOW_CRITICAL_GRADE=1 gh issue edit 12 --add-label impact:critical` and the variable is not in the hook's environment
- **THEN** the hook exits 2

#### Scenario: Environment ruling
- **WHEN** `CADENCE_ALLOW_CRITICAL_GRADE=1` is in the hook's environment and the command applies `impact:critical`
- **THEN** the hook exits 0 and the allow is recorded as a bypass

### Requirement: HELD issues stay open
`guard-held-close` (PreToolUse, Bash) SHALL block (exit 2, `is on the HELD ledger and must not be closed`) a `gh issue close` when an issue it could name is on the HELD ledger, and the reason MUST say to remove the entry first if the hold has ended. The ledger is whitespace-separated `owner/repo#N` entries from `CADENCE_DRAIN_HELD` when non-empty, else the `--ledger <path>` file (`#` lines are comments). No ledger, or no valid entry, SHALL allow every close.

#### Scenario: Held issue closed by repo flag
- **WHEN** the ledger holds `cameronsjo/cadence-ecosystem#354` and the command is `gh issue close 354 -R cameronsjo/cadence-ecosystem`
- **THEN** the hook exits 2 naming `cameronsjo/cadence-ecosystem#354`

#### Scenario: Ordinary close
- **WHEN** the ledger holds `cameronsjo/cadence#107` and the command is `gh issue close 108 -R cameronsjo/cadence`
- **THEN** the hook allows

#### Scenario: No ledger
- **WHEN** `CADENCE_DRAIN_HELD` is unset and no `--ledger` file is configured or readable
- **THEN** every `gh issue close` is allowed

### Requirement: HELD matching errs toward blocking
`guard-held-close` SHALL treat every issue-shaped operand (`N`, `#N`, an issue URL) as a candidate, flag values included. A number SHALL match against each `-R`/`--repo`/`GH_REPO=` value, else every remote of the checkout the close runs in, and against every ledger entry when no repository can be read. A non-literal selector (`$n`) SHALL search the whole command for a held number. The same number in an unheld repository SHALL be allowed. Closes across more than 16 directories SHALL block.

#### Scenario: Loop over a held number
- **WHEN** the ledger holds `cameronsjo/cadence#107`, the checkout's remote is `cameronsjo/cadence`, and the command is `for n in 12 107; do gh issue close "$n"; done`
- **THEN** the hook exits 2

#### Scenario: Flag value that is a held number
- **WHEN** the ledger holds `cameronsjo/cadence#107`, the checkout's remote is `cameronsjo/cadence`, and the command is `gh issue close 12 --comment 107`
- **THEN** the hook exits 2

#### Scenario: Same number elsewhere
- **WHEN** the ledger holds `cameronsjo/cadence#107` and the command is `gh issue close 107 -R cameronsjo/forgectl`
- **THEN** the hook allows

### Requirement: Routes the HELD guard does not cover
`guard-held-close` SHALL allow, by design, closes that do not spell `gh issue close` in the command text it walks: `gh issue delete`, `gh issue transfer`, a `gh api` PATCH to `state=closed`, a GraphQL `closeIssue`, a merged PR's closing keyword, a gh alias, and `gh issue close` behind a prefix it does not peel (`xargs`, `sudo`, `timeout`, `env -i`). A failure to read the ledger file SHALL allow.

#### Scenario: Closed through the API
- **WHEN** the ledger holds `cameronsjo/cadence#107` and the command is `gh api -X PATCH repos/cameronsjo/cadence/issues/107 -f state=closed`
- **THEN** `guard-held-close` allows

### Requirement: Issue tracker routing nudge
`warn-issue-tracker` (PreToolUse, Bash) SHALL nudge, never block, when `gh issue create` or a `gh api` POST to `repos/OWNER/REPO/issues` targets an owned repository on the default host, under an owner that hosts a known tracker, that is not itself a known tracker. The nudge SHALL name the target and the per-component routing. The target SHALL come from the last `-R`/`--repo`, else the API path, else the `origin` remote of the command's directory. Every other target SHALL be silent.

#### Scenario: Owned non-tracker repo
- **WHEN** `CADENCE_ALLOWED_OWNERS=cameronsjo` and the command is `gh issue create -R cameronsjo/dotfiles --title t`
- **THEN** the hook exits 0 with a nudge naming `cameronsjo/dotfiles` and the routing (cadence plugins to `cameronsjo/cadence`, cadence-hooks to `cameronsjo/cadence-hooks`, forgectl and claunch to `cameronsjo/forgectl`, meta to `cameronsjo/cadence-ecosystem`)

#### Scenario: Known tracker
- **WHEN** the command is `gh issue create -R cameronsjo/cadence-hooks --title t`
- **THEN** the hook exits 0 with no output

#### Scenario: Third-party repo
- **WHEN** the command is `gh issue create -R rust-lang/cargo --title t`
- **THEN** the hook exits 0 with no output

### Requirement: Tracker set configuration
`warn-issue-tracker` SHALL take the known trackers from `CADENCE_ISSUE_TRACKERS` (comma-separated `owner/repo`), else the legacy `CADENCE_ISSUE_TRACKER`, else `cameronsjo/cadence`, `cameronsjo/cadence-hooks`, `cameronsjo/forgectl`, `cameronsjo/cadence-ecosystem` and the pre-rename alias `cameronsjo/claude-configurations`. An override MUST replace the default set and the owners the nudge is scoped to. The alias SHALL be accepted but never recommended.

#### Scenario: Pre-rename alias
- **WHEN** the default set applies and the command is `gh issue create -R cameronsjo/claude-configurations --title t`
- **THEN** the hook exits 0 with no output

### Requirement: Unreadable tracker target
`warn-issue-tracker` SHALL nudge with `can't tell which repo this issue files to` when the `-R`/`--repo` value is not a single readable `owner/repo` or two readings disagree, and MUST NOT block.

#### Scenario: Disagreeing repo flags
- **WHEN** the issue-create command carries two `-R` readings the parser cannot attribute
- **THEN** the hook exits 0 with the unreadable-target nudge asking for `-R owner/repo`

### Requirement: Long inline bodies
`warn-inline-body` (PreToolUse, Bash) SHALL nudge, never block, when the last body flag of a `gh pr create` or `gh issue create` segment is an inline `--body`/`-b` longer than 200 characters, heredoc substitutions included, giving the length and telling the operator to post with `--body-file`, the redaction review moment. A body of 200 characters or fewer, a `--body-file`/`-F` body, and other commands SHALL be silent. It MUST do no file or network I/O.

#### Scenario: Long inline body
- **WHEN** the command is `gh issue create -R o/r --title t --body '<300 characters>'`
- **THEN** the hook exits 0 with a nudge naming the 300-character body and `--body-file`

#### Scenario: Short or file body
- **WHEN** the command is `gh pr create --title t --body "Fixes the typo."` or `gh pr create --title t --body-file /tmp/w/body.md`
- **THEN** the hook exits 0 with no output

### Requirement: Switches and remote sessions
None of the issue guards SHALL be protected: each MUST honour `CADENCE_DISABLE` by name and `CADENCE_BYPASS=1`. Each SHALL run unchanged under `CLAUDE_CODE_REMOTE=true`.

#### Scenario: Disabled held guard
- **WHEN** `CADENCE_DISABLE=guard-held-close` and a held issue is closed
- **THEN** the hook exits 0
