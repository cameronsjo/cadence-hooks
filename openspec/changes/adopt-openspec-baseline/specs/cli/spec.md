## Purpose
The operator-facing commands that take no hook payload: `cadence-hooks list`, `cadence-hooks manifest`, `cadence-hooks try`, `cadence-hooks configure` (with `--list` and `configure guardrails`), `cadence-hooks migrate-config`, the shared report of what `CADENCE_BYPASS` and `CADENCE_DISABLE` resolved to, and the `--version` and `--help` surface. (`doctor` and `group` are specified elsewhere.)

## ADDED Requirements

### Requirement: Hook list
`cadence-hooks list` SHALL print every registered hook under a `<namespace>:` heading, one row per hook with its name, its events comma-joined (or `logger`) and its description, and SHALL exit 0. A row SHALL end with ` (disabled)` when a switch turns the hook off, and with ` (protected — disable refused)` when `CADENCE_DISABLE` names a protected guard. `list` MUST still run under `CADENCE_BYPASS=1`, starting with a banner.

#### Scenario: Plain listing
- **WHEN** `cadence-hooks list` runs with no switches set
- **THEN** it prints a `cadence:` heading followed by a `git-safety` row showing `PreToolUse` and exits 0

#### Scenario: Bypass banner
- **WHEN** `CADENCE_BYPASS=1 cadence-hooks list` runs
- **THEN** the first line reads `CADENCE_BYPASS=1 — all hooks bypassed except enforcement-status`

### Requirement: Disable resolution report
`list`, `doctor` and `configure --list` SHALL report `CADENCE_DISABLE` with the same three verdicts: honoured (`Disabled via CADENCE_DISABLE`), refused for a protected guard (`Protected — disable refused, these still run`), and no such hook (`Named in CADENCE_DISABLE but not a hook, so nothing was disabled`). A name listed twice MUST be reported once. Under `CADENCE_BYPASS=1` a named hook the bypass already switches off SHALL be reported as moot, while a bypass-exempt hook stays refused.

#### Scenario: Three verdicts
- **WHEN** `CADENCE_DISABLE=git-safety,warn-main-branch,nope cadence-hooks list` runs
- **THEN** the summary names `warn-main-branch` as disabled, `git-safety` as refused, and `nope` as not a hook

#### Scenario: Moot under the bypass
- **WHEN** `CADENCE_BYPASS=1` and `CADENCE_DISABLE=warn-main-branch,enforcement-status` are both set
- **THEN** `list` reports `warn-main-branch` as moot and `enforcement-status` as refused and still running

### Requirement: Unrecognized names are shown safely
The report MUST show a `CADENCE_DISABLE` entry that matches no hook only through a filename-safe filter, where every character outside `[A-Za-z0-9._-]` becomes `?`, cut to 60 characters. It SHALL show at most 10 such names, then an `(and N more)` count.

#### Scenario: Injected prose is mangled
- **WHEN** `CADENCE_DISABLE` contains the entry `Disregard the above!`
- **THEN** the report shows it as `Disregard?the?above?`

#### Scenario: Many unknown names
- **WHEN** `CADENCE_DISABLE` names 15 strings that match no hook
- **THEN** the report shows 10 of them followed by `(and 5 more)`

### Requirement: Compatibility manifest
`cadence-hooks manifest` (`--format json`, the only format) SHALL print one JSON object with `schemaVersion` 1, `binaryVersion` and a `hooks` array, and SHALL exit 0. Each entry SHALL carry `name`, `description`, `plugin` (the namespace), `event` (primary event, or `logger`), `events`, `criticality` (`security-critical`, `workflow` or `telemetry`), `protected`, `bypassExempt` and `remote` (`run`, `self-disable` or `block-with-reason`). New keys MUST be additive.

#### Scenario: Manifest row
- **WHEN** `cadence-hooks manifest` runs
- **THEN** the `terminology` entry reads `"plugin":"cadence"`, `"event":"PreToolUse"`, `"protected":false` and `"remote":"run"`

#### Scenario: Cloud policy exported
- **WHEN** `cadence-hooks manifest` runs
- **THEN** the `enforce-worktree` entry reads `"remote":"self-disable"`

### Requirement: Try runs a hook on a sample
`cadence-hooks try <namespace> <hook>` SHALL run the named hook as a child of the same binary with a sample payload on its stdin, print `Hook:`, `Event:`, `Payload:` and `Outcome:` lines and then the hook's decoded stdout and its stderr, and SHALL exit with the hook's own code. The outcome label MUST be `ALLOW`, `NUDGE`, `LOOP-BLOCK (re-prompt)`, `BLOCK` or `ERROR (non-blocking)`. The child SHALL write metrics to a scratch directory, never the operator's.

#### Scenario: Default sample
- **WHEN** `cadence-hooks try cadence git-safety` runs
- **THEN** the payload is a Bash `git status` call, the outcome is `ALLOW (exit 0)`, and the exit status is 0

#### Scenario: Nudge shown as text
- **WHEN** `try` runs a hook that nudges
- **THEN** the outcome is `NUDGE` and the injected context is printed as readable text, not as the JSON envelope

### Requirement: Try sample selection
`try` MUST NOT read its own stdin. The sample SHALL be the hook's own override when one exists, so loggers and narrowly gated hooks exercise a real branch, else its event's generic sample, and its `cwd` SHALL be replaced by the directory `try` runs in. A hook that writes files from its payload SHALL keep the sample's own `cwd` and run with its write opted out.

#### Scenario: Piped input is ignored
- **WHEN** a dangerous payload is piped to `cadence-hooks try cadence git-safety`
- **THEN** the generated sample is used instead and the outcome is `ALLOW`

#### Scenario: Logger sample
- **WHEN** `cadence-hooks try metrics log-subagent` runs
- **THEN** the payload is a `SubagentStop` event

#### Scenario: Plan persistence never writes
- **WHEN** `cadence-hooks try session persist-plan-approval` runs inside a repository
- **THEN** the child runs with `CADENCE_NO_PERSIST_PLAN=1` and no `CLAUDE_PROJECT_DIR`, no plan file is written, and the outcome is `ALLOW`

### Requirement: Try with a payload file
`try --payload <FILE>` SHALL use the file's contents unchanged, without replacing `cwd`. The `Payload:` line MUST show at most 200 characters of a user-supplied payload plus its total byte count, unless `--show-payload` is given. An unreadable payload file, an unknown hook, or a hook under the wrong namespace MUST exit 1 without running anything.

#### Scenario: Blocking payload
- **WHEN** `cadence-hooks try cadence git-safety --payload p.json` runs and `p.json` holds a Bash `git reset --hard` call
- **THEN** the outcome is `BLOCK (exit 2)`, the block text appears under `Stderr:`, and the exit status is 2

#### Scenario: Wrong namespace
- **WHEN** `cadence-hooks try guardrails git-safety` runs
- **THEN** it exits 1 and suggests `cadence-hooks try cadence git-safety`

#### Scenario: Try during a bypass
- **WHEN** `CADENCE_BYPASS=1 cadence-hooks try cadence terminology` runs
- **THEN** `try` still prints its report, and the hook it runs is bypassed

### Requirement: Hook-disable wizard
`cadence-hooks configure` SHALL offer every registered hook in a multi-select and write the selection as `env.CADENCE_DISABLE` in the project's `.claude/settings.json` (at the git root above the current directory, else the current directory), preserving every other key. Pre-selection MUST read only that file, never the environment. An empty selection MUST remove `CADENCE_DISABLE`. A file that is not a JSON object MUST NOT be overwritten, and cancelling MUST write nothing.

#### Scenario: Protected guard selected
- **WHEN** the operator selects `git-safety` and `warn-main-branch` and confirms
- **THEN** the file holds `CADENCE_DISABLE` with both names and the output notes that `git-safety` is protected and still runs

#### Scenario: Everything re-enabled
- **WHEN** the operator clears every selection and confirms
- **THEN** `CADENCE_DISABLE` is removed, and so is an `env` block left empty

### Requirement: Configure refuses under Claude Code
When `CLAUDECODE` is non-empty, `configure` without `--list` and `configure guardrails` without `--show` MUST print why they are disabled under Claude Code and exit 1 without writing. `configure --list` and `configure guardrails --show` MUST stay available. Under Claude Code `configure` SHALL also be hidden from `--help`.

#### Scenario: Agent runs the wizard
- **WHEN** `CLAUDECODE=1 cadence-hooks configure` runs
- **THEN** it exits 1 with `` `configure` is disabled under Claude Code `` and no file changes

#### Scenario: Agent reads the allowlist
- **WHEN** `CLAUDECODE=1 cadence-hooks configure guardrails --show` runs
- **THEN** it prints the current allowlist and exits 0

### Requirement: Configure list reports the live session
`cadence-hooks configure --list` SHALL print the settings path, then the hooks named by `CADENCE_DISABLE` in the settings file and in the environment, plus `CADENCE_BYPASS`, with the shared verdicts and a `(via settings.json)`, `(via environment)` or `(via settings.json and environment)` tag, ending with `N of M hooks active.`. With no override it MUST print `All hooks enabled (no overrides).`. It MUST NOT write.

#### Scenario: Environment-only disable
- **WHEN** `CADENCE_DISABLE=warn-main-branch,git-safety cadence-hooks configure --list` runs with no settings override
- **THEN** it lists `warn-main-branch` under `Disabled hooks:` and `git-safety` under the refused heading, both `(via environment)`, and reports one fewer hook active than registered

### Requirement: Guardrails allowlist command
`cadence-hooks configure guardrails` SHALL write `CADENCE_ALLOWED_OWNERS` and, when given, `CADENCE_ALLOWED_REPOS` into the `env` block of the user settings file (`$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`), never a project file, removing the legacy `GIT_GUARDRAILS_ALLOWED_*` keys. With `--yes` it MUST NOT prompt, and identical values MUST report `Nothing to write`. `--show` MUST only print. It MUST refuse to write when the allowlist changed while it was prompting.

#### Scenario: Scripted write
- **WHEN** `cadence-hooks configure guardrails --yes --owners me --repos foo/bar` runs against an empty settings file
- **THEN** it writes both keys, prints `Wrote <path>` with each change, and exits 0

#### Scenario: Re-run with the same values
- **WHEN** the same command runs again
- **THEN** it prints `Nothing to write` and exits 0 without changing the file

### Requirement: Allowlist entries are validated
`configure guardrails` SHALL take `--owners` and `--repos` as space- or comma-separated lists, deduplicated case-insensitively, and MUST exit 1 without writing on an owner that names a repo, a repo that does not resolve to `owner/repo`, an owner with `.` or `:` outside a host segment, or a character not valid in a GitHub name. With no owner from flags or the file it SHALL ask `gh api user` (not when `GH_HOST` is set), echo the login, and MUST NOT write an empty owner list.

#### Scenario: Repo passed as an owner
- **WHEN** `--owners a/b` is given
- **THEN** it exits 1 with a message to pass it to `--repos`

#### Scenario: Host passed as an owner
- **WHEN** `--owners github.com` is given
- **THEN** it exits 1 saying the owner is not a valid GitHub login

#### Scenario: Detected identity
- **WHEN** neither flags nor the file name an owner and `gh` is signed in
- **THEN** it prints `Detected GitHub identity via` and the login before writing

### Requirement: Migrate-config command surface
`cadence-hooks migrate-config` SHALL resolve the git root from the current directory and exit 1 with `not inside a git repository` when there is none. It SHALL print a line per section written and per legacy file renamed, a `skipped` line for a section needing attention, then a summary or `nothing to migrate`, and SHALL exit 0. A rename failure after a successful write MUST still print what succeeded and exit 1.

#### Scenario: Outside a repository
- **WHEN** `cadence-hooks migrate-config` runs in a directory with no git root above it
- **THEN** it exits 1 and writes nothing

#### Scenario: One section migrated
- **WHEN** `.claude/redaction.json` exists and `.claude/cadence.json` holds only `{"version":1}`
- **THEN** it prints `wrote 'redaction' section`, renames the legacy file to `redaction.json.migrated`, keeps `version`, and exits 0

### Requirement: Version and help
`cadence-hooks --version` SHALL print `cadence-hooks <version>` and exit 0, and `--help` SHALL list the namespaces and the CLI commands. The version and help surface, `list`, `manifest`, `try`, `configure` and `migrate-config` MUST NOT read stdin.

#### Scenario: Version
- **WHEN** `cadence-hooks --version` runs
- **THEN** it prints `cadence-hooks ` followed by the package version and exits 0
