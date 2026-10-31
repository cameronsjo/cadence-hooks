# doctor Specification

## Purpose
`cadence-hooks doctor` audits the hook wiring Claude Code will run on this machine: installed plugin `hooks.json` files, settings files, telemetry ledgers and the plugin cache. It reports findings as errors, warnings and notes, has a quiet SessionStart preflight mode, and a `--prune` mode for orphaned plugin-cache version directories.

## Requirements

### Requirement: Scan source
Without `--root`, `doctor` SHALL scan only the active installs named in `<plugins dir>/installed_plugins.json` (the plugins dir is `<Claude config dir>/plugins` when it exists, else `$HOME/.claude/plugins`), and MUST fall back to a recursive walk of `<plugins dir>/cache` only when that manifest is missing or unparseable. With `--root DIR`, it SHALL walk `DIR` recursively for `hooks/hooks.json` at any depth and MUST NOT run any live-machine check (telemetry, settings, cache health, repo config).

#### Scenario: Stale cached version is not scanned
- **WHEN** the plugin cache holds an old version directory whose `hooks.json` names a retired subcommand, and the manifest pins a newer version
- **THEN** `doctor` reports no skew for the old directory

#### Scenario: Fixture tree under --root
- **WHEN** `cadence-hooks doctor --root ./plugins` runs on a tree laid out as `<marketplace>/<plugin>/<sha>/hooks/hooks.json`
- **THEN** every `hooks.json` in the tree is scanned and findings are labelled with the plugin path, and stale metrics on the machine produce no finding

### Requirement: Wiring defects
For each hook command in a scanned `hooks.json`, `doctor` SHALL report: a single-quoted env-var expansion (such as `'${CLAUDE_PLUGIN_ROOT}'`) as an error; a `cadence-hooks` subcommand that lives under another namespace, or is absent from this binary, as a warning naming the binary version; a third-party CLI in command position that `PATH` cannot resolve as a warning; and a command that may block on empty stdin (`cat`, `jq` or `read` with no input) as an advisory warning.

#### Scenario: Single-quoted plugin root
- **WHEN** a plugin's `hooks.json` command is `'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' cadence terminology`
- **THEN** `doctor` prints an `error` finding that the single-quoted env var won't expand in /bin/sh and exits 2

#### Scenario: Unknown subcommand
- **WHEN** a wired command names `cadence future-hook`, which this binary lacks
- **THEN** a `warning` says the subcommand is not present in this binary and the fix names the upgrade path for the install channel (Homebrew, cargo, or the releases page)

### Requirement: Finding output is sanitized
Each finding SHALL print as `<level> [<plugin>] <file>[:line]: <diagnosis>` followed by `command:` and `fix:` lines, errors first, then warnings, then notes. Every file-sourced field MUST be stripped of terminal escape, C1 control, bidi and tag characters and bounded in length, while ordinary Unicode text is kept.

#### Scenario: Hostile plugin label
- **WHEN** an `installed_plugins.json` key contains an ANSI escape and a right-to-left override
- **THEN** the printed finding contains neither character

### Requirement: Group entries judged per member
A `cadence-hooks group ...` entry SHALL be judged member by member, so one stale member is reported by name. A member that is not in `<namespace>/<hook>` form, is not a tool-event check, is split or joined by quoting, or a flag on the group entry, MUST each be reported as a finding that counts as a wired hook not running.

#### Scenario: One stale group member
- **WHEN** a group entry lists `cadence/git-safety cadence/no-such-hook`
- **THEN** only `no-such-hook` is reported and `git-safety` is not

### Requirement: Plugin and cache health checks
In default mode without `--root`, `doctor` SHALL warn about: an installed hook-shipping plugin with no `enabledPlugins` entry (an explicit `false` stays silent); a plugin removed from its marketplace (in place of a skew warning for it); a pinned cache directory that is missing or empty; orphaned cache version directories; deployed cadence rules that differ from the pinned copy; and a marketplace checkout whose `origin` differs from its declared source.

#### Scenario: Installed but not enabled
- **WHEN** a plugin that ships `hooks/hooks.json` is installed and `settings.json` has a non-empty `enabledPlugins` map with no key for it
- **THEN** `doctor` warns that none of its hooks can fire

#### Scenario: Explicitly disabled plugin
- **WHEN** the plugin's `enabledPlugins` value is `false`
- **THEN** no unenabled finding is reported for it

### Requirement: Telemetry and environment checks
In default mode without `--root`, `doctor` SHALL warn about: stale or flatlined telemetry; fail-open telemetry over its thresholds in the last 7 days; slow hooks found in session logs; a metrics ledger of 64 MiB or more; a last `metrics rotate` success over 3 days old (or none with segments); archives over 500 MiB; a working or Claude config directory inside a cloud-synced tree; and inert `Bash(...)` rows in `permissions.deny` or `permissions.ask` of the user and project settings files.

#### Scenario: Oversized ledger
- **WHEN** a `*.jsonl` file in the metrics directory is 64 MiB
- **THEN** `doctor` warns about it and deletes nothing

#### Scenario: Archive not running
- **WHEN** `state/rotate.last-success` is 4 days old
- **THEN** `doctor` warns and names the `metrics_rotate_failed` rows to read

### Requirement: Configuration health checks
In default mode without `--root`, `doctor` SHALL warn about an unset `CADENCE_ALLOWED_OWNERS` or leftover `GIT_GUARDRAILS_ALLOWED_*` keys in the user settings, and, for the current repo, a leftover `.claude/redaction.json` or `.claude/terminology.json`, an unparseable `.claude/cadence.json`, and invalid `nudges` or `feedbackFooter` entries. Every check in default mode MUST fail open: an unreadable or malformed input yields no finding about itself unless that is what the check reports.

#### Scenario: Malformed repo config
- **WHEN** the current repo's `.claude/cadence.json` is not valid JSON
- **THEN** `doctor` warns that it fails to parse and exits 1

### Requirement: Exit status of the full report
The full report SHALL exit 0 when there are no errors or warnings (notes alone still print `cadence-hooks doctor: clean (<scanned> scanned)`), 1 when there are warnings but no errors, and 2 when there is at least one error. It MUST exit 2 with a stderr message, never 0, for a configuration error: a `--root` that does not exist, `$HOME` unset, or no manifest and no plugin cache. A failing run SHALL end with `cadence-hooks doctor: <n> error(s), <m> warning(s)`.

#### Scenario: Nonexistent root
- **WHEN** `cadence-hooks doctor --root /no/such/dir` runs
- **THEN** stderr names the missing scan root and the exit status is 2

#### Scenario: Warnings only
- **WHEN** the only finding is a stale-telemetry warning
- **THEN** the exit status is 1

### Requirement: Quiet SessionStart preflight
`doctor --quiet` SHALL report only blockers, meaning a wired hook is not running: shell-expansion errors, a wiring naming a subcommand or namespace this binary lacks, an unparseable or unrunnable group member, a missing CLI dependency, a hook-shipping plugin with no `enabledPlugins` entry, and a missing or empty pinned cache directory. With no blockers it MUST print nothing and exit 0. With blockers it SHALL exit 2 when any is an error, else 0.

#### Scenario: Clean preflight
- **WHEN** `cadence-hooks doctor --quiet` runs and only hook-latency or orphan warnings exist
- **THEN** stdout is empty and the exit status is 0

#### Scenario: Configuration error under --quiet
- **WHEN** `$HOME` is unset and `--quiet` is given
- **THEN** a one-error envelope goes to stdout, the detail goes to stderr, and the exit status is 2

### Requirement: Quiet envelope carries no plugin text
With blockers, `doctor --quiet` SHALL print to stdout one `<cadence-system-message>` envelope holding only the version and counts (`N error(s) and M inert hook wiring(s)`), plus an upgrade hint only when a subcommand is missing. It MUST NOT interpolate plugin-supplied text, and SHALL print at most once per day per distinct blocker set. A blocker in a plugin set to `false` in `enabledPlugins`, or in a project-scope install for another project, MUST be demoted to advisory.

#### Scenario: Inert wiring only
- **WHEN** a wired subcommand is missing from this binary and there are no errors
- **THEN** stdout holds one envelope naming `0 error(s) and 1 inert hook wiring(s)` and the exit status is 0

### Requirement: Enforcement switches are reported first
`doctor` SHALL run under `CADENCE_BYPASS=1`. Ahead of any finding it MUST report the enforcement state: the full report prints the bypass banner and every `CADENCE_DISABLE` entry as honoured, refused (protected), moot, or matching no hook; `--quiet` prints only what is really off (the `CADENCE_BYPASS=1` banner and the honoured-disable line) to stdout, without changing the exit status.

#### Scenario: Bypassed session preflight
- **WHEN** `CADENCE_BYPASS=1` is set and `doctor --quiet` finds no blockers
- **THEN** stdout carries the bypass banner and the exit status is 0

### Requirement: Prune is a dry run by default
`doctor --prune` SHALL list orphaned plugin-cache version directories (siblings of a pinned install directory that no manifest entry pins) with their sizes, delete nothing, and exit 0. Only `--prune --apply` MUST remove them. A missing manifest SHALL report nothing to prune with exit 0.

#### Scenario: Dry run
- **WHEN** `cadence-hooks doctor --prune` runs with two orphaned directories
- **THEN** it prints both with sizes, says `dry-run, nothing deleted`, removes nothing and exits 0

### Requirement: Prune flag validation
`--apply`, `--keep-newest N` or `--older-than AGE` without `--prune` MUST be a usage error with exit 2. `--older-than` SHALL accept a whole number with an `s`, `m`, `h`, `d` or `w` suffix and MUST reject a bare number, zero, or any other suffix.

#### Scenario: Apply without prune
- **WHEN** `cadence-hooks doctor --apply` runs
- **THEN** stderr says `--apply requires --prune` and the exit status is 2

#### Scenario: Bare age
- **WHEN** `cadence-hooks doctor --prune --older-than 7` runs
- **THEN** it is rejected as a usage error

### Requirement: Prune never removes what a session may be reading
`doctor --prune --apply` MUST NOT remove a directory outside the plugin cache, a pinned install, or a directory a pin resolves onto through a symlink. Without bounds, it SHALL refuse (stderr message, nothing deleted, exit 0) when a live session is registered, when a registry cannot be listed, when running `claude` processes outnumber registered sessions, or when processes cannot be enumerated. If any pin present before the prune is gone after it, the run MUST exit 2.

#### Scenario: Live peer refuses the prune
- **WHEN** a peer session's registry record is fresh and `doctor --prune --apply` runs without bounds or force
- **THEN** stderr says it is refusing to prune, every directory remains, and the exit status is 0

### Requirement: Bounded and forced prune
With `--keep-newest` or `--older-than`, `doctor --prune --apply` SHALL decide per directory and delete one only when its `.orphaned_at` stamp is readable, it is outside the newest N, older than the age, and orphaned before every live session started; a live session that cannot vouch for its start keeps every directory. `CADENCE_DOCTOR_PRUNE_FORCE` set to `1` or `true` SHALL override the live-session checks but not the bounds.

#### Scenario: Force override
- **WHEN** `doctor --prune --apply` runs with a live peer and `CADENCE_DOCTOR_PRUNE_FORCE=1`
- **THEN** the orphaned directories are removed and the pinned install remains
