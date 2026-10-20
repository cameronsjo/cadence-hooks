# configuration Specification

## Purpose
The configuration surface every cadence-hooks guard reads: the per-repo `.claude/cadence.json` (ADR-0002), the `CADENCE_*` environment variables including the `CADENCE_BYPASS` and `CADENCE_DISABLE` switches and the owner allowlists, and the two commands that write configuration, `cadence-hooks migrate-config` and `cadence-hooks configure guardrails`.

## Requirements

### Requirement: One per-repo config file
Per-repo guard configuration SHALL be read only from `<git root>/.claude/cadence.json`, each guard reading its own top-level section (`terminology`, `redaction`, `nudges`, and the top-level boolean `feedbackFooter`) under a `version: 1` envelope. Unknown top-level keys MUST be ignored. The legacy `.claude/redaction.json` and `.claude/terminology.json` MUST NOT be read.

#### Scenario: Legacy file only
- **WHEN** a repo has `.claude/terminology.json` with exemptions and no `.claude/cadence.json`
- **THEN** the terminology guard applies no exemption, and `cadence-hooks doctor` warns that the legacy file is orphaned

#### Scenario: Section a newer binary would read
- **WHEN** `cadence.json` carries a top-level key this binary does not know
- **THEN** the `terminology` and `redaction` sections still apply

### Requirement: Config failures fail open
A missing, unreadable, non-regular, non-UTF-8 or larger than 1 MiB `cadence.json`, or one that does not parse, SHALL yield every guard's default configuration and MUST NOT block or error. A leading UTF-8 BOM, `//` and `/* */` comments, and trailing commas MUST be tolerated. Config can only remove or demote a guard's findings, never add a block.

#### Scenario: Malformed file
- **WHEN** `.claude/cadence.json` is not valid JSON
- **THEN** every guard runs with its built-in defaults, the tool call is not blocked for that reason, and `cadence-hooks doctor` warns that the file fails to parse

#### Scenario: Commented config
- **WHEN** `cadence.json` begins with a BOM and contains a `//` comment and a trailing comma
- **THEN** its sections are applied as if the file were strict JSON

### Requirement: A malformed key drops only that key
Within a section that is a JSON object, a top-level key with the wrong shape SHALL be dropped while the rest of the section applies, and the drop MUST be named in a warning naming the key as `<section>.<key>` with an invalid shape. An unknown key SHALL be named as ignored, and a section that is not an object SHALL be ignored with one warning.

#### Scenario: Bad categories beside a good allowlist
- **WHEN** the `redaction` section has a malformed `categories` value and a valid `allowlist`
- **THEN** the allowlist still suppresses its entries and the nudge names `redaction.categories` as ignored

### Requirement: Config warnings are bounded
Config warnings MUST echo a key name only through a restricted character set (letters, digits, `_ . - [ ]`, anything else shown as `?`), capped at 80 characters, so no newline or escape sequence from the file reaches hook output. A rendered warning list MUST be capped at five lines plus a count of the rest.

#### Scenario: Many bad keys
- **WHEN** a section carries 50 unknown keys
- **THEN** the hook message lists five warnings and `… and 45 more config anomalies`

### Requirement: Per-nudge suppression
The `nudges` map SHALL be keyed by registry hook name, with `suppress` either `true` (every call) or a list of globs matched against the tool call's file path: a pattern containing `/` matches the repo-relative path (`*` stops at `/`, `**` crosses it), and a bare pattern matches the basename. A glob list MUST NOT match a call with no file path inside the repo, so a Bash-shaped nudge is silenced only by `suppress: true`.

#### Scenario: Suppressing a nudge by path
- **WHEN** `nudges` has `"warn-main-branch": { "suppress": ["docs/**"] }` and an Edit to `docs/guide.md` would draw that nudge
- **THEN** the hook exits 0 with no nudge

### Requirement: Suppression never touches a block
Suppression MUST apply only to a nudge from a hook the registry marks suppressible, and MUST NOT change a block or an ask, or any protected or security-critical hook. A malformed entry or glob SHALL suppress nothing.

#### Scenario: A block cannot be suppressed
- **WHEN** `nudges` names `git-safety` with `suppress: true` and a command runs `git reset --hard`
- **THEN** the command is still blocked, and `cadence-hooks doctor` warns that the key names a hook a repo config cannot silence

### Requirement: Feedback footer
Every hard block's stderr message SHALL end with `If this fired in error: /cadence:feedback` unless `CADENCE_NO_FEEDBACK_FOOTER` is set to any non-empty value or the repo's `cadence.json` sets `feedbackFooter` to `false`. The environment variable MUST win without reading the config. Nudges and allows MUST NOT carry the footer.

#### Scenario: Env suppression
- **WHEN** `CADENCE_NO_FEEDBACK_FOOTER=1` is set and a guard blocks
- **THEN** the block message has no feedback footer

### Requirement: Repo-declared env flags
A guard that reads a flag from a repo's own settings (such as `CADENCE_ALLOW_MAIN`) SHALL read `env.<key>` from `<repo>/.claude/settings.local.json` first and `<repo>/.claude/settings.json` second, taking the first file where the key is a string, boolean or number. Missing files, absent keys, malformed JSON and null, array or object values MUST declare nothing and fall through.

#### Scenario: Local settings override
- **WHEN** `settings.json` sets `CADENCE_ALLOW_MAIN` to `"false"` and `settings.local.json` sets it to `true`
- **THEN** the repo reads as declaring `true`

### Requirement: Blanket bypass
`CADENCE_BYPASS` set to exactly `1` SHALL skip every enforcement hook, protected ones included, except `enforcement-status`. CLI and diagnostic commands (`list`, `manifest`, `configure`, `doctor`, `try`, `migrate-config`, `session declare|status|plans|timer`, `metrics grade|price`) MUST keep working under it. Each skipped invocation SHALL print one stderr line naming the switch.

#### Scenario: Bypassed guard
- **WHEN** `CADENCE_BYPASS=1` and a command runs `git reset --hard`
- **THEN** `git-safety` does not run and the command is not blocked

### Requirement: Selective disable
`CADENCE_DISABLE` SHALL be a comma-separated list of hook names matched exactly and case-sensitively after trimming. A named protected hook MUST still run (disable refused), any other named hook MUST NOT run, and a name matching no hook disables nothing. Each skipped or refused invocation SHALL print one stderr line naming the switch.

#### Scenario: Disabling a nudge
- **WHEN** `CADENCE_DISABLE=warn-main-branch` and an Edit on `main` runs
- **THEN** `warn-main-branch` does not run and stderr says it is disabled via `CADENCE_DISABLE`

#### Scenario: Disabling a protected guard is refused
- **WHEN** `CADENCE_DISABLE=git-safety` and a command runs `git clean -fd`
- **THEN** `git-safety` still runs and blocks it

#### Scenario: Near-miss name
- **WHEN** `CADENCE_DISABLE=Enforce-Worktree`
- **THEN** nothing is disabled and `cadence-hooks list` reports the name as matching no hook

### Requirement: Owner allowlist parsing
`CADENCE_ALLOWED_OWNERS`, `CADENCE_ALLOWED_REPOS` and `CADENCE_EXTRA_HOSTS` SHALL be read from the hook's process environment as lists split on any mix of whitespace and commas, compared case-insensitively. An entry SHALL be read as `owner`, `host/owner` (one `/` and a `.` in the first segment), `owner/repo` (one `/`, no `.`), or `host/owner/repo`.

#### Scenario: Comma-separated owners
- **WHEN** `CADENCE_ALLOWED_OWNERS="alice, bob"` and a push targets `github.com/bob/x`
- **THEN** the target counts as owned

### Requirement: Allowlist host scoping
A bare allowlist entry MUST match only the default host (`GH_HOST`, else `github.com`) and any host in `CADENCE_EXTRA_HOSTS`. A host-qualified entry SHALL match only its own host.

#### Scenario: Bare entry on a self-hosted forge
- **WHEN** `CADENCE_ALLOWED_OWNERS=cameron` without `CADENCE_EXTRA_HOSTS` and a push targets `git.example.org/cameron/x`
- **THEN** the target does not count as owned

### Requirement: Unset owner allowlist
When `CADENCE_ALLOWED_OWNERS` names no owner, the push and gh-write guards SHALL block owner-checked operations with a message saying the allowlist is not configured. `cadence-hooks configure guardrails` SHALL write `CADENCE_ALLOWED_OWNERS` (and optionally `CADENCE_ALLOWED_REPOS`) into the `env` block of the user settings file (`$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`), never a project file, migrating legacy `GIT_GUARDRAILS_ALLOWED_*` keys forward.

#### Scenario: Fresh machine push
- **WHEN** `CADENCE_ALLOWED_OWNERS` is unset and a `git push` reaches `guard-push-remote`
- **THEN** the push is blocked with the not-configured message, and, when the user settings file exists, `cadence-hooks doctor` warns that the allowlist is unset

### Requirement: Migrating legacy config
`cadence-hooks migrate-config` SHALL merge `.claude/redaction.json` and `.claude/terminology.json` into the matching sections of `.claude/cadence.json`, preserve every other top-level key, and rename each consumed file to `*.json.migrated`. It MUST NOT overwrite a section already present (and then leaves that legacy file in place), MUST be a no-op on a re-run, and MUST exit non-zero rather than write when `cadence.json` is not a JSON object.

#### Scenario: Existing section is kept
- **WHEN** `cadence.json` already has a `terminology` section and `.claude/terminology.json` also exists
- **THEN** the existing section is unchanged and `terminology.json` is not renamed

#### Scenario: Re-run
- **WHEN** `migrate-config` runs a second time after a successful run
- **THEN** it reports nothing to do and changes no file
