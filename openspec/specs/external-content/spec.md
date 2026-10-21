# external-content Specification

## Purpose
Checks on text about to leave the machine in an external post: `cadence-hooks cadence redact-external-content` (a PreToolUse hook on Bash, Write, Edit and write-shaped MCP tools), the `cadence-hooks cadence redact-scan` CLI action that runs the same engine on stdin or a file, and `cadence-hooks cadence warn-overshare`, a PreToolUse nudge to audit about-to-ship content for personal context. All three run unchanged in a cloud session.

## Requirements

### Requirement: Posting commands and their bodies
`redact-external-content` SHALL judge a Bash command one segment at a time and treat a segment as a post when it runs `gh pr|issue|release|gist|discussion create|comment|edit|review|reopen`, `gh pr merge`, `gh repo|label create|edit`, a `gh api` write, `git commit`, or `tea pr|issue create|comment|edit`. It SHALL scan only the flag values that segment posts, reading a `--body-file` it names. A quoted mention of a posting command MUST NOT count as a post.

#### Scenario: Sibling segment is not read
- **WHEN** the command is `gh secret set N --body-file f && gh pr comment 5 -b hi`
- **THEN** the hook scans only `hi` and never opens `f`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash call runs `ls -la` or `gh pr view 5`
- **THEN** the hook exits 0 with no output and does not load the term source

#### Scenario: Heredoc in a commit message
- **WHEN** `git commit -m "$(cat <<'EOF' ... EOF)"` carries body lines
- **THEN** those body lines are scanned as the commit message

### Requirement: Credential tokens in a post block
`redact-external-content` SHALL block (exit 2) a post whose text, as written or as the shell passes it, carries a credential token. This block MUST hold regardless of the identity tier's mode, `CADENCE_ALLOW_SENSITIVE_TERMS`, or any repo config, and any identity or shaped findings MUST follow it in the same message.

#### Scenario: Token in a PR body
- **WHEN** `gh pr create --body` carries a live-looking access token
- **THEN** the hook exits 2 even with `CADENCE_ALLOW_SENSITIVE_TERMS=1` set

### Requirement: Identity tier blocks work-identifiable terms
`redact-external-content` SHALL load work-identifiable terms from `$HOME/.config/cadence/redaction.toml` only, with no environment override, and block (exit 2) a post carrying one, with stderr headed `redact-external-content: BLOCKED` and each term named verbatim as `[<id>] <snippet>`. No repo file MUST be able to add, remove or soften a term; only an `allow` entry in the term source (by `path`, `pattern` or `destinations`) MAY excuse a match.

#### Scenario: Term in an issue body
- **WHEN** the term source lists a term and `gh issue create --body` contains it
- **THEN** the hook exits 2 and stderr names the term's id and the matched text

#### Scenario: Repo allowlist cannot excuse it
- **WHEN** `.claude/cadence.json` `redaction.allowlist` names the same term
- **THEN** the hook still exits 2

### Requirement: Identity tier softening switches
A term source with `mode = "warn"` SHALL turn identity findings into a nudge that says it is not blocking; a term source with no `mode` MUST block. `CADENCE_ALLOW_SENSITIVE_TERMS` set to any value other than empty or `0` SHALL downgrade an identity block to a nudge and MUST record a bypass row naming the switch. `redact-external-content` is a protected guard, so `CADENCE_DISABLE` MUST NOT turn it off.

#### Scenario: Bypass switch armed
- **WHEN** `CADENCE_ALLOW_SENSITIVE_TERMS=1` is in the hook's environment and a post carries an identity term
- **THEN** the hook exits 0 with a nudge saying the block was suppressed and a bypass row is written

#### Scenario: Disable request refused
- **WHEN** `CADENCE_DISABLE=redact-external-content` is set and a post carries an identity term
- **THEN** the hook still exits 2

### Requirement: Identity tier fails open on its own failure
When the term source is absent, unreadable, malformed, or carries zero terms, the identity tier SHALL be inert and the hook MUST allow on its account. The hook MUST NOT announce that state on every post; `redact-scan --status`, `doctor` and the plugin's SessionStart report it. When the tier is armed and a posted text could not be read (an unreadable `--body-file`, stdin), the hook SHALL say so on stderr without changing the verdict.

#### Scenario: Machine without a term source
- **WHEN** no `redaction.toml` exists and a post carries text that would match on another machine
- **THEN** the identity tier contributes nothing and the hook does not block on it

### Requirement: Identity scan of file writes
On Write, Edit and write-shaped MCP calls, `redact-external-content` SHALL run the identity tier only, over introduced text, blocking only on occurrences beyond those already in the edit's `old_string`. It MUST skip the term source itself, and MUST skip a code or config file proven local (a home dotfile, `~/.config`, `~/.local`, `~/.cache` or a temp dir, outside any repo, sync tree or remote mount). A prose draft and an MCP write with no path MUST still be scanned.

#### Scenario: Prose draft in a temp directory
- **WHEN** a Write to `/tmp/pr-body.md` introduces an identity term
- **THEN** the hook exits 2

#### Scenario: Term carried through an edit
- **WHEN** an Edit's `old_string` holds an identity term once and its `new_string` holds it once
- **THEN** the hook exits 0

### Requirement: Shaped tier nudges on harness vocabulary
`redact-external-content` SHALL scan posted bodies for four categories, `skill-id` (a skill id such as `cadence:attune`), `marketplace` (plugin-cache paths), `local-path` (`/Users/...`, `~/.claude/...`) and `harness-noun` (`tool_input`, `tool_response`), and nudge, never block, on a hit. The shaped tier MUST NOT run on Write or Edit calls, and repeated hits MUST each be listed.

#### Scenario: Skill id in a public PR
- **WHEN** `gh pr create --body` mentions `cadence:attune`, no audience is configured, and the target repo is not an owned repo
- **THEN** the hook exits 0 with a nudge listing the `skill-id` hit

### Requirement: Audience tiers decide which shaped hits report
A shaped hit SHALL report only when the destination tier is wider than its ceiling. Tiers run `owned-internal`, `private-external`, `public`; built-in ceilings are `owned-internal`, and `always` reports everywhere. The destination tier MUST come from `CADENCE_AUDIENCE`, then the config's `originAudience`, then `public`; an unknown value MUST read as `public`. When every post target is owned per `CADENCE_ALLOWED_OWNERS`, `skill-id`, `marketplace` and `harness-noun` hits MUST be dropped.

#### Scenario: Owned-internal audience
- **WHEN** `CADENCE_AUDIENCE=owned-internal` and a commit message mentions `tool_input`
- **THEN** the hook exits 0 with no shaped nudge

#### Scenario: Unknown audience value
- **WHEN** `CADENCE_AUDIENCE=everyone` and a post mentions `~/.claude/settings.json`
- **THEN** the hook nudges as for `public`

### Requirement: Per-repo redaction config
The `redaction` section of `.claude/cadence.json` SHALL tune the shaped tier only: `originAudience`, per-category `ceiling`, `additionalPatterns` and `allowlist`. A malformed key MUST be dropped and named in the nudge. A post to a repo that is none of the checkout's remotes MUST NOT inherit the checkout's allowlist, ceilings or `originAudience`. A post carrying a fenced block over 40 lines to a stated `public` audience SHALL add a pasted-output nudge.

#### Scenario: Post to a foreign repo
- **WHEN** the checkout's allowlist covers a hit and the post runs `gh issue create -R other/repo`
- **THEN** the hit is still reported, with a note naming the foreign destination

### Requirement: redact-scan CLI scan
`cadence-hooks cadence redact-scan` SHALL scan stdin, or the file named by `--file`, with the same identity and shaped tiers, printing each shaped hit to stderr as `[<category>]:<line>:<snippet>`. Exit MUST be 0 when clean, 1 on a shaped hit or an enforced identity hit, and 2 on a usage error (a bad `--audience` or `--repo`, an unreadable file). `--repo OWNER/REPO` names the destination; the audience is `--audience`, then `CADENCE_AUDIENCE`, then config, then `public`.

#### Scenario: Clean body
- **WHEN** `echo "Fixes the parser" | cadence-hooks cadence redact-scan` runs
- **THEN** it exits 0 with no hit lines

#### Scenario: Shaped hit
- **WHEN** the scanned text mentions `tool_response` with no audience set
- **THEN** stderr carries `[harness-noun]:1:tool_response` and the exit status is 1

#### Scenario: Unarmed identity tier
- **WHEN** no term source exists
- **THEN** stderr carries one line saying the identity tier is not armed and the exit status is unchanged

### Requirement: redact-scan status, validation and init
`redact-scan --status` SHALL print whether the identity tier is armed, with its mode, `term_count` and `term_digest` when armed, and exit 0 armed or 1 not armed. `--validate-config` SHALL exit 0 for a valid term source and 2 with each problem on stderr. `--init` SHALL add a starter `redaction` section to `<git root>/.claude/cadence.json`, leave an existing section unchanged, and refuse (exit 2) to write through a symlink or into invalid JSON.

#### Scenario: Status without a term source
- **WHEN** `cadence-hooks cadence redact-scan --status` runs with no `redaction.toml`
- **THEN** it prints a line containing `redaction identity tier: NOT ARMED` and exits 1

#### Scenario: Init on an existing section
- **WHEN** `.claude/cadence.json` already has a `redaction` section and `--init` runs
- **THEN** the file is unchanged and the exit status is 0

### Requirement: Overshare audit triggers
`cadence warn-overshare` SHALL nudge, never block, with a `Pre-ship audit:` message asking the model to check outgoing content for personal context, on a Bash command carrying `git push` or a posting segment as defined for `redact-external-content` (a `gh api` write that posts no prose field excepted), and on a Write, Edit or MultiEdit to a path containing `/docs/field-reports/`. Reads, views and listings MUST be allowed.

#### Scenario: Push nudges
- **WHEN** a Bash call runs `git push origin main`
- **THEN** the hook exits 0 with a nudge containing `overshare`

#### Scenario: Ordinary command is allowed
- **WHEN** a Bash call runs `gh pr view 5` or `git status`
- **THEN** the hook exits 0 with no output

#### Scenario: Quoted mention
- **WHEN** the command is `echo 'docs: gh pr comment usage'`
- **THEN** the hook exits 0 with no output

### Requirement: Overshare audit escapes
`warn-overshare` SHALL allow a write whose path starts with a non-empty `OBSIDIAN_VAULT`. With `CADENCE_SKIP_OVERSHARE_AUDIT=1` exactly, it SHALL allow every call and record a bypass row only for a call that would have nudged; any other value MUST NOT silence it. It MAY also be silenced through the `nudges` map of `.claude/cadence.json`.

#### Scenario: Vault write
- **WHEN** `OBSIDIAN_VAULT=/vault` and a Write targets `/vault/docs/field-reports/x.md`
- **THEN** the hook exits 0 with no output

#### Scenario: Skip switch on an unrelated call
- **WHEN** `CADENCE_SKIP_OVERSHARE_AUDIT=1` is set and a Bash call runs `ls`
- **THEN** the hook exits 0 and records no bypass row
