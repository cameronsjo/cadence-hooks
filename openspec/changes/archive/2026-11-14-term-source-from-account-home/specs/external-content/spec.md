## MODIFIED Requirements

### Requirement: Identity tier blocks work-identifiable terms
`redact-external-content` SHALL load work-identifiable terms from `<account home>/.config/cadence/redaction.toml` only (the account database home, never `HOME` or `USERPROFILE`) and block (exit 2) a post carrying one, with stderr headed `redact-external-content: BLOCKED` and each term named verbatim as `[<id>] <snippet>`. No repo file MUST be able to add, remove or soften a term; only an `allow` entry in the term source (by `path`, `pattern` or `destinations`) MAY excuse a match.

#### Scenario: Term in an issue body
- **WHEN** the term source lists a term and `gh issue create --body` contains it
- **THEN** the hook exits 2 and stderr names the term's id and the matched text

#### Scenario: Repo allowlist cannot excuse it
- **WHEN** `.claude/cadence.json` `redaction.allowlist` names the same term
- **THEN** the hook still exits 2

#### Scenario: HOME set by a repo env block
- **WHEN** the hook's environment sets `HOME` to a directory with no term source and the account home has one
- **THEN** the term source in the account home is loaded and a post carrying one of its terms exits 2

### Requirement: Identity tier fails open on its own failure
When the term source is absent, malformed, or carries zero terms, the identity tier SHALL be inert and the hook MUST allow on its account. The hook MUST NOT announce an inert state per post; `redact-scan --status`, `doctor` and SessionStart report it. When the tier is armed and a posted text could not be read (an unreadable `--body-file`, stdin), the hook SHALL say so on stderr without changing the verdict.

#### Scenario: Machine without a term source
- **WHEN** no `redaction.toml` exists and a post carries text that would match on another machine
- **THEN** the identity tier contributes nothing and the hook does not block on it

### Requirement: redact-scan CLI scan
`cadence-hooks cadence redact-scan` SHALL scan stdin, or the file named by `--file`, with the same identity and shaped tiers, printing each shaped hit to stderr as `[<category>]:<line>:<snippet>`. Exit MUST be 0 when clean, 1 on a shaped hit, an enforced identity hit or an unreadable source, and 2 on a usage error (a bad `--audience` or `--repo`, an unreadable file). `--repo OWNER/REPO` names the destination; the audience is `--audience`, then `CADENCE_AUDIENCE`, then config, then `public`.

#### Scenario: Clean body
- **WHEN** `echo "Fixes the parser" | cadence-hooks cadence redact-scan` runs
- **THEN** it exits 0 with no hit lines

#### Scenario: Shaped hit
- **WHEN** the scanned text mentions `tool_response` with no audience set
- **THEN** stderr carries `[harness-noun]:1:tool_response` and the exit status is 1

#### Scenario: Unarmed identity tier
- **WHEN** no term source exists
- **THEN** stderr carries one line saying the identity tier is not armed and the exit status is unchanged

## ADDED Requirements

### Requirement: Unreadable term source blocks posts
When the term source exists but cannot be read, `redact-external-content` MUST block (exit 2) every post and commit message, naming the path and the fix, and `redact-scan` MUST exit 1 with the same message. An absent file MUST NOT trigger either.

#### Scenario: Term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file (permissions on it or its directory, a dangling link, a directory) and a Bash call posts any text or runs `git commit` with a message
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: redact-scan on a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and `redact-scan` scans a clean body
- **THEN** it exits 1 and stderr carries the same message
