## MODIFIED Requirements

### Requirement: Identity tier blocks work-identifiable terms
`redact-external-content` SHALL load work-identifiable terms from `<account home>/.config/cadence/redaction.toml` only (the home from the user database, never `HOME`) and block (exit 2) a post carrying one, with stderr headed `redact-external-content: BLOCKED` and each term named verbatim as `[<id>] <snippet>`. No repo file MUST be able to add, remove or soften a term; only an `allow` entry in the term source (by `path`, `pattern` or `destinations`) MAY excuse a match.

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

## ADDED Requirements

### Requirement: Unreadable term source blocks posts
When the term source exists but cannot be read, `redact-external-content` MUST block (exit 2) every post and commit message, naming the path and the fix. An absent file MUST NOT trigger this block.

#### Scenario: Term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file (permissions on it or its directory, a dangling link, a directory) and a Bash call posts any text or runs `git commit`
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line
