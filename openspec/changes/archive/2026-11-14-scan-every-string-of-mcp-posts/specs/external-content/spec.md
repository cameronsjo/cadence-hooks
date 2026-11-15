## MODIFIED Requirements

### Requirement: Unreadable term source blocks posts
When the term source exists but cannot be read, `redact-external-content` MUST block (exit 2) every post and commit message, and every `mcp__*` call that carries a string, except a call to a local tool or one whose content is a local file's, naming the path and the fix, and `redact-scan` MUST exit 1 with the same message. An absent file MUST NOT trigger either.

#### Scenario: Term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file (permissions on it or its directory, a dangling link, a directory) and a Bash call posts any text or runs `git commit` with a message
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: MCP post with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an `mcp__github__create_issue` call carries a clean `body`
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: redact-scan on a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and `redact-scan` scans a clean body
- **THEN** it exits 1 and stderr carries the same message

### Requirement: Identity scan of file writes
On Write and Edit calls, `redact-external-content` SHALL run the identity tier only, over introduced text, blocking only on occurrences beyond those already in the edit's `old_string`. It MUST skip the term source itself, and MUST skip a code or config file proven local (a home dotfile, `~/.config`, `~/.local`, `~/.cache` or a temp dir, outside any repo, sync tree or remote mount). A prose draft MUST still be scanned.

#### Scenario: Prose draft in a temp directory
- **WHEN** a Write to `/tmp/pr-body.md` introduces an identity term
- **THEN** the hook exits 2

#### Scenario: Term carried through an edit
- **WHEN** an Edit's `old_string` holds an identity term once and its `new_string` holds it once
- **THEN** the hook exits 0

## ADDED Requirements

### Requirement: Identity scan of MCP calls
On an `mcp__*` call, `redact-external-content` SHALL run the identity tier over every string value in the call's input at any depth, object keys included, read from the payload as sent so a field that fails the typed parse is still read. The top-level `file_path`/`path` MUST NOT be scanned. The shaped tier MUST NOT run on MCP calls.

#### Scenario: Issue body through an MCP tool
- **WHEN** an `mcp__github__create_issue` call carries an identity term only in `body`
- **THEN** the hook exits 2

#### Scenario: Term in a nested block array
- **WHEN** an MCP call carries an identity term only in a string nested in an array of objects
- **THEN** the hook exits 2

#### Scenario: Term only in the target path
- **WHEN** an MCP write's `path` names a directory holding an identity term and its `content` is clean
- **THEN** the hook exits 0

### Requirement: MCP command strings are scanned
On an `mcp__*` call, a `command` or `cmd` string SHALL be scanned like any other string, except the key the Bash surface reads (`command`, else `cmd`) on a local shell tool (`mcp__iterm__write_to_terminal`). A shell `command` SHALL also get the Bash-surface checks.

#### Scenario: Command sent to a server
- **WHEN** an `mcp__slack__run_command` call's `command` holds an identity term
- **THEN** the hook exits 2

#### Scenario: Command a local terminal runs
- **WHEN** an `mcp__iterm__write_to_terminal` call's `command` is `cd ~/<term-dir> && ls`
- **THEN** the hook exits 0

### Requirement: Credential scan of MCP calls
On every `mcp__*` call, local tools included, `redact-external-content` SHALL run the credential tier over the strings the identity scan reads, with or without a term source and in every identity mode. A token MUST block, and no bypass applies.

#### Scenario: Token in an MCP issue body
- **WHEN** an `mcp__github__create_issue` call carries a GitHub token only in `body` and no term source exists
- **THEN** the hook exits 2 and the message names the token's kind without the token

#### Scenario: MCP edit removes a token
- **WHEN** an MCP edit's `old_string` holds a token and its `new_string` does not
- **THEN** the hook exits 0

#### Scenario: Token typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call's `text` holds a token
- **THEN** the hook exits 2

### Requirement: Local MCP tools skip the identity tier
The identity tier MUST NOT run on a call to a local tool: `c3` `compact`, `model` or `rename`, `easel` `chart`, `herdr-bridge` `panes` or `read`, or a `rea` tool whose name neither starts with `capture_` or `observe_` nor contains `web` or `browser`. Server and tool are the text after `mcp__` split at the next `__`, matched exactly; a tool segment holding another `__` is not a local tool. Every other call SHALL get the identity tier, and every call SHALL get the credential tier.

#### Scenario: Local tool call
- **WHEN** an `mcp__herdr-bridge__read` call carries an identity term
- **THEN** the hook exits 0

#### Scenario: Prompt typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call carries an identity term
- **THEN** the hook exits 2

#### Scenario: Server that only resembles a listed one
- **WHEN** an `mcp__c3x__post` call carries an identity term
- **THEN** the hook exits 2

### Requirement: MCP path exemptions cover the file content only
When an MCP call's `file_path` or `path` is the term source or a code or config file proven local, the top-level new-side keys, old-side keys and `edits` MUST NOT be scanned, and every other string in the call MUST still be scanned.

#### Scenario: Comment beside a local attachment
- **WHEN** an MCP call's `path` is a config file in a temp dir and its `initial_comment` holds an identity term
- **THEN** the hook exits 2

### Requirement: MCP edits count against their old-side text
In an MCP call, a string under an old-side key (`old_string`, `oldString`, `old_str`, `old_text`, `oldText`) beside a new-side string MUST NOT be scanned; with no new-side sibling it SHALL be scanned like any other string. A new-side string beside it (`new_string`, `newString`, `new_str`, `new_text`, `newText`, `content`) MUST block only on each term's occurrences beyond that term's occurrences in the old-side text; any other string beside it MUST be scanned in full.

#### Scenario: MCP edit removes a term
- **WHEN** an MCP edit's `oldText` holds an identity term and its `newText` does not
- **THEN** the hook exits 0

#### Scenario: MCP edit adds an occurrence
- **WHEN** an MCP edit's `oldText` holds an identity term once and its `newText` holds it twice
- **THEN** the hook exits 2
