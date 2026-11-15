## MODIFIED Requirements

### Requirement: Unreadable term source blocks posts
When the term source exists but cannot be read, `redact-external-content` MUST block (exit 2) every post and commit message, and every `mcp__*` call, other than one to a local tool, that carries any string the identity tier reads, object keys included, naming the path and the fix, and `redact-scan` MUST exit 1 with the same message. An absent file MUST NOT trigger either.

#### Scenario: Term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file (permissions on it or its directory, a dangling link, a directory) and a Bash call posts any text or runs `git commit` with a message
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: MCP post with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an `mcp__github__create_issue` call carries a clean `body`
- **THEN** the hook exits 2 and stderr names the path and a `Fix:` line

#### Scenario: Empty MCP call with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP call's input is `{}`
- **THEN** the hook exits 0

#### Scenario: MCP call with only a key and a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP call's input is `{"page": 2}`
- **THEN** the hook exits 2

#### Scenario: Local path with a term source that cannot be read
- **WHEN** `redaction.toml` exists but is not a readable regular file and an MCP write names a provably local path and carries a `title` beside its `content`
- **THEN** the hook exits 2

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
On an `mcp__*` call, `redact-external-content` SHALL run the identity tier over every string value in the call's input at any depth, object keys included, read from the payload as sent so a field that fails the typed parse is still read. The top-level `file_path`/`path` SHALL be scanned like any other string. The shaped tier MUST NOT run on MCP calls.

#### Scenario: Issue body through an MCP tool
- **WHEN** an `mcp__github__create_issue` call carries an identity term only in `body`
- **THEN** the hook exits 2

#### Scenario: Term in a nested block array
- **WHEN** an MCP call carries an identity term only in a string nested in an array of objects
- **THEN** the hook exits 2

#### Scenario: Term only in a local-looking path
- **WHEN** an MCP write's `path` is an absolute path in a system temp dir naming a directory that holds an identity term, and its `content` is clean
- **THEN** the hook exits 2

#### Scenario: Term in a repo file path
- **WHEN** an `mcp__github__create_or_update_file` call's `path` is `docs/<term>-notes.md` and its `content` is clean
- **THEN** the hook exits 2

### Requirement: MCP command strings are scanned
On an `mcp__*` call, a `command` or `cmd` string SHALL be scanned like any other string. On a local shell tool (`mcp__iterm__write_to_terminal`), the key the Bash surface reads (`command`, else `cmd`) MUST NOT get the identity tier; the credential tier SHALL still read it. A shell `command` SHALL also get the Bash-surface checks, and a nudge from the string scan SHALL be shown beside their result.

#### Scenario: Command sent to a server
- **WHEN** an `mcp__slack__run_command` call's `command` holds an identity term
- **THEN** the hook exits 2

#### Scenario: Command a local terminal runs
- **WHEN** an `mcp__iterm__write_to_terminal` call's `command` is `cd ~/<term-dir> && ls`
- **THEN** the hook exits 0

#### Scenario: Token in a local terminal command
- **WHEN** an `mcp__iterm__write_to_terminal` call's `command` holds a token
- **THEN** the hook exits 2

#### Scenario: Warn-mode finding beside a command
- **WHEN** the term source is in warn mode and an MCP call carries `command: ls` and an identity term in `body`
- **THEN** the hook exits 0 and shows the finding

### Requirement: Credential scan of MCP calls
On every `mcp__*` call, local tools included, `redact-external-content` SHALL run the credential tier over every string in the input, the top-level `file_path`/`path`, the content beside any path and old-side edit text included, with or without a term source and in every identity mode. A token MUST block, and no bypass applies.

#### Scenario: Token in an MCP issue body
- **WHEN** an `mcp__github__create_issue` call carries a GitHub token only in `body` and no term source exists
- **THEN** the hook exits 2 and the message names the token's kind without the token

#### Scenario: MCP edit removes a token
- **WHEN** an MCP edit's `old_string` holds a token and its `new_string` does not
- **THEN** the hook exits 2, since the server receives the old side too

#### Scenario: Token typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call's `text` holds a token
- **THEN** the hook exits 2

#### Scenario: Token in a file path
- **WHEN** an MCP write's `path` holds a token, local or not
- **THEN** the hook exits 2

### Requirement: Local MCP tools skip the identity tier
The identity tier MUST NOT run on a call to a local tool: `c3` `compact`, `model` or `rename`, `easel` `chart`, `herdr-bridge` `panes` or `read`, or a `rea` tool on the binary's list of rea tools that neither launch a process, reach the network, nor write files. Server and tool are the text after `mcp__` split at the next `__`, matched exactly; a tool holding another `__` is not local. Every other call SHALL get the identity tier, and every call SHALL get the credential tier.

#### Scenario: Local tool call
- **WHEN** an `mcp__herdr-bridge__read` call carries an identity term
- **THEN** the hook exits 0

#### Scenario: Prompt typed into another agent
- **WHEN** an `mcp__herdr-bridge__send` call carries an identity term
- **THEN** the hook exits 2

#### Scenario: Server that only resembles a listed one
- **WHEN** an `mcp__c3x__post` call carries an identity term
- **THEN** the hook exits 2

#### Scenario: rea tool that reaches a process or the network
- **WHEN** an `mcp__rea__gdb_console` call carries an identity term
- **THEN** the hook exits 2

### Requirement: No path exemption on MCP calls
An MCP call's `file_path` or `path` MUST NOT exempt any string from either tier, whatever it names, and a `path`-scoped allow entry MUST NOT apply to an MCP call: whether a path is local is known only for this machine, and the server that receives the call may be remote. The term source, a code or config file proven local and `~/.ssh/config` are exempt on `Write` and `Edit` only.

#### Scenario: Token beside a local-looking path
- **WHEN** an `mcp__sandbox__write_file` call's `path` is `/tmp/notes.json` and its `content` holds a token
- **THEN** the hook exits 2

#### Scenario: Local source and remote destination
- **WHEN** an MCP call's `file_path` is a provably local path and its `path` is `docs/<term>.md`
- **THEN** the hook exits 2

#### Scenario: Path-scoped allow entry on an MCP call
- **WHEN** the term source holds an allow entry scoped to `path = "docs/"` and an `mcp__github__create_or_update_file` call's `path` is `docs/x.md` with an identity term in `content`
- **THEN** the hook exits 2

### Requirement: MCP edits count against their old-side text
In an MCP call, a string under an old-side key (`old_string`, `oldString`, `old_str`, `old_text`, `oldText`) beside a new-side string MUST NOT get the identity tier; with no new-side sibling it SHALL get it. The credential tier reads it either way. A new-side string beside it (`new_string`, `newString`, `new_str`, `new_text`, `newText`, `content`) MUST block only on each term's occurrences beyond that term's occurrences in the old-side text; any other string beside it MUST be scanned in full.

#### Scenario: MCP edit removes a term
- **WHEN** an MCP edit's `oldText` holds an identity term and its `newText` does not
- **THEN** the hook exits 0

#### Scenario: MCP edit adds an occurrence
- **WHEN** an MCP edit's `oldText` holds an identity term once and its `newText` holds it twice
- **THEN** the hook exits 2
