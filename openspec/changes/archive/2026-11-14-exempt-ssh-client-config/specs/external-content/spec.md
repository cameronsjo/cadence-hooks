## MODIFIED Requirements

### Requirement: Identity scan of file writes
On Write, Edit and write-shaped MCP calls, `redact-external-content` SHALL run the identity tier only, over introduced text, blocking only on occurrences beyond those already in the edit's `old_string`. It MUST skip the term source itself, and MUST skip a code or config file proven local (a home dotfile, `~/.ssh/config`, `~/.config`, `~/.local`, `~/.cache` or a temp dir, outside any repo, sync tree or remote mount). A prose draft and an MCP write with no path MUST still be scanned.

#### Scenario: Prose draft in a temp directory
- **WHEN** a Write to `/tmp/pr-body.md` introduces an identity term
- **THEN** the hook exits 2

#### Scenario: Term carried through an edit
- **WHEN** an Edit's `old_string` holds an identity term once and its `new_string` holds it once
- **THEN** the hook exits 0

## ADDED Requirements

### Requirement: SSH client config is the one exempt file under ~/.ssh
`~/.ssh/config` SHALL count as a local config file for the file-write exemption only as that exact resolved path under the account home, read as config rather than a prose draft. No other path under `~/.ssh`, no path with a `..` component, and no `~/.ssh/config` that resolves elsewhere MUST be exempt by it; `~/.aws/config` and `~/.kube/config` MUST still be scanned.

#### Scenario: SSH client config
- **WHEN** an Edit to `~/.ssh/config`, a regular file outside any repo or sync tree, introduces an identity term
- **THEN** the hook exits 0

#### Scenario: Cloud and cluster configs stay scanned
- **WHEN** an Edit to `~/.aws/config`, `~/.kube/config`, `~/.ssh/config.d/x` or `~/.ssh/../.aws/config` introduces an identity term
- **THEN** the hook exits 2
