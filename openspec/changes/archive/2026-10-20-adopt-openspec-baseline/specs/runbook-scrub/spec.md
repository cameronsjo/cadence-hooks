## Purpose
The secret-scrub gate on the off-machine runbooks directory: `cadence-hooks guardrails guard-runbook-scrub`, a PreToolUse guard that blocks an unscrubbed Write, Edit or MultiEdit into `$CADENCE_RUNBOOKS_DIR`, and `cadence-hooks cadence record-scrub`, the CLI action that records a scrubbed draft's content hash so the guard lets that exact content through.

## ADDED Requirements

### Requirement: Inert unless the runbooks directory is configured
`guard-runbook-scrub` SHALL allow every call when `CADENCE_RUNBOOKS_DIR` is unset, blank, or resolves to the filesystem root. A leading `~` or `~/` in the value MUST expand to the home directory, and a relative value MUST resolve against the payload `cwd`. The guard runs unchanged in a cloud session.

#### Scenario: Variable unset
- **WHEN** `CADENCE_RUNBOOKS_DIR` is unset and a Write targets any path
- **THEN** the hook exits 0 with no output

#### Scenario: Root is never the runbooks directory
- **WHEN** `CADENCE_RUNBOOKS_DIR=/` and a Write targets `/etc/notes.md`
- **THEN** the hook exits 0

### Requirement: Unscrubbed writes into the directory block
When a Write, Edit or MultiEdit (including an MCP write) targets a path inside the runbooks directory, the guard SHALL compute the resulting document (a Write's content, or the file on disk with every edit applied) and allow only when its SHA-256, with each `\r\n` read as `\n`, matches a recorded scrub marker. Otherwise it MUST block (exit 2) with `BLOCKED: guard-runbook-scrub:` and the scrub, record and promote steps.

#### Scenario: Recorded content is allowed
- **WHEN** `record-scrub` recorded a draft and a Write puts exactly that content into `$CADENCE_RUNBOOKS_DIR/deploy.md`
- **THEN** the hook exits 0

#### Scenario: Content changed after the scrub
- **WHEN** the Write's content differs from every recorded draft by one byte
- **THEN** the hook exits 2 and stderr names `cadence-hooks cadence record-scrub --file <draft>`

#### Scenario: Line endings do not matter
- **WHEN** the draft was recorded with CRLF endings and the Write carries the same text with LF endings
- **THEN** the hook exits 0

#### Scenario: Ordinary write elsewhere is allowed
- **WHEN** a Write targets `/repo/src/main.rs`, outside the runbooks directory
- **THEN** the hook exits 0 with no output

### Requirement: Where a path lands
The guard SHALL treat a path as inside the directory when either its lexical reading (`..` folded as text) or its physical reading (every existing symlink followed, `..` applied after it) is the directory or below it, comparing components ASCII-case-insensitively. A relative path MUST resolve against the payload `cwd`, and a symlink loop MUST fall back to the lexical reading.

#### Scenario: Symlink into the directory
- **WHEN** `/work/link` is a symlink to the runbooks directory and a Write targets `/work/link/x.md` with unrecorded content
- **THEN** the hook exits 2

#### Scenario: Different case on a case-insensitive volume
- **WHEN** the directory is `/vault/Runbooks` and a Write targets `/vault/runbooks/x.md` with unrecorded content
- **THEN** the hook exits 2

### Requirement: An uncomputable result blocks
When the guard cannot compute the resulting document it SHALL block, because no scrub can vouch for it: an Edit of an unreadable or non-UTF-8 file, an edit whose `old_string` is empty or not found literally, an edit without both an `old_string` and a `new_string` (an MCP `oldText`/`newText` edit), or a write with no content and no edit (an MCP move). An Edit that creates a new file therefore blocks; the Write tool is the way to create one.

#### Scenario: Edit text not found literally
- **WHEN** an Edit into the directory has an `old_string` that does not occur literally in the file on disk, even though the file is recorded
- **THEN** the hook exits 2 saying the resulting content cannot be computed

### Requirement: Scrub markers cannot be forged by a write
The guard SHALL block (exit 2) any Write, Edit or MultiEdit whose target lands in the scrub-marker directory, with a message saying markers are recorded only by `cadence-hooks cadence record-scrub`. This holds whatever the content, whenever `CADENCE_RUNBOOKS_DIR` is set; with it unset the guard is inert here too.

#### Scenario: Writing a marker file by hand
- **WHEN** a Write targets `<marker dir>/scrub-<hex>` while `CADENCE_RUNBOOKS_DIR` is set
- **THEN** the hook exits 2

### Requirement: Bash is not judged
`guard-runbook-scrub` SHALL NOT judge Bash commands: a `cp`, `mv`, redirect or any other command that writes into the runbooks directory MUST be allowed, because what a command writes is not knowable before it runs. Promotion goes through the Write tool, and a Bash copy is a deliberate step the guard does not second-guess.

#### Scenario: Copy into the directory
- **WHEN** a Bash call runs `cp draft.md "$CADENCE_RUNBOOKS_DIR/deploy.md"`
- **THEN** the hook exits 0 with no output

### Requirement: Escape and protection
Setting `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK` truthy (`1`, `true`, `yes`) in the hook's own environment SHALL turn a block into an allow and MUST record a bypass row naming the switch; a call that would not block MUST record nothing. An inline `VAR=1` prefix on a command does not reach the hook. The guard is protected, so `CADENCE_DISABLE` MUST NOT turn it off.

#### Scenario: Escape set
- **WHEN** `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK=1` is in the hook's environment and an unrecorded Write targets the directory
- **THEN** the hook exits 0 and a bypass row is written

#### Scenario: Escape set on an unrelated write
- **WHEN** the escape is set and a Write targets a path outside the directory
- **THEN** the hook exits 0 and no bypass row is written

#### Scenario: Disable request refused
- **WHEN** `CADENCE_DISABLE=guard-runbook-scrub` is set and an unrecorded Write targets the directory
- **THEN** the hook still exits 2

### Requirement: record-scrub records a content hash
`cadence-hooks cadence record-scrub --file <path>` SHALL hash the file's bytes with SHA-256, reading each `\r\n` as `\n`, and write a marker named `scrub-<hex>` holding only a `recorded_at` timestamp into the private marker directory (`<config dir>/cadence-hooks/markers`, or a per-user subdirectory of `CADENCE_MARKER_DIR` when set). It MUST exit 0 when recorded and print the digest. It trusts its caller: it does not run or check the scrub itself.

#### Scenario: Record a scrubbed draft
- **WHEN** `record-scrub --file draft.md` runs on a readable regular file
- **THEN** it exits 0, prints the sha256, and `guard-runbook-scrub` allows a Write of that exact content

### Requirement: record-scrub refuses what it cannot vouch for
`record-scrub` SHALL exit 1 and record nothing when the file is missing or unreadable, is not a regular file (a directory or FIFO, judged on the opened handle without blocking), is larger than 16 MiB, or when the marker directory is not private (0700) or the write fails. A missing `--file` MUST exit 2. A marker in a directory that is not private MUST NOT be honored by the guard either.

#### Scenario: FIFO refused without hanging
- **WHEN** `record-scrub --file` names a FIFO with no writer
- **THEN** it exits 1 promptly and writes no marker

#### Scenario: Missing argument
- **WHEN** `cadence-hooks cadence record-scrub` runs with no `--file`
- **THEN** it exits 2
