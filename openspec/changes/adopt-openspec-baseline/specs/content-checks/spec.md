## Purpose
Write-time content checks that judge the text a Write, Edit or MultiEdit puts on disk: `cadence-hooks cadence terminology`, `cadence orphaned-todos`, `cadence memory-guard`, `cadence line-endings`, `cadence env-vars`, `cadence markdown-lint`, `cadence warn-instruction-narrative`, `cadence warn-live-memory-write`, `cadence warn-plugin-root-cruft`, `cadence audit-runner-pool`, `rules validate-frontmatter` and `rules security-patterns`. All run on PreToolUse except `audit-runner-pool` and `security-patterns` (PostToolUse), and all run unchanged in a cloud session.

## ADDED Requirements

### Requirement: Terminology hard block
`cadence terminology` SHALL block (exit 2) a Write, Edit or MultiEdit whose introduced text contains one of its seven hard-block terms, matched case-insensitively at a word boundary, plural, past and gerund forms included. The stderr message MUST start with `BLOCKED: Inclusive terminology violation detected`, name the file, and give the required alternative for each term. A call with no editable text, or with no flagged term, MUST be allowed.

#### Scenario: Hard-block term in a new file
- **WHEN** a Write to `src/acl.rs` carries a hard-block term
- **THEN** the hook exits 2 and stderr names the term and its alternative

#### Scenario: Ordinary content is allowed
- **WHEN** a Write to `src/main.rs` carries content with no flagged term
- **THEN** the hook exits 0 with no output

#### Scenario: Substring of a longer word
- **WHEN** a flagged term appears only inside a longer word with no word boundary before it
- **THEN** the hook exits 0

### Requirement: Terminology judges only introduced text
`terminology` SHALL judge each edit fragment on its own and MUST drop a term that also appears in that fragment's `old_string`, so a term carried through an Edit never fires. A Write has no old text, so its whole content is judged. The one nudge-tier term (the dated word for a legacy exemption) MUST produce a nudge (exit 0 with the message as additional context), never a block.

#### Scenario: Pre-existing term carried through an Edit
- **WHEN** an Edit's `old_string` and `new_string` both contain the same hard-block term
- **THEN** the hook exits 0

#### Scenario: Edit introduces a term
- **WHEN** an Edit's `new_string` adds a hard-block term absent from its `old_string`
- **THEN** the hook exits 2 and names only that term

#### Scenario: Nudge-tier term
- **WHEN** a Write introduces only the nudge-tier term
- **THEN** the hook exits 0 with a message starting `Terminology nudge`

### Requirement: Terminology built-in exemptions
`terminology` SHALL allow every write to a file whose basename is `CLAUDE.md` in any case, to a path with consecutive `.claude` and `hooks` or `rules` components, and to a file inside the session's own cadence-hooks checkout (a worktree of it, or a gitignored nested checkout). A path that merely contains a `cadence-hooks` component outside the session's workspace, or a decorated name such as `evilclaude.md`, MUST NOT be exempt.

#### Scenario: Instruction file exempt
- **WHEN** a Write to `/repo/CLAUDE.md` carries a hard-block term
- **THEN** the hook exits 0

#### Scenario: Look-alike directory is not exempt
- **WHEN** the session's cwd is an unrelated repo and a Write to `/tmp/cadence-hooks/doc.md` carries a hard-block term
- **THEN** the hook exits 2

### Requirement: Terminology per-repo softening
`terminology` SHALL read `terminology.exemptions` from `<git root>/.claude/cadence.json`. Each entry has `paths` globs, optional `terms` (omitted means all), and optional `mode`: `allow` (default) drops the violation, `nudge` demotes a block to a nudge. The first matching entry MUST decide, and softening MUST only remove or demote, never add. A missing or invalid file MUST leave the block standing; a dropped malformed key MUST be named under `Config anomalies in .claude/cadence.json`.

#### Scenario: Nudge-mode exemption
- **WHEN** an exemption with `"mode": "nudge"` covers `config/acl.yml` and a Write to it carries a hard-block term
- **THEN** the hook exits 0 and returns a terminology nudge

#### Scenario: Bare pattern matches the basename
- **WHEN** an exemption lists `vendor-list.yml` and a Write to `deep/dir/vendor-list.yml` carries a hard-block term
- **THEN** the hook exits 0

#### Scenario: Invalid config file
- **WHEN** `.claude/cadence.json` is not valid JSON and a Write carries a hard-block term
- **THEN** the hook exits 2

### Requirement: Orphaned code markers
`cadence orphaned-todos` SHALL block (exit 2) a write whose introduced text has one of `TODO`, `FIXME`, `HACK`, `XXX`, `REFACTOR`, `BUG` or `OPTIMIZE` followed by a colon but not written as `MARKER(#123):`. The message MUST list each line as `L<n>: <text>` and end with `Required format: MARKER(#ISSUE): description`. A lowercase marker, or one with no colon, MUST NOT fire. The whole `new_string` is judged, so a marker carried through an Edit still blocks.

#### Scenario: Unreferenced marker in code
- **WHEN** a Write to `src/main.rs` has a line with an uppercase marker word directly followed by a colon
- **THEN** the hook exits 2 and stderr names that line number

#### Scenario: Referenced marker is allowed
- **WHEN** the same marker is written as `MARKER(#123):`
- **THEN** the hook exits 0

### Requirement: Orphaned-marker exemptions
`orphaned-todos` SHALL allow files with extension `md`, `txt`, `json`, `yml`, `yaml`, `toml`, `ini` or `env`, and any path under a `docs/` or `documentation/` directory. A file whose name merely contains `docs`, such as `src/docs_handler.rs`, MUST still be judged.

#### Scenario: Markdown is exempt
- **WHEN** a Write to `notes.md` contains an unreferenced marker
- **THEN** the hook exits 0

#### Scenario: Name containing docs is judged
- **WHEN** a Write to `src/docs_handler.rs` contains an unreferenced marker
- **THEN** the hook exits 2

### Requirement: Auto-memory line limits
`cadence memory-guard` SHALL judge only files under `<config dir>/projects/<slug>/memory/` (honoring `CLAUDE_CONFIG_DIR`) or a `.claude/projects/<slug>/memory/` tree, `..` resolved, counting lines of the resulting document. A `MEMORY.md` over 200 lines MUST block with `MEMORY.md is <n> lines (limit: 200)`; 180 to 200 lines MUST nudge; any other memory file over 300 lines MUST nudge. A `memory/` not directly under a slug MUST be allowed, and so must a call with nothing readable.

#### Scenario: Edit pushes MEMORY.md past the limit
- **WHEN** an Edit to `~/.claude/projects/foo/memory/MEMORY.md` would leave 250 lines
- **THEN** the hook exits 2 and stderr reads `MEMORY.md is 250 lines (limit: 200)`

#### Scenario: Exactly 200 lines
- **WHEN** a Write leaves `MEMORY.md` at 200 lines
- **THEN** the hook exits 0 with a nudge

#### Scenario: Project docs memory directory
- **WHEN** a 500-line Write targets `/project/docs/memory/MEMORY.md`
- **THEN** the hook exits 0 with no output

### Requirement: Shell script line endings
`cadence line-endings` SHALL block (exit 2) a write to a path ending in `.sh` or `.bash` (case-insensitive) whose introduced text contains a carriage return, as CRLF or alone, with a message starting `BLOCKED: Shell script contains Windows-style CRLF line endings`. Every other extension, `.zsh` included, MUST be allowed.

#### Scenario: CRLF in a bash script
- **WHEN** a Write to `script.sh` carries `#!/bin/bash\r\necho hello\r\n`
- **THEN** the hook exits 2

#### Scenario: LF script is allowed
- **WHEN** a Write to `script.sh` carries LF line endings only
- **THEN** the hook exits 0

### Requirement: Generic environment variable names
`cadence env-vars` SHALL nudge, never block, when Write or Edit text in a code file reads `DEBUG`, `DISABLE`, `NO_SPLASH`, `PORT`, `VERBOSE`, `QUIET` or `SILENT` through `process.env.X`, `os.getenv("X")`, `ENV['X']` or `std::env::var("X")`, listing each match and recommending a tool-prefixed name. Code files are the C-family, JVM, .NET, Swift, Go, Rust, Ruby, Python and JavaScript/TypeScript extensions; config, docs and shell files MUST be allowed.

#### Scenario: Bare name in TypeScript
- **WHEN** a Write to `src/app.ts` contains `process.env.DEBUG`
- **THEN** the hook exits 0 with a nudge listing `process.env.DEBUG`

#### Scenario: Prefixed name
- **WHEN** a Write to `src/app.ts` contains `process.env.MYAPP_DEBUG`
- **THEN** the hook exits 0 with no output

### Requirement: Markdown lint
`cadence markdown-lint` SHALL run the `markdownlint` CLI on the content of a Write to a path ending in lowercase `.md` and nudge with its findings when it exits non-zero, ending with a `Fix: markdownlint --fix '<path>'` line that survives the output clamp. It MUST NOT judge Edit or MultiEdit and MUST never block. When `markdownlint` is not on `PATH` or the run fails, it MUST allow silently, so an allowed Write is not proof of linting.

#### Scenario: CLI absent
- **WHEN** a Write to `README.md` runs on a machine without `markdownlint`
- **THEN** the hook exits 0 with no output

#### Scenario: Lint findings
- **WHEN** `markdownlint` reports violations for a Write to `docs/guide.md`
- **THEN** the hook exits 0 with a nudge naming `guide.md` and a `Fix:` line

### Requirement: Narrative in always-loaded instruction files
`cadence warn-instruction-narrative` SHALL judge only lines a write adds to a file named `CLAUDE.md`, `CLAUDE.local.md` or `AGENTS.md` (for a Write, lines absent on disk). It SHALL nudge on 3 or more past-event markers (an ISO date, `measured`, `incident`, `turned out`, `used to`, `previously`, `as of`, `verified`, `went missing`), or on an added paragraph past 8 sentences or 1200 characters carrying a marker. Code fences and table rows MUST be ignored, and length alone MUST NOT fire.

#### Scenario: Incident account added
- **WHEN** an Edit to `/repo/CLAUDE.md` adds a rule followed by a dated incident that also says `turned out` and `measured`
- **THEN** the hook exits 0 with a nudge naming the narrative markers

#### Scenario: Other files ignored
- **WHEN** the same text is written to `/repo/README.md`
- **THEN** the hook exits 0 with no output

### Requirement: Narrative nudge escape and fail-open
A pointer phrase anywhere in the addition (`commit history`, `see`, `memory`, `field report`, `docs/gotchas`) SHALL clear both narrative signals. `warn-instruction-narrative` MUST never block, and any read failure (an unreadable, non-UTF-8 or over-2 MiB file on disk) MUST allow.

#### Scenario: Dated pointer stays silent
- **WHEN** the added text is a short rule with a date and `The incident is in commit history.`
- **THEN** the hook exits 0 with no output

### Requirement: Direct writes to live auto-memory
`cadence warn-live-memory-write` SHALL nudge on a Write, Edit or MultiEdit to a file under `<config dir>/projects/<slug>/memory/` (relative paths resolved against the payload `cwd`) unless `<config dir>/cadence/dreams/<slug>/.dream-lock` exists and is under 6 hours old. A lock older than that MUST be named as a crashed run's leftover. The hook MUST read only the lock's metadata, echo the slug only when it is a plain `[A-Za-z0-9._-]+` name, and never block.

#### Scenario: No dream run in flight
- **WHEN** a Write targets `~/.claude/projects/foo/memory/notes.md` and no lock exists
- **THEN** the hook exits 0 with a nudge naming project `foo`

#### Scenario: Inside the adoption window
- **WHEN** the same Write happens while a lock under 6 hours old exists
- **THEN** the hook exits 0 with no output

### Requirement: Plugin-root docs and scripts
`cadence warn-plugin-root-cruft` SHALL nudge on a write to `<root>/plugins/<name>/docs/...` or `<root>/plugins/<name>/scripts/...` only when `<root>/.claude-plugin/marketplace.json` lists a plugin whose string `source` is `plugins/<name>`, with or without `./` and a trailing slash. A skill-nested `skills/<skill>/scripts/` path, a missing manifest, an undeclared directory and an unparseable manifest MUST all be allowed. It MUST never block.

#### Scenario: Declared plugin root
- **WHEN** the manifest declares `./plugins/cadence` and a Write targets `plugins/cadence/docs/plan.md`
- **THEN** the hook exits 0 with a nudge naming `plugins/cadence/docs/`

#### Scenario: No marketplace manifest
- **WHEN** the repo has no `.claude-plugin/marketplace.json`
- **THEN** the same Write exits 0 with no output

### Requirement: Runner-pool audit after a workflow edit
After a Write, Edit or MultiEdit to a `.yml` or `.yaml` file directly under `<root>/.github/workflows/`, `cadence audit-runner-pool` SHALL run `python3 audit-workflows.py <root>` from the newest `cadence-forge` copy in `<config dir>/plugins/cache/`, capped at 3.5 seconds. Exit 1 MUST nudge with the sanitized findings and exit 2 MUST nudge that the audit could not run. Any other outcome MUST be silent. The script location MUST NOT be configurable, and the hook MUST never block.

#### Scenario: Audit finds a problem
- **WHEN** an Edit to `/repo/.github/workflows/ci.yml` completes and the audit exits 1
- **THEN** the hook exits 0 with a nudge headed `Runner-pool audit found problems in the edited workflow`

#### Scenario: Script missing or slow
- **WHEN** no cached `audit-workflows.py` exists, or the audit runs past 3.5 seconds
- **THEN** the hook exits 0 with no output

#### Scenario: Nested workflow path
- **WHEN** a Write targets `/repo/.github/workflows/sub/ci.yml`
- **THEN** no audit runs and the hook exits 0

### Requirement: Which definition files frontmatter validation judges
`rules validate-frontmatter` SHALL judge a `SKILL.md` under a `skills/` directory, or a `.md` under `commands/` or `agents/`, only when that directory's parent is a Claude config directory (`.claude` or the `CLAUDE_CONFIG_DIR` basename), a plugin root holding `.claude-plugin/`, or a repo with a sibling `.claude/`, compared case-insensitively. It SHALL also judge a direct child `docs/plans/<name>.md`. Every other path, and a relative path, MUST be allowed.

#### Scenario: Documentation about commands
- **WHEN** a Write to `/repo/docs/commands/overview.md` has no frontmatter and `/repo/docs` has neither `.claude` nor `.claude-plugin`
- **THEN** the hook exits 0

#### Scenario: Project command without frontmatter
- **WHEN** a Write to `/repo/.claude/commands/ship.md` has no `---` frontmatter
- **THEN** the hook exits 2 with `Frontmatter validation failed: file missing YAML frontmatter`

### Requirement: Skill and command frontmatter rules
For skills and commands the hook SHALL block with `Frontmatter validation failed:` on a top-level key outside the allowed set, a boolean field other than `true` or `false`, or `effort` or `shell` outside their values. A skill MUST have `name` and `description`, and `name` MUST be bare kebab-case with no `plugin:` prefix and equal its directory. A command MUST NOT declare `name`. These checks judge the whole resulting document.

#### Scenario: Prefixed skill name
- **WHEN** a Write to `.claude/skills/attune/SKILL.md` declares `name: cadence:attune`
- **THEN** the hook exits 2 naming the bare-directory rule

#### Scenario: Name differs from directory
- **WHEN** a Write to `.claude/skills/attune/SKILL.md` declares `name: tune`
- **THEN** the hook exits 2 with `name 'tune' must match directory 'attune'`

### Requirement: Skill description and force-load rules
A skill `description` SHALL be one YAML line of at most 1024 characters, and an `@skills/` reference in a skill or command body outside code SHALL block, each only when the edit introduces it. A skill description with no trigger clause (`Use when`, `Use after`, `Use before`), in it or in `when_to_use`, MUST nudge rather than block, and only when the file on disk did not already lack one.

#### Scenario: Block scalar description
- **WHEN** a new skill's `description:` is a `>-` block scalar
- **THEN** the hook exits 2 naming the single-line rule

#### Scenario: Missing trigger clause
- **WHEN** a new skill's description says what it does but not when to use it
- **THEN** the hook exits 0 with a nudge asking for a trigger clause

### Requirement: Living-plan and agent frontmatter
For a `docs/plans/` file the hook SHALL block with `Living-plan frontmatter validation failed:` when the edit introduces a `provenance:` frontmatter key, a second frontmatter block, or a fenced `provenance:` block above the first heading; a problem already on disk MUST NOT block. For a plugin agent it SHALL nudge, never block, on `hooks`, `mcpServers` or `permissionMode`. For any agent whose description names teammate use it SHALL nudge on `skills` or `mcpServers`.

#### Scenario: Plan gains a provenance key
- **WHEN** a Write to `/repo/docs/plans/2026-10-01-x.md` adds a `provenance:` key the file on disk did not have
- **THEN** the hook exits 2

#### Scenario: Plugin agent sets hooks
- **WHEN** a Write to `<plugin>/agents/reviewer.md` declares `hooks:` and the plugin root has `.claude-plugin/`
- **THEN** the hook exits 0 with a nudge saying plugin agents ignore it

### Requirement: Security pattern hints
After a Write or Edit, `rules security-patterns` SHALL scan the resulting document against a fixed per-extension table of anti-patterns and nudge with `Security hints for <file>:` and one `L<n>: <message>` line per match. A pattern MUST apply only to its own extensions. It MUST never block, MUST skip `/.claude/hooks/`, `/.claude/settings`, `/.claude/rules/` and paths ending in `CLAUDE.md`, and MUST allow when no content can be read.

#### Scenario: Pickle in Python
- **WHEN** a Write to `app.py` contains `data = pickle.loads(blob)`
- **THEN** the hook exits 0 with a nudge reading `L1: RCE risk: use json or msgpack instead of pickle`

#### Scenario: Pattern in the wrong language
- **WHEN** a Write to `notes.txt` contains `pickle.loads`
- **THEN** the hook exits 0 with no output

### Requirement: Advisory nudges can be silenced per repo
`warn-instruction-narrative`, `warn-live-memory-write` and `warn-plugin-root-cruft` SHALL honor the `nudges` map of `.claude/cadence.json`: `{"<hook>": {"suppress": true}}` silences every call, and a glob list silences calls whose file path matches. The other hooks in this capability MUST NOT be silenced by that map, and a malformed entry MUST yield no suppression.

#### Scenario: Suppressed narrative nudge
- **WHEN** `.claude/cadence.json` sets `"nudges": {"warn-instruction-narrative": {"suppress": true}}` and a CLAUDE.md edit would nudge
- **THEN** the hook exits 0 with no output

#### Scenario: Blocking check is not suppressible
- **WHEN** the map names `orphaned-todos` and a Write adds an unreferenced marker to `src/main.rs`
- **THEN** the hook still exits 2
