# Hook Catalog

The full catalog of hooks shipped by the `cadence-hooks` binary, organized by
the plugin they serve. The binary is the single source of truth — run
`cadence-hooks list` for the live list with disable status, or `cadence-hooks
try <namespace> <hook>` to see any hook run against a sample payload (see
[docs/testing.md](testing.md)).

For how hooks communicate with Claude Code (stdin/stdout/exit codes), see
[Hook Protocol](../README.md#hook-protocol) in the README.

## cadence

| Hook | Event | What it does |
|------|-------|--------------|
| `terminology` | PreToolUse (Write, Edit) | Block inclusive terminology violations |
| `orphaned-todos` | PreToolUse (Write, Edit) | Require `MARKER(#issue):` format for TODO/FIXME/HACK |
| `prevent-secret-leaks` | PreToolUse (Read, Grep, Bash) | Block reading .env, credentials, private keys |
| `prevent-secret-writes` | PreToolUse (Write, Edit, Bash) | Block writing/deleting .env and credential files |
| `memory-guard` | PreToolUse (Write, Edit) | Enforce MEMORY.md line limits |
| `git-safety` | PreToolUse (Bash) | Block force-push to main, reset --hard, etc. |
| `line-endings` | PreToolUse (Write) | Validate shell script line endings (LF, not CRLF) |
| `env-vars` | PreToolUse (Write, Edit) | Warn on generic env var names (DEBUG, PORT) |
| `warn-docs-update` | PreToolUse (Bash) | Nudge to review docs when creating a PR (`gh pr create`) |
| `warn-changelog-entry` | PreToolUse (Bash) | Nudge to add a CHANGELOG.md entry when shipping code changes |
| `warn-overshare` | PreToolUse (Bash, Write, Edit) | Nudge to audit about-to-ship content for personal-context overshare |
| `nudge-polish-before-pr` | PreToolUse (Bash) | Nudge to run `/polish` (cadence-forge:polish) before `gh pr create` |
| `markdown-lint` | PreToolUse (Write) | Run markdownlint on markdown files |

`warn-overshare` does path triage only — it fires on commit/push/PR/issue Bash
commands and on Write/Edit to `docs/field-reports/`, then leaves the content
judgment to the model. It exempts writes under `$OBSIDIAN_VAULT`
(the safe home for personal context), and is silenced session-wide with
`CADENCE_SKIP_OVERSHARE_AUDIT=1`.

## guardrails (git-guardrails)

| Hook | Event | What it does |
|------|-------|--------------|
| `guard-push-remote` | PreToolUse (Bash) | Block git push to repos you don't own |
| `guard-gh-write` | PreToolUse (Bash) | Block gh write operations to non-owned repos |
| `guard-gh-dangerous` | PreToolUse (Bash) | Block irreversible gh operations (repo delete) |
| `guard-git-init` | PostToolUse (Bash) | Nudge to scaffold and confirm license after `git init` or `gh repo create` |
| `warn-main-branch` | PreToolUse (Write, Edit) | Warn when editing on main/master branch |
| `enforce-worktree` | PreToolUse (Write, Edit, Bash) | Block mutations and `git commit` in a primary checkout of a branch-mode repo — work in a worktree instead (exempt: `CADENCE_ALLOW_MAIN` repos, temp/scratch repos, `.claude/` + `docs/plans/` paths) |
| `warn-branch-base` | PreToolUse (Bash) | Warn when creating a branch from a non-main base |
| `warn-cron-datetime` | PreToolUse (CronCreate) | Inject current datetime before scheduling cron jobs |
| `warn-untracked` | PreToolUse (Bash) | Warn about untracked files during git commit |
| `nudge-upgrade-after-push` | PostToolUse (Bash) | Nudge to schedule a brew upgrade after pushing cadence-hooks to main |
| `guard-dotfiles` | PreToolUse (Edit, Write) | Block direct edits to production dotfiles (opt-in via `CADENCE_GUARD_DOTFILES=1`) |
| `warn-pr-issue-link` | PreToolUse (Bash) | Nudge when `gh pr create` has no closing issue keyword (`Closes #N`) in the body |
| `warn-issue-tracker` | PreToolUse (Bash) | Nudge when `gh issue create` targets an owned repo that is not a known ecosystem tracker |
| `verify-pr-autoclose` | PostToolUse (Bash) | Verify issue auto-close refs after PR create; close stragglers after merge |
| `guard-op-vault-scan` | PreToolUse (Bash) | Block 1Password vault enumeration (`op item list`); single-item reads stay allowed |
| `warn-curl-alias` | PreToolUse (Bash) | Warn when bare `curl` (aliased to curlie) is used with custom headers |
| `warn-gh-merge-preflight` | PreToolUse (Bash) | Pre-flight checklist before `gh pr merge` (isDraft, worktree, mergedAt verification) |
| `warn-coderabbit-retrigger` | PreToolUse (Bash) | Warn that `@coderabbitai review` comments are no-ops on already-reviewed content |
| `warn-alias-parsing` | PreToolUse (Bash) | Warn when piping aliased-tool output (cat/find/ls/du/df/top) into parsers |
| `guard-browser-device` | PreToolUse (Claude-in-Chrome MCP) | Block the first claude-in-chrome action per session until the target device is confirmed |
| `inject-gh-context` | SessionStart (startup, resume, compact) | Inject the gh-write allowlist + `-R owner/repo` rule into context |
| `inject-gh-write-context` | PreToolUse (Bash) | Re-inject the same allowlist + `-R owner/repo` rule just before a `gh` write that names no target |

`guard-browser-device` is a deliberate block (not a nudge): a nudge is exit 0,
so the browser action would already have hit a device before the context
arrived. It blocks the first claude-in-chrome tool call of a session, writes a
per-session marker, and allows every subsequent call — forcing the
`list_connected_browsers` → `select_browser` handshake the MCP server only
advises.

## rules

| Hook | Event | What it does |
|------|-------|--------------|
| `validate-frontmatter` | PreToolUse (Write, Edit) | Validate SKILL.md and command frontmatter |
| `security-patterns` | PostToolUse (Write, Edit) | Scan for security anti-patterns |

`security-patterns` is a **zero-config, no-API baseline** — a per-edit pattern
scan with no setup. For configurable patterns plus model-backed diff and commit
review, install the official `security-guidance` plugin
(`/plugin install security-guidance@claude-plugins-official`).

## obsidian (cadence-obsidian)

| Hook | Event | What it does |
|------|-------|--------------|
| `trash-guard` | PreToolUse (Bash) | Block destructive vault operations (`rm`, `git rm`, `unlink`, `shred`, `truncate`, `find -delete`, and clobber redirects); use `.trash/` instead |

A verb counts only where the shell runs an executable, and there are two such
positions: the head of a segment, and a `find` exec-family action
(`-exec`/`-execdir`/`-ok`/`-okdir`). Both are read the same way — past the
scaffolding of a compound statement (reserved words like `do`/`then`, the `( )`
and `{ }` of a group, a `case` arm's pattern label, a function definition
header), past transparent wrappers, past a command runner's own flags (`sudo`,
`xargs`, `nice`, `stdbuf`, `timeout`, `env`), and past git's global options to
its subcommand — so `git -C . rm x` and `find . -exec nice -n 10 rm {} \;` both
count. An operand a command re-executes (`eval …`, `find … -exec sh -c '…'`) is
scanned as a command in its own right, including behind those same runner flags
— `nice -n 10 sh -c 'rm x'` and `find … -exec env -i sh -c 'rm x' \;` are read,
not just the unflagged spellings. A command substitution runs in the parent
shell before any wrapper is spawned, so `bash -c '…' "$(rm x)"` is scanned on
both halves.

**The two combine.** Scaffolding and a re-executed operand are read by one
model, so `if true; then bash -c 'rm x'; fi`, `for f in a; do sh -c 'rm x'; done`
and `(bash -c 'rm x')` are scanned exactly as `bash -c 'rm x'` is. Until 0.70.0
they were not: the verb gate stripped the keyword and the hunt for a wrapper did
not, so the combination was the one spelling that escaped.

That is narrower than a scan of the whole command line, which is what this guard
used before 0.70.0 — `echo rm` and `npm run format` no longer match, and neither
does a verb reached by a spelling not listed above: one built by substitution
(`` `echo rm` x ``, `$(echo rm) x`), one carried in a body this model does not
treat as executed (a `trap` handler, a `coproc`), a deleting binary outside the
verb list (`srm x`), or one behind a runner option the grammar does not model
(`env -S 'rm x'`). A runner option the grammar cannot classify stops the scan
rather than being guessed past, so an unmodelled spelling costs a block here and
never creates a spurious one.

## metrics (cadence-metrics)

These are **loggers**, not guards: they append JSONL event records and always
exit 0. They never block a tool call (see
[Hook Protocol](../README.md#hook-protocol)).

| Hook | Event | What it does |
|------|-------|--------------|
| `snapshot` | PreToolUse (Bash, `git commit`) | Snapshot HEAD before a commit, so `log-commit` can tell whether it landed |
| `log-commit` | PostToolUse (Bash, `git commit`) | Scan the transcript for tokens since the last commit, compute cost, append to `commits.jsonl` |
| `log-subagent` | SubagentStart / SubagentStop | Append a subagent lifecycle record to `subagents.jsonl` |
| `log-session` | SessionEnd | Scan the whole session log at session end, compute per-model cost, append to `sessions.jsonl` |
| `log-session-start` | SessionStart | Stamp the session start timestamp, so `log-session` can compute `durationMs` at `SessionEnd` |
| `log-polish-nudge` | PostToolUse (Bash, `gh pr create`) | Record every nudged PR and whether `/polish` ran earlier this session, append to `polish_nudges.jsonl` |
| `log-ask-user-question` | PreToolUse (`AskUserQuestion`) | Record each call's stance (recommended / declared-no-rec / silent) and shape (multiSelect, question/option counts), append to `askuserquestion.jsonl` |

`log-commit` reads its price table from the embedded default, overridable with
`--prices <path>` (or `CADENCE_METRICS_PRICES`). Set `CADENCE_METRICS_DEBUG=1`
to add a `_keys` array of raw payload keys to subagent records — useful for
spotting schema additions across Claude Code releases.

Cost is computed **per model**: when a commit range spans multiple models
(opus → sonnet handoffs, fast-mode toggles), each model's tokens are priced at
its own rates and summed. Records carry the breakdown in a `byModel` array
(`[{model, tokens, costUsd}]`); rows written before this field existed are
single-model by definition.

## session (cadence-canon)

Multi-session coordination for the **cadence-canon** plugin (issue #54). Concurrent
Claude Code sessions sharing one repo checkout cannot see each other — these hooks
give sessions *identity* within a repo via a registry at `<repo>/.claude/sessions/`
(one file per session, mtime is the liveness heartbeat, auto-excluded from git via
`.git/info/exclude`).

| Hook | Event | What it does |
|------|-------|--------------|
| `start` | SessionStart | Register this session (deterministic adjective-noun name), sweep stale entries, and disclose live peers with a lane assessment + the multi-session protocol |
| `heartbeat` | PostToolUse | Touch this session's registry file; refresh the recorded branch so peers see branch drift |
| `guard` | PreToolUse (Bash, Edit, Write) | Warn — never block — on branch switches, blanket staging (`git add -A`, `git commit -a`), and writes inside a peer's declared paths |
| `warn-branch-drift` | PreToolUse (Bash, `git commit`) | Warn when HEAD drifted from the session's recorded branch at commit time |
| `warn-commit-provenance` | PreToolUse (Bash, `git commit`) | Nudge with a computed `Session-Id:` trailer block when a Claude-composed commit message lacks one |

Liveness is mtime-based: a session that crashes or closes simply stops heartbeating
and is presumed dead after 10 minutes (`CADENCE_SESSION_STALE_MINUTES`). No
deregistration ceremony. Stale entries are swept on the next `session start`.

### CLI actions (not hooks)

A few `cadence-hooks` subcommands are operator commands, not hooks — they take
no stdin payload, have no `hooks.json` wiring, and are not subject to
`CADENCE_DISABLE`. They are exempt from `CADENCE_BYPASS` so they keep working
during maintenance.

| Command | What it does |
|---------|--------------|
| `session declare` | Declare what this session is working on (`--intent`, `--touching`) so peers can assess collision risk |
| `session status` | List live and stale sessions registered in this repo |
| `guardrails dismiss-main-branch-warn` | Snooze `warn-main-branch` for this repo for a bounded window (`--for 2h`, capped at 24h) — see [Snoozing warn-main-branch](configuration.md#snoozing-warn-main-branch) |
| `guardrails dismiss-enforce-worktree` | Snooze the `enforce-worktree` block for this repo for a bounded window (`--for 30m`, capped at 24h) — the one-off escape for a legitimate primary-checkout mutation |
