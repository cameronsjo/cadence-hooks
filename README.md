# cadence-hooks

Compiled [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hooks in Rust. A single binary replaces dozens of shell and Node.js hook scripts across multiple plugins, with sub-millisecond cold starts and zero runtime dependencies.

## Why

Claude Code hooks run on every tool invocation. Shell scripts accumulate startup overhead — spawning bash, loading profiles, forking subprocesses. This repo compiles all hook logic into one native binary that reads JSON from stdin, writes diagnostics to stderr, and exits with the correct status code. The result is faster, more testable, and easier to distribute.

## Hooks

Hooks are organized by the plugin they serve:

### cadence

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
| `nudge-polish-before-pr` | PreToolUse (Bash) | Nudge to run `/polish` (cadence-forge:polish) before `gh pr create` |
| `markdown-lint` | PreToolUse (Write) | Run markdownlint on markdown files |

### guardrails (git-guardrails)

| Hook | Event | What it does |
|------|-------|--------------|
| `guard-push-remote` | PreToolUse (Bash) | Block git push to repos you don't own |
| `guard-gh-write` | PreToolUse (Bash) | Block gh write operations to non-owned repos |
| `guard-gh-dangerous` | PreToolUse (Bash) | Block irreversible gh operations (repo delete) |
| `guard-git-init` | PostToolUse (Bash) | Nudge to scaffold and confirm license after `git init` or `gh repo create` |
| `warn-main-branch` | PreToolUse (Write, Edit) | Warn when editing on main/master branch |
| `warn-branch-base` | PreToolUse (Bash) | Warn when creating a branch from a non-main base |
| `warn-cron-datetime` | PreToolUse (CronCreate) | Inject current datetime before scheduling cron jobs |
| `warn-untracked` | PreToolUse (Bash) | Warn about untracked files during git commit |
| `check-idle-return` | PreToolUse | Nudge after idle periods between edits |
| `nudge-upgrade-after-push` | PostToolUse (Bash) | Nudge to schedule a brew upgrade after pushing cadence-hooks to main |
| `guard-dotfiles` | PreToolUse (Edit, Write) | Block direct edits to production dotfiles (opt-in via `CADENCE_GUARD_DOTFILES=1`) |
| `warn-pr-issue-link` | PreToolUse (Bash) | Nudge when `gh pr create` has no closing issue keyword (`Closes #N`) in the body |
| `verify-pr-autoclose` | PostToolUse (Bash) | Verify issue auto-close refs after PR create; close stragglers after merge |
| `guard-op-vault-scan` | PreToolUse (Bash) | Block 1Password vault enumeration (`op item list`); single-item reads stay allowed |
| `warn-curl-alias` | PreToolUse (Bash) | Warn when bare `curl` (aliased to curlie) is used with custom headers |
| `warn-gh-merge-preflight` | PreToolUse (Bash) | Pre-flight checklist before `gh pr merge` (isDraft, worktree, mergedAt verification) |
| `warn-coderabbit-retrigger` | PreToolUse (Bash) | Warn that `@coderabbitai review` comments are no-ops on already-reviewed content |
| `warn-alias-parsing` | PreToolUse (Bash) | Warn when piping aliased-tool output (cat/find/ls/du/df/top) into parsers |

### rules

| Hook | Event | What it does |
|------|-------|--------------|
| `validate-frontmatter` | PreToolUse (Write, Edit) | Validate SKILL.md and command frontmatter |
| `security-patterns` | PreToolUse (Write, Edit) | Scan for security anti-patterns |

`security-patterns` is a **zero-config, no-API baseline** — a per-edit pattern scan with no
setup. For configurable patterns plus model-backed diff and commit review, install the
official `security-guidance` plugin (`/plugin install security-guidance@claude-plugins-official`).

### obsidian (cadence-obsidian)

| Hook | Event | What it does |
|------|-------|--------------|
| `trash-guard` | PreToolUse (Bash) | Block `rm` in Obsidian vault (use .trash/ instead) |

### metrics (cadence-metrics)

These are **loggers**, not guards: they append JSONL event records and always
exit 0. They never block a tool call (see [Hook Protocol](#hook-protocol)).

| Hook | Event | What it does |
|------|-------|--------------|
| `snapshot` | PreToolUse (Bash, `git commit`) | Snapshot HEAD before a commit, so `log-commit` can tell whether it landed |
| `log-commit` | PostToolUse (Bash, `git commit`) | Scan the transcript for tokens since the last commit, compute cost, append to `commits.jsonl` |
| `log-subagent` | SubagentStart / SubagentStop | Append a subagent lifecycle record to `subagents.jsonl` |

`log-commit` reads its price table from the embedded default, overridable with
`--prices <path>` (or `CADENCE_METRICS_PRICES`). Set `CADENCE_METRICS_DEBUG=1`
to add a `_keys` array of raw payload keys to subagent records — useful for
spotting schema additions across Claude Code releases.

Cost is computed **per model**: when a commit range spans multiple models
(opus → sonnet handoffs, fast-mode toggles), each model's tokens are priced at
its own rates and summed. Records carry the breakdown in a `byModel` array
(`[{model, tokens, costUsd}]`); rows written before this field existed are
single-model by definition.

### lab (cadence-lab)

Experimental hooks for the [cadence-lab](https://github.com/cameronsjo/cadence-lab)
plugin. The first is the **self-representation persona ledger** — a two-hook system
that captures a constrained, per-session self-representation and appends it to an
append-only `~/.claude/persona/personas.jsonl`.

| Hook | Event | What it does |
|------|-------|--------------|
| `persona-nudge` | SessionStart (startup, clear) | Inject a contract asking the model to record a constrained self-representation to a per-session staging file |
| `persona-gate` | PostToolUse (Write) | Validate the staging candidate; feed itemized corrections back for a rewrite, or promote the validated record into the ledger |

The gate uses the `LoopBlock` outcome — exit 0 with `{"decision":"block","reason":...}`
— rather than a hard `exit 2`, because `PostToolUse` fires *after* the write, so the
re-prompt convention (not the block convention) is what drives the rewrite. Cheek mode
ships `warn` (annotate a system-written `flags` field, still promote). Configure via
`~/.claude/persona/config.json`; record shape in the plugin's `schema/persona.schema.json`.

### session (cadence-canon)

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
| `declare` | CLI action | Declare what this session is working on (`--intent`, `--touching`) so peers can assess collision risk |
| `status` | CLI action | List live and stale sessions registered in this repo |

Liveness is mtime-based: a session that crashes or closes simply stops heartbeating
and is presumed dead after 10 minutes (`CADENCE_SESSION_STALE_MINUTES`). No
deregistration ceremony. Stale entries are swept on the next `session start`.

## Hook Protocol

Claude Code hooks communicate via a simple protocol:

```
stdin  → JSON { tool_name, tool_input: { file_path, command, content, ... }, cwd }
stdout ← Nudge messages (JSON additionalContext, injected into Claude's context)
stderr ← Block diagnostics (fed back to Claude)
exit   → 0 (allow / nudge) | 2 (block, prevent operation) | other (non-blocking error)
```

Each subcommand reads this JSON, runs its check, and exits. No network calls, no config files, no dependencies beyond the binary.

## Testing Hooks Manually

Hook subcommands expect piped stdin. Run one bare in a terminal and it prints
guidance instead of hanging:

```text
$ cadence-hooks lab persona-nudge
cadence-hooks: 'persona-nudge' is a Claude Code hook, not an interactive command.

It reads a JSON payload on stdin — Claude Code pipes this automatically on
SessionStart. Nothing was piped and stdin is a terminal, so it would wait forever.
...
```

The fastest way to see what a hook does is `try` — it generates a sample
payload for the hook's event, runs the hook against it, and reports the outcome:

```bash
$ cadence-hooks try lab persona-nudge
Hook:     lab persona-nudge — Inject the self-representation contract on session start
Event:    SessionStart
Payload:  {"cwd":"...","session_id":"test","source":"startup"}

Outcome:  NUDGE (exit 0)
Context injected (what Claude sees):

  Before other work, record a self-representation as ONE JSON object.
  This is not creative writing. Report what is actually true for you...

Stderr:   (none)
```

`try` decodes the hook protocol: nudge envelopes render their
`additionalContext` as readable text, re-prompt envelopes show the reason,
and the outcome line distinguishes `ALLOW` / `NUDGE` / `LOOP-BLOCK` / `BLOCK`.

Use `--payload <file>` to test with a real payload instead of the generated sample.

To pipe a payload by hand, match the shape to the hook's event
(`cadence-hooks list` shows each hook's event):

| Event | Minimal payload |
|---|---|
| PreToolUse | `{"tool_name":"Bash","tool_input":{"command":"git status"}}` |
| PostToolUse | `{"tool_name":"Edit","tool_input":{"file_path":"src/main.rs"},"tool_response":{"stdout":"ok"}}` |
| SessionStart | `{"session_id":"test","source":"startup"}` |
| Loggers (metrics, heartbeat) | `{"session_id":"test","hook_event_name":"PostToolUse","tool_input":{"command":"git status"}}` |

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | cadence-hooks guardrails guard-push-remote
```

Writing or debugging a check? See
[CONTRIBUTING.md → Reproducing a Check by Hand](CONTRIBUTING.md#reproducing-a-check-by-hand)
for the check-author's debugging loop and the per-tool payload shapes
(Write/Edit/MultiEdit carry their content in different fields).

## Installation

### From release (recommended)

Download the latest binary from [Releases](https://github.com/cameronsjo/cadence-hooks/releases):

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/cameronsjo/cadence-hooks/releases/latest/download/cadence-hooks-v0.1.0-macos-aarch64.tar.gz | tar xz
mv cadence-hooks ~/.local/bin/

# Linux (x86_64)
curl -sL https://github.com/cameronsjo/cadence-hooks/releases/latest/download/cadence-hooks-v0.1.0-linux-x86_64.tar.gz | tar xz
mv cadence-hooks ~/.local/bin/
```

### From source

```bash
cargo install --git https://github.com/cameronsjo/cadence-hooks.git
```

### Verify

```bash
cadence-hooks --version
cadence-hooks --help
```

## Usage

Each hook is a subcommand:

```bash
# Run a specific hook (normally called by Claude Code, not manually)
echo '{"tool_name":"Write","tool_input":{"file_path":"src/main.rs","content":"..."}}' \
  | cadence-hooks cadence terminology

# List available subcommands
cadence-hooks cadence --help
cadence-hooks guardrails --help
```

### Configuring in Claude Code

Reference the binary in your plugin's `hooks.json`:

```json
{
  "hooks": [
    {
      "type": "preToolUse",
      "matcher": "Write|Edit",
      "command": "cadence-hooks cadence terminology"
    },
    {
      "type": "preToolUse",
      "matcher": "Bash",
      "command": "cadence-hooks guardrails guard-push-remote"
    }
  ]
}
```

### Environment Variables

All cadence-hooks config lives under the `CADENCE_*` prefix. `OBSIDIAN_VAULT` is kept unprefixed because it's a cross-tool convention.

| Variable | Used by | Purpose |
|----------|---------|---------|
| `CADENCE_DISABLE` | all hooks | Comma-separated hook names to skip (e.g., `git-safety,warn-main-branch`) |
| `CADENCE_BYPASS` | all hooks | Set to `1` to skip all enforcement (maintenance bypass) |
| `CADENCE_ALLOWED_OWNERS` | `guard-push-remote`, `guard-gh-write` | Space or comma-separated usernames |
| `CADENCE_ALLOWED_REPOS` | `guard-gh-write` | Space or comma-separated `owner/repo` pairs |
| `CADENCE_EXTRA_HOSTS` | `guard-push-remote`, `guard-gh-write` | Self-hosted forge hosts that bare entries (`cameron`) should match in addition to the default host |
| `CADENCE_GH_STRICT_LOOPS` | `guard-gh-write` | Set to `1` to block all looped gh writes lacking `-R`, even provably deterministic ones |
| `CADENCE_GUARD_DOTFILES` | `guard-dotfiles` | Set to `1` to block direct edits to production dotfiles (clean no-op otherwise) |
| `CADENCE_SESSION_STALE_MINUTES` | `session` hooks | Minutes of heartbeat silence before a session is presumed dead (default 10) |
| `GH_AUTOCLOSE_WAIT_SECONDS` | `verify-pr-autoclose` | Seconds to wait after `gh pr merge` before checking for straggler issues (default 10) |
| `OBSIDIAN_VAULT` | `trash-guard` | Absolute path to Obsidian vault |

#### Allowlist host scoping

Bare entries in `CADENCE_ALLOWED_OWNERS` and `CADENCE_ALLOWED_REPOS` match only the default host (`github.com`, or `GH_HOST` if set). For self-hosted forges (Gitea, Forgejo, GitLab CE, Bitbucket Server), use one of:

- **Host-qualified entries** — `git.sjo.lol/cameron` matches only that host
- **`CADENCE_EXTRA_HOSTS`** — opt additional hosts into the bare-entry flow when you reuse the same username across forges you control

```bash
# Match `cameron` on github.com AND git.sjo.lol
export CADENCE_ALLOWED_OWNERS="cameron"
export CADENCE_EXTRA_HOSTS="git.sjo.lol"

# Or scope the entry explicitly without widening
export CADENCE_ALLOWED_OWNERS="cameron git.sjo.lol/cameron"
```

#### How guard-gh-write resolves targets

For a single `gh` write, the target resolves in order: explicit `-R`/`--repo` flag (all four forms: `-R x`, `-Rx`, `--repo x`, `--repo=x`) → positional `owner/repo` argument → `gh api repos/...` path → the working directory's git remotes. A resolved target is checked against the allowlists; an owned target proceeds without any flag.

**Forks** (a repo with both `origin` and `upstream` remotes) are allowed when **both** remotes belong to allowed owners — each judged against its own host. When either side is unowned, the write blocks and asks for an explicit `-R`.

**Loops** containing gh writes without `-R` follow a *relaxed-when-deterministic* policy: the write is allowed when the loop body provably never changes directory (no `cd`/`pushd`/`popd`/`eval`/`source`) **and** the working directory resolves to a single owned, non-fork repo. Under those conditions every iteration targets the same repo the guard verified — the same trust extended to single commands. Anything the analyzer cannot prove (directory changes inside the body, parse failures, forks, unowned directories) still blocks.

Set `CADENCE_GH_STRICT_LOOPS=1` to disable the relaxation and block every looped gh write that lacks `-R` (the pre-0.12 behavior). Block messages include the resolved `-R owner/repo` fix when the working directory is owned.

Under Claude Code (detected via `CLAUDECODE=1`), the `configure` subcommand is hidden from `--help` and refuses to run interactively. `configure --list` remains available. Run `configure` from a real terminal to change hook state.

### Auditing installed plugins

`doctor` scans every installed plugin's `hooks.json` for two classes of problems:

- **Shell-expansion bugs** (exit 2): single-quoted `'${CLAUDE_PLUGIN_ROOT}'` won't expand in `/bin/sh` — the harness reports a silent non-blocking failure and nothing surfaces to the user.
- **Subcommand skew** (exit 1): a hook references a subcommand this binary doesn't have — typically a plugin built for a newer version of cadence-hooks.

By default the scan is driven by `~/.claude/plugins/installed_plugins.json`, so only **active** installs are checked (the cache keeps stale plugin versions around — scanning those would report skew in code that no longer runs). With `--root`, the given tree is walked recursively, so both flat layouts (`<root>/<plugin>/hooks/hooks.json`) and the real cache layout (`<root>/<marketplace>/<plugin>/<sha>/hooks/hooks.json`) work.

```bash
# Scan active installs from ~/.claude/plugins/installed_plugins.json
cadence-hooks doctor

# Audit a specific tree (handy in CI before publishing a plugin)
cadence-hooks doctor --root ./plugins

# Preflight mode for SessionStart hooks — one summary line, non-zero only on errors
cadence-hooks doctor --quiet
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Warnings only — subcommand skew (version mismatch between plugin and binary) |
| 2 | Errors — shell-expansion bugs that will silently break hooks at runtime, or configuration/internal errors (`$HOME` unset, nonexistent `--root`) |

**Sample output (skew warning):**

```
warning [cadence@workbench] ~/.claude/plugins/cache/workbench/cadence/174e3eb0def9/hooks/hooks.json:12: subcommand 'cadence future-hook' is not present in this binary (v0.11.0)
  command: "${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence future-hook
  fix: brew upgrade cadence-hooks (or downgrade the plugin)

cadence-hooks doctor: 0 error(s), 1 warning(s)
```

**`--quiet` mode** is suitable for SessionStart preflight wiring. When clean it produces no output and exits 0; on warnings it prints one summary line to stdout and exits 0 (so a `set -euo pipefail` script won't abort); on errors it writes one line to stderr and exits 2.

The stream split is deliberate: warnings go to **stdout** (a caller capturing stdout gets the skew nudge to inject), errors go to **stderr** (a caller redirecting stderr to `/dev/null` still fails on the exit code). Redirect accordingly — `>/dev/null` silences the skew nudge, `2>/dev/null` silences error detail but not the failure.

```bash
# In a SessionStart hook — detect skew without blocking on warnings
if msg=$(cadence-hooks doctor --quiet 2>/dev/null); [ -n "$msg" ]; then
  echo "$msg" >&2
fi
```

### Snoozing warn-main-branch

`warn-main-branch` fires once per session — but during quick wrap-up edits on a repo that's intentionally on `main`, even one nudge per session is noise. Silence it for a time-bound window per-repo:

```bash
# Default: 30 minutes
cadence-hooks guardrails dismiss-main-branch-warn

# Explicit duration: 2h, 1d, 45s, etc. Capped at 24h.
cadence-hooks guardrails dismiss-main-branch-warn --for 2h
```

The snooze marker lives at `<repo>/.git/cadence-hooks/main-branch-snoozed-until`, so it's per-repo and ignored by default (`.git/` is never committed). The hook's own warn output also points at the command, so it's discoverable when the warning fires.

## Architecture

```
cadence-hooks (binary)
├── crates/core        — Hook protocol: JSON parsing, Check trait, exit codes
├── crates/cadence     — Cadence plugin hooks
├── crates/guardrails  — Git guardrails hooks
├── crates/rules       — Rules plugin hooks
├── crates/obsidian    — Obsidian plugin hooks
├── crates/metrics     — Fire-and-forget cost/usage loggers
├── crates/lab         — Experimental hooks (persona ledger)
├── crates/session     — Multi-session coordination (cadence-canon)
└── src/main.rs        — CLI: routes subcommands to checks
```

Each crate exposes structs implementing the `Check` trait:

```rust
pub trait Check {
    fn name(&self) -> &str;
    fn run(&self, input: &HookInput) -> CheckResult;
}
```

`CheckResult` carries an `Outcome` (Allow/Warn/Block) and an optional diagnostic message. The binary reads stdin, dispatches to the right check, prints the message to stderr, and exits with the outcome's code.

## Development

```bash
make help          # Show all targets
make test          # Run all 486 tests
make clippy        # Lint
make fmt           # Format
make ci            # Run all CI checks (fmt, clippy, test)
make install       # Install to ~/.cargo/bin
```

Requires Rust 2024 edition (1.85+).

## Reporting issues

Bug reports and feature requests for the binary belong here: [Issues](https://github.com/cameronsjo/cadence-hooks/issues/new/choose).

Two templates are available — Bug report (capture version, OS, plugin namespace, hook name, env, and repro) and Feature request. Issues about plugin distribution, marketplace metadata, or `hooks.json` wiring belong in [claude-configurations](https://github.com/cameronsjo/claude-configurations/issues) instead.

## License

[BSL-1.1](LICENSE) — free for personal, non-commercial use. Converts to MIT after four years.
