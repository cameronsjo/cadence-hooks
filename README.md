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
| `warn-untracked` | PreToolUse (Bash) | Warn about untracked files during git commit |
| `markdown-lint` | PreToolUse (Write) | Run markdownlint on markdown files |

### guardrails (git-guardrails)

| Hook | Event | What it does |
|------|-------|--------------|
| `guard-push-remote` | PreToolUse (Bash) | Block git push to repos you don't own |
| `guard-gh-write` | PreToolUse (Bash) | Block gh write operations to non-owned repos |
| `guard-gh-dangerous` | PreToolUse (Bash) | Block irreversible gh operations (repo delete) |
| `guard-git-init` | PreToolUse (Bash) | Nudge to scaffold after git init |
| `warn-main-branch` | PreToolUse (Write, Edit) | Warn when editing on main/master branch |
| `check-idle-return` | PreToolUse | Nudge after idle periods between edits |

### rules

| Hook | Event | What it does |
|------|-------|--------------|
| `validate-frontmatter` | PreToolUse (Write, Edit) | Validate SKILL.md and command frontmatter |
| `security-patterns` | PreToolUse (Write, Edit) | Scan for security anti-patterns |

### obsidian (cadence-obsidian)

| Hook | Event | What it does |
|------|-------|--------------|
| `trash-guard` | PreToolUse (Bash) | Block `rm` in Obsidian vault (use .trash/ instead) |

## Hook Protocol

Claude Code hooks communicate via a simple protocol:

```
stdin  → JSON { tool_name, tool_input: { file_path, command, content, ... }, cwd }
stderr ← Diagnostic message (shown to user)
exit   → 0 (allow) | 1 (warn, show message) | 2 (block, prevent operation)
```

Each subcommand reads this JSON, runs its check, and exits. No network calls, no config files, no dependencies beyond the binary.

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

Some hooks require configuration:

| Variable | Used by | Purpose |
|----------|---------|---------|
| `GIT_GUARDRAILS_ALLOWED_OWNERS` | `guard-push-remote`, `guard-gh-write` | Space or comma-separated usernames |
| `GIT_GUARDRAILS_ALLOWED_REPOS` | `guard-gh-write` | Space or comma-separated `owner/repo` pairs |
| `OBSIDIAN_VAULT` | `trash-guard` | Absolute path to Obsidian vault |

## Architecture

```
cadence-hooks (binary)
├── crates/core        — Hook protocol: JSON parsing, Check trait, exit codes
├── crates/cadence     — Cadence plugin hooks (10 checks)
├── crates/guardrails  — Git guardrails hooks (6 checks)
├── crates/rules       — Rules plugin hooks (2 checks)
├── crates/obsidian    — Obsidian plugin hooks (1 check)
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

## License

[BSL-1.1](LICENSE) — free for personal, non-commercial use. Converts to MIT after four years.
