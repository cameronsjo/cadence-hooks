# cadence-hooks

Compiled [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hooks in Rust. A single binary replaces dozens of shell and Node.js hook scripts across multiple plugins, with sub-millisecond cold starts and zero runtime dependencies.

## Why

Claude Code hooks run on every tool invocation. Shell scripts accumulate startup overhead — spawning bash, loading profiles, forking subprocesses. This repo compiles all hook logic into one native binary that reads JSON from stdin, writes diagnostics to stderr, and exits with the correct status code. The result is faster, more testable, and easier to distribute.

## Hooks

64 hooks across 6 namespaces, each named for the plugin it serves:

| Namespace | Plugin | Hooks | Focus |
|-----------|--------|-------|-------|
| `cadence` | cadence | 14 | Terminology, secret guards, git safety, memory limits, markdown/docs nudges |
| `guardrails` | git-guardrails | 26 | Push & gh-write allowlists, branch/PR/issue nudges, dotfile & vault guards |
| `rules` | cadence-rules | 4 | Frontmatter validation + a security anti-pattern scan |
| `obsidian` | cadence-obsidian | 1 | Block `rm` inside the Obsidian vault |
| `metrics` | cadence-metrics | 9 | Cost-per-commit and subagent JSONL loggers (never block) |
| `session` | cadence-canon | 10 | Multi-session identity, peer disclosure, lane warnings |

**Full catalog:** [docs/hooks.md](docs/hooks.md) — every hook with its event and behavior, plus the CLI actions (`session declare`/`status`, `dismiss-main-branch-warn`) that are commands rather than hooks.

## Hook Protocol

Claude Code hooks communicate via a simple protocol:

```text
stdin  → JSON { tool_name, tool_input: { file_path, command, content, ... }, cwd }
stdout ← Nudge messages (JSON additionalContext, injected into Claude's context)
stderr ← Block diagnostics (fed back to Claude)
exit   → 0 (allow / nudge) | 2 (block, prevent operation) | other (non-blocking error)
```

Each subcommand reads this JSON, runs its check, and exits. No network calls, no config files, no dependencies beyond the binary.

## Installation

### Homebrew (macOS / Linux — recommended)

```bash
brew install cameronsjo/tap/cadence-hooks
```

Upgrade later with `brew update && brew upgrade cadence-hooks`.

### Windows

Releases ship a Windows build (`cadence-hooks-vX.Y.Z-windows-x86_64.zip`
containing `cadence-hooks.exe`). Install via Scoop (preferred) or WinGet:

```powershell
# Scoop
scoop bucket add cameronsjo https://github.com/cameronsjo/scoop-bucket
scoop install cameronsjo/cadence-hooks

# WinGet
winget install cameronsjo.cadence-hooks
```

For the direct `.zip`, download from [Releases](https://github.com/cameronsjo/cadence-hooks/releases)
and unpack `cadence-hooks.exe` to a directory on your `PATH` (e.g.
`%LOCALAPPDATA%\cadence-hooks`).

> **Git Bash is required for the hooks to fire.** Cadence's plugins dispatch
> through `.sh` wrappers, and Claude Code runs shell-form hook commands via Git
> Bash on Windows (falling back to PowerShell, which can't run `.sh`, when Git
> Bash is absent). Install [Git for Windows](https://git-scm.com/download/win)
> and keep `bash` on `PATH`. The binary runs fine without it — the guards just
> won't fire.

### From source

```bash
cargo install --git https://github.com/cameronsjo/cadence-hooks.git
```

### Manual download

Each release publishes per-platform archives named
`cadence-hooks-${VERSION}-${platform}.tar.gz` (`.zip` on Windows), where
`platform` is one of `macos-aarch64`, `macos-x86_64`, `linux-x86_64`,
`linux-aarch64`, `windows-x86_64`. Pick your platform and pin a version:

```bash
VERSION=v0.29.0

# macOS (Apple Silicon)
curl -sL "https://github.com/cameronsjo/cadence-hooks/releases/download/${VERSION}/cadence-hooks-${VERSION}-macos-aarch64.tar.gz" | tar xz
mv cadence-hooks ~/.local/bin/

# Linux (x86_64)
curl -sL "https://github.com/cameronsjo/cadence-hooks/releases/download/${VERSION}/cadence-hooks-${VERSION}-linux-x86_64.tar.gz" | tar xz
mv cadence-hooks ~/.local/bin/
```

Browse all assets on the [Releases](https://github.com/cameronsjo/cadence-hooks/releases) page.

### Verifying release integrity

`cadence-hooks` decides whether the harness lets a `git push`, a `gh` write, or
an edit-on-`main` through — so every release is signed and attested. You can
prove a download came from this repo's release workflow before you trust it, via
either `gh attestation verify` (GitHub-native) or offline `cosign verify-blob`
over `checksums.txt`. Full instructions for both routes — the OIDC identity, the
SBOM, and the commands — are in [SECURITY.md](SECURITY.md).

### Verify

```bash
cadence-hooks --version
cadence-hooks --help
```

## Documentation

- [docs/hooks.md](docs/hooks.md) — full hook catalog (all 45 hooks + CLI actions)
- [docs/configuration.md](docs/configuration.md) — `hooks.json` wiring, environment variables, the `doctor` audit, snoozing `warn-main-branch`
- [docs/testing.md](docs/testing.md) — run any hook against a sample payload by hand, including how to tell a real binary block from a wrapper fail-open
- [CONTRIBUTING.md](CONTRIBUTING.md) — adding a hook and the check-author debugging loop
- [SECURITY.md](SECURITY.md) — release signing, SBOM, and verification

## Architecture

```text
cadence-hooks (binary)
├── crates/core        — Hook protocol: JSON parsing, Check trait, exit codes
├── crates/cadence     — Cadence plugin hooks
├── crates/guardrails  — Git guardrails hooks
├── crates/rules       — Rules plugin hooks
├── crates/obsidian    — Obsidian plugin hooks
├── crates/metrics     — Fire-and-forget cost/usage loggers
├── crates/lab         — Experimental hooks (currently empty; landing pad)
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
make help     # Show all targets
make ci       # fmt check + clippy + tests (run before every commit)
make test     # Run the test suite
make install  # Install to ~/.cargo/bin
```

Requires Rust 2024 edition (1.85+). See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, testing conventions, and how to add a hook.

## Reporting issues

All cadence ecosystem issues — including everything about this binary (a wrong
block/allow decision, a guard bug, a feature request, plus plugin distribution,
marketplace metadata, and `hooks.json` wiring) — go to one tracker:
[**claude-configurations**](https://github.com/cameronsjo/claude-configurations/issues).
There is no separate per-repo tracker; the meta-repo `CLAUDE.md` issue-filing
rule is the single source of truth. When reporting a binary bug, capture
`cadence-hooks --version`, OS, plugin namespace, hook name, relevant `CADENCE_*`
env, and a repro (a payload via `cadence-hooks try …`). The fastest path from a
hook firing in error is `/cadence:feedback`.

## License

[BSL-1.1](LICENSE) — free for personal, non-commercial use. Converts to MIT after four years.
