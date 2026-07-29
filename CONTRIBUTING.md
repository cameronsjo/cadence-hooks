# Contributing

Thank you for your interest in cadence-hooks. This project is currently maintained as a personal tool, but contributions are welcome.

## Getting Started

```bash
git clone https://github.com/cameronsjo/cadence-hooks.git
cd cadence-hooks
make ci    # Run fmt check, clippy, and tests
```

Requires Rust 2024 edition (1.85+).

### Windows

The binary builds and tests natively on Windows (`x86_64-pc-windows-msvc`); CI
runs the full `make ci` on `windows-latest`. `make` itself may not be present —
run the steps directly (`cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test --workspace`), or use Git Bash, which
provides `make`. The pre-commit hook needs a `bash` shell (Git Bash satisfies
it). Build a release binary with
`cargo build --release --target x86_64-pc-windows-msvc`.

## Development Workflow

1. Create a feature branch from `main`
2. Write tests first — each check should have both happy-path and edge-case coverage
3. Run `make ci` before pushing
4. Open a PR against `main`

## Prerelease Builds

The Homebrew beta channel (`cadence-hooks-beta`) is retired — it lagged stable
and created version-skew problems instead of catching them (#39). To run
prerelease code ahead of a stable release, install straight from a branch:

```bash
cargo install --git https://github.com/cameronsjo/cadence-hooks.git --branch <branch>
# or pin a specific commit:
cargo install --git https://github.com/cameronsjo/cadence-hooks.git --rev <sha>
```

This installs to `~/.cargo/bin/cadence-hooks`, which shadows the Homebrew
binary while `~/.cargo/bin` precedes `/opt/homebrew/bin` on `PATH`. Return to
stable with `cargo uninstall cadence-hooks` followed by
`brew install cameronsjo/tap/cadence-hooks` (or `brew upgrade`).

## Code Style

- **Conventional Commits**: `type(scope): description` (e.g., `fix(cadence): scope safe-template check to target`)
- **cargo fmt** and **cargo clippy** must pass with zero warnings
- Tests are in-file `#[cfg(test)] mod tests` blocks, not separate files
- Each check implements the `Check` trait from `cadence-hooks-core`

## Adding a New Hook

1. Add a module in the appropriate crate (`crates/cadence/`, `crates/guardrails/`, etc.)
2. Implement the `Check` trait
3. Export the module from the crate's `lib.rs`
4. Add a subcommand variant in `src/main.rs`
5. Add a `HookEntry` in `src/registry.rs` — name, description, plugin, and
   `event` (matching the `HookEvent` passed in the main.rs dispatch; `None`
   for loggers). The `registry_matches_clap_dispatch` test fails until the
   registry and dispatch agree
6. Write tests covering: allow, warn, block, edge cases, and bypass scenarios

New hooks inherit the interactive-terminal guard and `cadence-hooks try`
support automatically — both come from `run_check_from_stdin` /
`run_logger_from_stdin` plus the registry entry. There is nothing extra to
wire; verify with `cadence-hooks try <namespace> <name>`.

### Optional: effort-gating

The `Check` trait exposes a `skip_at_effort()` method that defaults to an
empty slice. Override it to short-circuit the check at specific effort
levels (`$CLAUDE_EFFORT` from Claude Code; defaults to `"medium"` when
unset):

```rust
impl Check for ExpensivePostScan {
    fn name(&self) -> &str { "expensive-post-scan" }
    fn run(&self, input: &HookInput) -> CheckResult { /* ... */ }

    fn skip_at_effort(&self) -> &[&str] {
        &["low"]  // skip when CLAUDE_EFFORT=low
    }
}
```

Most cadence-hooks checks are security/correctness invariants and should
keep the default (always run). Use this only when the check is genuinely
optional at the listed levels — typically heavy PostToolUse scans or
diagnostics that have no value on trivial sessions.

## Testing Conventions

- Test names describe the scenario: `bash_cat_example_redirect_to_env_blocked`
- Document known limitations as explicit test cases with comments
- Use helper functions (`make_input`, `make_bash_input`) for test setup
- Group tests: happy path first, then unhappy path / edge cases

### Running the suite from a `/tmp` worktree

`git worktree add /tmp/my-feature ...` (the pattern this project's own
worktree docs recommend) works fine for `cargo test --workspace`: fixture
directories that would otherwise land under the checkout's own `target/` —
itself under `/tmp` in that layout, which `enforce-worktree`'s carve-out
exempts — automatically relocate to `$XDG_CACHE_HOME` (or `$HOME/.cache`)
instead, so the guard's block/allow logic is still exercised for real
(cadence-hooks#403). A one-line `note:` on stderr says when this happens —
once per test binary (`cargo test --workspace` runs several, each its own
process), not once per fixture.

If your machine has neither a usable `$XDG_CACHE_HOME` nor any resolvable home
directory (a stripped-down sandbox), point fixtures at an explicit directory
instead:

```bash
export CADENCE_HOOKS_TEST_SCRATCH_ROOT=/some/carve-out-free/dir
```

## Reproducing a Check by Hand

A check is stdin JSON → exit code, so any reported bug (or new check) can be
driven from the CLI without launching Claude Code.
[docs/testing.md](docs/testing.md) covers the operator-level workflow (`try`,
bare-invocation guidance, event payload shapes); this section is the
check-author's debugging loop.

### Workflow

1. Start with `cadence-hooks try <namespace> <hook>` to confirm the hook's
   event and see a working sample payload
2. Copy that payload into a fixture file and switch to raw piping:
   `cadence-hooks <namespace> <hook> < fixture.json; echo "rc=$?"`
3. Change one `tool_input` field at a time to isolate what trips the check
4. If version drift is suspected, run both binaries against the same fixture:
   `cadence-hooks --version` (installed) vs
   `./target/release/cadence-hooks --version` (your checkout)
5. Once the failure is understood, add the payload as a unit test in the
   check's `#[cfg(test)]` block

Use `try` when you want to see what a hook does; use raw `printf | cadence-hooks ...`
when you need to control the exact payload — `try` always generates its own.

### Tool shapes

Each tool carries its content in a different field. A check that only reads
one shape silently misbehaves on the others — this is the most common check
bug class (#60, #63).

| Tool | Field to inspect | Notes |
|---|---|---|
| Write | `tool_input.content` | The whole document |
| Edit | `tool_input.old_string` / `new_string` | A *fragment* — `HookInput::effective_content()` reads `file_path` from disk and applies the replacement to get the document |
| MultiEdit | `tool_input.edits[]` | Array of `{old_string, new_string, replace_all}` applied in order |
| Bash | `tool_input.command` | The command string |

Checks that validate whole-document structure must use
`HookInput::effective_content()`, which simulates Edit/MultiEdit against the
on-disk file. This means an Edit/MultiEdit fixture only behaves realistically
when `file_path` points at a file that actually exists — create it first.

**Edit payload** (body-only edit to an on-disk SKILL.md — must allow):

```bash
mkdir -p /tmp/fixture/skills/demo
printf -- '---\nname: demo\ndescription: test\n---\n# Demo\n\nBody.\n' > /tmp/fixture/skills/demo/SKILL.md

printf '%s' '{"tool_name":"Edit","tool_input":{"file_path":"/tmp/fixture/skills/demo/SKILL.md","old_string":"Body.","new_string":"New body."}}' \
  | cadence-hooks rules validate-frontmatter; echo "rc=$?"   # expect rc=0
```

**MultiEdit payload** (same file, two sequential edits):

```bash
printf '%s' '{"tool_name":"MultiEdit","tool_input":{"file_path":"/tmp/fixture/skills/demo/SKILL.md","edits":[{"old_string":"# Demo","new_string":"# Demo v2"},{"old_string":"Body.","new_string":"New body."}]}}' \
  | cadence-hooks rules validate-frontmatter; echo "rc=$?"   # expect rc=0
```

### Reporting what you find

When filing a bug, note which binary you reproduced against
(`cadence-hooks --version` for the installed one, the branch/SHA for a
checkout build) — line numbers and behavior can differ between them.

## License

By contributing, you agree that your contributions will be licensed under [Apache-2.0 with the Commons Clause](LICENSE).
