# cadence-hooks

Rust workspace (8 crates) compiling to a single `cadence-hooks` binary. Dispatches Claude Code hook checks via clap subcommands, organized by namespace (cadence, guardrails, rules, obsidian, metrics, lab, session).

## Build & Test

- `make ci` = fmt-check + clippy `-D warnings` + all tests. Run before every commit — the pre-commit hook also needs cargo on PATH.
- cargo lives at `~/.cargo/bin` — `export PATH="$HOME/.cargo/bin:$PATH"` in every shell invocation, including git commits (the pre-commit hook runs cargo and aborts silently without it).
- `cargo fmt --all` before `make ci` after writing long assert lines — fmt-check fails CI otherwise.
- **Local `make ci` green does NOT guarantee CI green when the local Rust toolchain trails CI's.** CI runs the latest stable clippy, which flags lints the older local clippy doesn't (e.g. `collapsible_match` on 1.96). Treat the first CI run as the real clippy verdict, or `rustup update` before a PR.

## Release (fully automated — do NOT create tags or edit the tap formula manually)

1. `make bump VERSION=X.Y.Z` (updates Cargo.toml), then `cargo check` to refresh Cargo.lock
2. Commit both files, push to main
3. `auto-tag.yml` creates the `vX.Y.Z` tag → `release.yml` builds 4 platform binaries, publishes the GitHub Release, and sends a `repository_dispatch` that updates `cameronsjo/homebrew-tap`'s formula

Manual tagging or formula edits race the automation. Post-release: `brew update && brew upgrade cadence-hooks`, verify `cadence-hooks --version`.

## Gotchas

- **Ignore `make bump`'s "next steps" output** — it suggests `git tag` + `git push --tags`, which predates and races the auto-tag automation. Just commit and push; `auto-tag.yml` owns tagging.
- **hooks.json `if:` globs cannot match a pipe character** — `|` is the alternation separator. For checks that fire on pipelines (e.g. `warn-alias-parsing`), enumerate tool names in the filter and let the binary's pipe check do the precision work.
- **The git-safety hook (this repo's own product) blocks `git rebase` in Claude sessions.** To rebase a stacked PR branch onto main: cherry-pick its own commits onto a fresh branch from main, then `git push origin <tmp-branch>:<pr-branch> --force-with-lease`.
- **Registry/dispatch invariant**: every hook subcommand needs both a clap variant (src/main.rs) and a `HOOKS` entry (src/registry.rs) — including an `event` field that matches the `HookEvent` passed in the dispatch (`None` for loggers). The `registry_matches_clap_dispatch` unit test enforces this on every `cargo test`; the hooks.json audit test (`tests/hook_registration_audit.rs`) additionally cross-checks sibling plugin repos when they're present locally.
- **Hook subcommands are stdin-driven** — run bare in a terminal they print guidance and exit 1 (never hang, never block). `cadence-hooks try <ns> <sub>` is the manual-test path: it runs any hook against a generated sample payload and reports the outcome.
- **Guards fail open (ADR-0001)**: parse failures, unreadable files, and unknown subcommands exit 0/1, never 2. A guard's own failure must never block the user.
- **CADENCE_BYPASS=1 exempts `list`, `configure`, `doctor`, and the session CLI actions (`declare`, `status`)** — diagnostic/CLI commands must work during maintenance; enforcement hooks are bypassed.
