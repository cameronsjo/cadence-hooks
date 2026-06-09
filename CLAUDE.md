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

**Check `git log --oneline -5` on main for bump commits before choosing the next version number.** Parallel Claude sessions release from this repo too — a 0.15.1 shipped mid-session while another session was building what became 0.15.2. The race only surfaced because the bump commit failed loudly; don't rely on that.

**The `[Unreleased]` CHANGELOG drifts across rapid releases — attribute by tag, not convenience.** Back-to-back releases (0.15–0.19) left already-shipped bullets sitting under `[Unreleased]`. At release time, place each bullet under the version that actually shipped it — find it with `git tag --contains <commit>` — rather than folding everything into the new version. `release.yml` uses `generate_release_notes: true`, so the public notes come from PRs since the last tag, **not** the CHANGELOG; a mis-sectioned changelog silently contradicts the published release notes (and `make bump` only touches Cargo.toml, so the CHANGELOG is a separate, hand-maintained edit).

**To bundle N PRs into ONE release, hold the version.** Every push to `main` that changes the `Cargo.toml` version auto-tags and releases — so merging N version-bumping PRs cuts N releases. When landing a merge train, resolve each rebased PR's `Cargo.toml`/`Cargo.lock` version conflict to `main`'s *current* value (`git checkout --ours Cargo.toml Cargo.lock`, then `cargo build` to re-sync the lock) so the merges don't auto-tag, then `make bump` **once** at the end for a single release. (Verified 2026-06-08 bundling #75/#76/#78 into 0.25.0; #79 had already self-released 0.24.0 on its own merge because its bump survived.)

## Gotchas

- **Ignore `make bump`'s "next steps" output** — it suggests `git tag` + `git push --tags`, which predates and races the auto-tag automation. Just commit and push; `auto-tag.yml` owns tagging.
- **hooks.json `if:` globs cannot match a pipe character** — `|` is the alternation separator. For checks that fire on pipelines (e.g. `warn-alias-parsing`), enumerate tool names in the filter and let the binary's pipe check do the precision work.
- **The git-safety hook (this repo's own product) blocks `git rebase` in Claude sessions.** To rebase a stacked PR branch onto main: cherry-pick its own commits onto a fresh branch from main, then `git push origin <tmp-branch>:<pr-branch> --force-with-lease`.
- **Registry/dispatch invariant**: every hook subcommand needs both a clap variant (src/main.rs) and a `HOOKS` entry (src/registry.rs) — including an `event` field that matches the `HookEvent` passed in the dispatch (`None` for loggers). The `registry_matches_clap_dispatch` unit test enforces this on every `cargo test`; the hooks.json audit test (`tests/hook_registration_audit.rs`) additionally cross-checks sibling plugin repos when they're present locally. **That cross-sibling check (`all_binary_subcommands_are_registered`) fails *locally* when sibling plugin checkouts lack not-yet-merged wiring, but GitHub CI has no siblings and skips it — so the GitHub Check legs, not local `make ci`, gate a merge.** Only chase a local audit failure if `registry_matches_clap_dispatch` *also* fails (that's a real internal bug); a lone `all_binary_subcommands_are_registered` failure usually just means a wiring PR hasn't merged into the sibling checkout yet.
- **Hook subcommands are stdin-driven** — run bare in a terminal they print guidance and exit 1 (never hang, never block). `cadence-hooks try <ns> <sub>` is the manual-test path: it runs any hook against a generated sample payload and reports the outcome.
- **TTY-dependent behavior (the interactive-terminal guard) cannot be tested via Claude's Bash tool** — it pipes stdin, so `is_terminal()` is always false there. Verify with `script -q /dev/null cadence-hooks <ns> <sub>` (allocates a pty) or a real terminal.
- **`rules validate-frontmatter` no-ops on paths without a `skills/<dir>/` ancestor.** Manual-testing the skill-`name:` check needs a real `.../skills/<dir>/SKILL.md` path in the Write payload — a bare `mktemp` path makes the check skip entirely and return a **false PASS for every name**, even a deliberately-wrong suffix. Build the payload with `jq` against a `skills/<dir>/` path, and include a wrong-suffix case as a control: it must exit 2 to prove the validator actually engaged (otherwise an all-PASS run is meaningless).
- **Guards fail open (ADR-0001)**: parse failures, unreadable files, and unknown subcommands exit 0/1, never 2. A guard's own failure must never block the user.
- **CADENCE_BYPASS=1 exempts `list`, `configure`, `doctor`, and the session CLI actions (`declare`, `status`)** — diagnostic/CLI commands must work during maintenance; enforcement hooks are bypassed.
- **Repro scripts/fixtures containing flagged terminology must build the term by concatenation** (`TERM_W="$(printf 'white%s' 'list')"`) — the installed terminology guard blocks Writes containing the literal to any non-excluded path, including `/tmp`. CLAUDE.md and `cadence-hooks/` paths are excluded; scratch fixtures elsewhere are not.
