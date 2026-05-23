# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `metrics` namespace: fire-and-forget loggers for the [cadence-metrics](https://github.com/cameronsjo/cadence-metrics) plugin, ported from its bash hooks. `snapshot` (PreToolUse) records HEAD before a `git commit`; `log-commit` (PostToolUse) scans the transcript for token usage since the last commit, computes USD cost from an embedded-but-overridable price table (`--prices` / `CADENCE_METRICS_PRICES`), and appends to `commits.jsonl`; `log-subagent` (SubagentStart/Stop) appends lifecycle records to `subagents.jsonl` (`CADENCE_METRICS_DEBUG=1` adds a `_keys` field). New `Logger` trait + `run_logger_from_stdin` in core keep logging (always exit 0) separate from the enforcement `Check` trait. JSONL output verified at parity with the bash hooks.
- `nudge-polish-before-pr` hook (cadence plugin) fires on `gh pr create` and reminds the model to run `/polish` (cadence-forge:polish) — a branch-scoped polish pass against `origin/main` — before opening the PR. Gated by `if: "Bash(gh pr create*)"` so the binary only spawns on actual PR-create commands. Skippable for trivial fixes or branches already polished. Disable via `CADENCE_DISABLE=nudge-polish-before-pr`.
- `CADENCE_ALLOW_MAIN` env var permanently silences `warn-main-branch` for a repo. Set in `<repo>/.claude/settings.json` (project) or `~/.claude/settings.json` (user-global) under the `env` block. Truthy values: `1`, `true`, `yes` (case-insensitive). Useful for repos where main IS the working branch by design — personal scratchpads, dotfiles, vaults.
- `cadence-hooks doctor` subcommand scans installed plugin `hooks.json` files for shell-expansion bugs (initially: single-quoted `${CLAUDE_PLUGIN_ROOT}` and bare env vars). Reports one block per offender; exits 1 when violations exist. `--root <dir>` overrides the default `~/.claude/plugins/cache` scan path. (#24)
- `Check::skip_at_effort()` trait method lets individual checks opt out at specific `$CLAUDE_EFFORT` levels without each implementer reading the env var by hand. Default `&[]` preserves current behavior — opt in for heavy diagnostics that are optional on trivial sessions. (#23)

### Changed

- `warn-main-branch` message now suggests `--for 2h` (was `30m`) and surfaces both silencing options: time-bounded snooze and permanent `CADENCE_ALLOW_MAIN` env var.

### Fixed

- `warn-main-branch` now scopes branch detection to the edited file's repo via `git -C`, resolves relative file paths against `HookInput.cwd`, and passes the resolved `repo_root` to the snooze lookup. Previously the hook resolved git context from the hook process's CWD, so editing inside a nested repo from a session whose CWD was the outer parent both fired wrong warnings and broke per-repo snooze suppression. (#26)
- `prevent-secret-leaks` env-dump heuristic now position-checks chain segments with a quote-aware splitter instead of substring-matching. Eliminates false positives on benign commands containing `env` as a substring — branch names ending in `-env`, commit messages mentioning env vars, `gh env list`, `aws-vault env`, `direnv env`, `grep env_dump`, and heredocs inside `"$(...)"` no longer fire the nudge. (#22, #25)

## [0.8.0] - 2026-04-21

### Changed (breaking)

- Renamed all configuration env vars under a unified `CADENCE_*` prefix:
  - `CADENCE_HOOKS_DISABLE` → `CADENCE_DISABLE`
  - `CADENCE_HOOKS_BYPASS` → `CADENCE_BYPASS`
  - `GIT_GUARDRAILS_ALLOWED_OWNERS` → `CADENCE_ALLOWED_OWNERS`
  - `GIT_GUARDRAILS_ALLOWED_REPOS` → `CADENCE_ALLOWED_REPOS`
- `OBSIDIAN_VAULT` stays unprefixed (cross-tool convention).

### Added

- Under Claude Code (detected via `CLAUDECODE=1`), the `configure` subcommand is hidden from `--help` and refuses to run interactively. `configure --list` stays available. This closes a bypass route where an agent could silently disable guardrails by launching the interactive wizard.

### Migration

Update `.claude/settings.json` or any shell rc where you set the old vars:

```diff
- "CADENCE_HOOKS_DISABLE": "guard-push-remote"
+ "CADENCE_DISABLE": "guard-push-remote"
- "GIT_GUARDRAILS_ALLOWED_OWNERS": "cameronsjo cameron"
+ "CADENCE_ALLOWED_OWNERS": "cameronsjo cameron"
```

## [0.4.1] - 2026-03-16

### Added

- AST-based chain analysis for `git push` — chained pushes to the same remote (e.g. `git push origin main && git push origin v1.0`) are now allowed instead of blanket-blocked
- 15 adversarial tests for chain analysis bypass attempts

### Fixed

- Cross-platform `bump-version.sh` — works on both macOS and Linux

## [0.4.0] - 2026-03-16

### Added

- AST-based loop analysis via `brush-parser` — loops with explicit targets pointing to owned repos are now permitted instead of blanket-blocked
- `warn-cron-datetime` guardrail for CronCreate hooks
- Unit tests for `warn-main-branch` (10 tests) and `check-idle-return` (11 tests)
- Adversarial input tests and edge case hardening across all hooks
- Panic handler for graceful failure reporting

### Changed

- Extracted shared shell utilities (`strip_quotes`, `repo_from_url`, `git_command`, `parse_work_dir`) into `cadence-hooks-core::shell`
- `guard-gh-write` now resolves `cd` chains via `parse_work_dir`
- Reordered `guard-push-remote` checks so structural blocks precede env var checks
- Narrowed version-mismatch catch-all to specific clap error kinds
- 551 tests (up from 486)

### Fixed

- Normalized file paths to prevent bypass attacks
- Reduced false positives from CodeRabbit review findings
- Fail open with warning on plugin version mismatch

## [0.3.0] - 2026-03-12

### Added

- Initial implementation: 19 hooks across 4 plugin crates
- Core protocol library (`cadence-hooks-core`) with `Check` trait, JSON parsing, exit codes
- **cadence** hooks: terminology, orphaned-todos, prevent-secret-leaks, prevent-secret-writes, memory-guard, git-safety, line-endings, env-vars, warn-untracked, markdown-lint
- **guardrails** hooks: guard-push-remote, guard-gh-write, guard-gh-dangerous, guard-git-init, warn-main-branch, check-idle-return
- **rules** hooks: validate-frontmatter, security-patterns
- **obsidian** hooks: trash-guard
- CI workflow with fmt, clippy, and test checks
- Release workflow with cross-compilation (linux x86_64/aarch64, macOS x86_64/aarch64)
- SLSA build provenance attestation on releases
- 486 tests covering happy paths, edge cases, and bypass scenarios
