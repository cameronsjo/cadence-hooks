# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.20.0] - 2026-06-04

### Changed

- `guard-git-init` now also fires on `gh repo create` (not just `git init`), and its nudge frames the license as the author's decision — routing to `/cadence-groundwork:choosing-license` to compare options before assuming one. The guard name is unchanged. (Companion `if`-filter broadening ships in `cadence-guardrails`'s `hooks.json`.)

## [0.19.0] - 2026-06-04

### Changed

- `validate-skill-frontmatter` now accepts an optional `namespace:` prefix on a skill's `name:` field — the `plugin:directory` invocation id (e.g. `name: cadence:attune`, `name: cadence-forge:add-narrative-logging`). Bare names still pass; the post-colon suffix must still equal the skill directory, so `cadence:wrong` for an `attune/` dir is still blocked. The namespace itself is not verified against the plugin name: deriving the plugin from the file path is fragile (source vs cache) and the check must not force the prefix on non-cadence users. This reverses the prefix-rejection tightened in #65 — the cadence ecosystem standardizes on the prefix for discoverability and self-documenting source.

## [0.18.0] - 2026-06-04

### Changed

- Global state paths (metrics, persona ledger, the `doctor` plugin scan) now honor `CLAUDE_CONFIG_DIR`, matching Claude Code's own config-dir relocation, instead of hardcoding `~/.claude`. A new `cadence_hooks_core::paths` module resolves the config dir (first non-empty comma entry, `~`-expanded; falls back to `~/.claude`); `doctor`'s plugin scan falls back to `~/.claude/plugins` when the config-dir variant is absent, staying correct whichever directory the plugin loader uses.

## [0.15.1] - 2026-06-02

### Changed

- `guard-pr-issue-link` renamed to `warn-pr-issue-link` and downgraded from a hard block to a nudge. PRs without a linked issue are a routine, intentional workflow; the check now reminds about closing keywords instead of blocking `gh pr create`. The companion `verify-pr-autoclose` (PostToolUse, advisory) is unchanged and still covers broken issue refs.

## [0.13.0] - 2026-06-01

### Added

- Five guardrails checks converting machine-enforceable prose rules from a personal CLAUDE.md into deterministic hooks (#52, #53):
  - `guard-op-vault-scan` (**block**) — `op item list` / `op vault list` enumeration, including inside exec wrappers. Single-item reads (`op read`, `op item get`) stay allowed; the guard targets enumeration, not access.
  - `warn-curl-alias` (nudge) — bare `curl` with `-H`/`--header` flags, for machines where curl is aliased to curlie (which infers POST from JSON-like headers, causing silent 400s). Per-segment analysis keeps `grep -H` and other piped tools from false-positiving.
  - `warn-gh-merge-preflight` (nudge) — pre-flight checklist on `gh pr merge`: draft PRs report MERGEABLE/CLEAN but fail with a GraphQL error (check `isDraft`); worktree checkouts break `--delete-branch` local cleanup; failed merges may have landed server-side (verify `mergedAt` before retrying).
  - `warn-coderabbit-retrigger` (nudge) — `@coderabbitai review` comments are no-ops on already-reviewed content (CodeRabbit's incremental review is content-cached, not SHA-cached); push a new commit instead.
  - `warn-alias-parsing` (nudge) — piping aliased-tool output (`cat`/`find`/`ls`/`du`/`df`/`top` → bat/fd/eza/dust/duf/btm) into parsers. Fires only when the aliased tool is a pipeline *producer*; consumer position (`git diff | cat`) and interactive use stay silent.
- `KNOWN_DISTINCT_SETTINGS_SCRIPTS` allowlist in the registration audit test, for settings.json scripts that trip the keyword-overlap heuristic without duplicating any plugin hook (first entry: `block-vault-git-writes.sh`, an Obsidian-vault guard unrelated to the 1Password `guard-op-vault-scan`).

## [0.12.0] - 2026-06-01

Backfilled entry — this release shipped without a changelog section.

### Added

- Three guardrails checks: `guard-dotfiles` (block direct edits to production dotfiles, opt-in via `CADENCE_GUARD_DOTFILES=1`), `guard-pr-issue-link` (block `gh pr create` without a closing issue keyword), `verify-pr-autoclose` (verify and repair issue auto-close after PR create/merge). (#43, #47)
- `doctor` subcommand cross-reference + registry export + `--quiet`. (#39, #48)

### Fixed

- Mid-line security-pattern line numbers + audit enforcement for the cadence-rules migration. (#49)

### Removed

- Homebrew beta channel retired; stable formula is the single release channel. (#39, #50)

## [0.11.0] - 2026-05-30

### Added

- `lab` namespace for the [cadence-lab](https://github.com/cameronsjo/cadence-lab) plugin: a two-hook **self-representation persona ledger**. `persona-nudge` (SessionStart, startup/clear) injects a constrained contract asking the model to record a per-session self-representation (form/qualities/stance/color/texture/confidence) to a staging file; `persona-gate` (PostToolUse/Write) runs Tier 1 schema validation with itemized feedback plus a Tier 2 regex cheek heuristic (warn mode → system-written `flags`), then promotes the validated record into an append-only `~/.claude/persona/personas.jsonl`. The ledger only receives hook-written, validated records. Configurable via `~/.claude/persona/config.json`; retry cap downgrades to a `forced-accept` flag. New crate `crates/lab/`. (#41)
- Core: `HookEvent::SessionStart`, and `Outcome::LoopBlock` + `CheckResult::loop_block` — the documented exit-0 `{"decision":"block","reason":...}` re-prompt primitive for PostToolUse feedback loops (a hard `exit 2` can't un-run a tool that already executed). `HookInput` gains `session_id`/`source`/`model` fields + accessors (`Default` derived); new `make_session` test builder. All backward compatible — existing Pre/Post hooks are unaffected.

## [0.10.0] - 2026-05-23

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
