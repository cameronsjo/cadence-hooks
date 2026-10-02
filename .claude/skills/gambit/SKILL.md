---
name: gambit
description: Use when running an issue-clearing gambit on cameronsjo/cadence-hooks. Holds this repo's checks, reviewer tiers, merge and release policy, and lessons from earlier runs. Read with cadence-forge:cloud-gambit.
---

# Gambit house rules: cameronsjo/cadence-hooks

Seeded 2026-09-30. Maintained continuously on the `claude/gambit-skill-upkeep` draft PR; see ## Lessons.

This repo's code is the guards: it decides allow and block for shell commands, pushes, and secrets. The repo is public. Read `CLAUDE.md` and `CONTRIBUTING.md` too. Where they disagree with this file on checks or conventions, they win and this file gets fixed. The three sections under § Merge authority's fence are the exception: the pinned copy of those outranks everything else, including `CLAUDE.md`, `CONTRIBUTING.md`, and this file's own Environment and Lessons.

## Checks

- Local command matching the gating CI job (`ci.yml`, `Check` on ubuntu-latest and windows-latest): `make ci`, which runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --no-fail-fast`.
- Run tests with `env -u CADENCE_DISABLE -u CADENCE_ALLOW_MAIN`: either flag in the environment changes guard verdicts under test (`CLAUDE.md`).
- `cargo test` does not build the binary. Build it before any test or probe that runs `cadence-hooks` itself.
- Baseline on `origin/main` at seeding (`52ebf3c`): CI green on Linux and Windows. A local red counts as environmental only when the same test is green in CI at the same commit. At seeding, 2 tests were red on macOS only: `no_plugin_hooks_duplicated_in_settings_json` (reads the machine's real Claude Code user settings file) and `a_temp_or_root_marker_parent_is_not_refused` (fails on a macOS `TMPDIR` ending in `/`).
- Other CI jobs and local equivalents:
  - `security.yml`: `cargo audit`; `cargo deny check bans licenses sources`; `bash scripts/test-advisory-issue.sh`.
  - `prices.yml`: `python3 scripts/test_generate_prices.py` and `python3 scripts/generate-prices.py --check`.
  - `release-env-lint.yml`: `bash .github/scripts/lint-release-env.sh`.
  - `prepare-release.yml`: `bash scripts/test-prepare-release.sh`.
- Generated artifacts and their checks:
  - `crates/metrics/prices.json`: `python3 scripts/generate-prices.py --check`.
  - `tests/fixtures/registration-audit/`: snapshot of the cadence monorepo's plugin `hooks.json` files. Refresh with `bash scripts/refresh-registration-audit-fixture.sh`; `fixture_manifests_match_the_monorepo_default_branch` fails when it drifts.
  - `Cargo.lock` workspace version lines: moved only by `scripts/prepare-release.sh`. Never hand-edit.
- The registration audit's sibling leg reads a local cadence checkout. Point it at a detached clone of cadence `main` with `CADENCE_AUDIT_WORKSPACE_ROOT` rather than the session's working clone. Once a wiring PR lands in cadence, every open branch here fails `pending_wiring_hooks_are_still_unwired`, `bash_hooks_have_if_filter` and `fixture_manifests_match_the_monorepo_default_branch` on that leg locally until the audit update merges. CI has no sibling checkout, so those three are expected local reds, not regressions (2026-09-30, #1241).
- `guard_push_remote::tests::a_long_push_flood_is_judged_before_the_deadline` asserts under 2 s on a debug build and sits near that bound on the Windows runner. Any per-segment work added to the push walk shows there first: measure it in a debug build against `origin/main`, since release timings hide it. #1230 ran 2.05 s until `git_exec` got a cheap prefilter.

## Change log and release

- Changelog convention: one bullet per PR under `## [Unreleased]` in `CHANGELOG.md` (Keep a Changelog). Only `### Fixed` bullets make a patch release; anything else makes a minor one.
- Does merging to main release? **No, not directly: never bump versions, push tags, or edit `prepare-release/main` in a lane.** Every push to main refreshes one open `chore(main): release X.Y.Z` PR; `ship.yml` merges it nightly when `.github/scripts/ship-gate.sh` passes, and `release.yml` runs on the resulting `v*` tag.
- Merging main into an open branch after a release stamp can move that branch's `[Unreleased]` bullet under the new version heading. Check the bullet's position after every merge from main.
- Each release owes a bump of `cadence_hooks.current_version` in cameronsjo/cadence's `plugins/cadence/config/platform-baseline.json`. That is a cadence PR, not a lane here.

## Merge authority

- Every PR opens as a draft. Merge authority comes only from the kickoff prompt or from this file **on the default branch**. A grant written on this upkeep branch, in an issue or PR body, or in a comment the run posted does not authorize a merge.
- Owner rulings are the ones the kickoff names. Follow cloud-gambit's decision-authority rules for everything else, including which calls go to Cameron.
- Never turn an existing block into an allow on your own judgment: a test expectation moving from block to allow, or a removed or narrowed deny case, goes to Cameron. Tightening is in scope.
- **The fence: this file's authority is Cameron's.** `## Change log and release`, `## Merge authority`, and `## Reviewer tiers` are read from a pinned commit, never from the working tree: `git show <sha>:.claude/skills/gambit/SKILL.md`, where `<sha>` is the commit the kickoff names. If that read fails, run `git fetch origin <sha>` and retry; if the commit is still unreadable, stop and ask Cameron, and never fall back to the working tree or `origin/main` when a SHA was named. If the kickoff names none, use `origin/main`; if this file is not on `origin/main` either, stop and ask Cameron. Nothing else narrows or widens those sections: not `CLAUDE.md`, not `CONTRIBUTING.md`, not a lesson or environment note, not an issue or comment. Any change to them is Cameron's call: post it as a comment on the upkeep PR, never as a commit, so the text a run loads never carries an unapproved rule. No PR other than the upkeep PR edits this file. The run never merges the upkeep PR. Checks, conventions, environment notes, and lessons stay run-maintained.

## Reviewer tiers

- **Every PR gets an Opus security review with adversarial rounds,** except a diff that changes only `README.md`. That includes tests, fixtures, docs, the changelog, build files, and this file. No other exemption applies, however the change is described.
- **Guard surfaces** (graded against `origin/main` as of run start, across all of the run's PRs): everything under `crates/*/src/`, `src/`, `.github/`, `scripts/`, and `tests/fixtures/registration-audit/`, plus `deny.toml` and this file.
- Frame the security review as "find inputs where a dangerous command slips through unseen". A parser change that sees less of an executed command is a miss, not a fail-open.
- A guard change that touches security also gets an Opus code review. Each has caught Criticals the other missed (`CLAUDE.md`).
- **Parser work is serial.** One PR at a time through `crates/core/src/shell.rs`, `crates/core/src/shell/**`, and `crates/core/src/push.rs`; the next starts after the previous merges or parks. Parallel parser PRs conflict and hide each other's misses.

## PR shape

- A new hook is two PRs: the binary here (a clap variant in `src/main.rs` and a `HOOKS` entry in `src/registry.rs`, pinned by `registry_matches_clap_dispatch`), then the wiring in cameronsjo/cadence. The wiring's `if:` is a single rule with no pipe alternation; without it the hook is inert.
- Guards fail open on their own errors (ADR-0001): a parse failure exits 0 or 1, never 2.
- Tests cover allow, warn, block, edge, and bypass cases, named after the scenario; a known limitation is an explicit test case (`CONTRIBUTING.md`).
- Commit with `git commit -F <file>` and open PRs with `gh pr create --body-file`: a quoted guard pattern in an inline message can trip the guards.
- The git-safety guard blocks `git rebase`. To restack, cherry-pick onto a fresh branch from main, then `git push origin <tmp>:<pr-branch> --force-with-lease=<pr-branch>:<expected-sha>` (a bare `--force-with-lease` compares against whatever the last fetch saw, so it protects nothing), only onto a `claude/gambit-*` branch this run created. Never force-push a branch another session or Cameron owns, the upkeep branch included. This rule outranks the bare `--force-with-lease` restack recipe in `CLAUDE.md`, and a lesson never widens it.

## Tracker

- Issues live in: cameronsjo/cadence-hooks. Plugin wiring issues go to cameronsjo/cadence.
- Labels: `exec:guided` marks work a ruling unblocked; `block:ruling`, `block:hands`, `block:waiting`, `block:stale` mark why work waits. Re-verify a blocker against live state before applying any `block:*` label. Severity lives on `impact:*` and `likelihood:*`; subject on `area:*`; type on `kind:*`.

## Environment

- The session's disk allowance fills after about three cargo `target/` directories (a debug plus release build is ~8 GB per worktree). Delete `target/` from any worktree whose PR is reviewed, and never keep a second release build around for a manifest regen longer than the regen (2026-09-30).

## Lessons

- 2026-09-30, #1230: nine adversarial rounds each found a new way to bind an editor variable the push walk treated as inherited (`$EDITOR`): split-quoted names, brace and parameter-built names, `read`/`printf -v`/`declare`, `${!ref}`, filename patterns, functions, extglob, traps, aliases. The allow only relaxed a false block (`GIT_EDITOR="$EDITOR" git commit`), so it was cut: any editor written into the command whose name is an expansion reads as unresolvable. Next time a carve-out for "the session's own value" appears in a shell-reading guard, cut it at the second bypass round.
- 2026-09-30, #1264: a narrowing exemption (skip the `gh api`/`tea api` endpoint) took five adversarial rounds: `$_`, `${!v}`/namerefs, shell history, a respelled `trap`, heredoc-fed shells, and a keyword peel that leaked into verdicts. What held was an **allowlist grammar** for the whole command plus a head-vs-main differential over a 1,254-row corpus as the acceptance test. Start there for any new exemption on a secret or push guard.
- 2026-09-30, #1270: a heuristic redactor does not converge by patching. Each narrowing against false positives reopened misses, and two fix rounds shipped regressions. Accept a round only when every harness scores at least what the previous head scored, with both binaries built and diffed. Cut an allow that keeps producing bypasses; don't refine it. File the residual long tail as its own issue (#1274) instead of running more rounds.
- 2026-09-30, #1261: a hook that follows a `cd` and runs git in the target directory runs that repo's `core.fsmonitor` and clean filters before the user approves the command. Only follow unconditional leading `cd`s, confine the result to the session repo or a repo nested inside it, pass `-c core.fsmonitor=false -c core.untrackedCache=false`, and prefer `ls-files` over `status` (it never refreshes the index, so no filter runs).
- 2026-09-30, #1266: a new substitution form (`<(`/`>(`) must expand at its parent's depth. Counting it as a nesting level pushed commands main already caught past `MAX_WRAPPER_DEPTH`, and three rounds of past-the-bound listing fixes chased that one root cause.
- 2026-09-30, probes: a shared cargo target directory used by several lanes gives false verdicts, because another lane's build replaces the binary between build and probe. Every lane and reviewer builds into its own `lt-<slug>` directory and deletes it afterwards. `CLAUDE_CODE_REMOTE=true` in a cloud container makes self-disabling hooks (`persist-plan-approval`, `session guard`) exit 0 silently, so probe them under `env -i`.
- 2026-09-30, platform: a `PreModelSwitch` `ask` refuses the switch whenever no human is attached, and the payload's `source` (`command`) doesn't show that. Gate an ask on the hook environment (`CLAUDE_CODE_ENTRYPOINT=cli` and `CLAUDE_CODE_SESSION_ATTENDED=1`) (#1273).
