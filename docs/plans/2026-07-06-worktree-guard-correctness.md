# Worktree-guard correctness & evasions — implementation plan

> Plan PR (draft). Per-issue references use `Refs cameronsjo/cadence-hooks#N` — this document intentionally does **not** auto-close any implementation issue. Implementer: Sonnet drives Tasks A and C; **Task B must be Opus** (guard-feeding shell parser — security-sensitive) with a mandatory `cadence-forge:security-reviewer` (Opus) gate before merge. Dispatch each task as its own scoped session/PR; do them in the sequence below, not in parallel. Planned 2026-07-06.

## Context — why this cluster, evidence

All five actionable issues live in one function-and-a-half of shell-parsing code that decides *what a `Bash` command will actually do to a primary checkout*:

- `git_commit_targets` in `crates/guardrails/src/enforce_worktree.rs` (fn at line **190**, sole non-test caller at line **433**), and
- `parse_work_dir` in `crates/core/src/shell.rs` (fn at line **184**), the nudge-tier sibling.

Two verified inconsistencies drive the bugs:

1. **`git_commit_targets` tokenizes twice, two different ways.** Line **195** uses quote-aware `tokenize(&segment)` for the `cd` test, but line **225** re-tokenizes the *same segment* with `segment.split_whitespace()` for the `git`/`-C` walk. Quotes therefore defeat the git-word and `-C` detection (#230), and the loop iterates `split_segments_with_ops` (line 194) which never expands `sh -c '…'` wrappers (#228). A quote-aware, wrapper-expanding view already exists and is unused here: `command_segments` (`crates/core/src/shell.rs:493`) expands `sh`/`bash`/`zsh`/`dash -c`, `$(…)`, backticks, and visible assignments.
2. **`parse_work_dir` still carries the "`cd` before `||` is a no-op" heuristic** (`crates/core/src/shell.rs:194-196`) that `git_commit_targets` already abandoned in the #226 work (see its line 197 comment, "Always assume the cd succeeds"). #229 asks the two to agree.

Separately, the `is_absolute()` decision at `enforce_worktree.rs:256` treats POSIX shell literals (`/some/worktree`) as *relative* on Windows (no drive letter), which is why 9 `enforce_worktree` tests are red on `Check (windows-latest)` and `main` has been red since #226 (#235). CI matrix: `.github/workflows/ci.yml`, jobs `Check (ubuntu-latest)` / `Check (windows-latest)`, `fail-fast: false`, test step at line 39; Windows is non-required, so ubuntu-green PRs keep merging over it.

**Verified constraints an implementer must respect (from `cadence-hooks/CLAUDE.md`):**

- `enforce_worktree` Scratch/E2E tests **false-ALLOW everything** when the checkout sits under `.claude/worktrees/` or `/tmp` (the fixture-path prefix trips the guard's own temp/managed-dir carve-out). **Run the suite from a carve-out-free path:** `git worktree add --detach ~/verify <sha>`.
- `cargo test` does **not** build the `[[bin]]`; a pipe-probe of `target/debug/cadence-hooks` right after a green test run returns a uniform exit 127 that misreads as ALLOW. `cargo build --bin cadence-hooks` before any binary probe.
- Guards fail **open** (ADR-0001): parse failures exit 0/1, never 2. Every change here must preserve fail-open — but note the project's own rule: "sees less of an executed command" is a **miss**, not a licensed fail-open. Task B *widens* what the guard sees; it must not narrow it for any existing input.
- cargo is at `~/.cargo/bin` — `export PATH="$HOME/.cargo/bin:$PATH"` in every shell invocation, including the commit (the pre-commit hook runs `cargo fmt` and aborts without cargo on PATH).

**Open-PR overlap check (as of 2026-07-06):** the only open PR is #127 (`chore/relicense-commons-clause`) — licensing metadata only, **no overlap** with `enforce_worktree.rs` or `core/shell.rs`. No merge conflicts anticipated.

## Issues covered

| Issue | Disposition | One-line |
|---|---|---|
| #235 | **fixed here** (Task A, first) | Windows CI red: POSIX literals fail `is_absolute()`; unix-shaped fixtures push backslash paths through an escape-unaware tokenizer. |
| #228 | **fixed here** (Task B) | Shell-wrapper (`sh -c '… git commit'`) and quoted-command-word (`"git" commit`) evasions bypass commit-target detection. |
| #230 | **fixed here** (Task B, same patch) | Quoted `-C "…"` argument evades the `split_whitespace` git/flag walk. |
| #229 | **fixed here** (Task C, adjacent) | `parse_work_dir`'s `cd`-before-`||` no-op heuristic is wrong on cd-success; align with #226's "assume cd succeeds". |
| #234 | **options-only** (see Decision Points; recommended follow-up, not this batch) | `enforce-worktree` misses subprocess tree-mutations (`uv add`, `sed -i`, `>>`) in a primary checkout. |
| #164 | **umbrella-tracked** (direction, not built here) | Unified path/state classifier (`core::gitstate::GitState`) the guard family builds toward incrementally. |

## Approach

Recommended path: **land three small, independently-reviewable PRs in strict order — A (green CI) → B (tokenizer unification, #228+#230 as one patch) → C (parse_work_dir alignment)** — and treat #234 as an options decision (deferred follow-up) and #164 as the direction, per the #164 spike comment already on the issue. Only #235 and #234 carry genuine design choices, captured in options tables (below and in Decision Points). Everything else is a determined fix.

### #235 — recommended: POSIX-aware absolute test + `#[cfg(unix)]`-gate the backslash-fixture tests (with a native-Windows fixture added)

The 9 failures split cleanly into the issue's two facets:

- **Facet 1 — pure-string `is_absolute()` (4 tests: `dash_c_commit_targets_redirect`, `dash_c_still_overrides_cd`, `inline_config_commit_targets_cwd`, `multiple_commits_all_reported`).** Fix in code: these are *shell* paths, not OS paths — a leading `/` is absolute on every platform git will receive it on. This is a real correctness improvement (and makes the 4 tests pass on Windows, not just skip).
- **Facet 2 — real backslash Windows paths through `tokenize` (5 tests: `cd_into_other_primary_blocks_and_names_target_repo`, `dismiss_repo_flag_snoozes_target_not_cwd`, `cross_repo_block_message_names_target_repos_settings_path`, `cross_repo_commit_reads_target_repos_own_settings`, `cd_before_or_true_still_blocks_other_primary`).** These Scratch-fixture tests construct `git -C C:\…\repo commit`; `tokenize` is documented (shell.rs:46) as escape-unaware, so backslashes mangle before target resolution.

| #235 option | Fixes | Cost / risk | Recommendation |
|---|---|---|---|
| **(chosen)** POSIX-aware absolute helper for facet 1 + `#[cfg(unix)]`-gate the 5 facet-2 fixture tests + add one `#[cfg(windows)]` native-drive-path fixture test | Both facets; CI honestly green | Low; no change to the shell tokenizer | **Recommended** — smallest change that turns Windows green and keeps the fix trustworthy for B/C to build on |
| Teach `tokenize`/`strip_quotes` to preserve backslash runs in path position (ungate facet-2 tests on Windows) | Both facets natively | **Guard-feeding parser change → needs its own adversarial security review**; risks re-introducing escape ambiguity | Defer — do not bundle into a CI-unblock PR; revisit only if native-Windows product coverage is later required |

Rationale for choosing gate-not-tokenizer: #235's own scope note concludes shipped behavior is likely fine (WSL uses POSIX paths → facet 1 moot; native Windows paths are drive-lettered → `is_absolute()` already true). The failures are concentrated in unix-shaped *fixtures*. `#[cfg(unix)]` makes CI state that fact honestly; the added native-drive fixture proves the drive-lettered path *does* resolve, closing the coverage the gate would otherwise remove.

## Task breakdown

### Task A — #235: turn `Check (windows-latest)` green (do FIRST)

- **Scope:** POSIX-aware absolute test in `git_commit_targets`; cfg-gate the 5 backslash-fixture tests; add one native-Windows-drive fixture test. No behavior change on unix.
- **Files:** `crates/guardrails/src/enforce_worktree.rs` only.
- **Exact edits:**
  1. At line **256**, replace the `is_absolute()` branch. Add a small helper near `git_commit_targets`:
     ```rust
     /// A shell path is absolute if git will treat it as absolute: a leading `/`
     /// (POSIX / WSL / Git-Bash shell paths — `Path::is_absolute` is false for these
     /// on Windows) OR a platform-absolute path (native `C:\…`). These are shell
     /// paths, not OS paths, so decide on the string, not just the OS.
     fn is_shell_absolute(path: &str) -> bool {
         path.starts_with('/') || std::path::Path::new(path).is_absolute()
     }
     ```
     and change the match arm to `Some(path) if is_shell_absolute(path) => path.to_string(),`.
  2. Annotate the 5 facet-2 fixture tests (`cd_into_other_primary_blocks_and_names_target_repo` @1093, `cd_before_or_true_still_blocks_other_primary` @1130, `dismiss_repo_flag_snoozes_target_not_cwd` @1235, `cross_repo_commit_reads_target_repos_own_settings` @1316, `cross_repo_block_message_names_target_repos_settings_path` @1560) with `#[cfg(unix)]` above their existing `#[test]`. Add a one-line comment on each: `// unix-shaped fixture: builds POSIX command strings through an escape-unaware tokenizer; native-Windows path coverage is <new test name>`.
- **Test fixtures to add:** one `#[cfg(windows)]` test `native_windows_drive_path_commit_targets_redirect` asserting `git_commit_targets(r"git -C C:\repo\wt commit -m x", r"C:\cwd")` yields the drive-lettered target unchanged (proves `is_shell_absolute` returns true for `C:\…` via the `Path::is_absolute` arm).
- **Size:** S.
- **Suggested model:** Sonnet.

### Task B — #228 + #230: unified quote-aware, wrapper-expanding tokenization (ONE patch)

- **Scope:** Route `git_commit_targets`'s segment iteration and its git/`-C` walk through the already-existing quote-aware, wrapper-expanding primitives, so `sh -c '…'`, `"git"`, and quoted `-C "…"` are all seen. Single fix subsumes both issues.
- **Files:** `crates/guardrails/src/enforce_worktree.rs` (import line **58**; fn body **190-264**). No `core/shell.rs` change expected — `command_segments` and `tokenize` already provide what's needed; confirm before adding anything there.
- **Exact edits:**
  1. Import: change line 58 to pull in `command_segments` (drop `split_segments_with_ops` if it becomes unused): `use cadence_hooks_core::shell::{command_segments, resolve_cd_target, tokenize};`
  2. Line **194**: iterate `for segment in command_segments(command)` instead of `split_segments_with_ops(command)` (the `_next_op` is already unused). This surfaces `sh -c '…'` inner segments **plus** the literal wrapper segment; the wrapper segment's first token (`sh`) matches neither `cd` nor `git`, so it is harmlessly skipped — closes #228's wrapper facet.
  3. Line **225**: delete `let ws_tokens: Vec<&str> = segment.split_whitespace().collect();` and reuse the quote-aware `tokens` already computed at line 195 for the git-word test and the `-C`/`-c`/global-flag walk (lines 226-254). This closes #228's `"git"` quoted-word facet **and** #230's quoted-`-C` facet in one move. Adjust `redirect: Option<&str>` to own `String`/`&str` from the `tokens: Vec<String>` (borrow-lifetime: `tokens` outlives the walk, so `redirect: Option<&str>` referencing `tokens[idx]` is fine).
- **Test fixtures to add** (as unit cases in the `git_commit_targets (pure parsing)` block, ~line 580, mirroring existing style — each is a repro from the issues):
  - #228 wrapper: `sh -c 'cd /primary && git commit -m x'`, `bash -c "git commit -m x"`, `zsh -c 'git commit -m x'`, `env git commit -m x` → target `/primary` (or cwd) present (currently empty).
  - #228 quoted word: `"git" commit -m x` → cwd target present.
  - #230 quoted `-C`: `git -C "/some path with spaces" commit -m x` → target `/some path with spaces` (currently mis-parsed/empty).
  - Regression guards (must stay empty): `echo git commit -m x` (already @641), a heredoc body quoting `git commit`, and `sh -c 'echo not a commit'`.
- **Size:** M.
- **Suggested model:** **Opus.** Guard-feeding shell parser: per `cadence-hooks/CLAUDE.md`, new shell-parsing logic that feeds the guards gets an **adversarial `cadence-forge:security-reviewer` (Opus) review before merge — TDD + CI green is not enough** (a prior review caught a Critical heredoc evasion 96 tests + CI missed). Frame the reviewer prompt as: *find inputs where a `git commit` the shell executes slips past `git_commit_targets` unseen after this change.* Verify the change only ever **widens** the seen-command set (no input that previously produced a target now produces none).

### Task C — #229: align `parse_work_dir` with "assume cd succeeds" (adjacent, same area pass)

- **Scope:** Remove the `cd`-before-`||` no-op heuristic so `parse_work_dir` matches `git_commit_targets`' resolved model. Behavior change to nudge-tier consumers only.
- **Files:** `crates/core/src/shell.rs` (fn **184-210**; tests to update below).
- **Exact edits:**
  1. Delete the `||` short-circuit at lines **194-196** (the `if after.starts_with("||") { continue; }` block and its `after` binding at 189 if it becomes unused). Every `cd` the `CD_PATTERN` iterator finds now redirects `effective`, mirroring `git_commit_targets` (whose line-197 comment is the canonical rationale; cite it in a new doc line at the definition).
  2. Add a one-line doc note at the fn: ``// Assumes every `cd` succeeds (aligns with git_commit_targets, issue #229 / PR #226); `||`/`&&` are equal-precedence left-assoc, so a succeeding `cd` before `||` still changes the dir for what follows.``
- **Test fixtures to update** (these encode the *old* wrong assumption — new expected values follow "apply every cd left-to-right, assume success"):
  - `cd_or_then_and_cd` (shell.rs:**1458**) — update expected to the assume-success result.
  - `or_operator_no_change`-style case `parse_work_dir("cd /project || git push", "/home")` (line **1279**) — change expected from `/home` to `/project`.
  - `cd /fail || cd /recover && git push` (line **1462**) — expected becomes the last applied `cd` under the "apply all" model (`/recover`); mirror `git_commit_targets`' analogous tests at lines 715-737 for the exact shape.
  - Derive each new expected by mirroring `git_commit_targets`' `cd x || exit; git commit` test (enforce_worktree.rs:723) — do **not** hand-guess; run the updated fn and confirm against that reference model.
- **Size:** S.
- **Suggested model:** Sonnet. (Touches a fn consumed by nudge/marker-tier code — `guard_push_remote`, `nudge_upgrade_after_push`, `guard_gh_write`, `warn_issue_tracker` in `crates/guardrails`, plus `crates/cadence/src/git_safety.rs`, `crates/core/src/markers.rs`, and `crates/core/src/loop_analysis.rs`. No block guard consumes `parse_work_dir` functionally — `enforce_worktree.rs` mentions it in comments only — so a wrong-nudge is the worst case, not a bypassed block.)

## Sequencing & dependencies

1. **Task A (#235) first, its own PR, merged before B/C.** Rationale: `main`'s `Check (windows-latest)` is red; until it's green an implementer cannot tell whether B or C *broke* Windows or merely inherited the existing red. A is self-contained (no dependency on B's rewrite) precisely so it can land first. It also introduces `is_shell_absolute`, which B reuses.
2. **Task B (#228+#230) second, on green `main`.** Own PR + Opus security review gate. Depends on A only for a trustworthy CI signal (and reuses `is_shell_absolute`).
3. **Task C (#229) third (or bundled after B in the same area pass, separate commit/PR for reviewability).** Independent file (`core/shell.rs`) from B (`enforce_worktree.rs`), so no code conflict; sequenced after B to keep one reviewable change in flight at a time and because it's the lowest-severity (nudge-tier).

`#234` and `#164` are not in the execution sequence — see Decision Points and Out of Scope.

## Verification

Prefix every command with `export PATH="$HOME/.cargo/bin:$PATH"`. Run the `enforce_worktree` suite from a **carve-out-free path**, not the primary checkout or a `.claude/worktrees/`/`/tmp` dir:

```
git worktree add --detach ~/verify HEAD && cd ~/verify
```

- **Task A:**
  - Local (unix): `cargo test -p cadence-hooks-guardrails enforce_worktree` — all green; the 4 facet-1 tests pass unchanged; the 5 gated tests still run on unix.
  - **Authoritative Windows evidence (a macOS implementer cannot prove this locally):** push the PR and read the GitHub Actions check — `gh pr checks <n> -R cameronsjo/cadence-hooks` must show **`Check (windows-latest)` = pass**. This green check *is* the #235 acceptance criterion; local unix green is necessary but not sufficient.
- **Task B:**
  - `cargo test -p cadence-hooks-guardrails enforce_worktree` — new wrapper/quoted-word/quoted-`-C` cases green; all pre-existing `git_commit_targets` and Scratch tests still green (no regression).
  - Binary smoke (build the bin first): `cargo build --bin cadence-hooks`, then feed a crafted payload to the **bare** subcommand (not `try`, which ignores stdin and overrides cwd): pipe a `Bash` payload with `command: "sh -c 'cd <primary> && git commit -m x'"` and `cwd: <primary checkout>` to `cadence-hooks guardrails enforce-worktree`; expect **exit 2 (block)** where pre-fix it was exit 0. Repeat for `"git" commit -m x` and `git -C "/other primary" commit -m x`.
  - **Adversarial review artifact:** a `cadence-forge:security-reviewer` (Opus) pass with a written finding of "no new miss" (or fixes applied) recorded on the PR before merge.
- **Task C:** `cargo test -p cadence-hooks-core parse_work_dir` (and `cargo test -p cadence-hooks-core shell`) — updated `cd_or_then_and_cd`, the `|| git push`, and `cd /fail || cd /recover` cases green under the new expected values; the consuming crates still build (`cargo build`).
- **All tasks, before each commit:** `cargo fmt --all` then `make ci` (fmt-check + clippy `-D warnings` + tests) green. Note: local `make ci` green does not guarantee CI green if the local clippy trails CI's — treat the first CI run as the real clippy verdict.

## Decision points

1. **#234 — build a coarse tree-mutator guard now, or defer?** (Genuinely undecided; recommend **defer to a dedicated follow-up**, not this batch.)

   | #234 option | Behavior | Trade-off |
   |---|---|---|
   | **(A, recommended for the follow-up)** Nudge (not block) on a curated tree-mutator list (`uv add/remove/sync`, `npm/pnpm/pip install`, `sed -i`, `>>`/`>` into a tracked path) when in a primary checkout | Warns, doesn't block | Closes the recurring cases with no shell-effect prediction; a nudge false-positive is cheap. Size M. |
   | **(B)** Block on the same list | Exit 2 | Higher false-positive cost — many of those commands are legitimate in an `ALLOW_MAIN`-by-design repo or as read-only variants; inverts the fail tolerance the issue warns about. |
   | **(C)** Do nothing this batch | — | The issue itself frames this as a "coverage seam to flag, not a fix to prescribe"; correctness/CI fixes (A/B/C above) are the priority. |

   **Recommendation:** ship A/B/C (the parser correctness batch) first; open #234 as a follow-up implementing **Option A (nudge-only)**, sized M, gated behind the same Bash classifier that already recognizes the commit boundary. Reason to keep it out of this batch: it's additive *policy* over a new command taxonomy, not a fix to the existing tokenizer, and it wants its own design + false-positive tuning. **Question for Cameron: confirm #234 is a deferred nudge-only follow-up (Option A), or do you want it in scope now?**

2. **#235 facet-2 — cfg-gate the backslash-fixture tests, or fix the tokenizer to preserve backslashes?** Recommendation: **gate** (see #235 options table). A tokenizer change is a separate guard-feeding-parser review and shouldn't ride a CI-unblock PR. **Question for Cameron: accept `#[cfg(unix)]`-gating for the unix-shaped fixtures (with the added native-drive test), deferring native-Windows tokenizer coverage?**

## Out of scope

- **The `core::gitstate::GitState` refactor (#164).** This batch consolidates *command tokenization* (routing `git_commit_targets` through the existing `command_segments`/`tokenize`) — it does **not** build the shared path/repo/branch/operation classifier. **What remains of #164 after this batch** (per the incremental plan in the #164 spike comment already on the issue): add `crates/core/src/gitstate.rs` (`GitState` + pure `resolve()` over the existing `core::paths::find_git_root`/`resolve_git_common_dir`); migrate `check_idle_return` as the pipe-cleaner (characterization tests first); then `warn_subagent_worktree`, then `enforce_worktree` (dropping the cross-guard `pub(crate)` `is_primary_checkout`/`count_worktrees` borrow — a smell noted in the comment); then collapse the branch resolvers (`git branch --show-current` vs `symbolic-ref --short HEAD`) onto `GitState.branch`. Those are individually-reviewable follow-up PRs in a dedicated session, **not** a big-bang refactor here.
- **Changing `tokenize`/`strip_quotes` escape handling** (backslash-in-path). Explicitly deferred (Decision Point 2) — a guard-feeding parser change requiring its own adversarial review.
- **#234 tree-mutation coverage** — deferred follow-up (Decision Point 1).
- **The gh-command / operation-kind classifier axis** — the #164 comment calls this a separate axis (already centralized in `core::shell`); untouched here.
- **Release/version bump** — no `make bump` in this batch; each PR stages its CHANGELOG bullet under `[Unreleased]` per the repo's release discipline.
