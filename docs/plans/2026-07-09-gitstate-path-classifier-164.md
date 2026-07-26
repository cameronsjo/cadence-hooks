# Unified path/state classification for the git/branch guard family (#164) — implementation plan

> Plan PR (draft). Ships as `docs/plans/2026-07-09-gitstate-path-classifier-164.md`. Per-issue references use `Refs cameronsjo/cadence-hooks#164` — this document intentionally does **not** auto-close the issue; this is an umbrella for a dedicated multi-PR session, not a single fix. Implementer note: assume zero prior context — every file and line anchor below was verified against `origin/main` at v0.53.0+ (commit `f58eba7`) and will drift as the files change, so re-confirm each anchor before editing. Most PRs are **Opus** (guard-feeding logic); PR5 is Sonnet. Planned 2026-07-09.

## Context

Seven-plus false-positive incidents in the git/branch guard family were each patched with a one-off carve-out, and several fixes were followed by a sibling misfire. The root gap: there is **no single, tested notion of "what kind of path / repo / branch / operation is this?"** Repo-root resolution, branch/HEAD resolution, worktree-vs-primary-vs-temp detection, path-class membership (temp, `.claude/`-managed, git-root, home-child, vault, `docs/plans/`, memory, source), and the lexical `..`-normalization every carve-out depends on are each **re-derived and inconsistently applied** across `enforce_worktree`, `warn_main_branch`, `warn_subagent_worktree`, `guard_rm`, and the branch-resolver inlines.

The most recent prior art proves the shape works: `guard_rm.rs` already ships a `classify_path` → `TargetClass` map (`crates/guardrails/src/guard_rm.rs:85` enum, `:415` classifier) with **load-bearing ALLOW-before-BLOCK ordering** — temp / `.claude`-managed resolve to `Allow` *before* the git-root / home-child / vault rules can escalate to `Block`. That is the prototype this umbrella generalizes.

**Disposition: umbrella / incremental refactor for a dedicated session — multi-PR, additive-first.** #164's own body frames the misfire history as *"the seed corpus for regression cases"*; the classifier is additive (nothing consumes it at first), so PR1 cannot regress any guard.

## Issues covered

| Issue | State | Disposition | One-line |
|---|---|---|---|
| #151 | closed | seed corpus (retire, do not migrate) | `check-idle-return` cost/value — resolved to **retire** the guard; do not pipe-clean a guard slated for deletion. |
| #152 | closed | seed corpus | `warn-main-branch` carve-outs matched path components without canonicalizing `..` — the lexical-normalization gap. |
| #155 | closed | seed corpus / candidate consumer | nudge when a session works on an unrelated feature branch (resolved "build"). |
| #158 | closed | seed corpus (out-of-scope axis) | `guard-gh-write` loop-branch blocked `gh` reads it should allow — the read-vs-write axis, deferred here. |
| #33 | closed | seed corpus | `warn-main-branch` should skip when CWD is under `.claude/worktrees/`. |
| #35 | closed | seed corpus | branch-warn fired on writes to the memory directory. |
| guard-rm `TargetClass` | shipped 0.53.0 | prior-art prototype | `classify_path`/`TargetClass` (GitRepo/HomeChild/Vault, ALLOW-before-BLOCK) — the first real classifier; PR1 generalizes it and makes guard-rm its first consumer. |

## Relationship to #234

Independent — no sequencing dependency in either direction. #234 is a *command-taxonomy* addition on the existing scoped `Bash` walk (`collect_commit_targets`), **not** a consumer of this path/state classifier; it depends on today's helpers as-is. This doc carries the full joint ruling (below); #234's plan (`docs/plans/2026-07-09-enforce-worktree-subprocess-mutations.md`) carries the short form.

**One coordination point (not a dependency):** both tracks co-edit `crates/guardrails/src/enforce_worktree.rs` — #234 adds a predicate to `collect_commit_targets`, and this umbrella's PR4 reworks the same guard onto `GitState`. Whichever lands second rebases the other's hunk; it does not change the ruling that neither *blocks* the other.

## The joint ruling (#164 ⟷ #234): two independent tracks, no sequencing dependency

**Decision: two coordinated plan docs / two draft PRs, not one cluster plan.** Evidence, converging from the issues and the code:

1. **Already ruled upstream.** The merged worktree-guard plan (`docs/plans/2026-07-06-worktree-guard-correctness.md`) states verbatim that *"#234 and #164 are not in the execution sequence,"* lists #234 as options-only / recommended follow-up, and #164 as umbrella-tracked (direction, not built there).
2. **Different layers, confirmed in code.** #234 rides `enforce_worktree.rs`'s **existing** commit-boundary classifier — `collect_commit_targets` (`:273`), which already walks segments with per-segment `effective_dir` (the #228-safe recursion). #234 adds a command-taxonomy predicate to that same walk. #164 is a *path/state* consolidation (`GitState` + a path classifier) on a different axis. `enforce-worktree` *consumes* path/state helpers, but #234's new work does not depend on #164's.
3. **The dependency arrow, where one exists, runs the other way.** No issue or plan text makes #234 depend on, block, or be blocked by #164. #164 is additive — nothing consumes it at first, so it cannot regress a guard — and its seed corpus is fed **by** the incident issues and guard-rm's `TargetClass`.
4. **Different execution models.** #234 is a single M-sized nudge-tier addition to one guard. #164 is a multi-PR incremental umbrella for a dedicated session. Bundling two unrelated execution timelines into one doc serves neither.

## Approach

Two pure modules the family consumes as **thin policy**; the capstone *composes existing primitives* — explicitly **not** a big-bang rewrite.

- **`core::gitstate::GitState`** — `resolve(start: &Path) -> Option<GitState>` exposing **facts, not policy**: `repo_root`, `git_common_dir`, `branch: Option<String>`, `worktree_kind` (primary / linked), default branch. Built on the existing `core::paths::find_git_root` (`crates/core/src/paths.rs:86`) and `resolve_git_common_dir` (`:160`), plus `core::worktree`'s primary/linked detection. **Never expose an `is_main: bool` or any policy verdict** — each guard keeps its own policy *and* its own fail-direction, so the shared classifier cannot drift one guard's decision into another's (critically, cannot loosen `enforce_worktree`'s BLOCK direction).
- **`core::pathclass`** — generalize guard-rm's `classify_path`/`TargetClass` (`crates/guardrails/src/guard_rm.rs:85`/`:415`) into a shared `path → class` map (temp, `.claude`-managed, git-root, home-child, vault, `docs/plans/`, memory, source). **Preserve the ALLOW-before-BLOCK ordering — it is load-bearing** (an allow-class must resolve before an escalating block-class can match). Fold in `#152`'s lexical `..` normalization — the guard family already carries two implementations (`core::normalize_path` + `drop_dot_segments` in guard-rm at `crates/core/src/lib.rs:145`; `core::worktree::normalized_components` at `crates/core/src/worktree.rs:79`) — so that **no carve-out ever matches an uncanonicalized path**.
- Guards become **thin policy over the classifier**; every carve-out lives exactly once. Consolidation targets already visible in the code: env-truthiness checks (multiple identical copies), the `git_common_dir` resolution, the `rev-parse --show-toplevel` / `find_git_root` re-derivations, the divergent "path-under-root" tests, and the snooze-state resolvers.

## Task breakdown (the incremental PR sequence — each individually reviewable)

### PR1 — `gitstate.rs` + `pathclass` + characterization tests `[M]` · Opus

Additive, **zero consumers**. Add `crates/core/src/gitstate.rs` (`GitState` + pure `resolve()`) and the `pathclass` map. Refactor `guard_rm` to consume `pathclass` as the **first real consumer** — this proves the generalization against a live guard without behavior change. Seed-corpus regression suite drawn from the incident history (#151/#152/#155/#158/#33/#35). **Characterization discipline: byte-identical verdicts pre/post** — PR1 changes structure, never a decision.

> **Blocked on D5.** PR1's exact v1 class set depends on Decision D5. If D5 is unanswered at execution, default to the classes with a live consumer already (temp, `.claude`-managed, git-root, home-child, `docs/plans/`, source) and **defer `memory`/`vault`** to a later PR — `guard_rm` is the only current `Vault`/`HomeChild` consumer, so those classes can land with their second consumer rather than speculatively in PR1.

### PR2 — migrate the first live guard `[M]` · Opus

**Correction to the earlier spike:** the spike named `check_idle_return` as the pipe-cleaner, but **#151 resolved to *retire* that guard** — do **not** migrate a guard slated for deletion. Pipe-clean on `warn_subagent_worktree` or `warn_main_branch` instead (Decision D3). Characterization tests first; verdicts unchanged.

**PR2 ⟂ PR3 ownership:** if D3 picks `warn_main_branch` as the PR2 pipe-cleaner, it leaves PR3's scope — PR3 then covers only the *remaining* nudge guards, never re-migrating `warn_main_branch`. One guard is owned by exactly one PR; resolve D3 before splitting PR2/PR3 work.

### PR3 — `warn_main_branch` / remaining nudge guards `[M]` · Opus

Collapse the `.claude/` + `docs/plans/` carve-out and the `CADENCE_ALLOW_MAIN` asymmetry onto the shared resolution. Nudge-tier throughout — false-positive tolerance is high, but keep verdicts characterization-locked.

### PR4 — `enforce_worktree` (the only BLOCK guard) `[M]` · Opus — **highest risk**

Drop the cross-guard borrow (the `pub(crate)` primary-checkout / worktree-count helpers other guards reach into) and route through `GitState`. **Pin BOTH fail directions independently** — the shared classifier returns facts; `enforce_worktree` keeps its own BLOCK policy and `warn_*` keep their NUDGE policy, so neither can drift the other. **Mandatory `cadence-forge:security-reviewer` (Opus) before merge**, with a written **"no new miss" artifact** on the PR. Re-run the adversarial review *specifically on this transition*: a shared classifier feeding a BLOCK guard is exactly the NUDGE→state/BLOCK inversion the repo's own gotcha warns about — a once-benign nudge false-positive becomes a silent guard-bypass when the same predicate starts gating a block. ASK/BLOCK-default posture is preserved anywhere behavior loosens.

### PR5 — collapse branch resolvers onto `GitState.branch` `[S]` · Sonnet

Retire the duplicate branch-resolution inlines (`git branch --show-current` vs `symbolic-ref --short HEAD`) in favor of `GitState.branch`. Lowest severity; nudge/marker-tier consumers only.

## Sequencing & dependencies

PR1 first (additive, zero consumers). PR2–PR5 each depend **only** on PR1 and land individually — no strict ordering among them beyond PR4's elevated review bar. Every PR that touches guard-feeding parser logic or a guard's fail-direction (PR4 above all) carries the mandatory `cadence-forge:security-reviewer` (Opus) gate with the "no new miss" artifact. TDD + CI green is explicitly not enough for those PRs.

## Verification (for the implementing session)

- `export PATH="$HOME/.cargo/bin:$PATH"` for anything that compiles.
- **PR1 has zero behavior change** — the characterization tests must produce **byte-identical verdicts pre/post** for every seed-corpus input. Any verdict diff in PR1 is a bug, not an improvement.
- Later PRs: run the full guard test suites from a **carve-out-free path** (`git worktree add --detach ~/verify HEAD && cd ~/verify`) — `.claude/worktrees/` and temp checkouts false-ALLOW the enforce-worktree Scratch/E2E suite. `cargo build --bin cadence-hooks` before any pipe probe (`cargo test` does not build the `[[bin]]`). Clear `CADENCE_ALLOW_MAIN` explicitly (`env -u CADENCE_ALLOW_MAIN …`).
- `cargo fmt --all` then `make ci` green before each commit; treat the first CI run as the real clippy verdict.
- **The security-review "no new miss" artifact is a required PR verification artifact on PR4 (and any other parser/fail-direction-touching PR).**

## Decision points (Cameron's calls)

- **D3 — pipe-cleaner guard.** Given #151 retires `check_idle_return`, which guard is PR2's pipe-cleaner — `warn_subagent_worktree` or `warn_main_branch`?
- **D4 — #155 placement.** Does the unrelated-branch nudge (#155, resolved "build") ship as a `GitState` *consumer* inside this umbrella, or stay a separate feature PR?
- **D5 — `pathclass` v1 scope.** Which classes land in PR1 vs later — specifically whether `memory` and `vault` are in the first cut or deferred.

## Out of scope

- **The gh operation-kind (read-vs-write) classifier** — the explicitly-deferred third axis (ties to #158; `guard_gh_write` is still on the flat `command_segments` view — a separate #228-class fix). Not built here.
- **#234** — independent command-taxonomy addition (see the joint ruling).
- **Any big-bang rewrite** — the capstone composes existing primitives; it does not rewrite the guards wholesale.
- **Release/version bump** — no `make bump`; CHANGELOG bullets stage under `[Unreleased]` at implementation time per the repo's release discipline.
