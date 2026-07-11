# enforce-worktree: nudge on subprocess tree-mutations in a primary checkout — implementation plan

> Plan PR (draft). Ships as `docs/plans/2026-07-09-enforce-worktree-subprocess-mutations.md`. Per-issue references use `Refs cameronsjo/cadence-hooks#234` — this document intentionally does **not** auto-close the issue; the fix is a later, dedicated session. Implementer note: assume zero prior context — every file and line anchor below was verified against `origin/main` at v0.53.0+ (commit `f58eba7`) and will drift as the file changes, so re-confirm each anchor before editing. Task A is **Opus** (guard-feeding shell parser — security-sensitive) with a mandatory `cadence-forge:security-reviewer` (Opus) gate before merge; Task B is Sonnet. Planned 2026-07-09.

## Context

`enforce-worktree`'s `Bash` arm inspects only the **`git commit` boundary**. It walks a command, resolves each `git commit`'s effective target tree (honoring `cd`, `git -C`, and `sh -c '…'` wrappers), and blocks a commit that lands in the session's own primary checkout of a branch-mode repo. The `Write`/`Edit` arm blocks native file authoring into that same primary tree.

What it never inspects: **file mutations performed by a subprocess** — `uv add`/`uv sync`, `cargo add`, `pip`/`npm`/`pnpm`/`poetry`/`yarn install|add`, `sed -i <file>`, `tee <file>`, and `>>`/`>` redirects. These write tracked files in the primary checkout with no tripwire. The `git commit` arm is the persistence backstop, so tracked-tree state **accumulates silently** until the eventual `git commit` (or a native `Write`) finally trips the block — at which point unwinding the already-materialized changes is costly. This is a **documented, accepted miss** in the guard's own module doc (`crates/guardrails/src/enforce_worktree.rs:48-58`: *"file mutations via bash (`sed -i`, redirects) are not inspected — the `git commit` arm is the persistence backstop"*).

The disposition: **near-term, self-contained, single-guard nudge-tier addition.** It raises coverage of the subprocess-mutation class from silent-allow → advisory nudge. It is not a new block (see Approach / Out of scope for why blocking is rejected).

## Issues covered

| Issue | State | Disposition | One-line |
|---|---|---|---|
| #234 | open | **built here** (Task A) | `enforce-worktree` misses subprocess tree-mutations (`uv add`, `sed -i`, `>>`) in a primary checkout; tracked-tree state accumulates before the `git commit`/`Write` tripwire fires. |

## Relationship to #164

Independent — no sequencing dependency in either direction. #164 is a *path/state* consolidation (a shared `GitState` + path classifier the guard family consumes as thin policy). #234 is a *command-taxonomy* addition that rides the **existing** scoped `Bash` walk (`collect_commit_targets`' per-segment `effective_dir` recursion), not #164's classifier. No issue or plan text makes #234 depend on, block, or be blocked by #164; #234 consumes today's path/state helpers as-is. The fuller joint ruling lives in #164's plan doc (`docs/plans/2026-07-09-gitstate-path-classifier-164.md`).

**One coordination point (not a dependency):** both tracks co-edit `crates/guardrails/src/enforce_worktree.rs` — this track adds a predicate to `collect_commit_targets`, and #164's PR4 reworks the same guard onto `GitState`. Whichever lands second rebases the other's hunk; that is merge mechanics, not a logical dependency.

## Approach

Confirmed disposition (Decision Point D1): **Option A — nudge-only.** Rejected: a blocking tier (the arbitrary subprocess's target tree can't be resolved cheaply enough to gate on without an unacceptable false-block rate in an `ALLOW_MAIN`-by-design repo).

- **Add a second per-segment predicate to the same scoped walk `collect_commit_targets` already performs** (`crates/guardrails/src/enforce_worktree.rs:273`). Reuse its `effective_dir` cd-tracking (`:274`), its `split_segments_with_ops` segmentation (`:276`), and its `child_scripts` wrapper recursion (`:295`) — the #228-safe scoped view.
  - **MUST NOT** introduce or route through the flat `command_segments` primitive (`crates/core/src/shell.rs`). That flat view splices a child script's segments into the parent stream and loses per-segment `cd` scoping — it is the live #228 bypass class (still used by `guard_gh_write`/`guard_gh_dangerous`/`guard_op_vault_scan`, tracked separately). The commit arm was deliberately moved *off* it; the new predicate must not reintroduce it.
- **Nudge tier, not block.** Emit a `Nudge`, never an exit-2 `Block`. This raises coverage (silent-allow → nudge) and cannot weaken any existing block.
- **Primary-checkout-scoped.** Only nudge when the segment's effective cwd resolves into the session's *own* primary checkout — reuse the `Write`/`Edit` arm's `git_common_dir` equality scoping (`crates/guardrails/src/enforce_worktree.rs:600-604`; helper `git_common_dir` at `:454`) so a mutator run in a temp dir, a foreign repo, or a linked worktree does **not** fire.
- **Two mutator sub-classes (curated, coarse — no per-file tree prediction):**
  1. **Package-manager manifest/lock mutators** run in a primary checkout: `uv add|remove|sync`, `cargo add|rm`, `pip install`, `npm install|i|add`, `pnpm add|install`, `poetry add`, `yarn add`. No path resolution — *cwd-in-primary* is the sole trigger.
  2. **Direct file mutators with a resolvable target**: `sed -i <file>`, `tee <file>`, and `>>`/`>` redirect into a path. A redirect target is **not** a leading word — find it by scanning the segment for the redirect operator (an in-tree primitive exists: `shell::clobber_redirect_targets`, `crates/core/src/shell.rs:~515`, though note it deliberately excludes `>>` append, so append coverage means extending it or scoping v1 to `>` clobber — see D3). A verb target (`sed -i <file>`, `tee <file>`) sits in a **per-verb argument position**, not at `effective_dir`, so each enumerated verb needs its own target-argument extraction. Resolve the target relative to the segment's `effective_dir` and nudge only if it lands under the primary checkout.
- **Respect every existing carve-out** the guard family already honors: `.claude/` and `docs/plans/` paths, `CADENCE_ALLOW_MAIN`, the kill switch / `CADENCE_BYPASS`, temp-root, and the active-snooze dismissal. Match the once-per-session/snooze nudge ergonomics of the enforce-worktree family (a nudge should not fire on every keystroke of a busy session).

### Accepted misses (v1) — named, not silent

A curated allowlist has an open lower bound, and the scoped walk deliberately sees less than the shell runs. Every item below degrades to the **existing silent-allow**, never to a weakened block — this is a discipline nudge, not a security boundary — but each must be *named in the module doc's accepted-miss register* (`crates/guardrails/src/enforce_worktree.rs:48-58`) so the gap is documented, not implied:

- **Non-enumerated mutator verbs.** `cp`/`mv`/`install` into a tracked path, `dd of=…`, `truncate`, `patch`, `ed`/`ex`, `perl -i`, `awk -i inplace`, `python -c 'open(p,"w")'`, `cat > file`. The curated list is a **floor, not a fence**; widening it is follow-up, not a v1 blocker.
- **Variable- or substitution-pathed targets.** `OUT=/primary/f; cat > "$OUT"` (and `> "$(…)"`). The scoped walk carries **no assignment expansion** (that lives only on the flat `command_segments` view, which is the #228 bypass class this predicate MUST NOT use), so the target token stays unexpanded → resolves to no repo → fail-open miss. Accepted, precisely because widening to the flat view is rejected.
- **Prefix-flag wrappers.** `nice -n 10 <mutator>`, `env -i sh -c '<mutator>'` — the transparent-prefix stripper stops at a prefix whose next token is a flag (a flag could bind a value), so the mutator (or the wrapper body) is never reached. Inherits the commit arm's documented prefix-flag miss; the register's existing caveat must be **extended to the mutator predicate**, not just the commit/wrapper arm.
- **Nesting past the wrapper-depth budget.** `collect_commit_targets` recurses only while `depth < MAX_WRAPPER_DEPTH` (3); a mutator in a 4th `sh -c`/`$(…)` level is not reached. Inherits the walk's existing budget.
- **git-subcommand tree mutators without a `commit`.** `git apply`, `git restore`, `git rm`, `git mv`, `git stash pop` mutate tracked files but are not commit boundaries, and the flag-walk only matches the `commit` subcommand. (`git reset --hard` / destructive `git checkout` are already covered by the separate git-safety guard.) v1 **names** these, does not build them.

## Task breakdown

### Task A — command-taxonomy predicate + nudge wiring `[M]` · Opus

- **Scope:** implement the two mutator sub-classes on the scoped walk; emit a `Nudge` (not `Block`) carrying the accumulate-before-tripwire rationale and a dismiss/escape hint (`CADENCE_…`/snooze).
- **Files:** `crates/guardrails/src/enforce_worktree.rs` (the `collect_commit_targets` walk and the `Bash` arm at `:607`). Confirm whether `crates/core/src/shell.rs` needs any new primitive before adding one — the scoped walk already exposes `effective_dir`, `child_scripts`, and `resolve_cd_target`; prefer reuse.
- **Tests (property/unit, mirroring the existing `git_commit_targets` block ~`:800`):** hostile quoting; transparent-prefix wrappers (`env`, `nice` — note the guard already documents that a prefix's *own option flags* are unparsed, so `nice -n 10 …` is an accepted miss, not a target); `sh -c '…'`; `$(…)`; chained `cd && <mutator>`; redirect-into-tracked vs redirect-into-temp; child-`cd`-does-not-leak-to-parent. Include regression guards that must **stay silent** (a read-only variant, a mutator run in a temp dir, a `git commit` case that already blocks — no double-fire).
- **Mandatory `cadence-forge:security-reviewer` (Opus) before merge.** Frame the reviewer prompt as *"find a tree-mutator the shell actually runs that this detector never sees"* (a silent **miss**, not a false-block), **and cross-check the evasion classes against the Accepted-misses register above — any miss the reviewer finds that is NOT already named is a spec gap to close, not a shrug.** TDD + CI green is explicitly **not** sufficient — a prior adversarial review caught a Critical heredoc evasion that 96 core tests + full CI missed. The written "no new miss" finding is a **required verification artifact on the PR**. Because this adds a predicate that only *nudges* (no state mutation, no block), its false-positive tolerance is high — but the review still verifies the parser change never *narrows* what the commit arm already sees.

### Task B — docs + CHANGELOG bullet `[S]` · Sonnet

- Update the module doc comment (`crates/guardrails/src/enforce_worktree.rs:48-58`) to record that subprocess manifest/redirect mutations now **nudge** (they are no longer a silent miss).
- Stage the `[Unreleased]` CHANGELOG bullet **at implementation time** (NOT in this planning lane — see Out of scope).
- Registry/`hooks.json` unchanged (same `enforce-worktree` subcommand, new internal predicate) — confirm `registry_matches_clap_dispatch` stays green.

## Sequencing & dependencies

Single guard, single PR is viable; if split, Task A precedes Task B (docs describe shipped behavior). No cross-issue dependency. The mandatory security review gates Task A's merge.

## Verification (for the implementing session)

- `export PATH="$HOME/.cargo/bin:$PATH"` for anything that compiles.
- Run the `enforce_worktree` suite from a **carve-out-free path** — `.claude/worktrees/` and temp checkouts false-ALLOW the Scratch/E2E suite (the fixture-path prefix trips the guard's own temp/managed-dir carve-out). Use `git worktree add --detach ~/verify HEAD && cd ~/verify`.
- `cargo build --bin cadence-hooks` **before** any pipe probe — `cargo test` does not build the `[[bin]]`, so a probe right after a green test run returns a uniform exit 127 that misreads as ALLOW.
- Feed real attack payloads to the **bare** `cadence-hooks guardrails enforce-worktree` (which reads stdin and honors the payload `cwd`), **not** `cadence-hooks try` (which ignores stdin and overrides `cwd` with the process cwd). Clear `CADENCE_ALLOW_MAIN` explicitly (`env -u CADENCE_ALLOW_MAIN …`) — the implementer's shell environment can ambiently carry it and silently exempt every verification.
- Probe both sub-classes: `uv add serde` with `cwd` = primary checkout → **nudge**; the same in a temp dir / linked worktree → **silent**; `sed -i s/a/b/ src/foo.rs` in-primary → nudge; `echo x >> /tmp/scratch` → silent.
- `cargo fmt --all` then `make ci` green before commit. Treat the first CI run as the real clippy verdict (local clippy may trail CI's).
- **The security-review "no new miss" artifact must be recorded on the PR before merge.**

## Decision points (Cameron's calls)

- **D1 — mutator taxonomy for v1.** Which package managers / binaries ship in the first cut. Recommendation: the coarse list above; expand later. *(Disposition assumed confirmed as nudge-only per the merged worktree-guard plan; reopen if you want a blocking tier.)*
- **D2 — nudge ergonomics.** Does the new nudge share the enforce-worktree snooze/dismiss key, or get its own dismiss key so a user can silence subprocess-mutation nudges without silencing commit-boundary blocks?
- **D3 — redirect scope in v1.** The in-tree `clobber_redirect_targets` primitive covers `>` clobber but excludes `>>` append. Ship v1 as `>` clobber only (append named as an accepted miss / follow-up), or extend the primitive to cover `>>` now? Recommendation: `>` clobber in v1, append as a fast follow — the append case is rarer and extending a guard-feeding shell primitive is itself a security-reviewable change.

## Out of scope

- **A blocking tier** — explicitly rejected (un-gateable target tree; false-block cost in an `ALLOW_MAIN`-by-design repo).
- **Non-primary checkouts** — a mutator in a temp dir, foreign repo, or linked worktree does not fire.
- **The #164 path/state classifier** — independent axis; this predicate consumes today's helpers as-is.
- **Routing any guard onto/off the flat `command_segments` primitive** — the #228-class fix for `guard_gh_write` et al. is separate.
- **Release/version bump** — no `make bump`; the CHANGELOG bullet stages under `[Unreleased]` at implementation time per the repo's release discipline.
