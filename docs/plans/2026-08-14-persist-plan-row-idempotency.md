---
status: in-progress
next: PR cadence-hooks#693 review + merge (Cameron), then post-merge re-pin verify on sjomba
branch: plan/690-persist-plan-row-idempotency
approved_in: 7afe614c-d777-40a3-a059-91ba088c0026
approved_session_id: 7afe614c-d777-40a3-a059-91ba088c0026
session_name: tidal-anchor
session_id: f7964916-08bc-49a1-a75c-f107b3b3001a
model: claude-fable-5
harness: claude-code 2.1.232
machine: cf6e768835c7
---

# Fix persist-plan re-persist loop — row-keyed idempotency (cadence-hooks#690)

Panel: plan-reviewer (conflict/drift) + plan-reviewer (underspecification) + cameron-review ran — 29 findings, 26 folded in, 3 declined

## Context

`persist-plan` (UserPromptSubmit) re-persists the pristine approved plan snapshot on every prompt for the life of a session. Three code-verified facets, all confirmed on GitHub main (`crates/session/src/persist_plan.rs`) and live-reproduced on three machines (issue #690's comment thread — work, sjomba, the herdr session):

1. **The plans dir follows the session cwd.** `run_persist_plan` resolves `repo_root` via `crate::registry::repo_root(cwd)` — a bare `git rev-parse --show-toplevel` (`registry.rs:41`). A session whose cwd moves to a sibling/nested repo persists the plan there, and `canonical_plans_dir` (`persist_plan.rs:447`) runs `fs::create_dir_all` **before any idempotency check runs** — so even a turn that ends in a skip invents `docs/plans/` in the wrong repo. Blast radius includes nested forks of public upstreams.
2. **The dedupe cannot recognize a maintained or hand-persisted plan.** The `via_late_scan` gate (`persist_plan.rs:251`) scans the (cwd-resolved) plans dir via `file_matches_body`: tier 1 reads the recorded `body_sha256:` frontmatter key (absent from hand-persisted plans), tier 2 a legacy trailer, tier 3 recomputes the hash of the file's current body — which the living-plan lifecycle diverges by design (ticks, `## Deviations`, merged frontmatter). A correctly-maintained plan defeats all three tiers.
3. **Slug derivation never collides with hand-named files** — a filename-level backstop doesn't exist either (hash-based matching is the only recognition, and it fails per facet 2).

**The fix anchor already exists:** every successful persist appends a row to `<config_dir>/metrics/plan-links.jsonl` (`persist_and_nudge` → `append_plan_links_row`) carrying `body_sha256`. That file is **machine-local and cwd-independent** — a row-keyed idempotency tier answers "this machine already persisted this body" regardless of where the session's cwd has wandered. It closes facet 2 outright and bounds facet 1 to at most one write (the first persist, which is legitimate and writes the row; every later firing skips before touching any cwd-derived path). Facet 3 is subsumed: recognition becomes row-keyed, not name- or content-keyed.

All `persist_plan.rs` line citations are GitHub main as of 2026-08-14 (the local checkout is 33 commits behind and disagrees) — re-resolve by symbol at implementation time.

Scope note: all three field repros are the **late-scan path** (the injected `planContent` transcript entry re-fires on every prompt — `persist_plan.rs:205-221`). The prefix path and the `PersistPlanApproval` arm fire once per event by design and are untouched.

## Approach

Add a **tier-0 row check** to the late-scan path, and stop inventing directories on skip paths:

1. **New `session_already_persisted(body_hash, session_id) -> bool`** in `persist_plan.rs`: **tail-anchored** bounded read of `<metrics_dir>/plan-links.jsonl` via `cadence_hooks_core::transcript::read_tail` if its cap semantics fit, else a local tail-window read behind a named constant (`PLAN_LINKS_SCAN_MAX_BYTES: u64 = 256 * 1024`, ~1000 rows; skip the first partial line after seeking). Head-anchored `take(cap)` is wrong: the file is append-only, so recent rows live at the tail, and a head read silently blinds the check as the file grows. Match predicate: a row whose `body_sha256` equals the hash **AND** whose `child_session_id` equals the running session's id — session-keying makes suppression exactly coextensive with the defect (a session's own re-fires) and keeps a *different* session legitimately persisting the same body into another repo. Malformed lines skipped; unreadable file → `false`; a matching row that has scrolled out of the tail window → `false` (fail-open to the dir scan, ADR-0001). `metrics_dir()` note: `CADENCE_METRICS_DIR` is a **production** resolution tier, not a test-only seam — the new read behaves under it like every other consumer.
2. **Gate placement:** in `run_persist_plan`, at the point where `body_hash` is computed today — after the existing cwd/repo/session-id gates, whose order does not change (`via_late_scan` is derived at the extraction match at the top of the function, so it is available; `session_id` comes from the gate just above): `if via_late_scan && session_already_persisted(&body_hash, session_id) { return CheckResult::allow() }` — **before** any plans-dir resolution. **The silent `allow` (vs the dir tier's nudge) is a decision, not an oversight:** the row is written only by a persist that already nudged, so the user was told once; the per-prompt re-nudge is part of the noise this fix removes. The dir tier's `AlreadyPersisted → nudge` behavior is unchanged.
3. **Stop creating `docs/plans/` on the scan path:** split `canonical_plans_dir` into `existing_canonical_plans_dir(repo_root) -> Option<(PathBuf, PathBuf)>` — identical signature and symlink-escape `starts_with` guard, but requires the dir to already exist instead of `create_dir_all` — used by the late-scan dir check only. At scan time its two `None` causes (dir absent; symlink escaping the repo) correctly collapse to the same outcome — "nothing scannable here" — because a symlink-escaping dir must not be scanned either; the **write** path re-resolves through the existing creating variant with its own guard intact, so the refuse semantics on write are untouched. The creating variant's call site moves to write time: in `run_persist_plan` immediately before `persist_and_nudge` (prefix and late paths both), unchanged in `run_persist_plan_approval`. A repo with no `docs/plans/` still gets its legitimate first persist.
4. **The existing dir-wide scan stays** as the second recognition layer (covers a wiped metrics file, rows beyond the tail window, and pre-fix sessions with no rows). Module-doc naming discipline: recognition order is **row → dir scan**; the dir scan's per-file matching keeps its documented internal tiers (frontmatter key → legacy trailer → recompute). Never number across the two layers.
5. **Escape hatch:** `CADENCE_PERSIST_PLAN_FORCE` (any non-empty value) skips the row tier for the turn — the returnable escape the friction canon requires. The delete-and-retarget workflow (#690's wrong-repo case: delete the stray, want it in the right repo) is served two ways: a fresh session persists regardless (session-keying), and within the same session the env var forces it. A tier-0 skip stays otherwise **silent** — the row is written only by a persist that already nudged once, and per-prompt re-nudging is the noise this fix removes.
6. **Containment is preserved by construction:** both plans-dir variants keep the canonicalize + `starts_with(repo_root)` symlink-escape guard, and the two existing escape tests (`canonical_plans_dir_refuses_a_symlinked_docs_escaping_the_repo`, `run_persist_plan_never_writes_through_a_symlinked_docs_escaping_the_repo`) are named must-stay-green in the Tests task — the split is exactly where an escape check gets dropped from one branch, so the plan pins it.
7. **Schema pin:** the plan-links v2 doc comment gains one line pinning `body_sha256` **and** `child_session_id` as idempotency-critical, never-droppable fields (the comment already records the field-drop discipline for consumers; tier-0 makes these two load-bearing for correctness, and the live stream is mixed v1/v2).

**Scope caveat, stated:** tier-0's memory is config-dir-scoped (`metrics_dir()` sits under `claude_config_dir()`, which cadence#773 may move and `claude-as <profile>` already varies). A relocation empties the memory; the failure mode is **one benign duplicate** (the dir scan and re-written row then re-converge), never a lost persist.

**Residual, accepted:** a hand-persisted, diverged plan whose session has no row yet still gets **one** duplicate on the first late-scan firing — which writes the row and ends that session's loop. Bounded, not eliminated; noted on #690. (The broader row-permanence concern — same body, second repo, later session — is eliminated by session-keying, not accepted.)

## Tasks

- [x] **Worktree entry** — `cadence-hooks` is branch-mode: `git fetch` (local checkout is 33 commits behind), worktree on branch `plan/690-persist-plan-row-idempotency` from `origin/main`, `push -u`, draft PR at entry. Persist this plan to `cadence-hooks/docs/plans/` on that branch (Lane A — code-coupled).
- [x] **Implement** `session_already_persisted` + the late-path row gate in `run_persist_plan` (placement per Approach 2) + `existing_canonical_plans_dir` and the write-time move of the creating variant (Approach 3). Invoke `cadence-forge:developing-guards` before writing Rust. Module doc updated to the row → dir-scan recognition order.
- [x] **Tests** (same file's `mod tests`; metrics dir injected via the repo's **shared env-lock helper `crate::registry::test_metrics_env::with_metrics_dir`** — never a new private env mutator; minting a second lock is the recorded race of cadence-hooks#437/#446):
  - **Facet-1 regression:** two temp repos A and B; row for (hash, session) exists after a persist in A; cwd = B; late path → allow, and `B/docs/plans/` is **never created**
  - late path, no row, dir-tier match → **Nudge** (existing `AlreadyPersisted` behavior preserved — `end_to_end_re_fire_skips_write_but_still_nudges` stays green)
  - **Tier-0 attribution:** persist once (row written — assert the row in `plan-links.jsonl`), then **delete the plan file**; second firing → allow with no re-write (dir tier cannot match a deleted file, so only the row explains the skip — mirrors the field repro)
  - **Session-keying:** row exists for the same hash under a *different* `child_session_id` → does not suppress; persists normally
  - prefix path ignores rows (one-injection-one-date semantics preserved)
  - malformed rows skipped; matching row beyond the tail window → fail-open to dir tier (fixture sized just over `PLAN_LINKS_SCAN_MAX_BYTES` with the match at the head — documents the bound honestly, no multi-MB fixture)
  - `CADENCE_PERSIST_PLAN_FORCE=1` + matching row → persists anyway (escape hatch works)
  - must-stay-green: `canonical_plans_dir_refuses_a_symlinked_docs_escaping_the_repo`, `run_persist_plan_never_writes_through_a_symlinked_docs_escaping_the_repo` (containment across the variant split)
- [x] **Gates** — `make ci` (the repo's named gate); if running pieces directly, `cargo test --workspace --no-fail-fast`, `cargo clippy`, `cargo fmt --check`. CHANGELOG entry per repo convention.
- [x] **Polish + PR** — diff-based review arms (session cwd is the meta-repo; built-in `/polish` arms no-op on worktree diffs), `cadence:redaction` pre-post, PR body: `Fixes #690`, producer tuple (squash-merge repo), public refs only.
- [ ] **Close the loop** — comment on #690 naming the fix shape + the accepted residual; after merge, verify the re-pin on sjomba and confirm this very session's transcript (which still carries the injected `planContent`) no longer re-persists.

## Alternatives declined

- Resolve the plans dir from the plan's *own* repo instead of cwd — declined: the injected `planContent` carries no repo identity, so "the plan's repo" is not derivable at late-scan time; the row sidesteps needing it. (The repo-scoped destination generalization is recorded on cadence-hooks#692, not here.)
- Fuzzy tier-3 matching (first-heading + date) to recognize diverged hand-persisted plans — declined: a false skip silently loses a persist (worse than a duplicate); the row bounds the damage to one duplicate instead.
- Apply the row tier to the prefix and approval paths too — declined for scope: those fire once per event by design and none of the three field repros involve them; recorded as a follow-up option on #690.
- Per-repo opt-out (`repo_env_flag`) — separate ask, already filed as cadence-hooks#692; not this fix.

## Panel review — findings declined

- [cameron-review] "hoist `sha256_hex` above the cwd/repo/session gates" — superseded: session-keying needs `session_id`, which the gate just above resolves, so placement after the gates is forced and correct; the cwd gates create no filesystem paths, so nothing is lost.
- [cameron-review] "tier-0 should emit a disclosure nudge naming the prior plan_path" — declined in favor of silent-plus-escape: the row exists only because a persist already nudged once, and hooks are stateless per turn, so any disclosure is per-prompt noise — the exact symptom being fixed. `CADENCE_PERSIST_PLAN_FORCE` + fresh-session recovery carry the intentional-re-persist case. (Cameron can overrule at approval.)
- [cameron-review] "fold the prefix/approval arms into the row tier now that the reader exists" — stays declined for scope: those arms fire once per event by design, no field repro involves them; recorded as a follow-up option on #690.

## Execution

Solo (single-file Rust change requiring judgment about check ordering; not dispatchable). Security seat not seated, with the owner seat's caveat addressed in-plan: the refactor touches `canonical_plans_dir`'s containment guard call sites, so Approach 6 pins the guard in both variants and the Tests task names the two existing escape tests must-stay-green. No authN/Z, crypto, secrets, access-control, or exposure control changes posture; the change strictly narrows accidental writes.

## Verification

- `make ci` green including the six new tests; the facet-1 test asserts the wandered-cwd repo's `docs/plans/` is never created **when a row exists** (the no-row first persist legitimately writes to the cwd repo — that residual is bounded, not asserted away).
- Post-merge live check on sjomba, and it is decidable **in this session**: the earlier duplicate persists already wrote rows carrying this session's id, so after the re-pin the next prompt must produce no new duplicate and no re-nudge. A hand-check of `<config_dir>/metrics/plan-links.jsonl` confirms the rows exist before trusting the negative.

## Deviations

- Local `make ci` carried three machine-local reds, all attributed off-branch before shipping: `codex_coverage` ×2 (ambient `CADENCE_DISABLE=guard-rm` — green under `env -u`), `hook_registration_audit` (`inject-gh-context` awaits monorepo wiring; CI skips the sibling audit), `doctor_quiet_warnings_print_summary_to_stdout` (fails on pristine `origin/main` on this machine too). GitHub CI: both legs green.
- Polish security arm raised one Important (advisory, not applied): a *forged* `plan-links.jsonl` row suppresses persists silently — same silent-skip decision the plan's declined-findings section already records; suggested observability record left to Cameron's disposition.
