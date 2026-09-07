# Pre-push secret scan for the outbound push range — implementation plan

> Draft plan PR. Per-issue references use `Refs cameronsjo/cadence-hooks#237` — this
> document intentionally does **not** auto-close the implementation issue. Implementer:
> **Opus drives throughout** — this is a guard-feeding shell parser on the *push* path,
> where a MISS is a published secret. Two mandatory `cadence-forge:security-reviewer`
> (Opus) gates: Task 0 (the parser) and Task A (the guard). Binary PRs first; the plugin
> `hooks.json` companion is a release-gated follow-up. Dispatch each task as its own
> scoped session/PR, in the sequence below, not in parallel. Planned 2026-07-09.

## Context — why this plan

`cameronsjo/cadence#278` shipped a session **entry posture** for branch-mode repos: a
feature branch gets an immediate `push -u` + draft PR at creation, then a push after each
meaningful commit. That converts *push* into a default, unprompted action — removing the
informal last checkpoint (Claude Code's ask-before-push default) between an accidentally
committed secret and public remote history. A 2026-07-06 security review of the #278 stack
verified there is **no pre-push gate**: write-time guards cover the env/credential *file*
slice, but nothing scans commit *content* at push time; CodeRabbit scans *after* the push
(rotation, not prevention). #237 is the named deferred guardrail.

## Reality check up front — what this actually is

**Not** a reuse-maximal single guard. It is **a new hardened `core::shell` push-detection
primitive (precursor) + a cadence-crate scan guard that consumes it + the existing value
corpus.** The corpus and the per-commit patch-scan mechanic are genuinely reused; the *push
detection and range resolution are new work*, because the only hardened git-subcommand
parser in the tree (`git_commit_targets`) is **private to `crates/guardrails`** and
commit-specific — a cadence-crate guard cannot call it, and copying it forks the
security-critical parser the reuse ledger forbids. Owning that is the difference between
this plan and the one that would ship broken.

## What is reused verbatim (the real reuse ledger)

- **`scan_secret_values(text) -> Option<&'static str>`**
  (`crates/cadence/src/secret_patterns.rs:332`) — 6-family value corpus (AWS `AKIA…`/`ASIA…`,
  GitHub token + `github_pat_` prefix, OpenAI `T3BlbkFJ` infix, Slack `xox[baprs]-` prefix,
  PEM header), **name-only** return (never echoes the value), **no entropy** (deliberately
  rejected), FP-tuned by a discriminating test suite (SHAs, UUIDs, JWTs, base64, CSS `sk-`,
  redis). Reused unchanged.
- **Per-commit patch scan over `git log -p -U0`** — probe-validated: catches a secret
  **added then removed** within the range that a net `git diff base..HEAD` **misses**.
- **`command_segments` / `tokenize` / `child_scripts` / `split_segments_with_ops`**
  (`core::shell`) as the *building blocks* of the new Task-0 primitive.
- **Wiring template** `guard_op_vault_scan.rs`; four-place registration
  (`registry_matches_clap_dispatch` + `hook_registration_audit` enforce it).

## Adopt-over-build — reuse the corpus; honestly track recall

Rejecting the **gitleaks/trufflehog binary** is correct (single-binary bias; the
`markdown_lint.rs` silent-fail-open-when-absent precedent; subprocess budget; a second
grammar the ledger forbids). But "adopt over build" was conflated with "which corpus."
Ruling, split cleanly:

- **v1 ships on the in-house 6-family corpus** — precision-first, dogfoods the mechanism,
  zero new deps. Be candid: v1 catches those 6 families and nothing else (no
  GCP/Azure/Stripe/Twilio/GitLab/npm/generic high-entropy `KEY=`).
- **Tracked follow-up (new issue): corpus-recall expansion by vendoring gitleaks' MIT regex
  *rules as static Rust data*** — zero subprocess, zero single-binary cost, the same
  data-adoption move the ecosystem already made. The push gate is exactly where
  precision-over-recall legitimately *inverts* (rare scan, published-secret stakes), so
  recall should climb — but that is a follow-up, not a v1 gate. The binary rejection does
  **not** stand in for this.

## Placement & crate boundary — the lift the layout forces

`scan_secret_values` is `pub` in `crates/cadence`; the hardened git parser is **private** in
`crates/guardrails`; `core::shell` has the shell primitives but **no**
git-subcommand/`-C`/refspec detector. So a lift is unavoidable. Chosen: **build the push
detector in `core::shell`** (its natural home, beside `command_segments` / `parse_work_dir`),
guard stays in **`crates/cadence`** (cadence-namespace, beside `prevent-secret-leaks` /
`prevent-secret-writes`, reusing the corpus in-crate, no cross-crate dep). Bonus:
`guard_push_remote` (today substring-based) MAY later adopt the same core helper — a real
consolidation, not churn, and directionally aligned with #268.

**Name: `prevent-secret-push`.**

## Detection & range design (all defects from the panel folded)

1. **Trigger — hardened, in core.** New `core::shell::push_invocations(command, cwd) ->
   Vec<PushInvocation>` where `PushInvocation { work_dir, refspecs: Vec<Refspec>,
   all_or_mirror: bool }`. Built **non-flat** (segment-tree aware — a flat `command_segments`
   / `parse_work_dir` view splices `$(cd /x)`'s `cd` into the parent stream, the exact miss
   `git_commit_targets` rejected). Reuses `tokenize` + transparent-prefix skipping + the
   git-global `VALUE_GLOBALS` walk to (a) confirm the verb is `push`, (b) capture
   **`-C <dir>`** into `work_dir` (bare `parse_work_dir` is `cd`-only and blind to `-C`),
   (c) collect the actual **refspecs**. Skip `--dry-run`. **Per-refspec** delete detection
   (`--delete`, leading-`:` `:dead`) — never skip the whole command, so
   `git push origin :dead newbranch` still scans `newbranch`. Documented misses (state them,
   don't imply): dashed `git-push`, user aliases (`git pu`) — same limit as sibling guards.

2. **Range — from the refspec, not HEAD, correct ordering.** For each pushed source ref,
   outbound set = **`git rev-list <src-ref> --not --remotes`** — positive ref **before**
   `--not` (v1 wrote `--not --remotes HEAD`, which negates HEAD too → **scans zero, allows
   every push**; panel-confirmed by probe). `git push origin branchB` / `local:remote` scans
   *branchB* / *local*, not HEAD. `--all` / `--mirror` or any **unresolvable** refspec → scan
   every local branch's outbound set, or **block-with-reason** ("couldn't fully resolve the
   push — refusing to scan a subset"); never silently scan a subset and exit 0 (a miss is the
   wrong direction).

3. **First push = full history is the COMMON case, not an edge.** With no `refs/remotes/*` yet
   (fresh branch, first `push -u` to a new remote), `<ref> --not --remotes` expands to the
   entire history (probe: 5/5 commits). So the commit-count cap is the **primary correctness
   backstop**, not a nicety. Where the push target ref is determinable, prefer deriving the
   base from it over trusting stale `--remotes`. (Accepted residual: `--remotes` spans *all*
   remotes, not just the target — a commit already on a fork is excluded though pushing to
   origin publishes it there; marginal, documented.)

4. **Scan — patches, absolute-resolved paths.** `git log -p -U0 --no-color <range>` via an
   **error-distinguishing** git call (see §Fail direction), scan `+` lines with
   `scan_secret_values`. Parse the file path from the diff header (`+++ b/<path>`, `/dev/null`
   for deletes, rename headers) and **resolve it to absolute** (`work_dir` + relative)
   **before** `is_secret_scan_exempt` — the exemption matches a `cadence-hooks` path
   *component*, but `git log` emits *repo-relative* paths, so without the join it is a
   **no-op and the guard blocks its own repo's fixture pushes** (incl. Task A's own AKIA/PEM
   tests). Additionally exempt paths passing **`is_safe_template`**
   (`.example` / `.sample` / `.template` / `.test`) so *other* repos' documented fixture keys
   don't hard-block every push.

5. **Report.** On a hit: `CheckResult::block` naming **short-sha + path + pattern name** —
   never the value.

## Fail direction — the silent-allow trap, closed

`git_command` (`crates/core/src/shell.rs:156`) returns `None` on **both** subprocess error
*and* empty output — so "git errored" is indistinguishable from "nothing to push," and the
naive read (empty → allow) makes a git error a **silent ALLOW** (a miss, violating "sees less
= miss, not licensed fail-open"). `git_command_detailed` does **not** exist on `main` (v1
wrongly assumed it). Fix: Task 0 adds an **error-distinguishing** core call; a git error
**with a push detected** must **nudge-loud or block**, never silently allow. Genuine "0
commits to push" allows.

## Fail posture + override — **Decision Point (Cameron rules at Step-0)**

**Recommend BLOCK (exit 2), ack-only override.** Panel converged: the
#164/#151/#152/#155/#158 FP history was **trigger-scoping** FPs, not value-pattern FPs; the
write-time sibling already blocks on the identical corpus and is trusted; a warn-only secret
gate is a prose boundary that "loses to momentum." So Task B's adversarial energy goes at
**trigger + range**, not the value patterns.

- **`CADENCE_ALLOW_SECRET_PUSH=1`** — per-invocation ack (mirrors `CADENCE_ALLOW_MAIN`).
  **This is the only override.** Dropped v1's `CADENCE_NO_SECRET_SCAN` durable-disable:
  durably disabling a *security* guard is permanently defeating it; `CADENCE_BYPASS=1`
  already covers maintenance per ADR. Add durable-disable only if a real repo demands it.
- Block message names commit + path + pattern, offers *rotate if real* / the ack var if false
  positive, + feedback footer.

## Overflow posture — **Decision Point** — cut the nudge

Over-cap range (the common first-push-full-history case) → **scan newest-N then
BLOCK-with-count** ("range too large to fully scan — push blocked;
`CADENCE_ALLOW_SECRET_PUSH=1` to override"). v1's NUDGE-with-unscanned-count is **removed**:
it lets an adversary pad past N to force allow, and it silently allows exactly the
hardest-to-scan push — decoration by the plan's own "warn = decoration" thesis. Drop the
byte-cap machinery; keep a single generous commit cap (N≈200; `-U0` patches are sub-second).
The entry posture pushes small-and-often, so a legitimate over-cap push is rare and the ack
covers it.

## Relationship to siblings (cross-reference, no overlap)

- **#268 (gitstate/pathclass classifier)** — independent, no sequencing dependency. This
  guard needs no path *classification* (`is_main` etc.); it scans regardless of branch. The
  Task-0 `core::shell` push detector is directionally aligned with #268's "consolidate shared
  parsing" but is a distinct primitive (push/refspec/`-C`, not path-class). If #268 lands
  `GitState`, this guard MAY consume `repo_root` as tidy-up, not a prerequisite.
- **#267 (enforce-worktree subprocess nudge)** — independent; unrelated command taxonomy.

Third independent plan in the Step-0 queue.

## Task breakdown (all Opus; strict order; each its own PR)

### Task 0 — `core::shell::push_invocations` (precursor)

The hardened, non-flat, `-C`-aware, refspec-collecting push detector + the
error-distinguishing git call. **Guard-feeding parser → its own mandatory
`cadence-forge:security-reviewer` (Opus) gate**, framed *"find a `git push` the shell runs
that `push_invocations` never sees, or a refspec whose range it resolves wrong."* Pure `core`
unit tests (wrapper, quoting, `-C`, `$(…)`, multi-refspec, delete+publish, `--all` /
`--mirror`, `--dry-run`).

### Task A — the guard

New `crates/cadence/src/prevent_secret_push.rs` + `impl Check for PreventSecretPushGuard`,
consuming Task 0 + `scan_secret_values`. Range via corrected per-refspec `rev-list`;
absolute-resolved exemption + `is_safe_template`; overflow scan-N-then-block; ack override;
git-error → loud, not allow. Four-place wiring (template `guard_op_vault_scan.rs`):

- module export;
- `CadenceCommands::PreventSecretPush` + `hook_name()` arm + dispatch arm (`src/main.rs`);
- `HookEntry { name: "prevent-secret-push", plugin: "cadence", event: Some(PreToolUse) }`
  (`src/registry.rs`).

**Test harness:** fixture git repos (model on `enforce_worktree`'s Scratch/E2E harness) —
scope this as infrastructure, not just a case list. TDD must include:

- **first-push no-upstream range is NON-EMPTY** (regression-guards the ordering bug),
- added-then-removed catch,
- `git push origin branchB` scans branchB not HEAD,
- `git -C` redirect,
- delete+publish,
- in-repo fixture path is exempt,
- `--dry-run` allows,
- `sh -c 'git push'` still scanned,
- git-error does not allow,
- over-cap blocks,
- ack allows.

### Task B — MANDATORY adversarial security review

Of the guard (`cadence-forge:security-reviewer`, Opus). Written **"no new miss"** artifact.
TDD + CI green is explicitly insufficient (repo rule). Focus: trigger/range evasion, not
value patterns.

### Task C — plugin `hooks.json` companion (release-gated, separate PR/session)

After the binary releases, add the `Bash`-matcher `PreToolUse` entry to the **cadence
plugin's** `hooks.json` (beside the sibling secret guards). Binary-first/plugin-after;
`doctor` cross-checks.

## Verification (for the implementing session)

- `make ci` green from a **carve-out-free path** (not `.claude/worktrees/` or `/tmp` — they
  false-ALLOW `enforce_worktree`; use `git worktree add --detach ~/verify <sha>`). Local
  toolchain may trail CI clippy — treat first CI run as the real verdict.
- **Manual, hermetic:** `cargo build --bin cadence-hooks` first (else exit-127 misreads as
  ALLOW), pipe crafted payloads to the **bare** `cadence-hooks cadence prevent-secret-push`
  (honors payload `cwd`; `try` overrides cwd + ignores stdin). Cases mirror the TDD list,
  asserting the **exit code** (0 allow / 2 block) and that the block names commit + path +
  pattern and **never the value**.
- **TTY guard** untestable via piped stdin — `script -q /dev/null …`.

## Decision Points carried to Step-0

1. **Block vs warn** — recommend **BLOCK + ack override**.
2. **Overflow** — recommend **scan-newest-N then BLOCK-with-count** (not nudge/allow).
3. **Recall scope** — recommend **ship v1 on 6 families, track gitleaks-rules-as-data
   expansion** as a separate issue; don't let the binary rejection imply recall is settled.
4. **Scope acceptance** — this is **guard + a new core parser (Task 0)**, not a lone guard.
   Confirm the larger shape, or descope to substring detection (accepts the wrapper-evasion
   miss — *not* recommended for a security gate).

## Adversarial findings folded (v1 → this draft)

A 3-lens panel (plan-reviewer, red-team, cameron-review) ran against v1. What changed:

- **CRITICAL** `rev-list --not --remotes HEAD` scans zero (negates HEAD) → corrected ordering
  + non-empty first-push test. *(all 3 lenses + probe)*
- **CRITICAL** reuse of the hardened parser is impossible cross-crate (private to guardrails)
  → Task 0 builds it in `core::shell`; plan reframed as guard+primitive. *(plan-reviewer)*
- **CRITICAL** range from HEAD misses non-HEAD refspecs (`branchB`, `local:remote`, `--all`)
  → refspec-derived range. *(plan-reviewer, cameron)*
- **CRITICAL** `git_command` `None` conflates error/empty → silent-allow → error-distinguishing
  call; error-with-push never allows. *(plan-reviewer)*
- **HIGH** `is_secret_scan_exempt` no-ops on repo-relative diff paths → blocks own/fixture
  pushes → absolute-resolve before exemption + `is_safe_template` for off-repo fixtures.
  *(red-team, plan-reviewer)*
- **MEDIUM** `-C <dir>` work_dir blindness; delete+publish command-level skip; flat-view
  `$(cd)` miss → non-flat `-C`-aware core primitive, per-refspec delete. *(plan-reviewer)*
- **MEDIUM** overflow nudge = pad-past-N bypass → scan-N-then-block. *(all 3 lenses)*
- **YAGNI** two override vars → ack-only; recall honesty → tracked follow-up. *(cameron)*

## Alternatives declined

- Wrap gitleaks/trufflehog **binary** — external Go binary; single-binary + silent-fail-open
  costs. (Rules-as-data is a *tracked follow-up*, not declined.)
- Guard in `crates/guardrails` — forces the cross-crate dep the other direction; the core
  lift serves both crates and is directionally aligned with #268.
- Net-diff scan (`git diff base..HEAD`) — misses added-then-removed (probe-disproven).
- Range from HEAD / `@{u}` — wrong ref and fails at first push.
- Warn-only guard, or overflow-nudge — decoration for a security control.
