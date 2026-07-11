# cadence-hooks Performance Spine — Single-Dispatch Consolidation (#276) — plan, 2026-07-10

> Pickup contract for a zero-context session. **Re-verify at pickup** (state
> below is authoritative-as-of-2026-07-10, probed against `origin/main` =
> `2c50a9c` / v0.56.0; the local checkout HEAD was `44fc5dd`, 31 behind).
> Repo: `cameronsjo/cadence-hooks` (local checkout).

## Context — the 14→1 problem

A single Claude Code tool call fans out to one **hook process per registry
entry** for the matching event. Each pays its own fork/exec, builds the full
`clap` tree, parses the identical stdin payload, re-discovers the repo root
(fresh `git` children), re-reads `.claude/settings*.json`, and appends its own
telemetry rows. Nothing is shared across the fan-out.

Grounded in live wiring (plugin `hooks.json` under
`claude-configurations/*/plugins/*/hooks/`):

- The **cadence** plugin alone wires `PreToolUse` as `Write|Edit → 8 hooks`,
  `Bash → 7 hooks`, `Read|Grep → 1 hook`
  (`cadence/plugins/cadence/hooks/hooks.json`).
- Across all plugins a `Write`/`Edit` fires **14 binary invocations**,
  unconditionally (#276 comment, measured @ `44fc5dd`): cadence ×8,
  guardrails ×3, canon/session ×2, rules ×1.
- Each entry is **wrapper + binary = 2 processes** — `run-cadence-hooks.sh`
  does `command -v`, `mktemp`, `exec`, greps stderr for the stale-binary
  signature.
- `session heartbeat` fires on **every** `PostToolUse` (matcher `*`).

Measured cost (#271, CLOSED; Phase 1 shipped PR #273): ~4.7s per `Bash`, ~5.9s
per `Edit`/`Write` on a loaded host — enough to blow Claude Code's ~5s hook
budget, at which point guards **fail open and do not enforce**. Phase 1 bounded
*in-process* git time only. Single-dispatch is the deferred root-cause step:
**one binary invocation per hook event runs every applicable check in-process**
— one stdin parse, one repo discovery, one shared git probe, one process.

The registry (`src/registry.rs`, `HOOKS`) already centralizes all entries as
the single source of truth, cross-checked against the `clap` dispatch — the
natural seam for an internal dispatch loop.

## Preconditions

**The precondition gate is scoped to Task 4 only.** Tasks 1–3 (parity suite,
dispatch skeleton, aggregation-over-`merge`) are independent and additive —
**start them now** against `origin/main`. Only Task 4 (threading the shared
config loader + `GitState` through checks) depends on the branches below.

- **#153 unified config — a dependency of Task 4, not duplication.** Issue #153
  (`feat/unified-cadence-config-153`, 5 commits, on origin, ADR-0002) lands a
  shared loader + `migrate-config` subcommand + `doctor` warnings. Task 4's
  single per-event config load must call **that** loader. Provenance caveat: the
  `.claude/cadence.json` file itself is **runtime-produced by `migrate-config`**,
  not a committed artifact — the machinery lands, the file does not. Do not
  conflate the #153 loader with the **existing** `crates/core/src/config.rs`
  (864 lines, unrelated); confirm the new loader's module path at pickup.
- **pr4b GitState — a dependency of Task 4, and it is LOCAL-ONLY.**
  `feat/gitstate-pr4b-enforce-resolution` (2 commits: canonicalized
  `repo_root` + `git_common_dir`, guard-rm consumer) is **unpushed** — only
  `feat/gitstate-pr4-enforce` (no "b") is on origin. Task 4's precondition is
  therefore **push pr4b + open its PR + land to `origin/main`** as an explicit
  sub-step, not "it's already on a branch."

Re-verify all branch/worktree/registry state at pickup (`git branch -a`,
`git worktree list`, `git rev-list --count origin/main..<branch>`). The task
packet's fourth named worktree `feat/warn-branch-base-worktree-first` **did not
exist** on 2026-07-10 (nearest live: `feat/gitstate-pr5-branch-resolvers`).

## Non-goals

- **Resident daemon (claude-configurations#373) is OUT** — Phase 3, explicitly
  evidence-gated behind this work. Build it only if Task 6's telemetry shows the
  host still starved after the fan-out collapses. This plan produces that
  go/no-go data (Task 6).
- **New guard logic** — pure re-architecture; every verdict byte-for-byte
  identical (the parity gate).
- **Network export on the hot path** — the hook path ends at local file
  appends; any export is an off-path consumer (record in the ADR).

## Design — single-dispatch architecture

**One subcommand, `cadence-hooks dispatch <EVENT>`**, replaces the per-check
subcommands in wiring. Per invocation it:

1. **Reads stdin once** → `HookInput`. Fail-open on parse error (ADR-0001).
2. **Arms one deadline** (`core::deadline::arm()`) for the process — see the
   correlated-fail-open risk; this is why Task 5 adds a per-check soft budget.
3. **Discovers repo topology once** (pr4b `GitState`) and **loads
   `.claude/cadence.json` once** (#153 loader), handed to every check by
   reference (Task 4).
4. **Selects applicable checks** from `HOOKS`: entries whose event matches, whose
   plugin is enabled for this repo, honoring `PROTECTED_GUARDS`
   (`CADENCE_DISABLE` cannot neuter these). **Three dispatch classes**, all
   covered: `PreToolUse`, `PostToolUse`, and the **logger class** (registry
   `event: None`), which keys on the payload's `hook_event_name` — this class
   includes `SessionStart` context injectors **and the Subagent/Stop/PreCompact
   loggers** (e.g. `SubagentStart`/`SubagentStop`), which are *not* fixed
   `HookEvent` variants. None of these classes may be omitted from selection or
   parity.
5. **Runs every selected check** under **per-check `catch_unwind`** (Task 3),
   collecting `CheckResult`s. Checks already self-filter on `tool_name`, so
   matcher gating is preserved inside the loop.
6. **Aggregates via the existing `Outcome::merge`** (Task 3) — see below.
7. **Writes telemetry once per check** (`log_denial`/`log_timing`/`log_bypass`,
   name threaded as today in `src/dispatch.rs`), from one process.

**Aggregation REUSES `Outcome::merge`** (`crates/core/src/lib.rs:126`, test
suite 1451–1541) — do **not** build a fresh `aggregate()`/`ProcessOutcome`.
Fold the check loop over `merge`. The canonical, shipped precedence is
**Block > Ask > LoopBlock > Nudge > Allow** (most-restrictive-wins, mirroring
Claude Code's own `deny > ask`). One net `Outcome` → one exit code. Message
handling: concatenate every contributing check's rendered stderr/stdout in
registry order (stderr for a `Block`, the `permissionDecision:"ask"` envelope
for `Ask`, merged nudges for `Nudge`). Concatenation may short-circuit for
*reporting*; check *execution* never does (see run-all).

**Run-all is mandatory (decided here, not deferred).** Every selected check
executes even after a `Block` is seen — short-circuiting execution would drop
telemetry rows for the remaining checks and corrupt Task 6's count-in≠count-out
daemon go/no-go data. Only stderr/report concatenation may stop early.

**Rollback flag `CADENCE_DISPATCH_MODE=per-check|single`** (Task 2): production
can fall back to per-check dispatch **without reverting the `hooks.json`
rewiring** under live load. The dispatch entry reads it and, in `per-check`,
runs each selected check exactly as today.

## Task breakdown

Each task: own branch, PR to `origin/main`, `cargo test --workspace` green.

1. **Parity suite (FIRST — the acceptance gate for 2–5).** Generate the
   baseline by **grepping the live registry at pickup** (do NOT hard-code
   counts — the catalog drifts). For every registry entry across all three
   dispatch classes (PreToolUse, PostToolUse, logger incl. Subagent*/Stop/
   PreCompact), feed a payload corpus through today's single-check path and
   snapshot `(exit, stdout, stderr, denials row, timing row)`. **Aggregation
   oracle:** either extend the parity suite to capture Claude Code's *real*
   cross-process aggregation of simultaneous exits, or **state explicitly the
   oracle is MODELED (`Outcome::merge`), not observed** — and justify that
   `merge` is the same precedence Claude Code applies. *Acceptance:* generated
   baseline committed; class coverage complete; oracle stance documented.

2. **`dispatch` subcommand + registry selection + rollback flag.** Add
   `Commands::Dispatch { event }` to `src/main.rs`; selection over `HOOKS`
   (event/class filter + per-project disable + `PROTECTED_GUARDS`) in a new
   `src/dispatch_all.rs` (leave `src/dispatch.rs` untouched as the fallback).
   Wire `CADENCE_DISPATCH_MODE`. No aggregation yet — loop `run_logged_check`.
   *Acceptance:* `echo '<payload>' | cadence-hooks dispatch PreToolUse` runs the
   set; `per-check` mode reproduces today's path; parity suite green for
   single-trip payloads.

3. **Aggregation over `Outcome::merge` + per-check panic isolation (the
   correctness heart).** Fold the loop over `Outcome::merge` (reuse — no new
   engine). Wrap **each** check's `run` in `catch_unwind` (today only *loggers*
   are wrapped — `dispatch.rs:127`/`lib.rs:1077`; the guard path
   `run_logged_check→decide_check` has **none**, so in one process an uncaught
   panic in check K kills K+1..N and their telemetry). A panicking check
   degrades to that single check failing open per its own policy — never a
   whole-dispatch abort. *Acceptance:* unit tests for each precedence pair
   (Block+Nudge, Ask+Nudge, LoopBlock+Nudge, multi-Block order, Ask+Block);
   **a test that forces a panic in one check and asserts the rest still run and
   still emit telemetry**; parity suite green for multi-trip payloads.

4. **Single config + git-topology load (GATED — see Preconditions).**
   Precondition: #153 loader merged AND pr4b pushed+PR'd+merged to
   `origin/main`. **Enumerate** the checks that self-discover topology/config
   today — derive the list by grepping call sites (`find_git_root`,
   `git_common_dir`, and the `redaction.json`/`terminology.json` readers #153
   subsumes) — then refactor each to accept the shared `GitState` + config slice.
   *Acceptance:* the concrete enumerated list is in the PR; **per-check**
   acceptance that each named check now takes the shared context; a syscall/
   process trace shows **one** `find_git_root` and **one** config read per
   `dispatch`, vs N today; parity suite green.

5. **Per-check soft budget + wrapper shim (NOT retirement).** Add a per-check
   watchdog (thread join-with-timeout) so one slow/hung check is **skipped**,
   not fatal to the whole process — `deadline::arm()` bounds only git spawns, so
   a non-git hang or CPU stall would otherwise trip the single external timeout
   and fail **all** guards open at once (worse blast radius than today). Ship the
   `dispatch` wiring behind a **proving period** (length is a Cameron open
   decision); the wrapper/shim stays and must swallow specifically the `clap`
   **"unrecognized subcommand" exit-2** (an old binary predating `dispatch`) and
   **fail open — never block** (blocking would violate ADR-0001). `command -v`
   proves existence, not version — add a **dispatch-capability probe** (a version
   floor or `dispatch --help` check). *Acceptance:* watchdog test (one check
   sleeps past budget → skipped, others complete); shim test (simulated old
   binary → exit 0, tool proceeds); `doctor` passes.

6. **#373 go/no-go telemetry (named deliverable).** Capture **baseline**
   (processes-per-tool-call + latency, per-check timing rows) and **post**
   (1 process + latency) to a **durable file** the daemon decision reads
   (deadline-fail-open row frequency + external-kill scan rate before/after).
   *Acceptance:* the artifact file exists with both datasets; the go/no-go signal
   is stated in it.

7. **Wrapper retirement (a cycle LATER — not this batch).** After the proving
   period (**default: one release cycle of dogfooding**; Cameron owns the cadence
   call): rewrite the wiring to one `dispatch <EVENT>` entry **per event ×
   matcher group** (the decided per-matcher form — see Risks), retire the **5**
   shipping `run-cadence-hooks.sh` copies in `cadence/plugins/` (persona in
   cadence-lab is **out of the ship set**), and inline the fail-open into the
   hook command string.
   Sequence: binary shipping `dispatch` first, wiring rewrite second (the
   release-gating trap — `doctor` CI red-flags wiring ahead of the binary).

8. **ADR + changelog.** Record the re-architecture (it reverses the per-entry
   wiring model the ecosystem is built on): frozen-subcommand contract,
   `merge`-based precedence, run-all invariant, per-check panic + soft-budget
   isolation, network-free hot path, and the #373 escalation boundary.

**Global parity gate (Tasks 2–5):** the Task-1 baseline passes unchanged —
identical verdict/message/exit/telemetry per check before and after.

## Risks

- **Correlated fail-open under one deadline (highest — addressed, not sold as a
  win).** Consolidating N processes into one puts all checks under a **single**
  ~5s `hooks.json` timeout. `deadline::arm()` bounds git spawns only; a non-git
  hang or CPU stall trips the external kill and fails **every** guard open at
  once — a wider blast radius than today's per-process isolation (the #271
  storm). Mitigation: the per-check soft budget (Task 5). Residual, stated
  honestly: the *process-level* external timeout still exists; the soft budget
  shrinks but does not eliminate the correlation.
- **Panic blast radius** — one uncaught panic kills the shared process. Per-check
  `catch_unwind` (Task 3) is the net.
- **Shared-base churn** — rebasing onto a moving `core::paths`/`main.rs`.
  Mitigation: Task-4 gate; re-verify at pickup.
- **`if:`-glob erosion — DECIDED: keep coarse per-matcher `dispatch` entries.**
  One universal entry would convert today's zero-spawn cases (a plain `git
  status` gated out) into one guaranteed spawn. The wiring therefore uses one
  `dispatch <EVENT>` entry **per event × matcher group** (e.g. `Write|Edit`,
  `Bash`, `Read|Grep`), not a single catch-all — preserving the gated-Bash
  zero-spawn path. Reasoning: the universal-entry win is marginal (Write|Edit is
  already unconditional, 8→1) while the per-matcher form keeps the zero-spawn
  benefit where it exists. Applied in Task 7's wiring rewrite.
- **Version skew during rollout** — binary shipping `dispatch` must precede the
  wiring rewrite.

## Verification

- **Parity suite (primary):** Task-1 baseline green across all three dispatch
  classes.
- **Fan-out benchmark (headline):** on the affected host, `Edit`/`Write` and
  `Bash` — **14 binary execs → 1**. Math honesty: this removes ~13× **process-
  spawn** overhead; it does **not** claim ~0.4s. The single process still does
  **one** git discovery that can stall on a synced dir — that git-discovery floor
  **remains and is measured, not assumed** (Task 6 decomposes it).
- **Single-load probe:** trace confirms one `find_git_root` + one config read per
  `dispatch` (Task 4).
- **Telemetry integrity:** one row per *check*, not per process — count-in =
  count-out (feeds Task 6).
- **Isolation tests:** panic-in-one-check and slow-check-skipped both green.
- **`doctor` green** on migrated wiring; a live `Edit` traces to one process.

Every prior open decision is now resolved in-design: the `if:`-glob trade
(per-matcher entries, Risks), the wrapper scope (5 `cadence/plugins/` copies;
persona/lab out — Task 7), and the proving-period length (default one release
cycle of dogfooding; Cameron owns the cadence call — Task 7). No decision is
left dangling to the executor.

## Panel review — findings declined / affirmed

No findings declined outright. Affirmed as-is (recorded for provenance): the
exit-code mapping (0 allow/nudge/loopblock/ask, 2 block), the
#153-dependency-not-duplication framing for config, the precondition
self-correction (4→3 worktrees), and the daemon-#373-out-of-scope framing — all
verified against live state, no change required.

## Sources

- Issues #276 (design + measured fan-out), #271 (CLOSED; P0 + Phase 1 PR #273),
  #153 (unified config + ADR-0002), claude-configurations#373 (daemon, out).
- Code @ `origin/main` (`2c50a9c`): `src/main.rs`, `src/dispatch.rs`,
  `src/registry.rs` (`HOOKS`, `plugin_for`), `crates/core/src/lib.rs`
  (`HookEvent`, `Outcome` + `Outcome::merge`:126 tests 1451–1541, `Check`,
  `decide_check`, `emit_and_exit`), `crates/core/src/{paths,config,deadline}.rs`.
- Wiring: `cadence/plugins/cadence/hooks/hooks.json`, `.../run-cadence-hooks.sh`.
- Branch/worktree state verified live 2026-07-10: origin/main `2c50a9c`, local
  HEAD `44fc5dd`; pr4b unpushed; `Outcome::merge` present; registry counts
  re-derive at pickup.

## Panel review

Panel: 2× adversarial plan-reviewer lenses (conflict/drift, underspecification) +
a live-state red-team seat + owner-lens review — ~34 findings (majority live-state
confirmations), all actionable folded, 0 declined. Verdicts: SOUND-WITH-FIXES ×3
/ APPROVE-WITH-CHANGES. Load-bearing rulings folded: aggregate over the existing
`Outcome::merge` (don't rebuild), ADD per-check catch_unwind (loggers-only
today), address correlated fail-open under the collapsed 5s budget, decide
run-all + the if-glob trade in-design (not deferred to the executor), sequence
wrapper retirement a cycle after dispatch ships, add a CADENCE_DISPATCH_MODE
rollback gate, scope the hard gate to Task 4.
