---
status: blocked
branch: feat/single-dispatch
pr: cameronsjo/cadence-hooks#596
updated: 2026-08-04
approved_session_id: ed99c6a8-17fe-4a32-b09e-55f6d22c4652
approved_in: frost-rondo
next: >-
  BLOCKED on cameronsjo/cadence#783 — confirm whether Codex honours `if:`.
  That answer decides the whole build: if Codex ignores filters, this plan is
  right and one Bash call drops 61 processes to 5-6; if Codex honours them, the
  correct fix is instead reverting cadence#596's PreToolUse half (318/318
  duplicates, ~half a day, no release) plus the wrapper work in
  cadence-hooks#595. Do not start Task 1 before that is settled.
  Once unblocked: Task 1 (registry gains `matchers` as a LIST — seven checks are
  wired under two matchers for the same event), then Task 2.6 (thread-safe panic
  seam, cadence-hooks#593) which blocks all threading.
---

# Hook dispatch redesign — one process per (event × plugin × matcher)

**Tracking:** cadence-hooks#276 · **Decided:** 2026-08-04 · **Driver: Codex, not latency.**

## Why this exists

Claude Code and Codex both spawn **one process per matching hook object**. Cadence
currently wires **85 PreToolUse hook objects across 17 matcher entries**. The redesign
collapses dispatch to one binary invocation per `(event, plugin, matcher)` — 85 → 17 —
and absorbs the bash wrapper's policy layer into the binary.

**The justification is Codex.** Codex does not honour `if:` filters. The asset builder
emits them anyway — `hooks.codex.json` is a near-verbatim copy of `hooks.json`, with
only two transforms (SessionEnd timeout capped to 3, `run-hook.cmd` → `bash <cmd>`) —
so every filter cadence writes is inert on that harness.

| per `Bash` call | Claude (filters honoured) | Codex (filters inert) |
|---|---|---|
| today | ~5 processes | **61** — every Bash-wired object |
| after | 5 | **5–6** |

~55 spawns eliminated per Bash call on Codex, at a measured 15.1 ms floor each. That is
the same fork/exec pressure implicated in the cancel storms, except on Codex it is the
steady state rather than a tail case.

**The Claude-side latency argument is dropped.** It was measured and it does not hold —
see *Superseded claims*. Consolidation on Claude buys duplicate elimination and a lower
tail, not a mean win. Do not re-derive it.

**A second-order consequence, load-bearing for the design:** under Codex, checks
*already* receive payload shapes they were never routed to — 61 unfiltered objects on
every Bash call. So "consolidation would let checks see unrouted payloads" is not a new
hazard on that harness; it is the lived status quo, and the scope audit (Task 6) is
overdue independent of this work.

### Open confirmation — the one fact everything rests on

Codex's `if:` inertness is asserted from operator knowledge, not yet cited. It is now the
justification for the whole build. **Confirm before Task 3 lands** — either a Codex hooks
doc reference or an observed session — and record it in the compat report, because
`build-codex-assets.py` currently emits `if:` as though it works. If it turns out Codex
*does* honour `if:`, the Codex arithmetic above collapses and this plan reverts to the
parked state.

## The shape decision

**Keyed by `(plugin, matcher)`. Not `matcher: "*"`.**

Measured against live wiring — 85 hook objects → 17 entries:

| tool | today (objects) | today (spawns, Claude) | after |
|---|---|---|---|
| Bash | 61 | 5 | **5** |
| Edit | 17 | 17 | **6** |
| Write | 15 | 15 | **4** |
| Read / Grep / AskUserQuestion | 2 each | 2 | 2 |
| Task | 2 | 2 | **1** |
| CronCreate | 1 | 1 | 1 |

After ≤ today per tool type, always. `matcher: "*"` is rejected: it hands checks payload
shapes they were never routed to on *Claude* as well, and it is strictly broader than the
`Bash(*gh *)` that #596's security seat already refused for `redact-external-content`
(the hooks filter is that check's only subcommand boundary — a bare `gh` match would
route `gh secret set --body` into a scanner whose flag semantics assume posting).

Ceiling is **6**, not 5 — guardrails carries two Edit-matching matchers
(`Edit|Write|mcp__…` and `^Edit$|mcp__.*(delete|remove|move|rename).*`).

## Verified facts (round-2 red team, executed not reasoned)

- 85 objects / 17 entries; per-plugin objects guardrails 38, cadence 34, canon 8,
  metrics 2, rules 2, obsidian 1; entries 7/3/2/2/2/1.
- 322 redundant processes, per-check split matching exactly: warn-overshare 184,
  guard-rm 93, warn-alias-parsing 23, session:guard 11, redact-external-content 8,
  nudge-polish-before-pr 3.
- **`registry.plugin` has no `"canon"` value at all** — it takes six values (cadence 14,
  guardrails 28, metrics 9, obsidian 1, rules 4, **session 11**). `--plugin canon` would
  select **zero** checks. Canon's four checks carry `plugin: "session"`
  (`registry.rs:379-399`).
- **Six** plugins carry PreToolUse objects, not five.
- `deadline.rs`: `MIN_BUDGET_MS = 1000` (`:39`), `DEFAULT_BUDGET_MS = 3000` (`:34`),
  `DEADLINE_HIT`/`SUPPRESSED_BLOCK` process-global `AtomicBool`s (`:51-52`) with **no
  clear anywhere in the file**.
- `doctor` fails on **both** argument orders (executed; both exit 1).
- Shipped 0.72.1 exits 1 on `run pre-tool-use --plugin guardrails`.
- Production spawn floor is **15.1 ms** through `run-cadence-hooks.sh`, vs 2.2 ms bare.
  ~5 ms bash startup, ~8 ms wrapper subshells.
- Batches already execute **concurrently** — corpus sum/max ratio 6.96×.
- The pin/mtime divergence is live: `installed_plugins.json` pins `07292c4a110d-*`, this
  session's PATH carries `b8e203e5abc5-*`.

## Tasks

### Task 1 — registry gains a matcher; one name→check mapping

`HookEntry` (`registry.rs:9`) carries `name`, `description`, `plugin`, `event` — no tool
matcher. Add it; selection key becomes `(event, plugin, matcher)`. Extend
`registry_matches_clap_dispatch` to keep it in sync.

- **Pick and state the plugin key.** `registry.plugin` is the CLI namespace, not the
  wiring plugin. Canon wires under `session`, so `--plugin canon` selects zero. Choose
  one and encode it; the mismatch is silent in both directions.
- **Loggers are out of scope.** `registry.rs:16` documents `event: None` for
  fire-and-forget loggers (metrics 8, session 3); `None` never equals
  `Some(PreToolUse)`, so a naive batch selects zero and every metrics logger silently
  stops firing. Loggers implement `Logger`, not `Check`, via `run_logged_logger`
  (`dispatch.rs:350`). **Metrics and session logger wiring is untouched.** Note the
  consequence: metrics' 2 objects keep spawning individually on top of consolidated
  entries.
- Arg-carrying variants (`PlatformDrift{..}` at `main.rs:446`/`:960`, `LogCommit`,
  `LogSession`) cannot come from a name alone — encode the exclusion; the sync test
  demands totality. Prefer `&'static dyn Check` for the unit-struct bulk (~50 call sites
  pass references today) over `Box<dyn Check>`.
- **`Check` needs a `Sync` bound** (`lib.rs:1167` declares none). Compiles trivially
  today — every implementor is a unit struct — and is what makes Task 4's threading
  sound. State it so a future check holding a `RefCell` fails to compile rather than
  silently racing.

### Task 2 — factor the per-check body out of `run_logged_check`

Split into (a) stdin/normalize/Codex prologue, (b) a per-check body over a parsed
`&HookInput` + normalized targets. `run_logged_check` is `-> !` and `process::exit`s on
every path **including the panic arm** (`dispatch.rs:193-215`); the body must **return**,
with exits moved to the caller.

Return `Option<CheckResult>`: `decide_check` (`lib.rs:1370`) returns `None` for
effort-skipped checks, and collapsing that to `Allow` inflates every adherence
denominator — the failure `Aggregated`'s doc comment (`dispatch.rs:255-263`) exists to
prevent.

### Task 3 — absorb the wrapper's policy layer into the binary

The wrapper does four things: ADR-0008 fail-open when the binary is absent;
version-skew fail-open (#39 P0); harness detection (explicit `CADENCE_HARNESS` → Codex's
`PLUGIN_ROOT` contract → env sniffing); and the **Codex fail-closed inversion**, where
protected guards deny rather than fail open.

Move harness detection and the fail-open/fail-closed policy into Rust, where it is
unit-testable. Retain a **minimal wrapper** — `command -v` is a builtin and `exec`
replaces the shell, so no forks:

```bash
command -v cadence-hooks >/dev/null 2>&1 || { <harness-aware missing-binary policy>; }
exec cadence-hooks "$@"
```

~10 of the 13 ms recovered on **every** spawn, on both harnesses.

**The missing-binary decision cannot move into the binary** — nothing can ask a binary
that is not there. It stays in the wrapper, and it stays harness-aware: deleting the
wrapper outright would downgrade Codex protected guards from **deny** to **loud allow**,
a security regression on the stricter harness. Ruled: keep it, as deliberate policy.

Accepted: a missing binary now produces ~5 errors per tool call continuously rather than
silent allow. That is the intended posture — a silent fail-open is a dead control that
looks healthy. Note they land as `hook_non_blocking_error`, a channel already holding
967 rows, so "loud" is loud only to someone reading it.

### Task 4 — thread-safe panic seam and deadline scoping (BLOCKING, before any threading)

Batch checks run on **threads**, each keeping a full 3000 ms budget under one wall clock
— the only option reproducing today's semantics, since today's processes are already
concurrent (measured, 6.96× sum/max). The budget is never divided, so `MIN_BUDGET_MS` is
never crossed.

**The panic hook is main-thread-gated and voids this as written** (`main.rs:715-717`):

```rust
let on_main = MAIN_THREAD.get() == Some(&std::thread::current().id());
if !(on_main && PANIC_GUARDED.load(Ordering::Relaxed)) { process::exit(1); }
```

On any worker thread that takes `process::exit(1)` **before unwinding**, so
`catch_unwind` never regains control: one panicking check kills the process and every
sibling's verdict, including an already-computed Block. Exit 1 is fail-open. Found
independently by the security and red-team seats.

Required — and `main.rs`'s panic block appears in no prior task's file list:

- Replace `PANIC_GUARDED` + `MAIN_THREAD` with a **thread-local** "this thread has a
  `catch_unwind` waiting" flag, set by `PanicGuard::arm()`, cleared on `Drop`. Keep the
  exit-1 path for unflagged threads so `run_bounded_with`'s drain threads retain today's
  behaviour — relaxing to "any thread with the global set" would swallow a drain-thread
  panic and reintroduce #349.
- `PANIC_GUARDED`'s `Drop` stores `false` (`dispatch.rs:82,89`); concurrently, check A's
  drop clears it while check B is inside its region. `Relaxed` is documented as
  sufficient *because* store and load are same-thread.
- **Explicit stack size.** `std::thread` defaults to 2 MiB vs the macOS main thread's
  8 MiB. `loop_analysis.rs` feeds raw `tool_input.command` to brush-parser's recursive
  descent, so a worker cuts the nesting depth an attacker-controlled command needs by
  ~4×, and a stack overflow aborts the process uncatchably. Use
  `Builder::new().stack_size(8 * 1024 * 1024)`; state the size.
- **One thread per selected check, no pool.** Any bounded pool puts a wave-K check's full
  budget at wall-clock K × 3000 ms — 23 checks over 4 workers is up to 18 s against a 5 s
  external timeout, killed from outside and unloggably.
- **`arm()` first in every per-check body.** `deadline::state()` (`:97`) returns
  `Unarmed(total)` when `HOOK_START` is unset; a worker that forgets lands there silently
  and each git spawn gets a fresh 3000 ms with no aggregate bound.
- Make `DEADLINE_HIT`/`SUPPRESSED_BLOCK` per-check-scoped. Sticky globals otherwise make
  one timeout emit `deadline_block_suppressed` rows for every subsequent check — that
  signal means *an enforcement block was bypassed*, so multiplying and misattributing it
  destroys the channel that would reveal a budget regression.

### Task 5 — the batch subcommand

Prologue once, then every `registry::HOOKS` entry whose event, plugin, and matcher apply,
each on its own guarded thread.

- **Fork the aggregator; do not modify `aggregate_results`.** It harvests messages only
  from winning-outcome results (`dispatch.rs:309`) and takes `block_metadata` from the
  first winner (`:315`); changing it changes the single-check multi-target path and
  breaks the three unit tests at `:468-531`.
- **Collect join handles in declaration order and aggregate only after all joins** —
  never on completion order. Threads make completion nondeterministic while
  `block_metadata`, `winning_bypass`, joined-message order and stderr breadcrumbs are all
  observable. `bypasses.contains(&bypass)` (`:301-308`) becomes a cross-thread
  accumulation, so bypass row order is nondeterministic too.
- **Every joined message carries a `<hook-name>:` prefix.** Nothing in `CheckResult`
  carries the name; process separation supplied it implicitly. Decide, before coding:
  whether a Nudge may ride a Block (Block is exit 2, stderr-only, stdout ignored — a
  joined advisory reads as the refusal reason); where `LoopBlock+Nudge` and `Ask+Nudge`
  put `additionalContext`; and how a second blocking check's `rule_id`/`fix` survives
  `BlockMetadata`'s single slot (`rm .env` hits `guard-rm` **and**
  `prevent-secret-writes`).
- **Assign the batch exit code.** `dispatch.rs:193-215` exits 1 so Claude Code surfaces
  stderr on non-zero-non-2 and discards it on 0. A batch that must exit 2 for a Block has
  no stderr channel left. Name the channel that keeps a panic observable.
- **Port the per-process control surfaces**, all of which vanish silently otherwise:
  `CADENCE_DISABLE` and `PROTECTED_GUARDS` gate on `hook_name(&cli.command)`
  (`main.rs:812-828`), which returns `None` for a batch — **every disabled hook silently
  starts running again**. Re-evaluate per check. `codex_fail_closed` (`:333`) gates on
  `is_security_critical`: **fail closed iff the batch contains ≥1 security-critical
  check**, naming which could not be proved safe — a batch with no critical member must
  keep failing open or the plan gains coverage. Thread the per-check name into
  `log_denial`/`log_bypass` and scope bypass dedupe per check, or one
  `CADENCE_ALLOW_MAIN` ride by `enforce-worktree` and one by `warn-main-branch` collapse
  into a single row.
- **Timeouts collide.** cadence has 32 PreToolUse objects at `timeout: 5` and **two at
  10** (`markdown-lint`, `warn-docs-update`); `warn-docs-update` lands in the Bash batch
  with 23 five-second siblings. Choosing 5 halves its budget; choosing 10 invalidates
  `MAX_BUDGET_MS = 4500`, pinned to "the tightest 5s external timeout". Decide and own
  it; `hooks.json` timeouts appear in no file list today.

### Task 6 — the scope audit is the gate; the differential is the net under it

A differential running each check individually and batched **on the same fixture** is the
same computation twice and passes by construction. The real regression is **scope**.

**Scope audit, all 85 wirings, as a merge gate on the wiring PR.** One row per wiring,
explicit Allow / Block / panic-free verdict on the payload shapes it will newly receive.
Hunt checks that **block** or **panic** on an unseen shape (an unwrap on a field present
for `Bash` and absent for `Write`) — not merely ones that fail to self-gate.
`warn_overshare` does self-gate; the other 84 are unaudited.

Note the audit's pass criterion redefines coverage as **verdict**-equality rather than
**invocation**-equality. If that is intended, Requirements must say so.

Differential assertions beyond outcome equality: every blocking check's `rule_id`
recoverable from user-visible output; one bypass row per check per distinct mechanism;
**zero** deadline rows for checks that spawned no subprocess; every shape-conflicting
merge pair; a deeply-nested payload case **against the threaded batch**; a poisoned
`LazyLock`; and a panic **on a worker thread** asserting siblings still emit.

If the test spawns the binary, `cargo build --bin cadence-hooks` is mandatory — `cargo
test` does not build it and a pipe-probe exits 127, reading as uniform ALLOW. Run
`--no-fail-fast` (#591).

### Task 7 — `doctor` learns the batch shape, in the same binary PR

`extract_invocation` (`doctor.rs:147`) takes the first two non-flag tokens; both argument
orders yield unknown pairs and exit 1, failing `plugin-hooks-skew.yml`. Without this the
wiring PR cannot merge — discovered at CI time, after an irreversible release.

### Task 8 — release, upgrade both Macs, then rewire

Release per `cadence-hooks/CLAUDE.md`. `make report --check` cannot catch a wrong
`--workspace`.

**Deployment order is a safety constraint.** Wiring auto-updates at session start; the
binary moves only on `brew upgrade`. Consolidated wiring reaches the second Mac first,
guaranteed, and 0.72.1 exits 1 there — fail-open across **all 23 guardrails checks at
once**, as `hook_non_blocking_error`. Upgrade and verify `--version` on both Macs before
the wiring PR merges.

Then the wiring PR, plus: three tests in `hook_registration_audit.rs` go red
(`bash_hooks_have_if_filter` :764 — `INTENTIONAL_UNFILTERED_BASH_HOOKS` at :263 already
exists as the allowlist, 4 entries with rationales;
`all_binary_subcommands_are_registered` :627; `pending_wiring_hooks_are_still_unwired`
:705); `platform-baseline.json` `current_version` from `gh release view`, never
hand-typed; **codex assets only** (`hooks.codex.json`) — catalog/graph/`llms.txt` derive
from skills and are untouched. `docs/codex-compatibility-report.json` regenerates at
release, *before* the wiring lands, so it ships stale and `--check` cannot catch it —
budget a third PR.

Before trusting a local audit failure: `git -C <workspace>/cadence status -sb` — the
audit reads the sibling working tree and a `behind N` checkout produces false findings.

### Task 9 — verify

Read wiring from `installed_plugins.json`, never newest-mtime (the divergence is live).

Criteria: each selected check runs **exactly once** per batch (the in-process ledger —
"zero duplicate subcommands" is unmeasurable post-change and true by construction); max
batch size **≤ 6**; measured p99 batch wall-clock under a stated ceiling; **and the Codex
per-Bash-call process count**, which is the number this build exists for.

`hooks.jsonl` `ms` changes meaning — process wall-clock (including fork/exec and startup)
to in-process check time. Record batch wall-clock as a distinct field or state that the
1112–1115 ms baseline resets. "No cancellations" is unfalsifiable: 3 storms in 93 days is
a 96.8% base rate for a clean day.

## Accepted regressions

- **Isolation collapses.** ~35 OS failure domains become one per plugin. SIGKILL, OOM,
  abort, stack overflow, or the external timeout takes out a whole plugin's suite. Under
  single-exit a late crash **retroactively erases an early Block**, so ordering
  security-critical checks first does not help. The four cancel storms were *external
  timeout kills* — today one kill takes one check; after, all 29 guardrails checks. **The
  motivating incident becomes the worst regression.** Threading contains ordinary
  unwinding panics only once Task 4 lands; it never contains overflow or abort.
- **Shared `LazyLock` statics become a cross-check contamination channel** —
  `SECRET_VALUE_PATTERNS`, `shell::LOOP_PATTERN`, `terminology::BLOCK_PATTERNS`, five in
  `redact_external_content`. A poisoned lazy panics every later access.
- **Missing binary is now loud, not silent** (Task 3), continuously rather than once.

## Superseded claims — do not re-derive

- ~~"3.46 → 5.0 spawns/call, a mean regression."~~ Artifact of assuming `matcher: "*"`.
  Under the ruled shape, after ≤ today per tool type.
- ~~"~65 ms saved, ~4 ms cost, 16× net win."~~ Wrong three ways: measured the **bare
  binary** when production always pays the 15.1 ms wrapper (floor 6.8× too low); summed
  **serial** costs when duplicates already run concurrently (6.96× sum/max); and quoted
  the **p81** 6× multiplicity as typical (median firing call sees 1×, saving zero).
  Corrected net on Claude: **−6 to +21 ms/call, straddling zero.**
- ~~"#580 is ~1 ms."~~ A 1 ms delta between two different checks at 1 ms resolution — the
  measurement floor, not a measurement. Do #580 anyway; it is cheap.
- ~~Task 0's gate.~~ Answered a question the ruled shape does not pose. Retained in git
  history only.
- **Unresolved from red team:** production per-process median is ~300 ms, flat across
  checks doing 2 ms and 17 ms of isolated work — a dominant fixed overhead the isolated
  measurement does not capture, cause unattributed. Settling it needs a probe inside a
  live session. Treat as the cancel-storm hypothesis is treated: named, not assumed.

## Cheaper alternatives — deliberately not taken

- **Revert #596's PreToolUse half.** Recovers 318/318 duplicates on Claude for ~half a
  day, no release. **Does nothing for Codex**, which ignores `if:` — the whole driver.
  Ruled a baby step, not the goal. Keep as the fallback if the Codex premise fails.
- **Trim the wrapper's subshells only.** Absorbed into Task 3 as part of the redesign.
- **Upstream report** — the docs promise identical command hooks are deduplicated by
  command string and args; 206 byte-identical `warn-overshare` handlers say otherwise.
  **File it regardless**; if upstream honours the union the Claude-side duplication
  dissolves for free. Costs 30 minutes and gates nothing.
- **Resident daemon** (claude-configurations#373) — #276's own note says try this first.

## Panel record

Round 1: 4 of 5 seats delivered — security **BLOCK** (4 blocking), conflict (5 blocking),
underspec (9 defects), red-team (3 blockers). Round 2: 4 of 4 — security **BLOCK** on the
thread/panic seam, conflict found the two-shapes contradiction, red-team dismantled the
Task 0 measurement, owner recommended **PROCEED SMALLER** (overridden: the owner seat
computed Claude-only and had no visibility into the Codex driver).

**35 findings folded, 0 declined.** Two reclassified: #580 follow-up → prerequisite →
cheap-anyway; the owner's revert → fallback rather than replacement.

The panel's own bookkeeping failed three times, always toward false reassurance — plan
mode blocked the shared report dir, an in-turn poll loop could not receive replies, and
the orchestrator's scratchpad path diverged from the one it handed out. Filed
cameronsjo/cadence#780 with the fix that worked: **findings inline as the contract, file
as convenience, end the turn to receive.**
