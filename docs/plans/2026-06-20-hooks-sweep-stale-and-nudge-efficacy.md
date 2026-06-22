# Plan: cadence-hooks #155 (sweep_stale bug) + #151 (polish-nudge efficacy)

> Design/analysis record. #155 is implemented in this PR (TDD: RED test → wire
> heartbeat-sweep → green). #151 is a measurement methodology whose full run is
> a later deliverable (~2026-07-10..07-17); the Tier-1 grep is validated now.

## Context

Two open issues on `cameronsjo/claude-configurations` need a design pass, and they are
different *kinds* of work:

- **#155** is a real bug: `sweep_stale` reaped **0 of 17** stale session lanes in a shared
  checkout (2026-06-19). It needs root-causing (framed with `cadence-forge:using-systematic-debugging`),
  a fix, and the regression test that would have caught it.
- **#151** is an efficacy/measurement task, not a code change: verify that the 0.32→0.33
  polish-nudge reword actually reduced *rationalized* skips of `/polish` before `gh pr create`.
  It needs a measurement methodology — signal, before/after boundary, success threshold,
  observation window.

---

## Part 1 — #155: `sweep_stale` reaps nothing

### Systematic-debugging Phase 1: evidence (what the code actually does)

All line refs are `crates/session/`.

The registry models session liveness as **file mtime** of each `<name>.<short-id>.json` in
`<repo>/.claude/sessions/`. The heartbeat (PostToolUse) rewrites the file → refreshes mtime.

Two predicates that #155 suspects of disagreeing are in fact **identical**:

| Path | Threshold | Age source | Decision |
|---|---|---|---|
| `session status` → `read_peers` (`registry.rs`, `cli.rs`) | `stale_minutes()*60` (default **30 min**) | `mtime_age_secs` | `idle_secs > stale_secs` → `[STALE]` |
| `sweep_stale` (`registry.rs`) | `stale_minutes()*60` (default **30 min**) | `mtime_age_secs` (same fn) | `age > stale_secs` → `remove_file` |

Same threshold function, same mtime helper. **At a single instant the classifier and the
reaper cannot disagree on a given file.** So #155's "classification and reaping are out of
step" is not a predicate mismatch — it is a *timing/trigger* gap.

**The decisive evidence — sweep has exactly one production trigger.** `git grep` for
`sweep_stale` callers (verified on origin/main, 2026-06-21):

- `crates/session/src/start.rs` — `run_start`, the **SessionStart** hook. *(only production caller)*
- `crates/lab/src/nudge.rs` — an unrelated namesake (lab nudge), not the session reaper.
- `crates/session/src/backstop.rs` / `end.rs` — only *mention* it in comments; the SessionEnd
  backstop (#108) deliberately defers to "the next `session start` sweeps it by age".
- tests only otherwise.

Every other write/refresh path **never sweeps**:

- `run_heartbeat` (PostToolUse, `heartbeat.rs`) — `touch_own` only, the high-frequency path.
- `run_declare` / `run_status` (CLI, `cli.rs`) — write/read only.
- `Guard` (PreToolUse, `guard.rs`) — `live_peers` read only.

cadence-canon `hooks/hooks.json` confirms the wiring: `session start`→SessionStart,
`session guard`→PreToolUse, `session heartbeat`→PostToolUse — **only start sweeps.**

### First hypothesis (the one to verify) — name the failing predicate

> **`sweep_stale` is invoked from exactly one event — SessionStart — and observes a single
> instant. The failing "predicate" is the sweep's *trigger set*, not its staleness
> comparison: the only high-frequency, always-firing signal every live session emits (the
> heartbeat) never calls the reaper.**

Why this produces "0 of 17" in a shared, long-lived checkout:

- A lane is reaped only if a *new* SessionStart happens while that lane is already past 30 min.
- The dominant session is long-lived; it swept once at its own start (days ago). Lanes that go
  stale *after* that start have no later start to reap them.
- Forks/subagents (the doc-orphan scan that filed #155 was a fork) **do not fire the
  cadence-canon SessionStart**, so they register/observe but never sweep.
- Result: dead lanes accumulate; `session status` keeps *classifying* them `[STALE]` (on
  demand, any time) while nothing *reaps* them (only at start). The 17 stale `.json` files and
  the corroborating 17-day-old `.claude/intros/` are the same "dead state never reclaimed".

### Hypotheses ruled out by reading (record them so they aren't re-chased)

- **Wrong timestamp (created vs last-active).** `sweep_stale` uses `mtime` (last-active /
  last heartbeat), not `started_epoch`. Correct direction. Disproved.
- **Predicate divergence (display vs reap).** Same `stale_minutes()` and same `mtime_age_secs`.
  Disproved.
- **Own-suffix over-exclusion.** `short_id` = first **8** chars of a UUID; full `session_id` is
  verified (`matches_own`, #90), so no realistic collision masks a peer. Disproved.
- **Write access.** `.claude/sessions/` is inside the repo and user-owned; `remove_file`
  succeeds in normal use. (TCC-over-SSH only blocks *enumeration* of `~/Documents`-class dirs,
  not an in-repo path.) Not the cause; note as a secondary check only.

### Phase 3/4: the fix — give the reaper a high-frequency trigger

Wire `sweep_stale` into **`run_heartbeat`** (PostToolUse), preserving start.rs's safe ordering:

1. `touch_own` first (writes/refreshes *self*, mtime ≈ now) — so a quiet session can never
   sweep its own aged file (#69 protection).
2. then `registry::sweep_stale(dir, stale_minutes()*60, session_id)` — own sid excluded as
   defense-in-depth (it was just refreshed anyway).

Effect: any live, active session prunes dead peers within ~one heartbeat after they cross the
30-min threshold — the sweep no longer depends on a fresh SessionStart that may never come.

**Files:** `crates/session/src/heartbeat.rs` (`run_heartbeat` core + the `Logger::run`
wrapper computes `stale_minutes()*60`; thread `stale_secs` into the testable core, mirroring
`run_start`'s injected `stale_secs`). No change to `sweep_stale` itself — it already works
(`sweep_removes_stale_keeps_fresh` passes); the gap was always wiring.

**Known trade-off to state in the fix (not over-engineer):** mtime liveness cannot distinguish
"dead" from "alive but quiet > 30 min". A quiet-but-alive peer swept mid-think rebuilds a
minimal record on its next heartbeat, losing declared `intent`/`touching` (the #69 hazard, but
for a peer). This risk already exists at start-sweep; heartbeat-sweep only makes the existing
30-min policy fire more often. The 30-min threshold is the agreed cushion; no new false-reap
*class* is introduced. (Alternative triggers — guard/PreToolUse, or CLI status/declare — are
weaker: CLI doesn't fire unattended; guard is a `Check`, less clean for a side effect.)

### The regression test that would have caught it

A unit test of `sweep_stale` alone never could — `sweep_removes_stale_keeps_fresh` already
passes. The gap is *wiring*, so the test must assert the **trigger**:
`heartbeat_sweeps_stale_peer_keeps_self_and_live` writes an aged peer + a fresh peer, fires
`run_heartbeat(..., stale_secs=0)`, and asserts the stale peer is reaped while the fresh peer
and self survive. Written RED first (`cadence-forge:using-test-driven-development`): it fails on
current code (heartbeat never sweeps) and passes after wiring.

---

## Part 2 — #151: measure the polish-nudge efficacy

### Verified chronology (the before/after boundary)

Issue body says "0.32.0 → 0.33.0"; ground truth from `git log --all`:

- **v0.32.0** — `72b99fa` (2026-06-19 **19:50** CDT): closed the "just markdown" and
  "already TDD'd/attuned/reviewed" rationalizations (clauses `behavior, not documentation`
  + `they don't replace it`; **two** pinning tests).
- **v0.33.0** — `5455196` (2026-06-19 **20:24** CDT): added the **"don't skip silently"**
  stated-reason mandate — the noisy-exit clause this issue centers on.

→ **Authoritative "after" boundary: 2026-06-19 ~20:24 CDT.** Anything before ~19:50 CDT is
clean "before"; the 34-min gap between commits is negligible against a 3–4 week window.

### What a "rationalized skip" is (the signal definition)

The nudge fires on `gh pr create` (`nudge_polish_before_pr.rs`). A skip event = a session
that ran `gh pr create` on a branch that is **not** a trivial one-liner and **not** already
polished, where `/polish` (or `/polish docs`) did **not** run on that branch first. Classify
each skip:

- **Silent** — no stated reason (violates the 0.33.0 mandate → mandate not landing).
- **Legitimate** — stated reason is genuinely "trivial one-liner" or "already polished". OK.
- **Rationalized** — stated reason is a *closed* loophole: "just markdown / docs", or
  "already TDD'd / attuned / reviewed / planned". This is the failure the reword targets.

### Where the signal lives — transcripts, not metrics JSONL

The judgment ("was a reason stated? which kind?") is **Claude's prose**, which aggregate
cadence-metrics event logs do not carry. The rich source is the **per-session transcript**
(`~/.claude/projects/<project-slug>/*.jsonl`):

- Bash `tool_use` with the full command string → detect `gh pr create` (the denominator) and
  any preceding `/polish` run.
- `Skill` `tool_use` → detect `cadence-forge:polish` / `/polish docs` invocations.
- assistant text → the stated reason / rationalization (the qualitative judgment).

**Corpus (decided): whole ecosystem, this Mac** — all `~/.claude/projects/*/*.jsonl` on the M3
Air, across every cadence repo, indexed via `commits.jsonl`. Transcripts are per-project AND
per-machine; extending to the M5 Pro is a later option if this Mac's history proves too thin.

**cadence-metrics JSONL is insufficient — but `commits.jsonl` is a useful index:**

- The only two logs are `commits.jsonl` and `subagents.jsonl` (in `${CLAUDE_CONFIG_DIR}/metrics/`).
  **Neither records** a command string, tool name, skill invocation, `gh pr create`, or any
  nudge-firing event — so the rationalized-skip signal is *not* directly queryable from metrics.
- But every `commits.jsonl` record carries `ts`, `sessionId`, `branch`, `repo`, and crucially
  **`transcriptPath`**. That makes `commits.jsonl` a cheap **corpus index**: enumerate
  PR-bearing sessions and their transcript files, bucket by `ts` around the boundary, then read
  only those transcripts — instead of blind-globbing every `*.jsonl`.

### Measurement design — two tiers

**Tier 1 (deterministic, cheap): the skip RATE.** Use `commits.jsonl` as the index to
enumerate candidate sessions, bucket them by `ts` into before (`< 2026-06-19 20:24 CDT`) and
after, then read only the indexed transcripts. For each session containing a `gh pr create`:
denominator = PR-creating sessions; numerator = those with **no** preceding `/polish` Skill run
on that branch. `skip_rate = numerator / denominator`, before vs after.

**Tier 2 (LLM-judge over transcripts): the rationalization mix.** For each Tier-1 skip case,
an Opus judge reads the turns around `gh pr create` and classifies: silent / legitimate /
rationalized (and which closed loophole). Batch through a small judge fan-out (a few agents each
handling several cases sequentially, to dodge the ~3–4 concurrent rate limit).

**Bonus signal:** count behavioral-markdown branches (skill/agent/command/rule/CLAUDE.md edits)
that got a *real* `/polish` after the boundary where before they'd be skipped — direct evidence
the "behavior, not documentation" clause landed.

### Success threshold

The reword works if, in the after window:
- **Silent skips → ~0** (the 0.33.0 mandate lands — every skip states a reason), AND
- **Rationalized skips (closed loopholes) → 0, or a clear drop vs before**.
- Legitimate skips (trivial / already-polished) are expected and fine — not failures.

If rationalizations persist → next lever is escalating the nudge register (earned emphasis, per
`writing-skills`) or moving enforcement upstream — a separate REFACTOR round, not this measurement.

### Observation window

Source intro `2026-06-19-2054-polish-nudge-noisy-exit.md` says revisit in **~3–4 weeks**.
From the 2026-06-19 boundary → **revisit window ≈ 2026-07-10 to 2026-07-17**. Sample size may
be small; if so the measurement is qualitative (read every skip case), not statistical — state
the N, never imply coverage you don't have.

### New-instrumentation design line (decided: include as a follow-up PR)

Today there is **no** nudge-firing event and **no** tool-invocation event, so a clean forward
rate is impossible without new telemetry. If that rate is wanted, add deterministic hook-layer
events (its own small PR, separate from this measurement):
- emit a metrics event when `nudge-polish-before-pr` fires (session id, branch, repo, ts) — the
  denominator (every PR that got nudged);
- emit an event when `cadence-forge:polish` runs (session id, branch) — to subtract polished
  branches.

"Nudge fired but no polish on that session/branch" = a deterministic skip candidate. This still
cannot judge *rationalized vs legitimate* (that stays prose/transcript), but it gives an
objective skip-rate going forward and a clean denominator that transcript-grep approximates.

---

## Verification (for the implementation sessions that follow this design)

- **#155:** add the RED `heartbeat_sweeps_stale_peer_*` test → confirm it fails on current
  `main` (heartbeat doesn't sweep) → wire sweep into `run_heartbeat` → `make ci` green →
  manual check: in a tempdir/`session status` with N aged lanes, a heartbeat reaps them.
- **#151:** dry-run the Tier-1 grep over this project's transcripts to confirm it correctly
  identifies `gh pr create` sessions and preceding `/polish` runs before scaling to the full
  this-Mac ecosystem corpus.

## Resolved decisions

- **#155 fix trigger** — heartbeat-sweep (firm recommendation; alternatives weaker).
- **#151 scope** — retrospective transcript analysis (run ~2026-07-10..07-17) **+** a separated
  instrumentation design line as a follow-up PR.
- **#151 corpus** — whole ecosystem, this Mac (M3 Air), indexed via `commits.jsonl`.

## Sequencing note

These are two independent issues; do them as two PRs. #155 is a code change (TDD: RED test →
wire heartbeat-sweep → green); #151 is an analysis deliverable whose optional instrumentation
line, if pursued, is a third small PR. Per repo convention, hold the `Cargo.toml` version bump
until ready to release so each merge doesn't auto-tag.
