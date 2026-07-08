# Conversational How/Why Capture — implementation plan

> **Plan PR (draft).** Ships as `docs/plans/2026-07-08-conversational-howwhy-capture.md` on `cameronsjo/cadence-hooks`. This document is the whole contract — a fresh implementer session executes it with zero prior context.
> **Refs (never `Closes` — this is a plan, not the fix):** findings UU-6, UU-8, UU-10, UU-11 of the methodology-coverage blind-spot pass, `docs/audits/2026-07-08-methodology-coverage-blind-spot-pass.md` on `cameronsjo/claude-configurations` (private meta-repo). No GitHub issues exist for these findings by design — this plan PR *is* the actionable artifact.
> **Implementer note:** Two repos, both cloned locally. Binary = `/Users/cameronsjo/Projects/claude-configurations/cadence-hooks` (`cameronsjo/cadence-hooks`, Rust; released **v0.52.0** as of 2026-07-08 — note the local checkout was observed 13 commits behind origin/main at planning time; `git fetch` + plan against `origin/main`, not the stale tree). Plugins = `/Users/cameronsjo/Projects/claude-configurations/cadence` (`cameronsjo/cadence` monorepo; metrics plugin at `plugins/cadence-metrics/`, core skills at `plugins/cadence/skills/`, agents at `plugins/cadence/agents/` — agent file locations are a **claim-to-verify**, confirm with `ls` before editing). Read `crates/metrics/src/log_plan_phase.rs` (the event-widening precedent), `log_skill.rs` on origin/main (the schemaVersion + privacy precedent), and `log_bypass.rs` (the reason-carrying precedent) before touching anything.
> **Planned 2026-07-08.**

## Context

The blind-spot pass verdict on the core thesis (*git tracks who/what/when/where; cadence captures how/why*): it **holds at the artifact tier** (ADRs, TUNING-FORK, commit messages, field reports, capture manifests, drills, memory) and **leaks at the conversational tier** — the user's answers, the reviewer's dismissals, the router's declines, the human's overrides. This cluster plugs the conversational-tier leaks that have a mechanical capture point.

**This cluster is the evidence layer; the local session store is its consumer, not a rejected alternative.** The in-flight local session-store project ingests raw transcripts for archaeology; these four findings need *structured* rows first — a Q→A ledger is queryable (`jq` over a stream) in a way a transcript grep is not, and a dismissal that lands in a PR review comment is visible to the *next reviewer*, which a dead transcript never is. This plan produces those structured source rows; the session store's ingest makes them queryable downstream. Framing corrected at Step-0 gate (Cameron, 2026-07-08) — the original draft cast the store as an alternative that failed to satisfy these asks, which had the relationship backwards.

**Ingest read-path verified live (2026-07-08).** A read-only query against the local session store's Postgres table confirmed it actively tails `askuserquestion.jsonl` and `bypasses.jsonl` on its regular sync cycle, keyed by stream — row counts matched disk to within one sync-cycle's lag (its own sync agent last exited 0). The evidence-layer claim above is proven against live state, not aspirational.

**Verified shipped state (probed 2026-07-08 against origin/main):**

- `askuserquestion.jsonl` — written by `LogAskUserQuestion` (`crates/metrics/src/log_askuserquestion.rs`), wired **PreToolUse:AskUserQuestion** only. Records stance/shape (`stance`, `multiSelect`, `nQuestions`, `nOptions`, `sessionId`, `model`). Fires *before the user answers*; the chosen option, "Other" free-text, and annotation notes are persisted nowhere. No `schemaVersion` field (implicit v0).
- `skills.jsonl` — **UU-8's invocation half already shipped**: `log-skill` subcommand + `LogSkill` logger landed as cadence-hooks#258 (Refs #215), released **v0.52.0**; the `PostToolUse:Skill` matcher is live in `plugins/cadence-metrics/hooks/hooks.json`. Records skill id in clear, `argsHash` (privacy D5), `repo`, `schemaVersion`.
- `bypasses.jsonl` — `log_bypass.rs` already records guard bypasses **armed** (a `dismiss-*` snooze set, with a **user-authored `reason`**) and **used** (a write riding through), privacy-by-construction. The override ledger UU-11 asks for substantially exists; the gaps are narrower than the finding assumed (see table).
- `denials.jsonl` — `log_denial.rs` records `(hook, tool, repo, session, ts, decision)` per deny. No synthetic denial-id; a `(session, hook, ts-window)` join to a subsequent bypass row is already expressible without one.

## Findings covered — disposition and repo

| Finding | Short name | Repo that owns the fix | Disposition in this plan |
|---|---|---|---|
| **UU-6** | AskUserQuestion answers die with the transcript | **cadence-hooks** (rework logger) + **cadence** (additive wiring) | The one real binary change in this cluster. Widen `log-ask-user-question` to also accept `PostToolUse` and record the answer row. Release-gated wiring companion. Carries **Decision D1** (answer-text privacy). |
| **UU-8** | Skill-invocation compliance + declines unobserved | **cadence-hooks** (done) / **cadence** (prose) / meta-repo (out of scope) | Invocation half **already shipped** (#258, v0.52.0) — task here = verify + document closure in the audit's terms. Decline half: no hook event exists for a non-invocation → prose convention only (fixed decline grammar). Expected-floor *reader* lives with the session-mart in `claude-configurations` — **out of this two-repo cluster's scope**, noted for the meta-repo. |
| **UU-10** | Subagent dismissal rationale discarded | **cadence** (agent + skill prose) | Zero binary. Output-contract addition to reviewer-class agents; polish/review skills carry the block into the PR-visible artifact. |
| **UU-11** | Guard overrides have no ledger | **cadence-hooks** (docs) + **cadence** (prose routing) | Mostly **already built** (`bypasses.jsonl` + `reason`). Tasks: document it as the override ledger; route methodology toward `dismiss-*` (which records a why) over `!`-prefix (which is invisible to hooks — a platform boundary, not a fixable gap); one-line schema.md note on the denial→bypass join. Nothing net-new in the binary. |

## Reuse ledger (use / abuse / reuse / rework)

Systems-thinking constraint honored: **no new streams, no new subcommands, one new matcher.**

| Change | Mode | Existing mechanism |
|---|---|---|
| UU-6 answer rows | **Rework** | `log_plan_phase.rs`'s event-widening precedent (one subcommand accepting multiple `hook_event_name`s) applied to `log_askuserquestion.rs`; same stream (`askuserquestion.jsonl`), same subcommand — a `phase: "asked"\|"answered"` discriminator, no new stream |
| UU-6 schemaVersion adoption | **Reuse** | #238's centralized schemaVersion policy (`common.rs` constants — exact naming is a claim-to-verify against origin/main); stamping the widened stream explicit-v1 mirrors `log_skill.rs` |
| UU-6 wiring | **Reuse** | Existing `run-cadence-hooks.sh metrics log-ask-user-question` command string, added under a `PostToolUse` matcher — identical shape to the existing PreToolUse entry |
| UU-8 invocation telemetry | **Already shipped** | `skills.jsonl` (#258) — consume, don't build |
| UU-8 decline grammar | **Use** | using-cadence already *mandates* announcing declines; the change only fixes the sentence shape ("Declined `<skill>`: `<why>`") so chronicle/transcript greps and a future harvest can parse it — zero new mechanism |
| UU-10 dismissal blocks | **Rework** | Reviewer agents already return structured Critical/Important/Nit findings; the contract grows a "Dismissed (n): reason each" section — same artifact, one more section. Carried into PR reviews by the existing polish/review-loop path |
| UU-11 override ledger | **Use/abuse** | `bypasses.jsonl` — "abuse" in the best sense: it was built as a bypass audit; we *declare* it the override ledger and route practice through `dismiss-*` so the `reason` field gets exercised. The NL-lens "write-only stream" note resolves the moment the session-mart reads it (meta-repo, out of scope here) |
| UU-11 denial→override linkage | **Use** | `(session, hook, ts)` join across `denials.jsonl` × `bypasses.jsonl` — document the join; no synthetic id needed |

Net-new justification ledger: the single net-new surface is **one `PostToolUse: AskUserQuestion` matcher block** in `hooks.json` — unavoidable, because answers only exist post-tool-use and nothing else fires there.

## Approach

### The repo split (explicit)

**Binary-side (cadence-hooks, Rust — `crates/metrics/` + docs):**

1. **UU-6 rework of `log_askuserquestion.rs`:**
   - Accept `hook_event_name ∈ {PreToolUse, PostToolUse}` (drop the implicit pre-only assumption; keep the questions-guard for the pre path).
   - Pre path: unchanged record + `"phase": "asked"` + `schemaVersion`.
   - Post path: build an `"answered"` record from `tool_response` — **claim-to-verify:** the exact PostToolUse payload shape for AskUserQuestion (which key carries the selected answers/notes — probe with `CADENCE_METRICS_DEBUG=1` + a scratch `_keys` dump, the #221-probe pattern from the C8 plan, before coding the extractor).
   - Record per answered question: question `header`, selected option label(s), whether the selection was the recommended option (reuses the `stance` classifier's recommended-detection), and — gated on **D1** — "Other"/annotation free-text.
   - Tests mirror `log_plan_phase.rs`'s dual-event tests.
2. **UU-11 docs:** `plugins/cadence-metrics/docs/schema.md` (travels with the plugin repo — see plugin side) gains the "bypasses.jsonl is the override ledger" section + the denials×bypasses join example. Binary-side task is only to confirm field names against `log_bypass.rs` while writing it.
3. **UU-8 closure verification:** read-only — confirm `skills.jsonl` rows appear on current release (one `Skill` invocation, `tail -1 ~/.claude/metrics/skills.jsonl`), then record closure in the PR description. No code.

**Plugin-side (cadence, markdown/JSON — `plugins/cadence-metrics/`, `plugins/cadence/`):**

4. **UU-6 wiring (release-gated):** additive `PostToolUse` `AskUserQuestion` matcher in `plugins/cadence-metrics/hooks/hooks.json`, pointing at the *existing* `metrics log-ask-user-question`.
5. **UU-6/UU-11 schema docs:** `plugins/cadence-metrics/docs/schema.md` — widened askuserquestion stream (v1, `phase` discriminator), override-ledger section per (2).
6. **UU-8 decline grammar:** one-sentence change in `plugins/cadence/skills/using-cadence/SKILL.md`'s decline-announcement rule: fixed grammar "Declined `<skill>`: `<one-line why>`". (Behavioral skill edit → check whether the drilling gate (ADR-0032) applies; a single-sentence grammar constraint is arguably below the drill threshold — flag at PR review rather than pre-drilling.)
7. **UU-10 output contracts:** add a "Dismissed findings" section requirement to `plugins/cadence/agents/code-reviewer.md` and `plugins/cadence/agents/plan-reviewer.md` (+ `plugins/cadence-forge/agents/security-reviewer.md` — path is a claim-to-verify), and one line in `cadence-forge:polish` / `cadence-forge:review-loop` skills carrying the block into the PR review comment.
8. **UU-11 prose routing:** in the guardrails/whoami-adjacent prose (`plugins/cadence/skills/whoami/SKILL.md` or `plugins/cadence-guardrails/README.md` — implementer picks the surface that documents overrides today, claim-to-verify), state the preference: a deliberate step-around of a *correct* block goes through `cadence-hooks dismiss-*` (recorded, reasoned) rather than `!`-prefix (invisible); `!`-prefix remains for classifier-blocked grants per the background-mode rules.

### The two-repo release-gate (must be obeyed)

- **UU-6 introduces NO new subcommand** — the `hooks.json` companion adds a `PostToolUse` matcher pointing at the existing `metrics log-ask-user-question`, so **doctor CI will not trip** (it keys on subcommand names). But the companion is **behaviorally release-gated**: the un-widened binary's pre-only guard makes a `PostToolUse` payload no-op (fails open, inert) until the release that accepts the new event. → Land + release the binary widening **first**, then merge the wiring PR — for correctness, not CI.
- Tasks 5–8 are markdown-only → no doctor involvement, mergeable any time.
- Removal companions merge free (doctor flags unknown names, never absences) — irrelevant here but stated per the C-series convention.

## Decision D1 (Cameron, at plan review) — answer-text privacy

The metrics doctrine is privacy-by-construction (denials/bypasses never log content; `log_skill` hashes args). UU-6's *entire value* is the user's why — the selected label, and especially "Other" free-text and notes. Options:

- **D1-a (recommended):** log selected option labels verbatim (Claude-authored, bounded, low-sensitivity) **and** "Other"/notes free-text — this is the irreplaceable user intent the thesis says to keep; the stream lives in `~/.claude/metrics/`, same trust domain as the transcript itself.
- **D1-b:** labels verbatim, free-text behind `CADENCE_LOG_ANSWER_TEXT=1` (default off) — consistent doctrine, but defaults the thesis-critical field to the floor.
- **D1-c:** labels only — safest, loses the "Other" why entirely.

The plan proceeds with D1-a unless overridden at review.

## Task breakdown

| # | Task | Repo | Dispatch |
|---|---|---|---|
| 1 | Payload probe: capture a real `PostToolUse:AskUserQuestion` payload (`_keys` + answer shape), attach to PR | cadence-hooks | Sonnet implementer, worktree |
| 2 | Rework `log_askuserquestion.rs` (dual-event, `phase`, schemaVersion, answer record per D1) + tests + CHANGELOG bullet under `[Unreleased]` | cadence-hooks | Sonnet implementer (same worktree as 1) |
| 3 | Verify UU-8 closure (skills.jsonl live row) + document in PR body | cadence-hooks | fold into task 2's session, read-only |
| 4 | Release: `make bump` in a worktree per repo CLAUDE.md (single release; check for parallel-session bumps first) | cadence-hooks | orchestrator |
| 5 | Wiring PR: PostToolUse matcher + schema.md (widened stream v1 + override-ledger section + join example) | cadence | Sonnet implementer, **after** task-4 release |
| 6 | Decline grammar sentence in using-cadence | cadence | fold into task 5 |
| 7 | Reviewer-agent "Dismissed findings" contracts + polish/review-loop carry-through | cadence | Sonnet implementer (may parallel task 5; different files) |
| 8 | Override prose routing (dismiss-over-!-prefix) | cadence | fold into task 7 |

## Verification

- `make ci` green on cadence-hooks; new dual-event tests pass.
- End-to-end: with the released binary + merged wiring, answer a live AskUserQuestion and `tail -2 ~/.claude/metrics/askuserquestion.jsonl` — an `asked` row and an `answered` row with matching session, the answered row carrying the selected label (and free-text per D1). This exercises the real flow, not a fixture.
- Doctor: `cadence-hooks doctor --root plugins/cadence-metrics` (from the cadence checkout) reports no skew after both merges.
- UU-10: run one `cadence:code-reviewer` on a real diff; its report contains a "Dismissed" section (empty is fine — present is the contract).
- Negative control: a `PostToolUse` payload against the *pre-widening* binary no-ops silently (fail-open proof, one `try --payload` run).

## Orchestrator

**Sonnet-drivable** once D1 is resolved at plan approval — every task is spec'd, the one probe (task 1) has a written procedure, and the release-gate sequencing is explicit. Named Opus trigger: if the task-1 payload probe reveals AskUserQuestion answers do **not** surface in `PostToolUse` `tool_response` (platform premise failure), stop and replan — that's the deferred-decision/replan trigger, same class as the C8 plan's #221 gate.
