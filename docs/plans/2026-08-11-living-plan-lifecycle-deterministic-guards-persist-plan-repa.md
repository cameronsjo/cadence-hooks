---
status: "in-flight"
updated: "2026-08-11"
branch: "plan/living-plan-lifecycle-guards"
pr: "cameronsjo/cadence-hooks#671"
next: "Task 1: instrument run_persist_plan early-returns against session beffcf50; work payload sample owed from Cameron"
body_sha256: "3aac1eaabc19ef8667c4573ab3da2f6e3cb4f732253df6877b2ef1ee125a9c1d"
session: "frost-anchor"
session_id: "1322f0d3-8e45-49be-b07c-217268925560"
model: "claude-fable-5"
harness: "claude-code 2.1.227"
machine: "cf6e768835c7"
approved_in: "frost-anchor"
approved_session_id: "1322f0d3-8e45-49be-b07c-217268925560"
---

# Living-plan lifecycle: deterministic guards + persist-plan repair

Panel: 2 seats ran — 27 findings, 24 folded in, 3 declined

## Context

Cameron's work session confirmed the living-plan lifecycle (ADR-0038) fails in practice: plans aren't being created, stored, or updated, so a session parking for days has no durable re-grounding artifact. Root causes as understood at approval, amended loudly by the panel (see Deviations — items 1–2 were refuted and replaced by the sharper defect below):

1. **The UserPromptSubmit persist arm fails at an unidentified early-return** *(panel-corrected; supersedes the approved defects 1–2)*. The legacy prefix `Implement the following plan:` still matches — four real approve-and-clear sessions in the last three days opened with it verbatim (`beffcf50`, `704b5087`, `7895ce32`, `d7cca765`) — yet none persisted: `~/.claude/metrics/plan-links.jsonl` has 12 rows ever, none from those sessions. The approval arm (`persist-plan-approval`) works on this machine (it persisted this very document; approval `tool_response` still carries `plan`, and `tool_input` now also carries `plan` + `planFilePath`). The real defect is one of `run_persist_plan`'s silent early-returns, to be named by Task 1's instrumentation. Rejection correctly no-ops (bare error-string result, verified).
2. **The work machine's failure is separately uncharacterized** — payload sample owed (Cameron relay); its cadence-hooks install state unknown.
3. **The mid-execution guard never existed.** Execution-zone updates (tick, `next:`, `updated:`) are 100% prose (cadence-rules § Plan Execution, outro/handoff skills). The one filed deterministic backstop — [cadence-hooks#429](https://github.com/cameronsjo/cadence-hooks/issues/429) ready-flip guard — is open, unbuilt, and carries a "wait for the trial" gate that Cameron's ruling now supersedes (record as an issue comment). Nothing was removed; prose was the whole mechanism.
4. **Attune's "already attuned" exemption swallows persistence** (work Claude's report): a session with an approved plan in context marks attune `exempt` and skips the persist step entirely.
5. **Plans don't follow the template and don't get ticked.** The harness's plan-mode workflow imposes its own body shape (Context/Changes/Verification), displacing cadence's template (Panel stanza, Alternatives declined, checkbox tasks) — and nothing lints the persisted doc beyond the Panel-line nudge (#624). Ticking has no mechanism at all (defect 3).
6. **Plugin-shipped rules never load — and `cadence-rules.md` specifically has no working install path.** Work Claude's [cadence#942](https://github.com/cameronsjo/cadence/issues/942) pins it: the `cadence-rules:init-*` skills installed 24 workbench files correctly, but the core plugin's own `cadence-rules.md` has exactly one installer (`cadence-groundwork:initializing-cadence`), which sits in no preflight path and never ran. Absent from all three candidate homes, with zero signal — "the MUST was never loadable." The durable fix is doctrine carried by hooks plus absence detection.
7. **The persistence obligation is addressed only to the planner's seat** (#942 seam 3): a session *executing* a plan approved elsewhere — handed over as initial-prompt text — never calls `ExitPlanMode`, so neither trigger fires and no rule speaks to it. The work session shipped 8 commits, a merged PR, and an ADR with no plan file.

Ruling from Cameron: build all the guards; prose isn't enough.

## Tasks

### Task 1 — Probe first (evidence before code)

- [ ] **Instrument the UPS-arm failure** (panel-rescoped): trace every early-return in `run_persist_plan` (prompt/prefix, empty body, cwd, repo_root, unsafe session_id, `canonical_plans_dir`) and `claim_target`'s give-up path against session `beffcf50`'s recorded prompt — name the specific return that ate four real persists before Task 2 writes any code
- [x] Local approval-path probe: approval `tool_response` carries `plan`; `tool_input` carries `plan` + `planFilePath`; rejection = bare error string (this session's transcript, claude-code 2.1.227 / hooks 0.75.1)
- [ ] Work payload sample: Cameron relays work Claude's `ExitPlanMode` transcript line + `cadence-hooks --version` at work
- [ ] Record the evidence on a new cadence-hooks issue (platform-moved-under-the-hook; sibling of #396's probe); comment on #429 that Cameron's 2026-08-11 ruling supersedes its wait-for-the-trial gate

### Task 2 — Repair the persist-plan triggers (cadence-hooks)

`crates/session/src/persist_plan.rs` (re-resolve all line cites against `origin/main` first — the plan's cites came from a checkout 26 commits behind):

- [ ] Fix the Task-1-named early-return in the UserPromptSubmit arm
- [ ] Robustness on the approval arm: source the plan from `tool_response.plan` → `tool_input.plan` → plan-store `planFilePath` read, first present wins; keep the rejection no-op and the subagent gate
- [ ] Cross-trigger idempotency: both arms must normalize to a byte-identical body before hashing (`body_sha256`), and the approval arm wins on same-session double-fire — state it in tests, not just here
- [ ] Tests: all payload shapes, rejection, double-fire skip, the named early-return's regression case

### Task 3 — The four guards (cadence-hooks, advisory tier — all four in scope)

- [ ] **Guard 1 — uncommitted-plan nudge** (`session start` only, not UserPromptSubmit — once per session, no per-prompt friction): an in-flight `docs/plans/*.md` that is untracked or dirty (git status via the session crate's existing git helpers; non-git cwd = silent no-fire) ⇒ one line "persisted plan uncommitted — commit it (explicit-path git add)"
- [ ] **Guard 2 — commit-without-plan-touch advisory** (PostToolUse Bash, `git commit`, single-rule `if:` — no pipe alternation, the log-polish-nudge dead-hook precedent): repo has a `status: in-flight` plan bound to the current branch (fallback: shared-main plans match any branch; stale `branch:` = no-fire) and the last 3 commits didn't touch it ⇒ "tick the plan, bump `updated:`/`next:`". Consult the command's exit status — an aborted commit never nudges. Once per session
- [ ] **Guard 3 — ready-flip guard** (closes #429): two separate PreToolUse rows (`gh pr ready`, `gh pr merge` — never one alternated rule) while the branch's plan has unticked boxes or `status: in-flight` ⇒ warn, never block
- [ ] **Guard 4 — plan-format lint at persist time**: widen the Panel-line nudge (#624) to also flag a missing Alternatives-declined stanza and zero `- [ ]` checkboxes. Drop the frontmatter-key arm (dead by construction — `render_frontmatter` just wrote those keys). Preserve the shipped nudge's invariants: detection runs after the claim succeeds, and the nudge appends static text only, never matched content
- [ ] **Shared body reader**: guards 2–4 need checkbox counts from the body, which `plan_scan.rs` deliberately never reads. Add a separately-bounded body scanner (line + byte caps, same hostile-directory discipline), placed so both the session crate and the guards reach it; frontmatter stays untrusted (charset-validate before rendering into context)

### Task 4 — Wiring + release

- [ ] `cadence/plugins/cadence/hooks/hooks.json`: budget 3+ new rows (PostToolUse/Bash for guard 2 — none exists today; two PreToolUse rows for guard 3), each single-rule; regen codex assets (`scripts/build-codex-assets.py --check`)
- [ ] Wiring may merge before the release — verified safe: an unknown subcommand takes `run-cadence-hooks.sh`'s inert path (exit 0, one stderr line/day) on machines with older binaries
- [ ] Release per CLAUDE.md's full checklist: `make bump` + `cargo check` + `make report` with explicit `--workspace` (the worktree wiring-emptying trap) + CHANGELOG `[Unreleased]` stamp + `platform-baseline.json` `cadence_hooks.current_version` bump in the cadence monorepo (already stale at 0.74.0 vs released 0.75.1 — fix in passing)
- [ ] Brew upgrade gates on sjomba/M5/work — Cameron actions

### Task 5 — Close the attune-exemption hole (cadence plugin, prose)

- [ ] attune / using-cadence: the "approved plan in context = attuned" exemption becomes a **forcing function** (#942 seam 4): the exemption form must cite the plan's on-disk path — `attune (executing approved plan — docs/plans/<file>)` — unfillable when the file is missing; a missing file means persist it now. This also binds the executing seat (defect 7)
- [ ] attune: plan-mode drafts (plan file at `~/.claude/plans/`) MUST still carry cadence's template shape — Panel line, Alternatives declined, checkbox tasks — so the persisted doc lints clean under guard 4. The harness workflow dictates *where* the draft lives, never its shape. **Sequencing: this PR merges before or with guard 4's wiring** — shipping the lint first would nudge every plan until the shape fix lands
- [ ] Same-PR regen: catalog, graph, llms.txt

### Task 6 — Rules-delivery repair (cadence-hooks binary + cadence wiring; addresses [cadence#942](https://github.com/cameronsjo/cadence/issues/942))

- [ ] **Absence detection** in `session start`: check `${CLAUDE_CONFIG_DIR:-~/.claude}/rules/cadence/cadence-rules.md` (that exact precedence — the `initializing-cadence` install target); missing ⇒ once per calendar day (the platform-drift daily-gate mechanism is the in-tree pattern) one line naming `cadence-groundwork:initializing-cadence` as the installer. No "plugin active" predicate needed — the check only runs when the cadence plugin's own wiring invoked it
- [ ] **Doctrine rides the scanner**: append the two load-bearing Plan Execution lines (tick as work lands; reconcile before trusting) to the in-flight-plans SessionStart disclosure
- [ ] File the rules-transport ruling issue on cadence (SessionStart wholesale injection vs status quo) — decide-and-record, not build

### Task 7 — Housekeeping (meta-repo, shared-main — not this repo)

- [x] Flip the two stale meta-repo plan docs to `done` — landed as claude-configurations `248a401` (forgectl-claunch-auto-migrate: [forgectl#258](https://github.com/cameronsjo/forgectl/pull/258) merged; repair-and-format-desktop-file-json: executed 2026-07-26, artifacts verified)

## Out of scope (Cameron actions, noted not built)

- Work-machine adoption: install/upgrade cadence-hooks + rules at work (Ruling 4 of the lifecycle plan already scoped this out).
- Task 1's work payload sample is a Cameron hand-off; only Task 2's UPS-arm fix blocks on the *local* instrumentation, not on the work sample.

## Verification

- Task 1's instrumentation names the failing early-return before Task 2's code — probe-first, same discipline that caught #396's field rename.
- Guard tests from a clean slate per repo class (branch-mode, shared-main, no-plan repo — the no-fire case), plus failed-command no-fire cases for guard 2.
- End-to-end dogfood: approve a real plan in a fresh session → doc persisted → commit without touching it → advisory fires → `gh pr ready` with unticked boxes → warn fires.
- `make ci` (fmt + clippy `-D warnings` + tests) and `cargo test --workspace --no-fail-fast` in cadence-hooks; codex `--check`; catalog/graph `--check` on the cadence PR.

## Execution shape

cadence-hooks work in this worktree (`plan/living-plan-lifecycle-guards`, based on `origin/main` @ 0.75.1); Tasks 2–3 sequential PRs, Task 4 wiring PR in cadence may precede the release, Task 5 cadence PR merges before or with guard 4's wiring, Task 6 splits binary (cadence-hooks) and wiring (cadence). Task 1's local instrumentation gates Task 2; nothing else blocks on the Cameron hand-offs.

## Alternatives declined

- **Rules-transport rebuild (SessionStart injects rules wholesale)** — deferred to a filed ruling, not built here; this plan only stops the silent absence (Task 6's decide-and-record bullet).
- **Blocking guards instead of advisory** — declined per the friction canon: a false block on legitimate work costs more than a missed nudge; every guard here warns, never blocks.
- **Prose-only repair (tighten the skills, skip the guards)** — declined by Cameron's ruling: prose failed observably at work; determinism is the point.

## Panel review — findings declined

- **[plan-reviewer, Task 7 blocked by enforce-worktree]** — misread: Task 7 targets the meta-repo (shared-main by design, `CADENCE_ALLOW_MAIN`), not cadence-hooks; it executed cleanly as `248a401`. Wording clarified instead.
- **[red-team, Task 7 files not in this repo]** — same misread, same resolution: the task always named the meta-repo's `docs/plans/`; the heading now says so explicitly.
- **[plan-reviewer, llms.txt regen may be a no-op]** — advisory, accepted as-is: the regen stays in Task 5's checklist because it is the ungated artifact; a no-op regen costs nothing.

## Deviations

- **2026-08-11 — Defect 1 as approved overclaims.** The local probe (this session's transcript, claude-code 2.1.227 + cadence-hooks 0.75.1) shows approval `tool_response` still carries `plan` — the same-session persist fired and wrote this very document. `tool_input` now carries `plan` + `planFilePath`. Reality-forced amendment, staleness-first.
- **2026-08-11 — Context folded from [cadence#942](https://github.com/cameronsjo/cadence/issues/942)** (posted after approval): defect 6 narrowed (init-* works; `cadence-rules.md`'s sole installer sits outside every preflight), defect 7 added (executing-seat gap), Task 5 upgraded to the cite-the-path forcing function, Task 6 retargeted at the `initializing-cadence` install path.
- **2026-08-11 — Panel refuted both approved persist-defect root causes.** The red-team seat proved the legacy prefix still matches (four live sessions) and persistence still fails — the defect is an unnamed early-return, not the prefix and not the payload field. Task 1 rescoped from payload-shape capture to early-return instrumentation against session `beffcf50`; Task 2 rescoped to fix-what-Task-1-names. The plan's file:line cites and test count also derived from a checkout 26 commits behind `origin/main`; the worktree is based on current `origin/main` and cites re-resolve at edit time.
- **2026-08-11 — Guard specs tightened per panel** (events pinned, dedupe rules named, no-fire cases for failed commands, guard 4's dead frontmatter-arm dropped, new bounded body reader named, wiring rows budgeted 3+, release checklist completed with the platform-baseline bump).

## Learnings

_(populated as execution lands)_
