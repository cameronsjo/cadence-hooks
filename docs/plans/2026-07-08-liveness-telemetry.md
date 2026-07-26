# Liveness & Enforcement Telemetry — implementation plan

> **Plan PR (draft).** Ships as `docs/plans/2026-07-08-liveness-telemetry.md` on `cameronsjo/cadence-hooks`. This document is the whole contract — a fresh implementer session executes it with zero prior context.
> **Refs (never `Closes` — this is a plan, not the fix):** `Refs` the blind-spot audit at `cameronsjo/claude-configurations` → `docs/audits/2026-07-08-methodology-coverage-blind-spot-pass.md` (findings UU-1, UU-2, UU-12). No tracker issues exist for these findings by design — the fix batch shipped straight to plan PRs.
> **Implementer note:** Two repos, both cloned locally. Binary = `/Users/cameronsjo/Projects/claude-configurations/cadence-hooks` (`cameronsjo/cadence-hooks`, Rust; **this checkout's `Cargo.toml` reads 0.49.0 — fetch and check `gh release view --repo cameronsjo/cadence-hooks` before planning version numbers; memory records v0.52.0 shipped, so the checkout may be behind origin**). Plugins = `/Users/cameronsjo/Projects/claude-configurations/cadence` (`cameronsjo/cadence` monorepo; canon wiring is `plugins/cadence-canon/`). Read `crates/session/src/heartbeat.rs`, `crates/session/src/registry.rs`, `crates/session/src/identity.rs`, `src/dispatch.rs`, and `crates/metrics/src/log_plan_phase.rs` before touching anything — they are the mechanisms this whole cluster bends.
> **Planned 2026-07-08.**

## Context

The 2026-07-08 methodology-coverage blind-spot pass flagged three gaps in the session-liveness and enforcement layers. **Planning probes partially corrected one of them — read this section before the findings table, because the plan below targets the corrected reality, not the audit's original wording.**

**Corrections from ground truth (verified in this checkout on 2026-07-08):**

1. **UU-1 overstated the heartbeat gap.** The audit claimed the heartbeat fires "only on git/Edit/Write." Live source (`plugins/cadence-canon/hooks/hooks.json:58-79`) wires `session heartbeat` on PostToolUse for `Bash` (prefiltered `if: Bash(*git *)`) **and** `Edit|Write|Read|Grep|Glob` — and both installed cache SHAs carry the same wide matcher. Read-heavy analysis sessions DO heartbeat. The *residual* gap is real but narrower: sessions whose activity is **Agent dispatches, Skill invocations, non-git Bash, WebFetch/WebSearch, SendMessage, or AskUserQuestion** emit no heartbeat — i.e. pure-orchestrator sessions (dispatch subagents, wait, synthesize) and skill-driven flows, which is exactly the shape long fan-out sessions take.
2. **The staleness TTL is 30 minutes, not 10.** `registry::stale_minutes()` reads `CADENCE_SESSION_STALE_MINUTES`, default **30** (`crates/session/src/registry.rs:22-25`). The canon README's "stale (10 min)" text is doc drift — a subsidiary fix in this cluster. *(Claim-to-verify: grep the README's exact wording before editing.)*
3. **The audit's live-registry evidence is ambiguous.** "6 lane files vs ~10 announced peers" can be explained by normal `session end` removal between observations, not sweep bias. The plan therefore treats UU-1 as *gap-closing plus instrumentation* (measure sweeps before assuming casualties), not as a confirmed data-loss incident.

UU-2 and UU-12 verified as written: no metrics stream observes fail-open events (`crates/metrics/src/` has loggers for denials, timing, bypasses, etc. — nothing failure-of-the-guard-layer-shaped), and `SessionRecord` (`crates/session/src/identity.rs:13-38`) carries no version field, so protocol skew between concurrent peers is undetectable.

## Findings covered — disposition and repo

| Finding | Short form | Repo that owns the fix | Disposition in this plan |
|---|---|---|---|
| **UU-1** | Orchestrator-shaped sessions never heartbeat; sweeps can reclaim live state | **cadence** (canon `hooks.json` — wiring only) + **cadence-hooks** (sweep instrumentation) | Widen the heartbeat matcher (rework, no new subcommand). Instrument `sweep_stale` so future reclaims are observable. TTL stays 30m; env knob already exists. |
| **UU-2** | Fail-open has no failure telemetry | **cadence-hooks** (binary) + **cadence** (metrics schema docs) | New `failopen.jsonl` writes from the existing dispatch fail-open sites + a `doctor` fail-open-count check. One new logger module, **no new subcommand** (see Approach). |
| **UU-12** | No protocol-version handshake among peers | **cadence-hooks** (session crate) | Stamp `SessionRecord` with binary version + plugin SHA; disclose skew in `session status`/start disclosure. Additive serde fields — old lane files must still parse. |
| — | Canon README says 10-minute TTL | **cadence** (canon README) | One-line doc fix riding the wiring PR. |

## Approach

### The repo split (explicit)

**Binary-side (cadence-hooks, Rust):**

- **UU-1b — sweep observability.** `registry::sweep_stale` (`crates/session/src/registry.rs`) currently deletes silently. Add a fire-and-forget JSONL row per reaped lane (session name/id, age at reap, which trigger swept it — SessionStart / heartbeat / guard / status / backstop, all five call sites take `stale_secs` from the same helper). Write into the **existing metrics stream family** (`~/.claude/metrics/`), new file `sweeps.jsonl`, born with `schemaVersion` per the C8 policy (`log_plan_phase.rs:24` is the reference: `const SCHEMA_VERSION: u32 = 1`).
- **UU-2 — fail-open telemetry.** `src/dispatch.rs` already performs **two fail-open side effects** on every dispatch (the denial write and the timing write — see its module docs, lines 15-16, 49-56). Add the third: when a check panics (the existing panic-catch path), when stdin parse fails open, and when the **unknown-subcommand / version-mismatch path** returns allow (the behavior locked by `tests/version_mismatch.rs`), append a row to `failopen.jsonl` with `{kind: panic|parse|version_mismatch, namespace, subcommand, schemaVersion}`. Same fully-fail-open discipline as `log_denial`: a failed telemetry write never perturbs the allow (ADR-0001). **No new CLI subcommand** — these writes happen inside the dispatch path, so **doctor CI is not involved** (doctor keys on `hooks.json` subcommand references).
- **UU-2b — doctor surfaces it.** `src/doctor.rs` gains a section: count `failopen.jsonl` rows in the last N days, warn above a threshold (suggest N=7, threshold=1 for `version_mismatch`, higher for `parse`). Doctor is already the "is my install healthy" surface; this is the cheapest reader that makes the stream non-write-only from birth.
- **UU-12 — version stamp.** Add `Option<String>` fields to `SessionRecord` (`identity.rs`): `hooks_version` (from `env!("CARGO_PKG_VERSION")`) and `plugin_sha` (from `${CLAUDE_PLUGIN_ROOT}` path segment if parseable — *claim-to-verify: confirm the cache dir name embeds the SHA prefix, format `<sha12>-<hash>`*). `session start` populates them; `session status` and the start disclosure append a one-line skew warning when a peer's `hooks_version` differs from self. `#[serde(default)]` on both fields so existing lane files parse unchanged.

**Plugin-side (cadence, markdown/JSON — `plugins/cadence-canon/`):**

- **UU-1a — matcher widening.** Rework `hooks.json`: replace the two PostToolUse heartbeat entries with a single `matcher: "*"` entry (drop the `if: Bash(*git *)` prefilter on the Bash entry — heartbeat is a cheap mtime touch; *claim-to-verify: confirm `matcher: "*"` is valid in plugin hooks.json against current Claude Code docs, else enumerate `Agent|Skill|Bash|Edit|Write|Read|Grep|Glob|WebFetch|WebSearch`*). `session heartbeat` is an **existing subcommand**, so **doctor will not trip** — this companion is *not* release-gated for CI. It IS behaviorally coupled to UU-1b only for observability, not correctness: safe to merge independently.
- **README TTL fix** — 10 min → 30 min (`CADENCE_SESSION_STALE_MINUTES`, default 30), same PR.
- **Metrics schema docs** — document `sweeps.jsonl` and `failopen.jsonl` in `plugins/cadence-metrics/docs/schema.md` (schema docs travel with the plugin repo even though writers live in the binary — same split as the C8 cluster).

### Reuse ledger (nothing net-new without a named parent)

| Change | Mechanism it uses/abuses/reuses/reworks | Net-new? |
|---|---|---|
| Heartbeat coverage (UU-1a) | **Rework** — widen the existing `session heartbeat` matcher in the existing hooks.json entry; zero binary change | No |
| Sweep telemetry (UU-1b) | **Reuse** — metrics JSONL family + `Logger` fire-and-forget pattern + C8 `schemaVersion` policy; **abuse** of `sweep_stale`'s existing single choke point (all five triggers already funnel through it) | New *file* only; pattern is copied verbatim from `log_plan_phase.rs` |
| Fail-open rows (UU-2) | **Reuse** — dispatch.rs's existing fail-open side-effect slots (denial + timing writes already prove the pattern); extend, don't invent | New logger module; justified — no existing stream carries guard-layer failures, which is the finding itself |
| Doctor fail-open check (UU-2b) | **Reuse** — doctor is the existing health surface; adding a section, not a tool | No |
| Version stamp (UU-12) | **Rework** — two `#[serde(default)]` fields on the existing `SessionRecord`; skew line rides the existing status/disclosure renderer | No |
| Transcript-mtime liveness (considered) | Would **reuse** the transcript file the harness already maintains — **deliberately deferred**: the registry can't portably locate another session's transcript path, and matcher widening closes most of the gap at zero new surface. Revisit only if sweep telemetry shows live-session reaps persisting after UU-1a ships. | Deferred |

### The two-repo release-gate (must be obeyed)

- **No new subcommands anywhere in this cluster** → `cameronsjo/cadence`'s `hooks-skew.yml` doctor check **never trips**. The canon `hooks.json` widening references only the existing `session heartbeat`.
- **Ordering is still behavioral:** ship the binary (sweep telemetry + failopen + version stamp) and cut a release **before** merging the canon wiring PR, so the widened heartbeat lands on a binary whose sweeps are already observable — the instrumentation should be watching while the fix rolls out, not after.
- Old binary + new hooks.json is safe (heartbeat is an existing subcommand); new binary + old hooks.json is safe (all changes additive/fail-open). No hard gate, one soft ordering preference.

## Task breakdown

| # | Task | Repo | Dispatch |
|---|---|---|---|
| 1 | `sweeps.jsonl` logger at the `sweep_stale` choke point, `schemaVersion: 1`, tests (reap → row; failed write → still reaps) | cadence-hooks | implementer, sonnet |
| 2 | `failopen.jsonl` rows from dispatch.rs's panic/parse/version-mismatch paths, tests mirroring `tests/version_mismatch.rs` | cadence-hooks | implementer, sonnet |
| 3 | Doctor fail-open + sweep-count section, threshold warnings | cadence-hooks | implementer, sonnet |
| 4 | `SessionRecord` version fields + skew disclosure line, `#[serde(default)]` back-compat tests (old lane file fixture must parse) | cadence-hooks | implementer, sonnet |
| 5 | Release the binary (version bump **in a worktree off origin/main** — the primary checkout blocks the bump commit; see memory `cadence-hooks-release-bump-needs-worktree`) | cadence-hooks | orchestrator |
| 6 | Canon `hooks.json` matcher widening + README TTL fix + metrics schema docs | cadence | implementer, sonnet |
| 7 | Verify end-to-end (below) and close the loop on the audit doc | orchestrator | — |

Tasks 1-4 are independent of each other (separate files; task 4 touches identity.rs/start/status only) — parallelizable as isolated-worktree implementers if desired, but sequential in one worktree is simpler and they're small.

## Verification

1. **Heartbeat widening:** in a scratch session, run only `Agent`-dispatch + `WebSearch` turns for >30 min with a peer session watching `session status` — the lane must stay `[LIVE]`. Before the fix, the same drill reads `[STALE]`.
2. **Sweep telemetry:** set `CADENCE_SESSION_STALE_MINUTES=1`, start + abandon a scratch session, trigger a peer heartbeat, then `jq . ~/.claude/metrics/sweeps.jsonl | tail -1` — row carries the reaped id, age, trigger.
3. **Fail-open:** invoke a nonexistent subcommand via `run-cadence-hooks.sh session no-such-check < payload.json` — exit 0 (fail-open preserved) AND a `version_mismatch` row lands in `failopen.jsonl`; `cadence-hooks doctor` reports the count.
4. **Skew:** hand-edit a scratch lane file's `hooks_version` to `0.0.1`, run `session status` — skew line appears; delete the field entirely — file still parses (back-compat).
5. Full suite: `$HOME/.cargo/bin/cargo test` (cargo is not on the non-interactive PATH — memory `cadence-hooks-cargo-path-in-bash-tool`).

## Orchestrator

**Sonnet-drivable.** Every task is spec'd to file-level mechanics against verified reference patterns; no adjudication or mid-flight replanning is anticipated. Escalate to Opus only on the named trigger: the UU-1a matcher probe (`matcher: "*"` validity) coming back negative **and** the enumerated-matcher fallback colliding with harness matcher-syntax limits — that's a replan, not a substitution.
