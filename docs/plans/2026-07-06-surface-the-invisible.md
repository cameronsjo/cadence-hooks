# Surface the Invisible — fail-open breadcrumbs & posture disclosure

> **Plan PR (draft) on `cameronsjo/cadence-hooks`.** Ships as `docs/plans/2026-07-06-surface-the-invisible.md`.
> Refs cameronsjo/cadence-hooks#69 · Refs cameronsjo/cadence-hooks#183 · Refs cameronsjo/cadence-hooks#236 · Refs cameronsjo/cadence-hooks#156 · Refs cameronsjo/cadence#223 (companion prose Refs cameronsjo/cadence#278).
> **Implementer note:** you have zero context from the planning session. Everything you need is below — exact files, functions, line anchors (verified against `main` at cadence-hooks `v0.48.0`), commands, and acceptance evidence. Follow the cadence-hooks `CLAUDE.md` release/worktree discipline. Do not write `Closes` for any issue ref; use `Refs …#N`.
> Planned 2026-07-06.

---

## Context — the theme, why now, the #156 unblocking evidence

**The theme.** Several cadence guardrails are designed to **fail open** (ADR-0001, `docs/adr/0001-fail-open.md`): a guard's own failure must never block the user. That is correct. The cost is **silence** — a guardrail the user believes is enforcing can be quietly inert (stale/missing binary), and a wall the user is about to hit (`enforce-worktree`) is never announced until the first Edit/Write trips it. Silent states give the user no signal. This cluster gives silent states a voice: **stderr breadcrumbs** for fail-open paths, and **SessionStart posture disclosure** for the worktree wall — without changing any exit code or block decision.

**Why now.** The wrapper-side breadcrumb design is fully specified in cadence#223; the SessionStart peer-disclosure surface (`session start`, wired by the `cadence-canon` plugin) already exists and is the natural home for a posture line; and the one deferred piece (#156) has a *claimed* platform unblock to re-verify. Bundling them keeps one coherent "surface the invisible" story and one disclosure vocabulary.

**#156 unblocking evidence — RE-VERIFIED 2026-07-06, and it does NOT cleanly unblock.**

- Source consulted: **https://code.claude.com/docs/en/hooks** (the `docs.anthropic.com/en/docs/claude-code/hooks-reference` URL 301-redirects to `code.claude.com/docs/en/hooks-reference`, which currently **404s** — the live reference is the `/hooks` page).
- What the docs say **today**: the common-input-fields section **lists `permission_mode`** among fields present across events — *but with the explicit caveat* **"Not all events receive this field. Check the JSON example in each hook event section."** The **SessionStart JSON input example omits `permission_mode`** — it shows only `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `source`, and `model`.
- **Verdict:** the docs are self-contradictory for SessionStart and, on the authoritative example, **do NOT confirm** that SessionStart carries `permission_mode`. The #156 comment's premise ("universal common input field … including SessionStart") is **not** substantiated by the current docs. Therefore **#156 stays deferred and gated on a runtime probe** (Task B1), not built on the docs' generic common-field claim. The binary-side prerequisite is real and unchanged: `HookInput` (`crates/core/src/lib.rs:145`) has **no `permission_mode` field** (confirmed — the struct carries `tool_name`, `tool_input`, `tool_response`, `cwd`, `transcript_path`, `session_id`, `source`, `model`, `agent_id` only).

---

## Issues covered — per-issue disposition

| Issue | Repo | Title (short) | Disposition in this plan |
|---|---|---|---|
| **#69** | cadence-hooks | wrapper fails open silently; document isolation | **Mostly landed / verify.** Ask 2 (isolation docs) is **already done** — `docs/testing.md` §"Is a block the binary or the wrapper?" (lines 61-83) + README link (line 120). Ask 1 (make it visible) is delegated to **cadence#223**. #69 stays open until cadence#223 lands. → **Task A0** (doc reconciliation only). |
| **#183** | cadence-hooks | silent fail-open masked 5 weeks of dark commit logging | **Largely covered.** The doctor-side ask ("name missing metrics subcommands at session start") is **already shipped** — `doctor` emits a `staleness_finding` (`src/doctor.rs:445`) and version-skew naming (`judge_invocation`, `src/doctor.rs:215`). The remaining real-time gap is the **wrapper breadcrumb = cadence#223**. → covered by **Task C1**; add a one-line cross-ref note. No new binary code required. |
| **#236** | cadence-hooks | SessionStart worktree-posture disclosure | **Build (binary-side).** Extend the existing `session start` disclosure to emit a worktree-posture line, reusing `enforce_worktree` detection. → **Task A1.** Companion prose is cadence#278 (out of scope here). |
| **#156** | cadence-hooks | plan-mode-at-start attune backstop (deferred) | **Do NOT build.** Docs do not confirm the unblock; trip-wire not yet tripped. → **Task B1** documents a runtime probe + the two gates that would authorize building it later. |
| **cadence#223** | cadence | wrapper emits once/day stderr notice when binary missing/stale | **Build (plugin-side).** Add `notify_inert()` to the wrapper. → **Task C1.** Pure shell; does **not** touch `hooks.json`, so it does **not** trip doctor CI and can merge independent of any binary release. |

---

## Approach — one coherent disclosure design

Two silent-state families, two surfaces, one vocabulary.

**1. Fail-open breadcrumbs → stderr, throttled once/day.**
The hook protocol uses **stdout** as its data channel (a SessionStart nudge injects context via stdout; a block feeds stderr back to Claude). So a *diagnostic* breadcrumb that must not perturb the protocol goes to **stderr only**, and exit codes stay unchanged (fail-open preserved). Throttle to **once per calendar day** via a date-keyed marker so it nudges, never spams a hot path. This is exactly the shape cadence#223 specifies and that `metrics warn-stale` already uses (`crates/metrics/src/warn_stale.rs:161`, marker `state/stale_warn.date`).

- Marker dir: `${XDG_STATE_HOME:-$HOME/.local/state}/cadence-hooks/` (align with cadence#223's `notify_inert`).
- Message format (stderr): `cadence-hooks: guardrails inert — <cause>. Guards are NOT running. Fix: <action>. (once/day)`

**2. SessionStart posture → the `session start` disclosure surface (stdout / `additionalContext`).**
`enforce-worktree` is announced only by hitting it. `session start` (`crates/session/src/start.rs`, the `Start` check) already runs at SessionStart under the `cadence-canon` plugin and already renders a disclosure (peer/lane). Add a **worktree-posture line** to that same surface, gated by the **same predicate `enforce_worktree` uses to decide whether it *would* block** — so the line fires exactly where the wall exists and stays silent where an exemption would waive it.

- Message (nudge, one line): `Branch-mode repo, primary checkout: feature work starts in a worktree (EnterWorktree / git worktree add) — the first Edit/Write here will be blocked.`
- Optional (cheap, MAY skip): when cwd is already a linked worktree, a one-line confirmation the posture is right.

### Decided design choices (not open questions)

| Choice | Decision | Why |
|---|---|---|
| Breadcrumb channel | **stderr**, exit code unchanged | stdout is the protocol channel; fail-open must stay fail-open |
| Breadcrumb throttle | **once/day**, date-keyed marker | matches cadence#223 + `warn-stale` precedent; avoids per-tool-call spam |
| Posture channel | reuse **`session start`** disclosure (stdout nudge) | same surface as peer disclosure; SessionStart-only ⇒ fires once/session |
| Posture gating | **reuse `enforce_worktree`'s block predicate** (minus the mutation trigger) | line fires iff the wall would; honors `CADENCE_ALLOW_MAIN`, `CADENCE_NO_ENFORCE_WORKTREE`, temp-dir, active snooze |

### The one genuinely-undecided call (see Decision Points) — #236 wiring shape

| Option | New subcommand? | hooks.json change? | doctor-CI gate? | Notes |
|---|---|---|---|---|
| **A (recommended)** — extend the existing `Start` check to also emit the posture line | **No** | **No** | **No** | Posture rides the `session start` output already wired by cadence-canon. Zero plugin-side PR. Goes live on the next binary release automatically. |
| **B** — new `session posture-warn` (or `session start-posture`) subcommand, wired as a new SessionStart entry in `cadence-canon/hooks/hooks.json` | **Yes** | **Yes** | **Yes** | Cleaner separation, but requires **binary release BEFORE** the plugin hooks.json PR (see Sequencing) and adds a registry/clap/dispatch entry. |

Recommend **A** — it sidesteps the doctor-CI gate entirely and needs no plugin PR.

---

## Task breakdown

> Model legend: **haiku** = mechanical/lookup, **sonnet** = spec'd implementation with light judgment. All binary-side work obeys cadence-hooks `CLAUDE.md`: `export PATH="$HOME/.cargo/bin:$PATH"`, `make ci` before commit, do feature work in a **worktree** (the repo's own `enforce-worktree` blocks primary-checkout writes/commits).

### Binary-side (repo: `cameronsjo/cadence-hooks`)

---

**Task A0 — #69 doc reconciliation (verify, minimal edit).** · size **XS** · model **haiku**

- **Scope:** #69 ask 2 is already satisfied by `docs/testing.md:61-83` and `README.md:120`. Line 81-82 of `docs/testing.md` states the wrapper *"now emits a once/day stderr notice (`cameronsjo/cadence#223`)"* — this is **ahead of the code** (the wrapper is still silent until Task C1 lands). Reconcile: either (a) leave as-is if C1 is landing in the same train, or (b) soften to *"will emit … once cadence#223 lands"* if C1 is deferred.
- **Files:** `docs/testing.md` (only if softening). No code.
- **Tests:** none (prose). Run `npx --yes markdownlint-cli2 docs/testing.md` and filter to structural findings only (repo ships no markdownlint config; MD013/MD060 noise is pre-existing — see cadence-hooks `CLAUDE.md`).
- **Do NOT** re-write the isolation section; it already exists and is correct.

---

**Task A1 — #236 worktree-posture disclosure (Option A: extend `session start`).** · size **M** · model **sonnet**

- **Scope:** add a worktree-posture line to the SessionStart disclosure, gated by the same predicate `enforce_worktree` uses to decide a block, honoring all exemptions. Fire once/session (it's SessionStart). Must emit **even when there are no live peers** (today `run_start` returns `Allow` silently when `peers.is_empty()` — `crates/session/src/start.rs:107-109`).
- **Primary files:**
  - `crates/session/src/start.rs` — `run_start` (line 41) and `render_disclosure` (line 115). Compose a posture line and include it whether or not peers exist. Suggested shape: add a pure helper `fn worktree_posture_line(cwd: &str) -> Option<String>` and, in `run_start`, build the final `CheckResult` from `[posture_line?, peer_disclosure?]` joined — returning `Nudge` if either is present, else `Allow`.
  - **Reuse detection from** `crates/guardrails/src/enforce_worktree.rs`. The block decision is `should_block(is_primary, allowed_main, kill_switch, temp_root, snoozed)` = `is_primary && !allowed_main && !kill_switch && !temp_root && !snoozed` (line 267-275). The posture line should fire on the **same condition minus the mutation trigger** (SessionStart has no command to parse). Concretely reuse:
    - `warn_subagent_worktree::is_primary_checkout(repo_root)` (imported at `enforce_worktree.rs:57`)
    - `is_temp_root(...)` (`enforce_worktree.rs:122`)
    - `dismiss_enforce_worktree::is_snoozed_now(repo_root)` (`enforce_worktree.rs:338`)
    - `CADENCE_ALLOW_MAIN` via `cadence_hooks_core::config::repo_env_flag(repo_root, "CADENCE_ALLOW_MAIN")` (`enforce_worktree.rs:110`) **and** the env form
    - `CADENCE_NO_ENFORCE_WORKTREE` kill switch (`enforce_worktree.rs:88-89`)
    - `is_claude_managed_dir` / `is_plan_doc_dir` early-outs (`enforce_worktree.rs:329`)
  - **Preferred refactor (light judgment, keeps one source of truth):** extract the exemption/primary-checkout evaluation in `enforce_worktree.rs` into a pure, `pub(crate)`-or-`pub` predicate (e.g. `fn would_block_here(dir: &Path) -> bool`, decoupled from any command string) that both `enforce_worktree`'s `assess_dir` and the new session posture call. Do **not** duplicate the exemption logic in `start.rs` — a drift between "the line fires" and "the wall blocks" is the exact bug to avoid. If a cross-crate call is awkward (`enforce_worktree` is in `crates/guardrails`, `start` in `crates/session`), lift the shared predicate into `crates/core` (`cadence_hooks_core`), which both already depend on.
  - **Message text** (from #236): `Branch-mode repo, primary checkout: feature work starts in a worktree (EnterWorktree / git worktree add) — the first Edit/Write here will be blocked.`
- **Tests** (`crates/session/src/start.rs` `#[cfg(test)]`, mirror the existing `run_start`/`render_disclosure` unit tests; inject cwd/branch as the current tests do):
  - primary checkout of a branch-mode repo → posture line present (with **and** without peers).
  - `CADENCE_ALLOW_MAIN` set / repo-declared → **no** posture line.
  - `CADENCE_NO_ENFORCE_WORKTREE` set → no line.
  - linked worktree (or non-primary) → no wall line (optionally the confirmation line).
  - active `dismiss-enforce-worktree` snooze → no line.
  - **Parity test (critical):** for a matrix of dirs, `posture_line.is_some() == enforce_worktree would block` — locks the two to one predicate.
- **Registry/dispatch:** Option A adds **no** subcommand → no `src/registry.rs` / `src/main.rs` change → `registry_matches_clap_dispatch` unaffected. (Option B would need both — see Decision Points.)
- **Gotcha (from cadence-hooks `CLAUDE.md`):** `enforce-worktree`'s Scratch/E2E tests false-allow when the checkout sits under `.claude/worktrees/` or `/tmp`. Run the suite from a carve-out-free path (`git worktree add --detach ~/verify <sha>`) and `cargo build --bin cadence-hooks` before any pipe-probe (`cargo test` does not build the bin → exit 127 misreads as ALLOW).

---

**Task B1 — #156 runtime probe + gated backstop (DOCUMENT ONLY, do not implement the guard).** · size **S** (probe) · model **sonnet**

- **Scope:** #156 is deferred by design (prose-now / guardrail-deferred). Today's docs do **not** confirm SessionStart carries `permission_mode`, so **do not add the field or the guard on the strength of the docs.** Instead, run and record a **runtime probe** to settle the platform question empirically, and document the two gates that must both hold before building.
- **The probe (settles the platform half):** capture a **real** SessionStart hook payload and check for `permission_mode`. Add a throwaway logging hook or inspect an existing SessionStart transcript. Minimal approach: temporarily wire a SessionStart command that dumps stdin to a file, open a session in **plan mode** (`claude --permission-mode plan`) and in default mode, and diff the payloads. Record verbatim in the PR/issue whether `permission_mode` is present and its value per mode.
  - If **present** → the platform blocker is genuinely gone; the remaining work is binary-side only (add `permission_mode: Option<String>` to `HookInput` at `crates/core/src/lib.rs:145`, deserializing to `None` when absent, mirroring the existing `source`/`model` optional fields + their unit tests at `lib.rs:1341-1352`). Still do **not** build the guard until the behavioral trip-wire (below) fires.
  - If **absent** → confirm #156 stays fully blocked on the platform; leave the comment updated with the probe evidence and the docs URL. Do not add the field speculatively.
- **The behavioral trip-wire (settles the "is it needed" half, unchanged from the issue):** build the backstop **only if**, after the `cadence:using-cadence` gate reword shipped, `attune` is still observed getting skipped on plan-mode-pinned sessions that start creative work. Until observed, the reword is presumed sufficient. Also note the **constant-signal trap**: for a plan-mode-pinned user `permission_mode` reads `"plan"` every turn, so any future guard must key on a **content** signal (creative-work intent), not the mode alone.
- **Files:** none in this plan beyond documenting the probe result in the #156 thread. The `HookInput` field is a *follow-up*, authorized only by a positive probe **and** a tripped wire.
- **Tests:** none now.

---

### Plugin-side (repo: `cameronsjo/cadence`)

---

**Task C1 — cadence#223 wrapper fail-open once/day stderr notice.** · size **S** · model **sonnet**

- **Scope:** make the wrapper's two silent fail-open paths narratable. Preserve fail-open exactly — exit codes stay `0` at both sites. Add a `notify_inert()` throttled once/day.
- **Files (the wrapper is 5 byte-identical copies in this monorepo — md5 `c30fc818…`, verified 2026-07-06):**
  - `plugins/cadence/hooks/run-cadence-hooks.sh`
  - `plugins/cadence-rules/hooks/run-cadence-hooks.sh`
  - `plugins/cadence-canon/hooks/run-cadence-hooks.sh`
  - `plugins/cadence-metrics/hooks/run-cadence-hooks.sh`
  - `plugins/cadence-guardrails/hooks/run-cadence-hooks.sh`
  - **Finding — no generator/sync script exists** (searched; none found). The copies are hand-synced, so edit all five identically. After editing, re-verify they remain byte-identical: `md5 -q plugins/*/hooks/run-cadence-hooks.sh | sort -u | wc -l` must print `1`.
  - **Out of scope for a `cadence` PR:** a 6th copy lives in the separate **`cadence-lab`** repo at `plugins/persona/hooks/run-cadence-hooks.sh` — file a follow-up on cadence-lab; do not edit cross-repo from the cadence PR.
- **Current wrapper (verified, `plugins/cadence/hooks/run-cadence-hooks.sh`):**
  - missing binary → `if [ -z "$BINARY" ]; then exit 0; fi` (lines 9-11), silent.
  - stale binary → `grep -qiE "unrecognized subcommand|wasn't recognized"` → `exit 0` (lines 25-29), silent.
- **Change (from cadence#223, adapt marker to match `warn-stale` if it differs):**

  ```bash
  notify_inert() {
    local marker="${XDG_STATE_HOME:-$HOME/.local/state}/cadence-hooks/fail-open-$(date +%Y%m%d)"
    [ -e "$marker" ] && return 0
    mkdir -p "$(dirname "$marker")" 2>/dev/null && : > "$marker" 2>/dev/null || true
    echo "cadence-hooks: guardrails inert — $1. Guards are NOT running. Fix: brew upgrade cadence-hooks (or reinstall). (once/day)" >&2
  }
  ```

  - missing → `notify_inert "the 'cadence-hooks' binary is not on PATH"; exit 0`
  - stale → `notify_inert "the installed binary is stale (missing subcommand '$*')"; exit 0`
  - Keep the `|| true` guards (marker I/O must not trip `set -euo pipefail`); keep the cheap `[ -e ]` short-circuit for the hot path.
- **Does NOT trip doctor CI:** this edits only the shell wrapper, not any `hooks.json` — `hooks-skew.yml` scans `plugins/*/hooks/**` but doctor's skew check inspects **hook command subcommand references** in `hooks.json`, not the wrapper body. No new subcommand is introduced, so this merges independent of any binary release. (Confirm with the Verification command below.)
- **Tests:** the cadence monorepo wrapper has no unit harness; verify by hand (see Verification C1). Add a bullet under `[Unreleased]` in the plugin's changelog if one exists.

---

## Sequencing & dependencies

Tasks are largely independent. Two ordering rules and one non-rule:

1. **`cadence#223` (Task C1) is independent** of any binary release — pure shell, no `hooks.json` change, no new subcommand → **does not trip the doctor-CI gate**. Merge whenever. **#69 stays open until C1 lands** (and Task A0's `docs/testing.md` present-tense line is then accurate).
2. **#236 Option A (Task A1) needs no plugin PR.** It ships in the binary; the posture line goes live automatically when Claude Code re-pins the new `cadence-hooks` release at session start. No sequencing hazard.
3. **The doctor-CI gate — applies ONLY if #236 is built as Option B (new subcommand).** Call this out explicitly so the implementer does not trip it:

### ⚠️ The doctor-CI gate (binary release BEFORE any additive hooks.json companion)

The `cameronsjo/cadence` repo runs **`.github/workflows/hooks-skew.yml`** on any change under `plugins/*/hooks/**`. It calls the reusable **`cameronsjo/cadence-hooks/.github/workflows/plugin-hooks-skew.yml`** (pinned `@a7f35b0…`), which installs the **latest RELEASED `cadence-hooks` binary** and runs **`cadence-hooks doctor --root .`** across every `plugins/<name>/hooks/`. `doctor` flags any hook command referencing a **subcommand the released binary does not ship** (`judge_invocation` → "not present in this binary", `src/doctor.rs:238`), exiting non-zero → **red CI**.

**Consequence:** if you take **Option B** and add a new `session posture-warn` (or similar) entry to `plugins/cadence-canon/hooks/hooks.json`, that cadence PR **fails hooks-skew until the cadence-hooks binary that ships the subcommand is RELEASED** (not merely merged — the gate installs a release). Required order for Option B:

1. Land the binary subcommand in cadence-hooks (`src/main.rs` clap variant + `src/registry.rs` `HOOKS` entry with `event: Some(HookEvent::SessionStart)` + dispatch wiring; `registry_matches_clap_dispatch` and the hooks.json audit test enforce this).
2. **Cut a cadence-hooks release** (`make bump` in a worktree off `origin/main`, push tip to `main` → auto-tag → release + tap update; see cadence-hooks `CLAUDE.md`). Verify via the tag/Release/tap formula, not the CI check.
3. **Only then** open the cadence PR wiring the new subcommand into `cadence-canon/hooks/hooks.json`. It goes green because the released binary now knows the subcommand.

(Removal companions merge free; only **additive** subcommand references are gated. This is the recorded "two-repo companion release-gating" hazard.)

**Recommendation:** take **Option A** and this gate never engages — no cadence PR, no release-ordering dance.

---

## Verification — exact commands/evidence per task

> cadence-hooks: `export PATH="$HOME/.cargo/bin:$PATH"` first; run the suite from a carve-out-free path per `CLAUDE.md`.

**Task A0 (#69 docs):**

- `grep -n "Is a block the binary or the wrapper" docs/testing.md` → matches (section present).
- `grep -n "cadence#223" docs/testing.md` → line ~82 present.
- If softened, re-read the edited paragraph to confirm tense matches C1's landing state.

**Task A1 (#236 posture):**

- `make ci` green (`fmt-check` + `clippy -D warnings` + all tests).
- New unit tests pass, including the **parity test** (`posture_line.is_some() == would_block`).
- Behavioral proof — build the bin, pipe a SessionStart payload from a **primary checkout of a branch-mode repo** straight to the bare subcommand (not `try`, which overrides cwd and ignores stdin):

  ```
  cargo build --bin cadence-hooks
  echo '{"session_id":"probe","source":"startup","cwd":"<primary-checkout-abs-path>"}' \
    | ./target/debug/cadence-hooks session start; echo "exit: $?"
  ```

  Expect stdout to contain the posture line, exit `0`.
- Exemption proof — repeat with `CADENCE_NO_ENFORCE_WORKTREE=1` (and separately from a linked worktree cwd): **no** posture line.
- Parity spot-check — same cwd through `guardrails enforce-worktree` with a mutation payload blocks (exit 2) **iff** the posture line fired.

**Task B1 (#156 probe):**

- Probe artifact: the captured SessionStart payload file(s), with `permission_mode` present/absent recorded verbatim per mode, pasted into the #156 thread alongside the docs URL (`https://code.claude.com/docs/en/hooks`) and today's date. No code to verify.

**Task C1 (cadence#223 wrapper):**

- Byte-identity preserved: `md5 -q plugins/*/hooks/run-cadence-hooks.sh | sort -u | wc -l` → `1`.
- Missing-binary path (run with `cadence-hooks` off PATH):

  ```
  env PATH=/usr/bin:/bin bash plugins/cadence/hooks/run-cadence-hooks.sh cadence terminology < /dev/null; echo "exit: $?"
  ```

  Expect a one-line stderr notice on the **first** run today, exit `0`; a **second** run the same day is silent (marker short-circuit), exit `0`.
- Stale-binary path: point PATH at a stub `cadence-hooks` that prints `error: unrecognized subcommand` to stderr and exits non-zero; confirm the notice fires once/day and exit stays `0`.
- Marker: `ls "${XDG_STATE_HOME:-$HOME/.local/state}/cadence-hooks/fail-open-$(date +%Y%m%d)"` exists after the first fire.
- Doctor-gate non-impact: `cadence-hooks doctor --root .` from the cadence monorepo root exits `0`/`1` **unchanged** by this PR (no new subcommand referenced) — proves C1 does not trip `hooks-skew.yml`.

---

## Decision points — Cameron's calls

1. **#236 wiring shape — Option A vs B.** *(Recommended: **A**.)* Extend the existing `session start` disclosure (no new subcommand, no plugin PR, no doctor-CI gate, ships on next binary release) — or a dedicated `session posture-warn` subcommand wired into `cadence-canon/hooks/hooks.json` (cleaner separation, but requires binary-release-before-plugin sequencing). **Recommendation: A** — the posture line is one string on a surface that already runs at SessionStart; a whole subcommand + release-ordering dance buys only cosmetic separation.

2. **Shared-predicate refactor location.** *(Recommended: **lift to `crates/core`**.)* To keep "the line fires" and "the wall blocks" as **one** predicate, extract the exemption/primary-checkout check. `enforce_worktree` lives in `crates/guardrails`, `session start` in `crates/session`; both depend on `crates/core`. **Recommendation:** put the pure `would_block_here(dir)`-style predicate in `cadence_hooks_core` and call it from both. Alternative (more surface, more drift risk): duplicate a trimmed copy in `start.rs`.

3. **#156 — run the runtime probe now, or leave fully deferred?** *(Recommended: **run the probe, defer the guard**.)* The docs don't settle whether SessionStart carries `permission_mode`; a 10-minute empirical probe (Task B1) settles it durably and updates the issue with ground truth, without committing to build. The guard itself stays gated on the behavioral trip-wire regardless. **Recommendation:** probe now (cheap, kills a stale-claim cycle), build later only if the wire trips.

4. **Task A0 tense fix — now or with C1?** *(Recommended: **leave as-is if C1 rides the same train; soften only if C1 slips**.)* `docs/testing.md:81-82` already asserts the wrapper "now emits" the notice. If C1 lands together, it's accurate; if C1 is deferred, soften to future tense to avoid documenting unshipped behavior.

5. **cadence-lab persona wrapper copy — follow-up now or later?** *(Recommended: **file a follow-up on cadence-lab**.)* The 6th wrapper copy (`cadence-lab/plugins/persona/hooks/run-cadence-hooks.sh`) is a separate repo; keeping it in sync is real but out of scope for the cadence PR. **Recommendation:** file a one-line cadence-lab issue referencing cadence#223 so the persona copy doesn't silently diverge.

---

## Out of scope

- **The `enforce-worktree` subprocess-coverage gap (#234)** — `git checkout -b`, `uv add`, `sed -i`, redirects still slip past the mutation trigger. The posture disclosure *shrinks its window* (announces the wall at entry) but does not close it; #234 remains its own fix (planned separately in `2026-07-06-worktree-guard-correctness.md`).
- **The #156 backstop guard itself** — deferred; only the runtime probe + field-addition prerequisites are documented here.
- **cadence#278** (attune / using-worktrees entry-steering prose, the methodology half of #236) — lives on the cadence plugin tracker; not touched by this binary-side plan.
- **The durable-state / CP4 attune re-fire fix** (cadence#174, claude-configurations#313) — the deeper fix #156's comment points at; separate track.
- **Any change to fail-open exit-code semantics** (ADR-0001) — this cluster adds *narration only*; no block/allow decision or exit code changes.
- **cadence-lab persona wrapper edit** — separate repo; follow-up issue only (Decision Point 5).
- **Consolidating the 5 hand-synced wrapper copies behind a generator** — a real latent maintenance hazard (no sync script exists today), but a bigger refactor than this cluster; note it, don't do it here.
