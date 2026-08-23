//! Logged dispatch: the binary-level bridge that records a hook's decision
//! (`denials.jsonl`) and wall-clock time (`hooks.jsonl`) between running and
//! exiting.
//!
//! `core` decides (it holds the [`Check`] trait) but cannot reach the metrics
//! crate's writer (metrics depends on core, not the reverse); the binary depends
//! on both **and** is the only layer that knows the canonical registry hook name
//! (`Check::name()` diverges from it — e.g. `terminology-guard` vs the registry
//! `terminology`). So the denial and timing writes live here, calling
//! [`cadence_hooks_metrics::log_denial`] / [`cadence_hooks_metrics::log_timing`]
//! with the name threaded from `main::hook_name`.
//!
//! These wrappers mirror [`cadence_hooks_core::run_check_from_stdin`] /
//! [`cadence_hooks_core::run_logger_from_stdin`] step for step — the
//! interactive-terminal guard, fail-open stdin parse, effort-skip / panic-catch —
//! and add exactly two fail-open side effects (the denial write, then the timing
//! write) sequenced *after* the decision is recorded and *before* the process
//! emits and exits, so the block a guard emits, its exit code, and a logger's
//! output are all byte-for-byte unchanged.
//!
//! One deliberate divergence from core: both wrappers bracket the check/logger
//! call with `main::PANIC_GUARDED` so a panic unwinds into their `catch_unwind`
//! instead of being cut short by the global panic hook's exit
//! (cameronsjo/cadence-hooks#349). Core's `run_check_from_stdin` has no such
//! guard — it is the unlogged path, with no telemetry tail to protect.

use cadence_hooks_core::{
    BypassProvenance, Check, CheckResult, HookEvent, HookInput, Logger, MetricsInput, Outcome,
    decide_check, emit_and_exit, guard_interactive_terminal,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Debug-only, env-gated panic source for the dispatch panic-guard tests.
///
/// No check or logger has a CLI-reachable panic trigger — which is exactly why
/// cameronsjo/cadence-hooks#349 (the Check path's missing guard) survived
/// unnoticed: nothing could spawn-test the panic path end to end. This supplies
/// one, from inside the guarded region so it exercises the real
/// `catch_unwind` seam rather than a stand-in.
///
/// `#[cfg(debug_assertions)]` is load-bearing: the trigger does not exist in a
/// release binary, so a shipped build cannot be made to panic through it even
/// with `CADENCE_TEST_PANIC=1` set.
///
/// In a *debug* build it is a real enforcement bypass — it fires ahead of
/// `decide_check`, so every guard degrades to non-enforcing — and this repo runs
/// `./target/debug/cadence-hooks` routinely. So it announces itself on stderr,
/// exactly as `CADENCE_BYPASS=1` does in `main`: suppression always leaves a
/// trace (#89).
#[cfg(debug_assertions)]
fn test_panic_trigger() {
    if std::env::var("CADENCE_TEST_PANIC").as_deref() == Ok("1") {
        eprintln!(
            "⚠️  cadence-hooks: enforcement bypassed — CADENCE_TEST_PANIC=1 is forcing a \
             synthetic panic before this hook can decide (debug builds only)"
        );
        panic!("CADENCE_TEST_PANIC: synthetic panic exercising the dispatch panic guard");
    }
}

#[cfg(not(debug_assertions))]
fn test_panic_trigger() {}

/// Sets `main::PANIC_GUARDED` for as long as it is alive, clearing it on drop.
///
/// The flag must be cleared on **both** exits from a guarded region — the
/// ordinary return and the unwind — or a later panic outside the region would
/// find a guard that is no longer there and be swallowed instead of taking the
/// fail-open exit. A manual set/clear pair holds that invariant only by virtue
/// of how the two call sites happen to be written today; an `?`, an early
/// return, or a new branch slipped between them would break it silently, with
/// no test to catch it. `Drop` cannot be skipped, and — the point here — it
/// runs *during* the unwind, so the guarded and panicking paths clear the flag
/// through the same line of code.
struct PanicGuard;

impl PanicGuard {
    fn arm() -> Self {
        crate::PANIC_GUARDED.store(true, Ordering::Relaxed);
        PanicGuard
    }
}

impl Drop for PanicGuard {
    fn drop(&mut self) {
        crate::PANIC_GUARDED.store(false, Ordering::Relaxed);
    }
}

/// Run a single check from stdin, record its decision to `denials.jsonl` and its
/// wall-clock time to `hooks.jsonl`, then emit and exit exactly as
/// [`cadence_hooks_core::run_check_from_stdin`] would.
///
/// `hook` is the canonical registry name from `main::hook_name`; when `None`
/// (e.g. a subcommand with no registry mapping) it falls back to `check.name()`.
pub fn run_logged_check(check: &dyn Check, event: HookEvent, hook: Option<&str>) -> ! {
    let started = Instant::now();
    // Arm the shared subprocess deadline before any guard logic can spawn git
    // (cadence-hooks#271): probes abandon at the internal budget so the guard
    // decides and self-reports instead of being killed by the external
    // hooks.json timeout, which is unloggable.
    cadence_hooks_core::deadline::arm();
    guard_interactive_terminal(check.name(), Some(event), None);
    // Hoisted above the stdin parse so both the parse-failure arm and the
    // decided-result arm below can record against the same canonical name.
    let hook_name = hook.unwrap_or_else(|| check.name());
    let input = match HookInput::from_stdin() {
        Ok(input) => input,
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            // `e` is this binary's own message ("Failed to parse hook JSON:
            // <serde error>") — a line/column locator, never an echo of the
            // payload, so recording it keeps the no-payload posture.
            cadence_hooks_metrics::log_failopen(
                "parse",
                crate::registry::plugin_for(hook_name),
                Some(hook_name),
                env!("CARGO_PKG_VERSION"),
                Some(&e),
            );
            process::exit(0);
        }
    };
    let normalized_inputs = match input.normalized_inputs() {
        Ok(inputs) => inputs,
        Err(error) => {
            cadence_hooks_metrics::log_failopen(
                "parse",
                crate::registry::plugin_for(hook_name),
                Some(hook_name),
                env!("CARGO_PKG_VERSION"),
                Some(&error),
            );
            // The diagnostic names why normalization gave up without ever
            // echoing the patch body — `error` is this binary's own message.
            eprintln!(
                "cadence-hooks: {error}; security-critical patch targets could not \
                 be enumerated. Review the patch and retry with a parseable \
                 operation or apply it yourself."
            );
            process::exit(0);
        }
    };
    // A panicking check must not skip the telemetry writes or reach the user as
    // a hard exit. `PANIC_GUARDED` tells the global panic hook (src/main.rs) to
    // *return* instead of calling `process::exit` — a panic hook runs before
    // unwinding begins, so its exit would kill the process and this
    // `catch_unwind` would never regain control (cameronsjo/cadence-hooks#349).
    // The guard lives here rather than inside `core::decide_check` because core
    // can reach neither the metrics crate nor the canonical registry hook name
    // (see this module's header).
    // The deadline + timing writes that close out every dispatch, shared by the
    // decided arm and the panic arm so a future edit to the tail cannot land in
    // one and drift in the other. `enforced` is the only thing that differs: a
    // panic stopped nothing, so it always passes `false`.
    let emit_telemetry_tail = |enforced: bool| {
        log_deadline_degradation(hook_name, crate::registry::plugin_for(hook_name), enforced);
        cadence_hooks_metrics::log_timing(
            hook_name,
            crate::registry::plugin_for(hook_name).unwrap_or("unknown"),
            event.name(),
            started.elapsed().as_millis(),
            input.session_id(),
        );
    };
    let decided = {
        let _guard = PanicGuard::arm();
        catch_unwind(AssertUnwindSafe(|| {
            test_panic_trigger();
            let mut results = Vec::new();
            for target in &normalized_inputs {
                let Some(result) = decide_check(check, target) else {
                    continue;
                };
                results.push(result);
            }
            aggregate_results(results)
        }))
    };
    let decided = match decided {
        Ok(decided) => decided,
        Err(_) => {
            // The panic hook already printed the breadcrumb and wrote the
            // `panic` failopen row with the payload and location — one row per
            // panic. What is lost without this arm is the rest of the dispatch
            // tail, so emit it before leaving.
            emit_telemetry_tail(false);
            // Exit 1, not 0. Neither code blocks — `Outcome::code` maps every
            // non-Block outcome to 0 — so the *user's* operation proceeds
            // either way, and this arm does not need 0 to fail open. What 1
            // buys is DETECTABILITY: Claude Code surfaces a hook's stderr on a
            // non-zero, non-2 exit and discards it on 0. At 0, a check that
            // panics on every invocation — total enforcement failure for a
            // block-capable guard like `guard-gh-write` — is indistinguishable
            // in real time from one that works, with the panic breadcrumb
            // written to stderr and thrown away and the only record a
            // `failopen.jsonl` row nobody reads until they run `doctor`.
            // A panic is the loudest thing this binary can notice about itself;
            // it keeps the louder exit.
            process::exit(1);
        }
    };
    match decided {
        // Effort-skipped → silent Allow, nothing to record.
        None => process::exit(Outcome::Allow.code()),
        Some(Aggregated {
            result,
            outcomes,
            bypasses,
        }) => {
            // The audit writes run once per hook invocation, against the payload
            // the harness actually sent. Writing them inside the per-target loop
            // made denial volume proportional to the patch body — one
            // `apply_patch` with N operations wrote up to N rows per
            // security-critical hook into an uncapped `denials.jsonl`.
            //
            // But one row must not mean one decision *remembered*. `log_denial`
            // takes every target's outcome and tallies them, so a mixed
            // invocation (one Block, eleven Nudges) still records that eleven
            // nudges fired — collapsing those into the winner would silently
            // delete the denominator of every adherence rate. Bypasses are
            // deduped rather than aggregated: they are a different event class
            // with no strictest-wins ordering, and losing one loses the only
            // record that a guardrail was stepped outside of.
            cadence_hooks_metrics::log_denial(hook_name, event, &input, &outcomes);
            for provenance in &bypasses {
                cadence_hooks_metrics::log_bypass(cadence_hooks_metrics::BypassEvent::used(
                    hook_name, &input, provenance,
                ));
            }
            // A Block/Ask outcome stopped the operation, so a timed-out probe
            // did not degrade to fail-open — don't emit the plain deadline row
            // (Allow/Nudge let the tool proceed, so those still do).
            let enforced = matches!(result.outcome, Outcome::Block | Outcome::Ask);
            emit_telemetry_tail(enforced);
            // Sits AFTER the telemetry tail on purpose: a suppressed duplicate
            // is still a decision this hook made, so it stays counted in
            // `denials.jsonl` and `hooks.jsonl`. Only the operator-facing
            // emission is dropped.
            if !claim_emission(&result, &input, event, hook_name) {
                process::exit(Outcome::Nudge.code());
            }
            emit_and_exit(&result, event);
        }
    }
}

/// Should this decision's advisory context actually reach the operator?
///
/// One `hooks.json` can register the same command several times under one
/// matcher with overlapping `if:` globs, so a single tool call spawns N
/// identical hook processes that each print the same advisory
/// (claude-configurations#472). Every one of them sees the same payload, so
/// they claim the same key and only the first emits.
///
/// **Only `Nudge` is gated, and only with a non-empty message.** A `Block` or
/// `Ask` stops the operation, so suppressing its message would leave the
/// operator staring at a halted tool call with no reason given — an advisory
/// heard twice is noise, an enforcement heard zero times is a broken guard.
/// `Allow` has nothing to say. The message is part of the key, so two hooks
/// with genuinely different things to report both still speak.
///
/// **And only for a hook in `markers::DEDUPE_ELIGIBLE_HOOKS`** — the handful of
/// commands actually registered more than once in a single matcher block. Every
/// other hook reaches the operator unconditionally, whatever the key says.
fn claim_emission(
    result: &CheckResult,
    input: &HookInput,
    event: HookEvent,
    hook_name: &str,
) -> bool {
    if result.outcome != Outcome::Nudge {
        return true;
    }
    let Some(message) = result.message.as_deref().filter(|m| !m.is_empty()) else {
        return true;
    };
    cadence_hooks_core::markers::claim_tool_event_nudge(input, event, hook_name, message)
}

/// One invocation's decision, plus the two things the audit writes need that the
/// winning [`CheckResult`] cannot carry.
///
/// The winner answers "what happened to the tool call", which is the only
/// question `emit_and_exit` asks. The ledger asks two more — *which decisions
/// were made* and *which guardrails were stepped outside of* — and both are
/// properties of the whole target set. Folding them into the winner is what lost
/// them: a Block winner discards the sibling Nudges (a different event class,
/// and the denominator for every adherence rate) and every bypass ridden by a
/// target that did not win.
struct Aggregated {
    /// The strictest result: what the tool call actually gets.
    result: CheckResult,
    /// Every judged target's outcome, in judge order. The denial row's
    /// per-decision tally is computed from this, never from the winner alone.
    outcomes: Vec<Outcome>,
    /// Every DISTINCT bypass ridden across targets — one row per distinct
    /// provenance, bounded by the dismissals the user has already armed and
    /// never by patch size. Distinct rather than per-target so the ledger keeps
    /// the volume cap that moved these writes out of the loop: N targets riding
    /// one dismissal produce N identical provenances and one row.
    ///
    /// The bound is armed dismissals, not mechanisms — equality spans
    /// `reason`/`expires_at`/`armed_by_session` too, so a patch touching N repos
    /// that each carry their own armed snooze does yield N rows. Those are N
    /// genuinely distinct events a per-target ledger would also have recorded,
    /// and none of it is attacker-chosen the way target count was.
    bypasses: Vec<BypassProvenance>,
}

fn aggregate_results(mut results: Vec<CheckResult>) -> Option<Aggregated> {
    if results.is_empty() {
        return None;
    }
    let outcomes: Vec<Outcome> = results.iter().map(|result| result.outcome).collect();
    let outcome = outcomes
        .iter()
        .fold(Outcome::Allow, |merged, other| merged.merge(*other));
    let mut messages = Vec::new();
    let mut block_metadata = None;
    let mut winning_bypass = None;
    let mut bypasses: Vec<BypassProvenance> = Vec::new();
    for result in &mut results {
        // Harvested from EVERY result, not just the winners: a bypass ridden by
        // a target whose Allow lost to a sibling Block is still a guardrail that
        // was stepped outside of, and the row recording it is the whole point of
        // `bypasses.jsonl`.
        if let Some(bypass) = result.bypass.take() {
            if result.outcome == outcome && winning_bypass.is_none() {
                winning_bypass = Some(bypass.clone());
            }
            if !bypasses.contains(&bypass) {
                bypasses.push(bypass);
            }
        }
        if result.outcome != outcome {
            continue;
        }
        if let Some(message) = result.message.take() {
            messages.push(message);
        }
        if block_metadata.is_none() {
            block_metadata = result.block_metadata.take();
        }
    }
    Some(Aggregated {
        result: CheckResult {
            outcome,
            message: (!messages.is_empty()).then(|| messages.join("\n\n")),
            block_metadata,
            // Unchanged from before: the winner carries a winner's bypass, so
            // every existing consumer of this field sees what it always did.
            bypass: winning_bypass,
        },
        outcomes,
        bypasses,
    })
}

/// Run a fire-and-forget logger from stdin, record its wall-clock time to
/// `hooks.jsonl`, then **always exit 0** — exactly as
/// [`cadence_hooks_core::run_logger_from_stdin`] would.
///
/// Replicates the core wrapper faithfully (interactive-terminal guard →
/// `MetricsInput::from_stdin` → panic-caught `logger.run`) and adds exactly one
/// fail-open side effect (the timing write) before `process::exit(0)`. Logger
/// semantics are unchanged: a parse error, a missing field, or a panicking
/// implementation still degrades to a no-op exit 0.
///
/// `hook` is the canonical registry name from `main::hook_name`; `event` is
/// recorded as the constant `"logger"` since loggers react to `hook_event_name`
/// in the payload rather than a fixed [`HookEvent`].
pub fn run_logged_logger(
    logger: &dyn Logger,
    sample_override: Option<&str>,
    hook: Option<&str>,
) -> ! {
    let started = Instant::now();
    // Same arming as run_logged_check: loggers spawn git too (heartbeat,
    // backstop) and must decide inside the external hooks.json budget.
    cadence_hooks_core::deadline::arm();
    guard_interactive_terminal(logger.name(), None, sample_override);
    let namespace = crate::registry::plugin_for(hook.unwrap_or(""));
    // Capture the session id (when the payload carries one) for the timing row;
    // a parse failure leaves it `None`, matching core's fail-open-to-exit-0 path.
    let mut session_id: Option<String> = None;
    match MetricsInput::from_stdin() {
        Ok(input) => {
            session_id = input.session_id.clone();
            // A panicking logger must not skip the timing write or the exit-0
            // below. Catch the unwind so the contract holds even on a buggy
            // implementation. `AssertUnwindSafe` is required because
            // `&dyn Logger` is not `UnwindSafe`; we exit immediately
            // afterward, so there is no post-panic state to corrupt.
            //
            // `PANIC_GUARDED` is what makes this reachable at all: without it
            // the global panic hook exits the process before unwinding starts,
            // so the documented always-exit-0 contract did not actually hold
            // (cameronsjo/cadence-hooks#349).
            let _guard = PanicGuard::arm();
            // The `Err` is deliberately discarded: no `log_failopen` belongs
            // here, because the panic hook already wrote the `panic` row with
            // the payload and source location this site never had. One row per
            // panic. A logger has no result to report either way.
            //
            // Unlike the check path above, a panicking logger still exits 0 —
            // that is `run_logged_logger`'s documented contract, and a logger
            // enforces nothing, so there is no enforcement failure to make
            // visible.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                test_panic_trigger();
                logger.run(&input)
            }));
        }
        Err(e) => {
            cadence_hooks_metrics::log_failopen(
                "parse",
                namespace,
                hook,
                env!("CARGO_PKG_VERSION"),
                Some(&e),
            );
        }
    }
    // Loggers never block, so a deadline hit here is always a fail-open degradation.
    log_deadline_degradation(hook.unwrap_or("unknown"), namespace, false);
    cadence_hooks_metrics::log_timing(
        hook.unwrap_or("unknown"),
        namespace.unwrap_or("metrics"),
        "logger",
        started.elapsed().as_millis(),
        session_id.as_deref(),
    );
    process::exit(0);
}

/// Emit the loud fail-open row + stderr breadcrumb when this process's git
/// probes hit the internal deadline (cadence-hooks#271). Two tiers, sharper
/// one wins: a suppressed fail-closed block (`deadline_block_suppressed`)
/// means enforcement was actually bypassed; a plain `deadline` means git-backed
/// checks degraded to their ordinary fail-open arms.
///
/// **Both tiers require `!enforced`.** `enforced` is true when the guard's
/// final outcome was `Block` or `Ask` — the operation was stopped (exit 2) or
/// gated on the user (who then sees the prompt), so nothing silently proceeded.
/// A *silent* bypass — the only thing worth a loud row — happens exactly when
/// the tool runs anyway (Allow/Nudge). A fail-closed arm can set the sticky
/// `suppressed_block` flag on one segment's timed-out probe while a *later*,
/// purely-static check legitimately blocks the whole command (e.g.
/// `git push --force origin HEAD; git push --force origin main` — segment 1's
/// branch probe times out, segment 2 blocks with no spawn). Reporting
/// `deadline_block_suppressed` there is a false positive on the very signal
/// Phase 1.5 reads as "an ownership block was bypassed", so both tiers gate on
/// the final outcome, not just the sticky flag.
///
/// Both writes are fully fail-open and never perturb the verdict or exit code.
fn log_deadline_degradation(hook_name: &str, namespace: Option<&'static str>, enforced: bool) {
    use cadence_hooks_core::deadline;
    if deadline::suppressed_block() && !enforced {
        cadence_hooks_metrics::log_failopen(
            "deadline_block_suppressed",
            namespace,
            Some(hook_name),
            env!("CARGO_PKG_VERSION"),
            // A deadline is a timeout, not a failure carrying a message —
            // `reason` already says everything there is to say.
            None,
        );
        eprintln!(
            "cadence-hooks: {hook_name}: git probe deadline exceeded; a fail-closed block was degraded to allow (see failopen.jsonl)"
        );
    } else if deadline::hit() && !enforced {
        cadence_hooks_metrics::log_failopen(
            "deadline",
            namespace,
            Some(hook_name),
            env!("CARGO_PKG_VERSION"),
            None,
        );
        eprintln!(
            "cadence-hooks: {hook_name}: git probe deadline exceeded; git-backed checks degraded to fail-open"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{BlockMetadata, BypassKind};

    #[test]
    fn aggregate_keeps_the_winning_blocks_message_and_metadata() {
        let result = aggregate_results(vec![
            CheckResult::nudge("advisory"),
            CheckResult::block_structured(
                "blocked",
                BlockMetadata {
                    rule_id: "test-rule".to_string(),
                    fix: "--safe".to_string(),
                    allowed_owners: Vec::new(),
                    severity: "error",
                },
            ),
        ])
        .expect("aggregate");

        assert_eq!(result.result.outcome, Outcome::Block);
        assert_eq!(result.result.message.as_deref(), Some("blocked"));
        assert_eq!(
            result
                .result
                .block_metadata
                .as_ref()
                .map(|metadata| metadata.fix.as_str()),
            Some("--safe")
        );
        // Every judged target's outcome survives, in judge order — the denial
        // ledger tallies from this, so a losing Nudge must still be here.
        assert_eq!(result.outcomes, vec![Outcome::Nudge, Outcome::Block]);
    }

    #[test]
    fn aggregate_returns_none_when_every_target_is_effort_skipped() {
        assert!(aggregate_results(Vec::new()).is_none());
    }

    /// A bypass ridden by a target whose Allow LOST to a sibling Block must
    /// still reach the ledger. Harvesting only from winners dropped it: the
    /// aggregate is Block, the Allow is skipped, and the only record that a
    /// guardrail was stepped outside of is gone.
    #[test]
    fn aggregate_harvests_a_bypass_from_a_losing_target() {
        let mut allowed = CheckResult::allow();
        allowed.bypass = Some(BypassProvenance {
            kind: BypassKind::Dismissal,
            mechanism: "dismiss-prevent-secret-writes".to_string(),
            reason: Some("rotating the fixture".to_string()),
            expires_at: None,
            armed_by_session: None,
        });

        let aggregated =
            aggregate_results(vec![allowed, CheckResult::block("blocked")]).expect("aggregate");

        assert_eq!(aggregated.result.outcome, Outcome::Block);
        assert_eq!(
            aggregated
                .bypasses
                .iter()
                .map(|provenance| provenance.mechanism.as_str())
                .collect::<Vec<_>>(),
            ["dismiss-prevent-secret-writes"],
            "a losing target's bypass must survive aggregation"
        );
    }

    /// Deduped, not accumulated: N targets riding ONE dismissal are one event,
    /// so the write keeps the volume cap that moved it out of the per-target
    /// loop. Two distinct mechanisms are two events and both survive.
    #[test]
    fn aggregate_dedupes_identical_bypasses_but_keeps_distinct_ones() {
        let provenance = |mechanism: &str| BypassProvenance {
            kind: BypassKind::Dismissal,
            mechanism: mechanism.to_string(),
            reason: None,
            expires_at: None,
            armed_by_session: None,
        };
        let carrying = |mechanism: &str| {
            let mut result = CheckResult::allow();
            result.bypass = Some(provenance(mechanism));
            result
        };

        let aggregated = aggregate_results(vec![
            carrying("dismiss-guard-rm"),
            carrying("dismiss-guard-rm"),
            carrying("dismiss-guard-rm"),
            carrying("CADENCE_ALLOW_MAIN"),
        ])
        .expect("aggregate");

        assert_eq!(
            aggregated
                .bypasses
                .iter()
                .map(|provenance| provenance.mechanism.as_str())
                .collect::<Vec<_>>(),
            ["dismiss-guard-rm", "CADENCE_ALLOW_MAIN"],
            "three rides of one dismissal are one event; a second mechanism is another"
        );
    }

    // --- claim_emission (the per-tool-event advisory dedupe gate, #472) ---

    /// The payload every process of one fan-out sees: same session, same
    /// command, same everything.
    fn fanout_input(command: &str) -> HookInput {
        HookInput {
            session_id: Some("sid-472".into()),
            ..cadence_hooks_core::test_builders::make_bash(command)
        }
    }

    #[test]
    fn dedupe_suppresses_a_repeat_nudge() {
        let tmp = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(tmp.path(), || {
            let input = fanout_input("git push");
            let nudge = CheckResult::nudge("mind the overshare");

            assert!(
                claim_emission(&nudge, &input, HookEvent::PreToolUse, "warn-overshare"),
                "the first process of the fan-out must emit"
            );
            assert!(
                !claim_emission(&nudge, &input, HookEvent::PreToolUse, "warn-overshare"),
                "a second identical registration must stay silent"
            );
            assert!(
                claim_emission(
                    &CheckResult::nudge("a different advisory"),
                    &input,
                    HookEvent::PreToolUse,
                    "warn-overshare"
                ),
                "a genuinely different message is different information and must reach the operator"
            );
        });
    }

    #[test]
    fn dedupe_never_suppresses_a_block() {
        let tmp = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(tmp.path(), || {
            let input = fanout_input("git push --force origin main");
            let block = CheckResult::block("blocked");
            let ask = CheckResult {
                outcome: Outcome::Ask,
                message: Some("confirm?".to_string()),
                block_metadata: None,
                bypass: None,
            };

            for _ in 0..3 {
                assert!(
                    claim_emission(&block, &input, HookEvent::PreToolUse, "git-safety"),
                    "an enforcement message must never be deduped away"
                );
                assert!(
                    claim_emission(&ask, &input, HookEvent::PreToolUse, "git-safety"),
                    "an Ask gates the operator and must always carry its reason"
                );
            }
        });
    }

    /// The #472 regression fixture: one multi-command Bash call, registered
    /// under overlapping `if:` globs that each match a different segment
    /// (`git commit`, `git push`, `gh pr create`), spawns three processes with
    /// identical payloads — and must produce exactly ONE emission. The fixture
    /// hook is `warn-overshare` — a hook still on `DEDUPE_ELIGIBLE_HOOKS` with
    /// genuinely overlapping registrations (`nudge-polish-before-pr` left the
    /// list when cadence#912 consolidated its wiring).
    #[test]
    fn dedupe_collapses_a_multi_command_fan_out_to_one_emission() {
        let tmp = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(tmp.path(), || {
            let input = fanout_input("git commit -m 'ship it' && git push && gh pr create --fill");
            let nudge = CheckResult::nudge("possible overshare in the outgoing content");

            let emissions = (0..3)
                .filter(|_| claim_emission(&nudge, &input, HookEvent::PreToolUse, "warn-overshare"))
                .count();

            assert_eq!(
                emissions, 1,
                "three overlapping registrations of one tool event must nudge once"
            );
        });
    }

    /// The narrowing that makes the gate safe: a hook that is NOT a known
    /// fan-out offender is never gated, so two same-event nudges from it both
    /// reach the operator even when their payload fingerprints identically.
    ///
    /// Shaped after `warn-empty-answers` / `warn-recommended-option`, which fire
    /// per *question* within one `AskUserQuestion` call — same session, same
    /// tool payload, genuinely different things to say.
    #[test]
    fn non_allowlisted_hook_is_never_gated() {
        let tmp = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(tmp.path(), || {
            let input = fanout_input("irrelevant — the payload is identical either way");
            let nudge = CheckResult::nudge("that answer set looks empty");

            for _ in 0..5 {
                assert!(
                    claim_emission(&nudge, &input, HookEvent::PreToolUse, "warn-empty-answers"),
                    "a hook outside DEDUPE_ELIGIBLE_HOOKS must never be suppressed, \
                     however identical the event looks"
                );
            }

            // Positive control: the same identical repeat IS collapsed for an
            // allowlisted hook, so the assertion above proves the allowlist and
            // not a dead gate.
            assert!(claim_emission(
                &nudge,
                &input,
                HookEvent::PreToolUse,
                "warn-overshare"
            ));
            assert!(
                !claim_emission(&nudge, &input, HookEvent::PreToolUse, "warn-overshare"),
                "the gate must still collapse a real fan-out"
            );
        });
    }
}
