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
    Check, CheckResult, HookEvent, HookInput, Logger, MetricsInput, Outcome, decide_check,
    emit_and_exit, guard_interactive_terminal,
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
            if codex_fail_closed(hook_name) {
                eprintln!(
                    "cadence-hooks: security-critical hook input could not be parsed; \
                     blocking because the guard cannot prove the operation safe. \
                     Fix the hook payload/schema or run the reviewed operation yourself."
                );
                process::exit(2);
            }
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
            if codex_fail_closed(hook_name) {
                eprintln!(
                    "cadence-hooks: {error}; blocked because security-critical patch \
                     targets could not be enumerated. Review the patch and retry with \
                     a parseable operation or apply it yourself."
                );
                process::exit(2);
            }
            eprintln!("cadence-hooks: {error}");
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
            let mut aggregate = CheckResult::allow();
            let mut messages = Vec::new();
            for target in &normalized_inputs {
                let Some(result) = decide_check(check, target) else {
                    continue;
                };
                cadence_hooks_metrics::log_denial(hook_name, event, target, result.outcome);
                if let Some(prov) = &result.bypass {
                    cadence_hooks_metrics::log_bypass(cadence_hooks_metrics::BypassEvent::used(
                        hook_name, target, prov,
                    ));
                }
                aggregate.outcome = aggregate.outcome.merge(result.outcome);
                if let Some(message) = result.message {
                    messages.push(message);
                }
            }
            aggregate.message = (!messages.is_empty()).then(|| messages.join("\n\n"));
            Some(aggregate)
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
        Some(result) => {
            // A Block/Ask outcome stopped the operation, so a timed-out probe
            // did not degrade to fail-open — don't emit the plain deadline row
            // (Allow/Nudge let the tool proceed, so those still do).
            let enforced = matches!(result.outcome, Outcome::Block | Outcome::Ask);
            emit_telemetry_tail(enforced);
            emit_and_exit(&result, event);
        }
    }
}

fn codex_fail_closed(hook_name: &str) -> bool {
    cadence_hooks_core::is_codex_harness() && crate::registry::is_security_critical(hook_name)
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
