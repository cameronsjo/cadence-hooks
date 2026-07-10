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

use cadence_hooks_core::{
    Check, HookEvent, HookInput, Logger, MetricsInput, Outcome, decide_check, emit_and_exit,
    guard_interactive_terminal,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process;
use std::time::Instant;

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
            cadence_hooks_metrics::log_failopen(
                "parse",
                crate::registry::plugin_for(hook_name),
                Some(hook_name),
                env!("CARGO_PKG_VERSION"),
            );
            process::exit(0); // Fail open on parse errors (ADR-0001)
        }
    };
    match decide_check(check, &input) {
        // Effort-skipped → silent Allow, nothing to record.
        None => process::exit(Outcome::Allow.code()),
        Some(result) => {
            // Record before emitting. Both writes are fully fail-open, so neither
            // can perturb the block message or the exit code that follows.
            cadence_hooks_metrics::log_denial(hook_name, event, &input, result.outcome);
            // A bypass-allow rode through an active dismissal / env switch. Record
            // *that a guard was stepped outside of* — the one event the denial log
            // can't see (it drops Allow). Fully fail-open, same as log_denial: a
            // failed write never perturbs the allow or its exit code (ADR-0001).
            if let Some(prov) = &result.bypass {
                cadence_hooks_metrics::log_bypass(cadence_hooks_metrics::BypassEvent::used(
                    hook_name, &input, prov,
                ));
            }
            log_deadline_degradation(hook_name, crate::registry::plugin_for(hook_name));
            cadence_hooks_metrics::log_timing(
                hook_name,
                crate::registry::plugin_for(hook_name).unwrap_or("unknown"),
                event.name(),
                started.elapsed().as_millis(),
                input.session_id(),
            );
            emit_and_exit(&result, event);
        }
    }
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
            let result = catch_unwind(AssertUnwindSafe(|| logger.run(&input)));
            if result.is_err() {
                cadence_hooks_metrics::log_failopen(
                    "panic",
                    namespace,
                    hook,
                    env!("CARGO_PKG_VERSION"),
                );
            }
        }
        Err(_) => {
            cadence_hooks_metrics::log_failopen(
                "parse",
                namespace,
                hook,
                env!("CARGO_PKG_VERSION"),
            );
        }
    }
    log_deadline_degradation(hook.unwrap_or("unknown"), namespace);
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
/// checks degraded to their ordinary fail-open arms. Both writes are fully
/// fail-open and never perturb the verdict or exit code that follows.
fn log_deadline_degradation(hook_name: &str, namespace: Option<&'static str>) {
    use cadence_hooks_core::deadline;
    if deadline::suppressed_block() {
        cadence_hooks_metrics::log_failopen(
            "deadline_block_suppressed",
            namespace,
            Some(hook_name),
            env!("CARGO_PKG_VERSION"),
        );
        eprintln!(
            "cadence-hooks: {hook_name}: git probe deadline exceeded; a fail-closed block was degraded to allow (see failopen.jsonl)"
        );
    } else if deadline::hit() {
        cadence_hooks_metrics::log_failopen(
            "deadline",
            namespace,
            Some(hook_name),
            env!("CARGO_PKG_VERSION"),
        );
        eprintln!(
            "cadence-hooks: {hook_name}: git probe deadline exceeded; git-backed checks degraded to fail-open"
        );
    }
}
