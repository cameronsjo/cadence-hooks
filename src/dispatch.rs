//! Logged check dispatch: the binary-level bridge that records a guard's
//! decision to `denials.jsonl` between deciding and exiting.
//!
//! `core` decides (it holds the [`Check`] trait) but cannot reach the metrics
//! crate's writer (metrics depends on core, not the reverse); the binary depends
//! on both **and** is the only layer that knows the canonical registry hook name
//! (`Check::name()` diverges from it — e.g. `terminology-guard` vs the registry
//! `terminology`). So the denial write lives here, calling
//! [`cadence_hooks_metrics::log_denial`] with the name threaded from
//! `main::hook_name`.
//!
//! This mirrors [`cadence_hooks_core::run_check_from_stdin`] step for step — the
//! interactive-terminal guard, fail-open stdin parse, effort-skip — and adds
//! exactly one call (the denial write) on the decided-outcome path, so the block
//! the guard emits and its exit code are byte-for-byte unchanged.

use cadence_hooks_core::{
    Check, HookEvent, HookInput, Outcome, decide_check, emit_and_exit, guard_interactive_terminal,
};
use std::process;

/// Run a single check from stdin, record its decision to `denials.jsonl`, then
/// emit and exit exactly as [`cadence_hooks_core::run_check_from_stdin`] would.
///
/// `hook` is the canonical registry name from `main::hook_name`; when `None`
/// (e.g. a subcommand with no registry mapping) it falls back to `check.name()`.
pub fn run_logged_check(check: &dyn Check, event: HookEvent, hook: Option<&str>) -> ! {
    guard_interactive_terminal(check.name(), Some(event), None);
    let input = match HookInput::from_stdin() {
        Ok(input) => input,
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            process::exit(0); // Fail open on parse errors (ADR-0001)
        }
    };
    match decide_check(check, &input) {
        // Effort-skipped → silent Allow, nothing to record.
        None => process::exit(Outcome::Allow.code()),
        Some(result) => {
            // Record before emitting. The write is fully fail-open, so it cannot
            // perturb the block message or the exit code that follows.
            cadence_hooks_metrics::log_denial(
                hook.unwrap_or_else(|| check.name()),
                event,
                &input,
                result.outcome,
            );
            emit_and_exit(&result, event);
        }
    }
}
