//! Per-process wall-clock budget for subprocess spawns (cadence-hooks#271).
//!
//! Every hook check runs as its own short-lived process with an external
//! hooks.json timeout (typically 5s). When a spawned `git` stalls — cloud-synced
//! `.git`, sync-client locks, load — the external timeout kills this process
//! from outside, and the kill is unloggable: the guard silently fails open.
//! This module gives the process an *internal* deadline safely under the
//! external one, so git probes are abandoned in time for the guard to decide,
//! exit, and record the degradation itself (`failopen.jsonl` via the binary
//! layer — this crate cannot depend on metrics).
//!
//! The budget is shared across all spawns in one process: the second probe
//! gets only what the first left. State is process-global (`OnceLock` /
//! `AtomicBool`) — each hook invocation is a fresh process, so "process" and
//! "invocation" coincide; CLI paths that never `arm()` fall back to a
//! per-spawn cap instead of a shared budget (doctor's many sequential probes
//! keep working, but none can hang forever).
//!
//! `CADENCE_HOOK_DEADLINE_MS` tunes the budget. It is security-relevant:
//! guards treat a timed-out probe as fail-open, so a tiny value would be a
//! guard-softening primitive and a huge value would let the deadline never
//! fire (both injectable via a repo `.envrc` or CI env). Positive values
//! therefore clamp into [`MIN_BUDGET_MS`, `MAX_BUDGET_MS`]. `0` disables the
//! deadline entirely — the *safe* direction: spawns revert to unbounded and
//! fail-closed arms stay fail-closed.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Default shared budget. Bounds only in-process git time — the wrapper /
/// fork-exec slice before `main` runs is outside our control, so this must
/// leave real headroom under the 5s external hooks.json timeout.
const DEFAULT_BUDGET_MS: u64 = 3000;

/// Floor for positive overrides. Below this a slow-but-healthy host would
/// time out routine probes, quietly converting fail-closed guard arms to
/// fail-open (see module doc).
const MIN_BUDGET_MS: u64 = 1000;

/// Ceiling for positive overrides. A value at or above the tightest 5s
/// external hooks.json timeout would let the internal deadline never fire —
/// reverting to the pre-#271 silent external-kill this module exists to
/// prevent. A caller who genuinely wants no bound uses `0` (disabled), not a
/// huge value; a repo-injected huge value clamps here instead of neutralizing
/// the mitigation.
const MAX_BUDGET_MS: u64 = 4500;

static HOOK_START: OnceLock<Instant> = OnceLock::new();
static BUDGET: OnceLock<Option<Duration>> = OnceLock::new();
static DEADLINE_HIT: AtomicBool = AtomicBool::new(false);
static SUPPRESSED_BLOCK: AtomicBool = AtomicBool::new(false);

/// What a spawn site should do with its next subprocess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetState {
    /// A hook invocation armed the shared budget; this much remains.
    Armed(Duration),
    /// No hook armed the budget (CLI path) — cap each spawn individually
    /// at the full configured budget.
    Unarmed(Duration),
    /// `CADENCE_HOOK_DEADLINE_MS=0` — no bounding at all.
    Disabled,
}

/// Start the shared budget clock. Idempotent; called at the top of the hook
/// dispatch paths (never on CLI paths).
pub fn arm() {
    HOOK_START.get_or_init(Instant::now);
}

/// The configured budget: `None` means disabled.
fn budget() -> Option<Duration> {
    *BUDGET.get_or_init(|| budget_from(std::env::var("CADENCE_HOOK_DEADLINE_MS").ok().as_deref()))
}

/// Parse a raw `CADENCE_HOOK_DEADLINE_MS` value. Pure for unit tests.
///
/// Unset/empty/garbage → default; `0` → disabled (`None`); positive values
/// clamp into [`MIN_BUDGET_MS`, `MAX_BUDGET_MS`].
fn budget_from(raw: Option<&str>) -> Option<Duration> {
    match raw.map(str::trim) {
        None | Some("") => Some(Duration::from_millis(DEFAULT_BUDGET_MS)),
        Some(s) => match s.parse::<u64>() {
            Ok(0) => None,
            // Clamp both ends: a tiny value is a guard-softening primitive, a
            // huge value neutralizes the mitigation (see the const docs).
            Ok(ms) => Some(Duration::from_millis(
                ms.clamp(MIN_BUDGET_MS, MAX_BUDGET_MS),
            )),
            Err(_) => Some(Duration::from_millis(DEFAULT_BUDGET_MS)),
        },
    }
}

/// Budget available to the next spawn.
pub fn state() -> BudgetState {
    match budget() {
        None => BudgetState::Disabled,
        Some(total) => match HOOK_START.get() {
            None => BudgetState::Unarmed(total),
            Some(start) => BudgetState::Armed(remaining_at(total, start.elapsed())),
        },
    }
}

/// Shared-budget arithmetic. Pure for unit tests.
fn remaining_at(total: Duration, elapsed: Duration) -> Duration {
    total.saturating_sub(elapsed)
}

/// Record that a spawn was abandoned (or skipped) at the deadline. The binary
/// layer reads this at exit to emit the loud fail-open row + breadcrumb.
pub fn note_hit() {
    DEADLINE_HIT.store(true, Ordering::Relaxed);
}

/// Whether any spawn in this process was abandoned at the deadline.
pub fn hit() -> bool {
    DEADLINE_HIT.load(Ordering::Relaxed)
}

/// Record that a *fail-closed* guard arm downgraded its block to allow
/// because the probe it needed timed out. This is the sharper of the two
/// degradations — the binary layer emits it as its own fail-open reason so
/// "git checks were slow" and "an enforcement block was bypassed" stay
/// distinguishable in telemetry.
pub fn note_suppressed_block() {
    SUPPRESSED_BLOCK.store(true, Ordering::Relaxed);
}

/// Whether a fail-closed arm suppressed a block this process (see
/// [`note_suppressed_block`]).
pub fn suppressed_block() -> bool {
    SUPPRESSED_BLOCK.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_defaults_when_unset_or_empty() {
        assert_eq!(
            budget_from(None),
            Some(Duration::from_millis(DEFAULT_BUDGET_MS))
        );
        assert_eq!(
            budget_from(Some("")),
            Some(Duration::from_millis(DEFAULT_BUDGET_MS))
        );
        assert_eq!(
            budget_from(Some("  ")),
            Some(Duration::from_millis(DEFAULT_BUDGET_MS))
        );
    }

    #[test]
    fn budget_zero_disables() {
        assert_eq!(budget_from(Some("0")), None);
    }

    #[test]
    fn budget_clamps_small_positive_values_to_floor() {
        // A tiny positive value is a guard-softening primitive — clamp, don't honor.
        assert_eq!(
            budget_from(Some("1")),
            Some(Duration::from_millis(MIN_BUDGET_MS))
        );
        assert_eq!(
            budget_from(Some("400")),
            Some(Duration::from_millis(MIN_BUDGET_MS))
        );
        assert_eq!(budget_from(Some("1000")), Some(Duration::from_millis(1000)));
    }

    #[test]
    fn budget_honors_values_in_range() {
        assert_eq!(budget_from(Some("4200")), Some(Duration::from_millis(4200)));
    }

    #[test]
    fn budget_clamps_large_values_to_ceiling() {
        // A huge value would let the internal deadline never fire — clamp so a
        // repo-injected value can't neutralize the mitigation. Use 0 to disable.
        assert_eq!(
            budget_from(Some("600000")),
            Some(Duration::from_millis(MAX_BUDGET_MS))
        );
    }

    #[test]
    fn budget_garbage_falls_back_to_default() {
        assert_eq!(
            budget_from(Some("fast")),
            Some(Duration::from_millis(DEFAULT_BUDGET_MS))
        );
        assert_eq!(
            budget_from(Some("-5")),
            Some(Duration::from_millis(DEFAULT_BUDGET_MS))
        );
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let total = Duration::from_millis(3000);
        assert_eq!(
            remaining_at(total, Duration::from_millis(1000)),
            Duration::from_millis(2000)
        );
        assert_eq!(
            remaining_at(total, Duration::from_millis(9000)),
            Duration::ZERO
        );
    }

    #[test]
    fn hit_flag_sets_and_reads() {
        // Process-global — other tests in this binary may also set it, so only
        // assert the one-way transition.
        note_hit();
        assert!(hit());
    }
}
