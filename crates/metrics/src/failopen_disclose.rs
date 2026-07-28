//! SessionStart disclosure when the guard suite has recently been failing open
//! (cameronsjo/cadence-hooks#277).
//!
//! #271/PR #273 made a git-probe timeout *loud* in the ledger — `deadline` and
//! `deadline_block_suppressed` rows in `failopen.jsonl`, plus a `doctor`
//! latency scan. Both are **pull**: on the affected host nobody runs `doctor`,
//! so the suite can sit mostly non-enforcing for days with nothing reaching the
//! operator. #271's own reporter ran that way. This is the **push** half — the
//! machine says it at session start instead of waiting to be asked.
//!
//! Two tiers, because the two ledger rows mean different things (the shaping
//! asked for on #277):
//!
//! - **degraded** — `deadline` rows at or above a threshold. Probes timed out
//!   and guards fell back to their ordinary fail-open arms. Load-correlated,
//!   often benign in ones and twos, which is why it is threshold-gated.
//! - **not enforcing** — any `deadline_block_suppressed` row. A fail-closed
//!   guard arm downgraded a real block to an allow: enforcement was actually
//!   bypassed. One row is the whole finding, so this tier ignores the
//!   threshold and fires at 1.
//!
//! Gated once per calendar day per tier by a marker file, mirroring
//! [`crate::warn_stale`] — the alarm this replaces was ignorable partly because
//! it was noise. A tier *escalation* (degraded → not enforcing) re-fires the
//! same day; a rising count within one tier does not, the same trade
//! `warn_stale`'s flatline token makes.
//!
//! Fail-open everywhere (ADR-0001): a missing ledger, an unreadable file, a bad
//! env value, or a marker write error all resolve to silence or a plain line —
//! never a block, never a panic. This module only ever returns an optional
//! string; the caller decides what to do with it.

use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::log_failopen::{FailopenCounts, recent_failopen_report};

/// How far back the disclosure looks. A **day**, not `doctor`'s 7-day window:
/// this line answers "are guards enforcing *right now*", so a burst that ended
/// last Tuesday must age out rather than nag through a week of healthy
/// sessions. Fixed rather than env-tunable — the threshold below is the knob
/// worth exposing, and two interacting knobs make a silent line hard to
/// diagnose.
const DISCLOSE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Default `deadline` rows in the window before the degraded tier speaks, when
/// `CADENCE_FAILOPEN_DISCLOSE_MIN` is unset, zero, or unparseable.
///
/// Three, because one timeout is a slow disk moment and two is a coincidence;
/// three inside a single day is a pattern the operator can act on. The
/// not-enforcing tier deliberately does not consult this — see the module doc.
const DEFAULT_DISCLOSE_MIN: u64 = 3;

/// Which tier fired. Ordered by severity, and the marker token is derived from
/// it so an escalation is not suppressed by the earlier tier's marker.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Tier {
    /// Probes timed out; guards fell back to their fail-open arms.
    Degraded,
    /// A guard that should have blocked allowed instead.
    NotEnforcing,
}

/// Threshold from `CADENCE_FAILOPEN_DISCLOSE_MIN`, default
/// `DEFAULT_DISCLOSE_MIN`.
///
/// Mirrors `warn_stale::stale_days`: trims, parses `u64`, rejects zero and
/// junk. A pure resolver ([`disclose_min_from`]) does the work so the fallbacks
/// are unit-testable without process-global env. Private, unlike its
/// `warn_stale` counterpart — nothing outside this module reports the
/// configured threshold yet, and `doctor` can have it exported the day it does.
fn disclose_min() -> u64 {
    disclose_min_from(std::env::var("CADENCE_FAILOPEN_DISCLOSE_MIN").ok())
}

/// Pure resolver behind [`disclose_min`]. `None`, zero, or an unparseable value
/// all fall back to [`DEFAULT_DISCLOSE_MIN`]. Zero is rejected rather than
/// honored: a threshold of 0 would fire on an empty window forever.
fn disclose_min_from(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_DISCLOSE_MIN)
}

/// The tier the windowed counts warrant, or `None` for silence. Pure.
///
/// `deadline_block_suppressed` is checked first and unconditionally: it is the
/// sharper row, and a machine with one suppressed block and two deadlines must
/// report the suppression rather than fall silent under the degraded
/// threshold.
///
/// This fires on an absolute count, not the rate cadence-hooks#277 proposed
/// ("68% of guard runs hit the deadline"): the telemetry carries no
/// total-invocation denominator to divide by. The two are not equivalent —
/// a busy host can pass the count while failing open a small fraction of the
/// time, and a quiet one can trip it while barely running guards at all. Revisit
/// if a denominator ever lands.
fn tier_for(counts: &FailopenCounts, min: u64) -> Option<Tier> {
    if counts.deadline_block_suppressed > 0 {
        Some(Tier::NotEnforcing)
    } else if counts.deadline >= min {
        Some(Tier::Degraded)
    } else {
        None
    }
}

/// The short label a tier is remembered by in the once-per-day marker. Carries
/// the tier but **not** the counts, so a count climbing 3 → 9 within one tier
/// stays silent while an escalation to a new tier speaks the same day.
fn tier_token(tier: Tier) -> &'static str {
    match tier {
        Tier::Degraded => "degraded",
        Tier::NotEnforcing => "not-enforcing",
    }
}

/// The window as whole hours, floored at 1 so a sub-hour window (tests, a
/// future tuning) never renders as "the last 0h".
fn window_hours(window: Duration) -> u64 {
    (window.as_secs() / 3_600).max(1)
}

/// The disclosure line: what happened, how many, over what window, and where to
/// look. One sentence per tier, in the plain prose the other SessionStart
/// disclosure parts use — no emoji, since this joins the posture/peer/plan
/// block rather than the guardrails terminal output.
fn disclosure_message(tier: Tier, counts: &FailopenCounts, window: Duration) -> String {
    let hours = window_hours(window);
    match tier {
        Tier::Degraded => format!(
            "cadence-hooks: {} guard probe(s) hit the deadline in the last {hours}h — guards on \
             this machine degraded to their fail-open arms and may not be enforcing. Run \
             `cadence-hooks doctor`; the rows are in the metrics dir's `failopen.jsonl`.",
            counts.deadline
        ),
        Tier::NotEnforcing => format!(
            "cadence-hooks: guards are NOT enforcing — {} block(s) were suppressed by a probe \
             timeout in the last {hours}h, so a guard that should have blocked allowed instead. \
             Run `cadence-hooks doctor`; the rows are in the metrics dir's `failopen.jsonl`.",
            counts.deadline_block_suppressed
        ),
    }
}

/// Basename of the once-per-day marker under `<metrics_dir>/state/`. The gate
/// itself is [`crate::common::claim_daily_alarm`], shared with
/// [`crate::warn_stale`] so the two alarms cannot drift apart.
const MARKER_FILE: &str = "failopen_warn.date";

/// Testable core: ledger dir, window, clock, and threshold injected. Reads the
/// windowed fail-open counts, picks a tier, claims today's slot for it, and
/// returns the disclosure line on the first sighting of that tier today —
/// `None` when healthy, already disclosed, or on any fail-open path.
///
/// Claiming the slot writes the marker as a side effect, exactly as
/// `warn_stale` does.
pub fn failopen_disclosure_line(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    min: u64,
) -> Option<String> {
    // The `current_version` argument only narrows `version_mismatch`, which
    // this disclosure never reads — the deadline pair is counted across
    // versions by design (it is environment-correlated, not version-
    // correlated). Passing this crate's own version keeps the call honest
    // without affecting either count. No recency reasons: the line needs
    // counts only.
    let (counts, _) = recent_failopen_report(dir, window, now, env!("CARGO_PKG_VERSION"), &[]);
    let tier = tier_for(&counts, min)?;

    crate::common::claim_daily_alarm(dir, MARKER_FILE, tier_token(tier))
        .then(|| disclosure_message(tier, &counts, window))
}

/// The disclosure for the live metrics dir, over the shipped window and the
/// configured threshold. The seam `session start` composes into its
/// SessionStart block — kept separate from [`failopen_disclosure_line`] so the
/// core stays free of process-global env and wall-clock reads.
pub fn disclosure_line() -> Option<String> {
    failopen_disclosure_line(
        &crate::metrics_dir(),
        DISCLOSE_WINDOW,
        SystemTime::now(),
        disclose_min(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;
    use crate::log_failopen::log_failopen;
    use tempfile::TempDir;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    /// Where [`crate::common::claim_daily_alarm`] puts this module's marker.
    fn marker_path(dir: &Path) -> std::path::PathBuf {
        dir.join("state").join(MARKER_FILE)
    }

    /// Append `n` rows of `reason` to `<dir>/failopen.jsonl` through the real
    /// writer, so the fixture and production share one row shape — including
    /// the `ts` format the windowing compares lexicographically, which a
    /// hand-built fixture would have to re-derive.
    ///
    /// `log_failopen` resolves its target from `CADENCE_METRICS_DIR`, so the
    /// write is pinned under the crate-wide `ENV_LOCK` — the same helper shape
    /// every other module in this crate uses, sharing the one lock rather than
    /// minting a sibling.
    fn write_rows(dir: &Path, reason: &str, n: u64) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        for _ in 0..n {
            log_failopen(reason, Some("guardrails"), Some("guard-rm"), "1.0.0", None);
        }
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    // --- threshold resolution ---

    #[test]
    fn disclose_min_defaults_and_rejects_junk() {
        assert_eq!(disclose_min_from(None), DEFAULT_DISCLOSE_MIN);
        assert_eq!(disclose_min_from(Some("".into())), DEFAULT_DISCLOSE_MIN);
        assert_eq!(disclose_min_from(Some("0".into())), DEFAULT_DISCLOSE_MIN);
        assert_eq!(disclose_min_from(Some("nope".into())), DEFAULT_DISCLOSE_MIN);
        assert_eq!(disclose_min_from(Some(" 7 ".into())), 7);
    }

    // --- tier selection (pure) ---

    #[test]
    fn tier_is_none_below_threshold() {
        let counts = FailopenCounts {
            deadline: 2,
            ..Default::default()
        };
        assert_eq!(tier_for(&counts, 3), None);
    }

    #[test]
    fn tier_is_degraded_at_threshold() {
        let counts = FailopenCounts {
            deadline: 3,
            ..Default::default()
        };
        assert_eq!(tier_for(&counts, 3), Some(Tier::Degraded));
    }

    #[test]
    fn one_suppressed_block_outranks_a_sub_threshold_deadline_count() {
        // The sharper row must not be masked by the degraded tier's threshold:
        // enforcement was actually bypassed, which is the whole finding.
        let counts = FailopenCounts {
            deadline: 1,
            deadline_block_suppressed: 1,
            ..Default::default()
        };
        assert_eq!(tier_for(&counts, 3), Some(Tier::NotEnforcing));
    }

    // --- end-to-end over a real ledger ---

    #[test]
    fn missing_ledger_is_silent() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3),
            None
        );
    }

    #[test]
    fn below_threshold_is_silent_and_writes_no_marker() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 2);

        assert_eq!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3),
            None
        );
        assert!(
            !marker_path(tmp.path()).exists(),
            "a silent run must not stamp the marker — it would suppress a real \
             disclosure later the same day"
        );
    }

    #[test]
    fn at_threshold_discloses_count_window_and_where_to_look() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 3);

        let msg = failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3)
            .expect("at threshold → disclosed");
        assert!(msg.contains('3'), "names the count: {msg}");
        assert!(msg.contains("24h"), "names the window: {msg}");
        assert!(msg.contains("failopen.jsonl"), "where to look: {msg}");
        assert!(
            msg.contains("cadence-hooks doctor"),
            "doctor pointer: {msg}"
        );
    }

    #[test]
    fn suppressed_block_discloses_the_not_enforcing_tier() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline_block_suppressed", 1);

        let msg = failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3)
            .expect("one suppressed block → disclosed regardless of threshold");
        assert!(
            msg.contains("NOT enforcing"),
            "top tier is unmissable: {msg}"
        );
        assert!(msg.contains("failopen.jsonl"), "where to look: {msg}");
    }

    #[test]
    fn second_run_the_same_day_is_suppressed() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 3);

        assert!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3).is_some(),
            "first sighting today speaks"
        );
        assert_eq!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3),
            None,
            "same tier, same UTC day → silent"
        );
    }

    #[test]
    fn escalating_to_a_sharper_tier_re_fires_the_same_day() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 3);
        assert!(failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3).is_some());

        // Enforcement is now actually being bypassed — today's `degraded`
        // marker must not swallow that.
        write_rows(tmp.path(), "deadline_block_suppressed", 1);
        let msg = failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3)
            .expect("escalation speaks even after today's degraded marker");
        assert!(msg.contains("NOT enforcing"), "the sharper tier: {msg}");
    }

    #[test]
    fn a_stale_marker_from_another_day_does_not_suppress() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 3);
        let marker = marker_path(tmp.path());
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "1999-01-01 degraded").unwrap();

        assert!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 3).is_some(),
            "yesterday's marker is not today's"
        );
    }

    #[test]
    fn a_raised_threshold_silences_a_count_that_would_otherwise_speak() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 3);

        // The threshold reaches the count comparison — the injected value, not
        // the default, decides. Resolving `CADENCE_FAILOPEN_DISCLOSE_MIN` into
        // that value is `disclose_min_from`'s job and is covered above; this
        // pins the other half of the override, that the resolved number is
        // actually the one consulted.
        assert_eq!(
            failopen_disclosure_line(tmp.path(), DAY, SystemTime::now(), 10),
            None,
            "3 rows under a threshold of 10 → silent"
        );
    }

    #[test]
    fn rows_outside_the_window_are_not_counted() {
        let tmp = TempDir::new().unwrap();
        write_rows(tmp.path(), "deadline", 5);

        // The window is `[now - window, ∞)` — it has no upper bound, so aging a
        // burst out means moving the CLOCK forward past it, not moving `now`
        // back. A decade on, today's rows sit well before the cutoff. Proves
        // the disclosure reads a *recent* burst, not the ledger's whole
        // history.
        let a_decade_on = SystemTime::now() + Duration::from_secs(3650 * 24 * 60 * 60);
        assert_eq!(
            failopen_disclosure_line(tmp.path(), DAY, a_decade_on, 3),
            None,
            "an aged-out burst is silent"
        );
    }
}
