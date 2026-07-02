//! `metrics warn-stale` — telemetry staleness alarm at SessionStart.
//!
//! Fires once per day when the newest cadence-metrics JSONL write is older than
//! a threshold (default 4 days). A stale metrics dir means the plugin's
//! PostToolUse/Stop loggers stopped firing — usually mis-wired hooks or a
//! disabled plugin — so telemetry silently flatlines while sessions keep
//! running. This is the alarm the "second death" incident (cadence#146) lacked:
//! the dir went quiet and nothing surfaced it.
//!
//! Fail-open everywhere (ADR-0001): a missing dir, an unreadable file, a fresh
//! install with no JSONL, a bad env value, a marker IO error — all resolve to
//! silence or a plain nudge, never a block, never a panic. The result is only
//! ever `Allow` or `Nudge`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Default staleness threshold in days when `CADENCE_METRICS_STALE_DAYS` is
/// unset, zero, or unparseable.
const DEFAULT_STALE_DAYS: u64 = 4;

const SECS_PER_DAY: u64 = 86_400;

/// Slack past `now` before a file's mtime is treated as future-dated and
/// excluded from the newest-write selection. Absorbs benign clock skew (NTP
/// jitter, mtime-vs-`now` rounding) while still discarding a wildly
/// future-stamped file that would otherwise mask a genuinely stale dir.
const FUTURE_SLACK: Duration = Duration::from_secs(300);

/// A staleness verdict: the dir's newest JSONL write is older than the
/// threshold. Names the newest file so the message points at real telemetry.
#[derive(Debug, PartialEq, Eq)]
pub struct StaleReport {
    /// Basename of the newest `*.jsonl` file — the one defining dir freshness.
    pub newest_file: String,
    /// Whole days since that newest write.
    pub age_days: u64,
}

/// Staleness threshold from `CADENCE_METRICS_STALE_DAYS`, default 4 days.
///
/// Mirrors `registry::stale_minutes`: trims, parses `u64`, rejects zero and
/// junk. A pure resolver ([`stale_days_from`]) does the work so the fallbacks
/// are unit-testable without process-global env.
pub fn stale_days() -> u64 {
    stale_days_from(std::env::var("CADENCE_METRICS_STALE_DAYS").ok())
}

/// Pure resolver behind [`stale_days`]. `None`, zero, or an unparseable value
/// all fall back to [`DEFAULT_STALE_DAYS`].
fn stale_days_from(raw: Option<String>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&d| d > 0)
        .unwrap_or(DEFAULT_STALE_DAYS)
}

/// The configured staleness threshold as a [`Duration`].
pub fn stale_threshold() -> Duration {
    Duration::from_secs(stale_days() * SECS_PER_DAY)
}

/// The metrics root directory. Re-exported from `common` so callers outside the
/// crate — the `doctor` surface — can resolve it without reaching a private mod.
pub fn metrics_dir() -> PathBuf {
    crate::common::metrics_dir()
}

/// Pure staleness core: is `dir`'s newest top-level `*.jsonl` write older than
/// `threshold` as of `now`?
///
/// - Only top-level `*.jsonl` files count. `read_dir` does not recurse, so the
///   `state/` subdir (markers) is never seen; the extension filter drops any
///   other file. The once-per-day marker therefore can never freshen the
///   signal it gates.
/// - Files stamped more than [`FUTURE_SLACK`] into the future are **excluded**
///   from the newest-write selection. A single clock-skewed or hostile
///   future-dated file must not become a perpetual "newest" whose age underflows
///   and silently reports the whole dir fresh — the exact blind spot the alarm
///   exists to avoid. Staleness is computed from the newest *non-future* file.
/// - Residual case: when *every* `*.jsonl` is future-dated (all excluded), there
///   is no non-future write to judge, so the result is `None` (fail-open). A
///   wholly future-stamped dir is a broken clock, not evidence of staleness, and
///   silence is the safe direction.
/// - Missing dir, unreadable dir, or no `*.jsonl` → `None` (fail-open: a fresh
///   install is indistinguishable from a healthy one, so it stays silent).
pub fn staleness(dir: &Path, threshold: Duration, now: SystemTime) -> Option<StaleReport> {
    let entries = std::fs::read_dir(dir).ok()?;

    let future_cutoff = now + FUTURE_SLACK;
    let mut newest: Option<(SystemTime, String)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        // Skip a far-future file so it can never mask a stale dir by winning the
        // newest-write race.
        if mtime > future_cutoff {
            continue;
        }
        let is_newer = newest.as_ref().is_none_or(|(seen, _)| mtime > *seen);
        if is_newer {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            newest = Some((mtime, name));
        }
    }

    let (mtime, name) = newest?;
    // The newest file is within `FUTURE_SLACK` of now, so a within-slack skew
    // makes `duration_since` err → clamp to zero (fresh), never underflow.
    let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);
    if age <= threshold {
        return None;
    }
    Some(StaleReport {
        newest_file: name,
        age_days: age.as_secs() / SECS_PER_DAY,
    })
}

/// One-line staleness summary shared by the SessionStart nudge and the `doctor`
/// finding: names the newest file and its age. Says nothing about *how* to fix
/// it — the caller appends its own remediation framing.
pub fn staleness_summary(report: &StaleReport) -> String {
    format!(
        "cadence-metrics telemetry is stale: newest metrics `*.jsonl` write is {}d old ({}).",
        report.age_days, report.newest_file
    )
}

/// The SessionStart nudge: the staleness summary plus the cross-machine
/// compare-wiring remediation. Never says "reinstall" — the likely cause is a
/// mis-wired hook or a disabled plugin, diagnosable by comparing against a
/// healthy machine.
fn nudge_message(report: &StaleReport) -> String {
    format!(
        "{} Hooks may be mis-wired or the metrics plugin disabled — run \
         `cadence-hooks doctor` and compare wiring against a healthy machine.",
        staleness_summary(report)
    )
}

/// The once-per-day marker file: `<dir>/state/stale_warn.date`, holding a UTC
/// `YYYY-MM-DD`. When today's date already sits there, the check stays silent so
/// the alarm fires at most once per calendar day. Not a `*.jsonl`, and inside
/// `state/`, so it can never freshen the staleness signal it gates.
fn marker_path(dir: &Path) -> PathBuf {
    dir.join("state").join("stale_warn.date")
}

/// Today's UTC date, `YYYY-MM-DD` — the marker's freshness token. Sliced from
/// the canonical jiff-backed timestamp so it shares the ledger's clock.
fn today_utc() -> String {
    crate::common::utc_timestamp()[..10].to_string()
}

/// Register-time alarm: warn once per day when metrics telemetry has gone stale.
pub struct WarnStale;

impl Check for WarnStale {
    fn name(&self) -> &str {
        "warn-stale"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        run_warn_stale(&metrics_dir(), stale_threshold(), SystemTime::now())
    }
}

/// Testable core: dir, threshold, and clock injected. Reads the staleness
/// verdict, consults the once-per-day marker, and returns `Nudge` (first stale
/// sighting today) or `Allow` (fresh, already warned today, or any fail-open
/// path). Never blocks — the ADR-0001 lock.
pub fn run_warn_stale(dir: &Path, threshold: Duration, now: SystemTime) -> CheckResult {
    let Some(report) = staleness(dir, threshold, now) else {
        return CheckResult::allow();
    };

    let marker = marker_path(dir);
    let today = today_utc();
    if let Ok(existing) = std::fs::read_to_string(&marker)
        && existing.trim() == today
    {
        // Already warned today — stay silent until tomorrow.
        return CheckResult::allow();
    }

    // Record today's warning. Fail-open: a marker write error must not suppress
    // the nudge (a repeat warning beats a missed one) and must never crash.
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, &today);

    CheckResult::nudge(nudge_message(&report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use std::fs;
    use tempfile::TempDir;

    /// A threshold far larger than any test file's age — nothing is ever stale.
    const HUGE: Duration = Duration::from_secs(3650 * SECS_PER_DAY);

    fn write_jsonl(dir: &Path, name: &str) {
        fs::write(dir.join(name), "{}\n").unwrap();
    }

    // 1. A dir whose newest .jsonl is older than the threshold warns, names the
    //    file, and points at the doctor.
    #[test]
    fn stale_dir_warns() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("subagents.jsonl"), "names the file: {msg}");
        assert!(msg.contains("stale"), "says stale: {msg}");
        assert!(
            msg.contains("cadence-hooks doctor"),
            "doctor pointer: {msg}"
        );
    }

    // 2. A huge threshold makes a fresh file non-stale → silent.
    #[test]
    fn fresh_dir_silent() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");

        let r = run_warn_stale(tmp.path(), HUGE, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 3. A missing dir is fail-open silent.
    #[test]
    fn missing_dir_silent() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");

        let r = run_warn_stale(&missing, Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 4. An existing dir with no .jsonl is silent (fresh install is
    //    indistinguishable from healthy).
    #[test]
    fn empty_dir_silent() {
        let tmp = TempDir::new().unwrap();

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 5. A fresh non-.jsonl file and a stale .jsonl still warns, naming the
    //    .jsonl; state/ contents never count toward freshness.
    #[test]
    fn non_jsonl_ignored() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");
        fs::write(tmp.path().join("notes.txt"), "fresh\n").unwrap();
        // A .jsonl buried in state/ must not be picked up (non-recursion).
        fs::create_dir_all(tmp.path().join("state")).unwrap();
        write_jsonl(&tmp.path().join("state"), "buried.jsonl");

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("subagents.jsonl"), "names the jsonl: {msg}");
        assert!(!msg.contains("notes.txt"), "ignores non-jsonl: {msg}");
        assert!(!msg.contains("buried.jsonl"), "ignores state/ jsonl: {msg}");
    }

    // 6. A marker already stamped with today's date suppresses the warning.
    #[test]
    fn marker_today_suppresses() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");
        fs::create_dir_all(tmp.path().join("state")).unwrap();
        fs::write(marker_path(tmp.path()), today_utc()).unwrap();

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow, "today's marker suppresses");
    }

    // 7. A marker stamped with an old date warns and is rewritten to today.
    #[test]
    fn marker_stale_warns_and_updates() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");
        fs::create_dir_all(tmp.path().join("state")).unwrap();
        fs::write(marker_path(tmp.path()), "2000-01-01").unwrap();

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge, "yesterday's marker still warns");
        let stamped = fs::read_to_string(marker_path(tmp.path())).unwrap();
        assert_eq!(stamped.trim(), today_utc(), "marker rewritten to today");
    }

    // 8. The pure env resolver: None/zero/junk → 4; a valid value passes through
    //    (with trimming).
    #[test]
    fn stale_days_env_resolution() {
        assert_eq!(stale_days_from(None), 4);
        assert_eq!(stale_days_from(Some("7".into())), 7);
        assert_eq!(stale_days_from(Some("0".into())), 4);
        assert_eq!(stale_days_from(Some("junk".into())), 4);
        assert_eq!(stale_days_from(Some("  5  ".into())), 5);
    }

    // 9. ADR-0001 lock: the result is only ever Nudge or Allow, never a block.
    #[test]
    fn never_blocks() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert!(
            matches!(r.outcome, Outcome::Allow | Outcome::Nudge),
            "warn-stale must never block: {:?}",
            r.outcome
        );
    }

    /// Stamp `name`'s mtime `secs` into the future — the clock-skew fixture.
    fn write_future_jsonl(dir: &Path, name: &str, secs: u64) {
        let path = dir.join(name);
        fs::write(&path, "{}\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(secs))
            .unwrap();
    }

    // 10. A future-dated file must not mask a genuinely stale dir: staleness is
    //     computed from the newest NON-future file, so the alarm still fires and
    //     names that file, not the future one.
    #[test]
    fn future_mtime_ignored_uses_non_future_file() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl"); // ~now → stale under ZERO
        write_future_jsonl(tmp.path(), "commits.jsonl", 10 * SECS_PER_DAY);

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(
            r.outcome,
            Outcome::Nudge,
            "future file must not mask staleness"
        );
        let msg = r.message.unwrap();
        assert!(
            msg.contains("subagents.jsonl"),
            "reports the non-future file: {msg}"
        );
        assert!(
            !msg.contains("commits.jsonl"),
            "future file excluded: {msg}"
        );
    }

    // 11. When EVERY .jsonl is future-dated, there is no non-future write to
    //     judge → fail-open silent (a broken clock is not evidence of staleness).
    #[test]
    fn all_future_silent() {
        let tmp = TempDir::new().unwrap();
        write_future_jsonl(tmp.path(), "subagents.jsonl", 10 * SECS_PER_DAY);

        let r = run_warn_stale(tmp.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "all-future dir is fail-open silent"
        );
    }
}
