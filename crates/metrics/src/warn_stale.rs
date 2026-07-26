//! `metrics warn-stale` — telemetry staleness alarm at SessionStart.
//!
//! Fires once per day on either of two verdicts:
//!
//! - **Stale** — every watched write is older than a threshold (default 4
//!   days). The whole subsystem has gone quiet.
//! - **Flatline** — the subsystem is demonstrably alive (something wrote
//!   recently) but a named *continuous* stream has stopped anyway. This is the
//!   per-collector death a directory-grain check cannot see (#217): one live
//!   stream keeps the dir fresh while a sibling silently dies. It is the shape
//!   of the proven failure — `commits.jsonl` dead for five weeks while
//!   `sessions.jsonl` wrote the whole time (cadence#146) — which the
//!   dir-grain alarm would have reported as healthy.
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

/// Streams whose silence is evidence of **breakage**, not of calm.
///
/// This is the whole judgment behind the flatline verdict, so the membership
/// rule matters more than the list: a stream belongs here only when an ordinary
/// active week *must* produce writes to it. Session stops, commits, subagent
/// dispatches, skill invocations and insight captures all recur on any machine
/// doing real work, so a multi-day gap in one of them while the rest of the
/// subsystem is live means that collector died.
///
/// Deliberately **excluded** are the event-sparse streams — `denials.jsonl`,
/// `bypasses.jsonl`, `sweeps.jsonl`, `askuserquestion.jsonl`, `failopen.jsonl`,
/// and the threshold-gated `hooks.jsonl` (slow-hook samples only). Silence
/// there is *good news*: no guard denied anything, nothing failed open, no hook
/// ran slow. Alarming on a quiet week would train the operator to dismiss this
/// nudge, which is exactly how a real dead collector gets skipped.
const CONTINUOUS_STREAMS: &[&str] = &[
    "commits.jsonl",
    "insights.jsonl",
    "sessions.jsonl",
    "skills.jsonl",
    "subagents.jsonl",
];

/// A staleness verdict: every watched write is older than the threshold. Names
/// the newest file so the message points at real telemetry.
#[derive(Debug, PartialEq, Eq)]
pub struct StaleReport {
    /// Basename of the newest watched file — the one defining overall freshness.
    pub newest_file: String,
    /// Whole days since that newest write.
    pub age_days: u64,
}

/// A flatline verdict: named continuous streams stopped while the subsystem as
/// a whole kept writing.
#[derive(Debug, PartialEq, Eq)]
pub struct FlatlineReport {
    /// `(basename, age_days)` per stopped continuous stream, sorted by name.
    pub streams: Vec<(String, u64)>,
    /// Basename of the freshest watched write — the proof the subsystem is
    /// alive, and therefore that the stopped streams are broken rather than
    /// merely idle.
    pub liveness_proof: String,
    /// Whole days since that freshest write.
    pub liveness_age_days: u64,
}

/// What the watched telemetry looks like right now. `None` from
/// [`telemetry_verdict`] means healthy (or nothing to judge).
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Everything watched is older than the threshold.
    Stale(StaleReport),
    /// Some watched stream is fresh, but a continuous stream has stopped.
    Flatline(FlatlineReport),
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

/// Watched ledgers that live **outside** the metrics dir, so the newest-file
/// scan can never see them (#217's second gap).
///
/// `<config_dir>/cadence/insights.jsonl` is written by the cadence plugin's
/// `capture-insights.sh` hook — inside the hook system, so the "hooks may be
/// mis-wired or the plugin disabled" remediation is the right one for it.
///
/// `<config_dir>/cadence/sessions/scorecard.jsonl` is deliberately **not** here
/// despite being named in #217: it is derived by a meta-repo script, not by any
/// hook, so a hook-wiring remediation would send the operator down a false
/// trail. A ledger this check cannot explain is worse than one it does not
/// mention.
pub fn extra_watched_paths() -> Vec<PathBuf> {
    vec![
        cadence_hooks_core::paths::claude_config_dir()
            .join("cadence")
            .join("insights.jsonl"),
    ]
}

/// How long ago `mtime` was, as of `now`, clamped at zero.
///
/// A within-[`FUTURE_SLACK`] skew makes `duration_since` err — clamping to
/// zero reads that as "fresh", which is the safe direction, and never
/// underflows.
fn age(now: SystemTime, mtime: SystemTime) -> Duration {
    now.duration_since(mtime).unwrap_or(Duration::ZERO)
}

/// Every watched file's `(basename, mtime)`: the top-level `*.jsonl` files in
/// `dir` plus each path in `extra`.
///
/// - `read_dir` does not recurse, so the `state/` subdir (markers) is never
///   seen; the extension filter drops any other file. The once-per-day marker
///   therefore can never freshen the signal it gates.
/// - Files stamped more than [`FUTURE_SLACK`] into the future are **excluded**.
///   A single clock-skewed or hostile future-dated file must not become a
///   perpetual "newest" whose age underflows and silently reports everything
///   fresh — the exact blind spot the alarm exists to avoid.
/// - Metadata is resolved through the symlink (`fs::metadata`, not
///   `DirEntry::metadata`): a ledger symlinked elsewhere should be judged by
///   the write time of the file it actually points at, and the `is_file` test
///   still keeps directories out.
/// - Every IO error is skipped rather than propagated — a single unreadable
///   entry must not blind the whole check.
/// - Keyed by **basename**, keeping the newest write per name. An `extra` path
///   can resolve to a file the dir scan already saw (set `CADENCE_METRICS_DIR`
///   to the config dir's `cadence/` and `insights.jsonl` arrives twice), and a
///   duplicate would otherwise let one ledger be named twice in a single
///   flatline verdict.
fn collect_watched(dir: &Path, extra: &[PathBuf], now: SystemTime) -> Vec<(String, SystemTime)> {
    let future_cutoff = now + FUTURE_SLACK;
    let mut watched: std::collections::BTreeMap<String, SystemTime> =
        std::collections::BTreeMap::new();

    let mut consider = |path: &Path| {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if !meta.is_file() {
            return;
        }
        let Ok(mtime) = meta.modified() else {
            return;
        };
        if mtime > future_cutoff {
            return;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        watched
            .entry(name)
            .and_modify(|seen| {
                if mtime > *seen {
                    *seen = mtime;
                }
            })
            .or_insert(mtime);
    };

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                consider(&path);
            }
        }
    }
    for path in extra {
        consider(path);
    }

    watched.into_iter().collect()
}

/// Pure verdict core: judge `dir`'s top-level `*.jsonl` files plus `extra`
/// against `threshold` as of `now`.
///
/// Precedence is deliberate — **stale subsumes flatline**. When nothing has
/// written recently, naming individual dead streams would be noise on top of a
/// louder signal, so the whole-subsystem verdict wins and the flatline scan
/// never runs.
///
/// Returns `None` when healthy, and also when there is nothing to judge:
/// missing dir, unreadable dir, no watched file, or every file future-dated. A
/// fresh install is indistinguishable from a healthy one and a wholly
/// future-stamped dir is a broken clock — silence is the safe direction for
/// both.
pub fn telemetry_verdict(
    dir: &Path,
    extra: &[PathBuf],
    threshold: Duration,
    now: SystemTime,
) -> Option<Verdict> {
    let watched = collect_watched(dir, extra, now);

    let (newest_name, newest_mtime) = watched.iter().max_by_key(|(_, mtime)| *mtime)?;
    let newest_age = age(now, *newest_mtime);

    if newest_age > threshold {
        return Some(Verdict::Stale(StaleReport {
            newest_file: newest_name.clone(),
            age_days: newest_age.as_secs() / SECS_PER_DAY,
        }));
    }

    // Something wrote recently, so the subsystem is alive. Any continuous
    // stream that stopped anyway is a dead collector the newest-write signal
    // reports as healthy.
    let mut streams: Vec<(String, u64)> = watched
        .iter()
        .filter(|(name, _)| CONTINUOUS_STREAMS.contains(&name.as_str()))
        .filter_map(|(name, mtime)| {
            let stream_age = age(now, *mtime);
            (stream_age > threshold).then(|| (name.clone(), stream_age.as_secs() / SECS_PER_DAY))
        })
        .collect();

    if streams.is_empty() {
        return None;
    }
    streams.sort();

    Some(Verdict::Flatline(FlatlineReport {
        streams,
        liveness_proof: newest_name.clone(),
        liveness_age_days: newest_age.as_secs() / SECS_PER_DAY,
    }))
}

/// One-line verdict summary shared by the SessionStart nudge and the `doctor`
/// finding. Says nothing about *how* to fix it — the caller appends its own
/// remediation framing.
///
/// The flatline wording names the liveness proof explicitly, because that
/// contrast *is* the finding: without it the reader has no way to tell a dead
/// collector from a quiet week.
pub fn verdict_summary(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Stale(report) => format!(
            "cadence-metrics telemetry is stale: newest watched write is {}d old ({}).",
            report.age_days, report.newest_file
        ),
        Verdict::Flatline(report) => {
            let stopped = report
                .streams
                .iter()
                .map(|(name, days)| format!("{name} ({days}d)"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "cadence-metrics telemetry has partially flatlined: {stopped} stopped \
                 writing while {} wrote {}d ago, so a directory-grain check reads this \
                 as healthy.",
                report.liveness_proof, report.liveness_age_days
            )
        }
    }
}

/// The short label a verdict is remembered by in the once-per-day marker.
///
/// Stale collapses to one token; flatline carries the **set** of stopped
/// streams but not their ages, so a stream aging 5d → 6d stays silent while a
/// *newly* dead stream re-fires the same day. A collector that dies at 10am
/// should not have to wait until tomorrow to be reported.
fn verdict_token(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Stale(_) => "stale".to_string(),
        Verdict::Flatline(report) => {
            let names: Vec<&str> = report
                .streams
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            format!("flatline:{}", names.join(","))
        }
    }
}

/// The SessionStart nudge: the verdict summary plus the cross-machine
/// compare-wiring remediation. Never says "reinstall" — the likely cause is a
/// mis-wired hook or a disabled plugin, diagnosable by comparing against a
/// healthy machine.
fn nudge_message(verdict: &Verdict) -> String {
    format!(
        "{} Hooks may be mis-wired or the metrics plugin disabled — run \
         `cadence-hooks doctor` and compare wiring against a healthy machine.",
        verdict_summary(verdict)
    )
}

/// The once-per-day marker file: `<dir>/state/stale_warn.date`, holding a UTC
/// `YYYY-MM-DD` followed by the verdict token. When today's date and the same
/// verdict already sit there, the check stays silent so the alarm fires at most
/// once per calendar day *per distinct verdict*. Not a `*.jsonl`, and inside
/// `state/`, so it can never freshen the staleness signal it gates.
fn marker_path(dir: &Path) -> PathBuf {
    dir.join("state").join("stale_warn.date")
}

/// Today's UTC date, `YYYY-MM-DD` — the marker's freshness token. Sliced from
/// the canonical jiff-backed timestamp so it shares the ledger's clock.
fn today_utc() -> String {
    crate::common::utc_timestamp()[..10].to_string()
}

/// Register-time alarm: warn once per day when metrics telemetry has gone stale
/// or a continuous stream has flatlined.
pub struct WarnStale;

impl Check for WarnStale {
    fn name(&self) -> &str {
        "warn-stale"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        run_warn_stale(
            &metrics_dir(),
            &extra_watched_paths(),
            stale_threshold(),
            SystemTime::now(),
        )
    }
}

/// Testable core: dir, extra paths, threshold, and clock injected. Reads the
/// verdict, consults the once-per-day marker, and returns `Nudge` (first
/// sighting of this verdict today) or `Allow` (healthy, already warned, or any
/// fail-open path). Never blocks — the ADR-0001 lock.
pub fn run_warn_stale(
    dir: &Path,
    extra: &[PathBuf],
    threshold: Duration,
    now: SystemTime,
) -> CheckResult {
    let Some(verdict) = telemetry_verdict(dir, extra, threshold, now) else {
        return CheckResult::allow();
    };

    let marker = marker_path(dir);
    let token = format!("{} {}", today_utc(), verdict_token(&verdict));
    if let Ok(existing) = std::fs::read_to_string(&marker)
        && existing.trim() == token
    {
        // Already warned about this exact verdict today — stay silent.
        return CheckResult::allow();
    }

    // Record today's warning. Fail-open: a marker write error must not suppress
    // the nudge (a repeat warning beats a missed one) and must never crash.
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, &token);

    CheckResult::nudge(nudge_message(&verdict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use std::fs;
    use tempfile::TempDir;

    /// A threshold far larger than any test file's age — nothing is ever stale.
    const HUGE: Duration = Duration::from_secs(3650 * SECS_PER_DAY);

    /// A threshold the aged fixtures below straddle: 4 days, the shipped default.
    const FOUR_DAYS: Duration = Duration::from_secs(4 * SECS_PER_DAY);

    fn write_jsonl(dir: &Path, name: &str) {
        fs::write(dir.join(name), "{}\n").unwrap();
    }

    /// Write `name` and backdate its mtime by `days` — the differential-age
    /// fixture the flatline verdict needs (every file the same age can only
    /// ever produce the whole-dir verdict).
    fn write_jsonl_aged(dir: &Path, name: &str, days: u64) {
        let path = dir.join(name);
        fs::write(&path, "{}\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(days * SECS_PER_DAY))
            .unwrap();
    }

    /// No extra watched paths — the common case for dir-only fixtures.
    const NO_EXTRA: &[PathBuf] = &[];

    // 1. A dir whose newest .jsonl is older than the threshold warns, names the
    //    file, and points at the doctor.
    #[test]
    fn stale_dir_warns() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
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

        let r = run_warn_stale(tmp.path(), NO_EXTRA, HUGE, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 3. A missing dir is fail-open silent.
    #[test]
    fn missing_dir_silent() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");

        let r = run_warn_stale(&missing, NO_EXTRA, Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 4. An existing dir with no .jsonl is silent (fresh install is
    //    indistinguishable from healthy).
    #[test]
    fn empty_dir_silent() {
        let tmp = TempDir::new().unwrap();

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
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

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("subagents.jsonl"), "names the jsonl: {msg}");
        assert!(!msg.contains("notes.txt"), "ignores non-jsonl: {msg}");
        assert!(!msg.contains("buried.jsonl"), "ignores state/ jsonl: {msg}");
    }

    // 6. A marker already stamped with today's date AND the same verdict
    //    suppresses the warning.
    #[test]
    fn marker_today_suppresses() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");
        fs::create_dir_all(tmp.path().join("state")).unwrap();
        fs::write(marker_path(tmp.path()), format!("{} stale", today_utc())).unwrap();

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow, "today's marker suppresses");
    }

    // 7. A marker stamped with an old date warns and is rewritten to today.
    #[test]
    fn marker_stale_warns_and_updates() {
        let tmp = TempDir::new().unwrap();
        write_jsonl(tmp.path(), "subagents.jsonl");
        fs::create_dir_all(tmp.path().join("state")).unwrap();
        fs::write(marker_path(tmp.path()), "2000-01-01 stale").unwrap();

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge, "yesterday's marker still warns");
        let stamped = fs::read_to_string(marker_path(tmp.path())).unwrap();
        assert_eq!(
            stamped.trim(),
            format!("{} stale", today_utc()),
            "marker rewritten to today's verdict"
        );
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

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
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

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
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

        let r = run_warn_stale(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now());
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "all-future dir is fail-open silent"
        );
    }

    // ── flatline: the #217 masking bug ──────────────────────────────────────

    // 12. THE REGRESSION TEST for #217. A dead continuous stream beside a live
    //     one — the exact commits.jsonl/sessions.jsonl shape of cadence#146.
    //     Dir-grain freshness reports this healthy; the flatline verdict names
    //     the dead stream AND the live one that was masking it.
    #[test]
    fn dead_stream_beside_live_one_flatlines() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);

        let r = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge, "a dead stream must be reported");
        let msg = r.message.unwrap();
        assert!(
            msg.contains("commits.jsonl"),
            "names the dead stream: {msg}"
        );
        assert!(msg.contains("40d"), "names its age: {msg}");
        assert!(
            msg.contains("sessions.jsonl"),
            "names the liveness proof: {msg}"
        );
    }

    // 13. The noise floor: an event-sparse stream going quiet is GOOD news and
    //     must stay silent. Without this, a week with no guard denials would
    //     nag daily — and an operator who learns to dismiss the nudge misses a
    //     real dead collector.
    #[test]
    fn sparse_stream_silence_is_not_a_flatline() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "denials.jsonl", 40);
        write_jsonl_aged(tmp.path(), "bypasses.jsonl", 40);
        write_jsonl_aged(tmp.path(), "hooks.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);

        let r = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "quiet sparse streams are not a defect"
        );
    }

    // 14. Stale subsumes flatline: when nothing has written recently, the
    //     whole-subsystem verdict wins rather than enumerating dead streams on
    //     top of a louder signal.
    #[test]
    fn whole_subsystem_stale_wins_over_flatline() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 30);

        let verdict =
            telemetry_verdict(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now()).unwrap();
        assert!(
            matches!(verdict, Verdict::Stale(_)),
            "expected Stale, got {verdict:?}"
        );
    }

    // 15. All continuous streams fresh → silent, even with the flatline scan
    //     enabled.
    #[test]
    fn all_streams_fresh_silent() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 1);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);

        assert!(telemetry_verdict(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now()).is_none());
    }

    // 16. Multiple dead streams are all named, sorted, so the operator sees the
    //     full blast radius rather than one arbitrary representative.
    #[test]
    fn multiple_dead_streams_all_named_sorted() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "subagents.jsonl", 20);
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);

        let verdict =
            telemetry_verdict(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now()).unwrap();
        let Verdict::Flatline(report) = verdict else {
            panic!("expected Flatline, got {verdict:?}");
        };
        let names: Vec<&str> = report.streams.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["commits.jsonl", "subagents.jsonl"]);
    }

    // ── extra watched paths: the #217 out-of-dir gap ────────────────────────

    // 17. A ledger OUTSIDE the metrics dir is watched. insights.jsonl lives in
    //     <config>/cadence/, so no read_dir over the metrics dir can ever see
    //     it — today it can die at any grain with no alarm.
    #[test]
    fn extra_path_outside_dir_is_watched() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);
        write_jsonl_aged(outside.path(), "insights.jsonl", 40);
        let extra = vec![outside.path().join("insights.jsonl")];

        let r = run_warn_stale(tmp.path(), &extra, FOUR_DAYS, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("insights.jsonl"), "names the ledger: {msg}");
    }

    // 17b. The basename-dedup merge path: the SAME file reached by both the dir
    //      scan and an `extra` entry (what happens when CADENCE_METRICS_DIR is
    //      pointed at the config dir's `cadence/`). Without the keying, one
    //      ledger would be named twice in a single flatline verdict.
    #[test]
    fn extra_path_inside_scanned_dir_is_not_double_counted() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "insights.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);
        // Same file, reached the second way.
        let extra = vec![tmp.path().join("insights.jsonl")];

        let verdict = telemetry_verdict(tmp.path(), &extra, FOUR_DAYS, SystemTime::now()).unwrap();
        let Verdict::Flatline(report) = verdict else {
            panic!("expected Flatline, got {verdict:?}");
        };
        let names: Vec<&str> = report.streams.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["insights.jsonl"],
            "one ledger, named once — not once per route"
        );
    }

    // 18. A missing extra path is skipped, not fatal — the machine may simply
    //     never have captured an insight.
    #[test]
    fn missing_extra_path_is_skipped() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);
        let extra = vec![tmp.path().join("nope").join("insights.jsonl")];

        let r = run_warn_stale(tmp.path(), &extra, FOUR_DAYS, SystemTime::now());
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // 19. A fresh extra path counts as liveness proof, so it can be the reason
    //     a dir-only reading would have called everything stale.
    #[test]
    fn fresh_extra_path_proves_liveness() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(outside.path(), "insights.jsonl", 0);
        let extra = vec![outside.path().join("insights.jsonl")];

        let verdict = telemetry_verdict(tmp.path(), &extra, FOUR_DAYS, SystemTime::now()).unwrap();
        let Verdict::Flatline(report) = verdict else {
            panic!("expected Flatline (the fresh extra path proves life), got {verdict:?}");
        };
        assert_eq!(report.liveness_proof, "insights.jsonl");
    }

    // ── marker: verdict-aware suppression ───────────────────────────────────

    // 20. A NEWLY dead stream re-fires the same day. The old date-only marker
    //     would have swallowed it until tomorrow — a collector that dies at
    //     10am should not go unreported for 14 hours.
    #[test]
    fn new_dead_stream_refires_same_day() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);

        let first = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(first.outcome, Outcome::Nudge, "first sighting warns");

        let repeat = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(repeat.outcome, Outcome::Allow, "same verdict stays silent");

        // A second collector dies — the verdict set changed.
        write_jsonl_aged(tmp.path(), "skills.jsonl", 40);
        let widened = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(
            widened.outcome,
            Outcome::Nudge,
            "a newly dead stream re-fires the same day"
        );
        let msg = widened.message.unwrap();
        assert!(msg.contains("skills.jsonl"), "names the new death: {msg}");
    }

    // 21. Ages are NOT in the marker token, so a stream merely aging 5d → 6d
    //     does not re-nag within the day.
    #[test]
    fn aging_alone_does_not_refire() {
        let tmp = TempDir::new().unwrap();
        write_jsonl_aged(tmp.path(), "commits.jsonl", 40);
        write_jsonl_aged(tmp.path(), "sessions.jsonl", 0);
        let _ = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());

        // Same stream, older.
        write_jsonl_aged(tmp.path(), "commits.jsonl", 60);
        let again = run_warn_stale(tmp.path(), NO_EXTRA, FOUR_DAYS, SystemTime::now());
        assert_eq!(
            again.outcome,
            Outcome::Allow,
            "same stream set, just older — no re-nag"
        );
    }
}
