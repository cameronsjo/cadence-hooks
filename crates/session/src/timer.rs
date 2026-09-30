//! `session timer <start|lap|stop> [LABEL]` — a wall-clock stopwatch the agent
//! can drive from its Bash tool (cadence-hooks#480).
//!
//! A CLI action, not a hook: it reads no stdin payload and has no hooks.json
//! wiring, like `session declare`. Timers are named (`LABEL`, default
//! `default`) and scoped to the session (`--session-id`, then
//! `CLAUDE_SESSION_ID`, then `CLAUDE_CODE_SESSION_ID`); with no resolvable
//! session they share a `shared` scope, so the command still works from a
//! plain terminal.
//!
//! - `start` records now, restarting a running timer of the same name.
//! - `lap` prints the elapsed time and keeps the timer running.
//! - `stop` prints the elapsed time, removes the timer, and appends one row
//!   to `<metrics_dir>/timers.jsonl` (`ts`, `sessionId`, `label`,
//!   `elapsedMs`) — the wall-clock axis the other ledgers lack.
//!
//! State: `<metrics_dir>/state/timers/<scope>/<label>`, holding the start as
//! Unix milliseconds, written owner-only.
//!
//! Exit codes: **0** on success; **1** when the label is invalid, the timer
//! was never started, or its state could not be written — with the reason on
//! stderr, so a script can tell "no timer" from an elapsed time on stdout.

use crate::afk_gap::write_private;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The label used when none is given.
pub const DEFAULT_LABEL: &str = "default";
/// The scope used when no session id resolves.
const SHARED_SCOPE: &str = "shared";
/// Longest accepted label.
const MAX_LABEL_LEN: usize = 64;

/// The three stopwatch actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerAction {
    Start,
    Lap,
    Stop,
}

/// Pure: a label is 1–64 chars of ASCII alphanumerics, `-`, `_`, or `.`, and
/// not a dot-only name — so it can never leave the timer directory.
pub fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.bytes().all(|b| b == b'.')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Pure: render milliseconds as `850ms`, `12.3s`, `4m 05s`, or `2h 03m 09s`.
pub fn format_elapsed(ms: u64) -> String {
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let secs = ms / 1000;
    if secs < 60 {
        return format!("{}.{}s", secs, (ms % 1000) / 100);
    }
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h == 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{h}h {m:02}m {s:02}s")
    }
}

/// Current Unix time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn timer_path(state_dir: &Path, scope: &str, label: &str) -> PathBuf {
    state_dir.join("timers").join(scope).join(label)
}

fn read_start(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// What a timer action produced: the stdout line on success, or the stderr
/// reason on failure. `elapsed_ms` is set on a successful `stop`, for the
/// ledger row.
#[derive(Debug, PartialEq, Eq)]
pub struct TimerOutcome {
    pub ok: bool,
    pub line: String,
    pub stopped_ms: Option<u64>,
}

impl TimerOutcome {
    fn ok(line: String) -> Self {
        Self {
            ok: true,
            line,
            stopped_ms: None,
        }
    }
    fn err(line: String) -> Self {
        Self {
            ok: false,
            line,
            stopped_ms: None,
        }
    }
}

/// Testable core: apply `action` to the timer `label` under `state_dir`,
/// scoped by `scope`, at time `now`. Never touches the ledger.
pub fn apply(
    state_dir: &Path,
    scope: &str,
    action: TimerAction,
    label: &str,
    now: u64,
) -> TimerOutcome {
    if !is_valid_label(label) {
        return TimerOutcome::err(format!(
            "invalid timer label {label:?}: use 1-{MAX_LABEL_LEN} characters of letters, \
             digits, '-', '_', or '.'"
        ));
    }
    let path = timer_path(state_dir, scope, label);
    let running = read_start(&path);
    match action {
        TimerAction::Start => {
            if let Err(e) = write_private(&path, now.to_string().as_bytes()) {
                return TimerOutcome::err(format!("timer '{label}': could not record start: {e}"));
            }
            match running {
                Some(start) => TimerOutcome::ok(format!(
                    "timer '{label}' restarted (was at {})",
                    format_elapsed(now.saturating_sub(start))
                )),
                None => TimerOutcome::ok(format!("timer '{label}' started")),
            }
        }
        TimerAction::Stop => {
            // Claim the timer by renaming it away first: of two concurrent
            // stops exactly one rename succeeds, so exactly one logs a row.
            // `~` is outside the label charset, so no valid label can name
            // (and so collide with) a claim file.
            let claim = path.with_file_name(format!("{label}~stop.{}", std::process::id()));
            if std::fs::rename(&path, &claim).is_err() {
                return not_running(label);
            }
            let claimed = read_start(&claim);
            let _ = std::fs::remove_file(&claim);
            let Some(start) = claimed else {
                return not_running(label);
            };
            let elapsed = now.saturating_sub(start);
            TimerOutcome {
                ok: true,
                line: format!("timer '{label}': {} (stopped)", format_elapsed(elapsed)),
                stopped_ms: Some(elapsed),
            }
        }
        TimerAction::Lap => {
            let Some(start) = running else {
                return not_running(label);
            };
            TimerOutcome::ok(format!(
                "timer '{label}': {} (running)",
                format_elapsed(now.saturating_sub(start))
            ))
        }
    }
}

fn not_running(label: &str) -> TimerOutcome {
    TimerOutcome::err(format!(
        "timer '{label}' is not running — start it with `cadence-hooks session timer start {label}`"
    ))
}

/// Append one stopped-timer row to `<metrics_dir>/timers.jsonl`. Best-effort.
fn log_stop(metrics_dir: &Path, session_id: Option<&str>, label: &str, elapsed_ms: u64) {
    if std::fs::create_dir_all(metrics_dir).is_err() {
        return;
    }
    let row = serde_json::json!({
        "ts": cadence_hooks_metrics::common::utc_timestamp(),
        "sessionId": session_id,
        "label": label,
        "elapsedMs": elapsed_ms,
    });
    if let Ok(mut file) = cadence_hooks_metrics::open_ledger(metrics_dir.join("timers.jsonl")) {
        let mut line = row.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// `session timer` entry point. Returns the process exit code.
pub fn run_timer(action: TimerAction, label: Option<String>, session_id: Option<String>) -> u8 {
    let label = label.unwrap_or_else(|| DEFAULT_LABEL.to_string());
    // An explicit id that fails validation is a caller error, not a cue to
    // fall back to the shared scope and quietly run someone else's timer.
    if let Some(bad) = session_id
        .as_deref()
        .filter(|s| !crate::identity::is_safe_session_id(s))
    {
        eprintln!(
            "invalid --session-id {:?}: use letters, digits, '-', or '_'",
            crate::identity::sanitize_field(bad, 80)
        );
        return 1;
    }
    let sid = crate::cli::resolve_session_id(session_id);
    let scope = sid.as_deref().unwrap_or(SHARED_SCOPE);
    let outcome = apply(
        &cadence_hooks_metrics::common::state_dir(),
        scope,
        action,
        &label,
        now_ms(),
    );
    if !outcome.ok {
        eprintln!("{}", outcome.line);
        return 1;
    }
    if let Some(ms) = outcome.stopped_ms {
        log_stop(
            &cadence_hooks_metrics::metrics_dir(),
            sid.as_deref(),
            &label,
            ms,
        );
    }
    cadence_hooks_core::outln!("{}", outcome.line);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_table() {
        for (label, ok) in [
            ("default", true),
            ("build", true),
            ("cargo-test_2.release", true),
            ("", false),
            (".", false),
            ("..", false),
            ("../escape", false),
            ("a/b", false),
            ("with space", false),
            ("naïve", false),
            (&"x".repeat(64), true),
            (&"x".repeat(65), false),
        ] {
            assert_eq!(is_valid_label(label), ok, "{label:?}");
        }
    }

    #[test]
    fn format_elapsed_table() {
        for (ms, want) in [
            (0, "0ms"),
            (850, "850ms"),
            (1000, "1.0s"),
            (12_345, "12.3s"),
            (59_999, "59.9s"),
            (60_000, "1m 00s"),
            (245_000, "4m 05s"),
            (3_600_000, "1h 00m 00s"),
            (7_389_000, "2h 03m 09s"),
        ] {
            assert_eq!(format_elapsed(ms), want, "{ms}");
        }
    }

    #[test]
    fn start_lap_stop_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let out = apply(dir, "s1", TimerAction::Start, "build", 1_000);
        assert_eq!(out, TimerOutcome::ok("timer 'build' started".into()));

        let lap = apply(dir, "s1", TimerAction::Lap, "build", 66_000);
        assert!(lap.ok);
        assert_eq!(lap.line, "timer 'build': 1m 05s (running)");
        assert_eq!(lap.stopped_ms, None);

        let stop = apply(dir, "s1", TimerAction::Stop, "build", 3_000);
        assert!(stop.ok);
        assert_eq!(stop.line, "timer 'build': 2.0s (stopped)");
        assert_eq!(stop.stopped_ms, Some(2_000));

        // Stopped means gone.
        let again = apply(dir, "s1", TimerAction::Stop, "build", 4_000);
        assert!(!again.ok);
        assert!(again.line.contains("not running"), "{}", again.line);
    }

    #[test]
    fn start_on_a_running_timer_restarts_it() {
        let tmp = tempfile::tempdir().unwrap();
        apply(tmp.path(), "s", TimerAction::Start, "t", 0);
        let out = apply(tmp.path(), "s", TimerAction::Start, "t", 90_000);
        assert_eq!(out.line, "timer 't' restarted (was at 1m 30s)");
        let lap = apply(tmp.path(), "s", TimerAction::Lap, "t", 91_000);
        assert_eq!(lap.line, "timer 't': 1.0s (running)");
    }

    #[test]
    fn lap_and_stop_without_start_fail() {
        let tmp = tempfile::tempdir().unwrap();
        for action in [TimerAction::Lap, TimerAction::Stop] {
            let out = apply(tmp.path(), "s", action, "never", 10);
            assert!(!out.ok, "{action:?}");
            assert!(
                out.line.contains("session timer start never"),
                "{}",
                out.line
            );
        }
    }

    #[test]
    fn concurrent_stops_log_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        apply(tmp.path(), "s", TimerAction::Start, "t", 0);
        let dir = tmp.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || apply(&dir, "s", TimerAction::Stop, "t", 1_000))
            })
            .collect();
        let stopped = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|o| o.stopped_ms.is_some())
            .count();
        assert_eq!(stopped, 1);
        // No claim file left behind.
        let left: Vec<_> = std::fs::read_dir(tmp.path().join("timers").join("s"))
            .unwrap()
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn scopes_and_labels_are_independent() {
        let tmp = tempfile::tempdir().unwrap();
        apply(tmp.path(), "a", TimerAction::Start, "x", 0);
        assert!(!apply(tmp.path(), "b", TimerAction::Lap, "x", 5).ok);
        assert!(!apply(tmp.path(), "a", TimerAction::Lap, "y", 5).ok);
        assert!(apply(tmp.path(), "a", TimerAction::Lap, "x", 5).ok);
    }

    #[test]
    fn invalid_label_touches_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let out = apply(tmp.path(), "s", TimerAction::Start, "../x", 0);
        assert!(!out.ok);
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_clock_step_backwards_reads_zero_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        apply(tmp.path(), "s", TimerAction::Start, "t", 10_000);
        let out = apply(tmp.path(), "s", TimerAction::Stop, "t", 5_000);
        assert_eq!(out.stopped_ms, Some(0));
    }

    #[test]
    fn stop_row_shape() {
        let tmp = tempfile::tempdir().unwrap();
        log_stop(tmp.path(), Some("sid"), "build", 1234);
        log_stop(tmp.path(), None, "x", 5);
        let body = std::fs::read_to_string(tmp.path().join("timers.jsonl")).unwrap();
        let rows: Vec<serde_json::Value> = body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["sessionId"], "sid");
        assert_eq!(rows[0]["label"], "build");
        assert_eq!(rows[0]["elapsedMs"], 1234);
        assert!(rows[0]["ts"].is_string());
        assert!(rows[1]["sessionId"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn timer_state_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        apply(tmp.path(), "s", TimerAction::Start, "t", 0);
        let mode = std::fs::metadata(timer_path(tmp.path(), "s", "t"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
