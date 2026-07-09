//! Append-only telemetry for `sweep_stale` (the reaper that removes aged-out
//! session-registry files) — one line per reaped file to
//! `<metrics_dir>/sweeps.jsonl`. Cross-machine/cross-session liveness sweeps
//! were previously invisible; this makes them observable.
//!
//! A **free function**, not a [`cadence_hooks_core::Logger`] impl: unlike the
//! `Logger` loggers (wired through the normal hook-dispatch path), this is
//! called directly from `cadence-hooks-session`'s `sweep_stale`, which fires
//! from both the PostToolUse heartbeat and `session start` — neither of which
//! is itself a dispatched `Logger`.
//!
//! Fully fail-open (ADR-0001): every step degrades to a no-op — a full disk or
//! a read-only metrics dir must never perturb the reap it is recording.

use crate::common;
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Schema version stamped on every `sweeps.jsonl` row. A new stream (cadence#238
/// convention) — does not share `common`'s existing version constants.
const SWEEP_SCHEMA_VERSION: u32 = 1;

/// Build the `sweeps.jsonl` record. Pure — no I/O.
fn build_sweep_record(
    trigger: &str,
    session_id: Option<&str>,
    name: Option<&str>,
    age_secs: u64,
) -> Value {
    json!({
        "schemaVersion": SWEEP_SCHEMA_VERSION,
        "trigger": trigger,
        "sessionId": session_id,
        "name": name,
        "ageSecs": age_secs,
        "ts": common::utc_timestamp(),
    })
}

/// Append one sweep event to `<metrics_dir>/sweeps.jsonl`.
///
/// `trigger` names the call site (`"heartbeat"` | `"start"`), `session_id` /
/// `name` are the reaped record's identity when it could be parsed (`None`
/// when the file was garbage or unreadable — the parse is best-effort and
/// must never gate the delete it's recording), and `age_secs` is the file's
/// mtime age at reap time.
///
/// Fully fail-open (ADR-0001): a missing dir it can't create, or a failed open
/// / write, degrades to a no-op — the caller's delete is untouched.
pub fn log_sweep(trigger: &str, session_id: Option<&str>, name: Option<&str>, age_secs: u64) {
    let record = build_sweep_record(trigger, session_id, name, age_secs);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("sweeps.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// Count `sweeps.jsonl` rows whose `ts` is within `window` of `now`. Pure —
/// operates on file contents, no I/O. Patterned on `log_session::count_commits`.
///
/// A row's `ts` is compared lexicographically against `cutoff` — valid because
/// both are the same fixed-width ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) shape, which
/// sorts identically to chronological order. Unparsable rows and rows missing
/// `ts` are skipped, not counted.
fn count_recent(jsonl: &str, cutoff: &str) -> u64 {
    jsonl
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| {
            v.get("ts")
                .and_then(Value::as_str)
                .is_some_and(|ts| ts >= cutoff)
        })
        .count() as u64
}

/// Count `sweeps.jsonl` rows within `window` of `now`.
///
/// Fail-open: a missing/unreadable `<dir>/sweeps.jsonl`, or any unparsable
/// row, contributes 0 / is skipped rather than erroring. Doctor visibility
/// only — never gates anything.
pub fn recent_sweep_count(dir: &Path, window: Duration, now: SystemTime) -> u64 {
    let Ok(contents) = std::fs::read_to_string(dir.join("sweeps.jsonl")) else {
        return 0;
    };
    let cutoff_ts =
        jiff::Timestamp::try_from(now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH))
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let cutoff = cutoff_ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    count_recent(&contents, &cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;

    // --- record shape ---

    #[test]
    fn record_has_expected_fields_with_identity() {
        let rec = build_sweep_record("heartbeat", Some("sess-1"), Some("quiet-loom"), 1800);
        assert_eq!(rec["schemaVersion"], 1);
        assert_eq!(rec["trigger"], "heartbeat");
        assert_eq!(rec["sessionId"], "sess-1");
        assert_eq!(rec["name"], "quiet-loom");
        assert_eq!(rec["ageSecs"], 1800);
        assert!(rec["ts"].is_string());
    }

    #[test]
    fn record_nulls_identity_when_unparsable() {
        let rec = build_sweep_record("start", None, None, 42);
        assert_eq!(rec["trigger"], "start");
        assert!(rec["sessionId"].is_null());
        assert!(rec["name"].is_null());
        assert_eq!(rec["ageSecs"], 42);
    }

    // --- log_sweep end-to-end (tempdir) ---

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        f();
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("sweeps.jsonl");
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
                .collect(),
            Err(_) => vec![],
        }
    }

    #[test]
    fn log_sweep_writes_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_sweep("heartbeat", Some("sess-1"), Some("quiet-loom"), 1800);
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["trigger"], "heartbeat");
        assert_eq!(rows[0]["sessionId"], "sess-1");
        assert_eq!(rows[0]["name"], "quiet-loom");
        assert_eq!(rows[0]["ageSecs"], 1800);
    }

    #[test]
    fn log_sweep_writes_null_identity_when_none() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_sweep("start", None, None, 99);
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["trigger"], "start");
        assert!(rows[0]["sessionId"].is_null());
        assert!(rows[0]["name"].is_null());
    }

    // --- count_recent (pure) ---

    #[test]
    fn count_recent_counts_rows_at_or_after_cutoff() {
        let jsonl = [
            r#"{"ts":"2026-07-01T00:00:00Z"}"#,
            r#"{"ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"ts":"2026-07-09T00:00:00Z"}"#,
            "not json at all",
            r#"{"noTs":true}"#,
        ]
        .join("\n");
        assert_eq!(count_recent(&jsonl, "2026-07-08T00:00:00Z"), 2);
        assert_eq!(count_recent(&jsonl, "2026-07-09T00:00:00Z"), 1);
        assert_eq!(count_recent(&jsonl, "2026-07-10T00:00:00Z"), 0);
        assert_eq!(count_recent("", "2026-07-08T00:00:00Z"), 0);
    }

    // --- recent_sweep_count end-to-end (tempdir) ---

    #[test]
    fn recent_sweep_count_missing_file_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            recent_sweep_count(
                tmp.path(),
                Duration::from_secs(7 * 86_400),
                SystemTime::now()
            ),
            0
        );
    }

    #[test]
    fn recent_sweep_count_counts_within_window() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_sweep("heartbeat", Some("sess-1"), Some("quiet-loom"), 1800);
            log_sweep("start", None, None, 42);
        });
        let count = recent_sweep_count(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
        );
        assert_eq!(count, 2);
    }

    #[test]
    fn recent_sweep_count_excludes_outside_window() {
        let tmp = tempfile::tempdir().unwrap();
        let old_row = r#"{"schemaVersion":1,"trigger":"start","sessionId":null,"name":null,"ageSecs":1,"ts":"2000-01-01T00:00:00Z"}"#;
        std::fs::write(tmp.path().join("sweeps.jsonl"), format!("{old_row}\n")).unwrap();
        let count = recent_sweep_count(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
        );
        assert_eq!(count, 0);
    }
}
