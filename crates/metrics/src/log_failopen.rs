//! Append-only telemetry for the binary's fail-open paths (panic, stdin-parse
//! failure, clap version-skew) to `<metrics_dir>/failopen.jsonl` — this JSONL
//! stream keeps these previously-silent degradations consistent with the
//! existing denial/timing/bypass rail on `<metrics_dir>/`; wiring these
//! streams into a fuller OTLP-based observability stack is a named follow-up,
//! not this change.

use crate::common;
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Schema version stamped on every `failopen.jsonl` row. A new stream
/// (cadence#238 convention) — does not share `common`'s existing version
/// constants.
const FAILOPEN_SCHEMA_VERSION: u32 = 1;

/// Build the `failopen.jsonl` record. Pure — no I/O.
fn build_failopen_record(
    reason: &str,
    namespace: Option<&str>,
    subcommand: Option<&str>,
    binary_version: &str,
) -> Value {
    json!({
        "schemaVersion": FAILOPEN_SCHEMA_VERSION,
        "reason": reason,
        "namespace": namespace,
        "subcommand": subcommand,
        "binaryVersion": binary_version,
        "ts": common::utc_timestamp(),
    })
}

/// Append one fail-open event to `<metrics_dir>/failopen.jsonl`.
///
/// `reason` names the degradation (`"panic"` | `"parse"` | `"version_mismatch"`),
/// `namespace` / `subcommand` are the CLI position that triggered it when known
/// (`None` when the call site can't determine one — e.g. the global panic
/// hook has no `Check`/`Logger` in scope), and `binary_version` is this
/// process's own `CARGO_PKG_VERSION` — plain log metadata distinguishing this
/// row from any session-level version stamp.
///
/// Fully fail-open (ADR-0001): a missing dir it can't create, or a failed open
/// / write, degrades to a no-op — the caller's exit path is untouched.
pub fn log_failopen(
    reason: &str,
    namespace: Option<&str>,
    subcommand: Option<&str>,
    binary_version: &str,
) {
    let record = build_failopen_record(reason, namespace, subcommand, binary_version);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("failopen.jsonl");

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

/// Fail-open row counts within a time window, grouped by `reason`.
///
/// `version_mismatch` is pre-filtered (by [`recent_failopen_counts`]) to rows
/// whose `binaryVersion` equals the caller's `current_version` — see that
/// function's doc for why.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct FailopenCounts {
    pub panic: u64,
    pub parse: u64,
    pub version_mismatch: u64,
    /// Git probes hit the #271 in-process deadline; guards degraded to their
    /// ordinary fail-open arms. Load-correlated, like `parse`.
    pub deadline: u64,
    /// A fail-closed guard arm downgraded its block to allow because its probe
    /// timed out — enforcement was actually bypassed, the sharpest row here.
    pub deadline_block_suppressed: u64,
}

/// Count `failopen.jsonl` rows within `window` of `now`, filtered by `reason`
/// and (when `version_filter` is `Some`) an exact `binaryVersion` match. Pure
/// — operates on file contents, no I/O.
///
/// `ts` is compared lexicographically against `cutoff` — valid because both
/// are the same fixed-width ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) shape, which sorts
/// identically to chronological order. Unparsable rows and rows missing a
/// required field are skipped, not counted.
fn count_recent(jsonl: &str, cutoff: &str, reason: &str, version_filter: Option<&str>) -> u64 {
    jsonl
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| v.get("reason").and_then(Value::as_str) == Some(reason))
        .filter(|v| {
            v.get("ts")
                .and_then(Value::as_str)
                .is_some_and(|ts| ts >= cutoff)
        })
        .filter(|v| match version_filter {
            Some(want) => v.get("binaryVersion").and_then(Value::as_str) == Some(want),
            None => true,
        })
        .count() as u64
}

/// Count `failopen.jsonl` rows within `window` of `now`, grouped by `reason`.
///
/// `version_mismatch` counts ONLY rows whose `binaryVersion` equals
/// `current_version` (the caller's own running binary version) — this is the
/// deliberate reconciliation for a sanctioned new-hooks.json+old-binary release
/// transition: a `version_mismatch` row logged by an *older* binary hitting a
/// subcommand a newer hooks.json expects (or vice versa) is expected noise
/// during a rollout and must not alarm. A recurrence tagged with the CURRENT
/// binary's own version means the skew didn't resolve, which is what's worth
/// surfacing. `panic`/`parse` counts are NOT version-filtered — any occurrence
/// on any version is worth counting.
///
/// Fail-open: a missing/unreadable `<dir>/failopen.jsonl`, or any unparsable
/// row, contributes 0 / is skipped rather than erroring. Doctor visibility
/// only — never gates anything.
pub fn recent_failopen_counts(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    current_version: &str,
) -> FailopenCounts {
    let Ok(contents) = std::fs::read_to_string(dir.join("failopen.jsonl")) else {
        return FailopenCounts::default();
    };
    let cutoff_ts =
        jiff::Timestamp::try_from(now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH))
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let cutoff = cutoff_ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();

    FailopenCounts {
        panic: count_recent(&contents, &cutoff, "panic", None),
        parse: count_recent(&contents, &cutoff, "parse", None),
        version_mismatch: count_recent(
            &contents,
            &cutoff,
            "version_mismatch",
            Some(current_version),
        ),
        // Deadline rows are environment-correlated (slow disk, load), not
        // version-correlated — count across versions, like panic/parse.
        deadline: count_recent(&contents, &cutoff, "deadline", None),
        deadline_block_suppressed: count_recent(
            &contents,
            &cutoff,
            "deadline_block_suppressed",
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;

    // --- record shape ---

    #[test]
    fn record_has_expected_fields_for_panic() {
        let rec = build_failopen_record("panic", Some("cadence"), Some("terminology"), "1.2.3");
        assert_eq!(rec["schemaVersion"], 1);
        assert_eq!(rec["reason"], "panic");
        assert_eq!(rec["namespace"], "cadence");
        assert_eq!(rec["subcommand"], "terminology");
        assert_eq!(rec["binaryVersion"], "1.2.3");
        assert!(rec["ts"].is_string());
    }

    #[test]
    fn record_has_expected_fields_for_parse() {
        let rec = build_failopen_record("parse", Some("metrics"), Some("log-subagent"), "0.50.0");
        assert_eq!(rec["reason"], "parse");
        assert_eq!(rec["namespace"], "metrics");
        assert_eq!(rec["subcommand"], "log-subagent");
        assert_eq!(rec["binaryVersion"], "0.50.0");
    }

    #[test]
    fn record_has_expected_fields_for_version_mismatch() {
        let rec = build_failopen_record(
            "version_mismatch",
            Some("future-plugin"),
            Some("some-hook"),
            "0.50.0",
        );
        assert_eq!(rec["reason"], "version_mismatch");
        assert_eq!(rec["namespace"], "future-plugin");
        assert_eq!(rec["subcommand"], "some-hook");
    }

    #[test]
    fn record_nulls_namespace_and_subcommand_when_unknown() {
        let rec = build_failopen_record("panic", None, None, "0.50.0");
        assert_eq!(rec["reason"], "panic");
        assert!(rec["namespace"].is_null());
        assert!(rec["subcommand"].is_null());
        assert_eq!(rec["binaryVersion"], "0.50.0");
    }

    // --- log_failopen end-to-end (tempdir) ---

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
        let path = dir.join("failopen.jsonl");
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
    fn log_failopen_writes_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("parse", Some("cadence"), Some("terminology"), "1.2.3");
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["reason"], "parse");
        assert_eq!(rows[0]["namespace"], "cadence");
        assert_eq!(rows[0]["subcommand"], "terminology");
        assert_eq!(rows[0]["binaryVersion"], "1.2.3");
    }

    #[test]
    fn log_failopen_writes_null_fields_when_none() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", None, None, "0.50.0");
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["reason"], "panic");
        assert!(rows[0]["namespace"].is_null());
        assert!(rows[0]["subcommand"].is_null());
    }

    // --- count_recent (pure) ---

    fn sample_jsonl() -> String {
        [
            r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"version_mismatch","binaryVersion":"0.9.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"version_mismatch","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#,
            "not json at all",
        ]
        .join("\n")
    }

    #[test]
    fn count_recent_filters_by_reason_and_window() {
        let jsonl = sample_jsonl();
        let cutoff = "2026-07-01T00:00:00Z";
        assert_eq!(count_recent(&jsonl, cutoff, "panic", None), 1);
        assert_eq!(count_recent(&jsonl, cutoff, "parse", None), 2);
        assert_eq!(count_recent("", cutoff, "panic", None), 0);
    }

    #[test]
    fn count_recent_version_filter_scopes_version_mismatch() {
        let jsonl = sample_jsonl();
        let cutoff = "2026-07-01T00:00:00Z";
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("1.0.0")),
            1
        );
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("0.9.0")),
            1
        );
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("2.0.0")),
            0
        );
        assert_eq!(count_recent(&jsonl, cutoff, "version_mismatch", None), 2);
    }

    #[test]
    fn count_recent_garbage_lines_skipped_not_panicking() {
        assert_eq!(
            count_recent("not json\n{}\n", "2026-01-01T00:00:00Z", "panic", None),
            0
        );
    }

    // --- recent_failopen_counts end-to-end (tempdir) ---

    #[test]
    fn recent_failopen_counts_missing_file_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let counts = recent_failopen_counts(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
        );
        assert_eq!(counts, FailopenCounts::default());
    }

    #[test]
    fn recent_failopen_counts_groups_by_reason_and_current_version() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", Some("cadence"), Some("terminology"), "1.0.0");
            log_failopen("parse", Some("cadence"), Some("terminology"), "1.0.0");
            // Old-version mismatch: the sanctioned rollout transition — excluded.
            log_failopen("version_mismatch", Some("future"), Some("hook"), "0.9.0");
            // Current-version mismatch: didn't resolve — counted.
            log_failopen("version_mismatch", Some("future"), Some("hook"), "1.0.0");
        });
        let counts = recent_failopen_counts(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
        );
        assert_eq!(
            counts,
            FailopenCounts {
                panic: 1,
                parse: 1,
                version_mismatch: 1,
                deadline: 0,
                deadline_block_suppressed: 0,
            }
        );
    }

    #[test]
    fn recent_failopen_counts_excludes_outside_window() {
        let tmp = tempfile::tempdir().unwrap();
        let old_row = r#"{"schemaVersion":1,"reason":"panic","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        std::fs::write(tmp.path().join("failopen.jsonl"), format!("{old_row}\n")).unwrap();
        let counts = recent_failopen_counts(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
        );
        assert_eq!(counts, FailopenCounts::default());
    }
}
