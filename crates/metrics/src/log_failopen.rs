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
/// `version_mismatch` is pre-filtered (by [`counts_from`]) to rows whose
/// `binaryVersion` equals the caller's `current_version` — see that function's
/// doc for why.
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

/// Recency + version context for one `reason`'s windowed rows — the fields
/// doctor needs to tell a *fixed* fail-open burst from a *live* one. Counting
/// stays window-wide (a wiring problem is not version-specific, so filtering
/// the count the way `version_mismatch` does would under-report a live issue);
/// this rides alongside the count instead. It names when the reason last fired,
/// on which binary version, and how many of the windowed rows carry the CURRENT
/// binary's version. Zero on the current version is the tell that the feed was
/// already fixed in a shipped release and the burst is just aging out of the
/// 7-day window.
#[derive(Debug, PartialEq, Eq)]
pub struct FailopenRecency {
    /// The most recent windowed row's `ts` for this reason.
    pub last_ts: String,
    /// The `binaryVersion` on that most recent row (`"unknown"` if it was
    /// absent — every row written by this binary stamps one).
    pub last_version: String,
    /// How many of this reason's windowed rows carry `current_version`.
    pub on_current_version: u64,
}

/// The `failopen.jsonl` rows matching `reason` within the window — the single
/// filter both counting and recency read, so their row sets are structurally
/// the same rather than two prose-aligned re-implementations. Pure — operates
/// on file contents, no I/O.
///
/// `ts` is compared lexicographically against `cutoff` — valid because both
/// are the same fixed-width ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) shape, which sorts
/// identically to chronological order. Unparsable rows and rows missing
/// `reason` or `ts` are skipped.
fn windowed_rows<'a>(
    jsonl: &'a str,
    cutoff: &'a str,
    reason: &'a str,
) -> impl Iterator<Item = Value> + 'a {
    jsonl
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(move |v| v.get("reason").and_then(Value::as_str) == Some(reason))
        .filter(move |v| {
            v.get("ts")
                .and_then(Value::as_str)
                .is_some_and(|ts| ts >= cutoff)
        })
}

/// Count [`windowed_rows`] for `reason`, optionally narrowing to an exact
/// `binaryVersion` match (`version_filter`). Pure — no I/O.
fn count_recent(jsonl: &str, cutoff: &str, reason: &str, version_filter: Option<&str>) -> u64 {
    windowed_rows(jsonl, cutoff, reason)
        .filter(|v| match version_filter {
            Some(want) => v.get("binaryVersion").and_then(Value::as_str) == Some(want),
            None => true,
        })
        .count() as u64
}

/// Lexicographically-comparable ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) lower bound for
/// `window` before `now` — the cutoff every row's `ts` is compared against, by
/// both counting and recency. Its fixed-width shape sorts identically to
/// chronological order, so a plain string compare is a valid time compare.
fn window_cutoff(now: SystemTime, window: Duration) -> String {
    let cutoff_ts =
        jiff::Timestamp::try_from(now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH))
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    cutoff_ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Counts grouped by `reason` over already-read `failopen.jsonl` `contents`.
/// Pure — no I/O.
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
fn counts_from(contents: &str, cutoff: &str, current_version: &str) -> FailopenCounts {
    FailopenCounts {
        panic: count_recent(contents, cutoff, "panic", None),
        parse: count_recent(contents, cutoff, "parse", None),
        version_mismatch: count_recent(contents, cutoff, "version_mismatch", Some(current_version)),
        // Deadline rows are environment-correlated (slow disk, load), not
        // version-correlated — count across versions, like panic/parse.
        deadline: count_recent(contents, cutoff, "deadline", None),
        deadline_block_suppressed: count_recent(
            contents,
            cutoff,
            "deadline_block_suppressed",
            None,
        ),
    }
}

/// Per-reason counts plus recency + version context for `recency_reason`, from a
/// single read of `<dir>/failopen.jsonl`. Doctor's `parse` finding needs both
/// the count and the recency clause, so folding them into one reader parses the
/// file once — the counts and the recency derive from the same [`windowed_rows`]
/// pass, not two independent reads.
///
/// The recency component is `None` when `recency_reason` has no rows in the
/// window. Fail-open: a missing/unreadable file yields `(FailopenCounts::default(),
/// None)` rather than erroring. Doctor visibility only — never gates anything.
pub fn recent_failopen_report(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    current_version: &str,
    recency_reason: &str,
) -> (FailopenCounts, Option<FailopenRecency>) {
    let Ok(contents) = std::fs::read_to_string(dir.join("failopen.jsonl")) else {
        return (FailopenCounts::default(), None);
    };
    let cutoff = window_cutoff(now, window);
    let counts = counts_from(&contents, &cutoff, current_version);
    let recency = recency_from(&contents, &cutoff, recency_reason, current_version);
    (counts, recency)
}

/// Strip control characters (ANSI escapes, newlines) from a file-sourced string
/// before it is interpolated into terminal-printed `doctor` output.
fn display_safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Pure recency computation over `failopen.jsonl` contents. Reads the same
/// [`windowed_rows`] `count_recent` counts — so the recency row set *is* the
/// counted set, not a parallel re-derivation — then reports the max-`ts` row's
/// timestamp and version plus the current-version row count. `None` when no row
/// matches.
fn recency_from(
    jsonl: &str,
    cutoff: &str,
    reason: &str,
    current_version: &str,
) -> Option<FailopenRecency> {
    let rows: Vec<Value> = windowed_rows(jsonl, cutoff, reason).collect();

    // Comparator form, not `max_by_key`: the key borrows from the row, which a
    // `-> B` key closure can't outlive. On a `ts` tie (two rows in the same
    // second, plausible under a burst) `max_by` keeps the later row in file
    // order — an arbitrary but deterministic winner, which is all a recency
    // display needs.
    let last = rows.iter().max_by(|a, b| {
        let ta = a.get("ts").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("ts").and_then(Value::as_str).unwrap_or("");
        ta.cmp(tb)
    })?;
    // display_safe: these land verbatim in a terminal-printed doctor diagnosis.
    // The values are this binary's own `ts`/`binaryVersion`, so only a
    // hand-tampered failopen.jsonl could smuggle ANSI/control bytes through —
    // strip them as defense-in-depth against escape-sequence injection.
    let last_ts = display_safe(last.get("ts").and_then(Value::as_str)?);
    let last_version = display_safe(
        last.get("binaryVersion")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    );
    let on_current_version = rows
        .iter()
        .filter(|v| v.get("binaryVersion").and_then(Value::as_str) == Some(current_version))
        .count() as u64;

    Some(FailopenRecency {
        last_ts,
        last_version,
        on_current_version,
    })
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

    // --- recent_failopen_report end-to-end (tempdir) ---

    #[test]
    fn recent_failopen_report_missing_file_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        let (counts, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            "parse",
        );
        assert_eq!(counts, FailopenCounts::default());
        assert!(recency.is_none());
    }

    #[test]
    fn recent_failopen_report_groups_by_reason_and_current_version() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", Some("cadence"), Some("terminology"), "1.0.0");
            log_failopen("parse", Some("cadence"), Some("terminology"), "1.0.0");
            // Old-version mismatch: the sanctioned rollout transition — excluded.
            log_failopen("version_mismatch", Some("future"), Some("hook"), "0.9.0");
            // Current-version mismatch: didn't resolve — counted.
            log_failopen("version_mismatch", Some("future"), Some("hook"), "1.0.0");
        });
        let (counts, _) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            "parse",
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

    // --- recency (pure + end-to-end) ---

    #[test]
    fn recency_from_reports_last_row_and_current_version_count() {
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-18T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.66.0","ts":"2026-07-19T00:00:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        // Max-ts row is the 0.61.0 one at 20:51, even though it is not last in
        // file order — recency picks by timestamp, not position.
        assert_eq!(recency.last_ts, "2026-07-20T20:51:00Z");
        assert_eq!(recency.last_version, "0.61.0");
        assert_eq!(recency.on_current_version, 1);
    }

    #[test]
    fn recency_from_none_on_current_version_is_the_fixed_burst_signal() {
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-18T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.on_current_version, 0);
        assert_eq!(recency.last_version, "0.61.0");
    }

    #[test]
    fn recency_from_ts_tie_keeps_later_file_order_row() {
        // Two rows in the same second — the documented `max_by` tie rule keeps
        // the later one in file order.
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.62.0","ts":"2026-07-20T20:51:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "0.62.0");
    }

    #[test]
    fn recency_from_no_matching_rows_is_none() {
        let jsonl = r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2026-07-20T00:00:00Z"}"#;
        assert!(recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "1.0.0").is_none());
    }

    #[test]
    fn recency_from_excludes_rows_outside_window() {
        let jsonl = r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        assert!(recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "1.0.0").is_none());
    }

    #[test]
    fn recency_from_missing_binary_version_reports_unknown() {
        let jsonl = r#"{"reason":"parse","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "unknown");
        assert_eq!(recency.on_current_version, 0);
    }

    #[test]
    fn recency_from_strips_control_bytes_from_display_fields() {
        // A hand-tampered row smuggling an ANSI escape (JSON \u001b) into
        // binaryVersion — the ESC byte is stripped, leaving the sequence's inert
        // tail as plain text rather than a terminal color command.
        let jsonl =
            r#"{"reason":"parse","binaryVersion":"0.61.0\u001b[31mX","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "0.61.0[31mX");
    }

    #[test]
    fn recent_failopen_report_recency_reads_written_rows() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("parse", Some("cadence"), Some("heartbeat"), "0.61.0");
        });
        let (_, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "0.66.0",
            "parse",
        );
        let recency = recency.unwrap();
        assert_eq!(recency.last_version, "0.61.0");
        assert_eq!(recency.on_current_version, 0);
    }

    #[test]
    fn recent_failopen_report_excludes_outside_window() {
        let tmp = tempfile::tempdir().unwrap();
        let old_row = r#"{"schemaVersion":1,"reason":"panic","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        std::fs::write(tmp.path().join("failopen.jsonl"), format!("{old_row}\n")).unwrap();
        let (counts, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            "parse",
        );
        assert_eq!(counts, FailopenCounts::default());
        assert!(recency.is_none());
    }
}
