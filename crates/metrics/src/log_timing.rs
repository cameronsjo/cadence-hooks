//! Threshold-gated self-timing for the hook dispatch hot path: one line per
//! *slow* hook to `<metrics_dir>/hooks.jsonl`, so a guard or logger that starts
//! costing real wall-clock time surfaces in telemetry instead of hiding.
//!
//! Called from the **binary** (`src/dispatch.rs`), which is the only layer that
//! wraps a hook's full run and knows the canonical registry name. The timing
//! write is the last side effect before exit: it runs *after* the guard's
//! decision has been logged and *before* the process emits and exits, so it can
//! never perturb the block message, the exit code, or the logger's output.
//!
//! **Gated by construction:** the common case is a *fast* hook, and a fast hook
//! writes nothing — `over_threshold` filters below `CADENCE_HOOK_TIMING_THRESHOLD_MS`
//! (default 1000ms) so the hot path adds zero I/O until a hook is genuinely slow.
//! Every step is fail-open per ADR-0001 — a full disk or a read-only metrics dir
//! degrades to a no-op and the hook's own behavior is unchanged.

use crate::common;
use serde_json::{Value, json};
use std::io::Write;

/// Default slow-hook threshold in milliseconds when
/// `CADENCE_HOOK_TIMING_THRESHOLD_MS` is unset or unparseable.
const DEFAULT_THRESHOLD_MS: u128 = 1000;

/// Record a hook's wall-clock time at the dispatch seam — but only when it
/// exceeds the threshold.
///
/// `hook` is the canonical registry name threaded from the binary, `plugin` its
/// namespace, `event` the rendered event string (e.g. `PreToolUse`, `logger`),
/// and `elapsed_ms` the measured duration. `session_id` is recorded when present
/// and null otherwise. Fully fail-open: any error along the way is a no-op.
pub fn log_timing(
    hook: &str,
    plugin: &str,
    event: &str,
    elapsed_ms: u128,
    session_id: Option<&str>,
) {
    if !over_threshold(elapsed_ms, threshold_ms()) {
        return;
    }

    let record = build_timing_record(hook, plugin, event, elapsed_ms, session_id);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("hooks.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        // `record` is compact JSON — one line, no embedded newlines.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// The slow-hook threshold in milliseconds. Reads
/// `CADENCE_HOOK_TIMING_THRESHOLD_MS`; a missing or unparseable value falls back
/// to [`DEFAULT_THRESHOLD_MS`].
fn threshold_ms() -> u128 {
    std::env::var("CADENCE_HOOK_TIMING_THRESHOLD_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_THRESHOLD_MS)
}

/// True when `elapsed_ms` strictly exceeds `threshold`. Pure — the elapsed value
/// is passed in so the gate is unit-testable without sleeping. Strict `>` so a
/// hook landing exactly on the threshold is *not* logged.
fn over_threshold(elapsed_ms: u128, threshold: u128) -> bool {
    elapsed_ms > threshold
}

/// Build the `hooks.jsonl` record. Pure — no I/O beyond [`common::utc_timestamp`].
/// camelCase keys: `ts`, `hook`, `plugin`, `event`, `elapsedMs` (numeric),
/// `sessionId` (null when `None`).
fn build_timing_record(
    hook: &str,
    plugin: &str,
    event: &str,
    elapsed_ms: u128,
    session_id: Option<&str>,
) -> Value {
    json!({
        "ts": common::utc_timestamp(),
        "hook": hook,
        "plugin": plugin,
        "event": event,
        "elapsedMs": elapsed_ms,
        "sessionId": session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- over_threshold ---

    #[test]
    fn over_threshold_true_above() {
        assert!(over_threshold(1500, 1000));
    }

    #[test]
    fn over_threshold_false_at_boundary() {
        // Strict `>` — a hook exactly at the threshold is not slow.
        assert!(!over_threshold(1000, 1000));
    }

    #[test]
    fn over_threshold_false_below() {
        assert!(!over_threshold(500, 1000));
    }

    // --- threshold_ms (env-mutating; serialized) ---

    /// Serialize the env-mutating tests against every other module's: the
    /// process-global `CADENCE_HOOK_TIMING_THRESHOLD_MS` / `CADENCE_METRICS_DIR`
    /// are shared with sibling loggers' tests (`log_denial`), so all hold the one
    /// crate-wide lock.
    use crate::common::ENV_LOCK;

    fn with_threshold_env<F: FnOnce()>(value: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            match value {
                Some(v) => std::env::set_var("CADENCE_HOOK_TIMING_THRESHOLD_MS", v),
                None => std::env::remove_var("CADENCE_HOOK_TIMING_THRESHOLD_MS"),
            }
        }
        f();
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::remove_var("CADENCE_HOOK_TIMING_THRESHOLD_MS");
        }
    }

    #[test]
    fn threshold_ms_reads_env() {
        with_threshold_env(Some("250"), || {
            assert_eq!(threshold_ms(), 250);
        });
    }

    #[test]
    fn threshold_ms_defaults_when_unset() {
        with_threshold_env(None, || {
            assert_eq!(threshold_ms(), DEFAULT_THRESHOLD_MS);
        });
    }

    #[test]
    fn threshold_ms_defaults_on_garbage() {
        with_threshold_env(Some("abc"), || {
            assert_eq!(threshold_ms(), DEFAULT_THRESHOLD_MS);
        });
    }

    // --- build_timing_record ---

    #[test]
    fn record_has_expected_camelcase_fields() {
        let rec = build_timing_record("terminology", "cadence", "PreToolUse", 1500, Some("sess-1"));
        assert_eq!(rec["hook"], "terminology");
        assert_eq!(rec["plugin"], "cadence");
        assert_eq!(rec["event"], "PreToolUse");
        // Numeric, not a string.
        assert_eq!(rec["elapsedMs"], 1500);
        assert!(rec["elapsedMs"].is_number());
        assert_eq!(rec["sessionId"], "sess-1");
        assert!(rec["ts"].is_string());
    }

    #[test]
    fn record_session_id_null_when_none() {
        let rec = build_timing_record("git-safety", "cadence", "PreToolUse", 2000, None);
        assert!(rec["sessionId"].is_null());
    }

    // --- log_timing end-to-end (tempdir, default threshold) ---

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test in this module.
        // Clear the threshold so the default (1000ms) applies.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
            std::env::remove_var("CADENCE_HOOK_TIMING_THRESHOLD_MS");
        }
        f();
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("hooks.jsonl");
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
    fn slow_hook_writes_one_row() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            // Elapsed injected as a u128 — no Instant, no sleep.
            log_timing("terminology", "cadence", "PreToolUse", 1500, Some("sess-1"));
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["elapsedMs"], 1500);
        assert_eq!(rows[0]["hook"], "terminology");
        assert_eq!(rows[0]["plugin"], "cadence");
    }

    #[test]
    fn fast_hook_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_timing("terminology", "cadence", "PreToolUse", 500, Some("sess-1"));
        });
        assert!(
            read_lines(tmp.path()).is_empty(),
            "a fast hook must not write a row"
        );
        assert!(!tmp.path().join("hooks.jsonl").exists());
    }
}
