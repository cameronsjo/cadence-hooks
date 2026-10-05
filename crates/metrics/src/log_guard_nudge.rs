//! Append-only telemetry for `session guard` nudge fires — one line per fire
//! to `<metrics_dir>/guard_nudges.jsonl` (cadence-hooks#272 item 1).
//!
//! The shared-main guard's three nudges (branch switch, blanket staging, a
//! write into a peer's declared lane) were uncounted, so whether any of them
//! earns a block tier could only be argued from anecdote. Each row names the
//! check that fired, so a per-check count is one `jq` group-by away: frequent
//! blanket-add rows at N≈10 argue for escalation, silence argues the prose is
//! winning. The escalation itself is a separate, later decision.
//!
//! A **free function**, like [`crate::log_sweep`]: `session guard` is a
//! PreToolUse check, not a dispatched `Logger`, so it calls this directly on
//! the nudge path. It writes a row and nothing else — no hook output, no
//! context. Fully fail-open (ADR-0001): every step degrades to a no-op.

use crate::common;
use serde_json::{Value, json};
use std::io::Write;

/// Schema version stamped on every `guard_nudges.jsonl` row. A new stream.
const GUARD_NUDGE_SCHEMA_VERSION: u32 = 1;

/// Build the `guard_nudges.jsonl` record. Pure — no I/O.
///
/// `session_id` is recorded only when it has the shape of a real one
/// ([`common::is_safe_session_id`]), else `null`: it comes from the payload.
/// Peer identities and the path that tripped a lane nudge are deliberately
/// left out — they come from peer-written files, and the counter needs only
/// which check fired and how many peers were live.
fn build_guard_nudge_record(
    ts: &str,
    check: &str,
    tool: &str,
    session_id: Option<&str>,
    peer_count: usize,
    repo: &str,
) -> Value {
    json!({
        "schemaVersion": GUARD_NUDGE_SCHEMA_VERSION,
        "ts": ts,
        "check": check,
        "tool": tool,
        "sessionId": session_id.filter(|id| common::is_safe_session_id(id)),
        "peerCount": peer_count,
        "repo": repo,
    })
}

/// Append one nudge-fire row to `<metrics_dir>/guard_nudges.jsonl`.
///
/// `check` names the nudge (`branch_switch` | `blanket_add` |
/// `lane_collision`), `tool` the tool it fired on, `peer_count` the live peers
/// at fire time, and `cwd` the session cwd the repo name is resolved from.
pub fn log_guard_nudge(
    check: &str,
    tool: &str,
    session_id: Option<&str>,
    peer_count: usize,
    cwd: Option<&str>,
) {
    let record = build_guard_nudge_record(
        &common::utc_timestamp(),
        check,
        tool,
        session_id,
        peer_count,
        &common::repo_basename(cwd),
    );
    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(mut handle) = common::open_ledger(dir.join("guard_nudges.jsonl")) {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        let mut line = record.to_string();
        line.push('\n');
        let _ = handle.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;

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

    #[test]
    fn record_shape_per_check() {
        for (check, tool) in [
            ("branch_switch", "Bash"),
            ("blanket_add", "Bash"),
            ("lane_collision", "Edit"),
            ("lane_collision", "Bash"),
        ] {
            let rec = build_guard_nudge_record("T", check, tool, Some("sess-1"), 2, "repo");
            assert_eq!(rec["schemaVersion"], 1, "{rec}");
            assert_eq!(rec["ts"], "T");
            assert_eq!(rec["check"], check);
            assert_eq!(rec["tool"], tool);
            assert_eq!(rec["sessionId"], "sess-1");
            assert_eq!(rec["peerCount"], 2);
            assert_eq!(rec["repo"], "repo");
        }
    }

    #[test]
    fn unsafe_or_missing_session_id_records_null() {
        for id in [None, Some(""), Some("../etc"), Some("a b")] {
            let rec = build_guard_nudge_record("T", "blanket_add", "Bash", id, 1, "r");
            assert!(rec["sessionId"].is_null(), "{id:?} -> {rec}");
        }
    }

    #[test]
    fn log_guard_nudge_appends_one_row_per_fire() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_guard_nudge("branch_switch", "Bash", Some("s-1"), 1, None);
            log_guard_nudge("lane_collision", "Write", Some("s-1"), 3, None);
        });
        let text = std::fs::read_to_string(tmp.path().join("guard_nudges.jsonl")).unwrap();
        let rows: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("valid JSON row"))
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["check"], "branch_switch");
        assert_eq!(rows[1]["check"], "lane_collision");
        assert_eq!(rows[1]["peerCount"], 3);
    }

    #[test]
    fn unwritable_metrics_dir_is_a_silent_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular file where the metrics dir should be: create_dir_all fails.
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, "x").unwrap();
        with_metrics_dir(&blocker, || {
            log_guard_nudge("blanket_add", "Bash", Some("s-1"), 1, None);
        });
        assert_eq!(std::fs::read_to_string(&blocker).unwrap(), "x");
    }
}
