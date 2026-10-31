//! `SubagentStart` / `SubagentStop` — append one line per event to
//! `<metrics_dir>/subagents.jsonl`.
//!
//! Port of `log-subagent-event.sh`. A lifecycle audit log, plus a cost flush
//! on `SubagentStop` (#283): the agent's own transcript is scanned and priced
//! with the same machinery `log-commit` / `log-session` use, so read-only
//! agents (reviewers, explorers) that never commit still land a `costUsd`.
//! Cost fields are `null` when the agent transcript is missing, unreadable, or
//! carries no usage — the lifecycle row is written regardless (fail soft).
//! When `CADENCE_METRICS_DEBUG=1`, a `_keys` array of the raw payload's
//! top-level keys is appended, surfacing schema additions across Claude Code
//! releases.

use crate::common;
use crate::compute_cost::compute_cost_by_model;
use crate::prices::Prices;
use crate::transcript::{TranscriptScan, UsageScan, scan_transcript};
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Appends a line to `subagents.jsonl` for each subagent lifecycle event.
pub struct LogSubagent;

impl Logger for LogSubagent {
    fn name(&self) -> &str {
        "log-subagent"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(event) = input.hook_event_name.as_deref() else {
            return;
        };
        if event != "SubagentStart" && event != "SubagentStop" {
            return;
        }
        if is_side_agent_stop(event, input.agent_type.as_deref()) {
            return;
        }

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let debug = std::env::var("CADENCE_METRICS_DEBUG").as_deref() == Ok("1");
        let mut record = build_subagent_record(input, &common::utc_timestamp(), debug);
        let marker = start_marker_path(
            &common::state_dir(),
            input.session_id.as_deref(),
            input.agent_id.as_deref(),
        );
        if event == "SubagentStart" {
            if let Some(marker) = marker
                && has_agent_type(input.agent_type.as_deref())
            {
                write_start_marker(&marker, now_ms());
            }
        } else {
            if input.duration_ms.is_none()
                && let Some(ms) = marker.as_deref().and_then(take_start_marker)
                && let Some(elapsed) = elapsed_ms(ms, now_ms())
            {
                record["durationMs"] = json!(elapsed);
            }
            let prices = Prices::load(None);
            let usage = agent_transcript_path(input).and_then(|p| scan_agent_transcript(&p));
            add_cost_fields(&mut record, usage.as_ref(), &prices);
        }

        if let Ok(mut file) = common::open_ledger(dir.join("subagents.jsonl")) {
            // Build the whole line (record + newline) and write it in one
            // write_all, matching log_commit.rs — a single O_APPEND write is
            // atomic, so concurrent appends from parallel subagents can't
            // interleave a record with its trailing newline (#94).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// A `SubagentStop` with no agent type is one of the harness's own side agents,
/// not one the session dispatched: every dispatched agent, `general-purpose`
/// included, carries a type and has a `SubagentStart`, and these have neither a
/// Start nor a transcript. They were 62k of 75k Stop rows (cadence-hooks#1587).
/// Pure.
fn is_side_agent_stop(event: &str, agent_type: Option<&str>) -> bool {
    event == "SubagentStop" && !has_agent_type(agent_type)
}

/// True when the payload names an agent type. A Start marker is written only
/// for a typed Start, since only a typed Stop reads it back. Pure.
fn has_agent_type(agent_type: Option<&str>) -> bool {
    agent_type.is_some_and(|t| !t.trim().is_empty())
}

/// `<state>/subagents/<session>/<agent>.start`, holding the Start time in epoch
/// milliseconds. `None` when either id is missing or could steer the path out
/// of the state dir. `log-session` removes the session's directory at
/// SessionEnd, so a Start whose Stop never arrives does not linger. Pure.
fn start_marker_path(
    state_dir: &Path,
    session_id: Option<&str>,
    agent_id: Option<&str>,
) -> Option<PathBuf> {
    let session = session_id.filter(|s| common::is_safe_session_id(s))?;
    let agent = agent_id.filter(|s| common::is_safe_session_id(s))?;
    Some(
        state_dir
            .join("subagents")
            .join(session)
            .join(format!("{agent}.start")),
    )
}

/// Milliseconds from Start to Stop, or `None` when the clock went backwards.
/// Pure.
fn elapsed_ms(start_ms: u64, now_ms: u64) -> Option<u64> {
    now_ms.checked_sub(start_ms)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Fail-open (ADR-0001): a write that fails leaves the Stop row without a
/// duration, nothing more.
fn write_start_marker(marker: &Path, ms: u64) {
    if let Some(parent) = marker.parent()
        && common::create_private_dir(parent).is_ok()
        && let Ok(mut file) = common::open_state_marker(marker, false)
    {
        let _ = file.write_all(ms.to_string().as_bytes());
    }
}

/// Read and remove the Start marker. `None` when it is missing or unparsable.
fn take_start_marker(marker: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(marker).ok()?;
    let _ = std::fs::remove_file(marker);
    text.trim().parse().ok()
}

/// Build the JSONL record for a subagent event. Pure — no I/O.
fn build_subagent_record(input: &MetricsInput, ts: &str, include_keys: bool) -> Value {
    let mut record = json!({
        "ts": ts,
        "event": input.hook_event_name,
        "sessionId": input.session_id,
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
        "parentAgentId": input.parent_agent_id,
        "sourceAgentId": input.source_agent_id,
        "cwd": input.cwd,
        "transcriptPath": input.transcript_path,
        "durationMs": input.duration_ms,
    });

    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }

    record
}

/// The subagent's own transcript: `<parent transcript minus .jsonl>/subagents/
/// agent-<agentId>.jsonl`. `transcript_path` on a `SubagentStop` payload names
/// the *parent* session transcript. `None` when either input is absent, the
/// parent path doesn't end in `.jsonl`, or `agent_id` could steer the join
/// outside that directory (same charset gate as session ids). Pure.
fn agent_transcript_path(input: &MetricsInput) -> Option<PathBuf> {
    let agent_id = input
        .agent_id
        .as_deref()
        .filter(|s| common::is_safe_session_id(s))?;
    let parent = input.transcript_path.as_deref()?.strip_suffix(".jsonl")?;
    if parent.is_empty() {
        return None;
    }
    Some(
        Path::new(parent)
            .join("subagents")
            .join(format!("agent-{agent_id}.jsonl")),
    )
}

/// Upper bound on how much of an agent transcript is read. The path is built
/// from payload fields, so the file behind it is not trusted to be small; a
/// transcript past this size records `null` cost rather than holding the hook
/// open on an unbounded read. Read through `core::paths::read_capped`, which
/// also refuses a FIFO or device without blocking on it.
const MAX_AGENT_TRANSCRIPT_BYTES: u64 = 256 * 1024 * 1024;

/// Scan the whole agent transcript for usage. `None` on a missing, unreadable,
/// non-regular, or oversized file, or one with no assistant usage yet (e.g. not
/// flushed at the hook tick) — the caller then records the cost fields as
/// `null`.
fn scan_agent_transcript(path: &Path) -> Option<UsageScan> {
    scan_agent_transcript_capped(path, MAX_AGENT_TRANSCRIPT_BYTES)
}

/// [`scan_agent_transcript`] with the cap as a parameter, so the over-cap arm
/// is testable without a 256 MiB fixture.
fn scan_agent_transcript_capped(path: &Path, cap: u64) -> Option<UsageScan> {
    let transcript = cadence_hooks_core::paths::read_capped(path, cap)?;
    match scan_transcript(&transcript, None) {
        TranscriptScan::Usage(usage) => Some(usage),
        TranscriptScan::Diagnostic(_) | TranscriptScan::Empty => None,
    }
}

/// Stamp `model` / `tokens` / `byModel` / `unpricedModels` / `costUsd` onto a
/// Stop record — the same shapes `commits.jsonl` and `sessions.jsonl` carry,
/// priced from the same table, so the three ledgers stay comparable. With no
/// usage every field is `null` ("unknown"), never `0` ("free"). Pure.
fn add_cost_fields(record: &mut Value, usage: Option<&UsageScan>, prices: &Prices) {
    let Some(obj) = record.as_object_mut() else {
        return;
    };
    let Some(usage) = usage else {
        for key in ["model", "tokens", "byModel", "unpricedModels", "costUsd"] {
            obj.insert(key.into(), Value::Null);
        }
        return;
    };
    let (by_model, unpriced) = usage.priced_breakdown(prices);
    obj.insert("model".into(), json!(usage.scan.model));
    obj.insert("tokens".into(), usage.tokens_json());
    obj.insert("byModel".into(), json!(by_model));
    obj.insert("unpricedModels".into(), json!(unpriced));
    obj.insert(
        "costUsd".into(),
        json!(compute_cost_by_model(&usage.scan.by_model, prices)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop_event() -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("SubagentStop".into()),
            session_id: Some("s1".into()),
            agent_id: Some("a1".into()),
            agent_type: Some("Explore".into()),
            duration_ms: Some(4200),
            raw_keys: vec!["hook_event_name".into(), "agent_id".into()],
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_subagent() {
        assert_eq!(LogSubagent.name(), "log-subagent");
    }

    #[test]
    fn record_carries_lifecycle_fields() {
        let record = build_subagent_record(&stop_event(), "2026-05-19T00:00:00Z", false);
        assert_eq!(record["event"], "SubagentStop");
        assert_eq!(record["agentType"], "Explore");
        assert_eq!(record["durationMs"], 4200);
        assert_eq!(record["ts"], "2026-05-19T00:00:00Z");
        // Absent fields serialize as null, not omitted.
        assert!(record["parentSessionId"].is_null());
        assert!(record.get("_keys").is_none());
    }

    #[test]
    fn debug_adds_keys() {
        let record = build_subagent_record(&stop_event(), "2026-05-19T00:00:00Z", true);
        let keys = record["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("agent_id")));
    }

    #[test]
    fn non_subagent_event_is_noop() {
        // PreToolUse should not be logged here.
        let input = MetricsInput {
            hook_event_name: Some("PreToolUse".into()),
            ..Default::default()
        };
        LogSubagent.run(&input);
    }

    fn with_metrics_dir<F: FnOnce()>(dir: &Path, f: F) {
        let _guard = crate::common::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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

    fn rows(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("subagents.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn event(name: &str, agent_type: Option<&str>) -> MetricsInput {
        MetricsInput {
            hook_event_name: Some(name.into()),
            session_id: Some("s1".into()),
            agent_id: Some("a1".into()),
            agent_type: agent_type.map(String::from),
            ..Default::default()
        }
    }

    /// cadence-hooks#1587: a Stop with no agent type is a harness side agent
    /// and writes no row; a typed Stop still does.
    #[test]
    fn side_agent_stop_writes_no_row() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            LogSubagent.run(&event("SubagentStop", Some("")));
            LogSubagent.run(&event("SubagentStop", None));
            LogSubagent.run(&event("SubagentStop", Some("Explore")));
        });
        let rows = rows(tmp.path());
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["agentType"], "Explore");
    }

    #[test]
    fn side_agent_predicate() {
        assert!(is_side_agent_stop("SubagentStop", None));
        assert!(is_side_agent_stop("SubagentStop", Some(" ")));
        assert!(!is_side_agent_stop("SubagentStop", Some("general-purpose")));
        assert!(!is_side_agent_stop("SubagentStart", None));
    }

    /// A Stop with no payload duration takes it from the Start marker, then
    /// removes the marker.
    #[test]
    fn stop_fills_duration_from_the_start_marker() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            LogSubagent.run(&event("SubagentStart", Some("Explore")));
            LogSubagent.run(&event("SubagentStop", Some("Explore")));
        });
        let rows = rows(tmp.path());
        assert_eq!(rows.len(), 2);
        assert!(rows[0]["durationMs"].is_null(), "Start has no duration");
        assert!(rows[1]["durationMs"].is_u64(), "{}", rows[1]);
        assert!(
            !tmp.path().join("state/subagents/s1/a1.start").exists(),
            "the marker is consumed"
        );
    }

    /// The duration is measured from the marker's time: a Start ten seconds
    /// ago yields at least ten seconds.
    #[test]
    fn duration_is_measured_from_the_marker_time() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("state/subagents/s1/a1.start");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, (now_ms() - 10_000).to_string()).unwrap();
        with_metrics_dir(tmp.path(), || {
            LogSubagent.run(&event("SubagentStop", Some("Explore")));
        });
        let ms = rows(tmp.path())[0]["durationMs"].as_u64().unwrap();
        assert!((10_000..60_000).contains(&ms), "{ms}");
    }

    /// An untyped Start would never be read back, so it writes no marker.
    #[test]
    fn untyped_start_writes_no_marker() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            LogSubagent.run(&event("SubagentStart", Some("")));
        });
        assert!(!tmp.path().join("state/subagents/s1/a1.start").exists());
    }

    /// A duration the payload already carries wins over the marker.
    #[test]
    fn payload_duration_wins_over_the_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let mut stop = event("SubagentStop", Some("Explore"));
        stop.duration_ms = Some(4200);
        with_metrics_dir(tmp.path(), || {
            LogSubagent.run(&event("SubagentStart", Some("Explore")));
            LogSubagent.run(&stop);
        });
        assert_eq!(rows(tmp.path())[1]["durationMs"], 4200);
    }

    #[test]
    fn start_marker_path_refuses_unsafe_ids() {
        let state = Path::new("/state");
        assert_eq!(
            start_marker_path(state, Some("s1"), Some("a1")),
            Some(PathBuf::from("/state/subagents/s1/a1.start"))
        );
        assert_eq!(start_marker_path(state, Some("../x"), Some("a1")), None);
        assert_eq!(start_marker_path(state, Some("s1"), Some("a/b")), None);
        assert_eq!(start_marker_path(state, None, Some("a1")), None);
    }

    #[test]
    fn elapsed_ms_refuses_a_backwards_clock() {
        assert_eq!(elapsed_ms(1_000, 1_500), Some(500));
        assert_eq!(elapsed_ms(2_000, 1_500), None);
    }

    #[test]
    fn record_serializes_to_single_line() {
        // #94: the single-write_all fix is only atomic-per-record if the record
        // has no embedded newline. Compact JSON guarantees this; lock it down.
        let line = build_subagent_record(&stop_event(), "2026-05-19T00:00:00Z", true).to_string();
        assert!(!line.contains('\n'), "record must be one line: {line}");
    }

    const AGENT_TRANSCRIPT: &str = concat!(
        r#"{"type":"user","message":{"role":"user","content":"review this"}}"#,
        "\n",
        r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":1000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":100}}}"#,
        "\n",
        r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":500,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":50}}}"#,
        "\n",
    );

    #[test]
    fn agent_transcript_path_derives_from_parent_and_agent_id() {
        let input = MetricsInput {
            transcript_path: Some("/p/slug/sess-1.jsonl".into()),
            agent_id: Some("abc123".into()),
            ..Default::default()
        };
        assert_eq!(
            agent_transcript_path(&input),
            Some(PathBuf::from("/p/slug/sess-1/subagents/agent-abc123.jsonl"))
        );
    }

    #[test]
    fn agent_transcript_path_rejects_unsafe_agent_id_and_bad_parent() {
        for (tp, aid) in [
            ("/p/s.jsonl", "../../etc/passwd"),
            ("/p/s.jsonl", "a/b"),
            ("/p/s.jsonl", ""),
            ("/p/s.txt", "abc"),
            (".jsonl", "abc"),
        ] {
            let input = MetricsInput {
                transcript_path: Some(tp.into()),
                agent_id: Some(aid.into()),
                ..Default::default()
            };
            assert_eq!(agent_transcript_path(&input), None, "{tp} / {aid}");
        }
    }

    #[test]
    fn stop_record_carries_cost_from_agent_transcript() {
        let tmp = tempfile::TempDir::new().unwrap();
        let parent = tmp.path().join("sess-1.jsonl");
        std::fs::write(&parent, "").unwrap();
        let agent_dir = tmp.path().join("sess-1").join("subagents");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(agent_dir.join("agent-a1.jsonl"), AGENT_TRANSCRIPT).unwrap();

        let input = MetricsInput {
            transcript_path: Some(parent.to_string_lossy().into_owned()),
            ..stop_event()
        };
        let prices = Prices::embedded();
        let usage = agent_transcript_path(&input).and_then(|p| scan_agent_transcript(&p));
        assert!(usage.is_some(), "fixture must produce a usage scan");
        let mut record = build_subagent_record(&input, "2026-05-19T00:00:00Z", false);
        add_cost_fields(&mut record, usage.as_ref(), &prices);

        assert_eq!(record["model"], "claude-opus-4-7");
        assert_eq!(record["tokens"]["input"], 1500);
        assert_eq!(record["tokens"]["output"], 150);
        let expected = compute_cost_by_model(&usage.as_ref().unwrap().scan.by_model, &prices);
        assert!(expected > 0.0, "opus-4-7 must be priced");
        assert_eq!(record["costUsd"], json!(expected));
        assert_eq!(record["byModel"].as_array().unwrap().len(), 1);
        assert!(!record.to_string().contains("review this"));
    }

    #[test]
    fn stop_record_cost_is_null_when_agent_transcript_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input = MetricsInput {
            transcript_path: Some(tmp.path().join("gone.jsonl").to_string_lossy().into_owned()),
            ..stop_event()
        };
        let usage = agent_transcript_path(&input).and_then(|p| scan_agent_transcript(&p));
        assert!(usage.is_none());
        let mut record = build_subagent_record(&input, "2026-05-19T00:00:00Z", false);
        add_cost_fields(&mut record, None, &Prices::embedded());
        for key in ["model", "tokens", "byModel", "unpricedModels", "costUsd"] {
            assert!(record.get(key).is_some_and(Value::is_null), "{key}");
        }
        // Lifecycle fields survive the cost miss.
        assert_eq!(record["agentType"], "Explore");
    }

    #[test]
    fn stop_record_cost_is_null_when_agent_transcript_has_no_usage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("agent-a1.jsonl");
        std::fs::write(
            &path,
            r#"{"type":"user","message":{"role":"user","content":"x"}}"#,
        )
        .unwrap();
        assert!(scan_agent_transcript(&path).is_none());
    }

    #[test]
    fn oversized_agent_transcript_has_null_cost() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("agent-a1.jsonl");
        std::fs::write(&path, AGENT_TRANSCRIPT).unwrap();
        let len = AGENT_TRANSCRIPT.len() as u64;
        assert!(scan_agent_transcript_capped(&path, len).is_some());
        assert!(scan_agent_transcript_capped(&path, len - 1).is_none());
    }

    #[test]
    fn directory_agent_transcript_has_null_cost() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(scan_agent_transcript(tmp.path()).is_none());
    }

    /// A FIFO at the agent-transcript path has no writer, so a plain open
    /// would block the hook forever. It must come back `None`, promptly.
    #[cfg(unix)]
    #[test]
    fn fifo_agent_transcript_returns_promptly_with_null_cost() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("agent-a1.jsonl");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(scan_agent_transcript(&fifo).is_none());
        });
        let is_none = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("scanning a FIFO must not block");
        assert!(is_none);
    }
}
