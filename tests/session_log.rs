//! Integration tests for `metrics log-session` — the `sessions.jsonl` writer
//! that fires at `SessionEnd` (O3).
//!
//! The binary is spawned as a child process with `CADENCE_METRICS_DIR` pointed
//! at a per-test tempdir, so the write lands nowhere real and the env override
//! is isolated (never touches the test runner's process-global env).

use std::io::Write;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Don't inherit env that would bypass, disable, or re-price the logger.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    cmd.env_remove("CADENCE_METRICS_PRICES");
    cmd
}

/// Spawn the binary with JSON on stdin and return the completed output.
fn run_with_stdin(mut cmd: Command, input: &str) -> std::process::Output {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to execute binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(input.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

/// Build a SessionEnd payload with **structural** JSON escaping.
///
/// The transcript path is a tempdir path — on Windows that's `C:\Users\...`,
/// whose backslashes are invalid JSON escapes. Interpolating it into a raw
/// string template with `format!` would produce unparseable JSON, `MetricsInput`
/// would fail to deserialize, and the logger would silently fail open (no row).
/// Building the payload with `serde_json::json!` escapes the path correctly on
/// every platform (#170).
fn session_payload(
    session_id: &str,
    event: &str,
    transcript: &std::path::Path,
    reason: Option<&str>,
) -> String {
    let mut obj = serde_json::json!({
        "session_id": session_id,
        "hook_event_name": event,
        "transcript_path": transcript.to_string_lossy(),
        "cwd": "/tmp",
    });
    if let Some(r) = reason {
        obj["reason"] = serde_json::Value::String(r.to_string());
    }
    obj.to_string()
}

/// A transcript with two priced assistant messages. Written to `path`.
fn write_transcript(path: &std::path::Path) {
    let transcript = [
        r#"{"type":"user","message":{"role":"user","content":"hi"}}"#,
        r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":1000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":100}}}"#,
        r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":2000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":200}}}"#,
    ]
    .join("\n");
    std::fs::write(path, transcript).expect("write transcript");
}

// ── RED-first: no row without a SessionEnd event ─────────────────────────

#[test]
fn non_session_end_event_writes_no_row() {
    // The gate: a PostToolUse payload (wrong event) must not write a session
    // row. This is the RED assertion — the absence the writer must respect.
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-1", "PostToolUse", &transcript, None);
    let output = run_with_stdin(cmd, &payload);

    assert_eq!(output.status.code(), Some(0), "loggers always exit 0");
    assert!(
        !dir.path().join("sessions.jsonl").exists(),
        "no row for a non-SessionEnd event"
    );
}

// ── GREEN: one row at SessionEnd, with the full schema ───────────────────

#[test]
fn session_end_writes_one_priced_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload(
        "sess-1",
        "SessionEnd",
        &transcript,
        Some("prompt_input_exit"),
    );
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0), "loggers always exit 0");

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl"))
        .expect("sessions.jsonl must exist after SessionEnd");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "exactly one row, got: {contents}");

    let row: serde_json::Value = serde_json::from_str(lines[0]).expect("row parses as JSON");
    assert_eq!(row["sessionId"], "sess-1");
    assert_eq!(row["reason"], "prompt_input_exit");
    assert_eq!(row["model"], "claude-opus-4-7");
    // tokens == whole-transcript sum (m1 + m2).
    assert_eq!(row["tokens"]["input"], 3000);
    assert_eq!(row["tokens"]["output"], 300);
    assert_eq!(row["messagesScanned"], 2);
    // A priced model → positive cost, non-empty byModel, empty unpricedModels.
    assert!(
        row["costUsd"].as_f64().unwrap() > 0.0,
        "priced model costs > 0"
    );
    assert!(!row["byModel"].as_array().unwrap().is_empty());
    assert!(row["unpricedModels"].as_array().unwrap().is_empty());
}

#[test]
fn unpriced_model_lands_in_unpriced_never_silently_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    // `gpt-9` is absent from the embedded price table (#95).
    std::fs::write(
        &transcript,
        r#"{"message":{"id":"m1","role":"assistant","model":"gpt-9","usage":{"input_tokens":100,"output_tokens":10}}}"#,
    )
    .expect("write transcript");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-2", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    let unpriced = row["unpricedModels"].as_array().unwrap();
    assert_eq!(unpriced.len(), 1);
    assert_eq!(unpriced[0], "gpt-9");
    assert!(row["reason"].is_null(), "absent reason → null");
}

// ── Session bounds: log-session-start / log-session round trip (#182) ────

/// Build a SessionStart payload for `metrics log-session-start`.
fn session_start_payload(session_id: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "hook_event_name": "SessionStart",
        "cwd": "/tmp",
    })
    .to_string()
}

#[test]
fn session_start_then_end_round_trip_computes_duration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut start_cmd = cadence_hooks();
    start_cmd.env("CADENCE_METRICS_DIR", dir.path());
    start_cmd.args(["metrics", "log-session-start"]);
    let start_output = run_with_stdin(start_cmd, &session_start_payload("sess-bounds"));
    assert_eq!(start_output.status.code(), Some(0), "loggers always exit 0");

    let mut end_cmd = cadence_hooks();
    end_cmd.env("CADENCE_METRICS_DIR", dir.path());
    end_cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-bounds", "SessionEnd", &transcript, None);
    let end_output = run_with_stdin(end_cmd, &payload);
    assert_eq!(end_output.status.code(), Some(0), "loggers always exit 0");

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl"))
        .expect("sessions.jsonl must exist after SessionEnd");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("row parses as JSON");
    assert!(row["startTs"].is_string(), "startTs should be stamped");
    assert!(row["endTs"].is_string(), "endTs should be stamped");
    assert!(
        row["durationMs"].as_i64().unwrap() >= 0,
        "durationMs should be a non-negative number: {row}"
    );

    // The `.start` marker is consumed — a second SessionEnd for the same
    // session must not see a stale duration.
    assert!(
        !dir.path().join("state").join("sess-bounds.start").exists(),
        "start marker must be consumed"
    );
}

#[test]
fn session_end_without_start_marker_has_null_bounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // No log-session-start ran for this session — SessionEnd fires on its own.
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-no-start", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    assert!(row["startTs"].is_null(), "no marker → startTs null");
    assert!(row["durationMs"].is_null(), "no marker → durationMs null");
    assert!(row["endTs"].is_string(), "endTs is always stamped");
    assert_eq!(row["commits"], 0, "no commits.jsonl → commits 0");
}

#[test]
fn session_end_counts_commits_for_this_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // Seed commits.jsonl with 2 rows for this session and 1 for another.
    let commits_jsonl = [
        r#"{"sessionId":"sess-commits"}"#,
        r#"{"sessionId":"other-session"}"#,
        r#"{"sessionId":"sess-commits"}"#,
    ]
    .join("\n");
    std::fs::write(dir.path().join("commits.jsonl"), commits_jsonl).expect("seed commits.jsonl");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-commits", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    assert_eq!(row["commits"], 2, "only this session's commit rows count");
}

// ── Fail-open: an unwritable metrics dir never perturbs the exit code ─────

#[test]
fn unwritable_metrics_dir_fails_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // Point CADENCE_METRICS_DIR at a *file* — create_dir_all fails, the write
    // is skipped, and the logger still exits 0 without panicking.
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, "x").expect("write blocker file");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", &blocker);
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-3", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0), "fail-open: still exits 0");
}
