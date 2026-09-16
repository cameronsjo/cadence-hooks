//! End-to-end coverage for `cadence model-posture`'s wire format.
//!
//! The unit tests in `crates/cadence/src/model_posture.rs` prove *when* the
//! posture line is owed. They cannot see the envelope it ships in: the emitted
//! JSON is rendered by the binary's dispatch layer, and `hookEventName` there
//! has to follow the payload's own event because this one subcommand is wired on
//! both SessionStart and PostModelSwitch. A wrong event name, or plain text
//! where JSON belongs, delivers nothing — Claude Code reads no other channel at
//! exit 0 — while every unit test stays green.
//!
//! So each case below runs the real binary and parses its stdout with
//! `serde_json`.

use std::io::Write;
use std::process::Command;

const POSTURE_LINE: &str = "Session is on Fable. Load cadence:using-fable before substantive work.";

/// Throwaway metrics root, so a run of this suite cannot append rows to the
/// operator's real ledger. Held process-lifetime so it outlives every child.
fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

fn run(payload: &str) -> std::process::Output {
    run_in(scratch_metrics_dir(), payload)
}

fn run_in(metrics_dir: &std::path::Path, payload: &str) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // A runner session can ambiently carry either of these, which would exempt
    // the hook and turn an emit-expecting assertion into a false pass.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    // Nudge rows are on by default; an ambient opt-out would make the denial
    // row vanish and read as a pass in the telemetry test below.
    cmd.env_remove("CADENCE_LOG_NUDGES");
    cmd.env("CADENCE_METRICS_DIR", metrics_dir);
    cmd.args(["cadence", "model-posture"]);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to execute binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

/// Parse stdout as JSON and assert the whole envelope, event name included.
fn assert_posture_envelope(output: &std::process::Output, expected_event: &str) {
    assert_eq!(output.status.code(), Some(0), "the hook must never block");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}), got: {stdout:?}"));
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"], expected_event,
        "the envelope must name the event that actually fired"
    );
    assert_eq!(
        json["hookSpecificOutput"]["additionalContext"],
        POSTURE_LINE
    );
    assert!(
        json["hookSpecificOutput"]["additionalContext"].is_string(),
        "additionalContext must be a JSON string"
    );
}

fn assert_silent(output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "expected no stdout, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_switch_onto_fable_emits_the_post_model_switch_envelope() {
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "PostModelSwitch",
        "from_model": "claude-opus-5",
        "to_model": "claude-fable-5-1",
        "source": "command",
    })
    .to_string();
    assert_posture_envelope(&run(&payload), "PostModelSwitch");
}

#[test]
fn a_session_starting_on_fable_emits_the_session_start_envelope() {
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "model": "claude-fable-5-1",
    })
    .to_string();
    assert_posture_envelope(&run(&payload), "SessionStart");
}

#[test]
fn the_reversed_switch_is_silent() {
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "PostModelSwitch",
        "from_model": "claude-fable-5-1",
        "to_model": "claude-opus-5",
        "source": "command",
    })
    .to_string();
    assert_silent(&run(&payload));
}

#[test]
fn a_session_starting_on_opus_is_silent() {
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "model": "claude-opus-5",
    })
    .to_string();
    assert_silent(&run(&payload));
}

#[test]
fn a_resume_restore_onto_fable_still_emits() {
    // SessionStart is not a reliable backstop here: `model` is documented as
    // optional and omitted "after `/clear` or when a session is restored
    // through conversation recovery". Suppressing this would trade one
    // duplicated line for total silence on the sessions the hook exists for.
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "PostModelSwitch",
        "from_model": "claude-opus-5",
        "to_model": "claude-fable-5-1",
        "source": "resume",
    })
    .to_string();
    assert_posture_envelope(&run(&payload), "PostModelSwitch");
}

#[test]
fn a_session_start_that_omits_the_model_field_is_silent() {
    // The documented `/clear` and conversation-recovery shape. Nothing to
    // report, and nothing to crash on — but it is why the switch half must not
    // defer to this one.
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "SessionStart",
        "source": "resume",
    })
    .to_string();
    assert_silent(&run(&payload));
}

#[test]
fn an_empty_payload_is_silent_and_exits_zero() {
    assert_silent(&run("{}"));
}

/// The denial row records the event too, and it is a *separate* read of the
/// same rebinding. An implementation that resolved the payload's event only for
/// the output envelope and left the audit rows on the dispatch-time fallback
/// would pass every other test in this file while writing `SessionStart` on
/// every switch — a ledger that quietly disagrees with what fired.
#[test]
fn the_denial_row_records_the_payload_event_not_the_fallback() {
    let dir = tempfile::tempdir().expect("temp metrics dir");
    let payload = serde_json::json!({
        "session_id": "s-telemetry",
        "hook_event_name": "PostModelSwitch",
        "from_model": "claude-opus-5",
        "to_model": "claude-fable-5-1",
        "source": "command",
    })
    .to_string();
    assert_posture_envelope(&run_in(dir.path(), &payload), "PostModelSwitch");

    let rows = std::fs::read_to_string(dir.path().join("denials.jsonl"))
        .expect("a nudging hook must write a denials.jsonl row");
    let row: serde_json::Value = rows
        .lines()
        .find(|line| line.contains("\"model-posture\""))
        .map(|line| serde_json::from_str(line).expect("the row must be JSON"))
        .expect("no model-posture row written");
    assert_eq!(row["event"], "PostModelSwitch");
    assert_eq!(row["decision"], "nudge");
}

#[test]
fn unparseable_json_fails_open_with_no_stdout() {
    let output = run("not json");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a parse failure must never block (ADR-0001)"
    );
    assert!(output.stdout.is_empty());
}
