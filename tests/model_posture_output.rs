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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // A runner session can ambiently carry either of these, which would exempt
    // the hook and turn an emit-expecting assertion into a false pass.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env("CADENCE_METRICS_DIR", scratch_metrics_dir());
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
fn a_resume_restore_onto_fable_is_silent() {
    let payload = serde_json::json!({
        "session_id": "s1",
        "hook_event_name": "PostModelSwitch",
        "from_model": "claude-opus-5",
        "to_model": "claude-fable-5-1",
        "source": "resume",
    })
    .to_string();
    assert_silent(&run(&payload));
}

#[test]
fn an_empty_payload_is_silent_and_exits_zero() {
    assert_silent(&run("{}"));
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
