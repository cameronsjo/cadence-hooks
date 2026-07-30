//! Cross-process integration test for the once-per-day nudge gate (#458).
//!
//! The honest RED must run the binary in **two separate processes**. An
//! in-process double-invoke would also pass against a gate keyed on
//! process-local state; only two real invocations prove the marker survives
//! process death, which is the whole point — every SessionStart is a fresh
//! process, and that is why an ungated drift nudge repeated forever.

use std::io::Write;
use std::process::Command;

/// Build the child command, sandboxed to `marker_dir` via `CADENCE_MARKER_DIR`
/// so the daily stamp never lands in the real per-user marker directory (#302)
/// — `.env()` only affects the *child's* environment, so this needs no
/// serialization against other tests.
fn cadence_hooks(marker_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Don't inherit enforcement toggles from the test runner's session.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    // The gate's own escape hatch would defeat the assertion outright.
    cmd.env_remove("CADENCE_NO_DAILY_GATE");
    cmd.env("CADENCE_MARKER_DIR", marker_dir);
    cmd
}

/// Spawn the binary with JSON on stdin and return the completed output. A
/// BrokenPipe on write is expected when the child exits before draining stdin.
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

/// A baseline guaranteed to put the installed cadence-hooks behind: a major
/// crossing nudges whatever the running version is. The Claude Code half is
/// pinned current and the payload carries no transcript, so exactly one nudge
/// term — and therefore one stable gate token — is in play.
fn write_baseline(dir: &std::path::Path) -> String {
    let path = dir.join("platform-baseline.json");
    std::fs::write(
        &path,
        r#"{"claude_code":{"last_swept_version":"2.1.218","swept_on":"2026-07-26","sweep_doc":"n/a"},"cadence_hooks":{"current_version":"99.0.0"}}"#,
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

/// A SessionStart payload. Built with a JSON serializer, NOT `format!`: on
/// Windows the temp paths carry backslashes, and a raw `\U`/`\r` in a JSON
/// string is an invalid escape — a hand-built payload would fail to parse, the
/// hook would fail open (exit 0, silent), and invocation 1 would never nudge.
fn session_payload(session_id: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "source": "startup",
        "hook_event_name": "SessionStart",
    })
    .to_string()
}

#[test]
fn platform_drift_nudges_once_per_day_across_processes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let baseline = write_baseline(dir.path());
    // Both invocations must share one marker dir — invocation 2 needs to see
    // invocation 1's stamp — but isolated to this test alone (#302).
    let marker_dir = tempfile::tempdir().expect("marker tempdir");

    // Invocation 1: nothing stamped today → the drift nudge fires.
    let mut cmd1 = cadence_hooks(marker_dir.path());
    cmd1.args(["cadence", "platform-drift", "--baseline", &baseline]);
    let out1 = run_with_stdin(cmd1, &session_payload("daily-gate-1"));
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    assert_eq!(out1.status.code(), Some(0), "invocation 1 exits 0");
    assert!(
        stdout1.contains("cadence-hooks is behind"),
        "invocation 1 must nudge (a separate process): {stdout1}"
    );

    // Invocation 2: a distinct session in a distinct process, same drift state
    // → invocation 1's stamp must suppress it.
    let mut cmd2 = cadence_hooks(marker_dir.path());
    cmd2.args(["cadence", "platform-drift", "--baseline", &baseline]);
    let out2 = run_with_stdin(cmd2, &session_payload("daily-gate-2"));
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(out2.status.code(), Some(0), "invocation 2 exits 0");
    assert!(
        stdout2.trim().is_empty(),
        "invocation 2 must be silent — the drift state already nudged today: {stdout2}"
    );
}
