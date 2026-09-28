//! End-to-end coverage for `guardrails enforcement-status`
//! (cameronsjo/cadence-ecosystem#582).
//!
//! The unit tests pin the report text. These pin what only the real binary
//! decides: that the hook still runs under the blanket bypass it reports on,
//! that a refused disable does not silence it, and that the report reaches
//! Claude Code as SessionStart `additionalContext` on exit 0.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Throwaway metrics root, so a run of this suite cannot append rows to the
/// operator's real ledger. Held process-lifetime so it outlives every child.
fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

/// Run the hook with exactly the given switches set; every other ambient
/// switch is cleared so a runner session cannot decide the outcome.
fn run(bypass_value: Option<&str>, disable_value: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.args(["guardrails", "enforcement-status"])
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env("CADENCE_METRICS_DIR", scratch_metrics_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = bypass_value {
        cmd.env("CADENCE_BYPASS", value);
    }
    if let Some(value) = disable_value {
        cmd.env("CADENCE_DISABLE", value);
    }
    let mut child = cmd.spawn().expect("failed to execute binary");
    let payload = serde_json::json!({
        "session_id": "enforcement-status-e2e",
        "hook_event_name": "SessionStart",
        "source": "startup",
    })
    .to_string();
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

/// The `additionalContext` string, asserting the SessionStart envelope and
/// exit 0 on the way.
fn context_of(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report is advisory and exits 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is JSON: {e}\nstdout: {stdout}\nstderr: {stderr}"));
    let hook_output = &parsed["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "SessionStart", "{parsed}");
    hook_output["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("additionalContext is a string, not {hook_output}"))
        .to_string()
}

#[test]
fn a_clean_environment_prints_nothing() {
    let output = run(None, None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.trim().is_empty(), "expected silence, got: {stdout}");
}

#[test]
fn the_blanket_bypass_is_reported_and_does_not_silence_the_report() {
    let context = context_of(&run(Some("1"), None));
    assert!(context.contains("CADENCE_BYPASS=1"), "{context}");
    assert!(context.contains("trash-guard"), "{context}");
}

#[test]
fn a_disable_naming_a_protected_guard_is_reported() {
    let context = context_of(&run(None, Some("git-safety")));
    assert!(context.contains("git-safety"), "{context}");
    assert!(context.contains("refused"), "{context}");
}

#[test]
fn disabling_the_report_itself_is_refused_and_reported() {
    let context = context_of(&run(None, Some("enforcement-status")));
    assert!(context.contains("enforcement-status"), "{context}");
}

#[test]
fn a_disable_naming_only_unprotected_hooks_prints_nothing() {
    let output = run(None, Some("warn-main-branch"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.trim().is_empty(), "expected silence, got: {stdout}");
}
