//! Integration coverage for guard-rm's NUDGE tier (cameronsjo/cadence-hooks#344).
//!
//! guard-rm had no Nudge precedent before #344 — every prior verdict was
//! Allow, Ask, or Block — so the delivery shape is asserted end to end through
//! the real binary rather than trusted from the unit tests. A Nudge that
//! renders as anything but `hookSpecificOutput.additionalContext` on exit 0 is
//! invisible: Claude Code reads no other channel at exit 0, so the tier would
//! ship, pass every unit test, and inject nothing.

use std::io::Write;
use std::process::Command;

/// Throwaway metrics root, so a run of this suite cannot append rows to the
/// operator's real ledger. Held process-lifetime so it outlives every child.
fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // A runner session can ambiently carry either of these, which would exempt
    // the guard and turn the assertion below into a false pass.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env("CADENCE_METRICS_DIR", scratch_metrics_dir());
    cmd
}

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

/// A flat sweep of secret-shaped names under `/tmp` nudges: exit 0, with the
/// context on stdout in the PreToolUse envelope.
///
/// `/tmp` is the fixed temp-root branch, so this holds whatever the runner's
/// `HOME`/`TMPDIR` are — and nothing is created or deleted, since the guard
/// classifies the pattern text and never touches the filesystem.
#[test]
fn a_secret_shaped_sweep_nudges_with_additional_context() {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -f /tmp/cadence-guard-rm-nudge-probe/*.pem" },
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "guard-rm"]);
    let output = run_with_stdin(cmd, &payload);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a nudge exits 0.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is JSON: {e}\n{stdout}"));
    let hook_output = &parsed["hookSpecificOutput"];
    assert_eq!(hook_output["hookEventName"], "PreToolUse");
    let context = hook_output["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("additionalContext is a string, not {hook_output}"));
    assert!(
        context.contains("guard-rm"),
        "the nudge names the guard: {context}"
    );
    // A nudge is not a prompt and not a block — neither envelope may appear.
    assert!(
        hook_output.get("permissionDecision").is_none(),
        "a nudge must not carry a permission decision: {hook_output}"
    );
    assert!(stderr.is_empty(), "a nudge writes no stderr: {stderr}");
}

/// The control: an ordinary artifact sweep in the same directory stays a silent
/// allow. Without it, a nudge that fired on *everything* would pass the test
/// above.
#[test]
fn an_ordinary_sweep_stays_silent() {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -f /tmp/cadence-guard-rm-nudge-probe/*.tgz" },
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "guard-rm"]);
    let output = run_with_stdin(cmd, &payload);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "an allow emits nothing: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
