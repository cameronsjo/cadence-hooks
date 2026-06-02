//! Integration tests for the `try` subcommand (issue #56) and the
//! piped-stdin path of the interactive-terminal guard.
//!
//! The TTY branch of the guard itself is not testable here — test runners
//! (and CI) never attach a terminal to stdin, which is also why the guard
//! can never misfire in production. Its message contents are unit-tested
//! in cadence-hooks-core.

use std::io::Write;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Ensure tests don't inherit env vars from the test runner's session
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    cmd
}

/// Spawns the binary with JSON on stdin and returns the completed output.
///
/// A child that decides its outcome without reading stdin (a bypassed or
/// disabled hook exits immediately) may close the pipe before the write
/// completes — that BrokenPipe is expected, not a test failure (#59).
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

// ── try: happy paths ─────────────────────────────────────────────────

#[test]
fn try_runs_a_check_and_reports_outcome() {
    let mut cmd = cadence_hooks();
    cmd.args(["try", "cadence", "terminology"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The sample Bash payload ("git status") trips no terminology rule —
    // a silent allow, which the decoded outcome reports as ALLOW (not the
    // old ambiguous "ALLOW / NUDGE").
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("Hook:"), "report shows hook line: {stdout}");
    assert!(
        stdout.contains("PreToolUse"),
        "report shows the event: {stdout}"
    );
    assert!(
        stdout.contains("Payload:"),
        "report echoes payload: {stdout}"
    );
    assert!(
        stdout.contains("Outcome:  ALLOW (exit 0)"),
        "report shows decoded outcome: {stdout}"
    );
}

#[test]
fn try_nudge_renders_context_as_readable_text() {
    // warn-curl-alias is pure string logic: bare curl + custom header → nudge.
    let dir = std::env::temp_dir().join(format!("cadence-try-nudge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payload_path = dir.join("payload.json");
    std::fs::write(
        &payload_path,
        r#"{"tool_name":"Bash","tool_input":{"command":"curl -H 'Accept: application/json' https://example.com"}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args([
        "try",
        "guardrails",
        "warn-curl-alias",
        "--payload",
        payload_path.to_str().unwrap(),
    ]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("Outcome:  NUDGE (exit 0)"),
        "nudge outcome is decoded, not ambiguous: {stdout}"
    );
    assert!(
        stdout.contains("Context injected (what Claude sees):"),
        "nudge heading present: {stdout}"
    );
    assert!(
        !stdout.contains("hookSpecificOutput"),
        "protocol envelope is decoded away, not echoed: {stdout}"
    );
    assert!(
        !stdout.contains("\\n"),
        "context renders real newlines, not escapes: {stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn try_runs_a_logger() {
    let mut cmd = cadence_hooks();
    // Point metrics at a temp dir so the logger's side effect lands nowhere real.
    let tmp = std::env::temp_dir().join("cadence-hooks-try-test");
    cmd.env("CADENCE_METRICS_DIR", &tmp);
    cmd.args(["try", "metrics", "snapshot"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Loggers always exit 0.
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("logger"),
        "report labels the event as logger: {stdout}"
    );
}

#[test]
fn try_injects_cwd_into_sample_payload() {
    let mut cmd = cadence_hooks();
    cmd.args(["try", "cadence", "terminology"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(r#""cwd":"#),
        "sample payload carries cwd: {stdout}"
    );
}

#[test]
fn try_accepts_payload_file_override() {
    let dir = std::env::temp_dir().join(format!("cadence-try-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payload_path = dir.join("payload.json");
    std::fs::write(
        &payload_path,
        r#"{"tool_name":"Bash","tool_input":{"command":"echo custom-payload-marker"}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args([
        "try",
        "cadence",
        "terminology",
        "--payload",
        payload_path.to_str().unwrap(),
    ]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("custom-payload-marker"),
        "report echoes the file payload: {stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ── try: error paths ─────────────────────────────────────────────────

#[test]
fn try_unknown_hook_points_to_list() {
    let mut cmd = cadence_hooks();
    cmd.args(["try", "bogus", "nothere"]);

    let output = cmd.output().expect("failed to execute binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("cadence-hooks list"),
        "error points to list: {stderr}"
    );
}

#[test]
fn try_wrong_namespace_suggests_correct_one() {
    let mut cmd = cadence_hooks();
    cmd.args(["try", "cadence", "guard-push-remote"]);

    let output = cmd.output().expect("failed to execute binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("guardrails"),
        "error names the right namespace: {stderr}"
    );
    assert!(
        stderr.contains("try guardrails guard-push-remote"),
        "error gives the corrected command: {stderr}"
    );
}

#[test]
fn try_missing_payload_file_errors() {
    let mut cmd = cadence_hooks();
    cmd.args([
        "try",
        "cadence",
        "terminology",
        "--payload",
        "/nonexistent/payload.json",
    ]);

    let output = cmd.output().expect("failed to execute binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("cannot read payload file"),
        "error names the problem: {stderr}"
    );
}

// ── try: exemptions ──────────────────────────────────────────────────

#[test]
fn try_works_during_bypass() {
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BYPASS", "1");
    cmd.args(["try", "cadence", "terminology"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // try itself is a CLI command, exempt from bypass. The hook it spawns IS
    // bypassed (exits 0 with the bypass warning) — the report stays honest.
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("Outcome:"), "report still prints: {stdout}");
}

#[test]
fn bypass_exemption_is_positional_not_any_token() {
    // A hook invocation whose *argument* equals a CLI-action word must still
    // be bypassed — only the subcommand position grants the exemption.
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BYPASS", "1");
    cmd.args(["metrics", "log-commit", "--prices", "try"]);

    let output = run_with_stdin(cmd, "{}");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stderr.contains("bypassed"),
        "hook with 'try' as an argument value must still be bypassed: {stderr}"
    );
}

#[test]
fn session_cli_actions_remain_bypass_exempt() {
    // `session status` is argv[1]="session", argv[2]="status" — the positional
    // match must still exempt it.
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BYPASS", "1");
    cmd.args(["session", "status"]);

    let output = cmd.output().expect("failed to execute binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("all enforcement bypassed"),
        "session status must not be short-circuited by bypass: {stderr}"
    );
}

// ── try: per-hook sample correctness ─────────────────────────────────

#[test]
fn try_log_subagent_uses_subagent_event_sample() {
    let mut cmd = cadence_hooks();
    let tmp = std::env::temp_dir().join("cadence-hooks-try-test");
    cmd.env("CADENCE_METRICS_DIR", &tmp);
    cmd.args(["try", "metrics", "log-subagent"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The registry override must put a SubagentStop payload on stdin — the
    // generic PostToolUse fallback would make this logger no-op silently.
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("SubagentStop"),
        "log-subagent sample must use a Subagent event: {stdout}"
    );
}

// ── interactive guard: piped stdin must never trip it ────────────────

#[test]
fn piped_stdin_does_not_trigger_interactive_guard() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);

    let output = run_with_stdin(cmd, "{}");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Empty-object payload → fail-open allow (exit 0), and no interactive guidance.
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        !stderr.contains("interactive command"),
        "guard must not fire on piped stdin: {stderr}"
    );
}

#[test]
fn piped_stdin_logger_does_not_trigger_interactive_guard() {
    let mut cmd = cadence_hooks();
    let tmp = std::env::temp_dir().join("cadence-hooks-try-test");
    cmd.env("CADENCE_METRICS_DIR", &tmp);
    cmd.args(["metrics", "snapshot"]);

    let output = run_with_stdin(cmd, "{}");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        !stderr.contains("interactive command"),
        "guard must not fire on piped stdin: {stderr}"
    );
}
