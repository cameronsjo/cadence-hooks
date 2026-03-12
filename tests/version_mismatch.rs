//! Integration tests verifying that unknown subcommands and arguments
//! fail open (exit 1, warn) instead of blocking (exit 2).
//!
//! This prevents version mismatches between the cadence-hooks binary and
//! plugins from accidentally blocking legitimate operations.

use std::process::Command;

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
}

#[test]
fn unknown_top_level_subcommand_fails_open() {
    let output = cadence_hooks()
        .args(["future-plugin", "some-hook"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown plugin subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized command"),
        "should mention unrecognized command: {stderr}"
    );
    assert!(
        stderr.contains("To update:"),
        "should include update instructions: {stderr}"
    );
}

#[test]
fn unknown_plugin_subcommand_fails_open() {
    let output = cadence_hooks()
        .args(["cadence", "not-a-real-hook"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown hook subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized command"),
        "should mention unrecognized command: {stderr}"
    );
}

#[test]
fn unknown_guardrails_subcommand_fails_open() {
    let output = cadence_hooks()
        .args(["guardrails", "guard-new-feature"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown guardrails subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stderr_includes_installed_version() {
    let output = cadence_hooks()
        .args(["cadence", "nonexistent-hook"])
        .output()
        .expect("failed to execute binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cadence-hooks v"),
        "should show installed version: {stderr}"
    );
}

#[test]
fn stderr_includes_release_url() {
    let output = cadence_hooks()
        .args(["cadence", "nonexistent-hook"])
        .output()
        .expect("failed to execute binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("github.com/cameronsjo/cadence-hooks/releases"),
        "should include release URL: {stderr}"
    );
}

#[test]
fn help_flag_still_works() {
    let output = cadence_hooks()
        .args(["--help"])
        .output()
        .expect("failed to execute binary");

    // --help exits 0 and shows help text
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cadence-hooks") || stdout.contains("Compiled Claude Code hooks"),
        "help should show program info: {stdout}"
    );
}

#[test]
fn version_flag_still_works() {
    let output = cadence_hooks()
        .args(["--version"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cadence-hooks"),
        "version should show program name: {stdout}"
    );
}

#[test]
fn valid_subcommand_still_works() {
    // A valid subcommand with valid JSON on stdin should work normally.
    // Send a minimal allow-case input to terminology.
    let output = cadence_hooks()
        .args(["cadence", "terminology"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(b"{}")?;
            }
            child.wait_with_output()
        })
        .expect("failed to execute binary");

    // Empty input => no tool_input => allow
    assert_eq!(
        output.status.code(),
        Some(0),
        "valid subcommand with empty input should allow.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
