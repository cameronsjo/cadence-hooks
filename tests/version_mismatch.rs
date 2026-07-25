//! Integration tests verifying that deployment errors fail open (exit 1, warn)
//! instead of blocking (exit 2).
//!
//! Covers ADR 0008 failure modes:
//! - Unknown subcommand/argument (clap interception) — tested below
//! - Panic in check logic — an *unguarded* panic exits 1 via `set_hook` in
//!   `main()`; one inside a dispatch guard fails open at exit 0 instead
//!   (cameronsjo/cadence-hooks#349). Both live in `failopen_telemetry.rs`,
//!   which owns the synthetic `CADENCE_TEST_PANIC` trigger
//! - Missing binary (exit 127) — handled by consuming plugins' shell guards

use std::process::Command;

/// The binary under test, with `CADENCE_METRICS_DIR` pointed at a fresh temp
/// dir. Several of these invocations write a `failopen.jsonl` row; without the
/// override they land in the operator's live ledger and inflate `doctor`'s own
/// counts with synthetic subcommand names (cameronsjo/cadence-hooks#398).
///
/// The `TempDir` rides along in the return value because it must outlive the
/// spawned process — dropping it deletes the directory, so a caller that
/// discards it would be writing into a path that no longer exists. Bind it as
/// `_tmp`, never `_`.
fn cadence_hooks() -> (Command, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create a temp metrics dir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env("CADENCE_METRICS_DIR", tmp.path());
    (cmd, tmp)
}

#[test]
fn unknown_top_level_subcommand_fails_open() {
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
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
        stderr.contains("unrecognized subcommand"),
        "should mention unrecognized subcommand: {stderr}"
    );
    assert!(
        stderr.contains("To update:"),
        "should include update instructions: {stderr}"
    );
}

#[test]
fn unknown_plugin_subcommand_fails_open() {
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
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
        stderr.contains("unrecognized subcommand"),
        "should mention unrecognized subcommand: {stderr}"
    );
}

#[test]
fn unknown_guardrails_subcommand_fails_open() {
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
        .args(["guardrails", "guard-new-feature"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown guardrails subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand"),
        "should mention unrecognized subcommand: {stderr}"
    );
}

#[test]
fn stderr_includes_version_and_release_url() {
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
        .args(["cadence", "nonexistent-hook"])
        .output()
        .expect("failed to execute binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cadence-hooks v"),
        "should show installed version: {stderr}"
    );
    assert!(
        stderr.contains("github.com/cameronsjo/cadence-hooks/releases"),
        "should include release URL: {stderr}"
    );
}

#[test]
fn help_flag_still_works() {
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
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
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
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
fn distant_name_subcommand_fails_open() {
    // A name that is far from any existing subcommand — ensures clap doesn't
    // treat it as a typo with a "did you mean?" suggestion that bypasses our
    // InvalidSubcommand catch.
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
        .args(["cadence", "zzz-future-hook"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "distant-name subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand"),
        "should mention unrecognized subcommand: {stderr}"
    );
}

#[test]
fn missing_subcommand_fails_open() {
    // Running `cadence-hooks` with no arguments triggers MissingSubcommand.
    // This must exit 1 (warn), not 2 (block).
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "missing subcommand should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no subcommand given"),
        "bare invocation should say 'no subcommand given', not a version warning: {stderr}"
    );
    assert!(
        !stderr.contains("newer version"),
        "bare invocation must not claim a plugin expects a newer version: {stderr}"
    );
}

#[test]
fn namespace_without_hook_says_no_subcommand() {
    // `cadence-hooks cadence` — a real namespace with no hook name. Hits the
    // same MissingSubcommand arm as a bare run, so it gets plain guidance, not
    // the version-skew warning (#223).
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
        .args(["cadence"])
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "namespace-only invocation should exit 1 (warn), not block.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no subcommand given"),
        "namespace-only should say 'no subcommand given': {stderr}"
    );
    assert!(
        !stderr.contains("newer version"),
        "namespace-only must not claim a plugin expects a newer version: {stderr}"
    );
}

#[test]
fn valid_subcommand_with_empty_input_allows() {
    // A valid subcommand with valid JSON on stdin should work normally.
    // Send a minimal allow-case input to terminology.
    let (mut cmd, _tmp) = cadence_hooks();
    let output = cmd
        .args(["cadence", "terminology"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                // BrokenPipe means the child exited before reading stdin —
                // expected for early-exit paths, not a test failure (#59).
                if let Err(e) = stdin.write_all(b"{}")
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    return Err(e);
                }
            }
            child.wait_with_output()
        })
        .expect("failed to execute binary");

    // Empty JSON object => no tool_input => allow
    assert_eq!(
        output.status.code(),
        Some(0),
        "valid subcommand with empty input should allow.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
