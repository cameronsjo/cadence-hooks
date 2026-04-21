//! Integration tests for CADENCE_DISABLE selective hook disabling
//! and the `list` subcommand.
//!
//! Verifies that individual hooks can be skipped via the env var, while
//! non-listed hooks still run normally.

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
fn run_with_stdin(mut cmd: Command, input: &str) -> std::process::Output {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to execute binary");
    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(input.as_bytes()).unwrap();
    }
    child.wait_with_output().expect("failed to wait on binary")
}

#[test]
fn disabled_hook_exits_zero() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "terminology");

    // Even without valid stdin, a disabled hook should exit 0 before reading input.
    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "disabled hook should exit 0 (allow).\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn disabled_hook_produces_no_output() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "git-safety");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "disabled hook should produce no stdout"
    );
    assert!(
        output.stderr.is_empty(),
        "disabled hook should produce no stderr"
    );
}

#[test]
fn comma_separated_list_disables_multiple() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "terminology,git-safety,line-endings");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "hook in comma-separated disable list should exit 0"
    );
}

#[test]
fn spaces_around_commas_tolerated() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "terminology , git-safety , line-endings");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "should tolerate spaces around commas in disable list"
    );
}

#[test]
fn non_disabled_hook_still_runs() {
    let input = r#"{"tool_name":"Write","tool_input":{"file_path":"test.txt","content":"hello"}}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "git-safety,line-endings");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "non-disabled hook should still run (and allow clean input).\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_var_unset_does_not_disable() {
    let input = r#"{}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env_remove("CADENCE_DISABLE");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "hook should run normally when env var is unset.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn empty_env_var_does_not_disable() {
    let input = r#"{}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "empty disable list should not affect hook execution.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn partial_name_match_does_not_disable() {
    let input = r#"{}"#;

    // "git" is a substring of "git-safety" but not an exact match
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "git");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "partial name match should not disable the hook.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guardrails_hook_can_be_disabled() {
    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "warn-main-branch"]);
    cmd.env("CADENCE_DISABLE", "warn-main-branch");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "guardrails hook should be disableable too"
    );
}

#[test]
fn obsidian_hook_can_be_disabled() {
    let mut cmd = cadence_hooks();
    cmd.args(["obsidian", "trash-guard"]);
    cmd.env("CADENCE_DISABLE", "trash-guard");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "obsidian hook should be disableable too"
    );
}

#[test]
fn rules_hook_can_be_disabled() {
    let mut cmd = cadence_hooks();
    cmd.args(["rules", "validate-frontmatter"]);
    cmd.env("CADENCE_DISABLE", "validate-frontmatter");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "rules hook should be disableable too"
    );
}

// ── list subcommand ──────────────────────────────────────────────────

#[test]
fn list_shows_all_plugin_groups() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cadence:"), "should show cadence group");
    assert!(
        stdout.contains("guardrails:"),
        "should show guardrails group"
    );
    assert!(stdout.contains("rules:"), "should show rules group");
    assert!(stdout.contains("obsidian:"), "should show obsidian group");
}

#[test]
fn list_shows_hook_names_and_descriptions() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("git-safety"), "should list git-safety hook");
    assert!(
        stdout.contains("Block dangerous git operations"),
        "should include description"
    );
}

#[test]
fn list_shows_disabled_status() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);
    cmd.env("CADENCE_DISABLE", "git-safety,warn-main-branch");

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Disabled hooks should be marked
    let git_safety_line = stdout.lines().find(|l| l.contains("git-safety")).unwrap();
    assert!(
        git_safety_line.contains("(disabled)"),
        "disabled hook should be marked: {git_safety_line}"
    );

    // Non-disabled hooks should not be marked
    let terminology_line = stdout.lines().find(|l| l.contains("terminology")).unwrap();
    assert!(
        !terminology_line.contains("(disabled)"),
        "non-disabled hook should not be marked: {terminology_line}"
    );
}

#[test]
fn list_works_during_bypass() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);
    cmd.env("CADENCE_BYPASS", "1");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "list should work even when bypass is active"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CADENCE_BYPASS=1"),
        "should show bypass status"
    );
    assert!(
        stdout.contains("(disabled)"),
        "all hooks should show as disabled during bypass"
    );
}
