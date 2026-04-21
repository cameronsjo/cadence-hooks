//! Integration tests for the `configure` subcommand.
//!
//! Tests the `--list` flag and settings.json read/write behavior.
//! The interactive multi-select cannot be tested without a TTY,
//! so we focus on the non-interactive paths.

use std::fs;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    cmd
}

// ── configure --list ─────────────────────────────────────────────────

#[test]
fn configure_list_shows_all_enabled_when_no_settings() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout.contains("All hooks enabled"),
        "should report all enabled when no settings exist: {stdout}"
    );
}

#[test]
fn configure_list_shows_disabled_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"env":{"CADENCE_DISABLE":"git-safety,warn-main-branch"}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout.contains("git-safety"),
        "should list disabled hook: {stdout}"
    );
    assert!(
        stdout.contains("warn-main-branch"),
        "should list disabled hook: {stdout}"
    );
    assert!(
        stdout.contains("Disabled hooks:"),
        "should show disabled section: {stdout}"
    );
}

#[test]
fn configure_list_shows_settings_path() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("settings.json"),
        "should show settings path: {stdout}"
    );
}

#[test]
fn configure_list_shows_hook_count() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"env":{"CADENCE_DISABLE":"git-safety"}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show "N of M hooks active"
    assert!(
        stdout.contains("hooks active"),
        "should show active hook count: {stdout}"
    );
}

#[test]
fn configure_list_handles_malformed_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(claude_dir.join("settings.json"), "not valid json {{{").unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "should gracefully handle malformed settings"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("All hooks enabled"),
        "malformed settings should show all enabled: {stdout}"
    );
}

#[test]
fn configure_list_handles_empty_disable_value() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"env":{"CADENCE_DISABLE":""}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout.contains("All hooks enabled"),
        "empty disable value should show all enabled: {stdout}"
    );
}

#[test]
fn configure_list_preserves_unknown_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"env":{"CADENCE_DISABLE":"future-hook,git-safety"}}"#,
    )
    .unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("future-hook"),
        "should show unknown hooks too: {stdout}"
    );
    assert!(
        stdout.contains("(unknown hook)"),
        "should mark unknown hooks: {stdout}"
    );
}

// ── configure works during bypass ────────────────────────────────────

#[test]
fn configure_works_during_bypass() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.env("CADENCE_BYPASS", "1");
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "configure should work even when bypass is active"
    );
}

// ── configure finds git root ─────────────────────────────────────────

#[test]
fn configure_finds_git_root_settings() {
    let tmp = tempfile::tempdir().unwrap();

    // Create a fake git root with settings
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let claude_dir = tmp.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"env":{"CADENCE_DISABLE":"terminology"}}"#,
    )
    .unwrap();

    // Run from a subdirectory
    let subdir = tmp.path().join("src").join("deep");
    fs::create_dir_all(&subdir).unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.current_dir(&subdir);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout.contains("terminology"),
        "should find settings from git root when run from subdir: {stdout}"
    );
}

// ── configure blocked under Claude Code ──────────────────────────────

#[test]
fn configure_interactive_refused_under_claude_code() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure"]);
    cmd.env("CLAUDECODE", "1");
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(1),
        "configure should exit 1 under Claude Code. stderr: {stderr}"
    );
    assert!(
        stderr.contains("disabled under Claude Code"),
        "should explain why it refused: {stderr}"
    );
}

#[test]
fn configure_list_allowed_under_claude_code() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.env("CLAUDECODE", "1");
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "configure --list is read-only and should still work under Claude Code"
    );
}

#[test]
fn configure_hidden_from_help_under_claude_code() {
    let mut cmd = cadence_hooks();
    cmd.args(["--help"]);
    cmd.env("CLAUDECODE", "1");

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("configure"),
        "configure should not appear in --help under Claude Code: {stdout}"
    );
}

#[test]
fn configure_visible_in_help_without_claude_code() {
    let mut cmd = cadence_hooks();
    cmd.args(["--help"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("configure"),
        "configure should appear in --help when not under Claude Code: {stdout}"
    );
}

#[test]
fn configure_empty_claudecode_does_not_block() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = cadence_hooks();
    cmd.args(["configure", "--list"]);
    cmd.env("CLAUDECODE", "");
    cmd.current_dir(tmp.path());

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "empty CLAUDECODE should not trigger the guard"
    );
}
