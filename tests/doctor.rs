//! Integration tests for `cadence-hooks doctor`.
//!
//! Build a fixture plugin cache in a tempdir, point doctor at it via
//! `--root`, and assert exit code + stderr/stdout content.

use std::process::Command;

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
}

/// Create `<root>/<plugin>/hooks/hooks.json` with the given JSON body.
fn write_plugin(root: &std::path::Path, plugin: &str, hooks_json: &str) {
    let dir = root.join(plugin).join("hooks");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hooks.json"), hooks_json).unwrap();
}

#[test]
fn doctor_clean_cache_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "clean-plugin",
        r#"{
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{ "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh\" arg" }]
                }]
            }
        }"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clean"),
        "expected clean output, got: {stdout}"
    );
}

#[test]
fn doctor_detects_single_quoted_plugin_root() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "buggy-plugin",
        r#"{
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{ "command": "'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg" }]
                }]
            }
        }"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "should exit 2 when shell-expansion errors found. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("buggy-plugin"),
        "should name the plugin: {stdout}"
    );
    assert!(
        stdout.contains("CLAUDE_PLUGIN_ROOT"),
        "should quote the offending snippet: {stdout}"
    );
    assert!(
        stdout.contains("single-quoted env var"),
        "should explain the diagnosis: {stdout}"
    );
}

#[test]
fn doctor_handles_empty_root_directory() {
    // No plugin subdirs at all — exit 0 with the clean message.
    let tmp = tempfile::tempdir().unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_skips_plugins_without_hooks_json() {
    // Plugin dir exists but has no hooks/hooks.json — doctor just ignores it.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("plugin-without-hooks")).unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_skips_invalid_json() {
    // Garbage JSON shouldn't crash doctor — the plugin loader is the right
    // place to surface JSON syntax errors.
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(tmp.path(), "broken-plugin", "{ not valid json");

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_finds_violation_across_multiple_plugins() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "clean-plugin",
        r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "command": "\"${X}\"" }]}] }}"#,
    );
    write_plugin(
        tmp.path(),
        "buggy-plugin-a",
        r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "command": "'${A}'" }]}] }}"#,
    );
    write_plugin(
        tmp.path(),
        "buggy-plugin-b",
        r#"{ "hooks": { "PostToolUse": [{ "hooks": [{ "command": "'$B'" }]}] }}"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    // Shell-expansion bugs are Severity::Error → exit 2.
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("buggy-plugin-a"));
    assert!(stdout.contains("buggy-plugin-b"));
    assert!(stdout.contains("2 finding"));
}
