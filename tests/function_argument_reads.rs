//! cameronsjo/cadence-hooks#1409: `f(){ cat "$1"; }; f .env` makes bash read
//! `.env`, but the name never sits where a reader takes a file. Through the
//! built binary, so the block's exit code and message are what Claude sees.

mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn scratch() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp dir"))
        .path()
}

fn run(command: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "function-argument-reads",
        "cwd": scratch(),
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let mut cmd: Command = support::cadence_hooks();
    cmd.env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env("CADENCE_METRICS_DIR", scratch())
        .env("HOME", scratch())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .args(["cadence", "prevent-secret-leaks"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload.as_bytes()).expect("write payload");
    }
    child.wait_with_output().expect("wait on cadence-hooks")
}

fn assert_exit(commands: &[&str], code: i32, why: &str) {
    let wrong: Vec<(&str, Option<i32>)> = commands
        .iter()
        .map(|c| (*c, run(c).status.code()))
        .filter(|(_, got)| *got != Some(code))
        .collect();
    assert!(wrong.is_empty(), "{wrong:?} did not exit {code}: {why}");
}

#[test]
fn a_secret_name_passed_to_a_reading_function_is_blocked() {
    assert_exit(
        &[
            r#"f(){ cat "$1"; }; f .env"#,
            r#"function f { cat "$1"; }; f .env"#,
            "function f() { cat \"$@\"; }\nf .env",
            r#"f(){ "$@"; }; f cat .env"#,
            r#"f() { echo "$1" | xargs cat; }; f .env"#,
            r#"f(){ for x in "$@"; do cat "$x"; done; }; f .env"#,
            // The accepted cost: the rule does not read what the body does.
            r#"f(){ echo "$1"; }; f .env"#,
            r#"f(){ git add "$@"; }; f .env"#,
        ],
        2,
        "a positional function and a secret name",
    );
    let out = run(r#"f(){ cat "$1"; }; f .env"#);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("in a command that defines a function reading its arguments"),
        "the block names the rule: {stderr}"
    );
}

#[test]
fn positional_functions_with_no_secret_name_still_pass() {
    assert_exit(
        &[
            r#"f(){ echo "$1"; }; f notes.txt"#,
            r#"f(){ cat "$1"; }; f README.md"#,
            r#"f(){ git add "$@"; }; f src/"#,
            r#"cat "$1""#,
        ],
        0,
        "a positional function with no secret name",
    );
}

#[test]
fn two_hundred_definitions_and_a_long_command_are_judged_in_one_pass() {
    // The rule reads the command once for definitions and once for words, so
    // 200 definitions and a long tail cost a few milliseconds, not a walk per
    // call (#1420 security review I-D). The budget applies under
    // `CADENCE_TIMING_TESTS=1` in release.
    let definitions: String = (0..200)
        .map(|i| format!("f{i}(){{ # don't\n echo \"$1\"; f{} \"$1\"; }}\n", i + 1))
        .collect();
    let calls: String = (0..200).map(|i| format!("f{i} build{i}; ")).collect();
    let command = format!("{definitions}{calls}{}", "echo x; ".repeat(2000));
    let timed = |command: &str| {
        let started = std::time::Instant::now();
        let out = run(command);
        cadence_hooks_core::test_builders::assert_elapsed_under(
            "200 definitions and a long command",
            started.elapsed(),
            std::time::Duration::from_secs(1),
        );
        out
    };
    let allowed = timed(&command);
    let blocked = timed(&format!("{command}f0 .env"));
    assert_eq!(
        blocked.status.code(),
        Some(2),
        "a secret name after the definitions"
    );
    // Every body opens with a comment, which the scan cannot delimit, so it
    // reads as a positional function; with no secret word it still passes.
    assert_eq!(allowed.status.code(), Some(0), "no secret name");
}
