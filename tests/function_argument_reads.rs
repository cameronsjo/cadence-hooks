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
            "f(){ cat; }; f < .env",
        ],
        2,
        "the function body reads the secret file",
    );
    let out = run(r#"f(){ cat "$1"; }; f .env"#);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("passed to the function `f`"),
        "the block names the function: {stderr}"
    );
}

#[test]
fn functions_that_do_not_read_a_secret_still_pass() {
    assert_exit(
        &[
            r#"f(){ echo "$1"; }; f .env"#,
            r#"f(){ cat "$1"; }; f README.md"#,
            r#"f(){ git add "$@"; }; f .env"#,
            r#"cat "$1""#,
        ],
        0,
        "no secret name reaches a reader",
    );
}
