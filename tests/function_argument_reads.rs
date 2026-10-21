//! A shell function beside a secret name. cameronsjo/cadence-hooks#1409 blocked
//! any such command; cadence-ecosystem ADR-0046 rule 1 put function
//! indirection out of scope, so only a literal read blocks. Through the built
//! binary, so the exit code is what Claude sees.

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
fn a_function_definition_beside_a_secret_name_passes() {
    assert_exit(
        &[
            r#"f(){ echo "$1"; }; f .env"#,
            r#"die(){ echo "$*" >&2; exit 1; }; [ -f .env ] || die "missing .env""#,
            r#"f(){ git add "$@"; }; f .env"#,
            r#"f(){ echo hi; }; f; git commit -m 'mention .env'"#,
            r#"f(){ cat "$1"; }; f .env"#,
        ],
        0,
        "a function definition and a secret name",
    );
    assert_exit(
        &["f(){ cat .env; }; f", r#"f(){ echo "$1"; }; f x; cat .env"#],
        2,
        "a literal read beside a function definition",
    );
}

#[test]
fn functions_with_no_secret_name_still_pass() {
    assert_exit(
        &[
            r#"f(){ echo "$1"; }; f notes.txt"#,
            r#"f(){ cat "$1"; }; f README.md"#,
            r#"f(){ git add "$@"; }; f src/"#,
            r#"cat "$1""#,
        ],
        0,
        "a function definition with no secret name",
    );
}

#[test]
fn two_hundred_definitions_and_a_long_command_are_judged_in_one_pass() {
    // 200 definitions and a long tail cost about what the reader scan does
    // (#1420 security review I-D). The budget applies under
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
    let allowed = timed(&format!("{command}f0 .env"));
    let blocked = timed(&format!("{command}cat .env"));
    assert_eq!(
        blocked.status.code(),
        Some(2),
        "a literal read after the definitions"
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "a secret name handed to a function"
    );
}

#[test]
fn a_literal_read_at_the_end_of_a_long_command_still_blocks() {
    // The reader scan still reaches a read after a long run of other words:
    // 1000 `$(…)` assignments and their echoes, or a 50 KB value referenced
    // 15 000 times before a `-c` script behind an option.
    let assignments: String = (0..1000)
        .map(|i| format!("OUT{i}=$(git rev-parse HEAD~{i})\n"))
        .collect();
    let echoes: String = (0..1000).map(|i| format!("echo \"$OUT{i}\"\n")).collect();
    let after_assignments = format!("{assignments}{echoes}cat .env");
    let after_a_long_value = format!(
        "V='({}'; echo {}; bash -O extglob -c 'cat .env'",
        "x".repeat(50_000),
        "$V ".repeat(15_000)
    );
    assert_exit(
        &[&after_assignments, &after_a_long_value],
        2,
        "a literal read at the end of a long command",
    );
}
