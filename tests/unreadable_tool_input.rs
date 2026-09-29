//! End-to-end coverage for a `tool_input` whose operation-bearing field is
//! present but mistyped (cadence-hooks#1087).
//!
//! Before the fix, one wrong-typed field degraded the whole `tool_input` to
//! `None`, so every guard saw "no command" and allowed. Now the readable fields
//! are salvaged, and a security-critical guard blocks when the field it would
//! judge is the one that could not be read.

mod support;

use std::io::Write;
use std::process::Stdio;

/// Pipe `payload` to `<namespace> <hook>` and return `(exit code, stderr)`.
fn run_hook(args: &[&str], payload: &str) -> (Option<i32>, String) {
    let (code, stderr, _) = run_hook_with_ledger(args, payload);
    (code, stderr)
}

/// [`run_hook`], also returning the raw `failopen.jsonl` text ("" when none).
fn run_hook_with_ledger(args: &[&str], payload: &str) -> (Option<i32>, String, String) {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let markers = tempfile::tempdir().expect("temp marker dir");
    let output = support::cadence_hooks()
        .args(args)
        .env("CADENCE_METRICS_DIR", metrics.path())
        .env("CADENCE_MARKER_DIR", markers.path())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_ALLOW_MAIN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run hook");
    let ledger = std::fs::read_to_string(metrics.path().join("failopen.jsonl")).unwrap_or_default();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        ledger,
    )
}

#[test]
fn mistyped_tool_input_is_judged_not_waved_through() {
    let cwd = tempfile::tempdir().expect("temp cwd");
    let cwd = cwd.path().to_string_lossy().into_owned();
    // (hook, tool_name, tool_input, expected exit, why)
    let cases: &[(&str, &str, serde_json::Value, i32, &str)] = &[
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": "git reset --hard", "file_path": 5}),
            2,
            "the issue's repro: an unrelated mistyped field no longer hides the command",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": "ls", "file_path": 5}),
            0,
            "an unrelated mistyped field on a harmless command still allows",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": ["git", "reset", "--hard"]}),
            2,
            "an argv-array command is joined and judged",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": ["ls", "-la"]}),
            0,
            "a harmless argv-array command is joined and allowed",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": ["git", "reset", 5]}),
            2,
            "an array with a non-string element cannot be read, so it blocks",
        ),
        (
            "prevent-secret-writes",
            "Edit",
            serde_json::json!({"file_path": "notes.txt", "old_string": "a", "new_string": "b", "replace_all": "true"}),
            0,
            "a string replace_all is read, not a block",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": {"nested": "git reset --hard"}}),
            2,
            "an object command cannot be read, so it blocks",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!("git reset --hard"),
            2,
            "a non-object Bash tool_input cannot be read, so it blocks",
        ),
        (
            "prevent-secret-writes",
            "Write",
            serde_json::json!({"file_path": "cfg/.env", "content": ["A=1"]}),
            2,
            "a mistyped Write content blocks",
        ),
        (
            "prevent-secret-writes",
            "Write",
            serde_json::json!({"file_path": ["cfg/.env"], "content": "A=1"}),
            2,
            "a mistyped Write path blocks",
        ),
        (
            "prevent-secret-writes",
            "mcp__fs__write_file",
            serde_json::json!({"path": "notes.txt", "content": [{"type": "text"}]}),
            0,
            "third-party MCP shapes are not judged as drift",
        ),
        (
            "prevent-secret-leaks",
            "Read",
            serde_json::json!({"file_path": "notes.txt", "limit": "ten"}),
            0,
            "an unmodeled field never counts",
        ),
        (
            "git-safety",
            "Bash",
            serde_json::json!({"command": "ls"}),
            0,
            "a well-formed payload is unaffected",
        ),
    ];
    for (hook, tool, input, expected, why) in cases {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
            "cwd": cwd,
        })
        .to_string();
        let (code, stderr) = run_hook(&["cadence", hook], &payload);
        assert_eq!(code, Some(*expected), "{why}: {hook} {input}: {stderr}");
    }
}

/// A mistyped top-level field no longer fails the whole parse and exits 0
/// with the command unjudged (review N4). (payload, expected exit, why)
#[test]
fn mistyped_top_level_field_does_not_skip_the_guard() {
    let cases: &[(&str, i32, &str)] = &[
        (
            r#"{"tool_name":"Bash","cwd":5,"tool_input":{"command":"git reset --hard"}}"#,
            2,
            "a numeric cwd is dropped and the command judged",
        ),
        (
            r#"{"tool_name":"Bash","session_id":{},"tool_input":{"command":"git reset --hard"}}"#,
            2,
            "an object session_id is dropped and the command judged",
        ),
        (
            r#"{"tool_name":5,"tool_input":{"command":"git reset --hard"}}"#,
            2,
            "without a readable tool_name the operation cannot be judged",
        ),
        (
            r#"{"tool_name":"Bash","cwd":5,"tool_input":{"command":"ls"}}"#,
            0,
            "a harmless command with a numeric cwd still allows",
        ),
    ];
    for (payload, expected, why) in cases {
        let (code, stderr) = run_hook(&["cadence", "git-safety"], payload);
        assert_eq!(code, Some(*expected), "{why}: {stderr}");
    }
}

/// A non-critical hook runs on the salvaged input instead of blocking, so a
/// mistyped field never turns an advisory hook into an enforcement point.
#[test]
fn non_critical_hook_does_not_block_on_unreadable_input() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":["ls"]},"cwd":"/"}"#;
    let (code, stderr) = run_hook(&["guardrails", "warn-main-branch"], payload);
    assert_eq!(code, Some(0), "{stderr}");
}

/// The block message names the field, never its value.
#[test]
fn block_message_names_the_field_not_the_value() {
    let secret = "never-echo-this-value";
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": [secret, 5]},
        "cwd": "/",
    })
    .to_string();
    let (code, stderr, ledger) = run_hook_with_ledger(&["cadence", "git-safety"], &payload);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("command present with the wrong type"),
        "{stderr}"
    );
    assert!(!stderr.contains(secret), "{stderr}");
    // Review N1: the block leaves an `unreadable_input` row naming the field.
    let rows: Vec<serde_json::Value> = ledger
        .lines()
        .map(|line| serde_json::from_str(line).expect("jsonl row"))
        .collect();
    assert!(
        rows.iter().any(|row| row["reason"] == "unreadable_input"
            && row["subcommand"] == "git-safety"
            && row["error"] == "wrong type: command"),
        "{ledger}"
    );
    assert!(!ledger.contains(secret), "{ledger}");
}
