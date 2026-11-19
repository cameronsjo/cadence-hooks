//! The confirm tier end to end, through the real binary
//! (cameronsjo/cadence-hooks#1658): exit codes across separate processes, the
//! ledger row a pass writes, and two processes of one tool call agreeing.

mod support;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The binary, sandboxed to `root` for markers and metrics.
fn cadence_hooks(root: &Path) -> Command {
    let mut cmd = support::cadence_hooks();
    cmd.env("CADENCE_MARKER_DIR", root.join("markers"));
    cmd.env("CADENCE_METRICS_DIR", root.join("metrics"));
    cmd
}

fn run(root: &Path, payload: &serde_json::Value) -> Output {
    let mut child = cadence_hooks(root)
        .args(["guardrails", "guard-op-vault-scan"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cadence-hooks");
    let body = payload.to_string();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(body.as_bytes());
    }
    child.wait_with_output().expect("wait for cadence-hooks")
}

fn payload(command: &str, session: Option<&str>, call: &str) -> serde_json::Value {
    let mut p = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": call,
        "cwd": "/",
    });
    if let Some(s) = session {
        p["session_id"] = serde_json::json!(s);
    }
    p
}

fn bypass_rows(root: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(root.join("metrics").join("bypasses.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn second_attempt_passes_once_and_writes_a_confirmed_row() {
    let root = tempfile::tempdir().unwrap();
    let first = run(root.path(), &payload("op item list", Some("sess-a"), "t1"));
    assert_eq!(first.status.code(), Some(2), "{}", stderr(&first));
    assert!(
        stderr(&first).contains("Are you sure?"),
        "{}",
        stderr(&first)
    );
    assert!(bypass_rows(root.path()).is_empty());

    let second = run(
        root.path(),
        &payload("op item list | grep api", Some("sess-a"), "t2"),
    );
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    let rows = bypass_rows(root.path());
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row["event"], "used");
    assert_eq!(row["kind"], "confirmed");
    assert_eq!(row["mechanism"], "confirm-retry");
    assert_eq!(row["hook"], "guard-op-vault-scan");
    assert_eq!(row["sessionId"], "sess-a");
    // Ledger privacy: no command text.
    assert!(!row.to_string().contains("op item"), "{row}");

    let third = run(root.path(), &payload("op item list", Some("sess-a"), "t3"));
    assert_eq!(third.status.code(), Some(2));
}

#[test]
fn two_processes_of_one_call_agree() {
    // `guard-op-vault-scan` is wired twice under one matcher; a command that
    // matches both `if:` filters spawns it twice per tool call.
    let root = tempfile::tempdir().unwrap();
    let cmd = "op item list && op vault list";
    for _ in 0..2 {
        let out = run(root.path(), &payload(cmd, Some("sess-b"), "t1"));
        assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    }
    for _ in 0..2 {
        let out = run(root.path(), &payload(cmd, Some("sess-b"), "t2"));
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    }
    // One confirmation, one ledger row, however many processes ran.
    let rows = bypass_rows(root.path());
    assert_eq!(rows.len(), 1, "{rows:?}");
}

#[test]
fn no_session_id_never_passes_and_says_so() {
    let root = tempfile::tempdir().unwrap();
    for call in ["t1", "t2", "t3"] {
        let out = run(root.path(), &payload("op item list", None, call));
        assert_eq!(out.status.code(), Some(2));
        assert!(
            stderr(&out).contains("A second attempt will be blocked too"),
            "{}",
            stderr(&out)
        );
    }
}
