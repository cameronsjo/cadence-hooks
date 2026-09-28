//! A busy session stays live in the registry (cameronsjo/cadence-hooks#902).
//!
//! The per-call `session heartbeat` hook is unwired, so liveness rides the
//! `persist-plan-approval` process that already runs on every `PostToolUse`.
//! This drives the compiled binary with an ordinary tool's payload and asserts
//! the session's registry record is written: the `doctor --prune --apply`
//! gate reads that record's mtime to decide whether a session is live.

use std::io::Write;
use std::process::{Command, Stdio};

fn init_repo(dir: &std::path::Path) {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("git")
    };
    assert!(git(&["init", "-q", "-b", "main"]).success());
    assert!(git(&["config", "user.email", "t@t"]).success());
    assert!(git(&["config", "user.name", "t"]).success());
    assert!(git(&["commit", "--allow-empty", "-q", "-m", "root"]).success());
}

#[test]
fn an_ordinary_tool_call_refreshes_the_session_record() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let config = tempfile::tempdir().unwrap();
    let metrics = tempfile::tempdir().unwrap();
    let sid = "11111111-2222-3333-4444-555555555555";
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/tmp/x" },
        "session_id": sid,
        "cwd": repo.path(),
    })
    .to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["session", "persist-plan-approval"])
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CLAUDECODE")
        .env("CLAUDE_CONFIG_DIR", config.path())
        .env("CADENCE_METRICS_DIR", metrics.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let record = repo
        .path()
        .join(".claude/sessions")
        .join(format!("{sid}.json"));
    assert!(
        record.is_file(),
        "a Read call must leave the session registered as live: {}",
        record.display()
    );
}
