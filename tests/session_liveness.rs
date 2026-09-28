//! A busy session stays live in the registry (cameronsjo/cadence-hooks#902).
//!
//! The per-call `session heartbeat` hook is unwired, so liveness rides the
//! `persist-plan-approval` process that already runs on every `PostToolUse`.
//! These drive the compiled binary with an ordinary tool's payload. The
//! `doctor --prune --apply` gate reads the local and mirror records' mtimes
//! to decide whether a session is live.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const SID: &str = "11111111-2222-3333-4444-555555555555";

fn init_repo(dir: &Path) {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            // A global commit.gpgSign would fail the fixture commit.
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("git")
    };
    assert!(git(&["init", "-q", "-b", "main"]).success());
    assert!(git(&["config", "user.email", "t@t"]).success());
    assert!(git(&["config", "user.name", "t"]).success());
    assert!(git(&["commit", "--allow-empty", "-q", "-m", "root"]).success());
}

fn post_tool_use(repo: &Path, config: &Path, metrics: &Path) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/tmp/x" },
        "session_id": SID,
        "cwd": repo,
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["session", "persist-plan-approval"])
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_SESSION_STALE_MINUTES")
        .env_remove("CLAUDECODE")
        .env("CLAUDE_CONFIG_DIR", config)
        .env("CADENCE_METRICS_DIR", metrics)
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
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

fn set_mtime(path: &Path, t: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

#[test]
fn an_ordinary_tool_call_keeps_a_busy_session_live() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let config = tempfile::tempdir().unwrap();
    let metrics = tempfile::tempdir().unwrap();
    let local = repo
        .path()
        .join(".claude/sessions")
        .join(format!("{SID}.json"));
    let mirror = config
        .path()
        .join("cadence/live-sessions")
        .join(format!("{SID}.json"));

    // First call registers the session in both registries.
    post_tool_use(repo.path(), config.path(), metrics.path());
    assert!(local.is_file(), "local record: {}", local.display());
    assert!(mirror.is_file(), "mirror record: {}", mirror.display());

    // A fresh record is left alone: the throttle holds.
    let old = SystemTime::now() - Duration::from_secs(60);
    set_mtime(&local, old);
    set_mtime(&mirror, old);
    post_tool_use(repo.path(), config.path(), metrics.path());
    assert_eq!(
        mtime(&mirror),
        old,
        "a 1-minute-old record is not rewritten"
    );

    // The bug: a 40-minute-old record on a busy session gets refreshed.
    let aged = SystemTime::now() - Duration::from_secs(40 * 60);
    set_mtime(&local, aged);
    set_mtime(&mirror, aged);
    post_tool_use(repo.path(), config.path(), metrics.path());
    let fresh = SystemTime::now() - Duration::from_secs(60);
    assert!(mtime(&local) > fresh, "local record refreshed");
    assert!(mtime(&mirror) > fresh, "mirror record refreshed");
}
