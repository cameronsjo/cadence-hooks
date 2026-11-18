//! End-to-end: the `warn-overshare` commit quiet period through the real binary
//! (cameronsjo/cadence-hooks#1636). The unit tests drive the check; this drives
//! the dispatcher, which is what spends the quiet period.

mod support;

use std::io::Write;
use std::process::Stdio;

const SESSION: &str = "quiet-period-session";

/// A git-root tempdir, with `cadence_json` (when given) as `.claude/cadence.json`.
fn repo(cadence_json: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    if let Some(body) = cadence_json {
        std::fs::create_dir(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/cadence.json"), body).unwrap();
    }
    dir
}

/// Run `warn-overshare` on a Bash `command` from `cwd`; true when it reminded.
fn reminds(cwd: &std::path::Path, markers: &std::path::Path, command: &str) -> bool {
    let payload = serde_json::json!({
        "session_id": SESSION, "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "cwd": cwd, "tool_input": {"command": command},
    })
    .to_string();
    let mut cmd = support::cadence_hooks();
    cmd.env_remove("CADENCE_SKIP_OVERSHARE_AUDIT")
        .args(["cadence", "warn-overshare"])
        .current_dir(cwd)
        .env("CADENCE_MARKER_DIR", markers)
        .env("CADENCE_METRICS_DIR", markers.join("metrics"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(payload.as_bytes());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "never blocks");
    String::from_utf8_lossy(&out.stdout).contains("Pre-ship audit")
}

const SUPPRESS: &str = r#"{"nudges":{"warn-overshare":{"suppress":true}}}"#;

#[test]
fn a_plain_commit_reminds_once_then_is_silent() {
    let (repo, markers) = (repo(None), tempfile::tempdir().unwrap());
    assert!(reminds(repo.path(), markers.path(), "git commit -m 'a'"));
    assert!(!reminds(repo.path(), markers.path(), "git commit -m 'b'"));
    assert!(!reminds(repo.path(), markers.path(), "git commit -m 'c'"));
}

#[test]
fn a_suppressed_first_commit_does_not_spend_the_reminder() {
    let (quiet, loud) = (repo(Some(SUPPRESS)), repo(None));
    let markers = tempfile::tempdir().unwrap();
    // Control: the config really silences the reminder here.
    assert!(!reminds(quiet.path(), markers.path(), "git commit -m 'a'"));
    // The first reminder that is actually delivered in the session still fires.
    assert!(reminds(loud.path(), markers.path(), "git commit -m 'b'"));
    // That delivery is what spends it.
    assert!(!reminds(loud.path(), markers.path(), "git commit -m 'c'"));
}

#[test]
fn a_push_and_a_chained_commit_remind_after_the_quiet_period_is_spent() {
    let (repo, markers) = (repo(None), tempfile::tempdir().unwrap());
    assert!(reminds(repo.path(), markers.path(), "git commit -m 'a'"));
    assert!(!reminds(repo.path(), markers.path(), "git commit -m 'b'"));
    assert!(reminds(repo.path(), markers.path(), "git push origin HEAD"));
    assert!(reminds(
        repo.path(),
        markers.path(),
        "git commit -m 'c' && git push"
    ));
    assert!(reminds(
        repo.path(),
        markers.path(),
        "gh pr create --title t --body b"
    ));
}
