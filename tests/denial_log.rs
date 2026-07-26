//! Integration tests for the `denials.jsonl` audit log written at the dispatch
//! outcome→exit-code seam (O1).
//!
//! Drives the built binary end to end: a terminology-violating Edit piped to
//! `cadence terminology` must (a) still block byte-identically, and (b) append
//! exactly one privacy-safe deny row to `denials.jsonl`. A companion run against
//! an unwritable metrics dir proves the write is fail-open and never perturbs
//! the block (ADR-0001).

use std::io::Write;
use std::process::{Command, Output};

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Isolate from the test runner's session env so the block output and the
    // logging decision are deterministic.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CADENCE_LOG_NUDGES");
    cmd.env_remove("CADENCE_NO_FEEDBACK_FOOTER");
    cmd.env_remove("CLAUDECODE");
    cmd.env_remove("CLAUDE_EFFORT");
    cmd
}

/// A terminology-violating Edit against a non-excluded, non-git path. The
/// `old_string` carries no violation, so the introduced `whitelist` fires a
/// hard block (exit 2).
const BLOCK_PAYLOAD: &str = r#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/o1-denial-it/notes.md","new_string":"we should whitelist this host","old_string":"we should permit this host"},"session_id":"itsess","cwd":"/tmp/o1-denial-it"}"#;

fn run_terminology(metrics_dir: &std::path::Path) -> Output {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_METRICS_DIR", metrics_dir);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(BLOCK_PAYLOAD.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

fn denial_rows(metrics_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let path = metrics_dir.join("denials.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each denials.jsonl line is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
}

#[test]
fn block_writes_one_privacy_safe_deny_row() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_terminology(tmp.path());

    // The block itself is unchanged: exit 2, block message + feedback footer.
    assert_eq!(out.status.code(), Some(2), "terminology block must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BLOCKED: Inclusive terminology"),
        "block message present: {stderr}"
    );
    assert!(
        stderr.contains("whitelist"),
        "names the offending term: {stderr}"
    );
    assert!(
        stderr.contains("/cadence:feedback"),
        "feedback footer present: {stderr}"
    );
    assert!(out.stdout.is_empty(), "a block must emit no stdout");

    // Exactly one deny row, with the canonical hook name and no sensitive keys.
    let rows = denial_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one denial row: {rows:?}");
    let row = &rows[0];
    assert_eq!(
        row["hook"], "terminology",
        "canonical registry name, not Check::name()"
    );
    assert_eq!(row["decision"], "deny");
    assert_eq!(row["event"], "PreToolUse");
    assert_eq!(row["tool"], "Edit");
    assert_eq!(row["sessionId"], "itsess");
    assert!(row["ts"].is_string());
    assert!(row["repo"].is_string());

    // Privacy by construction: no command, file path, or edited content anywhere.
    let obj = row.as_object().expect("row is an object");
    for forbidden in ["command", "file_path", "filePath", "content", "new_string"] {
        assert!(
            !obj.contains_key(forbidden),
            "row must not carry '{forbidden}': {row}"
        );
    }
    let serialized = row.to_string();
    assert!(
        !serialized.contains("/tmp/o1-denial-it"),
        "leaked path: {serialized}"
    );
    assert!(
        !serialized.contains("host"),
        "leaked edited content: {serialized}"
    );
}

#[test]
fn nudge_writes_one_row_by_default() {
    // The #420 default flip, proven through the built binary: with
    // CADENCE_LOG_NUDGES unset (the harness strips it), a nudging check must
    // append one decision:"nudge" row. warn-branch-base nudges deterministically
    // on this payload — pure command tokenization, no git state required
    // (verified from a non-git cwd).
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    // Build via serde_json so the cwd is JSON-escaped — a raw format! left
    // Windows path backslashes unescaped, the binary failed open on the
    // malformed payload, and the test failed only on Windows CI.
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "git checkout -b probe-branch probe-base"},
        "session_id": "itnudge",
        "cwd": cwd,
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "warn-branch-base"]);
    cmd.env("CADENCE_METRICS_DIR", tmp.path());
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    let out = child.wait_with_output().expect("failed to wait on binary");

    assert_eq!(out.status.code(), Some(0), "a nudge is advisory — exit 0");
    let rows = denial_rows(tmp.path());
    assert_eq!(
        rows.len(),
        1,
        "default-on must write the nudge row: {rows:?}"
    );
    assert_eq!(rows[0]["decision"], "nudge");
    assert_eq!(rows[0]["hook"], "warn-branch-base");
}

#[test]
fn logging_does_not_perturb_the_block_when_write_fails() {
    // Byte-identity: the block's stderr and exit code must be the same whether
    // the denial write succeeds (writable dir) or fail-opens (unwritable dir).
    // This is the load-bearing "logger must not touch enforcement output" check.
    let ok = tempfile::tempdir().unwrap();
    let writable = run_terminology(ok.path());

    // An unwritable metrics dir: a path whose parent is a regular file, so
    // create_dir_all fails and the writer degrades to a no-op.
    let blocker_dir = tempfile::tempdir().unwrap();
    let blocker_file = blocker_dir.path().join("not-a-dir");
    std::fs::write(&blocker_file, b"x").unwrap();
    let unwritable_metrics = blocker_file.join("metrics");
    let failopen = run_terminology(&unwritable_metrics);

    assert_eq!(writable.status.code(), Some(2));
    assert_eq!(
        failopen.status.code(),
        Some(2),
        "fail-open write still exits 2"
    );
    assert_eq!(
        writable.stderr, failopen.stderr,
        "block stderr must be byte-identical regardless of write outcome"
    );
    assert_eq!(writable.stdout, failopen.stdout, "no stdout in either case");

    // The fail-open run wrote nothing; the writable run wrote exactly one row.
    assert!(!unwritable_metrics.join("denials.jsonl").exists());
    assert_eq!(denial_rows(ok.path()).len(), 1);
}
