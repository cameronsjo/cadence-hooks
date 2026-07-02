//! Cross-process integration tests for the session-scoped marker family (CP0).
//!
//! The honest RED for session scoping must run the binary in **two separate
//! processes**: an in-process double-invoke passes today because
//! `process::id()` is stable within one test process. Two real invocations get
//! two pids under the pre-CP0 code, so the pid-keyed marker never matches and
//! the once-per-session nudge fires twice — exactly the bug CP0 closes (#133).

use std::io::Write;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Don't inherit enforcement toggles from the test runner's session.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    // PPID is the pre-CP0 session key; remove it so the fallback path is
    // exercised deterministically. CADENCE_ALLOW_MAIN would silence the nudge.
    cmd.env_remove("PPID");
    cmd.env_remove("CADENCE_ALLOW_MAIN");
    cmd
}

/// Spawn the binary with JSON on stdin and return the completed output. A
/// BrokenPipe on write is expected when the child exits before draining stdin.
fn run_with_stdin(mut cmd: Command, input: &str) -> std::process::Output {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to execute binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(input.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

/// Build a throwaway git repo on `main` (unborn branch — no commit needed).
fn init_main_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let ok = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(dir.path())
        .status()
        .expect("git init");
    assert!(ok.success(), "git init failed");
    dir
}

/// A payload unique per run so markers from prior test runs (which persist in
/// the temp marker dir) never mask the assertion.
fn edit_payload(repo: &std::path::Path, session_id: &str) -> String {
    let file = repo.join("f.txt");
    format!(
        r#"{{"session_id":"{}","cwd":"{}","tool_name":"Edit","tool_input":{{"file_path":"{}"}}}}"#,
        session_id,
        repo.display(),
        file.display()
    )
}

#[test]
fn warn_main_branch_nudges_once_per_session() {
    let repo = init_main_repo();
    let session_id = format!(
        "cp0-red-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let payload = edit_payload(repo.path(), &session_id);

    // Invocation 1: same session, first edit on main → nudge.
    let mut cmd1 = cadence_hooks();
    cmd1.args(["guardrails", "warn-main-branch"]);
    let out1 = run_with_stdin(cmd1, &payload);
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    assert_eq!(out1.status.code(), Some(0), "invocation 1 exits 0");
    assert!(
        stdout1.contains("feature branch"),
        "invocation 1 must nudge (a separate process): {stdout1}"
    );

    // Invocation 2: same session id, distinct process (distinct pid) → the
    // marker written by invocation 1 must suppress this one.
    let mut cmd2 = cadence_hooks();
    cmd2.args(["guardrails", "warn-main-branch"]);
    let out2 = run_with_stdin(cmd2, &payload);
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(out2.status.code(), Some(0), "invocation 2 exits 0");
    assert!(
        stdout2.trim().is_empty(),
        "invocation 2 must be silent — the session already nudged: {stdout2}"
    );
}
