//! Integration tests for the `failopen.jsonl` telemetry stream — the
//! fire-and-forget record of the binary's fail-open paths (panic, stdin-parse
//! failure, clap version-skew). Companion to `version_mismatch.rs`, which
//! covers the same fail-open *behavior* (exit codes, stderr) without asserting
//! on the telemetry rows.
//!
//! The panic path is covered by the `CADENCE_TEST_PANIC` tests at the bottom.
//! No *real* check or logger has a CLI-reachable panic — which is precisely why
//! cameronsjo/cadence-hooks#349 (a `Check` dispatch path whose panic guard was
//! unreachable) went unnoticed for as long as it did — so `dispatch.rs` carries
//! a `#[cfg(debug_assertions)]` env-gated trigger inside the guarded region.
//! Those two tests therefore only pass against a debug build, which is what
//! `cargo test` produces.

mod support;

use std::io::Write;
use std::process::{Command, Output};

fn cadence_hooks() -> Command {
    support::cadence_hooks()
}

fn failopen_rows(metrics_dir: &std::path::Path) -> Vec<serde_json::Value> {
    read_jsonl(&metrics_dir.join("failopen.jsonl"))
}

fn read_jsonl(path: &std::path::Path) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each JSONL line is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
}

/// Run the binary with `{}` on stdin and the synthetic panic trigger armed,
/// against a fresh metrics dir. Returns the process output plus the dir, so a
/// caller can read both `failopen.jsonl` and `hooks.jsonl` from it.
fn run_with_panic_armed(args: &[&str]) -> (Output, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cadence_hooks();
    cmd.args(args);
    cmd.env("CADENCE_METRICS_DIR", tmp.path());
    cmd.env("CADENCE_TEST_PANIC", "1");
    // Every run is "slow", so the timing row is written unconditionally.
    cmd.env("CADENCE_HOOK_TIMING_THRESHOLD_MS", "0");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(b"{}") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    let out = child.wait_with_output().expect("failed to wait on binary");
    (out, tmp)
}

#[test]
fn unknown_subcommand_writes_version_mismatch_row() {
    let tmp = tempfile::tempdir().unwrap();
    let out: Output = cadence_hooks()
        .args(["future-plugin", "some-hook"])
        .env("CADENCE_METRICS_DIR", tmp.path())
        .output()
        .expect("failed to execute binary");

    assert_eq!(
        out.status.code(),
        Some(1),
        "unknown subcommand still exits 1 (warn): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one failopen row: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["reason"], "version_mismatch");
    assert_eq!(row["namespace"], "future-plugin");
    assert_eq!(row["subcommand"], "some-hook");
    assert_eq!(row["binaryVersion"], env!("CARGO_PKG_VERSION"));
    assert!(row["ts"].is_string());
    // The clap error *kind*, not the full multi-line ANSI-colored error.
    assert_eq!(row["error"], "InvalidSubcommand");
}

#[test]
fn malformed_stdin_on_a_check_writes_parse_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_METRICS_DIR", tmp.path());
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(b"not valid json") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    let out = child.wait_with_output().expect("failed to wait on binary");

    assert_eq!(
        out.status.code(),
        Some(0),
        "malformed stdin fails open (exit 0), never blocks: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one failopen row: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["reason"], "parse");
    assert_eq!(row["namespace"], "cadence");
    assert_eq!(row["subcommand"], "terminology");
    assert_eq!(row["binaryVersion"], env!("CARGO_PKG_VERSION"));
    let error = row["error"].as_str().expect("parse rows carry an error");
    assert!(
        error.contains("Failed to parse hook JSON"),
        "the parser's own message is recorded: {error}"
    );
}

#[test]
fn malformed_stdin_on_a_logger_writes_parse_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "log-subagent"]);
    cmd.env("CADENCE_METRICS_DIR", tmp.path());
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(b"not valid json") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    let out = child.wait_with_output().expect("failed to wait on binary");

    assert_eq!(
        out.status.code(),
        Some(0),
        "malformed stdin fails open (exit 0), never blocks: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one failopen row: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["reason"], "parse");
    assert_eq!(row["namespace"], "metrics");
    assert_eq!(row["subcommand"], "log-subagent");
    assert_eq!(row["binaryVersion"], env!("CARGO_PKG_VERSION"));
    let error = row["error"].as_str().expect("parse rows carry an error");
    assert!(
        error.contains("Failed to parse hook JSON"),
        "the parser's own message is recorded: {error}"
    );
}

// --- panic path (cameronsjo/cadence-hooks#349) ---

#[test]
fn a_panicking_check_fails_open_and_dispatch_survives_it() {
    // The one test that proves #349 fixed. Before the fix the global panic hook
    // called `process::exit(1)` *before* unwinding began, so `catch_unwind` in
    // dispatch never regained control and the run ended mid-flight.
    //
    // The exit code is deliberately UNCHANGED at 1 — it is the fail-open warn
    // code, and it keeps the panic visible (Claude Code surfaces stderr on a
    // non-zero, non-2 exit). So the exit code alone cannot distinguish fixed
    // from broken here; the `hooks.jsonl` row below is what does, because it is
    // written only after `catch_unwind` returns.
    let (out, tmp) = run_with_panic_armed(&["cadence", "terminology"]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "a panicking check warns (exit 1) and never blocks (exit 2): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one row per panic: {rows:?}");
    assert_eq!(rows[0]["reason"], "panic");
    let error = rows[0]["error"]
        .as_str()
        .expect("the panic row carries the payload");
    // Match on the file name alone, without a leading separator: `Location::file()`
    // yields the path as the compiler saw it, so a `src/` prefix is `src\` on
    // Windows. The property under test is that the location was recorded and
    // points at the dispatch site, which the bare file name pins on every host.
    assert!(
        error.contains("CADENCE_TEST_PANIC") && error.contains("dispatch.rs:"),
        "payload and source location are both recorded: {error}"
    );

    // THE load-bearing assertion: the timing row proves dispatch RESUMED past
    // the panic rather than being aborted. Pre-fix this file is empty, because
    // the panic hook exited the process before the telemetry tail could run.
    let timings = read_jsonl(&tmp.path().join("hooks.jsonl"));
    assert_eq!(
        timings.len(),
        1,
        "dispatch ran its telemetry tail after catching the panic: {timings:?}"
    );
    assert_eq!(timings[0]["hook"], "terminology");

    // The breadcrumb the non-zero exit exists to surface.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("internal error (panic)"),
        "the operator sees the panic on the turn it happens: {stderr}"
    );
}

#[test]
fn a_panicking_logger_still_exits_zero() {
    // `run_logged_logger` documents an always-exit-0 contract. Until #349 that
    // contract was violated by any panic, because the panic hook exited 1
    // before the existing `catch_unwind` could see the unwind.
    //
    // The logger keeps exit 0 where the check path above keeps exit 1: a logger
    // enforces nothing, so a panicking one has no enforcement failure to make
    // visible, and its contract is the stronger constraint.
    let (out, tmp) = run_with_panic_armed(&["metrics", "log-subagent"]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "a logger never emits a non-zero exit, panic or not: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one row per panic: {rows:?}");
    assert_eq!(rows[0]["reason"], "panic");
    assert!(rows[0]["error"].is_string());

    let timings = read_jsonl(&tmp.path().join("hooks.jsonl"));
    assert_eq!(
        timings.len(),
        1,
        "the timing write after the guard still ran: {timings:?}"
    );
}

/// Pipe `payload` to `args` against a fresh metrics dir; return the dir.
fn run_with_payload(args: &[&str], payload: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let mut child = cadence_hooks()
        .args(args)
        .env("CADENCE_METRICS_DIR", tmp.path())
        .env_remove("CADENCE_DISABLE")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(payload.as_bytes());
    }
    let out = child.wait_with_output().expect("failed to wait on binary");
    assert_eq!(
        out.status.code(),
        Some(0),
        "drift never changes the exit code"
    );
    tmp
}

/// #364: an object whose declared field mismatches writes one `schema_drift`
/// row naming only the key, on both the check and the logger dispatch paths.
#[test]
fn object_shaped_mismatch_writes_schema_drift_row() {
    let secret = "never-copy-this-value";
    let payload = format!(
        r#"{{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{{"command":"ls"}},"tool_response":{{"stdout":{{"t":"{secret}"}}}}}}"#
    );
    for args in [
        &["metrics", "log-subagent"][..],
        &["cadence", "git-safety"][..],
    ] {
        let tmp = run_with_payload(args, &payload);
        let rows = failopen_rows(tmp.path());
        assert_eq!(rows.len(), 1, "{args:?}: {rows:?}");
        assert_eq!(rows[0]["reason"], "schema_drift");
        assert_eq!(rows[0]["subcommand"], args[1]);
        assert_eq!(
            rows[0]["error"],
            "tool_response: object did not match its typed shape"
        );
        let raw = std::fs::read_to_string(tmp.path().join("failopen.jsonl")).unwrap();
        assert!(!raw.contains(secret), "no payload value reaches the ledger");
    }
}

/// #364: a `group` fan-out writes the drift rows once for the payload, not
/// once per member.
#[test]
fn group_fan_out_writes_schema_drift_once() {
    let payload = r#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"stdout":{"t":"x"}}}"#;
    let tmp = run_with_payload(
        &[
            "group",
            "cadence/git-safety",
            "cadence/prevent-secret-leaks",
            "cadence/prevent-secret-writes",
        ],
        payload,
    );
    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "one drift row per payload key: {rows:?}");
    assert_eq!(rows[0]["reason"], "schema_drift");
    assert_eq!(rows[0]["subcommand"], "git-safety");
}

/// #364: expected per-tool variance (a non-object response) stays silent.
#[test]
fn non_object_tool_response_writes_no_failopen_row() {
    let payload = r#"{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Read","tool_response":"contents"}"#;
    for args in [
        &["metrics", "log-subagent"][..],
        &["cadence", "git-safety"][..],
    ] {
        let tmp = run_with_payload(args, payload);
        assert!(failopen_rows(tmp.path()).is_empty(), "{args:?}");
    }
}
