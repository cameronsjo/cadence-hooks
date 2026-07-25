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

use std::io::Write;
use std::process::{Command, Output};

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
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

/// How long the parent stalls before feeding the child stdin. Both dispatch
/// wrappers start their timer *before* the blocking stdin read, so this stall
/// lands inside the measured span and puts `elapsed_ms` deterministically above
/// the zeroed threshold below — without it a panicking dispatch clocks 0 ms and
/// `log_timing`'s strict `>` writes nothing, which would make the
/// "dispatch resumed" assertion vacuous rather than merely flaky.
const STDIN_STALL: std::time::Duration = std::time::Duration::from_millis(20);

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
    std::thread::sleep(STDIN_STALL);
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
    // dispatch never regained control: the run ended at exit 1 with no timing
    // row. Three assertions, each pinning a distinct half of the fix.
    let (out, tmp) = run_with_panic_armed(&["cadence", "terminology"]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "a panicking check fails open (exit 0) — not 1 (the old panic-hook \
         exit) and certainly not 2 (a block): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rows = failopen_rows(tmp.path());
    assert_eq!(rows.len(), 1, "exactly one row per panic: {rows:?}");
    assert_eq!(rows[0]["reason"], "panic");
    let error = rows[0]["error"]
        .as_str()
        .expect("the panic row carries the payload");
    assert!(
        error.contains("CADENCE_TEST_PANIC") && error.contains("at src/dispatch.rs:"),
        "payload and source location are both recorded: {error}"
    );

    // The timing row is the proof dispatch RESUMED past the panic rather than
    // being aborted mid-flight — it is written after the `catch_unwind` returns.
    let timings = read_jsonl(&tmp.path().join("hooks.jsonl"));
    assert_eq!(
        timings.len(),
        1,
        "dispatch ran its telemetry tail after catching the panic: {timings:?}"
    );
    assert_eq!(timings[0]["hook"], "terminology");
}

#[test]
fn a_panicking_logger_still_exits_zero() {
    // `run_logged_logger` documents an always-exit-0 contract. Until #349 that
    // contract was violated by any panic, because the panic hook exited 1
    // before the existing `catch_unwind` could see the unwind.
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
