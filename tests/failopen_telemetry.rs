//! Integration tests for the `failopen.jsonl` telemetry stream — the
//! fire-and-forget record of the binary's fail-open paths (panic, stdin-parse
//! failure, clap version-skew). Companion to `version_mismatch.rs`, which
//! covers the same fail-open *behavior* (exit codes, stderr) without asserting
//! on the telemetry rows.
//!
//! The panic path is not covered here — no CLI-reachable trigger exists to
//! spawn-test it, matching `version_mismatch.rs`'s note that the panic-hook
//! arm is exercised only indirectly.

use std::io::Write;
use std::process::{Command, Output};

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
}

fn failopen_rows(metrics_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let path = metrics_dir.join("failopen.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each failopen.jsonl line is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
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
}
