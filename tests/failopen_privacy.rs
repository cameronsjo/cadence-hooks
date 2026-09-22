//! `failopen.jsonl` rows never carry payload-derived text
//! (cameronsjo/cadence-hooks#959).
//!
//! Each test drives the real binary down one fail-open path with a canary in
//! the input, then asserts two things about the ledger: exactly one row was
//! written, and its `error` field does not contain the canary. The row-count
//! assertion is what keeps the negative one honest — with no row, "the canary
//! is absent" would pass having checked nothing.
//!
//! Every spawn clears `CADENCE_DISABLE` and `CADENCE_BYPASS`: an operator-set
//! value for either empties the row set and would make the negative assertion
//! vacuous. The panic tests use the debug-only `CADENCE_TEST_PANIC=formatted`
//! trigger in `dispatch.rs`, so they pass only against a debug build, which is
//! what `cargo test` produces.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const CANARY: &str = "CNRY959ZQ";
const CANARY_NUMBER: &str = "959424242";

fn read_failopen_rows(metrics_dir: &std::path::Path) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(metrics_dir.join("failopen.jsonl")) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each JSONL line is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
}

/// Run the binary with `stdin` piped in and `envs` set, against a fresh
/// metrics dir. Returns the output and the dir.
fn run(args: &[&str], stdin: &[u8], envs: &[(&str, &str)]) -> (Output, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.args(args)
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_BYPASS")
        .env("CADENCE_METRICS_DIR", tmp.path())
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut pipe) = child.stdin {
        match pipe.write_all(stdin) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    let out = child.wait_with_output().expect("failed to wait on binary");
    (out, tmp)
}

/// The single row's `error` field, after asserting there is exactly one row
/// and it has the expected `reason`.
fn only_row_error(metrics_dir: &std::path::Path, reason: &str, out: &Output) -> String {
    let rows = read_failopen_rows(metrics_dir);
    assert_eq!(
        rows.len(),
        1,
        "exactly one failopen row: {rows:?}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(rows[0]["reason"], reason, "{rows:?}");
    rows[0]["error"]
        .as_str()
        .expect("the row carries an error")
        .to_string()
}

#[test]
fn check_parse_row_omits_scalar() {
    let (out, tmp) = run(&["cadence", "terminology"], br#"{"cwd":959424242}"#, &[]);
    let error = only_row_error(tmp.path(), "parse", &out);
    assert!(!error.contains(CANARY_NUMBER), "payload leaked: {error}");
    assert!(error.contains("data error"), "{error}");
}

#[test]
fn logger_parse_row_omits_string() {
    let (out, tmp) = run(
        &["metrics", "log-subagent"],
        br#"{"duration_ms":"CNRY959ZQ"}"#,
        &[],
    );
    let error = only_row_error(tmp.path(), "parse", &out);
    assert!(!error.contains(CANARY), "payload leaked: {error}");
}

#[test]
fn logger_parse_row_omits_integer() {
    let (out, tmp) = run(
        &["metrics", "log-subagent"],
        br#"{"duration_ms":-959424242}"#,
        &[],
    );
    let error = only_row_error(tmp.path(), "parse", &out);
    assert!(!error.contains(CANARY_NUMBER), "payload leaked: {error}");
}

#[test]
fn syntax_row_keeps_locator() {
    let (out, tmp) = run(&["cadence", "terminology"], br#"{"a":CNRY959ZQ}"#, &[]);
    let error = only_row_error(tmp.path(), "parse", &out);
    assert!(!error.contains(CANARY), "payload leaked: {error}");
    assert!(error.contains("line 1 column"), "{error}");
}

const FORMATTED_PANIC: &[(&str, &str)] = &[
    ("CADENCE_TEST_PANIC", "formatted"),
    ("CADENCE_TEST_PANIC_TEXT", CANARY),
];

#[test]
fn check_panic_row_omits_formatted_payload() {
    let (out, tmp) = run(&["cadence", "terminology"], b"{}", FORMATTED_PANIC);
    let error = only_row_error(tmp.path(), "panic", &out);
    assert!(!error.contains(CANARY), "payload leaked: {error}");
    assert!(error.contains("withheld"), "{error}");
    // The bare file name, not `src/dispatch.rs`: `Location::file()` uses the
    // host separator, so the prefix is `src\` on Windows.
    assert!(error.contains("dispatch.rs:"), "{error}");
}

#[test]
fn logger_panic_row_omits_formatted_payload() {
    let (out, tmp) = run(&["metrics", "log-subagent"], b"{}", FORMATTED_PANIC);
    let error = only_row_error(tmp.path(), "panic", &out);
    assert!(!error.contains(CANARY), "payload leaked: {error}");
    assert!(error.contains("withheld"), "{error}");
}
