//! Integration tests for `cadence-hooks metrics price` — the CLI action that
//! prices one finished transcript and prints `{costUsd, byModel, unpricedModels}`.
//!
//! A CLI action, not a hook: `CADENCE_BYPASS` must not short-circuit it, and an
//! unreadable transcript exits 1 with a reason rather than printing a zero cost.

mod support;

use std::process::Command;

/// Two priced models (a 1h cache write on the first) and one the table lacks.
const TRANSCRIPT: &str = concat!(
    r#"{"type":"assistant","message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":1000000,"cache_creation_input_tokens":1000000,"cache_creation":{"ephemeral_1h_input_tokens":400000},"cache_read_input_tokens":2000000,"output_tokens":100000}}}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m2","role":"assistant","model":"claude-sonnet-5","usage":{"input_tokens":500000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":50000}}}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m3","role":"assistant","model":"no-such-model-9","usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":10}}}"#,
);

fn cadence_hooks() -> Command {
    let mut cmd = support::cadence_hooks();
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    // Would re-price every figure asserted below.
    cmd.env_remove("CADENCE_METRICS_PRICES");
    cmd
}

fn run(mut cmd: Command) -> (i32, String, String) {
    let out = cmd.output().expect("failed to execute binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("t.jsonl");
    std::fs::write(&path, TRANSCRIPT).expect("write");
    path
}

#[test]
fn prices_a_transcript_and_lists_the_unpriced_model() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture(dir.path());
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    // opus-5: 1M x 5 + 600k x 6.25 + 400k x 10 + 2M x 0.50 + 100k x 25 = 16.25
    // sonnet-5: 500k x 2 + 50k x 10 = 1.50
    let cost = v["costUsd"].as_f64().expect("costUsd");
    assert!((cost - 17.75).abs() < 0.01, "costUsd {cost}");
    assert_eq!(v["unpricedModels"], serde_json::json!(["no-such-model-9"]));
    let by_model = v["byModel"].as_array().expect("byModel");
    assert_eq!(by_model.len(), 3);
    assert_eq!(by_model[0]["model"], "claude-opus-5");
    assert_eq!(by_model[0]["tokens"]["cacheCreate"], 1_000_000);
    assert_eq!(by_model[0]["tokens"]["cacheCreate1h"], 400_000);
    assert_eq!(by_model[2]["costUsd"], 0.0);
    assert_eq!(stdout.trim().lines().count(), 1, "one JSON line: {stdout}");
}

#[test]
fn an_unreadable_transcript_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(dir.path().join("does-not-exist.jsonl"));
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "no partial output: {stdout}");
    assert!(stderr.contains("cannot read"), "{stderr}");
}

#[test]
fn a_missing_transcript_flag_is_a_usage_error() {
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "price", "--json"]);
    let (code, stdout, _stderr) = run(cmd);

    assert_eq!(code, 2);
    assert!(stdout.is_empty());
}

#[test]
fn a_price_table_override_re_prices_the_transcript() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture(dir.path());
    let table = dir.path().join("prices.json");
    std::fs::write(
        &table,
        r#"{"models":{"claude-opus-5":{"inputPerMTok":1.0,"outputPerMTok":0.0,"cacheWritePerMTok":0.0,"cacheWrite1hPerMTok":0.0,"cacheReadPerMTok":0.0}}}"#,
    )
    .expect("write table");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_PRICES", &table);
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    assert!(
        (v["costUsd"].as_f64().expect("costUsd") - 1.0).abs() < 0.01,
        "{stdout}"
    );
    assert_eq!(
        v["unpricedModels"],
        serde_json::json!(["claude-sonnet-5", "no-such-model-9"])
    );
}

/// `CADENCE_BYPASS=1` must not turn a CLI action into a silent exit 0.
#[test]
fn cadence_bypass_does_not_silence_a_cli_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture(dir.path());
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BYPASS", "1");
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "a bypassed run still prints the pricing: {stdout}"
    );
}

#[test]
fn cadence_disable_does_not_silence_a_cli_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture(dir.path());
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_DISABLE", "metrics,price,metrics-price");
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(&path);
    let (code, stdout, stderr) = run(cmd);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "stdout: {stdout}"
    );
}

#[test]
fn a_directory_is_not_a_transcript() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "price", "--json", "--transcript"])
        .arg(dir.path());
    let (code, stdout, stderr) = run(cmd);
    assert_eq!(code, 1, "stdout: {stdout}");
    assert!(stderr.contains("not a regular file"), "stderr: {stderr}");
    assert!(stdout.is_empty());
}

#[test]
fn a_named_price_table_that_cannot_be_read_exits_1() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture(dir.path());
    let mut cmd = cadence_hooks();
    cmd.env_remove("CADENCE_METRICS_PRICES");
    cmd.args([
        "metrics",
        "price",
        "--json",
        "--prices",
        "/nonexistent/prices.json",
        "--transcript",
    ])
    .arg(&path);
    let (code, stdout, stderr) = run(cmd);
    assert_eq!(code, 1, "stdout: {stdout}");
    assert!(
        stderr.contains("cannot read price table"),
        "stderr: {stderr}"
    );
    assert!(stdout.is_empty());
}
