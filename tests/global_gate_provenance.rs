//! `CADENCE_BYPASS` / `CADENCE_DISABLE` leave a `bypasses.jsonl` provenance row
//! (cadence-hooks#223). The gates exit before the dispatch seam, so they record
//! at the gate itself.

mod support;

use std::process::Command;

fn cmd(metrics: &std::path::Path) -> Command {
    let mut c = support::cadence_hooks();
    for v in ["CADENCE_BYPASS", "CADENCE_DISABLE", "CLAUDECODE"] {
        c.env_remove(v);
    }
    c.env("CADENCE_METRICS_DIR", metrics);
    c.env("CLAUDE_CODE_SESSION_ID", "sess-gate");
    c
}

fn rows(metrics: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(metrics.join("bypasses.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON row"))
        .collect()
}

#[test]
fn global_bypass_records_a_row_and_still_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let out = cmd(dir.path())
        .args(["cadence", "git-safety"])
        .env("CADENCE_BYPASS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let r = rows(dir.path());
    assert_eq!(r.len(), 1, "one row per bypassed invocation: {r:?}");
    assert_eq!(r[0]["event"], "used");
    assert_eq!(r[0]["kind"], "global_bypass");
    assert_eq!(r[0]["mechanism"], "CADENCE_BYPASS=1");
    assert_eq!(r[0]["hook"], "cadence git-safety");
    assert_eq!(r[0]["sessionId"], "sess-gate");
}

#[test]
fn bypass_exempt_command_records_nothing() {
    // `list` is exempt from the bypass, so nothing was bypassed.
    let dir = tempfile::tempdir().unwrap();
    let _ = cmd(dir.path())
        .arg("list")
        .env("CADENCE_BYPASS", "1")
        .output()
        .unwrap();
    assert!(rows(dir.path()).is_empty());
}

#[test]
fn global_disable_records_a_row_naming_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    let out = cmd(dir.path())
        .args(["cadence", "line-endings"])
        .env("CADENCE_DISABLE", "line-endings")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let r = rows(dir.path());
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["kind"], "global_disable");
    assert_eq!(r[0]["mechanism"], "CADENCE_DISABLE");
    assert_eq!(r[0]["hook"], "line-endings");
}

#[test]
fn refused_disable_of_a_protected_guard_records_nothing() {
    // The guard still runs, so nothing was disabled.
    let dir = tempfile::tempdir().unwrap();
    let _ = cmd(dir.path())
        .args(["cadence", "git-safety"])
        .env("CADENCE_DISABLE", "git-safety")
        .output()
        .unwrap();
    assert!(
        rows(dir.path())
            .iter()
            .all(|r| r["kind"] != "global_disable")
    );
}

#[test]
fn unwritable_metrics_dir_fails_open() {
    // ADR-0001: a metrics dir that is a plain file must not change the exit.
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, "x").unwrap();
    let out = cmd(&blocker)
        .args(["cadence", "git-safety"])
        .env("CADENCE_BYPASS", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}
