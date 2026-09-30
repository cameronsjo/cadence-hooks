//! Cloud-session behavior (`CLAUDE_CODE_REMOTE=true`), cameronsjo/cadence-hooks#1197.
//!
//! One table drives every registered hook through the real binary with the
//! variable set on the child only (the test process env is never touched, so
//! no env lock is needed) and asserts what the registry declares.

mod support;

use serde_json::Value;
use std::io::Write;
use std::process::{Output, Stdio};

fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

fn run(ns: &str, hook: &str, stdin: &str, remote: bool, extra: &[(&str, &str)]) -> Output {
    let mut cmd = support::cadence_hooks();
    cmd.args([ns, hook])
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOWED_OWNERS")
        .env("CADENCE_METRICS_DIR", scratch_metrics_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if remote {
        cmd.env("CLAUDE_CODE_REMOTE", "true");
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn binary");
    if let Some(ref mut si) = child.stdin {
        let _ = si.write_all(stdin.as_bytes());
    }
    child.wait_with_output().expect("wait")
}

fn manifest() -> Vec<Value> {
    let out = support::cadence_hooks()
        .args(["manifest", "--format", "json"])
        .output()
        .expect("manifest");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("json");
    doc["hooks"].as_array().expect("hooks").clone()
}

#[test]
fn every_hook_behaves_as_its_remote_policy_declares() {
    let hooks = manifest();
    assert!(hooks.len() > 40);
    let mut self_disabled = 0;
    for h in &hooks {
        let (ns, name) = (h["plugin"].as_str().unwrap(), h["name"].as_str().unwrap());
        let policy = h["remote"]
            .as_str()
            .expect("every hook exports a remote policy");
        // Not-JSON stdin: a hook that runs reports the parse failure on stderr;
        // a self-disabled one never reads stdin, so it is silent with exit 0.
        let out = run(ns, name, "not json", true, &[]);
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        match policy {
            "self-disable" => {
                self_disabled += 1;
                assert_eq!(out.status.code(), Some(0), "{ns} {name}");
                assert!(
                    stdout.is_empty() && stderr.is_empty(),
                    "{ns} {name}: {stdout}{stderr}"
                );
            }
            "run" => {
                // Loggers read stdin quietly, so only hooks with an event can be
                // told apart from a self-disable by their stderr.
                if h["event"] != "logger" {
                    assert!(
                        stderr.contains("Failed to parse hook JSON"),
                        "{ns} {name} should have run in the cloud: {stdout}{stderr}"
                    );
                }
            }
            other => panic!("{ns} {name}: unexpected policy {other}"),
        }
    }
    assert!(
        self_disabled >= 15,
        "the self-disable set collapsed: {self_disabled}"
    );
}

/// `nudge-afk-gap` must stay silent in the cloud even when enabled and fed a
/// payload that would fire locally: its tool-activity stamp comes from
/// `persist-plan-approval`, which self-disables there (cadence-hooks#480).
#[test]
fn afk_gap_self_disables_in_the_cloud_even_when_enabled() {
    let metrics = tempfile::tempdir().unwrap();
    let state = metrics.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("afk-cloud-sid.afk-gap"), "1").unwrap();
    let payload =
        r#"{"session_id":"afk-cloud-sid","hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
    let dir = metrics.path().to_str().unwrap();
    for (remote, fires) in [(true, false), (false, true)] {
        std::fs::write(state.join("afk-cloud-sid.afk-gap"), "1").unwrap();
        let out = run(
            "session",
            "nudge-afk-gap",
            payload,
            remote,
            &[("CADENCE_AFK_GAP", "1"), ("CADENCE_METRICS_DIR", dir)],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "remote={remote}");
        assert_eq!(
            stdout.contains("later…"),
            fires,
            "remote={remote}: {stdout}"
        );
    }
}

#[test]
fn policy_is_inert_outside_a_cloud_session() {
    // Same payload, remote unset: a self-disabled hook (enforce-worktree) runs.
    let out = run("guardrails", "enforce-worktree", "not json", false, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Failed to parse hook JSON"), "{stderr}");
}

#[test]
fn only_the_exact_string_true_counts_as_a_cloud_session() {
    for v in ["1", "TRUE", "false", ""] {
        let out = run(
            "guardrails",
            "enforce-worktree",
            "not json",
            false,
            &[("CLAUDE_CODE_REMOTE", v)],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Failed to parse"), "{v:?}: {stderr}");
    }
}

fn session_start_context(remote_owners: Option<&str>, bypass: bool) -> Option<String> {
    let payload = r#"{"session_id":"s","hook_event_name":"SessionStart","source":"startup"}"#;
    let mut extra = Vec::new();
    if let Some(o) = remote_owners {
        extra.push(("CADENCE_ALLOWED_OWNERS", o));
    }
    if bypass {
        extra.push(("CADENCE_BYPASS", "1"));
    }
    let out = run("guardrails", "enforcement-status", payload, true, &extra);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        return None;
    }
    let v: Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "SessionStart");
    // The scratch CADENCE_METRICS_DIR trips the armed-switch line, which comes
    // first; the cloud status is the last line of the same context.
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    let last = ctx.lines().last().unwrap();
    last.starts_with("cadence-hooks: ")
        .then(|| last.to_string())
}

#[test]
fn session_start_reports_armed_or_inert_in_the_cloud() {
    let armed = session_start_context(Some("me"), false).expect("armed line");
    assert_eq!(
        armed,
        format!("cadence-hooks: ARMED v{}", env!("CARGO_PKG_VERSION"))
    );
    let inert = session_start_context(None, false).expect("inert line");
    assert_eq!(
        inert,
        "cadence-hooks: INERT (allowed owners not configured)"
    );
}

#[test]
fn session_start_is_silent_outside_the_cloud() {
    let payload = r#"{"session_id":"s","hook_event_name":"SessionStart","source":"startup"}"#;
    let out = run("guardrails", "enforcement-status", payload, false, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("ARMED") && !stdout.contains("INERT"),
        "{stdout}"
    );
}
