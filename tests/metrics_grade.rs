//! Integration tests for `cadence-hooks metrics grade` — the CLI action that
//! grades one transcript and prints the JSON (cadence-ecosystem#524).
//!
//! Unlike a hook, this reads no stdin payload and is not subject to
//! `CADENCE_DISABLE`. It also **fails closed**: an unidentifiable or unreadable
//! transcript exits 1 with a reason rather than printing an empty grading,
//! because a cost figure nobody can trace back to a file is worse than no
//! figure. Every test here therefore asserts the exit code as well as output.

use std::process::Command;

const ID: &str = "0e0e5f58-9ca8-4d51-bb3e-1d79a02636ae";

/// A two-gap transcript: one under the cache TTL, one over it.
const TRANSCRIPT: &str = concat!(
    r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":"do the thing"}}"#,
    "\n",
    r#"{"type":"assistant","timestamp":"2020-01-01T00:46:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":10,"cache_read_input_tokens":0,"cache_creation_input_tokens":500000,"output_tokens":5}}}"#,
    "\n",
    r#"{"type":"assistant","timestamp":"2020-01-01T02:46:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":20,"cache_read_input_tokens":0,"cache_creation_input_tokens":1000000,"output_tokens":5}}}"#,
);

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    // Would re-price every figure asserted below.
    cmd.env_remove("CADENCE_METRICS_PRICES");
    // The --session-id default. Left set, a test asserting "no transcript
    // named" would instead resolve the *live* session and pass for the wrong
    // reason — or fail confusingly on a machine where that session exists.
    cmd.env_remove("CLAUDE_CODE_SESSION_ID");
    cmd.env_remove("CLAUDE_CONFIG_DIR");
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

/// Seed `<root>/projects/<slug>/<id>.jsonl`.
fn seed(root: &std::path::Path, slug: &str, id: &str, body: &str) -> std::path::PathBuf {
    let dir = root.join("projects").join(slug);
    std::fs::create_dir_all(&dir).expect("create project dir");
    let path = dir.join(format!("{id}.jsonl"));
    std::fs::write(&path, body).expect("write transcript");
    path
}

#[test]
fn transcript_flag_grades_and_prints_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("t.jsonl");
    std::fs::write(&path, TRANSCRIPT).expect("write");

    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "grade", "--transcript"]).arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    let g: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(g["wallClockMs"], 9_960_000);
    assert_eq!(g["gaps"].as_array().expect("gaps").len(), 2);
    assert_eq!(g["gaps"][0]["coldRestartUsd"], 0.0, "under the TTL");
    assert_eq!(g["gaps"][1]["coldRestartUsd"], 9.5, "1M x (10.00 - 0.50)");
    assert_eq!(g["assistantTurns"], 2);
    assert_eq!(g["userPrompts"], 1);

    assert!(
        !stdout.contains("do the thing"),
        "no prompt text may reach the printed grading"
    );
}

#[test]
fn session_id_resolves_under_the_config_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path(), "-some-project-slug", ID, TRANSCRIPT);

    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.args(["metrics", "grade", "--session-id", ID]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    let g: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(g["wallClockMs"], 9_960_000);
}

#[test]
fn session_id_defaults_to_the_ambient_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path(), "-slug", ID, TRANSCRIPT);

    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.env("CLAUDE_CODE_SESSION_ID", ID);
    cmd.args(["metrics", "grade"]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "stdout is JSON"
    );
}

#[test]
fn a_non_uuid_session_id_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.args(["metrics", "grade", "--session-id", "../../etc/passwd"]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1, "fails closed");
    assert!(stdout.is_empty(), "nothing printed: {stdout}");
    assert!(stderr.contains("not a UUID"), "names the reason: {stderr}");
}

#[test]
fn an_unmatched_session_id_names_where_it_looked() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("projects")).expect("create projects");

    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.args(["metrics", "grade", "--session-id", ID]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("no transcript"), "{stderr}");
    assert!(
        stderr.contains("projects"),
        "names the search root: {stderr}"
    );
}

#[test]
fn an_ambiguous_session_id_refuses_rather_than_guessing() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path(), "-project-a", ID, TRANSCRIPT);
    seed(dir.path(), "-project-b", ID, TRANSCRIPT);

    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.args(["metrics", "grade", "--session-id", ID]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1, "taking the first would grade an arbitrary session");
    assert!(stdout.is_empty());
    assert!(stderr.contains("matches 2 transcripts"), "{stderr}");
    assert!(stderr.contains("-project-a"), "{stderr}");
    assert!(stderr.contains("-project-b"), "{stderr}");
}

#[test]
fn a_subagent_transcript_is_never_graded_as_a_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("projects/-slug/session-dir/subagents");
    std::fs::create_dir_all(&sub).expect("create subagent dir");
    std::fs::write(sub.join(format!("{ID}.jsonl")), TRANSCRIPT).expect("write");

    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", dir.path());
    cmd.args(["metrics", "grade", "--session-id", ID]);
    let (code, _stdout, stderr) = run(cmd);

    assert_eq!(code, 1, "subagent transcripts are not sessions");
    assert!(stderr.contains("no transcript"), "{stderr}");
}

#[test]
fn an_unreadable_transcript_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = cadence_hooks();
    cmd.args(["metrics", "grade", "--transcript"])
        .arg(dir.path().join("does-not-exist.jsonl"));
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "no partial grading: {stdout}");
    assert!(stderr.contains("cannot read"), "{stderr}");
}

#[test]
fn naming_no_transcript_at_all_says_how_to_name_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = cadence_hooks();
    // Point HOME at an empty dir too, so the ~/.claude fallback finds nothing
    // and this cannot pass by accidentally reading the real config dir.
    cmd.env("HOME", dir.path());
    cmd.args(["metrics", "grade"]);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("--transcript") && stderr.contains("--session-id"),
        "the error names both ways to say which transcript: {stderr}"
    );
}

/// `CADENCE_BYPASS=1` must not silence a CLI action either.
///
/// Bypassed, `grade` exited 0 having printed nothing — and an operator piping
/// it to `jq` reads absent output as "this session had no cold restarts"
/// rather than "the command never ran". That is exactly the failure the
/// fail-closed exit codes exist to prevent, arriving through the one env var
/// whose documented purpose is keeping diagnostic commands working.
#[test]
fn cadence_bypass_does_not_silence_a_cli_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("t.jsonl");
    std::fs::write(&path, TRANSCRIPT).expect("write");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BYPASS", "1");
    cmd.args(["metrics", "grade", "--transcript"]).arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    let g: serde_json::Value =
        serde_json::from_str(&stdout).expect("a bypassed run still prints the grading");
    assert_eq!(g["wallClockMs"], 9_960_000);
}

/// `grade` is a CLI action, not a hook — `CADENCE_DISABLE` must not reach it.
#[test]
fn cadence_disable_does_not_silence_a_cli_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("t.jsonl");
    std::fs::write(&path, TRANSCRIPT).expect("write");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_DISABLE", "grade,metrics,all");
    cmd.args(["metrics", "grade", "--transcript"]).arg(&path);
    let (code, stdout, stderr) = run(cmd);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "still grades: {stdout}"
    );
}
