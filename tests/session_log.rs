//! Integration tests for `metrics log-session` — the `sessions.jsonl` writer
//! that fires at `SessionEnd` (O3).
//!
//! The binary is spawned as a child process with `CADENCE_METRICS_DIR` pointed
//! at a per-test tempdir, so the write lands nowhere real and the env override
//! is isolated (never touches the test runner's process-global env).

mod support;

use std::io::Write;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = support::cadence_hooks();
    // Don't inherit env that would re-price the logger.
    cmd.env_remove("CLAUDECODE");
    cmd.env_remove("CADENCE_METRICS_PRICES");
    cmd
}

/// Spawn the binary with JSON on stdin and return the completed output.
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

/// Build a SessionEnd payload with **structural** JSON escaping.
///
/// The transcript path is a tempdir path — on Windows that's `C:\Users\...`,
/// whose backslashes are invalid JSON escapes. Interpolating it into a raw
/// string template with `format!` would produce unparseable JSON, `MetricsInput`
/// would fail to deserialize, and the logger would silently fail open (no row).
/// Building the payload with `serde_json::json!` escapes the path correctly on
/// every platform (#170).
fn session_payload(
    session_id: &str,
    event: &str,
    transcript: &std::path::Path,
    reason: Option<&str>,
) -> String {
    let mut obj = serde_json::json!({
        "session_id": session_id,
        "hook_event_name": event,
        "transcript_path": transcript.to_string_lossy(),
        "cwd": "/tmp",
    });
    if let Some(r) = reason {
        obj["reason"] = serde_json::Value::String(r.to_string());
    }
    obj.to_string()
}

/// A transcript with two priced assistant messages. Written to `path`.
fn write_transcript(path: &std::path::Path) {
    let transcript = [
        r#"{"type":"user","message":{"role":"user","content":"hi"}}"#,
        r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":1000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":100}}}"#,
        r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":2000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":200}}}"#,
    ]
    .join("\n");
    std::fs::write(path, transcript).expect("write transcript");
}

// ── RED-first: no row without a SessionEnd event ─────────────────────────

#[test]
fn non_session_end_event_writes_no_row() {
    // The gate: a PostToolUse payload (wrong event) must not write a session
    // row. This is the RED assertion — the absence the writer must respect.
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-1", "PostToolUse", &transcript, None);
    let output = run_with_stdin(cmd, &payload);

    assert_eq!(output.status.code(), Some(0), "loggers always exit 0");
    assert!(
        !dir.path().join("sessions.jsonl").exists(),
        "no row for a non-SessionEnd event"
    );
}

// ── GREEN: one row at SessionEnd, with the full schema ───────────────────

#[test]
fn session_end_writes_one_priced_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload(
        "sess-1",
        "SessionEnd",
        &transcript,
        Some("prompt_input_exit"),
    );
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0), "loggers always exit 0");

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl"))
        .expect("sessions.jsonl must exist after SessionEnd");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "exactly one row, got: {contents}");

    let row: serde_json::Value = serde_json::from_str(lines[0]).expect("row parses as JSON");
    assert_eq!(row["sessionId"], "sess-1");
    assert_eq!(row["reason"], "prompt_input_exit");
    assert_eq!(row["model"], "claude-opus-4-7");
    // tokens == whole-transcript sum (m1 + m2).
    assert_eq!(row["tokens"]["input"], 3000);
    assert_eq!(row["tokens"]["output"], 300);
    assert_eq!(row["messagesScanned"], 2);
    // A priced model → positive cost, non-empty byModel, empty unpricedModels.
    assert!(
        row["costUsd"].as_f64().unwrap() > 0.0,
        "priced model costs > 0"
    );
    assert!(!row["byModel"].as_array().unwrap().is_empty());
    assert!(row["unpricedModels"].as_array().unwrap().is_empty());
}

#[test]
fn unpriced_model_lands_in_unpriced_never_silently_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    // `gpt-9` is absent from the embedded price table (#95).
    std::fs::write(
        &transcript,
        r#"{"message":{"id":"m1","role":"assistant","model":"gpt-9","usage":{"input_tokens":100,"output_tokens":10}}}"#,
    )
    .expect("write transcript");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-2", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    let unpriced = row["unpricedModels"].as_array().unwrap();
    assert_eq!(unpriced.len(), 1);
    assert_eq!(unpriced[0], "gpt-9");
    assert!(row["reason"].is_null(), "absent reason → null");
}

// ── Session bounds: log-session-start / log-session round trip (#182) ────

/// Build a SessionStart payload for `metrics log-session-start`.
fn session_start_payload(session_id: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "hook_event_name": "SessionStart",
        "cwd": "/tmp",
    })
    .to_string()
}

#[test]
fn session_start_then_end_round_trip_computes_duration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    let mut start_cmd = cadence_hooks();
    start_cmd.env("CADENCE_METRICS_DIR", dir.path());
    start_cmd.args(["metrics", "log-session-start"]);
    let start_output = run_with_stdin(start_cmd, &session_start_payload("sess-bounds"));
    assert_eq!(start_output.status.code(), Some(0), "loggers always exit 0");

    let mut end_cmd = cadence_hooks();
    end_cmd.env("CADENCE_METRICS_DIR", dir.path());
    end_cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-bounds", "SessionEnd", &transcript, None);
    let end_output = run_with_stdin(end_cmd, &payload);
    assert_eq!(end_output.status.code(), Some(0), "loggers always exit 0");

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl"))
        .expect("sessions.jsonl must exist after SessionEnd");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("row parses as JSON");
    assert!(row["startTs"].is_string(), "startTs should be stamped");
    assert!(row["endTs"].is_string(), "endTs should be stamped");
    assert!(
        row["durationMs"].as_i64().unwrap() >= 0,
        "durationMs should be a non-negative number: {row}"
    );

    // The `.start` marker is consumed — a second SessionEnd for the same
    // session must not see a stale duration.
    assert!(
        !dir.path().join("state").join("sess-bounds.start").exists(),
        "start marker must be consumed"
    );
}

#[test]
fn session_end_without_start_marker_has_null_bounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // No log-session-start ran for this session — SessionEnd fires on its own.
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-no-start", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    assert!(row["startTs"].is_null(), "no marker → startTs null");
    assert!(row["durationMs"].is_null(), "no marker → durationMs null");
    assert!(row["endTs"].is_string(), "endTs is always stamped");
    assert_eq!(row["commits"], 0, "no commits.jsonl → commits 0");
}

#[test]
fn session_end_counts_commits_for_this_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // Seed commits.jsonl with 2 rows for this session and 1 for another.
    let commits_jsonl = [
        r#"{"sessionId":"sess-commits"}"#,
        r#"{"sessionId":"other-session"}"#,
        r#"{"sessionId":"sess-commits"}"#,
    ]
    .join("\n");
    std::fs::write(dir.path().join("commits.jsonl"), commits_jsonl).expect("seed commits.jsonl");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-commits", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    assert_eq!(row["commits"], 2, "only this session's commit rows count");
}

/// cadence-hooks#1589: a session started under this binary has a commit
/// counter, and SessionEnd takes its count from it, not from the ledger. The
/// seeded ledger rows would say 2; the counter says 0, and wins. The counter
/// is removed once read.
#[test]
fn session_end_counts_commits_from_the_counter_not_the_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);
    let ledger = [
        r#"{"sessionId":"sess-counted"}"#,
        r#"{"sessionId":"sess-counted"}"#,
    ]
    .join("\n");
    std::fs::write(dir.path().join("commits.jsonl"), ledger).expect("seed commits.jsonl");

    for (sub, event) in [
        ("log-session-start", "SessionStart"),
        ("log-session", "SessionEnd"),
    ] {
        let payload = with_source(
            &session_payload("sess-counted", event, &transcript, None),
            "startup",
        );
        run_metrics(dir.path(), sub, &payload);
    }

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("row written");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("parse");
    assert_eq!(row["commits"], 0, "the counter, not the ledger, decides");
    assert!(
        !dir.path().join("state/commits/sess-counted").exists(),
        "SessionEnd removes the counter it read"
    );
}

fn with_source(payload: &str, source: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(payload).expect("payload json");
    v["source"] = serde_json::Value::String(source.into());
    v.to_string()
}

fn run_metrics(metrics: &std::path::Path, sub: &str, payload: &str) {
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", metrics);
    cmd.args(["metrics", sub]);
    assert_eq!(run_with_stdin(cmd, payload).status.code(), Some(0), "{sub}");
}

/// A resume after SessionEnd gets no counter, so its commit count comes from
/// the ledger and still includes the commits made before the resume.
#[test]
fn a_resumed_session_counts_its_earlier_commits_from_the_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);
    let start = |src: &str| {
        with_source(
            &session_payload("sess-resumed", "SessionStart", &transcript, None),
            src,
        )
    };
    let end = session_payload("sess-resumed", "SessionEnd", &transcript, None);
    run_metrics(dir.path(), "log-session-start", &start("startup"));
    run_metrics(dir.path(), "log-session", &end);
    // Two commits landed in the ledger before the resume.
    let ledger = [
        r#"{"sessionId":"sess-resumed"}"#,
        r#"{"sessionId":"sess-resumed"}"#,
    ]
    .join("\n");
    std::fs::write(dir.path().join("commits.jsonl"), ledger).expect("seed commits.jsonl");
    run_metrics(dir.path(), "log-session-start", &start("resume"));
    assert!(
        !dir.path().join("state/commits/sess-resumed").exists(),
        "a resume starts no counter"
    );
    run_metrics(dir.path(), "log-session", &end);
    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl")).expect("rows");
    let last: serde_json::Value =
        serde_json::from_str(contents.lines().last().unwrap()).expect("parse");
    assert_eq!(last["commits"], 2, "the pre-resume commits still count");
}

/// A scratch repo with one commit; returns its HEAD. Isolated from the
/// operator's git config.
fn git_repo(dir: &std::path::Path) -> String {
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@invalid")
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    std::fs::create_dir_all(dir).unwrap();
    git(&["init", "-q"]);
    git(&["commit", "-q", "--allow-empty", "-m", "one"]);
    git(&["rev-parse", "HEAD"])
}

/// Land a second commit in `repo` with `before` as the snapshot, then run
/// `log-commit` for `session`.
fn commit_and_log(
    metrics: &std::path::Path,
    repo: &std::path::Path,
    session: &str,
    transcript: &std::path::Path,
) {
    let before = git_repo_head(repo);
    let state = metrics.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join(format!("{session}.before")), &before).unwrap();
    let status = std::process::Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "two",
        ])
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@invalid")
        .status()
        .expect("git commit");
    assert!(status.success());
    let payload = serde_json::json!({
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m two"},
        "transcript_path": transcript.to_string_lossy(),
        "cwd": repo.to_string_lossy(),
    })
    .to_string();
    run_metrics(metrics, "log-commit", &payload);
}

fn git_repo_head(repo: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit_rows(metrics: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(metrics.join("commits.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("row"))
        .collect()
}

/// With a counter, log-commit resumes from the counter's `last`, not from the
/// ledger: `last` says m1 and the ledger says m2, and the new row's
/// `sinceMarker` is m1. The commit then bumps the counter and moves `last`.
#[test]
fn log_commit_resumes_from_the_counter_not_the_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (metrics, repo) = (dir.path().join("metrics"), dir.path().join("repo"));
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);
    git_repo(&repo);
    let start = with_source(
        &session_payload("sess-c", "SessionStart", &transcript, None),
        "startup",
    );
    run_metrics(&metrics, "log-session-start", &start);
    std::fs::write(metrics.join("state/commits/sess-c/last"), "m1").unwrap();
    std::fs::write(
        metrics.join("commits.jsonl"),
        "{\"sessionId\":\"sess-c\",\"lastMessageId\":\"m2\"}\n",
    )
    .unwrap();
    commit_and_log(&metrics, &repo, "sess-c", &transcript);
    let rows = commit_rows(&metrics);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[1]["sinceMarker"], "m1");
    let count = std::fs::metadata(metrics.join("state/commits/sess-c/count"))
        .unwrap()
        .len();
    assert_eq!(count, 1);
    assert_eq!(
        std::fs::read_to_string(metrics.join("state/commits/sess-c/last")).unwrap(),
        "m2"
    );
}

/// Without a counter (a session from before the upgrade), log-commit resumes
/// from the ledger and creates no counter.
#[test]
fn log_commit_without_a_counter_uses_the_ledger_and_creates_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (metrics, repo) = (dir.path().join("metrics"), dir.path().join("repo"));
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);
    git_repo(&repo);
    std::fs::create_dir_all(&metrics).unwrap();
    std::fs::write(
        metrics.join("commits.jsonl"),
        "{\"sessionId\":\"sess-old\",\"lastMessageId\":\"m1\"}\n",
    )
    .unwrap();
    commit_and_log(&metrics, &repo, "sess-old", &transcript);
    let rows = commit_rows(&metrics);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[1]["sinceMarker"], "m1");
    assert!(!metrics.join("state/commits/sess-old").exists());
}

/// A row that fails to write leaves the counter where it was.
#[test]
fn a_failed_commit_row_leaves_the_counter_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (metrics, repo) = (dir.path().join("metrics"), dir.path().join("repo"));
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);
    git_repo(&repo);
    let start = with_source(
        &session_payload("sess-f", "SessionStart", &transcript, None),
        "startup",
    );
    run_metrics(&metrics, "log-session-start", &start);
    std::fs::create_dir_all(metrics.join("commits.jsonl")).unwrap();
    commit_and_log(&metrics, &repo, "sess-f", &transcript);
    let count = std::fs::metadata(metrics.join("state/commits/sess-f/count"))
        .unwrap()
        .len();
    assert_eq!(count, 0);
}

// ── Fail-open: an unwritable metrics dir never perturbs the exit code ─────

#[test]
fn unwritable_metrics_dir_fails_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_transcript(&transcript);

    // Point CADENCE_METRICS_DIR at a *file* — create_dir_all fails, the write
    // is skipped, and the logger still exits 0 without panicking.
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, "x").expect("write blocker file");

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", &blocker);
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-3", "SessionEnd", &transcript, None);
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0), "fail-open: still exits 0");
}

// ── The grading key (cadence-ecosystem#524) ──────────────────────────────

/// A transcript with two real gaps: one under the cache TTL and one over it.
///
/// The timestamps are what make this a grading fixture rather than a token
/// one — `write_transcript` above carries none, so it grades to all zeroes and
/// could not tell a working grader from a stubbed one.
fn write_timestamped_transcript(path: &std::path::Path) {
    let transcript = [
        r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"role":"user","content":"hi"}}"#,
        // 46 minutes: a gap, but under the 1h TTL, so a measured zero.
        r#"{"type":"assistant","timestamp":"2020-01-01T00:46:00Z","message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":1000,"cache_creation_input_tokens":500000,"cache_read_input_tokens":0,"output_tokens":100}}}"#,
        // 2 hours: over the TTL, restarting on a priced model.
        r#"{"type":"assistant","timestamp":"2020-01-01T02:46:00Z","message":{"id":"m2","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":2000,"cache_creation_input_tokens":1000000,"cache_read_input_tokens":0,"output_tokens":200}}}"#,
    ]
    .join("\n");
    std::fs::write(path, transcript).expect("write transcript");
}

#[test]
fn session_end_row_carries_a_grading() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transcript = dir.path().join("transcript.jsonl");
    write_timestamped_transcript(&transcript);

    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_METRICS_DIR", dir.path());
    cmd.args(["metrics", "log-session"]);
    let payload = session_payload("sess-grade", "SessionEnd", &transcript, Some("clear"));
    let output = run_with_stdin(cmd, &payload);
    assert_eq!(output.status.code(), Some(0), "loggers always exit 0");

    let contents = std::fs::read_to_string(dir.path().join("sessions.jsonl"))
        .expect("sessions.jsonl must exist after SessionEnd");
    let row: serde_json::Value =
        serde_json::from_str(contents.lines().next().expect("one row")).expect("row parses");

    // Additive — the version does not move for a new key.
    assert_eq!(row["schemaVersion"], 2, "additive fields do not bump");

    let g = &row["grading"];
    assert!(
        g.is_object(),
        "grading is always an object, never null: {row}"
    );
    assert_eq!(g["wallClockMs"], 9_960_000, "00:00:00 -> 02:46:00");
    assert_eq!(g["gaps"].as_array().expect("gaps array").len(), 2);
    assert_eq!(
        g["gaps"][0]["coldRestartUsd"], 0.0,
        "46 minutes is under the TTL — a measured zero, not a null"
    );
    // 1,000,000 tokens x (10.00 - 0.50) / 1e6 = 9.50, at the embedded rates.
    assert_eq!(g["gaps"][1]["coldRestartUsd"], 9.5);
    assert_eq!(g["coldRestartUsdTotal"], 9.5);
    assert_eq!(g["assistantTurns"], 2);
    assert_eq!(g["userPrompts"], 1);
    assert_eq!(g["flags"]["afkGap"], true);
    assert_eq!(g["flags"]["coldRestart"], true);
    assert_eq!(g["config"]["grindTurnsPerPrompt"], 30.0);

    // The invariant that outranks every field above.
    assert!(
        !contents.contains("\"hi\""),
        "no prompt text may reach a metrics record: {contents}"
    );
}
