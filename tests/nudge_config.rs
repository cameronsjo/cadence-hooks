//! End-to-end: the `nudges` map and `feedbackFooter` of `.claude/cadence.json`
//! (cameronsjo/cadence-hooks#216, ADR-0002 §3).
//!
//! The nudge under test is `warn-plugin-root-cruft` (advisory, path-scoped, and
//! deterministic from files alone). The block under test is `git-safety`.

mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

/// A git-root tempdir declaring plugin `foo` in its marketplace manifest, with
/// `cadence_json` (when given) as `.claude/cadence.json`.
fn repo(cadence_json: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    std::fs::create_dir(dir.path().join(".claude-plugin")).unwrap();
    std::fs::write(
        dir.path().join(".claude-plugin/marketplace.json"),
        r#"{"plugins":[{"source":"./plugins/foo"}]}"#,
    )
    .unwrap();
    if let Some(body) = cadence_json {
        std::fs::create_dir(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/cadence.json"), body).unwrap();
    }
    dir
}

fn run(dir: &std::path::Path, args: &[&str], payload: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd: Command = support::cadence_hooks();
    for var in [
        "CADENCE_BYPASS",
        "CADENCE_DISABLE",
        "CADENCE_ALLOW_MAIN",
        "CADENCE_NO_FEEDBACK_FOOTER",
        "CLAUDECODE",
    ] {
        cmd.env_remove(var);
    }
    cmd.args(args)
        .current_dir(dir)
        .env("CADENCE_METRICS_DIR", scratch_metrics_dir())
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(payload.as_bytes());
    child.wait_with_output().unwrap()
}

fn write_payload(dir: &std::path::Path, rel: &str) -> String {
    serde_json::json!({
        "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Write",
        "cwd": dir, "tool_input": {"file_path": dir.join(rel), "content": "x"},
    })
    .to_string()
}

fn cruft(dir: &std::path::Path, rel: &str, env: &[(&str, &str)]) -> (i32, String) {
    let out = run(
        dir,
        &["cadence", "warn-plugin-root-cruft"],
        &write_payload(dir, rel),
        env,
    );
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

const CRUFT_PATH: &str = "plugins/foo/docs/plan.md";

#[test]
fn baseline_nudges_without_a_config() {
    let dir = repo(None);
    let (code, stdout) = cruft(dir.path(), CRUFT_PATH, &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("plugin-runtime-only"),
        "expected the nudge: {stdout}"
    );
}

#[test]
fn config_suppresses_by_boolean_and_by_glob() {
    let rows: &[(&str, &str, bool)] = &[
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":true}}}"#,
            CRUFT_PATH,
            true,
        ),
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":["plugins/foo/docs/**"]}}}"#,
            CRUFT_PATH,
            true,
        ),
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":["*.md"]}}}"#,
            CRUFT_PATH,
            true,
        ),
        // the glob scopes it: a non-matching glob leaves the nudge live
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":["plugins/bar/**"]}}}"#,
            CRUFT_PATH,
            false,
        ),
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":["docs/**"]}}}"#,
            CRUFT_PATH,
            false,
        ),
        (
            r#"{"nudges":{"warn-plugin-root-cruft":{"suppress":false}}}"#,
            CRUFT_PATH,
            false,
        ),
        // another hook's entry does not silence this one
        (
            r#"{"nudges":{"warn-overshare":{"suppress":true}}}"#,
            CRUFT_PATH,
            false,
        ),
    ];
    for (cfg, rel, suppressed) in rows {
        let dir = repo(Some(cfg));
        let (code, stdout) = cruft(dir.path(), rel, &[]);
        assert_eq!(code, 0, "{cfg}");
        assert_eq!(stdout.trim().is_empty(), *suppressed, "{cfg}: {stdout}");
    }
}

/// Malformed config never blocks and never suppresses: the nudge stays live.
#[test]
fn malformed_config_fails_open_and_keeps_the_nudge() {
    for cfg in [
        "{not json",
        "[]",
        r#"{"nudges": []}"#,
        r#"{"nudges": {"warn-plugin-root-cruft": {"suppress": "yes"}}}"#,
        r#"{"nudges": {"warn-plugin-root-cruft": 7}}"#,
        r#"{"nudges": {"warn-plugin-root-cruft": {"suppress": ["[oops"]}}}"#,
    ] {
        let dir = repo(Some(cfg));
        let (code, stdout) = cruft(dir.path(), CRUFT_PATH, &[]);
        assert_eq!(code, 0, "{cfg}");
        assert!(stdout.contains("plugin-runtime-only"), "{cfg}: {stdout}");
    }
}

/// The existing env toggles keep working alongside a config that does not
/// suppress (env OR config suppresses), and a config that suppresses is
/// unaffected by their absence.
#[test]
fn env_and_config_are_additive() {
    let dir = repo(Some(r#"{"nudges":{"warn-overshare":{"suppress":true}}}"#));
    // the env-only hook toggle: CADENCE_DISABLE still switches the nudge off
    let out = run(
        dir.path(),
        &["cadence", "warn-plugin-root-cruft"],
        &write_payload(dir.path(), CRUFT_PATH),
        &[("CADENCE_DISABLE", "warn-plugin-root-cruft")],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

/// A config entry naming a block never silences it — a protected guard, and a
/// blocking hook that is not protected alike.
#[test]
fn config_cannot_silence_a_block() {
    let cfg = r#"{"nudges":{"git-safety":{"suppress":true},"terminology":{"suppress":true},
                 "prevent-secret-writes":{"suppress":true}}}"#;
    let dir = repo(Some(cfg));
    let payload = serde_json::json!({
        "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "cwd": dir.path(), "tool_input": {"command": "git reset --hard HEAD~5"},
    })
    .to_string();
    let with = run(dir.path(), &["cadence", "git-safety"], &payload, &[]);
    let plain = repo(None);
    let without = run(plain.path(), &["cadence", "git-safety"], &payload, &[]);
    assert_eq!(
        with.status.code(),
        without.status.code(),
        "config must not change a block's verdict"
    );
    assert_eq!(
        without.status.code(),
        Some(2),
        "fixture must actually block"
    );
}

#[test]
fn feedback_footer_config_and_env() {
    let payload = |dir: &std::path::Path| {
        serde_json::json!({
            "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "cwd": dir, "tool_input": {"command": "git reset --hard HEAD~5"},
        })
        .to_string()
    };
    type Row<'a> = (Option<&'a str>, &'a [(&'a str, &'a str)], bool);
    let rows: &[Row] = &[
        (None, &[], true),
        (Some(r#"{"feedbackFooter": true}"#), &[], true),
        (Some(r#"{"feedbackFooter": false}"#), &[], false),
        (Some(r#"{"feedbackFooter": "off"}"#), &[], true),
        (None, &[("CADENCE_NO_FEEDBACK_FOOTER", "1")], false),
        (
            Some(r#"{"feedbackFooter": true}"#),
            &[("CADENCE_NO_FEEDBACK_FOOTER", "1")],
            false,
        ),
    ];
    for (cfg, env, shown) in rows {
        let dir = repo(*cfg);
        let out = run(
            dir.path(),
            &["cadence", "git-safety"],
            &payload(dir.path()),
            env,
        );
        assert_eq!(out.status.code(), Some(2), "{cfg:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            stderr.contains("/cadence:feedback"),
            *shown,
            "{cfg:?} {env:?}: {stderr}"
        );
    }
}
