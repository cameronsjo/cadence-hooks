//! Cross-process (binary-level) integration tests for the model-guard
//! recommended-driver feature (cameronsjo/cadence-hooks — "stronger prose,
//! not teeth"), landing alongside `crates/session/src/persist_plan.rs`'s own
//! extensive inline unit-test module.
//!
//! `persist_plan.rs` follows this crate's inline-`#[cfg(test)]` convention —
//! there is no separate-test-file precedent anywhere under
//! `crates/session/src/`, and the diff under test already carries ~150 lines
//! of inline coverage for `recommended_tier`'s parser priorities, the nudge
//! composition, the v3 `plan-links.jsonl` schema, and the dir-scan-skip
//! repair. Duplicating those as a new source file under `crates/` would just
//! re-express the same in-process unit tests through an unconventional
//! location.
//!
//! What the inline tests do NOT cover is the compiled BINARY's own stdin/
//! stdout contract for this feature: real JSON on stdin, the real
//! `hookSpecificOutput.additionalContext` envelope on stdout, and the CLI
//! surface (`session persist-plan-approval`) a real
//! Claude Code hook invocation actually drives. That is exactly the gap this
//! repo's existing top-level `tests/*.rs` integration suite fills for other
//! hooks (see `tests/session_markers.rs`, `tests/try_hook.rs`), so this file
//! follows that established convention rather than inventing a new one.

use std::io::Write;
use std::process::Command;

fn cadence_hooks(metrics_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    // Sandbox the plan-links.jsonl append so this suite never writes into a
    // real per-user metrics dir (same discipline as tests/session_markers.rs
    // and tests/try_hook.rs's log-skill regression).
    cmd.env("CADENCE_METRICS_DIR", metrics_dir);
    cmd
}

/// Spawn the binary with JSON on stdin and return the completed output. A
/// BrokenPipe on write is expected when the child exits before draining
/// stdin (matches the sibling files' helper).
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

fn init_repo(dir: &std::path::Path) {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("git")
    };
    assert!(git(&["init", "-q", "-b", "main"]).success());
    assert!(git(&["config", "user.email", "t@t"]).success());
    assert!(git(&["config", "user.name", "t"]).success());
    assert!(git(&["commit", "--allow-empty", "-q", "-m", "root"]).success());
}

/// Extract `hookSpecificOutput.additionalContext` from a real (non-`try`)
/// hook invocation's stdout — the raw JSON envelope, not `try`'s decoded
/// human-readable report.
fn additional_context(stdout: &str) -> String {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid hook JSON");
    v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn approval_nudge_carries_the_model_check_directive_for_a_recorded_driver() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let metrics_dir = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "ExitPlanMode",
        "tool_input": {
            "plan": "# Fix The Widget\n\n## Orchestrator\n\n**Driver:** Sonnet — fully spec'd.",
        },
        "tool_response": { "isAgent": false },
        "cwd": repo.path().to_string_lossy(),
        "session_id": "approving-session",
    })
    .to_string();

    let mut cmd = cadence_hooks(metrics_dir.path());
    cmd.args(["session", "persist-plan-approval"]);
    let output = run_with_stdin(cmd, &payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");

    let ctx = additional_context(&stdout);
    assert!(
        ctx.contains("Approved plan persisted to"),
        "a fresh approval persist still carries the persist sentence: {ctx}"
    );
    assert!(
        ctx.contains("This plan's recommended driver is sonnet"),
        "the parsed Driver: tier must reach the real hook's additionalContext: {ctx}"
    );
    assert!(
        ctx.find("Approved plan persisted to").unwrap() < ctx.find("recommended driver").unwrap(),
        "directive lands after the persist sentence: {ctx}"
    );

    let links = std::fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
    assert!(
        links.contains("\"recommended_model\":\"sonnet\""),
        "the v3 row must carry the tier parsed from the real payload: {links}"
    );
}

#[test]
fn approval_nudge_omits_the_directive_when_no_driver_is_recorded() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let metrics_dir = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "ExitPlanMode",
        "tool_input": {
            "plan": "# Fix The Widget\n\n## Goal\n\nDo the thing.",
        },
        "tool_response": { "isAgent": false },
        "cwd": repo.path().to_string_lossy(),
        "session_id": "approving-session-2",
    })
    .to_string();

    let mut cmd = cadence_hooks(metrics_dir.path());
    cmd.args(["session", "persist-plan-approval"]);
    let output = run_with_stdin(cmd, &payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");

    let ctx = additional_context(&stdout);
    assert!(
        ctx.contains("Approved plan persisted to"),
        "still a fresh persist: {ctx}"
    );
    assert!(
        !ctx.contains("recommended driver"),
        "no directive text end to end when the plan carries no recognized Driver: anchor: {ctx}"
    );

    let links = std::fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
    assert!(
        !links.contains("recommended_model"),
        "the v3 row must OMIT recommended_model (never null) when unparsed: {links}"
    );
    assert!(
        links.contains("\"schemaVersion\":3"),
        "the row must still stamp schema v3: {links}"
    );
}

#[test]
fn approval_from_a_subagent_never_persists_regardless_of_driver_tier() {
    // Regression guard: `isAgent: true` must still skip the whole persist —
    // the new tier-parsing/nudge-composition code must not accidentally
    // bypass this pre-existing gate on its way to computing a directive.
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let metrics_dir = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "ExitPlanMode",
        "tool_input": {
            "plan": "# Fix The Widget\n\n## Orchestrator\n\n**Driver:** Opus — escalated.",
        },
        "tool_response": { "isAgent": true },
        "cwd": repo.path().to_string_lossy(),
        "session_id": "subagent-session",
    })
    .to_string();

    let mut cmd = cadence_hooks(metrics_dir.path());
    cmd.args(["session", "persist-plan-approval"]);
    let output = run_with_stdin(cmd, &payload);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.trim().is_empty() || additional_context(&stdout).is_empty(),
        "a subagent approval must not nudge at all: {stdout}"
    );
    assert!(
        !repo.path().join("docs/plans").exists(),
        "a subagent approval must never write a plan doc"
    );
}
