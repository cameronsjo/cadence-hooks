//! Binary-level contract for `session lint-plan-shape` — the call-side
//! plan-shape gate on `PreToolUse:ExitPlanMode` (the plan-shape-gate plan,
//! 2026-08-23; the persist-time lint in cadence-hooks#675 sees the plan only
//! after approval, so it could not stop the operator reading a wrong-shaped
//! plan).
//!
//! Every case feeds a JSON **fixture file** under `tests/fixtures/plan_shape/`
//! (not an inline escape) so the same payloads double as the wiring PR's
//! smoke inputs: `cadence-hooks session lint-plan-shape < <fixture>; echo $?`.
//!
//! The decision table under test:
//!
//! | payload | verdict |
//! |---|---|
//! | top-level, harness-template plan (no `Panel:` line) | exit 2, stderr names the three stanzas + the in-band escape |
//! | top-level, template-shaped plan | exit 0, reminders-only nudge (subagents stopped, operator asked) |
//! | top-level, `Panel: none — reason`, no checkbox tasks | exit 0, one nudge sentence + the reminders |
//! | subagent-originated (`agent_id` present), harness-template plan | exit 0, silent |
//! | empty `tool_input`, no plan path | exit 0, silent (fail-open, ADR-0001) |
//! | no inline plan, `planFilePath` inside the plan store | read through the bounded reader; judged |
//! | no inline plan, `planFilePath` OUTSIDE the plan store | exit 0, silent (never read) |

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/plan_shape")
        .join(name)
}

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    cmd.args(["session", "lint-plan-shape"]);
    cmd
}

/// Spawn the binary with the fixture's bytes on stdin.
fn run_fixture(name: &str) -> Output {
    run_with_stdin(
        cadence_hooks(),
        &std::fs::read_to_string(fixture(name)).unwrap(),
    )
}

fn run_with_stdin(mut cmd: Command, input: &str) -> Output {
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

fn additional_context(stdout: &str) -> String {
    if stdout.trim().is_empty() {
        return String::new();
    }
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid hook JSON");
    v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

const SUBAGENTS_REMINDER: &str = "Make sure all your subagents have stopped.";
const OPERATOR_ASK_REMINDER: &str = "Did your operator ask to see the plan?";

fn assert_silent_allow(out: &Output, case: &str) {
    assert_eq!(out.status.code(), Some(0), "{case}: expected exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.trim().is_empty(),
        "{case}: stderr must be empty, got {stderr}"
    );
    let ctx = additional_context(&String::from_utf8_lossy(&out.stdout));
    assert!(ctx.is_empty(), "{case}: expected no nudge, got {ctx}");
}

#[test]
fn harness_template_plan_is_blocked_naming_stanzas_and_escape() {
    let out = run_fixture("epm-harness-template.json");
    assert_eq!(
        out.status.code(),
        Some(2),
        "harness-template plan must block"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("a settled Panel: line"), "stderr: {stderr}");
    assert!(
        stderr.contains("an Alternatives-declined stanza"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("checkbox tasks"), "stderr: {stderr}");
    assert!(
        stderr.contains("Panel: none — <reason>"),
        "escape template: {stderr}"
    );
    assert!(
        stderr.contains("shift-tab"),
        "leave-plan-mode escape: {stderr}"
    );
    assert!(
        stderr.contains(SUBAGENTS_REMINDER) && stderr.contains(OPERATOR_ASK_REMINDER),
        "the block carries both presentation reminders: {stderr}"
    );
    // The message renders as one clean paragraph — a hand-wrapped literal that
    // leaked its indentation once shipped green past the substring asserts.
    assert!(!stderr.contains("  "), "no double spaces: {stderr}");
    // Static names only — never matched plan text (cadence-hooks#715).
    assert!(
        !stderr.contains("widget"),
        "plan text must never be echoed: {stderr}"
    );
    assert!(
        !stderr.contains("## Context"),
        "plan text must never be echoed: {stderr}"
    );
}

#[test]
fn template_shaped_plan_nudges_the_presentation_reminders_only() {
    let out = run_fixture("epm-template-shaped.json");
    assert_eq!(
        out.status.code(),
        Some(0),
        "template-shaped plan must allow"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.trim().is_empty(),
        "a nudge rides stdout, not stderr: {stderr}"
    );
    let ctx = additional_context(&String::from_utf8_lossy(&out.stdout));
    assert!(
        ctx.contains(SUBAGENTS_REMINDER) && ctx.contains(OPERATOR_ASK_REMINDER),
        "the clean-plan nudge carries both presentation reminders: {ctx}"
    );
    assert!(
        !ctx.contains("lacks"),
        "a template-shaped plan draws no missing-stanza text: {ctx}"
    );
}

#[test]
fn settled_panel_none_with_no_boxes_nudges_once_and_allows() {
    let out = run_fixture("epm-panel-none-no-boxes.json");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.trim().is_empty(),
        "a nudge rides stdout, not stderr: {stderr}"
    );
    let ctx = additional_context(&String::from_utf8_lossy(&out.stdout));
    assert!(
        ctx.contains("checkbox tasks"),
        "nudge names the missing stanza: {ctx}"
    );
    assert!(
        !ctx.contains("a settled Panel: line"),
        "Panel line is settled: {ctx}"
    );
    assert!(
        !ctx.contains("an Alternatives-declined stanza"),
        "alternatives present: {ctx}"
    );
    assert_eq!(
        ctx.matches("plan-shape gate:").count(),
        1,
        "one composed line, not one per stanza: {ctx}"
    );
    assert!(
        ctx.contains("the plan template: `cadence:arrange` `references/plan-template.md`."),
        "the nudge names the template's home: {ctx}"
    );
    assert!(
        ctx.contains(SUBAGENTS_REMINDER) && ctx.ends_with(OPERATOR_ASK_REMINDER),
        "the stanza nudge ends with the presentation reminders: {ctx}"
    );
}

#[test]
fn subagent_call_with_harness_template_plan_is_exempt() {
    let out = run_fixture("epm-subagent-harness-template.json");
    assert_silent_allow(&out, "subagent");
}

#[test]
fn empty_tool_input_without_plan_path_fails_open_silently() {
    let out = run_fixture("epm-empty-tool-input.json");
    assert_silent_allow(&out, "empty tool_input");
}

/// `CLAUDE_CONFIG_DIR` roots the plan store at `<dir>/plans`; a
/// `planFilePath` inside it is read (bounded, containment-checked) when the
/// inline `tool_input.plan` is absent, and judged like inline text.
#[test]
fn plan_file_path_inside_the_plan_store_is_read_and_judged() {
    let cfg = tempfile::tempdir().unwrap();
    let plans = cfg.path().join("plans");
    std::fs::create_dir_all(&plans).unwrap();
    let plan_path = plans.join("harness.md");
    std::fs::copy(fixture("plan-store-harness-template.md"), &plan_path).unwrap();
    let payload = serde_json::json!({
        "session_id": "test",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "ExitPlanMode",
        "tool_input": {"planFilePath": plan_path.to_string_lossy()},
    })
    .to_string();
    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", cfg.path());
    let out = run_with_stdin(cmd, &payload);
    assert_eq!(
        out.status.code(),
        Some(2),
        "plan-store harness plan must block"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("a settled Panel: line"), "stderr: {stderr}");
}

#[test]
fn plan_file_path_outside_the_plan_store_is_never_read() {
    let cfg = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cfg.path().join("plans")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let plan_path = outside.path().join("harness.md");
    std::fs::copy(fixture("plan-store-harness-template.md"), &plan_path).unwrap();
    let payload = serde_json::json!({
        "session_id": "test",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "ExitPlanMode",
        "tool_input": {"planFilePath": plan_path.to_string_lossy()},
    })
    .to_string();
    let mut cmd = cadence_hooks();
    cmd.env("CLAUDE_CONFIG_DIR", cfg.path());
    let out = run_with_stdin(cmd, &payload);
    assert_silent_allow(&out, "out-of-store planFilePath");
}

/// A non-`ExitPlanMode` tool name on the same subcommand is a no-op — the
/// hooks.json matcher is the real gate, this is the binary-side belt.
#[test]
fn other_tool_names_are_ignored() {
    let payload = r#"{"session_id":"test","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let out = run_with_stdin(cadence_hooks(), payload);
    assert_silent_allow(&out, "non-ExitPlanMode tool");
}
