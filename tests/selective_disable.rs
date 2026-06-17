//! Integration tests for CADENCE_DISABLE selective hook disabling
//! and the `list` subcommand.
//!
//! Verifies that individual hooks can be skipped via the env var, while
//! non-listed hooks still run normally.

use std::io::Write;
use std::process::Command;

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // Ensure tests don't inherit env vars from the test runner's session
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CLAUDECODE");
    cmd
}

/// Spawns the binary with JSON on stdin and returns the completed output.
///
/// A child that decides its outcome without reading stdin (a bypassed or
/// disabled hook exits immediately) may close the pipe before the write
/// completes — that BrokenPipe is expected, not a test failure (#59).
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

#[test]
fn disabled_hook_exits_zero() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "terminology");

    // Even without valid stdin, a disabled hook should exit 0 before reading input.
    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "disabled hook should exit 0 (allow).\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn disabled_advisory_hook_exits_zero_with_notice() {
    // An advisory (non-protected) hook disabled via CADENCE_DISABLE exits 0
    // before reading stdin and produces no stdout — but now leaves a one-line
    // stderr notice so the suppression is always traceable (#89). (Was
    // `disabled_hook_produces_no_output`, which asserted silent disable of the
    // protected git-safety guard — the bug #89 fixes.)
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "line-endings"]);
    cmd.env("CADENCE_DISABLE", "line-endings");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "disabled hook should produce no stdout"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("disabled via CADENCE_DISABLE"),
        "disabling an advisory hook must leave a trace: {stderr}"
    );
}

#[test]
fn comma_separated_list_disables_multiple() {
    // line-endings is advisory (not protected), so it actually disables.
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "line-endings"]);
    cmd.env("CADENCE_DISABLE", "terminology,line-endings,orphaned-todos");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "hook in comma-separated disable list should exit 0"
    );
}

#[test]
fn spaces_around_commas_tolerated() {
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "line-endings"]);
    cmd.env(
        "CADENCE_DISABLE",
        "terminology , line-endings , orphaned-todos",
    );

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "should tolerate spaces around commas in disable list"
    );
}

#[test]
fn non_disabled_hook_still_runs() {
    let input = r#"{"tool_name":"Write","tool_input":{"file_path":"test.txt","content":"hello"}}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "git-safety,line-endings");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "non-disabled hook should still run (and allow clean input).\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_var_unset_does_not_disable() {
    let input = r#"{}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env_remove("CADENCE_DISABLE");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "hook should run normally when env var is unset.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn empty_env_var_does_not_disable() {
    let input = r#"{}"#;

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "terminology"]);
    cmd.env("CADENCE_DISABLE", "");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "empty disable list should not affect hook execution.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn partial_name_match_does_not_disable() {
    let input = r#"{}"#;

    // "git" is a substring of "git-safety" but not an exact match
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "git");

    let output = run_with_stdin(cmd, input);

    assert_eq!(
        output.status.code(),
        Some(0),
        "partial name match should not disable the hook.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guardrails_hook_can_be_disabled() {
    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "warn-main-branch"]);
    cmd.env("CADENCE_DISABLE", "warn-main-branch");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "guardrails hook should be disableable too"
    );
}

#[test]
fn obsidian_trash_guard_disable_refused() {
    // trash-guard is a protected (data-loss) guard: CADENCE_DISABLE must NOT
    // silently neuter it. Feed a vault-targeting `rm` and assert it STILL blocks
    // (exit 2) despite the disable — proving the guard actually engaged, not
    // merely that it didn't short-circuit (#89). (An exit-code-1 check on an
    // empty-stdin invocation can't catch a silent-disable regression: the guard
    // fails open to exit 0 on EOF per ADR-0001, same code a "disabled" path
    // would return. A real payload + exit-2 is the unambiguous proof it ran.)
    // (Was `obsidian_hook_can_be_disabled`, asserting silent disable.)
    let mut cmd = cadence_hooks();
    cmd.args(["obsidian", "trash-guard"]);
    cmd.env("CADENCE_DISABLE", "trash-guard");
    cmd.env("OBSIDIAN_VAULT", "/vault");
    let output = run_with_stdin(
        cmd,
        r#"{"tool_name":"Bash","tool_input":{"command":"rm /vault/notes/todo.md"}}"#,
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "protected trash-guard must still block a vault rm despite CADENCE_DISABLE.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to disable protected guard"),
        "protected guard disable must be refused with a notice: {stderr}"
    );
    assert!(stderr.contains("trash-guard"));
}

#[test]
fn protected_guard_cannot_be_disabled_via_cadence_disable() {
    // git-safety is protected: naming it in CADENCE_DISABLE must NOT skip it.
    // Feed the dangerous payload and assert it STILL blocks (exit 2) — proving
    // the guard actually engaged, not merely that it didn't short-circuit (#89).
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("CADENCE_DISABLE", "git-safety");
    let output = run_with_stdin(
        cmd,
        r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~3"}}"#,
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "protected git-safety must still block despite CADENCE_DISABLE"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to disable protected guard"));
    assert!(stderr.contains("git-safety"));
}

#[test]
fn rules_hook_can_be_disabled() {
    let mut cmd = cadence_hooks();
    cmd.args(["rules", "validate-frontmatter"]);
    cmd.env("CADENCE_DISABLE", "validate-frontmatter");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "rules hook should be disableable too"
    );
}

// ── list subcommand ──────────────────────────────────────────────────

#[test]
fn list_shows_all_plugin_groups() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cadence:"), "should show cadence group");
    assert!(
        stdout.contains("guardrails:"),
        "should show guardrails group"
    );
    assert!(stdout.contains("rules:"), "should show rules group");
    assert!(stdout.contains("obsidian:"), "should show obsidian group");
}

#[test]
fn list_shows_hook_names_and_descriptions() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("git-safety"), "should list git-safety hook");
    assert!(
        stdout.contains("Block dangerous git operations"),
        "should include description"
    );
}

#[test]
fn list_shows_disabled_status() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);
    cmd.env("CADENCE_DISABLE", "git-safety,warn-main-branch");

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // git-safety is protected: the listing must show the refusal, not claim
    // it's disabled (#89).
    let git_safety_line = stdout.lines().find(|l| l.contains("git-safety")).unwrap();
    assert!(
        git_safety_line.contains("(protected — disable refused)"),
        "protected hook in disable list should show refusal: {git_safety_line}"
    );

    // An advisory hook in the disable list is marked disabled.
    let warn_line = stdout
        .lines()
        .find(|l| l.contains("warn-main-branch"))
        .unwrap();
    assert!(
        warn_line.contains("(disabled)"),
        "advisory disabled hook should be marked: {warn_line}"
    );

    // Non-disabled hooks should not be marked.
    let terminology_line = stdout.lines().find(|l| l.contains("terminology")).unwrap();
    assert!(
        !terminology_line.contains("(disabled)"),
        "non-disabled hook should not be marked: {terminology_line}"
    );
}

#[test]
fn list_works_during_bypass() {
    let mut cmd = cadence_hooks();
    cmd.args(["list"]);
    cmd.env("CADENCE_BYPASS", "1");

    let output = cmd.output().expect("failed to execute binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "list should work even when bypass is active"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CADENCE_BYPASS=1"),
        "should show bypass status"
    );
    assert!(
        stdout.contains("(disabled)"),
        "all hooks should show as disabled during bypass"
    );
}

#[test]
fn session_status_works_during_bypass() {
    // `session status` is a CLI action, not an enforcement hook — it must be
    // exempt from CADENCE_BYPASS (a bypassed status would hide live peers
    // exactly when someone is debugging coordination). Run from a non-git
    // temp dir so the command exercises its "not a repo" path with no side
    // effects on the real registry.
    let tmp = std::env::temp_dir().join(format!("session-bypass-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let mut cmd = cadence_hooks();
    cmd.args(["session", "status"]);
    cmd.env("CADENCE_BYPASS", "1");
    cmd.current_dir(&tmp);

    let output = cmd.output().expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !stderr.contains("all enforcement bypassed"),
        "status must not be swallowed by the bypass: {stderr}"
    );
    assert!(
        stdout.contains("not inside a git repository"),
        "status ran and reported the non-repo cwd: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn session_enforcement_hooks_still_bypassed() {
    // The exemption is for CLI actions only — `session guard` (an enforcement
    // hook) must still be swallowed by CADENCE_BYPASS.
    let mut cmd = cadence_hooks();
    cmd.args(["session", "guard"]);
    cmd.env("CADENCE_BYPASS", "1");

    let output = run_with_stdin(
        cmd,
        r#"{"tool_name":"Bash","tool_input":{"command":"git checkout main"}}"#,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stderr.contains("all enforcement bypassed"),
        "guard is an enforcement hook and must be bypassed: {stderr}"
    );
}
