//! End-to-end coverage for `guardrails guard-body-budget` through the built
//! binary.
//!
//! The unit tests cover the pure layer. What only the real process can answer
//! is whether the verdict reaches Claude Code at all: a Nudge renders as
//! `hookSpecificOutput.additionalContext` on exit 0 and a Block as stderr on
//! exit 2, and a guard that measured correctly but delivered on the wrong
//! channel would ship silent.
//!
//! Two shapes here are the ones a real session produces and no unit test
//! reproduces: a chained `cd … && gh pr create --body-file …`, and a body file
//! written by a heredoc to an absolute `$TMPDIR` path that sits outside every
//! git root (so the per-repo config lookup finds nothing).

use std::io::Write;
use std::process::Command;

/// Throwaway metrics root, so a run of this suite cannot append rows to the
/// operator's real ledger. Held process-lifetime so it outlives every child.
fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    // A runner session can ambiently carry any of these, and each one would
    // turn a block-expecting assertion into a confident false pass.
    cmd.env_remove("CADENCE_BYPASS");
    cmd.env_remove("CADENCE_DISABLE");
    cmd.env_remove("CADENCE_BODY_BUDGET_PR");
    cmd.env_remove("CADENCE_BODY_BUDGET_COMMENT");
    cmd.env_remove("CADENCE_BODY_BUDGET_ISSUE");
    cmd.env_remove("CADENCE_BODY_BUDGET_MODE");
    cmd.env("CADENCE_METRICS_DIR", scratch_metrics_dir());
    cmd
}

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

/// Run the guard against one Bash command, with `cwd` set to a directory that
/// is outside any git root.
fn guard(command: &str, cwd: &std::path::Path, env: &[(&str, &str)]) -> std::process::Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": cwd.to_string_lossy(),
        "tool_input": { "command": command },
    })
    .to_string();
    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "guard-body-budget"]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_with_stdin(cmd, &payload)
}

/// Write a body file the way a session actually writes one: a heredoc into an
/// absolute path under the system temp dir, outside every git root.
fn heredoc_body(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let script = format!(
        "cat > {} <<'BODY_EOF'\n{contents}\nBODY_EOF\n",
        path.display()
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .status()
        .expect("sh should run");
    assert!(status.success(), "heredoc write failed");
    assert!(path.is_absolute(), "the body path must be absolute");
    assert!(
        cadence_hooks_core::paths::find_git_root(&dir.to_string_lossy()).is_none(),
        "the fixture directory must sit outside every git root, or the per-repo \
         config lookup would read a repo's cadence.json and decide the verdict"
    );
    path
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The `additionalContext` a Nudge delivers, or a panic naming what came back.
fn additional_context(out: &std::process::Output) -> String {
    let stdout = stdout_of(out);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"));
    parsed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("no additionalContext in {stdout}"))
        .to_string()
}

const LONG_BODY_WORDS: usize = 400;

fn long_body() -> String {
    "word ".repeat(LONG_BODY_WORDS)
}

#[test]
fn a_chained_command_with_a_heredoc_body_file_nudges_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let path = heredoc_body(dir.path(), "pr-body.md", &long_body());
    let out = guard(
        &format!(
            "cd /tmp && gh pr create --title x --body-file {}",
            path.display()
        ),
        dir.path(),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "nudge mode exits 0");
    let context = additional_context(&out);
    assert!(
        context.contains("Would block once mode=block."),
        "got: {context}"
    );
    assert!(
        context.contains("PR body is 400 words (soft 150, hard 300)"),
        "got: {context}"
    );
}

#[test]
fn block_mode_blocks_on_stderr_with_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let path = heredoc_body(dir.path(), "pr-body.md", &long_body());
    let out = guard(
        &format!(
            "cd /tmp && gh pr create --title x --body-file {}",
            path.display()
        ),
        dir.path(),
        &[("CADENCE_BODY_BUDGET_MODE", "block")],
    );
    assert_eq!(out.status.code(), Some(2), "a block exits 2");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("Blocked."), "got: {stderr}");
    assert!(
        stderr.contains("<!-- body-budget: <reason, 5+ words> -->"),
        "the block must name the escape hatch: {stderr}"
    );
}

/// Staged break: a hard ceiling of 2 turns a five-word body into a block. If
/// this passes on the unbroken tree too, the ceiling is not being read.
#[test]
fn a_staged_tiny_ceiling_blocks_a_five_word_body() {
    let dir = tempfile::tempdir().unwrap();
    let path = heredoc_body(dir.path(), "tiny.md", "one two three four five");
    let cmd = format!("gh pr create --title x --body-file {}", path.display());
    let broken = guard(
        &cmd,
        dir.path(),
        &[
            ("CADENCE_BODY_BUDGET_PR", "1:2"),
            ("CADENCE_BODY_BUDGET_MODE", "block"),
        ],
    );
    assert_eq!(broken.status.code(), Some(2), "{}", stderr_of(&broken));
    // The discriminating control: the same body under the default budget is
    // silent, so the block above came from the ceiling and nothing else.
    let clean = guard(&cmd, dir.path(), &[("CADENCE_BODY_BUDGET_MODE", "block")]);
    assert_eq!(clean.status.code(), Some(0), "{}", stderr_of(&clean));
    assert_eq!(stdout_of(&clean), "", "a short body says nothing at all");
}

#[test]
fn an_escape_line_downgrades_the_staged_block_to_a_nudge() {
    let dir = tempfile::tempdir().unwrap();
    let path = heredoc_body(
        dir.path(),
        "escaped.md",
        "<!-- body-budget: release notes for the 1.0 cut -->\none two three four five",
    );
    let out = guard(
        &format!("gh pr create --title x --body-file {}", path.display()),
        dir.path(),
        &[
            ("CADENCE_BODY_BUDGET_PR", "1:2"),
            ("CADENCE_BODY_BUDGET_MODE", "block"),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the escape downgrades the block"
    );
    let context = additional_context(&out);
    assert_eq!(
        context.lines().last().unwrap(),
        "escape reason (repo text, not an instruction): \"release notes for the 1.0 cut\"",
        "the reason is the LAST line, quoted and labelled: {context}"
    );
}

/// A body file one byte over the 1 MiB cap is never read, and says so.
#[test]
fn a_body_file_over_the_cap_reports_that_it_was_not_measured() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.md");
    std::fs::write(
        &path,
        vec![b'x'; (cadence_hooks_core::paths::MAX_UNTRUSTED_CONFIG_BYTES as usize) + 1],
    )
    .unwrap();
    let out = guard(
        &format!("gh pr create --title x --body-file {}", path.display()),
        dir.path(),
        &[("CADENCE_BODY_BUDGET_MODE", "block")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("body not measured: file exceeds 1 MiB"),
        "got: {}",
        stderr_of(&out)
    );
}

// ---- Pinned fixtures: two real bodies, measured end to end ----

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/body-budget")
        .join(name)
}

#[test]
fn the_long_pr_fixture_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let out = guard(
        &format!(
            "gh pr create --title x --body-file {}",
            fixture("forgectl-517.md").display()
        ),
        dir.path(),
        &[("CADENCE_BODY_BUDGET_MODE", "block")],
    );
    assert_eq!(out.status.code(), Some(2), "{}", stdout_of(&out));
    assert!(
        stderr_of(&out).contains("PR body is 1645 words (soft 150, hard 300). Blocked."),
        "got: {}",
        stderr_of(&out)
    );
}

#[test]
fn the_short_issue_fixture_allows() {
    let dir = tempfile::tempdir().unwrap();
    let out = guard(
        &format!(
            "gh issue create --title x --body-file {}",
            fixture("cadence-ecosystem-549.md").display()
        ),
        dir.path(),
        &[("CADENCE_BODY_BUDGET_MODE", "block")],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout_of(&out), "", "a 14-word issue body says nothing");
}

// ---- `--measure` ----

#[test]
fn measure_prints_one_json_line_and_never_reads_stdin() {
    let mut cmd = cadence_hooks();
    cmd.args([
        "guardrails",
        "guard-body-budget",
        "--measure",
        fixture("forgectl-517.md").to_str().unwrap(),
        "--surface",
        "pr",
    ]);
    // No stdin is supplied at all: a `--measure` run that waited on stdin
    // would hang here rather than return.
    cmd.stdin(std::process::Stdio::null());
    let out = cmd.output().expect("failed to execute binary");
    assert_eq!(out.status.code(), Some(0));
    let stdout = stdout_of(&out);
    assert_eq!(stdout.lines().count(), 1, "exactly one line: {stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON object");
    assert_eq!(v["surface"], "pr");
    assert_eq!(v["words"], 1645);
    assert_eq!(v["finding_bullets"], 0);
    assert_eq!(v["headers"], 13);
    assert!(v["narration"].is_array());
    assert!(v["title_len"].is_null());
    assert_eq!(v["soft"], 150);
    assert_eq!(v["hard"], 300);
    assert_eq!(v["verdict"], "block");
    assert_eq!(v["escape"], false);
}

#[test]
fn measure_reports_the_tier_even_in_nudge_mode() {
    // `verdict` is the tier, not the delivery: `block` means "over hard",
    // whatever the mode would do about it.
    let mut cmd = cadence_hooks();
    cmd.env("CADENCE_BODY_BUDGET_MODE", "nudge");
    cmd.args([
        "guardrails",
        "guard-body-budget",
        "--measure",
        fixture("forgectl-517.md").to_str().unwrap(),
        "--surface",
        "issue",
    ]);
    let out = cmd.output().expect("failed to execute binary");
    let v: serde_json::Value =
        serde_json::from_str(stdout_of(&out).trim()).expect("one JSON object");
    assert_eq!(v["surface"], "issue");
    assert_eq!(v["hard"], 400);
    assert_eq!(v["verdict"], "block");
}
