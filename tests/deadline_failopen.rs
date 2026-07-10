//! Integration tests for the #271 subprocess deadline: a stalled `git` must
//! never ride a guard past its hooks.json budget — the guard abandons the
//! probe, decides, exits fast, and records the degradation loudly
//! (`failopen.jsonl` reasons `deadline` / `deadline_block_suppressed`).
//!
//! A fake `git` on PATH (a script that sleeps far past the configured budget)
//! stands in for the pathological host: cloud-synced `.git`, sync-client
//! locks, fork/exec starvation. Each test invokes the real binary
//! (`CARGO_BIN_EXE_cadence-hooks`), so the full dispatch → deadline → telemetry
//! wiring is exercised, not a unit seam.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
}

/// Write an executable `git` into `dir` that sleeps far past any test budget.
///
/// `/bin/sleep` by absolute path: the shim runs with the test's shim-only
/// PATH, where a bare `sleep` resolves to nothing and the script would exit
/// 127 instantly — reading as "git answered badly" instead of a hang.
fn write_hanging_git(dir: &std::path::Path) {
    let path = dir.join("git");
    std::fs::write(&path, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Write an executable `git` into `dir` that appends one line to `count_file`
/// per invocation, then delegates to the real git at `real_git`.
fn write_counting_git(dir: &std::path::Path, count_file: &std::path::Path, real_git: &str) {
    let path = dir.join("git");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\necho x >> \"{}\"\nexec {} \"$@\"\n",
            count_file.display(),
            real_git
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn run_with_payload(cmd: &mut Command, payload: &str) -> Output {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn binary");
    if let Some(ref mut stdin) = child.stdin {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write child stdin: {e}"),
        }
    }
    child.wait_with_output().expect("failed to wait on binary")
}

fn failopen_rows(metrics_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let path = metrics_dir.join("failopen.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("each failopen.jsonl line is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
}

#[test]
fn hanging_git_on_edit_fails_open_fast_with_deadline_row() {
    let shim = tempfile::tempdir().unwrap();
    write_hanging_git(shim.path());
    let metrics = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let target = work.path().join("src/lib.rs");

    let payload = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": target.to_string_lossy() },
        "cwd": work.path().to_string_lossy(),
    })
    .to_string();

    let started = Instant::now();
    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "enforce-worktree"]);
    cmd.env("PATH", shim.path()); // only the hanging git is reachable
    cmd.env("CADENCE_HOOK_DEADLINE_MS", "1000");
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    cmd.env_remove("CADENCE_ALLOW_MAIN");
    cmd.env_remove("CADENCE_NO_ENFORCE_WORKTREE");
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);
    let elapsed = started.elapsed();

    assert_eq!(
        out.status.code(),
        Some(0),
        "a timed-out probe fails open, never blocks: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The whole point: decide well inside the 5s external hooks.json budget
    // instead of being killed by it. Generous bound for slow CI.
    assert!(
        elapsed < Duration::from_secs(4),
        "guard must abandon the probe at its ~1s budget, took {elapsed:?}"
    );
    let rows = failopen_rows(metrics.path());
    assert_eq!(rows.len(), 1, "exactly one failopen row: {rows:?}");
    assert_eq!(rows[0]["reason"], "deadline");
    assert_eq!(rows[0]["namespace"], "guardrails");
    assert_eq!(rows[0]["subcommand"], "enforce-worktree");
    assert_eq!(rows[0]["binaryVersion"], env!("CARGO_PKG_VERSION"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("deadline exceeded"),
        "stderr breadcrumb expected: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn hanging_branch_resolution_never_blocks_bare_head_force_push() {
    let shim = tempfile::tempdir().unwrap();
    write_hanging_git(shim.path());
    let metrics = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "git push --force origin HEAD" },
        "cwd": work.path().to_string_lossy(),
    })
    .to_string();

    let started = Instant::now();
    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("PATH", shim.path());
    cmd.env("CADENCE_HOOK_DEADLINE_MS", "1000");
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);
    let elapsed = started.elapsed();

    // Pre-#271 this was a fail-closed block ("unresolvable current branch") —
    // on the slow host it fixes, the deadline would have converted every
    // routine feature-branch force push into a false block.
    assert_ne!(
        out.status.code(),
        Some(2),
        "a timed-out branch resolution must not block: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "guard must abandon the probe at its ~1s budget, took {elapsed:?}"
    );
    let rows = failopen_rows(metrics.path());
    assert_eq!(rows.len(), 1, "exactly one failopen row: {rows:?}");
    assert_eq!(
        rows[0]["reason"], "deadline_block_suppressed",
        "a suppressed fail-closed block gets the sharper reason: {rows:?}"
    );
    assert_eq!(rows[0]["subcommand"], "git-safety");
}

#[test]
fn push_loop_padding_flood_blocks_instead_of_failing_open() {
    // The #271 security regression gate. A push loop that resolves a flood of
    // remotes drains the shared deadline; if the trailing push's ownership
    // probe times out and the loop arm fails OPEN, an unowned push executes.
    // The loop arm therefore fails CLOSED on ANY resolution timeout — this is
    // robust to a slow host inflating each probe (which defeats a completion-
    // count discriminator), because it doesn't depend on how the budget drained.
    let shim = tempfile::tempdir().unwrap();
    // Fast fake git: every remote resolution fails quickly (nonexistent
    // remote), completing a spawn and burning ~one poll interval of budget.
    let git_path = shim.path().join("git");
    std::fs::write(&git_path, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&git_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let metrics = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    // ~200 padding pushes reliably exceed the 1000ms floor budget at the ~10ms
    // poll interval, then one push whose resolution is pre-exhausted → TimedOut.
    let mut body = String::new();
    for i in 0..200 {
        body.push_str(&format!("git push r{i}; "));
    }
    body.push_str("git push evilremote main");
    let command = format!("for x in 1; do {body}; done");

    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": work.path().to_string_lossy(),
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "guard-push-remote"]);
    cmd.env("PATH", shim.path());
    cmd.env("CADENCE_HOOK_DEADLINE_MS", "1000");
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    cmd.env("CADENCE_ALLOWED_OWNERS", "cameronsjo");
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a loop-arm resolution timeout must BLOCK, not fail open: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("timed out"),
        "block message names the timeout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The guard ENFORCED (blocked), so nothing degraded to fail-open — the
    // timed-out probe must NOT emit a plain `deadline` row or the misleading
    // "degraded to fail-open" breadcrumb (CodeRabbit finding on #273).
    let rows = failopen_rows(metrics.path());
    assert!(
        rows.iter().all(|r| r["reason"] != "deadline"),
        "a block must not log a fail-open deadline row: {rows:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("degraded to fail-open"),
        "no fail-open breadcrumb on an enforced block: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn enforce_worktree_edit_arm_stays_within_spawn_budget() {
    // Regression gate (#271 prevention): the Edit/Write arm's git spawn count
    // grew unnoticed from ~1 to 4-5 across releases; this pins it. The count
    // is location-independent — the arm's probes (target common dir, cwd
    // common dir, repo root) all run BEFORE any temp-root carve-out is
    // consulted, and the snooze/meta reads are pure filesystem now.
    let real_git = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert!(!real_git.is_empty(), "real git required for this test");

    let shim = tempfile::tempdir().unwrap();
    let counts = tempfile::tempdir().unwrap();
    let count_file = counts.path().join("spawns");
    write_counting_git(shim.path(), &count_file, &real_git);
    let metrics = tempfile::tempdir().unwrap();

    // A real repo so every probe answers and the arm runs to completion.
    let work = tempfile::tempdir().unwrap();
    for args in [
        &["init", "-q", "-b", "main"][..],
        &["config", "user.email", "t@t"][..],
        &["config", "user.name", "t"][..],
        &["commit", "-q", "--allow-empty", "-m", "init"][..],
    ] {
        let ok = Command::new(&real_git)
            .arg("-C")
            .arg(work.path())
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed setting up fixture");
    }
    let target = work.path().join("src/lib.rs");

    let payload = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": target.to_string_lossy() },
        "cwd": work.path().to_string_lossy(),
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "enforce-worktree"]);
    cmd.env("PATH", shim.path());
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    cmd.env_remove("CADENCE_ALLOW_MAIN");
    cmd.env_remove("CADENCE_NO_ENFORCE_WORKTREE");
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);
    assert_eq!(
        out.status.code(),
        Some(0),
        "temp fixture repo is carve-out allowed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let spawns = std::fs::read_to_string(&count_file)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    assert!(
        spawns <= 3,
        "enforce-worktree Edit arm spawn budget is 3 (target common dir, cwd \
         common dir, repo root); got {spawns} — a new per-edit git probe crept in"
    );
    assert!(spawns > 0, "counting shim never ran — harness broken");
}
