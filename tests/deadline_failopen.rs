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

/// Write an executable `git` into `dir` that appends its full argv (one line
/// per invocation) to `count_file`, then delegates to the real git at
/// `real_git`. Logging argv (not just a bare marker) lets a caller assert on
/// exactly which commands ran, not merely how many — the difference between
/// counting spawns and pinning them.
fn write_counting_git(dir: &std::path::Path, count_file: &std::path::Path, real_git: &str) {
    let path = dir.join("git");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"$@\" >> \"{}\"\nexec {} \"$@\"\n",
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
fn enforce_worktree_edit_is_immune_to_a_hanging_git() {
    // Since cadence-hooks#164, enforce-worktree resolves repo/worktree identity
    // through `core::gitstate::GitState` — a pure filesystem walk — and spawns
    // NO `git`. So even with only a hanging `git` on PATH it decides instantly
    // from the on-disk `.git`, never invokes the shim, and therefore records no
    // `deadline` degradation: the guard graduated past the #271 exposure rather
    // than merely surviving it. (A plain tempdir isn't a git repo, so the
    // verdict is a fail-open allow — the point here is the *absence* of a spawn,
    // not the verdict.)
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
        "not a repo → fail-open allow: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Nowhere near the hanging git's 30s sleep — it was never spawned.
    assert!(
        elapsed < Duration::from_secs(4),
        "enforce resolves via the filesystem, never awaiting the hanging git; took {elapsed:?}"
    );
    let rows = failopen_rows(metrics.path());
    assert!(
        rows.is_empty(),
        "no git spawn → no deadline degradation to record: {rows:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("deadline exceeded"),
        "no deadline breadcrumb when no probe ran: {}",
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
fn suppressed_block_not_logged_when_a_later_static_check_blocks() {
    // A multi-segment command where segment 1's git probe times out (setting
    // the sticky suppressed-block flag) but segment 2 statically blocks with no
    // spawn. The operation is ENFORCED (exit 2), so nothing was bypassed — the
    // sharp `deadline_block_suppressed` row must NOT fire (it would be a false
    // positive on the exact signal Phase 1.5 reads as an active bypass).
    let shim = tempfile::tempdir().unwrap();
    write_hanging_git(shim.path());
    let metrics = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "Bash",
        // seg 1: bare-HEAD force push → branch resolution hangs → suppressed flag.
        // seg 2: force push to protected `main` → pure token match → hard block.
        "tool_input": { "command": "git push --force origin HEAD; git push --force origin main" },
        "cwd": work.path().to_string_lossy(),
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["cadence", "git-safety"]);
    cmd.env("PATH", shim.path());
    cmd.env("CADENCE_HOOK_DEADLINE_MS", "1000");
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);

    assert_eq!(
        out.status.code(),
        Some(2),
        "the protected-branch force push must block: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = failopen_rows(metrics.path());
    assert!(
        rows.iter()
            .all(|r| r["reason"] != "deadline_block_suppressed"),
        "an enforced block must not log a bypassed-enforcement row: {rows:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("degraded to allow"),
        "no bypass breadcrumb on an enforced block: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
fn enforce_worktree_edit_arm_spawns_no_git() {
    // Regression gate, sharpened by cadence-hooks#164: the Edit/Write arm's git
    // spawn count grew unnoticed from ~1 to 4-5 across releases, then #271
    // pinned it at ≤3. Routing identity through `GitState` (a filesystem walk)
    // drops it to ZERO — enforce-worktree no longer spawns `git` at all. This
    // pins that floor: any future per-edit `git` probe creeping back in is a red
    // run. (Formerly asserted `spawns > 0`; that "harness broken" guard is now
    // the *expected* state, so the assertion inverts.)
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
    assert_eq!(
        spawns, 0,
        "enforce-worktree Edit arm must spawn zero git (resolution is a GitState \
         filesystem walk); got {spawns} — a git probe crept back in"
    );
}

use cadence_hooks_core::test_builders::{Scratch, git_in};

/// This crate's own `target/`-relative scratch root for the mutation-nudge
/// spawn-bound tests below — `env!` resolves at THIS call site, so the
/// promoted `Scratch` (cadence-hooks#485; formerly this file's own
/// near-identical copy of `enforce_worktree`'s in-crate helper) still lands
/// fixtures under `target/mutation-nudge-scratch/`, exactly where the
/// pre-promotion local helper put them.
fn scratch_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/mutation-nudge-scratch")
}

/// Two existing tracked files in DISTINCT subdirectories, so the mutation walk
/// produces two genuinely distinct assess-paths (not deduped to one
/// directory) — the fixture that actually exercises "N targets in one repo",
/// not a single target trivially giving N=1.
///
/// Three `git` invocations, not five: the two `git config` calls fold into
/// the commit as `-c user.email=… -c user.name=…` rather than their own
/// spawns — this fixture setup runs with the real PATH (before the counting
/// shim is installed for the actual test command below), so it costs nothing
/// toward any spawn assertion, but there's no reason to pay 5 spawns when 3
/// do the same job.
fn init_mutation_nudge_repo(dir: &std::path::Path) {
    git_in(dir, &["init", "-q", "-b", "main"]);
    std::fs::write(dir.join("root_file.txt"), "x").unwrap();
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub").join("sub_file.txt"), "x").unwrap();
    git_in(dir, &["add", "-A"]);
    git_in(
        dir,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    );
}

/// The real `git` on PATH — resolved once per test *binary* (not once per
/// test) via `OnceLock`, since it never changes within a run. The counting
/// shim installed on the child process's PATH delegates to this path.
fn real_git() -> &'static str {
    static REAL_GIT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    REAL_GIT.get_or_init(|| {
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
        real_git
    })
}

/// Full content the counting shim recorded — one line of argv per `git`
/// invocation, in call order.
fn spawn_log(count_file: &std::path::Path) -> String {
    std::fs::read_to_string(count_file).unwrap_or_default()
}

/// Run the mutation-nudge scenario (`tee root_file.txt sub/sub_file.txt` in a
/// fresh primary-repo `Scratch` fixture) through the real binary with an
/// argv-recording `git` shim on PATH, returning `(stdout, spawn log)`.
///
/// `allow_main` toggles `CADENCE_ALLOW_MAIN` — the ONLY difference between the
/// blocked-path and allow-path tests below, so the differential is exact.
/// Nudge/denial logging is left at its default (ON) rather than special-cased
/// off: the shim recording full argv lets each test assert on exactly which
/// commands ran, so the metrics layer's own git spawn (found while writing
/// this test — `repo_basename`'s `rev-parse --show-toplevel`, fired by the
/// nudge/denial logger, cadence-hooks#292 review) is pinned by name rather
/// than suppressed by a knob that could silently grow.
fn run_mutation_nudge(tag: &str, allow_main: bool) -> (String, String) {
    let scratch = Scratch::new(&scratch_root(), tag);
    init_mutation_nudge_repo(&scratch.0);

    let shim = tempfile::tempdir().unwrap();
    let counts = tempfile::tempdir().unwrap();
    let count_file = counts.path().join("spawns");
    write_counting_git(shim.path(), &count_file, real_git());
    let metrics = tempfile::tempdir().unwrap();

    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "tee root_file.txt sub/sub_file.txt" },
        "cwd": scratch.0.to_string_lossy(),
    })
    .to_string();

    let mut cmd = cadence_hooks();
    cmd.args(["guardrails", "enforce-worktree"]);
    cmd.env("PATH", shim.path());
    cmd.env("CADENCE_METRICS_DIR", metrics.path());
    if allow_main {
        cmd.env("CADENCE_ALLOW_MAIN", "true");
    } else {
        cmd.env_remove("CADENCE_ALLOW_MAIN");
    }
    cmd.env_remove("CADENCE_NO_ENFORCE_WORKTREE");
    cmd.env_remove("CADENCE_DISABLE");
    let out = run_with_payload(&mut cmd, &payload);

    assert_eq!(
        out.status.code(),
        Some(0),
        "enforce-worktree must exit 0 here (a nudge is advisory, and \
         CADENCE_ALLOW_MAIN must allow): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (stdout, spawn_log(&count_file))
}

#[test]
fn enforce_worktree_mutation_nudge_blocked_path_spawns_one_git() {
    // cadence-hooks#292's corrected premise: the issue as filed assumed
    // GitState::resolve still spawned git (it's been a pure filesystem walk
    // since #164 — deadline_failopen.rs's own edit-arm test above already
    // pins that at zero) and that the mutation-nudge loop's spawn count scaled
    // with the number of distinct mutation targets. It doesn't: `mutation_nudge`
    // returns on the FIRST target whose containing repo would block, and
    // `GitProbe::is_commitless` is memoized on repo_root regardless — so N
    // distinct targets (here 2, in different subdirectories, so they aren't
    // trivially deduped to one directory) in the SAME primary repo still cost
    // exactly one `git` spawn from enforce-worktree itself (the `rev-list
    // --count -n1 --all` bootstrap-exemption probe on the would-block path).
    //
    // A second, separate spawn is real and expected here: the nudge/denial
    // logger resolves its own `repo` field via `repo_basename`'s `rev-parse
    // --show-toplevel` on every guard's Nudge outcome — the metrics layer's
    // cost, not enforce-worktree's, but genuinely on PATH in the DEFAULT
    // (nudge-logging-on) configuration. Asserting on both by name, in order,
    // pins the full default-config cost rather than hiding one behind a knob.
    let (stdout, log) = run_mutation_nudge("blocked", false);

    assert!(
        stdout.contains("enforce-worktree: this command mutates"),
        "expected the mutation nudge to fire in this primary-checkout fixture: {stdout}"
    );

    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected exactly 2 git invocations (enforce-worktree's is_commitless \
         + the metrics logger's repo_basename); got: {lines:?}"
    );
    assert!(
        lines[0].contains("rev-list") && lines[0].contains("--count") && lines[0].contains("-n1"),
        "first spawn should be enforce-worktree's is_commitless bootstrap-exemption probe: {}",
        lines[0]
    );
    assert_eq!(
        lines[1].trim(),
        "rev-parse --show-toplevel",
        "second spawn should be the metrics logger's repo_basename lookup: {}",
        lines[1]
    );
}

#[test]
fn enforce_worktree_mutation_nudge_allow_path_spawns_zero_git() {
    // Differential control for the test above: the identical fixture and
    // command, differing ONLY in CADENCE_ALLOW_MAIN — assess_dir never
    // reaches the would-block branch, so is_commitless (enforce-worktree's one
    // git spawn on the blocked path) is never called, GitState resolution is
    // git-free regardless, and no Nudge outcome means the metrics logger's
    // repo_basename spawn never fires either. Total: zero.
    let (stdout, log) = run_mutation_nudge("allowed", true);

    assert!(
        !stdout.contains("enforce-worktree: this command mutates"),
        "CADENCE_ALLOW_MAIN must suppress the nudge, not just the block: {stdout}"
    );
    assert_eq!(
        log, "",
        "an exempted primary checkout must spawn zero git on the mutation-nudge \
         path; got: {log:?}"
    );
}
