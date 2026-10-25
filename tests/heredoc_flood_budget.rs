//! End-to-end timing guard for nested-heredoc floods, through the built binary.
//!
//! The third review of cadence-hooks#1093 measured a quoted nested-heredoc
//! flood (`echo "` + `$(cat <<E⏎x⏎`×n + `E⏎)`×n + `" ; cat .env`) driving
//! `strip_heredoc_bodies` into multiplicative work: at 12 KB the wired
//! `cadence` hook group ran past its 4000 ms deadline and ALLOWED, where main
//! blocked in 0.08 s. A hook that times out fails open, so slow is a bypass.
//! The unit tests pin the work bound; only the real process shows the verdict
//! reaching Claude Code before the deadline does.

mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Throwaway metrics root, so denials logged by this suite never reach the
/// operator's real ledger.
fn scratch_metrics_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp metrics dir"))
        .path()
}

/// The wired group's hook deadline; past it the group fails open. It says so on
/// stdout when it exits 0 (a member that finished nudged, so the notice rides
/// the envelope's `additionalContext`) and on stderr when it exits 1.
const GROUP_DEADLINE: Duration = Duration::from_millis(4000);

fn run(args: &[&str], command: &str) -> (Output, Duration) {
    run_with_env(args, command, &[])
}

fn run_with_env(args: &[&str], command: &str, env: &[(&str, &str)]) -> (Output, Duration) {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "heredoc-flood",
        "cwd": scratch_metrics_dir(),
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let mut cmd: Command = support::cadence_hooks();
    // Any of these, carried ambiently, turns a block-expecting assertion into
    // a confident false failure or pass.
    cmd.env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env("CADENCE_METRICS_DIR", scratch_metrics_dir())
        .envs(env.iter().copied())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("write payload: {e}"),
        }
    }
    let out = child.wait_with_output().expect("wait on cadence-hooks");
    (out, started.elapsed())
}

/// The review's three shapes, each sized to at least `target` bytes.
fn shapes(target: usize) -> Vec<(&'static str, String)> {
    let build = |name: &'static str, f: &dyn Fn(usize) -> String| {
        let mut n = 1;
        while f(n).len() < target {
            n *= 2;
        }
        (name, f(n))
    };
    vec![
        build("quoted", &|n| {
            format!(
                "echo \"{}{}\" ; cat .env",
                "$(cat <<E\nx\n".repeat(n),
                "E\n)".repeat(n)
            )
        }),
        build("unquoted", &|n| {
            format!(
                "echo {}{} ; cat .env",
                "$(cat <<E\nx\n".repeat(n),
                "E\n)".repeat(n)
            )
        }),
        build("balanced", &|n| {
            format!(
                "echo \"{}{}\" ; cat .env",
                "$(cat <<E\nx\nE\n".repeat(n),
                ")".repeat(n)
            )
        }),
    ]
}

#[test]
fn bare_prevent_secret_leaks_blocks_nested_heredoc_floods() {
    for target in [10_000, 50_000, 200_000] {
        for (name, command) in shapes(target) {
            let (out, took) = run(&["cadence", "prevent-secret-leaks"], &command);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{name} ({} B) was not blocked; stderr: {}",
                command.len(),
                String::from_utf8_lossy(&out.stderr)
            );
            // The verdict always runs; the unchanged budget is opt-in.
            cadence_hooks_core::test_builders::assert_elapsed_under(
                &format!("{name} ({} B)", command.len()),
                took,
                Duration::from_secs(10),
            );
        }
    }
}

#[test]
fn wired_cadence_group_blocks_nested_heredoc_floods_before_its_deadline() {
    // The group fails OPEN at 4000 ms, so an exit 2 here is itself the proof
    // the scan finished inside the deadline. Crossing it on a loaded machine
    // passes unless `CADENCE_TIMING_TESTS=1` (cadence-hooks#1366). 200 KB is
    // left to the bare-hook test above: a debug build of the full group needs
    // ~2 s there, too close to the deadline to assert on a shared runner.
    for target in [10_000, 50_000] {
        for (name, command) in shapes(target) {
            let (out, took) = run(
                &[
                    "group",
                    "cadence/git-safety",
                    "cadence/prevent-secret-writes",
                    "cadence/prevent-secret-leaks",
                    "cadence/warn-docs-update",
                ],
                &command,
            );
            cadence_hooks_core::test_builders::assert_blocked_before_deadline(
                &format!("{name} ({} B)", command.len()),
                out.status.code(),
                &String::from_utf8_lossy(&out.stdout),
                &String::from_utf8_lossy(&out.stderr),
                took,
                GROUP_DEADLINE,
            );
        }
    }
}

/// The helper must accept what the real wired group prints when it misses its
/// deadline, not just a synthetic string (cadence-hooks#1366). A 1 ms budget
/// makes the group stop waiting after ~1 s, and the debug-only stall keeps
/// every member busy past that, whatever the machine's speed. The stall knob
/// does not exist in release builds, so the test is ignored there; the debug
/// suite runs it on every platform. Every member stalls, so none nudges and this
/// is the exit-1, stderr form; the exit-0, stdout form is pinned by the unit
/// tests in `test_builders` and by the flood test above under load.
#[test]
#[cfg_attr(not(debug_assertions), ignore = "needs the debug-only group stall")]
fn the_real_group_fail_open_is_accepted_only_without_timing_opt_in() {
    use cadence_hooks_core::test_builders::is_group_fail_open;
    let (out, took) = run_with_env(
        &[
            "group",
            "cadence/git-safety",
            "cadence/prevent-secret-writes",
            "cadence/prevent-secret-leaks",
            "cadence/warn-docs-update",
        ],
        "cat .env",
        &[
            ("CADENCE_HOOK_DEADLINE_MS", "1"),
            ("CADENCE_TEST_GROUP_STALL_MS", "5000"),
        ],
    );
    let (code, stdout, stderr) = (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let deadline = Duration::from_millis(1);
    assert!(
        is_group_fail_open(false, code, &stdout, &stderr, took, deadline),
        "the real fail-open was not recognised: exit {code:?} after {took:?}; \
         stdout: {stdout}; stderr: {stderr}"
    );
    assert!(
        !is_group_fail_open(true, code, &stdout, &stderr, took, deadline),
        "strict mode must fail the real fail-open"
    );
}
