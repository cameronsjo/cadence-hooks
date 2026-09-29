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

fn run(args: &[&str], command: &str) -> (Output, Duration) {
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
            // Generous for a debug build on a loaded runner; the regression
            // this pins was tens of seconds at these sizes.
            assert!(
                took < Duration::from_secs(10),
                "{name} ({} B): {took:?}",
                command.len()
            );
        }
    }
}

#[test]
fn wired_cadence_group_blocks_nested_heredoc_floods_before_its_deadline() {
    // The group fails OPEN at 4000 ms, so an exit 2 here is itself the proof
    // the scan finished inside the deadline. 200 KB is left to the bare-hook
    // test above: a debug build of the full group needs ~2 s there, too close
    // to the deadline to assert on a shared runner.
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
            assert_eq!(
                out.status.code(),
                Some(2),
                "{name} ({} B) was not blocked in {took:?}; stderr: {}",
                command.len(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
