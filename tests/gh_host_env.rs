//! `guard-gh-write` host resolution under a process `GH_HOST`.
//!
//! This runs in a child process on purpose. `GH_HOST` is process-global, and
//! many guardrails unit tests read `default_host()` without the env lock.
//! Setting it inside that test binary flipped their bare-owner verdicts
//! whenever the two overlapped. A child's environment touches nothing else.

use std::io::Write;
use std::process::{Command, Stdio};

fn guard(command: &str, gh_host: &str) -> i32 {
    let scratch = tempfile::tempdir().expect("temp metrics dir");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": "/tmp",
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["guardrails", "guard-gh-write"])
        // Ambient switches would exempt the guard and fake a pass.
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOWED_REPOS")
        .env_remove("CADENCE_EXTRA_HOSTS")
        .env("CADENCE_ALLOWED_OWNERS", "cameronsjo")
        .env("CADENCE_METRICS_DIR", scratch.path())
        .env("GH_HOST", gh_host)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cadence-hooks");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait");
    out.status.code().expect("exit code")
}

/// A bare allowlist entry follows the process `GH_HOST`, and `--hostname`
/// still outranks it. Neither path reads a subcommand's flag table, so the
/// `gh api` gate must leave both intact.
#[test]
fn process_gh_host_moves_the_default_host_and_hostname_outranks_it() {
    for command in [
        "gh pr create -R cameronsjo/x -f --title t",
        "gh api repos/cameronsjo/x -X POST -f title=t",
    ] {
        assert_eq!(
            guard(command, "git.sjo.lol"),
            0,
            "bare owner follows the process GH_HOST: {command}"
        );
    }
    for command in [
        "gh pr create -R cameronsjo/x -f --hostname evil.example.com --title t",
        "gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f title=t",
    ] {
        assert_eq!(
            guard(command, "git.sjo.lol"),
            2,
            "--hostname outranks the process GH_HOST: {command}"
        );
    }
}
