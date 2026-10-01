//! cameronsjo/cadence-hooks#1279, #1231 review: a fail-closed guard refuses a
//! command part of which it could not read. Padding a command with brace
//! expansions until the expansion budget is spent left a later
//! `{git,reset,--hard}` whole, so it ran past every guard; wrapping each pad
//! in a script read two ways halved the pads that took. Through the built
//! binary, because the refusal lives in the dispatch seam, not in a guard.

mod support;

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn scratch() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("temp dir"))
        .path()
}

fn run(args: &[&str], command: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "unread-command",
        "cwd": scratch(),
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let mut cmd: Command = support::cadence_hooks();
    cmd.env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOW_MAIN")
        .env("CADENCE_METRICS_DIR", scratch())
        .env("HOME", scratch())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(payload.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("write payload: {e}"),
        }
    }
    child.wait_with_output().expect("wait on cadence-hooks")
}

const PAD: &str = r": {1..1024}{1..4} a\b";

/// Each pad spelled inside a wrapper the hunt reads.
fn wrapped(wrapper: &str) -> String {
    match wrapper {
        "top" => PAD.to_string(),
        "sh" => format!("sh -c '{PAD}'"),
        "bash" => format!("bash -c '{PAD}'"),
        "find" => format!(r"find . -exec sh -c '{PAD}' \;"),
        "xargs" => format!("echo | xargs sh -c '{PAD}'"),
        "trap" => format!("trap '{PAD}' EXIT"),
        "herestring" => format!("bash <<< '{PAD}'"),
        "rebase" => format!("git rebase -x '{PAD}' HEAD"),
        other => unreachable!("{other}"),
    }
}

#[test]
fn padded_commands_are_refused_by_every_fail_closed_guard() {
    let wrappers = [
        "top",
        "sh",
        "bash",
        "find",
        "xargs",
        "trap",
        "herestring",
        "rebase",
    ];
    for pads in [6, 8, 16] {
        for wrapper in wrappers {
            let padding = format!("{}; ", wrapped(wrapper)).repeat(pads);
            for (args, tail) in [
                (["cadence", "git-safety"], "{git,reset,--hard}"),
                (["cadence", "prevent-secret-writes"], "{cp,d,.env}"),
            ] {
                let command = format!("{padding}{tail}");
                let out = run(&args, &command);
                assert_eq!(
                    out.status.code(),
                    Some(2),
                    "{args:?} {pads}x {wrapper} {tail}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

#[test]
fn a_command_padded_past_the_budget_is_refused_whatever_it_runs() {
    // A harmless tail: only the unread padding can refuse it, so this shows
    // the refusal itself, not a guard reading the tail.
    let command = format!("{}{{echo,hi}}", format!("{PAD}; ").repeat(80));
    for args in [
        ["cadence", "git-safety"],
        ["cadence", "prevent-secret-writes"],
        ["cadence", "prevent-secret-leaks"],
    ] {
        let out = run(&args, &command);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        // prevent-secret-leaks refuses the same input with its own message.
        assert!(stderr.contains("too large"), "{args:?}: {stderr}");
    }
}

#[test]
fn modest_brace_expansions_still_pass() {
    for command in [
        "echo {1..10}",
        "mkdir -p src/{a,b,c}",
        "cp x.{txt,bak} /tmp",
        "for i in {1..4096}; do :; done",
        "echo {a,b}{c,d} 'x\\y'",
        "bash -c 'echo {a,b} a\\b'",
    ] {
        for args in [
            ["cadence", "git-safety"],
            ["cadence", "prevent-secret-writes"],
            ["cadence", "prevent-secret-leaks"],
            ["cadence", "prevent-secret-push"],
            ["guardrails", "guard-push-remote"],
        ] {
            let out = run(&args, command);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{args:?} {command}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
