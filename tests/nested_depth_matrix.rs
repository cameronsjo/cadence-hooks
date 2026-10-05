//! A command nested in process substitutions, `$(…)` and backticks reaches
//! the guards that judge commands at every depth, 1 through 8
//! (cameronsjo/cadence-hooks#1267, #1233): read where the walk reaches it,
//! and refused past the depth it reads. `enforce-worktree` let a commit
//! four levels down land in a primary checkout
//! (`cat <(echo $(echo $(echo $(git commit -m x))))`). Through the built
//! binary, against a real primary checkout.
#![cfg(unix)]

mod support;

use cadence_hooks_core::git_fixtures::{Scratch, git_in};
use std::io::Write;
use std::process::{Output, Stdio};

fn scratch_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/nested-depth-scratch")
}

fn run(args: &[&str], command: &str, cwd: &std::path::Path) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "nested-depth",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let metrics = tempfile::tempdir().expect("metrics dir");
    let mut cmd = support::cadence_hooks();
    cmd.env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOW_MAIN")
        .env_remove("CADENCE_NO_ENFORCE_WORKTREE")
        .env_remove("CLAUDE_CODE_REMOTE")
        .env("CADENCE_METRICS_DIR", metrics.path())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    child.wait_with_output().expect("wait on cadence-hooks")
}

/// `inner` wrapped in `depth` levels of one shape: `p` a process
/// substitution, `d` a `$(…)`, `q` a quoted `"$(…)"`, `b` one backtick level
/// outermost then `$(…)`, `pd`/`dp`/`alt` mixes.
fn nest(shape: &str, depth: usize, inner: &str) -> String {
    let kinds: Vec<char> = (0..depth)
        .map(|level| match shape {
            "pd" => {
                if level == 0 {
                    'p'
                } else {
                    'd'
                }
            }
            "dp" => {
                if level + 1 == depth {
                    'p'
                } else {
                    'd'
                }
            }
            "alt" => {
                if level % 2 == 0 {
                    'p'
                } else {
                    'd'
                }
            }
            "b" => {
                if level == 0 {
                    'b'
                } else {
                    'd'
                }
            }
            other => other.chars().next().expect("a shape"),
        })
        .collect();
    let mut text = inner.to_string();
    for kind in kinds.iter().rev() {
        text = match kind {
            'p' => format!("cat <({text})"),
            'd' => format!("echo $({text})"),
            'q' => format!("echo \"$({text})\""),
            'b' => format!("echo `{text}`"),
            other => unreachable!("{other}"),
        };
    }
    text
}

const SHAPES: [&str; 7] = ["p", "d", "q", "pd", "dp", "alt", "b"];

#[test]
fn a_nested_command_is_judged_at_every_depth() {
    let scratch = Scratch::new(&scratch_root(), "primary");
    let repo = scratch.path();
    git_in(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("f"), "x").unwrap();
    git_in(repo, &["add", "f"]);
    git_in(
        repo,
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
    for depth in 1..=8 {
        for shape in SHAPES {
            for (args, inner) in [
                (["guardrails", "enforce-worktree"], "git commit -m x"),
                (["cadence", "git-safety"], "git reset --hard"),
                (["cadence", "prevent-secret-writes"], "cp d .env"),
            ] {
                let command = nest(shape, depth, inner);
                let out = run(&args, &command, repo);
                assert_eq!(
                    out.status.code(),
                    Some(2),
                    "{args:?} depth {depth} {shape}: {command}\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
    // Nested as deep, but harmless: still allowed.
    for shape in SHAPES {
        for inner in ["git status", "git log -1", "echo {a,b}"] {
            let command = nest(shape, 6, inner);
            let out = run(&["guardrails", "enforce-worktree"], &command, repo);
            assert_eq!(out.status.code(), Some(0), "{command}");
        }
    }
}
