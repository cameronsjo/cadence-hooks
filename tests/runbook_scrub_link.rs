//! cameronsjo/cadence-hooks#1412, #1417 review: a link toward the
//! scrub-marker directory is refused on its own, through the built binary.
//!
//! `guard-runbook-scrub` judges each command against the filesystem as it is
//! before the command runs. Refusing a link only when the same command also
//! wrote left a two-call split open: a write backgrounded by one call runs
//! after the link a second call makes, and each call alone read as harmless.
//! Each row below is one such split. The call that makes the link must block,
//! and an unrelated link must not.
#![cfg(unix)]

mod support;

use cadence_hooks_core::git_fixtures::Scratch;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target/runbook-scrub-link-scratch")
}

/// The binary's verdict on `command`, run from `cwd`, with the runbooks
/// directory and the marker-directory override inside `root`.
fn judge(root: &Path, cwd: &Path, command: &str) -> Output {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "runbook-scrub-link",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut cmd = support::cadence_hooks();
    for var in [
        "CADENCE_BYPASS",
        "CADENCE_DISABLE",
        "CADENCE_ALLOW_UNSCRUBBED_RUNBOOK",
        "CLAUDECODE",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("HOME", root.join("home"))
        .env("CADENCE_RUNBOOKS_DIR", root.join("vault/Runbooks"))
        .env("CADENCE_MARKER_DIR", root.join("cfg"))
        .env("CADENCE_METRICS_DIR", root.join("metrics"))
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .args(["guardrails", "guard-runbook-scrub"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn cadence-hooks");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.to_string().as_bytes());
    }
    child.wait_with_output().expect("wait on cadence-hooks")
}

#[test]
fn a_link_toward_the_marker_dir_blocks_in_whichever_call_makes_it() {
    let scratch = Scratch::outside_checkout(&scratch_root(), "two-call-split");
    let root = scratch.path().canonicalize().unwrap();
    for d in ["home", "vault/Runbooks", "cfg", "work", "s"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let work = root.join("work");
    // `CADENCE_MARKER_DIR` is the base the marker dir is made under, so it is
    // the marker dir's parent: a recursive copy into a link to it lands one.
    let parent = root.join("cfg");
    let x = root.join("s/x");
    let (p, x) = (parent.display(), x.display());

    let splits = [
        // Write backgrounded first; the link comes in the next call.
        (
            format!("(sleep 10; cp -r forged/markers {x}/) &"),
            format!("ln -s {p} {x}"),
            2,
        ),
        // Link backgrounded first, behind `nohup sh -c`; the write follows.
        (
            format!("nohup sh -c 'sleep 5; ln -s {p} {x}' >/dev/null 2>&1 &"),
            format!("sleep 10; cp -r forged/markers {x}/"),
            1,
        ),
        // Link backgrounded first, in a subshell; the write follows.
        (
            format!("(sleep 5; ln -s {p} {x}) &"),
            format!("sleep 10; cp -r forged/markers {x}/"),
            1,
        ),
    ];
    for (first, second, link_call) in &splits {
        let link = if *link_call == 1 { first } else { second };
        let write = if *link_call == 1 { second } else { first };
        let got = judge(&root, &work, link);
        assert_eq!(
            got.status.code(),
            Some(2),
            "the call that makes the link must block: `{link}`: {}",
            String::from_utf8_lossy(&got.stderr)
        );
        assert!(
            String::from_utf8_lossy(&got.stderr).contains("creates a link"),
            "`{link}`: {}",
            String::from_utf8_lossy(&got.stderr)
        );
        // Control: the write alone was never what refused it.
        assert_eq!(
            judge(&root, &work, write).status.code(),
            Some(0),
            "the write alone is allowed: `{write}`"
        );
    }

    // Control: a link to somewhere unrelated passes on its own.
    let elsewhere = root.join("s/tool");
    assert_eq!(
        judge(&root, &work, &format!("ln -s {} {x}", elsewhere.display()))
            .status
            .code(),
        Some(0)
    );
}
