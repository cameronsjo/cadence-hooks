//! cameronsjo/cadence-hooks#1413: the temp-root carve-out never resolves
//! `$TMPDIR`. The session owns the parent of `$TMPDIR`, so it can swap the
//! directory for a symlink to a directory it wants counted as temp; resolving
//! the link handed that directory the carve-out. Through the built binary, one
//! test per caller: `enforce-worktree` (a repo root, read physically by git)
//! and `guard-git-init` (an init site, read as spelled). Each pairs the refusal
//! with a control on the real directory, so a fixture that never reached the
//! carve-out cannot pass.
#![cfg(unix)]

mod support;

use cadence_hooks_core::git_fixtures::{Scratch, init_repo};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target/temp-root-symlink-scratch")
}

/// `<scratch>/real` (a directory), `<scratch>/link -> real`, and
/// `<scratch>/home`, which covers neither, so the home veto stays out of it.
struct Tree {
    _scratch: Scratch,
    real: PathBuf,
    link: PathBuf,
    home: PathBuf,
}

fn tree(tag: &str) -> Tree {
    let scratch = Scratch::outside_checkout(&scratch_root(), tag);
    let root = scratch.path().canonicalize().unwrap();
    let real = root.join("real");
    let link = root.join("link");
    let home = root.join("home");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    Tree {
        _scratch: scratch,
        real,
        link,
        home,
    }
}

fn run(args: &[&str], payload: &serde_json::Value, tmpdir: &Path, home: &Path) -> Output {
    let mut cmd = support::cadence_hooks();
    for var in [
        "CADENCE_BYPASS",
        "CADENCE_DISABLE",
        "CADENCE_ALLOW_MAIN",
        "CADENCE_NO_ENFORCE_WORKTREE",
        "CLAUDECODE",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("TMPDIR", tmpdir)
        .env("HOME", home)
        .env("CADENCE_METRICS_DIR", home.join("metrics"))
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .args(args)
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
fn enforce_worktree_gives_no_carve_out_through_a_symlinked_tmpdir() {
    let t = tree("enforce-worktree");
    let repo = t.real.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "temp-root-symlink",
        "cwd": repo,
        "tool_name": "Write",
        "tool_input": { "file_path": repo.join("f.txt"), "content": "y" },
    });
    let args = ["guardrails", "enforce-worktree"];

    let control = run(&args, &payload, &t.real, &t.home);
    assert_eq!(
        control.status.code(),
        Some(0),
        "control: a primary checkout under the real $TMPDIR is carved out: {control:?}"
    );
    let linked = run(&args, &payload, &t.link, &t.home);
    assert_eq!(
        linked.status.code(),
        Some(2),
        "a $TMPDIR that is a symlink must not carve out what it points at: {linked:?}"
    );
}

#[test]
fn guard_git_init_gives_no_carve_out_through_a_symlinked_tmpdir() {
    let t = tree("guard-git-init");
    let args = ["guardrails", "guard-git-init"];
    let init = |site: &Path, tmpdir: &Path| {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "temp-root-symlink",
            "cwd": t.home,
            "tool_name": "Bash",
            "tool_input": { "command": format!("git init {}", site.display()) },
        });
        let out = run(&args, &payload, tmpdir, &t.home);
        assert_eq!(out.status.code(), Some(0), "the guard only nudges: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert_eq!(
        init(&t.real.join("x"), &t.real),
        "",
        "control: an init under the real $TMPDIR is a throwaway"
    );
    for site in [t.link.join("x"), t.real.join("x")] {
        assert!(
            init(&site, &t.link).contains("New repo detected"),
            "a $TMPDIR that is a symlink must not mark {} as a throwaway",
            site.display()
        );
    }
}
