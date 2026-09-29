//! End-to-end: `record-polish` then `nudge-polish-before-pr`, both through the
//! built binary (cadence-hooks#826).
//!
//! Every other polish test stops at the marker file (does the record write it)
//! or starts from it (does the gate read it). These run the pair together, so
//! the clap layer, the exit codes, and the marker key both sides compute are
//! all in the loop: a record whose key the gate cannot find fails here.

mod support;

use cadence_hooks_core::git_fixtures::{Scratch, git_in};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target/polish-gate-e2e-scratch")
}

/// The binary, sandboxed to `marker_dir`, with every ambient toggle that
/// silences or disables a check removed.
fn cadence_hooks(marker_dir: &Path, cwd: &Path) -> Command {
    let mut cmd = support::cadence_hooks();
    for var in [
        "CADENCE_BYPASS",
        "CADENCE_DISABLE",
        "CADENCE_ALLOW_MAIN",
        "CLAUDECODE",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("CADENCE_MARKER_DIR", marker_dir);
    cmd.env("CADENCE_METRICS_DIR", marker_dir.join("metrics"));
    cmd.current_dir(cwd);
    cmd
}

fn record(marker_dir: &Path, cwd: &Path, args: &[&str]) -> Output {
    cadence_hooks(marker_dir, cwd)
        .args(["cadence", "record-polish"])
        .args(args)
        .output()
        .expect("run record-polish")
}

/// Pipe a Bash PreToolUse payload for `command` in `cwd` to the gate.
fn gate(marker_dir: &Path, cwd: &Path, command: &str) -> Output {
    let payload = serde_json::json!({
        "session_id": "polish-gate-e2e",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": cwd.to_string_lossy(),
    })
    .to_string();
    let mut child = cadence_hooks(marker_dir, cwd)
        .args(["cadence", "nudge-polish-before-pr"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the gate");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    child.wait_with_output().expect("wait for the gate")
}

/// A repo on `main` with one commit, `origin/main` pointing at it, and
/// `feat/a` carrying a code change on top — so the gate's branch diff
/// touches code on `feat/a`.
fn repo(tag: &str) -> (Scratch, PathBuf, PathBuf) {
    let scratch = Scratch::new(&scratch_root(), tag);
    let repo = scratch.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git_in(&repo, &["init", "-q", "-b", "main"]);
    git_in(&repo, &["config", "user.email", "t@t"]);
    git_in(&repo, &["config", "user.name", "t"]);
    std::fs::write(repo.join("README.md"), "x\n").unwrap();
    git_in(&repo, &["add", "README.md"]);
    git_in(&repo, &["commit", "-q", "-m", "init"]);
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&repo, &["checkout", "-q", "-b", "feat/a"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    git_in(&repo, &["add", "src/lib.rs"]);
    git_in(&repo, &["commit", "-q", "-m", "a"]);
    let markers = scratch.path().join("markers");
    std::fs::create_dir_all(&markers).unwrap();
    (scratch, repo, markers)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

const FULL_RECORD: &[&str] = &[
    "--fresh",
    "--arm",
    "security=ran",
    "--arm-model",
    "security=opus",
];

#[test]
fn a_record_on_the_attached_branch_lets_its_ship_pass_silently() {
    let (_scratch, repo, markers) = repo("attached");
    let recorded = record(&markers, &repo, FULL_RECORD);
    assert_eq!(recorded.status.code(), Some(0), "{recorded:?}");

    let gated = gate(&markers, &repo, "gh pr create -t a -b b");
    assert_eq!(gated.status.code(), Some(0), "{gated:?}");
    assert_eq!(stdout(&gated), "", "a polished ship passes silently");
}

#[test]
fn a_detached_head_records_nothing_and_the_gate_nudges() {
    let (_scratch, repo, markers) = repo("detached");
    git_in(&repo, &["checkout", "-q", "--detach"]);
    let recorded = record(&markers, &repo, FULL_RECORD);
    assert_eq!(
        recorded.status.code(),
        Some(1),
        "a detached HEAD has no branch to key a marker on: {recorded:?}"
    );

    let gated = gate(&markers, &repo, "gh pr create -t a -b b");
    assert_eq!(gated.status.code(), Some(0), "the gate never blocks");
    assert!(
        stdout(&gated).contains("No polish recorded"),
        "{}",
        stdout(&gated)
    );
}

#[test]
fn a_record_for_one_branch_does_not_cover_another() {
    let (_scratch, repo, markers) = repo("other-branch");
    let recorded = record(&markers, &repo, FULL_RECORD);
    assert_eq!(recorded.status.code(), Some(0), "{recorded:?}");
    git_in(&repo, &["checkout", "-q", "-b", "feat/b"]);

    let gated = gate(&markers, &repo, "gh pr create -t a -b b");
    assert_eq!(gated.status.code(), Some(0));
    assert!(
        stdout(&gated).contains("No polish recorded"),
        "{}",
        stdout(&gated)
    );
}

#[test]
fn an_explicit_branch_record_covers_a_ship_from_a_subshell() {
    // The record's `--repo-root`/`--branch` spelling and the gate's
    // per-segment directory (cadence-hooks#997) must land on one key.
    let (_scratch, repo, markers) = repo("explicit-branch");
    let recorded = record(
        &markers,
        &markers,
        &[
            "--repo-root",
            repo.to_str().unwrap(),
            "--branch",
            "feat/a",
            "--fresh",
            "--arm",
            "security=ran",
            "--arm-model",
            "security=opus",
        ],
    );
    assert_eq!(recorded.status.code(), Some(0), "{recorded:?}");

    let parent = repo.parent().unwrap();
    let gated = gate(&markers, parent, "(cd repo && gh pr create -t a -b b)");
    assert_eq!(gated.status.code(), Some(0));
    assert_eq!(stdout(&gated), "", "{}", stdout(&gated));
}

#[test]
fn an_unattested_security_record_on_a_code_branch_asks_for_the_family() {
    // cadence-hooks#785, through both halves: a record without
    // `--arm-model` is accepted, and the gate asks for the attestation.
    let (_scratch, repo, markers) = repo("unattested");
    let recorded = record(&markers, &repo, &["--fresh", "--arm", "security=ran"]);
    assert_eq!(recorded.status.code(), Some(0), "{recorded:?}");

    let gated = gate(&markers, &repo, "gh pr create -t a -b b");
    assert_eq!(gated.status.code(), Some(0));
    let out = stdout(&gated);
    assert!(out.contains("not which model family"), "{out}");
    assert!(!out.contains("No polish recorded"), "{out}");
}
