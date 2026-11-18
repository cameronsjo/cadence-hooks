//! `guard-gh-write` under the hook process's own environment: `GH_HOST`,
//! `GH_REPO` and `HOME`.
//!
//! This runs in a child process on purpose. Each of these is process-global,
//! and many guardrails unit tests read `default_host()`, `GH_REPO` or the
//! home directory without the env lock. Setting one inside that test binary
//! flipped their verdicts whenever the two overlapped. A child's environment
//! touches nothing else.

mod support;

use cadence_hooks_core::git_fixtures::{git_in, init_repo};
use std::io::Write;
use std::process::Stdio;

fn guard(command: &str, gh_host: &str) -> i32 {
    guard_in(command, "/tmp", &[("GH_HOST", gh_host)])
}

/// Run the guard on `command` from `cwd`, with `env` set on the child and
/// every other variable the guard reads cleared.
fn guard_in(command: &str, cwd: &str, env: &[(&str, &str)]) -> i32 {
    let scratch = tempfile::tempdir().expect("temp metrics dir");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": cwd,
    })
    .to_string();
    let mut cmd = support::cadence_hooks();
    cmd.args(["guardrails", "guard-gh-write"])
        // Ambient switches would exempt the guard and fake a pass.
        .env_remove("CADENCE_BYPASS")
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOWED_REPOS")
        .env_remove("CADENCE_EXTRA_HOSTS")
        .env_remove("CDPATH")
        // The guard reads both, so an exported one would move these verdicts.
        .env_remove("GH_REPO")
        .env_remove("GH_HOST")
        .env("CADENCE_ALLOWED_OWNERS", "cameronsjo")
        .env("CADENCE_METRICS_DIR", scratch.path());
    for (name, value) in env {
        cmd.env(name, value);
    }
    let mut child = cmd
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

fn checkout(dir: &std::path::Path, origin: &str) {
    std::fs::create_dir_all(dir).expect("create checkout dir");
    init_repo(dir);
    git_in(dir, &["remote", "add", "origin", origin]);
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

/// A `GH_HOST` set by the command itself, other than inline on the gh word,
/// is not read (the `gh-write-literal-targets-only` change): an `export`, a
/// bare reassignment of an inherited `GH_HOST`, and an `unset`. Each would
/// move the host of an owned `-R` onto one the allowlist does not cover, and
/// each allows. The inline control still blocks.
#[test]
fn a_gh_host_the_command_sets_is_not_read() {
    // Each row's owner is allowed only on the host the hook process names,
    // so reading the command's own `GH_HOST` would turn it into a block.
    for (command, env) in [
        (
            "export GH_HOST=evil.example.com && gh pr create -R cameronsjo/x --title t",
            &[][..],
        ),
        (
            "GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
            &[("GH_HOST", "github.com")][..],
        ),
        (
            "unset GH_HOST; gh pr create -R cameronsjo/x --title t",
            &[
                ("GH_HOST", "git.sjo.lol"),
                ("CADENCE_ALLOWED_OWNERS", "git.sjo.lol/cameronsjo"),
            ][..],
        ),
    ] {
        assert_eq!(guard_in(command, "/tmp", env), 0, "{command}");
    }
    assert_eq!(
        guard_in(
            "gh pr create -R cameronsjo/x --title t",
            "/tmp",
            &[("CADENCE_ALLOWED_OWNERS", "git.sjo.lol/cameronsjo")]
        ),
        2,
        "control: the pinned owner is not allowed on github.com, where unset would land"
    );
    assert_eq!(
        guard_in(
            "GH_HOST=evil.example.com gh pr create -R cameronsjo/x --title t",
            "/tmp",
            &[]
        ),
        2,
        "an inline GH_HOST is read"
    );
}

/// gh writes an un-flagged command to the `GH_REPO` it inherits, so the hook
/// process's own `GH_REPO` is judged: unowned blocks from an owned checkout,
/// owned allows, and a literal `-R` still outranks it.
#[test]
fn the_hook_process_gh_repo_is_judged() {
    let root = tempfile::tempdir().expect("temp root");
    let owned = root.path().join("owned");
    checkout(&owned, "https://github.com/cameronsjo/tool.git");
    let cwd = owned.to_str().expect("utf-8 path");
    let comment = "gh issue comment 1 --body hi";
    assert_eq!(
        guard_in(comment, cwd, &[]),
        0,
        "control: the owned checkout allows"
    );
    assert_eq!(guard_in(comment, cwd, &[("GH_REPO", "evil/x")]), 2);
    assert_eq!(guard_in(comment, cwd, &[("GH_REPO", "cameronsjo/x")]), 0);
    assert_eq!(
        guard_in(
            "gh issue comment 1 -R cameronsjo/tool --body hi",
            cwd,
            &[("GH_REPO", "evil/x")]
        ),
        0,
        "-R outranks GH_REPO"
    );
    assert_eq!(
        guard_in(
            "export GH_REPO=cameronsjo/tool; gh issue comment 1 --body hi",
            cwd,
            &[("GH_REPO", "evil/x")]
        ),
        0,
        "a literal export replaces the inherited GH_REPO"
    );
    // The deploy-key and autolink writes read it too (they take `-R`).
    for command in [
        "gh repo deploy-key delete 1",
        "gh repo autolink create KEY https://u",
    ] {
        assert_eq!(
            guard_in(command, cwd, &[("GH_REPO", "evil/x")]),
            2,
            "inherited GH_REPO on {command}"
        );
        assert_eq!(guard_in(command, cwd, &[]), 0, "control: {command}");
    }
}

/// `cd "$HOME/x"` lands where `cd ~/x` does, so a write after it is judged on
/// that checkout's remotes in every spelling bash expands. A `$HOME` bash
/// does not expand (`'$HOME/x'`), or one the command may have rebound, is a
/// directory the guard cannot follow and allows.
///
/// Runs on every platform, Windows included, with the same expected verdicts:
/// `$HOME` and `~` both expand against the child's `HOME` (the guard's
/// `user_home`), so on Windows both land on the same native path with `/up`
/// joined, and the guard reads that checkout's remotes the same way.
#[test]
fn a_home_cd_target_lands_where_the_tilde_does() {
    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("home");
    checkout(&home.join("up"), "https://github.com/evil/up.git");
    let owned = root.path().join("owned");
    checkout(&owned, "https://github.com/cameronsjo/tool.git");
    let cwd = owned.to_str().expect("utf-8 path");
    let env = [("HOME", home.to_str().expect("utf-8 path"))];
    for (command, expected) in [
        ("cd ~/up && gh pr create --title t", 2),
        ("cd \"$HOME/up\" && gh pr create --title t", 2),
        ("cd $HOME/up && gh issue comment 3 --body hi", 2),
        ("cd \"${HOME}\"/up && gh issue comment 3 --body hi", 2),
        ("cd '$HOME/up' && gh pr create --title t", 0),
        ("HOME=/x; cd \"$HOME/up\" && gh pr create --title t", 0),
        // A `HOME=` the command carries anywhere leaves the target unread,
        // even where it would not move the `cd` (over-reading, never a miss):
        // inline on the gh word, behind `env`, and on the `cd` itself.
        ("cd \"$HOME/up\" && HOME=/x gh pr create --title t", 0),
        ("cd \"$HOME/up\" && env HOME=/x gh pr create --title t", 0),
        ("HOME=/x cd \"$HOME/up\"; gh pr create --title t", 0),
        (
            "XDG_CONFIG_HOME=/x; cd \"$HOME/up\" && gh pr create --title t",
            2,
        ),
        ("gh pr create --title t", 0),
    ] {
        assert_eq!(guard_in(command, cwd, &env), expected, "{command}");
    }
}

/// With a home path that holds a space, bash splits an unquoted `$HOME/up`
/// into two words, so `cd` fails and the write after `;` runs in the owned
/// checkout: the guard leaves that target unread and allows. zsh would land
/// in `~/up` instead; that miss is an accepted gap. The quoted form is one
/// word and still lands in `~/up`.
#[test]
fn an_unquoted_home_with_a_space_is_left_unread() {
    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("with space");
    checkout(&home.join("up"), "https://github.com/evil/up.git");
    let owned = root.path().join("owned");
    checkout(&owned, "https://github.com/cameronsjo/tool.git");
    let cwd = owned.to_str().expect("utf-8 path");
    let env = [("HOME", home.to_str().expect("utf-8 path"))];
    for (command, expected) in [
        ("cd $HOME/up; gh pr create --title t", 0),
        ("cd \"$HOME/up\"; gh pr create --title t", 2),
        ("cd \"$HOME\"/up; gh pr create --title t", 2),
    ] {
        assert_eq!(guard_in(command, cwd, &env), expected, "{command}");
    }
}
