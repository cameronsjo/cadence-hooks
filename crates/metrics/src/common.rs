//! Shared helpers for the metrics loggers: git-commit detection, git queries,
//! metrics directory resolution, and timestamps.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Matches `git commit` and `git -C <dir> commit`, after a start-of-string or a
/// shell separator, while ignoring `git commit-tree` and similar. Ported from
/// the bash `grep -E` pattern.
fn commit_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|[\s;&|])git\s+(-C\s+\S+\s+)?commit(\s|$)")
            .expect("commit regex must compile")
    })
}

/// True when `command` invokes `git commit` (not `git commit-tree`, etc.).
pub fn is_git_commit(command: &str) -> bool {
    commit_regex().is_match(command)
}

/// The metrics root: `<config_dir>/metrics`, where `<config_dir>` honors
/// `CLAUDE_CONFIG_DIR` (else `~/.claude`).
pub fn metrics_dir() -> PathBuf {
    cadence_hooks_core::paths::claude_config_dir().join("metrics")
}

/// The per-session state directory: `<metrics_dir>/state`.
pub fn state_dir() -> PathBuf {
    metrics_dir().join("state")
}

/// True when `session_id` is safe to embed in a state filename — non-empty and
/// composed only of ASCII alphanumerics, `-`, or `_`. Session IDs are UUID-like;
/// anything containing path separators or `..` is rejected so a malformed or
/// hostile payload can never steer a write outside [`state_dir`].
pub fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Build a `git` command rooted at `cwd` when it's an existing directory,
/// otherwise inheriting the process working directory (mirrors the bash
/// `cd "$cwd" && git ...` / bare-`git` fallback).
fn git_in(cwd: Option<&str>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd
        && Path::new(dir).is_dir()
    {
        cmd.current_dir(dir);
    }
    cmd
}

/// Run a git command and return its trimmed stdout, or `None` on failure or
/// empty output.
fn git_output(cwd: Option<&str>, args: &[&str]) -> Option<String> {
    let output = git_in(cwd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Current `HEAD` SHA in `cwd`.
pub fn head_sha(cwd: Option<&str>) -> Option<String> {
    git_output(cwd, &["rev-parse", "HEAD"])
}

/// Current branch name in `cwd` (empty string on detached HEAD or failure).
///
/// Uses `symbolic-ref --quiet --short HEAD`, which exits non-zero on a detached
/// HEAD — so [`git_output`] yields `None` and we return empty, as documented.
/// (`rev-parse --abbrev-ref HEAD` would return the literal string `"HEAD"`.)
pub fn branch(cwd: Option<&str>) -> String {
    git_output(cwd, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default()
}

/// Repo name: the basename of the git worktree root (`rev-parse --show-toplevel`)
/// so a subdirectory name is never logged as the repo. Falls back to the
/// `cwd`/process-directory basename when not inside a git repo.
pub fn repo_basename(cwd: Option<&str>) -> String {
    let dir = match git_output(cwd, &["rev-parse", "--show-toplevel"]) {
        Some(toplevel) => PathBuf::from(toplevel),
        None => match cwd {
            Some(d) if Path::new(d).is_dir() => PathBuf::from(d),
            _ => std::env::current_dir().unwrap_or_default(),
        },
    };
    dir.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Current UTC timestamp, ISO 8601 second precision (`%Y-%m-%dT%H:%M:%SZ`).
///
/// Re-exports the canonical [`cadence_hooks_core::time::utc_timestamp`] so every
/// logger shares one timestamp source (jiff-backed, portable to Windows).
pub fn utc_timestamp() -> String {
    cadence_hooks_core::time::utc_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_plain_git_commit() {
        assert!(is_git_commit("git commit -m 'x'"));
        assert!(is_git_commit("git commit"));
    }

    #[test]
    fn detects_git_c_commit() {
        assert!(is_git_commit("git -C /some/repo commit -m x"));
    }

    #[test]
    fn detects_commit_after_separator() {
        assert!(is_git_commit("cd repo && git commit -m x"));
        assert!(is_git_commit("foo; git commit"));
    }

    #[test]
    fn ignores_commit_tree() {
        assert!(!is_git_commit("git commit-tree abc123"));
    }

    #[test]
    fn ignores_non_commit_git() {
        assert!(!is_git_commit("git status"));
        assert!(!is_git_commit("git push origin main"));
    }

    #[test]
    fn ignores_unrelated_commands() {
        assert!(!is_git_commit("echo committing changes"));
        assert!(!is_git_commit("ls -la"));
    }

    #[test]
    fn safe_session_id_accepts_uuid_like() {
        assert!(is_safe_session_id("a1b2c3d4-5e6f-7890-abcd-ef0123456789"));
        assert!(is_safe_session_id("session_42"));
        assert!(is_safe_session_id("ABC-123_xyz"));
    }

    #[test]
    fn safe_session_id_rejects_traversal_and_separators() {
        assert!(!is_safe_session_id(""));
        assert!(!is_safe_session_id(".."));
        assert!(!is_safe_session_id("../../etc/passwd"));
        assert!(!is_safe_session_id("a/b"));
        assert!(!is_safe_session_id("a.before")); // '.' is not allowed
        assert!(!is_safe_session_id("with space"));
        assert!(!is_safe_session_id("/abs"));
    }

    #[test]
    fn timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        // e.g. 2026-05-19T00:51:45Z — 20 chars, ends in Z.
        assert!(ts.ends_with('Z'), "timestamp should end in Z: {ts}");
        assert_eq!(ts.len(), 20, "ISO second-precision UTC is 20 chars: {ts}");
    }
}
