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

/// The metrics root: `${HOME:-/tmp}/.claude/metrics`.
pub fn metrics_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".claude").join("metrics")
}

/// The per-session state directory: `<metrics_dir>/state`.
pub fn state_dir() -> PathBuf {
    metrics_dir().join("state")
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
pub fn branch(cwd: Option<&str>) -> String {
    git_output(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_default()
}

/// Repo basename: the final path component of `cwd`, or the process cwd's.
pub fn repo_basename(cwd: Option<&str>) -> String {
    let dir = match cwd {
        Some(d) if Path::new(d).is_dir() => PathBuf::from(d),
        _ => std::env::current_dir().unwrap_or_default(),
    };
    dir.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Current UTC timestamp, ISO 8601 second precision (`%Y-%m-%dT%H:%M:%SZ`).
///
/// Shells out to `date -u` to match the bash hooks exactly and avoid pulling a
/// date/time crate into the workspace. Falls back to an empty string if `date`
/// is somehow unavailable — the line is still written, just without a `ts`.
pub fn utc_timestamp() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
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
    fn timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        // e.g. 2026-05-19T00:51:45Z — 20 chars, ends in Z.
        assert!(ts.ends_with('Z'), "timestamp should end in Z: {ts}");
        assert_eq!(ts.len(), 20, "ISO second-precision UTC is 20 chars: {ts}");
    }
}
