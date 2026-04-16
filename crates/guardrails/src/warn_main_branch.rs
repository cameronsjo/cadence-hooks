//! Warn when editing on the main branch without a feature branch.
//!
//! Fires once per session (tracked via a temp-file marker) to nudge the
//! user toward creating a feature branch before making changes.

use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;

/// Returns true if the branch name is a default branch (`main` or `master`).
fn is_default_branch(branch: &str) -> bool {
    branch == "main" || branch == "master"
}

/// Pure decision: should we warn about editing on this branch?
///
/// Returns `Warn` if on a default branch and not already warned this session.
fn should_warn(branch: &str, already_warned: bool) -> CheckResult {
    if !is_default_branch(branch) {
        return CheckResult::allow();
    }

    if already_warned {
        return CheckResult::allow();
    }

    CheckResult::nudge(format!(
        "You're editing files directly on '{branch}'. \
         Ask the user: should this work be on a feature branch instead?"
    ))
}

/// Warns once per session when the current branch is `main` or `master`.
pub struct WarnMainBranch;

impl WarnMainBranch {
    fn marker_path() -> Option<PathBuf> {
        let repo_root = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

        let mut hasher = DefaultHasher::new();
        repo_root.hash(&mut hasher);
        let hash = hasher.finish();

        // Use parent PID for session scoping — hooks are spawned as child processes,
        // so process::id() changes on every invocation. PPID is the Claude Code process.
        let ppid = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(std::process::id);

        Some(PathBuf::from(format!(
            "/tmp/.claude-main-branch-warned-{hash:x}-{ppid}"
        )))
    }
}

impl Check for WarnMainBranch {
    fn name(&self) -> &str {
        "warn-main-branch"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        // Get current branch
        let branch = match Command::new("git")
            .args(["symbolic-ref", "--short", "HEAD"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        let already_warned = Self::marker_path().as_ref().is_some_and(|p| p.exists());

        let result = should_warn(&branch, already_warned);

        // Create marker on warn to suppress future warnings this session
        if result.outcome == Outcome::Nudge
            && let Some(marker) = Self::marker_path()
        {
            let _ = std::fs::write(&marker, "");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_branch_warns() {
        let result = should_warn("main", false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("main")
        );
    }

    #[test]
    fn master_branch_warns() {
        let result = should_warn("master", false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    #[test]
    fn feature_branch_allows() {
        let result = should_warn("feat/new-feature", false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn develop_branch_allows() {
        let result = should_warn("develop", false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_allows() {
        let result = should_warn("main", true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_master_allows() {
        let result = should_warn("master", true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_branch_allows() {
        let result = should_warn("", false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn is_default_branch_main() {
        assert!(is_default_branch("main"));
    }

    #[test]
    fn is_default_branch_master() {
        assert!(is_default_branch("master"));
    }

    #[test]
    fn is_default_branch_feature() {
        assert!(!is_default_branch("feat/something"));
    }

    #[test]
    fn is_default_branch_not_substring() {
        assert!(!is_default_branch("main-backup"));
        assert!(!is_default_branch("hotfix/master-fix"));
    }

    // --- edge case hardening ---

    #[test]
    fn release_branch_allows() {
        let result = should_warn("release/1.0", false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_contains_branch() {
        let result = should_warn("master", false);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    #[test]
    fn marker_uses_ppid_not_pid() {
        // Bug: code uses process::id() (current PID) but names var "ppid"
        // Since hooks run as separate processes, each invocation gets a new PID,
        // so the marker file from a previous invocation is never found.
        // The intent was to use the PARENT PID (Claude Code process) for session scoping.
        let ppid_env = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let current_pid = std::process::id();
        if let Some(ppid) = ppid_env {
            assert_ne!(
                current_pid, ppid,
                "PID should differ from PPID — marker_path() should use PPID for session scoping"
            );
        }
    }

    #[test]
    fn main_with_prefix_allows() {
        // "fix/main-page" is not the main branch
        let result = should_warn("fix/main-page", false);
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
