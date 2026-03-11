//! Warn when editing on the main branch without a feature branch.
//!
//! Fires once per session (tracked via a temp-file marker) to nudge the
//! user toward creating a feature branch before making changes.

use claude_hooks_core::{Check, CheckResult, HookInput};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;

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
        let ppid = std::process::id();

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

        if branch != "main" && branch != "master" {
            return CheckResult::allow();
        }

        // Check if already warned this session
        if let Some(marker) = Self::marker_path() {
            if marker.exists() {
                return CheckResult::allow();
            }
            // Create marker to suppress future warnings
            let _ = std::fs::write(&marker, "");
        }

        CheckResult::warn(format!(
            "You're editing files directly on '{branch}'. \
             Ask the user: should this work be on a feature branch instead?"
        ))
    }
}
