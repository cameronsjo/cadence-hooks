//! Warn about untracked files during git commit operations.
//!
//! Shells out to `git ls-files --others --exclude-standard` to detect
//! files that might have been forgotten. Filters out build artifacts.

use claude_hooks_core::{Check, CheckResult, HookInput};
use std::process::Command;

/// Build artifact extensions to filter from untracked file warnings.
const BUILD_ARTIFACT_EXTENSIONS: &[&str] = &[
    "log", "tmp", "cache", "pyc", "class", "o", "a", "so", "dylib",
];

/// Warns when git commit runs with untracked files that may have been forgotten.
pub struct WarnUntrackedFiles;

impl Check for WarnUntrackedFiles {
    fn name(&self) -> &str {
        "warn-untracked-files"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Only trigger on git add/commit
        if !command.starts_with("git add") && !command.starts_with("git commit") {
            return CheckResult::allow();
        }

        // Get untracked files from git
        let output = match Command::new("git").args(["status", "--porcelain"]).output() {
            Ok(out) => out,
            Err(_) => return CheckResult::allow(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Filter to untracked files (lines starting with ??)
        let untracked: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("??"))
            .map(|line| line.trim_start_matches("?? "))
            .collect();

        if untracked.is_empty() {
            return CheckResult::allow();
        }

        // Filter out build artifacts
        let important: Vec<&&str> = untracked
            .iter()
            .filter(|file| {
                !BUILD_ARTIFACT_EXTENSIONS
                    .iter()
                    .any(|ext| file.ends_with(&format!(".{ext}")))
            })
            .collect();

        if important.is_empty() {
            return CheckResult::allow();
        }

        let count = important.len();
        let mut msg = format!("⚠️  Warning: {count} untracked file(s) detected\n\n");
        msg.push_str("These files may need to be included in your commit:\n");
        for file in &important {
            msg.push_str(&format!("  ?? {file}\n"));
        }

        CheckResult::warn(msg)
    }
}
