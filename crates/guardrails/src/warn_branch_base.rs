//! Warn when creating a branch from a non-main base.
//!
//! Detects `git checkout -b` and `git switch -c` commands and checks
//! whether the current branch is `main` or `master`. Nudges to switch
//! to main first to avoid stacking branches.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::process::Command;

/// Warns when creating a new branch from a non-main base.
pub struct WarnBranchBase;

impl Check for WarnBranchBase {
    fn name(&self) -> &str {
        "warn-branch-base"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !is_branch_create(command) {
            return CheckResult::allow();
        }

        // If an explicit base is given (e.g., `git checkout -b feat main`), check that
        if let Some(base) = explicit_base(command) {
            if is_main_branch(&base) {
                return CheckResult::allow();
            }
            return CheckResult::warn(format!(
                "⚠️  Creating branch from `{base}`, not main.\n   \
                 If this is intentional (stacked branch), proceed.\n   \
                 Otherwise: `git checkout main && git pull` first."
            ));
        }

        // No explicit base — check current branch
        let current = match current_branch() {
            Some(b) => b,
            None => return CheckResult::allow(),
        };

        if is_main_branch(&current) {
            return CheckResult::allow();
        }

        CheckResult::warn(format!(
            "⚠️  Creating branch from `{current}`, not main.\n   \
             If this is intentional (stacked branch), proceed.\n   \
             Otherwise: `git checkout main && git pull` first."
        ))
    }
}

/// Check if command creates a new branch.
fn is_branch_create(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // git checkout -b <name>
    let has_checkout_b = tokens
        .windows(3)
        .any(|w| w[0] == "git" && w[1] == "checkout" && w[2] == "-b");

    // git switch -c <name> or git switch --create <name>
    let has_switch_c = tokens
        .windows(3)
        .any(|w| w[0] == "git" && w[1] == "switch" && (w[2] == "-c" || w[2] == "--create"));

    has_checkout_b || has_switch_c
}

/// Extract explicit base branch if provided.
/// `git checkout -b feat main` → Some("main")
/// `git checkout -b feat` → None
fn explicit_base(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Find the -b or -c/--create flag, then the branch name is next, and base is after that
    for (i, token) in tokens.iter().enumerate() {
        if (*token == "-b" || *token == "-c" || *token == "--create")
            && i >= 1
            && (tokens[i - 1] == "checkout" || tokens[i - 1] == "switch")
        {
            // tokens[i+1] = new branch name, tokens[i+2] = base (if present)
            if i + 2 < tokens.len() {
                let candidate = tokens[i + 2];
                // Skip if it looks like a flag
                if !candidate.starts_with('-') {
                    return Some(candidate.to_string());
                }
            }
            return None;
        }
    }
    None
}

fn is_main_branch(name: &str) -> bool {
    let name = name.strip_prefix("origin/").unwrap_or(name);
    name == "main" || name == "master"
}

fn current_branch() -> Option<String> {
    Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some(cmd.into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    // --- is_branch_create ---

    #[test]
    fn checkout_b_detected() {
        assert!(is_branch_create("git checkout -b feature"));
    }

    #[test]
    fn switch_c_detected() {
        assert!(is_branch_create("git switch -c feature"));
    }

    #[test]
    fn switch_create_detected() {
        assert!(is_branch_create("git switch --create feature"));
    }

    #[test]
    fn plain_checkout_not_detected() {
        assert!(!is_branch_create("git checkout main"));
    }

    #[test]
    fn plain_switch_not_detected() {
        assert!(!is_branch_create("git switch main"));
    }

    #[test]
    fn non_git_not_detected() {
        assert!(!is_branch_create("echo hello"));
    }

    // --- explicit_base ---

    #[test]
    fn explicit_base_present() {
        assert_eq!(
            explicit_base("git checkout -b feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn explicit_base_origin() {
        assert_eq!(
            explicit_base("git checkout -b feature origin/main"),
            Some("origin/main".to_string())
        );
    }

    #[test]
    fn no_explicit_base() {
        assert_eq!(explicit_base("git checkout -b feature"), None);
    }

    #[test]
    fn switch_explicit_base() {
        assert_eq!(
            explicit_base("git switch -c feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn flag_after_name_not_base() {
        assert_eq!(explicit_base("git checkout -b feature --track"), None);
    }

    // --- is_main_branch ---

    #[test]
    fn main_is_main() {
        assert!(is_main_branch("main"));
    }

    #[test]
    fn master_is_main() {
        assert!(is_main_branch("master"));
    }

    #[test]
    fn origin_main_is_main() {
        assert!(is_main_branch("origin/main"));
    }

    #[test]
    fn feature_is_not_main() {
        assert!(!is_main_branch("feature/cool-stuff"));
    }

    // --- Check::run ---

    #[test]
    fn non_branch_command_allowed() {
        let result = WarnBranchBase.run(&make_bash("git status"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = WarnBranchBase.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_main_base_allowed() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_origin_main_allowed() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature origin/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_non_main_base_warned() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature develop"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
        assert!(result.message.unwrap().contains("develop"));
    }

    #[test]
    fn switch_explicit_master_allowed() {
        let result = WarnBranchBase.run(&make_bash("git switch -c feature master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
