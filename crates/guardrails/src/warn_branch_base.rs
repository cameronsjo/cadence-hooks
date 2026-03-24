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
            return CheckResult::nudge(format!(
                "⚠️  Creating branch from `{base}`, not main.\n   \
                 If this is intentional (stacked branch), proceed.\n   \
                 Otherwise: `git checkout main && git pull` first."
            ));
        }

        // No explicit base — check current branch in the hook's working directory
        let current = match current_branch(input.cwd.as_deref()) {
            Some(b) => b,
            None => return CheckResult::allow(),
        };

        if is_main_branch(&current) {
            return CheckResult::allow();
        }

        CheckResult::nudge(format!(
            "⚠️  Creating branch from `{current}`, not main.\n   \
             If this is intentional (stacked branch), proceed.\n   \
             Otherwise: `git checkout main && git pull` first."
        ))
    }
}

/// Check if command creates a new branch.
fn is_branch_create(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // git checkout -b/-B <name>
    let has_checkout_b = tokens
        .windows(3)
        .any(|w| w[0] == "git" && w[1] == "checkout" && (w[2] == "-b" || w[2] == "-B"));

    // git switch -c/-C/--create <name>
    let has_switch_c = tokens.windows(3).any(|w| {
        w[0] == "git" && w[1] == "switch" && (w[2] == "-c" || w[2] == "-C" || w[2] == "--create")
    });

    has_checkout_b || has_switch_c
}

/// Extract explicit base branch if provided.
/// `git checkout -b feat main` → Some("main")
/// `git checkout -b feat` → None
fn explicit_base(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Find the -b/-B or -c/-C/--create flag, then the branch name is next.
    // After that, skip any flags (e.g. --track, -t) to find the base.
    for (i, token) in tokens.iter().enumerate() {
        if (*token == "-b"
            || *token == "-B"
            || *token == "-c"
            || *token == "-C"
            || *token == "--create")
            && i >= 1
            && (tokens[i - 1] == "checkout" || tokens[i - 1] == "switch")
        {
            // tokens[i+1] = new branch name; scan past flags (--track, -t) to find base
            for candidate in tokens.iter().skip(i + 2) {
                if !candidate.starts_with('-') {
                    return Some(candidate.to_string());
                }
            }
            return None;
        }
    }
    None
}

/// Recognized main branch refs. Only exact matches are accepted to avoid
/// false positives like `origin/feature/main`.
const MAIN_BRANCH_REFS: &[&str] = &[
    "main",
    "master",
    "origin/main",
    "origin/master",
    "upstream/main",
    "upstream/master",
];

fn is_main_branch(name: &str) -> bool {
    MAIN_BRANCH_REFS.contains(&name)
}

fn current_branch(cwd: Option<&str>) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(["branch", "--show-current"]);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.output()
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

    #[test]
    fn explicit_base_after_track_flag() {
        assert_eq!(
            explicit_base("git checkout -b feature --track origin/develop"),
            Some("origin/develop".to_string())
        );
    }

    #[test]
    fn explicit_base_after_short_track_flag() {
        assert_eq!(
            explicit_base("git switch -c feature -t origin/main"),
            Some("origin/main".to_string())
        );
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

    #[test]
    fn upstream_main_is_main() {
        assert!(is_main_branch("upstream/main"));
    }

    #[test]
    fn arbitrary_remote_master_is_not_main() {
        // Only origin/ and upstream/ prefixes are recognized
        assert!(!is_main_branch("fork/master"));
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
        assert!(result.message.unwrap().contains("develop"));
    }

    #[test]
    fn switch_explicit_master_allowed() {
        let result = WarnBranchBase.run(&make_bash("git switch -c feature master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Bug 5a: -B and -C (force variants) ---

    #[test]
    fn checkout_force_b_detected() {
        assert!(is_branch_create("git checkout -B feature"));
    }

    #[test]
    fn switch_force_c_detected() {
        assert!(is_branch_create("git switch -C feature"));
    }

    #[test]
    fn explicit_base_with_force_b() {
        assert_eq!(
            explicit_base("git checkout -B feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn explicit_base_with_force_c() {
        assert_eq!(
            explicit_base("git switch -C feature origin/main"),
            Some("origin/main".to_string())
        );
    }

    // --- Bug 5b: is_main_branch over-match ---

    #[test]
    fn feature_main_is_not_main() {
        // origin/feature/main should NOT be treated as a main branch
        assert!(!is_main_branch("origin/feature/main"));
    }

    #[test]
    fn feature_slash_master_is_not_main() {
        assert!(!is_main_branch("origin/hotfix/master"));
    }

    #[test]
    fn upstream_master_is_main() {
        assert!(is_main_branch("upstream/master"));
    }
}
