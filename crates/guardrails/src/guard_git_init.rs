//! Detect `git init` and prompt for project scaffolding.
//!
//! When a new repository is initialised, this check reminds the user to run
//! `/a-star-is-born` so the repo starts with standard project files.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Warns when `git init` is detected so the user can scaffold project standards.
pub struct GuardGitInit;

impl Check for GuardGitInit {
    fn name(&self) -> &str {
        "guard-git-init"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("git") || !command.contains("init") {
            return CheckResult::allow();
        }

        // Simple regex-free check: "git init" as a standalone command
        let words: Vec<&str> = command.split_whitespace().collect();
        let has_git_init = words.windows(2).any(|w| w[0] == "git" && w[1] == "init");

        if has_git_init {
            return CheckResult::nudge(
                "New repo detected. Run /a-star-is-born to scaffold project standards \
                 (.gitignore, README, CONTRIBUTING, CHANGELOG, LICENSE, Makefile, linting, CI/CD).",
            );
        }

        CheckResult::allow()
    }
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

    #[test]
    fn git_init_detected() {
        let result = GuardGitInit.run(&make_bash("git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_with_path() {
        let result = GuardGitInit.run(&make_bash("git init my-project"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn normal_command_passes() {
        let result = GuardGitInit.run(&make_bash("git status"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GuardGitInit.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn init_without_git_allowed() {
        let result = GuardGitInit.run(&make_bash("npm init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_without_init_allowed() {
        let result = GuardGitInit.run(&make_bash("git commit -m 'initial'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_with_branch() {
        let result = GuardGitInit.run(&make_bash("git init -b main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_in_chain() {
        // "git" and "init" both present but not adjacent as "git init"
        // The command is "mkdir proj && git init" — "git init" IS adjacent here
        let result = GuardGitInit.run(&make_bash("mkdir proj && git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn git_and_init_non_adjacent_allowed() {
        // "git" and "init" both present but not adjacent
        let result = GuardGitInit.run(&make_bash("git submodule init"));
        // "git" and "submodule" are adjacent, then "submodule" and "init"
        // windows(2) checks: [git, submodule], [submodule, init] — neither is [git, init]
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn terraform_init_not_detected() {
        // "init" without "git" — should pass the !contains("git") check
        let result = GuardGitInit.run(&make_bash("terraform init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_bare_warned() {
        let result = GuardGitInit.run(&make_bash("git init --bare"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_reinit_warned() {
        // Re-init existing repo
        let result = GuardGitInit.run(&make_bash("cd /project && git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }
}
