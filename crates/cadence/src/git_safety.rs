use claude_hooks_core::{Check, CheckResult, HookInput};

/// Commands that are always blocked — destructive with no undo.
const BLOCKED_COMMANDS: &[&str] = &[
    "git push --force origin main",
    "git push --force origin master",
    "git push -f origin main",
    "git push -f origin master",
    "git push origin main --force",
    "git push origin master --force",
    "git push origin main -f",
    "git push origin master -f",
    "git reset --hard",
    "git checkout -- .",
    "git clean -fd",
    "git clean -df",
    "git clean -f",
    "git reflog expire --expire=now --all",
    "git gc --prune=now",
    "git branch -D main",
    "git branch -D master",
];

/// Regex-style patterns for blocked commands (rebase main/master).
const BLOCKED_REGEX_FRAGMENTS: &[(&str, &str)] = &[
    ("git rebase", "main"),
    ("git rebase", "master"),
];

/// Commands that trigger a warning but are allowed.
const WARNING_PATTERNS: &[&str] = &[
    "git push --force",
    "git push -f",
    "git reset",
    "git rebase",
    "git commit --amend",
    "git stash drop",
    "git stash clear",
    "git branch -d",
    "git branch -D",
    "git remote remove",
    "git remote rm",
];

pub struct GitSafetyGuard;

impl Check for GitSafetyGuard {
    fn name(&self) -> &str {
        "git-safety"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("git") {
            return CheckResult::allow();
        }

        let lower = command.to_lowercase();

        // Check absolute blocks first
        for blocked in BLOCKED_COMMANDS {
            if lower.contains(blocked) {
                return CheckResult::block(format!(
                    "🚫 BLOCKED: Dangerous git operation detected.\n\n\
                     Command: {command}\n\n\
                     This operation could cause data loss or rewrite shared history.\n\
                     If you really need to do this, run it manually outside Claude Code."
                ));
            }
        }

        // Check regex-style blocks (rebase main/master)
        for (prefix, suffix) in BLOCKED_REGEX_FRAGMENTS {
            if lower.contains(prefix) && lower.contains(suffix) {
                return CheckResult::block(format!(
                    "🚫 BLOCKED: Dangerous git operation detected.\n\n\
                     Command: {command}\n\n\
                     This operation could cause data loss or rewrite shared history.\n\
                     If you really need to do this, run it manually outside Claude Code."
                ));
            }
        }

        // Check warnings
        for pattern in WARNING_PATTERNS {
            if lower.contains(pattern) {
                return CheckResult::warn(format!(
                    "⚠️  Git operation may modify history or lose work: {command}"
                ));
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bash_input(command: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some(command.into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn normal_git_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin feature-branch"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn force_push_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin main"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git reset --hard"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase main"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn amend_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git commit --amend"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn force_push_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin feature"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn non_git_command_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("ls -la"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }
}
