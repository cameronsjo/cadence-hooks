//! Block irreversible `gh` operations.
//!
//! `gh repo delete` is permanently destructive with no undo. This guard
//! blocks it in direct invocations and inside shell exec wrappers (`bash -c`).

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

static GH_REPO_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh\s+repo\s+delete\b").expect("pattern should compile"));

static EXEC_WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(bash|sh|zsh)\s+-c\b").expect("pattern should compile"));

/// Blocks `gh repo delete` and other irreversible GitHub CLI operations.
pub struct GhDangerousGuard;

impl Check for GhDangerousGuard {
    fn name(&self) -> &str {
        "guard-gh-dangerous"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("gh") {
            return CheckResult::allow();
        }

        // Strip quoted strings to avoid false positives from prose
        let stripped = strip_quotes(command);

        // Pass 1: direct invocation (after stripping quotes)
        if let Some(m) = GH_REPO_DELETE.find(&stripped) {
            return CheckResult::block(&format!(
                "🚫 git-guardrails: gh repo delete is blocked\n   \
                 Found: `{}`\n   \
                 Fix: delete manually via github.com — this is irreversible",
                m.as_str().trim(),
            ));
        }

        // Pass 2: inside exec wrappers (bash -c "gh repo delete ...")
        if EXEC_WRAPPER.is_match(&stripped) {
            if let Some(m) = GH_REPO_DELETE.find(command) {
                return CheckResult::block(&format!(
                    "🚫 git-guardrails: gh repo delete is blocked\n   \
                     Found: `{}`\n   \
                     Fix: delete manually via github.com — this is irreversible",
                    m.as_str().trim(),
                ));
            }
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
    fn direct_repo_delete_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_in_exec_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("bash -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_in_quotes_not_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo \"don't gh repo delete anything\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn normal_gh_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh pr list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GhDangerousGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn zsh_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("zsh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn sh_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("sh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Unhappy path: evasion scenarios ---

    #[test]
    fn repo_delete_in_single_quotes_not_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo 'gh repo delete is dangerous'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn repo_delete_with_confirm_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete my-repo --confirm"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_full_path_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete owner/my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn gh_repo_list_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo create my-new-repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_view_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo view owner/repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn repo_delete_in_chain_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo done && gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn no_tool_name_allowed() {
        let input = HookInput {
            tool_name: None,
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("gh repo delete".into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = GhDangerousGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- edge case hardening ---

    #[test]
    fn empty_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash(""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn whitespace_only_allowed() {
        let result = GhDangerousGuard.run(&make_bash("   "));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn word_boundary_hyphenated_allowed() {
        // "gh-repo-delete" is hyphenated, not "gh repo delete"
        let result = GhDangerousGuard.run(&make_bash("gh-repo-delete something"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn exec_wrapper_without_c_flag_still_blocked() {
        // Pass 1 catches "gh repo delete" anywhere in the stripped command,
        // regardless of whether it's inside an exec wrapper
        let result = GhDangerousGuard.run(&make_bash("bash script.sh gh repo delete"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_with_extra_spaces_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh  repo  delete  my-repo"));
        // Extra spaces between words — regex uses \s+ so this still matches
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
