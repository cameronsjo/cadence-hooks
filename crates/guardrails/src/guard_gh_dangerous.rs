use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

static GH_REPO_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh\s+repo\s+delete\b").expect("pattern should compile"));

static EXEC_WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(bash|sh|zsh)\s+-c\b").expect("pattern should compile"));

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
        if GH_REPO_DELETE.is_match(&stripped) {
            return CheckResult::block(
                "🚫 git-guardrails: gh repo delete is blocked\n   \
                 Repository deletion is irreversible — delete manually via github.com",
            );
        }

        // Pass 2: inside exec wrappers (bash -c "gh repo delete ...")
        if EXEC_WRAPPER.is_match(&stripped) && GH_REPO_DELETE.is_match(command) {
            return CheckResult::block(
                "🚫 git-guardrails: gh repo delete is blocked\n   \
                 Repository deletion is irreversible — delete manually via github.com",
            );
        }

        CheckResult::allow()
    }
}

fn strip_quotes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '"' {
                        break;
                    }
                }
            }
            '\'' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\'' {
                        break;
                    }
                }
            }
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
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
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_in_exec_wrapper_blocked() {
        let result =
            GhDangerousGuard.run(&make_bash("bash -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_in_quotes_not_blocked() {
        let result =
            GhDangerousGuard.run(&make_bash("echo \"don't gh repo delete anything\""));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn normal_gh_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh pr list"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GhDangerousGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn zsh_wrapper_blocked() {
        let result =
            GhDangerousGuard.run(&make_bash("zsh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn sh_wrapper_blocked() {
        let result =
            GhDangerousGuard.run(&make_bash("sh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    // strip_quotes tests
    #[test]
    fn strip_double_quotes() {
        assert_eq!(strip_quotes("echo \"hello\" world"), "echo  world");
    }

    #[test]
    fn strip_single_quotes() {
        assert_eq!(strip_quotes("echo 'hello' world"), "echo  world");
    }

    #[test]
    fn strip_empty_quotes() {
        assert_eq!(strip_quotes("echo \"\" world"), "echo  world");
    }

    #[test]
    fn strip_no_quotes() {
        assert_eq!(strip_quotes("echo hello"), "echo hello");
    }

    #[test]
    fn strip_unmatched_quote_consumes_rest() {
        // Unmatched quote consumes everything after it
        let result = strip_quotes("echo \"unterminated");
        assert_eq!(result, "echo ");
    }
}
