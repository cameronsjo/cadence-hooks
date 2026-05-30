//! Nudge to run `/polish` before creating a pull request.
//!
//! Fires on `gh pr create` and reminds the model that
//! [cadence-forge:polish](https://github.com/cameronsjo/cadence-forge) runs a
//! branch-scoped polish pass against `origin/main` — simplifying code,
//! tightening narrative logging, filling test gaps, and updating docs.
//! Skippable when the change is trivial or polish has already been run.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges to run `/polish` (cadence-forge:polish) before opening a PR.
pub struct NudgePolishBeforePr;

impl Check for NudgePolishBeforePr {
    fn name(&self) -> &str {
        "nudge-polish-before-pr"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !is_gh_pr_create(command) {
            return CheckResult::allow();
        }

        CheckResult::nudge(
            "Before opening this PR, consider running `/polish` — a branch-scoped \
             polish pass (cadence-forge:polish) that simplifies code, tightens \
             narrative logging, fills test gaps, and updates docs against \
             `origin/main`. Skip only if this is a trivial fix or polish has \
             already been run on this branch."
                .to_string(),
        )
    }
}

/// Returns true if `command` contains a `gh pr create` token sequence.
///
/// Token-based to avoid substring false positives (e.g. branch names
/// containing the literal string `gh-pr-create`).
fn is_gh_pr_create(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .windows(3)
        .any(|w| w[0] == "gh" && w[1] == "pr" && w[2] == "create")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{Outcome, test_builders::make_bash};

    #[test]
    fn gh_pr_create_nudges() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr create --title test"));
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"), "message should mention /polish");
    }

    #[test]
    fn gh_pr_create_with_heredoc_body_nudges() {
        let cmd = "gh pr create --title test --body \"$(cat <<'EOF'\n## Summary\nfoo\nEOF\n)\"";
        let result = NudgePolishBeforePr.run(&make_bash(cmd));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_list_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr list"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr view 123"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_review_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr review 123 --approve"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_issue_create_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh issue create --title test"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn git_command_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("git commit -m 'gh pr create'"));
        // Token detection: "gh pr create" appears as substring inside a single-quoted
        // arg but split_whitespace yields ["git", "commit", "-m", "'gh", "pr", "create'"].
        // The window check requires exact "gh", "pr", "create" — quoted tokens fail.
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = NudgePolishBeforePr.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn branch_name_with_pr_create_substring_allowed() {
        // Branch named gh-pr-create-experiments shouldn't fire.
        let result = NudgePolishBeforePr.run(&make_bash("git checkout gh-pr-create-experiments"));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
