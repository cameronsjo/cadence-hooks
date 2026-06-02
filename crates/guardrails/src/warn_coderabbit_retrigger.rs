//! Warn that `@coderabbitai review` comments don't force a fresh review.
//!
//! CodeRabbit's incremental review is content-cached, not SHA-cached. A
//! re-trigger comment posts "Review triggered" but submits nothing when the
//! head's content was already reviewed. The reliable way to force a fresh
//! pass is pushing a new commit (including force-push after a rebase).

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges that CodeRabbit re-trigger comments are no-ops on reviewed content.
pub struct WarnCoderabbitRetrigger;

/// Does the (quote-stripped) command invoke a gh comment subcommand?
///
/// Requires both `gh` and `comment` as standalone tokens, so commit messages
/// and other commands that merely *mention* CodeRabbit never match.
fn is_gh_comment(stripped: &str) -> bool {
    let tokens: Vec<&str> = stripped.split_whitespace().collect();
    tokens.contains(&"gh") && tokens.contains(&"comment")
}

/// Is the comment body a CodeRabbit re-review trigger?
///
/// Checked against the *raw* command because the trigger phrase lives inside
/// the quoted `--body` value. `@coderabbitai resolve` and other commands are
/// not review triggers.
fn is_review_trigger(raw: &str) -> bool {
    raw.contains("@coderabbitai")
        && (raw.contains("@coderabbitai review") || raw.contains("full review"))
}

impl Check for WarnCoderabbitRetrigger {
    fn name(&self) -> &str {
        "warn-coderabbit-retrigger"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("coderabbitai") {
            return CheckResult::allow();
        }

        let stripped = strip_quotes(command);

        if !is_gh_comment(&stripped) || !is_review_trigger(command) {
            return CheckResult::allow();
        }

        CheckResult::nudge(
            "CodeRabbit's incremental review is content-cached, not SHA-cached — \
             '@coderabbitai review' posts \"Review triggered\" but submits nothing when this \
             content was already reviewed. To force a fresh pass, push a new commit (including \
             a force-push after a rebase); expect the review ~30 seconds after a real push.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    // --- guard clause: non-matching commands stay allowed ---

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnCoderabbitRetrigger.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        let result = WarnCoderabbitRetrigger.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn plain_pr_comment_allowed() {
        let result =
            WarnCoderabbitRetrigger.run(&make_bash("gh pr comment 5 --body \"LGTM, merging\""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn coderabbit_resolve_command_allowed() {
        // @coderabbitai resolve is not a re-review trigger
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "gh pr comment 5 --body \"@coderabbitai resolve\"",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn commit_message_mentioning_coderabbit_review_allowed() {
        // Commit messages routinely reference CodeRabbit review feedback —
        // not a re-trigger attempt.
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "git commit -m \"fix: address @coderabbitai review findings\"",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- happy path: re-trigger comments nudge ---

    #[test]
    fn coderabbit_review_comment_nudges() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "gh pr comment 5 --body \"@coderabbitai review\"",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn coderabbit_full_review_comment_nudges() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "gh pr comment 5 --body '@coderabbitai full review'",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn coderabbit_review_with_repo_flag_nudges() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "gh pr comment 12 -R cameronsjo/cadence --body \"@coderabbitai review\"",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn coderabbit_review_in_chain_nudges() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "cd /repo && gh pr comment 5 --body \"@coderabbitai review\"",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- nudge message quality ---

    #[test]
    fn nudge_message_explains_content_caching() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(
            "gh pr comment 5 --body \"@coderabbitai review\"",
        ));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("content-cached"),
            "nudge should explain the caching behavior: {msg}"
        );
        assert!(
            msg.contains("push a new commit") || msg.contains("Push a new commit"),
            "nudge should give the fix: {msg}"
        );
    }

    // --- edge cases ---

    #[test]
    fn empty_command_allowed() {
        let result = WarnCoderabbitRetrigger.run(&make_bash(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_comments_allowed() {
        // Reading comments that happen to mention CodeRabbit is not a trigger
        let result = WarnCoderabbitRetrigger.run(&make_bash("gh pr view 5 --comments"));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
