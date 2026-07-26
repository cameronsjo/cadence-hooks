//! Pre-flight checklist nudge before `gh pr merge`.
//!
//! Three gotchas bite repeatedly when merging PRs from the CLI:
//!
//! 1. **Draft PRs silently block merge** — `gh pr view --json mergeable,mergeStateStatus`
//!    reports `MERGEABLE`/`CLEAN` on drafts, then the merge fails with
//!    `GraphQL: Pull Request is still a draft`. Only `isDraft` reveals it.
//! 2. **Worktree checkouts break `--delete-branch`** — the server-side merge
//!    succeeds, but gh's local checkout/branch-delete step fails when the
//!    branch (or main) is checked out in another worktree, leaving the remote
//!    branch undeleted.
//! 3. **A failed `gh pr merge` may have merged anyway** — always verify with
//!    `gh pr view <n> --json mergedAt,mergeCommit` before retrying or assuming
//!    failure.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges a pre-flight checklist on `gh pr merge`.
pub struct WarnGhMergePreflight;

/// Returns true if `command` contains a `gh pr merge` token sequence.
///
/// Token-based to avoid substring false positives (hyphenated script names,
/// prose). Caller is expected to strip quotes first.
fn is_gh_pr_merge(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .windows(3)
        .any(|w| w[0] == "gh" && w[1] == "pr" && w[2] == "merge")
}

impl Check for WarnGhMergePreflight {
    fn name(&self) -> &str {
        "warn-gh-merge-preflight"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("gh") {
            return CheckResult::allow();
        }

        // Strip quoted strings so prose mentioning the command doesn't fire.
        let stripped = strip_quotes(command);

        if !is_gh_pr_merge(&stripped) {
            return CheckResult::allow();
        }

        CheckResult::nudge(
            "gh pr merge preflight: (1) drafts report MERGEABLE but fail with a GraphQL error — \
             check `gh pr view <n> --json isDraft`, run `gh pr ready <n>` first; (2) a branch \
             checked out in any worktree makes `--delete-branch` fail locally after the \
             server-side merge — delete remotely instead: `git push origin --delete <branch>`; \
             (3) on any merge error, verify `gh pr view <n> --json mergedAt,mergeCommit` before \
             retrying — the merge may have landed.",
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
        let result = WarnGhMergePreflight.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr view 5 --json mergedAt"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_create_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr create --title test"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn git_merge_allowed() {
        // git merge is not gh pr merge
        let result = WarnGhMergePreflight.run(&make_bash("git merge feature-branch"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- happy path: gh pr merge nudges ---

    #[test]
    fn gh_pr_merge_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 5 --squash"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_with_delete_branch_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 5 --squash --delete-branch"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_auto_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge --auto --squash"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_in_chain_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("cd /repo && gh pr merge 12 --merge"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_with_repo_flag_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 7 -R owner/repo --squash"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- nudge message quality: all three gotchas present ---

    #[test]
    fn nudge_message_covers_draft_check() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 5 --squash"));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("isDraft"),
            "nudge should mention the isDraft pre-check: {msg}"
        );
    }

    #[test]
    fn nudge_message_covers_merged_at_verification() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 5 --squash"));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("mergedAt"),
            "nudge should mention post-error mergedAt verification: {msg}"
        );
    }

    #[test]
    fn nudge_message_covers_worktree_gotcha() {
        let result = WarnGhMergePreflight.run(&make_bash("gh pr merge 5 --delete-branch"));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("worktree"),
            "nudge should mention the worktree/--delete-branch gotcha: {msg}"
        );
    }

    // --- edge cases ---

    #[test]
    fn quoted_prose_mentioning_merge_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash("echo 'remember to gh pr merge later'"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_command_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn hyphenated_lookalike_allowed() {
        let result = WarnGhMergePreflight.run(&make_bash("./gh-pr-merge-helper.sh"));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
