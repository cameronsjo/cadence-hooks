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

use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, skip_transparent_prefixes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges a pre-flight checklist on `gh pr merge`.
pub struct WarnGhMergePreflight;

/// Returns true if `command` contains a `gh pr merge` token sequence.
///
/// Token- and segment-based to avoid substring false positives (hyphenated
/// script names, prose) while recognizing shell-wrapper bodies. Only the
/// command word folds; the `pr merge` subcommands remain case-sensitive.
fn is_gh_pr_merge(command: &str) -> bool {
    command_segments(command).into_iter().any(|segment| {
        // Reserved words and group punctuation go first, then transparent
        // prefixes and `NAME=value` assignments, so `GH_TOKEN=x gh pr merge`,
        // `env … gh`, `time gh`, and `then gh pr merge` are seen
        // (cadence-hooks#545).
        let tokens = executable_tokens(&segment);
        let argv = skip_transparent_prefixes(&tokens);
        argv.first()
            .is_some_and(|first| command_word(first).as_ref() == "gh")
            && argv.get(1).map(String::as_str) == Some("pr")
            && argv.get(2).map(String::as_str) == Some("merge")
    })
}

impl Check for WarnGhMergePreflight {
    fn name(&self) -> &str {
        "warn-gh-merge-preflight"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !is_gh_pr_merge(command) {
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
    fn case_folded_gh_pr_merge_nudges() {
        let result = WarnGhMergePreflight.run(&make_bash("GH pr merge 5 --squash"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn case_fold_does_not_fold_merge_subcommands() {
        let result = WarnGhMergePreflight.run(&make_bash("GH PR merge 5 --squash"));
        assert_eq!(result.outcome, Outcome::Allow);
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

    #[test]
    fn prefixed_and_keyword_wrapped_merge_nudges() {
        // cadence-hooks#545: each was silent because the segment head was
        // compared without skipping prefixes or reserved words.
        for command in [
            "GH_TOKEN=x gh pr merge 5",
            "env GH_TOKEN=x gh pr merge 5",
            "time gh pr merge 5 --squash",
            "command gh pr merge 5",
            "nohup gh pr merge 5",
            "exec gh pr merge 5",
            "for p in 1 2; do gh pr merge $p; done",
            "if true; then gh pr merge 5; fi",
        ] {
            let result = WarnGhMergePreflight.run(&make_bash(command));
            assert_eq!(result.outcome, Outcome::Nudge, "{command}");
        }
    }

    #[test]
    fn the_rewrites_wins_and_controls_hold() {
        for command in ["bash -c 'gh pr merge 5'", "/opt/homebrew/bin/gh pr merge 5"] {
            let result = WarnGhMergePreflight.run(&make_bash(command));
            assert_eq!(result.outcome, Outcome::Nudge, "{command}");
        }
        for command in [
            "echo 'gh pr merge 5'",
            "gh pr comment 5 --body 'run gh pr merge 5 next'",
            "GH_TOKEN=x gh pr view 5",
        ] {
            let result = WarnGhMergePreflight.run(&make_bash(command));
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
        }
    }
}
