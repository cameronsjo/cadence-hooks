//! `guardrails inject-gh-write-context` — PreToolUse hook.
//!
//! Just-in-time twin of [`inject_gh_context`](super::inject_gh_context), which
//! primes the same allowlist + `-R owner/repo` rule at SessionStart. Session
//! start is far from the write: by the time a `gh pr create` is composed, that
//! context may be many turns — or a compaction — behind, and the write lands
//! without `-R`, silently targeting whatever cwd's git remote happens to be.
//! This check re-states the rule at the moment it applies.
//!
//! Fires only on the shapes that need it: a segment that actually invokes `gh`,
//! runs a write sub-command, and names no explicit target. Reads never fire
//! (they need no `-R`), and a write that already carries `-R`, an
//! `/repos/owner/repo` API path, or a positional repo argument is left alone —
//! the advice would be noise.
//!
//! **Deliberately un-deduped.** Repeating on every bare write is the mechanism,
//! not a defect: the case this exists to catch is a model that lost the
//! SessionStart context, so suppressing the repeat would silence the fire that
//! matters most. Nudges are exit 0, so the cost of a repeat is a line of
//! context, never a blocked command.
//!
//! Enforcement still lives in [`guard_gh_write`](super::guard_gh_write); this
//! check only advises, and reuses that guard's write-detection and
//! target-detection so the nudge and the block cannot drift apart.

use cadence_hooks_core::shell::command_segments;
use cadence_hooks_core::{Check, CheckResult, HookInput};

use crate::guard_gh_write::{is_write_command, segment_invokes_gh, segment_lacks_explicit_target};
use crate::inject_gh_context::render_from_env;

/// Re-inject the gh allowlist + `-R` rule just before an untargeted gh write.
pub struct InjectGhWriteContext;

impl Check for InjectGhWriteContext {
    fn name(&self) -> &str {
        "inject-gh-write-context"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        let needs_context = command_segments(command).into_iter().any(|segment| {
            segment_invokes_gh(&segment)
                && is_write_command(&segment)
                && segment_lacks_explicit_target(&segment)
        });

        if !needs_context {
            return CheckResult::allow();
        }

        CheckResult::nudge(render_from_env())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    fn outcome(command: &str) -> Outcome {
        InjectGhWriteContext.run(&make_bash(command)).outcome
    }

    // --- guard clauses: nothing to advise on ---

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(InjectGhWriteContext.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        assert_eq!(outcome("git status"), Outcome::Allow);
    }

    // --- reads need no `-R`, so they never fire ---

    #[test]
    fn gh_pr_list_allowed() {
        assert_eq!(outcome("gh pr list"), Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        assert_eq!(outcome("gh pr view 5 --json mergedAt"), Outcome::Allow);
    }

    // --- untargeted writes nudge ---

    #[test]
    fn gh_pr_create_without_target_nudges() {
        assert_eq!(outcome("gh pr create --title x"), Outcome::Nudge);
    }

    #[test]
    fn case_folded_gh_pr_create_nudges() {
        assert_eq!(outcome("GH pr create --title x"), Outcome::Nudge);
    }

    #[test]
    fn case_fold_does_not_fold_gh_subcommands() {
        assert_eq!(outcome("GH PR create --title x"), Outcome::Allow);
    }

    #[test]
    fn gh_issue_comment_without_target_nudges() {
        assert_eq!(outcome("gh issue comment 5 --body x"), Outcome::Nudge);
    }

    #[test]
    fn gh_release_create_without_target_nudges() {
        assert_eq!(outcome("gh release create v1"), Outcome::Nudge);
    }

    #[test]
    fn gh_api_write_without_repo_flag_nudges() {
        // The path names a repo, but `gh api repos/o/r` is a bare path with no
        // leading slash — API_REPOS matches it, so this shape is targeted.
        // Use a non-repo endpoint to exercise the untargeted API write.
        assert_eq!(outcome("gh api user/repos -X POST"), Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_without_target_nudges() {
        assert_eq!(outcome("gh pr merge 5 --squash"), Outcome::Nudge);
    }

    // --- the segment walk, which is why this reads command_segments at all ---

    #[test]
    fn untargeted_write_in_a_later_segment_nudges() {
        assert_eq!(
            outcome("cd /repo && gh pr create --title x"),
            Outcome::Nudge
        );
    }

    #[test]
    fn one_targeted_segment_does_not_excuse_an_untargeted_one() {
        // Per-segment, not whole-command: a `-R` anywhere in the line would
        // otherwise silence the advice for a sibling write that has none.
        assert_eq!(
            outcome("gh pr create -R o/r --title x && gh issue comment 5 --body y"),
            Outcome::Nudge
        );
    }

    #[test]
    fn every_segment_targeted_allowed() {
        assert_eq!(
            outcome("gh pr create -R o/r --title x && gh issue comment 5 -R o/r --body y"),
            Outcome::Allow
        );
    }

    #[test]
    fn nudge_message_carries_the_dash_r_rule() {
        let msg = InjectGhWriteContext
            .run(&make_bash("gh pr create --title x"))
            .message
            .expect("nudge always carries a message");
        assert!(
            msg.contains("`-R owner/repo`"),
            "nudge should carry the -R rule verbatim from render_context: {msg}"
        );
    }

    // --- explicit targets are left alone, in all four `-R` spellings ---

    #[test]
    fn separated_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create -R o/r --title x"), Outcome::Allow);
    }

    #[test]
    fn attached_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create -Ro/r --title x"), Outcome::Allow);
    }

    #[test]
    fn equals_joined_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create --repo=o/r --title x"), Outcome::Allow);
    }

    #[test]
    fn long_repo_flag_allowed() {
        assert_eq!(
            outcome("gh issue comment 5 --repo o/r --body x"),
            Outcome::Allow
        );
    }

    #[test]
    fn api_repos_path_allowed() {
        assert_eq!(outcome("gh api repos/o/r -X POST"), Outcome::Allow);
    }

    // --- positional-target shapes are left alone ---

    #[test]
    fn gh_repo_create_positional_allowed() {
        assert_eq!(outcome("gh repo create o/name"), Outcome::Allow);
    }

    #[test]
    fn gh_repo_fork_positional_allowed() {
        assert_eq!(outcome("gh repo fork o/r"), Outcome::Allow);
    }

    #[test]
    fn gh_gist_create_allowed() {
        // Gists have no repo target at all — `-R` would be meaningless.
        assert_eq!(outcome("gh gist create f"), Outcome::Allow);
    }

    // --- regression pin: prose is not an invocation (#212) ---

    #[test]
    fn gh_write_quoted_in_a_commit_message_allowed() {
        assert_eq!(
            outcome(r#"git commit -m "document the gh pr create flow""#),
            Outcome::Allow
        );
    }

    #[test]
    fn check_name_matches_subcommand() {
        assert_eq!(InjectGhWriteContext.name(), "inject-gh-write-context");
    }
}
