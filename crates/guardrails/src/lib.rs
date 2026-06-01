//! Hooks for the [git-guardrails](https://github.com/cameronsjo/git-guardrails) plugin.
//!
//! Ownership-aware guards that prevent Claude Code from pushing to repos
//! you don't own, writing to upstream issues, or running irreversible operations.

/// Nudge after idle periods between edits to re-check context.
pub mod check_idle_return;
/// Per-repo snooze command + helper consumed by `warn_main_branch`.
pub mod dismiss_main_branch_warn;
/// Block direct edits to production dotfiles; redirect to chezmoi source.
pub mod guard_dotfiles;
/// Block irreversible `gh` operations (repo delete).
pub mod guard_gh_dangerous;
/// Block `gh` write operations targeting repos you don't own.
pub mod guard_gh_write;
/// Nudge to scaffold project standards after `git init`.
pub mod guard_git_init;
/// Block `gh pr create` when the PR body has no closing keyword linking to an issue.
pub mod guard_pr_issue_link;
/// Block `git push` to remotes owned by others.
pub mod guard_push_remote;
/// Shared closing-keyword detection for GitHub issue references.
pub mod issue_refs;
/// Nudge to schedule a brew upgrade after pushing cadence-hooks to main.
pub mod nudge_upgrade_after_push;
/// Warn about broken issue refs on PR create; close straggler issues on PR merge.
pub mod verify_pr_autoclose;
/// Warn when creating a branch from a non-main base.
pub mod warn_branch_base;
/// Remind to check datetime before scheduling cron jobs.
pub mod warn_cron_datetime;
/// Warn when editing files directly on main/master branch.
pub mod warn_main_branch;
/// Warn about untracked files during git commit operations.
pub mod warn_untracked;
