//! Hooks for the [git-guardrails](https://github.com/cameronsjo/git-guardrails) plugin.
//!
//! Ownership-aware guards that prevent Claude Code from pushing to repos
//! you don't own, writing to upstream issues, or running irreversible operations.

/// Nudge after idle periods between edits to re-check context.
pub mod check_idle_return;
/// Block irreversible `gh` operations (repo delete).
pub mod guard_gh_dangerous;
/// Block `gh` write operations targeting repos you don't own.
pub mod guard_gh_write;
/// Nudge to scaffold project standards after `git init`.
pub mod guard_git_init;
/// Block `git push` to remotes owned by others.
pub mod guard_push_remote;
/// Warn when creating a branch from a non-main base.
pub mod warn_branch_base;
/// Remind to check datetime before scheduling cron jobs.
pub mod warn_cron_datetime;
/// Warn when editing files directly on main/master branch.
pub mod warn_main_branch;
/// Warn about untracked files during git commit operations.
pub mod warn_untracked;
