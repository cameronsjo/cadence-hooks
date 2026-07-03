//! Hooks for the [git-guardrails](https://github.com/cameronsjo/git-guardrails) plugin.
//!
//! Ownership-aware guards that prevent Claude Code from pushing to repos
//! you don't own, writing to upstream issues, or running irreversible operations.

/// Nudge after idle periods between edits to re-check context.
pub mod check_idle_return;
/// Per-repo snooze command + helper consumed by `enforce_worktree`.
pub mod dismiss_enforce_worktree;
/// Per-repo snooze command + helper consumed by `warn_main_branch`.
pub mod dismiss_main_branch_warn;
/// Block mutations in a primary checkout of a branch-mode repo.
pub mod enforce_worktree;
/// Block the first Claude-in-Chrome action per session until the device is confirmed.
pub mod guard_browser_device;
/// Block direct edits to production dotfiles; redirect to chezmoi source.
pub mod guard_dotfiles;
/// Block irreversible `gh` operations (repo delete).
pub mod guard_gh_dangerous;
/// Block `gh` write operations targeting repos you don't own.
pub mod guard_gh_write;
/// Nudge to scaffold project standards after `git init`.
pub mod guard_git_init;
/// Block uninvited 1Password vault enumeration (`op item list`).
pub mod guard_op_vault_scan;
/// Block `git push` to remotes owned by others.
pub mod guard_push_remote;
/// Inject the gh-write allowlist + `-R` rule on SessionStart.
pub mod inject_gh_context;
/// Shared closing-keyword detection for GitHub issue references.
pub mod issue_refs;
/// Nudge to schedule a brew upgrade after pushing cadence-hooks to main.
pub mod nudge_upgrade_after_push;
/// Warn about broken issue refs on PR create; close straggler issues on PR merge.
pub mod verify_pr_autoclose;
/// Warn when piping aliased-tool output (ls/find/cat/du/df/top) into parsers.
pub mod warn_alias_parsing;
/// Warn when creating a branch from a non-main base.
pub mod warn_branch_base;
/// Warn that CodeRabbit re-trigger comments are no-ops on already-reviewed content.
pub mod warn_coderabbit_retrigger;
/// Remind to check datetime before scheduling cron jobs.
pub mod warn_cron_datetime;
/// Warn when bare `curl` (aliased to curlie) is used with custom headers.
pub mod warn_curl_alias;
/// Pre-flight checklist nudge before `gh pr merge` (draft, worktree, verify).
pub mod warn_gh_merge_preflight;
/// Warn when creating/publicizing a repo whose name or description telegraphs sensitive content.
pub mod warn_going_public;
/// Nudge when `gh issue create` targets an owned repo other than the canonical issue tracker.
pub mod warn_issue_tracker;
/// Warn when editing files directly on main/master branch.
pub mod warn_main_branch;
/// Remind on `gh pr create` when the PR body has no closing keyword linking to an issue.
pub mod warn_pr_issue_link;
/// Nudge when the live subagent count is at or over the configured cap.
pub mod warn_subagent_concurrency;
/// Warn when dispatching a subagent from main while a sibling worktree exists.
pub mod warn_subagent_worktree;
/// Warn about untracked files during git commit operations.
pub mod warn_untracked;
