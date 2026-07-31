//! Hooks for the [git-guardrails](https://github.com/cameronsjo/git-guardrails) plugin.
//!
//! Ownership-aware guards that prevent Claude Code from pushing to repos
//! you don't own, writing to upstream issues, or running irreversible operations.

/// Shared test lock serializing every test that mutates the process-global
/// `CADENCE_ALLOW_MAIN` env var — read by `warn_main_branch::is_main_allowed`
/// and `warn_branch_base`'s `would_block_here`. Module-local locks in separate
/// files provide no mutual exclusion under cargo's parallel test runner, so
/// they race (cadence-hooks#298); one crate-shared lock serializes them all.
#[cfg(test)]
pub(crate) static CADENCE_ALLOW_MAIN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Shared test lock serializing every test in this crate that mutates a
/// process-global env var OUTSIDE the `CADENCE_ALLOW_MAIN` family above
/// (`guard_push_remote`, `guard_gh_write`, `warn_issue_tracker`,
/// `warn_subagent_worktree`, `warn_going_public`, `warn_subagent_concurrency`,
/// `guard_read_model` — seven modules, seven different var sets). Each used
/// to mint its own module-local `ENV_LOCK`, on the theory that disjoint var
/// sets need no shared exclusion — but that theory lives only in a doc
/// comment, and the moment two modules' vars overlap (or a future edit adds
/// one that does), the failure is a silent flake under cargo's parallel test
/// runner, not a compile error (cadence-hooks#446, same root cause as #298).
/// One lock removes the need to keep proving disjointness — mirrors the
/// ruling `crates/metrics/src/common.rs` already made for its own env-mutating
/// tests (one crate-wide `ENV_LOCK`, not one per var family).
#[cfg(test)]
static CADENCE_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with each `(key, value)` in `vars` set (`None` removes the var),
/// serialized against every other env-mutating test in this crate via
/// [`CADENCE_ENV_TEST_LOCK`], and restore the *prior* value of each var
/// afterward — panic-safe via `catch_unwind`, so a failing `f` still restores
/// rather than leaking state into the next test in the same binary.
///
/// The single shared implementation for every module whose tests fit this
/// vars-slice shape. Mirrors `core::test_builders::with_marker_dir`'s
/// discipline: the lock lives behind this one function so a module cannot
/// mint a rival — `use crate::with_env;`, never a module-local copy.
#[cfg(test)]
pub(crate) fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
    let _guard = CADENCE_ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let prior: Vec<(String, Option<String>)> = vars
        .iter()
        .map(|(k, _)| ((*k).to_string(), std::env::var(*k).ok()))
        .collect();
    for (k, v) in vars {
        // SAFETY: serialized via CADENCE_ENV_TEST_LOCK; restored below.
        unsafe {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in prior {
        // SAFETY: same lock still held; restoring prior state.
        unsafe {
            match v {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

/// A single-commit repo whose `origin` has stable GitHub owner/repo identity.
///
/// Tests that assert ownership or repo-name behavior must not read the
/// enclosing checkout's live remote: a local-path clone has no owner/repo and
/// flips those assertions (#254).
#[cfg(test)]
pub(crate) fn github_origin_repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("create hermetic git fixture");
    cadence_hooks_core::git_fixtures::init_repo(repo.path());
    cadence_hooks_core::git_fixtures::git_in(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/cameronsjo/cadence-hooks.git",
        ],
    );
    repo
}

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
/// Opt-in per-model Read/Grep guard; block reads by the resolved session model.
pub mod guard_read_model;
/// Path-aware triage of rm-family delete commands (allow/ask/block).
pub mod guard_rm;
/// Inject the gh-write allowlist + `-R` rule on SessionStart.
pub mod inject_gh_context;
/// Re-inject the gh-write allowlist + `-R` rule just before an untargeted gh write.
pub mod inject_gh_write_context;
/// Shared closing-keyword detection for GitHub issue references.
pub mod issue_refs;
/// Shared message text duplicated across guardrails call sites (cadence-hooks#327).
pub mod messages;
/// Nudge to schedule a brew upgrade after pushing cadence-hooks to main.
pub mod nudge_upgrade_after_push;
/// Shared provenance sidecar for the `dismiss-*` snooze markers.
pub mod snooze_meta;
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
