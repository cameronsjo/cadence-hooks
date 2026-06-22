//! Warn when dispatching a subagent from the main checkout while a sibling
//! git worktree exists.
//!
//! A subagent inherits the **spawning session's working directory**. A session
//! in the main checkout spawns subagents that operate on the main checkout —
//! never a sibling worktree. So when a feature worktree exists and the intent
//! is to isolate subagent work in it, dispatching from the main checkout lands
//! the work in main instead. This nudge fires once per session (per repo) on an
//! `Agent`/`Task` spawn when:
//!
//! 1. the spawn does not already set `isolation: "worktree"` (which would give
//!    it a fresh agent-owned worktree, so it's already confined), and
//! 2. the spawning session sits in the **primary checkout** (its `.git` is a
//!    directory — a linked worktree's `.git` is a *file*, meaning the session
//!    is already inside a worktree and its subagents inherit that isolation), and
//! 3. a **sibling worktree exists** (`git worktree list` shows more than the
//!    primary) — the sharpener that keeps the nudge silent unless a worktree is
//!    actually in play.
//!
//! Silence permanently for a repo by setting `CADENCE_ALLOW_SUBAGENT_FROM_MAIN=true`
//! in `<repo>/.claude/settings.json`'s `env` block (or `~/.claude/settings.json`
//! for user-global). For repos where dispatching subagents from main is the
//! intended workflow.

use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// Returns true if `repo_root` is a **primary checkout** — its `.git` is a
/// directory. A linked worktree's `.git` is a *file* pointing into the primary
/// repo's `.git/worktrees/`, so a `false` here means the session is already
/// inside a worktree (and its subagents inherit that worktree). Mirrors the
/// `.git`-dir primitive in `cadence_hooks_session::registry::ensure_git_excluded`.
fn is_primary_checkout(repo_root: &str) -> bool {
    Path::new(repo_root).join(".git").is_dir()
}

/// Count the worktrees in `git worktree list --porcelain` output.
///
/// Each worktree is introduced by a line starting with `worktree `. The primary
/// checkout is always one entry, so `> 1` means at least one *sibling* worktree.
fn count_worktrees(porcelain: &str) -> usize {
    porcelain
        .lines()
        .filter(|l| l.starts_with("worktree "))
        .count()
}

/// Returns true if `CADENCE_ALLOW_SUBAGENT_FROM_MAIN` is set to a truthy value.
fn is_subagent_from_main_allowed() -> bool {
    is_allowed_value(
        std::env::var("CADENCE_ALLOW_SUBAGENT_FROM_MAIN")
            .ok()
            .as_deref(),
    )
}

/// Pure: classify a `CADENCE_ALLOW_SUBAGENT_FROM_MAIN` value as truthy or falsy.
///
/// Truthy: `"1"`, `"true"`, `"yes"` (case-insensitive, trimmed). Anything else
/// — unset, empty, `"0"`, `"false"` — is falsy. Mirrors `warn_main_branch`'s
/// `is_main_allowed_value`.
fn is_allowed_value(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// The nudge message: names the behavior (cwd inheritance → main, not the
/// worktree) and both fixes, plus the silence env var.
fn warn_message() -> String {
    "You're dispatching a subagent from the main checkout while a sibling git worktree exists. \
     Subagents inherit the spawning session's working directory, so this work will land in the \
     main checkout — not the worktree.\n\
     To isolate it: dispatch from a session already inside the worktree, or pass \
     isolation: \"worktree\" to give the spawn a fresh agent-owned worktree.\n\
     To silence for this repo: set CADENCE_ALLOW_SUBAGENT_FROM_MAIN=true in .claude/settings.json"
        .to_string()
}

/// Pure decision: should we warn about this subagent dispatch?
///
/// Nudge only when the session is in the primary checkout, a sibling worktree
/// exists, the spawn isn't already worktree-isolated, we haven't warned this
/// session, and the repo isn't permanently opted out. Any one of those
/// suppresses the nudge.
fn assess_spawn(
    in_main: bool,
    worktree_exists: bool,
    isolation_worktree: bool,
    already_warned: bool,
    allowed: bool,
) -> CheckResult {
    if allowed || already_warned || isolation_worktree || !in_main || !worktree_exists {
        return CheckResult::allow();
    }
    CheckResult::nudge(warn_message())
}

/// Warns once per session when a subagent is dispatched from the main checkout
/// while a sibling worktree exists.
pub struct WarnSubagentWorktree;

impl WarnSubagentWorktree {
    /// Build the per-session marker path scoped to a specific repo root.
    ///
    /// Hashes the repo root so two repos with the same name don't share markers.
    /// The PPID component ties the marker to the Claude Code session — hooks run
    /// as separate child processes, so `process::id()` changes every invocation;
    /// the parent PID (Claude Code) is stable across a session. Mirrors
    /// `warn_main_branch::marker_path`.
    fn marker_path(repo_root: &str) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        repo_root.hash(&mut hasher);
        let hash = hasher.finish();

        let ppid = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(std::process::id);

        cadence_hooks_core::paths::marker_temp_dir()
            .join(format!(".claude-subagent-worktree-warned-{hash:x}-{ppid}"))
    }
}

impl Check for WarnSubagentWorktree {
    fn name(&self) -> &str {
        "warn-subagent-worktree"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Only subagent dispatches. `Agent` is the current tool name; `Task` is
        // the pre-2.1.63 name, kept for resilience. Every other tool call exits
        // here before any git spawn. (In production the hooks.json matcher
        // already filters to Agent|Task, so this is belt-and-suspenders.)
        if !matches!(input.tool_name(), Some("Agent" | "Task")) {
            return CheckResult::allow();
        }

        // cwd of the spawning session — the directory its subagents inherit.
        let cwd = input.cwd.as_deref().unwrap_or(".");

        // Not in a git repo → nothing to isolate. Fail open (ADR-0001).
        let Some(repo_root) = git_command(cwd, &["rev-parse", "--show-toplevel"]) else {
            return CheckResult::allow();
        };

        let in_main = is_primary_checkout(&repo_root);
        let worktree_exists = git_command(cwd, &["worktree", "list", "--porcelain"])
            .map(|out| count_worktrees(&out) > 1)
            .unwrap_or(false);
        let isolation_worktree = input.isolation() == Some("worktree");

        let marker = Self::marker_path(&repo_root);
        let already_warned = marker.exists();
        let allowed = is_subagent_from_main_allowed();

        let result = assess_spawn(
            in_main,
            worktree_exists,
            isolation_worktree,
            already_warned,
            allowed,
        );

        if result.outcome == Outcome::Nudge {
            let _ = std::fs::write(&marker, "");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_agent, make_bash};

    // --- assess_spawn (pure decision) ---

    #[test]
    fn all_conditions_met_warns() {
        let result = assess_spawn(true, true, false, false, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.expect("nudge has a message");
        assert!(msg.contains("worktree"));
        assert!(msg.contains("CADENCE_ALLOW_SUBAGENT_FROM_MAIN"));
    }

    #[test]
    fn allowed_suppresses() {
        let result = assess_spawn(true, true, false, false, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_suppresses() {
        let result = assess_spawn(true, true, false, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn isolation_worktree_suppresses() {
        // The spawn already gets a fresh worktree — nothing to warn about.
        let result = assess_spawn(true, true, true, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn inside_worktree_suppresses() {
        // Session is already inside a worktree (.git is a file) → its subagents
        // inherit that worktree, so no nudge.
        let result = assess_spawn(false, true, false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn no_sibling_worktree_suppresses() {
        // In main but no worktree in play — the common case, stays silent.
        let result = assess_spawn(true, false, false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn message_names_both_fixes() {
        let msg = warn_message();
        assert!(
            msg.contains("inside the worktree"),
            "should name the dispatch-from-inside fix: {msg}"
        );
        assert!(
            msg.contains("isolation: \"worktree\""),
            "should name the isolation fix: {msg}"
        );
    }

    // --- count_worktrees ---

    #[test]
    fn count_worktrees_single_root() {
        let porcelain = "worktree /Users/x/repo\nHEAD abc123\nbranch refs/heads/main\n";
        assert_eq!(count_worktrees(porcelain), 1);
    }

    #[test]
    fn count_worktrees_two_roots() {
        let porcelain = "worktree /Users/x/repo\nHEAD abc\nbranch refs/heads/main\n\
                         \nworktree /Users/x/repo/.claude/worktrees/feat\nHEAD def\nbranch refs/heads/feat\n";
        assert_eq!(count_worktrees(porcelain), 2);
    }

    #[test]
    fn count_worktrees_empty() {
        assert_eq!(count_worktrees(""), 0);
    }

    #[test]
    fn count_worktrees_ignores_non_worktree_lines() {
        // A branch named "worktree-x" must not be counted — only lines that
        // *start* with "worktree " (the porcelain entry marker) count.
        let porcelain = "worktree /Users/x/repo\nbranch refs/heads/worktree-experiment\n";
        assert_eq!(count_worktrees(porcelain), 1);
    }

    // --- is_primary_checkout (.git dir vs file) ---

    #[test]
    fn primary_checkout_when_git_is_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_primary_checkout(dir.path().to_str().unwrap()));
    }

    #[test]
    fn not_primary_checkout_when_git_is_file() {
        // A linked worktree's .git is a file ("gitdir: ...").
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".git"),
            "gitdir: /repo/.git/worktrees/feat\n",
        )
        .unwrap();
        assert!(!is_primary_checkout(dir.path().to_str().unwrap()));
    }

    #[test]
    fn not_primary_checkout_when_git_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_primary_checkout(dir.path().to_str().unwrap()));
    }

    // --- run() early exits ---

    #[test]
    fn non_agent_tool_allows() {
        // A Bash call must never trip the warning — it returns before any git
        // spawn, so no repo is needed.
        let result = WarnSubagentWorktree.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn agent_outside_git_repo_allows() {
        // A temp dir that is not a git repo → rev-parse fails → fail-open allow.
        let dir = tempfile::tempdir().unwrap();
        let input = make_agent(Some("general-purpose"), None, dir.path().to_str().unwrap());
        let result = WarnSubagentWorktree.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- isolation() round-trips via make_agent ---

    #[test]
    fn make_agent_carries_isolation() {
        let input = make_agent(Some("general-purpose"), Some("worktree"), "/tmp");
        assert_eq!(input.isolation(), Some("worktree"));
        assert_eq!(input.subagent_type(), Some("general-purpose"));
        assert_eq!(input.tool_name(), Some("Agent"));
    }

    #[test]
    fn make_agent_omits_isolation_as_none() {
        let input = make_agent(None, None, "/tmp");
        assert_eq!(input.isolation(), None);
        assert_eq!(input.subagent_type(), None);
    }

    // --- marker path ---

    #[test]
    fn marker_path_differs_per_repo() {
        let a = WarnSubagentWorktree::marker_path("/tmp/repo-a");
        let b = WarnSubagentWorktree::marker_path("/tmp/repo-b");
        assert_ne!(a, b, "marker path must include a repo-specific hash");
    }

    #[test]
    fn marker_path_stable_for_same_repo() {
        let a = WarnSubagentWorktree::marker_path("/tmp/repo");
        let b = WarnSubagentWorktree::marker_path("/tmp/repo");
        assert_eq!(a, b);
    }

    #[test]
    fn marker_path_is_distinct_from_main_branch_marker() {
        // The two once-per-session guards must not collide on a marker name, or
        // one warning would suppress the other.
        let m = WarnSubagentWorktree::marker_path("/tmp/repo");
        assert!(
            m.to_string_lossy().contains("subagent-worktree-warned"),
            "marker name must be guard-specific: {}",
            m.display()
        );
    }

    // --- is_allowed_value (pure) ---

    #[test]
    fn allowed_value_unset_is_false() {
        assert!(!is_allowed_value(None));
    }

    #[test]
    fn allowed_value_empty_is_false() {
        assert!(!is_allowed_value(Some("")));
        assert!(!is_allowed_value(Some("   ")));
    }

    #[test]
    fn allowed_value_falsy_strings() {
        assert!(!is_allowed_value(Some("0")));
        assert!(!is_allowed_value(Some("false")));
        assert!(!is_allowed_value(Some("no")));
        assert!(!is_allowed_value(Some("off")));
    }

    #[test]
    fn allowed_value_truthy_strings() {
        assert!(is_allowed_value(Some("1")));
        assert!(is_allowed_value(Some("true")));
        assert!(is_allowed_value(Some("yes")));
    }

    #[test]
    fn allowed_value_case_insensitive() {
        assert!(is_allowed_value(Some("TRUE")));
        assert!(is_allowed_value(Some("Yes")));
    }

    #[test]
    fn allowed_value_trims_whitespace() {
        assert!(is_allowed_value(Some("  true  ")));
        assert!(is_allowed_value(Some("\t1\n")));
    }
}
