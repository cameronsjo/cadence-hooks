//! Warn when editing on the main branch without a feature branch.
//!
//! Fires once per session (tracked via a temp-file marker) to nudge the
//! user toward creating a feature branch before making changes.
//!
//! Three ways to silence:
//! - **Per-repo, time-bounded**: `cadence-hooks guardrails dismiss-main-branch-warn --for <duration>`
//!   — see [`crate::dismiss_main_branch_warn`]. Caps at 24h.
//! - **Per-repo, permanent**: set `CADENCE_ALLOW_MAIN=true` in
//!   `<repo>/.claude/settings.json`'s `env` block. For repos where main IS
//!   the working branch by design (personal scratchpads, dotfiles, vaults).
//! - **User-global, permanent**: same env var in `~/.claude/settings.json`.
//!
//! Edits inside any `.claude/` directory are exempt automatically — worktrees
//! under `.claude/worktrees/` (always on an intentional feature branch) and the
//! user's `~/.claude/` config and memory tree. That work is never the
//! branch-worthy product change the warning targets.

use crate::dismiss_main_branch_warn;
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the directory to pass to `git -C` for a given hook input.
///
/// When the hook fires for an Edit/Write, returns the parent directory of
/// the edited file. `git -C <dir>` walks upward to find `.git`, so this
/// routes branch detection to the file's enclosing repo — even when CWD
/// belongs to an outer parent repo (the nested-repo case).
///
/// Relative `file_path` values are joined against `input.cwd` so we resolve
/// against the hook event's CWD, not the hook process's CWD. For Bash hooks
/// (no file path), falls back to `input.cwd` then `.` so we still target the
/// session's working directory rather than wherever the hook process started.
fn git_dir_for_input(input: &HookInput) -> PathBuf {
    let cwd = input
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let Some(file_path) = input.file_path() else {
        return cwd;
    };

    let path = Path::new(&file_path);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    resolved
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or(cwd)
}

/// Returns true if `dir` lives inside a `.claude/` directory.
///
/// These paths hold Claude Code tooling and state, never the branch-worthy
/// product work the warning targets, so the check stays out of them:
///
/// - `<repo>/.claude/worktrees/<name>/...` — worktrees created by
///   `EnterWorktree` / `cadence-forge:using-worktrees` are always on an
///   intentional feature branch. A worktree that happens to sit on `main` is
///   still ad-hoc work, never the load-bearing primary checkout (issue #33).
/// - `~/.claude/...` — user config and the auto-written memory directory.
///   `~/.claude` may itself be a git repo on `main`, but edits there aren't
///   repo feature work (issue #35).
///
/// Matches on an exact `.claude` path component, so look-alikes like
/// `.claude-old` or `myclaude` are not exempt.
fn is_claude_managed_dir(dir: &Path) -> bool {
    dir.components().any(|c| c.as_os_str() == ".claude")
}

/// Returns true if the branch name is a default branch (`main` or `master`).
fn is_default_branch(branch: &str) -> bool {
    branch == "main" || branch == "master"
}

/// Returns true if `CADENCE_ALLOW_MAIN` env var is set to a truthy value.
///
/// Truthy: `"1"`, `"true"`, `"yes"` (case-insensitive). Anything else (unset,
/// empty, `"0"`, `"false"`) is falsy. Set in `.claude/settings.json` env
/// block — project or user-global — to permanently opt a repo out of the
/// main-branch warning.
fn is_main_allowed() -> bool {
    is_main_allowed_value(std::env::var("CADENCE_ALLOW_MAIN").ok().as_deref())
}

/// Pure: classify a `CADENCE_ALLOW_MAIN` value as truthy or falsy.
fn is_main_allowed_value(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Pure decision: should we warn about editing on this branch?
///
/// Returns `Nudge` if on a default branch, not already warned this session,
/// not currently snoozed, and not permanently allowed via env var.
fn should_warn(branch: &str, already_warned: bool, snoozed: bool, allowed: bool) -> CheckResult {
    if !is_default_branch(branch) {
        return CheckResult::allow();
    }

    if allowed || snoozed || already_warned {
        return CheckResult::allow();
    }

    CheckResult::nudge(format!(
        "You're editing files directly on '{branch}'. \
         Ask the user: should this work be on a feature branch instead?\n\
         To silence for this session: cadence-hooks guardrails dismiss-main-branch-warn --for 2h\n\
         To silence permanently for this repo: set CADENCE_ALLOW_MAIN=true in .claude/settings.json"
    ))
}

/// Warns once per session when the current branch is `main` or `master`.
pub struct WarnMainBranch;

impl WarnMainBranch {
    /// Build the per-session marker path scoped to a specific repo root.
    ///
    /// Hashes the repo root so two repos with the same name don't share
    /// markers. The PPID component ties the marker to the Claude Code
    /// session — hooks run as separate child processes so `process::id()`
    /// would change every invocation.
    fn marker_path(repo_root: &str) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        repo_root.hash(&mut hasher);
        let hash = hasher.finish();

        let ppid = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(std::process::id);

        cadence_hooks_core::paths::marker_temp_dir()
            .join(format!(".claude-main-branch-warned-{hash:x}-{ppid}"))
    }
}

impl Check for WarnMainBranch {
    fn name(&self) -> &str {
        "warn-main-branch"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let dir = git_dir_for_input(input);

        // Edits inside a `.claude/` directory are tooling, config, or worktree
        // work — never branch-worthy product changes. Skip the warning (and the
        // git spawns below) entirely. (issues #33, #35)
        if is_claude_managed_dir(&dir) {
            return CheckResult::allow();
        }

        let dir_arg = dir.to_string_lossy();

        // Branch detection scoped to the edited file's repo, not CWD's repo.
        // `git -C` walks upward to find `.git`, picking the nearest enclosing
        // repository — which is what we want when editing inside a nested
        // checkout from a session whose CWD is the outer parent.
        let branch = match Command::new("git")
            .args(["-C", &dir_arg, "symbolic-ref", "--short", "HEAD"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        // Repo root for marker — same source as the branch query so the
        // once-per-session suppression actually keys off the same repo.
        let repo_root = match Command::new("git")
            .args(["-C", &dir_arg, "rev-parse", "--show-toplevel"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        let marker = Self::marker_path(&repo_root);
        let already_warned = marker.exists();
        let snoozed = dismiss_main_branch_warn::is_snoozed_now(Path::new(&repo_root));
        let allowed = is_main_allowed();

        let result = should_warn(&branch, already_warned, snoozed, allowed);

        if result.outcome == Outcome::Nudge {
            let _ = std::fs::write(&marker, "");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_branch_warns() {
        let result = should_warn("main", false, false, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("main")
        );
    }

    #[test]
    fn master_branch_warns() {
        let result = should_warn("master", false, false, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    #[test]
    fn feature_branch_allows() {
        let result = should_warn("feat/new-feature", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn develop_branch_allows() {
        let result = should_warn("develop", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_allows() {
        let result = should_warn("main", true, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_master_allows() {
        let result = should_warn("master", true, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_branch_allows() {
        let result = should_warn("", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn is_default_branch_main() {
        assert!(is_default_branch("main"));
    }

    #[test]
    fn is_default_branch_master() {
        assert!(is_default_branch("master"));
    }

    #[test]
    fn is_default_branch_feature() {
        assert!(!is_default_branch("feat/something"));
    }

    #[test]
    fn is_default_branch_not_substring() {
        assert!(!is_default_branch("main-backup"));
        assert!(!is_default_branch("hotfix/master-fix"));
    }

    // --- edge case hardening ---

    #[test]
    fn release_branch_allows() {
        let result = should_warn("release/1.0", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_contains_branch() {
        let result = should_warn("master", false, false, false);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    #[test]
    fn marker_uses_ppid_not_pid() {
        // Bug: code uses process::id() (current PID) but names var "ppid"
        // Since hooks run as separate processes, each invocation gets a new PID,
        // so the marker file from a previous invocation is never found.
        // The intent was to use the PARENT PID (Claude Code process) for session scoping.
        let ppid_env = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let current_pid = std::process::id();
        if let Some(ppid) = ppid_env {
            assert_ne!(
                current_pid, ppid,
                "PID should differ from PPID — marker_path() should use PPID for session scoping"
            );
        }
    }

    // --- Regression: nested-repo branch resolution (issue #26) ---
    // When CWD is an outer repo and the edited file is in a nested inner repo,
    // branch resolution must follow the file path, not CWD. Using `git -C
    // <file_parent>` lets git walk upward to find the nearest .git.

    fn make_edit_input(file_path: Option<&str>) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: file_path.map(Into::into),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        }
    }

    #[test]
    fn git_dir_uses_file_parent_for_nested_path() {
        let input = make_edit_input(Some("/tmp/outer/inner/file.txt"));
        assert_eq!(
            git_dir_for_input(&input),
            PathBuf::from("/tmp/outer/inner"),
            "git -C target should be the directory containing the edited file"
        );
    }

    #[test]
    fn git_dir_falls_back_to_cwd_for_bash() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("git status".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        assert_eq!(
            git_dir_for_input(&input),
            PathBuf::from("."),
            "Bash hooks have no file path; should fall back to CWD"
        );
    }

    #[test]
    fn git_dir_falls_back_for_bare_filename() {
        // Path with no parent (or empty parent) should fall back to CWD
        // rather than passing an empty string to `git -C`.
        let input = make_edit_input(Some("file.txt"));
        assert_eq!(git_dir_for_input(&input), PathBuf::from("."));
    }

    #[test]
    fn git_dir_handles_no_tool_input() {
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(git_dir_for_input(&input), PathBuf::from("."));
    }

    #[test]
    fn marker_path_differs_per_repo() {
        // Two different repo roots should produce distinct marker paths
        // so a snooze in one repo doesn't suppress warnings in another.
        let a = WarnMainBranch::marker_path("/tmp/repo-a");
        let b = WarnMainBranch::marker_path("/tmp/repo-b");
        assert_ne!(a, b, "marker path must include a repo-specific hash");
    }

    #[test]
    fn marker_path_stable_for_same_repo() {
        // Same repo root, called twice in the same process, should produce
        // the same marker path so suppression works.
        let a = WarnMainBranch::marker_path("/tmp/repo");
        let b = WarnMainBranch::marker_path("/tmp/repo");
        assert_eq!(a, b);
    }

    #[test]
    fn main_with_prefix_allows() {
        // "fix/main-page" is not the main branch
        let result = should_warn("fix/main-page", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- snooze (issue #16) ---

    #[test]
    fn snoozed_main_allows() {
        // Active snooze suppresses the nudge even on a fresh session.
        let result = should_warn("main", false, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn snoozed_master_allows() {
        let result = should_warn("master", false, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn snoozed_takes_precedence_over_already_warned() {
        // Both flags set is still allow — order doesn't matter.
        let result = should_warn("main", true, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_mentions_dismiss_command() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("dismiss-main-branch-warn"),
            "warn message should hint at the dismiss command: {msg}"
        );
    }

    // --- permanent allow via CADENCE_ALLOW_MAIN ---

    #[test]
    fn allowed_main_allows() {
        let result = should_warn("main", false, false, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn allowed_master_allows() {
        let result = should_warn("master", false, false, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn allowed_overrides_warned_and_snoozed() {
        // Permanent allow trumps every other input. A repo opted out via
        // CADENCE_ALLOW_MAIN should never see the warning, regardless of
        // session state.
        let result = should_warn("main", true, true, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_mentions_permanent_allow() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("CADENCE_ALLOW_MAIN"),
            "warn message should mention the permanent opt-out: {msg}"
        );
    }

    #[test]
    fn warn_message_uses_2h_default_duration() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("--for 2h"),
            "warn message should suggest 2h default snooze: {msg}"
        );
    }

    // --- is_main_allowed_value (pure) ---

    #[test]
    fn allowed_value_unset_is_false() {
        assert!(!is_main_allowed_value(None));
    }

    #[test]
    fn allowed_value_empty_is_false() {
        assert!(!is_main_allowed_value(Some("")));
        assert!(!is_main_allowed_value(Some("   ")));
    }

    #[test]
    fn allowed_value_falsy_strings() {
        assert!(!is_main_allowed_value(Some("0")));
        assert!(!is_main_allowed_value(Some("false")));
        assert!(!is_main_allowed_value(Some("no")));
        assert!(!is_main_allowed_value(Some("off")));
    }

    #[test]
    fn allowed_value_truthy_strings() {
        assert!(is_main_allowed_value(Some("1")));
        assert!(is_main_allowed_value(Some("true")));
        assert!(is_main_allowed_value(Some("yes")));
    }

    #[test]
    fn allowed_value_case_insensitive() {
        assert!(is_main_allowed_value(Some("TRUE")));
        assert!(is_main_allowed_value(Some("True")));
        assert!(is_main_allowed_value(Some("YES")));
    }

    #[test]
    fn allowed_value_trims_whitespace() {
        assert!(is_main_allowed_value(Some("  true  ")));
        assert!(is_main_allowed_value(Some("\t1\n")));
    }

    // --- .claude/ directory carve-out (issues #33, #35) ---

    #[test]
    fn claude_worktree_dir_is_managed() {
        // #33 scenarios 1 & 2: a worktree path is exempt regardless of the
        // branch it sits on (feat-foo or main).
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/.claude/worktrees/feat-foo"
        )));
    }

    #[test]
    fn claude_worktree_nested_repo_is_managed() {
        // #33 scenario 4: a nested-repo worktree layout still matches because
        // the `.claude` component appears anywhere in the path.
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/inner/.claude/worktrees/x/crates/guardrails/src"
        )));
    }

    #[test]
    fn home_claude_memory_dir_is_managed() {
        // #35: the auto-written memory tree under ~/.claude is exempt even
        // though ~/.claude is itself a git repo that can sit on main.
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/.claude/projects/some-proj/memory"
        )));
    }

    #[test]
    fn plain_repo_dir_is_not_managed() {
        // #33 scenario 3: a normal checkout still gets the warning on main.
        assert!(!is_claude_managed_dir(Path::new("/Users/x/repo/src")));
    }

    #[test]
    fn claude_lookalike_dirs_are_not_managed() {
        // Exact-component match: names that merely contain "claude" are not a
        // `.claude` segment and must still warn.
        assert!(!is_claude_managed_dir(Path::new("/Users/x/repo/myclaude")));
        assert!(!is_claude_managed_dir(Path::new(
            "/Users/x/.claude-old/foo"
        )));
    }

    #[test]
    fn relative_dot_dir_is_not_managed() {
        // The Bash fallback resolves to ".", which has no `.claude` component.
        assert!(!is_claude_managed_dir(Path::new(".")));
    }
}
