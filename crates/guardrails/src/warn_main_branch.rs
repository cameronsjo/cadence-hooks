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

use crate::dismiss_main_branch_warn;
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;

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
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "yes") => true,
        _ => false,
    }
}

/// Pure decision: should we warn about editing on this branch?
///
/// Returns `Nudge` if on a default branch, not already warned this session,
/// not currently snoozed, and not permanently allowed via env var.
fn should_warn(
    branch: &str,
    already_warned: bool,
    snoozed: bool,
    allowed: bool,
) -> CheckResult {
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
    fn marker_path() -> Option<PathBuf> {
        let repo_root = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

        let mut hasher = DefaultHasher::new();
        repo_root.hash(&mut hasher);
        let hash = hasher.finish();

        // Use parent PID for session scoping — hooks are spawned as child processes,
        // so process::id() changes on every invocation. PPID is the Claude Code process.
        let ppid = std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(std::process::id);

        Some(PathBuf::from(format!(
            "/tmp/.claude-main-branch-warned-{hash:x}-{ppid}"
        )))
    }
}

impl Check for WarnMainBranch {
    fn name(&self) -> &str {
        "warn-main-branch"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        // Get current branch
        let branch = match Command::new("git")
            .args(["symbolic-ref", "--short", "HEAD"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        let already_warned = Self::marker_path().as_ref().is_some_and(|p| p.exists());
        let snoozed = dismiss_main_branch_warn::is_snoozed_now();
        let allowed = is_main_allowed();

        let result = should_warn(&branch, already_warned, snoozed, allowed);

        // Create marker on warn to suppress future warnings this session
        if result.outcome == Outcome::Nudge
            && let Some(marker) = Self::marker_path()
        {
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
}
