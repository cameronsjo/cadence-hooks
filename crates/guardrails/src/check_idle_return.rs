//! Detect idle returns and suggest re-orientation.
//!
//! Tracks the last edit timestamp via a temp-file marker. When the user
//! returns after 5+ minutes of inactivity, warns them to review context.
//! After 8+ hours, suggests starting a fresh session.

use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::{Check, CheckResult, HookInput};

#[cfg(test)]
use cadence_hooks_core::Outcome;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const IDLE_THRESHOLD_SECS: u64 = 300; // 5 minutes
const NEW_SESSION_THRESHOLD_SECS: u64 = 28800; // 8 hours

/// Pure decision: determine outcome based on the idle gap in seconds.
///
/// - `None`: no previous marker (first edit) — allow
/// - gap < 5 min: allow (active session)
/// - gap 5 min to 8 hr: warn (idle return)
/// - gap >= 8 hr: warn (stale session, suggest fresh session)
fn idle_outcome(gap: Option<u64>) -> CheckResult {
    let Some(gap) = gap else {
        return CheckResult::allow();
    };

    if gap >= NEW_SESSION_THRESHOLD_SECS {
        let hours = gap / 3600;
        CheckResult::nudge(format!(
            "It's been {hours}h since your last edit. Consider starting a \
             fresh session and re-orienting before continuing."
        ))
    } else if gap >= IDLE_THRESHOLD_SECS {
        let mins = gap / 60;
        CheckResult::nudge(format!(
            "It's been {mins}m since your last edit. Before continuing: \
             check for uncommitted changes worth committing, and consider \
             saving any learnings to auto memory."
        ))
    } else {
        CheckResult::allow()
    }
}

/// Warns when the user returns after extended idle time.
pub struct CheckIdleReturn;

impl CheckIdleReturn {
    /// The last-edit marker, scoped to this session AND the edited file's repo.
    ///
    /// Repo resolution uses `git -C <cwd>` (house style) so nested-repo edits key
    /// to the right checkout. Session-scoping is the #132 fix: "idle" now means
    /// *this session's* last edit — a peer's activity in the same repo no longer
    /// refreshes your marker and masks your idle return.
    fn marker_path(input: &HookInput) -> Option<PathBuf> {
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let repo_root = git_command(cwd, &["rev-parse", "--show-toplevel"])?;
        Some(cadence_hooks_core::markers::session_marker(
            input,
            "last-edit",
            Some(&repo_root),
        ))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Check for CheckIdleReturn {
    fn name(&self) -> &str {
        "check-idle-return"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(marker) = Self::marker_path(input) else {
            return CheckResult::allow();
        };

        let now = Self::now_secs();

        let gap = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|contents| contents.trim().parse::<u64>().ok())
            .map(|last_ts| now.saturating_sub(last_ts));

        let result = idle_outcome(gap);

        // Always update this session's marker with the current timestamp.
        let _ = cadence_hooks_core::markers::write_marker(&marker, &now.to_string());

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_previous_marker_allows() {
        let result = idle_outcome(None);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn zero_gap_allows() {
        let result = idle_outcome(Some(0));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn recent_edit_allows() {
        // 2 minutes — well within active session
        let result = idle_outcome(Some(120));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn just_under_threshold_allows() {
        let result = idle_outcome(Some(299));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn exactly_at_threshold_warns() {
        let result = idle_outcome(Some(300));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("5m")
        );
    }

    #[test]
    fn ten_minutes_idle_warns() {
        let result = idle_outcome(Some(600));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("10m")
        );
    }

    #[test]
    fn one_hour_idle_warns() {
        let result = idle_outcome(Some(3600));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("60m")
        );
    }

    #[test]
    fn just_under_new_session_warns() {
        let result = idle_outcome(Some(28799));
        assert_eq!(result.outcome, Outcome::Nudge);
        // 28799 / 60 = 479 minutes
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("479m")
        );
    }

    #[test]
    fn exactly_at_new_session_warns_fresh_session() {
        // 8 hours — stale session, suggest fresh start
        let result = idle_outcome(Some(28800));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("8h")
        );
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("fresh session")
        );
    }

    #[test]
    fn day_old_session_warns_fresh_session() {
        let result = idle_outcome(Some(86400));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("24h")
        );
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("fresh session")
        );
    }

    #[test]
    fn twelve_hour_gap_warns_fresh_session() {
        let result = idle_outcome(Some(43200));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("12h")
        );
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("fresh session")
        );
    }

    // --- session-scoped marker keying (#132) ---

    fn init_git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("git init");
        assert!(ok.success(), "git init failed");
        dir
    }

    fn input_in_repo(session_id: &str, repo: &std::path::Path) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            session_id: Some(session_id.into()),
            cwd: Some(repo.to_string_lossy().into_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn marker_path_differs_per_session() {
        // Same repo, two sessions → distinct markers. Before #132 the marker was
        // keyed on the repo hash alone, so both sessions shared one path.
        let repo = init_git_repo();
        let a = CheckIdleReturn::marker_path(&input_in_repo("sid-a", repo.path()));
        let b = CheckIdleReturn::marker_path(&input_in_repo("sid-b", repo.path()));
        assert!(a.is_some() && b.is_some(), "repo resolves");
        assert_ne!(a, b, "same repo, different session → distinct markers");
    }

    #[test]
    fn peer_activity_does_not_mask_idle_session() {
        // Session A last edited 10m ago; peer B just edited in the same repo. A's
        // idle return must still fire — B's fresh marker is B's, not A's (#132).
        let repo = init_git_repo();
        let input_a = input_in_repo("idle-session-a", repo.path());
        let input_b = input_in_repo("busy-session-b", repo.path());
        let now = CheckIdleReturn::now_secs();
        let marker_a = CheckIdleReturn::marker_path(&input_a).expect("A marker");
        let marker_b = CheckIdleReturn::marker_path(&input_b).expect("B marker");
        cadence_hooks_core::markers::write_marker(&marker_a, &(now - 600).to_string()).unwrap();
        cadence_hooks_core::markers::write_marker(&marker_b, &now.to_string()).unwrap();

        let result = CheckIdleReturn.run(&input_a);
        assert_eq!(
            result.outcome,
            Outcome::Nudge,
            "A's idle return still fires"
        );
        assert!(
            result.message.as_deref().unwrap().contains("10m"),
            "A sees its own 10m gap, not B's fresh activity"
        );
    }
}
