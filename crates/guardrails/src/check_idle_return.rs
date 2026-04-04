//! Detect idle returns and suggest re-orientation.
//!
//! Tracks the last edit timestamp via a temp-file marker. When the user
//! returns after 5+ minutes of inactivity, warns them to review context.
//! After 8+ hours, suggests starting a fresh session.

use cadence_hooks_core::{Check, CheckResult, HookInput};

#[cfg(test)]
use cadence_hooks_core::Outcome;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;
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

        Some(PathBuf::from(format!("/tmp/.claude-last-edit-{hash:x}")))
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

    fn run(&self, _input: &HookInput) -> CheckResult {
        let Some(marker) = Self::marker_path() else {
            return CheckResult::allow();
        };

        let now = Self::now_secs();

        let gap = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|contents| contents.trim().parse::<u64>().ok())
            .map(|last_ts| now.saturating_sub(last_ts));

        let result = idle_outcome(gap);

        // Always update marker with current timestamp
        let _ = std::fs::write(&marker, now.to_string());

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
        assert!(result.message.as_deref().expect("nudge should have a message").contains("5m"));
    }

    #[test]
    fn ten_minutes_idle_warns() {
        let result = idle_outcome(Some(600));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.as_deref().expect("nudge should have a message").contains("10m"));
    }

    #[test]
    fn one_hour_idle_warns() {
        let result = idle_outcome(Some(3600));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.as_deref().expect("nudge should have a message").contains("60m"));
    }

    #[test]
    fn just_under_new_session_warns() {
        let result = idle_outcome(Some(28799));
        assert_eq!(result.outcome, Outcome::Nudge);
        // 28799 / 60 = 479 minutes
        assert!(result.message.as_deref().expect("nudge should have a message").contains("479m"));
    }

    #[test]
    fn exactly_at_new_session_warns_fresh_session() {
        // 8 hours — stale session, suggest fresh start
        let result = idle_outcome(Some(28800));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.as_deref().expect("nudge should have a message").contains("8h"));
        assert!(result.message.as_deref().expect("nudge should have a message").contains("fresh session"));
    }

    #[test]
    fn day_old_session_warns_fresh_session() {
        let result = idle_outcome(Some(86400));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.as_deref().expect("nudge should have a message").contains("24h"));
        assert!(result.message.as_deref().expect("nudge should have a message").contains("fresh session"));
    }

    #[test]
    fn twelve_hour_gap_warns_fresh_session() {
        let result = idle_outcome(Some(43200));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.as_deref().expect("nudge should have a message").contains("12h"));
        assert!(result.message.as_deref().expect("nudge should have a message").contains("fresh session"));
    }
}
