//! `session heartbeat` — PostToolUse logger.
//!
//! Touches this session's registry file on every (wired) tool call, so file
//! mtime is the liveness signal. Also refreshes the recorded branch, which is
//! how peers learn about branch drift. Fire-and-forget: implemented as a
//! [`Logger`], never blocks, never errors.

use crate::identity;
use crate::registry;
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::{Logger, MetricsInput};

/// Touch this session's registry file (mtime = heartbeat).
pub struct Heartbeat;

impl Logger for Heartbeat {
    fn name(&self) -> &str {
        "heartbeat"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(sid) = input
            .session_id
            .as_deref()
            .filter(|s| identity::is_safe_session_id(s))
        else {
            return;
        };
        let Some(cwd) = input.cwd.as_deref() else {
            return;
        };
        let Some(dir) = registry::sessions_dir(cwd) else {
            return;
        };
        let branch = git_command(cwd, &["branch", "--show-current"]);
        run_heartbeat(&dir, sid, branch);
    }
}

/// Testable core: upsert the session's record, refreshing mtime and branch.
pub fn run_heartbeat(dir: &std::path::Path, session_id: &str, branch: Option<String>) {
    let _ = registry::touch_own(dir, session_id, branch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SessionRecord;
    use tempfile::TempDir;

    #[test]
    fn heartbeat_refreshes_existing_record() {
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            name: "quiet-loom".into(),
            session_id: "self-session".into(),
            branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(tmp.path(), "self-session", Some("feat/drifted".into()));

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.branch.as_deref(),
            Some("feat/drifted"),
            "branch drift recorded"
        );
    }

    #[test]
    fn heartbeat_creates_record_when_missing() {
        // A heartbeat firing before `session start` (partial plugin wiring)
        // must still register the session.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("sessions");
        run_heartbeat(&dir, "unregistered-session", Some("main".into()));
        assert!(registry::read_own(&dir, "unregistered-session").is_some());
    }

    #[test]
    fn heartbeat_makes_stale_record_live_again() {
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            name: "quiet-loom".into(),
            session_id: "self-session".into(),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Before heartbeat: stale at a zero-second threshold (any age counts).
        let peers = registry::read_peers(tmp.path(), "other", 0);
        assert!(peers[0].stale);

        run_heartbeat(tmp.path(), "self-session", None);

        let peers = registry::read_peers(tmp.path(), "other", 0);
        assert!(!peers[0].stale, "heartbeat resets liveness");
    }
}
