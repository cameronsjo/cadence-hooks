//! `session heartbeat` — PostToolUse logger.
//!
//! Touches this session's registry file on every (wired) tool call, so file
//! mtime is the liveness signal. Also refreshes the last-observed branch.
//! The triggering command decides whether THIS session deliberately switched
//! branches: only a self-switch moves the drift baseline (`declared_branch`);
//! a peer moving shared HEAD updates the observed branch but leaves the
//! baseline, so the divergence stays detectable at commit time (#70).
//! Fire-and-forget: implemented as a [`Logger`], never blocks, never errors.

use crate::guard;
use crate::identity;
use crate::registry;
use cadence_hooks_core::shell::{git_command, strip_quotes};
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
        run_heartbeat(&dir, sid, branch, input.command());
    }
}

/// Testable core: upsert the session's record, refreshing mtime and the
/// last-observed branch. `command` is the triggering tool's Bash command, if
/// any; the drift baseline moves only when it is THIS session's own
/// `git checkout`/`switch`. Quotes are stripped first so a quoted command (e.g.
/// `echo 'git checkout x'`) is not mistaken for a real switch — the same
/// discipline `guard`/`branch_drift` apply before calling these parsers.
pub fn run_heartbeat(
    dir: &std::path::Path,
    session_id: &str,
    branch: Option<String>,
    command: Option<&str>,
) {
    let is_self_switch = command
        .map(|c| guard::is_branch_switch(&strip_quotes(c)))
        .unwrap_or(false);
    let _ = registry::touch_own(dir, session_id, branch, is_self_switch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SessionRecord;
    use tempfile::TempDir;

    #[test]
    fn heartbeat_non_switch_updates_observed_branch_but_not_baseline() {
        // Reframed from the bug-codifying `heartbeat_refreshes_existing_record`,
        // which asserted the heartbeat overwriting the recorded branch was
        // correct. It is not: a non-switch heartbeat (a peer moved shared HEAD,
        // then this session ran e.g. `cargo build`) must refresh the *observed*
        // branch for display, but must NOT move the drift baseline — otherwise
        // the peer's checkout is absorbed and the divergence vanishes at commit
        // (#70).
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            name: "quiet-loom".into(),
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            "self-session",
            Some("feat/peer-moved".into()),
            Some("cargo build"),
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.branch.as_deref(),
            Some("feat/peer-moved"),
            "observed branch refreshed for display"
        );
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("main"),
            "drift baseline unchanged on a non-switch — #70 fix"
        );
    }

    #[test]
    fn heartbeat_self_checkout_updates_declared_baseline() {
        // A self-switch (this session's own `git checkout`/`switch`) re-baselines
        // the drift reference to where it now intends to commit, so a later
        // commit on that branch is not falsely flagged as drift.
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            name: "quiet-loom".into(),
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            "self-session",
            Some("feat/mine".into()),
            Some("git checkout -b feat/mine"),
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(back.branch.as_deref(), Some("feat/mine"));
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("feat/mine"),
            "self-switch re-baselines the drift reference"
        );
    }

    #[test]
    fn heartbeat_creates_record_when_missing() {
        // A heartbeat firing before `session start` (partial plugin wiring)
        // must still register the session.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("sessions");
        run_heartbeat(&dir, "unregistered-session", Some("main".into()), None);
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

        run_heartbeat(tmp.path(), "self-session", None, None);

        let peers = registry::read_peers(tmp.path(), "other", 0);
        assert!(!peers[0].stale, "heartbeat resets liveness");
    }
}
