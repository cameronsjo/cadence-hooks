//! `session end` — SessionEnd logger.
//!
//! Deregisters this session from the repo registry when it ends (`/clear`,
//! exit, logout), so it stops appearing as a live peer immediately rather than
//! lingering until the next `session start` sweeps it by age (#97). Liveness
//! is otherwise mtime-only, so without this an ended session is disclosed as a
//! phantom peer for up to the staleness window.
//!
//! `HookEvent` has no `SessionEnd` variant, so this is modelled as a
//! fire-and-forget [`Logger`] (like `heartbeat`) that reacts to
//! `hook_event_name` in the payload. Never blocks, never errors (ADR-0001).

use crate::identity;
use crate::registry;
use cadence_hooks_core::{Logger, MetricsInput};

/// Remove this session's registry file on SessionEnd.
pub struct End;

impl Logger for End {
    fn name(&self) -> &str {
        "end"
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
        run_end(input.hook_event_name.as_deref(), &dir, sid);
    }
}

/// Testable core: deregister `session_id` from `dir`, but ONLY on SessionEnd.
/// The registry path is injected so tests can target a tempdir without a git
/// repository.
///
/// The event gate lives here, not just in the hooks.json wiring, because this
/// DELETES the session's lane: a misrouted wiring on any other event must never
/// reach `remove_own`, or a live session would erase its own record on, say,
/// its first PostToolUse.
///
/// Deregistering on *every* SessionEnd reason is deliberate, and reconciles with
/// the #69 re-registration-preserves-lane fix in [`crate::start`]: empirically
/// (verified 2026-06-17), `/clear` and `/compact` mint a NEW session_id and fire
/// SessionEnd for the *old* id — so deregistering the old id removes a genuine
/// phantom, and the successor session registers fresh under its own id. #69's
/// same-session_id re-registration path is therefore the *resume* path
/// (`--resume`/`--continue` reusing an id after an exit), not the `/clear` path.
/// We do NOT gate on the `reason` field: the only id-reusing case is resume, and
/// there the lost `intent`/`touching` are best-effort and self-heal on the next
/// heartbeat (`touch_own` rebuilds the record) — a bounded, transient
/// degradation, not the lane loss #69 fixed. (Compaction uses the separate
/// `PreCompact` hook, not SessionEnd, so a live session never self-deregisters
/// mid-work.) Revisiting the resume case is tracked as claude-configurations#136.
pub fn run_end(hook_event_name: Option<&str>, dir: &std::path::Path, session_id: &str) {
    if hook_event_name != Some("SessionEnd") {
        return;
    }
    let _ = registry::remove_own(dir, session_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SessionRecord;
    use tempfile::TempDir;

    fn record(name: &str, session_id: &str) -> SessionRecord {
        SessionRecord {
            name: name.into(),
            session_id: session_id.into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        }
    }

    #[test]
    fn run_end_on_session_end_removes_lane() {
        let tmp = TempDir::new().unwrap();
        registry::write_record(tmp.path(), &record("quiet-loom", "self-session")).unwrap();
        run_end(Some("SessionEnd"), tmp.path(), "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_none(),
            "SessionEnd deregisters the session's lane"
        );
    }

    #[test]
    fn run_end_ignores_non_session_end_event() {
        // The gate is the whole point: this logger DELETES the lane, so a
        // misrouted wiring on any other event (here PostToolUse) must NOT
        // reach remove_own — else a live session erases its own record on its
        // first tool call.
        let tmp = TempDir::new().unwrap();
        registry::write_record(tmp.path(), &record("quiet-loom", "self-session")).unwrap();
        run_end(Some("PostToolUse"), tmp.path(), "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_some(),
            "a non-SessionEnd event must NOT deregister the live session"
        );
    }

    #[test]
    fn run_end_ignores_missing_event() {
        let tmp = TempDir::new().unwrap();
        registry::write_record(tmp.path(), &record("quiet-loom", "self-session")).unwrap();
        run_end(None, tmp.path(), "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_some(),
            "an absent hook_event_name must NOT deregister the session"
        );
    }
}
