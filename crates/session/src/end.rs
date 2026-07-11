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
/// We do NOT gate on the `reason` field. This was investigated and ruled out
/// under claude-configurations#136 (resolved 2026-06-19): there is no exit-time
/// signal that a *later* cold `--resume` is coming. A clean exit fires reason
/// `other` / `prompt_input_exit` whether or not the id is ever resumed, and the
/// SessionEnd `reason: "resume"` value covers only in-the-moment resumption, not
/// a cold `claude --resume <id>` minutes or hours later — so a `reason` allowlist
/// could not catch the very case #136 is about, while still adding staleness-prone
/// state to maintain.
///
/// The residual is accepted as a bounded degradation. On resume,
/// `--resume`/`--continue` reuses the id and fires SessionStart (`source=resume`),
/// so [`crate::start`]'s re-registration runs — but finds no record (this fn
/// removed it) and rebuilds a *minimal* lane: liveness, `branch`, and the
/// `declared_branch` baseline re-seed immediately, while `intent`/`touching` are
/// best-effort metadata the session re-declares via `session declare` (they are
/// not auto-restored). The only fix that would carry `intent`/`touching` across a
/// resume is a tombstone / soft-delete, deliberately deferred (P3) until the loss
/// proves to matter in practice. (Compaction uses the separate `PreCompact` hook,
/// not SessionEnd, so a live session never self-deregisters mid-work.)
///
/// **Goal exception.** A record carrying an ACTIVE goal (`goal declare`) is
/// *orphaned* — kept on disk with `goal.orphaned_epoch` stamped — instead of
/// removed. `/clear` mints a NEW session id for the successor (re-verified live
/// 2026-07-10), so deleting the record here would destroy the goal the
/// successor is entitled to adopt via `goal reinject` (`source == "clear"`).
/// The orphan is not a phantom peer ([`registry::read_peers`] skips
/// orphaned-goal records), is consumed by the adopting SessionStart, and is
/// otherwise reaped by the normal mtime sweep — no second store, no second
/// sweep rule. This is precisely the tombstone/soft-delete deferred above,
/// scoped to the one field whose loss proved to matter.
pub fn run_end(hook_event_name: Option<&str>, dir: &std::path::Path, session_id: &str) {
    if hook_event_name != Some("SessionEnd") {
        return;
    }
    if let Some(mut record) = registry::read_own(dir, session_id)
        && let Some(goal) = record.goal.as_mut()
        && goal.is_active()
    {
        goal.orphaned_epoch = Some(identity::now_epoch());
        let _ = registry::write_record(dir, &record);
        return;
    }
    let _ = registry::remove_own(dir, session_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{GoalState, SessionRecord};
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
    fn run_end_orphans_goal_bearing_record_instead_of_removing() {
        // The /clear handoff: the successor session arrives under a NEW id, so
        // the goal-bearing record must survive SessionEnd — marked orphaned,
        // not deleted — for `goal reinject` to adopt.
        let tmp = TempDir::new().unwrap();
        let mut rec = record("quiet-loom", "self-session");
        rec.goal = Some(GoalState {
            text: "ship the goal primitive".into(),
            ..Default::default()
        });
        registry::write_record(tmp.path(), &rec).unwrap();
        run_end(Some("SessionEnd"), tmp.path(), "self-session");
        let back = registry::read_own(tmp.path(), "self-session")
            .expect("goal-bearing record survives SessionEnd");
        assert!(
            back.goal.unwrap().orphaned_epoch.is_some(),
            "record is marked orphaned for the successor to adopt"
        );
    }

    #[test]
    fn run_end_removes_record_with_superseded_goal() {
        // Only an ACTIVE goal earns the orphan handoff — a superseded goal is
        // dead weight and the record deregisters normally.
        let tmp = TempDir::new().unwrap();
        let mut rec = record("quiet-loom", "self-session");
        rec.goal = Some(GoalState {
            text: "old goal".into(),
            superseded: true,
            ..Default::default()
        });
        registry::write_record(tmp.path(), &rec).unwrap();
        run_end(Some("SessionEnd"), tmp.path(), "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_none(),
            "superseded goal does not exempt the record from deregistration"
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
