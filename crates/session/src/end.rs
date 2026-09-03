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
        // Deregister from the cross-checkout mirror FIRST, and unconditionally.
        // It needs only the session id, while everything below needs a repo —
        // and a session that ends from a cwd outside any git repository (the
        // operator cd'd to ~ before exiting) would otherwise leave a ghost
        // record blocking every liveness-gated operation for the full stale
        // window, naming a session that has ended. The read side was
        // deliberately changed to consult the mirror when not in a repo, so the
        // removal side has to agree (cadence-hooks#634).
        if input.hook_event_name.as_deref() == Some("SessionEnd") {
            let _ = registry::remove_own(&registry::global_sessions_dir(), sid);
        }
        let Some(cwd) = input.cwd.as_deref() else {
            return;
        };
        let Some(dir) = registry::sessions_dir(cwd) else {
            return;
        };
        run_end(input.hook_event_name.as_deref(), &dir, None, sid);
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
pub fn run_end(
    hook_event_name: Option<&str>,
    dir: &std::path::Path,
    global_dir: Option<&std::path::Path>,
    session_id: &str,
) {
    if hook_event_name != Some("SessionEnd") {
        return;
    }
    let _ = registry::remove_own(dir, session_id);
    // Injected rather than resolved here, so a test cannot reach the machine's
    // real mirror. `End::run` does the unconditional removal above, before it
    // needs a repo; this arm exists for callers that already hold both dirs.
    if let Some(global) = global_dir {
        let _ = registry::remove_own(global, session_id);
    }
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
        run_end(Some("SessionEnd"), tmp.path(), None, "self-session");
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
        run_end(Some("PostToolUse"), tmp.path(), None, "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_some(),
            "a non-SessionEnd event must NOT deregister the live session"
        );
    }

    #[test]
    fn run_end_ignores_missing_event() {
        let tmp = TempDir::new().unwrap();
        registry::write_record(tmp.path(), &record("quiet-loom", "self-session")).unwrap();
        run_end(None, tmp.path(), None, "self-session");
        assert!(
            registry::find_own(tmp.path(), "self-session").is_some(),
            "an absent hook_event_name must NOT deregister the session"
        );
    }
}
