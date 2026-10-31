//! `SessionStart` — stamp the current timestamp as this session's start marker
//! at `<state_dir>/<session_id>.start`, so the paired `log-session` logger can
//! compute a session's wall-clock duration at `SessionEnd`.
//!
//! Sibling of [`crate::snapshot`]: same before-marker shape, different pairing
//! (`log-session` reads and consumes the marker instead of `log-commit`).
//! Fire-and-forget: silent no-op on any failure, never blocks.

use crate::common;
use cadence_hooks_core::{Logger, MetricsInput};

/// Stamps the session start timestamp at `SessionStart`.
pub struct LogSessionStart;

impl Logger for LogSessionStart {
    fn name(&self) -> &str {
        "log-session-start"
    }

    fn run(&self, input: &MetricsInput) {
        if input.hook_event_name.as_deref() != Some("SessionStart") {
            return;
        }

        let Some(session_id) = input
            .session_id
            .as_deref()
            .filter(|s| common::is_safe_session_id(s))
        else {
            return;
        };

        let dir = common::state_dir();
        if common::create_private_dir(&dir).is_err() {
            return;
        }
        if starts_a_counter(input.source.as_deref()) {
            crate::session_commits::start(&dir, session_id);
        }
        if let Ok(mut file) =
            common::open_state_marker(&dir.join(format!("{session_id}.start")), false)
        {
            let _ = std::io::Write::write_all(&mut file, common::utc_timestamp().as_bytes());
        }
    }
}

/// Only a session that is new under its id starts a commit counter: `startup`,
/// and `clear` (a fresh id and transcript). A `resume` reuses an id whose
/// earlier commits sit in the ledger, and `compact` may too, so an empty
/// counter would hide them and re-price the whole transcript at the next
/// commit; those stay on the ledger. A missing `source` also stays on the
/// ledger, which is slower but still counts correctly. Pure.
fn starts_a_counter(source: Option<&str>) -> bool {
    matches!(source, Some("startup" | "clear"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with(event: &str, session: Option<&str>) -> MetricsInput {
        MetricsInput {
            session_id: session.map(String::from),
            hook_event_name: Some(event.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn only_new_sessions_start_a_counter() {
        assert!(starts_a_counter(Some("startup")));
        assert!(starts_a_counter(Some("clear")));
        for source in [Some("resume"), Some("compact"), Some("other"), None] {
            assert!(!starts_a_counter(source), "{source:?}");
        }
    }

    #[test]
    fn name_is_log_session_start() {
        assert_eq!(LogSessionStart.name(), "log-session-start");
    }

    #[test]
    fn non_session_start_is_noop() {
        LogSessionStart.run(&input_with("SessionEnd", Some("s1")));
    }

    #[test]
    fn missing_session_is_noop() {
        LogSessionStart.run(&input_with("SessionStart", None));
        LogSessionStart.run(&input_with("SessionStart", Some("")));
    }

    #[test]
    fn unsafe_session_id_is_noop() {
        LogSessionStart.run(&input_with("SessionStart", Some("../../etc/passwd")));
        LogSessionStart.run(&input_with("SessionStart", Some("a/b")));
    }

    #[test]
    fn session_start_writes_marker() {
        // `CADENCE_METRICS_DIR` is process-global — serialize against every
        // other env-mutating test crate-wide (see `common::ENV_LOCK`).
        let _guard = common::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized against every other env-mutating test crate-wide via `common::ENV_LOCK`.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", tmp.path());
        }

        LogSessionStart.run(&input_with("SessionStart", Some("s1")));

        let marker = tmp.path().join("state").join("s1.start");
        assert!(marker.is_file(), "expected {marker:?} to exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the marker names a session: owner-only");
        }
        let contents = std::fs::read_to_string(&marker).unwrap();
        assert!(
            contents.ends_with('Z'),
            "expected an ISO timestamp: {contents}"
        );

        // SAFETY: serialized against every other env-mutating test crate-wide via `common::ENV_LOCK`.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }
}
