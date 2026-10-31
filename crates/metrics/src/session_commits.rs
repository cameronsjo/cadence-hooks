//! Per-session commit state under `<state>/commits/<session>/`, so neither
//! `log-commit` nor `log-session` has to read the commits ledger to learn what
//! this session already committed (cameronsjo/cadence-hooks#1589).
//!
//! - `count`: one byte appended per commit. The count is the file length, so
//!   two commits landing at once each add their byte (`O_APPEND`) and neither
//!   increment is lost.
//! - `last`: the newest commit row's `lastMessageId`, overwritten per commit.
//!
//! `log-session-start` creates an empty `count` when a session starts fresh
//! (`source` `startup` or `clear`), so a session that never commits reads as
//! zero without a ledger read. Any other session (started before this state
//! existed, a resume after its SessionEnd, a `compact`, no `source`) has no
//! `count`; `record` never creates one, and its readers fall back to the
//! bounded ledger read. `log-session` removes the directory at `SessionEnd`, after
//! reading it. Every step is fail-open (ADR-0001): a write that fails leaves
//! the fallback in charge.

use crate::common;
use std::io::Write;
use std::path::{Path, PathBuf};

const COUNT_FILE: &str = "count";
const LAST_FILE: &str = "last";

/// `<state>/commits/<session>`. `None` for a session id unsafe in a path. Pure.
fn session_dir(state_dir: &Path, session_id: &str) -> Option<PathBuf> {
    common::is_safe_session_id(session_id).then(|| state_dir.join("commits").join(session_id))
}

/// Start the session's counter at zero (`SessionStart`). An existing counter is
/// left alone: a resumed session keeps its count.
pub fn start(state_dir: &Path, session_id: &str) {
    let Some(dir) = session_dir(state_dir, session_id) else {
        return;
    };
    if common::create_private_dir(&dir).is_ok() {
        let _ = open_count(&dir.join(COUNT_FILE), true);
    }
}

/// Record one commit and its `lastMessageId`, only for a session whose counter
/// [`start`] created. A session without one (started before this state
/// existed, or resumed after its SessionEnd) has earlier commits only in the
/// ledger, so creating a counter here would hide them; it stays on the ledger.
pub fn record(state_dir: &Path, session_id: &str, last_message_id: Option<&str>) {
    let Some(dir) = session_dir(state_dir, session_id) else {
        return;
    };
    let Ok(mut file) = open_count(&dir.join(COUNT_FILE), false) else {
        return;
    };
    if file.write_all(b".").is_err() {
        return;
    }
    let last = dir.join(LAST_FILE);
    match last_message_id {
        Some(id) => {
            // Write a temp file and rename it over `last`, so a concurrent
            // reader sees the old id or the new one, never an empty or partial
            // file (an empty one would re-price from session start).
            let tmp = dir.join(format!("{LAST_FILE}.{}.tmp", std::process::id()));
            let written = common::open_state_marker(&tmp, false)
                .and_then(|mut file| file.write_all(id.as_bytes()));
            if written.is_err() || std::fs::rename(&tmp, &last).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        None => {
            let _ = std::fs::remove_file(&last);
        }
    }
}

/// Commits recorded this session, or `None` when the session has no counter
/// (started before this state existed, or its write failed) and the caller
/// should fall back to the ledger.
pub fn count(state_dir: &Path, session_id: &str) -> Option<u64> {
    let path = session_dir(state_dir, session_id)?.join(COUNT_FILE);
    std::fs::symlink_metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|m| m.len())
}

/// What the state knows about the previous commit's `lastMessageId`:
/// `Known(Some)` after a commit, `Known(None)` for a counted session with no
/// commit yet, `Unknown` when there is no counter and the caller should fall
/// back to the ledger.
#[derive(Debug, PartialEq, Eq)]
pub enum LastMessage {
    Known(Option<String>),
    Unknown,
}

pub fn last_message_id(state_dir: &Path, session_id: &str) -> LastMessage {
    let Some(dir) = session_dir(state_dir, session_id) else {
        return LastMessage::Unknown;
    };
    if count(state_dir, session_id).is_none() {
        return LastMessage::Unknown;
    }
    match read_nofollow(&dir.join(LAST_FILE)) {
        Ok(id) if !id.trim().is_empty() => LastMessage::Known(Some(id.trim().to_string())),
        Ok(_) => LastMessage::Known(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LastMessage::Known(None),
        Err(_) => LastMessage::Unknown,
    }
}

/// Read a small state file in one open that refuses a symlink, so there is no
/// check-then-read gap.
fn read_nofollow(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut text = String::new();
    options.open(path)?.take(4096).read_to_string(&mut text)?;
    Ok(text)
}

/// Append-only, `0600`, never through a symlink. `create` only from [`start`].
fn open_count(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(create).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_started_session_counts_zero_and_knows_it_has_no_last_message() {
        let tmp = tempfile::tempdir().unwrap();
        start(tmp.path(), "s1");
        assert_eq!(count(tmp.path(), "s1"), Some(0));
        assert_eq!(last_message_id(tmp.path(), "s1"), LastMessage::Known(None));
    }

    #[test]
    fn an_unstarted_session_is_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(count(tmp.path(), "s1"), None);
        assert_eq!(last_message_id(tmp.path(), "s1"), LastMessage::Unknown);
    }

    #[test]
    fn commits_count_up_and_keep_the_newest_message_id() {
        let tmp = tempfile::tempdir().unwrap();
        start(tmp.path(), "s1");
        start(tmp.path(), "s2");
        record(tmp.path(), "s1", Some("m1"));
        record(tmp.path(), "s1", Some("m2"));
        record(tmp.path(), "s2", Some("x"));
        assert_eq!(count(tmp.path(), "s1"), Some(2));
        assert_eq!(count(tmp.path(), "s2"), Some(1));
        assert_eq!(
            last_message_id(tmp.path(), "s1"),
            LastMessage::Known(Some("m2".into()))
        );
    }

    /// A session with no counter stays on the ledger: a commit does not create
    /// one (that would hide its earlier ledger commits).
    #[test]
    fn a_commit_without_a_counter_creates_none() {
        let tmp = tempfile::tempdir().unwrap();
        record(tmp.path(), "s1", Some("m1"));
        assert_eq!(count(tmp.path(), "s1"), None);
        assert_eq!(last_message_id(tmp.path(), "s1"), LastMessage::Unknown);
    }

    #[test]
    fn a_resumed_session_keeps_its_count() {
        let tmp = tempfile::tempdir().unwrap();
        start(tmp.path(), "s1");
        record(tmp.path(), "s1", Some("m1"));
        start(tmp.path(), "s1");
        assert_eq!(count(tmp.path(), "s1"), Some(1));
    }

    #[test]
    fn concurrent_commits_lose_no_increment() {
        let tmp = tempfile::tempdir().unwrap();
        start(tmp.path(), "s1");
        let state = tmp.path().to_path_buf();
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let state = state.clone();
                std::thread::spawn(move || record(&state, "s1", Some(&format!("m{i}"))))
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(count(tmp.path(), "s1"), Some(16));
    }

    #[test]
    fn unsafe_session_ids_write_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        start(tmp.path(), "../x");
        record(tmp.path(), "../x", Some("m"));
        assert!(!tmp.path().join("commits").exists());
        assert_eq!(count(tmp.path(), "../x"), None);
        assert!(!tmp.path().join("x").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_counter_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("commits/s1");
        std::fs::create_dir_all(&dir).unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(COUNT_FILE)).unwrap();
        record(tmp.path(), "s1", Some("m"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert_eq!(count(tmp.path(), "s1"), None, "a symlink is not a counter");
    }
}
