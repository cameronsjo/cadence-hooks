//! Session-scoped, per-user marker primitive for the advisory marker family.
//!
//! The once-per-session guards (`warn-main-branch`, `warn-subagent-worktree`,
//! `guard-browser-device`, `check-idle-return`, and the main-branch snooze) all
//! record state in a temp-file marker. Before CP0 each rolled its own path
//! scheme, keyed on `PPID`→`process::id()` — but `PPID` is a shell builtin that
//! is never exported into a hook's environment, so the fallback fired and every
//! separate hook process got a fresh `process::id()`, defeating the once-per-
//! *session* intent (the marker was never found on the next invocation).
//!
//! This module centralizes the family (#147) on two guarantees:
//! - **Session scoping** via [`session_marker`]: the key is the Claude Code
//!   `session_id` (stable across a session's many hook processes), hashed.
//! - **A private 0700 directory** via [`marker_dir`]: removes the cross-user
//!   symlink pre-plant that a world-writable `/tmp` marker name invites, with
//!   [`write_marker`] adding `create_new`+`rename` as same-user TOCTOU defense.
//!
//! Markers are advisory — every failure path degrades open (ADR-0001): a marker
//! that can't be written just means the nudge may re-fire, never a block.

use crate::HookInput;
use crate::paths;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

/// The per-user private directory holding the advisory marker family.
///
/// `<temp>/cadence-hooks-{hash(home)}`, created `0700` on unix so a co-tenant
/// cannot pre-plant a symlink at a predictable marker name (the actual #147
/// attack). The home hash keeps two users on a shared host from colliding.
///
/// **Fails open** to the shared [`paths::marker_temp_dir`] when the private dir
/// can't be created or secured (or a symlink squats its path): markers are
/// advisory, so a re-fired nudge is the acceptable degraded mode, never a block.
pub fn marker_dir() -> PathBuf {
    let base = paths::marker_temp_dir();
    let mut hasher = DefaultHasher::new();
    paths::user_home_lossy_or_default().hash(&mut hasher);
    let dir = base.join(format!("cadence-hooks-{:x}", hasher.finish()));
    if harden_marker_dir(&dir).is_ok() {
        dir
    } else {
        base
    }
}

/// Create the marker dir and lock it to `0700`, refusing a pre-planted symlink.
#[cfg(unix)]
fn harden_marker_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::symlink_metadata(dir)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "marker dir path is a symlink",
        ));
    }
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Non-unix: create the dir, still refusing a pre-planted symlink. Windows has
/// no `0700` equivalent here — the per-user temp root already carries the ACL.
#[cfg(not(unix))]
fn harden_marker_dir(dir: &Path) -> io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dir)
        && meta.file_type().is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "marker dir path is a symlink",
        ));
    }
    std::fs::create_dir_all(dir)
}

/// The session scope key: the Claude Code `session_id` when present, else the
/// legacy `PPID`→`process::id()` fallback. Hooks are child processes, so `PPID`
/// (the Claude Code process) is the stable identifier when a payload omits the
/// session id; `process::id()` is the last-resort per-invocation value.
fn session_scope(input: &HookInput) -> String {
    input.session_id().map(str::to_string).unwrap_or_else(|| {
        std::env::var("PPID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(std::process::id)
            .to_string()
    })
}

/// Non-cryptographic hash of `s`. `DefaultHasher::new()` uses fixed keys, so the
/// value is stable across the many separate hook processes of one session — the
/// property the whole marker scheme depends on.
fn hash_of(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Build a session-scoped marker path under the private [`marker_dir`].
///
/// Filename `{kind}-{repo_hash:x}-{sid_hash:x}`; the repo component is omitted
/// when `repo_root` is `None` (e.g. the session-global browser-device
/// handshake, which has no repo). Both `session_id` and `repo_root` are
/// payload-controlled strings, so they are ALWAYS hashed, never used as path
/// components — a manual `--session-id ../../x` is inert (the result is a direct
/// child of [`marker_dir`]).
///
/// The hash is non-cryptographic and fixed-seed, so marker names are predictable
/// by design: security rests on the `0700` [`marker_dir`], never on name
/// secrecy. `agent_id` is deliberately NOT part of the key — `HookInput` carries
/// none today, and CP2 will decide whether subagent-scoped markers extend it.
pub fn session_marker(input: &HookInput, kind: &str, repo_root: Option<&str>) -> PathBuf {
    let sid_hash = hash_of(&session_scope(input));
    let name = match repo_root {
        Some(root) => format!("{kind}-{:x}-{sid_hash:x}", hash_of(root)),
        None => format!("{kind}-{sid_hash:x}"),
    };
    marker_dir().join(name)
}

/// Write `contents` to a marker path symlink-safely.
///
/// Stage to a uniquely-named `.{name}.{pid}.tmp` sibling with `create_new`
/// (`O_EXCL`, which never follows a pre-planted symlink), then `rename` over the
/// target (`rename` replaces the path itself, never following a symlink at the
/// target). Lifted from `cadence_hooks_session::registry::atomic_write` so the
/// marker family has one hardened write surface (#147). Never call bare
/// `fs::write` on a marker path — that follows a symlink squatting the name.
///
/// Callers that use a marker purely as a presence flag may ignore the returned
/// error: a failed write degrades to a re-fired nudge, never a block (ADR-0001).
pub fn write_marker(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "marker".to_string());
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(f) => f,
        // A stale temp from a crashed same-PID process is the only benign
        // collision — remove and retry once.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?
        }
        Err(e) => return Err(e),
    };
    if let Err(e) = file.write_all(contents.as_bytes()) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with_session(sid: &str) -> HookInput {
        HookInput {
            session_id: Some(sid.into()),
            ..Default::default()
        }
    }

    #[test]
    fn session_marker_differs_per_session() {
        let a = session_marker(&input_with_session("sid-a"), "kind", Some("/tmp/repo"));
        let b = session_marker(&input_with_session("sid-b"), "kind", Some("/tmp/repo"));
        assert_ne!(a, b, "distinct sessions must not share a marker");
    }

    #[test]
    fn session_marker_differs_per_repo() {
        let a = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo-a"));
        let b = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo-b"));
        assert_ne!(a, b, "distinct repos must not share a marker");
    }

    #[test]
    fn session_marker_stable_for_same_inputs() {
        let a = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo"));
        let b = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo"));
        assert_eq!(a, b, "same inputs must produce the same marker");
    }

    #[test]
    fn session_marker_repo_scoped_differs_from_global() {
        // Omitting repo_root (global handshake) must not collide with a
        // repo-scoped marker for the same kind + session.
        let scoped = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo"));
        let global = session_marker(&input_with_session("sid"), "kind", None);
        assert_ne!(scoped, global);
    }

    #[test]
    fn session_marker_never_embeds_raw_session_id() {
        // A path-traversal session id must be hashed to a plain filename — the
        // result is always a direct child of marker_dir(), never an escape.
        let input = input_with_session("../../evil");
        let p = session_marker(&input, "test-kind", None);
        assert_eq!(
            p.parent(),
            Some(marker_dir().as_path()),
            "marker must be a direct child of the private dir: {p:?}"
        );
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(
            !name.contains('/') && !name.contains(".."),
            "filename must carry no traversal: {name}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn marker_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = marker_dir();
        // marker_dir() only returns the private path when it secured it; if it
        // fell back to the shared temp root, that's the fail-open path and 0700
        // is not asserted. In the normal test environment the private dir is
        // created and locked down.
        if dir != paths::marker_temp_dir() {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "marker dir must be owner-only");
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_marker_does_not_clobber_preplanted_symlink() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let victim = tmp.path().join("victim.txt");
        std::fs::write(&victim, "precious\n").unwrap();

        let target = dir.join("some-marker");
        let temp_path = dir.join(format!(".some-marker.{}.tmp", std::process::id()));
        symlink(&victim, &temp_path).unwrap();

        write_marker(&target, "state").expect("marker write succeeds");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "precious\n",
            "victim must not be clobbered through the pre-planted symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "state",
            "the marker still lands"
        );
    }

    #[test]
    fn write_marker_round_trips_and_leaves_no_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("m");
        write_marker(&target, "hello").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["m".to_string()], "no stray .tmp left behind");
    }

    #[test]
    fn write_marker_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("m");
        write_marker(&target, "first").unwrap();
        write_marker(&target, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
    }
}
