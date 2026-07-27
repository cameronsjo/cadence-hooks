//! Session-scoped, per-user marker primitive for the advisory marker family.
//!
//! The once-per-session guards (`warn-main-branch`, `warn-subagent-worktree`,
//! `guard-browser-device`, and the main-branch snooze) all
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
use crate::gitstate::GitState;
use crate::paths;
use crate::shell::parse_work_dir;
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
///
/// Honors `CADENCE_MARKER_DIR` as a base-directory override, read
/// unconditionally like `CADENCE_METRICS_DIR` (`crates/metrics/src/common.rs`)
/// — not `#[cfg(test)]`-gated, since the integration suite (`tests/session_markers.rs`)
/// exercises the real compiled binary, which must honor it too. When set and
/// non-empty, the per-user hashed subdir is created under it instead of the
/// shared [`paths::marker_temp_dir`]; [`harden_marker_dir`] still runs on the
/// result, so an override can never skip the `0700` lockdown — it can only
/// fail open to an *unhardened override base* the same way the default path
/// fails open to an unhardened [`paths::marker_temp_dir`]. Intended for tests
/// today (#302); a real caller setting it changes only which advisory nudge
/// state that caller's own process sees.
pub fn marker_dir() -> PathBuf {
    marker_dir_from(std::env::var("CADENCE_MARKER_DIR").ok())
}

/// Pure resolver behind [`marker_dir`]: takes the `CADENCE_MARKER_DIR` value
/// explicitly (rather than reading process-global env) so the override is
/// unit-testable without env mutation, mirroring `metrics_dir_from`
/// (`crates/metrics/src/common.rs`). `None` or an empty string falls through to
/// the shared [`paths::marker_temp_dir`].
///
/// The override replaces only the *base* the per-user hashed subdir is created
/// under — [`harden_marker_dir`] still runs on the derived path, so an override
/// never bypasses the `0700` lockdown.
fn marker_dir_from(override_dir: Option<String>) -> PathBuf {
    let base = marker_base_from(override_dir);
    let mut hasher = DefaultHasher::new();
    paths::user_home_lossy_or_default().hash(&mut hasher);
    let dir = base.join(format!("cadence-hooks-{:x}", hasher.finish()));
    if harden_marker_dir(&dir).is_ok() {
        dir
    } else {
        base
    }
}

/// The base directory the per-user hashed subdir is created under: the
/// `CADENCE_MARKER_DIR` override when set non-empty, else the shared
/// [`paths::marker_temp_dir`].
///
/// Split out so [`marker_dir_is_private`] can recognize the fail-open result
/// (which *is* this base) without re-deriving the naming scheme.
fn marker_base_from(override_dir: Option<String>) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => paths::marker_temp_dir(),
    }
}

/// True when [`marker_dir`] resolved to its hardened `0700` per-user directory,
/// false when it failed open to the shared base.
///
/// The shared base is world-writable on a multi-user host, so a marker there is
/// pre-plantable by a co-tenant. Presence-only markers tolerate that (the
/// family's documented posture — [`write_marker`] still refuses to follow a
/// symlink). A marker whose *content* decides whether a nudge is suppressed does
/// not: a planted file with a guessable stamp would mute the nudge, and on a
/// sticky `/tmp` the corrective rename fails, so the mute persists. Consumers
/// that read marker content to gate output check this first and skip the gate.
pub fn marker_dir_is_private() -> bool {
    marker_dir() != marker_base_from(std::env::var("CADENCE_MARKER_DIR").ok())
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

/// The session scope key: the Claude Code `session_id` when present, else a
/// per-process best-effort id.
///
/// No session_id in payload → per-process best-effort (advisory only; a future
/// block-gating consumer must require session_id). The pre-CP0 `PPID` env read is
/// gone — `PPID` is never exported into a hook's environment (the very bug #133
/// fixed), so it only ever fell through to `process::id()` anyway.
fn session_scope(input: &HookInput) -> String {
    input
        .session_id()
        .map(str::to_string)
        .unwrap_or_else(|| std::process::id().to_string())
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

/// A repo+branch-keyed marker path under the private [`marker_dir`], session-
/// independent so a delegated (subagent) polish and the parent PR resolve the
/// same path. Both `repo_root` and `branch` are payload/git-derived strings, so
/// they are ALWAYS hashed, never used as path components — a crafted branch name
/// like `../../x` is inert (the result is a direct child of [`marker_dir`]).
///
/// Keyed per-`(repo, branch)` on purpose: two sessions polishing two branches of
/// one repo don't clobber each other's marker, and a different-branch marker is a
/// key-miss by construction — the property the pre-PR gate keys its branch
/// scoping on.
pub fn polish_marker(repo_root: &str, branch: &str) -> PathBuf {
    marker_dir().join(format!(
        "polish-{:x}-{:x}",
        hash_of(repo_root),
        hash_of(branch)
    ))
}

/// True when a branch-scoped polish marker exists for the `(repo, branch)` a
/// `gh pr create` command targets. Single source of truth for "did `/polish`
/// record for this PR's branch" — the pre-PR gate acts on it and the
/// polish-nudge metric records it, so the two cannot disagree (#177).
///
/// Resolves the repo identity via [`crate::gitstate::GitState`] — keyed on the
/// canonicalized `git rev-parse --git-common-dir`, not `--show-toplevel`
/// (cadence-hooks#324) — so a linked worktree and its primary checkout key to
/// the same marker; `branch` comes from `cwd` too, honoring a `cd`-prefixed
/// command via [`parse_work_dir`] — mirrors the record side. Any missing piece
/// (no cwd, not a repo, detached HEAD) yields `false` (fail-open, ADR-0001).
pub fn polish_marker_present(command: &str, cwd: Option<&str>) -> bool {
    let Some(cwd) = cwd else { return false };
    let dir = parse_work_dir(command, cwd);
    let Some(state) = GitState::resolve(Path::new(&dir)) else {
        return false;
    };
    let Some(branch) = state.branch else {
        return false;
    };
    polish_marker(&state.git_common_dir.to_string_lossy(), &branch).is_file()
}

/// The daily-gate marker path for `kind`: `<marker_dir>/daily-{kind}`.
///
/// Unlike [`session_marker`], `kind` is a compile-time-constant call-site string
/// (`"platform-drift"`), never payload-derived, so it stays readable rather than
/// hashed — a legible marker name is what makes the gate debuggable by hand. The
/// name is still reduced to `[A-Za-z0-9_-]` so the primitive cannot escape
/// [`marker_dir`] whatever a future call site passes.
pub fn daily_marker(kind: &str) -> PathBuf {
    let safe: String = kind
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    marker_dir().join(format!("daily-{safe}"))
}

/// True on the first sighting of `token` for `kind` today — the once-per-day
/// nudge gate.
///
/// Stamps `"{local_date} {token}"` through the symlink-safe [`write_marker`] and
/// returns `false` only when the marker already carries exactly that stamp. The
/// key is *content*, not a bare date, inheriting the reasoning behind
/// `warn-stale`'s `verdict_token`: a changed token re-fires the same day, so a
/// partial upgrade gets reported when it happens instead of waiting for
/// tomorrow.
///
/// **Local date, deliberately diverging from `warn-stale`'s UTC one.** This gate
/// means "once per calendar day as the operator experiences it", matching the
/// shell `notify_inert` precedent it generalizes; a UTC day boundary falls
/// mid-afternoon or mid-evening in much of the world and would split one working
/// day across two gate windows.
///
/// Fails open in **both** directions (ADR-0001): an unreadable marker fires (a
/// repeated nudge beats a missed one), and a failed write still fires — the
/// nudge is simply not suppressed next session either.
///
/// `CADENCE_NO_DAILY_GATE` (any non-empty value) disables the gate: every call
/// fires and nothing is stamped, so a session debugging a nudge sees it every
/// time.
///
/// The gate is also skipped whenever [`marker_dir_is_private`] is false. This is
/// the first marker in the family whose *content* decides whether output is
/// suppressed, so unlike the presence-only markers it cannot ride the shared
/// fail-open base: a co-tenant could pre-plant the (fully static) filename with a
/// guessable stamp and mute the nudge for the day. Degraded hardening therefore
/// degrades toward nudging, which is the same direction every other failure path
/// here takes.
pub fn claim_today(kind: &str, token: &str) -> bool {
    if std::env::var("CADENCE_NO_DAILY_GATE").is_ok_and(|v| !v.is_empty()) {
        return true;
    }
    if !marker_dir_is_private() {
        return true;
    }
    let path = daily_marker(kind);
    let stamp = format!("{} {token}", crate::time::local_date());
    if std::fs::read_to_string(&path).is_ok_and(|existing| existing.trim() == stamp) {
        return false;
    }
    let _ = write_marker(&path, &stamp);
    true
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
    // The one shared marker-dir env helper (and its one lock) for the whole
    // workspace — never mint a module-local sibling (#446).
    use crate::test_builders::with_marker_dir;

    // --- marker_dir_from (pure resolver behind CADENCE_MARKER_DIR) ---

    #[test]
    fn marker_dir_from_override_is_used_as_base() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = marker_dir_from(Some(tmp.path().to_string_lossy().into_owned()));
        assert!(
            dir.starts_with(tmp.path()),
            "override must become the base the hashed subdir is created under: {dir:?}"
        );
    }

    #[test]
    fn marker_dir_from_empty_override_falls_through() {
        // An empty CADENCE_MARKER_DIR must not shadow the default (guards the
        // `!dir.is_empty()` branch), mirroring metrics_dir_from's same guard.
        let dir = marker_dir_from(Some(String::new()));
        assert!(
            dir.starts_with(paths::marker_temp_dir()),
            "empty override must fall through to marker_temp_dir: {dir:?}"
        );
    }

    #[test]
    fn marker_dir_from_none_falls_through() {
        let dir = marker_dir_from(None);
        assert!(dir.starts_with(paths::marker_temp_dir()));
    }

    #[cfg(unix)]
    #[test]
    fn marker_dir_from_override_is_still_hardened() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = marker_dir_from(Some(tmp.path().to_string_lossy().into_owned()));
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "an overridden base must still get the 0700-hardened derived dir"
        );
    }

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
        // Holds ENV_LOCK across both reads so a concurrent `with_marker_dir`
        // test can't flip CADENCE_MARKER_DIR between them (#369): the stability
        // property is "same inputs + same env → same marker".
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let a = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo"));
            let b = session_marker(&input_with_session("sid"), "kind", Some("/tmp/repo"));
            assert_eq!(a, b, "same inputs must produce the same marker");
        });
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
        // Under ENV_LOCK so the `session_marker` read and the `marker_dir()`
        // read in the assert resolve the same base (#369).
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
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
        });
    }

    #[test]
    fn polish_marker_differs_per_branch() {
        let a = polish_marker("/tmp/repo", "branch-a");
        let b = polish_marker("/tmp/repo", "branch-b");
        assert_ne!(a, b, "distinct branches must not share a marker");
    }

    #[test]
    fn polish_marker_differs_per_repo() {
        let a = polish_marker("/tmp/repo-a", "main");
        let b = polish_marker("/tmp/repo-b", "main");
        assert_ne!(a, b, "distinct repos must not share a marker");
    }

    #[test]
    fn polish_marker_stable_for_same_inputs() {
        // Under ENV_LOCK so a concurrent `with_marker_dir` test can't flip the
        // base between the two reads (#369).
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let a = polish_marker("/tmp/repo", "main");
            let b = polish_marker("/tmp/repo", "main");
            assert_eq!(a, b, "same inputs must produce the same marker");
        });
    }

    #[test]
    fn polish_marker_never_embeds_raw_branch_or_repo() {
        // A path-traversal branch/repo must be hashed to a plain filename — the
        // result is always a direct child of marker_dir(), never an escape.
        // Under ENV_LOCK so both reads resolve the same base (#369).
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let p = polish_marker("../../evil-repo", "../../evil-branch");
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
        });
    }

    #[cfg(unix)]
    #[test]
    fn marker_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        // Under ENV_LOCK + an override base so this never creates/hardens the
        // real per-user marker dir (#302/#369); the override is still hardened,
        // so the 0700 property holds on it just the same.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let dir = marker_dir();
            // marker_dir() only returns the private path when it secured it; if it
            // fell back to the shared temp root, that's the fail-open path and 0700
            // is not asserted. In the normal test environment the private dir is
            // created and locked down.
            if dir != paths::marker_temp_dir() {
                let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700, "marker dir must be owner-only");
            }
        });
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

    // --- polish_marker_present (shared gate/metric helper, #177) ---

    /// Init a git repo in a fresh tempdir, checked out on `branch`, and return
    /// the tempdir plus the git-resolved (canonicalized) `git_common_dir` — the
    /// same key `polish_marker_present` now resolves via [`GitState`], so both
    /// sides key markers identically (no hand-rolled second resolution).
    fn init_repo_on_branch(branch: &str) -> (tempfile::TempDir, String) {
        use std::process::Command;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["checkout", "-q", "-b", branch]);
        let state = GitState::resolve(tmp.path()).expect("temp repo resolves git state");
        let root = state.git_common_dir.to_string_lossy().into_owned();
        (tmp, root)
    }

    #[test]
    fn polish_marker_present_true_for_current_branch_with_marker() {
        let (tmp, root) = init_repo_on_branch("feat/thing");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/thing"), "{}").unwrap();
            assert!(polish_marker_present(
                "gh pr create --title x",
                Some(tmp.path().to_str().unwrap())
            ));
        });
    }

    #[test]
    fn polish_marker_present_false_for_different_branch_marker() {
        // A marker for branch A must NOT satisfy a repo checked out on branch B.
        let (tmp, root) = init_repo_on_branch("branch-b");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "branch-a"), "{}").unwrap();
            assert!(!polish_marker_present(
                "gh pr create --title x",
                Some(tmp.path().to_str().unwrap())
            ));
        });
    }

    #[test]
    fn polish_marker_present_false_when_no_marker() {
        // polish_marker_present reads marker_dir() (env), so hold ENV_LOCK
        // against concurrent with_marker_dir writers (#369) and keep the lookup
        // off the real per-user dir (#302). Unlike the two-read stability tests
        // this can't flip its assertion, but an unguarded env read still races
        // a writer's set_var (unsound in edition 2024).
        let (tmp, _root) = init_repo_on_branch("feat/unmarked");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            assert!(!polish_marker_present(
                "gh pr create --title x",
                Some(tmp.path().to_str().unwrap())
            ));
        });
    }

    #[test]
    fn polish_marker_present_false_when_cwd_none() {
        // No cwd → unresolved → false (fail-open, ADR-0001).
        assert!(!polish_marker_present("gh pr create --title x", None));
    }

    #[test]
    fn polish_marker_present_false_for_non_repo_cwd() {
        // A real directory that is not a git repo → GitState::resolve is None
        // → false (fail-open, ADR-0001) — still holds after the #324 re-key.
        let tmp = tempfile::tempdir().unwrap();
        assert!(!polish_marker_present(
            "gh pr create --title x",
            Some(tmp.path().to_str().unwrap())
        ));
    }

    // --- claim_today (the once-per-day nudge gate, #458) ---
    //
    // Every case runs under `with_marker_dir` so the stamps land in a fresh
    // tempdir, never the real per-user marker directory (#302), and so the
    // `CADENCE_NO_DAILY_GATE` mutation below is serialized by the same lock.

    #[test]
    fn claim_today_fires_on_first_sighting() {
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            assert!(
                claim_today("test-gate", "tok"),
                "an unstamped kind must fire"
            );
        });
    }

    #[test]
    fn claim_today_suppresses_same_token_same_day() {
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            assert!(claim_today("test-gate", "tok"));
            assert!(
                !claim_today("test-gate", "tok"),
                "the same token must be silent for the rest of the day"
            );
        });
    }

    #[test]
    fn claim_today_refires_on_changed_token_same_day() {
        // Content-keyed, not date-keyed: a partial upgrade changes the token and
        // must be reported when it happens, not tomorrow.
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            assert!(claim_today("test-gate", "tok-a"));
            assert!(
                claim_today("test-gate", "tok-b"),
                "a changed token must re-fire the same day"
            );
            assert!(
                !claim_today("test-gate", "tok-b"),
                "and then be gated itself"
            );
        });
    }

    #[test]
    fn claim_today_refires_and_restamps_on_stale_date() {
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            let path = daily_marker("test-gate");
            write_marker(&path, "2020-01-01 tok").unwrap();
            assert!(
                claim_today("test-gate", "tok"),
                "yesterday's stamp must not gate today"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                format!("{} tok", crate::time::local_date()),
                "the stale stamp must be replaced with today's"
            );
        });
    }

    #[test]
    fn claim_today_unreadable_marker_fires() {
        // Fail-open (ADR-0001): a marker that cannot be read is not evidence
        // the nudge already fired. A directory at the marker path makes
        // `read_to_string` fail without making the path absent.
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            std::fs::create_dir_all(daily_marker("test-gate")).unwrap();
            assert!(claim_today("test-gate", "tok"));
        });
    }

    #[test]
    fn claim_today_always_fires_under_escape_hatch() {
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            // SAFETY: `with_marker_dir` holds the one env lock for this whole
            // closure, so this mutation is serialized against every other
            // env-mutating test in the binary.
            unsafe {
                std::env::set_var("CADENCE_NO_DAILY_GATE", "1");
            }
            assert!(claim_today("test-gate", "tok"));
            assert!(
                claim_today("test-gate", "tok"),
                "the escape hatch must fire every time, never stamping"
            );
            assert!(
                !daily_marker("test-gate").exists(),
                "a disabled gate must leave no marker behind"
            );
            // SAFETY: still inside the env lock held by `with_marker_dir`.
            unsafe {
                std::env::remove_var("CADENCE_NO_DAILY_GATE");
            }
        });
    }

    #[test]
    fn daily_marker_never_escapes_the_private_dir() {
        // `kind` is a call-site constant, so it is kept readable rather than
        // hashed — but a traversal-shaped kind must still be inert.
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            let p = daily_marker("../../evil");
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
        });
    }

    #[test]
    fn claim_today_never_suppresses_from_the_shared_fail_open_base() {
        // The shared base is pre-plantable by a co-tenant, and this marker's
        // CONTENT decides suppression — so a planted stamp there must not be
        // able to mute the nudge. Modelled by pointing CADENCE_MARKER_DIR at a
        // path where the hashed subdir cannot be created (a regular FILE, so
        // `create_dir_all` fails), which is exactly what makes `marker_dir()`
        // fail open to the base.
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("occupied");
        std::fs::write(&not_a_dir, "").unwrap();
        with_marker_dir(&not_a_dir, || {
            assert!(
                !marker_dir_is_private(),
                "precondition: this must be the fail-open path, or the test proves nothing"
            );
            assert!(claim_today("test-gate", "tok"));
            assert!(
                claim_today("test-gate", "tok"),
                "a degraded marker dir must never suppress, however many times it is asked"
            );
        });
    }

    #[test]
    fn marker_dir_is_private_when_hardening_succeeds() {
        // The positive control for the test above: the same assertion against a
        // usable base must report private, or `marker_dir_is_private` could be
        // returning false unconditionally.
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            assert!(marker_dir_is_private());
        });
    }

    #[test]
    fn daily_marker_differs_per_kind() {
        let tmp = tempfile::tempdir().unwrap();
        with_marker_dir(tmp.path(), || {
            assert_ne!(daily_marker("gate-a"), daily_marker("gate-b"));
        });
    }
}
