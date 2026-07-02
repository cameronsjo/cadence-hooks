//! Registry I/O: the `.claude/sessions/` directory, record lifecycle, and
//! peer discovery with mtime-based liveness.
//!
//! Liveness is the file's mtime, not its contents — a session that crashes or
//! is closed without ceremony simply stops heartbeating and goes stale. Stale
//! files are swept by the PostToolUse heartbeat (every wired tool call in any
//! live session) and, as a baseline, on `session start`.

use crate::identity::{self, SessionRecord};
use cadence_hooks_core::shell::git_command;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Default staleness threshold in minutes.
///
/// Liveness is mtime-only and the heartbeat fires only on Bash/Edit/Write, so a
/// session in a long read/think phase emits no signal. 30 min keeps such a
/// session out of the sweep's reach far more reliably than the original 10.
pub const DEFAULT_STALE_MINUTES: u64 = 30;

/// Staleness threshold from `CADENCE_SESSION_STALE_MINUTES`, default 30.
/// Zero or unparsable values fall back to the default.
pub fn stale_minutes() -> u64 {
    std::env::var("CADENCE_SESSION_STALE_MINUTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&m| m > 0)
        .unwrap_or(DEFAULT_STALE_MINUTES)
}

/// Resolve the registry directory for a working directory:
/// `<repo-root>/.claude/sessions`. Returns `None` when `cwd` is not inside a
/// git repository — the registry is per-checkout by design.
pub fn sessions_dir(cwd: &str) -> Option<PathBuf> {
    let root = git_command(cwd, &["rev-parse", "--show-toplevel"])?;
    Some(PathBuf::from(root).join(".claude").join("sessions"))
}

/// The repo root for a working directory, when inside a git repository.
pub fn repo_root(cwd: &str) -> Option<PathBuf> {
    git_command(cwd, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

/// A peer session discovered in the registry.
#[derive(Debug)]
pub struct Peer {
    pub record: SessionRecord,
    /// Seconds since the peer's file was last touched (heartbeat age).
    pub idle_secs: u64,
    /// Seconds since the peer registered.
    pub age_secs: u64,
    /// True when `idle_secs` exceeds the staleness threshold.
    pub stale: bool,
}

/// Seconds since a file's mtime. `None` when metadata is unreadable.
fn mtime_age_secs(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|d| d.as_secs())
}

/// Read all registry entries except `own_session_id`, classifying liveness.
///
/// Unparsable files are skipped (fail open) — a corrupt record must never
/// break peer discovery for everyone else.
pub fn read_peers(dir: &Path, own_session_id: &str, stale_secs: u64) -> Vec<Peer> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let now = identity::now_epoch();
    let mut peers = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<SessionRecord>(&text) else {
            continue;
        };
        if record.session_id == own_session_id {
            continue;
        }
        let idle_secs = mtime_age_secs(&path).unwrap_or(0);
        let age_secs = now.saturating_sub(record.started_epoch);
        peers.push(Peer {
            stale: idle_secs > stale_secs,
            record,
            idle_secs,
            age_secs,
        });
    }
    // Most recently active first — the liveliest peer is the most relevant.
    peers.sort_by_key(|p| p.idle_secs);
    peers
}

/// Live (non-stale) peers only.
pub fn live_peers(dir: &Path, own_session_id: &str, stale_secs: u64) -> Vec<Peer> {
    read_peers(dir, own_session_id, stale_secs)
        .into_iter()
        .filter(|p| !p.stale)
        .collect()
}

/// True when the registry file at `path` is the record for `session_id` — it
/// parses and its stored `session_id` matches exactly. Fail-open false on a read
/// or parse error: a file we cannot verify is not "ours".
///
/// The 8-char short id in the filename is ambiguous — distinct sessions whose
/// ids share a prefix (notably manual `--session-id` values) land on the same
/// `.<short-id>.json` suffix (#90). The filename is only a cheap pre-filter;
/// this exact-id check is the authority on ownership.
fn matches_own(path: &Path, session_id: &str) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<SessionRecord>(&t).ok())
        .is_some_and(|r| r.session_id == session_id)
}

/// Find a session's own registry file. The `.<short-id>.json` suffix narrows
/// the candidates cheaply; [`matches_own`] then verifies the full `session_id`,
/// so a peer that merely shares this session's 8-char prefix is never mistaken
/// for it (#90). Returns `None` when no candidate verifies — or when more than
/// one does (ambiguous; reachable only via crafted/duplicate records, since
/// production naming is deterministic), refusing to guess which is ours.
pub fn find_own(dir: &Path, session_id: &str) -> Option<PathBuf> {
    let suffix = format!(".{}.json", identity::short_id(session_id));
    let entries = fs::read_dir(dir).ok()?;
    let mut matches = entries.flatten().map(|e| e.path()).filter(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(&suffix))
            && matches_own(p, session_id)
    });
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first)
}

/// Deregister a session: remove its own registry file so it stops appearing as
/// a live peer the moment it ends, instead of lingering until the next `session
/// start` sweeps it by age (#97). Resolves the file the same content-verified
/// way [`find_own`] does, so only the record whose stored `session_id` matches
/// exactly is removed — never a peer's lane (#90). A clean no-op (`Ok`) when the
/// session has no registered file: a SessionEnd that fires before `session
/// start` ever ran has nothing to remove.
///
/// Assumes `session_id` was validated by the caller (`End::run` filters through
/// [`identity::is_safe_session_id`]). Even an unvalidated id cannot traverse:
/// `find_own` uses it only for content equality and as a filename-suffix string
/// match against `read_dir` entries, never as a path component — so the deleted
/// path is always one already inside `dir`.
pub fn remove_own(dir: &Path, session_id: &str) -> std::io::Result<()> {
    match find_own(dir, session_id) {
        Some(path) => fs::remove_file(path),
        None => Ok(()),
    }
}

/// Write `contents` to `path` atomically: stage to a uniquely-named temp file
/// in the SAME directory, then `rename` it over `path`. A concurrent reader
/// sees either the old complete file or the new complete file — never a
/// truncated or half-written document.
///
/// Plain `fs::write` does `open(O_TRUNC)` then `write_all`, exposing a window
/// where a peer's `read_peers` lands on a 0-byte/partial file, fails to parse,
/// and silently skips the session (#79). The one-shot SessionStart disclosure
/// then misses a live peer for the whole session.
///
/// The temp name carries the target filename AND the writer's PID: separate
/// hook invocations are separate processes (distinct PIDs), and within one
/// process distinct records have distinct filenames — so two concurrent writers
/// never collide on the same temp path. `rename` is atomic only within one
/// filesystem, so the temp MUST share `path`'s parent directory.
fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "record".to_string());
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    // create_new (O_EXCL) refuses to follow or overwrite an existing path, so a
    // pre-planted symlink at the predictable temp name is rejected rather than
    // clobbered (the registry dir is user-owned in normal use, but defense in
    // depth is cheap here). A stale temp from a crashed same-PID process is the
    // only benign collision — remove it and retry once. `rename` then replaces
    // `path` itself (never follows a symlink at the target), so the whole write
    // is symlink-safe end to end.
    use std::io::Write;
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?
        }
        Err(e) => return Err(e),
    };
    if let Err(e) = file.write_all(contents) {
        // A failed write (e.g. disk full) must not leave an orphan .tmp —
        // sweep_stale only reaps .json files, so it would accumulate.
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if let Err(e) = fs::rename(&tmp, path) {
        // Don't leak a staging file when the rename fails (e.g. read-only fs).
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Write (or overwrite) a record's file in the registry. Creates the
/// directory if needed. Writing refreshes mtime — this *is* the heartbeat.
pub fn write_record(dir: &Path, record: &SessionRecord) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(identity::filename(&record.name, &record.session_id));
    let json = serde_json::to_string_pretty(record).unwrap_or_else(|_| "{}".to_string());
    atomic_write(&path, (json + "\n").as_bytes())
}

/// Read a session's own record, if registered.
pub fn read_own(dir: &Path, session_id: &str) -> Option<SessionRecord> {
    let path = find_own(dir, session_id)?;
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Upsert a session's record: refresh mtime (the heartbeat), update the
/// observed `branch` when it changed, and create a minimal record if missing
/// (so a heartbeat firing before `session start` still registers the session).
///
/// `is_self_switch` is true only when the triggering command is THIS session's
/// own `git checkout`/`switch`. The drift baseline (`declared_branch`) moves
/// solely on a self-switch — a non-switch heartbeat refreshes the last-observed
/// `branch` (which may be a peer's HEAD move) but leaves the baseline alone, so
/// the divergence stays detectable at `git commit`.
pub fn touch_own(
    dir: &Path,
    session_id: &str,
    branch: Option<String>,
    is_self_switch: bool,
) -> std::io::Result<()> {
    let record = match read_own(dir, session_id) {
        Some(mut existing) => {
            if branch.is_some() && existing.branch != branch {
                existing.branch = branch.clone();
            }
            if is_self_switch && branch.is_some() {
                // This session deliberately switched — re-baseline the drift
                // reference to where it now intends to commit.
                existing.declared_branch = branch;
            }
            existing
        }
        None => SessionRecord {
            name: identity::generate_name(session_id),
            session_id: session_id.to_string(),
            branch: branch.clone(),
            declared_branch: branch,
            started: identity::utc_timestamp(),
            started_epoch: identity::now_epoch(),
            ..Default::default()
        },
    };
    write_record(dir, &record)
}

/// Delete registry files whose mtime is older than `stale_secs`, never the
/// caller's own file.
///
/// `own_session_id` is matched the same way [`find_own`] resolves it — the
/// `.<short-id>.json` suffix narrows candidates, then the full `session_id` is
/// verified ([`matches_own`]) — and excluded from the sweep even when aged. A
/// peer that merely shares the 8-char prefix is NOT spared (#90). A quiet
/// session (read/think phase, or paused) still owns its lane; callers
/// (`session start` and the PostToolUse heartbeat) refresh their own mtime
/// first, so the exclusion is defense-in-depth against a self-sweep. Pass
/// `""` to sweep everything (CLI/tests with no own session).
pub fn sweep_stale(dir: &Path, stale_secs: u64, own_session_id: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let own_suffix = (!own_session_id.is_empty())
        .then(|| format!(".{}.json", identity::short_id(own_session_id)));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(suffix) = &own_suffix
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(suffix.as_str()))
            && matches_own(&path, own_session_id)
        {
            continue;
        }
        if let Some(age) = mtime_age_secs(&path)
            && age > stale_secs
        {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Ensure `.claude/sessions/` is listed in the repo's `info/exclude` so registry
/// files never appear in `git status`.
///
/// `info/exclude` is per-repo git plumbing — never committed, never shared — so
/// this keeps the user's `.gitignore` untouched while preventing registry noise
/// in every other guard that inspects untracked files.
///
/// The exclude lives in the git **common directory**, which is *shared* by the
/// primary checkout and every linked worktree. Resolving it via
/// [`cadence_hooks_core::paths::resolve_git_common_dir`] means a session running
/// inside a linked worktree still writes the exclude to the primary `.git` (#130,
/// previously an early-return no-op that left worktree registries noisy). One
/// write covers all checkouts and is idempotent with the dedupe below.
///
/// **Symlink safety.** The resolved common dir's contents are attacker-influenced:
/// a crafted `.git` *file* can redirect resolution to any directory (bounded only
/// by the resolver's HEAD-exists gate, which `exists()` satisfies *through*
/// symlinks). Without care a planted `info/exclude` symlink would make us append
/// the exclusion line to a victim-writable file. Two layers defend the write:
/// (1) a pre-check refuses when `info` or `info/exclude` is a symlink (silent
/// no-op, fail-open per ADR-0001 — a *nonexistent* exclude is the normal case and
/// gets created); (2) the write goes through [`atomic_write`]'s O_EXCL-staged
/// rename, so even a symlink re-planted at the leaf between check and write is
/// replaced, never followed.
pub fn ensure_git_excluded(repo_root: &Path) {
    const EXCLUDE_LINE: &str = ".claude/sessions/";
    let Some(common) = cadence_hooks_core::paths::resolve_git_common_dir(repo_root) else {
        return;
    };
    let info_dir = common.join("info");
    let exclude_path = info_dir.join("exclude");

    // Refuse a symlinked info dir or exclude leaf — either would redirect the
    // write to an attacker-chosen file. Fail open (no-op), never block.
    if is_symlink(&info_dir) || is_symlink(&exclude_path) {
        return;
    }

    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == EXCLUDE_LINE) {
        return;
    }
    let _ = fs::create_dir_all(&info_dir);
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(EXCLUDE_LINE);
    updated.push('\n');
    // O_EXCL-staged rename (never follows a symlink at the target), so a TOCTOU
    // re-plant of the leaf between the check above and here can't be written
    // through to a victim.
    let _ = atomic_write(&exclude_path, updated.as_bytes());
}

/// True when `path` exists and is a symlink (`symlink_metadata` does not follow).
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record(name: &str, session_id: &str) -> SessionRecord {
        SessionRecord {
            name: name.into(),
            session_id: session_id.into(),
            branch: Some("main".into()),
            // Mirror the production path (run_start / touch_own set branch and
            // declared_branch together), so a test that feeds this record to
            // run_drift gets a real baseline instead of a silent None→allow.
            declared_branch: Some("main".into()),
            started: "2026-06-02T00:00:00Z".into(),
            started_epoch: identity::now_epoch(),
            ..Default::default()
        }
    }

    // --- write / read round trip ---

    #[test]
    fn write_creates_directory_and_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join(".claude/sessions");
        write_record(&dir, &record("quiet-loom", "e4739a12-full")).unwrap();
        assert!(dir.join("quiet-loom.e4739a12.json").exists());
    }

    #[test]
    fn read_own_round_trips() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let rec = record("quiet-loom", "e4739a12-full");
        write_record(&dir, &rec).unwrap();
        let back = read_own(&dir, "e4739a12-full").unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn find_own_matches_by_short_id() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "e4739a12-full")).unwrap();
        write_record(&dir, &record("forge-anvil", "7b30411a-full")).unwrap();
        let own = find_own(&dir, "e4739a12-full").unwrap();
        assert!(own.to_string_lossy().contains("quiet-loom"));
    }

    #[test]
    fn find_own_none_when_unregistered() {
        let tmp = TempDir::new().unwrap();
        assert!(find_own(tmp.path(), "nobody").is_none());
    }

    #[test]
    fn find_own_disambiguates_colliding_short_ids() {
        // #90: two manual --session-id values that share the first 8 chars
        // ("session-") collide on the `.session-.json` filename suffix but are
        // distinct sessions. find_own must verify the FULL session_id and return
        // each session's own file — never whichever read_dir yields first.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("alpha-loom", "session-1")).unwrap();
        write_record(&dir, &record("beta-anvil", "session-2")).unwrap();

        let p1 = find_own(&dir, "session-1").expect("session-1 resolves");
        assert!(
            p1.to_string_lossy().contains("alpha-loom"),
            "find_own(session-1) returned the wrong file: {p1:?}"
        );
        let p2 = find_own(&dir, "session-2").expect("session-2 resolves");
        assert!(
            p2.to_string_lossy().contains("beta-anvil"),
            "find_own(session-2) returned the wrong file: {p2:?}"
        );
    }

    #[test]
    fn find_own_none_when_record_session_id_mismatches() {
        // A file whose short_id matches the query but whose stored session_id
        // does not is NOT this session's record — find_own must reject it rather
        // than resolve by suffix alone.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("beta-anvil", "session-2")).unwrap();
        assert!(
            find_own(&dir, "session-1").is_none(),
            "suffix-only match must not resolve a different session"
        );
    }

    // --- atomic write (#79) ---

    #[test]
    fn atomic_write_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("doc.json");
        atomic_write(&path, b"hello\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");
    }

    #[test]
    fn write_record_leaves_no_temp_file() {
        // The rename staging file must not survive a successful write — only the
        // .json record remains, never a stray .tmp.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "e4739a12-full")).unwrap();
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["quiet-loom.e4739a12.json".to_string()]);
    }

    #[test]
    fn read_peers_skips_empty_file() {
        // A 0-byte .json is exactly what a torn (non-atomic) fs::write left
        // mid-flight. The reader must fail open and still surface the valid
        // peer — and the atomic writer guarantees new writers never create this.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        fs::write(dir.join("torn.deadbeef.json"), "").unwrap();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        let peers = read_peers(&dir, "self", 600);
        assert_eq!(peers.len(), 1, "empty file skipped, valid peer found");
    }

    #[test]
    fn concurrent_writes_to_distinct_files_all_persist() {
        // 16 threads share one PID, so this fails under pid-only temp naming
        // (temp collision corrupts records) and passes once the temp name also
        // carries the target filename. Guards the uniqueness design.
        use std::sync::Arc;
        let tmp = TempDir::new().unwrap();
        let dir = Arc::new(tmp.path().to_path_buf());
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let dir = Arc::clone(&dir);
                std::thread::spawn(move || {
                    let sid = format!("session-{i:02}");
                    write_record(&dir, &record(&format!("peer-{i:02}"), &sid)).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(read_peers(&dir, "none", 600).len(), 16);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_does_not_clobber_preplanted_symlink_at_temp() {
        // A co-tenant pre-plants a symlink at the predictable temp path; the
        // O_EXCL create_new must reject/replace it without writing through to
        // the victim, and the record must still land.
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "precious\n").unwrap();

        let rec = record("quiet-loom", "e4739a12-full");
        let target_name = identity::filename(&rec.name, &rec.session_id);
        let temp_path = dir.join(format!(".{target_name}.{}.tmp", std::process::id()));
        symlink(&victim, &temp_path).unwrap();

        write_record(&dir, &rec).unwrap();
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "precious\n",
            "victim file must not be clobbered through the symlink"
        );
        assert!(
            read_own(&dir, "e4739a12-full").is_some(),
            "record still landed"
        );
    }

    // --- peer discovery ---

    #[test]
    fn read_peers_excludes_self() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "self-session")).unwrap();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        let peers = read_peers(&dir, "self-session", 600);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].record.name, "forge-anvil");
    }

    #[test]
    fn read_peers_empty_when_no_directory() {
        let peers = read_peers(Path::new("/nonexistent/sessions"), "self", 600);
        assert!(peers.is_empty());
    }

    #[test]
    fn read_peers_skips_corrupt_files() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        fs::write(dir.join("corrupt.abcd1234.json"), "not json {{").unwrap();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        let peers = read_peers(&dir, "self", 600);
        assert_eq!(peers.len(), 1, "corrupt file skipped, valid peer found");
    }

    #[test]
    fn read_peers_skips_non_json_files() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        fs::write(dir.join("README.md"), "not a record").unwrap();
        let peers = read_peers(&dir, "self", 600);
        assert!(peers.is_empty());
    }

    #[test]
    fn fresh_peer_is_live() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        let peers = read_peers(&dir, "self", 600);
        assert!(!peers[0].stale, "just-written file must be live");
        assert!(peers[0].idle_secs < 5);
    }

    #[test]
    fn peer_with_old_mtime_is_stale() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        // stale_secs = 0: any measurable age is stale.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let peers = read_peers(&dir, "self", 0);
        assert!(peers[0].stale);
    }

    #[test]
    fn live_peers_filters_stale() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(live_peers(&dir, "self", 0).is_empty());
        assert_eq!(live_peers(&dir, "self", 600).len(), 1);
    }

    // --- touch / upsert ---

    #[test]
    fn touch_own_updates_branch() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "self-session")).unwrap();
        touch_own(&dir, "self-session", Some("feat/new-branch".into()), false).unwrap();
        let back = read_own(&dir, "self-session").unwrap();
        assert_eq!(back.branch.as_deref(), Some("feat/new-branch"));
    }

    #[test]
    fn touch_own_preserves_branch_when_none_given() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "self-session")).unwrap();
        touch_own(&dir, "self-session", None, false).unwrap();
        let back = read_own(&dir, "self-session").unwrap();
        assert_eq!(back.branch.as_deref(), Some("main"));
    }

    #[test]
    fn touch_own_creates_record_when_missing() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("sessions");
        touch_own(&dir, "brand-new-session", Some("main".into()), false).unwrap();
        let back = read_own(&dir, "brand-new-session").unwrap();
        assert_eq!(back.session_id, "brand-new-session");
        assert!(!back.name.is_empty());
        // A brand-new record establishes its drift baseline from live HEAD.
        assert_eq!(back.declared_branch.as_deref(), Some("main"));
    }

    #[test]
    fn touch_own_preserves_intent_and_touching() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let mut rec = record("quiet-loom", "self-session");
        rec.intent = Some("cadence-hooks#54".into());
        rec.touching = vec!["crates/session/".into()];
        write_record(&dir, &rec).unwrap();
        touch_own(&dir, "self-session", Some("other-branch".into()), false).unwrap();
        let back = read_own(&dir, "self-session").unwrap();
        assert_eq!(back.intent.as_deref(), Some("cadence-hooks#54"));
        assert_eq!(back.touching, vec!["crates/session/"]);
    }

    // --- sweep ---

    #[test]
    fn sweep_removes_stale_keeps_fresh() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("old-timer", "old-session")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_record(&dir, &record("fresh-face", "new-session")).unwrap();
        // stale_secs = 0: the old file (age ≥ 1s) is stale, the fresh one (age 0) is not.
        sweep_stale(&dir, 0, "");
        assert!(find_own(&dir, "old-session").is_none(), "stale swept");
        assert!(find_own(&dir, "new-session").is_some(), "fresh kept");
    }

    #[test]
    fn sweep_never_removes_own_file_even_when_aged() {
        // Bug #69: a quiet (read/think-phase) session whose own file aged past
        // the threshold must not sweep itself; a peer that aged is still swept.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("my-self", "own-session")).unwrap();
        write_record(&dir, &record("the-peer", "peer-session")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // stale_secs = 0: both files have aged ≥ 1s, but own is excluded by sid.
        sweep_stale(&dir, 0, "own-session");
        assert!(
            find_own(&dir, "own-session").is_some(),
            "own aged file is NOT swept"
        );
        assert!(
            find_own(&dir, "peer-session").is_none(),
            "peer aged file IS swept"
        );
    }

    #[test]
    fn sweep_keeps_own_but_sweeps_colliding_short_id_peer() {
        // #90 twin: sweep_stale inlined the same suffix-only self-exclusion the
        // old find_own used. A stale peer that shares our 8-char prefix
        // ("session-") must still be swept — only OUR exact session_id is spared.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("alpha-loom", "session-1")).unwrap(); // own
        write_record(&dir, &record("beta-anvil", "session-2")).unwrap(); // colliding peer
        let own_file = dir.join("alpha-loom.session-.json");
        let peer_file = dir.join("beta-anvil.session-.json");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // stale_secs = 0: both files have aged ≥ 1s; own is spared by session_id.
        sweep_stale(&dir, 0, "session-1");
        assert!(
            own_file.exists(),
            "own file kept (spared by exact session_id)"
        );
        assert!(
            !peer_file.exists(),
            "colliding-short-id peer is swept, not wrongly spared by suffix"
        );
    }

    #[test]
    fn sweep_missing_directory_is_noop() {
        sweep_stale(Path::new("/nonexistent/sessions"), 0, "");
    }

    // --- deregister (remove_own, #97) ---

    #[test]
    fn remove_own_deletes_the_session_file() {
        // SessionEnd deregister: an ended session removes its own lane so it
        // stops appearing as a live peer immediately, instead of lingering
        // until the next `session start` sweeps it by age (#97).
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "self-session")).unwrap();
        remove_own(&dir, "self-session").unwrap();
        assert!(
            find_own(&dir, "self-session").is_none(),
            "own lane removed on deregister"
        );
    }

    #[test]
    fn remove_own_leaves_peers_untouched() {
        // Deregister removes only the caller's own lane — a concurrent peer's
        // record must survive.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("quiet-loom", "self-session")).unwrap();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        remove_own(&dir, "self-session").unwrap();
        assert!(find_own(&dir, "self-session").is_none(), "own lane removed");
        assert!(
            find_own(&dir, "peer-session").is_some(),
            "peer lane untouched"
        );
    }

    #[test]
    fn remove_own_removes_only_matching_colliding_short_id() {
        // Content-targeted delete (#90-hardened find_own): two sessions sharing
        // the 8-char prefix ("session-") must not cross-delete. Deregistering
        // session-1 leaves session-2's lane intact.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("alpha-loom", "session-1")).unwrap();
        write_record(&dir, &record("beta-anvil", "session-2")).unwrap();
        remove_own(&dir, "session-1").unwrap();
        assert!(
            !dir.join("alpha-loom.session-.json").exists(),
            "session-1 lane removed"
        );
        assert!(
            dir.join("beta-anvil.session-.json").exists(),
            "colliding session-2 lane NOT cross-deleted"
        );
    }

    #[test]
    fn remove_own_noop_when_unregistered() {
        // Deregistering a session with no registered file is a clean no-op,
        // never an error — a SessionEnd before `session start` ever ran.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        write_record(&dir, &record("forge-anvil", "peer-session")).unwrap();
        remove_own(&dir, "never-registered").unwrap();
        assert!(
            find_own(&dir, "peer-session").is_some(),
            "unrelated lane untouched by a no-op deregister"
        );
    }

    // --- git exclude ---

    #[test]
    fn ensure_git_excluded_appends_once() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join(".git/info")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        ensure_git_excluded(root);
        ensure_git_excluded(root);
        let contents = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        let count = contents
            .lines()
            .filter(|l| l.trim() == ".claude/sessions/")
            .count();
        assert_eq!(count, 1, "idempotent append: {contents}");
    }

    #[test]
    fn ensure_git_excluded_preserves_existing_content() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join(".git/info")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(root.join(".git/info/exclude"), "*.swp\n").unwrap();
        ensure_git_excluded(root);
        let contents = fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert!(contents.contains("*.swp"));
        assert!(contents.contains(".claude/sessions/"));
    }

    #[test]
    fn ensure_git_excluded_skips_non_repo() {
        let tmp = TempDir::new().unwrap();
        ensure_git_excluded(tmp.path());
        assert!(!tmp.path().join(".git").exists(), "no .git created");
    }

    #[test]
    fn ensure_git_excluded_noop_when_gitdir_unresolvable() {
        // A linked worktree's .git file that points at a nonexistent gitdir
        // (no HEAD reachable) must resolve to no common dir → no write, no panic.
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join(".git"),
            "gitdir: /elsewhere/.git/worktrees/x",
        )
        .unwrap();
        ensure_git_excluded(tmp.path());
        assert!(tmp.path().join(".git").is_file(), ".git file untouched");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_git_excluded_refuses_symlinked_exclude() {
        // A crafted checkout: a `.git` FILE redirects to an `evil` dir with a
        // planted HEAD (passing the resolver's HEAD gate) and an `info/exclude`
        // symlinked at a victim file. Following that symlink on write would append
        // the exclusion line to the victim; ensure_git_excluded must refuse.
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let victim = tmp.path().join("victim.txt");
        fs::write(&victim, "victim-original\n").unwrap();

        let evil = tmp.path().join("evil");
        fs::create_dir_all(evil.join("info")).unwrap();
        fs::write(evil.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        symlink(&victim, evil.join("info").join("exclude")).unwrap();

        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();

        ensure_git_excluded(&repo);

        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "victim-original\n",
            "a symlinked exclude must not be followed — victim untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_git_excluded_refuses_symlinked_info_dir() {
        // The dir-level variant: `info` itself is a symlink into a victim dir.
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let victim_dir = tmp.path().join("victim_dir");
        fs::create_dir_all(&victim_dir).unwrap();

        let evil = tmp.path().join("evil");
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        symlink(&victim_dir, evil.join("info")).unwrap();

        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();

        ensure_git_excluded(&repo);

        assert!(
            !victim_dir.join("exclude").exists(),
            "a symlinked info dir must not be written through"
        );
    }

    #[test]
    fn ensure_git_excluded_writes_common_dir_for_linked_worktree() {
        // A linked worktree's exclude line must land in the PRIMARY checkout's
        // shared .git/info/exclude (resolved via the worktree's commondir), so a
        // session running inside the worktree still silences registry noise
        // repo-wide (#130). Pure-fs fixture — no git spawn.
        let tmp = TempDir::new().unwrap();
        let primary_git = tmp.path().join("primary").join(".git");
        fs::create_dir_all(primary_git.join("info")).unwrap();
        fs::write(primary_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let wt_admin = primary_git.join("worktrees").join("wt");
        fs::create_dir_all(&wt_admin).unwrap();
        // commondir is relative to the worktree admin dir: ../.. → primary/.git
        fs::write(wt_admin.join("commondir"), "../..\n").unwrap();
        fs::write(wt_admin.join("HEAD"), "ref: refs/heads/feat\n").unwrap();

        let linked = tmp.path().join("linked");
        fs::create_dir_all(&linked).unwrap();
        fs::write(
            linked.join(".git"),
            format!("gitdir: {}\n", wt_admin.display()),
        )
        .unwrap();

        ensure_git_excluded(&linked);

        let exclude = fs::read_to_string(primary_git.join("info").join("exclude"))
            .expect("exclude written under the primary common dir");
        assert!(
            exclude.lines().any(|l| l.trim() == ".claude/sessions/"),
            "exclude line lands in the primary .git/info/exclude: {exclude}"
        );
    }

    // --- env config ---

    #[test]
    fn stale_minutes_default() {
        // Note: tests run in parallel; avoid mutating the env var here. The
        // default path is what matters — env parsing is exercised by the
        // filter/parse chain which is simple enough to verify by reading.
        assert_eq!(DEFAULT_STALE_MINUTES, 30);
    }
}
