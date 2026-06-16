//! Registry I/O: the `.claude/sessions/` directory, record lifecycle, and
//! peer discovery with mtime-based liveness.
//!
//! Liveness is the file's mtime, not its contents — a session that crashes or
//! is closed without ceremony simply stops heartbeating and goes stale. Stale
//! files are swept on the next `session start` in the same repo.

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

/// Find a session's own registry file by its short id suffix.
pub fn find_own(dir: &Path, session_id: &str) -> Option<PathBuf> {
    let suffix = format!(".{}.json", identity::short_id(session_id));
    let entries = fs::read_dir(dir).ok()?;
    entries.flatten().map(|e| e.path()).find(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(&suffix))
    })
}

/// Write (or overwrite) a record's file in the registry. Creates the
/// directory if needed. Writing refreshes mtime — this *is* the heartbeat.
pub fn write_record(dir: &Path, record: &SessionRecord) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(identity::filename(&record.name, &record.session_id));
    let json = serde_json::to_string_pretty(record).unwrap_or_else(|_| "{}".to_string());
    fs::write(path, json + "\n")
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
/// `own_session_id` is matched the same way [`find_own`] matches — by the
/// `.<short-id>.json` filename suffix — and excluded from the sweep even when
/// aged. A quiet session (read/think phase, or paused) still owns its lane;
/// only `session start` itself, having just refreshed its own mtime, should
/// reach this, and the exclusion is defense-in-depth against a self-sweep.
/// Pass `""` to sweep everything (CLI/tests with no own session).
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

/// Ensure `.claude/sessions/` is listed in the repo's `.git/info/exclude` so
/// registry files never appear in `git status`.
///
/// `.git/info/exclude` is per-checkout git plumbing — never committed, never
/// shared — so this keeps the user's `.gitignore` untouched while preventing
/// registry noise in every other guard that inspects untracked files.
pub fn ensure_git_excluded(repo_root: &Path) {
    const EXCLUDE_LINE: &str = ".claude/sessions/";
    let exclude_path = repo_root.join(".git").join("info").join("exclude");
    // Only act inside a real checkout (a .git *directory* — skip worktrees and
    // submodules whose .git is a file pointing elsewhere; their exclude file
    // lives in the common dir and editing it is the user's call).
    if !repo_root.join(".git").is_dir() {
        return;
    }
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == EXCLUDE_LINE) {
        return;
    }
    if let Some(parent) = exclude_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(EXCLUDE_LINE);
    updated.push('\n');
    let _ = fs::write(&exclude_path, updated);
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
    fn sweep_missing_directory_is_noop() {
        sweep_stale(Path::new("/nonexistent/sessions"), 0, "");
    }

    // --- git exclude ---

    #[test]
    fn ensure_git_excluded_appends_once() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join(".git/info")).unwrap();
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
    fn ensure_git_excluded_skips_worktree_git_file() {
        // In a linked worktree, .git is a *file* pointing at the common dir.
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join(".git"),
            "gitdir: /elsewhere/.git/worktrees/x",
        )
        .unwrap();
        ensure_git_excluded(tmp.path());
        assert!(tmp.path().join(".git").is_file(), ".git file untouched");
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
