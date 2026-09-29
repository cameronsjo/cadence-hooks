//! Nudge on a direct write to live auto-memory outside a dream adoption window.
//!
//! `cadence:dream`'s contract is that **adoption is the only writer of live
//! memory**: dream snapshots `<config dir>/projects/<slug>/memory/`, curates the
//! copy, and replaces the live store under a per-project run lock
//! (`<config dir>/cadence/dreams/<slug>/.dream-lock`). Any session can still
//! Write into the live directory directly, and nothing said so.
//!
//! A `PreToolUse` check on Write/Edit/MultiEdit. When the target is under a
//! live auto-memory directory and no fresh run lock is held for that project,
//! it nudges. **Warn only** — tend's approved retires and ordinary memory
//! writes stay legal; the message only names the contract
//! (cadence-hooks#618).
//!
//! The lock counts as open when it exists and its mtime is younger than
//! [`LOCK_MAX_AGE`] — the same 6-hour window dream uses to tell a live run from
//! a crashed run's leftover. The check reads one `stat`; it never opens the
//! lock or any memory file. Every I/O failure allows (ADR-0001).

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A run lock older than this is a crashed run's leftover, not an open window.
/// Mirrors the reclaim threshold in dream's adoption protocol.
pub const LOCK_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// Nudges when a write targets live auto-memory while no dream run holds the lock.
pub struct WarnLiveMemoryWrite;

impl Check for WarnLiveMemoryWrite {
    fn name(&self) -> &str {
        "warn-live-memory-write"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let config_dir = cadence_hooks_core::paths::claude_config_dir();
        judge(input, &config_dir.to_string_lossy(), SystemTime::now())
    }
}

/// [`Check::run`] with the config dir and clock passed in, so tests never touch
/// the process-global `CLAUDE_CONFIG_DIR`.
pub fn judge(input: &HookInput, config_dir: &str, now: SystemTime) -> CheckResult {
    let Some(path) = input.file_path() else {
        return CheckResult::allow();
    };
    let Some(target) = live_memory_target(&path, config_dir) else {
        return CheckResult::allow();
    };
    match lock_state(&target.lock_path(), now) {
        LockState::Open => CheckResult::allow(),
        state => CheckResult::nudge(render(&target, state)),
    }
}

/// A write target resolved to its auto-memory store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTarget {
    /// The Claude config root the store lives under.
    pub root: PathBuf,
    /// The project slug — the store's directory name under `projects/`.
    pub slug: String,
}

impl MemoryTarget {
    /// Where dream holds its per-project run lock for this store.
    pub fn lock_path(&self) -> PathBuf {
        self.root
            .join("cadence")
            .join("dreams")
            .join(&self.slug)
            .join(".dream-lock")
    }
}

/// Resolve `path` to the live auto-memory store it writes into, if any.
///
/// Live memory is `<root>/projects/<slug>/memory/<file…>`, where `<root>` is the
/// resolved `config_dir` (honoring a relocated `CLAUDE_CONFIG_DIR`) or any
/// default `.claude` directory in the path. `.`/`..` are resolved first, so a
/// traversal-addressed path cannot present another segment where `memory`
/// should be — the same anchoring `memory-guard` uses (#93). Pure: no I/O.
pub fn live_memory_target(path: &str, config_dir: &str) -> Option<MemoryTarget> {
    let components = normalized_components(path);
    let config = normalized_components(config_dir);
    let absolute = path.starts_with('/') || path.starts_with('\\');
    let rebuild = |parts: &[String]| -> PathBuf {
        let joined = parts.join("/");
        PathBuf::from(if absolute {
            format!("/{joined}")
        } else {
            joined
        })
    };

    if !config.is_empty()
        && let Some(rest) = components.strip_prefix(config.as_slice())
        && rest.len() >= 4
        && rest[0] == "projects"
        && rest[2] == "memory"
    {
        return Some(MemoryTarget {
            root: rebuild(&components[..config.len()]),
            slug: rest[1].clone(),
        });
    }

    let i = components
        .windows(4)
        .position(|w| w[0] == ".claude" && w[1] == "projects" && w[3] == "memory")?;
    // A file must sit below `memory/`, not be the directory itself.
    if components.len() <= i + 4 {
        return None;
    }
    Some(MemoryTarget {
        root: rebuild(&components[..=i]),
        slug: components[i + 2].clone(),
    })
}

fn normalized_components(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for component in raw.replace('\\', "/").split('/') {
        match component {
            "" | "." => {}
            ".." if out.last().is_some_and(|last| last != "..") => {
                out.pop();
            }
            value => out.push(value.to_owned()),
        }
    }
    out
}

/// What the run lock says about the adoption window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// A dream run holds a fresh lock — the adoption window is open.
    Open,
    /// No lock (or an unreadable one): no run is in flight.
    Absent,
    /// A lock older than [`LOCK_MAX_AGE`]: a crashed run's leftover.
    Stale,
}

/// Classify the lock at `path` against `now`. Reads metadata only. A lock
/// whose mtime is unreadable or in the future counts as open — the harmless
/// direction for a nudge, since it can only suppress one.
pub fn lock_state(path: &Path, now: SystemTime) -> LockState {
    let Ok(meta) = std::fs::metadata(path) else {
        return LockState::Absent;
    };
    if !meta.is_file() {
        return LockState::Absent;
    }
    let Ok(modified) = meta.modified() else {
        return LockState::Open;
    };
    match now.duration_since(modified) {
        Ok(age) if age > LOCK_MAX_AGE => LockState::Stale,
        _ => LockState::Open,
    }
}

fn render(target: &MemoryTarget, state: LockState) -> String {
    let slug = cadence_hooks_core::display::sanitize_field(&target.slug, 80);
    let lock_note = match state {
        LockState::Stale => {
            " A run lock exists but is older than 6 hours — a crashed run's leftover, not an open window."
        }
        _ => "",
    };
    format!(
        "🧠  Direct write to live auto-memory (project `{slug}`) outside a dream adoption window.{lock_note}\n\n\
         cadence:dream's contract is that adoption is the only writer of live memory: \
         it snapshots the store, curates the copy, and replaces the live dir under its run lock. \
         A direct write here is drift that the next dream run has to reconcile.\n\n\
         This write stays legal — an approved tend retire or a deliberate memory note is fine. \
         If you are curating (merging, rewording, pruning), leave it to a dream run instead."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "/home/u/.claude";

    fn target(path: &str) -> Option<MemoryTarget> {
        live_memory_target(path, CFG)
    }

    #[test]
    fn resolves_live_memory_under_the_config_dir() {
        let t = target("/home/u/.claude/projects/-home-u-repo/memory/MEMORY.md").unwrap();
        assert_eq!(t.root, PathBuf::from("/home/u/.claude"));
        assert_eq!(t.slug, "-home-u-repo");
        assert_eq!(
            t.lock_path(),
            PathBuf::from("/home/u/.claude/cadence/dreams/-home-u-repo/.dream-lock")
        );
        // Nested topic files are live memory too.
        assert!(target("/home/u/.claude/projects/s/memory/topics/a.md").is_some());
    }

    #[test]
    fn honors_a_relocated_config_dir() {
        let t = live_memory_target("/cfg/alt/projects/slug/memory/x.md", "/cfg/alt").unwrap();
        assert_eq!(t.root, PathBuf::from("/cfg/alt"));
        assert_eq!(t.slug, "slug");
    }

    #[test]
    fn default_claude_tree_matches_even_when_config_dir_differs() {
        let t = live_memory_target("/other/.claude/projects/s/memory/x.md", "/cfg/alt").unwrap();
        assert_eq!(t.root, PathBuf::from("/other/.claude"));
        assert_eq!(t.slug, "s");
    }

    #[test]
    fn non_memory_paths_do_not_resolve() {
        for p in [
            "/repo/docs/memory/notes.md",
            "/home/u/.claude/projects/s/docs/memory/x.md",
            "/home/u/.claude/projects/s/transcript.jsonl",
            "/home/u/.claude/cadence/dreams/s/2026-09-01/output/MEMORY.md",
            "/home/u/.claude/projects/s/memory",
        ] {
            assert_eq!(target(p), None, "{p}");
        }
    }

    #[test]
    fn traversal_is_resolved_before_anchoring() {
        let t = target("/home/u/.claude/projects/s/docs/../memory/MEMORY.md").unwrap();
        assert_eq!(t.slug, "s");
        assert_eq!(
            target("/home/u/.claude/projects/s/memory/../notes.md"),
            None
        );
    }

    #[test]
    fn lock_state_follows_presence_and_age() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".dream-lock");
        let now = SystemTime::now();
        assert_eq!(lock_state(&lock, now), LockState::Absent);

        std::fs::write(&lock, "session 2026-09-29T00:00:00Z").unwrap();
        assert_eq!(lock_state(&lock, now), LockState::Open);

        let later = now + LOCK_MAX_AGE + Duration::from_secs(60);
        assert_eq!(lock_state(&lock, later), LockState::Stale);

        // A directory where the lock should be is not a lock.
        let dir_lock = dir.path().join("dirlock");
        std::fs::create_dir(&dir_lock).unwrap();
        assert_eq!(lock_state(&dir_lock, now), LockState::Absent);
    }

    /// End to end through `judge`, with a temp config dir so the real
    /// `~/.claude` is never read and no process env is touched.
    #[test]
    fn judge_nudges_without_a_lock_and_allows_inside_the_window() {
        use cadence_hooks_core::Outcome;
        use cadence_hooks_core::test_builders::{make_bash, make_edit, make_write};

        let cfg = tempfile::tempdir().unwrap();
        let cfg_str = cfg.path().to_str().unwrap();
        let file = cfg.path().join("projects/slug/memory/MEMORY.md");
        let file_str = file.to_str().unwrap();
        let lock = cfg.path().join("cadence/dreams/slug/.dream-lock");
        let now = SystemTime::now();

        let write = make_write(file_str, "- a note\n");
        let result = judge(&write, cfg_str, now);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap().contains("adoption window"));

        std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
        std::fs::write(&lock, "dream-session 2026-09-29T00:00:00Z").unwrap();
        assert_eq!(judge(&write, cfg_str, now).outcome, Outcome::Allow);
        let edit = make_edit(file_str, "a", "b");
        assert_eq!(judge(&edit, cfg_str, now).outcome, Outcome::Allow);

        // The same lock, 6h+ later, is a crashed run's leftover: nudge, and say so.
        let later = now + LOCK_MAX_AGE + Duration::from_secs(60);
        let stale = judge(&write, cfg_str, later);
        assert_eq!(stale.outcome, Outcome::Nudge);
        assert!(stale.message.unwrap().contains("older than 6 hours"));

        // Another project's store is not covered by this project's lock.
        let other = cfg.path().join("projects/other/memory/x.md");
        let w2 = make_write(other.to_str().unwrap(), "x");
        assert_eq!(judge(&w2, cfg_str, now).outcome, Outcome::Nudge);

        // A non-memory path, or a tool with no path, is never judged.
        let plain = make_write("/repo/src/main.rs", "fn main() {}");
        assert_eq!(judge(&plain, cfg_str, now).outcome, Outcome::Allow);
        assert_eq!(
            judge(&make_bash("ls"), cfg_str, now).outcome,
            Outcome::Allow
        );
    }
}
