//! Per-repo snooze for the `enforce-worktree` guard.
//!
//! Mirrors [`crate::dismiss_main_branch_warn`] — same marker format
//! (epoch-seconds line under `.git/cadence-hooks/`), same 24h cap, same
//! duration grammar — but with its own marker file so snoozing the hard block
//! and snoozing the main-branch nudge stay independent decisions.
//!
//! Exposes:
//! - `is_snoozed_now(repo_root)` — used by `enforce-worktree` before blocking
//! - `run_dismiss(duration_str)` — the `dismiss-enforce-worktree` subcommand
//!
//! The marker lives in the **primary checkout's** `.git/` directory — which is
//! exactly where the guard fires, so `git rev-parse --show-toplevel` from the
//! blocked directory resolves to the right root.

use crate::dismiss_main_branch_warn::{is_snoozed_at, parse_duration};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

const SNOOZE_DIR: &str = ".git/cadence-hooks";
const SNOOZE_FILE: &str = "enforce-worktree-snoozed-until";
/// Same cap as the main-branch snooze: a lingering marker would silently
/// disable the block long after the one-off reason for it expired.
const MAX_SNOOZE_SECONDS: u64 = 24 * 60 * 60;

/// Marker file path for a given repo root.
pub fn marker_path(repo_root: &Path) -> PathBuf {
    repo_root.join(SNOOZE_DIR).join(SNOOZE_FILE)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the marker for the given repo and decide if the snooze is active.
pub fn is_snoozed_now(repo_root: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(marker_path(repo_root)) else {
        return false;
    };
    is_snoozed_at(&contents, now_epoch())
}

/// Locate the current repo root via `git rev-parse --show-toplevel`.
fn repo_root() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Entry point for the `dismiss-enforce-worktree` subcommand.
///
/// Writes the epoch-seconds expiry marker and confirms. Exits 1 on failure
/// (missing repo, invalid duration, write error); 0 on success — this is a
/// user-facing CLI, not a hook.
pub fn run_dismiss(duration_str: &str) -> ! {
    let Some(duration) = parse_duration(duration_str) else {
        eprintln!(
            "cadence-hooks: invalid duration '{duration_str}'\n   \
             Expected: <number><s|m|h|d>, e.g. `30m`, `2h`, `1d`"
        );
        process::exit(1);
    };

    let secs = duration.as_secs();
    if secs > MAX_SNOOZE_SECONDS {
        eprintln!(
            "cadence-hooks: snooze duration capped at 24h (got {duration_str})\n   \
             Re-run with a smaller window, or run again later to renew."
        );
        process::exit(1);
    }

    let Some(root) = repo_root() else {
        eprintln!(
            "cadence-hooks: not inside a git repository\n   \
             dismiss-enforce-worktree must be run from within the repo you want to unblock."
        );
        process::exit(1);
    };

    let path = marker_path(&root);
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("cadence-hooks: could not create {}: {e}", parent.display());
        process::exit(1);
    }

    let until = now_epoch().saturating_add(secs);
    if let Err(e) = fs::write(&path, format!("{until}\n")) {
        eprintln!("cadence-hooks: could not write {}: {e}", path.display());
        process::exit(1);
    }

    println!(
        "enforce-worktree unblocked for {duration_str} in {} (until epoch {until})",
        root.display()
    );
    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_path_is_under_dot_git() {
        let p = marker_path(Path::new("/tmp/repo"));
        assert_eq!(
            p,
            Path::new("/tmp/repo/.git/cadence-hooks/enforce-worktree-snoozed-until")
        );
    }

    #[test]
    fn marker_is_distinct_from_main_branch_snooze() {
        // Snoozing the hard block and snoozing the nudge are independent.
        let root = Path::new("/tmp/repo");
        assert_ne!(
            marker_path(root),
            crate::dismiss_main_branch_warn::marker_path(root)
        );
    }

    #[test]
    fn unreadable_marker_is_not_snoozed() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(!is_snoozed_now(tmp.path()));
    }

    #[test]
    fn future_marker_is_snoozed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = marker_path(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{}\n", now_epoch() + 3600)).unwrap();
        assert!(is_snoozed_now(tmp.path()));
    }

    #[test]
    fn expired_marker_is_not_snoozed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = marker_path(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "100\n").unwrap();
        assert!(!is_snoozed_now(tmp.path()));
    }
}
