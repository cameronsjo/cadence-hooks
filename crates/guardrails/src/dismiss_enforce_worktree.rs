//! Per-repo snooze for the `enforce-worktree` guard.
//!
//! Mirrors [`crate::dismiss_main_branch_warn`] — same marker format
//! (epoch-seconds line), same 24h cap, same duration grammar — but with its own
//! marker file so snoozing the hard block and snoozing the main-branch nudge stay
//! independent decisions.
//!
//! Exposes:
//! - `is_snoozed_now(repo_root)` — used by `enforce-worktree` before blocking
//! - `run_dismiss(duration_str)` — the `dismiss-enforce-worktree` subcommand
//!
//! The marker lives under the **git common dir**
//! (`<primary>/.git/cadence-hooks/`), which every linked worktree shares — so a
//! snooze recorded from inside a worktree is seen from the primary checkout,
//! where the guard actually fires (#179). Both the reader and the dismiss CLI
//! resolve the common dir via `git rev-parse --git-common-dir` rather than
//! assuming the marker sits under the passed directory's own `.git`.

use crate::dismiss_main_branch_warn::{is_snoozed_at, parse_duration};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

/// Subdirectory (relative to the git common dir) that holds the marker. The
/// common dir already ends in `.git`, so this is `.git/cadence-hooks/` on disk.
const SNOOZE_DIR: &str = "cadence-hooks";
const SNOOZE_FILE: &str = "enforce-worktree-snoozed-until";
/// Same cap as the main-branch snooze: a lingering marker would silently
/// disable the block long after the one-off reason for it expired.
const MAX_SNOOZE_SECONDS: u64 = 24 * 60 * 60;

/// Marker file path within a git common dir.
///
/// `git_common_dir` is the primary checkout's `.git` directory — shared across
/// all linked worktrees — so the marker resolves to
/// `<primary>/.git/cadence-hooks/enforce-worktree-snoozed-until` no matter which
/// worktree wrote it.
pub fn marker_path(git_common_dir: &Path) -> PathBuf {
    git_common_dir.join(SNOOZE_DIR).join(SNOOZE_FILE)
}

/// Resolve the absolute git common dir for `dir` via
/// `git rev-parse --git-common-dir`. `None` when `dir` is not inside a git repo
/// (or git is unavailable) — callers treat that as fail-open.
fn git_common_dir(dir: &Path) -> Option<PathBuf> {
    cadence_hooks_core::shell::git_command(
        &dir.to_string_lossy(),
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .map(PathBuf::from)
}

/// The marker path for `dir`, resolving the shared common dir first. `None` when
/// `dir` is not inside a git repo. Used by the reader and the tests.
pub fn marker_path_for(dir: &Path) -> Option<PathBuf> {
    git_common_dir(dir).map(|c| marker_path(&c))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the marker for the given repo and decide if the snooze is active.
///
/// Resolves the marker through the shared git common dir, so a snooze written
/// from a linked worktree is honoured here at the primary checkout. A missing
/// marker, or a `repo_root` that isn't inside a git repo, yields `false`
/// (fail-open — ADR-0001).
pub fn is_snoozed_now(repo_root: &Path) -> bool {
    let Some(path) = marker_path_for(repo_root) else {
        return false;
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    is_snoozed_at(&contents, now_epoch())
}

/// Entry point for the `dismiss-enforce-worktree` subcommand.
///
/// Writes the epoch-seconds expiry marker under the shared git common dir and
/// confirms. Exits 1 on failure (missing repo, invalid duration, write error);
/// 0 on success — this is a user-facing CLI, not a hook.
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

    let cwd = Path::new(".");
    let Some(common) = git_common_dir(cwd) else {
        eprintln!(
            "cadence-hooks: not inside a git repository\n   \
             dismiss-enforce-worktree must be run from within the repo you want to unblock."
        );
        process::exit(1);
    };

    let path = marker_path(&common);
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

    // Prefer the friendly repo toplevel for the confirmation; fall back to the
    // common dir if `--show-toplevel` doesn't resolve (e.g. a bare repo).
    let where_display =
        cadence_hooks_core::shell::git_command(".", &["rev-parse", "--show-toplevel"])
            .unwrap_or_else(|| common.display().to_string());
    println!(
        "enforce-worktree unblocked for {duration_str} in {where_display} (until epoch {until})"
    );
    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Init a bare-minimum git repo in a fresh tempdir. No commit — enough for
    /// `--git-common-dir` to resolve. Returns the tempdir (kept alive by caller).
    fn init_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let ok = Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["init", "-q"])
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git init failed");
        tmp
    }

    #[test]
    fn marker_path_is_under_dot_git() {
        let p = marker_path(Path::new("/tmp/repo/.git"));
        assert_eq!(
            p,
            Path::new("/tmp/repo/.git/cadence-hooks/enforce-worktree-snoozed-until")
        );
    }

    #[test]
    fn marker_is_distinct_from_main_branch_snooze() {
        // Snoozing the hard block and snoozing the nudge are independent. The
        // enforce marker keys off the common dir (`.git`); the main-branch legacy
        // reference keys off the repo root — distinctness holds either way.
        let root = Path::new("/tmp/repo");
        assert_ne!(
            marker_path(&root.join(".git")),
            crate::dismiss_main_branch_warn::marker_path(root)
        );
    }

    #[test]
    fn unreadable_marker_is_not_snoozed() {
        // Real repo, no marker written → read fails → not snoozed.
        let tmp = init_repo();
        assert!(!is_snoozed_now(tmp.path()));
    }

    #[test]
    fn non_repo_dir_is_not_snoozed() {
        // A directory outside any git repo → common dir unresolved → fail-open.
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_snoozed_now(tmp.path()));
    }

    #[test]
    fn future_marker_is_snoozed() {
        let tmp = init_repo();
        let repo = tmp.path();
        let path = marker_path_for(repo).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{}\n", now_epoch() + 3600)).unwrap();
        assert!(is_snoozed_now(repo));
    }

    #[test]
    fn expired_marker_is_not_snoozed() {
        let tmp = init_repo();
        let repo = tmp.path();
        let path = marker_path_for(repo).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "100\n").unwrap();
        assert!(!is_snoozed_now(repo));
    }

    #[test]
    fn dismiss_writes_marker_readable_across_linked_worktree() {
        // A snooze recorded from inside a linked worktree must be seen from the
        // primary checkout, since they share one git common dir (#179).
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("repo");
        fs::create_dir(&primary).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&primary, &["init", "-q"]);
        // `git worktree add -b` bases the new branch on HEAD, so a commit must
        // exist first.
        git(
            &primary,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
        );
        let worktree = tmp.path().join("wt");
        git(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                &worktree.to_string_lossy(),
                "-b",
                "feat/x",
            ],
        );

        // Write the snooze via the worktree's resolved marker path...
        let path = marker_path_for(&worktree).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("{}\n", now_epoch() + 3600)).unwrap();

        // ...and read it back from the primary checkout.
        assert!(is_snoozed_now(&primary));
    }
}
