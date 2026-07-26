//! Per-repo snooze for the `enforce-worktree` guard.
//!
//! Mirrors [`crate::dismiss_main_branch_warn`] — same marker format
//! (epoch-seconds line), same 24h cap, same duration grammar — but with its own
//! marker file so snoozing the hard block and snoozing the main-branch nudge stay
//! independent decisions.
//!
//! Exposes:
//! - `is_snoozed_now(repo_root)` — used by `enforce-worktree` before blocking
//! - `perform_dismiss(duration_str, reason, repo)` — the `dismiss-enforce-worktree` subcommand
//!
//! The marker lives under the **git common dir**
//! (`<primary>/.git/cadence-hooks/`), which every linked worktree shares — so a
//! snooze recorded from inside a worktree is seen from the primary checkout,
//! where the guard actually fires (#179). Both the reader and the dismiss CLI
//! resolve the common dir via `git rev-parse --git-common-dir` rather than
//! assuming the marker sits under the passed directory's own `.git`.

use crate::dismiss_main_branch_warn::{parse_duration, session_id_from_env};
use crate::snooze_meta::{self, DismissArmed, SnoozeMeta};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Same cap as the main-branch snooze: a lingering marker would silently
/// disable the block long after the one-off reason for it expired.
const MAX_SNOOZE_SECONDS: u64 = 24 * 60 * 60;

/// Marker file path within a git common dir. Delegates to
/// `cadence_hooks_core::worktree` (cadence-hooks#236), which owns the marker
/// path/format so `enforce_worktree` and `session::start`'s posture line read
/// the identical snooze state.
///
/// `git_common_dir` is the primary checkout's `.git` directory — shared across
/// all linked worktrees — so the marker resolves to
/// `<primary>/.git/cadence-hooks/enforce-worktree-snoozed-until` no matter which
/// worktree wrote it.
pub fn marker_path(git_common_dir: &Path) -> PathBuf {
    cadence_hooks_core::worktree::enforce_worktree_marker_path(git_common_dir)
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
    cadence_hooks_core::worktree::enforce_worktree_marker_path_for(dir)
}

/// The provenance sidecar beside the snooze marker for `dir` (resolved through
/// the shared common dir). `None` when `dir` isn't inside a git repo.
pub fn meta_path_for(dir: &Path) -> Option<PathBuf> {
    marker_path_for(dir).map(|m| snooze_meta::sidecar_for(&m))
}

/// Read the provenance sidecar for `repo_root`'s active snooze — reason, arming
/// session, expiry. `None` when the sidecar is missing/unreadable (an older
/// marker armed before this feature, or a fail-open sidecar write): the guard
/// then attributes the bypass with a `None` reason and still allows.
pub fn read_meta(repo_root: &Path) -> Option<SnoozeMeta> {
    SnoozeMeta::read(&meta_path_for(repo_root)?)
}

/// [`read_meta`] for a caller that already resolved the git common dir — pure
/// filesystem, no git subprocess (the #271 spawn-reduction path).
pub fn read_meta_in(git_common_dir: &Path) -> Option<SnoozeMeta> {
    let marker = cadence_hooks_core::worktree::enforce_worktree_marker_path(git_common_dir);
    SnoozeMeta::read(&snooze_meta::sidecar_for(&marker))
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the marker for the given repo and decide if the snooze is active.
/// Delegates to `cadence_hooks_core::worktree::is_snoozed_now` — the same
/// snooze check `session::start`'s posture line consults, so the two can
/// never disagree about whether a dismissal is currently active.
///
/// Resolves the marker through the shared git common dir, so a snooze written
/// from a linked worktree is honoured here at the primary checkout. A missing
/// marker, or a `repo_root` that isn't inside a git repo, yields `false`
/// (fail-open — ADR-0001).
pub fn is_snoozed_now(repo_root: &Path) -> bool {
    cadence_hooks_core::worktree::is_snoozed_now(repo_root)
}

/// The dismiss mechanism name recorded in bypass provenance.
const MECHANISM: &str = "dismiss-enforce-worktree";

/// Perform the `dismiss-enforce-worktree` action: validate, gate on `--reason`,
/// write the epoch marker **and** its provenance sidecar under the shared git
/// common dir. Returns [`DismissArmed`] for the binary to log + confirm.
///
/// Prints every error to stderr and returns `Err(())` (the binary exits 1) —
/// missing repo, invalid duration, over-cap, or a missing `--reason` for a
/// snooze longer than 1h. On success prints nothing and returns `Ok`.
///
/// `repo`, when given, names the repo to snooze instead of the current
/// directory's — the marker is written under `--repo <path>`'s resolved git
/// common dir. This matters because the guard keys its block off the **target**
/// repo of a `cd <dir> && git commit` (or `git -C <dir> …`), which may differ
/// from wherever the shell happens to be sitting (issue #224); a dismiss run
/// from the shell's cwd would snooze the wrong marker.
///
/// The load-bearing marker stays exactly `{until}\n` (the guard's first-line
/// parse is untouched); provenance rides in the sibling sidecar. The sidecar
/// write is best-effort — a failure warns but does not fail the dismissal, so a
/// snooze never depends on the audit trail succeeding (ADR-0001).
///
/// The `Err` is unit on purpose: this function prints every error to stderr
/// itself, so the caller only needs pass/fail to pick an exit code.
#[allow(clippy::result_unit_err)]
pub fn perform_dismiss(
    duration_str: &str,
    reason: Option<&str>,
    repo: Option<String>,
) -> Result<DismissArmed, ()> {
    let Some(duration) = parse_duration(duration_str) else {
        eprintln!(
            "cadence-hooks: invalid duration '{duration_str}'\n   \
             Expected: <number><s|m|h|d>, e.g. `30m`, `2h`, `1d`"
        );
        return Err(());
    };

    let secs = duration.as_secs();
    if secs > MAX_SNOOZE_SECONDS {
        eprintln!(
            "cadence-hooks: snooze duration capped at 24h (got {duration_str})\n   \
             Re-run with a smaller window, or run again later to renew."
        );
        return Err(());
    }

    // Reason gate: required over 1h, nudged at or under.
    let nudge = match snooze_meta::reason_gate(secs, reason, MECHANISM, duration_str) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("{msg}");
            return Err(());
        }
    };

    let target = repo
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let Some(common) = git_common_dir(&target) else {
        eprintln!(
            "cadence-hooks: not inside a git repository\n   \
             dismiss-enforce-worktree must be run from within (or point --repo at) the repo you \
             want to unblock."
        );
        return Err(());
    };

    let path = marker_path(&common);
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("cadence-hooks: could not create {}: {e}", parent.display());
        return Err(());
    }

    let armed_at = now_epoch();
    let until = armed_at.saturating_add(secs);
    if let Err(e) = fs::write(&path, format!("{until}\n")) {
        eprintln!("cadence-hooks: could not write {}: {e}", path.display());
        return Err(());
    }

    // Provenance sidecar — best-effort, must never fail the snooze.
    let reason = snooze_meta::normalize_reason(reason);
    let session_id = session_id_from_env();
    let meta = SnoozeMeta {
        reason: reason.clone(),
        session_id: session_id.clone(),
        armed_at: Some(armed_at as i64),
        expires_at: Some(until as i64),
    };
    let sidecar = snooze_meta::sidecar_for(&path);
    if let Err(e) = fs::write(&sidecar, meta.to_json()) {
        eprintln!(
            "cadence-hooks: note — snooze set, but provenance sidecar {} could not be written: {e}",
            sidecar.display()
        );
    }

    // Prefer the friendly repo toplevel for the confirmation; fall back to the
    // common dir if `--show-toplevel` doesn't resolve (e.g. a bare repo).
    let where_display = cadence_hooks_core::shell::git_command(
        &target.to_string_lossy(),
        &["rev-parse", "--show-toplevel"],
    )
    .unwrap_or_else(|| common.display().to_string());
    let mut confirmation = format!(
        "enforce-worktree unblocked for {duration_str} in {where_display} (until epoch {until})"
    );
    if let Some(n) = nudge {
        confirmation.push_str("\n   ");
        confirmation.push_str(&n);
    }

    Ok(DismissArmed {
        guard_hook: "enforce-worktree",
        mechanism: MECHANISM,
        reason,
        session_id,
        repo_root: Some(where_display),
        armed_at: armed_at as i64,
        expires_at: until as i64,
        confirmation,
    })
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

    // --- perform_dismiss validation (early-return paths only) ---
    //
    // Only the paths that reject BEFORE resolving the git common dir are safe to
    // unit-test: the success path writes a marker into the process cwd's repo,
    // which under `cargo test` is the real cadence-hooks checkout. The success
    // wiring (marker + sidecar + DismissArmed + armed event) is covered
    // end-to-end against a scratch repo instead.

    #[test]
    fn perform_dismiss_rejects_invalid_duration() {
        assert!(perform_dismiss("bogus", None, None).is_err());
    }

    #[test]
    fn perform_dismiss_rejects_over_cap() {
        // 2d exceeds the 24h cap → Err before touching git.
        assert!(perform_dismiss("2d", Some("why"), None).is_err());
    }

    #[test]
    fn perform_dismiss_rejects_long_snooze_without_reason() {
        // The reason gate rejects >1h without a reason, before touching git.
        assert!(perform_dismiss("4h", None, None).is_err());
    }
}
