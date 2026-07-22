//! Record that `/polish` (cadence-forge:polish) ran on this branch.
//!
//! A **CLI action**, not a hook: the polish skill's Wrap-up shells out to
//! `cadence-hooks cadence record-polish` after a completed pass, which writes a
//! branch-scoped marker under the private [`markers::marker_dir`]. The pre-PR
//! gate ([`crate::nudge_polish_before_pr`]) then reads that marker instead of
//! scanning the session transcript.
//!
//! The marker key is `(repo_root, branch)` (see [`markers::polish_marker`]),
//! where `repo_root` is the canonicalized `git rev-parse --git-common-dir`
//! (cadence-hooks#324) — stable across every worktree of a repo, not
//! `--show-toplevel` (a linked worktree's own path). Detection is therefore
//! invocation-agnostic (Skill call, `/polish` slash-command, or a delegated
//! subagent all end by running this), worktree-agnostic (recording from a
//! worktree satisfies a ship command run from the primary checkout, and vice
//! versa), and branch-scoped (a marker for branch A cannot satisfy a PR on
//! branch B).
//!
//! Advisory, always — this must never fail the user's polish pass. Every error
//! path (not a repo, detached HEAD, unwritable marker dir) prints one stderr
//! line and exits 0 (ADR-0001).

use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::markers::{polish_marker, write_marker};
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::time::utc_timestamp;
use serde_json::json;
use std::path::Path;

/// Resolve `repo_root`, `branch`, and `head_sha` from `dir`, letting explicit
/// overrides bypass resolution so tests need no real repository.
///
/// `repo_root` and `branch` come from [`GitState::resolve`] — a pure
/// filesystem walk keyed on the canonicalized `git_common_dir`, matching the
/// read side ([`cadence_hooks_core::markers::polish_marker_present`]) so a
/// worktree and its primary checkout key to the same marker. `head_sha` is
/// still resolved via a `git` shell-out: it's provenance metadata, not part of
/// the key, and best-effort — a repo with no commits yet has no `HEAD`, so it
/// resolves to `None` and the field is recorded as an empty string rather than
/// failing the record. `repo_root` and `branch` are the load-bearing key; when
/// either can't be resolved the caller degrades to a no-op (exit 0).
fn resolve(
    dir: &str,
    repo_root: Option<String>,
    branch: Option<String>,
) -> Option<(String, String, String)> {
    let git_state = || GitState::resolve(std::path::Path::new(dir));
    let repo_root = repo_root
        .or_else(|| git_state().map(|state| state.git_common_dir.to_string_lossy().into_owned()))?;
    let branch = branch.or_else(|| git_state().and_then(|state| state.branch))?;
    // Polish does not commit (SKILL.md), so this is the pre-polish base SHA — a
    // provenance breadcrumb for CP2, never an exact-match key. Empty when the
    // repo has no HEAD yet.
    let head_sha = git_command(dir, &["rev-parse", "HEAD"]).unwrap_or_default();
    Some((repo_root, branch, head_sha))
}

/// Build the marker payload. Presence is what CP1 gates on; the fields are
/// stored now so CP2's freshness/scope escalation needs no format change.
fn marker_content(branch: &str, head_sha: &str, scope: &str) -> String {
    json!({
        "branch": branch,
        "head_sha": head_sha,
        "recorded_at": utc_timestamp(),
        "scope": scope,
    })
    .to_string()
}

/// One-line success verdict: the marker path (the payload a caller probes to
/// confirm the pre-PR gate is satisfied) plus the (repo@branch, scope) key.
fn record_verdict(repo_root: &str, branch: &str, scope: &str, path: &Path) -> String {
    format!(
        "recorded polish marker: {} ({repo_root}@{branch} scope={scope})",
        path.display()
    )
}

/// Write the branch-scoped polish marker, resolving repo/branch/HEAD from the
/// current directory unless overridden. Fail-open: any missing context or write
/// error prints one stderr line and returns without error — a CLI action must
/// never fail the polish pass it is recording (ADR-0001).
pub fn run_record(repo_root: Option<String>, branch: Option<String>, scope: Option<String>) {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| ".".to_string());

    let Some((repo_root, branch, head_sha)) = resolve(&cwd, repo_root, branch) else {
        eprintln!(
            "cadence-hooks record-polish: could not resolve repo root / branch \
             (not a git repo, or detached HEAD) — no marker recorded."
        );
        return;
    };

    let scope = scope.unwrap_or_else(|| "full".to_string());
    let content = marker_content(&branch, &head_sha, &scope);
    let path = polish_marker(&repo_root, &branch);
    match write_marker(&path, &content) {
        Ok(()) => println!("{}", record_verdict(&repo_root, &branch, &scope, &path)),
        Err(e) => eprintln!(
            "cadence-hooks record-polish: marker write failed ({e}) — pre-PR gate may re-nudge."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::with_marker_dir;
    use cadence_hooks_core::markers::polish_marker;

    #[test]
    fn marker_content_is_parseable_json_with_all_fields() {
        let content = marker_content("feat/x", "abc123", "full");
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["branch"], "feat/x");
        assert_eq!(v["head_sha"], "abc123");
        assert_eq!(v["scope"], "full");
        // recorded_at is an ISO-8601 UTC instant (jiff `utc_timestamp`).
        let ts = v["recorded_at"].as_str().unwrap();
        assert!(ts.ends_with('Z'), "recorded_at should be UTC: {ts}");
    }

    #[test]
    fn record_verdict_names_path_repo_branch_and_scope() {
        let path = polish_marker("/tmp/repo", "feat/x");
        let verdict = record_verdict("/tmp/repo", "feat/x", "full", &path);
        assert!(verdict.contains(&path.display().to_string()));
        assert!(verdict.contains("/tmp/repo@feat/x"));
        assert!(verdict.contains("scope=full"));
    }

    #[test]
    fn resolve_uses_explicit_overrides_without_touching_git() {
        // Explicit repo_root + branch bypass the git shell-out, so a bogus dir
        // still resolves — the property the write test below relies on.
        let resolved = resolve(
            "/nonexistent/not-a-repo",
            Some("/tmp/repo".into()),
            Some("main".into()),
        );
        let (repo_root, branch, _head) = resolved.expect("overrides resolve");
        assert_eq!(repo_root, "/tmp/repo");
        assert_eq!(branch, "main");
    }

    #[test]
    fn run_record_writes_marker_at_expected_path_with_parseable_content() {
        // Both `polish_marker` calls below resolve `marker_dir()` from the same
        // (overridden) environment, so the recomputed path matches what
        // `run_record` actually wrote — isolated to a tempdir so this never
        // lands in the real per-user marker directory (#302).
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-test-repo";
            let branch = "feat/record-polish-y";
            let path = polish_marker(repo, branch);

            run_record(Some(repo.into()), Some(branch.into()), Some("code".into()));

            assert!(path.is_file(), "marker should exist at {path:?}");
            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["branch"], branch);
            assert_eq!(v["scope"], "code");
        });
    }

    #[test]
    fn run_record_degrades_to_noop_when_repo_unresolved() {
        // No overrides, and `cargo test`'s cwd IS this real git checkout, so
        // `resolve` actually succeeds here (unlike the name implies) and
        // `run_record` really does write a marker — isolate it (#302), same as
        // every other write-path test in this module.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            run_record(None, None, Some("full".into()));
        });
    }

    // --- worktree-stable keying (cadence-hooks#324) ---

    /// Init a primary checkout with one commit (a real commit is required —
    /// `git worktree add` refuses an unborn branch), plus a `git` closure bound
    /// to that checkout.
    fn init_primary_with_commit(primary: &std::path::Path) {
        std::fs::create_dir_all(primary).unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(primary)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "init"]);
    }

    #[test]
    fn worktree_record_satisfies_primary_check_same_branch() {
        // RED (#324): a polish recorded from a LINKED WORKTREE must satisfy a
        // ship command run from the PRIMARY checkout on the same branch — the
        // marker key must be common-dir-based, not `--show-toplevel`-based
        // (a worktree's toplevel is its own path, not the shared repo).
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);

        let wt = tmp.path().join("wt");
        let git = |args: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&primary)
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "git {args:?} failed"
            );
        };
        git(&[
            "worktree",
            "add",
            "-q",
            wt.to_str().unwrap(),
            "-b",
            "feat/thing",
        ]);

        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            // Record from the WORKTREE path — the record side's own resolution.
            let wt_str = wt.to_str().unwrap().to_string();
            let (repo_root, branch, head_sha) =
                resolve(&wt_str, None, None).expect("worktree resolves repo/branch");
            assert_eq!(branch, "feat/thing");
            let content = marker_content(&branch, &head_sha, "full");
            write_marker(&polish_marker(&repo_root, &branch), &content).unwrap();

            // Free the branch from the worktree and check it out on the primary —
            // the realistic sequel to "finished the worktree, shipping from primary".
            git(&["worktree", "remove", "--force", wt.to_str().unwrap()]);
            git(&["checkout", "-q", "feat/thing"]);

            assert!(
                cadence_hooks_core::markers::polish_marker_present(
                    "gh pr create --title x",
                    Some(primary.to_str().unwrap()),
                ),
                "a polish marker recorded from a linked worktree must satisfy a ship \
                 command run from the primary checkout on the same branch"
            );
        });
    }
}
