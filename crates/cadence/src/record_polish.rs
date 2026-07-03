//! Record that `/polish` (cadence-forge:polish) ran on this branch.
//!
//! A **CLI action**, not a hook: the polish skill's Wrap-up shells out to
//! `cadence-hooks cadence record-polish` after a completed pass, which writes a
//! branch-scoped marker under the private [`markers::marker_dir`]. The pre-PR
//! gate ([`crate::nudge_polish_before_pr`]) then reads that marker instead of
//! scanning the session transcript.
//!
//! The marker key is `(repo_root, branch)` (see [`markers::polish_marker`]), so
//! detection is invocation-agnostic (Skill call, `/polish` slash-command, or a
//! delegated subagent all end by running this) and branch-scoped (a marker for
//! branch A cannot satisfy a PR on branch B).
//!
//! Advisory, always — this must never fail the user's polish pass. Every error
//! path (not a repo, detached HEAD, unwritable marker dir) prints one stderr
//! line and exits 0 (ADR-0001).

use cadence_hooks_core::markers::{polish_marker, write_marker};
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::time::utc_timestamp;
use serde_json::json;

/// Resolve `repo_root`, `branch`, and `head_sha` from `dir` via git, letting
/// explicit overrides bypass the shell-out so tests need no real repository.
///
/// `head_sha` is best-effort: a repo with no commits yet has no `HEAD`, so it
/// resolves to `None` and the field is recorded as an empty string rather than
/// failing the record. `repo_root` and `branch` are the load-bearing key; when
/// either can't be resolved the caller degrades to a no-op (exit 0).
fn resolve(
    dir: &str,
    repo_root: Option<String>,
    branch: Option<String>,
) -> Option<(String, String, String)> {
    let repo_root =
        repo_root.or_else(|| git_command(dir, &["rev-parse", "--show-toplevel"]))?;
    let branch = branch.or_else(|| git_command(dir, &["branch", "--show-current"]))?;
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
    if let Err(e) = write_marker(&path, &content) {
        eprintln!("cadence-hooks record-polish: marker write failed ({e}) — pre-PR gate may re-nudge.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // With explicit overrides the write path is `polish_marker(repo, branch)`
        // — the same value this test recomputes, since both calls resolve
        // `marker_dir()` from the same environment. No env mutation needed: the
        // marker lands in the real private dir at a hashed, unique name; we read
        // it back and clean up. A repo/branch unlikely to collide with any peer.
        let repo = "/tmp/record-polish-test-repo";
        let branch = "feat/record-polish-y";
        let path = polish_marker(repo, branch);
        let _ = std::fs::remove_file(&path); // ensure a clean slate

        run_record(Some(repo.into()), Some(branch.into()), Some("code".into()));

        assert!(path.is_file(), "marker should exist at {path:?}");
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["branch"], branch);
        assert_eq!(v["scope"], "code");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_record_degrades_to_noop_when_repo_unresolved() {
        // No overrides + a non-repo cwd → resolve returns None → no panic, no
        // marker. Asserts the call simply returns (fail-open) without unwinding;
        // a bad marker dir would likewise exit via the write_marker arm.
        run_record(None, None, Some("full".into()));
    }
}
