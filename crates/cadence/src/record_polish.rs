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

/// The canonical marker key for a directory: the canonicalized
/// `git_common_dir` from [`GitState::resolve`]. `None` when `dir` is not inside
/// a git repository.
fn repo_key(dir: &str) -> Option<String> {
    GitState::resolve(std::path::Path::new(dir))
        .map(|state| state.git_common_dir.to_string_lossy().into_owned())
}

/// Resolve `repo_root`, `branch`, and `head_sha` from `dir`, letting explicit
/// overrides stand in so tests need no real repository.
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
///
/// An explicit `repo_root` is resolved through that same canonicalization
/// rather than used verbatim (cadence-hooks#417), so the flag can only ever
/// *locate* the repo — never *redefine* the key. Passing the linked worktree
/// you happen to be standing in is the most natural thing to do and was
/// precisely the value that broke: it wrote a marker under the worktree's own
/// path, which the ship gate — keyed on the common dir — can never read. The
/// failure was silent and delayed, surfacing later as a polish nudge on a
/// branch that genuinely had been polished.
///
/// When the path resolves to no repository at all the literal value stands,
/// which is what keeps the test override (a bogus dir plus an explicit branch,
/// resolving without touching git) working. A path *inside* a repo resolves
/// upward to that repo — locating by any path under it is the affordance, so
/// only a path under no repo falls through to the literal.
///
/// An explicit `repo_root` re-bases the **whole** resolution, not just the repo
/// half: `branch` and `head_sha` are read from that same checkout rather than
/// from `dir`. Splitting them is a live mis-record, and #417 is what made it
/// reachable — before it, an explicit root produced a key nothing read, so the
/// asymmetry was inert. With the repo half correct and the branch half still
/// coming from the caller's cwd, an orchestrator recording on a worker's behalf
/// (`record-polish --repo-root <worker worktree>`, no `--branch`, run from a
/// checkout sitting on `main`) would write a marker keyed to the worker's repo
/// but the *orchestrator's* branch: the polished branch keeps getting nudged,
/// and `main` is silently credited with a polish it never had. That is exactly
/// the case the flag exists for, so the two halves must move together.
fn resolve(
    dir: &str,
    repo_root: Option<String>,
    branch: Option<String>,
) -> Option<(String, String, String)> {
    let base = repo_root.as_deref().unwrap_or(dir).to_string();
    let git_state = || GitState::resolve(std::path::Path::new(&base));
    let repo_root = repo_root
        .map(|explicit| {
            repo_key(&explicit).unwrap_or_else(|| {
                // Say so. The whole failure #417 exists to kill is a success
                // verdict over a key nothing will read, and the literal
                // fallback is the one surviving path that can still produce
                // one — a typo'd root keys the typo, and a relative root keys
                // the bare string, which collides across repos.
                eprintln!(
                    "cadence-hooks record-polish: --repo-root {explicit} is not a git \
                     repository — any marker will use that literal key, which the \
                     pre-PR gate will not match unless it was given the same literal."
                );
                explicit
            })
        })
        .or_else(|| git_state().map(|state| state.git_common_dir.to_string_lossy().into_owned()))?;
    let branch = branch.or_else(|| git_state().and_then(|state| state.branch))?;
    // Polish does not commit (SKILL.md), so this is the pre-polish base SHA — a
    // provenance breadcrumb for CP2, never an exact-match key. Empty when the
    // repo has no HEAD yet.
    let head_sha = git_command(&base, &["rev-parse", "HEAD"]).unwrap_or_default();
    Some((repo_root, branch, head_sha))
}

/// Parse repeatable `--arm name=state` values into the roster, dropping (and
/// naming, on stderr) any value without a `name=state` shape — fail-open, the
/// rest of the record still lands (ADR-0001).
fn parse_arms(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((name, state)) if !name.is_empty() && !state.is_empty() => {
                Some((name.trim().to_string(), state.trim().to_string()))
            }
            _ => {
                eprintln!(
                    "cadence-hooks record-polish: ignoring malformed --arm {entry:?} \
                     (expected name=state, e.g. security=ran)"
                );
                None
            }
        })
        .collect()
}

/// Build the marker payload. Presence is what CP1 gates on; the fields are
/// stored now so CP2's freshness/scope escalation needs no format change.
/// The `arms` roster (cadence-hooks#467) is **additive and optional**: absent
/// on a roster-less record, so legacy readers and legacy markers both keep
/// working — an absent roster reads as *unknown*, never as *skipped*.
fn marker_content(branch: &str, head_sha: &str, scope: &str, arms: &[(String, String)]) -> String {
    let mut v = json!({
        "branch": branch,
        "head_sha": head_sha,
        "recorded_at": utc_timestamp(),
        "scope": scope,
    });
    if !arms.is_empty() {
        let roster: serde_json::Map<String, serde_json::Value> = arms
            .iter()
            .map(|(name, state)| (name.clone(), json!(state)))
            .collect();
        v["arms"] = serde_json::Value::Object(roster);
    }
    v.to_string()
}

/// One-line success verdict: the marker path (the payload a caller probes to
/// confirm the pre-PR gate is satisfied) plus the (repo@branch, scope) key —
/// and the arm roster when one was recorded, so the caller sees what the gate
/// will see.
fn record_verdict(
    repo_root: &str,
    branch: &str,
    scope: &str,
    arms: &[(String, String)],
    path: &Path,
) -> String {
    let roster = if arms.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = arms.iter().map(|(n, s)| format!("{n}={s}")).collect();
        format!(" arms={}", list.join(","))
    };
    format!(
        "recorded polish marker: {} ({repo_root}@{branch} scope={scope}{roster})",
        path.display()
    )
}

/// Write the branch-scoped polish marker, resolving repo/branch/HEAD from the
/// current directory unless overridden. Fail-open: any missing context or write
/// error prints one stderr line and returns without error — a CLI action must
/// never fail the polish pass it is recording (ADR-0001).
pub fn run_record(
    repo_root: Option<String>,
    branch: Option<String>,
    scope: Option<String>,
    arm: Vec<String>,
) {
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
    let arms = parse_arms(&arm);
    let content = marker_content(&branch, &head_sha, &scope, &arms);
    let path = polish_marker(&repo_root, &branch);
    match write_marker(&path, &content) {
        Ok(()) => println!(
            "{}",
            record_verdict(&repo_root, &branch, &scope, &arms, &path)
        ),
        Err(e) => eprintln!(
            "cadence-hooks record-polish: marker write failed ({e}) — pre-PR gate may re-nudge."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::markers::polish_marker;
    use cadence_hooks_core::test_builders::with_marker_dir;

    #[test]
    fn marker_content_is_parseable_json_with_all_fields() {
        let content = marker_content("feat/x", "abc123", "full", &[]);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["branch"], "feat/x");
        assert_eq!(v["head_sha"], "abc123");
        assert_eq!(v["scope"], "full");
        // recorded_at is an ISO-8601 UTC instant (jiff `utc_timestamp`).
        let ts = v["recorded_at"].as_str().unwrap();
        assert!(ts.ends_with('Z'), "recorded_at should be UTC: {ts}");
        // #467: a roster-less record carries NO arms key at all — absent, not
        // empty — so legacy-shaped markers stay the common case on disk.
        assert!(v.get("arms").is_none(), "no --arm flags → no arms key");
    }

    #[test]
    fn marker_content_records_arm_roster_additively() {
        // #467 RED: the roster rides an additive "arms" object.
        let arms = vec![
            ("security".to_string(), "ran".to_string()),
            ("tests".to_string(), "skipped".to_string()),
        ];
        let content = marker_content("feat/x", "abc123", "code", &arms);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["arms"]["security"], "ran");
        assert_eq!(v["arms"]["tests"], "skipped");
        assert_eq!(v["scope"], "code", "existing fields unchanged");
    }

    #[test]
    fn parse_arms_accepts_name_state_and_drops_malformed() {
        let raw = vec![
            "security=ran".to_string(),
            "bogus".to_string(),
            "=x".to_string(),
            "docs=skipped".to_string(),
        ];
        let arms = parse_arms(&raw);
        assert_eq!(
            arms,
            vec![
                ("security".to_string(), "ran".to_string()),
                ("docs".to_string(), "skipped".to_string()),
            ],
            "malformed entries drop without failing the record"
        );
    }

    #[test]
    fn record_verdict_names_path_repo_branch_and_scope() {
        let path = polish_marker("/tmp/repo", "feat/x");
        let verdict = record_verdict("/tmp/repo", "feat/x", "full", &[], &path);
        assert!(verdict.contains(&path.display().to_string()));
        assert!(verdict.contains("/tmp/repo@feat/x"));
        assert!(verdict.contains("scope=full"));
        assert!(!verdict.contains("arms="), "no roster → no arms clause");
    }

    #[test]
    fn record_verdict_names_the_roster_when_present() {
        // #467: the verdict shows the caller what the gate will see.
        let path = polish_marker("/tmp/repo", "feat/x");
        let arms = vec![("security".to_string(), "skipped".to_string())];
        let verdict = record_verdict("/tmp/repo", "feat/x", "code", &arms, &path);
        assert!(verdict.contains("arms=security=skipped"), "{verdict}");
    }

    #[test]
    fn resolve_uses_explicit_overrides_without_touching_git() {
        // Explicit repo_root + branch supply both halves of the KEY without a
        // repository, so a bogus dir still resolves — the property the write
        // test below relies on. (`head_sha` still shells out, now against the
        // flag's value rather than `dir`; it is provenance, not key material,
        // and fails to empty here.) A non-repo `repo_root` is NOT a path #417
        // canonicalizes: there is no repo to resolve it against, so the literal
        // value stands.
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

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("code".into()),
                vec!["security=ran".into()],
            );

            assert!(path.is_file(), "marker should exist at {path:?}");
            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["branch"], branch);
            assert_eq!(v["scope"], "code");
            // #467: the roster round-trips through the written marker.
            assert_eq!(v["arms"]["security"], "ran");
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
            run_record(None, None, Some("full".into()), vec![]);
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
            let content = marker_content(&branch, &head_sha, "full", &[]);
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

    #[test]
    fn explicit_repo_root_keys_the_same_marker_the_ship_gate_reads() {
        // RED (#417): `--repo-root` used to be the marker key VERBATIM, while
        // the default path keyed on the canonicalized `git_common_dir`. Passing
        // the linked worktree you are standing in — the most natural value —
        // therefore wrote a marker the ship gate could never read, and the
        // failure surfaced later as a nudge on a branch that HAD been polished.
        //
        // Resolving the flag through the same canonicalization makes it able to
        // locate the repo but not redefine the key, so all three spellings
        // below must produce one key: the worktree path, the primary path, and
        // no flag at all.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);

        let wt = tmp.path().join("wt");
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&primary)
                .args([
                    "worktree",
                    "add",
                    "-q",
                    wt.to_str().unwrap(),
                    "-b",
                    "feat/x"
                ])
                .output()
                .unwrap()
                .status
                .success(),
            "git worktree add failed"
        );

        let wt_str = wt.to_str().unwrap().to_string();
        let primary_str = primary.to_str().unwrap().to_string();

        let key =
            |dir: &str, explicit: Option<String>| resolve(dir, explicit, None).expect("resolves").0;

        let via_flag_from_worktree = key(&primary_str, Some(wt_str.clone()));
        let via_flag_from_primary = key(&wt_str, Some(primary_str.clone()));
        let via_cwd = key(&wt_str, None);

        assert_eq!(
            via_flag_from_worktree, via_cwd,
            "--repo-root pointing at a linked worktree must key the same marker \
             the default cwd resolution writes"
        );
        assert_eq!(
            via_flag_from_primary, via_cwd,
            "--repo-root pointing at the primary checkout must key the same marker too"
        );

        // An explicit root re-bases the BRANCH too (security review, #417).
        // With `--repo-root <worktree>` and no `--branch`, the branch must come
        // from that worktree — not from the caller's cwd, which here is the
        // primary sitting on `main`. Splitting them credits `main` with a
        // polish it never had while the polished branch keeps getting nudged.
        let (_, branch_from_flag, _) =
            resolve(&primary_str, Some(wt_str.clone()), None).expect("resolves");
        assert_eq!(
            branch_from_flag, "feat/x",
            "--repo-root must re-base the branch resolution, not just the repo key"
        );

        // And the end-to-end property that actually matters: a marker recorded
        // with `--repo-root <worktree>` satisfies a ship run from the primary.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let (repo_root, branch, head_sha) =
                resolve(&primary_str, Some(wt_str.clone()), Some("feat/x".into()))
                    .expect("resolves");
            write_marker(
                &polish_marker(&repo_root, &branch),
                &marker_content(&branch, &head_sha, "code", &[]),
            )
            .unwrap();

            assert!(
                cadence_hooks_core::markers::polish_marker_present(
                    "gh pr create --title x",
                    Some(&wt_str),
                ),
                "a marker recorded via --repo-root must be readable by the ship gate"
            );
        });
    }
}
