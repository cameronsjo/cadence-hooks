//! Count the commits each of a repo's worktrees would lose if nobody pushed
//! (cadence-hooks#619).
//!
//! A worktree's branch is durable once pushed and nowhere else before that.
//! `cadence:using-agent-teams` says so in prose; this module makes it a
//! measurement, taken at session end by [`crate::backstop::BackstopRecord`] and
//! surfaced by [`crate::backstop::BackstopWarn`] at the next session start —
//! the deferred shape that module's docs explain, because `SessionEnd` output
//! reaches no user-visible surface.
//!
//! ## What counts as unpushed
//!
//! One rule for every worktree: `rev-list --count HEAD --not --remotes` — the
//! commits reachable from the worktree's HEAD that **no remote-tracking ref**
//! contains. The measure answers the question the advisory is for ("what is
//! lost if this machine dies?"), and it answers it the same way for every
//! branch, so none can hide in the gap between two rules:
//!
//! - a branch with an upstream reports what the upstream does not have;
//! - a branch pushed without `-u` — no upstream configured, yet published —
//!   reports zero, because the remote already has those commits;
//! - a branch stacked on a pushed base reports only its own commits, not its
//!   base's;
//! - a branch that was never pushed at all reports everything past the nearest
//!   published commit, the riskiest case and the one a bare `@{u}..` probe
//!   silently reports as zero.
//!
//! A stale remote-tracking ref over-excludes: nothing here fetches, so a branch
//! whose remote counterpart was deleted elsewhere still measures against the
//! last ref this checkout saw and under-reports. Under-reporting is the safe
//! direction for an advisory, and fetching is not.
//!
//! [`has_remote_tracking_refs`] gates the whole measure: with no
//! remote-tracking refs at all, `--not --remotes` excludes nothing and every
//! commit would read as unpushed, so a local-only repository reports nothing
//! instead.
//!
//! A detached HEAD is skipped: there is no branch to push, and the commits are
//! reachable from wherever it was detached in all but deliberate cases.
//!
//! ## Bounding
//!
//! Each worktree costs one `git` spawn, all of them under the shared
//! per-process deadline (`cadence_hooks_core::deadline`). Two bounds keep a
//! large or slow repo from eating the whole budget:
//!
//! - at most [`MAX_WORKTREES`] worktrees are probed — the session's own
//!   checkout first, so the cap can never cost the caller its own count, and
//!   then the siblings in `git worktree list` order; and
//! - the scan stops at the first probe the deadline abandons.
//!
//! Either bound sets [`WorktreeScan::truncated`], which the rendered warning
//! states rather than passing off a partial count as complete.

use cadence_hooks_core::shell::{GitOutput, GitQuery, git_command_detailed, git_output_detailed};
use serde::{Deserialize, Serialize};

/// Most worktrees to probe in one scan. A repo with more than this is scanned
/// partially and says so — the alternative is spending the whole subprocess
/// budget on an end-of-session advisory. Also the most worktrees any one
/// warning renders, so a marker cannot grow the text without bound.
pub const MAX_WORKTREES: usize = 16;

/// One worktree whose branch carries commits no remote has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpushedWorktree {
    /// Canonical path to the worktree — what tells the session's own checkout
    /// from a sibling, and what an operator needs to go find the work.
    pub path: String,
    /// The branch name, short form (`feat/x`).
    pub branch: String,
    /// Commits reachable from this worktree's HEAD that no remote-tracking ref
    /// contains.
    pub commits: usize,
}

/// The result of one scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorktreeScan {
    /// Worktrees with unpushed commits, in `git worktree list` order.
    pub unpushed: Vec<UnpushedWorktree>,
    /// True when the scan stopped early — past [`MAX_WORKTREES`], or at a
    /// probe the deadline abandoned. The counts collected are still accurate;
    /// there may simply be more.
    pub truncated: bool,
}

/// One entry of `git worktree list --porcelain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    /// Absolute path to the worktree.
    pub path: String,
    /// Short branch name, or `None` for a detached HEAD.
    pub branch: Option<String>,
    /// True for the repository's bare main worktree, which has no checkout.
    pub bare: bool,
}

/// Parse `git worktree list --porcelain -z`.
///
/// The format is one block per worktree, opening with `worktree <path>`;
/// `branch refs/heads/<name>` names the branch, `detached` and `bare` are
/// valueless flags. Unknown keys (`locked`, `prunable`, `HEAD`) are ignored
/// rather than rejected, so a newer git adding a key cannot empty the scan.
///
/// **NUL-separated, not newline-separated.** `-z` terminates every record with
/// a NUL and separates blocks with an empty record, which is the only framing
/// a path may not contain: a worktree at a path with a newline in it splits
/// into a phantom entry under newline framing, and git's own `-z` exists for
/// exactly that reason.
///
/// Pure — the whole parsing surface is table-testable without a repository.
pub fn parse_worktree_list(porcelain: &str) -> Vec<WorktreeEntry> {
    let mut entries: Vec<WorktreeEntry> = Vec::new();
    for line in porcelain.split('\0') {
        // No trimming: under `-z` git emits no trailing whitespace, and a
        // worktree path is allowed to end in any byte but NUL.
        if let Some(path) = line.strip_prefix("worktree ") {
            entries.push(WorktreeEntry {
                path: path.to_string(),
                branch: None,
                bare: false,
            });
            continue;
        }
        // Every other key belongs to the block opened by the last `worktree`
        // line. A stray key before any block is dropped rather than
        // misattributed.
        let Some(current) = entries.last_mut() else {
            continue;
        };
        if let Some(reference) = line.strip_prefix("branch ") {
            current.branch = Some(
                reference
                    .strip_prefix("refs/heads/")
                    .unwrap_or(reference)
                    .to_string(),
            );
        } else if line == "bare" {
            current.bare = true;
        }
    }
    entries
}

/// Whether the repository has any remote-tracking ref at all.
///
/// This asks about exactly the ref namespace the measure walks: `--remotes`
/// means `refs/remotes`, so `for-each-ref --count=1 refs/remotes` answers the
/// only question the gate has — is there anything for `--not --remotes` to
/// exclude? A gate that named `origin` instead would silently report nothing
/// for a repository whose remote is called `upstream`, and for an `origin`
/// whose default branch is `trunk` with no `origin/HEAD` to find it by.
///
/// `false` when the answer is empty, unavailable, or abandoned at the
/// deadline: with nothing to exclude, every commit would read as unpushed and
/// the advisory would fire on every local-only repository.
pub fn has_remote_tracking_refs(dir: &str) -> bool {
    matches!(
        git_command_detailed(dir, &["for-each-ref", "--count=1", "refs/remotes"]),
        GitQuery::Value(_)
    )
}

/// How many commits `dir`'s checked-out branch carries that no remote has.
///
/// `Ok(None)` means "nothing to measure": `has_remote_refs` is false, or git
/// could not answer. `Err(())` means the probe was abandoned at the deadline —
/// the caller stops scanning rather than reporting a short list as complete.
type CountOutcome = Result<Option<usize>, ()>;

/// One measure for every worktree: commits reachable from HEAD that no
/// remote-tracking ref contains.
///
/// `--not --remotes` is what makes a branch's *publication*, rather than its
/// upstream configuration, decide the count. `git push origin feat/x` without
/// `-u` publishes the branch and configures no upstream, so an `@{u}..HEAD`
/// probe cannot see it at all and a `<default>..HEAD` fallback counts commits
/// the remote already holds — worse on a branch stacked on a pushed base,
/// where the base's commits are counted against the child.
///
/// `has_remote_refs` — [`has_remote_tracking_refs`] for this repository — is
/// required because `--not --remotes` with no `refs/remotes` excludes nothing:
/// every commit in the repository would read as unpushed.
fn unpushed_count(dir: &str, has_remote_refs: bool) -> CountOutcome {
    if !has_remote_refs {
        return Ok(None);
    }
    count_unpushed(dir)
}

/// `git rev-list --count HEAD --not --remotes` in `dir`.
///
/// `Ok(None)` for a git error (an unborn HEAD, a broken ref), `Err(())` for a
/// deadline timeout. A spawn failure — no `git` on `PATH` — is `Err(())` too:
/// it will not succeed for the next worktree either, so continuing would spend
/// the remaining budget learning the same thing.
fn count_unpushed(dir: &str) -> CountOutcome {
    match git_output_detailed(dir, &["rev-list", "--count", "HEAD", "--not", "--remotes"]) {
        GitOutput::Ok(value) => Ok(value.trim().parse::<usize>().ok()),
        GitOutput::Failed => Ok(None),
        GitOutput::Unavailable | GitOutput::TimedOut => Err(()),
    }
}

/// Scan every worktree of the repository containing `dir`, the session's own
/// checkout included.
///
/// One rule for every worktree is the point: the caller tells its own checkout
/// from a sibling by comparing [`canonical_path`] against
/// [`UnpushedWorktree::path`], rather than this scan applying a second rule to
/// one of them.
pub fn scan(dir: &str) -> WorktreeScan {
    let porcelain = match git_output_detailed(dir, &["worktree", "list", "--porcelain", "-z"]) {
        GitOutput::Ok(text) => text,
        // No repository or no git — nothing to report, and nothing was
        // skipped, so this is not a truncated scan.
        GitOutput::Failed | GitOutput::Unavailable => return WorktreeScan::default(),
        // Out of budget before the list was even read: worktrees may well
        // carry unpushed work and this scan will never know, which is exactly
        // what `truncated` says.
        GitOutput::TimedOut => {
            return WorktreeScan {
                unpushed: Vec::new(),
                truncated: true,
            };
        }
    };

    let has_remote_refs = has_remote_tracking_refs(dir);
    let mut scan = WorktreeScan::default();

    let mut candidates: Vec<WorktreeEntry> = parse_worktree_list(&porcelain)
        .into_iter()
        .filter(|entry| !entry.bare && entry.branch.is_some())
        .collect();

    // The caller's own checkout is probed first. The cap applies in list
    // order, and a session sitting in the 17th worktree of a busy repo would
    // otherwise have its OWN count silently dropped while 16 siblings were
    // named — the one count it is most able to act on (cadence-hooks#619
    // review).
    let here = canonical_path(dir);
    if let Some(index) = candidates
        .iter()
        .position(|entry| canonical_path(&entry.path) == here)
    {
        let own = candidates.remove(index);
        candidates.insert(0, own);
    }

    if candidates.len() > MAX_WORKTREES {
        scan.truncated = true;
    }

    for entry in candidates.into_iter().take(MAX_WORKTREES) {
        let Some(branch) = entry.branch else { continue };
        match unpushed_count(&entry.path, has_remote_refs) {
            Ok(Some(commits)) if commits > 0 => {
                scan.unpushed.push(UnpushedWorktree {
                    path: canonical_path(&entry.path),
                    branch,
                    commits,
                });
            }
            Ok(_) => {}
            Err(()) => {
                scan.truncated = true;
                break;
            }
        }
    }

    scan
}

/// The canonical form of `path`, or the path itself when it cannot be resolved
/// (a pruned worktree, a permission error). Both sides of any comparison go
/// through this, so a symlinked prefix (macOS `/var` vs `/private/var`) cannot
/// make one worktree fail to match itself. Falling back to the literal string
/// keeps the function total: worst case two spellings fail to match and a
/// worktree is reported twice, which is the harmless direction.
pub fn canonical_path(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use std::path::{Path, PathBuf};

    // --- parse_worktree_list: table ---

    /// Fixture builder: `-z` framing from a readable newline-written block.
    /// Only fixtures that deliberately carry a newline INSIDE a record build
    /// their string by hand.
    fn z(porcelain: &str) -> String {
        porcelain.replace('\n', "\0")
    }

    #[test]
    fn parses_a_primary_and_two_linked_worktrees() {
        let porcelain = z("\
worktree /repo
HEAD abc123
branch refs/heads/main

worktree /repo/.claude/worktrees/a
HEAD def456
branch refs/heads/feat/a

worktree /repo/.claude/worktrees/b
HEAD 789abc
detached
");
        let entries = parse_worktree_list(&porcelain);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "/repo");
        assert_eq!(entries[0].branch.as_deref(), Some("main"));
        assert_eq!(entries[1].branch.as_deref(), Some("feat/a"));
        assert_eq!(entries[2].branch, None, "a detached worktree has no branch");
        assert!(entries.iter().all(|e| !e.bare));
    }

    #[test]
    fn parses_a_bare_main_worktree() {
        let entries = parse_worktree_list(&z("worktree /repo.git\nbare\n"));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].bare);
    }

    #[test]
    fn keeps_a_branch_name_containing_slashes_and_ignores_unknown_keys() {
        let entries = parse_worktree_list(&z(
            "worktree /repo\nHEAD abc\nbranch refs/heads/feat/deep/name\nlocked\nprunable gone\n",
        ));
        assert_eq!(entries[0].branch.as_deref(), Some("feat/deep/name"));
    }

    #[test]
    fn ignores_keys_before_any_worktree_block() {
        assert!(parse_worktree_list(&z("branch refs/heads/x\nbare\n")).is_empty());
    }

    #[test]
    fn a_path_containing_a_newline_stays_one_entry() {
        // The reason for `-z`: under newline framing the second half of this
        // path opens a phantom block, and the real worktree loses its branch.
        let porcelain = "worktree /repo/wt/a\nb\0HEAD abc\0branch refs/heads/feat/a\0\0";
        let entries = parse_worktree_list(porcelain);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].path, "/repo/wt/a\nb");
        assert_eq!(entries[0].branch.as_deref(), Some("feat/a"));
    }

    #[test]
    fn parses_empty_output_as_no_worktrees() {
        assert!(parse_worktree_list("").is_empty());
    }

    // --- integration: real repos with a fake remote ---

    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/unpushed-worktrees-scratch")
    }

    /// A repo on `main` whose one commit is pushed to a bare remote on disk.
    fn repo_with_remote(scratch: &Scratch) -> PathBuf {
        let remote = scratch.path().join("remote.git");
        std::fs::create_dir_all(&remote).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);

        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &["remote", "add", "origin", &remote.to_string_lossy()],
        );
        git_in(&repo, &["push", "-q", "-u", "origin", "main"]);
        repo
    }

    /// Add a linked worktree on a new branch and commit `n` files in it.
    fn worktree_with_commits(repo: &Path, name: &str, branch: &str, n: usize) -> PathBuf {
        let path = repo.join("wt").join(name);
        git_in(
            repo,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                branch,
                &path.to_string_lossy(),
                "main",
            ],
        );
        for i in 0..n {
            let file = path.join(format!("{name}-{i}.txt"));
            std::fs::write(&file, "x").unwrap();
            git_in(&path, &["add", "."]);
            git_in(&path, &["commit", "-q", "-m", "work"]);
        }
        path
    }

    #[test]
    fn counts_an_unpushed_branch_with_no_upstream() {
        let scratch = Scratch::new(&scratch_root(), "no-upstream");
        let repo = repo_with_remote(&scratch);
        let wt = worktree_with_commits(&repo, "a", "feat/a", 2);

        let scan = scan(&repo.to_string_lossy());

        assert!(!scan.truncated);
        assert_eq!(
            scan.unpushed,
            vec![UnpushedWorktree {
                path: canonical_path(&wt.to_string_lossy()),
                branch: "feat/a".into(),
                commits: 2,
            }],
            "a never-pushed branch loses every commit past the last published one"
        );
    }

    #[test]
    fn the_session_own_checkout_is_scanned_by_the_same_rule() {
        let scratch = Scratch::new(&scratch_root(), "own-checkout");
        let repo = repo_with_remote(&scratch);
        // A commit on `main` in the primary checkout, never pushed.
        std::fs::write(repo.join("h.txt"), "z").unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "unpushed on main"]);

        let scan = scan(&repo.to_string_lossy());

        assert_eq!(
            scan.unpushed,
            vec![UnpushedWorktree {
                path: canonical_path(&repo.to_string_lossy()),
                branch: "main".into(),
                commits: 1,
            }],
            "the primary checkout is a worktree like any other"
        );
    }

    #[test]
    fn counts_commits_ahead_of_a_configured_upstream() {
        let scratch = Scratch::new(&scratch_root(), "with-upstream");
        let repo = repo_with_remote(&scratch);
        let wt = worktree_with_commits(&repo, "b", "feat/b", 1);
        // Publish the branch, then add one more commit on top of it.
        git_in(&wt, &["push", "-q", "-u", "origin", "feat/b"]);
        std::fs::write(wt.join("extra.txt"), "y").unwrap();
        git_in(&wt, &["add", "."]);
        git_in(&wt, &["commit", "-q", "-m", "after push"]);

        let scan = scan(&repo.to_string_lossy());

        assert_eq!(
            scan.unpushed,
            vec![UnpushedWorktree {
                path: canonical_path(&wt.to_string_lossy()),
                branch: "feat/b".into(),
                commits: 1,
            }],
            "only the commit made after the push counts"
        );
    }

    #[test]
    fn a_fully_pushed_worktree_is_silent() {
        let scratch = Scratch::new(&scratch_root(), "pushed");
        let repo = repo_with_remote(&scratch);
        let wt = worktree_with_commits(&repo, "c", "feat/c", 1);
        git_in(&wt, &["push", "-q", "-u", "origin", "feat/c"]);

        let scan = scan(&repo.to_string_lossy());

        assert!(scan.unpushed.is_empty(), "{scan:?}");
        assert!(!scan.truncated);
    }

    #[test]
    fn every_worktree_with_work_is_reported() {
        let scratch = Scratch::new(&scratch_root(), "several");
        let repo = repo_with_remote(&scratch);
        worktree_with_commits(&repo, "d", "feat/d", 1);
        worktree_with_commits(&repo, "e", "feat/e", 3);

        let scan = scan(&repo.to_string_lossy());

        let branches: Vec<&str> = scan.unpushed.iter().map(|w| w.branch.as_str()).collect();
        assert_eq!(branches, vec!["feat/d", "feat/e"], "{scan:?}");
        assert_eq!(scan.unpushed[1].commits, 3);
    }

    #[test]
    fn a_detached_worktree_is_skipped() {
        let scratch = Scratch::new(&scratch_root(), "detached");
        let repo = repo_with_remote(&scratch);
        let wt = worktree_with_commits(&repo, "g", "feat/g", 1);
        git_in(&wt, &["checkout", "-q", "--detach"]);

        let scan = scan(&repo.to_string_lossy());
        assert!(
            scan.unpushed.is_empty(),
            "a detached HEAD has no branch to push: {scan:?}"
        );
    }

    #[test]
    fn a_repo_with_no_remote_reports_nothing() {
        let scratch = Scratch::new(&scratch_root(), "no-remote");
        let repo = scratch.path().join("solo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        worktree_with_commits(&repo, "f", "feat/f", 1);

        let scan = scan(&repo.to_string_lossy());
        assert!(
            scan.unpushed.is_empty(),
            "with no remote there is nothing to be unpushed against: {scan:?}"
        );
    }

    #[test]
    fn a_non_repository_directory_reports_nothing() {
        let scratch = Scratch::new(&scratch_root(), "not-a-repo");
        let scan = scan(&scratch.path().to_string_lossy());
        assert_eq!(scan, WorktreeScan::default());
    }

    #[test]
    fn the_gate_sees_a_remote_tracking_ref_however_it_is_named() {
        let scratch = Scratch::new(&scratch_root(), "gate-present");
        let repo = repo_with_remote(&scratch);
        // A `git push` sets no `origin/HEAD`, and the gate does not need one.
        assert!(has_remote_tracking_refs(&repo.to_string_lossy()));
    }

    #[test]
    fn the_gate_is_false_without_a_remote() {
        let scratch = Scratch::new(&scratch_root(), "gate-absent");
        let repo = scratch.path().join("solo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        assert!(!has_remote_tracking_refs(&repo.to_string_lossy()));
    }

    #[test]
    fn a_remote_not_named_origin_is_still_a_remote() {
        let scratch = Scratch::new(&scratch_root(), "upstream-remote");
        let remote = scratch.path().join("remote.git");
        std::fs::create_dir_all(&remote).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);

        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &["remote", "add", "upstream", &remote.to_string_lossy()],
        );
        git_in(&repo, &["push", "-q", "upstream", "main"]);
        std::fs::write(repo.join("after.txt"), "x").unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "unpushed"]);

        let scan = scan(&repo.to_string_lossy());

        assert_eq!(
            scan.unpushed.len(),
            1,
            "`origin` is a convention, not the gate: {scan:?}"
        );
        assert_eq!(scan.unpushed[0].commits, 1);
    }

    #[test]
    fn an_origin_whose_default_branch_is_trunk_is_still_measured() {
        let scratch = Scratch::new(&scratch_root(), "trunk-default");
        let remote = scratch.path().join("remote.git");
        std::fs::create_dir_all(&remote).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "trunk"]);

        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_in(&repo, &["init", "-q", "-b", "trunk"]);
        git_in(&repo, &["config", "user.email", "t@t"]);
        git_in(&repo, &["config", "user.name", "t"]);
        std::fs::write(repo.join("f.txt"), "x").unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "init"]);
        git_in(
            &repo,
            &["remote", "add", "origin", &remote.to_string_lossy()],
        );
        git_in(&repo, &["push", "-q", "origin", "trunk"]);
        std::fs::write(repo.join("after.txt"), "x").unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "unpushed"]);

        let scan = scan(&repo.to_string_lossy());

        assert_eq!(
            scan.unpushed.len(),
            1,
            "no origin/HEAD and no origin/main, but plenty to measure: {scan:?}"
        );
        assert_eq!(scan.unpushed[0].commits, 1);
        assert_eq!(scan.unpushed[0].branch, "trunk");
    }

    #[test]
    fn a_repo_past_the_worktree_cap_is_truncated() {
        let scratch = Scratch::new(&scratch_root(), "cap");
        let repo = repo_with_remote(&scratch);
        // One unpushed commit in the primary checkout too, so every candidate
        // carries work and the cap is the only thing shortening the list.
        std::fs::write(repo.join("own.txt"), "z").unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "unpushed on main"]);
        for i in 0..=MAX_WORKTREES {
            let name = format!("cap{i}");
            worktree_with_commits(&repo, &name, &format!("feat/{name}"), 1);
        }

        let scan = scan(&repo.to_string_lossy());

        assert!(scan.truncated, "past the cap the scan says so: {scan:?}");
        assert_eq!(scan.unpushed.len(), MAX_WORKTREES, "{scan:?}");
    }

    #[test]
    fn the_cap_never_drops_the_callers_own_checkout() {
        let scratch = Scratch::new(&scratch_root(), "cap-own-first");
        let repo = repo_with_remote(&scratch);
        for i in 0..MAX_WORKTREES {
            let name = format!("a{i:02}");
            worktree_with_commits(&repo, &name, &format!("feat/{name}"), 1);
        }
        // The caller sits in the LAST worktree git lists, past the cap.
        let own = worktree_with_commits(&repo, "zzz", "feat/zzz", 1);

        let scan = scan(&own.to_string_lossy());

        assert!(scan.truncated, "{scan:?}");
        let own_path = canonical_path(&own.to_string_lossy());
        let mine = scan
            .unpushed
            .iter()
            .find(|w| w.path == own_path)
            .unwrap_or_else(|| panic!("the caller's own worktree must survive the cap: {scan:?}"));
        assert_eq!(mine.commits, 1);
        assert_eq!(mine.branch, "feat/zzz");
    }

    #[test]
    fn a_branch_pushed_without_an_upstream_reports_zero() {
        let scratch = Scratch::new(&scratch_root(), "pushed-no-upstream");
        let repo = repo_with_remote(&scratch);
        let wt = worktree_with_commits(&repo, "nou", "feat/nou", 1);
        // No `-u`: the branch is published, no upstream is configured.
        git_in(&wt, &["push", "-q", "origin", "feat/nou"]);

        let scan = scan(&repo.to_string_lossy());

        assert!(
            scan.unpushed.is_empty(),
            "the remote already has these commits: {scan:?}"
        );
    }

    #[test]
    fn a_branch_stacked_on_a_pushed_base_counts_only_its_own_commits() {
        let scratch = Scratch::new(&scratch_root(), "stacked");
        let repo = repo_with_remote(&scratch);
        let base = worktree_with_commits(&repo, "base", "feat/base", 1);
        git_in(&base, &["push", "-q", "origin", "feat/base"]);

        let top = repo.join("wt").join("top");
        git_in(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "feat/top",
                &top.to_string_lossy(),
                "feat/base",
            ],
        );
        std::fs::write(top.join("top.txt"), "t").unwrap();
        git_in(&top, &["add", "."]);
        git_in(&top, &["commit", "-q", "-m", "own work"]);

        let scan = scan(&repo.to_string_lossy());

        assert_eq!(
            scan.unpushed,
            vec![UnpushedWorktree {
                path: canonical_path(&top.to_string_lossy()),
                branch: "feat/top".into(),
                commits: 1,
            }],
            "the base's published commit belongs to no worktree's count: {scan:?}"
        );
    }
}
