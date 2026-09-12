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
//! One rule for every worktree, chosen so a branch cannot hide in the gap
//! between two rules:
//!
//! 1. **With an upstream**, the count is `rev-list --count @{u}..HEAD` — the
//!    commits the configured upstream does not have.
//! 2. **Without an upstream**, the count is `rev-list --count <default>..HEAD`
//!    against the remote's default branch ([`default_remote_ref`]). A branch
//!    that was never pushed has no upstream at all, which is the *riskiest*
//!    case and the one a bare `@{u}..` probe silently reports as zero.
//!
//! A detached HEAD is skipped: there is no branch to push, and the commits are
//! reachable from wherever it was detached in all but deliberate cases.
//!
//! ## Bounding
//!
//! Each worktree costs one or two `git` spawns, all of them under the shared
//! per-process deadline (`cadence_hooks_core::deadline`). Two bounds keep a
//! large or slow repo from eating the whole budget:
//!
//! - at most [`MAX_WORKTREES`] worktrees are probed, and
//! - the scan stops at the first probe the deadline abandons.
//!
//! Either bound sets [`WorktreeScan::truncated`], which the rendered warning
//! states rather than passing off a partial count as complete.

use cadence_hooks_core::shell::{GitOutput, GitQuery, git_command_detailed, git_output_detailed};
use serde::{Deserialize, Serialize};

/// Most worktrees to probe in one scan. A repo with more than this is scanned
/// partially and says so — the alternative is spending the whole subprocess
/// budget on an end-of-session advisory.
const MAX_WORKTREES: usize = 16;

/// Remote-tracking refs tried, in order, when a remote publishes no
/// `origin/HEAD`. A bare clone or a remote added by hand often has none.
const DEFAULT_REF_FALLBACKS: &[&str] = &["origin/main", "origin/master"];

/// One worktree whose branch carries commits no remote has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpushedWorktree {
    /// Canonical path to the worktree — what tells the session's own checkout
    /// from a sibling, and what an operator needs to go find the work.
    pub path: String,
    /// The branch name, short form (`feat/x`).
    pub branch: String,
    /// Commits absent from the upstream (or from the remote's default branch,
    /// when the branch has no upstream).
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

/// Parse `git worktree list --porcelain`.
///
/// The format is one blank-line-separated block per worktree, opening with
/// `worktree <path>`; `branch refs/heads/<name>` names the branch, `detached`
/// and `bare` are valueless flags. Unknown keys (`locked`, `prunable`,
/// `HEAD`) are ignored rather than rejected, so a newer git adding a key
/// cannot empty the scan.
///
/// Pure — the whole parsing surface is table-testable without a repository.
pub fn parse_worktree_list(porcelain: &str) -> Vec<WorktreeEntry> {
    let mut entries: Vec<WorktreeEntry> = Vec::new();
    for line in porcelain.lines() {
        let line = line.trim_end();
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

/// The remote-tracking ref that stands in for "published" when a branch has no
/// upstream.
///
/// `refs/remotes/origin/HEAD` first — the remote's own answer — then the
/// conventional [`DEFAULT_REF_FALLBACKS`], each verified to exist before it is
/// returned. `None` when the repository has no remote-tracking refs at all, in
/// which case an upstream-less branch is simply not counted: with nothing to
/// compare against, every commit would look unpushed and the advisory would
/// fire on every local-only repository.
pub fn default_remote_ref(dir: &str) -> Option<String> {
    if let GitQuery::Value(name) = git_command_detailed(
        dir,
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    ) {
        return Some(name);
    }
    DEFAULT_REF_FALLBACKS.iter().copied().find_map(|candidate| {
        matches!(
            git_command_detailed(dir, &["rev-parse", "--verify", "--quiet", candidate]),
            GitQuery::Value(_)
        )
        .then(|| candidate.to_string())
    })
}

/// How many commits `dir`'s checked-out branch carries that no remote has.
///
/// `Ok(None)` means "nothing to measure against": no upstream and no default
/// remote ref. `Err(())` means the probe was abandoned at the deadline — the
/// caller stops scanning rather than reporting a short list as complete.
type CountOutcome = Result<Option<usize>, ()>;

fn unpushed_count(dir: &str, default_ref: Option<&str>) -> CountOutcome {
    match count_range(dir, "@{u}..HEAD") {
        Ok(Some(n)) => return Ok(Some(n)),
        // A missing upstream exits non-zero, which is the fallback's trigger —
        // not an error.
        Ok(None) => {}
        Err(()) => return Err(()),
    }
    let Some(default_ref) = default_ref else {
        return Ok(None);
    };
    count_range(dir, &format!("{default_ref}..HEAD"))
}

/// `git rev-list --count <range>` in `dir`.
///
/// `Ok(None)` for a git error (an unknown ref, no upstream, an unborn HEAD),
/// `Err(())` for a deadline timeout. A spawn failure — no `git` on `PATH` —
/// is `Err(())` too: it will not succeed for the next worktree either, so
/// continuing would spend the remaining budget learning the same thing.
fn count_range(dir: &str, range: &str) -> CountOutcome {
    match git_output_detailed(dir, &["rev-list", "--count", range]) {
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
    let porcelain = match git_output_detailed(dir, &["worktree", "list", "--porcelain"]) {
        GitOutput::Ok(text) => text,
        // No repository, no git, or out of budget — nothing to report, and
        // nothing was skipped, so this is not a truncated scan.
        GitOutput::Failed | GitOutput::Unavailable | GitOutput::TimedOut => {
            return WorktreeScan::default();
        }
    };

    let default_ref = default_remote_ref(dir);
    let mut scan = WorktreeScan::default();

    let candidates: Vec<WorktreeEntry> = parse_worktree_list(&porcelain)
        .into_iter()
        .filter(|entry| !entry.bare && entry.branch.is_some())
        .collect();

    if candidates.len() > MAX_WORKTREES {
        scan.truncated = true;
    }

    for entry in candidates.into_iter().take(MAX_WORKTREES) {
        let Some(branch) = entry.branch else { continue };
        match unpushed_count(&entry.path, default_ref.as_deref()) {
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

    #[test]
    fn parses_a_primary_and_two_linked_worktrees() {
        let porcelain = "\
worktree /repo
HEAD abc123
branch refs/heads/main

worktree /repo/.claude/worktrees/a
HEAD def456
branch refs/heads/feat/a

worktree /repo/.claude/worktrees/b
HEAD 789abc
detached
";
        let entries = parse_worktree_list(porcelain);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "/repo");
        assert_eq!(entries[0].branch.as_deref(), Some("main"));
        assert_eq!(entries[1].branch.as_deref(), Some("feat/a"));
        assert_eq!(entries[2].branch, None, "a detached worktree has no branch");
        assert!(entries.iter().all(|e| !e.bare));
    }

    #[test]
    fn parses_a_bare_main_worktree() {
        let entries = parse_worktree_list("worktree /repo.git\nbare\n");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].bare);
    }

    #[test]
    fn keeps_a_branch_name_containing_slashes_and_ignores_unknown_keys() {
        let entries = parse_worktree_list(
            "worktree /repo\nHEAD abc\nbranch refs/heads/feat/deep/name\nlocked\nprunable gone\n",
        );
        assert_eq!(entries[0].branch.as_deref(), Some("feat/deep/name"));
    }

    #[test]
    fn ignores_keys_before_any_worktree_block() {
        assert!(parse_worktree_list("branch refs/heads/x\nbare\n").is_empty());
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
            "a never-pushed branch is measured against the remote's default branch"
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
    fn default_remote_ref_resolves_origin_main_without_origin_head() {
        let scratch = Scratch::new(&scratch_root(), "default-ref");
        let repo = repo_with_remote(&scratch);
        // A `git push` sets no `origin/HEAD`, so this exercises the fallback.
        assert_eq!(
            default_remote_ref(&repo.to_string_lossy()).as_deref(),
            Some("origin/main")
        );
    }

    #[test]
    fn default_remote_ref_is_none_without_a_remote() {
        let scratch = Scratch::new(&scratch_root(), "default-ref-none");
        let repo = scratch.path().join("solo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        assert_eq!(default_remote_ref(&repo.to_string_lossy()), None);
    }
}
