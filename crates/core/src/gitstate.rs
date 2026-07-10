//! `gitstate` — one tested resolution of "what git state is this path in?"
//!
//! The git/branch guard family re-derived repo-root resolution, branch/HEAD
//! resolution, and worktree-vs-primary detection inconsistently across
//! `enforce_worktree`, `warn_main_branch`, `warn_subagent_worktree`, and the
//! branch-resolver inlines — the root gap behind a string of false-positive
//! incidents (cadence-hooks#164). [`GitState`] is the single source of those
//! facts, built on the existing pure primitives in [`crate::paths`]
//! ([`find_git_root`](crate::paths::find_git_root),
//! [`resolve_git_common_dir`](crate::paths::resolve_git_common_dir)).
//!
//! **Facts, not policy.** [`GitState`] exposes `repo_root`, `git_common_dir`,
//! `branch`, `worktree_kind`, and `default_branch` — and deliberately **no**
//! `is_main`/block/allow verdict. Each guard keeps its own policy *and* its own
//! fail-direction over these facts, so the shared resolver can never drift one
//! guard's decision into another's — critically, it cannot loosen
//! `enforce_worktree`'s BLOCK direction (cadence-hooks#164).
//!
//! **Pure filesystem, no `git` spawn.** Resolution is a filesystem walk plus a
//! few small reads of `HEAD`-family files, so it is cheap and testable without a
//! subprocess — the same discipline `resolve_git_common_dir` already keeps.

use crate::paths::{find_git_root, read_gitdir_file, resolve_git_common_dir};
use std::path::{Path, PathBuf};

/// Whether a checkout is the repository's **primary** checkout or a **linked**
/// worktree — decided by whether its `.git` is a directory (primary) or a file
/// pointing into the primary's `.git/worktrees/` (linked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeKind {
    /// The primary checkout — `.git` is a directory.
    Primary,
    /// A linked worktree — `.git` is a file.
    Linked,
}

/// Resolved git facts for a starting path. Constructed by [`GitState::resolve`];
/// carries no policy — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitState {
    /// The enclosing checkout root — the nearest ancestor with a `.git` entry.
    pub repo_root: PathBuf,
    /// The shared `.git` common dir — one per repository across the primary
    /// checkout and every linked worktree (holds `refs`, `objects`).
    pub git_common_dir: PathBuf,
    /// The checked-out branch of *this* checkout, or `None` for a detached HEAD.
    pub branch: Option<String>,
    /// Primary checkout vs linked worktree.
    pub worktree_kind: WorktreeKind,
    /// The repository's default branch, from `refs/remotes/origin/HEAD`, or
    /// `None` when there is no `origin` remote (or it is unreadable).
    pub default_branch: Option<String>,
}

impl GitState {
    /// Resolve the git facts enclosing `start`, or `None` when `start` is not
    /// inside a git repository (or the `.git` is not a real git dir — a `HEAD`
    /// is required, matching [`resolve_git_common_dir`]).
    pub fn resolve(start: &Path) -> Option<GitState> {
        let repo_root = find_git_root(&start.to_string_lossy())?;
        let (worktree_kind, git_dir) = worktree_git_dir(&repo_root)?;
        let git_common_dir = resolve_git_common_dir(&repo_root)?;
        let branch = head_branch(&git_dir);
        let default_branch = default_branch_from(&git_common_dir);
        Some(GitState {
            repo_root,
            git_common_dir,
            branch,
            worktree_kind,
            default_branch,
        })
    }

    /// True for the primary checkout (`.git` is a directory).
    pub fn is_primary(&self) -> bool {
        self.worktree_kind == WorktreeKind::Primary
    }

    /// True for a linked worktree (`.git` is a file).
    pub fn is_linked(&self) -> bool {
        self.worktree_kind == WorktreeKind::Linked
    }
}

/// The worktree's own git admin directory — where *this* checkout's `HEAD`
/// lives — plus whether it is primary or linked. For a primary checkout this is
/// `<repo_root>/.git`; for a linked worktree it is the admin dir the `.git`
/// *file* points at (`…/.git/worktrees/<name>`), which is NOT the shared common
/// dir. `None` when `.git` is neither a dir nor a parseable file.
fn worktree_git_dir(repo_root: &Path) -> Option<(WorktreeKind, PathBuf)> {
    let dot_git = repo_root.join(".git");
    if dot_git.is_dir() {
        Some((WorktreeKind::Primary, dot_git))
    } else if dot_git.is_file() {
        read_gitdir_file(&dot_git, repo_root).map(|d| (WorktreeKind::Linked, d))
    } else {
        None
    }
}

/// Parse `<git_dir>/HEAD` into the branch name, or `None` for a detached HEAD
/// (a raw object id) or an unreadable file. `git_dir` is the *worktree's own*
/// admin dir, so a linked worktree reports its own branch, not the primary's.
fn head_branch(git_dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    head.trim()
        .strip_prefix("ref: refs/heads/")
        .map(str::to_string)
}

/// Read the repository's default branch from
/// `<common_dir>/refs/remotes/origin/HEAD` (`ref: refs/remotes/origin/<branch>`),
/// or `None` when there is no `origin` remote / the symref is unreadable.
fn default_branch_from(common_dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(common_dir.join("refs/remotes/origin/HEAD")).ok()?;
    head.trim()
        .strip_prefix("ref: refs/remotes/origin/")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A primary checkout on `branch` with an optional `origin/HEAD` default.
    fn init_primary(dir: &Path, branch: &str, default: Option<&str>) {
        let git = dir.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), format!("ref: refs/heads/{branch}\n")).unwrap();
        if let Some(def) = default {
            let remotes = git.join("refs").join("remotes").join("origin");
            std::fs::create_dir_all(&remotes).unwrap();
            std::fs::write(
                remotes.join("HEAD"),
                format!("ref: refs/remotes/origin/{def}\n"),
            )
            .unwrap();
        }
    }

    #[test]
    fn resolves_primary_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        init_primary(tmp.path(), "feat/x", Some("main"));
        let state = GitState::resolve(tmp.path()).expect("resolves");
        assert_eq!(state.repo_root, tmp.path());
        assert_eq!(state.git_common_dir, tmp.path().join(".git"));
        assert_eq!(state.branch.as_deref(), Some("feat/x"));
        assert_eq!(state.worktree_kind, WorktreeKind::Primary);
        assert!(state.is_primary());
        assert!(!state.is_linked());
        assert_eq!(state.default_branch.as_deref(), Some("main"));
    }

    #[test]
    fn resolves_from_a_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        init_primary(tmp.path(), "main", None);
        let sub = tmp.path().join("crates").join("core");
        std::fs::create_dir_all(&sub).unwrap();
        let state = GitState::resolve(&sub).expect("walks up to the repo root");
        assert_eq!(state.repo_root, tmp.path());
        assert_eq!(state.branch.as_deref(), Some("main"));
        assert_eq!(state.default_branch, None, "no origin/HEAD → no default");
    }

    #[test]
    fn detached_head_has_no_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(
            git.join("HEAD"),
            "0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        let state = GitState::resolve(tmp.path()).expect("resolves");
        assert_eq!(state.branch, None);
        assert_eq!(state.worktree_kind, WorktreeKind::Primary);
    }

    #[test]
    fn resolves_linked_worktree_branch_and_kind() {
        // A linked worktree: `.git` is a FILE pointing at the primary's admin
        // dir, which holds this worktree's own HEAD. The branch must come from
        // there, not the primary's HEAD, and the kind must be Linked.
        let tmp = tempfile::tempdir().unwrap();
        let primary_git = tmp.path().join("primary").join(".git");
        std::fs::create_dir_all(&primary_git).unwrap();
        std::fs::write(primary_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let admin = primary_git.join("worktrees").join("wt");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(admin.join("commondir"), "../..\n").unwrap();
        std::fs::write(admin.join("HEAD"), "ref: refs/heads/feat/y\n").unwrap();

        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(
            linked.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .unwrap();

        let state = GitState::resolve(&linked).expect("resolves linked worktree");
        assert_eq!(state.worktree_kind, WorktreeKind::Linked);
        assert!(state.is_linked());
        assert_eq!(
            state.branch.as_deref(),
            Some("feat/y"),
            "linked worktree reports its own branch, not the primary's"
        );
        // The common dir resolves back to the primary's .git (holds the HEAD).
        assert!(state.git_common_dir.join("HEAD").exists());
    }

    #[test]
    fn non_repo_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(GitState::resolve(tmp.path()), None);
    }

    #[test]
    fn git_dir_without_head_is_none() {
        // A `.git` dir lacking HEAD is not a real git dir (matches
        // resolve_git_common_dir's guard).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        assert_eq!(GitState::resolve(tmp.path()), None);
    }
}
