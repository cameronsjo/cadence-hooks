//! One resolution of "which repo does this target actually live in?"
//! (cameronsjo/cadence-hooks#225).
//!
//! Guards used to judge the repo enclosing the hook payload's `cwd`, but the
//! repo a mutation lands in is often a different one: the steady state of a
//! **meta-repo** session, where `cwd` is an outer git repo whose `.gitignore`
//! hides nested source repos (`cadence-ecosystem/cadence/`,
//! `cadence-ecosystem/cadence-hooks/`, …) and the work happens inside them.
//! This module is the shared answer: given the command's working dir and a
//! file/dir target, resolve the **effective repo** — the innermost git repo
//! containing the target, not the cwd's — and say how it relates to the cwd's
//! repo ([`RepoRelation`]).
//!
//! Innermost falls out of walking up from the target and taking the first
//! `.git`; a gitignored nested repo is found the same as a tracked one because
//! the walk never consults the parent's ignore rules. [`nested_is_gitignored`]
//! reports the meta-repo shape explicitly for callers that want to name it.
//!
//! **Facts, not policy, and fail closed.** [`Resolution`] separates "no repo
//! here" ([`Resolution::NotARepo`]) from "cannot say"
//! ([`Resolution::Ambiguous`]). A guard whose verdict *relaxes* on the repo
//! (an exemption) must treat both non-`Resolved` outcomes as "not exempt"; a
//! guard that only nudges may fail open on them. Ambiguity is reported for:
//! empty/NUL targets, a `..` the filesystem cannot resolve (the lexical and
//! physical readings differ), paths past `PATH_MAX`, git's discovery being
//! redirected by environment (`GIT_DIR`, …), and a `.git` on the walk that
//! [`GitState`] refuses (unreadable or forged layout).
//!
//! **Bounded cost.** A resolution is one `canonicalize` plus a walk-up of stats
//! and the small `HEAD` reads [`GitState::resolve`] already does — no `git`
//! spawn. [`RepoResolver`] memoizes per start directory, so many targets in one
//! command cost one resolution per distinct directory.

use crate::gitstate::GitState;
use crate::paths::find_git_root;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// Longest path the OS can resolve (Linux `PATH_MAX`); past it every stat
/// fails, so the target is ambiguous rather than walked.
const MAX_TARGET_PATH_LEN: usize = 4096;

/// Env vars that redirect git's own repo discovery, so a filesystem walk may
/// disagree with what `git` would answer.
const DISCOVERY_ENV: [&str; 4] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

/// What a target path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A file (possibly not yet created): the repo is the one enclosing it.
    File,
    /// An existing directory (a package-manager verb's cwd, a `cd` target). A
    /// directory that does not exist is [`Ambiguity::MissingDir`]: a shell
    /// never gets there, so the enclosing repo is not the command's repo.
    Dir,
}

/// How the effective repo relates to the repo enclosing the cwd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoRelation {
    /// Same checkout root.
    SameCheckout,
    /// Same repository (shared common dir), a different worktree.
    SameRepoOtherWorktree,
    /// The target's repo sits inside the cwd repo's tree — the meta-repo
    /// shape (a gitignored or untracked nested repo, or a submodule).
    Nested,
    /// The cwd's repo sits inside the target's repo (a session opened in a
    /// nested repo, editing the outer one).
    Enclosing,
    /// Unrelated repositories.
    Foreign,
    /// The cwd is not inside any (readable) repo.
    CwdNotARepo,
}

/// A resolved effective repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRepo {
    /// The repo enclosing the target.
    pub state: GitState,
    /// The repo enclosing the cwd, when there is one.
    pub cwd_state: Option<GitState>,
    /// How the two relate.
    pub relation: RepoRelation,
}

impl EffectiveRepo {
    /// True when the target's repo is not the cwd's own checkout — the case a
    /// message should say so instead of naming the cwd repo.
    pub fn differs_from_cwd_repo(&self) -> bool {
        self.relation != RepoRelation::SameCheckout
    }
}

/// Why a target could not be attributed to one repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambiguity {
    /// Empty target or a NUL byte.
    BadTarget,
    /// A [`TargetKind::Dir`] target that does not exist.
    MissingDir,
    /// A `..` in a path the filesystem cannot resolve.
    UnresolvableParentDir,
    /// Longer than the OS can resolve.
    TooLong,
    /// Git's discovery is redirected by environment.
    DiscoveryRedirected,
    /// A `.git` on the walk exists but is not a readable git dir.
    UnreadableRepo,
}

/// The outcome of resolving a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The innermost repo containing the target.
    Resolved(Box<EffectiveRepo>),
    /// Definitely no repo encloses the target.
    NotARepo,
    /// Cannot say — fail closed where the verdict relaxes on the repo.
    Ambiguous(Ambiguity),
}

impl Resolution {
    /// The resolved repo, or `None` for both [`Resolution::NotARepo`] and
    /// [`Resolution::Ambiguous`]. The right reading for a guard that relaxes
    /// only on an affirmative answer.
    pub fn resolved(&self) -> Option<&EffectiveRepo> {
        match self {
            Resolution::Resolved(r) => Some(r.as_ref()),
            _ => None,
        }
    }
}

/// Memoizing resolver — one per hook invocation.
#[derive(Debug, Default)]
pub struct RepoResolver {
    cache: HashMap<PathBuf, Option<GitState>>,
    redirected: Option<bool>,
}

impl RepoResolver {
    /// A fresh resolver with an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve the effective repo for `target` (relative targets join `cwd`).
    pub fn resolve(&mut self, cwd: &Path, target: &Path, kind: TargetKind) -> Resolution {
        let redirected = *self
            .redirected
            .get_or_insert_with(|| DISCOVERY_ENV.iter().any(|v| std::env::var_os(v).is_some()));
        self.resolve_inner(cwd, target, kind, redirected)
    }

    /// [`RepoResolver::resolve`] with the discovery-redirect verdict injected,
    /// so tests need no process-env mutation.
    fn resolve_inner(
        &mut self,
        cwd: &Path,
        target: &Path,
        kind: TargetKind,
        redirected: bool,
    ) -> Resolution {
        if redirected {
            return Resolution::Ambiguous(Ambiguity::DiscoveryRedirected);
        }
        let start = match start_dir(cwd, target, kind) {
            Ok(dir) => dir,
            Err(why) => return Resolution::Ambiguous(why),
        };
        let Some(state) = self.state(&start) else {
            // `GitState` refuses a malformed `.git` and reads it as absent;
            // a `.git` anywhere on the walk means "cannot say", not "no repo".
            return if find_git_root(&start.to_string_lossy()).is_some() {
                Resolution::Ambiguous(Ambiguity::UnreadableRepo)
            } else {
                Resolution::NotARepo
            };
        };
        let cwd_state = self.state(cwd);
        let relation = relate(&state, cwd_state.as_ref());
        Resolution::Resolved(Box::new(EffectiveRepo {
            state,
            cwd_state,
            relation,
        }))
    }

    fn state(&mut self, dir: &Path) -> Option<GitState> {
        self.cache
            .entry(dir.to_path_buf())
            .or_insert_with(|| GitState::resolve(dir))
            .clone()
    }
}

/// One-shot [`RepoResolver::resolve`] for a single target.
pub fn resolve_effective_repo(cwd: &Path, target: &Path, kind: TargetKind) -> Resolution {
    RepoResolver::new().resolve(cwd, target, kind)
}

/// The directory whose repo a Bash `command` operates in: `cwd` after the
/// command's leading `cd` chain ([`crate::shell::parse_work_dir`]), resolved
/// to the innermost repo root — so `cd <nested> && git …` from a meta-repo
/// session is judged against the nested repo, not the meta-repo.
///
/// - No `cd` in effect: `cwd` itself, unchanged (the long-standing reading).
/// - A `cd` into the session's own repo, or into a repo nested INSIDE its
///   tree (the gitignored nested repo of a meta-repo, a worktree kept under
///   the checkout): that repo's root.
/// - Anything else is `None`:
///   - a `cd` that does not run unconditionally — the chain must be the
///     command's leading segments, each a bare `cd` joined by `&&` or `;`
///     (`false && cd x`, `cd x || exit`, `git status; cd x` all fail this),
///     since [`crate::shell::parse_work_dir`] assumes every `cd` runs;
///   - a target outside the session repo's tree (an unrelated checkout, an
///     enclosing repo, a sibling worktree), or a session cwd in no repo;
///   - a target that is no repo, does not exist, or cannot be read
///     ([`Resolution::NotARepo`] / [`Resolution::Ambiguous`]).
///
/// **Why so narrow.** Callers run `git` in the returned directory before the
/// user approves the command, and a repo's own config can name programs git
/// executes (`core.fsmonitor`, filter drivers). The session's own tree is the
/// only one a hook may treat that way; a command's text must never be able to
/// point a hook at an arbitrary repo on disk.
///
/// `None` means "cannot name the repo this command runs in". Only a guard that
/// nudges may read it as quiet; a guard whose verdict relaxes on the repo must
/// read it as "not exempt".
pub fn command_repo_dir(command: &str, cwd: &str) -> Option<String> {
    let work = crate::shell::parse_work_dir(command, cwd);
    if work == cwd {
        return Some(cwd.to_string());
    }
    if !leading_cd_chain_is_unconditional(command) {
        return None;
    }
    let resolution = resolve_effective_repo(Path::new(cwd), Path::new(&work), TargetKind::Dir);
    let repo = resolution.resolved()?;
    let session_root = std::fs::canonicalize(&repo.cwd_state.as_ref()?.repo_root).ok()?;
    let target_root = std::fs::canonicalize(&repo.state.repo_root).ok()?;
    target_root
        .starts_with(&session_root)
        .then(|| target_root.to_string_lossy().into_owned())
}

/// True when every `cd` segment of `command` is part of an unconditional
/// leading chain: the segments up to and including the last `cd` are all bare
/// `cd` commands, each followed by `&&` or `;`. A `cd` behind a guard
/// (`false && cd x`), before `||`, in a pipeline, or after any other command
/// fails — the caller cannot be sure the shell ends up there. So does a
/// newline between `cd`s, which [`crate::shell::parse_work_dir`] does not
/// follow: the directory it reports would not be where the shell ends up.
fn leading_cd_chain_is_unconditional(command: &str) -> bool {
    let segments = crate::shell::split_segments_with_ops(command);
    let is_cd = |segment: &str| {
        crate::shell::tokenize(segment)
            .first()
            .is_some_and(|word| word == "cd")
    };
    let Some(last_cd) = segments.iter().rposition(|(segment, _)| is_cd(segment)) else {
        return false;
    };
    segments[..=last_cd]
        .iter()
        .all(|(segment, op)| is_cd(segment) && matches!(op, Some("&&" | ";")))
}

fn relate(target: &GitState, cwd: Option<&GitState>) -> RepoRelation {
    let Some(cwd) = cwd else {
        return RepoRelation::CwdNotARepo;
    };
    if target.repo_root == cwd.repo_root {
        RepoRelation::SameCheckout
    } else if target.git_common_dir == cwd.git_common_dir {
        RepoRelation::SameRepoOtherWorktree
    } else if target.repo_root.starts_with(&cwd.repo_root) {
        RepoRelation::Nested
    } else if cwd.repo_root.starts_with(&target.repo_root) {
        RepoRelation::Enclosing
    } else {
        RepoRelation::Foreign
    }
}

/// The directory to start the repo walk from.
///
/// An existing target is canonicalized whole, so a symlinked final component
/// lands where the write would (the link's destination repo, not the link's
/// directory). A missing target ascends lexically to its nearest existing
/// directory — but only when it carries no `..`, since lexical and physical
/// parents disagree there.
fn start_dir(cwd: &Path, target: &Path, kind: TargetKind) -> Result<PathBuf, Ambiguity> {
    let raw = target.as_os_str();
    if raw.is_empty() || raw.to_string_lossy().contains('\0') {
        return Err(Ambiguity::BadTarget);
    }
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    };
    if joined.as_os_str().len() > MAX_TARGET_PATH_LEN {
        return Err(Ambiguity::TooLong);
    }
    if let Ok(canonical) = std::fs::canonicalize(&joined) {
        return Ok(match kind {
            TargetKind::Dir if canonical.is_dir() => canonical,
            _ => canonical
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or(canonical),
        });
    }
    if kind == TargetKind::Dir {
        return Err(Ambiguity::MissingDir);
    }
    // Missing file target: physically resolve the longest existing prefix (so a
    // `..` inside it is settled by the filesystem), then ascend lexically
    // through the missing tail. A `..` in the missing tail has no physical
    // reading, so the answer is "cannot say".
    let mut prefix = PathBuf::new();
    let mut missing: Vec<Component> = Vec::new();
    for comp in joined.components() {
        if missing.is_empty() {
            let next = prefix.join(comp);
            if std::fs::symlink_metadata(&next).is_ok() {
                prefix = next;
                continue;
            }
        }
        missing.push(comp);
    }
    if missing.iter().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Ambiguity::UnresolvableParentDir);
    }
    let base = std::fs::canonicalize(&prefix).map_err(|_| Ambiguity::UnresolvableParentDir)?;
    // The last missing component is the file's own name.
    let mut dir = base;
    if !dir.is_dir() {
        dir = dir.parent().map(Path::to_path_buf).unwrap_or(dir);
    }
    Ok(dir)
}

/// True only when the cwd repo **affirmatively** ignores the nested repo's
/// root (`git check-ignore`) — the gitignored meta-repo shape. Any doubt
/// (not nested, git failure, timeout) is `false`. One bounded `git` spawn, so
/// call it for naming the shape in a message, never on a hot path or as an
/// input to a relaxing verdict.
pub fn nested_is_gitignored(repo: &EffectiveRepo) -> bool {
    use crate::shell::{GitOutput, git_output_detailed};
    if repo.relation != RepoRelation::Nested {
        return false;
    }
    let Some(cwd_state) = &repo.cwd_state else {
        return false;
    };
    let Ok(rel) = repo.state.repo_root.strip_prefix(&cwd_state.repo_root) else {
        return false;
    };
    let rel = rel.to_string_lossy().into_owned();
    matches!(
        git_output_detailed(
            &cwd_state.repo_root.to_string_lossy(),
            &["check-ignore", "--", &rel]
        ),
        GitOutput::Ok(out) if !out.is_empty()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixtures::{Scratch, git_in, init_repo};

    fn scratch(tag: &str) -> Scratch {
        Scratch::outside_checkout(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-target-repo-scratch"),
            tag,
        )
    }

    /// The canonical meta-repo: `meta/` is a repo whose `.gitignore` hides
    /// `plugin/`, itself an independent repo. Returns (scratch, meta, plugin).
    fn meta_layout(tag: &str) -> (Scratch, PathBuf, PathBuf) {
        let s = scratch(tag);
        let meta = s.path().join("meta");
        let plugin = meta.join("plugin");
        std::fs::create_dir_all(&plugin).unwrap();
        init_repo(&meta);
        std::fs::write(meta.join(".gitignore"), "plugin/\n").unwrap();
        git_in(&meta, &["add", ".gitignore"]);
        git_in(&meta, &["commit", "-q", "-m", "ignore"]);
        init_repo(&plugin);
        std::fs::create_dir_all(plugin.join("src")).unwrap();
        (s, meta, plugin)
    }

    fn resolved(r: Resolution) -> EffectiveRepo {
        match r {
            Resolution::Resolved(e) => *e,
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    fn canon(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap()
    }

    #[test]
    fn file_in_gitignored_nested_repo_resolves_to_the_nested_repo() {
        let (_s, meta, plugin) = meta_layout("nested-file");
        let target = plugin.join("src/lib.rs");
        std::fs::write(&target, "x").unwrap();
        let e = resolved(resolve_effective_repo(&meta, &target, TargetKind::File));
        assert_eq!(e.state.repo_root, canon(&plugin));
        assert_eq!(e.cwd_state.as_ref().unwrap().repo_root, canon(&meta));
        assert_eq!(e.relation, RepoRelation::Nested);
        assert!(e.differs_from_cwd_repo());
        assert!(nested_is_gitignored(&e));
    }

    #[test]
    fn table_of_targets_from_the_meta_repo_cwd() {
        let (_s, meta, plugin) = meta_layout("table");
        std::fs::write(meta.join("README.md"), "x").unwrap();
        let cases: Vec<(&str, PathBuf, TargetKind, PathBuf, RepoRelation)> = vec![
            (
                "meta file",
                meta.join("README.md"),
                TargetKind::File,
                meta.clone(),
                RepoRelation::SameCheckout,
            ),
            (
                "relative nested file (not yet created)",
                PathBuf::from("plugin/src/new.rs"),
                TargetKind::File,
                plugin.clone(),
                RepoRelation::Nested,
            ),
            (
                "nested file in a not-yet-created subtree",
                plugin.join("src/deep/er/new.rs"),
                TargetKind::File,
                plugin.clone(),
                RepoRelation::Nested,
            ),
            (
                "nested dir target",
                plugin.join("src"),
                TargetKind::Dir,
                plugin.clone(),
                RepoRelation::Nested,
            ),
            (
                "nested repo root as a dir target",
                plugin.clone(),
                TargetKind::Dir,
                plugin.clone(),
                RepoRelation::Nested,
            ),
            (
                "the `.git`-less sibling dir of meta is meta's",
                PathBuf::from("docs/new.md"),
                TargetKind::File,
                meta.clone(),
                RepoRelation::SameCheckout,
            ),
            (
                "resolvable parent-dir hop into the nested repo",
                PathBuf::from("plugin/src/../src/x.rs"),
                TargetKind::File,
                plugin.clone(),
                RepoRelation::Nested,
            ),
        ];
        for (label, target, kind, want_root, want_rel) in cases {
            let e = resolved(resolve_effective_repo(&meta, &target, kind));
            assert_eq!(e.state.repo_root, canon(&want_root), "{label}");
            assert_eq!(e.relation, want_rel, "{label}");
        }
    }

    #[test]
    fn nested_cwd_editing_the_outer_repo_is_enclosing() {
        let (_s, meta, plugin) = meta_layout("enclosing");
        let e = resolved(resolve_effective_repo(
            &plugin,
            &meta.join("README.md"),
            TargetKind::File,
        ));
        assert_eq!(e.state.repo_root, canon(&meta));
        assert_eq!(e.relation, RepoRelation::Enclosing);
        assert!(!nested_is_gitignored(&e), "only Nested can be ignored");
    }

    #[test]
    fn linked_worktree_of_the_cwd_repo_is_same_repo_other_worktree() {
        let s = scratch("linked");
        let main = s.path().join("main");
        std::fs::create_dir_all(&main).unwrap();
        init_repo(&main);
        let wt = s.path().join("wt");
        git_in(
            &main,
            &["worktree", "add", "-q", "-b", "b", &wt.to_string_lossy()],
        );
        let e = resolved(resolve_effective_repo(
            &main,
            &wt.join("f.txt"),
            TargetKind::File,
        ));
        assert_eq!(e.relation, RepoRelation::SameRepoOtherWorktree);
        assert_eq!(e.state.repo_root, canon(&wt));
    }

    #[test]
    fn unrelated_repo_is_foreign_and_a_non_repo_cwd_is_named() {
        let s = scratch("foreign");
        let a = s.path().join("a");
        let b = s.path().join("b");
        let plain = s.path().join("plain");
        for d in [&a, &b, &plain] {
            std::fs::create_dir_all(d).unwrap();
        }
        init_repo(&a);
        init_repo(&b);
        let e = resolved(resolve_effective_repo(
            &a,
            &b.join("f.txt"),
            TargetKind::File,
        ));
        assert_eq!(e.relation, RepoRelation::Foreign);
        let e = resolved(resolve_effective_repo(
            &plain,
            &b.join("f.txt"),
            TargetKind::File,
        ));
        assert_eq!(e.relation, RepoRelation::CwdNotARepo);
    }

    #[test]
    fn a_file_outside_every_repo_is_not_a_repo() {
        let s = scratch("none");
        let plain = s.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(
            resolve_effective_repo(&plain, &plain.join("x/y.txt"), TargetKind::File),
            Resolution::NotARepo
        );
    }

    #[test]
    fn ambiguous_inputs_fail_closed_never_fall_back_to_the_cwd_repo() {
        let (_s, meta, plugin) = meta_layout("ambiguous");
        // A `..` in a missing tail: lexically inside the plugin, physically
        // `meta/missing/../x` — the two readings disagree, so no answer.
        let dotdot = plugin.join("missing/../../x.rs");
        assert_eq!(
            resolve_effective_repo(&meta, &dotdot, TargetKind::File),
            Resolution::Ambiguous(Ambiguity::UnresolvableParentDir)
        );
        assert_eq!(
            resolve_effective_repo(&meta, &meta.join("no/such/dir"), TargetKind::Dir),
            Resolution::Ambiguous(Ambiguity::MissingDir)
        );
        assert_eq!(
            resolve_effective_repo(&meta, Path::new(""), TargetKind::File),
            Resolution::Ambiguous(Ambiguity::BadTarget)
        );
        assert_eq!(
            resolve_effective_repo(&meta, Path::new("a\0b"), TargetKind::File),
            Resolution::Ambiguous(Ambiguity::BadTarget)
        );
        let long = meta.join("a/".repeat(3000));
        assert_eq!(
            resolve_effective_repo(&meta, &long, TargetKind::File),
            Resolution::Ambiguous(Ambiguity::TooLong)
        );
        let mut r = RepoResolver::new();
        assert_eq!(
            r.resolve_inner(&meta, &plugin.join("f"), TargetKind::File, true),
            Resolution::Ambiguous(Ambiguity::DiscoveryRedirected)
        );
    }

    #[test]
    fn a_forged_git_file_on_the_walk_is_ambiguous_not_the_outer_repo() {
        let (_s, meta, _plugin) = meta_layout("forged");
        let bad = meta.join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join(".git"), "gitdir: /nonexistent/elsewhere\n").unwrap();
        assert_eq!(
            resolve_effective_repo(&meta, &bad.join("f.rs"), TargetKind::File),
            Resolution::Ambiguous(Ambiguity::UnreadableRepo)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_out_of_the_nested_repo_resolves_where_the_write_lands() {
        let (_s, meta, plugin) = meta_layout("symlink");
        std::fs::write(meta.join("README.md"), "x").unwrap();
        // plugin/src/link -> ../../README.md (a file in the OUTER repo).
        std::os::unix::fs::symlink("../../README.md", plugin.join("src/link")).unwrap();
        let e = resolved(resolve_effective_repo(
            &meta,
            &plugin.join("src/link"),
            TargetKind::File,
        ));
        assert_eq!(
            e.state.repo_root,
            canon(&meta),
            "write lands in the outer repo"
        );
    }

    #[test]
    fn resolver_memoizes_per_start_directory() {
        let (_s, meta, plugin) = meta_layout("cache");
        let mut r = RepoResolver::new();
        for i in 0..50 {
            let t = plugin.join(format!("src/f{i}.rs"));
            resolved(r.resolve(&meta, &t, TargetKind::File));
        }
        // Two distinct start dirs (plugin/src and meta), however many targets.
        assert_eq!(r.cache.len(), 2);
    }

    #[test]
    fn a_pathological_target_stays_fast() {
        let (_s, meta, _plugin) = meta_layout("perf");
        let deep = format!("{}x", "a/".repeat(2000));
        let started = std::time::Instant::now();
        let _ = resolve_effective_repo(&meta, Path::new(&deep), TargetKind::File);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn command_repo_dir_keys_off_the_repo_a_leading_cd_moves_into() {
        let (s, meta, plugin) = meta_layout("command-dir");
        std::fs::create_dir_all(meta.join("plain-dir")).unwrap();
        // An unrelated repo outside the session's tree, and a symlink inside
        // the meta repo that points at it.
        let foreign = s.path().join("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        init_repo(&foreign);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&foreign, meta.join("link-out")).unwrap();
        let m = meta.to_str().unwrap();
        let f = foreign.to_str().unwrap();
        let p = canon(&plugin).to_string_lossy().into_owned();
        let meta_root = canon(&meta).to_string_lossy().into_owned();
        // (label, command, cwd, expected)
        let mut cases: Vec<(&str, String, &str, Option<String>)> = vec![
            (
                "no cd: the cwd, unchanged",
                "git status".into(),
                m,
                Some(m.into()),
            ),
            (
                "meta cwd, cd into the gitignored nested repo",
                "cd plugin && git status".into(),
                m,
                Some(p.clone()),
            ),
            (
                "meta cwd, cd into a subdir of the nested repo",
                format!("cd {}/src && git status", plugin.display()),
                m,
                Some(p.clone()),
            ),
            (
                "multi-cd chain ending in the nested repo",
                "cd plain-dir && cd ../plugin && git status".into(),
                m,
                Some(p.clone()),
            ),
            (
                "a newline-joined cd chain the parser does not follow: quiet",
                "cd plain-dir\ncd ../plugin && git status".into(),
                m,
                None,
            ),
            (
                "a plain dir inside the meta repo: the meta repo",
                "cd plain-dir; git status".into(),
                m,
                Some(meta_root.clone()),
            ),
            (
                "nested cwd, cd out to the enclosing meta repo: outside the session tree",
                format!("cd {m} && git status"),
                &p,
                None,
            ),
            (
                "cd into an unrelated repo",
                format!("cd {f} && git status"),
                m,
                None,
            ),
            (
                "cd into an unrelated repo via ..",
                "cd ../foreign && git status".into(),
                m,
                None,
            ),
            (
                "a cd behind `false &&` may never run",
                "false && cd plugin && git status".into(),
                m,
                None,
            ),
            (
                "a cd before `||`",
                "cd plugin || exit; git status".into(),
                m,
                None,
            ),
            (
                "a cd after another command",
                "git status; cd plugin && git status".into(),
                m,
                None,
            ),
            (
                "a cd in a pipeline",
                "cd plugin | cat; git status".into(),
                m,
                None,
            ),
            (
                "cd into a missing dir: cannot say",
                "cd no-such-dir && git status".into(),
                m,
                None,
            ),
        ];
        #[cfg(unix)]
        cases.push((
            "a symlink inside the meta repo pointing out of it",
            "cd link-out && git status".into(),
            m,
            None,
        ));
        for (label, command, cwd, want) in cases {
            assert_eq!(command_repo_dir(&command, cwd), want, "{label}");
        }
    }
}
