//! Shared worktree-discipline primitives for `guardrails::enforce_worktree`
//! and `session::start`'s posture disclosure (cadence-hooks#236).
//!
//! `enforce_worktree` lives in `crates/guardrails`, `session::start` in
//! `crates/session` — neither depends on the other, but both depend on this
//! crate. The block decision honored here is the composite: **primary
//! checkout, not exempted by env/repo settings, not a temp root, not
//! snoozed**. Extracted so the SessionStart posture line and the actual
//! `enforce-worktree` block can never drift apart into "the line fires but
//! the wall doesn't" (or vice versa) — see [`would_block_here`].
//!
//! `enforce_worktree::assess_dir` does NOT delegate wholesale to
//! [`would_block_here`]: it needs the decomposed booleans (is_primary,
//! snoozed, allowed_main, kill_switch) to attribute *which* exemption
//! bypassed a would-be block, and its `git commit` arm deliberately does NOT
//! apply the `.claude/`/`docs/plans/` carve-out (issue #239 F6/F7 — that
//! carve-out leaking into the commit arm punched a hole in the cross-repo
//! guard). Both call the same primitives below, so the *primitives* — not the
//! composition — are the single source of truth.

use crate::HookInput;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Resolve the directory a git query should target for a hook input.
///
/// For an Edit/Write, returns the parent directory of the edited file, so
/// `git -C <dir>` (or a `GitState::resolve` walk) picks the file's *enclosing*
/// repo even when the session's cwd belongs to an outer parent repo (the
/// nested-repo case). Relative `file_path` values join against `input.cwd` — the
/// hook event's cwd, not the hook process's. For inputs with no file path (Bash),
/// falls back to `input.cwd`, then `.`.
///
/// Shared by `warn-main-branch` and `enforce-worktree` so neither guard borrows
/// the other's copy (cadence-hooks#164).
pub fn git_dir_for_input(input: &HookInput) -> PathBuf {
    let cwd = input
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let Some(file_path) = input.file_path() else {
        return cwd;
    };

    let path = Path::new(&file_path);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    resolved
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or(cwd)
}

/// Pure: classify a truthy env value (`1`/`true`/`yes`, trimmed,
/// case-insensitive). Mirrors `warn_main_branch::is_main_allowed_value` and
/// `warn_subagent_worktree::is_allowed_value`.
pub fn is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Returns true if `repo_root` is a **primary checkout** — classified by
/// resolved git identity, not by the surface form of `.git`. A conventional
/// primary has a `.git` *directory* (the fast path). But a
/// `--separate-git-dir` primary *also* has a `.git` *file* (like a linked
/// worktree does), so the file-vs-dir surface form alone can't tell them apart
/// (cadence-hooks#255): a separate-git-dir primary's `.git` file resolves to a
/// git-dir that IS the shared common dir, whereas a linked worktree's `.git`
/// file resolves to a git-dir under `.git/worktrees/<name>`, distinct from the
/// common dir. So the rule is: **primary iff the canonical git-dir equals the
/// canonical git-common-dir**, resolved the same spawn-free way
/// [`crate::gitstate::GitState::resolve`] does.
///
/// Any resolution failure returns `false` (fail-open per ADR-0001 — a broken
/// `.git` must never *newly* block).
pub fn is_primary_checkout(repo_root: &str) -> bool {
    let root = Path::new(repo_root);
    let dot_git = root.join(".git");
    // Fast path: a real `.git` directory is always a primary checkout.
    if dot_git.is_dir() {
        return true;
    }
    // `.git` is a file (or absent): resolve the worktree admin dir (git-dir),
    // then compare canonical identities against the common dir.
    let Some(git_dir) = crate::paths::read_gitdir_file(&dot_git, root) else {
        return false;
    };
    git_dir_is_common_dir(&git_dir, root)
}

/// True when an already-resolved worktree git-dir **is** the repository's
/// shared common dir — the canonical primary-vs-linked comparison, factored out
/// so [`is_primary_checkout`] and [`crate::gitstate::GitState`] cannot drift
/// apart (cadence-hooks#345). `GitState` classified by the `.git` surface form
/// alone, so a `--separate-git-dir` primary read as Linked there while reading
/// Primary here — one repository, two answers, depending on which guard asked.
///
/// The comparison is the one [`is_primary_checkout`]'s docs describe: a
/// primary's git-dir IS the common dir, a linked worktree's is
/// `…/.git/worktrees/<name>` and is not. Both sides are canonicalized so `..`
/// segments (`resolve_git_common_dir` returns an un-normalized
/// `…/worktrees/<wt>/../..` for a linked worktree) and symlinked prefixes
/// (macOS `/var` vs `/private/var`) cannot make one repository compare unequal
/// to itself.
///
/// Any resolution failure returns `false` — **not** primary. That is the
/// fail-open direction for both callers (ADR-0001): a broken `.git` must never
/// *newly* block `enforce-worktree`, nor *newly* nudge `warn-subagent-worktree`.
///
/// Callers handle the `.git`-is-a-directory fast path themselves, since they
/// already stat it to decide whether there is a git-dir file to read at all.
pub(crate) fn git_dir_is_common_dir(git_dir: &Path, repo_root: &Path) -> bool {
    let Some(common_dir) = crate::paths::resolve_git_common_dir(repo_root) else {
        return false;
    };
    match (
        std::fs::canonicalize(git_dir),
        std::fs::canonicalize(&common_dir),
    ) {
        (Ok(g), Ok(c)) => g == c,
        _ => false,
    }
}

/// Pure-ish: does `path` live under a temp root? `tmpdir` is the `$TMPDIR`
/// value, when set. True for `/tmp`, `/private/tmp`, and `$TMPDIR` (with the
/// canonicalized form too, for macOS's `/var/folders` vs `/private/var`
/// split). The one non-pure step is a `canonicalize` of the `$TMPDIR` value.
///
/// This is the generic predicate behind [`is_temp_root`]; `guardrails::guard_rm`
/// reuses it to classify an `rm` target path (cadence-hooks#261), while
/// `is_temp_root` keeps its repo-root-focused name for the enforce-worktree
/// carve-out.
pub fn path_under_temp_root(path: &Path, tmpdir: Option<&str>) -> bool {
    let fixed = path.starts_with("/tmp") || path.starts_with("/private/tmp");
    let via_env = tmpdir
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "/")
        .is_some_and(|t| {
            // `path` (a repo root from `git rev-parse --show-toplevel`, or a
            // resolved `rm` target) may be canonicalized (`/private/var/…` on
            // macOS) while `$TMPDIR` is not (`/var/folders/…`) — compare
            // against the canonicalized tmpdir too, or the match never fires
            // on macOS.
            path.starts_with(t)
                || std::fs::canonicalize(t)
                    .is_ok_and(|c| c != Path::new("/") && path.starts_with(&c))
        });
    fixed || via_env
}

/// Pure: is `repo_root` inside a temp tree? Scratch/fixture repos live here;
/// enforcing worktree discipline on them would only produce noise. Delegates
/// to [`path_under_temp_root`] — kept as a named alias for the enforce-worktree
/// carve-out's readability.
pub fn is_temp_root(repo_root: &Path, tmpdir: Option<&str>) -> bool {
    path_under_temp_root(repo_root, tmpdir)
}

/// Lexically normalize `dir`'s components — resolving `.` and `..` without
/// touching the filesystem — returning the surviving component `OsString`s
/// (root/prefix dropped; carve-outs match only normal segments).
fn normalized_components(dir: &Path) -> Vec<OsString> {
    let mut out: Vec<OsString> = Vec::new();
    for c in dir.components() {
        match c {
            Component::Normal(s) => out.push(s.to_os_string()),
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Returns true if `dir` lives inside a `.claude/` directory — Claude Code
/// tooling/state, never the branch-worthy product work these guards target.
///
/// Layer B: this lexical `.claude`-anywhere match is a coarse stand-in for "is
/// Claude-managed state", not a precise repo classification. One consequence
/// worth stating plainly — a *primary checkout* that itself lives under a
/// `.claude/` path is intentionally exempt from enforce-worktree. That coarse
/// exemption is exactly why the `#312` `Scratch` fixtures assert their roots
/// stay OUT of `.claude/` (and out of any temp root): a fixture under a
/// carve-out would silently exempt every case and make the block paths
/// untestable.
pub fn is_claude_managed_dir(dir: &Path) -> bool {
    normalized_components(dir)
        .iter()
        .any(|c| c.as_os_str() == ".claude")
}

/// Returns true if `dir` is a cadence plan-document directory
/// (`docs/plans`) — approved plans are copied there on the default branch by
/// design (cadence's plan-execution rule), so authoring one is not the
/// branch-worthy product change these guards target.
pub fn is_plan_doc_dir(dir: &Path) -> bool {
    let comps = normalized_components(dir);
    comps
        .windows(2)
        .any(|w| w[0].as_os_str() == "docs" && w[1].as_os_str() == "plans")
}

/// Marker sub-path (relative to a git common dir) recording an active
/// `dismiss-enforce-worktree` snooze. The common dir already ends in `.git`,
/// so this resolves on disk to `.git/cadence-hooks/enforce-worktree-snoozed-until`.
const SNOOZE_DIR: &str = "cadence-hooks";
const SNOOZE_FILE: &str = "enforce-worktree-snoozed-until";

/// The enforce-worktree snooze marker path within a git common dir.
pub fn enforce_worktree_marker_path(git_common_dir: &Path) -> PathBuf {
    git_common_dir.join(SNOOZE_DIR).join(SNOOZE_FILE)
}

/// Resolve the absolute git common dir for `dir` — shared across every
/// linked worktree of one repo (#179) — via
/// `git rev-parse --path-format=absolute --git-common-dir`. `None` when
/// `dir` isn't inside a git repo, or git is unavailable.
fn git_common_dir(dir: &Path) -> Option<PathBuf> {
    crate::shell::git_command(
        &dir.to_string_lossy(),
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .map(PathBuf::from)
}

/// The enforce-worktree snooze marker path for `dir`, resolving the shared
/// common dir first. `None` when `dir` isn't inside a git repo.
pub fn enforce_worktree_marker_path_for(dir: &Path) -> Option<PathBuf> {
    git_common_dir(dir).map(|c| enforce_worktree_marker_path(&c))
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the enforce-worktree snooze marker for `repo_root` and decide if it
/// is active. Resolves through the shared git common dir, so a snooze
/// written from a linked worktree is honored here at the primary checkout. A
/// missing marker, or a `repo_root` that isn't inside a git repo, yields
/// `false` (fail-open — ADR-0001).
pub fn is_snoozed_now(repo_root: &Path) -> bool {
    match git_common_dir(repo_root) {
        Some(common) => is_snoozed_in_common_dir(&common),
        None => false,
    }
}

/// Snooze check for a caller that has already resolved the git common dir —
/// pure filesystem, no git subprocess. The dismiss writer anchors the marker
/// under the same `--path-format=absolute --git-common-dir` resolution, so a
/// pre-resolved common dir from that command form reads the same marker the
/// writer armed.
pub fn is_snoozed_in_common_dir(git_common_dir: &Path) -> bool {
    let path = enforce_worktree_marker_path(git_common_dir);
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let now = now_epoch();
    matches!(contents.trim().parse::<u64>(), Ok(until) if until > now)
}

/// Pure decision, all environment resolved by the caller. Mirrors
/// `enforce_worktree::should_block` exactly — this IS that function, lifted
/// so both callers use one definition.
pub fn should_block(
    is_primary: bool,
    allowed_main: bool,
    kill_switch: bool,
    temp_root: bool,
    snoozed: bool,
) -> bool {
    is_primary && !allowed_main && !kill_switch && !temp_root && !snoozed
}

/// Resolve the repo root enclosing `dir`, if any.
fn repo_root_for(dir: &Path) -> Option<String> {
    crate::shell::git_command(&dir.to_string_lossy(), &["rev-parse", "--show-toplevel"])
}

/// Would `enforce-worktree` block a mutation landing directly in `dir`?
/// The composite predicate — primary checkout, not exempted by
/// `CADENCE_ALLOW_MAIN` (env or repo-declared), not the kill switch, not a
/// temp root, not snoozed — honoring the same `.claude/`/`docs/plans/`
/// early-out the Edit/Write arm applies to its target file's directory.
///
/// This mirrors the Edit/Write arm's decision for a hypothetical edit
/// *directly in* `dir` (same repo, no cross-repo `-C`/`cd` redirect to
/// consider) — the exact question a SessionStart posture line answers
/// ("will my first Edit/Write here be blocked?"). It deliberately does
/// **not** cover the `git commit` arm's broader cross-repo-target scope,
/// which has no cwd-only analog.
pub fn would_block_here(dir: &Path) -> bool {
    if is_claude_managed_dir(dir) || is_plan_doc_dir(dir) {
        return false;
    }
    let Some(repo_root) = repo_root_for(dir) else {
        return false;
    };
    let repo_root_path = Path::new(&repo_root);
    let is_primary = is_primary_checkout(&repo_root);
    let temp_root = is_temp_root(repo_root_path, std::env::var("TMPDIR").ok().as_deref());
    let snoozed = is_snoozed_now(repo_root_path);
    let allow_main_env = is_truthy(std::env::var("CADENCE_ALLOW_MAIN").ok().as_deref());
    let repo_declared = is_primary
        && !allow_main_env
        && is_truthy(crate::config::repo_env_flag(repo_root_path, "CADENCE_ALLOW_MAIN").as_deref());
    let allowed_main = allow_main_env || repo_declared;
    let kill_switch = is_truthy(std::env::var("CADENCE_NO_ENFORCE_WORKTREE").ok().as_deref());
    should_block(is_primary, allowed_main, kill_switch, temp_root, snoozed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_truthy ---

    #[test]
    fn truthy_values() {
        assert!(is_truthy(Some("1")));
        assert!(is_truthy(Some("true")));
        assert!(is_truthy(Some("YES")));
        assert!(is_truthy(Some("  true  ")));
    }

    #[test]
    fn falsy_values() {
        assert!(!is_truthy(None));
        assert!(!is_truthy(Some("")));
        assert!(!is_truthy(Some("0")));
        assert!(!is_truthy(Some("false")));
    }

    // --- is_primary_checkout ---

    #[test]
    fn primary_checkout_when_git_is_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        assert!(is_primary_checkout(dir.path().to_str().unwrap()));
    }

    #[test]
    fn not_primary_checkout_when_git_is_file() {
        // A real linked worktree: its `.git` file resolves to a git-dir under
        // `.git/worktrees/<name>`, distinct from the shared common dir — so the
        // resolved-identity check classifies it as NOT primary.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("repo");
        std::fs::create_dir_all(&primary).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let ok = std::process::Command::new("git")
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
        git(&primary, &["config", "user.email", "t@t"]);
        git(&primary, &["config", "user.name", "t"]);
        git(&primary, &["commit", "-q", "--allow-empty", "-m", "init"]);
        let wt = tmp.path().join("wt");
        git(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                &wt.to_string_lossy(),
                "-b",
                "feat/x",
            ],
        );
        assert!(!is_primary_checkout(wt.to_str().unwrap()));
        // Control: the primary checkout itself IS primary (`.git` is a dir).
        assert!(is_primary_checkout(primary.to_str().unwrap()));
    }

    #[test]
    fn separate_git_dir_primary_is_primary() {
        // `git init --separate-git-dir` produces a `.git` *file* on a genuine
        // primary checkout — its git-dir equals the common dir, so it must be
        // classified primary despite the file surface form (cadence-hooks#255).
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let gitdir = tmp.path().join("gitdir");
        std::fs::create_dir_all(&work).unwrap();
        let ok = std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(format!("--separate-git-dir={}", gitdir.display()))
            .arg(&work)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git init --separate-git-dir failed");
        assert!(work.join(".git").is_file(), "sanity: .git is a file");
        assert!(is_primary_checkout(work.to_str().unwrap()));
    }

    #[test]
    fn separate_git_dir_resolution_failure_fails_open() {
        // A dangling gitdir pointer (target does not exist) resolves to no real
        // git dir — fail open to NOT primary rather than newly blocking.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".git"),
            "gitdir: /nonexistent/dangling.git\n",
        )
        .unwrap();
        assert!(!is_primary_checkout(dir.path().to_str().unwrap()));
    }

    #[test]
    fn not_primary_checkout_when_git_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_primary_checkout(dir.path().to_str().unwrap()));
    }

    // --- is_temp_root ---

    #[test]
    fn tmp_roots_are_temp() {
        assert!(is_temp_root(Path::new("/tmp/scratch-repo"), None));
        assert!(is_temp_root(Path::new("/private/tmp/fixture"), None));
    }

    #[test]
    fn home_repo_is_not_temp() {
        assert!(!is_temp_root(Path::new("/Users/dev/Projects/repo"), None));
    }

    // --- is_claude_managed_dir / is_plan_doc_dir ---

    #[test]
    fn claude_worktree_dir_is_managed() {
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/.claude/worktrees/feat-foo"
        )));
    }

    #[test]
    fn plain_repo_dir_is_not_managed() {
        assert!(!is_claude_managed_dir(Path::new("/Users/x/repo/src")));
    }

    #[test]
    fn docs_plans_dir_is_plan_doc() {
        assert!(is_plan_doc_dir(Path::new("/Users/x/repo/docs/plans")));
    }

    #[test]
    fn plain_repo_dir_is_not_plan_doc() {
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/src")));
    }

    // --- should_block (pure decision) ---

    #[test]
    fn primary_branch_mode_blocks() {
        assert!(should_block(true, false, false, false, false));
    }

    #[test]
    fn worktree_allows() {
        assert!(!should_block(false, false, false, false, false));
    }

    #[test]
    fn allow_main_repo_allows() {
        assert!(!should_block(true, true, false, false, false));
    }

    #[test]
    fn kill_switch_allows() {
        assert!(!should_block(true, false, true, false, false));
    }

    #[test]
    fn temp_root_allows() {
        assert!(!should_block(true, false, false, true, false));
    }

    #[test]
    fn snoozed_allows() {
        assert!(!should_block(true, false, false, false, true));
    }

    // --- is_snoozed_now ---

    fn init_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let ok = std::process::Command::new("git")
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
    fn unreadable_marker_is_not_snoozed() {
        let tmp = init_repo();
        assert!(!is_snoozed_now(tmp.path()));
    }

    #[test]
    fn non_repo_dir_is_not_snoozed() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_snoozed_now(tmp.path()));
    }

    #[test]
    fn future_marker_is_snoozed() {
        let tmp = init_repo();
        let repo = tmp.path();
        let path = enforce_worktree_marker_path_for(repo).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{}\n", now_epoch() + 3600)).unwrap();
        assert!(is_snoozed_now(repo));
    }

    #[test]
    fn expired_marker_is_not_snoozed() {
        let tmp = init_repo();
        let repo = tmp.path();
        let path = enforce_worktree_marker_path_for(repo).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "100\n").unwrap();
        assert!(!is_snoozed_now(repo));
    }

    // --- would_block_here ---
    //
    // A tempdir-based fixture would trip `is_temp_root`'s own exemption and
    // false-allow every case (the documented Scratch/E2E gotcha) — these
    // fixtures live under `target/`, a non-temp root, mirroring
    // `enforce_worktree`'s own `Scratch` test helper.

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/core-worktree-scratch")
                .join(format!("{tag}-{}", std::process::id()));
            // #312: a `.claude/` component or a temp prefix on the fixture root
            // would silently exempt every case (the guard's own carve-outs) and
            // make the block paths pass vacuously. Fail loudly instead.
            assert!(
                !is_claude_managed_dir(&root)
                    && !path_under_temp_root(&root, std::env::var("TMPDIR").ok().as_deref()),
                "fixture root sits under a carve-out (.claude/ or temp) — run the suite \
                 from a carve-out-free checkout: {}",
                root.display()
            );
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn init_repo_with_commit(dir: &Path) {
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "init"]);
    }

    // `would_block_here` reads real process env (`CADENCE_ALLOW_MAIN`,
    // `CADENCE_NO_ENFORCE_WORKTREE`), which a caller's own environment may
    // already set (e.g. a session-wide `CADENCE_ALLOW_MAIN=true`) — clear
    // both for the one test that asserts a block actually fires, serialized
    // against any other env-mutating test in this module.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn primary_checkout_would_block() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let scratch = Scratch::new("would-block");
        init_repo_with_commit(&scratch.0);
        // SAFETY: serialized via ENV_LOCK; no other test in this module reads
        // these vars concurrently.
        let prev_allow = std::env::var("CADENCE_ALLOW_MAIN").ok();
        let prev_kill = std::env::var("CADENCE_NO_ENFORCE_WORKTREE").ok();
        unsafe {
            std::env::remove_var("CADENCE_ALLOW_MAIN");
            std::env::remove_var("CADENCE_NO_ENFORCE_WORKTREE");
        }
        let result = would_block_here(&scratch.0);
        unsafe {
            match prev_allow {
                Some(v) => std::env::set_var("CADENCE_ALLOW_MAIN", v),
                None => std::env::remove_var("CADENCE_ALLOW_MAIN"),
            }
            match prev_kill {
                Some(v) => std::env::set_var("CADENCE_NO_ENFORCE_WORKTREE", v),
                None => std::env::remove_var("CADENCE_NO_ENFORCE_WORKTREE"),
            }
        }
        assert!(result, "primary checkout blocks with no env exemption");
    }

    #[test]
    fn linked_worktree_does_not_block() {
        let scratch = Scratch::new("would-block-wt");
        init_repo_with_commit(&scratch.0);
        let wt = scratch.0.join("wt");
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(&scratch.0)
            .args([
                "worktree",
                "add",
                "-q",
                &wt.to_string_lossy(),
                "-b",
                "feat/x",
            ])
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git worktree add failed");
        assert!(!would_block_here(&wt));
    }

    #[test]
    fn claude_managed_subdir_does_not_block() {
        let scratch = Scratch::new("would-block-claude");
        init_repo_with_commit(&scratch.0);
        let claude_dir = scratch.0.join(".claude").join("worktrees").join("x");
        std::fs::create_dir_all(&claude_dir).unwrap();
        assert!(!would_block_here(&claude_dir));
    }

    #[test]
    fn plan_doc_subdir_does_not_block() {
        let scratch = Scratch::new("would-block-plans");
        init_repo_with_commit(&scratch.0);
        let plans_dir = scratch.0.join("docs").join("plans");
        std::fs::create_dir_all(&plans_dir).unwrap();
        assert!(!would_block_here(&plans_dir));
    }

    #[test]
    fn non_repo_dir_does_not_block() {
        let scratch = Scratch::new("would-block-non-repo");
        // A bare scratch dir is NOT repo-less: it sits under the crate's own
        // `target/`, so repo resolution walks up to the enclosing checkout —
        // whose `.git` is a dir on a primary clone (CI) but a file in a
        // linked/detached worktree (local verify). Pin the dir to "no repo
        // resolvable" with a dead gitdir pointer so the None branch is what's
        // tested on every platform.
        std::fs::write(scratch.0.join(".git"), "gitdir: /nonexistent\n").unwrap();
        assert!(!would_block_here(&scratch.0));
    }
}
