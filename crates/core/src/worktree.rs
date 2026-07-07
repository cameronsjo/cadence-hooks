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

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Pure: classify a truthy env value (`1`/`true`/`yes`, trimmed,
/// case-insensitive). Mirrors `warn_main_branch::is_main_allowed_value` and
/// `warn_subagent_worktree::is_allowed_value`.
pub fn is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Returns true if `repo_root` is a **primary checkout** — its `.git` is a
/// directory. A linked worktree's `.git` is a *file* pointing into the
/// primary repo's `.git/worktrees/`.
pub fn is_primary_checkout(repo_root: &str) -> bool {
    Path::new(repo_root).join(".git").is_dir()
}

/// Pure: is `repo_root` inside a temp tree? `tmpdir` is the `$TMPDIR` value,
/// when set. Scratch/fixture repos live here; enforcing worktree discipline
/// on them would only produce noise.
pub fn is_temp_root(repo_root: &Path, tmpdir: Option<&str>) -> bool {
    let fixed = repo_root.starts_with("/tmp") || repo_root.starts_with("/private/tmp");
    let via_env = tmpdir
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "/")
        .is_some_and(|t| {
            // `repo_root` comes from `git rev-parse --show-toplevel`, which
            // canonicalizes (`/private/var/…` on macOS) while `$TMPDIR` does
            // not (`/var/folders/…`) — compare against the canonicalized
            // tmpdir too, or the exemption never fires on macOS.
            repo_root.starts_with(t)
                || std::fs::canonicalize(t)
                    .is_ok_and(|c| c != Path::new("/") && repo_root.starts_with(&c))
        });
    fixed || via_env
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
    let Some(path) = enforce_worktree_marker_path_for(repo_root) else {
        return false;
    };
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
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".git"),
            "gitdir: /repo/.git/worktrees/feat\n",
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
