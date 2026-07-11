//! Warn when creating a branch from a non-main base.
//!
//! Detects `git checkout -b` and `git switch -c` commands. In a **primary
//! checkout** under worktree discipline — the state `enforce-worktree` would
//! otherwise gate a mutation in, via [`would_block_here`] — branching in
//! place at all is the anti-pattern, regardless of the base named: the
//! primary checkout is meant to stay on `main`/`master` while feature work
//! happens in a worktree. That case gets a worktree-first nudge, replacing
//! the older "switch to main first" advice, which wrongly presumed
//! branching in-place was fine as long as the base was main. Everywhere
//! else (a linked worktree, an exempted repo, no resolvable cwd), the
//! original base-branch check is unchanged: whether the current branch (or
//! an explicit base argument) is `main`/`master`, nudging to switch to main
//! first to avoid stacking branches.

use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::worktree::would_block_here;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;

/// Warns when creating a new branch from a non-main base.
pub struct WarnBranchBase;

impl Check for WarnBranchBase {
    fn name(&self) -> &str {
        "warn-branch-base"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !is_branch_create(command) {
            return CheckResult::allow();
        }

        // Branching in place in a primary checkout under worktree discipline
        // is the pattern `enforce-worktree` exists to prevent — checked
        // first, ahead of the base-branch logic below, since it applies
        // regardless of which base is named. Only when the cwd resolves to
        // a repo `would_block_here` can judge; no cwd falls through to the
        // existing behavior (fail open, ADR-0001).
        // TODO(#164): GitState will absorb this suppression gate.
        if let Some(cwd) = input.cwd.as_deref()
            && would_block_here(Path::new(cwd))
        {
            return CheckResult::nudge(worktree_first_message());
        }

        // If an explicit base is given (e.g., `git checkout -b feat main`), check that
        if let Some(base) = explicit_base(command) {
            if is_main_branch(&base) {
                return CheckResult::allow();
            }
            return CheckResult::nudge(format!(
                "⚠️  Creating branch from `{base}`, not main.\n   \
                 If this is intentional (stacked branch), proceed.\n   \
                 Otherwise: `git checkout main && git pull` first."
            ));
        }

        // No explicit base — check current branch in the hook's working directory
        let current = match current_branch(input.cwd.as_deref()) {
            Some(b) => b,
            None => return CheckResult::allow(),
        };

        if is_main_branch(&current) {
            return CheckResult::allow();
        }

        CheckResult::nudge(format!(
            "⚠️  Creating branch from `{current}`, not main.\n   \
             If this is intentional (stacked branch), proceed.\n   \
             Otherwise: `git checkout main && git pull` first."
        ))
    }
}

/// The worktree-first nudge for a primary checkout under worktree
/// discipline: names the anti-pattern (branching in place) rather than
/// the base branch, and points at the worktree-entry playbook.
fn worktree_first_message() -> String {
    "⚠️  Branching in a primary checkout is the pattern `enforce-worktree` prevents.\n   \
     Create a worktree instead: `git worktree add .claude/worktrees/<slug> -b <branch>` \
     (or EnterWorktree), then create the branch there.\n   \
     See cadence-forge:using-worktrees § Session Entry Posture."
        .to_string()
}

/// Check if command creates a new branch.
fn is_branch_create(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // git checkout -b/-B <name>
    let has_checkout_b = tokens
        .windows(3)
        .any(|w| w[0] == "git" && w[1] == "checkout" && (w[2] == "-b" || w[2] == "-B"));

    // git switch -c/-C/--create <name>
    let has_switch_c = tokens.windows(3).any(|w| {
        w[0] == "git" && w[1] == "switch" && (w[2] == "-c" || w[2] == "-C" || w[2] == "--create")
    });

    has_checkout_b || has_switch_c
}

/// Extract explicit base branch if provided.
/// `git checkout -b feat main` → Some("main")
/// `git checkout -b feat` → None
fn explicit_base(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Find the -b/-B or -c/-C/--create flag, then the branch name is next.
    // After that, skip any flags (e.g. --track, -t) to find the base.
    for (i, token) in tokens.iter().enumerate() {
        if (*token == "-b"
            || *token == "-B"
            || *token == "-c"
            || *token == "-C"
            || *token == "--create")
            && i >= 1
            && (tokens[i - 1] == "checkout" || tokens[i - 1] == "switch")
        {
            // tokens[i+1] = new branch name; scan past flags (--track, -t) to find base
            for candidate in tokens.iter().skip(i + 2) {
                if !candidate.starts_with('-') {
                    return Some(candidate.to_string());
                }
            }
            return None;
        }
    }
    None
}

/// Recognized main branch refs. Only exact matches are accepted to avoid
/// false positives like `origin/feature/main`.
const MAIN_BRANCH_REFS: &[&str] = &[
    "main",
    "master",
    "origin/main",
    "origin/master",
    "upstream/main",
    "upstream/master",
];

fn is_main_branch(name: &str) -> bool {
    MAIN_BRANCH_REFS.contains(&name)
}

/// The current branch of the repo enclosing `cwd`, or `None` for a detached
/// HEAD / not-a-repo. Resolves via the shared [`GitState`] — a pure-filesystem
/// read of `HEAD` — instead of a `git branch --show-current` spawn
/// (cadence-hooks#164). `GitState.branch` is `None` on a detached HEAD, matching
/// the old empty-string→`None` normalization exactly.
fn current_branch(cwd: Option<&str>) -> Option<String> {
    GitState::resolve(Path::new(cwd.unwrap_or("."))).and_then(|s| s.branch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};

    // --- is_branch_create ---

    #[test]
    fn checkout_b_detected() {
        assert!(is_branch_create("git checkout -b feature"));
    }

    #[test]
    fn switch_c_detected() {
        assert!(is_branch_create("git switch -c feature"));
    }

    #[test]
    fn switch_create_detected() {
        assert!(is_branch_create("git switch --create feature"));
    }

    #[test]
    fn plain_checkout_not_detected() {
        assert!(!is_branch_create("git checkout main"));
    }

    #[test]
    fn plain_switch_not_detected() {
        assert!(!is_branch_create("git switch main"));
    }

    #[test]
    fn non_git_not_detected() {
        assert!(!is_branch_create("echo hello"));
    }

    // --- explicit_base ---

    #[test]
    fn explicit_base_present() {
        assert_eq!(
            explicit_base("git checkout -b feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn explicit_base_origin() {
        assert_eq!(
            explicit_base("git checkout -b feature origin/main"),
            Some("origin/main".to_string())
        );
    }

    #[test]
    fn no_explicit_base() {
        assert_eq!(explicit_base("git checkout -b feature"), None);
    }

    #[test]
    fn switch_explicit_base() {
        assert_eq!(
            explicit_base("git switch -c feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn flag_after_name_not_base() {
        assert_eq!(explicit_base("git checkout -b feature --track"), None);
    }

    #[test]
    fn explicit_base_after_track_flag() {
        assert_eq!(
            explicit_base("git checkout -b feature --track origin/develop"),
            Some("origin/develop".to_string())
        );
    }

    #[test]
    fn explicit_base_after_short_track_flag() {
        assert_eq!(
            explicit_base("git switch -c feature -t origin/main"),
            Some("origin/main".to_string())
        );
    }

    // --- is_main_branch ---

    #[test]
    fn main_is_main() {
        assert!(is_main_branch("main"));
    }

    #[test]
    fn master_is_main() {
        assert!(is_main_branch("master"));
    }

    #[test]
    fn origin_main_is_main() {
        assert!(is_main_branch("origin/main"));
    }

    #[test]
    fn feature_is_not_main() {
        assert!(!is_main_branch("feature/cool-stuff"));
    }

    #[test]
    fn upstream_main_is_main() {
        assert!(is_main_branch("upstream/main"));
    }

    #[test]
    fn arbitrary_remote_master_is_not_main() {
        // Only origin/ and upstream/ prefixes are recognized
        assert!(!is_main_branch("fork/master"));
    }

    // --- Check::run ---

    #[test]
    fn non_branch_command_allowed() {
        let result = WarnBranchBase.run(&make_bash("git status"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnBranchBase.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_main_base_allowed() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_origin_main_allowed() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature origin/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_non_main_base_warned() {
        let result = WarnBranchBase.run(&make_bash("git checkout -b feature develop"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
        assert!(result.message.unwrap().contains("develop"));
    }

    #[test]
    fn switch_explicit_master_allowed() {
        let result = WarnBranchBase.run(&make_bash("git switch -c feature master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Bug 5a: -B and -C (force variants) ---

    #[test]
    fn checkout_force_b_detected() {
        assert!(is_branch_create("git checkout -B feature"));
    }

    #[test]
    fn switch_force_c_detected() {
        assert!(is_branch_create("git switch -C feature"));
    }

    #[test]
    fn explicit_base_with_force_b() {
        assert_eq!(
            explicit_base("git checkout -B feature main"),
            Some("main".to_string())
        );
    }

    #[test]
    fn explicit_base_with_force_c() {
        assert_eq!(
            explicit_base("git switch -C feature origin/main"),
            Some("origin/main".to_string())
        );
    }

    // --- Bug 5b: is_main_branch over-match ---

    #[test]
    fn feature_main_is_not_main() {
        // origin/feature/main should NOT be treated as a main branch
        assert!(!is_main_branch("origin/feature/main"));
    }

    #[test]
    fn feature_slash_master_is_not_main() {
        assert!(!is_main_branch("origin/hotfix/master"));
    }

    #[test]
    fn upstream_master_is_main() {
        assert!(is_main_branch("upstream/master"));
    }

    // --- worktree-first nudge (folded enforce-worktree suppression gate) ---
    //
    // `would_block_here` reads real repo state and process env, so these
    // fixtures live under `target/`, not a tempdir — the temp-root exemption
    // would otherwise mask every primary-checkout case (the documented
    // Scratch/E2E gotcha `enforce_worktree`'s own tests carry the same note
    // for).

    use std::path::PathBuf;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/warn-branch-base-scratch")
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

    fn git_in(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed in {dir:?}");
    }

    fn init_repo(dir: &Path) {
        git_in(dir, &["init", "-q", "-b", "main"]);
        git_in(dir, &["config", "user.email", "t@t"]);
        git_in(dir, &["config", "user.name", "t"]);
        std::fs::write(dir.join("f.txt"), "x").unwrap();
        git_in(dir, &["add", "f.txt"]);
        git_in(dir, &["commit", "-q", "-m", "init"]);
    }

    /// Primary repo + linked worktree under a non-temp scratch root.
    fn primary_and_worktree(scratch: &Scratch) -> (PathBuf, PathBuf) {
        let primary = scratch.0.join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        let wt = scratch.0.join("wt");
        git_in(
            &primary,
            &["worktree", "add", &wt.to_string_lossy(), "-b", "feat/x"],
        );
        (primary, wt)
    }

    // `would_block_here` reads real process env (`CADENCE_ALLOW_MAIN`,
    // `CADENCE_NO_ENFORCE_WORKTREE`), unlike `enforce_worktree`'s own tests
    // (which inject an `EnvConfig`) — so these tests pin real env, serialized
    // via the shared `crate::CADENCE_ALLOW_MAIN_TEST_LOCK` and restored on drop,
    // panic included. The lock is crate-wide, not module-local, because
    // `warn_main_branch`'s tests mutate `CADENCE_ALLOW_MAIN` too — two separate
    // module locks would not exclude each other under cargo's parallel runner
    // (cadence-hooks#298). Mirrors `session::start`'s
    // `with_worktree_env`/`WorktreeEnvGuard` pattern.

    struct WorktreeEnvGuard {
        allow: Option<std::ffi::OsString>,
        kill: Option<std::ffi::OsString>,
    }

    impl Drop for WorktreeEnvGuard {
        fn drop(&mut self) {
            // SAFETY: only constructed inside `with_worktree_env`, which
            // holds `CADENCE_ALLOW_MAIN_TEST_LOCK` for this guard's whole
            // lifetime (declared after the lock, so it drops before the lock
            // releases — panic included).
            unsafe {
                match self.allow.take() {
                    Some(v) => std::env::set_var("CADENCE_ALLOW_MAIN", v),
                    None => std::env::remove_var("CADENCE_ALLOW_MAIN"),
                }
                match self.kill.take() {
                    Some(v) => std::env::set_var("CADENCE_NO_ENFORCE_WORKTREE", v),
                    None => std::env::remove_var("CADENCE_NO_ENFORCE_WORKTREE"),
                }
            }
        }
    }

    fn with_worktree_env<T>(allow: Option<&str>, kill: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _lock = crate::CADENCE_ALLOW_MAIN_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _restore = WorktreeEnvGuard {
            allow: std::env::var_os("CADENCE_ALLOW_MAIN"),
            kill: std::env::var_os("CADENCE_NO_ENFORCE_WORKTREE"),
        };
        // SAFETY: serialized via ENV_LOCK; `_restore` puts the caller's
        // values back on scope exit.
        unsafe {
            match allow {
                Some(v) => std::env::set_var("CADENCE_ALLOW_MAIN", v),
                None => std::env::remove_var("CADENCE_ALLOW_MAIN"),
            }
            match kill {
                Some(v) => std::env::set_var("CADENCE_NO_ENFORCE_WORKTREE", v),
                None => std::env::remove_var("CADENCE_NO_ENFORCE_WORKTREE"),
            }
        }
        f()
    }

    fn with_clean_worktree_env<T>(f: impl FnOnce() -> T) -> T {
        with_worktree_env(None, None, f)
    }

    #[test]
    fn checkout_b_in_primary_checkout_nudges_worktree_first() {
        with_clean_worktree_env(|| {
            let scratch = Scratch::new("checkout-b-primary");
            let (primary, _wt) = primary_and_worktree(&scratch);
            let input = make_bash_with_cwd("git checkout -b feat/x", primary.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(msg.contains("enforce-worktree"), "names the guard: {msg}");
            assert!(msg.contains("worktree add"), "points at the fix: {msg}");
        });
    }

    #[test]
    fn switch_c_in_primary_checkout_nudges_worktree_first() {
        with_clean_worktree_env(|| {
            let scratch = Scratch::new("switch-c-primary");
            let (primary, _wt) = primary_and_worktree(&scratch);
            let input = make_bash_with_cwd("git switch -c feat/x", primary.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
            assert!(
                result.message.unwrap().contains("enforce-worktree"),
                "switch -c gets the same worktree-first nudge as checkout -b"
            );
        });
    }

    #[test]
    fn checkout_b_in_linked_worktree_keeps_existing_behavior() {
        with_clean_worktree_env(|| {
            let scratch = Scratch::new("checkout-b-wt");
            let (_primary, wt) = primary_and_worktree(&scratch);
            // `wt` is checked out on `feat/x` (non-main) — since
            // `would_block_here` is false here (linked worktree, `.git` is a
            // file), this falls through to the original current-branch base
            // nudge, unchanged.
            let input = make_bash_with_cwd("git checkout -b feat/y", wt.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(
                !msg.contains("enforce-worktree"),
                "linked worktree must not get the primary-only nudge: {msg}"
            );
            assert!(msg.contains("feat/x"), "names the actual base: {msg}");
        });
    }

    #[test]
    fn checkout_b_allow_main_suppresses_worktree_first_nudge() {
        with_worktree_env(Some("true"), None, || {
            let scratch = Scratch::new("checkout-b-allow-main");
            let (primary, _wt) = primary_and_worktree(&scratch);
            // Base is main and CADENCE_ALLOW_MAIN exempts the primary from
            // `would_block_here` — falls through to the unchanged
            // explicit-base-is-main Allow.
            let input =
                make_bash_with_cwd("git checkout -b feat/x main", primary.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }

    #[test]
    fn checkout_b_kill_switch_suppresses_worktree_first_nudge() {
        with_worktree_env(None, Some("1"), || {
            let scratch = Scratch::new("checkout-b-kill-switch");
            let (primary, _wt) = primary_and_worktree(&scratch);
            let input = make_bash_with_cwd("git checkout -b feat/x", primary.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            // CADENCE_NO_ENFORCE_WORKTREE exempts the primary, so this falls
            // through to the original current-branch check — current branch
            // is main, so it's silent.
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }

    // Unix-only: core's temp-root detection (`path_under_temp_root`) keys off
    // `/tmp`/`/private/tmp` and `$TMPDIR`, with no Windows `TEMP`/`TMP`
    // handling — so `std::env::temp_dir()` (a `C:\…\Temp` path on Windows) is
    // not seen as a temp root and this suppression can't be exercised there.
    // No D3 coverage is lost: the `would_block_here`-false fall-through this
    // asserts is also covered cross-platform by the `allow_main` and
    // `kill_switch` suppression tests above.
    #[cfg(unix)]
    #[test]
    fn checkout_b_temp_root_suppresses_worktree_first_nudge() {
        with_clean_worktree_env(|| {
            let root =
                std::env::temp_dir().join(format!("warn-branch-base-temp-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            init_repo(&root);
            let input = make_bash_with_cwd("git checkout -b feat/x", root.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            // A temp-root repo is exempt from `would_block_here`, so this
            // falls through — current branch is main, so it's silent.
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
            let _ = std::fs::remove_dir_all(&root);
        });
    }

    #[test]
    fn explicit_non_main_base_outside_primary_unchanged() {
        with_clean_worktree_env(|| {
            let scratch = Scratch::new("explicit-base-wt");
            let (_primary, wt) = primary_and_worktree(&scratch);
            let input = make_bash_with_cwd("git checkout -b feature develop", wt.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(!msg.contains("enforce-worktree"), "not a primary: {msg}");
            assert!(msg.contains("develop"), "names the explicit base: {msg}");
        });
    }

    #[test]
    fn plain_checkout_in_primary_stays_silent() {
        with_clean_worktree_env(|| {
            let scratch = Scratch::new("plain-checkout-primary");
            let (primary, _wt) = primary_and_worktree(&scratch);
            // No `-b`/`-c` — is_branch_create gates before the worktree-first
            // check ever runs.
            let input = make_bash_with_cwd("git checkout main", primary.to_str().unwrap());
            let result = WarnBranchBase.run(&input);
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }
}
