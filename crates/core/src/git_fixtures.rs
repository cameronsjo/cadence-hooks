//! Git-fixture builders for integration tests that exercise a
//! carve-out-sensitive guard (`enforce-worktree` and its mutation-nudge
//! channel) against a real, on-disk git repo.
//!
//! Gated behind the `test-builders` feature, same as [`crate::test_builders`]
//! — see that module for the dev-dependency snippet. Kept as a separate
//! module rather than folded into `test_builders` because these builders
//! spawn `git` subprocesses and touch the filesystem, which every consumer of
//! `test_builders`'s plain `HookInput` builders (`make_bash`, `make_edit`, …)
//! would otherwise have to compile too.
//!
//! This module never ships in the production `cadence-hooks` binary — but
//! that guarantee rests on the workspace `Cargo.toml` declaring
//! `resolver = "2"`. Under Cargo's older resolver (v1), a `[dev-dependencies]`
//! feature request unifies into the same crate's *normal* dependency feature
//! set, which would compile this module — subprocess spawning and recursive
//! directory removal included — into the shipped binary as dead code. A
//! resolver downgrade is the one change that silently reopens that.

use crate::worktree::{is_claude_managed_dir, path_under_temp_root};
use std::path::{Path, PathBuf};

/// A `target/`-rooted (never tempdir-rooted), auto-cleaning scratch directory.
/// [`path_under_temp_root`] exempts anything under the platform temp dir
/// (cadence-hooks#312), so a tempdir-rooted fixture would silently allow every
/// blocked-path case and the test would never reach the git-spawning/blocking
/// branch at all.
///
/// `root` is the caller's own `target/`-relative scratch root — typically
/// `Path::new(env!("CARGO_MANIFEST_DIR")).join(...)`, computed at the CALL
/// SITE and passed in, since `env!` bakes in the invoking crate's manifest
/// dir at compile time, not this crate's. Baking a fixed relative join in
/// here instead would root every caller's scratch dir under core's own
/// `target/`, silently losing each caller's distinct fixture-directory name.
pub struct Scratch(PathBuf);

impl Scratch {
    /// `tag` plus the current process id makes each call's directory unique
    /// across concurrent test runs sharing one `root`.
    pub fn new(root: &Path, tag: &str) -> Self {
        // `Scratch::new` is public API, not a private test-module struct —
        // `tag` is a traversal-capable parameter feeding `remove_dir_all`
        // below. Every current call site passes a string literal, but "safe
        // because every caller today passes a literal" is a property of the
        // call sites, not of the function, and this function is public
        // precisely because its callers can no longer be enumerated. Pin the
        // property here instead of relying on a survey a future caller could
        // invalidate.
        assert!(
            !tag.contains(['/', '\\']) && !tag.contains(".."),
            "tag must not contain a path separator or `..`: {tag:?}"
        );
        let dir = root.join(format!("{tag}-{}", std::process::id()));
        // #312: the whole point of a `target/`-rooted fixture is to sit
        // OUTSIDE the guard's own carve-outs — a `.claude/` component or a
        // temp prefix would silently exempt every fixture and make the block
        // paths pass vacuously. Fail loudly rather than test nothing.
        assert!(
            !is_claude_managed_dir(&dir)
                && !path_under_temp_root(&dir, std::env::var("TMPDIR").ok().as_deref()),
            "fixture root sits under a carve-out (.claude/ or temp) — run the suite \
             from a carve-out-free checkout: {}",
            dir.display()
        );
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// The fixture's root directory.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `git` with `args` in `dir`, asserting success.
///
/// Always resolves `git` off `PATH` rather than an absolute path. Fixture
/// setup like this always runs in the TEST PROCESS's own environment, never
/// the child `cadence-hooks` binary's — callers that install a `git` shim
/// (a counting or hanging fake) do so only on the CHILD command's `PATH`
/// (`cmd.env("PATH", shim.path())`), which this process's own `PATH` never
/// sees. So a bare `"git"` here always resolves to the real binary, the same
/// one an absolute-path resolution (e.g. a cached `command -v git`) would
/// have found — there is no shimmed-PATH hazard for this helper to guard
/// against.
pub fn git_in(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(ok, "git {args:?} failed in {dir:?}");
}

/// Initialize `dir` as a single-commit git repo on `main` — the minimal
/// fixture shape `Scratch`-based tests join a subdirectory of and hand to.
pub fn init_repo(dir: &Path) {
    git_in(dir, &["init", "-q", "-b", "main"]);
    git_in(dir, &["config", "user.email", "t@t"]);
    git_in(dir, &["config", "user.name", "t"]);
    std::fs::write(dir.join("f.txt"), "x").unwrap();
    git_in(dir, &["add", "f.txt"]);
    git_in(dir, &["commit", "-q", "-m", "init"]);
}

// This module's own tests were promoted from three duplicated in-crate copies
// (`worktree.rs`, `enforce_worktree.rs`, `tests/deadline_failopen.rs`) with no
// direct coverage of its own — every existing test exercises `Scratch`/`git_in`/
// `init_repo` only indirectly, through a guard that happens to use them. These
// pin the fixture module's own behavior: the carve-out assert, the stale-dir
// wipe on `new()`, `Drop` cleanup, and `git_in`/`init_repo` success/failure.
#[cfg(test)]
mod tests {
    use super::*;

    /// This module's own `target/`-relative scratch root, mirroring the
    /// `scratch_root()` convention every consumer of this fixture uses —
    /// `env!` resolves at THIS call site, landing under core's own `target/`.
    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/git-fixtures-scratch")
    }

    #[test]
    fn new_creates_a_directory_at_the_expected_path() {
        let scratch = Scratch::new(&scratch_root(), "new-basic");
        assert!(scratch.path().is_dir());
        assert!(scratch.path().starts_with(scratch_root()));
    }

    #[test]
    fn new_wipes_a_stale_directory_from_a_previous_run() {
        // A prior run that crashed or was killed before `Drop` fired would
        // leave the same tag+pid directory behind with old contents — `new()`
        // must not just no-op create_dir_all over it, it must wipe it first.
        let root = scratch_root();
        let tag = "stale-wipe";
        let dir = root.join(format!("{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("leftover.txt"), "stale").unwrap();

        let scratch = Scratch::new(&root, tag);
        assert!(scratch.path().is_dir());
        assert!(
            !scratch.path().join("leftover.txt").exists(),
            "new() must wipe pre-existing content at the same path"
        );
    }

    #[test]
    fn drop_removes_the_scratch_directory() {
        let dir_path;
        {
            let scratch = Scratch::new(&scratch_root(), "drop-cleanup");
            dir_path = scratch.path().to_path_buf();
            assert!(dir_path.is_dir());
        } // `scratch` drops here.
        assert!(!dir_path.exists(), "Drop must remove the fixture directory");
    }

    #[test]
    #[should_panic(expected = "path separator")]
    fn new_panics_when_tag_contains_a_path_separator() {
        let _ = Scratch::new(&scratch_root(), "../escape");
    }

    #[test]
    #[should_panic(expected = "carve-out")]
    fn new_panics_when_root_sits_under_a_temp_root() {
        // Fixed check in `path_under_temp_root`: anything under `/tmp` counts,
        // independent of `$TMPDIR` — no env setup needed to trigger it.
        let _ = Scratch::new(Path::new("/tmp/git-fixtures-carveout-check"), "x");
    }

    #[test]
    #[should_panic(expected = "carve-out")]
    fn new_panics_when_root_contains_a_claude_component() {
        let root = scratch_root().join(".claude");
        let _ = Scratch::new(&root, "x");
    }

    #[test]
    fn git_in_runs_a_successful_command() {
        let scratch = Scratch::new(&scratch_root(), "git-in-ok");
        git_in(scratch.path(), &["init", "-q", "-b", "main"]);
        assert!(scratch.path().join(".git").is_dir());
    }

    #[test]
    #[should_panic(expected = "failed in")]
    fn git_in_panics_on_a_failing_command() {
        let scratch = Scratch::new(&scratch_root(), "git-in-fail");
        // `git status` would still succeed here — the scratch dir sits under
        // this checkout's own `target/`, so git's upward `.git` search finds
        // the enclosing repo rather than failing. An unrecognized subcommand
        // fails regardless of ambient repo context.
        git_in(scratch.path(), &["not-a-real-git-subcommand"]);
    }

    #[test]
    fn init_repo_creates_a_single_commit_on_main() {
        let scratch = Scratch::new(&scratch_root(), "init-repo");
        init_repo(scratch.path());

        assert!(scratch.path().join(".git").is_dir());
        assert!(scratch.path().join("f.txt").is_file());

        let branch = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(scratch.path())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&branch.stdout).trim(),
            "main",
            "init_repo leaves the repo on main"
        );

        let log = std::process::Command::new("git")
            .args(["log", "--oneline"])
            .current_dir(scratch.path())
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&log.stdout).lines().count(),
            1,
            "init_repo makes exactly one commit"
        );
    }
}
