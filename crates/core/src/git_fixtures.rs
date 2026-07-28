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
