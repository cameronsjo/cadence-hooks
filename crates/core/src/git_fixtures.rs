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

use crate::worktree::{is_claude_managed_dir, path_under_temp_root_with_canonical};
use std::path::{Path, PathBuf};

/// Env var overriding [`resolve_scratch_dir`]'s fallback root, for the rare
/// case where neither the caller's default nor `$XDG_CACHE_HOME`/`$HOME/.cache`
/// escapes a carve-out (e.g. a sandboxed runner with `$XDG_CACHE_HOME` itself
/// under `/tmp`). Unset in the overwhelming common case. `pub(crate)`, not
/// `pub` — no caller outside this crate needs the Rust constant; the env var
/// itself is a shell-level contract (documented in `CONTRIBUTING.md`), set
/// from a developer's shell, never referenced by name from other crates'
/// code.
pub(crate) const SCRATCH_ROOT_OVERRIDE_ENV: &str = "CADENCE_HOOKS_TEST_SCRATCH_ROOT";

/// A `target/`-rooted-by-default (never tempdir-rooted), auto-cleaning
/// scratch directory. [`crate::worktree::path_under_temp_root`] exempts anything under the
/// platform temp dir (cadence-hooks#312), so a tempdir-rooted fixture would
/// silently allow every blocked-path case and the test would never reach the
/// git-spawning/blocking branch at all.
///
/// `root` is the caller's own `target/`-relative scratch root — typically
/// `Path::new(env!("CARGO_MANIFEST_DIR")).join(...)`, computed at the CALL
/// SITE and passed in, since `env!` bakes in the invoking crate's manifest
/// dir at compile time, not this crate's. Baking a fixed relative join in
/// here instead would root every caller's scratch dir under core's own
/// `target/`, silently losing each caller's distinct fixture-directory name.
///
/// `root` is only ever a *default*, not a guarantee — see
/// [`resolve_scratch_dir`] for what happens when it lands inside a carve-out
/// anyway (cadence-hooks#403).
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
        let dir = resolve_scratch_dir(root, tag);
        let _ = std::fs::remove_dir_all(&dir);
        // `escapes_carveout` is purely lexical — it blesses `$XDG_CACHE_HOME`
        // (or the override) without checking it's writable. On a read-only
        // or vendored cache home this create would fail — name the escape
        // hatch in the message rather than dying with a bare `Os { code: 30,
        // ReadOnlyFilesystem }` that never points at the fix (cadence-hooks#403
        // code review).
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!(
                "failed to create fixture dir {}: {e} — if this is under \
                 $XDG_CACHE_HOME/$HOME/.cache and it's read-only or vendored, set \
                 {SCRATCH_ROOT_OVERRIDE_ENV} to a writable, carve-out-free directory",
                dir.display()
            )
        });
        Self(dir)
    }

    /// The fixture's root directory.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Resolve `root.join("{tag}-{pid}")`, guaranteeing the result sits outside
/// every enforce-worktree carve-out (`.claude/` or a temp root) — see the
/// module doc for why that guarantee matters. Reads real process env; see
/// [`resolve_scratch_dir_with`] for the injectable decision this wraps.
pub(crate) fn resolve_scratch_dir(root: &Path, tag: &str) -> PathBuf {
    let override_root = std::env::var_os(SCRATCH_ROOT_OVERRIDE_ENV).map(PathBuf::from);
    resolve_scratch_dir_with(
        root,
        tag,
        std::env::var("TMPDIR").ok().as_deref(),
        override_root.as_deref(),
        xdg_cache_home().as_deref(),
        Some(&crate::paths::user_home_lossy_or_default()),
    )
}

/// `resolve_scratch_dir`'s decision, with every environment input passed in
/// rather than read live — so tests can exercise the fallback chain without
/// mutating real process env (which every concurrently-running test in the
/// same binary would also observe, since `cargo test` runs tests as threads
/// in one process; cadence-hooks#403 code review).
///
/// `root` is tried first, since it keeps fixtures local to the checkout for
/// the common case. But `root` is computed from `CARGO_MANIFEST_DIR`, which
/// lives INSIDE the checkout — so when the checkout itself sits under a
/// carve-out — any worktree under `.claude/worktrees/`, or one rooted in
/// `/tmp`; `escapes_carveout` below exempts both (cadence-hooks#403) —
/// `root` is under that same carve-out and no
/// subdirectory of it can escape. In that case, fall back to a location
/// outside the checkout entirely: `override_root`
/// ([`SCRATCH_ROOT_OVERRIDE_ENV`]) if given, else `xdg_cache_home`
/// (`$XDG_CACHE_HOME`/`$HOME/.cache`) — both of which exist on any machine
/// that can run `cargo test` at all, and neither of which is
/// checkout-relative. `$XDG_CACHE_HOME` over `$CARGO_HOME`
/// (cadence-hooks#505): this data is disposable cache, not a cargo artifact,
/// and a `$CARGO_HOME`-rooted path is never swept by `cargo clean` while
/// `Scratch`'s `Drop` only reclaims the `{tag}-{pid}` leaf — the namespace
/// parent accumulated forever. `$XDG_CACHE_HOME` is purpose-fit for
/// disposable data and gets swept by normal cache conventions instead.
/// Panics only if none of these escape the carve-out, which should never
/// happen outside a deliberately broken environment.
///
/// This never silently narrows coverage: every caller's actual test logic
/// still runs against a real, non-exempt fixture, whichever root won.
fn resolve_scratch_dir_with(
    root: &Path,
    tag: &str,
    tmpdir: Option<&str>,
    override_root: Option<&Path>,
    xdg_cache_home: Option<&Path>,
    home: Option<&str>,
) -> PathBuf {
    // `$TMPDIR` is invariant for the process — canonicalize once (a real
    // `realpath` syscall chain) and reuse it across all three candidates,
    // rather than re-canonicalizing per candidate inside `escapes_carveout`
    // (cadence-hooks#403 code review: the relocation path this function
    // exists for is precisely the one that was paying that cost 2-3x).
    let tmpdir_canonical = crate::worktree::canonicalize_tmpdir(tmpdir, home);
    let suffix = format!("{tag}-{}", std::process::id());
    let candidate = |base: &Path| base.join(&suffix);
    // Canonicalize `dir` (or its nearest existing ancestor — the `{tag}-{pid}`
    // leaf doesn't exist yet when this runs) before checking it: a lexical
    // check on the literal `CARGO_MANIFEST_DIR`-derived string can diverge
    // from what the guard being tested actually sees, if any ancestor
    // component is a symlink. Verified empirically (cadence-hooks#403 code
    // review / CodeRabbit): `git rev-parse --show-toplevel` — what
    // `enforce-worktree`'s own checks resolve a repo root through —
    // resolves symlinks (a checkout reached via a symlink into `/tmp`
    // reports the real `/tmp/...` path), so a fixture root whose LITERAL
    // path escapes the carve-out could still land somewhere the guard's
    // real resolution treats as exempt, reopening this exact bug through
    // symlink indirection instead of a direct `/tmp` prefix.
    let escapes_carveout = |dir: &Path| {
        let resolved = canonicalize_nearest_existing(dir);
        !is_claude_managed_dir(&resolved)
            && !path_under_temp_root_with_canonical(
                &resolved,
                tmpdir,
                tmpdir_canonical.as_deref(),
                home,
            )
    };

    let default_dir = candidate(root);
    if escapes_carveout(&default_dir) {
        return default_dir;
    }

    // `root`'s own final component names the CALLER's distinct fixture
    // directory (`git-fixtures-scratch`, `enforce-worktree-scratch`,
    // `session-posture-scratch`, …) — the module doc at the top explains why
    // `root` is taken at all rather than a fixed relative join. A fallback
    // that dropped this component would collapse every caller into one
    // shared directory once relocated, and since `Drop` only reclaims the
    // `{tag}-{pid}` leaf, the accumulating parent gives no hint which crate
    // produced what (cadence-hooks#403 code review). Preserve it as a
    // namespacing subdirectory under whichever fallback root wins.
    let namespace = root
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| std::ffi::OsString::from("scratch"));

    if let Some(override_root) = override_root {
        let dir = candidate(&override_root.join(&namespace));
        assert!(
            escapes_carveout(&dir),
            "{SCRATCH_ROOT_OVERRIDE_ENV} itself sits under a carve-out (.claude/ or temp): {}",
            dir.display()
        );
        note_relocation_once(&format!(
            "via ${SCRATCH_ROOT_OVERRIDE_ENV}: {}",
            dir.display()
        ));
        return dir;
    }

    if let Some(xdg_cache_home) = xdg_cache_home {
        // `cadence-hooks/test-scratch`: a proper XDG-style app subdirectory
        // (`$XDG_CACHE_HOME/cadence-hooks/…`), not the old flat
        // `cadence-hooks-test-scratch` hyphenation — leaves room for other
        // cadence-hooks cache data to live alongside this without a naming
        // collision.
        let dir = candidate(
            &xdg_cache_home
                .join("cadence-hooks")
                .join("test-scratch")
                .join(&namespace),
        );
        if escapes_carveout(&dir) {
            note_relocation_once(&format!("to $XDG_CACHE_HOME: {}", dir.display()));
            return dir;
        }
    }

    panic!(
        "fixture root sits under a carve-out (.claude/ or temp), and no carve-out-free \
         fallback was found ($XDG_CACHE_HOME/$HOME/.cache also under one) — the checkout itself \
         likely lives under a temp root (cadence-hooks#403): {}\n\
         Set ${SCRATCH_ROOT_OVERRIDE_ENV} to a carve-out-free directory to run the suite \
         from here.",
        default_dir.display()
    );
}

/// Canonicalize `path`, walking up to the nearest existing ancestor when
/// `path` itself doesn't exist yet (`std::fs::canonicalize` errors on a
/// missing path, and the `{tag}-{pid}` leaf a `Scratch` candidate names is
/// never created before this check runs) — then re-append the removed tail
/// components onto the resolved ancestor.
///
/// Falls back to `path` unchanged if canonicalization never succeeds (no
/// ancestor exists, or another resolution failure) — fail-open to the
/// lexical check rather than panicking on a filesystem edge case unrelated
/// to what this function exists to catch.
fn canonicalize_nearest_existing(path: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(&cur) {
            let mut result = canonical;
            for component in tail.into_iter().rev() {
                result.push(component);
            }
            return result;
        }
        let Some(name) = cur.file_name().map(std::ffi::OsStr::to_os_string) else {
            return path.to_path_buf();
        };
        tail.push(name);
        if !cur.pop() {
            return path.to_path_buf();
        }
    }
}

/// Print the carve-out relocation notice to stderr exactly **once per
/// process**, not once per `Scratch::new` call. A `/tmp`-worktree test run
/// calls this indirectly from every one of the ~120 fixture call sites
/// across the workspace — without the guard, that's up to ~120 near-identical
/// stderr lines (cadence-hooks#403 code review), which is exactly the noise
/// the single `note:` line this docstring — and `CONTRIBUTING.md` — promise.
fn note_relocation_once(detail: &str) {
    static NOTED: std::sync::Once = std::sync::Once::new();
    NOTED.call_once(|| {
        eprintln!(
            "note: checkout lives under a carve-out (.claude/ or temp) — fixtures relocated \
             {detail} (further relocations this run are silent)"
        );
    });
}

/// `$XDG_CACHE_HOME`, falling back to the user's home directory joined with
/// `.cache` — both stable, checkout-independent locations that exist on any
/// machine able to run `cargo test`. Reads real process env; see
/// [`xdg_cache_home_from`] for the injectable decision this wraps.
///
/// Routes the fallback through [`crate::paths::user_home`] rather than
/// reading `$HOME` directly (cadence-hooks#403 code review, carried forward
/// in #505): `$HOME` is unix-only, and `CONTRIBUTING.md` documents Windows
/// support, where a contributor has no `$HOME` at all — `user_home` already
/// carries the `$USERPROFILE`/`$HOMEDRIVE`+`$HOMEPATH` chain.
fn xdg_cache_home() -> Option<PathBuf> {
    xdg_cache_home_from(
        crate::paths::non_empty_var("XDG_CACHE_HOME"),
        crate::paths::user_home(),
    )
}

/// `xdg_cache_home`'s decision, with `$XDG_CACHE_HOME` and the resolved home
/// directory passed in rather than read live — so the empty-`$XDG_CACHE_HOME`
/// rule is pinnable without mutating real process env (cadence-hooks#403
/// code review: the rule was documented at length but had no test, and
/// couldn't get one against the live-env version).
///
/// `xdg_cache_home_var` comes from [`crate::paths::non_empty_var`], which
/// already treats an empty-but-set var as unset — without that,
/// `XDG_CACHE_HOME=""` would make `PathBuf::from("")`, and joining
/// `cadence-hooks/test-scratch` onto it resolves that *relative* path, which
/// names neither `.claude/` nor a temp root, so `escapes_carveout` would
/// bless it and this fixture would be created relative to the test binary's
/// cwd instead of failing loudly.
///
/// An empty value is only the *narrowest* spelling of that hazard, though:
/// any relative value (`XDG_CACHE_HOME=cache`) lands in the same place, for
/// the same reason. So the rule is absoluteness, not non-emptiness — which is
/// also what the XDG base-directory spec requires, where a relative value is
/// to be ignored (#516 review).
///
/// Each candidate is filtered on its own rather than the chain being filtered
/// once at the end: `a.or(b).filter(..)` would validate only whichever arm
/// won, silently exempting the other. A relative `$XDG_CACHE_HOME` must fall
/// through to the home-based path, and a non-absolute home must not sneak in
/// behind it.
fn xdg_cache_home_from(
    xdg_cache_home_var: Option<String>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    let from_var = xdg_cache_home_var
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    let from_home = home.map(|h| h.join(".cache")).filter(|p| p.is_absolute());
    from_var.or(from_home)
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
    // Gated to match its only consumer — the `#[cfg(unix)]` symlink test
    // below. Unconditional here, it is an unused import on Windows, which
    // `-D warnings` turns into a build failure (caught by CI, not locally).
    #[cfg(unix)]
    use crate::worktree::path_under_temp_root;

    /// This module's own `target/`-relative scratch root, mirroring the
    /// `scratch_root()` convention every consumer of this fixture uses —
    /// `env!` resolves at THIS call site, landing under core's own `target/`.
    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/git-fixtures-scratch")
    }

    #[test]
    fn new_creates_a_tag_pid_named_directory() {
        // `scratch_root()` is only ever a *default* (cadence-hooks#403) —
        // when THIS checkout itself sits under a carve-out (a `/tmp`
        // worktree), `Scratch` relocates, so asserting `starts_with
        // scratch_root()` here would reintroduce the exact bug #403 fixes
        // for this one test. The carve-out-escape guarantee itself is
        // pinned hermetically by the `resolve_*` tests below, against
        // `resolve_scratch_dir_with` directly — not here, and not by
        // constructing a real `Scratch` against a hardcoded carve-out root
        // (that would relocate into this machine's REAL `$XDG_CACHE_HOME` on
        // every run, carve-out or not; see the comment above the
        // `resolve_*` tests). This test only pins what's true regardless of
        // which root wins: a real directory, named `{tag}-{pid}`.
        let scratch = Scratch::new(&scratch_root(), "new-basic");
        assert!(scratch.path().is_dir());
        assert!(
            scratch
                .path()
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("new-basic-")),
            "unexpected fixture path: {}",
            scratch.path().display()
        );
    }

    #[test]
    fn new_wipes_a_stale_directory_from_a_previous_run() {
        // A prior run that crashed or was killed before `Drop` fired would
        // leave the same tag+pid directory behind with old contents — `new()`
        // must not just no-op create_dir_all over it, it must wipe it first.
        //
        // Pre-seeding `root.join("{tag}-{pid}")` directly (rather than asking
        // where `Scratch` actually resolves to) would only exercise the wipe
        // when `root` happens to escape a carve-out — a `resolve_scratch_dir`
        // relocation (cadence-hooks#403) would leave the pre-seeded stale dir
        // untouched at a path `Scratch` never visits, and the assertion below
        // would pass vacuously. Learn the real resolved path via the pure
        // `resolve_scratch_dir` (no filesystem writes) rather than
        // constructing-then-dropping a throwaway `Scratch` — same `tag` and
        // process (so same pid), so the real `Scratch::new` call below
        // resolves identically.
        let root = scratch_root();
        let tag = "stale-wipe";
        let dir = resolve_scratch_dir(&root, tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("leftover.txt"), "stale").unwrap();

        let scratch = Scratch::new(&root, tag);
        assert_eq!(
            scratch.path().to_path_buf(),
            dir,
            "sanity: Scratch::new must resolve to the same path resolve_scratch_dir predicted"
        );
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

    // --- carve-out relocation (cadence-hooks#403) ---
    //
    // `root` is only a default — when it lands inside a carve-out (e.g. the
    // checkout itself sits under a `/tmp`-rooted worktree), the resolver
    // must relocate to escape it rather than panic, so the guard's actual
    // block/allow logic still runs for real instead of the whole suite
    // reporting confusing failures.
    //
    // The fallback-chain branches (default escapes, override wins,
    // `$XDG_CACHE_HOME` fallback, the final panic) are pinned against
    // `resolve_scratch_dir_with` directly, with every env input passed as a
    // plain argument — NOT via a real `Scratch::new` call against a
    // hardcoded carve-out root. Two hazards rule that out: (1) `cargo test`
    // runs tests as threads in one process, so a real `std::env::set_var`
    // would be visible to every *other* concurrently-running test's own
    // `Scratch::new`/`resolve_scratch_dir` call, most of which don't
    // coordinate on any lock — a real, observed hazard while developing this
    // fix, not a hypothetical one; and (2) a hardcoded carve-out root
    // relocates on EVERY run, not just when the ambient checkout is actually
    // under one — which means every plain `cargo test` (not just a `/tmp`
    // worktree run) would create-then-partially-clean a directory under this
    // machine's REAL `$XDG_CACHE_HOME` (`Drop` only removes the `{tag}-{pid}`
    // leaf, so the `cadence-hooks/test-scratch` parent accumulates forever).
    // Verified on this machine: it did (cadence-hooks#403 code review; the
    // root moved from `$CARGO_HOME` to `$XDG_CACHE_HOME` in #505, but the
    // same accumulation hazard applies to whichever root is live).
    //
    // The "this candidate must look carved-out" tests below anchor on
    // `std::env::temp_dir()`, not a hardcoded `/tmp/...` literal — a Unix
    // literal is meaningless on Windows, twice over (Windows CI red on
    // PR#507): `path_under_temp_root`'s fixed check hardcodes `/tmp` and
    // `/private/tmp` only, and `canonicalize_nearest_existing` walks a
    // non-existent Unix-style literal up to a REAL, drive-qualified Windows
    // ancestor that doesn't match either — so `escapes_carveout` returned
    // true for the "carved-out" default on Windows, and the function
    // short-circuited there without ever reaching the branch under test.
    // Anchoring on the real temp dir and passing it as `tmpdir` too routes
    // through the portable `via_env` check on every platform, the same
    // mechanism that already handles macOS's `/var` vs `/private/var` split.

    /// A directory guaranteed to be recognized as under a carve-out (temp
    /// root) on ANY platform — see the comment above.
    fn temp_carveout_root(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join("git-fixtures-carveout-portability-check")
            .join(tag)
    }

    /// The `tmpdir` value to pair with [`temp_carveout_root`], so
    /// `path_under_temp_root_with_canonical`'s `via_env` branch recognizes
    /// paths built from it — the same real, resolvable directory on every
    /// platform, unlike a hardcoded `/tmp` literal.
    fn temp_carveout_tmpdir() -> String {
        std::env::temp_dir().to_string_lossy().into_owned()
    }

    #[test]
    fn resolve_uses_the_default_when_it_escapes_the_carveout() {
        let root = Path::new("/Users/dev/checkout/target/scratch");
        let dir = resolve_scratch_dir_with(root, "basic", None, None, None, None);
        assert_eq!(dir, root.join(format!("basic-{}", std::process::id())));
    }

    #[test]
    fn resolve_override_wins_when_default_is_carved_out() {
        let tmpdir = temp_carveout_tmpdir();
        let dir = resolve_scratch_dir_with(
            &temp_carveout_root("override-wins"),
            "tag",
            Some(&tmpdir),
            Some(Path::new("/Users/dev/.cache/cadence-hooks/test-scratch")),
            Some(Path::new("/Users/dev/.cache/should-not-be-used")),
            None,
        );
        assert!(
            dir.starts_with("/Users/dev/.cache/cadence-hooks/test-scratch"),
            "override must be tried before the $XDG_CACHE_HOME fallback: {}",
            dir.display()
        );
    }

    #[test]
    fn resolve_falls_back_to_xdg_cache_home_when_default_is_temp_and_no_override() {
        let tmpdir = temp_carveout_tmpdir();
        let dir = resolve_scratch_dir_with(
            &temp_carveout_root("xdg-cache-home-fallback"),
            "tag",
            Some(&tmpdir),
            None,
            Some(Path::new("/Users/dev/.cache")),
            None,
        );
        assert!(dir.starts_with("/Users/dev/.cache/cadence-hooks/test-scratch"));
    }

    #[test]
    fn resolve_falls_back_to_xdg_cache_home_when_default_is_claude_managed() {
        let dir = resolve_scratch_dir_with(
            Path::new("/Users/dev/checkout/.claude/scratch"),
            "tag",
            None,
            None,
            Some(Path::new("/Users/dev/.cache")),
            None,
        );
        // `!is_claude_managed_dir(&dir)` alone would pass for ANY non-`.claude`
        // result, including a wrong branch that happened to land somewhere
        // else entirely — it can't distinguish "took the $XDG_CACHE_HOME
        // fallback" from "went somewhere unrelated" (cadence-hooks#403 code
        // review). Mirror the sibling temp-root test's `starts_with` so this
        // actually pins the branch under test.
        assert!(
            dir.starts_with("/Users/dev/.cache/cadence-hooks/test-scratch"),
            "must take the $XDG_CACHE_HOME fallback, not just land somewhere non-.claude: {}",
            dir.display()
        );
        assert!(!is_claude_managed_dir(&dir));
    }

    #[test]
    #[should_panic(expected = "CADENCE_HOOKS_TEST_SCRATCH_ROOT")]
    fn resolve_panics_when_nothing_escapes_the_carveout() {
        let tmpdir = temp_carveout_tmpdir();
        let _ = resolve_scratch_dir_with(
            &temp_carveout_root("nothing-escapes"),
            "tag",
            Some(&tmpdir),
            None,
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "itself sits under a carve-out")]
    fn resolve_panics_when_the_override_itself_is_carved_out() {
        let tmpdir = temp_carveout_tmpdir();
        let bad_override = temp_carveout_root("bad-override");
        let _ = resolve_scratch_dir_with(
            &temp_carveout_root("default"),
            "tag",
            Some(&tmpdir),
            Some(&bad_override),
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "carve-out")]
    fn resolve_panics_when_xdg_cache_home_itself_is_carved_out_and_no_override() {
        // A gap in the earlier fallback-chain tests: none of them passed an
        // `xdg_cache_home` that is ITSELF under a carve-out (as opposed to
        // `None`) — so the "nothing escapes" panic path was pinned only for
        // a missing `$XDG_CACHE_HOME`, not a carved-out one. Both must panic;
        // this exercises the other branch (cadence-hooks#403 code review).
        let tmpdir = temp_carveout_tmpdir();
        let carved_out_xdg_cache_home = temp_carveout_root("carved-out-xdg-cache-home");
        let _ = resolve_scratch_dir_with(
            &temp_carveout_root("default"),
            "tag",
            Some(&tmpdir),
            None,
            Some(&carved_out_xdg_cache_home),
            None,
        );
    }

    #[test]
    #[cfg(unix)]
    fn resolve_scratch_dir_resolves_symlinks_before_checking_the_carveout() {
        // A checkout reached via a symlink can have a LITERAL path that
        // doesn't look like a carve-out, while resolving — as `git
        // rev-parse --show-toplevel` (what the guard under test actually
        // uses) resolves — to a real location that IS one. Verified
        // empirically (cadence-hooks#403 code review / CodeRabbit): a
        // symlink at a non-carve-out path pointing into `/tmp` makes `git
        // rev-parse --show-toplevel`, run from inside it, report the
        // resolved `/private/tmp/...` form, not the symlinked literal path.
        // A lexical-only carve-out check would miss this and hand back a
        // fixture the real guard machinery still treats as exempt.
        let real_target = Path::new("/tmp/git-fixtures-symlink-target-check");
        let _ = std::fs::remove_dir_all(real_target);
        std::fs::create_dir_all(real_target).unwrap();

        // The symlink itself must live at a location guaranteed non-carve-out
        // REGARDLESS of where this test's own checkout sits — `scratch_root()`
        // won't do, since it's checkout-relative and would itself be under
        // `/tmp` when this suite runs from a `/tmp` worktree (exactly the
        // scenario this fix targets), which would make the sanity assertion
        // below fail for the wrong reason. `xdg_cache_home()` is the one
        // location this module already treats as reliably outside every
        // carve-out.
        let symlink_parent = xdg_cache_home()
            .expect("test environment must have $XDG_CACHE_HOME or a resolvable home directory")
            .join("git-fixtures-symlink-check");
        std::fs::create_dir_all(&symlink_parent).unwrap();
        let symlink_root = symlink_parent.join("symlink-checkout-check");
        let _ = std::fs::remove_file(&symlink_root);
        std::os::unix::fs::symlink(real_target, &symlink_root).unwrap();

        // Sanity: the literal path does NOT lexically look like a carve-out.
        assert!(
            !path_under_temp_root(&symlink_root.join("tag-x"), None, None),
            "test setup: the symlink's literal path must not itself start with /tmp"
        );

        let dir = resolve_scratch_dir_with(
            &symlink_root,
            "symlink-check",
            None,
            None,
            Some(Path::new("/Users/dev/.cache")),
            None,
        );
        assert!(
            dir.starts_with("/Users/dev/.cache/cadence-hooks/test-scratch"),
            "must relocate via the $XDG_CACHE_HOME fallback — the symlink resolves under /tmp \
             even though its literal path doesn't: {}",
            dir.display()
        );

        let _ = std::fs::remove_file(&symlink_root);
        let _ = std::fs::remove_dir_all(&symlink_parent);
        let _ = std::fs::remove_dir_all(real_target);
    }

    /// An absolute path on EVERY platform.
    ///
    /// A `/`-leading literal like `/Users/dev` is absolute on unix but NOT on
    /// Windows, where `Path::is_absolute` demands a prefix (`C:\`). Since
    /// `xdg_cache_home_from` now filters on absoluteness, feeding it unix
    /// literals would make these tests fail on Windows only — the same shape
    /// that took two CI rounds to find in #507. `temp_dir()` is absolute
    /// everywhere, and nothing here touches the filesystem.
    fn abs_for_test(tag: &str) -> PathBuf {
        std::env::temp_dir().join(tag)
    }

    #[test]
    fn xdg_cache_home_from_prefers_the_env_var() {
        let custom = abs_for_test("custom-cache-home");
        let dir = xdg_cache_home_from(
            Some(custom.to_string_lossy().into_owned()),
            Some(abs_for_test("dev-home")),
        );
        assert_eq!(dir, Some(custom));
    }

    #[test]
    fn xdg_cache_home_from_falls_back_to_home_when_env_var_is_none() {
        // `None` here simulates `non_empty_var("XDG_CACHE_HOME")` having
        // already turned an empty-but-set `$XDG_CACHE_HOME=""` into `None` —
        // that filtering is `non_empty_var`'s job (tested in `paths.rs`), not
        // this function's; this pins `xdg_cache_home_from`'s OWN composition
        // rule: `None` falls back to `home.join(".cache")`.
        let home = abs_for_test("dev-home");
        let dir = xdg_cache_home_from(None, Some(home.clone()));
        assert_eq!(dir, Some(home.join(".cache")));
    }

    #[test]
    fn xdg_cache_home_from_ignores_a_relative_env_value() {
        // #516 review. `non_empty_var` only strips the EMPTY spelling; a
        // non-empty relative value (`XDG_CACHE_HOME=cache`) reaches here
        // intact and would otherwise be taken as-is — resolving against the
        // test binary's cwd, which is exactly the checkout-relative outcome
        // this whole fallback exists to avoid. The XDG base-directory spec
        // says to ignore a relative value; so does this.
        let home = abs_for_test("dev-home");

        // Positive control: an absolute value of the same shape IS taken, so
        // the assertion below discriminates on absoluteness rather than
        // passing for some unrelated reason.
        let absolute = abs_for_test("cache");
        assert_eq!(
            xdg_cache_home_from(
                Some(absolute.to_string_lossy().into_owned()),
                Some(home.clone())
            ),
            Some(absolute),
            "positive control: an absolute $XDG_CACHE_HOME is honored"
        );

        assert_eq!(
            xdg_cache_home_from(Some("cache".to_string()), Some(home.clone())),
            Some(home.join(".cache")),
            "a relative $XDG_CACHE_HOME is ignored, falling through to home"
        );
    }

    #[test]
    fn xdg_cache_home_from_rejects_a_relative_home_too() {
        // Each candidate is filtered on its own. Filtering the chain once at
        // the end (`a.or(b).filter(..)`) would validate only the winning arm,
        // so a relative env value falling through to an equally relative home
        // would still yield a cwd-relative path. Both must be rejected.
        let dir = xdg_cache_home_from(
            Some("cache".to_string()),
            Some(PathBuf::from("relative-home")),
        );
        assert_eq!(
            dir, None,
            "neither candidate is absolute, so there is no usable cache root"
        );
    }

    #[test]
    fn xdg_cache_home_from_is_none_when_neither_is_available() {
        let dir = xdg_cache_home_from(None, None);
        assert_eq!(dir, None);
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
