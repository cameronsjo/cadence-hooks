//! Resolving Claude Code's global config directory.
//!
//! Claude Code honors a `CLAUDE_CONFIG_DIR` environment variable that relocates
//! its entire global config/state tree (default `~/.claude`). Hooks are **not**
//! handed a config-dir env var at runtime, so any code that resolves a global
//! path must read the variable itself.
//!
//! The variable's value may be a comma-separated list of directories; for the
//! purpose of *writing* state (metrics, persona ledger, insights) we take the
//! first non-empty entry. The pure [`resolve_config_dir`] form keeps the logic
//! unit-testable without touching process env (which is process-global and
//! races parallel tests), mirroring the `expand_tilde`/`expand_tilde_with`
//! split elsewhere in the workspace.

use std::io::Read;
use std::path::{Path, PathBuf};

/// The current user's home directory, portably.
///
/// Tries `HOME` (unix, and set by most shells on Windows too), then the native
/// Windows pair `USERPROFILE` and `HOMEDRIVE`+`HOMEPATH`. Returns `None` only
/// when none of these are set — callers decide their own fallback (a temp dir,
/// an empty string) rather than baking in a unix-only `/tmp`.
pub fn user_home() -> Option<PathBuf> {
    resolve_home(
        non_empty_var("HOME").as_deref(),
        non_empty_var("USERPROFILE").as_deref(),
        non_empty_var("HOMEDRIVE").as_deref(),
        non_empty_var("HOMEPATH").as_deref(),
    )
}

/// Pure form of [`user_home`]: pick the home directory from the candidate env
/// values in precedence order (`HOME` → `USERPROFILE` → `HOMEDRIVE`+`HOMEPATH`).
/// Kept env-free so the precedence is unit-testable without mutating
/// process-global state, mirroring the [`resolve_config_dir`] split.
pub fn resolve_home(
    home: Option<&str>,
    userprofile: Option<&str>,
    homedrive: Option<&str>,
    homepath: Option<&str>,
) -> Option<PathBuf> {
    if let Some(home) = home {
        return Some(PathBuf::from(home));
    }
    if let Some(profile) = userprofile {
        return Some(PathBuf::from(profile));
    }
    match (homedrive, homepath) {
        (Some(drive), Some(path)) => Some(PathBuf::from(format!("{drive}{path}"))),
        _ => None,
    }
}

/// [`user_home`] as a `String`, empty when no home directory resolves.
///
/// For the string-prefix path comparisons (dotfile matching, `~` expansion in
/// shell-path parsing) where a `PathBuf` is unwieldy and an empty string is the
/// right "matches nothing" sentinel. Sites that need a writable fallback should
/// use `user_home().unwrap_or_else(marker_temp_dir)` instead.
pub fn user_home_lossy_or_default() -> String {
    user_home()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The system temp directory, portably (`%TEMP%` on Windows, `/tmp` on unix).
///
/// Wraps [`std::env::temp_dir`] so marker/state files land in a writable
/// per-platform location instead of a hardcoded `/tmp` that does not exist on
/// native Windows.
pub fn marker_temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Read an environment variable, treating empty as unset.
fn non_empty_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Walk up from `start` to the first directory containing a `.git` entry.
///
/// `.git` may be a directory (normal checkout) or a file (linked worktree);
/// `Path::exists` catches both. Returns `None` if no ancestor has one. Used by
/// guards that read a per-repo `<git-root>/.claude/*.json` override file.
pub fn find_git_root(start: &str) -> Option<PathBuf> {
    let mut dir = PathBuf::from(start);
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// True when `path` resolves inside `dir` (string-prefix on normalized paths).
///
/// Existence-independent — a purely lexical containment test, so it holds for a
/// Write to a not-yet-created file. `path` arrives forward-slash-normalized
/// (from `HookInput::file_path`), but `dir` is a native `PathBuf` whose
/// `to_string_lossy` is backslash-joined on Windows. Normalize both sides so the
/// prefix test is separator-agnostic. Any `..` in `path` is rejected outright so
/// a traversal target can never be judged "within".
pub fn is_within(path: &str, dir: &Path) -> bool {
    let path = crate::normalize_path(path);
    if path.contains("..") {
        return false;
    }
    let needle = format!("{}/", crate::normalize_path(&dir.to_string_lossy()));
    path.starts_with(&needle)
}

/// Cap for an untrusted per-repo `.claude/*.json` read. These are tiny
/// hand-authored exemption lists; 1 MiB is ~100–1000x any legitimate size and
/// bounds a pathological/malicious multi-GB blob from OOM-ing the hook.
const MAX_UNTRUSTED_CONFIG_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Read a per-repo, repo-controlled `.claude/*.json` config safely.
///
/// Rejects anything that is not a **regular file** (metadata() follows
/// symlinks, so a link to /dev/zero or a FIFO resolves to a non-regular
/// target and is rejected on `stat`, before any blocking read) and caps the
/// read at [`MAX_UNTRUSTED_CONFIG_BYTES`]. Returns `None` on any rejection or
/// IO error so callers fail open (ADR-0001): a rejected config == a missing one.
pub fn read_untrusted_config(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None; // FIFO / device / dir / broken symlink
    }
    if meta.len() > MAX_UNTRUSTED_CONFIG_BYTES {
        return None; // oversized regular file
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    file.take(MAX_UNTRUSTED_CONFIG_BYTES) // TOCTOU belt-and-suspenders
        .read_to_string(&mut buf)
        .ok()?; // non-UTF8 → None (same as read_to_string)
    Some(buf)
}

/// Resolve a checkout's git **common directory** — the shared `.git` that holds
/// repo-wide plumbing (`info/exclude`, `refs`, `objects`) for the primary
/// checkout and every linked worktree of the same repository.
///
/// Pure filesystem walk, no `git` spawn (this is the future primitive for the
/// #164 worktree classifier — keep it dependency-free):
/// - `.git` is a directory → that directory is the common dir.
/// - `.git` is a file (`gitdir: <path>`) → parse the target worktree admin dir,
///   then read its `commondir` file to reach the shared `.git`. A relative
///   `gitdir` joins against `repo_root`; a relative `commondir` joins against the
///   admin dir. No `commondir` file → the admin dir is itself the common dir
///   (submodule layout).
///
/// Returns `None` unless the resolved directory looks like a real git dir (a
/// `HEAD` entry exists). The `.git` file is repo-controlled data and downstream
/// callers *write* into the returned dir, so a crafted `gitdir: /Users/x/.ssh`
/// must not resolve — the `HEAD` check bounds where a downstream write can land.
pub fn resolve_git_common_dir(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    let common = if dot_git.is_dir() {
        dot_git
    } else if dot_git.is_file() {
        let gitdir = read_gitdir_file(&dot_git, repo_root)?;
        resolve_commondir(&gitdir)
    } else {
        return None;
    };
    // A real git dir has a HEAD. This bounds a crafted `.git` file that would
    // otherwise point a downstream write at an arbitrary directory.
    common.join("HEAD").exists().then_some(common)
}

/// Parse a `.git` *file*'s `gitdir: <path>` line into the worktree admin dir,
/// joining a relative target against the `.git` file's parent (`repo_root`).
///
/// `pub(crate)` so [`crate::gitstate`] can resolve a linked worktree's admin
/// dir (which holds that worktree's own `HEAD`) without re-deriving the parse.
pub(crate) fn read_gitdir_file(dot_git_file: &Path, repo_root: &Path) -> Option<PathBuf> {
    let contents = std::fs::read_to_string(dot_git_file).ok()?;
    let target = contents
        .lines()
        .find_map(|l| l.trim().strip_prefix("gitdir:"))
        .map(str::trim)?;
    Some(join_maybe_relative(target, repo_root))
}

/// Read `<gitdir>/commondir` to reach the shared `.git`; absent or empty →
/// `gitdir` itself is the common dir (a submodule has no separate common dir).
fn resolve_commondir(gitdir: &Path) -> PathBuf {
    match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(raw) => {
            let rel = raw.trim();
            if rel.is_empty() {
                gitdir.to_path_buf()
            } else {
                join_maybe_relative(rel, gitdir)
            }
        }
        Err(_) => gitdir.to_path_buf(),
    }
}

/// Join `p` against `base` when relative; return it as-is when absolute.
fn join_maybe_relative(p: &str, base: &Path) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

/// Claude Code's global config dir, honoring `CLAUDE_CONFIG_DIR` (else `~/.claude`).
pub fn claude_config_dir() -> PathBuf {
    let cfg = std::env::var("CLAUDE_CONFIG_DIR").ok();
    let home = user_home().unwrap_or_else(marker_temp_dir);
    resolve_config_dir(cfg.as_deref(), &home.to_string_lossy())
}

/// Pure form: first non-empty comma entry of `config_dir`, `~`-expanded;
/// else `<home>/.claude`.
pub fn resolve_config_dir(config_dir: Option<&str>, home: &str) -> PathBuf {
    if let Some(first) = config_dir.and_then(|raw| {
        raw.split(',')
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(str::to_owned)
    }) {
        return expand_tilde_with(&first, home);
    }
    PathBuf::from(home).join(".claude")
}

/// Replace a leading `~/` (or a bare `~`) with `home`; pass other paths through.
pub fn expand_tilde_with(s: &str, home: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        PathBuf::from(home).join(rest)
    } else if s == "~" {
        PathBuf::from(home)
    } else {
        PathBuf::from(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_falls_back_to_home_dot_claude() {
        assert_eq!(
            resolve_config_dir(None, "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn empty_string_falls_back_to_home_dot_claude() {
        assert_eq!(
            resolve_config_dir(Some(""), "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn single_absolute_path() {
        assert_eq!(
            resolve_config_dir(Some("/custom/claude"), "/home/test"),
            PathBuf::from("/custom/claude")
        );
    }

    #[test]
    fn tilde_prefixed_path_expands() {
        assert_eq!(
            resolve_config_dir(Some("~/work-claude"), "/home/test"),
            PathBuf::from("/home/test/work-claude")
        );
    }

    #[test]
    fn comma_list_takes_first_entry() {
        assert_eq!(
            resolve_config_dir(Some("/first,/second,/third"), "/home/test"),
            PathBuf::from("/first")
        );
    }

    #[test]
    fn leading_empty_comma_entry_is_skipped() {
        assert_eq!(
            resolve_config_dir(Some(",/real"), "/home/test"),
            PathBuf::from("/real")
        );
    }

    #[test]
    fn whitespace_around_entries_is_trimmed() {
        assert_eq!(
            resolve_config_dir(Some("  /spaced  ,  /other  "), "/home/test"),
            PathBuf::from("/spaced")
        );
    }

    #[test]
    fn all_empty_entries_fall_back() {
        assert_eq!(
            resolve_config_dir(Some(" , , "), "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn resolve_home_prefers_home() {
        assert_eq!(
            resolve_home(
                Some("/home/u"),
                Some(r"C:\Users\u"),
                Some("C:"),
                Some(r"\Users\u")
            ),
            Some(PathBuf::from("/home/u"))
        );
    }

    #[test]
    fn resolve_home_falls_back_to_userprofile() {
        assert_eq!(
            resolve_home(None, Some(r"C:\Users\u"), Some("C:"), Some(r"\Users\u")),
            Some(PathBuf::from(r"C:\Users\u"))
        );
    }

    #[test]
    fn resolve_home_joins_homedrive_and_homepath() {
        assert_eq!(
            resolve_home(None, None, Some("C:"), Some(r"\Users\u")),
            Some(PathBuf::from(r"C:\Users\u"))
        );
    }

    #[test]
    fn resolve_home_none_when_all_absent() {
        assert_eq!(resolve_home(None, None, None, None), None);
    }

    #[test]
    fn resolve_home_needs_both_homedrive_and_homepath() {
        assert_eq!(resolve_home(None, None, Some("C:"), None), None);
        assert_eq!(resolve_home(None, None, None, Some(r"\Users\u")), None);
    }

    #[test]
    fn marker_temp_dir_is_absolute() {
        // std::env::temp_dir is always an absolute, existing-or-creatable path
        // on every supported platform; we only assert it is non-empty/absolute.
        assert!(marker_temp_dir().is_absolute());
    }

    // --- resolve_git_common_dir (#130 / #164 primitive) ---

    #[test]
    fn common_dir_plain_checkout_is_dot_git() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        assert_eq!(resolve_git_common_dir(tmp.path()), Some(git));
    }

    #[test]
    fn common_dir_linked_worktree_absolute_gitdir() {
        let tmp = tempfile::tempdir().unwrap();
        let primary_git = tmp.path().join("primary").join(".git");
        std::fs::create_dir_all(&primary_git).unwrap();
        std::fs::write(primary_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let admin = primary_git.join("worktrees").join("wt");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(admin.join("commondir"), "../..\n").unwrap();

        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(
            linked.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .unwrap();

        let common = resolve_git_common_dir(&linked).expect("resolves");
        // Points at the primary .git (via ../..); HEAD is reachable through it.
        assert!(common.join("HEAD").exists());
    }

    #[test]
    fn common_dir_linked_worktree_relative_gitdir() {
        let tmp = tempfile::tempdir().unwrap();
        let primary_git = tmp.path().join(".git");
        std::fs::create_dir_all(&primary_git).unwrap();
        std::fs::write(primary_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let admin = primary_git.join("worktrees").join("wt");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(admin.join("commondir"), "../..\n").unwrap();

        // A .git file whose gitdir is RELATIVE to the worktree root.
        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(linked.join(".git"), "gitdir: ../.git/worktrees/wt\n").unwrap();

        let common = resolve_git_common_dir(&linked).expect("resolves relative gitdir");
        assert!(common.join("HEAD").exists());
    }

    #[test]
    fn common_dir_submodule_without_commondir_is_gitdir() {
        // A submodule's .git file points at an admin dir with a HEAD but no
        // commondir file → the admin dir itself is the common dir.
        let tmp = tempfile::tempdir().unwrap();
        let admin = tmp.path().join(".git-modules").join("sub");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(admin.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();

        assert_eq!(resolve_git_common_dir(&sub), Some(admin));
    }

    #[test]
    fn common_dir_garbage_git_file_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".git"), "not a gitdir line\n").unwrap();
        assert_eq!(resolve_git_common_dir(tmp.path()), None);
    }

    #[test]
    fn common_dir_resolved_without_head_is_none() {
        // A crafted `.git` file pointing at a real dir that has NO HEAD must not
        // resolve — otherwise a downstream write could land anywhere (#147/#130).
        let tmp = tempfile::tempdir().unwrap();
        let evil = tmp.path().join("not-a-git-dir");
        std::fs::create_dir_all(&evil).unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();
        assert_eq!(resolve_git_common_dir(&repo), None);
    }

    #[test]
    fn common_dir_absent_git_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(resolve_git_common_dir(tmp.path()), None);
    }

    #[test]
    fn expand_tilde_with_handles_prefix_bare_and_absolute() {
        assert_eq!(
            expand_tilde_with("~/x/y", "/home/test"),
            PathBuf::from("/home/test/x/y")
        );
        assert_eq!(
            expand_tilde_with("~", "/home/test"),
            PathBuf::from("/home/test")
        );
        assert_eq!(
            expand_tilde_with("/abs/path", "/home/test"),
            PathBuf::from("/abs/path")
        );
    }

    // --- is_within (containment primitive, promoted from lab #139) ---

    #[test]
    fn is_within_checks_prefix_and_traversal() {
        let dir = Path::new("/home/u/.claude/persona/staging");
        assert!(is_within("/home/u/.claude/persona/staging/s1.json", dir));
        assert!(!is_within("/home/u/.claude/persona/personas.jsonl", dir));
        assert!(!is_within("/etc/passwd", dir));
        assert!(!is_within(
            "/home/u/.claude/persona/staging/../personas.jsonl",
            dir
        ));
    }

    #[test]
    fn is_within_rejects_any_traversal_component() {
        let dir = Path::new("/home/u/cadence-hooks");
        // A `..` anywhere in the candidate path is rejected outright.
        assert!(!is_within("/home/u/cadence-hooks/../evil.md", dir));
        assert!(!is_within("/home/u/cadence-hooks/a/../../evil.md", dir));
    }

    #[test]
    fn is_within_normalizes_backslash_dir() {
        // On Windows the dir is backslash-joined while the hook path is
        // forward-slash-normalized; both sides must normalize to match.
        let dir = Path::new(r"C:\Users\u\.claude\persona\staging");
        assert!(is_within("C:/Users/u/.claude/persona/staging/s1.json", dir));
        assert!(!is_within("C:/Users/u/.claude/persona/personas.jsonl", dir));
    }

    #[test]
    fn is_within_prefix_boundary_needs_separator() {
        // A sibling dir sharing a name prefix must NOT be judged "within" —
        // the trailing `/` on the needle enforces the component boundary.
        let dir = Path::new("/home/u/cadence-hooks");
        assert!(is_within("/home/u/cadence-hooks/crates/x.rs", dir));
        assert!(!is_within("/home/u/cadence-hooks-legacy/x.rs", dir));
    }

    // --- read_untrusted_config (#157 special-file DoS hardening) ---

    #[test]
    fn read_untrusted_config_reads_small_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, r#"{"ok":true}"#).unwrap();
        assert_eq!(
            read_untrusted_config(&path),
            Some(r#"{"ok":true}"#.to_string())
        );
    }

    #[test]
    fn read_untrusted_config_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_untrusted_config(&tmp.path().join("absent.json")), None);
    }

    #[test]
    fn read_untrusted_config_rejects_directory() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_untrusted_config(tmp.path()), None);
    }

    #[test]
    fn read_untrusted_config_rejects_oversized() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.json");
        // One byte over the 1 MiB cap.
        std::fs::write(&path, vec![b'x'; (1024 * 1024) + 1]).unwrap();
        assert_eq!(read_untrusted_config(&path), None);
    }

    #[test]
    fn read_untrusted_config_reads_at_or_below_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atcap.json");
        // Just under the cap → accepted.
        let body = vec![b'y'; (1024 * 1024) - 1];
        std::fs::write(&path, &body).unwrap();
        let read = read_untrusted_config(&path).expect("under-cap file reads");
        assert_eq!(read.len(), body.len());
    }

    #[cfg(unix)]
    #[test]
    fn read_untrusted_config_rejects_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fifo.json");
        // mkfifo via the system binary keeps the dev-deps unchanged.
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("spawn mkfifo");
        assert!(status.success(), "mkfifo failed");
        // A FIFO is not a regular file → rejected on stat, no blocking read.
        assert_eq!(read_untrusted_config(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn read_untrusted_config_rejects_symlink_to_dev_zero() {
        // The headline DoS: a symlink to an endless special file. metadata()
        // follows the link to a non-regular target, so it is rejected on stat —
        // this test must NOT hang.
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("evil.json");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert_eq!(read_untrusted_config(&link), None);
    }
}
