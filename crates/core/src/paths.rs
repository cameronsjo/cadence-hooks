//! Resolving Claude Code's global config directory.
//!
//! Claude Code honors a `CLAUDE_CONFIG_DIR` environment variable that relocates
//! its entire global config/state tree (default `~/.claude`). Hooks are **not**
//! handed a config-dir env var at runtime, so any code that resolves a global
//! path must read the variable itself.
//!
//! The variable's value may be a comma-separated list of directories; for the
//! purpose of *writing* state (metrics, insights) we take the
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
///
/// `pub(crate)`, not private: [`crate::git_fixtures`]'s `xdg_cache_home`
/// (née `cargo_home`, cadence-hooks#505) reuses this for the identical
/// empty-var-is-unset rule rather than hand-rolling it a second time
/// (cadence-hooks#403 code review).
pub(crate) fn non_empty_var(key: &str) -> Option<String> {
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

/// Path fragments that mark a cloud-sync provider's local mirror.
///
/// Matched case-insensitively against a path's own components, never as a bare
/// substring — `~/src/dropbox-client` is a project, not a synced tree, and a
/// substring test would flag it. Each entry is a directory NAME a provider
/// creates: macOS iCloud Drive lives under `Library/Mobile Documents`, and
/// modern macOS third-party providers mount under `Library/CloudStorage`.
pub const CLOUD_SYNC_MARKERS: &[&str] = &[
    "OneDrive",
    "Dropbox",
    "CloudStorage",
    "Mobile Documents",
    "Google Drive",
    "GoogleDrive",
    "pCloud Drive",
    "Sync.com",
    "iCloudDrive",
    "Nextcloud",
    "ownCloud",
    "Box Sync",
    "MEGA",
    "Proton Drive",
];

/// The provider marker in `path`, if any component names one.
///
/// Component-wise and case-insensitive: a provider directory is a real path
/// segment, so testing components avoids the `dropbox-client` false positive a
/// substring search produces, while still catching a nested repo far below the
/// sync root.
///
/// A component matches on exact equality **or** on a `"<marker> - "` prefix.
/// The second form is not a nicety: a Microsoft 365 business or school tenant
/// syncs to a folder named `OneDrive - <Organization>`, which is the dominant
/// real-world shape of the very deployment this check exists to catch, and
/// exact equality alone silently never fires for it. The separator is spelled
/// with surrounding spaces deliberately — a bare `-` boundary would re-admit
/// `dropbox-client`, the exact false positive component matching was chosen to
/// avoid.
pub fn cloud_sync_marker(path: &Path) -> Option<&'static str> {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .find_map(|segment| {
            CLOUD_SYNC_MARKERS
                .iter()
                .find(|m| {
                    segment.eq_ignore_ascii_case(m)
                        || segment.len() > m.len() + 3
                            && segment
                                .get(..m.len())
                                .is_some_and(|h| h.eq_ignore_ascii_case(m))
                            && segment.get(m.len()..).is_some_and(|t| t.starts_with(" - "))
                })
                .copied()
        })
}

/// Does a file at or under `dir` leave the machine with no command at all?
///
/// `Some(true)` when the deepest existing ancestor sits on a file system that
/// is not local (macOS: no `MNT_LOCAL`; Linux: any type but a known local
/// disk or memory file system), or, on macOS, when an ancestor is a File Provider root. iCloud's
/// Desktop & Documents sync marks `~/Documents` that way while its path names
/// no provider, so [`cloud_sync_marker`] cannot see it. `None` when a lookup
/// fails for any reason but absence, and on every other platform: the caller
/// cannot tell.
pub fn syncs_or_mounts_remotely(dir: &Path) -> Option<bool> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut checked_mount = false;
        for d in dir.ancestors() {
            let c = std::ffi::CString::new(d.as_os_str().as_bytes()).ok()?;
            if !checked_mount {
                match is_remote_mount(&c) {
                    Ok(true) => return Some(true),
                    Ok(false) => checked_mount = true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return None,
                }
            }
            #[cfg(target_os = "macos")]
            if is_file_provider_root(&c)? {
                return Some(true);
            }
        }
        checked_mount.then_some(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // No mount check here (a Windows share or mapped drive looks like
        // any other path), so this cannot tell.
        let _ = dir;
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_remote_mount(path: &std::ffi::CStr) -> std::io::Result<bool> {
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `buf` is a writable `statfs`; the
    // struct is read only after the call reports success.
    let rc = unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `statfs` returned 0, so it filled `buf`.
    let st = unsafe { buf.assume_init() };
    #[cfg(target_os = "macos")]
    {
        Ok(st.f_flags & libc::MNT_LOCAL as u32 == 0)
    }
    #[cfg(target_os = "linux")]
    {
        // Local disk and memory file systems (statfs(2)). Anything else,
        // NFS, SMB, FUSE, a cluster file system or a type added later, counts
        // as remote: a list of remote types is never complete.
        const LOCAL: &[u64] = &[
            0xEF53,      // ext2/3/4
            0x5846_5342, // XFS
            0x9123_683E, // Btrfs
            0x2FC1_2FC1, // ZFS
            0xF2F5_2010, // F2FS
            0xCA45_1A4E, // bcachefs
            0x0102_1994, // tmpfs
            0x8584_58F6, // ramfs
            0x794C_7630, // overlayfs
            0xF15F,      // eCryptfs (an encrypted home over a local disk)
        ];
        // `f_type` is signed on some targets and unsigned on others.
        #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
        let kind = (st.f_type as u64) & 0xFFFF_FFFF;
        Ok(!LOCAL.contains(&kind))
    }
}

/// Does `path` carry a File Provider domain? `None` when the lookup fails for
/// a reason other than the attribute or the path being absent.
#[cfg(target_os = "macos")]
fn is_file_provider_root(path: &std::ffi::CStr) -> Option<bool> {
    // SAFETY: both strings are NUL-terminated; a null buffer of size 0 asks
    // only for the attribute's length.
    let rc = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"com.apple.file-provider-domain-id".as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if rc >= 0 {
        return Some(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOATTR | libc::ENOENT | libc::ENOTSUP) => Some(false),
        _ => None,
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
pub const MAX_UNTRUSTED_CONFIG_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Why a capped read yielded no text.
///
/// [`read_capped`] collapses all four to `None`, which is the right answer for
/// a config load that fails open either way. A caller that must *say something*
/// about an oversized file needs them apart, so the detailed readers hand back
/// this instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedReadError {
    /// Missing, permission-denied, or any other IO error. The file is not
    /// there for anyone, so a caller that fails open on it loses nothing.
    Unreadable,
    /// The path exists but is not a regular file — a FIFO, a device, a
    /// directory, or a `/dev/fd/N` process substitution.
    ///
    /// **Apart from [`Unreadable`](CappedReadError::Unreadable) because the two
    /// mean opposite things to a guard.** A missing path yields nothing to the
    /// command either; a FIFO yields its content to the command and nothing to
    /// the reader, because reading it here would consume the stream (and can
    /// block forever). A guard that measures file content must refuse this
    /// shape rather than wave it through as if the file were absent.
    NotRegular,
    /// The bytes are not valid UTF-8.
    NotUtf8,
    /// The content exceeds the cap.
    OverCap,
}

/// Read a per-repo, repo-controlled `.claude/*.json` config safely — the
/// [`read_capped`] discipline at [`MAX_UNTRUSTED_CONFIG_BYTES`].
pub fn read_untrusted_config(path: &Path) -> Option<String> {
    read_capped(path, MAX_UNTRUSTED_CONFIG_BYTES)
}

/// [`read_untrusted_config`], reporting why a read yielded nothing.
pub fn read_untrusted_config_detailed(path: &Path) -> Result<String, CappedReadError> {
    read_capped_detailed(path, MAX_UNTRUSTED_CONFIG_BYTES)
}

/// Read a small untrusted file whole, or reject it: `None` when it is not a
/// regular file, when its content exceeds `max_bytes`, or on any IO error —
/// so callers fail open (ADR-0001), a rejected file being the same as a
/// missing one.
///
/// The non-regular check must happen on `stat` **before** the open: a FIFO
/// blocks on open, so rejecting it afterwards would be too late (`metadata()`
/// follows symlinks, so a link to `/dev/zero` or to a FIFO resolves to its
/// non-regular target and is caught here too).
///
/// **The size cap is enforced by the read, never by `st_size`.** A
/// `/proc`-style file on Linux reports a size of 0 and then yields unbounded
/// content, so a `metadata().len()` pre-check would wave it through — reading
/// `max_bytes + 1` and rejecting a buffer that fills it holds the cap on an
/// honest file and a liar identically, with at most one extra byte read. This
/// is the same take-then-check discipline `session::persist_plan`'s
/// `file_matches_body` uses.
///
/// For a file whose *tail* is what matters — a session transcript — use
/// `crate::transcript::read_tail` instead: this reads from the front, and
/// rejects rather than truncates.
pub fn read_capped(path: &Path, max_bytes: u64) -> Option<String> {
    read_capped_detailed(path, max_bytes).ok()
}

/// Open `path` for reading without blocking on a FIFO with no writer, and
/// without letting a terminal device become the process's controlling
/// terminal (`O_NOCTTY`). `O_NONBLOCK` has no effect on a regular file's reads.
pub fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// Open `path` as a regular file WITHOUT following a symlink at its final
/// component and without blocking on a FIFO: `O_NOFOLLOW | O_NONBLOCK |
/// O_NOCTTY | O_CLOEXEC`, then the OPENED handle must `fstat` as a regular
/// file. `None` for a symlink, FIFO, device, directory, or any IO error, so a
/// planted non-regular file at a predictable path reads as absent instead of
/// stalling the hook until its deadline (cameronsjo/cadence-hooks#1256). No
/// stat-then-open window: the verdict is on the handle actually read. Off
/// Unix it is a plain open plus the same handle check.
pub fn open_regular_nofollow(path: &Path) -> Option<std::fs::File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)
            .ok()?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// [`read_capped`] through [`open_regular_nofollow`]: whole-file UTF-8 read of
/// a regular, non-symlink file of at most `max_bytes`, else `None`.
pub fn read_capped_nofollow(path: &Path, max_bytes: u64) -> Option<String> {
    read_opened_capped(open_regular_nofollow(path)?, max_bytes).ok()
}

/// [`read_capped`], reporting *why* instead of collapsing to `None`. The single
/// implementation — `read_capped` is a projection of it, so the two can never
/// drift on where the cap sits or what counts as a readable file.
///
/// The non-UTF-8 case is distinguished by `ErrorKind::InvalidData`, which is
/// exactly what `read_to_string` raises for bytes that are not valid UTF-8;
/// every other IO error is [`CappedReadError::Unreadable`].
pub fn read_capped_detailed(path: &Path, max_bytes: u64) -> Result<String, CappedReadError> {
    let meta = std::fs::metadata(path).map_err(|_| CappedReadError::Unreadable)?;
    if !meta.is_file() {
        // FIFO / device / dir. A broken symlink is NOT here: `metadata`
        // follows the link, fails, and returns `Unreadable` above.
        return Err(CappedReadError::NotRegular);
    }
    // The `stat` above follows the path; the path can be swapped for a FIFO
    // between it and the open. Opening non-blocking keeps that FIFO from
    // blocking the open itself, and re-checking the OPENED handle (`fstat`)
    // decides on the object actually read — the pre-check stays only as the
    // cheap early answer.
    let file = open_nonblocking(path).map_err(|_| CappedReadError::Unreadable)?;
    read_opened_capped(file, max_bytes)
}

/// The post-open half of [`read_capped_detailed`]: judge the OPENED handle by
/// `fstat`, then read at most `max_bytes + 1`. Split out so the fstat check —
/// the one that closes the stat/open race — is testable on its own, since the
/// path-level `stat` answers first whenever no race occurs.
fn read_opened_capped(file: std::fs::File, max_bytes: u64) -> Result<String, CappedReadError> {
    if !file
        .metadata()
        .map_err(|_| CappedReadError::Unreadable)?
        .is_file()
    {
        return Err(CappedReadError::NotRegular);
    }
    let mut buf = String::new();
    file.take(max_bytes + 1)
        .read_to_string(&mut buf)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => CappedReadError::NotUtf8,
            _ => CappedReadError::Unreadable,
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(CappedReadError::OverCap);
    }
    Ok(buf)
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
    // Repo-controlled data, same untrusted-input class as `.claude/*.json` —
    // bounded so a crafted or pathological `.git` file can't OOM a hook that
    // now runs on every metrics write (`repo_basename`'s `GitState::resolve`
    // path), not just the occasional guard invocation.
    let contents = read_capped(dot_git_file, MAX_UNTRUSTED_CONFIG_BYTES)?;
    let target = contents
        .lines()
        .find_map(|l| l.trim().strip_prefix("gitdir:"))
        .map(str::trim)?;
    Some(join_maybe_relative(target, repo_root))
}

/// Read `<gitdir>/commondir` to reach the shared `.git`; absent or empty →
/// `gitdir` itself is the common dir (a submodule has no separate common dir).
fn resolve_commondir(gitdir: &Path) -> PathBuf {
    // Same bounded-read discipline as `read_gitdir_file` above — repo-controlled,
    // on the same hot path.
    match read_capped(&gitdir.join("commondir"), MAX_UNTRUSTED_CONFIG_BYTES) {
        Some(raw) => {
            let rel = raw.trim();
            if rel.is_empty() {
                gitdir.to_path_buf()
            } else {
                join_maybe_relative(rel, gitdir)
            }
        }
        None => gitdir.to_path_buf(),
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
    if let Some(first) = first_config_entry(config_dir) {
        return expand_tilde_with(first, home);
    }
    PathBuf::from(home).join(".claude")
}

/// The first usable entry of a `CLAUDE_CONFIG_DIR` value: comma-split and
/// trimmed, first non-empty one wins. The one place that rule is written.
fn first_config_entry(config_dir: Option<&str>) -> Option<&str> {
    config_dir.and_then(|raw| raw.split(',').map(str::trim).find(|s| !s.is_empty()))
}

/// Does a `CLAUDE_CONFIG_DIR` value carry at least one usable entry?
///
/// The predicate behind [`resolve_config_dir`]'s first branch, exposed so a
/// caller that must decide *whether* a config dir was named — rather than
/// which one — asks the same question the resolver answers, instead of a
/// looser `!value.is_empty()` that accepts a degenerate `","` or `" "`
/// the resolver itself treats as unset (cadence-hooks#599).
pub fn config_dir_is_named(config_dir: Option<&str>) -> bool {
    first_config_entry(config_dir).is_some()
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
    #[test]
    fn cloud_sync_marker_survives_a_multibyte_component() {
        // Byte 8 of "OneDrivé…" falls inside `é`; slicing there used to panic.
        let path = std::path::Path::new("/Users/x/OneDrivé - Acme/repo");
        assert_eq!(super::cloud_sync_marker(path), None);
        let path = std::path::Path::new("/Users/x/OneDrive - Acmé/repo");
        assert_eq!(super::cloud_sync_marker(path), Some("OneDrive"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_plain_temp_dir_is_local_and_a_missing_tail_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(super::syncs_or_mounts_remotely(dir.path()), Some(false));
        let tail = dir.path().join("not/yet/here");
        assert_eq!(super::syncs_or_mounts_remotely(&tail), Some(false));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn other_platforms_cannot_tell() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(super::syncs_or_mounts_remotely(dir.path()), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_provider_root_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let ok = std::process::Command::new("xattr")
            .args(["-w", "com.apple.file-provider-domain-id", "fixture"])
            .arg(dir.path())
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let below = dir.path().join("sub/new");
        assert_eq!(super::syncs_or_mounts_remotely(&below), Some(true));
    }

    #[cfg(unix)]
    #[test]
    fn opened_fifo_is_rejected_by_fstat_without_blocking() {
        // #818 review N3: a path swapped for a FIFO after the `stat` must be
        // refused on the handle. Opening non-blocking must not hang with no
        // writer, and the fstat must answer NotRegular before any read.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("spawn mkfifo");
        assert!(status.success());
        let file = open_nonblocking(&fifo).expect("non-blocking open of a FIFO");
        assert_eq!(
            read_opened_capped(file, 1024),
            Err(CappedReadError::NotRegular)
        );
        let regular = dir.path().join("f");
        std::fs::write(&regular, "use flake\n").unwrap();
        let file = open_nonblocking(&regular).unwrap();
        assert_eq!(read_opened_capped(file, 1024).as_deref(), Ok("use flake\n"));
    }

    #[cfg(unix)]
    #[test]
    fn read_capped_nofollow_table() {
        // cameronsjo/cadence-hooks#1256 M-3: a planted FIFO or symlink at a
        // predictable plan path reads as absent, never stalls, never follows.
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("plan.md");
        std::fs::write(&regular, "body\n").unwrap();
        let big = dir.path().join("big.md");
        std::fs::write(&big, "x".repeat(65)).unwrap();
        let fifo = dir.path().join("fifo.md");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let link = dir.path().join("link.md");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let cases: [(&Path, Option<&str>); 6] = [
            (&regular, Some("body\n")),
            (&big, None),
            (&fifo, None),
            (&link, None),
            (&sub, None),
            (Path::new("/nonexistent/plan.md"), None),
        ];
        for (path, want) in cases {
            assert_eq!(
                read_capped_nofollow(path, 64).as_deref(),
                want,
                "{}",
                path.display()
            );
        }
    }

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
    fn config_dir_is_named_agrees_with_the_resolver() {
        // The predicate must answer "did this value name a dir?" for exactly
        // the values `resolve_config_dir` takes its first branch on — the two
        // reading the same value differently is the bug it exists to prevent.
        for named in ["/custom/claude", "~/work-claude", ",/real", "  /spaced  "] {
            assert!(config_dir_is_named(Some(named)), "{named:?} names a dir");
            assert_ne!(
                resolve_config_dir(Some(named), "/home/test"),
                PathBuf::from("/home/test/.claude"),
                "{named:?} must not fall back"
            );
        }
        for unnamed in [",", " , , ", " ", ""] {
            assert!(
                !config_dir_is_named(Some(unnamed)),
                "{unnamed:?} names none"
            );
            assert_eq!(
                resolve_config_dir(Some(unnamed), "/home/test"),
                PathBuf::from("/home/test/.claude"),
                "{unnamed:?} must fall back"
            );
        }
        assert!(!config_dir_is_named(None), "an unset var names none");
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
        let dir = Path::new("/home/u/.claude/metrics/staging");
        assert!(is_within("/home/u/.claude/metrics/staging/s1.json", dir));
        assert!(!is_within("/home/u/.claude/metrics/commits.jsonl", dir));
        assert!(!is_within("/etc/passwd", dir));
        assert!(!is_within(
            "/home/u/.claude/metrics/staging/../commits.jsonl",
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
        let dir = Path::new(r"C:\Users\u\.claude\metrics\staging");
        assert!(is_within("C:/Users/u/.claude/metrics/staging/s1.json", dir));
        assert!(!is_within("C:/Users/u/.claude/metrics/commits.jsonl", dir));
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

    // --- read_capped: the take-then-check gate (#361) ---

    #[test]
    fn read_capped_accepts_exactly_the_cap() {
        // The boundary of the take-then-check arithmetic: `take(max + 1)` fills
        // to max on a file of exactly max, and `len <= max` accepts it. An
        // off-by-one here silently rejects a legitimate at-cap file.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("exact.txt");
        std::fs::write(&path, vec![b'z'; 512]).unwrap();
        assert_eq!(read_capped(&path, 512).map(|s| s.len()), Some(512));
    }

    #[test]
    fn read_capped_rejects_one_byte_over_the_cap() {
        // The other side of the same boundary. This is also the ONLY gate on
        // size — there is no `st_size` pre-check to fall back on — so passing
        // here is what proves the cap is enforced by the read itself, which is
        // what makes it hold on a file that misreports its size (#361).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("over.txt");
        std::fs::write(&path, vec![b'z'; 513]).unwrap();
        assert_eq!(read_capped(&path, 512), None);
    }

    #[test]
    fn read_capped_reads_a_small_file_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("msg.txt");
        std::fs::write(&path, "fix: thing\n\nSession-Id: abc\n").unwrap();
        assert_eq!(
            read_capped(&path, 64 * 1024).as_deref(),
            Some("fix: thing\n\nSession-Id: abc\n")
        );
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
