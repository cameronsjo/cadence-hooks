//! Shared helpers for the metrics loggers: git-commit detection, git queries,
//! metrics directory resolution, and timestamps.

use regex::Regex;
use serde_json::json;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Matches `git commit` and `git -C <dir> commit`, after a start-of-string or a
/// shell separator, while ignoring `git commit-tree` and similar. Ported from
/// the bash `grep -E` pattern.
fn commit_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|[\s;&|])git\s+(-C\s+\S+\s+)?commit(\s|$)")
            .expect("commit regex must compile")
    })
}

/// True when `command` invokes `git commit` (not `git commit-tree`, etc.).
pub fn is_git_commit(command: &str) -> bool {
    commit_regex().is_match(command)
}

/// The metrics root directory.
///
/// Resolution order:
/// 1. `CADENCE_METRICS_DIR` — when set and non-empty, the value **is** the
///    metrics dir (JSONL files and the `state/` subdir live directly inside it).
///    An explicit override always wins — it names an exact directory, not a
///    root to layer the cadence-owned cutover under.
/// 2. `<config_dir>/cadence/metrics` (the "new root") when it already exists —
///    either a fresh install that has started writing there, or a machine
///    the cadence#773 migration script has already run on.
/// 3. `<config_dir>/metrics` (the "legacy root") when it exists and the new
///    root does not — the read-both window: an unmigrated install keeps
///    reading and writing its existing ledgers in place. Resolved through any
///    symlink (cadence-hooks#626, from the cadence#773 B-classify ruling): on
///    a multi-profile machine the legacy root can be a symlink shared across
///    profiles, and operating on the symlink path itself — rather than its
///    target — is exactly what breaks the second profile silently once the
///    first profile's migration moves the shared target.
/// 4. Otherwise (neither root exists — a true fresh install) — the new root,
///    created lazily on first write.
///
/// `<config_dir>` honors `CLAUDE_CONFIG_DIR` and falls back to `~/.claude`
/// (`cadence_hooks_core::paths::claude_config_dir`).
///
/// This binary's job is exactly the new default plus the read-both window —
/// moving *data* already under the legacy root is the monorepo's migration
/// script's job (cadence#773), operator-scheduled after this ships. An
/// earlier relocation attempt stranded ten of twelve live ledgers by skipping
/// that read-both step entirely; this cutover is what closes that gap.
pub fn metrics_dir() -> PathBuf {
    metrics_dir_from(
        std::env::var("CADENCE_METRICS_DIR").ok(),
        cadence_hooks_core::paths::claude_config_dir(),
    )
}

/// Pure-ish resolver behind [`metrics_dir`]: takes the `CADENCE_METRICS_DIR`
/// override and the already-resolved config dir directly, so the write-new /
/// read-both precedence is testable against a temp-dir fixture without
/// mutating `CLAUDE_CONFIG_DIR` (process-global, races parallel tests).
///
/// Only the existence checks below touch the filesystem; the precedence logic
/// itself is a pure function of `(override_dir, config_dir, what's on disk)`.
fn metrics_dir_from(override_dir: Option<String>, config_dir: PathBuf) -> PathBuf {
    if let Some(dir) = override_dir
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    let new_root = config_dir.join("cadence").join("metrics");
    if new_root.is_dir() {
        return new_root;
    }
    let legacy_root = config_dir.join("metrics");
    if legacy_root.is_dir() {
        // Resolve a symlinked legacy root to its real target (see the
        // symlink caveat on `metrics_dir`'s doc comment above). A dangling
        // or non-symlink path canonicalizes to itself or fails; either way,
        // fall back to the un-resolved path rather than losing the read.
        return std::fs::canonicalize(&legacy_root).unwrap_or(legacy_root);
    }
    new_root
}

/// Open a metrics ledger for appending, creating it owner-only (`0600`).
///
/// Every `<metrics_dir>/*.jsonl` writer goes through here (cadence-hooks#425).
/// Rows are privacy-safe by construction, but repo basenames and session ids
/// are still metadata worth keeping from other local users, and the default
/// `OpenOptions` mode is world-readable under a permissive umask. A ledger an
/// older binary already created with group/other bits has exactly those bits
/// cleared through the open handle (owner bits are kept), so existing installs
/// converge on their next write; a mode that is already tighter is left alone.
///
/// On Unix the final path component is opened with `O_NOFOLLOW`: a ledger
/// that is a symlink fails to open, so nothing is appended through it and no
/// chmod lands on whatever it points at. The caller treats that like any other
/// open failure and skips the row (ADR-0001). Permissions are a Unix concept;
/// elsewhere this is a plain create-and-append open. A failed tighten is
/// ignored, so the append still happens.
///
/// Past the size cap ([`ledger_max_bytes`]) the ledger first rotates to
/// a dated segment `<name>.<YYYYMMDDTHHMMSSZ>-<NNN>.jsonl` (cameronsjo/cadence#2074,
/// cameronsjo/cadence-hooks#1585): see [`rotate_if_over_cap`]. A
/// rotation problem is logged and ignored, never returned.
pub fn open_ledger(path: impl AsRef<Path>) -> std::io::Result<std::fs::File> {
    open_ledger_capped(path.as_ref(), ledger_max_bytes())
}

/// Env var that sets the rotation cap, in bytes, for every `<metrics_dir>/*.jsonl`
/// ledger. `0` turns rotation off; unset, empty, or unparsable keeps
/// [`DEFAULT_LEDGER_MAX_BYTES`].
pub const LEDGER_MAX_BYTES_ENV: &str = "CADENCE_METRICS_MAX_BYTES";

/// Default rotation cap: 16 MiB per ledger file. Rotation never deletes a
/// segment, so history is kept whole; the cap only bounds the size of each file
/// a reader loads.
pub const DEFAULT_LEDGER_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Smallest cap honored. Anything lower is almost certainly a unit slip (`16`
/// meaning 16 MiB), and at a few hundred bytes a row it would rotate on every
/// write, scattering each ledger across thousands of two-row segments. A lower
/// value keeps [`DEFAULT_LEDGER_MAX_BYTES`].
pub const MIN_LEDGER_MAX_BYTES: u64 = 1024 * 1024;

/// The rotation cap in bytes, or `None` when `CADENCE_METRICS_MAX_BYTES=0`
/// turned rotation off.
pub fn ledger_max_bytes() -> Option<u64> {
    parse_ledger_max_bytes(std::env::var(LEDGER_MAX_BYTES_ENV).ok().as_deref())
}

fn parse_ledger_max_bytes(raw: Option<&str>) -> Option<u64> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Some(DEFAULT_LEDGER_MAX_BYTES),
        Some(v) => match v.parse::<u64>() {
            Ok(0) => None,
            Ok(n) if n >= MIN_LEDGER_MAX_BYTES => Some(n),
            // An unreadable or implausibly small cap must not silently disable
            // the safeguard or erase history.
            Ok(_) | Err(_) => Some(DEFAULT_LEDGER_MAX_BYTES),
        },
    }
}

/// Upper bound on same-second segment names tried before giving up, and the
/// width of the zero-padded sequence (`000`-`999`). A ledger rotates once per
/// cap's worth of rows, so even one collision is rare.
#[cfg(unix)]
const MAX_SEGMENT_ATTEMPTS: u32 = 1000;

/// The segment `path` rotates to as the `seq`th rotation in the second
/// `stamp` (compact UTC, `YYYYMMDDTHHMMSSZ`): `denials.jsonl` →
/// `denials.<stamp>-<seq as 3 digits>.jsonl`, in the same directory. The fixed
/// width makes byte order of the names equal their time order, so a script
/// can read `<stem>.*.jsonl` sorted by name, then the live file.
pub fn ledger_segment_path(path: &Path, stamp: &str, seq: u32) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    debug_assert!(
        name.ends_with(".jsonl"),
        "ledger names end in .jsonl: {name}"
    );
    let stem = name.strip_suffix(".jsonl").unwrap_or(name);
    path.with_file_name(format!("{stem}.{stamp}-{seq:03}.jsonl"))
}

/// Sort key of a rotated segment of the ledger named `ledger_name`
/// (`denials.jsonl`), or `None` when `candidate` is not one: the stamp, then
/// the sequence, oldest first. Pure.
fn segment_sort_key(ledger_name: &str, candidate: &str) -> Option<(String, u32)> {
    let stem = ledger_name.strip_suffix(".jsonl")?;
    let (stamp, seq) = candidate
        .strip_prefix(stem)?
        .strip_prefix('.')?
        .strip_suffix(".jsonl")?
        .split_once('-')?;
    if !(is_segment_stamp(stamp) && seq.len() == 3 && seq.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some((stamp.to_string(), seq.parse().ok()?))
}

/// `YYYYMMDDTHHMMSSZ`. Pure.
fn is_segment_stamp(stamp: &str) -> bool {
    let b = stamp.as_bytes();
    b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
}

/// Compact form of an ISO 8601 UTC timestamp (`2026-10-31T03:14:02Z` →
/// `20261031T031402Z`), comparable with segment stamps. Pure.
pub(crate) fn compact_stamp(iso: &str) -> String {
    iso.chars().filter(|c| !matches!(c, '-' | ':')).collect()
}

/// Split a rotated segment's file name into its ledger stem, stamp and
/// sequence (`denials.20261031T031402Z-001.jsonl` → `("denials",
/// "20261031T031402Z", 1)`), or `None` when `file_name` is not a segment. Pure.
pub(crate) fn split_segment_name(file_name: &str) -> Option<(String, String, u32)> {
    let (stem, _) = file_name.strip_suffix(".jsonl")?.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let (stamp, seq) = segment_sort_key(&format!("{stem}.jsonl"), file_name)?;
    Some((stem.to_string(), stamp, seq))
}

/// Whether `file_name` is a rotated segment of some ledger
/// (`<stem>.<YYYYMMDDTHHMMSSZ>-<NNN>.jsonl`), as opposed to a live ledger. Pure.
pub fn is_ledger_segment(file_name: &str) -> bool {
    file_name
        .strip_suffix(".jsonl")
        .and_then(|rest| rest.rsplit_once('.'))
        .filter(|(stem, _)| !stem.is_empty())
        .is_some_and(|(stem, _)| segment_sort_key(&format!("{stem}.jsonl"), file_name).is_some())
}

/// Every rotated segment of the ledger at `path` with its stamp, oldest
/// first. Regular files only, not followed through a symlink (the writers open
/// with `O_NOFOLLOW`, and a FIFO would block the read). Empty when the
/// directory is unreadable.
pub(crate) fn stamped_segments(path: &Path) -> Vec<(String, PathBuf)> {
    let Some(ledger_name) = path.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut segments: Vec<((String, u32), PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let key = segment_sort_key(ledger_name, entry.file_name().to_str()?)?;
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_file)
                .map(|_| (key, entry.path()))
        })
        .collect();
    segments.sort();
    segments
        .into_iter()
        .map(|((stamp, _), path)| (stamp, path))
        .collect()
}

/// Every rotated segment of the ledger at `path`, oldest first.
pub fn ledger_segments(path: &Path) -> Vec<PathBuf> {
    stamped_segments(path).into_iter().map(|(_, p)| p).collect()
}

/// Read `parts` in order and join them, never fusing a part that lacks a
/// trailing newline with the next. Regular files only, not through a symlink.
/// `None` when nothing can be read.
fn read_joined<'a>(parts: impl Iterator<Item = &'a Path>) -> Option<String> {
    let read = |p: &Path| {
        std::fs::symlink_metadata(p)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|_| std::fs::read_to_string(p).ok())
    };
    let mut all: Option<String> = None;
    for part in parts.filter_map(read) {
        let joined = all.get_or_insert_with(String::new);
        if !joined.is_empty() && !joined.ends_with('\n') {
            joined.push('\n');
        }
        joined.push_str(&part);
    }
    all
}

/// Read a ledger as one string, oldest rows first: every rotated segment in
/// time order, then the live file. `None` when nothing can be read.
///
/// This reads the ledger's whole history, so prefer [`read_ledger_since`] or
/// [`read_ledger_recent`] where the caller only needs a window. A rotation
/// landing between the directory listing and the live read can leave the
/// just-rotated rows out of this one read; the next read sees them in their
/// segment.
pub fn read_ledger(path: &Path) -> Option<String> {
    let segments = ledger_segments(path);
    read_joined(
        segments
            .iter()
            .map(PathBuf::as_path)
            .chain(std::iter::once(path)),
    )
}

/// [`read_ledger`], skipping segments that can hold no row at or after
/// `since` (an ISO 8601 UTC timestamp). A segment holds rows written before it
/// was stamped, so one stamped before `since` is skipped whole. The caller
/// still filters rows by `ts`.
pub fn read_ledger_since(path: &Path, since: &str) -> Option<String> {
    let since = compact_stamp(since);
    let segments = stamped_segments(path);
    read_joined(
        segments
            .iter()
            .filter(|(stamp, _)| *stamp >= since)
            .map(|(_, p)| p.as_path())
            .chain(std::iter::once(path)),
    )
}

/// The newest rotated segment, then the live file: the recent rows a
/// per-session lookup needs, at a bounded cost (at most about twice the cap).
pub fn read_ledger_recent(path: &Path) -> Option<String> {
    let newest = ledger_segments(path).pop();
    read_joined(newest.as_deref().into_iter().chain(std::iter::once(path)))
}

/// Compact UTC stamp for a new segment, `YYYYMMDDTHHMMSSZ`, from the ledgers'
/// shared clock.
#[cfg(any(unix, test))]
pub(crate) fn segment_stamp_now() -> String {
    compact_stamp(&utc_timestamp())
}

/// Whether a failed `link(2)` means this filesystem cannot hard-link, so the
/// rename fallback applies. Any other error is a real failure to report.
#[cfg(unix)]
fn link_unsupported(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
    ) || err.raw_os_error() == Some(libc::EMLINK)
}

/// Move the live ledger at `path` to a new segment stamped `stamp` without
/// ever replacing an existing file (cameronsjo/cadence-hooks#1585).
///
/// `link(2)` refuses an existing name, so link-then-unlink is a rename that
/// cannot clobber an older segment. The live name is unlinked only after the
/// segment is confirmed to be the same inode, and a failed unlink removes the
/// new link again, so the ledger is never left under two names (which would
/// count every row twice). A reader listing the directory between the link
/// and the unlink can still see the rows twice in that one read.
///
/// Where the filesystem cannot hard-link, fall back to `rename` onto a name
/// checked free. The caller's lock on the live inode keeps any other rotator
/// of this generation out, so the check races only a rotator of another
/// generation in the same second.
/// debt: check-then-rename can replace a segment on a filesystem without hard links, renamex_np(RENAME_EXCL) / renameat2(RENAME_NOREPLACE) if a ledger ever lives on one
#[cfg(unix)]
fn rotate_aside(path: &Path, stamp: &str) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    for seq in 0..MAX_SEGMENT_ATTEMPTS {
        let candidate = ledger_segment_path(path, stamp, seq);
        match std::fs::hard_link(path, &candidate) {
            Ok(()) => {
                let same = match (
                    std::fs::symlink_metadata(path),
                    std::fs::symlink_metadata(&candidate),
                ) {
                    (Ok(live), Ok(seg)) => live.ino() == seg.ino() && live.dev() == seg.dev(),
                    _ => false,
                };
                let unlinked = if same {
                    std::fs::remove_file(path)
                } else {
                    Err(std::io::Error::other(format!(
                        "expected {} to be the live ledger's inode after linking, found another file",
                        candidate.display()
                    )))
                };
                return match unlinked {
                    Ok(()) => Ok(()),
                    // Someone else moved the live name aside: the segment is
                    // the only name left, which is the goal.
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(err) => {
                        let _ = std::fs::remove_file(&candidate);
                        Err(err)
                    }
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) if link_unsupported(&err) => match std::fs::symlink_metadata(&candidate) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return std::fs::rename(path, &candidate);
                }
                Err(err) => return Err(err),
            },
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "expected a free segment name for stamp {stamp}, found all {MAX_SEGMENT_ATTEMPTS} taken"
        ),
    ))
}

/// Move the live ledger at `path` aside to a new dated segment now, whatever
/// its size, under the same protocol as a cap rotation: an exclusive `flock` on
/// the live inode, the move only while the path still names that inode, and
/// [`rotate_aside`]'s never-replace rename. Concurrent appenders that open the
/// path afterwards start a fresh live file. Returns the segment name, or `None`
/// when there is no live file to move. Used by `metrics rotate
/// --quarantine-test-rows`, which must split rows without rewriting a live file.
#[cfg(unix)]
pub(crate) fn rotate_live_now(path: &Path) -> std::io::Result<Option<PathBuf>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;

    let file = match std::fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    // SAFETY: `file` owns a valid descriptor for the whole call, and `flock`
    // touches no memory. Blocking is fine: a cap rotator holds it for one rename.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let held = file.metadata()?;
    match std::fs::symlink_metadata(path) {
        Ok(on_disk) if on_disk.ino() == held.ino() && on_disk.dev() == held.dev() => {}
        // Another process rotated it between our open and our lock: its rows
        // are already in a segment, and the fresh live file is someone else's.
        Ok(_) => return Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    }
    let stamp = segment_stamp_now();
    rotate_aside(path, &stamp)?;
    // `rotate_aside` picked the first free sequence for `stamp`; find the one
    // that is this inode.
    for seq in 0..MAX_SEGMENT_ATTEMPTS {
        let candidate = ledger_segment_path(path, &stamp, seq);
        match std::fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.ino() == held.ino() && meta.dev() == held.dev() => {
                return Ok(Some(candidate));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::other(format!(
        "expected the moved ledger under a {stamp} segment name beside {}, found none",
        path.display()
    )))
}

pub(crate) fn open_ledger_capped(path: &Path, cap: Option<u64>) -> std::io::Result<std::fs::File> {
    let file = open_append(path)?;
    #[cfg(unix)]
    if let Some(cap) = cap {
        return Ok(rotate_if_over_cap(path, file, cap, segment_stamp_now));
    }
    #[cfg(not(unix))]
    let _ = cap; // debt: no rotation off Unix (rename-over-open-file semantics differ), flock-free Windows scheme if a Windows ledger ever reaches the doctor warning
    Ok(file)
}

/// Rotate `path` to a new dated segment ([`rotate_aside`]) when the already-open `file` is at or past `cap`,
/// and return the handle to append to.
///
/// Safe with several hook processes at once:
/// - The rotator takes a non-blocking `flock` on the live inode. A process that
///   loses the race skips rotation and appends as before.
/// - Under the lock the rotator renames only if the path still names the inode
///   it holds, so a process that opened the old file before another rotated it
///   cannot rotate the fresh file out from under a newer generation.
/// - The move never replaces an existing segment. A process still holding the
///   old inode finishes its single `O_APPEND` write into the segment, the same
///   in-flight write a plain archive would catch.
///
/// Every failure returns a usable handle (ADR-0001) and is recorded in
/// `failopen.jsonl`.
#[cfg(unix)]
fn rotate_if_over_cap(
    path: &Path,
    file: std::fs::File,
    cap: u64,
    stamp: impl FnOnce() -> String,
) -> std::fs::File {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let Ok(held) = file.metadata() else {
        return file;
    };
    if held.len() < cap {
        return file;
    }
    // SAFETY: `file` owns a valid descriptor for the whole call, and `flock`
    // touches no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            crate::log_failopen::log_rotation_failure(path, &err);
        }
        return file; // WouldBlock: another process is rotating this ledger
    }
    let renamed = match std::fs::symlink_metadata(path) {
        Ok(on_disk) if on_disk.ino() == held.ino() && on_disk.dev() == held.dev() => {
            rotate_aside(path, &stamp())
        }
        // The path names a different inode: another process already rotated.
        Ok(_) => Ok(()),
        // Moved aside by hand (`doctor`'s archive remediation): nothing to
        // rotate, and the reopen below starts a fresh file.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    };
    match renamed {
        // The lock dies with the old handle when it drops here.
        Ok(()) => open_append(path).unwrap_or(file),
        Err(err) => {
            crate::log_failopen::log_rotation_failure(path, &err);
            file
        }
    }
}

/// Create `dir` and any missing parents, each new one mode `0700` on Unix, so
/// per-session state names (session ids, which switch a session used) are not
/// listable by other local users.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Open a per-session state marker for writing, mode `0600` and never through
/// a symlink on Unix. `exclusive` fails with `AlreadyExists` when the file is
/// there; otherwise an existing file is truncated.
pub fn open_state_marker(path: &Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        if let Ok(meta) = file.metadata() {
            let mode = meta.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(mode & !0o077));
            }
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

/// Harness stamped on schema-v2 rows.
///
/// Constant since the Codex adapters were retired (#1040). The field stays
/// because rows written before 2026-08-23 carry the other value, and a reader
/// of the ledger still needs it to interpret them.
pub fn harness() -> &'static str {
    "claude"
}

/// Append a schema-only transcript diagnostic. No transcript text, tool input,
/// prompt, patch, or output is accepted by this API.
pub fn append_transcript_diagnostic(harness: &str, source_format: &str, code: &str, stream: &str) {
    let dir = metrics_dir();
    append_transcript_diagnostic_to(&dir, harness, source_format, code, stream);
}

const MAX_DIAGNOSTICS_BYTES: u64 = 1_048_576;

fn append_transcript_diagnostic_to(
    dir: &Path,
    harness: &str,
    source_format: &str,
    code: &str,
    stream: &str,
) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = dir.join("diagnostics.jsonl");
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_DIAGNOSTICS_BYTES) {
        return;
    }
    let record = json!({
        "schemaVersion": TOKEN_RECORD_SCHEMA_VERSION,
        "ts": utc_timestamp(),
        "harness": harness,
        "sourceFormat": source_format,
        "code": code,
        "stream": stream,
        "priced": false,
    });
    if let Ok(mut file) = open_ledger(path) {
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// The per-session state directory: `<metrics_dir>/state`.
pub fn state_dir() -> PathBuf {
    metrics_dir().join("state")
}

/// True when `session_id` is safe to embed in a state filename — non-empty and
/// composed only of ASCII alphanumerics, `-`, or `_`. Session IDs are UUID-like;
/// anything containing path separators or `..` is rejected so a malformed or
/// hostile payload can never steer a write outside [`state_dir`].
pub fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Build a `git` command rooted at `cwd` when it's an existing directory,
/// otherwise inheriting the process working directory (mirrors the bash
/// `cd "$cwd" && git ...` / bare-`git` fallback).
fn git_in(cwd: Option<&str>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd
        && Path::new(dir).is_dir()
    {
        cmd.current_dir(dir);
    }
    cmd
}

/// Run a git command and return its trimmed stdout, or `None` on failure or
/// empty output.
fn git_output(cwd: Option<&str>, args: &[&str]) -> Option<String> {
    let mut cmd = git_in(cwd);
    cmd.args(args);
    let output = match cadence_hooks_core::shell::run_git_bounded(&mut cmd) {
        cadence_hooks_core::shell::GitSpawn::Completed(output) if output.status.success() => output,
        // A truncated SHA is not a SHA.
        cadence_hooks_core::shell::GitSpawn::Completed(_)
        | cadence_hooks_core::shell::GitSpawn::Truncated(_)
        | cadence_hooks_core::shell::GitSpawn::SpawnFailed
        | cadence_hooks_core::shell::GitSpawn::TimedOut => return None,
    };
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Current `HEAD` SHA in `cwd`.
pub fn head_sha(cwd: Option<&str>) -> Option<String> {
    git_output(cwd, &["rev-parse", "HEAD"])
}

/// Current branch name in `cwd` (empty string on detached HEAD or failure).
///
/// Uses `symbolic-ref --quiet --short HEAD`, which exits non-zero on a detached
/// HEAD — so [`git_output`] yields `None` and we return empty, as documented.
/// (`rev-parse --abbrev-ref HEAD` would return the literal string `"HEAD"`.)
pub fn branch(cwd: Option<&str>) -> String {
    git_output(cwd, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default()
}

/// Repo name: the basename of the repository the checkout at `cwd` belongs
/// to — never a linked worktree's own directory name (`.claude/worktrees/<slug>`),
/// which [`GitState::resolve`](cadence_hooks_core::gitstate::GitState::resolve)
/// deliberately does not expose as `repo_root` for a linked worktree.
///
/// Resolution order:
/// 1. `git_common_dir` ends in `.git` (the overwhelmingly common shape, both
///    primary checkouts and linked worktrees): the repo dir is its parent.
/// 2. Otherwise — a bare repo or a `--separate-git-dir` primary, where the
///    common dir is not named `.git` — best-effort falls back to
///    `repo_root` itself.
/// 3. Not inside a git repo at all (or [`GitState::resolve`] can't place
///    `cwd`): falls back to the `cwd`/process-directory basename, as before.
pub fn repo_basename(cwd: Option<&str>) -> String {
    let dir = match cwd.and_then(|d| cadence_hooks_core::gitstate::GitState::resolve(Path::new(d)))
    {
        // Exact component match, not a string suffix: `ends_with(".git")` on
        // the whole path would also match a `--separate-git-dir` target
        // conventionally named `<name>.git` (e.g. `/gitdirs/myrepo.git`),
        // taking this branch and reporting `gitdirs` — the *parent* of the
        // admin dir, not the repo — as the repo name. Comparing the final
        // path component to the literal `.git` closes that: only a real
        // `.git`-named dir (primary checkout or linked worktree) takes this
        // branch; a `--separate-git-dir` admin dir named `myrepo.git` falls
        // through to the `repo_root` branch below, same as a bare repo.
        Some(state) if state.git_common_dir.file_name() == Some(OsStr::new(".git")) => state
            .git_common_dir
            .parent()
            .map(PathBuf::from)
            .unwrap_or(state.repo_root),
        // Bare repo or `--separate-git-dir` primary: the common dir isn't
        // named `.git`, so there's no parent to peel — best-effort fall back
        // to the resolved repo root.
        Some(state) => state.repo_root,
        None => match cwd {
            Some(d) if Path::new(d).is_dir() => PathBuf::from(d),
            _ => std::env::current_dir().unwrap_or_default(),
        },
    };
    dir.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Current UTC timestamp, ISO 8601 second precision (`%Y-%m-%dT%H:%M:%SZ`).
///
/// Re-exports the canonical [`cadence_hooks_core::time::utc_timestamp`] so every
/// logger shares one timestamp source (jiff-backed, portable to Windows).
pub fn utc_timestamp() -> String {
    cadence_hooks_core::time::utc_timestamp()
}

/// Today's UTC date, `YYYY-MM-DD` — the freshness half of a once-per-day alarm
/// marker. Sliced from [`utc_timestamp`] so it shares the ledgers' clock rather
/// than introducing a second one.
pub fn today_utc() -> String {
    utc_timestamp()[..10].to_string()
}

/// Claim today's slot for a once-per-day alarm, returning `true` when the
/// caller should speak.
///
/// The marker is `<dir>/state/<filename>` and holds `<UTC date> <verdict>`. A
/// caller whose exact `verdict` is already recorded for today gets `false` and
/// stays silent; anyone else records the new pair and gets `true`. Keying on
/// the verdict as well as the date is what lets an *escalation* speak the same
/// day while a repeat of the same finding does not — so `verdict` should name
/// the alarm's shape, never a count that drifts on every run.
///
/// Living under `state/` is deliberate: the marker is not a `*.jsonl`, and it
/// sits outside the ledger dir proper, so writing it can never freshen the
/// staleness signal [`crate::warn_stale`] reads.
///
/// Fail-open (ADR-0001): an unreadable marker is treated as absent, and a write
/// error is swallowed. Both fail toward *speaking* — a repeated alarm beats a
/// missed one.
pub fn claim_daily_alarm(dir: &Path, filename: &str, verdict: &str) -> bool {
    let marker = dir.join("state").join(filename);
    let token = format!("{} {}", today_utc(), verdict);
    if let Ok(existing) = std::fs::read_to_string(&marker)
        && existing.trim() == token
    {
        return false;
    }
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, &token);
    true
}

/// Strip display-affecting characters from a file-sourced string before it is
/// interpolated into terminal output or into the `additionalContext` blob a
/// nudge injects into the agent's context.
///
/// Two families, not one. `char::is_control` covers only **Cc** — C0, DEL, C1 —
/// which handles ANSI escapes and newlines. It passes **Cf** (format)
/// characters, and those reorder rendered text without being "control"
/// characters at all: U+202E RIGHT-TO-LEFT OVERRIDE and the U+2066–U+2069
/// directional isolates are the Trojan-Source primitives. U+2028/U+2029 are
/// line/paragraph separators that some renderers break on. Strip all of them.
///
/// **The agent-context sink is the strict one.** A terminal reader sees a
/// mangled line; an injected newline in `additionalContext` starts what reads
/// as a new instruction. Anything file-sourced — a ledger field, a filename —
/// must pass through here before it reaches either sink.
pub fn display_safe(s: &str) -> String {
    s.chars().filter(|c| !is_display_unsafe(*c)).collect()
}

/// Whether `c` can alter how the rest of a line renders, or ride into an
/// agent's context invisibly: any Cc control, any Cf format character, or the
/// Unicode line/paragraph separators.
///
/// **The range list now lives in
/// [`cadence_hooks_core::display::is_invisible_or_control`]**, which
/// `core::display::sanitize_field` also uses. It was maintained here while that
/// sanitizer — the one every *hook message* goes through — carried a shorter,
/// bidi-shaped enumeration that passed U+2028/U+2029, U+2060–U+2064, U+061C,
/// U+180E and the whole Tags block. Two lists for one question is how that gap
/// stayed open, so there is one list, in the crate both sides already depend on
/// (cadence-hooks#610 Gate 2). This wrapper stays because the two sinks differ
/// in what they DO with the verdict: metrics filters the character out, hook
/// text replaces it with a space.
fn is_display_unsafe(c: char) -> bool {
    cadence_hooks_core::display::is_invisible_or_control(c)
}

/// [`display_safe`] plus a character ceiling — filtering alone bounds the
/// *character set* but not the *length*, and an unbounded file-sourced string
/// can still flood a terminal line or a nudge.
///
/// Truncation counts **characters, not bytes**, and slices at the boundary
/// `char_indices` reports — a byte slice at a fixed offset would panic
/// mid-codepoint on a multi-byte value, which inside a fail-open writer would
/// be a panic on the panic path.
pub fn display_safe_bounded(s: &str, max_chars: usize) -> String {
    let cleaned = display_safe(s);
    match cleaned.char_indices().nth(max_chars) {
        Some((boundary, _)) => format!("{}…", &cleaned[..boundary]),
        None => cleaned,
    }
}

/// The character a run of disallowed bytes collapses to in [`filename_safe`].
/// Deliberately not something a real ledger name contains, so a sanitized name
/// can never be mistaken for — or collide with — a legitimate one.
const FILENAME_REPLACEMENT: char = '?';

/// An **allowlist** sanitizer for a value that is a *name*, not prose: keeps
/// `[A-Za-z0-9._-]`, collapses every run of anything else to a single
/// [`FILENAME_REPLACEMENT`], and bounds the result.
///
/// **Why a second sanitizer rather than reusing [`display_safe`].** That one is
/// a denylist over the Cc and Cf categories, and a denylist cannot close this
/// class for two structural reasons:
///
/// 1. **The invisible-smuggling primitive is not confined to Cf.** Variation
///    selectors — U+FE00–U+FE0F and U+E0100–U+E01EF — are category **Mn**, so a
///    Cf-complete enumeration misses them *by construction*. They encode
///    invisible bytes exactly the way the Tags block does. Chasing that with
///    more denied ranges is a race against Unicode itself.
/// 2. **Stripping invisibles does not stop visible prose.** A name is
///    attacker-chosen text landing inside a sentence in the agent's context;
///    removing newlines demotes a fake system turn to an inline instruction, it
///    does not remove it. The allowlist excludes the SPACE character, so smuggled
///    prose arrives as `Disregard?the?above` — visibly mangled rather than
///    fluent.
///
/// Real ledger names (`commits.jsonl`, `askuserquestion.jsonl`) satisfy the
/// allowlist exactly, so the constraint costs nothing on every legitimate input.
///
/// Runs collapse rather than delete, which also keeps the result **injective
/// enough**: deleting would map `commits\u{200B}.jsonl` onto the real
/// `commits.jsonl`, merging a hostile entry with a live one and letting a dead
/// stream read as alive. Replacement keeps them distinct.
///
/// Use [`display_safe`] instead for diagnostic *prose* (an error message), where
/// spaces and punctuation are legitimate content.
pub fn filename_safe(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars));
    let mut chars = 0usize;
    let mut in_run = false;
    for c in s.chars() {
        if chars >= max_chars {
            out.push('…');
            break;
        }
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
            chars += 1;
            in_run = false;
        } else if !in_run {
            out.push(FILENAME_REPLACEMENT);
            chars += 1;
            in_run = true;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Schema versioning (the metrics data contract)
// ---------------------------------------------------------------------------
//
// A metrics stream MAY stamp an explicit integer `schemaVersion` on every row
// so consumers branch on a declared contract version instead of probing field
// presence. Each stream's version is a `*_SCHEMA_VERSION` constant defined here
// — one greppable source of truth — read by that stream's logger. Keep the
// constant and the stream's row in `plugins/cadence-metrics/docs/schema.md`
// (cadence repo) in lockstep.
//
// Bump policy (Keep-a-Changelog for the data contract):
//   - ADDITIVE change (new nullable field, new `event` enum value): DO NOT bump.
//     Old consumers keep working; the field/value is simply absent or unseen on
//     older rows.
//   - BREAKING change (field renamed / removed / retyped, or a field's meaning
//     changes): bump the stream's constant by 1 and document the cutover in a
//     "Schema version history" note in `schema.md`.
//
// Streams predating this convention (`commits` / `subagents` / `denials` /
// `sessions`) are implicitly version 0. They adopt a constant here on their
// *next* shape change (opportunistic adoption, cadence#238) — historical
// un-stamped lines are never backfilled.

/// Schema version stamped on every `skills.jsonl` row.
pub const SKILL_SCHEMA_VERSION: u32 = 1;

/// Schema version stamped on every `askuserquestion.jsonl` row (both
/// `asked` and `answered` phases).
pub const ASKUSERQUESTION_SCHEMA_VERSION: u32 = 1;

/// Schema version for cross-harness commit and session token records.
pub const TOKEN_RECORD_SCHEMA_VERSION: u32 = 2;

/// Crate-wide serialization lock for env-mutating tests.
///
/// `CADENCE_METRICS_DIR` and its siblings are process-global, so every test that
/// `set_var`/`remove_var`s one must hold *this one* lock — a per-module lock only
/// serializes within its own module and lets tests in different modules
/// (`log_denial`, `log_timing`, …) race on the same global.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// #425: a new ledger is owner-only, whatever the umask.
    #[cfg(unix)]
    #[test]
    fn open_ledger_creates_owner_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        let mut file = open_ledger(&path).unwrap();
        file.write_all(b"{}\n").unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    /// #425: a ledger an older binary left world-readable is tightened on the
    /// next append, and its contents are appended to, not replaced.
    #[cfg(unix)]
    #[test]
    fn open_ledger_tightens_an_existing_readable_ledger() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("subagents.jsonl");
        std::fs::write(&path, "a\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        open_ledger(&path).unwrap().write_all(b"b\n").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
    }

    /// A mode already tighter than 0600 is never loosened.
    #[cfg(unix)]
    #[test]
    fn open_ledger_leaves_a_tighter_mode_alone() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hooks.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
        open_ledger(&path).unwrap();
        assert_eq!(mode_of(&path), 0o200);
    }

    /// Tightening clears only group/other bits; owner bits are not reset to
    /// a flat 0600.
    #[cfg(unix)]
    #[test]
    fn open_ledger_clears_only_group_and_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("sessions.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o754)).unwrap();
        open_ledger(&path).unwrap();
        assert_eq!(mode_of(&path), 0o700);
    }

    /// A symlinked ledger fails to open: nothing is appended through it and
    /// its target's mode is untouched.
    #[cfg(unix)]
    #[test]
    fn open_ledger_refuses_a_symlinked_ledger() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("elsewhere");
        std::fs::write(&target, "keep\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = tmp.path().join("commits.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            open_ledger(&link).is_err(),
            "a symlinked ledger must not open"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
        assert_eq!(mode_of(&target), 0o644);
    }

    /// End to end through a writer: the diagnostic append skips a symlinked
    /// ledger silently instead of writing through it.
    #[cfg(unix)]
    #[test]
    fn diagnostic_append_skips_a_symlinked_ledger() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, tmp.path().join("diagnostics.jsonl")).unwrap();
        append_transcript_diagnostic_to(tmp.path(), "claude", "jsonl", "code", "main");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
    }

    #[test]
    fn ledger_cap_parses_env_values() {
        let d = Some(DEFAULT_LEDGER_MAX_BYTES);
        assert_eq!(parse_ledger_max_bytes(None), d);
        assert_eq!(parse_ledger_max_bytes(Some("")), d);
        assert_eq!(parse_ledger_max_bytes(Some("  ")), d);
        assert_eq!(
            parse_ledger_max_bytes(Some("lots")),
            d,
            "garbage keeps the default"
        );
        assert_eq!(parse_ledger_max_bytes(Some("-5")), d);
        assert_eq!(parse_ledger_max_bytes(Some("2097152")), Some(2_097_152));
        assert_eq!(parse_ledger_max_bytes(Some(" 2097152 ")), Some(2_097_152));
        assert_eq!(
            parse_ledger_max_bytes(Some("1048576")),
            Some(MIN_LEDGER_MAX_BYTES),
            "the floor itself is honored"
        );
        assert_eq!(
            parse_ledger_max_bytes(Some("16")),
            d,
            "a MiB-for-bytes slip keeps the default instead of erasing history"
        );
        assert_eq!(parse_ledger_max_bytes(Some("1048575")), d);
        assert_eq!(
            parse_ledger_max_bytes(Some("0")),
            None,
            "0 turns rotation off"
        );
    }

    #[test]
    fn segment_path_keeps_the_ledger_stem_and_directory() {
        assert_eq!(
            ledger_segment_path(Path::new("/m/denials.jsonl"), "20261031T031402Z", 0),
            PathBuf::from("/m/denials.20261031T031402Z-000.jsonl")
        );
        assert_eq!(
            ledger_segment_path(Path::new("/m/plan-links.jsonl"), "20261031T031402Z", 12),
            PathBuf::from("/m/plan-links.20261031T031402Z-012.jsonl")
        );
    }

    #[test]
    fn segment_names_parse_and_sort_oldest_first() {
        let key = |c: &str| segment_sort_key("denials.jsonl", c);
        assert_eq!(
            key("denials.20261031T031402Z-000.jsonl"),
            Some(("20261031T031402Z".to_string(), 0))
        );
        assert_eq!(
            key("denials.20261031T031402Z-012.jsonl"),
            Some(("20261031T031402Z".to_string(), 12))
        );
        // Name order is read order: a script sorting `<stem>.*.jsonl` by name
        // reads them in the same order `read_ledger` does.
        let mut names = vec![
            "denials.20261101T000000Z-000.jsonl",
            "denials.20261031T031402Z-010.jsonl",
            "denials.20261031T031402Z-009.jsonl",
            "denials.20261031T031402Z-000.jsonl",
        ];
        let mut by_key = names.clone();
        names.sort_unstable();
        by_key.sort_by_key(|n| key(n));
        assert_eq!(names, by_key);
        for not_a_segment in [
            "denials.jsonl",
            "denials.20261031T031402Z.jsonl",
            "denials.20261031T031402Z-9.jsonl",
            "denials.20261031T031402Z-1000.jsonl",
            "denials.jsonl.1",
            "denials.archived.jsonl",
            "denials.20261031T031402Z-000.jsonl.gz",
            "denials.20261031T031402-000.jsonl",
            "denials.20261031T031402Z-.jsonl",
            "denials.20261031T031402Z-00x.jsonl",
            "subagents.20261031T031402Z-000.jsonl",
            // Another ledger whose name starts with this one's stem.
            "denials-extra.20261031T031402Z-000.jsonl",
        ] {
            assert_eq!(key(not_a_segment), None, "{not_a_segment}");
        }
        assert!(is_ledger_segment("denials.20261031T031402Z-000.jsonl"));
        assert!(is_ledger_segment("plan-links.20261031T031402Z-003.jsonl"));
        assert!(!is_ledger_segment("denials.jsonl"));
        assert!(!is_ledger_segment(".20261031T031402Z-000.jsonl"));
    }

    #[test]
    fn segment_stamp_now_is_compact_utc() {
        assert!(
            is_segment_stamp(&segment_stamp_now()),
            "{}",
            segment_stamp_now()
        );
    }

    #[cfg(unix)]
    fn append_rotating(path: &Path, cap: Option<u64>, line: &str) {
        let mut file = open_ledger_capped(path, cap).unwrap();
        file.write_all(line.as_bytes()).unwrap();
    }

    #[cfg(unix)]
    fn segment_contents(path: &Path) -> Vec<String> {
        ledger_segments(path)
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn ledger_at_the_cap_rotates_to_a_dated_segment() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "old-1\nold-2\n").unwrap();

        append_rotating(&path, Some(12), "new\n");

        let segments = ledger_segments(&path);
        assert_eq!(segments.len(), 1, "{segments:?}");
        assert!(
            is_ledger_segment(segments[0].file_name().unwrap().to_str().unwrap()),
            "{segments:?}"
        );
        assert_eq!(segment_contents(&path), ["old-1\nold-2\n"]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(mode_of(&segments[0]), 0o600);
        assert_eq!(mode_of(&path), 0o600);
    }

    /// The cameronsjo/cadence-hooks#1585 regression: a second rotation must
    /// keep the first generation, even inside the same second.
    #[cfg(unix)]
    #[test]
    fn rotations_keep_every_generation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "gen-1\n").unwrap();

        append_rotating(&path, Some(6), "gen-2\n"); // rotates gen-1
        append_rotating(&path, Some(6), "gen-3\n"); // rotates gen-2
        append_rotating(&path, Some(6), "gen-4\n"); // rotates gen-3

        assert_eq!(segment_contents(&path), ["gen-1\n", "gen-2\n", "gen-3\n"]);
        assert_eq!(
            read_ledger(&path).as_deref(),
            Some("gen-1\ngen-2\ngen-3\ngen-4\n")
        );
    }

    /// An existing segment at the stamp's name is never replaced: the next
    /// sequence number is used instead.
    #[cfg(unix)]
    #[test]
    fn a_taken_segment_name_moves_to_the_next_sequence() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        let stamp = "20260101T000000Z";
        std::fs::write(ledger_segment_path(&path, stamp, 0), "earlier\n").unwrap();
        std::fs::write(&path, "later\n").unwrap();

        let held = open_append(&path).unwrap();
        let mut handle = rotate_if_over_cap(&path, held, 1, || stamp.to_string());
        handle.write_all(b"live\n").unwrap();

        assert_eq!(
            std::fs::read_to_string(ledger_segment_path(&path, stamp, 0)).unwrap(),
            "earlier\n"
        );
        assert_eq!(
            std::fs::read_to_string(ledger_segment_path(&path, stamp, 1)).unwrap(),
            "later\n"
        );
        assert_eq!(
            read_ledger(&path).as_deref(),
            Some("earlier\nlater\nlive\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn ledger_under_the_cap_or_with_rotation_off_stays_whole() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "12345\n").unwrap();

        append_rotating(&path, Some(7), "a\n"); // 6 bytes held < 7
        append_rotating(&path, None, "b\n");

        assert!(ledger_segments(&path).is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "12345\na\nb\n");
    }

    /// Fill every name a rotation stamped `stamp` could take, so it fails.
    #[cfg(unix)]
    fn take_every_segment_name(path: &Path, stamp: &str) {
        for seq in 0..MAX_SEGMENT_ATTEMPTS {
            std::fs::write(ledger_segment_path(path, stamp, seq), "").unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_rotation_error_is_logged_and_the_append_still_lands() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "old\n").unwrap();
        let stamp = "20260101T000000Z";
        take_every_segment_name(&path, stamp);

        let held = open_append(&path).unwrap();
        let mut handle = rotate_if_over_cap(&path, held, 1, || stamp.to_string());
        handle.write_all(b"new\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old\nnew\n");
        let logged = std::fs::read_to_string(tmp.path().join("failopen.jsonl")).unwrap();
        let row: serde_json::Value = serde_json::from_str(logged.trim()).unwrap();
        assert_eq!(row["reason"], "ledger_rotate_failed");
        assert_eq!(row["subcommand"], "denials.jsonl");
    }

    #[cfg(unix)]
    #[test]
    fn a_failopen_rotation_error_is_not_logged_into_itself() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("failopen.jsonl");
        std::fs::write(&path, "old\n").unwrap();
        let stamp = "20260101T000000Z";
        take_every_segment_name(&path, stamp);

        let held = open_append(&path).unwrap();
        let mut handle = rotate_if_over_cap(&path, held, 1, || stamp.to_string());
        handle.write_all(b"new\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old\nnew\n");
    }

    /// A process that opened the ledger before another rotated it still holds
    /// the old inode (now a segment). Rotating from that stale handle must not
    /// move the fresh live file aside.
    #[cfg(unix)]
    #[test]
    fn a_stale_handle_does_not_rotate_the_newer_generation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "generation-one\n").unwrap();
        let stale = open_append(&path).unwrap();

        append_rotating(&path, Some(5), "generation-two\n"); // rotates

        let mut handle = rotate_if_over_cap(&path, stale, 5, segment_stamp_now);
        handle.write_all(b"from-stale\n").unwrap();

        assert_eq!(
            segment_contents(&path),
            ["generation-one\n"],
            "one segment, untouched by the stale rotator"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "generation-two\nfrom-stale\n",
            "the stale handle is swapped for the live file"
        );
    }

    /// Another process is mid-rotation (it holds the lock): this writer skips
    /// rotating, appends as before, and reports nothing.
    #[cfg(unix)]
    #[test]
    fn a_writer_that_loses_the_lock_race_appends_without_rotating() {
        use std::os::unix::io::AsRawFd;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "over-the-cap\n").unwrap();
        let rival = open_append(&path).unwrap();
        // SAFETY: `rival` owns a valid descriptor for the whole call.
        assert_eq!(
            unsafe { libc::flock(rival.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "positive control: the rival takes the lock"
        );

        append_rotating(&path, Some(5), "mine\n");

        assert!(
            ledger_segments(&path).is_empty(),
            "no rotation under a held lock"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "over-the-cap\nmine\n"
        );
        assert!(
            !tmp.path().join("failopen.jsonl").exists(),
            "losing the race is not an error"
        );
        drop(rival);

        // Control: once the lock is free the same call rotates.
        append_rotating(&path, Some(5), "later\n");
        assert_eq!(ledger_segments(&path).len(), 1);
    }

    /// `doctor`'s remediation moves the ledger aside by hand; a writer that had
    /// it open then finds nothing at the path. That is not a failure.
    #[cfg(unix)]
    #[test]
    fn a_ledger_moved_aside_mid_write_is_replaced_not_reported() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("denials.jsonl");
        std::fs::write(&path, "over-the-cap\n").unwrap();
        let held = open_append(&path).unwrap();
        std::fs::rename(&path, tmp.path().join("denials.jsonl.archived")).unwrap();

        let mut handle = rotate_if_over_cap(&path, held, 5, segment_stamp_now);
        handle.write_all(b"fresh\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
        assert!(ledger_segments(&path).is_empty());
        assert!(!tmp.path().join("failopen.jsonl").exists());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_appenders_lose_no_row_across_rotations() {
        const THREADS: usize = 8;
        const ROWS: usize = 250;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("subagents.jsonl");
        let pad = "x".repeat(60);

        // ~85 bytes a row, 2000 rows, a 40 KB cap: several rotations, many of
        // them inside one second, and every row must survive across the
        // segments and the live file.
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let (path, pad) = (&path, &pad);
                scope.spawn(move || {
                    for i in 0..ROWS {
                        let row = format!("{{\"t\":{t},\"i\":{i},\"pad\":\"{pad}\"}}\n");
                        append_rotating(path, Some(40_000), &row);
                    }
                });
            }
        });

        // A rotation that loses the non-blocking flock to a busy appender is
        // skipped, so how many segments appear depends on scheduling (CI saw
        // fewer than 3). What the test needs is that the rows crossed at least
        // one rotation.
        assert!(
            !ledger_segments(&path).is_empty(),
            "the cap was crossed at least once"
        );
        let all = read_ledger(&path).unwrap();
        let mut seen = std::collections::HashSet::new();
        for line in all.lines() {
            let row: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("torn or interleaved line {line:?}: {e}"));
            assert!(
                seen.insert((row["t"].as_u64().unwrap(), row["i"].as_u64().unwrap())),
                "duplicate row {line}"
            );
        }
        assert_eq!(seen.len(), THREADS * ROWS, "no row lost");
    }

    #[test]
    fn read_ledger_returns_segments_in_order_then_live() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("commits.jsonl");
        assert_eq!(read_ledger(&path), None, "nothing exists");

        std::fs::write(&path, "live\n").unwrap();
        assert_eq!(read_ledger(&path).as_deref(), Some("live\n"));

        // Written out of order; read back by stamp, then sequence. A segment
        // with no trailing newline must not fuse with the next part.
        std::fs::write(ledger_segment_path(&path, "20261002T000000Z", 0), "third").unwrap();
        std::fs::write(
            ledger_segment_path(&path, "20261001T000000Z", 10),
            "second\n",
        )
        .unwrap();
        std::fs::write(ledger_segment_path(&path, "20261001T000000Z", 9), "first\n").unwrap();
        // Not this ledger's segments.
        std::fs::write(
            tmp.path().join("sessions.20261001T000000Z-000.jsonl"),
            "x\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("commits.jsonl.1"), "x\n").unwrap();
        assert_eq!(
            read_ledger(&path).as_deref(),
            Some("first\nsecond\nthird\nlive\n")
        );

        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            read_ledger(&path).as_deref(),
            Some("first\nsecond\nthird"),
            "segments only"
        );
    }

    #[test]
    fn windowed_reads_skip_segments_that_cannot_hold_the_window() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("failopen.jsonl");
        std::fs::write(ledger_segment_path(&path, "20261001T000000Z", 0), "oct-1\n").unwrap();
        std::fs::write(
            ledger_segment_path(&path, "20261015T120000Z", 0),
            "oct-15\n",
        )
        .unwrap();
        std::fs::write(
            ledger_segment_path(&path, "20261015T120000Z", 1),
            "oct-15b\n",
        )
        .unwrap();
        std::fs::write(&path, "live\n").unwrap();

        // A segment stamped at the cutoff second can hold a row from that
        // second, so it is kept.
        assert_eq!(
            read_ledger_since(&path, "2026-10-15T12:00:00Z").as_deref(),
            Some("oct-15\noct-15b\nlive\n")
        );
        assert_eq!(
            read_ledger_since(&path, "2026-10-15T12:00:01Z").as_deref(),
            Some("live\n")
        );
        assert_eq!(
            read_ledger_since(&path, "2026-09-01T00:00:00Z").as_deref(),
            Some("oct-1\noct-15\noct-15b\nlive\n")
        );
        assert_eq!(
            read_ledger_recent(&path).as_deref(),
            Some("oct-15b\nlive\n"),
            "the newest segment, then live"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_named_like_a_segment_is_not_read() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("bypasses.jsonl");
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, "{\"secret\":1}\n").unwrap();
        std::os::unix::fs::symlink(&outside, ledger_segment_path(&path, "20261001T000000Z", 0))
            .unwrap();
        std::fs::write(&path, "live\n").unwrap();

        assert!(ledger_segments(&path).is_empty());
        assert_eq!(read_ledger(&path).as_deref(), Some("live\n"));
    }

    #[test]
    fn display_safe_is_unchanged_by_the_move_to_core() {
        // One fixture carrying every class the range list covers, pinned as a
        // whole. `is_display_unsafe` now delegates to
        // `core::display::is_invisible_or_control`; this is what says the
        // delegation did not quietly change what `display_safe` strips.
        let every_class = concat!(
            "start",
            "\u{0007}",  // Cc: bell
            "\n",        // Cc: newline
            "\u{00AD}",  // soft hyphen
            "\u{061C}",  // Arabic letter mark
            "\u{180E}",  // Mongolian vowel separator
            "\u{200B}",  // zero-width space
            "\u{202E}",  // right-to-left override
            "\u{2028}",  // line separator
            "\u{2060}",  // word joiner
            "\u{2066}",  // first strong isolate
            "\u{FEFF}",  // BOM
            "\u{FFF9}",  // interlinear annotation anchor
            "\u{1D173}", // musical beam
            "\u{E0041}", // Tags block
            "-café-日本-🚀",
        );
        assert_eq!(display_safe(every_class), "start-café-日本-🚀");
    }

    // `metrics_dir`'s resolution order is tested through the pure(-ish)
    // `metrics_dir_from` helper against a temp-dir fixture, so these never
    // touch process-global env (no `set_var`/`remove_var`, no serialization
    // lock, no cross-test leakage) — except the dedicated
    // `CLAUDE_CONFIG_DIR`-override test at the bottom of this module, which
    // does hold `ENV_LOCK`.

    #[test]
    fn metrics_dir_override_via_cadence_metrics_dir() {
        // A non-empty override value becomes the metrics dir verbatim, even
        // when a config dir with an existing new/legacy root is supplied —
        // the override always wins.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            metrics_dir_from(
                Some("/tmp/cadence-test-metrics".to_string()),
                tmp.path().to_path_buf()
            ),
            std::path::PathBuf::from("/tmp/cadence-test-metrics")
        );
    }

    #[test]
    fn metrics_dir_empty_override_falls_through() {
        // An empty CADENCE_METRICS_DIR must not shadow the default (guards the
        // `!dir.is_empty()` branch).
        let tmp = tempfile::tempdir().unwrap();
        let dir = metrics_dir_from(Some(String::new()), tmp.path().to_path_buf());
        assert_eq!(dir, tmp.path().join("cadence").join("metrics"));
    }

    // --- write-new / read-both precedence (cadence-hooks#626) ---

    #[test]
    fn fresh_install_writes_land_under_the_new_config_root() {
        // Neither the new nor the legacy root exists on disk yet — a true
        // fresh install. The resolved dir is the new root (created lazily by
        // the first write), never the legacy shape.
        let tmp = tempfile::tempdir().unwrap();
        let dir = metrics_dir_from(None, tmp.path().to_path_buf());
        assert_eq!(dir, tmp.path().join("cadence").join("metrics"));
        assert!(!dir.exists(), "resolving the dir must not create it");
    }

    #[test]
    fn legacy_only_data_is_still_read() {
        // An unmigrated install: only the legacy `<config>/metrics` root has
        // ever existed. The read-both window means it keeps being resolved
        // until the migration script moves its data.
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("metrics");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("commits.jsonl"), "{}\n").unwrap();

        let dir = metrics_dir_from(None, tmp.path().to_path_buf());
        // Canonicalized: the resolver always resolves the legacy root before
        // returning it (cheap and correct even when it's a plain directory,
        // not just when it's a symlink — see the dedicated symlink test
        // below), and on macOS a tempdir's own path traverses a `/tmp` ->
        // `/private/tmp`-style symlink, so the literal `legacy` path and its
        // canonical form can legitimately differ here too.
        assert_eq!(dir, std::fs::canonicalize(&legacy).unwrap());
        assert!(dir.join("commits.jsonl").exists());
    }

    #[test]
    fn new_root_takes_precedence_once_both_exist() {
        // Both roots present — the shape mid-migration, or right after the
        // script runs and leaves the legacy root behind for a beat. The new
        // root wins outright; this binary never merges the two trees.
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("metrics");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("commits.jsonl"), "{}\n").unwrap();

        let new_root = tmp.path().join("cadence").join("metrics");
        std::fs::create_dir_all(&new_root).unwrap();
        std::fs::write(new_root.join("commits.jsonl"), "{}\n").unwrap();

        let dir = metrics_dir_from(None, tmp.path().to_path_buf());
        assert_eq!(dir, new_root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_legacy_root_resolves_to_its_target() {
        // The multi-profile caveat: the legacy root is a symlink (shared
        // across profiles) rather than a real directory. Operating on the
        // symlink path itself is what breaks a second profile silently once
        // its target moves — resolve to the target instead.
        let tmp = tempfile::tempdir().unwrap();
        let real_target = tmp.path().join("shared-metrics-target");
        std::fs::create_dir_all(&real_target).unwrap();
        std::fs::write(real_target.join("commits.jsonl"), "{}\n").unwrap();

        let legacy = tmp.path().join("metrics");
        std::os::unix::fs::symlink(&real_target, &legacy).unwrap();

        let dir = metrics_dir_from(None, tmp.path().to_path_buf());
        assert_eq!(dir, std::fs::canonicalize(&real_target).unwrap());
    }

    #[test]
    fn claude_config_dir_override_is_respected() {
        // `metrics_dir()` itself (not the pure helper) must resolve the
        // config root through `CLAUDE_CONFIG_DIR`, honoring a relocated
        // config dir end to end. Holds `ENV_LOCK` (see the module doc above)
        // since this mutates process-global env, and clears
        // `CADENCE_METRICS_DIR` so it can't shadow the config-dir path this
        // test is asserting on.
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let previous_config_dir = std::env::var("CLAUDE_CONFIG_DIR").ok();
        let previous_metrics_dir = std::env::var("CADENCE_METRICS_DIR").ok();
        // SAFETY: serialized by ENV_LOCK above — no other thread in this
        // process reads/writes CLAUDE_CONFIG_DIR or CADENCE_METRICS_DIR while
        // this guard is held.
        unsafe {
            std::env::set_var("CLAUDE_CONFIG_DIR", tmp.path());
            std::env::remove_var("CADENCE_METRICS_DIR");
        }

        let dir = metrics_dir();

        // SAFETY: same justification as above — still under ENV_LOCK.
        unsafe {
            match previous_config_dir {
                Some(v) => std::env::set_var("CLAUDE_CONFIG_DIR", v),
                None => std::env::remove_var("CLAUDE_CONFIG_DIR"),
            }
            match previous_metrics_dir {
                Some(v) => std::env::set_var("CADENCE_METRICS_DIR", v),
                None => std::env::remove_var("CADENCE_METRICS_DIR"),
            }
        }

        assert_eq!(dir, tmp.path().join("cadence").join("metrics"));
    }

    #[test]
    fn transcript_diagnostics_stop_at_the_size_cap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("diagnostics.jsonl");
        std::fs::write(&path, vec![b'x'; MAX_DIAGNOSTICS_BYTES as usize]).unwrap();

        append_transcript_diagnostic_to(temp.path(), "codex", "unknown", "schema", "session");

        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            MAX_DIAGNOSTICS_BYTES
        );
    }

    #[test]
    fn detects_plain_git_commit() {
        assert!(is_git_commit("git commit -m 'x'"));
        assert!(is_git_commit("git commit"));
    }

    #[test]
    fn detects_git_c_commit() {
        assert!(is_git_commit("git -C /some/repo commit -m x"));
    }

    #[test]
    fn detects_commit_after_separator() {
        assert!(is_git_commit("cd repo && git commit -m x"));
        assert!(is_git_commit("foo; git commit"));
    }

    #[test]
    fn ignores_commit_tree() {
        assert!(!is_git_commit("git commit-tree abc123"));
    }

    #[test]
    fn ignores_non_commit_git() {
        assert!(!is_git_commit("git status"));
        assert!(!is_git_commit("git push origin main"));
    }

    #[test]
    fn ignores_unrelated_commands() {
        assert!(!is_git_commit("echo committing changes"));
        assert!(!is_git_commit("ls -la"));
    }

    #[test]
    fn safe_session_id_accepts_uuid_like() {
        assert!(is_safe_session_id("a1b2c3d4-5e6f-7890-abcd-ef0123456789"));
        assert!(is_safe_session_id("session_42"));
        assert!(is_safe_session_id("ABC-123_xyz"));
    }

    #[test]
    fn safe_session_id_rejects_traversal_and_separators() {
        assert!(!is_safe_session_id(""));
        assert!(!is_safe_session_id(".."));
        assert!(!is_safe_session_id("../../etc/passwd"));
        assert!(!is_safe_session_id("a/b"));
        assert!(!is_safe_session_id("a.before")); // '.' is not allowed
        assert!(!is_safe_session_id("with space"));
        assert!(!is_safe_session_id("/abs"));
    }

    #[test]
    fn timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        // e.g. 2026-05-19T00:51:45Z — 20 chars, ends in Z.
        assert!(ts.ends_with('Z'), "timestamp should end in Z: {ts}");
        assert_eq!(ts.len(), 20, "ISO second-precision UTC is 20 chars: {ts}");
    }

    // `repo_basename`'s git-backed resolution — this crate's first tests to
    // spin up a real on-disk repo. `Scratch` is `target/`-rooted by default
    // (never tempdir-rooted, cadence-hooks#312/#403's carve-out gotcha), so
    // these run outside the enforce-worktree carve-out like every other
    // consumer of `cadence_hooks_core::git_fixtures`.
    mod repo_basename_tests {
        use super::*;
        use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
        use std::path::{Path, PathBuf};

        /// This crate's own `target/`-relative scratch root — `env!` resolves
        /// at THIS call site, landing under `crates/metrics`'s own `target/`.
        fn scratch_root() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/metrics-repo-basename-scratch")
        }

        #[test]
        fn primary_checkout_names_the_repo() {
            let scratch = Scratch::new(&scratch_root(), "primary");
            let repo = scratch.path().join("myrepo");
            std::fs::create_dir(&repo).unwrap();
            init_repo(&repo);

            assert_eq!(repo_basename(Some(&repo.to_string_lossy())), "myrepo");
        }

        /// The regression this fix closes: a linked worktree at
        /// `<repo>/.claude/worktrees/<slug>` must still report the *repo's*
        /// name, never `<slug>` — `git_common_dir`'s parent is the repo root
        /// on both the primary checkout and every linked worktree.
        #[test]
        fn linked_worktree_names_the_repo_not_the_slug() {
            let scratch = Scratch::new(&scratch_root(), "linked");
            let repo = scratch.path().join("myrepo");
            std::fs::create_dir(&repo).unwrap();
            init_repo(&repo);

            let wt = repo.join(".claude").join("worktrees").join("some-slug");
            std::fs::create_dir_all(wt.parent().unwrap()).unwrap();
            git_in(
                &repo,
                &["worktree", "add", &wt.to_string_lossy(), "-b", "feat/x"],
            );

            let basename = repo_basename(Some(&wt.to_string_lossy()));
            assert_eq!(basename, "myrepo");
            assert_ne!(basename, "some-slug");
        }

        /// The regression a naive `ends_with(".git")` on the whole path would
        /// reintroduce: a `--separate-git-dir` admin dir conventionally named
        /// `<repo>.git` (a real-world layout, e.g. bare-style admin dirs under
        /// `/gitdirs/`) also ends with the literal `.git`, so a string-suffix
        /// check takes the "parent of git_common_dir" branch and reports the
        /// admin dir's *parent* (`gitdirs`) as the repo — not the actual repo
        /// working directory, and not even a subdirectory of it. Comparing
        /// the exact final path component to `.git` closes this: the admin
        /// dir here is named `myrepo.git`, not `.git`, so it correctly falls
        /// through to the `repo_root` branch instead.
        #[test]
        fn separate_git_dir_named_with_dot_git_suffix_does_not_report_its_parent() {
            let scratch = Scratch::new(&scratch_root(), "separate-gitdir");
            let admin = scratch.path().join("gitdirs").join("myrepo.git");
            std::fs::create_dir_all(admin.parent().unwrap()).unwrap();
            let repo = scratch.path().join("myrepo");
            std::fs::create_dir(&repo).unwrap();
            git_in(
                &repo,
                &["init", "--separate-git-dir", &admin.to_string_lossy()],
            );

            let basename = repo_basename(Some(&repo.to_string_lossy()));
            assert_eq!(basename, "myrepo");
            assert_ne!(basename, "gitdirs");
        }

        #[test]
        fn non_repo_dir_falls_back_to_cwd_basename() {
            // A genuine system tempdir, not a `Scratch` — `Scratch` is
            // `target/`-rooted by default (cadence-hooks#312/#403), which
            // nests it inside THIS repo's own working tree on a plain
            // checkout. `GitState::resolve` then correctly walks up and
            // finds cadence-hooks' own `.git`, so a `Scratch`-based "not a
            // repo" dir isn't actually outside a repo on CI (only locally,
            // where a `.claude/worktrees/` checkout trips Scratch's
            // carve-out relocation to `$XDG_CACHE_HOME` and masks it). A
            // system tempdir is outside any repo regardless of where the
            // test runs.
            let dir = tempfile::Builder::new()
                .prefix("not-a-repo-")
                .tempdir()
                .unwrap();
            let expected = dir
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();

            assert_eq!(repo_basename(Some(&dir.path().to_string_lossy())), expected);
        }
    }
}
