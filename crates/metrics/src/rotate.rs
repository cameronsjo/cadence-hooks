//! `metrics rotate`: age-based archive of rotated ledger segments, the
//! `denials` daily rollup, the per-session state sweep, and the one-time
//! `--quarantine-test-rows` move (cameronsjo/cadence-hooks#1590).
//!
//! The rule every step keeps: **no step loses a ledger row, and no step
//! rewrites a live `*.jsonl` file.** Archiving works only on dated segments,
//! which writers already moved aside. The quarantine moves the live `denials`
//! file aside first, through the same `flock` and inode check a cap rotation
//! uses, so concurrent appenders start a fresh live file.
//!
//! Every move is crash-safe through a manifest (`state/rotate-manifest.json`)
//! written before the move and deleted after it. The archive grows by a new
//! gzip member written into a temp file (old archive bytes + the member) and
//! renamed over the archive, so an existing archive is never truncated in
//! place. A segment is deleted only after the archive is fsynced and its new
//! member decodes to the segment's exact bytes. The next run finishes or rolls
//! back whatever a leftover manifest names before doing anything else.
//!
//! Layout under `<metrics_dir>`:
//!
//! - `archive/<ledger>.<YYYY-MM>.jsonl.gz` — archived segments, by the month
//!   of the segment stamp
//! - `archive/denials.testrows.jsonl.gz` — rows `--quarantine-test-rows` moved
//! - `rollups/denials-daily.jsonl` — per-day denial counts
//! - `state/rotate.lock`, `state/rotate-manifest.json`,
//!   `state/rotate.last-success`, `state/rotate.day`,
//!   `state/quarantine-<YYYY-MM-DD>.json`

use crate::common;
use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

/// Archive directory under the metrics dir.
pub const ARCHIVE_DIR: &str = "archive";
/// Rollup directory under the metrics dir.
pub const ROLLUPS_DIR: &str = "rollups";
/// Exclusive lock every `metrics rotate` run takes, under `state/`.
pub const LOCK_FILE: &str = "rotate.lock";
/// Crash-recovery manifest for the move in flight, under `state/`.
pub const MANIFEST_FILE: &str = "rotate-manifest.json";
/// UTC timestamp of the last complete run, under `state/`.
pub const LAST_SUCCESS_FILE: &str = "rotate.last-success";
/// UTC date of the last SessionStart attempt, under `state/`.
pub const DAILY_MARKER_FILE: &str = "rotate.day";
/// Archive of quarantined `denials` test rows, under `archive/`.
pub const TESTROWS_ARCHIVE: &str = "denials.testrows.jsonl.gz";
/// The `denials` daily rollup ledger, under `rollups/`.
pub const DENIALS_ROLLUP: &str = "denials-daily.jsonl";
/// `failopen.jsonl` reason for every `metrics rotate` failure.
pub const FAILOPEN_REASON: &str = "metrics_rotate_failed";

/// `denials` segments older than this are archived.
pub const DENIALS_RETENTION_DAYS: u64 = 90;
/// Every other ledger's segments older than this are archived, the never-drop
/// ledgers ([`NEVER_DROP_LEDGERS`]) included.
pub const DEFAULT_RETENTION_DAYS: u64 = 180;
/// Ledgers whose rows are compressed but never dropped. No step of this
/// command drops a row of any ledger; the list names the ledgers a future
/// drop policy must never touch, and they archive at the default age.
pub const NEVER_DROP_LEDGERS: [&str; 3] = ["commits", "sessions", "plan-links"];
/// A per-session state dir whose newest entry is older than this is swept.
pub const STALE_SESSION_STATE_DAYS: u64 = 7;
/// The `state/` parents whose per-session dirs the sweep may remove:
/// `subagents/<session>/` (`log-subagent` Start markers), `bypass/<session>/`
/// (once-per-session bypass claims), and `commits/<session>/` (the per-session
/// commit counter, cameronsjo/cadence-hooks#1599).
pub const SESSION_STATE_PARENTS: [&str; 3] = ["subagents", "bypass", "commits"];
/// Time the SessionStart run may spend before it stops between segments.
pub const SESSION_START_BUDGET: Duration = Duration::from_secs(2);
/// The SessionStart run leaves a segment larger than twice the rotation cap
/// (32 MiB at the default 16 MiB cap) to `metrics rotate` run by hand. A
/// segment is the live file at the moment it crossed the cap, so an ordinary
/// one is just over the cap and must pass; only a ledger that outgrew the cap
/// before rotation existed is deferred, so it cannot stall a session start.
pub const SESSION_START_SEGMENT_CAP_FACTOR: u64 = 2;

/// [`SESSION_START_SEGMENT_CAP_FACTOR`] times the rotation cap; with rotation
/// off, the factor times the default cap.
pub fn session_start_max_segment_bytes() -> u64 {
    session_start_bound(common::ledger_max_bytes())
}

/// Pure form of [`session_start_max_segment_bytes`] over the resolved cap.
pub fn session_start_bound(cap: Option<u64>) -> u64 {
    cap.unwrap_or(common::DEFAULT_LEDGER_MAX_BYTES)
        .saturating_mul(SESSION_START_SEGMENT_CAP_FACTOR)
}
/// How long [`try_lock`] keeps retrying a lock that looks held. A test binary
/// (or any multithreaded caller) that spawns a child shares the lock's open
/// file description with that child between `fork` and `exec`, so the lock can
/// look held for a moment with no other run alive; a real run holds it far
/// longer than this.
#[cfg(unix)]
const LOCK_RETRY: Duration = Duration::from_millis(250);
/// Slack over a segment's length that [`archive_holds`] decodes before it
/// stops: the archived content is the segment plus at most one newline.
const DECODE_SLACK_BYTES: u64 = 1024 * 1024;
/// Wait after moving the live `denials` file aside before reading it, so an
/// appender that opened the old file finishes its one write first.
pub const QUARANTINE_GRACE: Duration = Duration::from_secs(1);

/// Why `metrics rotate` refuses to run off Unix.
pub const UNSUPPORTED: &str =
    "needs Unix (an flock run lock); nothing was changed on this platform";

const DAY_SECS: u64 = 86_400;
/// Depth bound for the per-session mtime walk; the dirs hold flat markers.
const MAX_STATE_DEPTH: usize = 4;

/// A step of a manifest-protected move, named so a test can fail right after
/// it and prove the next run recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The `denials` rollup rows for the segment are appended.
    AfterRollup,
    /// The manifest is written.
    AfterManifest,
    /// The new archive is written to its temp file, not yet renamed.
    AfterArchiveTemp,
    /// The new archive is renamed into place.
    AfterArchiveRename,
    /// What the segment will hold is recorded in the manifest
    /// (`final_sha256`/`final_len`), before the segment is replaced.
    AfterFinalRecorded,
    /// The segment's new contents (kept rows, rows appended since the read, a
    /// torn last row) are written to their temp file.
    AfterKeptTemp,
    /// The segment is deleted or replaced by what it keeps; only the manifest
    /// is left.
    AfterSourceDone,
}

/// Fault injection for tests: called after each [`Step`]; an `Err` aborts the
/// run there, as a kill would.
pub type Fault<'a> = &'a dyn Fn(Step) -> std::io::Result<()>;

/// No faults: the production path.
pub fn no_fault(_: Step) -> std::io::Result<()> {
    Ok(())
}

/// Options for one archive run.
pub struct RotateOptions<'a> {
    /// Unix seconds the retention windows and the sweep are measured from.
    pub now: i64,
    /// Stop cleanly between segments once this passes.
    pub deadline: Option<Instant>,
    /// Leave segments larger than this for a later run (the SessionStart run
    /// sets [`session_start_max_segment_bytes`]; the CLI sets none).
    pub max_segment_bytes: Option<u64>,
    /// Test fault injection.
    pub fault: Fault<'a>,
}

/// What one archive run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RotateReport {
    /// Another run held the lock; nothing was done.
    pub skipped: bool,
    /// The deadline stopped the run before every eligible segment was archived.
    pub partial: bool,
    /// `(segment, archive, rows)` per archived segment.
    pub archived: Vec<(String, String, u64)>,
    /// Per-session state dirs removed.
    pub swept: usize,
    /// Segments past retention left for a later run because they exceed
    /// [`RotateOptions::max_segment_bytes`].
    pub deferred: usize,
    /// A leftover manifest was completed or rolled back first.
    pub recovered: bool,
    /// Archives found damaged; their segments were left in place and the
    /// rest of the run went on.
    pub damaged: Vec<String>,
    /// `denials` segments past retention held back because
    /// `--quarantine-test-rows` has not run here yet ([`quarantine_has_run`]).
    pub awaiting_quarantine: usize,
}

/// The crash-recovery record for one move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Manifest {
    /// `archive` or `quarantine`.
    pub op: String,
    /// The source segment's file name in the metrics dir.
    pub segment: String,
    /// The archive's file name in `archive/`.
    pub archive: String,
    /// Rows moving into the archive.
    pub rows: u64,
    /// sha256 of the source segment's bytes as read.
    pub sha256: String,
    /// Byte length of the source segment as read.
    pub source_len: u64,
    /// sha256 of the bytes the new archive member decodes to.
    pub archived_sha256: String,
    /// The archive's byte length before the move (0 when it did not exist).
    pub archive_len_before: u64,
    /// Quarantine: sha256 of the rows that stay in the segment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_sha256: Option<String>,
    /// sha256 of exactly what the segment holds once the move finishes,
    /// recorded (with [`Manifest::final_len`]) before the segment is replaced,
    /// so a crash after the replace reads as finished rather than unproven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_sha256: Option<String>,
    /// Byte length that goes with [`Manifest::final_sha256`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_len: Option<u64>,
}

// ---------------------------------------------------------------------------
// Pure decisions
// ---------------------------------------------------------------------------

/// Days a segment of the ledger `stem` stays a plain segment before it is
/// archived. Pure.
pub fn retention_days(stem: &str) -> u64 {
    match stem {
        "denials" => DENIALS_RETENTION_DAYS,
        _ => DEFAULT_RETENTION_DAYS,
    }
}

/// Unix seconds of a compact segment stamp (`YYYYMMDDTHHMMSSZ`). Pure.
pub(crate) fn stamp_unix(stamp: &str) -> Option<i64> {
    let b = stamp.get(..16)?;
    let iso = format!(
        "{}-{}-{}T{}:{}:{}Z",
        b.get(0..4)?,
        b.get(4..6)?,
        b.get(6..8)?,
        b.get(9..11)?,
        b.get(11..13)?,
        b.get(13..15)?
    );
    iso.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

/// Whether a segment of `stem` stamped `stamp` is past its retention window
/// at `now` (strictly older than the window). An unparsable stamp never is. Pure.
pub fn past_retention(stem: &str, stamp: &str, now: i64) -> bool {
    let Some(at) = stamp_unix(stamp) else {
        return false;
    };
    let window = i64::try_from(retention_days(stem) * DAY_SECS).unwrap_or(i64::MAX);
    now.saturating_sub(at) > window
}

/// The monthly archive a segment of `stem` stamped `stamp` moves into. Pure.
pub(crate) fn archive_name(stem: &str, stamp: &str) -> String {
    format!(
        "{stem}.{}-{}.jsonl.gz",
        stamp.get(0..4).unwrap_or("0000"),
        stamp.get(4..6).unwrap_or("00")
    )
}

/// The `YYYY-MM` of a monthly archive of `stem`, or `None` when `file_name`
/// is not one (the test-row archive is not). Pure.
pub(crate) fn archive_month(stem: &str, file_name: &str) -> Option<String> {
    let month = file_name
        .strip_prefix(stem)?
        .strip_prefix('.')?
        .strip_suffix(".jsonl.gz")?;
    let b = month.as_bytes();
    (b.len() == 7 && b[4] == b'-' && b[..4].iter().chain(&b[5..]).all(u8::is_ascii_digit))
        .then(|| month.to_string())
}

fn uuid_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("uuid regex must compile")
    })
}

/// Whether a `denials` row is a test row: it parses as JSON and its
/// `sessionId` is absent, null, not a string, or not a UUID. A line that does
/// not parse is kept, since nothing proves it is a test row. Pure.
pub fn is_test_row(line: &str) -> bool {
    let Ok(row) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    !row.get("sessionId")
        .and_then(Value::as_str)
        .is_some_and(|id| uuid_regex().is_match(id))
}

/// `bytes` with a final newline added when it has content and lacks one, so
/// concatenated members never fuse two rows. Pure.
fn normalized(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

/// How recently a segment must have changed for its torn last row to be held
/// back for its writer: far longer than a hook takes to finish one append.
const TORN_TAIL_HOLD: Duration = Duration::from_secs(60);

/// Whether `path` changed within [`TORN_TAIL_HOLD`]. Unreadable reads as
/// recent, which only holds a torn row back one more run.
fn recently_modified(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_none_or(|age| age < TORN_TAIL_HOLD)
}

/// Length of the bytes up to and including the last newline: the rows a move
/// may take. A torn last row (no newline yet, its writer still mid-append)
/// stays in the segment. Pure.
fn complete_len(bytes: &[u8]) -> usize {
    bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1)
}

/// Non-blank lines in `bytes`. Pure.
fn row_count(bytes: &[u8]) -> u64 {
    bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .count() as u64
}

/// Split `bytes` into `(kept, test)` rows, each newline-terminated, blank lines
/// dropped. Pure.
fn split_test_rows(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut kept = Vec::new();
    let mut test = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let target = match std::str::from_utf8(line) {
            Ok(text) if is_test_row(text) => &mut test,
            _ => &mut kept,
        };
        target.extend_from_slice(line);
        target.push(b'\n');
    }
    (kept, test)
}

/// Per-(day, hook, repo, decision) counts of the `denials` rows in `bytes`,
/// as rollup rows naming `segment` and `movedSha256`, the hash of the bytes
/// being moved, so a segment moved twice (rows left behind the first time)
/// rolls each part up once. Rows that do not parse are left out of the counts
/// (their bytes still go to the archive). Pure.
pub(crate) fn denial_rollup_rows(bytes: &[u8], segment: &str) -> Vec<Value> {
    let moved = sha256_hex(bytes);
    let mut counts: BTreeMap<(String, String, String, String), u64> = BTreeMap::new();
    for line in bytes.split(|b| *b == b'\n') {
        let Ok(row) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        let field = |key: &str| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let ts = field("ts");
        let day = ts.get(..10).unwrap_or("unknown").to_string();
        *counts
            .entry((day, field("hook"), field("repo"), field("decision")))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((day, hook, repo, decision), count)| {
            json!({
                "schemaVersion": 1,
                "day": day,
                "hook": hook,
                "repo": repo,
                "decision": decision,
                "count": count,
                "segment": segment,
                "movedSha256": moved,
            })
        })
        .collect()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Private file I/O: 0600 files, 0700 dirs, never through a symlink
// ---------------------------------------------------------------------------

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

/// Make sure `dir` is a real directory (creating it `0700` when absent),
/// refusing a symlink or a file in its place.
pub(crate) fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => Ok(()),
        Ok(_) => Err(io_err(format!(
            "expected {} to be a directory, found a symlink or file",
            dir.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => common::create_private_dir(dir),
        Err(err) => Err(err),
    }
}

/// Read a regular file without following a symlink. `None` when absent.
pub(crate) fn read_regular(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let mut file = match open_read_nofollow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// Open a regular file for reading, never through a symlink.
pub(crate) fn open_read_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK so a FIFO planted under a ledger name cannot hang the open.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io_err(format!(
            "expected {} to be a regular file",
            path.display()
        )));
    }
    Ok(file)
}

/// Create a new `0600` file, failing when the name exists, never through a
/// symlink.
fn create_private_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Remove `path` when present.
fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Write `bytes` to `dir/name` through a `0600` temp file renamed over it, so
/// a reader never sees a half-written file.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    remove_if_present(&tmp)?;
    let mut file = create_private_new(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, dir.join(name))?;
    fsync_dir(dir)
}

fn gzip_member(content: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    encoder.finish()
}

/// Decode every gzip member in `bytes`, concatenated.
#[cfg(all(test, unix))]
pub(crate) fn gunzip_all(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    if bytes.is_empty() {
        return Ok(out);
    }
    MultiGzDecoder::new(bytes).read_to_end(&mut out)?;
    Ok(out)
}

/// Decode every gzip member in `bytes`, stopping past `cap` output bytes.
/// `None` when the output would exceed `cap`.
fn gunzip_capped(bytes: &[u8], cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    if bytes.is_empty() {
        return Ok(Some(out));
    }
    MultiGzDecoder::new(bytes)
        .take(cap.saturating_add(1))
        .read_to_end(&mut out)?;
    Ok((out.len() as u64 <= cap).then_some(out))
}

/// What [`salvage_hint`] says instead of commands when a name or directory
/// would display differently from what it is.
const UNSAFE_NAME_HINT: &str = "its name or directory holds invisible or control characters (or is \
     not UTF-8), so no commands are given: list the directory with `ls -b`, rename the file to a \
     plain name by hand, and run `cadence-hooks metrics rotate` again";

/// `s` as one single-quoted shell word. Pure.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The commands that save a damaged archive's intact rows: move it aside,
/// decode every member up to the damage (`gzip -dc` writes what it decoded
/// before it stops), keep only complete lines (a streaming gzip also writes the
/// damaged member's partial output, which ends mid-row), and compress that back
/// under the archive's name, owner-only. Then rerun `metrics rotate`.
pub fn salvage_hint(archive_dir: &Path, name: &str) -> String {
    // Every place this text reaches a person strips invisible and control
    // characters, so a command built from such a name would name a different
    // file once displayed (a stripped zero-width character turns it into the
    // intact archive's name). Give no command then.
    // A directory that is not UTF-8 displays lossily, so it counts too.
    let Some(dir_text) = archive_dir.to_str() else {
        return UNSAFE_NAME_HINT.to_string();
    };
    if common::display_safe(name) != name || common::display_safe(dir_text) != dir_text {
        return UNSAFE_NAME_HINT.to_string();
    }
    let aside = shell_quote(&format!("./{name}.damaged"));
    format!(
        "save its intact rows with: {}, then run `cadence-hooks metrics rotate` again; keep {aside} \
         until the rows check out (the commands stop if an older {aside} exists: remove or rename it first)",
        salvage_commands(archive_dir, name)
    )
}

/// The shell commands [`salvage_hint`] names. Every path is one single-quoted
/// word and every name starts with `./`, so no file name can run a command or
/// read as an option. The chain stops, non-zero, when `<name>.damaged`
/// already exists (`mv -n` would exit 0 when it declines), so a rerun never
/// replaces the first copy and the rows still undecoded in it. Pure.
pub fn salvage_commands(archive_dir: &Path, name: &str) -> String {
    let dir = shell_quote(&archive_dir.display().to_string());
    let live = shell_quote(&format!("./{name}"));
    let aside = shell_quote(&format!("./{name}.damaged"));
    format!(
        "cd {dir} && [ ! -e {aside} ] && [ ! -L {aside} ] && mv {live} {aside} && \
         (umask 077; gzip -dc {aside} 2>/dev/null | perl -ne 'print if /\\n\\z/' | gzip > {live})"
    )
}

/// Refuse to grow an archive whose existing bytes do not decode to the end:
/// gzip cannot resync past a damaged member, so every member appended after it
/// would be unreadable while its source segment is deleted.
fn check_archive_decodes(archive_dir: &Path, name: &str) -> std::io::Result<()> {
    let Some(old) = read_regular(&archive_dir.join(name))? else {
        return Ok(());
    };
    if old.is_empty() {
        return Ok(());
    }
    std::io::copy(&mut MultiGzDecoder::new(&old[..]), &mut std::io::sink())
        .map(|_| ())
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "expected archive {name} to decode to the end before appending, found it damaged \
                     ({err}); its segments stay in place and the archive is untouched. {}",
                    salvage_hint(archive_dir, name)
                ),
            )
        })
}

/// Grow `archive/<name>` by one gzip member holding `content`: old archive
/// bytes plus the member go into a `0600` temp file, fsynced, then renamed
/// over the archive. The existing archive is never truncated in place.
fn append_member(
    archive_dir: &Path,
    name: &str,
    content: &[u8],
    fault: Fault<'_>,
) -> std::io::Result<()> {
    check_archive_decodes(archive_dir, name)?;
    let path = archive_dir.join(name);
    let old = read_regular(&path)?.unwrap_or_default();
    let tmp = archive_dir.join(format!(".{name}.tmp"));
    remove_if_present(&tmp)?;
    let mut file = create_private_new(&tmp)?;
    file.write_all(&old)?;
    file.write_all(&gzip_member(content)?)?;
    file.sync_all()?;
    drop(file);
    fault(Step::AfterArchiveTemp)?;
    std::fs::rename(&tmp, &path)?;
    fsync_dir(archive_dir)
}

/// Whether the archive holds the member the manifest describes: it grew past
/// its recorded length and the bytes after that length decode to content with
/// the recorded sha256 and row count.
pub(crate) fn archive_holds(archive_dir: &Path, manifest: &Manifest) -> std::io::Result<bool> {
    let Some(bytes) = read_regular(&archive_dir.join(&manifest.archive))? else {
        return Ok(false);
    };
    let Ok(before) = usize::try_from(manifest.archive_len_before) else {
        return Ok(false);
    };
    if bytes.len() <= before {
        return Ok(false);
    }
    // The member this move wrote decodes to the segment plus at most one
    // newline; anything that decodes to far more is not it.
    let cap = manifest.source_len.saturating_add(DECODE_SLACK_BYTES);
    let Ok(Some(tail)) = gunzip_capped(&bytes[before..], cap) else {
        return Ok(false);
    };
    Ok(sha256_hex(&tail) == manifest.archived_sha256 && row_count(&tail) == manifest.rows)
}

/// Whether a manifest's names stay inside the metrics dir: `segment` is a
/// segment name and `archive` is that ledger's monthly archive or the test-row
/// archive. Pure.
pub(crate) fn manifest_names_ok(manifest: &Manifest) -> bool {
    let Some((stem, stamp, _)) = common::split_segment_name(&manifest.segment) else {
        return false;
    };
    if manifest.segment.contains('/') {
        return false;
    }
    match manifest.op.as_str() {
        "archive" => manifest.archive == archive_name(&stem, &stamp),
        "quarantine" => stem == "denials" && manifest.archive == TESTROWS_ARCHIVE,
        _ => false,
    }
}

pub(crate) fn read_manifest(state: &Path) -> std::io::Result<Option<Manifest>> {
    let Some(bytes) = read_regular(&state.join(MANIFEST_FILE))? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|err| {
        io_err(format!(
            "expected {MANIFEST_FILE} to hold a rotate manifest, found unparsable JSON: {err}"
        ))
    })
}

fn write_manifest(state: &Path, manifest: &Manifest) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|err| io_err(format!("serialize the rotate manifest: {err}")))?;
    write_atomic(state, MANIFEST_FILE, &bytes)
}

fn remove_manifest(state: &Path) -> std::io::Result<()> {
    remove_if_present(&state.join(MANIFEST_FILE))?;
    fsync_dir(state)
}

/// Hold the run lock: `Some(file)` while held, `None` when another run has it.
#[cfg(unix)]
fn try_lock(state: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(state.join(LOCK_FILE))?;
    if !file.metadata()?.is_file() {
        return Err(io_err(format!(
            "expected {} to be a regular file",
            state.join(LOCK_FILE).display()
        )));
    }
    let give_up = Instant::now() + LOCK_RETRY;
    loop {
        // SAFETY: `file` owns a valid descriptor for the whole call, and
        // `flock` touches no memory.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(file));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            return Err(err);
        }
        // A child forked by another thread can hold the lock for a moment
        // (see LOCK_RETRY); a real run is still running after the retries.
        if Instant::now() >= give_up {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Hold `state/rotate.lock` shared while `metrics cat` reads, blocking until a
/// running archive move finishes; a rotate that starts meanwhile cannot take
/// its exclusive lock and skips. `None` when `state/` does not exist (no run
/// has ever started, so there is nothing to race).
#[cfg(unix)]
pub(crate) fn lock_shared(state: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    match std::fs::symlink_metadata(state) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Err(io_err(format!(
                "expected {} to be a directory, found a symlink or file",
                state.display()
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    }
    let path = state.join(LOCK_FILE);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        // A reader without write access can still take a shared lock on an
        // existing lock file opened read-only; the caller handles the rest.
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            // O_NONBLOCK: a FIFO planted under the lock name must not hang
            // the open; the regular-file check below refuses it.
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
            {
                Ok(file) => file,
                Err(_) => return Err(err),
            }
        }
        Err(err) => return Err(err),
    };
    if !file.metadata()?.is_file() {
        return Err(io_err(format!(
            "expected {} to be a regular file",
            path.display()
        )));
    }
    // SAFETY: `file` owns a valid descriptor for the whole call, and `flock`
    // touches no memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some(file))
}

/// Off Unix nothing archives (see [`UNSUPPORTED`]), so there is no move to race.
#[cfg(not(unix))]
pub(crate) fn lock_shared(_state: &Path) -> std::io::Result<Option<std::fs::File>> {
    Ok(None)
}

// Never reached: `rotate` and `quarantine` return early off Unix (UNSUPPORTED).
#[cfg(not(unix))]
fn try_lock(state: &Path) -> std::io::Result<Option<std::fs::File>> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join(LOCK_FILE))
        .map(Some)
}

/// Every segment in `dir` (any ledger) as `(file name, stem, stamp)`, in name
/// order, regular files only.
fn all_segments(dir: &Path) -> Vec<(String, String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let (stem, stamp, _) = common::split_segment_name(&name)?;
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_file)
                .map(|_| (name, stem, stamp))
        })
        .collect();
    out.sort();
    out
}

fn dirs(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        dir.join("state"),
        dir.join(ARCHIVE_DIR),
        dir.join(ROLLUPS_DIR),
    )
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Where a manifest's move stands, judged from the archive and the segment's
/// current bytes. One answer for both [`recover`] (which acts on it) and
/// `metrics cat` (which prints what the segment will hold), so the two can
/// never disagree about which rows are where.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MoveState {
    /// The archive does not hold the member: nothing moved, the segment keeps
    /// every row.
    NotDone,
    /// The member is archived and the segment already holds what it should
    /// (gone, or the kept rows).
    Finished,
    /// The member is archived and proven to be this segment's rows; the
    /// segment should be left holding `remaining`: rows appended after the
    /// read, after the kept rows for a quarantine.
    Pending {
        /// What the segment holds once the move finishes.
        remaining: Vec<u8>,
    },
    /// Nothing proves the archived member is this segment's rows.
    Unproven(String),
}

/// Judge `manifest` against the archive and `current`, the segment's bytes
/// now (`None` when it is gone). The archived member must decode to exactly
/// what the segment's first `source_len` bytes give (the segment itself for an
/// archive, its test rows for a quarantine); a manifest's own hashes are never
/// enough on their own.
pub(crate) fn move_state(
    archive_dir: &Path,
    manifest: &Manifest,
    current: Option<&[u8]>,
) -> std::io::Result<MoveState> {
    if !manifest_names_ok(manifest) {
        return Ok(MoveState::Unproven(format!(
            "expected the rotate manifest to name a segment and its archive, found {:?} and {:?}",
            manifest.segment, manifest.archive
        )));
    }
    if !archive_holds(archive_dir, manifest)? {
        return Ok(MoveState::NotDone);
    }
    // A crash after the segment was replaced: it holds exactly what the
    // manifest recorded it would. Exact, not a prefix: before the replace the
    // segment can start with those bytes (the kept rows lead a quarantined
    // segment). Before the replace it cannot equal them, since the original
    // holds the moved rows as well.
    if let (Some(sha), Some(flen), Some(bytes)) =
        (&manifest.final_sha256, manifest.final_len, current)
        && bytes.len() as u64 == flen
        && sha256_hex(bytes) == *sha
    {
        return Ok(MoveState::Finished);
    }
    let len = usize::try_from(manifest.source_len).unwrap_or(usize::MAX);
    // The segment as it was read, if it still starts with exactly that.
    let original = current
        .and_then(|b| b.get(..len))
        .filter(|p| sha256_hex(p) == manifest.sha256);
    let suffix = |bytes: &[u8]| bytes.get(len..).unwrap_or_default().to_vec();
    // Bytes after the moved prefix are kept only when that prefix ended on a
    // row boundary; otherwise the first of them would be the rest of a row
    // the move split.
    if let (Some(bytes), Some(original)) = (current, original)
        && bytes.len() > len
        && !original.is_empty()
        && !original.ends_with(b"\n")
    {
        return Ok(MoveState::Unproven(format!(
            "expected the moved part of {} to end on a row boundary, found a split row",
            manifest.segment
        )));
    }
    match manifest.op.as_str() {
        "archive" => match (current, original) {
            (None, _) => Ok(MoveState::Finished),
            (Some(bytes), Some(original))
                if sha256_hex(&normalized(original)) == manifest.archived_sha256 =>
            {
                Ok(MoveState::Pending {
                    remaining: suffix(bytes),
                })
            }
            (Some(_), _) => Ok(MoveState::Unproven(format!(
                "expected {} to start with the archived copy (sha256 {}), found different bytes; \
                 compare it with {} by hand, then remove {MANIFEST_FILE}",
                manifest.segment, manifest.sha256, manifest.archive
            ))),
        },
        "quarantine" => {
            let kept_sha = manifest.kept_sha256.clone().unwrap_or_default();
            match (current, original) {
                (Some(bytes), _) if sha256_hex(bytes) == kept_sha => Ok(MoveState::Finished),
                (None, _) if kept_sha == sha256_hex(b"") => Ok(MoveState::Finished),
                (Some(bytes), Some(original)) => {
                    let (mut kept, test) = split_test_rows(&normalized(original));
                    if sha256_hex(&test) != manifest.archived_sha256
                        || row_count(&test) != manifest.rows
                        || sha256_hex(&kept) != kept_sha
                    {
                        return Ok(MoveState::Unproven(format!(
                            "expected the test rows of {} to be the archived member, found others",
                            manifest.segment
                        )));
                    }
                    kept.extend_from_slice(&suffix(bytes));
                    Ok(MoveState::Pending { remaining: kept })
                }
                (Some(_), None) => Ok(MoveState::Unproven(format!(
                    "expected {} to start with the quarantined original (sha256 {}), found different bytes",
                    manifest.segment, manifest.sha256
                ))),
                (None, _) => Ok(MoveState::Unproven(format!(
                    "expected {} to hold its kept rows, found it missing",
                    manifest.segment
                ))),
            }
        }
        other => Ok(MoveState::Unproven(format!(
            "expected a rotate manifest op of archive or quarantine, found {other:?}"
        ))),
    }
}

/// Finish or roll back the move a leftover manifest names. Returns whether
/// there was one. A manifest whose state cannot be proven ([`MoveState`]) is
/// left in place and reported, so `metrics cat` keeps printing the segment as
/// it is and an operator can look.
pub(crate) fn recover(dir: &Path, fault: Fault<'_>) -> std::io::Result<bool> {
    let (state, archive_dir, _) = dirs(dir);
    let Some(manifest) = read_manifest(&state)? else {
        return Ok(false);
    };
    let source = dir.join(&manifest.segment);
    let current = if manifest_names_ok(&manifest) {
        read_regular(&source)?
    } else {
        None
    };
    match move_state(&archive_dir, &manifest, current.as_deref())? {
        MoveState::NotDone => {
            // The archive rename never happened, so the archive is as it was;
            // at most a temp file is left. The source still holds every row.
            remove_if_present(&archive_dir.join(format!(".{}.tmp", manifest.archive)))?;
            remove_if_present(&dir.join(format!(".{}.tmp", manifest.segment)))?;
            if current.is_none() {
                return Err(io_err(format!(
                    "expected {} to exist while its archive move is incomplete, found it missing",
                    manifest.segment
                )));
            }
        }
        MoveState::Finished => {}
        // Rows appended after the read (and a torn last row) stay, in their
        // segment.
        MoveState::Pending { remaining } => {
            finish_move(dir, &manifest, &remaining, fault)?;
            return Ok(true);
        }
        MoveState::Unproven(why) => return Err(io_err(why)),
    }
    remove_manifest(&state).map(|()| true)
}

/// Leave the segment holding exactly `remaining` and clear the manifest. What
/// it will hold is recorded in the manifest first, so a crash anywhere after
/// that reads as finished on the next run.
// debt: a writer still holding the segment open after `remaining` is read loses every write it makes after that (it writes to the replaced file); rows from writers that reopen by path, or that land before the re-read, are kept. Exposure is the quarantine's freshly moved live file within QUARANTINE_GRACE (archive segments are archive-age); closes only with writers that flock every append
fn finish_move(
    dir: &Path,
    manifest: &Manifest,
    remaining: &[u8],
    fault: Fault<'_>,
) -> std::io::Result<()> {
    let (state, _, _) = dirs(dir);
    if !remaining.is_empty() {
        let recorded = Manifest {
            final_sha256: Some(sha256_hex(remaining)),
            final_len: Some(remaining.len() as u64),
            ..manifest.clone()
        };
        write_manifest(&state, &recorded)?;
        fault(Step::AfterFinalRecorded)?;
    }
    replace_source(dir, &manifest.segment, remaining, fault)?;
    fault(Step::AfterSourceDone)?;
    remove_manifest(&state)
}

/// Replace segment `name` with `kept` through a temp file and a rename, or
/// delete it when `kept` is empty.
fn replace_source(dir: &Path, name: &str, kept: &[u8], fault: Fault<'_>) -> std::io::Result<()> {
    let path = dir.join(name);
    if kept.is_empty() {
        remove_if_present(&path)?;
        return fsync_dir(dir);
    }
    let tmp = dir.join(format!(".{name}.tmp"));
    remove_if_present(&tmp)?;
    let mut file = create_private_new(&tmp)?;
    file.write_all(kept)?;
    file.sync_all()?;
    drop(file);
    fault(Step::AfterKeptTemp)?;
    std::fs::rename(&tmp, &path)?;
    fsync_dir(dir)
}

// ---------------------------------------------------------------------------
// Archive run
// ---------------------------------------------------------------------------

/// Segment names already rolled up, from every rollup row's `segment`.
/// The rollup key for moving `bytes` out of `segment`. Pure.
fn rollup_key(segment: &str, moved_sha256: &str) -> String {
    format!("{segment}#{moved_sha256}")
}

/// Every (segment, moved bytes) already rolled up, as [`rollup_key`]s.
fn rolled_up_segments(rollup: &Path) -> BTreeSet<String> {
    common::read_ledger(rollup)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|row| {
            let segment = row.get("segment").and_then(Value::as_str)?;
            let moved = row
                .get("movedSha256")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Some(rollup_key(segment, moved))
        })
        .collect()
}

/// Whether the file at `path`, `len` bytes long, ends without a newline.
fn ends_mid_line(path: &Path, len: u64) -> std::io::Result<bool> {
    use std::io::{Seek, SeekFrom};
    if len == 0 {
        return Ok(false);
    }
    let mut file = open_read_nofollow(path)?;
    file.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] != b'\n')
}

fn archive_segment(
    dir: &Path,
    name: &str,
    stem: &str,
    stamp: &str,
    rolled_up: &mut BTreeSet<String>,
    fault: Fault<'_>,
) -> std::io::Result<Option<u64>> {
    let (state, archive_dir, rollups) = dirs(dir);
    let Some(bytes) = read_regular(&dir.join(name))? else {
        return Ok(None);
    };
    // A torn last row is held back only while a writer could still be
    // finishing it (the file changed within TORN_TAIL_HOLD). A segment old
    // enough to archive has no writer left, so its torn or newline-less last
    // row moves too, closed with a newline, rather than staying forever.
    let (moved, content) = if recently_modified(&dir.join(name)) {
        let cut = complete_len(&bytes);
        (bytes[..cut].to_vec(), bytes[..cut].to_vec())
    } else {
        (bytes.clone(), normalized(&bytes))
    };
    if content.is_empty() {
        return Ok(None);
    }
    let rows = row_count(&content);
    let key = rollup_key(name, &sha256_hex(&content));

    if stem == "denials" && !rolled_up.contains(&key) {
        let mut out = String::new();
        for row in denial_rollup_rows(&content, name) {
            out.push_str(&row.to_string());
            out.push('\n');
        }
        if !out.is_empty() {
            // One write, so a kill rarely leaves half a segment's rollup; a
            // partial last line from one is closed off, never joined onto.
            let rollup = rollups.join(DENIALS_ROLLUP);
            let mut file = common::open_ledger(&rollup)?;
            if ends_mid_line(&rollup, file.metadata()?.len())? {
                out.insert(0, '\n');
            }
            file.write_all(out.as_bytes())?;
            file.sync_all()?;
        }
        rolled_up.insert(key);
    }
    fault(Step::AfterRollup)?;

    let archive = archive_name(stem, stamp);
    let archive_len_before = match std::fs::symlink_metadata(archive_dir.join(&archive)) {
        Ok(meta) if meta.is_file() => meta.len(),
        Ok(_) => {
            return Err(io_err(format!(
                "expected archive {archive} to be a regular file, found a symlink or other file"
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => return Err(err),
    };
    check_archive_decodes(&archive_dir, &archive)?;
    let manifest = Manifest {
        op: "archive".to_string(),
        segment: name.to_string(),
        archive: archive.clone(),
        rows,
        sha256: sha256_hex(&moved),
        source_len: moved.len() as u64,
        archived_sha256: sha256_hex(&content),
        archive_len_before,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    write_manifest(&state, &manifest)?;
    fault(Step::AfterManifest)?;
    append_member(&archive_dir, &archive, &content, fault)?;
    fault(Step::AfterArchiveRename)?;
    if !archive_holds(&archive_dir, &manifest)? {
        return Err(io_err(format!(
            "expected {archive} to hold {rows} new rows from {name} after the write, found otherwise"
        )));
    }
    // Finish through the same judgement recovery uses: it re-reads the
    // segment, so rows appended by path before that re-read (and a torn last
    // row held back) stay. A writer still holding the file open loses what
    // it writes after the re-read (see `finish_move`).
    recover(dir, fault)?;
    Ok(Some(rows))
}

/// Newest mtime under `path` (itself included), never following a symlink.
fn newest_mtime(path: &Path, depth: usize) -> Option<SystemTime> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mut newest = meta.modified().ok()?;
    if meta.file_type().is_dir() && depth < MAX_STATE_DEPTH {
        for entry in std::fs::read_dir(path).ok()?.flatten() {
            if let Some(t) = newest_mtime(&entry.path(), depth + 1) {
                newest = newest.max(t);
            }
        }
    }
    Some(newest)
}

/// Remove `state/<parent>/<session>/` dirs whose newest entry is older than
/// [`STALE_SESSION_STATE_DAYS`]: sessions that never reached SessionEnd. Only
/// real directories (never a symlink) whose names pass
/// [`common::is_safe_session_id`], under real parent directories.
pub(crate) fn sweep_session_state(state: &Path, now: i64) -> (usize, Vec<String>) {
    let cutoff =
        now.saturating_sub(i64::try_from(STALE_SESSION_STATE_DAYS * DAY_SECS).unwrap_or(0));
    let mut removed = 0;
    let mut errors = Vec::new();
    for parent in SESSION_STATE_PARENTS {
        let parent_dir = state.join(parent);
        let Ok(meta) = std::fs::symlink_metadata(&parent_dir) else {
            continue;
        };
        if !meta.file_type().is_dir() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&parent_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            if !common::is_safe_session_id(&name) {
                continue;
            }
            let path = entry.path();
            let is_real_dir =
                std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir());
            if !is_real_dir {
                continue;
            }
            let stale = newest_mtime(&path, 0)
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_secs()).ok())
                .is_some_and(|secs| secs < cutoff);
            if stale {
                match std::fs::remove_dir_all(&path) {
                    Ok(()) => removed += 1,
                    Err(err) => errors.push(format!("remove stale state/{parent}/{name}: {err}")),
                }
            }
        }
    }
    (removed, errors)
}

/// Whether `--quarantine-test-rows` has completed a real run in `dir`: a
/// regular `state/quarantine-*.json` record exists. Until then no `denials`
/// segment is archived, so test rows are moved out before they reach a monthly
/// archive and the rollup.
pub fn quarantine_has_run(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir.join("state")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        name.starts_with("quarantine-")
            && name.ends_with(".json")
            && entry.file_type().is_ok_and(|t| t.is_file())
    })
}

/// One archive run over `dir`. Takes the lock (skipping when another run has
/// it), recovers a leftover manifest, archives every segment past retention
/// in name order until the deadline (`denials` only once the quarantine has
/// run), sweeps stale per-session state, and writes `state/rotate.last-success`
/// only when all of it succeeded.
pub fn rotate(dir: &Path, opts: &RotateOptions<'_>) -> Result<RotateReport, String> {
    if cfg!(not(unix)) {
        return Err(UNSUPPORTED.to_string());
    }
    let (state, archive_dir, rollups) = dirs(dir);
    ensure_private_dir(&state).map_err(|e| format!("prepare state/: {e}"))?;
    let Some(_lock) = try_lock(&state).map_err(|e| format!("open {LOCK_FILE}: {e}"))? else {
        return Ok(RotateReport {
            skipped: true,
            ..RotateReport::default()
        });
    };
    let mut report = RotateReport {
        recovered: recover(dir, opts.fault).map_err(|e| format!("recover the last move: {e}"))?,
        ..RotateReport::default()
    };
    ensure_private_dir(&archive_dir).map_err(|e| format!("prepare {ARCHIVE_DIR}/: {e}"))?;
    ensure_private_dir(&rollups).map_err(|e| format!("prepare {ROLLUPS_DIR}/: {e}"))?;
    let mut rolled_up = rolled_up_segments(&rollups.join(DENIALS_ROLLUP));

    let mut damage_notes: Vec<String> = Vec::new();
    let quarantined = quarantine_has_run(dir);
    for (name, stem, stamp) in all_segments(dir) {
        if !past_retention(&stem, &stamp, opts.now) {
            continue;
        }
        if stem == "denials" && !quarantined {
            // Held until the test rows are out; the run is not complete.
            report.awaiting_quarantine += 1;
            report.partial = true;
            continue;
        }
        if report.damaged.contains(&archive_name(&stem, &stamp)) {
            continue;
        }
        if opts.deadline.is_some_and(|d| Instant::now() >= d) {
            report.partial = true;
            break;
        }
        let too_big = opts.max_segment_bytes.is_some_and(|max| {
            std::fs::symlink_metadata(dir.join(&name)).is_ok_and(|m| m.len() > max)
        });
        if too_big {
            // Left for a hand-run `metrics rotate`; the run is not complete.
            report.deferred += 1;
            report.partial = true;
            continue;
        }
        match archive_segment(dir, &name, &stem, &stamp, &mut rolled_up, opts.fault) {
            Ok(Some(rows)) => {
                report
                    .archived
                    .push((name.clone(), archive_name(&stem, &stamp), rows))
            }
            Ok(None) => {}
            // A damaged archive fails before any manifest is written, so the
            // run can leave that archive's segments and go on with the rest
            // instead of stopping every ledger's archive until someone acts.
            Err(err)
                if err.kind() == std::io::ErrorKind::InvalidData
                    && matches!(read_manifest(&state), Ok(None)) =>
            {
                report.damaged.push(archive_name(&stem, &stamp));
                report.partial = true;
                damage_notes.push(format!("archive {name}: {err}"));
            }
            // Anything else stops: a manifest may be pending, and the next
            // move would overwrite it.
            Err(err) => return Err(format!("archive {name}: {err}")),
        }
    }

    let (swept, errors) = sweep_session_state(&state, opts.now);
    report.swept = swept;
    let errors: Vec<String> = damage_notes.into_iter().chain(errors).collect();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    if !report.partial {
        let mut file = common::open_state_marker(&state.join(LAST_SUCCESS_FILE), false)
            .map_err(|e| format!("write {LAST_SUCCESS_FILE}: {e}"))?;
        file.write_all(common::utc_timestamp().as_bytes())
            .map_err(|e| format!("write {LAST_SUCCESS_FILE}: {e}"))?;
    }
    Ok(report)
}

fn now_unix() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// `metrics rotate` (CLI): exit 0 on success or a lost lock, 1 on failure,
/// which is also recorded in `failopen.jsonl`.
pub fn run_rotate_cli(dir: &Path) -> u8 {
    if cfg!(not(unix)) {
        eprintln!("metrics rotate: {UNSUPPORTED}");
        return 1;
    }
    let opts = RotateOptions {
        now: now_unix(),
        deadline: None,
        max_segment_bytes: None,
        fault: &no_fault,
    };
    match rotate(dir, &opts) {
        Ok(report) if report.skipped => {
            cadence_hooks_core::outln!(
                "metrics rotate: another run holds state/{LOCK_FILE}; skipping"
            );
            0
        }
        Ok(report) => {
            let rows: u64 = report.archived.iter().map(|(_, _, r)| r).sum();
            cadence_hooks_core::outln!(
                "metrics rotate: archived {} segments ({rows} rows), swept {} stale session dirs{}",
                report.archived.len(),
                report.swept,
                if report.recovered {
                    ", finished an interrupted move first"
                } else {
                    ""
                }
            );
            if report.awaiting_quarantine > 0 {
                cadence_hooks_core::outln!(
                    "metrics rotate: {} denials segments wait for `cadence-hooks metrics rotate --quarantine-test-rows` (check first with --dry-run)",
                    report.awaiting_quarantine
                );
            }
            0
        }
        Err(err) => {
            crate::log_failopen::log_failopen_at(dir, FAILOPEN_REASON, "rotate", &err);
            eprintln!("metrics rotate: {}", common::display_safe(&err));
            1
        }
    }
}

/// The SessionStart run: at most once per UTC day (`state/rotate.day`), within
/// [`SESSION_START_BUDGET`], failing open. Whatever the budget leaves waits for
/// the next day. A failure is a `failopen.jsonl` row, never an error.
pub fn run_daily_at_session_start(dir: &Path) {
    if cfg!(not(unix)) || !dir.is_dir() {
        return;
    }
    let state = dir.join("state");
    let marker = state.join(DAILY_MARKER_FILE);
    let today = common::today_utc();
    if read_regular(&marker)
        .ok()
        .flatten()
        .is_some_and(|b| b.trim_ascii() == today.as_bytes())
    {
        return;
    }
    if ensure_private_dir(&state).is_err() {
        return;
    }
    match common::open_state_marker(&marker, false) {
        Ok(mut file) => {
            let _ = file.write_all(today.as_bytes());
        }
        Err(_) => return,
    }
    let opts = RotateOptions {
        now: now_unix(),
        deadline: Some(Instant::now() + SESSION_START_BUDGET),
        max_segment_bytes: Some(session_start_max_segment_bytes()),
        fault: &no_fault,
    };
    if let Err(err) = rotate(dir, &opts) {
        crate::log_failopen::log_failopen_at(dir, FAILOPEN_REASON, "rotate", &err);
    }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

/// Options for one quarantine run.
pub struct QuarantineOptions<'a> {
    /// Count and report; change nothing.
    pub dry_run: bool,
    /// Wait after moving the live file aside ([`QUARANTINE_GRACE`]).
    pub grace: Duration,
    /// Test fault injection.
    pub fault: Fault<'a>,
}

/// One file's quarantine counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineFile {
    /// File name in the metrics dir.
    pub file: String,
    /// sha256 of the file as read.
    pub sha256: String,
    /// Rows before.
    pub rows_before: u64,
    /// Rows after (kept).
    pub rows_after: u64,
    /// Rows moved to the test-row archive.
    pub test_rows: u64,
}

/// What one quarantine run found or did.
#[derive(Debug, Default)]
pub struct QuarantineReport {
    /// Per-file counts, segments in name order, then the live file.
    pub files: Vec<QuarantineFile>,
    /// The segment the live file moved to, when it held test rows.
    pub live_moved_to: Option<String>,
    /// The `state/quarantine-*.json` record this real run wrote (every real
    /// run writes one, even when nothing moved; a dry run writes none).
    pub record: Option<String>,
}

fn count_file(name: &str, bytes: &[u8]) -> QuarantineFile {
    let (kept, test) = split_test_rows(&normalized(bytes));
    QuarantineFile {
        file: name.to_string(),
        sha256: sha256_hex(bytes),
        rows_before: row_count(bytes),
        rows_after: row_count(&kept),
        test_rows: row_count(&test),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

fn quarantine_segment(
    dir: &Path,
    name: &str,
    fault: Fault<'_>,
) -> std::io::Result<Option<QuarantineFile>> {
    let (state, archive_dir, _) = dirs(dir);
    let path = dir.join(name);
    let mut held = match open_read_nofollow(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes)?;
    drop(held);
    // Only whole rows move: the live file was just moved aside, so a writer
    // may still be finishing its last row. Counts come from the bytes that
    // move; the recorded sha256 is the whole file's.
    let moved = &bytes[..complete_len(&bytes)];
    let counts = QuarantineFile {
        sha256: sha256_hex(&bytes),
        ..count_file(name, moved)
    };
    let (kept, test) = split_test_rows(moved);
    if test.is_empty() {
        return Ok(Some(counts));
    }
    check_archive_decodes(&archive_dir, TESTROWS_ARCHIVE)?;
    let archive_len_before = std::fs::symlink_metadata(archive_dir.join(TESTROWS_ARCHIVE))
        .map(|m| m.len())
        .unwrap_or(0);
    let manifest = Manifest {
        op: "quarantine".to_string(),
        segment: name.to_string(),
        archive: TESTROWS_ARCHIVE.to_string(),
        rows: row_count(&test),
        sha256: sha256_hex(moved),
        source_len: moved.len() as u64,
        archived_sha256: sha256_hex(&test),
        archive_len_before,
        kept_sha256: Some(sha256_hex(&kept)),
        final_sha256: None,
        final_len: None,
    };
    write_manifest(&state, &manifest)?;
    fault(Step::AfterManifest)?;
    append_member(&archive_dir, TESTROWS_ARCHIVE, &test, fault)?;
    fault(Step::AfterArchiveRename)?;
    if !archive_holds(&archive_dir, &manifest)? {
        return Err(io_err(format!(
            "expected {TESTROWS_ARCHIVE} to hold {} new rows from {name} after the write, found otherwise",
            manifest.rows
        )));
    }
    // Finish through recovery's judgement: it re-reads the segment, so rows
    // appended before that re-read (and the torn last row held back) stay
    // after the kept rows. A writer still holding the moved live file open
    // loses what it writes after the re-read (see `finish_move`); that is
    // the exposure QUARANTINE_GRACE narrows.
    recover(dir, fault)?;
    Ok(Some(counts))
}

#[cfg(unix)]
fn move_live_aside(live: &Path) -> Result<Option<PathBuf>, String> {
    common::rotate_live_now(live).map_err(|e| format!("move denials.jsonl aside: {e}"))
}

#[cfg(not(unix))]
fn move_live_aside(_live: &Path) -> Result<Option<PathBuf>, String> {
    Err("quarantine moves the live ledger aside, which needs Unix".to_string())
}

/// `metrics rotate --quarantine-test-rows`: move every `denials` row whose
/// `sessionId` is not a UUID out of the live file and its segments into
/// `archive/denials.testrows.jsonl.gz`.
pub fn quarantine(dir: &Path, opts: &QuarantineOptions<'_>) -> Result<QuarantineReport, String> {
    if cfg!(not(unix)) {
        return Err(UNSUPPORTED.to_string());
    }
    let live = dir.join("denials.jsonl");
    let mut report = QuarantineReport::default();

    if opts.dry_run {
        let manifest = read_manifest(&dir.join("state")).map_err(|e| e.to_string())?;
        for path in common::ledger_segments(&live)
            .into_iter()
            .chain(std::iter::once(live.clone()))
        {
            let name = file_name(&path);
            if let Some(bytes) = read_regular(&path).map_err(|e| format!("read {name}: {e}"))? {
                report.files.push(count_file(&name, &bytes));
            }
        }
        if manifest.is_some() {
            return Err(format!(
                "a leftover {MANIFEST_FILE} names an interrupted move; run without --dry-run to finish it"
            ));
        }
        return Ok(report);
    }

    let (state, archive_dir, _) = dirs(dir);
    ensure_private_dir(&state).map_err(|e| format!("prepare state/: {e}"))?;
    let Some(_lock) = try_lock(&state).map_err(|e| format!("open {LOCK_FILE}: {e}"))? else {
        return Err(format!("another run holds state/{LOCK_FILE}; try again"));
    };
    recover(dir, opts.fault).map_err(|e| format!("recover the last move: {e}"))?;
    ensure_private_dir(&archive_dir).map_err(|e| format!("prepare {ARCHIVE_DIR}/: {e}"))?;

    let live_has_test_rows = read_regular(&live)
        .map_err(|e| format!("read denials.jsonl: {e}"))?
        .is_some_and(|b| count_file("denials.jsonl", &b).test_rows > 0);
    if live_has_test_rows {
        let moved = move_live_aside(&live)?;
        report.live_moved_to = moved.as_deref().map(file_name);
        std::thread::sleep(opts.grace);
    }

    for path in common::ledger_segments(&live) {
        let name = file_name(&path);
        if let Some(counts) = quarantine_segment(dir, &name, opts.fault)
            .map_err(|e| format!("quarantine {name}: {e}"))?
        {
            report.files.push(counts);
        }
    }
    if let Some(bytes) = read_regular(&live).map_err(|e| format!("read denials.jsonl: {e}"))? {
        report.files.push(count_file("denials.jsonl", &bytes));
    }

    // Written on every real run, even one that moved nothing, so a clean
    // machine also opens the `denials` archive gate (`quarantine_has_run`).
    {
        let record = json!({
            "schemaVersion": 1,
            "ts": common::utc_timestamp(),
            "host": gethostname::gethostname().to_string_lossy(),
            "archive": format!("{ARCHIVE_DIR}/{TESTROWS_ARCHIVE}"),
            "liveMovedTo": report.live_moved_to,
            "files": report.files,
        });
        let bytes = serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?;
        let base = format!("quarantine-{}", common::today_utc());
        let name = (0..1000)
            .map(|n| {
                if n == 0 {
                    format!("{base}.json")
                } else {
                    format!("{base}-{n}.json")
                }
            })
            .find(|n| std::fs::symlink_metadata(state.join(n)).is_err())
            .ok_or_else(|| format!("expected a free {base}*.json name, found all taken"))?;
        write_atomic(&state, &name, &bytes).map_err(|e| format!("write {name}: {e}"))?;
        report.record = Some(name);
    }
    Ok(report)
}

/// `metrics rotate --quarantine-test-rows [--dry-run]` (CLI): exit 0 on
/// success, 1 on failure (recorded in `failopen.jsonl` unless a dry run).
pub fn run_quarantine_cli(dir: &Path, dry_run: bool) -> u8 {
    if cfg!(not(unix)) {
        eprintln!("metrics rotate: {UNSUPPORTED}");
        return 1;
    }
    let opts = QuarantineOptions {
        dry_run,
        grace: QUARANTINE_GRACE,
        fault: &no_fault,
    };
    match quarantine(dir, &opts) {
        Ok(report) => {
            for f in &report.files {
                cadence_hooks_core::outln!(
                    "{}: {} rows, {} test rows{}",
                    common::display_safe(&f.file),
                    f.rows_before,
                    f.test_rows,
                    if dry_run { " (dry run)" } else { "" }
                );
            }
            let total: u64 = report.files.iter().map(|f| f.test_rows).sum();
            if dry_run {
                cadence_hooks_core::outln!(
                    "metrics rotate: would move {total} test rows to {ARCHIVE_DIR}/{TESTROWS_ARCHIVE}; nothing changed"
                );
            } else {
                cadence_hooks_core::outln!(
                    "metrics rotate: moved {total} test rows to {ARCHIVE_DIR}/{TESTROWS_ARCHIVE}{}",
                    report
                        .record
                        .as_deref()
                        .map(|r| format!("; record in state/{r}"))
                        .unwrap_or_default()
                );
            }
            0
        }
        Err(err) => {
            if !dry_run {
                crate::log_failopen::log_failopen_at(dir, FAILOPEN_REASON, "rotate", &err);
            }
            eprintln!("metrics rotate: {}", common::display_safe(&err));
            1
        }
    }
}

// ---------------------------------------------------------------------------
// Health (doctor)
// ---------------------------------------------------------------------------

/// What `doctor` needs to judge the archive's health.
#[derive(Debug, PartialEq, Eq)]
pub struct RotateHealth {
    /// Unix seconds of the last complete run, when recorded and readable.
    pub last_success: Option<i64>,
    /// Whether any rotated segment exists in the metrics dir.
    pub segments_present: bool,
}

/// Read the archive's health inputs from `dir`. Fail-open: unreadable reads
/// as absent.
pub fn rotate_health(dir: &Path) -> RotateHealth {
    let last_success = read_regular(&dir.join("state").join(LAST_SUCCESS_FILE))
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse::<jiff::Timestamp>().ok())
        .map(|t| t.as_second());
    RotateHealth {
        last_success,
        segments_present: !all_segments(dir).is_empty(),
    }
}

// Unix only: off Unix `rotate` and `quarantine` refuse to run (UNSUPPORTED).
#[cfg(all(test, unix))]
#[path = "rotate_tests.rs"]
mod tests;
