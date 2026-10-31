//! `metrics cat <ledger>`: one ledger's whole history as JSONL on stdout, so
//! readers stop globbing segments and archives themselves
//! (cameronsjo/cadence-hooks#1590).
//!
//! Order: the monthly archives (month order), then the rotated segments (name
//! order, which is time order), then the live file. `--include-test-rows`
//! prepends `archive/denials.testrows.jsonl.gz` for `denials`. A move a crash
//! left half done is printed once: a segment whose bytes the archive already
//! holds (per the leftover manifest) is skipped, and a segment whose test rows
//! the test-row archive already holds prints its kept rows only.

use crate::common;
use crate::rotate::{self, ARCHIVE_DIR, TESTROWS_ARCHIVE};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

/// Whether `ledger` is a plain ledger name (`denials`, `plan-links`): ASCII
/// alphanumerics, `-` and `_` only, so it can never name a path. Pure.
pub fn is_ledger_name(ledger: &str) -> bool {
    !ledger.is_empty()
        && ledger
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parse a `--since` value (an ISO 8601 timestamp, or a `YYYY-MM-DD` date
/// meaning its UTC midnight) into the compact `YYYYMMDDTHHMMSSZ` form rows and
/// segment stamps compare against. Pure.
pub fn parse_since(value: &str) -> Option<String> {
    let ts = value.parse::<jiff::Timestamp>().ok().or_else(|| {
        value
            .parse::<jiff::civil::Date>()
            .ok()
            .and_then(|d| d.to_zoned(jiff::tz::TimeZone::UTC).ok())
            .map(|z| z.timestamp())
    })?;
    Some(common::compact_stamp(
        &ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    ))
}

struct Emitter<'a, W: Write> {
    out: &'a mut W,
    since: Option<jiff::Timestamp>,
}

impl<W: Write> Emitter<'_, W> {
    /// Print `reader`'s rows. A read error names `source`; a write error (a
    /// closed pipe) passes through as is.
    fn emit(&mut self, reader: impl Read, source: &Path) -> std::io::Result<()> {
        for line in BufReader::new(reader).split(b'\n') {
            let line = line.map_err(|err| named(source, &err))?;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if let Some(since) = self.since {
                // Parsed, so fractional seconds and `+00:00` offsets compare
                // by instant, not by spelling.
                let ts = serde_json::from_slice::<Value>(&line).ok().and_then(|row| {
                    row.get("ts")
                        .and_then(Value::as_str)
                        .and_then(|ts| ts.parse::<jiff::Timestamp>().ok())
                });
                if !ts.is_some_and(|ts| ts >= since) {
                    continue;
                }
            }
            self.out.write_all(&line)?;
            self.out.write_all(b"\n")?;
        }
        Ok(())
    }

    fn emit_file(&mut self, path: &Path) -> std::io::Result<()> {
        match rotate::open_read_nofollow(path) {
            Ok(file) => self.emit(file, path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(named(path, &err)),
        }
    }

    fn emit_gz(&mut self, path: &Path) -> std::io::Result<()> {
        match rotate::open_read_nofollow(path) {
            Ok(file) => self.emit(flate2::read::MultiGzDecoder::new(file), path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(named(path, &err)),
        }
    }
}

/// `err` with the path it happened on, keeping its kind.
fn named(path: &Path, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("read {}: {err}", path.display()))
}

/// Take the shared rotate lock, or read unlocked with a stderr note when the
/// lock file cannot be opened for lack of permission or a read-only
/// filesystem: reading must not need write access to the metrics dir.
fn shared_lock_or_note(state: &Path) -> std::io::Result<Option<std::fs::File>> {
    match rotate::lock_shared(state) {
        Ok(lock) => Ok(lock),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            eprintln!(
                "metrics cat: cannot lock {}/{} ({err}); reading without it, so a rotate running now could make a row print twice or not at all",
                state.display(),
                rotate::LOCK_FILE
            );
            Ok(None)
        }
        Err(err) => Err(named(&state.join(rotate::LOCK_FILE), &err)),
    }
}

/// Stream `ledger`'s history from `dir` to `out`. `since` is compact
/// (`YYYYMMDDTHHMMSSZ`); when set, only rows whose `ts` is at or after it
/// print, and archives and segments that cannot hold such a row are skipped.
pub fn cat(
    dir: &Path,
    ledger: &str,
    since: Option<&str>,
    include_test_rows: bool,
    out: &mut impl Write,
) -> std::io::Result<()> {
    let archive_dir = dir.join(ARCHIVE_DIR);
    let live = dir.join(format!("{ledger}.jsonl"));
    // Shared lock for the whole read: a running archive move finishes first,
    // and a rotate that starts meanwhile skips, so no row moves between the
    // archive and segment phases below.
    let _lock = shared_lock_or_note(&dir.join("state"))?;
    // A manifest left by a crash names one segment whose rows may be in two
    // places. Unreadable manifest: print everything (fail toward completeness).
    let manifest = rotate::read_manifest(&dir.join("state")).ok().flatten();
    // The same judgement `recover` acts on: a segment whose move is proven
    // archived prints only what it will hold once the move finishes (rows
    // appended since, after the kept rows of a quarantine); anything unproven
    // prints as it is.
    let pending: Option<(String, Vec<u8>)> = manifest.and_then(|m| {
        if !rotate::manifest_names_ok(&m) {
            return None;
        }
        let current = rotate::read_regular(&dir.join(&m.segment)).ok().flatten();
        match rotate::move_state(&archive_dir, &m, current.as_deref()) {
            Ok(rotate::MoveState::Pending { remaining }) => Some((m.segment, remaining)),
            _ => None,
        }
    });

    let since_ts = since
        .and_then(rotate::stamp_unix)
        .and_then(|secs| jiff::Timestamp::from_second(secs).ok());
    let mut emitter = Emitter {
        out,
        since: since_ts,
    };
    if include_test_rows && ledger == "denials" {
        emitter.emit_gz(&archive_dir.join(TESTROWS_ARCHIVE))?;
    }

    // Only an absent `archive/` means "nothing archived"; an unreadable one
    // is an error, or every archived row would silently go missing.
    let mut months: Vec<(String, String)> = match std::fs::read_dir(&archive_dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                rotate::archive_month(ledger, &name).map(|m| (m, name))
            })
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => {
            return Err(std::io::Error::new(
                err.kind(),
                format!("list {}: {err}", archive_dir.display()),
            ));
        }
    };
    months.sort();
    let mut damaged = false;
    for (month, name) in months {
        // A month's archive holds segments stamped that month, whose rows are
        // no newer than the month's end.
        if since.is_some_and(|s| month.replace('-', "").as_str() < s.get(..6).unwrap_or("")) {
            continue;
        }
        // A damaged archive is reported and skipped, so the rest of the
        // history (later archives, segments, the live file) still prints; the
        // run still exits non-zero.
        match emitter.emit_gz(&archive_dir.join(&name)) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::InvalidInput
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                // The name comes from a directory listing, so it is shown
                // through `display_safe`; the commands quote it for the shell.
                eprintln!(
                    "metrics cat: {ARCHIVE_DIR}/{} could not be decoded to the end ({err}); \
                     its remaining rows are skipped. {}",
                    common::display_safe(&name),
                    common::display_safe(&rotate::salvage_hint(&archive_dir, &name))
                );
                damaged = true;
            }
            Err(err) => return Err(err),
        }
    }

    for (stamp, path) in common::stamped_segments(&live) {
        if since.is_some_and(|s| stamp.as_str() < s) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        match &pending {
            Some((segment, remaining)) if segment == name => {
                emitter.emit(&remaining[..], &path)?;
            }
            _ => emitter.emit_file(&path)?,
        }
    }
    emitter.emit_file(&live)?;
    if damaged {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "a damaged archive was skipped; every other row printed",
        ));
    }
    Ok(())
}

/// `metrics cat` (CLI): exit 0 on success, 2 on a bad argument, 1 on a read
/// failure.
pub fn run_cat_cli(dir: &Path, ledger: &str, since: Option<&str>, include_test_rows: bool) -> u8 {
    let ledger = ledger.strip_suffix(".jsonl").unwrap_or(ledger);
    if !is_ledger_name(ledger) {
        eprintln!(
            "metrics cat: expected a ledger name like `denials`, found {:?}",
            common::display_safe_bounded(ledger, 80)
        );
        return 2;
    }
    let since = match since.map(|s| (s, parse_since(s))) {
        None => None,
        Some((_, Some(compact))) => Some(compact),
        Some((raw, None)) => {
            eprintln!(
                "metrics cat: expected --since as an ISO 8601 UTC timestamp or YYYY-MM-DD, found {:?}",
                common::display_safe_bounded(raw, 80)
            );
            return 2;
        }
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    match cat(dir, ledger, since.as_deref(), include_test_rows, &mut out).and_then(|()| out.flush())
    {
        Ok(()) => 0,
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(err) => {
            eprintln!("metrics cat: {ledger}: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_names_are_plain_words() {
        assert!(is_ledger_name("denials"));
        assert!(is_ledger_name("plan-links"));
        assert!(!is_ledger_name(""));
        assert!(!is_ledger_name("../denials"));
        assert!(!is_ledger_name("a/b"));
        assert!(!is_ledger_name("denials.testrows"));
    }

    #[test]
    fn since_accepts_timestamps_and_dates() {
        assert_eq!(
            parse_since("2026-10-31T03:14:02Z").as_deref(),
            Some("20261031T031402Z")
        );
        assert_eq!(
            parse_since("2026-10-31").as_deref(),
            Some("20261031T000000Z")
        );
        assert_eq!(parse_since("yesterday"), None);
    }
}
