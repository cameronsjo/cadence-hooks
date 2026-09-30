//! Record that a runbook's content passed the secret scrub
//! (cameronsjo/cadence-hooks#755).
//!
//! A **CLI action**, not a hook: the `cadence:mining-runbooks` promotion step
//! runs `scrub.py --apply`, then `scrub.py` in check mode, and only on a
//! check-mode exit 0 runs `cadence-hooks cadence record-scrub --file <draft>`.
//! That writes a marker keyed on the SHA-256 of the file's bytes, with
//! `\r\n` read as `\n` ([`markers::scrub_digest`], [`markers::scrub_marker`]);
//! `guardrails guard-runbook-scrub` then lets a
//! Write/Edit under `$CADENCE_RUNBOOKS_DIR` through only when the resulting
//! document hashes to a recorded marker.
//!
//! **It trusts its caller**, exactly as `record-polish` does: it records the
//! hash of whatever file it is handed and does not run or verify the scrub
//! itself. The guard makes skipping the gate a deliberate, visible act (a
//! `record-scrub` call in the transcript) instead of a silent omission; it
//! does not make a lying caller impossible.
//!
//! Exit codes:
//!
//! - **0** — a marker was written.
//! - **1** — nothing was recorded: the file is unreadable, not a regular file,
//!   or the marker directory is not private or not writable.
//! - **2** — usage error (clap's own code for a missing `--file`).

use cadence_hooks_core::markers::{
    polish_dir_is_private, scrub_digest, scrub_marker, write_marker,
};
use cadence_hooks_core::time::utc_timestamp;
use std::path::Path;

/// Largest file `record-scrub` hashes. A runbook is a few KiB of markdown; the
/// cap only bounds a mistaken `--file` at a huge binary.
pub const MAX_SCRUB_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Hash `path`'s bytes, or say why they cannot be hashed.
///
/// The file is opened once and judged by the OPENED handle (`fstat`), then
/// read through a `MAX_SCRUB_FILE_BYTES + 1` cap: a path swapped for a FIFO,
/// a device or a larger file between a `stat` and the read can no longer
/// stall the reader or have bytes other than the judged object's hashed.
/// Opening non-blocking keeps a FIFO from stalling the open itself.
fn read_for_digest(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let unreadable = |e: std::io::Error| format!("cannot read {path:?} ({e})");
    // `open` follows a symlink, so a link to a regular file is hashed as
    // that file — the bytes the Write will carry are what matter, not the name.
    let file = cadence_hooks_core::paths::open_nonblocking(path).map_err(unreadable)?;
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        // A FIFO or `/dev/fd/N` would hand this reader one stream and the
        // Write another; a directory has no content to vouch for.
        return Err(format!("{path:?} is not a regular file"));
    }
    let too_large =
        || format!("{path:?} is larger than {MAX_SCRUB_FILE_BYTES} bytes — not a runbook");
    if meta.len() > MAX_SCRUB_FILE_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SCRUB_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    // A file that grew after the `fstat` is read no further than the cap.
    if bytes.len() as u64 > MAX_SCRUB_FILE_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

/// The marker body: when it was recorded. Nothing path- or content-derived is
/// stored — the filename already is the content key, and the marker dir is
/// not a second copy of the runbook.
fn marker_content() -> String {
    serde_json::json!({ "recorded_at": utc_timestamp() }).to_string()
}

/// Run `cadence-hooks cadence record-scrub --file <path>`. Returns the exit code.
pub fn run_record(file: &str) -> u8 {
    let path = Path::new(file);
    let bytes = match read_for_digest(path) {
        Ok(bytes) => bytes,
        Err(why) => {
            eprintln!("cadence-hooks record-scrub: {why} — nothing recorded.");
            return 1;
        }
    };
    // The guard ignores a marker in a plantable directory, so recording into
    // one would report success for a marker nothing will ever honor.
    if !polish_dir_is_private() {
        eprintln!(
            "cadence-hooks record-scrub: the marker directory is not private (0700) — \
             nothing recorded, and guard-runbook-scrub would not honor a marker there."
        );
        return 1;
    }
    let digest = scrub_digest(&bytes);
    let marker = scrub_marker(&digest);
    match write_marker(&marker, &marker_content()) {
        Ok(()) => {
            cadence_hooks_core::outln!(
                "recorded scrub marker for {file:?} (sha256 {digest}): {}",
                marker.display()
            );
            0
        }
        Err(e) => {
            eprintln!(
                "cadence-hooks record-scrub: marker write failed ({e}) — this record did not land."
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::markers::scrub_marker_present;
    use cadence_hooks_core::test_builders::with_marker_dir;

    #[test]
    fn records_a_marker_keyed_on_the_exact_bytes() {
        let markers = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let file = work.path().join("draft.md");
        std::fs::write(&file, "# Runbook\n\nscrubbed body\n").unwrap();
        with_marker_dir(markers.path(), || {
            let digest = scrub_digest(b"# Runbook\n\nscrubbed body\n");
            assert!(!scrub_marker_present(&digest));
            assert_eq!(run_record(file.to_str().unwrap()), 0);
            assert!(scrub_marker_present(&digest));
            // One byte of difference is a different key.
            assert!(!scrub_marker_present(&scrub_digest(
                b"# Runbook\n\nscrubbed body\n\n"
            )));
        });
    }

    #[test]
    fn records_nothing_for_an_unreadable_or_irregular_file() {
        let markers = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let missing = work.path().join("absent.md");
        with_marker_dir(markers.path(), || {
            for path in [missing.to_str().unwrap(), work.path().to_str().unwrap()] {
                assert_eq!(run_record(path), 1, "{path}");
            }
        });
    }

    /// A FIFO with no writer is refused without stalling: the open is
    /// non-blocking and the opened handle is what is judged.
    #[cfg(unix)]
    #[test]
    fn refuses_a_fifo_without_blocking() {
        let markers = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let fifo = work.path().join("draft.md");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        with_marker_dir(markers.path(), || {
            assert_eq!(run_record(fifo.to_str().unwrap()), 1);
        });
    }

    /// A file past the cap is refused, whatever its size read as.
    #[test]
    fn refuses_a_file_past_the_cap() {
        let work = tempfile::tempdir().unwrap();
        let big = work.path().join("big.md");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(MAX_SCRUB_FILE_BYTES + 1).unwrap();
        let err = read_for_digest(&big).unwrap_err();
        assert!(err.contains("larger than"), "{err}");
        file.set_len(MAX_SCRUB_FILE_BYTES).unwrap();
        assert_eq!(
            read_for_digest(&big).unwrap().len() as u64,
            MAX_SCRUB_FILE_BYTES
        );
    }
}
