//! `cadence-hooks metrics price` — price one finished transcript.
//!
//! A CLI action, not a hook. It reuses the pieces `log_session` writes
//! `sessions.jsonl` with — [`scan_transcript`], [`compute_cost_by_model`] and
//! [`UsageScan::priced_breakdown`] — so the printed `costUsd` and `byModel`
//! are the figures a `sessions.jsonl` row for the same transcript carries.
//! There is no pricing logic here.
//!
//! It fails closed: an unreadable transcript, one that is not a regular file
//! or is over [`MAX_TRANSCRIPT_BYTES`], or a named price table that cannot be
//! read or parsed, exits 1 with the reason on stderr rather than printing a
//! cost. A drain worker can influence the transcript path forgectl passes, so
//! a FIFO or `/dev/zero` must not hang or exhaust the caller.

use crate::compute_cost::compute_cost_by_model;
use crate::prices::Prices;
use crate::transcript::{TranscriptScan, scan_transcript};
use serde_json::{Value, json};
use std::io::Read;

/// The largest transcript `metrics price` reads.
pub const MAX_TRANSCRIPT_BYTES: u64 = 512 * 1024 * 1024;

/// Reads `path` as UTF-8, refusing anything that is not a regular file once
/// symlinks are followed, and anything over `cap` bytes. The file is opened
/// first (non-blocking on Unix, so a FIFO cannot block the open) and the type
/// is checked on the open handle, so the check and the read see one file.
pub(crate) fn read_transcript(path: &str, cap: u64) -> Result<String, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let file = opts
        .open(path)
        .map_err(|e| format!("cannot read {path:?}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read {path:?}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path:?} is not a regular file"));
    }
    let mut contents = String::new();
    file.take(cap + 1)
        .read_to_string(&mut contents)
        .map_err(|e| format!("cannot read {path:?}: {e}"))?;
    if contents.len() as u64 > cap {
        return Err(format!("{path:?} is over the {cap}-byte limit"));
    }
    Ok(contents)
}

/// The `{costUsd, byModel, unpricedModels}` object for one transcript string.
///
/// `Err` carries a reason when the transcript has a usage schema that cannot
/// be priced. A transcript with no usage records prices to `$0` with empty
/// lists: readable, just empty.
pub fn price_json(transcript: &str, prices: &Prices) -> Result<Value, String> {
    match scan_transcript(transcript, None) {
        TranscriptScan::Usage(usage) => {
            let (by_model, unpriced) = usage.priced_breakdown(prices);
            Ok(json!({
                "costUsd": compute_cost_by_model(&usage.scan.by_model, prices),
                "byModel": by_model,
                "unpricedModels": unpriced,
            }))
        }
        TranscriptScan::Diagnostic(d) => Err(format!(
            "transcript usage cannot be priced ({} {}: {})",
            d.harness, d.source_format, d.code
        )),
        TranscriptScan::Empty => Ok(json!({
            "costUsd": 0.0,
            "byModel": [],
            "unpricedModels": [],
        })),
    }
}

/// Entry point for `metrics price`. Returns the process exit code: 0 on a
/// readable transcript (unpriced models included), 1 on one it cannot read or
/// price. Usage errors (exit 2) are clap's.
pub fn run_price(transcript: &str, prices_path: Option<&str>) -> u8 {
    let contents = match read_transcript(transcript, MAX_TRANSCRIPT_BYTES) {
        Ok(c) => c,
        Err(reason) => {
            eprintln!("metrics price: {reason}");
            return 1;
        }
    };
    let prices = match Prices::load_strict(prices_path) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("metrics price: {reason}");
            return 1;
        }
    };
    match price_json(&contents, &prices) {
        Ok(v) => {
            cadence_hooks_core::outln!("{v}");
            0
        }
        Err(reason) => {
            eprintln!("metrics price: {reason}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two models, a 1h cache write on the first, and one model the table
    /// does not know. Message ids differ so the scan counts each.
    const TRANSCRIPT: &str = concat!(
        r#"{"type":"assistant","message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":1000000,"cache_creation_input_tokens":1000000,"cache_creation":{"ephemeral_1h_input_tokens":400000},"cache_read_input_tokens":2000000,"output_tokens":100000}}}"#,
        "\n",
        r#"{"type":"assistant","message":{"id":"m2","role":"assistant","model":"claude-sonnet-5","usage":{"input_tokens":500000,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":50000}}}"#,
        "\n",
        r#"{"type":"assistant","message":{"id":"m3","role":"assistant","model":"no-such-model-9","usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":10}}}"#,
    );

    /// Hand-computed from `prices.json`:
    /// opus-5: 1M x 5.00 + 600k x 6.25 + 400k x 10.00 + 2M x 0.50 + 100k x 25.00
    ///       = 5 + 3.75 + 4 + 1 + 2.5 = 16.25
    /// sonnet-5: 500k x 2.00 + 50k x 10.00 = 1 + 0.5 = 1.5
    const EXPECTED_USD: f64 = 17.75;

    #[test]
    fn matches_the_table_by_hand() {
        let v = price_json(TRANSCRIPT, &Prices::embedded()).unwrap();
        let cost = v["costUsd"].as_f64().unwrap();
        assert!((cost - EXPECTED_USD).abs() < 0.01, "got {cost}");
        assert_eq!(v["unpricedModels"], json!(["no-such-model-9"]));
        assert_eq!(v["byModel"].as_array().unwrap().len(), 3);
        assert_eq!(v["byModel"][0]["tokens"]["cacheCreate1h"], 400_000);
    }

    #[test]
    fn a_capped_read_refuses_an_oversized_or_non_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        std::fs::write(&path, "0123456789").unwrap();
        let p = path.to_str().unwrap();
        assert_eq!(read_transcript(p, 10).unwrap(), "0123456789");
        assert!(read_transcript(p, 9).unwrap_err().contains("limit"));
        let d = dir.path().to_str().unwrap();
        assert!(read_transcript(d, 10).is_err());
    }

    /// Exactly `cap` bytes is accepted, `cap + 1` refused. Removing
    /// `take(cap + 1)` leaves this green: the later length check still
    /// refuses `cap + 1`, so `take` only bounds memory, which a small file
    /// cannot observe.
    #[test]
    fn the_cap_boundary_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let p = path.to_str().unwrap();
        std::fs::write(&path, "a".repeat(64)).unwrap();
        assert_eq!(read_transcript(p, 64).unwrap().len(), 64);
        std::fs::write(&path, "a".repeat(65)).unwrap();
        assert!(read_transcript(p, 64).unwrap_err().contains("limit"));
    }

    /// A FIFO with no writer is refused at once rather than blocking.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = read_transcript(path.to_str().unwrap(), 10).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn an_empty_transcript_prices_to_zero() {
        let v = price_json("", &Prices::embedded()).unwrap();
        assert_eq!(v["costUsd"], 0.0);
        assert_eq!(v["byModel"], json!([]));
        assert_eq!(v["unpricedModels"], json!([]));
    }
}
