//! `cadence-hooks metrics price` — price one finished transcript.
//!
//! A CLI action, not a hook. It reuses the pieces `log_session` writes
//! `sessions.jsonl` with — [`scan_transcript`], [`compute_cost_by_model`] and
//! [`UsageScan::priced_breakdown`] — so the printed `costUsd` and `byModel`
//! are the figures a `sessions.jsonl` row for the same transcript carries.
//! There is no pricing logic here.
//!
//! Like `metrics grade` it fails closed: an unreadable transcript exits 1 with
//! the reason on stderr rather than printing a zero cost.

use crate::compute_cost::compute_cost_by_model;
use crate::prices::Prices;
use crate::transcript::{TranscriptScan, scan_transcript};
use serde_json::{Value, json};

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
    let contents = match std::fs::read_to_string(transcript) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("metrics price: cannot read {transcript}: {e}");
            return 1;
        }
    };
    let prices = Prices::load(prices_path);
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

    /// The same functions `log_session` uses, called directly, give the same
    /// figures: the CLI cannot drift from the `sessions.jsonl` writer.
    #[test]
    fn agrees_with_the_sessions_writer_path() {
        let prices = Prices::embedded();
        let v = price_json(TRANSCRIPT, &prices).unwrap();
        let TranscriptScan::Usage(usage) = scan_transcript(TRANSCRIPT, None) else {
            panic!("fixture must scan as usage");
        };
        let writer_cost = compute_cost_by_model(&usage.scan.by_model, &prices);
        let (writer_by_model, _) = usage.priced_breakdown(&prices);
        assert!((v["costUsd"].as_f64().unwrap() - writer_cost).abs() < 0.01);
        assert_eq!(v["byModel"], Value::Array(writer_by_model));
    }

    #[test]
    fn an_empty_transcript_prices_to_zero() {
        let v = price_json("", &Prices::embedded()).unwrap();
        assert_eq!(v["costUsd"], 0.0);
        assert_eq!(v["byModel"], json!([]));
        assert_eq!(v["unpricedModels"], json!([]));
    }
}
