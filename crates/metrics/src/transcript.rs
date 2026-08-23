//! Versioned, metadata-only transcript scanner for Claude.
//!
//! The scanners deserialize usage metadata and identifiers only. Prompt,
//! response, tool-call, and patch content are never represented in these
//! types and therefore cannot be copied into metrics records.

use crate::model_breakdown::{by_model_json, unpriced_models};
use crate::prices::Prices;
use crate::scan_tokens::{ScanResult, scan_tokens};
use serde_json::Value;

/// A successful usage scan.
///
/// `harness` and `source_format` are retained after the Codex scanner's
/// retirement (#1040): they are stamped onto schema-v2 rows, and rows written
/// before 2026-08-23 carry the other harness's values, so a reader still needs
/// the fields to interpret the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageScan {
    pub scan: ScanResult,
    pub harness: &'static str,
    pub source_format: &'static str,
    pub reasoning_output: u64,
    pub total_tokens: u64,
}

impl UsageScan {
    /// The `(byModel, unpricedModels)` pair for a token record.
    ///
    /// Per-model costs, with only the models actually missing a price listed as
    /// unpriced.
    ///
    /// Lifted here from two verbatim copies in `log_commit::build_commit_record`
    /// and `log_session::build_session_record`. They were identical, so nothing
    /// was broken — but two independently-maintained copies of a pricing rule is
    /// how a record shape drifts, and the copy had already spread to the
    /// `claude_usage()` test helper in both modules.
    #[must_use]
    pub fn priced_breakdown(&self, prices: &Prices) -> (Vec<Value>, Vec<&str>) {
        (
            by_model_json(&self.scan.by_model, prices),
            unpriced_models(&self.scan.by_model, prices),
        )
    }

    /// A Claude-harness scan wrapping `scan`, with `total_tokens` summed.
    ///
    /// Test-only, and shared: `log_commit` and `log_session` each carried a
    /// byte-identical private copy, which is the same duplication that produced
    /// the pricing branch above.
    #[cfg(test)]
    pub(crate) fn claude(scan: ScanResult) -> Self {
        let total_tokens = scan.tokens.input
            + scan.tokens.cache_create
            + scan.tokens.cache_read
            + scan.tokens.output;
        Self {
            scan,
            harness: "claude",
            source_format: "claude-transcript-v1",
            reasoning_output: 0,
            total_tokens,
        }
    }
}

/// Privacy-safe diagnostic for a transcript schema that cannot be priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDiagnostic {
    pub harness: &'static str,
    pub source_format: &'static str,
    pub code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptScan {
    Usage(UsageScan),
    Diagnostic(ScanDiagnostic),
    Empty,
}

pub fn scan_transcript(transcript: &str, marker: Option<&str>) -> TranscriptScan {
    match scan_tokens(transcript, marker) {
        Some(scan) => {
            let total_tokens = scan.tokens.input
                + scan.tokens.cache_create
                + scan.tokens.cache_read
                + scan.tokens.output;
            TranscriptScan::Usage(UsageScan {
                scan,
                harness: "claude",
                source_format: "claude-transcript-v1",
                reasoning_output: 0,
                total_tokens,
            })
        }
        None => TranscriptScan::Empty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_tokens::Tokens;

    /// A Claude transcript with an unpriced model lists exactly that model.
    ///
    /// Inherited from `priced_breakdown_splits_on_the_harness`. The split it
    /// asserted is gone with the Codex scanner (#1040) — there is one harness
    /// now — but the surviving half is the rule `log_commit` and `log_session`
    /// both depend on, so it keeps a test.
    #[test]
    fn priced_breakdown_lists_only_models_missing_a_price() {
        let scan = ScanResult {
            tokens: Tokens::default(),
            last_message_id: String::new(),
            messages_scanned: 0,
            model: "no-such-model-4-9".to_string(),
            by_model: vec![("no-such-model-4-9".to_string(), Tokens::default())],
        };
        let usage = UsageScan::claude(scan);
        let (_, unpriced) = usage.priced_breakdown(&Prices::embedded());
        assert_eq!(
            unpriced,
            ["no-such-model-4-9"],
            "a model with no price entry must be reported unpriced"
        );
    }

    /// Prompt text must never reach a metrics record, whatever else the scan
    /// emits.
    ///
    /// Inherited from `prompt_content_is_not_deserialized_or_emitted`, which ran
    /// this invariant against a Codex rollout fixture. It was the *only* test of
    /// the property in this crate, so retiring the Codex scanner would have
    /// dropped the coverage entirely rather than narrowing it — re-pointed at a
    /// Claude transcript instead.
    #[test]
    fn prompt_content_is_not_deserialized_or_emitted() {
        let secret = "never-copy-this-prompt";
        let transcript = [
            format!(r#"{{"type":"user","message":{{"role":"user","content":"{secret}"}}}}"#),
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":2,"output_tokens":3}}}"#.to_string(),
        ]
        .join("\n");

        let scanned = scan_transcript(&transcript, None);
        // Control: the scan must have actually found usage, or the assertion
        // below would pass on an empty result that proves nothing.
        assert!(
            matches!(scanned, TranscriptScan::Usage(_)),
            "fixture must produce a usage scan: {scanned:?}"
        );
        assert!(!format!("{scanned:?}").contains(secret));
    }
}
