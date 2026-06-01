//! Scan a Claude Code transcript JSONL and sum token usage over a range.
//!
//! Pure port of `scan-tokens.sh`. Given the transcript contents and an optional
//! `from` message id, sum the token usage of every assistant message *after*
//! that id (exclusive). Returns `None` when there is nothing to report — no
//! matching messages, the marker isn't found, or the range is empty — mirroring
//! the bash "emit nothing, skip the commit" behavior.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Token totals for a scanned range.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub input: u64,
    pub cache_create: u64,
    pub cache_read: u64,
    pub output: u64,
}

/// Result of scanning a transcript range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Grand total of all tokens in the range (all models combined).
    pub tokens: Tokens,
    pub last_message_id: String,
    pub messages_scanned: usize,
    /// The model of the last assistant message in the range (backward-compat).
    pub model: String,
    /// Per-model token buckets, sorted by model name (BTreeMap order).
    /// Always populated; single-model ranges produce a one-entry vec.
    pub by_model: Vec<(String, Tokens)>,
}

#[derive(Deserialize)]
struct Line {
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    id: Option<String>,
    role: Option<String>,
    model: Option<String>,
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

/// Sum token usage for assistant messages after `from` (exclusive).
///
/// - `from` is `None` or empty: scan from the start.
/// - `from` not found among scanned messages: returns `None` (the marker
///   predates this transcript — skip rather than overcount).
/// - No assistant messages in range: returns `None`.
pub fn scan_tokens(transcript: &str, from: Option<&str>) -> Option<ScanResult> {
    let msgs: Vec<Message> = transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Line>(line).ok())
        .filter_map(|line| line.message)
        .filter(|m| m.usage.is_some() && m.id.is_some() && m.role.as_deref() == Some("assistant"))
        .collect();

    let start = match from {
        None | Some("") => 0,
        Some(marker) => {
            let idx = msgs.iter().position(|m| m.id.as_deref() == Some(marker))?;
            idx + 1
        }
    };

    if msgs.len() <= start {
        return None;
    }

    let range = &msgs[start..];
    let mut tokens = Tokens::default();
    let mut by_model: BTreeMap<String, Tokens> = BTreeMap::new();
    for m in range {
        if let Some(u) = &m.usage {
            let delta_input = u.input_tokens;
            let delta_cache_create = u.cache_creation_input_tokens;
            let delta_cache_read = u.cache_read_input_tokens;
            let delta_output = u.output_tokens;

            tokens.input += delta_input;
            tokens.cache_create += delta_cache_create;
            tokens.cache_read += delta_cache_read;
            tokens.output += delta_output;

            let model_key = m.model.clone().unwrap_or_else(|| "unknown".to_string());
            let bucket = by_model.entry(model_key).or_default();
            bucket.input += delta_input;
            bucket.cache_create += delta_cache_create;
            bucket.cache_read += delta_cache_read;
            bucket.output += delta_output;
        }
    }

    let last = range.last()?;
    let by_model_vec: Vec<(String, Tokens)> = by_model.into_iter().collect();
    Some(ScanResult {
        tokens,
        last_message_id: last.id.clone()?,
        messages_scanned: range.len(),
        model: last.model.clone().unwrap_or_else(|| "unknown".to_string()),
        by_model: by_model_vec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two assistant messages with usage, plus a user line that must be ignored.
    fn fixture() -> String {
        [
            r#"{"type":"user","message":{"role":"user","content":"hi"}}"#,
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":2,"output_tokens":3}}}"#,
            r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":20,"cache_creation_input_tokens":0,"cache_read_input_tokens":8,"output_tokens":4}}}"#,
        ]
        .join("\n")
    }

    #[test]
    fn cold_start_sums_all() {
        let result = scan_tokens(&fixture(), None).unwrap();
        assert_eq!(result.tokens.input, 30);
        assert_eq!(result.tokens.cache_create, 5);
        assert_eq!(result.tokens.cache_read, 10);
        assert_eq!(result.tokens.output, 7);
        assert_eq!(result.messages_scanned, 2);
        assert_eq!(result.last_message_id, "m2");
        assert_eq!(result.model, "claude-opus-4-7");
    }

    #[test]
    fn from_marker_sums_remainder() {
        let result = scan_tokens(&fixture(), Some("m1")).unwrap();
        assert_eq!(result.tokens.input, 20);
        assert_eq!(result.messages_scanned, 1);
        assert_eq!(result.last_message_id, "m2");
    }

    #[test]
    fn marker_at_end_yields_none() {
        assert!(scan_tokens(&fixture(), Some("m2")).is_none());
    }

    #[test]
    fn marker_absent_yields_none() {
        // Marker not in transcript — skip rather than overcount from the start.
        assert!(scan_tokens(&fixture(), Some("nonexistent")).is_none());
    }

    #[test]
    fn empty_transcript_yields_none() {
        assert!(scan_tokens("", None).is_none());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let transcript = [
            "garbage not json",
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-haiku-4-5","usage":{"input_tokens":1,"output_tokens":1}}}"#,
        ]
        .join("\n");
        let result = scan_tokens(&transcript, None).unwrap();
        assert_eq!(result.messages_scanned, 1);
        assert_eq!(result.tokens.input, 1);
        // Absent cache fields default to zero.
        assert_eq!(result.tokens.cache_read, 0);
    }

    #[test]
    fn model_falls_back_to_unknown() {
        let transcript =
            r#"{"message":{"id":"m1","role":"assistant","usage":{"output_tokens":1}}}"#;
        let result = scan_tokens(transcript, None).unwrap();
        assert_eq!(result.model, "unknown");
    }

    // --- by_model bucket tests ---

    /// Single-model range: by_model has exactly one entry matching the totals.
    #[test]
    fn single_model_by_model_has_one_bucket() {
        let result = scan_tokens(&fixture(), None).unwrap();
        assert_eq!(result.by_model.len(), 1);
        let (model, tokens) = &result.by_model[0];
        assert_eq!(model, "claude-opus-4-7");
        assert_eq!(tokens.input, 30);
        assert_eq!(tokens.cache_create, 5);
        assert_eq!(tokens.cache_read, 10);
        assert_eq!(tokens.output, 7);
    }

    /// Model-transition range: two buckets in deterministic (sorted) order.
    #[test]
    fn two_model_transition_by_model_has_two_buckets() {
        let transcript = [
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-sonnet-4-5","usage":{"input_tokens":100,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":10}}}"#,
            r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":200,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":20}}}"#,
        ]
        .join("\n");
        let result = scan_tokens(&transcript, None).unwrap();
        assert_eq!(result.by_model.len(), 2);
        // BTreeMap order: claude-opus-4-7 < claude-sonnet-4-5 lexicographically
        let (model0, tok0) = &result.by_model[0];
        let (model1, tok1) = &result.by_model[1];
        assert_eq!(model0, "claude-opus-4-7");
        assert_eq!(tok0.input, 200);
        assert_eq!(tok0.output, 20);
        assert_eq!(model1, "claude-sonnet-4-5");
        assert_eq!(tok1.input, 100);
        assert_eq!(tok1.output, 10);
        // Grand total still correct
        assert_eq!(result.tokens.input, 300);
        assert_eq!(result.tokens.output, 30);
    }

    /// Unknown-model messages produce an "unknown" bucket (but contribute $0 to cost).
    #[test]
    fn unknown_model_gets_own_bucket() {
        let transcript =
            r#"{"message":{"id":"m1","role":"assistant","usage":{"output_tokens":5}}}"#;
        let result = scan_tokens(transcript, None).unwrap();
        assert_eq!(result.by_model.len(), 1);
        let (model, tokens) = &result.by_model[0];
        assert_eq!(model, "unknown");
        assert_eq!(tokens.output, 5);
    }
}
