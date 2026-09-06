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
    /// Grand total of cache-creation tokens, from the API's authoritative
    /// scalar. Always the sum of every TTL bucket, named or not.
    pub cache_create: u64,
    /// The 1-hour-TTL slice of `cache_create`, which bills at 2x input rather
    /// than the 5-minute 1.25x. Zero on transcripts predating the sub-bucket.
    pub cache_create_1h: u64,
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
    /// Per-TTL breakdown of the scalar above. Absent on older transcripts.
    #[serde(default)]
    cache_creation: Option<CacheCreation>,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

/// The `usage.cache_creation` object's TTL sub-buckets.
///
/// Only the 1-hour bucket is read: it is the one that bills at a different
/// rate. The 5-minute slice is derived as `cache_create - cache_create_1h`, so
/// a TTL bucket this struct does not name still lands in the total and simply
/// bills at the 5-minute rate rather than vanishing.
#[derive(Deserialize, Default)]
struct CacheCreation {
    #[serde(default)]
    ephemeral_1h_input_tokens: u64,
}

/// Sum token usage for assistant messages after `from` (exclusive).
///
/// - `from` is `None` or empty: scan from the start.
/// - `from` not found among scanned messages: returns `None` (the marker
///   predates this transcript — skip rather than overcount).
/// - No assistant messages in range: returns `None`.
pub fn scan_tokens(transcript: &str, from: Option<&str>) -> Option<ScanResult> {
    let marker = from.unwrap_or("");
    // None/"" → sum from the start; otherwise accumulate only after the marker
    // message. `started` gates accumulation; `marker_seen` distinguishes
    // "marker found, nothing after" (→ None) from "marker never found" (→ None).
    let mut started = marker.is_empty();
    let mut marker_seen = started;

    let mut tokens = Tokens::default();
    let mut by_model: BTreeMap<String, Tokens> = BTreeMap::new();
    let mut messages_scanned = 0usize;
    let mut last_id: Option<String> = None;
    let mut last_model: Option<String> = None;

    for line in transcript.lines() {
        // Cheap byte-scan pre-filter (#96): before the marker, only pay for a
        // full JSON parse on a line that could BE the marker. This bounds the
        // O(transcript) parse to the tail past the marker — the hot-path cost
        // on every commit. A candidate is still fully parsed and accepted only
        // when it is an assistant message with id == marker, so a content
        // substring match never false-starts accumulation.
        if !started && !line.contains(marker) {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Line>(line) else {
            continue;
        };
        let Some(m) = parsed.message else {
            continue;
        };
        if m.usage.is_none() || m.id.is_none() || m.role.as_deref() != Some("assistant") {
            continue;
        }
        if !started {
            if m.id.as_deref() == from {
                started = true;
                marker_seen = true;
            }
            // The marker message itself is excluded from the sum.
            continue;
        }

        let u = m.usage.as_ref().unwrap();
        // The scalar is the API's authoritative total; the sub-bucket is read
        // alongside it, never instead of it. Summing the named sub-buckets
        // would silently drop any future TTL the struct does not name out of
        // the ledger and out of the cost.
        let create_1h = u
            .cache_creation
            .as_ref()
            .map_or(0, |c| c.ephemeral_1h_input_tokens);
        tokens.input += u.input_tokens;
        tokens.cache_create += u.cache_creation_input_tokens;
        tokens.cache_create_1h += create_1h;
        tokens.cache_read += u.cache_read_input_tokens;
        tokens.output += u.output_tokens;

        let model_key = m.model.clone().unwrap_or_else(|| "unknown".to_string());
        let bucket = by_model.entry(model_key.clone()).or_default();
        bucket.input += u.input_tokens;
        bucket.cache_create += u.cache_creation_input_tokens;
        bucket.cache_create_1h += create_1h;
        bucket.cache_read += u.cache_read_input_tokens;
        bucket.output += u.output_tokens;

        messages_scanned += 1;
        last_id = m.id.clone();
        last_model = Some(model_key);
    }

    if !marker_seen || messages_scanned == 0 {
        // Marker predated this transcript, or nothing new since it — skip
        // rather than overcount (mirrors the bash "emit nothing" behavior).
        return None;
    }
    Some(ScanResult {
        tokens,
        last_message_id: last_id?,
        messages_scanned,
        model: last_model.unwrap_or_else(|| "unknown".to_string()),
        by_model: by_model.into_iter().collect(),
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

    // --- 1-hour cache-creation sub-bucket (cadence-ecosystem#522) ---

    #[test]
    fn one_hour_sub_bucket_is_captured_without_disturbing_the_scalar() {
        // Every cache write in the sampled corpus lands in the 1h bucket, and
        // the scalar equals 5m + 1h.
        let transcript = r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":4,"cache_creation_input_tokens":1000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":1000},"cache_read_input_tokens":7,"output_tokens":2}}}"#;
        let r = scan_tokens(transcript, None).unwrap();
        assert_eq!(r.tokens.cache_create, 1000, "scalar is the grand total");
        assert_eq!(r.tokens.cache_create_1h, 1000);
        let (_, bucket) = &r.by_model[0];
        assert_eq!(bucket.cache_create, 1000, "per-model bucket tracks too");
        assert_eq!(bucket.cache_create_1h, 1000);
    }

    #[test]
    fn legacy_scalar_only_leaves_the_one_hour_bucket_at_zero() {
        // Transcripts predating `cache_creation` must price entirely at the
        // 5-minute rate, exactly as they do today.
        let r = scan_tokens(&fixture(), None).unwrap();
        assert_eq!(r.tokens.cache_create, 5);
        assert_eq!(r.tokens.cache_create_1h, 0);
    }

    #[test]
    fn scalar_exceeding_the_named_sub_buckets_is_still_counted_in_full() {
        // The guard for reading the scalar rather than summing sub-buckets: an
        // unnamed TTL (here, a hypothetical 1-day bucket) must not vanish from
        // the total. 900 = 1000 scalar - 100 named 1h.
        let transcript = r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"cache_creation_input_tokens":1000,"cache_creation":{"ephemeral_5m_input_tokens":400,"ephemeral_1d_input_tokens":500,"ephemeral_1h_input_tokens":100},"output_tokens":1}}}"#;
        let r = scan_tokens(transcript, None).unwrap();
        assert_eq!(
            r.tokens.cache_create, 1000,
            "the unnamed 1d bucket must stay in the total"
        );
        assert_eq!(r.tokens.cache_create_1h, 100);
    }

    #[test]
    fn marker_substring_in_earlier_content_does_not_false_start() {
        // #96: a user line mentions "m1" before the real m1 assistant message.
        // The contains() pre-filter parses it but must reject it (not an
        // assistant message with id==m1), so only m2 is summed — not m1+m2.
        let transcript = [
            r#"{"type":"user","message":{"role":"user","content":"continue from m1"}}"#,
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":1}}}"#,
            r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-8","usage":{"input_tokens":20,"output_tokens":2}}}"#,
        ]
        .join("\n");
        let r = scan_tokens(&transcript, Some("m1")).unwrap();
        assert_eq!(
            r.tokens.input, 20,
            "m2 only; 30 would mean a false start on m1"
        );
        assert_eq!(r.messages_scanned, 1);
        assert_eq!(r.last_message_id, "m2");
    }
}
