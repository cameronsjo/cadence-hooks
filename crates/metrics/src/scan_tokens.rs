//! Scan a Claude Code transcript JSONL and sum token usage over a range.
//!
//! Pure port of `scan-tokens.sh`. Given the transcript contents and an optional
//! `from` message id, sum the token usage of every assistant message *after*
//! that id (exclusive). Locally-synthesized `<synthetic>` records count as
//! scanned and can be the marker, but add no tokens and no model bucket.
//! Returns `None` when there is nothing to report — no
//! matching messages, the marker isn't found, or the range is empty — mirroring
//! the bash "emit nothing, skip the commit" behavior.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use serde::Deserialize;

/// The model string Claude Code writes for a locally-synthesized assistant
/// record. Such a record carries `usage` but is no model call: the scan adds
/// no tokens or model bucket for it, and the session grader does not count it
/// as a turn.
pub(crate) const SYNTHETIC_MODEL: &str = "<synthetic>";

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
    /// Assistant records in the range, `<synthetic>` ones included, so this
    /// counts records rather than model calls.
    pub messages_scanned: usize,
    /// The model of the last non-synthetic assistant message in the range
    /// (backward-compat), or `unknown` when the range holds only synthetic
    /// records.
    pub model: String,
    /// Per-model token buckets, sorted by model name (BTreeMap order).
    /// Single-model ranges produce a one-entry vec; a range of only
    /// `<synthetic>` records produces an empty one.
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
    ///
    /// Read leniently: an unexpected shape here degrades to `None` rather than
    /// failing the whole line. A strict field would be a silent data-loss path
    /// — `scan_tokens` skips an unparseable line entirely, so one unfamiliar
    /// `cache_creation` shape would drop that message's *scalar* token counts
    /// too, and dropping the marker message would skip the whole record.
    #[serde(default, deserialize_with = "lenient_cache_creation")]
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
#[derive(Deserialize)]
pub(crate) struct CacheCreation {
    #[serde(default)]
    pub(crate) ephemeral_1h_input_tokens: u64,
}

/// Deserialize `cache_creation` without letting its shape veto the whole line.
///
/// Never fails: an unexpected shape yields `None`, so the message's
/// authoritative `cache_creation_input_tokens` scalar still lands in the
/// ledger and only the 1-hour split is lost. The strict form would discard the
/// message's tokens outright — the failure this parser exists to avoid.
pub(crate) fn lenient_cache_creation<'de, D>(
    deserializer: D,
) -> Result<Option<CacheCreation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(raw.and_then(|v| serde_json::from_value(v).ok()))
}

/// Incremental, line-by-line token usage accumulator.
///
/// Powers both the in-memory [`scan_tokens`] helper and the streaming
/// [`scan_tokens_reader`] / [`scan_tokens_file`] paths, as well as the
/// single-pass scan+grade stream in [`crate::session_grade`].
pub struct TokenScanner<'a> {
    from: Option<&'a str>,
    marker: &'a str,
    started: bool,
    marker_seen: bool,
    tokens: Tokens,
    by_model: BTreeMap<String, Tokens>,
    messages_scanned: usize,
    last_id: Option<String>,
    last_model: Option<String>,
    last_message_offset: Option<u64>,
}

impl<'a> TokenScanner<'a> {
    /// Start scanning. `from == None` or `Some("")` sums from the first line;
    /// otherwise accumulation begins strictly after the assistant message with
    /// `id == from`.
    #[must_use]
    pub fn new(from: Option<&'a str>) -> Self {
        let marker = from.unwrap_or("");
        let started = marker.is_empty();
        Self {
            from,
            marker,
            started,
            marker_seen: started,
            tokens: Tokens::default(),
            by_model: BTreeMap::new(),
            messages_scanned: 0,
            last_id: None,
            last_model: None,
            last_message_offset: None,
        }
    }

    /// Feed one JSONL line (without trailing newline) at byte offset `0`.
    pub fn feed_line(&mut self, line: &str) {
        self.feed_line_at(line, 0);
    }

    /// Feed one JSONL line (without trailing newline) located at `line_offset`
    /// in the underlying transcript file.
    pub fn feed_line_at(&mut self, line: &str, line_offset: u64) {
        // Cheap byte-scan pre-filter (#96): before the marker, only pay for a
        // full JSON parse on a line that could BE the marker. This bounds the
        // O(transcript) parse to the tail past the marker — the hot-path cost
        // on every commit. A candidate is still fully parsed and accepted only
        // when it is an assistant message with id == marker, so a content
        // substring match never false-starts accumulation.
        if !self.started && !line.contains(self.marker) {
            return;
        }
        let Ok(parsed) = serde_json::from_str::<Line>(line) else {
            return;
        };
        let Some(m) = parsed.message else {
            return;
        };
        if m.role.as_deref() != Some("assistant") {
            return;
        }
        let (Some(id), Some(u)) = (m.id, m.usage) else {
            return;
        };
        let create_1h = u
            .cache_creation
            .as_ref()
            .map_or(0, |c| c.ephemeral_1h_input_tokens);
        self.record_assistant_usage(
            id,
            m.model,
            u.input_tokens,
            u.cache_creation_input_tokens,
            create_1h,
            u.cache_read_input_tokens,
            u.output_tokens,
            line_offset,
        );
    }

    /// Feed an already-parsed assistant message with usage. Used by the
    /// single-pass streaming scan+grade path so each line is deserialized once.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_assistant_usage(
        &mut self,
        id: String,
        model: Option<String>,
        input_tokens: u64,
        cache_creation_input_tokens: u64,
        create_1h: u64,
        cache_read_input_tokens: u64,
        output_tokens: u64,
        line_offset: u64,
    ) {
        if !self.started {
            if Some(id.as_str()) == self.from {
                self.started = true;
                self.marker_seen = true;
            }
            // The marker message itself is excluded from the sum.
            return;
        }

        // A locally-synthesized record (Code Mode writes many) is no model
        // call: it bills nothing and has no price, so a bucket for it would
        // add `<synthetic>` to `byModel` and a false gap to `unpricedModels`.
        // It still counts as scanned and still moves the marker: a second
        // commit in the same Code Mode turn has only synthetic records after
        // the first commit's marker, and `log-commit` writes no row for an
        // empty range.
        if model.as_deref() == Some(SYNTHETIC_MODEL) {
            self.messages_scanned += 1;
            self.last_id = Some(id);
            self.last_message_offset = Some(line_offset);
            return;
        }

        // The scalar is the API's authoritative total; the sub-bucket is read
        // alongside it, never instead of it. Summing the named sub-buckets
        // would silently drop any future TTL the struct does not name out of
        // the ledger and out of the cost.
        self.tokens.input += input_tokens;
        self.tokens.cache_create += cache_creation_input_tokens;
        self.tokens.cache_create_1h += create_1h;
        self.tokens.cache_read += cache_read_input_tokens;
        self.tokens.output += output_tokens;

        let model_key = model.unwrap_or_else(|| "unknown".to_string());
        let bucket = self.by_model.entry(model_key.clone()).or_default();
        bucket.input += input_tokens;
        bucket.cache_create += cache_creation_input_tokens;
        bucket.cache_create_1h += create_1h;
        bucket.cache_read += cache_read_input_tokens;
        bucket.output += output_tokens;

        self.messages_scanned += 1;
        self.last_id = Some(id);
        self.last_model = Some(model_key);
        self.last_message_offset = Some(line_offset);
    }

    /// Finish scanning and return the aggregated [`ScanResult`], or `None` if
    /// the marker was not found or no assistant messages followed it.
    #[must_use]
    pub fn finish(self) -> Option<ScanResult> {
        self.finish_with_offset().map(|(result, _)| result)
    }

    /// Finish scanning and return both the [`ScanResult`] and the byte offset
    /// of the line containing `last_message_id`.
    #[must_use]
    pub fn finish_with_offset(self) -> Option<(ScanResult, u64)> {
        if !self.marker_seen || self.messages_scanned == 0 {
            // Marker predated this transcript, or nothing new since it — skip
            // rather than overcount (mirrors the bash "emit nothing" behavior).
            return None;
        }
        let result = ScanResult {
            tokens: self.tokens,
            last_message_id: self.last_id?,
            messages_scanned: self.messages_scanned,
            model: self.last_model.unwrap_or_else(|| "unknown".to_string()),
            by_model: self.by_model.into_iter().collect(),
        };
        Some((result, self.last_message_offset.unwrap_or(0)))
    }
}

/// True when `line` is an assistant message with `usage` and `id == expected_id`.
fn line_matches_marker(line: &str, expected_id: &str) -> bool {
    if !line.contains(expected_id) {
        return false;
    }
    let Ok(parsed) = serde_json::from_str::<Line>(line) else {
        return false;
    };
    let Some(m) = parsed.message else {
        return false;
    };
    m.usage.is_some()
        && m.role.as_deref() == Some("assistant")
        && m.id.as_deref() == Some(expected_id)
}

/// Sum token usage for assistant messages after `from` (exclusive).
///
/// - `from` is `None` or empty: scan from the start.
/// - `from` not found among scanned messages: returns `None` (the marker
///   predates this transcript — skip rather than overcount).
/// - No assistant messages in range: returns `None`. A range holding only
///   `<synthetic>` records is not empty: it returns zero tokens, so a commit
///   made later in the same Code Mode turn still gets its row.
pub fn scan_tokens(transcript: &str, from: Option<&str>) -> Option<ScanResult> {
    let mut scanner = TokenScanner::new(from);
    for line in transcript.lines() {
        scanner.feed_line(line);
    }
    scanner.finish()
}

/// Stream token usage from a [`BufRead`] starting at `initial_offset`,
/// returning both the [`ScanResult`] and the byte offset of the last scanned
/// assistant message's line.
pub fn scan_tokens_reader<R: BufRead>(
    mut reader: R,
    from: Option<&str>,
    initial_offset: u64,
) -> std::io::Result<Option<(ScanResult, u64)>> {
    let mut scanner = TokenScanner::new(from);
    let mut buf = String::new();
    let mut pos = initial_offset;
    loop {
        buf.clear();
        let line_offset = pos;
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        pos += n as u64;
        let line = buf.trim_end_matches(['\r', '\n']);
        scanner.feed_line_at(line, line_offset);
    }
    Ok(scanner.finish_with_offset())
}

/// Stream token usage from a transcript file, seeking directly to `hint_offset`
/// when both `from` and `hint_offset` are provided and the line at
/// `hint_offset` is confirmed to be the `from` assistant message.
///
/// If the file was truncated, rewritten, or `hint_offset` does not point at
/// the expected `from` message line, rewinds to byte 0 and performs a full
/// streaming scan.
pub fn scan_tokens_file(
    path: &Path,
    from: Option<&str>,
    hint_offset: Option<u64>,
) -> std::io::Result<Option<(ScanResult, u64)>> {
    let mut file = std::fs::File::open(path)?;
    if let (Some(marker), Some(offset)) = (from.filter(|m| !m.is_empty()), hint_offset) {
        let file_len = file.metadata()?.len();
        if offset < file_len {
            file.seek(SeekFrom::Start(offset))?;
            let mut reader = BufReader::new(&mut file);
            let mut marker_line = String::new();
            let n = reader.read_line(&mut marker_line)?;
            let trimmed = marker_line.trim_end_matches(['\r', '\n']);
            if n > 0 && line_matches_marker(trimmed, marker) {
                // Verified the marker line at `offset`; stream only the tail.
                return scan_tokens_reader(reader, None, offset + n as u64);
            }
            // Hint was stale (file truncated/rewritten): rewind and scan from 0.
            drop(reader);
            file.seek(SeekFrom::Start(0))?;
        }
    }
    scan_tokens_reader(BufReader::new(file), from, 0)
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

    #[test]
    fn synthetic_records_add_no_tokens_or_bucket() {
        // Non-zero usage on purpose: the filter keys on the model string, not
        // on the record happening to carry zeros.
        let t = [
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":3}}}"#,
            r#"{"message":{"id":"s1","role":"assistant","model":"<synthetic>","usage":{"input_tokens":500,"cache_read_input_tokens":7,"output_tokens":9}}}"#,
        ]
        .join("\n");
        let r = scan_tokens(&t, None).expect("the range is scanned");
        assert_eq!(r.by_model.len(), 1, "{:?}", r.by_model);
        assert_eq!(r.by_model[0].0, "claude-opus-4-7");
        assert_eq!(r.tokens.input, 10);
        assert_eq!(r.tokens.cache_read, 0);
        assert_eq!(r.tokens.output, 3);
        assert_eq!(r.model, "claude-opus-4-7");
        assert_eq!(r.messages_scanned, 2);
        assert_eq!(
            r.last_message_id, "s1",
            "a synthetic record still moves the marker"
        );
    }

    #[test]
    fn a_marker_on_a_synthetic_id_resolves() {
        let t = [
            r#"{"message":{"id":"s1","role":"assistant","model":"<synthetic>","usage":{"input_tokens":0}}}"#,
            r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":4}}}"#,
        ]
        .join("\n");
        let r = scan_tokens(&t, Some("s1")).expect("marker found");
        assert_eq!(r.tokens.input, 4);
        assert_eq!(r.last_message_id, "m2");
    }

    /// Two commits in one Code Mode turn: after the first commit's marker the
    /// range holds only synthetic records, and it must still scan (zero
    /// tokens, no bucket) so `log-commit` writes the second row.
    #[test]
    fn a_range_of_only_synthetic_records_scans_as_zero() {
        let t = [
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":4}}}"#,
            r#"{"message":{"id":"s1","role":"assistant","model":"<synthetic>","usage":{"input_tokens":1}}}"#,
            r#"{"message":{"id":"s2","role":"assistant","model":"<synthetic>","usage":{"input_tokens":1}}}"#,
        ]
        .join("\n");
        let r = scan_tokens(&t, Some("s1")).expect("a synthetic-only range is not empty");
        assert_eq!(r.tokens, Tokens::default());
        assert!(r.by_model.is_empty(), "{:?}", r.by_model);
        assert_eq!(r.model, "unknown");
        assert_eq!(r.last_message_id, "s2");
    }

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
    fn unexpected_cache_creation_shape_keeps_the_message_counted() {
        // A strict field would fail the whole line here, dropping the
        // authoritative scalar along with the 1h split — silent data loss in a
        // cost ledger. Only the split may be lost.
        for shape in [
            r#""not-an-object""#,
            "42",
            "[1,2,3]",
            r#"{"ephemeral_1h_input_tokens":"seventeen"}"#,
            r#"{"ephemeral_1h_input_tokens":-5}"#,
            r#"{"ephemeral_1h_input_tokens":1.5}"#,
            "null",
        ] {
            let transcript = format!(
                r#"{{"message":{{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{{"input_tokens":9,"cache_creation_input_tokens":1000,"cache_creation":{shape},"output_tokens":2}}}}}}"#
            );
            let r = scan_tokens(&transcript, None)
                .unwrap_or_else(|| panic!("message must survive cache_creation={shape}"));
            assert_eq!(r.tokens.input, 9, "input survives {shape}");
            assert_eq!(r.tokens.cache_create, 1000, "scalar survives {shape}");
            assert_eq!(r.tokens.cache_create_1h, 0, "split degrades on {shape}");
        }
    }

    #[test]
    fn an_unparseable_marker_message_would_skip_the_whole_record() {
        // The control proving the test above measures something: scan_tokens
        // drops a line it cannot parse, and dropping the marker returns None —
        // which is why cache_creation must never be able to fail a line.
        let transcript = [
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-5","usage":{"input_tokens":1,"output_tokens":1}}}"#,
            "{ not json at all",
        ]
        .join("\n");
        assert!(
            scan_tokens(&transcript, Some("nonexistent-marker")).is_none(),
            "a dropped line takes its message out of the scan entirely"
        );
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

    #[test]
    fn scan_tokens_file_resumes_from_verified_byte_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let line1 = r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":1}}}"#;
        let line2 = r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":20,"output_tokens":2}}}"#;
        let line3 = r#"{"message":{"id":"m3","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":30,"output_tokens":3}}}"#;
        std::fs::write(&path, format!("{line1}\n{line2}\n")).unwrap();

        let (first, offset) = scan_tokens_file(&path, None, None).unwrap().unwrap();
        assert_eq!(first.last_message_id, "m2");
        assert_eq!(offset, (line1.len() + 1) as u64);

        // Append m3 and resume directly from m2's byte offset.
        std::fs::write(&path, format!("{line1}\n{line2}\n{line3}\n")).unwrap();
        let (second, offset2) = scan_tokens_file(&path, Some("m2"), Some(offset))
            .unwrap()
            .unwrap();
        assert_eq!(second.tokens.input, 30);
        assert_eq!(second.messages_scanned, 1);
        assert_eq!(second.last_message_id, "m3");
        assert_eq!(offset2, (line1.len() + 1 + line2.len() + 1) as u64);

        // No new lines after m3 -> None even with a valid offset hint.
        assert!(
            scan_tokens_file(&path, Some("m3"), Some(offset2))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn scan_tokens_file_falls_back_when_offset_is_stale_or_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let line1 = r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":10,"output_tokens":1}}}"#;
        let line2 = r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":25,"output_tokens":4}}}"#;
        std::fs::write(&path, format!("{line1}\n{line2}\n")).unwrap();

        // Stale offset pointing into the middle of line1 must rewind and still find m1 -> m2.
        let (res, _) = scan_tokens_file(&path, Some("m1"), Some(5))
            .unwrap()
            .unwrap();
        assert_eq!(res.tokens.input, 25);
        assert_eq!(res.last_message_id, "m2");

        // Offset past EOF (truncated file) must rewind and still find m1 -> m2.
        let (res_eof, _) = scan_tokens_file(&path, Some("m1"), Some(999_999))
            .unwrap()
            .unwrap();
        assert_eq!(res_eof.tokens.input, 25);
        assert_eq!(res_eof.last_message_id, "m2");
    }
}
