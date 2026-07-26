//! Versioned, metadata-only transcript scanners for Claude and Codex.
//!
//! The scanners deserialize usage metadata and identifiers only. Prompt,
//! response, tool-call, and patch content are never represented in these
//! types and therefore cannot be copied into metrics records.

use crate::scan_tokens::{ScanResult, Tokens, scan_tokens};
use serde::Deserialize;
use std::collections::BTreeMap;

/// A successful cross-harness usage scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageScan {
    pub scan: ScanResult,
    pub harness: &'static str,
    pub source_format: &'static str,
    pub reasoning_output: u64,
    pub total_tokens: u64,
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

pub fn scan_transcript(transcript: &str, marker: Option<&str>, harness: &str) -> TranscriptScan {
    if harness == "codex" {
        scan_codex_rollout_v1(transcript, marker)
    } else {
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
}

#[derive(Debug, Deserialize)]
struct RolloutLine {
    #[serde(rename = "type")]
    kind: String,
    payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CodexUsage {
    input: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
    reasoning: u64,
    total: u64,
}

impl CodexUsage {
    fn checked_sub(self, earlier: Self) -> Option<Self> {
        Some(Self {
            input: self.input.checked_sub(earlier.input)?,
            cached: self.cached.checked_sub(earlier.cached)?,
            cache_write: self.cache_write.checked_sub(earlier.cache_write)?,
            output: self.output.checked_sub(earlier.output)?,
            reasoning: self.reasoning.checked_sub(earlier.reasoning)?,
            total: self.total.checked_sub(earlier.total)?,
        })
    }

    fn marker(self, ordinal: usize) -> String {
        format!(
            "codex-v1:{ordinal}:{}:{}:{}:{}:{}:{}",
            self.input, self.cached, self.cache_write, self.output, self.reasoning, self.total
        )
    }
}

fn parse_marker(marker: Option<&str>) -> Option<(usize, CodexUsage)> {
    let marker = marker?;
    let mut parts = marker.split(':');
    if parts.next()? != "codex-v1" {
        return None;
    }
    Some((
        parts.next()?.parse().ok()?,
        CodexUsage {
            input: parts.next()?.parse().ok()?,
            cached: parts.next()?.parse().ok()?,
            cache_write: parts.next()?.parse().ok()?,
            output: parts.next()?.parse().ok()?,
            reasoning: parts.next()?.parse().ok()?,
            total: parts.next()?.parse().ok()?,
        },
    ))
}

fn usage_from_value(value: &serde_json::Value) -> Option<CodexUsage> {
    let get = |key| value.get(key).and_then(serde_json::Value::as_u64);
    Some(CodexUsage {
        input: get("input_tokens")?,
        cached: get("cached_input_tokens")?,
        cache_write: get("cache_write_input_tokens").unwrap_or(0),
        output: get("output_tokens")?,
        reasoning: get("reasoning_output_tokens").unwrap_or(0),
        total: get("total_tokens")?,
    })
}

fn scan_codex_rollout_v1(transcript: &str, marker: Option<&str>) -> TranscriptScan {
    let mut saw_session_meta = false;
    let mut saw_token_event = false;
    let mut schema_invalid = false;
    let mut latest = None;
    let mut ordinal = 0usize;
    let mut model = "unknown".to_string();

    for raw in transcript.lines() {
        let Ok(line) = serde_json::from_str::<RolloutLine>(raw) else {
            continue;
        };
        match line.kind.as_str() {
            "session_meta" => saw_session_meta = true,
            "turn_context" => {
                if let Some(value) = line.payload.get("model").and_then(|v| v.as_str()) {
                    model = value.to_string();
                }
            }
            "event_msg"
                if line.payload.get("type").and_then(|v| v.as_str()) == Some("token_count") =>
            {
                saw_token_event = true;
                let value = line
                    .payload
                    .get("info")
                    .and_then(|info| info.get("total_token_usage"));
                match value.and_then(usage_from_value) {
                    Some(usage) => {
                        ordinal += 1;
                        latest = Some(usage);
                    }
                    None => schema_invalid = true,
                }
            }
            _ => {}
        }
    }

    if !saw_session_meta || schema_invalid {
        return TranscriptScan::Diagnostic(ScanDiagnostic {
            harness: "codex",
            source_format: "codex-rollout-unknown",
            code: "unknown-codex-rollout-schema",
        });
    }
    let Some(latest) = latest else {
        return if saw_token_event {
            TranscriptScan::Diagnostic(ScanDiagnostic {
                harness: "codex",
                source_format: "codex-rollout-unknown",
                code: "unknown-codex-rollout-schema",
            })
        } else {
            TranscriptScan::Empty
        };
    };

    let (messages_scanned, usage) = match marker {
        None | Some("") => (ordinal, latest),
        Some(value) => {
            let Some((earlier_ordinal, earlier)) = parse_marker(Some(value)) else {
                return TranscriptScan::Diagnostic(ScanDiagnostic {
                    harness: "codex",
                    source_format: "codex-rollout-v1",
                    code: "unknown-codex-token-marker",
                });
            };
            let Some(delta) = latest.checked_sub(earlier) else {
                return TranscriptScan::Diagnostic(ScanDiagnostic {
                    harness: "codex",
                    source_format: "codex-rollout-v1",
                    code: "codex-token-counter-regressed",
                });
            };
            if ordinal <= earlier_ordinal || delta.total == 0 {
                return TranscriptScan::Empty;
            }
            (ordinal - earlier_ordinal, delta)
        }
    };

    // Codex reports input_tokens inclusive of cached input. The canonical
    // non-cache input bucket subtracts both cache categories.
    let uncached = usage
        .input
        .saturating_sub(usage.cached)
        .saturating_sub(usage.cache_write);
    let tokens = Tokens {
        input: uncached,
        cache_create: usage.cache_write,
        cache_read: usage.cached,
        output: usage.output,
    };
    let mut by_model = BTreeMap::new();
    by_model.insert(model.clone(), tokens.clone());

    TranscriptScan::Usage(UsageScan {
        scan: ScanResult {
            tokens,
            last_message_id: latest.marker(ordinal),
            messages_scanned,
            model,
            by_model: by_model.into_iter().collect(),
        },
        harness: "codex",
        source_format: "codex-rollout-v1",
        reasoning_output: usage.reasoning,
        total_tokens: usage.total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rollout(total_input: u64, cached: u64, output: u64) -> String {
        [
            r#"{"type":"session_meta","payload":{"cli_version":"0.145.0"}}"#.to_string(),
            r#"{"type":"turn_context","payload":{"model":"gpt-5.6-sol"}}"#.to_string(),
            serde_json::json!({
                "type": "event_msg",
                "payload": {
                    "type": "token_count",
                    "info": {
                        "total_token_usage": {
                            "input_tokens": total_input,
                            "cached_input_tokens": cached,
                            "cache_write_input_tokens": 3,
                            "output_tokens": output,
                            "reasoning_output_tokens": 7,
                            "total_tokens": total_input + output,
                        }
                    }
                }
            })
            .to_string(),
        ]
        .join("\n")
    }

    #[test]
    fn codex_v1_extracts_usage_metadata_only() {
        let TranscriptScan::Usage(result) = scan_transcript(&rollout(100, 40, 10), None, "codex")
        else {
            panic!("expected usage")
        };
        assert_eq!(result.source_format, "codex-rollout-v1");
        assert_eq!(result.scan.tokens.input, 57);
        assert_eq!(result.scan.tokens.cache_create, 3);
        assert_eq!(result.scan.tokens.cache_read, 40);
        assert_eq!(result.scan.tokens.output, 10);
        assert_eq!(result.reasoning_output, 7);
        assert_eq!(result.total_tokens, 110);
        assert_eq!(result.scan.model, "gpt-5.6-sol");
    }

    #[test]
    fn codex_marker_uses_cumulative_delta() {
        let TranscriptScan::Usage(first) = scan_transcript(&rollout(100, 40, 10), None, "codex")
        else {
            panic!("expected usage")
        };
        let transcript = [
            rollout(100, 40, 10),
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":150,"cached_input_tokens":60,"cache_write_input_tokens":5,"output_tokens":20,"reasoning_output_tokens":9,"total_tokens":170}}}}"#.to_string(),
        ]
        .join("\n");
        let TranscriptScan::Usage(delta) =
            scan_transcript(&transcript, Some(&first.scan.last_message_id), "codex")
        else {
            panic!("expected delta")
        };
        assert_eq!(delta.scan.tokens.input, 28);
        assert_eq!(delta.scan.tokens.cache_create, 2);
        assert_eq!(delta.scan.tokens.cache_read, 20);
        assert_eq!(delta.scan.tokens.output, 10);
        assert_eq!(delta.total_tokens, 60);
    }

    #[test]
    fn unknown_codex_schema_is_diagnostic_not_zero_usage() {
        let input = r#"{"type":"session_meta","payload":{"cli_version":"9.0.0"}}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"new_field":1}}}}"#;
        assert_eq!(
            scan_transcript(input, None, "codex"),
            TranscriptScan::Diagnostic(ScanDiagnostic {
                harness: "codex",
                source_format: "codex-rollout-unknown",
                code: "unknown-codex-rollout-schema",
            })
        );
    }

    #[test]
    fn prompt_content_is_not_deserialized_or_emitted() {
        let secret = "never-copy-this-prompt";
        let transcript = format!(
            "{}\n{{\"type\":\"response_item\",\"payload\":{{\"content\":\"{secret}\"}}}}",
            rollout(10, 0, 2)
        );
        let result = format!("{:?}", scan_transcript(&transcript, None, "codex"));
        assert!(!result.contains(secret));
    }
}
