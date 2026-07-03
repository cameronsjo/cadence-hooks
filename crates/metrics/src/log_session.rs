//! `SessionEnd` — scan the whole transcript for token usage, compute cost, and
//! append one line to `<metrics_dir>/sessions.jsonl`.
//!
//! Sibling of [`crate::log_commit`]: where `log-commit` scans the range since
//! the last commit marker, `log-session` scans the *whole* transcript once at
//! session end. `sum(commits) ≤ session` — the gap is uncommitted-work cost;
//! each `/clear` segment mints a new session id and so writes its own row.
//!
//! Fire-and-forget: silent no-op on any failure, never blocks.

use crate::common;
use crate::compute_cost::compute_cost_by_model;
use crate::model_breakdown::{by_model_json, unpriced_models};
use crate::prices::Prices;
use crate::scan_tokens::{ScanResult, scan_tokens};
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a per-session cost line to `sessions.jsonl` at `SessionEnd`. Holds
/// the optional price table override path supplied via `--prices`.
pub struct LogSession {
    pub prices_path: Option<String>,
}

impl Logger for LogSession {
    fn name(&self) -> &str {
        "log-session"
    }

    fn run(&self, input: &MetricsInput) {
        // Belt-and-suspenders gate: only write on SessionEnd. This fn never
        // deletes state, but the gate keeps a misrouted event from writing a
        // spurious row (mirrors `crates/session/src/end.rs`).
        if input.hook_event_name.as_deref() != Some("SessionEnd") {
            return;
        }

        let Some(session_id) = input
            .session_id
            .as_deref()
            .filter(|s| common::is_safe_session_id(s))
        else {
            return;
        };
        let Some(transcript_path) = input.transcript_path.as_deref() else {
            return;
        };
        if !std::path::Path::new(transcript_path).is_file() {
            return;
        }

        let Ok(transcript) = std::fs::read_to_string(transcript_path) else {
            return;
        };
        // Whole transcript, no marker. `None` scan → nothing to price → skip.
        let Some(scan) = scan_tokens(&transcript, None) else {
            return;
        };

        let prices = Prices::load(self.prices_path.as_deref());
        let cost = compute_cost_by_model(&scan.by_model, &prices);

        let branch = common::branch(input.cwd.as_deref());
        let repo = common::repo_basename(input.cwd.as_deref());

        let record = build_session_record(
            &common::utc_timestamp(),
            input,
            session_id,
            &branch,
            &repo,
            &scan,
            cost,
            &prices,
        );

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let sessions_path = dir.join("sessions.jsonl");

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&sessions_path)
        {
            // Build the whole line (record + newline) and write it in a single
            // `write_all`, so concurrent appends from other sessions can't
            // interleave a record with its trailing newline. `record` is compact
            // JSON, so this is one line with no embedded newlines.
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Build the `sessions.jsonl` record. Pure — no I/O. The `byModel`/`unpricedModels`
/// shapes come from [`crate::model_breakdown`], shared verbatim with `log_commit`.
#[allow(clippy::too_many_arguments)]
fn build_session_record(
    ts: &str,
    input: &MetricsInput,
    session_id: &str,
    branch: &str,
    repo: &str,
    scan: &ScanResult,
    cost: f64,
    prices: &Prices,
) -> Value {
    let by_model = by_model_json(&scan.by_model, prices);
    let unpriced = unpriced_models(&scan.by_model, prices);

    json!({
        "ts": ts,
        "sessionId": session_id,
        "transcriptPath": input.transcript_path,
        "repo": repo,
        "branch": branch,
        "reason": input.reason,
        "durationApproxMs": input.duration_ms,
        "model": scan.model,
        "tokens": {
            "input": scan.tokens.input,
            "cacheCreate": scan.tokens.cache_create,
            "cacheRead": scan.tokens.cache_read,
            "output": scan.tokens.output,
        },
        "costUsd": cost,
        "byModel": by_model,
        "unpricedModels": unpriced,
        "messagesScanned": scan.messages_scanned,
        "lastMessageId": scan.last_message_id,
        "agentId": input.agent_id,
        "parentSessionId": input.parent_session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_tokens::Tokens;

    #[test]
    fn name_is_log_session() {
        assert_eq!(LogSession { prices_path: None }.name(), "log-session");
    }

    fn sample_scan() -> ScanResult {
        ScanResult {
            tokens: Tokens {
                input: 100,
                cache_create: 50,
                cache_read: 200,
                output: 30,
            },
            last_message_id: "m9".into(),
            messages_scanned: 3,
            model: "claude-opus-4-7".into(),
            by_model: vec![(
                "claude-opus-4-7".into(),
                Tokens {
                    input: 100,
                    cache_create: 50,
                    cache_read: 200,
                    output: 30,
                },
            )],
        }
    }

    fn sample_input() -> MetricsInput {
        MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/tmp/t.jsonl".into()),
            hook_event_name: Some("SessionEnd".into()),
            reason: Some("prompt_input_exit".into()),
            duration_ms: Some(4567),
            agent_id: Some("a1".into()),
            parent_session_id: Some("ps1".into()),
            ..Default::default()
        }
    }

    #[test]
    fn session_record_has_full_schema() {
        let prices = Prices::embedded();
        let record = build_session_record(
            "2026-07-02T00:00:00Z",
            &sample_input(),
            "s1",
            "feat/x",
            "myrepo",
            &sample_scan(),
            0.001234,
            &prices,
        );
        assert_eq!(record["sessionId"], "s1");
        assert_eq!(record["transcriptPath"], "/tmp/t.jsonl");
        assert_eq!(record["repo"], "myrepo");
        assert_eq!(record["branch"], "feat/x");
        assert_eq!(record["reason"], "prompt_input_exit");
        assert_eq!(record["durationApproxMs"], 4567);
        assert_eq!(record["model"], "claude-opus-4-7");
        assert_eq!(record["tokens"]["input"], 100);
        assert_eq!(record["tokens"]["cacheCreate"], 50);
        assert_eq!(record["tokens"]["cacheRead"], 200);
        assert_eq!(record["tokens"]["output"], 30);
        assert_eq!(record["costUsd"], 0.001234);
        assert_eq!(record["messagesScanned"], 3);
        assert_eq!(record["lastMessageId"], "m9");
        assert_eq!(record["agentId"], "a1");
        assert_eq!(record["parentSessionId"], "ps1");
        // byModel is always present and non-empty for a scanned range.
        assert!(record["byModel"].is_array());
        assert_eq!(record["byModel"].as_array().unwrap().len(), 1);
        assert_eq!(record["byModel"][0]["model"], "claude-opus-4-7");
        // Priced model → empty unpriced array.
        assert!(record["unpricedModels"].as_array().unwrap().is_empty());
    }

    #[test]
    fn session_record_absent_optional_fields_are_null() {
        let prices = Prices::embedded();
        let input = MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/tmp/t.jsonl".into()),
            hook_event_name: Some("SessionEnd".into()),
            ..Default::default()
        };
        let record = build_session_record(
            "2026-07-02T00:00:00Z",
            &input,
            "s1",
            "",
            "myrepo",
            &sample_scan(),
            0.0,
            &prices,
        );
        // Absent → null, not omitted.
        assert!(record["reason"].is_null());
        assert!(record["durationApproxMs"].is_null());
        assert!(record["agentId"].is_null());
        assert!(record["parentSessionId"].is_null());
        assert_eq!(record["branch"], "");
    }

    #[test]
    fn session_record_flags_unpriced_model_never_silently_zero() {
        // #95: an unpriced model id must land in unpricedModels rather than
        // silently costing $0 with no trace.
        let prices = Prices::embedded();
        let scan = ScanResult {
            tokens: Tokens {
                input: 100,
                ..Default::default()
            },
            last_message_id: "m9".into(),
            messages_scanned: 1,
            model: "gpt-9".into(),
            by_model: vec![(
                "gpt-9".into(),
                Tokens {
                    input: 100,
                    ..Default::default()
                },
            )],
        };
        let record = build_session_record(
            "ts",
            &sample_input(),
            "s1",
            "main",
            "r",
            &scan,
            0.0,
            &prices,
        );
        let unpriced = record["unpricedModels"].as_array().unwrap();
        assert_eq!(unpriced.len(), 1);
        assert_eq!(unpriced[0], "gpt-9");
    }

    /// Whole ≥ parts: a session scan of the full transcript costs at least as
    /// much as any commit scanning a proper sub-range of the same transcript.
    #[test]
    fn session_cost_ge_subrange_commit_cost() {
        let transcript = [
            r#"{"message":{"id":"m1","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":100,"output_tokens":10}}}"#,
            r#"{"message":{"id":"m2","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":200,"output_tokens":20}}}"#,
            r#"{"message":{"id":"m3","role":"assistant","model":"claude-opus-4-7","usage":{"input_tokens":300,"output_tokens":30}}}"#,
        ]
        .join("\n");
        let prices = Prices::embedded();

        // Whole transcript (what log-session records).
        let whole = scan_tokens(&transcript, None).unwrap();
        let whole_cost = compute_cost_by_model(&whole.by_model, &prices);

        // A commit scanning only the range after m1 (sums m2 + m3) — a proper
        // subrange of the same transcript.
        let part = scan_tokens(&transcript, Some("m1")).unwrap();
        let part_cost = compute_cost_by_model(&part.by_model, &prices);

        assert!(part_cost > 0.0, "subrange must have a positive cost");
        assert!(
            whole_cost >= part_cost,
            "whole session cost {whole_cost} must be >= subrange commit cost {part_cost}"
        );
        // And the session's recorded tokens equal the whole-transcript sum.
        assert_eq!(whole.tokens.input, 600);
        assert_eq!(whole.tokens.output, 60);
    }
}
