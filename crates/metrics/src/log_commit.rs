//! `PostToolUse:Bash` — when a `git commit` moved HEAD, scan the transcript for
//! token usage since the last commit (or session start), compute cost, and
//! append one line to `<metrics_dir>/commits.jsonl`.
//!
//! Port of `log-commit.sh`. Silent no-op on any failure — never blocks.

use crate::common;
use crate::compute_cost::compute_cost_by_model;
use crate::prices::Prices;
use crate::transcript::{TranscriptScan, UsageScan, scan_transcript};
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a cost-per-commit line to `commits.jsonl`. Holds the optional price
/// table override path supplied via `--prices`.
pub struct LogCommit {
    pub prices_path: Option<String>,
}

impl Logger for LogCommit {
    fn name(&self) -> &str {
        "log-commit"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(command) = input.command() else {
            return;
        };
        if !common::is_git_commit(command) {
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

        // The snapshot from the PreToolUse partner. Consume it (the bash hook
        // `rm`s it) so a later non-commit Bash call can't reuse a stale SHA.
        let before_file = common::state_dir().join(format!("{session_id}.before"));
        let Ok(sha_before) = std::fs::read_to_string(&before_file) else {
            return;
        };
        let _ = std::fs::remove_file(&before_file);
        let sha_before = sha_before.trim().to_string();
        if sha_before.is_empty() {
            return;
        }

        let Some(sha_after) = common::head_sha(input.cwd.as_deref()) else {
            return;
        };
        if sha_before == sha_after {
            return; // commit didn't land (no-op commit)
        }

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let commits_path = dir.join("commits.jsonl");

        let last_message_id = std::fs::read_to_string(&commits_path)
            .ok()
            .and_then(|contents| parse_last_message_id(&contents, session_id));

        let Ok(transcript) = std::fs::read_to_string(transcript_path) else {
            return;
        };
        let usage = match scan_transcript(&transcript, last_message_id.as_deref()) {
            TranscriptScan::Usage(usage) => usage,
            TranscriptScan::Diagnostic(diagnostic) => {
                common::append_transcript_diagnostic(
                    diagnostic.harness,
                    diagnostic.source_format,
                    diagnostic.code,
                    "commits",
                );
                return;
            }
            TranscriptScan::Empty => return,
        };

        let prices = Prices::load(self.prices_path.as_deref());
        // Unconditional since the unpriced harness was retired (#1040). It was
        // `(usage.harness == "claude").then(...)`, which is now a tautology —
        // left in place it would read as live logic while its `unwrap_or(0.0)`
        // fallback silently rendered "unpriced" as "$0.00" in any aggregation.
        let cost = compute_cost_by_model(&usage.scan.by_model, &prices);

        let since_marker = last_message_id.as_deref().unwrap_or("session-start");
        let branch = common::branch(input.cwd.as_deref());
        let repo = common::repo_basename(input.cwd.as_deref());

        let record = build_commit_record(
            &common::utc_timestamp(),
            input,
            &sha_before,
            &sha_after,
            &branch,
            &repo,
            &usage,
            cost,
            since_marker,
            &prices,
        );

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&commits_path)
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

/// Find the `lastMessageId` of the most recent `commits.jsonl` entry for this
/// session. Pure — operates on file contents, no I/O.
fn parse_last_message_id(commits_jsonl: &str, session_id: &str) -> Option<String> {
    commits_jsonl
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .rfind(|v| v.get("sessionId").and_then(Value::as_str) == Some(session_id))
        .and_then(|v| {
            v.get("lastMessageId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
}

/// Build the `commits.jsonl` record. Pure — no I/O.
#[allow(clippy::too_many_arguments)]
fn build_commit_record(
    ts: &str,
    input: &MetricsInput,
    sha_before: &str,
    sha_after: &str,
    branch: &str,
    repo: &str,
    usage: &UsageScan,
    cost: f64,
    since_marker: &str,
    prices: &Prices,
) -> Value {
    // Per-model breakdown + unpriced-model flags, shared verbatim with
    // `log_session` so the two loggers' shapes cannot drift (see
    // `crate::model_breakdown`).
    let scan = &usage.scan;
    let (by_model, unpriced) = usage.priced_breakdown(prices);

    let mut record = json!({
        "schemaVersion": common::TOKEN_RECORD_SCHEMA_VERSION,
        "ts": ts,
        "harness": usage.harness,
        "sourceFormat": usage.source_format,
        "sessionId": input.session_id,
        "transcriptPath": input.transcript_path,
        "commitHashBefore": sha_before,
        "commitHashAfter": sha_after,
        "branch": branch,
        "repo": repo,
        "model": scan.model,
        "tokens": {
            "input": scan.tokens.input,
            "cacheCreate": scan.tokens.cache_create,
            "cacheRead": scan.tokens.cache_read,
            "output": scan.tokens.output,
            "reasoningOutput": usage.reasoning_output,
            "total": usage.total_tokens,
        },
        "byModel": by_model,
        "unpricedModels": unpriced,
        "messagesScanned": scan.messages_scanned,
        "lastMessageId": scan.last_message_id,
        "sinceMarker": since_marker,
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
        "parentAgentId": input.parent_agent_id,
    });
    record["costUsd"] = json!(cost);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prices::Prices;
    use crate::scan_tokens::{ScanResult, Tokens};

    #[test]
    fn name_is_log_commit() {
        assert_eq!(LogCommit { prices_path: None }.name(), "log-commit");
    }

    #[test]
    fn parse_last_message_id_picks_latest_for_session() {
        let jsonl = [
            r#"{"sessionId":"s1","lastMessageId":"m1"}"#,
            r#"{"sessionId":"s2","lastMessageId":"x9"}"#,
            r#"{"sessionId":"s1","lastMessageId":"m5"}"#,
        ]
        .join("\n");
        assert_eq!(parse_last_message_id(&jsonl, "s1").as_deref(), Some("m5"));
        assert_eq!(parse_last_message_id(&jsonl, "s2").as_deref(), Some("x9"));
    }

    #[test]
    fn parse_last_message_id_absent_session() {
        let jsonl = r#"{"sessionId":"s1","lastMessageId":"m1"}"#;
        assert_eq!(parse_last_message_id(jsonl, "other"), None);
    }

    #[test]
    fn parse_last_message_id_empty_file() {
        assert_eq!(parse_last_message_id("", "s1"), None);
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

    fn sample_usage() -> UsageScan {
        UsageScan::claude(sample_scan())
    }

    fn sample_input() -> MetricsInput {
        MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/tmp/t.jsonl".into()),
            agent_id: Some("a1".into()),
            agent_type: Some("Explore".into()),
            ..Default::default()
        }
    }

    #[test]
    fn commit_record_has_full_schema() {
        let prices = Prices::embedded();
        let record = build_commit_record(
            "2026-05-19T00:00:00Z",
            &sample_input(),
            "aaaa",
            "bbbb",
            "feat/x",
            "myrepo",
            &sample_usage(),
            0.001234,
            "m1",
            &prices,
        );
        assert_eq!(record["sessionId"], "s1");
        assert_eq!(record["commitHashBefore"], "aaaa");
        assert_eq!(record["commitHashAfter"], "bbbb");
        assert_eq!(record["branch"], "feat/x");
        assert_eq!(record["repo"], "myrepo");
        assert_eq!(record["model"], "claude-opus-4-7");
        assert_eq!(record["tokens"]["input"], 100);
        assert_eq!(record["tokens"]["cacheCreate"], 50);
        assert_eq!(record["tokens"]["cacheRead"], 200);
        assert_eq!(record["tokens"]["output"], 30);
        assert_eq!(record["costUsd"], 0.001234);
        assert_eq!(record["schemaVersion"], 2);
        assert_eq!(record["harness"], "claude");
        assert_eq!(record["sourceFormat"], "claude-transcript-v1");
        assert_eq!(record["tokens"]["total"], 380);
        assert_eq!(record["messagesScanned"], 3);
        assert_eq!(record["lastMessageId"], "m9");
        assert_eq!(record["sinceMarker"], "m1");
        assert_eq!(record["agentType"], "Explore");
        // Main-thread fields absent → null, not omitted.
        assert!(record["parentSessionId"].is_null());
        // byModel is always present.
        assert!(record["byModel"].is_array());
        assert_eq!(record["byModel"].as_array().unwrap().len(), 1);
        assert_eq!(record["byModel"][0]["model"], "claude-opus-4-7");
    }

    #[test]
    fn commit_record_session_start_marker() {
        let prices = Prices::embedded();
        let record = build_commit_record(
            "2026-05-19T00:00:00Z",
            &sample_input(),
            "aaaa",
            "bbbb",
            "",
            "myrepo",
            &sample_usage(),
            0.0,
            "session-start",
            &prices,
        );
        assert_eq!(record["sinceMarker"], "session-start");
        assert_eq!(record["branch"], "");
        assert_eq!(record["costUsd"], 0.0);
    }

    #[test]
    fn commit_record_by_model_multi_bucket() {
        use crate::scan_tokens::Tokens;
        let prices = Prices::embedded();
        let scan = ScanResult {
            tokens: Tokens {
                input: 300,
                cache_create: 0,
                cache_read: 0,
                output: 30,
            },
            last_message_id: "m2".into(),
            messages_scanned: 2,
            model: "claude-opus-4-7".into(),
            by_model: vec![
                (
                    "claude-opus-4-7".into(),
                    Tokens {
                        input: 200,
                        cache_create: 0,
                        cache_read: 0,
                        output: 20,
                    },
                ),
                (
                    "claude-sonnet-4-5".into(),
                    Tokens {
                        input: 100,
                        cache_create: 0,
                        cache_read: 0,
                        output: 10,
                    },
                ),
            ],
        };
        let cost = compute_cost_by_model(&scan.by_model, &prices);
        let record = build_commit_record(
            "2026-06-01T00:00:00Z",
            &sample_input(),
            "aaaa",
            "bbbb",
            "main",
            "myrepo",
            &UsageScan::claude(scan),
            cost,
            "m0",
            &prices,
        );
        let by_model_arr = record["byModel"].as_array().unwrap();
        assert_eq!(by_model_arr.len(), 2);
        // Both buckets have model + tokens + costUsd
        for bucket in by_model_arr {
            assert!(bucket["model"].is_string());
            assert!(bucket["tokens"]["input"].is_number());
            assert!(bucket["costUsd"].is_number());
        }
        // Grand total costUsd matches sum of per-bucket costUsd
        let bucket_sum: f64 = by_model_arr
            .iter()
            .map(|b| b["costUsd"].as_f64().unwrap())
            .sum();
        let total = record["costUsd"].as_f64().unwrap();
        assert!((total - bucket_sum).abs() < 1e-9);
    }

    #[test]
    fn commit_record_flags_unpriced_models() {
        // #95: a model absent from the price table is recorded in unpricedModels
        // so the silent $0 cost is greppable.
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
        let rec = build_commit_record(
            "ts",
            &sample_input(),
            "a",
            "b",
            "main",
            "r",
            &UsageScan::claude(scan),
            0.0,
            "m0",
            &prices,
        );
        let unpriced = rec["unpricedModels"].as_array().unwrap();
        assert_eq!(unpriced.len(), 1);
        assert_eq!(unpriced[0], "gpt-9");
    }

    #[test]
    fn commit_record_no_unpriced_for_known_model() {
        // sample_scan() uses claude-opus-4-7, which is priced → empty array.
        let rec = build_commit_record(
            "ts",
            &sample_input(),
            "a",
            "b",
            "main",
            "r",
            &sample_usage(),
            0.001,
            "m1",
            &Prices::embedded(),
        );
        assert!(rec["unpricedModels"].as_array().unwrap().is_empty());
    }

    /// Every commit record carries a real `costUsd` and the schema-v2
    /// `reasoningOutput` field.
    ///
    /// Inherited from `codex_record_uses_nullable_estimate_without_cost_usd`,
    /// which asserted the nullable-estimate shape written for the unpriced
    /// harness. That harness is retired (#1040) and the branch with it, so the
    /// assertions invert; `reasoningOutput` is retained and keeps its coverage,
    /// which is why this was rewritten rather than deleted.
    #[test]
    fn record_carries_a_real_cost_and_reasoning_output() {
        let mut usage = sample_usage();
        usage.reasoning_output = 20;
        let rec = build_commit_record(
            "ts",
            &sample_input(),
            "a",
            "b",
            "main",
            "r",
            &usage,
            0.004_2,
            "session-start",
            &Prices::embedded(),
        );
        assert_eq!(rec["costUsd"], 0.004_2);
        assert!(rec.get("estimatedCostUsd").is_none());
        assert!(rec.get("pricingSource").is_none());
        assert!(rec.get("pricingVerifiedAt").is_none());
        assert_eq!(rec["tokens"]["reasoningOutput"], 20);
    }
}
