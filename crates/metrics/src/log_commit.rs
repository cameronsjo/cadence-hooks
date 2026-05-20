//! `PostToolUse:Bash` — when a `git commit` moved HEAD, scan the transcript for
//! token usage since the last commit (or session start), compute cost, and
//! append one line to `<metrics_dir>/commits.jsonl`.
//!
//! Port of `log-commit.sh`. Silent no-op on any failure — never blocks.

use crate::common;
use crate::compute_cost::compute_cost;
use crate::prices::Prices;
use crate::scan_tokens::{ScanResult, scan_tokens};
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

        let Some(session_id) = input.session_id.as_deref().filter(|s| !s.is_empty()) else {
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
        let Some(scan) = scan_tokens(&transcript, last_message_id.as_deref()) else {
            return; // nothing new since the marker — skip rather than overcount
        };

        let prices = Prices::load(self.prices_path.as_deref());
        let cost = compute_cost(&scan.tokens, &scan.model, &prices);

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
            &scan,
            cost,
            since_marker,
        );

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&commits_path)
        {
            let _ = writeln!(file, "{record}");
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
    scan: &ScanResult,
    cost: f64,
    since_marker: &str,
) -> Value {
    json!({
        "ts": ts,
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
        },
        "costUsd": cost,
        "messagesScanned": scan.messages_scanned,
        "lastMessageId": scan.last_message_id,
        "sinceMarker": since_marker,
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
        "parentAgentId": input.parent_agent_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_tokens::Tokens;

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
        }
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
        let record = build_commit_record(
            "2026-05-19T00:00:00Z",
            &sample_input(),
            "aaaa",
            "bbbb",
            "feat/x",
            "myrepo",
            &sample_scan(),
            0.001234,
            "m1",
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
        assert_eq!(record["messagesScanned"], 3);
        assert_eq!(record["lastMessageId"], "m9");
        assert_eq!(record["sinceMarker"], "m1");
        assert_eq!(record["agentType"], "Explore");
        // Main-thread fields absent → null, not omitted.
        assert!(record["parentSessionId"].is_null());
    }

    #[test]
    fn commit_record_session_start_marker() {
        let record = build_commit_record(
            "2026-05-19T00:00:00Z",
            &sample_input(),
            "aaaa",
            "bbbb",
            "",
            "myrepo",
            &sample_scan(),
            0.0,
            "session-start",
        );
        assert_eq!(record["sinceMarker"], "session-start");
        assert_eq!(record["branch"], "");
        assert_eq!(record["costUsd"], 0.0);
    }
}
