//! `SubagentStart` / `SubagentStop` — append one line per event to
//! `<metrics_dir>/subagents.jsonl`.
//!
//! Port of `log-subagent-event.sh`. A lifecycle audit log only — no token or
//! cost data (cross-reference `commits.jsonl` via `parentSessionId`). When
//! `CADENCE_METRICS_DEBUG=1`, a `_keys` array of the raw payload's top-level
//! keys is appended, surfacing schema additions across Claude Code releases.

use crate::common;
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a line to `subagents.jsonl` for each subagent lifecycle event.
pub struct LogSubagent;

impl Logger for LogSubagent {
    fn name(&self) -> &str {
        "log-subagent"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(event) = input.hook_event_name.as_deref() else {
            return;
        };
        if event != "SubagentStart" && event != "SubagentStop" {
            return;
        }

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let debug = std::env::var("CADENCE_METRICS_DEBUG").as_deref() == Ok("1");
        let record = build_subagent_record(input, &common::utc_timestamp(), debug);

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("subagents.jsonl"))
        {
            let _ = writeln!(file, "{record}");
        }
    }
}

/// Build the JSONL record for a subagent event. Pure — no I/O.
fn build_subagent_record(input: &MetricsInput, ts: &str, include_keys: bool) -> Value {
    let mut record = json!({
        "ts": ts,
        "event": input.hook_event_name,
        "sessionId": input.session_id,
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
        "parentAgentId": input.parent_agent_id,
        "sourceAgentId": input.source_agent_id,
        "cwd": input.cwd,
        "transcriptPath": input.transcript_path,
        "durationMs": input.duration_ms,
    });

    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stop_event() -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("SubagentStop".into()),
            session_id: Some("s1".into()),
            agent_id: Some("a1".into()),
            agent_type: Some("Explore".into()),
            duration_ms: Some(4200),
            raw_keys: vec!["hook_event_name".into(), "agent_id".into()],
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_subagent() {
        assert_eq!(LogSubagent.name(), "log-subagent");
    }

    #[test]
    fn record_carries_lifecycle_fields() {
        let record = build_subagent_record(&stop_event(), "2026-05-19T00:00:00Z", false);
        assert_eq!(record["event"], "SubagentStop");
        assert_eq!(record["agentType"], "Explore");
        assert_eq!(record["durationMs"], 4200);
        assert_eq!(record["ts"], "2026-05-19T00:00:00Z");
        // Absent fields serialize as null, not omitted.
        assert!(record["parentSessionId"].is_null());
        assert!(record.get("_keys").is_none());
    }

    #[test]
    fn debug_adds_keys() {
        let record = build_subagent_record(&stop_event(), "2026-05-19T00:00:00Z", true);
        let keys = record["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("agent_id")));
    }

    #[test]
    fn non_subagent_event_is_noop() {
        // PreToolUse should not be logged here.
        let input = MetricsInput {
            hook_event_name: Some("PreToolUse".into()),
            ..Default::default()
        };
        LogSubagent.run(&input);
    }
}
