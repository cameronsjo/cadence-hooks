//! `EnterPlanMode` / `ExitPlanMode` — append one line per event to
//! `<metrics_dir>/plan-phases.jsonl`.
//!
//! Reacts to `PostToolUse` and derives its event from `tool_name` rather than
//! a fixed `hook_event_name` gate (sibling of [`crate::log_subagent`]'s
//! two-event shape). Carries the same whole-transcript token/cost scan as
//! [`crate::log_session`] (`scan_tokens` + `Prices::load`), but never gates
//! the row on it — a stale or missing transcript degrades `tokensSinceStart`
//! / `costUsd` / `model` to `null` rather than skipping the write, so a
//! plan-phase transition is never silently dropped for lack of pricing data.
//!
//! Stamps `schemaVersion` (`common::PLAN_PHASE_SCHEMA_VERSION`) on every row.
//! The shared per-stream version convention and its bump policy live in
//! [`crate::common`] (schema versioning section).

use crate::common;
use crate::compute_cost::compute_cost_by_model;
use crate::prices::Prices;
use crate::scan_tokens::{ScanResult, scan_tokens};
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a line to `plan-phases.jsonl` for each plan lifecycle event. Holds
/// the optional price table override path supplied via `--prices`, mirroring
/// [`crate::log_session::LogSession`].
pub struct LogPlanPhase {
    pub prices_path: Option<String>,
}

impl Logger for LogPlanPhase {
    fn name(&self) -> &str {
        "log-plan-phase"
    }

    fn run(&self, input: &MetricsInput) {
        if input.hook_event_name.as_deref() != Some("PostToolUse") {
            return;
        }
        let Some(event) = plan_event(input.tool_name.as_deref()) else {
            return;
        };

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let summary = token_summary(input, self.prices_path.as_deref());
        let branch = common::branch(input.cwd.as_deref());
        let repo = common::repo_basename(input.cwd.as_deref());
        let ts = common::utc_timestamp();
        let debug = std::env::var("CADENCE_METRICS_DEBUG").as_deref() == Ok("1");

        let record = build_plan_phase_record(
            input,
            event,
            &ts,
            &repo,
            &branch,
            summary.as_ref().map(|(scan, _)| scan),
            summary.as_ref().map(|(_, cost)| *cost),
            debug,
        );

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("plan-phases.jsonl"))
        {
            // Single write_all of record + newline, matching log_subagent.rs —
            // atomic per-record so concurrent appends can't interleave.
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Map a hook's `tool_name` to a plan-lifecycle event name. `None` for any
/// tool other than `EnterPlanMode`/`ExitPlanMode` (or a missing `tool_name`) —
/// the caller no-ops rather than logging every tool call.
fn plan_event(tool_name: Option<&str>) -> Option<&'static str> {
    match tool_name {
        Some("EnterPlanMode") => Some("plan_enter"),
        Some("ExitPlanMode") => Some("plan_exit"),
        _ => None,
    }
}

/// Whole-transcript token scan + cost, verbatim the same approach as
/// [`crate::log_session::LogSession::run`]: `scan_tokens(&transcript, None)`,
/// `Prices::load` from the `--prices` path, and an `is_safe_session_id` guard
/// on the session id before touching the transcript path. Returns `None` on
/// any failure (unsafe/missing session id, missing/unreadable transcript, or
/// nothing to scan) — the caller treats that as "no pricing data", not an
/// error.
fn token_summary(input: &MetricsInput, prices_path: Option<&str>) -> Option<(ScanResult, f64)> {
    input
        .session_id
        .as_deref()
        .filter(|s| common::is_safe_session_id(s))?;
    let transcript_path = input.transcript_path.as_deref()?;
    if !std::path::Path::new(transcript_path).is_file() {
        return None;
    }
    let transcript = std::fs::read_to_string(transcript_path).ok()?;
    let scan = scan_tokens(&transcript, None)?;
    let prices = Prices::load(prices_path);
    let cost = compute_cost_by_model(&scan.by_model, &prices);
    Some((scan, cost))
}

/// Build the JSONL record for a plan-phase event. Pure — no I/O. `scan`/`cost`
/// are `None` when [`token_summary`] couldn't price the transcript; the
/// resulting `model` / `tokensSinceStart` / `costUsd` fields serialize as
/// explicit `null`, per crate convention.
#[allow(clippy::too_many_arguments)]
fn build_plan_phase_record(
    input: &MetricsInput,
    event: &str,
    ts: &str,
    repo: &str,
    branch: &str,
    scan: Option<&ScanResult>,
    cost: Option<f64>,
    include_keys: bool,
) -> Value {
    let model = scan.map(|s| s.model.clone());
    let tokens_since_start = scan.map(|s| {
        json!({
            "input": s.tokens.input,
            "cacheCreate": s.tokens.cache_create,
            "cacheRead": s.tokens.cache_read,
            "output": s.tokens.output,
        })
    });

    let mut record = json!({
        "schemaVersion": common::PLAN_PHASE_SCHEMA_VERSION,
        "ts": ts,
        "event": event,
        "sessionId": input.session_id,
        "transcriptPath": input.transcript_path,
        "repo": repo,
        "branch": branch,
        "model": model,
        "tokensSinceStart": tokens_since_start,
        "costUsd": cost,
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
    });

    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_plan_input() -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("PostToolUse".into()),
            tool_name: Some("ExitPlanMode".into()),
            session_id: Some("s1".into()),
            raw_keys: vec!["hook_event_name".into(), "tool_name".into()],
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_plan_phase() {
        assert_eq!(LogPlanPhase { prices_path: None }.name(), "log-plan-phase");
    }

    // --- event derivation ---

    #[test]
    fn enter_plan_mode_derives_plan_enter() {
        assert_eq!(plan_event(Some("EnterPlanMode")), Some("plan_enter"));
    }

    #[test]
    fn exit_plan_mode_derives_plan_exit() {
        assert_eq!(plan_event(Some("ExitPlanMode")), Some("plan_exit"));
    }

    #[test]
    fn other_tool_derives_none() {
        assert_eq!(plan_event(Some("Bash")), None);
    }

    #[test]
    fn missing_tool_name_derives_none() {
        assert_eq!(plan_event(None), None);
    }

    #[test]
    fn wrong_hook_event_is_noop() {
        // PreToolUse (or any non-PostToolUse event) must not log, even with a
        // recognized tool_name.
        let input = MetricsInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: Some("ExitPlanMode".into()),
            ..Default::default()
        };
        LogPlanPhase { prices_path: None }.run(&input);
    }

    #[test]
    fn other_tool_on_post_tool_use_is_noop() {
        let input = MetricsInput {
            hook_event_name: Some("PostToolUse".into()),
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        LogPlanPhase { prices_path: None }.run(&input);
    }

    // --- record shape ---

    #[test]
    fn record_carries_event_and_context_fields() {
        let record = build_plan_phase_record(
            &exit_plan_input(),
            "plan_exit",
            "2026-07-05T00:00:00Z",
            "myrepo",
            "feat/x",
            None,
            None,
            false,
        );
        assert_eq!(record["schemaVersion"], common::PLAN_PHASE_SCHEMA_VERSION);
        assert_eq!(record["ts"], "2026-07-05T00:00:00Z");
        assert_eq!(record["event"], "plan_exit");
        assert_eq!(record["sessionId"], "s1");
        assert_eq!(record["repo"], "myrepo");
        assert_eq!(record["branch"], "feat/x");
    }

    #[test]
    fn absent_optional_fields_are_null() {
        let record = build_plan_phase_record(
            &exit_plan_input(),
            "plan_exit",
            "2026-07-05T00:00:00Z",
            "myrepo",
            "feat/x",
            None,
            None,
            false,
        );
        assert!(record["transcriptPath"].is_null());
        assert!(record["model"].is_null());
        assert!(record["tokensSinceStart"].is_null());
        assert!(record["costUsd"].is_null());
        assert!(record["agentId"].is_null());
        assert!(record["agentType"].is_null());
        assert!(record["parentSessionId"].is_null());
        assert!(record.get("_keys").is_none());
    }

    #[test]
    fn present_scan_populates_model_and_tokens() {
        let scan = ScanResult {
            tokens: crate::scan_tokens::Tokens {
                input: 100,
                cache_create: 50,
                cache_read: 200,
                output: 30,
            },
            last_message_id: "m9".into(),
            messages_scanned: 3,
            model: "claude-opus-4-8".into(),
            by_model: vec![],
        };
        let record = build_plan_phase_record(
            &exit_plan_input(),
            "plan_exit",
            "2026-07-05T00:00:00Z",
            "myrepo",
            "feat/x",
            Some(&scan),
            Some(0.001234),
            false,
        );
        assert_eq!(record["model"], "claude-opus-4-8");
        assert_eq!(record["tokensSinceStart"]["input"], 100);
        assert_eq!(record["tokensSinceStart"]["cacheCreate"], 50);
        assert_eq!(record["tokensSinceStart"]["cacheRead"], 200);
        assert_eq!(record["tokensSinceStart"]["output"], 30);
        assert_eq!(record["costUsd"], 0.001234);
    }

    #[test]
    fn debug_adds_keys() {
        let record = build_plan_phase_record(
            &exit_plan_input(),
            "plan_exit",
            "2026-07-05T00:00:00Z",
            "myrepo",
            "feat/x",
            None,
            None,
            true,
        );
        let keys = record["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("tool_name")));
    }

    #[test]
    fn record_serializes_to_single_line() {
        let line = build_plan_phase_record(
            &exit_plan_input(),
            "plan_exit",
            "2026-07-05T00:00:00Z",
            "myrepo",
            "feat/x",
            None,
            None,
            true,
        )
        .to_string();
        assert!(!line.contains('\n'), "record must be one line: {line}");
    }

    #[test]
    fn token_summary_none_without_session_id() {
        let input = MetricsInput {
            transcript_path: Some("/nonexistent/path.jsonl".into()),
            ..Default::default()
        };
        assert!(token_summary(&input, None).is_none());
    }

    #[test]
    fn token_summary_none_for_unreadable_transcript() {
        let input = MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/nonexistent/path.jsonl".into()),
            ..Default::default()
        };
        assert!(token_summary(&input, None).is_none());
    }
}
