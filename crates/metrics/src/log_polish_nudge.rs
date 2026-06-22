//! `PostToolUse:Bash` — when `gh pr create` runs, append one line to
//! `<metrics_dir>/polish_nudges.jsonl` recording the nudge-fire and whether
//! `/polish` ran earlier this session.
//!
//! This is the deterministic denominator for the polish-nudge efficacy
//! measurement (claude-configurations#151): every `gh pr create` *is* a nudged
//! PR (it fires `nudge-polish-before-pr`), so the same [`is_gh_pr_create`]
//! predicate gates both. `polished` is a best-effort transcript scan for a
//! `cadence-forge:polish` Skill invocation earlier in the session — a row with
//! `polished: false` is a deterministic *skip candidate*. Distinguishing a
//! rationalized skip from a legitimate one stays a transcript/prose judgment;
//! this logger only makes the rate queryable without re-mining every transcript.
//!
//! Silent no-op on any failure — never blocks (it is a [`Logger`]).

use crate::common;
use cadence_hooks_core::shell::is_gh_pr_create;
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a nudge-fire line to `polish_nudges.jsonl`.
pub struct LogPolishNudge;

impl Logger for LogPolishNudge {
    fn name(&self) -> &str {
        "log-polish-nudge"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(command) = input.command() else {
            return;
        };
        // The denominator is defined as "every PR that fired the nudge", so the
        // gate MUST be the same predicate the nudge uses.
        if !is_gh_pr_create(command) {
            return;
        }
        // Skip malformed payloads (mirrors the other loggers); session_id is
        // recorded as a JSON value, never used in a path, so this is hygiene.
        if !input
            .session_id
            .as_deref()
            .is_some_and(common::is_safe_session_id)
        {
            return;
        }

        // Did `/polish` run earlier this session? Best-effort — a missing or
        // unreadable transcript yields `false` (an honest "no evidence of
        // polish"), never a panic.
        let polished = input
            .transcript_path
            .as_deref()
            .filter(|p| std::path::Path::new(p).is_file())
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| transcript_has_polish_run(&t))
            .unwrap_or(false);

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("polish_nudges.jsonl");

        let record = build_polish_nudge_record(
            &common::utc_timestamp(),
            input,
            &common::branch(input.cwd.as_deref()),
            &common::repo_basename(input.cwd.as_deref()),
            polished,
        );

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Single `write_all` of record + newline so concurrent appends from
            // other sessions can't interleave (mirrors log_commit).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// True when the session transcript contains a `cadence-forge:polish` Skill
/// invocation. Pure — operates on the transcript text, no I/O.
///
/// Matches a `tool_use` block whose tool is `Skill` and whose `skill` argument
/// contains `polish`; prose that merely mentions `/polish` (a `text` block) does
/// NOT match — only an actual Skill invocation counts.
fn transcript_has_polish_run(transcript: &str) -> bool {
    transcript.lines().any(line_is_polish_skill_use)
}

/// True when one transcript line is an assistant message containing a `Skill`
/// `tool_use` whose `skill` argument names a polish skill. A line that fails to
/// parse, carries no `message.content` array, or holds only `text`/non-Skill
/// blocks yields `false` — so prose mentioning `/polish` never counts.
fn line_is_polish_skill_use(line: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    let Some(content) = value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    content.iter().any(|block| {
        block.get("type").and_then(Value::as_str) == Some("tool_use")
            && block.get("name").and_then(Value::as_str) == Some("Skill")
            && block
                .get("input")
                .and_then(|i| i.get("skill"))
                .and_then(Value::as_str)
                .is_some_and(|skill| skill.to_ascii_lowercase().contains("polish"))
    })
}

/// Build the `polish_nudges.jsonl` record. Pure — no I/O.
fn build_polish_nudge_record(
    ts: &str,
    input: &MetricsInput,
    branch: &str,
    repo: &str,
    polished: bool,
) -> Value {
    json!({
        "ts": ts,
        "sessionId": input.session_id,
        "transcriptPath": input.transcript_path,
        "branch": branch,
        "repo": repo,
        "polished": polished,
        "agentId": input.agent_id,
        "parentSessionId": input.parent_session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_log_polish_nudge() {
        assert_eq!(LogPolishNudge.name(), "log-polish-nudge");
    }

    fn assistant_line(content: &str) -> String {
        format!(r#"{{"type":"assistant","message":{{"role":"assistant","content":[{content}]}}}}"#)
    }

    #[test]
    fn transcript_with_polish_skill_use_is_detected() {
        let line = assistant_line(
            r#"{"type":"tool_use","name":"Skill","input":{"skill":"cadence-forge:polish"}}"#,
        );
        assert!(
            transcript_has_polish_run(&line),
            "a cadence-forge:polish Skill invocation must be detected"
        );
    }

    #[test]
    fn transcript_with_slash_polish_skill_use_is_detected() {
        // The bare `/polish` form still surfaces as a Skill tool_use whose skill
        // argument contains "polish".
        let line =
            assistant_line(r#"{"type":"tool_use","name":"Skill","input":{"skill":"polish"}}"#);
        assert!(transcript_has_polish_run(&line));
    }

    #[test]
    fn transcript_without_polish_is_not_detected() {
        // A gh pr create Bash call but no polish anywhere → skip candidate.
        let line = assistant_line(
            r#"{"type":"tool_use","name":"Bash","input":{"command":"gh pr create --fill"}}"#,
        );
        assert!(!transcript_has_polish_run(&line));
    }

    #[test]
    fn prose_mentioning_polish_is_not_a_run() {
        // Text that merely talks about /polish is NOT a polish run — only an
        // actual Skill invocation counts. This is the false-positive guard.
        let line = assistant_line(r#"{"type":"text","text":"I will skip /polish here"}"#);
        assert!(!transcript_has_polish_run(&line));
    }

    #[test]
    fn other_skill_is_not_polish() {
        let line = assistant_line(
            r#"{"type":"tool_use","name":"Skill","input":{"skill":"cadence-forge:ship"}}"#,
        );
        assert!(!transcript_has_polish_run(&line));
    }

    #[test]
    fn corrupt_transcript_line_is_skipped() {
        assert!(!transcript_has_polish_run("not json {{\n"));
    }

    fn sample_input() -> MetricsInput {
        MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/tmp/t.jsonl".into()),
            agent_id: Some("a1".into()),
            ..Default::default()
        }
    }

    #[test]
    fn record_has_full_schema() {
        let rec = build_polish_nudge_record(
            "2026-06-21T00:00:00Z",
            &sample_input(),
            "feat/x",
            "myrepo",
            false,
        );
        assert_eq!(rec["ts"], "2026-06-21T00:00:00Z");
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["transcriptPath"], "/tmp/t.jsonl");
        assert_eq!(rec["branch"], "feat/x");
        assert_eq!(rec["repo"], "myrepo");
        assert_eq!(rec["polished"], false);
        assert_eq!(rec["agentId"], "a1");
        // Main-thread field absent → null, not omitted.
        assert!(rec["parentSessionId"].is_null());
    }

    #[test]
    fn record_marks_polished_true() {
        let rec = build_polish_nudge_record("ts", &sample_input(), "feat/x", "myrepo", true);
        assert_eq!(rec["polished"], true);
    }
}
