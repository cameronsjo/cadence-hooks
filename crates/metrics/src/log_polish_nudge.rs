//! `PostToolUse:Bash` — when a polish **ship anchor** runs (`gh pr ready`, a
//! non-draft `gh pr create`, or a bare `gh pr merge`), append one line to
//! `<metrics_dir>/polish_nudges.jsonl` recording the nudge-fire and whether
//! `/polish` ran earlier this session.
//!
//! This is the deterministic denominator for the polish-nudge efficacy
//! measurement (claude-configurations#151): every ship anchor *is* a nudged PR
//! (it fires `nudge-polish-before-pr`), so the same [`polish_ship_anchor`]
//! predicate gates both — a draft create nudges nowhere, so it is logged
//! nowhere either (#297). Each row carries the anchor **kind**, because a
//! draft-first branch now trips `ready` and again at `merge` (#325) and the two
//! rows would otherwise read as two separate ships; dedup on `(repo, branch)`
//! or split by `anchor` before computing a rate. `polished` is a best-effort transcript scan for a
//! `cadence-forge:polish` Skill invocation earlier in the session — a row with
//! `polished: false` is a deterministic *skip candidate*. Distinguishing a
//! rationalized skip from a legitimate one stays a transcript/prose judgment;
//! this logger only makes the rate queryable without re-mining every transcript.
//!
//! Silent no-op on any failure — never blocks (it is a [`Logger`]).

use crate::common;
use cadence_hooks_core::markers::polish_marker_present;
use cadence_hooks_core::shell::polish_ship_anchor;
use cadence_hooks_core::transcript::{
    subagent_transcripts_have_polish_run, transcript_has_polish_run,
};
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
        // gate MUST be the same predicate the nudge uses. The anchor KIND rides
        // along on the row: a draft-first branch now trips `ready` and again at
        // `merge` (#325), and without the kind those two rows read as two
        // separate ships of the same branch.
        let Some(anchor) = polish_ship_anchor(command) else {
            return;
        };
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
        // polish"), never a panic. Scans the parent transcript *and* this
        // session's subagent transcripts, so a delegated polish run is recorded
        // honestly rather than logged as `polished: false` (#247).
        let polished = input
            .transcript_path
            .as_deref()
            .filter(|p| std::path::Path::new(p).is_file())
            .map(|p| {
                let parent_polished = std::fs::read_to_string(p)
                    .map(|t| transcript_has_polish_run(&t))
                    .unwrap_or(false);
                parent_polished || subagent_transcripts_have_polish_run(std::path::Path::new(p))
            })
            .unwrap_or(false);

        // The branch-scoped marker signal the pre-PR gate actually acts on —
        // the same [`polish_marker_present`] the gate calls, so the metric can
        // never disagree with the gate (#177). Recorded alongside `polished`
        // (the transcript scan) so scan-vs-marker drift is measurable.
        let marker_present = polish_marker_present(command, input.cwd.as_deref());

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
            marker_present,
            anchor,
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

/// Build the `polish_nudges.jsonl` record. Pure — no I/O.
fn build_polish_nudge_record(
    ts: &str,
    input: &MetricsInput,
    branch: &str,
    repo: &str,
    polished: bool,
    marker_present: bool,
    anchor: &str,
) -> Value {
    json!({
        "ts": ts,
        "anchor": anchor,
        "sessionId": input.session_id,
        "transcriptPath": input.transcript_path,
        "branch": branch,
        "repo": repo,
        "polished": polished,
        "markerPresent": marker_present,
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
            false,
            "ready",
        );
        assert_eq!(rec["ts"], "2026-06-21T00:00:00Z");
        // The anchor kind is what keeps the ledger interpretable once one
        // branch can trip two anchors (#325) — a row without it cannot be told
        // apart from a second genuine ship of the same branch.
        assert_eq!(rec["anchor"], "ready");
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["transcriptPath"], "/tmp/t.jsonl");
        assert_eq!(rec["branch"], "feat/x");
        assert_eq!(rec["repo"], "myrepo");
        assert_eq!(rec["polished"], false);
        // The branch-scoped marker signal, recorded alongside `polished`.
        assert_eq!(rec["markerPresent"], false);
        assert_eq!(rec["agentId"], "a1");
        // Main-thread field absent → null, not omitted.
        assert!(rec["parentSessionId"].is_null());
    }

    #[test]
    fn record_marks_polished_true() {
        let rec = build_polish_nudge_record(
            "ts",
            &sample_input(),
            "feat/x",
            "myrepo",
            true,
            false,
            "create",
        );
        assert_eq!(rec["polished"], true);
        assert_eq!(rec["markerPresent"], false);
    }

    #[test]
    fn record_marks_marker_present_true() {
        // `markerPresent` serializes both signals independently of `polished`.
        let rec = build_polish_nudge_record(
            "ts",
            &sample_input(),
            "feat/x",
            "myrepo",
            false,
            true,
            "create",
        );
        assert_eq!(rec["markerPresent"], true);
        assert_eq!(rec["polished"], false);
    }
}
