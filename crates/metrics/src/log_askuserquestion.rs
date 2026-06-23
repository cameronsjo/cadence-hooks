//! `PreToolUse:AskUserQuestion` — append one line to
//! `<metrics_dir>/askuserquestion.jsonl` recording the call's *stance*
//! (recommended / declared-no-rec / silent) and *shape* (multiSelect, question
//! and option counts).
//!
//! This is the diagnostic denominator for claude-configurations#210: it makes
//! "how often does Claude declare a stance vs. stay silent on an
//! AskUserQuestion?" queryable without mining transcripts. Stage 1 ships it
//! pure-observational (no behavior change); the `silent` count — sampled by
//! hand — settles whether a missing "(Recommended)" is an omission or a
//! genuinely-equivalent question. The classifier is shared with the
//! `warn-recommended-option` nudge
//! ([`cadence_hooks_rules::askuserquestion::stance`]) so logger and nudge
//! never drift.
//!
//! Silent no-op on any failure — never blocks (it is a [`Logger`]).

use crate::common;
use cadence_hooks_core::{AskQuestion, Logger, MetricsInput};
use cadence_hooks_rules::askuserquestion::stance;
use serde_json::{Value, json};
use std::io::Write;

/// Appends a stance/shape line to `askuserquestion.jsonl`.
pub struct LogAskUserQuestion;

impl Logger for LogAskUserQuestion {
    fn name(&self) -> &str {
        "log-ask-user-question"
    }

    fn run(&self, input: &MetricsInput) {
        // Only the PreToolUse AskUserQuestion call carries `questions`; every
        // other event no-ops before touching the filesystem.
        let Some(questions) = input
            .tool_input
            .as_ref()
            .and_then(|ti| ti.questions.as_deref())
        else {
            return;
        };
        if questions.is_empty() {
            return;
        }

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("askuserquestion.jsonl");

        let record = build_record(&common::utc_timestamp(), input, questions);

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Single `write_all` of record + newline so concurrent appends from
            // other sessions can't interleave (mirrors log_commit / log_polish_nudge).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Build the `askuserquestion.jsonl` record. Pure — no I/O.
///
/// `multiSelect` is true when *any* question in the call is multi-select;
/// `nOptions` is the total option count across all questions. `model` and
/// `sessionId` are recorded verbatim (null when the payload omits them) — they
/// are JSON values only, never used to build a path, so no sanitizing is needed.
fn build_record(ts: &str, input: &MetricsInput, questions: &[AskQuestion]) -> Value {
    let n_options: usize = questions
        .iter()
        .map(|q| q.options.as_ref().map_or(0, |o| o.len()))
        .sum();
    let multi_select = questions.iter().any(|q| q.multi_select.unwrap_or(false));
    json!({
        "ts": ts,
        "stance": stance(questions).as_str(),
        "multiSelect": multi_select,
        "nQuestions": questions.len(),
        "nOptions": n_options,
        "sessionId": input.session_id,
        "model": input.model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::AskOption;

    fn q(text: &str, labels: &[&str], multi: bool) -> AskQuestion {
        AskQuestion {
            question: Some(text.into()),
            header: Some("H".into()),
            multi_select: Some(multi),
            options: Some(
                labels
                    .iter()
                    .map(|l| AskOption {
                        label: Some((*l).into()),
                        description: None,
                    })
                    .collect(),
            ),
        }
    }

    fn input_with_model(model: Option<&str>) -> MetricsInput {
        MetricsInput {
            session_id: Some("s1".into()),
            model: model.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_ask_user_question() {
        assert_eq!(LogAskUserQuestion.name(), "log-ask-user-question");
    }

    #[test]
    fn record_captures_silent_stance_and_shape() {
        let qs = vec![q("Which approach?", &["A", "B", "C"], false)];
        let rec = build_record(
            "2026-06-22T00:00:00Z",
            &input_with_model(Some("claude-opus-4-8")),
            &qs,
        );
        assert_eq!(rec["ts"], "2026-06-22T00:00:00Z");
        assert_eq!(rec["stance"], "silent");
        assert_eq!(rec["multiSelect"], false);
        assert_eq!(rec["nQuestions"], 1);
        assert_eq!(rec["nOptions"], 3);
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["model"], "claude-opus-4-8");
    }

    #[test]
    fn record_captures_recommended_stance() {
        let qs = vec![q("Which?", &["A (Recommended)", "B"], false)];
        let rec = build_record("ts", &input_with_model(None), &qs);
        assert_eq!(rec["stance"], "recommended");
        // Absent model → null, not omitted.
        assert!(rec["model"].is_null());
    }

    #[test]
    fn record_captures_declared_no_rec_stance() {
        let qs = vec![q("Which? — no clear recommendation", &["A", "B"], false)];
        let rec = build_record("ts", &input_with_model(None), &qs);
        assert_eq!(rec["stance"], "declared_no_rec");
    }

    #[test]
    fn record_sums_options_and_ors_multiselect_across_questions() {
        let qs = vec![
            q("Q1?", &["A", "B"], false),
            q("Q2?", &["C", "D", "E"], true),
        ];
        let rec = build_record("ts", &input_with_model(None), &qs);
        assert_eq!(rec["nQuestions"], 2);
        assert_eq!(rec["nOptions"], 5);
        assert_eq!(rec["multiSelect"], true);
    }
}
