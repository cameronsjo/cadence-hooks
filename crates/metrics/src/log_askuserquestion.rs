//! `AskUserQuestion` — append one line per lifecycle phase to
//! `<metrics_dir>/askuserquestion.jsonl`.
//!
//! Dual-event: one subcommand, one stream, a `phase` discriminator.
//!
//! - `PreToolUse` → `"asked"`: the call's *stance* (recommended /
//!   declared-no-rec / silent) and *shape* (multiSelect, question and option
//!   counts). This is the diagnostic denominator for
//!   claude-configurations#210: it makes "how often does Claude declare a
//!   stance vs. stay silent on an AskUserQuestion?" queryable without mining
//!   transcripts. The stance classifier is shared with the
//!   `warn-recommended-option` nudge
//!   ([`cadence_hooks_rules::askuserquestion::stance`]) so logger and nudge
//!   never drift.
//! - `PostToolUse` → `"answered"`: the user's actual answer per question —
//!   UU-6 (2026-07-08 methodology-coverage blind-spot pass). Without this, the
//!   selected label and any "Other" free-text die with the transcript once the
//!   conversation scrolls past. Per Decision D1-a, answers are logged
//!   **verbatim, unredacted** — this stream's whole value is the user's why,
//!   and it lives in `~/.claude/metrics/`, the same trust domain as the
//!   transcript itself. `matchedRecommended` reuses
//!   [`cadence_hooks_rules::askuserquestion::is_recommended_label`] so the
//!   "did the user pick the recommended option" signal never drifts from the
//!   stance classifier's own marker detection.
//!
//! Both phases stamp `schemaVersion` (`common::ASKUSERQUESTION_SCHEMA_VERSION`).
//! Any other event, or a payload missing the phase-relevant data (no
//! questions on Pre; no answers on Post), no-ops before touching the
//! filesystem — silent, never blocks (it is a [`Logger`]).

use crate::common;
use cadence_hooks_core::{AskQuestion, Logger, MetricsInput};
use cadence_hooks_rules::askuserquestion::{is_recommended_label, stance};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;

/// Appends an `asked`/`answered` line to `askuserquestion.jsonl`.
pub struct LogAskUserQuestion;

impl Logger for LogAskUserQuestion {
    fn name(&self) -> &str {
        "log-ask-user-question"
    }

    fn run(&self, input: &MetricsInput) {
        // `ts`/`debug` are computed only once a record is actually going to be
        // built — every early return above (wrong event, no data) skips them.
        let record = match input.hook_event_name.as_deref() {
            Some("PreToolUse") => {
                let questions = input
                    .tool_input
                    .as_ref()
                    .and_then(|ti| ti.questions.as_deref())
                    .filter(|qs| !qs.is_empty());
                let Some(questions) = questions else {
                    return;
                };
                build_asked_record(&common::utc_timestamp(), input, questions, is_debug())
            }
            Some("PostToolUse") => {
                let answers = input
                    .tool_response
                    .as_ref()
                    .and_then(|tr| tr.answers.as_ref())
                    .filter(|a| !a.is_empty());
                let Some(answers) = answers else {
                    return;
                };
                let questions = input
                    .tool_input
                    .as_ref()
                    .and_then(|ti| ti.questions.as_deref())
                    .unwrap_or(&[]);
                build_answered_record(
                    &common::utc_timestamp(),
                    input,
                    questions,
                    answers,
                    is_debug(),
                )
            }
            _ => return,
        };

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("askuserquestion.jsonl"))
        {
            // Single `write_all` of record + newline so concurrent appends from
            // other sessions can't interleave (mirrors log_commit / log_polish_nudge).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Whether `CADENCE_METRICS_DEBUG` is set, gating the `_keys` debug field.
fn is_debug() -> bool {
    std::env::var("CADENCE_METRICS_DEBUG").as_deref() == Ok("1")
}

/// Build the `"asked"` phase record. Pure — no I/O.
///
/// `multiSelect` is true when *any* question in the call is multi-select;
/// `nOptions` is the total option count across all questions. `model` and
/// `sessionId` are recorded verbatim (null when the payload omits them) — they
/// are JSON values only, never used to build a path, so no sanitizing is needed.
fn build_asked_record(
    ts: &str,
    input: &MetricsInput,
    questions: &[AskQuestion],
    include_keys: bool,
) -> Value {
    let n_options: usize = questions
        .iter()
        .map(|q| q.options.as_ref().map_or(0, |o| o.len()))
        .sum();
    let multi_select = questions.iter().any(|q| q.multi_select.unwrap_or(false));
    let mut record = json!({
        "schemaVersion": common::ASKUSERQUESTION_SCHEMA_VERSION,
        "ts": ts,
        "phase": "asked",
        "stance": stance(questions).as_str(),
        "multiSelect": multi_select,
        "nQuestions": questions.len(),
        "nOptions": n_options,
        "sessionId": input.session_id,
        "model": input.model,
    });
    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }
    record
}

/// Whether `answer_str` actually *selects* the question's recommended option —
/// not just whether the raw string happens to contain the marker.
///
/// Splits `answer_str` on `", "` (multiSelect answers are comma-joined per
/// [`cadence_hooks_core::ToolResponse::answers`]'s doc contract) and checks
/// each selected piece against `question`'s own option labels, flagging a
/// match only when the SELECTED label is itself marked `(Recommended)`. A
/// plain substring check on the whole answer string would false-positive on
/// "Other" free-text that happens to mention the phrase (e.g. "not the
/// (Recommended) one, do X instead") and can't correctly handle a
/// multi-select pick that includes some but not all recommended options.
/// `false` when `question` is `None` (a payload-shape drift already noted by
/// the `header: null` fallback) — no options to check against.
fn answer_matches_recommended(question: Option<&AskQuestion>, answer_str: &str) -> bool {
    let Some(options) = question.and_then(|q| q.options.as_ref()) else {
        return false;
    };
    answer_str.split(", ").any(|selected| {
        options
            .iter()
            .any(|o| o.label.as_deref() == Some(selected) && is_recommended_label(selected))
    })
}

/// Build the `"answered"` phase record. Pure — no I/O.
///
/// Per D1-a, `answer` is the verbatim selected-label (or "Other" free-text)
/// string the platform hands back in `tool_response.answers` — no redaction,
/// no hashing. `header` is recovered by joining `answers` (keyed by the full
/// question text) against `questions` (which still carries the original
/// `question`/`header` pair on the PostToolUse payload); a question whose text
/// can't be matched — a payload-shape drift, not the common case — falls back
/// to `null` rather than dropping the answer. `matchedRecommended` is `false`
/// for a `null`/non-string answer (an unanswered or malformed entry can't have
/// matched anything).
///
/// `answers` entries are sorted by question text before building the array —
/// `HashMap` iteration order is randomized per-process, so without this the
/// row's `answers` array would be a different order on every invocation for
/// the same logical data. (A call with two questions sharing identical text
/// would already have collapsed to one entry upstream, in the platform's own
/// `tool_response.answers` map — not something this join can recover.)
fn build_answered_record(
    ts: &str,
    input: &MetricsInput,
    questions: &[AskQuestion],
    answers: &HashMap<String, Value>,
    include_keys: bool,
) -> Value {
    let question_for = |question_text: &str| -> Option<&AskQuestion> {
        questions
            .iter()
            .find(|q| q.question.as_deref() == Some(question_text))
    };

    let mut sorted_answers: Vec<(&String, &Value)> = answers.iter().collect();
    sorted_answers.sort_by_key(|(a, _)| *a);

    let answered: Vec<Value> = sorted_answers
        .into_iter()
        .map(|(question_text, answer)| {
            let question = question_for(question_text);
            let matched_recommended = answer
                .as_str()
                .is_some_and(|s| answer_matches_recommended(question, s));
            json!({
                "header": question.and_then(|q| q.header.clone()),
                "answer": answer,
                "matchedRecommended": matched_recommended,
            })
        })
        .collect();

    let mut record = json!({
        "schemaVersion": common::ASKUSERQUESTION_SCHEMA_VERSION,
        "ts": ts,
        "phase": "answered",
        "sessionId": input.session_id,
        "model": input.model,
        "answers": answered,
    });
    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{AskOption, ToolInput, ToolResponse};

    fn q(text: &str, header: &str, labels: &[&str], multi: bool) -> AskQuestion {
        AskQuestion {
            question: Some(text.into()),
            header: Some(header.into()),
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

    fn pre_input(questions: Vec<AskQuestion>) -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("PreToolUse".into()),
            session_id: Some("s1".into()),
            tool_input: Some(ToolInput {
                questions: Some(questions),
                ..Default::default()
            }),
            raw_keys: vec!["hook_event_name".into(), "tool_input".into()],
            ..Default::default()
        }
    }

    fn post_input(questions: Vec<AskQuestion>, answers: HashMap<String, Value>) -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("PostToolUse".into()),
            session_id: Some("s1".into()),
            tool_input: Some(ToolInput {
                questions: Some(questions),
                ..Default::default()
            }),
            tool_response: Some(ToolResponse {
                answers: Some(answers),
                ..Default::default()
            }),
            raw_keys: vec!["hook_event_name".into(), "tool_response".into()],
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_ask_user_question() {
        assert_eq!(LogAskUserQuestion.name(), "log-ask-user-question");
    }

    // --- run(): event/data gating (no-ops must never touch the filesystem) ---

    /// Run `f` with `CADENCE_METRICS_DIR` pointed at a fresh empty tempdir, then
    /// assert `askuserquestion.jsonl` was never created — a no-op that silently
    /// wrote the file would otherwise pass with no assertion at all.
    fn assert_noop(f: impl FnOnce()) {
        let _guard = common::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by ENV_LOCK; no other thread reads/writes
        // CADENCE_METRICS_DIR while this guard is held.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", tmp.path());
        }
        f();
        assert!(
            !tmp.path().join("askuserquestion.jsonl").exists(),
            "no-op run must never create askuserquestion.jsonl"
        );
        // SAFETY: same ENV_LOCK guard as the set above.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    #[test]
    fn wrong_hook_event_is_noop() {
        let input = MetricsInput {
            hook_event_name: Some("SessionStart".into()),
            tool_input: Some(ToolInput {
                questions: Some(vec![q("Q?", "H", &["A"], false)]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_noop(|| LogAskUserQuestion.run(&input));
    }

    #[test]
    fn pre_without_questions_is_noop() {
        assert_noop(|| {
            LogAskUserQuestion.run(&pre_input(vec![]));
            LogAskUserQuestion.run(&MetricsInput {
                hook_event_name: Some("PreToolUse".into()),
                ..Default::default()
            });
        });
    }

    #[test]
    fn post_without_answers_is_noop() {
        assert_noop(|| {
            LogAskUserQuestion.run(&post_input(vec![], HashMap::new()));
            LogAskUserQuestion.run(&MetricsInput {
                hook_event_name: Some("PostToolUse".into()),
                ..Default::default()
            });
        });
    }

    // --- "asked" phase (unchanged behavior + phase/schemaVersion) ---

    #[test]
    fn asked_record_carries_phase_and_schema_version() {
        let qs = vec![q("Which approach?", "Approach", &["A", "B", "C"], false)];
        let rec = build_asked_record(
            "2026-06-22T00:00:00Z",
            &input_with_model(Some("claude-opus-4-8")),
            &qs,
            false,
        );
        assert_eq!(rec["schemaVersion"], common::ASKUSERQUESTION_SCHEMA_VERSION);
        assert_eq!(rec["phase"], "asked");
        assert_eq!(rec["ts"], "2026-06-22T00:00:00Z");
        assert_eq!(rec["stance"], "silent");
        assert_eq!(rec["multiSelect"], false);
        assert_eq!(rec["nQuestions"], 1);
        assert_eq!(rec["nOptions"], 3);
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["model"], "claude-opus-4-8");
    }

    #[test]
    fn asked_record_captures_recommended_stance() {
        let qs = vec![q("Which?", "H", &["A (Recommended)", "B"], false)];
        let rec = build_asked_record("ts", &input_with_model(None), &qs, false);
        assert_eq!(rec["stance"], "recommended");
        // Absent model → null, not omitted.
        assert!(rec["model"].is_null());
    }

    #[test]
    fn asked_record_captures_declared_no_rec_stance() {
        let qs = vec![q(
            "Which? — no clear recommendation",
            "H",
            &["A", "B"],
            false,
        )];
        let rec = build_asked_record("ts", &input_with_model(None), &qs, false);
        assert_eq!(rec["stance"], "declared_no_rec");
    }

    #[test]
    fn asked_record_sums_options_and_ors_multiselect_across_questions() {
        let qs = vec![
            q("Q1?", "H1", &["A", "B"], false),
            q("Q2?", "H2", &["C", "D", "E"], true),
        ];
        let rec = build_asked_record("ts", &input_with_model(None), &qs, false);
        assert_eq!(rec["nQuestions"], 2);
        assert_eq!(rec["nOptions"], 5);
        assert_eq!(rec["multiSelect"], true);
    }

    #[test]
    fn asked_debug_adds_keys() {
        let qs = vec![q("Q?", "H", &["A"], false)];
        let input = MetricsInput {
            raw_keys: vec!["tool_input".into()],
            ..input_with_model(None)
        };
        let rec = build_asked_record("ts", &input, &qs, true);
        let keys = rec["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("tool_input")));
    }

    // --- "answered" phase ---

    #[test]
    fn answered_record_carries_phase_schema_and_header() {
        let qs = vec![q(
            "Which approach?",
            "Approach",
            &["Alpha (Recommended)", "Beta"],
            false,
        )];
        let mut answers = HashMap::new();
        answers.insert("Which approach?".to_string(), json!("Alpha (Recommended)"));
        let rec = build_answered_record(
            "2026-07-09T00:00:00Z",
            &input_with_model(Some("claude-opus-4-8")),
            &qs,
            &answers,
            false,
        );
        assert_eq!(rec["schemaVersion"], common::ASKUSERQUESTION_SCHEMA_VERSION);
        assert_eq!(rec["phase"], "answered");
        assert_eq!(rec["ts"], "2026-07-09T00:00:00Z");
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["model"], "claude-opus-4-8");
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered.len(), 1);
        assert_eq!(answered[0]["header"], "Approach");
        assert_eq!(answered[0]["answer"], "Alpha (Recommended)");
        assert_eq!(answered[0]["matchedRecommended"], true);
    }

    #[test]
    fn answered_record_flags_non_recommended_selection() {
        let qs = vec![q(
            "Which approach?",
            "Approach",
            &["Alpha (Recommended)", "Beta"],
            false,
        )];
        let mut answers = HashMap::new();
        answers.insert("Which approach?".to_string(), json!("Beta"));
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered[0]["matchedRecommended"], false);
    }

    #[test]
    fn answered_record_orders_deterministically_by_question_text() {
        // HashMap iteration order is randomized per-process; the answers array
        // must be reproducible across runs for the same logical data.
        let qs = vec![
            q("Zeta question?", "Z", &["A"], false),
            q("Alpha question?", "A", &["A"], false),
            q("Mid question?", "M", &["A"], false),
        ];
        let mut answers = HashMap::new();
        answers.insert("Zeta question?".to_string(), json!("z"));
        answers.insert("Alpha question?".to_string(), json!("a"));
        answers.insert("Mid question?".to_string(), json!("m"));

        let rec1 = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let rec2 = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        assert_eq!(rec1, rec2, "identical input must serialize identically");

        let headers: Vec<&str> = rec1["answers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["header"].as_str().unwrap())
            .collect();
        // Sorted by question text ("Alpha" < "Mid" < "Zeta"), not insertion order.
        assert_eq!(headers, vec!["A", "M", "Z"]);
    }

    #[test]
    fn answered_record_logs_free_text_verbatim() {
        // D1-a: "Other"/free-text answers are logged verbatim, unredacted —
        // this is the irreplaceable user intent the whole stream exists for.
        let qs = vec![q("Pick one", "Pick", &["A (Recommended)", "B"], false)];
        let mut answers = HashMap::new();
        answers.insert(
            "Pick one".to_string(),
            json!("Neither — do X instead because Y"),
        );
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered[0]["answer"], "Neither — do X instead because Y");
        assert_eq!(answered[0]["matchedRecommended"], false);
    }

    #[test]
    fn answered_record_free_text_mentioning_recommended_marker_is_not_matched() {
        // A "(Recommended)" substring inside free-text prose must NOT flag
        // matchedRecommended — only an actual selected option label counts.
        let qs = vec![q(
            "Pick one",
            "Pick",
            &["Alpha (Recommended)", "Beta"],
            false,
        )];
        let mut answers = HashMap::new();
        answers.insert(
            "Pick one".to_string(),
            json!("Not the (Recommended) one, do Gamma instead"),
        );
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered[0]["matchedRecommended"], false);
    }

    #[test]
    fn answered_record_multiselect_matches_when_a_recommended_option_is_selected() {
        let qs = vec![q(
            "Pick some",
            "Pick",
            &["Alpha", "Beta", "Gamma (Recommended)"],
            true,
        )];
        let mut answers = HashMap::new();
        answers.insert("Pick some".to_string(), json!("Beta, Gamma (Recommended)"));
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered[0]["matchedRecommended"], true);
    }

    #[test]
    fn answered_record_multiselect_without_recommended_pick_is_not_matched() {
        let qs = vec![q(
            "Pick some",
            "Pick",
            &["Alpha", "Beta", "Gamma (Recommended)"],
            true,
        )];
        let mut answers = HashMap::new();
        answers.insert("Pick some".to_string(), json!("Alpha, Beta"));
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert_eq!(answered[0]["matchedRecommended"], false);
    }

    #[test]
    fn answered_record_null_answer_is_not_matched_recommended() {
        let qs = vec![q("Pick one", "Pick", &["A"], false)];
        let mut answers = HashMap::new();
        answers.insert("Pick one".to_string(), Value::Null);
        let rec = build_answered_record("ts", &input_with_model(None), &qs, &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert!(answered[0]["answer"].is_null());
        assert_eq!(answered[0]["matchedRecommended"], false);
    }

    #[test]
    fn answered_record_unmatched_question_text_falls_back_to_null_header() {
        // Defensive: a header lookup that can't join back to `questions` (a
        // payload-shape drift) must not drop the answer, just its header.
        let mut answers = HashMap::new();
        answers.insert("Some question?".to_string(), json!("An answer"));
        let rec = build_answered_record("ts", &input_with_model(None), &[], &answers, false);
        let answered = rec["answers"].as_array().unwrap();
        assert!(answered[0]["header"].is_null());
        assert_eq!(answered[0]["answer"], "An answer");
    }

    #[test]
    fn answered_debug_adds_keys() {
        let mut answers = HashMap::new();
        answers.insert("Q?".to_string(), json!("A"));
        let input = MetricsInput {
            raw_keys: vec!["tool_response".into()],
            ..input_with_model(None)
        };
        let rec = build_answered_record("ts", &input, &[], &answers, true);
        let keys = rec["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("tool_response")));
    }

    // --- serialization ---

    #[test]
    fn asked_record_serializes_to_single_line() {
        let qs = vec![q("Q?", "H", &["A"], false)];
        let line = build_asked_record("ts", &input_with_model(None), &qs, true).to_string();
        assert!(!line.contains('\n'), "record must be one line: {line}");
    }

    #[test]
    fn answered_record_serializes_to_single_line() {
        let mut answers = HashMap::new();
        answers.insert("Q?".to_string(), json!("A"));
        let line =
            build_answered_record("ts", &input_with_model(None), &[], &answers, true).to_string();
        assert!(!line.contains('\n'), "record must be one line: {line}");
    }

    // --- run(): end-to-end via a temp metrics dir ---

    #[test]
    fn run_pre_then_post_appends_both_phases() {
        let _guard = common::ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by ENV_LOCK; no other thread reads/writes
        // CADENCE_METRICS_DIR while this guard is held.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", tmp.path());
        }

        let make_qs = || {
            vec![q(
                "Which approach?",
                "Approach",
                &["Alpha (Recommended)", "Beta"],
                false,
            )]
        };
        LogAskUserQuestion.run(&pre_input(make_qs()));
        let mut answers = HashMap::new();
        answers.insert("Which approach?".to_string(), json!("Alpha (Recommended)"));
        LogAskUserQuestion.run(&post_input(make_qs(), answers));

        let contents = std::fs::read_to_string(tmp.path().join("askuserquestion.jsonl")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected one asked + one answered line");
        let asked: Value = serde_json::from_str(lines[0]).unwrap();
        let answered: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(asked["phase"], "asked");
        assert_eq!(answered["phase"], "answered");

        // SAFETY: same ENV_LOCK guard as the set above.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }
}
