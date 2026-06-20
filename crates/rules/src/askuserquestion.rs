//! AskUserQuestion advisory nudges.
//!
//! Two non-blocking checks wired on the `AskUserQuestion` tool:
//! - PreToolUse [`WarnRecommendedOption`]: reminds Claude to label a recommended
//!   option "(Recommended)" and list it first when it has a clear preference.
//! - PostToolUse [`WarnEmptyAnswers`]: detects empty/garbage answers from
//!   auto-approve modes (anthropics/claude-code#29962) and nudges to re-ask as
//!   plain text and wait. Ports the retired `guard-askuserquestion.sh`.
//!
//! Both are nudges (exit 0, additionalContext), never blocks: the
//! "(Recommended)" rule is conditional ("when you have a clear preference"), so
//! a hard block would over-apply to genuinely-equivalent options.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::collections::HashMap;

const RECOMMENDED_MARKER: &str = "(Recommended)";

/// PreToolUse nudge: remind Claude to label a recommended AskUserQuestion option.
pub struct WarnRecommendedOption;

impl Check for WarnRecommendedOption {
    fn name(&self) -> &str {
        "warn-recommended-option"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if input.tool_name() != Some("AskUserQuestion") {
            return CheckResult::allow();
        }
        let Some(questions) = input.ask_questions() else {
            return CheckResult::allow();
        };
        if questions.is_empty() {
            return CheckResult::allow();
        }
        let has_recommended = questions
            .iter()
            .flat_map(|q| q.options.iter().flatten())
            .any(|o| {
                o.label
                    .as_deref()
                    .is_some_and(|l| l.contains(RECOMMENDED_MARKER))
            });
        if has_recommended {
            CheckResult::allow()
        } else {
            CheckResult::nudge(
                "None of these AskUserQuestion options is labeled \"(Recommended)\". \
                 If one option is your clear recommendation, label it \"(Recommended)\" \
                 and list it first so the user can decide faster. If the options are \
                 genuinely equivalent, no change is needed.",
            )
        }
    }
}

/// PostToolUse nudge: re-ask when AskUserQuestion returns empty/garbage answers.
pub struct WarnEmptyAnswers;

impl Check for WarnEmptyAnswers {
    fn name(&self) -> &str {
        "warn-empty-answers"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if input.tool_name() != Some("AskUserQuestion") {
            return CheckResult::allow();
        }
        // Only judge once the tool has run (PostToolUse). A PreToolUse
        // AskUserQuestion payload carries no `tool_response` — not our concern
        // here; the Pre check owns that path. This `tool_response`-presence gate
        // keeps the Post check inert if it ever sees a Pre-shaped payload.
        let Some(response) = input.tool_response.as_ref() else {
            return CheckResult::allow();
        };
        if answers_are_empty_or_garbage(response.answers.as_ref()) {
            CheckResult::nudge(
                "AskUserQuestion returned empty/garbage answers — no human responded. \
                 This is a known auto-approve artifact (anthropics/claude-code#29962). \
                 Do NOT proceed with defaults. Re-ask the same questions as plain text \
                 in your response, then WAIT for the user to reply before continuing.",
            )
        } else {
            CheckResult::allow()
        }
    }
}

/// True when the answers dict is missing, empty, or every value is blank /
/// `.` / `null` / `undefined` (the auto-approve garbage signatures the retired
/// shell guard flagged).
fn answers_are_empty_or_garbage(answers: Option<&HashMap<String, serde_json::Value>>) -> bool {
    match answers {
        None => true,
        // `all` over an empty map is vacuously true — an empty answers dict is
        // itself the garbage signal.
        Some(map) => map.values().all(is_garbage_value),
    }
}

fn is_garbage_value(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => {
            let t = s.trim();
            t.is_empty() || t == "." || t == "null" || t == "undefined"
        }
        // A real structured answer (number/bool/array/object) is not garbage.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{AskOption, AskQuestion, ToolInput, ToolResponse};
    use serde_json::json;

    fn pre_input(option_labels: &[&str]) -> HookInput {
        HookInput {
            tool_name: Some("AskUserQuestion".into()),
            tool_input: Some(ToolInput {
                questions: Some(vec![AskQuestion {
                    question: Some("Which approach?".into()),
                    header: Some("Approach".into()),
                    multi_select: Some(false),
                    options: Some(
                        option_labels
                            .iter()
                            .map(|l| AskOption {
                                label: Some((*l).into()),
                                description: Some("desc".into()),
                            })
                            .collect(),
                    ),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn post_input(answers: Option<HashMap<String, serde_json::Value>>) -> HookInput {
        HookInput {
            tool_name: Some("AskUserQuestion".into()),
            tool_response: Some(ToolResponse {
                answers,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // --- WarnRecommendedOption ---

    #[test]
    fn pre_wrong_tool_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        assert_eq!(
            WarnRecommendedOption.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn pre_no_questions_allows() {
        let input = HookInput {
            tool_name: Some("AskUserQuestion".into()),
            ..Default::default()
        };
        assert_eq!(
            WarnRecommendedOption.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn pre_with_recommended_allows() {
        let input = pre_input(&["Option A (Recommended)", "Option B"]);
        assert_eq!(
            WarnRecommendedOption.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn pre_without_recommended_nudges() {
        let input = pre_input(&["Option A", "Option B"]);
        let result = WarnRecommendedOption.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
        assert!(result.message.unwrap().contains("(Recommended)"));
    }

    #[test]
    fn pre_recommended_in_any_question_allows() {
        // ANY option across ALL questions carrying the marker is enough.
        let input = HookInput {
            tool_name: Some("AskUserQuestion".into()),
            tool_input: Some(ToolInput {
                questions: Some(vec![
                    AskQuestion {
                        options: Some(vec![AskOption {
                            label: Some("Plain".into()),
                            description: None,
                        }]),
                        ..Default::default()
                    },
                    AskQuestion {
                        options: Some(vec![AskOption {
                            label: Some("Best (Recommended)".into()),
                            description: None,
                        }]),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            WarnRecommendedOption.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- WarnEmptyAnswers ---

    #[test]
    fn post_wrong_tool_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        assert_eq!(
            WarnEmptyAnswers.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn post_no_response_allows() {
        // A Pre-shaped AskUserQuestion payload (no tool_response) is inert here.
        let input = HookInput {
            tool_name: Some("AskUserQuestion".into()),
            ..Default::default()
        };
        assert_eq!(
            WarnEmptyAnswers.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn post_real_answers_allow() {
        let mut map = HashMap::new();
        map.insert("Which approach?".to_string(), json!("Option A"));
        assert_eq!(
            WarnEmptyAnswers.run(&post_input(Some(map))).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn post_empty_map_nudges() {
        assert_eq!(
            WarnEmptyAnswers
                .run(&post_input(Some(HashMap::new())))
                .outcome,
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn post_absent_answers_nudges() {
        assert_eq!(
            WarnEmptyAnswers.run(&post_input(None)).outcome,
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn post_all_garbage_values_nudge() {
        for garbage in [
            json!(""),
            json!("   "),
            json!("."),
            json!("null"),
            json!("undefined"),
            json!(null),
        ] {
            let mut map = HashMap::new();
            map.insert("Q?".to_string(), garbage.clone());
            assert_eq!(
                WarnEmptyAnswers.run(&post_input(Some(map))).outcome,
                cadence_hooks_core::Outcome::Nudge,
                "garbage value {garbage:?} should nudge"
            );
        }
    }

    #[test]
    fn post_one_real_answer_among_garbage_allows() {
        let mut map = HashMap::new();
        map.insert("Q1?".to_string(), json!(""));
        map.insert("Q2?".to_string(), json!("Real answer"));
        assert_eq!(
            WarnEmptyAnswers.run(&post_input(Some(map))).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- pure helpers ---

    #[test]
    fn garbage_value_classification() {
        assert!(is_garbage_value(&json!("")));
        assert!(is_garbage_value(&json!("  ")));
        assert!(is_garbage_value(&json!(".")));
        assert!(is_garbage_value(&json!("null")));
        assert!(is_garbage_value(&json!("undefined")));
        assert!(is_garbage_value(&json!(null)));
        assert!(!is_garbage_value(&json!("Option A")));
        assert!(!is_garbage_value(&json!(42)));
        assert!(!is_garbage_value(&json!(true)));
    }
}
