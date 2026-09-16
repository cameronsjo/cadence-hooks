//! `cadence model-posture` — inject the Fable seat posture when the session's
//! model is (or becomes) Fable.
//!
//! One subcommand, two halves, picked from the payload's `hook_event_name`:
//!
//! - **SessionStart** reads the `model` field Claude Code sends with the
//!   session's starting model.
//! - **PostModelSwitch** reads `to_model` (the model the session switched to)
//!   and `from_model` (the one it left).
//!
//! It emits one constant line and nothing else. No payload value is ever
//! interpolated into the output, so a crafted `to_model` cannot smuggle text
//! into Claude's context through this hook — the payload can only decide
//! *whether* the fixed line is emitted.
//!
//! **Silence is the default.** The line is emitted only when the target model
//! matches Fable and, on a switch, the session was not already on Fable. Every
//! other case — a non-Fable target, an unmodeled event, an absent
//! `hook_event_name`, a wrong-typed or all-`None` payload — exits 0 with no
//! stdout.
//!
//! **The switch half does not suppress a `resume` restore**, even though
//! SessionStart fires for the same session. It would be suppressing the one
//! case where SessionStart is least able to cover it: `model` is documented as
//! optional and "can be omitted, for example after `/clear` or when a session
//! is restored through conversation recovery" (live hooks doc, SessionStart
//! input, read 2026-09-15). The trade is one duplicated line against the
//! feature going silent on exactly the sessions it exists for, which is not a
//! trade worth taking for a nudge that costs one line of context.
//!
//! There is deliberately **no once-per-day gate**. The Fable-target filter is
//! what bounds the volume: `opusplan` fires `PostModelSwitch` on every
//! plan-mode toggle, but it targets Opus in plan mode and Sonnet outside it, so
//! neither direction reaches the emitter.
//!
//! The emitted *content* is one constant; the emitted *length* is not bounded
//! here. A payload carrying several normalized targets (an `apply_patch` body,
//! a rename) has its per-target results joined by the dispatch layer, so the
//! line would repeat. Neither wired event carries a `tool_input`, so this is
//! unreachable in practice — and it is the shared behavior of every nudge
//! check, not something this hook introduces.

use cadence_hooks_core::{Check, CheckResult, HookEvent, HookInput, model_matches};

/// The one line this hook can emit. A constant — never built from the payload.
pub const FABLE_POSTURE_LINE: &str =
    "Session is on Fable. Load cadence:using-fable before substantive work.";

/// Model tokens that identify the Fable family. Matched case-insensitively as a
/// substring (`cadence_hooks_core::model_matches`), so a canonical id carrying a
/// `[1m]` context-window suffix still matches.
const FABLE_TOKENS: [&str; 1] = ["claude-fable"];

/// True when the model id names a Fable model.
fn is_fable(model: &str) -> bool {
    model_matches(model, &FABLE_TOKENS)
}

/// Pure emitter: the posture line, or `None` for silence.
///
/// `target` is the model the session is (or has just become) running —
/// `model` on SessionStart, `to_model` on a switch. `from` is meaningful on
/// `PostModelSwitch` only.
///
/// No `source` parameter: neither half filters on it. See the module docs for
/// why the switch half does not suppress a `resume` restore.
pub fn posture_line(
    event: HookEvent,
    from: Option<&str>,
    target: Option<&str>,
) -> Option<&'static str> {
    // No identified target model is silence — the same fail-direction
    // `guard-read-model` takes on an unresolvable model.
    if !target.is_some_and(is_fable) {
        return None;
    }
    match event {
        HookEvent::SessionStart => Some(FABLE_POSTURE_LINE),
        // Already on Fable — the seat did not change.
        HookEvent::PostModelSwitch if from.is_some_and(is_fable) => None,
        HookEvent::PostModelSwitch => Some(FABLE_POSTURE_LINE),
        HookEvent::PreToolUse | HookEvent::PostToolUse | HookEvent::UserPromptSubmit => None,
    }
}

/// Inject the Fable seat posture at session start and on a switch onto Fable.
pub struct ModelPosture;

impl Check for ModelPosture {
    fn name(&self) -> &str {
        "model-posture"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // An unmodeled or absent event is silence, never a defaulted half: the
        // emitted envelope names the event, so guessing it wrong would ship a
        // mismatched `hookEventName`.
        let Some(event) = input
            .hook_event_name
            .as_deref()
            .and_then(HookEvent::from_name)
        else {
            return CheckResult::allow();
        };
        // Exhaustive on purpose: a new `HookEvent` variant must break the build
        // here and force a decision, rather than being absorbed by a wildcard.
        let (from, target) = match event {
            HookEvent::SessionStart => (None, input.model.as_deref()),
            HookEvent::PostModelSwitch => (input.from_model.as_deref(), input.to_model.as_deref()),
            HookEvent::PreToolUse | HookEvent::PostToolUse | HookEvent::UserPromptSubmit => {
                return CheckResult::allow();
            }
        };
        match posture_line(event, from, target) {
            Some(line) => CheckResult::nudge(line.to_string()),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    fn switch(from: Option<&str>, to: Option<&str>, source: Option<&str>) -> HookInput {
        HookInput {
            hook_event_name: Some("PostModelSwitch".into()),
            from_model: from.map(str::to_string),
            to_model: to.map(str::to_string),
            source: source.map(str::to_string),
            ..Default::default()
        }
    }

    fn session_start(model: Option<&str>) -> HookInput {
        HookInput {
            hook_event_name: Some("SessionStart".into()),
            source: Some("startup".into()),
            model: model.map(str::to_string),
            ..Default::default()
        }
    }

    // --- posture_line (pure) — the switch half ---

    #[test]
    fn switch_onto_fable_from_opus_emits() {
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-opus-5"),
                Some("claude-fable-5-1"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn switch_away_from_fable_is_silent() {
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-fable-5-1"),
                Some("claude-opus-5"),
            ),
            None
        );
    }

    #[test]
    fn switch_fable_to_fable_is_silent() {
        // Already on Fable — an `opusplan`-style toggle between two Fable ids
        // must not repeat the posture.
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-fable-5-1"),
                Some("claude-fable-5-1[1m]"),
            ),
            None
        );
    }

    #[test]
    fn the_one_megacontext_suffix_is_tolerated_on_both_sides() {
        // The matcher strips `[1m]` before comparing; the raw payload value
        // does not, so the emitter must tolerate it wherever it appears.
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-opus-5[1m]"),
                Some("claude-fable-5-1[1m]"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn no_switch_source_suppresses_the_posture() {
        // `source` does not gate either half. `resume` is the load-bearing row:
        // suppressing it would hand the whole feature to SessionStart, whose
        // `model` field is documented as optional and omitted "after `/clear`
        // or when a session is restored through conversation recovery" — the
        // sessions this hook most exists for. `auto` is a real fallback the
        // harness performed, so the seat changed and the posture is owed.
        for source in ["command", "picker", "sdk", "auto", "resume"] {
            let result = ModelPosture.run(&switch(
                Some("claude-opus-5"),
                Some("claude-fable-5-1"),
                Some(source),
            ));
            assert_eq!(
                result.message.as_deref(),
                Some(FABLE_POSTURE_LINE),
                "PostModelSwitch source {source:?} must still emit"
            );
        }
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("CLAUDE-OPUS-5"),
                Some("CLAUDE-FABLE-5-1"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn a_missing_from_model_still_emits_onto_fable() {
        // `from_model` absent is not evidence the session was already on Fable.
        assert_eq!(
            posture_line(HookEvent::PostModelSwitch, None, Some("claude-fable-5-1"),),
            Some(FABLE_POSTURE_LINE)
        );
    }

    // --- posture_line (pure) — the SessionStart half ---

    #[test]
    fn session_start_on_fable_emits() {
        assert_eq!(
            posture_line(HookEvent::SessionStart, None, Some("claude-fable-5-1"),),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn session_start_on_fable_emits_for_every_trigger() {
        // Every documented SessionStart trigger, `fork` included (2.1.214+,
        // which reported `resume` before that). None of them gates the posture.
        for source in ["startup", "resume", "clear", "compact", "fork"] {
            let input = HookInput {
                source: Some(source.into()),
                ..session_start(Some("claude-fable-5-1"))
            };
            assert_eq!(
                ModelPosture.run(&input).message.as_deref(),
                Some(FABLE_POSTURE_LINE),
                "SessionStart source {source:?} must still emit"
            );
        }
    }

    #[test]
    fn session_start_on_opus_is_silent() {
        assert_eq!(
            posture_line(HookEvent::SessionStart, None, Some("claude-opus-5"),),
            None
        );
    }

    // --- posture_line (pure) — the silent floor ---

    #[test]
    fn all_none_is_silent() {
        assert_eq!(posture_line(HookEvent::PostModelSwitch, None, None), None);
        assert_eq!(posture_line(HookEvent::SessionStart, None, None), None);
    }

    #[test]
    fn an_unrelated_event_is_silent_even_on_fable() {
        assert_eq!(
            posture_line(HookEvent::PreToolUse, None, Some("claude-fable-5-1"),),
            None
        );
        assert_eq!(
            posture_line(HookEvent::UserPromptSubmit, None, Some("claude-fable-5-1"),),
            None
        );
    }

    // --- Check::run — event routing from the payload ---

    #[test]
    fn run_switch_onto_fable_nudges_with_the_constant_line() {
        let result = ModelPosture.run(&switch(
            Some("claude-opus-5"),
            Some("claude-fable-5-1"),
            Some("command"),
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert_eq!(result.message.as_deref(), Some(FABLE_POSTURE_LINE));
    }

    #[test]
    fn run_reversed_switch_allows_silently() {
        let result = ModelPosture.run(&switch(
            Some("claude-fable-5-1"),
            Some("claude-opus-5"),
            Some("command"),
        ));
        assert_eq!(result.outcome, Outcome::Allow);
        assert_eq!(result.message, None);
    }

    #[test]
    fn run_session_start_on_fable_nudges() {
        let result = ModelPosture.run(&session_start(Some("claude-fable-5-1")));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert_eq!(result.message.as_deref(), Some(FABLE_POSTURE_LINE));
    }

    #[test]
    fn run_reads_the_session_start_model_field_not_to_model() {
        // A SessionStart payload carrying a stray `to_model` must not be read
        // as a switch — the halves are picked by event, not by field presence.
        let input = HookInput {
            hook_event_name: Some("SessionStart".into()),
            model: Some("claude-opus-5".into()),
            to_model: Some("claude-fable-5-1".into()),
            ..Default::default()
        };
        assert_eq!(ModelPosture.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_without_a_hook_event_name_allows() {
        let input = HookInput {
            to_model: Some("claude-fable-5-1".into()),
            model: Some("claude-fable-5-1".into()),
            ..Default::default()
        };
        assert_eq!(ModelPosture.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_with_an_unmodeled_event_allows() {
        let input = HookInput {
            hook_event_name: Some("PreModelSwitch".into()),
            from_model: Some("claude-opus-5".into()),
            to_model: Some("claude-fable-5-1".into()),
            ..Default::default()
        };
        assert_eq!(ModelPosture.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_on_an_empty_payload_allows() {
        assert_eq!(
            ModelPosture.run(&HookInput::default()).outcome,
            Outcome::Allow
        );
    }

    // --- payload parsing: lenient by construction ---

    #[test]
    fn a_wrong_typed_model_field_degrades_to_silence_not_a_parse_error() {
        // `lenient_option` turns a wrong-typed `to_model` into `None` rather
        // than failing the whole parse, so the hook stays silent instead of
        // taking the fail-open parse-error path.
        let input: HookInput = serde_json::from_str(
            r#"{"hook_event_name":"PostModelSwitch","from_model":"claude-opus-5","to_model":{"id":"claude-fable-5-1"},"source":"command"}"#,
        )
        .expect("a wrong-typed to_model must not fail the parse");
        assert_eq!(input.to_model, None);
        assert_eq!(ModelPosture.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn a_real_switch_payload_parses_into_the_modeled_fields() {
        let input: HookInput = serde_json::from_str(
            r#"{"session_id":"abc123","cwd":"/tmp","hook_event_name":"PostModelSwitch","from_model":"claude-opus-5","to_model":"claude-fable-5-1","requested_model":"fable","source":"command","context_tokens":182340,"prompt_cache_warm":true,"cache_ttl":"5m","estimated_cache_write_usd":1.1396,"pricing":"catalog"}"#,
        )
        .expect("the documented PostModelSwitch payload must parse");
        assert_eq!(input.from_model.as_deref(), Some("claude-opus-5"));
        assert_eq!(input.to_model.as_deref(), Some("claude-fable-5-1"));
        assert_eq!(input.source.as_deref(), Some("command"));
        assert_eq!(ModelPosture.run(&input).outcome, Outcome::Nudge);
    }
}
