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
//! matches Fable and, on a switch, the session was not already on Fable and the
//! switch is not the model restore a `resume` performs (SessionStart already
//! covers a restored model). Every other case — a non-Fable target, an
//! unmodeled event, an absent `hook_event_name`, a wrong-typed or all-`None`
//! payload — exits 0 with no stdout.
//!
//! There is deliberately **no once-per-day gate**. The Fable-target filter is
//! what bounds the volume: `opusplan` fires `PostModelSwitch` on every
//! plan-mode toggle, but those switches target Opus, not Fable, so they never
//! reach the emitter.

use cadence_hooks_core::{Check, CheckResult, HookEvent, HookInput, model_matches};

/// The one line this hook can emit. A constant — never built from the payload.
pub const FABLE_POSTURE_LINE: &str =
    "Session is on Fable. Load cadence:using-fable before substantive work.";

/// Model tokens that identify the Fable family. Matched case-insensitively as a
/// substring (`cadence_hooks_core::model_matches`), so a canonical id carrying a
/// `[1m]` context-window suffix still matches.
const FABLE_TOKENS: [&str; 1] = ["claude-fable"];

/// The `PostModelSwitch` `source` value for the model Claude Code restores when
/// a session resumes. SessionStart already emits the posture for that model, so
/// the switch half stays quiet on it rather than saying the same thing twice.
const RESUME_SOURCE: &str = "resume";

/// True when the model id names a Fable model.
fn is_fable(model: &str) -> bool {
    model_matches(model, &FABLE_TOKENS)
}

/// Pure emitter: the posture line, or `None` for silence.
///
/// `target` is the model the session is (or has just become) running —
/// `model` on SessionStart, `to_model` on a switch. `from` and `source` are
/// meaningful on `PostModelSwitch` only.
pub fn posture_line(
    event: HookEvent,
    from: Option<&str>,
    target: Option<&str>,
    source: Option<&str>,
) -> Option<&'static str> {
    // No identified target model is silence — the same fail-direction
    // `guard-read-model` takes on an unresolvable model.
    if !target.is_some_and(is_fable) {
        return None;
    }
    match event {
        HookEvent::SessionStart => Some(FABLE_POSTURE_LINE),
        HookEvent::PostModelSwitch => {
            // A resume restores the session's saved model; SessionStart fires
            // for that same session and already carries the posture.
            if source.is_some_and(|s| s.eq_ignore_ascii_case(RESUME_SOURCE)) {
                return None;
            }
            // Already on Fable — the seat did not change.
            if from.is_some_and(is_fable) {
                return None;
            }
            Some(FABLE_POSTURE_LINE)
        }
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
        let (from, target) = match event {
            HookEvent::SessionStart => (None, input.model.as_deref()),
            HookEvent::PostModelSwitch => (input.from_model.as_deref(), input.to_model.as_deref()),
            _ => return CheckResult::allow(),
        };
        match posture_line(event, from, target, input.source.as_deref()) {
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
                Some("command"),
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
                Some("command"),
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
                Some("command"),
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
                Some("command"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn resume_source_is_silent_on_the_switch_half() {
        // SessionStart already emits for a restored model.
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-opus-5"),
                Some("claude-fable-5-1"),
                Some("resume"),
            ),
            None
        );
    }

    #[test]
    fn auto_fallback_onto_fable_emits() {
        // `auto` is a real switch Claude Code made on its own — the seat
        // changed, so the posture is owed.
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("claude-opus-5"),
                Some("claude-fable-5-1"),
                Some("auto"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                Some("CLAUDE-OPUS-5"),
                Some("CLAUDE-FABLE-5-1"),
                Some("command"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn a_missing_from_model_still_emits_onto_fable() {
        // `from_model` absent is not evidence the session was already on Fable.
        assert_eq!(
            posture_line(
                HookEvent::PostModelSwitch,
                None,
                Some("claude-fable-5-1"),
                Some("command"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    // --- posture_line (pure) — the SessionStart half ---

    #[test]
    fn session_start_on_fable_emits() {
        assert_eq!(
            posture_line(
                HookEvent::SessionStart,
                None,
                Some("claude-fable-5-1"),
                Some("startup"),
            ),
            Some(FABLE_POSTURE_LINE)
        );
    }

    #[test]
    fn session_start_on_fable_emits_for_every_trigger() {
        // The SessionStart half has no source filter — `resume` suppression
        // belongs to the switch half alone, and suppressing it here would make
        // a resumed Fable session the one case with no posture at all.
        for source in ["startup", "resume", "clear", "compact"] {
            assert_eq!(
                posture_line(
                    HookEvent::SessionStart,
                    None,
                    Some("claude-fable-5-1"),
                    Some(source),
                ),
                Some(FABLE_POSTURE_LINE),
                "SessionStart source {source:?} must still emit"
            );
        }
    }

    #[test]
    fn session_start_on_opus_is_silent() {
        assert_eq!(
            posture_line(
                HookEvent::SessionStart,
                None,
                Some("claude-opus-5"),
                Some("startup"),
            ),
            None
        );
    }

    // --- posture_line (pure) — the silent floor ---

    #[test]
    fn all_none_is_silent() {
        assert_eq!(
            posture_line(HookEvent::PostModelSwitch, None, None, None),
            None
        );
        assert_eq!(
            posture_line(HookEvent::SessionStart, None, None, None),
            None
        );
    }

    #[test]
    fn an_unrelated_event_is_silent_even_on_fable() {
        assert_eq!(
            posture_line(
                HookEvent::PreToolUse,
                None,
                Some("claude-fable-5-1"),
                Some("command"),
            ),
            None
        );
        assert_eq!(
            posture_line(
                HookEvent::UserPromptSubmit,
                None,
                Some("claude-fable-5-1"),
                Some("command"),
            ),
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
