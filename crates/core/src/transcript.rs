//! Session-transcript scanning shared across hooks.
//!
//! Claude Code records each session as an append-only JSONL transcript (one
//! message per line). Hooks that need to know *what already happened this
//! session* — e.g. "did `/polish` run before this `gh pr create`?" — scan that
//! transcript. The detection is deliberately pure (operates on the transcript
//! text, no I/O) so both the fire-and-forget metrics logger and the PreToolUse
//! gate that blocks an evidenced polish-skip share one implementation and one
//! set of tests.

use serde_json::Value;

/// True when the session transcript contains a `cadence-forge:polish` Skill
/// invocation. Pure — operates on the transcript text, no I/O.
///
/// Matches a `tool_use` block whose tool is `Skill` and whose `skill` argument
/// contains `polish`; prose that merely mentions `/polish` (a `text` block) does
/// NOT match — only an actual Skill invocation counts. `.any()` short-circuits
/// on the first match, so a long transcript with an early polish run is cheap.
pub fn transcript_has_polish_run(transcript: &str) -> bool {
    transcript.lines().any(line_is_polish_skill_use)
}

/// True when one transcript line is an assistant message containing a `Skill`
/// `tool_use` whose `skill` argument names a polish skill. A line that fails to
/// parse, carries no `message.content` array, or holds only `text`/non-Skill
/// blocks yields `false` — so prose mentioning `/polish` never counts.
pub(crate) fn line_is_polish_skill_use(line: &str) -> bool {
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
                .is_some_and(is_polish_skill)
    })
}

/// True when a skill id names the polish skill: the bare `polish` form or any
/// `<namespace>:polish` form (e.g. `cadence-forge:polish`), case-insensitive.
/// Matches the id's leaf — the segment after the last `:` — exactly, so a decoy
/// like `writing-polish-notes` that merely *contains* `polish` is rejected. The
/// precision matters now that a spurious match would silently satisfy a gate
/// that drives a hard block.
fn is_polish_skill(skill: &str) -> bool {
    skill
        .rsplit(':')
        .next()
        .is_some_and(|leaf| leaf.eq_ignore_ascii_case("polish"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn decoy_skill_merely_containing_polish_is_not_a_run() {
        // A future skill whose id only *contains* "polish" must NOT satisfy the
        // gate now that detection drives a hard block — only the polish skill's
        // exact leaf does.
        for decoy in [
            "writing-polish-notes",
            "cadence-forge:polish-helper",
            "cadence-forge:repolish",
        ] {
            let line = assistant_line(&format!(
                r#"{{"type":"tool_use","name":"Skill","input":{{"skill":"{decoy}"}}}}"#
            ));
            assert!(
                !transcript_has_polish_run(&line),
                "decoy {decoy:?} must not count as a polish run"
            );
        }
    }

    #[test]
    fn is_polish_skill_matches_leaf_exactly() {
        assert!(is_polish_skill("polish"));
        assert!(is_polish_skill("cadence-forge:polish"));
        assert!(is_polish_skill("Cadence-Forge:POLISH"));
        assert!(!is_polish_skill("writing-polish-notes"));
        assert!(!is_polish_skill("cadence-forge:polish-helper"));
        assert!(!is_polish_skill("cadence-forge:ship"));
    }

    #[test]
    fn corrupt_transcript_line_is_skipped() {
        assert!(!transcript_has_polish_run("not json {{\n"));
    }
}
