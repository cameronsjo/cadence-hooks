//! Session-transcript scanning shared across hooks.
//!
//! Claude Code records each session as an append-only JSONL transcript (one
//! message per line). Hooks that need to know *what already happened this
//! session* — e.g. "did `/polish` run before this `gh pr create`?" — scan that
//! transcript. The detection is deliberately pure (operates on the transcript
//! text, no I/O) so both the fire-and-forget metrics logger and the PreToolUse
//! gate that blocks an evidenced polish-skip share one implementation and one
//! set of tests.

use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Minimal transcript-line shape for model resolution. Only the fields
/// [`last_assistant_model`] needs are deserialized; every other key is ignored.
/// Deliberately local (not shared with `metrics::scan_tokens`) so the guardrails
/// path carries no `metrics` dependency — see the reference implementation
/// `metrics::scan_tokens::scan_tokens`, which resolves the same last-assistant
/// model as a side effect of token accounting.
#[derive(Deserialize)]
struct ModelLine {
    message: Option<ModelMessage>,
}

#[derive(Deserialize)]
struct ModelMessage {
    role: Option<String>,
    model: Option<String>,
}

/// The model id of the *last* assistant message in a session transcript, or
/// `None` when no assistant message carries a non-empty `model`.
///
/// Scans lines from the tail (`.lines().rev()`) and returns the first that
/// parses as a message with `role == "assistant"` and a non-empty `model` —
/// so the newest model wins and a short transcript with a late model is cheap.
/// Corrupt lines, non-assistant messages, and assistant messages without a
/// model are skipped, never fatal. Pure — operates on the transcript text, no
/// I/O.
///
/// Reference implementation: `metrics::scan_tokens::scan_tokens` resolves the
/// same last-assistant model while accounting tokens; this is the minimal,
/// dependency-free variant the read-model guard needs.
pub fn last_assistant_model(transcript: &str) -> Option<String> {
    transcript.lines().rev().find_map(|line| {
        let parsed = serde_json::from_str::<ModelLine>(line).ok()?;
        let message = parsed.message?;
        if message.role.as_deref() != Some("assistant") {
            return None;
        }
        message.model.filter(|m| !m.is_empty())
    })
}

/// Minimal transcript-line shape for harness-version resolution: the
/// top-level `version` field (the harness build string, e.g. `"2.1.214"`)
/// alongside the nested `message.role` needed to scope the scan to assistant
/// lines. Deliberately separate from [`ModelLine`] — `version` lives at the
/// line's top level while `model` lives nested under `message`, so one
/// shared struct would carry a dead field on every deserialize.
#[derive(Deserialize)]
struct HarnessVersionLine {
    version: Option<String>,
    message: Option<AssistantRole>,
}

#[derive(Deserialize)]
struct AssistantRole {
    role: Option<String>,
}

/// The harness build version (e.g. `"2.1.214"`) stamped on the top-level
/// `version` field of the *last* assistant message in a session transcript,
/// or `None` when no assistant line carries a non-empty `version`.
///
/// Mirrors [`last_assistant_model`]'s tail-scan discipline exactly, reading
/// the sibling top-level field instead of the nested `message.model` one —
/// see that function's docs for the scan/skip semantics. Pure — operates on
/// the transcript text, no I/O.
pub fn last_assistant_harness_version(transcript: &str) -> Option<String> {
    transcript.lines().rev().find_map(|line| {
        let parsed = serde_json::from_str::<HarnessVersionLine>(line).ok()?;
        let message = parsed.message?;
        if message.role.as_deref() != Some("assistant") {
            return None;
        }
        parsed.version.filter(|v| !v.is_empty())
    })
}

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

/// True when any child subagent transcript under
/// `<parent-stem>/subagents/agent-*.jsonl` shows a polish Skill run.
///
/// Claude Code records a subagent's transcript next to the parent's: a parent
/// `<dir>/<session>.jsonl` has its children at `<dir>/<session>/subagents/`.
/// Polish invoked *inside* a delegated session therefore lives in a child file
/// the parent-only [`transcript_has_polish_run`] never reads — this scans those
/// children so a delegated polish run still satisfies the pre-PR gate (#247).
///
/// Fail-safe at every step: a missing `subagents/` dir, no children, or an
/// unreadable child all yield `false`, so the caller falls through to the
/// existing parent-transcript decision (ADR-0001 — never block on our own
/// missing data). Never panics. `.any()` short-circuits on the first child that
/// shows a polish run.
pub fn subagent_transcripts_have_polish_run(parent_transcript_path: &Path) -> bool {
    let Some(dir) = subagents_dir(parent_transcript_path) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        is_agent_transcript(&path)
            && std::fs::read_to_string(&path)
                .map(|c| transcript_has_polish_run(&c))
                .unwrap_or(false)
    })
}

/// The `subagents/` directory a parent transcript's children live in:
/// `<parent-dir>/<parent-stem>/subagents`. `None` when the path has no parent
/// or no file stem (so a degenerate path can't panic the scan).
fn subagents_dir(parent_transcript_path: &Path) -> Option<PathBuf> {
    Some(
        parent_transcript_path
            .parent()?
            .join(parent_transcript_path.file_stem()?)
            .join("subagents"),
    )
}

/// True when a path names a subagent transcript: a `.jsonl` file whose name
/// starts with `agent-`. Excludes the `agent-*.meta.json` companion sidecars
/// (extension `json`, not `jsonl`), which are not transcripts.
fn is_agent_transcript(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("jsonl")
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("agent-"))
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

    // --- subagent_transcripts_have_polish_run (#247) ---

    /// A realistic transcript line carrying a `cadence-forge:polish` Skill run.
    const POLISH_LINE: &str = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","name":"Skill","input":{"skill":"cadence-forge:polish"}}]}}"#;

    /// Stand up a `<dir>/<sess>/subagents/` tree and return the *parent*
    /// transcript path (`<dir>/<sess>.jsonl`) the helper derives children from.
    /// The parent file itself is never read by the helper, so it need not exist.
    fn parent_with_subagents(dir: &std::path::Path) -> PathBuf {
        let subagents = dir.join("sess").join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();
        dir.join("sess.jsonl")
    }

    #[test]
    fn subagent_polish_in_child_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = parent_with_subagents(tmp.path());
        std::fs::write(
            tmp.path()
                .join("sess")
                .join("subagents")
                .join("agent-a1.jsonl"),
            POLISH_LINE,
        )
        .unwrap();
        assert!(
            subagent_transcripts_have_polish_run(&parent),
            "a polish run in a child subagent transcript must be detected"
        );
    }

    #[test]
    fn subagent_meta_json_companion_is_ignored() {
        // Only an `agent-a1.meta.json` sidecar exists (no `.jsonl` transcript).
        // It is not a transcript, so it must not count even if it held polish text.
        let tmp = tempfile::tempdir().unwrap();
        let parent = parent_with_subagents(tmp.path());
        std::fs::write(
            tmp.path()
                .join("sess")
                .join("subagents")
                .join("agent-a1.meta.json"),
            POLISH_LINE,
        )
        .unwrap();
        assert!(
            !subagent_transcripts_have_polish_run(&parent),
            "a .meta.json companion must be ignored, not scanned"
        );
    }

    #[test]
    fn no_subagents_dir_is_false() {
        // Parent path with no `subagents/` directory beside it → false, never panic.
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("sess.jsonl");
        assert!(!subagent_transcripts_have_polish_run(&parent));
    }

    #[test]
    fn child_without_polish_is_false() {
        // A child transcript exists but holds no polish Skill run → false.
        let tmp = tempfile::tempdir().unwrap();
        let parent = parent_with_subagents(tmp.path());
        std::fs::write(
            tmp.path().join("sess").join("subagents").join("agent-a1.jsonl"),
            r#"{"message":{"role":"assistant","content":[{"type":"text","text":"no polish here"}]}}"#,
        )
        .unwrap();
        assert!(!subagent_transcripts_have_polish_run(&parent));
    }

    // --- last_assistant_model (#144) ---

    fn model_line(role: &str, model: &str) -> String {
        format!(r#"{{"message":{{"role":"{role}","model":"{model}"}}}}"#)
    }

    #[test]
    fn last_assistant_model_returns_newest() {
        // Two assistant models in order — the last (tail-most) wins.
        let transcript = [
            model_line("assistant", "claude-sonnet-4-5"),
            model_line("assistant", "claude-opus-4-8"),
        ]
        .join("\n");
        assert_eq!(
            last_assistant_model(&transcript).as_deref(),
            Some("claude-opus-4-8"),
            "the last assistant model must win over earlier ones"
        );
    }

    #[test]
    fn last_assistant_model_skips_trailing_user_and_corrupt_lines() {
        // A trailing user turn and a corrupt line after the assistant model must
        // not shadow it — the scan skips non-assistant and unparseable lines.
        let transcript = [
            model_line("assistant", "claude-opus-4-8"),
            r#"{"message":{"role":"user","content":"next"}}"#.to_string(),
            "not json {{".to_string(),
        ]
        .join("\n");
        assert_eq!(
            last_assistant_model(&transcript).as_deref(),
            Some("claude-opus-4-8")
        );
    }

    #[test]
    fn last_assistant_model_none_without_assistant() {
        // Only user turns → no model to resolve.
        let transcript = [
            r#"{"message":{"role":"user","content":"hi"}}"#,
            r#"{"message":{"role":"user","content":"still hi"}}"#,
        ]
        .join("\n");
        assert_eq!(last_assistant_model(&transcript), None);
    }

    #[test]
    fn last_assistant_model_none_when_assistant_has_no_model() {
        // Assistant messages without a `model` field yield None, not a panic.
        let transcript = r#"{"message":{"role":"assistant","content":"thinking"}}"#;
        assert_eq!(last_assistant_model(transcript), None);
    }

    #[test]
    fn last_assistant_model_ignores_empty_model_string() {
        // A present-but-empty model is treated as absent.
        let transcript = model_line("assistant", "");
        assert_eq!(last_assistant_model(&transcript), None);
    }

    #[test]
    fn last_assistant_model_empty_transcript_is_none() {
        assert_eq!(last_assistant_model(""), None);
    }

    // --- last_assistant_harness_version ---

    fn harness_line(role: &str, version: &str) -> String {
        format!(r#"{{"version":"{version}","message":{{"role":"{role}"}}}}"#)
    }

    #[test]
    fn last_assistant_harness_version_returns_newest() {
        let transcript = [
            harness_line("assistant", "2.1.200"),
            harness_line("assistant", "2.1.214"),
        ]
        .join("\n");
        assert_eq!(
            last_assistant_harness_version(&transcript).as_deref(),
            Some("2.1.214"),
            "the last assistant harness version must win over earlier ones"
        );
    }

    #[test]
    fn last_assistant_harness_version_skips_trailing_user_and_corrupt_lines() {
        let transcript = [
            harness_line("assistant", "2.1.214"),
            r#"{"version":"2.1.215","message":{"role":"user"}}"#.to_string(),
            "not json {{".to_string(),
        ]
        .join("\n");
        assert_eq!(
            last_assistant_harness_version(&transcript).as_deref(),
            Some("2.1.214")
        );
    }

    #[test]
    fn last_assistant_harness_version_none_without_assistant() {
        let transcript = [
            r#"{"version":"2.1.214","message":{"role":"user"}}"#,
            r#"{"version":"2.1.215","message":{"role":"user"}}"#,
        ]
        .join("\n");
        assert_eq!(last_assistant_harness_version(&transcript), None);
    }

    #[test]
    fn last_assistant_harness_version_none_when_assistant_has_no_version() {
        let transcript = r#"{"message":{"role":"assistant"}}"#;
        assert_eq!(last_assistant_harness_version(transcript), None);
    }

    #[test]
    fn last_assistant_harness_version_ignores_empty_version_string() {
        let transcript = harness_line("assistant", "");
        assert_eq!(last_assistant_harness_version(&transcript), None);
    }

    #[test]
    fn last_assistant_harness_version_empty_transcript_is_none() {
        assert_eq!(last_assistant_harness_version(""), None);
    }
}
