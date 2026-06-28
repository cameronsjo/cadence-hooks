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
use std::path::{Path, PathBuf};

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
            tmp.path().join("sess").join("subagents").join("agent-a1.jsonl"),
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
}
