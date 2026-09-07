//! Session-transcript scanning shared across hooks.
//!
//! Claude Code records each session as an append-only JSONL transcript (one
//! message per line). Hooks that need to know *what already happened this
//! session* — e.g. "did `/polish` run before this `gh pr create`?" — scan that
//! transcript. The detection is deliberately pure (operates on the transcript
//! text, no I/O) so both the fire-and-forget metrics logger and the PreToolUse
//! gate that blocks an evidenced polish-skip share one implementation and one
//! set of tests.
//!
//! [`read_tail`] is the one deliberate exception to that purity: getting the
//! transcript text off disk is I/O every consumer of the pure resolvers needs,
//! and doing it once here is what keeps the bound in a single place (#361).

use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Default bound for a transcript tail read: 1 MiB.
///
/// Every consumer of [`read_tail`] resolves a field off the *last assistant
/// line* ([`last_assistant_model`], [`last_assistant_harness_version`]), and on
/// each of today's callers that line sits at or near the very end of the file —
/// the hook fires while the assistant's own tool call is the newest turn. 1 MiB
/// therefore covers the needed line hundreds of times over, with headroom for a
/// tail made entirely of large tool-result lines, while bounding the read of a
/// long session's multi-hundred-MB transcript to a fixed cost.
pub const TAIL_READ_MAX_BYTES: u64 = 1024 * 1024;

/// Read the last [`TAIL_READ_MAX_BYTES`] of a session transcript.
/// See [`read_tail_bounded`] for the semantics.
pub fn read_tail(path: &Path) -> Option<String> {
    read_tail_bounded(path, TAIL_READ_MAX_BYTES)
}

/// Read at most `max_bytes` from the START of `path`, returning whole lines.
///
/// [`read_tail_bounded`]'s head-side sibling, for consumers that resolve a
/// field off the transcript's FIRST rows (e.g. the injected implement-plan
/// prompt an approve-and-clear launch writes as the session's first user
/// line). Same containment posture: the cap is enforced with `take`, a
/// non-regular target is rejected on the pre-open `stat`, and when the file
/// is larger than the cap the trailing partial line — a fragment the caller
/// would not have parsed anyway — is dropped, so every returned line is
/// complete. `None` on any open/stat/read failure or non-UTF-8 content.
pub fn read_head_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    use std::io::Read as _;

    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None; // FIFO / device / dir / broken symlink
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(meta.len().min(max_bytes) as usize);
    file.take(max_bytes).read_to_end(&mut buf).ok()?;

    if buf.len() as u64 == max_bytes {
        // Drop the trailing partial line: `\n` cannot occur inside a
        // multi-byte UTF-8 sequence, so truncating after the last `\n` keeps
        // the remainder valid and line-complete. A window with no newline at
        // all is entirely one fragment, so all of it goes. Decided on the
        // BUFFER length, not `st_size` — a file lying about its size (the
        // `/proc`-style case) must not skip the truncation and leak a
        // fragment past the documented whole-lines guarantee. (A file of
        // exactly `max_bytes` whose last line lacks a trailing newline loses
        // that final line — an acceptable edge for a bound this size.)
        let cut = buf.iter().rposition(|&b| b == b'\n').map_or(0, |nl| nl + 1);
        buf.truncate(cut);
    }
    String::from_utf8(buf).ok()
}

/// Read at most `max_bytes` from the END of `path`, returning whole lines.
///
/// The transcript resolvers in this module all scan from the tail
/// (`.lines().rev()`), so they never need the head of a file that can reach
/// hundreds of MB in a long session. This is the shared bounded read those
/// callers route through instead of `read_to_string`.
///
/// **The cap does not trust `st_size`.** The read is capped with
/// `take(max_bytes)` regardless of what the size said, so a file reporting 0
/// while holding gigabytes (a `/proc`-style file on Linux) is still bounded —
/// it is simply read from the front instead of seeked. The size is used only
/// to choose the seek offset, so a lie costs a wrong window, never an
/// unbounded read.
///
/// **A byte offset can land mid-codepoint.** When the file is larger than the
/// cap, everything up to and including the first `\n` in the window is dropped:
/// that first line is a fragment of a line the caller would not have parsed
/// anyway, and `\n` cannot occur inside a multi-byte UTF-8 sequence, so the
/// remainder is guaranteed to start on a codepoint boundary. Tail-scan
/// semantics tolerate the loss — a dropped fragment is one line further from
/// the tail than anything the resolvers want. A window with no `\n` at all (one
/// pathologically long final line) yields an empty string, and the caller's
/// resolver returns `None` — fail-open, per ADR-0001.
///
/// `None` on any open/stat/read failure or non-UTF-8 content, matching the
/// `read_to_string` this replaces. A non-regular target (directory, FIFO,
/// device) is rejected on the pre-open `stat`, since a FIFO blocks on `open`
/// and a check afterwards would already be too late — the same ordering
/// [`crate::paths::read_capped`] depends on.
pub fn read_tail_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    if !std::fs::metadata(path).ok()?.is_file() {
        return None; // FIFO / device / dir / broken symlink
    }
    let mut file = std::fs::File::open(path).ok()?;
    // Length from an `fstat` on the OPEN handle, not the path stat above: the
    // seek offset is then computed from the file we actually hold, with no
    // second path resolution in between. The `take` below bounds the read
    // whatever this reports, so a lie costs at most a wasted seek.
    let len = file.metadata().ok()?.len();
    let seeked = len > max_bytes;
    if seeked {
        file.seek(SeekFrom::Start(len - max_bytes)).ok()?;
    }

    let mut buf = Vec::with_capacity(len.min(max_bytes) as usize);
    (&file).take(max_bytes).read_to_end(&mut buf).ok()?;

    if seeked {
        // Drop the leading partial line — see the codepoint note above. A
        // window with no newline at all is entirely one fragment, so all of it
        // goes.
        let cut = buf
            .iter()
            .position(|&b| b == b'\n')
            .map_or(buf.len(), |newline| newline + 1);
        buf.drain(..cut);
    }
    String::from_utf8(buf).ok()
}

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

    // --- read_tail_bounded (#361) ---

    /// Write `content` to a fresh temp dir and return `(dir, path)`. The dir is
    /// returned so the caller keeps it alive for the test's duration.
    fn transcript_file(content: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sess.jsonl");
        std::fs::write(&path, content).unwrap();
        (tmp, path)
    }

    #[test]
    fn read_tail_returns_a_short_file_whole() {
        // Under the bound → read from offset 0, so NO partial-line drop. The
        // first line must survive; this is the per-caller behavior preservation.
        let content = [
            model_line("assistant", "claude-sonnet-4-5"),
            model_line("assistant", "claude-opus-4-8"),
        ]
        .join("\n");
        let (_tmp, path) = transcript_file(content.as_bytes());
        assert_eq!(read_tail_bounded(&path, 1024).as_deref(), Some(&*content));
    }

    #[test]
    fn read_tail_bounds_the_read_of_a_large_file() {
        // A file far over the bound: the read must be capped at the bound, and
        // the tail-most assistant model must still resolve off what came back.
        const BOUND: u64 = 4 * 1024;
        let filler = model_line("assistant", "claude-old-model");
        let mut content = String::new();
        while content.len() < 40 * 1024 {
            content.push_str(&filler);
            content.push('\n');
        }
        content.push_str(&model_line("assistant", "claude-fable-5"));
        let (_tmp, path) = transcript_file(content.as_bytes());

        let tail = read_tail_bounded(&path, BOUND).unwrap();
        assert!(
            tail.len() as u64 <= BOUND,
            "the read must be bounded: got {} bytes for a {}-byte bound",
            tail.len(),
            BOUND
        );
        assert!(
            (tail.len() as u64) < content.len() as u64,
            "the fixture must actually exceed the bound, or this proves nothing"
        );
        assert_eq!(
            last_assistant_model(&tail).as_deref(),
            Some("claude-fable-5"),
            "the tail-most model must still resolve from the bounded read"
        );
    }

    #[test]
    fn read_tail_drops_a_line_split_mid_codepoint() {
        // The bound lands INSIDE a multi-byte character on the first line of the
        // window. A naive byte slice would be invalid UTF-8; dropping through
        // the first newline must yield clean, whole lines.
        let head = format!("{{\"pad\":\"{}\"}}", "é".repeat(64)); // 2 bytes each
        let tail_line = model_line("assistant", "claude-fable-5");
        let content = format!("{head}\n{tail_line}");
        let (_tmp, path) = transcript_file(content.as_bytes());

        // The head's last `é` occupies bytes head.len()-4..head.len()-2 (the
        // trailing `"}` is the final 2 bytes), so a window opening at
        // head.len()-3 starts on that character's SECOND byte.
        let bound = (content.len() - (head.len() - 3)) as u64;
        assert_eq!(
            content.as_bytes()[head.len() - 3] & 0b1100_0000,
            0b1000_0000,
            "the fixture must actually open mid-codepoint (a continuation byte), \
             or this test proves nothing"
        );

        let tail = read_tail_bounded(&path, bound).unwrap();
        assert_eq!(
            tail, tail_line,
            "the mid-codepoint partial line must be dropped, leaving whole lines"
        );
        assert_eq!(
            last_assistant_model(&tail).as_deref(),
            Some("claude-fable-5")
        );
    }

    #[test]
    fn read_tail_window_without_a_newline_is_empty() {
        // One pathologically long line, so the whole window is a fragment. No
        // whole line survives → empty, and the resolver falls through to None
        // (fail-open) rather than parsing a truncated JSON object.
        let content = model_line("assistant", &"m".repeat(4096));
        let (_tmp, path) = transcript_file(content.as_bytes());
        let tail = read_tail_bounded(&path, 64).unwrap();
        assert_eq!(tail, "");
        assert_eq!(last_assistant_model(&tail), None);
    }

    #[test]
    fn read_tail_at_exactly_the_bound_keeps_the_first_line() {
        // Boundary: len == max_bytes is NOT over the bound, so no seek and no
        // partial-line drop. An off-by-one here would eat a real first line.
        let content = model_line("assistant", "claude-fable-5");
        let (_tmp, path) = transcript_file(content.as_bytes());
        assert_eq!(
            read_tail_bounded(&path, content.len() as u64).as_deref(),
            Some(&*content)
        );
    }

    #[test]
    fn read_tail_missing_file_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            read_tail_bounded(&tmp.path().join("absent.jsonl"), 1024),
            None
        );
    }

    #[test]
    fn read_tail_non_regular_target_is_none() {
        // A directory at the transcript path is not a transcript.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_tail_bounded(tmp.path(), 1024), None);
    }

    #[test]
    fn read_tail_non_utf8_is_none() {
        // Matches the `read_to_string` this replaces: undecodable → None →
        // the caller fails open.
        let (_tmp, path) = transcript_file(&[0xff, 0xfe, b'\n', 0xff]);
        assert_eq!(read_tail_bounded(&path, 1024), None);
    }

    #[test]
    fn read_tail_empty_file_is_empty() {
        let (_tmp, path) = transcript_file(b"");
        assert_eq!(read_tail_bounded(&path, 1024).as_deref(), Some(""));
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
