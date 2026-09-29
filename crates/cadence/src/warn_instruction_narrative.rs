//! Nudge when an always-loaded instruction file gains narrative.
//!
//! `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` load at every session start,
//! so every token in them is paid by sessions that never touch the subject.
//! What accumulates there is usually the *story* behind a rule — a dated
//! incident, a root cause, the measurement that justified it — which belongs in
//! the commit that made the rule, a gotcha doc, or project memory.
//!
//! A `PreToolUse` check on Write/Edit/MultiEdit, gated on the target's basename.
//! It judges only the text the call **adds** — for Edit/MultiEdit the
//! `new_string` lines absent from `old_string`, for Write the content lines
//! absent from the file on disk — so a line a previous session already settled
//! is never re-flagged. Two independent signals, either sufficient:
//!
//! 1. **Length** — an added paragraph of more than [`MAX_SENTENCES`] sentences
//!    or more than [`MAX_PARAGRAPH_CHARS`] characters. Fenced code blocks and
//!    table rows are stripped first, and each list item or heading starts its
//!    own paragraph, so a long SQL example, a wide table, or a run of short
//!    bullets does not trip it.
//! 2. **Narrative markers** — [`MIN_MARKERS`] or more markers that the text is
//!    about a past event (an ISO date, `measured`, `incident`, …) **and** no
//!    pointer phrase anywhere in the addition. A pointer (`commit history`,
//!    `see`, …) clears this signal entirely, because a dated pointer is how a
//!    legitimate one-line reference reads.
//!
//! An RFC-2119 keyword is deliberately NOT exculpatory: a paragraph that opens
//! with `**MUST NOT**` contains a rule, not *only* a rule (cadence-hooks#922).
//!
//! Warn only — exit 0 with the message as additional context. A long paragraph
//! is sometimes exactly right, and a false block on an instruction-file edit
//! costs more than a missed nudge. Every read failure allows (ADR-0001).

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

/// Basenames of the always-loaded instruction files this check watches.
const INSTRUCTION_FILES: &[&str] = &["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"];

/// An added paragraph with more sentences than this trips the length signal.
pub const MAX_SENTENCES: usize = 3;

/// An added paragraph with more characters than this trips the length signal.
pub const MAX_PARAGRAPH_CHARS: usize = 400;

/// This many narrative markers (with no pointer phrase) trip the marker signal.
pub const MIN_MARKERS: usize = 2;

/// Cap on the on-disk read a Write diffs against. An instruction file past this
/// is not one this check can usefully judge; the read fails and the check allows.
const MAX_ON_DISK_BYTES: u64 = 2 * 1024 * 1024;

/// Markers that a text is *about* a past event rather than stating a rule.
static MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b\d{4}-\d{2}-\d{2}\b|\bmeasured\b|\bincident\b|\bwent missing\b|\bturned out\b|\bused to\b|\bpreviously\b|\bas of\b|\bverified\b",
    )
    .expect("marker regex compiles")
});

/// Phrases that point the story at a home outside the instruction file.
static POINTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bcommit history\b|docs/gotchas|\bfield reports?\b|\bsee\b|\bmemory\b")
        .expect("pointer regex compiles")
});

/// A sentence end: terminal punctuation (optionally closed by a quote, paren,
/// or emphasis marker) followed by whitespace or the end of the paragraph.
static SENTENCE_END_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[.!?]+[)"'*_\]]*(\s|$)"#).expect("sentence regex compiles"));

/// Abbreviations whose period is not a sentence end.
static ABBREVIATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(e\.g|i\.e|etc|vs|cf|approx|incl|resp|no)\.").expect("abbrev regex compiles")
});

/// Inline code spans, whose punctuation is not prose.
static INLINE_CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"`[^`\n]*`").expect("inline code regex compiles"));

/// Nudges when an instruction-file edit adds narrative-sized or story-shaped text.
pub struct WarnInstructionNarrative;

impl Check for WarnInstructionNarrative {
    fn name(&self) -> &str {
        "warn-instruction-narrative"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };
        if !is_instruction_file(&path) {
            return CheckResult::allow();
        }
        let Some(fragments) = input.edit_fragments() else {
            return CheckResult::allow();
        };

        // A Write carries no old_string; its "before" is the file on disk.
        let is_write = input
            .tool_input
            .as_ref()
            .is_some_and(|ti| ti.content.is_some());
        let mut added: Vec<Vec<(String, bool)>> = Vec::new();
        for (new, old) in &fragments {
            let before = if is_write {
                match read_before(input.literal_file_path().unwrap_or(&path)) {
                    Some(text) => text,
                    None => return CheckResult::allow(),
                }
            } else {
                old.clone()
            };
            added.push(added_lines(new, &before));
        }

        match judge(&added) {
            Some(finding) => CheckResult::nudge(render(&path, &finding)),
            None => CheckResult::allow(),
        }
    }
}

/// True when `path`'s basename is one of the always-loaded instruction files.
pub fn is_instruction_file(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| INSTRUCTION_FILES.contains(&name))
}

/// The on-disk "before" a Write is diffed against. A missing file is a new
/// file — everything is added — so it reads as empty. Any other failure
/// (permission, non-regular, oversized, non-UTF-8) returns `None` and the
/// caller allows (ADR-0001).
fn read_before(path: &str) -> Option<String> {
    let p = Path::new(path);
    if !p.exists() && p.symlink_metadata().is_err() {
        return Some(String::new());
    }
    cadence_hooks_core::paths::read_capped(p, MAX_ON_DISK_BYTES)
}

/// Pair each line of `new` with whether it is added — absent from `before`.
/// Comparison is on trimmed lines, so re-indenting a settled line does not make
/// it new. The positional shape is kept so paragraphs are maximal runs of
/// *consecutive* added lines (an unchanged line between two added ones splits
/// them), and so fence state can follow unchanged lines too.
pub fn added_lines(new: &str, before: &str) -> Vec<(String, bool)> {
    let existing: HashSet<&str> = before.lines().map(str::trim).collect();
    new.lines()
        .map(|line| (line.to_string(), !existing.contains(line.trim())))
        .collect()
}

/// Which signal fired, for the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A paragraph past the length limits.
    Length {
        sentences: usize,
        chars: usize,
        excerpt: String,
    },
    /// Enough narrative markers with no pointer phrase.
    Markers { count: usize },
}

/// Pure decision over the positional added-line views of every fragment.
///
/// Fences are tracked over the whole fragment (added or not), because an added
/// line inside an unchanged fence is still code. Only added prose lines feed
/// paragraphs and markers.
pub fn judge(fragments: &[Vec<(String, bool)>]) -> Option<Finding> {
    let mut paragraphs: Vec<String> = Vec::new();
    let mut prose: Vec<String> = Vec::new();

    fn flush(current: &mut Vec<String>, paragraphs: &mut Vec<String>) {
        if !current.is_empty() {
            paragraphs.push(current.join(" "));
            current.clear();
        }
    }

    for lines in fragments {
        let mut in_fence: Option<char> = None;
        let mut current: Vec<String> = Vec::new();
        for (text, added) in lines {
            let t = text.trim();
            // Fence state follows every line, added or not.
            if let Some(marker) = in_fence {
                if closes_fence(t, marker) {
                    in_fence = None;
                }
                flush(&mut current, &mut paragraphs);
                continue;
            }
            if let Some(marker) = fence_marker(t) {
                in_fence = Some(marker);
                flush(&mut current, &mut paragraphs);
                continue;
            }
            // An unchanged line, a blank line, or a table row ends the run.
            if !added || t.is_empty() || t.starts_with('|') {
                flush(&mut current, &mut paragraphs);
                continue;
            }
            if t.starts_with('#') {
                // Headings are labels, not paragraphs; they still count as prose.
                flush(&mut current, &mut paragraphs);
                prose.push(t.to_string());
                continue;
            }
            if starts_list_item(t) {
                flush(&mut current, &mut paragraphs);
            }
            prose.push(t.to_string());
            current.push(t.to_string());
        }
        flush(&mut current, &mut paragraphs);
    }

    for p in &paragraphs {
        let sentences = count_sentences(p);
        let chars = p.chars().count();
        if sentences > MAX_SENTENCES || chars > MAX_PARAGRAPH_CHARS {
            return Some(Finding::Length {
                sentences,
                chars,
                excerpt: cadence_hooks_core::display::sanitize_field(p, 80),
            });
        }
    }

    let addition = prose.join("\n");
    let count = MARKER_RE.find_iter(&addition).count();
    if count >= MIN_MARKERS && !POINTER_RE.is_match(&addition) {
        return Some(Finding::Markers { count });
    }
    None
}

/// The fence character a line opens with (```` ``` ```` or `~~~`), if any.
fn fence_marker(trimmed: &str) -> Option<char> {
    if trimmed.starts_with("```") {
        Some('`')
    } else if trimmed.starts_with("~~~") {
        Some('~')
    } else {
        None
    }
}

/// True when `trimmed` closes a fence opened with `marker`.
fn closes_fence(trimmed: &str, marker: char) -> bool {
    let run = trimmed.chars().take_while(|c| *c == marker).count();
    run >= 3 && trimmed[run * marker.len_utf8()..].trim().is_empty()
}

/// True for a markdown list-item line (`- `, `* `, `+ `, `1. `, `1) `).
fn starts_list_item(t: &str) -> bool {
    if t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ") {
        return true;
    }
    let digits = t.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && (t[digits..].starts_with(". ") || t[digits..].starts_with(") "))
}

/// Count sentences in a paragraph: sentence ends outside inline code, ignoring
/// common abbreviations. A paragraph with text but no terminal punctuation is
/// one sentence.
pub fn count_sentences(paragraph: &str) -> usize {
    let no_code = INLINE_CODE_RE.replace_all(paragraph, "CODE");
    let no_abbrev = ABBREVIATION_RE.replace_all(&no_code, "$1");
    let ends = SENTENCE_END_RE.find_iter(&no_abbrev).count();
    let trailing = SENTENCE_END_RE
        .split(&no_abbrev)
        .last()
        .is_some_and(|tail| tail.chars().any(char::is_alphanumeric));
    ends + usize::from(trailing)
}

fn render(path: &str, finding: &Finding) -> String {
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("instruction file");
    let why = match finding {
        Finding::Length {
            sentences,
            chars,
            excerpt,
        } => format!(
            "an added paragraph runs {sentences} sentences / {chars} characters \
             (limits: {MAX_SENTENCES} sentences, {MAX_PARAGRAPH_CHARS} characters): \"{excerpt}\""
        ),
        Finding::Markers { count } => format!(
            "the addition carries {count} narrative markers (dates, `measured`, `incident`, \
             `turned out`, …) and no pointer to where the story lives"
        ),
    };
    format!(
        "📚  {name} is loaded into every session, and this edit reads like narrative — {why}.\n\n\
         Keep the rule, plus one pointer to the story. The story itself costs a session \
         nothing in any of these homes:\n  \
         - the commit message that makes the rule\n  \
         - a gotcha doc (e.g. docs/gotchas/)\n  \
         - project memory\n\n\
         Advisory only — a long paragraph is sometimes exactly right."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit, make_write};

    /// The rejected paragraph: a genuine rule, followed by the incident account
    /// that belonged in the commit message. Leads with an RFC-2119 keyword on
    /// purpose — the keyword must not clear it.
    const REJECTED: &str = "**MUST NOT** restart the socket daemon from a hook. On 2026-03-14 the \
        auth socket went missing mid-session after a hook restarted it, and every git operation \
        failed with a permission error. It turned out the daemon re-created the socket under a new \
        inode, so existing clients kept a dead handle. We measured it across three machines before \
        settling on the rule.";

    /// The replacement that survived: the rule plus a pointer.
    const SURVIVOR: &str = "**MUST NOT** restart the socket daemon from a hook — clients keep a \
        dead handle. The incident is in commit history.";

    fn outcome(input: &HookInput) -> Outcome {
        WarnInstructionNarrative.run(input).outcome
    }

    #[test]
    fn rejected_paragraph_nudges_despite_rfc2119_lead() {
        let input = make_edit("/repo/CLAUDE.md", "", REJECTED);
        assert_eq!(outcome(&input), Outcome::Nudge);
    }

    #[test]
    fn surviving_rule_plus_pointer_is_silent() {
        let input = make_edit("/repo/CLAUDE.md", "", SURVIVOR);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn dated_pointer_stays_silent() {
        // Two markers (a date and `incident`), but a pointer phrase clears them.
        let text = "Never reuse the socket path — see the 2026-01-01 incident in commit history.";
        let input = make_edit("/repo/AGENTS.md", "", text);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn two_markers_fire_without_the_length_signal() {
        let text = "Pin the toolchain. It used to drift; verified on 2026-02-02.";
        assert!(text.len() < MAX_PARAGRAPH_CHARS);
        assert!(count_sentences(text) <= MAX_SENTENCES);
        let input = make_edit("/repo/CLAUDE.md", "", text);
        let result = WarnInstructionNarrative.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap().contains("narrative markers"));
    }

    #[test]
    fn a_single_marker_is_silent() {
        let input = make_edit("/repo/CLAUDE.md", "", "As of v2 the flag is required.");
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn wide_table_row_does_not_trip_length() {
        let row = format!("| `col` | {} |", "wide cell text ".repeat(40));
        assert!(row.len() > MAX_PARAGRAPH_CHARS);
        let input = make_edit("/repo/CLAUDE.md", "", &row);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn fenced_code_does_not_trip_length() {
        let sql = format!(
            "Run this:\n\n```sql\n{}\n```\n",
            "SELECT a, b, c FROM t WHERE x = 1. AND y = 2. ".repeat(20)
        );
        let input = make_edit("/repo/CLAUDE.md", "", &sql);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn four_short_sentences_trip_length() {
        let text = "Build first. Then test. Then lint. Then ship.";
        assert_eq!(count_sentences(text), 4);
        let input = make_edit("/repo/CLAUDE.md", "", text);
        assert_eq!(outcome(&input), Outcome::Nudge);
    }

    #[test]
    fn a_run_of_short_bullets_is_not_one_paragraph() {
        let bullets = (0..12)
            .map(|i| format!("- Rule number {i} applies to every crate in the workspace."))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(bullets.len() > MAX_PARAGRAPH_CHARS);
        let input = make_edit("/repo/CLAUDE.md", "", &bullets);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn only_added_lines_are_judged_on_edit() {
        // The long paragraph is in both old and new — already settled.
        let old = format!("{REJECTED}\n\n- a");
        let new = format!("{REJECTED}\n\n- b");
        let input = make_edit("/repo/CLAUDE.md", &old, &new);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn multi_edit_fragments_are_all_judged() {
        let input = make_multi_edit("/repo/CLAUDE.md", &[("x", "short"), ("y", REJECTED)]);
        assert_eq!(outcome(&input), Outcome::Nudge);
    }

    #[test]
    fn write_diffs_against_the_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(&path, format!("# Rules\n\n{REJECTED}\n")).unwrap();
        let p = path.to_str().unwrap();

        // Re-writing the settled paragraph plus a short new line: silent.
        let same = make_write(p, &format!("# Rules\n\n{REJECTED}\n\n- New short rule.\n"));
        assert_eq!(outcome(&same), Outcome::Allow);

        // A Write to a brand-new file judges everything.
        let fresh = dir.path().join("sub").join("AGENTS.md");
        let new = make_write(fresh.to_str().unwrap(), REJECTED);
        assert_eq!(outcome(&new), Outcome::Nudge);
    }

    #[test]
    fn other_files_are_ignored() {
        for path in [
            "/repo/README.md",
            "/repo/docs/CLAUDE.md.bak",
            "/repo/claude.md",
            "/repo/NOTCLAUDE.md",
        ] {
            let input = make_edit(path, "", REJECTED);
            assert_eq!(outcome(&input), Outcome::Allow, "{path}");
        }
        for path in [
            "/repo/CLAUDE.md",
            "/repo/sub/CLAUDE.local.md",
            "/a/AGENTS.md",
        ] {
            assert!(is_instruction_file(path), "{path}");
        }
    }

    #[test]
    fn abbreviations_and_code_do_not_inflate_sentences() {
        assert_eq!(
            count_sentences("Use a flag, e.g. `--x. --y. --z.` in CI, i.e. always."),
            1
        );
        assert_eq!(count_sentences("No terminal punctuation here"), 1);
        assert_eq!(count_sentences(""), 0);
    }

    #[test]
    fn non_payload_tools_allow() {
        let input = cadence_hooks_core::test_builders::make_bash("cat CLAUDE.md");
        assert_eq!(outcome(&input), Outcome::Allow);
    }
}
