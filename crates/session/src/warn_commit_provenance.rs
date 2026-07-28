//! `session warn-commit-provenance` — PreToolUse commit-time provenance nudge
//! (cadence#473, commit half; the persist-plan half lives in
//! [`crate::persist_plan`] and shares [`crate::provenance::machine_digest`]).
//!
//! Fires once per session (tracked via a temp-file marker, mirroring
//! `warn_main_branch`), not once per commit (#370) — a session making many
//! commits under an explicit no-trailer message contract saw this nudge on
//! every single one, pure noise once the session already knows the format.
//!
//! A Claude-composed commit is easier to trace back to its producing session
//! when its message carries a `Session-Id:` trailer. Rather than asking every
//! session to remember the format, this check watches `git commit` at
//! PreToolUse time and, when the message lacks that marker, nudges with the
//! trailer block ALREADY COMPUTED and ready to copy — the friction of
//! recalling the format is the reason compliance is inconsistent, not
//! unwillingness.
//!
//! **Warn tier only, never blocks (ADR-0001).** Every uncertainty — no
//! message derivable, an unreadable `-F` file, a missing transcript, an
//! unresolvable model/harness/session field — degrades to either a silent
//! allow (no message at all) or a nudge with whatever tuple fields resolved.
//! A hook bug must never stop a commit.
//!
//! Detection reuses [`crate::branch_drift::is_git_commit`] (the sibling
//! PreToolUse-Bash-commit check) and `cadence_hooks_core::shell`'s existing
//! parsers (`tokenize`, `strip_quotes`) rather than a third hand-rolled
//! git-commit parser.

use crate::identity;
use crate::provenance;
use cadence_hooks_core::paths;
use cadence_hooks_core::shell::{strip_quotes, tokenize};
use cadence_hooks_core::transcript;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};

/// The trailer marker whose presence in a commit message satisfies this
/// check — any commit that already carries it is left alone.
const SESSION_ID_MARKER: &str = "Session-Id:";

/// Cap on a `-F`/`--file` commit-message file's size before it's treated as
/// unreadable. Real commit messages run well under this; the cap exists so a
/// crafted huge file can't turn a PreToolUse hook into a self-inflicted
/// slowdown (same defensive posture as `persist_plan`'s
/// `PARENT_SCAN_MAX_FILE_BYTES`, scaled down for a single small text file).
const MAX_MESSAGE_FILE_BYTES: u64 = 64 * 1024;

/// Nudge toward carrying the producer-tuple trailer on Claude-composed commits.
pub struct WarnCommitProvenance;

impl Check for WarnCommitProvenance {
    fn name(&self) -> &str {
        "warn-commit-provenance"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        // Narrow defense-in-depth: this check fires on every `git commit`
        // Bash invocation, and the `Check` dispatch path (unlike `Logger`'s)
        // has no panic guard today (a separate, broader gap tracked
        // elsewhere). A bug here must not stop a commit, so a panic
        // degrades to a silent allow rather than propagating — same guard
        // `PersistPlan::run` uses.
        std::panic::catch_unwind(|| run_warn_commit_provenance(input, &host))
            .unwrap_or_else(|_| CheckResult::allow())
    }
}

/// Testable core: `host` is injected so tests exercise the real
/// [`provenance::machine_digest`] derivation without depending on the
/// process's actual hostname.
pub fn run_warn_commit_provenance(input: &HookInput, host: &str) -> CheckResult {
    if input.tool_name() != Some("Bash") {
        return CheckResult::allow();
    }
    let Some(command) = input.command() else {
        return CheckResult::allow();
    };
    if !crate::branch_drift::is_git_commit(&strip_quotes(command)) {
        return CheckResult::allow();
    }

    let Some(message) = extract_commit_message(command, input.cwd.as_deref()) else {
        return CheckResult::allow();
    };
    if message.contains(SESSION_ID_MARKER) {
        return CheckResult::allow();
    }

    // Once-per-session, not once-per-commit (#370): a session that makes many
    // commits under an explicit no-trailer message contract (e.g. a dispatched
    // implementer following a fixed commit-message spec) saw this nudge fire
    // on every single one — pure noise once the session has already seen the
    // format. Global (repo_root: None), unlike warn-main-branch's per-repo
    // marker: "does this session know the trailer format" doesn't reset per
    // repo the way "is this branch main" does.
    let marker = cadence_hooks_core::markers::session_marker(input, "provenance-nudge-shown", None);
    if marker.exists() {
        return CheckResult::allow();
    }

    // Build the message BEFORE writing the marker: if build_nudge ever panics
    // (caught by the caller's catch_unwind), the marker must not already be on
    // disk — that would permanently suppress a nudge the user never saw.
    let msg = build_nudge(input, host);
    let _ = cadence_hooks_core::markers::write_marker(&marker, "");

    CheckResult::nudge(msg)
}

// ---------------------------------------------------------------------------
// Message extraction: inline -m/--message, heredoc-in-command-string, -F/--file
// ---------------------------------------------------------------------------

/// Extract the commit message from a `git commit` Bash command, across the
/// three shapes Claude actually emits. Returns `None` when no message can be
/// derived — an editor-based commit, a bare `--amend`, or an unreadable/
/// oversized `-F` file — which the caller treats as a silent allow.
///
/// `-F`/`--file` takes priority over `-m`/`--message` when both are present
/// (an unusual shape git itself rejects; if it somehow appears, the file is
/// the more literal source of the actual committed text). Multiple `-m`
/// flags are concatenated with a blank line between, matching git's own
/// paragraph semantics for repeated `-m`.
fn extract_commit_message(command: &str, cwd: Option<&str>) -> Option<String> {
    let tokens = tokenize(command);
    let mut messages: Vec<String> = Vec::new();
    let mut file_arg: Option<String> = None;

    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        match tok {
            "-m" | "--message" => {
                if let Some(v) = tokens.get(i + 1) {
                    messages.push(resolve_message_value(v));
                }
                i += 2;
                continue;
            }
            "-F" | "--file" => {
                if let Some(v) = tokens.get(i + 1) {
                    file_arg = Some(v.clone());
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        if let Some(v) = tok.strip_prefix("--message=") {
            messages.push(resolve_message_value(v));
        } else if let Some(v) = tok.strip_prefix("--file=") {
            file_arg = Some(v.to_string());
        }
        i += 1;
    }

    if let Some(path) = file_arg {
        return read_message_file(&path, cwd);
    }
    if messages.is_empty() {
        return None;
    }
    Some(messages.join("\n\n"))
}

/// Resolve one captured `-m`/`--message` token value: if it embeds a
/// `$(cat <<'WORD' … WORD)`-style heredoc — the estate's common shape for a
/// multi-line commit message, which [`tokenize`]'s single-quote-state parser
/// captures verbatim inside the outer double quotes — extract the body
/// between the delimiter lines. A plain literal value passes through as-is.
fn resolve_message_value(value: &str) -> String {
    extract_heredoc_body(value).unwrap_or_else(|| value.to_string())
}

/// Extract the body of a heredoc embedded within `value`: find the first
/// line introducing a `<<WORD`/`<<-WORD`/`<<'WORD'`/`<<"WORD"` delimiter,
/// then the body is every line up to (not including) the first following
/// terminator line — matched per real bash semantics: `<<-WORD` tolerates a
/// leading-tab-indented terminator, plain `<<WORD` requires an exact match.
///
/// Only the FIRST delimiter/terminator pair is ever resolved — a `value`
/// that somehow concatenates two heredoc substitutions (`$(cat <<'A' …
/// A)$(cat <<'B' … B)`) yields only the first body; anything from the first
/// terminator onward, including a second heredoc, is silently dropped
/// rather than guessed at or merged (pinned by
/// `extract_heredoc_two_heredocs_in_one_value_only_first_extracted`).
///
/// `None` when `value` carries no heredoc delimiter (a plain literal
/// message), or when a delimiter is found but its terminator never appears —
/// mirroring `core::shell::strip_heredoc_bodies`'s terminator-not-found
/// discipline: never guess at a boundary that wasn't confidently located.
fn extract_heredoc_body(value: &str) -> Option<String> {
    let lines: Vec<&str> = value.lines().collect();
    let (idx, word, strip_leading_tabs) = lines
        .iter()
        .enumerate()
        .find_map(|(idx, line)| heredoc_delimiter(line).map(|(w, s)| (idx, w, s)))?;
    let end = lines[idx + 1..]
        .iter()
        .position(|line| terminator_matches(line, word, strip_leading_tabs))
        .map(|offset| idx + 1 + offset)?;
    Some(lines[idx + 1..end].join("\n"))
}

/// True when `line` is the terminator for a heredoc introduced with
/// delimiter `word`. The strip-leading-tabs form (`<<-WORD`) strips only
/// leading TABS before comparing (bash's own rule — not arbitrary
/// whitespace); the plain form (`<<WORD`) requires an exact match.
fn terminator_matches(line: &str, word: &str, strip_leading_tabs: bool) -> bool {
    if strip_leading_tabs {
        line.trim_start_matches('\t') == word
    } else {
        line == word
    }
}

/// The delimiter word introduced by a `<<`/`<<-` on `line`, if any, paired
/// with whether it's the strip-leading-tabs form (`<<-WORD`). An optional
/// surrounding quote around the word suppresses expansion in real bash but
/// doesn't affect body extraction here — only the word matters.
fn heredoc_delimiter(line: &str) -> Option<(&str, bool)> {
    let idx = line.find("<<")?;
    let after = &line[idx + 2..];
    let strip_leading_tabs = after.starts_with('-');
    let rest = after.strip_prefix('-').unwrap_or(after);
    let rest = rest.trim_start();
    let word = if let Some(stripped) = rest.strip_prefix('\'') {
        stripped.split('\'').next()?
    } else if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()?
    } else {
        rest.split(|c: char| c.is_whitespace() || c == ')').next()?
    };
    (!word.is_empty()).then_some((word, strip_leading_tabs))
}

/// Read a `-F`/`--file` commit-message file: untrusted, attacker-influenceable
/// text — opened and read only, never written, created, or canonicalized.
/// Resolves a relative `path` against `cwd`; a missing `cwd` for a relative
/// path, a missing/non-file/oversized target, or a read failure all collapse
/// to `None` (silent allow) — never an error, never a guess.
///
/// The non-regular and size gates are [`paths::read_capped`]'s, so the
/// [`MAX_MESSAGE_FILE_BYTES`] cap is enforced by the read itself rather than
/// trusting `st_size` — a file that lies about its size (a `/proc`-style file
/// on Linux) is rejected the same as an honestly oversized one (#361).
fn read_message_file(path: &str, cwd: Option<&str>) -> Option<String> {
    let resolved = resolve_message_path(path, cwd)?;
    paths::read_capped(&resolved, MAX_MESSAGE_FILE_BYTES)
}

/// Resolve a `-F` path argument: absolute paths pass through; a relative
/// path joins onto `cwd` (from the PreToolUse payload — the directory Claude
/// wrote the file from). `None` when relative and `cwd` is absent.
fn resolve_message_path(path: &str, cwd: Option<&str>) -> Option<PathBuf> {
    let p = Path::new(path);
    if p.is_absolute() {
        Some(p.to_path_buf())
    } else {
        cwd.map(|c| Path::new(c).join(p))
    }
}

// ---------------------------------------------------------------------------
// Nudge: the computed producer-tuple trailer block
// ---------------------------------------------------------------------------

/// Render the nudge: an instruction line plus the trailer block, with each
/// tuple field's line present only when resolvable — an unresolvable field
/// is omitted, never rendered blank or guessed (the nudge's job is making
/// compliance easy, not being complete).
///
/// The transcript is read AT MOST ONCE per run (not once for `Model:` and
/// again for `Harness:`) — its content is threaded to both resolvers.
/// `Model:`/`Harness:` are transcript- or env-sourced text, not the
/// hardened Session-Id/Name/Machine fields, so each is passed through
/// `identity::sanitize_field` before interpolation: a crafted transcript
/// `model`/`version` value, or an `AI_AGENT` env value, could otherwise
/// smuggle newlines (serde decodes `\n` escapes to real control bytes) or
/// oversized text into the nudge Claude reads as context.
fn build_nudge(input: &HookInput, host: &str) -> String {
    let mut lines = Vec::new();
    if let Some((name, session_id)) = resolve_session_name_and_id(input) {
        lines.push(format!("Session-Name: {name}"));
        lines.push(format!("Session-Id: {session_id}"));
    }
    let transcript_content = input
        .transcript_path()
        .and_then(|path| transcript::read_tail(Path::new(path)));
    if let Some(model) = resolve_model(transcript_content.as_deref()) {
        lines.push(format!(
            "Model: {}",
            identity::sanitize_field(&model, identity::MAX_FIELD_DISPLAY)
        ));
    }
    if let Some(harness) = resolve_harness(transcript_content.as_deref()) {
        lines.push(format!(
            "Harness: claude-code {}",
            identity::sanitize_field(&harness, identity::MAX_FIELD_DISPLAY)
        ));
    }
    lines.push(format!("Machine: {}", provenance::machine_digest(host)));

    format!(
        "This commit message doesn't carry a `{SESSION_ID_MARKER}` trailer. For traceable \
         provenance, consider appending this computed block to the commit message:\n\n{}",
        lines.join("\n")
    )
}

/// The session's display name and id, when the payload's `session_id` is
/// present and safe to render. A missing or unsafe id omits both the
/// `Session-Name:` and `Session-Id:` lines rather than rendering an untrusted
/// value into the nudge Claude reads as context — same discipline as
/// `persist_plan`'s and `branch_drift`'s session-id handling.
fn resolve_session_name_and_id(input: &HookInput) -> Option<(String, String)> {
    let session_id = input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))?;
    Some((identity::generate_name(session_id), session_id.to_string()))
}

/// The current session model, resolved from the transcript tail — same call
/// pattern as `guardrails::guard_read_model::GuardReadModel::run`. Takes the
/// already-read transcript content rather than re-reading the file, so a
/// single run resolves both `Model:` and `Harness:` off one read.
///
/// `pub(crate)`: `persist_plan`'s frontmatter emitter reuses this rather than
/// re-deriving model resolution a second way (cadence-hooks#396's "reuse the
/// existing provenance machinery" design point).
pub(crate) fn resolve_model(transcript_content: Option<&str>) -> Option<String> {
    transcript::last_assistant_model(transcript_content?)
}

/// The harness version: prefer the transcript's top-level `version` field on
/// the last assistant line; fall back to parsing the `AI_AGENT` env var
/// (`claude-code_2-1-215_agent` → `2.1.215`) when the transcript doesn't
/// resolve it. `None` when neither source yields a version — the `Harness:`
/// line is then omitted entirely rather than rendered from a guess.
///
/// `pub(crate)`: shared with `persist_plan` — see [`resolve_model`].
pub(crate) fn resolve_harness(transcript_content: Option<&str>) -> Option<String> {
    if let Some(content) = transcript_content
        && let Some(version) = transcript::last_assistant_harness_version(content)
    {
        return Some(version);
    }
    std::env::var("AI_AGENT")
        .ok()
        .and_then(|v| parse_ai_agent_version(&v))
}

/// Parse the `AI_AGENT` env var's `claude-code_<X-Y-Z>_agent` shape into a
/// dotted version string (`2-1-215` → `2.1.215`). `None` for any value that
/// doesn't carry both the exact prefix and suffix, or whose version segment
/// is empty — never a partial/mangled guess.
fn parse_ai_agent_version(value: &str) -> Option<String> {
    let version_part = value.strip_prefix("claude-code_")?.strip_suffix("_agent")?;
    (!version_part.is_empty()).then(|| version_part.replace('-', "."))
}

/// Serializes tests that mutate the process-global `AI_AGENT` env var,
/// mirroring `guardrails::guard_read_model`'s `ENV_LOCK`/`with_env` pattern.
///
/// `pub(crate)` and hoisted OUT of this module's own `mod tests` (rather than
/// each test module defining its own private lock) so `persist_plan`'s tests
/// — which exercise the SAME `resolve_harness` AI_AGENT fallback via a
/// different call path — serialize against this exact lock. Both modules
/// compile into one `cadence-hooks-session` test binary, and `cargo test`
/// runs its tests multi-threaded by default: two independently-locked env
/// mutators would not actually be mutually exclusive, just each internally
/// consistent — a real flakiness risk for a process-global var, not a
/// theoretical one (cameronsjo/cadence-hooks#396 review).
#[cfg(test)]
pub(crate) static AI_AGENT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn with_ai_agent_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
    let _guard = AI_AGENT_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prior = std::env::var("AI_AGENT").ok();
    // SAFETY: serialized via AI_AGENT_ENV_LOCK; restored below.
    unsafe {
        match value {
            Some(v) => std::env::set_var("AI_AGENT", v),
            None => std::env::remove_var("AI_AGENT"),
        }
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    // SAFETY: same lock still held; restoring prior state.
    unsafe {
        match prior {
            Some(v) => std::env::set_var("AI_AGENT", v),
            None => std::env::remove_var("AI_AGENT"),
        }
    }
    result.unwrap_or_else(|e| std::panic::resume_unwind(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{Outcome, ToolInput};

    fn bash_input(
        cmd: &str,
        session_id: Option<&str>,
        cwd: Option<&str>,
        transcript_path: Option<&str>,
    ) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(ToolInput {
                command: Some(cmd.into()),
                ..Default::default()
            }),
            session_id: session_id.map(String::from),
            cwd: cwd.map(String::from),
            transcript_path: transcript_path.map(String::from),
            ..Default::default()
        }
    }

    // --- Check::run guard clauses ---

    #[test]
    fn non_bash_tool_allows() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            ..Default::default()
        };
        assert_eq!(WarnCommitProvenance.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn non_commit_git_allows() {
        let input = bash_input("git status", Some("sid"), None, None);
        assert_eq!(
            run_warn_commit_provenance(&input, "host").outcome,
            Outcome::Allow
        );
    }

    // --- extraction: inline -m ---

    #[test]
    fn extract_single_inline_dash_m() {
        assert_eq!(
            extract_commit_message("git commit -m 'fix: thing'", None),
            Some("fix: thing".to_string())
        );
    }

    #[test]
    fn extract_multiple_dash_m_concatenated_with_blank_line() {
        assert_eq!(
            extract_commit_message("git commit -m 'subject' -m 'body line'", None),
            Some("subject\n\nbody line".to_string())
        );
    }

    #[test]
    fn extract_long_message_flag() {
        assert_eq!(
            extract_commit_message("git commit --message 'fix: thing'", None),
            Some("fix: thing".to_string())
        );
    }

    #[test]
    fn extract_message_equals_form() {
        assert_eq!(
            extract_commit_message("git commit --message='fix: thing'", None),
            Some("fix: thing".to_string())
        );
    }

    // --- extraction: heredoc-in-command-string ---

    #[test]
    fn extract_heredoc_body_from_command_string() {
        let command = "git commit -m \"$(cat <<'EOF'\nfix: something\n\nbody paragraph\nEOF\n)\"";
        assert_eq!(
            extract_commit_message(command, None),
            Some("fix: something\n\nbody paragraph".to_string())
        );
    }

    #[test]
    fn extract_heredoc_with_session_id_trailer_is_visible_to_the_marker_check() {
        let command =
            "git commit -m \"$(cat <<'EOF'\nfix: something\n\nSession-Id: abc123\nEOF\n)\"";
        let message = extract_commit_message(command, None).unwrap();
        assert!(message.contains("Session-Id: abc123"));
    }

    // --- extraction: -F/--file ---

    #[test]
    fn extract_dash_f_relative_path_resolves_against_cwd() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("msg.txt"), "fix: from file").unwrap();
        let command = "git commit -F msg.txt";
        let cwd = tmp.path().to_string_lossy().into_owned();
        assert_eq!(
            extract_commit_message(command, Some(&cwd)),
            Some("fix: from file".to_string())
        );
    }

    #[test]
    fn extract_dash_f_absolute_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("msg.txt");
        std::fs::write(&path, "fix: from file").unwrap();
        let command = format!("git commit -F {}", path.display());
        assert_eq!(
            extract_commit_message(&command, None),
            Some("fix: from file".to_string())
        );
    }

    #[test]
    fn extract_file_equals_form() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("msg.txt");
        std::fs::write(&path, "fix: from file").unwrap();
        let command = format!("git commit --file={}", path.display());
        assert_eq!(
            extract_commit_message(&command, None),
            Some("fix: from file".to_string())
        );
    }

    #[test]
    fn extract_dash_f_unreadable_is_none() {
        assert_eq!(
            extract_commit_message("git commit -F /no/such/file.txt", None),
            None
        );
    }

    #[test]
    fn extract_dash_f_oversized_is_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("huge.txt");
        std::fs::write(&path, "x".repeat((MAX_MESSAGE_FILE_BYTES as usize) + 1)).unwrap();
        let command = format!("git commit -F {}", path.display());
        assert_eq!(extract_commit_message(&command, None), None);
    }

    #[test]
    fn extract_dash_f_at_exactly_the_cap_still_reads() {
        // The boundary the oversize rejection sits on: a message file of
        // exactly MAX_MESSAGE_FILE_BYTES is under the cap and must still be
        // read. Guards an off-by-one in the take-then-check gate (#361).
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("exact.txt");
        let msg = "x".repeat(MAX_MESSAGE_FILE_BYTES as usize);
        std::fs::write(&path, &msg).unwrap();
        let command = format!("git commit -F {}", path.display());
        assert_eq!(extract_commit_message(&command, None), Some(msg));
    }

    // --- extraction: no message derivable ---

    #[test]
    fn extract_no_message_flag_is_none() {
        assert_eq!(extract_commit_message("git commit --amend", None), None);
        assert_eq!(extract_commit_message("git commit", None), None);
    }

    // --- run_warn_commit_provenance: end-to-end gating ---

    #[test]
    fn message_already_carrying_session_id_allows() {
        let input = bash_input(
            "git commit -m 'fix: thing\n\nSession-Id: existing'",
            Some("sid"),
            None,
            None,
        );
        assert_eq!(
            run_warn_commit_provenance(&input, "host").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn no_message_derivable_allows() {
        let input = bash_input("git commit --amend", Some("sid"), None, None);
        assert_eq!(
            run_warn_commit_provenance(&input, "host").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn missing_session_id_marker_nudges() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let input = bash_input("git commit -m 'fix: thing'", Some("sid12345"), None, None);
            let result = run_warn_commit_provenance(&input, "host");
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(msg.contains("Session-Id:"));
            assert!(msg.contains("Machine:"));
        });
    }

    // --- once-per-session suppression (#370) ---

    #[test]
    fn second_commit_same_session_does_not_renudge() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let input = bash_input("git commit -m 'fix: thing'", Some("slate-sid"), None, None);
            assert_eq!(
                run_warn_commit_provenance(&input, "host").outcome,
                Outcome::Nudge,
                "first commit this session must still nudge"
            );

            let input2 = bash_input(
                "git commit -m 'fix: another thing'",
                Some("slate-sid"),
                None,
                None,
            );
            assert_eq!(
                run_warn_commit_provenance(&input2, "host").outcome,
                Outcome::Allow,
                "a second commit in the same session must not renudge — the session already saw it"
            );
        });
    }

    #[test]
    fn different_session_still_nudges_after_another_sessions_marker() {
        // The marker is session-scoped, not global-forever: a distinct
        // session_id must see its own first nudge regardless of what any
        // other session already acknowledged.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let first = bash_input("git commit -m 'fix: thing'", Some("session-a"), None, None);
            assert_eq!(
                run_warn_commit_provenance(&first, "host").outcome,
                Outcome::Nudge
            );

            let other = bash_input("git commit -m 'fix: thing'", Some("session-b"), None, None);
            assert_eq!(
                run_warn_commit_provenance(&other, "host").outcome,
                Outcome::Nudge,
                "a different session_id must still nudge on its own first commit"
            );
        });
    }

    #[test]
    fn oversized_dash_f_file_allows_end_to_end() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("huge.txt");
        std::fs::write(&path, "x".repeat((MAX_MESSAGE_FILE_BYTES as usize) + 1)).unwrap();
        let command = format!("git commit -F {}", path.display());
        let input = bash_input(&command, Some("sid"), None, None);
        assert_eq!(
            run_warn_commit_provenance(&input, "host").outcome,
            Outcome::Allow
        );
    }

    // --- nudge content: full tuple resolution end-to-end ---

    #[test]
    fn nudge_carries_full_computed_tuple() {
        let tmp = tempfile::TempDir::new().unwrap();
        let transcript_path = tmp.path().join("sess.jsonl");
        std::fs::write(
            &transcript_path,
            r#"{"version":"2.1.214","message":{"role":"assistant","model":"claude-fable-5"}}"#,
        )
        .unwrap();

        // Same tempdir doubles as the marker-dir sandbox (#370) — this test
        // reaches the nudge point, which now writes a session marker.
        with_marker_dir(tmp.path(), || {
            let input = bash_input(
                "git commit -m 'fix: thing'",
                Some("cedar-session-id"),
                None,
                Some(&transcript_path.to_string_lossy()),
            );
            let result = run_warn_commit_provenance(&input, "sjomba.local");
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap();

            assert!(
                msg.contains(&format!(
                    "Session-Name: {}",
                    identity::generate_name("cedar-session-id")
                )),
                "computed session name present: {msg}"
            );
            assert!(msg.contains("Session-Id: cedar-session-id"), "{msg}");
            assert!(msg.contains("Model: claude-fable-5"), "{msg}");
            assert!(msg.contains("Harness: claude-code 2.1.214"), "{msg}");
            assert!(
                msg.contains(&format!(
                    "Machine: {}",
                    provenance::machine_digest("sjomba.local")
                )),
                "computed machine digest present: {msg}"
            );
        });
    }

    #[test]
    fn nudge_resolves_the_tuple_from_a_transcript_past_the_tail_bound() {
        // #361 behavior preservation. Bounding the read (`transcript::read_tail`)
        // is only safe if the fields still resolve on the file shape the bound
        // actually bites: a transcript past `TAIL_READ_MAX_BYTES`. Boundedness
        // itself is proved in `core::transcript`'s unit tests — this asserts the
        // caller did not LOSE resolution by adopting the bound.
        let tmp = tempfile::TempDir::new().unwrap();
        let transcript_path = tmp.path().join("sess.jsonl");
        let mut content = String::new();
        while (content.len() as u64) < cadence_hooks_core::transcript::TAIL_READ_MAX_BYTES * 2 {
            content.push_str(r#"{"message":{"role":"user","content":"padding"}}"#);
            content.push('\n');
        }
        content.push_str(
            r#"{"version":"2.1.214","message":{"role":"assistant","model":"claude-fable-5"}}"#,
        );
        std::fs::write(&transcript_path, &content).unwrap();

        with_marker_dir(tmp.path(), || {
            let input = bash_input(
                "git commit -m 'fix: thing'",
                Some("cedar-session-id"),
                None,
                Some(&transcript_path.to_string_lossy()),
            );
            let result = run_warn_commit_provenance(&input, "sjomba.local");
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(msg.contains("Model: claude-fable-5"), "{msg}");
            assert!(msg.contains("Harness: claude-code 2.1.214"), "{msg}");
        });
    }

    #[test]
    fn nudge_omits_unresolvable_fields_but_still_fires() {
        // No session_id, no transcript, no AI_AGENT — only Machine: resolves.
        // The instructional sentence still mentions the backtick-wrapped
        // `Session-Id:` marker name, so the negative assertions check for the
        // rendered FIELD LINE shape (colon-space-value), not the bare word.
        // AI_AGENT is explicitly cleared — this session's own real Claude
        // Code process sets it, which would otherwise let Harness: resolve
        // and falsify the "nothing but Machine resolves" premise.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_ai_agent_env(None, || {
            with_marker_dir(marker_tmp.path(), || {
                let input = bash_input("git commit -m 'fix: thing'", None, None, None);
                let result = run_warn_commit_provenance(&input, "host");
                assert_eq!(result.outcome, Outcome::Nudge);
                let msg = result.message.unwrap();
                assert!(!msg.contains("Session-Name: "), "{msg}");
                assert!(!msg.contains("Session-Id: "), "{msg}");
                assert!(!msg.contains("Model: "), "{msg}");
                assert!(!msg.contains("Harness: "), "{msg}");
                assert!(msg.contains("Machine: "), "{msg}");
            });
        });
    }

    // --- AI_AGENT env fallback (process-global — serialized + restored) ---
    //
    // `with_ai_agent_env`/`AI_AGENT_ENV_LOCK` now live at the module level
    // (above `mod tests`), `pub(crate)`, so `persist_plan`'s tests share the
    // exact same lock — see that definition's doc for why a second,
    // independently-locked copy here would be a real cross-module race, not
    // just a duplicate. `use super::*` brings both into scope in this module.

    // --- CADENCE_MARKER_DIR (process-global — serialized + restored) ---
    //
    // Any test that reaches the nudge point also writes a session marker
    // (#370), so it is isolated to a scratch tempdir and `cargo test` never
    // writes into the real per-user marker directory (the #302/#269 class).
    //
    // This module used to carry its own `MARKER_ENV_LOCK` + `with_marker_dir`.
    // Both are gone: `CADENCE_MARKER_DIR` is one process-global, so it gets ONE
    // lock and ONE helper workspace-wide (#446) — a private copy here serializes
    // only against this module and races every other crate's marker tests in the
    // same binary. The panic-safe catch_unwind + restore-prior shape this copy
    // pioneered was promoted into the shared helper rather than lost.
    use cadence_hooks_core::test_builders::with_marker_dir;

    #[test]
    fn resolve_harness_falls_back_to_ai_agent_env_when_transcript_absent() {
        with_ai_agent_env(Some("claude-code_2-1-215_agent"), || {
            assert_eq!(resolve_harness(None), Some("2.1.215".to_string()));
        });
    }

    #[test]
    fn resolve_harness_prefers_transcript_over_ai_agent_env() {
        with_ai_agent_env(Some("claude-code_9-9-999_agent"), || {
            let content = r#"{"version":"2.1.214","message":{"role":"assistant"}}"#;
            assert_eq!(resolve_harness(Some(content)), Some("2.1.214".to_string()));
        });
    }

    // --- AI_AGENT fallback parsing ---

    #[test]
    fn parse_ai_agent_version_valid() {
        assert_eq!(
            parse_ai_agent_version("claude-code_2-1-215_agent"),
            Some("2.1.215".to_string())
        );
    }

    #[test]
    fn parse_ai_agent_version_wrong_shape_is_none() {
        assert_eq!(parse_ai_agent_version("something-else"), None);
        assert_eq!(parse_ai_agent_version("claude-code_agent"), None);
        // Prefix and suffix both match, but the version segment between them
        // is empty — never render a blank/guessed harness version.
        assert_eq!(parse_ai_agent_version("claude-code__agent"), None);
    }

    // --- heredoc delimiter parsing ---

    #[test]
    fn heredoc_delimiter_quoted_and_unquoted() {
        assert_eq!(heredoc_delimiter("$(cat <<'EOF'"), Some(("EOF", false)));
        assert_eq!(heredoc_delimiter("$(cat <<\"EOF\""), Some(("EOF", false)));
        assert_eq!(heredoc_delimiter("$(cat <<EOF"), Some(("EOF", false)));
        assert_eq!(heredoc_delimiter("$(cat <<-EOF"), Some(("EOF", true)));
        assert_eq!(heredoc_delimiter("no heredoc here"), None);
    }

    #[test]
    fn extract_heredoc_body_terminator_not_found_is_none() {
        // Single-line value: no terminator line can ever appear after it.
        assert_eq!(extract_heredoc_body("plain message, no heredoc"), None);
    }

    // --- heredoc terminator: real bash semantics (dash strips tabs, plain is exact) ---

    #[test]
    fn heredoc_dash_form_tolerates_leading_tab_indented_terminator() {
        let value = "$(cat <<-'EOF'\nbody\n\tEOF\n)";
        assert_eq!(extract_heredoc_body(value), Some("body".to_string()));
    }

    #[test]
    fn heredoc_plain_form_rejects_indented_terminator() {
        // Real bash requires an EXACT match for the plain `<<WORD` form — a
        // tab-indented terminator line does not close it, so the "terminator
        // never appears" fallback applies (never a guessed boundary).
        let value = "$(cat <<'EOF'\nbody\n\tEOF\n)";
        assert_eq!(extract_heredoc_body(value), None);
    }

    // --- documented single-heredoc-per-value limitation ---

    #[test]
    fn extract_heredoc_two_heredocs_in_one_value_only_first_extracted() {
        // A single -m value that somehow concatenates two heredoc
        // substitutions only yields the first body — everything from the
        // first terminator onward (including the second heredoc) is
        // silently dropped, never guessed at or merged. Two SEPARATE `-m`
        // flags, each with its own heredoc, are unaffected by this: each is
        // tokenized into its own value and resolved independently (see
        // `extract_multiple_dash_m_concatenated_with_blank_line`).
        let command =
            "git commit -m \"$(cat <<'A'\nfirst body\nA\n)$(cat <<'B'\nsecond body\nB\n)\"";
        assert_eq!(
            extract_commit_message(command, None),
            Some("first body".to_string())
        );
    }
}
