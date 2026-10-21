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
//! A second, unrelated nudge rides the same hook (cadence-hooks#1439): a
//! `git commit --no-edit` that would finish a conflicted merge whose message
//! carries trailers. See [`conflicts_after_trailers_nudge`].
//!
//! Detection reuses [`crate::branch_drift::is_git_commit`] (the sibling
//! PreToolUse-Bash-commit check) and `cadence_hooks_core::shell`'s existing
//! parsers (`tokenize`, `strip_quotes`) rather than a third hand-rolled
//! git-commit parser.

use crate::identity;
use crate::provenance;
use cadence_hooks_core::paths;
use cadence_hooks_core::shell::{is_assignment_word, strip_quotes, tokenize};
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
    if input.normalized_tool_name() != Some("Bash") {
        return CheckResult::allow();
    }
    let Some(command) = input.command() else {
        return CheckResult::allow();
    };
    if !crate::branch_drift::is_git_commit(&strip_quotes(command)) {
        return CheckResult::allow();
    }

    // A conflicted merge finished with `--no-edit` reuses MERGE_MSG, which git
    // ended with a `# Conflicts:` block. That is state, not a message the
    // command carries, so it is judged before the message is extracted and
    // does not spend the once-per-session marker below (#1439).
    if let Some(nudge) = conflicts_after_trailers_nudge(command, input.cwd.as_deref()) {
        return CheckResult::nudge(nudge);
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
// Nudge: a conflicted merge's `# Conflicts:` block below the trailers (#1439)
// ---------------------------------------------------------------------------

/// The header line git appends to MERGE_MSG when a merge stops on conflicts.
const CONFLICTS_HEADER: &str = "# Conflicts:";

/// The nudge text. Static: the merge message is untrusted, so none of it is
/// echoed.
const CONFLICTS_AFTER_TRAILERS_NUDGE: &str = "A merge is waiting on this commit, and its pending \
    message (MERGE_MSG) has git's `# Conflicts:` block below the trailers. `git commit \
    --no-edit` keeps `#` lines under its default cleanup (`whitespace`), so the commit would \
    land with that block after the trailers, and they would no longer be the final paragraph; a \
    lint or tool that reads the final paragraph then misses them. If no other line of the \
    message starts with `#`, run `git commit --no-edit --cleanup=strip`. It removes the block, \
    but it drops every line that starts with `#`, an issue reference or a markdown heading \
    included, with no warning. If the message has such lines, copy the file `git rev-parse \
    --git-path MERGE_MSG` prints, cut the `# Conflicts:` line and everything after it, and run \
    `git commit -F <copy>` instead.";

/// Nudge when this command is a `git commit --no-edit` that would finish a
/// conflicted merge, and the merge message has trailers followed by git's
/// `# Conflicts:` block.
///
/// Every condition has to be read exactly, or the nudge stays silent (the
/// check never blocks, ADR-0001):
///
/// - the command has a segment that is `git commit` with nothing between the
///   two words (`git -C dir commit` names a repo this does not resolve) and
///   `--no-edit`, and none of `-m`/`--message`, `-F`/`--file`, `-C`/`-c`
///   (reuse a message), `--cleanup` or `-e`/`--edit` — each of those names the
///   message or how it is cleaned, or opens an editor whose default cleanup
///   strips the block, so MERGE_MSG's block is not what lands;
/// - the directory the command runs in (after any `cd` chain) is in a git
///   repository with a `MERGE_HEAD`;
/// - that repository's MERGE_MSG reads under the size cap and passes
///   [`conflicts_block_follows_trailers`].
fn conflicts_after_trailers_nudge(command: &str, cwd: Option<&str>) -> Option<String> {
    let cwd = cwd?;
    let args = cadence_hooks_core::shell::split_segments_with_ops(command)
        .into_iter()
        .find_map(|(segment, _)| no_edit_commit_args(&tokenize(&segment)))?;
    if !finishes_with_merge_msg(&args) {
        return None;
    }
    let work_dir = cadence_hooks_core::shell::parse_work_dir(command, cwd);
    let git_dir =
        cadence_hooks_core::shell::git_command(&work_dir, &["rev-parse", "--absolute-git-dir"])?;
    let git_dir = Path::new(&git_dir);
    if !git_dir.join("MERGE_HEAD").is_file() {
        return None;
    }
    let merge_msg =
        paths::read_capped_nofollow(&git_dir.join("MERGE_MSG"), MAX_MESSAGE_FILE_BYTES)?;
    conflicts_block_follows_trailers(&merge_msg).then(|| CONFLICTS_AFTER_TRAILERS_NUDGE.to_string())
}

/// The arguments after `commit` when `tokens` is a plain `git commit` (leading
/// `VAR=value` words allowed, no git options before the subcommand).
fn no_edit_commit_args(tokens: &[String]) -> Option<Vec<String>> {
    let mut words = tokens.iter().skip_while(|t| is_assignment_word(t));
    if words.next().map(String::as_str) != Some("git") {
        return None;
    }
    if words.next().map(String::as_str) != Some("commit") {
        return None;
    }
    Some(words.cloned().collect())
}

/// True when `args` (after `git commit`) ask for `--no-edit` and name no
/// message source or cleanup mode of their own.
fn finishes_with_merge_msg(args: &[String]) -> bool {
    let mut no_edit = false;
    for arg in args {
        match arg.as_str() {
            "--no-edit" => no_edit = true,
            "--message" | "--file" | "--cleanup" | "--reuse-message" | "--reedit-message"
            | "--edit" => {
                return false;
            }
            long if long.starts_with("--message=")
                || long.starts_with("--file=")
                || long.starts_with("--cleanup=")
                || long.starts_with("--reuse-message=")
                || long.starts_with("--reedit-message=") =>
            {
                return false;
            }
            // A short-option cluster (`-m`, `-am`, `-F`, `-C`, `-c`, `-e`) that
            // carries a message, reuse or edit flag. A value word never starts with
            // a dash that is a lone `-`.
            short
                if short.starts_with('-')
                    && !short.starts_with("--")
                    && short.len() > 1
                    && short
                        .chars()
                        .skip(1)
                        .any(|c| matches!(c, 'm' | 'F' | 'C' | 'c' | 'e')) =>
            {
                return false;
            }
            _ => {}
        }
    }
    no_edit
}

/// True when `merge_msg` holds git's `# Conflicts:` header and the paragraph
/// just above it has a trailer line (`Token: value`).
///
/// The first paragraph is the subject, never a trailer block, so a subject
/// like `fix: thing` does not count (git applies the same rule).
fn conflicts_block_follows_trailers(merge_msg: &str) -> bool {
    let lines: Vec<&str> = merge_msg.lines().collect();
    let Some(header) = lines.iter().position(|l| l.trim_end() == CONFLICTS_HEADER) else {
        return false;
    };
    let Some(last) = lines[..header].iter().rposition(|l| !l.trim().is_empty()) else {
        return false;
    };
    let first = lines[..=last]
        .iter()
        .rposition(|l| l.trim().is_empty())
        .map_or(0, |blank| blank + 1);
    first > 0 && lines[first..=last].iter().any(|l| is_trailer_line(l))
}

/// `Token: value` — a token of letters, digits and hyphens that starts with a
/// letter, then a colon and whitespace (git's trailer shape, minus the
/// configurable separators).
fn is_trailer_line(line: &str) -> bool {
    let Some((token, rest)) = line.split_once(':') else {
        return false;
    };
    token
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && rest.starts_with(char::is_whitespace)
}

// ---------------------------------------------------------------------------
// Nudge: the computed producer-tuple trailer block
// ---------------------------------------------------------------------------

/// The `Machine:` value: a fixed `cloud` in a cloud session, where a hostname
/// digest identifies a throwaway VM (cameronsjo/cadence-hooks#1197).
fn machine_field(host: &str) -> String {
    machine_field_for(host, cadence_hooks_core::remote::is_remote())
}

fn machine_field_for(host: &str, remote: bool) -> String {
    if remote {
        cadence_hooks_core::remote::CLOUD_MACHINE.to_string()
    } else {
        provenance::machine_digest(host)
    }
}

/// Render the nudge: an instruction line plus the trailer block, with each
/// tuple field's line present only when resolvable — an unresolvable field
/// is omitted, never rendered blank or guessed (the nudge's job is making
/// compliance easy, not being complete).
///
/// The transcript is read AT MOST ONCE per run (not once for `Model:` and
/// again for `Harness:`) — its content is threaded to both resolvers.
/// `Model:`/`Harness:` are transcript- or env-sourced text, not the
/// hardened Session-Id/Machine fields, so each is passed through
/// `identity::sanitize_field` before interpolation: a crafted transcript
/// `model`/`version` value, or an `AI_AGENT` env value, could otherwise
/// smuggle newlines (serde decodes `\n` escapes to real control bytes) or
/// oversized text into the nudge Claude reads as context.
fn build_nudge(input: &HookInput, host: &str) -> String {
    let mut lines = Vec::new();
    if let Some(session_id) = resolve_session_id(input) {
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
    lines.push(format!("Machine: {}", machine_field(host)));

    format!(
        "This commit message doesn't carry a `{SESSION_ID_MARKER}` trailer. For traceable \
         provenance, consider appending this computed block to the commit message:\n\n{}",
        lines.join("\n")
    )
}

/// The session's id, when the payload carries one that is safe to render. A
/// missing or unsafe id omits the `Session-Id:` line rather than rendering an
/// untrusted value into the nudge Claude reads as context — same discipline as
/// `persist_plan`'s and `branch_drift`'s session-id handling.
fn resolve_session_id(input: &HookInput) -> Option<String> {
    input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
        .map(str::to_string)
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

    #[test]
    fn machine_field_is_cloud_only_when_remote() {
        assert_eq!(machine_field_for("host", true), "cloud");
        assert_eq!(
            machine_field_for("host", false),
            provenance::machine_digest("host")
        );
        assert_ne!(machine_field_for("host", false), "cloud");
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
                !msg.contains("Session-Name"),
                "the name half of the tuple is retired: {msg}"
            );
            assert!(
                msg.lines().any(|l| l == "Session-Id: cedar-session-id"),
                "Session-Id leads the suggested block: {msg}"
            );
            assert!(msg.contains("Model: claude-fable-5"), "{msg}");
            assert!(msg.contains("Harness: claude-code 2.1.214"), "{msg}");
            assert!(
                // `machine_field` follows the ambient CLAUDE_CODE_REMOTE, so the
                // expectation does too; both branches are pinned in
                // `machine_field_is_cloud_only_when_remote`.
                msg.contains(&format!("Machine: {}", machine_field("sjomba.local"))),
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

    // --- a conflicted merge's `# Conflicts:` block below the trailers (#1439) ---

    const TRAILERS_MESSAGE: &str =
        "Merge feat\n\nSession-Id: 1111\nModel: m\nCo-Authored-By: Claude <n@a>";

    /// `git` in `dir` with discovery vars cleared (a concurrent test must not
    /// redirect it) and no exit-code check: a conflicted merge exits 1. The
    /// comment character and commit cleanup are pinned to git's defaults, so a
    /// developer's global `core.commentChar` or `commit.cleanup` cannot change
    /// what MERGE_MSG or a landed commit looks like.
    fn raw_git(dir: &Path, args: &[&str]) -> std::process::Output {
        let mut cmd = std::process::Command::new("git");
        for var in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            cmd.env_remove(var);
        }
        cmd.args(["-c", "commit.gpgsign=false"])
            .args(["-c", "core.commentChar=#"])
            .args(["-c", "commit.cleanup=default"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap()
    }

    /// A repo on `main` with a `feat` branch that changes `f.txt` the other
    /// way, so merging or cherry-picking `feat` conflicts. `feat`'s tip commit
    /// carries `feat_message`.
    fn diverged_repo(feat_message: &str) -> tempfile::TempDir {
        use cadence_hooks_core::git_fixtures::init_repo;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        init_repo(p);
        let ok = |args: &[&str]| {
            let out = raw_git(p, args);
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        ok(&["switch", "-q", "-c", "feat"]);
        std::fs::write(p.join("f.txt"), "feat").unwrap();
        ok(&["commit", "-q", "-am", feat_message]);
        ok(&["switch", "-q", "main"]);
        std::fs::write(p.join("f.txt"), "main").unwrap();
        ok(&["commit", "-q", "-am", "main change"]);
        dir
    }

    /// A repo stopped mid-merge on a conflict in `f.txt`, the merge started
    /// with `git merge --no-ff -m <merge_message> feat`.
    fn conflicted_merge(merge_message: &str) -> tempfile::TempDir {
        let dir = diverged_repo("feat");
        let p = dir.path();
        let merge = raw_git(p, &["merge", "--no-ff", "-m", merge_message, "feat"]);
        assert!(!merge.status.success(), "the merge must stop on a conflict");
        assert!(p.join(".git/MERGE_HEAD").is_file());
        dir
    }

    fn run_in(command: &str, cwd: &Path) -> CheckResult {
        let input = bash_input(command, Some("sid"), cwd.to_str(), None);
        run_warn_commit_provenance(&input, "host")
    }

    fn is_conflicts_nudge(result: &CheckResult) -> bool {
        result
            .message
            .as_deref()
            .is_some_and(|m| m.contains("# Conflicts:"))
    }

    #[test]
    fn no_edit_commit_of_a_conflicted_merge_with_trailers_nudges_to_strip_the_block() {
        let repo = conflicted_merge(TRAILERS_MESSAGE);
        let result = run_in("git commit --no-edit", repo.path());
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(
            msg.contains("git commit --no-edit --cleanup=strip"),
            "the nudge names the action: {msg}"
        );
        assert!(msg.contains("# Conflicts:"), "{msg}");
        assert!(
            msg.contains("drops every line that starts with `#`")
                && msg.contains("git rev-parse --git-path MERGE_MSG")
                && msg.contains("git commit -F <copy>"),
            "the nudge says what strip drops and gives the safe route: {msg}"
        );
        assert!(
            !msg.contains("keeps the rest"),
            "strip does not keep the rest of the message: {msg}"
        );
        assert!(
            !msg.contains("1111") && !msg.contains("Co-Authored-By"),
            "the merge message is untrusted and never echoed: {msg}"
        );
    }

    #[test]
    fn the_conflicts_nudge_finds_the_commit_in_a_chain_or_after_a_cd() {
        let repo = conflicted_merge(TRAILERS_MESSAGE);
        let dir = repo.path().to_str().unwrap();
        for (command, cwd) in [
            ("git add -A && git commit --no-edit", repo.path()),
            ("GIT_EDITOR=true git commit --no-edit", repo.path()),
            ("GIT_SSH_COMMAND+=x git commit --no-edit", repo.path()),
            ("git commit -a --no-edit -S", repo.path()),
            (&format!("cd {dir} && git commit --no-edit"), Path::new("/")),
        ] {
            let result = run_in(command, cwd);
            assert!(
                is_conflicts_nudge(&result),
                "{command}: {:?}",
                result.message
            );
            assert_eq!(result.outcome, Outcome::Nudge, "{command}");
        }
    }

    #[test]
    fn the_conflicts_nudge_stays_silent_when_the_command_names_its_own_message_or_cleanup() {
        let repo = conflicted_merge(TRAILERS_MESSAGE);
        let file = repo.path().join("msg.txt");
        std::fs::write(&file, "Merge feat\n\nSession-Id: 2222\n").unwrap();
        let from_file = format!("git commit --no-edit -F {}", file.display());
        for command in [
            // The strip is already asked for, or another cleanup is chosen.
            "git commit --no-edit --cleanup=strip",
            "git commit --no-edit --cleanup strip",
            "git commit --no-edit --cleanup=whitespace",
            // The message comes from the command, not MERGE_MSG. These carry
            // a Session-Id so the provenance nudge stays out of the way too.
            "git commit --no-edit -m 'Merge feat Session-Id: 3'",
            "git commit --no-edit -am 'Merge feat Session-Id: 3'",
            "git commit --no-edit --message='Merge feat Session-Id: 3'",
            "git commit --no-edit -C HEAD",
            "git commit --no-edit --reuse-message=HEAD",
            from_file.as_str(),
            // The editor's default cleanup strips the block.
            "git commit --no-edit --edit",
            "git commit --no-edit -e",
            // No `--no-edit`: git would open an editor, not reuse the block.
            "git commit",
            "git commit -a",
            // A git option before the subcommand may name another repo.
            &format!("git -C {} commit --no-edit", repo.path().display()),
        ] {
            let result = run_in(command, Path::new("/"));
            assert!(
                !is_conflicts_nudge(&result),
                "{command}: {:?}",
                result.message
            );
            let result = run_in(command, repo.path());
            assert!(
                !is_conflicts_nudge(&result),
                "{command}: {:?}",
                result.message
            );
        }
    }

    #[test]
    fn the_conflicts_nudge_needs_trailers_above_the_block() {
        // No trailers at all, and a conventional subject that has the shape of
        // one but is the first paragraph, never a trailer block.
        for message in ["Merge feat", "fix: resolve the merge"] {
            let repo = conflicted_merge(message);
            let result = run_in("git commit --no-edit", repo.path());
            assert!(
                !is_conflicts_nudge(&result),
                "{message}: {:?}",
                result.message
            );
        }
    }

    #[test]
    fn the_conflicts_nudge_needs_a_merge_in_progress() {
        let repo = tempfile::tempdir().unwrap();
        cadence_hooks_core::git_fixtures::init_repo(repo.path());
        let result = run_in("git commit --no-edit", repo.path());
        assert!(!is_conflicts_nudge(&result), "{:?}", result.message);
        // A directory that is not a repo at all.
        let plain = tempfile::tempdir().unwrap();
        let result = run_in("git commit --no-edit", plain.path());
        assert!(!is_conflicts_nudge(&result), "{:?}", result.message);
    }

    #[test]
    fn the_conflicts_nudge_needs_a_merge_head_not_just_a_conflicted_message() {
        // A conflicted cherry-pick writes MERGE_MSG with the picked commit's
        // trailers above git's `# Conflicts:` block, but leaves
        // CHERRY_PICK_HEAD, not MERGE_HEAD. The nudge is for merges only.
        let repo = diverged_repo("feat\n\nSession-Id: 1111\nCo-Authored-By: Claude <n@a>");
        let pick = raw_git(repo.path(), &["cherry-pick", "feat"]);
        assert!(!pick.status.success(), "the pick must stop on a conflict");
        let git_dir = repo.path().join(".git");
        assert!(git_dir.join("CHERRY_PICK_HEAD").is_file());
        assert!(!git_dir.join("MERGE_HEAD").exists());
        let merge_msg = std::fs::read_to_string(git_dir.join("MERGE_MSG")).unwrap();
        assert!(
            conflicts_block_follows_trailers(&merge_msg),
            "the fixture must hold trailers above the block: {merge_msg:?}"
        );
        let result = run_in("git commit --no-edit", repo.path());
        assert!(!is_conflicts_nudge(&result), "{:?}", result.message);
    }

    #[test]
    fn the_conflicts_nudge_stays_silent_without_a_cwd() {
        // With no `cwd` in the payload the hook cannot say which repo the
        // command runs in. The `cd` names an absolute conflicted repo, so a
        // fallback to "." would find it and nudge.
        let repo = conflicted_merge(TRAILERS_MESSAGE);
        let command = format!("cd {} && git commit --no-edit", repo.path().display());
        let with_cwd = run_in(&command, Path::new("/"));
        assert!(is_conflicts_nudge(&with_cwd), "{:?}", with_cwd.message);
        let input = bash_input(&command, Some("sid"), None, None);
        let result = run_warn_commit_provenance(&input, "host");
        assert!(!is_conflicts_nudge(&result), "{:?}", result.message);
    }

    /// MERGE_MSG is read under the 64 KB cap and without following a symlink,
    /// and a FIFO there must not stall the hook. Each swap leaves a message
    /// that would nudge if it were read, so silence means the read refused it.
    #[test]
    fn the_conflicts_nudge_reads_merge_msg_under_the_cap_and_without_following_links() {
        let repo = conflicted_merge(TRAILERS_MESSAGE);
        let merge_msg = repo.path().join(".git/MERGE_MSG");
        let original = std::fs::read_to_string(&merge_msg).unwrap();
        assert!(
            is_conflicts_nudge(&run_in("git commit --no-edit", repo.path())),
            "control: the untouched MERGE_MSG nudges"
        );

        // Over the cap, with trailers above the block.
        let (subject, rest) = original.split_once("\n\n").unwrap();
        let oversized = format!(
            "{subject}\n\n{}\n\n{rest}",
            "x".repeat(MAX_MESSAGE_FILE_BYTES as usize + 1)
        );
        assert!(oversized.len() as u64 > MAX_MESSAGE_FILE_BYTES);
        assert!(conflicts_block_follows_trailers(&oversized));
        std::fs::write(&merge_msg, &oversized).unwrap();
        let result = run_in("git commit --no-edit", repo.path());
        assert!(
            !is_conflicts_nudge(&result),
            "an oversized MERGE_MSG is not read: {:?}",
            result.message
        );

        #[cfg(unix)]
        {
            // A symlink to a valid trailers+block message.
            let real = repo.path().join(".git/MERGE_MSG.real");
            std::fs::write(&real, &original).unwrap();
            std::fs::remove_file(&merge_msg).unwrap();
            std::os::unix::fs::symlink(&real, &merge_msg).unwrap();
            let result = run_in("git commit --no-edit", repo.path());
            assert!(
                !is_conflicts_nudge(&result),
                "a symlinked MERGE_MSG is not followed: {:?}",
                result.message
            );

            // A FIFO with no writer: opening it for reading blocks forever.
            // The hook runs on a thread so a regression fails the test rather
            // than hanging it.
            std::fs::remove_file(&merge_msg).unwrap();
            let made = std::process::Command::new("mkfifo")
                .arg(&merge_msg)
                .status()
                .unwrap();
            assert!(made.success(), "mkfifo");
            let (tx, rx) = std::sync::mpsc::channel();
            let dir = repo.path().to_path_buf();
            std::thread::spawn(move || {
                let _ = tx.send(run_in("git commit --no-edit", &dir));
            });
            let result = rx
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("a FIFO at MERGE_MSG must not stall the hook");
            assert!(
                !is_conflicts_nudge(&result),
                "a FIFO MERGE_MSG is not read: {:?}",
                result.message
            );
        }
    }

    #[test]
    fn the_conflicts_nudge_does_not_spend_the_provenance_marker() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = conflicted_merge(TRAILERS_MESSAGE);
            let conflicts = run_in("git commit --no-edit", repo.path());
            assert!(is_conflicts_nudge(&conflicts));
            // The trailer-less commit that follows still gets its own nudge.
            let plain = run_in("git commit -m 'fix: thing'", repo.path());
            assert_eq!(plain.outcome, Outcome::Nudge);
            assert!(
                plain.message.unwrap().contains(SESSION_ID_MARKER),
                "the provenance nudge fires once the conflicts nudge has"
            );
        });
    }

    #[test]
    fn conflicts_block_follows_trailers_table() {
        let block = "# Conflicts:\n#\tf.txt\n";
        // (merge message, expected)
        let cases: &[(String, bool)] = &[
            (format!("Merge x\n\nSession-Id: 1\n\n{block}"), true),
            (
                format!("Merge x\n\nbody\n\nCo-Authored-By: A <a@b>\n\n{block}"),
                true,
            ),
            (format!("Merge x\n\nSigned-off-by: A <a@b>\n{block}"), true),
            // Subject only, or a subject shaped like a trailer.
            (format!("Merge x\n\n{block}"), false),
            (format!("fix: thing\n\n{block}"), false),
            (format!("Merge x\n{block}"), false),
            // A body paragraph that is prose, not a trailer.
            (
                format!("Merge x\n\nResolved the clash by hand.\n\n{block}"),
                false,
            ),
            // Lines with a colon that are not trailers: a URL (no whitespace
            // after the colon), a token with spaces, a token that starts with
            // a digit.
            (
                format!("Merge x\n\nhttps://example.com/x\n\n{block}"),
                false,
            ),
            (
                format!("Merge x\n\nResolved by hand: kept both.\n\n{block}"),
                false,
            ),
            (format!("Merge x\n\n1st: thing\n\n{block}"), false),
            // One trailer line is enough in a paragraph that also has prose.
            (
                format!("Merge x\n\nResolved the clash by hand.\nSession-Id: 1\n\n{block}"),
                true,
            ),
            // The header but nothing above it, and no header at all.
            (block.to_string(), false),
            ("Merge x\n\nSession-Id: 1\n".to_string(), false),
            // Trailers that sit below the block are not "followed by" it.
            (format!("Merge x\n\n{block}\nSession-Id: 1\n"), false),
            // A header with trailing text is not git's header line.
            (
                "Merge x\n\nSession-Id: 1\n\n# Conflicts: none\n".to_string(),
                false,
            ),
        ];
        for (message, want) in cases {
            assert_eq!(
                conflicts_block_follows_trailers(message),
                *want,
                "{message:?}"
            );
        }
    }

    #[test]
    fn finishes_with_merge_msg_reads_the_flags() {
        let args = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        for (flags, want) in [
            ("--no-edit", true),
            ("-a --no-edit", true),
            ("--no-edit --no-verify -S", true),
            ("-a", false),
            ("--no-edit -m x", false),
            ("--no-edit -sm x", false),
            ("--no-edit -F f", false),
            ("--no-edit --file=f", false),
            ("--no-edit -c HEAD", false),
            ("--no-edit --cleanup=strip", false),
            ("--no-edit --message x", false),
            ("--no-edit --reuse-message HEAD", false),
            ("--no-edit --file f", false),
            ("--no-edit --reedit-message HEAD", false),
            ("--no-edit --reedit-message=HEAD", false),
            ("--no-edit --edit", false),
            ("--no-edit -e", false),
            ("--no-edit -ae", false),
        ] {
            assert_eq!(finishes_with_merge_msg(&args(flags)), want, "{flags}");
        }
    }

    /// The nudge's advice, run for real: `--no-edit` alone leaves the block
    /// below the trailers, `--no-edit --cleanup=strip` removes it and leaves
    /// the trailers as the final paragraph.
    #[test]
    fn the_advised_cleanup_strips_the_block_and_the_plain_commit_keeps_it() {
        let landed = |flags: &[&str]| {
            let repo = conflicted_merge(TRAILERS_MESSAGE);
            std::fs::write(repo.path().join("f.txt"), "resolved").unwrap();
            assert!(raw_git(repo.path(), &["add", "f.txt"]).status.success());
            let mut args = vec!["commit", "--no-edit"];
            args.extend_from_slice(flags);
            let out = raw_git(repo.path(), &args);
            assert!(out.status.success(), "{args:?}: {out:?}");
            let body = raw_git(repo.path(), &["log", "-1", "--format=%B"]);
            String::from_utf8(body.stdout).unwrap()
        };
        let plain = landed(&[]);
        let conflicts = plain.find("# Conflicts:").expect("kept without cleanup");
        let last_trailer = plain.find("Co-Authored-By:").unwrap();
        assert!(
            conflicts > last_trailer,
            "the block sits below the trailers"
        );
        let stripped = landed(&["--cleanup=strip"]);
        assert!(!stripped.contains("# Conflicts:"), "{stripped:?}");
        assert!(
            stripped
                .trim_end()
                .ends_with("Co-Authored-By: Claude <n@a>"),
            "the trailers are the final paragraph: {stripped:?}"
        );
    }

    /// The nudge's warning and its safe route, run for real: `--cleanup=strip`
    /// also drops body lines that start with `#`, while committing a copy of
    /// MERGE_MSG cut at the `# Conflicts:` line with `-F` keeps them and
    /// still leaves the trailers as the final paragraph.
    #[test]
    fn strip_drops_other_hash_lines_and_the_file_route_keeps_them() {
        let message = "Merge feat\n\n#1439 is the issue this closes.\n## A heading\n\n\
                       Session-Id: 1111\nCo-Authored-By: Claude <n@a>";
        let resolved = || {
            let repo = conflicted_merge(message);
            std::fs::write(repo.path().join("f.txt"), "resolved").unwrap();
            assert!(raw_git(repo.path(), &["add", "f.txt"]).status.success());
            repo
        };
        let body_of = |repo: &Path| {
            let out = raw_git(repo, &["log", "-1", "--format=%B"]);
            String::from_utf8(out.stdout).unwrap()
        };

        let repo = resolved();
        let out = raw_git(repo.path(), &["commit", "--no-edit", "--cleanup=strip"]);
        assert!(out.status.success(), "{out:?}");
        let stripped = body_of(repo.path());
        assert!(!stripped.contains("# Conflicts:"), "{stripped:?}");
        assert!(
            !stripped.contains("#1439") && !stripped.contains("## A heading"),
            "strip drops every line that starts with `#`: {stripped:?}"
        );

        let repo = resolved();
        let path = raw_git(repo.path(), &["rev-parse", "--git-path", "MERGE_MSG"]);
        let path = repo
            .path()
            .join(String::from_utf8(path.stdout).unwrap().trim());
        let merge_msg = std::fs::read_to_string(path).unwrap();
        let cut: Vec<&str> = merge_msg
            .lines()
            .take_while(|l| l.trim_end() != CONFLICTS_HEADER)
            .collect();
        let scratch = tempfile::tempdir().unwrap();
        let copy = scratch.path().join("msg.txt");
        std::fs::write(&copy, format!("{}\n", cut.join("\n"))).unwrap();
        let out = raw_git(repo.path(), &["commit", "-F", copy.to_str().unwrap()]);
        assert!(out.status.success(), "{out:?}");
        let kept = body_of(repo.path());
        assert!(!kept.contains("# Conflicts:"), "{kept:?}");
        assert!(
            kept.contains("#1439 is the issue this closes.") && kept.contains("## A heading"),
            "the file route keeps the other `#` lines: {kept:?}"
        );
        assert!(
            kept.trim_end().ends_with("Co-Authored-By: Claude <n@a>"),
            "the trailers are the final paragraph: {kept:?}"
        );
    }
}
