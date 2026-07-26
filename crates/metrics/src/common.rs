//! Shared helpers for the metrics loggers: git-commit detection, git queries,
//! metrics directory resolution, and timestamps.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Matches `git commit` and `git -C <dir> commit`, after a start-of-string or a
/// shell separator, while ignoring `git commit-tree` and similar. Ported from
/// the bash `grep -E` pattern.
fn commit_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(^|[\s;&|])git\s+(-C\s+\S+\s+)?commit(\s|$)")
            .expect("commit regex must compile")
    })
}

/// True when `command` invokes `git commit` (not `git commit-tree`, etc.).
pub fn is_git_commit(command: &str) -> bool {
    commit_regex().is_match(command)
}

/// The metrics root directory.
///
/// Resolution order:
/// 1. `CADENCE_METRICS_DIR` — when set and non-empty, the value **is** the
///    metrics dir (JSONL files and the `state/` subdir live directly inside it).
/// 2. `<config_dir>/metrics` — where `<config_dir>` honors `CLAUDE_CONFIG_DIR`
///    (else `~/.claude`).
pub fn metrics_dir() -> PathBuf {
    metrics_dir_from(std::env::var("CADENCE_METRICS_DIR").ok())
}

/// Pure resolver behind [`metrics_dir`]: takes the `CADENCE_METRICS_DIR` value
/// explicitly (rather than reading process-global env) so the resolution order
/// is unit-testable without `set_var`/`remove_var`. `None` or an empty string
/// falls through to the `<config_dir>/metrics` default.
fn metrics_dir_from(override_dir: Option<String>) -> PathBuf {
    if let Some(dir) = override_dir
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    cadence_hooks_core::paths::claude_config_dir().join("metrics")
}

/// The per-session state directory: `<metrics_dir>/state`.
pub fn state_dir() -> PathBuf {
    metrics_dir().join("state")
}

/// True when `session_id` is safe to embed in a state filename — non-empty and
/// composed only of ASCII alphanumerics, `-`, or `_`. Session IDs are UUID-like;
/// anything containing path separators or `..` is rejected so a malformed or
/// hostile payload can never steer a write outside [`state_dir`].
pub fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Build a `git` command rooted at `cwd` when it's an existing directory,
/// otherwise inheriting the process working directory (mirrors the bash
/// `cd "$cwd" && git ...` / bare-`git` fallback).
fn git_in(cwd: Option<&str>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = cwd
        && Path::new(dir).is_dir()
    {
        cmd.current_dir(dir);
    }
    cmd
}

/// Run a git command and return its trimmed stdout, or `None` on failure or
/// empty output.
fn git_output(cwd: Option<&str>, args: &[&str]) -> Option<String> {
    let mut cmd = git_in(cwd);
    cmd.args(args);
    let output = match cadence_hooks_core::shell::run_git_bounded(&mut cmd) {
        cadence_hooks_core::shell::GitSpawn::Completed(output) if output.status.success() => output,
        _ => return None,
    };
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Current `HEAD` SHA in `cwd`.
pub fn head_sha(cwd: Option<&str>) -> Option<String> {
    git_output(cwd, &["rev-parse", "HEAD"])
}

/// Current branch name in `cwd` (empty string on detached HEAD or failure).
///
/// Uses `symbolic-ref --quiet --short HEAD`, which exits non-zero on a detached
/// HEAD — so [`git_output`] yields `None` and we return empty, as documented.
/// (`rev-parse --abbrev-ref HEAD` would return the literal string `"HEAD"`.)
pub fn branch(cwd: Option<&str>) -> String {
    git_output(cwd, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default()
}

/// Repo name: the basename of the git worktree root (`rev-parse --show-toplevel`)
/// so a subdirectory name is never logged as the repo. Falls back to the
/// `cwd`/process-directory basename when not inside a git repo.
pub fn repo_basename(cwd: Option<&str>) -> String {
    let dir = match git_output(cwd, &["rev-parse", "--show-toplevel"]) {
        Some(toplevel) => PathBuf::from(toplevel),
        None => match cwd {
            Some(d) if Path::new(d).is_dir() => PathBuf::from(d),
            _ => std::env::current_dir().unwrap_or_default(),
        },
    };
    dir.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Current UTC timestamp, ISO 8601 second precision (`%Y-%m-%dT%H:%M:%SZ`).
///
/// Re-exports the canonical [`cadence_hooks_core::time::utc_timestamp`] so every
/// logger shares one timestamp source (jiff-backed, portable to Windows).
pub fn utc_timestamp() -> String {
    cadence_hooks_core::time::utc_timestamp()
}

/// Strip display-affecting characters from a file-sourced string before it is
/// interpolated into terminal output or into the `additionalContext` blob a
/// nudge injects into the agent's context.
///
/// Two families, not one. `char::is_control` covers only **Cc** — C0, DEL, C1 —
/// which handles ANSI escapes and newlines. It passes **Cf** (format)
/// characters, and those reorder rendered text without being "control"
/// characters at all: U+202E RIGHT-TO-LEFT OVERRIDE and the U+2066–U+2069
/// directional isolates are the Trojan-Source primitives. U+2028/U+2029 are
/// line/paragraph separators that some renderers break on. Strip all of them.
///
/// **The agent-context sink is the strict one.** A terminal reader sees a
/// mangled line; an injected newline in `additionalContext` starts what reads
/// as a new instruction. Anything file-sourced — a ledger field, a filename —
/// must pass through here before it reaches either sink.
pub fn display_safe(s: &str) -> String {
    s.chars().filter(|c| !is_display_unsafe(*c)).collect()
}

/// Whether `c` can alter how the rest of a line renders, or ride into an
/// agent's context invisibly: any Cc control, any Cf format character, or the
/// Unicode line/paragraph separators.
///
/// Cf is matched by explicit ranges rather than a Unicode-property crate — this
/// stays dependency-free — but the enumeration is deliberately the **whole**
/// category, not just the famous blocks. Partial coverage is the trap: the
/// obvious primitives (U+202E, the isolates) protect a *terminal*, while the
/// primitive that matters for the agent-context sink is the **Tags** block
/// (U+E0000–U+E007F). `U+E0001` plus `U+E0020`–`U+E007F` encodes arbitrary
/// ASCII that renders as nothing at all yet survives into `additionalContext`
/// and through most tokenizers — invisible text smuggling, and it is Cf, so
/// `is_control` passes it and no bidi-shaped range catches it.
///
/// So the list below is maintained against the Unicode Cf category as a whole.
/// If a future Unicode release adds a Cf block, it belongs here. `is_control`
/// already covers Cc.
fn is_display_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{2028}' | '\u{2029}'          // line / paragraph separator
            | '\u{00AD}'                      // soft hyphen
            | '\u{0600}'..='\u{0605}'         // Arabic number signs
            | '\u{061C}'                      // Arabic letter mark
            | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}'         // Arabic pound / piastre marks
            | '\u{08E2}'
            | '\u{180E}'                      // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}'         // zero-width space … RTL mark
            | '\u{202A}'..='\u{202E}'         // bidi embeddings + OVERRIDE
            | '\u{2060}'..='\u{2064}'         // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}'         // directional isolates
            | '\u{206A}'..='\u{206F}'         // deprecated format controls
            | '\u{FEFF}'                      // zero-width no-break space (BOM)
            | '\u{FFF9}'..='\u{FFFB}'         // interlinear annotation
            | '\u{110BD}' | '\u{110CD}'       // Kaithi number sign
            | '\u{13430}'..='\u{1343F}'       // Egyptian hieroglyph format
            | '\u{1BCA0}'..='\u{1BCA3}'       // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}'       // musical beam / phrase controls
            | '\u{E0000}'..='\u{E007F}'       // TAGS — invisible text smuggling
        )
}

/// [`display_safe`] plus a character ceiling — filtering alone bounds the
/// *character set* but not the *length*, and an unbounded file-sourced string
/// can still flood a terminal line or a nudge.
///
/// Truncation counts **characters, not bytes**, and slices at the boundary
/// `char_indices` reports — a byte slice at a fixed offset would panic
/// mid-codepoint on a multi-byte value, which inside a fail-open writer would
/// be a panic on the panic path.
pub fn display_safe_bounded(s: &str, max_chars: usize) -> String {
    let cleaned = display_safe(s);
    match cleaned.char_indices().nth(max_chars) {
        Some((boundary, _)) => format!("{}…", &cleaned[..boundary]),
        None => cleaned,
    }
}

/// The character a run of disallowed bytes collapses to in [`filename_safe`].
/// Deliberately not something a real ledger name contains, so a sanitized name
/// can never be mistaken for — or collide with — a legitimate one.
const FILENAME_REPLACEMENT: char = '?';

/// An **allowlist** sanitizer for a value that is a *name*, not prose: keeps
/// `[A-Za-z0-9._-]`, collapses every run of anything else to a single
/// [`FILENAME_REPLACEMENT`], and bounds the result.
///
/// **Why a second sanitizer rather than reusing [`display_safe`].** That one is
/// a denylist over the Cc and Cf categories, and a denylist cannot close this
/// class for two structural reasons:
///
/// 1. **The invisible-smuggling primitive is not confined to Cf.** Variation
///    selectors — U+FE00–U+FE0F and U+E0100–U+E01EF — are category **Mn**, so a
///    Cf-complete enumeration misses them *by construction*. They encode
///    invisible bytes exactly the way the Tags block does. Chasing that with
///    more denied ranges is a race against Unicode itself.
/// 2. **Stripping invisibles does not stop visible prose.** A name is
///    attacker-chosen text landing inside a sentence in the agent's context;
///    removing newlines demotes a fake system turn to an inline instruction, it
///    does not remove it. The allowlist excludes the SPACE character, so smuggled
///    prose arrives as `Disregard?the?above` — visibly mangled rather than
///    fluent.
///
/// Real ledger names (`commits.jsonl`, `askuserquestion.jsonl`) satisfy the
/// allowlist exactly, so the constraint costs nothing on every legitimate input.
///
/// Runs collapse rather than delete, which also keeps the result **injective
/// enough**: deleting would map `commits\u{200B}.jsonl` onto the real
/// `commits.jsonl`, merging a hostile entry with a live one and letting a dead
/// stream read as alive. Replacement keeps them distinct.
///
/// Use [`display_safe`] instead for diagnostic *prose* (an error message), where
/// spaces and punctuation are legitimate content.
pub fn filename_safe(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars));
    let mut chars = 0usize;
    let mut in_run = false;
    for c in s.chars() {
        if chars >= max_chars {
            out.push('…');
            break;
        }
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
            chars += 1;
            in_run = false;
        } else if !in_run {
            out.push(FILENAME_REPLACEMENT);
            chars += 1;
            in_run = true;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Schema versioning (the metrics data contract)
// ---------------------------------------------------------------------------
//
// A metrics stream MAY stamp an explicit integer `schemaVersion` on every row
// so consumers branch on a declared contract version instead of probing field
// presence. Each stream's version is a `*_SCHEMA_VERSION` constant defined here
// — one greppable source of truth — read by that stream's logger. Keep the
// constant and the stream's row in `plugins/cadence-metrics/docs/schema.md`
// (cadence repo) in lockstep.
//
// Bump policy (Keep-a-Changelog for the data contract):
//   - ADDITIVE change (new nullable field, new `event` enum value): DO NOT bump.
//     Old consumers keep working; the field/value is simply absent or unseen on
//     older rows.
//   - BREAKING change (field renamed / removed / retyped, or a field's meaning
//     changes): bump the stream's constant by 1 and document the cutover in a
//     "Schema version history" note in `schema.md`.
//
// Streams predating this convention (`commits` / `subagents` / `denials` /
// `sessions`) are implicitly version 0. They adopt a constant here on their
// *next* shape change (opportunistic adoption, cadence#238) — historical
// un-stamped lines are never backfilled.

/// Schema version stamped on every `skills.jsonl` row.
pub const SKILL_SCHEMA_VERSION: u32 = 1;

/// Schema version stamped on every `askuserquestion.jsonl` row (both
/// `asked` and `answered` phases).
pub const ASKUSERQUESTION_SCHEMA_VERSION: u32 = 1;

/// Crate-wide serialization lock for env-mutating tests.
///
/// `CADENCE_METRICS_DIR` and its siblings are process-global, so every test that
/// `set_var`/`remove_var`s one must hold *this one* lock — a per-module lock only
/// serializes within its own module and lets tests in different modules
/// (`log_denial`, `log_timing`, …) race on the same global.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    // `metrics_dir`'s resolution order is tested through the pure
    // `metrics_dir_from` helper, so these tests never touch process-global env
    // (no `set_var`/`remove_var`, no serialization lock, no cross-test leakage).

    #[test]
    fn metrics_dir_override_via_cadence_metrics_dir() {
        // A non-empty override value becomes the metrics dir verbatim.
        assert_eq!(
            metrics_dir_from(Some("/tmp/cadence-test-metrics".to_string())),
            std::path::PathBuf::from("/tmp/cadence-test-metrics")
        );
    }

    #[test]
    fn metrics_dir_fallback_contains_metrics() {
        // No override → the `<config_dir>/metrics` default.
        let dir = metrics_dir_from(None);
        assert!(
            dir.to_string_lossy().contains("metrics"),
            "fallback metrics_dir should contain 'metrics': {dir:?}"
        );
    }

    #[test]
    fn metrics_dir_empty_override_falls_through() {
        // An empty CADENCE_METRICS_DIR must not shadow the default (guards the
        // `!dir.is_empty()` branch).
        let dir = metrics_dir_from(Some(String::new()));
        assert!(
            dir.to_string_lossy().contains("metrics"),
            "empty override should fall through to default: {dir:?}"
        );
    }

    #[test]
    fn detects_plain_git_commit() {
        assert!(is_git_commit("git commit -m 'x'"));
        assert!(is_git_commit("git commit"));
    }

    #[test]
    fn detects_git_c_commit() {
        assert!(is_git_commit("git -C /some/repo commit -m x"));
    }

    #[test]
    fn detects_commit_after_separator() {
        assert!(is_git_commit("cd repo && git commit -m x"));
        assert!(is_git_commit("foo; git commit"));
    }

    #[test]
    fn ignores_commit_tree() {
        assert!(!is_git_commit("git commit-tree abc123"));
    }

    #[test]
    fn ignores_non_commit_git() {
        assert!(!is_git_commit("git status"));
        assert!(!is_git_commit("git push origin main"));
    }

    #[test]
    fn ignores_unrelated_commands() {
        assert!(!is_git_commit("echo committing changes"));
        assert!(!is_git_commit("ls -la"));
    }

    #[test]
    fn safe_session_id_accepts_uuid_like() {
        assert!(is_safe_session_id("a1b2c3d4-5e6f-7890-abcd-ef0123456789"));
        assert!(is_safe_session_id("session_42"));
        assert!(is_safe_session_id("ABC-123_xyz"));
    }

    #[test]
    fn safe_session_id_rejects_traversal_and_separators() {
        assert!(!is_safe_session_id(""));
        assert!(!is_safe_session_id(".."));
        assert!(!is_safe_session_id("../../etc/passwd"));
        assert!(!is_safe_session_id("a/b"));
        assert!(!is_safe_session_id("a.before")); // '.' is not allowed
        assert!(!is_safe_session_id("with space"));
        assert!(!is_safe_session_id("/abs"));
    }

    #[test]
    fn timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        // e.g. 2026-05-19T00:51:45Z — 20 chars, ends in Z.
        assert!(ts.ends_with('Z'), "timestamp should end in Z: {ts}");
        assert_eq!(ts.len(), 20, "ISO second-precision UTC is 20 chars: {ts}");
    }
}
