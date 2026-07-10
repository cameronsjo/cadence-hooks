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

/// Schema version stamped on every `plan-phases.jsonl` row.
pub const PLAN_PHASE_SCHEMA_VERSION: u32 = 1;

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
