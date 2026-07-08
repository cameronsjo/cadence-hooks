//! Append-only audit log for guard fires at the dispatch outcome→exit-code
//! seam: one line per hard `deny` to `<metrics_dir>/denials.jsonl` (and per
//! `nudge` when `CADENCE_LOG_NUDGES` is set).
//!
//! Called from the **binary** (`src/dispatch.rs`), not from a `Logger`: the
//! denial is a side effect of an *enforcement* check, and only the binary knows
//! the canonical registry hook name (`check.name()` diverges from it). The write
//! must never perturb the block it is recording — every step is fail-open per
//! ADR-0001, so a full disk or a read-only metrics dir degrades to a no-op and
//! the guard still exits 2 with its unchanged stderr.
//!
//! **Privacy by construction:** the record names *which guard fired on which
//! tool in which repo* — never *what was blocked*. It never reads the command
//! text, file path, or edited content off the [`HookInput`]; a unit test asserts
//! those keys are absent.

use crate::common;
use cadence_hooks_core::{HookEvent, HookInput, Outcome};
use serde_json::{Value, json};
use std::io::Write;

/// Record a guard's decision at the dispatch seam.
///
/// - `Block` → always logged as `decision: "deny"`.
/// - `Nudge` / `LoopBlock` → logged as `decision: "nudge"` **only** when
///   `CADENCE_LOG_NUDGES` is set to a non-empty value (default OFF, so the
///   common advisory path adds zero hot-path I/O).
/// - `Allow` → never logged.
///
/// `hook` is the canonical registry name threaded from the binary (e.g.
/// `terminology`, not the `Check::name()` value `terminology-guard`).
pub fn log_denial(hook: &str, event: HookEvent, input: &HookInput, outcome: Outcome) {
    let Some(decision) = decision_for(outcome, nudges_enabled()) else {
        return;
    };

    let record = build_denial_record(hook, event, input, decision);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("denials.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        // `record` is compact JSON — one line, no embedded newlines.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// True when `CADENCE_LOG_NUDGES` is set to a non-empty value.
fn nudges_enabled() -> bool {
    std::env::var("CADENCE_LOG_NUDGES")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Map an [`Outcome`] to the `decision` field, or `None` when nothing should be
/// logged. Pure — `nudges_on` is passed in so the env read stays out of the
/// mapping and the mapping is unit-testable. `LoopBlock` (advisory, exit 0) maps
/// to `"nudge"` alongside `Nudge`.
///
/// `Ask` maps to `"ask"` and is logged *unconditionally* (like `Block`), not
/// gated on `nudges_on`: forcing an interactive prompt is a real guard
/// intervention — it overrides a settings `allow` rule — so a proving period
/// needs to see it, not just hard denies.
fn decision_for(outcome: Outcome, nudges_on: bool) -> Option<&'static str> {
    match outcome {
        Outcome::Block => Some("deny"),
        Outcome::Ask => Some("ask"),
        Outcome::Nudge | Outcome::LoopBlock => nudges_on.then_some("nudge"),
        Outcome::Allow => None,
    }
}

/// Build the `denials.jsonl` record. Pure — no I/O beyond the git query behind
/// [`common::repo_basename`]. Reads only non-sensitive context off the input
/// (tool name, session id, agent id, cwd→repo) — never the command, file path,
/// or edited content.
fn build_denial_record(hook: &str, event: HookEvent, input: &HookInput, decision: &str) -> Value {
    json!({
        "ts": common::utc_timestamp(),
        "hook": hook,
        "event": event.name(),
        "decision": decision,
        "tool": input.tool_name(),
        "repo": common::repo_basename(input.cwd.as_deref()),
        "sessionId": input.session_id(),
        "agentId": input.agent_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::ToolInput;

    fn edit_input() -> HookInput {
        // A payload carrying sensitive fields (command, file_path, content) — the
        // record must expose none of them.
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(ToolInput {
                file_path: Some("/secret/path/notes.md".into()),
                command: Some("rm -rf /secret".into()),
                new_string: Some("whitelist the host".into()),
                ..Default::default()
            }),
            cwd: Some("/tmp".into()),
            session_id: Some("sess-1".into()),
            agent_id: Some("agent-9".into()),
            ..Default::default()
        }
    }

    // --- decision_for ---

    #[test]
    fn block_always_denies() {
        assert_eq!(decision_for(Outcome::Block, false), Some("deny"));
        assert_eq!(decision_for(Outcome::Block, true), Some("deny"));
    }

    #[test]
    fn allow_never_logs() {
        assert_eq!(decision_for(Outcome::Allow, false), None);
        assert_eq!(decision_for(Outcome::Allow, true), None);
    }

    #[test]
    fn nudge_and_loop_block_gated_on_env() {
        assert_eq!(decision_for(Outcome::Nudge, false), None);
        assert_eq!(decision_for(Outcome::Nudge, true), Some("nudge"));
        assert_eq!(decision_for(Outcome::LoopBlock, false), None);
        assert_eq!(decision_for(Outcome::LoopBlock, true), Some("nudge"));
    }

    #[test]
    fn ask_always_logs_ungated() {
        // Ask is a real intervention (overrides an allow rule), so it logs
        // regardless of CADENCE_LOG_NUDGES — the proving period needs it.
        assert_eq!(decision_for(Outcome::Ask, false), Some("ask"));
        assert_eq!(decision_for(Outcome::Ask, true), Some("ask"));
    }

    // --- build_denial_record ---

    #[test]
    fn record_has_expected_fields() {
        let rec = build_denial_record("terminology", HookEvent::PreToolUse, &edit_input(), "deny");
        assert_eq!(rec["hook"], "terminology");
        assert_eq!(rec["event"], "PreToolUse");
        assert_eq!(rec["decision"], "deny");
        assert_eq!(rec["tool"], "Edit");
        assert_eq!(rec["sessionId"], "sess-1");
        assert_eq!(rec["agentId"], "agent-9");
        assert!(rec["ts"].is_string());
        assert!(rec["repo"].is_string());
    }

    #[test]
    fn record_omits_sensitive_keys() {
        // Privacy by construction: the record must never carry command content,
        // file paths, or edited text — only which guard fired on which tool.
        let rec = build_denial_record("git-safety", HookEvent::PreToolUse, &edit_input(), "deny");
        let obj = rec.as_object().expect("record is an object");
        for forbidden in ["command", "file_path", "filePath", "content", "new_string"] {
            assert!(
                !obj.contains_key(forbidden),
                "record must not carry '{forbidden}': {rec}"
            );
        }
        // And no *value* in the record leaks the sensitive strings.
        let serialized = rec.to_string();
        assert!(
            !serialized.contains("/secret/path"),
            "leaked file path: {serialized}"
        );
        assert!(
            !serialized.contains("rm -rf"),
            "leaked command: {serialized}"
        );
        assert!(
            !serialized.contains("whitelist"),
            "leaked content: {serialized}"
        );
    }

    #[test]
    fn record_main_thread_agent_id_is_null() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            cwd: Some("/tmp".into()),
            session_id: Some("s".into()),
            ..Default::default()
        };
        let rec = build_denial_record("guard-push-remote", HookEvent::PreToolUse, &input, "deny");
        assert!(rec["agentId"].is_null());
    }

    // --- log_denial end-to-end (tempdir) ---

    /// Serialize the env-mutating tests against every other module's: the
    /// process-global `CADENCE_METRICS_DIR` / `CADENCE_LOG_NUDGES` are shared with
    /// sibling loggers' tests (`log_timing`), so all hold the one crate-wide lock.
    use crate::common::ENV_LOCK;

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, nudges: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
            match nudges {
                Some(v) => std::env::set_var("CADENCE_LOG_NUDGES", v),
                None => std::env::remove_var("CADENCE_LOG_NUDGES"),
            }
        }
        f();
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
            std::env::remove_var("CADENCE_LOG_NUDGES");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("denials.jsonl");
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
                .collect(),
            Err(_) => vec![],
        }
    }

    #[test]
    fn block_writes_one_deny_row() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "terminology",
                HookEvent::PreToolUse,
                &edit_input(),
                Outcome::Block,
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["decision"], "deny");
        assert_eq!(rows[0]["hook"], "terminology");
    }

    #[test]
    fn allow_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "terminology",
                HookEvent::PreToolUse,
                &edit_input(),
                Outcome::Allow,
            );
        });
        assert!(
            read_lines(tmp.path()).is_empty(),
            "Allow must not write a row"
        );
        assert!(!tmp.path().join("denials.jsonl").exists());
    }

    #[test]
    fn nudge_skipped_without_env_logged_with_env() {
        let tmp = tempfile::tempdir().unwrap();
        // Env unset → no row.
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "warn-main-branch",
                HookEvent::PreToolUse,
                &edit_input(),
                Outcome::Nudge,
            );
        });
        assert!(
            read_lines(tmp.path()).is_empty(),
            "nudge without env must not write"
        );

        // Env set → exactly one nudge row.
        with_metrics_dir(tmp.path(), Some("1"), || {
            log_denial(
                "warn-main-branch",
                HookEvent::PreToolUse,
                &edit_input(),
                Outcome::Nudge,
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["decision"], "nudge");
    }
}
