//! Append-only audit log for guard *bypasses* — the events a bare denial log
//! cannot see: a guardrail was stepped outside of, either **armed** (a
//! `dismiss-*` snooze was set) or **used** (a write rode through an active
//! dismissal / env switch, which surfaces at the dispatch seam as a bare
//! `Allow`). One line per event to `<metrics_dir>/bypasses.jsonl`.
//!
//! Sibling of [`crate::log_denial`], and shares its two doctrines:
//!
//! - **Fail-open (ADR-0001):** every step degrades to a no-op — a full disk or a
//!   read-only metrics dir must never perturb the allow it is recording, nor the
//!   dismiss CLI's own exit.
//! - **Privacy by construction:** the record names *which guard was bypassed, how,
//!   in which repo, by which session* — plus a **user-authored** `reason`. It
//!   never reads the command text, file path, or edited content off the input; a
//!   unit test asserts those keys are absent.
//!
//! Called from the **binary** (`src/dispatch.rs` for `used`, the `dismiss-*`
//! CLI arm in `src/main.rs` for `armed`), never from a guard: only the binary
//! reaches the metrics writer, and only it knows the canonical registry name.

use crate::common;
use cadence_hooks_core::{BypassProvenance, HookInput};
use serde_json::{Value, json};
use std::io::Write;

/// One bypass event, ready to serialize. Built via [`BypassEvent::used`] (at the
/// dispatch seam) or [`BypassEvent::armed`] (at dismiss time). Fields the event
/// kind doesn't carry are `None` (e.g. `tool`/`agent` on an `armed` event —
/// arming a snooze is not a tool call).
pub struct BypassEvent {
    /// `"armed"` (a dismissal was set) or `"used"` (a bypass was ridden through).
    event: &'static str,
    /// Canonical guard name the bypass applies to (e.g. `enforce-worktree`).
    hook: Option<String>,
    /// Tool that rode through, for a `used` event (`None` for `armed`).
    tool: Option<String>,
    /// Repo basename (never the full path).
    repo: Option<String>,
    /// Session that triggered / armed the bypass.
    session: Option<String>,
    /// Subagent that rode through, when the payload carried one.
    agent: Option<String>,
    /// `"dismissal"` | `"env_switch"`.
    kind: &'static str,
    /// Concrete mechanism (`dismiss-enforce-worktree`, `CADENCE_ALLOW_MAIN`, …).
    mechanism: String,
    /// User-authored `--reason`, when present.
    reason: Option<String>,
    /// Unix epoch seconds the dismissal expires, when known.
    expires_at: Option<i64>,
    /// Unix epoch seconds the dismissal was armed, when known (`armed` events).
    armed_at: Option<i64>,
}

impl BypassEvent {
    /// A bypass that was **used**: an operation rode through an active dismissal
    /// or env switch, surfacing at the dispatch seam as an allow carrying
    /// [`BypassProvenance`]. Reads only non-sensitive context off the input
    /// (tool, session, agent, cwd→repo basename) — never the command or path.
    pub fn used(hook: &str, input: &HookInput, prov: &BypassProvenance) -> Self {
        Self {
            event: "used",
            hook: Some(hook.to_string()),
            tool: input.tool_name().map(str::to_string),
            repo: Some(common::repo_basename(input.cwd.as_deref())),
            session: input.session_id().map(str::to_string),
            agent: input.agent_id().map(str::to_string),
            kind: prov.kind.as_str(),
            mechanism: prov.mechanism.clone(),
            reason: prov.reason.clone(),
            expires_at: prov.expires_at,
            armed_at: None,
        }
    }

    /// A dismissal that was **armed**: a `dismiss-*` snooze was set (records the
    /// arming even if the snooze is never ridden through). Always a `dismissal`
    /// kind. `repo_root` is resolved to a basename here so the caller never has
    /// to reach into the privacy contract.
    ///
    /// `repo_root` arrives already resolved by the caller (the toplevel path a
    /// `dismiss-*` CLI arm computed for its own confirmation message, or a
    /// bare-repo common-dir fallback), so `repo_basename` re-derives a fact the
    /// caller already has. That was a second `git` subprocess before
    /// cameronsjo/cadence#857; `repo_basename` is now a pure filesystem walk
    /// (`GitState::resolve`), so the redundancy is a walk, not a spawn, and it's
    /// the only path that's correct for both the toplevel and bare-repo shapes
    /// `repo_root` can carry — left as-is rather than reshaping the CLI arms to
    /// pass a pre-computed basename for a cost that no longer exists.
    #[allow(clippy::too_many_arguments)]
    pub fn armed(
        hook: &str,
        mechanism: &str,
        reason: Option<&str>,
        session: Option<&str>,
        repo_root: Option<&str>,
        armed_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            event: "armed",
            hook: Some(hook.to_string()),
            tool: None,
            repo: Some(common::repo_basename(repo_root)),
            session: session.map(str::to_string),
            agent: None,
            kind: "dismissal",
            mechanism: mechanism.to_string(),
            reason: reason.map(str::to_string),
            expires_at: Some(expires_at),
            armed_at: Some(armed_at),
        }
    }

    /// Build the `bypasses.jsonl` record. Pure — no I/O beyond the git query
    /// behind [`common::repo_basename`] the constructors already ran. Emits only
    /// non-sensitive context plus the user-authored reason.
    fn to_record(&self) -> Value {
        json!({
            "ts": common::utc_timestamp(),
            "event": self.event,
            "hook": self.hook,
            "tool": self.tool,
            "repo": self.repo,
            "sessionId": self.session,
            "agentId": self.agent,
            "kind": self.kind,
            "mechanism": self.mechanism,
            "reason": self.reason,
            "expiresAt": self.expires_at,
            "armedAt": self.armed_at,
        })
    }
}

/// Append one bypass event to `<metrics_dir>/bypasses.jsonl`.
///
/// Fully fail-open (ADR-0001): a missing dir it can't create, or a failed open /
/// write, degrades to a no-op — the caller's allow and exit code are untouched.
pub fn log_bypass(event: BypassEvent) {
    let record = event.to_record();

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("bypasses.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;
    use cadence_hooks_core::{BypassKind, ToolInput};

    fn used_input() -> HookInput {
        // A payload carrying sensitive fields — the record must expose none.
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(ToolInput {
                file_path: Some("/secret/path/notes.md".into()),
                command: Some("rm -rf /secret".into()),
                new_string: Some("allowlist the host".into()),
                ..Default::default()
            }),
            cwd: Some("/tmp".into()),
            session_id: Some("sess-1".into()),
            agent_id: Some("agent-9".into()),
            ..Default::default()
        }
    }

    fn dismissal_prov() -> BypassProvenance {
        BypassProvenance {
            kind: BypassKind::Dismissal,
            mechanism: "dismiss-enforce-worktree".into(),
            reason: Some("dogfooding vault symlink".into()),
            expires_at: Some(2_000_000_000),
            armed_by_session: Some("sess-1".into()),
        }
    }

    // --- record shape ---

    #[test]
    fn used_record_has_expected_fields() {
        let ev = BypassEvent::used("enforce-worktree", &used_input(), &dismissal_prov());
        let rec = ev.to_record();
        assert_eq!(rec["event"], "used");
        assert_eq!(rec["hook"], "enforce-worktree");
        assert_eq!(rec["tool"], "Edit");
        assert_eq!(rec["sessionId"], "sess-1");
        assert_eq!(rec["agentId"], "agent-9");
        assert_eq!(rec["kind"], "dismissal");
        assert_eq!(rec["mechanism"], "dismiss-enforce-worktree");
        assert_eq!(rec["reason"], "dogfooding vault symlink");
        assert_eq!(rec["expiresAt"], 2_000_000_000_i64);
        assert!(rec["armedAt"].is_null(), "used events carry no armedAt");
        assert!(rec["ts"].is_string());
        assert!(rec["repo"].is_string());
    }

    #[test]
    fn armed_record_has_expected_fields() {
        let ev = BypassEvent::armed(
            "enforce-worktree",
            "dismiss-enforce-worktree",
            Some("plan doc on main"),
            Some("sess-7"),
            Some("/tmp"),
            1_700_000_000,
            1_700_003_600,
        );
        let rec = ev.to_record();
        assert_eq!(rec["event"], "armed");
        assert_eq!(rec["kind"], "dismissal");
        assert_eq!(rec["reason"], "plan doc on main");
        assert_eq!(rec["sessionId"], "sess-7");
        assert_eq!(rec["armedAt"], 1_700_000_000_i64);
        assert_eq!(rec["expiresAt"], 1_700_003_600_i64);
        assert!(rec["tool"].is_null(), "arming is not a tool call");
        assert!(rec["agentId"].is_null());
    }

    #[test]
    fn env_switch_used_has_no_reason() {
        let prov = BypassProvenance {
            kind: BypassKind::EnvSwitch,
            mechanism: "CADENCE_ALLOW_MAIN".into(),
            reason: None,
            expires_at: None,
            armed_by_session: None,
        };
        let rec = BypassEvent::used("enforce-worktree", &used_input(), &prov).to_record();
        assert_eq!(rec["kind"], "env_switch");
        assert_eq!(rec["mechanism"], "CADENCE_ALLOW_MAIN");
        assert!(rec["reason"].is_null());
        assert!(rec["expiresAt"].is_null());
    }

    #[test]
    fn record_omits_sensitive_keys() {
        // Privacy by construction: never carry command content, file paths, or
        // edited text — only which guard was bypassed, how, and the user reason.
        let rec =
            BypassEvent::used("enforce-worktree", &used_input(), &dismissal_prov()).to_record();
        let obj = rec.as_object().expect("record is an object");
        for forbidden in ["command", "file_path", "filePath", "content", "new_string"] {
            assert!(
                !obj.contains_key(forbidden),
                "record must not carry '{forbidden}': {rec}"
            );
        }
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
            !serialized.contains("allowlist the host"),
            "leaked content: {serialized}"
        );
    }

    // --- log_bypass end-to-end (tempdir) ---

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        f();
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("bypasses.jsonl");
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
    fn used_writes_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_bypass(BypassEvent::used(
                "enforce-worktree",
                &used_input(),
                &dismissal_prov(),
            ));
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event"], "used");
        assert_eq!(rows[0]["mechanism"], "dismiss-enforce-worktree");
    }

    #[test]
    fn armed_writes_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_bypass(BypassEvent::armed(
                "warn-main-branch",
                "dismiss-main-branch-warn",
                None,
                Some("s"),
                Some("/tmp"),
                100,
                200,
            ));
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event"], "armed");
    }
}
