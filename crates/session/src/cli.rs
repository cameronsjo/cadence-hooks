//! CLI actions: `session declare` and `session status`.
//!
//! These are user/skill-facing commands, not hooks — they read no stdin
//! payload and are exempt from hooks.json wiring (like
//! `guardrails dismiss-main-branch-warn`). Both always exit successfully:
//! a coordination convenience must never fail a script that calls it.

use crate::identity;
use crate::registry;

/// Priority order for resolving a session id: explicit flag, then
/// `CLAUDE_SESSION_ID`, then `CLAUDE_CODE_SESSION_ID` (#366: a shell Claude
/// Code spawns via its Bash tool does not carry `CLAUDE_SESSION_ID`, but does
/// carry `CLAUDE_CODE_SESSION_ID` — without this fallback, `session declare`
/// run from the Bash tool can't self-identify at all). Pure — env values
/// passed as arguments, never read from `std::env` here, so the ordering is
/// fixture-testable without mutating process-global env (mirrors
/// `redact_external_content::resolve_dest_tier`'s seam).
///
/// Each candidate is validated BEFORE selection, not after: an `.or().or()`
/// chain followed by a single trailing `.filter()` would pick the first
/// *present* candidate regardless of safety, then reject the whole result if
/// that one candidate is unsafe — never falling through to a later, safe
/// candidate. `find` validates in priority order instead, so an unsafe
/// `CLAUDE_SESSION_ID` correctly falls through to a safe
/// `CLAUDE_CODE_SESSION_ID` rather than failing the whole resolution.
fn resolve_session_id_from(
    flag: Option<String>,
    claude_session_id: Option<String>,
    claude_code_session_id: Option<String>,
) -> Option<String> {
    [flag, claude_session_id, claude_code_session_id]
        .into_iter()
        .flatten()
        .find(|s| identity::is_safe_session_id(s))
}

/// Resolve this session's id from the real environment. See
/// [`resolve_session_id_from`] for the priority order and rationale.
fn resolve_session_id(flag: Option<String>) -> Option<String> {
    resolve_session_id_from(
        flag,
        std::env::var("CLAUDE_SESSION_ID").ok(),
        std::env::var("CLAUDE_CODE_SESSION_ID").ok(),
    )
}

/// Apply a declaration to a record. Pure — fully testable.
///
/// Omitted fields are preserved; provided-but-blank values are explicit
/// clears:
/// - `intent: None` → preserve; `Some("  ")` → clear; `Some(text)` → set
///   (trimmed)
/// - `touching` empty (flag never passed) → preserve; entries that normalize
///   to nothing (all blank) → clear; otherwise → set (trimmed, blanks
///   dropped)
fn apply_declaration(
    record: &mut identity::SessionRecord,
    intent: Option<String>,
    touching: Vec<String>,
) {
    match intent {
        Some(s) if s.trim().is_empty() => record.intent = None,
        Some(s) => record.intent = Some(s.trim().to_string()),
        None => {}
    }
    if !touching.is_empty() {
        record.touching = touching
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
}

/// `session declare --intent <...> --touching <...>` — update this session's
/// lane declaration so peers can assess collision risk.
pub fn run_declare(intent: Option<String>, touching: Vec<String>, session_id: Option<String>) {
    let Some(sid) = resolve_session_id(session_id) else {
        println!(
            "session declare: no session id. Pass --session-id or run inside Claude Code \
             (CLAUDE_SESSION_ID or CLAUDE_CODE_SESSION_ID)."
        );
        return;
    };
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(dir) = registry::sessions_dir(&cwd) else {
        println!("session declare: not inside a git repository — no registry to declare in.");
        return;
    };

    // Upsert: keep existing fields, apply the declaration.
    let mut record = registry::read_own(&dir, &sid).unwrap_or_else(|| identity::SessionRecord {
        name: identity::generate_name(&sid),
        session_id: sid.clone(),
        started: identity::utc_timestamp(),
        started_epoch: identity::now_epoch(),
        ..Default::default()
    });
    apply_declaration(&mut record, intent, touching);
    match registry::write_record(&dir, &record) {
        Ok(()) => {
            // The record may have been seeded by another process — sanitize
            // everything echoed back, same discipline as the hook paths.
            let lanes: Vec<String> = record
                .touching
                .iter()
                .take(identity::MAX_LANES)
                .map(|t| identity::sanitize_field(t, identity::MAX_FIELD_DISPLAY))
                .collect();
            println!(
                "Declared: {} working on {}{}",
                identity::sanitize_field(&record.name, 40),
                record
                    .intent
                    .as_deref()
                    .map(|i| identity::sanitize_field(i, identity::MAX_FIELD_DISPLAY))
                    .unwrap_or_else(|| "(no intent)".to_string()),
                if lanes.is_empty() {
                    String::new()
                } else {
                    format!(", touching {}", lanes.join(", "))
                }
            );
        }
        Err(e) => println!("session declare: could not write registry: {e}"),
    }
}

/// `session status` — list live and stale sessions in this repo's registry.
pub fn run_status() {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(dir) = registry::sessions_dir(&cwd) else {
        println!("session status: not inside a git repository.");
        return;
    };
    let stale_secs = registry::stale_minutes() * 60;
    // Pass an id no real session can have so every entry is listed.
    let all = registry::read_peers(&dir, "", stale_secs);
    if all.is_empty() {
        println!("No sessions registered in {}", dir.display());
        return;
    }
    println!("Sessions in {}:\n", dir.display());
    // Every displayed field comes from peer-written files — sanitize, same
    // discipline as the hook paths (garbled terminal output is lower stakes
    // than context injection, but the rule is one rule).
    for peer in &all {
        let r = &peer.record;
        println!(
            "  {:<20} {:<10} branch={:<30} active {}{}",
            identity::sanitize_field(&r.name, 40),
            identity::short_id(&r.session_id),
            r.branch
                .as_deref()
                .map(|b| identity::sanitize_field(b, identity::MAX_FIELD_DISPLAY))
                .unwrap_or_else(|| "-".to_string()),
            identity::relative_age(peer.idle_secs),
            if peer.stale { "  [STALE]" } else { "" }
        );
        if let Some(intent) = &r.intent {
            println!(
                "  {:<20} intent: {}",
                "",
                identity::sanitize_field(intent, identity::MAX_FIELD_DISPLAY)
            );
        }
        if !r.touching.is_empty() {
            let lanes: Vec<String> = r
                .touching
                .iter()
                .take(identity::MAX_LANES)
                .map(|t| identity::sanitize_field(t, identity::MAX_FIELD_DISPLAY))
                .collect();
            println!("  {:<20} touching: {}", "", lanes.join(", "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_session_id_prefers_flag() {
        let resolved = resolve_session_id(Some("from-flag".into()));
        assert_eq!(resolved.as_deref(), Some("from-flag"));
    }

    #[test]
    fn resolve_session_id_from_rejects_unsafe_flag_with_no_fallback() {
        // Via the pure seam with explicit None env args, not the real
        // resolve_session_id(Some("../escape".into())): with the #366 fix,
        // an unsafe flag now correctly falls through to a real
        // CLAUDE_CODE_SESSION_ID when this test process actually has one set
        // (true whenever this suite runs inside a live Claude Code session),
        // so asserting None through the impure entry point would be
        // environment-dependent rather than a property of the resolver.
        assert!(resolve_session_id_from(Some("../escape".into()), None, None).is_none());
    }

    // --- #366: CLAUDE_CODE_SESSION_ID fallback, via the pure seam ---

    #[test]
    fn resolve_session_id_from_prefers_flag_over_both_env_vars() {
        let resolved = resolve_session_id_from(
            Some("from-flag".into()),
            Some("from-claude-session-id".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-flag"));
    }

    #[test]
    fn resolve_session_id_from_prefers_claude_session_id_over_claude_code_session_id() {
        let resolved = resolve_session_id_from(
            None,
            Some("from-claude-session-id".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-session-id"));
    }

    #[test]
    fn resolve_session_id_from_falls_back_to_claude_code_session_id() {
        // The reported bug: a Bash-tool-spawned subshell has no
        // CLAUDE_SESSION_ID, only CLAUDE_CODE_SESSION_ID — declare must
        // still self-identify from it.
        let resolved =
            resolve_session_id_from(None, None, Some("from-claude-code-session-id".into()));
        assert_eq!(resolved.as_deref(), Some("from-claude-code-session-id"));
    }

    #[test]
    fn resolve_session_id_from_none_when_all_absent() {
        assert!(resolve_session_id_from(None, None, None).is_none());
    }

    #[test]
    fn resolve_session_id_from_rejects_unsafe_claude_code_session_id() {
        assert!(resolve_session_id_from(None, None, Some("../escape".into())).is_none());
    }

    #[test]
    fn resolve_session_id_from_unsafe_claude_session_id_falls_through_to_safe_claude_code_session_id()
     {
        // The critical case: an unsafe higher-priority candidate must not
        // fail the whole resolution when a safe lower-priority one exists —
        // each candidate is validated before selection, not after.
        let resolved = resolve_session_id_from(
            None,
            Some("../escape".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-code-session-id"));
    }

    #[test]
    fn resolve_session_id_from_unsafe_flag_falls_through_to_safe_claude_session_id() {
        let resolved = resolve_session_id_from(
            Some("../escape".into()),
            Some("from-claude-session-id".into()),
            None,
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-session-id"));
    }

    // --- declaration semantics ---

    fn declared_record() -> identity::SessionRecord {
        identity::SessionRecord {
            name: "quiet-loom".into(),
            session_id: "s1".into(),
            intent: Some("cadence-hooks#52".into()),
            touching: vec!["crates/guardrails/".into()],
            ..Default::default()
        }
    }

    #[test]
    fn omitted_fields_are_preserved() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, None, Vec::new());
        assert_eq!(rec.intent.as_deref(), Some("cadence-hooks#52"));
        assert_eq!(rec.touching, vec!["crates/guardrails/"]);
    }

    #[test]
    fn provided_fields_are_set_and_trimmed() {
        let mut rec = declared_record();
        apply_declaration(
            &mut rec,
            Some("  cadence-hooks#54  ".into()),
            vec!["  crates/session/  ".into()],
        );
        assert_eq!(rec.intent.as_deref(), Some("cadence-hooks#54"));
        assert_eq!(rec.touching, vec!["crates/session/"]);
    }

    #[test]
    fn blank_intent_is_explicit_clear() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, Some("   ".into()), Vec::new());
        assert!(rec.intent.is_none(), "blank intent clears");
        assert!(!rec.touching.is_empty(), "touching untouched");
    }

    #[test]
    fn all_blank_touching_is_explicit_clear() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, None, vec!["  ".into(), "".into()]);
        assert!(rec.touching.is_empty(), "all-blank list clears lanes");
        assert!(rec.intent.is_some(), "intent untouched");
    }

    #[test]
    fn blank_touching_entries_are_dropped() {
        let mut rec = declared_record();
        apply_declaration(
            &mut rec,
            None,
            vec!["crates/session/".into(), "   ".into(), "src/".into()],
        );
        assert_eq!(rec.touching, vec!["crates/session/", "src/"]);
    }

    // Note: the run_declare/run_status I/O paths are exercised end-to-end by
    // the plugin smoke test; here they'd require mutating process-global
    // state (env, cwd) which races parallel tests. The env-var fallback
    // priority itself is covered above via the pure resolve_session_id_from
    // seam, which needs no env mutation.
}
