//! CLI actions: `session declare` and `session status`.
//!
//! These are user/skill-facing commands, not hooks — they read no stdin
//! payload and are exempt from hooks.json wiring (like
//! `guardrails dismiss-main-branch-warn`). Both always exit successfully:
//! a coordination convenience must never fail a script that calls it.

use crate::identity;
use crate::registry;

/// Resolve this session's id: explicit flag first, then
/// `CLAUDE_CODE_SESSION_ID` (the variable Claude Code actually exports into
/// Bash tool invocations — verified live 2026-07-10), then the legacy
/// `CLAUDE_SESSION_ID` as a compatibility fallback.
///
/// `pub(crate)` so the `goal` CLI verbs resolve identity the same way.
pub(crate) fn resolve_session_id(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok())
        .or_else(|| std::env::var("CLAUDE_SESSION_ID").ok())
        .filter(|s| identity::is_safe_session_id(s))
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
             (CLAUDE_CODE_SESSION_ID)."
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
    fn resolve_session_id_rejects_unsafe_flag() {
        assert!(resolve_session_id(Some("../escape".into())).is_none());
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

    // Note: the env-var fallback and the run_declare/run_status I/O paths are
    // exercised end-to-end by the plugin smoke test; here they'd require
    // mutating process-global state (env, cwd) which races parallel tests.
}
