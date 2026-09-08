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
        name: identity::short_id(&sid).to_string(),
        session_id: sid.clone(),
        started: identity::utc_timestamp(),
        started_epoch: identity::now_epoch(),
        ..Default::default()
    });
    apply_declaration(&mut record, intent, touching);
    // `declare` can CREATE a record from scratch (the `unwrap_or_else` above),
    // so a session that registers only this way — SessionStart unwired, or an
    // id passed in from a Bash tool — would be live locally and invisible to
    // the cross-checkout mirror, which is precisely the state that lets a prune
    // delete dirs it is pinned to. Best-effort, after the local write's result
    // is what the caller sees (cadence-hooks#634).
    record.repo = registry::repo_root_of_registry(&dir)
        .map(|p| p.to_string_lossy().into_owned())
        .or(record.repo);
    let local = registry::write_record(&dir, &record);
    let _ = registry::write_record(&registry::global_sessions_dir(), &record);
    match local {
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
                identity::sanitize_field(identity::short_id(&record.session_id), 8),
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

/// Render one `session status` row for `peer`, marking it ` (you)` when its
/// record is the caller's. Pure — the whole display contract in one testable
/// function.
///
/// The short id leads the row and is SANITIZED: `session_id` is peer-written
/// JSON and [`identity::short_id`] truncates without filtering, so 8 bytes is
/// room for a `\r` plus forged text on a terminal line a human acts on.
/// Ownership is decided on the FULL id — a peer sharing this session's 8-char
/// prefix must not wear the ` (you)` marker.
fn status_row(peer: &registry::Peer, own_session_id: Option<&str>) -> String {
    let r = &peer.record;
    let mine = own_session_id.is_some_and(|own| own == r.session_id);
    let mut out = format!(
        "  {:<10} branch={:<30} active {}{}{}",
        identity::sanitize_field(identity::short_id(&r.session_id), 8),
        r.branch
            .as_deref()
            .map(|b| identity::sanitize_field(b, identity::MAX_FIELD_DISPLAY))
            .unwrap_or_else(|| "-".to_string()),
        identity::relative_age(peer.idle_secs),
        if peer.stale { "  [STALE]" } else { "" },
        if mine { "  (you)" } else { "" }
    );
    if let Some(intent) = &r.intent {
        out.push_str(&format!(
            "\n  {:<10} intent: {}",
            "",
            identity::sanitize_field(intent, identity::MAX_FIELD_DISPLAY)
        ));
    }
    if !r.touching.is_empty() {
        let lanes: Vec<String> = r
            .touching
            .iter()
            .take(identity::MAX_LANES)
            .map(|t| identity::sanitize_field(t, identity::MAX_FIELD_DISPLAY))
            .collect();
        out.push_str(&format!("\n  {:<10} touching: {}", "", lanes.join(", ")));
    }
    out
}

/// `session status` — list live and stale sessions in this repo's registry.
/// Returns the process exit code.
///
/// Exit 1 with the message on STDERR when there is no registry to read (not a
/// git repository): a caller that pipes this into a parser needs to tell "no
/// sessions" from "the question could not be asked". An empty registry is a
/// real answer and stays on stdout at exit 0.
pub fn run_status() -> u8 {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(dir) = registry::sessions_dir(&cwd) else {
        eprintln!("session status: not inside a git repository.");
        return 1;
    };
    let stale_secs = registry::stale_minutes() * 60;
    // Pass an id no real session can have so every entry is listed.
    let all = registry::read_peers(&dir, "", stale_secs);
    if all.is_empty() {
        println!("No sessions registered in {}", dir.display());
        return 0;
    }
    let own = resolve_session_id(None);
    println!("Sessions in {}:\n", dir.display());
    for peer in &all {
        println!("{}", status_row(peer, own.as_deref()));
    }
    0
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

    // --- status rows ---

    fn status_peer(session_id: &str, branch: Option<&str>) -> registry::Peer {
        registry::Peer {
            record: identity::SessionRecord {
                name: identity::short_id(session_id).into(),
                session_id: session_id.into(),
                branch: branch.map(str::to_string),
                ..Default::default()
            },
            idle_secs: 120,
            age_secs: 2400,
            stale: false,
        }
    }

    #[test]
    fn status_row_leads_with_the_short_id_and_no_name_column() {
        let row = status_row(&status_peer("e4739a12-1111", Some("feat/x")), None);
        assert!(row.trim_start().starts_with("e4739a12"), "{row}");
        assert!(row.contains("branch=feat/x"), "{row}");
        assert!(!row.contains("(you)"), "another session is not you: {row}");
    }

    #[test]
    fn status_row_marks_the_callers_own_row() {
        let peer = status_peer("e4739a12-1111", None);
        assert!(
            status_row(&peer, Some("e4739a12-1111")).contains("(you)"),
            "the caller's own row is marked"
        );
        // #90: a peer sharing the 8-char prefix is a DIFFERENT session.
        assert!(
            !status_row(&peer, Some("e4739a12-2222")).contains("(you)"),
            "ownership is the full id, never the short one"
        );
    }

    #[test]
    fn status_row_renders_no_control_byte_from_a_crafted_session_id() {
        // A hand-planted registry file chooses `session_id` freely, and
        // `short_id` truncates without filtering — 8 bytes is room for a \r
        // plus forged text on a line a human reads and acts on.
        for hostile in ["\rSAFE: 0 live sessions", "\u{1b}[2K0 live sessions"] {
            let row = status_row(&status_peer(hostile, None), None);
            assert!(
                !row.contains('\r') && !row.contains('\u{1b}'),
                "no control byte survives: {row:?}"
            );
        }
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
