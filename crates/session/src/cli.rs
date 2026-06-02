//! CLI actions: `session declare` and `session status`.
//!
//! These are user/skill-facing commands, not hooks — they read no stdin
//! payload and are exempt from hooks.json wiring (like
//! `guardrails dismiss-main-branch-warn`). Both always exit successfully:
//! a coordination convenience must never fail a script that calls it.

use crate::identity;
use crate::registry;

/// Resolve this session's id: explicit flag first, then `CLAUDE_SESSION_ID`
/// (exported by Claude Code into every Bash invocation).
fn resolve_session_id(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("CLAUDE_SESSION_ID").ok())
        .filter(|s| identity::is_safe_session_id(s))
}

/// `session declare --intent <...> --touching <...>` — update this session's
/// lane declaration so peers can assess collision risk.
pub fn run_declare(intent: Option<String>, touching: Vec<String>, session_id: Option<String>) {
    let Some(sid) = resolve_session_id(session_id) else {
        println!(
            "session declare: no session id. Pass --session-id or run inside Claude Code \
             (CLAUDE_SESSION_ID)."
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
    if intent.is_some() {
        record.intent = intent;
    }
    if !touching.is_empty() {
        record.touching = touching;
    }
    match registry::write_record(&dir, &record) {
        Ok(()) => {
            println!(
                "Declared: {} working on {}{}",
                record.name,
                record.intent.as_deref().unwrap_or("(no intent)"),
                if record.touching.is_empty() {
                    String::new()
                } else {
                    format!(", touching {}", record.touching.join(", "))
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
    for peer in &all {
        let r = &peer.record;
        println!(
            "  {:<20} {:<10} branch={:<30} active {}{}",
            r.name,
            identity::short_id(&r.session_id),
            r.branch.as_deref().unwrap_or("-"),
            identity::relative_age(peer.idle_secs),
            if peer.stale { "  [STALE]" } else { "" }
        );
        if let Some(intent) = &r.intent {
            println!("  {:<20} intent: {intent}", "");
        }
        if !r.touching.is_empty() {
            println!("  {:<20} touching: {}", "", r.touching.join(", "));
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

    // Note: the env-var fallback and the run_declare/run_status I/O paths are
    // exercised end-to-end by the plugin smoke test; here they'd require
    // mutating process-global state (env, cwd) which races parallel tests.
}
