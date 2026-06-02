//! `session start` — SessionStart hook.
//!
//! Registers this session in the repo's registry, sweeps stale entries,
//! ensures the registry is git-excluded, and — when live peers exist —
//! injects a disclosure with a lane assessment and the multi-session
//! protocol. The disclosure automates what was previously a hand-typed
//! `<disclosure>` block (see the 2026-06-01 branch-collision field report).

use crate::identity::{self, SessionRecord};
use crate::registry::{self, Peer};
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Register this session and disclose live peers.
pub struct Start;

impl Check for Start {
    fn name(&self) -> &str {
        "start"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(cwd) = input.cwd.as_deref() else {
            return CheckResult::allow();
        };
        let Some(dir) = registry::sessions_dir(cwd) else {
            // Not a git repository — no registry, nothing to coordinate.
            return CheckResult::allow();
        };
        if let Some(root) = registry::repo_root(cwd) {
            registry::ensure_git_excluded(&root);
        }
        let branch = git_command(cwd, &["branch", "--show-current"]);
        let stale_secs = registry::stale_minutes() * 60;
        run_start(input, &dir, branch, stale_secs)
    }
}

/// Testable core: registry path and branch are injected so tests can target a
/// tempdir without a git repository.
pub fn run_start(
    input: &HookInput,
    dir: &std::path::Path,
    branch: Option<String>,
    stale_secs: u64,
) -> CheckResult {
    let Some(sid) = input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
    else {
        return CheckResult::allow();
    };

    // Housekeeping: presumed-dead sessions leave the room before roll call.
    registry::sweep_stale(dir, stale_secs);

    // Register (or re-register on resume/clear/compact — preserves any
    // declared intent/touching from earlier in the session).
    let record = match registry::read_own(dir, sid) {
        Some(mut existing) => {
            if branch.is_some() {
                existing.branch = branch;
            }
            existing
        }
        None => SessionRecord {
            name: identity::generate_name(sid),
            session_id: sid.to_string(),
            branch,
            started: identity::utc_timestamp(),
            started_epoch: identity::now_epoch(),
            ..Default::default()
        },
    };
    if registry::write_record(dir, &record).is_err() {
        // Fail open: a read-only filesystem must not break session start.
        return CheckResult::allow();
    }

    // Disclose live peers, if any.
    let peers = registry::live_peers(dir, sid, stale_secs);
    if peers.is_empty() {
        return CheckResult::allow();
    }
    CheckResult::nudge(render_disclosure(&record, &peers))
}

/// Render the peer disclosure: who else is live, what they're touching, and
/// the coordination protocol. Pure — fully testable.
pub fn render_disclosure(own: &SessionRecord, peers: &[Peer]) -> String {
    let mut msg = String::new();

    for peer in peers {
        let r = &peer.record;
        msg.push_str(&format!(
            "Another session ({}) is live in this repo",
            r.name
        ));
        if let Some(branch) = &r.branch {
            msg.push_str(&format!(" — on `{branch}`"));
        }
        if let Some(intent) = &r.intent {
            msg.push_str(&format!(", working {intent}"));
        }
        if !r.touching.is_empty() {
            msg.push_str(&format!(", touching {}", r.touching.join(", ")));
        }
        msg.push_str(&format!(
            ". Started {}, last active {}.\n",
            identity::relative_age(peer.age_secs),
            identity::relative_age(peer.idle_secs)
        ));
    }

    msg.push_str(&format!(
        "\nYou are registered as **{}**.\n\
         \n\
         Multi-session protocol (this checkout is shared mutable state):\n\
         1. Re-verify branch and `git status` in the same turn as every mutation — a gather from a previous turn is already stale.\n\
         2. Do not switch branches; the other session's working tree depends on the current one.\n\
         3. Use explicit-path `git add` only — never `-A`/`-a`.\n\
         4. Read the `[branch sha]` line in every `git commit` output; a branch you don't expect means a collision.\n\
         5. Route writes that belong on other branches through `gh api` (contents API), not checkout.\n\
         6. If your work overlaps a peer's declared paths, stop and tell the user the sessions need sequencing.",
        own.name
    ));

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_session;
    use tempfile::TempDir;

    fn make_session_with_cwd(session_id: &str, source: &str, cwd: &str) -> HookInput {
        let mut input = make_session(session_id, source);
        input.cwd = Some(cwd.to_string());
        input
    }

    // --- guard clauses ---

    #[test]
    fn no_session_id_allows() {
        let tmp = TempDir::new().unwrap();
        let input = HookInput {
            cwd: Some("/tmp".into()),
            ..Default::default()
        };
        let r = run_start(&input, tmp.path(), None, 600);
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn unsafe_session_id_allows() {
        let tmp = TempDir::new().unwrap();
        let input = make_session_with_cwd("../escape", "startup", "/tmp");
        let r = run_start(&input, tmp.path(), None, 600);
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "no file written for unsafe id"
        );
    }

    // --- registration ---

    #[test]
    fn empty_room_registers_silently() {
        let tmp = TempDir::new().unwrap();
        let input = make_session_with_cwd("solo-session", "startup", "/tmp");
        let r = run_start(&input, tmp.path(), Some("main".into()), 600);
        assert_eq!(r.outcome, Outcome::Allow, "no peers → no disclosure");
        let own = registry::read_own(tmp.path(), "solo-session").unwrap();
        assert_eq!(own.branch.as_deref(), Some("main"));
        assert!(!own.name.is_empty());
    }

    #[test]
    fn reregistration_preserves_declared_lane() {
        let tmp = TempDir::new().unwrap();
        // First registration + declaration.
        let input = make_session_with_cwd("self-session", "startup", "/tmp");
        run_start(&input, tmp.path(), Some("main".into()), 600);
        let mut rec = registry::read_own(tmp.path(), "self-session").unwrap();
        rec.intent = Some("cadence-hooks#54".into());
        rec.touching = vec!["crates/session/".into()];
        registry::write_record(tmp.path(), &rec).unwrap();

        // Re-register (e.g. after /clear) on a new branch.
        let input = make_session_with_cwd("self-session", "clear", "/tmp");
        run_start(&input, tmp.path(), Some("feat/x".into()), 600);

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(back.intent.as_deref(), Some("cadence-hooks#54"));
        assert_eq!(back.branch.as_deref(), Some("feat/x"));
    }

    // --- disclosure ---

    #[test]
    fn live_peer_triggers_disclosure() {
        let tmp = TempDir::new().unwrap();
        // A peer registers first.
        let peer_input = make_session_with_cwd("peer-session", "startup", "/tmp");
        run_start(&peer_input, tmp.path(), Some("feat/issue-52".into()), 600);

        // We arrive.
        let input = make_session_with_cwd("self-session", "startup", "/tmp");
        let r = run_start(&input, tmp.path(), Some("main".into()), 600);
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("feat/issue-52"), "peer branch named: {msg}");
        assert!(msg.contains("Multi-session protocol"), "protocol included");
        assert!(
            msg.contains("explicit-path"),
            "field-report takeaway included"
        );
    }

    #[test]
    fn stale_peer_does_not_trigger_disclosure() {
        let tmp = TempDir::new().unwrap();
        let peer_input = make_session_with_cwd("peer-session", "startup", "/tmp");
        run_start(&peer_input, tmp.path(), None, 600);
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // stale_secs = 0: any measurable age (whole seconds) counts as stale.
        let input = make_session_with_cwd("self-session", "startup", "/tmp");
        let r = run_start(&input, tmp.path(), None, 0);
        assert_eq!(r.outcome, Outcome::Allow, "stale peers are ignored");
        assert!(
            registry::read_own(tmp.path(), "peer-session").is_none(),
            "stale peer swept on start"
        );
    }

    #[test]
    fn own_old_registration_does_not_disclose() {
        let tmp = TempDir::new().unwrap();
        // Same session re-starting (e.g. compact) must not see itself as a peer.
        let input = make_session_with_cwd("self-session", "startup", "/tmp");
        run_start(&input, tmp.path(), None, 600);
        let r = run_start(&input, tmp.path(), None, 600);
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // --- render_disclosure ---

    fn make_peer(
        name: &str,
        branch: Option<&str>,
        intent: Option<&str>,
        touching: &[&str],
    ) -> Peer {
        Peer {
            record: SessionRecord {
                name: name.into(),
                session_id: format!("{name}-id"),
                branch: branch.map(String::from),
                intent: intent.map(String::from),
                touching: touching.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            idle_secs: 120,
            age_secs: 2400,
            stale: false,
        }
    }

    #[test]
    fn disclosure_includes_peer_details() {
        let own = SessionRecord {
            name: "forge-warden".into(),
            session_id: "self".into(),
            ..Default::default()
        };
        let peers = vec![make_peer(
            "quiet-loom",
            Some("feat/issue-52-claudemd-checks"),
            Some("cadence-hooks#52"),
            &["crates/guardrails/"],
        )];
        let msg = render_disclosure(&own, &peers);
        assert!(msg.contains("quiet-loom"));
        assert!(msg.contains("feat/issue-52-claudemd-checks"));
        assert!(msg.contains("cadence-hooks#52"));
        assert!(msg.contains("crates/guardrails/"));
        assert!(msg.contains("40 min ago"), "age rendered: {msg}");
        assert!(msg.contains("2 min ago"), "idle rendered: {msg}");
        assert!(msg.contains("forge-warden"), "own name rendered");
    }

    #[test]
    fn disclosure_omits_undeclared_fields() {
        let own = SessionRecord {
            name: "forge-warden".into(),
            session_id: "self".into(),
            ..Default::default()
        };
        let peers = vec![make_peer("quiet-loom", None, None, &[])];
        let msg = render_disclosure(&own, &peers);
        assert!(msg.contains("quiet-loom"));
        assert!(
            !msg.contains(", working "),
            "no intent → no 'working' clause"
        );
        assert!(
            !msg.contains(", touching "),
            "no paths → no 'touching' clause"
        );
    }

    #[test]
    fn disclosure_lists_multiple_peers() {
        let own = SessionRecord {
            name: "forge-warden".into(),
            session_id: "self".into(),
            ..Default::default()
        };
        let peers = vec![
            make_peer("quiet-loom", Some("feat/a"), None, &[]),
            make_peer("amber-anvil", Some("feat/b"), None, &[]),
        ];
        let msg = render_disclosure(&own, &peers);
        assert!(msg.contains("quiet-loom"));
        assert!(msg.contains("amber-anvil"));
    }
}
