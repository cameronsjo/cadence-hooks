//! `session guard` — PreToolUse lane warnings.
//!
//! When live peers exist, warn — never block (ADR-0001) — on actions that
//! intersect their lanes:
//!
//! - **Branch switches** (`git checkout <branch>`, `git switch`): the peer's
//!   working tree depends on the current branch.
//! - **Blanket staging** (`git add -A`, `git commit -a`): sweeps the peer's
//!   in-progress files into your commit.
//! - **Writes inside a peer's declared paths** (`touching`): direct lane
//!   collision.
//!
//! Every result is `allow()` or `nudge()` — a registry problem or an
//! unparsable command must never stop work.

use crate::registry::{self, Peer};
use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Warn when an action intersects a live peer's lane.
pub struct Guard;

impl Check for Guard {
    fn name(&self) -> &str {
        "guard"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(cwd) = input.cwd.as_deref() else {
            return CheckResult::allow();
        };
        let Some(sid) = input.session_id() else {
            // Can't distinguish self from peers without a session id — fail open.
            return CheckResult::allow();
        };
        let Some(dir) = registry::sessions_dir(cwd) else {
            return CheckResult::allow();
        };
        let stale_secs = registry::stale_minutes() * 60;
        let peers = registry::live_peers(&dir, sid, stale_secs);
        run_guard(input, &peers)
    }
}

/// Testable core: assess the action against the given live peers.
pub fn run_guard(input: &HookInput, peers: &[Peer]) -> CheckResult {
    if peers.is_empty() {
        return CheckResult::allow();
    }
    let peer_names: Vec<&str> = peers.iter().map(|p| p.record.name.as_str()).collect();
    let names = peer_names.join(", ");

    match input.tool_name() {
        Some("Bash") => {
            let Some(command) = input.command() else {
                return CheckResult::allow();
            };
            let stripped = strip_quotes(command);
            if is_branch_switch(&stripped) {
                return CheckResult::nudge(format!(
                    "Heads up: {names} {is_are} live in this checkout. Switching branches yanks \
                     the working tree out from under {them}. If the work belongs on another \
                     branch, deliver it with `gh api` (contents API) or coordinate with the user \
                     to sequence the sessions.",
                    is_are = if peers.len() == 1 { "is" } else { "are" },
                    them = if peers.len() == 1 { "it" } else { "them" },
                ));
            }
            if is_blanket_add(&stripped) {
                return CheckResult::nudge(format!(
                    "Heads up: {names} {is_are} live in this checkout. Blanket staging \
                     (`git add -A`, `git commit -a`) can sweep a peer's in-progress files into \
                     your commit. Use explicit-path `git add` instead.",
                    is_are = if peers.len() == 1 { "is" } else { "are" },
                ));
            }
            CheckResult::allow()
        }
        Some("Edit") | Some("Write") => {
            let Some(path) = input.file_path() else {
                return CheckResult::allow();
            };
            if let Some((peer_name, lane)) = path_in_peer_lane(&path, peers) {
                return CheckResult::nudge(format!(
                    "Heads up: `{path}` is inside `{lane}`, which session {peer_name} declared \
                     it is working on. Check with the user before editing here — the sessions \
                     may need sequencing.",
                ));
            }
            CheckResult::allow()
        }
        _ => CheckResult::allow(),
    }
}

/// True when the command switches branches: `git checkout <branch>`,
/// `git checkout -b <new>`, `git switch <branch>`.
///
/// `git checkout -- <path>` and `git checkout <ref> -- <path>` are file
/// restores, not switches. `git checkout <path>` without `--` is ambiguous
/// without repo knowledge — treated as a switch (this is a nudge, not a
/// block; a false positive costs one line of context).
pub fn is_branch_switch(command: &str) -> bool {
    for segment in command.split(&['&', ';', '|'][..]) {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        let Some(git_pos) = tokens.iter().position(|t| *t == "git") else {
            continue;
        };
        // Skip git's own flags/options (e.g. `git -C /path checkout x`).
        let mut idx = git_pos + 1;
        while idx < tokens.len() && (tokens[idx].starts_with('-') || tokens[idx - 1] == "-C") {
            idx += 1;
        }
        let Some(subcommand) = tokens.get(idx) else {
            continue;
        };
        if *subcommand != "checkout" && *subcommand != "switch" {
            continue;
        }
        let rest = &tokens[idx + 1..];
        if rest.is_empty() {
            continue;
        }
        // `--` before any non-flag argument → file restore, not a switch.
        let first_non_flag = rest.iter().position(|t| !t.starts_with('-'));
        let double_dash = rest.iter().position(|t| *t == "--");
        match (first_non_flag, double_dash) {
            (_, Some(dd)) if first_non_flag.is_none_or(|nf| dd < nf) => continue,
            (None, None) => {
                // Only flags (e.g. `git switch -c` missing its arg, `git checkout -b`).
                // `-b`/`-c` create-and-switch even when the name is on the next
                // token that didn't parse — treat flag-only as a switch attempt.
                if rest.iter().any(|t| *t == "-b" || *t == "-c") {
                    return true;
                }
                continue;
            }
            _ => return true,
        }
    }
    false
}

/// True when the command stages or commits with a blanket flag:
/// `git add -A`, `git add --all`, `git add .`, `git commit -a`/`-am`/`--all`.
pub fn is_blanket_add(command: &str) -> bool {
    for segment in command.split(&['&', ';', '|'][..]) {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        let Some(git_pos) = tokens.iter().position(|t| *t == "git") else {
            continue;
        };
        let mut idx = git_pos + 1;
        while idx < tokens.len() && (tokens[idx].starts_with('-') || tokens[idx - 1] == "-C") {
            idx += 1;
        }
        let Some(subcommand) = tokens.get(idx) else {
            continue;
        };
        let rest = &tokens[idx + 1..];
        match *subcommand {
            "add" => {
                if rest.iter().any(|t| {
                    *t == "-A" || *t == "--all" || *t == "." || *t == "-u" || *t == "--update"
                }) {
                    return true;
                }
            }
            "commit" => {
                if rest.iter().any(|t| {
                    *t == "-a"
                        || *t == "--all"
                        || (t.starts_with("-a") && !t.starts_with("--") && t.len() > 2)
                }) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// If `path` falls inside any live peer's declared `touching` paths, return
/// the peer's name and the matching lane prefix.
pub fn path_in_peer_lane<'a>(path: &str, peers: &'a [Peer]) -> Option<(&'a str, &'a str)> {
    for peer in peers {
        for lane in &peer.record.touching {
            let lane_trimmed = lane.trim_end_matches('/');
            if lane_trimmed.is_empty() {
                continue;
            }
            // `touching` entries are repo-relative; the edited path may be
            // absolute. Containment with a path-boundary check on both sides.
            let needle = format!("/{lane_trimmed}/");
            if path.contains(&needle)
                || path.starts_with(&format!("{lane_trimmed}/"))
                || path == lane_trimmed
                || path.ends_with(&format!("/{lane_trimmed}"))
            {
                return Some((peer.record.name.as_str(), lane.as_str()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SessionRecord;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_bash, make_edit};

    fn peer(name: &str, touching: &[&str]) -> Peer {
        Peer {
            record: SessionRecord {
                name: name.into(),
                session_id: format!("{name}-id"),
                branch: Some("feat/peer-branch".into()),
                touching: touching.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            idle_secs: 60,
            age_secs: 600,
            stale: false,
        }
    }

    fn with_session(mut input: HookInput) -> HookInput {
        input.session_id = Some("self-session".into());
        input
    }

    // --- guard clauses ---

    #[test]
    fn no_peers_allows_everything() {
        let input = with_session(make_bash("git checkout other-branch"));
        let r = run_guard(&input, &[]);
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn non_git_bash_allows() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("cargo test"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Allow);
    }

    #[test]
    fn read_tool_allows() {
        let peers = vec![peer("quiet-loom", &["crates/"])];
        let mut input = with_session(HookInput::default());
        input.tool_name = Some("Read".into());
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Allow);
    }

    // --- branch switch warnings ---

    #[test]
    fn checkout_branch_warns_with_peers() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git checkout feat/other"));
        let r = run_guard(&input, &peers);
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("quiet-loom"));
        assert!(msg.contains("gh api"), "escape hatch suggested: {msg}");
    }

    #[test]
    fn git_switch_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git switch main"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Nudge);
    }

    #[test]
    fn checkout_create_branch_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git checkout -b feat/new"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Nudge);
    }

    #[test]
    fn checkout_file_restore_allows() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git checkout -- src/main.rs"));
        assert_eq!(
            run_guard(&input, &peers).outcome,
            Outcome::Allow,
            "`--` restore is not a branch switch"
        );
    }

    #[test]
    fn checkout_in_chained_command_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("cd /repo && git checkout main && git pull"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Nudge);
    }

    #[test]
    fn quoted_checkout_in_echo_allows() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("echo 'git checkout main'"));
        assert_eq!(
            run_guard(&input, &peers).outcome,
            Outcome::Allow,
            "quoted text is stripped before matching"
        );
    }

    #[test]
    fn git_dash_c_checkout_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git -C /some/repo checkout feat/x"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Nudge);
    }

    // --- blanket staging warnings ---

    #[test]
    fn git_add_all_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        for cmd in ["git add -A", "git add --all", "git add .", "git add -u"] {
            let input = with_session(make_bash(cmd));
            assert_eq!(
                run_guard(&input, &peers).outcome,
                Outcome::Nudge,
                "should warn on: {cmd}"
            );
        }
    }

    #[test]
    fn git_commit_dash_a_warns() {
        let peers = vec![peer("quiet-loom", &[])];
        for cmd in ["git commit -a -m x", "git commit -am x", "git commit --all"] {
            let input = with_session(make_bash(cmd));
            assert_eq!(
                run_guard(&input, &peers).outcome,
                Outcome::Nudge,
                "should warn on: {cmd}"
            );
        }
    }

    #[test]
    fn explicit_path_add_allows() {
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_bash("git add src/main.rs && git commit -m 'x'"));
        assert_eq!(
            run_guard(&input, &peers).outcome,
            Outcome::Allow,
            "explicit-path staging is the protocol — no warning"
        );
    }

    // --- lane collision warnings ---

    #[test]
    fn edit_inside_peer_lane_warns() {
        let peers = vec![peer("quiet-loom", &["crates/guardrails/"])];
        let input = with_session(make_edit(
            "/Users/dev/cadence-hooks/crates/guardrails/src/lib.rs",
        ));
        let r = run_guard(&input, &peers);
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("quiet-loom"));
        assert!(msg.contains("crates/guardrails/"));
    }

    #[test]
    fn edit_outside_peer_lane_allows() {
        let peers = vec![peer("quiet-loom", &["crates/guardrails/"])];
        let input = with_session(make_edit("/Users/dev/cadence-hooks/crates/core/src/lib.rs"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Allow);
    }

    #[test]
    fn edit_with_undeclared_peer_allows() {
        // A peer with no declared lane can't produce path collisions.
        let peers = vec![peer("quiet-loom", &[])];
        let input = with_session(make_edit("/Users/dev/repo/src/anything.rs"));
        assert_eq!(run_guard(&input, &peers).outcome, Outcome::Allow);
    }

    #[test]
    fn substring_lane_does_not_false_positive() {
        // "crates/guard" must not match "crates/guardrails-other/".
        let peers = vec![peer("quiet-loom", &["crates/guard"])];
        let input = with_session(make_edit("/repo/crates/guardrails/src/lib.rs"));
        assert_eq!(
            run_guard(&input, &peers).outcome,
            Outcome::Allow,
            "path-boundary matching, not substring"
        );
    }

    // --- pure helper edge cases ---

    #[test]
    fn branch_switch_detection() {
        assert!(is_branch_switch("git checkout main"));
        assert!(is_branch_switch("git switch feat/x"));
        assert!(is_branch_switch("git checkout -b new-branch"));
        assert!(is_branch_switch("git switch -c new-branch"));
        assert!(is_branch_switch("cd /x && git checkout other"));
        assert!(!is_branch_switch("git checkout -- file.rs"));
        assert!(!is_branch_switch("git status"));
        assert!(!is_branch_switch("git checkout"));
        assert!(!is_branch_switch("echo checkout main"));
    }

    #[test]
    fn blanket_add_detection() {
        assert!(is_blanket_add("git add -A"));
        assert!(is_blanket_add("git add ."));
        assert!(is_blanket_add("git commit -am 'msg'"));
        assert!(!is_blanket_add("git add src/main.rs"));
        assert!(!is_blanket_add("git add CLAUDE.md docs/plan.md"));
        assert!(!is_blanket_add("git commit -m 'msg'"));
        assert!(!is_blanket_add("git commit --amend"));
    }

    #[test]
    fn lane_matching_boundaries() {
        let peers = vec![peer("p", &["src/"])];
        assert!(path_in_peer_lane("/repo/src/main.rs", &peers).is_some());
        assert!(path_in_peer_lane("src/main.rs", &peers).is_some());
        assert!(path_in_peer_lane("/repo/srclike/main.rs", &peers).is_none());
        assert!(path_in_peer_lane("/repo/other/file.rs", &peers).is_none());
    }
}
