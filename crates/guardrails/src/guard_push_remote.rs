//! Validate `git push` targets against an owner allowlist.
//!
//! Resolves the push URL for the current branch (or explicit remote) and
//! verifies the repository owner is in the configured allowlist. Also blocks
//! looped pushes and force-push to `main`.

use cadence_hooks_core::config::{self, AllowEntry, env_allow_entries, env_extra_hosts};
use cadence_hooks_core::loop_analysis::{self, ChainAnalysis, LoopAnalysis};
use cadence_hooks_core::shell::{
    LOOP_PATTERN, git_command, host_and_repo_from_url, parse_work_dir, strip_quotes,
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

/// Resolve the push URL for a git repo.
fn resolve_push_url(work_dir: &str, explicit_remote: Option<&str>) -> Option<String> {
    if let Some(remote) = explicit_remote {
        return git_command(work_dir, &["remote", "get-url", "--push", remote]);
    }

    // No explicit remote — find where bare push would go
    let branch = git_command(work_dir, &["branch", "--show-current"])?;
    let tracking = git_command(work_dir, &["config", &format!("branch.{branch}.remote")])
        .unwrap_or_else(|| "origin".to_string());
    git_command(work_dir, &["remote", "get-url", "--push", &tracking])
}

/// Extract explicit remote name from `git push [flags] <remote> [refspec]`.
fn extract_remote(command: &str, work_dir: &str) -> Option<String> {
    let segment = command
        .split("git push")
        .nth(1)?
        .split(&['&', ';', '|'][..])
        .next()?;

    // Strip flags, take first remaining word
    let args: String = segment
        .split_whitespace()
        .filter(|w| !w.starts_with('-'))
        .collect::<Vec<&str>>()
        .join(" ");

    let candidate = args.split_whitespace().next()?;

    // Verify it's a known remote, not a refspec
    let remotes = git_command(work_dir, &["remote"])?;
    if remotes.lines().any(|r| r == candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
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
            return CheckResult::block(
                "🚫 git-guardrails: Not configured — run /guardrails-init to set up\n   \
                 CADENCE_ALLOWED_OWNERS is not set.",
            );
        }

        // Validate ownership of explicit remotes in loops
        if let LoopAnalysis::AllTargetsExplicit(cmds) = &loop_result {
            let cwd_fallback_loop = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| ".".to_string());
            let cwd_loop = input.cwd.as_deref().unwrap_or(&cwd_fallback_loop);
            let work_dir_loop = parse_work_dir(command, cwd_loop);

            for cmd in cmds {
                if let Some(remote) = &cmd.explicit_repo
                    && let Some(url) = resolve_push_url(&work_dir_loop, Some(remote))
                    && !check_owner(&url, &allowed_owners, &allowed_repos, &extra_hosts)
                {
                    return CheckResult::block(format!(
                        "🚫 git-guardrails: Push loop targets remote you don't own\n   \
                         Found: remote `{remote}` → {url}\n   \
                         Fix: push to an owned remote instead, or run each push individually"
                    ));
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

        // Not a git repo — let git fail naturally
        if git_command(&work_dir, &["rev-parse", "--git-dir"]).is_none() {
            return CheckResult::allow();
        }

        // Extract and resolve remote
        let explicit_remote = extract_remote(command, &work_dir);
        let remote_url = resolve_push_url(&work_dir, explicit_remote.as_deref());

        let Some(url) = remote_url else {
            return CheckResult::block(format!(
                "⚠️  git-guardrails: Cannot resolve push target\n   \
                 Directory: {work_dir}\n   \
                 Push explicitly: git push origin main"
            ));
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
            }),
            cwd: None,
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
}
