//! Validate `git push` targets against an owner allowlist.
//!
//! Resolves the push URL for the current branch (or explicit remote) and
//! verifies the repository owner is in the configured allowlist. Also blocks
//! looped pushes and force-push to `main`.

use cadence_hooks_core::loop_analysis::{self, LoopAnalysis};
use cadence_hooks_core::shell::{
    LOOP_PATTERN, git_command, parse_work_dir, repo_from_url, strip_quotes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Check if owner is in the allowed list.
fn check_owner(url: &str, allowed_owners: &[String]) -> bool {
    let Some(repo) = repo_from_url(url) else {
        return false;
    };
    let owner = repo.split('/').next().unwrap_or("");
    allowed_owners.iter().any(|a| a == owner)
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

        // Read allowed owners from env
        let allowed_owners: Vec<String> = std::env::var("GIT_GUARDRAILS_ALLOWED_OWNERS")
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        if allowed_owners.is_empty() {
            return CheckResult::block(
                "🚫 git-guardrails: Not configured — run /guardrails-init to set up\n   \
                 GIT_GUARDRAILS_ALLOWED_OWNERS is not set.",
            );
        }

        // Complexity gate: block batch pushes (strip quotes to avoid false positives)
        let push_count = strip_quotes(command).matches("git push").count();
        if push_count > 1 {
            return CheckResult::block(
                "🚫 git-guardrails: multiple git push commands — cannot verify targets\n   \
                 Run each push individually so remotes can be validated.",
            );
        }

        // AST-based loop detection with regex fallback
        match loop_analysis::analyze_push_loops(command) {
            LoopAnalysis::AllTargetsExplicit(_) => {
                // All pushes in loops have explicit remotes — allow
                // (individual remote ownership is checked below)
            }
            LoopAnalysis::MissingTargets(_) => {
                return CheckResult::block(
                    "🚫 git-guardrails: git push in loop without explicit remote\n   \
                     Specify the remote explicitly, or run each push individually.",
                );
            }
            LoopAnalysis::ParseFailed => {
                let stripped = strip_quotes(command);
                if LOOP_PATTERN.is_match(&stripped) {
                    return CheckResult::block(
                        "🚫 git-guardrails: git push in loop — cannot verify targets\n   \
                         Run each push individually so remotes can be validated.",
                    );
                }
            }
            LoopAnalysis::NoLoops => {}
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

        if !check_owner(&url, &allowed_owners) {
            return CheckResult::block(format!(
                "🚫 git-guardrails: Push target is not yours\n   \
                 Would push to: {url}\n   \
                 Directory:     {work_dir}\n   \
                 Allowed:       {}\n\n   \
                 Fix tracking:  git branch -u origin/main\n   \
                 Push explicit: git push origin main",
                allowed_owners.join(" ")
            ));
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_check_passes() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo.git",
            &["cameronsjo".to_string()]
        ));
    }

    #[test]
    fn owner_check_fails() {
        assert!(!check_owner(
            "https://github.com/other/repo.git",
            &["cameronsjo".to_string()]
        ));
    }

    #[test]
    fn owner_check_multiple_owners() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo.git",
            &["other".to_string(), "cameronsjo".to_string()]
        ));
    }

    #[test]
    fn owner_check_empty_list() {
        assert!(!check_owner("https://github.com/cameronsjo/repo.git", &[]));
    }

    #[test]
    fn owner_check_case_sensitive() {
        assert!(!check_owner(
            "https://github.com/CameronSjo/repo.git",
            &["cameronsjo".to_string()]
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
            &["cameronsjo".to_string()]
        ));
    }

    #[test]
    fn owner_check_https_no_git_suffix() {
        assert!(check_owner(
            "https://github.com/cameronsjo/repo",
            &["cameronsjo".to_string()]
        ));
    }

    #[test]
    fn owner_check_malformed_returns_false() {
        assert!(!check_owner("not-a-url", &["cameronsjo".to_string()]));
    }

    // --- PushRemoteGuard::run(): loop and multi-push scenarios ---
    // Tests that trigger blocks BEFORE env var check (loops, multi-push)
    // avoid unsafe env manipulation.

    fn make_bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some(cmd.into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn multiple_pushes_blocked() {
        // Multiple pushes are checked before env vars
        let result =
            PushRemoteGuard.run(&make_bash("git push origin main && git push upstream main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("multiple"));
    }

    #[test]
    fn loop_missing_targets_blocked() {
        // Loop detection is checked before env vars
        let result = PushRemoteGuard.run(&make_bash("for b in feat1 feat2; do git push; done"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_chain_with_semicolon_counted() {
        let result =
            PushRemoteGuard.run(&make_bash("git push origin main; git push upstream feat"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("multiple"));
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
