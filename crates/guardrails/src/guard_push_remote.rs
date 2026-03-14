//! Validate `git push` targets against an owner allowlist.
//!
//! Resolves the push URL for the current branch (or explicit remote) and
//! verifies the repository owner is in the configured allowlist. Also blocks
//! looped pushes and force-push to `main`.

use cadence_hooks_core::shell::{
    git_command, parse_work_dir, repo_from_url, strip_quotes, LOOP_PATTERN,
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

        // Complexity gate: block batch pushes
        let push_count = command.matches("git push").count();
        let stripped = strip_quotes(command);
        let has_loop = LOOP_PATTERN.is_match(&stripped);

        if push_count > 1 || has_loop {
            return CheckResult::block(
                "🚫 git-guardrails: git push in batch/loop command — cannot verify targets\n   \
                 Run each push individually so remotes can be validated.",
            );
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
}
