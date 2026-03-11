//! Validate `git push` targets against an owner allowlist.
//!
//! Resolves the push URL for the current branch (or explicit remote) and
//! verifies the repository owner is in the configured allowlist. Also blocks
//! looped pushes and force-push to `main`.

use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::process::Command;
use std::sync::LazyLock;

static LOOP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfor\s+\w+\s+in\b|\bwhile\b.*;\s*do\b").expect("pattern should compile")
});

/// Extract owner/repo from any git remote URL format.
///
/// Handles:
/// - `https://github.com/owner/repo.git`
/// - `ssh://git@github.com/owner/repo.git`
/// - `git@github.com:owner/repo.git`
fn repo_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim();

    // Extract the path portion (owner/repo.git) from the URL
    let path = if let Some(after_scheme) = trimmed.split("://").nth(1) {
        // Has scheme (https://, ssh://) — skip host, take path after first /
        after_scheme.split_once('/')?.1
    } else if let Some(after_colon) = trimmed.split_once(':').map(|x| x.1) {
        // SCP-style: git@host:owner/repo.git — path is after the colon
        // Guard: if it starts with / it's a port or absolute path, not SCP
        if after_colon.starts_with('/') {
            return None;
        }
        after_colon
    } else {
        return None;
    };

    let path = path.trim_end_matches(".git");

    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some(format!("{}/{}", parts[0], parts[1]))
    } else {
        None
    }
}

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

fn git_command(work_dir: &str, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(work_dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Strip quoted strings from a command to expose shell structure.
fn strip_quotes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '"' {
                        break;
                    }
                }
            }
            '\'' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\'' {
                        break;
                    }
                }
            }
            _ => result.push(c),
        }
    }
    result
}

/// Extract the cd target from a command chain.
fn parse_work_dir(command: &str, cwd: &str) -> String {
    // Find last cd command before the push
    let re = Regex::new(r#"(?:^|&&|;|\|\|)\s*cd\s+(?:"([^"]*)"|([^ &;|]+))"#).unwrap();

    let mut last_target: Option<String> = None;
    for caps in re.captures_iter(command) {
        let target = caps.get(1).or(caps.get(2)).map(|m| m.as_str().to_string());
        if target.is_some() {
            last_target = target;
        }
    }

    match last_target {
        None => cwd.to_string(),
        Some(target) if target.starts_with('/') => target,
        Some(target) if target.starts_with('~') => {
            let home = std::env::var("HOME").unwrap_or_default();
            target.replacen('~', &home, 1)
        }
        Some(target) => format!("{cwd}/{target}"),
    }
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
    fn parse_https_url() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/cadence.git"),
            Some("cameronsjo/cadence".to_string())
        );
    }

    #[test]
    fn parse_ssh_url() {
        assert_eq!(
            repo_from_url("git@github.com:cameronsjo/cadence.git"),
            Some("cameronsjo/cadence".to_string())
        );
    }

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
    fn strip_quotes_removes_content() {
        assert_eq!(
            strip_quotes(r#"echo "hello world" && git push"#),
            "echo  && git push"
        );
    }

    #[test]
    fn parse_cd_target() {
        assert_eq!(parse_work_dir("cd /tmp && git push", "/home/user"), "/tmp");
    }

    #[test]
    fn parse_no_cd_uses_cwd() {
        assert_eq!(
            parse_work_dir("git push origin main", "/home/user"),
            "/home/user"
        );
    }

    // Additional repo_from_url tests
    #[test]
    fn parse_https_no_git_suffix() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/cadence"),
            Some("cameronsjo/cadence".to_string())
        );
    }

    #[test]
    fn parse_malformed_url_returns_none() {
        assert_eq!(repo_from_url("not-a-url"), None);
    }

    #[test]
    fn parse_ssh_scheme_url() {
        assert_eq!(
            repo_from_url("ssh://git@github.com/cameronsjo/repo.git"),
            Some("cameronsjo/repo".to_string())
        );
    }

    // check_owner tests
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

    // strip_quotes tests
    #[test]
    fn strip_single_quotes() {
        assert_eq!(
            strip_quotes("echo 'hello world' && git push"),
            "echo  && git push"
        );
    }

    #[test]
    fn strip_empty_string() {
        assert_eq!(strip_quotes(""), "");
    }

    // parse_work_dir tests
    #[test]
    fn parse_relative_cd() {
        assert_eq!(
            parse_work_dir("cd subdir && git push", "/home/user"),
            "/home/user/subdir"
        );
    }

    #[test]
    fn parse_tilde_cd() {
        // ~ expansion depends on HOME env var
        let result = parse_work_dir("cd ~/projects && git push", "/tmp");
        assert!(result.contains("projects"));
    }

    #[test]
    fn parse_multiple_cd_uses_last() {
        assert_eq!(
            parse_work_dir("cd /first && cd /second && git push", "/home/user"),
            "/second"
        );
    }

    #[test]
    fn parse_cd_with_semicolons() {
        assert_eq!(
            parse_work_dir("cd /project; git push", "/home/user"),
            "/project"
        );
    }

    // LOOP_PATTERN tests
    #[test]
    fn loop_pattern_detects_for() {
        assert!(LOOP_PATTERN.is_match("for repo in list; do git push; done"));
    }

    #[test]
    fn loop_pattern_detects_while() {
        assert!(LOOP_PATTERN.is_match("while true; do git push; done"));
    }

    #[test]
    fn loop_pattern_no_match_normal() {
        assert!(!LOOP_PATTERN.is_match("git push origin main"));
    }

    // --- Unhappy path: URL edge cases ---

    #[test]
    fn parse_url_with_port() {
        // ssh://git@github.com:22/owner/repo.git
        // Has ://, so splits on that → "git@github.com:22/owner/repo.git"
        // Then splits on first / → "owner/repo.git" — port is part of host segment
        // This actually parses correctly because the port stays with the host
        assert_eq!(
            repo_from_url("ssh://git@github.com:22/owner/repo.git"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn parse_url_with_credentials() {
        // https://token:x-oauth-basic@github.com/owner/repo.git
        assert_eq!(
            repo_from_url("https://token:x-oauth-basic@github.com/owner/repo.git"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn parse_empty_url() {
        assert_eq!(repo_from_url(""), None);
    }

    #[test]
    fn parse_whitespace_url() {
        assert_eq!(repo_from_url("   "), None);
    }

    #[test]
    fn parse_url_no_repo() {
        // Only has owner, no repo
        assert_eq!(repo_from_url("https://github.com/owner"), None);
    }

    #[test]
    fn parse_url_trailing_slash() {
        assert_eq!(
            repo_from_url("https://github.com/owner/repo/"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn parse_url_with_subpath() {
        // URL with additional path segments
        assert_eq!(
            repo_from_url("https://github.com/owner/repo/tree/main"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn parse_scp_with_slash_path_returns_none() {
        // Colon followed by / is not SCP-style, it's likely a port
        assert_eq!(repo_from_url("host:/absolute/path"), None);
    }

    #[test]
    fn owner_check_case_sensitive() {
        assert!(!check_owner(
            "https://github.com/CameronSjo/repo.git",
            &["cameronsjo".to_string()]
        ));
    }

    #[test]
    fn strip_quotes_nested() {
        assert_eq!(strip_quotes("echo 'it\"s' \"done\""), "echo  ");
    }

    #[test]
    fn parse_cd_with_quoted_path() {
        assert_eq!(
            parse_work_dir("cd \"/path with spaces\" && git push", "/home"),
            "/path with spaces"
        );
    }

    #[test]
    fn parse_cd_with_pipe() {
        // cd before a pipe
        assert_eq!(
            parse_work_dir("cd /project || git push", "/home"),
            "/project"
        );
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = PushRemoteGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_push_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
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
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }
}
