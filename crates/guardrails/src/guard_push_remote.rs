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
        after_scheme.splitn(2, '/').nth(1)?
    } else if let Some(after_colon) = trimmed.splitn(2, ':').nth(1) {
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
        let target = caps
            .get(1)
            .or(caps.get(2))
            .map(|m| m.as_str().to_string());
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
        assert_eq!(
            parse_work_dir("cd /tmp && git push", "/home/user"),
            "/tmp"
        );
    }

    #[test]
    fn parse_no_cd_uses_cwd() {
        assert_eq!(
            parse_work_dir("git push origin main", "/home/user"),
            "/home/user"
        );
    }
}
