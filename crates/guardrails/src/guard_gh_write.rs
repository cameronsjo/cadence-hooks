use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::process::Command;
use std::sync::LazyLock;

// --- Write detection patterns ---

static WRITE_ACTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"gh\s+(pr|issue|release|label|repo|gist|workflow)\s+(create|merge|close|comment|edit|delete|transfer|archive|rename|review|reopen|ready|lock|unlock|fork|run|enable|disable)"
    ).expect("pattern should compile")
});

static API_WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*(-X|--method)\s+(POST|PUT|PATCH|DELETE)")
        .expect("pattern should compile")
});

static API_FIELD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*\s(-f\s|--field\s|-F\s|--raw-field\s)")
        .expect("pattern should compile")
});

static API_INPUT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+api.*\s--input\s").expect("pattern should compile"));

static LOOP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfor\s+\w+\s+in\b|\bwhile\b.*;\s*do\b").expect("pattern should compile")
});

static REPO_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(-R|--repo)\s+([^ ]+)").expect("pattern should compile")
});

static REPO_CREATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+repo\s+create\b").expect("pattern should compile"));

static API_REPOS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/?repos/([^/]+/[^/ ]+)").expect("pattern should compile")
});

fn is_write_command(command: &str) -> bool {
    WRITE_ACTIONS.is_match(command)
        || API_WRITE_METHOD.is_match(command)
        || API_FIELD_FLAGS.is_match(command)
        || API_INPUT_FLAG.is_match(command)
}

fn strip_quotes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '"' { break; }
                }
            }
            '\'' => {
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\'' { break; }
                }
            }
            _ => result.push(c),
        }
    }
    result
}

fn repo_from_url(url: &str) -> String {
    url.trim()
        .split("://")
        .last()
        .unwrap_or(url)
        .splitn(2, '/')
        .last()
        .unwrap_or(url)
        .trim_end_matches(".git")
        .splitn(3, '/')
        .take(2)
        .collect::<Vec<&str>>()
        .join("/")
}

fn git_cmd(work_dir: &str, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C").arg(work_dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve target repo from command context.
enum RepoResolution {
    Resolved(String),
    Fork { origin: String, upstream: String },
    Unresolvable,
}

fn resolve_target_repo(command: &str, work_dir: &str, allowed_owners: &[String]) -> RepoResolution {
    // 1. Explicit -R / --repo flag
    if let Some(caps) = REPO_FLAG.captures(command)
        && let Some(repo) = caps.get(2) {
            return RepoResolution::Resolved(repo.as_str().to_string());
        }

    // 2. gh repo create <name>
    if REPO_CREATE.is_match(command) {
        let after = command.split("gh repo create").nth(1).unwrap_or("").trim();
        let first_arg = after.split_whitespace().next().unwrap_or("");
        if !first_arg.is_empty() && !first_arg.starts_with('-') {
            if first_arg.contains('/') {
                return RepoResolution::Resolved(first_arg.to_string());
            }
            let default_owner = allowed_owners.first().map(|s| s.as_str()).unwrap_or("");
            return RepoResolution::Resolved(format!("{default_owner}/{first_arg}"));
        }
    }

    // 3. gh api repos/OWNER/REPO
    if let Some(caps) = API_REPOS.captures(command)
        && let Some(repo) = caps.get(1) {
            return RepoResolution::Resolved(repo.as_str().to_string());
        }

    // 4. Git remotes (with fork detection)
    if let Some(upstream_url) = git_cmd(work_dir, &["remote", "get-url", "upstream"]) {
        let origin_url = git_cmd(work_dir, &["remote", "get-url", "origin"]).unwrap_or_default();
        return RepoResolution::Fork {
            origin: repo_from_url(&origin_url),
            upstream: repo_from_url(&upstream_url),
        };
    }

    if let Some(origin_url) = git_cmd(work_dir, &["remote", "get-url", "origin"]) {
        return RepoResolution::Resolved(repo_from_url(&origin_url));
    }

    RepoResolution::Unresolvable
}

fn is_allowed(repo: &str, allowed_owners: &[String], allowed_repos: &[String]) -> bool {
    if allowed_repos.iter().any(|r| r == repo) {
        return true;
    }
    let owner = repo.split('/').next().unwrap_or("");
    allowed_owners.iter().any(|a| a == owner)
}

pub struct GhWriteGuard;

impl Check for GhWriteGuard {
    fn name(&self) -> &str {
        "guard-gh-write"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("gh") {
            return CheckResult::allow();
        }

        let allowed_owners: Vec<String> = std::env::var("GIT_GUARDRAILS_ALLOWED_OWNERS")
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        let allowed_repos: Vec<String> = std::env::var("GIT_GUARDRAILS_ALLOWED_REPOS")
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        // Loop detection
        let stripped = strip_quotes(command);
        if LOOP_PATTERN.is_match(&stripped) && command.contains("gh") {
            return CheckResult::block(
                "🚫 git-guardrails: gh command in loop — cannot verify targets\n   \
                 Run each gh command individually.",
            );
        }

        // Only guard write operations
        if !is_write_command(command) {
            return CheckResult::allow();
        }

        // Fail-safe: block when unconfigured
        if allowed_owners.is_empty() {
            return CheckResult::block(
                "🚫 git-guardrails: Not configured — run /guardrails-init to set up\n   \
                 GIT_GUARDRAILS_ALLOWED_OWNERS is not set.",
            );
        }

        // Gists are user-scoped
        if Regex::new(r"gh\s+gist\s").unwrap().is_match(command) {
            return CheckResult::allow();
        }

        // Fork creates under your account
        if Regex::new(r"gh\s+repo\s+fork\b").unwrap().is_match(command) {
            return CheckResult::allow();
        }

        let cwd = input.cwd.as_deref().unwrap_or(".");
        let work_dir = cwd; // Simplified — full cd parsing in guard_push_remote

        match resolve_target_repo(command, work_dir, &allowed_owners) {
            RepoResolution::Fork { origin, upstream } => CheckResult::block(format!(
                "🚫 git-guardrails: Write operation in a fork — specify target with -R\n   \
                 Fork:     {origin}\n   \
                 Upstream: {upstream}\n\n   \
                 Use -R {origin} to target your fork\n   \
                 Use -R {upstream} to target upstream (if intended)"
            )),
            RepoResolution::Unresolvable => CheckResult::block(
                "⚠️  git-guardrails: Cannot determine target repo for gh write operation\n   \
                 Use -R owner/repo to specify target explicitly.",
            ),
            RepoResolution::Resolved(repo) => {
                if is_allowed(&repo, &allowed_owners, &allowed_repos) {
                    CheckResult::allow()
                } else {
                    CheckResult::block(format!(
                        "🚫 git-guardrails: gh write targets repo you don't own\n   \
                         Target:  {repo}\n   \
                         Allowed: owners=[{}] repos=[{}]\n\n   \
                         DO NOT override with env vars. Instead:\n   \
                         1. Confirm the user intends to write to this repo\n   \
                         2. Write a shell script the user can execute manually",
                        allowed_owners.join(" "),
                        allowed_repos.join(" ")
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pr_create_as_write() {
        assert!(is_write_command("gh pr create --title test"));
    }

    #[test]
    fn detects_api_post_as_write() {
        assert!(is_write_command("gh api repos/foo/bar -X POST"));
    }

    #[test]
    fn pr_list_is_not_write() {
        assert!(!is_write_command("gh pr list"));
    }

    #[test]
    fn repo_flag_extraction() {
        let caps = REPO_FLAG.captures("gh pr create -R cameronsjo/test --title hi");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(2).unwrap().as_str(), "cameronsjo/test");
    }

    #[test]
    fn repo_flag_long_form() {
        let caps = REPO_FLAG.captures("gh issue create --repo cameronsjo/test --title hi");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(2).unwrap().as_str(), "cameronsjo/test");
    }

    // Write detection patterns
    #[test]
    fn issue_create_is_write() {
        assert!(is_write_command("gh issue create --title test"));
    }

    #[test]
    fn release_create_is_write() {
        assert!(is_write_command("gh release create v1.0.0"));
    }

    #[test]
    fn pr_merge_is_write() {
        assert!(is_write_command("gh pr merge 123"));
    }

    #[test]
    fn pr_close_is_write() {
        assert!(is_write_command("gh pr close 123"));
    }

    #[test]
    fn issue_comment_is_write() {
        assert!(is_write_command("gh issue comment 123 --body 'hello'"));
    }

    #[test]
    fn repo_fork_is_write() {
        assert!(is_write_command("gh repo fork owner/repo"));
    }

    #[test]
    fn api_put_is_write() {
        assert!(is_write_command("gh api repos/foo/bar -X PUT"));
    }

    #[test]
    fn api_delete_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --method DELETE"));
    }

    #[test]
    fn api_with_field_is_write() {
        assert!(is_write_command("gh api repos/foo/bar -f title=test"));
    }

    #[test]
    fn api_with_input_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --input data.json"));
    }

    #[test]
    fn issue_list_is_not_write() {
        assert!(!is_write_command("gh issue list"));
    }

    #[test]
    fn pr_view_is_not_write() {
        assert!(!is_write_command("gh pr view 123"));
    }

    #[test]
    fn api_get_is_not_write() {
        assert!(!is_write_command("gh api repos/foo/bar"));
    }

    // is_allowed
    #[test]
    fn is_allowed_by_owner() {
        assert!(is_allowed(
            "cameronsjo/repo",
            &["cameronsjo".to_string()],
            &[]
        ));
    }

    #[test]
    fn is_allowed_by_repo() {
        assert!(is_allowed(
            "other/repo",
            &[],
            &["other/repo".to_string()]
        ));
    }

    #[test]
    fn is_not_allowed_unknown() {
        assert!(!is_allowed(
            "stranger/repo",
            &["cameronsjo".to_string()],
            &[]
        ));
    }

    // strip_quotes
    #[test]
    fn strip_quotes_preserves_unquoted() {
        assert_eq!(strip_quotes("gh pr create"), "gh pr create");
    }

    // repo_from_url
    #[test]
    fn repo_from_https_url() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/repo.git"),
            "cameronsjo/repo"
        );
    }

    #[test]
    fn repo_from_https_url_no_git() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/repo"),
            "cameronsjo/repo"
        );
    }

    // API repos pattern
    #[test]
    fn api_repos_pattern_matches() {
        let caps = API_REPOS.captures("gh api repos/cameronsjo/test/pulls");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(1).unwrap().as_str(), "cameronsjo/test");
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn loop_pattern_detects_for_loop() {
        assert!(LOOP_PATTERN.is_match("for repo in list; do gh pr create; done"));
    }

    #[test]
    fn loop_pattern_detects_while_loop() {
        assert!(LOOP_PATTERN.is_match("while true; do gh pr merge; done"));
    }

    #[test]
    fn loop_pattern_no_match_normal() {
        assert!(!LOOP_PATTERN.is_match("gh pr create --title test"));
    }

    #[test]
    fn workflow_run_is_write() {
        assert!(is_write_command("gh workflow run deploy.yml"));
    }

    #[test]
    fn workflow_enable_is_write() {
        assert!(is_write_command("gh workflow enable deploy.yml"));
    }

    #[test]
    fn workflow_disable_is_write() {
        assert!(is_write_command("gh workflow disable deploy.yml"));
    }

    #[test]
    fn label_create_is_write() {
        assert!(is_write_command("gh label create bug"));
    }

    #[test]
    fn gist_create_is_write() {
        assert!(is_write_command("gh gist create file.txt"));
    }

    #[test]
    fn issue_edit_is_write() {
        assert!(is_write_command("gh issue edit 123 --title new"));
    }

    #[test]
    fn pr_review_is_write() {
        assert!(is_write_command("gh pr review 123 --approve"));
    }

    #[test]
    fn pr_ready_is_write() {
        assert!(is_write_command("gh pr ready 123"));
    }

    #[test]
    fn issue_reopen_is_write() {
        assert!(is_write_command("gh issue reopen 123"));
    }

    #[test]
    fn issue_lock_is_write() {
        assert!(is_write_command("gh issue lock 123"));
    }

    #[test]
    fn repo_archive_is_write() {
        assert!(is_write_command("gh repo archive owner/repo"));
    }

    #[test]
    fn repo_rename_is_write() {
        assert!(is_write_command("gh repo rename new-name"));
    }

    #[test]
    fn release_delete_is_write() {
        assert!(is_write_command("gh release delete v1.0.0"));
    }

    #[test]
    fn api_patch_is_write() {
        assert!(is_write_command("gh api repos/foo/bar -X PATCH -f title=new"));
    }

    #[test]
    fn api_method_patch_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --method PATCH"));
    }

    #[test]
    fn repo_view_is_not_write() {
        assert!(!is_write_command("gh repo view owner/repo"));
    }

    #[test]
    fn release_list_is_not_write() {
        assert!(!is_write_command("gh release list"));
    }

    #[test]
    fn is_allowed_empty_lists() {
        assert!(!is_allowed("owner/repo", &[], &[]));
    }

    #[test]
    fn is_allowed_exact_repo_match() {
        assert!(is_allowed(
            "external/specific-repo",
            &[],
            &["external/specific-repo".to_string()]
        ));
    }

    #[test]
    fn is_allowed_owner_and_repo() {
        // Both match — should still return true
        assert!(is_allowed(
            "cameronsjo/repo",
            &["cameronsjo".to_string()],
            &["cameronsjo/repo".to_string()]
        ));
    }

    #[test]
    fn strip_quotes_mixed() {
        assert_eq!(
            strip_quotes("gh pr create --title 'test' --body \"desc\""),
            "gh pr create --title  --body "
        );
    }

    #[test]
    fn repo_from_ssh_url_known_limitation() {
        // guard_gh_write's repo_from_url uses a simpler parser than guard_push_remote's.
        // SCP-style URLs (git@host:owner/repo) are not properly handled here —
        // it splits on "://" (no match), then splits on "/" getting the wrong segments.
        let result = repo_from_url("git@github.com:cameronsjo/repo.git");
        // "git@github.com:cameronsjo" / "repo" → only gets "repo"
        assert_eq!(result, "repo");
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GhWriteGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("ls -la".into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = GhWriteGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }
}
