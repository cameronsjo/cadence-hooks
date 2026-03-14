//! Guard against unintended `gh` write operations.
//!
//! Detects `gh` sub-commands that mutate GitHub state (create, merge, close,
//! comment, edit, delete, etc.) and verifies the target repository belongs to
//! an allowed owner list. Also blocks looped writes and cross-repo mutations.

use cadence_hooks_core::loop_analysis::{self, LoopAnalysis};
use cadence_hooks_core::shell::{
    LOOP_PATTERN, git_command, parse_work_dir, repo_from_url, strip_quotes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

// --- Write detection patterns ---

static WRITE_ACTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"gh\s+(pr|issue|release|label|repo|gist|workflow)\s+(create|merge|close|comment|edit|delete|transfer|archive|rename|review|reopen|ready|lock|unlock|fork|run|enable|disable)"
    ).expect("pattern should compile")
});

static API_WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*(-X|--method)\s+(?i)(POST|PUT|PATCH|DELETE)")
        .expect("pattern should compile")
});

static API_FIELD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*\s(-f[\s\S]|--field[\s=]|-F[\s\S]|--raw-field[\s=])")
        .expect("pattern should compile")
});

static API_INPUT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+api.*\s--input\s").expect("pattern should compile"));

static REPO_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(-R|--repo)\s+([^ ]+)").expect("pattern should compile"));

static REPO_CREATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+repo\s+create\b").expect("pattern should compile"));

static API_REPOS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/?repos/([^/]+/[^/ ]+)").expect("pattern should compile"));

fn is_write_command(command: &str) -> bool {
    WRITE_ACTIONS.is_match(command)
        || API_WRITE_METHOD.is_match(command)
        || API_FIELD_FLAGS.is_match(command)
        || API_INPUT_FLAG.is_match(command)
}

/// Resolve target repo from command context.
#[derive(Debug)]
enum RepoResolution {
    Resolved(String),
    Fork { origin: String, upstream: String },
    Unresolvable,
}

fn resolve_target_repo(command: &str, work_dir: &str, allowed_owners: &[String]) -> RepoResolution {
    // 1. Explicit -R / --repo flag
    if let Some(caps) = REPO_FLAG.captures(command)
        && let Some(repo) = caps.get(2)
    {
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
        && let Some(repo) = caps.get(1)
    {
        return RepoResolution::Resolved(repo.as_str().to_string());
    }

    // 4. Git remotes (with fork detection)
    if let Some(upstream_url) = git_command(work_dir, &["remote", "get-url", "upstream"]) {
        let origin_url =
            git_command(work_dir, &["remote", "get-url", "origin"]).unwrap_or_default();
        return RepoResolution::Fork {
            origin: repo_from_url(&origin_url).unwrap_or_default(),
            upstream: repo_from_url(&upstream_url).unwrap_or_default(),
        };
    }

    if let Some(origin_url) = git_command(work_dir, &["remote", "get-url", "origin"]) {
        match repo_from_url(&origin_url) {
            Some(repo) => return RepoResolution::Resolved(repo),
            None => return RepoResolution::Unresolvable,
        }
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

/// Guards against unintended `gh` CLI write operations on unauthorized repositories.
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

        // AST-based loop detection with regex fallback
        match loop_analysis::analyze_gh_loops(command) {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                // All gh commands in loops have explicit -R flags — check ownership
                let all_owned = cmds.iter().all(|c| {
                    c.explicit_repo
                        .as_ref()
                        .is_some_and(|r| is_allowed(r, &allowed_owners, &allowed_repos))
                });
                if !all_owned {
                    let targets: Vec<&str> = cmds
                        .iter()
                        .filter_map(|c| c.explicit_repo.as_deref())
                        .collect();
                    return CheckResult::block(format!(
                        "🚫 git-guardrails: gh loop targets repo you don't own\n   \
                         Targets: {}\n   \
                         Allowed: owners=[{}] repos=[{}]",
                        targets.join(", "),
                        allowed_owners.join(" "),
                        allowed_repos.join(" "),
                    ));
                }
                // All targets owned — allow the loop
            }
            LoopAnalysis::MissingTargets(_) => {
                return CheckResult::block(
                    "🚫 git-guardrails: gh command in loop without explicit -R flag\n   \
                     Use -R owner/repo on each gh command, or run them individually.",
                );
            }
            LoopAnalysis::ParseFailed => {
                // Regex fallback when AST parser can't handle the syntax
                let stripped = strip_quotes(command);
                if LOOP_PATTERN.is_match(&stripped) {
                    return CheckResult::block(
                        "🚫 git-guardrails: gh command in loop — cannot verify targets\n   \
                         Run each gh command individually.",
                    );
                }
            }
            LoopAnalysis::NoLoops => {} // Continue to write detection
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
        let work_dir = parse_work_dir(command, cwd);

        match resolve_target_repo(command, &work_dir, &allowed_owners) {
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
    use cadence_hooks_core::loop_analysis::{LoopAnalysis, analyze_gh_loops};

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
        assert!(is_allowed("other/repo", &[], &["other/repo".to_string()]));
    }

    #[test]
    fn is_not_allowed_unknown() {
        assert!(!is_allowed(
            "stranger/repo",
            &["cameronsjo".to_string()],
            &[]
        ));
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
        assert!(is_write_command(
            "gh api repos/foo/bar -X PATCH -f title=new"
        ));
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
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GhWriteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- edge case hardening ---

    #[test]
    fn loop_explicit_unowned_blocks() {
        // Loop with -R pointing to unowned repo should block
        let result =
            analyze_gh_loops("for i in 1 2; do gh label create bug -R stranger/repo; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("stranger/repo"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn gist_create_detected_as_write() {
        assert!(is_write_command("gh gist create file.txt"));
    }

    #[test]
    fn repo_fork_detected_as_write() {
        assert!(is_write_command("gh repo fork owner/repo"));
    }

    #[test]
    fn api_repos_with_query_params() {
        let caps = API_REPOS.captures("gh api repos/cameronsjo/test/pulls?state=open");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(1).unwrap().as_str(), "cameronsjo/test");
    }

    #[test]
    fn repo_create_without_owner_uses_default() {
        // resolve_target_repo for "gh repo create my-repo" without owner
        // should prepend the first allowed owner
        let allowed = vec!["cameronsjo".to_string()];
        let resolved = resolve_target_repo("gh repo create my-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved(repo) => {
                assert_eq!(repo, "cameronsjo/my-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_create_with_owner() {
        let allowed = vec!["cameronsjo".to_string()];
        let resolved = resolve_target_repo("gh repo create cameronsjo/new-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved(repo) => {
                assert_eq!(repo, "cameronsjo/new-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn api_compact_field_flag_detected() {
        // Bug: -fkey=value (no space after -f) evades write detection
        assert!(
            is_write_command("gh api repos/foo/bar -ftitle=test"),
            "compact -f flag should be detected as write"
        );
    }

    #[test]
    fn uppercase_method_not_matched() {
        // "gh pr VIEW" is not a write — "VIEW" not in write actions list
        assert!(!is_write_command("gh pr view 123"));
    }

    #[test]
    fn api_lowercase_post_is_write() {
        assert!(
            is_write_command("gh api repos/stranger/repo -X post"),
            "lowercase HTTP method should be detected as write"
        );
    }

    #[test]
    fn api_mixed_case_delete_is_write() {
        assert!(
            is_write_command("gh api repos/foo/bar --method Delete"),
            "mixed-case HTTP method should be detected as write"
        );
    }
}
