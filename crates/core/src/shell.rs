//! Shell parsing utilities shared across hook crates.
//!
//! Provides functions for stripping quoted content, parsing git remote URLs,
//! running git commands, and resolving working directories from `cd` chains.

use regex::Regex;
use std::process::Command;
use std::sync::LazyLock;

/// Strip quoted strings from a shell command to expose its structure.
///
/// Removes content between matching `'` or `"` delimiters (including the
/// delimiters themselves). Unmatched quotes consume the rest of the string.
pub fn strip_quotes(s: &str) -> String {
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

/// Extract `(host, "owner/repo")` from any git remote URL format.
///
/// Handles:
/// - `https://github.com/owner/repo.git`
/// - `ssh://git@github.com/owner/repo.git`
/// - `git@github.com:owner/repo.git` (SCP-style)
/// - URLs with ports, credentials, trailing slashes, and subpaths
pub fn host_and_repo_from_url(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim();

    let (host, path) = if let Some(after_scheme) = trimmed.split("://").nth(1) {
        // Has scheme (https://, ssh://) — extract host, then path after first /
        let (host_part, path) = after_scheme.split_once('/')?;
        // Strip credentials: user@host or token:x-oauth@host
        let host_part = host_part.rsplit('@').next().unwrap_or(host_part);
        // Strip port: host:22
        let host_part = host_part.split(':').next().unwrap_or(host_part);
        (host_part, path)
    } else if let Some((before_colon, after_colon)) = trimmed.split_once(':') {
        // SCP-style: git@host:owner/repo.git — path is after the colon
        // Guard: if it starts with / it's a port or absolute path, not SCP
        if after_colon.starts_with('/') {
            return None;
        }
        // Strip user: git@host
        let host = before_colon.rsplit('@').next().unwrap_or(before_colon);
        (host, after_colon)
    } else {
        return None;
    };

    if host.is_empty() {
        return None;
    }

    let path = path.trim_end_matches(".git");

    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some((host.to_lowercase(), format!("{}/{}", parts[0], parts[1])))
    } else {
        None
    }
}

/// Extract `owner/repo` from any git remote URL format.
///
/// Convenience wrapper around [`host_and_repo_from_url`] that discards the host.
pub fn repo_from_url(url: &str) -> Option<String> {
    host_and_repo_from_url(url).map(|(_, repo)| repo)
}

/// Run a git command in a specific working directory.
///
/// Returns trimmed stdout on success, `None` on failure or empty output.
pub fn git_command(work_dir: &str, args: &[&str]) -> Option<String> {
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

static CD_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Group 1: separator (&&, ;, ||, or empty for start-of-string)
    // Group 2: double-quoted path, Group 3: single-quoted path, Group 4: bare path
    Regex::new(r#"(^|&&|;|\|\|)\s*cd\s+(?:"([^"]*)"|'([^']*)'|([^ &;|]+))"#)
        .expect("pattern should compile")
});

/// Extract the effective working directory from `cd` chains in a command.
///
/// Walks the command left-to-right, splitting by operators (`&&`, `;`, `||`),
/// and accumulates directory changes:
/// - `cd a && cd b` → `cwd/a/b` (both apply on success path)
/// - `cd /abs && cd rel` → `/abs/rel`
/// - `cd a || cmd` → `cwd` (cd before `||` only runs on failure path)
/// - `~` expanded via `$HOME`
/// - No `cd` found returns `cwd` unchanged
pub fn parse_work_dir(command: &str, cwd: &str) -> String {
    let mut effective = cwd.to_string();

    for caps in CD_PATTERN.captures_iter(command) {
        let full_match = caps.get(0).unwrap();
        let after = command[full_match.end()..].trim_start();

        // If this cd is followed by `||`, the commands after `||` only run
        // when the cd fails — so the cd doesn't change the effective directory
        // for those commands.
        if after.starts_with("||") {
            continue;
        }

        let target = caps
            .get(2)
            .or(caps.get(3))
            .or(caps.get(4))
            .map(|m| m.as_str().to_string());

        let Some(target) = target else { continue };

        effective = resolve_cd_target(&target, &effective);
    }

    effective
}

/// Resolve a single cd target against the current effective directory.
fn resolve_cd_target(target: &str, effective: &str) -> String {
    if target.starts_with('/') {
        target.to_string()
    } else if target.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_default();
        target.replacen('~', &home, 1)
    } else {
        format!("{effective}/{target}")
    }
}

/// Regex pattern for detecting shell loops (`for ... in` / `while ... do`).
pub static LOOP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bfor\s+\w+\s+in\b|\bwhile\b.*;\s*do\b").expect("pattern should compile")
});

#[cfg(test)]
mod tests {
    use super::*;

    // --- strip_quotes ---

    #[test]
    fn preserves_unquoted() {
        assert_eq!(strip_quotes("gh pr create"), "gh pr create");
    }

    #[test]
    fn removes_double_quoted_content() {
        assert_eq!(strip_quotes("echo \"hello\" world"), "echo  world");
    }

    #[test]
    fn removes_single_quoted_content() {
        assert_eq!(strip_quotes("echo 'hello' world"), "echo  world");
    }

    #[test]
    fn removes_empty_quotes() {
        assert_eq!(strip_quotes("echo \"\" world"), "echo  world");
    }

    #[test]
    fn strips_mixed_quotes() {
        assert_eq!(
            strip_quotes("gh pr create --title 'test' --body \"desc\""),
            "gh pr create --title  --body "
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn unmatched_quote_consumes_rest() {
        assert_eq!(strip_quotes("echo \"unterminated"), "echo ");
    }

    #[test]
    fn nested_quotes() {
        assert_eq!(strip_quotes("echo 'it\"s' \"done\""), "echo  ");
    }

    // --- repo_from_url ---

    #[test]
    fn https_url() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/repo.git"),
            Some("cameronsjo/repo".to_string())
        );
    }

    #[test]
    fn https_url_no_git_suffix() {
        assert_eq!(
            repo_from_url("https://github.com/cameronsjo/repo"),
            Some("cameronsjo/repo".to_string())
        );
    }

    #[test]
    fn ssh_scp_url() {
        assert_eq!(
            repo_from_url("git@github.com:cameronsjo/repo.git"),
            Some("cameronsjo/repo".to_string())
        );
    }

    #[test]
    fn ssh_scheme_url() {
        assert_eq!(
            repo_from_url("ssh://git@github.com/cameronsjo/repo.git"),
            Some("cameronsjo/repo".to_string())
        );
    }

    #[test]
    fn url_with_port() {
        assert_eq!(
            repo_from_url("ssh://git@github.com:22/owner/repo.git"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn url_with_credentials() {
        assert_eq!(
            repo_from_url("https://token:x-oauth-basic@github.com/owner/repo.git"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn url_trailing_slash() {
        assert_eq!(
            repo_from_url("https://github.com/owner/repo/"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn url_with_subpath() {
        assert_eq!(
            repo_from_url("https://github.com/owner/repo/tree/main"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn malformed_url_returns_none() {
        assert_eq!(repo_from_url("not-a-url"), None);
    }

    #[test]
    fn empty_url() {
        assert_eq!(repo_from_url(""), None);
    }

    #[test]
    fn whitespace_url() {
        assert_eq!(repo_from_url("   "), None);
    }

    #[test]
    fn url_no_repo_segment() {
        assert_eq!(repo_from_url("https://github.com/owner"), None);
    }

    #[test]
    fn scp_with_slash_path_returns_none() {
        assert_eq!(repo_from_url("host:/absolute/path"), None);
    }

    // --- parse_work_dir ---

    #[test]
    fn absolute_cd() {
        assert_eq!(parse_work_dir("cd /tmp && git push", "/home/user"), "/tmp");
    }

    #[test]
    fn no_cd_uses_cwd() {
        assert_eq!(
            parse_work_dir("git push origin main", "/home/user"),
            "/home/user"
        );
    }

    #[test]
    fn relative_cd() {
        assert_eq!(
            parse_work_dir("cd subdir && git push", "/home/user"),
            "/home/user/subdir"
        );
    }

    #[test]
    fn tilde_cd() {
        let result = parse_work_dir("cd ~/projects && git push", "/tmp");
        assert!(result.contains("projects"));
    }

    #[test]
    fn multiple_absolute_cd_uses_last() {
        assert_eq!(
            parse_work_dir("cd /first && cd /second && git push", "/home/user"),
            "/second"
        );
    }

    #[test]
    fn chained_relative_cds_accumulate() {
        assert_eq!(
            parse_work_dir("cd repo && cd nested && git push", "/home/user"),
            "/home/user/repo/nested"
        );
    }

    #[test]
    fn cd_with_semicolons() {
        assert_eq!(
            parse_work_dir("cd /project; git push", "/home/user"),
            "/project"
        );
    }

    #[test]
    fn cd_with_quoted_path() {
        assert_eq!(
            parse_work_dir("cd \"/path with spaces\" && git push", "/home"),
            "/path with spaces"
        );
    }

    #[test]
    fn cd_before_or_does_not_apply() {
        // cd before || only runs on success; git push runs on failure,
        // so the push executes from the original cwd, not /project.
        assert_eq!(parse_work_dir("cd /project || git push", "/home"), "/home");
    }

    #[test]
    fn cd_with_single_quoted_path() {
        assert_eq!(
            parse_work_dir("cd '/path with spaces' && git push", "/home"),
            "/path with spaces"
        );
    }

    // --- LOOP_PATTERN ---

    #[test]
    fn detects_for_loop() {
        assert!(LOOP_PATTERN.is_match("for repo in list; do git push; done"));
    }

    #[test]
    fn detects_while_loop() {
        assert!(LOOP_PATTERN.is_match("while true; do git push; done"));
    }

    #[test]
    fn no_match_normal_command() {
        assert!(!LOOP_PATTERN.is_match("git push origin main"));
    }

    // --- host_and_repo_from_url ---

    #[test]
    fn host_and_repo_https() {
        assert_eq!(
            host_and_repo_from_url("https://github.com/cameronsjo/repo.git"),
            Some(("github.com".to_string(), "cameronsjo/repo".to_string()))
        );
    }

    #[test]
    fn host_and_repo_ssh_scp() {
        assert_eq!(
            host_and_repo_from_url("git@gitea.internal:cameron/cadence.git"),
            Some(("gitea.internal".to_string(), "cameron/cadence".to_string()))
        );
    }

    #[test]
    fn host_and_repo_ssh_scheme() {
        assert_eq!(
            host_and_repo_from_url("ssh://git@github.com/owner/repo.git"),
            Some(("github.com".to_string(), "owner/repo".to_string()))
        );
    }

    #[test]
    fn host_and_repo_with_port() {
        assert_eq!(
            host_and_repo_from_url("ssh://git@github.com:22/owner/repo.git"),
            Some(("github.com".to_string(), "owner/repo".to_string()))
        );
    }

    #[test]
    fn host_and_repo_with_credentials() {
        assert_eq!(
            host_and_repo_from_url("https://token:x-oauth-basic@github.com/owner/repo.git"),
            Some(("github.com".to_string(), "owner/repo".to_string()))
        );
    }

    #[test]
    fn host_and_repo_custom_host() {
        assert_eq!(
            host_and_repo_from_url("https://gitea.internal/cameron/cadence"),
            Some(("gitea.internal".to_string(), "cameron/cadence".to_string()))
        );
    }

    #[test]
    fn host_and_repo_normalizes_host_case() {
        assert_eq!(
            host_and_repo_from_url("https://GitHub.COM/owner/repo"),
            Some(("github.com".to_string(), "owner/repo".to_string()))
        );
    }

    #[test]
    fn host_and_repo_malformed_returns_none() {
        assert_eq!(host_and_repo_from_url("not-a-url"), None);
    }

    #[test]
    fn host_and_repo_no_repo_segment() {
        assert_eq!(host_and_repo_from_url("https://github.com/owner"), None);
    }

    // --- adversarial: repo_from_url ---

    #[test]
    fn git_protocol_url() {
        assert_eq!(
            repo_from_url("git://github.com/owner/repo.git"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn empty_owner_returns_none() {
        assert_eq!(repo_from_url("https://github.com//repo.git"), None);
    }

    #[test]
    fn owner_only_no_repo() {
        assert_eq!(repo_from_url("https://github.com/owner"), None);
    }

    #[test]
    fn deep_path_takes_first_two() {
        assert_eq!(
            repo_from_url("https://github.com/owner/repo/tree/main/src"),
            Some("owner/repo".to_string())
        );
    }

    #[test]
    fn url_with_query_string() {
        // Query string is part of the path after splitn — repo extracts cleanly
        // because splitn(3, '/') captures at most 3 segments
        let result = repo_from_url("https://github.com/owner/repo?tab=readme");
        assert_eq!(result, Some("owner/repo?tab=readme".to_string()));
    }

    #[test]
    fn url_with_fragment() {
        let result = repo_from_url("https://github.com/owner/repo#section");
        assert_eq!(result, Some("owner/repo#section".to_string()));
    }

    #[test]
    fn empty_string_returns_none() {
        assert_eq!(repo_from_url(""), None);
    }

    // --- adversarial: strip_quotes ---

    #[test]
    fn unicode_smart_quotes_not_stripped() {
        // Smart quotes (U+201C, U+201D) are not stripped — only ASCII quotes
        assert_eq!(
            strip_quotes("echo \u{201c}hello\u{201d}"),
            "echo \u{201c}hello\u{201d}"
        );
    }

    // --- adversarial: parse_work_dir ---

    #[test]
    fn semicolon_no_space() {
        assert_eq!(parse_work_dir("cd /project;git push", "/home"), "/project");
    }

    #[test]
    fn relative_parent_path() {
        assert_eq!(
            parse_work_dir("cd ../sibling && git push", "/home/user/project"),
            "/home/user/project/../sibling"
        );
    }

    #[test]
    fn mixed_separators() {
        // All three cds are on && or ; path — each absolute overrides
        assert_eq!(
            parse_work_dir("cd /first && cd /second; cd /third && git push", "/home"),
            "/third"
        );
    }

    #[test]
    fn cd_or_then_and_cd() {
        // cd /fail || cd /recover && git push
        // cd /fail is before ||, so skipped; cd /recover is on success path
        assert_eq!(
            parse_work_dir("cd /fail || cd /recover && git push", "/home"),
            "/recover"
        );
    }

    #[test]
    fn no_cd_returns_cwd() {
        assert_eq!(
            parse_work_dir("git push origin main", "/workspace"),
            "/workspace"
        );
    }

    #[test]
    fn cd_in_double_quotes_not_executed() {
        // cd inside quotes should still be captured by the regex if quoted path
        let result = parse_work_dir("cd \"/some/path\" && git push", "/home");
        assert_eq!(result, "/some/path");
    }

    // --- adversarial: LOOP_PATTERN ---

    #[test]
    fn incomplete_for_without_do_still_matches() {
        // LOOP_PATTERN is intentionally broad — matches "for x in" even without "do"
        // The AST parser handles syntactic validation; regex is a safety net
        assert!(LOOP_PATTERN.is_match("for x in 1 2 3"));
    }

    #[test]
    fn for_in_word_boundary() {
        // "information" contains "for" but not as a word boundary
        assert!(!LOOP_PATTERN.is_match("echo information about this"));
    }
}
