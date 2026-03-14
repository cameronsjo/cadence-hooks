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

/// Extract `owner/repo` from any git remote URL format.
///
/// Handles:
/// - `https://github.com/owner/repo.git`
/// - `ssh://git@github.com/owner/repo.git`
/// - `git@github.com:owner/repo.git` (SCP-style)
/// - URLs with ports, credentials, trailing slashes, and subpaths
pub fn repo_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim();

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
    Regex::new(r#"(?:^|&&|;|\|\|)\s*cd\s+(?:"([^"]*)"|([^ &;|]+))"#)
        .expect("pattern should compile")
});

/// Extract the effective working directory from `cd` chains in a command.
///
/// Finds the last `cd <target>` before other commands and resolves it:
/// - Absolute paths returned as-is
/// - `~` expanded via `$HOME`
/// - Relative paths joined with `cwd`
/// - No `cd` found returns `cwd` unchanged
pub fn parse_work_dir(command: &str, cwd: &str) -> String {
    let mut last_target: Option<String> = None;
    for caps in CD_PATTERN.captures_iter(command) {
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
    fn multiple_cd_uses_last() {
        assert_eq!(
            parse_work_dir("cd /first && cd /second && git push", "/home/user"),
            "/second"
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
    fn cd_with_pipe() {
        assert_eq!(
            parse_work_dir("cd /project || git push", "/home"),
            "/project"
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
        assert_eq!(
            parse_work_dir("cd /first && cd /second; cd /third && git push", "/home"),
            "/third"
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
