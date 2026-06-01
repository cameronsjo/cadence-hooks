//! Block `gh pr create` when the PR body has no closing keyword linking to an issue.
//!
//! Detects `gh pr create` commands and ensures the PR body contains a recognized
//! closing keyword (`closes`, `fixes`, `resolves` and their variants) followed by
//! an issue reference (`#N`). Port improvement over the original Bash version:
//! when `--body-file`/`-F` is present, the file's contents are also scanned so
//! the keyword inside the file is not false-blocked.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

// Closing keyword regex — case-insensitive, matches the closing keyword immediately
// followed by optional whitespace and a #N issue reference.
static CLOSING_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(close[sd]?|fix(e[sd])?|resolve[sd]?)\s+#[0-9]+")
        .expect("closing keyword pattern should compile")
});

// Matches `--body-file <path>` or `-F <path>` in the command.
static BODY_FILE_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:--body-file|-F)\s+(\S+)").expect("body-file flag pattern should compile")
});

/// Extract the path argument from `--body-file <path>` or `-F <path>`.
///
/// Pure: no I/O. Returns `None` when neither flag is present.
pub(crate) fn extract_body_file_path(command: &str) -> Option<String> {
    BODY_FILE_FLAG
        .captures(command)
        .and_then(|caps| caps.get(1))
        .map(|m| {
            m.as_str()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
}

/// Pure decision function. Returns `Some(deny_message)` when the PR should be
/// blocked, `None` when it should be allowed.
///
/// `body_file_contents` carries the body file's text when `--body-file`/`-F` is
/// present and the file was successfully read; `None` when the flag is absent OR
/// when the file could not be read (fail-closed in the latter case).
pub(crate) fn judge_pr_create(command: &str, body_file_contents: Option<&str>) -> Option<String> {
    // Only guard `gh pr create`
    if !command.contains("gh pr create") {
        return None;
    }

    // Check the inline command text for a closing keyword
    if CLOSING_KEYWORD.is_match(command) {
        return None;
    }

    // Check the body file contents when provided
    if let Some(contents) = body_file_contents {
        if CLOSING_KEYWORD.is_match(contents) {
            return None;
        }
        // Body file was provided but contains no keyword — deny
        return Some(deny_message());
    }

    // No body-file provided (or it couldn't be read — fail closed): deny
    Some(deny_message())
}

fn deny_message() -> String {
    "🚫 git-guardrails: PR body must include a closing keyword linking to a GitHub Issue\n   \
     (e.g., 'Closes #123').\n   \
     Fix: add 'Closes #N', 'Fixes #N', or 'Resolves #N' to the PR body before creating."
        .to_string()
}

/// Blocks `gh pr create` when no closing keyword is found in the PR body.
pub struct PrIssueLinkGuard;

impl Check for PrIssueLinkGuard {
    fn name(&self) -> &str {
        "guard-pr-issue-link"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Fast-path: not a gh pr create
        if !command.contains("gh pr create") {
            return CheckResult::allow();
        }

        // Extract --body-file/-F path and try to read the file
        let body_file_contents: Option<String> =
            extract_body_file_path(command).and_then(|path| std::fs::read_to_string(&path).ok());

        match judge_pr_create(command, body_file_contents.as_deref()) {
            Some(msg) => CheckResult::block(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    // ---- Pure function tests (judge_pr_create) ----

    // Test case 1: non-gh-pr-create command — allow
    #[test]
    fn non_pr_create_command_allowed() {
        assert!(judge_pr_create("git status", None).is_none());
    }

    // Test case 2: inline body with "Closes #N" — allow
    #[test]
    fn inline_body_closes_allowed() {
        assert!(judge_pr_create(r#"gh pr create --title x --body "Closes #12""#, None).is_none());
    }

    // Test case 3: case-insensitive — "fixes #7" — allow
    #[test]
    fn inline_body_fixes_lowercase_allowed() {
        assert!(judge_pr_create(r#"gh pr create --title x --body "fixes #7""#, None).is_none());
    }

    // Test case 4: "Resolved #9" — allow (resolve[sd]? matches Resolved)
    #[test]
    fn inline_body_resolved_allowed() {
        assert!(judge_pr_create(r#"gh pr create --title x --body "Resolved #9""#, None).is_none());
    }

    // Test case 5: no closing keyword in inline body — deny
    #[test]
    fn inline_body_no_keyword_denied() {
        assert!(judge_pr_create(r#"gh pr create --title x --body "no link here""#, None).is_some());
    }

    // Test case 6: --body-file with keyword in file — allow (port improvement)
    #[test]
    fn body_file_with_keyword_allowed() {
        let file_contents = "This PR closes #42 by implementing the feature.";
        assert!(judge_pr_create("gh pr create -t x -F body.md", Some(file_contents)).is_none());
    }

    // Test case 6b: --body-file flag present but file unreadable — deny (fail closed)
    #[test]
    fn body_file_unreadable_denied() {
        // body_file_contents = None means the file could not be read
        // When there's a -F flag but we pass None, judge_pr_create should deny
        // (this is the fail-closed behavior for unreadable body files)
        // The command has -F so extract_body_file_path would return Some(path),
        // but the file read fails, so body_file_contents is None.
        // judge_pr_create receives None and denies because no keyword in command either.
        assert!(judge_pr_create("gh pr create -t x -F /nonexistent/body.md", None).is_some());
    }

    // Test case 7: "#5" without closing keyword — deny
    #[test]
    fn bare_issue_reference_without_keyword_denied() {
        assert!(judge_pr_create(r#"gh pr create --body "see #5""#, None).is_some());
    }

    // Test case 8: gh pr list — allow
    #[test]
    fn gh_pr_list_allowed() {
        assert!(judge_pr_create("gh pr list", None).is_none());
    }

    // Extra: long-form --body-file flag with keyword in file — allow
    #[test]
    fn long_form_body_file_with_keyword_allowed() {
        let file_contents = "Fixes #99\n\nDetailed description here.";
        assert!(
            judge_pr_create(
                "gh pr create --title 'fix thing' --body-file body.md",
                Some(file_contents)
            )
            .is_none()
        );
    }

    // Extra: body file with no keyword — deny
    #[test]
    fn body_file_without_keyword_denied() {
        let file_contents = "This is a detailed description with no issue link.";
        assert!(judge_pr_create("gh pr create -t x -F body.md", Some(file_contents)).is_some());
    }

    // Extra: "Closes" uppercase — allow (case insensitive)
    #[test]
    fn closes_uppercase_allowed() {
        assert!(judge_pr_create(r#"gh pr create --body "CLOSES #10""#, None).is_none());
    }

    // Extra: "Resolves #N" — allow
    #[test]
    fn resolves_allowed() {
        assert!(judge_pr_create(r#"gh pr create --body "Resolves #88""#, None).is_none());
    }

    // Extra: "Fixed #N" — allow
    #[test]
    fn fixed_allowed() {
        assert!(judge_pr_create(r#"gh pr create --body "Fixed #3""#, None).is_none());
    }

    // ---- extract_body_file_path tests (pure parser) ----

    #[test]
    fn extracts_long_form_body_file_path() {
        let cmd = "gh pr create --title x --body-file ./my-body.md";
        assert_eq!(
            extract_body_file_path(cmd),
            Some("./my-body.md".to_string())
        );
    }

    #[test]
    fn extracts_short_form_body_file_path() {
        let cmd = "gh pr create -t x -F body.md";
        assert_eq!(extract_body_file_path(cmd), Some("body.md".to_string()));
    }

    #[test]
    fn extracts_body_file_path_strips_quotes() {
        let cmd = r#"gh pr create --body-file "path/to/body.md""#;
        assert_eq!(
            extract_body_file_path(cmd),
            Some("path/to/body.md".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_body_file_flag() {
        let cmd = r#"gh pr create --title x --body "Closes #1""#;
        assert!(extract_body_file_path(cmd).is_none());
    }

    // ---- Check::run integration tests ----

    #[test]
    fn check_blocks_pr_create_without_keyword() {
        let result = PrIssueLinkGuard.run(&make_bash(
            r#"gh pr create --title "my PR" --body "no issue link""#,
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn check_allows_pr_create_with_keyword() {
        let result = PrIssueLinkGuard.run(&make_bash(
            r#"gh pr create --title "my PR" --body "Closes #5""#,
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn check_allows_non_pr_create() {
        let result = PrIssueLinkGuard.run(&make_bash("git status"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn check_allows_no_command() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = PrIssueLinkGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn deny_message_includes_fix_line() {
        let msg = deny_message();
        assert!(msg.contains("Closes #N"));
        assert!(msg.contains("Fixes #N"));
        assert!(msg.contains("Resolves #N"));
    }
}
