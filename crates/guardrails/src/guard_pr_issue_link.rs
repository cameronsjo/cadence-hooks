//! Block `gh pr create` when the PR body has no closing keyword linking to an issue.
//!
//! Detects `gh pr create` commands and ensures the PR body contains a recognized
//! closing keyword (`closes`, `fixes`, `resolves` and their variants) followed by
//! an issue reference (`#N`). Port improvement over the original Bash version:
//! when `--body-file`/`-F` is present, the file's contents are also scanned so
//! the keyword inside the file is not false-blocked.

use crate::issue_refs::has_closing_keyword;
use cadence_hooks_core::shell::{strip_quotes, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Extract the path argument from `--body-file <path>`, `--body-file=<path>`,
/// or `-F <path>`.
///
/// Pure: no I/O. Returns `None` when no body-file flag is present.
///
/// Operates on shell tokens, not the raw string, so flag-looking text inside
/// quoted arguments (`--body "see --body-file foo"`) is data, never a flag —
/// a raw regex scan there would conjure a phantom unreadable file and fail
/// the guard open.
pub(crate) fn extract_body_file_path(command: &str) -> Option<String> {
    let tokens = tokenize(command);
    let mut iter = tokens.into_iter();
    while let Some(token) = iter.next() {
        if token == "--body-file" || token == "-F" {
            return iter.next();
        }
        if let Some(path) = token.strip_prefix("--body-file=") {
            return Some(path.to_string());
        }
    }
    None
}

/// Resolution of the `--body-file`/`-F` flag on a `gh pr create` command.
#[derive(Debug)]
pub(crate) enum BodyFile {
    /// No body-file flag present.
    Absent,
    /// Flag present; the file was read successfully.
    Contents(String),
    /// Flag present but the file could not be read (race, permissions, path).
    Unreadable,
}

/// Pure decision function. Returns `Some(deny_message)` when the PR should be
/// blocked, `None` when it should be allowed.
pub(crate) fn judge_pr_create(command: &str, body_file: &BodyFile) -> Option<String> {
    // Only guard `gh pr create`. Strip quoted regions first so text like
    // `echo "gh pr create ..."` is treated as data, not a command.
    if !strip_quotes(command).contains("gh pr create") {
        return None;
    }

    // Check the inline command text for a closing keyword. The keyword lives
    // inside the quoted `--body "..."` string, so this checks the raw command.
    if has_closing_keyword(command) {
        return None;
    }

    match body_file {
        // File read and contains a keyword — allow.
        BodyFile::Contents(contents) if has_closing_keyword(contents) => None,
        // File read but no keyword anywhere — deny.
        BodyFile::Contents(_) => Some(deny_message()),
        // Flag present but the file could not be read — fail OPEN (ADR-0001).
        // This is the guard's own verification failure (write/hook race,
        // permissions, path resolution), not the user's violation.
        BodyFile::Unreadable => None,
        // No body file and no keyword in the command — deny.
        BodyFile::Absent => Some(deny_message()),
    }
}

fn deny_message() -> String {
    "🚫 guard-pr-issue-link: PR body must include a closing keyword linking to a GitHub Issue\n   \
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

        // Fast-path: not a gh pr create (quoted occurrences are data, not commands)
        if !strip_quotes(command).contains("gh pr create") {
            return CheckResult::allow();
        }

        // Resolve the body file (if any) into the three-state BodyFile.
        let body_file = match extract_body_file_path(command) {
            None => BodyFile::Absent,
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(contents) => BodyFile::Contents(contents),
                Err(_) => BodyFile::Unreadable,
            },
        };

        match judge_pr_create(command, &body_file) {
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
        assert!(judge_pr_create("git status", &BodyFile::Absent).is_none());
    }

    // Test case 2: inline body with "Closes #N" — allow
    #[test]
    fn inline_body_closes_allowed() {
        assert!(
            judge_pr_create(
                r#"gh pr create --title x --body "Closes #12""#,
                &BodyFile::Absent
            )
            .is_none()
        );
    }

    // Test case 3: case-insensitive — "fixes #7" — allow
    #[test]
    fn inline_body_fixes_lowercase_allowed() {
        assert!(
            judge_pr_create(
                r#"gh pr create --title x --body "fixes #7""#,
                &BodyFile::Absent
            )
            .is_none()
        );
    }

    // Test case 4: "Resolved #9" — allow (resolve[sd]? matches Resolved)
    #[test]
    fn inline_body_resolved_allowed() {
        assert!(
            judge_pr_create(
                r#"gh pr create --title x --body "Resolved #9""#,
                &BodyFile::Absent
            )
            .is_none()
        );
    }

    // Test case 5: no closing keyword in inline body — deny
    #[test]
    fn inline_body_no_keyword_denied() {
        assert!(
            judge_pr_create(
                r#"gh pr create --title x --body "no link here""#,
                &BodyFile::Absent
            )
            .is_some()
        );
    }

    // Test case 6: --body-file with keyword in file — allow (port improvement)
    #[test]
    fn body_file_with_keyword_allowed() {
        let contents = BodyFile::Contents("This PR closes #42 by implementing the feature.".into());
        assert!(judge_pr_create("gh pr create -t x -F body.md", &contents).is_none());
    }

    // Test case 6b: --body-file flag present but file unreadable — fail OPEN (ADR-0001).
    // An unreadable file is the guard's own verification failure (write/hook race,
    // permissions, path resolution) — never block the user on it.
    #[test]
    fn body_file_unreadable_fails_open() {
        assert!(
            judge_pr_create(
                "gh pr create -t x -F /nonexistent/body.md",
                &BodyFile::Unreadable
            )
            .is_none()
        );
    }

    // Test case 7: "#5" without closing keyword — deny
    #[test]
    fn bare_issue_reference_without_keyword_denied() {
        assert!(judge_pr_create(r#"gh pr create --body "see #5""#, &BodyFile::Absent).is_some());
    }

    // Test case 8: gh pr list — allow
    #[test]
    fn gh_pr_list_allowed() {
        assert!(judge_pr_create("gh pr list", &BodyFile::Absent).is_none());
    }

    // Quoted occurrence: 'gh pr create' inside a quoted string is data, not a
    // command — must not trigger the guard.
    #[test]
    fn quoted_pr_create_text_not_guarded() {
        assert!(
            judge_pr_create(
                r#"echo "gh pr create needs a closing keyword in its body""#,
                &BodyFile::Absent
            )
            .is_none()
        );
    }

    // Extra: long-form --body-file flag with keyword in file — allow
    #[test]
    fn long_form_body_file_with_keyword_allowed() {
        let contents = BodyFile::Contents("Fixes #99\n\nDetailed description here.".into());
        assert!(
            judge_pr_create(
                "gh pr create --title 'fix thing' --body-file body.md",
                &contents
            )
            .is_none()
        );
    }

    // Extra: body file with no keyword — deny
    #[test]
    fn body_file_without_keyword_denied() {
        let contents =
            BodyFile::Contents("This is a detailed description with no issue link.".into());
        assert!(judge_pr_create("gh pr create -t x -F body.md", &contents).is_some());
    }

    // Extra: "Closes" uppercase — allow (case insensitive)
    #[test]
    fn closes_uppercase_allowed() {
        assert!(
            judge_pr_create(r#"gh pr create --body "CLOSES #10""#, &BodyFile::Absent).is_none()
        );
    }

    // Extra: "Resolves #N" — allow
    #[test]
    fn resolves_allowed() {
        assert!(
            judge_pr_create(r#"gh pr create --body "Resolves #88""#, &BodyFile::Absent).is_none()
        );
    }

    // Extra: "Fixed #N" — allow
    #[test]
    fn fixed_allowed() {
        assert!(judge_pr_create(r#"gh pr create --body "Fixed #3""#, &BodyFile::Absent).is_none());
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

    // `--body-file` appearing inside quoted body text is data, not a flag.
    // Treating it as a flag turns the phantom (unreadable) path into a
    // fail-open bypass: no keyword anywhere, yet the PR is allowed.
    #[test]
    fn quoted_body_text_mentioning_body_file_is_not_a_flag() {
        let cmd = r#"gh pr create --title x --body "see --body-file foo""#;
        assert!(extract_body_file_path(cmd).is_none());
    }

    #[test]
    fn quoted_body_text_mentioning_short_flag_is_not_a_flag() {
        let cmd = r#"gh pr create --title x --body "pass -F notes.md to gh""#;
        assert!(extract_body_file_path(cmd).is_none());
    }

    // gh accepts `--body-file=path` — must resolve the same as the spaced form,
    // otherwise the flag goes undetected and a keyword-bearing file is ignored
    // (false block).
    #[test]
    fn extracts_equals_form_body_file_path() {
        let cmd = "gh pr create --title x --body-file=./body.md";
        assert_eq!(extract_body_file_path(cmd), Some("./body.md".to_string()));
    }

    // Quoted paths containing spaces must be captured whole — truncating at the
    // first space makes the file unreadable, and the fail-open path would then
    // let an unverified PR through.
    #[test]
    fn extracts_double_quoted_path_with_spaces() {
        let cmd = r#"gh pr create -F "docs/pr bodies/body.md""#;
        assert_eq!(
            extract_body_file_path(cmd),
            Some("docs/pr bodies/body.md".to_string())
        );
    }

    #[test]
    fn extracts_single_quoted_path_with_spaces() {
        let cmd = "gh pr create --body-file 'my body files/pr.md'";
        assert_eq!(
            extract_body_file_path(cmd),
            Some("my body files/pr.md".to_string())
        );
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

    // End-to-end: quoted body text mentioning --body-file must NOT become a
    // phantom unreadable file (which would fail open). No keyword → block.
    #[test]
    fn check_blocks_quoted_body_file_mention_without_keyword() {
        let result = PrIssueLinkGuard.run(&make_bash(
            r#"gh pr create --title x --body "see --body-file foo""#,
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // Check::run with an unreadable body file — fail open end-to-end.
    #[test]
    fn check_allows_unreadable_body_file() {
        let result = PrIssueLinkGuard.run(&make_bash(
            "gh pr create -t x --body-file /nonexistent/dir/body-that-cannot-exist.md",
        ));
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

    // The deny message names this check (not the legacy plugin name) so a
    // blocked user can find the responsible guard.
    #[test]
    fn deny_message_names_the_check() {
        let msg = deny_message();
        assert!(
            msg.contains("guard-pr-issue-link:"),
            "deny message should name the check, got: {msg}"
        );
    }
}
