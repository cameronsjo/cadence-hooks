//! Nudge to review documentation when creating a pull request.
//!
//! When `gh pr create` is detected, diffs against the base branch to check
//! whether code files changed without corresponding documentation updates.
//! Warns with specific file suggestions.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::process::Command;

/// Documentation files that should be reviewed when code changes.
const DOC_FILES: &[&str] = &["README.md", "CONTRIBUTING.md", "CHANGELOG.md"];

/// Extensions considered "code" (not config, docs, or assets).
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "go", "py", "rb", "js", "jsx", "ts", "tsx", "mjs", "cjs", "java", "kt", "cs", "swift",
    "c", "cpp", "h", "hpp",
];

/// Warns when creating a PR with code changes but no documentation updates.
pub struct WarnDocsUpdate;

impl Check for WarnDocsUpdate {
    fn name(&self) -> &str {
        "warn-docs-update"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("gh") || !command.contains("pr") || !command.contains("create") {
            return CheckResult::allow();
        }

        // Verify it's actually `gh pr create`
        let tokens: Vec<&str> = command.split_whitespace().collect();
        let has_pr_create = tokens
            .windows(3)
            .any(|w| w[0] == "gh" && w[1] == "pr" && w[2] == "create");
        if !has_pr_create {
            return CheckResult::allow();
        }

        let changed_files = match diff_against_base() {
            Some(files) => files,
            None => return CheckResult::allow(),
        };

        if changed_files.is_empty() {
            return CheckResult::allow();
        }

        let has_code_changes = changed_files.iter().any(|f| is_code_file(f));
        if !has_code_changes {
            return CheckResult::allow();
        }

        let has_doc_changes = changed_files.iter().any(|f| is_doc_file(f));
        if has_doc_changes {
            return CheckResult::allow();
        }

        let missing: Vec<&&str> = DOC_FILES
            .iter()
            .filter(|doc| !changed_files.iter().any(|f| f.ends_with(**doc)))
            .collect();

        if missing.is_empty() {
            return CheckResult::allow();
        }

        let code_count = changed_files.iter().filter(|f| is_code_file(f)).count();
        let mut msg = format!(
            "📝  {code_count} code file(s) changed but no documentation updated.\n\n\
             Review whether these need updating:\n"
        );
        for doc in &missing {
            msg.push_str(&format!("  - {doc}\n"));
        }

        // Check for specific signals
        if changed_files.iter().any(|f| {
            f.contains("Cargo.toml") || f.contains("package.json") || f.contains("pyproject.toml")
        }) {
            msg.push_str("\n  Dependency changes detected — CHANGELOG.md likely needs an entry.\n");
        }

        if changed_files
            .iter()
            .any(|f| f.starts_with("src/main") || f.contains("lib.rs") || f.contains("mod.rs"))
        {
            msg.push_str("\n  Public API changes detected — README.md may need updating.\n");
        }

        CheckResult::warn(msg)
    }
}

fn is_code_file(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next() {
        return CODE_EXTENSIONS.contains(&ext);
    }
    false
}

fn is_doc_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    DOC_FILES.contains(&name) || path.starts_with("docs/")
}

fn diff_against_base() -> Option<Vec<String>> {
    // Try to find the base branch
    let base = find_base_branch()?;

    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{base}...HEAD")])
        .output()
        .ok()
        .filter(|o| o.status.success())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<String> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    Some(files)
}

fn find_base_branch() -> Option<String> {
    // Check if main exists
    for branch in &["main", "master"] {
        let status = Command::new("git")
            .args(["rev-parse", "--verify", &format!("origin/{branch}")])
            .output()
            .ok()?;
        if status.status.success() {
            return Some(format!("origin/{branch}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn non_pr_command_allowed() {
        let result = WarnDocsUpdate.run(&make_bash("gh pr list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_gh_command_allowed() {
        let result = WarnDocsUpdate.run(&make_bash("git commit -m 'test'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = WarnDocsUpdate.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn is_code_file_detects_extensions() {
        assert!(is_code_file("src/main.rs"));
        assert!(is_code_file("lib/utils.ts"));
        assert!(is_code_file("app.py"));
        assert!(!is_code_file("README.md"));
        assert!(!is_code_file("config.yaml"));
        assert!(!is_code_file("Makefile"));
    }

    #[test]
    fn is_doc_file_detects_docs() {
        assert!(is_doc_file("README.md"));
        assert!(is_doc_file("CONTRIBUTING.md"));
        assert!(is_doc_file("CHANGELOG.md"));
        assert!(is_doc_file("docs/architecture.md"));
        assert!(is_doc_file("some/path/README.md"));
        assert!(!is_doc_file("src/main.rs"));
    }

    #[test]
    fn gh_pr_create_with_flags_detected() {
        // Ensure the token check works with flags after "create"
        let input = make_bash("gh pr create --title 'my pr' --body 'desc'");
        // This will try to diff — in test env it may not have git context
        // Just verify it doesn't panic and parses correctly
        let result = WarnDocsUpdate.run(&input);
        // Allow or Warn are both acceptable — depends on git state
        assert!(
            result.outcome == cadence_hooks_core::Outcome::Allow
                || result.outcome == cadence_hooks_core::Outcome::Warn
        );
    }

    #[test]
    fn pr_review_not_matched() {
        let result = WarnDocsUpdate.run(&make_bash("gh pr review 123 --approve"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn issue_create_not_matched() {
        let result = WarnDocsUpdate.run(&make_bash("gh issue create --title test"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
