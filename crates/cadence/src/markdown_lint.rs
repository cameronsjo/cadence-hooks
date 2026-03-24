//! Run markdownlint on markdown files being written.
//!
//! Shells out to `markdownlint` CLI if available. Skips silently when
//! the tool is not installed, so this hook degrades gracefully.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::io::Write;
use std::process::Command;

/// Determine if the input represents a markdown Write operation worth linting.
///
/// Returns `true` when: path ends with `.md`, tool is `Write`, and content exists.
/// Pure guard-clause logic — no I/O.
pub fn should_lint(path: Option<&str>, tool_name: Option<&str>, content: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    if !p.ends_with(".md") {
        return false;
    }
    if tool_name != Some("Write") {
        return false;
    }
    content.is_some()
}

/// Warns when markdownlint reports issues in written markdown content.
pub struct MarkdownLint;

impl Check for MarkdownLint {
    fn name(&self) -> &str {
        "markdown-lint"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if !should_lint(
            input.file_path().as_deref(),
            input.tool_name(),
            input.content(),
        ) {
            return CheckResult::allow();
        }

        let content = input.content().unwrap();
        let path = input.file_path().unwrap();

        // Check if markdownlint is available
        if Command::new("markdownlint")
            .arg("--version")
            .output()
            .is_err()
        {
            return CheckResult::allow(); // Skip if not installed
        }

        // Write content to temp file and lint
        let tmp = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(_) => return CheckResult::allow(),
        };

        if tmp.as_file().write_all(content.as_bytes()).is_err() {
            return CheckResult::allow();
        }

        let output = match Command::new("markdownlint").arg(tmp.path()).output() {
            Ok(out) => out,
            Err(_) => return CheckResult::allow(),
        };

        if output.status.success() {
            return CheckResult::allow();
        }

        let lint_output = String::from_utf8_lossy(&output.stdout);
        let filename = path.rsplit('/').next().unwrap_or(&path);

        CheckResult::nudge(format!(
            "⚠️  Markdown linting issues detected in {filename}\n\n{lint_output}\n\
             Fix: markdownlint --fix {path}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path_returns_false() {
        assert!(!should_lint(None, Some("Write"), Some("# Hello")));
    }

    #[test]
    fn non_md_returns_false() {
        assert!(!should_lint(
            Some("/project/src/main.rs"),
            Some("Write"),
            Some("code")
        ));
    }

    #[test]
    fn non_write_tool_returns_false() {
        assert!(!should_lint(
            Some("/project/README.md"),
            Some("Edit"),
            Some("# Hi")
        ));
    }

    #[test]
    fn no_content_returns_false() {
        assert!(!should_lint(
            Some("/project/README.md"),
            Some("Write"),
            None
        ));
    }

    #[test]
    fn md_write_with_content_returns_true() {
        assert!(should_lint(
            Some("/project/README.md"),
            Some("Write"),
            Some("# Hello\n\nWorld")
        ));
    }

    #[test]
    fn nested_path_md_returns_true() {
        assert!(should_lint(
            Some("/project/docs/guide/setup.md"),
            Some("Write"),
            Some("content")
        ));
    }

    #[test]
    fn uppercase_md_returns_false() {
        // .MD is not .md — case sensitive extension check
        assert!(!should_lint(
            Some("/project/README.MD"),
            Some("Write"),
            Some("# Hi")
        ));
    }

    #[test]
    fn read_tool_returns_false() {
        assert!(!should_lint(
            Some("/project/README.md"),
            Some("Read"),
            Some("# Hi")
        ));
    }
}
