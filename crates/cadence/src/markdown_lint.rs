//! Run markdownlint on markdown files being written.
//!
//! Shells out to `markdownlint` CLI if available. Skips silently when
//! the tool is not installed, so this hook degrades gracefully.

use claude_hooks_core::{Check, CheckResult, HookInput};
use std::io::Write;
use std::process::Command;

/// Warns when markdownlint reports issues in written markdown content.
pub struct MarkdownLint;

impl Check for MarkdownLint {
    fn name(&self) -> &str {
        "markdown-lint"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        if !path.ends_with(".md") {
            return CheckResult::allow();
        }

        // Only check Write operations (Edit is validated at final Write)
        if input.tool_name() != Some("Write") {
            return CheckResult::allow();
        }

        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

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

        let stderr = String::from_utf8_lossy(&output.stdout);
        let filename = path.rsplit('/').next().unwrap_or(path);

        CheckResult::warn(format!(
            "⚠️  Markdown linting issues detected in {filename}\n\n{stderr}\n\
             Fix: markdownlint --fix {path}"
        ))
    }
}
