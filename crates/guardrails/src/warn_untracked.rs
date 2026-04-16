//! Warn about untracked files during git commit operations.
//!
//! Shells out to `git ls-files --others --exclude-standard` to detect
//! files that might have been forgotten. Filters out build artifacts.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;
use std::process::Command;

/// Build artifact extensions to filter from untracked file warnings.
const BUILD_ARTIFACT_EXTENSIONS: &[&str] = &[
    "log", "tmp", "cache", "pyc", "class", "o", "a", "so", "dylib",
];

/// Parse `git status --porcelain` output and return non-artifact untracked files.
///
/// Filters lines starting with `??`, strips the prefix, and removes files
/// whose extensions match known build artifacts. Pure function — no I/O.
pub fn filter_untracked(porcelain: &str) -> Vec<&str> {
    let untracked: Vec<&str> = porcelain
        .lines()
        .filter(|line| line.starts_with("??"))
        .map(|line| line.trim_start_matches("?? "))
        .collect();

    untracked
        .into_iter()
        .filter(|file| {
            !BUILD_ARTIFACT_EXTENSIONS
                .iter()
                .any(|ext| file.ends_with(&format!(".{ext}")))
        })
        .collect()
}

/// Warns when git commit runs with untracked files that may have been forgotten.
pub struct WarnUntrackedFiles;

impl Check for WarnUntrackedFiles {
    fn name(&self) -> &str {
        "warn-untracked-files"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Only trigger on git add/commit
        if !command.starts_with("git add") && !command.starts_with("git commit") {
            return CheckResult::allow();
        }

        // Get untracked files from git (respect cwd from hook payload)
        let mut cmd = Command::new("git");
        cmd.args(["status", "--porcelain"]);
        if let Some(dir) = input.cwd.as_deref()
            && Path::new(dir).is_dir()
        {
            cmd.current_dir(dir);
        }
        let output = match cmd.output() {
            Ok(out) => out,
            Err(_) => return CheckResult::allow(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let important = filter_untracked(&stdout);

        if important.is_empty() {
            return CheckResult::allow();
        }

        let count = important.len();
        let mut msg = format!("⚠️  Warning: {count} untracked file(s) detected\n\n");
        msg.push_str("These files may need to be included in your commit:\n");
        for file in &important {
            msg.push_str(&format!("  ?? {file}\n"));
        }

        CheckResult::nudge(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    // --- filter_untracked: pure function tests ---

    #[test]
    fn parses_untracked_files() {
        let porcelain = "?? src/new_file.rs\n?? README.md\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/new_file.rs", "README.md"]);
    }

    #[test]
    fn ignores_staged_files() {
        let porcelain = "A  src/added.rs\nM  src/modified.rs\n?? untracked.rs\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["untracked.rs"]);
    }

    #[test]
    fn filters_log_artifacts() {
        let porcelain = "?? build.log\n?? src/main.rs\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/main.rs"]);
    }

    #[test]
    fn filters_pyc_artifacts() {
        let porcelain = "?? __pycache__/module.pyc\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn filters_object_files() {
        let porcelain = "?? build/main.o\n?? build/lib.a\n?? build/lib.so\n?? build/lib.dylib\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn filters_tmp_and_cache() {
        let porcelain = "?? session.tmp\n?? data.cache\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn keeps_important_files() {
        let porcelain = "?? Cargo.toml\n?? src/lib.rs\n?? .gitignore\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn mixed_artifacts_and_important() {
        let porcelain = "?? src/new.rs\n?? build.log\n?? module.pyc\n?? README.md\n?? temp.tmp\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/new.rs", "README.md"]);
    }

    #[test]
    fn empty_output() {
        let result = filter_untracked("");
        assert!(result.is_empty());
    }

    #[test]
    fn only_artifacts() {
        let porcelain = "?? a.log\n?? b.tmp\n?? c.cache\n?? d.pyc\n?? e.class\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    // --- run() guard clauses ---

    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn no_command_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = WarnUntrackedFiles.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn non_git_command_allows() {
        let result = WarnUntrackedFiles.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn git_status_allows() {
        let result = WarnUntrackedFiles.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
