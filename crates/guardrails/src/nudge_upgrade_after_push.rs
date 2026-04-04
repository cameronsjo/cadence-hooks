//! Nudge to schedule a Homebrew upgrade after pushing cadence-hooks to main.
//!
//! Fires as a PostToolUse hook on `git push`. Detects whether the push
//! originated from the `cameronsjo/cadence-hooks` repo and targeted the
//! main branch. If so, emits a nudge telling Claude to schedule a deferred
//! `brew upgrade` via CronCreate (one-shot, ~4 minutes out) to allow CI
//! time to build and publish the new beta release.

use cadence_hooks_core::shell::{git_command, host_and_repo_from_url, parse_work_dir};
use cadence_hooks_core::{Check, CheckResult, HookInput};

const TARGET_REPO: &str = "cameronsjo/cadence-hooks";

/// Check if the push targets the main branch.
///
/// Looks for an explicit refspec first (`git push origin main`),
/// then falls back to the current branch for bare `git push`.
fn is_push_to_main(command: &str, work_dir: &str) -> bool {
    // Explicit refspec: `git push origin main`, `git push origin main:main`
    if let Some(after_push) = command.split("git push").nth(1) {
        let segment = after_push.split(&['&', ';', '|'][..]).next().unwrap_or("");
        let args: Vec<&str> = segment
            .split_whitespace()
            .filter(|w| !w.starts_with('-'))
            .collect();
        // args[0] = remote, args[1] = refspec
        if let Some(refspec) = args.get(1) {
            let src = refspec.split(':').next().unwrap_or(refspec);
            return src == "main" || src == "master";
        }
    }

    // Bare `git push` — check current branch
    git_command(work_dir, &["branch", "--show-current"])
        .map(|b| b == "main" || b == "master")
        .unwrap_or(false)
}

/// Nudge Claude to schedule a deferred brew upgrade after pushing cadence-hooks.
pub struct NudgeUpgradeAfterPush;

impl Check for NudgeUpgradeAfterPush {
    fn name(&self) -> &str {
        "nudge-upgrade-after-push"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("git push") {
            return CheckResult::allow();
        }

        // Resolve working directory (handles `cd /foo && git push`)
        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
        let work_dir = parse_work_dir(command, cwd);

        // Check if this is the cadence-hooks repo
        let Some(remote_url) = git_command(&work_dir, &["remote", "get-url", "origin"]) else {
            return CheckResult::allow();
        };
        let Some((_host, repo_path)) = host_and_repo_from_url(&remote_url) else {
            return CheckResult::allow();
        };
        // Normalize: strip .git suffix, compare case-insensitively
        let normalized = repo_path.trim_end_matches(".git").to_lowercase();
        if normalized != TARGET_REPO {
            return CheckResult::allow();
        }

        // Check if pushing to main
        if !is_push_to_main(command, &work_dir) {
            return CheckResult::allow();
        }

        CheckResult::nudge(
            "cadence-hooks was just pushed to main. \
             CI will build a new beta release in ~2 minutes, then auto-update the Homebrew tap.\n\n\
             Schedule a deferred brew upgrade: use CronCreate with recurring: false, \
             ~4 minutes from now, prompt: \
             \"Run: ${CLAUDE_PLUGIN_ROOT}/hooks/upgrade-cadence-hooks.sh \
             (where CLAUDE_PLUGIN_ROOT is the git-guardrails plugin root). \
             This watches the CI run and upgrades cadence-hooks-beta via Homebrew. \
             Report the result to the user.\"\n\n\
             Tell the user you're scheduling the upgrade.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{HookInput, Outcome, ToolInput};

    fn make_bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(ToolInput {
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
    fn no_command_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn non_push_command_allows() {
        let result = NudgeUpgradeAfterPush.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn push_from_other_repo_allows() {
        // This will resolve to whatever CWD the test runs in,
        // which won't be cameronsjo/cadence-hooks
        let result = NudgeUpgradeAfterPush.run(&make_bash("git push origin main"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn is_push_to_main_explicit_refspec() {
        assert!(is_push_to_main("git push origin main", "/tmp"));
        assert!(is_push_to_main("git push origin main:main", "/tmp"));
    }

    #[test]
    fn is_push_to_main_feature_branch() {
        assert!(!is_push_to_main("git push origin feature/foo", "/tmp"));
    }

    #[test]
    fn is_push_to_main_bare_push_non_main() {
        // Bare push without refspec — falls back to current branch.
        // In test env, current branch is unlikely "main", so this should be false.
        // (We can't mock git_command easily, so just verify it doesn't panic.)
        let result = is_push_to_main("git push origin", "/tmp/nonexistent");
        // Could be true or false depending on test env — just verify no panic
        let _ = result;
    }
}
