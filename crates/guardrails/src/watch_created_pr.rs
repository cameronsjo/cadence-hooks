//! After `gh pr create` succeeds, have forgectl watch the new PR for this
//! session, so the c3 mod can hand the session its checks, reviews and merge
//! as they happen (forgectl `events`).
//!
//! PostToolUse, always allows, says nothing. The PR comes from the command's
//! stdout ([`pr_from_create_stdout`]): exactly one github.com PR URL, never a
//! guess from `origin`. The session id is the hook payload's. The one spawn,
//! `forgectl events watch --session <id> <owner/repo#N>`, is bounded like
//! every other tool call a nudge makes; any failure (no forgectl, a refused
//! id) changes nothing.

use cadence_hooks_core::shell::{gh_pr_segments, gh_pr_subcommand};
use cadence_hooks_core::{Check, CheckResult, HookInput};

use crate::bounded_tool::run_tool;
use crate::verify_pr_autoclose::pr_from_create_stdout;

/// Watches each PR this session creates.
pub struct WatchCreatedPr;

/// A session id forgectl will name a feed after: 1 to 128 of `[A-Za-z0-9._-]`,
/// not starting with `.`.
pub fn valid_session(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The `owner/repo#N` to watch, when `command` created exactly one github.com PR.
pub fn created_pr(command: &str, stdout: &str) -> Option<String> {
    if !gh_pr_segments(command)
        .iter()
        .any(|t| gh_pr_subcommand(t) == Some("create"))
    {
        return None;
    }
    let (host, slug, number) = pr_from_create_stdout(stdout)?;
    (host == "github.com").then(|| format!("{slug}#{number}"))
}

impl Check for WatchCreatedPr {
    fn name(&self) -> &str {
        "watch-created-pr"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let (Some(command), Some(stdout), Some(session)) = (
            input.command(),
            input.tool_response_stdout(),
            input.session_id.as_deref(),
        ) else {
            return CheckResult::allow();
        };
        if !valid_session(session) {
            return CheckResult::allow();
        }
        let Some(pr) = created_pr(command, stdout) else {
            return CheckResult::allow();
        };
        let cwd = std::env::temp_dir();
        let _ = run_tool(
            "forgectl",
            &["events", "watch", "--session", session, &pr],
            &cwd,
            &[],
        );
        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_created_pr() {
        assert_eq!(
            created_pr(
                "gh pr create --title t --body-file b",
                "https://github.com/Cameronsjo/Forgectl/pull/12\n"
            ),
            Some("cameronsjo/forgectl#12".into())
        );
    }

    #[test]
    fn ignores_other_commands_hosts_and_two_urls() {
        assert_eq!(
            created_pr("gh pr view 12", "https://github.com/o/r/pull/12"),
            None
        );
        assert_eq!(
            created_pr("gh pr create", "https://ghe.example/o/r/pull/12"),
            None
        );
        assert_eq!(
            created_pr(
                "gh pr create",
                "https://github.com/o/r/pull/12 https://github.com/o/r/pull/13"
            ),
            None
        );
    }

    #[test]
    fn session_ids() {
        assert!(valid_session("0b5c3f1e-2f2a-4f6e-9d3c-1a2b3c4d5e6f"));
        assert!(!valid_session("../x"));
        assert!(!valid_session(".hidden"));
        assert!(!valid_session(""));
        assert!(!valid_session(&"a".repeat(129)));
    }
}
