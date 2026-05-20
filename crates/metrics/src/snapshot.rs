//! `PreToolUse:Bash` — snapshot HEAD before a `git commit` so the post-commit
//! logger can tell whether the commit actually landed.
//!
//! Port of `pre-commit-snapshot.sh`. Writes the current HEAD SHA to
//! `<state_dir>/<session_id>.before`. Silent no-op on anything unexpected.

use crate::common;
use cadence_hooks_core::{Logger, MetricsInput};

/// Snapshots HEAD before a git commit.
pub struct Snapshot;

impl Logger for Snapshot {
    fn name(&self) -> &str {
        "snapshot"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(command) = input.command() else {
            return;
        };
        if !common::is_git_commit(command) {
            return;
        }

        let Some(session_id) = input.session_id.as_deref().filter(|s| !s.is_empty()) else {
            return;
        };

        let dir = common::state_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        if let Some(sha) = common::head_sha(input.cwd.as_deref()) {
            let _ = std::fs::write(dir.join(format!("{session_id}.before")), sha);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with(command: &str, session: Option<&str>) -> MetricsInput {
        MetricsInput {
            session_id: session.map(String::from),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some(command.to_string()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn name_is_snapshot() {
        assert_eq!(Snapshot.name(), "snapshot");
    }

    #[test]
    fn non_commit_is_noop() {
        // No panic, no write attempt path taken — the command isn't a commit.
        Snapshot.run(&input_with("git status", Some("s1")));
    }

    #[test]
    fn missing_session_is_noop() {
        Snapshot.run(&input_with("git commit -m x", None));
        Snapshot.run(&input_with("git commit -m x", Some("")));
    }

    #[test]
    fn missing_command_is_noop() {
        Snapshot.run(&MetricsInput {
            session_id: Some("s1".into()),
            ..Default::default()
        });
    }
}
