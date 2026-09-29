//! Bounded runner for the external tools the advisory nudges query (`gh`,
//! `chezmoi`).
//!
//! Every spawn goes through [`run_bounded_capped`], the same wall-clock bound
//! the git probes use, capped at [`TOOL_CAP`] and never past what the shared
//! per-invocation budget ([`cadence_hooks_core::deadline`]) has left. A tool
//! that stalls on the network or a lock is killed and reaped in time for the
//! hook to exit on its own, instead of the external hooks.json timeout
//! killing it from outside. Stdout is capped at [`MAX_STDOUT`], so a tool
//! that loops output is killed at the cap rather than filling memory. Every failure — spawn error, non-zero exit,
//! timeout, truncated output — is `None`, and the callers read `None` as
//! "stay silent" (ADR-0001).

use cadence_hooks_core::deadline::{self, BudgetState};
use cadence_hooks_core::shell::{GitSpawn, run_bounded_capped};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::warn_unreviewed_ready_flip::GhRunner;

/// The most one tool call may take, well under the 3s default shared budget
/// and the 5s external hooks.json timeout. Applies even when the deadline is
/// disabled (`CADENCE_HOOK_DEADLINE_MS=0`): these are network calls made by
/// nudges, and no nudge is worth an unbounded wait.
pub const TOOL_CAP: Duration = Duration::from_millis(2000);

/// The most stdout one tool call may return. The largest legitimate answer
/// (a 100-node GraphQL page, a `chezmoi status` listing) is far below it.
pub const MAX_STDOUT: usize = 1024 * 1024;

/// The timeout for the next tool spawn, or `None` when the shared budget is
/// already spent.
fn next_timeout(program: &'static str) -> Option<Duration> {
    match deadline::state() {
        BudgetState::Armed(remaining) if remaining.is_zero() => {
            deadline::note_hit_by(program);
            None
        }
        BudgetState::Armed(remaining) => Some(remaining.min(TOOL_CAP)),
        BudgetState::Unarmed(cap) => Some(cap.min(TOOL_CAP)),
        BudgetState::Disabled => Some(TOOL_CAP),
    }
}

/// Run `program args…` in `cwd` with `env` added, returning trimmed stdout on
/// a zero exit and `None` on anything else.
pub fn run_tool(
    program: &'static str,
    args: &[&str],
    cwd: &std::path::Path,
    env: &[(String, String)],
) -> Option<String> {
    let timeout = next_timeout(program)?;
    let mut cmd = Command::new(program);
    cmd.current_dir(cwd)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .args(args);
    let was_hit = deadline::hit();
    let result = run_bounded_capped(&mut cmd, timeout, Some(MAX_STDOUT));
    // The runner records a bare deadline hit; when this spawn is what hit
    // it, name the tool so the exit breadcrumb does not blame git.
    if !was_hit && deadline::hit() {
        deadline::note_hit_by(program);
    }
    match result {
        GitSpawn::Completed(out) if out.status.success() => {
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        // A truncated answer is a wrong answer for an advisory read.
        GitSpawn::Completed(_)
        | GitSpawn::Truncated(_)
        | GitSpawn::SpawnFailed
        | GitSpawn::TimedOut => None,
    }
}

/// `gh` through [`run_tool`], in the session cwd with `env` (such as
/// `GH_HOST`) scoped to the spawned process.
pub struct BoundedGhRunner {
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
}

impl GhRunner for BoundedGhRunner {
    fn run(&self, args: &[&str]) -> Option<String> {
        run_tool("gh", args, &self.cwd, &self.env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_is_none_not_a_panic() {
        let dir = std::env::temp_dir();
        assert_eq!(
            run_tool("cadence-hooks-no-such-tool-xyz", &["--version"], &dir, &[]),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_zero_exit_returns_trimmed_stdout_and_a_failure_is_none() {
        let dir = std::env::temp_dir();
        assert_eq!(
            run_tool("sh", &["-c", "echo '  hi  '"], &dir, &[]).as_deref(),
            Some("hi")
        );
        assert_eq!(run_tool("sh", &["-c", "echo x; exit 3"], &dir, &[]), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_stalled_tool_is_cut_off_at_the_cap() {
        let dir = std::env::temp_dir();
        let started = std::time::Instant::now();
        assert_eq!(run_tool("sleep", &["10"], &dir, &[]), None);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_loops_output_is_cut_off_at_the_byte_cap() {
        let dir = std::env::temp_dir();
        let started = std::time::Instant::now();
        assert_eq!(run_tool("yes", &[], &dir, &[]), None);
        assert!(
            started.elapsed() < TOOL_CAP,
            "the byte cap, not the wall-clock cap, must end the run"
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_reaches_the_spawned_tool() {
        let dir = std::env::temp_dir();
        let env = vec![("CADENCE_BOUNDED_TOOL_PROBE".to_string(), "v1".to_string())];
        assert_eq!(
            run_tool(
                "sh",
                &["-c", "printf %s \"$CADENCE_BOUNDED_TOOL_PROBE\""],
                &dir,
                &env
            )
            .as_deref(),
            Some("v1")
        );
    }
}
