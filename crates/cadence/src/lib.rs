//! Hooks for the [cadence](https://github.com/cameronsjo/cadence) plugin.
//!
//! Code quality, secret protection, and development hygiene checks
//! that run on every tool invocation during a Claude Code session.

/// Run the runner-pool workflow audit after a workflow file is edited (PostToolUse).
pub mod audit_runner_pool;
/// Require `MARKER(#issue):` format for TODO, FIXME, HACK, and other code markers.
pub mod block_orphaned_todos;
/// Nudge before internal harness vocabulary leaks into an external post.
pub mod credential_scan;
/// The `forgectl env` line the secret guards append to an env-file block.
mod forgectl_hint;
/// Block dangerous git operations (force-push main, reset --hard, etc.).
pub mod git_safety;
/// Block `gh issue close` against the HELD-issue ledger.
pub mod guard_held_close;
/// Ask before a command prints a bare, unnamed secret value (PreToolUse).
pub mod guard_secret_dump;
/// Run markdownlint on markdown files being written.
pub mod markdown_lint;
/// Enforce line limits on MEMORY.md and topic files.
pub mod memory_guard;
/// Inject the Fable seat posture at session start and on a switch onto Fable
/// (SessionStart + PostModelSwitch).
pub mod model_posture;
/// Nudge to run `/polish` (cadence-forge:polish) before creating a PR.
pub mod nudge_polish_before_pr;
/// Nudge when the installed cadence-hooks binary or Claude Code has drifted
/// behind the plugin-shipped platform baseline (SessionStart).
pub mod platform_drift;
/// Block reading secrets (.env, credentials, private keys) into context.
pub mod prevent_secret_leaks;
/// Block a `git push` that would publish a secret (pre-push scan).
pub mod prevent_secret_push;
/// Block writing or deleting secrets (.env, credentials, private keys).
pub mod prevent_secret_writes;
/// Record that `/polish` ran on this branch (writes a branch-scoped marker). CLI action.
pub mod record_polish;
/// Record that a runbook's content passed the secret scrub (writes a content-hash marker). CLI action.
pub mod record_scrub;
pub mod redact_external_content;
/// Mask secret values in Bash output before they reach the transcript (PostToolUse).
pub mod redact_secret_output;
/// Shared secret file patterns for both secret guards.
pub mod secret_patterns;
/// Block inclusive terminology violations in written content.
pub mod terminology;
/// Warn on generic environment variable names (DEBUG, PORT) that should be prefixed.
pub mod validate_env_vars;
/// Block CRLF line endings in shell scripts.
pub mod validate_line_endings;
/// Nudge to add a CHANGELOG.md entry when shipping code changes.
pub mod warn_changelog_entry;
/// Nudge to review documentation when creating a pull request.
pub mod warn_docs_update;
/// Nudge when an always-loaded instruction file gains narrative.
pub mod warn_instruction_narrative;
/// Nudge on a direct write to live auto-memory outside a dream adoption window.
pub mod warn_live_memory_write;
/// Nudge to audit about-to-ship content for personal-context overshare.
pub mod warn_overshare;
/// Nudge on a write that creates plugin-root `docs/` or `scripts/` content.
pub mod warn_plugin_root_cruft;

// Tests that write real marker files (#302) sandbox them through
// `cadence_hooks_core::test_builders::with_marker_dir` — the ONE helper, over
// the one lock, for the `CADENCE_MARKER_DIR` global. This crate used to carry a
// private `test_support` copy; two uncoordinated mutexes over a single env var
// are the #446 race no critical section can fix, so it was deleted rather than
// left beside the shared one.
