//! Hooks for the [cadence](https://github.com/cameronsjo/cadence) plugin.
//!
//! Code quality, secret protection, and development hygiene checks
//! that run on every tool invocation during a Claude Code session.

/// Require `MARKER(#issue):` format for TODO, FIXME, HACK, and other code markers.
pub mod block_orphaned_todos;
/// Block dangerous git operations (force-push main, reset --hard, etc.).
pub mod git_safety;
/// Run markdownlint on markdown files being written.
pub mod markdown_lint;
/// Enforce line limits on MEMORY.md and topic files.
pub mod memory_guard;
/// Block reading secrets (.env, credentials, private keys) into context.
pub mod prevent_secret_leaks;
/// Block writing or deleting secrets (.env, credentials, private keys).
pub mod prevent_secret_writes;
/// Block inclusive terminology violations in written content.
pub mod terminology;
/// Warn on generic environment variable names (DEBUG, PORT) that should be prefixed.
pub mod validate_env_vars;
/// Block CRLF line endings in shell scripts.
pub mod validate_line_endings;
/// Warn about untracked files during git commit operations.
pub mod warn_untracked;
