//! Multi-session coordination hooks for Claude Code.
//!
//! Concurrent Claude Code sessions sharing one repo checkout cannot see each
//! other — branch position and working-tree state silently expire the moment
//! another session acts. This crate gives sessions *identity* within a repo:
//!
//! - Each session registers a file in `<repo>/.claude/sessions/` at start.
//!   The filename is the identity claim (`<name>.<short-id>.json`); the
//!   contents are the lane declaration (branch, intent, touched paths).
//! - File mtime is the liveness heartbeat. Stale files are presumed dead and
//!   swept — no deregistration ceremony required.
//! - New sessions receive a disclosure (`additionalContext`) describing live
//!   peers and the coordination protocol.
//! - A PreToolUse guard warns — never blocks (ADR-0001) — when an action
//!   intersects a live peer's lane.
//!
//! Consumed by the `cadence-canon` plugin (same voice entering at offset
//! times, harmonious by construction). Hook surface: issue #54.
//!
//! | Subcommand  | Event        | Module        |
//! |-------------|--------------|---------------|
//! | `start`     | SessionStart | [`start`]     |
//! | `heartbeat` | PostToolUse  | [`heartbeat`] |
//! | `guard`     | PreToolUse   | [`guard`]     |
//! | `declare`   | CLI action   | [`cli`]       |
//! | `status`    | CLI action   | [`cli`]       |

/// CLI actions: `declare` (lane declaration) and `status` (registry listing).
pub mod cli;
/// PreToolUse lane warnings — never blocks.
pub mod guard;
/// PostToolUse heartbeat — touches the session's own registry file.
pub mod heartbeat;
/// Pure domain logic: deterministic naming, record schema, relative ages.
pub mod identity;
/// Registry I/O: the `.claude/sessions/` directory and peer discovery.
pub mod registry;
/// SessionStart hook: register self, sweep stale, disclose live peers.
pub mod start;
