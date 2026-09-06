//! Fire-and-forget metrics loggers for the
//! [cadence-metrics](https://github.com/cameronsjo/cadence-metrics) plugin.
//!
//! Unlike the enforcement crates, these implement [`cadence_hooks_core::Logger`]:
//! they append JSONL event records (cost-per-commit, subagent lifecycle) and
//! never block a tool call. Pure helpers ([`scan_tokens`], [`compute_cost`]) are
//! unit-tested in isolation; the loggers wire filesystem and git I/O around them.

/// Shared logger helpers: git-commit detection, metrics-dir resolution,
/// timestamps, and the `display_safe` family — the sanitizers every
/// file-sourced string passes through before it reaches a terminal line or an
/// agent-facing nudge. Public so `doctor` shares one implementation rather than
/// growing a second that can drift.
pub mod common;

/// USD cost from token totals and a model name.
pub mod compute_cost;
/// Disclose at SessionStart when the guard suite has recently been failing open.
pub mod failopen_disclose;
/// Append AskUserQuestion stance/shape records to `askuserquestion.jsonl`.
pub mod log_askuserquestion;
/// Append guard-bypass audit records (armed/used) to `bypasses.jsonl`.
pub mod log_bypass;
/// Append cost-per-commit records to `commits.jsonl`.
pub mod log_commit;
/// Append guard-denial audit records to `denials.jsonl`.
pub mod log_denial;
/// Append fail-open telemetry (panic / parse / version-skew) to `failopen.jsonl`.
pub mod log_failopen;
/// Append polish-nudge (`gh pr create`) records to `polish_nudges.jsonl`.
pub mod log_polish_nudge;
/// Append per-session cost records to `sessions.jsonl` at `SessionEnd`.
pub mod log_session;
/// Stamp this session's start timestamp at `SessionStart`.
pub mod log_session_start;
/// Append Skill tool invocation records to `skills.jsonl`.
pub mod log_skill;
/// Append subagent lifecycle records to `subagents.jsonl`.
pub mod log_subagent;
/// Append sweep-reap records to `sweeps.jsonl`.
pub mod log_sweep;
/// Append threshold-gated hook self-timing records to `hooks.jsonl`.
pub mod log_timing;
/// Shared per-model breakdown builders for `byModel[]` / `unpricedModels[]`.
pub mod model_breakdown;
/// Embedded + overridable model price table.
pub mod prices;
/// Sum transcript token usage over a range.
pub mod scan_tokens;
/// Deterministic session grading: gaps, cold-restart dollars, peak context.
pub mod session_grade;
/// Snapshot HEAD before a `git commit`.
pub mod snapshot;
/// Versioned Claude transcript usage scanner.
pub mod transcript;
/// Warn at SessionStart when metrics telemetry has gone stale.
pub mod warn_stale;

/// The metrics root directory (`CADENCE_METRICS_DIR`, else
/// `<config_dir>/metrics`) — the single source of truth every stream's
/// writer resolves against. Re-exported so a JSONL append living outside
/// this crate (e.g. `session persist-plan-approval`'s `plan-links.jsonl`) reuses the
/// resolution instead of re-deriving it.
pub use common::metrics_dir;

pub use log_askuserquestion::LogAskUserQuestion;
pub use log_bypass::{BypassEvent, log_bypass};
pub use log_commit::LogCommit;
pub use log_denial::log_denial;
pub use log_failopen::log_failopen;
pub use log_polish_nudge::LogPolishNudge;
pub use log_session::LogSession;
pub use log_session_start::LogSessionStart;
pub use log_skill::LogSkill;
pub use log_subagent::LogSubagent;
pub use log_sweep::log_sweep;
pub use log_timing::log_timing;
pub use snapshot::Snapshot;
pub use warn_stale::WarnStale;
