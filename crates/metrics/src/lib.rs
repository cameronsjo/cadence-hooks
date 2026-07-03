//! Fire-and-forget metrics loggers for the
//! [cadence-metrics](https://github.com/cameronsjo/cadence-metrics) plugin.
//!
//! Unlike the enforcement crates, these implement [`cadence_hooks_core::Logger`]:
//! they append JSONL event records (cost-per-commit, subagent lifecycle) and
//! never block a tool call. Pure helpers ([`scan_tokens`], [`compute_cost`]) are
//! unit-tested in isolation; the loggers wire filesystem and git I/O around them.

mod common;

/// USD cost from token totals and a model name.
pub mod compute_cost;
/// Append AskUserQuestion stance/shape records to `askuserquestion.jsonl`.
pub mod log_askuserquestion;
/// Append cost-per-commit records to `commits.jsonl`.
pub mod log_commit;
/// Append guard-denial audit records to `denials.jsonl`.
pub mod log_denial;
/// Append polish-nudge (`gh pr create`) records to `polish_nudges.jsonl`.
pub mod log_polish_nudge;
/// Append per-session cost records to `sessions.jsonl` at `SessionEnd`.
pub mod log_session;
/// Stamp this session's start timestamp at `SessionStart`.
pub mod log_session_start;
/// Append subagent lifecycle records to `subagents.jsonl`.
pub mod log_subagent;
/// Append threshold-gated hook self-timing records to `hooks.jsonl`.
pub mod log_timing;
/// Shared per-model breakdown builders for `byModel[]` / `unpricedModels[]`.
pub mod model_breakdown;
/// Embedded + overridable model price table.
pub mod prices;
/// Sum transcript token usage over a range.
pub mod scan_tokens;
/// Snapshot HEAD before a `git commit`.
pub mod snapshot;
/// Warn at SessionStart when metrics telemetry has gone stale.
pub mod warn_stale;

pub use log_askuserquestion::LogAskUserQuestion;
pub use log_commit::LogCommit;
pub use log_denial::log_denial;
pub use log_polish_nudge::LogPolishNudge;
pub use log_session::LogSession;
pub use log_session_start::LogSessionStart;
pub use log_subagent::LogSubagent;
pub use log_timing::log_timing;
pub use snapshot::Snapshot;
pub use warn_stale::WarnStale;
