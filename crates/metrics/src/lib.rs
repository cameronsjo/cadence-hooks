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
/// Append polish-nudge (`gh pr create`) records to `polish_nudges.jsonl`.
pub mod log_polish_nudge;
/// Append subagent lifecycle records to `subagents.jsonl`.
pub mod log_subagent;
/// Embedded + overridable model price table.
pub mod prices;
/// Sum transcript token usage over a range.
pub mod scan_tokens;
/// Snapshot HEAD before a `git commit`.
pub mod snapshot;

pub use log_askuserquestion::LogAskUserQuestion;
pub use log_commit::LogCommit;
pub use log_polish_nudge::LogPolishNudge;
pub use log_subagent::LogSubagent;
pub use snapshot::Snapshot;
