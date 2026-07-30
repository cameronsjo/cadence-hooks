//! Nudge when dispatching a subagent while the live subagent count is already
//! at or over a configured cap.
//!
//! Concurrency limits on heavy-context subagent fan-outs are an *observed*
//! server-side throttle, not physics — a burst of ~simultaneous heavy agents
//! hits request throttling well before any usage limit. This guard reads the
//! live subagent count from the metrics `subagents.jsonl` lifecycle log and
//! **nudges** (never blocks) on an `Agent`/`Task` spawn when the count is at or
//! over `CADENCE_MAX_CONCURRENT_SUBAGENTS` (default 5). The nudge is advisory:
//! the dispatch always proceeds.
//!
//! LIVE COUNT: `log_subagent` writes one line per lifecycle event — a
//! `SubagentStart` and a matching `SubagentStop`, each carrying `event`,
//! `agentId`, and `sessionId`. So the live count is the number of distinct
//! `agentId`s that have a `SubagentStart` record and **no** matching
//! `SubagentStop`. Records are scoped to the current session by `sessionId`;
//! when at least one record carries the current session id, only matching
//! records are considered.
//!
//! Two different "no match" cases must NOT collapse into one branch (#512):
//! when the log is well-formed (some record carries *a* sessionId) but none
//! carries *this* session's id, that's a real zero — the session just hasn't
//! spawned anything yet — and the count must report 0, not every other
//! session's agents. Only when the log carries **no** session-scoping data at
//! all (empty, garbage, or a schema missing the `sessionId` field entirely) is
//! the session genuinely unscopable, and the count falls back to **all** live
//! agents — the broader, safer estimate for that case.
//!
//! FAIL-OPEN (ADR-0001): any failure to read or parse the log yields `allow()`.
//! A missing log, garbage bytes, or an unreadable directory never blocks or
//! nudges — an observability gap must not impede dispatch.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::PathBuf;

/// Default concurrency cap when `CADENCE_MAX_CONCURRENT_SUBAGENTS` is unset or
/// unparseable. Matches the steady-state ceiling observed before heavy-context
/// bursts start throttling.
const DEFAULT_LIMIT: usize = 5;

/// The metrics directory holding `subagents.jsonl`.
///
/// Mirrors `metrics::common::metrics_dir`'s resolution order via the same public
/// `core` helpers — computed inline here to avoid a cross-crate edit to
/// `metrics::common` (merge isolation with sibling PRs):
/// 1. `CADENCE_METRICS_DIR` when set and non-empty — used verbatim.
/// 2. `<claude_config_dir>/metrics` otherwise, where `claude_config_dir` honors
///    `CLAUDE_CONFIG_DIR` (else `~/.claude`).
fn metrics_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CADENCE_METRICS_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    cadence_hooks_core::paths::claude_config_dir().join("metrics")
}

/// The configured concurrency cap: `CADENCE_MAX_CONCURRENT_SUBAGENTS` parsed as
/// a `usize`, else [`DEFAULT_LIMIT`]. Delegates to the pure [`parse_limit`].
fn subagent_limit() -> usize {
    parse_limit(
        std::env::var("CADENCE_MAX_CONCURRENT_SUBAGENTS")
            .ok()
            .as_deref(),
    )
}

/// Pure: parse a `CADENCE_MAX_CONCURRENT_SUBAGENTS` value into a cap.
///
/// A well-formed unsigned integer wins; `None`, empty, or unparseable input
/// falls back to [`DEFAULT_LIMIT`]. Parsed as `u64` first (matching the env
/// convention elsewhere) then narrowed, so an absurdly large value still yields
/// a usable cap.
fn parse_limit(value: Option<&str>) -> usize {
    value
        .map(str::trim)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| n as usize)
        .unwrap_or(DEFAULT_LIMIT)
}

/// A single parsed `subagents.jsonl` record: `(event, agentId, sessionId)`.
type SubagentRecord = (String, String, Option<String>);

/// How a target session resolves against the records in the log (#512).
///
/// The critical distinction is between a *real* zero and a genuinely
/// unscopable log — both look like "nothing matched" to a naive check, but
/// they demand opposite counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionScope {
    /// At least one record carries the target session id — scope to those.
    Matched,
    /// The log carries session-scoping data (some record has *a* sessionId)
    /// but none names this session. This session simply has zero rows —
    /// report 0, not the other sessions' agents.
    WellFormedNoMatch,
    /// No record in the log carries any sessionId at all (empty, garbage, or
    /// a schema missing the field entirely) — there is no scoping data to
    /// trust. Genuinely unscopable: fall back to counting every live agent.
    Unscopable,
}

/// Pure: resolve which [`SessionScope`] applies for `session_id` against
/// `records`.
fn resolve_session_scope(records: &[SubagentRecord], session_id: Option<&str>) -> SessionScope {
    let Some(target) = session_id else {
        return SessionScope::Unscopable;
    };
    let has_any_session_data = records.iter().any(|(_, _, sid)| sid.is_some());
    if !has_any_session_data {
        return SessionScope::Unscopable;
    }
    if records
        .iter()
        .any(|(_, _, sid)| sid.as_deref() == Some(target))
    {
        SessionScope::Matched
    } else {
        SessionScope::WellFormedNoMatch
    }
}

/// Pure: count live subagents in `subagents.jsonl` content.
///
/// A subagent is *live* when its `agentId` has a `SubagentStart` record and no
/// matching `SubagentStop`. Reconciliation is by `agentId`.
///
/// Session scoping is resolved by [`resolve_session_scope`]: a session with
/// zero rows in an otherwise well-formed log is a real zero, while a log with
/// no session-scoping data at all falls back to counting every live agent.
/// See the module-level doc comment for why these must not collapse (#512).
///
/// Malformed or blank lines are skipped individually without panicking; records
/// are guaranteed single-line JSON.
fn count_live_subagents(jsonl: &str, session_id: Option<&str>) -> usize {
    // Parse (event, agentId, sessionId) triples from each well-formed line.
    let records: Vec<SubagentRecord> = jsonl
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            let event = value.get("event")?.as_str()?.to_string();
            let agent_id = value.get("agentId")?.as_str()?.to_string();
            let sid = value
                .get("sessionId")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some((event, agent_id, sid))
        })
        .collect();

    let scope = resolve_session_scope(&records, session_id);
    let scoped = records.iter().filter(|(_, _, sid)| match scope {
        SessionScope::Matched => sid.as_deref() == session_id,
        // Real zero: no rows for this session, but the log had scoping data
        // to check that against. Nothing to reconcile.
        SessionScope::WellFormedNoMatch => false,
        SessionScope::Unscopable => true,
    });

    // Reconcile Start/Stop by agentId. An agent is live iff it started and has
    // not stopped.
    use std::collections::HashMap;
    let mut seen: HashMap<&str, (bool, bool)> = HashMap::new();
    for (event, agent_id, _) in scoped {
        let entry = seen.entry(agent_id.as_str()).or_insert((false, false));
        match event.as_str() {
            "SubagentStart" => entry.0 = true,
            "SubagentStop" => entry.1 = true,
            _ => {}
        }
    }

    seen.values()
        .filter(|(started, stopped)| *started && !*stopped)
        .count()
}

/// The nudge message: names the live count, the cap, and the env var to raise it.
fn concurrency_message(live: usize, limit: usize) -> String {
    format!(
        "You already have {live} live subagent(s), at or over the concurrency cap of {limit}. \
         Heavy-context fan-outs can hit server-side request throttling in this regime — consider \
         waiting for one to finish, dispatching in waves, or batching related work into one agent. \
         To raise the cap: set CADENCE_MAX_CONCURRENT_SUBAGENTS in .claude/settings.json."
    )
}

/// Pure decision: nudge when `live >= limit`, else allow.
fn assess_concurrency(live: usize, limit: usize) -> CheckResult {
    if live >= limit {
        CheckResult::nudge(concurrency_message(live, limit))
    } else {
        CheckResult::allow()
    }
}

/// Nudges when the live subagent count is at or over the configured cap.
pub struct WarnSubagentConcurrency;

impl Check for WarnSubagentConcurrency {
    fn name(&self) -> &str {
        "warn-subagent-concurrency"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Only subagent dispatches. `Agent` is current; `Task` is the pre-2.1.63
        // name, kept for resilience. Every other tool exits here. (The hooks.json
        // matcher already filters to Agent|Task in production — belt-and-suspenders.)
        if !matches!(input.tool_name(), Some("Agent" | "Task")) {
            return CheckResult::allow();
        }

        // Fail-open (ADR-0001): any read failure yields allow. A missing log is
        // the common early-session case — never nudge on it.
        let path = metrics_dir().join("subagents.jsonl");
        let Ok(jsonl) = std::fs::read_to_string(&path) else {
            return CheckResult::allow();
        };

        let live = count_live_subagents(&jsonl, input.session_id());
        assess_concurrency(live, subagent_limit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_agent, make_bash};

    // --- count_live_subagents (pure) ---

    #[test]
    fn three_starts_one_stop_counts_two() {
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\",\"sessionId\":\"s\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a3\",\"sessionId\":\"s\"}
{\"event\":\"SubagentStop\",\"agentId\":\"a2\",\"sessionId\":\"s\"}";
        assert_eq!(count_live_subagents(jsonl, Some("s")), 2);
    }

    #[test]
    fn start_and_stop_same_agent_counts_zero() {
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s\"}
{\"event\":\"SubagentStop\",\"agentId\":\"a1\",\"sessionId\":\"s\"}";
        assert_eq!(count_live_subagents(jsonl, Some("s")), 0);
    }

    #[test]
    fn session_filter_counts_only_matching_session() {
        // a1 lives under session s1; a2 lives under s2. Scoped to s1 → only a1.
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s1\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\",\"sessionId\":\"s2\"}";
        assert_eq!(count_live_subagents(jsonl, Some("s1")), 1);
    }

    #[test]
    fn well_formed_log_with_no_rows_for_this_session_reports_real_zero() {
        // a1 lives under s1, a2 lives under s2 — both rows carry a sessionId,
        // so the log is well-formed for scoping purposes. Session "sX" has
        // zero rows in it.
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s1\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\",\"sessionId\":\"s2\"}";

        // Positive control: this exact input is capable of producing a
        // nonzero count when scoping is dropped (session_id: None already
        // takes the Unscopable/count-all path) — proving the test can
        // discriminate, not just pass vacuously. This is the number the old,
        // collapsed fallback would have returned for the unmatched "sX" too.
        assert_eq!(
            count_live_subagents(jsonl, None),
            2,
            "positive control: 2 agents are live when nothing scopes by session"
        );

        // Fixed behavior: "sX" is a real, well-formed absence — report 0, not
        // the other sessions' 2 live agents.
        assert_eq!(count_live_subagents(jsonl, Some("sX")), 0);
    }

    #[test]
    fn schema_missing_session_id_field_is_unscopable_falls_back_to_count_all() {
        // Both rows parse as valid JSON with event + agentId, but neither
        // carries a sessionId field at all — there is no scoping data
        // anywhere in the log to trust, so this is genuinely unscopable.
        // Falls back to counting every live agent.
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\"}";
        assert_eq!(count_live_subagents(jsonl, Some("s")), 2);
    }

    #[test]
    fn mixed_valid_and_garbage_lines_trusts_the_valid_rows_scoping() {
        // a1's row is well-formed with sessionId "other"; the second line is
        // garbage and never parses into a record at all — it contributes
        // neither a match nor scoping data. Because at least one *surviving*
        // record carries a sessionId, the log is judged well-formed, so the
        // non-matching session is a real zero, not a trigger for count-all.
        // Safe direction: garbage lines must never launder an over-count back
        // in by tipping a well-formed file into "unscopable" — they're simply
        // dropped, same as always, and the rows that DO parse are trusted.
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"other\"}
not json at all";
        assert_eq!(count_live_subagents(jsonl, Some("s")), 0);
    }

    #[test]
    fn no_session_id_counts_all() {
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s1\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\",\"sessionId\":\"s2\"}";
        assert_eq!(count_live_subagents(jsonl, None), 2);
    }

    #[test]
    fn malformed_and_blank_lines_skipped_without_panic() {
        let jsonl = "\
{\"event\":\"SubagentStart\",\"agentId\":\"a1\",\"sessionId\":\"s\"}

not json at all
{\"event\":\"SubagentStart\"}
{\"event\":\"SubagentStart\",\"agentId\":\"a2\",\"sessionId\":\"s\"}";
        // a1 and a2 are the only well-formed live records; the garbage, blank,
        // and agentId-less lines are skipped.
        assert_eq!(count_live_subagents(jsonl, Some("s")), 2);
    }

    #[test]
    fn empty_log_counts_zero() {
        assert_eq!(count_live_subagents("", Some("s")), 0);
    }

    // --- assess_concurrency (pure decision) ---

    #[test]
    fn below_limit_allows() {
        assert_eq!(assess_concurrency(3, 5).outcome, Outcome::Allow);
    }

    #[test]
    fn at_limit_nudges() {
        let result = assess_concurrency(5, 5);
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn over_limit_nudges() {
        assert_eq!(assess_concurrency(8, 5).outcome, Outcome::Nudge);
    }

    #[test]
    fn nudge_message_names_count_cap_and_env_var() {
        let result = assess_concurrency(7, 5);
        let msg = result.message.expect("nudge has a message");
        assert!(msg.contains('7'), "names the live count: {msg}");
        assert!(msg.contains('5'), "names the cap: {msg}");
        assert!(
            msg.contains("CADENCE_MAX_CONCURRENT_SUBAGENTS"),
            "names the env var: {msg}"
        );
    }

    // --- parse_limit (pure) ---

    #[test]
    fn parse_limit_unset_is_default() {
        assert_eq!(parse_limit(None), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_limit_empty_is_default() {
        assert_eq!(parse_limit(Some("")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("   ")), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_limit_garbage_is_default() {
        assert_eq!(parse_limit(Some("abc")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("-3")), DEFAULT_LIMIT);
        assert_eq!(parse_limit(Some("3.5")), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_limit_valid_wins() {
        assert_eq!(parse_limit(Some("10")), 10);
        assert_eq!(parse_limit(Some("  2  ")), 2);
        assert_eq!(parse_limit(Some("0")), 0);
    }

    // --- run() ---

    #[test]
    fn non_agent_tool_allows() {
        // A Bash call must never nudge — it exits before any log read.
        let result = WarnSubagentConcurrency.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn missing_log_fails_open() {
        // Point CADENCE_METRICS_DIR at an empty temp dir (no subagents.jsonl) →
        // read fails → allow. Serialized against other env-touching tests.
        let _guard = crate::CADENCE_ENV_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: guarded by CADENCE_ENV_TEST_LOCK; restored below.
        unsafe { std::env::set_var("CADENCE_METRICS_DIR", dir.path()) };
        let input = make_agent(Some("general-purpose"), None, "/tmp");
        let result = WarnSubagentConcurrency.run(&input);
        unsafe { std::env::remove_var("CADENCE_METRICS_DIR") };
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn garbage_bytes_fail_open() {
        // A subagents.jsonl full of non-JSON garbage → zero live → allow (below
        // the default cap). Never panics.
        let _guard = crate::CADENCE_ENV_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // Invalid UTF-8 bytes → read_to_string fails → fail-open; plus non-JSON
        // ASCII so even a lenient read yields zero live records.
        std::fs::write(
            dir.path().join("subagents.jsonl"),
            b"\x00\xff garbage\nmore junk\n",
        )
        .unwrap();
        // SAFETY: guarded by CADENCE_ENV_TEST_LOCK; restored below.
        unsafe { std::env::set_var("CADENCE_METRICS_DIR", dir.path()) };
        let input = make_agent(Some("general-purpose"), None, "/tmp");
        let result = WarnSubagentConcurrency.run(&input);
        unsafe { std::env::remove_var("CADENCE_METRICS_DIR") };
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // The two tests above that mutate process-global env (`set_var`) serialize
    // via the crate-shared CADENCE_ENV_TEST_LOCK (#446).
}
