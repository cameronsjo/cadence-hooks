//! Scan recent Claude Code session logs for slow / cancelled cadence hook
//! runs (cadence-hooks#271, prevention P2).
//!
//! When a guard's git probes stall on a slow host, Claude Code's external
//! hooks.json timeout kills the process and the binary can't self-report — the
//! guard silently fails open. The binary-side `failopen.jsonl` `deadline`
//! telemetry (PR-A) closes that for *git-backed* guards, but a pure-CPU guard
//! (`prevent-secret-writes`) that's merely starved by fork/exec contention
//! never touches the deadline, so its degradation is invisible there too.
//!
//! The one place that degradation IS recorded is Claude Code's own session
//! logs: every hook execution is a JSON record carrying the `command`, its
//! `durationMs`, and a `type`. There is no explicit "killed at the timeout
//! budget" field (a slow-but-completed hook logs `hook_success` with a high
//! `durationMs`; `hook_cancelled` is rare and ambiguous), so this scan reports
//! the signal that IS present and per-guard clean: **latency**. A cadence hook
//! that ran ≥ [`SLOW_MS`] — on a healthy host they finish in well under 250ms
//! — is degraded whether or not it was ultimately killed; a `hook_cancelled`
//! is surfaced separately as a probable kill.
//!
//! Read-only, bounded to the most-recent [`MAX_FILES`] logs by mtime. Output
//! carries only subcommand names, counts, and durations — never command
//! contents, cwd, or transcript text.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A cadence hook run at or above this wall time is counted as degraded.
/// Healthy runs on this machine are 19–242ms; the #271 affected host reports
/// ~5000ms, so 1000ms cleanly separates the two without flagging a normal
/// slow-ish run.
const SLOW_MS: u64 = 1000;

/// Cap the scan to the N most-recently-modified session logs — matches the
/// #271 reporter's own "50 most-recent" methodology and bounds the read on a
/// machine with a deep project history.
const MAX_FILES: usize = 50;

/// Per-subcommand latency tally over the scanned window.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HookLatency {
    pub subcommand: String,
    /// Runs with `durationMs >= SLOW_MS`.
    pub slow: u64,
    /// `hook_cancelled` records — a probable external kill.
    pub cancelled: u64,
    /// Largest `durationMs` observed for this subcommand.
    pub max_ms: u64,
}

/// The `run-cadence-hooks.sh <namespace> <subcommand>` marker and how to pull
/// the `<namespace> <subcommand>` label out of a command string. Returns the
/// two trailing tokens (e.g. `cadence prevent-secret-leaks`) or `None` when the
/// command isn't a cadence hook dispatch.
fn cadence_subcommand(command: &str) -> Option<String> {
    let idx = command.find("run-cadence-hooks.sh")?;
    let tail = command[idx + "run-cadence-hooks.sh".len()..].trim();
    // Strip a trailing quote left by `…run-cadence-hooks.sh" cadence x`.
    let tail = tail.strip_prefix('"').unwrap_or(tail).trim_start();
    let mut tokens = tail.split_whitespace();
    let ns = tokens.next()?;
    let sub = tokens.next()?;
    if ns.is_empty() || sub.is_empty() {
        return None;
    }
    Some(format!("{ns} {sub}"))
}

/// Fold one hook-execution record into the tally. Ignores non-cadence hooks and
/// records with no usable `command`.
fn record_hook(tallies: &mut Vec<HookLatency>, obj: &serde_json::Map<String, Value>) {
    let Some(command) = obj.get("command").and_then(Value::as_str) else {
        return;
    };
    let Some(sub) = cadence_subcommand(command) else {
        return;
    };
    let dur = obj.get("durationMs").and_then(Value::as_u64);
    let cancelled = obj.get("type").and_then(Value::as_str) == Some("hook_cancelled");
    let is_slow = dur.is_some_and(|d| d >= SLOW_MS);
    if !cancelled && !is_slow {
        return;
    }
    let entry = match tallies.iter_mut().find(|t| t.subcommand == sub) {
        Some(e) => e,
        None => {
            tallies.push(HookLatency {
                subcommand: sub,
                ..Default::default()
            });
            tallies.last_mut().expect("just pushed")
        }
    };
    if cancelled {
        entry.cancelled += 1;
    }
    if is_slow {
        entry.slow += 1;
    }
    if let Some(d) = dur {
        entry.max_ms = entry.max_ms.max(d);
    }
}

/// Walk a parsed session-log line for hook-execution objects (they appear both
/// at the top level and nested inside `stop_hook_summary.hookInfos`).
fn walk(value: &Value, tallies: &mut Vec<HookLatency>) {
    match value {
        Value::Object(obj) => {
            // A hook-execution record has a `command`; the stop-summary form
            // nests bare `{command,durationMs}` entries under `hookInfos`.
            if obj.contains_key("command") {
                record_hook(tallies, obj);
            }
            for v in obj.values() {
                walk(v, tallies);
            }
        }
        Value::Array(items) => {
            for v in items {
                walk(v, tallies);
            }
        }
        _ => {}
    }
}

/// Pure core: fold session-log JSONL lines into a per-subcommand latency
/// tally, sorted worst-first (most slow runs, then highest max). Unparsable
/// lines are skipped.
pub fn scan_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<HookLatency> {
    let mut tallies: Vec<HookLatency> = Vec::new();
    for line in lines {
        if !line.contains("run-cadence-hooks.sh") {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        walk(&value, &mut tallies);
    }
    tallies.sort_by(|a, b| {
        b.slow
            .cmp(&a.slow)
            .then(b.cancelled.cmp(&a.cancelled))
            .then(b.max_ms.cmp(&a.max_ms))
    });
    tallies
}

/// The `<config>/projects` directory holding Claude Code session logs.
pub fn projects_dir() -> PathBuf {
    cadence_hooks_core::paths::claude_config_dir().join("projects")
}

/// The `MAX_FILES` most-recently-modified `*.jsonl` logs under `projects_dir`,
/// filtered to files touched within `window` of `now` (an untouched-in-window
/// log can hold no relevant recent run). Best-effort: an unreadable dir yields
/// an empty list.
fn recent_logs(projects: &Path, window: Duration, now: SystemTime) -> Vec<PathBuf> {
    let cutoff = now.checked_sub(window);
    let mut files: Vec<(SystemTime, PathBuf)> = Vec::new();
    let Ok(sessions) = std::fs::read_dir(projects) else {
        return Vec::new();
    };
    for project in sessions.flatten() {
        let Ok(inner) = std::fs::read_dir(project.path()) else {
            continue;
        };
        for entry in inner.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            if cutoff.is_some_and(|c| modified < c) {
                continue;
            }
            files.push((modified, path));
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    files.truncate(MAX_FILES);
    files.into_iter().map(|(_, p)| p).collect()
}

/// Scan the recent session logs and return the per-subcommand latency tally.
/// Read-only and fully best-effort — any read failure contributes nothing.
pub fn scan_recent(projects: &Path, window: Duration, now: SystemTime) -> Vec<HookLatency> {
    let mut tallies: Vec<HookLatency> = Vec::new();
    for log in recent_logs(projects, window, now) {
        let Ok(contents) = std::fs::read_to_string(&log) else {
            continue;
        };
        // Merge each file's tally into the running one.
        for found in scan_lines(contents.lines()) {
            match tallies
                .iter_mut()
                .find(|t| t.subcommand == found.subcommand)
            {
                Some(e) => {
                    e.slow += found.slow;
                    e.cancelled += found.cancelled;
                    e.max_ms = e.max_ms.max(found.max_ms);
                }
                None => tallies.push(found),
            }
        }
    }
    tallies.sort_by(|a, b| {
        b.slow
            .cmp(&a.slow)
            .then(b.cancelled.cmp(&a.cancelled))
            .then(b.max_ms.cmp(&a.max_ms))
    });
    tallies
}

/// One-line human summary of a tally for the doctor finding, or `None` when
/// nothing crossed the bar. Names subcommands + counts + max duration only.
pub fn summary(tallies: &[HookLatency], days: u64) -> Option<String> {
    let total_slow: u64 = tallies.iter().map(|t| t.slow).sum();
    let total_cancelled: u64 = tallies.iter().map(|t| t.cancelled).sum();
    if total_slow == 0 && total_cancelled == 0 {
        return None;
    }
    // Top few offenders by the sort order scan_recent already applied.
    let detail = tallies
        .iter()
        .take(4)
        .map(|t| {
            format!(
                "{} ({} slow{}, max {}ms)",
                t.subcommand,
                t.slow,
                if t.cancelled > 0 {
                    format!(", {} cancelled", t.cancelled)
                } else {
                    String::new()
                },
                t.max_ms
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "{total_slow} cadence hook run(s) ≥{SLOW_MS}ms{} in the last {days} days \
         (Claude Code session logs) — hooks are degrading under slow subprocess \
         I/O and may be exceeding their hooks.json timeout. Worst: {detail}",
        if total_cancelled > 0 {
            format!(" and {total_cancelled} cancelled")
        } else {
            String::new()
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_subcommand_extracts_ns_and_sub() {
        assert_eq!(
            cadence_subcommand(
                "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" cadence prevent-secret-leaks"
            ),
            Some("cadence prevent-secret-leaks".to_string())
        );
        assert_eq!(
            cadence_subcommand("bash /x/run-cadence-hooks.sh guardrails enforce-worktree"),
            Some("guardrails enforce-worktree".to_string())
        );
    }

    #[test]
    fn cadence_subcommand_ignores_non_cadence() {
        assert_eq!(cadence_subcommand("cmux hooks claude stop"), None);
        assert_eq!(cadence_subcommand("run-cadence-hooks.sh cadence"), None); // no sub
    }

    #[test]
    fn scan_counts_slow_and_cancelled_by_subcommand() {
        let lines = vec![
            // fast — ignored
            r#"{"type":"hook_success","hookName":"PreToolUse:Edit","command":"x/run-cadence-hooks.sh cadence prevent-secret-writes","durationMs":42}"#,
            // slow
            r#"{"type":"hook_success","hookName":"PreToolUse:Edit","command":"x/run-cadence-hooks.sh cadence prevent-secret-writes","durationMs":5300}"#,
            // slow again, higher
            r#"{"type":"hook_success","hookName":"PreToolUse:Bash","command":"x/run-cadence-hooks.sh cadence prevent-secret-writes","durationMs":6100}"#,
            // cancelled (probable kill) on a different sub
            r#"{"type":"hook_cancelled","hookName":"PreToolUse:Edit","command":"x/run-cadence-hooks.sh guardrails enforce-worktree","durationMs":null}"#,
            // a non-cadence hook — ignored
            r#"{"type":"hook_success","hookName":"Stop","command":"cmux hooks claude stop","durationMs":9000}"#,
        ];
        let got = scan_lines(lines.into_iter());
        assert_eq!(got.len(), 2);
        // Sorted worst-first: prevent-secret-writes has 2 slow.
        assert_eq!(got[0].subcommand, "cadence prevent-secret-writes");
        assert_eq!(got[0].slow, 2);
        assert_eq!(got[0].cancelled, 0);
        assert_eq!(got[0].max_ms, 6100);
        assert_eq!(got[1].subcommand, "guardrails enforce-worktree");
        assert_eq!(got[1].cancelled, 1);
        assert_eq!(got[1].slow, 0);
    }

    #[test]
    fn scan_skips_unparsable_lines() {
        let lines = vec![
            "not json at all but mentions run-cadence-hooks.sh",
            r#"{"type":"hook_success","command":"x/run-cadence-hooks.sh cadence git-safety","durationMs":2000}"#,
        ];
        let got = scan_lines(lines.into_iter());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].slow, 1);
    }

    #[test]
    fn summary_none_when_all_fast() {
        assert!(summary(&[], 7).is_none());
        let fast = vec![HookLatency {
            subcommand: "cadence git-safety".into(),
            slow: 0,
            cancelled: 0,
            max_ms: 240,
        }];
        assert!(summary(&fast, 7).is_none());
    }

    #[test]
    fn summary_names_offenders_and_counts() {
        let t = vec![HookLatency {
            subcommand: "cadence prevent-secret-writes".into(),
            slow: 21,
            cancelled: 0,
            max_ms: 5500,
        }];
        let s = summary(&t, 7).unwrap();
        assert!(s.contains("21 cadence hook run"));
        assert!(s.contains("cadence prevent-secret-writes"));
        assert!(s.contains("5500ms"));
    }
}
