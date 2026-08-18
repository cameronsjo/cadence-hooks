//! Append-only audit log for guard fires at the dispatch outcome→exit-code
//! seam: one line per hard `deny` to `<metrics_dir>/denials.jsonl` (and per
//! `nudge`, unless `CADENCE_LOG_NUDGES` opts out).
//!
//! Called from the **binary** (`src/dispatch.rs`), not from a `Logger`: the
//! denial is a side effect of an *enforcement* check, and only the binary knows
//! the canonical registry hook name (`check.name()` diverges from it). The write
//! must never perturb the block it is recording — every step is fail-open per
//! ADR-0001, so a full disk or a read-only metrics dir degrades to a no-op and
//! the guard still exits 2 with its unchanged stderr.
//!
//! **Privacy by construction:** the record names *which guard fired on which
//! tool in which repo* — never *what was blocked*. It never reads the command
//! text, file path, or edited content off the [`HookInput`]; a unit test asserts
//! those keys are absent.

use crate::common;
use cadence_hooks_core::{HookEvent, HookInput, Outcome};
use serde_json::{Value, json};
use std::io::Write;

/// Record a guard's decision at the dispatch seam.
///
/// - `Block` → always logged as `decision: "deny"`.
/// - `Nudge` → logged as `decision: "nudge"` by **default**;
///   `CADENCE_LOG_NUDGES=0|false|off` opts out (cadence-hooks#420 — nudge-fire
///   rates are the denominator for every adherence measurement, and a
///   dark-by-default layer went unnoticed for its whole life).
/// - `Allow` → never logged (the hot path stays I/O-free).
///
/// `hook` is the canonical registry name threaded from the binary (e.g.
/// `terminology`, not the `Check::name()` value `terminology-guard`).
///
/// `outcomes` carries EVERY normalized target's outcome — one element for an
/// ordinary tool call, N for a Codex `apply_patch` with N file operations.
///
/// **Exactly one row is written per hook invocation regardless of N.** Writing
/// per target made ledger volume proportional to an attacker-chosen patch body:
/// one `apply_patch` with N operations wrote up to N rows per security-critical
/// hook, into a file with no size cap.
///
/// One row must not mean one decision *remembered*, though. Passing only the
/// strictest outcome deduplicated nothing — it deleted a different event class:
/// a mixed invocation (one target blocks, eleven nudge) wrote a lone `deny` row
/// with no trace that the nudges happened, and nudge-fire rates are the
/// denominator for every adherence measurement. So the row carries a
/// per-decision tally alongside the winning `decision`. `targets` stays the
/// number *judged*, which is deliberately not recoverable from the tally: an
/// `Allow` target is judged and never tallied.
pub fn log_denial(hook: &str, event: HookEvent, input: &HookInput, outcomes: &[Outcome]) {
    let nudges_on = nudges_enabled();
    let Some(decision) = decision_for(strictest(outcomes), nudges_on) else {
        return;
    };

    let record = build_denial_record(hook, event, input, decision, outcomes, nudges_on);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("denials.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        // `record` is compact JSON — one line, no embedded newlines.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// True unless `CADENCE_LOG_NUDGES` explicitly opts out: `0` / `false` / `off`
/// (ASCII case-insensitive) or set-but-empty (`CADENCE_LOG_NUDGES=`, which was
/// OFF under the old opt-in semantics and stays OFF — a value-free kill
/// switch). Unset — the common case — means ON (#420). Any other value,
/// including the legacy opt-in `1`, also means ON, so a config written against
/// the old default keeps working unchanged.
fn nudges_enabled() -> bool {
    std::env::var("CADENCE_LOG_NUDGES")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

/// Map an [`Outcome`] to the `decision` field, or `None` when nothing should be
/// logged. Pure — `nudges_on` is passed in so the env read stays out of the
/// mapping and the mapping is unit-testable.
///
/// `Ask` maps to `"ask"` and is logged *unconditionally* (like `Block`), not
/// gated on `nudges_on`: forcing an interactive prompt is a real guard
/// intervention — it overrides a settings `allow` rule — so a proving period
/// needs to see it, not just hard denies.
fn decision_for(outcome: Outcome, nudges_on: bool) -> Option<&'static str> {
    match outcome {
        Outcome::Block => Some("deny"),
        Outcome::Ask => Some("ask"),
        Outcome::Nudge => nudges_on.then_some("nudge"),
        Outcome::Allow => None,
    }
}

/// Build the `denials.jsonl` record. Pure — no I/O beyond the git query behind
/// [`common::repo_basename`]. Reads only non-sensitive context off the input
/// (tool name, session id, agent id, cwd→repo) — never the command, file path,
/// or edited content.
fn build_denial_record(
    hook: &str,
    event: HookEvent,
    input: &HookInput,
    decision: &str,
    outcomes: &[Outcome],
    nudges_on: bool,
) -> Value {
    json!({
        "ts": common::utc_timestamp(),
        "hook": hook,
        "event": event.name(),
        // The strictest decision across targets — what the tool call got.
        "decision": decision,
        "tool": input.tool_name(),
        "repo": common::repo_basename(input.cwd.as_deref()),
        "sessionId": input.session_id(),
        "agentId": input.agent_id(),
        // How many normalized targets one invocation judged. A path count, never
        // a path: it says how wide the operation was, not what it touched.
        "targets": outcomes.len(),
        // What each of them decided, so a mixed invocation stays countable per
        // decision. Omits `Allow` (never logged) and, when nudges are opted out,
        // `nudge` — so the tally holds exactly the rows a per-target ledger
        // would have written, minus the row count.
        "decisions": decision_tally(outcomes, nudges_on),
    })
}

/// The strictest outcome across every judged target, folded with the same
/// [`Outcome::merge`] the dispatch aggregate uses — so the row's `decision` and
/// what the tool call actually got cannot disagree.
fn strictest(outcomes: &[Outcome]) -> Outcome {
    outcomes
        .iter()
        .fold(Outcome::Allow, |merged, other| merged.merge(*other))
}

/// `{"deny": 1, "nudge": 11}` — one count per loggable decision, in a stable
/// order so rows stay diffable. The insertion order below is `deny`/`ask`/
/// `nudge`, but that is not what lands: serde_json is built here without
/// `preserve_order`, so `Map` is a `BTreeMap` and the emitted keys are
/// alphabetical. Stability is what the diffability claim needs, and a
/// `BTreeMap` supplies it. Pure, and separate from the record builder so the
/// tally rule is testable without a timestamp or a repo probe.
fn decision_tally(outcomes: &[Outcome], nudges_on: bool) -> Value {
    let mut tally = serde_json::Map::new();
    for kind in ["deny", "ask", "nudge"] {
        let count = outcomes
            .iter()
            .filter(|outcome| decision_for(**outcome, nudges_on) == Some(kind))
            .count();
        if count > 0 {
            tally.insert(kind.to_string(), json!(count));
        }
    }
    Value::Object(tally)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::ToolInput;

    fn edit_input() -> HookInput {
        // A payload carrying sensitive fields (command, file_path, content) — the
        // record must expose none of them.
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(ToolInput {
                file_path: Some("/secret/path/notes.md".into()),
                command: Some("rm -rf /secret".into()),
                new_string: Some("whitelist the host".into()),
                ..Default::default()
            }),
            cwd: Some("/tmp".into()),
            session_id: Some("sess-1".into()),
            agent_id: Some("agent-9".into()),
            ..Default::default()
        }
    }

    // --- decision_for ---

    #[test]
    fn block_always_denies() {
        assert_eq!(decision_for(Outcome::Block, false), Some("deny"));
        assert_eq!(decision_for(Outcome::Block, true), Some("deny"));
    }

    #[test]
    fn allow_never_logs() {
        assert_eq!(decision_for(Outcome::Allow, false), None);
        assert_eq!(decision_for(Outcome::Allow, true), None);
    }

    #[test]
    fn nudge_gated_on_env() {
        assert_eq!(decision_for(Outcome::Nudge, false), None);
        assert_eq!(decision_for(Outcome::Nudge, true), Some("nudge"));
    }

    #[test]
    fn ask_always_logs_ungated() {
        // Ask is a real intervention (overrides an allow rule), so it logs
        // regardless of CADENCE_LOG_NUDGES — the proving period needs it.
        assert_eq!(decision_for(Outcome::Ask, false), Some("ask"));
        assert_eq!(decision_for(Outcome::Ask, true), Some("ask"));
    }

    // --- build_denial_record ---

    #[test]
    fn record_has_expected_fields() {
        let rec = build_denial_record(
            "terminology",
            HookEvent::PreToolUse,
            &edit_input(),
            "deny",
            &[Outcome::Block],
            true,
        );
        assert_eq!(rec["hook"], "terminology");
        assert_eq!(rec["event"], "PreToolUse");
        assert_eq!(rec["decision"], "deny");
        assert_eq!(rec["tool"], "Edit");
        assert_eq!(rec["sessionId"], "sess-1");
        assert_eq!(rec["agentId"], "agent-9");
        assert!(rec["ts"].is_string());
        assert!(rec["repo"].is_string());
    }

    #[test]
    fn record_omits_sensitive_keys() {
        // Privacy by construction: the record must never carry command content,
        // file paths, or edited text — only which guard fired on which tool.
        let rec = build_denial_record(
            "git-safety",
            HookEvent::PreToolUse,
            &edit_input(),
            "deny",
            &[Outcome::Block],
            true,
        );
        let obj = rec.as_object().expect("record is an object");
        for forbidden in ["command", "file_path", "filePath", "content", "new_string"] {
            assert!(
                !obj.contains_key(forbidden),
                "record must not carry '{forbidden}': {rec}"
            );
        }
        // And no *value* in the record leaks the sensitive strings.
        let serialized = rec.to_string();
        assert!(
            !serialized.contains("/secret/path"),
            "leaked file path: {serialized}"
        );
        assert!(
            !serialized.contains("rm -rf"),
            "leaked command: {serialized}"
        );
        assert!(
            !serialized.contains("whitelist"),
            "leaked content: {serialized}"
        );
    }

    #[test]
    fn record_main_thread_agent_id_is_null() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            cwd: Some("/tmp".into()),
            session_id: Some("s".into()),
            ..Default::default()
        };
        let rec = build_denial_record(
            "guard-push-remote",
            HookEvent::PreToolUse,
            &input,
            "deny",
            &[Outcome::Block],
            true,
        );
        assert!(rec["agentId"].is_null());
    }

    // --- log_denial end-to-end (tempdir) ---

    /// Serialize the env-mutating tests against every other module's: the
    /// process-global `CADENCE_METRICS_DIR` / `CADENCE_LOG_NUDGES` are shared with
    /// sibling loggers' tests (`log_timing`), so all hold the one crate-wide lock.
    use crate::common::ENV_LOCK;

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, nudges: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
            match nudges {
                Some(v) => std::env::set_var("CADENCE_LOG_NUDGES", v),
                None => std::env::remove_var("CADENCE_LOG_NUDGES"),
            }
        }
        f();
        // SAFETY: serialized against every other env-mutating test in this module.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
            std::env::remove_var("CADENCE_LOG_NUDGES");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("denials.jsonl");
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
                .collect(),
            Err(_) => vec![],
        }
    }

    #[test]
    fn block_writes_one_deny_row() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "terminology",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Block],
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["decision"], "deny");
        assert_eq!(rows[0]["hook"], "terminology");
    }

    /// The row carries the fan-out as a count, so a wide operation is still
    /// visible in the ledger without being amplified into it.
    #[test]
    fn record_carries_the_target_count() {
        let rec = build_denial_record(
            "prevent-secret-writes",
            HookEvent::PreToolUse,
            &edit_input(),
            "deny",
            &[Outcome::Block; 37],
            true,
        );
        assert_eq!(rec["targets"], 37);
        // A count, not a path list — the privacy contract is unchanged.
        assert!(rec["targets"].is_number());
    }

    /// The regression this pins: one row must not mean one decision remembered.
    /// Collapsing a mixed invocation to its strictest outcome erased the nudge
    /// decisions entirely, and nudge-fire rates are the denominator for every
    /// adherence measurement.
    #[test]
    fn record_tallies_every_decision_not_just_the_winner() {
        let mut outcomes = vec![Outcome::Block];
        outcomes.extend(std::iter::repeat_n(Outcome::Nudge, 11));

        let rec = build_denial_record(
            "prevent-secret-writes",
            HookEvent::PreToolUse,
            &edit_input(),
            "deny",
            &outcomes,
            true,
        );

        assert_eq!(rec["decision"], "deny", "the tool call was blocked");
        assert_eq!(rec["decisions"], json!({"deny": 1, "nudge": 11}));
        assert_eq!(rec["targets"], 12);
    }

    /// `targets` counts what was JUDGED and the tally counts what was LOGGED, so
    /// an all-Allow target set is deliberately not recoverable from the tally.
    #[test]
    fn tally_omits_allow_while_targets_still_counts_it() {
        let outcomes = [Outcome::Block, Outcome::Allow, Outcome::Allow];
        let rec = build_denial_record(
            "guard-rm",
            HookEvent::PreToolUse,
            &edit_input(),
            "deny",
            &outcomes,
            true,
        );
        assert_eq!(rec["decisions"], json!({"deny": 1}));
        assert_eq!(rec["targets"], 3);
    }

    /// The tally honours the nudge opt-out the same way the row does — it holds
    /// exactly the rows a per-target ledger would have written.
    #[test]
    fn tally_respects_the_nudge_opt_out() {
        let outcomes = [Outcome::Block, Outcome::Nudge, Outcome::Ask];
        assert_eq!(
            decision_tally(&outcomes, true),
            json!({"deny": 1, "ask": 1, "nudge": 1})
        );
        assert_eq!(
            decision_tally(&outcomes, false),
            json!({"deny": 1, "ask": 1}),
            "an opted-out nudge is not written, so it is not tallied"
        );
    }

    /// `strictest` must agree with the dispatch aggregate, or the row's
    /// `decision` would describe a fate the tool call did not get.
    #[test]
    fn strictest_matches_outcome_merge() {
        assert_eq!(strictest(&[Outcome::Nudge, Outcome::Block]), Outcome::Block);
        assert_eq!(strictest(&[Outcome::Nudge, Outcome::Ask]), Outcome::Ask);
        assert_eq!(strictest(&[Outcome::Allow, Outcome::Allow]), Outcome::Allow);
        assert_eq!(strictest(&[]), Outcome::Allow);
    }

    /// One invocation writes exactly one row however many targets it judged.
    /// The per-target write this replaces made ledger volume proportional to an
    /// attacker-chosen patch body, into a file with no size cap.
    #[test]
    fn a_wide_invocation_still_writes_exactly_one_row() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "prevent-secret-writes",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Block; 500],
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1, "500 targets must not write 500 rows");
        assert_eq!(rows[0]["targets"], 500);
    }

    #[test]
    fn allow_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "terminology",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Allow],
            );
        });
        assert!(
            read_lines(tmp.path()).is_empty(),
            "Allow must not write a row"
        );
        assert!(!tmp.path().join("denials.jsonl").exists());
    }

    #[test]
    fn nudge_logged_by_default_and_with_legacy_opt_in() {
        let tmp = tempfile::tempdir().unwrap();
        // Env unset (the common case) → one nudge row, ON by default (#420).
        with_metrics_dir(tmp.path(), None, || {
            log_denial(
                "warn-main-branch",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Nudge],
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(
            rows.len(),
            1,
            "nudge with env unset must write (default ON)"
        );
        assert_eq!(rows[0]["decision"], "nudge");

        // The legacy opt-in value stays ON — configs written against the old
        // default keep working unchanged.
        with_metrics_dir(tmp.path(), Some("1"), || {
            log_denial(
                "warn-main-branch",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Nudge],
            );
        });
        assert_eq!(read_lines(tmp.path()).len(), 2);
    }

    #[test]
    fn nudge_opt_out_values_suppress_the_row() {
        let tmp = tempfile::tempdir().unwrap();
        for off in ["0", "false", "off", "FALSE", " Off ", ""] {
            with_metrics_dir(tmp.path(), Some(off), || {
                log_denial(
                    "warn-main-branch",
                    HookEvent::PreToolUse,
                    &edit_input(),
                    &[Outcome::Nudge],
                );
            });
        }
        assert!(
            read_lines(tmp.path()).is_empty(),
            "every opt-out spelling must suppress the nudge row"
        );
        // Opt-out never touches deny rows.
        with_metrics_dir(tmp.path(), Some("0"), || {
            log_denial(
                "terminology",
                HookEvent::PreToolUse,
                &edit_input(),
                &[Outcome::Block],
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["decision"], "deny");
    }
}
