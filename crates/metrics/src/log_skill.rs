//! `Skill` tool invocations — append one line per call to
//! `<metrics_dir>/skills.jsonl`.
//!
//! A lifecycle audit log only — no token or cost data (sibling of
//! [`crate::log_subagent`]). Privacy-by-construction (D5): the skill id is
//! recorded in clear (it's not sensitive — it's a plugin:directory name), but
//! the skill's `args` string is NEVER logged raw. Instead, `argsHash` carries a
//! non-reversible [`std::collections::hash_map::DefaultHasher`] digest of it —
//! the same fixed-key, stable-across-processes hash [`cadence_hooks_core::markers`]
//! uses for its marker filenames.
//!
//! Stamps `schemaVersion` (`common::SKILL_SCHEMA_VERSION`) on every row. Unlike
//! its [`crate::log_subagent`] sibling, the record also carries a `repo` field
//! (basename of the cwd) — a skill invocation is meaningful *per repo* (the
//! co-fire matrix groups by project), whereas a subagent lifecycle event is
//! already attributable via its `parentSessionId` chain.

use crate::common;
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;

/// Appends a line to `skills.jsonl` for each `Skill` tool invocation.
pub struct LogSkill;

impl Logger for LogSkill {
    fn name(&self) -> &str {
        "log-skill"
    }

    fn run(&self, input: &MetricsInput) {
        if input.hook_event_name.as_deref() != Some("PostToolUse") {
            return;
        }
        if input.tool_name.as_deref() != Some("Skill") {
            return;
        }

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }

        let debug = std::env::var("CADENCE_METRICS_DEBUG").as_deref() == Ok("1");
        let record = build_skill_record(input, &common::utc_timestamp(), debug);

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("skills.jsonl"))
        {
            // Build the whole line (record + newline) and write it in one
            // write_all, matching log_subagent.rs — a single O_APPEND write is
            // atomic, so concurrent appends can't interleave a record with its
            // trailing newline (#94).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Non-reversible digest of a skill's `args` string, hex-encoded. `None`
/// (JSON `null`) when `args` is absent — never hash an absent value into a
/// spurious "empty string" digest.
fn args_hash(args: Option<&str>) -> Option<String> {
    args.map(|s| {
        let mut h = DefaultHasher::new();
        s.hash(&mut h);
        format!("{:016x}", h.finish())
    })
}

/// Build the JSONL record for a skill invocation. Pure — no I/O.
fn build_skill_record(input: &MetricsInput, ts: &str, include_keys: bool) -> Value {
    let skill = input.tool_input.as_ref().and_then(|ti| ti.skill.clone());
    let args = input.tool_input.as_ref().and_then(|ti| ti.args.as_deref());

    let mut record = json!({
        "schemaVersion": common::SKILL_SCHEMA_VERSION,
        "ts": ts,
        "event": "skill",
        "sessionId": input.session_id,
        "repo": common::repo_basename(input.cwd.as_deref()),
        "skill": skill,
        "argsHash": args_hash(args),
        "agentId": input.agent_id,
        "agentType": input.agent_type,
        "parentSessionId": input.parent_session_id,
    });

    if include_keys && let Some(obj) = record.as_object_mut() {
        obj.insert("_keys".to_string(), json!(input.raw_keys));
    }

    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::ToolInput;

    fn skill_event() -> MetricsInput {
        MetricsInput {
            hook_event_name: Some("PostToolUse".into()),
            tool_name: Some("Skill".into()),
            session_id: Some("s1".into()),
            agent_id: Some("a1".into()),
            agent_type: Some("Explore".into()),
            tool_input: Some(ToolInput {
                skill: Some("cadence:attune".into()),
                args: Some("execute C8".into()),
                ..Default::default()
            }),
            raw_keys: vec!["hook_event_name".into(), "tool_name".into()],
            ..Default::default()
        }
    }

    #[test]
    fn name_is_log_skill() {
        assert_eq!(LogSkill.name(), "log-skill");
    }

    #[test]
    fn record_carries_skill_in_clear_and_hashed_args() {
        let record = build_skill_record(&skill_event(), "2026-07-07T00:00:00Z", false);
        assert_eq!(record["schemaVersion"], common::SKILL_SCHEMA_VERSION);
        assert_eq!(record["event"], "skill");
        assert_eq!(record["skill"], "cadence:attune");
        assert_eq!(record["ts"], "2026-07-07T00:00:00Z");
        let hash = record["argsHash"].as_str().expect("argsHash present");
        assert_ne!(hash, "execute C8", "raw args must never be logged");
        assert!(record.get("_keys").is_none());
    }

    #[test]
    fn args_hash_is_stable_across_builds() {
        let a = build_skill_record(&skill_event(), "2026-07-07T00:00:00Z", false);
        let b = build_skill_record(&skill_event(), "2026-07-07T00:00:00Z", false);
        assert_eq!(a["argsHash"], b["argsHash"]);
    }

    #[test]
    fn wrong_hook_event_is_noop() {
        let input = MetricsInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: Some("Skill".into()),
            ..Default::default()
        };
        LogSkill.run(&input);
    }

    #[test]
    fn wrong_tool_name_is_noop() {
        let input = MetricsInput {
            hook_event_name: Some("PostToolUse".into()),
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        LogSkill.run(&input);
    }

    #[test]
    fn absent_args_yields_null_hash() {
        let mut input = skill_event();
        input.tool_input = Some(ToolInput {
            skill: Some("cadence:attune".into()),
            args: None,
            ..Default::default()
        });
        let record = build_skill_record(&input, "2026-07-07T00:00:00Z", false);
        assert!(record["argsHash"].is_null());
    }

    #[test]
    fn debug_adds_keys() {
        let record = build_skill_record(&skill_event(), "2026-07-07T00:00:00Z", true);
        let keys = record["_keys"].as_array().unwrap();
        assert!(keys.contains(&json!("tool_name")));
    }

    #[test]
    fn record_serializes_to_single_line() {
        // #94: the single-write_all fix is only atomic-per-record if the record
        // has no embedded newline. Compact JSON guarantees this; lock it down.
        let line = build_skill_record(&skill_event(), "2026-07-07T00:00:00Z", true).to_string();
        assert!(!line.contains('\n'), "record must be one line: {line}");
    }
}
