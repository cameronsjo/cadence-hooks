//! `cadence-hooks try <namespace> <subcommand>` — run a hook against a
//! generated sample payload and report the outcome.
//!
//! Self-executes the current binary with the payload piped to stdin, so the
//! exercised path (clap parse → stdin read → serde → check) is exactly what
//! Claude Code drives in production — nothing here can drift from the real
//! dispatch.

use crate::registry;
use cadence_hooks_core::{HookEvent, LOGGER_SAMPLE_PAYLOAD};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Maximum bytes of payload echoed in the report. User-supplied payloads
/// (`--payload`) can carry real command text or file content — bound the
/// echo so `try` never leaks full payloads into scrollback or CI logs.
/// `--show-payload` opts in to the full echo.
const PAYLOAD_PREVIEW_LIMIT: usize = 200;

/// Run `<namespace> <subcommand>` against a sample (or `--payload`) payload
/// and print a report.
///
/// Exit code: the hook's own exit code on a successful run (0 allow/nudge,
/// 2 block), or 1 when the hook could not be run at all (unknown name,
/// unreadable payload file, spawn failure).
pub fn run(
    namespace: &str,
    subcommand: &str,
    payload_file: Option<&Path>,
    show_payload: bool,
) -> i32 {
    let Some(entry) = registry::entry(namespace, subcommand) else {
        if let Some(actual_ns) = registry::namespace_of(subcommand) {
            eprintln!(
                "cadence-hooks: '{subcommand}' belongs to the '{actual_ns}' namespace, not '{namespace}'.\n\
                 \n\
                 Try: cadence-hooks try {actual_ns} {subcommand}"
            );
        } else {
            eprintln!(
                "cadence-hooks: no hook named '{namespace} {subcommand}'.\n\
                 \n\
                 See 'cadence-hooks list' for every hook and its namespace."
            );
        }
        return 1;
    };

    let payload = match payload_file {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "cadence-hooks: cannot read payload file {}: {e}",
                    path.display()
                );
                return 1;
            }
        },
        None => sample_payload_with_cwd(namespace, subcommand, entry.event),
    };

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cadence-hooks: cannot resolve own binary path: {e}");
            return 1;
        }
    };

    let event_label = match entry.event {
        Some(e) => e.name(),
        None => "logger (reacts to hook_event_name in the payload)",
    };
    println!("Hook:     {namespace} {subcommand} — {}", entry.description);
    println!("Event:    {event_label}");
    println!(
        "Payload:  {}",
        payload_preview(payload.trim(), payload_file.is_some(), show_payload)
    );
    println!();

    let mut child = match Command::new(&exe)
        .args([namespace, subcommand])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cadence-hooks: failed to spawn {}: {e}", exe.display());
            return 1;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        // Ignore write errors: a hook that exits before reading stdin (e.g.
        // bypassed) closes the pipe early, and that's not a try failure.
        let _ = stdin.write_all(payload.as_bytes());
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("cadence-hooks: failed to wait for hook: {e}");
            return 1;
        }
    };

    let code = output.status.code().unwrap_or(-1);
    let outcome = match code {
        0 => "ALLOW / NUDGE",
        2 => "BLOCK",
        _ => "ERROR (non-blocking)",
    };

    println!("Outcome:  {outcome} (exit {code})");
    print_stream("Stdout", &output.stdout);
    print_stream("Stderr", &output.stderr);

    code
}

/// Bound the payload echo for user-supplied payloads; generated samples are
/// synthetic (no secrets) and always short enough to show in full.
fn payload_preview(payload: &str, user_supplied: bool, show_payload: bool) -> String {
    if !user_supplied || show_payload || payload.len() <= PAYLOAD_PREVIEW_LIMIT {
        return payload.to_string();
    }
    let truncated: String = payload.chars().take(PAYLOAD_PREVIEW_LIMIT).collect();
    format!(
        "{truncated}... ({} bytes total — pass --show-payload for the full payload)",
        payload.len()
    )
}

/// The sample payload for a hook, with the real working directory injected
/// so hooks that resolve git state see the repo `try` was run from.
///
/// Per-hook registry overrides (`registry::sample_for`) win over event-based
/// samples — loggers gate on `hook_event_name` and command shapes, so the
/// generic fallback can exercise the wrong branch.
fn sample_payload_with_cwd(namespace: &str, subcommand: &str, event: Option<HookEvent>) -> String {
    let base = match registry::sample_for(namespace, subcommand) {
        Some(sample) => sample,
        None => match event {
            Some(e) => e.sample_payload(),
            None => LOGGER_SAMPLE_PAYLOAD,
        },
    };
    match serde_json::from_str::<serde_json::Value>(base) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut()
                && let Ok(cwd) = std::env::current_dir()
            {
                obj.insert(
                    "cwd".into(),
                    serde_json::Value::String(cwd.display().to_string()),
                );
            }
            v.to_string()
        }
        // Unreachable while the round-trip unit tests hold, but degrade
        // gracefully rather than panic.
        Err(_) => base.to_string(),
    }
}

/// Print a captured output stream: inline when short, indented block when long.
fn print_stream(label: &str, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        println!("{label}:   (none)");
    } else if trimmed.lines().count() == 1 {
        println!("{label}:   {trimmed}");
    } else {
        println!("{label}:");
        for line in trimmed.lines() {
            println!("  {line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_payload_with_cwd_injects_cwd() {
        let payload =
            sample_payload_with_cwd("cadence", "terminology", Some(HookEvent::PreToolUse));
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("cwd").is_some(), "cwd should be injected: {payload}");
        assert_eq!(v["tool_name"], "Bash");
    }

    #[test]
    fn sample_payload_for_logger_uses_metrics_shape() {
        let payload = sample_payload_with_cwd("session", "heartbeat", None);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("hook_event_name").is_some());
        assert!(v.get("cwd").is_some());
    }

    #[test]
    fn sample_payload_uses_registry_override_for_log_subagent() {
        // log-subagent only reacts to SubagentStart/SubagentStop — the registry
        // override must win over the generic PostToolUse fallback.
        let payload = sample_payload_with_cwd("metrics", "log-subagent", None);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            v["hook_event_name"], "SubagentStop",
            "registry override should be used: {payload}"
        );
    }

    #[test]
    fn generated_payload_preview_is_never_truncated() {
        let long_sample = format!(r#"{{"tool_name":"Bash","content":"{}"}}"#, "x".repeat(500));
        let preview = payload_preview(&long_sample, false, false);
        assert_eq!(preview, long_sample, "generated samples show in full");
    }

    #[test]
    fn user_payload_preview_is_bounded() {
        let long_payload = format!(r#"{{"tool_name":"Bash","content":"{}"}}"#, "x".repeat(500));
        let preview = payload_preview(&long_payload, true, false);
        assert!(preview.len() < long_payload.len(), "should truncate");
        assert!(
            preview.contains("--show-payload"),
            "should name the opt-in flag: {preview}"
        );
    }

    #[test]
    fn user_payload_shown_in_full_with_opt_in() {
        let long_payload = format!(r#"{{"tool_name":"Bash","content":"{}"}}"#, "x".repeat(500));
        let preview = payload_preview(&long_payload, true, true);
        assert_eq!(preview, long_payload, "--show-payload shows everything");
    }

    #[test]
    fn short_user_payload_shown_in_full() {
        let short = r#"{"tool_name":"Bash"}"#;
        let preview = payload_preview(short, true, false);
        assert_eq!(preview, short, "short payloads need no truncation");
    }
}
