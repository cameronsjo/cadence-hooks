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

/// Run `<namespace> <subcommand>` against a sample (or `--payload`) payload
/// and print a report.
///
/// Exit code: the hook's own exit code on a successful run (0 allow/nudge,
/// 2 block), or 1 when the hook could not be run at all (unknown name,
/// unreadable payload file, spawn failure).
pub fn run(namespace: &str, subcommand: &str, payload_file: Option<&Path>) -> i32 {
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
        None => sample_payload_with_cwd(entry.event),
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
    println!("Payload:  {}", payload.trim());
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

/// The sample payload for an event, with the real working directory injected
/// so hooks that resolve git state see the repo `try` was run from.
fn sample_payload_with_cwd(event: Option<HookEvent>) -> String {
    let base = match event {
        Some(e) => e.sample_payload(),
        None => LOGGER_SAMPLE_PAYLOAD,
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
        let payload = sample_payload_with_cwd(Some(HookEvent::PreToolUse));
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("cwd").is_some(), "cwd should be injected: {payload}");
        assert_eq!(v["tool_name"], "Bash");
    }

    #[test]
    fn sample_payload_for_logger_uses_metrics_shape() {
        let payload = sample_payload_with_cwd(None);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("hook_event_name").is_some());
        assert!(v.get("cwd").is_some());
    }
}
