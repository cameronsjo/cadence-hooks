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

    // A metrics logger writes unconditionally and silently (no stdout on
    // success), so without this override `try` appends a real row to the
    // live production metrics stream every time it exercises one (#269).
    // Scratch dir is best-effort: if it can't be created, the child falls
    // back to the real metrics dir rather than failing the `try` run — the
    // pre-existing (buggy) behavior, not a new failure mode — but this must
    // never be a *silent* fallback, or the exact bug being fixed recurs
    // invisibly.
    let metrics_scratch = tempfile::tempdir().ok();
    if metrics_scratch.is_none() {
        eprintln!(
            "cadence-hooks: could not create a scratch metrics dir — this run \
             may write a real row into the production metrics directory."
        );
    }

    let mut command = Command::new(&exe);
    command
        .args([namespace, subcommand])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(scratch) = &metrics_scratch {
        command.env("CADENCE_METRICS_DIR", scratch.path());
    }

    let mut child = match command.spawn() {
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
    let kind = classify_stdout(&output.stdout);

    println!("Outcome:  {} (exit {code})", outcome_label(code, &kind));
    match &kind {
        StdoutKind::Empty => println!("Stdout:   (none)"),
        StdoutKind::Nudge(ctx) => {
            println!("Context injected (what Claude sees):");
            println!();
            print_text_block(ctx);
        }
        StdoutKind::LoopBlock(reason) => {
            println!("Re-prompt reason (fed back to Claude):");
            println!();
            print_text_block(reason);
        }
        StdoutKind::OtherJson(pretty) => {
            println!("Stdout:");
            print_text_block(pretty);
        }
        StdoutKind::Raw(_) => print_stream("Stdout", &output.stdout),
    }
    print_stream("Stderr", &output.stderr);

    code
}

/// The hook's stdout decoded per the hook protocol.
///
/// `try` is a teaching tool — the point is showing what the hook *says to
/// Claude*, not echoing the protocol envelope it says it in.
#[derive(Debug, PartialEq)]
enum StdoutKind {
    /// No output — a silent allow.
    Empty,
    /// Nudge envelope: `hookSpecificOutput.additionalContext` injected into
    /// Claude's context.
    Nudge(String),
    /// Re-prompt envelope: `decision: "block"` + `reason` fed back so the
    /// model rewrites (PostToolUse LoopBlock).
    LoopBlock(String),
    /// Valid JSON without a recognized protocol shape (pretty-printed).
    OtherJson(String),
    /// Anything that isn't JSON.
    Raw(String),
}

/// Decode stdout into its protocol meaning.
fn classify_stdout(bytes: &[u8]) -> StdoutKind {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return StdoutKind::Empty;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return StdoutKind::Raw(trimmed.to_string());
    };
    // LoopBlock first: its envelope also mirrors the message into
    // hookSpecificOutput.additionalContext, so the decision/reason pair is
    // the distinguishing shape.
    if v.get("decision").and_then(|d| d.as_str()) == Some("block")
        && let Some(reason) = v.get("reason").and_then(|r| r.as_str())
    {
        return StdoutKind::LoopBlock(reason.to_string());
    }
    if let Some(ctx) = v
        .pointer("/hookSpecificOutput/additionalContext")
        .and_then(|c| c.as_str())
    {
        return StdoutKind::Nudge(ctx.to_string());
    }
    StdoutKind::OtherJson(serde_json::to_string_pretty(&v).unwrap_or_else(|_| trimmed.to_string()))
}

/// The outcome label, sharpened by what stdout actually carried.
///
/// Exit 0 alone is ambiguous (allow and nudge share it); the decoded stdout
/// disambiguates.
fn outcome_label(code: i32, kind: &StdoutKind) -> &'static str {
    match (code, kind) {
        (0, StdoutKind::Nudge(_)) => "NUDGE",
        (0, StdoutKind::LoopBlock(_)) => "LOOP-BLOCK (re-prompt)",
        (0, _) => "ALLOW",
        (2, _) => "BLOCK",
        _ => "ERROR (non-blocking)",
    }
}

/// Print multi-line text indented two spaces.
fn print_text_block(text: &str) {
    for line in text.lines() {
        if line.is_empty() {
            println!();
        } else {
            println!("  {line}");
        }
    }
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

/// `(namespace, subcommand)` pairs whose sample payload's `cwd` `try` must
/// NEVER override with the real `current_dir()`.
///
/// `sample_payload_with_cwd`'s normal behavior — inject the real cwd, so most
/// checks exercise real repo/git-state detection — is correct for the
/// overwhelming majority of hooks, which only ever READ state. It is actively
/// dangerous for a hook with a genuine filesystem WRITE side effect: injecting
/// a real repo path let a bare `cadence-hooks try session persist-plan-approval`
/// (or the since-removed `persist-plan`) actually create a plan doc in whatever repo the
/// user happened to be standing in when they ran `try` — reachable endpoints
/// included `~/.claude/rules/`. Verified end to end (cameronsjo/cadence-hooks#396
/// review): a real plan doc landed in a real repo during review, then had to
/// be manually removed.
///
/// Every entry here MUST carry its own `cwd` in its `registry::sample_for`
/// override (see `session persist-plan-approval`'s override),
/// pointed at a path that cannot resolve as a git repo — never left absent,
/// since an absent `cwd` degrades most Checks to a no-op fail-open, not a
/// demonstration of the hook's real behavior.
const CWD_OVERRIDE_REFUSED: &[(&str, &str)] = &[("session", "persist-plan-approval")];

/// The sample payload for a hook, with the real working directory injected
/// so hooks that resolve git state see the repo `try` was run from — EXCEPT
/// for [`CWD_OVERRIDE_REFUSED`] entries, whose own sample `cwd` is left
/// exactly as the registry declared it.
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
    if CWD_OVERRIDE_REFUSED.contains(&(namespace, subcommand)) {
        return base.to_string();
    }
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
    fn cwd_override_refused_never_injects_the_real_cwd() {
        // Regression (cameronsjo/cadence-hooks#396 review): these two hooks
        // have a genuine filesystem WRITE side effect — injecting the real
        // current_dir() let a bare `try` actually write a plan doc into
        // whatever repo the user was standing in. The sample's own
        // deliberately-nonexistent `cwd` must survive untouched.
        for (namespace, subcommand) in CWD_OVERRIDE_REFUSED {
            let payload =
                sample_payload_with_cwd(namespace, subcommand, Some(HookEvent::PostToolUse));
            let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(
                v["cwd"], "/nonexistent-cadence-hooks-try-sandbox",
                "{namespace} {subcommand} must keep its sentinel cwd, not the real current_dir(): {payload}"
            );
        }
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

    // --- stdout protocol decoding ---

    #[test]
    fn classify_empty_stdout() {
        assert_eq!(classify_stdout(b""), StdoutKind::Empty);
        assert_eq!(classify_stdout(b"  \n"), StdoutKind::Empty);
    }

    #[test]
    fn classify_nudge_envelope_extracts_context() {
        let stdout = br#"{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"Line one.\nLine two."}}"#;
        match classify_stdout(stdout) {
            StdoutKind::Nudge(ctx) => {
                assert_eq!(ctx, "Line one.\nLine two.");
            }
            other => panic!("expected Nudge, got {other:?}"),
        }
    }

    #[test]
    fn classify_loop_block_wins_over_nudge_mirror() {
        // LoopBlock envelopes mirror the reason into additionalContext —
        // the decision/reason pair must take precedence.
        let stdout = br#"{"decision":"block","reason":"rewrite it","hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"rewrite it"}}"#;
        match classify_stdout(stdout) {
            StdoutKind::LoopBlock(reason) => assert_eq!(reason, "rewrite it"),
            other => panic!("expected LoopBlock, got {other:?}"),
        }
    }

    #[test]
    fn classify_unrecognized_json_pretty_prints() {
        let stdout = br#"{"custom":{"nested":true}}"#;
        match classify_stdout(stdout) {
            StdoutKind::OtherJson(pretty) => {
                assert!(pretty.contains('\n'), "should be pretty-printed: {pretty}");
                assert!(pretty.contains("\"nested\": true"));
            }
            other => panic!("expected OtherJson, got {other:?}"),
        }
    }

    #[test]
    fn classify_non_json_is_raw() {
        assert_eq!(
            classify_stdout(b"plain text output"),
            StdoutKind::Raw("plain text output".to_string())
        );
    }

    #[test]
    fn outcome_labels_disambiguate_exit_zero() {
        assert_eq!(outcome_label(0, &StdoutKind::Empty), "ALLOW");
        assert_eq!(outcome_label(0, &StdoutKind::Nudge("ctx".into())), "NUDGE");
        assert_eq!(
            outcome_label(0, &StdoutKind::LoopBlock("r".into())),
            "LOOP-BLOCK (re-prompt)"
        );
        assert_eq!(outcome_label(2, &StdoutKind::Empty), "BLOCK");
        assert_eq!(outcome_label(1, &StdoutKind::Empty), "ERROR (non-blocking)");
    }
}
