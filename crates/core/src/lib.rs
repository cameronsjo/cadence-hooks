//! Core protocol for Claude Code hooks.
//!
//! All hooks receive JSON on stdin describing the tool invocation
//! and exit with a status code:
//! - 0: allow / nudge (operation proceeds, stdout included in transcript)
//! - 2: block (operation prevented, stderr fed back to Claude)
//!
//! Run from an interactive terminal (stdin is a TTY) instead of a pipe, hook
//! entry points print usage guidance and exit 1 rather than blocking on a
//! read that would never see EOF.

pub mod config;
pub mod loop_analysis;
pub mod shell;

#[cfg(feature = "test-builders")]
pub mod test_builders;

use serde::Deserialize;
use std::io::{IsTerminal, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process;

/// The hook event type determines output format for nudges.
///
/// PreToolUse and PostToolUse use different JSON structures in the
/// Claude Code hook protocol. The event type must be passed to
/// [`run_check`] so nudge messages are formatted correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    /// PreToolUse — fires before a tool executes.
    PreToolUse,
    /// PostToolUse — fires after a tool executes.
    PostToolUse,
    /// SessionStart — fires when a session begins (startup/resume/clear/compact).
    /// Nudges inject context via `hookSpecificOutput.additionalContext`.
    SessionStart,
}

impl HookEvent {
    /// The event name as it appears in the Claude Code hook protocol
    /// (`hookEventName`, hooks.json matchers).
    pub fn name(&self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::SessionStart => "SessionStart",
        }
    }

    /// A minimal valid payload for this event, used by the interactive-terminal
    /// guidance and the `try` subcommand. Each sample must deserialize as
    /// [`HookInput`] — enforced by unit test.
    pub fn sample_payload(&self) -> &'static str {
        match self {
            HookEvent::PreToolUse => {
                r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#
            }
            HookEvent::PostToolUse => {
                r#"{"tool_name":"Edit","tool_input":{"file_path":"src/main.rs"},"tool_response":{"stdout":"ok"}}"#
            }
            HookEvent::SessionStart => r#"{"session_id":"test","source":"startup"}"#,
        }
    }
}

/// Exit codes matching Claude Code's hook contract.
///
/// Claude Code recognises two exit codes:
///   0 — success (stdout included in transcript)
///   2 — block  (stderr fed back to Claude, tool call prevented)
/// Any other code is a non-blocking error (stderr shown only in verbose mode).
///
/// `Nudge` exits 0 so its message lands in the transcript as context
/// without interrupting the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Operation allowed, no message.
    Allow,
    /// Operation allowed, contextual message shown in transcript (exit 0, stdout).
    Nudge,
    /// Operation blocked, error message shown (exit 2, stderr).
    Block,
    /// Re-prompt loop (exit 0). The tool already ran, so the write stands, but
    /// Claude Code's `{"decision":"block","reason":...}` convention feeds the
    /// reason back so the model self-corrects with a fresh write. Used by
    /// PostToolUse feedback loops (e.g. validate-then-rewrite gates) where a
    /// hard `Block` (exit 2) cannot un-run the tool.
    LoopBlock,
}

impl Outcome {
    pub fn code(self) -> i32 {
        match self {
            Outcome::Allow => 0,
            Outcome::Nudge => 0,
            Outcome::LoopBlock => 0,
            Outcome::Block => 2,
        }
    }

    /// Merge two outcomes, keeping the more severe one.
    pub fn merge(self, other: Outcome) -> Outcome {
        match (self, other) {
            (Outcome::Block, _) | (_, Outcome::Block) => Outcome::Block,
            (Outcome::LoopBlock, _) | (_, Outcome::LoopBlock) => Outcome::LoopBlock,
            (Outcome::Nudge, _) | (_, Outcome::Nudge) => Outcome::Nudge,
            _ => Outcome::Allow,
        }
    }
}

/// Normalize a file path for consistent matching:
/// - Replace backslashes with forward slashes (Windows compatibility)
/// - Strip null bytes (C string truncation attack prevention)
/// - Trim trailing slashes and whitespace
fn normalize_path(path: &str) -> String {
    let cleaned: String = path
        .replace('\\', "/")
        .replace('\0', "")
        .trim()
        .trim_end_matches('/')
        .to_string();
    cleaned
}

/// The JSON structure Claude Code sends to PreToolUse/PostToolUse hooks on stdin.
///
/// `session_id`, `source`, and `model` are top-level fields the `SessionStart`
/// payload carries (and which some PostToolUse payloads also include). They
/// deserialize to `None` when absent, so existing Pre/Post hooks are unaffected.
/// `Default` is derived so call sites can construct partial inputs via
/// `..Default::default()`.
#[derive(Debug, Default, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<ToolInput>,
    /// The tool response (stdout, stderr) from the tool execution.
    /// Available in PostToolUse hooks — absent in PreToolUse and SessionStart.
    pub tool_response: Option<ToolResponse>,
    pub cwd: Option<String>,
    /// Claude Code session id — present on `SessionStart`.
    pub session_id: Option<String>,
    /// `SessionStart` trigger: `startup` | `resume` | `clear` | `compact`.
    pub source: Option<String>,
    /// Model id for the session (e.g. `claude-opus-4-8`), when supplied.
    pub model: Option<String>,
}

/// Tool-specific fields from the hook input.
#[derive(Debug, Deserialize)]
pub struct ToolInput {
    pub file_path: Option<String>,
    pub path: Option<String>,
    pub command: Option<String>,
    pub content: Option<String>,
    pub new_string: Option<String>,
    pub old_string: Option<String>,
}

/// The tool response, available in PostToolUse hooks.
///
/// Claude Code sends the tool's stdout (and optionally stderr) back in the
/// hook payload so post-processing hooks can inspect the result without
/// re-running the command.
#[derive(Debug, Default, Deserialize)]
pub struct ToolResponse {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

impl HookInput {
    /// Read and parse hook input from stdin.
    pub fn from_stdin() -> Result<Self, String> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {e}"))?;
        serde_json::from_str(&buf).map_err(|e| format!("Failed to parse hook JSON: {e}"))
    }

    /// Resolved file path — checks file_path first, then path.
    /// Returns a normalized path (trimmed, slashes normalized, null bytes removed).
    pub fn file_path(&self) -> Option<String> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.file_path.as_deref().or(ti.path.as_deref()))
            .map(normalize_path)
    }

    /// The bash command, if this is a Bash tool invocation.
    pub fn command(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.command.as_deref())
    }

    /// The content being written (Write tool) or the replacement text (Edit tool).
    pub fn content(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.content.as_deref().or(ti.new_string.as_deref()))
    }

    /// The tool name (Write, Edit, Bash, etc.)
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// The Claude Code session id, if present (SessionStart and some payloads).
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The SessionStart trigger source (startup/resume/clear/compact), if present.
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// The session model id, if present.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The stdout from the tool response (PostToolUse only).
    pub fn tool_response_stdout(&self) -> Option<&str> {
        self.tool_response
            .as_ref()
            .and_then(|tr| tr.stdout.as_deref())
    }
}

/// The JSON Claude Code sends to fire-and-forget metrics loggers.
///
/// A superset of [`HookInput`]: it carries the session, transcript, and
/// subagent context that *logging* needs but *enforcement* does not. Every
/// field is optional — absent keys deserialize to `None`, mirroring the
/// `// null` defaults the bash hooks used. Reacts to `PreToolUse`,
/// `PostToolUse`, `SubagentStart`, and `SubagentStop`; the originating event
/// is read from `hook_event_name` rather than the static [`HookEvent`] enum.
#[derive(Debug, Default, Deserialize)]
pub struct MetricsInput {
    pub session_id: Option<String>,
    pub transcript_path: Option<String>,
    pub hook_event_name: Option<String>,
    pub cwd: Option<String>,
    pub tool_input: Option<ToolInput>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub parent_session_id: Option<String>,
    pub parent_agent_id: Option<String>,
    pub source_agent_id: Option<String>,
    pub duration_ms: Option<u64>,
    /// Top-level keys present in the raw payload. Populated by [`Self::from_json`],
    /// not deserialized — powers the `CADENCE_METRICS_DEBUG` `_keys` field that
    /// surfaces schema additions across Claude Code releases.
    #[serde(skip)]
    pub raw_keys: Vec<String>,
}

impl MetricsInput {
    /// Read and parse metrics input from stdin.
    pub fn from_stdin() -> Result<Self, String> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {e}"))?;
        Self::from_json(&buf)
    }

    /// Parse metrics input from a JSON string, capturing the raw top-level keys.
    pub fn from_json(s: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("Failed to parse hook JSON: {e}"))?;
        let mut input: MetricsInput = serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse hook JSON: {e}"))?;
        if let Some(obj) = value.as_object() {
            input.raw_keys = obj.keys().cloned().collect();
        }
        Ok(input)
    }

    /// The bash command, if this event carries a Bash tool invocation.
    pub fn command(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.command.as_deref())
    }
}

/// Result of running a single check.
pub struct CheckResult {
    pub outcome: Outcome,
    pub message: Option<String>,
}

impl CheckResult {
    pub fn allow() -> Self {
        Self {
            outcome: Outcome::Allow,
            message: None,
        }
    }

    pub fn nudge(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Nudge,
            message: Some(message.into()),
        }
    }

    pub fn block(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Block,
            message: Some(message.into()),
        }
    }

    /// Re-prompt loop result (exit 0). The message is fed back via Claude Code's
    /// `{"decision":"block","reason":...}` convention so the model rewrites.
    pub fn loop_block(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::LoopBlock,
            message: Some(message.into()),
        }
    }
}

/// A hook check that can be run against input.
pub trait Check {
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str;

    /// Run the check against the given input.
    fn run(&self, input: &HookInput) -> CheckResult;

    /// Effort levels at which this check should short-circuit to Allow
    /// without running. Reads `$CLAUDE_EFFORT` (set by Claude Code per
    /// dispatch; defaults to `"medium"` when unset).
    ///
    /// Empty (default) means "always run". Most cadence-hooks checks are
    /// security/correctness invariants and should run at every effort
    /// level — opt in here only when the check is genuinely optional at
    /// the listed levels.
    fn skip_at_effort(&self) -> &[&str] {
        &[]
    }
}

/// Pure: should `run_check` short-circuit for the given effort level?
///
/// `current` is `$CLAUDE_EFFORT` from the hook payload; `None` is
/// treated as `"medium"` (Claude Code's documented default).
fn should_skip_for_effort(skip_levels: &[&str], current: Option<&str>) -> bool {
    let effective = current.unwrap_or("medium");
    skip_levels.contains(&effective)
}

/// Run a single check, emit output, and exit.
///
/// Routing:
/// - `skip_at_effort()` matches `$CLAUDE_EFFORT` → silent Allow (exit 0),
///   `check.run()` is not called.
/// - Nudge → JSON to stdout with `additionalContext` (exit 0).
///   Claude Code parses this and injects the message into Claude's context.
///   The JSON format differs by event type (PreToolUse vs PostToolUse).
/// - Block → plain text to stderr (exit 2).
///   Claude Code feeds stderr back to Claude as an error.
/// - Allow → silent exit 0.
pub fn run_check(check: &dyn Check, input: &HookInput, event: HookEvent) -> ! {
    let current_effort = std::env::var("CLAUDE_EFFORT").ok();
    if should_skip_for_effort(check.skip_at_effort(), current_effort.as_deref()) {
        process::exit(Outcome::Allow.code());
    }

    let result = check.run(input);
    if let Some(msg) = &result.message {
        let event_name = event.name();
        match result.outcome {
            Outcome::Nudge => {
                let json = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "additionalContext": msg
                    }
                });
                println!("{json}");
            }
            Outcome::LoopBlock => {
                // PostToolUse re-prompt: the tool already ran, so exit 0 and use
                // the `decision: block` convention to feed the reason back. Also
                // mirror it into additionalContext for clients that read that.
                let json = serde_json::json!({
                    "decision": "block",
                    "reason": msg,
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "additionalContext": msg
                    }
                });
                println!("{json}");
            }
            Outcome::Block => {
                eprint!("{msg}");
                if !msg.ends_with('\n') {
                    eprintln!();
                }
            }
            Outcome::Allow => {}
        }
    }
    process::exit(result.outcome.code());
}

/// The generic fallback payload for fire-and-forget loggers ([`MetricsInput`]
/// shape). Must deserialize as [`MetricsInput`] — enforced by unit test.
///
/// This is a *fallback*: loggers react to `hook_event_name` in the payload and
/// each one cares about different events (e.g. `log-subagent` only reacts to
/// `SubagentStart`/`SubagentStop`). Per-hook sample overrides live in the
/// binary's registry (`registry::sample_for`) and are passed in via the
/// `sample_override` parameters below.
pub const LOGGER_SAMPLE_PAYLOAD: &str = r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_input":{"command":"git status"}}"#;

/// Build the guidance shown when a hook subcommand is run from an interactive
/// terminal (stdin is a TTY) instead of receiving piped JSON.
///
/// Without this, the stdin read blocks forever waiting for EOF the terminal
/// never sends — which reads as "the binary locked up."
///
/// `event` is `None` for loggers, which react to `hook_event_name` in the
/// payload rather than a fixed event. `sample_override` replaces the
/// event-derived sample when the caller knows a better payload for this
/// specific hook (from the binary's registry). `argv` is the process
/// invocation (`std::env::args()`), passed explicitly so the builder is
/// unit-testable.
pub fn interactive_terminal_help(
    hook_name: &str,
    event: Option<HookEvent>,
    sample_override: Option<&str>,
    argv: &[String],
) -> String {
    let subcommand_path = if argv.len() > 1 {
        argv[1..].join(" ")
    } else {
        hook_name.to_string()
    };
    let (fires_on, default_sample) = match event {
        Some(e) => (e.name(), e.sample_payload()),
        None => ("tool events", LOGGER_SAMPLE_PAYLOAD),
    };
    let sample = sample_override.unwrap_or(default_sample);
    format!(
        "cadence-hooks: '{hook_name}' is a Claude Code hook, not an interactive command.\n\
         \n\
         It reads a JSON payload on stdin — Claude Code pipes this automatically on\n\
         {fires_on}. Nothing was piped and stdin is a terminal, so it would wait forever.\n\
         \n\
         Quick test:\n\
         \n\
         \u{20} cadence-hooks try {subcommand_path}\n\
         \n\
         Or pipe a payload manually:\n\
         \n\
         \u{20} echo '{sample}' | cadence-hooks {subcommand_path}\n\
         \n\
         Explore:\n\
         \n\
         \u{20} cadence-hooks list      all hooks and what they do\n\
         \u{20} cadence-hooks doctor    audit installed plugin wiring\n"
    )
}

/// If stdin is an interactive terminal, print guidance and exit 1.
///
/// Exit 1 (not 0) so scripts see the hook did not run; never 2 — interactive
/// misuse is not a hook context, and a hook's own non-hook situation must
/// never block (ADR-0001). Invisible in production: Claude Code always pipes,
/// so `is_terminal()` is false there.
fn guard_interactive_terminal(
    hook_name: &str,
    event: Option<HookEvent>,
    sample_override: Option<&str>,
) {
    if std::io::stdin().is_terminal() {
        let argv: Vec<String> = std::env::args().collect();
        eprint!(
            "{}",
            interactive_terminal_help(hook_name, event, sample_override, &argv)
        );
        process::exit(1);
    }
}

/// Run a single check from stdin. Convenience wrapper for subcommands.
pub fn run_check_from_stdin(check: &dyn Check, event: HookEvent) -> ! {
    guard_interactive_terminal(check.name(), Some(event), None);
    match HookInput::from_stdin() {
        Ok(input) => run_check(check, &input, event),
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            process::exit(0); // Fail open on parse errors
        }
    }
}

/// A fire-and-forget metrics logger.
///
/// Unlike [`Check`], a `Logger` makes no allow/block decision — it performs a
/// side effect (append a JSONL line, write a state file) and never influences
/// the tool call that triggered it. There is no `CheckResult`: the contract is
/// "log if you can, otherwise do nothing."
pub trait Logger {
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str;

    /// Perform the logging side effect. Must not panic on bad input — degrade
    /// to a no-op instead, so a malformed payload never disrupts the session.
    fn run(&self, input: &MetricsInput);
}

/// Run a logger from stdin, then **always exit 0**.
///
/// Logging is fire-and-forget: a parse error, a missing field, or a failed
/// write must never block the operation that triggered the hook. This mirrors
/// the bash `|| true` discipline — loggers never emit exit 2, never block.
///
/// `sample_override` is the per-hook sample payload from the binary's registry
/// (`registry::sample_for`), shown in the interactive-terminal guidance.
/// Loggers react to different `hook_event_name` values, so the generic
/// [`LOGGER_SAMPLE_PAYLOAD`] fallback may exercise the wrong branch for a
/// specific logger.
pub fn run_logger_from_stdin(logger: &dyn Logger, sample_override: Option<&str>) -> ! {
    guard_interactive_terminal(logger.name(), None, sample_override);
    if let Ok(input) = MetricsInput::from_stdin() {
        // A panicking logger must not skip the exit-0 below. Catch the unwind so
        // the contract holds even on a buggy implementation. `AssertUnwindSafe`
        // is required because `&dyn Logger` is not `UnwindSafe`; we exit
        // immediately afterward, so there is no post-panic state to corrupt.
        let _ = catch_unwind(AssertUnwindSafe(|| logger.run(&input)));
    }
    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Outcome ---

    #[test]
    fn outcome_codes() {
        assert_eq!(Outcome::Allow.code(), 0);
        assert_eq!(Outcome::Nudge.code(), 0);
        assert_eq!(Outcome::LoopBlock.code(), 0);
        assert_eq!(Outcome::Block.code(), 2);
    }

    #[test]
    fn outcome_merge_loop_block_below_block_above_nudge() {
        assert_eq!(Outcome::LoopBlock.merge(Outcome::Nudge), Outcome::LoopBlock);
        assert_eq!(Outcome::Nudge.merge(Outcome::LoopBlock), Outcome::LoopBlock);
        assert_eq!(Outcome::Block.merge(Outcome::LoopBlock), Outcome::Block);
        assert_eq!(Outcome::LoopBlock.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::LoopBlock.merge(Outcome::Allow), Outcome::LoopBlock);
    }

    #[test]
    fn check_result_loop_block() {
        let r = CheckResult::loop_block("rewrite");
        assert_eq!(r.outcome, Outcome::LoopBlock);
        assert_eq!(r.message.as_deref(), Some("rewrite"));
    }

    #[test]
    fn session_start_fields_deserialize() {
        let json = r#"{"session_id":"s1","source":"startup","model":"claude-opus-4-8"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.session_id(), Some("s1"));
        assert_eq!(input.source(), Some("startup"));
        assert_eq!(input.model(), Some("claude-opus-4-8"));
    }

    #[test]
    fn session_fields_absent_are_none() {
        let input: HookInput = serde_json::from_str(r#"{"tool_name":"Write"}"#).unwrap();
        assert_eq!(input.session_id(), None);
        assert_eq!(input.source(), None);
        assert_eq!(input.model(), None);
    }

    #[test]
    fn outcome_merge_block_wins() {
        assert_eq!(Outcome::Block.merge(Outcome::Allow), Outcome::Block);
        assert_eq!(Outcome::Allow.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::Block.merge(Outcome::Nudge), Outcome::Block);
        assert_eq!(Outcome::Nudge.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::Block.merge(Outcome::Block), Outcome::Block);
    }

    #[test]
    fn outcome_merge_warn_over_allow() {
        assert_eq!(Outcome::Nudge.merge(Outcome::Allow), Outcome::Nudge);
        assert_eq!(Outcome::Allow.merge(Outcome::Nudge), Outcome::Nudge);
        assert_eq!(Outcome::Nudge.merge(Outcome::Nudge), Outcome::Nudge);
    }

    #[test]
    fn outcome_merge_allow_only_when_both_allow() {
        assert_eq!(Outcome::Allow.merge(Outcome::Allow), Outcome::Allow);
    }

    // --- HookInput accessors ---

    fn make_input(
        tool_name: Option<&str>,
        file_path: Option<&str>,
        path: Option<&str>,
        command: Option<&str>,
        content: Option<&str>,
        new_string: Option<&str>,
    ) -> HookInput {
        HookInput {
            tool_name: tool_name.map(String::from),
            tool_input: Some(ToolInput {
                file_path: file_path.map(String::from),
                path: path.map(String::from),
                command: command.map(String::from),
                content: content.map(String::from),
                new_string: new_string.map(String::from),
                old_string: None,
            }),
            cwd: None,
            ..Default::default()
        }
    }

    #[test]
    fn file_path_prefers_file_path_over_path() {
        let input = make_input(None, Some("/a.rs"), Some("/b.rs"), None, None, None);
        assert_eq!(input.file_path().as_deref(), Some("/a.rs"));
    }

    #[test]
    fn file_path_falls_back_to_path() {
        let input = make_input(None, None, Some("/b.rs"), None, None, None);
        assert_eq!(input.file_path().as_deref(), Some("/b.rs"));
    }

    #[test]
    fn file_path_none_when_both_absent() {
        let input = make_input(None, None, None, None, None, None);
        assert!(input.file_path().is_none());
    }

    #[test]
    fn file_path_none_when_no_tool_input() {
        let input = HookInput {
            tool_name: None,
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert!(input.file_path().is_none());
    }

    #[test]
    fn command_accessor() {
        let input = make_input(None, None, None, Some("git push"), None, None);
        assert_eq!(input.command(), Some("git push"));
    }

    #[test]
    fn command_none_when_absent() {
        let input = make_input(None, None, None, None, None, None);
        assert_eq!(input.command(), None);
    }

    #[test]
    fn content_prefers_content_over_new_string() {
        let input = make_input(None, None, None, None, Some("content"), Some("new_string"));
        assert_eq!(input.content(), Some("content"));
    }

    #[test]
    fn content_falls_back_to_new_string() {
        let input = make_input(None, None, None, None, None, Some("replacement"));
        assert_eq!(input.content(), Some("replacement"));
    }

    #[test]
    fn content_none_when_both_absent() {
        let input = make_input(None, None, None, None, None, None);
        assert_eq!(input.content(), None);
    }

    #[test]
    fn tool_name_accessor() {
        let input = make_input(Some("Bash"), None, None, None, None, None);
        assert_eq!(input.tool_name(), Some("Bash"));
    }

    #[test]
    fn tool_name_none_when_absent() {
        let input = HookInput {
            tool_name: None,
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(input.tool_name(), None);
    }

    // --- CheckResult constructors ---

    #[test]
    fn check_result_allow() {
        let r = CheckResult::allow();
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(r.message.is_none());
    }

    #[test]
    fn check_result_warn() {
        let r = CheckResult::nudge("caution");
        assert_eq!(r.outcome, Outcome::Nudge);
        assert_eq!(r.message.as_deref(), Some("caution"));
    }

    #[test]
    fn check_result_block() {
        let r = CheckResult::block("stopped");
        assert_eq!(r.outcome, Outcome::Block);
        assert_eq!(r.message.as_deref(), Some("stopped"));
    }

    #[test]
    fn check_result_accepts_string() {
        let r = CheckResult::nudge(String::from("owned"));
        assert_eq!(r.message.as_deref(), Some("owned"));
    }

    // --- JSON deserialization ---

    #[test]
    fn deserialize_full_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/a.rs","command":null}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name(), Some("Read"));
        assert_eq!(input.file_path().as_deref(), Some("/a.rs"));
    }

    #[test]
    fn deserialize_minimal_input() {
        let json = r#"{}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name(), None);
        assert!(input.file_path().is_none());
    }

    #[test]
    fn deserialize_bash_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.command(), Some("git status"));
    }

    // --- Path normalization ---

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(normalize_path("/project/.env/"), "/project/.env");
    }

    #[test]
    fn normalize_strips_trailing_whitespace() {
        assert_eq!(normalize_path("/project/.env "), "/project/.env");
    }

    #[test]
    fn normalize_strips_leading_whitespace() {
        assert_eq!(normalize_path("  /project/.env"), "/project/.env");
    }

    #[test]
    fn normalize_strips_null_bytes() {
        assert_eq!(normalize_path("/project/.env\0.txt"), "/project/.env.txt");
    }

    #[test]
    fn normalize_converts_backslashes() {
        assert_eq!(normalize_path(r"C:\Users\dev\.env"), "C:/Users/dev/.env");
    }

    #[test]
    fn normalize_combined_attack() {
        assert_eq!(normalize_path(" /project/.env\0/ "), "/project/.env");
    }

    #[test]
    fn normalize_preserves_clean_path() {
        assert_eq!(
            normalize_path("/project/src/main.rs"),
            "/project/src/main.rs"
        );
    }

    #[test]
    fn file_path_normalizes_trailing_slash() {
        let input = make_input(None, Some("/project/.env/"), None, None, None, None);
        assert_eq!(input.file_path().as_deref(), Some("/project/.env"));
    }

    #[test]
    fn file_path_normalizes_backslash() {
        let input = make_input(None, Some(r"C:\Users\.env"), None, None, None, None);
        assert_eq!(input.file_path().as_deref(), Some("C:/Users/.env"));
    }

    // --- effort gating ---

    #[test]
    fn effort_skip_empty_list_runs_at_every_level() {
        assert!(!should_skip_for_effort(&[], Some("low")));
        assert!(!should_skip_for_effort(&[], Some("medium")));
        assert!(!should_skip_for_effort(&[], Some("high")));
        assert!(!should_skip_for_effort(&[], None));
    }

    #[test]
    fn effort_skip_matches_current_level() {
        assert!(should_skip_for_effort(&["low"], Some("low")));
        assert!(should_skip_for_effort(&["low", "medium"], Some("medium")));
        assert!(should_skip_for_effort(&["high", "xhigh"], Some("xhigh")));
    }

    #[test]
    fn effort_skip_does_not_match_other_levels() {
        assert!(!should_skip_for_effort(&["low"], Some("medium")));
        assert!(!should_skip_for_effort(&["low"], Some("high")));
        assert!(!should_skip_for_effort(&["high"], Some("low")));
    }

    #[test]
    fn effort_skip_unset_treats_as_medium() {
        // Claude Code's documented default is "medium" when the field is
        // absent from the payload, so the env var being unset should be
        // equivalent to medium.
        assert!(should_skip_for_effort(&["medium"], None));
        assert!(!should_skip_for_effort(&["low"], None));
        assert!(!should_skip_for_effort(&["high"], None));
    }

    #[test]
    fn check_trait_default_skip_at_effort_is_empty() {
        struct Stub;
        impl Check for Stub {
            fn name(&self) -> &str {
                "stub"
            }
            fn run(&self, _input: &HookInput) -> CheckResult {
                CheckResult::allow()
            }
        }
        assert!(Stub.skip_at_effort().is_empty());
    }

    #[test]
    fn check_trait_skip_at_effort_overridable() {
        struct LowSkip;
        impl Check for LowSkip {
            fn name(&self) -> &str {
                "low-skip"
            }
            fn run(&self, _input: &HookInput) -> CheckResult {
                CheckResult::allow()
            }
            fn skip_at_effort(&self) -> &[&str] {
                &["low"]
            }
        }
        assert_eq!(LowSkip.skip_at_effort(), &["low"]);
    }

    // --- MetricsInput ---

    #[test]
    fn metrics_input_parses_full_payload() {
        let json = r#"{
            "session_id": "s1",
            "transcript_path": "/tmp/t.jsonl",
            "hook_event_name": "PostToolUse",
            "cwd": "/repo",
            "tool_input": {"command": "git commit -m x"},
            "agent_id": "a1",
            "agent_type": "Explore",
            "parent_session_id": "ps1",
            "parent_agent_id": "pa1",
            "source_agent_id": "src1",
            "duration_ms": 1234
        }"#;
        let input = MetricsInput::from_json(json).unwrap();
        assert_eq!(input.session_id.as_deref(), Some("s1"));
        assert_eq!(input.hook_event_name.as_deref(), Some("PostToolUse"));
        assert_eq!(input.command(), Some("git commit -m x"));
        assert_eq!(input.agent_type.as_deref(), Some("Explore"));
        assert_eq!(input.duration_ms, Some(1234));
    }

    #[test]
    fn metrics_input_absent_fields_are_none() {
        let input = MetricsInput::from_json(r#"{"session_id": "s1"}"#).unwrap();
        assert_eq!(input.session_id.as_deref(), Some("s1"));
        assert_eq!(input.transcript_path, None);
        assert_eq!(input.agent_id, None);
        assert_eq!(input.duration_ms, None);
        assert_eq!(input.command(), None);
    }

    #[test]
    fn metrics_input_captures_raw_keys() {
        let input = MetricsInput::from_json(r#"{"session_id": "s1", "novel_field": 7}"#).unwrap();
        assert!(input.raw_keys.contains(&"session_id".to_string()));
        assert!(input.raw_keys.contains(&"novel_field".to_string()));
    }

    #[test]
    fn metrics_input_rejects_malformed_json() {
        assert!(MetricsInput::from_json("not json").is_err());
    }

    // --- Interactive terminal guidance ---

    #[test]
    fn event_names_match_protocol() {
        assert_eq!(HookEvent::PreToolUse.name(), "PreToolUse");
        assert_eq!(HookEvent::PostToolUse.name(), "PostToolUse");
        assert_eq!(HookEvent::SessionStart.name(), "SessionStart");
    }

    #[test]
    fn sample_payloads_parse_as_hook_input() {
        for event in [
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
            HookEvent::SessionStart,
        ] {
            let parsed: Result<HookInput, _> = serde_json::from_str(event.sample_payload());
            assert!(
                parsed.is_ok(),
                "sample for {} must deserialize as HookInput: {:?}",
                event.name(),
                parsed.err()
            );
        }
    }

    #[test]
    fn pre_tool_use_sample_carries_a_command() {
        let input: HookInput =
            serde_json::from_str(HookEvent::PreToolUse.sample_payload()).unwrap();
        assert!(input.command().is_some());
    }

    #[test]
    fn logger_sample_payload_parses_as_metrics_input() {
        let parsed = MetricsInput::from_json(LOGGER_SAMPLE_PAYLOAD);
        assert!(parsed.is_ok(), "{:?}", parsed.err());
        assert_eq!(
            parsed.unwrap().hook_event_name.as_deref(),
            Some("PostToolUse")
        );
    }

    #[test]
    fn interactive_help_names_hook_event_and_commands() {
        let argv: Vec<String> = ["cadence-hooks", "lab", "persona-nudge"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let msg =
            interactive_terminal_help("persona-nudge", Some(HookEvent::SessionStart), None, &argv);
        assert!(msg.contains("'persona-nudge'"));
        assert!(msg.contains("SessionStart"));
        assert!(msg.contains("cadence-hooks try lab persona-nudge"));
        assert!(msg.contains("| cadence-hooks lab persona-nudge"));
        assert!(msg.contains(HookEvent::SessionStart.sample_payload()));
        assert!(msg.contains("cadence-hooks list"));
        assert!(msg.contains("cadence-hooks doctor"));
    }

    #[test]
    fn interactive_help_for_logger_uses_metrics_sample() {
        let argv: Vec<String> = ["cadence-hooks", "metrics", "snapshot"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let msg = interactive_terminal_help("snapshot", None, None, &argv);
        assert!(msg.contains("tool events"));
        assert!(msg.contains(LOGGER_SAMPLE_PAYLOAD));
        assert!(msg.contains("cadence-hooks try metrics snapshot"));
    }

    #[test]
    fn interactive_help_sample_override_replaces_default() {
        let argv: Vec<String> = ["cadence-hooks", "metrics", "log-subagent"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let override_sample = r#"{"hook_event_name":"SubagentStop","agent_id":"a1"}"#;
        let msg = interactive_terminal_help("log-subagent", None, Some(override_sample), &argv);
        assert!(
            msg.contains(override_sample),
            "override sample should appear: {msg}"
        );
        assert!(
            !msg.contains(LOGGER_SAMPLE_PAYLOAD),
            "generic fallback should be replaced: {msg}"
        );
    }

    #[test]
    fn interactive_help_falls_back_to_hook_name_without_argv() {
        let msg = interactive_terminal_help("terminology", Some(HookEvent::PreToolUse), None, &[]);
        assert!(msg.contains("cadence-hooks try terminology"));
        assert!(msg.contains("| cadence-hooks terminology"));
    }
}
