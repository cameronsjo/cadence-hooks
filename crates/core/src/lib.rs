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

pub mod branch_diff;
pub mod config;
pub mod deadline;
pub mod display;
pub mod gitstate;
pub mod loop_analysis;
pub mod markers;
pub mod patch;
pub mod pathclass;
pub mod paths;
pub mod shell;
pub mod time;
pub mod transcript;
pub mod worktree;

// Also compiled for this crate's own `#[cfg(test)]` modules, which share the
// marker-dir env helper it carries — one global, one lock, one helper (#446).
#[cfg(any(test, feature = "test-builders"))]
pub mod test_builders;

// Git-fixture builders (a `target/`-rooted `Scratch` plus `git_in`/`init_repo`)
// live separately from `test_builders`'s `HookInput` builders — the two have
// nothing in common beyond both being test-only, and folding fixtures that
// spawn `git` subprocesses into the `HookInput`-builder module would make
// every consumer of `make_bash`/`make_edit` compile that code too.
#[cfg(any(test, feature = "test-builders"))]
pub mod git_fixtures;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// UserPromptSubmit — fires when the user (or the harness, on an
    /// approve-and-clear plan re-injection) submits a prompt. Nudges inject
    /// context via `hookSpecificOutput.additionalContext`, same as SessionStart.
    UserPromptSubmit,
}

impl HookEvent {
    /// The event name as it appears in the Claude Code hook protocol
    /// (`hookEventName`, hooks.json matchers).
    pub fn name(&self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::SessionStart => "SessionStart",
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
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
            HookEvent::UserPromptSubmit => r#"{"prompt":"test prompt"}"#,
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
    /// Surface the interactive permission prompt (exit 0). Emits a PreToolUse
    /// `permissionDecision: "ask"` envelope on stdout. Per Claude Code's
    /// precedence (`deny` > `defer` > `ask` > `allow`, most-restrictive-wins),
    /// an `ask` decision prompts the user *even when a settings `allow` rule
    /// would otherwise auto-approve* — so a guard can force a confirmation on an
    /// operation it can neither prove safe (Allow) nor prove dangerous (Block).
    /// PreToolUse only; never emitted by a PostToolUse hook.
    Ask,
}

impl Outcome {
    pub fn code(self) -> i32 {
        match self {
            Outcome::Allow => 0,
            Outcome::Nudge => 0,
            Outcome::Ask => 0,
            Outcome::Block => 2,
        }
    }

    /// Merge two outcomes, keeping the more severe one.
    ///
    /// Severity, most-to-least: `Block` > `Ask` > `Nudge` > `Allow`. `Ask`
    /// outranks `Nudge` (a prompt is a stronger intervention than a silent
    /// context line) but yields to `Block`.
    pub fn merge(self, other: Outcome) -> Outcome {
        match (self, other) {
            (Outcome::Block, _) | (_, Outcome::Block) => Outcome::Block,
            (Outcome::Ask, _) | (_, Outcome::Ask) => Outcome::Ask,
            (Outcome::Nudge, _) | (_, Outcome::Nudge) => Outcome::Nudge,
            _ => Outcome::Allow,
        }
    }
}

/// Set once this process parses a payload only the Codex harness produces.
/// See [`is_codex_payload_shape`] for the sniff and [`is_codex_harness`] for why
/// it exists.
static CODEX_PAYLOAD_SEEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Tool names no Claude Code build sends and every Codex build does.
///
/// `spawn_agents_on_csv`/`multi_agents` are deliberately absent: they alias to
/// `Agent` like `spawn_agent` does, but they are variant spellings this repo has
/// not measured, and a sniff list is a place to be conservative rather than
/// exhaustive — a name that turns out to exist on some other harness would start
/// applying Codex strictness there.
const CODEX_ONLY_TOOLS: &[&str] = &["apply_patch", "exec_command", "unified_exec", "spawn_agent"];

/// Does this raw payload carry a shape only Codex produces?
///
/// Two signals, OR'd: a [`CODEX_ONLY_TOOLS`] tool name, or a string-valued
/// `tool_input` (Codex's freeform-body form; Claude Code sends an object).
///
/// Pure, and public so the rule is testable without mutating process state.
#[must_use]
pub fn is_codex_payload_shape(value: &serde_json::Value) -> bool {
    let codex_only_tool = value
        .get("tool_name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|name| CODEX_ONLY_TOOLS.contains(&name));
    let freeform_tool_input = value
        .get("tool_input")
        .is_some_and(serde_json::Value::is_string);
    codex_only_tool || freeform_tool_input
}

/// Whether this process is running under the Codex harness.
///
/// The single source of truth for the harness question. Security behaviour keys
/// off this (fail-closed parse denial, the `Ask` → `Block` conversion) and so
/// does metrics tagging, so all callers must agree — a site that compared
/// case-sensitively while another compared case-insensitively would fail **open**
/// on `CADENCE_HARNESS=Codex` at exactly the moment metrics recorded the run as
/// Codex.
///
/// Two independent signals, OR'd:
///
/// 1. `CADENCE_HARNESS` — set by the Codex wrapper. Matching is case-insensitive:
///    the value is set by shell wrappers, and a harness that announces itself at
///    all should be honoured however it cased it.
/// 2. A Codex-shaped payload already parsed by this process
///    ([`is_codex_payload_shape`]).
///
/// The second exists because the *normalization* is unconditional while the
/// *hardening* was conditional, which is the worst-shaped failure available: on a
/// Codex session where the wrapper did not export the variable, payloads still
/// normalize and guards still fire, so the integration looks healthy — while a
/// malformed payload on a security-critical hook exits 0 instead of 2, and a
/// guard returning `Ask` exits 0 with an envelope Codex cannot render, so the
/// operation proceeds unconfirmed. The wrapper does export it today; this is the
/// belt to that suspenders, and it is derivable from data the normalizer already
/// inspects.
///
/// **The sniff can only ever ADD strictness, never subtract it.** Both directions
/// were checked rather than assumed:
///
/// - A false *positive* under Claude Code costs nothing reachable. The only
///   `Outcome::Ask` producer in the tree is `guard-rm`, and both of its routes
///   need an object `tool_input` (a `command`, or a `file_path` plus
///   `operation: "delete"`); a string-valued `tool_input` degrades to `None`, so
///   such a payload returns Allow and there is no Ask to convert to a Block. The
///   fail-closed parse arm is likewise unreachable — if stdin failed to parse,
///   no payload was sniffed.
/// - A false *negative* leaves exactly today's behaviour: the env check alone.
///
/// Spoofing is safe in the same direction: an attacker-set
/// `CADENCE_HARNESS=codex`, or a payload crafted to look Codex-shaped, only makes
/// this binary stricter. The danger was always *absence*.
#[must_use]
pub fn is_codex_harness() -> bool {
    is_codex_harness_value(std::env::var("CADENCE_HARNESS").ok().as_deref())
        || CODEX_PAYLOAD_SEEN.load(std::sync::atomic::Ordering::Relaxed)
}

/// Pure resolver behind [`is_codex_harness`], so the matching rule is testable
/// without mutating process environment shared by every parallel test.
#[must_use]
pub fn is_codex_harness_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("codex"))
}

/// Normalize a file path for consistent matching:
/// - Replace backslashes with forward slashes (Windows compatibility)
/// - Strip null bytes (C string truncation attack prevention)
/// - Trim trailing slashes and whitespace
///
/// Exposed so guards that compare an env-sourced path (e.g. an Obsidian vault
/// root) against hook-supplied paths can normalize **both sides** before a
/// string prefix test — otherwise a `C:\vault` env value never matches a
/// `C:/vault` hook path on Windows.
pub fn normalize_path(path: &str) -> String {
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
#[derive(Debug, Default, Clone, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    /// The harness-neutral view of [`Self::tool_name`], derived at parse time by
    /// [`Self::from_json`] — never deserialized from the payload.
    ///
    /// A Codex `exec_command` and a Claude `Bash` are the same operation as far
    /// as a guard is concerned, and so are `mcp__filesystem__write_file` and
    /// `Write`. Guards that gate on *what the operation does* read this via
    /// [`Self::normalized_tool_name`]; guards that gate on *which tool the
    /// harness actually named* keep reading [`Self::tool_name`].
    ///
    /// Kept as a SEPARATE field rather than overwriting `tool_name`, because
    /// overwriting silently unhooked `guard-browser-device`: it matches
    /// `mcp__claude-in-chrome__*`, and four of those names (`read_page`,
    /// `read_console_messages`, `read_network_requests`, `tabs_create_mcp`)
    /// classify as `Read`/`Write`, so the rewritten name no longer matched the
    /// prefix and the first browser action of a session ran against an
    /// unconfirmed device. Preserving the literal name is the durable shape:
    /// it holds even if Codex later grows a Claude-in-Chrome route, which a
    /// harness gate on the rewrite would not.
    ///
    /// `#[serde(skip)]` is load-bearing. This field steers enforcement, so a
    /// payload must not be able to supply it — a hand-set `"normalized_tool":
    /// "Read"` on a write payload would talk every content guard out of
    /// scanning. It is derived, or it is `None`.
    #[serde(skip)]
    pub normalized_tool: Option<String>,
    #[serde(default, deserialize_with = "lenient_option")]
    pub tool_input: Option<ToolInput>,
    /// The tool response (stdout, stderr) from the tool execution.
    /// Available in PostToolUse hooks — absent in PreToolUse and SessionStart.
    /// Shape varies by tool; a mismatch degrades to `None` (see `lenient_option`).
    #[serde(default, deserialize_with = "lenient_option")]
    pub tool_response: Option<ToolResponse>,
    pub cwd: Option<String>,
    /// Absolute path to the session transcript (`.jsonl`). A documented common
    /// field present on every hook event — PreToolUse included — so a guard can
    /// scan what already happened this session (e.g. did `/polish` run before
    /// this `gh pr create`?). Deserializes to `None` when absent, so existing
    /// hooks are unaffected.
    pub transcript_path: Option<String>,
    /// Claude Code session id — present on `SessionStart`.
    pub session_id: Option<String>,
    /// `SessionStart` trigger: `startup` | `resume` | `clear` | `compact`.
    pub source: Option<String>,
    /// Model id for the session (e.g. `claude-opus-4-8`), when supplied.
    pub model: Option<String>,
    /// Subagent id for a dispatched agent, when the payload carries it. Mirrors
    /// [`MetricsInput::agent_id`]; deserializes to `None` on the main thread and
    /// on payloads that omit it. Carried so the denial audit log can attribute a
    /// guard fire to the subagent that triggered it.
    pub agent_id: Option<String>,
    /// The submitted prompt text — present on `UserPromptSubmit`, absent on
    /// every other event. Deserializes to `None` when absent, so existing
    /// PreToolUse/PostToolUse/SessionStart hooks are unaffected.
    pub prompt: Option<String>,
}

/// Tool-specific fields from the hook input.
///
/// `Serialize` is derived so the dedupe gate can fingerprint a whole tool
/// payload rather than a hand-maintained field list — a modeled field added
/// here is then part of the key for free, and [`Self::extra`] covers the
/// unmodeled rest.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ToolInput {
    pub file_path: Option<String>,
    pub path: Option<String>,
    #[serde(alias = "sourcePath", alias = "from")]
    pub source: Option<String>,
    #[serde(alias = "destinationPath", alias = "to")]
    pub destination: Option<String>,
    pub command: Option<String>,
    /// Codex unified-exec/function form; normalized to `command` at parse time.
    pub cmd: Option<String>,
    /// Codex `apply_patch` freeform body; expanded into per-target HookInputs
    /// by [`HookInput::normalized_inputs`].
    pub patch: Option<String>,
    /// Harness-neutral operation kind for adapters that need deletion or
    /// rename semantics beyond the legacy Write/Edit tool name.
    pub operation: Option<String>,
    pub content: Option<String>,
    pub new_string: Option<String>,
    pub old_string: Option<String>,
    /// Edit tool: replace every occurrence of `old_string` (default: first only).
    pub replace_all: Option<bool>,
    /// MultiEdit tool: sequence of edit operations applied in order.
    pub edits: Option<Vec<EditOperation>>,
    /// AskUserQuestion tool: the questions being asked, each with its options.
    pub questions: Option<Vec<AskQuestion>>,
    /// Agent/Task tool: which subagent type the dispatch spawns. Absent for a
    /// fork-yourself dispatch (`subagent_type` omitted). Carried for diagnostics
    /// only — guards do not branch on the value.
    pub subagent_type: Option<String>,
    /// Agent/Task tool: isolation mode for the spawned subagent. `Some("worktree")`
    /// means the spawn gets a fresh agent-owned worktree; absent means the
    /// subagent inherits the spawning session's working directory.
    pub isolation: Option<String>,
    /// Skill tool: the invoked skill id (e.g. `cadence:attune`).
    pub skill: Option<String>,
    /// Skill tool: the skill's argument string. NEVER logged raw — only a
    /// non-reversible hash of it is recorded (see `log_skill`).
    pub args: Option<String>,
    /// ExitPlanMode tool: the plan's markdown body as carried on the CALL
    /// side. The current harness fills this at call time (live-verified
    /// 2026-08-11, claude-code 2.1.227 — cadence-hooks#672), where the
    /// 2.1.220-era probe found it EMPTY with the plan only in
    /// `tool_response.plan`. Both sources stay modeled; consumers try the
    /// response first (the historically reliable field), then this.
    pub plan: Option<String>,
    /// ExitPlanMode tool: path to the harness's own plan-store copy
    /// (`~/.claude/plans/<slug>.md`), carried on the call side alongside
    /// `plan` (cadence-hooks#672). Last-resort plan source when both inline
    /// fields are absent.
    #[serde(rename = "planFilePath")]
    pub plan_file_path: Option<String>,
    /// Every `tool_input` key this struct does not model, captured verbatim.
    ///
    /// Guards never read it. It exists so a *whole-payload* fingerprint — the
    /// dedupe gate's key (`markers::claim_tool_event_nudge`) — cannot collapse
    /// two genuinely different tool calls that happen to differ only in a field
    /// the parser has not modeled yet. `BTreeMap` (not `HashMap`) because that
    /// key must be byte-stable across the separate hook processes of one
    /// fan-out, and only an ordered map serializes deterministically.
    ///
    /// NEVER logged, and never a guard input: an attacker-supplied key here
    /// would otherwise be a free channel into whatever read it.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// A single edit operation within a MultiEdit tool call.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct EditOperation {
    pub old_string: Option<String>,
    pub new_string: Option<String>,
    pub replace_all: Option<bool>,
}

/// A single AskUserQuestion question and its answer options.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AskQuestion {
    pub question: Option<String>,
    pub header: Option<String>,
    pub multi_select: Option<bool>,
    pub options: Option<Vec<AskOption>>,
}

/// A single answer option within an AskUserQuestion question.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct AskOption {
    pub label: Option<String>,
    pub description: Option<String>,
}

/// Apply a single old→new replacement to a document.
fn apply_edit(doc: &str, old: &str, new: &str, replace_all: bool) -> String {
    if replace_all {
        doc.replace(old, new)
    } else {
        doc.replacen(old, new, 1)
    }
}

/// The tool response, available in PostToolUse hooks.
///
/// Claude Code sends the tool's stdout (and optionally stderr) back in the
/// hook payload so post-processing hooks can inspect the result without
/// re-running the command.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ToolResponse {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// AskUserQuestion tool: answers keyed by question text. Values are strings
    /// (multiSelect = comma-joined) or null when unanswered. Present only on the
    /// PostToolUse payload for AskUserQuestion.
    pub answers: Option<HashMap<String, serde_json::Value>>,
    /// ExitPlanMode tool: the approved plan's full markdown body. Present on
    /// same-session plan approval (`PostToolUse:ExitPlanMode`) — live-verified
    /// 2026-07-25 (cadence-hooks#396) that on this path `tool_input.plan` is
    /// EMPTY and this is the only field carrying the plan text.
    pub plan: Option<String>,
    /// ExitPlanMode tool: the app's own plans-store copy path, when the client
    /// wrote one. Carried for parity with the documented payload shape; not
    /// consulted by any check today.
    #[serde(rename = "filePath")]
    pub file_path: Option<String>,
    /// ExitPlanMode tool: true when the approving turn ran inside a subagent
    /// rather than the top-level session. `persist-plan-approval` skips these —
    /// only a top-level session's own approval persists a plan doc.
    #[serde(rename = "isAgent")]
    pub is_agent: Option<bool>,
    /// ExitPlanMode tool: true when the approving turn's tool set included the
    /// Agent/Task tool. Carried for parity with the documented payload shape;
    /// not consulted by any check today.
    #[serde(rename = "hasTaskTool")]
    pub has_task_tool: Option<bool>,
}

/// Deserialize an optional typed field leniently: a present value whose JSON
/// shape does not match `T` degrades to `None` instead of failing the entire
/// payload parse. Claude Code's `tool_input`/`tool_response` shapes vary by
/// tool — a plain string for `Read`, an array for `Glob`, a Bash-style object
/// for `Bash` — and one mismatched field must not blind an enforcement guard or
/// silently drop a metrics row for the rest of the payload (cadence-hooks#356).
///
/// The degradation is **deliberately silent**: the common case is expected
/// per-tool variance, and logging it would reintroduce the ~242/week failopen
/// noise this fix removes (it fires on every non-Bash tool call). The tradeoff
/// is that a *genuine* future schema drift in these fields also degrades
/// unobserved; distinguishing expected variance from real drift (log only an
/// object whose typed fields mismatch, not a non-object shape) is tracked in
/// cadence-hooks#364.
fn lenient_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

/// Resolve every supported `apply_patch` body envelope without letting one
/// recognized field shadow another. `patch` is the already-normalized internal
/// form; retaining it here preserves existing compatibility while subjecting it
/// to the same conflict check as external harness envelopes.
fn resolve_apply_patch_body(value: &serde_json::Value) -> Result<Option<&str>, &'static str> {
    let tool_input = value.get("tool_input");
    let candidates = [
        tool_input.and_then(serde_json::Value::as_str),
        tool_input
            .and_then(|input| input.get("command"))
            .and_then(serde_json::Value::as_str),
        tool_input
            .and_then(|input| input.get("input"))
            .and_then(serde_json::Value::as_str),
        tool_input
            .and_then(|input| input.get("patch"))
            .and_then(serde_json::Value::as_str),
        value.get("input").and_then(serde_json::Value::as_str),
    ];
    let mut candidates = candidates.into_iter().flatten();
    let Some(first) = candidates.next() else {
        return Ok(None);
    };
    if candidates.any(|candidate| candidate != first) {
        return Err("apply_patch payload contains conflicting patch bodies");
    }
    Ok(Some(first))
}

impl HookInput {
    /// Read and parse hook input from stdin.
    pub fn from_stdin() -> Result<Self, String> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {e}"))?;
        Self::from_json(&buf)
    }

    /// Parse a Claude or Codex hook payload and normalize harness aliases.
    ///
    /// Raw inputs are never retained beyond this value. In particular, a patch
    /// body is parsed in memory and is not included in parse diagnostics.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let mut value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("Failed to parse hook JSON: {e}"))?;
        // Sniffed on the RAW value, before the `apply_patch` rewrite below turns
        // a string `tool_input` into an object and erases the second signal.
        if is_codex_payload_shape(&value) {
            CODEX_PAYLOAD_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let tool_name = value
            .get("tool_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if tool_name == "apply_patch" {
            let patch = resolve_apply_patch_body(&value)
                .map_err(str::to_string)?
                .map(str::to_string);
            if let Some(patch) = patch {
                value["tool_input"] = serde_json::json!({"patch": patch});
            }
        }
        let mut input: HookInput =
            serde_json::from_value(value).map_err(|e| format!("Failed to parse hook JSON: {e}"))?;
        if let Some(tool_input) = input.tool_input.as_mut()
            && tool_input.command.is_none()
        {
            tool_input.command = tool_input.cmd.take();
        }
        // Every alias below writes `normalized_tool`, never `tool_name` — see
        // that field's doc comment for why the literal name has to survive.
        if matches!(
            input.tool_name.as_deref(),
            Some("exec_command" | "unified_exec" | "shell")
        ) {
            input.normalized_tool = Some("Bash".to_string());
        }
        if matches!(
            input.tool_name.as_deref(),
            Some("spawn_agent" | "spawn_agents_on_csv" | "multi_agents")
        ) {
            input.normalized_tool = Some("Agent".to_string());
        }
        if let Some(name) = input.tool_name.as_deref()
            && name.starts_with("mcp__")
        {
            let lower = name.to_ascii_lowercase();
            let operation = if lower.contains("delete") || lower.contains("remove") {
                Some(("Edit", "delete"))
            } else if lower.contains("write") || lower.contains("create") {
                Some(("Write", "create"))
            } else if lower.contains("edit") || lower.contains("update") {
                Some(("Edit", "update"))
            } else if lower.contains("move") || lower.contains("rename") {
                Some(("Edit", "rename"))
            } else if lower.contains("read")
                || lower.contains("get_file")
                || lower.contains("fetch_file")
                || lower.contains("load_file")
            {
                Some(("Read", "read"))
            } else if lower.contains("grep")
                || lower.contains("search")
                || lower.contains("find_file")
            {
                Some(("Grep", "search"))
            } else {
                None
            };
            if let Some((tool, operation)) = operation {
                input.normalized_tool = Some(tool.to_string());
                if let Some(tool_input) = input.tool_input.as_mut() {
                    tool_input.operation = Some(operation.to_string());
                }
            }
        }
        Ok(input)
    }

    /// Expand a Codex `apply_patch` payload into one Claude-shaped input per
    /// target operation. Non-patch payloads return a single clone.
    pub fn normalized_inputs(&self) -> Result<Vec<Self>, String> {
        if self.tool_name() != Some("apply_patch") {
            if self.operation() == Some("rename")
                && let Some(tool_input) = self.tool_input.as_ref()
                && let (Some(source), Some(destination)) =
                    (tool_input.source.clone(), tool_input.destination.clone())
            {
                return Ok(vec![
                    self.file_operation("Edit", "rename-source", source, None, None),
                    self.file_operation(
                        "Write",
                        "rename-destination",
                        destination,
                        None,
                        tool_input.content.clone(),
                    ),
                ]);
            }
            return Ok(vec![self.clone()]);
        }
        let patch = self
            .tool_input
            .as_ref()
            .and_then(|tool_input| tool_input.patch.as_deref())
            .ok_or_else(|| "apply_patch payload omitted patch body".to_string())?;
        let operations =
            patch::parse(patch).map_err(|error| format!("apply_patch schema rejected: {error}"))?;
        let mut inputs = Vec::new();
        for operation in operations {
            match operation {
                patch::Operation::Create { path, content } => {
                    inputs.push(self.file_operation("Write", "create", path, None, Some(content)));
                }
                patch::Operation::Update {
                    path,
                    old,
                    new,
                    move_to,
                } => {
                    let operation = if move_to.is_some() {
                        "rename-source"
                    } else {
                        "update"
                    };
                    inputs.push(self.file_operation(
                        "Edit",
                        operation,
                        path.clone(),
                        old,
                        new.clone(),
                    ));
                    if let Some(destination) = move_to {
                        inputs.push(self.file_operation(
                            "Write",
                            "rename-destination",
                            destination,
                            None,
                            new,
                        ));
                    }
                }
                patch::Operation::Delete { path } => {
                    inputs.push(self.file_operation(
                        "Edit",
                        "delete",
                        path,
                        None,
                        Some(String::new()),
                    ));
                }
            }
        }
        if inputs.is_empty() {
            return Err("apply_patch contained no file operations".to_string());
        }
        Ok(inputs)
    }

    fn file_operation(
        &self,
        tool_name: &str,
        operation: &str,
        path: String,
        old: Option<String>,
        new: Option<String>,
    ) -> Self {
        let mut result = self.clone();
        // The synthesized per-target view is a *normalized* one — the literal
        // harness tool is still `apply_patch` (or the MCP rename tool), and the
        // denial ledger records that rather than a shape this binary invented.
        result.normalized_tool = Some(tool_name.to_string());
        result.tool_input = Some(ToolInput {
            file_path: Some(path),
            operation: Some(operation.to_string()),
            old_string: old,
            new_string: if tool_name == "Edit" {
                new.clone()
            } else {
                None
            },
            content: if tool_name == "Write" { new } else { None },
            ..ToolInput::default()
        });
        result
    }

    /// Resolved file path — checks file_path first, then path.
    /// Returns a normalized path (trimmed, slashes normalized, null bytes removed).
    pub fn file_path(&self) -> Option<String> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.file_path.as_deref().or(ti.path.as_deref()))
            .map(normalize_path)
    }

    /// Harness-neutral operation kind supplied by Codex adapters.
    pub fn operation(&self) -> Option<&str> {
        self.tool_input.as_ref()?.operation.as_deref()
    }

    /// The bash command, if this is a Bash tool invocation.
    pub fn command(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.command.as_deref())
    }

    /// The subagent isolation mode for an Agent/Task spawn, if set.
    ///
    /// `Some("worktree")` means the spawn already gets a fresh agent-owned
    /// worktree (so it is confined); `None` means the subagent inherits the
    /// spawning session's working directory.
    pub fn isolation(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.isolation.as_deref())
    }

    /// The subagent type for an Agent/Task spawn, if set (`None` for a
    /// fork-yourself dispatch). Diagnostics only.
    pub fn subagent_type(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.subagent_type.as_deref())
    }

    /// The content being written (Write tool) or the replacement text (Edit tool).
    ///
    /// For Edit, this is the replacement *fragment*, not the resulting document.
    /// Checks that validate whole-document structure (frontmatter, etc.) must
    /// use [`Self::effective_content`] instead.
    pub fn content(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.content.as_deref().or(ti.new_string.as_deref()))
    }

    /// The `(introduced, removed)` text-fragment pairs a tool call carries, so a
    /// content guard can inspect *what the edit introduces* uniformly across
    /// Write, Edit, and MultiEdit:
    ///
    /// - Write (`content`) → one pair `(content, "")` — no removed fragment.
    /// - Edit (`new_string`/`old_string`) → one pair.
    /// - MultiEdit (`edits[]`) → one pair per element.
    ///
    /// `None` when the payload carries no editable text (e.g. Read, Bash).
    ///
    /// Fragments are kept SEPARATE (not concatenated) so a phrase pattern can't
    /// match across an edit boundary, and so each edit's removed-context
    /// subtraction stays scoped to that edit. Use this — not [`Self::content`],
    /// which is `None` for MultiEdit — for fragment-scanning guards that must
    /// also see `edits[]` (#83); use [`Self::effective_content`] only when the
    /// whole resulting document matters.
    pub fn edit_fragments(&self) -> Option<Vec<(String, String)>> {
        let ti = self.tool_input.as_ref()?;

        if let Some(new) = ti.content.as_deref().or(ti.new_string.as_deref()) {
            let old = ti.old_string.as_deref().unwrap_or_default().to_string();
            return Some(vec![(new.to_string(), old)]);
        }

        if let Some(edits) = ti.edits.as_ref() {
            let pairs: Vec<(String, String)> = edits
                .iter()
                .map(|e| {
                    (
                        e.new_string.as_deref().unwrap_or_default().to_string(),
                        e.old_string.as_deref().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            return (!pairs.is_empty()).then_some(pairs);
        }

        None
    }

    /// The full document the tool call will produce.
    ///
    /// - Write (`content` present) → the content as-is.
    /// - Edit (`old_string`/`new_string` present) → reads the **literal**
    ///   `file_path` (falling back to `path`) from disk — *not* the
    ///   `normalize_path`-processed value — applies the replacement (honoring
    ///   `replace_all`), returns the result. Simulating against the literal
    ///   write target keeps a guard validating the same file Claude Code will
    ///   actually write, even when the path carries a trailing space/backslash
    ///   or null byte.
    /// - MultiEdit (`edits[]` present) → reads the file, applies each edit in order.
    /// - File unreadable, missing, or non-UTF-8 for Edit/MultiEdit → `None`
    ///   (fail open, ADR-0001). A future *blocking* content-security guard that
    ///   adopts this helper must supply its own fail-closed default rather than
    ///   treating `None` as "allow".
    pub fn effective_content(&self) -> Option<String> {
        let ti = self.tool_input.as_ref()?;

        // Write: content is already the whole document.
        if let Some(content) = ti.content.as_deref() {
            return Some(content.to_string());
        }

        // Edit / MultiEdit: simulate the edit against the on-disk file, reading
        // the LITERAL write target (not the normalized path) so the simulation
        // matches the exact file Claude Code will write.
        let path = ti.file_path.as_deref().or(ti.path.as_deref())?;
        let on_disk = std::fs::read_to_string(path).ok()?;

        if let (Some(old), Some(new)) = (ti.old_string.as_deref(), ti.new_string.as_deref()) {
            return Some(apply_edit(
                &on_disk,
                old,
                new,
                ti.replace_all.unwrap_or(false),
            ));
        }

        if let Some(edits) = ti.edits.as_ref() {
            let mut doc = on_disk;
            for edit in edits {
                let (Some(old), Some(new)) =
                    (edit.old_string.as_deref(), edit.new_string.as_deref())
                else {
                    continue;
                };
                doc = apply_edit(&doc, old, new, edit.replace_all.unwrap_or(false));
            }
            return Some(doc);
        }

        None
    }

    /// The tool name **exactly as the harness sent it** (`Write`, `Edit`,
    /// `Bash`, `exec_command`, `mcp__claude-in-chrome__read_page`, …).
    ///
    /// Use this when the guard's question is "which tool is this?" — a
    /// fully-qualified MCP name, a Claude-only tool with no Codex counterpart
    /// (`AskUserQuestion`, `ExitPlanMode`, `CronCreate`), or an audit record of
    /// what actually ran. Use [`Self::normalized_tool_name`] when the question
    /// is "what does this operation do?".
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// The harness-neutral tool name: [`Self::normalized_tool`] when the parse
    /// derived one, otherwise [`Self::tool_name`] unchanged.
    ///
    /// Under Claude Code the two agree for every native tool, so a guard that
    /// switches to this reads identically there; under Codex (and for MCP
    /// filesystem servers on either harness) it is what lets a `Write` gate see
    /// `mcp__filesystem__write_file`. Every guard gating on a Claude tool name
    /// — `Bash`, `Agent`/`Task`, `Edit`/`Write`/`MultiEdit`/`NotebookEdit`,
    /// `Read`, `Grep` — wants this one.
    pub fn normalized_tool_name(&self) -> Option<&str> {
        self.normalized_tool
            .as_deref()
            .or(self.tool_name.as_deref())
    }

    /// The Claude Code session id, if present (SessionStart and some payloads).
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The absolute path to the session transcript (`.jsonl`), if present.
    /// A documented common field on every hook event (PreToolUse included).
    pub fn transcript_path(&self) -> Option<&str> {
        self.transcript_path.as_deref()
    }

    /// The SessionStart trigger source (startup/resume/clear/compact), if present.
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// The session model id, if present.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The subagent id, if the payload carried one (`None` on the main thread).
    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    /// The submitted prompt text, if present (`UserPromptSubmit` only).
    pub fn prompt(&self) -> Option<&str> {
        self.prompt.as_deref()
    }

    /// The stdout from the tool response (PostToolUse only).
    pub fn tool_response_stdout(&self) -> Option<&str> {
        self.tool_response
            .as_ref()
            .and_then(|tr| tr.stdout.as_deref())
    }

    /// The `ExitPlanMode` plan text from a `PostToolUse` `tool_response.plan`
    /// payload — present on same-session plan approval, where `tool_input.plan`
    /// is empty (cadence-hooks#396).
    pub fn tool_response_plan(&self) -> Option<&str> {
        self.tool_response
            .as_ref()
            .and_then(|tr| tr.plan.as_deref())
    }

    /// The `ExitPlanMode` plan text from the CALL side (`tool_input.plan`) —
    /// filled by the current harness at call time (cadence-hooks#672), empty
    /// in the 2.1.220-era payloads. Fallback source after
    /// [`Self::tool_response_plan`].
    pub fn tool_input_plan(&self) -> Option<&str> {
        self.tool_input.as_ref().and_then(|ti| ti.plan.as_deref())
    }

    /// The harness plan-store path for an `ExitPlanMode` call, preferring the
    /// response-side `filePath` over the call-side `planFilePath`
    /// (cadence-hooks#672). Last-resort plan source when both inline plan
    /// fields are absent.
    pub fn plan_file_path(&self) -> Option<&str> {
        self.tool_response
            .as_ref()
            .and_then(|tr| tr.file_path.as_deref())
            .or_else(|| {
                self.tool_input
                    .as_ref()
                    .and_then(|ti| ti.plan_file_path.as_deref())
            })
    }

    /// The AskUserQuestion questions carried by this tool call, if any.
    pub fn ask_questions(&self) -> Option<&[AskQuestion]> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.questions.as_deref())
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
    #[serde(default, deserialize_with = "lenient_option")]
    pub tool_input: Option<ToolInput>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub parent_session_id: Option<String>,
    pub parent_agent_id: Option<String>,
    pub source_agent_id: Option<String>,
    pub duration_ms: Option<u64>,
    /// SessionEnd exit reason (e.g. `other`, `prompt_input_exit`, `resume`),
    /// when the payload carries it. Recorded on the `sessions.jsonl` row so a
    /// session's terminal cause is greppable; deserializes to `None` when absent.
    pub reason: Option<String>,
    /// Model id for the session (e.g. `claude-opus-4-8`), when the payload
    /// carries it (SessionStart and some Pre/PostToolUse payloads). Mirrors
    /// [`HookInput::model`]; deserializes to `None` when absent.
    pub model: Option<String>,
    /// The tool that fired this event (e.g. `EnterPlanMode`, `ExitPlanMode`,
    /// `Bash`). Mirrors [`HookInput::tool_name`]; deserializes to `None` when
    /// absent. Powers event-derivation loggers like `log-ask-user-question`
    /// that key off which tool ran rather than a fixed `hook_event_name`.
    pub tool_name: Option<String>,
    /// The tool response, available in PostToolUse payloads. Mirrors
    /// [`HookInput::tool_response`]; deserializes to `None` on PreToolUse and
    /// other events that carry no response. Additive — every existing logger
    /// ignores it. Shape varies by tool; a mismatch degrades to `None` rather
    /// than failing the whole payload parse (see `lenient_option`).
    #[serde(default, deserialize_with = "lenient_option")]
    pub tool_response: Option<ToolResponse>,
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

/// Structured metadata attached to a hard block, so Claude self-corrects from
/// a machine-parseable payload instead of re-parsing prose. Renders into the
/// PreToolUse JSON envelope as `additionalContext` (and as a parallel JSON
/// fragment inside `permissionDecisionReason`, so it survives whichever field
/// Claude Code surfaces on `deny`).
///
/// `severity` is a `&'static str` because every call site picks a constant
/// (`"error"`, `"warn"`) — making it an enum would force serde glue without
/// adding value.
#[derive(Debug, Clone, Serialize)]
pub struct BlockMetadata {
    /// Stable identifier for the rule that fired — e.g. `gh-write-unauthorized-target`.
    /// Names a rule, not a hook subcommand, so a hook with multiple branches can
    /// expose them distinctly to downstream tooling.
    pub rule_id: String,

    /// Concrete fragment the user (or Claude) can apply verbatim on retry.
    /// Typically a flag + value (e.g. `-R cameronsjo/cadence`), not a full
    /// reconstructed command — full reconstruction is fragile and rarely needed.
    pub fix: String,

    /// Currently-configured allowlist, serialized as display strings. Empty
    /// when no allowlist is configured (the unconfigured fail-safe block).
    pub allowed_owners: Vec<String>,

    /// `"error"` for blocking violations, `"warn"` for advisory blocks.
    pub severity: &'static str,
}

/// Why a guard allowed an operation it would otherwise have acted on.
///
/// v1 distinguishes a time-bounded `dismiss-*` snooze from a per-guard
/// environment switch. Future kinds (`GlobalBypass`/`GlobalDisable` for the
/// `main.rs` gates, `Exemption`, `EffortSkip`) extend this as the remaining
/// bypass surface opts in — see the deferred follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassKind {
    /// A `cadence-hooks guardrails dismiss-*` snooze marker was active.
    Dismissal,
    /// A per-guard environment switch (e.g. `CADENCE_ALLOW_MAIN`,
    /// `CADENCE_NO_ENFORCE_WORKTREE`) suppressed the guard.
    EnvSwitch,
}

impl BypassKind {
    /// Stable snake_case wire token, so the metrics record shape doesn't couple
    /// to the Rust variant spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            BypassKind::Dismissal => "dismissal",
            BypassKind::EnvSwitch => "env_switch",
        }
    }
}

/// Attribution for a bypass-allow: *why* a guard let an operation through that
/// its own invariant would otherwise have blocked or nudged. Rides on
/// [`CheckResult::bypass`] so the dispatch seam can record the ride-through
/// (in `src/dispatch.rs`) without a new [`Outcome`] variant.
///
/// **Privacy contract (inherited from the denial log):** carries only the
/// mechanism, a user-authored `reason`, the arming session, and the expiry —
/// never a command, path, or edited content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassProvenance {
    /// Dismissal vs env-switch.
    pub kind: BypassKind,
    /// The concrete mechanism, e.g. `dismiss-enforce-worktree` or
    /// `CADENCE_ALLOW_MAIN`.
    pub mechanism: String,
    /// The user-authored `--reason` from a `dismiss-*` snooze, when present.
    /// Always `None` for an env-switch (there is nowhere to author one).
    pub reason: Option<String>,
    /// Unix epoch seconds when the dismissal expires, when known.
    pub expires_at: Option<i64>,
    /// The session id that armed the dismissal, when the sidecar recorded it.
    pub armed_by_session: Option<String>,
}

/// Result of running a single check.
pub struct CheckResult {
    pub outcome: Outcome,
    pub message: Option<String>,
    /// Structured payload attached to hard blocks. Always `None` for
    /// `Allow`, `Nudge`, and `Ask` (their delivery shapes don't carry it).
    /// When `Some`, its `fix` is folded into the block's stderr
    /// message (exit 2 surfaces stderr only — see [`render_output`]).
    pub block_metadata: Option<BlockMetadata>,
    /// Attribution when the guard allowed *because a bypass was active* — a
    /// snooze marker or an env switch — rather than because the operation was
    /// fine on its own. `None` for a normal allow/nudge/block. When `Some`, the
    /// dispatch seam records a `used` line in `bypasses.jsonl`.
    pub bypass: Option<BypassProvenance>,
}

impl CheckResult {
    pub fn allow() -> Self {
        Self {
            outcome: Outcome::Allow,
            message: None,
            block_metadata: None,
            bypass: None,
        }
    }

    pub fn nudge(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Nudge,
            message: Some(message.into()),
            block_metadata: None,
            bypass: None,
        }
    }

    pub fn block(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Block,
            message: Some(message.into()),
            block_metadata: None,
            bypass: None,
        }
    }

    /// Hard block carrying a [`BlockMetadata`] payload. Use this when the rule
    /// can name a concrete fix — `block(...)` stays the right call when the
    /// block is purely advisory (e.g. an unconfigured fail-safe).
    pub fn block_structured(message: impl Into<String>, meta: BlockMetadata) -> Self {
        Self {
            outcome: Outcome::Block,
            message: Some(message.into()),
            block_metadata: Some(meta),
            bypass: None,
        }
    }

    /// Force the interactive permission prompt (exit 0). The `message` becomes
    /// the `permissionDecisionReason` shown to the user. Use when a guard can
    /// neither prove an operation safe (allow) nor prove it dangerous (block),
    /// so the human decides. See [`Outcome::Ask`] for the precedence guarantee.
    pub fn ask(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Ask,
            message: Some(message.into()),
            block_metadata: None,
            bypass: None,
        }
    }

    /// An [`Outcome::Allow`] that carries [`BypassProvenance`]: the guard let the
    /// operation through *because a bypass was active*, not because the operation
    /// was fine on its own. Exit code is still 0 — the provenance rides the result
    /// so the dispatch seam records a `used` line in `bypasses.jsonl`.
    pub fn allow_bypassed(bypass: BypassProvenance) -> Self {
        Self {
            outcome: Outcome::Allow,
            message: None,
            block_metadata: None,
            bypass: Some(bypass),
        }
    }

    /// Attach [`BypassProvenance`] to a result that is **not** a plain allow.
    ///
    /// [`allow_bypassed`](Self::allow_bypassed) covers the common shape — a
    /// bypass turns a block into a silent allow. It does not cover a guard with
    /// more than one severity tier, where a bypass downgrades the hard tier but
    /// the soft tier still has something to say: dropping to `allow_bypassed`
    /// would silently discard that message, and returning a bare `nudge` would
    /// lose the provenance row in `bypasses.jsonl`.
    ///
    /// `redact-external-content` is the first such guard: with the identity
    /// bypass armed and both an identity and a shaped hit present, the honest
    /// result is a nudge carrying the shaped finding *and* the attribution that
    /// a bypass suppressed the block.
    pub fn with_bypass(mut self, bypass: BypassProvenance) -> Self {
        self.bypass = Some(bypass);
        self
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

/// The feedback-channel footer appended to hard blocks. Points the user at the
/// `cadence:feedback` skill so a false-positive block becomes one structured
/// issue on the meta-repo instead of silent friction.
const FEEDBACK_FOOTER: &str = "\n\nIf this fired in error: /cadence:feedback";

/// Resolve the feedback footer from the environment.
///
/// Returns `None` when `CADENCE_NO_FEEDBACK_FOOTER` is set to any non-empty
/// value (the suppression toggle), otherwise the [`FEEDBACK_FOOTER`] text.
fn feedback_footer() -> Option<String> {
    let suppressed = std::env::var("CADENCE_NO_FEEDBACK_FOOTER")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if suppressed {
        None
    } else {
        Some(FEEDBACK_FOOTER.to_string())
    }
}

/// Compose the message body emitted for an outcome, appending the feedback
/// footer to **hard blocks only** (never Nudge/Allow — they aren't errors the
/// user needs a feedback channel for).
///
/// `footer` is the resolved footer ([`feedback_footer`]); passing it in keeps
/// this pure and unit-testable without mutating process-global env.
fn apply_feedback_footer(outcome: Outcome, msg: &str, footer: Option<&str>) -> String {
    match (outcome, footer) {
        (Outcome::Block, Some(f)) => format!("{msg}{f}"),
        _ => msg.to_string(),
    }
}

/// The stdout/stderr payloads to emit for a rendered check outcome.
///
/// Extracted as a pure value so the exit-code × output-shape matrix is
/// unit-testable — [`run_check`] itself `process::exit`s and can't be asserted
/// directly. A `None` stream means "write nothing to it."
#[derive(Debug, Default, PartialEq, Eq)]
struct RenderedOutput {
    stdout: Option<String>,
    stderr: Option<String>,
}

/// Pure: compute what a check outcome writes to stdout/stderr, honoring Claude
/// Code's exit-code contract.
///
/// The contract (code.claude.com/docs/en/hooks):
/// - **Exit 0** (Allow/Nudge/Ask): stdout JSON is parsed for control
///   (`hookSpecificOutput`, `decision`); stderr is ignored.
/// - **Exit 2** (Block): stdout is **ignored entirely** — only stderr is fed
///   back to Claude. So a block emits *no* stdout: a JSON envelope there is
///   never read, and a wrong-shaped one (e.g. an object-valued
///   `additionalContext`) registers as an output-schema validation failure in
///   telemetry while delivering nothing.
///
/// Structured block hints ([`BlockMetadata::fix`]) therefore ride the stderr
/// channel: the `fix` is appended as a `Fix:` line *only when the prose doesn't
/// already carry one*, so the machine-intended hint reaches Claude via the only
/// channel exit 2 surfaces — without duplicating a fix the block message already
/// spells out.
///
/// `footer` is the resolved feedback footer ([`feedback_footer`]); passing it in
/// keeps this pure without touching process-global env.
fn render_output(
    outcome: Outcome,
    message: Option<&str>,
    block_metadata: Option<&BlockMetadata>,
    event: HookEvent,
    footer: Option<&str>,
) -> RenderedOutput {
    let Some(msg) = message else {
        return RenderedOutput::default();
    };
    let event_name = event.name();
    match outcome {
        Outcome::Nudge => RenderedOutput {
            stdout: Some(
                serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "additionalContext": msg,
                    }
                })
                .to_string(),
            ),
            stderr: None,
        },
        Outcome::Ask => RenderedOutput {
            // PreToolUse ask: exit 0 with a `permissionDecision: "ask"` envelope.
            // Claude Code shows the interactive permission prompt, using `msg` as
            // the reason — overriding a settings `allow` rule (most-restrictive
            // precedence). The reason field is a JSON string, mirroring the
            // additionalContext string-type contract (never an object).
            stdout: Some(
                serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "ask",
                        "permissionDecisionReason": msg,
                    }
                })
                .to_string(),
            ),
            stderr: None,
        },
        Outcome::Block => {
            // Exit 2 = stderr only. The structured `fix` (the one part that was
            // JSON-only) folds into the prose here, on the channel exit 2
            // surfaces — but only when the message doesn't already carry a
            // `Fix:` line, to avoid a duplicate.
            let mut body = msg.to_string();
            if let Some(meta) = block_metadata {
                let has_fix_line = msg.lines().any(|l| l.trim_start().starts_with("Fix:"));
                if !meta.fix.is_empty() && !has_fix_line {
                    body.push_str(&format!("\n   Fix: {}", meta.fix));
                }
            }
            let mut full = apply_feedback_footer(Outcome::Block, &body, footer);
            if !full.ends_with('\n') {
                full.push('\n');
            }
            RenderedOutput {
                stdout: None,
                stderr: Some(full),
            }
        }
        Outcome::Allow => RenderedOutput::default(),
    }
}

/// Run a single check, emit output, and exit.
///
/// Routing (delegated to the pure [`render_output`], then written and exited):
/// - `skip_at_effort()` matches `$CLAUDE_EFFORT` → silent Allow (exit 0),
///   `check.run()` is not called.
/// - Nudge / Ask → JSON to stdout (exit 0). Claude Code parses this and
///   injects the message into Claude's context.
/// - Block → text to stderr **only** (exit 2). Claude Code ignores stdout on a
///   block, so no JSON envelope is emitted there; the structured [`BlockMetadata`]
///   `fix` is folded into the stderr text instead (see [`render_output`]).
/// - Allow → silent exit 0.
pub fn run_check(check: &dyn Check, input: &HookInput, event: HookEvent) -> ! {
    match decide_check(check, input) {
        None => process::exit(Outcome::Allow.code()),
        Some(result) => emit_and_exit(&result, event),
    }
}

/// The decide half of [`run_check`]: honor `skip_at_effort()`, then run the
/// check. `None` means the check was short-circuited to Allow for the current
/// `$CLAUDE_EFFORT` and `check.run()` was **not** called — the caller must treat
/// it as a silent Allow. `Some(result)` carries the check's outcome.
///
/// Split out so a caller (the binary's logged-dispatch wrapper) can observe the
/// [`CheckResult`] — e.g. to record a denial — between deciding and exiting,
/// without changing what [`run_check`] itself does.
pub fn decide_check(check: &dyn Check, input: &HookInput) -> Option<CheckResult> {
    let current_effort = std::env::var("CLAUDE_EFFORT").ok();
    if should_skip_for_effort(check.skip_at_effort(), current_effort.as_deref()) {
        return None;
    }
    Some(check.run(input))
}

/// The emit-and-exit half of [`run_check`]: render the outcome to stdout/stderr
/// per Claude Code's exit-code contract, then `process::exit` with the outcome's
/// code. Never returns.
///
/// Behaviourally identical to the tail of the pre-split [`run_check`], so the
/// `render_output` matrix tests remain the safety net for the output shape.
pub fn emit_and_exit(result: &CheckResult, event: HookEvent) -> ! {
    if result.outcome == Outcome::Ask && is_codex_harness() {
        let reason = result.message.as_deref().unwrap_or("confirmation required");
        eprintln!(
            "{reason}\n\nBlocked because Codex hooks cannot hand an Ask decision to the user. \
             Review the target, then use the documented scoped bypass or run the operation \
             yourself outside the agent session."
        );
        process::exit(Outcome::Block.code());
    }
    let rendered = render_output(
        result.outcome,
        result.message.as_deref(),
        result.block_metadata.as_ref(),
        event,
        feedback_footer().as_deref(),
    );
    if let Some(out) = rendered.stdout {
        println!("{out}");
    }
    if let Some(err) = rendered.stderr {
        eprint!("{err}");
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
///
/// `pub` so the binary's logged-dispatch wrapper ([`crate`] consumers in `src/`)
/// can reuse the same interactive-terminal guard as [`run_check_from_stdin`].
pub fn guard_interactive_terminal(
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
///
/// Routes through [`HookInput::normalized_inputs`], so a harness payload that
/// expands into several targets (a Codex `apply_patch` carrying N file
/// operations) is judged per target and the strictest verdict wins — the same
/// semantics the shipped binary gets from `dispatch::run_logged_check`.
///
/// It was left unnormalized when patch expansion landed, which made it a second,
/// *weaker* entry point wearing the name "convenience wrapper": an `apply_patch`
/// payload reached the check as one opaque input with no `file_path`, so every
/// path- and content-scanning guard saw nothing to judge. Nothing shipped was
/// exposed — every `src/main.rs` hook arm calls the dispatch wrapper — but this
/// is public API, and the next caller to reach for the convenient one would have
/// silently got less enforcement.
///
/// What it deliberately does NOT gain is the dispatch wrapper's telemetry tail
/// (denial ledger, timing, panic guard) or its Codex fail-closed parse arm: those
/// need the canonical registry hook name, which lives in the binary. So this
/// stays the *unlogged* path, not a weaker one.
pub fn run_check_from_stdin(check: &dyn Check, event: HookEvent) -> ! {
    guard_interactive_terminal(check.name(), Some(event), None);
    let input = match HookInput::from_stdin() {
        Ok(input) => input,
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            process::exit(0); // Fail open on parse errors
        }
    };
    let targets = match input.normalized_inputs() {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("cadence-hooks: {e}");
            process::exit(0); // Fail open on normalization errors
        }
    };
    // Strictest-wins, ties to the earlier target — the same rule as the binary's
    // `aggregate_results`, kept here rather than shared because that function
    // lives in the binary (which depends on core, not the reverse). This half
    // does not join the losers' messages: the binary needs that for its denial
    // ledger, an unlogged wrapper does not.
    let mut merged: Option<CheckResult> = None;
    for target in &targets {
        let Some(result) = decide_check(check, target) else {
            continue;
        };
        let strictest = match &merged {
            None => true,
            Some(previous) => previous.outcome.merge(result.outcome) != previous.outcome,
        };
        if strictest {
            merged = Some(result);
        }
    }
    match merged {
        None => process::exit(Outcome::Allow.code()),
        Some(result) => emit_and_exit(&result, event),
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
        assert_eq!(Outcome::Block.code(), 2);
    }

    // --- the payload-shape harness sniff (C3) ---

    /// Both Codex signals are recognized. Asserted on the pure predicate so the
    /// test says nothing about process-global state other tests may have set.
    #[test]
    fn codex_payload_shapes_are_recognized() {
        for raw in [
            r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\n*** End Patch"}"#,
            r#"{"tool_name":"exec_command","tool_input":{"cmd":"ls"}}"#,
            r#"{"tool_name":"unified_exec","tool_input":{"cmd":"ls"}}"#,
            r#"{"tool_name":"spawn_agent","tool_input":{}}"#,
            // The freeform-body signal on its own, with no Codex-only name.
            r#"{"tool_name":"Read","tool_input":"/etc/hosts"}"#,
        ] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(
                is_codex_payload_shape(&value),
                "should sniff as Codex: {raw}"
            );
        }
    }

    /// The other direction, which is the one that matters: an ordinary Claude
    /// Code payload must NOT trip the sniff, or every session would silently
    /// take the Codex hardening path.
    #[test]
    fn claude_payload_shapes_are_not_sniffed_as_codex() {
        for raw in [
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
            r#"{"tool_name":"Edit","tool_input":{"file_path":"a","old_string":"x","new_string":"y"}}"#,
            r#"{"tool_name":"Agent","tool_input":{"subagent_type":"explorer"}}"#,
            r#"{"tool_name":"mcp__claude-in-chrome__read_page","tool_input":{}}"#,
            r#"{"session_id":"s","source":"startup"}"#,
            // Not a substring match: a Claude tool whose name merely contains a
            // Codex-only name must not sniff.
            r#"{"tool_name":"apply_patch_helper","tool_input":{}}"#,
        ] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(
                !is_codex_payload_shape(&value),
                "should NOT sniff as Codex: {raw}"
            );
        }
    }

    /// End to end: parsing a Codex payload makes `is_codex_harness()` true with
    /// `CADENCE_HARNESS` unset — the whole point of the fallback. Deliberately
    /// one-directional: the flag is process-global and sticky by design, so a
    /// "stays false" assertion here would be a race against every other test in
    /// this binary. That direction is covered above, on the pure predicate.
    #[test]
    fn parsing_a_codex_payload_arms_the_harness_fallback() {
        HookInput::from_json(r#"{"tool_name":"exec_command","tool_input":{"cmd":"ls"}}"#).unwrap();
        assert!(
            is_codex_harness(),
            "a parsed Codex payload must arm the harness fallback without the env var"
        );
    }

    #[test]
    fn codex_shell_and_subagent_aliases_normalize() {
        let shell = HookInput::from_json(
            r#"{"tool_name":"exec_command","tool_input":{"cmd":"git status"}}"#,
        )
        .unwrap();
        assert_eq!(shell.tool_name(), Some("exec_command"));
        assert_eq!(shell.normalized_tool_name(), Some("Bash"));
        assert_eq!(shell.command(), Some("git status"));

        let agent = HookInput::from_json(r#"{"tool_name":"spawn_agent","tool_input":{}}"#).unwrap();
        assert_eq!(agent.tool_name(), Some("spawn_agent"));
        assert_eq!(agent.normalized_tool_name(), Some("Agent"));
    }

    #[test]
    fn codex_filesystem_mcp_operations_normalize() {
        let write = HookInput::from_json(
            r#"{"tool_name":"mcp__filesystem__write_file","tool_input":{"path":"a","content":"x"}}"#,
        )
        .unwrap();
        assert_eq!(write.normalized_tool_name(), Some("Write"));
        assert_eq!(write.operation(), Some("create"));
        assert_eq!(write.file_path().as_deref(), Some("a"));

        let delete = HookInput::from_json(
            r#"{"tool_name":"mcp__filesystem__delete_file","tool_input":{"path":"a"}}"#,
        )
        .unwrap();
        assert_eq!(delete.normalized_tool_name(), Some("Edit"));
        assert_eq!(delete.operation(), Some("delete"));

        let read = HookInput::from_json(
            r#"{"tool_name":"mcp__filesystem__read_file","tool_input":{"path":".env"}}"#,
        )
        .unwrap();
        assert_eq!(read.normalized_tool_name(), Some("Read"));
        assert_eq!(read.operation(), Some("read"));

        let rename = HookInput::from_json(
            r#"{"tool_name":"mcp__filesystem__move_file","tool_input":{"source":"a","destination":"b"}}"#,
        )
        .unwrap()
        .normalized_inputs()
        .unwrap();
        assert_eq!(rename.len(), 2);
        assert_eq!(rename[0].file_path().as_deref(), Some("a"));
        assert_eq!(rename[1].file_path().as_deref(), Some("b"));
    }

    /// The `grep`/`search`/`find_file` and `get_file`/`fetch_file`/`load_file`
    /// arms of the `mcp__` heuristic, which no test reached — only
    /// `write_file`/`delete_file`/`read_file`/`move_file` were exercised, so
    /// half the classifier was live-but-unpinned.
    #[test]
    fn remaining_mcp_heuristic_branches_classify() {
        let cases = [
            ("mcp__code__grep", "Grep", "search"),
            ("mcp__notion__search_pages", "Grep", "search"),
            ("mcp__fs__find_file", "Grep", "search"),
            ("mcp__fs__get_file", "Read", "read"),
            ("mcp__fs__fetch_file", "Read", "read"),
            ("mcp__fs__load_file", "Read", "read"),
        ];
        for (tool, expected_tool, expected_operation) in cases {
            let input =
                HookInput::from_json(&format!(r#"{{"tool_name":"{tool}","tool_input":{{}}}}"#))
                    .unwrap();
            assert_eq!(input.normalized_tool_name(), Some(expected_tool), "{tool}");
            assert_eq!(input.operation(), Some(expected_operation), "{tool}");
            // And, per the C1 fix, the literal name always survives.
            assert_eq!(input.tool_name(), Some(tool));
        }
    }

    /// Precedence is fail-safe by construction: a name matching two arms takes
    /// the more destructive one, so a mis-sniff over-blocks rather than
    /// under-blocks. Pinned because the arm ORDER is the whole rule.
    #[test]
    fn mcp_heuristic_precedence_favours_the_destructive_reading() {
        // `delete` is tested before `read`, so a "read-and-delete" tool is a
        // delete.
        let input = HookInput::from_json(
            r#"{"tool_name":"mcp__fs__read_then_delete_file","tool_input":{}}"#,
        )
        .unwrap();
        assert_eq!(input.normalized_tool_name(), Some("Edit"));
        assert_eq!(input.operation(), Some("delete"));

        // An unclassifiable MCP tool gets no normalized view at all, and so
        // reaches guards under its own name.
        let unknown =
            HookInput::from_json(r#"{"tool_name":"mcp__weather__forecast","tool_input":{}}"#)
                .unwrap();
        assert_eq!(
            unknown.normalized_tool_name(),
            Some("mcp__weather__forecast")
        );
        assert_eq!(unknown.operation(), None);
    }

    #[test]
    fn codex_patch_expands_every_target_and_rename_destination() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\n*** Add File: a\n+x\n*** Update File: b\n*** Move to: c\n@@\n-old\n+new\n*** Delete File: d\n*** End Patch"}"#,
        )
        .unwrap();
        let targets = input.normalized_inputs().unwrap();
        let paths = targets
            .iter()
            .filter_map(HookInput::file_path)
            .collect::<Vec<_>>();
        assert_eq!(paths, ["a", "b", "c", "d"]);
        assert_eq!(
            targets
                .iter()
                .map(HookInput::normalized_tool_name)
                .collect::<Vec<_>>(),
            [Some("Write"), Some("Edit"), Some("Write"), Some("Edit")]
        );
    }

    #[test]
    fn codex_patch_command_object_expands_target() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: command.txt\n+ok\n*** End Patch"}}"#,
        )
        .unwrap();
        let targets = input.normalized_inputs().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].file_path().as_deref(), Some("command.txt"));
        assert_eq!(targets[0].content(), Some("ok"));
    }

    #[test]
    fn codex_patch_input_object_expands_target() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** Add File: input.txt\n+ok\n*** End Patch"}}"#,
        )
        .unwrap();
        let targets = input.normalized_inputs().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].file_path().as_deref(), Some("input.txt"));
        assert_eq!(targets[0].content(), Some("ok"));
    }

    #[test]
    fn codex_patch_top_level_input_expands_target() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","input":"*** Begin Patch\n*** Add File: top-level.txt\n+ok\n*** End Patch"}"#,
        )
        .unwrap();
        let targets = input.normalized_inputs().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].file_path().as_deref(), Some("top-level.txt"));
        assert_eq!(targets[0].content(), Some("ok"));
    }

    #[test]
    fn codex_patch_normalized_patch_field_expands_target() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","tool_input":{"patch":"*** Begin Patch\n*** Add File: normalized.txt\n+ok\n*** End Patch"}}"#,
        )
        .unwrap();
        let targets = input.normalized_inputs().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].file_path().as_deref(), Some("normalized.txt"));
        assert_eq!(targets[0].content(), Some("ok"));
    }

    #[test]
    fn codex_patch_identical_duplicate_bodies_expand_target() {
        let patch = "*** Begin Patch\n*** Add File: duplicate.txt\n+ok\n*** End Patch";
        let payload = serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"command": patch, "input": patch, "patch": patch},
            "input": patch,
        });
        let input = HookInput::from_json(&payload.to_string()).unwrap();
        let targets = input.normalized_inputs().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].file_path().as_deref(), Some("duplicate.txt"));
        assert_eq!(targets[0].content(), Some("ok"));
    }

    #[test]
    fn codex_patch_conflicting_bodies_fail_without_echoing_them() {
        let benign = "*** Begin Patch\n*** Add File: benign.txt\n+ok\n*** End Patch";
        let secret = "*** Begin Patch\n*** Add File: secret.env\n+TOP_SECRET\n*** End Patch";
        let payloads = [
            serde_json::json!({
                "tool_name": "apply_patch",
                "tool_input": {"command": benign, "input": secret},
            }),
            serde_json::json!({
                "tool_name": "apply_patch",
                "tool_input": {"command": benign},
                "input": secret,
            }),
            serde_json::json!({
                "tool_name": "apply_patch",
                "tool_input": {"command": benign, "patch": secret},
            }),
        ];
        for payload in payloads {
            let error = HookInput::from_json(&payload.to_string()).unwrap_err();
            assert!(error.contains("conflicting patch bodies"), "{error}");
            assert!(!error.contains("benign.txt"), "{error}");
            assert!(!error.contains("secret.env"), "{error}");
            assert!(!error.contains("TOP_SECRET"), "{error}");
        }
    }

    #[test]
    fn malformed_object_wrapped_patch_diagnostic_does_not_echo_body() {
        for field in ["command", "input"] {
            let payload = serde_json::json!({
                "tool_name": "apply_patch",
                "tool_input": {field: "*** Begin Patch\nTOP_SECRET\n*** End Patch"},
            });
            let input = HookInput::from_json(&payload.to_string()).unwrap();
            let error = input.normalized_inputs().unwrap_err();
            assert!(error.contains("schema rejected"), "{field}: {error}");
            assert!(!error.contains("TOP_SECRET"), "{field}: {error}");
        }
    }

    #[test]
    fn malformed_codex_patch_diagnostic_does_not_echo_body() {
        let input = HookInput::from_json(
            r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\nTOP_SECRET\n*** End Patch"}"#,
        )
        .unwrap();
        let error = input.normalized_inputs().unwrap_err();
        assert!(error.contains("schema rejected"));
        assert!(!error.contains("TOP_SECRET"));
    }

    // --- feedback footer ---

    #[test]
    fn feedback_footer_appends_to_blocks() {
        let out = apply_feedback_footer(Outcome::Block, "blocked: nope", Some(FEEDBACK_FOOTER));
        assert!(out.starts_with("blocked: nope"));
        assert!(out.contains("/cadence:feedback"));
        assert!(out.ends_with(FEEDBACK_FOOTER));
    }

    #[test]
    fn feedback_footer_skips_nudge_and_allow() {
        // The footer is a block-only affordance — nudges are not errors the
        // user needs a feedback channel for, so they pass through.
        assert_eq!(
            apply_feedback_footer(Outcome::Nudge, "heads up", Some(FEEDBACK_FOOTER)),
            "heads up"
        );
        assert_eq!(
            apply_feedback_footer(Outcome::Allow, "", Some(FEEDBACK_FOOTER)),
            ""
        );
    }

    #[test]
    fn feedback_footer_omitted_from_block_when_suppressed() {
        // `None` models the CADENCE_NO_FEEDBACK_FOOTER suppression path.
        assert_eq!(
            apply_feedback_footer(Outcome::Block, "blocked", None),
            "blocked"
        );
    }

    // `feedback_footer()` reads process-global env; serialize the two
    // env-mutating tests so they don't race each other. No other test touches
    // this variable, so the lock only guards this pair.
    static FOOTER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn feedback_footer_present_by_default() {
        let _guard = FOOTER_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against the other env-mutating footer test.
        unsafe { std::env::remove_var("CADENCE_NO_FEEDBACK_FOOTER") };
        let footer = feedback_footer().expect("footer present by default");
        assert!(footer.contains("/cadence:feedback"));
    }

    #[test]
    fn feedback_footer_suppressed_by_env() {
        let _guard = FOOTER_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against the other env-mutating footer test.
        unsafe { std::env::set_var("CADENCE_NO_FEEDBACK_FOOTER", "1") };
        let result = feedback_footer();
        unsafe { std::env::remove_var("CADENCE_NO_FEEDBACK_FOOTER") };
        assert!(result.is_none(), "footer suppressed when env set");
    }

    // --- BlockMetadata / block_structured ---

    fn sample_metadata() -> BlockMetadata {
        BlockMetadata {
            rule_id: "test-rule".to_string(),
            fix: "-R owner/repo".to_string(),
            allowed_owners: vec!["alice".to_string(), "bob".to_string()],
            severity: "error",
        }
    }

    #[test]
    fn block_constructor_leaves_metadata_none() {
        // Existing call sites that haven't migrated to block_structured stay
        // on the legacy stderr path — no JSON envelope emitted.
        let r = CheckResult::block("bad");
        assert!(r.block_metadata.is_none());
        assert!(matches!(r.outcome, Outcome::Block));
    }

    #[test]
    fn block_structured_carries_metadata() {
        let r = CheckResult::block_structured("bad", sample_metadata());
        let meta = r.block_metadata.expect("metadata attached");
        assert_eq!(meta.rule_id, "test-rule");
        assert_eq!(meta.fix, "-R owner/repo");
        assert_eq!(meta.allowed_owners, vec!["alice", "bob"]);
        assert_eq!(meta.severity, "error");
        assert!(matches!(r.outcome, Outcome::Block));
    }

    #[test]
    fn allow_nudge_have_no_metadata() {
        // Only hard blocks carry structured metadata. The other outcomes
        // serialize through a different envelope (additionalContext for
        // Nudge) where it has no place.
        assert!(CheckResult::allow().block_metadata.is_none());
        assert!(CheckResult::nudge("x").block_metadata.is_none());
    }

    #[test]
    fn block_metadata_serializes_with_expected_fields() {
        // Pin the wire shape — downstream consumers (and the future PR that
        // upgrades guard-push-remote to the same primitive) depend on these
        // field names. A casual rename would silently break them.
        let v = serde_json::to_value(sample_metadata()).expect("serializes");
        assert_eq!(v["rule_id"], "test-rule");
        assert_eq!(v["fix"], "-R owner/repo");
        assert_eq!(v["allowed_owners"], serde_json::json!(["alice", "bob"]));
        assert_eq!(v["severity"], "error");
    }

    #[test]
    fn block_metadata_serializes_empty_allowlist_as_empty_array() {
        // When the unconfigured fail-safe fires there is no allowlist — the
        // field must still serialize to a JSON array, not be omitted, so
        // consumers don't have to special-case "missing vs empty".
        let meta = BlockMetadata {
            rule_id: "x".to_string(),
            fix: String::new(),
            allowed_owners: vec![],
            severity: "error",
        };
        let v = serde_json::to_value(meta).expect("serializes");
        assert_eq!(v["allowed_owners"], serde_json::json!([]));
    }

    // --- render_output: exit-code × output-shape matrix (#165) ---

    #[test]
    fn render_block_emits_no_stdout() {
        // THE anti-regression assertion: a hard block (exit 2) must never write
        // stdout. Claude Code ignores stdout on exit 2; a JSON envelope there is
        // pure liability (#165 — 99 output-schema validation failures from one
        // guard emitting an object-valued additionalContext on this ignored path).
        let rendered = render_output(
            Outcome::Block,
            Some("🚫 blocked: target you don't own"),
            Some(&sample_metadata()),
            HookEvent::PreToolUse,
            None,
        );
        assert_eq!(rendered.stdout, None, "block must emit no stdout");
        let stderr = rendered.stderr.expect("block writes stderr");
        assert!(stderr.contains("target you don't own"));
    }

    #[test]
    fn render_block_folds_fix_into_stderr_when_prose_lacks_one() {
        // The structured `fix` was the only JSON-only datum; it must reach Claude
        // via the exit-2-honored channel (stderr), appended as a Fix: line when
        // the prose doesn't already carry one. This mirrors the reproduced #165
        // case (`disallowed_message`, which has no prose Fix line).
        let rendered = render_output(
            Outcome::Block,
            Some("🚫 blocked: no fix line here"),
            Some(&sample_metadata()), // fix = "-R owner/repo"
            HookEvent::PreToolUse,
            None,
        );
        let stderr = rendered.stderr.expect("block writes stderr");
        assert!(
            stderr.contains("Fix: -R owner/repo"),
            "fix folded into stderr: {stderr}"
        );
    }

    #[test]
    fn render_block_does_not_duplicate_existing_fix_line() {
        // When the prose already spells out a Fix:, the metadata fix is NOT
        // re-appended — exactly one Fix line survives.
        let rendered = render_output(
            Outcome::Block,
            Some("🚫 blocked\n   Fix: add `-R owner/repo`"),
            Some(&sample_metadata()),
            HookEvent::PreToolUse,
            None,
        );
        let stderr = rendered.stderr.expect("block writes stderr");
        let fix_lines = stderr
            .lines()
            .filter(|l| l.trim_start().starts_with("Fix:"))
            .count();
        assert_eq!(fix_lines, 1, "exactly one Fix line: {stderr}");
    }

    #[test]
    fn render_block_without_metadata_is_stderr_only() {
        let rendered = render_output(
            Outcome::Block,
            Some("plain block"),
            None,
            HookEvent::PreToolUse,
            None,
        );
        assert_eq!(rendered.stdout, None);
        assert!(rendered.stderr.expect("stderr").contains("plain block"));
    }

    #[test]
    fn render_block_stderr_ends_with_newline() {
        let rendered = render_output(
            Outcome::Block,
            Some("no trailing newline"),
            None,
            HookEvent::PreToolUse,
            None,
        );
        assert!(rendered.stderr.expect("stderr").ends_with('\n'));
    }

    #[test]
    fn render_block_appends_feedback_footer_when_present() {
        let rendered = render_output(
            Outcome::Block,
            Some("blocked"),
            None,
            HookEvent::PreToolUse,
            Some(FEEDBACK_FOOTER),
        );
        assert!(
            rendered
                .stderr
                .expect("stderr")
                .contains("/cadence:feedback")
        );
    }

    #[test]
    fn render_nudge_stdout_additional_context_is_string() {
        // Locks the field TYPE: additionalContext must be a JSON string (schema
        // requires a string, capped 10k chars), never a struct/object.
        let rendered = render_output(
            Outcome::Nudge,
            Some("heads up: editing on main"),
            None,
            HookEvent::PreToolUse,
            None,
        );
        assert_eq!(rendered.stderr, None, "nudge writes no stderr");
        let json: serde_json::Value =
            serde_json::from_str(&rendered.stdout.expect("nudge writes stdout"))
                .expect("valid JSON");
        assert!(
            json["hookSpecificOutput"]["additionalContext"].is_string(),
            "additionalContext must be a string, got {}",
            json["hookSpecificOutput"]["additionalContext"]
        );
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn render_allow_and_empty_message_emit_nothing() {
        assert_eq!(
            render_output(Outcome::Allow, None, None, HookEvent::PreToolUse, None),
            RenderedOutput::default()
        );
        // A None message on any outcome emits nothing (the skip/allow path).
        assert_eq!(
            render_output(Outcome::Block, None, None, HookEvent::PreToolUse, None),
            RenderedOutput::default()
        );
    }

    // --- Ask outcome: exit code, render shape, merge severity (#261) ---

    #[test]
    fn ask_exits_zero() {
        // Ask is a prompt, not a hard block — it must exit 0 so the JSON on
        // stdout is parsed for the permissionDecision (exit 2 would discard it).
        assert_eq!(Outcome::Ask.code(), 0);
    }

    #[test]
    fn render_ask_emits_permission_decision_ask_on_stdout() {
        // THE Ask contract: a PreToolUse `permissionDecision: "ask"` envelope on
        // stdout, no stderr. The reason must be a JSON string (mirroring the
        // additionalContext string-type contract), never an object.
        let rendered = render_output(
            Outcome::Ask,
            Some("rm target could not be proven safe — confirm?"),
            None,
            HookEvent::PreToolUse,
            None,
        );
        assert_eq!(rendered.stderr, None, "ask writes no stderr");
        let json: serde_json::Value =
            serde_json::from_str(&rendered.stdout.expect("ask writes stdout")).expect("valid JSON");
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(
            json["hookSpecificOutput"]["permissionDecisionReason"].is_string(),
            "permissionDecisionReason must be a string, got {}",
            json["hookSpecificOutput"]["permissionDecisionReason"]
        );
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "rm target could not be proven safe — confirm?"
        );
    }

    #[test]
    fn render_ask_does_not_append_feedback_footer() {
        // The feedback footer is a hard-block affordance; an Ask is a routine
        // prompt, so the footer must not leak into the reason.
        let rendered = render_output(
            Outcome::Ask,
            Some("confirm?"),
            None,
            HookEvent::PreToolUse,
            Some(FEEDBACK_FOOTER),
        );
        let json: serde_json::Value =
            serde_json::from_str(&rendered.stdout.expect("ask writes stdout")).expect("valid JSON");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"], "confirm?",
            "no footer folded into an ask reason"
        );
    }

    #[test]
    fn render_ask_with_none_message_emits_nothing() {
        // A None message short-circuits before the match, like every outcome.
        assert_eq!(
            render_output(Outcome::Ask, None, None, HookEvent::PreToolUse, None),
            RenderedOutput::default()
        );
    }

    #[test]
    fn outcome_merge_ask_below_block_above_nudge() {
        // Block > Ask > Nudge > Allow.
        assert_eq!(Outcome::Block.merge(Outcome::Ask), Outcome::Block);
        assert_eq!(Outcome::Ask.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::Ask.merge(Outcome::Nudge), Outcome::Ask);
        assert_eq!(Outcome::Nudge.merge(Outcome::Ask), Outcome::Ask);
        assert_eq!(Outcome::Ask.merge(Outcome::Allow), Outcome::Ask);
        assert_eq!(Outcome::Allow.merge(Outcome::Ask), Outcome::Ask);
    }

    #[test]
    fn check_result_ask() {
        let r = CheckResult::ask("confirm this rm");
        assert_eq!(r.outcome, Outcome::Ask);
        assert_eq!(r.message.as_deref(), Some("confirm this rm"));
        assert!(r.block_metadata.is_none());
        assert!(r.bypass.is_none());
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
    fn pre_tool_use_payload_carries_transcript_path() {
        // The real PreToolUse payload shape (per the Claude Code hooks docs):
        // transcript_path is a common field present on every event. A guard that
        // scans the session transcript depends on this deserializing.
        let json = r#"{"session_id":"abc123","transcript_path":"/home/u/.claude/projects/x/t.jsonl","cwd":"/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            input.transcript_path(),
            Some("/home/u/.claude/projects/x/t.jsonl")
        );
        assert_eq!(input.command(), Some("gh pr create"));
    }

    #[test]
    fn transcript_path_absent_is_none() {
        // Backward compatibility: payloads without the field (older clients, or
        // synthetic test inputs) deserialize to None, never an error.
        let input: HookInput = serde_json::from_str(r#"{"tool_name":"Bash"}"#).unwrap();
        assert_eq!(input.transcript_path(), None);
    }

    #[test]
    fn codex_harness_match_is_case_insensitive() {
        // The security paths (fail-closed parse denial, Ask -> Block) and the
        // metrics harness tag all read this one rule. When they disagreed, a
        // non-lowercase value tagged the run "codex" in metrics while both
        // security paths silently treated it as Claude — failing open exactly
        // when the ledger said Codex was driving.
        for value in ["codex", "Codex", "CODEX", "cOdEx"] {
            assert!(
                is_codex_harness_value(Some(value)),
                "{value} should be recognized as the Codex harness"
            );
        }
    }

    #[test]
    fn codex_harness_match_rejects_non_codex_values() {
        for value in ["claude", "", "codexx", "co dex", "codex-cli"] {
            assert!(
                !is_codex_harness_value(Some(value)),
                "{value} should not be recognized as the Codex harness"
            );
        }
        assert!(!is_codex_harness_value(None));
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
                ..Default::default()
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

    // --- edit_fragments (#83) ---

    #[test]
    fn edit_fragments_write_single_pair_no_old() {
        let input = make_input(Some("Write"), Some("/a.rs"), None, None, Some("doc"), None);
        assert_eq!(
            input.edit_fragments(),
            Some(vec![("doc".to_string(), String::new())])
        );
    }

    #[test]
    fn edit_fragments_edit_pairs_new_and_old() {
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(ToolInput {
                file_path: Some("/a.rs".into()),
                new_string: Some("new".into()),
                old_string: Some("old".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            input.edit_fragments(),
            Some(vec![("new".to_string(), "old".to_string())])
        );
    }

    #[test]
    fn edit_fragments_multi_edit_one_pair_per_edit() {
        // The MultiEdit case content() returns None for — one (new, old) pair
        // per edits[] element, in order.
        let input = HookInput {
            tool_name: Some("MultiEdit".into()),
            tool_input: Some(ToolInput {
                file_path: Some("/a.rs".into()),
                edits: Some(vec![
                    EditOperation {
                        old_string: Some("o1".into()),
                        new_string: Some("n1".into()),
                        replace_all: None,
                    },
                    EditOperation {
                        old_string: Some("o2".into()),
                        new_string: Some("n2".into()),
                        replace_all: None,
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(input.content(), None, "content() is blind to MultiEdit");
        assert_eq!(
            input.edit_fragments(),
            Some(vec![
                ("n1".to_string(), "o1".to_string()),
                ("n2".to_string(), "o2".to_string()),
            ])
        );
    }

    #[test]
    fn edit_fragments_none_for_bash() {
        let input = make_input(Some("Bash"), None, None, Some("ls"), None, None);
        assert_eq!(input.edit_fragments(), None);
    }

    // --- effective_content ---

    fn make_disk_edit(path: &str, old: &str, new: &str, replace_all: Option<bool>) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(ToolInput {
                file_path: Some(path.into()),
                old_string: Some(old.into()),
                new_string: Some(new.into()),
                replace_all,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn apply_edit_replaces_first_occurrence_only() {
        assert_eq!(apply_edit("a b a", "a", "x", false), "x b a");
    }

    #[test]
    fn apply_edit_replace_all_replaces_every_occurrence() {
        assert_eq!(apply_edit("a b a", "a", "x", true), "x b x");
    }

    #[test]
    fn effective_content_write_returns_content() {
        let input = make_input(Some("Write"), Some("/a.md"), None, None, Some("doc"), None);
        assert_eq!(input.effective_content().as_deref(), Some("doc"));
    }

    #[test]
    fn effective_content_edit_simulates_against_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md");
        std::fs::write(&path, "line one\nline two\nline three\n").unwrap();

        let input = make_disk_edit(path.to_str().unwrap(), "line two", "line 2", None);
        assert_eq!(
            input.effective_content().as_deref(),
            Some("line one\nline 2\nline three\n")
        );
    }

    #[test]
    fn effective_content_edit_honors_replace_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md");
        std::fs::write(&path, "x x x").unwrap();

        let input = make_disk_edit(path.to_str().unwrap(), "x", "y", Some(true));
        assert_eq!(input.effective_content().as_deref(), Some("y y y"));
    }

    #[test]
    fn effective_content_edit_missing_file_is_none() {
        let input = make_disk_edit("/nonexistent/path/doc.md", "a", "b", None);
        assert_eq!(input.effective_content(), None);
    }

    #[test]
    fn effective_content_edit_reads_literal_not_normalized_path() {
        // A path with a trailing space: normalize_path() would trim it and read
        // a *different* (nonexistent) file. effective_content() must read the
        // LITERAL write target so a guard validates the same file Claude Code
        // actually writes (#129).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md ");
        std::fs::write(&path, "line one\nline two\n").unwrap();

        let literal = path.to_str().unwrap();
        assert!(
            literal.ends_with(' '),
            "test path must retain its trailing space, got {literal:?}"
        );
        // The normalized form trims the space and points at a nonexistent file.
        assert_ne!(normalize_path(literal), literal);

        let input = make_disk_edit(literal, "line two", "line 2", None);
        assert_eq!(
            input.effective_content().as_deref(),
            Some("line one\nline 2\n"),
            "should simulate against the literal trailing-space path, not the trimmed one"
        );
    }

    #[test]
    fn effective_content_multi_edit_applies_sequentially() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.md");
        std::fs::write(&path, "alpha beta gamma").unwrap();

        let input = HookInput {
            tool_name: Some("MultiEdit".into()),
            tool_input: Some(ToolInput {
                file_path: Some(path.to_str().unwrap().into()),
                edits: Some(vec![
                    EditOperation {
                        old_string: Some("alpha".into()),
                        new_string: Some("one".into()),
                        replace_all: None,
                    },
                    EditOperation {
                        old_string: Some("gamma".into()),
                        new_string: Some("three".into()),
                        replace_all: None,
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(input.effective_content().as_deref(), Some("one beta three"));
    }

    #[test]
    fn effective_content_none_without_content_or_edit_fields() {
        let input = make_input(Some("Read"), Some("/a.md"), None, None, None, None);
        assert_eq!(input.effective_content(), None);
    }

    #[test]
    fn deserialize_edit_with_replace_all() {
        let json = r#"{"tool_name":"Edit","tool_input":{"file_path":"/a.md","old_string":"a","new_string":"b","replace_all":true}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_input.as_ref().unwrap().replace_all, Some(true));
    }

    #[test]
    fn deserialize_multi_edit_payload() {
        let json = r#"{"tool_name":"MultiEdit","tool_input":{"file_path":"/a.md","edits":[{"old_string":"a","new_string":"b"},{"old_string":"c","new_string":"d","replace_all":true}]}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let edits = input.tool_input.as_ref().unwrap().edits.as_ref().unwrap();
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].old_string.as_deref(), Some("a"));
        assert_eq!(edits[1].replace_all, Some(true));
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

    // --- bypass provenance ---

    #[test]
    fn plain_constructors_carry_no_bypass() {
        // Only allow_bypassed sets provenance; every other constructor leaves it
        // None so the dispatch seam records nothing for a normal allow/block.
        assert!(CheckResult::allow().bypass.is_none());
        assert!(CheckResult::nudge("x").bypass.is_none());
        assert!(CheckResult::block("y").bypass.is_none());
    }

    #[test]
    fn allow_bypassed_carries_provenance() {
        let prov = BypassProvenance {
            kind: BypassKind::Dismissal,
            mechanism: "dismiss-enforce-worktree".to_string(),
            reason: Some("dogfooding vault symlink".to_string()),
            expires_at: Some(2_000_000_000),
            armed_by_session: Some("sess-1".to_string()),
        };
        let r = CheckResult::allow_bypassed(prov.clone());
        assert_eq!(r.outcome, Outcome::Allow, "bypass-allow still exits 0");
        assert_eq!(r.bypass.as_ref(), Some(&prov));
    }

    #[test]
    fn bypass_kind_wire_tokens_are_stable() {
        // Metrics records key off these; a rename would silently break greps.
        assert_eq!(BypassKind::Dismissal.as_str(), "dismissal");
        assert_eq!(BypassKind::EnvSwitch.as_str(), "env_switch");
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

    #[test]
    fn deserialize_agent_isolation_and_subagent_type() {
        // The Agent tool's input carries snake_case `subagent_type` and
        // `isolation` (confirmed against real session payloads).
        let json = r#"{"tool_name":"Agent","tool_input":{"subagent_type":"general-purpose","isolation":"worktree"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.subagent_type(), Some("general-purpose"));
        assert_eq!(input.isolation(), Some("worktree"));
    }

    #[test]
    fn agent_fields_absent_are_none() {
        // A fork-yourself / no-isolation dispatch omits both keys; serde maps
        // the absent fields to None (backward-compatible with every other tool).
        let json = r#"{"tool_name":"Agent","tool_input":{"description":"do x"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.subagent_type(), None);
        assert_eq!(input.isolation(), None);
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
        assert_eq!(input.reason, None);
        assert_eq!(input.command(), None);
    }

    #[test]
    fn metrics_input_parses_session_end_reason() {
        // The SessionEnd payload carries `reason`; it lands on the
        // `sessions.jsonl` row so a session's terminal cause is greppable.
        let json =
            r#"{"session_id":"s1","hook_event_name":"SessionEnd","reason":"prompt_input_exit"}"#;
        let input = MetricsInput::from_json(json).unwrap();
        assert_eq!(input.reason.as_deref(), Some("prompt_input_exit"));
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

    #[test]
    fn metrics_input_tolerates_non_object_tool_response() {
        // A tool's `tool_response` shape varies by tool: a plain string (Read),
        // an array (Glob), a Bash-style object (Bash). A shape that does not
        // match the typed `ToolResponse` must degrade to `None`, not fail the
        // whole payload parse and silently drop the metrics row (#356).
        let string_shaped =
            MetricsInput::from_json(r#"{"tool_name":"Read","tool_response":"file contents"}"#)
                .expect("string tool_response must not fail the parse");
        assert!(string_shaped.tool_response.is_none());
        assert_eq!(string_shaped.tool_name.as_deref(), Some("Read"));

        let array_shaped =
            MetricsInput::from_json(r#"{"tool_name":"Glob","tool_response":["a.txt","b.txt"]}"#)
                .expect("array tool_response must not fail the parse");
        assert!(array_shaped.tool_response.is_none());

        // Explicit `null` also degrades to `None` (serde's Option handling).
        let null_shaped = MetricsInput::from_json(r#"{"tool_name":"Read","tool_response":null}"#)
            .expect("null tool_response must not fail the parse");
        assert!(null_shaped.tool_response.is_none());
    }

    #[test]
    fn hook_input_tolerates_non_object_tool_response() {
        // Enforcement guards parse `HookInput`; a mismatched `tool_response`
        // must not blind a guard that only needs `tool_input` — the typed
        // response degrades to `None` while `tool_input` still parses (#356).
        let input: HookInput = serde_json::from_str(
            r#"{"tool_name":"Read","tool_input":{"file_path":"src/main.rs"},"tool_response":"contents"}"#,
        )
        .expect("string tool_response must not fail HookInput parse");
        assert!(input.tool_response.is_none());
        assert_eq!(
            input.tool_input.and_then(|ti| ti.file_path).as_deref(),
            Some("src/main.rs")
        );
    }

    #[test]
    fn metrics_input_parses_tool_name_from_post_tool_use() {
        // Event-derivation loggers key off this field.
        let json = r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash"}"#;
        let input = MetricsInput::from_json(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
    }

    // --- Interactive terminal guidance ---

    #[test]
    fn event_names_match_protocol() {
        assert_eq!(HookEvent::PreToolUse.name(), "PreToolUse");
        assert_eq!(HookEvent::PostToolUse.name(), "PostToolUse");
        assert_eq!(HookEvent::SessionStart.name(), "SessionStart");
        assert_eq!(HookEvent::UserPromptSubmit.name(), "UserPromptSubmit");
    }

    #[test]
    fn sample_payloads_parse_as_hook_input() {
        for event in [
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
            HookEvent::SessionStart,
            HookEvent::UserPromptSubmit,
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
    fn user_prompt_submit_sample_carries_a_prompt() {
        let input: HookInput =
            serde_json::from_str(HookEvent::UserPromptSubmit.sample_payload()).unwrap();
        assert!(input.prompt().is_some_and(|p| !p.is_empty()));
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
        let argv: Vec<String> = ["cadence-hooks", "session", "start"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let msg = interactive_terminal_help("start", Some(HookEvent::SessionStart), None, &argv);
        assert!(msg.contains("'start'"));
        assert!(msg.contains("SessionStart"));
        assert!(msg.contains("cadence-hooks try session start"));
        assert!(msg.contains("| cadence-hooks session start"));
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

    #[test]
    fn deserialize_askuserquestion_tool_input() {
        let json = r#"{"tool_name":"AskUserQuestion","tool_input":{"questions":[{"question":"Which approach?","header":"Approach","multiSelect":false,"options":[{"label":"Option A (Recommended)","description":"first"},{"label":"Option B","description":"second"}]}]}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let qs = input.ask_questions().expect("questions present");
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].multi_select, Some(false));
        let opts = qs[0].options.as_ref().unwrap();
        assert_eq!(opts[0].label.as_deref(), Some("Option A (Recommended)"));
    }

    #[test]
    fn deserialize_askuserquestion_answers() {
        let json = r#"{"tool_name":"AskUserQuestion","tool_response":{"answers":{"Which approach?":"Option A"}}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let answers = input
            .tool_response
            .as_ref()
            .unwrap()
            .answers
            .as_ref()
            .unwrap();
        assert_eq!(answers.get("Which approach?").unwrap(), "Option A");
    }
}
