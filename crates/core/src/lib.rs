//! Core protocol for Claude Code hooks.
//!
//! All hooks receive JSON on stdin describing the tool invocation,
//! write diagnostics to stderr, and exit with a status code:
//! - 0: allow (operation proceeds)
//! - 1: warn (operation proceeds, message shown)
//! - 2: block (operation prevented)

use serde::Deserialize;
use std::io::Read;
use std::process;

/// Exit codes matching Claude Code's hook contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Operation allowed, no message.
    Allow,
    /// Operation allowed, advisory message shown.
    Warn,
    /// Operation blocked, error message shown.
    Block,
}

impl Outcome {
    pub fn code(self) -> i32 {
        match self {
            Outcome::Allow => 0,
            Outcome::Warn => 1,
            Outcome::Block => 2,
        }
    }

    /// Merge two outcomes, keeping the more severe one.
    pub fn merge(self, other: Outcome) -> Outcome {
        match (self, other) {
            (Outcome::Block, _) | (_, Outcome::Block) => Outcome::Block,
            (Outcome::Warn, _) | (_, Outcome::Warn) => Outcome::Warn,
            _ => Outcome::Allow,
        }
    }
}

/// The JSON structure Claude Code sends to PreToolUse/PostToolUse hooks on stdin.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<ToolInput>,
    pub cwd: Option<String>,
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
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input
            .as_ref()
            .and_then(|ti| ti.file_path.as_deref().or(ti.path.as_deref()))
    }

    /// The bash command, if this is a Bash tool invocation.
    pub fn command(&self) -> Option<&str> {
        self.tool_input.as_ref().and_then(|ti| ti.command.as_deref())
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

    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Warn,
            message: Some(message.into()),
        }
    }

    pub fn block(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Block,
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
}

/// Run a single check, emit output, and exit.
pub fn run_check(check: &dyn Check, input: &HookInput) -> ! {
    let result = check.run(input);
    if let Some(msg) = &result.message {
        eprint!("{msg}");
        if !msg.ends_with('\n') {
            eprintln!();
        }
    }
    process::exit(result.outcome.code());
}

/// Run a single check from stdin. Convenience wrapper for subcommands.
pub fn run_check_from_stdin(check: &dyn Check) -> ! {
    match HookInput::from_stdin() {
        Ok(input) => run_check(check, &input),
        Err(e) => {
            eprintln!("claude-hooks: {e}");
            process::exit(0); // Fail open on parse errors
        }
    }
}
