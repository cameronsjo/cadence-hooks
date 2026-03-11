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

#[cfg(test)]
mod tests {
    use super::*;

    // --- Outcome ---

    #[test]
    fn outcome_codes() {
        assert_eq!(Outcome::Allow.code(), 0);
        assert_eq!(Outcome::Warn.code(), 1);
        assert_eq!(Outcome::Block.code(), 2);
    }

    #[test]
    fn outcome_merge_block_wins() {
        assert_eq!(Outcome::Block.merge(Outcome::Allow), Outcome::Block);
        assert_eq!(Outcome::Allow.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::Block.merge(Outcome::Warn), Outcome::Block);
        assert_eq!(Outcome::Warn.merge(Outcome::Block), Outcome::Block);
        assert_eq!(Outcome::Block.merge(Outcome::Block), Outcome::Block);
    }

    #[test]
    fn outcome_merge_warn_over_allow() {
        assert_eq!(Outcome::Warn.merge(Outcome::Allow), Outcome::Warn);
        assert_eq!(Outcome::Allow.merge(Outcome::Warn), Outcome::Warn);
        assert_eq!(Outcome::Warn.merge(Outcome::Warn), Outcome::Warn);
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
        }
    }

    #[test]
    fn file_path_prefers_file_path_over_path() {
        let input = make_input(None, Some("/a.rs"), Some("/b.rs"), None, None, None);
        assert_eq!(input.file_path(), Some("/a.rs"));
    }

    #[test]
    fn file_path_falls_back_to_path() {
        let input = make_input(None, None, Some("/b.rs"), None, None, None);
        assert_eq!(input.file_path(), Some("/b.rs"));
    }

    #[test]
    fn file_path_none_when_both_absent() {
        let input = make_input(None, None, None, None, None, None);
        assert_eq!(input.file_path(), None);
    }

    #[test]
    fn file_path_none_when_no_tool_input() {
        let input = HookInput {
            tool_name: None,
            tool_input: None,
            cwd: None,
        };
        assert_eq!(input.file_path(), None);
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
        let r = CheckResult::warn("caution");
        assert_eq!(r.outcome, Outcome::Warn);
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
        let r = CheckResult::warn(String::from("owned"));
        assert_eq!(r.message.as_deref(), Some("owned"));
    }

    // --- JSON deserialization ---

    #[test]
    fn deserialize_full_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/a.rs","command":null}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name(), Some("Read"));
        assert_eq!(input.file_path(), Some("/a.rs"));
    }

    #[test]
    fn deserialize_minimal_input() {
        let json = r#"{}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name(), None);
        assert_eq!(input.file_path(), None);
    }

    #[test]
    fn deserialize_bash_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.command(), Some("git status"));
    }
}
