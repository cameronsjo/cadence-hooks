//! Warn when piping output from shell-aliased tools into parsers.
//!
//! Modern CLI replacements (`cat`→`bat`, `find`→`fd`, `ls`→`eza`, `du`→`dust`,
//! `df`→`duf`, `top`→`btm`) change output format — and `find`→`fd` changes
//! syntax entirely. Piping their output into grep/awk/xargs parses the
//! replacement's format, not the original's. The fix is `command <tool>` or an
//! absolute path.
//!
//! Scope is deliberately narrow to avoid false positives: the nudge fires only
//! when an aliased tool is a *producer* in a pipeline (a non-final pipe stage).
//! Interactive use (`ls -la`) and consumer position (`git diff | cat`) stay
//! silent.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Tools that are commonly aliased to modern replacements with different output.
const ALIASED_TOOLS: &[(&str, &str)] = &[
    ("cat", "bat"),
    ("find", "fd"),
    ("ls", "eza"),
    ("du", "dust"),
    ("df", "duf"),
    ("top", "btm"),
];

/// Command wrappers whose next argument is the real tool being run.
const WRAPPERS: &[&str] = &["xargs", "sudo", "env", "nice", "timeout"];

/// Splits a command into chain segments (`&&`, `||`, `;`) — NOT single pipes.
static CHAIN_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\|\||&&|;").expect("pattern should compile"));

/// Nudges to use `command <tool>` when piping aliased tool output to parsers.
pub struct WarnAliasParsing;

/// If this pipe stage's producing command is a bare aliased tool, return the
/// (tool, replacement) pair.
fn stage_aliased_tool(stage: &str) -> Option<(&'static str, &'static str)> {
    let tokens: Vec<&str> = stage.split_whitespace().collect();

    // Skip through wrappers (`xargs ls`, `sudo du`) and env assignments
    // (`LC_ALL=C find`) to reach the real tool.
    let mut idx = 0;
    while idx < tokens.len() && (WRAPPERS.contains(&tokens[idx]) || tokens[idx].contains('=')) {
        idx += 1;
    }

    let first = tokens.get(idx)?;

    // `command <tool>` is the fix — never flag it. Absolute paths are
    // different tokens and never match the bare names below.
    if *first == "command" {
        return None;
    }

    ALIASED_TOOLS
        .iter()
        .find(|(tool, _)| tool == first)
        .copied()
}

impl Check for WarnAliasParsing {
    fn name(&self) -> &str {
        "warn-alias-parsing"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Pipes are the only scope of this check.
        if !command.contains('|') {
            return CheckResult::allow();
        }

        // Strip quoted strings so prose and quoted examples don't fire.
        let stripped = strip_quotes(command);

        // Chain segments first (&&, ||, ;), then pipe stages within each.
        for chain in CHAIN_SPLIT.split(&stripped) {
            let stages: Vec<&str> = chain.split('|').collect();
            if stages.len() < 2 {
                continue;
            }

            // Every stage except the last produces output that gets parsed.
            for stage in &stages[..stages.len() - 1] {
                if let Some((tool, replacement)) = stage_aliased_tool(stage) {
                    return CheckResult::nudge(format!(
                        "`{tool}` is aliased to `{replacement}` on this machine — piped output \
                         is {replacement}'s format, not {tool}'s, and may not parse as expected. \
                         Use `command {tool}` (or an absolute path) when parsing output \
                         programmatically."
                    ));
                }
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    // --- guard clause: non-matching commands stay allowed ---

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnAliasParsing.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        let result = WarnAliasParsing.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn command_prefixed_ls_pipe_allowed() {
        let result = WarnAliasParsing.run(&make_bash("command ls -1 | grep config"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn absolute_path_find_pipe_allowed() {
        let result = WarnAliasParsing.run(&make_bash("/usr/bin/find . -name '*.rs' | xargs wc -l"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn ls_without_pipe_allowed() {
        // Interactive listing — output format doesn't matter
        let result = WarnAliasParsing.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn pipe_without_aliased_tools_allowed() {
        let result = WarnAliasParsing.run(&make_bash("grep -r TODO src/ | sort | uniq"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn aliased_tool_as_consumer_allowed() {
        // `| cat` as a pager-disable trick — cat is the last stage, its output
        // goes to the terminal, nothing parses it
        let result = WarnAliasParsing.run(&make_bash("git diff | cat"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn similar_name_subcommand_allowed() {
        // "ls-files" is a git subcommand, "ls" is not the first token
        let result = WarnAliasParsing.run(&make_bash("git ls-files | grep test"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- happy path: aliased producer piped to parser nudges ---

    #[test]
    fn ls_piped_to_grep_nudges() {
        let result = WarnAliasParsing.run(&make_bash("ls -1 | grep config"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn find_piped_to_xargs_nudges() {
        let result = WarnAliasParsing.run(&make_bash("find . -name '*.rs' | xargs wc -l"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn cat_piped_to_jq_nudges() {
        let result = WarnAliasParsing.run(&make_bash("cat data.json | jq '.items'"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn du_piped_to_sort_nudges() {
        let result = WarnAliasParsing.run(&make_bash("du -sh * | sort -h"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn df_piped_to_awk_nudges() {
        let result = WarnAliasParsing.run(&make_bash("df -h | awk '{print $5}'"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn aliased_producer_in_chain_nudges() {
        let result = WarnAliasParsing.run(&make_bash("cd /tmp && ls | grep log"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- nudge message quality ---

    #[test]
    fn nudge_message_names_tool_and_alias() {
        let result = WarnAliasParsing.run(&make_bash("ls -1 | grep config"));
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("ls"), "nudge should name the tool: {msg}");
        assert!(msg.contains("eza"), "nudge should name the alias: {msg}");
        assert!(
            msg.contains("command ls"),
            "nudge should give the fix: {msg}"
        );
    }

    #[test]
    fn nudge_message_names_find_fd() {
        let result = WarnAliasParsing.run(&make_bash("find . -type f | head -5"));
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("fd"), "nudge should name the fd alias: {msg}");
    }

    // --- edge cases ---

    #[test]
    fn quoted_prose_with_pipe_allowed() {
        let result = WarnAliasParsing.run(&make_bash("echo 'try: ls | grep foo'"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_command_allowed() {
        let result = WarnAliasParsing.run(&make_bash(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn logical_or_not_treated_as_pipe() {
        // `||` is logical-or, not a pipe — `ls` output goes nowhere
        let result = WarnAliasParsing.run(&make_bash("ls /missing || echo 'not found'"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn middle_pipe_stage_producer_nudges() {
        // Aliased tool in the middle of a pipeline still produces parsed output
        let result = WarnAliasParsing.run(&make_bash("echo /tmp | xargs ls | grep log"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }
}
