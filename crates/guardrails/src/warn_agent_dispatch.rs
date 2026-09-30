//! Warn on an Agent/Task dispatch that trips a known dispatch trap.
//!
//! Advisory only: every arm nudges, none blocks (ADR-0001). Three arms:
//!
//! 1. **Omit-model** (cadence-hooks#606): a non-fork dispatch with no `model`
//!    silently inherits the session's most expensive tier.
//! 2. **Fork-model** (#606): a `model` override on a fork dispatch is ignored
//!    by the platform. A fork is `subagent_type: "fork"` or, per
//!    [`cadence_hooks_core::ToolInput::subagent_type`], an omitted type.
//! 3. **Execution oracle** (#837, option a): a brief that asks the subagent to
//!    run or execute candidate commands without naming a scrubbed or isolated
//!    HOME/env. On 2026-09-04 a reviewer ran a corpus containing `rm -rf ~`
//!    against the real HOME. This is a nudge naming the requirement, not the
//!    structural control the issue asks for.
//!
//! The `SendMessage` arm of #606 (a named dispatch whose agent definition
//! omits `SendMessage` from `tools:`) is NOT implemented: it needs agent-file
//! resolution across project, user and plugin-cache roots plus a frontmatter
//! parse, and the payload keys that mark a teammate spawn are unprobed.
//!
//! The prompt is untrusted free text: it is scanned, never echoed.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Phrases that say the subagent is to execute candidate commands. Lowercase
/// substrings, deliberately narrow: "run the tests" must stay silent.
const EXEC_PHRASES: &[&str] = &[
    "execution oracle",
    "run each command",
    "execute each command",
    "run every command",
    "execute every command",
    "run the corpus",
    "execute the corpus",
    "run the candidate",
    "execute the candidate",
    "run these commands",
    "execute these commands",
    "run the commands",
    "execute the commands",
    "in a real shell",
    "what bash would do",
    "what the shell would do",
];

/// Phrases showing the brief already names containment. Any one silences arm 3.
const ISOLATION_PHRASES: &[&str] = &[
    "scratch home",
    "scrubbed",
    "isolated home",
    "isolated env",
    "temp home",
    "fake home",
    "throwaway home",
    "sandbox",
    "container",
    "env -i",
    "home=",
    "empty path",
    "bash -n",
    "do not execute",
    "do not run",
    "never execute",
    "never run",
];

fn is_fork(subagent_type: Option<&str>) -> bool {
    match subagent_type.map(str::trim) {
        None | Some("") => true,
        Some(t) => t.eq_ignore_ascii_case("fork"),
    }
}

/// Pure: does the prompt ask for execution with no containment named?
fn is_uncontained_execution(prompt: &str) -> bool {
    let p = prompt.to_ascii_lowercase();
    EXEC_PHRASES.iter().any(|x| p.contains(x)) && !ISOLATION_PHRASES.iter().any(|x| p.contains(x))
}

/// Pure decision over the four dispatch fields.
fn assess(
    subagent_type: Option<&str>,
    model: Option<&str>,
    prompt: Option<&str>,
) -> Vec<&'static str> {
    let mut notes = Vec::new();
    let has_model = model.is_some_and(|m| !m.trim().is_empty());
    let fork = is_fork(subagent_type);
    if !fork && !has_model {
        notes.push(
            "This dispatch sets no `model`, so it inherits the session's most expensive tier. \
             Pass `model` explicitly (or confirm the agent definition pins one).",
        );
    }
    if fork && has_model {
        notes.push(
            "A `model` override on a fork dispatch is ignored by the platform. Drop it, or \
             dispatch a named `subagent_type` if you need a different model.",
        );
    }
    if prompt.is_some_and(is_uncontained_execution) {
        notes.push(
            "The brief asks the subagent to execute commands but names no scrubbed or isolated \
             HOME/env. Executing candidate input against the real HOME can destroy it (`rm -rf ~` \
             incident, 2026-09-04). Require a scratch HOME and a deny-by-default PATH, or parse \
             with `bash -n` instead of executing.",
        );
    }
    notes
}

/// Warns on Agent/Task dispatch traps. Never blocks.
pub struct WarnAgentDispatch;

impl Check for WarnAgentDispatch {
    fn name(&self) -> &str {
        "warn-agent-dispatch"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        if !matches!(input.normalized_tool_name(), Some("Agent" | "Task")) {
            return CheckResult::allow();
        }
        let notes = assess(
            input.subagent_type(),
            input.agent_model(),
            input.agent_prompt(),
        );
        if notes.is_empty() {
            return CheckResult::allow();
        }
        CheckResult::nudge(notes.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn omit_and_fork_arms() {
        // (subagent_type, model, expected substring or None)
        let table: &[(Option<&str>, Option<&str>, Option<&str>)] = &[
            (Some("general-purpose"), None, Some("no `model`")),
            (Some("general-purpose"), Some("  "), Some("no `model`")),
            (Some("general-purpose"), Some("haiku"), None),
            (Some("cadence:explorer"), None, Some("no `model`")),
            (Some("fork"), None, None),
            (Some("Fork"), Some("haiku"), Some("ignored by the platform")),
            (None, None, None),
            (None, Some("haiku"), Some("ignored by the platform")),
            (Some(""), Some("opus"), Some("ignored by the platform")),
        ];
        for (ty, model, want) in table {
            let notes = assess(*ty, *model, None).join(" ");
            match want {
                Some(w) => assert!(notes.contains(w), "{ty:?} {model:?}: {notes}"),
                None => assert!(notes.is_empty(), "{ty:?} {model:?}: {notes}"),
            }
        }
    }

    #[test]
    fn execution_oracle_arm() {
        let table: &[(&str, bool)] = &[
            (
                "Run each command in the corpus and report what bash does",
                true,
            ),
            ("Use the shell as an execution oracle for these rows", true),
            ("Execute the candidate strings in a real shell", true),
            ("RUN THE CORPUS and compare", true),
            // Containment named: silent.
            ("Run each command with HOME=$(mktemp -d) and env -i", false),
            ("Execute the commands inside a scratch home", false),
            ("Run the corpus in a container", false),
            ("Do not execute the commands; use bash -n to parse", false),
            // Ordinary work: silent.
            ("Run the tests and report failures", false),
            ("Review the diff for correctness", false),
            ("", false),
        ];
        for (prompt, want) in table {
            assert_eq!(is_uncontained_execution(prompt), *want, "{prompt}");
        }
    }

    #[test]
    fn oracle_message_never_echoes_the_prompt() {
        let prompt = "Run each command: rm -rf ~ SECRET-MARKER";
        let notes = assess(Some("fork"), None, Some(prompt)).join(" ");
        assert!(notes.contains("HOME"), "{notes}");
        assert!(!notes.contains("SECRET-MARKER") && !notes.contains("rm -rf ~ S"));
    }

    #[test]
    fn all_arms_combine_in_one_nudge() {
        let notes = assess(Some("general-purpose"), None, Some("run the corpus"));
        assert_eq!(notes.len(), 2);
    }

    fn agent(json_tool_input: &str, tool: &str) -> HookInput {
        HookInput::from_json(&format!(
            r#"{{"tool_name":"{tool}","tool_input":{json_tool_input}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn run_is_advisory_and_tool_scoped() {
        let check = WarnAgentDispatch;
        let table: &[(&str, &str, Outcome)] = &[
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","prompt":"x"}"#,
                Outcome::Nudge,
            ),
            (
                "Task",
                r#"{"subagent_type":"general-purpose","prompt":"x"}"#,
                Outcome::Nudge,
            ),
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","model":"haiku","prompt":"x"}"#,
                Outcome::Allow,
            ),
            (
                "Agent",
                r#"{"subagent_type":"fork","model":"opus"}"#,
                Outcome::Nudge,
            ),
            (
                "Agent",
                r#"{"subagent_type":"general-purpose","model":"haiku","prompt":"run the corpus"}"#,
                Outcome::Nudge,
            ),
        ];
        for (tool, ti, want) in table {
            assert_eq!(check.run(&agent(ti, tool)).outcome, *want, "{tool} {ti}");
        }
        assert_eq!(check.run(&make_bash("ls")).outcome, Outcome::Allow);
    }
}
