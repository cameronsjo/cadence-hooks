//! Single source of truth for the hook catalog.
//! Backs `cadence-hooks list`, hook-name resolution, `doctor`'s
//! subcommand cross-reference (issue #39 P1), and `try`'s sample-payload
//! selection (issue #56).

use cadence_hooks_core::HookEvent;

/// A hook entry with its name, description, plugin group, and event.
pub struct HookEntry {
    pub name: &'static str,
    pub description: &'static str,
    /// CLI namespace: cadence | guardrails | rules | obsidian | metrics | lab | session
    pub plugin: &'static str,
    /// Hook event this command serves — drives `try`'s sample-payload shape.
    /// `None` for fire-and-forget loggers, which react to `hook_event_name`
    /// in the payload rather than a fixed event. Keep in sync with the
    /// dispatch in main.rs (the event passed to `run_check_from_stdin`).
    pub event: Option<HookEvent>,
}

/// Complete catalog of all hooks. Single source of truth for `list` output
/// and `hook_name()` resolution. Keep in sync with the enum variants in main.rs.
pub const HOOKS: &[HookEntry] = &[
    // cadence
    HookEntry {
        name: "terminology",
        description: "Block inclusive terminology violations",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "orphaned-todos",
        description: "Block orphaned code markers without issue references",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "prevent-secret-leaks",
        description: "Guard against reading/ingesting secrets",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "prevent-secret-writes",
        description: "Guard against writing/editing/deleting secrets",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "memory-guard",
        description: "Enforce MEMORY.md line limits",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "git-safety",
        description: "Block dangerous git operations",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "line-endings",
        description: "Validate shell script line endings",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "env-vars",
        description: "Warn about generic environment variable names",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-docs-update",
        description: "Nudge to review docs when creating a PR",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-overshare",
        description: "Nudge to audit about-to-ship content for personal-context overshare",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "nudge-polish-before-pr",
        description: "Nudge to run `/polish` before creating a PR",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "markdown-lint",
        description: "Run markdownlint on markdown files",
        plugin: "cadence",
        event: Some(HookEvent::PreToolUse),
    },
    // guardrails
    HookEntry {
        name: "guard-push-remote",
        description: "Block git push to non-owned remotes",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-gh-dangerous",
        description: "Block irreversible gh operations (repo delete)",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-gh-write",
        description: "Block gh write operations to non-owned repos",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-git-init",
        description: "Nudge to scaffold and confirm license after git init or gh repo create",
        plugin: "guardrails",
        event: Some(HookEvent::PostToolUse),
    },
    HookEntry {
        name: "warn-main-branch",
        description: "Warn when editing on main/master branch",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "check-idle-return",
        description: "Nudge after idle periods between edits",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-branch-base",
        description: "Warn when creating a branch from a non-main base",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-cron-datetime",
        description: "Remind to check datetime before scheduling cron jobs",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "nudge-upgrade-after-push",
        description: "Nudge to schedule a brew upgrade after pushing cadence-hooks to main",
        plugin: "guardrails",
        event: Some(HookEvent::PostToolUse),
    },
    HookEntry {
        name: "warn-untracked",
        description: "Warn about untracked files during git commit operations",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-dotfiles",
        description: "Block direct edits to production dotfiles (opt-in)",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-pr-issue-link",
        description: "Nudge when gh pr create has no closing issue keyword",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "verify-pr-autoclose",
        description: "Verify and repair issue auto-close after PR create/merge",
        plugin: "guardrails",
        event: Some(HookEvent::PostToolUse),
    },
    HookEntry {
        name: "guard-op-vault-scan",
        description: "Block uninvited 1Password vault enumeration (op item list)",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-curl-alias",
        description: "Warn when bare curl (aliased to curlie) is used with custom headers",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-gh-merge-preflight",
        description: "Pre-flight checklist nudge before gh pr merge (draft, worktree, verify)",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-coderabbit-retrigger",
        description: "Warn that CodeRabbit re-trigger comments are no-ops on reviewed content",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-alias-parsing",
        description: "Warn when piping aliased-tool output (ls/find/cat/du/df/top) into parsers",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-browser-device",
        description: "Block the first Claude-in-Chrome action per session until the device is confirmed",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "inject-gh-context",
        description: "Inject the gh-write allowlist + `-R` rule on SessionStart",
        plugin: "guardrails",
        event: Some(HookEvent::SessionStart),
    },
    // rules
    HookEntry {
        name: "validate-frontmatter",
        description: "Validate SKILL.md and command frontmatter",
        plugin: "rules",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "security-patterns",
        description: "Scan for security anti-patterns",
        plugin: "rules",
        event: Some(HookEvent::PostToolUse),
    },
    // obsidian
    HookEntry {
        name: "trash-guard",
        description: "Block rm in Obsidian vault (use .trash/ instead)",
        plugin: "obsidian",
        event: Some(HookEvent::PreToolUse),
    },
    // metrics
    HookEntry {
        name: "snapshot",
        description: "Snapshot HEAD before a git commit (PreToolUse)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-commit",
        description: "Log cost-per-commit after a git commit (PostToolUse)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-subagent",
        description: "Log subagent lifecycle (SubagentStart / SubagentStop)",
        plugin: "metrics",
        event: None,
    },
    // lab
    HookEntry {
        name: "persona-nudge",
        description: "Inject the self-representation contract on session start",
        plugin: "lab",
        event: Some(HookEvent::SessionStart),
    },
    HookEntry {
        name: "persona-gate",
        description: "Validate and promote a self-representation candidate",
        plugin: "lab",
        event: Some(HookEvent::PostToolUse),
    },
    // session (cadence-canon)
    HookEntry {
        name: "start",
        description: "Register this session in the repo registry and disclose live peers",
        plugin: "session",
        event: Some(HookEvent::SessionStart),
    },
    HookEntry {
        name: "heartbeat",
        description: "Touch this session's registry file (mtime is the liveness signal)",
        plugin: "session",
        event: None,
    },
    HookEntry {
        name: "guard",
        description: "Warn when an action intersects a live peer session's lane",
        plugin: "session",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-branch-drift",
        description: "Warn when HEAD drifted from the session's recorded branch at git commit",
        plugin: "session",
        event: Some(HookEvent::PreToolUse),
    },
];

/// The registry entry for `<namespace> <subcommand>`, if one exists.
pub fn entry(namespace: &str, subcommand: &str) -> Option<&'static HookEntry> {
    HOOKS
        .iter()
        .find(|h| h.plugin == namespace && h.name == subcommand)
}

/// Per-hook sample payload overrides for `try` and the interactive-terminal
/// guidance.
///
/// Hooks not listed here fall back to event-based samples
/// ([`HookEvent::sample_payload`] for checks, `LOGGER_SAMPLE_PAYLOAD` for
/// loggers). Overrides exist where the generic sample would exercise the
/// wrong branch — loggers gate on `hook_event_name` and specific command
/// shapes, so a generic payload can no-op while appearing healthy.
///
/// Every sample here must deserialize as `MetricsInput` (loggers) or
/// `HookInput` (checks) — enforced by unit test.
pub fn sample_for(namespace: &str, subcommand: &str) -> Option<&'static str> {
    match (namespace, subcommand) {
        // snapshot gates on a `git commit` command (PreToolUse partner of log-commit)
        ("metrics", "snapshot") => Some(
            r#"{"session_id":"test","hook_event_name":"PreToolUse","tool_input":{"command":"git commit -m test"}}"#,
        ),
        // log-commit gates on a `git commit` command after it ran
        ("metrics", "log-commit") => Some(
            r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_input":{"command":"git commit -m test"},"transcript_path":"/tmp/transcript.jsonl"}"#,
        ),
        // log-subagent only reacts to SubagentStart / SubagentStop
        ("metrics", "log-subagent") => Some(
            r#"{"session_id":"test","hook_event_name":"SubagentStop","agent_id":"agent-1","agent_type":"Explore","duration_ms":1234}"#,
        ),
        // warn-branch-drift early-exits unless the command is a git commit —
        // the generic PreToolUse sample (`git status`) would never reach the
        // drift comparison.
        ("session", "warn-branch-drift") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"git commit -m test"}}"#,
        ),
        _ => None,
    }
}

/// True when `<namespace> <subcommand>` names a registered hook.
pub fn is_known(namespace: &str, subcommand: &str) -> bool {
    entry(namespace, subcommand).is_some()
}

/// If `subcommand` exists under a different namespace, return that namespace.
/// Used for "namespace mismatch" diagnostics.
pub fn namespace_of(subcommand: &str) -> Option<&'static str> {
    HOOKS
        .iter()
        .find(|h| h.name == subcommand)
        .map(|h| h.plugin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_known_true_for_real_pair() {
        assert!(is_known("guardrails", "guard-push-remote"));
    }

    #[test]
    fn is_known_false_for_unknown_subcommand() {
        assert!(!is_known("guardrails", "nonexistent-hook"));
    }

    #[test]
    fn is_known_false_for_known_subcommand_in_wrong_namespace() {
        // guard-push-remote belongs to guardrails, not cadence
        assert!(!is_known("cadence", "guard-push-remote"));
    }

    #[test]
    fn namespace_of_returns_correct_namespace() {
        assert_eq!(namespace_of("guard-push-remote"), Some("guardrails"));
    }

    #[test]
    fn namespace_of_returns_none_for_nonexistent() {
        assert_eq!(namespace_of("nonexistent"), None);
    }

    #[test]
    fn entry_returns_event_for_sample_payload_selection() {
        let e = entry("lab", "persona-nudge").expect("persona-nudge registered");
        assert_eq!(e.event, Some(HookEvent::SessionStart));
    }

    #[test]
    fn entry_returns_none_for_unknown_pair() {
        assert!(entry("cadence", "guard-push-remote").is_none());
    }

    #[test]
    fn sample_overrides_exist_for_event_gated_loggers() {
        // These three loggers gate on specific hook_event_name values or
        // command shapes — the generic fallback would no-op them.
        for name in ["snapshot", "log-commit", "log-subagent"] {
            assert!(
                sample_for("metrics", name).is_some(),
                "{name} needs a sample override"
            );
        }
        // heartbeat reacts to any tool event — generic fallback is correct.
        assert!(sample_for("session", "heartbeat").is_none());
        assert!(sample_for("cadence", "terminology").is_none());
    }

    #[test]
    fn sample_overrides_parse_as_metrics_input() {
        for hook in HOOKS {
            if let Some(sample) = sample_for(hook.plugin, hook.name) {
                let parsed = cadence_hooks_core::MetricsInput::from_json(sample);
                assert!(
                    parsed.is_ok(),
                    "sample for {} {} must parse: {:?}",
                    hook.plugin,
                    hook.name,
                    parsed.err()
                );
            }
        }
    }

    #[test]
    fn log_subagent_sample_uses_subagent_event() {
        let sample = sample_for("metrics", "log-subagent").unwrap();
        let parsed = cadence_hooks_core::MetricsInput::from_json(sample).unwrap();
        assert_eq!(parsed.hook_event_name.as_deref(), Some("SubagentStop"));
    }

    #[test]
    fn only_loggers_have_no_event() {
        // Fire-and-forget loggers react to `hook_event_name` in the payload
        // rather than a fixed event; everything else must declare one.
        let loggers = ["snapshot", "log-commit", "log-subagent", "heartbeat"];
        for hook in HOOKS {
            if loggers.contains(&hook.name) {
                assert!(
                    hook.event.is_none(),
                    "{} is a logger and should have event: None",
                    hook.name
                );
            } else {
                assert!(
                    hook.event.is_some(),
                    "{} is a check and must declare its event",
                    hook.name
                );
            }
        }
    }
}
