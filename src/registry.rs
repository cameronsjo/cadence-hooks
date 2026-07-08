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
    HookEntry {
        name: "redact-external-content",
        description: "Nudge when an external post mentions internal harness vocabulary",
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
        name: "enforce-worktree",
        description: "Block mutations in a primary checkout of a branch-mode repo",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-subagent-worktree",
        description: "Warn when dispatching a subagent from main while a sibling worktree exists",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-subagent-concurrency",
        description: "Nudge when live subagents reach the concurrency cap on an Agent/Task spawn",
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
        name: "guard-rm",
        description: "Path-aware rm triage: allow temp/managed, block home/vault/repo, ask the rest",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "guard-read-model",
        description: "Block Read/Grep by resolved session model (opt-in)",
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
        name: "warn-issue-tracker",
        description: "Nudge when gh issue create targets a repo other than the canonical tracker",
        plugin: "guardrails",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-going-public",
        description: "Nudge on repo create/publicize when name or description telegraphs sensitive content",
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
    HookEntry {
        name: "warn-recommended-option",
        description: "Nudge to label a recommended AskUserQuestion option \"(Recommended)\"",
        plugin: "rules",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "warn-empty-answers",
        description: "Nudge to re-ask when AskUserQuestion returns empty auto-approve answers",
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
    HookEntry {
        name: "log-session",
        description: "Log per-session cost at SessionEnd (SessionEnd)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-session-start",
        description: "Capture session start timestamp (SessionStart)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-plan-phase",
        description: "Log plan-lifecycle events: EnterPlanMode / ExitPlanMode (PostToolUse)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-polish-nudge",
        description: "Log polish-nudge skips: gh pr create + whether /polish ran (PostToolUse)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-ask-user-question",
        description: "Log AskUserQuestion stance + shape on every call (PreToolUse)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "log-skill",
        description: "Log skill invocations (PostToolUse:Skill)",
        plugin: "metrics",
        event: None,
    },
    HookEntry {
        name: "warn-stale",
        description: "Warn at SessionStart when metrics telemetry has gone stale",
        plugin: "metrics",
        event: Some(HookEvent::SessionStart),
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
    HookEntry {
        name: "warn-branch-intent",
        description: "Nudge when new work starts on a stale, unrelated feature branch",
        plugin: "session",
        event: Some(HookEvent::PreToolUse),
    },
    HookEntry {
        name: "end",
        description: "Deregister this session's registry file when it ends (SessionEnd)",
        plugin: "session",
        event: None,
    },
    HookEntry {
        name: "backstop-record",
        description: "Record loose ends at session end for the next start to surface (SessionEnd)",
        plugin: "session",
        event: None,
    },
    HookEntry {
        name: "backstop-warn",
        description: "Warn at session start when the last session left loose ends",
        plugin: "session",
        event: Some(HookEvent::SessionStart),
    },
];

/// The registry entry for `<namespace> <subcommand>`, if one exists.
pub fn entry(namespace: &str, subcommand: &str) -> Option<&'static HookEntry> {
    HOOKS
        .iter()
        .find(|h| h.plugin == namespace && h.name == subcommand)
}

/// The plugin namespace for a canonical hook `name`, if it is registered.
/// Used by the dispatch self-timing write to tag which plugin owns a slow hook.
pub fn plugin_for(name: &str) -> Option<&'static str> {
    HOOKS.iter().find(|h| h.name == name).map(|h| h.plugin)
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
        // log-session gates on hook_event_name == "SessionEnd" and scans the
        // transcript; the generic logger sample carries a different event and
        // no transcript, so it would no-op before writing a row.
        ("metrics", "log-session") => Some(
            r#"{"session_id":"test","hook_event_name":"SessionEnd","transcript_path":"/tmp/transcript.jsonl","cwd":"/tmp","reason":"prompt_input_exit"}"#,
        ),
        // log-session-start gates on hook_event_name == "SessionStart"; the
        // generic logger sample carries a different event and would no-op.
        ("metrics", "log-session-start") => {
            Some(r#"{"session_id":"test","hook_event_name":"SessionStart","cwd":"/tmp"}"#)
        }
        // log-plan-phase gates on hook_event_name == "PostToolUse" plus a
        // tool_name of EnterPlanMode/ExitPlanMode; the generic logger sample
        // carries neither and would no-op.
        ("metrics", "log-plan-phase") => Some(
            r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"ExitPlanMode","transcript_path":"/tmp/transcript.jsonl","cwd":"/tmp"}"#,
        ),
        // log-polish-nudge gates on a `gh pr create` command (the nudge denominator)
        ("metrics", "log-polish-nudge") => Some(
            r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_input":{"command":"gh pr create --title test"},"transcript_path":"/tmp/transcript.jsonl"}"#,
        ),
        // log-ask-user-question records every AskUserQuestion call's stance +
        // shape; the generic logger sample carries no `questions` and would no-op.
        ("metrics", "log-ask-user-question") => Some(
            r#"{"session_id":"test","hook_event_name":"PreToolUse","model":"claude-opus-4-8","tool_input":{"questions":[{"question":"Which approach?","header":"Approach","multiSelect":false,"options":[{"label":"Option A","description":"first"},{"label":"Option B","description":"second"}]}]}}"#,
        ),
        // log-skill gates on tool_name == "Skill"; the generic PostToolUse
        // logger sample carries no tool_name and would no-op.
        ("metrics", "log-skill") => Some(
            r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"Skill","cwd":"/tmp","tool_input":{"skill":"cadence:attune","args":"execute C8"}}"#,
        ),
        // warn-branch-drift early-exits unless the command is a git commit —
        // the generic PreToolUse sample (`git status`) would never reach the
        // drift comparison.
        ("session", "warn-branch-drift") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"git commit -m test"}}"#,
        ),
        // warn-branch-intent gates on an Edit/Write mutation; the generic
        // PreToolUse sample carries no cwd, so it would fail open before the
        // registry/git evaluation. This Edit payload exercises the guard path
        // and fail-opens cleanly (cwd not a registered session).
        ("session", "warn-branch-intent") => Some(
            r#"{"session_id":"test","tool_name":"Edit","cwd":"/tmp","tool_input":{"file_path":"/tmp/x.rs"}}"#,
        ),
        // end gates on hook_event_name == "SessionEnd"; the generic logger
        // sample carries a different event and would no-op before the gate.
        ("session", "end") => {
            Some(r#"{"session_id":"test","hook_event_name":"SessionEnd","cwd":"/tmp"}"#)
        }
        // warn-recommended-option: a question with no "(Recommended)" option → nudge
        ("rules", "warn-recommended-option") => Some(
            r#"{"tool_name":"AskUserQuestion","tool_input":{"questions":[{"question":"Which approach?","header":"Approach","multiSelect":false,"options":[{"label":"Option A","description":"first"},{"label":"Option B","description":"second"}]}]}}"#,
        ),
        // warn-empty-answers: a PostToolUse response with empty answers → nudge
        ("rules", "warn-empty-answers") => Some(
            r#"{"tool_name":"AskUserQuestion","tool_input":{"questions":[{"question":"Which approach?","options":[{"label":"Option A"}]}]},"tool_response":{"answers":{"Which approach?":""}}}"#,
        ),
        // backstop-record gates on hook_event_name == "SessionEnd" too — the
        // generic logger sample would no-op before the gate.
        ("session", "backstop-record") => {
            Some(r#"{"session_id":"test","hook_event_name":"SessionEnd","cwd":"/tmp"}"#)
        }
        // backstop-warn is a SessionStart check; carry a cwd so `try` resolves a
        // sessions dir instead of the cwd-less event sample.
        ("session", "backstop-warn") => {
            Some(r#"{"session_id":"test","source":"startup","cwd":"/tmp"}"#)
        }
        // warn-subagent-worktree only engages on an Agent/Task spawn; the generic
        // Bash PreToolUse sample would no-op. Carry a cwd so the git checks have a
        // directory to resolve against.
        ("guardrails", "warn-subagent-worktree") => Some(
            r#"{"tool_name":"Agent","tool_input":{"subagent_type":"general-purpose"},"cwd":"/tmp"}"#,
        ),
        // warn-subagent-concurrency only engages on an Agent/Task spawn; the
        // generic Bash PreToolUse sample would no-op before the log read.
        ("guardrails", "warn-subagent-concurrency") => Some(
            r#"{"tool_name":"Agent","tool_input":{"subagent_type":"general-purpose"},"cwd":"/tmp"}"#,
        ),
        // enforce-worktree only engages on a file mutation or git commit; the
        // generic Bash sample would no-op. Note `try` substitutes the process
        // cwd, so from a real primary checkout this smoke-tests live state.
        ("guardrails", "enforce-worktree") => Some(
            r#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/sample/file.txt"},"cwd":"/tmp"}"#,
        ),
        // guard-read-model only gates Read/Grep; the generic Bash PreToolUse
        // sample would no-op. Carry a Read payload so `try`/list fail-open cleanly
        // (no MODELS env in a smoke run → disabled → allow).
        ("guardrails", "guard-read-model") => {
            Some(r#"{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"cwd":"/tmp"}"#)
        }
        // guard-rm only engages on an rm-family Bash command; the generic
        // `git status` sample would find no delete target and no-op. Carry an
        // absolute /tmp target so the smoke run resolves ALLOW independent of
        // the process cwd `try` substitutes.
        ("guardrails", "guard-rm") => Some(
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/scratch/foo"},"cwd":"/tmp"}"#,
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
        // These loggers gate on specific hook_event_name values or command
        // shapes — the generic fallback would no-op them.
        for name in [
            "snapshot",
            "log-commit",
            "log-subagent",
            "log-session",
            "log-plan-phase",
        ] {
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
        let loggers = [
            "snapshot",
            "log-commit",
            "log-subagent",
            "log-session",
            "log-session-start",
            "log-plan-phase",
            "log-polish-nudge",
            "log-ask-user-question",
            "log-skill",
            "heartbeat",
            "end",
            "backstop-record",
        ];
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
