//! Single source of truth for the hook catalog.
//! Backs `cadence-hooks list`, hook-name resolution, and `doctor`'s
//! subcommand cross-reference (issue #39 P1).

/// A hook entry with its name, description, and plugin group.
pub struct HookEntry {
    pub name: &'static str,
    pub description: &'static str,
    /// CLI namespace: cadence | guardrails | rules | obsidian | metrics | lab
    pub plugin: &'static str,
}

/// Complete catalog of all hooks. Single source of truth for `list` output
/// and `hook_name()` resolution. Keep in sync with the enum variants in main.rs.
pub const HOOKS: &[HookEntry] = &[
    // cadence
    HookEntry {
        name: "terminology",
        description: "Block inclusive terminology violations",
        plugin: "cadence",
    },
    HookEntry {
        name: "orphaned-todos",
        description: "Block orphaned code markers without issue references",
        plugin: "cadence",
    },
    HookEntry {
        name: "prevent-secret-leaks",
        description: "Guard against reading/ingesting secrets",
        plugin: "cadence",
    },
    HookEntry {
        name: "prevent-secret-writes",
        description: "Guard against writing/editing/deleting secrets",
        plugin: "cadence",
    },
    HookEntry {
        name: "memory-guard",
        description: "Enforce MEMORY.md line limits",
        plugin: "cadence",
    },
    HookEntry {
        name: "git-safety",
        description: "Block dangerous git operations",
        plugin: "cadence",
    },
    HookEntry {
        name: "line-endings",
        description: "Validate shell script line endings",
        plugin: "cadence",
    },
    HookEntry {
        name: "env-vars",
        description: "Warn about generic environment variable names",
        plugin: "cadence",
    },
    HookEntry {
        name: "warn-docs-update",
        description: "Nudge to review docs when creating a PR",
        plugin: "cadence",
    },
    HookEntry {
        name: "nudge-polish-before-pr",
        description: "Nudge to run `/polish` before creating a PR",
        plugin: "cadence",
    },
    HookEntry {
        name: "markdown-lint",
        description: "Run markdownlint on markdown files",
        plugin: "cadence",
    },
    // guardrails
    HookEntry {
        name: "guard-push-remote",
        description: "Block git push to non-owned remotes",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-gh-dangerous",
        description: "Block irreversible gh operations (repo delete)",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-gh-write",
        description: "Block gh write operations to non-owned repos",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-git-init",
        description: "Nudge to scaffold after git init",
        plugin: "guardrails",
    },
    HookEntry {
        name: "warn-main-branch",
        description: "Warn when editing on main/master branch",
        plugin: "guardrails",
    },
    HookEntry {
        name: "check-idle-return",
        description: "Nudge after idle periods between edits",
        plugin: "guardrails",
    },
    HookEntry {
        name: "warn-branch-base",
        description: "Warn when creating a branch from a non-main base",
        plugin: "guardrails",
    },
    HookEntry {
        name: "warn-cron-datetime",
        description: "Remind to check datetime before scheduling cron jobs",
        plugin: "guardrails",
    },
    HookEntry {
        name: "nudge-upgrade-after-push",
        description: "Nudge to schedule a brew upgrade after pushing cadence-hooks to main",
        plugin: "guardrails",
    },
    HookEntry {
        name: "warn-untracked",
        description: "Warn about untracked files during git commit operations",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-dotfiles",
        description: "Block direct edits to production dotfiles (opt-in)",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-pr-issue-link",
        description: "Block gh pr create without a closing issue keyword",
        plugin: "guardrails",
    },
    HookEntry {
        name: "verify-pr-autoclose",
        description: "Verify and repair issue auto-close after PR create/merge",
        plugin: "guardrails",
    },
    HookEntry {
        name: "guard-op-vault-scan",
        description: "Block uninvited 1Password vault enumeration (op item list)",
        plugin: "guardrails",
    },
    // rules
    HookEntry {
        name: "validate-frontmatter",
        description: "Validate SKILL.md and command frontmatter",
        plugin: "rules",
    },
    HookEntry {
        name: "security-patterns",
        description: "Scan for security anti-patterns",
        plugin: "rules",
    },
    // obsidian
    HookEntry {
        name: "trash-guard",
        description: "Block rm in Obsidian vault (use .trash/ instead)",
        plugin: "obsidian",
    },
    // metrics
    HookEntry {
        name: "snapshot",
        description: "Snapshot HEAD before a git commit (PreToolUse)",
        plugin: "metrics",
    },
    HookEntry {
        name: "log-commit",
        description: "Log cost-per-commit after a git commit (PostToolUse)",
        plugin: "metrics",
    },
    HookEntry {
        name: "log-subagent",
        description: "Log subagent lifecycle (SubagentStart / SubagentStop)",
        plugin: "metrics",
    },
    // lab
    HookEntry {
        name: "persona-nudge",
        description: "Inject the self-representation contract on session start",
        plugin: "lab",
    },
    HookEntry {
        name: "persona-gate",
        description: "Validate and promote a self-representation candidate",
        plugin: "lab",
    },
];

/// True when `<namespace> <subcommand>` names a registered hook.
pub fn is_known(namespace: &str, subcommand: &str) -> bool {
    HOOKS
        .iter()
        .any(|h| h.plugin == namespace && h.name == subcommand)
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
}
