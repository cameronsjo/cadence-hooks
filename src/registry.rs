//! Single source of truth for the hook catalog.
//! Backs `cadence-hooks list`, hook-name resolution, `doctor`'s
//! subcommand cross-reference (issue #39 P1), and `try`'s sample-payload
//! selection (issue #56).

use cadence_hooks_core::HookEvent;

/// A hook entry with its name, description, CLI namespace, and event.
pub struct HookEntry {
    pub name: &'static str,
    pub description: &'static str,
    /// The clap namespace this subcommand is dispatched under. The valid
    /// set is derived from `Cli::command()` by `registry_matches_clap_dispatch`
    /// (src/main.rs), not hand-enumerated here, so this field is held to
    /// exactly the namespaces clap declares, in both directions.
    ///
    /// **Not the Claude Code plugin that wires the hook**, and the two differ:
    /// every `session` subcommand is wired by the always-on `cadence` plugin,
    /// because plan and session state must reach a session that enables nothing
    /// else. This field was called `plugin` until cadence-hooks#884, which is
    /// what made that read as a claim about ownership. Owning-plugin truth
    /// lives in `tests/hook_registration_audit.rs` — the `BINARY_PLUGIN_DIRS`
    /// mapping and the `INTENTIONAL_CROSS_PLUGIN_HOOKS` table — which is
    /// checked against the real `hooks.json` manifests.
    pub namespace: &'static str,
    /// Every hook event this command is wired on. The first entry is the
    /// primary event — the one `try` builds its sample payload from and the one
    /// main.rs's dispatch passes as the fallback. More than one entry marks a
    /// multi-event hook (`model-posture`), whose dispatch resolves the reported
    /// event from the payload's `hook_event_name`. Empty for fire-and-forget
    /// loggers, which react to `hook_event_name` in the payload rather than a
    /// fixed event. Keep the primary in sync with the dispatch in main.rs.
    pub events: &'static [HookEvent],
    /// What this hook does under `CLAUDE_CODE_REMOTE=true` (a Claude Code cloud
    /// session). Required, so a new hook cannot ship without a decision
    /// (cameronsjo/cadence-hooks#1197). Each entry carries a one-line rationale
    /// comment above the field.
    pub remote: RemotePolicy,
    /// Whether a repo's `.claude/cadence.json` `nudges` map may silence this
    /// hook's **nudge** outcomes (cameronsjo/cadence-hooks#216, ADR-0002 §3).
    /// Required, so a new hook cannot ship without the decision.
    ///
    /// `true` only for a hook that is advisory end to end: it never blocks and
    /// never asks, is not in `PROTECTED_GUARDS` or `SECURITY_CRITICAL_HOOKS`,
    /// and reacts to a tool call or session event (not a logger). Dispatch
    /// enforces the field independently of `doctor`, and only ever rewrites a
    /// `Nudge` outcome, so a `Block` or `Ask` is untouched even for a
    /// suppressible hook. When unsure, `false`: suppression is opt-in.
    /// `registry_suppressible_entries_are_advisory_only` holds the invariants.
    pub suppressible: bool,
}

/// A hook's behavior in a cloud session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemotePolicy {
    /// Runs exactly as it does locally.
    Run,
    /// Exits 0 with no output: the hook's job is machine-local state or a local
    /// workflow that does not exist in a throwaway VM.
    SelfDisable,
    /// Exits 2 with the reason on stderr. No hook uses it yet; the variant is
    /// part of the declared policy surface.
    #[allow(dead_code)]
    BlockWithReason(&'static str),
}

impl RemotePolicy {
    /// The stable label the manifest and docs use.
    pub fn label(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::SelfDisable => "self-disable",
            Self::BlockWithReason(_) => "block-with-reason",
        }
    }
}

/// What dispatch does about `hook` given whether this is a cloud session.
/// `None` runs the hook; `Some(policy)` is a policy that stops it. Pure over
/// its inputs so the table is testable without the process env.
pub fn remote_gate(hook: &str, remote: bool) -> Option<RemotePolicy> {
    if !remote {
        return None;
    }
    let entry = HOOKS.iter().find(|h| h.name == hook)?;
    match entry.remote {
        RemotePolicy::Run => None,
        stop => Some(stop),
    }
}

/// Apply the remote policy for `hook` to this process: exit 0 silently for a
/// self-disabled hook, exit 2 with the reason for a blocked one, return for
/// everything else. Called after the `CADENCE_DISABLE` resolution and before
/// any stdin is read.
pub fn enforce_remote_policy(hook: &str) {
    match remote_gate(hook, cadence_hooks_core::remote::is_remote()) {
        None | Some(RemotePolicy::Run) => {}
        Some(RemotePolicy::SelfDisable) => std::process::exit(0),
        Some(RemotePolicy::BlockWithReason(reason)) => {
            eprintln!("cadence-hooks: {hook} is blocked in cloud sessions: {reason}");
            std::process::exit(2);
        }
    }
}

impl HookEntry {
    /// The primary event (`events[0]`); `None` for a logger.
    pub fn event(&self) -> Option<HookEvent> {
        self.events.first().copied()
    }

    /// Every event, comma-joined, or `logger` when there is none — the label
    /// `list` and `try` print.
    pub fn events_label(&self) -> String {
        if self.events.is_empty() {
            return "logger".to_string();
        }
        self.events
            .iter()
            .map(HookEvent::name)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Complete catalog of all hooks. Single source of truth for `list` output
/// and `hook_name()` resolution. Keep in sync with the enum variants in main.rs.
pub const HOOKS: &[HookEntry] = &[
    // cadence
    HookEntry {
        name: "terminology",
        description: "Block inclusive terminology violations",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content guard; no machine-local state.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "orphaned-todos",
        description: "Block orphaned code markers without issue references",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content guard; no machine-local state.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "prevent-secret-leaks",
        description: "Guard against reading/ingesting secrets",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "prevent-secret-writes",
        description: "Guard against writing/editing/deleting secrets",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "prevent-secret-push",
        description: "Block a git push that would publish a secret-named file, a credential token, or a commit or tag message or ref name carrying one",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "memory-guard",
        description: "Enforce MEMORY.md line limits",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge; harmless when the local memory dir is absent.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "git-safety",
        description: "Block dangerous git operations",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "line-endings",
        description: "Validate shell script line endings",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content guard; no machine-local state.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "env-vars",
        description: "Warn about generic environment variable names",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content guard; no machine-local state.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-docs-update",
        description: "Nudge to review docs when creating a PR",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge about the repo's own content.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-changelog-entry",
        description: "Nudge to add a CHANGELOG.md entry when shipping code changes",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge about the repo's own content.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-overshare",
        description: "Nudge to audit about-to-ship content for personal-context overshare",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge about the repo's own content.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-instruction-narrative",
        description: "Nudge when an always-loaded instruction file (CLAUDE.md, AGENTS.md) gains narrative",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge about the repo's own content.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-live-memory-write",
        description: "Nudge on a direct write to live auto-memory outside a dream adoption window",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge; harmless when the local memory dir is absent.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-plugin-root-cruft",
        description: "Nudge on a write creating plugin-root docs/ or scripts/ in a plugin marketplace",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge about the repo's own content.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "nudge-polish-before-pr",
        description: "Nudge to run `/polish` before creating a PR",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge; cloud sessions ship PRs too.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "markdown-lint",
        description: "Run markdownlint on markdown files",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only lint; fails open when no markdownlint CLI is on PATH.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "audit-runner-pool",
        description: "Run the runner-pool workflow audit after a workflow file is edited; findings return as a nudge",
        namespace: "cadence",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only audit of the edited workflow file.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "redact-external-content",
        description: "Nudge when an external post mentions internal harness vocabulary",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-held-close",
        description: "Block `gh issue close` when the target is on the HELD-issue ledger (`--ledger` file, or `CADENCE_DRAIN_HELD`)",
        namespace: "cadence",
        events: &[HookEvent::PreToolUse],
        // Remote: security guard; the cloud VM still needs it.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "platform-drift",
        description: "Nudge when cadence-hooks or Claude Code has drifted behind the plugin-shipped platform baseline",
        namespace: "cadence",
        events: &[HookEvent::SessionStart],
        // Remote: read-only; ruled Run for cloud sessions (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        // Wired on SessionStart *and* PostModelSwitch; the subcommand picks its
        // half from the payload's `hook_event_name`. The first event is primary.
        name: "model-posture",
        description: "Inject the Fable seat posture at session start and on a switch onto Fable",
        namespace: "cadence",
        events: &[HookEvent::SessionStart, HookEvent::PostModelSwitch],
        // Remote: read-only; ruled Run for cloud sessions (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    // guardrails
    HookEntry {
        name: "guard-push-remote",
        description: "Block git push to non-owned remotes",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: the guards worth having in the cloud (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-gh-dangerous",
        description: "Block irreversible gh operations (repo delete)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: the guards worth having in the cloud (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-gh-write",
        description: "Block gh write operations to non-owned repos",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: the guards worth having in the cloud (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-forge-write",
        description: "Block tea/glab write operations to non-owned repos",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: an owner-allowlist write guard, like guard-gh-write (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-critical-grade",
        description: "Block applying impact:critical / likelihood:critical labels without a human ruling",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: a label-write guard like guard-gh-write; cloud sessions carry
        // the same token, so the same preventive control applies (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-git-init",
        description: "Nudge to scaffold and confirm license after git init or gh repo create",
        namespace: "guardrails",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only guard.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-main-branch",
        description: "Warn when editing on main/master branch",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: nudge only; a fresh clone starts on the default branch.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "enforce-worktree",
        description: "Block mutations in a primary checkout of a branch-mode repo",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: the fresh cloud clone is the primary checkout and all work lands on a session branch, so the guard would block every commit.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "warn-subagent-worktree",
        description: "Warn when dispatching a subagent from main while a sibling worktree exists",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: steers toward sibling worktrees, which a single-clone cloud VM does not use.
        remote: RemotePolicy::SelfDisable,
        suppressible: true,
    },
    HookEntry {
        name: "warn-agent-dispatch",
        description: "Warn on an Agent/Task dispatch with no model, a model on a fork, or an execution brief with no isolated HOME",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-branch-base",
        description: "Warn when creating a branch from a non-main base",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-cron-datetime",
        description: "Remind to check datetime before scheduling cron jobs",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "nudge-upgrade-after-push",
        description: "Nudge to schedule a brew upgrade after pushing cadence-hooks to main",
        namespace: "guardrails",
        events: &[HookEvent::PostToolUse],
        // Remote: suggests a local cron and a script that does not exist in the plugin.
        remote: RemotePolicy::SelfDisable,
        suppressible: true,
    },
    HookEntry {
        name: "warn-untracked",
        description: "Warn about untracked files during git commit operations",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-amend-pushed",
        description: "Warn when git commit --amend rewrites a commit a remote already has",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "guard-dotfiles",
        description: "Block direct edits to production dotfiles (opt-in)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "enforcement-status",
        description: "Report at SessionStart when CADENCE_BYPASS=1 or CADENCE_DISABLE names a protected guard; in a cloud session (CLAUDE_CODE_REMOTE=true) also one ARMED/INERT line",
        namespace: "guardrails",
        events: &[HookEvent::SessionStart],
        // Remote: carries the ARMED/INERT line (#1197); must survive.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-read-model",
        description: "Block Read/Grep by resolved session model (opt-in)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-pr-issue-link",
        description: "Nudge when gh pr create has no closing issue keyword",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "guard-body-budget",
        description: "Measure gh pr/issue bodies against a per-surface word budget",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-issue-tracker",
        description: "Nudge when gh issue create targets a repo other than the canonical tracker",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-going-public",
        description: "Nudge on repo create/publicize when name or description telegraphs sensitive content",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-inline-body",
        description: "Nudge when gh pr/issue create posts a long body inline instead of via --body-file",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "verify-pr-autoclose",
        description: "Verify and repair issue auto-close after PR create/merge",
        namespace: "guardrails",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "guard-sops-decrypt",
        description: "Block a sops decrypt whose plaintext is not consumed by an allowed tool",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: no-op when the tool is absent; harmless to keep armed.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-runbook-scrub",
        description: "Block an unscrubbed write into $CADENCE_RUNBOOKS_DIR (content-hash scrub marker)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: inert unless CADENCE_RUNBOOKS_DIR is set; harmless to keep armed.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "guard-op-vault-scan",
        description: "Block uninvited 1Password vault enumeration (op item list)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: no-op when the tool is absent; harmless to keep armed.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-curl-alias",
        description: "Warn when bare curl (aliased to curlie) is used with custom headers",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-gh-merge-preflight",
        description: "Pre-flight checklist nudge before gh pr merge (draft, worktree, verify)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-unreviewed-ready-flip",
        description: "Warn on gh pr ready/merge when the PR head has no reviewed signal (human APPROVED or a clean cadence-review marker)",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-chezmoi-apply",
        description: "Warn when `chezmoi apply` would overwrite files `chezmoi status` shows drifted locally; the nudge flags an unscoped apply",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only nudge; no-op without chezmoi.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-entry-posture",
        description: "Warn on a session's first write in a linked worktree whose branch has no upstream or no open PR",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-stacked-base-delete",
        description: "Warn before deleting a branch (`git push --delete`, `gh pr merge --delete-branch`) that open PRs use as their base",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-stale-pr-body",
        description: "Warn on `gh pr ready`/`gh pr merge` when the PR body was never edited since creation while the branch gained commits",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-alias-parsing",
        description: "Warn when piping aliased-tool output (ls/find/cat/du/df/top) into parsers",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "guard-browser-device",
        description: "Block the first Claude-in-Chrome action per session until the device is confirmed",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: no-op when the tool is absent; harmless to keep armed.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "inject-gh-write-context",
        description: "Re-inject the gh-write allowlist + `-R` rule before an untargeted gh write",
        namespace: "guardrails",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only guard or nudge over the command or repo.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    // rules
    HookEntry {
        name: "validate-frontmatter",
        description: "Validate SKILL.md, command, living-plan, and plugin-agent frontmatter",
        namespace: "rules",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content check.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "security-patterns",
        description: "Scan for security anti-patterns",
        namespace: "rules",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only content check.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-recommended-option",
        description: "Nudge to label a recommended AskUserQuestion option \"(Recommended)\"",
        namespace: "rules",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only content check.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-empty-answers",
        description: "Nudge to re-ask when AskUserQuestion returns empty auto-approve answers",
        namespace: "rules",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only content check.
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    // obsidian
    HookEntry {
        name: "trash-guard",
        description: "Block rm in Obsidian vault (use .trash/ instead)",
        namespace: "obsidian",
        events: &[HookEvent::PreToolUse],
        // Remote: guard over the tool call; inert without a vault.
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "trash-guard-liveness",
        description: "Report at SessionStart when a configured vault's trash-guard routes no longer judge as contracted",
        namespace: "obsidian",
        events: &[HookEvent::SessionStart],
        // Remote: probes a machine-local Obsidian vault configuration.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    // metrics
    HookEntry {
        name: "snapshot",
        description: "Snapshot HEAD before a git commit (PreToolUse)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-commit",
        description: "Log cost-per-commit after a git commit (PostToolUse)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-subagent",
        description: "Log subagent lifecycle (SubagentStart / SubagentStop)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-session",
        description: "Log per-session cost at SessionEnd (SessionEnd)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-session-start",
        description: "Capture session start timestamp (SessionStart)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-polish-nudge",
        description: "Log polish-nudge skips: gh pr create + whether /polish ran (PostToolUse)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-ask-user-question",
        description: "Log AskUserQuestion asked (PreToolUse) + answered (PostToolUse) events",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "log-skill",
        description: "Log skill invocations (PostToolUse:Skill)",
        namespace: "metrics",
        events: &[],
        // Remote: writes ledgers under the Claude config dir, lost with the VM.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "warn-stale",
        description: "Warn at SessionStart when metrics telemetry has gone stale",
        namespace: "metrics",
        events: &[HookEvent::SessionStart],
        // Remote: reports on metrics ledgers that cloud sessions never write.
        remote: RemotePolicy::SelfDisable,
        suppressible: true,
    },
    // session — the clap namespace for plan and session state. Wired by the
    // always-on `cadence` plugin, not by a plugin of its own: `cadence-canon`
    // used to own these and is retired (cadence-ecosystem ADR-0030 Phase 2),
    // so there is no `canon` namespace to carry (cadence-hooks#884).
    HookEntry {
        name: "start",
        description: "Register this session, disclose live peers, and surface in-flight plans",
        namespace: "session",
        events: &[HookEvent::SessionStart],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "heartbeat",
        description: "Touch this session's registry file (mtime is the liveness signal)",
        namespace: "session",
        events: &[],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "guard",
        description: "Warn when an action intersects a live peer session's lane",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "warn-branch-drift",
        description: "Warn when HEAD drifted from the session's recorded branch at git commit",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only against the repo (#1197).
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-branch-intent",
        description: "Nudge when new work starts on a stale, unrelated feature branch",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only against the repo (#1197).
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "warn-commit-provenance",
        description: "Nudge toward a Session-Id: trailer on a Claude-composed commit message",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: runs, but the Machine: field becomes the fixed value `cloud` (#1197).
        remote: RemotePolicy::Run,
        suppressible: true,
    },
    HookEntry {
        name: "end",
        description: "Deregister this session's registry file when it ends (SessionEnd)",
        namespace: "session",
        events: &[],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "backstop-record",
        description: "Record loose ends at session end for the next start to surface (SessionEnd)",
        namespace: "session",
        events: &[],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "backstop-warn",
        description: "Warn at session start when the last session left loose ends",
        namespace: "session",
        events: &[HookEvent::SessionStart],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: true,
    },
    HookEntry {
        name: "persist-plan-approval",
        description: "Persist an approved plan at approval, merging into its own frontmatter and nudging when it carries no settled Panel: line; CADENCE_NO_PERSIST_PLAN opts out (PostToolUse:ExitPlanMode)",
        namespace: "session",
        events: &[HookEvent::PostToolUse],
        // Remote: the session registry, lanes and plan store are machine-local; persist-plan-approval would write into the session's repo.
        remote: RemotePolicy::SelfDisable,
        suppressible: false,
    },
    HookEntry {
        name: "nudge-plan-tick",
        description: "Nudge once per session when successful commits keep skipping the branch's in-flight plan doc (PostToolUse:Bash)",
        namespace: "session",
        events: &[HookEvent::PostToolUse],
        // Remote: read-only against the repo (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "warn-plan-ready-flip",
        description: "Warn on gh pr ready/merge while the branch's plan is still in-flight or carries unticked boxes (PreToolUse:Bash)",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only against the repo (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "lint-plan-shape",
        description: "Block ExitPlanMode when the plan carries no settled Panel: line (escape: `Panel: none — <reason>`); nudge when other template stanzas are missing; every outcome carries the presentation reminders (subagents stopped, operator asked to see the plan); subagent calls and unreadable plans allow (PreToolUse:ExitPlanMode)",
        namespace: "session",
        events: &[HookEvent::PreToolUse],
        // Remote: read-only against the repo (#1197).
        remote: RemotePolicy::Run,
        suppressible: false,
    },
    HookEntry {
        name: "plan-driver",
        description: "Ask to confirm a /model switch (command or picker, attended TUI only: CLAUDE_CODE_ENTRYPOINT=cli and CLAUDE_CODE_SESSION_ATTENDED=1, never -p, stream-json, SDK or CLAUDE_CODE_REMOTE, where an ask refuses the switch) away from the Driver family of this session's in-flight plan — matched by frontmatter approved_session_id, else branch: (PreModelSwitch)",
        namespace: "session",
        events: &[HookEvent::PreModelSwitch],
        // Remote: read-only; the check self-silences under CLAUDE_CODE_REMOTE,
        // where a streamed /model cannot answer an ask and would be refused (#989).
        remote: RemotePolicy::Run,
        // It asks, never nudges.
        suppressible: false,
    },
];

/// Whether `.claude/cadence.json` may silence `hook`'s nudges. `false` for an
/// unknown name, so a typo suppresses nothing.
pub fn is_suppressible(hook: &str) -> bool {
    HOOKS.iter().any(|h| h.name == hook && h.suppressible)
}

/// The registry entry for `<namespace> <subcommand>`, if one exists.
pub fn entry(namespace: &str, subcommand: &str) -> Option<&'static HookEntry> {
    HOOKS
        .iter()
        .find(|h| h.namespace == namespace && h.name == subcommand)
}

/// Guards whose inability to parse a relevant operation must block rather than
/// fail open.
///
/// `pub(crate)` so `bypass_report`'s tests can cross-check it against
/// `cadence_hooks_core::bypass::PROTECTED_GUARDS` — two lists about the same
/// risk, maintained apart, whose divergences must be deliberate.
pub(crate) const SECURITY_CRITICAL_HOOKS: &[&str] = &[
    "prevent-secret-leaks",
    "prevent-secret-writes",
    "prevent-secret-push",
    "git-safety",
    "guard-push-remote",
    "guard-gh-dangerous",
    "guard-gh-write",
    "guard-op-vault-scan",
    "guard-sops-decrypt",
    "guard-runbook-scrub",
    "guard-browser-device",
    "guard-dotfiles",
    "enforce-worktree",
    "guard-read-model",
    "trash-guard",
];

/// True for guards whose inability to parse a relevant operation must block.
pub fn is_security_critical(name: &str) -> bool {
    SECURITY_CRITICAL_HOOKS.contains(&name)
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
        // model-posture picks its half from `hook_event_name` and only emits on
        // a Fable target; the generic SessionStart sample carries neither, so it
        // would report silence and prove nothing about the hook.
        ("cadence", "model-posture") => Some(
            r#"{"session_id":"test","hook_event_name":"PostModelSwitch","from_model":"claude-opus-5","to_model":"claude-fable-5-1","source":"command"}"#,
        ),
        // audit-runner-pool gates on a write to `.github/workflows/*.y{a,}ml`;
        // the generic PostToolUse sample names no file and would no-op.
        ("cadence", "audit-runner-pool") => Some(
            r#"{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"Write","cwd":"/tmp","tool_input":{"file_path":"/tmp/repo/.github/workflows/ci.yml","content":"name: ci\n"}}"#,
        ),
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
        // warn-unreviewed-ready-flip gates on `gh pr ready`/`gh pr merge`;
        // the generic PreToolUse sample carries neither the command nor a
        // real git remote, so the try run exercises the matcher then fails
        // open on the git-remote lookup (no origin in a sample cwd) —
        // useful signal without a live gh call.
        ("guardrails", "warn-unreviewed-ready-flip") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh pr merge 5 --squash"}}"#,
        ),
        // The five nudges-b hooks each gate on one command shape the generic
        // `git status` sample never reaches. guard-held-close allows here
        // unless `CADENCE_DRAIN_HELD` holds the named issue (`try` passes no
        // `--ledger`). warn-chezmoi-apply's sample is a dry run on purpose:
        // `try` must never execute `chezmoi status`, which runs templates.
        ("cadence", "guard-held-close") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh issue close 354 -R cameronsjo/cadence-ecosystem"}}"#,
        ),
        ("guardrails", "warn-chezmoi-apply") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"chezmoi apply --dry-run"}}"#,
        ),
        ("guardrails", "warn-entry-posture") => Some(
            r#"{"session_id":"test","tool_name":"Edit","cwd":"/tmp","tool_input":{"file_path":"/tmp/x.rs"}}"#,
        ),
        ("guardrails", "warn-stacked-base-delete") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"git push origin --delete feat/sample"}}"#,
        ),
        ("guardrails", "warn-stale-pr-body") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh pr ready 5"}}"#,
        ),
        // guard-critical-grade only engages on a gh call that applies a label;
        // the generic sample would allow without judging anything.
        ("guardrails", "guard-critical-grade") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh issue edit 12 --add-label impact:critical"}}"#,
        ),
        // guard-body-budget only engages on a gh posting subcommand carrying a
        // body flag; the generic PreToolUse sample (`git status`) would allow
        // without measuring anything.
        ("guardrails", "guard-body-budget") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh pr create --title test --body \"a short sample body\""}}"#,
        ),
        // warn-inline-body only engages on `gh pr|issue create` with an inline
        // body past the threshold; the generic sample (`git status`) would allow.
        ("guardrails", "warn-inline-body") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"gh issue create --title test --body \"This sample body is deliberately long enough to cross the inline-body threshold, so that try exercises the nudge path rather than the silent short-body allow. It says nothing else, and it is posted nowhere at all.\""}}"#,
        ),
        // warn-instruction-narrative only engages on a CLAUDE.md/AGENTS.md
        // write; the generic sample is a Bash call and would allow unjudged.
        ("cadence", "warn-instruction-narrative") => Some(
            r#"{"session_id":"test","tool_name":"Edit","tool_input":{"file_path":"/tmp/cadence-try/CLAUDE.md","old_string":"","new_string":"Pin the toolchain. It used to drift; verified on 2026-02-02."}}"#,
        ),
        // warn-amend-pushed only engages on an amending `git commit`; the
        // generic PreToolUse sample (`git status`) would never reach the probe.
        // `try` substitutes the process cwd, so this smoke-tests live state.
        ("guardrails", "warn-amend-pushed") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"git commit --amend --no-edit"}}"#,
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
        // warn-commit-provenance early-exits unless the command is a git
        // commit carrying an extractable message — the generic PreToolUse
        // sample (`git status`) would never reach the Session-Id: check.
        ("session", "warn-commit-provenance") => Some(
            r#"{"session_id":"test","tool_name":"Bash","tool_input":{"command":"git commit -m test"}}"#,
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
        // persist-plan-approval gates on tool_name == "ExitPlanMode" and a
        // non-empty tool_response.plan; the generic PostToolUse sample carries
        // neither, so `try` would fail open before ever reaching the write
        // path.
        //
        // This hook has a genuine filesystem WRITE side effect, so `try` must
        // never let it write (cameronsjo/cadence-hooks#396 review: a real plan
        // doc once landed in a real repo). A sandbox `cwd` alone no longer
        // guarantees that: the destination resolver follows
        // `CLAUDE_PROJECT_DIR` and falls back to a user-scoped plans dir
        // (cameronsjo/cadence-hooks#1021). What stops the write is `try_hook`
        // running this hook with `CADENCE_NO_PERSIST_PLAN=1` and without
        // `CLAUDE_PROJECT_DIR`: the opt-out is the resolver's first check, so
        // `try` always reports ALLOW here and demonstrates none of the hook's
        // branches. The nonexistent `cwd` (kept by `CWD_OVERRIDE_REFUSED`) is
        // a second layer, not the guarantee.
        ("session", "persist-plan-approval") => Some(
            // Extra `#` in the raw-string delimiter: the payload's own plan
            // text embeds a literal `"#` (a quote immediately followed by an
            // ATX heading marker), which would otherwise close a `r#"..."#`
            // raw string early.
            r##"{"session_id":"test","tool_name":"ExitPlanMode","cwd":"/nonexistent-cadence-hooks-try-sandbox","transcript_path":"/tmp/test.jsonl","tool_response":{"plan":"# Try Sample\n\nbody text","isAgent":false}}"##,
        ),
        // lint-plan-shape gates on tool_name == "ExitPlanMode" and a plan text;
        // the generic PreToolUse sample carries neither, so `try` would fail
        // open before ever judging a plan. The sample is the harness's own
        // Context/Changes/Verification shape — the artifact the gate exists to
        // stop — so `try session lint-plan-shape` demonstrates the block.
        ("session", "lint-plan-shape") => Some(
            r##"{"session_id":"test","tool_name":"ExitPlanMode","cwd":"/tmp","permission_mode":"plan","tool_input":{"plan":"# Try Sample\n\n## Context\n\nprose\n\n## Changes\n\n1. do a thing\n","planFilePath":"/nonexistent/plans/try.md"}}"##,
        ),
        // warn-subagent-worktree only engages on an Agent/Task spawn; the generic
        // Bash PreToolUse sample would no-op. Carry a cwd so the git checks have a
        // directory to resolve against.
        ("guardrails", "warn-subagent-worktree") => Some(
            r#"{"tool_name":"Agent","tool_input":{"subagent_type":"general-purpose"},"cwd":"/tmp"}"#,
        ),
        // warn-agent-dispatch only engages on an Agent/Task spawn; a general-purpose
        // dispatch with no model shows the omit-model nudge under `try`.
        ("guardrails", "warn-agent-dispatch") => Some(
            r#"{"tool_name":"Agent","tool_input":{"subagent_type":"general-purpose","prompt":"x"},"cwd":"/tmp"}"#,
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
        _ => None,
    }
}

/// True when `<namespace> <subcommand>` names a registered hook.
pub fn is_known(namespace: &str, subcommand: &str) -> bool {
    entry(namespace, subcommand).is_some()
}

/// The clap namespace `subcommand` is registered under, if any.
///
/// Two callers, one question: "namespace mismatch" diagnostics, and the
/// dispatch self-timing write, which tags a slow hook with its namespace.
/// Until cadence-hooks#884 the second called a behaviorally identical
/// `plugin_for`, whose name implied it answered the different question of
/// which Claude Code plugin wires the hook. It never did.
pub fn namespace_of(subcommand: &str) -> Option<&'static str> {
    HOOKS
        .iter()
        .find(|h| h.name == subcommand)
        .map(|h| h.namespace)
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
        let e = entry("session", "start").expect("start registered");
        assert_eq!(e.event(), Some(HookEvent::SessionStart));
    }

    #[test]
    fn entry_returns_none_for_unknown_pair() {
        assert!(entry("cadence", "guard-push-remote").is_none());
    }

    #[test]
    fn security_critical_registry_covers_protected_guards() {
        assert!(is_security_critical("guard-push-remote"));
        assert!(is_security_critical("prevent-secret-writes"));
        assert!(!is_security_critical("warn-main-branch"));
    }

    #[test]
    fn every_security_critical_name_is_registered() {
        for name in SECURITY_CRITICAL_HOOKS {
            assert!(
                HOOKS.iter().any(|hook| hook.name == *name),
                "{name} is classified security-critical but is not registered"
            );
        }
    }

    #[test]
    fn sample_overrides_exist_for_event_gated_loggers() {
        // These loggers gate on specific hook_event_name values or command
        // shapes — the generic fallback would no-op them.
        for name in ["snapshot", "log-commit", "log-subagent", "log-session"] {
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
            if let Some(sample) = sample_for(hook.namespace, hook.name) {
                let parsed = cadence_hooks_core::MetricsInput::from_json(sample);
                assert!(
                    parsed.is_ok(),
                    "sample for {} {} must parse: {:?}",
                    hook.namespace,
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
                    hook.events.is_empty(),
                    "{} is a logger and should have no events",
                    hook.name
                );
            } else {
                assert!(
                    !hook.events.is_empty(),
                    "{} is a check and must declare its event",
                    hook.name
                );
            }
        }
    }

    /// The hook rows in one `## <namespace>` section of `docs/hooks.md`: each
    /// table row whose first cell is a single backticked name, up to the next
    /// `## ` heading. The `### CLI actions` subsection lists commands, not
    /// hooks, so the scan stops there.
    fn documented_hooks(doc: &str, namespace: &str) -> Vec<String> {
        let mut in_section = false;
        let mut rows = Vec::new();
        for line in doc.lines() {
            if let Some(heading) = line.strip_prefix("## ") {
                in_section = heading.split_whitespace().next() == Some(namespace);
                continue;
            }
            if line.starts_with("### CLI actions") {
                in_section = false;
            }
            if !in_section {
                continue;
            }
            if let Some(rest) = line.strip_prefix("| `")
                && let Some((name, _)) = rest.split_once("` |")
            {
                rows.push(name.to_string());
            }
        }
        rows
    }

    fn registered_in(namespace: &str) -> Vec<&'static str> {
        HOOKS
            .iter()
            .filter(|h| h.namespace == namespace)
            .map(|h| h.name)
            .collect()
    }

    fn namespaces() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = HOOKS.iter().map(|h| h.namespace).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// `docs/hooks.md` claims to catalog every hook. Every registered hook has
    /// exactly one row in its namespace's section, and every row names a
    /// registered hook (cameronsjo/cadence-hooks#789).
    #[test]
    fn docs_hooks_catalog_matches_registry() {
        let doc = include_str!("../docs/hooks.md");
        for ns in namespaces() {
            let documented = documented_hooks(doc, ns);
            let registered = registered_in(ns);
            let missing: Vec<_> = registered
                .iter()
                .filter(|n| !documented.iter().any(|d| d == *n))
                .collect();
            let unknown: Vec<_> = documented
                .iter()
                .filter(|d| !registered.contains(&d.as_str()))
                .collect();
            assert!(
                missing.is_empty() && unknown.is_empty(),
                "docs/hooks.md `## {ns}` is out of step with src/registry.rs: \
                 missing rows {missing:?}, rows for unregistered hooks {unknown:?}"
            );
            assert_eq!(
                documented.len(),
                registered.len(),
                "docs/hooks.md `## {ns}` lists a hook more than once: {documented:?}"
            );
        }
    }

    /// Hooks that do not simply `Run` in a cloud session. Everything not listed
    /// here must declare `Run`, so a new hook cannot slip in with a different
    /// policy without this table being updated with it (#1197).
    const NOT_RUN_IN_CLOUD: &[&str] = &[
        "enforce-worktree",
        "warn-subagent-worktree",
        "nudge-upgrade-after-push",
        "trash-guard-liveness",
        "snapshot",
        "log-commit",
        "log-subagent",
        "log-session",
        "log-session-start",
        "log-polish-nudge",
        "log-ask-user-question",
        "log-skill",
        "warn-stale",
        "start",
        "heartbeat",
        "guard",
        "end",
        "backstop-record",
        "backstop-warn",
        "persist-plan-approval",
    ];

    #[test]
    fn hook_names_are_unique_across_namespaces() {
        // `remote_gate` resolves by name alone, like `namespace_of`.
        let mut names: Vec<_> = HOOKS.iter().map(|h| h.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }

    #[test]
    fn every_hook_declares_the_remote_policy_the_table_expects() {
        for h in HOOKS {
            let expected = if NOT_RUN_IN_CLOUD.contains(&h.name) {
                RemotePolicy::SelfDisable
            } else {
                RemotePolicy::Run
            };
            assert_eq!(h.remote, expected, "{} {}", h.namespace, h.name);
        }
        for name in NOT_RUN_IN_CLOUD {
            assert!(HOOKS.iter().any(|h| h.name == *name), "stale row {name}");
        }
    }

    #[test]
    fn remote_gate_stops_only_non_run_hooks_and_only_when_remote() {
        for h in HOOKS {
            assert_eq!(remote_gate(h.name, false), None, "{}: not remote", h.name);
            let gated = remote_gate(h.name, true);
            match h.remote {
                RemotePolicy::Run => assert_eq!(gated, None, "{}", h.name),
                stop => assert_eq!(gated, Some(stop), "{}", h.name),
            }
        }
        assert_eq!(remote_gate("no-such-hook", true), None);
    }

    #[test]
    fn a_blocking_policy_is_reported_as_such() {
        assert_eq!(
            RemotePolicy::BlockWithReason("x").label(),
            "block-with-reason"
        );
        assert_eq!(RemotePolicy::SelfDisable.label(), "self-disable");
        assert_eq!(RemotePolicy::Run.label(), "run");
    }

    /// Every hook row in `docs/hooks.md` carries the remote-policy column value
    /// the registry declares (#1197).
    #[test]
    fn docs_hooks_catalog_states_each_remote_policy() {
        let doc = include_str!("../docs/hooks.md");
        for h in HOOKS {
            let row = doc
                .lines()
                .find(|l| l.starts_with(&format!("| `{}` |", h.name)))
                .unwrap_or_else(|| panic!("no docs row for {}", h.name));
            let last = row.trim_end_matches('|').rsplit('|').next().unwrap().trim();
            assert_eq!(last, h.remote.label(), "docs remote cell for {}", h.name);
        }
    }

    /// The README's per-namespace `Hooks` count matches the registry.
    #[test]
    fn readme_namespace_counts_match_registry() {
        let readme = include_str!("../README.md");
        for ns in namespaces() {
            let prefix = format!("| `{ns}` |");
            let row = readme
                .lines()
                .find(|l| l.starts_with(&prefix))
                .unwrap_or_else(|| panic!("README.md has no namespace row for `{ns}`"));
            let count: usize = row
                .split('|')
                .map(str::trim)
                .nth(3)
                .and_then(|c| c.parse().ok())
                .unwrap_or_else(|| panic!("README.md row for `{ns}` has no numeric count: {row}"));
            assert_eq!(
                count,
                registered_in(ns).len(),
                "README.md says `{ns}` has {count} hooks; src/registry.rs registers {}",
                registered_in(ns).len()
            );
        }
    }
    /// A `suppressible` hook can never be a security guard, a detector exempt
    /// from the blanket bypass, or a logger — the config surface must not be
    /// able to name anything whose silence is a harm (#216).
    #[test]
    fn registry_suppressible_entries_are_advisory_only() {
        use cadence_hooks_core::bypass::{BYPASS_EXEMPT_HOOKS, PROTECTED_GUARDS};
        let mut count = 0;
        for h in HOOKS.iter().filter(|h| h.suppressible) {
            count += 1;
            assert!(
                !PROTECTED_GUARDS.contains(&h.name),
                "{} is protected and cannot be suppressible",
                h.name
            );
            assert!(
                !is_security_critical(h.name),
                "{} is security-critical and cannot be suppressible",
                h.name
            );
            assert!(
                !BYPASS_EXEMPT_HOOKS.contains(&h.name),
                "{} is bypass-exempt and cannot be suppressible",
                h.name
            );
            assert!(
                !h.events.is_empty(),
                "{} is a logger: it emits no nudge to suppress",
                h.name
            );
            assert!(
                !h.name.starts_with("guard-")
                    && !h.name.starts_with("enforce-")
                    && !h.name.starts_with("prevent-"),
                "{} is named like a block-capable guard",
                h.name
            );
        }
        assert!(
            count > 0,
            "no suppressible hooks: the nudges config would be inert"
        );
    }

    #[test]
    fn is_suppressible_is_false_for_unknown_and_blocking_hooks() {
        for (name, want) in [
            ("warn-overshare", true),
            ("backstop-warn", true),
            ("git-safety", false),
            ("enforce-worktree", false),
            ("redact-external-content", false),
            ("terminology", false),
            ("log-session", false),
            ("no-such-hook", false),
            ("", false),
        ] {
            assert_eq!(is_suppressible(name), want, "{name}");
        }
    }
}
