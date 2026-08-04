//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each hook subcommand reads JSON from stdin (the hook protocol) and exits
//! with 0 (allow), 1 (warn), or 2 (block). The CLI commands (`list`, `doctor`,
//! `configure`, `try`, `migrate-config`, `session declare`/`status`) take no
//! stdin.

use cadence_hooks_core::HookEvent;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::process;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::ThreadId;

/// Set by [`dispatch`] around the region its `catch_unwind` covers, and read by
/// the global panic hook below.
///
/// A panic hook runs **before** unwinding begins, so the hook's
/// `process::exit(1)` terminated the process and no `catch_unwind` downstream
/// ever regained control — every guard in the tree was dead code
/// (cameronsjo/cadence-hooks#349). This flag lets the hook *return* instead,
/// handing the unwind to the waiting guard, and only where a guard is actually
/// waiting. Unguarded panics keep the historical exit-1 path exactly.
///
/// `Relaxed` is sufficient: the store and the panic hook's load happen on the
/// same thread in program order, and a load from any *other* thread is
/// short-circuited by the `MAIN_THREAD` test below before its value matters.
pub(crate) static PANIC_GUARDED: AtomicBool = AtomicBool::new(false);

/// The thread `main` runs on, pinned at entry.
///
/// `PANIC_GUARDED` is a process-global, but the `catch_unwind` it advertises
/// only catches unwinds on the **main** thread. Guarded regions spawn worker
/// threads (`core::shell::run_bounded_with`'s stdout drain), and a panic there
/// unwinds that thread, not `main` — so without this test the hook would skip
/// the exit for a panic nothing is positioned to catch, silently losing the
/// fail-open exit. `OnceLock` rather than a constant because a thread id is
/// only knowable at runtime.
static MAIN_THREAD: OnceLock<ThreadId> = OnceLock::new();

/// Return true when running inside Claude Code. Detected via `CLAUDECODE=1`,
/// which Claude Code exports for every spawned shell. Empty/unset means no.
fn under_claude_code() -> bool {
    std::env::var("CLAUDECODE")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

mod configure;
mod dispatch;
mod doctor;
mod hook_latency;
mod migrate;
mod registry;
mod try_hook;
use registry::{HOOKS, HookEntry};

/// Guards that prevent irreversible harm — secret exposure, data loss,
/// destructive git/gh/remote/vault operations. `CADENCE_DISABLE` (silent,
/// persistent, settable in settings.json `env`) must not be able to neuter
/// these; only the loud, per-session `CADENCE_BYPASS` can (#89).
const PROTECTED_GUARDS: &[&str] = &[
    "prevent-secret-leaks",
    "prevent-secret-writes",
    // Carries the fail-closed identity tier. Protection is per-guard, so this
    // also strips CADENCE_DISABLE from the same guard's *advisory* tiers —
    // accepted deliberately (ruled 2026-08-03): the alternative was splitting
    // one guard in two, and the remaining levers for a noisy nudge are the
    // per-repo allowlist and originAudience, both config edits. Without this
    // line, one environment variable silently disarms the leak protection.
    "redact-external-content",
    "git-safety",
    "guard-push-remote",
    "guard-gh-dangerous",
    "guard-gh-write",
    "guard-op-vault-scan",
    "guard-browser-device",
    "guard-dotfiles",
    "guard-read-model",
    "trash-guard",
];

#[derive(Parser)]
#[command(
    name = "cadence-hooks",
    version,
    about = "Compiled Claude Code hooks — hook subcommands read a JSON payload on stdin"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cadence plugin hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Cadence(CadenceCommands),

    /// Git guardrails hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Guardrails(GuardrailsCommands),

    /// Rules plugin hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Rules(RulesCommands),

    /// Cadence Obsidian plugin hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Obsidian(ObsidianCommands),

    /// Cadence metrics logging hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Metrics(MetricsCommands),

    /// Multi-session coordination hooks (cadence-canon; hooks read JSON on stdin)
    #[command(subcommand)]
    Session(SessionCommands),

    /// Run a hook against a generated sample payload (manual testing)
    Try {
        /// Hook namespace (cadence, guardrails, rules, obsidian, metrics, session)
        namespace: String,
        /// Hook name (see `cadence-hooks list`)
        subcommand: String,
        /// Read the payload from a file instead of generating a sample
        #[arg(long, value_name = "FILE")]
        payload: Option<std::path::PathBuf>,
        /// Echo user-supplied payloads in full (default: bounded preview)
        #[arg(long)]
        show_payload: bool,
    },

    /// List all hooks with events, descriptions, and disable status
    List,

    /// Emit the complete hook registry as a machine-readable compatibility manifest
    Manifest {
        /// Output format
        #[arg(long, value_enum, default_value_t = ManifestFormat::Json)]
        format: ManifestFormat,
    },

    /// Interactively configure which hooks to disable for this project
    Configure {
        /// Print current configuration without interactive mode
        #[arg(long)]
        list: bool,
    },

    /// Scan installed plugin hooks.json files for shell-expansion bugs and subcommand skew
    Doctor {
        /// Scan a specific directory instead of ~/.claude/plugins/cache
        #[arg(long, value_name = "DIR")]
        root: Option<std::path::PathBuf>,
        /// One-line summary output; exit non-zero only on errors. For SessionStart preflight.
        #[arg(long)]
        quiet: bool,
        /// List orphaned plugin-cache version dirs that would be removed (dry-run; no deletion)
        #[arg(long)]
        prune: bool,
        /// With --prune, actually remove the orphaned version dirs (default is dry-run)
        #[arg(long)]
        apply: bool,
    },

    /// Convert legacy .claude/{redaction,terminology}.json into the unified .claude/cadence.json (#153)
    MigrateConfig,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ManifestFormat {
    Json,
}

#[derive(Subcommand)]
enum CadenceCommands {
    /// Block inclusive terminology violations
    Terminology,
    /// Block orphaned code markers without issue references
    OrphanedTodos,
    /// Guard against reading/ingesting secrets
    PreventSecretLeaks,
    /// Guard against writing/editing/deleting secrets
    PreventSecretWrites,
    /// Enforce MEMORY.md line limits
    MemoryGuard,
    /// Block dangerous git operations
    GitSafety,
    /// Validate shell script line endings
    LineEndings,
    /// Warn about generic environment variable names
    EnvVars,
    /// Nudge to review docs when creating a PR
    WarnDocsUpdate,
    /// Nudge to audit about-to-ship content for personal-context overshare
    WarnOvershare,
    /// Nudge to run `/polish` (cadence-forge:polish) before creating a PR
    NudgePolishBeforePr,
    /// Run markdownlint on markdown files
    MarkdownLint,
    /// Nudge when an external post mentions internal harness vocabulary
    RedactExternalContent,
    /// Nudge when the cadence-hooks binary or Claude Code has drifted behind
    /// the plugin-shipped platform baseline (SessionStart)
    PlatformDrift {
        /// Path to the platform-baseline.json shipped by the cadence plugin
        #[arg(long, value_name = "PATH")]
        baseline: Option<String>,
    },
    /// Scan text (stdin or --file) for redaction hits at a destination
    /// audience tier. CLI action — the single engine behind the redaction
    /// skill's pre-post scan (exit 0 clean / 1 hits on stderr / 2 usage)
    RedactScan {
        /// Scan a file instead of stdin
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
        /// Destination tier: owned-internal | private-external | public
        /// (default: config originAudience, else public)
        #[arg(long, value_name = "TIER")]
        audience: Option<String>,
        /// Scaffold the redaction section of .claude/cadence.json and exit
        #[arg(long)]
        init: bool,
        /// Report whether the identity tier is armed, and exit. Consumed by the
        /// cadence plugin's SessionStart: an absent or unreadable term source
        /// is a silent disarm on the machine you are not looking at, so it has
        /// to announce itself once per session. Exit 0 armed / 1 unarmed.
        #[arg(long)]
        status: bool,
    },
    /// Record that /polish ran on this branch (writes a branch-scoped marker). CLI action.
    RecordPolish {
        /// Repository to record against (default: the current directory's).
        /// Resolved to the repo's shared git dir, so any worktree of it works
        /// and the marker stays readable by the pre-PR gate
        #[arg(long, value_name = "PATH")]
        repo_root: Option<String>,
        /// Branch to record against (default: the checked-out branch)
        #[arg(long, value_name = "NAME")]
        branch: Option<String>,
        /// What the pass covered — `full`, `code`, or `docs` (default: full)
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        /// Per-arm outcome, repeatable — e.g. `--arm security=ran --arm
        /// tests=skipped`. Recorded additively; a marker without a roster
        /// reads as unknown, never as skipped (cadence-hooks#467)
        #[arg(long = "arm", value_name = "NAME=STATE", action = clap::ArgAction::Append)]
        arm: Vec<String>,
    },
}

#[derive(Subcommand)]
enum GuardrailsCommands {
    /// Block git push to non-owned remotes
    GuardPushRemote,
    /// Block irreversible gh operations (repo delete)
    GuardGhDangerous,
    /// Block gh write operations to non-owned repos
    GuardGhWrite,
    /// Nudge to scaffold and confirm license after git init or gh repo create
    GuardGitInit,
    /// Warn when editing on main/master branch
    WarnMainBranch,
    /// Warn when dispatching a subagent from main while a sibling worktree exists
    WarnSubagentWorktree,
    /// Nudge when the live subagent count is at or over the concurrency cap
    WarnSubagentConcurrency,
    /// Warn when creating a branch from a non-main base
    WarnBranchBase,
    /// Remind to check datetime before scheduling cron jobs
    WarnCronDatetime,
    /// Nudge to schedule a brew upgrade after pushing cadence-hooks to main
    NudgeUpgradeAfterPush,
    /// Warn about untracked files during git commit operations
    WarnUntracked,
    /// Block direct edits to production dotfiles (opt-in via CADENCE_GUARD_DOTFILES=1)
    GuardDotfiles,
    /// Path-aware triage of rm-family deletes (allow temp/managed, block home/vault/repo, ask the rest)
    GuardRm,
    /// SessionStart assertion that guard-rm is present and classifying deletes as contracted
    GuardRmLiveness,
    /// Block Read/Grep by resolved session model (opt-in via CADENCE_READ_MODEL_GUARD_MODELS)
    GuardReadModel,
    /// Nudge when `gh pr create` has no closing issue keyword in the body
    WarnPrIssueLink,
    /// Nudge when `gh issue create` targets a repo other than the canonical issue tracker
    WarnIssueTracker,
    /// Nudge on repo create/publicize when name or description telegraphs sensitive content
    WarnGoingPublic,
    /// Verify issue auto-close after PR create/merge; close stragglers
    VerifyPrAutoclose,
    /// Block uninvited 1Password vault enumeration (op item list)
    GuardOpVaultScan,
    /// Warn when bare curl (aliased to curlie) is used with custom headers
    WarnCurlAlias,
    /// Pre-flight checklist nudge before gh pr merge (draft, worktree, verify)
    WarnGhMergePreflight,
    /// Warn that CodeRabbit re-trigger comments are no-ops on reviewed content
    WarnCoderabbitRetrigger,
    /// Warn when piping aliased-tool output (ls/find/cat/du/df/top) into parsers
    WarnAliasParsing,
    /// Block the first Claude-in-Chrome action per session until the device is confirmed
    GuardBrowserDevice,
    /// Inject the gh-write allowlist + `-R` rule on SessionStart
    InjectGhContext,
    /// Re-inject the gh-write allowlist + `-R` rule before an untargeted gh write
    InjectGhWriteContext,
    /// Snooze warn-main-branch for this repo for the given duration
    DismissMainBranchWarn {
        /// Duration to snooze, e.g. `30m`, `2h`, `1d`. Capped at 24h.
        #[arg(long = "for", default_value = "30m", value_name = "DURATION")]
        for_: String,
        /// Why the guard is being dismissed. Required for snoozes over 1h;
        /// recorded in the bypass provenance log.
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
    },
    /// Block mutations in a primary checkout of a branch-mode repo
    EnforceWorktree,
    /// Snooze enforce-worktree for this repo for the given duration
    DismissEnforceWorktree {
        /// Duration to snooze, e.g. `30m`, `2h`, `1d`. Capped at 24h.
        #[arg(long = "for", default_value = "30m", value_name = "DURATION")]
        for_: String,
        /// Why the guard is being dismissed. Required for snoozes over 1h;
        /// recorded in the repo-visible bypass provenance log.
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Repo to snooze, if not the current directory's repo — e.g. after a
        /// `cd <other-repo> && git commit` was blocked against that repo.
        #[arg(long, value_name = "PATH")]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// Validate SKILL.md and command frontmatter
    ValidateFrontmatter,
    /// Scan for security anti-patterns
    SecurityPatterns,
    /// Nudge to label a recommended AskUserQuestion option "(Recommended)"
    WarnRecommendedOption,
    /// Nudge to re-ask when AskUserQuestion returns empty auto-approve answers
    WarnEmptyAnswers,
}

#[derive(Subcommand)]
enum ObsidianCommands {
    /// Block rm in Obsidian vault (use .trash/ instead)
    TrashGuard,
}

#[derive(Subcommand)]
enum MetricsCommands {
    /// Snapshot HEAD before a git commit (PreToolUse)
    Snapshot,
    /// Log cost-per-commit after a git commit (PostToolUse)
    LogCommit {
        /// Override path to the model price table (JSON). Falls back to the
        /// embedded default; `CADENCE_METRICS_PRICES` env takes precedence.
        #[arg(long, value_name = "PATH")]
        prices: Option<String>,
    },
    /// Log subagent lifecycle (SubagentStart / SubagentStop)
    LogSubagent,
    /// Log per-session cost at SessionEnd (SessionEnd)
    LogSession {
        /// Override path to the model price table (JSON). Falls back to the
        /// embedded default; `CADENCE_METRICS_PRICES` env takes precedence.
        #[arg(long, value_name = "PATH")]
        prices: Option<String>,
    },
    /// Capture session start timestamp (SessionStart)
    LogSessionStart,
    /// Log polish-nudge skips: `gh pr create` + whether /polish ran (PostToolUse)
    LogPolishNudge,
    /// Log AskUserQuestion: asked (PreToolUse) + answered (PostToolUse)
    LogAskUserQuestion,
    /// Log skill invocations (PostToolUse:Skill)
    LogSkill,
    /// Warn at SessionStart when metrics telemetry has gone stale (SessionStart)
    WarnStale,
}

#[derive(Subcommand)]
enum SessionCommands {
    /// Register this session in the repo registry and disclose live peers (SessionStart)
    Start,
    /// Touch this session's registry file — mtime is the liveness signal (PostToolUse)
    Heartbeat,
    /// Warn when an action intersects a live peer's lane (PreToolUse)
    Guard,
    /// Warn when HEAD drifted from the session's recorded branch at git commit (PreToolUse)
    WarnBranchDrift,
    /// Nudge when new work starts on a stale, unrelated feature branch (PreToolUse)
    WarnBranchIntent,
    /// Nudge toward a `Session-Id:` trailer on a Claude-composed commit message (PreToolUse)
    WarnCommitProvenance,
    /// Deregister this session's registry file when it ends (SessionEnd logger)
    End,
    /// Record loose ends when the session ends, for the next start to surface (SessionEnd logger)
    BackstopRecord,
    /// Warn at session start when the last session in this repo left loose ends (SessionStart)
    BackstopWarn,
    /// Persist an approved plan whose post-approval turn was wiped (UserPromptSubmit)
    PersistPlan,
    /// Persist an approved plan on same-session approval (PostToolUse:ExitPlanMode)
    PersistPlanApproval,
    /// Declare what this session is working on, so peers can assess collision risk
    Declare {
        /// What this session is working on (e.g. "cadence-hooks#54")
        #[arg(long, value_name = "TEXT")]
        intent: Option<String>,
        /// Repo-relative paths this session expects to touch (repeatable)
        #[arg(long, value_name = "PATH")]
        touching: Vec<String>,
        /// Session id override (defaults to $CLAUDE_SESSION_ID)
        #[arg(long, value_name = "ID")]
        session_id: Option<String>,
    },
    /// List live and stale sessions registered in this repo
    Status,
}

/// Returns the kebab-case hook name for the resolved subcommand.
/// These match the CLI names that clap derives from the enum variants.
fn hook_name(cmd: &Commands) -> Option<&'static str> {
    match cmd {
        Commands::Cadence(c) => Some(match c {
            CadenceCommands::Terminology => "terminology",
            CadenceCommands::OrphanedTodos => "orphaned-todos",
            CadenceCommands::PreventSecretLeaks => "prevent-secret-leaks",
            CadenceCommands::PreventSecretWrites => "prevent-secret-writes",
            CadenceCommands::MemoryGuard => "memory-guard",
            CadenceCommands::GitSafety => "git-safety",
            CadenceCommands::LineEndings => "line-endings",
            CadenceCommands::EnvVars => "env-vars",
            CadenceCommands::WarnDocsUpdate => "warn-docs-update",
            CadenceCommands::WarnOvershare => "warn-overshare",
            CadenceCommands::NudgePolishBeforePr => "nudge-polish-before-pr",
            CadenceCommands::MarkdownLint => "markdown-lint",
            CadenceCommands::RedactExternalContent => "redact-external-content",
            CadenceCommands::PlatformDrift { .. } => "platform-drift",
            // record-polish and redact-scan are CLI actions, not hooks — no
            // hooks.json wiring and not subject to CADENCE_DISABLE (same
            // treatment as declare / status / dismiss-*).
            CadenceCommands::RecordPolish { .. } => return None,
            CadenceCommands::RedactScan { .. } => return None,
        }),
        Commands::Guardrails(g) => Some(match g {
            GuardrailsCommands::GuardPushRemote => "guard-push-remote",
            GuardrailsCommands::GuardGhDangerous => "guard-gh-dangerous",
            GuardrailsCommands::GuardGhWrite => "guard-gh-write",
            GuardrailsCommands::GuardGitInit => "guard-git-init",
            GuardrailsCommands::WarnMainBranch => "warn-main-branch",
            GuardrailsCommands::WarnSubagentWorktree => "warn-subagent-worktree",
            GuardrailsCommands::WarnSubagentConcurrency => "warn-subagent-concurrency",
            GuardrailsCommands::WarnBranchBase => "warn-branch-base",
            GuardrailsCommands::WarnCronDatetime => "warn-cron-datetime",
            GuardrailsCommands::NudgeUpgradeAfterPush => "nudge-upgrade-after-push",
            GuardrailsCommands::WarnUntracked => "warn-untracked",
            GuardrailsCommands::GuardDotfiles => "guard-dotfiles",
            GuardrailsCommands::GuardRm => "guard-rm",
            GuardrailsCommands::GuardRmLiveness => "guard-rm-liveness",
            GuardrailsCommands::GuardReadModel => "guard-read-model",
            GuardrailsCommands::WarnPrIssueLink => "warn-pr-issue-link",
            GuardrailsCommands::WarnIssueTracker => "warn-issue-tracker",
            GuardrailsCommands::WarnGoingPublic => "warn-going-public",
            GuardrailsCommands::VerifyPrAutoclose => "verify-pr-autoclose",
            GuardrailsCommands::GuardOpVaultScan => "guard-op-vault-scan",
            GuardrailsCommands::WarnCurlAlias => "warn-curl-alias",
            GuardrailsCommands::WarnGhMergePreflight => "warn-gh-merge-preflight",
            GuardrailsCommands::WarnCoderabbitRetrigger => "warn-coderabbit-retrigger",
            GuardrailsCommands::WarnAliasParsing => "warn-alias-parsing",
            GuardrailsCommands::GuardBrowserDevice => "guard-browser-device",
            GuardrailsCommands::InjectGhContext => "inject-gh-context",
            GuardrailsCommands::InjectGhWriteContext => "inject-gh-write-context",
            GuardrailsCommands::EnforceWorktree => "enforce-worktree",
            // The dismiss-* subcommands are CLI actions, not hooks —
            // they have no PreToolUse/PostToolUse wiring and aren't subject
            // to CADENCE_DISABLE. Falling out of the Some(...) here is
            // intentional; handle them specially below.
            GuardrailsCommands::DismissMainBranchWarn { .. } => return None,
            GuardrailsCommands::DismissEnforceWorktree { .. } => return None,
        }),
        Commands::Rules(r) => Some(match r {
            RulesCommands::ValidateFrontmatter => "validate-frontmatter",
            RulesCommands::SecurityPatterns => "security-patterns",
            RulesCommands::WarnRecommendedOption => "warn-recommended-option",
            RulesCommands::WarnEmptyAnswers => "warn-empty-answers",
        }),
        Commands::Obsidian(o) => Some(match o {
            ObsidianCommands::TrashGuard => "trash-guard",
        }),
        Commands::Metrics(m) => Some(match m {
            MetricsCommands::Snapshot => "snapshot",
            MetricsCommands::LogCommit { .. } => "log-commit",
            MetricsCommands::LogSubagent => "log-subagent",
            MetricsCommands::LogSession { .. } => "log-session",
            MetricsCommands::LogSessionStart => "log-session-start",
            MetricsCommands::LogPolishNudge => "log-polish-nudge",
            MetricsCommands::LogAskUserQuestion => "log-ask-user-question",
            MetricsCommands::LogSkill => "log-skill",
            MetricsCommands::WarnStale => "warn-stale",
        }),
        Commands::Session(s) => Some(match s {
            SessionCommands::Start => "start",
            SessionCommands::Heartbeat => "heartbeat",
            SessionCommands::Guard => "guard",
            SessionCommands::WarnBranchDrift => "warn-branch-drift",
            SessionCommands::WarnBranchIntent => "warn-branch-intent",
            SessionCommands::WarnCommitProvenance => "warn-commit-provenance",
            SessionCommands::End => "end",
            SessionCommands::BackstopRecord => "backstop-record",
            SessionCommands::BackstopWarn => "backstop-warn",
            SessionCommands::PersistPlan => "persist-plan",
            SessionCommands::PersistPlanApproval => "persist-plan-approval",
            // declare and status are CLI actions, not hooks — no hooks.json
            // wiring and not subject to CADENCE_DISABLE (same treatment as
            // dismiss-main-branch-warn).
            SessionCommands::Declare { .. } | SessionCommands::Status => return None,
        }),
        Commands::Try { .. }
        | Commands::List
        | Commands::Manifest { .. }
        | Commands::Configure { .. }
        | Commands::Doctor { .. }
        | Commands::MigrateConfig => None,
    }
}

/// Prints all hooks grouped by plugin, showing disable status.
fn print_hook_list() {
    let disable_var = std::env::var("CADENCE_DISABLE").unwrap_or_default();
    let disabled: Vec<&str> = disable_var
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let bypassed = std::env::var("CADENCE_BYPASS").as_deref() == Ok("1");

    if bypassed {
        println!("CADENCE_BYPASS=1 — all hooks bypassed\n");
    }

    let mut current_plugin = "";
    for hook in HOOKS {
        if hook.plugin != current_plugin {
            if !current_plugin.is_empty() {
                println!();
            }
            println!("{}:", hook.plugin);
            current_plugin = hook.plugin;
        }

        let status = if bypassed {
            " (disabled)"
        } else if disabled.contains(&hook.name) {
            // A protected guard named in CADENCE_DISABLE is refused, not
            // disabled — don't let the listing claim it's off (#89).
            if PROTECTED_GUARDS.contains(&hook.name) {
                " (protected — disable refused)"
            } else {
                " (disabled)"
            }
        } else {
            ""
        };

        let event = match hook.event {
            Some(e) => e.name(),
            None => "logger",
        };

        println!(
            "  {:<28} {:<13} {}{}",
            hook.name, event, hook.description, status
        );
    }

    if !disabled.is_empty() {
        println!("\nDisabled via CADENCE_DISABLE: {}", disabled.join(", "));
    }
}

fn print_hook_manifest(format: ManifestFormat) {
    match format {
        ManifestFormat::Json => {
            let hooks = HOOKS
                .iter()
                .map(|hook| {
                    serde_json::json!({
                        "name": hook.name,
                        "description": hook.description,
                        "plugin": hook.plugin,
                        "event": hook.event.map(|event| event.name()).unwrap_or("logger"),
                        "criticality": if registry::is_security_critical(hook.name) {
                            "security-critical"
                        } else if hook.event.is_none() {
                            "telemetry"
                        } else {
                            "workflow"
                        },
                        "protected": PROTECTED_GUARDS.contains(&hook.name),
                    })
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::json!({
                    "schemaVersion": 1,
                    "binaryVersion": env!("CARGO_PKG_VERSION"),
                    "hooks": hooks,
                })
            );
        }
    }
}

fn main() {
    // Pin the main thread before anything can spawn — the panic hook's guard
    // test below is only meaningful once this is set. The `Result` is
    // discarded because `main` runs once: an `Err` would mean the cell was
    // already set, which cannot happen, and failing open on it is right anyway
    // (an unset cell just restores the unconditional exit-1 path).
    let _ = MAIN_THREAD.set(std::thread::current().id());

    // Maintenance bypass — set CADENCE_BYPASS=1 to skip all enforcement.
    // Useful when editing hook source or testing. Per-session, can't be left on accidentally.
    // Note: `list`, `configure`, `doctor`, `try`, `migrate-config`, and the
    // session CLI actions (`declare`, `status`) are exempt — they're
    // CLI/diagnostic/maintenance commands, not enforcement paths, and must work
    // always. A bypassed doctor would report false-clean in CI; a bypassed
    // `session status` would hide live peers exactly when someone is debugging
    // coordination; a bypassed `migrate-config` would silently migrate nothing.
    let bypassed = std::env::var("CADENCE_BYPASS").as_deref() == Ok("1");
    // Match on subcommand *position* (argv[1], or argv[1]+argv[2] for session
    // CLI actions) — not any argv token, which would let a hook argument that
    // happens to equal "list"/"try"/etc. skip the bypass short-circuit.
    let mut positional = std::env::args().skip(1);
    let bypass_exempt = matches!(
        (positional.next().as_deref(), positional.next().as_deref()),
        (
            Some("list" | "manifest" | "configure" | "doctor" | "try" | "migrate-config"),
            _
        ) | (Some("session"), Some("declare" | "status"))
    );
    if bypassed && !bypass_exempt {
        eprintln!("⚠️  cadence-hooks: all enforcement bypassed (CADENCE_BYPASS=1)");
        process::exit(0);
    }

    // Catch panics and exit 1 (warn) instead of the default exit 101 — a panic
    // means a bug in a check, and it must not block the user's operation.
    // Exception: inside a `PANIC_GUARDED` region this hook returns instead of
    // exiting, so the waiting `catch_unwind` can finish the dispatch tail and
    // fail open at exit 0 (see the flag's doc, cameronsjo/cadence-hooks#349).
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(msg) = info.payload().downcast_ref::<&str>() {
            (*msg).to_string()
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            msg.clone()
        } else {
            "unknown panic".to_string()
        };
        eprintln!(
            "cadence-hooks: internal error (panic). This hook will not block your operation.\n\
             {payload}"
        );
        // Best-effort argv re-read: this closure has no access to the `Check`/
        // `Logger`/`hook` context computed elsewhere in `main` (a panic can
        // strike anywhere), so it re-derives the attempted subcommand purely
        // for diagnostic tagging — not validated against the registry.
        let mut argv = std::env::args().skip(1);
        let namespace = argv.next();
        let subcommand = argv.next();
        // The payload plus the source location — the two things that make this
        // row answer "why did it panic?" instead of merely "it panicked"
        // (cameronsjo/cadence-hooks#398).
        //
        // NO CURRENTLY-REACHABLE PATH LEAKS HOOK DATA HERE, but this is text
        // the repo does not author, so the property is not structural. A panic
        // anywhere in the process lands here, including inside `regex`,
        // `serde_json`, `jiff`, and `brush-parser` — which is fed raw
        // `tool_input.command` (crates/core/src/loop_analysis.rs). Rust's own
        // panic messages are *designed* to embed data: `slice_error_fail`
        // quotes the offending string, `Result::unwrap` prints `{:?}` of the
        // error. So the first future `&s[..n]` on a payload-derived string
        // would write up to 200 characters of hook input into a durable
        // ledger. Today every production `panic!`/`.expect()` carries a static
        // message, the config-driven regex compiles use `if let Ok(re)` rather
        // than `.expect`, and every byte-index slice derives its offsets from
        // ASCII-anchored searches. If that ever stops holding, redact through
        // the same seam `crates/cadence/src/secret_patterns.rs`'s
        // `scan_secret_values` uses — it returns a pattern *name*, never the
        // matched value.
        let error = match info.location() {
            Some(loc) => format!("{payload} (at {}:{})", loc.file(), loc.line()),
            None => payload,
        };
        cadence_hooks_metrics::log_failopen(
            "panic",
            namespace.as_deref(),
            subcommand.as_deref(),
            env!("CARGO_PKG_VERSION"),
            Some(&error),
        );
        // Exit only when nothing downstream is positioned to catch this unwind.
        // A panic hook runs before unwinding starts, so exiting here would make
        // every `catch_unwind` in the tree unreachable — see `PANIC_GUARDED`.
        let on_main = MAIN_THREAD.get() == Some(&std::thread::current().id());
        if !(on_main && PANIC_GUARDED.load(Ordering::Relaxed)) {
            process::exit(1);
        }
    }));

    // Build the clap Command. Under Claude Code, hide `configure` from --help
    // so the agent can't discover it as a bypass route. The runtime check below
    // also refuses to run it — defense in depth.
    let mut cmd = Cli::command();
    if under_claude_code() {
        cmd = cmd.mut_subcommand("configure", |sc| sc.hide(true));
    }

    let cli = match cmd.try_get_matches() {
        Ok(matches) => match Cli::from_arg_matches(&matches) {
            Ok(cli) => cli,
            Err(e) => {
                eprintln!("cadence-hooks: internal error hydrating args: {e}");
                process::exit(1);
            }
        },
        Err(e) => {
            // Clap errors must NOT block operations. Exit code 2 from clap would
            // be interpreted as "block" by the hook protocol, so every arm here
            // fails open (exit 1) instead.
            let installed = env!("CARGO_PKG_VERSION");
            match e.kind() {
                // No subcommand provided — bare `cadence-hooks`, or a namespace
                // with no hook (e.g. `cadence-hooks cadence`). This is NOT a
                // version problem: these hooks are invoked by plugins, not run
                // by hand. Point at --help instead of crying "newer version"
                // (claude-configurations #223).
                clap::error::ErrorKind::MissingSubcommand
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    eprintln!(
                        "cadence-hooks v{installed}: no subcommand given.\n\
                         \n\
                         These hooks are invoked by Claude Code plugins, not run directly.\n\
                         Run 'cadence-hooks --help' to list subcommands, or\n\
                         'cadence-hooks doctor' to audit installed plugin wiring."
                    );
                    process::exit(1);
                }
                // Unknown subcommand name (`cadence-hooks future-plugin hook`) or
                // an unrecognized flag on a known subcommand — a plugin likely
                // expects a newer build. This path deliberately stays
                // channel-agnostic (cargo / releases), unlike `doctor`'s
                // channel-aware advisory: cargo/releases is truthful regardless
                // of how this binary was installed, so it never degenerates into
                // a no-op `brew upgrade` (#223) here, where we can't run doctor's
                // fuller "already current" detection.
                clap::error::ErrorKind::InvalidSubcommand
                | clap::error::ErrorKind::UnknownArgument => {
                    eprintln!(
                        "cadence-hooks v{installed}: unrecognized subcommand or arguments.\n\
                         \n\
                         This usually means a plugin expects a newer version of cadence-hooks.\n\
                         \n\
                         To update:\n\
                         \x20 cargo install --git https://github.com/cameronsjo/cadence-hooks.git\n\
                         \n\
                         Or download the latest release:\n\
                         \x20 https://github.com/cameronsjo/cadence-hooks/releases/latest\n\
                         \n\
                         Underlying error: {e}"
                    );
                    // Best-effort argv re-read, same as the panic hook — a
                    // clap parse failure means `cli`/`hook_name` were never
                    // computed, so the raw argv position is all we have.
                    let mut argv = std::env::args().skip(1);
                    let namespace = argv.next();
                    let subcommand = argv.next();
                    // The clap error *kind* ("InvalidSubcommand" /
                    // "UnknownArgument"), not the full error — that is
                    // multi-line and ANSI-colored, and the kind is the whole
                    // diagnostic here anyway.
                    cadence_hooks_metrics::log_failopen(
                        "version_mismatch",
                        namespace.as_deref(),
                        subcommand.as_deref(),
                        installed,
                        Some(&format!("{:?}", e.kind())),
                    );
                    process::exit(1);
                }
                // Everything else (--help, --version, other clap errors) uses
                // clap's default behavior.
                _ => e.exit(),
            }
        }
    };

    // Selective disable — skip specific hooks by name via CADENCE_DISABLE.
    // Comma-separated list of hook names (e.g., "warn-main-branch,line-endings").
    // Set per-project in .claude/settings.json `env` block, or ad-hoc in shell.
    // Emits a one-line stderr notice whenever it disables (or refuses to
    // disable) a hook, so suppression always leaves a trace (#89).
    if let Ok(disabled) = std::env::var("CADENCE_DISABLE")
        && let Some(name) = hook_name(&cli.command)
        && disabled.split(',').any(|h| h.trim() == name)
    {
        if PROTECTED_GUARDS.contains(&name) {
            // Refuse: the guard still runs (fall through to dispatch).
            eprintln!(
                "⚠️  cadence-hooks: refusing to disable protected guard '{name}' \
                 via CADENCE_DISABLE (it still runs). Use CADENCE_BYPASS=1 for a \
                 one-session maintenance bypass."
            );
        } else {
            eprintln!("⚠️  cadence-hooks: '{name}' disabled via CADENCE_DISABLE");
            process::exit(0);
        }
    }

    // The canonical registry hook name for the dispatched subcommand, threaded
    // into the logged-dispatch wrapper so `denials.jsonl` records the name that
    // cross-references `registry::HOOKS` / `hookFiredTotal` — not the divergent
    // `Check::name()` (e.g. `terminology`, not `terminology-guard`). `Copy`
    // (`Option<&'static str>`), so binding it here borrows `&cli.command` before
    // the `match` below moves it. `None` for the CLI-action subcommands, which
    // never dispatch a check.
    let canonical_hook = hook_name(&cli.command);

    // Event type aliases for readability at callsites.
    let pre = HookEvent::PreToolUse;
    let post = HookEvent::PostToolUse;
    let session = HookEvent::SessionStart;
    let user_prompt_submit = HookEvent::UserPromptSubmit;

    match cli.command {
        Commands::Try {
            namespace,
            subcommand,
            payload,
            show_payload,
        } => {
            process::exit(try_hook::run(
                &namespace,
                &subcommand,
                payload.as_deref(),
                show_payload,
            ));
        }
        Commands::List => {
            print_hook_list();
            process::exit(0);
        }
        Commands::Manifest { format } => {
            print_hook_manifest(format);
            process::exit(0);
        }
        Commands::Configure { list } => {
            // Under Claude Code, refuse the interactive wizard — it edits settings.json
            // and would let the agent silently disable guardrails. `--list` is read-only
            // and stays available for visibility.
            if under_claude_code() && !list {
                eprintln!(
                    "cadence-hooks: `configure` is disabled under Claude Code.\n\
                     \n\
                     This would let the agent edit .claude/settings.json and disable hooks.\n\
                     Run it yourself from a terminal, or use `configure --list` to see\n\
                     current state."
                );
                process::exit(1);
            }
            configure::run(list, HOOKS);
        }
        Commands::Doctor {
            root,
            quiet,
            prune,
            apply,
        } => {
            process::exit(doctor::run(root.as_deref(), quiet, prune, apply).into());
        }
        Commands::MigrateConfig => {
            process::exit(migrate::run().into());
        }
        Commands::Cadence(cmd) => match cmd {
            CadenceCommands::Terminology => dispatch::run_logged_check(
                &cadence_hooks_cadence::terminology::TerminologyGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::OrphanedTodos => dispatch::run_logged_check(
                &cadence_hooks_cadence::block_orphaned_todos::OrphanedTodoGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::PreventSecretLeaks => dispatch::run_logged_check(
                &cadence_hooks_cadence::prevent_secret_leaks::SecretLeaksGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::PreventSecretWrites => dispatch::run_logged_check(
                &cadence_hooks_cadence::prevent_secret_writes::SecretWritesGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::MemoryGuard => dispatch::run_logged_check(
                &cadence_hooks_cadence::memory_guard::MemoryGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::GitSafety => dispatch::run_logged_check(
                &cadence_hooks_cadence::git_safety::GitSafetyGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::LineEndings => dispatch::run_logged_check(
                &cadence_hooks_cadence::validate_line_endings::LineEndingsGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::EnvVars => dispatch::run_logged_check(
                &cadence_hooks_cadence::validate_env_vars::EnvVarGuard,
                pre,
                canonical_hook,
            ),
            CadenceCommands::WarnDocsUpdate => dispatch::run_logged_check(
                &cadence_hooks_cadence::warn_docs_update::WarnDocsUpdate,
                pre,
                canonical_hook,
            ),
            CadenceCommands::WarnOvershare => dispatch::run_logged_check(
                &cadence_hooks_cadence::warn_overshare::WarnOvershare,
                pre,
                canonical_hook,
            ),
            CadenceCommands::NudgePolishBeforePr => dispatch::run_logged_check(
                &cadence_hooks_cadence::nudge_polish_before_pr::NudgePolishBeforePr,
                pre,
                canonical_hook,
            ),
            CadenceCommands::MarkdownLint => dispatch::run_logged_check(
                &cadence_hooks_cadence::markdown_lint::MarkdownLint,
                pre,
                canonical_hook,
            ),
            CadenceCommands::RedactExternalContent => dispatch::run_logged_check(
                &cadence_hooks_cadence::redact_external_content::RedactExternalContent,
                pre,
                canonical_hook,
            ),
            CadenceCommands::PlatformDrift { baseline } => dispatch::run_logged_check(
                &cadence_hooks_cadence::platform_drift::PlatformDrift {
                    baseline_path: baseline,
                },
                session,
                canonical_hook,
            ),
            CadenceCommands::RecordPolish {
                repo_root,
                branch,
                scope,
                arm,
            } => {
                cadence_hooks_cadence::record_polish::run_record(repo_root, branch, scope, arm);
            }
            CadenceCommands::RedactScan {
                file,
                audience,
                init,
                status,
            } => {
                if status {
                    process::exit(
                        cadence_hooks_cadence::redact_external_content::run_status().into(),
                    );
                }
                process::exit(
                    cadence_hooks_cadence::redact_external_content::run_scan(file, audience, init)
                        .into(),
                );
            }
        },
        Commands::Guardrails(cmd) => match cmd {
            GuardrailsCommands::GuardPushRemote => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_push_remote::PushRemoteGuard,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardGhDangerous => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_gh_dangerous::GhDangerousGuard,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardGhWrite => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_gh_write::GhWriteGuard,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardGitInit => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_git_init::GuardGitInit,
                post,
                canonical_hook,
            ),
            GuardrailsCommands::WarnMainBranch => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_main_branch::WarnMainBranch,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnSubagentWorktree => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_subagent_worktree::WarnSubagentWorktree,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnSubagentConcurrency => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_subagent_concurrency::WarnSubagentConcurrency,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnBranchBase => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_branch_base::WarnBranchBase,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnCronDatetime => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_cron_datetime::WarnCronDatetime,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::NudgeUpgradeAfterPush => dispatch::run_logged_check(
                &cadence_hooks_guardrails::nudge_upgrade_after_push::NudgeUpgradeAfterPush,
                post,
                canonical_hook,
            ),
            GuardrailsCommands::WarnUntracked => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_untracked::WarnUntrackedFiles,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardDotfiles => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_dotfiles::GuardDotfiles,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardRm => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_rm::GuardRm,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardRmLiveness => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_rm_liveness::GuardRmLiveness,
                session,
                canonical_hook,
            ),
            GuardrailsCommands::GuardReadModel => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_read_model::GuardReadModel,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnPrIssueLink => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_pr_issue_link::WarnPrIssueLink,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnIssueTracker => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_issue_tracker::WarnIssueTracker,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnGoingPublic => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_going_public::GoingPublicGuard,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::VerifyPrAutoclose => dispatch::run_logged_check(
                &cadence_hooks_guardrails::verify_pr_autoclose::VerifyPrAutoclose,
                post,
                canonical_hook,
            ),
            GuardrailsCommands::GuardOpVaultScan => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_op_vault_scan::OpVaultScanGuard,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnCurlAlias => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_curl_alias::WarnCurlAlias,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnGhMergePreflight => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_gh_merge_preflight::WarnGhMergePreflight,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnCoderabbitRetrigger => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_coderabbit_retrigger::WarnCoderabbitRetrigger,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::WarnAliasParsing => dispatch::run_logged_check(
                &cadence_hooks_guardrails::warn_alias_parsing::WarnAliasParsing,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::GuardBrowserDevice => dispatch::run_logged_check(
                &cadence_hooks_guardrails::guard_browser_device::GuardBrowserDevice,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::InjectGhContext => dispatch::run_logged_check(
                &cadence_hooks_guardrails::inject_gh_context::InjectGhContext,
                session,
                canonical_hook,
            ),
            GuardrailsCommands::InjectGhWriteContext => dispatch::run_logged_check(
                &cadence_hooks_guardrails::inject_gh_write_context::InjectGhWriteContext,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::EnforceWorktree => dispatch::run_logged_check(
                &cadence_hooks_guardrails::enforce_worktree::EnforceWorktree,
                pre,
                canonical_hook,
            ),
            GuardrailsCommands::DismissMainBranchWarn { for_, reason } => {
                finish_dismiss(
                    cadence_hooks_guardrails::dismiss_main_branch_warn::perform_dismiss(
                        &for_,
                        reason.as_deref(),
                    ),
                );
            }
            GuardrailsCommands::DismissEnforceWorktree { for_, reason, repo } => {
                finish_dismiss(
                    cadence_hooks_guardrails::dismiss_enforce_worktree::perform_dismiss(
                        &for_,
                        reason.as_deref(),
                        repo,
                    ),
                );
            }
        },
        Commands::Rules(cmd) => match cmd {
            RulesCommands::ValidateFrontmatter => dispatch::run_logged_check(
                &cadence_hooks_rules::validate_skill_frontmatter::ValidateSkillFrontmatter,
                pre,
                canonical_hook,
            ),
            RulesCommands::SecurityPatterns => dispatch::run_logged_check(
                &cadence_hooks_rules::check_security_patterns::SecurityPatternScanner,
                post,
                canonical_hook,
            ),
            RulesCommands::WarnRecommendedOption => dispatch::run_logged_check(
                &cadence_hooks_rules::askuserquestion::WarnRecommendedOption,
                pre,
                canonical_hook,
            ),
            RulesCommands::WarnEmptyAnswers => dispatch::run_logged_check(
                &cadence_hooks_rules::askuserquestion::WarnEmptyAnswers,
                post,
                canonical_hook,
            ),
        },
        Commands::Obsidian(cmd) => match cmd {
            ObsidianCommands::TrashGuard => dispatch::run_logged_check(
                &cadence_hooks_obsidian::trash_guard::ObsidianTrashGuard,
                pre,
                canonical_hook,
            ),
        },
        Commands::Metrics(cmd) => match cmd {
            MetricsCommands::Snapshot => dispatch::run_logged_logger(
                &cadence_hooks_metrics::Snapshot,
                registry::sample_for("metrics", "snapshot"),
                canonical_hook,
            ),
            MetricsCommands::LogCommit { prices } => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogCommit {
                    prices_path: prices,
                },
                registry::sample_for("metrics", "log-commit"),
                canonical_hook,
            ),
            MetricsCommands::LogSubagent => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogSubagent,
                registry::sample_for("metrics", "log-subagent"),
                canonical_hook,
            ),
            MetricsCommands::LogSession { prices } => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogSession {
                    prices_path: prices,
                },
                registry::sample_for("metrics", "log-session"),
                canonical_hook,
            ),
            MetricsCommands::LogSessionStart => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogSessionStart,
                registry::sample_for("metrics", "log-session-start"),
                canonical_hook,
            ),
            MetricsCommands::LogPolishNudge => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogPolishNudge,
                registry::sample_for("metrics", "log-polish-nudge"),
                canonical_hook,
            ),
            MetricsCommands::LogAskUserQuestion => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogAskUserQuestion,
                registry::sample_for("metrics", "log-ask-user-question"),
                canonical_hook,
            ),
            MetricsCommands::LogSkill => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogSkill,
                registry::sample_for("metrics", "log-skill"),
                canonical_hook,
            ),
            // warn-stale is a SessionStart *check*, not a logger — it reads the
            // metrics dir's mtimes rather than reacting to a tool event.
            MetricsCommands::WarnStale => dispatch::run_logged_check(
                &cadence_hooks_metrics::WarnStale,
                session,
                canonical_hook,
            ),
        },
        Commands::Session(cmd) => match cmd {
            SessionCommands::Start => dispatch::run_logged_check(
                &cadence_hooks_session::start::Start,
                session,
                canonical_hook,
            ),
            // Heartbeat/End/BackstopRecord run through the logged dispatcher so
            // the #271 subprocess deadline is armed (they spawn git) and its
            // degradation rows have an emission path — core cannot reach the
            // metrics crate to report a deadline hit itself.
            SessionCommands::Heartbeat => dispatch::run_logged_logger(
                &cadence_hooks_session::heartbeat::Heartbeat,
                registry::sample_for("session", "heartbeat"),
                canonical_hook,
            ),
            SessionCommands::Guard => dispatch::run_logged_check(
                &cadence_hooks_session::guard::Guard,
                pre,
                canonical_hook,
            ),
            SessionCommands::WarnBranchDrift => dispatch::run_logged_check(
                &cadence_hooks_session::branch_drift::WarnBranchDrift,
                pre,
                canonical_hook,
            ),
            SessionCommands::WarnBranchIntent => dispatch::run_logged_check(
                &cadence_hooks_session::branch_intent::WarnBranchIntent,
                pre,
                canonical_hook,
            ),
            SessionCommands::WarnCommitProvenance => dispatch::run_logged_check(
                &cadence_hooks_session::warn_commit_provenance::WarnCommitProvenance,
                pre,
                canonical_hook,
            ),
            SessionCommands::End => dispatch::run_logged_logger(
                &cadence_hooks_session::end::End,
                registry::sample_for("session", "end"),
                canonical_hook,
            ),
            SessionCommands::BackstopRecord => dispatch::run_logged_logger(
                &cadence_hooks_session::backstop::BackstopRecord,
                registry::sample_for("session", "backstop-record"),
                canonical_hook,
            ),
            SessionCommands::BackstopWarn => dispatch::run_logged_check(
                &cadence_hooks_session::backstop::BackstopWarn,
                session,
                canonical_hook,
            ),
            SessionCommands::PersistPlan => dispatch::run_logged_check(
                &cadence_hooks_session::persist_plan::PersistPlan,
                user_prompt_submit,
                canonical_hook,
            ),
            SessionCommands::PersistPlanApproval => dispatch::run_logged_check(
                &cadence_hooks_session::persist_plan::PersistPlanApproval,
                post,
                canonical_hook,
            ),
            SessionCommands::Declare {
                intent,
                touching,
                session_id,
            } => {
                cadence_hooks_session::cli::run_declare(intent, touching, session_id);
            }
            SessionCommands::Status => {
                cadence_hooks_session::cli::run_status();
            }
        },
    }
}

/// Finish a `dismiss-*` CLI action. On success, record the `bypass_armed` event
/// (the binary owns the metrics writer — this keeps the guardrails crate
/// metrics-free, mirroring the used-at-seam pattern in [`dispatch`]) and print
/// the confirmation before exiting 0. On a handled error — already reported to
/// stderr by `perform_dismiss` — exit 1. The armed write is fire-and-forget
/// inside [`cadence_hooks_metrics::log_bypass`]: a failure never affects the exit.
fn finish_dismiss(result: Result<cadence_hooks_guardrails::snooze_meta::DismissArmed, ()>) -> ! {
    match result {
        Ok(armed) => {
            cadence_hooks_metrics::log_bypass(cadence_hooks_metrics::BypassEvent::armed(
                armed.guard_hook,
                armed.mechanism,
                armed.reason.as_deref(),
                armed.session_id.as_deref(),
                armed.repo_root.as_deref(),
                armed.armed_at,
                armed.expires_at,
            ));
            println!("{}", armed.confirmation);
            std::process::exit(0);
        }
        Err(()) => std::process::exit(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry must mirror clap's dispatch exactly — both directions.
    ///
    /// This is the mechanical enforcement of "single source of truth"
    /// (issue #39 P1): it is filesystem-independent, so it runs on every
    /// bare-checkout `cargo test`, unlike the hooks.json audit test which
    /// skips when sibling plugin dirs are absent.
    #[test]
    fn registry_matches_clap_dispatch() {
        let cli = Cli::command();
        let namespaces = [
            "cadence",
            "guardrails",
            "rules",
            "obsidian",
            "metrics",
            "session",
        ];
        // clap subcommands that are CLI actions, not hooks (no hooks.json wiring).
        let non_hooks = [
            "dismiss-main-branch-warn",
            "dismiss-enforce-worktree",
            "declare",
            "status",
            "record-polish",
            "redact-scan",
        ];

        let mut clap_pairs: Vec<(String, String)> = Vec::new();
        for ns in namespaces {
            let ns_cmd = cli
                .find_subcommand(ns)
                .unwrap_or_else(|| panic!("namespace '{ns}' should exist in clap"));
            for sub in ns_cmd.get_subcommands() {
                let name = sub.get_name().to_string();
                if !non_hooks.contains(&name.as_str()) {
                    clap_pairs.push((ns.to_string(), name));
                }
            }
        }

        // Direction 1: every dispatchable clap subcommand has a registry entry.
        for (ns, sub) in &clap_pairs {
            assert!(
                registry::is_known(ns, sub),
                "clap subcommand '{ns} {sub}' is dispatchable but missing from \
                 registry::HOOKS — list/doctor/configure won't know it exists"
            );
        }

        // Direction 2: every registry entry is a dispatchable clap subcommand.
        for hook in HOOKS {
            assert!(
                clap_pairs
                    .iter()
                    .any(|(ns, sub)| ns == hook.plugin && sub == hook.name),
                "registry entry '{} {}' has no clap subcommand — it's listed but not dispatchable",
                hook.plugin,
                hook.name
            );
        }
    }
}
