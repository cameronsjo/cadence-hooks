//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each hook subcommand reads JSON from stdin (the hook protocol) and exits
//! with 0 (allow), 1 (warn), or 2 (block). The CLI commands (`list`, `doctor`,
//! `configure`, `try`, `session declare`/`status`) take no stdin.

use cadence_hooks_core::{HookEvent, run_logger_from_stdin};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::process;

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

    /// Cadence lab (experimental) hooks (read hook JSON on stdin)
    #[command(subcommand)]
    Lab(LabCommands),

    /// Multi-session coordination hooks (cadence-canon; hooks read JSON on stdin)
    #[command(subcommand)]
    Session(SessionCommands),

    /// Run a hook against a generated sample payload (manual testing)
    Try {
        /// Hook namespace (cadence, guardrails, rules, obsidian, metrics, lab, session)
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
    /// Record that /polish ran on this branch (writes a branch-scoped marker). CLI action.
    RecordPolish {
        #[arg(long, value_name = "PATH")]
        repo_root: Option<String>,
        #[arg(long, value_name = "NAME")]
        branch: Option<String>,
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
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
    /// Log plan-lifecycle events: EnterPlanMode / ExitPlanMode (PostToolUse)
    LogPlanPhase {
        /// Override path to the model price table (JSON). Falls back to the
        /// embedded default; `CADENCE_METRICS_PRICES` env takes precedence.
        #[arg(long, value_name = "PATH")]
        prices: Option<String>,
    },
    /// Log polish-nudge skips: `gh pr create` + whether /polish ran (PostToolUse)
    LogPolishNudge,
    /// Log AskUserQuestion stance + shape on every call (PreToolUse)
    LogAskUserQuestion,
    /// Log skill invocations (PostToolUse:Skill)
    LogSkill,
    /// Warn at SessionStart when metrics telemetry has gone stale (SessionStart)
    WarnStale,
}

#[derive(Subcommand)]
enum LabCommands {
    /// Inject the self-representation contract on session start (SessionStart)
    PersonaNudge,
    /// Validate and promote a self-representation candidate (PostToolUse)
    PersonaGate,
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
    /// Deregister this session's registry file when it ends (SessionEnd logger)
    End,
    /// Record loose ends when the session ends, for the next start to surface (SessionEnd logger)
    BackstopRecord,
    /// Warn at session start when the last session in this repo left loose ends (SessionStart)
    BackstopWarn,
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
            // record-polish is a CLI action, not a hook — no hooks.json wiring
            // and not subject to CADENCE_DISABLE (same treatment as declare /
            // status / dismiss-*).
            CadenceCommands::RecordPolish { .. } => return None,
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
            MetricsCommands::LogPlanPhase { .. } => "log-plan-phase",
            MetricsCommands::LogPolishNudge => "log-polish-nudge",
            MetricsCommands::LogAskUserQuestion => "log-ask-user-question",
            MetricsCommands::LogSkill => "log-skill",
            MetricsCommands::WarnStale => "warn-stale",
        }),
        Commands::Lab(l) => Some(match l {
            LabCommands::PersonaNudge => "persona-nudge",
            LabCommands::PersonaGate => "persona-gate",
        }),
        Commands::Session(s) => Some(match s {
            SessionCommands::Start => "start",
            SessionCommands::Heartbeat => "heartbeat",
            SessionCommands::Guard => "guard",
            SessionCommands::WarnBranchDrift => "warn-branch-drift",
            SessionCommands::WarnBranchIntent => "warn-branch-intent",
            SessionCommands::End => "end",
            SessionCommands::BackstopRecord => "backstop-record",
            SessionCommands::BackstopWarn => "backstop-warn",
            // declare and status are CLI actions, not hooks — no hooks.json
            // wiring and not subject to CADENCE_DISABLE (same treatment as
            // dismiss-main-branch-warn).
            SessionCommands::Declare { .. } | SessionCommands::Status => return None,
        }),
        Commands::Try { .. }
        | Commands::List
        | Commands::Configure { .. }
        | Commands::Doctor { .. } => None,
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

fn main() {
    // Maintenance bypass — set CADENCE_BYPASS=1 to skip all enforcement.
    // Useful when editing hook source or testing. Per-session, can't be left on accidentally.
    // Note: `list`, `configure`, `doctor`, `try`, and the session CLI actions
    // (`declare`, `status`) are exempt — they're CLI/diagnostic commands, not
    // enforcement paths, and must work always. A bypassed doctor would report
    // false-clean in CI; a bypassed `session status` would hide live peers
    // exactly when someone is debugging coordination.
    let bypassed = std::env::var("CADENCE_BYPASS").as_deref() == Ok("1");
    // Match on subcommand *position* (argv[1], or argv[1]+argv[2] for session
    // CLI actions) — not any argv token, which would let a hook argument that
    // happens to equal "list"/"try"/etc. skip the bypass short-circuit.
    let mut positional = std::env::args().skip(1);
    let bypass_exempt = matches!(
        (positional.next().as_deref(), positional.next().as_deref()),
        (Some("list" | "configure" | "doctor" | "try"), _)
            | (Some("session"), Some("declare" | "status"))
    );
    if bypassed && !bypass_exempt {
        eprintln!("⚠️  cadence-hooks: all enforcement bypassed (CADENCE_BYPASS=1)");
        process::exit(0);
    }

    // Catch panics and exit 1 (warn) instead of the default exit 101.
    // A panic means a bug in a check — it should not block the user's operation.
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
        cadence_hooks_metrics::log_failopen(
            "panic",
            namespace.as_deref(),
            subcommand.as_deref(),
            env!("CARGO_PKG_VERSION"),
        );
        process::exit(1);
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
                    cadence_hooks_metrics::log_failopen(
                        "version_mismatch",
                        namespace.as_deref(),
                        subcommand.as_deref(),
                        installed,
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
            CadenceCommands::RecordPolish {
                repo_root,
                branch,
                scope,
            } => {
                cadence_hooks_cadence::record_polish::run_record(repo_root, branch, scope);
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
            MetricsCommands::LogPlanPhase { prices } => dispatch::run_logged_logger(
                &cadence_hooks_metrics::LogPlanPhase {
                    prices_path: prices,
                },
                registry::sample_for("metrics", "log-plan-phase"),
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
        Commands::Lab(cmd) => match cmd {
            LabCommands::PersonaNudge => dispatch::run_logged_check(
                &cadence_hooks_lab::nudge::PersonaNudge,
                session,
                canonical_hook,
            ),
            LabCommands::PersonaGate => dispatch::run_logged_check(
                &cadence_hooks_lab::gate::PersonaGate,
                post,
                canonical_hook,
            ),
        },
        Commands::Session(cmd) => match cmd {
            SessionCommands::Start => dispatch::run_logged_check(
                &cadence_hooks_session::start::Start,
                session,
                canonical_hook,
            ),
            SessionCommands::Heartbeat => run_logger_from_stdin(
                &cadence_hooks_session::heartbeat::Heartbeat,
                registry::sample_for("session", "heartbeat"),
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
            SessionCommands::End => run_logger_from_stdin(
                &cadence_hooks_session::end::End,
                registry::sample_for("session", "end"),
            ),
            SessionCommands::BackstopRecord => run_logger_from_stdin(
                &cadence_hooks_session::backstop::BackstopRecord,
                registry::sample_for("session", "backstop-record"),
            ),
            SessionCommands::BackstopWarn => dispatch::run_logged_check(
                &cadence_hooks_session::backstop::BackstopWarn,
                session,
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
            "lab",
            "session",
        ];
        // clap subcommands that are CLI actions, not hooks (no hooks.json wiring).
        let non_hooks = [
            "dismiss-main-branch-warn",
            "dismiss-enforce-worktree",
            "declare",
            "status",
            "record-polish",
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
