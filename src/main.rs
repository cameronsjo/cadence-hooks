//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each hook subcommand reads JSON from stdin (the hook protocol) and exits
//! with 0 (allow), 1 (warn), or 2 (block). The CLI commands (`list`, `doctor`,
//! `configure`, `try`, `session declare`/`status`) take no stdin.

use cadence_hooks_core::{HookEvent, run_check_from_stdin, run_logger_from_stdin};
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
mod doctor;
mod registry;
mod try_hook;
use registry::{HOOKS, HookEntry};

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
    /// Nudge after idle periods between edits
    CheckIdleReturn,
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
    /// Nudge when `gh pr create` has no closing issue keyword in the body
    WarnPrIssueLink,
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
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// Validate SKILL.md and command frontmatter
    ValidateFrontmatter,
    /// Scan for security anti-patterns
    SecurityPatterns,
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
        }),
        Commands::Guardrails(g) => Some(match g {
            GuardrailsCommands::GuardPushRemote => "guard-push-remote",
            GuardrailsCommands::GuardGhDangerous => "guard-gh-dangerous",
            GuardrailsCommands::GuardGhWrite => "guard-gh-write",
            GuardrailsCommands::GuardGitInit => "guard-git-init",
            GuardrailsCommands::WarnMainBranch => "warn-main-branch",
            GuardrailsCommands::CheckIdleReturn => "check-idle-return",
            GuardrailsCommands::WarnBranchBase => "warn-branch-base",
            GuardrailsCommands::WarnCronDatetime => "warn-cron-datetime",
            GuardrailsCommands::NudgeUpgradeAfterPush => "nudge-upgrade-after-push",
            GuardrailsCommands::WarnUntracked => "warn-untracked",
            GuardrailsCommands::GuardDotfiles => "guard-dotfiles",
            GuardrailsCommands::WarnPrIssueLink => "warn-pr-issue-link",
            GuardrailsCommands::VerifyPrAutoclose => "verify-pr-autoclose",
            GuardrailsCommands::GuardOpVaultScan => "guard-op-vault-scan",
            GuardrailsCommands::WarnCurlAlias => "warn-curl-alias",
            GuardrailsCommands::WarnGhMergePreflight => "warn-gh-merge-preflight",
            GuardrailsCommands::WarnCoderabbitRetrigger => "warn-coderabbit-retrigger",
            GuardrailsCommands::WarnAliasParsing => "warn-alias-parsing",
            GuardrailsCommands::GuardBrowserDevice => "guard-browser-device",
            GuardrailsCommands::InjectGhContext => "inject-gh-context",
            // dismiss-main-branch-warn is a CLI action, not a hook —
            // it has no PreToolUse/PostToolUse wiring and isn't subject
            // to CADENCE_DISABLE. Falling out of the Some(...) here is
            // intentional; handle it specially below.
            GuardrailsCommands::DismissMainBranchWarn { .. } => return None,
        }),
        Commands::Rules(r) => Some(match r {
            RulesCommands::ValidateFrontmatter => "validate-frontmatter",
            RulesCommands::SecurityPatterns => "security-patterns",
        }),
        Commands::Obsidian(o) => Some(match o {
            ObsidianCommands::TrashGuard => "trash-guard",
        }),
        Commands::Metrics(m) => Some(match m {
            MetricsCommands::Snapshot => "snapshot",
            MetricsCommands::LogCommit { .. } => "log-commit",
            MetricsCommands::LogSubagent => "log-subagent",
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

        let status = if bypassed || disabled.contains(&hook.name) {
            " (disabled)"
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
            // Clap errors (unknown subcommand, missing args, etc.) must NOT block
            // operations. Exit code 2 from clap would be interpreted as "block" by
            // the hook protocol. Instead, fail open with a warning so the user
            // knows their cadence-hooks binary may be out of date.
            let installed = env!("CARGO_PKG_VERSION");
            match e.kind() {
                // InvalidSubcommand: entirely unknown subcommand name
                //   (e.g., `cadence-hooks future-plugin some-hook`)
                // UnknownArgument: known subcommand but with unrecognized flags/args
                //   (e.g., `cadence-hooks cadence terminology --new-flag`)
                // MissingSubcommand / DisplayHelpOnMissingArgumentOrSubcommand:
                //   no subcommand provided (e.g., bare `cadence-hooks` or `cadence-hooks cadence`)
                // All indicate misconfiguration or version mismatch. Warn (exit 1) instead of blocking.
                clap::error::ErrorKind::InvalidSubcommand
                | clap::error::ErrorKind::UnknownArgument
                | clap::error::ErrorKind::MissingSubcommand
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    eprintln!(
                        "cadence-hooks v{installed}: unrecognized command or arguments.\n\
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
                    process::exit(1);
                }
                // Everything else (--help, --version, other clap errors) uses
                // clap's default behavior.
                _ => e.exit(),
            }
        }
    };

    // Selective disable — skip specific hooks by name via CADENCE_DISABLE.
    // Comma-separated list of hook names (e.g., "git-safety,warn-main-branch").
    // Set per-project in .claude/settings.json `env` block, or ad-hoc in shell.
    if let Ok(disabled) = std::env::var("CADENCE_DISABLE")
        && let Some(name) = hook_name(&cli.command)
        && disabled.split(',').any(|h| h.trim() == name)
    {
        process::exit(0);
    }

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
        Commands::Doctor { root, quiet } => {
            process::exit(doctor::run(root.as_deref(), quiet).into());
        }
        Commands::Cadence(cmd) => match cmd {
            CadenceCommands::Terminology => {
                run_check_from_stdin(&cadence_hooks_cadence::terminology::TerminologyGuard, pre)
            }
            CadenceCommands::OrphanedTodos => run_check_from_stdin(
                &cadence_hooks_cadence::block_orphaned_todos::OrphanedTodoGuard,
                pre,
            ),
            CadenceCommands::PreventSecretLeaks => run_check_from_stdin(
                &cadence_hooks_cadence::prevent_secret_leaks::SecretLeaksGuard,
                pre,
            ),
            CadenceCommands::PreventSecretWrites => run_check_from_stdin(
                &cadence_hooks_cadence::prevent_secret_writes::SecretWritesGuard,
                pre,
            ),
            CadenceCommands::MemoryGuard => {
                run_check_from_stdin(&cadence_hooks_cadence::memory_guard::MemoryGuard, pre)
            }
            CadenceCommands::GitSafety => {
                run_check_from_stdin(&cadence_hooks_cadence::git_safety::GitSafetyGuard, pre)
            }
            CadenceCommands::LineEndings => run_check_from_stdin(
                &cadence_hooks_cadence::validate_line_endings::LineEndingsGuard,
                pre,
            ),
            CadenceCommands::EnvVars => {
                run_check_from_stdin(&cadence_hooks_cadence::validate_env_vars::EnvVarGuard, pre)
            }
            CadenceCommands::WarnDocsUpdate => run_check_from_stdin(
                &cadence_hooks_cadence::warn_docs_update::WarnDocsUpdate,
                pre,
            ),
            CadenceCommands::WarnOvershare => {
                run_check_from_stdin(&cadence_hooks_cadence::warn_overshare::WarnOvershare, pre)
            }
            CadenceCommands::NudgePolishBeforePr => run_check_from_stdin(
                &cadence_hooks_cadence::nudge_polish_before_pr::NudgePolishBeforePr,
                pre,
            ),
            CadenceCommands::MarkdownLint => {
                run_check_from_stdin(&cadence_hooks_cadence::markdown_lint::MarkdownLint, pre)
            }
        },
        Commands::Guardrails(cmd) => match cmd {
            GuardrailsCommands::GuardPushRemote => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_push_remote::PushRemoteGuard,
                pre,
            ),
            GuardrailsCommands::GuardGhDangerous => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_gh_dangerous::GhDangerousGuard,
                pre,
            ),
            GuardrailsCommands::GuardGhWrite => {
                run_check_from_stdin(&cadence_hooks_guardrails::guard_gh_write::GhWriteGuard, pre)
            }
            GuardrailsCommands::GuardGitInit => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_git_init::GuardGitInit,
                post,
            ),
            GuardrailsCommands::WarnMainBranch => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_main_branch::WarnMainBranch,
                pre,
            ),
            GuardrailsCommands::CheckIdleReturn => run_check_from_stdin(
                &cadence_hooks_guardrails::check_idle_return::CheckIdleReturn,
                pre,
            ),
            GuardrailsCommands::WarnBranchBase => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_branch_base::WarnBranchBase,
                pre,
            ),
            GuardrailsCommands::WarnCronDatetime => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_cron_datetime::WarnCronDatetime,
                pre,
            ),
            GuardrailsCommands::NudgeUpgradeAfterPush => run_check_from_stdin(
                &cadence_hooks_guardrails::nudge_upgrade_after_push::NudgeUpgradeAfterPush,
                post,
            ),
            GuardrailsCommands::WarnUntracked => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_untracked::WarnUntrackedFiles,
                pre,
            ),
            GuardrailsCommands::GuardDotfiles => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_dotfiles::GuardDotfiles,
                pre,
            ),
            GuardrailsCommands::WarnPrIssueLink => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_pr_issue_link::WarnPrIssueLink,
                pre,
            ),
            GuardrailsCommands::VerifyPrAutoclose => run_check_from_stdin(
                &cadence_hooks_guardrails::verify_pr_autoclose::VerifyPrAutoclose,
                post,
            ),
            GuardrailsCommands::GuardOpVaultScan => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_op_vault_scan::OpVaultScanGuard,
                pre,
            ),
            GuardrailsCommands::WarnCurlAlias => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_curl_alias::WarnCurlAlias,
                pre,
            ),
            GuardrailsCommands::WarnGhMergePreflight => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_gh_merge_preflight::WarnGhMergePreflight,
                pre,
            ),
            GuardrailsCommands::WarnCoderabbitRetrigger => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_coderabbit_retrigger::WarnCoderabbitRetrigger,
                pre,
            ),
            GuardrailsCommands::WarnAliasParsing => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_alias_parsing::WarnAliasParsing,
                pre,
            ),
            GuardrailsCommands::GuardBrowserDevice => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_browser_device::GuardBrowserDevice,
                pre,
            ),
            GuardrailsCommands::InjectGhContext => run_check_from_stdin(
                &cadence_hooks_guardrails::inject_gh_context::InjectGhContext,
                session,
            ),
            GuardrailsCommands::DismissMainBranchWarn { for_ } => {
                cadence_hooks_guardrails::dismiss_main_branch_warn::run_dismiss(&for_);
            }
        },
        Commands::Rules(cmd) => match cmd {
            RulesCommands::ValidateFrontmatter => run_check_from_stdin(
                &cadence_hooks_rules::validate_skill_frontmatter::ValidateSkillFrontmatter,
                pre,
            ),
            RulesCommands::SecurityPatterns => run_check_from_stdin(
                &cadence_hooks_rules::check_security_patterns::SecurityPatternScanner,
                post,
            ),
        },
        Commands::Obsidian(cmd) => match cmd {
            ObsidianCommands::TrashGuard => run_check_from_stdin(
                &cadence_hooks_obsidian::trash_guard::ObsidianTrashGuard,
                pre,
            ),
        },
        Commands::Metrics(cmd) => match cmd {
            MetricsCommands::Snapshot => run_logger_from_stdin(
                &cadence_hooks_metrics::Snapshot,
                registry::sample_for("metrics", "snapshot"),
            ),
            MetricsCommands::LogCommit { prices } => run_logger_from_stdin(
                &cadence_hooks_metrics::LogCommit {
                    prices_path: prices,
                },
                registry::sample_for("metrics", "log-commit"),
            ),
            MetricsCommands::LogSubagent => run_logger_from_stdin(
                &cadence_hooks_metrics::LogSubagent,
                registry::sample_for("metrics", "log-subagent"),
            ),
        },
        Commands::Lab(cmd) => match cmd {
            LabCommands::PersonaNudge => {
                run_check_from_stdin(&cadence_hooks_lab::nudge::PersonaNudge, session)
            }
            LabCommands::PersonaGate => {
                run_check_from_stdin(&cadence_hooks_lab::gate::PersonaGate, post)
            }
        },
        Commands::Session(cmd) => match cmd {
            SessionCommands::Start => {
                run_check_from_stdin(&cadence_hooks_session::start::Start, session)
            }
            SessionCommands::Heartbeat => run_logger_from_stdin(
                &cadence_hooks_session::heartbeat::Heartbeat,
                registry::sample_for("session", "heartbeat"),
            ),
            SessionCommands::Guard => {
                run_check_from_stdin(&cadence_hooks_session::guard::Guard, pre)
            }
            SessionCommands::WarnBranchDrift => {
                run_check_from_stdin(&cadence_hooks_session::branch_drift::WarnBranchDrift, pre)
            }
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
        let non_hooks = ["dismiss-main-branch-warn", "declare", "status"];

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
