//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each subcommand reads JSON from stdin (the hook protocol) and exits with
//! 0 (allow), 1 (warn), or 2 (block).

use cadence_hooks_core::{HookEvent, run_check_from_stdin};
use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "cadence-hooks", version, about = "Compiled Claude Code hooks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cadence plugin hooks
    #[command(subcommand)]
    Cadence(CadenceCommands),

    /// Git guardrails hooks
    #[command(subcommand)]
    Guardrails(GuardrailsCommands),

    /// Rules plugin hooks
    #[command(subcommand)]
    Rules(RulesCommands),

    /// Cadence Obsidian plugin hooks
    #[command(subcommand)]
    Obsidian(ObsidianCommands),

    /// List all hooks with descriptions and disable status
    List,
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
    /// Nudge to scaffold after git init
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

/// A hook entry with its name, description, and plugin group.
struct HookEntry {
    name: &'static str,
    description: &'static str,
    plugin: &'static str,
}

/// Complete catalog of all hooks. Single source of truth for `list` output
/// and `hook_name()` resolution. Keep in sync with the enum variants above.
const HOOKS: &[HookEntry] = &[
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
];

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
        }),
        Commands::Rules(r) => Some(match r {
            RulesCommands::ValidateFrontmatter => "validate-frontmatter",
            RulesCommands::SecurityPatterns => "security-patterns",
        }),
        Commands::Obsidian(o) => Some(match o {
            ObsidianCommands::TrashGuard => "trash-guard",
        }),
        Commands::List => None,
    }
}

/// Prints all hooks grouped by plugin, showing disable status.
fn print_hook_list() {
    let disable_var = std::env::var("CADENCE_HOOKS_DISABLE").unwrap_or_default();
    let disabled: Vec<&str> = disable_var
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let bypassed = std::env::var("CADENCE_HOOKS_BYPASS").as_deref() == Ok("1");

    if bypassed {
        println!("CADENCE_HOOKS_BYPASS=1 — all hooks bypassed\n");
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

        println!("  {:<28} {}{}", hook.name, hook.description, status);
    }

    if !disabled.is_empty() {
        println!(
            "\nDisabled via CADENCE_HOOKS_DISABLE: {}",
            disabled.join(", ")
        );
    }
}

fn main() {
    // Maintenance bypass — set CADENCE_HOOKS_BYPASS=1 to skip all enforcement.
    // Useful when editing hook source or testing. Per-session, can't be left on accidentally.
    // Note: `list` subcommand is exempt — it needs to show bypass status.
    let bypassed = std::env::var("CADENCE_HOOKS_BYPASS").as_deref() == Ok("1");
    if bypassed && !std::env::args().any(|a| a == "list") {
        eprintln!("⚠️  cadence-hooks: all enforcement bypassed (CADENCE_HOOKS_BYPASS=1)");
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

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
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

    // Selective disable — skip specific hooks by name via CADENCE_HOOKS_DISABLE.
    // Comma-separated list of hook names (e.g., "git-safety,warn-main-branch").
    // Set per-project in .claude/settings.json `env` block, or ad-hoc in shell.
    if let Ok(disabled) = std::env::var("CADENCE_HOOKS_DISABLE")
        && let Some(name) = hook_name(&cli.command)
            && disabled.split(',').any(|h| h.trim() == name) {
                process::exit(0);
            }

    // Event type aliases for readability at callsites.
    let pre = HookEvent::PreToolUse;
    let post = HookEvent::PostToolUse;

    match cli.command {
        Commands::List => {
            print_hook_list();
            process::exit(0);
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
    }
}
