//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each subcommand reads JSON from stdin (the hook protocol) and exits with
//! 0 (allow), 1 (warn), or 2 (block).

use cadence_hooks_core::run_check_from_stdin;
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

fn main() {
    // Maintenance bypass — set CADENCE_HOOKS_BYPASS=1 to skip all enforcement.
    // Useful when editing hook source or testing. Per-session, can't be left on accidentally.
    if std::env::var("CADENCE_HOOKS_BYPASS").as_deref() == Ok("1") {
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

    match cli.command {
        Commands::Cadence(cmd) => match cmd {
            CadenceCommands::Terminology => {
                run_check_from_stdin(&cadence_hooks_cadence::terminology::TerminologyGuard)
            }
            CadenceCommands::OrphanedTodos => run_check_from_stdin(
                &cadence_hooks_cadence::block_orphaned_todos::OrphanedTodoGuard,
            ),
            CadenceCommands::PreventSecretLeaks => {
                run_check_from_stdin(&cadence_hooks_cadence::prevent_secret_leaks::SecretLeaksGuard)
            }
            CadenceCommands::PreventSecretWrites => run_check_from_stdin(
                &cadence_hooks_cadence::prevent_secret_writes::SecretWritesGuard,
            ),
            CadenceCommands::MemoryGuard => {
                run_check_from_stdin(&cadence_hooks_cadence::memory_guard::MemoryGuard)
            }
            CadenceCommands::GitSafety => {
                run_check_from_stdin(&cadence_hooks_cadence::git_safety::GitSafetyGuard)
            }
            CadenceCommands::LineEndings => run_check_from_stdin(
                &cadence_hooks_cadence::validate_line_endings::LineEndingsGuard,
            ),
            CadenceCommands::EnvVars => {
                run_check_from_stdin(&cadence_hooks_cadence::validate_env_vars::EnvVarGuard)
            }
            CadenceCommands::WarnDocsUpdate => {
                run_check_from_stdin(&cadence_hooks_cadence::warn_docs_update::WarnDocsUpdate)
            }
            CadenceCommands::MarkdownLint => {
                run_check_from_stdin(&cadence_hooks_cadence::markdown_lint::MarkdownLint)
            }
        },
        Commands::Guardrails(cmd) => match cmd {
            GuardrailsCommands::GuardPushRemote => {
                run_check_from_stdin(&cadence_hooks_guardrails::guard_push_remote::PushRemoteGuard)
            }
            GuardrailsCommands::GuardGhDangerous => run_check_from_stdin(
                &cadence_hooks_guardrails::guard_gh_dangerous::GhDangerousGuard,
            ),
            GuardrailsCommands::GuardGhWrite => {
                run_check_from_stdin(&cadence_hooks_guardrails::guard_gh_write::GhWriteGuard)
            }
            GuardrailsCommands::GuardGitInit => {
                run_check_from_stdin(&cadence_hooks_guardrails::guard_git_init::GuardGitInit)
            }
            GuardrailsCommands::WarnMainBranch => {
                run_check_from_stdin(&cadence_hooks_guardrails::warn_main_branch::WarnMainBranch)
            }
            GuardrailsCommands::CheckIdleReturn => {
                run_check_from_stdin(&cadence_hooks_guardrails::check_idle_return::CheckIdleReturn)
            }
            GuardrailsCommands::WarnBranchBase => {
                run_check_from_stdin(&cadence_hooks_guardrails::warn_branch_base::WarnBranchBase)
            }
            GuardrailsCommands::WarnCronDatetime => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_cron_datetime::WarnCronDatetime,
            ),
            GuardrailsCommands::WarnUntracked => run_check_from_stdin(
                &cadence_hooks_guardrails::warn_untracked::WarnUntrackedFiles,
            ),
        },
        Commands::Rules(cmd) => match cmd {
            RulesCommands::ValidateFrontmatter => run_check_from_stdin(
                &cadence_hooks_rules::validate_skill_frontmatter::ValidateSkillFrontmatter,
            ),
            RulesCommands::SecurityPatterns => run_check_from_stdin(
                &cadence_hooks_rules::check_security_patterns::SecurityPatternScanner,
            ),
        },
        Commands::Obsidian(cmd) => match cmd {
            ObsidianCommands::TrashGuard => {
                run_check_from_stdin(&cadence_hooks_obsidian::trash_guard::ObsidianTrashGuard)
            }
        },
    }
}
