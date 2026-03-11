//! CLI entry point for compiled Claude Code hooks.
//!
//! Dispatches to per-crate check implementations via `clap` subcommands.
//! Each subcommand reads JSON from stdin (the hook protocol) and exits with
//! 0 (allow), 1 (warn), or 2 (block).

use cadence_hooks_core::run_check_from_stdin;
use clap::{Parser, Subcommand};

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
    /// Warn about untracked files during git operations
    WarnUntracked,
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
    let cli = Cli::parse();

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
            CadenceCommands::WarnUntracked => {
                run_check_from_stdin(&cadence_hooks_cadence::warn_untracked::WarnUntrackedFiles)
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
