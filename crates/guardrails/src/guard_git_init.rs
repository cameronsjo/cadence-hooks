//! Detect new-repo creation (`git init` or `gh repo create`) and prompt for
//! project scaffolding and an explicit license decision.
//!
//! When a new repository is created — locally with `git init` or directly on
//! GitHub with `gh repo create` — this check reminds the user to run
//! `/a-star-is-born` so the repo starts with standard project files, and to
//! confirm the intended license with the author rather than silently assuming
//! one.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Warns on new-repo creation so the user can scaffold standards and confirm a license.
pub struct GuardGitInit;

/// `git init` as a standalone command — `[git, init]` adjacency.
///
/// Retains chained-command behavior (e.g. `mkdir proj && git init`) since
/// adjacency is checked across the whole token stream.
fn is_git_init(cmd: &str) -> bool {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    words.windows(2).any(|w| w[0] == "git" && w[1] == "init")
}

/// `gh repo create` as a standalone command — `[gh, repo, create]` adjacency.
///
/// Does not fire on `gh repo clone|view|list|fork|edit`, and skips when a help
/// flag (`--help`/`-h`) appears anywhere in the command — exploring the help
/// text creates no repo, so there is nothing to nudge about.
fn is_gh_repo_create(cmd: &str) -> bool {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    if words.iter().any(|w| *w == "--help" || *w == "-h") {
        return false;
    }
    words
        .windows(3)
        .any(|w| w[0] == "gh" && w[1] == "repo" && w[2] == "create")
}

impl Check for GuardGitInit {
    fn name(&self) -> &str {
        "guard-git-init"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Strip quoted strings first so prose like `echo "gh repo create"`
        // doesn't trip the matcher (consistency with sibling gh guards).
        //
        // Accepted limitation: this is an advisory nudge, not a security block,
        // so it deliberately does NOT do the two-pass exec-wrapper unwrap that
        // `guard_gh_dangerous` does. Quoted-subcommand forms (`git 'init'`) and
        // wrapped forms (`bash -c "gh repo create foo"`) slip through — the
        // worst case is a missed reminder, and stripping quotes to defuse prose
        // false-positives is the right trade for a nudge.
        let stripped = strip_quotes(command);

        if is_git_init(&stripped) || is_gh_repo_create(&stripped) {
            return CheckResult::nudge(
                "New repo detected. Run /a-star-is-born to scaffold project standards \
                 (.gitignore, README, CONTRIBUTING, CHANGELOG, LICENSE, Makefile, linting, CI/CD). \
                 The license is the author's decision — confirm which license they want before \
                 assuming one; /cadence-groundwork:choosing-license helps compare options.",
            );
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn git_init_detected() {
        let result = GuardGitInit.run(&make_bash("git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_with_path() {
        let result = GuardGitInit.run(&make_bash("git init my-project"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn normal_command_passes() {
        let result = GuardGitInit.run(&make_bash("git status"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = GuardGitInit.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn init_without_git_allowed() {
        let result = GuardGitInit.run(&make_bash("npm init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_without_init_allowed() {
        let result = GuardGitInit.run(&make_bash("git commit -m 'initial'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_with_branch() {
        let result = GuardGitInit.run(&make_bash("git init -b main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_in_chain() {
        // `split_whitespace` tokenizes "mkdir proj && git init" as
        // [mkdir, proj, &&, git, init], so [git, init] is still adjacent and
        // the chained command nudges.
        let result = GuardGitInit.run(&make_bash("mkdir proj && git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    // --- gh repo create coverage ---

    #[test]
    fn gh_repo_create_detected() {
        let result = GuardGitInit.run(&make_bash("gh repo create foo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_create_bare_detected() {
        let result = GuardGitInit.run(&make_bash("gh repo create"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_create_in_chain_detected() {
        let result = GuardGitInit.run(&make_bash("mkdir foo && gh repo create foo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_create_with_license_still_nudges() {
        // Deliberate: the guard cannot know the author was consulted. `--license`
        // stamps a license, but confirming the author's intent is the whole point,
        // so we still nudge.
        let result = GuardGitInit.run(&make_bash("gh repo create --license mit foo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_clone_allowed() {
        let result = GuardGitInit.run(&make_bash("gh repo clone owner/repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_view_allowed() {
        let result = GuardGitInit.run(&make_bash("gh repo view"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_list_allowed() {
        let result = GuardGitInit.run(&make_bash("gh repo list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_fork_allowed() {
        let result = GuardGitInit.run(&make_bash("gh repo fork owner/repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_help_allowed() {
        let result = GuardGitInit.run(&make_bash("gh repo create --help"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_in_quotes_allowed() {
        // After strip_quotes the command body has no `gh repo create` tokens.
        let result = GuardGitInit.run(&make_bash("echo \"gh repo create\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_in_exec_wrapper_is_missed() {
        // Documents the accepted limitation: `strip_quotes` removes the quoted
        // body, so a `bash -c "gh repo create foo"` wrapper slips past this
        // advisory nudge. Unlike `guard_gh_dangerous` (a security block), the
        // nudge does not do a second raw-command pass — a missed reminder is
        // the only cost. This asserts the current behavior, not desired output.
        let result = GuardGitInit.run(&make_bash("bash -c \"gh repo create foo\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_short_help_flag_allowed() {
        // `-h` is checked alongside `--help`; only `--help` was covered above.
        let result = GuardGitInit.run(&make_bash("gh repo create -h"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_help_suppresses_even_with_name() {
        // The help-flag check spans the whole token stream, so a help flag
        // suppresses the nudge even when a repo name is also present.
        let result = GuardGitInit.run(&make_bash("gh repo create foo --help"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_extra_whitespace_detected() {
        // split_whitespace collapses runs of spaces, so adjacency still holds.
        let result = GuardGitInit.run(&make_bash("gh  repo   create  foo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn git_and_init_non_adjacent_allowed() {
        // "git" and "init" both present but not adjacent
        let result = GuardGitInit.run(&make_bash("git submodule init"));
        // "git" and "submodule" are adjacent, then "submodule" and "init"
        // windows(2) checks: [git, submodule], [submodule, init] — neither is [git, init]
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn terraform_init_not_detected() {
        let result = GuardGitInit.run(&make_bash("terraform init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_bare_warned() {
        let result = GuardGitInit.run(&make_bash("git init --bare"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_reinit_warned() {
        // Re-init existing repo
        let result = GuardGitInit.run(&make_bash("cd /project && git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }
}
