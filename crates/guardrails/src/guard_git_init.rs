//! Detect new-repo creation (`git init` or `gh repo create`) and prompt for
//! project scaffolding and an explicit license decision.
//!
//! When a new repository is created — locally with `git init` or directly on
//! GitHub with `gh repo create` — this check reminds the user to run
//! `/a-star-is-born` so the repo starts with standard project files, and to
//! confirm the intended license with the author rather than silently assuming
//! one.
//!
//! **Throwaway repos under a temp root are exempt** (cameronsjo/cadence#899).
//! Test fixtures, scratch probes, and `mktemp -d` sandboxes are `git init`ed
//! constantly, and none of them wants a scaffolding-and-license reminder. The
//! suppression keys on the *path* the repo is being created at — the `git init`
//! target resolved against the last literal `cd`, else the event cwd — and
//! reuses [`path_under_temp_root`], the same primitive `guard_rm` classifies
//! delete targets with.
//!
//! A "zero commits, no remote" predicate was considered for this and REJECTED:
//! it is true of *every* repo one millisecond after `git init`, so it would
//! suppress ~100% of legitimate nudges — the guard would fire only for repos
//! that no longer need it. Path is the only signal available at init time that
//! separates a fixture from a project.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::worktree::path_under_temp_root;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};

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

/// `git init`'s explicit target directory, when it names one literally.
///
/// The first non-flag token after `[git, init]`, skipping init's own flags and
/// consuming the values of the flags that take one. Returns `None` for a bare
/// `git init` and for a target that is only a `$VAR` or `~` — an unexpanded
/// spelling names no path this parser can resolve, so the caller falls through
/// to the next candidate rather than guessing.
fn init_target(cmd: &str) -> Option<&str> {
    /// `git init` flags whose value is a separate token — the value must not be
    /// mistaken for the target directory.
    const VALUE_FLAGS: [&str; 4] = ["-b", "--initial-branch", "--separate-git-dir", "--template"];

    let words: Vec<&str> = cmd.split_whitespace().collect();
    let start = words
        .windows(2)
        .position(|w| w[0] == "git" && w[1] == "init")?
        + 2;

    let mut idx = start;
    while let Some(word) = words.get(idx) {
        if VALUE_FLAGS.contains(word) {
            idx += 2;
        } else if word.starts_with('-') {
            // `--initial-branch=main` and friends carry their value inline.
            idx += 1;
        } else {
            return Some(*word).filter(|t| !t.starts_with('$') && !t.starts_with('~'));
        }
    }
    None
}

/// The target of the LAST literal `cd <dir>` in the command, when there is one.
///
/// Deliberately not full cwd tracking — `guard_rm::collect_targets` carries
/// that machinery because it gates deletions; this is an advisory nudge, and
/// the last `cd` is where a `cd … && git init` chain leaves the shell. Mirrors
/// that parser's conventions: the literal first token only, cd's own flags
/// skipped, and a bare `-` or a `$VAR` yielding `None` because the resulting
/// directory is unknowable here.
fn last_cd_target(cmd: &str) -> Option<&str> {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let mut found = None;

    for (pos, word) in words.iter().enumerate() {
        if *word != "cd" {
            continue;
        }
        let mut idx = pos + 1;
        while words
            .get(idx)
            .is_some_and(|t| *t == "--" || (t.starts_with('-') && *t != "-"))
        {
            idx += 1;
        }
        found = words
            .get(idx)
            .copied()
            .filter(|t| *t != "-" && !t.starts_with('$'));
    }
    found
}

/// Is this `git init` creating a throwaway repo under a temp root?
///
/// Resolution follows the shell's own order. The `cd` runs first, so the last
/// literal `cd` — else the event cwd — is the directory `git init` executes in;
/// an explicit init target is then resolved against *that*, not against the cwd
/// the command started in. So `cd /tmp/x && git init sub` reads as `/tmp/x/sub`,
/// and an absolute target overrides both.
///
/// Each candidate falls through when it cannot be resolved to a path, rather
/// than ending the search: a relative target with no directory to join onto
/// names nothing, and treating it as an answer would discard a perfectly
/// resolvable `cd` behind it.
///
/// One fallback: when NOTHING resolves and the command contains a `mktemp`
/// invocation, treat it as throwaway. That covers the common fixture chain
/// `d=$(mktemp -d) && git init "$d"`, where quote-stripping leaves the target
/// unspellable. The tell is gated on nothing else resolving precisely so it
/// cannot suppress a nudge for an explicit real path sitting next to an
/// unrelated `mktemp`.
fn is_throwaway(cmd: &str, cwd: Option<&str>, tmpdir: Option<&str>, home: Option<&str>) -> bool {
    let resolve = |candidate: &str, base: Option<&Path>| -> Option<PathBuf> {
        let path = Path::new(candidate);
        if path.is_absolute() {
            Some(path.to_path_buf())
        } else {
            base.map(|b| b.join(path))
        }
    };

    let cwd_path = cwd.map(Path::new);
    let effective_dir = last_cd_target(cmd)
        .and_then(|dir| resolve(dir, cwd_path))
        .or_else(|| cwd_path.map(Path::to_path_buf));
    let resolved = init_target(cmd)
        .and_then(|target| resolve(target, effective_dir.as_deref()))
        .or(effective_dir);

    match resolved {
        Some(path) => path_under_temp_root(&path, tmpdir, home),
        None => mentions_mktemp(cmd),
    }
}

/// Does any token in `cmd` invoke `mktemp`?
///
/// Matches the tail of a token after the characters that can precede a command
/// word — `d=$(mktemp` and `/usr/bin/mktemp` both count — because the fixture
/// chains this exists for wrap `mktemp` in a substitution.
fn mentions_mktemp(cmd: &str) -> bool {
    cmd.split_whitespace().any(|token| {
        token
            .rsplit(['$', '(', '`', ';', '&', '|', '=', '/', '{'])
            .next()
            == Some("mktemp")
    })
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

        let creates_remote = is_gh_repo_create(&stripped);

        if is_git_init(&stripped) || creates_remote {
            // Read the env once, guard_rm's convention, and hand both values to
            // the pure decision. `home` feeds `path_under_temp_root`'s veto on a
            // `$TMPDIR` that swallows the home directory (cadence-hooks#569) —
            // without it, `TMPDIR=$HOME` would silence the nudge estate-wide.
            //
            // Only the LOCAL arm is exempt. `gh repo create` publishes a repo to
            // GitHub; the directory it happens to run from says nothing about
            // whether that repo is disposable, so a temp cwd must not silence it.
            let tmpdir = std::env::var("TMPDIR").ok();
            let home = cadence_hooks_core::paths::user_home_lossy_or_default();
            if !creates_remote
                && is_throwaway(
                    &stripped,
                    input.cwd.as_deref(),
                    tmpdir.as_deref(),
                    Some(&home),
                )
            {
                return CheckResult::allow();
            }

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
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};

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

    // --- throwaway-repo suppression ---

    #[test]
    fn git_init_under_slash_tmp_allowed() {
        let result = GuardGitInit.run(&make_bash_with_cwd("git init", "/tmp/probe-1"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_under_private_tmp_allowed() {
        let result = GuardGitInit.run(&make_bash_with_cwd("git init", "/private/tmp/probe-2"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_with_explicit_temp_path_allowed() {
        // The init target outranks a real cwd — the repo lands in /tmp.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "git init /tmp/fixture",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_after_cd_to_temp_allowed() {
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "cd /tmp/fixture && git init",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_relative_target_after_cd_to_temp_allowed() {
        // The relative target resolves against the `cd`, not the starting cwd —
        // the repo lands at /tmp/fixture/sub.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "cd /tmp/fixture && git init sub",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mktemp_fixture_chain_allowed() {
        // `strip_quotes` eats `"$d"`, so no candidate resolves and the mktemp
        // tell is what carries the suppression.
        let result = GuardGitInit.run(&make_bash("d=$(mktemp -d) && git init \"$d\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_init_in_real_project_still_nudges() {
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "git init",
            "/Users/x/Projects/new-thing",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_under_home_tmp_still_nudges() {
        // A directory NAMED tmp under home is not a temp root.
        let result = GuardGitInit.run(&make_bash_with_cwd("git init", "/Users/x/tmp/new-thing"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn mktemp_does_not_suppress_explicit_real_path() {
        // The mktemp tell is gated on nothing else resolving; an explicit real
        // target answers first.
        let result = GuardGitInit.run(&make_bash("mktemp -d && git init /Users/x/Projects/real"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn git_init_no_cwd_still_nudges() {
        // Nothing resolves and nothing tells — fail open to the nudge (ADR-0001).
        let result = GuardGitInit.run(&make_bash("git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_create_from_temp_cwd_still_nudges() {
        // The remote arm is never throwaway — the cwd it runs from is irrelevant.
        let result = GuardGitInit.run(&make_bash_with_cwd("gh repo create foo", "/tmp/probe-3"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }
}
