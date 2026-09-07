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
//! suppression keys on the *path* the repo is being created at. The command is
//! walked segment by segment, tracking `cd` the way the shell does, so **every**
//! `git init` gets its own resolved site; suppression needs all of them under a
//! temp root. Position matters in both directions — a `cd` after the init cannot
//! reclassify it, and a temp-rooted fixture cannot vouch for a real repo created
//! later in the same command. Classification reuses [`path_under_temp_root`],
//! the same primitive `guard_rm` classifies delete targets with.
//!
//! A "zero commits, no remote" predicate was considered for this and REJECTED:
//! it is true of *every* repo one millisecond after `git init`, so it would
//! suppress ~100% of legitimate nudges — the guard would fire only for repos
//! that no longer need it. Path is the only signal available at init time that
//! separates a fixture from a project.

use cadence_hooks_core::shell::{looks_absolute, strip_quotes};
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

/// Tokens that end one command and begin the next. Splitting on these is what
/// makes the walk below position-aware: a `cd` only moves the shell when it is
/// its own segment's first word, so `echo cd /tmp && git init` no longer reads
/// as a `cd`, and a `cd` *after* the init cannot reach back and reclassify it.
const SEPARATORS: [&str; 5] = ["&&", "||", ";", "|", "&"];

/// `git init` flags whose value is a separate token — the value must never be
/// mistaken for the target directory.
const INIT_VALUE_FLAGS: [&str; 4] = ["-b", "--initial-branch", "--separate-git-dir", "--template"];

/// Where one `git init` in the command will create its repo.
#[derive(Debug, PartialEq, Eq)]
enum InitSite {
    /// The resolved directory the repo lands in.
    At(PathBuf),
    /// The target names a value the shell builds at run time, or no directory
    /// is knowable at all — there is no path to classify.
    Unresolvable,
}

/// Strip surrounding quote characters and reject spellings this parser cannot
/// resolve: an unexpanded `$VAR` or `~`, and the empty string.
fn literal_path_token(token: &str) -> Option<&str> {
    let bare = token.trim_matches(['"', '\'']);
    if bare.is_empty() || bare.starts_with('$') || bare.starts_with('~') {
        return None;
    }
    Some(bare)
}

/// Join `candidate` onto `base`, or take it whole when it is absolute.
///
/// Absoluteness is decided from the STRING, via `core::shell::looks_absolute`,
/// not from `Path::is_absolute`. These are bash command lines: a leading `/` is
/// absolute regardless of the host this binary was compiled for. `is_absolute`
/// is drive-letter-aware only on Windows, so it calls `/Users/x/project`
/// *relative* there — the target then found no base to join onto, resolved to
/// nothing, and a real repo classified as `Unresolvable`, which handed the
/// verdict to the `mktemp` tell (the Windows-only false-allow on
/// `mktemp -d && git init /Users/x/Projects/real`). Same platform split, same
/// fail-open shape as `enforce_worktree`'s `is_shell_absolute`
/// (cadence-hooks#377/#378), so it takes that function's remedy: the string
/// check first, with `Path::is_absolute` kept as a belt-and-braces fallback for
/// a native Windows form the string check does not cover (a UNC share).
fn resolve_against(candidate: &str, base: Option<&Path>) -> Option<PathBuf> {
    if looks_absolute(candidate) || Path::new(candidate).is_absolute() {
        Some(PathBuf::from(candidate))
    } else {
        base.map(|b| b.join(candidate))
    }
}

/// The directory a `cd` segment moves the shell to, or `None` when it cannot be
/// named. Mirrors `guard_rm::collect_targets`' conventions: cd's own flags are
/// skipped, and a bare `-`, a `$VAR`, or a missing target makes the new
/// directory UNKNOWN rather than silently keeping the old one.
fn cd_destination(segment: &[&str], base: Option<&Path>) -> Option<PathBuf> {
    let mut idx = 1;
    while segment
        .get(idx)
        .is_some_and(|t| *t == "--" || (t.starts_with('-') && *t != "-"))
    {
        idx += 1;
    }
    let target = segment.get(idx)?;
    if *target == "-" {
        return None;
    }
    resolve_against(literal_path_token(target)?, base)
}

/// Classify the `git init` occurring in `rest` — the segment's tokens after the
/// `[git, init]` pair — against the directory the shell is standing in.
fn init_site(rest: &[&str], effective_dir: Option<&Path>) -> InitSite {
    let mut idx = 0;
    while let Some(word) = rest.get(idx) {
        if INIT_VALUE_FLAGS.contains(word) {
            idx += 2;
        } else if word.starts_with('-') {
            // `--initial-branch=main` and friends carry their value inline.
            idx += 1;
        } else {
            // An explicit target outranks the cwd even when it cannot be
            // resolved — `git init "$d"` names a directory that is emphatically
            // not the one the shell is standing in, so falling back to the cwd
            // would classify the wrong path.
            return match literal_path_token(word).and_then(|t| resolve_against(t, effective_dir)) {
                Some(path) => InitSite::At(path),
                None => InitSite::Unresolvable,
            };
        }
    }
    // No target: the repo lands wherever the shell currently is.
    match effective_dir {
        Some(dir) => InitSite::At(dir.to_path_buf()),
        None => InitSite::Unresolvable,
    }
}

/// Walk the command segment by segment, tracking `cd` the way the shell does,
/// and return one site per `git init` — in command order.
///
/// A miniature cwd tracker rather than a whole-string scan, because both of the
/// shortcuts it replaces were false-allows: taking the LAST `cd` anywhere let a
/// `cd` *after* the init decide its verdict, and resolving only the FIRST
/// `git init` let a temp-rooted fixture vouch for a real repo created later in
/// the same command.
fn init_sites(cmd: &str, cwd: Option<&str>) -> Vec<InitSite> {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let mut effective_dir: Option<PathBuf> = cwd.map(PathBuf::from);
    let mut sites = Vec::new();

    for segment in words.split(|word| SEPARATORS.contains(word)) {
        if segment.first() == Some(&"cd") {
            effective_dir = cd_destination(segment, effective_dir.as_deref());
            continue;
        }
        if let Some(pos) = segment
            .windows(2)
            .position(|w| w[0] == "git" && w[1] == "init")
        {
            sites.push(init_site(&segment[pos + 2..], effective_dir.as_deref()));
        }
    }
    sites
}

/// Is every repo this command creates a throwaway under a temp root?
///
/// **Every** one, deliberately — a single init that resolves outside a temp root
/// keeps the nudge for the whole command. Suppression is the permissive verdict
/// here, so an ambiguous command fails toward the reminder.
///
/// An `Unresolvable` site counts as throwaway only when the command invokes
/// `mktemp`, which is what carries the fixture chain
/// `d=$(mktemp -d) && git init "$d"`. That tell is gated on the site being
/// unresolvable, so a `mktemp` sitting next to an explicit real path never
/// silences it.
fn is_throwaway(cmd: &str, cwd: Option<&str>, tmpdir: Option<&str>, home: Option<&str>) -> bool {
    let sites = init_sites(cmd, cwd);
    if sites.is_empty() {
        return false;
    }
    let mktemp = mentions_mktemp(cmd);
    sites.iter().all(|site| match site {
        InitSite::At(path) => path_under_temp_root(path, tmpdir, home),
        InitSite::Unresolvable => mktemp,
    })
}

/// Does any token in `cmd` invoke `mktemp`?
///
/// Compares the tail of a token after the characters that can precede a command
/// word, with trailing substitution and quote punctuation trimmed — so
/// `$(mktemp)`, `d=$(mktemp`, and `/usr/bin/mktemp` all count. The fixture
/// chains this exists for wrap `mktemp` in a substitution, and an echoed decoy
/// is defused by the caller's gate rather than here: a decoy leaves the init
/// site resolvable, and a resolvable site never consults this tell.
fn mentions_mktemp(cmd: &str) -> bool {
    cmd.split_whitespace().any(|token| {
        token
            .rsplit(['$', '(', '`', ';', '&', '|', '=', '/', '{'])
            .next()
            .map(|tail| tail.trim_end_matches([')', '}', '"', '\'', ';']))
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
            //
            // Resolution reads the RAW command, not `stripped`. Quote-stripping
            // exists to keep prose from tripping the *trigger*; by here the
            // trigger has already fired, and the raw text is what still spells
            // the target — `git init "$d"` survives as a `$`-token to classify
            // rather than vanishing into a bare `git init` that would wrongly
            // resolve to the cwd.
            let tmpdir = std::env::var("TMPDIR").ok();
            let home = cadence_hooks_core::paths::user_home_lossy_or_default();
            if !creates_remote
                && is_throwaway(
                    command,
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
        // A realistic payload: the fixture chain runs from a real project cwd.
        // The explicit `"$d"` target is unresolvable but still outranks that
        // cwd, so the mktemp tell is what carries the suppression.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "d=$(mktemp -d) && git init \"$d\"",
            "/Users/x/Projects/real",
        ));
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
    fn windows_drive_init_target_resolves_standalone() {
        // The counterpart to `mktemp_does_not_suppress_explicit_real_path`, and
        // the reason absoluteness is decided from the string: a drive path reads
        // absolute on EVERY build, so the resolution this asserts is testable
        // from any host rather than only on a Windows runner. Were it read as
        // relative, the target would resolve to nothing and the mktemp tell
        // would allow.
        let result = GuardGitInit.run(&make_bash("mktemp -d && git init C:\\Users\\x\\real"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn cd_to_temp_after_init_still_nudges() {
        // The `cd` runs AFTER the repo is created, so it says nothing about
        // where the repo landed — that is the starting cwd, a real project.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "git init && cd /tmp/logs",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn echoed_cd_decoy_still_nudges() {
        // `cd` is an argument to `echo` here, not a command — the shell never
        // leaves the project directory.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "echo cd /tmp && git init",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn temp_fixture_does_not_vouch_for_later_real_init() {
        // Two inits: the first is a temp fixture, the second a real repo. Every
        // site must be throwaway, so the real one keeps the nudge.
        let result = GuardGitInit.run(&make_bash_with_cwd(
            "git init /tmp/fixture && cd /Users/x/Projects/new && git init",
            "/Users/x/Projects/real",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn temp_init_prefix_does_not_vouch_for_unresolvable_later_init() {
        // Same shape with a `;` separator and a `~` cd the parser cannot expand:
        // the second site is Unresolvable with no mktemp tell, so it nudges.
        let result = GuardGitInit.run(&make_bash("git init /tmp/x; cd ~/p && git init"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn gh_repo_create_from_temp_cwd_still_nudges() {
        // The remote arm is never throwaway — the cwd it runs from is irrelevant.
        let result = GuardGitInit.run(&make_bash_with_cwd("gh repo create foo", "/tmp/probe-3"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }
}
