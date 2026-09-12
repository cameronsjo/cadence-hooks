//! Warn when `git commit --amend` would rewrite a commit that is already on a
//! remote (cadence-hooks#610).
//!
//! Amending a commit that no remote has seen is ordinary hygiene. Amending one
//! that a remote already carries rewrites published history: the local branch
//! and the remote branch diverge, and the only way to reconcile them is a
//! force-push. That second case is the one worth naming, and the test for it is
//! fully deterministic — the repository's remote-tracking refs either contain
//! the commit or they do not.
//!
//! **Remote-tracking refs are a local cache**, so that is what the advisory
//! claims: a commit pushed from a sibling clone reads as unpublished until this
//! one fetches, and a branch deleted upstream reads as published until a
//! `fetch --prune`. Advisory text says "your remote-tracking refs" rather than
//! asserting the remote's live state.
//!
//! **Advisory only, always.** This check never blocks (ADR-0001): amending a
//! pushed commit is a legitimate operation on a branch nobody else reads, and
//! the guard cannot know which branch that is. It exits 0 with a message naming
//! the remote refs that already carry the commit and the follow-up-commit
//! alternative.
//!
//! Every resolution failure — no repository, an unborn `HEAD`, git missing from
//! `PATH`, or the shared subprocess deadline expiring — yields silence rather
//! than a nudge. A guard that cannot see the answer must not invent one.
//!
//! ## Relationship to `cadence git-safety`
//!
//! `git-safety` already nudges on *every* `git commit --amend` with a generic
//! "rewrites last commit". This check is the sharper, state-aware half: it
//! stays silent on the common unpublished amend and speaks only when the
//! rewrite has a remote consequence, naming the refs. The two are wired
//! independently, so a session that finds the unconditional nudge noisy can
//! disable `git-safety` and keep this one (`CADENCE_DISABLE`).
//!
//! ## What the scan sees
//!
//! Amend detection runs over every executable segment `core::shell` can reach,
//! `sh -c '…'` wrappers, command substitutions, and loop/conditional bodies
//! included ([`command_segments`] + [`executable_tokens`]).
//!
//! The probed *directory* is deliberately narrower: the payload `cwd`, advanced
//! only by a `cd` that is a **top-level segment's own command** and ordered
//! **before** the amend, then by that segment's `-C` chain. A `cd` written
//! inside a quoted argument is one token and moves nothing, and a `cd` after
//! the amend moves nothing either — both were live misreads before
//! cadence-hooks#610's security review. A `cd` inside a subshell or a loop body
//! is a named accepted miss: it does not move the parent shell's directory in
//! every case, and guessing wrong points the probe at a different repository.
//!
//! A `--git-dir` or `--work-tree` amend is skipped outright. Its repository is
//! not the segment's directory, so probing there would answer a confident
//! question about the wrong repo — silence is the honest result.
//!
//! Every miss is a lost nudge, never a bypassed block: the check has no block
//! arm.

use cadence_hooks_core::display::sanitize_field;
use cadence_hooks_core::shell::{
    GitOutput, command_segments, command_word, executable_tokens, git_output_detailed,
    resolve_cd_target, skip_transparent_prefixes, split_segments_with_ops,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Most remote refs to name before collapsing the rest into a count. A commit
/// on a dozen mirrors makes the point in five.
const MAX_LISTED_REFS: usize = 5;

/// Display cap for a single remote ref name. A ref name is attacker-chosen in a
/// hostile clone, and the whole list lands in the `additionalContext` Claude
/// reads — [`MAX_LISTED_REFS`] caps how many are named, this caps how long each
/// one may be.
const MAX_REF_DISPLAY: usize = 80;

/// `git` global options whose value is a SEPARATE following word. The walk
/// below must not re-read such a value as a flag: `git -c --work-tree=/x
/// commit` passes that string to `-c`, and reading it as a redirect would
/// probe a tree git never touches. Mirrors the list
/// `guardrails::enforce_worktree` walks for the same reason.
const VALUE_GLOBALS: &[&str] = &[
    "-C",
    "-c",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
    "--work-tree",
    "--git-dir",
];

/// True when `token` selects `git commit`'s `--amend`.
///
/// Matched by PREFIX because git's parse-options accepts any unambiguous
/// abbreviation: `git commit --am` amends. Two characters is the shortest
/// unambiguous prefix (`--a` is ambiguous with `--all` and `--author`, and git
/// rejects it), so names shorter than that are not amends and must not match.
///
/// A `--no-`-prefixed spelling fails the `starts_with` test and so is never
/// read as an amend.
fn is_amend_flag(token: &str) -> bool {
    let Some(name) = token.strip_prefix("--") else {
        return false;
    };
    name.len() >= 2 && "amend".starts_with(name)
}

/// `git commit` options whose value is a SEPARATE following word. That value is
/// data, not a flag: `git commit -m --amend` sets a commit *message*, it does
/// not amend. Prefix-matched for the same reason [`is_amend_flag`] is — git
/// accepts any unambiguous abbreviation.
const COMMIT_VALUE_OPTS: &[&str] = &[
    "-m",
    "-c",
    "-C",
    "-F",
    "-t",
    "-S",
    "-u",
    "--message",
    "--file",
    "--author",
    "--date",
    "--reuse-message",
    "--reedit-message",
    "--fixup",
    "--squash",
    "--cleanup",
    "--template",
    "--trailer",
    "--untracked-files",
    "--pathspec-from-file",
];

/// True when `token` is an option that consumes the NEXT word as its value.
/// A `--opt=value` spelling carries its own value, so it consumes nothing.
fn takes_separate_value(token: &str) -> bool {
    if token.contains('=') {
        return false;
    }
    if let Some(name) = token.strip_prefix("--") {
        return !name.is_empty()
            && COMMIT_VALUE_OPTS
                .iter()
                .filter_map(|opt| opt.strip_prefix("--"))
                .any(|opt| opt.starts_with(name));
    }
    // A short option carries its value attached (`-mwip`) or separate (`-m wip`);
    // only the bare form consumes the next word.
    COMMIT_VALUE_OPTS.contains(&token)
}

/// True when `args` (everything after the `commit` subcommand) selects an
/// amend.
///
/// Two things are skipped rather than read as flags:
///
/// - Everything after `--`, the end-of-options separator: `git commit --
///   --amend` commits a file named `--amend` and rewrites nothing.
/// - The value of any option that takes one ([`takes_separate_value`]), so a
///   message or author string spelling `--amend` is not read as the flag.
fn selects_amend(args: &[String]) -> bool {
    let mut idx = 0;
    while idx < args.len() {
        let arg = args[idx].as_str();
        if arg == "--" {
            return false;
        }
        if is_amend_flag(arg) {
            return true;
        }
        idx += if takes_separate_value(arg) { 2 } else { 1 };
    }
    false
}

/// True when `argv`'s git globals redirect the repository somewhere this check
/// cannot resolve — `--git-dir` or `--work-tree`, in either spelling.
fn redirects_repository(argv: &[String]) -> bool {
    argv.iter().enumerate().any(|(i, token)| {
        matches!(token.as_str(), "--git-dir" | "--work-tree")
            || token.starts_with("--git-dir=")
            || token.starts_with("--work-tree=")
            // A value that merely LOOKS like one of these belongs to the
            // preceding option and is not a redirect.
            && i > 0
            && !VALUE_GLOBALS.contains(&argv[i - 1].as_str())
    })
}

/// The directories an amending `git commit` in `command` would run in, one per
/// matching segment, resolved against `cwd`.
///
/// Walks the command's TOP-LEVEL segments in order, carrying an effective
/// directory that only a top-level `cd` moves — and only for the segments that
/// follow it, since the shell's `cd` takes effect after that segment runs.
/// Within each top-level segment, every executable segment `core::shell` can
/// reach is examined for an amend (a `sh -c` wrapper, a substitution, a loop
/// body), each resolved against that segment's effective directory plus its own
/// `-C` chain.
///
/// Empty when the command contains no amend — the common case, and the one that
/// costs no git spawn at all.
fn amend_target_dirs(command: &str, cwd: &str) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    let mut effective = cwd.to_string();

    for (segment, _op) in split_segments_with_ops(command) {
        for inner in command_segments(&segment) {
            if let Some(dir) = amend_dir_of(&executable_tokens(&inner), &effective)
                && !dirs.contains(&dir)
            {
                dirs.push(dir);
            }
        }

        // A `cd` applies to what comes AFTER it, so this runs once the segment
        // has been examined. Only the segment's own leading `cd` counts: a `cd`
        // inside a quoted argument is a single token and never reaches here.
        let tokens = executable_tokens(&segment);
        if tokens.first().map(String::as_str) == Some("cd")
            && let Some(target) = tokens.get(1)
        {
            effective = resolve_cd_target(target, &effective);
        }
    }

    dirs
}

/// The directory an amending `git commit` in `argv` would run in, or `None`
/// when `argv` is not one.
fn amend_dir_of(tokens: &[String], effective: &str) -> Option<String> {
    let argv = skip_transparent_prefixes(tokens);
    // `command_word` normalizes `/usr/bin/git`, `\git`, and the Windows
    // `git.exe` spellings — an exact compare against "git" misses every one of
    // them.
    if command_word(argv.first()?) != "git" {
        return None;
    }

    let mut redirect: Option<String> = None;
    let mut idx = 1;
    while idx < argv.len()
        && (argv[idx].starts_with('-') || VALUE_GLOBALS.contains(&argv[idx - 1].as_str()))
    {
        // `-C` compounds: each hop resolves against the previous one.
        if argv[idx - 1] == "-C" {
            let from = redirect.as_deref().unwrap_or(effective);
            redirect = Some(resolve_cd_target(&argv[idx], from));
        }
        idx += 1;
    }

    if argv.get(idx).map(String::as_str) != Some("commit") {
        return None;
    }
    if !selects_amend(&argv[idx + 1..]) {
        return None;
    }
    // The repository is elsewhere and this check cannot say where — answering
    // about the segment's directory would be a confident answer about the wrong
    // repo.
    if redirects_repository(&argv[..idx]) {
        return None;
    }

    Some(redirect.unwrap_or_else(|| effective.to_string()))
}

/// The refs named by `git for-each-ref --format='%(refname:short) %(symref)'`
/// over `refs/remotes/`: one `<name> [<symref target>]` per line.
///
/// A row with a non-empty symref field is a symbolic ref (`origin/HEAD`), a
/// pointer at a branch already listed on its own — dropped, so the same branch
/// is not reported twice in a shape no one pushes to.
///
/// **`for-each-ref`, not `git branch -r`.** `branch` is porcelain: with
/// `color.ui = always` its names come back wrapped in SGR escapes, and with
/// `column.ui = always` several refs share a line — measured, that pasted four
/// names into one "ref" and silently DROPPED the one sharing a line with
/// `origin/HEAD`, because the old symbolic-line filter discarded the whole
/// line. `for-each-ref` is plumbing and honors neither setting.
fn parse_remote_refs(output: &str) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    for line in output.lines() {
        let (name, symref) = match line.trim_end().split_once(' ') {
            Some((name, rest)) => (name, rest.trim()),
            None => (line.trim_end(), ""),
        };
        let name = name.trim();
        if name.is_empty() || !symref.is_empty() {
            continue;
        }
        if !refs.iter().any(|existing| existing == name) {
            refs.push(name.to_string());
        }
    }
    refs
}

/// Remote refs containing `HEAD` in `dir`, or `None` when the question could
/// not be answered.
///
/// The three outcomes that are not a clean answer — git exited non-zero (no
/// repository, unborn `HEAD`), git could not be spawned, or the deadline
/// expired — all collapse to `None`, i.e. silence. `Ok("")` is a real answer
/// ("no remote has it") and also yields `None`, because the nudge has nothing
/// to say; [`git_output_detailed`] is used rather than the `Option`-shaped
/// wrapper so that distinction is visible here rather than folded away.
fn remote_refs_containing_head(dir: &str) -> Option<Vec<String>> {
    match git_output_detailed(
        dir,
        &[
            "for-each-ref",
            "--contains",
            "HEAD",
            "--format=%(refname:short) %(symref)",
            "refs/remotes/",
        ],
    ) {
        GitOutput::Ok(out) => {
            let refs = parse_remote_refs(&out);
            (!refs.is_empty()).then_some(refs)
        }
        GitOutput::Failed | GitOutput::Unavailable | GitOutput::TimedOut => None,
    }
}

/// The advisory text naming the refs that already carry the commit.
fn message(refs: &[String]) -> String {
    // Ref names are attacker-chosen in a hostile clone and this text lands in
    // the additionalContext Claude reads — sanitize every one at display time,
    // the rule `core::display` states for any untrusted interpolation.
    let listed: Vec<String> = refs
        .iter()
        .take(MAX_LISTED_REFS)
        .map(|r| sanitize_field(r, MAX_REF_DISPLAY))
        .collect();
    let mut named = listed.join(", ");
    if refs.len() > listed.len() {
        named.push_str(&format!(" (+{} more)", refs.len() - listed.len()));
    }

    format!(
        "⚠️  Your remote-tracking refs already carry this commit: {named}\n\n\
         `git commit --amend` rewrites it, so the local branch and the remote \
         branch diverge and only a force-push can reconcile them.\n\n\
         Safer: leave the pushed commit alone and record the change as a new \
         commit on top (`git commit`), then push normally.\n\
         Amend anyway if this branch is yours alone and you expect the \
         force-push."
    )
}

/// Nudges when an amending `git commit` targets a commit a remote already has.
pub struct WarnAmendPushed;

impl Check for WarnAmendPushed {
    fn name(&self) -> &str {
        "warn-amend-pushed"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let cwd = input.cwd.as_deref().unwrap_or(".");

        for dir in amend_target_dirs(command, cwd) {
            if let Some(refs) = remote_refs_containing_head(&dir) {
                return CheckResult::nudge(message(&refs));
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};
    use std::path::{Path, PathBuf};

    // --- is_amend_flag / selects_amend: pure ---

    #[test]
    fn amend_flag_spellings() {
        for token in ["--amend", "--amen", "--ame", "--am"] {
            assert!(is_amend_flag(token), "{token} selects --amend");
        }
        for token in [
            "--a",
            "--all",
            "--author",
            "--no-amend",
            "-a",
            "amend",
            "--",
        ] {
            assert!(!is_amend_flag(token), "{token} does not select --amend");
        }
    }

    #[test]
    fn selects_amend_stops_at_end_of_options() {
        let args: Vec<String> = ["--", "--amend"].iter().map(|s| s.to_string()).collect();
        assert!(
            !selects_amend(&args),
            "a pathspec named --amend is not an amend"
        );
    }

    #[test]
    fn selects_amend_finds_the_flag_anywhere() {
        let args: Vec<String> = ["-a", "--no-edit", "--amend"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(selects_amend(&args));
    }

    #[test]
    fn selects_amend_skips_option_values() {
        // `git commit -m --amend` writes a MESSAGE reading "--amend"; it
        // rewrites nothing.
        for spelling in [
            vec!["-m", "--amend"],
            vec!["--message", "--amend"],
            vec!["--author", "--amend"],
            vec!["-F", "--amend"],
        ] {
            let args: Vec<String> = spelling.iter().map(|s| s.to_string()).collect();
            assert!(
                !selects_amend(&args),
                "{spelling:?} passes --amend as a value"
            );
        }
    }

    #[test]
    fn selects_amend_still_sees_the_flag_after_an_option_value() {
        let args: Vec<String> = ["-m", "wip", "--amend"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(selects_amend(&args));
    }

    #[test]
    fn an_attached_option_value_consumes_no_following_word() {
        let args: Vec<String> = ["--message=wip", "--amend"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            selects_amend(&args),
            "`--opt=value` carries its own value and must not swallow --amend"
        );
    }

    // --- amend_target_dirs: table ---

    #[test]
    fn amend_spellings_resolve_to_the_cwd() {
        let matching = [
            "git commit --amend",
            "git commit --amend --no-edit",
            "git commit -a --amend",
            "git commit --am",
            "/usr/bin/git commit --amend",
            r"\git commit --amend",
            "git -c commit.gpgsign=false commit --amend",
            "git add -A && git commit --amend --no-edit",
            // Keyword-headed segments: a bare token walk never reached these.
            "for d in x; do git commit --amend; done",
            "if true; then git commit --amend; fi",
            "sh -c 'git commit --amend'",
        ];
        for command in matching {
            assert_eq!(
                amend_target_dirs(command, "/cwd"),
                vec!["/cwd".to_string()],
                "{command} should resolve one amend target"
            );
        }
    }

    #[test]
    fn non_amend_commands_resolve_nothing() {
        let ignored = [
            "git commit -m 'x'",
            "git commit --all --no-edit",
            "git push --force origin feature",
            "git rebase -i HEAD~2",
            "echo git commit --amend",
            "ls -la",
            "git commit -- --amend",
            "git commit -m --amend",
            // The repository is elsewhere; probing the segment's dir would
            // answer confidently about the wrong repo.
            "git --git-dir=/other/.git commit --amend",
            "git --work-tree=/other commit --amend",
            "git --git-dir /other/.git commit --amend",
        ];
        for command in ignored {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} should resolve no amend target"
            );
        }
    }

    #[test]
    fn dash_c_redirects_the_probe() {
        assert_eq!(
            amend_target_dirs("git -C /some/worktree commit --amend", "/cwd"),
            vec!["/some/worktree".to_string()]
        );
    }

    #[test]
    fn dash_c_compounds_and_resolves_relative_hops() {
        assert_eq!(
            amend_target_dirs("git -C /a -C b commit --amend", "/cwd"),
            vec!["/a/b".to_string()]
        );
    }

    #[test]
    fn dash_c_value_is_not_reread_as_a_redirect() {
        // `-C` is the VALUE of `-c` here, so it must not move the probe.
        assert_eq!(
            amend_target_dirs("git -c alias.x=-C commit --amend", "/cwd"),
            vec!["/cwd".to_string()]
        );
        // The bare spelling is the sharper case: a walk that re-read the value
        // as a flag would treat `commit` as the `-C` target directory.
        assert!(
            !amend_target_dirs("git -c -C commit --amend", "/cwd").contains(&"commit".to_string()),
            "the subcommand must never be read as a -C directory"
        );
    }

    #[test]
    fn a_cd_before_the_amend_moves_the_probe() {
        assert_eq!(
            amend_target_dirs("cd /elsewhere && git commit --amend", "/cwd"),
            vec!["/elsewhere".to_string()]
        );
    }

    #[test]
    fn a_cd_after_the_amend_does_not_move_the_probe() {
        // The shell runs the amend in the OLD directory. Reading the whole
        // command for `cd`s made this probe a different repository entirely —
        // a confident nudge about a commit the amend never touches
        // (cadence-hooks#610 security + code review).
        assert_eq!(
            amend_target_dirs("git commit --amend && cd /elsewhere", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            amend_target_dirs("git commit --amend ; cd /elsewhere", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn a_cd_inside_a_quoted_argument_moves_nothing() {
        // Commit-message prose is data, not a command.
        assert_eq!(
            amend_target_dirs("git commit --amend -m \"wip; cd /elsewhere later\"", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn duplicate_targets_collapse() {
        assert_eq!(
            amend_target_dirs("git commit --amend; git commit --amend --no-edit", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    // --- parse_remote_refs: pure ---

    #[test]
    fn parses_and_dedupes_remote_refs() {
        // `for-each-ref --format='%(refname:short) %(symref)'`: a plain ref
        // carries an empty second field, a symbolic ref names its target.
        let out = "origin/main \norigin refs/remotes/origin/main\nupstream/main \n\norigin/main \n";
        assert_eq!(
            parse_remote_refs(out),
            vec!["origin/main".to_string(), "upstream/main".to_string()]
        );
    }

    #[test]
    fn parses_empty_output_as_no_refs() {
        assert!(parse_remote_refs("").is_empty());
        assert!(parse_remote_refs("   \n\n").is_empty());
    }

    // --- message rendering ---

    #[test]
    fn message_sanitizes_a_hostile_ref_name() {
        // Ref names are attacker-chosen in a hostile clone, and this text lands
        // in the additionalContext Claude reads.
        let long = "origin/".to_string() + &"x".repeat(400);
        let text = message(&["origin/a\u{202e}b".to_string(), long]);
        assert!(
            !text.contains('\u{202e}'),
            "a bidi override is flattened: {text:?}"
        );
        assert!(
            text.contains('…'),
            "an over-long ref is truncated: {text:?}"
        );
        assert!(!text.contains(&"x".repeat(200)), "{text:?}");
    }

    #[test]
    fn message_names_the_refs_and_the_alternative() {
        let refs = vec!["origin/main".to_string()];
        let text = message(&refs);
        assert!(text.contains("origin/main"), "names the ref: {text}");
        assert!(text.contains("new commit"), "names the alternative: {text}");
    }

    #[test]
    fn message_collapses_a_long_ref_list() {
        let refs: Vec<String> = (0..8).map(|i| format!("r{i}/main")).collect();
        let text = message(&refs);
        assert!(text.contains("(+3 more)"), "{text}");
        assert!(!text.contains("r5/main"), "{text}");
    }

    // --- integration: a real scratch repo with a fake remote ---

    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/warn-amend-pushed-scratch")
    }

    /// A single-commit repo whose one commit has been pushed to a bare "remote"
    /// on disk, so `refs/remotes/origin/main` genuinely exists. Returns the
    /// working repo's path.
    fn repo_with_pushed_commit(scratch: &Scratch) -> std::path::PathBuf {
        let remote = scratch.path().join("remote.git");
        std::fs::create_dir_all(&remote).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);

        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &["remote", "add", "origin", &remote.to_string_lossy()],
        );
        git_in(&repo, &["push", "-q", "origin", "main"]);
        repo
    }

    #[test]
    fn nudges_when_head_is_on_the_remote() {
        let scratch = Scratch::new(&scratch_root(), "pushed");
        let repo = repo_with_pushed_commit(&scratch);

        let input = make_bash_with_cwd("git commit --amend --no-edit", &repo.to_string_lossy());
        let result = WarnAmendPushed.run(&input);

        assert_eq!(result.outcome, Outcome::Nudge);
        let message = result.message.unwrap_or_default();
        assert!(
            message.contains("origin/main"),
            "the nudge names the remote ref: {message}"
        );
    }

    #[test]
    fn silent_when_head_is_a_local_commit_on_top() {
        let scratch = Scratch::new(&scratch_root(), "unpushed");
        let repo = repo_with_pushed_commit(&scratch);
        std::fs::write(repo.join("g.txt"), "y").unwrap();
        git_in(&repo, &["add", "g.txt"]);
        git_in(&repo, &["commit", "-q", "-m", "local only"]);

        let input = make_bash_with_cwd("git commit --amend --no-edit", &repo.to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn silent_on_a_non_amend_commit_in_a_pushed_repo() {
        let scratch = Scratch::new(&scratch_root(), "plain-commit");
        let repo = repo_with_pushed_commit(&scratch);

        let input = make_bash_with_cwd("git commit -m 'x'", &repo.to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn dash_c_probes_the_redirected_repo() {
        let scratch = Scratch::new(&scratch_root(), "dash-c");
        let repo = repo_with_pushed_commit(&scratch);

        // The session sits in the scratch root, which is not a repo at all; the
        // `-C` is what makes the probe land on the pushed checkout.
        let command = format!("git -C {} commit --amend", repo.to_string_lossy());
        let input = make_bash_with_cwd(&command, &scratch.path().to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Nudge);
    }

    #[test]
    fn silent_outside_a_repository() {
        let scratch = Scratch::new(&scratch_root(), "no-repo");
        let input = make_bash_with_cwd("git commit --amend", &scratch.path().to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn empty_command_allows() {
        assert_eq!(WarnAmendPushed.run(&make_bash("")).outcome, Outcome::Allow);
    }
}
