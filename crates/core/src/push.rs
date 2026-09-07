//! `git push` detection and outbound-range resolution.
//!
//! The primitive a push-time content guard stands on: *which* pushes will this
//! command run, *from which directory*, *publishing which refs*, and *which
//! commits* does each of those refs put on a remote that does not have them yet.
//!
//! **Why this is not [`crate::shell::git_push_segments`].** That helper answers a
//! narrower question — the words after `push`, for ownership-validating the
//! destination — and answers it from a FLAT [`split_segments`] view with no
//! working-directory tracking. Three gaps make it unusable for a content guard:
//!
//! - **No `-C`.** `git -C /elsewhere push` publishes from a different repository.
//!   A scanner that resolves its range in the session's cwd scans the wrong
//!   history and finds nothing — a silent miss, which for a secret guard is a
//!   published secret.
//! - **Flat expansion.** A flat view splices a `$(cd /x)`'s `cd` into the parent
//!   stream, moving the tracked directory for segments the shell still runs in
//!   the parent's cwd. This is the exact miss `enforce_worktree`'s
//!   `collect_targets` walk was built non-flat to reject (cadence-hooks#228), and
//!   this walk mirrors it.
//! - **No refspecs.** `git push origin branchB` publishes `branchB`, not `HEAD`.
//!   A range derived from `HEAD` scans a branch the push never touches.
//!
//! **Fail direction.** Every ambiguity here resolves toward *seeing more*, never
//! toward a quiet allow. An unclassifiable option leaves its value visible as a
//! candidate refspec (extra scanning), an unrecognised `--all` spelling still
//! sets [`PushInvocation::all_or_mirror`] (scan everything), and a redirect this
//! walk cannot model sets [`PushInvocation::unresolved`] so the caller can refuse
//! rather than scan a subset. The one flag whose detection would *license* an
//! allow — `--dry-run` — is matched EXACTLY for that reason: under-detecting it
//! costs a false block on a harmless command, over-detecting it would let a real
//! push through unscanned.

use crate::shell::{
    GitOutput, MAX_WRAPPER_DEPTH, child_scripts, command_word, executable_tokens,
    git_output_detailed, peel_command_runners, resolve_cd_target, split_segments_with_ops,
    strip_group_wrappers,
};

/// One refspec a `git push` names, with the local side a range resolver needs.
///
/// Per-refspec rather than per-command, because the two kinds coexist in one
/// invocation: `git push origin :dead newbranch` deletes `dead` AND publishes
/// `newbranch`, so a command-level "this is a delete, skip it" test drops the
/// publish (plan finding, cadence-hooks#237).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refspec {
    /// The refspec exactly as written, for a message that quotes the command.
    pub raw: String,
    /// The LOCAL side — the ref whose outbound commits this push publishes.
    /// `None` for a delete (nothing is published) and for a source this walk
    /// could not read.
    pub source: Option<String>,
    /// The remote side, when the refspec named one.
    pub destination: Option<String>,
    /// A ref deletion: `--delete`/`-d`, or a leading-colon `:dead`. Publishes
    /// no content, so a scanner skips it — this one refspec, never the command.
    pub is_delete: bool,
    /// This refspec was not written on the command line: it stands for the ref
    /// a bare `git push` publishes (`HEAD`). Kept distinguishable so a caller
    /// can report "we assumed HEAD" rather than quoting a refspec the user
    /// never typed.
    pub implicit: bool,
}

/// One `git push` the command will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushInvocation {
    /// The directory git will run in, after `cd` accumulation and any `-C`
    /// redirect. Always populated — the caller's cwd when nothing moved it.
    pub work_dir: String,
    /// The refspecs this push publishes, in command order. Never empty: a bare
    /// `git push` yields one implicit `HEAD` refspec.
    pub refspecs: Vec<Refspec>,
    /// `--all` or `--mirror` — the push is not confined to the named refspecs,
    /// so a caller must widen its range to every local branch (or refuse).
    pub all_or_mirror: bool,
    /// `--dry-run`/`-n`: git contacts the remote but publishes nothing, so a
    /// content guard may allow. Matched exactly — see the module docs.
    pub dry_run: bool,
    /// This walk saw something it cannot model well enough to scan a COMPLETE
    /// range: a `--git-dir`/`--work-tree` redirect or the equivalent env
    /// prefix. A caller must refuse rather than scan a subset — the plan's
    /// "never silently scan a subset and exit 0".
    pub unresolved: bool,
}

/// Every `git push` the command runs, in command order.
///
/// `cwd` is the directory the command starts in. The walk is non-flat: a child
/// script (`sh -c '…'`, `$(…)`, backticks) is recursed with its own directory
/// scope, so a `cd` inside a subshell cannot move the parent's tracked
/// directory. Bounded by [`MAX_WRAPPER_DEPTH`].
///
/// A push found inside a substitution is REPORTED, not executed — the walk only
/// reads text. Reporting it is the point: `$(git push origin main)` really does
/// push, and a scanner that only looked at top-level segments would miss it.
pub fn push_invocations(command: &str, cwd: &str) -> Vec<PushInvocation> {
    let mut out = Vec::new();
    collect_push_invocations(command, cwd, 0, &mut out);
    out
}

/// Recursive worker for [`push_invocations`], mirroring
/// `enforce_worktree::collect_targets`: one `effective_dir` per script scope,
/// children recursed on the directory in effect where they appear.
fn collect_push_invocations(script: &str, cwd: &str, depth: usize, out: &mut Vec<PushInvocation>) {
    let mut effective_dir = cwd.to_string();

    for (segment, _next_op) in split_segments_with_ops(script) {
        let segment = strip_group_wrappers(&segment);
        let tokens = executable_tokens(segment);
        let argv = peel_command_runners(&tokens);

        // Children run with the directory in effect HERE — a substitution is
        // evaluated before its own segment runs — and in their OWN scope, so
        // their `cd`s die with the subshell.
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, segment) {
                collect_push_invocations(&child, &effective_dir, depth + 1, out);
            }
        }

        if tokens.first().map(String::as_str) == Some("cd") {
            effective_dir = apply_cd(&tokens, &effective_dir);
            continue;
        }

        // The prefix words `peel_command_runners` removed. A `GIT_DIR=`
        // assignment lives there, and it redirects the push exactly as the flag
        // does — checked on the prefix only, so a refspec or message that
        // happens to contain the text cannot mark an invocation unresolved.
        let prefix = &tokens[..tokens.len() - argv.len()];
        let env_redirect = prefix
            .iter()
            .any(|t| t.starts_with("GIT_DIR=") || t.starts_with("GIT_WORK_TREE="));

        if let Some(mut invocation) = push_invocation_of(argv, &effective_dir) {
            invocation.unresolved |= env_redirect;
            out.push(invocation);
        }
    }
}

/// Apply a `cd` segment to the tracked directory, or leave it alone when the
/// target is one this resolver cannot read.
///
/// Same refusal set as `enforce_worktree`'s `cd` arm, for the same reason: a
/// bare `cd`, a `-` (`$OLDPWD`), or an unexpanded `$VAR` yields a path string
/// that names no repository, and a directory that resolves to nothing fails
/// open downstream. Keeping the pre-`cd` directory is the honest answer.
fn apply_cd(tokens: &[String], effective_dir: &str) -> String {
    let mut idx = 1;
    while tokens
        .get(idx)
        .is_some_and(|t| t == "--" || (t.starts_with('-') && t != "-"))
    {
        idx += 1;
    }
    match tokens.get(idx) {
        Some(target) if target != "-" && !target.starts_with('$') => {
            resolve_cd_target(target, effective_dir)
        }
        _ => effective_dir.to_string(),
    }
}

/// git's global options that take a SEPARATE value word.
///
/// The same list `enforce_worktree::commit_targets_of` walks. It must be
/// complete in the value-taking direction: a global whose value is not consumed
/// stops the walk on that value, the subcommand is never reached, and the push
/// goes unseen (a silent miss, not a false block).
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

/// Walk git's globals, returning the effective work dir after any `-C`
/// redirect, whether a `--git-dir`/`--work-tree` redirect was seen, and the
/// slice beginning at git's SUBCOMMAND.
///
/// `argv` is the words AFTER the `git` verb.
///
/// **`-C` accumulates**, as git documents: each non-absolute hop resolves
/// against the preceding one.
///
/// **`--git-dir`/`--work-tree` are reported, not resolved.** Either one points
/// the push at a repository this walk would have to model git's own setup rules
/// to name correctly, and naming it *wrongly* means scanning the wrong history —
/// the miss this module exists to prevent. Reporting them as unresolved hands
/// the caller a refusal it can explain.
fn git_globals<'a>(argv: &'a [String], effective_dir: &str) -> (String, bool, &'a [String]) {
    let mut redirect: Option<String> = None;
    let mut foreign_redirect = false;
    let mut idx = 0;

    while idx < argv.len() {
        let token = argv[idx].as_str();
        let previous = idx.checked_sub(1).map(|p| argv[p].as_str());
        let is_value_of_global = previous.is_some_and(|p| VALUE_GLOBALS.contains(&p));

        if !token.starts_with('-') && !is_value_of_global {
            break;
        }

        if is_value_of_global {
            // A token that is the VALUE of the preceding global is never re-read
            // as a flag: `git -c --git-dir=/x push` passes that string to `-c`.
            match previous {
                Some("-C") => {
                    let base = redirect.as_deref().unwrap_or(effective_dir);
                    redirect = Some(resolve_cd_target(token, base));
                }
                Some("--work-tree" | "--git-dir") => foreign_redirect = true,
                _ => {}
            }
        } else if token.starts_with("--work-tree=") || token.starts_with("--git-dir=") {
            foreign_redirect = true;
        }
        idx += 1;
    }

    (
        redirect.unwrap_or_else(|| effective_dir.to_string()),
        foreign_redirect,
        &argv[idx..],
    )
}

/// Read one segment's argv as a `git push`, or `None` when it is not one.
///
/// `argv` is the prefix-/runner-peeled token view. The verb goes through
/// [`command_word`], so `/usr/bin/git push` and the alias-escaping `\git push`
/// resolve as the pushes they are; `push` stays case-sensitive because git's
/// subcommands are.
fn push_invocation_of(argv: &[String], effective_dir: &str) -> Option<PushInvocation> {
    if command_word(argv.first()?) != "git" {
        return None;
    }
    let (work_dir, foreign_redirect, rest) = git_globals(&argv[1..], effective_dir);
    let (subcommand, words) = rest.split_first()?;
    if subcommand != "push" {
        return None;
    }

    let scan = scan_push_words(words);
    let mut refspecs: Vec<Refspec> = scan
        .refspecs
        .iter()
        .map(|raw| parse_refspec(raw, scan.delete_flag))
        .collect();
    if refspecs.is_empty() {
        // A bare `git push` (or `git push origin`) publishes the current branch
        // under every `push.default` mode this tool ships into. Named implicit
        // so a caller can say so rather than quoting a refspec nobody typed.
        refspecs.push(Refspec {
            raw: "HEAD".to_string(),
            source: Some("HEAD".to_string()),
            destination: None,
            is_delete: false,
            implicit: true,
        });
    }

    Some(PushInvocation {
        work_dir,
        refspecs,
        all_or_mirror: scan.all_or_mirror,
        dry_run: scan.dry_run,
        unresolved: foreign_redirect,
    })
}

/// What a walk of `git push`'s own option grammar found.
struct PushWordScan {
    /// Positional words after the first — the first positional is git's
    /// repository argument, every later one is a refspec.
    refspecs: Vec<String>,
    all_or_mirror: bool,
    dry_run: bool,
    delete_flag: bool,
}

/// Walk the words AFTER `push`, separating options from positionals.
///
/// The option grammar is the one [`crate::shell::push_repository_argument`]
/// models — same separate-value long options, same `-o` short-cluster rule —
/// but this walk collects EVERY positional rather than stopping at the first,
/// because the ones after the repository are the refspecs.
fn scan_push_words(words: &[String]) -> PushWordScan {
    let mut scan = PushWordScan {
        refspecs: Vec::new(),
        all_or_mirror: false,
        dry_run: false,
        delete_flag: false,
    };
    let mut positionals = 0usize;
    let mut options_ended = false;
    let mut index = 0;

    while index < words.len() {
        let word = words[index].as_str();

        if !options_ended && word == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        if !options_ended && let Some(rest) = word.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (rest, None),
            };
            // `--all`/`--mirror` matched by PREFIX, the way git's parse-options
            // resolves an unambiguous abbreviation. Over-matching here only
            // widens the range a caller scans, so an ambiguous prefix git would
            // reject costs nothing.
            if abbreviates("all", name) || abbreviates("mirror", name) {
                scan.all_or_mirror = true;
            }
            // Exact, both of them, and for opposite reasons. `dry-run` licenses
            // an allow, so a loose match is a bypass. `delete` skips a refspec,
            // so a loose match is a miss. Under-matching either only over-blocks.
            if name == "dry-run" {
                scan.dry_run = true;
            }
            if name == "delete" {
                scan.delete_flag = true;
            }
            let takes_separate_value =
                inline.is_none() && crate::shell::long_option_takes_separate_value(name);
            index += if takes_separate_value { 2 } else { 1 };
            continue;
        }

        if !options_ended && let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) {
            // `-o` is `git push`'s only value-taking shorthand, so the cluster's
            // FLAG span ends at the first `o`; everything after it is that
            // option's glued value. Scanning the whole token for `n` instead
            // would read `-ono` — `-o` with the value `no` — as a dry run, and a
            // false `dry_run` is a real push allowed unscanned.
            let flags = match cluster.find('o') {
                Some(position) => &cluster[..=position],
                None => cluster,
            };
            if flags.contains('n') {
                scan.dry_run = true;
            }
            if flags.contains('d') {
                scan.delete_flag = true;
            }
            let value_is_next_word =
                matches!(cluster.find('o'), Some(pos) if pos + 1 == cluster.len());
            index += if value_is_next_word { 2 } else { 1 };
            continue;
        }

        positionals += 1;
        // The first positional is the repository; the rest are refspecs.
        if positionals > 1 {
            scan.refspecs.push(word.to_string());
        }
        index += 1;
    }

    scan
}

/// Is `candidate` a non-empty prefix of `full` — the abbreviation rule git's
/// parse-options applies to long option names?
fn abbreviates(full: &str, candidate: &str) -> bool {
    !candidate.is_empty() && full.starts_with(candidate)
}

/// Read one refspec word into its local and remote sides.
///
/// `[+]<src>[:<dst>]`. A leading `+` is force, not part of the ref. An empty
/// source (`:dead`) is a deletion, as is anything under a command-level
/// `--delete`.
fn parse_refspec(raw: &str, delete_flag: bool) -> Refspec {
    let body = raw.strip_prefix('+').unwrap_or(raw);
    let (source, destination) = match body.split_once(':') {
        Some((s, d)) => (s, Some(d.to_string())),
        None => (body, None),
    };
    let is_delete = delete_flag || source.is_empty();
    Refspec {
        raw: raw.to_string(),
        source: (!is_delete && !source.is_empty()).then(|| source.to_string()),
        destination: destination.or_else(|| (!is_delete).then(|| source.to_string())),
        is_delete,
        implicit: false,
    }
}

/// The commits a push of `source_ref` would put on a remote that lacks them.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundRange {
    /// The commit shas, newest first. **Empty is a real answer** — genuinely
    /// nothing to push — and is the ONLY shape a caller may read as "allow".
    Commits(Vec<String>),
    /// git ran and refused to resolve the range (an unknown ref, a corrupt
    /// repository, a ref this module declined to hand to git at all). A caller
    /// must NOT read this as an empty range: that read is what turns a git
    /// error into a silent allow.
    Unresolved,
    /// The guard's own infrastructure failed — git could not be spawned, or the
    /// hook deadline expired. ADR-0001 fail-open territory, and distinct from
    /// [`OutboundRange::Unresolved`] so a caller can treat the two differently.
    Unavailable,
}

/// Resolve the outbound commit set for one pushed ref.
///
/// **The argument order is the whole correctness of this function.**
/// `git rev-list <ref> --not --remotes` lists commits reachable from `<ref>`
/// and from no remote-tracking ref. Writing it `--not --remotes <ref>` — the
/// spelling this plan's first draft carried — puts `<ref>` on the NEGATED side
/// too, so the set is always empty and every push is allowed. A guard built on
/// that could not have gone red.
///
/// **A first push has no `refs/remotes/*` at all, so the range is the entire
/// history.** That is the common case, not an edge: any fresh branch's first
/// `push -u` resolves this way. A caller therefore needs a commit cap, and the
/// cap is a correctness backstop rather than a nicety.
///
/// Accepted residual: `--remotes` spans EVERY remote, so a commit already on a
/// fork is excluded even though pushing to `origin` publishes it there.
pub fn outbound_commits(work_dir: &str, source_ref: &str) -> OutboundRange {
    if !is_safe_ref(source_ref) {
        return OutboundRange::Unresolved;
    }
    // The trailing `--` pins every earlier word as a revision, so a ref that
    // also names a file in the tree cannot make git ask which was meant.
    match git_output_detailed(
        work_dir,
        &["rev-list", source_ref, "--not", "--remotes", "--"],
    ) {
        GitOutput::Ok(text) => OutboundRange::Commits(
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        GitOutput::Failed => OutboundRange::Unresolved,
        GitOutput::Unavailable | GitOutput::TimedOut => OutboundRange::Unavailable,
    }
}

/// May this string be handed to git as a revision?
///
/// **An allowlist, not a denylist.** The value comes off a command line this
/// tool did not write, and it lands in `git`'s argv — where a leading `-` makes
/// it an OPTION. `git rev-list --output=/tmp/x --not --remotes` writes a file;
/// other option spellings change what the command means entirely. Enumerating
/// the dangerous spellings means tracking git's option surface forever, so this
/// admits only what it can vouch for and refuses everything else, unknown
/// spellings included.
///
/// The refusal is not a fail-open: a caller reads it as
/// [`OutboundRange::Unresolved`], which blocks.
///
/// The shape rules are git-check-ref-format's, minus the ones the charset
/// already covers: no leading `-` (option), `/` (not a ref) or `.`, no `..` or
/// `//`, no trailing `/` or `.lock`. `HEAD` and `refs/heads/topic` pass.
pub fn is_safe_ref(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 255
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !candidate.starts_with(['-', '/', '.'])
        && !candidate.ends_with('/')
        && !candidate.ends_with(".lock")
        && !candidate.contains("..")
        && !candidate.contains("//")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_fixtures::{Scratch, git_in, init_repo};
    use std::path::{Path, PathBuf};

    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-push-scratch")
    }

    /// The local sides of every refspec across every detected push, flattened —
    /// the view most assertions here care about.
    fn sources(command: &str, cwd: &str) -> Vec<String> {
        push_invocations(command, cwd)
            .into_iter()
            .flat_map(|invocation| invocation.refspecs)
            .filter_map(|refspec| refspec.source)
            .collect()
    }

    fn only(command: &str, cwd: &str) -> PushInvocation {
        let mut found = push_invocations(command, cwd);
        assert_eq!(found.len(), 1, "expected exactly one push in {command:?}");
        found.remove(0)
    }

    #[test]
    fn bare_git_push_yields_an_implicit_head_refspec() {
        let invocation = only("git push", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert_eq!(invocation.refspecs.len(), 1);
        assert!(invocation.refspecs[0].implicit);
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("HEAD"));
        assert!(!invocation.unresolved);
    }

    #[test]
    fn sh_dash_c_wrapper_is_seen() {
        assert_eq!(sources("sh -c 'git push origin main'", "/repo"), ["main"]);
    }

    #[test]
    fn bash_lc_wrapper_is_seen() {
        assert_eq!(
            sources("bash -lc \"git push origin main\"", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn env_and_command_prefixes_are_seen() {
        assert_eq!(sources("env FOO=1 git push origin main", "/repo"), ["main"]);
        assert_eq!(sources("command git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn push_behind_a_sudo_runner_with_flags_is_seen() {
        // The runner peel walks a modelled runner's OWN flags; refusing at the
        // first `-` would hide the push entirely.
        assert_eq!(
            sources("sudo -u me git push origin main", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn quoted_git_push_in_an_echo_is_not_a_push() {
        // Tokenizing is what kills this: the quoted text is one argument word
        // and never sits in command position.
        assert!(push_invocations("echo \"git push origin main\"", "/repo").is_empty());
    }

    #[test]
    fn dash_capital_c_redirects_the_work_dir() {
        let invocation = only("git -C /elsewhere push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/elsewhere");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn dash_capital_c_accumulates_relative_hops() {
        let invocation = only("git -C sub -C deeper push", "/repo");
        assert_eq!(invocation.work_dir, "/repo/sub/deeper");
    }

    #[test]
    fn cd_moves_the_work_dir_for_a_later_push() {
        let invocation = only("cd /other && git push", "/repo");
        assert_eq!(invocation.work_dir, "/other");
    }

    #[test]
    fn command_substitution_cd_does_not_move_the_parent_work_dir() {
        // The flat-view miss this walk exists to reject: `$(cd /x)`'s `cd`
        // belongs to a subshell and must not re-point the parent's push.
        let invocation = only("echo $(cd /x) && git push", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
    }

    #[test]
    fn backtick_substitution_push_is_reported_not_executed() {
        let found = push_invocations("echo `git push origin main`", "/repo");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn multiple_refspecs_are_all_collected() {
        assert_eq!(
            sources("git push origin main topic release", "/repo"),
            ["main", "topic", "release"]
        );
    }

    #[test]
    fn local_colon_remote_refspec_takes_the_local_side() {
        let invocation = only("git push origin local:remote", "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("local"));
        assert_eq!(
            invocation.refspecs[0].destination.as_deref(),
            Some("remote")
        );
    }

    #[test]
    fn push_origin_branch_b_resolves_branch_b_not_head() {
        assert_eq!(sources("git push origin branchB", "/repo"), ["branchB"]);
    }

    #[test]
    fn force_plus_prefix_is_stripped_from_the_source_ref() {
        assert_eq!(sources("git push origin +main:main", "/repo"), ["main"]);
    }

    #[test]
    fn delete_and_publish_in_one_command_keeps_the_publish() {
        let invocation = only("git push origin :dead newbranch", "/repo");
        assert_eq!(invocation.refspecs.len(), 2);
        assert!(invocation.refspecs[0].is_delete);
        assert_eq!(invocation.refspecs[0].source, None);
        assert!(!invocation.refspecs[1].is_delete);
        assert_eq!(invocation.refspecs[1].source.as_deref(), Some("newbranch"));
    }

    #[test]
    fn delete_flag_marks_every_refspec_a_delete() {
        let invocation = only("git push --delete origin topic", "/repo");
        assert!(invocation.refspecs[0].is_delete);
        assert_eq!(invocation.refspecs[0].source, None);

        let short = only("git push -d origin topic", "/repo");
        assert!(short.refspecs[0].is_delete);
    }

    #[test]
    fn all_flag_is_flagged() {
        assert!(only("git push --all origin", "/repo").all_or_mirror);
    }

    #[test]
    fn mirror_flag_is_flagged() {
        assert!(only("git push --mirror origin", "/repo").all_or_mirror);
    }

    #[test]
    fn dry_run_long_and_short_are_flagged() {
        assert!(only("git push --dry-run origin main", "/repo").dry_run);
        assert!(only("git push -n origin main", "/repo").dry_run);
        assert!(!only("git push origin main", "/repo").dry_run);
    }

    #[test]
    fn dry_run_is_not_inferred_from_a_dash_o_option_value() {
        // `-ono` is `-o` carrying the glued value `no`. Reading the `n` in that
        // value as `--dry-run` would allow a real push unscanned.
        assert!(!only("git push -ono origin main", "/repo").dry_run);
    }

    #[test]
    fn separate_value_option_value_is_not_a_refspec() {
        // `--receive-pack`'s value must be consumed, or `ZZZ` poses as the
        // repository and `origin` as a refspec.
        assert_eq!(
            sources("git push --receive-pack ZZZ origin main", "/repo"),
            ["main"]
        );
    }

    #[test]
    fn git_dir_redirect_marks_the_invocation_unresolved() {
        assert!(only("git --git-dir=/x/.git push origin main", "/repo").unresolved);
        assert!(only("git --work-tree /x push origin main", "/repo").unresolved);
        // A `-c` VALUE that looks like a redirect is not one.
        assert!(!only("git -c --git-dir=/x push origin main", "/repo").unresolved);
    }

    #[test]
    fn git_dir_env_prefix_marks_the_invocation_unresolved() {
        assert!(only("GIT_DIR=/x/.git git push origin main", "/repo").unresolved);
        assert!(only("GIT_WORK_TREE=/x git push origin main", "/repo").unresolved);
    }

    #[test]
    fn two_pushes_in_one_chain_are_both_reported() {
        let found = push_invocations(
            "git push origin main; git -C /other push origin topic",
            "/repo",
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].work_dir, "/repo");
        assert_eq!(found[1].work_dir, "/other");
        assert_eq!(found[1].refspecs[0].source.as_deref(), Some("topic"));
    }

    #[test]
    fn is_safe_ref_rejects_flag_shaped_and_expansion_refs() {
        assert!(is_safe_ref("HEAD"));
        assert!(is_safe_ref("refs/heads/topic-1.2"));
        assert!(!is_safe_ref("--output=/tmp/x"));
        assert!(!is_safe_ref("-n"));
        assert!(!is_safe_ref("$BRANCH"));
        assert!(!is_safe_ref("a..b"));
        assert!(!is_safe_ref("main;rm"));
        assert!(!is_safe_ref(""));
        assert!(!is_safe_ref("topic.lock"));
    }

    #[test]
    fn outbound_commits_on_a_first_push_with_no_upstream_is_non_empty() {
        // The regression guard for the argument-order bug: with no
        // `refs/remotes/*` at all, the range is the whole history. The reversed
        // spelling returns empty here, which reads as "nothing to push".
        let scratch = Scratch::new(&scratch_root(), "first-push");
        let repo = scratch.path();
        init_repo(repo);
        std::fs::write(repo.join("second.txt"), "x").unwrap();
        git_in(repo, &["add", "second.txt"]);
        git_in(repo, &["commit", "-q", "-m", "second"]);

        let range = outbound_commits(&repo.to_string_lossy(), "HEAD");
        match range {
            OutboundRange::Commits(commits) => assert_eq!(commits.len(), 2),
            other => panic!("expected commits, got {other:?}"),
        }
    }

    #[test]
    fn outbound_commits_is_empty_when_everything_is_already_on_a_remote() {
        let scratch = Scratch::new(&scratch_root(), "already-pushed");
        let remote = scratch.path().join("remote.git");
        let work = scratch.path().join("work");
        std::fs::create_dir_all(&remote).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);
        init_repo(&work);
        git_in(
            &work,
            &["remote", "add", "origin", &remote.to_string_lossy()],
        );
        git_in(&work, &["push", "-q", "origin", "main"]);

        assert_eq!(
            outbound_commits(&work.to_string_lossy(), "main"),
            OutboundRange::Commits(Vec::new())
        );
    }

    #[test]
    fn outbound_commits_reports_unresolved_for_an_unknown_ref() {
        let scratch = Scratch::new(&scratch_root(), "unknown-ref");
        let repo = scratch.path();
        init_repo(repo);

        assert_eq!(
            outbound_commits(&repo.to_string_lossy(), "no-such-branch"),
            OutboundRange::Unresolved
        );
    }

    #[test]
    fn git_output_detailed_separates_an_empty_answer_from_an_error() {
        let scratch = Scratch::new(&scratch_root(), "empty-vs-error");
        let repo = scratch.path();
        init_repo(repo);
        let dir = repo.to_string_lossy();

        // git exits 0 with nothing to say — a real answer, not a failure.
        assert_eq!(
            git_output_detailed(&dir, &["rev-list", "HEAD", "--not", "HEAD", "--"]),
            GitOutput::Ok(String::new())
        );
        // git exits non-zero — the caller must not read this as "empty".
        assert_eq!(
            git_output_detailed(&dir, &["rev-list", "no-such-ref", "--"]),
            GitOutput::Failed
        );
    }
}
