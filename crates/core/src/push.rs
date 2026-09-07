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
    COMMAND_RUNNERS, GitOutput, MAX_WRAPPER_DEPTH, TRANSPARENT, child_scripts, command_word,
    executable_tokens_marked, git_output_detailed, is_assignment_word, is_redirect_token,
    peel_command_runners, resolve_cd_target, split_segments_with_ops, strip_group_wrappers,
    unescape_word,
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
    /// `--tags` — every ref under `refs/tags` is pushed. **A caller must treat
    /// this exactly like [`PushInvocation::all_or_mirror`] for range purposes.**
    ///
    /// Deliberately a separate field rather than folded into `all_or_mirror`: a
    /// caller that reads `all_or_mirror` as "widen to every local branch" still
    /// misses a tag pointing at a commit no branch reaches, which is the whole
    /// hazard. Measured — `git push --tags origin` publishes a tagged
    /// off-branch commit while `rev-list HEAD --not --remotes` is empty, and
    /// empty is the one shape a caller may read as allow.
    ///
    /// `--follow-tags` is NOT this flag: it pushes only tags reachable from the
    /// commits being pushed, which the refspec range already covers.
    pub tags: bool,
    /// `--dry-run`/`-n`: git contacts the remote but publishes nothing, so a
    /// content guard may allow. Matched exactly — see the module docs.
    pub dry_run: bool,
    /// This walk saw something it cannot model well enough to scan a COMPLETE
    /// range, so a caller must refuse rather than scan a subset — the plan's
    /// "never silently scan a subset and exit 0".
    ///
    /// **Which repository** — the push may not run where this walk thinks:
    ///
    /// - a `--git-dir`/`--work-tree` flag, or a `GIT_DIR=`/`GIT_WORK_TREE=` env
    ///   assignment, pointing git at a repository this walk would have to model
    ///   git's setup rules to name correctly;
    /// - a directory change this walk could not follow — a bare `cd`, `cd -`, a
    ///   `$`-bearing target, `popd`, a bare `pushd`. Every later push in that
    ///   scope is marked, because the tracked directory is now a guess.
    ///
    /// **Which refs** — a bare push may publish more than the current branch:
    ///
    /// - `push.default=matching`, or any configured `remote.<name>.push`
    ///   refspec, read from the repository;
    /// - the same two keys arriving on the command line via `-c` /
    ///   `--config-env`, which the repository probe cannot see;
    /// - any `GIT_CONFIG_*` env assignment, which can inject either key and
    ///   which that probe reports "not configured" about.
    ///
    /// The ref causes apply only when the refspecs are implicit — a named
    /// refspec replaces that computation anyway.
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
    collect_push_invocations(command, cwd, 0, false, &mut out);
    out
}

/// Recursive worker for [`push_invocations`], mirroring
/// `enforce_worktree::collect_targets`: one `effective_dir` per script scope,
/// children recursed on the directory in effect where they appear.
///
/// `inherited_unresolved` is the env half of that mirror, and it is the reason
/// this parameter exists rather than a local: a `GIT_DIR=`/`GIT_WORK_TREE=`
/// prefix on a WRAPPER segment is exported into the shell it spawns, so the
/// push inside `GIT_WORK_TREE=/x sh -c 'git push origin main'` really does run
/// redirected. Computing the flag on the wrapper and dropping it at the
/// recursion boundary handed the caller a resolvable-looking `work_dir` with
/// `unresolved: false` — the #228/#378 miss `collect_targets` threads
/// `inherited_env` to close, reopened here until this parameter landed. It
/// carries an unfollowable directory change for the same reason: a child starts
/// in the parent's cwd, so a cwd the parent lost is lost for the child too.
fn collect_push_invocations(
    script: &str,
    cwd: &str,
    depth: usize,
    inherited_unresolved: bool,
    out: &mut Vec<PushInvocation>,
) {
    let mut effective_dir = cwd.to_string();
    // Set by an EARLIER segment of this scope, and outliving it: a persistent
    // env redirect, or a directory change this walk could not follow. Either
    // way every later push in the scope is one this walk cannot vouch for.
    let mut scope_unresolved = inherited_unresolved;

    for (segment, _next_op) in split_segments_with_ops(script) {
        let trimmed = segment.trim();
        let segment = strip_group_wrappers(&segment);
        // **An unbalanced closer means the trim ate part of a real word.**
        // `strip_group_wrappers` removes a trailing `)`/`}` unconditionally,
        // without checking that an opener matched — so a segment whose last
        // token legitimately ends in one loses those bytes before tokenization.
        // `}` is an ordinary character there (measured: `bash -c 'echo push
        // origin main}'` prints it) and `git check-ref-format refs/heads/'main}'`
        // answers OK, so both faces are wrong ANSWERS rather than misses:
        // `git push origin secret}` reported the refspec `secret`, a different
        // ref than the command publishes, and `cd /other} && git push` reported
        // `/other` as the work dir with `unresolved: false` for a push that runs
        // in `/other}`. The second is the F9 mechanism reached through a path
        // that marked nothing.
        //
        // Counted rather than fixed in the shared primitive: that trim is
        // byte-identical to `origin/main` and shared with `guard_rm` and
        // `enforce_worktree`, so teaching the tokenizer that a trailing `}` is a
        // word character belongs behind its own issue. A balanced
        // `(git push …)` or `{ git push …; }` is untouched, and a trailing `;`
        // or whitespace trim is not a closer (cadence-hooks#237 security
        // review, F28).
        let openers = trimmed
            .chars()
            .take_while(|c| matches!(c, '(' | '{'))
            .count();
        let closers = trimmed
            .chars()
            .rev()
            .take_while(|c| matches!(c, ')' | '}' | ';' | ' ' | '\t'))
            .filter(|c| matches!(c, ')' | '}'))
            .count();
        let unbalanced_closer = closers > openers;
        // Marks ride alongside the tokens because quote removal has already
        // happened by the time anything downstream sees them, and a redirect
        // decision cannot be made without knowing what was quoted (F25).
        let (tokens, unquoted_prefix_lens) = executable_tokens_marked(segment);
        let argv = skip_runner_assignments(&tokens, peel_command_runners(&tokens));
        // `argv` is a tail subslice of `tokens`, so its marks are the same tail.
        let argv_quoted = &unquoted_prefix_lens[tokens.len().saturating_sub(argv.len())..];

        // The prefix words the peel removed. A `GIT_DIR=` assignment lives
        // there, and it redirects the push exactly as the flag does — checked
        // on the prefix only, so a refspec or message that happens to contain
        // the text cannot mark an invocation unresolved. Both spellings are
        // tested because an `env` OPERAND reaches `env` already unescaped.
        let prefix = &tokens[..tokens.len().saturating_sub(argv.len())];
        let prefix_redirect = prefix.iter().any(|word| {
            names_git_redirect(word) || names_git_redirect(unescape_word(word).as_ref())
        });

        if segment_persists_git_redirect(argv, &tokens) {
            scope_unresolved = true;
        }
        // An unbalanced closer reaches BOTH faces: the push read (whose refspec
        // lost bytes) and the directory read (whose operand did), so it marks
        // the whole scope rather than this segment alone.
        if unbalanced_closer {
            scope_unresolved = true;
        }
        let segment_unresolved = scope_unresolved || prefix_redirect;

        // Children run with the directory in effect HERE — a substitution is
        // evaluated before its own segment runs — and in their OWN scope, so
        // their `cd`s die with the subshell. What this walk cannot vouch for is
        // the opposite: an env redirect crosses into the child, and a directory
        // this walk has lost track of is lost for the child too.
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, segment) {
                collect_push_invocations(
                    &child,
                    &effective_dir,
                    depth + 1,
                    segment_unresolved,
                    out,
                );
            }
        }

        match directory_verb(&tokens) {
            Some(DirectoryVerb::Knowable(verb_tokens)) => {
                match resolve_directory_verb(verb_tokens, &effective_dir) {
                    Some(moved) => effective_dir = moved,
                    // The target could not be read. Keeping the pre-`cd`
                    // directory and saying nothing is the trap — see
                    // [`resolve_directory_verb`].
                    None => scope_unresolved = true,
                }
                continue;
            }
            Some(DirectoryVerb::Unknowable) => {
                scope_unresolved = true;
                // Deliberately NOT a `continue`. `eval` is both a directory-verb
                // refusal (F20) and a prefix a push can hide behind (F16), and
                // `continue`ing here would drop `eval git push origin main`
                // entirely — trading one silent allow for another. Falling
                // through costs nothing on the other rows: a `cd`-shaped segment
                // names no git verb, so both the push read and the fallback
                // below decline it.
            }
            None => {}
        }

        if let Some(mut invocation) = push_invocation_of(argv, argv_quoted, &effective_dir) {
            invocation.unresolved |= segment_unresolved;
            // Only an implicit refspec stands on the `push.default`
            // computation; a named one replaces it, so the config question does
            // not arise and no git call is made.
            if invocation.refspecs.iter().all(|refspec| refspec.implicit) {
                invocation.unresolved |= implicit_push_config_unresolvable(&invocation.work_dir);
            }
            out.push(invocation);
        } else if hides_a_push_behind_a_prefix(argv, &tokens, &unquoted_prefix_lens, &effective_dir)
        {
            out.push(PushInvocation {
                work_dir: effective_dir.clone(),
                refspecs: Vec::new(),
                all_or_mirror: false,
                tags: false,
                dry_run: false,
                unresolved: true,
            });
        }
    }
}

/// Does this segment run a push through a prefix the peel could not get past?
///
/// **A segment the walk cannot peel was being DROPPED, and absence is the
/// strongest allow shape there is.** [`crate::shell::skip_transparent_prefixes`]
/// refuses to skip a prefix whose next token is a flag — deliberately, so a
/// prefix's own option grammar is never parsed — and `command`, `exec`, `time`
/// and `nohup` have no `COMMAND_RUNNERS` second path the way `env` and `nice` do.
/// So `command -p git push origin main` and `exec -a x git push origin main`,
/// ordinary spellings with no escape anywhere, ran under bash, zsh and sh
/// (measured) while this module reported nothing at all.
///
/// This is `guard_rm`'s fallback (`guard_rm.rs`, cadence-hooks#426/#443) at the
/// push position: when `argv` still leads with a prefix and the segment names a
/// push anywhere in its token stream, emit an **unresolvable** push rather than
/// nothing. An unresolvable push is a refusal a caller can explain; an absent one
/// is a silent allow. Parsing each prefix's flag grammar instead would mean
/// enumerating someone else's surface, which grows without telling us.
///
/// `builtin -p git push` is over-refused — it fails in all three shells, so
/// nothing is published — and that is the safe side of this trade.
fn hides_a_push_behind_a_prefix(
    argv: &[String],
    tokens: &[String],
    unquoted_prefix_lens: &[usize],
    effective_dir: &str,
) -> bool {
    let leads_with_a_prefix = argv.first().is_some_and(|first| {
        // **`command_word`, not `names_transparent_prefix` — the membership test
        // has to BASENAME here.** Every sibling asking this question already
        // does: `guard_rm`'s fallback and `peel_command_runners`' runner test
        // both go through `command_word`. The shared primitive unescapes and
        // folds and stops there, so `/usr/bin/nohup -- git push origin main` and
        // `/usr/bin/time -p git push` — real binaries, ordinary spellings,
        // running under bash, zsh and sh (measured) — answered false and the
        // segment vanished. `env` and `nice` were saved only because they are
        // also `COMMAND_RUNNERS`, whose peel basenames.
        //
        // Fixed locally rather than in `names_transparent_prefix`: widening the
        // primitive reaches `skip_transparent_prefixes` and `enforce_worktree`'s
        // env walk, the whole-guard blast radius this branch has deferred twice.
        // The gap is recorded in the plan's documented-miss paragraph and filed
        // (cadence-hooks#237 security review, F22).
        let word = command_word(first);
        // `eval` joins the prefix set for the same reason `guard_rm` admits it:
        // it is in neither `TRANSPARENT` nor `COMMAND_RUNNERS`, so nothing else
        // in this walk will ever get past it.
        TRANSPARENT.contains(&word.as_ref()) || word == "eval"
    });
    leads_with_a_prefix && names_a_push(tokens, unquoted_prefix_lens, effective_dir)
}

/// Does this token stream run `git push`, at any position?
///
/// Runs only after the structured read has already declined the segment, so its
/// job is to decide between *refuse* and *say nothing*, never to describe the
/// push.
///
/// **It reads the globals rather than scanning adjacent pairs.** A `windows(2)`
/// scan required `git` and `push` to touch, and git accepts globals before its
/// subcommand — so `command -p git -C /other push origin main` slipped straight
/// back into the silent allow this fallback exists to close, and `-C /other`
/// does not merely hide that push, it sends it to another repository. Reusing
/// [`git_globals`] — the walk [`push_invocation_of`] already trusts — inherits
/// `VALUE_GLOBALS` for free, so the list cannot drift into a second spelling,
/// and it costs nothing in coarseness: the verb is still basenamed and the
/// subcommand still unescaped, so `\git pu\sh` still matches.
///
/// It does **not** stop the fallback firing on the phrase in argument position.
/// `command -p grep git push file` still refuses, because `git push` really is
/// adjacent there and reading those two words as a push is correct in
/// isolation. Telling them apart needs to know that `grep`, not `git`, is what
/// the prefix runs — the per-prefix flag grammar this fallback exists precisely
/// to avoid parsing. It is an over-refusal on a contrived command, pinned by a
/// test so it cannot drift unnoticed (cadence-hooks#237 security review, F23;
/// N26 stays open).
fn names_a_push(tokens: &[String], unquoted_prefix_lens: &[usize], effective_dir: &str) -> bool {
    // Redirections come out FIRST, for the same reason `push_invocation_of`
    // strips before its verb test: a redirect standing between `git` and its
    // subcommand stopped the globals walk dead, so `command -p git >log push`
    // reached neither the structured read nor this fallback (F26).
    let stripped: Vec<String> = strip_unquoted_redirections(tokens, unquoted_prefix_lens)
        .into_iter()
        .cloned()
        .collect();
    stripped.iter().enumerate().any(|(index, word)| {
        command_word(word) == "git"
            && stripped.get(index + 1..).is_some_and(|after_verb| {
                git_globals(after_verb, effective_dir)
                    .rest
                    .first()
                    .is_some_and(|subcommand| unescape_word(subcommand).as_ref() == "push")
            })
    })
}

/// Env-variable assignments that redirect a push somewhere this walk cannot
/// follow — the environment spelling of the flags that set `unresolved`.
///
/// Two families. `GIT_DIR`/`GIT_WORK_TREE` point git at another repository, the
/// env form of `--git-dir`/`--work-tree`. The `GIT_CONFIG_*` family injects
/// arbitrary configuration, which reaches `push.default` and
/// `remote.<name>.push` — and it is worse than the flag form for the probe in
/// [`implicit_push_config_unresolvable`], because after `GIT_CONFIG_COUNT` runs,
/// `git config --get push.default` (exactly what that probe reads) still answers
/// the repository's value. The probe's own instrument reports "not configured"
/// about a push git performs under the injected setting, so the only honest
/// answer is to refuse.
///
/// **The `GIT_CONFIG` family is matched as a family, not enumerated.** An
/// earlier cut listed `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_`, `GIT_CONFIG_VALUE_`,
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` — and a review found
/// `GIT_CONFIG_PARAMETERS`, a sixth spelling git honours standalone with no
/// `GIT_CONFIG_COUNT` at all (`GIT_CONFIG_PARAMETERS="'push.default=matching'"`
/// measured setting it). That is the second round in which one more member of
/// the same channel turned up, which is the tell that the list is the wrong
/// shape: it enumerates someone else's surface, and that surface grows without
/// telling us. Matching the prefix admits only what can be vouched for and
/// refuses the rest, unknown spellings included; over-refusing costs a caller an
/// explainable refusal.
const GIT_REDIRECT_ENV_PREFIXES: &[&str] = &["GIT_DIR=", "GIT_WORK_TREE=", "GIT_CONFIG"];

/// Skip assignment operands that a RUNNER hands to the program it execs, which
/// the shell has already unescaped.
///
/// **Two positions, opposite answers, same word.** `GIT_\DIR=/x git push` is an
/// assignment to no shell — a quoted character in the name disqualifies it, and
/// measured, all three answer `GIT_DIR=/nope: No such file or directory` — so
/// `is_assignment_word`'s raw test correctly refuses it and the walk correctly
/// sees no push. But as an operand of `env`, the shell strips the backslash
/// *before* `env` sees it, so `env GIT_\DIR=/x git push` really does set
/// `GIT_DIR` (measured: `env GIT_\DIR=/nope git rev-parse --git-dir` reports
/// `not a git repository: '/nope'` under bash, zsh and sh) — and the walk saw
/// no push at all for a command publishing from `/x`.
///
/// So the escape removal belongs HERE, at the runner-operand position, and not
/// inside `is_assignment_word`, where it would wrongly admit the bare-prefix
/// spelling. Gated on a runner actually having been peeled, for the same
/// reason.
fn skip_runner_assignments<'a>(tokens: &'a [String], argv: &'a [String]) -> &'a [String] {
    // **Keyed on the region the peel consumed, not on `tokens[0]`.** The runner
    // is not always first: any transparent prefix in front of it turned the gate
    // off while the peel still happened, so `exec env GIT_\DIR=/x git push` left
    // `argv[0]` as the assignment word and the whole segment went unseen — for a
    // command that publishes from `/x` (measured: `exec env GIT_\DIR=/nope git
    // rev-parse --git-dir` reports `not a git repository: '/nope'` under bash,
    // zsh and sh). Requiring SOME peeled word to be a runner keeps the
    // bare-prefix refusal below intact (cadence-hooks#237 security review, F19).
    let peeled = &tokens[..tokens.len().saturating_sub(argv.len())];
    let peeled_a_runner = !peeled.is_empty()
        && peeled
            .iter()
            .any(|word| COMMAND_RUNNERS.contains(&command_word(word).as_ref()));
    if !peeled_a_runner {
        return argv;
    }
    let mut start = 0;
    while argv
        .get(start)
        .is_some_and(|word| is_assignment_word(unescape_word(word).as_ref()))
    {
        start += 1;
    }
    argv.get(start..).unwrap_or(argv)
}

/// Is this word an assignment from [`GIT_REDIRECT_ENV_PREFIXES`]?
fn names_git_redirect(word: &str) -> bool {
    GIT_REDIRECT_ENV_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix))
}

/// Does this segment set a git redirect that OUTLIVES it?
///
/// Two shapes do, and they are the ones a command prefix is not: an explicit
/// `export`/`declare`/`typeset`, and an assignment segment with no command word
/// at all (`GIT_DIR=/x;`). Both leave the variable set for every later segment
/// in the scope.
///
/// A prefix (`GIT_DIR=/x git status`) is deliberately excluded — the shell sets
/// it for that one command — so it marks its own segment and never leaks
/// forward.
///
/// "No command word" is spelled as *every token is an assignment word*, not as
/// an empty `argv`: [`crate::shell::skip_transparent_prefixes`] stops before the
/// LAST token (`start + 1 < len`), so an assignment-only segment still comes
/// back as a one-token `argv` and an emptiness test never fires — measured, it
/// silently dropped `GIT_DIR=/x; git push`.
fn segment_persists_git_redirect(argv: &[String], tokens: &[String]) -> bool {
    let exported = argv.first().is_some_and(|word| {
        matches!(
            command_word(word).as_ref(),
            "export" | "declare" | "typeset"
        )
    }) && argv.iter().skip(1).any(|word| {
        // Both spellings, exactly as `prefix_redirect` does. `export`,
        // `declare` and `typeset` are BUILTINS, so the shell unescapes their
        // operands before they see them — measured, `export GIT_\DIR=/nope`
        // then `git rev-parse --git-dir` answers `not a git repository:
        // '/nope'` under bash, zsh and sh. Testing them raw left the redirect
        // invisible, and this one is worse than the `env` prefix form because
        // an `export` persists for EVERY later segment in the scope
        // (cadence-hooks#237 security review, F18).
        names_git_redirect(word) || names_git_redirect(unescape_word(word).as_ref())
    });

    let assignment_only = !tokens.is_empty() && tokens.iter().all(|t| is_assignment_word(t));

    exported || (assignment_only && tokens.iter().map(String::as_str).any(names_git_redirect))
}

/// Does this repository's configuration replace the "publish the current
/// branch" computation the implicit `HEAD` refspec stands for?
///
/// Two settings do. `push.default=matching` publishes every local branch with a
/// same-named remote branch, HEAD or not — measured: on `main` with a divergent
/// `side`, a bare `git push origin` pushes `side`. Any `remote.<name>.push`
/// refspec replaces the computation outright.
///
/// **git reports "unset" and "unreadable" identically** — both exit non-zero,
/// so both arrive as [`GitOutput::Failed`] and read here as *not configured*,
/// which keeps the `HEAD` refspec. That is right for the unset case, which is
/// the overwhelmingly common one and means the default (`simple`). It is a
/// resolved-looking answer for the unreadable case, but a directory where git
/// cannot read config is one where [`outbound_commits`] also fails, and that
/// fails closed — so the composed posture still refuses.
fn implicit_push_config_unresolvable(work_dir: &str) -> bool {
    let push_default_matches_every_branch = matches!(
        git_output_detailed(work_dir, &["config", "--get", "push.default"]),
        GitOutput::Ok(value) if value.trim() == "matching"
    );
    let remote_push_refspec_configured = matches!(
        git_output_detailed(work_dir, &["config", "--get-regexp", r"^remote\..*\.push$"]),
        GitOutput::Ok(value) if !value.trim().is_empty()
    );
    push_default_matches_every_branch || remote_push_refspec_configured
}

/// Does this segment change the shell's working directory?
///
/// `pushd`/`popd` are here because leaving them out is not a *safe* omission:
/// the walk keeps its old directory and reports it with full confidence, so an
/// unmodelled directory verb produces a wrong answer rather than a refusal.
/// `pushd` with a literal path moves exactly like `cd`; `popd` returns to a
/// directory this walk never recorded.
///
/// **The peel here is deliberately NARROWER than [`peel_command_runners`], which
/// the push side uses.** That asymmetry is the point, not an oversight: a
/// directory verb only moves THIS shell when it runs as a builtin of it.
/// Measured, `pwd` after each:
///
/// | spelling | bash | zsh | sh | this walk |
/// |---|---|---|---|---|
/// | `cd /b` | moves | moves | moves | moves |
/// | `builtin cd /b` | moves | moves | moves | moves |
/// | `\cd /b`, `c\d /b` | moves | moves | moves | moves |
/// | `command cd /b` | moves | **does not** | moves | **refuses** |
/// | `command -p cd /b` | moves | **does not** | moves | **refuses** |
/// | `command command cd /b` | moves | **does not** | moves | **refuses** |
/// | `env cd /b`, `nice cd /b` | does not | does not | does not | ignores |
///
/// Three groups, three answers. `builtin` is unanimous, so the move is
/// knowable. `env`/`nice` exec a child that exits, so nothing moves anywhere and
/// ignoring them is correct — which is why reusing the push side's peel, which
/// strips both, would move the tracked directory for commands no shell moved.
/// **`command` is the one this walk cannot answer**: zsh forces external lookup
/// and the external `cd` execs a child, so bash and zsh genuinely disagree, and
/// the Bash tool on this estate is zsh. Picking either answer states a directory
/// with `unresolved: false` that the other shell never entered, so a
/// `command`-prefixed directory verb refuses instead (cadence-hooks#237 security
/// review, F5).
///
/// **The verb is matched EXACTLY, not through [`command_word`].** That helper
/// case-folds and strips a path and a `.exe`, which is right for `git` — an
/// executable file, found on `PATH`, spelled however the filesystem allows.
/// `cd` is a shell BUILTIN, and neither transformation applies to one. Measured:
/// `CD /usr` and `/usr/bin/cd /usr` both leave bash in the ORIGINAL directory,
/// so folding either into `cd` would move the tracked directory for a command
/// the shell never honoured — the same wrong-repository answer from the
/// opposite direction. Only a leading backslash is stripped, because `\cd` is
/// alias suppression and really does run the builtin.
///
/// What a directory verb this walk found means for the tracked directory.
enum DirectoryVerb<'a> {
    /// A verb whose effect every shell agrees on. The slice starts at the verb.
    Knowable(&'a [String]),
    /// A verb this walk cannot resolve to a directory, for either of the two
    /// reasons named on [`directory_verb`]. The scope is marked unresolved.
    Unknowable,
}

/// Classify a segment as a directory verb, or `None` when it is not one.
///
/// Two shapes are [`DirectoryVerb::Unknowable`] rather than a move:
///
/// 1. **A `command` prefix.** bash and sh move, zsh does not (measured), and
///    nothing here knows which shell runs the command.
/// 2. **Any backslash in the verb word.** [`crate::shell::tokenize`] throws
///    quoting away, so `'c\d' /x` and `c\d /x` arrive as the SAME token — and
///    the shells split on exactly that: measured, `\cd /usr` moves under bash,
///    zsh and sh while `'\cd' /usr` moves under none of them, because the quotes
///    make it a literal command name. `cd\ /other` is a third reading: the
///    escaped space makes it one word the shell never runs, where the tokenizer
///    sees two.
///
/// **Point 2 is the opposite call from the push verb, deliberately.** There,
/// unescaping only widens what is seen, and seeing more is the safe direction
/// for a detector. Here a wrong move is a wrong repository, so a token that
/// merely *could* unescape to a directory verb refuses. That over-refuses the
/// unquoted `\cd`, which really does move — an explainable refusal, traded
/// against a silently wrong answer.
fn directory_verb(tokens: &[String]) -> Option<DirectoryVerb<'_>> {
    fn names_directory_verb(word: &str) -> bool {
        matches!(word, "cd" | "pushd" | "popd")
    }

    let mut start = 0;
    let mut command_prefixed = false;
    // **The peel reads the UNESCAPED word, and separately remembers that an
    // escape was there.** Comparing the raw token instead made a whole segment
    // invisible: `\builtin cd /other` broke the loop on `\builtin`, that word
    // became the candidate, it unescaped to `builtin` — not a directory verb —
    // and this returned `None`, which means "not a directory verb at all". The
    // caller then kept a STALE directory with `unresolved: false`, which is
    // strictly worse than the over-refusal below. Every row measured moves the
    // shell (cadence-hooks#237 security review, F9).
    let mut prefix_escaped = false;
    while start < tokens.len() {
        let raw = tokens[start].as_str();
        let word = unescape_word(raw);
        if is_assignment_word(word.as_ref()) {
            prefix_escaped |= raw.contains('\\');
            start += 1;
            continue;
        }
        // `builtin` takes NO options in bash, zsh or sh — measured, a flag word
        // makes it fail and the shell stays put, so `builtin -p cd /other`
        // never moves. Sharing `command`'s flag-skip loop swallowed the flag,
        // found `cd`, and reported the move: a wrong repository with
        // `unresolved: false`, and no `command_prefixed` to save it. `builtin
        // -- cd` splits three ways on top of that — bash and sh move, zsh does
        // not. Refusing on ANY flag is the same trade
        // [`resolve_directory_verb`] already makes for `pushd`: the flags that
        // change the verb outnumber the ones that do not, and enumerating them
        // is the wrong side of that problem.
        // **Both flag tests read the UNESCAPED word.** They were the last two
        // raw comparisons in this function, and a raw token starting with `\`
        // failed each of them: the loop broke on it, the flag became the
        // candidate, it was not a directory verb, and the walk returned `None`
        // — a stale directory with `unresolved: false`, the F9 mechanism one
        // token to the right. `builtin \-- cd /other` and `command \-p cd
        // /other` both move bash and sh (zsh stays), the exact three-way split
        // these arms exist to refuse. `prefix_escaped` below is a second,
        // independent route to the same answer.
        if word.as_ref() == "builtin" {
            prefix_escaped |= raw.contains('\\');
            start += 1;
            if tokens
                .get(start)
                .is_some_and(|next| unescape_word(next).starts_with('-'))
            {
                return Some(DirectoryVerb::Unknowable);
            }
            continue;
        }
        if word.as_ref() == "command" {
            command_prefixed = true;
            prefix_escaped |= raw.contains('\\');
            start += 1;
            // `command`'s own flags (`-p`, `-v`, `-V`) are real and enumerable,
            // and its verb refuses through `command_prefixed` regardless.
            while start < tokens.len() {
                let flag = unescape_word(&tokens[start]);
                if !flag.starts_with('-') || flag.as_ref() == "-" {
                    break;
                }
                prefix_escaped |= tokens[start].contains('\\');
                start += 1;
            }
            continue;
        }
        break;
    }
    let rest = tokens.get(start..)?;
    let candidate = rest.first()?;

    // `eval` in command position refuses outright. It is peeled by nothing — in
    // neither `TRANSPARENT` nor `COMMAND_RUNNERS` — so `eval cd /other` made
    // `eval` the candidate, `names_directory_verb` said no, and this returned
    // `None`, which the caller reads as "not a directory verb at all": it kept
    // the STALE directory and the later push reported `unresolved: false`
    // against the session's own checkout, while bash, zsh and sh had all moved
    // (measured). Over-refuses `eval echo hi`, which is explainable; the
    // structural fix is `child_scripts` learning `eval`, tracked as
    // cameronsjo/cadence-hooks#886 (cadence-hooks#237 security review, F20).
    if unescape_word(candidate).as_ref() == "eval" {
        return Some(DirectoryVerb::Unknowable);
    }

    if candidate.contains('\\') {
        // It could be a directory verb once the shell removes the escapes, and
        // the token cannot say whether it was quoted. Refuse if it might be
        // one; ignore it if it could not be.
        return names_directory_verb(unescape_word(candidate).as_ref())
            .then_some(DirectoryVerb::Unknowable);
    }
    // A `prefix_escaped` refusal for a NON-verb candidate was tried here and
    // withdrawn: it swallowed `\command git push origin main`, whose candidate
    // is `git`, turning a real push into a directory-verb refusal and dropping
    // it from the results. The unescaped flag tests above already close every
    // escaped-flag row on their own, and `prefix_escaped` still refuses on the
    // directory-verb path below, which is where it belongs.
    if !names_directory_verb(candidate) {
        return None;
    }
    // `Knowable` only when the WHOLE chain is backslash-free: an escape in the
    // prefix carries the same quoting ambiguity as one in the verb.
    Some(if command_prefixed || prefix_escaped {
        DirectoryVerb::Unknowable
    } else {
        DirectoryVerb::Knowable(rest)
    })
}

// [`unescape_word`] is core's shared quote removal — an escape walk, so `c\d`
// becomes `cd` while `\\cd` becomes a literal `\cd` the shell cannot find.
//
// It is used here INSTEAD of [`command_word`], which also case-folds and strips
// a path: both are right for an executable found on `PATH` and wrong for a
// builtin. Measured, `CD /usr` and `/usr/bin/cd /usr` leave bash in the ORIGINAL
// directory, so folding either into `cd` would move the tracked directory for a
// command the shell never honoured.

/// Where a directory verb leaves the shell, or `None` when this walk cannot
/// tell.
///
/// **`None` is a refusal, not a no-op, and that is the whole point.** The
/// earlier form returned the pre-`cd` directory on an unreadable target and set
/// nothing, on the reasoning that an unresolvable path fails open downstream.
/// That reasoning was wrong in this module's direction: the pre-`cd` directory
/// is not "nothing", it is the session's own checkout — a real repository that
/// answers `rev-list` confidently for a push that ran somewhere else. Measured
/// with `cd "$BUILD" && git push origin main`: the walk reported the session's
/// repo, `unresolved: false`, and `Commits([])` — allow — while the push
/// published a commit from another repository. The caller now gets
/// `unresolved` and can refuse.
///
/// Note the asymmetry that made this the one bad arm: `git -C $D push` resolves
/// to `<cwd>/$D`, a path that does not exist, so `rev-list` fails and the
/// composed posture blocks. Only the `cd` arm degraded to a *plausible wrong
/// answer*.
///
/// Unreadable: `popd`; ANY flagged `pushd`; a bare verb; `-` (`$OLDPWD`); a
/// target carrying an unexpanded `$` or a backtick; and more than one operand.
///
/// **`pushd` refuses on any flag rather than on a list of flags.** `-n` pushes
/// onto the stack *without moving* (measured: `pushd -n /b` from `/a` leaves
/// `pwd` at `/a`) and `+N`/`-N` rotate the stack, so the flags that change the
/// verb's meaning outnumber the ones that do not. Enumerating them is the wrong
/// side of that problem — a flag this walk has not heard of would silently take
/// the literal-path arm. A refusal for `-n` is a deliberate over-refusal: the
/// provable answer there is "does not move", and over-refusing costs an
/// explainable refusal while under-refusing costs a wrong repository.
///
/// **Two operands is bash's substitute form**, not a move: `cd repo other`
/// replaces `repo` with `other` inside `$PWD`, and measured it errors with
/// `too many arguments` and does not move at all. Taking the first operand
/// reported `<cwd>/repo` for a shell that never left `<cwd>`.
///
/// `$` is tested anywhere in the token, not just at the front — `cd "$HOME/x"`
/// and `cd /a/$B` are equally unknowable.
///
/// `tokens` begins at the verb ([`directory_verb`] did the peel).
fn resolve_directory_verb(tokens: &[String], effective_dir: &str) -> Option<String> {
    let verb = tokens.first()?.as_str();
    if verb == "popd" {
        return None;
    }
    let stack_verb = verb == "pushd";
    let mut idx = 1;
    // The flag skip reads the UNESCAPED word. Compared raw, `cd \-` was not
    // recognised as the bare `-` that means `$OLDPWD`; it fell through to
    // `resolve_cd_target`, which JOINED it, and the walk answered `/repo/\-`
    // for a shell sitting in `$OLDPWD`. It failed closed downstream — that path
    // does not exist, so `git -C` fails and the range is `Unresolved` — but an
    // invented directory is not an answer (cadence-hooks#237 security review,
    // N23).
    while tokens.get(idx).is_some_and(|t| {
        let t = unescape_word(t);
        t.as_ref() == "--" || (t.starts_with('-') && t.as_ref() != "-")
    }) {
        if stack_verb {
            return None;
        }
        idx += 1;
    }
    // A redirection is not an operand. `pushd <dir> >/dev/null` is how the
    // idiom is normally written, and counting the redirect words made that
    // ordinary, non-adversarial command refuse.
    let operands: Vec<&String> = strip_redirections(&tokens[idx..]);
    if operands.len() != 1 {
        return None;
    }
    match operands.first() {
        // The `-`/`+N` tests read the UNESCAPED operand for N23's reason: `cd
        // \-` is the shell's `$OLDPWD` spelling, and comparing it raw let it
        // fall through to `resolve_cd_target`, which joined it into a directory
        // that never existed. The TARGET itself is still resolved from the RAW
        // operand — unescaping it would invent a path that may exist and answer
        // `rev-list` confidently, where the raw spelling fails closed.
        Some(target)
            if unescape_word(target).as_ref() != "-"
                && !target.contains('$')
                && !target.contains('`')
                && !(stack_verb && unescape_word(target).starts_with('+')) =>
        {
            Some(resolve_cd_target(target, effective_dir))
        }
        _ => None,
    }
}

/// The words that are real operands, with redirections removed.
///
/// A redirect arrives as one token when its target is glued on (`>/dev/null`,
/// `2>&1`) and as two when the operator stands alone (`> log`), so the standalone
/// form consumes the word after it. [`is_redirect_token`] is core's own test for
/// the operator, shared rather than re-spelled.
/// [`strip_redirections`], but a token the shell QUOTED is never a redirection.
///
/// **Quote removal is what makes this necessary.** `tokenize` strips quotes, so
/// `'>leak'` and `>leak` arrive byte-identical and a strip judging the text
/// alone silently discards a legal refspec (`git check-ref-format
/// refs/heads/'>b'` answers OK) as if it were a redirection — the fail-open
/// direction this module exists to refuse. The marks come from
/// [`crate::shell::executable_tokens_marked`], which carries the one fact quote
/// removal destroys.
///
/// **The question is whether the redirect OPERATOR was quoted, not the token.**
/// The operator and its target are one word, and only the operator decides. A
/// whole-token mark refused to strip `>"$LOG"`, `2>"/dev/null"` and `>>"$LOG"` —
/// the spellings scripts are actually written in — turning each into a phantom
/// refspec that `is_safe_ref` then rejected, so an ordinary
/// `git push origin main >"$LOG" 2>&1` was blocked. The operator there is
/// unquoted; only the target is (cadence-hooks#237 security review, F27).
///
/// `unquoted_prefix_lens` is indexed in lockstep with `words`; a missing entry
/// reads as `0` — quoted from the first byte — so an absent mark keeps its
/// operand rather than dropping it.
fn strip_unquoted_redirections<'a>(
    words: &'a [String],
    unquoted_prefix_lens: &[usize],
) -> Vec<&'a String> {
    let mut operands = Vec::new();
    let mut idx = 0;
    while let Some(word) = words.get(idx) {
        let unquoted_prefix_len = unquoted_prefix_lens.get(idx).copied().unwrap_or(0);
        if let Some(operator) = redirect_operator(word)
            && unquoted_prefix_len >= operator.len
        {
            // Standalone operator: the next word is its target, not an operand.
            idx += if operator.is_whole_word { 2 } else { 1 };
            continue;
        }
        operands.push(word);
        idx += 1;
    }
    operands
}

/// The leading `&`/digits/`>`-`<` run that makes a word a redirection.
struct RedirectOperator {
    /// Byte length of that run — what a quote must clear to leave it intact.
    len: usize,
    /// The whole word is the operator, so its target is the next word.
    is_whole_word: bool,
}

/// Measure the redirect operator prefix, or `None` when the word is not
/// redirect-shaped.
///
/// Reads exactly what [`crate::shell::is_redirect_token`] reads, in the same
/// order, so the two cannot disagree about what counts as a redirection.
fn redirect_operator(word: &str) -> Option<RedirectOperator> {
    if !is_redirect_token(word) {
        return None;
    }
    let after_ampersands = word.trim_start_matches('&');
    let after_digits = after_ampersands.trim_start_matches(|c: char| c.is_ascii_digit());
    let after_operators = after_digits.trim_start_matches(['>', '<']);
    Some(RedirectOperator {
        len: word.len() - after_operators.len(),
        is_whole_word: after_operators.is_empty(),
    })
}

fn strip_redirections(words: &[String]) -> Vec<&String> {
    // One implementation, every prefix declared fully unquoted. A second body
    // here is exactly the drift this branch already paid for once at
    // `is_prefix_word`.
    //
    // **This quote-blind form has exactly one caller left —
    // [`resolve_directory_verb`] — and the F25 hazard documented above is live
    // there.** A quoted redirect-shaped `cd` operand is still discarded as a
    // redirection. It fails CLOSED in every shape measured: dropping the operand
    // makes `operands.len() != 1`, `resolve_directory_verb` returns `None`, and
    // the caller marks the scope unresolved — `cd '>x' && git push` answers
    // `unresolved: true`. That is why it is left as is; a reader patching that
    // function later should not take the block above as covering them.
    strip_unquoted_redirections(words, &vec![usize::MAX; words.len()])
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

/// What a walk of git's global options found, plus the slice beginning at git's
/// SUBCOMMAND.
struct GitGlobals<'a> {
    /// The effective work dir after any `-C` redirect.
    work_dir: String,
    /// `--git-dir`/`--work-tree` was seen — the push points at a repository
    /// this walk cannot name correctly.
    foreign_redirect: bool,
    /// A `-c`/`--config-env` global carried a key that replaces the bare-push
    /// ref computation (`push.default`, or a `remote.<name>.push` refspec).
    push_config_override: bool,
    /// The words from git's subcommand onward.
    rest: &'a [String],
}

/// Walk git's globals.
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
///
/// **`-c`/`--config-env` are reported by KEY, never interpreted.** The config
/// that decides what a bare push publishes can arrive on the command line, and
/// [`implicit_push_config_unresolvable`] cannot see it: that probe runs its own
/// `git config` subprocess, which reads the repository and inherits the hook
/// process's environment, not the command's. Measured — with
/// `git -c push.default=matching push origin`, the probe answers `simple` about
/// a push git performs under `matching`. Only the key is examined, and any
/// value marks the invocation unresolved, because reading the value would mean
/// re-implementing git's config parsing to decide a safety question.
fn git_globals<'a>(argv: &'a [String], effective_dir: &str) -> GitGlobals<'a> {
    let mut redirect: Option<String> = None;
    let mut foreign_redirect = false;
    let mut push_config_override = false;
    let mut idx = 0;

    while idx < argv.len() {
        // **Normalized once, then compared everywhere below.** git sees the word
        // after the shell removes the escapes — measured, `git --git-\dir=/x`
        // reports `not a git repository: '/x'` — but this walk compared the raw
        // token, so an escaped global went unread in two directions at once: a
        // `--git-\dir=` redirect left `unresolved: false` on a push that went
        // elsewhere, and `git -\C /other push` never even reached the
        // subcommand, so the push was absent from the results entirely.
        //
        // Unlike [`directory_verb`], unescaping here needs no ambiguity flag:
        // every arm below only widens what is SEEN, and none of them sets a
        // directory the shell might not have entered — `-C`'s value is still
        // resolved from the raw operand, which fails closed.
        let word = unescape_word(argv[idx].as_str());
        if !word.starts_with('-') {
            break;
        }

        // A value word is consumed WITH its flag, in one step, so it is never
        // re-read as a flag on the next pass. Deciding that by looking BACK at
        // the previous token instead — the shape
        // `enforce_worktree::commit_targets_of` uses — misreads a value that
        // happens to spell a global: in `git -c -C push origin main` the `-C` is
        // `-c`'s value, but a look-back walk then reads `push` as `-C`'s value,
        // never reaches the subcommand, and the push goes unseen.
        if VALUE_GLOBALS.contains(&word.as_ref()) {
            match word.as_ref() {
                // `-C` accumulates: resolve this hop against the previous one.
                // The VALUE stays raw — resolving it unescaped could invent a
                // directory, and an unresolvable one fails closed downstream.
                "-C" => {
                    if let Some(value) = argv.get(idx + 1) {
                        let base = redirect.as_deref().unwrap_or(effective_dir);
                        redirect = Some(resolve_cd_target(value, base));
                    }
                }
                "--work-tree" | "--git-dir" => foreign_redirect = true,
                "-c" | "--config-env"
                    if argv
                        .get(idx + 1)
                        .is_some_and(|value| sets_push_ref_computation(value)) =>
                {
                    push_config_override = true;
                }
                _ => {}
            }
            idx += 2;
            continue;
        }

        if word.starts_with("--work-tree=") || word.starts_with("--git-dir=") {
            foreign_redirect = true;
        }
        if let Some(setting) = word.strip_prefix("--config-env=")
            && sets_push_ref_computation(setting)
        {
            push_config_override = true;
        }
        idx += 1;
    }
    // A trailing value-taking global with no value (`git -C`) leaves `idx` past
    // the end; git errors on that command, and an empty slice reports no push.
    let idx = idx.min(argv.len());

    GitGlobals {
        work_dir: redirect.unwrap_or_else(|| effective_dir.to_string()),
        foreign_redirect,
        push_config_override,
        rest: &argv[idx..],
    }
}

/// Does this `-c`/`--config-env` setting name a key that decides which refs a
/// bare `git push` publishes?
///
/// `setting` is git's `key=value` (or `key=ENVVAR`) word; only the KEY matters.
/// Two keys qualify, the same two [`implicit_push_config_unresolvable`] reads
/// from the repository: `push.default`, and any `remote.<name>.push` refspec.
///
/// Section and variable names are case-insensitive to git, so the comparison is
/// too. `remote.<name>.pushurl` deliberately does NOT match — it changes where
/// the push goes, not which refs it carries.
///
/// The setting is unescaped first, for the same reason the flag word is: git
/// reads it after the shell removes the escapes, so `-c push.\default=matching`
/// really does set `push.default` (measured — `config --get push.default`
/// answers `matching`) while a raw compare read some other key and left the
/// invocation resolvable.
fn sets_push_ref_computation(setting: &str) -> bool {
    let setting = unescape_word(setting);
    let key = setting
        .split_once('=')
        .map_or(setting.as_ref(), |(key, _)| key);
    let key = key.to_ascii_lowercase();
    key == "push.default"
        || (key.starts_with("remote.")
            && key.ends_with(".push")
            && key.len() > "remote..push".len())
}

/// Read one segment's argv as a `git push`, or `None` when it is not one.
///
/// `argv` is the prefix-/runner-peeled token view. The verb goes through
/// [`command_word`], so `/usr/bin/git push` and the alias-escaping `\git push`
/// resolve as the pushes they are; `push` stays case-sensitive because git's
/// subcommands are.
fn push_invocation_of(
    argv: &[String],
    argv_quoted: &[usize],
    effective_dir: &str,
) -> Option<PushInvocation> {
    // **Redirections come out FIRST — before the verb, the globals and the
    // subcommand are read.** A redirection is legal anywhere in a simple
    // command, so all three of those reads could be handed a redirect token
    // where they expect a word, and each failed by returning `None`:
    // `git >log push origin main`, `git 2>/dev/null push origin main` and
    // `>log git push origin main` all run under bash, zsh and sh (measured — a
    // redirect between the command word and its arguments is transparent to
    // git) and every one of them was NO PUSH SEEN. Stripping only at the operand
    // scan, as the first cut did, left that whole surface untouched.
    //
    // Reading a redirect as a refspec was the other half, and this module's
    // first FALSE-REFUSAL class: `git push origin main > /dev/null` collected
    // `main`, `>` and `/dev/null`, `is_safe_ref` rejected `>`, and the range came
    // back `Unresolved` for the spelling every script uses.
    // `git push > log origin main` was worse — `>` was read as the REPOSITORY.
    //
    // The strip is quote-aware, and moving it earlier is exactly why it has to
    // be: a wider surface would otherwise mean a wider misread of a quoted
    // operand (cadence-hooks#237 security review, F24 and F26).
    let argv: Vec<String> = strip_unquoted_redirections(argv, argv_quoted)
        .into_iter()
        .cloned()
        .collect();
    if command_word(argv.first()?) != "git" {
        return None;
    }
    let globals = git_globals(&argv[1..], effective_dir);
    let (subcommand, words) = globals.rest.split_first()?;
    // `push` stays case-SENSITIVE — a git subcommand is — but it takes the same
    // backslash removal the verb does: `git pu\sh origin main` really pushes
    // (measured), and a literal compare read it as some other subcommand and
    // dropped the segment.
    if unescape_word(subcommand) != "push" {
        return None;
    }

    // Already stripped, at the top of this function — see the note there.
    let scan = scan_push_words(words);
    let mut refspecs: Vec<Refspec> = scan
        .refspecs
        .iter()
        .map(|raw| parse_refspec(raw, scan.delete_flag))
        .collect();
    let implicit = refspecs.is_empty();
    if implicit {
        // What a bare `git push` (or `git push origin`) publishes is decided by
        // `push.default` and by any `remote.<name>.push` refspec, NOT by this
        // module. `HEAD` is the answer under `simple`, `current` and `upstream`
        // — the default and the modes anything ships with — and it is WRONG
        // under `matching`, which publishes every same-named local branch.
        // So `HEAD` is recorded as the assumption, flagged `implicit`, and the
        // two settings that break it mark the invocation `unresolved`: the
        // repository's, read by [`implicit_push_config_unresolvable`], and the
        // command's own `-c`/`--config-env`, which that probe cannot see.
        refspecs.push(Refspec {
            raw: "HEAD".to_string(),
            source: Some("HEAD".to_string()),
            destination: None,
            is_delete: false,
            implicit: true,
        });
    }

    Some(PushInvocation {
        work_dir: globals.work_dir,
        refspecs,
        all_or_mirror: scan.all_or_mirror,
        tags: scan.tags,
        dry_run: scan.dry_run,
        unresolved: globals.foreign_redirect || (implicit && globals.push_config_override),
    })
}

/// What a walk of `git push`'s own option grammar found.
struct PushWordScan {
    /// Positional words after the first — the first positional is git's
    /// repository argument, every later one is a refspec.
    refspecs: Vec<String>,
    all_or_mirror: bool,
    tags: bool,
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
        tags: false,
        dry_run: false,
        delete_flag: false,
    };
    let mut positionals = 0usize;
    let mut options_ended = false;
    let mut index = 0;

    while index < words.len() {
        let raw = words[index].as_str();
        // **Options are read unescaped; the positional stays raw.** Argv proof,
        // all three shells: `printf "[%s]" --t\ags --mirr\or -\-all` yields
        // `[--tags][--mirror][--all]`. Comparing the raw word turned
        // `--a\ll` into an unrecognised option — the repository swallowed the
        // next word, no refspec was collected, and the implicit `HEAD` shipped
        // with `unresolved: false` while git published every branch. A
        // positional keeps its escape because a refspec goes to
        // [`is_safe_ref`], which correctly refuses a backslash.
        let word = unescape_word(raw);
        let word = word.as_ref();

        if !options_ended && word == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        if !options_ended && let Some(rest) = word.strip_prefix("--") {
            fn split_name(long: &str) -> (&str, Option<&str>) {
                match long.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (long, None),
                }
            }
            let (name, inline) = split_name(rest);
            // The same derivation over the RAW word, computed HERE beside its
            // unescaped twin rather than re-spelled at the `--dry-run` test
            // below. Two spellings of one derivation drift, and one edit to the
            // option grammar would change only one of them.
            let raw_name = raw.strip_prefix("--").map(|long| split_name(long).0);
            // `--all`/`--mirror` matched by PREFIX, the way git's parse-options
            // resolves an unambiguous abbreviation. Over-matching here only
            // widens the range a caller scans, so an ambiguous prefix git would
            // reject costs nothing.
            if abbreviates("all", name) || abbreviates("mirror", name) {
                scan.all_or_mirror = true;
            }
            // `--tags` widens the same way and is tracked separately — see the
            // field's docs. `--follow-tags` fails this test (`"tags"` does not
            // start with `"follow-tags"`) and is correctly non-widening.
            if abbreviates("tags", name) {
                scan.tags = true;
            }
            // Exact, both of them, and for opposite reasons. `dry-run` licenses
            // an allow, so a loose match is a bypass. `delete` skips a refspec,
            // so a loose match is a miss. Under-matching either only over-blocks.
            //
            // `dry-run` is additionally the ONE arm read on the RAW word: every
            // other test here fires more often once unescaped, which widens what
            // is scanned, while this one would license an allow. Under-matching
            // `--dry-\run` costs a false block on a harmless command.
            if raw_name == Some("dry-run") {
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
            // Short `-n` reads the RAW cluster, for the same reason the long
            // `--dry-run` does: it is the only allow-licensing arm.
            let raw_flags = raw
                .strip_prefix('-')
                .map(|c| match c.find('o') {
                    Some(position) => &c[..=position],
                    None => c,
                })
                .unwrap_or("");
            if raw_flags.contains('n') {
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
        // The first positional is the repository; the rest are refspecs. The
        // RAW word is kept — [`is_safe_ref`] refuses a backslash, so an escaped
        // refspec reaches the caller as unresolvable rather than as a guess.
        if positionals > 1 {
            scan.refspecs.push(raw.to_string());
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
///
/// **Task A owes two things this type cannot enforce.** A push that reaches
/// [`OutboundRange::Unavailable`] must block or nudge loudly, never allow —
/// history size alone can drive a first push into the deadline, so the
/// fail-open arm is reachable without an adversary. And the commit cap must be
/// applied *before* buffering: this call holds the whole `rev-list` stdout,
/// which on a first push is the entire history, with no size bound of its own.
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
    fn a_global_value_spelling_another_global_does_not_swallow_the_subcommand() {
        // `-C` here is `-c`'s value. A walk that decides "is this a value?" by
        // looking BACK one token then reads `push` as `-C`'s value, never
        // reaches the subcommand, and reports no push at all.
        let invocation = only("git -c -C push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("main"));
    }

    #[test]
    fn a_trailing_valueless_global_reports_no_push() {
        // `git -C` is an error git never runs; the walk must not panic on it.
        assert!(push_invocations("git -C", "/repo").is_empty());
    }

    #[test]
    fn git_dir_env_prefix_marks_the_invocation_unresolved() {
        assert!(only("GIT_DIR=/x/.git git push origin main", "/repo").unresolved);
        assert!(only("GIT_WORK_TREE=/x git push origin main", "/repo").unresolved);
    }

    #[test]
    fn env_redirect_on_a_wrapper_segment_reaches_the_child_push() {
        // The prefix assignment is exported into the child shell, so the push
        // inside it really does run redirected. Computing the flag on the
        // wrapper segment and dropping it at the recursion boundary is the
        // #228/#378 miss reopened in a new module.
        assert!(only("GIT_WORK_TREE=/x sh -c 'git push origin main'", "/repo").unresolved);
        assert!(only("GIT_DIR=/x/.git sh -c 'git push origin main'", "/repo").unresolved);
    }

    #[test]
    fn an_exported_git_dir_in_an_earlier_segment_marks_a_later_push_unresolved() {
        assert!(only("export GIT_DIR=/x/.git && git push origin main", "/repo").unresolved);
        assert!(only("export GIT_WORK_TREE=/x; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_bare_git_dir_assignment_segment_marks_a_later_push_unresolved() {
        // An assignment with no command word persists in the shell, unlike a
        // command prefix, which applies to that one command only.
        assert!(only("GIT_DIR=/x/.git; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_assignment_used_as_a_command_prefix_does_not_leak_to_a_later_push() {
        // `GIT_DIR=/x git status` sets the variable for `git status` alone, so
        // the push after it is NOT redirected and must stay resolvable.
        let found = push_invocations("GIT_DIR=/x/.git git status; git push origin main", "/repo");
        assert_eq!(found.len(), 1);
        assert!(!found[0].unresolved);
    }

    #[test]
    fn a_command_line_config_override_marks_an_implicit_refspec_unresolved() {
        // The walk's own `git config` subprocess reads the REPOSITORY, so a
        // setting the command supplies is structurally invisible to it.
        assert!(only("git -c push.default=matching push origin", "/repo").unresolved);
        assert!(only("git --config-env=push.default=V push origin", "/repo").unresolved);
        assert!(only("git --config-env push.default=V push origin", "/repo").unresolved);
        assert!(
            only(
                "git -c remote.origin.push=refs/heads/*:refs/heads/* push origin",
                "/repo"
            )
            .unresolved
        );
    }

    #[test]
    fn an_unrelated_command_line_config_leaves_an_implicit_refspec_resolved() {
        assert!(!only("git -c color.ui=never push origin", "/repo").unresolved);
        // `remote.<name>.pushurl` changes the destination, not the ref set.
        assert!(!only("git -c remote.origin.pushurl=/x push origin", "/repo").unresolved);
    }

    #[test]
    fn a_command_line_config_override_does_not_mark_an_explicit_refspec() {
        // A named refspec replaces the `push.default` computation outright, so
        // the override cannot change what is published.
        assert!(!only("git -c push.default=matching push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_git_config_env_prefix_marks_the_invocation_unresolved() {
        assert!(
            only(
                "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.default GIT_CONFIG_VALUE_0=matching git push",
                "/repo"
            )
            .unresolved
        );
        assert!(only("GIT_CONFIG_GLOBAL=/x git push origin main", "/repo").unresolved);
        assert!(only("GIT_CONFIG_SYSTEM=/x git push origin main", "/repo").unresolved);
        assert!(only("export GIT_CONFIG_COUNT=1 && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_unresolvable_cd_target_marks_every_later_push_unresolved() {
        // The pre-`cd` directory is not "nothing" — it is the session's own
        // checkout, which answers rev-list confidently for a push that ran
        // somewhere else.
        for command in [
            "cd \"$BUILD\" && git push origin main",
            "cd \"$HOME/other\" && git push origin main",
            "cd \"$(git rev-parse --show-toplevel)\" && git push origin main",
            "cd -; git push origin main",
            "cd; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should be unresolved: {command}");
        }
    }

    #[test]
    fn builtin_prefixed_cd_moves_the_work_dir() {
        // `builtin cd /usr` prints `/usr` under bash, zsh and sh alike — every
        // shell agrees, so the move is knowable.
        let invocation = only("builtin cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/other");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn command_prefixed_cd_is_shell_dependent_and_refuses() {
        // Measured: `command cd /usr` prints `/usr` under bash and sh but
        // `/tmp` under zsh, which forces external lookup — and the Bash tool on
        // this estate is zsh. The walk cannot know which shell runs, and an
        // earlier cut picked bash's answer and stated it with `unresolved:
        // false`.
        for command in [
            "command cd /other && git push origin main",
            "command -p cd /other && git push origin main",
            "command command cd /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn an_inner_backslash_in_the_verb_still_resolves_the_push() {
        // Measured: `g\it --version` prints `git version 2.55.0` under bash and
        // zsh. `command_word` stripped only a LEADING backslash after a
        // basename that splits on `\`, so `g\it` resolved to `it`, the segment
        // was dropped, and an empty invocation list is the strongest allow
        // shape there is.
        assert_eq!(sources("g\\it push origin main", "/repo"), ["main"]);
        assert_eq!(sources("gi\\t push origin main", "/repo"), ["main"]);
        // The subcommand takes the same escape (`git pu\sh` runs a push).
        assert_eq!(sources("git pu\\sh origin main", "/repo"), ["main"]);
    }

    #[test]
    fn a_backslash_bearing_directory_verb_refuses() {
        // `tokenize` throws quoting away, so `'c\d' /x` and `c\d /x` arrive as
        // the SAME token — and the shells disagree about them: measured, `\cd
        // /usr` moves under bash, zsh and sh while `'\cd' /usr` moves under
        // none of them (the quotes make it a literal command name). `cd\ /other`
        // is a third case: the escaped space makes it ONE word the shell never
        // runs, where the tokenizer sees two.
        //
        // For push detection, unescaping is safe — it only widens what is seen.
        // For a directory verb it is not: a wrong move is a wrong repository. So
        // a candidate that merely COULD unescape to a directory verb refuses.
        for command in [
            "'c\\d' /other && git push origin main",
            "c\\d /other && git push origin main",
            "\\cd /other && git push origin main",
            "cd\\ /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
    }

    #[test]
    fn a_backslash_bearing_prefix_refuses() {
        // The escape can sit in the PREFIX rather than the verb, and every one
        // of these moves the shell (measured under bash, zsh and sh; the
        // `\command` rows move under bash and sh only). Comparing the raw
        // prefix token made the whole segment invisible instead: the loop broke
        // on it, the prefix became the candidate, and `directory_verb` returned
        // None — so the walk kept a stale directory with `unresolved: false`,
        // which is worse than the over-refusal it replaced.
        for command in [
            "\\builtin cd /other && git push origin main",
            "buil\\tin cd /other && git push origin main",
            "b\\uiltin cd /other && git push origin main",
            "\\command cd /other && git push origin main",
            "comm\\and cd /other && git push origin main",
            "\\command -p cd /other && git push origin main",
            "\\builtin \\cd /other && git push origin main",
            "\\builtin popd && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
    }

    #[test]
    fn a_flagged_builtin_refuses() {
        // `builtin` takes NO options in bash, zsh or sh — measured, a flag word
        // makes it fail and the shell stays put. The peel shared one flag-skip
        // loop with `command`, so it skipped the flag, found `cd`, and reported
        // the move: a wrong repository with `unresolved: false`. Same trade
        // `resolve_directory_verb` already makes for `pushd` — refuse on ANY
        // flag rather than on a list of them.
        //
        // `builtin -- cd` is the second, independent half: bash and sh move,
        // zsh does not, and the Bash tool on this estate is zsh.
        for command in [
            "builtin -p cd /other ; git push origin main",
            "builtin -x cd /other ; git push origin main",
            "builtin --nope cd /other ; git push origin main",
            "builtin -p -q -z cd /other ; git push origin main",
            "builtin -p pushd /other ; git push origin main",
            "builtin -- cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
        }
        // Controls: an unflagged `builtin` still moves, and a flagged `command`
        // still refuses through its own arm.
        let moved = only("builtin cd /other && git push origin main", "/repo");
        assert_eq!(moved.work_dir, "/other");
        assert!(!moved.unresolved);
        assert!(only("command -v cd /other ; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_escaped_push_option_is_read_like_its_unescaped_control() {
        // Argv proof, all three shells:
        // `printf "[%s]" --t\ags --mirr\or -\-all` yields
        // `[--tags][--mirror][--all]`. The walk compared the raw word, so an
        // escaped `--all` read as an unrecognised option: `origin` became the
        // repository, no refspec was collected, and the implicit HEAD shipped
        // with `unresolved: false` while git published every branch.
        for command in [
            "git push --all origin",
            "git push --a\\ll origin",
            "git push -\\-all origin",
            "git push --al\\l origin",
            "git push --mirr\\or origin",
            "git push origin --a\\ll",
        ] {
            assert!(only(command, "/repo").all_or_mirror, "for {command}");
        }
        for command in [
            "git push --tags origin",
            "git push --t\\ags origin",
            "git push --ta\\gs origin main",
        ] {
            assert!(only(command, "/repo").tags, "for {command}");
        }
        // `--delete` widens the same way: an escaped spelling still deletes.
        assert!(only("git push --dele\\te origin topic", "/repo").refspecs[0].is_delete);
        // `dry_run` is the ONE arm where firing more often licenses an allow,
        // so it stays matched on the raw word and under-matches an escape.
        assert!(!only("git push --dry-\\run origin main", "/repo").dry_run);
        assert!(only("git push --dry-run origin main", "/repo").dry_run);
    }

    #[test]
    fn an_escaped_prefix_flag_refuses() {
        // `builtin \-- cd /other` and `command \-p cd /other` move bash and sh
        // (zsh stays) — the same three-way split F5 and F11 refuse. Both flag
        // tests read the raw token, so the escaped word failed them, became the
        // candidate, was not a directory verb, and the walk returned `None`:
        // a STALE directory with `unresolved: false`, the F9 mechanism one
        // token to the right.
        //
        // The last three rows are over-refusals — the shell stays put for
        // those — and that is the safe side, since the token cannot say whether
        // it was quoted.
        for command in [
            "builtin \\-- cd /other ; git push origin main",
            "command \\-p cd /other ; git push origin main",
            "builtin -- cd /other ; git push origin main",
            "command -p cd /other ; git push origin main",
            "builtin \\-p cd /other ; git push origin main",
            "command \\-v cd /other ; git push origin main",
            "builtin \\--nope cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "should refuse: {command}");
            assert_eq!(invocation.work_dir, "/repo", "no stale move: {command}");
        }
    }

    #[test]
    fn an_escaped_transparent_prefix_still_sees_the_push() {
        // `exec`, `command`, `builtin`, `time` and `nohup` are TRANSPARENT-only
        // — unlike `env`/`nice`, they have no second path through
        // `peel_command_runners` — so an escaped spelling made the whole
        // segment invisible and the push was absent from the results entirely.
        // Every row runs its argument in bash, zsh and sh.
        for command in [
            "exec git push origin main",
            "\\exec git push origin main",
            "\\command git push origin main",
            "\\builtin git push origin main",
            "\\time git push origin main",
            "ti\\me git push origin main",
            "\\nohup git push origin main",
            "time git push origin main",
            "nohup git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "for {command}");
        }
    }

    #[test]
    fn an_escaped_env_operand_redirect_is_seen() {
        // Two positions, opposite answers, same word. As an `env` OPERAND the
        // shell strips the backslash before `env` sees it, so `env GIT_\DIR=/x`
        // really sets GIT_DIR — measured, `env GIT_\DIR=/nope git rev-parse
        // --git-dir` reports `not a git repository: '/nope'` in all three
        // shells. As a bare shell PREFIX no shell honours it at all.
        assert!(only("env GIT_DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env GIT_\\DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env -i GIT_DIR=/x git push origin main", "/repo").unresolved);
        // Controls: the bare prefix spelling is honoured by no shell, so seeing
        // no push is the RIGHT answer and must stay that way.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
        assert!(push_invocations("GIT_CONFIG_\\COUNT=1 git push origin main", "/repo").is_empty());
    }

    #[test]
    fn a_flagged_transparent_prefix_reports_an_unresolved_push() {
        // No escape involved at all. `skip_transparent_prefixes` refuses to skip
        // a prefix whose next token is a flag — deliberately, so a prefix's own
        // option grammar is never parsed — and `command`/`exec`/`time`/`nohup`
        // have no `COMMAND_RUNNERS` second path the way `env`/`nice` do. The
        // segment therefore yielded NOTHING, which is the strongest allow shape
        // there is. Every row below runs under bash, zsh and sh (measured).
        for command in [
            "command -p git push origin main",
            "exec -a name git push origin main",
            "exec -c git push origin main",
            "exec -l git push origin main",
            "nohup -- git push origin main",
            "time -p git push origin main",
            // Over-refused on purpose: `builtin -p git push` fails in all three
            // shells, so nothing is published. An unresolvable push a caller can
            // explain beats an absent one it cannot see.
            "builtin -p git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(invocation.unresolved, "{command:?} must refuse, not vanish");
            assert_eq!(invocation.work_dir, "/repo", "{command:?}");
            assert!(invocation.refspecs.is_empty(), "{command:?}");
        }
        // `eval` joins the same fallback: it is in neither TRANSPARENT nor
        // COMMAND_RUNNERS, so the whole segment was invisible.
        assert!(only("eval git push origin main", "/repo").unresolved);
        // Controls: `env`/`nice` are ALSO command runners, whose peel has a real
        // flag grammar, so these resolve fully and must keep doing so.
        for command in [
            "env -i git push origin main",
            "nice -n 5 git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert!(!invocation.unresolved, "{command:?}");
            assert_eq!(
                invocation
                    .refspecs
                    .iter()
                    .filter_map(|r| r.source.clone())
                    .collect::<Vec<_>>(),
                ["main"],
                "{command:?}"
            );
        }
        // Control: a prefix with no push behind it stays absent, so the fallback
        // cannot invent an invocation out of any transparent prefix at all.
        assert!(push_invocations("command -p git status", "/repo").is_empty());
        assert!(push_invocations("exec -a name ls", "/repo").is_empty());
    }

    #[test]
    fn a_path_spelled_transparent_prefix_still_refuses() {
        // The fallback asked `names_transparent_prefix`, which unescapes and
        // folds but does NOT basename — while every sibling asking the same
        // question basenames (`guard_rm` and `peel_command_runners` both go
        // through `command_word`). `nohup` and `time` are real binaries in
        // /usr/bin, so this is not a theoretical spelling: each row below runs
        // under bash, zsh and sh (measured) and yielded nothing at all.
        for command in [
            "/usr/bin/nohup -- git push origin main",
            "/usr/bin/time -p git push origin main",
            "/usr/bin/nohup git push origin main",
            "/usr/bin/time git push origin main",
            "./nohup -- git push origin main",
            "command.exe -p git push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not vanish"
            );
        }
        // Controls: `env`/`nice` already survived a path because they are also
        // command runners, whose peel basenames. They must keep resolving fully.
        for command in [
            "/usr/bin/env -i git push origin main",
            "/usr/bin/nice -n 5 git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // Control: the bare spelling, unchanged.
        assert!(only("nohup -- git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_git_global_between_the_verb_and_push_still_refuses() {
        // The fallback was an ADJACENT-pair scan, so any global between `git`
        // and `push` restored the silent allow — and `-C /other` does not merely
        // hide the push, it redirects it to another repository. Every row is an
        // ordinary spelling with no escape anywhere.
        for command in [
            "command -p git -C /other push origin main",
            "exec -a x git -C /other push origin main",
            "time -p git -C /other push origin main",
            "nohup -- git -c a=b push origin main",
            "command -p git --git-dir=/x push origin main",
            "command -p git -c foo=bar push origin main",
            "eval git -C /other push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not vanish"
            );
        }
        // Controls: the shapes that already worked must keep working.
        for command in [
            "command -p git push origin main",
            "command -p git pu\\sh origin main",
            "command -p \\git push origin main",
            "command -p /usr/bin/git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // N26 is NOT closed by this fix, and the round's premise that it would be
        // does not hold. `command -p grep git push file` still refuses, because
        // `git push` really is adjacent in argument position: the structured read
        // finds `git` at index 3 and `git_globals` hands back `push` as its
        // subcommand, which is the correct reading of those two words in
        // isolation. Distinguishing them would require knowing that `grep` — not
        // `git` — is what the prefix runs, and that is exactly the per-prefix
        // flag grammar F16 declined to parse. Kept as a pinned over-refusal
        // rather than silently drifting.
        assert!(only("command -p grep git push file", "/repo").unresolved);
    }

    #[test]
    fn a_quoted_redirect_shaped_refspec_is_not_stripped() {
        // The fail-open the redirect strip introduced. `tokenize` performs quote
        // REMOVAL, so `'>leak'` and `>leak` arrive byte-identical, and a strip
        // judging the text alone discards the ambiguous case silently — the one
        // direction this module's doctrine forbids. `git check-ref-format
        // refs/heads/'>b'` answers OK, so these are legal refs.
        //
        // Every row must refuse. `is_safe_ref` rejects the `>` either way, so a
        // surviving token means `OutboundRange::Unresolved`, which a caller
        // cannot read as empty.
        for command in [
            "git push origin '>leak'",
            "git push origin '<leak'",
            "git push origin '2>x'",
            "git push origin '>' leak",
            "git push origin '>leak' main",
            "git push origin main '>leak'",
            "git push --delete origin '>leak'",
        ] {
            let invocation = only(command, "/repo");
            // Asserted on `raw`, not `source`: a `--delete` refspec has no
            // source by construction, so a source-only assertion would have
            // reported a kept operand as lost.
            assert!(
                invocation
                    .refspecs
                    .iter()
                    .any(|refspec| refspec.raw.contains('>') || refspec.raw.contains('<')),
                "{command:?} must keep the quoted operand, got {:?}",
                invocation.refspecs
            );
        }
        // The quoted operand in REPOSITORY position must not be read as a
        // redirect either — the refspec that follows is the real one.
        assert_eq!(sources("git push '>origin' main", "/repo"), ["main"]);
        // Control: the backslash spelling already refused, and must keep doing so
        // — the token keeps its backslash byte, so the strip never saw it.
        assert!(
            sources("git push origin \\>leak main", "/repo")
                .iter()
                .any(|s| s.contains('>'))
        );
        // Control: an ordinary UNQUOTED redirect is still stripped.
        assert_eq!(
            sources("git push origin main > /dev/null", "/repo"),
            ["main"]
        );
        assert_eq!(
            sources("git push origin main >/dev/null", "/repo"),
            ["main"]
        );
        // Control: a `>` inside a ref, not leading it, was never redirect-shaped.
        assert_eq!(
            sources("git push origin refs/heads/a>b", "/repo"),
            ["refs/heads/a>b"]
        );
    }

    #[test]
    fn a_redirect_with_a_quoted_target_is_still_a_redirect() {
        // Whole-token quote marking read `>"$LOG"` as "quoted", so the redirect
        // survived as a refspec, `is_safe_ref` rejected it, and the commonest
        // script spelling was refused. The operator is unquoted; only its TARGET
        // is. The mark this decision needs is about the operator prefix.
        for command in [
            "git push origin main >\"$LOG\"",
            "git push origin main >>\"$LOG\"",
            "git push origin main 2>\"$ERR\"",
            "git push origin main >\"$HOME/push.log\"",
            "git push origin main 2>\"/dev/null\"",
            "git push origin main >\"log\" 2>&1",
            "git push origin main >'/tmp/my log'",
            "git push --dry-run origin main >\"$LOG\"",
            // Controls: the standalone-operator form was never affected.
            "git push origin main > \"$LOG\"",
            "git push origin main > '/tmp/my log'",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // `--all` rows are in scope too. With the redirect stripped there is no
        // NAMED refspec left, so the implicit-`HEAD` arm fires — which is right:
        // `all_or_mirror` is what tells a caller the range is wider than HEAD.
        let all = only("git push --all origin >'log'", "/repo");
        assert!(all.all_or_mirror);
        assert!(all.refspecs.iter().all(|refspec| refspec.implicit));
        assert_eq!(sources("git push --all origin >'log'", "/repo"), ["HEAD"]);
    }

    #[test]
    fn a_quoted_redirect_operator_keeps_its_operand() {
        // The other side of the same mark. When the OPERATOR itself was quoted
        // the word is an operand, not a redirection — including the spellings
        // where the quote sits mid-operator or emits no bytes at all.
        for command in [
            "git push origin '>leak'",
            "git push origin '>'log",
            "git push origin ''>log",
            "git push origin 2'>'x",
            "git push origin '2'>x",
        ] {
            let invocation = only(command, "/repo");
            assert!(
                invocation
                    .refspecs
                    .iter()
                    .any(|refspec| refspec.raw.contains('>')),
                "{command:?} must keep the operand, got {:?}",
                invocation.refspecs
            );
        }
    }

    #[test]
    fn an_unbalanced_group_closer_refuses_rather_than_reporting_a_trimmed_word() {
        // `strip_group_wrappers` trims a trailing `}`/`)` unconditionally, so a
        // segment whose last token legitimately ends in one loses those bytes
        // before tokenization. `}` is an ordinary character there — measured,
        // `bash -c 'echo push origin main}'` prints it — and
        // `git check-ref-format refs/heads/'main}'` answers OK.
        //
        // The refspec face reports a DIFFERENT ref than the command publishes;
        // the directory face reports a different repository, both with
        // `unresolved: false`. Both are wrong answers, which this module exists
        // to prevent. bash and sh rows — zsh parse-errors on the source.
        for command in [
            "git push origin secret}",
            "git push origin secret}}",
            "git push --delete origin secret}",
            "git push origin main secret}",
            "git -C /other push origin secret}",
            "cd /other} && git push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "{command:?} must refuse, not answer"
            );
        }
        // Controls: a BALANCED wrapper is the shape the trim exists for, and
        // must keep resolving.
        assert_eq!(sources("(git push origin main)", "/repo"), ["main"]);
        assert_eq!(sources("{ git push origin main; }", "/repo"), ["main"]);
        assert_eq!(sources("git push origin main;", "/repo"), ["main"]);
        assert_eq!(sources("git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn a_redirection_before_the_subcommand_still_sees_the_push() {
        // A redirection is legal anywhere in a simple command, and the strip ran
        // AFTER the verb, globals and subcommand reads — so each of those was
        // handed a redirect token where it expected a word and returned None.
        // Every row runs under bash, zsh and sh (measured: a redirect between
        // the command word and its arguments is transparent to git).
        for command in [
            "git >log push origin main",
            "git 2>/dev/null push origin main",
            "git >/dev/null push origin secret-branch",
            ">log git push origin main",
        ] {
            assert!(
                !push_invocations(command, "/repo").is_empty(),
                "{command:?} must not vanish"
            );
        }
        assert_eq!(sources("git >log push origin main", "/repo"), ["main"]);
        assert_eq!(
            sources("git 2>/dev/null push origin main", "/repo"),
            ["main"]
        );
        assert!(only("git >log push --all", "/repo").all_or_mirror);
        // The prefix-wrapped spellings reach the fallback, which strips too.
        assert!(only("command -p git >log push origin main", "/repo").unresolved);
        assert!(only("nohup -- git 2>/dev/null push origin main", "/repo").unresolved);
        // Control: the trailing spelling, unchanged.
        assert_eq!(sources("git push origin main >log", "/repo"), ["main"]);
    }

    #[test]
    fn a_redirection_is_not_a_refspec() {
        // `strip_redirections` existed and was called at exactly one site — the
        // directory-verb operand read — while `scan_push_words` was handed the
        // words with the redirect tokens still in them. The first FALSE-REFUSAL
        // class this module has carried, on the most ordinary spelling there is:
        // `>` reaches `is_safe_ref`, which rejects it, and the range comes back
        // Unresolved for a push that is entirely routine.
        for command in [
            "git push origin main > /dev/null",
            "git push origin main >/dev/null",
            "git push origin main 2>&1",
            "git push origin main >log 2>&1",
            "git push origin main > out.txt",
            "git push origin main 2>/dev/null | tee log",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // A redirect BEFORE the operands must not be read as the repository.
        assert_eq!(sources("git push > log origin main", "/repo"), ["main"]);
        // Control.
        assert_eq!(sources("git push origin main", "/repo"), ["main"]);
    }

    #[test]
    fn an_escaped_runner_flag_still_sees_the_push() {
        // `skip_runner_flags` and `shell_c_argument_tokens` both compared raw
        // tokens, so an escaped flag was read as the command word and the peel
        // stopped there. Every row runs under bash, zsh and sh (measured); the
        // `env \-i GIT_DIR=/x` row is F14's own scenario one backslash to the
        // left, landing on the NO-PUSH-SEEN side F14 was raised to close.
        assert_eq!(
            sources("sh \\-c 'git push origin main'", "/repo"),
            ["main"],
            "an escaped -c must still surface the child script"
        );
        for command in [
            "nice \\-n 5 git push origin main",
            "sudo \\-u me git push origin main",
            "xargs \\-I{} git push origin main",
            "env \\-i git push origin main",
        ] {
            assert_eq!(sources(command, "/repo"), ["main"], "{command:?}");
        }
        // The redirect is still read through the escaped flag.
        assert!(only("env \\-i GIT_DIR=/x git push origin main", "/repo").unresolved);
        assert!(only("env \\-i GIT_\\DIR=/x git push origin main", "/repo").unresolved);
        // Control: the unescaped spelling, unchanged.
        assert_eq!(sources("sh -c 'git push origin main'", "/repo"), ["main"]);
    }

    #[test]
    fn an_escaped_cd_dash_refuses_rather_than_inventing_a_directory() {
        // `resolve_directory_verb` skipped flags on the raw token, so `\-` was
        // not recognised as the bare `-` meaning $OLDPWD; it fell through to
        // `resolve_cd_target`, which joined it into `/repo/\-`. It failed closed
        // downstream, but an invented directory is not an answer.
        assert!(only("cd \\- ; git push origin main", "/repo").unresolved);
        // Control: the unescaped spelling already refused.
        assert!(only("cd - ; git push origin main", "/repo").unresolved);
    }

    #[test]
    fn an_escaped_exported_redirect_marks_the_whole_scope() {
        // `export`/`declare`/`typeset` are builtins whose OPERANDS the shell
        // unescapes before they see them — measured, `export GIT_\DIR=/nope`
        // then `git rev-parse --git-dir` answers `not a git repository:
        // '/nope'` under bash, zsh and sh. The `exported` arm tested them raw,
        // so the redirect was invisible and every later push in the scope
        // reported `unresolved: false` against the session's own checkout.
        for command in [
            "export GIT_DIR=/x ; git push origin main",
            "export GIT_\\DIR=/x ; git push origin main",
            "typeset GIT_\\DIR=/x ; git push origin main",
            "declare -x GIT_\\DIR=/x ; git push origin main",
            "declare -x GIT_DIR=/x ; git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // Control, and it is why `assignment_only` stays RAW: a bare escaped
        // assignment segment is honoured by no shell, so seeing no push is the
        // right answer.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
    }

    #[test]
    fn a_runner_behind_a_prefix_still_skips_its_assignments() {
        // The gate read `tokens[0]`, but the runner is not always first: any
        // transparent prefix in front of it turned the gate off while the peel
        // still happened, leaving `argv[0]` as the assignment word itself.
        // Measured: `exec env GIT_\DIR=/nope git rev-parse --git-dir` answers
        // `not a git repository: '/nope'` under bash, zsh and sh.
        for command in [
            "exec env GIT_\\DIR=/x git push origin main",
            "command env GIT_\\DIR=/x git push origin main",
            "nohup env GIT_\\DIR=/x git push origin main",
        ] {
            assert!(only(command, "/repo").unresolved, "{command:?}");
        }
        // Controls: with no runner anywhere in the peeled region the bare-prefix
        // refusal must survive — no shell honours an escaped assignment prefix.
        assert!(push_invocations("GIT_\\DIR=/x git push origin main", "/repo").is_empty());
        assert!(push_invocations("GIT_CONFIG_\\COUNT=1 git push origin main", "/repo").is_empty());
    }

    #[test]
    fn an_eval_in_command_position_refuses_the_directory() {
        // `eval cd /other` moves bash, zsh and sh (measured), and `eval` is
        // peeled by nothing — so `directory_verb` answered `None`, meaning "not
        // a directory verb at all", the caller kept the STALE directory, and the
        // later push reported `/repo` with `unresolved: false`. That is the one
        // combination this module exists to prevent.
        let invocation = only("eval cd /other ; git push origin main", "/repo");
        assert!(invocation.unresolved);
        // Controls, all measured: these do NOT move the shell, so the walk is
        // right to keep the directory and stay resolved.
        for command in [
            "exec cd /other ; git push origin main",
            "env cd /other ; git push origin main",
            "nice cd /other ; git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/repo", "{command:?}");
            assert!(!invocation.unresolved, "{command:?}");
        }
        // `builtin builtin cd` DOES move, and still resolves.
        assert_eq!(
            only("builtin builtin cd /other ; git push origin main", "/repo").work_dir,
            "/other"
        );
    }

    #[test]
    fn an_escaped_git_global_is_read_like_its_unescaped_control() {
        // The shell removes the escape before git sees the word — measured,
        // `git --git-\dir=/nonexistent rev-parse` reports
        // `not a git repository: '/nonexistent'`. `git_globals` compared the raw
        // token, so a redirect went unflagged and an escaped `-C` was not even
        // seen as a push.
        //
        // Redirect flags: unresolved, exactly like the unescaped control.
        for command in [
            "git --git-dir=/x push origin main",
            "git --git-\\dir=/x push origin main",
            "git --work-tree=/x push origin main",
            "git --work-\\tree=/x push origin main",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "should refuse: {command}"
            );
        }
        // `-C` in either escaped spelling is still a push, and still redirects.
        for command in [
            "git -\\C /other push origin main",
            "git \\-C /other push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/other", "for {command}");
            assert_eq!(
                invocation.refspecs[0].source.as_deref(),
                Some("main"),
                "for {command}"
            );
        }
        // A config override reaches `push.default` through either escape.
        for command in [
            "git -c push.\\default=matching push origin",
            "git -\\c push.default=matching push origin",
            "git --config-\\env=push.default=P push origin",
        ] {
            assert!(
                only(command, "/repo").unresolved,
                "should refuse: {command}"
            );
        }
        // Control: an escaped global that names no redirect stays resolvable.
        assert!(!only("git -\\c color.ui=never push origin", "/repo").unresolved);
    }

    #[test]
    fn a_backslash_bearing_word_that_is_not_a_directory_verb_is_ignored() {
        // The refusal is scoped to tokens that could BE a directory verb.
        let invocation = only("ec\\ho hi && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn a_backslash_in_an_operand_is_left_alone() {
        // Only the VERB is unescaped. An operand keeps its backslash, so a
        // refspec carrying one fails `is_safe_ref` and refuses — the safe
        // direction, and the honest statement of what this walk models.
        let invocation = only("git push origin ma\\in", "/repo");
        assert_eq!(invocation.refspecs[0].source.as_deref(), Some("ma\\in"));
        assert!(!is_safe_ref("ma\\in"));
    }

    #[test]
    fn redirections_are_not_counted_as_operands() {
        // `pushd <dir> >/dev/null` is how the idiom is normally written, and
        // the operand count was reading the redirect as a second operand.
        for command in [
            "pushd /other >/dev/null && git push origin main",
            "cd /other 2>/dev/null && git push origin main",
            "cd /other > log 2>&1 && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/other", "for {command}");
            assert!(!invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn env_prefixed_cd_does_not_move_the_work_dir() {
        // Measured: `bash -c 'cd /tmp; env cd /usr; pwd'` prints `/tmp`. `env`
        // execs a CHILD, so the parent shell never moves — the push after it
        // runs in the original directory, and saying so is the correct answer.
        let invocation = only("env cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/repo");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn an_uppercase_or_path_qualified_cd_is_not_a_directory_verb() {
        // `cd` is a shell BUILTIN, so neither case-folding nor basename
        // stripping applies to it. Measured: `CD /usr` and `/usr/bin/cd /usr`
        // both leave bash in the original directory. Treating either as a move
        // would report a directory the shell never entered.
        for command in [
            "CD /other && git push origin main",
            "/usr/bin/cd /other && git push origin main",
        ] {
            let invocation = only(command, "/repo");
            assert_eq!(invocation.work_dir, "/repo", "for {command}");
            assert!(!invocation.unresolved, "for {command}");
        }
    }

    #[test]
    fn pushd_with_any_flag_marks_every_later_push_unresolved() {
        // `pushd -n /b` pushes onto the stack WITHOUT moving (measured: `pwd`
        // stays at `/a`). Enumerating which pushd flags move is the wrong side
        // of that problem, so any flag refuses.
        assert!(only("pushd -n /other && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_two_operand_cd_marks_every_later_push_unresolved() {
        // `cd <old> <new>` is bash's substitute form, not a move to `<old>`.
        // Measured: `cd repo other` errors and does not move.
        assert!(only("cd repo other && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn git_config_parameters_env_marks_the_invocation_unresolved() {
        // git honours this one standalone — no GIT_CONFIG_COUNT needed:
        // `GIT_CONFIG_PARAMETERS="'push.default=matching'" git config --get
        // push.default` prints `matching`.
        assert!(
            only(
                "GIT_CONFIG_PARAMETERS='push.default=matching' git push origin",
                "/repo"
            )
            .unresolved
        );
    }

    #[test]
    fn pushd_stack_rotation_marks_every_later_push_unresolved() {
        // `pushd +N`/`-N` rotate the directory stack, which this walk never
        // modelled. Measured: after two pushds, `pushd +1` really does move.
        assert!(only("pushd +1 && git push origin main", "/repo").unresolved);
        assert!(only("pushd -0 && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn pushd_with_a_literal_path_moves_the_work_dir() {
        let invocation = only("pushd /x && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/x");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn popd_marks_every_later_push_unresolved() {
        // `popd` returns to a directory this walk never recorded.
        assert!(only("popd && git push origin main", "/repo").unresolved);
        assert!(only("pushd && git push origin main", "/repo").unresolved);
    }

    #[test]
    fn a_resolvable_cd_still_leaves_a_later_push_resolved() {
        // The control for the two tests above: a literal target must not start
        // marking pushes unresolved.
        let invocation = only("cd /other && git push origin main", "/repo");
        assert_eq!(invocation.work_dir, "/other");
        assert!(!invocation.unresolved);
    }

    #[test]
    fn tags_flag_widens_the_ref_set_and_follow_tags_does_not() {
        // `--tags` publishes every ref under refs/tags, and a tag can point at
        // a commit no branch reaches — so HEAD's range is not the answer.
        let tagged = only("git push --tags origin", "/repo");
        assert!(tagged.tags);
        assert!(!tagged.all_or_mirror);
        // `--follow-tags` only pushes tags reachable from the pushed commits.
        let followed = only("git push --follow-tags origin main", "/repo");
        assert!(!followed.tags);
        assert!(!only("git push origin main", "/repo").tags);
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
    fn push_default_matching_marks_an_implicit_refspec_unresolved() {
        // `push.default=matching` publishes every same-named local branch, HEAD
        // or not, so the implicit HEAD refspec is not what git would push.
        let scratch = Scratch::new(&scratch_root(), "push-default-matching");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "matching"]);

        let invocation = only("git push origin", &repo.to_string_lossy());
        assert!(invocation.refspecs[0].implicit);
        assert!(invocation.unresolved);
    }

    #[test]
    fn push_default_simple_leaves_an_implicit_refspec_resolved() {
        let scratch = Scratch::new(&scratch_root(), "push-default-simple");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "simple"]);

        let invocation = only("git push origin", &repo.to_string_lossy());
        assert!(invocation.refspecs[0].implicit);
        assert!(!invocation.unresolved);
    }

    #[test]
    fn a_configured_remote_push_refspec_marks_an_implicit_refspec_unresolved() {
        let scratch = Scratch::new(&scratch_root(), "remote-push-refspec");
        let repo = scratch.path();
        init_repo(repo);
        git_in(
            repo,
            &["config", "remote.origin.push", "refs/heads/*:refs/heads/*"],
        );

        assert!(only("git push origin", &repo.to_string_lossy()).unresolved);
    }

    #[test]
    fn an_explicit_refspec_is_unaffected_by_push_default_matching() {
        // Named refspecs replace the push.default computation entirely, so the
        // config question never arises and no git call is made.
        let scratch = Scratch::new(&scratch_root(), "explicit-beats-matching");
        let repo = scratch.path();
        init_repo(repo);
        git_in(repo, &["config", "push.default", "matching"]);

        let invocation = only("git push origin main", &repo.to_string_lossy());
        assert!(!invocation.refspecs[0].implicit);
        assert!(!invocation.unresolved);
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
