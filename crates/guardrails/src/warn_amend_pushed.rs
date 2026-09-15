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
//! Amend detection and directory resolution run over the SAME unit: a top-level
//! segment's own tokens ([`split_segments_with_ops`] + [`executable_tokens`]).
//! Detection used to descend into wrappers, substitutions and loop bodies while
//! resolution stayed at the top level, and that gap is precisely how the check
//! produced confident answers about repositories the amend never touched. An
//! amend nested deeper is now a deliberate miss rather than a guess.
//!
//! The probed *directory* is decided by an **allowlist of command shapes**, and
//! that is a deliberate design choice rather than a conservative default. The
//! set of ways a shell can change directory has no closed enumeration — beyond
//! `cd` there is `pushd`, `eval`, a sourced script, a shell function, an alias,
//! a `CDPATH` hop, and whatever the next shell adds — so a list of spellings to
//! REFUSE can never be finished. A denylist of `cd` spellings shipped here
//! first, and `command cd`, `builtin cd`, `time cd`, `\cd`, `pushd` and `eval
//! 'cd …'` all walked straight past it into a confident nudge about the wrong
//! repository.
//!
//! So directory resolution proceeds only when EVERY segment is one of two
//! shapes it can prove ([`every_segment_is_followable`]):
//!
//! - the segment's OWN head executable is `git` (after the leading env
//!   assignments and transparent prefixes are peeled), which cannot move the
//!   directory; or
//! - the segment is a bare `cd <dir>` ([`bare_cd_target`]) **joined by `&&`,
//!   `;` or a newline, or ending the command**. `&` and `|` put one side in a
//!   subshell and `||` runs the rest only when the `cd` FAILED, so under those
//!   operators the effect is not known and the command is silenced.
//!
//! The accepted `cd` still carries one residual: a RELATIVE target is resolved
//! lexically against the effective directory, so a `CDPATH` entry that sends
//! `cd name` somewhere else would be followed to the wrong place. `CDPATH` is
//! rare, unset by default, and the miss is a wrong directory rather than an
//! unnoticed one — an absolute `cd` has no such gap.
//!
//! Any other head executable — `make`, `cargo`, `sh -c`, `pushd`, `eval`,
//! `source`, a shell function, a subshell opener — silences the whole command.
//! A `cd` written inside a quoted argument is one token and is not a command at
//! all, so a commit message mentioning `cd` still resolves normally.
//!
//! A `cd` carrying anything beyond its one directory argument is likewise not
//! the followable shape: `cd /b >/dev/null && git commit --amend` silences,
//! because the redirection makes the segment more than the `cd <dir>` whose
//! effect this check claims to know.
//!
//! A `--git-dir` or `--work-tree` amend is skipped outright, and so is a
//! `GIT_DIR=`/`GIT_WORK_TREE=` env prefix (bare or behind `env`). Its
//! repository is not the segment's directory, so probing there would answer a
//! confident question about the wrong repo — silence is the honest result.
//!
//! Silence costs one advisory nudge, and never more than that: the check has no
//! block arm, so every miss loses a warning and none bypasses a block, while a
//! guess would produce a confident claim about a repository the amend never
//! touched.

use cadence_hooks_core::display::sanitize_field;
use cadence_hooks_core::shell::{
    GitOutput, command_word, executable_tokens, git_output_detailed, has_unbalanced_groups,
    is_transparent_prefix_word, resolve_cd_target, skip_transparent_prefixes,
    split_segments_with_ops,
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
///
/// **Only options whose argument is REQUIRED belong here.** git's three
/// optional-argument commit options — `-S`/`--gpg-sign[=<keyid>]` and
/// `-u`/`--untracked-files[=<mode>]` — take a value only when it is *attached*
/// with `=`, so the following word is the next flag, not their argument. Listed
/// here they swallowed it: measured on git 2.55.0, `git commit -S --amend`,
/// `git commit -u --amend` and `git commit --untracked-files --amend` all amend,
/// and the guard read every one of them as a non-amend and stayed silent. An
/// `=`-attached spelling carries its own value and is handled by the
/// [`takes_separate_value`] `=` test, so dropping them loses nothing.
const COMMIT_VALUE_OPTS: &[&str] = &[
    "-m",
    "-c",
    "-C",
    "-F",
    "-t",
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
        let names_a_redirect = matches!(token.as_str(), "--git-dir" | "--work-tree")
            || token.starts_with("--git-dir=")
            || token.starts_with("--work-tree=");
        // A value that merely LOOKS like one of these belongs to the preceding
        // option and is not a redirect. Written as its own binding because `&&`
        // binds tighter than `||`: inlined, this clause guarded only the last
        // arm, so `git -c --git-dir=/other commit --amend` read as a redirect
        // and silently dropped the nudge.
        let belongs_to_the_preceding_option =
            i > 0 && VALUE_GLOBALS.contains(&argv[i - 1].as_str());
        names_a_redirect && !belongs_to_the_preceding_option
    })
}

/// The directories an amending `git commit` in `command` would run in, one per
/// matching segment, resolved against `cwd`.
///
/// Walks the command's TOP-LEVEL segments in order, carrying an effective
/// directory that only a bare `cd` moves — and only for the segments that
/// follow it, since the shell's `cd` takes effect after that segment runs.
/// Each segment is examined for an amend using its OWN tokens plus its own `-C`
/// chain: detection and resolution read the same unit, deliberately. A wrapper
/// script, a loop or conditional body, and a command substitution are not
/// examined at all — [`every_segment_is_followable`] has already silenced any
/// command containing one, because their working directory is not provable.
///
/// Empty when the command contains no amend — the common case, and the one that
/// costs no git spawn at all.
fn amend_target_dirs(command: &str, cwd: &str) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    let segments = split_segments_with_ops(command);

    if !every_segment_is_followable(&segments) {
        return dirs;
    }

    let mut effective = cwd.to_string();
    for (segment, _op) in &segments {
        // The operator is read by `every_segment_is_followable`, which has
        // already refused the whole command if any bare `cd` was joined by one
        // that makes its effect conditional or subshell-local.
        // The segment's OWN tokens, not the segments nested inside it. Every
        // surviving segment is git-headed or a bare `cd`, so an amend nested
        // deeper can only sit inside a command substitution — which the shell
        // runs in a subshell, in a directory this walk cannot prove. Resolving
        // it against `effective` would be the same wrong-repo answer the
        // allowlist exists to prevent, so it is a deliberate miss.
        if let Some(dir) = amend_dir_of(&executable_tokens(segment), &effective)
            && !dirs.contains(&dir)
        {
            dirs.push(dir);
        }

        // A `cd` applies to what comes AFTER it, so this runs once the segment
        // has been examined.
        if let Some(target) = bare_cd_target(segment) {
            effective = resolve_cd_target(&target, &effective);
        }
    }

    dirs
}

/// True when EVERY segment of the command is one of the two shapes whose effect
/// on the working directory this check can prove.
///
/// This is the allowlist named in the module header, and it replaced a denylist
/// of `cd` spellings. The denylist matched the literal token `cd`, so `command
/// cd /b`, `builtin cd /b`, `time cd /b`, `\cd /b`, `pushd /b` and `eval 'cd
/// /b'` all walked past it and produced a nudge naming the session's own refs
/// for an amend performed elsewhere — each one measured moving `$PWD`. Adding
/// those six spellings would have left the seventh: the set of ways a shell can
/// change directory is open-ended (a shell function, an alias, a sourced script,
/// a `CDPATH` hop), so no list of what to refuse can be finished. A list of what
/// to ACCEPT can.
///
/// The two accepted shapes:
///
/// - **git-headed.** The segment's OWN head executable is `git`, after the
///   leading env assignments and transparent prefixes
///   [`skip_transparent_prefixes`] already peels. Such a segment cannot move the
///   directory, and where it names another repository through
///   `-C`/`--git-dir`/`--work-tree` or the env, [`amend_dir_of`] handles it. A
///   command substitution written inside that command line runs in a subshell,
///   so it cannot move THIS shell's directory and gets no say here — testing
///   every nested segment's head instead silenced an ordinary
///   `git commit --amend -m "$(date)"`.
/// - **a bare `cd`** ([`bare_cd_target`]), whose one effect is known exactly.
///
/// Anything else — `make`, `cargo`, `sh -c`, `pushd`, `eval`, `source`, a shell
/// function — silences the whole command. That also retires the subshell
/// heuristic this function used to carry: `( cd /b && git commit --amend )`
/// splits into `( cd /b` and `git commit --amend )`, and the first is not a bare
/// `cd` (its raw text opens with a paren), so the command is unfollowable
/// without anyone having to reason about parens.
///
/// Silence costs one advisory nudge. Guessing costs a confident answer about a
/// repository the amend never touched, which is the failure this guard exists
/// to avoid.
fn every_segment_is_followable(segments: &[(String, Option<&'static str>)]) -> bool {
    segments.iter().all(|(segment, op)| {
        // A segment whose grouping syntax does not close is a fragment, not a
        // top-level command: a subshell opener/closer, or the residue of the
        // splitter cutting inside a `$( … )` or `` `…` `` substitution. `git log
        // $(git rev-parse HEAD; cd B) ; git commit --amend` splits at the `;`
        // INSIDE the substitution, and the fragment `cd B)` otherwise passes
        // the bare-`cd` test — tokens `["cd", "B"]`, raw text opening `cd ` —
        // which moved the probe into B on a command where the shell never
        // leaves the cwd.
        //
        // [`has_unbalanced_groups`] asks the shared quote scanner rather than
        // counting raw characters, because a raw count is wrong in both
        // directions: it misses the backtick spelling (no paren at all) and a
        // cut hidden behind quoted parens, and it silences honest commands
        // whose commit message contains `:)` or `fix(scope):`.
        if has_unbalanced_groups(segment) {
            return false;
        }
        if bare_cd_target(segment).is_some() {
            // The operator JOINING this `cd` to what follows decides whether
            // its effect is knowable. `&&` and `;` (and a newline, and nothing
            // at all) run the rest in this shell after the `cd` succeeded.
            // `&` and `|` put one side in a SUBSHELL, so `cd B & git commit
            // --amend` and `cd B | git commit --amend` leave $PWD untouched for
            // the amend — measured under bash and zsh. `||` runs the rest only
            // if the `cd` FAILED, so the shape test's promise ("this cd's
            // effect is known exactly") is simply false. Each of these produced
            // a nudge naming the wrong repository's refs.
            return matches!(op, None | Some("&&") | Some(";") | Some("\n"));
        }
        let tokens = executable_tokens(segment);
        // An empty segment (a trailing `;`) runs nothing and moves nothing.
        // The test is the segment's OWN head: a command substitution written
        // inside a git command line (`git commit --amend -m "$(date)"`) runs in
        // a subshell and cannot move this shell's directory, so it has no say
        // in whether the directory is followable.
        tokens.is_empty() || is_git_headed(&tokens)
    })
}

/// True when `tokens` runs `git`, after the leading env assignments and
/// transparent prefixes are peeled — so `command git commit`, `env FOO=1 git
/// commit` and `/usr/bin/git commit` all qualify, and `command cd` does not.
fn is_git_headed(tokens: &[String]) -> bool {
    skip_transparent_prefixes(tokens)
        .first()
        .is_some_and(|head| command_word(head) == "git")
}

/// `Some(<dir>)` when `segment` is a bare `cd <dir>` — the one directory change
/// whose effect is provable from the text.
///
/// Both halves are required. The TOKENS must be exactly `cd` plus one
/// non-flag argument, which rejects `cd` with options and `cd` with no
/// argument (a `$HOME` hop this check will not guess at). The RAW TEXT must
/// also begin with `cd` and a space, which is what rejects every spelling that
/// reaches the same builtin through something else — `command cd /b`, `builtin
/// cd /b`, `time cd /b`, `\cd /b` — and what rejects the subshell opener
/// `( cd /b`, whose tokens are exactly `["cd", "/b"]` once the paren is
/// stripped.
///
/// A quoted argument stays one token, so `cd '/tmp/old (archive)'` is a bare
/// `cd` and a commit message mentioning `cd` never becomes one.
fn bare_cd_target(segment: &str) -> Option<String> {
    let after_cd = segment.trim_start().strip_prefix("cd")?;
    if !after_cd.starts_with(char::is_whitespace) {
        return None;
    }
    match executable_tokens(segment).as_slice() {
        [head, dir] if head == "cd" && !dir.starts_with('-') => Some(dir.clone()),
        _ => None,
    }
}

/// True when the leading assignment words set `GIT_DIR` or `GIT_WORK_TREE`.
///
/// `GIT_DIR=/other/.git git commit --amend` names a target repository exactly
/// as plainly as `--git-dir` does, and [`skip_transparent_prefixes`] discards
/// those words before [`redirects_repository`] ever sees them — so the flag
/// spelling was refused while the env spelling produced a nudge naming the
/// SESSION's refs for a commit in another repo. Walks the same leading region
/// as `skip_transparent_prefixes`, over the shared
/// [`is_transparent_prefix_word`] predicate, so assignments behind `env` (`env
/// GIT_DIR=… git commit`) are seen too and the two walks cannot disagree about
/// where the region ends. Mirrors `guardrails::enforce_worktree`'s
/// `git_env_overrides`, which reads the same two variables for the same reason.
fn sets_git_repo_env(tokens: &[String]) -> bool {
    let mut idx = 0;
    while idx + 1 < tokens.len() && is_transparent_prefix_word(tokens, idx) {
        let token = tokens[idx].as_str();
        if token.starts_with("GIT_DIR=") || token.starts_with("GIT_WORK_TREE=") {
            return true;
        }
        idx += 1;
    }
    false
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
    while idx < argv.len() {
        let token = argv[idx].as_str();
        if !token.starts_with('-') {
            break;
        }
        // `-C` compounds: each hop resolves against the previous one.
        if token == "-C"
            && let Some(target) = argv.get(idx + 1)
        {
            let from = redirect.as_deref().unwrap_or(effective);
            redirect = Some(resolve_cd_target(target, from));
        }
        // A global that takes a separate value consumes the NEXT token as data.
        // Stepping one at a time and testing the PRECEDING token instead read a
        // value that happened to spell a global (`git -c --git-dir commit`) as a
        // global of its own, which then swallowed `commit` and lost the amend.
        idx += if VALUE_GLOBALS.contains(&token) { 2 } else { 1 };
    }

    if argv.get(idx).map(String::as_str) != Some("commit") {
        return None;
    }
    if !selects_amend(&argv[idx + 1..]) {
        return None;
    }
    // The repository is elsewhere and this check cannot say where — answering
    // about the segment's directory would be a confident answer about the wrong
    // repo. Both spellings count: the `--git-dir`/`--work-tree` flags, and the
    // `GIT_DIR=`/`GIT_WORK_TREE=` env prefix the flag walk never sees because
    // `skip_transparent_prefixes` already dropped it.
    if redirects_repository(&argv[..idx]) || sets_git_repo_env(tokens) {
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
    fn a_value_that_looks_like_a_git_dir_redirect_is_not_one() {
        // Each of these passes a repository-redirect SPELLING as the value of
        // `-c`. Git reads it as config data, so the amend still runs in the
        // session's own directory and the nudge is owed. Measured live before
        // the fix: the `--work-tree=` spelling nudged while both `--git-dir`
        // spellings went silent, because `&&` bound tighter than `||`.
        for command in [
            "git -c --git-dir=/other commit --amend",
            "git -c --git-dir commit --amend",
            "git -c --work-tree=/other commit --amend",
            "git -c --work-tree commit --amend",
        ] {
            assert_eq!(
                amend_target_dirs(command, "/cwd"),
                vec!["/cwd".to_string()],
                "{command} amends the session's own repo, so it is owed a nudge"
            );
        }
    }

    #[test]
    fn a_git_repo_env_prefix_silences_the_segment() {
        // Each of these names another repository through the environment. The
        // flag spelling was already refused; `skip_transparent_prefixes` drops
        // the assignment words before the flag walk sees them, so the env
        // spelling used to nudge naming the SESSION's refs for a commit made
        // elsewhere.
        for command in [
            "GIT_DIR=/other/.git git commit --amend",
            "GIT_WORK_TREE=/other GIT_DIR=/other/.git git commit --amend",
            "env GIT_DIR=/other/.git git commit --amend",
            "GIT_WORK_TREE=/other git commit --amend",
        ] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} names another repo through the environment"
            );
        }
        // Positive control: the same amend with no env prefix still resolves.
        assert_eq!(
            amend_target_dirs("git commit --amend", "/cwd"),
            vec!["/cwd".to_string()]
        );
        // An unrelated assignment word is not a repository redirect.
        assert_eq!(
            amend_target_dirs("FOO=bar git commit --amend", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn a_cd_inside_a_wrapper_silences_the_segment() {
        // Amend detection descends into these; directory resolution cannot
        // follow. Nudging would name the session's own refs for a commit made
        // in another repo.
        for command in [
            "sh -c 'cd /b && git commit --amend'",
            "bash -c 'cd /b; git commit --amend'",
            "( cd /b && git commit --amend )",
        ] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} moves the amend somewhere this walk cannot follow"
            );
        }
        // A top-level `cd` is followed, and keeps its existing behavior.
        assert_eq!(
            amend_target_dirs("cd /b && git commit --amend", "/cwd"),
            vec!["/b".to_string()]
        );
    }

    #[test]
    fn a_non_git_head_anywhere_silences_the_command() {
        // Every one of these reaches a directory change the guard cannot prove,
        // and every one moved `$PWD` when measured. A denylist of `cd`
        // spellings matched none of them, so the guard nudged naming the
        // session's own refs for an amend performed elsewhere. The allowlist
        // asks the opposite question — is this shape provable — and none of
        // these are.
        for command in [
            "command cd /b && git commit --amend",
            "builtin cd /b && git commit --amend",
            "time cd /b && git commit --amend",
            "eval 'cd /b' && git commit --amend",
            "pushd /b && git commit --amend",
            "\\cd /b && git commit --amend",
            // Not a directory change at all, but equally unprovable: the guard
            // cannot know what an arbitrary command did to the working dir.
            "make && git commit --amend",
            "git commit --amend && make",
            "source ./env.sh && git commit --amend",
            ". ./env.sh && git commit --amend",
            // These three DO amend in the session's own directory, so the
            // allowlist costs a real nudge on each. It is the price of the
            // shape test being decidable: a wrapper script or a loop body is
            // exactly where an unprovable `cd` hides, and the guard cannot tell
            // these apart from `sh -c 'cd /b && git commit --amend'` without
            // re-opening the question the denylist failed to answer.
            "sh -c 'git commit --amend'",
            "for d in x; do git commit --amend; done",
            "if true; then git commit --amend; fi",
            // Same class, same declared cost: the tail segment's head is not
            // `git`, so an amend that really does run in the session's own
            // directory goes unnudged.
            "git commit --amend || echo failed",
            "git commit --amend | tee /tmp/x",
        ] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} is not a shape this guard can follow"
            );
        }
    }

    #[test]
    fn an_operator_that_hides_the_cd_silences_the_command() {
        // The operator JOINING a bare `cd` decides whether its effect is
        // knowable, and the splitter has always returned it. Discarding it left
        // four wrong-repo nudges: `&` and `|` run one side in a subshell, so
        // $PWD never moves for the amend (measured under bash and zsh); `||`
        // runs the amend only if the `cd` FAILED, so no amend runs at all.
        for command in [
            "cd /b & git commit --amend",
            "cd /b | git commit --amend",
            "cd /b |& git commit --amend",
            "cd /b || git commit --amend",
        ] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} does not move the amend's directory the way a bare cd does"
            );
        }
        // The splitter cuts inside a substitution, and the fragment `cd /b)`
        // passes the bare-`cd` token and raw-text tests. Unclosed grouping
        // syntax is what says it is a fragment rather than a command — counted
        // outside quotes only, so all three spellings are caught.
        for command in [
            // `$( … )`: the paren spelling.
            "git log $(git rev-parse HEAD; cd /b) ; git commit --amend",
            // Backticks: the same cut with NO paren anywhere, which a raw paren
            // count could never see.
            "git log `git rev-parse HEAD; cd /b; git status` ; git commit --amend",
            // Quoted parens inside the substitution make a raw count balance,
            // hiding the real cut behind them.
            "git log $(echo ')' ; cd /b ; git log '(' ) ; git commit --amend",
        ] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} is cut inside a substitution, so its `cd` is a fragment"
            );
        }
        // A `cd` carrying anything beyond its one directory argument is not the
        // followable shape either.
        assert!(
            amend_target_dirs("cd /b >/dev/null && git commit --amend", "/cwd").is_empty(),
            "a redirected cd is more than the shape this check can prove"
        );
        // `&&` and `;` remain followable.
        assert_eq!(
            amend_target_dirs("cd /b && git commit --amend", "/cwd"),
            vec!["/b".to_string()]
        );
        assert_eq!(
            amend_target_dirs("cd /b ; git commit --amend", "/cwd"),
            vec!["/b".to_string()]
        );
    }

    #[test]
    fn the_allowlisted_shapes_still_resolve() {
        // Shape (a): every segment is git-headed, including the transparent
        // prefixes the module already peels.
        for command in [
            "git commit --amend",
            "git add . && git commit --amend",
            "FOO=bar git commit --amend",
            "command git commit --amend",
            // Commit-message prose is data, not a command, so neither a `cd`
            // nor a paren in it reaches the shape test.
            "git commit --amend -m 'cd into the dir'",
            "git commit --amend -m 'wip (typo)'",
        ] {
            assert_eq!(
                amend_target_dirs(command, "/cwd"),
                vec!["/cwd".to_string()],
                "{command} resolves to the session's own directory"
            );
        }
        // Shape (b): a bare `cd`, applying to what follows it.
        assert_eq!(
            amend_target_dirs("cd /a && git commit --amend", "/cwd"),
            vec!["/a".to_string()]
        );
        // The paren heuristic is gone, so a directory whose NAME carries parens
        // is an ordinary bare `cd` again.
        assert_eq!(
            amend_target_dirs("cd '/tmp/old (archive)' && git commit --amend", "/cwd"),
            vec!["/tmp/old (archive)".to_string()]
        );
        // A `-C` on the git segment itself still redirects the probe.
        assert_eq!(
            amend_target_dirs("git -C /a commit --amend", "/cwd"),
            vec!["/a".to_string()]
        );
        // A command substitution inside a git command line runs in a subshell,
        // so it cannot move THIS shell's directory and has no say in whether
        // the shape is followable. Testing every nested segment's head instead
        // of the segment's own silenced this ordinary amend.
        for command in [
            "git commit --amend -m \"$(date)\"",
            "git commit --amend -m \"release $(cat VERSION)\"",
            // The backtick spelling of the same thing: balanced, so whole.
            "git commit --amend -m \"built `date`\"",
            // Parens inside a quoted commit message are text, not grouping
            // syntax. A raw character count called each of these a fragment and
            // silenced an ordinary amend.
            "git commit --amend -m \"done :)\"",
            "git commit --amend -m \"(wip\"",
            "git commit --amend -m 'fix(scope): x'",
        ] {
            assert_eq!(
                amend_target_dirs(command, "/cwd"),
                vec!["/cwd".to_string()],
                "{command} amends in the session's own directory"
            );
        }
    }

    #[test]
    fn an_optional_argument_option_does_not_swallow_the_amend() {
        // git 2.55.0 amends on every one of these: `-S`/`--gpg-sign` and
        // `-u`/`--untracked-files` take a value only when attached with `=`.
        for command in [
            "git commit -S --amend",
            "git commit -u --amend",
            "git commit --untracked-files --amend",
            "git commit --gpg-sign --amend",
        ] {
            assert_eq!(
                amend_target_dirs(command, "/cwd"),
                vec!["/cwd".to_string()],
                "{command} amends, so it is owed a nudge"
            );
        }
        // Controls: no amend anywhere in these, so they stay silent.
        for command in ["git commit -S -m x", "git commit -u --no-edit"] {
            assert!(
                amend_target_dirs(command, "/cwd").is_empty(),
                "{command} does not amend"
            );
        }
        // An option whose argument really is required still consumes it, and an
        // `=`-attached optional argument is still its own value.
        assert!(
            amend_target_dirs("git commit -m --amend", "/cwd").is_empty(),
            "-m takes a required value, which happens to spell the flag"
        );
        assert_eq!(
            amend_target_dirs("git commit --untracked-files=no --amend", "/cwd"),
            vec!["/cwd".to_string()]
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

        // The session sits in a tempdir outside any repo — Scratch's default root is inside the
        // checkout, so a scratch cwd left this passing even if `-C` handling were deleted. The
        // `-C` is what makes the probe land on the pushed checkout.
        let outside = tempfile::tempdir().unwrap();
        let command = format!("git -C {} commit --amend", repo.to_string_lossy());
        let input = make_bash_with_cwd(&command, &outside.path().to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Nudge);
    }

    #[test]
    fn silent_outside_a_repository() {
        // Scratch's default root is inside the checkout, so the "no repo" premise held only on a
        // carve-out worktree; a tempdir is outside any repo everywhere.
        let outside = tempfile::tempdir().unwrap();
        let input = make_bash_with_cwd("git commit --amend", &outside.path().to_string_lossy());
        assert_eq!(WarnAmendPushed.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn empty_command_allows() {
        assert_eq!(WarnAmendPushed.run(&make_bash("")).outcome, Outcome::Allow);
    }
}
