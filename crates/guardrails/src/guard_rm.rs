//! guard-rm — path-aware triage of `rm`-family delete commands.
//!
//! Instead of a blanket permission prompt on every recursive delete, guard-rm
//! inspects each command's deletion targets and returns a graduated decision:
//!
//! - **ALLOW** (silent, exit 0) — a target under a temp root (`/tmp`,
//!   `/private/tmp`, `$TMPDIR`) or inside a `.claude/` session-scratch
//!   directory (one worktree, one session intro — see
//!   `pathclass::CLAUDE_SCRATCH_DIRS`). The friction removed.
//! - **BLOCK** (exit 2, disclosed message) — `/`, `$HOME`, a first-level home
//!   child, inside `$OBSIDIAN_VAULT`, or a git repo root / any path with a
//!   `.git` component.
//! - **ASK** ([`Outcome::Ask`], the prompt) — an unexpanded variable, a command
//!   substitution, a `..`-bearing path, a brace list, durable `.claude` state,
//!   or anything else not proven safe. This is the default, so nothing that
//!   prompts today stops prompting unless it is structurally proven safe.
//!
//! **The single-file rule is the one softening of the ambiguous middle.**
//! Without `-r`, `rm` and `unlink` cannot remove a directory — the shell
//! refuses — so a glob-free operand names exactly one file. That is a shell
//! guarantee costing no I/O, unlike a recoverability probe, and it lifts only
//! [`TargetClass::Unknown`] to ALLOW. Every protected class still blocks, and
//! durable `.claude` state is a separate class specifically so this rule cannot
//! reach it: one session transcript is still the only copy of that transcript.
//!
//! Three exclusions keep the premise true. `rm -d`/`--dir` leaves the class —
//! it removes an empty directory without `-r`. A glob-bearing operand leaves it
//! — `rm *` resolves to the *directory* the sweep runs in. And a brace-bearing
//! operand is unresolvable outright, because one token naming many targets
//! cannot be enumerated here, and `strip_group_wrappers` mangles it into a
//! single plausible-looking path whose first alternative escapes its class.
//!
//! **Charter:** a *discipline guard with an allow-granting edge*, not a security
//! boundary. Fails open (ADR-0001). Deliberately NOT in `PROTECTED_GUARDS`, so
//! `CADENCE_DISABLE=guard-rm` may neuter it. The catastrophic floor (built-in
//! circuit breakers + retained settings `deny` rows) bounds the
//! fail-open-plus-allow window.
//!
//! **v1 scope (deferred, not forgotten):** a fourth ALLOW mechanism — a per-repo
//! declared safe-path config (`.claude/rm-exemptions.json`) — was cut from v1 as
//! a Step-0 trim (YAGNI); it returns on a real trigger. v1 ships the three
//! structural ALLOW/BLOCK edges above plus the ASK default.
//!
//! **Scope, by design (documented misses, not holes):**
//! - The leading command word is basename-matched against `rm`/`unlink`/
//!   `shred`/`truncate` (plus `find … -delete`), after transparent prefixes
//!   (`command`/`env`/`VAR=x`/…). So `git rm`, `npm rm`, and a look-alike like
//!   `charm` are correctly *not* deletions.
//! - `sudo rm …` is out of scope: `sudo` is not a transparent prefix here, and
//!   a settings `allow Bash(rm:*)` rule keys on the leading word too, so `sudo`
//!   is consistently outside both. Adding `sudo`-flag parsing would risk a
//!   misread; the miss is intentional.
//! - A `..`-bearing target resolves ambiguously (symlinks, escapes), so it
//!   downgrades to ASK rather than a guessed BLOCK/ALLOW.
//! - Same-command variable expansion is deliberately **absent**. Resolving
//!   `SP=/tmp/x; rm -rf "$SP"` was built and then withdrawn: three adversarial
//!   review rounds found sixteen silent-ALLOW misses in it, and the last round
//!   found four *categorically* new mutation routes — `printf -v`, a
//!   transparent prefix defeating a builtin gate, `IFS` redefining word
//!   splitting, and subshell scoping erased by `strip_group_wrappers`. The
//!   shell moves a variable through more routes than a parser at this altitude
//!   can enumerate, so an unexpanded variable stays ASK.
//!
//! **Segment-aware parsing:** targets are collected by mirroring
//! `enforce_worktree::collect_commit_targets` — walking `split_segments_with_ops`
//! while tracking the effective cwd through `cd` chains, and recursing into each
//! segment's `child_scripts` (`sh -c '…'` wrappers, `$(…)`/backtick bodies) with
//! a *fresh* cwd scope. It deliberately does **not** flatten via
//! `command_segments`, which would splice a `$(cd /x)` into the parent stream
//! and misjudge a target the shell still deletes in the parent's cwd (issue
//! #228). Rolling no new recursion keeps the adversarially-reviewed primitives
//! the single source of truth.

use crate::enforce_worktree::{
    TRANSPARENT, is_assignment_word, skip_transparent_prefixes, strip_group_wrappers,
};
use cadence_hooks_core::pathclass::{self, PathClass, PathClassContext};
use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, basename, child_scripts, looks_absolute, resolve_cd_target,
    split_segments_with_ops, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome, normalize_path};
use std::path::Path;

/// Delete verbs whose leading command word marks a filesystem deletion.
/// Deliberately duplicates `obsidian::trash_guard`'s destructive-verb set (per
/// the plan's reuse ledger: promote when cheap, else duplicate with
/// attribution) — the two guards judge different things (vault membership vs
/// path class), so a shared const would couple them without real reuse.
const DELETE_VERBS: &[&str] = &["rm", "unlink", "shred", "truncate"];

/// The command word `token` names, stripped to what the shell will actually
/// run: `basename` so `/bin/rm` matches, and a leading `\` removed so the
/// alias-bypass form `\rm` is still seen as `rm`.
///
/// (Deliberate miss: `RM` on a case-insensitive volume — matching
/// case-insensitively would be wrong on Linux. Mitigated: a settings
/// `allow Bash(rm:*)` rule keys on the leading word too, so it defers, never
/// silently auto-approves.)
fn command_word(token: &str) -> &str {
    basename(token).trim_start_matches('\\')
}

/// `token` names one of the [`DELETE_VERBS`]. Shared by every site that has to
/// recognize a delete verb, so the `\`-strip above lives in exactly one place —
/// forgetting it at a new call site would silently re-open the alias bypass.
fn is_delete_verb(token: &str) -> bool {
    DELETE_VERBS.contains(&command_word(token))
}

/// A directory-changing builtin, as [`directory_change`] classifies it.
///
/// Two features were built here and withdrawn, for the same reason and by the
/// same ruling. First a `pushd`/`popd` stack, which produced a silent-ALLOW
/// regression in two consecutive review rounds. Then the **prefix layer** —
/// a list of words (`command`, `builtin`, `eval`, `time`) judged to keep a
/// following builtin in this shell — which produced three more.
///
/// The prefix layer failed because the question it asked has no name-shaped
/// answer. Whether a word keeps the command in the current shell depends on the
/// exact spelling *and* on which shell is running:
///
/// | form | zsh 5.9 | bash 5.3 | bash 3.2 |
/// |---|---|---|---|
/// | `command cd <dir>` | **stays** | moves | moves |
/// | `pushd <dir> -n` | **stays** | **stays** | moves |
/// | `/usr/bin/cd <dir>` | stays | stays | stays |
///
/// `command` forces an *external* lookup in zsh, so it reaches `/usr/bin/cd` —
/// a `#!/bin/sh` wrapper that runs `builtin cd` in a child, where the parent
/// never moves. Every round of enumeration answered the question for one shell
/// and was wrong in another.
///
/// So the question is no longer asked. What is modeled is only what every shell
/// agrees on: a bare `cd`/`pushd` (after assignment words, backslash-stripped),
/// and a leading `pushd -n`, which stays everywhere. Anything reached through a
/// prefix, spelled as a path, or carrying an option the shells disagree about is
/// **unknown** — which asks, and can never carry a stale directory forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryVerb {
    /// `cd` — moves to a directory named in the arguments.
    Cd,
    /// `pushd` — moves, or stays under a leading `-n`.
    PushDirectory,
    /// `popd` — returns to a stack entry this parser does not model.
    PopDirectory,
    /// A directory verb reached through a prefix whose in-shell behavior is
    /// shell-dependent. The shell may or may not have moved, and *either*
    /// assumption is wrong in some shell, so the position is unknown.
    Unmodeled,
}
use DirectoryVerb::{Cd, PopDirectory, PushDirectory, Unmodeled};

/// Words that may stand in front of a directory verb and change whether it runs
/// in this shell. Membership does not assert that they preserve the shell — it
/// asserts the opposite, that the answer is not knowable from the name, so the
/// position must be treated as unknown.
const SHELL_WORD_PREFIXES: &[&str] = &["command", "builtin", "eval", "time"];

/// The directory-verb name a token spells, with a leading `\` stripped and
/// **nothing else**.
///
/// Never `basename`. A path-spelled `/usr/bin/cd` or `./cd` is a *program*, not
/// the builtin — macOS really ships `/usr/bin/cd` as a `#!/bin/sh` wrapper that
/// runs `builtin cd` in a child, so no shell's parent moves for it. Matching it
/// by basename modeled a move that never happens in any shell.
fn directory_verb_word(token: &str) -> &str {
    token.trim_start_matches('\\')
}

/// Does the token run starting at `idx` eventually name a directory verb, after
/// any further prefixes and assignment words?
fn names_a_directory_verb(tokens: &[String], mut idx: usize) -> bool {
    while let Some(tok) = tokens.get(idx) {
        let word = directory_verb_word(tok);
        if is_assignment_word(tok) || SHELL_WORD_PREFIXES.contains(&word) {
            idx += 1;
        } else {
            return matches!(word, "cd" | "pushd" | "popd");
        }
    }
    false
}

/// The directory-changing verb this segment starts with, plus the index of its
/// first argument. `None` when the segment does not change the directory.
///
/// Assignment words are stepped over because that much *is* shell-independent:
/// every shell treats a leading `NAME=value` as an environment prefix and none
/// of them changes what the following word is.
fn directory_change(tokens: &[String]) -> Option<(DirectoryVerb, usize)> {
    let mut idx = 0;
    while tokens.get(idx).is_some_and(|t| is_assignment_word(t)) {
        idx += 1;
    }
    let word = directory_verb_word(tokens.get(idx)?);
    match word {
        "cd" => Some((Cd, idx + 1)),
        "pushd" => Some((PushDirectory, idx + 1)),
        "popd" => Some((PopDirectory, idx + 1)),
        w if SHELL_WORD_PREFIXES.contains(&w) && names_a_directory_verb(tokens, idx + 1) => {
            Some((Unmodeled, idx + 1))
        }
        _ => None,
    }
}

/// Does `flag` (in separate-token form) consume the following token as a value
/// for `verb`? Prevents a `shred -n 3` iteration count or a `truncate -s 0`
/// size from being misread as a path operand (which would resolve to a bogus
/// relative path and force a needless ASK). Glued (`-s0`) and `=`-joined
/// (`--size=0`) forms carry their value in one `-`-prefixed token and are
/// skipped as flags without this table. `rm`/`unlink` have no value flags.
fn takes_value(verb: &str, flag: &str) -> bool {
    match verb {
        "shred" => matches!(
            flag,
            "-n" | "--iterations" | "-s" | "--size" | "--random-source"
        ),
        "truncate" => matches!(flag, "-s" | "--size" | "-r" | "--reference"),
        _ => false,
    }
}

/// Does this invocation recurse? `rm` only — recursion is meaningless for
/// `unlink`/`shred`/`truncate`, which never descend into directories. True when
/// a short-flag cluster carries `r`/`R` (`-rf`, `-fr`) or a `--recursive` long
/// flag (or any unambiguous abbreviation of it) appears before a `--` operand
/// terminator.
fn rm_is_recursive(argv: &[String], verb: &str) -> bool {
    verb == "rm" && rm_has_flag(argv, &['r', 'R'], "recursive")
}

/// Does this `rm` carry `-d`/`--dir`, which removes an EMPTY directory without
/// `-r`? The single-file class rests on "without `-r` the shell refuses to
/// remove a directory", and this is the one flag that makes that false.
fn rm_removes_dir(argv: &[String]) -> bool {
    rm_has_flag(argv, &['d'], "dir")
}

/// Does `argv` carry a flag, in either the short-cluster form (`-rf` carrying
/// any of `shorts`) or a long form abbreviating `long`?
///
/// One implementation for both flags guard-rm cares about, because the fiddly
/// parts are identical and easy to get subtly different: the `--` operand
/// terminator must stop the scan, and GNU coreutils accepts any unambiguous
/// long-option abbreviation — `--r`, `--rec`, `--recu` all mean `--recursive`.
/// `--recursivex` is not a prefix and does not match; a bare `--` carries an
/// empty prefix and is the terminator handled above.
fn rm_has_flag(argv: &[String], shorts: &[char], long: &str) -> bool {
    for tok in argv.iter().skip(1) {
        if tok == "--" {
            break; // operands only after this
        }
        if let Some(rest) = tok.strip_prefix("--") {
            if !rest.is_empty() && long.starts_with(rest) {
                return true;
            }
            continue; // a long flag that abbreviates something else
        }
        // A short-flag cluster (`-rf`); the leading `-` is not a `--` long flag.
        if tok.starts_with('-') && tok.chars().any(|c| shorts.contains(&c)) {
            return true;
        }
    }
    false
}

/// Classification of a single resolved deletion target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetClass {
    /// Under a temp root. ALLOW.
    Temp,
    /// Strictly *under* a `.claude/` session-scratch directory (one worktree,
    /// one session intro). ALLOW. Neither the `.claude` dir nor a scratch dir
    /// itself is here — deleting either wholesale is not the transient-scratch
    /// case this ALLOW exists for, so both fall through to the block/ask rules,
    /// as does every durable `.claude` subtree (transcripts, metrics, skills,
    /// memory).
    ClaudeScratch,
    /// A transient scratch/editor-swap file directly under home whose name ends
    /// in a recognized ephemeral suffix (`.tmp`/`.swp`/`.swo`). ALLOW — deleting
    /// these is routine cleanup, not the destructive home-child case.
    Scratch,
    /// The filesystem root `/`. BLOCK.
    Root,
    /// The user's home directory itself. BLOCK.
    Home,
    /// A first-level entry directly under home (`~/Documents`, `~/.zshrc`). BLOCK.
    HomeChild,
    /// Inside the Obsidian vault. BLOCK.
    Vault,
    /// A git repo root (has a `.git` child), or any path with a `.git`
    /// component. BLOCK.
    GitRepo,
    /// Durable state under a `.claude/` directory — transcripts, the metrics
    /// audit trail, skills, rules, both memory trees. ASK, and deliberately a
    /// class of its own rather than [`Unknown`](TargetClass::Unknown): the
    /// single-file softening lifts `Unknown` to ALLOW, and one session
    /// transcript is still the only copy of that transcript.
    ClaudeState,
    /// Unexpanded variable, command substitution, or a `..`-bearing path that
    /// cannot be confidently resolved. ASK.
    Unresolvable,
    /// The genuine ambiguous middle. ASK (default).
    Unknown,
}

impl TargetClass {
    fn outcome(self) -> Outcome {
        match self {
            TargetClass::Temp | TargetClass::ClaudeScratch | TargetClass::Scratch => Outcome::Allow,
            TargetClass::Root
            | TargetClass::Home
            | TargetClass::HomeChild
            | TargetClass::Vault
            | TargetClass::GitRepo => Outcome::Block,
            TargetClass::ClaudeState | TargetClass::Unresolvable | TargetClass::Unknown => {
                Outcome::Ask
            }
        }
    }
}

/// Resolved environment context, injected so the decision core stays pure and
/// table-testable (no env reads, no I/O beyond the injected git-root probe and
/// `path_under_temp_root`'s tmpdir canonicalization).
struct RmContext<'a> {
    /// Home directory, normalized (no trailing slash).
    home: &'a str,
    /// Obsidian vault root, normalized, when `OBSIDIAN_VAULT` is set non-empty.
    vault: Option<&'a str>,
    /// `$TMPDIR`, for the temp-root check.
    tmpdir: Option<&'a str>,
}

/// A deletion target extracted from the command, before classification.
enum TargetToken {
    /// A path resolved against the effective cwd (a shell path string).
    Path(String),
    /// A file-scoped glob (`*.tgz`, `homebridge-*.tgz`) that names artifacts
    /// *within* `dir` rather than the directory itself. `recursive` records
    /// whether the invocation carried `-r`/`-R` — a recursive sweep is judged
    /// more conservatively than a flat one.
    FileGlob { dir: String, recursive: bool },
    /// A non-recursive `rm`/`unlink` naming one concrete path — no glob, so
    /// exactly one filesystem entry. Without `-r` the shell **refuses** to
    /// remove a directory, so this can only ever delete a single file; that is
    /// a shell guarantee, not a filesystem probe, and costs no I/O.
    ///
    /// Judged one step softer than [`Path`](TargetToken::Path), and only in the
    /// ambiguous middle. Every protected class still blocks, and durable
    /// `.claude` state has its own class precisely so it is not swept in here.
    SingleFile(String),
    /// An operand that could not be resolved (unexpanded var / substitution /
    /// `..`-bearing / brace list). Always ASK.
    Unresolvable,
}

/// Walk one script's segments, collecting every rm-family deletion target,
/// tracking the effective cwd across `cd`s and recursing into child scripts —
/// a direct mirror of `enforce_worktree::collect_commit_targets` (issue #228).
fn collect_targets(
    script: &str,
    cwd: &str,
    cwd_known: bool,
    depth: usize,
    out: &mut Vec<TargetToken>,
) {
    let mut effective_dir = cwd.to_string();
    // False once a `cd` moves somewhere this parser cannot name. A relative
    // target after that resolves against a directory the shell has already
    // left, so it must not carry the old directory's verdict.
    let mut dir_known = cwd_known;

    for (segment, _next_op) in split_segments_with_ops(script) {
        let segment = strip_group_wrappers(&segment);
        let tokens = tokenize(segment);
        let argv = skip_transparent_prefixes(&tokens);

        // Child scripts execute with the directory in effect HERE, in their own
        // scope: a wrapper inherits the accumulated cwd, a substitution runs
        // before its own segment. Recurse rather than flatten so a child's `cd`
        // never leaks back into this script's tracking.
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, segment) {
                collect_targets(&child, &effective_dir, dir_known, depth + 1, out);
            }
        }

        // Directory tracking — assume success (equal-precedence `&&`/`||`,
        // left-assoc), skip the verb's own flags, and treat a bare `-`, a
        // `$VAR`, or a missing target as unresolvable. Mirrors
        // `collect_commit_targets`.
        if let Some((verb, arg_start)) = directory_change(&tokens) {
            // `popd` returns to an entry this parser does not model, and an
            // `Unmodeled` verb was reached through a prefix whose behavior
            // differs between shells. Both mark the position unknown, which
            // asks — it can never carry a stale directory forward.
            if verb == PopDirectory || verb == Unmodeled {
                dir_known = false;
                continue;
            }

            let mut idx = arg_start;

            if verb == PushDirectory {
                let args = tokens.get(idx..).unwrap_or_default();
                // A LEADING `-n` suppresses the move in every shell, so the
                // directory is genuinely unchanged.
                if args.first().is_some_and(|a| a == "-n") {
                    continue;
                }
                // A `-n` anywhere else is where the shells part company:
                // `pushd <dir> -n` stays under zsh and bash 5, and moves under
                // bash 3.2. Unknown rather than guessed.
                if args.iter().any(|a| a == "-n") {
                    dir_known = false;
                    continue;
                }
                // A rotation, a `--`, or any other option: unmodeled.
                if args
                    .first()
                    .is_some_and(|a| a.starts_with('-') || a.starts_with('+'))
                {
                    dir_known = false;
                    continue;
                }
            }

            // `cd`'s own flags (`-L`, `-P`, `--`) carry no directory meaning, so
            // they are plain noise. A bare `-` is cd's previous-directory
            // operand, not a flag.
            if verb == Cd {
                while tokens
                    .get(idx)
                    .is_some_and(|t| t == "--" || (t.starts_with('-') && t != "-"))
                {
                    idx += 1;
                }
            }

            // A bare `-`, a missing target (including a bare `pushd`), or an
            // unexpanded variable makes the new directory UNKNOWN. Keeping the
            // pre-cd directory was a silent ALLOW: `cd $HOME; rm -rf Documents`
            // from a `/tmp` cwd resolved `Documents` under `/tmp` and allowed a
            // delete of `~/Documents`.
            match tokens.get(idx) {
                Some(target) if target != "-" && !target.starts_with('$') => {
                    effective_dir = resolve_cd_target(target, &effective_dir);
                }
                _ => dir_known = false,
            }
            continue;
        }

        // `skip_transparent_prefixes` stops at a prefix whose NEXT token is an
        // option (`env -i`, `env -u FOO`, `nice -n 10`), so `argv` still leads
        // with the prefix, the delete verb behind it is never seen, and an empty
        // target list reads as "not a deletion" — a silent ALLOW on a recursive
        // delete of a protected path (#426).
        //
        // Fixed guard_rm-locally rather than in the shared primitive: that one
        // is also `enforce_worktree`'s and carries its own adversarial-review
        // history, where the same clause is a deliberate, documented miss whose
        // cost is only a missed commit block.
        //
        // Unresolvable, not a parse of what follows: each prefix has its own
        // flag grammar (`env -u` and `nice -n` take a value, `env -i` does not),
        // and guessing wrong would skip past the delete verb itself. Gated on a
        // delete verb actually appearing, so `env -i ls` stays silent.
        // `eval` joins the prefix set here: it is in neither `TRANSPARENT` nor
        // the shell-preserving list, so `eval rm -rf ~/Documents` matched no
        // delete verb in command position and collected nothing — the same
        // silent ALLOW, and an explicit row in #426's table.
        if argv.first().is_some_and(|first| {
            let word = command_word(first);
            TRANSPARENT.contains(&word) || word == "eval"
        }) && tokens.iter().any(|t| is_delete_verb(t))
        {
            out.push(TargetToken::Unresolvable);
            continue;
        }

        let Some(first) = argv.first() else { continue };
        let verb = command_word(first);
        if DELETE_VERBS.contains(&verb) {
            let recursive = rm_is_recursive(argv, verb);
            let operands = delete_operands(argv, verb);
            // A recursive delete with no operand in the command text still
            // deletes something — the target reaches the shell by a route this
            // parser cannot see. An empty target list used to judge as ALLOW
            // ("not ours"), which turned an unreadable `rm -rf` into a silent
            // approval. A non-recursive `rm -f` and a `rm --help` carry no
            // recursion flag and stay out of this.
            if recursive && operands.is_empty() {
                out.push(TargetToken::Unresolvable);
            }
            // Without `-r`, `rm` and `unlink` cannot remove a directory — the
            // shell refuses. `rm -d`/`--dir` is the exception: it removes an
            // EMPTY directory without `-r`, so it is excluded rather than left
            // to falsify the premise.
            let single_file =
                !recursive && matches!(verb, "rm" | "unlink") && !rm_removes_dir(argv);
            for operand in operands {
                out.push(resolve_target(
                    &operand,
                    &effective_dir,
                    dir_known,
                    recursive,
                    single_file,
                ));
            }
        } else if verb == "xargs" && xargs_runs_delete(argv) {
            // `… | xargs rm -rf` takes its targets from stdin, so there is no
            // path in the command to classify. Emitting one Unresolvable defers
            // to the user; the previous behaviour — no targets at all — judged
            // as ALLOW and silently approved a recursive delete of whatever the
            // upstream stage produced.
            out.push(TargetToken::Unresolvable);
        } else if verb == "find" && find_is_destructive(argv) {
            // A `find` that deletes — via `-delete`/`-exec`/`-ok` running a
            // delete verb — targets its search roots. When the roots can't be
            // confidently identified (no explicit path, or an unrecognized
            // leading option that might have dropped one), one Unresolvable
            // target → ASK, rather than a silent cwd default.
            match find_roots(argv) {
                FindTargets::Paths(roots) => {
                    for root in roots {
                        // A destructive `find` recurses by nature — treat its
                        // roots conservatively (recursive = true).
                        out.push(resolve_target(
                            &root,
                            &effective_dir,
                            dir_known,
                            true,
                            false,
                        ));
                    }
                }
                FindTargets::Unresolvable => out.push(TargetToken::Unresolvable),
            }
        }
    }
}

/// The command `xargs` will run is a delete verb (`… | xargs rm -rf`).
///
/// Deliberately coarse — any token whose basename is a delete verb counts,
/// rather than parsing `xargs`'s own option grammar to locate the command word.
/// The precise version carries a real miss: a separate-token long option
/// (`xargs --max-args 3 rm -rf`) leaves its value exactly where the command word
/// is expected, so the scan stops on `3` and never sees the `rm`. A miss here is
/// a silent recursive delete; the cost of over-matching is one extra prompt on a
/// command that merely mentions a delete verb. Every outcome of this predicate
/// feeds an ASK, never an ALLOW, so it cannot open a hole in either direction.
fn xargs_runs_delete(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|tok| is_delete_verb(tok))
}

/// A `find` invocation that deletes: it carries `-delete`, or an
/// `-exec`/`-execdir`/`-ok`/`-okdir` whose command is a delete verb
/// (`find … -exec rm …`). The command word is scanned up to its `;`/`+`
/// terminator, so `-exec /bin/rm …`, `-exec env rm …`, and `-exec \rm …` are
/// caught. `-exec sh -c '…'` hides the delete inside the wrapper script — a
/// documented miss.
fn find_is_destructive(argv: &[String]) -> bool {
    if argv.iter().any(|t| t == "-delete") {
        return true;
    }
    let mut after_exec = false;
    for tok in argv.iter().skip(1) {
        match tok.as_str() {
            "-exec" | "-execdir" | "-ok" | "-okdir" => after_exec = true,
            ";" | "\\;" | "+" => after_exec = false,
            other if after_exec && is_delete_verb(other) => return true,
            _ => {}
        }
    }
    false
}

/// Path operands of an `rm`/`unlink`/`shred`/`truncate` invocation: non-flag
/// tokens after the verb, honoring `--` (everything after is a path) and each
/// verb's value-taking flags.
fn delete_operands(argv: &[String], verb: &str) -> Vec<String> {
    let mut operands = Vec::new();
    let mut i = 1;
    let mut after_dd = false;
    while i < argv.len() {
        let tok = &argv[i];
        if !after_dd {
            if tok == "--" {
                after_dd = true;
                i += 1;
                continue;
            }
            // A flag is `-`-prefixed and longer than a bare `-`.
            if tok.starts_with('-') && tok.len() > 1 {
                i += if takes_value(verb, tok) { 2 } else { 1 };
                continue;
            }
        }
        operands.push(tok.clone());
        i += 1;
    }
    operands
}

/// The search-root resolution of a destructive `find`.
enum FindTargets {
    /// Explicit path arguments to classify.
    Paths(Vec<String>),
    /// The roots can't be confidently identified → ASK. Two cases collapse here:
    /// no explicit path (the target is the implicit cwd, but a leading option we
    /// failed to recognize could equally have dropped a real root), and a
    /// leading `-`-token that isn't a known global option.
    Unresolvable,
}

/// Search roots of a `find` invocation: the path arguments between the global
/// options and the first expression token (`-name`, `-delete`, `(`, `!`, …).
///
/// `find`'s global options precede the paths and also start with `-`, so a
/// naive "break on the first `-`" drops the real root on `find -L <path>
/// -delete` and silently defaults it to the cwd — from a `.claude`/`tmp` cwd
/// that is a silent ALLOW of a protected delete. The known GNU ∪ BSD global
/// options are skipped (`-H`/`-L`/`-P`/`-E`/`-X`/`-d`/`-s`/`-x` boolean; `-D`/
/// `-O` valued, separate or glued). Rather than enumerate every `find` variant
/// (fragile — a missed option re-opens the hole), anything else is treated
/// conservatively: **no explicit path found → `Unresolvable` (ASK)**, never a
/// silent cwd default. `-f <path>` (BSD, *adds* a search root) also routes to
/// `Unresolvable` — its value is a real target this simple pass won't fold in.
fn find_roots(argv: &[String]) -> FindTargets {
    const GLOBAL_BOOL: &[&str] = &["-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x"];
    let mut i = 1;
    while let Some(tok) = argv.get(i) {
        let t = tok.as_str();
        if GLOBAL_BOOL.contains(&t) {
            i += 1;
        } else if t == "-D" || t == "-O" {
            i += 2; // separate-token value
        } else if t.starts_with("-D") || t.starts_with("-O") {
            i += 1; // glued value (`-O2`, `-Dtree`)
        } else {
            break;
        }
    }
    // At the first non-global token. A dash here means no explicit path was
    // given (expression start) OR an unrecognized/`-f` option — either way we
    // can't safely name the root, so ASK.
    match argv.get(i) {
        Some(tok) if !(tok.starts_with('-') || tok == "(" || tok == "!") => {
            let mut roots = Vec::new();
            while let Some(tok) = argv.get(i) {
                if tok.starts_with('-') || tok == "(" || tok == "!" {
                    break;
                }
                roots.push(tok.clone());
                i += 1;
            }
            FindTargets::Paths(roots)
        }
        _ => FindTargets::Unresolvable,
    }
}

/// Resolve one operand against the effective cwd, or mark it unresolvable.
/// `recursive` records whether the invocation carried `-r`/`-R`; it rides along
/// on a [`TargetToken::FileGlob`] so the judge can soften a flat artifact sweep
/// but not a recursive one.
fn resolve_target(
    operand: &str,
    effective_dir: &str,
    dir_known: bool,
    recursive: bool,
    single_file: bool,
) -> TargetToken {
    // Unexpanded variable / command substitution — can't prove anything. This
    // guard (with the `..` checks below) runs AHEAD of glob detection, so an
    // unresolvable operand never masquerades as a clean file-scoped sweep.
    if operand.contains('$') || operand.contains('`') {
        return TargetToken::Unresolvable;
    }
    // Brace expansion turns ONE token into many targets, and this parser has no
    // way to enumerate them. `rm -f ~/{Documents/notes,.zshrc}` reads as a
    // single glob-free path whose first alternative escapes its protected class
    // — which the single-file rule below would then soften to a silent ALLOW
    // while bash deleted both entries. Treat any brace-bearing operand as
    // unresolvable, the same posture `$` gets.
    if operand.contains('{') || operand.contains('}') {
        return TargetToken::Unresolvable;
    }
    // A `..` ANYWHERE in the operand, checked against the WHOLE token before it
    // is reduced to a literal prefix. The reduction below truncates at the
    // first `*`/`?`/`[`, so checking only the prefix let every `..` *behind* a
    // metachar sail past: `rm -rf /private/tmp/*/../../..` expands — for every
    // match — to `/`, and classified as a clean glob under `/private/tmp` it
    // was a silent ALLOW (#427).
    //
    // Same reasoning as the brace check above: one token naming a path this
    // parser cannot enumerate. The brace guard sat three lines above the very
    // truncation that defeated it for globs.
    if has_parent_segment(operand) {
        return TargetToken::Unresolvable;
    }
    // Reduce a glob to the literal directory it lives in: `rm -rf /tmp/x/*`
    // classifies `/tmp/x`, `rm -rf *` classifies the cwd, `rm -rf /*`
    // classifies `/`.
    let literal = glob_literal_prefix(operand);
    // A relative target only means something against a known directory. After a
    // `cd` this parser could not follow, the shell is somewhere else entirely,
    // so carrying the stale directory's verdict would describe the wrong path.
    // A `~`-anchored path is not relative — it resolves to home wherever the
    // shell stands — so gating it here would only lose a BLOCK.
    if !dir_known && !looks_absolute(literal) && !literal.starts_with('~') {
        return TargetToken::Unresolvable;
    }
    // A bare glob-less cwd reference (`*` → "", or a literal `.`) is the
    // effective directory itself.
    let resolved = if literal.is_empty() || literal == "." {
        effective_dir.to_string()
    } else if looks_absolute(literal) {
        // Absolute — POSIX `/…` or a Windows drive path `C:/…`. Use as-is;
        // `resolve_cd_target` only recognizes leading `/` (and `~`), so a drive
        // path would otherwise be joined onto the cwd and misclassified.
        literal.to_string()
    } else {
        resolve_cd_target(literal, effective_dir)
    };
    // The effective dir itself may carry a `..` from a `cd ..` — still ambiguous.
    if has_parent_segment(&resolved) {
        return TargetToken::Unresolvable;
    }
    // A file-scoped glob (`*.tgz`) names artifacts within `resolved`, not the
    // directory itself. Emit a FileGlob so the judge classifies the DIR and can
    // soften a git-repo artifact sweep. A bare `*`/`.*` is NOT file-scoped — it
    // means "everything here", so it stays a Path carrying the dir's verdict.
    if is_file_scoped_glob(operand) {
        return TargetToken::FileGlob {
            dir: resolved,
            recursive,
        };
    }
    // A glob-free operand under a non-recursive `rm`/`unlink` names exactly one
    // entry, and the shell will not let that entry be a directory. The
    // glob-metachar check is what keeps `rm *` out: that resolves to the
    // *directory* the sweep runs in, which is emphatically not one file.
    if single_file && !operand.contains(['*', '?', '[']) {
        return TargetToken::SingleFile(resolved);
    }
    TargetToken::Path(resolved)
}

/// True when `operand`'s final path segment is a glob that scopes to files
/// *within* a directory rather than naming the directory itself: it contains a
/// glob metachar (`*`/`?`/`[`), does NOT start with `.` (so `.*` — which matches
/// dotfiles like `.git`/`.env` — is excluded), and is not composed solely of
/// `*`/`?` (a bare `*` means "everything in this dir", not an artifact pattern).
fn is_file_scoped_glob(operand: &str) -> bool {
    let last = operand.rsplit('/').next().unwrap_or(operand);
    if !last.contains(['*', '?', '[']) || last.starts_with('.') {
        return false;
    }
    !last.chars().all(|c| c == '*' || c == '?')
}

/// The literal directory prefix of a (possibly globbed) operand: everything up
/// to the last `/` before the first glob metachar. A glob in the first segment
/// yields `""` (the cwd); a leading-`/` glob (`/*`) yields `/` (the root).
///
/// `[` is treated as a glob metachar unconditionally, though it is also a legal
/// filename character — so a literal `~/Documents/file[1].txt` reduces to
/// `~/Documents` and classifies as the exact home child (Block) rather than the
/// deeper ambiguous path (Ask). The error direction is always *more* restrictive
/// (Block/Ask, never a silent Allow), so it is safe, if occasionally strict.
fn glob_literal_prefix(operand: &str) -> &str {
    let Some(pos) = operand.find(['*', '?', '[']) else {
        return operand;
    };
    match operand[..pos].rfind('/') {
        Some(0) => "/",
        Some(slash) => &operand[..slash],
        None => "",
    }
}

/// True when any `/`-separated segment of `path` is exactly `..`.
fn has_parent_segment(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}

/// True when `norm`'s final path segment ends in a recognized transient suffix
/// (`.tmp`, `.swp`, `.swo`) — an editor swap file or a temp-write artifact.
/// `.bak`/`.orig`/`.old` are deliberately excluded: those can be intentional
/// backups a user means to keep, so they stay BLOCK under home.
fn is_transient_scratch(norm: &str) -> bool {
    let last = norm.rsplit('/').next().unwrap_or(norm);
    last.ends_with(".tmp") || last.ends_with(".swp") || last.ends_with(".swo")
}

/// Classify a resolved target path into guard-rm's [`TargetClass`].
///
/// Delegates the shared path facts to [`pathclass::classify`] — temp,
/// `.claude`-managed, git-root, and home-child — and layers guard-rm's own
/// root / home / vault policy on top. Those three stay guard-local: they have
/// only this one consumer today, so promoting them to the shared classifier
/// would couple without real reuse (cadence-hooks#164 D5). `is_git_root` is
/// injected (the wrapper stats `<target>/.git`; tests stub it) so this stays
/// pure.
///
/// Order is load-bearing: ALLOW rules run **before** BLOCK rules, so a scratch
/// target under a protected ancestor — a git worktree under `.claude`, a repo
/// checked out in `/tmp` — is ALLOW, not blocked as a git repo. guard-rm's
/// root/home checks sit ahead of the shared home-child, and vault ahead of the
/// shared git-root, preserving the prototype's exact precedence (and thus its
/// BLOCK-message wording). A `pathclass` `DocsPlans`/`Source` fact (no guard-rm
/// consumer) falls through to the ambiguous [`TargetClass::Unknown`] default.
fn classify_path(path: &str, ctx: &RmContext, is_git_root: &dyn Fn(&str) -> bool) -> TargetClass {
    let norm = pathclass::normalize(path);
    let pc_ctx = PathClassContext {
        home: ctx.home,
        tmpdir: ctx.tmpdir,
    };
    let shared = pathclass::classify(&norm, &pc_ctx, is_git_root);

    // ALLOW rules first — the shared classifier owns Temp and ClaudeScratch.
    match shared {
        PathClass::Temp => return TargetClass::Temp,
        PathClass::ClaudeScratch => return TargetClass::ClaudeScratch,
        _ => {}
    }

    // BLOCK rules. `normalize_path("/")` == "" (trailing slash trimmed), so an
    // empty norm IS the root — guard-rm's root/home outrank the shared home-child.
    if norm.is_empty() || norm == "/" {
        return TargetClass::Root;
    }
    if norm == ctx.home {
        return TargetClass::Home;
    }
    if shared == PathClass::HomeChild {
        // A transient scratch/swap file under home (`~/.claude.json.tmp`,
        // `~/.foo.swp`) is routine cleanup, not the destructive home-child case.
        if is_transient_scratch(&norm) {
            return TargetClass::Scratch;
        }
        return TargetClass::HomeChild;
    }
    // Vault is guard-rm-local (deferred from pathclass v1); checked ahead of the
    // shared git-root so a vault that is also a repo reports the vault.
    if let Some(vault) = ctx.vault
        && (norm == vault || norm.starts_with(&format!("{vault}/")))
    {
        return TargetClass::Vault;
    }
    if shared == PathClass::GitRoot {
        return TargetClass::GitRepo;
    }
    if shared == PathClass::ClaudeState {
        return TargetClass::ClaudeState;
    }

    TargetClass::Unknown
}

/// The decision core: collect targets, classify each, and keep the most severe
/// verdict (Block > Ask > Allow). Pure — env and the git-root probe are
/// injected.
fn judge_rm(
    command: &str,
    cwd: &str,
    ctx: &RmContext,
    is_git_root: &dyn Fn(&str) -> bool,
) -> CheckResult {
    let mut targets = Vec::new();
    collect_targets(command, cwd, true, 0, &mut targets);
    if targets.is_empty() {
        // Not a deletion at all — no delete verb, or one that removes nothing
        // (`rm --help`, a non-recursive `rm -f` with no operand). A *recursive*
        // delete with no readable operand does NOT land here: `collect_targets`
        // emits an Unresolvable for it, so it asks rather than falling through.
        return CheckResult::allow();
    }

    let mut worst = Outcome::Allow;
    let mut block_class: Option<TargetClass> = None;
    for target in &targets {
        let class = match target {
            TargetToken::Unresolvable => TargetClass::Unresolvable,
            TargetToken::Path(p) => classify_path(p, ctx, is_git_root),
            // One file, no recursion. Only the ambiguous middle softens: every
            // protected class keeps blocking, and `ClaudeState` is a separate
            // class precisely so it is not swept in here — a lone transcript is
            // still the only copy of that transcript.
            TargetToken::SingleFile(p) => match classify_path(p, ctx, is_git_root) {
                TargetClass::Unknown => TargetClass::Scratch,
                other => other,
            },
            TargetToken::FileGlob { dir, recursive } => {
                match classify_path(dir, ctx, is_git_root) {
                    // A flat artifact sweep in a git repo (`rm *.tgz`) is routine
                    // cleanup — soften to Scratch (Allow). A recursive one
                    // (`rm -rf project-*`) could dredge tracked directories → Ask.
                    TargetClass::GitRepo if !*recursive => TargetClass::Scratch,
                    TargetClass::GitRepo => TargetClass::Unknown,
                    // Every other dir class keeps its own verdict: Temp Allow,
                    // Home/HomeChild/Vault/Root Block, Unknown Ask.
                    other => other,
                }
            }
        };
        let outcome = class.outcome();
        // Remember the FIRST block-classified target only for message wording.
        // The choice is arbitrary, not an ordering — every BLOCK `TargetClass`
        // shares one `Outcome::Block`, so which one names the message doesn't
        // change the verdict.
        if outcome == Outcome::Block && block_class.is_none() {
            block_class = Some(class);
        }
        worst = worst.merge(outcome);
    }

    match worst {
        Outcome::Block => {
            CheckResult::block(block_message(block_class.unwrap_or(TargetClass::Unknown)))
        }
        Outcome::Ask => CheckResult::ask(ASK_MESSAGE),
        // Allow (and the impossible Nudge/LoopBlock) → defer to normal flow.
        _ => CheckResult::allow(),
    }
}

/// The ASK reason shown in the permission prompt.
const ASK_MESSAGE: &str = "guard-rm: this delete target could not be proven safe (an unexpanded variable, \
     a command substitution, or a path outside recognized temp/scratch roots). \
     Confirm the deletion, or opt out with CADENCE_DISABLE=guard-rm.";

/// The BLOCK message: names the protected location and every escape hatch.
fn block_message(class: TargetClass) -> String {
    let what = match class {
        TargetClass::Root => "the filesystem root `/`",
        TargetClass::Home => "your home directory",
        TargetClass::HomeChild => "a top-level entry in your home directory",
        TargetClass::Vault => "your Obsidian vault",
        TargetClass::GitRepo => "a git repository (a `.git` lives here)",
        _ => "a protected location",
    };
    format!(
        "🚫 guard-rm: this deletes {what}, which is almost never intended.\n   \
         To keep the file but get it out of the way, move it to the trash — \
         guard-rm never fires on `mv`:\n   \
         • mv <target> ~/.Trash\n   \
         If you truly mean to delete, opt out via Claude Code's own environment. \
         A command-line prefix (`CADENCE_DISABLE=guard-rm rm …`) has NO effect: \
         the hook reads its own environment, never the command string. Set one of \
         these in the `env` block of .claude/settings.json, or export it before \
         launching Claude Code:\n   \
         • CADENCE_DISABLE=guard-rm — opt this guard out (persists in settings)\n   \
         • CADENCE_BYPASS=1 — bypass all cadence enforcement for one session"
    )
}

/// Path-aware triage of `rm`-family delete commands.
pub struct GuardRm;

impl Check for GuardRm {
    fn name(&self) -> &str {
        "guard-rm"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let home = normalize_path(&cadence_hooks_core::paths::user_home_lossy_or_default());
        let vault = std::env::var("OBSIDIAN_VAULT")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| normalize_path(&v));
        let tmpdir = std::env::var("TMPDIR").ok();
        let cwd = input.cwd.as_deref().unwrap_or("/");
        let ctx = RmContext {
            home: &home,
            vault: vault.as_deref(),
            tmpdir: tmpdir.as_deref(),
        };
        judge_rm(command, cwd, &ctx, &is_git_root_on_disk)
    }
}

/// Real git-root probe: `<target>/.git` exists (a repo root, or a linked
/// worktree whose `.git` is a *file*). One `stat` per target — no subprocess.
fn is_git_root_on_disk(target: &str) -> bool {
    !target.is_empty() && Path::new(target).join(".git").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    /// The process home — the SAME value `resolve_cd_target` expands `~` to, so
    /// injected context and `~`-expansion agree (as they do in production, where
    /// both read `user_home_lossy_or_default`). Home-relative test cases use `~`
    /// rather than a hard-coded path so they hold whatever the runner's HOME is.
    fn home() -> String {
        normalize_path(&cadence_hooks_core::paths::user_home_lossy_or_default())
    }

    /// A vault root independent of home and temp (so no ALLOW rule pre-empts it).
    const VAULT: &str = "/vaults/main";

    /// Judge with the real home, a fixed vault, no tmpdir, and a git-root probe
    /// that returns true only for the exact paths in `git_roots`.
    fn judge_with(command: &str, cwd: &str, git_roots: &[&str]) -> Outcome {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let probe = |p: &str| git_roots.contains(&p);
        judge_rm(command, cwd, &ctx, &probe).outcome
    }

    /// Common case: no git roots on disk.
    fn judge(command: &str, cwd: &str) -> Outcome {
        judge_with(command, cwd, &[])
    }

    // --- #428: directory tracking, after two withdrawals ---

    /// The spellings every shell agrees on. `\cd` bypasses an alias and still
    /// runs the builtin; an assignment prefix is an environment prefix in every
    /// shell and changes nothing about the following word.
    #[test]
    fn shell_independent_cd_spellings_move_the_directory() {
        for command in [
            "cd ~; rm -rf Documents",
            r"\cd ~; rm -rf Documents",
            "FOO=1 cd ~; rm -rf Documents",
            "FOO=1 BAR=2 cd ~; rm -rf Documents",
            "pushd ~; rm -rf Documents",
        ] {
            assert_eq!(
                judge(command, "/private/tmp"),
                Outcome::Block,
                "every shell moves for this: {command}"
            );
        }
    }

    /// THE DIRECTION THAT MATTERS, and the one three review passes had no test
    /// for: home cwd, temp target. If the model invents a move here, a relative
    /// delete resolves under `/private/tmp` and a real `~/Documents` is removed
    /// silently. A false BLOCK in the other direction costs only noise; this
    /// costs the file.
    #[test]
    fn prefixed_directory_verbs_never_invent_a_move() {
        for command in [
            // `command cd` moves under bash and NOT under zsh, which forces an
            // external lookup — so neither answer is safe to assume.
            "command cd /private/tmp; rm -rf Documents",
            r"\command cd /private/tmp; rm -rf Documents",
            "builtin cd /private/tmp; rm -rf Documents",
            "eval cd /private/tmp; rm -rf Documents",
            "time cd /private/tmp; rm -rf Documents",
            "command builtin cd /private/tmp; rm -rf Documents",
            "FOO=1 command cd /private/tmp; rm -rf Documents",
            "command pushd /private/tmp; rm -rf Documents",
            // A trailing `-n`: stays under zsh and bash 5, moves under bash 3.2.
            "pushd /private/tmp -n; rm -rf Documents",
        ] {
            assert_ne!(
                judge(command, &home()),
                Outcome::Allow,
                "must not model a move the shell may not have made: {command}"
            );
        }
    }

    /// A path-spelled directory verb is a PROGRAM, not the builtin. macOS ships
    /// `/usr/bin/cd` as a `#!/bin/sh` wrapper that runs `builtin cd` in a
    /// child, so no shell's parent moves — matching by basename modeled a move
    /// that happens nowhere.
    #[test]
    fn path_spelled_directory_verb_is_not_a_directory_change() {
        for command in [
            "/usr/bin/cd /private/tmp; rm -rf Documents",
            "./cd /private/tmp; rm -rf Documents",
            "x/cd /private/tmp; rm -rf Documents",
            "/usr/bin/pushd /private/tmp; rm -rf Documents",
        ] {
            assert_eq!(
                judge(command, &home()),
                Outcome::Block,
                "the shell never left home: {command}"
            );
        }
    }

    /// A leading `pushd -n` suppresses the move in every shell, so the
    /// directory is genuinely unchanged rather than unknown — this is the one
    /// option the shells agree about.
    #[test]
    fn leading_pushd_dash_n_leaves_the_directory_unchanged() {
        assert_eq!(
            judge("pushd -n /private/tmp; rm -rf Documents", &home()),
            Outcome::Block
        );
        assert_eq!(
            judge(
                "cd ~; pushd -n /private/tmp; rm -rf Documents",
                "/private/tmp"
            ),
            Outcome::Block
        );
    }

    /// Every unmodeled directory form asks rather than guessing, and none of
    /// them can carry a stale directory forward.
    #[test]
    fn unmodeled_directory_forms_ask() {
        for command in [
            "popd; rm -rf build",
            "pushd ~; popd; rm -rf build",
            "pushd; rm -rf build",
            "pushd +1; rm -rf build",
            "pushd -- -n; rm -rf build",
            "command cd ~; rm -rf build",
            "time cd ~; rm -rf build",
        ] {
            assert_eq!(
                judge(command, "/private/tmp"),
                Outcome::Ask,
                "unmodeled move must ask: {command}"
            );
        }
    }

    /// `dir_known` is never restored to true, so a later `cd` cannot launder an
    /// unknown position back into a confident verdict.
    #[test]
    fn unknown_position_is_not_laundered_by_a_later_cd() {
        assert_eq!(
            judge("popd; cd /private/tmp; rm -rf Documents", &home()),
            Outcome::Ask
        );
    }

    // --- #426: a transparent prefix carrying a flag ---

    /// `skip_transparent_prefixes` stops at a prefix whose next token is an
    /// option, so `argv` still led with the prefix, the delete verb behind it
    /// was never seen, and an empty target list read as "not a deletion".
    #[test]
    fn transparent_prefix_with_a_flag_is_unresolvable_not_allowed() {
        for command in [
            "env -i rm -rf ~/Documents",
            "env -u FOO rm -rf ~/Documents",
            "nice -n 10 rm -rf ~/Documents",
            "nohup -x rm -rf ~/Documents",
        ] {
            assert_eq!(
                judge(command, "/private/tmp"),
                Outcome::Ask,
                "a delete behind a flagged prefix must not be a silent allow: {command}"
            );
        }
    }

    /// The unflagged forms still resolve fully, so this stayed a coverage gap
    /// rather than becoming a blanket "prefix means unknown".
    #[test]
    fn unflagged_transparent_prefix_still_resolves() {
        assert_eq!(
            judge("env rm -rf ~/Documents", "/private/tmp"),
            Outcome::Block
        );
        assert_eq!(
            judge("command rm -rf ~/Documents", "/private/tmp"),
            Outcome::Block
        );
    }

    /// Gated on a delete verb actually appearing — otherwise every flagged
    /// prefix in the session would start prompting.
    #[test]
    fn flagged_prefix_without_a_delete_verb_stays_silent() {
        assert_eq!(judge("env -i ls -la", "/private/tmp"), Outcome::Allow);
        assert_eq!(
            judge("nice -n 10 cargo build", "/private/tmp"),
            Outcome::Allow
        );
    }

    // --- #427: a `..` behind a glob metachar ---

    /// `glob_literal_prefix` truncates at the first metachar, so a `..` behind
    /// one was never inspected. Every match of `/private/tmp/*/../../..`
    /// expands to `/`, and it classified as a clean glob under `/private/tmp`.
    #[test]
    fn parent_segment_behind_a_glob_is_unresolvable() {
        assert_eq!(
            judge("rm -rf /private/tmp/*/../../..", "/anywhere"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm -f /private/tmp/*/../../../Users/me/.zshrc", "/anywhere"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm -rf /tmp/[abc]/../../etc", "/anywhere"),
            Outcome::Ask,
            "a bracket class is a metachar too"
        );
    }

    /// The glob-free control still behaves, and an ordinary glob with no `..`
    /// must not start prompting — that would nag on every routine sweep.
    #[test]
    fn ordinary_globs_are_unaffected_by_the_parent_check() {
        assert_eq!(judge("rm -rf /tmp/scratch/*", "/home"), Outcome::Allow);
        assert_eq!(
            judge("rm -rf /private/tmp/build/*", "/home"),
            Outcome::Allow
        );
        // A `..`-looking substring that is not a path segment stays resolvable.
        assert_eq!(judge("rm -rf /tmp/foo..bar/*", "/home"), Outcome::Allow);
    }

    // --- ALLOW: temp roots ---

    #[test]
    fn temp_absolute_allows() {
        assert_eq!(judge("rm -rf /tmp/scratch", "/anywhere"), Outcome::Allow);
        assert_eq!(judge("rm -rf /private/tmp/x", "/anywhere"), Outcome::Allow);
    }

    #[test]
    fn temp_via_cd_chain_allows() {
        assert_eq!(judge("cd /tmp && rm -rf build", "/home"), Outcome::Allow);
    }

    #[test]
    fn temp_glob_allows() {
        assert_eq!(judge("rm -rf /tmp/scratch/*", "/home"), Outcome::Allow);
    }

    #[test]
    fn tmp_lookalike_is_not_temp() {
        // Path::starts_with is component-wise, so `/tmpfoo` is NOT under `/tmp`.
        // Not temp, not protected → the ambiguous middle.
        assert_eq!(judge("rm -rf /tmpfoo/x", "/home"), Outcome::Ask);
    }

    // --- ALLOW: .claude-managed (strictly under) ---

    #[test]
    fn under_claude_worktree_allows() {
        assert_eq!(
            judge("rm -rf /srv/repo/.claude/worktrees/x", "/home"),
            Outcome::Allow
        );
    }

    #[test]
    fn claude_worktree_allows_even_if_git_root() {
        // A worktree's `.git` is a file, so the git-root probe would fire — but
        // the .claude ALLOW is checked first, so worktree cleanup is allowed.
        // Probe returns true for ALL paths to prove the ordering.
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let out = judge_rm(
            "rm -rf /srv/repo/.claude/worktrees/x",
            "/home",
            &ctx,
            &|_| true,
        )
        .outcome;
        assert_eq!(out, Outcome::Allow);
    }

    #[test]
    fn session_intro_allows() {
        assert_eq!(
            judge("rm -f /srv/repo/.claude/intros/2026-01-01-foo.md", "/home"),
            Outcome::Allow
        );
    }

    #[test]
    fn claude_dir_itself_is_not_allowed() {
        // Deleting `~/.claude` whole is not the transient-scratch case — it is a
        // first-level home child → BLOCK, never a silent ALLOW.
        assert_eq!(judge("rm -rf ~/.claude", "/home"), Outcome::Block);
    }

    #[test]
    fn scratch_dir_wholesale_is_not_allowed() {
        // One worktree is disposable; the whole worktrees folder is every
        // worktree at once, uncommitted work included.
        assert_eq!(
            judge("rm -rf /srv/repo/.claude/worktrees", "/home"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm -rf /srv/repo/.claude/intros", "/home"),
            Outcome::Ask
        );
    }

    #[test]
    fn durable_claude_state_asks() {
        // The holes table: every row was a verified SILENT ALLOW before the
        // `.claude` carve-out became an allowlist. None of these paths is
        // git-tracked, so nothing but a filesystem snapshot could restore them.
        for command in [
            "rm -rf ~/.claude/projects",     // every session transcript
            "rm -rf ~/.claude/metrics",      // the guards' own audit trail
            "rm -rf ~/.claude/plugins",      //
            "rm -rf ~/.claude/agent-memory", // accumulated reviewer learnings
            "rm -rf ~/.claude/skills",
            "rm -rf ~/.claude/rules",
            "rm -rf ~/.claude/hooks",
            "rm -rf ~/.claude/sessions",
            "rm -rf /srv/repo/.claude/agent-memory", // same, per-repo
            "rm -rf /srv/repo/.claude/memory",
        ] {
            assert_eq!(judge(command, "/home"), Outcome::Ask, "{command}");
        }
    }

    #[test]
    fn claude_git_dir_blocks() {
        // `rm -rf ~/.claude/.git` (a real chezmoi-migration step) rode the
        // blanket carve-out to a silent ALLOW, masking the git-root fact.
        assert_eq!(judge("rm -rf ~/.claude/.git", "/home"), Outcome::Block);
    }

    // --- BLOCK: root / home / home-child ---

    #[test]
    fn root_blocks() {
        assert_eq!(judge("rm -rf /", "/home"), Outcome::Block);
    }

    #[test]
    fn root_glob_blocks() {
        // `/*` reduces to `/` — must block, not be misread as the cwd.
        assert_eq!(judge("rm -rf /*", "/home"), Outcome::Block);
    }

    #[test]
    fn home_itself_blocks() {
        assert_eq!(judge("rm -rf ~", "/home"), Outcome::Block);
        assert_eq!(
            judge(&format!("rm -rf {}", home()), "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn home_child_blocks() {
        assert_eq!(judge("rm -rf ~/Documents", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf ~/.zshrc", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf ~/Desktop", "/home"), Outcome::Block);
    }

    #[test]
    fn deep_home_path_is_not_child() {
        // Only first-level home entries block; deeper paths fall to the middle.
        assert_eq!(judge("rm -rf ~/Documents/notes", "/home"), Outcome::Ask);
    }

    // --- ALLOW: transient-suffix scratch files directly under home (#316) ---

    #[test]
    fn transient_scratch_under_home_allows() {
        // Editor swaps and temp-write artifacts under home are routine cleanup.
        assert_eq!(judge("rm -f ~/.claude.json.tmp", "/home"), Outcome::Allow);
        assert_eq!(judge("rm -f ~/.foo.swp", "/home"), Outcome::Allow);
    }

    #[test]
    fn non_transient_home_child_still_blocks() {
        assert_eq!(judge("rm -rf ~/.zshrc", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf ~/Documents", "/home"), Outcome::Block);
        // `.bak` is a deliberate exclusion — it can be an intentional backup.
        assert_eq!(judge("rm -rf ~/Documents.bak", "/home"), Outcome::Block);
    }

    // --- BLOCK: vault ---

    #[test]
    fn vault_root_and_inside_block() {
        assert_eq!(judge("rm -rf /vaults/main", "/home"), Outcome::Block);
        assert_eq!(
            judge("rm -rf /vaults/main/notes/x.md", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn vault_lookalike_does_not_block() {
        // `/vaults/main-backup` is not the vault.
        assert_eq!(judge("rm -rf /vaults/main-backup/x", "/home"), Outcome::Ask);
    }

    #[test]
    fn no_vault_env_skips_vault_rule() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: None,
            tmpdir: None,
        };
        // The same path is just an unknown middle path with no vault configured.
        let out = judge_rm("rm -rf /vaults/main/x", "/home", &ctx, &|_| false).outcome;
        assert_eq!(out, Outcome::Ask);
    }

    // --- BLOCK: git repos ---

    #[test]
    fn dot_git_component_blocks() {
        assert_eq!(
            judge("rm -rf /Users/cam/proj/repo/.git", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("rm -rf /Users/cam/proj/repo/.git/hooks", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn git_repo_root_via_probe_blocks() {
        assert_eq!(
            judge_with(
                "rm -rf /Users/cam/proj/myrepo",
                "/home",
                &["/Users/cam/proj/myrepo"],
            ),
            Outcome::Block
        );
    }

    // --- ASK: unresolvable ---

    #[test]
    fn unexpanded_var_asks() {
        assert_eq!(judge("rm -rf $BUILD_DIR", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -rf ${OUT}/dist", "/home"), Outcome::Ask);
    }

    #[test]
    fn command_substitution_target_asks() {
        assert_eq!(judge("rm -rf $(mktemp -d)", "/home"), Outcome::Ask);
    }

    #[test]
    fn parent_escaping_path_asks() {
        assert_eq!(judge("rm -rf ../../etc", "/home/user/proj"), Outcome::Ask);
        assert_eq!(judge("rm -rf /tmp/../etc", "/home"), Outcome::Ask);
    }

    #[test]
    fn cd_with_parent_makes_target_ambiguous() {
        assert_eq!(judge("cd ../sibling && rm -rf x", "/a/b/c"), Outcome::Ask);
    }

    // --- ASK: default middle ---

    #[test]
    fn arbitrary_project_path_asks() {
        assert_eq!(judge("rm -rf /opt/app/cache", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -rf build", "/srv/project"), Outcome::Ask);
    }

    // --- most-severe wins across multiple targets ---

    #[test]
    fn mixed_targets_take_most_severe() {
        // temp (ALLOW) + home-child (BLOCK) → BLOCK.
        assert_eq!(judge("rm -rf /tmp/x ~/Documents", "/home"), Outcome::Block);
        // temp (ALLOW) + unresolvable (ASK) → ASK.
        assert_eq!(judge("rm -rf /tmp/x $VAR", "/home"), Outcome::Ask);
        // unresolvable (ASK) + root (BLOCK) → BLOCK.
        assert_eq!(judge("rm -rf $VAR /", "/home"), Outcome::Block);
    }

    // --- file-scoped globs classified by their directory (#322) ---

    #[test]
    fn file_scoped_glob_in_git_repo_allows() {
        // A flat artifact sweep in a git repo is routine cleanup.
        assert_eq!(
            judge_with("rm -f homebridge-dreo-*.tgz", "/srv/repo", &["/srv/repo"]),
            Outcome::Allow
        );
        assert_eq!(
            judge_with("rm -f *.tgz", "/srv/repo", &["/srv/repo"]),
            Outcome::Allow
        );
    }

    #[test]
    fn file_scoped_glob_in_temp_allows() {
        // A file-scoped glob under temp keeps the temp Allow.
        assert_eq!(judge("rm -rf /tmp/x/*.log", "/home"), Outcome::Allow);
    }

    #[test]
    fn bare_glob_in_git_repo_still_blocks() {
        // `*` and `.*` mean "everything here", not a file-scoped pattern — the
        // directory (a git repo) is the target → Block, no hole.
        assert_eq!(
            judge_with("rm -rf *", "/srv/repo", &["/srv/repo"]),
            Outcome::Block
        );
        assert_eq!(
            judge_with("rm -rf .*", "/srv/repo", &["/srv/repo"]),
            Outcome::Block
        );
    }

    #[test]
    fn file_scoped_glob_in_vault_still_blocks() {
        // A non-git dir class keeps its verdict — the vault stays Block.
        assert_eq!(judge("rm -f /vaults/main/*.md", "/home"), Outcome::Block);
    }

    #[test]
    fn recursive_file_glob_in_git_repo_asks() {
        // A recursive sweep could dredge tracked directories → Ask, not Allow.
        assert_eq!(
            judge_with("rm -rf project-*", "/srv/repo", &["/srv/repo"]),
            Outcome::Ask
        );
    }

    #[test]
    fn recursive_long_flag_abbreviations_detected() {
        // GNU rm expands any unambiguous `--r…` prefix to `--recursive`.
        let rm = |arg: &str| rm_is_recursive(&["rm".into(), arg.into(), "x".into()], "rm");
        assert!(rm("--recursive"));
        assert!(rm("--recu"));
        assert!(rm("--rec"));
        assert!(rm("--r"));
        // A bare `--` operand terminator is not a recursive flag.
        assert!(!rm("--"));
        // `--recursivex` is not a prefix of "recursive" → not matched.
        assert!(!rm("--recursivex"));
        // An unrelated long flag is not recursive.
        assert!(!rm("--force"));
    }

    #[test]
    fn abbreviated_recursive_file_glob_in_git_repo_asks() {
        // Security regression (#322): `--recu` IS a recursive delete, so a
        // file-scoped glob sweep in a git repo must not ride through to Allow on
        // a false non-recursive belief — it Asks, like `-rf` does.
        assert_eq!(
            judge_with("rm --recu project-*", "/srv/repo", &["/srv/repo"]),
            Outcome::Ask
        );
    }

    #[test]
    fn root_glob_still_blocks_under_file_glob_path() {
        // `/*` reduces to the root — the bare-glob path, never softened.
        assert_eq!(judge("rm -rf /*", "/home"), Outcome::Block);
    }

    // --- non-deletions & look-alikes → ALLOW (nothing to judge) ---

    #[test]
    fn non_rm_commands_allow() {
        assert_eq!(judge("charm install foo", "/home"), Outcome::Allow);
        assert_eq!(
            judge("git rm --cached ~/Documents/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(judge("npm rm left-pad", "/home"), Outcome::Allow);
        assert_eq!(judge("ls -la /", "/home"), Outcome::Allow);
    }

    #[test]
    fn rm_with_no_operands_allows_unless_recursive() {
        // A delete that removes nothing is not ours.
        assert_eq!(judge("rm --help", "/home"), Outcome::Allow);
        assert_eq!(judge("rm -f", "/home"), Outcome::Allow);
        // …but a bare recursive delete IS deleting something the guard cannot
        // see. It used to fall through to Allow.
        assert_eq!(judge("rm -rf", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -r", "/home"), Outcome::Ask);
        assert_eq!(judge("rm --recursive", "/home"), Outcome::Ask);
    }

    #[test]
    fn xargs_delete_asks() {
        // Targets arrive on stdin — unclassifiable, so defer rather than the
        // previous silent Allow.
        assert_eq!(judge("echo /etc | xargs rm -rf", "/home"), Outcome::Ask);
        assert_eq!(
            judge("find . -print0 | xargs -0 rm -rf", "/home"),
            Outcome::Ask
        );
        assert_eq!(judge("xargs rm < list.txt", "/home"), Outcome::Ask);
        assert_eq!(judge("cat l | xargs /bin/rm -rf", "/home"), Outcome::Ask);
        assert_eq!(judge("cat l | xargs env rm -rf", "/home"), Outcome::Ask);
        // The separate-token long option that a precise option-parser misses.
        assert_eq!(
            judge("cat l | xargs --max-args 3 rm -rf", "/home"),
            Outcome::Ask
        );
    }

    #[test]
    fn xargs_without_delete_verb_allows() {
        assert_eq!(
            judge("git ls-files | xargs grep -l foo", "/home"),
            Outcome::Allow
        );
        assert_eq!(judge("ls | xargs -n1 basename", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_without_delete_allows() {
        assert_eq!(
            judge("find /Users/cam/Documents -name '*.tmp'", "/home"),
            Outcome::Allow
        );
    }

    // --- adversarial shapes: wrappers, substitutions, groups, prefixes ---

    #[test]
    fn bash_c_wrapper_sees_inner_rm() {
        assert_eq!(judge("bash -lc 'rm -rf /'", "/home"), Outcome::Block);
        assert_eq!(judge("sh -c 'rm -rf /tmp/x'", "/home"), Outcome::Allow);
    }

    #[test]
    fn substitution_body_sees_inner_rm() {
        assert_eq!(judge("echo $(rm -rf ~)", "/home"), Outcome::Block);
    }

    #[test]
    fn group_wrapper_sees_rm() {
        assert_eq!(judge("(rm -rf /)", "/home"), Outcome::Block);
        assert_eq!(judge("{ rm -rf ~/Desktop; }", "/home"), Outcome::Block);
    }

    #[test]
    fn transparent_prefix_sees_rm() {
        assert_eq!(judge("env FOO=1 rm -rf /", "/home"), Outcome::Block);
        assert_eq!(judge("command rm -rf ~", "/home"), Outcome::Block);
    }

    #[test]
    fn path_qualified_verb_detected() {
        assert_eq!(judge("/bin/rm -rf /", "/home"), Outcome::Block);
        assert_eq!(judge("/usr/bin/unlink ~/.zshrc", "/home"), Outcome::Block);
    }

    #[test]
    fn double_dash_terminator_paths_after_it() {
        // Everything after `--` is a path even if it starts with `-`.
        assert_eq!(judge("rm -rf -- ~/Documents", "/home"), Outcome::Block);
    }

    #[test]
    fn quoted_path_with_spaces_resolved() {
        assert_eq!(
            judge("rm -rf \"/vaults/main/Field Reports\"", "/home"),
            Outcome::Block
        );
    }

    // --- value-flag handling (shred/truncate) ---

    #[test]
    fn shred_value_flag_not_misread_as_target() {
        // `-n 3` must not be read as a path `3`; only /tmp/x is the target.
        assert_eq!(judge("shred -n 3 /tmp/x", "/home"), Outcome::Allow);
    }

    #[test]
    fn truncate_size_flag_not_misread() {
        assert_eq!(judge("truncate -s 0 /tmp/log", "/home"), Outcome::Allow);
        assert_eq!(judge("truncate -s 0 ~/Documents", "/home"), Outcome::Block);
    }

    // --- find -delete targets the search roots ---

    #[test]
    fn find_delete_blocks_protected_root() {
        assert_eq!(
            judge("find ~/Documents -name '*.md' -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_delete_allows_temp_root() {
        assert_eq!(judge("find /tmp/x -delete", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_delete_no_explicit_path_asks() {
        // No explicit path before the expression: the target is the implicit
        // cwd, but a leading option we failed to recognize could equally have
        // dropped a real root — can't tell safely, so ASK (never a silent cwd
        // default that a `.claude`/`tmp` cwd would turn into ALLOW).
        assert_eq!(judge("find -name '*.md' -delete", "/home"), Outcome::Ask);
        assert_eq!(judge("find -delete", "/home"), Outcome::Ask);
    }

    #[test]
    fn find_bsd_global_options_keep_the_root() {
        // macOS ships BSD find: -x/-s/-E/-d/-X are global options too.
        assert_eq!(
            judge("find -x ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -s ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -E ~/Documents -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_unknown_leading_option_asks() {
        // An option outside the known GNU∪BSD global set might have dropped the
        // real root → ASK, not a silent cwd default.
        assert_eq!(
            judge("find -zzz ~/Documents -delete", "/home"),
            Outcome::Ask
        );
        // `-f <path>` (BSD, adds a search root) also routes to ASK.
        assert_eq!(judge("find -f ~/Documents -delete", "/home"), Outcome::Ask);
    }

    #[test]
    fn find_ok_and_backslash_exec_detected() {
        // `-ok`/`-okdir` are interactive `-exec`; a `\rm` behind -exec is still rm.
        assert_eq!(
            judge("find ~/Documents -ok rm {} +", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find ~/Documents -exec \\rm -rf {} +", "/home"),
            Outcome::Block
        );
    }

    // --- security-review fixes: find global options, -exec, \rm, dots ---

    #[test]
    fn find_leading_global_option_keeps_the_root() {
        // Sec #1: a leading -L/-H/-P (or -D/-O) must not drop the real root and
        // default to cwd. `find -L ~/Documents -delete` blocks, not allows.
        assert_eq!(
            judge("find -L ~/Documents -name '*.md' -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -P ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -O2 ~/Documents -delete", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find -D tree ~/Documents -delete", "/home"),
            Outcome::Block
        );
    }

    #[test]
    fn find_exec_delete_targets_the_root() {
        // Sec #2: `find … -exec rm …` deletes, so the search roots are targets.
        assert_eq!(
            judge("find ~/Documents -name '*.md' -exec rm -rf {} +", "/home"),
            Outcome::Block
        );
        assert_eq!(
            judge("find ~/Documents -execdir /bin/rm {} ;", "/home"),
            Outcome::Block
        );
        assert_eq!(judge("find /tmp/x -exec rm {} +", "/home"), Outcome::Allow);
    }

    #[test]
    fn find_without_exec_delete_still_read_only() {
        // A find whose -exec runs a non-delete command is read-only → Allow.
        assert_eq!(
            judge("find ~/Documents -exec cat {} +", "/home"),
            Outcome::Allow
        );
    }

    #[test]
    fn backslash_rm_alias_bypass_detected() {
        // Sec #3: `\rm` (bypasses a shell alias) is still `rm`.
        assert_eq!(judge("\\rm -rf /", "/home"), Outcome::Block);
    }

    #[test]
    fn dot_segments_do_not_downgrade_block() {
        // Sec #4: a `.` segment must not slip a home child past the exact match.
        assert_eq!(judge("rm -rf ~/./Documents", "/home"), Outcome::Block);
        assert_eq!(judge("rm -rf /vaults/./main/x", "/home"), Outcome::Block);
    }

    #[test]
    fn drive_absolute_path_treated_as_absolute() {
        // A Windows drive path (`C:/…`) is absolute — it must NOT be joined onto
        // the cwd, which would miss the exact classifiers. With the fix it
        // matches the (drive-path) vault → Block; without it, the joined
        // `/home/C:/vault/notes` would miss → Ask. (Regression for the Windows
        // `rm -rf C:/Users/<me>` home-delete case.)
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some("C:/vault"),
            tmpdir: None,
        };
        let out = judge_rm("rm -rf C:/vault/notes", "/home", &ctx, &|_| false).outcome;
        assert_eq!(out, Outcome::Block);
    }

    #[test]
    fn more_value_flags_not_misread() {
        // Cover the rest of the takes_value table + glued / =-joined forms.
        assert_eq!(
            judge("shred --iterations 3 /tmp/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(
            judge("shred --random-source /dev/urandom /tmp/x", "/home"),
            Outcome::Allow
        );
        assert_eq!(
            judge("truncate -r /tmp/ref /tmp/x", "/home"),
            Outcome::Allow
        );
        // Glued (`-s0`) and =-joined (`--size=0`) carry their own value — the
        // only operand is /tmp/x.
        assert_eq!(judge("truncate -s0 /tmp/x", "/home"), Outcome::Allow);
        assert_eq!(judge("truncate --size=0 /tmp/x", "/home"), Outcome::Allow);
    }

    // --- message content ---

    #[test]
    fn block_message_names_target_and_hatches() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let r = judge_rm("rm -rf /", "/home", &ctx, &|_| false);
        let msg = r.message.expect("block carries a message");
        assert!(msg.contains("filesystem root"));
        assert!(msg.contains("CADENCE_DISABLE=guard-rm"));
        assert!(msg.contains("CADENCE_BYPASS=1"));
    }

    #[test]
    fn block_message_bypass_hint_is_actionable() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: Some(VAULT),
            tmpdir: None,
        };
        let r = judge_rm("rm -rf /", "/home", &ctx, &|_| false);
        let msg = r.message.expect("block carries a message");
        // The recoverable alternative that never trips guard-rm.
        assert!(msg.contains("~/.Trash"));
        // The hatches live in Claude Code's environment, not the command line.
        assert!(msg.contains("settings.json") || msg.contains("environment"));
        // A command-line prefix is inert — the caveat must be spelled out.
        assert!(msg.contains("NO effect"));
    }

    #[test]
    fn ask_carries_reason() {
        let home = home();
        let ctx = RmContext {
            home: &home,
            vault: None,
            tmpdir: None,
        };
        let r = judge_rm("rm -rf $VAR", "/home", &ctx, &|_| false);
        assert_eq!(r.outcome, Outcome::Ask);
        assert!(
            r.message
                .expect("ask carries a reason")
                .contains("guard-rm")
        );
    }

    // --- Check::run plumbing (env-independent assertions) ---

    #[test]
    fn run_allows_non_command_payload() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_allows_temp_delete() {
        // `/tmp` is env-independent (the fixed temp-root branch), so this holds
        // regardless of the test runner's HOME/TMPDIR.
        let input = make_bash("rm -rf /tmp/guard-rm-test-scratch");
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_allows_non_rm() {
        let input = make_bash("charm install something");
        assert_eq!(GuardRm.run(&input).outcome, Outcome::Allow);
    }

    // --- single-file severity class ---

    #[test]
    fn single_file_delete_in_the_ambiguous_middle_allows() {
        // Without `-r` the shell refuses to remove a directory, so this can
        // only ever delete one file.
        assert_eq!(judge("rm build.log", "/srv/project"), Outcome::Allow);
        assert_eq!(judge("rm -f build.log", "/srv/project"), Outcome::Allow);
        assert_eq!(judge("rm /opt/app/cache/x.bin", "/home"), Outcome::Allow);
        assert_eq!(judge("unlink /opt/app/x.sock", "/home"), Outcome::Allow);
        // A tracked source file: git has it.
        assert_eq!(judge("rm src/main.rs", "/srv/project"), Outcome::Allow);
    }

    #[test]
    fn single_file_does_not_soften_a_protected_class() {
        assert_eq!(judge("rm ~/.zshrc", "/home"), Outcome::Block);
        assert_eq!(judge("rm /vaults/main/notes/x.md", "/home"), Outcome::Block);
        assert_eq!(judge("rm /srv/repo/.git/config", "/home"), Outcome::Block);
        assert_eq!(judge("rm /", "/home"), Outcome::Block);
        assert_eq!(judge("rm ~", "/home"), Outcome::Block);
    }

    #[test]
    fn single_file_does_not_soften_durable_claude_state() {
        // The interaction that would otherwise re-open the subtree the scratch
        // allowlist closed: one transcript is still the only copy of it.
        assert_eq!(
            judge("rm ~/.claude/projects/proj/session.jsonl", "/home"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm /srv/repo/.claude/agent-memory/reviewer.md", "/home"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm ~/.claude/metrics/denials.jsonl", "/home"),
            Outcome::Ask
        );
        // `DocsPlans` has no guard-rm arm and so reads as the ambiguous middle;
        // a plan doc under `.claude` must report durable state instead of
        // riding the softening.
        assert_eq!(
            judge("rm ~/.claude/docs/plans/2026-07-25-x.md", "/home"),
            Outcome::Ask
        );
    }

    #[test]
    fn single_file_requires_no_glob_and_no_recursion() {
        // `rm *` resolves to the DIRECTORY the sweep runs in — not one file.
        assert_eq!(
            judge_with("rm *", "/srv/repo", &["/srv/repo"]),
            Outcome::Block
        );
        // A recursive delete is never a single file, however it is spelled.
        assert_eq!(judge("rm -rf build.log", "/srv/project"), Outcome::Ask);
        assert_eq!(
            judge("rm --recursive build.log", "/srv/project"),
            Outcome::Ask
        );
        assert_eq!(judge("rm --recu build.log", "/srv/project"), Outcome::Ask);
        // `shred`/`truncate` keep their existing verdicts — not in the class.
        assert_eq!(judge("truncate -s 0 ~/Documents", "/home"), Outcome::Block);
    }

    #[test]
    fn rm_dash_d_is_not_a_single_file() {
        // `rm -d` removes an empty directory without `-r`, so the "the shell
        // refuses to remove a directory" premise does not hold for it.
        assert_eq!(judge("rm -d /opt/app/emptydir", "/home"), Outcome::Ask);
        assert_eq!(judge("rm --dir /opt/app/emptydir", "/home"), Outcome::Ask);
        assert_eq!(judge("rm -fd /opt/app/emptydir", "/home"), Outcome::Ask);
    }

    #[test]
    fn brace_expansion_is_not_one_target() {
        // One token, many targets. The first alternative's prefix would
        // otherwise pull the whole list out of its protected class, and the
        // single-file rule would soften it to silence while bash deleted every
        // entry. (`strip_group_wrappers` trims the trailing `}`, so this never
        // even reads as a brace list by the time it is classified.)
        assert_eq!(
            judge("rm -f ~/{Documents/notes,.zshrc}", "/home"),
            Outcome::Ask
        );
        assert_eq!(
            judge("rm -f /srv/repo/{README.md,.git/config}", "/home"),
            Outcome::Ask
        );
        assert_eq!(judge("rm -f build/{a,b}.o", "/srv/repo"), Outcome::Ask);
    }

    #[test]
    fn single_file_still_asks_when_the_path_is_unresolvable() {
        assert_eq!(judge("rm $SOMEFILE", "/srv/project"), Outcome::Ask);
        assert_eq!(judge("rm ../sibling/x", "/srv/project"), Outcome::Ask);
    }

    #[test]
    fn unfollowable_cd_makes_relative_targets_unresolvable() {
        // Keeping the pre-cd directory allowed `rm -rf Documents` to be judged
        // against a temp cwd the shell had already left.
        assert_eq!(
            judge("cd $UNKNOWN; rm -rf Documents", "/private/tmp"),
            Outcome::Ask
        );
        assert_eq!(judge("cd; rm -rf Documents", "/private/tmp"), Outcome::Ask);
        assert_eq!(
            judge("cd -; rm -rf Documents", "/private/tmp"),
            Outcome::Ask
        );
        // An absolute target after an unfollowable `cd` is still judgeable, and
        // so is a `~`-anchored one — neither is relative.
        assert_eq!(
            judge("cd $UNKNOWN; rm -rf /", "/private/tmp"),
            Outcome::Block
        );
        assert_eq!(
            judge("cd $UNKNOWN; rm -rf ~/Documents", "/private/tmp"),
            Outcome::Block
        );
    }
}
