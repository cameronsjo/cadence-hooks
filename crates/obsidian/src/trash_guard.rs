//! Redirect destructive commands and file-tool deletions inside an Obsidian
//! vault to `.trash/`.
//!
//! Obsidian has a built-in `.trash/` recycle bin. Deleting or truncating vault
//! files with `rm`, `unlink`, `shred`, `truncate`, or `find … -delete` bypasses
//! it and loses recoverability. This guard blocks those commands inside the
//! vault directory and suggests `mv` to `.trash/` instead.

use cadence_hooks_core::shell::{
    carries_substitution, child_scripts, clobber_redirect_targets, command_segments, command_word,
    executable_tokens, executable_tokens_marked, looks_absolute, peel_command_runners,
    redirect_operator_span, redirect_targets, segment_work_dirs, skip_git_global_options,
    strip_verbatim_prefix, substitution_bodies, tokenize, UNRESOLVABLE_DIR,
};
use cadence_hooks_core::{Check, CheckResult, HookInput, normalize_path};

/// Verbs that delete or zero the file they are handed.
const DESTRUCTIVE_VERBS: &[&str] = &["rm", "unlink", "shred", "truncate"];

/// `find` actions that name a second executable position.
const EXEC_ACTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// How far the scan follows a command that runs another command it carries as
/// an operand (`eval …`, `find … -exec sh -c '…'`). Bounded for the same
/// reason `command_segments` bounds wrapper nesting: a self-referential
/// spelling must not recurse without end.
const MAX_NESTED_DEPTH: usize = 3;

/// Destructive-command gate: shapes that delete or zero a vault file,
/// bypassing Obsidian's `.trash/`. Verbs are matched only where the shell runs
/// an executable, which is two positions — the segment head (after shell
/// keywords) and a `find` exec-family action — read through the SAME
/// [`peel_command_runners`]/[`head_deletes`] pair, plus an operand a command
/// re-executes (`eval`, `find … -exec sh -c`). A path-qualified invocation
/// (`/bin/unlink`) is caught, while prose or a filename argument such as
/// `echo RM` or `shredder.md` is not.
fn is_destructive(command: &str) -> bool {
    is_destructive_at(command, 0)
}

thread_local! {
    static RESCAN_LEFT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static RESCAN_SPENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Bytes the `eval`/`coproc`/`find -exec` re-scans of one judgement may read
/// again (cameronsjo/cadence-hooks#1266 review C3). Each re-scan runs the
/// whole `command_segments` walk on its operand, and a flood of
/// `$(eval `/`<(eval ` lists that walk's segments by the dozen, each most of
/// the command: re-reading every one cost 14–20 s at 200 KB, past the hook
/// deadline, which fails open. A fixed allowance, not one per byte of the
/// command: one re-scan of a 200 KB operand alone is most of the deadline.
const RESCAN_ALLOWANCE: usize = 64 * 1024;

thread_local! {
    static JUDGED_SEGMENTS: std::cell::RefCell<Option<(String, std::rc::Rc<Vec<String>>)>> =
        const { std::cell::RefCell::new(None) };
}

/// [`command_segments`] of `command`, read once per judgement: the
/// destructive test, the operand walk, the sibling check and the redirect
/// check each asked for the same walk, which on a 200 KB flood is most of
/// the deadline (cameronsjo/cadence-hooks#1266 review C3). Only the command
/// being judged is kept, and only while a [`RescanBudget`] is armed.
fn segments_of(command: &str) -> std::rc::Rc<Vec<String>> {
    let cached = JUDGED_SEGMENTS.with(|judged| {
        judged
            .borrow()
            .as_ref()
            .filter(|(text, _)| text == command)
            .map(|(_, segments)| segments.clone())
    });
    if let Some(segments) = cached {
        return segments;
    }
    let segments = std::rc::Rc::new(command_segments(command));
    let armed = RESCAN_LEFT.with(|left| left.get().is_some());
    JUDGED_SEGMENTS.with(|judged| {
        let mut judged = judged.borrow_mut();
        if armed && judged.is_none() {
            *judged = Some((command.to_string(), segments.clone()));
        }
    });
    segments
}

/// The re-scan allowance for one judgement, cleared when dropped.
struct RescanBudget;

impl RescanBudget {
    fn arm() -> RescanBudget {
        RESCAN_LEFT.with(|left| left.set(Some(RESCAN_ALLOWANCE)));
        RESCAN_SPENT.with(|spent| spent.set(false));
        JUDGED_SEGMENTS.with(|judged| *judged.borrow_mut() = None);
        RescanBudget
    }

    /// Whether the allowance ran out, leaving a re-scan unread.
    fn spent() -> bool {
        RESCAN_SPENT.with(std::cell::Cell::get)
    }
}

impl Drop for RescanBudget {
    fn drop(&mut self) {
        RESCAN_LEFT.with(|left| left.set(None));
        JUDGED_SEGMENTS.with(|judged| *judged.borrow_mut() = None);
    }
}

/// [`is_destructive_at`] on a script a segment re-executes, charged to the
/// re-scan allowance. Past it the script is not read: it counts as
/// destructive when its text could spell a deleting verb or a redirect
/// ([`DELETING_SPELLINGS`], the [`eval_flood`] rule), so the guard refuses
/// rather than grinding past its deadline.
fn rescanned_destructive(script: &str, depth: usize) -> bool {
    if rescan(script) {
        is_destructive_at(script, depth)
    } else {
        DELETING_SPELLINGS.iter().any(|verb| script.contains(verb))
    }
}

/// Charge a re-scan of `text`; `false`, and the allowance marked spent, when
/// it does not fit. Unarmed, every re-scan fits.
fn rescan(text: &str) -> bool {
    RESCAN_LEFT.with(|left| match left.get() {
        None => true,
        Some(have) if have >= text.len() => {
            left.set(Some(have - text.len()));
            true
        }
        Some(_) => {
            left.set(Some(0));
            RESCAN_SPENT.with(|spent| spent.set(true));
            false
        }
    })
}

/// Substrings that mark a deleting verb inside text the scan will not peel.
const DELETING_SPELLINGS: &[&str] = &[
    "rm", "unlink", "shred", "truncate", "find", "git", "-delete", ">",
];

/// A run of `eval` words longer than [`MAX_NESTED_DEPTH`] is a nest the walk
/// gives up on, and expanding it costs seconds per thousand words
/// (`eval ` × 30,000 took 27.7 s and the hook deadline fails OPEN). Read
/// linearly instead: `Some(true)` when the text past the run could carry a
/// deleting verb or a redirect (ambiguity blocks), `Some(false)` when it cannot, `None`
/// when there is no such run and the ordinary walk applies.
fn eval_flood(command: &str) -> Option<bool> {
    let mut run = 0;
    let mut start = None;
    for (offset, word) in word_offsets(command) {
        if word == "eval" {
            run += 1;
            if run > MAX_NESTED_DEPTH {
                start = Some(offset);
                break;
            }
        } else {
            run = 0;
        }
    }
    let start = start?;
    let rest = &command[start..];
    Some(DELETING_SPELLINGS.iter().any(|verb| rest.contains(verb)))
}

/// Whitespace-separated words with their byte offsets.
fn word_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_whitespace()
        .map(move |word| (word.as_ptr() as usize - text.as_ptr() as usize, word))
}

/// True when the command at the head of an already-peeled `argv` deletes or
/// zeroes the file it is handed.
///
/// `git rm` is judged as `rm` — it deletes the working-tree file the same way.
/// Same alias, same case-SENSITIVE subcommand spelling, as
/// `prevent_secret_writes::writer_targets`. `git`'s global options sit between
/// the verb and the subcommand, so `git -C . rm note.md` is read past them
/// rather than resolving its subcommand to `-C` (#528 review I2).
fn head_deletes(argv: &[String]) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    let verb = command_word(first);
    DESTRUCTIVE_VERBS.contains(&verb.as_ref())
        || (verb == "git"
            && skip_git_global_options(&argv[1..])
                .first()
                .map(String::as_str)
                == Some("rm"))
}

/// The command a `coproc` runs, given the `argv` that starts with `coproc`
/// (cadence-hooks#546). `coproc [NAME] command`: bash reads NAME only when the
/// command is a compound one (`{`, `(`, a loop or conditional keyword), so a
/// bare `coproc rm note.md` runs `rm` and `rm` is not a name. `None` when
/// nothing follows.
///
/// **Documented limit, not a bug:** a verb PRODUCED by a substitution in command
/// position is unknowable without running it, so this guard does not judge it
/// (`$(which rm) note.md`). Fail-closed on every unresolvable command word
/// would block `$EDITOR note.md`; the operator ruled (#546, option b) to leave
/// that shape and say so. A literal `echo`/`printf` is the exception: it is
/// read as the text it prints, so `$(echo rm) note.md` is judged as `rm
/// note.md` (cadence-hooks#1142).
fn coproc_command(argv: &[String]) -> Option<&[String]> {
    const COMPOUND_STARTS: &[&str] = &[
        "{", "(", "((", "[[", "if", "while", "until", "for", "select", "case",
    ];
    let rest = argv.get(1..).filter(|rest| !rest.is_empty())?;
    let is_name = |word: &str| {
        !word.is_empty()
            && !word.starts_with(|c: char| c.is_ascii_digit())
            && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let rest = match rest {
        [name, next, ..] if is_name(name) && COMPOUND_STARTS.contains(&next.as_str()) => &rest[1..],
        _ => rest,
    };
    Some(peel_command_runners(rest))
}

/// Worker for [`is_destructive`]; `depth` bounds the re-executed-operand walk.
fn is_destructive_at(command: &str, depth: usize) -> bool {
    for segment in segments_of(command).iter() {
        // Compound scaffolding first: `for f in *.md; do rm $f; done` segments
        // as `do rm $f`, `case x in x) rm $f;; esac` as `case x in x) rm $f`,
        // and `f() { rm $f; }` as `f() { rm $f` — so without this the head word
        // is `do`/`case`/`f()` and the `rm` behind it is never examined. The
        // wrapper hunt inside `command_segments` runs the SAME
        // `executable_tokens`, so a shell wrapper in those bodies is expanded
        // rather than hidden (#528 review E).
        let tokens = executable_tokens(segment);
        let argv = peel_command_runners(&tokens);
        if head_deletes(argv) {
            return true;
        }
        let Some(first) = argv.first() else {
            continue;
        };
        let verb = command_word(first);
        // `eval` re-executes its operand, so scan that operand as a command in
        // its own right — the head word of the segment is `eval`, and the verb
        // it runs is invisible to a head test.
        if verb == "eval" && depth < MAX_NESTED_DEPTH && argv.len() > 1 {
            let script = argv[1..].join(" ");
            if rescanned_destructive(&script, depth + 1) {
                return true;
            }
        }
        // `coproc` is a reserved word that runs a command, not a prefix with
        // flags, so the verb behind it is invisible to a head test. Its
        // operand is judged as a command in its own right, like `eval`'s.
        if verb == "coproc"
            && depth < MAX_NESTED_DEPTH
            && let Some(rest) = coproc_command(argv)
        {
            let script = rest.join(" ");
            if rescanned_destructive(&script, depth + 1) {
                return true;
            }
        }
        // `find … -delete` — `find` alone is read-only; only `-delete`
        // destroys. Exec-family actions name another executable position, so
        // inspect what follows the action rather than every operand in the
        // segment.
        if verb == "find" {
            if argv.iter().any(|token| token == "-delete") {
                return true;
            }
            for (i, token) in argv.iter().enumerate() {
                if !EXEC_ACTIONS.contains(&token.as_str()) {
                    continue;
                }
                // The action's argument list is an executable position like any
                // other, so it gets the SAME peel the segment head gets —
                // otherwise `-exec git rm {} \;` and `-exec nice -n 10 rm {} \;`
                // read their verb as `git`/`nice` and go unjudged.
                let action_argv = peel_command_runners(&argv[i + 1..]);
                if head_deletes(action_argv) {
                    return true;
                }
                // An exec action can name a shell instead of the verb itself
                // (`-exec sh -c 'rm …'`). `command_segments` only unwraps a
                // wrapper at the segment head, so the nested script is expanded
                // here, from the action's own argument list.
                //
                // The PEELED slice is handed over, so the verb test and the
                // wrapper test read the same window. `child_scripts` peels
                // again internally and the peel is idempotent, so this is
                // belt-and-suspenders rather than the only guard rope — but it
                // is the rope that does not depend on a callee's internals: a
                // reader here can see that `-exec nice -n 10 sh -c '…'` reaches
                // the wrapper hunt without going and checking what
                // `child_scripts` happens to strip today.
                if depth < MAX_NESTED_DEPTH
                    && child_scripts(action_argv, "")
                        .iter()
                        .any(|script| rescanned_destructive(script, depth + 1))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Filesystem existence probe for the redirect-truncation check. Injected so
/// the guard stays a pure function over fake paths in tests (#192): a `>`
/// redirect truncates only a file that ALREADY exists — distinguishing
/// truncate from benign new-file creation needs one stat at check time.
pub trait FileMeta {
    /// True iff `path` names an existing file (symlinks resolved by the real
    /// impl; the fake decides its own semantics).
    fn exists(&self, path: &str) -> bool;

    /// The physical location of an absolute, `..`-free `path`: its longest
    /// existing ancestor with every symlink resolved, plus the not-yet-existing
    /// tail. `None` when nothing can be resolved. Only ever used to ADD a
    /// block — an operand that looks outside the vault but physically lands
    /// in it (`/tmp/link-to-vault/note.md`) — so the default of "no physical
    /// view" keeps the lexical verdict (cadence-hooks#839).
    fn physical(&self, _path: &str) -> Option<String> {
        None
    }

    /// The canonical form of an EXISTING directory `path`, symlinks resolved and
    /// any Windows verbatim prefix stripped; `None` when it does not exist. One
    /// call is one `canonicalize`, which the caller budgets (cadence-hooks#1171).
    fn canonical_dir(&self, _path: &str) -> Option<String> {
        None
    }
}

/// Production impl over `std::fs`. Uses `symlink_metadata(...).is_ok()` — a
/// broken symlink still "exists" as a dir entry a `>` would clobber.
pub struct RealFs;
impl FileMeta for RealFs {
    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn physical(&self, path: &str) -> Option<String> {
        let path = std::path::Path::new(path);
        if let Ok(resolved) = std::fs::canonicalize(path) {
            return Some(normalize_path(&strip_verbatim_prefix(
                &resolved.to_string_lossy(),
            )));
        }
        // Find the longest existing prefix by binary search — existence is
        // monotone along the prefix chain — and resolve it once. A per-step
        // walk costs a full-path lookup per component, quadratic in depth:
        // 64 operands 1000 directories deep took 4.6 s that way.
        let components: Vec<_> = path.components().collect();
        let prefix = |n: usize| components[..n].iter().collect::<std::path::PathBuf>();
        let (mut lo, mut hi) = (0, components.len());
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if std::fs::symlink_metadata(prefix(mid)).is_ok() {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        let mut resolved = canonicalize_or_parent(&prefix(lo))?;
        resolved.extend(&components[lo..]);
        Some(normalize_path(&strip_verbatim_prefix(
            &resolved.to_string_lossy(),
        )))
    }

    fn canonical_dir(&self, path: &str) -> Option<String> {
        let resolved = std::fs::canonicalize(path).ok()?;
        Some(normalize_path(&strip_verbatim_prefix(
            &resolved.to_string_lossy(),
        )))
    }
}

/// Canonicalize an existing path; a dangling symlink, which does not, resolves
/// through its parent and keeps its own name.
fn canonicalize_or_parent(path: &std::path::Path) -> Option<std::path::PathBuf> {
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return Some(resolved);
    }
    let mut parent = std::fs::canonicalize(path.parent()?).ok()?;
    parent.push(path.file_name()?);
    Some(parent)
}

/// Split an absolute path into its root prefix (`"/"` or a Windows drive
/// prefix like `"C:/"`) and the segment body after it. Empty prefix means the
/// path wasn't recognized as absolute (shouldn't happen for callers here,
/// since `resolve_in_vault` always joins onto an absolute `cwd`/`vault`).
fn split_absolute_prefix(path: &str) -> (&str, &str) {
    if let Some(rest) = path.strip_prefix('/') {
        return ("/", rest);
    }
    let b = path.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/' {
        return (&path[..3], &path[3..]);
    }
    ("", path)
}

/// Lexically collapse `.`/`..` segments in an absolute path — a string
/// operation, not a filesystem canonicalization, since a redirect target may
/// not exist yet. `..` pops the last real segment; a `..` with nothing to pop
/// (already at root) is dropped rather than climbing above root. This runs
/// BEFORE the vault-prefix membership test so a climb like
/// `cwd=/home/user, target=../../vault/note.md` resolves to `/vault/note.md`
/// instead of string-testing a literal `/home/user/../../vault/note.md`,
/// which would never match the `/vault/` prefix even though the shell lands
/// inside the vault (#192 F4/F7).
fn collapse_dots(path: &str) -> String {
    let (prefix, body) = split_absolute_prefix(path);
    let mut segments: Vec<&str> = Vec::new();
    for seg in body.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("{prefix}{}", segments.join("/"))
}

/// Resolve a redirect target against `cwd`, returning its normalized,
/// dot-collapsed absolute path when that path falls inside `vault` (both
/// already normalized by the caller). A relative target resolves under
/// `cwd`, matching shell redirect semantics; an absolute target is checked
/// directly. `..`/`.` segments are lexically collapsed before the
/// vault-prefix test (#192 F4) — otherwise a climb-back-in (`../../vault/x`)
/// or climb-out (`../../../etc/passwd`) mis-resolves against the raw string.
/// Returns `None` when the collapsed path is outside the vault.
fn resolve_in_vault(target: &str, cwd: &str, vault: &str, vault_prefix: &str) -> Option<String> {
    let target = normalize_path(target);
    let resolved = if looks_absolute(&target) {
        target
    } else {
        normalize_path(&format!("{cwd}/{target}"))
    };
    let resolved = collapse_dots(&resolved);
    if resolved == vault || resolved.starts_with(vault_prefix) {
        Some(resolved)
    } else {
        None
    }
}

/// Most operands one destructive command may carry and still be judged
/// operand by operand. Each one can cost a `canonicalize` walk, and the hook
/// deadline fails OPEN, so a command past this keeps the cwd verdict (block)
/// instead of racing the clock.
const MAX_JUDGED_OPERANDS: usize = 64;

/// Longest operand judged, `PATH_MAX`: the kernel refuses a longer path, and
/// the physical walk costs a lookup per component, so anything past this is
/// read as possibly inside the vault.
const MAX_OPERAND_LEN: usize = 4096;

/// Deepest operand judged. Resolving a path through symlinks (`realpath`)
/// costs a lookup of every prefix, quadratic in depth, and an existing tree
/// 1000 directories deep took 0.57 s for 8 operands; anything deeper than this
/// is read as possibly inside the vault.
const MAX_OPERAND_DEPTH: usize = 64;

/// Longest command judged operand by operand. A deletion anyone types is far
/// shorter; past this the cwd verdict (block) stands without a second
/// segmentation pass over the input.
const MAX_JUDGED_COMMAND_LEN: usize = 16 * 1024;

/// Most segments a command may carry and still be judged operand by operand,
/// for the same reason: every `eval`/`find` segment is re-scanned, and a
/// 200 KB chain of them came within 0.05 s of the hook deadline.
const MAX_JUDGED_SEGMENTS: usize = 256;

/// Characters that make an operand's target unknowable from its text: a
/// parameter, substitution, glob, brace, extglob, or escape the shell
/// expands before `rm` sees the word. The tokenizer has already removed
/// quoting, so a quoted `'*'` lands here too — an over-block, never a miss.
/// (A tilde needs no entry: only an absolute word is judged, and a word that
/// starts with `/` is never tilde-expanded.)
const UNRESOLVABLE_OPERAND_CHARS: &[char] =
    &['$', '`', '*', '?', '[', ']', '{', '}', '(', ')', '\\'];

/// True when `path` (normalized, absolute) is the vault, sits inside it, or
/// is one of its ancestors — `rm -r /home/me` deletes a vault under it just
/// as surely as `rm /vault/note.md` does.
fn touches_vault(path: &str, vault: &str) -> bool {
    let vault_prefix = format!("{vault}/");
    path == vault
        || path.starts_with(&vault_prefix)
        || path.ends_with('/')
        || vault.starts_with(&format!("{path}/"))
}

/// Judge one operand of a deletion issued from inside the vault: `true` only
/// when it provably names a path outside it (cadence-hooks#839). Anything the
/// text cannot settle — a relative name (it resolves under the vault cwd), an
/// expansion, a `..` climb a symlink could redirect, a control character —
/// reads as inside.
fn operand_outside_vault(operand: &str, vault: &str, meta: &dyn FileMeta) -> bool {
    if operand.len() > MAX_OPERAND_LEN
        || !looks_absolute(operand)
        || operand.contains(UNRESOLVABLE_OPERAND_CHARS)
        || operand.chars().any(char::is_control)
    {
        return false;
    }
    let path = normalize_path(operand);
    if path.split('/').count() > MAX_OPERAND_DEPTH + 1
        || path.split('/').any(|segment| segment == "..")
    {
        return false;
    }
    let lexical = collapse_dots(&path);
    if touches_vault(&lexical, vault) {
        return false;
    }
    // A symlink outside the vault can point into it. Resolve both sides
    // physically, so neither a linked operand nor a vault reached through a
    // symlinked parent (`/var` → `/private/var`) slips past the prefix test.
    let physical_vault = meta.physical(vault);
    let vaults = std::iter::once(vault).chain(physical_vault.as_deref());
    match meta.physical(&lexical) {
        Some(physical) => !vaults
            .into_iter()
            .any(|v| touches_vault(&physical, v) || touches_vault(&lexical, v)),
        None => true,
    }
}

/// Verbs that neither touch the filesystem nor run another command, so a
/// segment made of one (with no output redirect) cannot change what a
/// sibling deletion's operand resolves to.
const INERT_VERBS: &[&str] = &[
    "echo", "printf", "true", ":", "ls", "cat", "pwd", "test", "[",
];

/// Is this non-deleting segment one that cannot reshape the filesystem before
/// a sibling deletion runs? An [`INERT_VERBS`] head with no output redirect.
/// Everything else — `ln`, `mv`, `cp`, `mkdir`, `cd`, `pushd`, a shell wrapper,
/// `find`, `eval`, a function call, an unknown command — is not.
fn is_inert_segment(argv: &[String], segment: &str) -> bool {
    argv.first()
        .is_some_and(|first| INERT_VERBS.contains(&command_word(first).as_ref()))
        && redirect_targets(segment).is_empty()
}

/// With the shell standing inside the vault, is every deletion the command
/// makes provably aimed outside it (cadence-hooks#839)? The cwd names where
/// the shell stands, not what `rm` is handed, so `rm /tmp/scratch.py` issued
/// from the vault is not the trash guard's business.
///
/// Only a plain deletion verb (`rm`, `unlink`, `shred`, `truncate`) at a
/// segment head is judged operand by operand. Every other destructive shape
/// keeps the cwd verdict: `git rm` (pathspecs, `--pathspec-from-file`),
/// `xargs` (operands arrive on stdin), and every command that sits beside the
/// deletion unless it is inert ([`is_inert_segment`]) — so `find`, `eval`, a
/// shell wrapper, and anything that could re-point an operand (`ln`, `mv`,
/// `cd`) keep the block. Options are skipped only before the
/// first operand or `--`, so a `-f` a strict-POSIX `rm` would treat as a file
/// is judged as one. A redirection is skipped only when its operator is
/// unquoted — a quoted `'>note.md'` is a file `rm` deletes.
fn deletions_all_outside_vault(command: &str, vault: &str, meta: &dyn FileMeta) -> bool {
    if command.len() > MAX_JUDGED_COMMAND_LEN {
        return false;
    }
    let segments: Vec<String> = segments_of(command).to_vec();
    if segments.len() > MAX_JUDGED_SEGMENTS {
        return false;
    }
    let mut judged = 0;
    for segment in segments {
        let (tokens, unquoted_prefix_lens) = executable_tokens_marked(&segment);
        let argv = peel_command_runners(&tokens);
        if !head_deletes(argv) {
            // Every other segment must be provably inert. The physical check
            // reads the disk at hook time, so a sibling that reshapes it first
            // — `ln -s <vault> /tmp/l; rm -rf /tmp/l/`, a `mv`, a `cd` — would
            // walk an operand into the vault after the check passed it.
            if !is_inert_segment(argv, &segment) {
                return false;
            }
            continue;
        }
        let runners = &tokens[..tokens.len() - argv.len()];
        if command_word(&argv[0]) == "git" || runners.iter().any(|t| command_word(t) == "xargs") {
            return false;
        }
        let lens = &unquoted_prefix_lens[unquoted_prefix_lens.len() - argv.len()..];
        let truncate = command_word(&argv[0]) == "truncate";
        let mut options_done = false;
        let mut i = 1;
        while let Some(arg) = argv.get(i) {
            if let Some((operator_len, bare)) = redirect_operator_span(arg)
                && lens.get(i).is_some_and(|&len| len >= operator_len)
            {
                i += if bare { 2 } else { 1 };
                continue;
            }
            if !options_done {
                if arg == "--" {
                    options_done = true;
                    i += 1;
                    continue;
                }
                if arg.len() > 1 && arg.starts_with('-') {
                    i += 1 + usize::from(truncate && option_takes_next_word(arg));
                    continue;
                }
            }
            options_done = true;
            judged += 1;
            if judged > MAX_JUDGED_OPERANDS || !operand_outside_vault(arg, vault, meta) {
                return false;
            }
            i += 1;
        }
    }
    true
}

/// Collect the path operands of every deletion in `command`, read through the
/// same segment/peel/`eval`/`find -exec` walk [`is_destructive_at`] uses, so an
/// operand is judged only where a deleting verb receives it. Options and
/// unquoted redirections are skipped; `find` contributes its start paths. A
/// deletion whose operands arrive on stdin (`xargs rm`) names none here.
fn deletion_operands(command: &str, depth: usize, out: &mut Vec<String>) {
    for segment in segments_of(command).iter() {
        let (tokens, unquoted_prefix_lens) = executable_tokens_marked(segment);
        let argv = peel_command_runners(&tokens);
        let Some(first) = argv.first() else {
            continue;
        };
        let lens = &unquoted_prefix_lens[unquoted_prefix_lens.len() - argv.len()..];
        let verb = command_word(first);
        if head_deletes(argv) {
            let mut start = 1;
            if verb == "git" {
                let rest = skip_git_global_options(&argv[1..]);
                start = argv.len() - rest.len() + 1;
            }
            collect_operands(argv, lens, start, false, verb == "truncate", out);
        } else if verb == "find" {
            let is_delete = argv.iter().any(|t| t == "-delete");
            let has_exec = argv.iter().any(|t| EXEC_ACTIONS.contains(&t.as_str()));
            if is_delete || has_exec {
                collect_operands(argv, lens, 1, true, false, out);
            }
            for (i, token) in argv.iter().enumerate() {
                if !EXEC_ACTIONS.contains(&token.as_str()) {
                    continue;
                }
                let action_argv = peel_command_runners(&argv[i + 1..]);
                if depth < MAX_NESTED_DEPTH {
                    for script in child_scripts(action_argv, "") {
                        if rescan(&script) {
                            deletion_operands(&script, depth + 1, out);
                        }
                    }
                }
            }
        } else if verb == "eval" && depth < MAX_NESTED_DEPTH && argv.len() > 1 {
            let script = argv[1..].join(" ");
            if rescan(&script) {
                deletion_operands(&script, depth + 1, out);
            }
        } else if verb == "coproc"
            && depth < MAX_NESTED_DEPTH
            && let Some(rest) = coproc_command(argv)
        {
            let script = rest.join(" ");
            if rescan(&script) {
                deletion_operands(&script, depth + 1, out);
            }
        }
    }
}

/// Push the operands of `argv[start..]`. `roots_only` (a `find`) stops at the
/// first expression token instead of skipping options. `truncate` also skips
/// the values of `-s`/`--size` (a size) and `-r`/`--reference` (a file it only
/// reads), which are not files it truncates (cadence-hooks#1172).
fn collect_operands(
    argv: &[String],
    lens: &[usize],
    start: usize,
    roots_only: bool,
    truncate: bool,
    out: &mut Vec<String>,
) {
    let mut options_done = false;
    let mut i = start;
    while let Some(arg) = argv.get(i) {
        if let Some((operator_len, bare)) = redirect_operator_span(arg)
            && lens.get(i).is_some_and(|&len| len >= operator_len)
        {
            i += if bare { 2 } else { 1 };
            continue;
        }
        if roots_only && (arg.starts_with('-') || arg == "(" || arg == "!") {
            break;
        }
        if !options_done && !roots_only {
            if arg == "--" {
                options_done = true;
                i += 1;
                continue;
            }
            if arg.len() > 1 && arg.starts_with('-') {
                i += 1 + usize::from(truncate && option_takes_next_word(arg));
                continue;
            }
        }
        options_done = true;
        out.push(arg.clone());
        i += 1;
    }
}

/// Does this `truncate` option leave its value in the next word? `-s SIZE` and
/// `-r RFILE`, alone or last in a cluster (`-cs 0`), and their long names, whole
/// or abbreviated as getopt allows (`--size 0`, `--ref f`). A value glued to
/// the option (`-s0`, `-cs0`, `--size=0`) is in the same word.
fn option_takes_next_word(arg: &str) -> bool {
    if let Some(long) = arg.strip_prefix("--") {
        return !long.is_empty()
            && !long.contains('=')
            && ("size".starts_with(long) || "reference".starts_with(long));
    }
    for (at, c) in arg.char_indices().skip(1) {
        match c {
            's' | 'r' => return at + c.len_utf8() == arg.len(),
            'c' | 'o' => {}
            _ => return false,
        }
    }
    false
}

/// Resolve a deletion operand lexically against `cwd` (`~` against `home`,
/// `..` collapsed). `None` for a `~user` form, which no text settles.
fn resolve_operand(operand: &str, cwd: &str, home: Option<&str>) -> Option<String> {
    let root = operand.trim().starts_with('/') && normalize_path(operand).is_empty();
    if root {
        return Some("/".to_string());
    }
    let operand = normalize_path(operand);
    let joined = if operand == "~" || operand.starts_with("~/") {
        format!("{}{}", normalize_path(home?), &operand[1..])
    } else if operand.starts_with('~') {
        return None;
    } else if looks_absolute(&operand) {
        operand
    } else {
        format!("{cwd}/{operand}")
    };
    looks_absolute(&joined).then(|| collapse_dots(&joined))
}

/// Judge an operand containing an expansion by its literal prefix. The shell
/// expands the rest, so the prefix may name the vault, something in it, or a
/// partial name of the vault or one of its ancestors (`~/Doc*`). An empty
/// prefix says nothing and is not judged.
fn operand_lexically_touches_vault(
    operand: &str,
    cwd: &str,
    vault: &str,
    home: Option<&str>,
) -> bool {
    let Some(at) = operand.find(GLOB_CHARS) else {
        return resolve_operand(operand, cwd, home).is_some_and(|path| touches_vault(&path, vault));
    };
    let prefix = &operand[..at];
    if prefix.is_empty() {
        return false;
    }
    let literal = if normalize_path(prefix).is_empty() {
        Some("/".to_string())
    } else {
        resolve_operand(prefix, cwd, home)
    };
    literal.is_some_and(|l| vault.starts_with(&l) || touches_vault(&l, vault))
}

/// Characters after which an operand's text is no longer its final path.
const GLOB_CHARS: &[char] = &['*', '?', '[', '{', '$', '`'];

/// Does a sibling segment of the deletion re-point or move a path into the
/// vault (`ln -s <vault> /out/l`, `mv <vault>/x /out/y`, `cp -s …`)? Such a
/// segment is not inert ([`is_inert_segment`], the rule the inside-the-vault
/// path applies), so a deletion that follows can reach the vault through what
/// it made: the physical check reads the disk before the link exists.
fn sibling_reshapes_vault(command: &str, cwd: &str, vault: &str, home: Option<&str>) -> bool {
    for segment in segments_of(command).iter() {
        let (tokens, unquoted_prefix_lens) = executable_tokens_marked(segment);
        let argv = peel_command_runners(&tokens);
        let Some(first) = argv.first() else {
            continue;
        };
        let verb = command_word(first);
        let makes_link = match verb.as_ref() {
            "ln" | "mv" => true,
            "cp" => argv.iter().skip(1).any(|a| {
                a == "--symbolic-link"
                    || a == "--link"
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains(['s', 'l']))
            }),
            _ => false,
        };
        if !makes_link || is_inert_segment(argv, segment) {
            continue;
        }
        let lens = &unquoted_prefix_lens[unquoted_prefix_lens.len() - argv.len()..];
        let mut operands = Vec::new();
        collect_operands(argv, lens, 1, false, false, &mut operands);
        if operands
            .iter()
            .any(|operand| operand_lexically_touches_vault(operand, cwd, vault, home))
        {
            return true;
        }
    }
    false
}

/// Most `canonicalize` calls one command may cost (cadence-hooks#1171).
const MAX_CANONICALIZE_CALLS: usize = 64;

/// With the shell standing OUTSIDE the vault, does any deletion operand name
/// the vault, something inside it, or an ancestor of it? Judged like a
/// deletion inside the vault: lexically first, then through the operand's
/// canonical PARENT, so `rm /outside/link/x` lands in the vault while `rm
/// /outside/link` (removing only the link) does not. Past the canonicalize
/// budget the answer is yes: an unjudged operand is read as inside.
fn operands_touch_vault(
    command: &str,
    cwd: &str,
    vault: &str,
    home: Option<&str>,
    meta: &dyn FileMeta,
) -> bool {
    let mut operands = Vec::new();
    deletion_operands(command, 0, &mut operands);
    // An operand the re-scan allowance left unread may name a vault path.
    if RescanBudget::spent() {
        return true;
    }
    // A relative operand a `cd` earlier in the command moved, judged where
    // it lands (cameronsjo/cadence-hooks#1271).
    operands.extend(moved_deletion_operands(command, cwd, vault, home));
    let mut calls = 0;
    let mut canonical_vault: Option<Option<String>> = None;
    for operand in operands {
        if operand.contains(GLOB_CHARS) {
            if operand_lexically_touches_vault(&operand, cwd, vault, home) {
                return true;
            }
            continue;
        }
        let Some(path) = resolve_operand(&operand, cwd, home) else {
            continue;
        };
        if touches_vault(&path, vault) {
            return true;
        }
        if path.len() > MAX_OPERAND_LEN || path.chars().any(char::is_control) {
            continue;
        }
        let Some((parent, name)) = path.rsplit_once('/') else {
            continue;
        };
        let parent = if parent.is_empty() { "/" } else { parent };
        calls += 1;
        if canonical_vault.is_none() {
            calls += 1;
            canonical_vault = Some(meta.canonical_dir(vault).map(|v| normalize_path(&v)));
        }
        if calls > MAX_CANONICALIZE_CALLS {
            return true;
        }
        let Some(real_parent) = meta.canonical_dir(parent) else {
            continue;
        };
        let real = format!("{}/{name}", normalize_path(&real_parent));
        if touches_vault(&real, vault)
            || canonical_vault
                .as_ref()
                .and_then(Option::as_deref)
                .is_some_and(|v| touches_vault(&real, v))
        {
            return true;
        }
    }
    false
}

/// Bytes of substitution bodies [`moved_deletion_operands`] reads again: a
/// `cd` someone types sits in a short command, and a flood of nested `$(`
/// would otherwise be walked once per level.
const MAX_MOVED_BODY_BYTES: usize = 16 * 1024;

/// Each relative deletion operand that a plain `cd`/`pushd` earlier in the
/// same command moved, rewritten as the absolute path it lands on, so the
/// caller judges it as if typed that way (cameronsjo/cadence-hooks#1271).
///
/// - **Top level and `( … )`**: [`segment_work_dirs`] places each segment, a
///   subshell's `cd` ending at its `)`. A segment it places in a directory
///   other than `cwd` contributes its deletions' relative operands there.
/// - **`$( … )`, backtick and `<( … )` bodies**: each body is placed as a
///   script of its own, so its `cd` moves only its own deletions. A body
///   starts in `cwd` when no top-level segment moved, and in a directory
///   the walk cannot place otherwise, so only an absolute (or
///   `$OBSIDIAN_VAULT`/`$HOME`/`~`) `cd` in it is followed.
/// - `$OBSIDIAN_VAULT` and `$HOME` read as the values the guard holds
///   ([`with_known_dirs`]).
///
/// A deletion after a move the walk cannot place (`cd "$D"`, `cd -`,
/// `popd`), or inside a wrapper script (`bash -c 'cd …; rm …'`), is not
/// listed: it keeps the verdict it had in `cwd`. Nothing here lifts a block;
/// every operand is judged in `cwd` as well.
fn moved_deletion_operands(
    command: &str,
    cwd: &str,
    vault: &str,
    home: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    if command.len() > MAX_JUDGED_COMMAND_LEN
        || !(command.contains("cd") || command.contains("pushd"))
    {
        return out;
    }
    let text = with_known_dirs(command, vault, home);
    let mut budget = MAX_MOVED_BODY_BYTES;
    let mut judged = 0;
    place_deletions(&text, cwd, 0, &mut budget, &mut judged, &mut out);
    out
}

/// [`moved_deletion_operands`] for one script started in `base`.
fn place_deletions(
    script: &str,
    base: &str,
    depth: usize,
    budget: &mut usize,
    judged: &mut usize,
    out: &mut Vec<String>,
) {
    let located = segment_work_dirs(script, base);
    let mut moved = false;
    for segment in &located {
        let dir: &str = &segment.dir;
        if dir == base {
            continue;
        }
        moved = true;
        if dir == UNRESOLVABLE_DIR
            || !DELETING_SPELLINGS
                .iter()
                .any(|verb| segment.raw.contains(verb))
        {
            continue;
        }
        *judged += 1;
        if *judged > MAX_JUDGED_SEGMENTS {
            return;
        }
        let dir = collapse_dots(&normalize_path(dir));
        let mut operands = Vec::new();
        deletion_operands(&segment.raw, 0, &mut operands);
        for operand in operands {
            if looks_absolute(&operand) || operand.starts_with('~') {
                continue;
            }
            let joined = format!("{dir}/{operand}");
            if !out.contains(&joined) {
                out.push(joined);
            }
        }
    }
    if depth >= MAX_NESTED_DEPTH {
        return;
    }
    let body_base = if moved { UNRESOLVABLE_DIR } else { base };
    for body in substitution_bodies(script) {
        if !(body.contains("cd") || body.contains("pushd"))
            || !DELETING_SPELLINGS.iter().any(|verb| body.contains(verb))
        {
            continue;
        }
        let Some(left) = budget.checked_sub(body.len()) else {
            return;
        };
        *budget = left;
        place_deletions(&body, body_base, depth + 1, budget, judged, out);
    }
}

/// `command` with each read of `$OBSIDIAN_VAULT`/`$HOME` (`${…}` too)
/// replaced by the value the guard holds, so the directory walk can place a
/// `cd` to one. Left as written when the command names the variable other
/// than by such a read (it may set it), or the value carries a character the
/// shell treats specially: the walk then cannot place that `cd`.
fn with_known_dirs<'a>(
    command: &'a str,
    vault: &str,
    home: Option<&str>,
) -> std::borrow::Cow<'a, str> {
    let mut out = std::borrow::Cow::Borrowed(command);
    for (name, value) in [("OBSIDIAN_VAULT", Some(vault)), ("HOME", home)] {
        let Some(value) = value.filter(|v| {
            !v.is_empty()
                && v.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ':')
                })
        }) else {
            continue;
        };
        let plain = format!("${name}");
        let braced = format!("${{{name}}}");
        let reads = out.matches(&plain).count() + out.matches(&braced).count();
        if reads == 0 || out.matches(name).count() != reads {
            continue;
        }
        let replaced = out.replace(&braced, value);
        let mut text = String::with_capacity(replaced.len());
        let mut rest = replaced.as_str();
        while let Some(at) = rest.find(&plain) {
            let after = &rest[at + plain.len()..];
            text.push_str(&rest[..at]);
            if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                text.push_str(&plain);
            } else {
                text.push_str(value);
            }
            rest = after;
        }
        text.push_str(rest);
        out = std::borrow::Cow::Owned(text);
    }
    out
}

/// Check if a destructive command targets the Obsidian vault, or if a
/// clobber (`>`, `>|`) redirect would truncate an existing vault file.
fn check_destructive_in_vault(
    command: &str,
    cwd: &str,
    vault: &str,
    meta: &dyn FileMeta,
) -> CheckResult {
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty());
    check_destructive_in_vault_at(command, cwd, vault, home.as_deref(), meta)
}

/// [`check_destructive_in_vault`] with the home directory passed in.
fn check_destructive_in_vault_at(
    command: &str,
    cwd: &str,
    vault: &str,
    home: Option<&str>,
    meta: &dyn FileMeta,
) -> CheckResult {
    // Normalize both sides before the prefix test: the vault root comes from
    // `OBSIDIAN_VAULT` (which on Windows may carry backslashes) while `cwd` and
    // the command's path args come from the hook payload. Without normalizing
    // both, a `C:\vault` env value never matches a `C:/vault` hook path.
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");

    // A flood the walk gives up on is not judged operand by operand: expanding
    // it is the cost, so it is answered from a linear read of its text.
    match eval_flood(command) {
        Some(true) => {
            return CheckResult::block(format!(
                "🚫 Obsidian vault detected. This command nests `eval` past what the guard \
                 can read and may delete or truncate vault files.\n\n\
                 .trash/ is Obsidian's built-in recycle bin. Move files there instead:\n  \
                 mkdir -p {vault}/.trash && mv <file> {vault}/.trash/"
            ));
        }
        Some(false) => return CheckResult::allow(),
        None => {}
    }

    let _rescan = RescanBudget::arm();
    if is_destructive(command) {
        let cwd_in_vault = cwd == vault || cwd.starts_with(&vault_prefix);
        let mut in_vault = cwd_in_vault && !deletions_all_outside_vault(command, &vault, meta);

        if !cwd_in_vault {
            // Quote-aware tokenize (not split_whitespace): a vault path with
            // spaces must be quoted (`"…/Field Reports/old.md"`), and
            // split_whitespace both shreds it across tokens and leaves a
            // leading `"` that defeats `looks_absolute`. tokenize keeps a
            // quoted path in one token and strips the quotes, so the
            // absolute/in-vault test sees the real path (#82).
            //
            // A word carrying a substitution is also read as the words of its
            // source, grouping syntax blanked out. The tokenizer keeps an
            // unquoted `$(echo /vault/x)` as ONE word (cadence-hooks#1106),
            // and `"$(echo /vault/x)"` always was one, but the vault path the
            // `rm` is handed sits inside it. One re-read per word keeps this
            // linear, where re-tokenizing every nested `command_segments`
            // body multiplied the work by the nesting depth.
            let words = tokenize(command);
            let inner_words: Vec<String> = words
                .iter()
                .filter(|word| carries_substitution(word))
                .flat_map(|word| tokenize(&word.replace(['(', ')', '`'], " ")))
                .collect();
            for part in words.into_iter().chain(inner_words) {
                let part = normalize_path(&part);
                if looks_absolute(&part) && (part == vault || part.starts_with(&vault_prefix)) {
                    in_vault = true;
                    break;
                }
            }
            // The words above catch a named vault path. A target that reaches
            // the vault by being an ancestor of it (`rm -rf ~/Documents`), a
            // relative climb, or a symlink parent needs the operands resolved
            // (cadence-hooks#1171).
            if !in_vault {
                in_vault = operands_touch_vault(command, &cwd, &vault, home, meta)
                    || sibling_reshapes_vault(command, &cwd, &vault, home);
            }
        }

        if in_vault {
            return CheckResult::block(format!(
                "🚫 Obsidian vault detected. This deletes or truncates vault files, \
                 bypassing recoverability.\n\n\
                 .trash/ is Obsidian's built-in recycle bin. Move files there instead:\n  \
                 mkdir -p {vault}/.trash && mv <file> {vault}/.trash/\n\n\
                 This preserves recoverability within Obsidian."
            ));
        }
    }

    // A `>`/`>|` redirect truncates its target the moment the shell opens it
    // for writing — even when the command that follows never runs. `>>`
    // (append) and a target that doesn't exist yet (new-file creation) are
    // not destructive, so only an existing vault file behind a clobber
    // redirect is blocked (#192). `command_segments` (not `split_segments`)
    // so a redirect hidden inside a `sh -c`/`bash -c` wrapper or a `$(…)`/
    // backtick substitution is also seen — the sibling secret-writes guard
    // uses the same wrapper-unwrapping splitter for the same reason.
    //
    // Each distinct target is judged once: a 200 KB flood of `>(` reads as
    // 100 000 redirects to the same word in every segment the body walk
    // lists, and resolving each again put the guard past its deadline, which
    // fails open (cameronsjo/cadence-hooks#1233). The verdict for a target
    // does not depend on which segment named it.
    let mut judged = std::collections::HashSet::new();
    for segment in segments_of(command).iter() {
        for target in clobber_redirect_targets(segment)
            .into_iter()
            .flat_map(|target| with_brace_expansion(&target))
        {
            if !judged.insert(target.clone()) {
                continue;
            }
            if let Some(resolved) = resolve_in_vault(&target, &cwd, &vault, &vault_prefix)
                && meta.exists(&resolved)
            {
                return CheckResult::block(format!(
                    "🚫 Obsidian vault detected. This `>` redirect truncates an existing vault \
                     file, bypassing recoverability.\n\n\
                     .trash/ is Obsidian's built-in recycle bin. Move the file there before \
                     overwriting it:\n  \
                     mkdir -p {vault}/.trash && mv {resolved} {vault}/.trash/\n\n\
                     Use `>>` to append, or target a new filename, to keep existing content."
                ));
            }
        }
    }

    CheckResult::allow()
}

/// A redirect target plus the names bash brace-expands it into. The target
/// comes back from the redirect parser as one unexpanded word, but bash
/// expands `>note.m{d..d}` to `note.md` before opening it. The written name is
/// judged as well as each expansion, so a quoted `"a{b,c}"` (never expanded by
/// bash) is still judged as written; an extra candidate can only add a block
/// on a file that exists in the vault (cameronsjo/cadence-hooks#1115).
fn with_brace_expansion(target: &str) -> Vec<String> {
    let mut names = vec![target.to_string()];
    if target.contains('{') {
        for word in tokenize(target) {
            if !names.contains(&word) {
                names.push(word);
            }
        }
    }
    names
}

/// Judge a harness deletion primitive that named a path directly — a normalized
/// Codex `apply_patch` `*** Delete File:`, which carries `operation: "delete"`
/// and no command for the command scanner to read.
///
/// **`rename-source` is deliberately not routed here.** `normalized_inputs` tags
/// the source half of `*** Update File: X` + `*** Move to: Y` (and an
/// `mcp__*move*`/`*rename*` call) as `"rename-source"`, and a move empties `X`
/// much as a delete does — but the block below *prescribes a move* ("Move it
/// into <vault>/.trash/"), and under Codex that remedy is spelled as exactly
/// such a rename, whose source is the in-vault path that just blocked. Judging
/// renames as deletions would leave a Codex session unable to comply with the
/// message it was just shown. `mv` is likewise outside the command scanner's
/// verb set on the Bash route, so the two harnesses agree. Same call, same
/// reasoning as the deleted delete guard's own path judgment
/// (cameronsjo/cadence-ecosystem#582; the code is in tag `v0.105.0`); pinned by
/// `normalized_patch_rename_inside_vault_is_not_a_delete`.
fn check_delete_in_vault(path: &str, cwd: &str, vault: &str) -> CheckResult {
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");
    if let Some(resolved) = resolve_in_vault(path, &cwd, &vault, &vault_prefix) {
        return CheckResult::block(format!(
            "🚫 Obsidian vault detected. This file operation deletes a vault file, \
             bypassing recoverability.\n\n\
             Move it into {vault}/.trash/ instead of deleting {resolved}."
        ));
    }
    CheckResult::allow()
}

/// Judge a `Write` whose content is empty or whitespace-only (cadence-hooks#534).
///
/// A `Write` replaces the file's whole content, so an empty one zeroes an
/// existing file exactly as `truncate -s0` or a `>` redirect does, and it is
/// judged the same way `rm` of that file is: blocked when the target resolves
/// inside the vault. Three shapes are deliberately untouched: a `Write` with
/// real content (an ordinary note update), a `Write` to a file that does not
/// exist yet (creating an empty note deletes nothing), and a target outside the
/// vault. A target reached through a symlink parent that lands in the vault is
/// judged by its physical location, like the operand walk above. "Whitespace"
/// is Unicode `White_Space`, so a lone newline or NBSP counts as empty: the
/// note is gone either way. A substantially-shorter overwrite is NOT judged;
/// that needs a size heuristic and would be noisy on legitimate rewrites.
fn check_truncate_in_vault(
    path: &str,
    content: &str,
    cwd: &str,
    vault: &str,
    meta: &dyn FileMeta,
) -> CheckResult {
    if !content.trim().is_empty() {
        return CheckResult::allow();
    }
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");
    let target = normalize_path(path);
    let absolute = if looks_absolute(&target) {
        target
    } else {
        normalize_path(&format!("{cwd}/{target}"))
    };
    let lexical = collapse_dots(&absolute);
    let resolved = if lexical.starts_with(&vault_prefix) {
        Some(lexical)
    } else {
        // A symlinked parent can land the write in the vault from outside it.
        meta.physical(&lexical).filter(|physical| {
            std::iter::once(vault.clone())
                .chain(meta.physical(&vault))
                .any(|v| physical.starts_with(&format!("{v}/")))
        })
    };
    match resolved {
        Some(resolved) if meta.exists(&resolved) => CheckResult::block(format!(
            "🚫 Obsidian vault detected. This `Write` carries no content, so it empties an \
             existing vault file, bypassing recoverability.\n\n\
             .trash/ is Obsidian's built-in recycle bin. Move the file there instead:\n  \
             mkdir -p {vault}/.trash && mv {resolved} {vault}/.trash/\n\n\
             Write real content to keep the note, or target a new filename."
        )),
        _ => CheckResult::allow(),
    }
}

/// Blocks destructive commands (rm, unlink, shred, truncate, or find -delete)
/// inside an Obsidian vault and suggests `.trash/` instead.
pub struct ObsidianTrashGuard;

impl Check for ObsidianTrashGuard {
    fn name(&self) -> &str {
        "obsidian-trash-guard"
    }

    fn refuses_unread_commands(&self) -> bool {
        true
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        match std::env::var("OBSIDIAN_VAULT") {
            Ok(vault) if !vault.is_empty() => judge(input, &vault, &RealFs),
            _ => CheckResult::allow(),
        }
    }
}

/// The guard's whole judgement for `vault`, with existence answered by `meta`.
/// [`ObsidianTrashGuard::run`] is this over the process environment and the
/// real filesystem; the liveness check drives it over a fake one so every route
/// is probed through the same dispatch a hook call takes.
pub(crate) fn judge(input: &HookInput, vault: &str, meta: &dyn FileMeta) -> CheckResult {
    let cwd = input.cwd.as_deref().unwrap_or("/");
    if input.operation() == Some("delete")
        && let Some(path) = input.file_path()
    {
        let result = check_delete_in_vault(&path, cwd, vault);
        if result.outcome == cadence_hooks_core::Outcome::Block {
            return result;
        }
    }

    if input.normalized_tool_name() == Some("Write")
        && let (Some(path), Some(content)) = (input.file_path(), input.content())
    {
        return check_truncate_in_vault(&path, content, cwd, vault, meta);
    }

    input.command().map_or_else(CheckResult::allow, |command| {
        check_destructive_in_vault(command, cwd, vault, meta)
    })
}

/// The one lock for every test that sets `OBSIDIAN_VAULT` in this crate.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn with_vault_env(f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let previous = std::env::var_os("OBSIDIAN_VAULT");
        // SAFETY: every OBSIDIAN_VAULT mutation in this crate is serialized by
        // ENV_LOCK and restored before the lock is released.
        unsafe { std::env::set_var("OBSIDIAN_VAULT", "/vault") };
        f();
        match previous {
            Some(value) => unsafe { std::env::set_var("OBSIDIAN_VAULT", value) },
            None => unsafe { std::env::remove_var("OBSIDIAN_VAULT") },
        }
    }

    fn make_bash_with_cwd(command: &str, cwd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                command: Some(command.into()),
                ..Default::default()
            }),
            cwd: Some(cwd.into()),
            ..Default::default()
        }
    }

    /// Fake existence probe for redirect-truncation tests: reports a path as
    /// existing iff it was explicitly seeded, so tests never touch real disk.
    #[derive(Default)]
    struct FakeFs(HashSet<String>);

    impl FakeFs {
        fn with(paths: &[&str]) -> Self {
            FakeFs(paths.iter().map(|s| s.to_string()).collect())
        }
    }

    impl FileMeta for FakeFs {
        fn exists(&self, path: &str) -> bool {
            self.0.contains(path)
        }
    }

    /// cadence-hooks#839: with the shell standing in the vault, a deletion is
    /// judged by where its operands point, not where the shell stands. Every
    /// row that allows names only absolute paths outside `/vault`; every row
    /// that blocks carries at least one operand the text cannot place outside
    /// it, or a destructive shape that is never judged operand by operand.
    #[test]
    fn deletion_from_vault_cwd_is_judged_by_its_operands() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let cases: &[(&str, cadence_hooks_core::Outcome)] = &[
            // The report, verbatim.
            ("command rm /tmp/l5probe/probe.py /tmp/b652/cases.py", Allow),
            ("rm -rf /tmp/build", Allow),
            ("rm -f -- /tmp/a /home/user/b", Allow),
            ("rm /tmp/a 2>/dev/null", Allow),
            ("rm /tmp/a > /dev/null", Allow),
            ("unlink /tmp/a", Allow),
            ("shred -u /tmp/secret", Allow),
            ("truncate -s0 /tmp/log", Allow),
            ("sudo rm /tmp/a", Allow),
            ("rm /tmp/a && rm /tmp/b", Allow),
            ("rm '/tmp/My File.md'", Allow),
            ("rm /tmp/./a", Allow),
            // A sibling that merely shares the vault's name prefix.
            ("rm /vault2/x", Allow),
            // Controls: the operand is, or may be, in the vault.
            ("rm note.md", Block),
            ("rm ./note.md", Block),
            ("rm /vault/note.md", Block),
            ("rm /vault", Block),
            ("rm -rf /", Block),
            ("rm /tmp/a note.md", Block),
            ("rm /tmp/a /vault/x", Block),
            ("rm /tmp/../vault/note.md", Block),
            (r"rm /tmp/\.\./vault/note.md", Block),
            ("rm /tmp/$X", Block),
            ("rm $X", Block),
            ("rm \"$X\"", Block),
            ("rm /tmp/*", Block),
            ("rm /va*/note.md", Block),
            ("rm /v?ult/note.md", Block),
            ("rm /[v]ault/note.md", Block),
            ("rm /{tmp/a,vault/x}", Block),
            ("rm /tmp/$(echo x)", Block),
            ("rm /tmp/a $(echo note.md)", Block),
            ("rm /tmp/a `echo note.md`", Block),
            ("rm \" /tmp/a\"", Block),
            ("rm ''", Block),
            ("rm ~/x", Block),
            // An option after an operand is a file under strict POSIX.
            ("rm /tmp/a -f", Block),
            ("rm -- -f", Block),
            // A quoted redirect-shaped word is a file `rm` deletes.
            ("rm /tmp/a '>note.md'", Block),
            // `-s`'s size and `-r`'s reference are not files truncated
            // (cadence-hooks#1172); every operand still is.
            ("truncate -s 0 /tmp/log", Allow),
            ("truncate --size 0 /tmp/log", Allow),
            ("truncate --size=0 /tmp/log", Allow),
            ("truncate -s0 /tmp/log", Allow),
            ("truncate -cs 0 /tmp/log", Allow),
            ("truncate -s +10K /tmp/log", Allow),
            ("truncate -r note.md /tmp/log", Allow),
            ("truncate --reference note.md /tmp/log", Allow),
            ("truncate --ref note.md /tmp/log", Allow),
            ("truncate -s 0 -r note.md /tmp/a /tmp/b", Allow),
            ("sudo truncate -s 0 /tmp/log", Allow),
            ("truncate -s 0 note.md", Block),
            ("truncate -s 0 /tmp/log note.md", Block),
            ("truncate -s 0 /vault/note.md", Block),
            ("truncate -s 0 -- note.md", Block),
            ("truncate -r /tmp/ref note.md", Block),
            ("truncate -r /tmp/ref -s 0 note.md", Block),
            ("truncate -s 0 -r /tmp/ref", Allow),
            ("truncate -s 0", Allow),
            ("truncate -s", Allow),
            ("truncate -rs 0 note.md", Block),
            ("truncate -cr note.md /tmp/log", Allow),
            ("truncate -s 0 $X", Block),
            ("truncate -s 0 /tmp/log; rm note.md", Block),
            // The size or reference of another verb is still an operand.
            ("rm -s 0 /tmp/a", Block),
            ("shred -n 3 /tmp/a", Block),
            ("rm /tmp/a; rm note.md", Block),
            // Shapes never judged operand by operand keep the cwd verdict.
            ("git rm /tmp/a", Block),
            ("echo note.md | xargs rm", Block),
            ("xargs rm /tmp/a", Block),
            ("find /tmp/x -delete", Block),
            (r"find /tmp/x -exec rm {} \;", Block),
            ("eval rm /tmp/a", Block),
            ("sh -c 'eval rm /tmp/a'", Block),
            (r"find /tmp -exec sh -c 'rm /tmp/a' \;", Block),
            // A wrapper is not inert, whatever its script says.
            ("sh -c 'rm /tmp/a'", Block),
            ("sh -c 'rm note.md'", Block),
            ("bash -c 'rm \"$1\"' _ note.md", Block),
            ("bash -c 'cd /tmp && rm a'", Block),
            // A sibling that could re-point an operand before the deletion
            // runs keeps the block; only inert siblings pass.
            ("ln -s /vault /tmp/l; rm -rf /tmp/l/", Block),
            ("ln -s /vault /tmp/l && rm -rf /tmp/l/note.md", Block),
            ("mv /vault/note.md /tmp/y; rm /tmp/y", Block),
            ("cd /tmp && rm -rf x", Block),
            ("cd /tmp && rm -rf /tmp/x", Block),
            ("pushd /tmp; rm /tmp/x", Block),
            ("mkdir -p /tmp/d && rm -r /tmp/d", Block),
            ("cp -r /vault /tmp/v; rm -r /tmp/v", Block),
            ("my_func; rm /tmp/x", Block),
            ("echo $(ln -s /vault /tmp/l); rm -rf /tmp/l/", Block),
            ("echo x > /tmp/f; rm /tmp/a", Block),
            ("ls /tmp; rm /tmp/x.txt", Allow),
            ("echo done && rm /tmp/a", Allow),
            ("test -e /tmp/a && rm /tmp/a", Allow),
            ("[ -e /tmp/a ] && rm /tmp/a", Allow),
            ("cat /tmp/list | rm /tmp/a", Allow),
            ("pwd; printf 'x'; true; :; rm /tmp/a", Allow),
        ];
        for &(command, expected) in cases {
            let result =
                check_destructive_in_vault(command, "/vault", "/vault", &FakeFs::default());
            assert_eq!(result.outcome, expected, "cwd=/vault: {command}");
        }
        // The same allowed shapes from a vault SUBDIRECTORY.
        let result =
            check_destructive_in_vault("rm /tmp/a", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, Allow);
    }

    #[test]
    fn deletion_from_vault_cwd_blocks_an_ancestor_of_the_vault() {
        for command in ["rm -rf /home/me", "rm -rf /home", "rm -rf /home/me/"] {
            let result = check_destructive_in_vault(
                command,
                "/home/me/Vault",
                "/home/me/Vault",
                &FakeFs::default(),
            );
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Block,
                "{command}"
            );
        }
        let result = check_destructive_in_vault(
            "rm -rf /home/me/other",
            "/home/me/Vault",
            "/home/me/Vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn deletion_from_vault_cwd_past_a_size_cap_keeps_blocking() {
        let at_cap = format!("rm {}", vec!["/tmp/a"; MAX_JUDGED_OPERANDS].join(" "));
        let past_cap = format!("{at_cap} /tmp/a");
        let long_operand = format!("rm /{}", "a/".repeat(MAX_OPERAND_LEN / 2));
        assert_eq!(
            check_destructive_in_vault(&long_operand, "/vault", "/vault", &FakeFs::default())
                .outcome,
            cadence_hooks_core::Outcome::Block
        );
        let too_deep = format!("rm /{}x", "a/".repeat(MAX_OPERAND_DEPTH));
        assert_eq!(
            check_destructive_in_vault(&too_deep, "/vault", "/vault", &FakeFs::default()).outcome,
            cadence_hooks_core::Outcome::Block
        );
        let at_depth = format!("rm /{}x", "a/".repeat(MAX_OPERAND_DEPTH - 1));
        assert_eq!(
            check_destructive_in_vault(&at_depth, "/vault", "/vault", &FakeFs::default()).outcome,
            cadence_hooks_core::Outcome::Allow
        );
        let at_len = format!("rm /{}", "a".repeat(MAX_OPERAND_LEN - 1));
        assert_eq!(
            check_destructive_in_vault(&at_len, "/vault", "/vault", &FakeFs::default()).outcome,
            cadence_hooks_core::Outcome::Allow
        );
        let too_long = format!("rm {}", vec!["/tmp/abcdefghij"; 1200].join(" "));
        assert!(too_long.len() > MAX_JUDGED_COMMAND_LEN);
        assert_eq!(
            check_destructive_in_vault(&too_long, "/vault", "/vault", &FakeFs::default()).outcome,
            cadence_hooks_core::Outcome::Block
        );
        let many_segments = "echo x; ".repeat(MAX_JUDGED_SEGMENTS) + "rm /tmp/a";
        assert_eq!(
            check_destructive_in_vault(&many_segments, "/vault", "/vault", &FakeFs::default())
                .outcome,
            cadence_hooks_core::Outcome::Block
        );
        let fs = FakeFs::default();
        assert_eq!(
            check_destructive_in_vault(&at_cap, "/vault", "/vault", &fs).outcome,
            cadence_hooks_core::Outcome::Allow
        );
        assert_eq!(
            check_destructive_in_vault(&past_cap, "/vault", "/vault", &fs).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    /// A symlink outside the vault that points into it is judged by where it
    /// lands, on real disk: the lexical path says "outside", the physical one
    /// says "vault".
    // Embeds native paths in a POSIX shell string or uses Unix-only temp roots;
    // Windows paths lose their backslashes to shell escaping, as in real bash.
    #[cfg(unix)]
    #[test]
    fn deletion_from_vault_cwd_through_a_symlink_into_the_vault_blocks() {
        use cadence_hooks_core::git_fixtures::Scratch;
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-fixtures");
        let scratch = Scratch::new(&root, "trash-guard-839");
        let base = scratch
            .path()
            .canonicalize()
            .expect("scratch canonicalizes");
        let vault = base.join("vault");
        let outside = base.join("outside");
        std::fs::create_dir_all(vault.join("notes")).expect("vault dir");
        std::fs::create_dir_all(&outside).expect("outside dir");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&vault, outside.join("link")).expect("symlink");
            std::os::unix::fs::symlink(&vault, base.join("vault-alias")).expect("alias");
        }
        let vault_s = vault.to_string_lossy().into_owned();
        let outside_s = outside.to_string_lossy().into_owned();
        #[cfg(unix)]
        let alias_s = base.join("vault-alias").to_string_lossy().into_owned();
        let judge = |command: &str, vault: &str| {
            check_destructive_in_vault(command, vault, vault, &RealFs).outcome
        };
        use cadence_hooks_core::Outcome::Allow;
        #[cfg(unix)]
        use cadence_hooks_core::Outcome::Block;
        assert_eq!(judge(&format!("rm {outside_s}/plain.txt"), &vault_s), Allow);
        #[cfg(unix)]
        {
            assert_eq!(
                judge(&format!("rm {outside_s}/link/note.md"), &vault_s),
                Block
            );
            // A link the same command creates does not exist at hook time.
            assert_eq!(
                judge(
                    &format!("ln -s {vault_s} {outside_s}/new; rm -rf {outside_s}/new/"),
                    &vault_s
                ),
                Block
            );
            // A dangling link resolves through its parent, not to nothing.
            std::os::unix::fs::symlink(base.join("gone"), outside.join("dangling"))
                .expect("dangling");
            assert_eq!(judge(&format!("rm {outside_s}/dangling"), &vault_s), Allow);
            assert_eq!(
                judge(&format!("rm -r {outside_s}/link/notes"), &vault_s),
                Block
            );
            // The vault named through a symlinked path, the operand spelled
            // physically.
            assert_eq!(judge(&format!("rm {vault_s}/note.md"), &alias_s), Block);
            assert_eq!(judge(&format!("rm {outside_s}/plain.txt"), &alias_s), Allow);
        }
    }

    #[test]
    fn verbatim_prefix_is_stripped_from_canonical_output() {
        for (raw, want) in [
            (r"\\?\C:\Users\me\Vault", r"C:\Users\me\Vault"),
            (r"\\?\UNC\srv\share\Vault", r"\\srv\share\Vault"),
            (r"C:\Users\me", r"C:\Users\me"),
            ("/home/me/Vault", "/home/me/Vault"),
            (r"\\srv\share", r"\\srv\share"),
            ("", ""),
        ] {
            assert_eq!(strip_verbatim_prefix(raw), want, "{raw}");
        }
    }

    /// cadence-hooks#1171: with the shell OUTSIDE the vault, a deletion whose
    /// operand is the vault, inside it, or an ancestor of it is a vault
    /// deletion; everyday deletions stay allowed.
    #[test]
    fn deletion_from_outside_cwd_is_judged_by_its_resolved_operands() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let vault = "/home/me/Documents/Vault";
        let cases: &[(&str, &str, cadence_hooks_core::Outcome)] = &[
            ("/home/me", "rm -rf ~/Documents", Block),
            ("/home/me", "rm -rf ~/Documents/", Block),
            ("/home/me", "rm -rf ~", Block),
            ("/home/me", "rm -rf Documents", Block),
            ("/home/me", "rm -rf ./Documents/../Documents", Block),
            ("/home/me/Documents", "rm -rf .", Block),
            ("/home/me/Documents", "rm -r ../Documents", Block),
            ("/home/me/Documents/x", "rm -rf ..", Block),
            ("/home/me/Documents", "rm -rf Vault", Block),
            ("/home/me/Documents", "rm -rf Vault/note.md", Block),
            ("/home/me", "rm -rf /home/me/Documents", Block),
            ("/home/me", "rm -rf /home", Block),
            ("/home/me", "rm -rf /", Block),
            ("/home/me", "sudo rm -rf ~/Documents", Block),
            ("/home/me", "unlink ~/Documents", Block),
            ("/home/me", "git rm -r ~/Documents", Block),
            ("/home/me", "find ~/Documents -delete", Block),
            ("/home/me", "find ~/Documents -exec rm {} +", Block),
            ("/home/me", "eval rm -rf ~/Documents", Block),
            ("/home/me", "sh -c 'rm -rf ~/Documents'", Block),
            ("/home/me", "rm -f -- ~/Documents", Block),
            ("/home/me", "rm -rf /tmp/x ~/Documents", Block),
            // Everyday deletions stay allowed.
            ("/home/me/project", "rm -rf target/", Allow),
            ("/home/me/project", "rm /tmp/x", Allow),
            ("/home/me", "rm -rf ~/Downloads", Allow),
            ("/home/me", "rm -rf ~/Documents2", Allow),
            ("/home/me", "rm -rf ~/Documents/Vault2", Allow),
            ("/home/me/Documents", "rm -rf Other", Allow),
            ("/home/me/Documents", "rm -rf ../Downloads", Allow),
            ("/home/me/Documents", "rm Vault2/x", Allow),
            ("/home/me/project", "rm -rf ~/.cache/x", Allow),
            ("/home/me", "rm -rf ~other/Documents", Allow),
            // Words that are not deletion operands are not judged.
            ("/home/me", "echo ~/Documents", Allow),
            ("/home/me", "ls ~/Documents; rm x", Allow),
            ("/home/me", "rm -rf x > ~/Documents.log", Allow),
        ];
        for &(cwd, command, expected) in cases {
            let result = check_destructive_in_vault_at(
                command,
                cwd,
                vault,
                Some("/home/me"),
                &FakeFs::default(),
            );
            assert_eq!(result.outcome, expected, "cwd={cwd}: {command}");
        }
        // No HOME: a tilde operand cannot be resolved, so it is not judged.
        let result = check_destructive_in_vault_at(
            "rm -rf ~/Documents",
            "/home/me",
            vault,
            None,
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, Allow);
    }

    /// Fake canonicalizer: maps a directory to its canonical form, or reports
    /// it absent; counts calls so the budget is observable.
    struct LinkFs {
        map: std::collections::HashMap<String, String>,
        calls: std::cell::Cell<usize>,
    }

    impl FileMeta for LinkFs {
        fn exists(&self, path: &str) -> bool {
            self.map.contains_key(path)
        }
        fn canonical_dir(&self, path: &str) -> Option<String> {
            self.calls.set(self.calls.get() + 1);
            self.map.get(path).cloned()
        }
    }

    #[test]
    fn deletion_through_a_symlinked_parent_is_judged_by_the_canonical_parent() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let fs = LinkFs {
            map: [
                ("/vault", "/vault"),
                ("/outside/link", "/vault"),
                ("/outside/link/notes", "/vault/notes"),
                ("/outside", "/outside"),
                ("/outside/plain", "/outside/plain"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            calls: std::cell::Cell::new(0),
        };
        let judge = |command: &str| {
            check_destructive_in_vault_at(command, "/work", "/vault", None, &fs).outcome
        };
        assert_eq!(judge("rm /outside/link/x"), Block);
        assert_eq!(judge("rm -r /outside/link/notes/x"), Block);
        assert_eq!(judge("rm -r /outside/link/notes"), Block);
        // `rm link` removes only the link.
        assert_eq!(judge("rm /outside/link"), Allow);
        assert_eq!(judge("rm /outside/plain/x"), Allow);
        // A parent that does not exist is never stat-ed into a verdict.
        assert_eq!(judge("rm /outside/missing/x"), Allow);
        // Budget: 64 calls in total; one past it reads as inside.
        let many = |n: usize| format!("rm {}", vec!["/outside/plain/x"; n].join(" "));
        fs.calls.set(0);
        assert_eq!(judge(&many(63)), Allow);
        assert_eq!(fs.calls.get(), 64);
        assert_eq!(judge(&many(64)), Block);
    }

    /// The same, on real disk: an outside symlink into the vault, judged by its
    /// canonical parent, with the fixtures kept out of `/tmp`.
    // Embeds native paths in a POSIX shell string or uses Unix-only temp roots;
    // Windows paths lose their backslashes to shell escaping, as in real bash.
    #[cfg(unix)]
    #[test]
    fn deletion_from_outside_cwd_through_a_real_symlink_blocks() {
        use cadence_hooks_core::git_fixtures::Scratch;
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-fixtures");
        let scratch = Scratch::new(&root, "trash-guard-1171");
        let base = scratch
            .path()
            .canonicalize()
            .expect("scratch canonicalizes");
        let vault = base.join("docs").join("vault");
        let outside = base.join("outside");
        std::fs::create_dir_all(vault.join("notes")).expect("vault dir");
        std::fs::create_dir_all(&outside).expect("outside dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&vault, outside.join("link")).expect("symlink");
        let vault_s = vault.to_string_lossy().into_owned();
        let outside_s = outside.to_string_lossy().into_owned();
        let docs_s = base.join("docs").to_string_lossy().into_owned();
        let judge = |command: &str| {
            check_destructive_in_vault_at(command, &outside_s, &vault_s, None, &RealFs).outcome
        };
        use cadence_hooks_core::Outcome::{Allow, Block};
        assert_eq!(judge("rm plain.txt"), Allow);
        assert_eq!(judge(&format!("rm -rf {docs_s}")), Block);
        assert_eq!(judge("rm -rf ../docs"), Block);
        #[cfg(unix)]
        {
            assert_eq!(judge("rm link/notes/x.md"), Block);
            assert_eq!(judge("rm link"), Allow);
        }
    }

    #[test]
    fn deletion_from_outside_cwd_judges_a_glob_by_its_literal_prefix() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let vault = "/home/me/Documents/Vault";
        for (cwd, command, expected) in [
            ("/home/me", "rm -rf ~/Doc*", Block),
            ("/home/me", "rm -rf ~/Documents/*", Block),
            ("/home/me", "rm -rf ~/Documents/Vault/*.md", Block),
            ("/home/me", "rm -rf ~/D?cuments", Block),
            ("/home/me", "rm -rf /home/me/Documents/V*", Block),
            ("/home/me", "rm -rf /*", Block),
            ("/home/me", "rm -rf /home/*", Block),
            ("/home/me", "rm -rf Doc*", Block),
            ("/home/me", "rm -rf ~/Documents/{Vault,x}", Block),
            ("/home/me", "rm -rf ~/Documents/$X", Block),
            ("/home/me", "rm -rf ~/Downloads/*", Allow),
            ("/home/me", "rm -rf ~/Documents2/*", Allow),
            ("/home/me", "rm -rf ~/Documents/Other/*", Allow),
            ("/home/me/project", "rm -rf D*", Allow),
            ("/tmp", "rm -rf /tmp/*", Allow),
            // An empty literal prefix keeps the verdict the rest of the scan reached.
            ("/home/me", "rm $X", Allow),
            ("/home/me", "rm *.log", Allow),
        ] {
            let result = check_destructive_in_vault_at(
                command,
                cwd,
                vault,
                Some("/home/me"),
                &FakeFs::default(),
            );
            assert_eq!(result.outcome, expected, "cwd={cwd}: {command}");
        }
    }

    #[test]
    fn deletion_from_outside_cwd_after_a_link_or_move_of_the_vault_blocks() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        for (command, expected) in [
            ("ln -s /vault /out/l; rm /out/l/x", Block),
            ("ln -s /vault/notes /out/l && rm -r /out/l/x", Block),
            ("mv /vault/note.md /out/y; rm /out/y", Block),
            ("cp -s /vault/note.md /out/y; rm /out/y", Block),
            ("cp -rs /vault /out/y; rm -r /out/y/x", Block),
            ("ln -s / /out/l; rm /out/l/x", Block),
            // Links and moves that never touch the vault leave the deletion alone.
            ("ln -s /tmp/a /out/l; rm /out/l", Allow),
            ("mv /tmp/a /tmp/b; rm /tmp/b", Allow),
            ("cp /tmp/a /out/y; rm /out/y", Allow),
            ("ln -s /vault /out/l", Allow),
        ] {
            let result =
                check_destructive_in_vault_at(command, "/work", "/vault", None, &FakeFs::default());
            assert_eq!(result.outcome, expected, "{command}");
        }
    }

    #[test]
    fn an_eval_flood_is_answered_without_expanding_it() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let start = std::time::Instant::now();
        let flood = "eval ".repeat(30_000);
        for (command, expected) in [
            (format!("{flood}rm x"), Block),
            (format!("{flood}find . -delete"), Block),
            (format!("{flood}echo hi > f"), Block),
            (format!("{flood}echo hi"), Allow),
        ] {
            for cwd in ["/home/me", "/vault"] {
                let result = check_destructive_in_vault_at(
                    &command,
                    cwd,
                    "/vault",
                    None,
                    &FakeFs::default(),
                );
                assert_eq!(result.outcome, expected, "cwd={cwd}");
            }
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn non_rm_command_allowed() {
        let result = check_destructive_in_vault("ls -la", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_outside_vault_allowed() {
        let result =
            check_destructive_in_vault("rm temp.txt", "/home/user", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    /// cadence-hooks#1142: a literal `echo`/`printf` substitution that spells
    /// the verb or the operand is judged as the `rm` it runs.
    #[test]
    fn rm_spelled_by_a_literal_substitution_is_judged() {
        for command in [
            "$(echo rm) note.md",
            "`echo rm` note.md",
            "$(printf rm) -rf note.md",
            "$(echo rm -rf /vault/n.md)",
            "eval \"$(echo 'rm note.md')\"",
            "bash -c \"$(echo 'rm note.md')\"",
            "r$(echo m) note.md",
        ] {
            let result =
                check_destructive_in_vault(command, "/vault/notes", "/vault", &FakeFs::default());
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Block,
                "{command}"
            );
        }
        for command in [
            "$(echo ls) note.md",
            "$(echo echo) rm",
            "echo $(echo rm) note.md",
        ] {
            let result =
                check_destructive_in_vault(command, "/vault/notes", "/vault", &FakeFs::default());
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "{command}"
            );
        }
    }

    #[test]
    fn rm_of_a_vault_path_handed_through_a_substitution_blocked() {
        // cadence-hooks#1106 keeps an unquoted substitution as one word, so
        // the vault path is read from the substitution's own segment.
        for command in [
            "rm -rf $(echo /vault/n.md)",
            "rm -rf `echo /vault/n.md`",
            "rm -rf \"$(echo /vault/n.md)\"",
            "rm -rf $(realpath /vault/notes)/n.md",
        ] {
            let result =
                check_destructive_in_vault(command, "/home/user", "/vault", &FakeFs::default());
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Block,
                "{command}"
            );
        }
        let result = check_destructive_in_vault(
            "rm -rf $(echo /elsewhere/n.md)",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn clobber_of_a_glued_brace_name_judges_the_file_bash_writes() {
        // cadence-hooks#1092: `> note}` writes `note}`, not `note`.
        let fs = FakeFs(["/vault/note".to_string()].into_iter().collect());
        let result = check_destructive_in_vault("echo x > note}", "/vault", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        let fs = FakeFs(["/vault/note}".to_string()].into_iter().collect());
        let result = check_destructive_in_vault("echo x > note}", "/vault", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn case_folded_rm_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("RM note.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn case_folded_rm_runs_through_the_guard_entry_point() {
        with_vault_env(|| {
            let result = ObsidianTrashGuard.run(&make_bash_with_cwd("RM note.md", "/vault/notes"));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        });
    }

    /// Drive a command through the guard's real entry point and report the
    /// outcome, so the differential table below tests what a hook payload
    /// actually reaches rather than a helper's internals.
    fn outcome_in_vault(command: &str) -> cadence_hooks_core::Outcome {
        let mut outcome = cadence_hooks_core::Outcome::Allow;
        with_vault_env(|| {
            outcome = ObsidianTrashGuard
                .run(&make_bash_with_cwd(command, "/vault/notes"))
                .outcome;
        });
        outcome
    }

    // --- Non-head deletion shapes (#528 security review C1) ---
    //
    // Every command here was measured deleting a real file through `bash`, and
    // every one was BLOCK before this guard moved to a segment-head scan. They
    // are driven through `Check::run` because the regression lived in the
    // path from payload to verdict, not in any single helper.

    #[test]
    fn git_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("git rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn sudo_with_user_flag_rm_inside_vault_blocked() {
        // A flag on the peel prefix must not abort the peel.
        assert_eq!(
            outcome_in_vault("sudo -u me rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn sudo_with_long_flag_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("sudo --preserve-env rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn xargs_null_delimited_rm_inside_vault_blocked() {
        // The canonical safe-for-spaces delete idiom.
        assert_eq!(
            outcome_in_vault("find . -name '*.md' -print0 | xargs -0 rm"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn xargs_with_glued_value_flag_rm_inside_vault_blocked() {
        // `-n1` glues its value to the flag; `-n 1` spells it as the next word.
        assert_eq!(
            outcome_in_vault("xargs -n1 rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
        assert_eq!(
            outcome_in_vault("xargs -n 1 rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn for_loop_body_rm_inside_vault_blocked() {
        // `do` occupies the segment head; the `rm` is behind it.
        assert_eq!(
            outcome_in_vault("for f in *.md; do rm $f; done"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn while_loop_body_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("while read f; do rm $f; done < list"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn if_branch_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("if true; then rm note.md; fi"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn eval_operand_rm_inside_vault_blocked() {
        // `eval` re-executes its operand, quoted or not.
        assert_eq!(
            outcome_in_vault("eval rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
        assert_eq!(
            outcome_in_vault("eval \"rm note.md\""),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn find_exec_nested_shell_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault(r"find . -name x -exec sh -c 'rm note.md' \;"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn git_rm_behind_a_global_option_inside_vault_blocked() {
        // `git`'s own globals sit where the `rm` subcommand test reads, so an
        // alias anchored at `argv[1]` missed every one of these (#528 I2).
        // Each was measured deleting a real file through `bash`.
        for command in [
            "git -C . rm note.md",
            "git -C . rm -r notes/",
            "git --no-pager rm note.md",
            "git -c core.pager=cat rm note.md",
            "git --git-dir=.git rm note.md",
            "git -P rm note.md",
            "sudo git -C . rm note.md",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn benign_git_subcommand_behind_a_global_option_stays_allowed() {
        // The option skip must expose the subcommand, not blur it: a
        // non-destructive `git` verb behind the same globals stays Allow.
        for command in [
            "git -C . status",
            "git --no-pager log --oneline",
            "git -c core.pager=cat diff",
            "git -C . rm-cached note.md",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    #[test]
    fn runner_prefixes_outside_transparent_rm_inside_vault_blocked() {
        // `TRANSPARENT` admits `nice`/`env` only while the next token is not an
        // option, and does not model `timeout`/`stdbuf` at all, so each of
        // these reached no verb gate (#528 review I1).
        for command in [
            "nice -n 10 rm note.md",
            "nice -10 rm note.md",
            "stdbuf -o0 rm note.md",
            "timeout 5 rm note.md",
            "timeout -k 1 5 rm note.md",
            "env -i /bin/rm note.md",
            "env -u FOO rm note.md",
            "env -i FOO=bar rm note.md",
            // GNU env's bare `-` and signal options (cameronsjo/cadence-hooks#1135).
            "env - rm note.md",
            "env --default-signal rm note.md",
            "env --ignore-signal=INT rm note.md",
            "env --block-signal=INT rm note.md",
            "env --list-signal-handling rm note.md",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn find_exec_action_peels_runners_and_git_inside_vault_blocked() {
        // A `find` exec action is an executable position like the segment head,
        // but read the literal next word until now — so every peel the head
        // gained (runner flags, `git`'s globals) was absent one position in
        // (#528 review I1). Each row was measured deleting a real file through
        // `bash`; the first is plain `git rm`, the row this guard's alias
        // exists for, reached through the exec position.
        for command in [
            r"find . -name note.md -exec git rm {} \;",
            r"find . -name note.md -exec git -C . rm {} \;",
            r"find . -name note.md -exec sudo rm {} \;",
            r"find . -name note.md -exec nice -n 10 rm {} \;",
            r"find . -name note.md -exec env -i /bin/rm {} \;",
            r"find . -name note.md -exec stdbuf -o0 rm {} \;",
            "find . -name note.md -exec nice -n 10 rm {} +",
            r"find . -name note.md -execdir nice -n 10 rm {} \;",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn platform_runner_option_spellings_rm_inside_vault_blocked() {
        // Two spellings the runner grammars missed, both verified against the
        // real tool on macOS — `-P utilpath` is in `/usr/bin/env`'s own usage
        // line, and BSD `nice` accepts the doubled-dash adjustment (it warns
        // `setpriority: Permission denied` and execs the utility anyway). Each
        // was measured deleting a real file through `bash`.
        for command in [
            "env -P /bin rm note.md",
            "env -P/bin rm note.md",
            "nice --10 rm note.md",
            "nice --20 rm note.md",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn modelled_runner_with_a_flag_does_not_hide_a_shell_wrapper() {
        // #528 review C-D1. `peel_to_command` fed only the VERB test; the
        // wrapper hunt ran its own weaker model that refused at a runner's
        // first option — so the one-token difference between
        // `nice bash -c 'rm note.md'` (Block) and
        // `nice -n 10 bash -c 'rm note.md'` (Allow) decided whether a
        // measured deletion was seen, even though `nice -n 10 rm note.md`
        // blocked at the verb gate with the SAME flag. Every row below was
        // measured deleting a real file through `bash`.
        for command in [
            "nice -n 10 bash -c 'rm note.md'",
            "nice -n10 bash -c 'rm note.md'",
            "nice -10 bash -c 'rm note.md'",
            "nice --10 bash -c 'rm note.md'",
            "nice --adjustment 10 bash -c 'rm note.md'",
            "env -i sh -c 'rm note.md'",
            "env -u FOO sh -c 'rm note.md'",
            "env -P /bin sh -c 'rm note.md'",
            "env -P/bin sh -c 'rm note.md'",
            "env -0 sh -c 'rm note.md'",
            "sudo -u me sh -c 'rm note.md'",
            "sudo --user=me sh -c 'rm note.md'",
            "stdbuf -o0 sh -c 'rm note.md'",
            "stdbuf -o 0 sh -c 'rm note.md'",
            "timeout 5 sh -c 'rm note.md'",
            "timeout -k 1 5 sh -c 'rm note.md'",
            // The canonical null-delimited idiom, wrapped: the script reads
            // its operands from `"$@"`, so no delete verb is ever spelled at
            // an executable position the head scan can see.
            r#"xargs -0 sh -c 'rm "$@"' _"#,
            "xargs -I{} sh -c 'rm note.md'",
            "xargs -n1 sh -c 'rm note.md'",
            // Stacked runners, and a runner mixed with a transparent prefix
            // or an assignment word — the peel must survive every layer.
            "nice -n 10 env -i sh -c 'rm note.md'",
            "sudo -u me nice -n 10 sh -c 'rm note.md'",
            "env -i sudo -u me sh -c 'rm note.md'",
            "command nice -n 10 sh -c 'rm note.md'",
            "exec nice -n 10 sh -c 'rm note.md'",
            "FOO=1 nice -n 10 sh -c 'rm note.md'",
            "nice -n 10 FOO=1 sh -c 'rm note.md'",
            // Every shell spelling the wrapper hunt recognizes, behind a flag.
            "nice -n 10 /bin/sh -c 'rm note.md'",
            "nice -n 10 zsh -c 'rm note.md'",
            "nice -n 10 dash -c 'rm note.md'",
            "nice -n 10 bash -lc 'rm note.md'",
            "nice -n 10 bash -c -- 'rm note.md'",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn find_exec_action_with_a_flagged_runner_does_not_hide_a_shell_wrapper() {
        // The same finding at the second executable position. The exec window
        // handed `child_scripts` the UNPEELED slice, so a flagged runner in
        // front of the shell hid the script there too. Each row was measured
        // deleting a real file through `bash`.
        for command in [
            r"find . -name note.md -exec nice -n 10 bash -c 'rm note.md' \;",
            r"find . -name note.md -exec nice -10 bash -c 'rm note.md' \;",
            r"find . -name note.md -exec nice --10 bash -c 'rm note.md' \;",
            r"find . -name note.md -exec env -i sh -c 'rm note.md' \;",
            r"find . -name note.md -exec env -u FOO sh -c 'rm note.md' \;",
            r"find . -name note.md -exec env -P /bin sh -c 'rm note.md' \;",
            r"find . -name note.md -exec stdbuf -o0 sh -c 'rm note.md' \;",
            r"find . -name note.md -exec sudo -u me sh -c 'rm note.md' \;",
            r"find . -name note.md -exec timeout 5 sh -c 'rm note.md' \;",
            r"find . -name note.md -execdir nice -n 10 sh -c 'rm note.md' \;",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    /// An `eval` flood the re-scan allowance cannot read is judged from its
    /// text inside the deadline: a deleting verb in it blocks, and a flood
    /// with none is allowed (#1266 review C3).
    #[test]
    fn an_eval_substitution_flood_is_judged_promptly() {
        let limit =
            std::time::Duration::from_millis(if cfg!(debug_assertions) { 8000 } else { 500 });
        for opener in ["<(eval ", "$(eval ", "eval $(eval "] {
            let flood = opener.repeat(200 * 1024 / opener.len());
            for (tail, want) in [
                ("", cadence_hooks_core::Outcome::Allow),
                (" ; rm note.md", cadence_hooks_core::Outcome::Block),
            ] {
                let started = std::time::Instant::now();
                assert_eq!(
                    outcome_in_vault(&format!("{flood}{tail}")),
                    want,
                    "{opener:?}{tail:?}"
                );
                assert!(
                    started.elapsed() < limit,
                    "{opener:?}: {:?}",
                    started.elapsed()
                );
            }
        }
    }

    /// A delete nested past the expansion depth still reaches the guard
    /// (#1233 review C1, #1267).
    #[test]
    fn a_delete_nested_past_the_depth_bound_blocks() {
        for command in [
            "cat <(echo $(echo $(echo $(rm note.md))))",
            "echo $(echo $(echo $(echo $(echo $(rm note.md)))))",
            "cat <(cat <(cat <(cat <(cat <(rm note.md)))))",
            "x=$(cat <(echo $(echo $(bash -c \"rm note.md\"))))",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command}"
            );
        }
    }

    /// A process substitution runs its body in the parent's directory
    /// (cameronsjo/cadence-hooks#1233); quoted, it is literal text.
    #[test]
    fn a_delete_inside_a_process_substitution_blocks() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        for (command, outcome) in [
            ("cat <(rm note.md)", Block),
            ("tee >(rm note.md) </dev/null", Block),
            ("diff <(cat <(rm note.md)) x", Block),
            ("echo \"<(rm note.md)\"", Allow),
            ("echo '>(rm note.md)'", Allow),
        ] {
            assert_eq!(outcome_in_vault(command), outcome, "{command}");
        }
    }

    /// A 200 KB flood of process-substitution openers, whose bodies are now
    /// walked as commands, is judged inside the deadline, and a delete after
    /// it still blocks (cameronsjo/cadence-hooks#1233).
    #[test]
    fn a_process_substitution_flood_is_judged_promptly() {
        let limit =
            std::time::Duration::from_millis(if cfg!(debug_assertions) { 8000 } else { 500 });
        for opener in ["<(", ">(", ">(a "] {
            let flood = opener.repeat(200 * 1024 / opener.len());
            let started = std::time::Instant::now();
            assert_eq!(
                outcome_in_vault(&format!("{flood}\nrm note.md")),
                cadence_hooks_core::Outcome::Block,
                "{opener:?}"
            );
            let took = started.elapsed();
            assert!(took < limit, "{opener:?}: {took:?}");
        }
    }

    #[test]
    fn a_wrapper_segment_still_owes_its_command_substitutions() {
        // A `$(…)` runs in the PARENT before the wrapper is spawned, so a
        // segment can be a wrapper AND carry a substitution. `expand_segments`
        // treated the two as alternatives and dropped the substitution from
        // every wrapper segment — `bash -c 'echo hi' "$(rm note.md)"` deletes
        // the file (measured through `bash`) and reached no guard, and each
        // runner spelling the widened peel newly recognizes would have
        // inherited the same hole.
        for command in [
            r#"bash -c 'echo hi' "$(rm note.md)""#,
            r#"nice bash -c 'echo hi' "$(rm note.md)""#,
            r#"nice -n 10 bash -c 'echo hi' "$(rm note.md)""#,
            r#"sudo -u me bash -c 'echo hi' "$(rm note.md)""#,
            "nice -n 10 bash -c 'echo hi' `rm note.md`",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn compound_body_does_not_hide_a_shell_wrapper() {
        // #528 review E. The verb gate stripped shell keywords and group
        // punctuation before it peeled; the wrapper hunt inside
        // `command_segments` did not. So the segment head stayed `then`/`do`/
        // `(bash`, the hunt returned `None`, and the inner script reached no
        // guard — `if true; then rm note.md; fi` blocked while
        // `if true; then bash -c 'rm note.md'; fi` did not, on the same
        // keyword the gate one position over already stripped. Every row here
        // was measured deleting a real file through `bash`.
        for command in [
            "(bash -c 'rm note.md')",
            "{ bash -c 'rm note.md'; }",
            "if true; then bash -c 'rm note.md'; fi",
            "for f in a; do bash -c 'rm note.md'; done",
            "until false; do bash -c 'rm note.md'; done",
            "case x in x) bash -c 'rm note.md';; esac",
            "f() { bash -c 'rm note.md'; }",
            // The remaining spellings of the same four shapes.
            "while true; do bash -c 'rm note.md'; done",
            "f () { bash -c 'rm note.md'; }",
            "function f { bash -c 'rm note.md'; }",
            // The multi-line `case` puts the arm on a segment of its own, so
            // the label is the segment HEAD rather than mid-segment.
            "case x in\n  x) bash -c 'rm note.md';;\nesac",
            // Nesting, and a keyword in front of GLUED group punctuation —
            // the string-level strip cannot reach the `(` until `do` is gone,
            // which is why the two strips alternate.
            "if true; then if true; then bash -c 'rm note.md'; fi; fi",
            "{ { bash -c 'rm note.md'; }; }",
            "for f in a; do (bash -c 'rm note.md'); done",
            // Compound scaffolding stacked with a flagged runner and with a
            // substitution — both other #528 arms must still compose.
            "if true; then nice -n 10 bash -c 'rm note.md'; fi",
            "for f in a; do env -i sh -c 'rm note.md'; done",
            "{ sudo -u me bash -c 'rm note.md'; }",
            "(stdbuf -o0 sh -c 'rm note.md')",
            r#"{ bash -c 'echo hi' "$(rm note.md)"; }"#,
            r#"if true; then echo "$(rm note.md)"; fi"#,
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} must block"
            );
        }
    }

    #[test]
    fn compound_head_strip_does_not_invent_verbs() {
        // Controls for the compound strip. The scaffolding words themselves are
        // not commands, a `case` arm and a function header in front of harmless
        // work must stay silent, and a delete verb quoted as PROSE inside a
        // compound statement is an argument, not an executable position.
        for command in [
            "if true; then npm run format; fi",
            "for f in a; do echo \"$f\"; done",
            "while read -r line; do echo \"$line\"; done",
            "until curl -sf localhost:8080; do sleep 1; done",
            "{ npm test; }",
            "(cd /tmp && ls)",
            "(git status)",
            "case \"$1\" in start) npm start;; stop) npm stop;; esac",
            "deploy() { npm run build; }",
            "function deploy { npm run build; }",
            "f() { git status; }",
            "if [ -f note.md ]; then cat note.md; fi",
            // Prose, not execution.
            "echo 'case x in x) rm note.md;; esac'",
            "echo \"if true; then rm note.md; fi\"",
            "grep 'f()' src/main.rs",
            "sed -n 's/x)/y)/p' file",
            // A `)`-terminated head that is NOT a case label: a substitution
            // must not read as a pattern, and a script whose own operand closes
            // a paren must keep that operand.
            "$(date) --version",
            "bash -c 'echo hi)'",
            // Bare scaffolding words, and truncated tails, must not panic or
            // resolve a verb.
            "esac",
            "done",
            "fi",
            "case x in",
            "f()",
            "function",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    #[test]
    fn wrapper_hunt_peel_does_not_invent_verbs() {
        // Controls for the widened wrapper hunt, in three groups.
        for command in [
            // 1. The same flagged runners in front of a harmless script.
            "nice -n 10 bash -c 'echo hello'",
            "env -i sh -c 'ls -la'",
            "sudo -u me sh -c 'cat README.md'",
            "stdbuf -o0 sh -c 'npm run format'",
            "timeout 5 sh -c 'terraform fmt'",
            r#"xargs -0 sh -c 'echo "$@"' _"#,
            // 2. Runner options the grammar does NOT model still refuse the
            //    walk rather than resolving a wrong head word.
            "nice -é rm note.md",
            "env -é sh -c 'rm note.md'",
            "nice ---10 sh -c 'rm note.md'",
            "nice - rm note.md",
            // 3. `sudo -l`/`-V` REPORT and never exec, so the script behind
            //    them is not a command the shell runs — peeling there would
            //    manufacture a block on something that cannot delete.
            "sudo -l sh -c 'rm note.md'",
            "sudo -V sh -c 'rm note.md'",
            // Truncated tails must not panic or invent a verb.
            "nice -n",
            "env -i",
            "sudo -u",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    #[test]
    fn find_exec_action_peels_do_not_invent_verbs() {
        // Controls for the exec-position peel: the same shapes in front of a
        // harmless command must stay Allow, so widening the exec window does
        // not turn `find … -exec <anything> …` into a block.
        for command in [
            r"find . -name '*.md' -exec cat {} \;",
            r"find . -name '*.md' -exec git status {} \;",
            r"find . -name '*.md' -exec nice -n 10 cat {} \;",
            r"find . -name '*.md' -exec env -i /bin/cat {} \;",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    #[test]
    fn runner_prefixes_outside_transparent_do_not_invent_verbs() {
        // Controls for the four new runner arms: the same prefixes in front of
        // a harmless command must stay Allow.
        for command in [
            "nice -n 10 ls",
            "stdbuf -o0 cat note.md",
            "timeout 5 npm run format",
            "env -i /bin/ls",
            // The DURATION operand is not the command: `timeout 5` alone runs
            // nothing, and `rm` here is a filename argument to `grep`.
            "timeout 5 grep -r rm .",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    // --- Controls: false positives the head scan correctly removed ---
    //
    // These BLOCKED under the old whole-command `contains("rm")` scan and must
    // stay ALLOW. They pin the fix in the other direction: restoring the shapes
    // above must not restore the substring detector with them.

    #[test]
    fn npm_run_format_in_vault_stays_allowed() {
        assert_eq!(
            outcome_in_vault("npm run format"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn terraform_destroy_in_vault_stays_allowed() {
        assert_eq!(
            outcome_in_vault("terraform destroy"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn keyword_and_runner_peels_do_not_invent_verbs() {
        // Controls for the three new peels: a keyword with a harmless body, a
        // runner whose command is not destructive, and a `git` subcommand that
        // is not `rm` (case-sensitively — `git RM` is not a subcommand).
        for command in [
            "for f in *.md; do cat $f; done",
            "sudo -u me ls",
            "xargs -0 grep note",
            "git status",
            "git RM note.md",
            "eval ls",
            "find . -name x -exec sh -c 'cat note.md' \\;",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    /// The cadence-hooks#559 report table as a regression pin, plus one row
    /// (`find …`) that report did not name — a substring prefilter on a
    /// delete verb drags it in, and this guard must stay silent on it too.
    ///
    /// Filed against 0.70.0 against a guard that scanned the whole command
    /// string for `rm`, so `echo confirm`, `echo thermal` and a `gh` query
    /// naming `viewerPermission` were all blocked as vault deletions. The
    /// segment-head scan that shipped in 0.70.1 fixed it; this pins the whole
    /// reported corpus rather than the two words that happened to get tests.
    ///
    /// It is also the safety pin for this guard's wiring, which carries no
    /// `if:` filter at all — every Bash command in a vault session reaches it,
    /// so a substring detector here costs a block on ordinary work, not a
    /// wasted process (`docs/hooks.md` § Wiring prefilters).
    #[test]
    fn substring_rm_inside_an_ordinary_word_stays_allowed() {
        for command in [
            "echo confirm",
            "echo confabulate",
            "echo viewerPermission",
            "echo viewerAccess",
            "echo thermal",
            "echo thespian",
            "grep -inE 'alpha|thermal|gamma' notes.md",
            "gh repo view OWNER/REPO --json visibility,viewerPermission",
            "gh api repos/OWNER/REPO --jq .permissions.push",
            "grep -c 'alpha' notes.md",
            "gh label list --repo OWNER/REPO",
            "chmod 644 note.md",
            "git format-patch -1 HEAD",
            "terraform apply",
            "npm run warm-cache",
            "./perform-migration.sh",
            "find . -name '*.md' -print",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} deletes nothing and must stay allowed"
            );
        }
    }

    /// The other direction of the same pin: the shapes cadence-hooks#559
    /// confirmed still fired, plus the runner and compound spellings, must
    /// stay BLOCK. A fix for the false positives that quietly cost one of
    /// these would be the worse trade.
    #[test]
    fn real_vault_deletions_still_block() {
        for command in [
            "rm -rf note.md",
            "RM -rf note.md",
            "sudo rm note.md",
            "true && rm note.md",
            "find . -delete",
            "git rm note.md",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Block,
                "{command} deletes a vault file and must block"
            );
        }
    }

    #[test]
    fn destructive_word_as_an_argument_is_allowed() {
        with_vault_env(|| {
            let result =
                ObsidianTrashGuard.run(&make_bash_with_cwd("echo RM note.md", "/vault/notes"));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }

    #[test]
    fn normalized_patch_delete_inside_vault_is_blocked() {
        let result = check_delete_in_vault("note.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    /// A patch RENAME is a move, and this guard's own remedy is a move — see
    /// `check_delete_in_vault`'s doc comment. Pinned so the exclusion is an
    /// asserted boundary rather than an undocumented gap.
    #[test]
    fn normalized_patch_rename_inside_vault_is_not_a_delete() {
        let patch = "*** Begin Patch\n*** Update File: /vault/note.md\n\
                     *** Move to: /vault/.trash/note.md\n@@\n-old\n+new\n*** End Patch";
        let payload = serde_json::json!({
            "tool_name": "apply_patch",
            "cwd": "/vault",
            "tool_input": patch,
        })
        .to_string();
        let input = HookInput::from_json(&payload).expect("parse patch payload");
        let targets = input.normalized_inputs().expect("normalize patch");

        // The fact the exclusion rests on: the source half is `rename-source`,
        // so the `operation() == Some("delete")` route is never entered.
        assert_eq!(targets[0].operation(), Some("rename-source"));
        assert_ne!(
            targets[0].operation(),
            Some("delete"),
            "a move must not be tagged as a deletion"
        );

        // Control: the delete spelling of the same vault path still blocks, so
        // this pins a scope boundary rather than a hole in the delete route.
        assert_eq!(
            check_delete_in_vault("/vault/note.md", "/vault", "/vault").outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn rm_with_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "rm /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_double_quoted_vault_path_blocked() {
        // #82: a leading `"` must not defeat looks_absolute.
        let result = check_destructive_in_vault(
            "rm \"/vault/notes/todo.md\"",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "rm '/vault/notes/todo.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_double_quoted_vault_path_with_spaces_blocked() {
        // #82 headline repro: a spaced vault path must be quoted; split_whitespace
        // shredded it across tokens and the guard never saw the absolute path.
        let result = check_destructive_in_vault(
            "rm \"/vault/Field Reports/old.md\"",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_with_spaces_blocked() {
        let result = check_destructive_in_vault(
            "rm '/vault/Field Reports/old.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_with_spaces_allowed() {
        // Regression: a genuinely out-of-vault quoted spaced path stays Allow.
        let result = check_destructive_in_vault(
            "rm \"/home/user/Field Reports/old.md\"",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_allowed() {
        let result = check_destructive_in_vault(
            "rm '/other/note.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_rf_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("rm -rf old-notes/", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_multiple_files_in_vault_blocked() {
        let result = check_destructive_in_vault(
            "rm a.md b.md c.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_as_substring_not_matched() {
        // /vault2 should not match /vault
        let result =
            check_destructive_in_vault("rm file.md", "/vault2/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_rm_with_vault_path_allowed() {
        let result = check_destructive_in_vault(
            "cat /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_contains_vault_path() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("/vault/.trash/"));
    }

    // ObsidianTrashGuard::run() tests (needs OBSIDIAN_VAULT env var)
    #[test]
    fn run_no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = ObsidianTrashGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn rm_at_vault_root_blocked() {
        let result =
            check_destructive_in_vault("rm old-note.md", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_deeply_nested_in_vault_blocked() {
        let result = check_destructive_in_vault(
            "rm file.md",
            "/vault/a/b/c/d",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_glob_in_vault_blocked() {
        let result =
            check_destructive_in_vault("rm *.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_with_trailing_slash() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault/notes", "/vault/", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_trailing_slash_normalized() {
        // Trailing slash on vault is stripped before comparison
        let result =
            check_destructive_in_vault("rm note.md", "/vault", "/vault/", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_vault_matches_forward_slash_cwd() {
        // OBSIDIAN_VAULT with Windows backslashes must match a forward-slash
        // cwd from the hook payload once both sides are normalized.
        let result = check_destructive_in_vault(
            "rm note.md",
            "C:/vault/notes",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_command_path_matches_vault() {
        // A Windows drive-absolute command arg (`C:\vault\...`) normalizes to
        // `C:/vault/...` and is recognized as an explicit path, so an `rm`
        // targeting the vault from an outside cwd is blocked.
        let result = check_destructive_in_vault(
            r"rm C:\vault\notes\todo.md",
            "C:/home",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_drive_path_outside_vault_allowed() {
        // A drive-absolute path that isn't the vault must not false-match.
        let result = check_destructive_in_vault(
            r"rm C:\other\file.md",
            "C:/home",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mv_in_vault_allowed() {
        // mv is not rm — should be allowed
        let result =
            check_destructive_in_vault("mv old.md new.md", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_vault_path_deeply_nested() {
        let result = check_destructive_in_vault(
            "rm /vault/a/b/c.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_vault_path_but_wrong_prefix() {
        // /vault-backup is not /vault
        let result = check_destructive_in_vault(
            "rm /vault-backup/note.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn relative_path_in_non_vault_cwd_allowed() {
        let result = check_destructive_in_vault(
            "rm note.md",
            "/home/user/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_suggests_trash() {
        let result =
            check_destructive_in_vault("rm note.md", "/my-vault", "/my-vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(".trash"));
        assert!(msg.contains("/my-vault/.trash/"));
    }

    // --- Non-`rm` destructive verbs (#136) ---

    #[test]
    fn unlink_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "unlink note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "unlink /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "unlink /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn shred_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "shred -u note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "shred -u /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn truncate_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "truncate -s 0 note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "truncate -s 0 /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_delete_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "find . -name '*.md' -delete",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_delete_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "find /vault -name '*.md' -delete",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_without_delete_in_vault_allowed() {
        // Critical false-positive guard: `find` alone is read-only.
        let result = check_destructive_in_vault(
            "find . -name '*.md'",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_exec_rm_inside_vault_blocked() {
        // `find … -exec rm …` names a second executable position.
        let result = check_destructive_in_vault(
            "find . -name '*.md' -exec rm {} +",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Path-qualified verbs: basename match (#136 security follow-up) ---

    #[test]
    fn unlink_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/bin/unlink note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/shred -u note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/truncate -s 0 note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_path_qualified_delete_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/find . -delete",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shredder_filename_not_matched() {
        // No destructive verb — `shredder.md` is a bare filename token whose
        // basename is itself, so it must not match the `shred` verb.
        let result = check_destructive_in_vault(
            "cat shredder.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Clobber-redirect truncation of existing vault files (#192) ---

    #[test]
    fn truncate_redirect_existing_vault_file_blocked() {
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault("echo hi > note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn brace_expanded_redirect_target_is_judged_as_the_expanded_name() {
        // cameronsjo/cadence-hooks#1115: bash writes `note.md` for
        // `>note.m{d..d}` — a single-character sequence, not `{md..md}`.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        for (command, want) in [
            ("echo x >note.m{d..d}", cadence_hooks_core::Outcome::Block),
            ("echo x > note.m{d..d}", cadence_hooks_core::Outcome::Block),
            ("echo x > note.{md,}", cadence_hooks_core::Outcome::Block),
            // Controls: an expansion that names no existing file, and a
            // sequence bash leaves literal.
            ("echo x > other.m{d..d}", cadence_hooks_core::Outcome::Allow),
            ("echo x > note.{md..md}", cadence_hooks_core::Outcome::Allow),
            // Append never truncates.
            ("echo x >> note.m{d..d}", cadence_hooks_core::Outcome::Allow),
        ] {
            let result = check_destructive_in_vault(command, "/vault/notes", "/vault", &fs);
            assert_eq!(result.outcome, want, "{command}");
        }
    }

    #[test]
    fn create_redirect_new_vault_file_allowed() {
        // Same command, but the target doesn't exist yet — new-file creation
        // is not a truncation.
        let result = check_destructive_in_vault(
            "echo hi > note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn append_redirect_vault_file_allowed() {
        // `>>` never clobbers, regardless of existence.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result =
            check_destructive_in_vault("echo hi >> note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn colon_truncate_existing_vault_file_blocked() {
        // `:` is a no-op builtin, not a destructive verb — the redirect
        // branch is what catches this, independent of `is_destructive`.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault(": > note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn redirect_out_of_vault_allowed() {
        let fs = FakeFs::with(&["/tmp/x.md"]);
        let result =
            check_destructive_in_vault("echo hi > /tmp/x.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn quoted_redirect_in_prose_allowed() {
        // The `>` inside the quoted commit message is literal text, not a
        // redirect operator — no target is extracted at all.
        let result = check_destructive_in_vault(
            r#"git commit -m "use > carefully""#,
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn redirect_explicit_vault_path_from_outside_blocked() {
        let fs = FakeFs::with(&["/vault/note.md"]);
        let result = check_destructive_in_vault("echo hi > /vault/note.md", "/home", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Redirect-guard bypass hardening (security review #192 follow-up) ---

    #[test]
    fn sh_c_wrapped_redirect_into_existing_vault_file_blocked() {
        // F1: the redirect loop must see inside a `sh -c`/`bash -c` wrapper,
        // not just the literal top-level segment.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result =
            check_destructive_in_vault("sh -c 'echo x > note.md'", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn backslash_escaped_space_target_blocked() {
        // F2: Obsidian filenames routinely contain spaces; a backslash-escaped
        // space must not truncate the target early.
        let fs = FakeFs::with(&["/vault/notes/Daily Note.md"]);
        let result =
            check_destructive_in_vault(r"echo x > Daily\ Note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn glued_paren_subshell_truncate_blocked() {
        // F3: a glued closing paren from subshell grouping must not survive
        // into the resolved target and dodge the existence check.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault("(: > note.md)", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn dotdot_climb_into_vault_from_outside_blocked() {
        // F4: a `..` climb that lands back inside the vault must be caught
        // even though the raw joined string never has the `/vault/` prefix.
        let fs = FakeFs::with(&["/vault/note.md"]);
        let result =
            check_destructive_in_vault("echo x > ../../vault/note.md", "/home/user", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn dotdot_out_of_vault_allowed() {
        // F7 companion: a `..` climb that lands OUTSIDE the vault (even
        // though the raw string mis-resolves as in-vault before collapsing)
        // must stay Allow.
        let result = check_destructive_in_vault(
            "echo x > ../../../etc/passwd",
            "/vault",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    /// cadence-hooks#546: `coproc` takes a command, not flags, so the verb behind
    /// it sat outside the head scan. Rows that block delete a real file under
    /// bash; the allow rows are the false positives the head scan exists to
    /// avoid, plus the documented `$(…)` in command position.
    #[test]
    fn coproc_runs_its_command_through_the_verb_gate() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let cases: &[(&str, cadence_hooks_core::Outcome)] = &[
            ("coproc rm note.md", Block),
            ("coproc rm -f note.md", Block),
            ("coproc /bin/rm note.md", Block),
            ("coproc sudo rm note.md", Block),
            ("coproc unlink note.md", Block),
            ("coproc git rm note.md", Block),
            ("coproc { rm note.md; }", Block),
            ("coproc DEL { rm note.md; }", Block),
            ("coproc DEL ( rm note.md )", Block),
            ("coproc coproc rm note.md", Block),
            ("echo hi && coproc rm note.md", Block),
            ("coproc eval 'rm note.md'", Block),
            ("coproc sh -c 'rm note.md'", Block),
            ("coproc find . -delete", Block),
            // Controls: the false positives the narrowing removed stay removed.
            ("npm run format", Allow),
            ("terraform destroy", Allow),
            ("coproc npm run format", Allow),
            ("coproc terraform destroy", Allow),
            ("coproc cat note.md", Allow),
            // Bash reads NAME only before a compound command; here `DEL` is the
            // command and nothing is deleted (measured under bash 5).
            ("coproc DEL rm note.md", Allow),
            ("coproc DEL { cat note.md; }", Allow),
            ("coproc", Allow),
            ("echo coproc rm note.md", Allow),
            // Documented limit (#546): a substitution-produced verb is unknowable
            // — except a literal `echo`/`printf`, which is read as printed (#1142).
            ("$(which rm) note.md", Allow),
            ("$(echo rm) note.md", Block),
        ];
        for (command, expected) in cases {
            assert_eq!(outcome_in_vault(command), *expected, "{command}");
        }
    }

    #[test]
    fn coproc_deletion_from_outside_the_vault_is_judged_by_its_operand() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        let cases: &[(&str, cadence_hooks_core::Outcome)] = &[
            ("coproc rm /vault/note.md", Block),
            ("coproc DEL { rm /vault/note.md; }", Block),
            ("coproc rm /tmp/scratch", Allow),
            ("coproc cat /vault/note.md", Allow),
        ];
        for (command, expected) in cases {
            let result =
                check_destructive_in_vault(command, "/home/me", "/vault", &FakeFs::default());
            assert_eq!(result.outcome, *expected, "{command}");
        }
    }

    fn write_input(path: &str, content: Option<&str>, cwd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path.into()),
                content: content.map(Into::into),
                ..Default::default()
            }),
            cwd: Some(cwd.into()),
            ..Default::default()
        }
    }

    /// cadence-hooks#534: an empty `Write` to an existing vault file is a
    /// deletion. Real content, a new file, and a target outside the vault are
    /// untouched.
    #[test]
    fn empty_write_to_an_existing_vault_file_is_judged_like_a_deletion() {
        use cadence_hooks_core::Outcome::{Allow, Block};
        // (path, content, cwd, seeded as existing, expected)
        let cases: &[(&str, &str, &str, bool, cadence_hooks_core::Outcome)] = &[
            ("/vault/note.md", "", "/home/me", true, Block),
            ("/vault/note.md", "  \n\t\r\n", "/home/me", true, Block),
            ("/vault/note.md", "\n", "/home/me", true, Block),
            ("/vault/note.md", "\u{a0}", "/home/me", true, Block),
            ("/vault/sub/note.md", "", "/home/me", true, Block),
            ("note.md", "", "/vault", true, Block),
            ("../vault/note.md", "", "/home", true, Block),
            ("/home/me/../../vault/note.md", "", "/", true, Block),
            ("/vault/./sub/../note.md", "", "/", true, Block),
            // Real content is a note update.
            ("/vault/note.md", "x", "/home/me", true, Allow),
            ("/vault/note.md", "# Title\n", "/home/me", true, Allow),
            ("/vault/note.md", " x ", "/home/me", true, Allow),
            // A new file deletes nothing.
            ("/vault/new.md", "", "/home/me", false, Allow),
            // Outside the vault.
            ("/tmp/note.md", "", "/home/me", true, Allow),
            ("/vault2/note.md", "", "/home/me", true, Allow),
            ("/vault/../elsewhere/note.md", "", "/", true, Allow),
            ("note.md", "", "/home/me", true, Allow),
        ];
        for (path, content, cwd, exists, expected) in cases {
            let meta = if *exists {
                FakeFs::with(&[
                    "/vault/note.md",
                    "/vault/sub/note.md",
                    "/vault2/note.md",
                    "/tmp/note.md",
                    "/elsewhere/note.md",
                    "/home/me/note.md",
                ])
            } else {
                FakeFs::default()
            };
            let result = check_truncate_in_vault(path, content, cwd, "/vault", &meta);
            assert_eq!(result.outcome, *expected, "{path} {content:?} cwd={cwd}");
        }
    }

    #[test]
    fn empty_write_is_judged_only_for_the_write_tool_through_the_entry_point() {
        use cadence_hooks_core::Outcome::Allow;
        with_vault_env(|| {
            // Nothing is at /vault on the real disk, so an empty Write is a
            // new-file creation: allowed, and the arm is reached without error.
            let write = write_input("/vault/note.md", Some(""), "/home/me");
            assert_eq!(ObsidianTrashGuard.run(&write).outcome, Allow);
            // A Write with no content field is malformed, not a truncation.
            let missing = write_input("/vault/note.md", None, "/home/me");
            assert_eq!(ObsidianTrashGuard.run(&missing).outcome, Allow);
            // An Edit is not a Write, even with an empty replacement.
            let mut edit = write_input("/vault/note.md", None, "/home/me");
            edit.tool_name = Some("Edit".into());
            edit.tool_input.as_mut().unwrap().new_string = Some(String::new());
            assert_eq!(ObsidianTrashGuard.run(&edit).outcome, Allow);
        });
    }

    #[test]
    fn empty_write_to_a_real_vault_file_blocks_through_the_entry_point() {
        let dir = std::env::temp_dir().join(format!("cadence-trash-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("note.md");
        std::fs::write(&file, "keep me").unwrap();
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let previous = std::env::var_os("OBSIDIAN_VAULT");
        // SAFETY: serialized by ENV_LOCK and restored below.
        unsafe { std::env::set_var("OBSIDIAN_VAULT", &dir) };
        let path = file.to_string_lossy().into_owned();
        let empty = ObsidianTrashGuard.run(&write_input(&path, Some(""), "/"));
        let real = ObsidianTrashGuard.run(&write_input(&path, Some("x"), "/"));
        match previous {
            Some(value) => unsafe { std::env::set_var("OBSIDIAN_VAULT", value) },
            None => unsafe { std::env::remove_var("OBSIDIAN_VAULT") },
        }
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(empty.outcome, cadence_hooks_core::Outcome::Block);
        assert_eq!(real.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
