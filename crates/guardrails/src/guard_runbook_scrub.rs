//! Block an unscrubbed write into the runbooks directory
//! (cameronsjo/cadence-hooks#755).
//!
//! `cadence:mining-runbooks` drafts runbooks from transcript-derived text and
//! promotes them into the vault directory named by `$CADENCE_RUNBOOKS_DIR`,
//! which is backed up off-machine. Its secret-scrub gate (`scrub.py --apply`,
//! then check mode to exit 0) used to be skill prose only. This guard makes it
//! mechanical:
//!
//! - **Write / Edit / MultiEdit** whose target resolves under the directory is
//!   allowed only when the **resulting document** (the Write's content, or the
//!   on-disk file with the edit applied — [`HookInput::effective_content`])
//!   hashes to a marker `cadence-hooks cadence record-scrub --file <path>`
//!   recorded ([`markers::scrub_marker_present`]). A resulting document that
//!   cannot be computed (an Edit of an unreadable file) blocks.
//! - **Bash** writing into the directory — a redirect or a writer verb (`tee`,
//!   `cp`/`mv`/`install`/`ln`, `rsync`, `dd`, `truncate`, `touch`, `rm`,
//!   `sed -i`, …), as `prevent-secret-writes` parses them
//!   ([`segment_write_targets`]) — blocks outright: the bytes a command writes
//!   are not knowable before it runs, so there is nothing to match a marker
//!   against. The message points at the Write-tool path.
//! - An MCP-style move/copy (`tool_input.destination`) into the directory
//!   blocks outright for the same reason.
//!
//! **Where a path lands** is decided on two readings, and either one landing
//! inside is enough ([`PathShape::lands_in`]): the lexical path (`..` folded
//! textually) and the physical one (every existing symlink on the way
//! followed, `..` applied after it, as the kernel does). Components compare
//! ASCII-case-insensitively, because the vault lives on a case-insensitive
//! volume on macOS. A Bash target's glob component (`*`, `?`, `[`, `{`)
//! matches any single directory name; a `~` or `$HOME` / `$CADENCE_RUNBOOKS_DIR`
//! is expanded; a relative target is judged against the payload `cwd`, the
//! whole-command `cd` reading ([`parse_work_dir`]) and the directory its own
//! segment runs in ([`command_segments_with_dirs`]), keeping the sharpest verdict.
//!
//! **A command that names the directory may only read it.** When the command
//! text spells the directory (its configured, lexical, physical, or `~/` form,
//! on a path boundary, or `$CADENCE_RUNBOOKS_DIR` / `${CADENCE_RUNBOOKS_DIR…`
//! as an expansion), it also blocks on: any write target anywhere (other than
//! `/dev/null` and the standard streams); a target whose location the hook
//! cannot read (another variable, a substitution, `~user`, `**`, a relative
//! target after an unreadable `cd`); and any program outside a short read-only
//! list ([`READ_ONLY_PROGRAMS`]) — which is what catches the writers the
//! parser cannot see (`python -c`, `tar -x -C`, `git -C`, `mkdir`, `xargs cp`
//! fed on stdin, `unzip -d`, …).
//!
//! A Bash command carrying more target-plus-directory text than
//! [`JUDGE_BUDGET`] is refused as too large to judge, so a flood cannot run
//! out the hook deadline (which fails open).
//!
//! **Deliberately allowed (documented, not overlooked):**
//! - A command that never spells the directory and writes through a location
//!   the hook cannot read: `> "$OUT"`, `cd "$D" && … > f`, a directory spelled
//!   in pieces (`D=vault; … $BASE/$D/Runbooks`), or a program whose writes are
//!   invisible (`python script.py`, `tar -x` from inside a symlinked parent).
//!   Blocking every such command in every session would make the guard
//!   unusable.
//! - Reads of the directory by the listed read-only programs, including a
//!   `find` without `-exec`/`-ok`/`-delete`/`-fprint*`/`-fls`.
//! - A hard link: writing a file *outside* the directory that shares an inode
//!   with a runbook is judged by its own path.
//! - Unicode-normalization and non-ASCII case variants of the directory's
//!   spelling (only ASCII case is folded).
//! - `NotebookEdit` carries its target in `notebook_path`, which no guard
//!   reads; a notebook is not a runbook.
//!
//! **Charter:** a security guard. Inert when `$CADENCE_RUNBOOKS_DIR` is unset
//! or blank. Fails open on its own failure (ADR-0001) — no path or command
//! means allow — but never on a miss, and an uncomputable resulting document
//! blocks. Registered security-critical and in `PROTECTED_GUARDS`, so
//! `CADENCE_DISABLE` cannot neuter it. The returnable escape is
//! `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK` (truthy, read from the hook process's own
//! environment), which allows *and* records a bypass row.

use cadence_hooks_cadence::prevent_secret_writes::{segment_command_argv, segment_write_targets};
use cadence_hooks_core::markers;
use cadence_hooks_core::shell::{
    UNRESOLVABLE_DIR, command_segments_with_dirs, command_word, parse_work_dir,
};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput};
use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

/// The directory the guard protects. Unset or blank → the guard is inert.
pub const DIR_ENV: &str = "CADENCE_RUNBOOKS_DIR";

/// The returnable escape: set truthy to let an unscrubbed write through
/// deliberately. Read from the hook process's own environment only.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_UNSCRUBBED_RUNBOOK";

/// Symlink hops [`physical`] follows before giving up (Linux's `MAXSYMLINKS`).
const MAX_SYMLINK_HOPS: usize = 40;

/// Bytes of target-plus-directory text [`bash_write_into`] judges before it
/// refuses the command as too large. A real command spends a few hundred to a
/// few thousand (each target is charged its own length plus every directory
/// it is judged in); reaching this takes thousands of write targets or a
/// multi-kilobyte `cd` chain, and keeps a 200 KB adversarial command well
/// inside the hook deadline.
const JUDGE_BUDGET: usize = 256 * 1024;

/// Longest target text echoed into a block message.
const MAX_ECHO: usize = 200;

/// One path component, as a location judgment sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Comp {
    /// A literal directory or file name.
    Lit(String),
    /// `..`.
    Up,
    /// A glob component: matches any single name.
    Wild,
    /// A component the hook cannot read (`$VAR`, a substitution, `**`): it can
    /// stand for any number of names, `..` included.
    Opaque,
}

/// A path as components, absolute (from the root) by construction.
#[derive(Debug, Clone)]
struct PathShape(Vec<Comp>);

impl PathShape {
    /// Split `text` into components. `shell` classifies glob and opaque
    /// components (a Bash target); a Write-tool path is all literal.
    fn parse(text: &str, shell: bool) -> Vec<Comp> {
        text.replace('\\', "/")
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .map(|c| {
                if c == ".." {
                    Comp::Up
                } else if shell && (c.contains(['$', '`']) || c.contains("**")) {
                    Comp::Opaque
                } else if shell && c.contains(['*', '?', '[', '{']) {
                    Comp::Wild
                } else {
                    Comp::Lit(c.to_string())
                }
            })
            .collect()
    }

    fn has_opaque(&self) -> bool {
        self.0.contains(&Comp::Opaque)
    }

    /// `..` folded textually. An `..` after an opaque component is absorbed by
    /// it (the opaque part can stand for anything, so it stays opaque).
    fn lexical(&self) -> Vec<Comp> {
        let mut out: Vec<Comp> = Vec::new();
        for c in &self.0 {
            match c {
                Comp::Up => {
                    if out.last() != Some(&Comp::Opaque) {
                        out.pop();
                    }
                }
                other => out.push(other.clone()),
            }
        }
        out
    }

    /// The physical reading: the leading literal run resolved on disk
    /// ([`physical`]), the rest folded lexically. `None` when the walk cannot
    /// finish (a symlink loop) — the lexical reading still stands.
    fn physical(&self, resolver: &Resolver) -> Option<Vec<Comp>> {
        let split = self
            .0
            .iter()
            .position(|c| matches!(c, Comp::Wild | Comp::Opaque))
            .unwrap_or(self.0.len());
        let mut prefix = PathBuf::from("/");
        for c in &self.0[..split] {
            match c {
                Comp::Lit(name) => prefix.push(name),
                _ => prefix.push(".."),
            }
        }
        let resolved = resolver.physical(&prefix)?;
        let mut comps: Vec<Comp> = path_names(&resolved).into_iter().map(Comp::Lit).collect();
        comps.extend(self.0[split..].iter().cloned());
        Some(PathShape(comps).lexical())
    }

    /// True when either reading of this path is the directory `dir` (given as
    /// its possible spellings) or anything beneath it.
    fn lands_in(&self, dirs: &[Vec<String>], resolver: &Resolver) -> bool {
        let readings = std::iter::once(self.lexical()).chain(self.physical(resolver));
        readings
            .into_iter()
            .any(|comps| dirs.iter().any(|dir| reaches(&comps, dir)))
    }
}

/// True when `path` (already `..`-folded) is `dir` or beneath it. A glob
/// component matches any one name; an opaque one matches nothing here — the
/// caller routes opaque paths through the mention rule instead.
fn reaches(path: &[Comp], dir: &[String]) -> bool {
    path.len() >= dir.len()
        && path.iter().zip(dir).all(|(c, d)| match c {
            Comp::Lit(name) => name.eq_ignore_ascii_case(d),
            Comp::Wild => true,
            Comp::Up | Comp::Opaque => false,
        })
}

/// The normal-component names of an absolute path.
fn path_names(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// `path` with every symlink that exists on the way followed and each `..`
/// applied to the directory reached so far — what the kernel resolves — while
/// a component that does not exist yet is appended as spelled (a Write may
/// create it). `None` on a symlink loop past [`MAX_SYMLINK_HOPS`].
///
/// Linear in the path: the buffer grows in place, and once a component is
/// missing nothing below it can be a symlink, so the walk stops asking the
/// filesystem until a `..` climbs back out of the missing part.
fn physical(path: &Path) -> Option<PathBuf> {
    physical_walk(path).map(|(resolved, _)| resolved)
}

/// [`physical`], plus whether the resolved path's last component is missing
/// on disk (so nothing appended below it can be a symlink).
fn physical_walk(path: &Path) -> Option<(PathBuf, bool)> {
    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    push_components(&mut pending, path);
    let mut resolved = PathBuf::from("/");
    // How many trailing components of `resolved` do not exist on disk.
    let mut missing = 0usize;
    let mut hops = 0;
    while let Some(name) = pending.pop() {
        if name == ".." {
            resolved.pop();
            missing = missing.saturating_sub(1);
            continue;
        }
        resolved.push(&name);
        if missing > 0 {
            missing += 1;
            continue;
        }
        match std::fs::symlink_metadata(&resolved) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let target = std::fs::read_link(&resolved).ok()?;
                resolved.pop();
                if target.has_root() {
                    resolved = PathBuf::from("/");
                }
                push_components(&mut pending, &target);
            }
            Ok(_) => {}
            // Missing, or unreadable to this user — which the writer, running
            // as the same user, cannot traverse either.
            Err(_) => missing = 1,
        }
    }
    Some((resolved, missing > 0))
}

/// [`physical`] with each distinct parent directory walked once per run.
///
/// A command with thousands of targets in a handful of directories would
/// otherwise re-walk (and re-`stat`) the same directory chain per target. The
/// final component is still looked up every time, since it may itself be a
/// symlink (a file link pointing into the protected dir).
#[derive(Default)]
struct Resolver {
    parents: std::cell::RefCell<std::collections::HashMap<PathBuf, Option<(PathBuf, bool)>>>,
}

impl Resolver {
    fn physical(&self, path: &Path) -> Option<PathBuf> {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return physical(path);
        };
        let resolved_parent = self
            .parents
            .borrow_mut()
            .entry(parent.to_path_buf())
            .or_insert_with(|| physical_walk(parent))
            .clone();
        let (mut out, parent_missing) = resolved_parent?;
        out.push(name);
        if parent_missing {
            return Some(out);
        }
        match std::fs::symlink_metadata(&out) {
            Ok(meta) if meta.file_type().is_symlink() => physical(path),
            _ => Some(out),
        }
    }
}

/// Push `path`'s components onto a pop-from-the-end work stack, so the first
/// component is popped first. `.` is dropped; the root is implied.
fn push_components(stack: &mut Vec<std::ffi::OsString>, path: &Path) {
    let names: Vec<std::ffi::OsString> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    stack.extend(names.into_iter().rev());
}

/// The protected directory, resolved once per run.
struct RunbooksDir {
    /// Each spelling that names it: lexical and physical, as components.
    spellings: Vec<Vec<String>>,
    /// Lowercased texts whose appearance in a command names the directory.
    mentions: Vec<String>,
    /// `$CADENCE_RUNBOOKS_DIR` as configured (tilde-expanded), for expansion.
    value: String,
    home: Option<String>,
}

impl RunbooksDir {
    /// `None` when the variable is unset or blank — the guard is inert.
    fn resolve(raw: Option<&str>, home: Option<&str>, cwd: &str) -> Option<Self> {
        let raw = raw?.trim();
        if raw.is_empty() {
            return None;
        }
        let value = expand_home(raw, home);
        let shape = PathShape(absolute(&value, cwd, false));
        let lexical: Vec<String> = shape
            .lexical()
            .into_iter()
            .filter_map(|c| match c {
                Comp::Lit(n) => Some(n),
                _ => None,
            })
            .collect();
        let mut spellings = vec![lexical.clone()];
        if let Some(phys) = shape.physical(&Resolver::default()) {
            let phys: Vec<String> = phys
                .into_iter()
                .filter_map(|c| match c {
                    Comp::Lit(n) => Some(n),
                    _ => None,
                })
                .collect();
            if !phys
                .iter()
                .zip(&lexical)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                || phys.len() != lexical.len()
            {
                spellings.push(phys);
            }
        }
        // The root itself is never a runbooks dir: `CADENCE_RUNBOOKS_DIR=/`
        // would gate every write on the machine.
        spellings.retain(|s| !s.is_empty());
        if spellings.is_empty() {
            return None;
        }
        let mut mentions: BTreeSet<String> = BTreeSet::new();
        // The variable counts only as an expansion: its bare name in prose (a
        // commit message about this guard) names nothing.
        mentions.insert(format!("${}", DIR_ENV.to_ascii_lowercase()));
        mentions.insert(format!("${{{}", DIR_ENV.to_ascii_lowercase()));
        mentions.insert(raw.trim_end_matches('/').to_ascii_lowercase());
        for s in &spellings {
            let joined = format!("/{}", s.join("/")).to_ascii_lowercase();
            if let Some(h) = home {
                let h = h.trim_end_matches('/').to_ascii_lowercase();
                if let Some(rest) = joined.strip_prefix(&format!("{h}/")) {
                    mentions.insert(format!("~/{rest}"));
                }
            }
            mentions.insert(joined);
        }
        Some(Self {
            spellings,
            mentions: mentions.into_iter().filter(|m| !m.is_empty()).collect(),
            value,
            home: home.map(str::to_string),
        })
    }

    /// Does the command text spell the directory? A path spelling counts
    /// only on a path boundary, so `…/Runbooks-old` or `/other/vault/Runbooks`
    /// does not name `/vault/Runbooks`.
    fn named_in(&self, command: &str) -> bool {
        let lower = command.to_ascii_lowercase();
        let path_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
        self.mentions.iter().any(|m| {
            lower.match_indices(m.as_str()).any(|(at, _)| {
                let before = lower[..at].chars().next_back();
                let after = lower[at + m.len()..].chars().next();
                let open_before = m.starts_with('$') || !before.is_some_and(path_char);
                let open_after = if m.starts_with('$') {
                    !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                } else {
                    !after.is_some_and(|c| path_char(c) && c != '/')
                };
                open_before && open_after
            })
        })
    }

    /// Expand `$CADENCE_RUNBOOKS_DIR` / `$HOME` (bare or braced, on an
    /// identifier boundary) and a leading `~`/`~/` in a shell word.
    fn expand(&self, word: &str) -> String {
        if !word.contains(['$', '~']) {
            return word.to_string();
        }
        let mut text = word.to_string();
        for (name, value) in [
            (DIR_ENV, Some(self.value.as_str())),
            ("HOME", self.home.as_deref()),
        ] {
            if let Some(value) = value {
                text = substitute_var(&text, name, value);
            }
        }
        expand_home(&text, self.home.as_deref())
    }
}

/// Replace `$name` and `${name}` in `text` with `value`, only where the bare
/// form ends on an identifier boundary (`$HOMEX` is another variable).
fn substitute_var(text: &str, name: &str, value: &str) -> String {
    let text = text.replace(&format!("${{{name}}}"), value);
    let bare = format!("${name}");
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find(&bare) {
        let after = &rest[at + bare.len()..];
        out.push_str(&rest[..at]);
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            out.push_str(&bare);
        } else {
            out.push_str(value);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A leading `~` or `~/` replaced with `home`; any other text unchanged.
fn expand_home(text: &str, home: Option<&str>) -> String {
    match home {
        Some(home) if text == "~" => home.to_string(),
        Some(home) => text
            .strip_prefix("~/")
            .map(|rest| format!("{}/{rest}", home.trim_end_matches('/')))
            .unwrap_or_else(|| text.to_string()),
        None => text.to_string(),
    }
}

/// `text` as absolute components: as-is when rooted, else under `cwd`.
fn absolute(text: &str, cwd: &str, shell: bool) -> Vec<Comp> {
    let text = text.replace('\\', "/");
    if text.starts_with('/') {
        PathShape::parse(&text, shell)
    } else {
        let mut comps = PathShape::parse(cwd, false);
        comps.extend(PathShape::parse(&text, shell));
        comps
    }
}

/// How one write target relates to the directory.
#[derive(Debug, PartialEq, Eq)]
enum Landing {
    Inside,
    /// The location depends on something the hook cannot read.
    Unknown,
    Outside,
}

/// Where a Bash write target lands, judged against every directory the
/// command may run it in.
fn bash_target_landing(
    target: &str,
    work_dirs: &[&str],
    dir: &RunbooksDir,
    resolver: &Resolver,
) -> Landing {
    let text = dir.expand(target);
    // `~user` (the only `~` form left after expansion) is someone's home.
    let mut unknown = text.starts_with('~');
    let bases: &[&str] = if text.starts_with('/') {
        &["/"]
    } else {
        work_dirs
    };
    for base in bases {
        if *base == UNRESOLVABLE_DIR {
            unknown = true;
            continue;
        }
        let shape = PathShape(absolute(&text, base, true));
        if shape.lands_in(&dir.spellings, resolver) {
            return Landing::Inside;
        }
        unknown |= shape.has_opaque();
    }
    if unknown {
        Landing::Unknown
    } else {
        Landing::Outside
    }
}

/// The first Bash write target that lands in the directory — or, failing
/// that, one whose location the hook cannot read when the command names the
/// directory. Each segment's targets are judged in the directory that segment
/// runs in ([`command_segments_with_dirs`]), the payload `cwd`, and the
/// whole-command `cd` reading ([`parse_work_dir`]), keeping the sharpest
/// verdict.
///
/// Each judgment costs time linear in the target and the directories it is
/// judged in, and a flood of long `cd` chains and targets multiplies the two.
/// Past [`JUDGE_BUDGET`] bytes of judged text the command is refused as too
/// large to judge (the over-block direction): the hook deadline fails open,
/// so running out the clock must not be a way through.
fn bash_write_into(command: &str, cwd: &str, dir: &RunbooksDir) -> Option<BashFinding> {
    let whole = parse_work_dir(command, cwd);
    let mut judged: HashSet<(String, Rc<str>)> = HashSet::new();
    let mut unknown: Option<String> = None;
    let mut any_write: Option<String> = None;
    let mut writer: Option<String> = None;
    let mut spent = 0usize;
    let resolver = Resolver::default();
    for (segment, seg_dir) in command_segments_with_dirs(command, cwd) {
        if writer.is_none() {
            writer = unvetted_program(&segment_command_argv(&segment));
        }
        for target in segment_write_targets(&segment) {
            if !judged.insert((target.clone(), seg_dir.clone())) {
                continue;
            }
            spent += target.len() + seg_dir.len() + cwd.len() + whole.len();
            if spent > JUDGE_BUDGET {
                return Some(BashFinding::TooLarge);
            }
            let mut bases: Vec<&str> = vec![&seg_dir, cwd, &whole];
            bases.dedup();
            match bash_target_landing(&target, &bases, dir, &resolver) {
                Landing::Inside => return Some(BashFinding::Target(target)),
                Landing::Unknown => {
                    unknown.get_or_insert(target);
                }
                Landing::Outside => {
                    if !is_stream_sink(&target) {
                        any_write.get_or_insert(target);
                    }
                }
            }
        }
    }
    // A command that names the directory may read it, and nothing else: any
    // write it makes, and any program whose writes the parser cannot see
    // (an interpreter, `tar -x`, `git`, `mkdir`, …), is refused.
    if !dir.named_in(command) {
        return None;
    }
    unknown
        .or(any_write)
        .map(BashFinding::Target)
        .or_else(|| writer.map(BashFinding::Program))
}

/// Programs a command naming the runbooks directory may run: each only reads
/// its operands, or writes nothing but standard output. Matched on the peeled
/// command word ([`segment_command_argv`]), byte-exact, because this list
/// grants an allow. `find` qualifies only without a writing or exec action.
const READ_ONLY_PROGRAMS: &[&str] = &[
    "cat",
    "ls",
    "head",
    "tail",
    "wc",
    "grep",
    "egrep",
    "fgrep",
    "stat",
    "file",
    "diff",
    "cmp",
    "du",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "test",
    "[",
    "[[",
    "echo",
    "printf",
    "pwd",
    "cd",
    "pushd",
    "popd",
    "true",
    "false",
    ":",
    "less",
    "more",
    "bat",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "shasum",
    "b2sum",
    "cksum",
    "cut",
    "tr",
    "nl",
    "column",
    "tac",
    "rev",
    "jq",
    "find",
];

/// `find` actions that write, delete, or run another program.
const FIND_WRITING_ACTIONS: &[&str] = &[
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls",
];

/// The command word of `argv` when it is a program outside
/// [`READ_ONLY_PROGRAMS`] (or a `find` with a writing action). `None` for an
/// empty or assignment-only segment.
fn unvetted_program(argv: &[String]) -> Option<String> {
    let word = argv
        .iter()
        .find(|w| !is_assignment(w))
        .map(|w| command_word(w).into_owned())?;
    let vetted = READ_ONLY_PROGRAMS.contains(&word.as_str())
        && (word != "find"
            || !argv
                .iter()
                .any(|a| FIND_WRITING_ACTIONS.contains(&a.as_str())));
    (!vetted).then_some(word)
}

/// `NAME=value`: a shell variable assignment, not a program.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// A redirect target that is a stream, not a file: `/dev/null`, the standard
/// streams, the terminal, or a descriptor duplication (`&1`).
fn is_stream_sink(target: &str) -> bool {
    target.starts_with('&')
        || matches!(
            target,
            "/dev/null" | "/dev/stdout" | "/dev/stderr" | "/dev/tty" | "/dev/fd/1" | "/dev/fd/2"
        )
}

/// Why a Bash command is refused.
#[derive(Debug, PartialEq, Eq)]
enum BashFinding {
    /// This write target lands inside, or may and the command names the dir.
    Target(String),
    /// The command names the dir and runs this program, whose writes the
    /// parser cannot see.
    Program(String),
    /// The command is past [`JUDGE_BUDGET`].
    TooLarge,
}

/// True when a Write-tool path lands in the directory.
fn file_path_lands_in(path: &str, cwd: &str, dir: &RunbooksDir) -> bool {
    PathShape(absolute(path, cwd, false)).lands_in(&dir.spellings, &Resolver::default())
}

fn echo(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > MAX_ECHO {
        format!("{}…", clean.chars().take(MAX_ECHO).collect::<String>())
    } else {
        clean
    }
}

/// The two scrub commands and the escape, shared by every block.
const FIX_AND_ESCAPE: &str = "Fix: scrub the draft OUTSIDE the runbooks directory, then promote it \
     with the Write tool:\n     \
     1. `python3 scrub.py --apply <draft>`, then `python3 scrub.py <draft>` (check mode) \
     until it exits 0 — scrub.py ships with the cadence:mining-runbooks skill\n     \
     2. `cadence-hooks cadence record-scrub --file <draft>` — records the scrubbed \
     content's SHA-256\n     \
     3. Write that exact content into the runbooks directory; any later change to it \
     needs a fresh scrub and record.\n   \
     Escape: CADENCE_ALLOW_UNSCRUBBED_RUNBOOK=1 in a personal settings \"env\" block \
     (.claude/settings.local.json or ~/.claude/settings.json, never the shared \
     .claude/settings.json) allows it and records a bypass row. The hook reads Claude \
     Code's environment, not the command's, so an inline prefix does nothing; the setting \
     takes effect next session.";

fn write_block(path: &str, why: &str) -> String {
    format!(
        "🚫 BLOCKED: guard-runbook-scrub: {why}\n   \
         Found:  {}\n   \
         Why:    runbooks under $CADENCE_RUNBOOKS_DIR are promoted from transcript-derived \
         text into a vault that is backed up off-machine; the secret scrub is the gate.\n   \
         {FIX_AND_ESCAPE}",
        echo(path)
    )
}

fn bash_block(target: &str) -> String {
    format!(
        "🚫 BLOCKED: guard-runbook-scrub: this command writes into the runbooks directory \
         ($CADENCE_RUNBOOKS_DIR), and what a shell command writes cannot be matched to a \
         scrub marker before it runs.\n   \
         Found:  {}\n   \
         {FIX_AND_ESCAPE}",
        echo(target)
    )
}

/// Guards the runbooks directory against unscrubbed writes.
pub struct RunbookScrubGuard;

impl Check for RunbookScrubGuard {
    fn name(&self) -> &str {
        "guard-runbook-scrub"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let dir = std::env::var(DIR_ENV).ok();
        let escape = std::env::var(ESCAPE_ENV).ok();
        let home = cadence_hooks_core::paths::user_home().map(|h| h.to_string_lossy().into_owned());
        self.run_with(
            input,
            dir.as_deref(),
            escape.as_deref(),
            home.as_deref(),
            &markers::scrub_marker_present,
        )
    }
}

impl RunbookScrubGuard {
    /// [`Check::run`] with every environment input passed in, so tests need no
    /// env mutation and an ambient escape cannot turn a block-expecting
    /// assertion into a false pass (cadence-hooks#486).
    fn run_with(
        &self,
        input: &HookInput,
        dir: Option<&str>,
        escape: Option<&str>,
        home: Option<&str>,
        marked: &dyn Fn(&str) -> bool,
    ) -> CheckResult {
        let cwd = input
            .cwd
            .clone()
            .filter(|c| !c.trim().is_empty())
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|d| d.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "/".to_string());
        let Some(dir) = RunbooksDir::resolve(dir, home, &cwd) else {
            return CheckResult::allow();
        };

        let message = match input.normalized_tool_name().unwrap_or("") {
            "Write" | "Edit" | "MultiEdit" => {
                let destination = input
                    .tool_input
                    .as_ref()
                    .and_then(|ti| ti.destination.as_deref())
                    .filter(|d| file_path_lands_in(d, &cwd, &dir));
                if let Some(destination) = destination {
                    Some(write_block(
                        destination,
                        "this moves or copies a file into the runbooks directory, whose \
                         content cannot be matched to a scrub marker.",
                    ))
                } else {
                    let Some(path) = input.file_path() else {
                        return CheckResult::allow();
                    };
                    if !file_path_lands_in(&path, &cwd, &dir) {
                        return CheckResult::allow();
                    }
                    match input.effective_content() {
                        Some(content) if marked(&markers::scrub_digest(content.as_bytes())) => {
                            return CheckResult::allow();
                        }
                        Some(_) => Some(write_block(
                            &path,
                            "this write lands in the runbooks directory, and the resulting \
                             content has no scrub marker.",
                        )),
                        // Fail closed: an Edit of a file this hook cannot read
                        // has a resulting document nobody can vouch for.
                        None => Some(write_block(
                            &path,
                            "this edit lands in the runbooks directory, and its resulting \
                             content cannot be computed to check for a scrub marker.",
                        )),
                    }
                }
            }
            "Bash" => {
                let Some(command) = input.command() else {
                    return CheckResult::allow();
                };
                bash_write_into(command, &cwd, &dir).map(|finding| match finding {
                    BashFinding::Target(target) => bash_block(&target),
                    BashFinding::Program(program) => format!(
                        "🚫 BLOCKED: guard-runbook-scrub: this command names the runbooks \
                         directory ($CADENCE_RUNBOOKS_DIR) and runs `{}`, whose writes cannot \
                         be seen before it runs. A command that names the directory may only \
                         read it (cat, ls, grep, head, find without -exec/-delete, …).\n   \
                         {FIX_AND_ESCAPE}",
                        echo(&program)
                    ),
                    BashFinding::TooLarge => format!(
                        "🚫 BLOCKED: guard-runbook-scrub: this command carries too many write \
                         targets and directory changes to judge whether one lands in the \
                         runbooks directory ($CADENCE_RUNBOOKS_DIR), so it is refused rather \
                         than waved through.\n   \
                         If it does not write a runbook, split it into smaller commands.\n   {FIX_AND_ESCAPE}"
                    ),
                })
            }
            _ => None,
        };
        let Some(message) = message else {
            return CheckResult::allow();
        };
        // Evaluated only once the guard WOULD block, so an operator who leaves
        // the escape set records no bypass row for unrelated commands.
        if is_truthy(escape) {
            return CheckResult::allow_bypassed(BypassProvenance::env_switch(ESCAPE_ENV));
        }
        CheckResult::block(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::git_fixtures::Scratch;
    use cadence_hooks_core::test_builders::{
        make_bash_with_cwd, make_edit, make_multi_edit, make_write,
    };
    use std::cell::RefCell;

    /// A fixture tree outside `/tmp` and every carve-out ([`Scratch`]):
    /// `<root>/vault/Runbooks` is the protected dir, `<root>/work` a sibling,
    /// and `<root>/link` a symlink to the protected dir. `tag` is unique per
    /// test, since [`Scratch`] keys on tag + pid and tests share a process.
    struct Fixture {
        _scratch: Scratch,
        runbooks: String,
        work: String,
        root: String,
    }

    fn fixture(tag: &str) -> Fixture {
        let scratch_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/guard-runbook-scrub-scratch");
        let scratch = Scratch::new(&scratch_root, tag);
        let path = scratch.path().canonicalize().unwrap();
        let runbooks = path.join("vault/Runbooks");
        std::fs::create_dir_all(&runbooks).unwrap();
        std::fs::create_dir_all(path.join("work")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&runbooks, path.join("link")).unwrap();
        Fixture {
            runbooks: runbooks.to_string_lossy().into_owned(),
            work: path.join("work").to_string_lossy().into_owned(),
            root: path.to_string_lossy().into_owned(),
            _scratch: scratch,
        }
    }

    fn with_cwd(mut input: HookInput, cwd: &str) -> HookInput {
        input.cwd = Some(cwd.to_string());
        input
    }

    /// Run with the dir set, no escape, and a marker set of `marks`.
    fn run(input: &HookInput, dir: Option<&str>, marks: &[&str]) -> CheckResult {
        let digests: Vec<String> = marks
            .iter()
            .map(|m| markers::scrub_digest(m.as_bytes()))
            .collect();
        RunbookScrubGuard.run_with(input, dir, None, Some("/home/op"), &|d| {
            digests.iter().any(|x| x == d)
        })
    }

    fn outcome(input: &HookInput, dir: Option<&str>, marks: &[&str]) -> Outcome {
        run(input, dir, marks).outcome
    }

    #[test]
    fn inert_when_the_directory_is_unset_or_blank() {
        let f = fixture("inert-when-the-directory-is-unset-or-bla");
        let write = with_cwd(make_write(&format!("{}/a.md", f.runbooks), "x"), &f.work);
        let bash = make_bash_with_cwd(&format!("echo x > {}/a.md", f.runbooks), &f.work);
        for dir in [None, Some(""), Some("   ")] {
            assert_eq!(outcome(&write, dir, &[]), Outcome::Allow, "{dir:?}");
            assert_eq!(outcome(&bash, dir, &[]), Outcome::Allow, "{dir:?}");
        }
    }

    #[test]
    fn write_tool_rows() {
        let f = fixture("write-tool-rows");
        let rb = f.runbooks.as_str();
        let dir = Some(rb);
        // (path, content, marked contents, expected)
        let rows: Vec<(String, &str, Vec<&str>, Outcome)> = vec![
            // Unmarked write under the dir blocks.
            (format!("{rb}/new.md"), "body", vec![], Outcome::Block),
            // Nested and the dir itself.
            (format!("{rb}/sub/deep.md"), "body", vec![], Outcome::Block),
            // A marker for the identical content allows.
            (format!("{rb}/new.md"), "body", vec!["body"], Outcome::Allow),
            // A marker for different content does not.
            (
                format!("{rb}/new.md"),
                "body!",
                vec!["body"],
                Outcome::Block,
            ),
            // Case-folded spelling of the dir (case-insensitive volumes).
            (
                format!("{}/VAULT/runbooks/x.md", f.root),
                "body",
                vec![],
                Outcome::Block,
            ),
            // `..` escape back into the dir.
            (
                format!("{}/../vault/Runbooks/x.md", f.work),
                "body",
                vec![],
                Outcome::Block,
            ),
            // Trailing-slash / doubled-slash spellings.
            (format!("{rb}//x.md"), "body", vec![], Outcome::Block),
            // Outside the dir: unaffected.
            (format!("{}/x.md", f.work), "body", vec![], Outcome::Allow),
            // A sibling whose name only starts with the dir's.
            (format!("{rb}-old/x.md"), "body", vec![], Outcome::Allow),
            (
                format!("{}/vault/x.md", f.root),
                "body",
                vec![],
                Outcome::Allow,
            ),
            // `..` out of the dir.
            (format!("{rb}/../x.md"), "body", vec![], Outcome::Allow),
        ];
        for (path, content, marks, want) in rows {
            let input = with_cwd(make_write(&path, content), &f.work);
            assert_eq!(outcome(&input, dir, &marks), want, "{path} {content:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_paths_resolve_to_the_directory() {
        let f = fixture("symlinked-paths-resolve-to-the-directory");
        // Through a symlinked directory.
        let via_link = with_cwd(make_write(&format!("{}/link/x.md", f.root), "b"), &f.work);
        assert_eq!(outcome(&via_link, Some(&f.runbooks), &[]), Outcome::Block);
        // A symlinked *file* outside pointing at a (not-yet-existing) runbook.
        let file_link = format!("{}/innocent.md", f.work);
        std::os::unix::fs::symlink(format!("{}/target.md", f.runbooks), &file_link).unwrap();
        let input = with_cwd(make_write(&file_link, "b"), &f.work);
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
        // The dir configured through the symlink; a real-path write still blocks.
        let input = with_cwd(make_write(&format!("{}/y.md", f.runbooks), "b"), &f.work);
        let link_dir = format!("{}/link", f.root);
        assert_eq!(outcome(&input, Some(&link_dir), &[]), Outcome::Block);
        // `..` applied after the symlink, as the kernel does: link/.. is vault.
        let input = with_cwd(
            make_write(&format!("{}/link/../Runbooks/z.md", f.root), "b"),
            &f.work,
        );
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
    }

    #[test]
    fn edit_is_judged_on_the_simulated_resulting_document() {
        let f = fixture("edit-is-judged-on-the-simulated-resultin");
        let path = format!("{}/existing.md", f.runbooks);
        std::fs::write(&path, "alpha SECRET omega").unwrap();
        let edit = with_cwd(make_edit(&path, "SECRET", "[redacted]"), &f.work);
        // Marker for the fragment alone does not count; the whole result does.
        assert_eq!(
            outcome(&edit, Some(&f.runbooks), &["[redacted]"]),
            Outcome::Block
        );
        assert_eq!(
            outcome(&edit, Some(&f.runbooks), &["alpha [redacted] omega"]),
            Outcome::Allow
        );
        let multi = with_cwd(
            make_multi_edit(&path, &[("alpha", "a"), ("omega", "o")]),
            &f.work,
        );
        assert_eq!(
            outcome(&multi, Some(&f.runbooks), &["a SECRET o"]),
            Outcome::Allow
        );
        // An Edit whose file cannot be read: no resulting document, block.
        let missing = with_cwd(
            make_edit(&format!("{}/absent.md", f.runbooks), "a", "b"),
            &f.work,
        );
        assert_eq!(outcome(&missing, Some(&f.runbooks), &["b"]), Outcome::Block);
    }

    #[test]
    fn bash_rows() {
        let f = fixture("bash-rows");
        let rb = f.runbooks.as_str();
        let rows: Vec<(String, Outcome)> = vec![
            (format!("echo x > {rb}/a.md"), Outcome::Block),
            (format!("echo x >> {rb}/a.md"), Outcome::Block),
            (format!("echo x | tee {rb}/a.md"), Outcome::Block),
            (
                format!("echo x | tee -a {rb}/a.md >/dev/null"),
                Outcome::Block,
            ),
            (format!("cp draft.md {rb}/a.md"), Outcome::Block),
            (format!("cp draft.md {rb}"), Outcome::Block),
            (format!("cp -t {rb} draft.md"), Outcome::Block),
            (format!("mv draft.md {rb}/"), Outcome::Block),
            (format!("install -m 644 draft.md {rb}/a.md"), Outcome::Block),
            (format!("rsync -av draft.md {rb}/"), Outcome::Block),
            (
                format!("rsync -av draft.md {rb}/ --exclude tmp"),
                Outcome::Block,
            ),
            (
                format!("rsync --log-file={rb}/log x /elsewhere/"),
                Outcome::Block,
            ),
            (format!("sudo cp draft.md {rb}/a.md"), Outcome::Block),
            (format!("bash -c 'cat draft > {rb}/a.md'"), Outcome::Block),
            (format!("cd {rb} && echo x > a.md"), Outcome::Block),
            (format!("{{ echo x; }} > {rb}/a.md"), Outcome::Block),
            (format!("echo x > \"{rb}/my note.md\""), Outcome::Block),
            (
                format!("echo x > {}/../vault/Runbooks/a.md", f.work),
                Outcome::Block,
            ),
            (
                format!("echo x > {}/vault/Run*/a.md", f.root),
                Outcome::Block,
            ),
            (
                "echo x > $CADENCE_RUNBOOKS_DIR/a.md".to_string(),
                Outcome::Block,
            ),
            (
                "echo x > \"${CADENCE_RUNBOOKS_DIR}/a.md\"".to_string(),
                Outcome::Block,
            ),
            // A variable the hook cannot see, in a command naming the dir.
            (format!("D={rb}; F=$D; echo x > $F/a.md"), Outcome::Block),
            (
                format!("cd \"$(echo {rb})\" && echo x > a.md"),
                Outcome::Block,
            ),
            // A trailing redirect no longer hides the destination.
            (format!("cp draft.md {rb}/ 2>/dev/null"), Outcome::Block),
            (
                format!("sudo -n cp draft.md {rb}/ > /dev/null 2>&1"),
                Outcome::Block,
            ),
            // `${VAR:-default}`: the parser reads the default; the name blocks.
            (
                "echo x > ${CADENCE_RUNBOOKS_DIR:-/nonexistent}/a".to_string(),
                Outcome::Block,
            ),
            // Naming the dir: any write, or any program outside the read-only
            // list, blocks — these are the writers the parser cannot see.
            (format!("cp {rb}/a.md {}/copy.md", f.work), Outcome::Block),
            (format!("ls {rb} > {}/listing.txt", f.work), Outcome::Block),
            (format!("echo {rb}/ | xargs cp draft.md"), Outcome::Block),
            (format!("tar -xf x.tar -C {rb}"), Outcome::Block),
            (
                format!("python3 -c \"open('{rb}/a.md','w')\""),
                Outcome::Block,
            ),
            (format!("git -C {rb} init"), Outcome::Block),
            (format!("mkdir {rb}/sub"), Outcome::Block),
            (format!("unzip x.zip -d {rb}"), Outcome::Block),
            (format!("find {rb} -name '*.md' -delete"), Outcome::Block),
            (
                format!("find {rb} -name '*.md' -exec sh -c 'x' \\;"),
                Outcome::Block,
            ),
            // Naming the dir to read it stays allowed.
            (format!("cat {rb}/a.md"), Outcome::Allow),
            (format!("grep -rn term {rb} | head -20"), Outcome::Allow),
            (format!("ls -la {rb} 2>/dev/null"), Outcome::Allow),
            (format!("find {rb} -name '*.md' | wc -l"), Outcome::Allow),
            (format!("R={rb}; cat \"$R\"/a.md"), Outcome::Allow),
            // Outside the dir: unaffected.
            (format!("echo x > {}/a.md", f.work), Outcome::Allow),
            ("echo x > draft.md".to_string(), Outcome::Allow),
            (
                "python3 script.py && git commit -m x".to_string(),
                Outcome::Allow,
            ),
            // A sibling or look-alike path does not name the dir.
            (format!("echo x > {rb}-old/a.md"), Outcome::Allow),
            (format!("cp x /elsewhere{rb}"), Outcome::Allow),
            // The variable's bare name in prose is not an expansion.
            (
                "git commit -m 'guard reads CADENCE_RUNBOOKS_DIR'".to_string(),
                Outcome::Allow,
            ),
            // An opaque variable in a command that never names the dir.
            ("echo x > \"$OUT\"".to_string(), Outcome::Allow),
            ("cd \"$D\" && echo x > a.md".to_string(), Outcome::Allow),
        ];
        for (command, want) in rows {
            let input = make_bash_with_cwd(&command, &f.work);
            assert_eq!(outcome(&input, Some(rb), &[]), want, "{command}");
        }
    }

    #[test]
    fn a_relative_bash_write_from_inside_the_directory_blocks() {
        let f = fixture("a-relative-bash-write-from-inside-the-di");
        let input = make_bash_with_cwd("echo x > a.md", &f.runbooks);
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
    }

    #[test]
    fn a_bash_write_blocks_even_when_the_content_is_marked() {
        let f = fixture("a-bash-write-blocks-even-when-the-conten");
        let input = make_bash_with_cwd(&format!("echo body > {}/a.md", f.runbooks), &f.work);
        assert_eq!(
            outcome(&input, Some(&f.runbooks), &["body", "body\n"]),
            Outcome::Block
        );
    }

    #[test]
    fn tilde_and_home_spellings_expand() {
        // The dir configured with `~`, and targets spelled through `~`/$HOME.
        let rows = [
            (
                "~/Vault/Runbooks",
                "echo x > ~/Vault/Runbooks/a.md",
                Outcome::Block,
            ),
            (
                "~/Vault/Runbooks",
                "echo x > $HOME/Vault/Runbooks/a.md",
                Outcome::Block,
            ),
            (
                "/home/op/Vault/Runbooks",
                "echo x > ${HOME}/Vault/Runbooks/a.md",
                Outcome::Block,
            ),
            (
                "/home/op/Vault/Runbooks",
                "echo x > $HOMEDIR/Vault/Runbooks/a.md",
                Outcome::Allow,
            ),
            ("~/Vault/Runbooks", "echo x > ~/Vault/a.md", Outcome::Allow),
        ];
        for (dir, command, want) in rows {
            let input = make_bash_with_cwd(command, "/home/op/work");
            assert_eq!(outcome(&input, Some(dir), &[]), want, "{dir} {command}");
        }
        let write = with_cwd(make_write("/home/op/Vault/Runbooks/a.md", "b"), "/");
        assert_eq!(
            outcome(&write, Some("~/Vault/Runbooks"), &[]),
            Outcome::Block
        );
    }

    #[test]
    fn a_flood_past_the_judge_budget_is_refused_not_waved_through() {
        let f = fixture("judge-budget");
        // Each relative `cd` lengthens the directory every later target is
        // judged in; nothing here names the runbooks dir.
        let flood = (0..12_000)
            .map(|i| format!("cd d && echo>f{i}"))
            .collect::<Vec<_>>()
            .join(" && ");
        let input = make_bash_with_cwd(&flood, &f.work);
        let started = std::time::Instant::now();
        assert_eq!(
            bash_write_into(
                &flood,
                &f.work,
                &RunbooksDir::resolve(Some(&f.runbooks), None, "/").unwrap()
            ),
            Some(BashFinding::TooLarge)
        );
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
        // A short command outside the dir stays well under the budget.
        let small = make_bash_with_cwd("cd d && echo x > f", &f.work);
        assert_eq!(outcome(&small, Some(&f.runbooks), &[]), Outcome::Allow);
    }

    #[test]
    fn the_root_is_never_a_runbooks_directory() {
        let input = with_cwd(make_write("/etc/x", "b"), "/");
        assert_eq!(outcome(&input, Some("/"), &[]), Outcome::Allow);
    }

    #[test]
    fn block_message_names_both_scrub_commands_and_the_escape() {
        let f = fixture("block-message-names-both-scrub-commands-");
        for input in [
            with_cwd(make_write(&format!("{}/a.md", f.runbooks), "b"), &f.work),
            make_bash_with_cwd(&format!("cp x {}/", f.runbooks), &f.work),
        ] {
            let msg = run(&input, Some(&f.runbooks), &[]).message.unwrap();
            assert!(msg.contains("scrub.py --apply"), "{msg}");
            assert!(msg.contains("check mode"), "{msg}");
            assert!(
                msg.contains("cadence-hooks cadence record-scrub --file"),
                "{msg}"
            );
            assert!(msg.contains("CADENCE_ALLOW_UNSCRUBBED_RUNBOOK=1"), "{msg}");
            assert!(msg.contains("never the shared"), "{msg}");
        }
    }

    #[test]
    fn escape_allows_and_records_provenance_only_when_it_would_block() {
        let f = fixture("escape-allows-and-records-provenance-onl");
        let calls = RefCell::new(0);
        let marked = |_: &str| {
            *calls.borrow_mut() += 1;
            false
        };
        let inside = with_cwd(make_write(&format!("{}/a.md", f.runbooks), "b"), &f.work);
        let result =
            RunbookScrubGuard.run_with(&inside, Some(&f.runbooks), Some("1"), None, &marked);
        assert_eq!(result.outcome, Outcome::Allow);
        let bypass = result.bypass.expect("escape records provenance");
        assert_eq!(bypass.mechanism, ESCAPE_ENV);

        let bash = make_bash_with_cwd(&format!("cp x {}/", f.runbooks), &f.work);
        let result =
            RunbookScrubGuard.run_with(&bash, Some(&f.runbooks), Some("yes"), None, &marked);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.bypass.is_some());

        // Outside the dir: a plain allow, no bypass row.
        let outside = with_cwd(make_write(&format!("{}/a.md", f.work), "b"), &f.work);
        let result =
            RunbookScrubGuard.run_with(&outside, Some(&f.runbooks), Some("1"), None, &marked);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.bypass.is_none());

        // A falsy escape does nothing.
        let result =
            RunbookScrubGuard.run_with(&inside, Some(&f.runbooks), Some("0"), None, &marked);
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn a_symlink_loop_terminates_and_falls_back_to_the_lexical_reading() {
        let f = fixture("a-symlink-loop-does-not-hang-or-allow");
        #[cfg(unix)]
        {
            let a = format!("{}/loop-a", f.work);
            let b = format!("{}/loop-b", f.work);
            std::os::unix::fs::symlink(&b, &a).unwrap();
            std::os::unix::fs::symlink(&a, &b).unwrap();
            assert!(physical(Path::new(&format!("{a}/x"))).is_none());
            let input = with_cwd(make_write(&format!("{a}/x.md"), "b"), &f.work);
            assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Allow);
        }
    }
}
