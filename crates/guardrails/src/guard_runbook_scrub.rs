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
//!   on-disk file with every edit applied — [`resulting_document`]) hashes to
//!   a marker `cadence-hooks cadence record-scrub --file <path>` recorded
//!   ([`markers::scrub_marker_present`]; the digest is line-ending-insensitive).
//!   A resulting document that cannot be computed blocks: an Edit of an
//!   unreadable file, an edit whose `old_string` is not found literally in the
//!   document so far (Claude Code's own Edit normalizes curly quotes, so it
//!   may apply an edit this simulation cannot), or an edit entry without a
//!   readable `old_string`/`new_string` pair (an MCP `edit_file`'s
//!   `oldText`/`newText`). An MCP move into the directory arrives as a Write
//!   with no content and blocks the same way.
//! - **Bash** writing into the directory — a redirect or a writer verb (`tee`,
//!   `cp`/`mv`/`install`/`ln`, `rsync`, `dd`, `truncate`, `touch`, `rm`,
//!   `sed -i`, …), as `prevent-secret-writes` parses them
//!   ([`segment_write_targets`]) — blocks outright: the bytes a command writes
//!   are not knowable before it runs, so there is nothing to match a marker
//!   against. The message points at the Write-tool path.
//! - **The scrub-marker directory** ([`markers::polish_dir`]) is refused as a
//!   write target to every one of those tools, so a marker cannot be forged by
//!   writing the file `record-scrub` would have written. That refusal is part
//!   of this guard, so it too is active only while `$CADENCE_RUNBOOKS_DIR` is
//!   set.
//!
//! **Where a path lands** is decided on two readings, and either one landing
//! inside is enough ([`PathShape::lands_in`]): the lexical path (`..` folded
//! textually) and the physical one (every existing symlink on the way
//! followed, `..` applied after it, as the kernel does). Components compare
//! ASCII-case-insensitively, because the vault lives on a case-insensitive
//! volume on macOS. A Bash target's glob component (`*`, `?`, `[`, `{`)
//! matches any single directory name; a `~` or `$HOME` / `$CADENCE_RUNBOOKS_DIR`
//! (bare, braced, or with a `:-`/`-`/`:=`/`=` default) is expanded, and a
//! `$PWD`, `${PWD}` or `~+` is read as each directory the target may be judged
//! in; a relative target is judged against the payload `cwd`, the
//! whole-command `cd` reading ([`parse_work_dir`]) and the directory its own
//! segment runs in ([`command_segments_with_dirs`]), keeping the sharpest verdict.
//!
//! **A command that names the directory may only read it.** A command names
//! the directory when its text spells it — its configured, lexical, physical,
//! or `~/` form, on a path boundary (a short flag's attached value, `-C/…`,
//! counts), read after `$HOME`/`${HOME}`/`~` are expanded and `//` and `/./`
//! collapsed; or `$CADENCE_RUNBOOKS_DIR` / `${CADENCE_RUNBOOKS_DIR…` as an
//! expansion — or when a segment runs *inside* the directory, or runs in its
//! parent with a word that is the directory's own name (`tar -C Runbooks`,
//! `unzip -d Runbooks/`). Such a command also blocks on: any write target anywhere (other than
//! `/dev/null` and the standard streams); a target whose location the hook
//! cannot read (another variable, a substitution, `~user`, `**`, a relative
//! target after an unreadable `cd`); and any program outside a short read-only
//! list ([`READ_ONLY_PROGRAMS`]) — which is what catches the writers the
//! parser cannot see (`python -c`, `tar -x -C`, `git -C`, `mkdir`, `xargs cp`
//! fed on stdin, `unzip -d`, …).
//!
//! A listed reader counts as read-only only without the options that make it
//! write or run a program (`sort -o`/`-T`, `tree -o`/`-R`, `fd -x`, `rg --pre`,
//! a second `uniq` operand; long options matched by any `getopt_long` prefix)
//! and without a `NAME=value` assignment in front of it (`LESSOPEN=… less`,
//! `env RIPGREP_CONFIG_PATH=… rg`), or a standalone assignment of a variable
//! that steers one (`LESSOPEN=…; less f`, `PATH=…; cat f`).
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
//! - A relative spelling of the directory inside a program's own argument
//!   text, run from the parent (`python3 -c "open('Runbooks/a.md','w')"` in
//!   the vault): only a whole word equal to the directory's name counts.
//! - A `${HOME:-…}` whose default runs past [`MAX_DEFAULT_SCAN`] bytes stays
//!   unexpanded (opaque).
//! - MCP write verbs the tool-name classifier does not recognize
//!   (`append_file`, `save_file`, `str_replace`, `copy_file`, …) are not
//!   classified as writes and reach no branch of this guard.
//! - **Known miss:** a recursive copy or move into the marker directory's
//!   grandparent or higher (`cp -r forged ~/.claude`) is not refused; only
//!   the marker directory itself and its exact parent are.
//! - A lesskey file or `bat` config planted earlier in the real `$HOME`
//!   steers `less`/`bat` without any assignment in the command.
//! - A write into the marker directory through a location the hook cannot
//!   read, or by a program whose writes it cannot see, is not caught: the
//!   marker-dir refusal judges write targets only. (`record-scrub` itself
//!   trusts its caller, so it is the simpler forgery anyway.)
//! - `NotebookEdit` carries its target in `notebook_path`, which no guard
//!   reads; a notebook is not a runbook.
//!
//! **Known over-blocks (the safe direction, documented):**
//! - A session whose cwd is inside the directory: every command running a
//!   program outside the read-only list (`git status`, `python3 x.py`) blocks.
//! - A read of the directory that writes elsewhere: `ls Runbooks > /tmp/list`
//!   from the vault root names the directory and makes a write, so it blocks.
//! - An Edit that creates a new file (empty `old_string`) under the directory
//!   blocks as uncomputable; create it with the Write tool.
//! - Any write target that is exactly the marker directory's parent blocks,
//!   whatever the writer (a recursive copy there could land a forged marker
//!   directory) — unless that parent is the root or a shared temp dir.
//! - A mention is read additively (raw, expanded, and normalized text), so a
//!   spelling that walks back out (`…/Runbooks/../x.md`) still names it.
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
    UNRESOLVABLE_DIR, command_segments_with_dirs, command_word, parse_work_dir, tokenize,
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

/// Longest `${NAME:-default}` body [`substitute_var`] scans for its closing
/// brace. Past it the reference stays unexpanded (opaque), which keeps a flood
/// of unclosed `${HOME:-` openers linear.
const MAX_DEFAULT_SCAN: usize = 1024;

/// A character that can continue a path word in [`RunbooksDir::mention_text`].
fn mention_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '~' | '+' | '@')
}

/// `out` ends with `/..`: drop it and the component before it, when that
/// component is a plain name (not `..`, not empty, only path characters,
/// found within [`MAX_FOLD_SCAN`] bytes). Otherwise leave `out` alone.
fn fold_parent(out: &mut String) {
    let head = &out[..out.len() - 3];
    let mut window = head.len().saturating_sub(MAX_FOLD_SCAN);
    while !head.is_char_boundary(window) {
        window += 1;
    }
    let Some(slash) = head[window..].rfind('/').map(|i| i + window) else {
        return;
    };
    let name = &head[slash + 1..];
    if name.is_empty() || name == ".." || name == "." || !name.chars().all(mention_path_char) {
        return;
    }
    out.truncate(slash);
}

/// How far back [`fold_parent`] looks for the component a `..` cancels.
const MAX_FOLD_SCAN: usize = 4096;

/// True for a two-character drive component (`c:`).
fn is_drive_comp(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// A Windows drive spelling of `text` rewritten as `/x:/rest` (the letter
/// lowercased, separators forward): `X:\…`, `X:/…`, the verbatim `\\?\X:\…`,
/// and — when `git_bash` — Git Bash's `/x/…`. `None` for any other text.
///
/// Pure, so it is tested on every platform; only a Windows build applies it
/// ([`absolute`]), because on Unix `/c/…` is a real path and `C:` a file name.
fn drive_form(text: &str, git_bash: bool) -> Option<String> {
    let forward = text.replace('\\', "/");
    let t = forward.strip_prefix("//?/").unwrap_or(&forward);
    let b = t.as_bytes();
    let rest_ok = |at: usize| b.len() == at || b[at] == b'/';
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && rest_ok(2) {
        return Some(format!(
            "/{}:{}",
            b[0].to_ascii_lowercase() as char,
            &t[2..]
        ));
    }
    if git_bash && b.len() >= 2 && b[0] == b'/' && b[1].is_ascii_alphabetic() && rest_ok(2) {
        return Some(format!(
            "/{}:{}",
            b[1].to_ascii_lowercase() as char,
            &t[2..]
        ));
    }
    None
}

/// The extra command spellings of a drive-rooted mention `/x:/rest`:
/// `x:/rest` (native, after the command copy's `\` → `/`) and Git Bash's
/// `/x/rest`. Empty for any other mention. Pure; applied on Windows only.
fn drive_mentions(joined: &str) -> Vec<String> {
    let b = joined.as_bytes();
    if b.len() >= 3
        && b[0] == b'/'
        && is_drive_comp(&joined[1..3])
        && (b.len() == 3 || b[3] == b'/')
    {
        vec![
            joined[1..].to_string(),
            format!("/{}{}", &joined[1..2], &joined[3..]),
        ]
    } else {
        Vec::new()
    }
}

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
        for (i, c) in self.0[..split].iter().enumerate() {
            match c {
                // A drive component roots the path on that drive (Windows).
                Comp::Lit(name) if i == 0 && cfg!(windows) && is_drive_comp(name) => {
                    prefix = PathBuf::from(format!("{name}\\"));
                }
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
            // A Windows drive prefix, as the `x:` component [`drive_form`] makes.
            Component::Prefix(p) => {
                drive_form(&p.as_os_str().to_string_lossy(), false).map(|d| d[1..].to_string())
            }
            _ => None,
        })
        .collect()
}

/// The root a walk of `path` starts from: its drive root on Windows
/// (`C:\`), else `/`.
fn walk_root(path: &Path) -> PathBuf {
    match path.components().next() {
        Some(Component::Prefix(p)) => {
            let mut root = PathBuf::from(p.as_os_str());
            root.push(std::path::MAIN_SEPARATOR_STR);
            root
        }
        _ => PathBuf::from("/"),
    }
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
    let mut resolved = walk_root(path);
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
                    resolved = walk_root(&target);
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
            if cfg!(windows) {
                mentions.extend(drive_mentions(&joined));
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
    /// does not name `/vault/Runbooks`; a short-option cluster's attached
    /// value (`-C/vault/Runbooks`, `-xzC/…`) is on one.
    ///
    /// **Additive:** a mention counts when it is found in ANY of three
    /// readings — the raw lowercased text, [`Self::mention_text`] with quotes
    /// kept and no `..` folding, and the fully normalized one — because each
    /// transform also destroys spellings the others keep (`R/..` folds away;
    /// `r"R/x"` loses its boundary once the quote is stripped).
    fn named_in(&self, command: &str) -> bool {
        [
            command.to_ascii_lowercase(),
            self.mention_text(command, false),
            self.mention_text(command, true),
        ]
        .iter()
        .any(|text| self.named_in_text(text))
    }

    fn named_in_text(&self, lower: &str) -> bool {
        let path_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
        self.mentions.iter().any(|m| {
            lower.match_indices(m.as_str()).any(|(at, _)| {
                let head = &lower.as_bytes()[..at];
                let before = lower[..at].chars().next_back();
                let after = lower[at + m.len()..].chars().next();
                // `-C/path`, `-xzC/path`: a word-initial short-option
                // cluster's attached value.
                let letters = head
                    .iter()
                    .rev()
                    .take_while(|b| b.is_ascii_alphabetic())
                    .count();
                let dash = head.len().checked_sub(letters + 1);
                let short_flag = letters > 0
                    && dash.is_some_and(|d| {
                        head[d] == b'-' && (d == 0 || !path_char(head[d - 1] as char))
                    });
                let open_before =
                    m.starts_with('$') || short_flag || !before.is_some_and(path_char);
                let open_after = if m.starts_with('$') {
                    !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                } else {
                    !after.is_some_and(|c| path_char(c) && c != '/')
                };
                open_before && open_after
            })
        })
    }

    /// The lowercased copy of `command` the mention rule reads: quotes and
    /// backslashes removed (`"$HOME"/…`, `/vault/"Runbooks"`, `Run\\books`;
    /// on Windows a `\\` is read as `/` first); `$HOME`, `${HOME}` and its
    /// defaulted forms, and a word-initial `~`/`~/`, expanded; and `//`,
    /// `/./` and `/name/../` folded, so `/vault//Runbooks`,
    /// `/vault/./Runbooks` and `/vault/x/../Runbooks` spell `/vault/Runbooks`.
    /// Never executed or re-parsed: it only feeds a substring search.
    ///
    /// With `normalize` false, quotes and backslashes are kept and `..` is
    /// not folded (only the expansions and `//`/`/./` apply).
    fn mention_text(&self, command: &str, normalize: bool) -> String {
        let unquoted: String = command
            .chars()
            .filter_map(|c| match c {
                '"' | '\'' | '\\' if !normalize => Some(c),
                '"' | '\'' => None,
                '\\' if cfg!(windows) => Some('/'),
                '\\' => None,
                c => Some(c),
            })
            .collect();
        let text = match self.home.as_deref() {
            Some(home) => expand_word_tildes(&substitute_var(&unquoted, "HOME", home), home),
            None => unquoted,
        };
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '/' {
                if out.ends_with('/') {
                    continue;
                }
                if out.ends_with("/.") {
                    out.pop();
                    continue;
                }
            }
            out.push(c.to_ascii_lowercase());
            // `/name/..` just completed: fold it back to before `/name`.
            let at_end = chars
                .peek()
                .is_none_or(|n| *n == '/' || !mention_path_char(*n));
            if normalize && c == '.' && at_end && out.ends_with("/..") {
                fold_parent(&mut out);
            }
        }
        out
    }

    /// True when a directory a segment runs in names the runbooks directory:
    /// it is inside it, or it is its parent and a word of `argv` is the
    /// directory's own name (`tar -C Runbooks`, `unzip -d./Runbooks/`).
    fn named_by_work_dir(&self, work_dir: &str, argv: &[String], resolver: &Resolver) -> bool {
        if work_dir == UNRESOLVABLE_DIR {
            return false;
        }
        let shape = PathShape(absolute(work_dir, "/", false));
        if shape.lands_in(&self.spellings, resolver) {
            return true;
        }
        let readings: Vec<Vec<Comp>> = std::iter::once(shape.lexical())
            .chain(shape.physical(resolver))
            .collect();
        self.spellings.iter().any(|dir| {
            let Some((last, parent)) = dir.split_last() else {
                return false;
            };
            readings
                .iter()
                .any(|comps| comps.len() == parent.len() && reaches(comps, parent))
                && argv.iter().any(|w| word_names(w, last))
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

/// Replace `$name`, `${name}`, and the defaulted `${name:-…}` / `${name-…}`
/// / `${name:=…}` / `${name=…}` in `text` with `value` — each of which is
/// `value` when the variable is set, as the caller asserts it is. The bare
/// form counts only on an identifier boundary (`$HOMEX` is another variable);
/// `${name:+…}` and other operators stay as written (opaque).
fn substitute_var(text: &str, name: &str, value: &str) -> String {
    let bare = format!("${name}");
    let braced = format!("${{{name}");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix(braced.as_str()) {
            if let Some(end) = default_close(after) {
                out.push_str(value);
                rest = &after[end..];
            } else {
                out.push_str(&braced);
                rest = after;
            }
        } else if let Some(after) = tail.strip_prefix(bare.as_str()) {
            let joined = after
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            out.push_str(if joined { &bare } else { value });
            rest = after;
        } else {
            out.push('$');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// For the text after `${name`: the byte offset just past the reference's
/// closing `}` when it is `}` or a `:-`/`-`/`:=`/`=` default (nested braces
/// counted, scanning at most [`MAX_DEFAULT_SCAN`] bytes). `None` otherwise.
fn default_close(after: &str) -> Option<usize> {
    if after.starts_with('}') {
        return Some(1);
    }
    let op = [":-", ":=", "-", "="]
        .iter()
        .find(|op| after.starts_with(**op))?
        .len();
    let mut depth = 0usize;
    for (i, b) in after.bytes().enumerate().skip(op).take(MAX_DEFAULT_SCAN) {
        match b {
            b'{' => depth += 1,
            b'}' if depth == 0 => return Some(i + 1),
            b'}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// `text` with every word-initial `~` (alone, or before `/`) replaced by
/// `home`. A word starts at the text's start or after a character that
/// cannot continue a path (space, quote, `=`, `:`, `(`, …); `~user`, `~+`,
/// `~-` are left alone.
fn expand_word_tildes(text: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    let mut out = String::with_capacity(text.len());
    let mut prev: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let word_start = !prev.is_some_and(|p| {
            p.is_ascii_alphanumeric() || matches!(p, '_' | '-' | '.' | '/' | '~' | '$')
        });
        let ends = chars.peek().is_none_or(|n| {
            *n == '/' || n.is_whitespace() || matches!(n, '"' | '\'' | ';' | '&' | '|' | ')')
        });
        if c == '~' && word_start && ends {
            out.push_str(home);
        } else {
            out.push(c);
        }
        prev = Some(c);
    }
    out
}

/// `target` with `$PWD`, `${PWD}` (and its defaulted forms) and a leading
/// `~+` read as `work_dir`, the directory it is judged in.
fn expand_pwd(target: &str, work_dir: &str) -> String {
    let text = if target.contains("PWD") {
        substitute_var(target, "PWD", work_dir)
    } else {
        target.to_string()
    };
    match text.strip_prefix("~+") {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("{work_dir}{rest}"),
        _ => text,
    }
}

/// True when shell word `word` is the directory name `last` (or a path under
/// it): as-is, after a `--opt=` or a short flag (`-dRunbooks`), with leading
/// `./` and trailing `/` ignored. ASCII-case-insensitive.
fn word_names(word: &str, last: &str) -> bool {
    let mut candidates = vec![word];
    if let Some((_, value)) = word.split_once('=') {
        candidates.push(value);
    }
    if word.starts_with('-') && !word.starts_with("--") && word.len() > 2 {
        candidates.push(&word[2..]);
    }
    candidates.into_iter().any(|c| {
        let mut c = c;
        while let Some(rest) = c.strip_prefix("./") {
            c = rest;
        }
        let c = c.trim_end_matches('/');
        c.len() >= last.len()
            && c.is_char_boundary(last.len())
            && c[..last.len()].eq_ignore_ascii_case(last)
            && (c.len() == last.len() || c.as_bytes()[last.len()] == b'/')
    })
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
///
/// On Windows a drive spelling (`C:\…`, `C:/…`, `\\?\C:\…`, Git Bash's
/// `/c/…`) is rooted on a `c:` component ([`drive_form`]).
fn absolute(text: &str, cwd: &str, shell: bool) -> Vec<Comp> {
    let native = |t: &str| {
        cfg!(windows)
            .then(|| drive_form(t, true))
            .flatten()
            .unwrap_or_else(|| t.replace('\\', "/"))
    };
    let text = native(text);
    if text.starts_with('/') {
        PathShape::parse(&text, shell)
    } else {
        let mut comps = PathShape::parse(&native(cwd), false);
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

/// Where a Bash write target lands relative to the directory spelled
/// `spellings`, judged against every directory the command may run it in.
/// `dir` supplies the `~`/`$HOME`/`$CADENCE_RUNBOOKS_DIR` expansion; a
/// `$PWD`/`~+` is read as each work dir in turn.
fn bash_target_landing(
    target: &str,
    work_dirs: &[&str],
    dir: &RunbooksDir,
    spellings: &[Vec<String>],
    resolver: &Resolver,
) -> Landing {
    let text = dir.expand(target);
    let uses_pwd = text.contains("PWD") || text.starts_with("~+");
    let bases: &[&str] = if text.starts_with('/') && !uses_pwd {
        &["/"]
    } else {
        work_dirs
    };
    let mut unknown = false;
    for base in bases {
        if *base == UNRESOLVABLE_DIR {
            unknown = true;
            continue;
        }
        let text = if uses_pwd {
            expand_pwd(&text, base)
        } else {
            text.clone()
        };
        // `~user` or `~-` (the `~` forms left after expansion): a directory
        // the hook cannot read.
        unknown |= text.starts_with('~');
        let shape = PathShape(absolute(&text, base, true));
        if shape.lands_in(spellings, resolver) {
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

/// True when a Bash write target is exactly the parent of the directory
/// spelled `spellings` (either reading): a recursive copy or move there
/// (`cp -r forged/markers <parent>`) can land a whole forged directory.
fn bash_target_is_parent(
    target: &str,
    work_dirs: &[&str],
    dir: &RunbooksDir,
    spellings: &[Vec<String>],
    resolver: &Resolver,
) -> bool {
    // A parent that is the root or a shared temp dir (a `CADENCE_MARKER_DIR`
    // override under /tmp) is not refused: that would gate every copy there.
    let temp_dirs: Vec<String> = ["/tmp".to_string(), "/private/tmp".to_string()]
        .into_iter()
        .chain(std::env::var("TMPDIR").ok())
        .chain(Some(std::env::temp_dir().to_string_lossy().into_owned()))
        .map(|t| t.trim_end_matches(['/', '\\']).to_ascii_lowercase())
        .collect();
    let parents: Vec<&[String]> = spellings
        .iter()
        .filter(|s| s.len() > 1)
        .map(|s| &s[..s.len() - 1])
        .filter(|p| !temp_dirs.contains(&format!("/{}", p.join("/")).to_ascii_lowercase()))
        .collect();
    if parents.is_empty() {
        return false;
    }
    let text = dir.expand(target);
    let uses_pwd = text.contains("PWD") || text.starts_with("~+");
    let bases: &[&str] = if text.starts_with('/') && !uses_pwd {
        &["/"]
    } else {
        work_dirs
    };
    bases
        .iter()
        .filter(|b| **b != UNRESOLVABLE_DIR)
        .any(|base| {
            let text = if uses_pwd {
                expand_pwd(&text, base)
            } else {
                text.clone()
            };
            let shape = PathShape(absolute(&text, base, true));
            std::iter::once(shape.lexical())
                .chain(shape.physical(resolver))
                .any(|comps| {
                    parents
                        .iter()
                        .any(|p| comps.len() == p.len() && reaches(&comps, p))
                })
        })
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
fn bash_write_into(
    command: &str,
    cwd: &str,
    dir: &RunbooksDir,
    marker_dir: Option<&[Vec<String>]>,
) -> Option<BashFinding> {
    let whole = parse_work_dir(command, cwd);
    let mut judged: HashSet<(String, Rc<str>)> = HashSet::new();
    let mut unknown: Option<String> = None;
    let mut any_write: Option<String> = None;
    let mut writer: Option<String> = None;
    let mut spent = 0usize;
    let resolver = Resolver::default();
    // Work dirs already asked whether they name the runbooks dir, with the
    // argv words they were asked with — a flood repeats one directory.
    let mut dir_named = false;
    let mut asked: HashSet<(Rc<str>, Vec<String>)> = HashSet::new();
    for (segment, seg_dir) in command_segments_with_dirs(command, cwd) {
        let argv = segment_command_argv(&segment);
        if writer.is_none() {
            writer = unvetted_program(&segment, &argv);
        }
        if !dir_named && asked.insert((seg_dir.clone(), argv.clone())) {
            spent += seg_dir.len() + argv.iter().map(String::len).sum::<usize>();
            if spent > JUDGE_BUDGET {
                return Some(BashFinding::TooLarge);
            }
            dir_named = [&*seg_dir, cwd, whole.as_str()]
                .iter()
                .any(|d| dir.named_by_work_dir(d, &argv, &resolver));
        }
        for target in segment_write_targets(&segment) {
            if !judged.insert((target.clone(), seg_dir.clone())) {
                continue;
            }
            spent += target.len() + seg_dir.len() + cwd.len() + whole.len();
            if marker_dir.is_some() {
                spent += target.len() + seg_dir.len() + cwd.len() + whole.len();
            }
            if spent > JUDGE_BUDGET {
                return Some(BashFinding::TooLarge);
            }
            let mut bases: Vec<&str> = vec![&seg_dir, cwd, &whole];
            bases.dedup();
            // Every `$PWD`/`~+` expands to a whole work dir: charge the
            // expanded length, or a short spelling multiplies past the budget.
            let pwd_refs = target.matches("PWD").count() + usize::from(target.starts_with("~+"));
            if pwd_refs > 0 {
                let base_len: usize = bases.iter().map(|b| b.len()).sum();
                let passes = if marker_dir.is_some() { 3 } else { 1 };
                spent =
                    spent.saturating_add(pwd_refs.saturating_mul(base_len).saturating_mul(passes));
                if spent > JUDGE_BUDGET {
                    return Some(BashFinding::TooLarge);
                }
            }
            if let Some(markers) = marker_dir
                && (bash_target_landing(&target, &bases, dir, markers, &resolver)
                    == Landing::Inside
                    || bash_target_is_parent(&target, &bases, dir, markers, &resolver))
            {
                return Some(BashFinding::MarkerTarget(target));
            }
            match bash_target_landing(&target, &bases, dir, &dir.spellings, &resolver) {
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
    if !dir_named && !dir.named_in(command) {
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
    "rg",
    "fd",
    "tree",
    "sort",
    "uniq",
];

/// `find` actions that write, delete, or run another program.
const FIND_WRITING_ACTIONS: &[&str] = &[
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls",
];

/// True when `arg` is a long option that `getopt_long` would read as one of
/// `long` — the full name or any non-empty prefix of it (`--out`, `--o`),
/// bare or with `=value` — or a short-option cluster (`-uo`) carrying one of
/// `shorts`. A prefix another option shares is ambiguous, which the program
/// rejects; refusing it too only over-blocks.
fn has_option(arg: &str, long: &[&str], shorts: &[char]) -> bool {
    if let Some(name) = arg.strip_prefix("--") {
        let name = name.split_once('=').map_or(name, |(n, _)| n);
        return !name.is_empty() && long.iter().any(|l| l.starts_with(name));
    }
    arg.strip_prefix('-')
        .is_some_and(|cluster| cluster.chars().any(|c| shorts.contains(&c)))
}

/// `uniq`'s operands: `-` counts as one; the value word after `-f`/`-s`/`-w`
/// (or a cluster ending in one) and after a bare `--skip-fields`,
/// `--skip-chars`, `--check-chars` (or a prefix) is skipped; everything after
/// `--` is an operand.
fn uniq_operands(args: &[String]) -> usize {
    const VALUE_LONG: &[&str] = &["skip-fields", "skip-chars", "check-chars"];
    let mut count = 0;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            return count + (args.len() - i);
        }
        if a == "-" || !a.starts_with('-') {
            count += 1;
        } else if let Some(name) = a.strip_prefix("--") {
            if !name.contains('=')
                && !name.is_empty()
                && VALUE_LONG.iter().any(|l| l.starts_with(name))
            {
                i += 1;
            }
        } else if let Some(at) = a[1..].find(['f', 's', 'w']) {
            // The rest of the cluster is the value; nothing left: the next word.
            if a.len() == at + 2 {
                i += 1;
            }
        }
    }
    count
}

/// True when a listed program's options make it write a file or run another
/// program: `find` with a writing action; `sort -o`/`--output`,
/// `--compress-program`, `-T`/`--temporary-directory`; `tree -o`/`--output`
/// and `-R` (writes `00Tree.html` into each directory with `-H`);
/// `fd -x`/`-X`/`--exec`/`--exec-batch`; `rg --pre`; and `uniq` with a
/// second operand (its output file); `file -C`/`--compile` (writes a `.mgc`
/// into the cwd). Long options match by prefix
/// ([`has_option`]).
fn writes_or_runs(word: &str, args: &[String]) -> bool {
    let any = |long: &[&str], shorts: &[char]| args.iter().any(|a| has_option(a, long, shorts));
    match word {
        "find" => args
            .iter()
            .any(|a| FIND_WRITING_ACTIONS.contains(&a.as_str())),
        "sort" => any(
            &["output", "compress-program", "temporary-directory"],
            &['o', 'T'],
        ),
        "tree" => any(&["output"], &['o', 'R']),
        "fd" => any(&["exec", "exec-batch"], &['x', 'X']),
        "rg" => any(&["pre"], &[]),
        "file" => any(&["compile"], &['C']),
        "uniq" => uniq_operands(args) > 1,
        _ => false,
    }
}

/// Environment variables that make a listed reader run a program or read
/// another configuration (`LESSOPEN`, `PAGER`, `RIPGREP_CONFIG_PATH`, …), or
/// change which program runs at all (`PATH`, `LD_PRELOAD`).
fn is_steering_var(name: &str) -> bool {
    name.starts_with("LESS")
        || name.starts_with("BAT_")
        || name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || matches!(
            name,
            "RIPGREP_CONFIG_PATH"
                | "PAGER"
                | "MANPAGER"
                | "PATH"
                | "BASH_ENV"
                | "ENV"
                | "EDITOR"
                | "VISUAL"
                | "HOME"
                | "XDG_CONFIG_HOME"
        )
}

/// The command word of `segment` (whose peeled argv is `argv`) when it is a
/// program outside [`READ_ONLY_PROGRAMS`]; a listed one whose options write
/// or run another program ([`writes_or_runs`]); or a listed one run with any
/// `NAME=value` assignment in front of it — directly or through `env`/`sudo`
/// — since an assignment can point a reader at a program (`LESSOPEN`,
/// `RIPGREP_CONFIG_PATH`). An assignment-only segment counts when it sets an
/// [`is_steering_var`] name (`LESSOPEN=…; less f` reaches `less` when the
/// variable was already exported). `None` otherwise.
fn unvetted_program(segment: &str, argv: &[String]) -> Option<String> {
    let Some(at) = argv.iter().position(|w| !is_assignment(w)) else {
        return argv
            .iter()
            .find(|w| w.split_once('=').is_some_and(|(n, _)| is_steering_var(n)))
            .map(|w| echo(w));
    };
    let word = command_word(&argv[at]).into_owned();
    let vetted =
        READ_ONLY_PROGRAMS.contains(&word.as_str()) && !writes_or_runs(&word, &argv[at + 1..]);
    if !vetted {
        return Some(word);
    }
    // Vetted: refuse it if any assignment other than a harmless one comes
    // before it among the raw words (the ones `env`/`sudo` peeling drops
    // included), aligned from the tail since the peeled argv is a suffix of
    // them — or if a steering variable is assigned anywhere in the segment.
    let tokens = tokenize(segment);
    let steered = |w: &String| is_assignment(w) && !is_harmless_assignment(w);
    let tail = argv.len() - at;
    let refused = argv[..at].iter().any(steered)
        || tokens.len() < argv.len()
        || tokens[..tokens.len() - tail].iter().any(steered)
        || tokens.iter().any(|t| {
            is_assignment(t) && t.split_once('=').is_some_and(|(n, _)| is_steering_var(n))
        });
    refused.then(|| format!("{word} (with an environment assignment)"))
}

/// An assignment that cannot steer a listed reader: locale, time zone,
/// terminal size and color switches.
fn is_harmless_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with("LC_")
            || matches!(
                name,
                "LANG" | "LANGUAGE" | "TZ" | "NO_COLOR" | "COLUMNS" | "LINES" | "TERM"
            )
    })
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
    /// This write target lands in the scrub-marker directory.
    MarkerTarget(String),
    /// The command is past [`JUDGE_BUDGET`].
    TooLarge,
}

/// True when a Write-tool path lands in the directory spelled `spellings`.
fn file_path_lands_in(path: &str, cwd: &str, spellings: &[Vec<String>]) -> bool {
    PathShape(absolute(path, cwd, false)).lands_in(spellings, &Resolver::default())
}

/// The document a Write / Edit / MultiEdit leaves on disk, simulated
/// strictly, with `\r\n` read as `\n` on both sides (the scrub digest is
/// line-ending-insensitive). `None` — which the guard blocks on — when it
/// cannot be computed:
///
/// - an Edit/MultiEdit of a file that cannot be read as UTF-8;
/// - an edit whose `old_string` is empty or not found literally in the
///   document so far — Claude Code's Edit normalizes curly quotes and may
///   apply what this simulation cannot, so the result is unknown;
/// - an edit, or an `edits[]` entry, without both an `old_string` and a
///   `new_string` (an MCP `edit_file`'s `oldText`/`newText` entries);
/// - a payload carrying neither content nor any edit (an MCP move's
///   synthesized Write).
///
/// Stricter than [`HookInput::effective_content`], which skips an edit it
/// cannot apply; that helper's other consumers keep its semantics.
fn resulting_document(input: &HookInput) -> Option<String> {
    let ti = input.tool_input.as_ref()?;
    if let Some(content) = ti.content.as_deref() {
        return Some(content.to_string());
    }
    let mut edits: Vec<(Option<&str>, Option<&str>, bool)> = Vec::new();
    if ti.old_string.is_some() || ti.new_string.is_some() {
        edits.push((
            ti.old_string.as_deref(),
            ti.new_string.as_deref(),
            ti.replace_all.unwrap_or(false),
        ));
    }
    for e in ti.edits.iter().flatten() {
        edits.push((
            e.old_string.as_deref(),
            e.new_string.as_deref(),
            e.replace_all.unwrap_or(false),
        ));
    }
    if edits.is_empty() {
        return None;
    }
    let path = Path::new(ti.file_path.as_deref().or(ti.path.as_deref())?);
    // A relative path is the harness's, relative to the payload cwd, not to
    // this hook process's own working directory.
    let path = match input.cwd.as_deref().filter(|c| !c.trim().is_empty()) {
        Some(cwd) if path.is_relative() => Path::new(cwd).join(path),
        _ => path.to_path_buf(),
    };
    let mut doc = std::fs::read_to_string(&path).ok()?.replace("\r\n", "\n");
    for (old, new, all) in edits {
        let (old, new) = (old?.replace("\r\n", "\n"), new?.replace("\r\n", "\n"));
        if old.is_empty() || !doc.contains(&old) {
            return None;
        }
        doc = if all {
            doc.replace(&old, &new)
        } else {
            doc.replacen(&old, &new, 1)
        };
    }
    Some(doc)
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

fn marker_block(target: &str) -> String {
    format!(
        "🚫 BLOCKED: guard-runbook-scrub: this writes into the scrub-marker directory. \
         Scrub markers are recorded only by `cadence-hooks cadence record-scrub`, never \
         written directly.\n   \
         Found:  {}\n   \
         {FIX_AND_ESCAPE}",
        echo(target)
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

    fn refuses_unread_commands(&self) -> bool {
        true
    }

    // `touch`/`mkdir` operands are paths this guard judges.
    fn unread_inert_commands(&self) -> &'static [&'static str] {
        cadence_hooks_core::shell::UNREAD_INERT_COMMANDS
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let dir = std::env::var(DIR_ENV).ok();
        let escape = std::env::var(ESCAPE_ENV).ok();
        let home = cadence_hooks_core::paths::user_home().map(|h| h.to_string_lossy().into_owned());
        let marker_dir = markers::polish_dir().to_string_lossy().into_owned();
        self.run_with(
            input,
            Env {
                dir: dir.as_deref(),
                escape: escape.as_deref(),
                home: home.as_deref(),
                marker_dir: Some(&marker_dir),
            },
            &markers::scrub_marker_present,
        )
    }
}

/// Every environment input [`RunbookScrubGuard::run_with`] reads.
#[derive(Clone, Copy, Default)]
struct Env<'a> {
    /// `$CADENCE_RUNBOOKS_DIR`.
    dir: Option<&'a str>,
    /// `$CADENCE_ALLOW_UNSCRUBBED_RUNBOOK`.
    escape: Option<&'a str>,
    home: Option<&'a str>,
    /// The scrub-marker directory ([`markers::polish_dir`]).
    marker_dir: Option<&'a str>,
}

impl RunbookScrubGuard {
    /// [`Check::run`] with every environment input passed in, so tests need no
    /// env mutation and an ambient escape cannot turn a block-expecting
    /// assertion into a false pass (cadence-hooks#486).
    fn run_with(&self, input: &HookInput, env: Env, marked: &dyn Fn(&str) -> bool) -> CheckResult {
        let Env {
            dir,
            escape,
            home,
            marker_dir,
        } = env;
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
        // The marker directory, as spellings (lexical and physical).
        let marker_spellings = marker_dir
            .and_then(|m| RunbooksDir::resolve(Some(m), home, &cwd))
            .map(|m| m.spellings);

        let message = match input.normalized_tool_name().unwrap_or("") {
            "Write" | "Edit" | "MultiEdit" => {
                let Some(path) = input.file_path() else {
                    return CheckResult::allow();
                };
                if marker_spellings
                    .as_deref()
                    .is_some_and(|m| file_path_lands_in(&path, &cwd, m))
                {
                    Some(marker_block(&path))
                } else if !file_path_lands_in(&path, &cwd, &dir.spellings) {
                    return CheckResult::allow();
                } else {
                    match resulting_document(input) {
                        Some(content) if marked(&markers::scrub_digest(content.as_bytes())) => {
                            return CheckResult::allow();
                        }
                        Some(_) => Some(write_block(
                            &path,
                            "this write lands in the runbooks directory, and the resulting \
                             content has no scrub marker.",
                        )),
                        // Fail closed: a resulting document this hook cannot
                        // compute is one nobody can vouch for.
                        None => Some(write_block(
                            &path,
                            "this edit lands in the runbooks directory, and its resulting \
                             content cannot be computed to check for a scrub marker (an \
                             unreadable file, an old_string not found literally, or an edit \
                             without an old_string/new_string pair).",
                        )),
                    }
                }
            }
            "Bash" => {
                let Some(command) = input.command() else {
                    return CheckResult::allow();
                };
                bash_write_into(command, &cwd, &dir, marker_spellings.as_deref()).map(|finding| match finding {
                    BashFinding::Target(target) => bash_block(&target),
                    BashFinding::MarkerTarget(target) => marker_block(&target),
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
        // Canonical, minus Windows' verbatim `\\?\` prefix: the rows paste
        // these paths into strings, as a harness would send them.
        let canonical = scratch.path().canonicalize().unwrap();
        let path = PathBuf::from(
            canonical
                .to_string_lossy()
                .strip_prefix(r"\\?\")
                .map(str::to_string)
                .unwrap_or_else(|| canonical.to_string_lossy().into_owned()),
        );
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
        run_env(
            input,
            Env {
                dir,
                home: Some("/home/op"),
                ..Env::default()
            },
            marks,
        )
    }

    fn run_env(input: &HookInput, env: Env, marks: &[&str]) -> CheckResult {
        let digests: Vec<String> = marks
            .iter()
            .map(|m| markers::scrub_digest(m.as_bytes()))
            .collect();
        RunbookScrubGuard.run_with(input, env, &|d| digests.iter().any(|x| x == d))
    }

    fn env<'a>(dir: &'a str, escape: Option<&'a str>) -> Env<'a> {
        Env {
            dir: Some(dir),
            escape,
            ..Env::default()
        }
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
            #[cfg(unix)]
            assert_eq!(outcome(&bash, dir, &[]), Outcome::Allow, "{dir:?}");
        }
        let _ = bash;
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

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
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
            // Listed readers whose options write or run a program.
            (format!("sort -o {rb}/a.md {rb}/b.md"), Outcome::Block),
            (format!("sort -uo {rb}/a.md {rb}/b.md"), Outcome::Block),
            (format!("sort --output={rb}/a.md x"), Outcome::Block),
            (
                format!("sort --compress-program=sh {rb}/b.md"),
                Outcome::Block,
            ),
            (format!("uniq {rb}/b.md {rb}/a.md"), Outcome::Block),
            (format!("tree -o {rb}/a.md {rb}"), Outcome::Block),
            (format!("fd -e md . {rb} -x rm"), Outcome::Block),
            (format!("fd . {rb} --exec-batch rm"), Outcome::Block),
            (format!("rg --pre=./x term {rb}"), Outcome::Block),
            (format!("rg --pre ./x term {rb}"), Outcome::Block),
            // H1: `-` is an operand; a value word is not.
            (format!("cat s | uniq - {rb}/x.md"), Outcome::Block),
            (format!("uniq -f 1 - {rb}/x.md"), Outcome::Block),
            (
                format!("uniq --skip-fields 1 {rb}/a.md {rb}/x.md"),
                Outcome::Block,
            ),
            (format!("uniq -- {rb}/a.md -x"), Outcome::Block),
            // H2: getopt_long prefixes, temp dirs, tree -R.
            (format!("sort --out={rb}/a.md x"), Outcome::Block),
            (format!("sort --o {rb}/a.md x"), Outcome::Block),
            (format!("sort --compress=sh {rb}/b.md"), Outcome::Block),
            (format!("sort --com sh {rb}/b.md"), Outcome::Block),
            (format!("sort -T {rb} x"), Outcome::Block),
            (format!("sort --temporary-directory={rb} x"), Outcome::Block),
            (format!("sort --temp={rb} x"), Outcome::Block),
            (format!("tree -R -H . {rb}"), Outcome::Block),
            (format!("tree --output={rb}/a {rb}"), Outcome::Block),
            (format!("fd . {rb} --exe rm"), Outcome::Block),
            (format!("fd . {rb} --exec-b rm"), Outcome::Block),
            (format!("rg --pr=./x term {rb}"), Outcome::Block),
            // H3: an environment assignment reaches a listed program.
            (
                format!("LESSOPEN='|sh x %s' less {rb}/a.md"),
                Outcome::Block,
            ),
            (
                format!("RIPGREP_CONFIG_PATH=/x/rc rg term {rb}"),
                Outcome::Block,
            ),
            (format!("env PAGER=sh cat {rb}/a.md"), Outcome::Block),
            (format!("sudo LESSOPEN=x less {rb}/a.md"), Outcome::Block),
            (
                format!("export LESSOPEN='|sh x'; less {rb}/a.md"),
                Outcome::Block,
            ),
            (format!("LESSOPEN='|sh x'; less {rb}/a.md"), Outcome::Block),
            (format!("PATH=/x:$PATH; cat {rb}/a.md"), Outcome::Block),
            // Round 3: token alignment through runner options, and more
            // steering variables.
            (
                format!("env -u less LESSOPEN='|sh x %s' less {rb}/a.md"),
                Outcome::Block,
            ),
            (
                format!("exec -a less env LESSOPEN='|sh x' less {rb}/a.md"),
                Outcome::Block,
            ),
            (format!("HOME=/x; bat {rb}/a.md"), Outcome::Block),
            (format!("XDG_CONFIG_HOME=/x; bat {rb}/a.md"), Outcome::Block),
            (format!("HOME=/x less {rb}/a.md"), Outcome::Block),
            // `file -C` compiles a magic file into the cwd.
            (format!("cd {rb} && file -C -m /x/m"), Outcome::Block),
            (format!("file --compile -m /x/m {rb}/a.md"), Outcome::Block),
            // Naming the dir to read it stays allowed.
            (format!("cat {rb}/a.md"), Outcome::Allow),
            (format!("grep -rn term {rb} | head -20"), Outcome::Allow),
            (format!("ls -la {rb} 2>/dev/null"), Outcome::Allow),
            (format!("find {rb} -name '*.md' | wc -l"), Outcome::Allow),
            (format!("R={rb}; cat \"$R\"/a.md"), Outcome::Allow),
            (format!("rg -n term {rb}"), Outcome::Allow),
            (format!("fd -e md . {rb}"), Outcome::Allow),
            (format!("tree -L 2 {rb}"), Outcome::Allow),
            (format!("sort -u {rb}/a.md | uniq -c"), Outcome::Allow),
            (format!("uniq -c {rb}/a.md"), Outcome::Allow),
            (format!("uniq -f 1 {rb}/a.md"), Outcome::Allow),
            (format!("uniq --skip-chars=2 {rb}/a.md"), Outcome::Allow),
            (format!("sort -k2 -t, {rb}/a.md"), Outcome::Allow),
            (format!("sort --check {rb}/a.md"), Outcome::Allow),
            // Harmless locale/terminal assignments stay allowed.
            (format!("LC_ALL=C sort -u {rb}/a.md"), Outcome::Allow),
            (format!("LANG=C grep -rn x {rb}"), Outcome::Allow),
            (format!("TZ=UTC ls -l {rb}"), Outcome::Allow),
            (
                format!("NO_COLOR=1 TERM=dumb COLUMNS=80 ls {rb}"),
                Outcome::Allow,
            ),
            (format!("file {rb}/a.md"), Outcome::Allow),
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

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
    #[test]
    fn a_relative_bash_write_from_inside_the_directory_blocks() {
        let f = fixture("a-relative-bash-write-from-inside-the-di");
        let input = make_bash_with_cwd("echo x > a.md", &f.runbooks);
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
    }

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
    #[test]
    fn a_bash_write_blocks_even_when_the_content_is_marked() {
        let f = fixture("a-bash-write-blocks-even-when-the-conten");
        let input = make_bash_with_cwd(&format!("echo body > {}/a.md", f.runbooks), &f.work);
        assert_eq!(
            outcome(&input, Some(&f.runbooks), &["body", "body\n"]),
            Outcome::Block
        );
    }

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
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

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
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
                &RunbooksDir::resolve(Some(&f.runbooks), None, "/").unwrap(),
                None,
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
        let mut inputs = vec![with_cwd(
            make_write(&format!("{}/a.md", f.runbooks), "b"),
            &f.work,
        )];
        if cfg!(unix) {
            inputs.push(make_bash_with_cwd(
                &format!("cp x {}/", f.runbooks),
                &f.work,
            ));
        }
        for input in inputs {
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
        let result = RunbookScrubGuard.run_with(&inside, env(&f.runbooks, Some("1")), &marked);
        assert_eq!(result.outcome, Outcome::Allow);
        let bypass = result.bypass.expect("escape records provenance");
        assert_eq!(bypass.mechanism, ESCAPE_ENV);

        #[cfg(unix)]
        {
            let bash = make_bash_with_cwd(&format!("cp x {}/", f.runbooks), &f.work);
            let result = RunbookScrubGuard.run_with(&bash, env(&f.runbooks, Some("yes")), &marked);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(result.bypass.is_some());
        }

        // Outside the dir: a plain allow, no bypass row.
        let outside = with_cwd(make_write(&format!("{}/a.md", f.work), "b"), &f.work);
        let result = RunbookScrubGuard.run_with(&outside, env(&f.runbooks, Some("1")), &marked);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.bypass.is_none());

        // A falsy escape does nothing.
        let result = RunbookScrubGuard.run_with(&inside, env(&f.runbooks, Some("0")), &marked);
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_terminates_and_falls_back_to_the_lexical_reading() {
        let f = fixture("a-symlink-loop-does-not-hang-or-allow");
        let a = format!("{}/loop-a", f.work);
        let b = format!("{}/loop-b", f.work);
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        assert!(physical(Path::new(&format!("{a}/x"))).is_none());
        let input = with_cwd(make_write(&format!("{a}/x.md"), "b"), &f.work);
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Allow);
    }

    #[test]
    fn an_edit_that_cannot_be_simulated_literally_blocks_even_on_a_marked_file() {
        let f = fixture("an-edit-that-cannot-be-simulated-literal");
        let rb = f.runbooks.as_str();
        let path = format!("{rb}/quoted.md");
        let on_disk = "alpha \u{201c}q\u{201d} omega\n";
        std::fs::write(&path, on_disk).unwrap();
        // The on-disk document is marked, so a no-op simulation would allow.
        // (edit, marks, expected)
        let rows: Vec<(HookInput, Vec<&str>, Outcome)> = vec![
            // Straight quotes: Claude Code's Edit normalizes and applies it;
            // a literal simulation cannot, so the result is unknown.
            (
                make_edit(&path, "\"q\"", "LEAK"),
                vec![on_disk],
                Outcome::Block,
            ),
            // One MultiEdit entry missing is enough.
            (
                make_multi_edit(&path, &[("alpha", "a"), ("\"q\"", "LEAK")]),
                vec![on_disk, "a \u{201c}q\u{201d} omega\n"],
                Outcome::Block,
            ),
            // An empty old_string on an existing file.
            (make_edit(&path, "", "LEAK"), vec![on_disk], Outcome::Block),
            // A literal match still simulates and is judged on its result.
            (
                make_edit(&path, "alpha", "a"),
                vec!["a \u{201c}q\u{201d} omega\n"],
                Outcome::Allow,
            ),
            (
                make_edit(&path, "alpha", "a"),
                vec![on_disk],
                Outcome::Block,
            ),
        ];
        for (input, marks, want) in rows {
            let input = with_cwd(input, &f.work);
            assert_eq!(
                outcome(&input, Some(rb), &marks),
                want,
                "{:?}",
                input.tool_input
            );
        }
    }

    #[test]
    fn an_mcp_edit_without_an_old_new_pair_blocks() {
        let f = fixture("an-mcp-edit-without-an-old-new-pair-bloc");
        let path = format!("{}/doc.md", f.runbooks);
        std::fs::write(&path, "alpha\n").unwrap();
        let payload = |edits: serde_json::Value| {
            let raw = serde_json::json!({
                "tool_name": "mcp__filesystem__edit_file",
                "tool_input": {"path": path, "edits": edits},
                "cwd": f.work,
            });
            HookInput::from_json(&raw.to_string()).unwrap()
        };
        let rows = [
            // The MCP shape: `oldText`/`newText`, which no field reads.
            (
                serde_json::json!([{"oldText": "alpha", "newText": "LEAK"}]),
                Outcome::Block,
            ),
            // Half a pair.
            (serde_json::json!([{"old_string": "alpha"}]), Outcome::Block),
            (serde_json::json!([]), Outcome::Block),
            // A readable pair is simulated as usual.
            (
                serde_json::json!([{"old_string": "alpha", "new_string": "a"}]),
                Outcome::Allow,
            ),
        ];
        for (edits, want) in rows {
            let input = payload(edits.clone());
            assert_eq!(input.normalized_tool_name(), Some("Edit"));
            // The on-disk document is marked, and so is the one good result.
            assert_eq!(
                outcome(&input, Some(&f.runbooks), &["alpha\n", "a\n"]),
                want,
                "{edits}"
            );
        }
    }

    #[test]
    fn line_endings_do_not_change_the_verdict() {
        let f = fixture("line-endings-do-not-change-the-verdict");
        let rb = f.runbooks.as_str();
        // A draft recorded with LF endings, written with CRLF, and the reverse.
        let crlf = with_cwd(make_write(&format!("{rb}/a.md"), "a\r\nb\r\n"), &f.work);
        assert_eq!(outcome(&crlf, Some(rb), &["a\nb\n"]), Outcome::Allow);
        let lf = with_cwd(make_write(&format!("{rb}/a.md"), "a\nb\n"), &f.work);
        assert_eq!(outcome(&lf, Some(rb), &["a\r\nb\r\n"]), Outcome::Allow);
        // An LF old_string edits a CRLF file, as Claude Code's Edit does.
        let path = format!("{rb}/crlf.md");
        std::fs::write(&path, "one\r\ntwo\r\n").unwrap();
        let edit = with_cwd(make_edit(&path, "one\ntwo", "1\n2"), &f.work);
        assert_eq!(outcome(&edit, Some(rb), &["1\n2\n"]), Outcome::Allow);
        assert_eq!(outcome(&edit, Some(rb), &["one\ntwo\n"]), Outcome::Block);
    }

    #[test]
    fn the_marker_directory_is_refused_as_a_write_target() {
        let f = fixture("the-marker-directory-is-refused-as-a-wri");
        let md = format!("{}/markers", f.root);
        std::fs::create_dir_all(&md).unwrap();
        let with_markers = |input: &HookInput, dir: Option<&str>| {
            run_env(
                input,
                Env {
                    dir,
                    marker_dir: Some(&md),
                    ..Env::default()
                },
                &[],
            )
        };
        let write = with_cwd(make_write(&format!("{md}/scrub-abc"), "{}"), &f.work);
        let result = with_markers(&write, Some(&f.runbooks));
        assert_eq!(result.outcome, Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("scrub-marker directory"), "{msg}");
        assert!(msg.contains("cadence-hooks cadence record-scrub"), "{msg}");
        let edit = with_cwd(make_edit(&format!("{md}/scrub-abc"), "a", "b"), &f.work);
        assert_eq!(
            with_markers(&edit, Some(&f.runbooks)).outcome,
            Outcome::Block
        );
        // Inert with the runbooks dir unset, like the rest of the guard.
        assert_eq!(with_markers(&write, None).outcome, Outcome::Allow);
        // Elsewhere is unaffected.
        let other = with_cwd(make_write(&format!("{}/a.md", f.work), "x"), &f.work);
        assert_eq!(
            with_markers(&other, Some(&f.runbooks)).outcome,
            Outcome::Allow
        );
        #[cfg(unix)]
        for (command, want) in [
            (format!("touch {md}/scrub-abc"), Outcome::Block),
            (format!("echo '{{}}' > {md}/scrub-abc"), Outcome::Block),
            (format!("cd {md} && cp /x/y scrub-abc"), Outcome::Block),
            (format!("cp x {md}"), Outcome::Block),
            // L2: the marker dir's parent, where a recursive copy or move
            // lands a whole forged marker dir.
            (format!("cp -r forged/markers {}", f.root), Outcome::Block),
            (format!("mv forged/markers {}/", f.root), Outcome::Block),
            (format!("rsync -a forged/ {}", f.root), Outcome::Block),
            (format!("cp x {}/y", f.root), Outcome::Allow),
            (
                "cadence-hooks cadence record-polish".to_string(),
                Outcome::Allow,
            ),
            // `record-scrub` itself names neither directory as a target.
            (
                format!(
                    "cadence-hooks cadence record-scrub --file {}/draft.md",
                    f.work
                ),
                Outcome::Allow,
            ),
            (format!("ls {md}"), Outcome::Allow),
        ] {
            let input = make_bash_with_cwd(&command, &f.work);
            assert_eq!(
                with_markers(&input, Some(&f.runbooks)).outcome,
                want,
                "{command}"
            );
        }
    }

    // Shell semantics: Bash rows paste native paths into shell text.
    #[cfg(unix)]
    #[test]
    fn named_directory_spellings_rows() {
        let f = fixture("named-directory-spellings-rows");
        let rb = f.runbooks.as_str();
        let root = f.root.as_str();
        let vault = format!("{root}/vault");
        // (command, cwd, expected); HOME is the fixture root.
        let rows: Vec<(String, &str, Outcome)> = vec![
            // `$HOME` / `${HOME}` / defaulted spellings of the directory.
            (
                "tar -xf x.tar -C \"$HOME/vault/Runbooks\"".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "tar -xf x.tar -C ${HOME}/vault/Runbooks".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "tar -xf x.tar -C ${HOME:-/x}/vault/Runbooks".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "tar -xf x.tar -C ~/vault/Runbooks/".into(),
                &f.work,
                Outcome::Block,
            ),
            // `//` and `/./` inside the spelling.
            (
                format!("python3 -c \"open('{root}/vault//Runbooks/a.md','w')\""),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c \"open('{root}/./vault/./Runbooks/a.md','w')\""),
                &f.work,
                Outcome::Block,
            ),
            // A short flag's attached value.
            (format!("tar -xf x.tar -C{rb}"), &f.work, Outcome::Block),
            (format!("unzip x.zip -d{rb}/"), &f.work, Outcome::Block),
            // A relative name from the parent directory.
            ("tar -xf x.tar -C Runbooks".into(), &vault, Outcome::Block),
            ("unzip x.zip -d ./runbooks/".into(), &vault, Outcome::Block),
            ("unzip x.zip -dRunbooks".into(), &vault, Outcome::Block),
            (
                "tar --directory=Runbooks/sub -xf x".into(),
                &vault,
                Outcome::Block,
            ),
            (
                format!("cd {vault} && unzip x.zip -d Runbooks"),
                &f.work,
                Outcome::Block,
            ),
            // Running inside the directory.
            ("python3 -c \"open('a.md','w')\"".into(), rb, Outcome::Block),
            (format!("cd {rb}/sub && git init"), &f.work, Outcome::Block),
            // Reading it that way stays allowed.
            ("ls Runbooks".into(), &vault, Outcome::Allow),
            ("cat a.md".into(), rb, Outcome::Allow),
            // Look-alikes do not name it.
            (
                "tar -xf x.tar -C Runbooks-old".into(),
                &vault,
                Outcome::Allow,
            ),
            ("tar -xf x.tar -C Runbooks".into(), &f.work, Outcome::Allow),
            (format!("tar -xf x.tar -C{rb}-old"), &f.work, Outcome::Allow),
            (
                format!("tar -xf x.tar -C{root}/vault/./Runbooksx"),
                &f.work,
                Outcome::Allow,
            ),
            (
                "tar -xf x.tar -C $HOMEDIR/vault/Runbooks".into(),
                &f.work,
                Outcome::Allow,
            ),
            (
                "git commit -m 'edit runbooks'".into(),
                &vault,
                Outcome::Allow,
            ),
            // M1: quoting and escapes inside the spelling.
            (
                "tar -xf x.tar -C \"$HOME\"/vault/Runbooks".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "tar -xf x.tar -C ~/\"vault\"/'Runbooks'".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 x.py {root}/vault/\"Runbooks\""),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 x.py {root}/vault/Run\\books"),
                &f.work,
                Outcome::Block,
            ),
            // M2: `x/..` folded.
            (
                format!("python3 x.py {root}/vault/tmp/../Runbooks/a.md"),
                &f.work,
                Outcome::Block,
            ),
            // The raw spelling still names it (mentions are additive).
            (
                format!("python3 x.py {root}/vault/Runbooks/../x.md"),
                &f.work,
                Outcome::Block,
            ),
            // Round-3 regressions: the normalized copy loses these, the raw
            // text keeps them.
            (
                format!("x={rb}/..; python3 w.py ${{x%/..}}"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c \"import sys; open(sys.argv[1][:-3]+'/x.md','w')\" {rb}/.."),
                &f.work,
                Outcome::Block,
            ),
            (format!("python3 w.py {rb}/.."), &f.work, Outcome::Block),
            (
                format!("x={rb}~/..; python3 w.py $x"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("x={rb}:/..; python3 w.py $x"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c 'open(r\"{rb}/x.md\",\"w\")'"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c 'open(b\"{rb}/x.md\",\"w\")'"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c 'open(f\"{rb}/x.md\",\"w\")'"),
                &f.work,
                Outcome::Block,
            ),
            (
                format!("python3 -c 'open(u\"{rb}/x.md\",\"w\")'"),
                &f.work,
                Outcome::Block,
            ),
            // M3: a short-option cluster's attached value.
            (format!("tar -xzC{rb}"), &f.work, Outcome::Block),
            (
                format!("tar -xzf x.tgz -C{rb}/sub"),
                &f.work,
                Outcome::Block,
            ),
        ];
        for (command, cwd, want) in rows {
            let input = make_bash_with_cwd(&command, cwd);
            let got = run_env(
                &input,
                Env {
                    dir: Some(rb),
                    home: Some(root),
                    ..Env::default()
                },
                &[],
            )
            .outcome;
            assert_eq!(got, want, "{command} (cwd {cwd})");
        }
    }

    // `cd ~` resolves against the process's real home, so the directory is
    // spelled under it (nothing on disk is touched).
    #[cfg(unix)]
    #[test]
    fn a_cd_through_tilde_into_the_parent_names_the_directory() {
        let Some(home) = cadence_hooks_core::paths::user_home() else {
            return;
        };
        let home = home.to_string_lossy().into_owned();
        let dir = format!("{home}/no-such-runbook-scrub-vault-7f3a/Runbooks");
        let input = make_bash_with_cwd(
            "cd ~/no-such-runbook-scrub-vault-7f3a && unzip x.zip -d Runbooks",
            "/",
        );
        let got = run_env(
            &input,
            Env {
                dir: Some(&dir),
                home: Some(&home),
                ..Env::default()
            },
            &[],
        );
        assert_eq!(got.outcome, Outcome::Block);
    }

    #[cfg(unix)]
    #[test]
    fn pwd_and_defaulted_home_targets_rows() {
        let f = fixture("pwd-and-defaulted-home-targets-rows");
        let rb = f.runbooks.as_str();
        let root = f.root.as_str();
        let vault = format!("{root}/vault");
        let sub = format!("{root}/vault/sub");
        let rows: Vec<(String, &str, Outcome)> = vec![
            ("echo x > $PWD/Runbooks/a.md".into(), &vault, Outcome::Block),
            (
                "echo x > \"${PWD}/Runbooks/a.md\"".into(),
                &vault,
                Outcome::Block,
            ),
            (
                "echo x > ${PWD}/../Runbooks/a.md".into(),
                &sub,
                Outcome::Block,
            ),
            ("echo x > ~+/Runbooks/a.md".into(), &vault, Outcome::Block),
            (
                "cd .. && echo x > $PWD/Runbooks/a.md".into(),
                &sub,
                Outcome::Block,
            ),
            (
                "echo x > ${HOME:-/x}/vault/Runbooks/a.md".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "echo x > ${HOME-/x}/vault/Runbooks/a.md".into(),
                &f.work,
                Outcome::Block,
            ),
            (
                "echo x > ${HOME:=/x}/vault/Runbooks/a.md".into(),
                &f.work,
                Outcome::Block,
            ),
            // `~-` stays unknown: blocks only when the command names the dir.
            (
                format!("cd {rb} && cd /x && echo x > ~-/a.md"),
                &f.work,
                Outcome::Block,
            ),
            ("echo x > ~-/a.md".into(), &f.work, Outcome::Allow),
            // `$PWD` elsewhere.
            ("echo x > $PWD/a.md".into(), &f.work, Outcome::Allow),
            ("echo x > ~+/a.md".into(), &f.work, Outcome::Allow),
            (
                "echo x > $PWDX/Runbooks/a.md".into(),
                &vault,
                Outcome::Allow,
            ),
        ];
        for (command, cwd, want) in rows {
            let input = make_bash_with_cwd(&command, cwd);
            let got = run_env(
                &input,
                Env {
                    dir: Some(rb),
                    home: Some(root),
                    ..Env::default()
                },
                &[],
            )
            .outcome;
            assert_eq!(got, want, "{command} (cwd {cwd})");
        }
    }

    #[test]
    fn substitute_var_expands_set_forms_only() {
        for (text, want) in [
            ("$HOME/x", "/h/x"),
            ("${HOME}/x", "/h/x"),
            ("${HOME:-/d}/x", "/h/x"),
            ("${HOME-/d}/x", "/h/x"),
            ("${HOME:=/d}/x", "/h/x"),
            ("${HOME=/d}/x", "/h/x"),
            ("${HOME:-${X}}/x", "/h/x"),
            ("${HOME:+/d}/x", "${HOME:+/d}/x"),
            ("$HOMEDIR/x", "$HOMEDIR/x"),
            ("${HOMEDIR}/x", "${HOMEDIR}/x"),
            ("${HOME:-unclosed", "${HOME:-unclosed"),
            ("a$ b$", "a$ b$"),
        ] {
            assert_eq!(substitute_var(text, "HOME", "/h"), want, "{text}");
        }
        // A flood of unclosed defaults stays linear.
        let flood = "${HOME:-".repeat(25_000);
        let started = std::time::Instant::now();
        assert_eq!(substitute_var(&flood, "HOME", "/h"), flood);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn word_initial_tildes_expand() {
        for (text, want) in [
            ("~/v", "/h/v"),
            ("cd ~ && x", "cd /h && x"),
            ("-C ~/v", "-C /h/v"),
            ("a=~/v", "a=/h/v"),
            ("'~/v'", "'/h/v'"),
            ("x~/v", "x~/v"),
            ("~user/v", "~user/v"),
            ("~+/v", "~+/v"),
        ] {
            assert_eq!(expand_word_tildes(text, "/h/"), want, "{text}");
        }
    }

    // H4: every `$PWD` in a target expands to the whole work dir, so a
    // target of thousands of them after a long `cd` must be charged for
    // the expansion, not its spelling.
    #[cfg(unix)]
    #[test]
    fn a_pwd_amplification_flood_is_refused_quickly() {
        let f = fixture("a-pwd-amplification-flood-is-refused-qui");
        let long = format!("{}/{}", f.work, "d/".repeat(5_000));
        let command = format!("cd {long} && echo x > {}", "$PWD".repeat(10_000));
        let input = make_bash_with_cwd(&command, &f.work);
        let started = std::time::Instant::now();
        assert_eq!(
            bash_write_into(
                &command,
                &f.work,
                &RunbooksDir::resolve(Some(&f.runbooks), None, "/").unwrap(),
                None,
            ),
            Some(BashFinding::TooLarge)
        );
        assert_eq!(outcome(&input, Some(&f.runbooks), &[]), Outcome::Block);
        // Debug build; the release bound (< 0.5 s) is probed separately.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    // L2: a marker dir whose parent is a temp dir or the root (the
    // `CADENCE_MARKER_DIR` override case) does not refuse writes there.
    #[cfg(unix)]
    #[test]
    fn a_temp_or_root_marker_parent_is_not_refused() {
        let f = fixture("a-temp-or-root-marker-parent-is-not-refu");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        for (marker_dir, command) in [
            (
                "/tmp/cadence-markers-x".to_string(),
                "cp -r x /tmp".to_string(),
            ),
            (
                "/private/tmp/m-x".to_string(),
                "cp -r x /private/tmp/".to_string(),
            ),
            ("/m-x".to_string(), "cp -r x /".to_string()),
            (format!("{tmp}/m-x"), format!("cp -r x {tmp}")),
        ] {
            let input = make_bash_with_cwd(&command, &f.work);
            let got = run_env(
                &input,
                Env {
                    dir: Some(&f.runbooks),
                    marker_dir: Some(&marker_dir),
                    ..Env::default()
                },
                &[],
            );
            assert_eq!(got.outcome, Outcome::Allow, "{marker_dir} {command}");
        }
    }

    // L4: a relative Edit path is read against the payload cwd.
    #[test]
    fn a_relative_edit_path_is_read_against_the_payload_cwd() {
        let f = fixture("a-relative-edit-path-is-read-against-the");
        std::fs::write(format!("{}/rel.md", f.runbooks), "alpha\n").unwrap();
        let edit = with_cwd(make_edit("rel.md", "alpha", "a"), &f.runbooks);
        assert_eq!(resulting_document(&edit).as_deref(), Some("a\n"));
        assert_eq!(outcome(&edit, Some(&f.runbooks), &["a\n"]), Outcome::Allow);
    }

    #[test]
    fn drive_spellings_normalize_as_a_pure_function() {
        for (text, git_bash, want) in [
            (r"C:\Users\op\Vault", false, Some("/c:/Users/op/Vault")),
            ("C:/Users/op", false, Some("/c:/Users/op")),
            (r"\\?\D:\a\b", false, Some("/d:/a/b")),
            ("C:", false, Some("/c:")),
            ("/c/Users/op", true, Some("/c:/Users/op")),
            ("/c", true, Some("/c:")),
            ("/c/Users/op", false, None),
            ("/cd/x", true, None),
            ("/home/op", true, None),
            ("CC:/x", false, None),
            ("relative/x", true, None),
        ] {
            assert_eq!(drive_form(text, git_bash).as_deref(), want, "{text}");
        }
        assert_eq!(
            drive_mentions("/c:/users/op/runbooks"),
            vec![
                "c:/users/op/runbooks".to_string(),
                "/c/users/op/runbooks".to_string()
            ]
        );
        assert!(drive_mentions("/home/op").is_empty());
    }
}
