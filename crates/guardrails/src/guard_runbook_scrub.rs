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
//! - **The scrub-marker directory** ([`markers::polish_dir`]) is refused as a
//!   Write/Edit target, so a marker cannot be forged by writing the file
//!   `record-scrub` would have written.
//!
//! **Bash is not judged** (cameronsjo/cadence-hooks#1442, cadence-ecosystem
//! ADR-0046). The Bash leg read every command's write targets, links and `cd`s
//! to keep writes out of the directory, and the guesses it had to make about
//! paths it could not resolve drew three false-block reports in three days
//! (#1434, #1435, #1441). Guards stop accidents, not evasion: the skill
//! promotes runbooks with the Write tool, and a Bash copy into the directory
//! is a deliberate step this guard no longer second-guesses.
//!
//! **Where a path lands** is decided on two readings, and either one landing
//! inside is enough ([`PathShape::lands_in`]): the lexical path (`..` folded
//! textually) and the physical one (every existing symlink on the way
//! followed, `..` applied after it, as the kernel does). Components compare
//! ASCII-case-insensitively, because the vault lives on a case-insensitive
//! volume on macOS.
//!
//! **Known over-block:** an Edit that creates a new file (empty `old_string`)
//! under the directory blocks as uncomputable; create it with the Write tool.
//! `NotebookEdit` carries its target in `notebook_path`, which no guard reads;
//! a notebook is not a runbook.
//!
//! **Charter:** inert when `$CADENCE_RUNBOOKS_DIR` is unset or blank. Fails
//! open on its own failure (ADR-0001) — no path means allow — and an
//! uncomputable resulting document blocks. Registered security-critical and
//! in `PROTECTED_GUARDS`, so `CADENCE_DISABLE` cannot neuter it. The returnable
//! escape is `CADENCE_ALLOW_UNSCRUBBED_RUNBOOK` (truthy, read from the hook
//! process's own environment), which allows *and* records a bypass row.

use cadence_hooks_core::markers;
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput};
use std::path::{Component, Path, PathBuf};

/// The directory the guard protects. Unset or blank → the guard is inert.
pub const DIR_ENV: &str = "CADENCE_RUNBOOKS_DIR";

/// The returnable escape: set truthy to let an unscrubbed write through
/// deliberately. Read from the hook process's own environment only.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_UNSCRUBBED_RUNBOOK";

/// Symlink hops [`physical`] follows before giving up (Linux's `MAXSYMLINKS`).
const MAX_SYMLINK_HOPS: usize = 40;

/// Longest target text echoed into a block message.
const MAX_ECHO: usize = 200;

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
        Some(Self { spellings })
    }
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
        // The marker directory, as spellings (lexical and physical). Its
        // parents, which only the Bash arm reads, are worked out there.
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
            // Bash is not judged: the bytes a command writes are not knowable
            // before it runs, and reading its paths cost more false blocks than
            // it saved (cameronsjo/cadence-hooks#1442, #1434, #1435, #1441).
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
        for dir in [None, Some(""), Some("   ")] {
            assert_eq!(outcome(&write, dir, &[]), Outcome::Allow, "{dir:?}");
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

    // cameronsjo/cadence-hooks#1442: Bash is not judged, however plainly it
    // names the directory.
    #[test]
    fn a_bash_write_into_the_directory_is_not_judged() {
        let f = fixture("a-bash-write-into-the-directory-is-not-j");
        for command in [
            format!("echo x > {}/a.md", f.runbooks),
            format!("cp x {}/", f.runbooks),
            format!("ln -s {} link && echo x > link/a.md", f.runbooks),
        ] {
            let input = make_bash_with_cwd(&command, &f.work);
            assert_eq!(
                outcome(&input, Some(&f.runbooks), &[]),
                Outcome::Allow,
                "{command}"
            );
        }
    }

    #[test]
    fn the_root_is_never_a_runbooks_directory() {
        let input = with_cwd(make_write("/etc/x", "b"), "/");
        assert_eq!(outcome(&input, Some("/"), &[]), Outcome::Allow);
    }

    #[test]
    fn block_message_names_both_scrub_commands_and_the_escape() {
        let f = fixture("block-message-names-both-scrub-commands-");
        let input = with_cwd(make_write(&format!("{}/a.md", f.runbooks), "b"), &f.work);
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
    }
}
