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
//!   ([`bash_write_targets`]) — blocks outright: the bytes a command writes
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
//! whole-command `cd` reading ([`parse_work_dir`]) and every per-segment one
//! ([`segment_work_dirs`]), keeping the sharpest verdict.
//!
//! **Deliberately allowed (documented, not overlooked):**
//! - A Bash target whose location depends on something the hook cannot see —
//!   an environment variable other than the two above, a command
//!   substitution, `~user`, a `**` globstar, or a relative target after a `cd`
//!   the walk cannot resolve — blocks only when the command text names the
//!   directory (its configured, lexical, physical, or `~/` spelling, or the
//!   `CADENCE_RUNBOOKS_DIR` variable). Blocking every `> "$OUT"` in every
//!   session would make the guard unusable; a command that routes a write into
//!   the vault through an opaque variable *and* never spells the vault is the
//!   residual.
//! - Interpreters that write by themselves (`python -c "open(…,'w')"`,
//!   `node -e`, a script file) are opaque, as they are to
//!   `prevent-secret-writes`.
//! - A hard link: writing a file *outside* the directory that shares an inode
//!   with a runbook is judged by its own path.
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

use cadence_hooks_cadence::prevent_secret_writes::bash_write_targets;
use cadence_hooks_core::markers;
use cadence_hooks_core::shell::{UNRESOLVABLE_DIR, parse_work_dir, segment_work_dirs};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput};
use std::collections::BTreeSet;
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
    fn physical(&self) -> Option<Vec<Comp>> {
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
        let resolved = physical(&prefix)?;
        let mut comps: Vec<Comp> = path_names(&resolved).into_iter().map(Comp::Lit).collect();
        comps.extend(self.0[split..].iter().cloned());
        Some(PathShape(comps).lexical())
    }

    /// True when either reading of this path is the directory `dir` (given as
    /// its possible spellings) or anything beneath it.
    fn lands_in(&self, dirs: &[Vec<String>]) -> bool {
        let readings = std::iter::once(self.lexical()).chain(self.physical());
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
fn physical(path: &Path) -> Option<PathBuf> {
    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    push_components(&mut pending, path);
    let mut resolved = PathBuf::from("/");
    let mut hops = 0;
    while let Some(name) = pending.pop() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&name);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                if target.has_root() {
                    resolved = PathBuf::from("/");
                }
                push_components(&mut pending, &target);
            }
            _ => resolved = next,
        }
    }
    Some(resolved)
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
        if let Some(phys) = shape.physical() {
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
        mentions.insert(DIR_ENV.to_ascii_lowercase());
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

    fn named_in(&self, command: &str) -> bool {
        let lower = command.to_ascii_lowercase();
        self.mentions.iter().any(|m| lower.contains(m.as_str()))
    }

    /// Expand `$CADENCE_RUNBOOKS_DIR` / `$HOME` (bare or braced, on an
    /// identifier boundary) and a leading `~`/`~/` in a shell word.
    fn expand(&self, word: &str) -> String {
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
fn bash_target_landing(target: &str, work_dirs: &[String], dir: &RunbooksDir) -> Landing {
    let text = dir.expand(target);
    let mut unknown = text.starts_with('~');
    let bases: Vec<Option<&str>> = if text.starts_with('/') {
        vec![None]
    } else {
        work_dirs.iter().map(|d| Some(d.as_str())).collect()
    };
    for base in bases {
        let comps = match base {
            Some(d) if d == UNRESOLVABLE_DIR => {
                unknown = true;
                continue;
            }
            Some(d) => absolute(&text, d, true),
            None => absolute(&text, "/", true),
        };
        let shape = PathShape(comps);
        if shape.lands_in(&dir.spellings) {
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

/// The first Bash write target that lands in the directory, or that may and
/// the command names the directory.
fn bash_write_into(command: &str, cwd: &str, dir: &RunbooksDir) -> Option<String> {
    let targets = bash_write_targets(command);
    if targets.is_empty() {
        return None;
    }
    let mut work_dirs: BTreeSet<String> = BTreeSet::new();
    work_dirs.insert(cwd.to_string());
    work_dirs.insert(parse_work_dir(command, cwd));
    for seg in segment_work_dirs(command, cwd) {
        work_dirs.insert(seg.dir.to_string());
    }
    let work_dirs: Vec<String> = work_dirs.into_iter().collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut maybe: Option<&String> = None;
    for target in &targets {
        if !seen.insert(target.as_str()) {
            continue;
        }
        match bash_target_landing(target, &work_dirs, dir) {
            Landing::Inside => return Some(target.clone()),
            Landing::Unknown => {
                maybe.get_or_insert(target);
            }
            Landing::Outside => {}
        }
    }
    maybe.filter(|_| dir.named_in(command)).cloned()
}

/// True when a Write-tool path lands in the directory.
fn file_path_lands_in(path: &str, cwd: &str, dir: &RunbooksDir) -> bool {
    PathShape(absolute(path, cwd, false)).lands_in(&dir.spellings)
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
                bash_write_into(command, &cwd, &dir).map(|target| bash_block(&target))
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
            // Outside the dir: unaffected.
            (format!("echo x > {}/a.md", f.work), Outcome::Allow),
            ("echo x > draft.md".to_string(), Outcome::Allow),
            (format!("cp {rb}/a.md {}/copy.md", f.work), Outcome::Allow),
            (format!("cat {rb}/a.md"), Outcome::Allow),
            (format!("grep -r term {rb}"), Outcome::Allow),
            (format!("ls {rb} > {}/listing.txt", f.work), Outcome::Allow),
            (format!("echo x > {rb}-old/a.md"), Outcome::Allow),
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
    fn a_symlink_loop_does_not_hang_or_allow() {
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
