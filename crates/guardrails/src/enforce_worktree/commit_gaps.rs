//! Commit-arm gaps that need the command's own creations and brace words
//! (cameronsjo/cadence-hooks#1083, #1115).
//!
//! - **A target the command creates.** The hook fires before the command runs,
//!   so `mkdir -p <p>/x && cd <p>/x && git commit` names a directory that does
//!   not exist yet, and a directory git cannot resolve was judged "no repo" and
//!   allowed. [`Creations`] records what the same command makes: the paths of
//!   `git worktree add`, `git clone` and `git init` (a new repository, so the
//!   commit lands in it and the old allow stands), and the names of `ln -s`
//!   links (which can point anywhere, so a commit beneath one is unknown).
//!   Every other missing target is judged by its nearest existing ancestor.
//! - **A brace expansion too large to model.** Core expands a word's braces
//!   itself; one past its bounds reaches the guard whole, hiding the command it
//!   names. [`brace_overflow_hides_commit`] says when that could be a commit.
//!
//! What stays allowed, by design: a relative `git init`/`clone`/`worktree add`
//! path in a command the plain walk cannot follow (only an absolute path
//! exempts there, so such a commit is judged by its ancestor and may block);
//! a symlink made by anything but `ln -s` (`cp -s`, a script); a creation
//! verb that fails to run, then a path made by other means.

use super::{
    CARVED, CdEnv, Plain, command_tokens, lexical_normalize, peel_command_prefixes, plain_command,
    resolve_git_path, walk_plain,
};
use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, basename, brace_expansion_overflows, child_scripts, command_word,
    split_segments_with_ops, strip_compound_heads, tokenize_marked, unescape_word,
};
use std::path::Path;

/// What one command creates, as far as the guard can read it.
#[derive(Debug, Default)]
pub(super) struct Creations {
    /// Directories a new repository or worktree is made at: a commit there
    /// lands in that new repository, so it is not judged as a missing target.
    exempt: Vec<String>,
    /// Names an `ln -s` makes: a commit at or beneath one is unknown.
    links: Vec<String>,
    /// A link whose name could not be placed (a `$VAR`, a glob, or a relative
    /// name in a command that is not walked in order): any target may be under it.
    links_unplaced: bool,
}

impl Creations {
    /// Is `target` a directory this command makes a new repository at, or
    /// inside one?
    pub(super) fn covers(&self, target: &str) -> bool {
        self.exempt.iter().any(|e| under(target, e))
    }

    /// Could `target` lie beneath a symlink this command creates? `cwd` is
    /// the session's own directory, which a link cannot redirect.
    pub(super) fn link_hit(&self, target: &str, cwd: &str) -> bool {
        self.links.iter().any(|l| under(target, l))
            || (self.links_unplaced && target != lexical_normalize(cwd))
    }
}

/// `path` is `root` or a descendant of it (both normalized).
fn under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/') || root.ends_with('/'))
}

/// Read the creations of `command`. A plain command is walked in order, so a
/// relative path resolves from the one directory the shell is in; any other is
/// read segment by segment from `cwd`, where only an absolute path is trusted.
pub(super) fn creations_of(
    command: &str,
    cwd: &str,
    env: CdEnv<'_>,
    plain: Option<&Plain>,
) -> Creations {
    if !["init", "clone", "worktree", "ln"]
        .iter()
        .any(|verb| command.contains(verb))
    {
        return Creations::default();
    }
    if let Some(plain) = plain {
        let mut out = Creations::default();
        let walked = walk_plain(plain, cwd, env, |seg| {
            if seg.is_cd {
                return;
            }
            let (argv, _, _) = plain_command(&seg.words);
            let pwds: Vec<&str> = seg.dirs.iter().map(|d| d.pwd.as_str()).collect();
            // Two candidate directories: which one the verb runs in is not
            // known, so no relative path is trusted to exempt.
            note_argv(argv, &pwds, pwds.len() == 1, &mut out);
        });
        if walked.is_some() {
            return out;
        }
    }
    let mut out = Creations::default();
    scan_script(command, 0, cwd, &mut out);
    out
}

/// The union reading: every segment of `script` and its child scripts, from
/// the session cwd.
fn scan_script(script: &str, depth: usize, cwd: &str, out: &mut Creations) {
    for (raw, _) in split_segments_with_ops(script) {
        let segment = super::strip_group_punctuation(&raw).to_string();
        let marked = tokenize_marked(&segment);
        let words = command_tokens(&marked);
        let argv = peel_command_prefixes(strip_compound_heads(&words));
        note_argv(argv, &[cwd], false, out);
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, &segment) {
                scan_script(&child, depth + 1, cwd, out);
            }
        }
    }
}

/// A path word the guard can read literally: no expansion, glob or escape.
fn literal(word: &str) -> bool {
    !word.is_empty()
        && !word.contains(['$', '`', '~', '*', '?', '[', '{', '\\', '"', '\''])
        && !word.contains(CARVED)
}

/// Where a creation's path lands: from each of `pwds` when `precise` (one
/// directory), else only when the path is absolute.
fn place(word: &str, pwds: &[&str], precise: bool) -> Option<Vec<String>> {
    if !literal(word) {
        return None;
    }
    if super::is_shell_absolute(word) {
        return Some(vec![lexical_normalize(word)]);
    }
    precise.then(|| {
        pwds.iter()
            .map(|pwd| lexical_normalize(&resolve_git_path(word, pwd)))
            .collect()
    })
}

/// Note what one command (its words, prefixes peeled) creates.
fn note_argv(argv: &[String], pwds: &[&str], precise: bool, out: &mut Creations) {
    let Some(verb) = argv.first() else {
        return;
    };
    match command_word(verb).as_ref() {
        "ln" => note_ln(&argv[1..], pwds, precise, out),
        "git" => note_git(&argv[1..], pwds, precise, out),
        _ => {}
    }
}

fn note_git(args: &[String], pwds: &[&str], precise: bool, out: &mut Creations) {
    let words: Vec<String> = args.iter().map(|a| unescape_word(a).into_owned()).collect();
    let (rest, spec): (&[String], &GitVerb) = match words.first().map(String::as_str) {
        Some("init") => (&words[1..], &INIT),
        Some("clone") => (&words[1..], &CLONE),
        Some("worktree") if words.get(1).map(String::as_str) == Some("add") => {
            (&words[2..], &WORKTREE_ADD)
        }
        _ => return,
    };
    let Some(positional) = spec.positionals(rest) else {
        return;
    };
    let paths: Vec<String> = match spec.name {
        "init" => match positional.first() {
            Some(p) => vec![p.clone()],
            None if precise => pwds.iter().map(|p| (*p).to_string()).collect(),
            None => Vec::new(),
        },
        "clone" => match (positional.first(), positional.get(1)) {
            (_, Some(dest)) => vec![dest.clone()],
            (Some(url), None) => {
                let name = url.trim_end_matches('/');
                let name = name.rsplit(['/', ':']).next().unwrap_or(name);
                let name = name.strip_suffix(".git").unwrap_or(name);
                if name.is_empty() {
                    Vec::new()
                } else {
                    vec![name.to_string(), format!("{name}.git")]
                }
            }
            _ => Vec::new(),
        },
        _ => positional.first().cloned().into_iter().collect(),
    };
    for path in paths {
        // A `git init` with no path already carries an absolute pwd.
        if let Some(placed) = place(&path, pwds, precise) {
            for p in placed {
                if !out.exempt.contains(&p) {
                    out.exempt.push(p);
                }
            }
        }
    }
}

/// How one `git` verb's words split into options and operands.
struct GitVerb {
    name: &'static str,
    /// Options that take the next word as their value.
    valued: &'static [&'static str],
    /// Options that take none (an `--opt=value` form always needs none).
    flags: &'static [&'static str],
}

impl GitVerb {
    /// The operands of `rest`, or `None` when an option is not known: an
    /// unknown option could swallow an operand, so nothing is exempted.
    fn positionals(&self, rest: &[String]) -> Option<Vec<String>> {
        let mut out = Vec::new();
        let mut i = 0;
        let mut options_done = false;
        while let Some(word) = rest.get(i) {
            i += 1;
            if options_done || !word.starts_with('-') || word == "-" {
                out.push(word.clone());
            } else if word == "--" {
                options_done = true;
            } else if word.contains('=') || self.flags.contains(&word.as_str()) {
                continue;
            } else if self.valued.contains(&word.as_str()) {
                i += 1;
            } else {
                return None;
            }
        }
        Some(out)
    }
}

const INIT: GitVerb = GitVerb {
    name: "init",
    valued: &[
        "-b",
        "--initial-branch",
        "--separate-git-dir",
        "--template",
        "--object-format",
        "--ref-format",
    ],
    flags: &["-q", "--quiet", "--bare", "--shared"],
};

const CLONE: GitVerb = GitVerb {
    name: "clone",
    valued: &[
        "-b",
        "--branch",
        "--depth",
        "-o",
        "--origin",
        "--reference",
        "--reference-if-able",
        "--separate-git-dir",
        "-c",
        "--config",
        "--template",
        "-j",
        "--jobs",
        "--filter",
        "--server-option",
        "-u",
        "--upload-pack",
        "--shallow-since",
        "--shallow-exclude",
        "--bundle-uri",
        "--revision",
    ],
    flags: &[
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "--progress",
        "-n",
        "--no-checkout",
        "--bare",
        "--mirror",
        "-l",
        "--local",
        "--no-hardlinks",
        "-s",
        "--shared",
        "--recursive",
        "--recurse-submodules",
        "--shallow-submodules",
        "--single-branch",
        "--no-single-branch",
        "--no-tags",
        "--tags",
        "--dissociate",
        "--sparse",
        "--also-filter-submodules",
        "--remote-submodules",
        "--no-remote-submodules",
        "--reject-shallow",
        "-4",
        "-6",
    ],
};

const WORKTREE_ADD: GitVerb = GitVerb {
    name: "worktree",
    valued: &["-b", "-B", "--reason"],
    flags: &[
        "-f",
        "--force",
        "-d",
        "--detach",
        "--checkout",
        "--no-checkout",
        "--lock",
        "--orphan",
        "--guess-remote",
        "--no-guess-remote",
        "--track",
        "--no-track",
        "-q",
        "--quiet",
        "--relative-paths",
        "--no-relative-paths",
    ],
};

/// `ln -s`: the names it creates. A real directory as the last operand takes
/// the link inside it, under the source's own name.
fn note_ln(args: &[String], pwds: &[&str], precise: bool, out: &mut Creations) {
    let mut symbolic = false;
    let mut target_dir: Option<String> = None;
    let mut operands: Vec<String> = Vec::new();
    let mut i = 0;
    let mut options_done = false;
    while let Some(raw) = args.get(i) {
        i += 1;
        let word = unescape_word(raw).into_owned();
        if options_done || !word.starts_with('-') || word == "-" {
            operands.push(word);
        } else if word == "--" {
            options_done = true;
        } else if word == "--symbolic" {
            symbolic = true;
        } else if let Some(dir) = word.strip_prefix("--target-directory=") {
            target_dir = Some(dir.to_string());
        } else if word == "--target-directory" || word == "-t" {
            target_dir = args.get(i).map(|w| unescape_word(w).into_owned());
            i += 1;
        } else if word == "--suffix" || word == "-S" {
            i += 1;
        } else if !word.starts_with("--") {
            let cluster = &word[1..];
            symbolic |= cluster.contains('s');
            if let Some(at) = cluster.find('t') {
                if cluster[at + 1..].is_empty() {
                    target_dir = args.get(i).map(|w| unescape_word(w).into_owned());
                    i += 1;
                } else {
                    target_dir = Some(cluster[at + 1..].to_string());
                }
            }
        }
    }
    if !symbolic {
        return;
    }
    // Every name the link could take, as written: relative to where `ln` runs.
    let mut names: Vec<String> = Vec::new();
    match (&target_dir, operands.as_slice()) {
        (Some(dir), sources) => {
            names.extend(sources.iter().map(|s| format!("{dir}/{}", basename(s))));
        }
        (None, []) => return,
        (None, [only]) => names.push(basename(only).to_string()),
        (None, [sources @ .., last]) => {
            // An existing real directory takes the link inside it; anything
            // else (a new name, an existing link) is the link's own name.
            let is_real_dir = |name: &str| {
                place(name, pwds, precise).is_some_and(|placed| {
                    placed
                        .iter()
                        .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
                })
            };
            if !is_real_dir(last) {
                names.push(last.clone());
            }
            names.extend(sources.iter().map(|s| format!("{last}/{}", basename(s))));
        }
    }
    for name in names {
        match place(&name, pwds, precise) {
            Some(placed) => {
                for p in placed {
                    if !out.links.contains(&p) {
                        out.links.push(p);
                    }
                }
            }
            None => out.links_unplaced = true,
        }
    }
}

/// Could a brace expansion the guard cannot model hide a `git commit`?
///
/// Core leaves a word that expands past its bounds whole and unexpanded, so
/// the command it stands for is invisible. Such a command is rare; when it
/// mentions `git` or `commit`, or a brace word sits in command position (it
/// could expand to `git`), a commit may be hiding in it. A command past the
/// bounds that names neither (`echo {1..100000}`) is left alone.
pub(super) fn brace_overflow_hides_commit(command: &str) -> bool {
    if !brace_expansion_overflows(command) {
        return false;
    }
    if command.contains("commit") || command.contains("git") {
        return true;
    }
    split_segments_with_ops(command)
        .into_iter()
        .any(|(raw, _)| {
            let segment = super::strip_group_punctuation(&raw).to_string();
            let words = command_tokens(&tokenize_marked(&segment));
            let argv = peel_command_prefixes(strip_compound_heads(&words));
            argv.first().is_some_and(|w| w.contains('{'))
        })
}

#[cfg(test)]
mod tests {
    use super::super::{EnvConfig, run_enforce};
    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use cadence_hooks_core::test_builders::make_bash;
    use cadence_hooks_core::{HookInput, Outcome};
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> Scratch {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("target")
            .join("enforce-worktree-scratch");
        Scratch::new(&root, tag)
    }

    fn cfg() -> EnvConfig {
        EnvConfig {
            allow_main: false,
            kill_switch: false,
            tmpdir: None,
            home: String::new(),
        }
    }

    /// `(primary, worktree)` under a non-temp scratch root.
    fn repos(scratch: &Scratch) -> (PathBuf, PathBuf) {
        let primary = scratch.path().join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        let wt = scratch.path().join("wt");
        git_in(
            &primary,
            &["worktree", "add", &wt.to_string_lossy(), "-b", "feat/x"],
        );
        (primary, wt)
    }

    fn input(cmd: &str, cwd: &Path) -> HookInput {
        let mut input = make_bash(cmd);
        input.cwd = Some(cwd.to_string_lossy().into_owned());
        input
    }

    /// Run each `(cwd-is-primary, command, expected)` row; `{P}`, `{W}` and
    /// `{S}` name the primary, the linked worktree and the scratch root.
    fn table(tag: &str, rows: &[(bool, &str, Outcome)]) {
        let scratch = scratch(tag);
        let (p, w) = repos(&scratch);
        std::fs::create_dir(w.join("sub")).unwrap();
        for (from_primary, cmd, want) in rows {
            let cmd = cmd
                .replace("{P}", &p.to_string_lossy())
                .replace("{W}", &w.to_string_lossy())
                .replace("{S}", &scratch.path().to_string_lossy());
            let cwd = if *from_primary { &p } else { &w };
            let r = run_enforce(&input(&cmd, cwd), &cfg());
            assert_eq!(
                r.outcome,
                *want,
                "from {}: {cmd}\n{:?}",
                if *from_primary { "P" } else { "W" },
                r.message
            );
        }
    }

    #[test]
    fn a_target_the_command_makes_is_judged_by_its_nearest_existing_ancestor() {
        // cadence-hooks#1083: the issue's three shapes, plus their controls.
        table(
            "creations-ancestor",
            &[
                (
                    false,
                    "mkdir -p {P}/x && cd {P}/x && git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "mkdir -p {P}/x/y && git -C {P}/x/y commit -m x",
                    Outcome::Block,
                ),
                (
                    true,
                    "mkdir -p 2'>'x; git -C 2'>'x commit -m x",
                    Outcome::Block,
                ),
                (true, "mkdir d && cd d && git commit -m x", Outcome::Block),
                // The ancestor is a linked worktree: everyday, allowed.
                (
                    false,
                    "mkdir -p {W}/n/m && cd {W}/n/m && git commit -m x",
                    Outcome::Allow,
                ),
                (false, "mkdir n && cd n && git commit -m x", Outcome::Allow),
                (false, "git commit -m x", Outcome::Allow),
                (false, "cd sub && git commit -m x", Outcome::Allow),
                (false, "git -C {W}/sub commit -m x", Outcome::Allow),
                (true, "git commit -m x", Outcome::Block),
            ],
        );
    }

    #[test]
    fn a_symlink_the_command_makes_is_unknown_and_blocks() {
        table(
            "creations-symlink",
            &[
                (
                    false,
                    "ln -s {P} l && cd l && git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln -sfn {P} l && cd l && git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln -s {P} {W}/l && git -C {W}/l commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln -s {P} sub && cd sub/repo && git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln --symbolic {P} l; cd l; git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln -s -t {W} {P} && cd {W}/repo && git commit -m x",
                    Outcome::Block,
                ),
                (
                    false,
                    "sh -c 'ln -s {P} l && cd l && git commit -m x'",
                    Outcome::Block,
                ),
                (
                    false,
                    "ln -s {P} l && (cd l && git commit -m x)",
                    Outcome::Block,
                ),
                (
                    true,
                    "ln -s {W} l && cd l && git commit -m x",
                    Outcome::Block,
                ),
                // A link elsewhere in the command, and a link that is not
                // the commit's directory, change nothing.
                (false, "ln -s {P} l && git commit -m x", Outcome::Allow),
                (
                    false,
                    "ln -s {P} l; cd sub && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    false,
                    "ln {P}/a {W}/b && cd sub && git commit -m x",
                    Outcome::Allow,
                ),
            ],
        );
    }

    #[test]
    fn a_repository_the_command_makes_is_not_judged_as_a_missing_target() {
        // The guard's own recipes stay allowed from a primary.
        table(
            "creations-exempt",
            &[
                (
                    true,
                    "git worktree add ../nw -b nb && cd ../nw && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git worktree add {S}/nw2 && git -C {S}/nw2 commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git worktree add -b nb ../nw3 origin/main && cd ../nw3 && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git clone https://h/o/proj.git && cd proj && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git clone git@h:o/proj2 && cd proj2 && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git clone --depth 1 -b main https://h/o/p.git dest && cd dest && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "mkdir d && cd d && git init && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git init d2 && cd d2 && git commit -m x",
                    Outcome::Allow,
                ),
                (
                    true,
                    "git init -q -b main d3 && git -C d3 commit -m x",
                    Outcome::Allow,
                ),
                (
                    false,
                    "git clone https://h/o/proj.git && cd proj && git commit -m x",
                    Outcome::Allow,
                ),
                // Not a repository the command makes: still judged.
                (
                    true,
                    "mkdir -p sub2 && cd sub2 && git commit -m x",
                    Outcome::Block,
                ),
                (
                    true,
                    "git clone https://h/o/proj.git && cd other && git commit -m x",
                    Outcome::Block,
                ),
                // An option the guard cannot read could swallow the operand.
                (
                    true,
                    "git clone --weird https://h/o/proj.git && cd proj && git commit -m x",
                    Outcome::Block,
                ),
                (
                    true,
                    "git init {S}/somewhere && cd {P}/x && git commit -m x",
                    Outcome::Block,
                ),
            ],
        );
    }

    #[test]
    fn a_command_past_the_plain_walk_trusts_only_absolute_creation_paths() {
        table(
            "creations-nonplain",
            &[
                (
                    false,
                    "(git init {P}/abs && cd {P}/abs && git commit -m x)",
                    Outcome::Allow,
                ),
                (
                    false,
                    "(mkdir -p {P}/y && cd {P}/y && git commit -m x)",
                    Outcome::Block,
                ),
                // A relative init is not trusted here; the ancestor (a
                // worktree) is judged instead.
                (
                    false,
                    "(mkdir d && cd d && git init && git commit -m x)",
                    Outcome::Allow,
                ),
                (
                    true,
                    "(mkdir d && cd d && git init && git commit -m x)",
                    Outcome::Block,
                ),
            ],
        );
    }

    #[test]
    fn a_brace_word_that_is_a_whole_git_commit_is_seen() {
        // cadence-hooks#1115.
        table(
            "brace-command",
            &[
                (true, "{git,commit,-m,x}", Outcome::Block),
                (false, "{git,-C,{P},commit,-m,x}", Outcome::Block),
                (true, "{git,-C,{P},commit,-m,x}", Outcome::Block),
                (true, "{ {git,commit,-m,x}; }", Outcome::Block),
                (true, "echo hi && {git,commit,-m,x}", Outcome::Block),
                (false, "{git,-C,{W},commit,-m,x}", Outcome::Allow),
                (false, "{git,commit,-m,x}", Outcome::Allow),
                (true, "{git,status}", Outcome::Allow),
                (true, "{echo,hi}", Outcome::Allow),
                // The group closer still closes a group.
                (true, "{ git commit -m x; }", Outcome::Block),
                (false, "{ git commit -m x; }", Outcome::Allow),
                (false, "{ echo hi; }", Outcome::Allow),
            ],
        );
    }

    #[test]
    fn a_brace_expansion_past_the_bounds_that_may_hide_a_commit_blocks() {
        let big = "{1..100000}";
        let scratch = scratch("brace-overflow");
        let (_p, w) = repos(&scratch);
        for (cmd, want) in [
            (format!("git commit -m x {big}"), Outcome::Block),
            (format!("{{g,}}it co{{m,}}mit {big}"), Outcome::Block),
            (format!("{{g,}}it {big}"), Outcome::Block),
            (format!("echo {big}"), Outcome::Allow),
            (format!("for i in {big}; do :; done"), Outcome::Allow),
            // Any mention of `git` in such a command is refused.
            (format!("git status {big}"), Outcome::Block),
        ] {
            let r = run_enforce(&input(&cmd, &w), &cfg());
            assert_eq!(r.outcome, want, "{cmd}\n{:?}", r.message);
        }
    }

    #[test]
    fn an_unresolved_cd_blocks_a_commit_from_a_linked_worktree() {
        // cadence-hooks#346 option (b): already the behaviour (the union path
        // reports the cd and `run_enforce` blocks it from a worktree); pinned.
        let scratch = scratch("unresolved-cd");
        let (p, w) = repos(&scratch);
        std::fs::create_dir(w.join("sub")).unwrap();
        for cmd in [
            format!("X={}; cd \"$X\" && git commit -m x", p.display()),
            "cd \"$X\" && git commit -m x".to_string(),
            "cd ~otheruser/primary && git commit -m x".to_string(),
            "cd $(pwd)/.. && git commit -m x".to_string(),
            "cd sub* && git commit -m x".to_string(),
            "cd $X; echo hi; git commit -m x".to_string(),
        ] {
            let r = run_enforce(&input(&cmd, &w), &cfg());
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
            assert!(
                r.message
                    .as_deref()
                    .unwrap_or("")
                    .contains("git -C <path> commit"),
                "{cmd}: {:?}",
                r.message
            );
        }
        for cmd in ["cd sub && git commit -m x", "cd $X && echo hi"] {
            assert_eq!(
                run_enforce(&input(cmd, &w), &cfg()).outcome,
                Outcome::Allow,
                "{cmd}"
            );
        }
    }

    #[test]
    fn the_block_message_names_the_ff_merge_path_for_live_state_repos() {
        // cadence-hooks#717 option (b): message only.
        let scratch = scratch("live-state-message");
        let (p, _w) = repos(&scratch);
        let r = run_enforce(&input("git commit -m x", &p), &cfg());
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        assert!(msg.contains("git merge --ff-only"), "{msg}");
        assert!(msg.contains("auto-mode"), "{msg}");
    }
}
