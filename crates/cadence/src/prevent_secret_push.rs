//! Block a `git push` that would publish a secret (cameronsjo/cadence-hooks#890,
//! the guard half of #237).
//!
//! The entry posture makes push a default, unprompted action, which removes the
//! last informal checkpoint between a committed secret and public history.
//! This guard is the mechanical replacement: it scans what a push would
//! publish and refuses when a commit adds a secret-named file or a credential
//! token, or a commit or tag message carries one.
//!
//! **Trigger and range come from core.** [`push_invocations`] finds every push
//! the command runs (wrappers, `-C`, substitutions, refspecs). This module owns
//! the range and the scan. The range for a named source is
//! `git rev-list <src> --not --remotes` (positive ref BEFORE `--not`: the other
//! order negates the ref too and scans nothing): a commit reachable from ANY
//! remote-tracking ref reads as published, so a fork flow (a branch based on
//! `upstream/main` pushed to `origin`) does not re-scan upstream's history.
//! `--all`/`--branches` widen to every branch, `--mirror` (flag or
//! `remote.<dest>.mirror`) to every ref, `--tags` adds every tag. `tag <name>`
//! reads as `refs/tags/<name>`, `@` as `HEAD`.
//!
//! **Scan.** One `git log -p -U0 --cc --root` over the outbound range, so a
//! secret added and then removed inside the range is still seen (a net diff
//! misses it). Merge commits use `--cc`, which shows exactly the content a merge
//! introduces that no parent had. Content goes through
//! [`crate::credential_scan`] (the #1022 token shapes) and
//! [`scan_secret_values`]; names go through [`is_blocked`]. A second pass reads
//! the same commits as RAW objects (`git cat-file --batch`, header and
//! message, never re-encoded by an `encoding` header or
//! `i18n.logOutputEncoding`) through the same text scanner. Every named source
//! is read by its UNPEELED object, whatever its ref path or a raw sha: a tag
//! object is scanned raw and must tag a commit. Annotated tags `--tags`,
//! `--mirror` and `--follow-tags`/`push.followTags` publish are read the same
//! way, and every ref name the push writes (both sides of each refspec, the
//! current branch of a bare push, every ref a widening flag enumerates) goes
//! through the text scanner too. The block message carries short sha, path
//! and pattern name, never the value; a ref name carrying one is withheld.
//!
//! **Every spawn reads the objects the push sends.** Replace refs are off
//! (`--no-replace-objects`, `GIT_NO_REPLACE_OBJECTS`), and the patch pass pins
//! the config that can hide content: `--root` (`log.showRoot`), `--no-relative`
//! (`diff.relative`), `--no-ext-diff`, `--no-textconv`, `--text`,
//! `--no-renames`, forced `a/`/`b/` prefixes and `core.quotePath=false`.
//!
//! **Fails CLOSED, everywhere a push was detected.** Unlike most guards this one
//! never reads "git said nothing useful" as "nothing to push": an unresolved
//! invocation, an unreadable or unsafe source, a source or tag that is not a
//! commit (a tree or blob publishes content no patch shows), a nested tag, a
//! submodule push (`--recurse-submodules=on-demand|only`, the same in
//! `push.recurseSubmodules`, or `submodule.recurse`) in a repository that has
//! submodules (a top-level `.gitmodules` or a gitlink in the index), a failed,
//! unavailable or timed-out git spawn, a range over [`MAX_COMMITS`], a patch
//! over [`MAX_LOG_BYTES`], too many refspecs, an unparseable diff header —
//! all block, and the message says which. Only a genuinely empty range
//! allows. `git send-pack`, `git http-push` and the remote helpers
//! (`git remote-<transport>`, never the builtin `git remote`), with their
//! `git-<name>` executables, publish without `git push` and always block; so
//! do a dashed `git-push` executable and an `exec -a` naming a `git`-prefixed
//! argv[0] (git dispatches on it), which this does not model. So do a named
//! source spelled as a full-length object id that a ref is also named like
//! (git pushes the ref, `rev-parse` would read the object) and an outbound
//! commit whose `encoding` header is not UTF-8, US-ASCII or ISO-8859-* (a
//! token in it need not be ASCII bytes).
//!
//! **Aliases.** A `git <sub>` whose subcommand is not a builtin is looked up in
//! the repository's config (`alias.<sub>`, following alias-of-alias, past any
//! global options an alias value opens with). It blocks as unresolved when:
//! its value names `push` or `send-pack` or starts with `!`; an alias opens
//! with an option this cannot follow or holds options only; this same command
//! writes it with `git config`; the subcommand word carries `$` or a backtick;
//! the probe cannot see the config the call reads (a `GIT_CONFIG*`,
//! `GIT_DIR`, `GIT_COMMON_DIR`, `GIT_WORK_TREE`, `GIT_EXEC_PATH` or
//! `XDG_CONFIG_HOME` name, or `HOME=`, anywhere in the command read with its
//! quotes and backslashes removed, an `include.path`/`includeIf` mention,
//! `--git-dir`, `--work-tree`, `--config-env`, `-c include*`, or a directory
//! it cannot resolve); the probe
//! itself fails or times out; or `help.autocorrect` is set to run a guess
//! (anything but `0`/`false`/`no`/`off`/`never`/`show`/`prompt`) and the subcommand is
//! neither an alias, a builtin or exec-path command `git --list-cmds` knows,
//! nor an executable `git-<name>` in an absolute `PATH` directory.
//! Builtins skip all of it.
//!
//! **Bounded.** Every git spawn goes through `run_bounded_capped_input`
//! (process-group kill, stdout cap, shared hook deadline, stdin written from
//! its own thread). The commit cap is applied to git itself (`rev-list -n`),
//! so an entire first-push history is never buffered.
//!
//! **Deliberately allowed** (each documented, none silent):
//! - `--dry-run`/`-n` pushes and pure deletions (nothing is published);
//! - commits already reachable from ANY remote-tracking ref. That trusts,
//!   as published: a commit that is only on ANOTHER remote (a private
//!   upstream's history pushed to a public fork reads as already out); a
//!   remote-tracking ref that is stale, or was fabricated or moved by an
//!   EARLIER command (`git update-ref refs/remotes/...`, a fetch refspec
//!   writing another remote's refs) — only this command's own text is read;
//!   and a push whose real destination differs from its name
//!   (`remote.<name>.pushurl`, `url.<base>.pushInsteadOf`);
//! - **every file of a repository whose top-level path has a
//!   `cadence-hooks` component** — a whole-repo exemption from the content
//!   scan (the `prevent-secret-writes` one), because this repository's
//!   sources hold hundreds of fake tokens in unit tests. It keys on the
//!   repository's own location only: a `cadence-hooks/` directory inside any
//!   other repository is scanned. A known residual: any other checkout under
//!   such a component is content-exempt. Names and messages are still
//!   checked;
//! - a secret-*named* check skipped for a safe-template name (a
//!   [`crate::secret_patterns::SAFE_SUFFIXES`] suffix: `.example`,
//!   `.template`, `.sample`, `.defaults`, `.test`, `.ci`, `.pub`). Their
//!   CONTENT is still scanned;
//! - deleting a secret-named file (removal publishes no content);
//! - a submodule-recursing push in a repository with no submodules;
//! - secrets outside the corpus (no entropy scan; token *grammar* only), and
//!   Git LFS content: only the pointer file is in the commit, so the object
//!   the LFS pre-push hook uploads is never scanned.
//!
//! **Over-blocks on purpose:** `--tags` re-reads every tag and `--mirror`
//! every ref, published or not; `--follow-tags` re-reads every annotated tag
//! reachable from what is pushed, including tags the remote already has. A
//! submodule-recursing push in a repository whose index is too large to list
//! (over ~300k entries) is refused as too large to check for submodules.
//! A git command that sets, on its own command line, a value git runs as a
//! command (`-c core.sshCommand=…`, `-c core.pager=…`, `-c credential.helper=…`,
//! a `GIT_SSH_COMMAND=`/`GIT_PAGER=` prefix, …) reads as a push core cannot
//! resolve and is refused whatever its subcommand, `GIT_SSH_COMMAND='ssh -i
//! key' git push` included; the value is not parsed. An empty value and a
//! pager of `cat` are not counted (cameronsjo/cadence-hooks#1231).
//!
//! **Not covered:** pushes core does not detect — `gh repo create --push`,
//! `git subtree push`, a `git-<name>` executable on `PATH` other than
//! `send-pack`/`http-push`/`push`/`remote-*`, a push inside a script file, a
//! push nested in another git command's exec string (`git rebase -x`,
//! `git bisect run`, `git submodule foreach`, `git filter-branch` filters;
//! the git-safety hook blocks `git rebase` in sessions); a git config key
//! written by the same command through anything but `git config`/`git remote`
//! (an editor, a redirect into `.git/config`); a pushed commit on another
//! branch that adds a submodule the index and top-level `.gitmodules` do not
//! show. The `help.autocorrect` existence check asks git, and searches
//! `PATH`, with the hook's own `PATH`, which may differ from the command's.
//!
//! The one escape is [`ESCAPE_ENV`], read from the hook's environment, which
//! allows AND records a bypass row.

use crate::credential_scan;
use crate::secret_patterns::{
    is_blocked, is_safe_template, is_secret_scan_exempt, scan_secret_values,
};
use cadence_hooks_core::deadline::{self, BudgetState};
use cadence_hooks_core::push::{PushInvocation, is_safe_ref, push_invocations};
use cadence_hooks_core::shell::{
    GitSpawn, UNRESOLVABLE_DIR, command_segments_with_dirs, command_word,
    contains_ignoring_ascii_case, executable_tokens, peel_command_runners, resolve_cd_target,
    run_bounded_capped_input, skip_git_global_options, unescape_word,
};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput};
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

/// The per-invocation acknowledgement: set truthy in the hook's environment.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_SECRET_PUSH";

/// Most outbound commits scanned; a larger range blocks.
const MAX_COMMITS: usize = 2000;
/// Most patch bytes read; a larger patch blocks.
const MAX_LOG_BYTES: usize = 32 << 20;
/// Most commit-message bytes read.
const MAX_MESSAGE_BYTES: usize = 8 << 20;
/// Most refspec sources one push may name before the guard refuses to model it.
const MAX_SOURCES: usize = 16;
/// Most bytes of tag-object text read.
const MAX_TAG_BYTES: usize = 8 << 20;
/// Most bytes of config read.
const MAX_CONFIG_BYTES: usize = 1 << 20;
/// Most findings named in one message.
const MAX_HITS: usize = 5;
/// Ceiling for one small spawn, under the shared hook deadline.
const SPAWN_CAP: Duration = Duration::from_millis(2000);
/// Ceiling for a scan spawn when the deadline is disabled
/// (`CADENCE_HOOK_DEADLINE_MS=0`). Under an armed deadline a scan spawn takes
/// whatever the shared budget has left.
const LONG_CAP: Duration = Duration::from_secs(20);
/// Most distinct directories probed for aliases in one command.
const MAX_ALIAS_PROBES: usize = 4;
/// Deepest alias-of-alias chain followed.
const MAX_ALIAS_DEPTH: usize = 10;

/// Decides, from the ABSOLUTE path, whether the content scan is skipped.
type Exempt = fn(&str) -> bool;

/// One git answer, with the four outcomes kept apart.
enum Git<T = String> {
    Ok(T),
    /// The stdout cap was reached.
    Capped,
    /// git ran and exited non-zero (the code, when it had one).
    Failed(Option<i32>),
    /// Could not spawn, or the deadline expired.
    Down,
}

/// How much of the shared deadline a spawn may take.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Budget {
    /// A probe: at most [`SPAWN_CAP`].
    Probe,
    /// A scan (the patch and message passes): whatever the shared hook budget
    /// has left, so a large but honest range is not refused at 2 s.
    Scan,
}

fn git(work_dir: &str, args: &[&str], max_stdout: usize, budget: Budget) -> Git {
    match git_bytes(work_dir, args, max_stdout, budget, None) {
        Git::Ok(bytes) => Git::Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Git::Capped => Git::Capped,
        Git::Failed(code) => Git::Failed(code),
        Git::Down => Git::Down,
    }
}

/// [`git`] with raw stdout and optional stdin (`cat-file --batch`).
fn git_bytes(
    work_dir: &str,
    args: &[&str],
    max_stdout: usize,
    budget: Budget,
    input: Option<Vec<u8>>,
) -> Git<Vec<u8>> {
    let cap = |full: Duration| match budget {
        Budget::Probe => full.min(SPAWN_CAP),
        Budget::Scan => full,
    };
    let timeout = match deadline::state() {
        BudgetState::Armed(left) if left.is_zero() => {
            deadline::note_hit();
            return Git::Down;
        }
        BudgetState::Armed(left) => cap(left),
        BudgetState::Unarmed(total) => cap(total),
        BudgetState::Disabled => match budget {
            Budget::Probe => SPAWN_CAP,
            Budget::Scan => LONG_CAP,
        },
    };
    let mut cmd = Command::new("git");
    // Replace refs would make every read here see other objects than the ones
    // the push sends (`refs/replace/*` is honoured by log, not pack-objects).
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(work_dir)
        .args(args);
    match run_bounded_capped_input(&mut cmd, timeout, Some(max_stdout), input) {
        GitSpawn::Completed(out) if out.status.success() => Git::Ok(out.stdout),
        GitSpawn::Completed(out) => Git::Failed(out.status.code()),
        // The stdout cap kills the child, so its status says nothing; the
        // length says whether the cap was the reason.
        GitSpawn::Truncated(out) if out.stdout.len() >= max_stdout => Git::Capped,
        GitSpawn::Truncated(_) | GitSpawn::SpawnFailed | GitSpawn::TimedOut => Git::Down,
    }
}

/// Why the push cannot be allowed.
enum Stop {
    /// The range could not be fully scanned.
    Refused(String),
    /// Findings, newest commit first.
    Found(Vec<Hit>),
}

struct Hit {
    sha: String,
    path: String,
    what: String,
}

/// Printable, bounded rendering of attacker-controlled text.
fn sane(text: &str) -> String {
    text.chars()
        .take(120)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// What else the command does that changes what a push publishes, read from
/// its text: config it writes with `git config`/`git remote` (before the push
/// runs, so the repository probe cannot see it) and `-c` globals. A mention
/// only ever makes the judgment stricter.
#[derive(Default)]
struct CommandHints {
    follow_tags: bool,
    mirror: bool,
    recurse_submodules: bool,
    /// Aliases a `git config` segment writes, lowercased.
    aliases: Vec<String>,
}

/// One `git` invocation the command runs: its directory and the words from
/// its subcommand on.
struct GitCall {
    dir: String,
    /// The directory could not be followed (`cd "$D"`, `-C "$D"`, a
    /// backtick): `dir` is a stand-in, so an alias probe there proves nothing.
    dir_unresolved: bool,
    globals: Vec<String>,
    rest: Vec<String>,
    /// git runs under a name that picks its subcommand: a dashed `git-push`
    /// executable, or `exec -a <name>` (git dispatches on argv[0]).
    renamed: bool,
}

/// Plumbing that publishes objects without `git push`.
const RAW_PUSH_COMMANDS: &[&str] = &["send-pack", "http-push"];

/// A subcommand that publishes objects this guard cannot scan: raw push
/// plumbing, or a remote helper (`remote-https`, `remote-ext`, ...), which
/// takes `push` commands on stdin. The builtin `git remote` is not one.
fn unscannable_push(sub: &str) -> bool {
    RAW_PUSH_COMMANDS.contains(&sub) || sub.starts_with("remote-")
}

/// Does `exec`'s own option list (`-a NAME`, `-aNAME`, `-ca NAME`) set argv[0]
/// to a `git`-prefixed name, or to one this cannot read? git dispatches on
/// argv[0], so `exec -a git-push git origin b` pushes.
fn exec_renames_git(args: &[String]) -> bool {
    let mut words = args.iter().map(|w| unescape_word(w));
    while let Some(word) = words.next() {
        let Some(flags) = word
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && *f != "-")
        else {
            return false;
        };
        if let Some(at) = flags.find('a') {
            let name = match &flags[at + 1..] {
                "" => match words.next() {
                    Some(name) => name.into_owned(),
                    None => return false,
                },
                attached => attached.to_string(),
            };
            return name.contains(['$', '`']) || command_word(&name).starts_with("git");
        }
    }
    false
}

fn git_calls(command: &str, cwd: &str) -> Vec<GitCall> {
    if !contains_ignoring_ascii_case(command, "git") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (segment, dir) in command_segments_with_dirs(command, cwd) {
        let tokens = executable_tokens(&segment);
        let argv = peel_command_runners(&tokens);
        let Some(first) = argv.first() else { continue };
        let word = command_word(first);
        // `git-send-pack` or `git-push` run as its own executable is the same
        // push.
        let dashed = word
            .strip_prefix("git-")
            .filter(|sub| *sub == "push" || unscannable_push(sub));
        let exec_renamed = word == "exec" && exec_renames_git(&argv[1..]);
        if word != "git" && dashed.is_none() && !exec_renamed {
            continue;
        }
        let mut dir_unresolved = &*dir == UNRESOLVABLE_DIR || dir.contains(['$', '`']);
        let mut at = if &*dir == UNRESOLVABLE_DIR {
            cwd.to_string()
        } else {
            dir.to_string()
        };
        if exec_renamed {
            out.push(GitCall {
                dir: at,
                dir_unresolved,
                globals: Vec::new(),
                rest: vec!["exec -a".to_string()],
                renamed: true,
            });
            continue;
        }
        if let Some(sub) = dashed {
            out.push(GitCall {
                dir: at,
                dir_unresolved,
                globals: Vec::new(),
                rest: std::iter::once(sub.to_string())
                    .chain(argv[1..].iter().map(|w| unescape_word(w).into_owned()))
                    .collect(),
                renamed: sub == "push",
            });
            continue;
        }
        let rest = skip_git_global_options(&argv[1..]);
        let globals = &argv[1..argv.len() - rest.len()];
        let mut words = globals.iter();
        while let Some(word) = words.next() {
            if unescape_word(word) == "-C"
                && let Some(value) = words.next()
            {
                if value.contains(['$', '`']) {
                    dir_unresolved = true;
                } else {
                    at = resolve_cd_target(value, &at);
                }
            }
        }
        out.push(GitCall {
            dir: at,
            dir_unresolved,
            globals: globals
                .iter()
                .map(|w| unescape_word(w).into_owned())
                .collect(),
            rest: rest.iter().map(|w| unescape_word(w).into_owned()).collect(),
            renamed: false,
        });
    }
    out
}

fn command_hints(calls: &[GitCall]) -> CommandHints {
    let mut hints = CommandHints::default();
    for call in calls {
        let sub = call.rest.first().map(|s| s.to_ascii_lowercase());
        let config_words: Vec<&String> = match sub.as_deref() {
            Some("config") | Some("remote") => call.rest[1..].iter().collect(),
            _ => Vec::new(),
        };
        for word in call.globals.iter().chain(config_words.iter().copied()) {
            let lower = word.to_ascii_lowercase();
            hints.follow_tags |= lower.contains("push.followtags");
            hints.recurse_submodules |=
                lower.contains("push.recursesubmodules") || lower.contains("submodule.recurse");
            hints.mirror |= lower.contains(".mirror") || lower.starts_with("--mirror");
        }
        if sub.as_deref() == Some("config") {
            for word in &call.rest[1..] {
                let lower = word.to_ascii_lowercase();
                if let Some(name) = lower.strip_prefix("alias.") {
                    let name = name.split('=').next().unwrap_or(name);
                    hints.aliases.push(name.to_string());
                }
            }
        }
    }
    hints
}

/// Git builtins an alias cannot shadow (git runs the builtin), so a segment
/// running one needs no alias probe. Not exhaustive: a missing name costs one
/// config read, never a verdict.
const BUILTINS: &[&str] = &[
    "add",
    "am",
    "apply",
    "archive",
    "bisect",
    "blame",
    "branch",
    "bundle",
    "cat-file",
    "check-ignore",
    "checkout",
    "cherry",
    "cherry-pick",
    "clean",
    "clone",
    "commit",
    "config",
    "describe",
    "diff",
    "fetch",
    "for-each-ref",
    "format-patch",
    "fsck",
    "gc",
    "grep",
    "help",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge",
    "merge-base",
    "mv",
    "notes",
    "pull",
    "push",
    "range-diff",
    "rebase",
    "reflog",
    "remote",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "shortlog",
    "show",
    "show-ref",
    "sparse-checkout",
    "stash",
    "status",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "update-ref",
    "var",
    "version",
    "worktree",
];

/// Read `git config -z --get-regexp <regex>` as `(key, value)` pairs. A key
/// with no value reads as `true`, which is what git's boolean parser does.
fn read_config(dir: &str, regex: &str) -> Result<Vec<(String, String)>, Stop> {
    match git(
        dir,
        &["config", "-z", "--get-regexp", regex],
        MAX_CONFIG_BYTES,
        Budget::Probe,
    ) {
        Git::Ok(text) => Ok(text
            .split('\0')
            .filter(|r| !r.is_empty())
            .map(|r| match r.split_once('\n') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (r.to_string(), "true".to_string()),
            })
            .collect()),
        // `--get-regexp` exits 1 when nothing matches.
        Git::Failed(Some(1)) => Ok(Vec::new()),
        Git::Capped => Err(Stop::Refused("the git config is too large to read".into())),
        Git::Failed(_) => Err(Stop::Refused("git could not read the config".into())),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out reading the config".into(),
        )),
    }
}

/// What the repository's config says about a subcommand that is not a
/// builtin: its aliases (lowercased name → value) and whether
/// `help.autocorrect` would run a guessed command.
#[derive(Default)]
struct AliasConfig {
    aliases: HashMap<String, String>,
    autocorrect: bool,
}

fn alias_config(dir: &str) -> Result<AliasConfig, Stop> {
    let mut out = AliasConfig::default();
    for (key, value) in read_config(dir, "^(alias\\..*|help\\.autocorrect)$")? {
        if key == "help.autocorrect" {
            // git: `0`/`false`, `never`, `show` and `prompt` never run a guess
            // unattended; every other value (a delay, `immediate`, a negative
            // number, `true`) does. The last value wins.
            out.autocorrect = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off" | "never" | "show" | "prompt"
            );
        } else if let Some(name) = key.strip_prefix("alias.") {
            out.aliases.insert(name.to_ascii_lowercase(), value);
        }
    }
    Ok(out)
}

/// Is `name` a command git knows: a builtin, or a `git-<name>` in git's
/// exec-path or on `PATH`? git runs one before it would autocorrect, so such a
/// subcommand is not a guess. Builtins and the exec-path are asked of git
/// through `git --list-cmds=builtins,main`, which also covers Git for Windows
/// (dashed builtins are not installed there, and executables carry `.exe`);
/// `PATH` is searched here rather than through `others`, whose scan of every
/// `PATH` directory overran the probe budget on a loaded Windows runner. A
/// probe that fails is not remembered, so the next call asks again; until
/// git answers, only a `git-<name>` file on `PATH` counts (stricter).
fn external_subcommand_exists(dir: &str, name: &str) -> bool {
    static KNOWN: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    if name.is_empty() || name.contains(['/', '\\']) {
        return false;
    }
    let known = KNOWN.get().or_else(|| {
        match git(
            dir,
            &["--list-cmds=builtins,main"],
            256 * 1024,
            Budget::Probe,
        ) {
            Git::Ok(list) if !list.trim().is_empty() => {
                Some(KNOWN.get_or_init(|| list.lines().map(|l| l.trim().to_string()).collect()))
            }
            _ => None,
        }
    });
    if known.is_some_and(|known| known.contains(name)) {
        return true;
    }
    std::env::var_os("PATH").is_some_and(|path| path_runs_git_command(&path, name))
}

/// Whether `path` (a `PATH` value) holds a `git-<name>` git would run as
/// `git <name>`: a regular file with the owner execute bit, which is the
/// one bit git's own `is_executable` tests, in an absolute directory. A non-executable `git-psuh` is not a
/// command, so git still autocorrects `git psuh` to `push`; a relative or
/// empty entry resolves against wherever git runs, which is not this hook's
/// directory, so it is not trusted (stricter).
fn path_runs_git_command(path: &std::ffi::OsStr, name: &str) -> bool {
    let file = format!("git-{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .any(|dir| is_executable_file(&dir.join(&file)))
}

#[cfg(unix)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o100 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Why the alias `name` (following alias-of-alias) may run a push, if it may:
/// its value names `push`, `send-pack` or `http-push`, runs a shell (`!`),
/// opens with an option this cannot follow, or reaches a subcommand
/// `help.autocorrect` would guess at.
fn alias_runs_push(cfg: &AliasConfig, dir: &str, name: &str) -> Option<&'static str> {
    const PUSHES: &str = "is an alias that can run a push (its value names `push` or \
                          `send-pack`, or runs a shell command)";
    let mut name = name.to_string();
    for _ in 0..MAX_ALIAS_DEPTH {
        let Some(value) = cfg.aliases.get(&name) else {
            if cfg.autocorrect && !external_subcommand_exists(dir, &name) {
                return Some(
                    "is not a known command, and `help.autocorrect` would run git's guess \
                     at it (which may be `push`)",
                );
            }
            return None;
        };
        // git splits an alias with its own quoting, so `pu\sh` and `p"u"sh`
        // are `push` to it.
        let plain: String = value
            .chars()
            .filter(|c| !matches!(c, '\\' | '"' | '\''))
            .collect::<String>()
            .to_ascii_lowercase();
        if plain.trim_start().starts_with('!')
            || plain.contains("push")
            || plain.contains("send-pack")
        {
            return Some(PUSHES);
        }
        // An alias may open with git's global options (`-c a.b=c x`,
        // `--paginate x`); its subcommand is the first word after them.
        let words: Vec<String> = plain.split_whitespace().map(str::to_string).collect();
        let rest = skip_git_global_options(&words);
        match rest.first() {
            // Options only: git 2.43 refuses it as empty, but nothing here
            // vouches for every git, which could take the next word.
            None => {
                return Some("is an alias of git options only, with no subcommand of its own");
            }
            // An option this walk cannot classify: fail closed.
            Some(next) if next.starts_with('-') => {
                return Some("is an alias opening with an option this guard cannot follow");
            }
            Some(next) if BUILTINS.contains(&next.as_str()) => return None,
            Some(next) => name = next.clone(),
        }
    }
    Some("is an alias chain too deep to follow")
}

/// Why a `git` call the command makes may publish objects this guard cannot
/// scan, if one may: a raw push command, a subcommand word it cannot read, or
/// an alias (or autocorrected guess) that can push.
fn hidden_alias_push(command: &str, calls: &[GitCall], hints: &CommandHints) -> Option<String> {
    let mut probed: HashMap<String, Result<AliasConfig, String>> = HashMap::new();
    let mut command_blind: Option<Option<&'static str>> = None;
    let mut judged: std::collections::HashSet<(String, String)> = Default::default();
    for call in calls {
        let Some(sub) = call.rest.first() else {
            continue;
        };
        let sub = sub.to_ascii_lowercase();
        if call.renamed {
            return Some(format!(
                "`{}` runs git under a name that picks its subcommand (a dashed `git-push`, or \
                 `exec -a`), a push this guard cannot scan",
                if sub == "push" { "git-push" } else { "exec -a" }
            ));
        }
        if unscannable_push(&sub) {
            return Some(format!(
                "`git {sub}` publishes objects without `git push`, which this guard cannot scan"
            ));
        }
        if sub.contains(['$', '`']) {
            return Some(format!(
                "`git {}` names its subcommand through an expansion this guard cannot \
                 resolve",
                sane(&sub)
            ));
        }
        if sub.starts_with('-') || BUILTINS.contains(&sub.as_str()) {
            continue;
        }
        if hints.aliases.contains(&sub) {
            return Some(format!(
                "`git {}` runs an alias this same command writes",
                sane(&sub)
            ));
        }
        let blind = *command_blind.get_or_insert_with(|| command_probe_blind(command));
        if let Some(why) = alias_probe_blind(blind, call) {
            return Some(format!(
                "`git {}` may be an alias this guard cannot resolve ({why})",
                sane(&sub)
            ));
        }
        if !probed.contains_key(&call.dir) && probed.len() >= MAX_ALIAS_PROBES {
            return Some(format!(
                "`git {}` may be an alias, in more directories than this guard will probe",
                sane(&sub)
            ));
        }
        let cfg = probed.entry(call.dir.clone()).or_insert_with(|| {
            alias_config(&call.dir).map_err(|stop| match stop {
                Stop::Refused(why) => why,
                Stop::Found(_) => String::new(),
            })
        });
        let cfg = match cfg {
            Ok(cfg) => cfg,
            Err(why) => {
                return Some(format!("`git {}` may be an alias, and {why}", sane(&sub)));
            }
        };
        // One verdict per (directory, subcommand): a long command repeating
        // one call costs one walk, not one per repetition.
        if !judged.insert((call.dir.clone(), sub.clone())) {
            continue;
        }
        if let Some(why) = alias_runs_push(cfg, &call.dir, &sub) {
            return Some(format!("`git {}` {why}", sane(&sub)));
        }
    }
    None
}

/// Why no repository probe can see the config this command's git calls
/// read, judged once from the whole text: the name of an env variable that
/// moves git's config, repository or exec path (set by an assignment, or by
/// `read`, `printf -v`, `declare` and an `export`, so the bare name counts),
/// `HOME=`, or a config include. Plain substrings of the text with quotes and
/// backslashes removed (`GIT_"DIR"=` is `GIT_DIR=` to the shell), so a
/// mention anywhere counts — stricter, never looser.
fn command_probe_blind(command: &str) -> Option<&'static str> {
    const ENV: &[&str] = &[
        "GIT_CONFIG",
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_EXEC_PATH",
        "XDG_CONFIG_HOME",
        "HOME=",
    ];
    let plain: String = command
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    if ENV.iter().any(|name| plain.contains(name)) {
        return Some("the command sets git's config or repository environment");
    }
    if contains_ignoring_ascii_case(&plain, "include.path")
        || contains_ignoring_ascii_case(&plain, "includeif")
    {
        return Some("the command names a config include");
    }
    // Set by `-c` or an earlier `git config` in the same command, autocorrect
    // is invisible to the on-disk probe but turns `git psuh` into a push.
    if contains_ignoring_ascii_case(&plain, "help.autocorrect") {
        return Some("the command sets `help.autocorrect`");
    }
    None
}

/// Why the repository probe cannot see the config a `git` call reads, if it
/// cannot: the command redirects git's config or repository through env or
/// options the probe does not carry, or the call's directory is unknown.
fn alias_probe_blind(command_blind: Option<&'static str>, call: &GitCall) -> Option<&'static str> {
    if command_blind.is_some() {
        return command_blind;
    }
    let mut globals = call.globals.iter();
    while let Some(word) = globals.next() {
        let lower = word.to_ascii_lowercase();
        let redirects = ["--git-dir", "--work-tree", "--config-env"]
            .iter()
            .any(|opt| lower == *opt || lower.starts_with(&format!("{opt}=")));
        let include = lower == "-c"
            && globals
                .clone()
                .next()
                .is_some_and(|v| v.to_ascii_lowercase().starts_with("include"));
        if redirects || include {
            return Some("a git option redirects its config or repository");
        }
    }
    if call.dir_unresolved {
        return Some("its directory cannot be resolved");
    }
    None
}

/// The ref names a push's sources resolve through, plus what else widens it.
struct Range {
    /// Refspec sources, each vetted by [`is_safe_ref`].
    sources: Vec<String>,
    /// `--all`: every branch.
    branches: bool,
    /// `--mirror` or `remote.<dest>.mirror`: every ref.
    mirror: bool,
    /// `--tags`.
    tags: bool,
    /// `--follow-tags`/`push.followTags`.
    follow_tags: bool,
    /// The ref names the refspecs write, for the name scan.
    names: Vec<String>,
}

/// The local sides the push names, vetted and normalized: `tag <name>` →
/// `refs/tags/<name>`, `tags/<name>` → `refs/tags/<name>`, `@` → `HEAD`.
fn sources_of(inv: &PushInvocation) -> Result<Vec<String>, Stop> {
    let mut sources: Vec<String> = Vec::new();
    let specs: Vec<_> = inv.refspecs.iter().filter(|s| !s.is_delete).collect();
    let mut i = 0;
    while i < specs.len() {
        let spec = specs[i];
        i += 1;
        let Some(source) = spec.source.as_deref() else {
            return Err(Stop::Refused(format!(
                "could not read the source of refspec `{}`",
                sane(&spec.raw)
            )));
        };
        let source = if !spec.implicit && spec.raw == "tag" {
            // `git push origin tag v1`: the keyword and its name are one ref.
            let Some(name) = specs.get(i).and_then(|s| s.source.as_deref()) else {
                return Err(Stop::Refused("`tag` with no tag name after it".to_string()));
            };
            i += 1;
            format!("refs/tags/{name}")
        } else if source == "@" {
            "HEAD".to_string()
        } else if let Some(name) = source.strip_prefix("tags/") {
            format!("refs/tags/{name}")
        } else {
            source.to_string()
        };
        if !is_safe_ref(&source) {
            return Err(Stop::Refused(format!(
                "refspec source `{}` is not a plain ref name (revision expressions and globs \
                 cannot be scanned safely)",
                sane(&source)
            )));
        }
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    if sources.len() > MAX_SOURCES {
        return Err(Stop::Refused(format!(
            "the push names {} refs, over the {MAX_SOURCES} this guard will model",
            sources.len()
        )));
    }
    Ok(sources)
}

/// git's boolean reading of a config value: `false`/`no`/`off`, an empty
/// value and any integer equal to zero are false; everything else — `true`,
/// `yes`, `on`, any other integer, and values git would reject — reads true,
/// the stricter side for every key this guard reads.
fn truthy(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "false" | "no" | "off" | "") {
        return false;
    }
    value.parse::<i64>() != Ok(0)
}

/// Config keys the range depends on, read in one spawn.
const RANGE_CONFIG: &str = "^(push\\.(followtags|recursesubmodules)|submodule\\.recurse|\
    remote\\..*\\.mirror|remote\\.pushdefault|branch\\..*\\.(remote|pushremote))$";

/// The branch `HEAD` names, when it names one.
fn current_branch(work_dir: &str) -> Option<String> {
    match git(
        work_dir,
        &["symbolic-ref", "-q", "--short", "HEAD"],
        4096,
        Budget::Probe,
    ) {
        Git::Ok(b) if !b.trim().is_empty() => Some(b.trim().to_string()),
        _ => None,
    }
}

/// The configured remote this push goes to, for `remote.<dest>.mirror`: the
/// push's repository argument, or for a bare push `branch.<b>.pushRemote` /
/// `remote.pushDefault` / `branch.<b>.remote` / `origin`.
fn destination_remote(
    inv: &PushInvocation,
    cfg: &[(String, String)],
    branch: Option<&str>,
) -> String {
    let get = |key: &str| {
        cfg.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    if let Some(repo) = &inv.repository {
        return repo.clone();
    }
    let per_branch = |key: &str| branch.and_then(|b| get(&format!("branch.{b}.{key}")));
    per_branch("pushremote")
        .or_else(|| get("remote.pushdefault"))
        .or_else(|| per_branch("remote"))
        .unwrap_or_else(|| "origin".to_string())
}

/// Does the repository have submodules a recursive push could publish: a
/// `.gitmodules` at the top, or a gitlink (mode 160000) in the index?
fn has_submodules(work_dir: &str) -> Result<bool, Stop> {
    let top = repository_root(work_dir)?;
    if std::path::Path::new(&top).join(".gitmodules").exists() {
        return Ok(true);
    }
    match git(
        work_dir,
        &["ls-files", "-s", "-z"],
        MAX_LOG_BYTES,
        Budget::Scan,
    ) {
        Git::Ok(text) => Ok(text.split('\0').any(|entry| entry.starts_with("160000 "))),
        Git::Capped => Err(Stop::Refused(
            "the index is too large to check for submodules".into(),
        )),
        Git::Failed(_) => Err(Stop::Refused(
            "git could not read the index to check for submodules".into(),
        )),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out checking for submodules".into(),
        )),
    }
}

fn range_of(inv: &PushInvocation, hints: &CommandHints) -> Result<Option<Range>, Stop> {
    let sources = sources_of(inv)?;
    let cfg = read_config(&inv.work_dir, RANGE_CONFIG)?;
    let get_bool = |key: &str| {
        cfg.iter()
            .rev()
            .find(|(k, _)| k == key)
            .is_some_and(|(_, v)| truthy(v))
    };

    // Submodule commits live in other repositories: nothing here can scan them.
    // The flag overrides config; among config sources any one is enough. Only
    // a repository that has submodules can recurse into one.
    let unscannable = |v: &str| {
        !matches!(
            v.to_ascii_lowercase().as_str(),
            "check" | "no" | "false" | "off"
        )
    };
    let recurse: Option<String> = match inv.recurse_submodules.as_deref() {
        Some(value) => unscannable(value).then(|| value.to_string()),
        None => cfg
            .iter()
            .find(|(k, v)| k == "push.recursesubmodules" && unscannable(v))
            .map(|(_, v)| v.clone())
            .or_else(|| get_bool("submodule.recurse").then(|| "submodule.recurse".to_string()))
            .or_else(|| {
                hints
                    .recurse_submodules
                    .then(|| "set by this command".to_string())
            }),
    };
    if let Some(value) = recurse
        && has_submodules(&inv.work_dir)?
    {
        return Err(Stop::Refused(format!(
            "the push recurses into submodules (`{}`), whose commits this guard cannot scan",
            sane(&value)
        )));
    }

    let implicit = inv.refspecs.iter().all(|r| r.implicit);
    let branch = if inv.repository.is_none() || implicit {
        current_branch(&inv.work_dir)
    } else {
        None
    };
    let dest = destination_remote(inv, &cfg, branch.as_deref());
    let mirror = inv.mirror || get_bool(&format!("remote.{dest}.mirror")) || hints.mirror;
    let follow_tags = inv
        .follow_tags
        .unwrap_or_else(|| get_bool("push.followtags") || hints.follow_tags);

    let widened = inv.all_or_mirror || mirror || inv.tags;
    // The implicit `HEAD` is not published by a push that widens: `--tags`
    // pushes only tags, `--all`/`--mirror` their own ref sets.
    let sources: Vec<String> = if widened && implicit {
        Vec::new()
    } else {
        sources
    };
    if sources.is_empty() && !widened {
        return Ok(None); // nothing but deletions: nothing is published
    }
    // Every ref name the push writes on the remote, for the name scan: both
    // sides of each refspec, and the current branch for a bare push.
    let mut names: Vec<String> = inv
        .refspecs
        .iter()
        .filter(|r| !r.is_delete && !r.implicit)
        .flat_map(|r| [r.source.clone(), r.destination.clone()])
        .flatten()
        .collect();
    if implicit && !widened {
        names.extend(branch);
    }
    Ok(Some(Range {
        sources,
        branches: inv.all_or_mirror && !inv.mirror,
        mirror,
        tags: inv.tags,
        follow_tags,
        names,
    }))
}

/// The range as `git rev-list`/`git log` arguments (no `--`).
fn range_args(range: &Range) -> Vec<&str> {
    let mut args: Vec<&str> = Vec::new();
    if range.mirror {
        args.push("--all");
    } else {
        if range.branches {
            args.push("--branches");
        }
        args.extend(range.sources.iter().map(String::as_str));
        if range.tags {
            args.push("--tags");
        }
    }
    // Reachable from ANY remote-tracking ref reads as published — see the
    // module docs for what that trusts.
    args.extend(["--not", "--remotes"]);
    args
}

fn describe(range: &Range) -> String {
    if range.mirror {
        "--mirror".to_string()
    } else if range.branches {
        "--all".to_string()
    } else if range.sources.is_empty() {
        "--tags".to_string()
    } else {
        format!(
            "`{}`",
            range
                .sources
                .iter()
                .map(|s| sane(s))
                .collect::<Vec<_>>()
                .join("`, `")
        )
    }
}

/// Every named source must peel to a commit: a ref or tag naming a tree or a
/// blob publishes content no commit patch shows.
fn sources_are_commits(work_dir: &str, range: &Range) -> Result<(), Stop> {
    let peeled: Vec<String> = range
        .sources
        .iter()
        .filter(|s| *s != "HEAD")
        .map(|s| format!("{s}^{{commit}}"))
        .collect();
    if peeled.is_empty() {
        return Ok(());
    }
    // One spawn for all of them: rev-parse exits non-zero on any name that
    // does not peel to a commit, or does not resolve at all.
    let mut args = vec!["rev-parse"];
    args.extend(peeled.iter().map(String::as_str));
    args.push("--");
    match git(work_dir, &args, 64 * 1024, Budget::Probe) {
        Git::Ok(_) => Ok(()),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out resolving the pushed refs".into(),
        )),
        _ => Err(Stop::Refused(format!(
            "git could not resolve {} to a commit (a missing ref, or a ref or tag naming a \
             tree or blob, whose content this guard cannot scan)",
            describe(range)
        ))),
    }
}

/// git push matches a refspec source against ref NAMES before reading it as
/// an object id, while `rev-parse` and `cat-file` take a full-length hex name
/// as the object: a ref named like one (`refs/heads/<hex>`, `refs/tags/<hex>`,
/// `refs/remotes/<hex>/HEAD`) makes the scan read a different commit than the
/// push sends. One bounded `for-each-ref` over every such name; any match, or
/// no answer, refuses.
fn hex_sources_are_not_ref_names(work_dir: &str, range: &Range) -> Result<(), Stop> {
    let hex: Vec<&String> = range
        .sources
        .iter()
        .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();
    let Some(first) = hex.first() else {
        return Ok(());
    };
    let patterns: Vec<String> = hex
        .iter()
        .flat_map(|h| {
            [
                format!("refs/{h}"),
                format!("refs/*/{h}"),
                format!("refs/*/*/{h}"),
                format!("refs/remotes/{h}/HEAD"),
            ]
        })
        .collect();
    let mut args = vec!["for-each-ref", "--count=1", "--format=%(refname)"];
    args.extend(patterns.iter().map(String::as_str));
    match git(work_dir, &args, 64 * 1024, Budget::Probe) {
        Git::Ok(out) if out.trim().is_empty() => Ok(()),
        Git::Ok(_) | Git::Capped => Err(Stop::Refused(format!(
            "a ref is named like an object id the push names (`{}`): git pushes the ref, \
             while this guard would read the object",
            sane(first)
        ))),
        Git::Failed(_) => Err(Stop::Refused(
            "git could not list the refs named like an object id the push names".into(),
        )),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out listing refs named like an object id".into(),
        )),
    }
}

/// The outbound commits, newest first, capped at [`MAX_COMMITS`]. Second
/// value: the range held more than that.
fn outbound(work_dir: &str, range: &Range) -> Result<(Vec<String>, bool), Stop> {
    let limit = (MAX_COMMITS + 1).to_string();
    let mut args: Vec<&str> = vec!["rev-list", "-n", &limit];
    args.extend(range_args(range));
    args.push("--");
    match git(work_dir, &args, (MAX_COMMITS + 2) * 66, Budget::Probe) {
        Git::Ok(text) => {
            let mut shas: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            let over = shas.len() > MAX_COMMITS;
            shas.truncate(MAX_COMMITS);
            Ok((shas, over))
        }
        Git::Capped => Err(Stop::Refused(format!(
            "the range is too large to fully scan (over {MAX_COMMITS} commits)"
        ))),
        Git::Failed(_) => Err(Stop::Refused(format!(
            "git could not resolve the outbound range for {}",
            describe(range)
        ))),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out while resolving the outbound range".into(),
        )),
    }
}

/// Scan text with both corpora; the first pattern name, never the value.
fn scan_text(text: &str) -> Option<String> {
    if let Some(hit) = credential_scan::scan(text).first() {
        return Some(hit.kind.to_string());
    }
    scan_secret_values(text).map(str::to_string)
}

/// The path git printed in a `diff --git a/P b/P` header (no-renames, forced
/// `a/`/`b/` prefixes, so both sides are the same path). `None` when it cannot
/// be read — the caller blocks.
fn header_path(rest: &str) -> Option<String> {
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut end = None;
        let mut escaped = false;
        for (i, c) in quoted.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let inner = &quoted[..end?];
        return inner.strip_prefix("a/").map(unquote);
    }
    let len = rest.len().checked_sub(5)?;
    if len == 0 || len % 2 != 0 {
        return None;
    }
    let path = rest.get(2..2 + len / 2)?;
    (rest.starts_with("a/") && rest.get(2 + len / 2..)? == format!(" b/{path}"))
        .then(|| path.to_string())
}

/// Undo git's C-style path quoting: `\"`, `\\`, `\a \b \t \n \v \f \r`, and
/// `\NNN` octal bytes (which may spell UTF-8 together).
fn unquote(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let c = bytes[i + 1];
        let simple = match c {
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b't' => Some(b'\t'),
            b'n' => Some(b'\n'),
            b'v' => Some(0x0b),
            b'f' => Some(0x0c),
            b'r' => Some(b'\r'),
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            _ => None,
        };
        if let Some(b) = simple {
            out.push(b);
            i += 2;
            continue;
        }
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)) && d[0] <= b'3');
        match octal {
            Some(d) => {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Path of a combined-diff header (`diff --cc P`), quotes stripped.
fn combined_path(rest: &str) -> String {
    match rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => unquote(inner),
        None => rest.to_string(),
    }
}

#[derive(Default)]
struct FileState {
    path: Option<String>,
    unreadable: bool,
    deleted: bool,
    added: String,
}

/// Judge one commit's patch text (the output of the `git log -p` pass).
/// `exempt_repo` skips the content scan (names are still judged).
fn scan_patch(output: &str, exempt_repo: bool, hits: &mut Vec<Hit>) {
    let mut sha = String::new();
    let mut file = FileState::default();
    let mut cols = 0usize;
    let mut in_hunk = false;

    let flush = |sha: &str, file: &mut FileState, hits: &mut Vec<Hit>| {
        let f = std::mem::take(file);
        if hits.len() > MAX_HITS {
            return;
        }
        if f.unreadable {
            hits.push(Hit {
                sha: sha.to_string(),
                path: "(unreadable diff header)".into(),
                what: "could not read the path, so it could not be scanned".into(),
            });
            return;
        }
        let Some(path) = f.path else { return };
        if f.deleted {
            return;
        }
        let name = path.rsplit('/').next().unwrap_or(&path);
        // A safe-template NAME is not a secret name; its content still is
        // scanned below.
        if !is_safe_template(name) && is_blocked(name, &path) {
            hits.push(Hit {
                sha: sha.to_string(),
                path,
                what: "secret-named file".into(),
            });
            return;
        }
        if f.added.is_empty() || exempt_repo {
            return;
        }
        if let Some(what) = scan_text(&f.added) {
            hits.push(Hit {
                sha: sha.to_string(),
                path,
                what,
            });
        }
    };

    for line in output.split('\n') {
        if let Some(rest) = line.strip_prefix('\u{1}') {
            flush(&sha, &mut file, hits);
            sha = rest.chars().take(8).collect();
            in_hunk = false;
        } else if let Some(rest) = line.strip_prefix("diff --git ") {
            flush(&sha, &mut file, hits);
            in_hunk = false;
            match header_path(rest) {
                Some(p) => file.path = Some(p),
                None => file.unreadable = true,
            }
        } else if let Some(rest) = line
            .strip_prefix("diff --cc ")
            .or_else(|| line.strip_prefix("diff --combined "))
        {
            flush(&sha, &mut file, hits);
            in_hunk = false;
            file.path = Some(combined_path(rest));
        } else if !in_hunk && line.starts_with("deleted file mode") {
            file.deleted = true;
        } else if line.starts_with("@@") {
            in_hunk = true;
            cols = line
                .bytes()
                .take_while(|&b| b == b'@')
                .count()
                .saturating_sub(1)
                .max(1);
        } else if in_hunk && !line.starts_with('\\') {
            let Some(marks) = line.get(..cols) else {
                continue;
            };
            if marks.contains('+') {
                file.added.push_str(line.get(cols..).unwrap_or(""));
                file.added.push('\n');
            }
        }
    }
    flush(&sha, &mut file, hits);
}

/// The directory paths are joined to for the exemption: the work tree's top,
/// or the git dir of a bare repository.
fn repository_root(work_dir: &str) -> Result<String, Stop> {
    let first = git(
        work_dir,
        &["rev-parse", "--show-toplevel"],
        4096,
        Budget::Probe,
    );
    let answer = match first {
        Git::Ok(t) if !t.trim().is_empty() => return Ok(t.trim().to_string()),
        Git::Failed(_) => git(
            work_dir,
            &["rev-parse", "--absolute-git-dir"],
            4096,
            Budget::Probe,
        ),
        other => other,
    };
    match answer {
        Git::Ok(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out locating the repository".into(),
        )),
        _ => Err(Stop::Refused(
            "git could not locate the repository root".into(),
        )),
    }
}

fn scan_commits(work_dir: &str, range: &Range, exempt: Exempt) -> Result<Vec<Hit>, Stop> {
    let toplevel = repository_root(work_dir)?;
    let limit = MAX_COMMITS.to_string();
    let mut args: Vec<&str> = vec![
        "-c",
        "core.quotePath=false",
        "log",
        "-n",
        &limit,
        "-p",
        "-U0",
        "--cc",
        "--root",
        "--no-relative",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--text",
        "--no-notes",
        "--no-show-signature",
        "--encoding=UTF-8",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--format=%x01%H",
    ];
    args.extend(range_args(range));
    args.push("--");
    match git(work_dir, &args, MAX_LOG_BYTES, Budget::Scan) {
        Git::Ok(text) => {
            let mut hits = Vec::new();
            // The exemption keys on the repository's own location, never on a
            // path inside it: a `cadence-hooks/` directory in any other
            // repository is scanned like the rest.
            scan_patch(&text, exempt(&toplevel), &mut hits);
            Ok(hits)
        }
        Git::Capped => Err(Stop::Refused(format!(
            "the outbound patches are too large to scan (over {} MiB)",
            MAX_LOG_BYTES >> 20
        ))),
        Git::Failed(_) => Err(Stop::Refused(
            "git could not read the outbound patches".into(),
        )),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out reading the outbound patches".into(),
        )),
    }
}

/// One object read raw through `git cat-file --batch`.
struct RawObject {
    sha: String,
    kind: String,
    body: String,
}

/// Read `names` (object names or ref names, one per line) raw, in order, in
/// ONE `git cat-file --batch`. Raw means what the push sends: no encoding
/// header or `i18n.logOutputEncoding` re-encodes a message on this path.
/// Size-framed, so object content cannot pose as a record boundary. A name
/// that does not resolve, and any output this cannot frame, refuses.
fn read_objects(work_dir: &str, names: &[String], what: &str) -> Result<Vec<RawObject>, Stop> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = names.join("\n").into_bytes();
    input.push(b'\n');
    let out = match git_bytes(
        work_dir,
        &["cat-file", "--batch"],
        MAX_MESSAGE_BYTES,
        Budget::Scan,
        Some(input),
    ) {
        Git::Ok(out) => out,
        Git::Capped => return Err(Stop::Refused(format!("the {what} are too large to scan"))),
        Git::Failed(_) => return Err(Stop::Refused(format!("git could not read the {what}"))),
        Git::Down => {
            return Err(Stop::Refused(format!(
                "git was unavailable or timed out reading the {what}"
            )));
        }
    };
    let unreadable = || Stop::Refused(format!("git's answer for the {what} could not be read"));
    let mut objects = Vec::with_capacity(names.len());
    let mut at = 0;
    while at < out.len() {
        let end = out[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| at + i)
            .ok_or_else(unreadable)?;
        let header = String::from_utf8_lossy(&out[at..end]).into_owned();
        let parts: Vec<&str> = header.split(' ').collect();
        let [sha, kind, size] = parts.as_slice() else {
            return Err(Stop::Refused(format!(
                "git could not resolve one of the {what} (`{}`)",
                sane(&header)
            )));
        };
        let size: usize = size.parse().map_err(|_| unreadable())?;
        let body_end = end
            .checked_add(1 + size)
            .filter(|&e| e < out.len())
            .ok_or_else(unreadable)?;
        objects.push(RawObject {
            sha: sha.to_string(),
            kind: kind.to_string(),
            body: String::from_utf8_lossy(&out[end + 1..body_end]).into_owned(),
        });
        // Each object is followed by one LF.
        at = body_end + 1;
    }
    if objects.len() != names.len() {
        return Err(unreadable());
    }
    Ok(objects)
}

/// The outbound commits' raw objects — header and message — through the
/// same text scanner. Kept apart from the patch parse: a message is free
/// text that could otherwise pose as patch structure.
fn scan_messages(work_dir: &str, shas: &[String]) -> Result<Vec<Hit>, Stop> {
    let mut hits = Vec::new();
    let mut unreadable: Option<String> = None;
    for object in read_objects(work_dir, shas, "outbound commit messages")? {
        if let Some(what) = scan_text(&object.body) {
            hits.push(Hit {
                sha: object.sha.chars().take(8).collect(),
                path: "(commit message)".into(),
                what,
            });
        } else if unreadable.is_none() {
            unreadable = unscannable_encoding(&object.body);
        }
    }
    match unreadable {
        Some(encoding) if hits.is_empty() => Err(Stop::Refused(format!(
            "a commit message in encoding `{}` cannot be scanned (its token bytes need not be \
             ASCII)",
            sane(&encoding)
        ))),
        _ => Ok(hits),
    }
}

/// A raw commit's `encoding` header, when it names one whose bytes the text
/// scanner cannot read as-is: anything but UTF-8, US-ASCII or ISO-8859-*
/// (all ASCII-compatible, so a token keeps its bytes).
fn unscannable_encoding(body: &str) -> Option<String> {
    let header = body.split("\n\n").next().unwrap_or(body);
    let encoding = header
        .lines()
        .find_map(|line| line.strip_prefix("encoding "))?
        .trim();
    let lower = encoding.to_ascii_lowercase();
    let readable = matches!(
        lower.as_str(),
        "utf-8" | "utf8" | "us-ascii" | "ascii" | "latin1" | "latin-1"
    ) || lower.starts_with("iso-8859-");
    (!readable).then(|| encoding.to_string())
}

/// A ref name as shown in a finding: withheld when it carries the secret.
fn shown(name: &str) -> String {
    if scan_text(name).is_some() {
        "(ref name withheld)".to_string()
    } else {
        sane(name)
    }
}

/// One ref the push publishes, as `for-each-ref` or `cat-file` resolved it.
struct PublishedRef {
    name: String,
    sha: String,
    kind: String,
}

/// Enumerate refs matching `patterns` (every ref when empty), after
/// `filters`. Ref names hold no space or newline, so the line format needs
/// no delimiter.
fn list_refs(
    work_dir: &str,
    patterns: &[String],
    filters: &[String],
) -> Result<Vec<PublishedRef>, Stop> {
    let mut args: Vec<&str> = vec![
        "for-each-ref",
        "--format=%(objectname) %(objecttype) %(refname)",
    ];
    args.extend(filters.iter().map(String::as_str));
    args.extend(patterns.iter().map(String::as_str));
    let text = match git(work_dir, &args, MAX_TAG_BYTES, Budget::Scan) {
        Git::Ok(t) => t,
        Git::Capped => return Err(Stop::Refused("there are too many refs to scan".into())),
        Git::Failed(_) => return Err(Stop::Refused("git could not list the refs".into())),
        Git::Down => {
            return Err(Stop::Refused(
                "git was unavailable or timed out listing the refs".into(),
            ));
        }
    };
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let mut parts = line.splitn(3, ' ');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(sha), Some(kind), Some(name)) => Ok(PublishedRef {
                    name: name.to_string(),
                    sha: sha.to_string(),
                    kind: kind.to_string(),
                }),
                _ => Err(Stop::Refused("git's ref listing could not be read".into())),
            }
        })
        .collect()
}

/// Every ref and tag object the push publishes beyond its commits, and every
/// ref name it writes: each tag object is read raw (header and message) and
/// must peel straight to a commit; a ref naming anything but a commit or a
/// tag is refused; each name goes through the text scanner.
fn scan_refs_and_tags(work_dir: &str, range: &Range) -> Result<Vec<Hit>, Stop> {
    let mut refs: Vec<PublishedRef> = Vec::new();
    // Named sources, by the object each one resolves to — whatever the ref's
    // path, or a raw sha: its UNPEELED type decides.
    let named: Vec<String> = range
        .sources
        .iter()
        .filter(|s| *s != "HEAD")
        .cloned()
        .collect();
    for (name, object) in named
        .iter()
        .zip(read_objects(work_dir, &named, "pushed refs")?)
    {
        refs.push(PublishedRef {
            name: name.clone(),
            sha: object.sha,
            kind: object.kind,
        });
    }
    let covers_tags = range.mirror || range.tags;
    if range.mirror {
        refs.extend(list_refs(work_dir, &[], &[])?);
    } else {
        let mut patterns: Vec<String> = Vec::new();
        if range.branches {
            patterns.push("refs/heads".into());
        }
        if range.tags {
            patterns.push("refs/tags".into());
        }
        if !patterns.is_empty() {
            refs.extend(list_refs(work_dir, &patterns, &[])?);
        }
    }
    // `--follow-tags`: annotated tags reachable from what is pushed, whether
    // or not their commit is new — the tag object itself is. A lightweight
    // tag is not followed.
    if range.follow_tags && !covers_tags {
        let merged: Vec<String> = if range.branches {
            Vec::new() // every branch: every tag is a candidate
        } else {
            range
                .sources
                .iter()
                .map(|s| format!("--merged={s}"))
                .collect()
        };
        if range.branches || !merged.is_empty() {
            refs.extend(
                list_refs(work_dir, &["refs/tags".to_string()], &merged)?
                    .into_iter()
                    .filter(|r| r.kind == "tag"),
            );
        }
    }

    let mut hits = Vec::new();
    let mut names: Vec<&str> = range.names.iter().map(String::as_str).collect();
    names.extend(refs.iter().map(|r| r.name.as_str()));
    for name in names {
        if let Some(what) = scan_text(name) {
            hits.push(Hit {
                sha: "ref".into(),
                path: "(pushed ref name)".into(),
                what,
            });
        }
    }
    let mut tags: Vec<(String, String)> = Vec::new();
    for r in &refs {
        match r.kind.as_str() {
            "commit" => {}
            "tag" => {
                if !tags.iter().any(|(_, sha)| *sha == r.sha) {
                    tags.push((r.name.clone(), r.sha.clone()));
                }
            }
            other => hits.push(Hit {
                sha: "ref".into(),
                path: shown(&r.name),
                what: format!("points at a {}, which this guard cannot scan", sane(other)),
            }),
        }
    }
    let shas: Vec<String> = tags.iter().map(|(_, sha)| sha.clone()).collect();
    for ((name, _), object) in tags
        .iter()
        .zip(read_objects(work_dir, &shas, "tag objects")?)
    {
        // The header's `type` line: a tag of a tag carries a second message
        // this read never sees, a tag of a tree or blob publishes content no
        // patch shows.
        let target = object
            .body
            .lines()
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.strip_prefix("type "));
        if target != Some("commit") {
            hits.push(Hit {
                sha: "tag".into(),
                path: shown(name),
                what: format!(
                    "tags a {}, which this guard cannot scan",
                    sane(target.unwrap_or("unreadable object"))
                ),
            });
        }
        if let Some(what) = scan_text(&object.body) {
            hits.push(Hit {
                sha: "tag".into(),
                path: shown(name),
                what,
            });
        }
    }
    Ok(hits)
}

fn judge(command: &str, cwd: &str, exempt: Exempt) -> Result<(), Stop> {
    let calls = git_calls(command, cwd);
    let hints = command_hints(&calls);
    if let Some(why) = hidden_alias_push(command, &calls, &hints) {
        return Err(Stop::Refused(format!(
            "{why}, so what it publishes could not be resolved"
        )));
    }
    for inv in push_invocations(command, cwd) {
        if inv.dry_run {
            continue;
        }
        if inv.unresolved {
            return Err(Stop::Refused(
                "could not resolve which repository or refs this push publishes (a directory \
                 change, config override or environment it cannot follow)"
                    .into(),
            ));
        }
        let Some(range) = range_of(&inv, &hints)? else {
            continue;
        };
        sources_are_commits(&inv.work_dir, &range)?;
        hex_sources_are_not_ref_names(&inv.work_dir, &range)?;
        let (shas, over) = outbound(&inv.work_dir, &range)?;
        let mut hits = if shas.is_empty() {
            Vec::new()
        } else {
            let mut hits = scan_commits(&inv.work_dir, &range, exempt)?;
            if hits.len() <= MAX_HITS {
                hits.extend(scan_messages(&inv.work_dir, &shas)?);
            }
            hits
        };
        if hits.len() <= MAX_HITS {
            hits.extend(scan_refs_and_tags(&inv.work_dir, &range)?);
        }
        if !hits.is_empty() {
            return Err(Stop::Found(hits));
        }
        if over {
            return Err(Stop::Refused(format!(
                "the range is too large to fully scan (over {MAX_COMMITS} commits; the newest \
                 {MAX_COMMITS} were clean) — push blocked rather than partly scanned"
            )));
        }
    }
    Ok(())
}

fn render(stop: &Stop) -> String {
    const ACK: &str = "If this is a false positive, set CADENCE_ALLOW_SECRET_PUSH=1 in the hook's \
        environment (`.claude/settings.local.json` env block or `~/.claude/settings.json`, \
        never the shared settings; it applies from the next session, an inline `VAR=1 git push` \
        is not read). The allow is recorded as a bypass.";
    match stop {
        Stop::Refused(why) => format!(
            "BLOCKED: git push refused — {why}.\n\
             This guard fails closed: a push it cannot fully scan is not allowed. Narrow the \
             push (push fewer commits or name one branch), or acknowledge it.\n{ACK}"
        ),
        Stop::Found(hits) => {
            let mut out =
                String::from("BLOCKED: this push would publish a secret. Commits carrying one:\n");
            for h in hits.iter().take(MAX_HITS) {
                out.push_str(&format!(
                    "  {}  {}  ({})\n",
                    h.sha,
                    sane(&h.path),
                    sane(&h.what)
                ));
            }
            if hits.len() > MAX_HITS {
                out.push_str("  ...and more\n");
            }
            out.push_str(
                "If the secret is real, rotate it and rewrite the commit before pushing: \
                 removing it in a later commit does not help, the history is what is published.\n",
            );
            out.push_str(ACK);
            out
        }
    }
}

/// PreToolUse Bash guard on `git push`.
pub struct PreventSecretPushGuard;

impl Check for PreventSecretPushGuard {
    fn name(&self) -> &str {
        "prevent-secret-push"
    }

    fn refuses_unread_commands(&self) -> bool {
        true
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        self.run_with_escape(input, std::env::var(ESCAPE_ENV).ok().as_deref())
    }
}

impl PreventSecretPushGuard {
    /// [`Check::run`] with the escape's value passed in, so tests need no env
    /// mutation.
    fn run_with_escape(&self, input: &HookInput, escape: Option<&str>) -> CheckResult {
        self.run_with(input, escape, is_secret_scan_exempt)
    }

    fn run_with(&self, input: &HookInput, escape: Option<&str>, exempt: Exempt) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let Err(stop) = judge(command, cwd, exempt) else {
            return CheckResult::allow();
        };
        // Evaluated only once the guard WOULD block, so a standing setting does
        // not write a bypass row for every unrelated push.
        if is_truthy(escape) {
            return CheckResult::allow_bypassed(BypassProvenance::env_switch(ESCAPE_ENV));
        }
        CheckResult::block(render(&stop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_patterns::is_secret_scan_exempt;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::git_fixtures::Scratch;
    use cadence_hooks_core::test_builders::make_bash_with_cwd;
    use std::path::{Path, PathBuf};

    // Built by concatenation so this file carries no live-shaped literal.
    fn aws_key() -> String {
        format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE")
    }
    fn gh_token() -> String {
        format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
    }

    /// Fixture git, isolated from the machine's system and global config (a
    /// developer's `push.followTags`, `commit.gpgSign` or aliases must not
    /// change a fixture) and from leaked discovery variables.
    fn git_in(dir: &Path, args: &[&str]) {
        let out = git_cmd(dir, args).output().unwrap();
        assert!(out.status.success(), "git {args:?} in {dir:?}: {out:?}");
    }

    fn git_cmd(dir: &Path, args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new("git");
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_COMMON_DIR",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .current_dir(dir);
        cmd
    }

    /// Run fixture git with `input` on stdin, returning trimmed stdout.
    fn git_stdin(dir: &Path, args: &[&str], input: &[u8]) -> String {
        use std::io::Write;
        let mut child = git_cmd(dir, args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A work repo with a bare `origin` that already holds `main`, so
    /// `refs/remotes/origin/main` exists — the common non-first-push shape.
    struct Fx {
        _scratch: Scratch,
        work: PathBuf,
        remote: PathBuf,
    }

    impl Fx {
        fn new(tag: &str) -> Self {
            Self::new_in(tag, "work")
        }

        /// `work` names the checkout's directory under the scratch root; a
        /// nested `cadence-hooks/work` gives the absolute path the component
        /// the fixture exemption keys on, which the relocated root lacks.
        fn new_in(tag: &str, work: &str) -> Self {
            let scratch = Scratch::outside_checkout(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/secretpush-scratch"),
                tag,
            );
            let work = scratch.path().join(work);
            let remote = scratch.path().join("remote.git");
            std::fs::create_dir_all(&work).unwrap();
            std::fs::create_dir_all(&remote).unwrap();
            git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);
            git_in(&work, &["init", "-q", "-b", "main"]);
            git_in(&work, &["config", "user.email", "t@t"]);
            git_in(&work, &["config", "user.name", "t"]);
            // The guard's own spawns read the machine's global config; local
            // values pin every key that changes a verdict.
            for (key, value) in [
                ("commit.gpgSign", "false"),
                ("tag.gpgSign", "false"),
                ("push.followTags", "false"),
                ("push.recurseSubmodules", "no"),
                ("submodule.recurse", "false"),
                ("help.autocorrect", "0"),
            ] {
                git_in(&work, &["config", key, value]);
            }
            git_in(
                &work,
                &["remote", "add", "origin", remote.to_str().unwrap()],
            );
            let fx = Self {
                _scratch: scratch,
                work,
                remote,
            };
            fx.commit("README.md", "hello\n", "init");
            git_in(&fx.work, &["push", "-q", "origin", "main"]);
            fx
        }

        fn commit(&self, path: &str, body: &str, msg: &str) {
            let full = self.work.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, body).unwrap();
            git_in(&self.work, &["add", "-f", path]);
            git_in(&self.work, &["commit", "-q", "-m", msg]);
        }

        fn git(&self, args: &[&str]) {
            git_in(&self.work, args);
        }

        fn run(&self, command: &str) -> CheckResult {
            self.run_escape(command, None)
        }

        /// Runs with no content exemption, so a fixture's verdict never hangs
        /// on where the cache home happens to sit. The exemption tests pass
        /// the real [`is_secret_scan_exempt`] themselves.
        fn run_escape(&self, command: &str, escape: Option<&str>) -> CheckResult {
            let input = make_bash_with_cwd(command, self.work.to_str().unwrap());
            PreventSecretPushGuard.run_with(&input, escape, |_| false)
        }
    }

    fn assert_blocks(r: &CheckResult, needles: &[&str]) {
        assert_eq!(r.outcome, Outcome::Block, "{:?}", r.message);
        let msg = r.message.as_deref().unwrap_or("");
        for n in needles {
            assert!(msg.contains(n), "missing {n:?} in {msg}");
        }
    }

    fn assert_allows(r: &CheckResult) {
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
    }

    #[test]
    fn clean_push_and_non_push_commands_allow() {
        let fx = Fx::new("clean");
        fx.commit("src/a.txt", "fine\n", "add a");
        assert_allows(&fx.run("git push origin main"));
        assert_allows(&fx.run("git status"));
        assert_allows(&fx.run("echo git push"));
    }

    #[test]
    fn credential_token_in_outbound_commit_blocks_naming_sha_path_and_kind() {
        let fx = Fx::new("token");
        fx.commit("src/cfg.txt", &format!("key={}\n", aws_key()), "add cfg");
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["src/cfg.txt", "AWS access key id"]);
        assert!(!r.message.as_deref().unwrap().contains(&aws_key()));
    }

    #[test]
    fn github_token_blocks() {
        let fx = Fx::new("ghtoken");
        fx.commit("notes.md", &format!("t {}\n", gh_token()), "notes");
        assert_blocks(&fx.run("git push"), &["notes.md", "GitHub token"]);
    }

    #[test]
    fn secret_named_file_blocks_without_content_match() {
        let fx = Fx::new("named");
        fx.commit(".env", "FOO=bar\n", "add env");
        assert_blocks(
            &fx.run("git push origin main"),
            &[".env", "secret-named file"],
        );
    }

    #[test]
    fn key_material_binary_name_blocks() {
        let fx = Fx::new("p12");
        fx.commit("certs/prod.p12", "\u{0}\u{1}binary", "cert");
        assert_blocks(&fx.run("git push origin main"), &["certs/prod.p12"]);
    }

    #[test]
    fn pushed_secret_added_then_removed_is_still_caught() {
        let fx = Fx::new("addremove");
        fx.commit("a.txt", &format!("{}\n", aws_key()), "add secret");
        fx.commit("a.txt", "clean\n", "remove secret");
        assert_blocks(&fx.run("git push origin main"), &["a.txt"]);
    }

    #[test]
    fn first_push_with_no_remote_tracking_refs_scans_full_history() {
        let fx = Fx::new("first");
        fx.git(&["checkout", "-q", "-b", "feat"]);
        fx.commit("x.txt", &format!("{}\n", aws_key()), "x");
        // Drop every remote-tracking ref: the first push to a new remote.
        fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
        assert_blocks(&fx.run("git push -u origin feat"), &["x.txt"]);
    }

    #[test]
    fn already_published_secret_is_not_rescanned() {
        let fx = Fx::new("published");
        fx.commit("a.txt", &format!("{}\n", aws_key()), "old secret");
        fx.git(&["push", "-q", "origin", "main"]);
        fx.commit("b.txt", "clean\n", "clean");
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn push_of_other_branch_scans_that_branch_not_head() {
        let fx = Fx::new("branchb");
        fx.git(&["checkout", "-q", "-b", "branchB"]);
        fx.commit("b.txt", &format!("{}\n", aws_key()), "b");
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push origin branchB"), &["b.txt"]);
        // HEAD (main) itself has nothing outbound.
        assert_allows(&fx.run("git push origin main"));
        assert_blocks(&fx.run("git push origin branchB:remote-b"), &["b.txt"]);
    }

    #[test]
    fn dash_c_redirects_the_scan() {
        let fx = Fx::new("dashc");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        let other = fx._scratch.path().join("elsewhere");
        std::fs::create_dir_all(&other).unwrap();
        let cmd = format!("git -C {} push origin main", fx.work.display());
        let input = make_bash_with_cwd(&cmd, other.to_str().unwrap());
        assert_blocks(
            &PreventSecretPushGuard.run_with(&input, None, |_| false),
            &["s.txt"],
        );
    }

    #[test]
    fn delete_plus_publish_still_scans_the_publish() {
        let fx = Fx::new("delpub");
        fx.git(&["checkout", "-q", "-b", "newbranch"]);
        fx.commit("n.txt", &format!("{}\n", aws_key()), "n");
        assert_blocks(&fx.run("git push origin :dead newbranch"), &["n.txt"]);
        assert_allows(&fx.run("git push origin :dead"));
        assert_allows(&fx.run("git push origin --delete newbranch"));
    }

    #[test]
    fn dry_run_allows() {
        let fx = Fx::new("dry");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        assert_allows(&fx.run("git push --dry-run origin main"));
        assert_allows(&fx.run("git push -n origin main"));
    }

    #[test]
    fn wrapped_push_is_still_scanned() {
        let fx = Fx::new("wrapped");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        assert_blocks(&fx.run("sh -c 'git push origin main'"), &["s.txt"]);
        assert_blocks(&fx.run("echo hi && git push origin main"), &["s.txt"]);
        assert_blocks(&fx.run("echo $(git push origin main)"), &["s.txt"]);
    }

    /// cameronsjo/cadence-hooks#1226: a push a git subcommand runs through its
    /// own exec argument publishes the same commits, so it is scanned — or,
    /// where git runs it somewhere this guard cannot follow, refused.
    #[test]
    fn a_push_nested_in_a_git_exec_argument_is_scanned() {
        let fx = Fx::new("gitexec");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        for command in [
            "git rebase -x 'git push origin main' HEAD~1",
            "git rebase --exec='git push origin main' HEAD~1",
            "git rebase -ix'git push origin main' HEAD~1",
            "git bisect run git push origin main",
            "git bisect run sh -c 'git push origin main'",
        ] {
            assert_blocks(&fx.run(command), &["s.txt"]);
        }
        for command in [
            "git submodule foreach 'git push origin main'",
            "git filter-branch --env-filter 'git push origin main' HEAD",
            "git rebase -x \"$CMD\" HEAD~1",
            // Review 3: an outer alias reaching the nested git, and a
            // foreach command's positional parameters.
            "git -c alias.q=push rebase -x 'git q origin main' HEAD~1",
            "git -c alias.q=push bisect run git q origin main",
            "git submodule foreach 'eval \"$@\" #' 'git push origin main'",
            // Review 4: a `shift` the substitution cannot follow, and an
            // editor that is a command substitution.
            "git submodule foreach 'shift; eval \"$@\" #' x 'git push origin main'",
            "GIT_EDITOR='$(echo git push origin main)' git commit",
        ] {
            assert_blocks(&fx.run(command), &["could not resolve"]);
        }
        // Review 10: a dashed git program reached by path is read, and its
        // nested push scanned.
        for command in [
            "/usr/lib/git-core/git-rebase -i -x 'git push origin main' HEAD~1",
            "/usr/lib/git-core/git-bisect run git push origin main",
        ] {
            assert_blocks(&fx.run(command), &[]);
        }
        // Its raw text names the subcommand through `$@`, which the block
        // says in its own words.
        assert_blocks(
            &fx.run("git submodule foreach 'git \"$@\" #' push origin main"),
            &["cannot resolve"],
        );
        // Nothing nested pushes: nothing to scan.
        for command in [
            "git rebase -x 'make test' HEAD~1",
            "git bisect run make test",
            "git submodule foreach 'git pull origin $branch'",
        ] {
            assert_allows(&fx.run(command));
        }
    }

    #[test]
    fn in_repo_fixture_paths_are_exempt_from_the_content_scan() {
        // A repo whose checkout path carries a `cadence-hooks` component, like
        // this one, must be able to push its own fixture keys.
        let fx = Fx::new_in("exempt", "cadence-hooks/work");
        // The relative path (`tests/fx.rs`) carries no `cadence-hooks` component;
        // only the ABSOLUTE path does (the fixture's `cadence-hooks/work` dir), so the
        // exemption applies only if the guard joins the repo root first.
        fx.commit(
            "tests/fx.rs",
            &format!("const K: &str = \"{}\";\n", aws_key()),
            "fixture",
        );
        let cmd = "git push origin main";
        let input = make_bash_with_cwd(cmd, fx.work.to_str().unwrap());
        assert!(is_secret_scan_exempt(fx.work.to_str().unwrap()));
        assert_allows(&PreventSecretPushGuard.run_with(&input, None, is_secret_scan_exempt));
        // Same content outside a `cadence-hooks` component is blocked by the
        // REAL exemption, not a stand-in.
        let fx2 = Fx::new("exempt2");
        assert!(!is_secret_scan_exempt(fx2.work.to_str().unwrap()));
        fx2.commit("src/fx.rs", &format!("K=\"{}\"\n", aws_key()), "fixture");
        let input2 = make_bash_with_cwd(cmd, fx2.work.to_str().unwrap());
        assert_blocks(
            &PreventSecretPushGuard.run_with(&input2, None, is_secret_scan_exempt),
            &["src/fx.rs"],
        );
    }

    #[test]
    fn safe_template_names_skip_the_name_check_but_not_the_content_scan() {
        // The NAME is not a secret name…
        let fx = Fx::new("template");
        fx.commit(".env.example", "FOO=\n", "env example");
        fx.commit("id_rsa.pub", "ssh-ed25519 AAAA t@t\n", "pubkey");
        assert_allows(&fx.run("git push origin main"));
        // …but a live token inside one is still published.
        for name in [
            "config.example",
            ".env.sample",
            "creds.template",
            "a.test",
            "x.ci",
            "y.defaults",
            "z.pub",
        ] {
            let fx = Fx::new("template-content");
            fx.commit(name, &format!("k={}\n", aws_key()), "template");
            assert_blocks(
                &fx.run("git push origin main"),
                &[name, "AWS access key id"],
            );
        }
    }

    #[test]
    fn deleting_a_secret_file_is_not_an_add() {
        let fx = Fx::new("delete");
        // A committed and already-published `.env` (fixture git, not the guard).
        fx.commit(".env", "FOO=bar\n", "env");
        fx.git(&["push", "-q", "origin", "main"]);
        fx.git(&["rm", "-q", ".env"]);
        fx.git(&["commit", "-q", "-m", "rm"]);
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn over_cap_range_blocks_with_count() {
        let fx = Fx::new("overcap");
        // Bulk-create commits cheaply through fast-import.
        let mut stream = String::new();
        for i in 0..(MAX_COMMITS + 5) {
            // Only the first commit names its parent; the rest continue the branch.
            let from = if i == 0 {
                "from refs/heads/main^0\n"
            } else {
                ""
            };
            stream.push_str(&format!(
                "commit refs/heads/main\ncommitter t <t@t> {} +0000\ndata 1\nc\n{from}M 100644 inline f{i}.txt\ndata 2\nx\n\n",
                1_700_000_000 + i
            ));
        }
        let mut child = git_cmd(&fx.work, &["fast-import", "--quiet"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stream.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["too large"]);
        assert_blocks(&r, &[ESCAPE_ENV]);
    }

    #[test]
    fn oversized_patch_blocks() {
        let fx = Fx::new("bytes");
        // Several MiB over the cap, so the cap — not the clock — decides.
        let big = "xxxxxxxxxxxxxxx\n".repeat((MAX_LOG_BYTES + (4 << 20)) / 16);
        fx.commit("big.txt", &big, "big");
        assert_blocks(&fx.run("git push origin main"), &["too large"]);
    }

    #[test]
    fn unresolvable_range_blocks_never_allows() {
        let fx = Fx::new("unresolved");
        // Source ref does not exist: git errors, and error is not "nothing to push".
        assert_blocks(&fx.run("git push origin nosuchbranch"), &["nosuchbranch"]);
        // A source the guard will not hand to git.
        assert_blocks(&fx.run("git push origin HEAD~1:main"), &["HEAD~1"]);
        // A directory the walk cannot follow.
        assert_blocks(
            &fx.run("cd \"$SOMEWHERE\" && git push origin main"),
            &["resolve"],
        );
    }

    #[test]
    fn broken_repository_blocks() {
        let fx = Fx::new("broken");
        std::fs::remove_dir_all(fx.work.join(".git/objects")).unwrap();
        assert_blocks(
            &fx.run("git push origin main"),
            &["git could not", ESCAPE_ENV],
        );
    }

    #[test]
    fn all_and_mirror_widen_to_every_local_branch() {
        let fx = Fx::new("all");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("side.txt", &format!("{}\n", aws_key()), "side");
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push --all origin"), &["side.txt"]);
        assert_blocks(&fx.run("git push --mirror origin"), &["side.txt"]);
    }

    #[test]
    fn tags_push_scans_off_branch_commits_and_tag_objects() {
        let fx = Fx::new("tags");
        // A commit no branch reaches, pinned only by a tag.
        fx.git(&["checkout", "-q", "--detach"]);
        fx.commit("t.txt", &format!("{}\n", aws_key()), "tagged");
        fx.git(&["tag", "v1"]);
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push --tags origin"), &["t.txt"]);

        // An annotated tag whose MESSAGE carries the secret, on a published commit.
        let fx = Fx::new("tagmsg");
        fx.git(&["tag", "-a", "v2", "-m", &format!("note {}", gh_token())]);
        assert_blocks(&fx.run("git push --tags origin"), &["v2", "GitHub token"]);
        assert_blocks(&fx.run("git push origin v2"), &["v2"]);
    }

    #[test]
    fn evil_merge_content_is_scanned_but_merged_in_history_is_not_double_counted() {
        let fx = Fx::new("merge");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("s.txt", &format!("{}\n", gh_token()), "side");
        fx.git(&["checkout", "-q", "main"]);
        fx.commit("m.txt", "main\n", "main");
        fx.git(&["merge", "-q", "--no-commit", "--no-ff", "side"]);
        std::fs::write(fx.work.join("m.txt"), format!("{}\n", aws_key())).unwrap();
        fx.git(&["add", "m.txt"]);
        fx.git(&["commit", "-q", "-m", "merge"]);
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["m.txt", "s.txt"]);
        // Exactly two findings: the side commit's s.txt and the merge's own
        // m.txt. `--cc` must not report s.txt a second time on the merge.
        let msg = r.message.unwrap();
        assert_eq!(msg.matches("s.txt").count(), 1, "{msg}");
        assert_eq!(msg.matches("m.txt").count(), 1, "{msg}");
    }

    #[test]
    fn gitattributes_binary_marking_does_not_hide_content() {
        let fx = Fx::new("attrs");
        fx.commit(".gitattributes", "*.txt -diff\n", "attrs");
        fx.commit("h.txt", &format!("{}\n", aws_key()), "hidden");
        assert_blocks(&fx.run("git push origin main"), &["h.txt"]);
    }

    #[test]
    fn ack_env_allows_records_provenance_and_needs_a_would_be_block() {
        let fx = Fx::new("ack");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        let r = fx.run_escape("git push origin main", Some("1"));
        assert_eq!(r.outcome, Outcome::Allow);
        let p = r.bypass.expect("provenance recorded");
        assert_eq!(p.mechanism, ESCAPE_ENV);
        // Falsy values do not open it.
        for v in ["", "0", "no"] {
            assert_blocks(&fx.run_escape("git push origin main", Some(v)), &["s.txt"]);
        }
        // Set but nothing to block: allowed, with no provenance row.
        let clean = Fx::new("ack-clean");
        let r = clean.run_escape("git push origin main", Some("1"));
        assert_allows(&r);
        assert!(r.bypass.is_none());
    }

    #[test]
    fn many_findings_are_capped_in_the_message() {
        let fx = Fx::new("many");
        for i in 0..8 {
            fx.commit(&format!("k{i}.txt"), &format!("{}\n", aws_key()), "k");
        }
        let r = fx.run("git push origin main");
        assert_eq!(r.outcome, Outcome::Block);
        assert!(r.message.unwrap().contains("more"));
    }

    #[test]
    fn remote_dir_is_untouched_by_scanning() {
        let fx = Fx::new("readonly");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        assert_blocks(&fx.run("git push origin main"), &["s.txt"]);
        assert_eq!(git_out(&fx.remote, &["rev-list", "--all", "--count"]), "1");
    }

    #[test]
    fn header_path_reads_plain_spaced_and_quoted_paths() {
        for (rest, want) in [
            ("a/x.txt b/x.txt", Some("x.txt")),
            ("a/my dir/a b.txt b/my dir/a b.txt", Some("my dir/a b.txt")),
            ("\"a/q\\\"x.txt\" \"b/q\\\"x.txt\"", Some("q\"x.txt")),
            ("a/x.txt b/y.txt", None),
            ("nonsense", None),
            ("", None),
        ] {
            assert_eq!(header_path(rest).as_deref(), want, "{rest}");
        }
    }

    #[test]
    fn spaced_and_odd_paths_are_scanned() {
        let fx = Fx::new("spaces");
        fx.commit("my dir/a b.txt", &format!("{}\n", aws_key()), "spaced");
        assert_blocks(&fx.run("git push origin main"), &["my dir/a b.txt"]);
        let fx = Fx::new("unicode");
        fx.commit("caf\u{e9}/k.txt", &format!("{}\n", aws_key()), "u");
        assert_blocks(&fx.run("git push origin main"), &["caf\u{e9}/k.txt"]);
    }

    #[test]
    fn over_cap_range_still_names_a_secret_in_the_newest_commits() {
        let fx = Fx::new("overcap-hit");
        let mut stream = String::new();
        for i in 0..(MAX_COMMITS + 5) {
            let from = if i == 0 {
                "from refs/heads/main^0\n"
            } else {
                ""
            };
            stream.push_str(&format!(
                "commit refs/heads/main\ncommitter t <t@t> {} +0000\ndata 1\nc\n{from}M 100644 inline f{i}.txt\ndata 2\nx\n\n",
                1_700_000_000 + i
            ));
        }
        stream.push_str(&format!(
            "commit refs/heads/main\ncommitter t <t@t> 1800000000 +0000\ndata 1\nc\nM 100644 inline leak.txt\ndata {}\n{}\n\n",
            aws_key().len() + 1,
            aws_key()
        ));
        let mut child = git_cmd(&fx.work, &["fast-import", "--quiet"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stream.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert_blocks(&fx.run("git push origin main"), &["leak.txt"]);
    }

    /// Run `git` in `dir` with stdin, returning trimmed stdout.
    fn git_out(dir: &Path, args: &[&str]) -> String {
        let out = git_cmd(dir, args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    // --- review findings (cadence-hooks#890 review round) -----------------

    #[test]
    fn root_commit_is_scanned_despite_log_show_root_false() {
        let fx = Fx::new("showroot");
        fx.git(&["config", "log.showRoot", "false"]);
        fx.git(&["checkout", "-q", "--orphan", "fresh"]);
        fx.git(&["rm", "-rq", "--cached", "."]);
        fx.commit("root.txt", &format!("{}\n", aws_key()), "root");
        assert_blocks(&fx.run("git push origin fresh"), &["root.txt"]);
    }

    #[test]
    fn diff_relative_from_a_subdir_does_not_hide_files() {
        let fx = Fx::new("relative");
        fx.git(&["config", "diff.relative", "true"]);
        fx.commit("sub/keep.txt", "x\n", "sub");
        fx.git(&["push", "-q", "origin", "main"]);
        fx.commit("top.txt", &format!("{}\n", aws_key()), "top");
        let sub = fx.work.join("sub");
        let input = make_bash_with_cwd("git push origin main", sub.to_str().unwrap());
        assert_blocks(
            &PreventSecretPushGuard.run_with(&input, None, |_| false),
            &["top.txt"],
        );
    }

    #[test]
    fn replace_refs_do_not_change_what_is_scanned() {
        let fx = Fx::new("replace");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "secret");
        // A clean stand-in with the same parent, grafted over the real commit.
        let tree = git_out(&fx.work, &["rev-parse", "HEAD~1^{tree}"]);
        let parent = git_out(&fx.work, &["rev-parse", "HEAD~1"]);
        let clean = git_out(
            &fx.work,
            &["commit-tree", &tree, "-p", &parent, "-m", "clean"],
        );
        let real = git_out(&fx.work, &["rev-parse", "HEAD"]);
        fx.git(&["replace", &real, &clean]);
        assert_blocks(&fx.run("git push origin main"), &["s.txt"]);
    }

    #[test]
    fn tag_message_with_a_record_separator_byte_is_scanned_whole() {
        let fx = Fx::new("tagctl");
        let msg = fx._scratch.path().join("tagmsg");
        std::fs::write(&msg, format!("release\n\u{1}forged\n{}\n", gh_token())).unwrap();
        fx.git(&["tag", "-a", "v9", "-F", msg.to_str().unwrap()]);
        assert_blocks(&fx.run("git push origin v9"), &["v9", "GitHub token"]);
        assert_blocks(&fx.run("git push --tags origin"), &["v9", "GitHub token"]);
    }

    #[test]
    fn config_aliases_that_push_are_not_invisible() {
        let fx = Fx::new("alias");
        fx.commit("s.txt", "clean\n", "clean");
        // Persistent alias to push, and an alias of that alias.
        fx.git(&["config", "alias.pp", "push"]);
        fx.git(&["config", "alias.p2", "pp"]);
        fx.git(&["config", "alias.sh", "!git push origin main"]);
        fx.git(&["config", "alias.lg", "log --oneline"]);
        for cmd in ["git pp origin main", "git p2", "git sh", "git -C . pp"] {
            assert_blocks(&fx.run(cmd), &["alias"]);
        }
        // An alias that does not push is untouched, as is a builtin.
        assert_allows(&fx.run("git lg -1"));
        assert_allows(&fx.run("git status"));
        // Probing is bounded: past the cap an unknown subcommand is refused.
        let dirs: Vec<PathBuf> = (0..=MAX_ALIAS_PROBES)
            .map(|i| {
                let d = fx.work.join(format!("d{i}"));
                std::fs::create_dir_all(&d).unwrap();
                d
            })
            .collect();
        let many = dirs
            .iter()
            .map(|d| format!("git -C {} zz", d.display()))
            .collect::<Vec<_>>()
            .join("; ");
        assert_blocks(&fx.run(&many), &["more directories"]);
        // An alias this same command writes is refused before the probe could
        // see it.
        let fresh = Fx::new("alias-inline");
        assert_blocks(
            &fresh.run("git config alias.qq push; git qq origin main"),
            &["qq", "alias"],
        );
    }

    #[test]
    fn remote_mirror_config_widens_a_bare_push() {
        let fx = Fx::new("mirrorcfg");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("side.txt", &format!("{}\n", aws_key()), "side");
        fx.git(&["checkout", "-q", "main"]);
        assert_allows(&fx.run("git push origin"));
        fx.git(&["config", "remote.origin.mirror", "true"]);
        assert_blocks(&fx.run("git push origin"), &["side.txt"]);
        // Set by the same command.
        fx.git(&["config", "--unset", "remote.origin.mirror"]);
        assert_blocks(
            &fx.run("git config remote.origin.mirror true && git push origin"),
            &["side.txt"],
        );
    }

    #[test]
    fn a_ref_or_tag_naming_a_blob_or_tree_blocks() {
        let fx = Fx::new("blobtag");
        let file = fx._scratch.path().join("blob.txt");
        std::fs::write(&file, format!("{}\n", aws_key())).unwrap();
        let blob = git_out(&fx.work, &["hash-object", "-w", file.to_str().unwrap()]);
        fx.git(&["tag", "blobtag", &blob]);
        assert_blocks(&fx.run("git push origin blobtag"), &["blobtag"]);
        assert_blocks(&fx.run("git push --tags origin"), &["blobtag", "blob"]);
        let fx = Fx::new("treetag");
        fx.git(&["tag", "-a", "treetag", "-m", "t", "HEAD^{tree}"]);
        assert_blocks(&fx.run("git push origin treetag"), &["treetag"]);
        assert_blocks(&fx.run("git push --tags origin"), &["treetag", "tree"]);
        // A tag of a tag hides a second message.
        let fx = Fx::new("nestedtag");
        fx.git(&["tag", "-a", "inner", "-m", &format!("x {}", gh_token())]);
        fx.git(&["tag", "-a", "outer", "-m", "outer", "inner"]);
        fx.git(&["tag", "-d", "inner"]);
        assert_blocks(&fx.run("git push origin outer"), &["outer", "tag"]);
    }

    #[test]
    fn commit_message_secret_blocks() {
        let fx = Fx::new("commitmsg");
        std::fs::write(fx.work.join("a.txt"), "clean\n").unwrap();
        fx.git(&["add", "a.txt"]);
        fx.git(&["commit", "-q", "-m", &format!("deploy with {}", gh_token())]);
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["commit message", "GitHub token"]);
        assert!(!r.message.as_deref().unwrap().contains(&gh_token()));
    }

    #[test]
    fn a_commit_on_any_remote_reads_as_published_so_fork_flows_push() {
        // Fork flow: `upstream` history carries a fixture token; a branch
        // based on `upstream/main` goes to `origin`, which never had it.
        let fx = Fx::new("forkflow");
        let upstream = fx._scratch.path().join("upstream.git");
        let seed = fx._scratch.path().join("seed");
        std::fs::create_dir_all(&upstream).unwrap();
        std::fs::create_dir_all(&seed).unwrap();
        git_in(&upstream, &["init", "-q", "--bare", "-b", "main"]);
        git_in(&seed, &["init", "-q", "-b", "main"]);
        for (key, value) in [("user.email", "t@t"), ("user.name", "t")] {
            git_in(&seed, &["config", key, value]);
        }
        std::fs::write(seed.join("fx.txt"), format!("{}\n", aws_key())).unwrap();
        git_in(&seed, &["add", "fx.txt"]);
        git_in(&seed, &["commit", "-q", "-m", "fixture"]);
        git_in(&seed, &["push", "-q", upstream.to_str().unwrap(), "main"]);
        fx.git(&["remote", "add", "upstream", upstream.to_str().unwrap()]);
        fx.git(&["fetch", "-q", "upstream"]);
        fx.git(&["checkout", "-q", "-b", "feat", "upstream/main"]);
        fx.commit("clean.txt", "fine\n", "clean");
        assert_allows(&fx.run("git push origin feat"));
        assert_allows(&fx.run("git push -u origin feat"));
        // A new secret on top of the fork branch is still outbound.
        fx.commit("new.txt", &format!("{}\n", gh_token()), "new");
        assert_blocks(&fx.run("git push origin feat"), &["new.txt"]);
    }

    #[test]
    fn follow_tags_scans_annotated_tags_it_would_publish() {
        let fx = Fx::new("follow");
        // On an already-published commit: the tag object is still new.
        fx.git(&["tag", "-a", "v5", "-m", &format!("note {}", gh_token())]);
        assert_allows(&fx.run("git push origin main"));
        assert_blocks(&fx.run("git push --follow-tags origin main"), &["v5"]);
        assert_blocks(
            &fx.run("git -c push.followTags=true push origin main"),
            &["v5"],
        );
        fx.git(&["config", "push.followTags", "true"]);
        assert_blocks(&fx.run("git push origin main"), &["v5"]);
        assert_allows(&fx.run("git push --no-follow-tags origin main"));
        // With followTags off again, only resolving the NAMED source can find
        // the tag: `tags/X` and `tag X` both name it.
        fx.git(&["config", "push.followTags", "false"]);
        assert_allows(&fx.run("git push origin main"));
        assert_blocks(&fx.run("git push origin tags/v5"), &["v5", "GitHub token"]);
        assert_blocks(&fx.run("git push origin tag v5"), &["v5", "GitHub token"]);
    }

    #[test]
    fn recurse_submodules_that_push_them_blocks() {
        let fx = Fx::new("submods");
        fx.commit("a.txt", "clean\n", "clean");
        // Recursion only matters when the repository has submodules.
        fx.commit(
            ".gitmodules",
            "[submodule \"s\"]\n\tpath = s\n\turl = ../s\n",
            "modules",
        );
        for cmd in [
            "git push --recurse-submodules=on-demand origin main",
            "git push --recurse-submodules on-demand origin main",
            "git push --recurse-submodules=only origin main",
            "git -c push.recurseSubmodules=on-demand push origin main",
        ] {
            assert_blocks(&fx.run(cmd), &["submodules"]);
        }
        for cmd in [
            "git push --recurse-submodules=check origin main",
            "git push --no-recurse-submodules origin main",
        ] {
            assert_allows(&fx.run(cmd));
        }
        fx.git(&["config", "push.recurseSubmodules", "on-demand"]);
        assert_blocks(&fx.run("git push origin main"), &["submodules"]);
        assert_allows(&fx.run("git push --recurse-submodules=check origin main"));
        fx.git(&["config", "--unset", "push.recurseSubmodules"]);
        fx.git(&["config", "submodule.recurse", "true"]);
        assert_blocks(&fx.run("git push origin main"), &["submodules"]);
    }

    #[test]
    fn tag_keyword_and_at_sign_name_the_right_refs() {
        let fx = Fx::new("tagkw");
        fx.commit("a.txt", "clean\n", "clean");
        fx.git(&["tag", "v3"]);
        assert_allows(&fx.run("git push origin tag v3"));
        assert_allows(&fx.run("git push origin @"));
        assert_allows(&fx.run("git push origin @:refs/heads/other"));
        fx.git(&["tag", "-a", "v4", "-m", &format!("n {}", gh_token())]);
        assert_blocks(&fx.run("git push origin tag v4"), &["v4", "GitHub token"]);
        fx.commit("b.txt", &format!("{}\n", aws_key()), "secret");
        assert_blocks(&fx.run("git push origin @"), &["b.txt"]);
    }

    #[test]
    fn all_pushes_branches_only_and_tags_only_pushes_tags() {
        let fx = Fx::new("allbranches");
        // A secret on a detached commit pinned by an annotated tag: `--all`
        // publishes neither.
        fx.git(&["checkout", "-q", "--detach"]);
        fx.commit("d.txt", &format!("{}\n", aws_key()), "detached");
        fx.git(&["tag", "-a", "vd", "-m", &format!("m {}", gh_token())]);
        assert_allows(&fx.run("git push --all origin"));
        assert_blocks(&fx.run("git push --tags origin"), &["d.txt", "vd"]);
        assert_blocks(&fx.run("git push --mirror origin"), &["d.txt"]);
        // `--tags` from a HEAD carrying an unpublished secret does not push HEAD.
        let fx = Fx::new("tagsonly");
        fx.commit("h.txt", &format!("{}\n", aws_key()), "head");
        assert_allows(&fx.run("git push --tags origin"));
    }

    #[test]
    fn unquote_reads_git_c_quoting() {
        for (quoted, want) in [
            ("x\\ty", "x\ty"),
            ("x\\ny", "x\ny"),
            ("q\\001r", "q\u{1}r"),
            ("caf\\303\\251", "caf\u{e9}"),
            ("a\\\"b\\\\c", "a\"b\\c"),
            ("trail\\", "trail\\"),
        ] {
            assert_eq!(unquote(quoted), want, "{quoted}");
        }
    }

    // Unix only: Windows forbids control characters in file names.
    #[cfg(unix)]
    #[test]
    fn control_character_paths_are_scanned() {
        let fx = Fx::new("ctlpath");
        fx.commit("x\ty.txt", &format!("{}\n", aws_key()), "tab");
        assert_blocks(&fx.run("git push origin main"), &["x?y.txt"]);
    }

    // --- review round 2 (cadence-hooks#890) --------------------------------

    #[test]
    fn alias_values_opening_with_global_options_are_followed() {
        let fx = Fx::new("aliasopts");
        fx.git(&["config", "alias.y", "push"]);
        fx.git(&["config", "alias.x", "-c a.b=c y"]);
        fx.git(&["config", "alias.pp", "push"]);
        fx.git(&["config", "alias.p2", "--paginate pp"]);
        // Options only: git 2.43 refuses it ("empty alias"), so refusing it
        // too costs nothing, and an older git may splice the next word in.
        fx.git(&["config", "alias.opts", "-c a.b=c"]);
        fx.git(&["config", "alias.lg2", "-c color.ui=never log --oneline"]);
        for cmd in [
            "git x origin main",
            "git p2 origin main",
            "git opts push origin main",
        ] {
            assert_blocks(&fx.run(cmd), &["alias"]);
        }
        assert_allows(&fx.run("git lg2 -1"));
    }

    #[test]
    fn alias_probe_refuses_config_and_env_it_cannot_see() {
        let fx = Fx::new("aliasredirect");
        for cmd in [
            "GIT_CONFIG_GLOBAL=/tmp/x git zz origin main",
            "GIT_CONFIG_COUNT=1 git zz",
            "HOME=/tmp/x git zz",
            "XDG_CONFIG_HOME=/tmp/x git zz",
            "GIT_DIR=/tmp/x/.git git zz",
            "GIT_WORK_TREE=/tmp/x git zz",
            "GIT_COMMON_DIR=/tmp/x git zz",
            "git -c help.autocorrect=immediate psuh origin main",
            "git config help.autocorrect 1 && git psuh origin main",
            "git --git-dir=/tmp/x/.git zz",
            "git --work-tree /tmp/x zz",
            "git --config-env=alias.zz=V zz",
            "git -c include.path=/tmp/x zz",
            "git -c includeIf.onbranch:main.path=/tmp/x zz",
            "git -c INCLUDE.PATH=/tmp/x zz",
            "cd \"$D\" && git zz",
            "git -C \"$D\" zz",
            "git -C `pwd` zz",
            "GIT_EXEC_PATH=/tmp/x git zz",
            "export GIT_\"DIR\"=/tmp/x; git zz",
            "export 'GIT_DIR'=/tmp/x; git zz",
            "export GIT_DIR\\=/tmp/x; git zz",
            "export H\"OME\"=/tmp/x; git zz",
            "read GIT_DIR <<< /tmp/x; export GIT_DIR; git zz",
            "printf -v GIT_WORK_TREE /tmp/x; export GIT_WORK_TREE; git zz",
            "declare -x XDG_CONFIG_HOME=/tmp/x; git zz",
        ] {
            assert_blocks(&fx.run(cmd), &["alias"]);
        }
        // Builtins are unaffected.
        for cmd in [
            "HOME=/tmp/x git status",
            "GIT_DIR=.git git log -1",
            "git -c include.path=/tmp/x status",
            "git -c help.autocorrect=1 status",
            "cd \"$D\" && git status",
            "GIT_EXEC_PATH=/tmp/x git status",
            "read GIT_DIR <<< /tmp/x; export GIT_DIR; git log -1",
        ] {
            assert_allows(&fx.run(cmd));
        }
    }

    #[test]
    fn unresolvable_subcommand_word_blocks() {
        let fx = Fx::new("subvar");
        for cmd in [
            "git $X origin main",
            "git ${X} origin main",
            "git `echo push` origin main",
            "git \"$(echo pu)sh\" origin main",
        ] {
            assert_blocks(&fx.run(cmd), &["resolve"]);
        }
    }

    /// Write a raw commit object on top of HEAD and move `main` to it.
    fn raw_commit(fx: &Fx, extra_header: &str, message: &str) {
        let tree = git_out(&fx.work, &["rev-parse", "HEAD^{tree}"]);
        let parent = git_out(&fx.work, &["rev-parse", "HEAD"]);
        let body = format!(
            "tree {tree}\nparent {parent}\nauthor t <t@t> 1700000000 +0000\n\
             committer t <t@t> 1700000000 +0000\n{extra_header}\n{message}\n"
        );
        let sha = git_stdin(
            &fx.work,
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            body.as_bytes(),
        );
        fx.git(&["update-ref", "refs/heads/main", &sha]);
    }

    #[test]
    fn commit_messages_are_read_raw_not_re_encoded() {
        // An encoding header makes `%B` transcode the message into garbage.
        let fx = Fx::new("msgenc");
        raw_commit(&fx, "encoding UTF-16LE", &format!("deploy {}", gh_token()));
        assert_blocks(
            &fx.run("git push origin main"),
            &["commit message", "GitHub token"],
        );
        // So does the repository's output encoding.
        let fx = Fx::new("msgout");
        fx.git(&[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            &format!("x {}", gh_token()),
        ]);
        fx.git(&["config", "i18n.logOutputEncoding", "UTF-16"]);
        assert_blocks(
            &fx.run("git push origin main"),
            &["commit message", "GitHub token"],
        );
        // A token in a commit header is published too.
        let fx = Fx::new("msghdr");
        raw_commit(&fx, &format!("x-note {}", gh_token()), "clean");
        assert_blocks(&fx.run("git push origin main"), &["GitHub token"]);
    }

    #[test]
    fn truthy_follows_git_bool_semantics() {
        for value in ["true", "yes", "on", "1", "2", "-1", "TRUE", " On "] {
            assert!(truthy(value), "{value:?}");
        }
        for value in ["false", "no", "off", "0", "", "NO", "00"] {
            assert!(!truthy(value), "{value:?}");
        }
    }

    #[test]
    fn an_integer_mirror_setting_widens_the_push() {
        let fx = Fx::new("mirrorint");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("side.txt", &format!("{}\n", aws_key()), "side");
        fx.git(&["checkout", "-q", "main"]);
        fx.git(&["config", "remote.origin.mirror", "2"]);
        assert_blocks(&fx.run("git push origin"), &["side.txt"]);
    }

    /// Point a branch at a non-commit, which `update-ref` refuses: a loose
    /// ref file written directly (the files backend reads it as-is).
    fn force_ref(fx: &Fx, name: &str, sha: &str) {
        let path = fx.work.join(".git").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("{sha}\n")).unwrap();
    }

    #[test]
    fn tag_objects_reached_by_sha_or_a_non_tag_ref_are_scanned() {
        let fx = Fx::new("tagsha");
        fx.git(&["tag", "-a", "vt", "-m", &format!("note {}", gh_token())]);
        let tag = git_out(&fx.work, &["rev-parse", "refs/tags/vt"]);
        fx.git(&["tag", "-d", "vt"]);
        force_ref(&fx, "refs/heads/tb", &tag);
        fx.git(&["update-ref", "refs/remotes/x/v1", &tag]);
        for cmd in [
            format!("git push origin {tag}:refs/tags/vt"),
            "git push origin tb".to_string(),
            "git push origin refs/heads/tb:refs/heads/tb".to_string(),
            "git push origin refs/remotes/x/v1:refs/tags/v1".to_string(),
            "git push --all origin".to_string(),
        ] {
            assert_blocks(&fx.run(&cmd), &["GitHub token"]);
        }
        // A tag of a tree reached through a branch is refused.
        let fx = Fx::new("tagtree");
        fx.git(&["tag", "-a", "tt", "-m", "t", "HEAD^{tree}"]);
        let tag = git_out(&fx.work, &["rev-parse", "refs/tags/tt"]);
        fx.git(&["tag", "-d", "tt"]);
        force_ref(&fx, "refs/heads/tt", &tag);
        assert_blocks(&fx.run("git push --all origin"), &["tree"]);
    }

    #[test]
    fn send_pack_and_http_push_are_unscannable_pushes() {
        let fx = Fx::new("sendpack");
        let remote = fx.remote.display().to_string();
        for cmd in [
            format!("git send-pack {remote} main"),
            format!("git -C . send-pack {remote} main"),
            format!("git-send-pack {remote} main"),
            "git http-push https://example.invalid/r.git main".to_string(),
        ] {
            assert_blocks(&fx.run(&cmd), &["publishes objects without `git push`"]);
        }
        fx.git(&["config", "alias.sp", &format!("send-pack {remote}")]);
        assert_blocks(&fx.run("git sp main"), &["alias"]);
    }

    #[test]
    fn ref_names_carrying_a_token_block_without_echoing_it() {
        let fx = Fx::new("refname");
        let name = format!("fix-{}", gh_token());
        fx.git(&["branch", &name]);
        for cmd in [
            format!("git push origin {name}"),
            format!("git push origin main:refs/heads/{name}"),
            "git push --all origin".to_string(),
            "git push --mirror origin".to_string(),
        ] {
            let r = fx.run(&cmd);
            assert_blocks(&r, &["GitHub token"]);
            assert!(
                !r.message.as_deref().unwrap().contains(&gh_token()),
                "{cmd}"
            );
        }
        fx.git(&["checkout", "-q", &name]);
        assert_blocks(&fx.run("git push -u origin"), &["GitHub token"]);
        let fx = Fx::new("tagname");
        fx.git(&["tag", &format!("v-{}", gh_token())]);
        assert_blocks(&fx.run("git push --tags origin"), &["GitHub token"]);
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn the_exemption_keys_on_the_repository_toplevel_only() {
        let fx = Fx::new("exempt-sub");
        assert!(!is_secret_scan_exempt(fx.work.to_str().unwrap()));
        fx.commit("cadence-hooks/x.txt", &format!("{}\n", aws_key()), "subdir");
        let input = make_bash_with_cwd("git push origin main", fx.work.to_str().unwrap());
        assert_blocks(
            &PreventSecretPushGuard.run_with(&input, None, is_secret_scan_exempt),
            &["cadence-hooks/x.txt"],
        );
    }

    #[test]
    fn branches_and_follow_tags_abbreviations_are_read() {
        let fx = Fx::new("abbrev");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("side.txt", &format!("{}\n", aws_key()), "side");
        fx.git(&["checkout", "-q", "main"]);
        for cmd in [
            "git push --branches origin",
            "git push --br origin",
            "git push --b origin",
        ] {
            assert_blocks(&fx.run(cmd), &["side.txt"]);
        }
        let fx = Fx::new("abbrev-follow");
        fx.git(&["tag", "-a", "v7", "-m", &format!("n {}", gh_token())]);
        assert_blocks(&fx.run("git push --fol origin main"), &["v7"]);
        assert_blocks(&fx.run("git push --follow origin main"), &["v7"]);
        fx.git(&["config", "push.followTags", "true"]);
        assert_allows(&fx.run("git push --no-fol origin main"));
        assert_allows(&fx.run("git push --no-follow origin main"));
    }

    #[cfg(unix)]
    #[test]
    fn a_git_command_on_path_must_be_executable_in_an_absolute_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("git-psuh");
        std::fs::write(&shim, "").unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            !path_runs_git_command(&path, "psuh"),
            "a 0644 file is not a command"
        );
        // git tests the owner bit alone: group/other execute is not enough.
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o011)).unwrap();
        assert!(
            !path_runs_git_command(&path, "psuh"),
            "0011 is not a command"
        );
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o100)).unwrap();
        assert!(path_runs_git_command(&path, "psuh"));
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(path_runs_git_command(&path, "psuh"));
        // A relative or empty entry is not trusted, even when it holds one.
        let cwd = std::env::current_dir().unwrap();
        let rel = pathdiff_relative(dir.path(), &cwd);
        for entry in [rel.as_os_str(), std::ffi::OsStr::new("")] {
            let path = std::env::join_paths([entry]).unwrap();
            assert!(!path_runs_git_command(&path, "psuh"), "{entry:?}");
        }
    }

    /// `target` spelled relative to `base` (via `..`), for a relative PATH
    /// entry that really reaches it.
    #[cfg(unix)]
    fn pathdiff_relative(target: &std::path::Path, base: &std::path::Path) -> std::path::PathBuf {
        let mut rel = std::path::PathBuf::new();
        for _ in base.components().skip(1) {
            rel.push("..");
        }
        rel.join(target.strip_prefix("/").unwrap())
    }

    #[test]
    fn help_autocorrect_refuses_an_unknown_subcommand() {
        let fx = Fx::new("autocorrect");
        for value in ["1", "immediate", "-1", "true", "10"] {
            fx.git(&["config", "help.autocorrect", value]);
            assert_blocks(&fx.run("git psuh origin main"), &["autocorrect"]);
            // A real command outside the builtin list is not a guess.
            assert_allows(&fx.run("git hash-object README.md"));
        }
        for value in ["0", "false", "never", "show", "prompt"] {
            fx.git(&["config", "help.autocorrect", value]);
            assert_allows(&fx.run("git psuh origin main"));
        }
    }

    #[test]
    fn a_failed_alias_probe_blocks() {
        let fx = Fx::new("probefail");
        let missing = fx._scratch.path().join("no-such-dir");
        assert_blocks(
            &fx.run(&format!("git -C {} zz", missing.display())),
            &["config"],
        );
        // A config git cannot parse.
        let config = fx.work.join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("\n[broken\n");
        std::fs::write(&config, text).unwrap();
        assert_blocks(&fx.run("git zz"), &["config"]);
        assert_allows(&fx.run("echo hi"));
    }

    #[test]
    fn recursion_without_submodules_allows_and_with_a_gitlink_blocks() {
        let fx = Fx::new("nosubs");
        fx.commit("a.txt", "clean\n", "clean");
        assert_allows(&fx.run("git push --recurse-submodules=on-demand origin main"));
        fx.git(&["config", "submodule.recurse", "true"]);
        assert_allows(&fx.run("git push origin main"));
        fx.git(&["config", "push.recurseSubmodules", "only"]);
        assert_allows(&fx.run("git push origin main"));
        // A gitlink in the index, with no .gitmodules.
        let head = git_out(&fx.work, &["rev-parse", "HEAD"]);
        fx.git(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head},sub"),
        ]);
        assert_blocks(&fx.run("git push origin main"), &["submodules"]);
    }

    #[test]
    fn dashed_git_push_and_an_exec_renamed_git_are_unscannable_pushes() {
        let fx = Fx::new("dashedpush");
        for cmd in [
            "git-push origin main",
            "/usr/lib/git-core/git-push origin main",
            "git-push.exe origin main",
            "command git-push origin main",
            "exec -a git-push git origin main",
            "exec -ca git-push git origin main",
            "exec -l -a /x/git-push git origin main",
            "exec -agit-push git origin main",
            "exec -a git-status git origin main",
        ] {
            assert_blocks(&fx.run(cmd), &["cannot scan"]);
        }
        // A plain `exec`, and an `exec -a` naming anything but git, are not.
        assert_allows(&fx.run("exec git push origin main"));
        assert_allows(&fx.run("exec -a worker sleep 1"));
    }

    #[test]
    fn a_source_spelled_as_an_object_id_that_a_ref_also_names_blocks() {
        let fx = Fx::new("hexref");
        let clean = git_out(&fx.work, &["rev-parse", "HEAD"]);
        fx.git(&["checkout", "-q", "-b", "leak"]);
        fx.commit("leak.txt", &format!("{}\n", aws_key()), "leak");
        fx.git(&["checkout", "-q", "main"]);
        // git push reads the source as the ref; rev-parse as the object.
        for (made, cmd) in [
            (
                format!("refs/heads/{clean}"),
                format!("git push origin {clean}:refs/heads/x"),
            ),
            (
                format!("refs/tags/{clean}"),
                format!("git push origin +{clean}:refs/heads/x"),
            ),
            (
                format!("refs/remotes/{clean}/HEAD"),
                format!("git push origin {clean}:refs/heads/x"),
            ),
            (
                format!("refs/heads/{}", clean.to_uppercase()),
                format!("git push origin {}:refs/heads/x", clean.to_uppercase()),
            ),
        ] {
            fx.git(&["update-ref", &made, "leak"]);
            assert_blocks(&fx.run(&cmd), &["named like an object id"]);
            fx.git(&["update-ref", "-d", &made]);
        }
        // With no such ref, the object id is what git pushes.
        assert_allows(&fx.run(&format!("git push origin {clean}:refs/heads/x")));
    }

    #[test]
    fn remote_helpers_are_unscannable_pushes_but_git_remote_is_not() {
        let fx = Fx::new("remotehelper");
        for cmd in [
            "git remote-https origin https://example.invalid/r.git",
            "git remote-http origin http://example.invalid/r.git",
            "git remote-ext origin 'ext::sh -c x'",
            "git remote-fd 0",
            "git remote-ftps origin ftps://example.invalid/r.git",
            "git-remote-https origin https://example.invalid/r.git",
            "/usr/lib/git-core/git-remote-http origin http://example.invalid/r.git",
        ] {
            assert_blocks(&fx.run(cmd), &["cannot scan"]);
        }
        for cmd in ["git remote", "git remote -v", "git remote add up /tmp/x"] {
            assert_allows(&fx.run(cmd));
        }
    }

    #[test]
    fn commit_messages_in_an_unscannable_encoding_block() {
        for (tag, header) in [
            ("encutf7", "encoding UTF-7"),
            ("encebcdic", "encoding IBM037"),
        ] {
            let fx = Fx::new(tag);
            raw_commit(&fx, header, "clean");
            assert_blocks(&fx.run("git push origin main"), &["encoding"]);
        }
        // Recorded by git itself from `i18n.commitEncoding`.
        let fx = Fx::new("encgit");
        fx.git(&[
            "-c",
            "i18n.commitEncoding=UTF-7",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "clean",
        ]);
        assert_blocks(&fx.run("git push origin main"), &["encoding"]);
        // Encodings the scanner reads as-is.
        let fx = Fx::new("encok");
        for header in [
            "encoding UTF-8",
            "encoding utf8",
            "encoding US-ASCII",
            "encoding ascii",
            "encoding ISO-8859-1",
            "encoding iso-8859-15",
            "encoding latin1",
        ] {
            raw_commit(&fx, header, "clean");
        }
        assert_allows(&fx.run("git push origin main"));
    }
}
