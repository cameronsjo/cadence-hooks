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
//! `git rev-list <src> --not --remotes=<dest>` (positive ref BEFORE `--not`:
//! the other order negates the ref too and scans nothing), where `<dest>` is
//! the configured remote the push goes to — the push's repository argument, or
//! for a bare push `branch.<b>.pushRemote` / `remote.pushDefault` /
//! `branch.<b>.remote` / `origin`. A URL, a remote this command rewrites, or a
//! remote whose tracking refs another remote's fetch refspec writes falls back
//! to every remote-tracking ref (`--remotes`). `--all` widens to every branch,
//! `--mirror` (flag or `remote.<dest>.mirror`) to every ref, `--tags` adds
//! every tag. `tag <name>` reads as `refs/tags/<name>`, `@` as `HEAD`.
//!
//! **Scan.** One `git log -p -U0 --cc --root` over the outbound range, so a
//! secret added and then removed inside the range is still seen (a net diff
//! misses it). Merge commits use `--cc`, which shows exactly the content a merge
//! introduces that no parent had. Content goes through
//! [`crate::credential_scan`] (the #1022 token shapes) and
//! [`scan_secret_values`]; names go through [`is_blocked`]. A second pass reads
//! the same commits' MESSAGES through the same text scanner, and annotated tag
//! objects the push publishes (`--tags`, `--mirror`, `--follow-tags` /
//! `push.followTags`, a named tag) are read raw, header and message. The block
//! message carries short sha, path and pattern name, never the value.
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
//! `push.recurseSubmodules`, or `submodule.recurse`), a failed, unavailable or
//! timed-out git spawn, a range over [`MAX_COMMITS`], a patch over
//! [`MAX_LOG_BYTES`], too many refspecs, an unparseable diff header — all
//! block, and the message says which. Only a genuinely empty range allows.
//!
//! **Aliases.** A `git <sub>` whose subcommand is not a builtin is looked up in
//! the repository's config (`alias.<sub>`, following alias-of-alias); one whose
//! value names `push` or starts with `!` blocks as unresolved, as does one this
//! same command writes with `git config`.
//!
//! **Bounded.** Every git spawn goes through `run_bounded_capped` (process-group
//! kill, stdout cap, shared hook deadline). The commit cap is applied to git
//! itself (`rev-list -n`), so an entire first-push history is never buffered.
//!
//! **Deliberately allowed** (each documented, none silent):
//! - `--dry-run`/`-n` pushes and pure deletions (nothing is published);
//! - commits already reachable from the destination remote's tracking refs
//!   (or from ANY remote-tracking ref when the destination is a URL or cannot
//!   be named — a commit only on a fork then reads as published);
//! - **every file of a repository checked out under a `cadence-hooks` path
//!   component** — a whole-repo exemption from the content scan (the
//!   `prevent-secret-writes` one), because this repository's sources hold
//!   hundreds of fake tokens in unit tests. A known residual: any checkout
//!   under such a component, or a path below one, is content-exempt. Names
//!   and messages are still checked;
//! - a secret-*named* check skipped for a safe-template name (a
//!   [`crate::secret_patterns::SAFE_SUFFIXES`] suffix: `.example`,
//!   `.template`, `.sample`, `.defaults`, `.test`, `.ci`, `.pub`). Their
//!   CONTENT is still scanned;
//! - deleting a secret-named file (removal publishes no content);
//! - secrets outside the corpus (no entropy scan; token *grammar* only).
//!
//! **Over-blocks on purpose:** `--tags` re-reads every tag, published or not.
//!
//! **Not covered:** pushes core does not detect — `gh repo create --push`,
//! `git subtree push`, a `git-<name>` executable on `PATH`, a push inside a
//! script file; a git config key written by the same command through anything
//! but `git config`/`git remote` (an editor, a redirect into `.git/config`);
//! an alias in a directory the walk cannot follow (the hook's cwd is probed).
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
    run_bounded_capped, skip_git_global_options, unescape_word,
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
/// Deepest alias-of-alias chain followed.
const MAX_ALIAS_DEPTH: usize = 10;

/// Decides, from the ABSOLUTE path, whether the content scan is skipped.
type Exempt = fn(&str) -> bool;

/// One git answer, with the four outcomes kept apart.
enum Git {
    Ok(String),
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
    match run_bounded_capped(&mut cmd, timeout, Some(max_stdout)) {
        GitSpawn::Completed(out) if out.status.success() => {
            Git::Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
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

/// A delimiter no object can contain: 128 random bits from the process's
/// randomly seeded hasher. Used where git prints free text (a message, a tag)
/// between records, so a crafted message cannot forge a record boundary.
fn nonce() -> String {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    let mut a = state.build_hasher();
    a.write_u8(1);
    let mut b = state.build_hasher();
    b.write_u8(2);
    format!("@@cadence-{:016x}{:016x}@@", a.finish(), b.finish())
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
    globals: Vec<String>,
    rest: Vec<String>,
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
        if command_word(first) != "git" {
            continue;
        }
        let rest = skip_git_global_options(&argv[1..]);
        let globals = &argv[1..argv.len() - rest.len()];
        let mut at = if &*dir == UNRESOLVABLE_DIR {
            cwd.to_string()
        } else {
            dir.to_string()
        };
        let mut words = globals.iter();
        while let Some(word) = words.next() {
            if unescape_word(word) == "-C"
                && let Some(value) = words.next()
                && !value.contains(['$', '`'])
            {
                at = resolve_cd_target(value, &at);
            }
        }
        out.push(GitCall {
            dir: at,
            globals: globals
                .iter()
                .map(|w| unescape_word(w).into_owned())
                .collect(),
            rest: rest.iter().map(|w| unescape_word(w).into_owned()).collect(),
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

/// Does the alias `name` (following alias-of-alias) run a push, or a shell
/// command that can? `aliases` maps lowercased name → value.
fn alias_runs_push(aliases: &HashMap<String, String>, name: &str) -> bool {
    let mut name = name.to_string();
    for _ in 0..MAX_ALIAS_DEPTH {
        let Some(value) = aliases.get(&name) else {
            return false;
        };
        // git splits an alias with its own quoting, so `pu\sh` and `p"u"sh`
        // are `push` to it.
        let plain: String = value
            .chars()
            .filter(|c| !matches!(c, '\\' | '"' | '\''))
            .collect::<String>()
            .to_ascii_lowercase();
        if plain.trim_start().starts_with('!') || plain.contains("push") {
            return true;
        }
        match plain.split_whitespace().next() {
            Some(next) if !BUILTINS.contains(&next) => name = next.to_string(),
            _ => return false,
        }
    }
    true // a chain this deep is not something to vouch for
}

/// The first alias the command runs that hides a push, if any.
fn hidden_alias_push(calls: &[GitCall], hints: &CommandHints) -> Option<String> {
    let mut probed: HashMap<String, HashMap<String, String>> = HashMap::new();
    for call in calls {
        let Some(sub) = call.rest.first() else {
            continue;
        };
        let sub = sub.to_ascii_lowercase();
        if sub.starts_with('-') || BUILTINS.contains(&sub.as_str()) {
            continue;
        }
        if hints.aliases.contains(&sub) {
            return Some(sub);
        }
        let aliases = probed.entry(call.dir.clone()).or_insert_with(|| {
            // An unreadable config is not a detected push: nothing to judge.
            read_config(&call.dir, "^alias\\.")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(k, v)| Some((k.strip_prefix("alias.")?.to_ascii_lowercase(), v)))
                .collect()
        });
        if alias_runs_push(aliases, &sub) {
            return Some(sub);
        }
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
    /// What is already published: `--remotes=<dest>` or `--remotes`.
    negate: String,
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

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

/// Config keys the range depends on, read in one spawn.
const RANGE_CONFIG: &str = "^(push\\.(followtags|recursesubmodules)|submodule\\.recurse|\
    remote\\..*\\.(mirror|fetch|url)|remote\\.pushdefault|branch\\..*\\.(remote|pushremote))$";

/// The configured remote this push goes to, when it can be named.
fn destination_remote(
    inv: &PushInvocation,
    cfg: &[(String, String)],
    work_dir: &str,
) -> Option<String> {
    let get = |key: &str| {
        cfg.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    if let Some(repo) = &inv.repository {
        return Some(repo.clone());
    }
    let branch = match git(
        work_dir,
        &["symbolic-ref", "-q", "--short", "HEAD"],
        4096,
        Budget::Probe,
    ) {
        Git::Ok(b) => Some(b.trim().to_string()),
        _ => None,
    };
    let per_branch = |key: &str| {
        branch
            .as_deref()
            .and_then(|b| get(&format!("branch.{b}.{key}")))
    };
    per_branch("pushremote")
        .or_else(|| get("remote.pushdefault"))
        .or_else(|| per_branch("remote"))
        .or_else(|| Some("origin".to_string()))
}

/// `--remotes=<name>` when `name` is a configured remote whose tracking refs
/// only it writes; `--remotes` otherwise.
fn negation_for(name: Option<&str>, inv: &PushInvocation, cfg: &[(String, String)]) -> String {
    let all = "--remotes".to_string();
    // The command rewrites where the push goes: the probe's answer is stale.
    if !inv.config_remotes.is_empty()
        || !inv.config_destinations.is_empty()
        || inv.destination_unreadable
    {
        return all;
    }
    let Some(name) = name else { return all };
    if name.is_empty() || name.contains(['*', '?', '[', '\\', ':']) || name.starts_with('-') {
        return all;
    }
    let configured = cfg.iter().any(|(k, _)| k == &format!("remote.{name}.url"));
    if !configured {
        return all; // a URL, or a remote this command adds
    }
    // Another remote whose fetch refspec writes under refs/remotes/<name>/
    // would make those refs say "published" about commits the destination
    // never received.
    let ours = format!("refs/remotes/{name}/");
    let hijacked = cfg.iter().any(|(k, v)| {
        k.starts_with("remote.")
            && k.ends_with(".fetch")
            && k != &format!("remote.{name}.fetch")
            && v.split_once(':')
                .is_some_and(|(_, dst)| dst.starts_with(&ours))
    });
    if hijacked {
        return all;
    }
    format!("--remotes={name}")
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
    // The flag overrides config; among config sources any one is enough.
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
    if let Some(value) = recurse {
        return Err(Stop::Refused(format!(
            "the push recurses into submodules (`{}`), whose commits this guard cannot scan",
            sane(&value)
        )));
    }

    let dest = destination_remote(inv, &cfg, &inv.work_dir);
    let negate = negation_for(dest.as_deref(), inv, &cfg);
    let remote_mirror = dest
        .as_deref()
        .is_some_and(|d| get_bool(&format!("remote.{d}.mirror")));
    let mirror = inv.mirror || remote_mirror || hints.mirror;
    let follow_tags = inv
        .follow_tags
        .unwrap_or_else(|| get_bool("push.followtags") || hints.follow_tags);

    let widened = inv.all_or_mirror || mirror || inv.tags;
    // The implicit `HEAD` is not published by a push that widens: `--tags`
    // pushes only tags, `--all`/`--mirror` their own ref sets.
    let sources: Vec<String> = if widened && inv.refspecs.iter().all(|r| r.implicit) {
        Vec::new()
    } else {
        sources
    };
    if sources.is_empty() && !widened {
        return Ok(None); // nothing but deletions: nothing is published
    }
    Ok(Some(Range {
        sources,
        branches: inv.all_or_mirror && !inv.mirror,
        mirror,
        tags: inv.tags,
        follow_tags,
        negate,
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
    args.extend(["--not", range.negate.as_str()]);
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

/// The outbound commit count, capped. Second value: the range held more than
/// [`MAX_COMMITS`].
fn outbound(work_dir: &str, range: &Range) -> Result<(usize, bool), Stop> {
    let limit = (MAX_COMMITS + 1).to_string();
    let mut args: Vec<&str> = vec!["rev-list", "-n", &limit];
    args.extend(range_args(range));
    args.push("--");
    match git(work_dir, &args, (MAX_COMMITS + 2) * 66, Budget::Probe) {
        Git::Ok(text) => {
            let count = text.lines().filter(|l| !l.trim().is_empty()).count();
            Ok((count.min(MAX_COMMITS), count > MAX_COMMITS))
        }
        Git::Capped => Ok((MAX_COMMITS, true)),
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
fn scan_patch(output: &str, toplevel: &str, exempt: Exempt, hits: &mut Vec<Hit>) {
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
        let absolute = format!("{}/{}", toplevel.trim_end_matches('/'), path);
        if f.added.is_empty() || exempt(&absolute) {
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
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--format=%x01%H",
    ];
    args.extend(range_args(range));
    args.push("--");
    match git(work_dir, &args, MAX_LOG_BYTES, Budget::Scan) {
        Git::Ok(text) => {
            let mut hits = Vec::new();
            scan_patch(&text, &toplevel, exempt, &mut hits);
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

/// The outbound commits' messages, through the same text scanner. Kept apart
/// from the patch parse: a message is free text that could otherwise pose as
/// patch structure.
fn scan_messages(work_dir: &str, range: &Range) -> Result<Vec<Hit>, Stop> {
    let delimiter = nonce();
    let format = format!("--format={delimiter}%H%n%B");
    let limit = MAX_COMMITS.to_string();
    let mut args: Vec<&str> = vec![
        "log",
        "-n",
        &limit,
        "--no-color",
        "--no-notes",
        "--no-show-signature",
        &format,
    ];
    args.extend(range_args(range));
    args.push("--");
    let text = match git(work_dir, &args, MAX_MESSAGE_BYTES, Budget::Scan) {
        Git::Ok(t) => t,
        Git::Capped => {
            return Err(Stop::Refused(
                "the outbound commit messages are too large to scan".into(),
            ));
        }
        Git::Failed(_) => {
            return Err(Stop::Refused(
                "git could not read the outbound commit messages".into(),
            ));
        }
        Git::Down => {
            return Err(Stop::Refused(
                "git was unavailable or timed out reading the outbound commit messages".into(),
            ));
        }
    };
    let mut hits = Vec::new();
    // Every fragment is scanned whole; the delimiter cannot be forged.
    for record in text.split(delimiter.as_str()) {
        if let Some(what) = scan_text(record) {
            hits.push(Hit {
                sha: record.chars().take(8).collect(),
                path: "(commit message)".into(),
                what,
            });
        }
    }
    Ok(hits)
}

/// Every tag object and non-commit ref the push publishes: each tag object is
/// read raw (header and message) and must peel straight to a commit.
fn scan_tag_objects(work_dir: &str, range: &Range) -> Result<Vec<Hit>, Stop> {
    let mut hits = Vec::new();
    // Unfiltered: `--mirror` (every ref), `--tags`, and named sources.
    let named: Vec<String> = range
        .sources
        .iter()
        .filter(|s| *s != "HEAD")
        .flat_map(|s| {
            if s.starts_with("refs/") {
                vec![s.clone()]
            } else {
                vec![format!("refs/{s}"), format!("refs/tags/{s}")]
            }
        })
        .collect();
    let covers_tags = range.mirror || range.tags;
    if range.mirror {
        scan_refs(work_dir, &[], &[], &mut hits)?;
    } else {
        let mut patterns: Vec<String> = named;
        if range.tags {
            patterns.push("refs/tags".into());
        }
        if !patterns.is_empty() {
            scan_refs(work_dir, &patterns, &[], &mut hits)?;
        }
    }
    // `--follow-tags`: annotated tags reachable from what is pushed, whether
    // or not their commit is new — the tag object itself is.
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
            scan_refs(work_dir, &["refs/tags".to_string()], &merged, &mut hits)?;
        }
    }
    Ok(hits)
}

fn scan_refs(
    work_dir: &str,
    patterns: &[String],
    filters: &[String],
    hits: &mut Vec<Hit>,
) -> Result<(), Stop> {
    let delimiter = nonce();
    let format = format!(
        "--format={delimiter}%(objecttype) %(refname)%0a\
         %(if:equals=tag)%(objecttype)%(then)%(raw)%(end)"
    );
    let mut args: Vec<&str> = vec!["for-each-ref", &format];
    args.extend(filters.iter().map(String::as_str));
    args.extend(patterns.iter().map(String::as_str));
    let text = match git(work_dir, &args, MAX_TAG_BYTES, Budget::Scan) {
        Git::Ok(t) => t,
        Git::Capped => {
            return Err(Stop::Refused(
                "the tag objects are too large to scan".into(),
            ));
        }
        Git::Failed(_) => return Err(Stop::Refused("git could not read the tags".into())),
        Git::Down => {
            return Err(Stop::Refused(
                "git was unavailable or timed out reading the tags".into(),
            ));
        }
    };
    for record in text.split(delimiter.as_str()) {
        let (head, body) = record.split_once('\n').unwrap_or((record, ""));
        let (kind, name) = head.split_once(' ').unwrap_or((head, ""));
        let name = sane(name);
        match kind {
            "" if record.trim().is_empty() => continue,
            "commit" => continue,
            "tag" => {
                // The header's `type` line: a tag of a tag carries a second
                // message this read never sees, a tag of a tree or blob
                // publishes content no patch shows.
                let target = body
                    .lines()
                    .take_while(|l| !l.is_empty())
                    .find_map(|l| l.strip_prefix("type "));
                if target != Some("commit") {
                    hits.push(Hit {
                        sha: "tag".into(),
                        path: name.clone(),
                        what: format!(
                            "tags a {}, which this guard cannot scan",
                            sane(target.unwrap_or("unreadable object"))
                        ),
                    });
                }
            }
            other => {
                hits.push(Hit {
                    sha: "ref".into(),
                    path: name.clone(),
                    what: format!("points at a {}, which this guard cannot scan", sane(other)),
                });
                continue;
            }
        }
        if let Some(what) = scan_text(record) {
            hits.push(Hit {
                sha: "tag".into(),
                path: name,
                what,
            });
        }
    }
    Ok(())
}

fn judge(command: &str, cwd: &str, exempt: Exempt) -> Result<(), Stop> {
    let calls = git_calls(command, cwd);
    let hints = command_hints(&calls);
    if let Some(alias) = hidden_alias_push(&calls, &hints) {
        return Err(Stop::Refused(format!(
            "`git {}` is an alias that can run a push (its value names `push` or runs a \
             shell command), so what it publishes could not be resolved",
            sane(&alias)
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
        let (count, over) = outbound(&inv.work_dir, &range)?;
        let mut hits = if count == 0 {
            Vec::new()
        } else {
            let mut hits = scan_commits(&inv.work_dir, &range, exempt)?;
            if hits.len() <= MAX_HITS {
                hits.extend(scan_messages(&inv.work_dir, &range)?);
            }
            hits
        };
        if hits.len() <= MAX_HITS {
            hits.extend(scan_tag_objects(&inv.work_dir, &range)?);
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
    use cadence_hooks_core::git_fixtures::{Scratch, git_in};
    use cadence_hooks_core::test_builders::make_bash_with_cwd;
    use std::path::{Path, PathBuf};

    // Built by concatenation so this file carries no live-shaped literal.
    fn aws_key() -> String {
        format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE")
    }
    fn gh_token() -> String {
        format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
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
            git_in(&work, &["config", "commit.gpgsign", "false"]);
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
        let mut child = std::process::Command::new("git")
            .args(["fast-import", "--quiet"])
            .current_dir(&fx.work)
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
        let _ = fx.run("git push origin main");
        let out = std::process::Command::new("git")
            .args([
                "-C",
                fx.remote.to_str().unwrap(),
                "rev-list",
                "--all",
                "--count",
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
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
        let mut child = std::process::Command::new("git")
            .args(["fast-import", "--quiet"])
            .current_dir(&fx.work)
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
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
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
    fn only_the_destination_remotes_tracking_refs_count_as_published() {
        let fx = Fx::new("otherremote");
        let upstream = fx._scratch.path().join("upstream.git");
        std::fs::create_dir_all(&upstream).unwrap();
        git_in(&upstream, &["init", "-q", "--bare", "-b", "main"]);
        fx.git(&["remote", "add", "upstream", upstream.to_str().unwrap()]);
        fx.commit("s.txt", &format!("{}\n", aws_key()), "secret");
        // On upstream (so refs/remotes/upstream/main has it), not on origin.
        fx.git(&["push", "-q", "upstream", "main"]);
        assert_blocks(&fx.run("git push origin main"), &["s.txt"]);
        // The bare push resolves its remote the way git does.
        fx.git(&["branch", "-q", "--set-upstream-to=origin/main"]);
        assert_blocks(&fx.run("git push"), &["s.txt"]);
        // Pushing to the remote that has it: nothing new.
        assert_allows(&fx.run("git push upstream main"));
        // A URL destination keeps trusting every remote-tracking ref.
        let url = format!("git push {} main", fx.remote.display());
        assert_allows(&fx.run(&url));
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
        // `tags/X` names the tag.
        assert_blocks(&fx.run("git push origin tags/v5"), &["v5"]);
    }

    #[test]
    fn recurse_submodules_that_push_them_blocks() {
        let fx = Fx::new("submods");
        fx.commit("a.txt", "clean\n", "clean");
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

    #[test]
    fn control_character_paths_are_scanned() {
        let fx = Fx::new("ctlpath");
        fx.commit("x\ty.txt", &format!("{}\n", aws_key()), "tab");
        assert_blocks(&fx.run("git push origin main"), &["x?y.txt"]);
    }
}
