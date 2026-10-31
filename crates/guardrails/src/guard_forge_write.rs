//! Guard against unintended `tea` (Gitea) and `glab` (GitLab) write operations
//! (cameronsjo/cadence-hooks#355, option a).
//!
//! Mirrors `guard-gh-write`'s owner allowlist for the two other forge CLIs the
//! session-start context can route the model toward. A write to a repo whose
//! owner is not in `CADENCE_ALLOWED_OWNERS` (or whose repo is not in
//! `CADENCE_ALLOWED_REPOS`) blocks; a write whose target cannot be read from
//! the command blocks; reads pass untouched.
//!
//! **Deliberately small.** The verb tables below are explicit; a verb that is
//! not in them is treated as a read. `glab api` / `tea api` and raw `curl`
//! against a forge API are NOT covered (tracked in #355's scope note).
//!
//! **Bare targets are host-strict.** `-R owner/repo` names no host, so it is
//! matched against `CADENCE_EXTRA_HOSTS` (and, for `glab`, `GITLAB_HOST` /
//! `gitlab.com` when host-qualified allowlist entries name it), never against
//! the GitHub default host: an owner name reused on another forge is not
//! owned there unless the operator says so.
//!
//! **`tea` is read the way tea 0.16 reads itself** (cameronsjo/cadence-hooks#1601):
//! - The repo flag is `--repo`/`-r`. `-R` is `--remote`, a git remote name.
//!   Flags are read as tea's urfave/cli parser reads them: one or two
//!   dashes, a name or alias, `=` or the next word, and none after `--`, a
//!   lone `-`, or a single-dash word whose second character is not a letter.
//! - A `--repo` slug is `owner/repo` and tea keeps only its first two
//!   segments, so `--repo host/owner/repo` names owner `host`, repo `owner`.
//! - A slug names no host: tea sends it to its login's host. That host is
//!   read from tea's config (the `--login` one, else every login) and from
//!   `GITEA_INSTANCE_URL`, and the slug is owned only on all of them. A
//!   config with a login the guard cannot read, or one with content that
//!   yields no login (`logins :`, JSON, a BOM), refuses; only a missing,
//!   empty or comment-only config leaves the decision to
//!   `CADENCE_EXTRA_HOSTS`. An assignment in front of `tea` to `HOME`,
//!   `XDG_CONFIG_HOME` or a `GITEA_*` variable refuses.
//! - With no `--repo`, tea uses the repo of the directory it runs in. The
//!   guard reads that directory's git remotes (the payload `cwd` plus literal
//!   `cd`s, narrowed by `--remote`) and allows only when every one is owned.

use std::path::{Path, PathBuf};

use crate::guard_gh_write::dir_after_runners;

use cadence_hooks_core::config::{
    AllowEntry, env_allow_entries, env_extra_hosts, is_allowed_with_extra_hosts,
};
use cadence_hooks_core::shell::{
    COMMAND_RUNNERS, GitQuery, UNRESOLVABLE_DIR, command_segments, command_segments_with_dirs,
    command_word, executable_tokens, git_command_detailed, host_and_repo_from_url,
    is_assignment_word, names_transparent_prefix, parse_work_dir, peel_command_runners,
    strip_group_wrappers,
};
use cadence_hooks_core::{BlockMetadata, Check, CheckResult, HookInput};

/// `(noun aliases, write verbs)` for `glab`. Anything else is a read.
const GLAB_WRITES: &[(&[&str], &[&str])] = &[
    (
        &["mr", "merge-request"],
        &["create", "merge", "note", "close"],
    ),
    (&["issue"], &["create", "note", "close"]),
    (&["repo"], &["delete", "create"]),
];

/// `(noun aliases, write verbs)` for `tea`. `tea comment` is a top-level verb; `*` matches any verb.
const TEA_WRITES: &[(&[&str], &[&str])] = &[
    (
        &["pulls", "pull", "pr"],
        &["create", "c", "merge", "m", "close"],
    ),
    (&["issues", "issue", "i"], &["create", "c", "close"]),
    (&["repos", "repo", "r"], &["create", "c", "delete", "rm"]),
    // tea 0.16 names the command `comments`, with aliases `comment` and `c`.
    (&["comments", "comment", "c"], &["*"]),
];

/// Flags whose value is the FOLLOWING token, so it is not a positional.
const VALUE_FLAGS: &[&str] = &[
    "-R",
    "-r",
    "--repo",
    "--remote",
    "--login",
    "-l",
    "--output",
    "-o",
    "--hostname",
    "--owner",
    "-O",
    "--name",
    "--group",
    "-g",
    "--title",
    "-t",
    "--description",
    "-d",
    "--message",
    "-m",
    "--body",
];

#[derive(Debug, PartialEq, Eq)]
enum Forge {
    Glab,
    Tea,
}

/// A forge write found in one segment.
#[derive(Debug, PartialEq, Eq)]
struct ForgeWrite {
    forge: Forge,
    /// The whole segment, for the message.
    text: String,
    /// The owner/repo the command names, with an explicit host when a URL or
    /// `--hostname`/`GITLAB_HOST` gave one. `None` when nothing names a target.
    target: Option<Target>,
    /// `tea` only: how tea picks the login and the local repo.
    tea: TeaFlags,
}

/// The `tea` flags and inline assignment that choose its login and remote.
#[derive(Debug, Default, PartialEq, Eq)]
struct TeaFlags {
    /// `--login`/`-l`.
    login: Option<String>,
    /// `--remote`/`-R`: the git remote tea reads the repo from.
    remote: Option<String>,
    /// An inline assignment in front of `tea` to `HOME`, `XDG_CONFIG_HOME` or
    /// a `GITEA_*` variable, which moves tea's config or login.
    env_override: Option<String>,
    /// `--repo`/`-r` or `--owner` was given. tea then never uses the
    /// directory's repo, so a value the guard cannot read is unresolvable
    /// rather than a reason to judge the directory instead.
    repo_given: bool,
    /// The literal `--repo`/`-r` value, for the directory check: tea reads a
    /// value that names an existing directory as that local repo.
    repo_value: Option<String>,
    /// The write acts on the repo of the directory tea runs in when no
    /// `--repo` is given (`pulls`, `issues`, `comment`). `repos create|delete`
    /// act under the login's user instead.
    dir_scoped: bool,
    /// A flag that could name the repo, login, remote or owner in a spelling
    /// the guard does not read.
    unknown_target_flag: Option<String>,
}

/// One login from tea's config: its name and the host of its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TeaLogin {
    name: String,
    host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: Option<String>,
    owner: String,
    repo: String,
}

/// The value of `flag` (`-R x`, `-Rx`, `--repo x`, `--repo=x`), last one wins.
fn flag_value(args: &[String], names: &[&str]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        for name in names {
            if a == name {
                found = args.get(i + 1).cloned();
            } else if let Some(v) = a.strip_prefix(&format!("{name}=")) {
                found = Some(v.to_string());
            } else if name.len() == 2
                && !name.starts_with("--")
                && a.starts_with(name)
                && a.len() > 2
            {
                found = Some(a[2..].to_string());
            }
        }
        i += 1;
    }
    found
}

/// Positionals after the verb, skipping flags and the values of value flags.
fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            out.extend(args[i + 1..].iter().map(String::as_str));
            break;
        }
        if VALUE_FLAGS.contains(&a) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            out.push(a);
        }
        i += 1;
    }
    out
}

/// tea's flags that choose the repo, the login, the remote and the owner:
/// each long name and its aliases.
const TEA_REPO: &[&str] = &["repo", "r"];
const TEA_LOGIN: &[&str] = &["login", "l"];
const TEA_REMOTE: &[&str] = &["remote", "R"];
const TEA_OWNER: &[&str] = &["owner", "O"];
const TEA_NAME: &[&str] = &["name"];

/// tea flags (by name, any dash count) whose value is the next word, so the
/// word is not a positional.
const TEA_VALUE_NAMES: &[&str] = &[
    "repo",
    "r",
    "login",
    "l",
    "remote",
    "R",
    "owner",
    "O",
    "name",
    "title",
    "t",
    "description",
    "d",
    "message",
    "m",
    "body",
    "output",
    "o",
    "labels",
    "L",
    "assignees",
    "a",
    "milestone",
    "M",
    "deadline",
    "D",
    "base",
    "b",
    "head",
    "branch",
    "license",
    "gitignores",
    "readme",
    "trustmodel",
    "object-format",
    "description-file",
];

/// A tea flag word read the way urfave/cli (tea's parser) reads it: one or
/// two dashes, then a name, then an optional `=value`. `None` for a word that
/// is not a flag (`-`, `--`, a positional, three dashes).
fn tea_flag_word(word: &str) -> Option<(&str, Option<&str>)> {
    let body = word.strip_prefix("--").or_else(|| word.strip_prefix('-'))?;
    if body.is_empty() || body.starts_with('-') {
        return None;
    }
    Some(match body.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (body, None),
    })
}

/// Whether tea's parser stops reading flags at `word`, so it and every later
/// word are positionals: `--` (itself dropped), a lone `-`, or a single-dash
/// word whose second character is not a letter (`- fixed`, `-1`, `->`), as
/// urfave/cli v3 does.
fn tea_flag_stop(word: &str) -> bool {
    if word == "--" || word == "-" {
        return true;
    }
    let mut chars = word.chars();
    chars.next() == Some('-') && chars.next().is_some_and(|c| c != '-' && !c.is_alphabetic())
}

/// The value of the tea flag named by any of `names` (`--repo x`, `-repo x`,
/// `--r=x`, `-r x`), last one wins. tea does not take a value glued to a
/// short flag (`-rX`), so neither does this.
fn tea_flag(args: &[String], names: &[&str]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        if tea_flag_stop(&args[i]) {
            break;
        }
        if let Some((name, value)) = tea_flag_word(&args[i]) {
            let takes_next = value.is_none() && TEA_VALUE_NAMES.contains(&name);
            if names.contains(&name) {
                found = match value {
                    Some(v) => Some(v.to_string()),
                    None => args.get(i + 1).cloned(),
                };
            }
            if takes_next {
                i += 1;
            }
        }
        i += 1;
    }
    found
}

/// A tea flag the guard does not recognise whose name could be a misspelt or
/// extended repo, login, remote or owner flag (`--rep`, `-logi`, `--repos`).
/// tea may read it in a way the guard did not, so the write is refused.
fn tea_unknown_target_flag(args: &[String]) -> Option<String> {
    const STEMS: &[&str] = &["repo", "login", "remote", "owner"];
    let known = |n: &str| {
        [TEA_REPO, TEA_LOGIN, TEA_REMOTE, TEA_OWNER]
            .iter()
            .any(|names| names.contains(&n))
    };
    let near_miss = |name: &str| {
        !known(name)
            && STEMS.iter().any(|stem| {
                (name.len() >= 2 && stem.starts_with(name))
                    || name
                        .strip_prefix(stem)
                        .is_some_and(|rest| !rest.starts_with('-'))
            })
    };
    // The word after a value flag is its value (`--title "--remote fix"`),
    // so it is skipped, as tea skips it.
    let mut i = 0;
    while i < args.len() && !tea_flag_stop(&args[i]) {
        if let Some((name, value)) = tea_flag_word(&args[i]) {
            if near_miss(name) {
                return Some(args[i].clone());
            }
            if value.is_none() && TEA_VALUE_NAMES.contains(&name) {
                i += 1;
            }
        }
        i += 1;
    }
    None
}

/// [`positionals`] for tea, whose value flags take any dash count.
fn tea_positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if tea_flag_stop(a) {
            let from = if a == "--" { i + 1 } else { i };
            out.extend(args[from..].iter().map(String::as_str));
            break;
        }
        match tea_flag_word(a) {
            Some((name, None)) if TEA_VALUE_NAMES.contains(&name) => i += 1,
            Some(_) => {}
            None => out.push(a),
        }
        i += 1;
    }
    out
}

/// A repo spelled `owner/repo`, `group/sub/repo`, or a URL. Refuses anything
/// carrying an expansion: a target the shell computes is not a target read.
fn parse_target(value: &str, host: Option<&str>) -> Option<Target> {
    if value.is_empty() || value.contains(['$', '`', '*', '?', '{', '~', ' ']) {
        return None;
    }
    if value.contains("://") || value.contains('@') {
        let (h, path) = host_and_repo_from_url(value)?;
        let (owner, repo) = path.split_once('/')?;
        return Some(Target {
            host: Some(h),
            owner: owner.to_string(),
            repo: repo.trim_end_matches(".git").to_string(),
        });
    }
    let value = value.trim_matches('/');
    let (first, rest) = value.split_once('/')?;
    let repo = rest.rsplit('/').next().unwrap_or(rest);
    if first.is_empty() || repo.is_empty() || first == "." || first == ".." || rest.contains("..") {
        return None;
    }
    Some(Target {
        host: host.map(str::to_lowercase),
        owner: first.to_string(),
        repo: repo.trim_end_matches(".git").to_string(),
    })
}

/// A `tea --repo` slug, read as tea 0.16's `GetOwnerAndRepo` reads it: leading
/// `/` trimmed, split on `/`, owner and repo the first two parts, the rest
/// ignored. No host: tea has none in a slug, and a URL is not a slug to tea
/// (`https://h/o/r` names owner `https:` and an empty repo, so it is refused).
/// A one-part slug means the login's own user, which is not read here.
fn parse_tea_slug(value: &str) -> Option<Target> {
    if value.is_empty() || value.contains(['$', '`', '*', '?', '{', '~', ' ']) {
        return None;
    }
    let mut parts = value.trim_start_matches('/').split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let unreadable = |p: &str| p.is_empty() || p == "." || p == ".." || p.contains(':');
    if unreadable(owner) || unreadable(repo) {
        return None;
    }
    Some(Target {
        host: None,
        owner: owner.to_string(),
        repo: repo.to_string(),
    })
}

/// The host of a forge URL (`https://user@h:3000/x` → `h`), lowercased.
fn url_host(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let authority = rest.split('/').next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The logins in a tea `config.yml`, or `None` when any part of the
/// `logins:` list cannot be read. Reads only each item's `name:` and `url:`
/// keys at the item's own indent; every other key (tokens included) is
/// skipped unread.
///
/// A bare slug must be owned on every login host, so a login the guard drops
/// could turn a block into an allow. An item without a readable `name` and
/// `url`, a list written at column 0 under `logins:`, or a `logins:` with an
/// inline value other than `[]` makes the whole config unreadable, and an
/// unreadable config refuses the write.
fn parse_tea_logins(config: &str) -> Option<Vec<TeaLogin>> {
    let mut logins = Vec::new();
    let mut in_logins = false;
    let mut item_indent: Option<usize> = None;
    let mut current: Option<(Option<String>, Option<String>)> = None;
    let mut unreadable = false;
    // A layout the guard does not follow; kept apart from `unreadable`,
    // which the item closure below holds.
    let mut bad_shape = false;
    let mut flush = |current: &mut Option<(Option<String>, Option<String>)>| {
        let Some(item) = current.take() else {
            return;
        };
        match item {
            (Some(name), Some(url)) if url_host(&url).is_some() => logins.push(TeaLogin {
                name,
                host: url_host(&url).unwrap_or_default(),
            }),
            _ => unreadable = true,
        }
    };
    for line in config.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            // YAML allows a block list at the key's own column.
            if in_logins && trimmed.starts_with('-') {
                bad_shape = true;
                continue;
            }
            flush(&mut current);
            item_indent = None;
            in_logins = false;
            if let Some(value) = trimmed.strip_prefix("logins:") {
                let value = value.split('#').next().unwrap_or("").trim();
                match value {
                    "" => in_logins = true,
                    "[]" => {}
                    _ => bad_shape = true,
                }
            }
            continue;
        }
        if !in_logins {
            continue;
        }
        let (key_indent, key_line) = if let Some(after) = trimmed.strip_prefix("- ") {
            flush(&mut current);
            current = Some((None, None));
            let after_trimmed = after.trim_start();
            let at = indent + 2 + (after.len() - after_trimmed.len());
            item_indent = Some(at);
            (at, after_trimmed)
        } else if trimmed == "-" || trimmed.starts_with("-\t") {
            // An item whose keys start on the next line: not tea's own layout.
            bad_shape = true;
            continue;
        } else {
            (indent, trimmed)
        };
        if item_indent != Some(key_indent) {
            continue;
        }
        let Some((key, value)) = key_line.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        let Some(item) = current.as_mut() else {
            continue;
        };
        match key.trim() {
            "name" => item.0 = Some(value.to_string()),
            "url" => item.1 = Some(value.to_string()),
            _ => {}
        }
    }
    flush(&mut current);
    drop(flush);
    (!unreadable && !bad_shape).then_some(logins)
}

/// What the guard could read of tea's config.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TeaConfig {
    /// No config file: tea has no saved login.
    Absent,
    Logins(Vec<TeaLogin>),
    /// A config the guard could not read in full; the write is refused.
    Unreadable,
}

/// Where tea 0.16 looks for its config, in order: adrg/xdg's
/// `ConfigFile("tea/config.yml")` (`$XDG_CONFIG_HOME`, else
/// `~/Library/Application Support` on macOS and `~/.config` elsewhere), then
/// the legacy `~/.tea/tea.yml`.
fn tea_config_candidates(
    home: Option<&Path>,
    xdg_config_home: Option<&Path>,
    macos: bool,
) -> Vec<PathBuf> {
    let config_home = xdg_config_home.map(Path::to_path_buf).or_else(|| {
        home.map(|h| {
            if macos {
                h.join("Library").join("Application Support")
            } else {
                h.join(".config")
            }
        })
    });
    config_home
        .map(|c| c.join("tea").join("config.yml"))
        .into_iter()
        .chain(home.map(|h| h.join(".tea").join("tea.yml")))
        .collect()
}

#[cfg(test)]
thread_local! {
    /// The config home tests point tea's lookup at. Tests never change `HOME`
    /// or `XDG_CONFIG_HOME`: other tests read them on other threads to place
    /// their fixtures.
    static TEST_TEA_CONFIG_HOME: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// tea's config file, if one exists.
fn tea_config_path() -> Option<PathBuf> {
    #[cfg(test)]
    {
        TEST_TEA_CONFIG_HOME
            .with(|d| d.borrow().clone())
            .map(|d| d.join("tea").join("config.yml"))
            .filter(|p| p.is_file())
    }
    #[cfg(not(test))]
    {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let (home, xdg) = (var("HOME"), var("XDG_CONFIG_HOME"));
        tea_config_candidates(home.as_deref(), xdg.as_deref(), cfg!(target_os = "macos"))
            .into_iter()
            .find(|p| p.is_file())
    }
}

/// tea's config as far as the guard can read it.
fn load_tea_logins() -> TeaConfig {
    use std::io::Read;
    /// A tea config is a few hundred bytes per login; past this it is not one.
    const MAX_CONFIG_BYTES: u64 = 1 << 20;
    let Some(path) = tea_config_path() else {
        return TeaConfig::Absent;
    };
    let mut text = String::new();
    let read = std::fs::File::open(&path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text));
    // A truncated config could drop a login, so a config over the cap is unread.
    if read.is_err() || text.len() as u64 > MAX_CONFIG_BYTES {
        return TeaConfig::Unreadable;
    }
    // A config tea wrote with no login holds nothing worth reading, but one
    // that has content and yields no login is a layout this reader does not
    // follow (`logins :`, JSON, a BOM, an indented root), so it is refused.
    let blank = text
        .lines()
        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'));
    match parse_tea_logins(&text) {
        Some(logins) if !logins.is_empty() => TeaConfig::Logins(logins),
        Some(_) if blank => TeaConfig::Absent,
        _ => TeaConfig::Unreadable,
    }
}

/// The hosts tea may send a bare `owner/repo` to. A literal `--login` picks
/// that login (tea matches the name ignoring case); otherwise every saved
/// login, plus the `GITEA_INSTANCE_URL` host when one is set, which tea
/// prefers unless `--login` is given. An unreadable config, or a literal
/// `--login` naming no readable login, is `Err` with the fix to show. An
/// empty list means no login host is known.
fn tea_slug_hosts(
    flags: &TeaFlags,
    env_instance: Option<&str>,
    config: &TeaConfig,
) -> Result<Vec<String>, &'static str> {
    let logins: &[TeaLogin] = match config {
        TeaConfig::Unreadable => return Err(TEA_CONFIG_UNREADABLE),
        TeaConfig::Absent => &[],
        TeaConfig::Logins(logins) => logins,
    };
    let mut hosts: Vec<String> = match flags.login.as_deref() {
        Some(name) if !name.contains(['$', '`']) => {
            let picked: Vec<String> = logins
                .iter()
                .filter(|l| l.name.eq_ignore_ascii_case(name))
                .map(|l| l.host.clone())
                .collect();
            if picked.is_empty() {
                return Err(TEA_LOGIN_UNKNOWN);
            }
            picked
        }
        _ => {
            let mut all: Vec<String> = logins.iter().map(|l| l.host.clone()).collect();
            all.extend(env_instance.and_then(url_host));
            all
        }
    };
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

/// The words from the command that runs, once the prefixes and command runners
/// in front of it are peeled: `timeout 5 tea …`, `nice -n 5 glab …`,
/// `stdbuf -o0 tea …`, `xargs tea …` and `sudo -u me glab …` all run the forge
/// CLI. Only transparent prefixes were peeled before, so every runner hid the
/// write from this guard (cameronsjo/cadence-hooks#1262).
///
/// **A runner the peel cannot parse does not hide the write.** When the peel
/// stops on a runner or prefix (an option it does not model), the first
/// `tea`/`glab` word behind it is taken as the command, so the write is still
/// judged rather than skipped as a read.
fn forge_argv(tokens: &[String]) -> &[String] {
    let rest = peel_command_runners(tokens);
    let stuck = rest.first().is_some_and(|w| {
        COMMAND_RUNNERS.contains(&command_word(w).as_ref()) || names_transparent_prefix(w)
    });
    if !stuck {
        return rest;
    }
    // Only the words a runner can take before its command: options, other
    // runners and prefixes, assignments, and a number or duration
    // (`timeout --x 5`). The first other word is the command, so a `tea`
    // later in its arguments (`echo tea pr create …`) is not one.
    for (at, word) in rest.iter().enumerate() {
        let verb = command_word(word);
        if matches!(verb.as_ref(), "tea" | "glab") {
            return &rest[at..];
        }
        let runner_word = word.starts_with('-')
            || COMMAND_RUNNERS.contains(&verb.as_ref())
            || names_transparent_prefix(word)
            || is_assignment_word(word)
            || (word.starts_with(|c: char| c.is_ascii_digit())
                && word
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '.' | 's' | 'm' | 'h' | 'd')));
        if !runner_word {
            break;
        }
    }
    rest
}

/// The forge write in one segment, or `None` for anything else (reads
/// included). Pure apart from reading `GITLAB_HOST` for `glab`.
fn forge_write(segment: &str) -> Option<ForgeWrite> {
    let tokens = executable_tokens(strip_group_wrappers(segment));
    let rest = forge_argv(&tokens);
    let prefix_len = tokens.len() - rest.len();
    let head = rest.first()?;
    let forge = match command_word(head).as_ref() {
        "glab" => Forge::Glab,
        "tea" => Forge::Tea,
        _ => return None,
    };
    let args = &rest[1..];
    let pos = if forge == Forge::Tea {
        tea_positionals(args)
    } else {
        positionals(args)
    };
    let noun = *pos.first()?;
    let table = if forge == Forge::Glab {
        GLAB_WRITES
    } else {
        TEA_WRITES
    };
    let verb = pos.get(1).copied().unwrap_or("");
    let is_write = table.iter().any(|(nouns, verbs)| {
        nouns.contains(&noun) && (verbs.contains(&"*") || verbs.contains(&verb))
    });
    if !is_write {
        return None;
    }
    // Host override: an inline assignment, then `--hostname`, then the process.
    let inline_host = tokens[..prefix_len]
        .iter()
        .rev()
        .find_map(|t| {
            t.strip_prefix("GITLAB_HOST=")
                .or(t.strip_prefix("GL_HOST="))
        })
        .map(str::to_string);
    let host = if forge == Forge::Glab {
        inline_host
            .or_else(|| flag_value(args, &["--hostname"]))
            .or_else(|| std::env::var("GITLAB_HOST").ok().filter(|h| !h.is_empty()))
            .map(|h| {
                h.trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string()
            })
    } else {
        None
    };
    let host = host.as_deref();
    let after_verb = &pos[pos.len().min(2)..];
    if forge == Forge::Tea {
        return Some(tea_write(segment, args, &tokens[..prefix_len], after_verb));
    }
    let target = flag_value(args, &["-R", "-r", "--repo"])
        .and_then(|v| parse_target(&v, host))
        .or_else(|| {
            let owner = flag_value(args, &["--owner", "--group", "-g"])?;
            let name = flag_value(args, &["--name"])
                .or_else(|| after_verb.first().map(|s| s.to_string()))?;
            parse_target(&format!("{owner}/{name}"), host)
        })
        .or_else(|| {
            // `glab repo delete owner/repo`, `glab repo create owner/name`.
            if noun.starts_with("repo") || noun == "r" {
                parse_target(after_verb.first()?, host)
            } else {
                None
            }
        });
    Some(ForgeWrite {
        forge,
        text: segment.trim().to_string(),
        target,
        tea: TeaFlags::default(),
    })
}

/// A `tea` write: the `--repo` slug (or `repos … --owner o --name n`), and the
/// flags that pick tea's login and remote. `-R` is `--remote` to tea, never a
/// repo.
fn tea_write(segment: &str, args: &[String], prefix: &[String], after_verb: &[&str]) -> ForgeWrite {
    let repo_flag = tea_flag(args, TEA_REPO);
    let owner_flag = tea_flag(args, TEA_OWNER);
    let repo_given = repo_flag.is_some() || owner_flag.is_some();
    let repo_value = repo_flag.clone();
    let dir_scoped = !matches!(args_noun(args), Some("repos" | "repo" | "r"));
    let target = repo_flag.and_then(|v| parse_tea_slug(&v)).or_else(|| {
        let owner = owner_flag?;
        let name =
            tea_flag(args, TEA_NAME).or_else(|| after_verb.first().map(|s| s.to_string()))?;
        parse_tea_slug(&format!("{owner}/{name}"))
    });
    let env_override = prefix
        .iter()
        .filter(|t| is_assignment_word(t))
        .find(|t| {
            let name = t.split('=').next().unwrap_or("");
            matches!(name, "HOME" | "XDG_CONFIG_HOME") || name.starts_with("GITEA_")
        })
        .cloned();
    ForgeWrite {
        forge: Forge::Tea,
        text: segment.trim().to_string(),
        target,
        tea: TeaFlags {
            login: tea_flag(args, TEA_LOGIN),
            remote: tea_flag(args, TEA_REMOTE),
            env_override,
            repo_given,
            repo_value,
            dir_scoped,
            unknown_target_flag: tea_unknown_target_flag(args),
        },
    }
}

/// The tea noun: the first positional.
fn args_noun(args: &[String]) -> Option<&str> {
    tea_positionals(args).first().copied()
}

/// The repos a tea write with no `--repo` reaches: the remotes of the git repo
/// at `dir` (only `remote` when `--remote` names one). `Ok(None)` when the
/// directory or any remote cannot be read; `Err` when git timed out.
fn tea_remote_targets(dir: &str, remote: Option<&str>) -> Result<Option<Vec<Target>>, ()> {
    if dir == UNRESOLVABLE_DIR || remote.is_some_and(|r| r.contains(['$', '`'])) {
        return Ok(None);
    }
    let listing = match git_command_detailed(dir, &["config", "--get-regexp", r"^remote\..*\.url$"])
    {
        GitQuery::Value(v) => v,
        GitQuery::Failed => return Ok(None),
        GitQuery::TimedOut => return Err(()),
    };
    Ok(remote_targets(&listing, remote))
}

/// The number of `/` parts in a remote URL's path, `.git` and edge slashes
/// trimmed (`https://h/a/b.git` → 2, `git@h:a/b` → 2, `https://h/x/a/b` → 3).
fn remote_path_parts(url: &str) -> Option<usize> {
    let path = match url.split_once("://") {
        Some((_, rest)) => rest.split_once('/')?.1,
        None => url.split_once(':')?.1,
    };
    let path = path.trim_matches('/').trim_end_matches(".git");
    Some(path.split('/').count())
}

/// [`tea_remote_targets`]'s pure half: `remote.<name>.url <url>` lines to
/// targets. Any URL it cannot read, or no remote at all, is `None`.
fn remote_targets(listing: &str, remote: Option<&str>) -> Option<Vec<Target>> {
    let mut targets = Vec::new();
    for line in listing.lines() {
        let (key, url) = line.split_once(char::is_whitespace)?;
        let name = key.strip_prefix("remote.")?.strip_suffix(".url")?;
        if remote.is_some_and(|r| r != name) {
            continue;
        }
        // tea reads an https remote's last two path parts and an scp/ssh
        // remote's whole path, so only a two-part path reads the same both ways.
        if remote_path_parts(url.trim())? != 2 {
            return None;
        }
        let (host, path) = host_and_repo_from_url(url.trim())?;
        let (owner, repo) = path.split_once('/')?;
        targets.push(Target {
            host: Some(host),
            owner: owner.to_string(),
            repo: repo.to_string(),
        });
    }
    (!targets.is_empty()).then_some(targets)
}

/// Whether `target` is covered by the allowlists (see the module docs for the
/// host rule). `tea_hosts` are the hosts a bare tea slug may go to; the slug
/// is owned when it is owned on every one of them. The list is empty only when
/// tea's config is missing, empty or comment-only and no `GITEA_INSTANCE_URL`
/// is set; then a `CADENCE_EXTRA_HOSTS` host decides. An unreadable config never
/// reaches here: [`tea_slug_hosts`] refuses it first.
fn owned(forge: &Forge, target: &Target, lists: &Allowlists, tea_hosts: &[String]) -> bool {
    let check = |host: &str| {
        is_allowed_with_extra_hosts(
            host,
            &target.owner,
            &target.repo,
            &lists.owners,
            &lists.repos,
            &lists.extra_hosts,
        )
    };
    match (&target.host, forge) {
        (Some(host), _) => check(host),
        (None, Forge::Glab) => check("gitlab.com") || lists.extra_hosts.iter().any(|h| check(h)),
        // The login hosts are where tea sends the slug, so once any is known
        // only they decide; CADENCE_EXTRA_HOSTS is the fallback only when
        // tea's config is missing, empty or comment-only.
        (None, Forge::Tea) if !tea_hosts.is_empty() => tea_hosts.iter().all(|h| check(h)),
        (None, Forge::Tea) => lists.extra_hosts.iter().any(|h| check(h)),
    }
}

/// The operator's allowlists, read once per run.
struct Allowlists {
    owners: Vec<AllowEntry>,
    repos: Vec<AllowEntry>,
    extra_hosts: Vec<String>,
}

/// What one forge write resolved to.
enum Verdict {
    Owned,
    /// No target could be read; the fix to name.
    Unresolvable(&'static str),
    /// A target outside the allowlists, as the message names it, and whether
    /// it came from a tea `--repo` slug (which the slug note explains).
    Unowned(String, bool),
    /// Git timed out reading the remotes: the guard's own failure, so allow.
    TimedOut,
}

const GLAB_UNREADABLE: &str = "name the target literally with `-R owner/repo`";
const TEA_NO_CWD: &str = "name the repo literally with `--repo owner/repo` (tea's `-R` is \
    `--remote`, a git remote name). The hook payload named no working directory, so the \
    directory tea runs in could not be read";
const TEA_REPO_UNREADABLE: &str = "tea uses the `--repo`/`--owner` value it is given, and the \
    guard could not read it as a literal `owner/repo` (a variable, a path, a URL or a one-part \
    name). Name the repo literally with `--repo owner/repo`";
const TEA_REPO_IS_DIR: &str = "the `--repo` value is also a directory here, and tea then uses \
    that directory's git remotes. Name the repo with a literal `--repo owner/repo` that is not \
    a local path";
const TEA_REPOS_NO_OWNER: &str = "`tea repos create|delete` without `--owner` acts under the \
    tea login's user. Name the repo with `--owner <owner> --name <repo>`";
const TEA_REMOTES_UNREADABLE: &str = "with no `--repo`, tea writes to the repo of the directory \
    it runs in. The guard read that directory (the session's working directory, plus literal \
    `cd`s and `env -C`) and found no git remote it could read, or none named by `--remote`. \
    Name the repo literally with `--repo owner/repo` (tea's `-R` is `--remote`, a git remote name)";
const TEA_INSTANCE_ELSEWHERE: &str = "the command assigns `GITEA_INSTANCE_URL`, which can move \
    the login tea writes with, and the guard reads only its own environment. Run tea without \
    it, or pick the login with `--login`";
const TEA_ENV_INLINE: &str = "an assignment in front of `tea` sets `HOME`, `XDG_CONFIG_HOME` \
    or a `GITEA_*` variable, which moves the config or login tea uses, and the guard reads only \
    its own environment. Run tea without it, or pick the login with `--login`";

const TEA_CONFIG_UNREADABLE: &str = "tea's config has a login the guard cannot read (an \
    entry without a plain `name:` and `url:`, a list at the `logins:` key's own column, or a \
    file over 1 MiB), so it cannot tell which host tea writes to. Rewrite the config with \
    `tea login` or name the repo on an owned login with `--login`";
const TEA_LOGIN_UNKNOWN: &str = "the `--login` value names no login in tea's config";
const TEA_FLAG_UNREAD: &str = "a flag in the command could name the repo, login, remote or \
    owner in a spelling the guard does not read. Spell it `--repo`, `--login`, `--remote` or \
    `--owner`";

fn describe(t: &Target) -> String {
    format!(
        "{}{}/{}",
        t.host
            .as_deref()
            .map(|h| format!("{h}/"))
            .unwrap_or_default(),
        t.owner,
        t.repo
    )
}

/// Whether a tea write reads its repo from the directory it runs in.
fn needs_dir(write: &ForgeWrite) -> bool {
    write.target.is_none() && !write.tea.repo_given && write.tea.dir_scoped
}

/// Judge one tea write. `dirs` are the directories the segment may run in
/// (empty when the payload names no `cwd`); `logins` is read on first need.
/// `instance_elsewhere` says the command sets `GITEA_INSTANCE_URL` somewhere
/// other than this segment's own prefix (an earlier `export`), which may
/// change tea's login in a way the guard does not read.
fn judge_tea(
    write: &ForgeWrite,
    dirs: &[String],
    lists: &Allowlists,
    logins: &mut Option<TeaConfig>,
    instance_elsewhere: bool,
) -> Verdict {
    if write.tea.unknown_target_flag.is_some() {
        return Verdict::Unresolvable(TEA_FLAG_UNREAD);
    }
    if write.tea.env_override.is_some() {
        return Verdict::Unresolvable(TEA_ENV_INLINE);
    }
    if instance_elsewhere {
        return Verdict::Unresolvable(TEA_INSTANCE_ELSEWHERE);
    }
    let env_instance = std::env::var("GITEA_INSTANCE_URL")
        .ok()
        .filter(|u| !u.is_empty());
    let mut slug_hosts = || {
        let logins = logins.get_or_insert_with(load_tea_logins);
        tea_slug_hosts(&write.tea, env_instance.as_deref(), logins)
    };
    if let Some(t) = &write.target {
        // tea opens a `--repo` that names an existing directory as a local repo.
        let names_dir = write.tea.repo_value.as_deref().is_some_and(|v| {
            dirs.iter()
                .any(|d| d != UNRESOLVABLE_DIR && Path::new(d).join(v).is_dir())
        });
        if names_dir {
            return Verdict::Unresolvable(TEA_REPO_IS_DIR);
        }
        let hosts = match slug_hosts() {
            Ok(hosts) => hosts,
            Err(fix) => return Verdict::Unresolvable(fix),
        };
        if owned(&Forge::Tea, t, lists, &hosts) {
            return Verdict::Owned;
        }
        let on = if hosts.is_empty() {
            "no tea login host found".to_string()
        } else {
            hosts.join(", ")
        };
        return Verdict::Unowned(format!("{} (tea login host: {on})", describe(t)), true);
    }
    // tea uses a given `--repo`/`--owner` and never the directory's repo, so
    // one the guard could not read is not judged on the directory.
    if write.tea.repo_given {
        return Verdict::Unresolvable(TEA_REPO_UNREADABLE);
    }
    if !write.tea.dir_scoped {
        return Verdict::Unresolvable(TEA_REPOS_NO_OWNER);
    }
    if dirs.is_empty() {
        return Verdict::Unresolvable(TEA_NO_CWD);
    }
    // tea takes owner/repo from the remote, but `--login` or an env login
    // replaces the host it sends the write to. Then the remote's owner/repo is
    // judged as a bare slug on those login hosts, as a `--repo` slug is.
    let login_moved = write.tea.login.is_some() || env_instance.is_some();
    let hosts = if login_moved {
        match slug_hosts() {
            Ok(hosts) => hosts,
            Err(fix) => return Verdict::Unresolvable(fix),
        }
    } else {
        Vec::new()
    };
    for dir in dirs {
        let targets = match tea_remote_targets(dir, write.tea.remote.as_deref()) {
            Ok(Some(targets)) => targets,
            Ok(None) => return Verdict::Unresolvable(TEA_REMOTES_UNREADABLE),
            Err(()) => return Verdict::TimedOut,
        };
        for t in targets {
            let judged = if login_moved {
                Target { host: None, ..t }
            } else {
                t
            };
            if !owned(&Forge::Tea, &judged, lists, &hosts) {
                return Verdict::Unowned(
                    format!("{} (a git remote of {dir})", describe(&judged)),
                    false,
                );
            }
        }
    }
    Verdict::Owned
}

/// The block for one judged write, or `None` to keep going.
fn block_for(
    write: &ForgeWrite,
    verdict: Verdict,
    allowed: &str,
    display: &[String],
) -> Option<CheckResult> {
    let cli = if write.forge == Forge::Glab {
        "glab"
    } else {
        "tea"
    };
    let (rule_id, found, fix, with_note) = match verdict {
        Verdict::Owned => return None,
        Verdict::TimedOut => {
            cadence_hooks_core::deadline::note_suppressed_block();
            return None;
        }
        Verdict::Unresolvable(fix) => (
            "forge-write-target-unresolvable",
            format!("{cli} write with no readable target: {}", write.text),
            fix,
            write.forge == Forge::Glab,
        ),
        Verdict::Unowned(target, slug) => (
            "forge-write-unauthorized-target",
            format!("{cli} write targets {target}"),
            "target an owned repo, or ask the user",
            write.forge == Forge::Glab || slug,
        ),
    };
    let note = match (with_note, &write.forge) {
        (false, _) => "",
        (true, Forge::Glab) => {
            " Bare `owner/repo` matches only hosts in CADENCE_EXTRA_HOSTS; \
             qualify an entry as `host/owner` for another host."
        }
        (true, Forge::Tea) => {
            " tea reads `--repo owner/repo` on its login's host and keeps only the first two \
             parts, so `--repo host/owner/repo` names owner `host`. A bare slug is checked on \
             every tea login host in tea's config (or the `--login` one) and on \
             CADENCE_EXTRA_HOSTS; qualify an allowlist entry as `host/owner`."
        }
    };
    Some(CheckResult::block_structured(
        format!(
            "🚫 git-guardrails: {cli} write targets a repo you don't own (or none is readable)\n   \
             Found: {found}\n   \
             Allowed: {allowed}\n   \
             Fix: {fix}.{note}\n   \
             DO NOT override with env vars."
        ),
        BlockMetadata {
            rule_id: rule_id.to_string(),
            fix: fix.to_string(),
            allowed_owners: display.to_vec(),
            severity: "error",
        },
    ))
}

/// Block `tea`/`glab` writes to repos outside the owner allowlist.
pub struct ForgeWriteGuard;

impl Check for ForgeWriteGuard {
    fn name(&self) -> &str {
        "guard-forge-write"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let lower = command.to_ascii_lowercase();
        if !lower.contains("glab") && !lower.contains("tea") {
            return CheckResult::allow();
        }
        let lists = Allowlists {
            owners: env_allow_entries("CADENCE_ALLOWED_OWNERS"),
            repos: env_allow_entries("CADENCE_ALLOWED_REPOS"),
            extra_hosts: env_extra_hosts(),
        };
        let display: Vec<String> = lists
            .owners
            .iter()
            .chain(lists.repos.iter())
            .map(|e| e.to_string())
            .collect();
        let allowed = if display.is_empty() {
            "(none configured)".to_string()
        } else {
            display.join(" ")
        };
        let cwd = input.cwd.as_deref();
        // Only an assignment can change tea's login; a mention cannot.
        let instance_elsewhere = command.contains("GITEA_INSTANCE_URL=");
        let mut logins: Option<TeaConfig> = None;
        // The directory walk runs only once a tea write is found.
        let mut whole_dir: Option<Option<String>> = None;
        let mut any_needs_dir = false;

        // Reading 1: the whole command's segments, which carry an assignment
        // into later segments (`R=o/r; glab mr create -R $R`), in the
        // directory the whole-command scan reads.
        for segment in command_segments(command) {
            let Some(write) = forge_write(&segment) else {
                continue;
            };
            let verdict = match write.forge {
                Forge::Glab => match &write.target {
                    None => Verdict::Unresolvable(GLAB_UNREADABLE),
                    Some(t) if owned(&Forge::Glab, t, &lists, &[]) => Verdict::Owned,
                    Some(t) => Verdict::Unowned(describe(t), false),
                },
                Forge::Tea => {
                    let mut dirs: Vec<String> = whole_dir
                        .get_or_insert_with(|| cwd.map(|c| parse_work_dir(command, c)))
                        .as_deref()
                        .map(|d| vec![dir_after_runners(&segment, d)])
                        .unwrap_or_default();
                    // A `--repo` is checked for being a local directory in
                    // every directory a segment of the command may run in:
                    // segments do not line up across the two readings.
                    if let (Some(_), Some(cwd)) = (&write.tea.repo_value, cwd) {
                        for (_, d) in command_segments_with_dirs(command, cwd) {
                            let d = d.to_string();
                            if !dirs.contains(&d) {
                                dirs.push(d);
                            }
                        }
                    }
                    any_needs_dir |= needs_dir(&write);
                    judge_tea(&write, &dirs, &lists, &mut logins, instance_elsewhere)
                }
            };
            if let Some(block) = block_for(&write, verdict, &allowed, &display) {
                return block;
            }
        }

        // Reading 2: each segment in the directory it runs in, which follows a
        // `cd` the whole-command scan misses. Only tea writes that read their
        // repo from the directory depend on it; the rest were judged above.
        if let (true, Some(cwd)) = (any_needs_dir, cwd) {
            for (segment, segment_dir) in command_segments_with_dirs(command, cwd) {
                let Some(write) = forge_write(&segment) else {
                    continue;
                };
                if write.forge != Forge::Tea || !needs_dir(&write) {
                    continue;
                }
                let dirs = vec![dir_after_runners(&segment, &segment_dir)];
                let verdict = judge_tea(&write, &dirs, &lists, &mut logins, instance_elsewhere);
                if let Some(block) = block_for(&write, verdict, &allowed, &display) {
                    return block;
                }
            }
        }
        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_env;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    const ENV: &[(&str, Option<&str>)] = &[
        (
            "CADENCE_ALLOWED_OWNERS",
            Some("cameronsjo,git.sjo.lol/cameron"),
        ),
        ("CADENCE_ALLOWED_REPOS", None),
        ("CADENCE_EXTRA_HOSTS", Some("git.sjo.lol")),
        ("GITLAB_HOST", None),
        ("CADENCE_DISABLE", None),
        ("GITEA_INSTANCE_URL", None),
    ];

    /// Runs `f` with tea's config looked up under `dir` (`<dir>/tea/config.yml`),
    /// or with no tea config for `None`. Outside this, tests see no tea config.
    fn with_tea_home<T>(dir: Option<&Path>, f: impl FnOnce() -> T) -> T {
        TEST_TEA_CONFIG_HOME.with(|d| *d.borrow_mut() = dir.map(Path::to_path_buf));
        let out = f();
        TEST_TEA_CONFIG_HOME.with(|d| *d.borrow_mut() = None);
        out
    }

    fn outcome(command: &str) -> Outcome {
        let mut got = Outcome::Allow;
        with_env(ENV, || {
            got = ForgeWriteGuard.run(&make_bash(command)).outcome
        });
        got
    }

    #[test]
    fn writes_to_an_unowned_or_unknown_target_block() {
        for cmd in [
            "glab mr create -R evil/repo --title x",
            "glab mr merge 3 --repo evil/repo",
            "glab mr note 3 -R evil/repo -m hi",
            "glab mr close 3 -R evil/repo",
            "glab issue create -R evil/repo -t x",
            "glab issue note 2 -R evil/repo -m x",
            "glab issue close 2 -R evil/repo",
            "glab repo delete evil/repo --yes",
            "glab repo create evil/new",
            "glab repo create new --group evil",
            "tea pulls create -r evil/repo --title x",
            "tea pr merge 3 -r evil/repo",
            "tea issues close 2 --repo evil/repo",
            "tea issue create -r evil/repo -t x",
            "tea comment 3 hi -r evil/repo",
            "tea repos create --name x --owner evil",
            "tea repos delete --name x --owner evil",
            // Unknown target: no -R, nothing to read.
            "glab mr create --title x",
            "tea pulls create --title x",
            "tea comment 3 hi",
            "glab repo create newrepo",
            // Target the shell computes is not a target read.
            "glab mr create -R \"$T\" --title x",
            "glab mr create -R $(echo evil/repo)",
            // Host qualified to a host the allowlist does not name.
            "glab mr create -R https://gitlab.evil.com/cameron/x",
            "glab mr create -R cameronsjo/x --hostname gitlab.evil.com",
            "GITLAB_HOST=gitlab.evil.com glab mr create -R cameronsjo/x",
            // Wrapped and chained.
            "sh -c 'glab mr create -R evil/repo'",
            "glab mr list -R cameronsjo/x && glab mr create -R evil/repo",
            "env FOO=1 tea pulls create -r evil/repo",
        ] {
            assert_eq!(outcome(cmd), Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn writes_to_an_owned_target_and_all_reads_allow() {
        for cmd in [
            // Owned via CADENCE_EXTRA_HOSTS / host-qualified entries.
            "tea pulls create -r cameronsjo/x --title x",
            "tea issues close 2 --repo cameron/x",
            "glab mr create -R cameronsjo/x --title x",
            "glab repo create cameron/new --hostname git.sjo.lol",
            "glab mr create -R https://git.sjo.lol/cameron/x",
            "tea repos create --name x --owner cameron",
            // Reads, whatever the target.
            "glab mr list -R evil/repo",
            "glab mr view 3 -R evil/repo",
            "glab issue list",
            "glab repo view evil/repo",
            "glab auth status",
            "tea pulls list -r evil/repo",
            "tea issues -r evil/repo",
            "tea repos search foo",
            // Not the forge CLIs.
            "echo glab mr create -R evil/repo",
            "gh pr create",
            "ls -la tea",
        ] {
            assert_eq!(outcome(cmd), Outcome::Allow, "{cmd}");
        }
    }

    /// Every command runner and prefix in front of a forge write, against an
    /// unowned and an owned target (cameronsjo/cadence-hooks#1262): the runner
    /// runs the CLI, so the target decides, never the wrapper.
    #[test]
    fn a_runner_in_front_of_a_write_is_peeled_before_the_target_is_judged() {
        let wrappers = [
            "timeout 5",
            "timeout -s KILL 5",
            "timeout --kill-after=2 5",
            "nice",
            "nice -n 5",
            "nice -5",
            "nohup",
            "nohup --",
            "stdbuf -o0",
            "stdbuf -oL -eL",
            "xargs",
            "xargs -0",
            "sudo",
            "sudo -u me",
            "setsid",
            "env",
            "env -i",
            "command",
            "exec",
            "time",
            "/usr/bin/timeout 5",
            "timeout 5 nice -n 1",
            // A runner option the peel does not model: the write is still found.
            "timeout --frobnicate 5",
            "nice --frobnicate",
        ];
        for wrapper in wrappers {
            for (write, owned) in [
                ("tea pr create --repo evil/r", false),
                ("glab mr create -R evil/r --title x", false),
                ("tea pr create --repo cameronsjo/r", true),
                ("glab mr create -R cameronsjo/r --title x", true),
            ] {
                let cmd = format!("{wrapper} {write}");
                let want = if owned {
                    Outcome::Allow
                } else {
                    Outcome::Block
                };
                assert_eq!(outcome(&cmd), want, "{cmd}");
            }
            // A `tea` among the arguments of the command a runner runs is
            // not the command.
            let echoed = format!("{wrapper} echo tea pr create --repo evil/r");
            assert_eq!(outcome(&echoed), Outcome::Allow, "{echoed}");
            // A read behind the same runner stays a read.
            let read = format!("{wrapper} glab mr list -R evil/r");
            assert_eq!(outcome(&read), Outcome::Allow, "{read}");
        }
    }

    #[test]
    fn an_unconfigured_allowlist_blocks_every_write() {
        let vars: &[(&str, Option<&str>)] = &[
            ("CADENCE_ALLOWED_OWNERS", None),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("GITLAB_HOST", None),
        ];
        with_env(vars, || {
            let r = ForgeWriteGuard.run(&make_bash("glab mr create -R me/x"));
            assert_eq!(r.outcome, Outcome::Block);
            assert!(r.message.unwrap().contains("(none configured)"));
            let r = ForgeWriteGuard.run(&make_bash("glab mr list -R me/x"));
            assert_eq!(r.outcome, Outcome::Allow);
        });
    }

    #[test]
    fn the_block_message_names_found_allowed_and_fix() {
        with_env(ENV, || {
            let r = ForgeWriteGuard.run(&make_bash("glab mr create -R evil/repo"));
            let msg = r.message.unwrap();
            assert!(msg.contains("Found:") && msg.contains("evil/repo"), "{msg}");
            assert!(
                msg.contains("Allowed:") && msg.contains("cameronsjo"),
                "{msg}"
            );
            assert!(msg.contains("Fix:"), "{msg}");
            assert_eq!(
                r.block_metadata.unwrap().rule_id,
                "forge-write-unauthorized-target"
            );
        });
    }

    // --- tea, read the way tea 0.16 reads itself (cameronsjo/cadence-hooks#1601) ---

    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use cadence_hooks_core::test_builders::make_bash_with_cwd;
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> Scratch {
        Scratch::outside_checkout(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("forge-write-scratch"),
            tag,
        )
    }

    /// A tea config holding one login per `(name, url)`, with a token line so
    /// the parser is shown to skip it.
    fn tea_config(dir: &Path, logins: &[(&str, &str)]) -> PathBuf {
        let tea = dir.join("tea");
        std::fs::create_dir_all(&tea).unwrap();
        let mut text = String::from("logins:\n");
        for (name, url) in logins {
            text.push_str(&format!(
                "    - name: {name}\n      url: {url}\n      token: not-a-host\n      default: false\n      user: cameron\n"
            ));
        }
        text.push_str("preferences:\n    editor: false\n");
        std::fs::write(tea.join("config.yml"), text).unwrap();
        dir.to_path_buf()
    }

    /// The live allowlist shape from the report: `git.sjo.lol/cameron` owned,
    /// no CADENCE_EXTRA_HOSTS.
    fn run_tea(command: &str, cwd: Option<&Path>, config_home: &Path) -> CheckResult {
        let vars: &[(&str, Option<&str>)] = &[
            (
                "CADENCE_ALLOWED_OWNERS",
                Some("cameronsjo,git.sjo.lol/cameron"),
            ),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("CADENCE_DISABLE", None),
            ("GITEA_INSTANCE_URL", None),
        ];
        let input = match cwd {
            Some(dir) => make_bash_with_cwd(command, dir.to_str().unwrap()),
            None => make_bash(command),
        };
        with_tea_home(Some(config_home), || {
            with_env(vars, || ForgeWriteGuard.run(&input))
        })
    }

    fn sjo_config(tag: &str) -> Scratch {
        let s = scratch(tag);
        tea_config(s.path(), &[("sjo", "https://git.sjo.lol")]);
        s
    }

    /// Case 2 of #1601: a bare `--repo owner/repo` goes to the tea login's
    /// host, so it is owned when `host/owner` is.
    #[test]
    fn a_bare_tea_slug_is_judged_on_the_tea_login_host() {
        let cfg = sjo_config("tea-bare-slug");
        for cmd in [
            "tea pr create --repo cameron/lectern --title x",
            "tea pulls create -r cameron/lectern",
            "tea pr create --repo cameron/lectern --login sjo",
        ] {
            let r = run_tea(cmd, None, cfg.path());
            assert_eq!(r.outcome, Outcome::Allow, "{cmd}: {:?}", r.message);
        }
        // The same owner on a login host the allowlist does not name.
        let other = scratch("tea-bare-slug-other-host");
        tea_config(other.path(), &[("work", "https://gitea.example.com")]);
        let r = run_tea("tea pr create --repo cameron/lectern", None, other.path());
        assert_eq!(r.outcome, Outcome::Block);
        assert!(r.message.unwrap().contains("gitea.example.com"));
        // Two logins: the slug may go to either, so both must own it.
        let two = scratch("tea-bare-slug-two-logins");
        tea_config(
            two.path(),
            &[
                ("sjo", "https://git.sjo.lol"),
                ("work", "https://gitea.example.com"),
            ],
        );
        let r = run_tea("tea pr create --repo cameron/lectern", None, two.path());
        assert_eq!(r.outcome, Outcome::Block);
        // `--login` picks one, and only that host is judged.
        let r = run_tea(
            "tea pr create --repo cameron/lectern --login sjo",
            None,
            two.path(),
        );
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
        let r = run_tea(
            "tea pr create --repo cameron/lectern -l work",
            None,
            two.path(),
        );
        assert_eq!(r.outcome, Outcome::Block);
        // No tea config at all: no login host, so the slug is unowned.
        let none = scratch("tea-bare-slug-no-config");
        let r = run_tea("tea pr create --repo cameron/lectern", None, none.path());
        assert_eq!(r.outcome, Outcome::Block);
        assert!(r.message.unwrap().contains("no tea login host found"));
        // An inline instance URL is a login tea may use.
        let r = run_tea(
            "GITEA_INSTANCE_URL=https://gitea.example.com tea pr create --repo cameron/lectern",
            None,
            cfg.path(),
        );
        assert_eq!(r.outcome, Outcome::Block);
    }

    /// Case 3 of #1601: tea keeps the first two parts of a slug, so
    /// `host/owner/repo` names owner `host`, repo `owner`. It stays refused,
    /// and the message says why.
    #[test]
    fn a_host_qualified_tea_slug_names_the_host_as_owner_and_blocks() {
        let cfg = sjo_config("tea-qualified-slug");
        let r = run_tea(
            "tea pr create --repo git.sjo.lol/cameron/lectern",
            None,
            cfg.path(),
        );
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        assert!(
            msg.contains("tea write targets git.sjo.lol/cameron "),
            "{msg}"
        );
        assert!(
            msg.contains("`--repo host/owner/repo` names owner `host`"),
            "{msg}"
        );
        // A URL is not a slug to tea either.
        let r = run_tea(
            "tea pr create --repo https://git.sjo.lol/cameron/lectern",
            None,
            cfg.path(),
        );
        assert_eq!(r.outcome, Outcome::Block);
    }

    /// Case 1 of #1601: with no `--repo`, tea writes to the repo it runs in.
    /// The guard reads that directory's remotes, following a literal `cd`.
    #[test]
    fn a_tea_write_without_repo_is_judged_on_the_directory_remotes() {
        let cfg = sjo_config("tea-cwd-config");
        let root = scratch("tea-cwd-repos");
        let owned_repo = root.path().join("lectern");
        let unowned_repo = root.path().join("evil");
        let fork = root.path().join("fork");
        let plain = root.path().join("plain");
        for (dir, remotes) in [
            (
                &owned_repo,
                vec![("origin", "git@git.sjo.lol:cameron/lectern.git")],
            ),
            (
                &unowned_repo,
                vec![("origin", "https://git.sjo.lol/evil/repo.git")],
            ),
            (
                &fork,
                vec![
                    ("origin", "https://git.sjo.lol/cameron/lectern.git"),
                    ("upstream", "https://git.sjo.lol/evil/repo.git"),
                ],
            ),
        ] {
            std::fs::create_dir_all(dir).unwrap();
            init_repo(dir);
            for (name, url) in remotes {
                git_in(dir, &["remote", "add", name, url]);
            }
        }
        std::fs::create_dir_all(&plain).unwrap();

        let allow = |cmd: &str, cwd: &Path| {
            let r = run_tea(cmd, Some(cwd), cfg.path());
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "{cmd} in {cwd:?}: {:?}",
                r.message
            );
        };
        let block = |cmd: &str, cwd: &Path, rule: &str| {
            let r = run_tea(cmd, Some(cwd), cfg.path());
            assert_eq!(r.outcome, Outcome::Block, "{cmd} in {cwd:?}");
            assert_eq!(r.block_metadata.unwrap().rule_id, rule, "{cmd}");
        };
        allow("tea pr create --title x", &owned_repo);
        let cd = format!("cd '{}' && tea pr create --title x", owned_repo.display());
        allow(&cd, &plain);
        allow("tea pr create --title x -R origin", &fork);

        block(
            "tea pr create --title x",
            &unowned_repo,
            "forge-write-unauthorized-target",
        );
        // Either remote may be the one tea uses.
        block(
            "tea pr create --title x",
            &fork,
            "forge-write-unauthorized-target",
        );
        block(
            "tea pr create --title x -R upstream",
            &fork,
            "forge-write-unauthorized-target",
        );
        let cd = format!("cd '{}' && tea pr create --title x", unowned_repo.display());
        block(&cd, &owned_repo, "forge-write-unauthorized-target");
        // Not a repo, a remote that does not exist, or a `cd` the guard cannot read.
        block(
            "tea pr create --title x",
            &plain,
            "forge-write-target-unresolvable",
        );
        block(
            "tea pr create --title x -R nope",
            &owned_repo,
            "forge-write-target-unresolvable",
        );
        block(
            "cd \"$D\" && tea pr create --title x",
            &owned_repo,
            "forge-write-target-unresolvable",
        );
        // `-R` is tea's `--remote`, never a repo: an owner/repo there reads nothing.
        block(
            "tea pr create -R cameron/lectern --title x",
            &plain,
            "forge-write-target-unresolvable",
        );
    }

    #[test]
    fn the_tea_unresolvable_message_names_repo_not_dash_capital_r() {
        let none = scratch("tea-unresolvable-msg");
        let r = run_tea("tea pr create --title x", None, none.path());
        let msg = r.message.unwrap();
        assert!(msg.contains("`--repo owner/repo`"), "{msg}");
        assert!(msg.contains("tea's `-R` is `--remote`"), "{msg}");
    }

    #[test]
    fn tea_slugs_parse_as_tea_parses_them() {
        let t = |v: &str| parse_tea_slug(v).map(|t| (t.owner, t.repo));
        let pair = |o: &str, r: &str| Some((o.to_string(), r.to_string()));
        assert_eq!(t("cameron/lectern"), pair("cameron", "lectern"));
        assert_eq!(t("/cameron/lectern/"), pair("cameron", "lectern"));
        assert_eq!(
            t("git.sjo.lol/cameron/lectern"),
            pair("git.sjo.lol", "cameron")
        );
        for bad in ["lectern", "", "https://h/o/r", "./x", "o/..", "$O/r", "o/"] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }

    #[test]
    fn tea_logins_read_only_name_and_url_of_each_login() {
        let text = r#"logins:
  - name: sjo
    url: "https://Git.Sjo.Lol:3000"
    token: url-lookalike
  - url: https://b.example
    name: 'b'
    nested:
      url: https://evil.example
preferences:
  url: https://evil.example
"#;
        assert_eq!(
            parse_tea_logins(text),
            Some(vec![
                TeaLogin {
                    name: "sjo".into(),
                    host: "git.sjo.lol".into()
                },
                TeaLogin {
                    name: "b".into(),
                    host: "b.example".into()
                },
            ])
        );
        assert_eq!(parse_tea_logins("logins: []\n"), Some(vec![]));
        assert_eq!(
            parse_tea_logins("preferences:\n  editor: false\n"),
            Some(vec![])
        );
        // A login the guard cannot read could be the one that does not own
        // the slug, so any such login makes the config unreadable.
        for unreadable in [
            // An item with no url.
            "logins:\n  - name: sjo\n    url: https://git.sjo.lol\n  - name: other\n",
            // A flow-style item.
            "logins:\n  - {name: x, url: https://x.example}\n  - name: sjo\n    url: https://git.sjo.lol\n",
            // A quoted key, which YAML reads as `url`.
            "logins:\n  - name: work\n    \"url\": https://x.example\n",
            // A compact list at the key's own column.
            "logins:\n- name: sjo\n  url: https://git.sjo.lol\n- name: work\n  url: https://x.example\n",
            // An inline list.
            "logins: [{name: x, url: https://x.example}]\n",
            // An item whose keys start on the next line.
            "logins:\n  -\n    name: x\n    url: https://x.example\n",
        ] {
            assert_eq!(parse_tea_logins(unreadable), None, "{unreadable}");
        }
    }

    #[test]
    fn remote_listings_become_targets_or_nothing() {
        let listing = "remote.origin.url git@git.sjo.lol:cameron/lectern.git\n\
                       remote.up.stream.url https://h.example/o/r";
        let all = remote_targets(listing, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(describe(&all[0]), "git.sjo.lol/cameron/lectern");
        let one = remote_targets(listing, Some("up.stream")).unwrap();
        assert_eq!(describe(&one[0]), "h.example/o/r");
        assert!(remote_targets(listing, Some("nope")).is_none());
        assert!(remote_targets("remote.origin.url /local/path", None).is_none());
    }

    /// tea uses a given `--repo` and never the directory, so a `--repo` the
    /// guard cannot read is refused, not judged on the directory.
    #[test]
    fn an_unreadable_tea_repo_flag_is_not_judged_on_the_directory() {
        let cfg = sjo_config("tea-unreadable-repo-config");
        let root = scratch("tea-unreadable-repo");
        let repo = root.path().join("lectern");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "https://git.sjo.lol/cameron/lectern.git",
            ],
        );
        assert_eq!(
            run_tea("tea pr create --title x", Some(&repo), cfg.path()).outcome,
            Outcome::Allow,
            "control: the owned directory alone allows"
        );
        for cmd in [
            "tea pr create --repo \"$REPO\" --title x",
            "tea issue create -r ../upstream --title x",
            "tea pr create --repo ~/src/fork",
            "tea pr create --repo lectern",
            "tea pr create --repo https://git.sjo.lol/evil/x",
            "tea repos delete --owner \"$O\" --name x",
        ] {
            let r = run_tea(cmd, Some(&repo), cfg.path());
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
            assert_eq!(
                r.block_metadata.unwrap().rule_id,
                "forge-write-target-unresolvable",
                "{cmd}"
            );
        }
    }

    /// `--login` or an env login moves the host tea writes the directory's
    /// owner/repo to, and an exported instance URL is refused.
    #[test]
    fn a_moved_tea_login_judges_the_directory_repo_on_the_login_host() {
        let cfg = scratch("tea-moved-login-config");
        tea_config(
            cfg.path(),
            &[
                ("sjo", "https://git.sjo.lol"),
                ("work", "https://gitea.example.com"),
            ],
        );
        let root = scratch("tea-moved-login");
        let repo = root.path().join("lectern");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "git@git.sjo.lol:cameron/lectern.git",
            ],
        );
        let outcome = |cmd: &str| run_tea(cmd, Some(&repo), cfg.path()).outcome;
        assert_eq!(outcome("tea pr create --title x"), Outcome::Allow);
        assert_eq!(
            outcome("tea pr create --title x --login sjo"),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea pr create --title x --login SJO"),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea pr create --title x --login work"),
            Outcome::Block
        );
        assert_eq!(outcome("tea pr create --title x -l \"$L\""), Outcome::Block);
        assert_eq!(
            outcome("GITEA_INSTANCE_URL=https://gitea.example.com tea pr create --title x"),
            Outcome::Block
        );
        assert_eq!(
            outcome(
                "env GITEA_INSTANCE_URL=https://gitea.example.com tea pr create --title x --login sjo"
            ),
            Outcome::Block,
            "an inline GITEA_* assignment refuses, whatever `--login` says"
        );
        assert_eq!(
            outcome(
                "export GITEA_INSTANCE_URL=https://gitea.example.com && tea pr create --repo cameron/lectern --login sjo"
            ),
            Outcome::Block,
            "an instance URL the guard does not read refuses"
        );
    }

    /// Assignment carry-over, `repos` without an owner, a `--repo` that is a
    /// directory, and a remote tea reads differently.
    #[test]
    fn tea_and_glab_review_shapes() {
        let cfg = sjo_config("tea-review-shapes-config");
        let root = scratch("tea-review-shapes");
        let owned_repo = root.path().join("lectern");
        let evil = root.path().join("evil");
        let deep = root.path().join("deep");
        for (dir, url) in [
            (&owned_repo, "https://git.sjo.lol/cameron/lectern.git"),
            (&evil, "https://git.sjo.lol/evil/repo.git"),
            // tea reads the last two parts (`evil/r`); the guard must not read `cameron/x`.
            (&deep, "https://git.sjo.lol/cameron/x/evil/r.git"),
        ] {
            std::fs::create_dir_all(dir).unwrap();
            init_repo(dir);
            git_in(dir, &["remote", "add", "origin", url]);
        }
        // A directory under the owned checkout spelled like an owned slug.
        let slug_dir = owned_repo.join("cameron").join("fork");
        std::fs::create_dir_all(&slug_dir).unwrap();

        let outcome = |cmd: &str, cwd: &Path| run_tea(cmd, Some(cwd), cfg.path()).outcome;
        // An assignment in an earlier segment still reaches the write.
        assert_eq!(
            outcome("R=cameron/lectern; tea pr create --repo $R", &owned_repo),
            Outcome::Allow
        );
        assert_eq!(
            outcome("R=evil/x; tea pr create --repo $R", &owned_repo),
            Outcome::Block
        );
        let glab_vars: &[(&str, Option<&str>)] = &[
            ("CADENCE_ALLOWED_OWNERS", Some("gitlab.com/cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("GITLAB_HOST", None),
            ("CADENCE_DISABLE", None),
        ];
        with_env(glab_vars, || {
            let r = ForgeWriteGuard.run(&make_bash("R=cameronsjo/x; glab mr create -R $R"));
            assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
        });
        // `repos create|delete` act under the login user, never the directory.
        for cmd in [
            "tea repos create --name x",
            "tea repo delete --name important --login sjo",
        ] {
            assert_eq!(outcome(cmd, &owned_repo), Outcome::Block, "{cmd}");
        }
        // A `--repo` that is also a directory is opened as a local repo.
        assert_eq!(
            outcome("tea pr create --repo cameron/fork", &owned_repo),
            Outcome::Block
        );
        assert_eq!(
            outcome("tea pr create --repo cameron/lectern", &owned_repo),
            Outcome::Allow
        );
        // A remote path tea reads differently is unreadable.
        assert_eq!(outcome("tea pr create --title x", &deep), Outcome::Block);
    }

    /// A runner's own directory flag (`env -C`) moves tea.
    // Embeds native paths in a POSIX shell string; Windows paths lose their
    // backslashes to shell escaping, as in real bash.
    #[cfg(unix)]
    #[test]
    fn env_dash_c_moves_the_directory_tea_runs_in() {
        let cfg = sjo_config("tea-env-c-config");
        let root = scratch("tea-env-c");
        let owned_repo = root.path().join("lectern");
        let evil = root.path().join("evil");
        for (dir, url) in [
            (&owned_repo, "https://git.sjo.lol/cameron/lectern.git"),
            (&evil, "https://git.sjo.lol/evil/repo.git"),
        ] {
            std::fs::create_dir_all(dir).unwrap();
            init_repo(dir);
            git_in(dir, &["remote", "add", "origin", url]);
        }
        let outcome = |cmd: &str, cwd: &Path| run_tea(cmd, Some(cwd), cfg.path()).outcome;
        let env_c = format!("env -C '{}' tea pr create --title x", evil.display());
        assert_eq!(outcome(&env_c, &owned_repo), Outcome::Block);
        let env_c = format!("env -C '{}' tea pr create --title x", owned_repo.display());
        assert_eq!(outcome(&env_c, &evil), Outcome::Allow);
    }

    #[test]
    fn remote_paths_count_their_parts() {
        assert_eq!(remote_path_parts("https://h/a/b.git"), Some(2));
        assert_eq!(remote_path_parts("https://h/a/b/"), Some(2));
        assert_eq!(remote_path_parts("git@h:a/b.git"), Some(2));
        assert_eq!(remote_path_parts("ssh://git@h:22/a/b"), Some(2));
        assert_eq!(remote_path_parts("https://h/gitea/a/b"), Some(3));
    }

    /// With CADENCE_EXTRA_HOSTS set, a moved login still decides; `-O` is
    /// `--owner`; a `--repo` directory is found in a subshell's directory too.
    #[test]
    fn login_hosts_decide_over_extra_hosts_and_owner_alias_reads() {
        let cfg = scratch("tea-rereview-config");
        tea_config(
            cfg.path(),
            &[
                ("sjo", "https://git.sjo.lol"),
                ("work", "https://gitea.example.com"),
            ],
        );
        let root = scratch("tea-rereview");
        let repo = root.path().join("lectern");
        std::fs::create_dir_all(repo.join("sub").join("cameron").join("fork")).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "git@git.sjo.lol:cameron/lectern.git",
            ],
        );
        let vars: &[(&str, Option<&str>)] = &[
            ("CADENCE_ALLOWED_OWNERS", Some("cameron")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", Some("git.sjo.lol")),
            ("CADENCE_DISABLE", None),
            ("GITEA_INSTANCE_URL", None),
        ];
        let outcome = |cmd: &str| {
            let input = make_bash_with_cwd(cmd, repo.to_str().unwrap());
            with_tea_home(Some(cfg.path()), || {
                with_env(vars, || ForgeWriteGuard.run(&input).outcome)
            })
        };
        assert_eq!(
            outcome("tea pr create --title x --login sjo"),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea pr create --title x --login work"),
            Outcome::Block
        );
        assert_eq!(
            outcome("tea pr create --repo cameron/lectern --login sjo"),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea pr create --repo cameron/lectern --login work"),
            Outcome::Block
        );
        // Two logins and no `--login`: the slug may go to either host.
        assert_eq!(
            outcome("tea pr create --repo cameron/lectern"),
            Outcome::Block
        );
        // `-O` is tea's `--owner` alias.
        assert_eq!(
            outcome("tea repos create -O cameron --name x --login sjo"),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea repos create -O evil --name x --login sjo"),
            Outcome::Block
        );
        // The subshell runs tea in `sub`, where `cameron/fork` is a directory.
        assert_eq!(
            outcome("(cd sub && tea pr create --repo cameron/fork --login sjo)"),
            Outcome::Block
        );
        assert_eq!(
            outcome("(cd sub && tea pr create --repo cameron/lectern --login sjo)"),
            Outcome::Allow
        );
    }

    /// Runs the guard with `CADENCE_EXTRA_HOSTS=git.sjo.lol` and a bare
    /// `cameron` owner, the shape in which a dropped login used to fall back
    /// to the extra host. `config` is the tea config's text, or `None` for
    /// no config file.
    fn run_with_extra_hosts(tag: &str, config: Option<&str>, cwd: &Path, cmd: &str) -> CheckResult {
        let home = scratch(tag);
        if let Some(text) = config {
            let dir = home.path().join("tea");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("config.yml"), text).unwrap();
        }
        let vars: &[(&str, Option<&str>)] = &[
            ("CADENCE_ALLOWED_OWNERS", Some("cameron")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", Some("git.sjo.lol")),
            ("CADENCE_DISABLE", None),
            ("GITEA_INSTANCE_URL", None),
        ];
        let input = make_bash_with_cwd(cmd, cwd.to_str().unwrap());
        with_tea_home(Some(home.path()), || {
            with_env(vars, || ForgeWriteGuard.run(&input))
        })
    }

    const TWO_LOGINS: &str = "logins:\n    - name: sjo\n      url: https://git.sjo.lol\n    - name: work\n      url: https://gitea.example.com\n";

    fn owned_checkout(tag: &str) -> (Scratch, PathBuf) {
        let root = scratch(tag);
        let repo = root.path().join("lectern");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        git_in(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "git@git.sjo.lol:cameron/lectern.git",
            ],
        );
        (root, repo)
    }

    /// tea's parser takes one or two dashes, a name or its alias, and `=` or
    /// the next word, so `--r`, `-repo`, `--l` and `-login` name the repo
    /// and login just as `--repo` and `--login` do.
    #[test]
    fn tea_flags_are_read_in_every_spelling_tea_accepts() {
        let (_root, repo) = owned_checkout("tea-flag-spellings");
        let outcome = |cmd: &str| {
            run_with_extra_hosts("tea-flag-spellings-cfg", Some(TWO_LOGINS), &repo, cmd).outcome
        };
        for cmd in [
            "tea pr create --r victim/x --title t",
            "tea pr create --r=victim/x --title t",
            "tea pr create -repo victim/x --title t",
            "tea pr create -r=victim/x --title t",
            "tea pr create --title t --l work",
            "tea pr create --title t -login work",
            "tea pr create --title t --login=work",
            "tea pr create --repo cameron/lectern -login work",
            "tea pr create --repo cameron/lectern --l=work",
            "tea pr create --title t --R upstream",
        ] {
            assert_eq!(outcome(cmd), Outcome::Block, "{cmd}");
        }
        for cmd in [
            "tea pr create --title t --l sjo",
            "tea pr create -repo cameron/lectern -login sjo",
            "tea pr create --r=cameron/lectern --l=sjo",
            "tea pr create --title t -R origin --login sjo",
        ] {
            assert_eq!(outcome(cmd), Outcome::Allow, "{cmd}");
        }
    }

    /// A flag that could be a misspelt or extended repo, login, remote or
    /// owner flag is refused rather than guessed at.
    #[test]
    fn a_near_miss_target_flag_refuses() {
        let (_root, repo) = owned_checkout("tea-near-miss");
        for cmd in [
            "tea pr create --rep victim/x --title t",
            "tea pr create --repos victim/x --title t",
            "tea pr create --title t -logi work",
            "tea pr create --title t --remot upstream",
            "tea repos create --own victim --name x",
        ] {
            let r = run_with_extra_hosts("tea-near-miss-cfg", Some(TWO_LOGINS), &repo, cmd);
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
            assert!(
                r.message
                    .unwrap()
                    .contains("spelling the guard does not read"),
                "{cmd}"
            );
        }
        // Ordinary tea flags are not near misses.
        let r = run_with_extra_hosts(
            "tea-near-miss-cfg",
            Some(TWO_LOGINS),
            &repo,
            "tea pr create --title t --labels bug --login sjo --description d",
        );
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
    }

    /// A login the guard cannot read refuses the write; it never shrinks the
    /// host set, and never hands the decision to CADENCE_EXTRA_HOSTS.
    #[test]
    fn an_unreadable_tea_login_refuses_even_with_extra_hosts() {
        let (_root, repo) = owned_checkout("tea-unreadable-login");
        let unreadable = [
            // `work` has a quoted key, which tea's YAML reads as `url`.
            "logins:\n    - name: sjo\n      url: https://git.sjo.lol\n    - name: work\n      \"url\": https://gitea.example.com\n",
            // A compact list at the key's own column.
            "logins:\n- name: sjo\n  url: https://git.sjo.lol\n- name: work\n  url: https://gitea.example.com\n",
            // An inline list.
            "logins: [{name: work, url: https://gitea.example.com}]\n",
        ];
        for config in unreadable {
            for cmd in [
                "tea pr create --repo cameron/lectern",
                "tea pr create --title t --login sjo",
            ] {
                let r = run_with_extra_hosts("tea-unreadable-login-cfg", Some(config), &repo, cmd);
                assert_eq!(r.outcome, Outcome::Block, "{cmd} with {config}");
                assert!(
                    r.message.unwrap().contains("a login the guard cannot read"),
                    "{cmd} with {config}"
                );
            }
        }
        // A `--login` naming no login refuses too.
        let r = run_with_extra_hosts(
            "tea-unreadable-login-cfg",
            Some(TWO_LOGINS),
            &repo,
            "tea pr create --repo cameron/lectern --login nosuch",
        );
        assert_eq!(r.outcome, Outcome::Block);
        // No config at all: tea has no saved login, so the extra host decides.
        let r = run_with_extra_hosts(
            "tea-unreadable-login-none",
            None,
            &repo,
            "tea pr create --repo cameron/lectern",
        );
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
    }

    /// Only an assignment to GITEA_INSTANCE_URL can move tea's login; a
    /// command that merely mentions the name is judged as usual.
    #[test]
    fn only_an_instance_url_assignment_outside_the_tea_call_refuses() {
        let (_root, repo) = owned_checkout("tea-instance-mention");
        let outcome = |cmd: &str| {
            run_with_extra_hosts("tea-instance-mention-cfg", Some(TWO_LOGINS), &repo, cmd).outcome
        };
        assert_eq!(
            outcome("echo GITEA_INSTANCE_URL && tea pr create --title t --login sjo"),
            Outcome::Allow
        );
        assert_eq!(
            outcome(
                "export GITEA_INSTANCE_URL=https://gitea.example.com && tea pr create --title t --login sjo"
            ),
            Outcome::Block
        );
    }

    /// tea's `comments` command (aliases `comment`, `c`) and `repos rm` are
    /// writes too.
    #[test]
    fn tea_comment_and_repo_delete_aliases_are_writes() {
        for cmd in [
            "tea comments 3 lgtm --repo victim/x",
            "tea comment 3 lgtm --repo victim/x",
            "tea c 3 lgtm --repo victim/x",
            "tea repos rm --owner victim --name x --force",
            "tea repo delete -O victim --name x",
        ] {
            assert_eq!(outcome(cmd), Outcome::Block, "{cmd}");
        }
        for cmd in [
            "tea comments 3 lgtm --repo cameron/x",
            "tea repos rm --owner cameron --name x",
        ] {
            assert_eq!(outcome(cmd), Outcome::Allow, "{cmd}");
        }
    }

    /// A value that looks like a flag is the value of the flag before it.
    #[test]
    fn a_flag_value_is_not_read_as_a_near_miss() {
        assert_eq!(
            outcome("tea pr create --repo cameron/x --title \"--remote flag cleanup\""),
            Outcome::Allow
        );
        assert_eq!(
            outcome("tea pr create --repo cameron/x --title t --rep victim/y"),
            Outcome::Block
        );
    }

    #[test]
    fn tea_config_is_looked_up_where_tea_looks() {
        let home = Path::new("/h");
        assert_eq!(
            tea_config_candidates(Some(home), None, true),
            vec![
                PathBuf::from("/h/Library/Application Support/tea/config.yml"),
                PathBuf::from("/h/.tea/tea.yml"),
            ]
        );
        assert_eq!(
            tea_config_candidates(Some(home), None, false),
            vec![
                PathBuf::from("/h/.config/tea/config.yml"),
                PathBuf::from("/h/.tea/tea.yml"),
            ]
        );
        assert_eq!(
            tea_config_candidates(Some(home), Some(Path::new("/x")), true),
            vec![
                PathBuf::from("/x/tea/config.yml"),
                PathBuf::from("/h/.tea/tea.yml"),
            ]
        );
        assert_eq!(
            tea_config_candidates(None, Some(Path::new("/x")), false),
            vec![PathBuf::from("/x/tea/config.yml")]
        );
        assert!(tea_config_candidates(None, None, true).is_empty());
    }

    /// tea stops reading flags at `--`, a lone `-`, or a single-dash word
    /// whose second character is not a letter; every later word is a
    /// positional, so a `--repo` after a comment body like `- fixed` is
    /// text, and tea writes to the directory's repo.
    #[test]
    fn a_flag_after_tea_stops_reading_flags_is_a_positional() {
        let cfg = sjo_config("tea-flag-stop-config");
        let root = scratch("tea-flag-stop");
        let unowned = root.path().join("proj");
        std::fs::create_dir_all(&unowned).unwrap();
        init_repo(&unowned);
        git_in(
            &unowned,
            &[
                "remote",
                "add",
                "origin",
                "https://git.sjo.lol/stranger/proj.git",
            ],
        );
        git_in(
            &unowned,
            &[
                "remote",
                "add",
                "mine",
                "https://git.sjo.lol/cameron/proj.git",
            ],
        );
        let outcome = |cmd: &str| run_tea(cmd, Some(&unowned), cfg.path()).outcome;
        for cmd in [
            "tea comment 5 \"- fixed in abc\" --repo cameron/x",
            "tea comment 5 \"-1, not this way\" --repo cameron/x",
            "tea comment 5 \"-> see #4\" --repo cameron/x",
            "tea comment 5 - --repo cameron/x",
            "tea comment 5 \"- hi\" --remote mine",
            "tea comment 5 -- --repo cameron/x",
        ] {
            assert_eq!(outcome(cmd), Outcome::Block, "{cmd}");
        }
        // Before the stop word the flag still counts.
        assert_eq!(
            outcome("tea comment 5 --repo cameron/x \"- fixed in abc\""),
            Outcome::Allow
        );
        assert!(tea_flag_stop("-1") && tea_flag_stop("- x") && tea_flag_stop("-"));
        assert!(!tea_flag_stop("-r") && !tea_flag_stop("--repo") && !tea_flag_stop("-é"));
    }

    /// An existing tea config with content that yields no login is a layout
    /// the guard does not read, so it refuses rather than falling back.
    #[test]
    fn a_config_with_content_but_no_readable_login_refuses() {
        let (_root, repo) = owned_checkout("tea-zero-logins");
        for config in [
            "logins :\n    - name: far\n      url: https://far.example\n",
            "{\"logins\":[{\"name\":\"far\",\"url\":\"https://far.example\"}]}\n",
            "\u{feff}logins:\n    - name: far\n      url: https://far.example\n",
            "  logins:\n    - name: far\n      url: https://far.example\n",
            "logins: []\npreferences:\n    editor: false\n",
        ] {
            let r = run_with_extra_hosts(
                "tea-zero-logins-cfg",
                Some(config),
                &repo,
                "tea pr create --repo cameron/lectern",
            );
            assert_eq!(r.outcome, Outcome::Block, "{config:?}");
            assert!(
                r.message.unwrap().contains("a login the guard cannot read"),
                "{config:?}"
            );
        }
        // An empty or comment-only file holds no login: the extra host decides.
        for config in ["", "\n# nothing\n"] {
            let r = run_with_extra_hosts(
                "tea-zero-logins-cfg",
                Some(config),
                &repo,
                "tea pr create --repo cameron/lectern",
            );
            assert_eq!(r.outcome, Outcome::Allow, "{config:?}: {:?}", r.message);
        }
    }

    /// An assignment in front of `tea` to HOME, XDG_CONFIG_HOME or a GITEA_*
    /// variable moves tea's config or login, so it refuses.
    #[test]
    fn an_inline_tea_environment_assignment_refuses() {
        let (_root, repo) = owned_checkout("tea-inline-env");
        for cmd in [
            "XDG_CONFIG_HOME=/elsewhere tea pr create --repo cameron/lectern --login sjo",
            "HOME=/elsewhere tea pr create --repo cameron/lectern --login sjo",
            "GITEA_TOKEN=x tea pr create --repo cameron/lectern --login sjo",
            "env GITEA_INSTANCE_URL=https://git.sjo.lol tea pr create --repo cameron/lectern --login sjo",
        ] {
            let r = run_with_extra_hosts("tea-inline-env-cfg", Some(TWO_LOGINS), &repo, cmd);
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
            assert!(
                r.message.unwrap().contains("moves the config or login"),
                "{cmd}"
            );
        }
        let r = run_with_extra_hosts(
            "tea-inline-env-cfg",
            Some(TWO_LOGINS),
            &repo,
            "FOO=1 tea pr create --repo cameron/lectern --login sjo",
        );
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
    }

    /// The near-miss check and the positional reader stop where tea does.
    #[test]
    fn every_tea_flag_reader_stops_where_tea_does() {
        let (_root, repo) = owned_checkout("tea-stop-readers");
        // `--rep` after `-` is comment text, not a near-miss flag.
        let r = run_with_extra_hosts(
            "tea-stop-readers-cfg",
            Some(TWO_LOGINS),
            &repo,
            "tea comment 5 - --rep notes --login sjo",
        );
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "`--rep` after `-` is text: {:?}",
            r.message
        );
        let r = run_with_extra_hosts(
            "tea-stop-readers-cfg",
            Some(TWO_LOGINS),
            &repo,
            "tea comment 5 --login sjo - --rep notes",
        );
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let args = words(&["comment", "5", "- x", "--repo", "a/b"]);
        assert_eq!(
            tea_positionals(&args),
            vec!["comment", "5", "- x", "--repo", "a/b"]
        );
        let args = words(&["comment", "5", "--", "--repo", "a/b"]);
        assert_eq!(
            tea_positionals(&args),
            vec!["comment", "5", "--repo", "a/b"]
        );
        let args = words(&["comment", "5", "--repo", "a/b", "x"]);
        assert_eq!(tea_positionals(&args), vec!["comment", "5", "x"]);
    }
}
