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

use cadence_hooks_core::config::{
    AllowEntry, env_allow_entries, env_extra_hosts, is_allowed_with_extra_hosts,
};
use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, host_and_repo_from_url,
    skip_transparent_prefixes, strip_group_wrappers,
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
    (&["repos", "repo", "r"], &["create", "c", "delete"]),
    (&["comment"], &["*"]),
];

/// Flags whose value is the FOLLOWING token, so it is not a positional.
const VALUE_FLAGS: &[&str] = &[
    "-R",
    "-r",
    "--repo",
    "--login",
    "-l",
    "--output",
    "-o",
    "--hostname",
    "--owner",
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
}

#[derive(Debug, PartialEq, Eq)]
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

/// The forge write in one segment, or `None` for anything else (reads
/// included). Pure apart from reading `GITLAB_HOST` for `glab`.
fn forge_write(segment: &str) -> Option<ForgeWrite> {
    let tokens = executable_tokens(strip_group_wrappers(segment));
    let prefix_len = tokens.len() - skip_transparent_prefixes(&tokens).len();
    let rest = skip_transparent_prefixes(&tokens);
    let head = rest.first()?;
    let forge = match command_word(head).as_ref() {
        "glab" => Forge::Glab,
        "tea" => Forge::Tea,
        _ => return None,
    };
    let args = &rest[1..];
    let pos = positionals(args);
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
    })
}

/// Whether `target` is covered by the allowlists (see the module docs for the
/// host rule).
fn owned(
    forge: &Forge,
    target: &Target,
    owners: &[AllowEntry],
    repos: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    let check = |host: &str| {
        is_allowed_with_extra_hosts(
            host,
            &target.owner,
            &target.repo,
            owners,
            repos,
            extra_hosts,
        )
    };
    match (&target.host, forge) {
        (Some(host), _) => check(host),
        (None, Forge::Glab) => check("gitlab.com") || extra_hosts.iter().any(|h| check(h)),
        (None, Forge::Tea) => extra_hosts.iter().any(|h| check(h)),
    }
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
        let owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
        let repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
        let extra_hosts = env_extra_hosts();
        let display: Vec<String> = owners
            .iter()
            .chain(repos.iter())
            .map(|e| e.to_string())
            .collect();
        let allowed = if display.is_empty() {
            "(none configured)".to_string()
        } else {
            display.join(" ")
        };
        for segment in command_segments(command) {
            let Some(write) = forge_write(&segment) else {
                continue;
            };
            let cli = if write.forge == Forge::Glab {
                "glab"
            } else {
                "tea"
            };
            let (rule_id, found, fix) = match &write.target {
                None => (
                    "forge-write-target-unresolvable",
                    format!("{cli} write with no readable target: {}", write.text),
                    "name the target literally with `-R owner/repo`".to_string(),
                ),
                Some(t) if owned(&write.forge, t, &owners, &repos, &extra_hosts) => continue,
                Some(t) => (
                    "forge-write-unauthorized-target",
                    format!(
                        "{cli} write targets {}{}/{}",
                        t.host
                            .as_deref()
                            .map(|h| format!("{h}/"))
                            .unwrap_or_default(),
                        t.owner,
                        t.repo
                    ),
                    "target an owned repo, or ask the user".to_string(),
                ),
            };
            return CheckResult::block_structured(
                format!(
                    "🚫 git-guardrails: {cli} write targets a repo you don't own (or none is readable)\n   \
                     Found: {found}\n   \
                     Allowed: {allowed}\n   \
                     Fix: {fix}. Bare `owner/repo` matches only hosts in CADENCE_EXTRA_HOSTS; \
                     qualify an entry as `host/owner` for another host\n   \
                     DO NOT override with env vars."
                ),
                BlockMetadata {
                    rule_id: rule_id.to_string(),
                    fix,
                    allowed_owners: display.clone(),
                    severity: "error",
                },
            );
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
    ];

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
}
