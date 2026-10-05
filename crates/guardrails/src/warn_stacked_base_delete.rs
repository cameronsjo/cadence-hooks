//! Warn before deleting a branch that open PRs use as their base
//! (cameronsjo/cadence-hooks#473).
//!
//! Deleting a PR's base branch closes that PR; GitHub does not retarget it,
//! and a closed PR whose base is gone can be neither reopened nor retargeted,
//! so the dependent has to be recreated. The retarget-before-delete rule lives
//! in `cadence-forge:using-github-cli`; this nudge puts it in front of the
//! delete itself.
//!
//! Two delete paths are watched:
//!
//! - `git push <remote> --delete <branch>…` / `-d` / `:<branch>`, read by the
//!   shared push walk ([`push_locations`]). The remote is resolved from
//!   local git config (`git remote get-url`), or read directly when it is a
//!   URL. Either way its host must be `github.com` or `origin`'s host.
//! - `gh pr merge --delete-branch` / `-d`: the PR is resolved exactly as the
//!   ready-flip guards resolve it ([`FlipTarget`], [`resolve_pr`]) and its
//!   head branch is the one deleted. A cross-repository (fork) PR is skipped:
//!   its head lives in another repo, so no PR here bases on it.
//!
//! For each deleted branch the base repo's open PRs are listed with
//! `baseRefName` equal to it. Any hit nudges, naming the PR numbers and the
//! retarget command. Advisory only — deleting a branch nothing bases on is
//! the ordinary case — and fails open (ADR-0001) on every error. gh is never
//! pointed at a host other than `github.com` or `origin`'s host, whether the
//! command names it or a non-origin remote's URL does, and every gh call is
//! bounded ([`crate::bounded_tool`]).

use cadence_hooks_core::push::push_locations;
use cadence_hooks_core::shell::{
    gh_pr_segments, gh_pr_subcommand, git_command, host_and_repo_from_url,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::PathBuf;

use crate::bounded_tool::BoundedGhRunner;
use crate::warn_unreviewed_ready_flip::{
    FlipContext, FlipTarget, GhRunner, QueryRepo, hosts_are_trusted, resolve_pr,
};

/// Open PRs whose base is `$base`. `first: 20` bounds the answer; the nudge
/// names what it got.
const DEPENDENTS_QUERY: &str = "query($owner: String!, $name: String!, $base: String!) { \
    repository(owner: $owner, name: $name) { \
    pullRequests(baseRefName: $base, states: OPEN, first: 20) { nodes { number } } } }";

/// A merged PR's head branch and whether it lives in another repository.
const HEAD_QUERY: &str = "query($owner: String!, $name: String!, $number: Int!) { \
    repository(owner: $owner, name: $name) { pullRequest(number: $number) { \
    headRefName isCrossRepository } } }";

/// A branch name the hook will query for: git's ref charset, conservatively
/// (letters, digits, `.`, `_`, `-`, `/`), with no leading `-`.
fn is_safe_branch(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

/// Open PR numbers basing on `branch` in `repo`, or `None` on any failure.
fn dependents(gh: &dyn GhRunner, repo: &QueryRepo, branch: &str) -> Option<Vec<u64>> {
    let (flag, owner, name) = repo.graphql_fields();
    let query = format!("query={DEPENDENTS_QUERY}");
    let base = format!("base={branch}");
    let json = gh.run(&[
        "api", "graphql", "-f", &query, flag, &owner, flag, &name, "-f", &base,
    ])?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    let nodes = value
        .pointer("/data/repository/pullRequests/nodes")?
        .as_array()?;
    nodes
        .iter()
        .map(|n| n.get("number").and_then(serde_json::Value::as_u64))
        .collect()
}

/// The nudge for `branch` with dependents `prs`.
fn message(branch: &str, prs: &[u64]) -> String {
    let listed = prs
        .iter()
        .map(|n| format!("#{n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let (count, verb) = if prs.len() == 1 {
        ("1 open PR".to_string(), "bases")
    } else {
        (format!("{} open PRs", prs.len()), "base")
    };
    let first = prs.first().copied().unwrap_or_default();
    format!(
        "warn-stacked-base-delete: {count} ({listed}) {verb} on `{branch}`. Deleting \
         `{branch}` now CLOSES them — GitHub does not retarget a PR whose base is \
         deleted, and a closed PR with a missing base can be neither reopened nor \
         retargeted. Retarget each first (`gh pr edit {first} --base <new-base>`), then \
         delete. See `cadence-forge:using-github-cli` § stacked PRs. Advisory only."
    )
}

/// The `gh pr merge` path: `Some(message)` to nudge.
pub fn evaluate_merge(
    target: &FlipTarget,
    origin_host: Option<&str>,
    gh: &dyn GhRunner,
) -> Option<String> {
    if !hosts_are_trusted(&target.named_hosts, origin_host) {
        return None;
    }
    let (repo, number) = resolve_pr(target, gh)?;
    let (flag, owner, name) = repo.graphql_fields();
    let query = format!("query={HEAD_QUERY}");
    let num = format!("number={number}");
    let json = gh.run(&[
        "api", "graphql", "-f", &query, flag, &owner, flag, &name, "-F", &num,
    ])?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    let pr = value.pointer("/data/repository/pullRequest")?;
    if pr.get("isCrossRepository")?.as_bool()? {
        return None;
    }
    let head = pr.get("headRefName")?.as_str()?;
    if !is_safe_branch(head) {
        return None;
    }
    let prs = dependents(gh, &repo, head)?;
    (!prs.is_empty()).then(|| message(head, &prs))
}

/// The `git push --delete` path for one remote repo: `Some(message)` to nudge
/// on the first deleted branch with dependents.
pub fn evaluate_push(gh: &dyn GhRunner, repo: &QueryRepo, branches: &[String]) -> Option<String> {
    branches.iter().find_map(|branch| {
        let prs = dependents(gh, repo, branch)?;
        (!prs.is_empty()).then(|| message(branch, &prs))
    })
}

/// True when a `gh pr merge` operand list asks for the head branch deletion:
/// `--delete-branch`, `--delete-branch=true`, or a boolean short cluster
/// carrying `d` (`-d`, `-sd`). `-t`/`-b`/`-A` take values, so a cluster
/// containing them is not read.
fn merge_deletes_branch(tokens: &[String]) -> bool {
    tokens.iter().any(|t| {
        t == "--delete-branch"
            || t.eq_ignore_ascii_case("--delete-branch=true")
            || t.strip_prefix('-').is_some_and(|c| {
                !c.starts_with('-')
                    && c.contains('d')
                    && c.bytes().all(|b| matches!(b, b'd' | b'm' | b'r' | b's'))
            })
    })
}

/// The branch a push deletion refspec names, without `refs/heads/`.
fn deleted_branch(raw: &str, destination: Option<&str>) -> Option<String> {
    let name = destination.unwrap_or(raw);
    let name = name.strip_prefix('+').unwrap_or(name);
    let name = name.strip_prefix(':').unwrap_or(name);
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    is_safe_branch(name).then(|| name.to_string())
}

/// A remote name the hook will pass to `git remote get-url`.
fn is_safe_remote_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Resolve a push's repository argument to `(host, owner, name)`.
fn resolve_remote(work_dir: &str, repository: &str) -> Option<(String, String, String)> {
    let url = if repository.contains("://") || repository.contains('@') {
        repository.to_string()
    } else if is_safe_remote_name(repository) {
        git_command(work_dir, &["remote", "get-url", repository])?
    } else {
        return None;
    };
    let (host, slug) = host_and_repo_from_url(&url)?;
    let (owner, name) = slug.split_once('/')?;
    Some((host, owner.to_string(), name.to_string()))
}

/// Nudges when a branch delete would close PRs based on it.
pub struct WarnStackedBaseDelete;

impl WarnStackedBaseDelete {
    fn run_merge(input: &HookInput, command: &str) -> Option<String> {
        let tokens = gh_pr_segments(command)
            .into_iter()
            .find(|t| gh_pr_subcommand(t) == Some("merge") && merge_deletes_branch(t))?;
        let target = FlipTarget::from_tokens(&tokens)?;
        let ctx = FlipContext::for_target(&target, input);
        let gh = BoundedGhRunner {
            cwd: PathBuf::from(&ctx.cwd),
            env: ctx.env,
        };
        evaluate_merge(&target, ctx.origin_host.as_deref(), &gh)
    }

    fn run_push(input: &HookInput, command: &str) -> Option<String> {
        run_push_with(input, command, &|cwd, env| {
            Box::new(BoundedGhRunner { cwd, env }) as Box<dyn GhRunner>
        })
    }
}

/// Builds the gh runner for one push's working dir and env; a seam so tests
/// can record what (if anything) would be queried.
type GhFactory<'a> = dyn Fn(PathBuf, Vec<(String, String)>) -> Box<dyn GhRunner> + 'a;

/// The most deleted branches one command is checked for. Each costs a gh
/// call, and each deleting push up to two `git remote get-url` spawns, so a
/// flood of deletes would otherwise spend the whole hook budget and go
/// silent. Past the cap the nudge fires without the check.
const MAX_CHECKED_DELETES: usize = 8;

/// The nudge for a command deleting more branches than the hook will check.
fn unchecked_message(count: usize) -> String {
    format!(
        "warn-stacked-base-delete: this command deletes {count} branches, more \
         than the {MAX_CHECKED_DELETES} checked for dependent PRs. Deleting a branch an open \
         PR bases on CLOSES that PR — GitHub does not retarget it. Retarget any dependent \
         first (`gh pr edit <n> --base <new-base>`), then delete. See \
         `cadence-forge:using-github-cli` § stacked PRs. Advisory only."
    )
}

/// The `git push --delete` path with an injectable gh runner.
fn run_push_with(input: &HookInput, command: &str, make_gh: &GhFactory<'_>) -> Option<String> {
    let cwd_fallback = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| ".".to_string());
    let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
    // `push_locations`, not `push_invocations`: the latter's config probe
    // (two git spawns per push) runs only for pushes whose refspecs are all
    // implicit, and an implicit refspec is never a delete, so it could only
    // spend budget on pushes this hook skips anyway.
    // One delete is counted once: core may read the same push twice, once
    // per reading of a script whose spellings differ
    // (cameronsjo/cadence-hooks#1231 review I2).
    let mut seen = std::collections::HashSet::new();
    let deletes: Vec<_> = push_locations(command, cwd)
        .into_iter()
        .filter_map(|push| {
            if push.unresolved {
                return None;
            }
            let branches: Vec<String> = push
                .refspecs
                .iter()
                .filter(|r| r.is_delete)
                .filter_map(|r| deleted_branch(&r.raw, r.destination.as_deref()))
                .filter(|branch| {
                    seen.insert((
                        push.work_dir.clone(),
                        push.repository.clone(),
                        branch.clone(),
                    ))
                })
                .collect();
            (!branches.is_empty() && !push.unresolved).then_some((push, branches))
        })
        .collect();
    let deleted: usize = deletes.iter().map(|(_, branches)| branches.len()).sum();
    if deleted > MAX_CHECKED_DELETES {
        return Some(unchecked_message(deleted));
    }
    for (push, branches) in deletes {
        let Some(repository) = push.repository.as_deref() else {
            continue;
        };
        let Some((host, owner, name)) = resolve_remote(&push.work_dir, repository) else {
            continue;
        };
        // Query only a host the user already trusts: github.com or origin's
        // host. This applies to a named remote too — any remote's URL can
        // point anywhere, and `GH_HOST` makes gh send its enterprise token
        // to that host.
        let origin_host = git_command(&push.work_dir, &["remote", "get-url", "origin"])
            .and_then(|u| host_and_repo_from_url(&u))
            .map(|(h, _)| h);
        if !hosts_are_trusted(std::slice::from_ref(&host), origin_host.as_deref()) {
            continue;
        }
        let env = if host.eq_ignore_ascii_case("github.com") {
            Vec::new()
        } else {
            vec![("GH_HOST".to_string(), host)]
        };
        let gh = make_gh(PathBuf::from(&push.work_dir), env);
        let repo = QueryRepo::Named { owner, name };
        if let Some(msg) = evaluate_push(gh.as_ref(), &repo, &branches) {
            return Some(msg);
        }
    }
    None
}

impl Check for WarnStackedBaseDelete {
    fn name(&self) -> &str {
        "warn-stacked-base-delete"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        match Self::run_merge(input, command).or_else(|| Self::run_push(input, command)) {
            Some(msg) => CheckResult::nudge(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use std::cell::RefCell;

    /// Answers the head query, the dependents query, and `gh pr view`.
    struct FakeGh {
        head_json: Option<String>,
        dependents_json: Option<String>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeGh {
        fn new(head: Option<&str>, dependents: Option<&str>) -> Self {
            FakeGh {
                head_json: head.map(String::from),
                dependents_json: dependents.map(String::from),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(ToString::to_string).collect());
            if args.first() == Some(&"pr") {
                return Some(r#"{"number":9,"url":"https://github.com/o/r/pull/9"}"#.into());
            }
            let query = args.iter().find(|a| a.starts_with("query="))?;
            if query.contains("headRefName") {
                self.head_json.clone()
            } else {
                self.dependents_json.clone()
            }
        }
    }

    fn head(branch: &str, cross: bool) -> String {
        format!(
            r#"{{"data":{{"repository":{{"pullRequest":{{"headRefName":"{branch}","isCrossRepository":{cross}}}}}}}}}"#
        )
    }

    fn deps(numbers: &[u64]) -> String {
        let nodes: Vec<String> = numbers
            .iter()
            .map(|n| format!(r#"{{"number":{n}}}"#))
            .collect();
        format!(
            r#"{{"data":{{"repository":{{"pullRequests":{{"nodes":[{}]}}}}}}}}"#,
            nodes.join(",")
        )
    }

    fn merge_target(command: &str) -> FlipTarget {
        let tokens = gh_pr_segments(command)
            .into_iter()
            .find(|t| gh_pr_subcommand(t) == Some("merge") && merge_deletes_branch(t))
            .expect("a deleting merge");
        FlipTarget::from_tokens(&tokens).expect("target parses")
    }

    #[test]
    fn merge_delete_branch_with_dependents_nudges() {
        let gh = FakeGh::new(Some(&head("feat/base", false)), Some(&deps(&[41, 42])));
        let msg = evaluate_merge(
            &merge_target("gh pr merge 5 --squash --delete-branch"),
            None,
            &gh,
        )
        .expect("nudge");
        assert!(
            msg.contains("2 open PRs (#41, #42) base on `feat/base`"),
            "{msg}"
        );
        let calls = gh.calls.borrow();
        assert!(
            calls[1].contains(&"base=feat/base".to_string()),
            "{calls:?}"
        );
    }

    #[test]
    fn merge_delete_branch_without_dependents_is_silent() {
        let gh = FakeGh::new(Some(&head("feat/base", false)), Some(&deps(&[])));
        assert_eq!(
            evaluate_merge(&merge_target("gh pr merge 5 -sd"), None, &gh),
            None
        );
    }

    #[test]
    fn cross_repository_head_is_skipped() {
        let gh = FakeGh::new(Some(&head("main", true)), Some(&deps(&[1])));
        assert_eq!(
            evaluate_merge(&merge_target("gh pr merge 5 -d"), None, &gh),
            None
        );
        assert_eq!(
            gh.calls.borrow().len(),
            1,
            "no dependents query for a fork head"
        );
    }

    #[test]
    fn gh_failures_fail_open() {
        let gh = FakeGh::new(None, Some(&deps(&[1])));
        assert_eq!(
            evaluate_merge(&merge_target("gh pr merge 5 -d"), None, &gh),
            None
        );
        let gh = FakeGh::new(Some(&head("b", false)), None);
        assert_eq!(
            evaluate_merge(&merge_target("gh pr merge 5 -d"), None, &gh),
            None
        );
        let gh = FakeGh::new(Some(&head("b", false)), Some("garbage"));
        assert_eq!(
            evaluate_merge(&merge_target("gh pr merge 5 -d"), None, &gh),
            None
        );
    }

    #[test]
    fn merge_without_delete_is_not_a_delete() {
        for cmd in [
            "gh pr merge 5 --squash",
            "gh pr merge 5 --delete-branch=false",
            "gh pr merge 5 -t 'feat: d'",
        ] {
            let found = gh_pr_segments(cmd)
                .into_iter()
                .any(|t| merge_deletes_branch(&t));
            assert!(!found, "{cmd}");
        }
    }

    #[test]
    fn push_delete_with_dependents_nudges_naming_the_branch() {
        let gh = FakeGh::new(None, Some(&deps(&[7])));
        let repo = QueryRepo::Named {
            owner: "o".into(),
            name: "r".into(),
        };
        let msg = evaluate_push(&gh, &repo, &["stack/one".to_string()]).expect("nudge");
        assert!(msg.contains("1 open PR (#7) bases on `stack/one`"), "{msg}");
        assert!(gh.calls.borrow()[0].contains(&"owner=o".to_string()));
    }

    #[test]
    fn push_delete_branch_extraction() {
        let branches = |cmd: &str| -> Vec<String> {
            push_locations(cmd, "/tmp")
                .iter()
                .flat_map(|p| p.refspecs.iter())
                .filter(|r| r.is_delete)
                .filter_map(|r| deleted_branch(&r.raw, r.destination.as_deref()))
                .collect()
        };
        assert_eq!(branches("git push origin --delete feat/a"), ["feat/a"]);
        assert_eq!(
            branches("git push origin -d feat/a feat/b"),
            ["feat/a", "feat/b"]
        );
        assert_eq!(branches("git push origin :refs/heads/feat/a"), ["feat/a"]);
        assert!(branches("git push origin feat/a").is_empty());
        let repos: Vec<Option<String>> = push_locations("git push up --delete x", "/tmp")
            .into_iter()
            .map(|p| p.repository)
            .collect();
        assert_eq!(repos, [Some("up".to_string())]);
    }

    /// Records every gh call made through the factory; answers dependents.
    fn push_calls(dir: &std::path::Path, command: &str) -> (Option<String>, usize) {
        use std::rc::Rc;
        let calls: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
        struct Counting(Rc<RefCell<usize>>);
        impl GhRunner for Counting {
            fn run(&self, _args: &[&str]) -> Option<String> {
                *self.0.borrow_mut() += 1;
                Some(deps(&[7]))
            }
        }
        let input =
            cadence_hooks_core::test_builders::make_bash_with_cwd(command, dir.to_str().unwrap());
        let seen = Rc::clone(&calls);
        let msg = run_push_with(&input, command, &move |_cwd, _env| {
            Box::new(Counting(Rc::clone(&seen))) as Box<dyn GhRunner>
        });
        let n = *calls.borrow();
        (msg, n)
    }

    #[test]
    fn a_named_remote_on_an_untrusted_host_is_never_queried() {
        use cadence_hooks_core::git_fixtures::{git_in, init_repo};
        let repo = tempfile::tempdir().expect("tempdir");
        init_repo(repo.path());
        git_in(
            repo.path(),
            &["remote", "add", "origin", "https://github.com/o/r.git"],
        );
        git_in(
            repo.path(),
            &["remote", "add", "up", "https://evil.example/o/r.git"],
        );
        let (msg, calls) = push_calls(repo.path(), "git push up --delete feat");
        assert_eq!((msg, calls), (None, 0), "untrusted named remote");
        // Positive control: the same shape against the trusted origin queries.
        let (msg, calls) = push_calls(repo.path(), "git push origin --delete feat");
        assert!(calls > 0 && msg.is_some(), "origin must be queried");
    }

    #[test]
    fn a_delete_read_two_ways_is_counted_once() {
        // cameronsjo/cadence-hooks#1231 round 2 review I2: core reads a
        // script whose spellings differ both ways, so five `-x` deletes came
        // back as ten, past the eight this hook checks, and no dependent PR
        // was looked up. Each delete counts once, so all five are checked.
        use cadence_hooks_core::git_fixtures::{git_in, init_repo};
        let repo = tempfile::tempdir().expect("tempdir");
        init_repo(repo.path());
        git_in(
            repo.path(),
            &["remote", "add", "origin", "https://github.com/o/r.git"],
        );
        for values in [1, 5, 8] {
            let command = format!(
                "git rebase {}HEAD~1",
                (0..values)
                    .map(|n| format!("-x 'echo a\\b; git push origin --delete f{n}' "))
                    .collect::<String>()
            );
            let (msg, calls) = push_calls(repo.path(), &command);
            assert!(
                calls > 0,
                "{values}: checked, not counted past the cap: {msg:?}"
            );
            let msg = msg.expect("dependents nudge");
            assert!(!msg.contains("than the"), "{values}: {msg}");
        }
    }

    #[test]
    fn clone_floods_allow_before_the_deadline() {
        // A 200 KB flood of clones and bare pushes took ~3.1 s in release:
        // every bare push spent two git config probes in its own directory,
        // none of which a delete check reads. Nothing here deletes a branch.
        let repo = tempfile::tempdir().expect("tempdir");
        let cwd = repo.path().to_str().unwrap();
        for unit in [
            "git clone https://github.com/cameronsjo/x d && cd d && git push; cd ..; ",
            "gh repo clone cameronsjo/x && cd x && git push; cd ..; ",
        ] {
            let flood = unit.repeat(200_000 / unit.len());
            let input = cadence_hooks_core::test_builders::make_bash_with_cwd(&flood, cwd);
            #[cfg(not(windows))]
            let started = std::time::Instant::now();
            let result = WarnStackedBaseDelete.run(&input);
            // Unix only: a debug build on the Windows runner spawns processes
            // slowly enough to sit at the bound (2.26 s) with no regression.
            #[cfg(not(windows))]
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "{unit}: took {:?}",
                started.elapsed()
            );
            assert_eq!(result.outcome, Outcome::Allow, "{unit}");
        }
    }

    #[test]
    fn a_delete_flood_nudges_without_checking() {
        use cadence_hooks_core::git_fixtures::{git_in, init_repo};
        let repo = tempfile::tempdir().expect("tempdir");
        init_repo(repo.path());
        git_in(
            repo.path(),
            &["remote", "add", "origin", "https://github.com/o/r.git"],
        );
        // Past the cap: nudged, and nothing is queried.
        for command in [
            "cd d && git push origin --delete x; cd ..; ".repeat(4500),
            format!(
                "git push origin --delete {}",
                (0..30_000)
                    .map(|i| format!("b{i}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            "git push origin --delete a b c d e f g h i".to_string(),
        ] {
            // 2 s everywhere but a debug build on the Windows runner, which
            // reads this flood ~2.5x slower than Linux debug: after #1278's
            // second reading it sat past 2 s on every main commit while Linux
            // debug took 0.9 s and release 0.17 s. A return to quadratic work
            // still trips the wider bound.
            let limit = std::time::Duration::from_secs(if cfg!(all(windows, debug_assertions)) {
                6
            } else {
                2
            });
            let started = std::time::Instant::now();
            let (msg, calls) = push_calls(repo.path(), &command);
            let took = started.elapsed();
            assert!(took < limit, "{}: {took:?}", &command[..40]);
            assert_eq!(calls, 0);
            assert!(msg.is_some_and(|m| m.contains("more than the 8 checked")));
        }
        // At the cap, each branch is still checked.
        let (msg, calls) = push_calls(repo.path(), "git push origin --delete a b c d e f g h");
        assert_eq!(calls, 1, "the first branch with dependents answers");
        assert!(msg.is_some_and(|m| m.contains("bases on `a`")));
    }

    #[test]
    fn unrelated_commands_allow_without_any_call() {
        for cmd in [
            "git status",
            "gh pr merge 5 --squash",
            "git push origin main",
        ] {
            let input = cadence_hooks_core::test_builders::make_bash_with_cwd(cmd, "/nonexistent");
            assert_eq!(
                WarnStackedBaseDelete.run(&input).outcome,
                Outcome::Allow,
                "{cmd}"
            );
        }
    }
}
