//! Refuse PR merges a Claude Code cloud session (`CLAUDE_CODE_REMOTE=true`)
//! does not own (cameronsjo/cadence-hooks#1368).
//!
//! Under the cloud/local coordination conventions (cameronsjo/cadence-ecosystem
//! `docs/research/2026-10-11-cloud-local-agent-coordination.md`, rule 2 as
//! revised), a cloud session may merge only a PR it wholly owns: one whose head
//! is its own `claude/*` branch (project threads and gambit lanes,
//! cameronsjo/cadence#1677) in the same repository. Every
//! other PR is merged by the local chief-of-staff or by Cameron. In a local
//! session this guard allows everything.
//!
//! **What counts as a merge.** Every way the `gh` CLI starts or queues one:
//!
//! - `gh pr merge`, including `--auto` (it queues a merge). `--disable-auto`
//!   only cancels a queued merge, so it passes.
//! - `gh api` to `repos/<owner>/<repo>/pulls/<n>/merge` with any method but
//!   `GET`/`HEAD` (a `GET` there only asks whether the PR is merged).
//! - `gh api graphql` mutations whose root fields include
//!   [`MERGE_MUTATIONS`]. These name the PR by node ID, so the head is not
//!   resolved: they always block, and the fix is `gh pr merge`.
//!
//! **Ownership.** One `gh pr view --json headRefName,isCrossRepository,labels,url`
//! names the PR's head. The merge passes only when that head starts with
//! [`CLOUD_BRANCH_PREFIX`] and is not from a fork. Two Cameron-in-the-loop
//! cases the same answer shows also block: a label naming CITL, and a
//! signature-gated repository ([`SIGNATURE_GATED_REPOS`]). A release PR has a
//! `prepare-release/*` head, so the prefix rule already blocks it. The other
//! conditions (a manual rollout step, a settings change, a decision Cameron
//! has not made) stay with the convention.
//!
//! **Fails closed.** A merge whose head cannot be resolved blocks: an
//! unreadable selector, a `gh` call that fails or times out, a host the
//! command names other than `github.com` or `origin`'s, and a `gh api` write
//! whose endpoint the shell computes. A merge sent by another client (`curl`
//! to the REST API) is outside the threat model: the rule is about agents
//! following the convention, not an adversary.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use cadence_hooks_core::shell::{
    PrSelector, command_segments, gh_command_path, gh_pr_segments, gh_pr_subcommand,
    may_spell_word, pr_url_parts,
};
use cadence_hooks_core::{BlockMetadata, Check, CheckResult, HookInput};

use crate::bounded_tool::BoundedGhRunner;
use crate::guard_gh_write::{
    API_FIELD_FLAGS, API_INPUT_FLAG, MUTATION_KEYWORD, api_explicit_method,
    api_method_forces_write, gh_api_endpoint, gh_argv, graphql_query_value,
    graphql_root_mutation_fields, is_graphql_endpoint, segment_invokes_gh, strip_graphql_literals,
};
use crate::warn_unreviewed_ready_flip::{FlipContext, FlipTarget, GhRunner, hosts_are_trusted};

/// The head-branch prefix of a cloud session's own PRs.
const CLOUD_BRANCH_PREFIX: &str = "claude/";

/// Repositories whose merges need Cameron's signature (`owner/name` or a bare
/// name), compared case-insensitively against the repository name.
const SIGNATURE_GATED_REPOS: &[&str] = &["dotfiles-core", "cadence-lite"];

/// GraphQL mutation root fields that merge a PR or queue one to merge.
const MERGE_MUTATIONS: &[&str] = &[
    "mergePullRequest",
    "enablePullRequestAutoMerge",
    "enqueuePullRequest",
];

/// The fields `gh pr view` is asked for.
const PR_VIEW_FIELDS: &str = "headRefName,isCrossRepository,labels,url";

/// The REST merge endpoint's path, after any scheme, host, and GHES `api/v3/`
/// prefix are removed: owner, repo, and PR number. Case-insensitive so an
/// odd spelling is still a merge.
static PULL_MERGE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^repos/([^/]+)/([^/]+)/pulls/([^/]+)/merge/?$")
        .expect("pattern should compile")
});

/// A merge the command asks for, before its PR is looked up.
#[derive(Debug, PartialEq, Eq)]
enum MergeCall {
    /// A `gh pr merge` segment's tokens (`auto` when it only queues one).
    Pr { tokens: Vec<String>, auto: bool },
    /// A REST merge: `repo` is `None` for gh's `{owner}/{repo}` placeholders.
    Api { repo: Option<String>, number: u64 },
    /// A GraphQL mutation that merges or queues a merge.
    Graphql(String),
    /// A call that may merge but cannot be read: what is unreadable.
    Unreadable(&'static str),
}

/// What `gh pr view` says about the PR a merge names.
#[derive(Debug, PartialEq, Eq)]
struct PrFacts {
    url: String,
    repo: String,
    head: String,
    cross_repo: bool,
    labels: Vec<String>,
}

/// Why a merge was refused.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    /// The PR is not the cloud session's own.
    NotOwned {
        url: String,
        head: String,
        fork: bool,
    },
    /// The PR carries a CITL label.
    Citl { url: String, label: String },
    /// The PR's repository merges only with Cameron's signature.
    SignatureGated { url: String },
    /// A GraphQL merge mutation, which names the PR by node ID.
    Graphql(String),
    /// The merge's PR could not be resolved: why.
    Unresolved(&'static str),
}

/// The path part of a `gh api` endpoint: no query, fragment, scheme, host,
/// leading `/`, or GHES `api/v3/` prefix.
fn endpoint_path(endpoint: &str) -> &str {
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    let path = match path.split_once("://") {
        Some((_scheme, rest)) => rest.find('/').map_or("", |idx| &rest[idx..]),
        None => path,
    };
    let path = path.trim_start_matches('/');
    path.strip_prefix("api/v3/").unwrap_or(path)
}

/// An owner or repo name the guard passes to gh.
fn is_safe_name(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('-')
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether a `gh api` segment sends anything other than a `GET`/`HEAD`.
/// An explicit method decides; without one, gh sends `GET` unless a field or
/// `--input` turns it into a `POST`.
fn api_sends_write(segment: &str) -> bool {
    if api_method_forces_write(segment) {
        return true;
    }
    match api_explicit_method(segment).as_deref() {
        Some("GET" | "HEAD") => false,
        Some(_) => true,
        None => API_FIELD_FLAGS.is_match(segment) || API_INPUT_FLAG.is_match(segment),
    }
}

/// The merge call in a `gh api graphql` argv, if any.
fn graphql_call(argv: &[String]) -> Option<MergeCall> {
    let unreadable = Some(MergeCall::Unreadable("a GraphQL query that is not inline"));
    let Some(query) = graphql_query_value(argv) else {
        return unreadable;
    };
    // A query from a file, stdin, or a shell expansion cannot be read. Every
    // real query has a selection set, so one with no `{` is a shell variable
    // (`query="$Q"`) the tokenizer left unexpanded.
    if query.starts_with('@') || query.contains("$(") || query.contains('`') || !query.contains('{')
    {
        return unreadable;
    }
    let stripped = strip_graphql_literals(&query);
    if !MUTATION_KEYWORD.is_match(&stripped) {
        return None;
    }
    match graphql_root_mutation_fields(&stripped) {
        Some(fields) => fields
            .into_iter()
            .find(|f| MERGE_MUTATIONS.contains(&f.as_str()))
            .map(MergeCall::Graphql),
        None => Some(MergeCall::Unreadable(
            "a GraphQL mutation the guard cannot parse",
        )),
    }
}

/// The merge call in one `gh api` segment, if any.
fn api_call(segment: &str, argv: &[String]) -> Option<MergeCall> {
    let endpoint = gh_api_endpoint(segment).unwrap_or_default();
    if is_graphql_endpoint(&endpoint) {
        return graphql_call(argv);
    }
    if !api_sends_write(segment) {
        return None;
    }
    if endpoint.is_empty() || endpoint.contains(['$', '`']) {
        return Some(MergeCall::Unreadable(
            "a `gh api` write whose endpoint the shell computes",
        ));
    }
    let caps = PULL_MERGE_PATH.captures(endpoint_path(&endpoint))?;
    let unresolved = Some(MergeCall::Unreadable(
        "a `gh api` merge whose PR the guard cannot look up",
    ));
    // Another host, or an env override of the host or repo, points gh
    // somewhere this guard does not look.
    let host_ok = match endpoint.split_once("://") {
        Some((_, rest)) => rest
            .split('/')
            .next()
            .is_some_and(|h| h.eq_ignore_ascii_case("api.github.com")),
        None => true,
    };
    if !host_ok
        || ["GH_HOST", "GH_REPO", "--hostname"]
            .iter()
            .any(|w| segment.contains(w))
    {
        return unresolved;
    }
    let (owner, name) = (&caps[1], &caps[2]);
    let Ok(number) = caps[3].parse::<u64>() else {
        return unresolved;
    };
    let repo = match (owner, name) {
        ("{owner}", "{repo}") => None,
        _ if is_safe_name(owner) && is_safe_name(name) => Some(format!("{owner}/{name}")),
        _ => return unresolved,
    };
    Some(MergeCall::Api { repo, number })
}

/// Whether a `gh pr merge` argv only cancels a queued merge.
fn cancels_auto(tokens: &[String]) -> bool {
    tokens.iter().any(|t| t == "--disable-auto")
}

/// Every merge call in `command`.
fn merge_calls(command: &str) -> Vec<MergeCall> {
    let mut calls = Vec::new();
    let mut argv_merges = 0;
    for segment in command_segments(command) {
        if !segment_invokes_gh(&segment) {
            continue;
        }
        let Some(argv) = gh_argv(&segment) else {
            continue;
        };
        match gh_command_path(&argv, 2).as_slice() {
            ["pr", "merge"] if !cancels_auto(&argv) => argv_merges += 1,
            ["api", ..] => calls.extend(api_call(&segment, &argv)),
            _ => {}
        }
    }
    // The shared `gh pr` walk keeps the prefixes (`GH_REPO=`, `GH_HOST=`)
    // that decide which PR gh merges, so it is the one the lookup reads.
    let prs: Vec<MergeCall> = gh_pr_segments(command)
        .into_iter()
        .filter(|tokens| gh_pr_subcommand(tokens) == Some("merge") && !cancels_auto(tokens))
        .map(|tokens| MergeCall::Pr {
            auto: tokens.iter().any(|t| t == "--auto"),
            tokens,
        })
        .collect();
    // A merge the argv walk sees and the shared walk does not (an `eval`
    // wrapper) has no tokens to look up.
    if argv_merges > prs.len() {
        calls.push(MergeCall::Unreadable(
            "a `gh pr merge` the guard cannot read",
        ));
    }
    calls.extend(prs);
    calls
}

/// Read `gh pr view --json` output.
fn parse_facts(json: &str) -> Option<PrFacts> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let url = value.get("url")?.as_str()?.to_string();
    let (_host, owner, name, _number) = pr_url_parts(&url)?;
    Some(PrFacts {
        repo: format!("{owner}/{name}"),
        head: value.get("headRefName")?.as_str()?.to_string(),
        cross_repo: value.get("isCrossRepository")?.as_bool()?,
        labels: value
            .get("labels")?
            .as_array()?
            .iter()
            .filter_map(|l| l.get("name")?.as_str().map(String::from))
            .collect(),
        url,
    })
}

/// The ruling on a PR a cloud session merges.
fn rule(facts: PrFacts) -> Option<Finding> {
    let owned = facts
        .head
        .strip_prefix(CLOUD_BRANCH_PREFIX)
        .is_some_and(|rest| !rest.is_empty());
    if facts.cross_repo || !owned {
        return Some(Finding::NotOwned {
            url: facts.url,
            head: facts.head,
            fork: facts.cross_repo,
        });
    }
    if let Some(label) = facts
        .labels
        .iter()
        .find(|l| l.to_ascii_lowercase().contains("citl"))
    {
        return Some(Finding::Citl {
            url: facts.url,
            label: label.clone(),
        });
    }
    let name = facts.repo.rsplit('/').next().unwrap_or("");
    if SIGNATURE_GATED_REPOS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(name))
    {
        return Some(Finding::SignatureGated { url: facts.url });
    }
    None
}

/// Builds the gh runner for a working dir and env; a seam for tests.
type GhFactory<'a> = dyn Fn(PathBuf, Vec<(String, String)>) -> Box<dyn GhRunner> + 'a;

/// Look up a `gh pr merge`'s PR and rule on it.
fn judge_pr(tokens: &[String], input: &HookInput, gh: &GhFactory<'_>) -> Option<Finding> {
    let unresolved = Some(Finding::Unresolved(
        "the guard cannot tell which PR it merges",
    ));
    let Some(target) = FlipTarget::from_tokens(tokens) else {
        return unresolved;
    };
    let ctx = FlipContext::for_target(&target, input);
    if !hosts_are_trusted(&target.named_hosts, ctx.origin_host.as_deref()) {
        return Some(Finding::Unresolved(
            "it names a host other than github.com or origin's",
        ));
    }
    let selector = match &target.selector {
        PrSelector::None => None,
        PrSelector::Number(n) => Some(n.to_string()),
        PrSelector::Url {
            host,
            owner,
            repo,
            number,
        } => Some(format!("https://{host}/{owner}/{repo}/pull/{number}")),
        PrSelector::Other(sel) => Some(sel.clone()),
        PrSelector::Unreadable => return unresolved,
    };
    let repo = target.repo.repo_arg();
    let mut args = vec!["pr", "view", "--json", PR_VIEW_FIELDS];
    if let Some(repo) = repo.as_deref() {
        args.extend(["-R", repo]);
    }
    if let Some(sel) = selector.as_deref() {
        args.extend(["--", sel]);
    }
    lookup(&*gh(PathBuf::from(&ctx.cwd), ctx.env), &args)
}

/// Look up a REST merge's PR and rule on it.
fn judge_api(
    repo: Option<&str>,
    number: u64,
    input: &HookInput,
    gh: &GhFactory<'_>,
) -> Option<Finding> {
    let number = number.to_string();
    let mut args = vec!["pr", "view", "--json", PR_VIEW_FIELDS];
    if let Some(repo) = repo {
        args.extend(["-R", repo]);
    }
    args.extend(["--", number.as_str()]);
    let cwd = input.cwd.clone().unwrap_or_else(|| ".".to_string());
    lookup(&*gh(PathBuf::from(cwd), Vec::new()), &args)
}

/// Run one `gh pr view` and rule on the answer; a failed call blocks.
fn lookup(gh: &dyn GhRunner, args: &[&str]) -> Option<Finding> {
    match gh.run(args).as_deref().and_then(parse_facts) {
        Some(facts) => rule(facts),
        None => Some(Finding::Unresolved(
            "`gh pr view` could not name its head branch",
        )),
    }
}

/// Judge a command. `remote` is whether this is a cloud session.
fn judge(command: &str, remote: bool, input: &HookInput, gh: &GhFactory<'_>) -> Option<Finding> {
    if !remote || !may_spell_word(command, "gh") {
        return None;
    }
    merge_calls(command)
        .into_iter()
        .find_map(|call| match call {
            MergeCall::Pr { tokens, .. } => judge_pr(&tokens, input, gh),
            MergeCall::Api { repo, number } => judge_api(repo.as_deref(), number, input, gh),
            MergeCall::Graphql(field) => Some(Finding::Graphql(field)),
            MergeCall::Unreadable(why) => Some(Finding::Unresolved(why)),
        })
}

/// The block message for a finding.
fn block(finding: &Finding) -> CheckResult {
    const HAND_OFF: &str = "post your result on the PR instead (`gh pr comment <n> --body-file <file>`); \
         the local chief-of-staff or Cameron merges it";
    let (what, fix) = match finding {
        Finding::NotOwned { url, head, fork } => (
            format!(
                "{url} has head `{head}`{}, not this cloud session's own \
                 `{CLOUD_BRANCH_PREFIX}*` branch",
                if *fork { " from a fork" } else { "" }
            ),
            HAND_OFF,
        ),
        Finding::Citl { url, label } => (
            format!("{url} carries the `{label}` label, so Cameron is in the loop"),
            HAND_OFF,
        ),
        Finding::SignatureGated { url } => (
            format!("{url} is in a repository whose merges need Cameron's signature"),
            HAND_OFF,
        ),
        Finding::Graphql(field) => (
            format!(
                "the GraphQL mutation `{field}` names the PR by node ID, so its head is not checked"
            ),
            "merge with `gh pr merge <n>` so the guard can check the head branch",
        ),
        Finding::Unresolved(why) => (
            format!("the guard cannot confirm this merge is of the session's own PR: {why}"),
            "name the PR plainly (`gh pr merge <n> -R owner/repo`), or post your result on the PR \
             for the local chief-of-staff to merge",
        ),
    };
    CheckResult::block_structured(
        format!(
            "🚫 cloud-merge: a cloud session merges only its own `{CLOUD_BRANCH_PREFIX}*` PRs\n   \
             {what}\n   \
             Fix: {fix}"
        ),
        BlockMetadata {
            rule_id: "cloud-session-merge".to_string(),
            fix: fix.to_string(),
            allowed_owners: Vec::new(),
            severity: "error",
        },
    )
}

/// Block cloud-session merges of PRs the session does not own.
pub struct GuardCloudMerge;

impl GuardCloudMerge {
    fn run_with(input: &HookInput, remote: bool, gh: &GhFactory<'_>) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        judge(command, remote, input, gh).map_or_else(CheckResult::allow, |f| block(&f))
    }
}

impl Check for GuardCloudMerge {
    fn name(&self) -> &str {
        "guard-cloud-merge"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        Self::run_with(
            input,
            cadence_hooks_core::remote::is_remote(),
            &|cwd, env| Box::new(BoundedGhRunner { cwd, env }) as Box<dyn GhRunner>,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A `gh` that answers every `pr view` with `answer` and records calls.
    struct FakeGh {
        answer: Option<String>,
        calls: Rc<RefCell<Vec<Vec<String>>>>,
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(ToString::to_string).collect());
            self.answer.clone()
        }
    }

    fn pr_json(head: &str, cross: bool, labels: &[&str], url: &str) -> String {
        let labels: Vec<String> = labels
            .iter()
            .map(|l| format!(r#"{{"name":"{l}"}}"#))
            .collect();
        format!(
            r#"{{"headRefName":"{head}","isCrossRepository":{cross},"labels":[{}],"url":"{url}"}}"#,
            labels.join(",")
        )
    }

    const OWN: &str = "claude/project-thread-abc123";
    const URL: &str = "https://github.com/o/r/pull/5";

    /// Run the guard in a cloud session against a fake gh answering `answer`.
    fn cloud_with(command: &str, answer: Option<String>) -> (CheckResult, Vec<Vec<String>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&calls);
        let mut input = make_bash(command);
        input.cwd = Some("/nonexistent-cloud-merge-test".to_string());
        let result = GuardCloudMerge::run_with(&input, true, &move |_cwd, _env| {
            Box::new(FakeGh {
                answer: answer.clone(),
                calls: Rc::clone(&seen),
            }) as Box<dyn GhRunner>
        });
        let calls = calls.borrow().clone();
        (result, calls)
    }

    fn cloud_foreign(command: &str) -> Outcome {
        cloud_with(command, Some(pr_json("feat/local", false, &[], URL)))
            .0
            .outcome
    }

    fn cloud_own(command: &str) -> Outcome {
        cloud_with(command, Some(pr_json(OWN, false, &[], URL)))
            .0
            .outcome
    }

    #[test]
    fn local_sessions_merge_freely() {
        for command in [
            "gh pr merge 5 --squash",
            "gh api -X PUT repos/o/r/pulls/5/merge",
        ] {
            let result = GuardCloudMerge::run_with(&make_bash(command), false, &|_, _| {
                panic!("a local session must not call gh")
            });
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
        }
    }

    #[test]
    fn cloud_merge_of_a_foreign_pr_blocks() {
        for command in [
            "gh pr merge 5 --squash",
            "gh pr merge --auto --squash 5",
            "gh pr merge",
            "gh pr merge 5 -R o/r",
            "gh -R o/r pr merge 5",
            "gh pr -R o/r merge 5",
            "gh pr merge https://github.com/o/r/pull/5",
            "gh pr merge some-branch",
            "GH_TOKEN=x gh pr merge 5",
            "env GH_TOKEN=x gh pr merge 5",
            "time gh pr merge 5",
            "cd /repo && gh pr merge 12 --merge",
            "for p in 1 2; do gh pr merge $p; done",
            "bash -c 'gh pr merge 5'",
            "/opt/homebrew/bin/gh pr merge 5",
            "GH pr merge 5",
            "gh api -X PUT repos/o/r/pulls/5/merge",
            "gh api --method PUT /repos/o/r/pulls/5/merge -f merge_method=squash",
            "gh api -XPUT repos/{owner}/{repo}/pulls/5/merge",
            "gh api repos/o/r/pulls/5/merge -f merge_method=squash",
            "gh api https://api.github.com/repos/o/r/pulls/5/merge -X PUT",
            "gh api repos/o/r/pulls/5/merge --input body.json",
            "gh api -X \"$M\" repos/o/r/pulls/5/merge",
        ] {
            assert_eq!(cloud_foreign(command), Outcome::Block, "{command}");
        }
    }

    #[test]
    fn cloud_merge_of_its_own_pr_passes() {
        for command in [
            "gh pr merge 5 --squash",
            "gh pr merge --auto --squash 5",
            "gh pr merge",
            "gh pr merge 5 -R o/r --squash --delete-branch",
            "gh pr merge https://github.com/o/r/pull/5",
            "gh api -X PUT repos/o/r/pulls/5/merge",
            "gh api -XPUT repos/{owner}/{repo}/pulls/5/merge",
        ] {
            assert_eq!(cloud_own(command), Outcome::Allow, "{command}");
        }
    }

    #[test]
    fn the_lookup_asks_gh_for_the_named_pr() {
        let answer = Some(pr_json(OWN, false, &[], URL));
        let (_, calls) = cloud_with("gh pr merge 5 -R o/r", answer.clone());
        assert_eq!(
            calls,
            vec![vec![
                "pr",
                "view",
                "--json",
                PR_VIEW_FIELDS,
                "-R",
                "o/r",
                "--",
                "5"
            ]]
        );
        let (_, calls) = cloud_with("gh api -X PUT repos/o/r/pulls/7/merge", answer.clone());
        assert_eq!(
            calls,
            vec![vec![
                "pr",
                "view",
                "--json",
                PR_VIEW_FIELDS,
                "-R",
                "o/r",
                "--",
                "7"
            ]]
        );
        let (_, calls) = cloud_with("gh pr merge", answer);
        assert_eq!(calls, vec![vec!["pr", "view", "--json", PR_VIEW_FIELDS]]);
    }

    #[test]
    fn a_fork_head_with_the_cloud_prefix_blocks() {
        let (result, _) = cloud_with("gh pr merge 5", Some(pr_json(OWN, true, &[], URL)));
        assert_eq!(result.outcome, Outcome::Block);
        assert!(result.message.unwrap_or_default().contains("fork"));
    }

    #[test]
    fn the_bare_prefix_is_not_a_cloud_branch() {
        let (result, _) = cloud_with("gh pr merge 5", Some(pr_json("claude/", false, &[], URL)));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn citl_and_signature_gated_prs_block() {
        let (result, _) = cloud_with("gh pr merge 5", Some(pr_json(OWN, false, &["CITL"], URL)));
        assert_eq!(result.outcome, Outcome::Block);
        assert!(result.message.unwrap_or_default().contains("CITL"));
        let (result, _) = cloud_with(
            "gh pr merge 5",
            Some(pr_json(
                OWN,
                false,
                &[],
                "https://github.com/cameronsjo/dotfiles-core/pull/5",
            )),
        );
        assert_eq!(result.outcome, Outcome::Block);
        assert!(result.message.unwrap_or_default().contains("signature"));
    }

    #[test]
    fn an_unresolved_head_blocks() {
        for answer in [None, Some("not json".to_string()), Some("{}".to_string())] {
            let (result, _) = cloud_with("gh pr merge 5", answer);
            assert_eq!(result.outcome, Outcome::Block);
        }
    }

    #[test]
    fn unreadable_merges_block_without_a_lookup() {
        for command in [
            "eval \"gh pr merge 5\"",
            "gh pr merge 5 --bogus-flag x",
            "GH_HOST=evil.example gh pr merge 5",
            "gh api https://ghe.example/api/v3/repos/o/r/pulls/5/merge -X PUT",
            "GH_REPO=a/b gh api -X PUT repos/{owner}/{repo}/pulls/5/merge",
            "gh api -X PUT repos/o/r/pulls/x/merge",
            "gh api graphql -F query=@merge.graphql",
            "gh api graphql --input body.json",
            "gh api graphql -f query=\"$Q\"",
            "gh api graphql -f query=\"$(cat q.graphql)\"",
            "gh api -X PUT \"$EP\"",
        ] {
            let (result, calls) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Block, "{command}");
            assert!(calls.is_empty(), "{command}: {calls:?}");
        }
    }

    #[test]
    fn graphql_merge_mutations_block() {
        for query in [
            "mutation { mergePullRequest(input: {pullRequestId: \\\"P\\\"}) { clientMutationId } }",
            "mutation { enablePullRequestAutoMerge(input: {pullRequestId: \\\"P\\\"}) { clientMutationId } }",
            "mutation { enqueuePullRequest(input: {pullRequestId: \\\"P\\\"}) { clientMutationId } }",
            "mutation M { a: addComment(input: {}) { clientMutationId } b: mergePullRequest(input: {}) { clientMutationId } }",
        ] {
            let command = format!("gh api graphql -f query=\"{query}\"");
            let (result, _) = cloud_with(&command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Block, "{command}");
            assert!(
                result.message.unwrap_or_default().contains("gh pr merge"),
                "{command}"
            );
        }
    }

    #[test]
    fn the_block_names_the_hand_off() {
        let (result, _) = cloud_with(
            "gh pr merge 5",
            Some(pr_json("feat/local", false, &[], URL)),
        );
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("feat/local"), "{msg}");
        assert!(msg.contains("chief-of-staff"), "{msg}");
        assert!(msg.contains("gh pr comment"), "{msg}");
    }

    #[test]
    fn cloud_everyday_commands_pass_without_a_lookup() {
        for command in [
            "git status",
            "git merge origin/main",
            "gh pr view 5 --json mergedAt",
            "gh pr comment 5 --body-file /tmp/result.md",
            "gh pr comment 5 --body 'ready: run gh pr merge 5 locally'",
            "gh pr create --title t --body-file b.md",
            "gh pr ready 5",
            "gh pr merge 5 --disable-auto",
            "gh pr checks 5",
            "gh api repos/o/r/pulls/5/merge",
            "gh api -X GET repos/o/r/pulls/5/merge",
            "gh api repos/o/r/pulls/5",
            "gh api repos/o/r/issues/5/comments -f body=done",
            "gh api -X PATCH repos/o/r/pulls/5 -f title=x",
            "gh api \"repos/o/r/pulls?state=open\"",
            "gh api graphql -f query='query { viewer { login } }'",
            "gh api graphql -f query='query($n:Int!){ repository(owner:\"o\",name:\"r\"){ pullRequest(number:$n){ title } } }' -F n=5",
            "gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: \"T\"}) { clientMutationId } }'",
            "gh api graphql -f query='mutation { addComment(input: {subjectId: \"S\", body: \"mergePullRequest\"}) { clientMutationId } }'",
            "echo 'gh pr merge 5'",
            "./gh-pr-merge-helper.sh",
        ] {
            let (result, calls) = cloud_with(command, None);
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
            assert!(calls.is_empty(), "{command}: {calls:?}");
        }
    }

    #[test]
    fn endpoint_path_strips_prefixes() {
        assert_eq!(
            endpoint_path("/repos/o/r/pulls/5/merge?x=1"),
            "repos/o/r/pulls/5/merge"
        );
        assert_eq!(
            endpoint_path("https://ghe.example/api/v3/repos/o/r/pulls/5/merge"),
            "repos/o/r/pulls/5/merge"
        );
        assert_eq!(endpoint_path("https://api.github.com"), "");
    }
}
