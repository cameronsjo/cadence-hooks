//! Refuse PR merges a Claude Code cloud session (`CLAUDE_CODE_REMOTE=true`)
//! does not own (cameronsjo/cadence-hooks#1368).
//!
//! Under the cloud/local coordination conventions (cameronsjo/cadence-ecosystem
//! `docs/research/2026-10-11-cloud-local-agent-coordination.md`, rule 2 as
//! revised), a cloud session may merge only a PR it wholly owns: one whose head
//! is its own `claude/*` branch (project threads and gambit lanes,
//! cameronsjo/cadence#1677) in the same repository. Every other PR is merged
//! by the local chief-of-staff or by Cameron. In a local session this guard
//! allows everything.
//!
//! **What counts as a merge.** Every way the `gh` CLI merges a PR, queues a
//! PR merge, or merges a branch with no PR:
//!
//! - `gh pr merge`, including `--auto` (it queues a merge). `--disable-auto`
//!   only cancels a queued merge and `--help` prints usage, so both pass.
//! - `gh api` to `repos/<owner>/<repo>/pulls/<n>/merge` with any method but
//!   `GET`/`HEAD` (a `GET` there only asks whether the PR is merged).
//! - `gh api` writes to `repos/<owner>/<repo>/merges` (a branch merge with no
//!   PR to own), which always block.
//! - `gh api graphql` mutations whose root fields include
//!   [`MERGE_MUTATIONS`]. These name the PR by node ID (or name no PR), so the
//!   head is not resolved: they always block, and the fix is `gh pr merge`.
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
//! `gh pr create … && gh pr merge` never passes: the lookup runs before the
//! command, when the PR does not exist yet. Create the PR, then merge it in a
//! separate command.
//!
//! **An implicit merge must come first; name the repo with `-R` to chain
//! it.** The lookup runs before the command does. It reads the payload cwd,
//! the checked-out branch, its upstream config, and the hook's env, and any
//! earlier step can change them: `gh pr checkout 7`, `cd other`,
//! `export GH_REPO=a/b`, `git push -u fork HEAD`, `git fetch --set-upstream`,
//! or another merge (`gh pr merge -d` checks out the base branch). An earlier
//! read-only list kept missing commands like these, so it is gone. A merge
//! that does not name its repo and PR (no `-R` with the number, no URL; a
//! bare `gh pr merge 5` counts as unnamed) passes only when nothing can run
//! before it and its own step has no wrapper (`find -execdir`, `env -C`) or
//! `GIT_*` prefix. In a flat `&&`/`;`/`||` list ([`is_flat`]) the steps after
//! the merge cannot run before it, so `gh pr merge 5 && git pull` passes;
//! with a pipe, a background job, a loop, or a substitution, every other step
//! counts as possibly earlier. A named merge (`gh pr merge 5 -R o/r && …`, a
//! URL) can follow other steps, but any merge blocks when a step that can
//! run before it mentions a `GH_*` variable.
//!
//! **Fails closed.** A merge whose head cannot be resolved blocks: an
//! unreadable selector, a `gh` call that fails or times out, a host the
//! command names other than `github.com` or `origin`'s, a `gh api` write
//! whose computed endpoint may end in `merge`, and a GraphQL query that is
//! neither inline nor a file read while the call is the first step. That
//! last one also blocks read-only queries passed as `"$Q"`; it is the
//! accepted cost. A merge sent by another client (`curl` to the REST API) or
//! through a computed program name (`$(which gh) pr merge`) is outside the
//! threat model: the rule is about agents following the convention, not an
//! adversary.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use cadence_hooks_core::shell::{
    PrSelector, command_segments, command_word, executable_tokens, gh_command_path, gh_pr_segments,
    gh_pr_subcommand, is_assignment_word, may_spell_word, pr_url_parts, strip_group_wrappers,
};
use cadence_hooks_core::{BlockMetadata, Check, CheckResult, HookInput};

use crate::bounded_tool::BoundedGhRunner;
use crate::guard_gh_write::{
    API_FIELD_FLAGS, API_INPUT_FLAG, MUTATION_KEYWORD, api_explicit_method,
    api_method_forces_write, gh_api_endpoint, gh_argv, graphql_query_value,
    graphql_root_mutation_fields, is_graphql_endpoint, strip_graphql_literals,
};
use crate::warn_unreviewed_ready_flip::{FlipContext, FlipTarget, GhRunner, hosts_are_trusted};

/// The head-branch prefix of a cloud session's own PRs.
const CLOUD_BRANCH_PREFIX: &str = "claude/";

/// Repositories whose merges need Cameron's signature (`owner/name` or a bare
/// name), compared case-insensitively against the repository name.
const SIGNATURE_GATED_REPOS: &[&str] = &["dotfiles-core", "cadence-lite"];

/// GraphQL mutation root fields that merge a PR or queue one to merge.
const MERGE_MUTATIONS: &[&str] = &[
    "mergeBranch",
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

/// The REST branch-merge endpoint (`POST repos/<o>/<r>/merges`), which merges
/// a head into a base with no PR.
static BRANCH_MERGE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^repos/[^/]+/[^/]+/merges/?$").expect("pattern should compile")
});

/// A merge the command asks for, before its PR is looked up.
#[derive(Debug, PartialEq, Eq)]
enum MergeCall {
    /// A `gh pr merge` segment's tokens.
    Pr { tokens: Vec<String> },
    /// A REST merge: `repo` is `None` for gh's `{owner}/{repo}` placeholders.
    Api { repo: Option<String>, number: u64 },
    /// A REST merge of one branch into another, with no PR.
    BranchMerge,
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
    /// A merge of one branch into another, with no PR to own.
    BranchMerge,
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

/// The largest GraphQL query file the guard reads.
const MAX_QUERY_FILE: u64 = 1 << 20;

/// A `GH_*` variable named as its own word (not `HIGH_PRIORITY`).
static GH_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])GH_[A-Za-z0-9_]*").expect("pattern should compile")
});

/// A `GIT_*` variable named as its own word (`GIT_DIR`, `GIT_WORK_TREE`).
static GIT_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])GIT_[A-Za-z0-9_]*").expect("pattern should compile")
});

/// Redirects that write nothing a later step reads: to `/dev/null`, or one
/// stream onto another (`2>&1`, `>&2`). Each must end at a token boundary
/// (captured as `b`): `>&1q.gql` writes the file `1q.gql`, and
/// `>/dev/null.x` a file under `/dev`.
static HARMLESS_REDIRECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:(?:\d*>>?|&>>?)\s*/dev/null|\d*>&\d+)(?P<b>$|[\s;&|)])")
        .expect("pattern should compile")
});

/// `text` with every [`HARMLESS_REDIRECT`] blanked out. The boundary
/// character is kept, so a `|` or `&` after a redirect still reads as one.
fn strip_harmless_redirects(text: &str) -> String {
    HARMLESS_REDIRECT.replace_all(text, " ${b}").into_owned()
}

/// Words that make a command more than a flat `&&`/`;`/`||` list: loops,
/// functions, wrappers that run a command elsewhere or repeatedly.
static NOT_FLAT_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[^A-Za-z0-9_])(?:for|while|until|select|function|coproc|if|then|else|elif|do|done|case|esac|eval|exec|xargs|find|source|bash|sh|zsh|dash)(?:[^A-Za-z0-9_]|$)",
    )
    .expect("pattern should compile")
});

/// What the rest of the command can do to the state a merge's lookup reads.
#[derive(Debug, Clone, Copy)]
struct Surroundings {
    /// No step can run before the merge, and the merge's own step has no
    /// wrapper or `GIT_*` prefix, so nothing can move the cwd, switch the
    /// branch, rewrite branch config, change the default repo, or write a
    /// file before the state the lookup read is used.
    inert: bool,
    /// A step that can run before the merge mentions a `GH_*` variable,
    /// which can repoint gh (`export GH_REPO=…`) even for an explicit `-R`.
    sets_gh_env: bool,
}

/// Whether `command` is a flat list of simple steps joined by `&&`, `;`, or
/// `||`, so its steps run in [`command_segments`] order and a step after the
/// merge cannot run before it. Pipes, background jobs, loops, substitutions,
/// and wrappers all make it not flat.
fn is_flat(command: &str) -> bool {
    if NOT_FLAT_WORD.is_match(command)
        || ["$(", "`", "<(", ">(", "()"]
            .iter()
            .any(|w| command.contains(w))
    {
        return false;
    }
    let joined = strip_harmless_redirects(command);
    let joined = joined.replace("||", " ").replace("&&", " ");
    !joined.contains(['|', '&'])
}

/// Whether a merge's own step runs gh somewhere other than the payload cwd
/// and repo: anything before `gh` except plain transparent prefixes (`env`
/// with no options, `time`, `command`, `nohup`, `nice`) and non-`GIT_*`
/// assignments. `find -execdir`, `xargs`, `sudo`, `env -C`, and
/// `GIT_DIR=…` all count.
fn own_step_is_wrapped(segment: &str) -> bool {
    let tokens = executable_tokens(segment);
    let Some(at) = tokens.iter().position(|t| command_word(t).as_ref() == "gh") else {
        return true;
    };
    tokens[..at].iter().any(|t| {
        if is_assignment_word(t) {
            return GIT_VAR.is_match(t);
        }
        !matches!(
            command_word(t).as_ref(),
            "env" | "time" | "command" | "nohup" | "nice"
        )
    })
}

/// Read a `-F query=@<path>` file against the payload cwd, capped. Opened
/// once and read through the cap, so a file that grows is not read whole.
fn read_query_file(path: &str, cwd: &str) -> Option<String> {
    use std::io::Read;
    if path.is_empty() || path == "-" || path.contains(['$', '`']) {
        return None;
    }
    let file = std::fs::File::open(std::path::Path::new(cwd).join(path)).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_QUERY_FILE + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_QUERY_FILE).then_some(text)
}

/// The merge call in a `gh api graphql` argv, if any. A query file is read
/// only when no earlier step can write it (`quiet_before`).
fn graphql_call(argv: &[String], cwd: &str, quiet_before: bool) -> Option<MergeCall> {
    let unreadable = Some(MergeCall::Unreadable(
        "a GraphQL query that is not inline (a query file is read only when no other step \
         of the command can write it first)",
    ));
    let Some(mut query) = graphql_query_value(argv) else {
        return unreadable;
    };
    if let Some(path) = query.strip_prefix('@') {
        match read_query_file(path, cwd).filter(|_| quiet_before) {
            Some(text) => query = text,
            None => return unreadable,
        }
    }
    // A query from a shell expansion cannot be read. Every real query has a
    // selection set, so one with no `{` is a shell variable (`query="$Q"`)
    // the tokenizer left unexpanded.
    if query.contains("$(") || query.contains('`') || !query.contains('{') {
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

/// Whether a computed endpoint is still certainly not a merge: its last
/// path segment is literal and is neither `merge` nor `merges`
/// (`repos/$R/issues/5/comments`).
fn computed_endpoint_rules_out_merge(endpoint: &str) -> bool {
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    let last = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    !last.is_empty()
        && !last.contains(['$', '`'])
        && !last.eq_ignore_ascii_case("merge")
        && !last.eq_ignore_ascii_case("merges")
}

/// The merge call in one `gh api` segment, if any.
fn api_call(segment: &str, argv: &[String], cwd: &str, quiet_before: bool) -> Option<MergeCall> {
    let endpoint = gh_api_endpoint(segment).unwrap_or_default();
    if is_graphql_endpoint(&endpoint) {
        return graphql_call(argv, cwd, quiet_before);
    }
    if !api_sends_write(segment) {
        return None;
    }
    if endpoint.is_empty() || endpoint.contains(['$', '`']) {
        if computed_endpoint_rules_out_merge(&endpoint) {
            return None;
        }
        return Some(MergeCall::Unreadable(
            "a `gh api` write whose endpoint the shell computes",
        ));
    }
    let path = endpoint_path(&endpoint);
    if BRANCH_MERGE_PATH.is_match(path) {
        return Some(MergeCall::BranchMerge);
    }
    let caps = PULL_MERGE_PATH.captures(path)?;
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

/// Whether a `gh pr merge` argv merges nothing: `--disable-auto` only
/// cancels a queued merge, and `--help` prints usage.
fn merges_nothing(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|t| matches!(t.as_str(), "--disable-auto" | "--help" | "-h"))
}

/// Every merge call in `command`, each with what the rest of the command
/// can do to the state its lookup reads.
///
/// In a flat list ([`is_flat`]) only the steps before a merge can change
/// that state, so `gh pr merge 5 && git pull` judges the merge alone. In
/// anything else every other step counts, since it may run first. Another
/// merge step counts like any other earlier step (`gh pr merge -d` checks
/// out the base branch), and so does a wrapper on
/// the merge's own step.
fn merge_calls(command: &str, cwd: &str) -> Vec<(MergeCall, Surroundings)> {
    let segments = command_segments(command);
    let flat = is_flat(command);
    let before = |idx: usize| {
        segments
            .iter()
            .enumerate()
            .filter(move |(i, _)| *i != idx && (!flat || *i < idx))
    };
    let mut calls: Vec<(usize, MergeCall)> = Vec::new();
    for (idx, segment) in segments.iter().enumerate() {
        // No `segment_invokes_gh` pre-filter: it reads `(gh` as one word that
        // is not `gh`, so `(gh pr merge 99)` was skipped before any walk below
        // ran. The walks decide, and the argv walk reads the segment without
        // its group wrappers for the same reason.
        let segment = strip_group_wrappers(segment);
        // The shared `gh pr` walk strips group punctuation (`merge)` inside
        // `$(…)`) and keeps the prefixes (`GH_REPO=`, `GH_HOST=`) that decide
        // which PR gh merges, so it is the one the lookup reads.
        let pr_merge = gh_pr_segments(segment)
            .into_iter()
            .find(|t| gh_pr_subcommand(t) == Some("merge"));
        let argv = gh_argv(segment);
        let argv_path = argv
            .as_deref()
            .map(|a| gh_command_path(a, 2))
            .unwrap_or_default();
        let quiet_before = || before(idx).next().is_none();
        let call = match (pr_merge, argv_path.as_slice()) {
            (Some(tokens), _) if merges_nothing(&tokens) => None,
            (Some(tokens), _) => Some(MergeCall::Pr { tokens }),
            // A merge only the argv walk sees has no tokens to look up.
            (None, ["pr", "merge"]) if !argv.as_deref().is_some_and(merges_nothing) => Some(
                MergeCall::Unreadable("a `gh pr merge` the guard cannot read"),
            ),
            (None, ["api", ..]) => argv
                .as_deref()
                .and_then(|a| api_call(segment, a, cwd, quiet_before())),
            _ => None,
        };
        if let Some(call) = call {
            calls.push((idx, call));
        }
    }
    calls
        .into_iter()
        .map(|(idx, call)| {
            let around = Surroundings {
                inert: !own_step_is_wrapped(&segments[idx]) && before(idx).next().is_none(),
                sets_gh_env: before(idx).any(|(_, s)| GH_VAR.is_match(s)),
            };
            (call, around)
        })
        .collect()
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

/// Why a lookup cannot be trusted when another step of the command can
/// change what it reads, or `None` when it can. `explicit` is a merge that
/// names its repo itself (`-R`, a URL, or a literal REST path), so only a
/// `GH_*` change can repoint it.
fn surroundings_block(explicit: bool, around: Surroundings) -> Option<Finding> {
    if around.sets_gh_env {
        return Some(Finding::Unresolved(
            "another step of the command sets a `GH_*` variable, which can change the PR gh merges",
        ));
    }
    if !explicit && !around.inert {
        return Some(Finding::Unresolved(
            "another step of the command can change the directory, branch, or default repo \
             the merge resolves its PR from",
        ));
    }
    None
}

/// Look up a `gh pr merge`'s PR and rule on it.
fn judge_pr(
    tokens: &[String],
    around: Surroundings,
    input: &HookInput,
    gh: &GhFactory<'_>,
) -> Option<Finding> {
    let unresolved = Some(Finding::Unresolved(
        "the guard cannot tell which PR it merges",
    ));
    let Some(target) = FlipTarget::from_tokens(tokens) else {
        return unresolved;
    };
    let explicit = match &target.selector {
        PrSelector::Url { .. } => true,
        PrSelector::Number(_) | PrSelector::Other(_) => target.repo.repo_arg().is_some(),
        PrSelector::None | PrSelector::Unreadable => false,
    };
    if let Some(finding) = surroundings_block(explicit, around) {
        return Some(finding);
    }
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
    around: Surroundings,
    input: &HookInput,
    gh: &GhFactory<'_>,
) -> Option<Finding> {
    if let Some(finding) = surroundings_block(repo.is_some(), around) {
        return Some(finding);
    }
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
            "`gh pr view` gave no head branch (it failed, timed out, or the hook ran out of \
             time before calling it)",
        )),
    }
}

/// Judge a command. `remote` is whether this is a cloud session.
fn judge(command: &str, remote: bool, input: &HookInput, gh: &GhFactory<'_>) -> Option<Finding> {
    if !remote || !may_spell_word(command, "gh") {
        return None;
    }
    let cwd = input.cwd.clone().unwrap_or_else(|| ".".to_string());
    merge_calls(command, &cwd)
        .into_iter()
        .find_map(|(call, around)| match call {
            MergeCall::Pr { tokens } => judge_pr(&tokens, around, input, gh),
            MergeCall::Api { repo, number } => {
                judge_api(repo.as_deref(), number, around, input, gh)
            }
            MergeCall::BranchMerge => Some(Finding::BranchMerge),
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
        Finding::BranchMerge => (
            "this `gh api` call merges one branch into another with no PR, so there is no PR to own"
                .to_string(),
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
            "run the merge as its own command and name the PR (`gh pr merge <n> -R owner/repo`), \
             or post your result on the PR for the local chief-of-staff to merge",
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
        cloud_in("/nonexistent-cloud-merge-test", command, answer)
    }

    /// [`cloud_with`] with the payload cwd set to `cwd`.
    fn cloud_in(
        cwd: &str,
        command: &str,
        answer: Option<String>,
    ) -> (CheckResult, Vec<Vec<String>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&calls);
        let mut input = make_bash(command);
        input.cwd = Some(cwd.to_string());
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
            // Round 6: a `(` glued to `gh` used to skip the step entirely.
            "(gh pr merge 99)",
            "(gh pr merge 99 --squash) 2>&1 | tail -5",
            "(gh pr merge 99 --squash && echo ok) || echo failed",
            "true; (gh pr merge 99)",
            "(gh api -X PUT repos/e/x/pulls/9/merge)",
            "(gh api graphql -f query='mutation { mergePullRequest(input: {}) { clientMutationId } }')",
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
            "gh pr merge --help",
            "gh api repos/$GITHUB_REPOSITORY/issues/5/comments -f body=hi",
            "gh api -X POST \"repos/$REPO/issues/5/labels\" -f labels[]=x",
        ] {
            let (result, calls) = cloud_with(command, None);
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
            assert!(calls.is_empty(), "{command}: {calls:?}");
        }
    }

    #[test]
    fn a_step_that_can_change_the_merged_pr_blocks_without_a_lookup() {
        // Security review C1: each earlier step changes which PR gh merges,
        // while the lookup would read the state from before the command.
        for command in [
            "gh pr checkout 7 && gh pr merge --squash",
            "git switch feat/x && gh pr merge --squash",
            "git checkout -b tmp origin/feat && gh pr merge",
            "cd /tmp/other && gh pr merge 5 --squash",
            "cd x; gh pr merge 5",
            "bash -c \"cd x && gh pr merge 5\"",
            "cd /tmp/other && gh api -X PUT repos/{owner}/{repo}/pulls/5/merge",
            "export GH_REPO=a/b; gh pr merge 5",
            "GH_REPO=a/b; gh pr merge 5",
            "export GH_REPO=a/b; gh api -X PUT repos/{owner}/{repo}/pulls/5/merge",
            "gh repo set-default a/b && gh pr merge 5",
            "export GH_HOST=ghe.example; gh pr merge 5 -R o/r",
            "x=$(gh pr checkout 7 && gh pr merge)",
            "gh api -X PATCH \"repos/$REPO/pulls/$N\" -f title=x",
        ] {
            let (result, calls) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Block, "{command}");
            assert!(calls.is_empty(), "{command}: {calls:?}");
        }
    }

    #[test]
    fn an_explicit_or_undisturbed_merge_still_looks_up() {
        for command in [
            "cd /tmp/other && gh pr merge 5 -R o/r",
            "cd /tmp/other && gh pr merge https://github.com/o/r/pull/5",
            "cd /tmp/other && gh api -X PUT repos/o/r/pulls/5/merge",
            "git status && gh pr merge 5 -R o/r --squash",
            "gh pr view 5 --json headRefName && gh pr merge 5 -R o/r",
        ] {
            let (result, calls) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
            assert_eq!(calls.len(), 1, "{command}: {calls:?}");
        }
    }

    #[test]
    fn a_gh_repo_prefix_reaches_the_lookup() {
        let (_, calls) = cloud_with(
            "GH_REPO=a/b gh pr merge 5",
            Some(pr_json(OWN, false, &[], URL)),
        );
        assert_eq!(
            calls,
            vec![vec![
                "pr",
                "view",
                "--json",
                PR_VIEW_FIELDS,
                "-R",
                "a/b",
                "--",
                "5"
            ]]
        );
    }

    #[test]
    fn branch_merges_block() {
        for command in [
            "gh api -X POST repos/o/r/merges -f base=main -f head=feat",
            "gh api repos/o/r/merges -f base=main -f head=feat",
            "gh api graphql -f query='mutation { mergeBranch(input: {repositoryId: \"R\"}) { clientMutationId } }'",
        ] {
            let (result, calls) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Block, "{command}");
            assert!(calls.is_empty(), "{command}: {calls:?}");
        }
        let (result, _) = cloud_with("gh api repos/o/r/merges", None);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn a_graphql_query_file_is_read_only_when_the_call_stands_alone() {
        let dir = std::env::temp_dir().join(format!("cloud-merge-q-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("read.graphql"), "query { viewer { login } }").unwrap();
        std::fs::write(
            dir.join("merge.graphql"),
            "mutation { mergePullRequest(input: {pullRequestId: \"P\"}) { clientMutationId } }",
        )
        .unwrap();
        let cwd = dir.to_str().unwrap();
        let run = |command: &str| cloud_in(cwd, command, None).0.outcome;
        assert_eq!(run("gh api graphql -F query=@read.graphql"), Outcome::Allow);
        assert_eq!(
            run("gh api graphql -F query=@merge.graphql"),
            Outcome::Block
        );
        assert_eq!(
            run("cp merge.graphql read.graphql && gh api graphql -F query=@read.graphql"),
            Outcome::Block
        );
        assert_eq!(
            run("gh api graphql -F query=@missing.graphql"),
            Outcome::Block
        );
        // A pipe runs its steps together, so `jq` may run first: the file is
        // not read (round 5 removed the read-only list).
        assert_eq!(
            run("gh api graphql -F query=@read.graphql | jq .data"),
            Outcome::Block
        );
        assert_eq!(
            run("gh api graphql -F query=@merge.graphql | jq .data"),
            Outcome::Block
        );
        assert_eq!(
            run("cp merge.graphql read.graphql | gh api graphql -F query=@read.graphql"),
            Outcome::Block
        );
        // Security review round 3: `>&1q.gql` is a file write, not `>&1`.
        std::fs::write(dir.join("1q.gql"), "query { viewer { login } }").unwrap();
        assert_eq!(
            run(
                "echo 'mutation { mergePullRequest(input: {}) { clientMutationId } }' >&1q.gql; gh api graphql -F query=@1q.gql"
            ),
            Outcome::Block
        );
        assert_eq!(run("gh api graphql -F query=@1q.gql"), Outcome::Allow);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn steps_after_the_merge_in_a_flat_list_do_not_count() {
        // Second review round I2: these are routine merge-then-sync shapes.
        for command in [
            "gh pr merge 5 --squash && git pull",
            "gh pr merge --squash --delete-branch && git checkout main && git pull",
            "gh pr merge 5; git switch main",
            "gh pr merge 5 --squash 2>/dev/null && git pull",
            "gh pr view 5 2>&1 && gh pr merge 5 -R o/r --squash",
            "echo done >&2 && gh pr merge 5 -R o/r",
            // `GH_` matches a whole word, so this is not a `GH_*` change.
            "echo HIGH_PRIORITY && gh pr merge 5 -R o/r",
            "git add . && git commit -m x && gh pr merge 5 -R o/r --squash",
            "git push && gh pr merge 5 -R o/r --squash",
            "git push -u origin HEAD && gh pr merge https://github.com/o/r/pull/5",
            "git status 2>/dev/null >&2 && gh pr merge 5 -R o/r",
        ] {
            let (result, calls) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
            assert_eq!(calls.len(), 1, "{command}: {calls:?}");
        }
    }

    #[test]
    fn the_merge_steps_own_side_effects_count() {
        // Second review round I1: an earlier merge checks out the base, and a
        // wrapper or `GIT_*` prefix points gh at another checkout.
        for command in [
            "gh pr merge -d --squash && gh pr merge --squash",
            "gh pr merge 5 -R o/r -d && gh pr merge",
            "GIT_DIR=../other/.git gh pr merge",
            "GIT_WORK_TREE=../other gh pr merge 5",
            "find ../other -maxdepth 0 -execdir gh pr merge \\;",
            "env -C ../other gh pr merge 5",
            "sudo -u bot gh pr merge 5",
            "eval \"gh pr merge 5\"",
            "gh pr merge 5 | git checkout x",
            "gh pr merge 5 & git checkout x",
            "for i in 1; do gh pr merge 5; git checkout x; done",
            // Round 5: an implicit merge must come first. Each earlier miss
            // came from a step a read-only list let through.
            "git fetch --set-upstream fork claude/x && gh pr merge --squash",
            "git add . && git commit -m x && gh pr merge --squash",
            "git status && gh pr merge --squash",
            "echo hi && gh pr merge 5",
            "gh pr merge 4 -R o/r && gh pr merge 5",
            // `git push -u` repoints the upstream a selector-less merge reads.
            "git push -u fork HEAD && gh pr merge --squash",
            "git push && gh pr merge",
            "git push && gh pr merge 5",
            // The PR does not exist when the lookup runs.
            "gh pr create --fill && gh pr merge --auto",
            // A redirect to a real file is a write (`>&2q` writes `2q`).
            "echo x > f && gh pr merge 5",
            "echo hi >&2q && gh pr merge 5",
            "echo hi >/dev/null.x && gh pr merge 5",
            "echo hi 2>/dev/null| git checkout x; gh pr merge 5",
        ] {
            let (result, _) = cloud_with(command, Some(pr_json(OWN, false, &[], URL)));
            assert_eq!(result.outcome, Outcome::Block, "{command}");
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
