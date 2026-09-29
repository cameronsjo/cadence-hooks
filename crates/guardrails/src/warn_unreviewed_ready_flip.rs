//! Warn on `gh pr ready` / `gh pr merge` when the PR's head SHA carries
//! neither a human approval nor a cadence-dispatched review marker.
//!
//! CodeRabbit's retirement (cameronsjo/cadence#1037) replaced the bot review
//! with a convention: a dispatched reviewer's findings are posted on the PR
//! as a COMMENT review whose body's first line is a machine-readable marker
//! —`<!-- cadence-review: <reviewer> head=<40-char SHA> crit=<n> imp=<n> -->` — and
//! "reviewed" means that marker reads `crit=0 imp=0` on the current head, or
//! a non-author human review is APPROVED on it — and no reviewer's latest
//! decisive review is `CHANGES_REQUESTED`
//! (`cadence-forge:review-loop` § What "reviewed" means). An outstanding
//! request is head-independent, so the nudge names the dismissal command for
//! the operator rather than leaving a condition nobody can see how to clear
//! (cadence-hooks#978). This is the
//! deterministic backstop at the Ready-flip capture point, sibling to
//! `warn-plan-ready-flip`'s reconcile check.
//!
//! Advisory only — nudges, never blocks — and fails open (ADR-0001) on any
//! `gh` fetch error, JSON parse error, or unresolvable PR: an indeterminate
//! answer must never read as a block.
//!
//! The PR is resolved the way gh resolves it, not from `origin`
//! (cadence-hooks#1028, #920). A PR URL names its own repo. A number goes
//! to the `-R`/`--repo` repo when the command names one, and
//! otherwise to gh's `{owner}`/`{repo}` placeholders, run in the session cwd
//! (the hook payload's `cwd`; a leading `cd x &&` is not tracked) so gh picks
//! the repo it would pick there. No selector, or a branch name, is looked up
//! with `gh pr view` first (two calls). A repo flag with no selector,
//! conflicting repo values, or an unreadable selector stays silent: each is a
//! deliberate fail-open allow.
//!
//! The hook runs before the user approves the command, so it never sends a
//! request to a host the command text names unless that host is `github.com`
//! or `origin`'s host (local config). Any other host (from a PR URL, an
//! `-R HOST/OWNER/REPO`, or a URL-shaped selector) stays silent: gh would
//! otherwise contact a host the user has not approved, and send it
//! `GH_ENTERPRISE_TOKEN` when that is set.

use cadence_hooks_core::shell::{
    PrSelector, git_command, host_and_repo_from_url, pr_flip_segments, pr_selector, pr_url_parts,
    ship_target,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

/// The cadence-review marker: first line of a COMMENT review body.
/// `crit` and `imp` must both be `0` and `head` must equal the PR's current
/// head SHA for the marker to count as "reviewed".
///
/// This pattern is a **character-for-character translation** of the other
/// consumer of the same marker — `poll-prs.sh`'s `CADENCE_MARKER_RE` in
/// cameronsjo/cadence — with the bash ERE's positional groups given names:
///
/// ```text
/// ^<!-- cadence-review: [^ ]+ head=([0-9a-fA-F]{40}) crit=([0-9]+) imp=([0-9]+) -->
/// ```
///
/// Three things were looser here and are not any more
/// (cameronsjo/cadence-hooks#879):
///
/// - `head=` took any hex length; the bash side and
///   `cadence-forge:review-loop` § What "reviewed" means both say 40 ("the
///   full 40-char SHA. Anything shorter never matches").
/// - Every separator was `\s+` or `\s*`, so a tab, a double space, a newline
///   mid-marker, or a missing space before `-->` parsed here and did not
///   there. That direction is the dangerous one: this guard would read
///   "reviewed" on a marker the review loop's own poller never accepts.
/// - `\d` is Unicode-aware in this crate, so `crit=` accepted non-ASCII
///   digits; the bash side takes `[0-9]+`.
///
/// `\S+` for the reviewer field becomes `[^ ]+` for the same reason, in the
/// other direction: `\S` rejects a tab inside the reviewer token that the
/// bash side accepts. That is the one divergence `marker-shape.test.sh`
/// already conceded with "no fixture case"; it now has one, here.
///
/// None of this changes a verdict on a well-formed marker, and the `{40}` cap
/// changes no verdict at all, because [`is_reviewed`] compares the captured
/// SHA to the PR's full head for equality. The point is that one contract
/// with two parsers needs the parsers to accept the same strings; a gap only
/// one side enforces drifts again, and the next gap may not be harmless.
///
/// The pattern alone is not the contract. [`is_reviewed`] matches it against
/// the body's **first line, untrimmed** — the same string `poll-prs.sh` gets
/// from `split("\n")[0]` — and both halves of that close a divergence the
/// pattern could not:
///
/// - It used to match `body.trim_start()`, so a marker behind a blank line or
///   an indent cleared here and not there.
/// - It used to match the whole body. A negated character class in this crate
///   matches `\n` (only `.` excludes it), so `[^ ]+` on the reviewer field
///   swallowed a newline and a marker spanning two lines parsed here while
///   jq, handed one line, rejected it.
///
/// Both ran the same direction as the separators above: silence on a marker
/// the review loop's own poller never accepts. Leniency on a *positive*
/// signal is the under-nudging failure mode for a guard whose job is catching
/// an unreviewed flip, and the contract's own rule is that the marker is the
/// first line.
static MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^<!-- cadence-review: (?P<reviewer>[^ ]+) head=(?P<head>[0-9a-fA-F]{40}) crit=(?P<crit>[0-9]+) imp=(?P<imp>[0-9]+) -->",
    )
    .expect("pattern should compile")
});

/// Runs `gh` CLI commands, returning trimmed stdout on success or `None` on
/// error. Shared seam with `verify_pr_autoclose::GhRunner` in shape (not
/// reused directly — the two hooks fetch different endpoints and keeping
/// them independent avoids coupling an advisory nudge's tests to the
/// autoclose flow's fixtures).
pub trait GhRunner {
    fn run(&self, args: &[&str]) -> Option<String>;
}

/// The tokens of the first `gh pr ready` / `gh pr merge` segment in
/// `command`, or `None` when no segment is one. The matcher is the shared
/// [`pr_flip_segments`], so the retargeted and prefixed spellings the ship
/// anchor already sees (`gh -R o/r pr merge 5`, `GH_REPO=o/r gh pr merge 5`,
/// `env … gh pr merge 5`, a keyword-led `then gh pr merge 5`) are checked
/// here too (cadence-hooks#778), and `gh pr ready --undo` is excluded there.
/// Only that first flip segment is examined later; a second flip in the same
/// compound command is not checked.
fn flip_segment_tokens(command: &str) -> Option<Vec<String>> {
    pr_flip_segments(command).into_iter().next()
}

/// Which repo gh will query for the flipped PR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoChoice {
    /// The command names no repo: gh picks it from the cwd's git remotes.
    GhDefault,
    /// Every `-R`/`--repo` value names this one repo. Each part passed
    /// [`parse_repo_value`]'s charset check; gh gets them re-serialised
    /// ([`RepoChoice::repo_arg`]), never the value as typed.
    Explicit {
        host: Option<String>,
        owner: String,
        name: String,
    },
}

impl RepoChoice {
    /// The `-R` argument for gh, built only from parsed parts.
    fn repo_arg(&self) -> Option<String> {
        match self {
            RepoChoice::GhDefault => None,
            RepoChoice::Explicit {
                host: Some(host),
                owner,
                name,
            } => Some(format!("{host}/{owner}/{name}")),
            RepoChoice::Explicit {
                host: None,
                owner,
                name,
            } => Some(format!("{owner}/{name}")),
        }
    }
}

/// An owner or repo name the hook will pass to gh: ASCII letters, digits,
/// `.`, `_`, `-`, and no leading `-`.
fn is_safe_name(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('-')
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A host name the hook will pass to gh: ASCII letters, digits, `.`, `-`,
/// and no leading `-`.
fn is_safe_host(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('-')
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// Parse a `-R`/`--repo` value into `(host, owner, name)` the way go-gh does,
/// or `None` when the hook cannot be sure it reads it as gh does
/// (security review I1, round 2).
///
/// go-gh reads a value as a URL only when it starts with `git@` or a scheme;
/// otherwise it splits on `/` into `[HOST/]OWNER/REPO`. The hook does not
/// model the URL forms, so any value that could be one (`git@`, or any `:`)
/// is refused. So is any part outside the safe charsets, which rules out
/// `@`, `%`, whitespace, and non-ASCII. `github.com:x@evil.example/o/r` is the
/// case this closes: a remote-URL parser reads its host as `github.com`,
/// while gh splits it on `/` and connects to `evil.example`.
fn parse_repo_value(value: &str) -> Option<(Option<String>, String, String)> {
    if value.starts_with("git@") || value.contains(':') {
        return None;
    }
    let (host, owner, name) = match value.split('/').collect::<Vec<_>>().as_slice() {
        [owner, name] => (None, *owner, *name),
        [host, owner, name] => (Some(*host), *owner, *name),
        _ => return None,
    };
    if !is_safe_name(owner) || !is_safe_name(name) || !host.is_none_or(is_safe_host) {
        return None;
    }
    Some((
        host.map(str::to_ascii_lowercase),
        owner.to_string(),
        name.to_string(),
    ))
}

/// Where a flip points gh: the repo, the PR selector, and the host the
/// command text names (`None` when it names none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlipTarget {
    pub repo: RepoChoice,
    pub selector: PrSelector,
    /// The host `GH_HOST` is set to: a PR URL's, else an `-R HOST/…` one,
    /// else an inline `GH_HOST=`.
    pub host: Option<String>,
    /// Every host the command text names, lowercased, from any of those
    /// sources plus a URL-shaped `Other` selector. [`evaluate`] queries none
    /// of them unless each is trusted ([`hosts_are_trusted`]).
    pub named_hosts: Vec<String>,
}

/// The host of a URL-shaped selector gh would contact (`scheme://HOST/…`).
/// `Some(None)` when the token has a `://` but no bare hostname can be read
/// from it (userinfo, a port, an odd character), `None` when it is not
/// URL-shaped at all.
fn url_shaped_host(token: &str) -> Option<Option<String>> {
    static URL_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://([A-Za-z0-9.-]+)(?:/|$)")
            .expect("pattern should compile")
    });
    if !token.contains("://") {
        return None;
    }
    Some(
        URL_HOST_RE
            .captures(token)
            .map(|c| c[1].to_ascii_lowercase()),
    )
}

/// True when every repo value is empty and each one comes from a spelling
/// that names an empty value on purpose: `--repo=`, `-R=`, or `-R ""` /
/// `--repo ""`. gh reads an empty `-R` as "no override" and flips the cwd
/// repo's PR. An empty value from anything else (the scan's placeholder after
/// an unknown flag, or a flag with nothing after it) is not counted, so the
/// caller stays silent for it.
fn repo_values_are_deliberately_empty(tokens: &[String], repos: &[String]) -> bool {
    if repos.is_empty() || repos.iter().any(|r| !r.is_empty()) {
        return false;
    }
    let spelled = tokens
        .iter()
        .enumerate()
        .filter(|(i, t)| {
            matches!(t.as_str(), "--repo=" | "-R=")
                || (matches!(t.as_str(), "--repo" | "-R")
                    && tokens.get(i + 1).is_some_and(String::is_empty))
        })
        .count();
    spelled == repos.len()
}

/// True when every host in `named` is `github.com` or `origin_host`.
/// `origin_host` comes from local git config, so it is trusted; a host the
/// command text alone names is not.
pub fn hosts_are_trusted(named: &[String], origin_host: Option<&str>) -> bool {
    named.iter().all(|h| {
        h.eq_ignore_ascii_case("github.com")
            || origin_host.is_some_and(|o| h.eq_ignore_ascii_case(o))
    })
}

impl FlipTarget {
    /// Read the target from one flip segment's tokens. `None` when the repo
    /// values disagree or one does not parse, or when a URL-shaped selector
    /// has no readable host: gh's target is then unknown, and staying silent
    /// is a deliberate fail-open allow (ADR-0001).
    ///
    /// `pub` so the other flip-anchored nudges (`warn-stale-pr-body`,
    /// `warn-stacked-base-delete`) resolve the PR the same hardened way.
    pub fn from_tokens(tokens: &[String]) -> Option<Self> {
        let ship = ship_target(tokens);
        let selector = pr_selector(tokens);
        let mut repo_host: Option<String> = None;
        let repo =
            if ship.repos.is_empty() || repo_values_are_deliberately_empty(tokens, &ship.repos) {
                RepoChoice::GhDefault
            } else {
                let parsed = ship
                    .repos
                    .iter()
                    .map(|value| parse_repo_value(value))
                    .collect::<Option<Vec<_>>>()?;
                // GitHub owner and repo names are case-insensitive.
                let key = |(h, o, n): &(Option<String>, String, String)| {
                    (h.clone(), o.to_ascii_lowercase(), n.to_ascii_lowercase())
                };
                let (host, owner, name) = parsed.first()?.clone();
                if parsed.iter().any(|p| key(p) != key(&parsed[0])) {
                    return None;
                }
                repo_host.clone_from(&host);
                RepoChoice::Explicit { host, owner, name }
            };
        // A PR URL's owner and repo reach gh as GraphQL variables; hold them
        // to the same charset as a repo value.
        if matches!(&selector, PrSelector::Url { owner, repo, .. }
            if !(is_safe_name(owner) && is_safe_name(repo)))
        {
            return None;
        }
        let url_host = match &selector {
            PrSelector::Url { host, .. } => Some(host.clone()),
            _ => None,
        };
        // A selector gh would read as a URL of some other shape (`http://`,
        // a non-PR path) still makes `gh pr view` contact its host.
        let other_url_host = match &selector {
            PrSelector::Other(sel) => match url_shaped_host(sel) {
                None => None,
                Some(Some(host)) => Some(host),
                // URL-shaped with no readable host: fail-open allow.
                Some(None) => return None,
            },
            _ => None,
        };
        let named_hosts = [&url_host, &repo_host, &ship.host, &other_url_host]
            .into_iter()
            .flatten()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        Some(FlipTarget {
            repo,
            selector,
            host: url_host.or(repo_host).or(ship.host),
            named_hosts,
        })
    }
}

/// A parsed review: the author's login and, for a formal review, its state
/// and the commit SHA it was submitted against; for a cadence review, its
/// body (the marker lives in the body's first line).
///
/// `id` is the review's REST id (`databaseId`), which the dismissal command
/// names. `author_id` is the reviewer's numeric account id, the key
/// [`outstanding_changes_requested`] groups on; either is `None` when the
/// response carries no number for it.
struct ParsedReview {
    id: Option<u64>,
    author_id: Option<u64>,
    login: String,
    state: String,
    commit_id: String,
    body: String,
}

/// The PR's head, author, and its newest reviews in one GraphQL request.
///
/// `last: 100`, not the REST reviews list: that list is oldest-first and
/// returns 30 per page, so on a PR with more than 30 reviews the newest ones —
/// the ones that can match the current head — were never fetched.
///
/// The reviewer's numeric id and the review's own id serve the
/// `CHANGES_REQUESTED` half of the contract (cadence-hooks#978). The PR's
/// issue comments are read only to recognise a marker posted in the wrong
/// place (cadence-hooks#838); they never count as a reviewed signal.
const PR_STATE_QUERY: &str = "query($owner: String!, $name: String!, $number: Int!) { \
    repository(owner: $owner, name: $name) { pullRequest(number: $number) { \
    headRefOid author { login } \
    reviews(last: 100) { nodes { databaseId \
    author { login ... on User { databaseId } ... on Bot { databaseId } } \
    state commit { oid } body } } \
    comments(last: 100) { nodes { body } } } } }";

/// The fields [`evaluate`] needs from [`PR_STATE_QUERY`]'s response.
struct PrState {
    head: String,
    author: String,
    reviews: Vec<ParsedReview>,
    /// Issue-comment bodies, oldest first. Empty when the response has none.
    comments: Vec<String>,
}

/// Parse a [`PR_STATE_QUERY`] response. `None` on any parse failure or a
/// missing pull request — the caller reads that as fail-open. A deleted
/// account (`author: null`) or a review with no commit reads as an empty
/// string, which matches no login and no head.
fn parse_pr_state(json: &str) -> Option<PrState> {
    let str_at = |v: &serde_json::Value, path: &[&str]| -> String {
        path.iter()
            .try_fold(v, |acc, key| acc.get(key))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    // GraphQL can answer with partial `data` next to `errors`; a verdict
    // built from part of the reviews is worse than none, so fail open.
    if value.get("errors").is_some() {
        return None;
    }
    let pr = value.get("data")?.get("repository")?.get("pullRequest")?;
    let head = pr.get("headRefOid")?.as_str()?.to_string();
    let reviews = pr
        .get("reviews")?
        .get("nodes")?
        .as_array()?
        .iter()
        .map(|r| ParsedReview {
            id: r.get("databaseId").and_then(serde_json::Value::as_u64),
            author_id: r
                .get("author")
                .and_then(|a| a.get("databaseId"))
                .and_then(serde_json::Value::as_u64),
            login: str_at(r, &["author", "login"]),
            state: str_at(r, &["state"]),
            commit_id: str_at(r, &["commit", "oid"]),
            body: str_at(r, &["body"]),
        })
        .collect();
    // Comments feed only the misplaced-marker hint, so a response without
    // them reads as none rather than failing the whole verdict.
    let comments = pr
        .get("comments")
        .and_then(|c| c.get("nodes"))
        .and_then(serde_json::Value::as_array)
        .map(|nodes| nodes.iter().map(|c| str_at(c, &["body"])).collect())
        .unwrap_or_default();
    Some(PrState {
        head,
        author: str_at(pr, &["author", "login"]),
        reviews,
        comments,
    })
}

/// Is the PR reviewed at `head`, per `cadence-forge:review-loop` § What
/// "reviewed" means? Both halves of that contract must hold
/// (cadence-hooks#978): an approval signal on `head`
/// ([`has_approval_signal`]), and no outstanding `CHANGES_REQUESTED`
/// ([`outstanding_changes_requested`]).
fn is_reviewed(reviews: &[ParsedReview], head: &str, author: &str) -> bool {
    has_approval_signal(reviews, head, author) && outstanding_changes_requested(reviews).is_empty()
}

/// The contract's second half, as `poll-prs.sh`'s
/// `changes_requested_outstanding` computes it: group the reviews by
/// reviewer, take each reviewer's most recent *decisive* review (`APPROVED`
/// or `CHANGES_REQUESTED`), and return every one of those that requests
/// changes. `COMMENTED` and `PENDING` carry no verdict, and a dismissed
/// review's state becomes `DISMISSED`, so a dismissal clears it.
///
/// The key is the reviewer's numeric id, never the login, for the reason
/// `poll-prs.sh` gives: two deleted accounts both read as an empty login, and
/// grouping on it would let one's approval clear the other's block. A review
/// with no id forms a group of one, so an unattributable block is never
/// cleared.
///
/// The block is head-independent: a push does not clear it. That is the
/// operator's ruling on cadence-hooks#978, option (a), and it is safe only
/// because this guard nudges and never blocks. Only the newest 100 reviews
/// are read ([`PR_STATE_QUERY`]), so a request older than that is not seen.
fn outstanding_changes_requested(reviews: &[ParsedReview]) -> Vec<&ParsedReview> {
    let mut latest: Vec<(Option<u64>, &ParsedReview)> = Vec::new();
    for review in reviews {
        if review.state != "APPROVED" && review.state != "CHANGES_REQUESTED" {
            continue;
        }
        match review
            .author_id
            .and_then(|id| latest.iter_mut().find(|(key, _)| *key == Some(id)))
        {
            // Reviews arrive oldest first, so a later one replaces the earlier.
            Some(slot) => slot.1 = review,
            None => latest.push((review.author_id, review)),
        }
    }
    latest
        .into_iter()
        .map(|(_, review)| review)
        .filter(|review| review.state == "CHANGES_REQUESTED")
        .collect()
}

/// Does `reviews` carry a signal that counts as an approval for `head`,
/// authored by anyone other than `author`?
///
/// Two independent signals, either sufficient: a non-author human review
/// APPROVED on `head`, or a cadence-review marker whose `head` matches and
/// whose `crit`/`imp` are both zero. A marker or approval on a stale head
/// (a push since the review) does not count.
fn has_approval_signal(reviews: &[ParsedReview], head: &str, author: &str) -> bool {
    reviews.iter().any(|r| {
        // The non-author restriction applies only to a formal human APPROVED
        // review (self-approval proves nothing) — the cadence-review marker
        // is posted by the orchestrator's own token on the author's behalf,
        // never the PR author's, so it carries no author check.
        let formal_approved = r.login != author && r.state == "APPROVED" && r.commit_id == head;
        // The first line, taken as received, and nothing else — the same
        // string `poll-prs.sh` matches against (`split("\n")[0]`, untrimmed).
        // Both halves are load-bearing, and neither is obvious:
        //
        // - No trim. A marker behind a blank line or an indent is not the
        //   first line, and the bash side rejects it.
        // - One line only. Matching the whole body is not equivalent even
        //   with an identical pattern, because a negated character class in
        //   this crate matches `\n` (only `.` excludes it). So `[^ ]+` on the
        //   reviewer field would swallow a newline and let a marker spanning
        //   two lines parse here while jq — handed one line — rejects it.
        //
        // Regex-text parity is not consumer parity: what the caller slices
        // bounds the accepted language as much as the pattern does.
        let first_line = r.body.split('\n').next().unwrap_or_default();
        let marker_clean = MARKER_RE
            .captures(first_line)
            .is_some_and(|c| &c["head"] == head && &c["crit"] == "0" && &c["imp"] == "0");
        formal_approved || marker_clean
    })
}

/// The opening every well-formed marker starts with, as [`MARKER_RE`] spells it.
const MARKER_OPENING: &str = "<!-- cadence-review: ";

/// Does `body` look like an attempt at a cadence-review marker? An HTML
/// comment and the word `cadence-review` anywhere in it. Used only to word
/// the nudge ([`marker_hint`]); it never decides a verdict.
fn mentions_marker(body: &str) -> bool {
    body.contains("<!--") && body.contains("cadence-review")
}

/// What is wrong with a marker line [`MARKER_RE`] rejected, as static field
/// names (cadence-hooks#838). Every problem found is listed, since one marker
/// can carry several. Nothing from the line itself is echoed except a
/// character count: the body is PR text and the nudge reaches the session.
fn marker_problems(first_line: &str) -> Vec<String> {
    let Some(rest) = first_line.strip_prefix(MARKER_OPENING) else {
        return vec![
            "the review body's first line must be the marker, opening exactly \
             `<!-- cadence-review: `"
                .to_string(),
        ];
    };
    let fields: Vec<&str> = rest.split(' ').collect();
    let mut problems = Vec::new();
    if fields.first().is_none_or(|f| f.contains('=')) {
        problems.push("the `<reviewer>` field before `head=` is missing".to_string());
    }
    match fields.iter().find_map(|f| f.strip_prefix("head=")) {
        None if fields.iter().any(|f| f.starts_with("sha=")) => {
            problems.push("expected `head=<40-char SHA>`, found `sha=`".to_string());
        }
        None => problems.push("the `head=` field is missing".to_string()),
        Some(sha) if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) => {
            problems.push(format!(
                "`head=` must be the full 40-character SHA (found {} characters)",
                sha.chars().count()
            ));
        }
        Some(_) => {}
    }
    for field in ["crit=", "imp="] {
        if !fields.iter().any(|f| f.starts_with(field)) {
            problems.push(format!("the `{field}` field is missing"));
        }
    }
    if problems.is_empty() {
        problems.push(
            "the fields are separated by something other than single spaces, a count is not \
             ASCII digits, or the closing ` -->` is missing"
                .to_string(),
        );
    }
    problems
}

/// A sentence for the no-signal nudge when the PR carries a marker the guard
/// saw and could not use, so a session that posted one learns why it did not
/// count rather than reading the nudge as "you posted nothing"
/// (cadence-hooks#838). `None` when no review or comment mentions a marker.
///
/// The two places have different fixes, so they are told apart: a marker on
/// a review that does not parse names its broken fields; a marker only on an
/// issue comment has to be posted again as a review. The newest review with a
/// broken marker wins; a comment is reported only when no review mentions a
/// marker at all. A marker that parses but names another head or non-zero
/// counts is not a shape problem, and the main message already covers it.
fn marker_hint(state: &PrState) -> Option<String> {
    let reviews: Vec<&ParsedReview> = state
        .reviews
        .iter()
        .filter(|r| mentions_marker(&r.body))
        .collect();
    if let Some(broken) = reviews.iter().rev().find_map(|r| {
        let first_line = r.body.split('\n').next().unwrap_or_default();
        (!MARKER_RE.is_match(first_line)).then_some(first_line)
    }) {
        return Some(format!(
            " Found a `cadence-review` marker on a review that does not parse: {}.",
            marker_problems(broken).join("; ")
        ));
    }
    if reviews.is_empty() && state.comments.iter().any(|c| mentions_marker(c)) {
        return Some(
            " Found a `cadence-review` marker on an issue comment, which does not count: post \
             it as a review (`gh pr review --comment --body-file <file>`) with the marker as \
             the body's first line."
                .to_string(),
        );
    }
    None
}

/// A GitHub login safe to echo into the nudge: ASCII letters, digits, and
/// `-`, at most 39 characters (GitHub's own rule). Bot logins end in `[bot]`
/// in REST but arrive without it here, so the rule holds for them too.
fn is_safe_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 39
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The sentence naming each outstanding `CHANGES_REQUESTED` review and the
/// command that would dismiss it (cadence-hooks#978).
///
/// The ruling on #978 sets two limits, and both are kept here. The dismissal
/// command is printed with the PR and review id filled in, so the way to
/// clear the nudge is visible where it fires. And it is not the default
/// advice: the sentence leads with addressing the changes and asking for a
/// re-review, and names dismissal as the operator's call for a review they
/// judge stale or resolved. The guard never dismisses anything.
///
/// Every value in the command is either parsed ([`is_safe_name`],
/// [`is_safe_host`], a JSON number) or one of gh's `{owner}`/`{repo}`
/// placeholders, which gh fills from the cwd's repo the same way the query
/// did. A review with no id gets no command.
fn changes_requested_sentence(
    blockers: &[&ParsedReview],
    query_repo: &QueryRepo,
    host: Option<&str>,
    pr_num: u64,
) -> String {
    let repo_path = match query_repo {
        QueryRepo::Named { owner, name } => format!("repos/{owner}/{name}"),
        QueryRepo::Placeholders => "repos/{owner}/{repo}".to_string(),
    };
    let hostname = host
        .filter(|h| !h.eq_ignore_ascii_case("github.com") && is_safe_host(h))
        .map(|h| format!(" --hostname {h}"))
        .unwrap_or_default();
    let who = |r: &ParsedReview| {
        if is_safe_login(&r.login) {
            format!("@{}", r.login)
        } else {
            "a reviewer".to_string()
        }
    };
    let listed = blockers
        .iter()
        .map(|r| match r.id {
            Some(id) => format!(
                "{} (`gh api{hostname} -X PUT {repo_path}/pulls/{pr_num}/reviews/{id}/dismissals \
                 -f message='<reason>'`)",
                who(r)
            ),
            None => who(r),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        " PR #{pr_num} has an outstanding CHANGES_REQUESTED review — the reviewer's latest \
         decisive review requests changes, and a new push does not clear it. Address the \
         changes and ask for a re-review. If the operator judges a request stale or already \
         resolved, dismissing it is their call: {listed}."
    )
}

/// The repo half of the GraphQL request: explicit `owner`/`name` values, or
/// gh's `{owner}`/`{repo}` placeholders, which gh fills from the repo it
/// resolves in the cwd.
pub enum QueryRepo {
    Named { owner: String, name: String },
    Placeholders,
}

impl QueryRepo {
    /// The `(flag, owner, name)` field triple for `gh api graphql`: `-f`
    /// sends a value raw, and gh fills a `{owner}`/`{repo}` placeholder only
    /// in a `-F` field.
    pub fn graphql_fields(&self) -> (&'static str, String, String) {
        match self {
            QueryRepo::Named { owner, name } => {
                ("-f", format!("owner={owner}"), format!("name={name}"))
            }
            QueryRepo::Placeholders => {
                ("-F", "owner={owner}".to_string(), "name={repo}".to_string())
            }
        }
    }
}

/// Ask gh which PR a selector-less or non-numeric flip names:
/// `gh pr view --json number,url [-R repo] [-- selector]`. gh answers with
/// the PR's URL, which names its repo and number. `None` on any failure.
///
/// `repo` is [`RepoChoice::repo_arg`], built from parsed parts. `selector` is
/// the one command string that reaches gh as typed. It is safe there: it
/// follows `--`, so gh never reads it as a flag, and gh contacts a host for
/// it only when it is an `http(s)` URL. [`FlipTarget::from_tokens`] has
/// already read the host of any URL-shaped selector (stopping on userinfo, a
/// port, `%`, or non-ASCII) and [`evaluate`] has checked it against the
/// trusted set.
fn resolve_with_pr_view(
    gh: &dyn GhRunner,
    repo: Option<&str>,
    selector: Option<&str>,
) -> Option<(QueryRepo, u64)> {
    let mut args = vec!["pr", "view", "--json", "number,url"];
    if let Some(repo) = repo {
        args.extend(["-R", repo]);
    }
    if let Some(sel) = selector {
        args.extend(["--", sel]);
    }
    let json = gh.run(&args)?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    let (_host, owner, name, number) = pr_url_parts(value.get("url")?.as_str()?)?;
    if !(is_safe_name(&owner) && is_safe_name(&name)) {
        return None;
    }
    Some((QueryRepo::Named { owner, name }, number))
}

/// Which PR a flip names: its query repo and number, or `None` when that
/// cannot be said with confidence (fail-open allow, ADR-0001). Callers vet
/// hosts first ([`hosts_are_trusted`]); this may call `gh pr view`.
///
/// Shared with the other flip-anchored nudges so every one of them resolves
/// the PR exactly the way this guard does.
pub fn resolve_pr(target: &FlipTarget, gh: &dyn GhRunner) -> Option<(QueryRepo, u64)> {
    Some(match (&target.selector, &target.repo) {
        // A URL names its own repo; gh ignores `-R` for it.
        (
            PrSelector::Url {
                owner,
                repo,
                number,
                ..
            },
            _,
        ) => (
            QueryRepo::Named {
                owner: owner.clone(),
                name: repo.clone(),
            },
            *number,
        ),
        (PrSelector::Number(n), RepoChoice::Explicit { owner, name, .. }) => (
            QueryRepo::Named {
                owner: owner.clone(),
                name: name.clone(),
            },
            *n,
        ),
        // gh fills `{owner}`/`{repo}` from the repo it resolves in the cwd —
        // the same one the flip resolves, including a fork's upstream.
        (PrSelector::Number(n), RepoChoice::GhDefault) => (QueryRepo::Placeholders, *n),
        // No selector: gh flips the PR for the cwd's branch.
        (PrSelector::None, RepoChoice::GhDefault) => resolve_with_pr_view(gh, None, None)?,
        (PrSelector::Other(sel), RepoChoice::GhDefault) => {
            resolve_with_pr_view(gh, None, Some(sel))?
        }
        (PrSelector::Other(sel), repo @ RepoChoice::Explicit { .. }) => {
            resolve_with_pr_view(gh, repo.repo_arg().as_deref(), Some(sel))?
        }
        // Fail-open allow (ADR-0001): gh refuses a `-R` with no selector
        // ("argument required when using the --repo flag"), so the flip
        // itself fails and there is no PR to check.
        (PrSelector::None, RepoChoice::Explicit { .. }) => return None,
        // Fail-open allow (ADR-0001): an unknown flag or a lone `-` hides
        // which token is the PR, so no PR can be named with confidence.
        (PrSelector::Unreadable, _) => return None,
    })
}

/// Core decision logic, injected with a `GhRunner` for testability. Returns
/// `Some(message)` to nudge, `None` to stay silent (reviewed, or any
/// fetch/parse/resolution failure — fail open).
///
/// The runner is expected to run gh in the session cwd, with the command's
/// host, so the placeholder and `pr view` rows resolve the repo the flip
/// itself would. `origin_host` is `origin`'s host from local git config, or
/// `None` when it cannot be read.
pub fn evaluate(
    target: &FlipTarget,
    origin_host: Option<&str>,
    gh: &dyn GhRunner,
) -> Option<String> {
    // Fail-open allow (ADR-0001): this runs before the user approves the
    // command, so a host only the command text names must not receive a
    // request. Only `github.com` and origin's host are queried.
    if !hosts_are_trusted(&target.named_hosts, origin_host) {
        return None;
    }
    let (query_repo, pr_num) = resolve_pr(target, gh)?;

    // One request for the head, the author, and the reviews. Each `gh` call is
    // a process start plus a network round trip (~0.4s), and this used to make
    // two in sequence. Owner, name, and number go in as GraphQL variables, so
    // nothing from the command is spliced into the query text.
    let query = format!("query={PR_STATE_QUERY}");
    let number = format!("number={pr_num}");
    let (repo_flag, owner, name) = query_repo.graphql_fields();
    let state_json = gh.run(&[
        "api", "graphql", "-f", &query, repo_flag, &owner, repo_flag, &name, "-F", &number,
    ])?;
    let state = parse_pr_state(&state_json)?;

    if is_reviewed(&state.reviews, &state.head, &state.author) {
        return None;
    }
    // Which half of the contract failed decides what the nudge says.
    let approved = has_approval_signal(&state.reviews, &state.head, &state.author);
    let blockers = outstanding_changes_requested(&state.reviews);
    let head = state.head.as_str();
    // `chars`, not a byte slice: `headRefOid` comes from `gh` and a non-hex
    // value would panic a `&head[..7]` on a char boundary.
    let short_head = head.chars().take(7).collect::<String>();

    let mut msg =
        format!("warn-unreviewed-ready-flip: PR #{pr_num} is not reviewed at head {short_head}.");
    if !approved {
        msg.push_str(
            " It has no approval signal on this SHA — neither a non-author human APPROVED \
             review nor a `cadence-review` marker with `crit=0 imp=0`. Post the dispatched \
             reviewer's findings on the PR first.",
        );
        if let Some(hint) = marker_hint(&state) {
            msg.push_str(&hint);
        }
    }
    if !blockers.is_empty() {
        msg.push_str(&changes_requested_sentence(
            &blockers,
            &query_repo,
            target.host.as_deref(),
            pr_num,
        ));
    }
    msg.push_str(" See `cadence-forge:review-loop` § What \"reviewed\" means. Advisory only.");
    Some(msg)
}

/// Where and how a flip-anchored nudge runs gh: the session cwd, `origin`'s
/// host (local git config, `None` when unread or not needed), and the
/// `GH_HOST` override to scope to the spawned process.
pub struct FlipContext {
    pub cwd: String,
    pub origin_host: Option<String>,
    pub env: Vec<(String, String)>,
}

impl FlipContext {
    /// Resolve the context for `target` from the hook payload.
    pub fn for_target(target: &FlipTarget, input: &HookInput) -> Self {
        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);

        // Origin's host, from local git config. It is read only when needed:
        // to vet a non-github.com host the command names, or to set
        // `GH_HOST` when gh picks the repo from the cwd. A failed lookup
        // leaves it `None`.
        let needs_origin = target
            .named_hosts
            .iter()
            .any(|h| !h.eq_ignore_ascii_case("github.com"))
            || (target.host.is_none() && target.repo == RepoChoice::GhDefault);
        let origin_host = needs_origin
            .then(|| git_command(cwd, &["remote", "get-url", "origin"]))
            .flatten()
            .and_then(|url| host_and_repo_from_url(&url))
            .map(|(host, _slug)| host);

        // Host: what the command names (vetted in `evaluate`), else origin's
        // host when gh picks the repo from the cwd and origin is not on
        // github.com. An explicit bare `OWNER/REPO` goes to gh's own default
        // host, so no override is added for it.
        let host = target.host.clone().or_else(|| {
            if target.repo != RepoChoice::GhDefault {
                return None;
            }
            origin_host.clone().filter(|h| h != "github.com")
        });
        FlipContext {
            cwd: cwd.to_string(),
            origin_host,
            env: host
                .map(|h| vec![("GH_HOST".to_string(), h)])
                .unwrap_or_default(),
        }
    }
}

/// Nudges on `gh pr ready` / `gh pr merge` when the PR's head SHA has no
/// reviewed signal.
pub struct WarnUnreviewedReadyFlip;

impl Check for WarnUnreviewedReadyFlip {
    fn name(&self) -> &str {
        "warn-unreviewed-ready-flip"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let Some(tokens) = flip_segment_tokens(command) else {
            return CheckResult::allow();
        };
        // Conflicting or unparseable repo values: fail-open allow (ADR-0001).
        let Some(target) = FlipTarget::from_tokens(&tokens) else {
            return CheckResult::allow();
        };

        let ctx = FlipContext::for_target(&target, input);
        // Bounded per call (cadence-hooks#986): a gh answer slower than the
        // bounded runner's cap reads as no answer, and the nudge stays silent
        // rather than the external hooks.json timeout killing the hook.
        let gh = crate::bounded_tool::BoundedGhRunner {
            cwd: PathBuf::from(&ctx.cwd),
            env: ctx.env,
        };

        match evaluate(&target, ctx.origin_host.as_deref(), &gh) {
            Some(msg) => CheckResult::nudge(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    // --- matcher ---

    #[test]
    fn gh_pr_merge_matches() {
        assert!(flip_segment_tokens("gh pr merge 5 --squash").is_some());
    }

    #[test]
    fn gh_pr_ready_matches() {
        assert!(flip_segment_tokens("gh pr ready 5").is_some());
    }

    #[test]
    fn gh_pr_ready_undo_does_not_match() {
        // `--undo` flips the PR BACK to draft — it un-ships, so the reviewed
        // signal it would nudge about is not owed (cadence-hooks#774, sibling
        // of the `segment_ship_anchor` fix in #773).
        assert!(flip_segment_tokens("gh pr ready --undo").is_none());
        assert!(flip_segment_tokens("gh pr ready 12 --undo").is_none());
        assert!(flip_segment_tokens("cd repo && gh pr ready --undo").is_none());
        // Positive controls: the real flip still matches.
        assert!(flip_segment_tokens("gh pr ready").is_some());
        assert!(flip_segment_tokens("gh pr ready 12").is_some());
        // `--undo` is not a `gh pr merge` flag; merge never loses its match.
        assert!(flip_segment_tokens("gh pr merge 12 --undo").is_some());
    }

    #[test]
    fn gh_pr_ready_undo_as_a_redirect_target_still_matches() {
        // The shell eats a redirect target and a here-string word — gh never
        // sees the flag, so these ship for real and still owe the nudge.
        assert!(flip_segment_tokens("gh pr ready 12 > --undo").is_some());
        assert!(flip_segment_tokens("gh pr ready 12 <<< --undo").is_some());
    }

    #[test]
    fn unrelated_command_does_not_match() {
        assert!(flip_segment_tokens("gh pr view 5").is_none());
        assert!(flip_segment_tokens("git status").is_none());
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(WarnUnreviewedReadyFlip.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed_end_to_end() {
        let result = WarnUnreviewedReadyFlip.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn matcher_returns_the_first_flip_segments_tokens() {
        let tokens = flip_segment_tokens("git fetch && gh pr merge 5 && gh pr ready 6").unwrap();
        assert_eq!(tokens, vec!["gh", "pr", "merge", "5"]);
    }

    // --- marker parsing ---

    #[test]
    fn marker_regex_extracts_fields() {
        let body = "<!-- cadence-review: cadence:code-reviewer head=abc123abc123abc123abc123abc123abc123abc1 crit=0 imp=0 -->\n\nfindings";
        let c = MARKER_RE.captures(body).unwrap();
        assert_eq!(&c["head"], "abc123abc123abc123abc123abc123abc123abc1");
        assert_eq!(&c["crit"], "0");
        assert_eq!(&c["imp"], "0");
    }

    /// The marker's `head=` field is exactly 40 hex characters — the length
    /// `cadence-forge:review-loop` § What "reviewed" means documents and the
    /// length `poll-prs.sh`'s `CADENCE_MARKER_RE` pins. This regex accepted
    /// any hex length, so the two consumers accepted different sets of
    /// strings with nothing checking the gap (cadence-hooks#879).
    ///
    /// Both directions in one test: the documented 40-char marker matches,
    /// and each off-by-one neighbour (39 and 41) does not.
    #[test]
    fn marker_head_is_pinned_to_forty_hex() {
        let forty = "a".repeat(40);
        let thirty_nine = "a".repeat(39);
        let forty_one = "a".repeat(41);

        let marker = |sha: &str| {
            format!("<!-- cadence-review: code-reviewer head={sha} crit=0 imp=0 -->\n\nfindings")
        };

        assert!(
            MARKER_RE.captures(&marker(&forty)).is_some(),
            "the documented 40-char marker must match"
        );
        assert!(
            MARKER_RE.captures(&marker(&thirty_nine)).is_none(),
            "a 39-char SHA is not the documented marker"
        );
        assert!(
            MARKER_RE.captures(&marker(&forty_one)).is_none(),
            "a 41-char SHA is not the documented marker"
        );
        // The abbreviated SHA a human would paste from `git log --oneline`.
        assert!(
            MARKER_RE.captures(&marker("abc1234")).is_none(),
            "a short SHA is not the documented marker"
        );
    }

    /// Separators are literal single spaces, matching `poll-prs.sh`'s
    /// `CADENCE_MARKER_RE`. Under the old `\s+`/`\s*` spelling each of these
    /// parsed here and not there, so this guard would have read "reviewed" on
    /// a marker the review loop's own poller never accepts
    /// (cadence-hooks#879).
    #[test]
    fn marker_separators_are_literal_single_spaces() {
        let sha = "a".repeat(40);
        let canonical = format!("<!-- cadence-review: code-reviewer head={sha} crit=0 imp=0 -->");
        assert!(
            MARKER_RE.captures(&canonical).is_some(),
            "the documented marker must match"
        );

        for (label, marker) in [
            (
                "no space after the opening comment",
                format!("<!--cadence-review: code-reviewer head={sha} crit=0 imp=0 -->"),
            ),
            (
                "double space between fields",
                format!("<!-- cadence-review: code-reviewer  head={sha} crit=0 imp=0 -->"),
            ),
            (
                "tab separator",
                format!("<!-- cadence-review: code-reviewer\thead={sha} crit=0 imp=0 -->"),
            ),
            (
                "newline mid-marker",
                format!("<!-- cadence-review: code-reviewer head={sha}\ncrit=0 imp=0 -->"),
            ),
            (
                "no space before the closing comment",
                format!("<!-- cadence-review: code-reviewer head={sha} crit=0 imp=0-->"),
            ),
            (
                "non-ASCII digit in crit",
                format!("<!-- cadence-review: code-reviewer head={sha} crit=\u{0660} imp=0 -->"),
            ),
        ] {
            assert!(
                MARKER_RE.captures(&marker).is_none(),
                "{label}: must not parse — the bash consumer rejects it"
            );
        }

        // A tab *inside* the reviewer token has no case here on purpose:
        // `[^ ]+` accepts it on both sides, so it is parity, not a rejection.
        // The old `\S+` spelling rejected it — a divergence in the other
        // direction, and the one `marker-shape.test.sh` conceded with "no
        // fixture case". Asserting a rejection here failed, which is how the
        // direction got settled rather than assumed.
        let tabbed = format!("<!-- cadence-review: code\treviewer head={sha} crit=0 imp=0 -->");
        assert!(
            MARKER_RE.captures(&tabbed).is_some(),
            "a tab inside the reviewer token parses on both sides"
        );
    }

    /// A marker spanning two lines does not clear the gate. `[^ ]+` matches
    /// `\n` in this crate, so while `MARKER_RE` alone accepts this string,
    /// [`is_reviewed`] hands it only the first line — the same string
    /// `poll-prs.sh` matches. Without that slice the guard went silent on a
    /// marker jq rejects, which is the whole defect class this change is
    /// about (cadence-hooks#879).
    #[test]
    fn a_marker_spanning_two_lines_does_not_clear_the_gate() {
        let sha = "abc1234abcabc1234abcabc1234abcabc1234abc";
        let body =
            format!("<!-- cadence-review: rev\nSURPRISE head={sha} crit=0 imp=0 -->\nfindings");

        // The pattern on its own accepts it — the newline lands inside the
        // reviewer capture. This assertion is why the slice exists.
        assert!(
            MARKER_RE.captures(&body).is_some(),
            "precondition: the pattern alone matches across the newline"
        );

        let gh = FakeGh::new(
            sha,
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": sha,
                "body": body
            }]),
        );
        assert!(
            eval("gh pr merge 5", &gh).is_some(),
            "a marker whose reviewer field swallows a newline is not a marker"
        );
    }

    /// A marker that is not the body's first line does not clear the gate.
    /// `is_reviewed` used to match `body.trim_start()`, which let a body
    /// beginning with a blank line or an indent clear here while
    /// `poll-prs.sh`'s untrimmed `split("\n")[0]` rejected it — leniency on
    /// the positive signal, so an under-nudge (cadence-hooks#879).
    #[test]
    fn a_marker_behind_leading_whitespace_does_not_clear_the_gate() {
        let sha = "abc1234abcabc1234abcabc1234abcabc1234abc";
        let marker = format!("<!-- cadence-review: code-reviewer head={sha} crit=0 imp=0 -->");

        for (label, body) in [
            ("blank line first", format!("\n{marker}\nfindings")),
            ("indented", format!("  {marker}\nfindings")),
        ] {
            let gh = FakeGh::new(
                sha,
                "cameronsjo",
                serde_json::json!([{
                    "user": {"login": "cameronsjo"},
                    "state": "COMMENTED",
                    "commit_id": sha,
                    "body": body
                }]),
            );
            assert!(
                eval("gh pr merge 5", &gh).is_some(),
                "{label}: the marker is not the first line, so the gate is not clear"
            );
        }

        // Positive control: the same marker as the first line stays silent.
        let gh = FakeGh::new(
            sha,
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": sha,
                "body": format!("{marker}\nfindings")
            }]),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    /// The exact fixture `marker-shape.test.sh` in cameronsjo/cadence calls
    /// the "documented divergence": a truncated SHA that its bash regex
    /// rejects and its pinned copy of *this* regex accepted. After #879 both
    /// sides reject it, so the divergence is closed rather than documented.
    ///
    /// This is the end-to-end verdict, not the regression test for #879 —
    /// staging the break (putting `+` back in `MARKER_RE`) leaves it green,
    /// because [`is_reviewed`]'s full-SHA equality already rejected a short
    /// SHA one step later. `marker_head_is_pinned_to_forty_hex` is the test
    /// that goes red for that break. Both are worth keeping: this one holds
    /// the verdict if the equality check is ever refactored away.
    #[test]
    fn truncated_sha_marker_does_not_clear_the_gate() {
        let gh = FakeGh::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "body": "<!-- cadence-review: code-reviewer head=aaaaaaaa crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    // --- evaluate: fake GhRunner ---

    /// Run the hook's decision on a flip command, the way `run` builds it.
    fn eval(command: &str, gh: &dyn GhRunner) -> Option<String> {
        eval_with_origin(command, None, gh)
    }

    /// As [`eval`], with origin's host as `run` would read it.
    fn eval_with_origin(
        command: &str,
        origin_host: Option<&str>,
        gh: &dyn GhRunner,
    ) -> Option<String> {
        let tokens = flip_segment_tokens(command).expect("fixture must be a flip command");
        evaluate(&FlipTarget::from_tokens(&tokens)?, origin_host, gh)
    }

    struct FakeGh {
        /// The `gh api graphql` response.
        state_json: Option<String>,
        /// The `gh pr view --json number,url` response.
        pr_view_json: Option<String>,
        /// Every call's argv, in order.
        calls: std::cell::RefCell<Vec<Vec<String>>>,
        graphql_args: std::cell::RefCell<Vec<String>>,
    }

    impl FakeGh {
        /// `reviews` is written in the REST review shape (`user.login`,
        /// `commit_id`) the fixtures have always used, and converted here to
        /// the GraphQL shape the hook now reads.
        fn new(head: &str, author: &str, reviews: serde_json::Value) -> Self {
            let nodes: Vec<serde_json::Value> = reviews
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|r| {
                            serde_json::json!({
                                "databaseId": r["id"],
                                "author": {
                                    "login": r["user"]["login"],
                                    "databaseId": r["user"]["id"],
                                },
                                "state": r["state"],
                                "commit": {"oid": r["commit_id"]},
                                "body": r["body"],
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Self {
                state_json: Some(
                    serde_json::json!({"data": {"repository": {"pullRequest": {
                        "headRefOid": head,
                        "author": {"login": author},
                        "reviews": {"nodes": nodes},
                    }}}})
                    .to_string(),
                ),
                pr_view_json: None,
                calls: std::cell::RefCell::new(Vec::new()),
                graphql_args: std::cell::RefCell::new(Vec::new()),
            }
        }

        /// Add issue comments with these bodies to the GraphQL response.
        fn with_comments(mut self, bodies: &[&str]) -> Self {
            let mut state: serde_json::Value =
                serde_json::from_str(self.state_json.as_deref().unwrap()).unwrap();
            let nodes: Vec<serde_json::Value> = bodies
                .iter()
                .map(|b| serde_json::json!({ "body": b }))
                .collect();
            state["data"]["repository"]["pullRequest"]["comments"] =
                serde_json::json!({ "nodes": nodes });
            self.state_json = Some(state.to_string());
            self
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(ToString::to_string).collect());
            if args.first() == Some(&"pr") && args.get(1) == Some(&"view") {
                // Real gh 2.101.0 refuses `-R` with no selector: "argument
                // required when using the --repo flag".
                if args.contains(&"-R") && !args.contains(&"--") {
                    return None;
                }
                return self.pr_view_json.clone();
            }
            if args.first() == Some(&"api") && args.get(1) == Some(&"graphql") {
                *self.graphql_args.borrow_mut() = args.iter().map(ToString::to_string).collect();
                return self.state_json.clone();
            }
            None
        }
    }

    struct ErrGh;
    impl GhRunner for ErrGh {
        fn run(&self, _args: &[&str]) -> Option<String> {
            None
        }
    }

    #[test]
    fn marker_on_head_is_silent() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "abc1234abcabc1234abcabc1234abcabc1234abc",
                "body": "<!-- cadence-review: cadence:code-reviewer head=abc1234abcabc1234abcabc1234abcabc1234abc crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn human_approval_on_head_is_silent() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "someoneelse"},
                "state": "APPROVED",
                "commit_id": "abc1234abcabc1234abcabc1234abcabc1234abc",
                "body": ""
            }]),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn marker_on_stale_head_nudges() {
        let gh = FakeGh::new(
            "fed9999fedfed9999fedfed9999fedfed9999fed",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "111aaa111a111aaa111a111aaa111a111aaa111a",
                "body": "<!-- cadence-review: cadence:code-reviewer head=111aaa111a111aaa111a111aaa111a111aaa111a crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn marker_with_crit_nudges() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "abc1234abcabc1234abcabc1234abcabc1234abc",
                "body": "<!-- cadence-review: cadence:code-reviewer head=abc1234abcabc1234abcabc1234abcabc1234abc crit=1 imp=0 -->\nfindings"
            }]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn no_reviews_nudges() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn author_self_approval_nudges() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "APPROVED",
                "commit_id": "abc1234abcabc1234abcabc1234abcabc1234abc",
                "body": ""
            }]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    /// Pins the GraphQL field mapping in raw response JSON, bypassing
    /// [`FakeGh::new`]'s REST-to-GraphQL conversion (cadence-hooks#985): a bot
    /// login arrives without REST's `[bot]` suffix on both the PR author and
    /// the review author, so they still compare equal, and the reviewed
    /// commit is read from `commit.oid`.
    #[test]
    fn graphql_bot_login_and_commit_oid_mapping() {
        const HEAD: &str = "abc1234abcabc1234abcabc1234abcabc1234abc";
        const STALE: &str = "111aaa111a111aaa111a111aaa111a111aaa111a";
        // (case, PR author, reviewer, reviewed commit oid, nudges)
        let cases = [
            ("bot self-approval", "dependabot", "dependabot", HEAD, true),
            (
                "other bot approves head",
                "dependabot",
                "coderabbitai",
                HEAD,
                false,
            ),
            (
                "human approves bot pr",
                "dependabot",
                "cameronsjo",
                HEAD,
                false,
            ),
            (
                "approval on stale oid",
                "cameronsjo",
                "coderabbitai",
                STALE,
                true,
            ),
        ];
        for (case, author, reviewer, oid, nudges) in cases {
            let mut gh = FakeGh::new(HEAD, author, serde_json::json!([]));
            gh.state_json = Some(
                serde_json::json!({"data": {"repository": {"pullRequest": {
                    "headRefOid": HEAD,
                    "author": {"login": author},
                    "reviews": {"nodes": [{
                        "databaseId": 101,
                        "author": {"login": reviewer, "databaseId": 7},
                        "state": "APPROVED",
                        "commit": {"oid": oid},
                        "body": ""
                    }]},
                }}}})
                .to_string(),
            );
            assert_eq!(eval("gh pr merge 5", &gh).is_some(), nudges, "{case}");
        }
    }

    #[test]
    fn fetch_error_is_silent() {
        assert_eq!(eval("gh pr merge 5", &ErrGh), None);
    }

    #[test]
    fn malformed_reviews_json_is_silent() {
        let mut gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        gh.state_json = Some("not json".to_string());
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn missing_pull_request_is_silent() {
        let mut gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        gh.state_json = Some(r#"{"data":{"repository":{"pullRequest":null}}}"#.to_string());
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn graphql_errors_beside_partial_data_are_silent() {
        let mut gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        gh.state_json = Some(
            r#"{"data":{"repository":{"pullRequest":{"headRefOid":"abc1234abcabc1234abcabc1234abcabc1234abc",
                "author":{"login":"cameronsjo"},"reviews":{"nodes":[]}}}},
                "errors":[{"message":"rate limited"}]}"#
                .to_string(),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn deleted_author_and_commitless_review_parse_as_empty() {
        let state = parse_pr_state(
            r#"{"data":{"repository":{"pullRequest":{"headRefOid":"h","author":null,
                "reviews":{"nodes":[{"author":null,"state":"COMMENTED","commit":null,"body":"x"}]}}}}}"#,
        )
        .unwrap();
        assert_eq!(state.author, "");
        assert_eq!(state.reviews[0].login, "");
        assert_eq!(state.reviews[0].commit_id, "");
    }

    #[test]
    fn query_asks_for_the_newest_reviews_and_takes_the_repo_as_variables() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        let _ = eval("gh pr merge 5 -R some-owner/some-repo", &gh);
        let args = gh.graphql_args.borrow();
        let query = args.iter().find(|a| a.starts_with("query=")).unwrap();
        // Newest first: the oldest-first REST list stopped at 30 reviews.
        assert!(query.contains("reviews(last: 100)"), "{query}");
        // The repo reaches gh only as variables, never inside the query text.
        assert!(!query.contains("some-owner"), "{query}");
        assert!(args.contains(&"owner=some-owner".to_string()), "{args:?}");
        assert!(args.contains(&"name=some-repo".to_string()), "{args:?}");
        assert!(args.contains(&"number=5".to_string()), "{args:?}");
    }

    #[test]
    fn a_numbered_flip_costs_one_gh_call() {
        // Each `gh` call is a process start plus a network round trip, about
        // 0.4s. Two sequential calls made this the slowest hook in the suite.
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        let _ = eval("gh pr merge 5", &gh);
        assert_eq!(gh.call_count(), 1);
    }

    #[test]
    fn unresolvable_pr_number_is_silent() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        // No number in the command, and the `gh pr view --json number,url`
        // lookup returns None (FakeGh's default) — unresolvable.
        assert_eq!(eval("gh pr merge --auto", &gh), None);
    }

    // --- resolving the PR the way gh does (cadence-hooks#1028, #920) ---

    fn unreviewed_gh() -> FakeGh {
        FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        )
    }

    fn has(args: &[String], value: &str) -> bool {
        args.iter().any(|a| a == value)
    }

    #[test]
    fn repo_flag_after_the_number_is_the_repo_queried() {
        // The old guard queried origin's repo here, whatever `-R` said.
        let gh = unreviewed_gh();
        assert!(eval("gh pr merge 511 -R o/r", &gh).is_some());
        let args = gh.graphql_args.borrow();
        assert!(has(&args, "owner=o"), "{args:?}");
        assert!(has(&args, "name=r"), "{args:?}");
        assert!(has(&args, "number=511"), "{args:?}");
    }

    #[test]
    fn repo_flag_before_the_number_still_reads_the_number() {
        // The old number scan stopped at the `-R` value and fell back to an
        // unnumbered lookup that gh refuses, so this flip was never checked.
        let gh = unreviewed_gh();
        assert!(eval("gh pr merge -R o/r 511", &gh).is_some());
        assert_eq!(gh.call_count(), 1);
        let args = gh.graphql_args.borrow();
        assert!(has(&args, "owner=o"), "{args:?}");
        assert!(has(&args, "number=511"), "{args:?}");
    }

    #[test]
    fn attached_repo_spellings() {
        for command in ["gh pr merge --repo=o/r 5", "gh pr merge -Ro/r 5"] {
            let gh = unreviewed_gh();
            assert!(eval(command, &gh).is_some(), "{command}");
            let args = gh.graphql_args.borrow();
            assert!(has(&args, "owner=o"), "{command}: {args:?}");
            assert!(has(&args, "name=r"), "{command}: {args:?}");
            assert!(has(&args, "number=5"), "{command}: {args:?}");
        }
    }

    #[test]
    fn no_repo_flag_lets_gh_pick_the_repo() {
        // In a fork, gh resolves the upstream repo, not origin. The
        // placeholders let gh fill in the repo it would flip.
        let gh = unreviewed_gh();
        assert!(eval("gh pr merge 5", &gh).is_some());
        let args = gh.graphql_args.borrow();
        assert!(has(&args, "owner={owner}"), "{args:?}");
        assert!(has(&args, "name={repo}"), "{args:?}");
        // gh fills a placeholder only in a typed `-F` field.
        let owner_at = args.iter().position(|a| a == "owner={owner}").unwrap();
        assert_eq!(args[owner_at - 1], "-F", "{args:?}");
    }

    #[test]
    fn unnumbered_flip_resolves_without_repo_flag() {
        let mut gh = unreviewed_gh();
        gh.pr_view_json =
            Some(r#"{"number":7,"url":"https://github.com/up/stream/pull/7"}"#.to_string());
        assert!(eval("gh pr ready", &gh).is_some());
        let calls = gh.calls.borrow();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0], vec!["pr", "view", "--json", "number,url"]);
        assert!(has(&calls[1], "owner=up"), "{calls:?}");
        assert!(has(&calls[1], "name=stream"), "{calls:?}");
        assert!(has(&calls[1], "number=7"), "{calls:?}");
    }

    #[test]
    fn url_selector_names_its_own_repo() {
        // gh ignores `-R` for a URL, so the URL's repo is the one queried.
        let gh = unreviewed_gh();
        assert!(eval("gh pr merge https://github.com/x/y/pull/9 -R o/r", &gh).is_some());
        assert_eq!(gh.call_count(), 1);
        let args = gh.graphql_args.borrow();
        assert!(has(&args, "owner=x"), "{args:?}");
        assert!(has(&args, "name=y"), "{args:?}");
        assert!(has(&args, "number=9"), "{args:?}");
    }

    #[test]
    fn branch_selector_goes_after_double_dash() {
        let mut gh = unreviewed_gh();
        gh.pr_view_json = Some(r#"{"number":3,"url":"https://github.com/o/r/pull/3"}"#.to_string());
        assert!(eval("gh pr merge my-branch -R o/r", &gh).is_some());
        let calls = gh.calls.borrow();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(
            calls[0],
            vec![
                "pr",
                "view",
                "--json",
                "number,url",
                "-R",
                "o/r",
                "--",
                "my-branch"
            ]
        );
        assert!(has(&calls[1], "number=3"), "{calls:?}");
    }

    #[test]
    fn repo_flag_without_selector_makes_no_call() {
        // gh refuses this flip itself, so there is no PR to check.
        let gh = unreviewed_gh();
        assert_eq!(eval("gh pr merge -R o/r --squash", &gh), None);
        assert_eq!(gh.call_count(), 0);
    }

    #[test]
    fn disagreeing_repo_flags_are_silent() {
        let gh = unreviewed_gh();
        assert_eq!(eval("gh pr merge 5 -R a/b -R c/d", &gh), None);
        assert_eq!(gh.call_count(), 0);
    }

    // --- hosts the command names (security review I1) ---

    #[test]
    fn url_selector_on_an_unknown_host_makes_no_call() {
        // The hook runs before the user approves the command; a request to
        // this host would reach it (with GH_ENTERPRISE_TOKEN when set).
        let gh = unreviewed_gh();
        assert_eq!(
            eval("gh pr merge https://attacker.example/o/r/pull/1", &gh),
            None
        );
        assert_eq!(gh.call_count(), 0);
    }

    #[test]
    fn repo_flag_on_an_unknown_host_makes_no_call() {
        let gh = unreviewed_gh();
        assert_eq!(eval("gh pr merge 5 -R otherhost.example/o/r", &gh), None);
        assert_eq!(gh.call_count(), 0);
        let gh = unreviewed_gh();
        assert_eq!(
            eval("gh pr merge my-branch -R otherhost.example/o/r", &gh),
            None
        );
        assert_eq!(gh.call_count(), 0);
    }

    #[test]
    fn url_shaped_selector_on_an_unknown_host_makes_no_call() {
        // Not a PR URL, but `gh pr view` would still contact its host.
        for command in [
            "gh pr merge http://attacker.example/o/r/pull/1",
            "gh pr merge https://attacker.example/o/r/issues/1",
            "gh pr merge https://evil@github.com/o/r/pull/1",
            "gh pr merge https://github.com:443/o/r/pull/1",
        ] {
            let gh = unreviewed_gh();
            assert_eq!(eval(command, &gh), None, "{command}");
            assert_eq!(gh.call_count(), 0, "{command}");
        }
    }

    #[test]
    fn github_com_and_origin_hosts_are_still_queried() {
        for (command, origin) in [
            ("gh pr merge 5 -R github.com/o/r", None),
            ("gh pr merge https://GitHub.com/o/r/pull/5", None),
            (
                "gh pr merge 5 -R ghe.corp.example/o/r",
                Some("ghe.corp.example"),
            ),
            (
                "gh pr merge https://ghe.corp.example/o/r/pull/5",
                Some("ghe.corp.example"),
            ),
        ] {
            let gh = unreviewed_gh();
            assert!(
                eval_with_origin(command, origin, &gh).is_some(),
                "{command}"
            );
            assert_eq!(gh.call_count(), 1, "{command}");
            let args = gh.graphql_args.borrow();
            assert!(has(&args, "owner=o"), "{command}: {args:?}");
        }
    }

    #[test]
    fn host_trust_is_github_com_or_origin() {
        let named = |hosts: &[&str]| hosts.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(hosts_are_trusted(&named(&[]), None));
        assert!(hosts_are_trusted(&named(&["github.com"]), None));
        assert!(hosts_are_trusted(&named(&["ghe.x"]), Some("GHE.x")));
        assert!(!hosts_are_trusted(&named(&["ghe.x"]), None));
        assert!(!hosts_are_trusted(
            &named(&["github.com", "evil.x"]),
            Some("ghe.x")
        ));
    }

    // --- gh argv built only from parsed parts (security review I1, round 2) ---

    #[test]
    fn scp_shaped_repo_value_naming_another_host_makes_no_call() {
        // A remote-URL parser reads this host as github.com; go-gh splits it
        // on `/` and connects to evil.example. It must never reach gh.
        for command in [
            "gh pr merge my-branch -R github.com:x@evil.example/o/r",
            "gh pr merge 5 -R github.com:x@evil.example/o/r",
        ] {
            let gh = unreviewed_gh();
            assert_eq!(eval(command, &gh), None, "{command}");
            assert_eq!(gh.call_count(), 0, "{command}");
        }
    }

    #[test]
    fn repo_argv_is_built_from_parsed_parts() {
        let mut gh = unreviewed_gh();
        gh.pr_view_json = Some(r#"{"number":3,"url":"https://github.com/o/r/pull/3"}"#.to_string());
        let _ = eval("gh pr merge my-branch -R o/r", &gh);
        assert_eq!(
            gh.calls.borrow()[0],
            vec![
                "pr",
                "view",
                "--json",
                "number,url",
                "-R",
                "o/r",
                "--",
                "my-branch"
            ]
        );

        // The host is lowercased on the way through: gh gets the parsed
        // parts, not the spelling in the command.
        let mut gh = unreviewed_gh();
        gh.pr_view_json = Some(r#"{"number":3,"url":"https://github.com/o/r/pull/3"}"#.to_string());
        let _ = eval("gh pr merge my-branch -R GitHub.com/o/r", &gh);
        assert_eq!(
            gh.calls.borrow()[0],
            vec![
                "pr",
                "view",
                "--json",
                "number,url",
                "-R",
                "github.com/o/r",
                "--",
                "my-branch"
            ]
        );

        let gh = unreviewed_gh();
        let _ = eval("gh pr merge 5 -R o/r", &gh);
        assert_eq!(
            *gh.graphql_args.borrow(),
            vec![
                "api".to_string(),
                "graphql".to_string(),
                "-f".to_string(),
                format!("query={PR_STATE_QUERY}"),
                "-f".to_string(),
                "owner=o".to_string(),
                "-f".to_string(),
                "name=r".to_string(),
                "-F".to_string(),
                "number=5".to_string(),
            ]
        );
    }

    #[test]
    fn url_form_repo_values_are_silent() {
        // go-gh reads these as git URLs; the hook does not model that
        // parser, so it stays silent rather than guess.
        for command in [
            "gh pr merge 5 -R git@github.com:o/r.git",
            "gh pr merge 5 -R https://github.com/o/r",
            "gh pr merge 5 -R ssh://git@github.com/o/r",
        ] {
            let gh = unreviewed_gh();
            assert_eq!(eval(command, &gh), None, "{command}");
            assert_eq!(gh.call_count(), 0, "{command}");
        }
    }

    #[test]
    fn repo_value_outside_the_charset_is_silent() {
        for command in [
            "gh pr merge 5 -R o/r%2f",
            "gh pr merge 5 -R 'o /r'",
            "gh pr merge 5 -R o@x/r",
            "gh pr merge 5 -R a/b/c/d",
            "gh pr merge 5 -R o/-r",
            "gh pr merge 5 -R 'o/r\u{e9}'",
        ] {
            let gh = unreviewed_gh();
            assert_eq!(eval(command, &gh), None, "{command}");
            assert_eq!(gh.call_count(), 0, "{command}");
        }
    }

    // --- an empty repo value (security review N2) ---

    #[test]
    fn empty_repo_value_is_the_gh_default() {
        // gh reads an empty `-R` as no override and flips the cwd repo's PR.
        for command in [
            "gh pr merge --repo= 5",
            "gh pr merge -R= 5",
            "gh pr merge 5 -R ''",
        ] {
            let gh = unreviewed_gh();
            assert!(eval(command, &gh).is_some(), "{command}");
            let args = gh.graphql_args.borrow();
            assert!(has(&args, "owner={owner}"), "{command}: {args:?}");
            assert!(has(&args, "number=5"), "{command}: {args:?}");
        }
    }

    #[test]
    fn repo_value_hidden_by_an_unknown_flag_stays_silent() {
        // After `--newflag` the scan cannot tell whether `o/r` is a repo, so
        // it records an empty value. That is not a deliberate empty `-R`.
        let gh = unreviewed_gh();
        assert_eq!(eval("gh pr merge 5 --newflag -R o/r", &gh), None);
        assert_eq!(gh.call_count(), 0);
    }

    #[test]
    fn unreadable_selector_is_silent() {
        let gh = unreviewed_gh();
        assert_eq!(eval("gh pr merge --newflag x 5", &gh), None);
        assert_eq!(gh.call_count(), 0);
    }

    // --- retargeted and prefixed flips (cadence-hooks#778) ---

    #[test]
    fn retargeted_and_prefixed_flips_are_checked() {
        // Each was silent before: the matcher demanded `gh` then `pr` as the
        // first two tokens.
        for command in [
            "gh -R o/r pr merge 511",
            "gh --repo o/r pr ready 511",
            "gh --repo=o/r pr merge 511",
            "GH_REPO=o/r gh pr merge 511",
            "env GH_TOKEN=x gh -R o/r pr merge 511",
            "if true; then gh -R o/r pr merge 511; fi",
        ] {
            let gh = unreviewed_gh();
            assert!(eval(command, &gh).is_some(), "{command}");
            let args = gh.graphql_args.borrow();
            assert!(has(&args, "owner=o"), "{command}: {args:?}");
            assert!(has(&args, "name=r"), "{command}: {args:?}");
            assert!(has(&args, "number=511"), "{command}: {args:?}");
        }
    }

    #[test]
    fn prefixed_flip_on_an_untrusted_host_makes_no_call() {
        // Widening the matcher must not widen where the hook sends requests:
        // an inline `GH_HOST=` is still vetted before any call.
        let gh = unreviewed_gh();
        assert_eq!(eval("GH_HOST=evil.example gh pr merge 5", &gh), None);
        assert_eq!(gh.call_count(), 0);
    }

    #[test]
    fn retargeted_undo_does_not_match() {
        assert!(flip_segment_tokens("gh -R o/r pr ready 12 --undo").is_none());
    }

    // --- CHANGES_REQUESTED (cadence-hooks#978) ---

    const HEAD: &str = "abc1234abcabc1234abcabc1234abcabc1234abc";
    const OLD_HEAD: &str = "111aaa111a111aaa111a111aaa111a111aaa111a";

    fn clean_marker() -> serde_json::Value {
        serde_json::json!({
            "id": 900,
            "user": {"login": "cameronsjo", "id": 1},
            "state": "COMMENTED",
            "commit_id": HEAD,
            "body": format!("<!-- cadence-review: code-reviewer head={HEAD} crit=0 imp=0 -->\nnone")
        })
    }

    fn review(id: u64, user_id: u64, login: &str, state: &str, commit: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "user": {"login": login, "id": user_id},
            "state": state,
            "commit_id": commit,
            "body": ""
        })
    }

    #[test]
    fn outstanding_changes_requested_nudges_despite_a_clean_marker() {
        // The case #978 names: a reviewer requests changes, the author posts
        // a clean marker at the same head with no push.
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", HEAD),
                clean_marker()
            ]),
        );
        let msg = eval("gh pr merge 5", &gh).expect("an outstanding request must nudge");
        assert!(msg.contains("CHANGES_REQUESTED"), "{msg}");
        assert!(msg.contains("@rev"), "{msg}");
        assert!(
            msg.contains(
                "gh api -X PUT repos/{owner}/{repo}/pulls/5/reviews/101/dismissals -f message='<reason>'"
            ),
            "{msg}"
        );
        // The approval half held, so the no-signal sentence is not printed.
        assert!(!msg.contains("no approval signal"), "{msg}");
    }

    #[test]
    fn dismissal_is_not_the_default_advice() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", HEAD),
                clean_marker()
            ]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        let re_review = msg.find("re-review").expect("must advise a re-review");
        let dismiss = msg.find("dismissals").expect("must name the command");
        assert!(re_review < dismiss, "{msg}");
        assert!(msg.contains("operator"), "{msg}");
    }

    #[test]
    fn a_stale_head_request_is_still_outstanding() {
        // Head-independent, per the ruling: a push does not clear it.
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", OLD_HEAD),
                clean_marker()
            ]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn the_same_reviewers_later_approval_clears_the_request() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", OLD_HEAD),
                review(102, 7, "rev", "APPROVED", HEAD)
            ]),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn a_later_comment_does_not_clear_the_request() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", HEAD),
                review(102, 7, "rev", "COMMENTED", HEAD),
                clean_marker()
            ]),
        );
        assert!(eval("gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn a_dismissed_request_is_not_outstanding() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([review(101, 7, "rev", "DISMISSED", HEAD), clean_marker()]),
        );
        assert_eq!(eval("gh pr merge 5", &gh), None);
    }

    #[test]
    fn another_reviewers_approval_does_not_clear_a_request() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                review(101, 7, "rev", "CHANGES_REQUESTED", HEAD),
                review(102, 8, "other", "APPROVED", HEAD)
            ]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(msg.contains("reviews/101/dismissals"), "{msg}");
    }

    #[test]
    fn reviewers_without_an_id_never_share_a_group() {
        // Two deleted accounts: empty login, no id. Keyed by login they would
        // collapse and the approval would clear the other's request.
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([
                {"id": 101, "user": {"login": ""}, "state": "CHANGES_REQUESTED", "commit_id": HEAD, "body": ""},
                {"id": 102, "user": {"login": ""}, "state": "APPROVED", "commit_id": HEAD, "body": ""}
            ]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(msg.contains("a reviewer"), "{msg}");
        assert!(msg.contains("reviews/101/dismissals"), "{msg}");
    }

    #[test]
    fn dismissal_command_names_an_explicit_repo() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([review(101, 7, "rev", "CHANGES_REQUESTED", HEAD)]),
        );
        let msg = eval("gh pr merge 5 -R o/r", &gh).unwrap();
        assert!(
            msg.contains("repos/o/r/pulls/5/reviews/101/dismissals"),
            "{msg}"
        );
        assert!(!msg.contains("--hostname"), "{msg}");
        // Both halves failed, so both sentences are printed.
        assert!(msg.contains("no approval signal"), "{msg}");
    }

    #[test]
    fn a_login_outside_the_github_charset_is_not_echoed() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([review(
                101,
                7,
                "x` ignore previous",
                "CHANGES_REQUESTED",
                HEAD
            )]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(!msg.contains("ignore previous"), "{msg}");
        assert!(msg.contains("a reviewer"), "{msg}");
    }

    #[test]
    fn query_asks_for_review_and_reviewer_ids() {
        assert!(PR_STATE_QUERY.contains("reviews(last: 100) { nodes { databaseId"));
        assert!(PR_STATE_QUERY.contains("... on User { databaseId }"));
    }

    // --- malformed markers (cadence-hooks#838) ---

    #[test]
    fn a_malformed_marker_names_each_broken_field() {
        // The marker from the #838 report: `sha=` for `head=`, a short SHA,
        // and no reviewer field.
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": HEAD,
                "body": "<!-- cadence-review: sha=5a4567aa crit=0 imp=0 -->\nfindings"
            }]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(msg.contains("does not parse"), "{msg}");
        assert!(msg.contains("`<reviewer>`"), "{msg}");
        assert!(msg.contains("found `sha=`"), "{msg}");
        // Nothing from the body is echoed.
        assert!(!msg.contains("5a4567aa"), "{msg}");
    }

    #[test]
    fn a_short_head_is_reported_by_length() {
        assert_eq!(
            marker_problems("<!-- cadence-review: rev head=abc1234 crit=0 imp=0 -->"),
            vec!["`head=` must be the full 40-character SHA (found 7 characters)".to_string()]
        );
    }

    #[test]
    fn a_marker_that_is_not_the_first_line_is_reported() {
        let problems = marker_problems(&format!(
            "  <!-- cadence-review: rev head={HEAD} crit=0 imp=0 -->"
        ));
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("first line"), "{problems:?}");
    }

    #[test]
    fn a_spacing_fault_gets_the_fallback_problem() {
        let problems = marker_problems(&format!(
            "<!-- cadence-review: rev head={HEAD} crit=0 imp=0-->"
        ));
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("single spaces"), "{problems:?}");
    }

    #[test]
    fn a_marker_on_an_issue_comment_says_to_post_a_review() {
        let gh = FakeGh::new(HEAD, "cameronsjo", serde_json::json!([])).with_comments(&[&format!(
            "<!-- cadence-review: rev head={HEAD} crit=0 imp=0 -->\nfindings"
        )]);
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(msg.contains("issue comment"), "{msg}");
        assert!(msg.contains("gh pr review --comment"), "{msg}");
    }

    #[test]
    fn no_marker_anywhere_adds_no_hint() {
        let gh = FakeGh::new(HEAD, "cameronsjo", serde_json::json!([]))
            .with_comments(&["looks good to me"]);
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(!msg.contains("Found a"), "{msg}");
    }

    #[test]
    fn a_well_formed_stale_marker_is_not_called_malformed() {
        let gh = FakeGh::new(
            HEAD,
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": OLD_HEAD,
                "body": format!("<!-- cadence-review: rev head={OLD_HEAD} crit=0 imp=0 -->")
            }]),
        );
        let msg = eval("gh pr merge 5", &gh).unwrap();
        assert!(!msg.contains("does not parse"), "{msg}");
    }
}
