//! Warn on `gh pr ready` / `gh pr merge` when the PR's head SHA carries
//! neither a human approval nor a cadence-dispatched review marker.
//!
//! CodeRabbit's retirement (cameronsjo/cadence#1037) replaced the bot review
//! with a convention: a dispatched reviewer's findings are posted on the PR
//! as a COMMENT review whose body's first line is a machine-readable marker
//! —`<!-- cadence-review: <reviewer> head=<sha> crit=<n> imp=<n> -->` — and
//! "reviewed" means that marker reads `crit=0 imp=0` on the current head, or
//! a non-author human review is APPROVED on it
//! (`cadence-forge:review-loop` § What "reviewed" means). This is the
//! deterministic backstop at the Ready-flip capture point, sibling to
//! `warn-plan-ready-flip`'s reconcile check.
//!
//! Advisory only — nudges, never blocks — and fails open (ADR-0001) on any
//! `gh` fetch error, JSON parse error, or unresolvable PR: an indeterminate
//! answer must never read as a block.

use cadence_hooks_core::shell::{
    command_segments, command_word, git_command, host_and_repo_from_url, strip_group_wrappers,
    tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// The cadence-review marker: first line of a COMMENT review body.
/// `crit` and `imp` must both be `0` and `head` must equal the PR's current
/// head SHA for the marker to count as "reviewed".
static MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<!--\s*cadence-review:\s*(?P<reviewer>\S+)\s+head=(?P<head>[0-9a-fA-F]+)\s+crit=(?P<crit>\d+)\s+imp=(?P<imp>\d+)\s*-->")
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

/// Production `gh` runner: shells out to the system `gh` binary, scoping
/// `GH_HOST` to the spawned command for enterprise remotes.
pub struct RealGhRunner {
    pub gh_host: Option<String>,
}

impl GhRunner for RealGhRunner {
    fn run(&self, args: &[&str]) -> Option<String> {
        let mut cmd = std::process::Command::new("gh");
        if let Some(h) = &self.gh_host {
            cmd.env("GH_HOST", h);
        }
        let output = cmd.args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

/// Is `command` a `gh pr ready` / `gh pr merge` invocation? Segment- and
/// token-based (mirrors `warn_gh_merge_preflight::is_gh_pr_merge`) so a
/// hyphenated script name or quoted prose never matches, while flags after
/// the verb don't disturb the window.
fn is_pr_flip_command(command: &str) -> bool {
    command_segments(command).into_iter().any(|segment| {
        let tokens = tokenize(strip_group_wrappers(&segment));
        tokens
            .first()
            .is_some_and(|first| command_word(first).as_ref() == "gh")
            && tokens.get(1).map(String::as_str) == Some("pr")
            && matches!(
                tokens.get(2).map(String::as_str),
                Some("ready") | Some("merge")
            )
    })
}

/// Extract the PR number from a `gh pr ready`/`gh pr merge` command string,
/// if a bare integer token follows the subcommand. Mirrors
/// `verify_pr_autoclose::pr_number_from_merge_cmd`.
fn pr_number_from_command(command: &str) -> Option<u64> {
    for marker in ["gh pr ready", "gh pr merge"] {
        let Some(after) = command.split(marker).nth(1) else {
            continue;
        };
        for token in after.split_whitespace() {
            if token.starts_with('-') {
                continue;
            }
            if let Ok(n) = token.parse::<u64>() {
                return Some(n);
            }
            break;
        }
    }
    None
}

/// A parsed review: the author's login and, for a formal review, its state
/// and the commit SHA it was submitted against; for a cadence review, its
/// body (the marker lives in the body's first line).
struct ParsedReview {
    login: String,
    state: String,
    commit_id: String,
    body: String,
}

/// Parse the `gh api repos/{owner}/{repo}/pulls/{n}/reviews` JSON array.
/// Returns `None` on any parse failure — the caller reads that as fail-open.
fn parse_reviews(json: &str) -> Option<Vec<ParsedReview>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let arr = value.as_array()?;
    Some(
        arr.iter()
            .map(|r| ParsedReview {
                login: r
                    .get("user")
                    .and_then(|u| u.get("login"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                state: r
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                commit_id: r
                    .get("commit_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                body: r
                    .get("body")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect(),
    )
}

/// Does `reviews` carry a signal that counts as "reviewed" for `head`,
/// authored by anyone other than `author`?
///
/// Two independent signals, either sufficient: a non-author human review
/// APPROVED on `head`, or a cadence-review marker whose `head` matches and
/// whose `crit`/`imp` are both zero. A marker or approval on a stale head
/// (a push since the review) does not count.
fn is_reviewed(reviews: &[ParsedReview], head: &str, author: &str) -> bool {
    reviews.iter().any(|r| {
        // The non-author restriction applies only to a formal human APPROVED
        // review (self-approval proves nothing) — the cadence-review marker
        // is posted by the orchestrator's own token on the author's behalf,
        // never the PR author's, so it carries no author check.
        let formal_approved = r.login != author && r.state == "APPROVED" && r.commit_id == head;
        let marker_clean = MARKER_RE
            .captures(r.body.trim_start())
            .is_some_and(|c| &c["head"] == head && &c["crit"] == "0" && &c["imp"] == "0");
        formal_approved || marker_clean
    })
}

/// Core decision logic, injected with a `GhRunner` for testability. Returns
/// `Some(message)` to nudge, `None` to stay silent (reviewed, or any
/// fetch/parse/resolution failure — fail open).
pub fn evaluate(slug: &str, command: &str, gh: &dyn GhRunner) -> Option<String> {
    let pr_num = match pr_number_from_command(command) {
        Some(n) => n,
        None => {
            let raw = gh.run(&[
                "pr", "view", "--json", "number", "-q", ".number", "-R", slug,
            ]);
            raw.and_then(|s| s.parse::<u64>().ok())?
        }
    };

    let pr_json = gh.run(&[
        "pr",
        "view",
        &pr_num.to_string(),
        "--json",
        "headRefOid,author",
        "-R",
        slug,
    ])?;
    let pr_value: serde_json::Value = serde_json::from_str(&pr_json).ok()?;
    let head = pr_value
        .get("headRefOid")
        .and_then(serde_json::Value::as_str)?;
    let author = pr_value
        .get("author")
        .and_then(|a| a.get("login"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let (owner, repo) = slug.split_once('/')?;
    let reviews_json = gh.run(&[
        "api",
        &format!("repos/{owner}/{repo}/pulls/{pr_num}/reviews"),
    ])?;
    let reviews = parse_reviews(&reviews_json)?;

    if is_reviewed(&reviews, head, author) {
        return None;
    }

    Some(format!(
        "warn-unreviewed-ready-flip: PR #{pr_num} has no reviewed signal on head {short_head} — \
         neither a non-author human APPROVED review nor a `cadence-review` marker with \
         `crit=0 imp=0` on this SHA. Post the dispatched reviewer's findings on the PR first \
         (`cadence-forge:review-loop` § What \"reviewed\" means). Advisory only.",
        short_head = &head[..head.len().min(7)],
    ))
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
        if !is_pr_flip_command(command) {
            return CheckResult::allow();
        }

        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);

        let Some(remote_url) = git_command(cwd, &["remote", "get-url", "origin"]) else {
            return CheckResult::allow();
        };
        let Some((host, slug)) = host_and_repo_from_url(&remote_url) else {
            return CheckResult::allow();
        };
        let gh_host = if host == "github.com" {
            None
        } else {
            Some(host)
        };
        let gh = RealGhRunner { gh_host };

        match evaluate(&slug, command, &gh) {
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
        assert!(is_pr_flip_command("gh pr merge 5 --squash"));
    }

    #[test]
    fn gh_pr_ready_matches() {
        assert!(is_pr_flip_command("gh pr ready 5"));
    }

    #[test]
    fn unrelated_command_does_not_match() {
        assert!(!is_pr_flip_command("gh pr view 5"));
        assert!(!is_pr_flip_command("git status"));
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

    // --- pr_number_from_command ---

    #[test]
    fn pr_number_extracted_from_merge_and_ready() {
        assert_eq!(pr_number_from_command("gh pr merge 42 --squash"), Some(42));
        assert_eq!(pr_number_from_command("gh pr ready 7"), Some(7));
        assert_eq!(pr_number_from_command("gh pr merge --auto --squash"), None);
    }

    // --- marker parsing ---

    #[test]
    fn marker_regex_extracts_fields() {
        let body =
            "<!-- cadence-review: cadence:code-reviewer head=abc123 crit=0 imp=0 -->\n\nfindings";
        let c = MARKER_RE.captures(body).unwrap();
        assert_eq!(&c["head"], "abc123");
        assert_eq!(&c["crit"], "0");
        assert_eq!(&c["imp"], "0");
    }

    // --- evaluate: fake GhRunner ---

    struct FakeGh {
        pr_json: Option<String>,
        reviews_json: Option<String>,
        bare_pr_number: Option<String>,
    }

    impl FakeGh {
        fn new(head: &str, author: &str, reviews: serde_json::Value) -> Self {
            Self {
                pr_json: Some(
                    serde_json::json!({"headRefOid": head, "author": {"login": author}})
                        .to_string(),
                ),
                reviews_json: Some(reviews.to_string()),
                bare_pr_number: None,
            }
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            if args.first() == Some(&"pr") && args.get(1) == Some(&"view") {
                if args.contains(&"number") {
                    return self.bare_pr_number.clone();
                }
                return self.pr_json.clone();
            }
            if args.first() == Some(&"api") {
                return self.reviews_json.clone();
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
            "abc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "abc1234abc",
                "body": "<!-- cadence-review: cadence:code-reviewer head=abc1234abc crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
    }

    #[test]
    fn human_approval_on_head_is_silent() {
        let gh = FakeGh::new(
            "abc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "someoneelse"},
                "state": "APPROVED",
                "commit_id": "abc1234abc",
                "body": ""
            }]),
        );
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
    }

    #[test]
    fn marker_on_stale_head_nudges() {
        let gh = FakeGh::new(
            "fed9999fed",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "111aaa111a",
                "body": "<!-- cadence-review: cadence:code-reviewer head=111aaa111a crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn marker_with_crit_nudges() {
        let gh = FakeGh::new(
            "abc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "abc1234abc",
                "body": "<!-- cadence-review: cadence:code-reviewer head=abc1234abc crit=1 imp=0 -->\nfindings"
            }]),
        );
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn no_reviews_nudges() {
        let gh = FakeGh::new("abc1234abc", "cameronsjo", serde_json::json!([]));
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn author_self_approval_nudges() {
        let gh = FakeGh::new(
            "abc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "APPROVED",
                "commit_id": "abc1234abc",
                "body": ""
            }]),
        );
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn fetch_error_is_silent() {
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &ErrGh), None);
    }

    #[test]
    fn malformed_reviews_json_is_silent() {
        let mut gh = FakeGh::new("abc1234abc", "cameronsjo", serde_json::json!([]));
        gh.reviews_json = Some("not json".to_string());
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
    }

    #[test]
    fn unresolvable_pr_number_is_silent() {
        let gh = FakeGh::new("abc1234abc", "cameronsjo", serde_json::json!([]));
        // No number in the command, and the bare `gh pr view --json number`
        // lookup returns None (FakeGh's default) — unresolvable.
        assert_eq!(evaluate("owner/repo", "gh pr merge --auto", &gh), None);
    }
}
