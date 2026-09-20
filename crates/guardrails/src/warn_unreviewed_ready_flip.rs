//! Warn on `gh pr ready` / `gh pr merge` when the PR's head SHA carries
//! neither a human approval nor a cadence-dispatched review marker.
//!
//! CodeRabbit's retirement (cameronsjo/cadence#1037) replaced the bot review
//! with a convention: a dispatched reviewer's findings are posted on the PR
//! as a COMMENT review whose body's first line is a machine-readable marker
//! —`<!-- cadence-review: <reviewer> head=<40-char SHA> crit=<n> imp=<n> -->` — and
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
    carries_undo_flag, command_segments, command_word, git_command, host_and_repo_from_url,
    strip_group_wrappers, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
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
/// One deliberate difference remains, and it is leniency in the safe
/// direction: the caller matches against `body.trim_start()`, so invisible
/// leading whitespace before the marker is tolerated here and rejected there.
/// A marker that parses on the bash side always parses here.
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
///
/// `gh pr ready --undo` is excluded: it flips the PR back to DRAFT, the exact
/// retreat from the ship this guard's reviewed-signal nudge is about, so the
/// nudge would be noise. The `--undo` scan is
/// [`carries_undo_flag`][cadence_hooks_core::shell::carries_undo_flag] — the
/// same predicate the ship anchor uses (cadence-hooks#773/#774), which skips
/// redirect targets and here-string words because the shell eats them and gh
/// never sees the flag.
fn is_pr_flip_command(command: &str) -> bool {
    command_segments(command).into_iter().any(|segment| {
        let tokens = tokenize(strip_group_wrappers(&segment));
        let is_gh_pr = tokens
            .first()
            .is_some_and(|first| command_word(first).as_ref() == "gh")
            && tokens.get(1).map(String::as_str) == Some("pr");
        if !is_gh_pr {
            return false;
        }
        match tokens.get(2).map(String::as_str) {
            Some("ready") => !carries_undo_flag(tokens.get(3..).unwrap_or(&[])),
            Some("merge") => true,
            _ => false,
        }
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
        // `chars`, not a byte slice: `headRefOid` comes from `gh` and a
        // non-hex value would panic a `&head[..7]` on a char boundary.
        short_head = head.chars().take(7).collect::<String>(),
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
    fn gh_pr_ready_undo_does_not_match() {
        // `--undo` flips the PR BACK to draft — it un-ships, so the reviewed
        // signal it would nudge about is not owed (cadence-hooks#774, sibling
        // of the `segment_ship_anchor` fix in #773).
        assert!(!is_pr_flip_command("gh pr ready --undo"));
        assert!(!is_pr_flip_command("gh pr ready 12 --undo"));
        assert!(!is_pr_flip_command("cd repo && gh pr ready --undo"));
        // Positive controls: the real flip still matches.
        assert!(is_pr_flip_command("gh pr ready"));
        assert!(is_pr_flip_command("gh pr ready 12"));
        // `--undo` is not a `gh pr merge` flag; merge never loses its match.
        assert!(is_pr_flip_command("gh pr merge 12 --undo"));
    }

    #[test]
    fn gh_pr_ready_undo_as_a_redirect_target_still_matches() {
        // The shell eats a redirect target and a here-string word — gh never
        // sees the flag, so these ship for real and still owe the nudge.
        assert!(is_pr_flip_command("gh pr ready 12 > --undo"));
        assert!(is_pr_flip_command("gh pr ready 12 <<< --undo"));
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
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
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
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([{
                "user": {"login": "cameronsjo"},
                "state": "COMMENTED",
                "commit_id": "abc1234abcabc1234abcabc1234abcabc1234abc",
                "body": "<!-- cadence-review: cadence:code-reviewer head=abc1234abcabc1234abcabc1234abcabc1234abc crit=0 imp=0 -->\nfindings"
            }]),
        );
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
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
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
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
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
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
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn no_reviews_nudges() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
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
        assert!(evaluate("owner/repo", "gh pr merge 5", &gh).is_some());
    }

    #[test]
    fn fetch_error_is_silent() {
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &ErrGh), None);
    }

    #[test]
    fn malformed_reviews_json_is_silent() {
        let mut gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        gh.reviews_json = Some("not json".to_string());
        assert_eq!(evaluate("owner/repo", "gh pr merge 5", &gh), None);
    }

    #[test]
    fn unresolvable_pr_number_is_silent() {
        let gh = FakeGh::new(
            "abc1234abcabc1234abcabc1234abcabc1234abc",
            "cameronsjo",
            serde_json::json!([]),
        );
        // No number in the command, and the bare `gh pr view --json number`
        // lookup returns None (FakeGh's default) — unresolvable.
        assert_eq!(evaluate("owner/repo", "gh pr merge --auto", &gh), None);
    }
}
