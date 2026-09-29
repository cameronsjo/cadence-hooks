//! Warn on `gh pr ready` / `gh pr merge` when the PR body was never edited
//! after the PR was opened, while the branch has gained commits since
//! (cameronsjo/cadence-hooks#766).
//!
//! The entry posture opens a draft PR with a placeholder body before the work
//! exists. The ready flip is where that body is meant to be rewritten
//! (`using-worktrees` § Session Exit Posture, cameronsjo/cadence#1068), because
//! a squash merge turns it into the durable commit record. This is the
//! deterministic net under that doctrine, sibling of
//! `warn-unreviewed-ready-flip` and `warn-plan-ready-flip`, and it shares
//! their flip matcher ([`pr_flip_segments`]).
//!
//! **Signal.** GitHub's `lastEditedAt` on the PR is `null` (the body has never
//! been edited — a title edit does not set it) and at least one commit on the
//! PR has a committer date after the PR's `createdAt`. Committer dates move on
//! a rebase or amend, so rewritten history counts as new work too, which is
//! the case the body most needs refreshing.
//!
//! Advisory only, and fails open (ADR-0001) on every error: a gh failure or
//! timeout, unparseable JSON or timestamps, an unresolvable PR, or a host the
//! command names that is neither `github.com` nor `origin`'s. PR resolution is
//! `warn-unreviewed-ready-flip`'s ([`FlipTarget`], [`resolve_pr`]) so the two
//! nudges always examine the same PR, and every gh call is bounded
//! ([`crate::bounded_tool`]).

use cadence_hooks_core::shell::pr_flip_segments;
use cadence_hooks_core::time::rfc3339_unix_seconds;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::PathBuf;

use crate::bounded_tool::BoundedGhRunner;
use crate::warn_unreviewed_ready_flip::{
    FlipContext, FlipTarget, GhRunner, hosts_are_trusted, resolve_pr,
};

/// The PR's creation time, body edit time, and newest commits in one request.
/// Owner, name, and number go in as GraphQL variables, so nothing from the
/// command is spliced into the query text.
const BODY_STATE_QUERY: &str = "query($owner: String!, $name: String!, $number: Int!) { \
    repository(owner: $owner, name: $name) { pullRequest(number: $number) { \
    createdAt lastEditedAt \
    commits(last: 100) { nodes { commit { committedDate } } } } } }";

/// What the query says about the body's age against the branch.
#[derive(Debug, PartialEq, Eq)]
struct BodyState {
    /// The body has been edited at least once since creation.
    edited: bool,
    /// Commits whose committer date is after the PR's creation.
    commits_since_creation: usize,
}

/// Parse the GraphQL response. `None` on any shape or timestamp surprise.
fn parse_body_state(json: &str) -> Option<BodyState> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let pr = value.pointer("/data/repository/pullRequest")?;
    let created = rfc3339_unix_seconds(pr.get("createdAt")?.as_str()?)?;
    let edited = match pr.get("lastEditedAt")? {
        serde_json::Value::Null => false,
        serde_json::Value::String(_) => true,
        _ => return None,
    };
    let nodes = pr.pointer("/commits/nodes")?.as_array()?;
    let mut commits_since_creation = 0;
    for node in nodes {
        let date = rfc3339_unix_seconds(node.pointer("/commit/committedDate")?.as_str()?)?;
        if date > created {
            commits_since_creation += 1;
        }
    }
    Some(BodyState {
        edited,
        commits_since_creation,
    })
}

/// Core decision, injected with a `GhRunner`. `Some(message)` to nudge.
pub fn evaluate(
    target: &FlipTarget,
    origin_host: Option<&str>,
    gh: &dyn GhRunner,
) -> Option<String> {
    // Fail-open allow (ADR-0001): a host only the command text names must not
    // receive a request before the user approves the command.
    if !hosts_are_trusted(&target.named_hosts, origin_host) {
        return None;
    }
    let (query_repo, pr_num) = resolve_pr(target, gh)?;
    let (repo_flag, owner, name) = query_repo.graphql_fields();
    let query = format!("query={BODY_STATE_QUERY}");
    let number = format!("number={pr_num}");
    let json = gh.run(&[
        "api", "graphql", "-f", &query, repo_flag, &owner, repo_flag, &name, "-F", &number,
    ])?;
    let state = parse_body_state(&json)?;
    if state.edited || state.commits_since_creation == 0 {
        return None;
    }
    let n = state.commits_since_creation;
    let plural = if n == 1 { "" } else { "s" };
    Some(format!(
        "warn-stale-pr-body: PR #{pr_num}'s body has not been edited since the PR was opened, \
         and the branch has gained {n} commit{plural} since. The flip is where the \
         placeholder body gets rewritten — a squash merge makes it the durable record. \
         Refresh the title and body to describe what actually shipped (`gh pr edit \
         {pr_num} --body-file <file>`) before flipping. See `using-worktrees` § Session \
         Exit Posture. Advisory only."
    ))
}

/// Nudges on `gh pr ready` / `gh pr merge` when the PR body predates the
/// branch's commits.
pub struct WarnStalePrBody;

impl Check for WarnStalePrBody {
    fn name(&self) -> &str {
        "warn-stale-pr-body"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        // Only the first flip segment is examined, as in the sibling guard.
        let Some(tokens) = pr_flip_segments(command).into_iter().next() else {
            return CheckResult::allow();
        };
        let Some(target) = FlipTarget::from_tokens(&tokens) else {
            return CheckResult::allow();
        };
        let ctx = FlipContext::for_target(&target, input);
        let gh = BoundedGhRunner {
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
    use std::cell::RefCell;

    /// Answers `gh api graphql` with `state_json` and `gh pr view` with
    /// `pr_view_json`, recording every call.
    struct FakeGh {
        state_json: Option<String>,
        pr_view_json: Option<String>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl FakeGh {
        fn new(state_json: Option<&str>) -> Self {
            FakeGh {
                state_json: state_json.map(String::from),
                pr_view_json: Some(
                    r#"{"number":7,"url":"https://github.com/o/r/pull/7"}"#.to_string(),
                ),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(ToString::to_string).collect());
            match (args.first(), args.get(1)) {
                (Some(&"pr"), Some(&"view")) => self.pr_view_json.clone(),
                (Some(&"api"), Some(&"graphql")) => self.state_json.clone(),
                _ => None,
            }
        }
    }

    fn state(last_edited: &str, commit_dates: &[&str]) -> String {
        let nodes: Vec<String> = commit_dates
            .iter()
            .map(|d| format!(r#"{{"commit":{{"committedDate":"{d}"}}}}"#))
            .collect();
        format!(
            r#"{{"data":{{"repository":{{"pullRequest":{{"createdAt":"2026-09-01T10:00:00Z","lastEditedAt":{last_edited},"commits":{{"nodes":[{}]}}}}}}}}}}"#,
            nodes.join(",")
        )
    }

    fn target(command: &str) -> FlipTarget {
        let tokens = pr_flip_segments(command)
            .into_iter()
            .next()
            .expect("command should be a flip");
        FlipTarget::from_tokens(&tokens).expect("target should parse")
    }

    #[test]
    fn unedited_body_with_commits_after_creation_nudges() {
        let gh = FakeGh::new(Some(&state(
            "null",
            &[
                "2026-09-01T09:00:00Z",
                "2026-09-02T10:00:00Z",
                "2026-09-03T10:00:00Z",
            ],
        )));
        let msg = evaluate(&target("gh pr ready 12"), None, &gh).expect("should nudge");
        assert!(msg.contains("warn-stale-pr-body"), "{msg}");
        assert!(msg.contains("PR #12"), "{msg}");
        assert!(msg.contains("2 commits"), "{msg}");
    }

    #[test]
    fn edited_body_is_silent() {
        let gh = FakeGh::new(Some(&state(
            r#""2026-09-02T12:00:00Z""#,
            &["2026-09-03T10:00:00Z"],
        )));
        assert_eq!(evaluate(&target("gh pr ready 12"), None, &gh), None);
    }

    #[test]
    fn no_commits_after_creation_is_silent() {
        let gh = FakeGh::new(Some(&state(
            "null",
            &["2026-08-30T10:00:00Z", "2026-09-01T10:00:00Z"],
        )));
        assert_eq!(
            evaluate(&target("gh pr merge 12 --squash"), None, &gh),
            None
        );
    }

    #[test]
    fn gh_failure_or_garbage_fails_open() {
        let gh = FakeGh::new(None);
        assert_eq!(evaluate(&target("gh pr ready 12"), None, &gh), None);
        let gh = FakeGh::new(Some("not json"));
        assert_eq!(evaluate(&target("gh pr ready 12"), None, &gh), None);
        let gh = FakeGh::new(Some(&state("null", &["not-a-date"])));
        assert_eq!(evaluate(&target("gh pr ready 12"), None, &gh), None);
    }

    #[test]
    fn untrusted_host_is_never_queried() {
        let gh = FakeGh::new(Some(&state("null", &["2026-09-03T10:00:00Z"])));
        let t = target("gh pr ready https://evil.example/o/r/pull/3");
        assert_eq!(evaluate(&t, None, &gh), None);
        assert!(
            gh.calls.borrow().is_empty(),
            "no gh call for an untrusted host"
        );
    }

    #[test]
    fn selectorless_flip_resolves_through_pr_view_then_queries_named_repo() {
        let gh = FakeGh::new(Some(&state("null", &["2026-09-03T10:00:00Z"])));
        let msg = evaluate(&target("gh pr ready"), None, &gh).expect("should nudge");
        assert!(msg.contains("PR #7"), "{msg}");
        let calls = gh.calls.borrow();
        assert_eq!(calls[0][..2], ["pr".to_string(), "view".to_string()]);
        assert!(calls[1].contains(&"owner=o".to_string()), "{calls:?}");
        assert!(calls[1].contains(&"name=r".to_string()), "{calls:?}");
    }

    #[test]
    fn explicit_repo_goes_in_as_raw_variables() {
        let gh = FakeGh::new(Some(&state("null", &["2026-09-03T10:00:00Z"])));
        evaluate(&target("gh pr merge 5 -R acme/widgets"), None, &gh).expect("should nudge");
        let calls = gh.calls.borrow();
        let args = &calls[0];
        assert!(args.contains(&"owner=acme".to_string()), "{args:?}");
        assert!(args.contains(&"number=5".to_string()), "{args:?}");
        assert!(args.iter().any(|a| a == "-f"), "{args:?}");
    }

    #[test]
    fn non_flip_commands_are_silent_without_a_gh_call() {
        for cmd in ["gh pr view 12", "gh pr ready 12 --undo", "git status"] {
            let input = cadence_hooks_core::test_builders::make_bash(cmd);
            assert_eq!(WarnStalePrBody.run(&input).outcome, Outcome::Allow, "{cmd}");
        }
    }
}
