//! Advisory check: warn about broken issue refs on `gh pr create`; close
//! straggler issues on `gh pr merge` that GitHub's auto-close didn't fire for.
//!
//! PostToolUse Bash hook — **always exit 0** (never blocks). Side-effecting:
//! `handle_merge` may close open issues via `gh issue close`.
//!
//! Config knob: `GH_AUTOCLOSE_WAIT_SECONDS` (default `10`).

use cadence_hooks_core::shell::{git_command, host_and_repo_from_url};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

// Closing-keyword detection is shared with guard_pr_issue_link via issue_refs.
pub use crate::issue_refs::extract_refs;

/// Parse a git remote URL into `(host, "owner/repo")`.
///
/// Returns:
/// - `Some((None, slug))` for public GitHub (`github.com`)
/// - `Some((Some(host), slug))` for enterprise GitHub hosts
/// - `None` for local paths or unparseable URLs
///
/// Delegates to `host_and_repo_from_url` for URL parsing, which correctly
/// strips `.git` suffixes and handles dots in repo names.
pub fn parse_remote(url: &str) -> Option<(Option<String>, String)> {
    let (host, slug) = host_and_repo_from_url(url)?;
    if host == "github.com" {
        Some((None, slug))
    } else {
        Some((Some(host), slug))
    }
}

/// Extract the PR number from `gh pr create` stdout.
///
/// Looks for the first `/pull/<N>` URL in the output (the URL `gh` prints on success).
pub fn pr_number_from_create_stdout(stdout: &str) -> Option<u64> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"/pull/([0-9]+)").expect("pattern should compile"));
    RE.captures(stdout)?.get(1)?.as_str().parse().ok()
}

/// Extract the PR number from a `gh pr merge` command string.
///
/// Looks for the first bare integer token after `gh pr merge`. Returns `None`
/// when no number is present (bare `gh pr merge --squash` falls back to the
/// current-branch PR at runtime).
pub fn pr_number_from_merge_cmd(cmd: &str) -> Option<u64> {
    // Find "gh pr merge" then scan tokens after it for a bare integer
    let after = cmd.split("gh pr merge").nth(1)?;
    for token in after.split_whitespace() {
        if token.starts_with('-') {
            continue;
        }
        if let Ok(n) = token.parse::<u64>() {
            return Some(n);
        }
        // First non-flag, non-integer token → stop (e.g. a branch name)
        break;
    }
    None
}

// ---------------------------------------------------------------------------
// I/O traits (injected for testability)
// ---------------------------------------------------------------------------

/// Runs `gh` CLI commands, returning trimmed stdout on success or `None` on error.
pub trait GhRunner {
    fn run(&self, args: &[&str]) -> Option<String>;
}

/// Sleeps for a given number of seconds (injectable so tests don't actually sleep).
pub trait Clock {
    fn sleep_secs(&self, secs: u64);
}

// ---------------------------------------------------------------------------
// Real I/O implementations
// ---------------------------------------------------------------------------

/// Production `gh` runner: shells out to the system `gh` binary.
///
/// Carries the enterprise host (if any) and scopes `GH_HOST` to each spawned
/// command — no process-global env mutation.
pub struct RealGhRunner {
    /// `GH_HOST` value for enterprise GitHub remotes; `None` targets github.com.
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
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
}

/// Production clock: delegates to `std::thread::sleep`.
pub struct RealClock;

impl Clock for RealClock {
    fn sleep_secs(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

// ---------------------------------------------------------------------------
// Handle-create flow
// ---------------------------------------------------------------------------

/// Issue state as returned by `gh issue view --json state`.
#[derive(Debug, PartialEq, Eq)]
enum IssueState {
    Open,
    Closed,
    Missing,
}

/// Parse the state string from `gh issue view --json state -q .state`.
fn parse_issue_state(raw: Option<String>) -> IssueState {
    match raw.as_deref() {
        Some("OPEN") => IssueState::Open,
        Some("CLOSED") => IssueState::Closed,
        _ => IssueState::Missing,
    }
}

/// Fetch and classify the state of a single issue.
fn fetch_issue_state(gh: &dyn GhRunner, issue: u64, slug: &str) -> IssueState {
    let raw = gh.run(&[
        "issue",
        "view",
        &issue.to_string(),
        "--json",
        "state",
        "-q",
        ".state",
        "-R",
        slug,
    ]);
    parse_issue_state(raw)
}

/// Warn about broken issue references in a newly-created PR.
///
/// Fetches the PR body, extracts closing-keyword refs, and returns a warning
/// message for any ref that is CLOSED (auto-close can't re-fire) or MISSING
/// (not found). Returns `None` on the happy path (all refs OPEN, or no refs).
/// The caller routes the message through `CheckResult::nudge` so Claude sees it.
pub fn handle_create(slug: &str, stdout: &str, gh: &dyn GhRunner) -> Option<String> {
    let pr_num = pr_number_from_create_stdout(stdout)?;

    // Fetch the PR body as JSON then extract the body field
    let body_json = gh.run(&[
        "pr",
        "view",
        &pr_num.to_string(),
        "--json",
        "body",
        "-R",
        slug,
    ])?;

    // Parse body from JSON: {"body":"..."} — use serde_json for correctness
    let body: String = match serde_json::from_str::<serde_json::Value>(&body_json) {
        Ok(v) => v
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
        Err(_) => body_json, // fall back to raw if not JSON
    };

    let refs = extract_refs(&body);
    if refs.is_empty() {
        return None;
    }

    let mut warnings: Vec<String> = Vec::new();
    for issue in &refs {
        match fetch_issue_state(gh, *issue, slug) {
            IssueState::Open => {} // happy path
            IssueState::Closed => {
                warnings.push(format!(
                    "  - #{issue} already CLOSED — auto-close cannot re-fire"
                ));
            }
            IssueState::Missing => {
                warnings.push(format!("  - #{issue} not found in {slug}"));
            }
        }
    }

    if warnings.is_empty() {
        None
    } else {
        Some(format!(
            "verify-pr-autoclose: PR #{pr_num} has broken references:\n{}",
            warnings.join("\n")
        ))
    }
}

// ---------------------------------------------------------------------------
// Handle-merge flow
// ---------------------------------------------------------------------------

/// Close straggler issues that GitHub's auto-close missed after a PR merge.
///
/// Waits `wait_secs` (injected via `clock`) to give GitHub time to auto-close,
/// then checks each referenced issue. If still OPEN, closes it via `gh issue close`
/// with a commit-citing comment. Returns a summary message naming the closed
/// issues, or `None` when there was nothing to do. The caller routes the
/// message through `CheckResult::nudge` so Claude sees it.
pub fn handle_merge(
    slug: &str,
    cmd: &str,
    gh: &dyn GhRunner,
    clock: &dyn Clock,
    wait_secs: u64,
) -> Option<String> {
    // Resolve PR number: from command or from `gh pr view`
    let pr_num = match pr_number_from_merge_cmd(cmd) {
        Some(n) => n,
        None => {
            let raw = gh.run(&[
                "pr", "view", "--json", "number", "-q", ".number", "-R", slug,
            ]);
            raw.and_then(|s| s.parse::<u64>().ok())?
        }
    };

    clock.sleep_secs(wait_secs);

    // Fetch body + mergeCommit
    let pr_json = gh.run(&[
        "pr",
        "view",
        &pr_num.to_string(),
        "--json",
        "body,mergeCommit",
        "-R",
        slug,
    ])?;

    let value: serde_json::Value = serde_json::from_str(&pr_json).ok()?;

    let body = value
        .get("body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

    let merge_sha = value
        .get("mergeCommit")
        .and_then(|mc: &serde_json::Value| mc.get("oid"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    let refs = extract_refs(&body);
    if refs.is_empty() {
        return None;
    }

    let short_sha = if merge_sha.len() >= 7 {
        &merge_sha[..7]
    } else {
        merge_sha
    };

    let mut closed: Vec<String> = Vec::new();

    for issue in &refs {
        if fetch_issue_state(gh, *issue, slug) != IssueState::Open {
            continue;
        }

        let comment =
            format!("Closed via PR #{pr_num} (commit {short_sha}) — auto-close didn't fire.");

        let ok = gh
            .run(&[
                "issue",
                "close",
                &issue.to_string(),
                "-R",
                slug,
                "--comment",
                &comment,
            ])
            .is_some();

        if ok {
            closed.push(format!("#{issue}"));
        }
    }

    if closed.is_empty() {
        None
    } else {
        Some(format!(
            "verify-pr-autoclose: closed {} straggler issue(s) for PR #{pr_num}: {}",
            closed.len(),
            closed.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Check implementation
// ---------------------------------------------------------------------------

/// Advisory check for PR auto-close behaviour.
///
/// On `gh pr create`: warns about broken/already-closed issue refs in the PR body.
/// On `gh pr merge`: waits briefly, then closes any straggler issues that GitHub
/// missed, citing the merge commit.
///
/// Always exits 0 — never blocks.
pub struct VerifyPrAutoclose;

impl Check for VerifyPrAutoclose {
    fn name(&self) -> &str {
        "verify-pr-autoclose"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(cmd) = input.command() else {
            return CheckResult::allow();
        };

        // Resolve working directory
        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);

        // Get remote URL and parse it
        let Some(remote_url) = git_command(cwd, &["remote", "get-url", "origin"]) else {
            return CheckResult::allow();
        };

        let Some((host, slug)) = parse_remote(&remote_url) else {
            return CheckResult::allow();
        };

        // Enterprise GitHub: scope GH_HOST to the runner's spawned commands
        // rather than mutating this process's environment.
        let gh = RealGhRunner { gh_host: host };
        let clock = RealClock;
        let wait_secs: u64 = std::env::var("GH_AUTOCLOSE_WAIT_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let message = if cmd.contains("gh pr create") {
            let stdout = input.tool_response_stdout().unwrap_or("");
            handle_create(&slug, stdout, &gh)
        } else if cmd.contains("gh pr merge") {
            handle_merge(&slug, cmd, &gh, &clock, wait_secs)
        } else {
            // Not a create or merge command — no handler invoked
            None
        };

        match message {
            Some(msg) => CheckResult::nudge(msg),
            None => CheckResult::allow(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_bash, make_bash_post_tool_use};
    use std::cell::RefCell;
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Pure layer tests (cases 1–10)
    // -----------------------------------------------------------------------

    // Case 1: extract_refs — deduped, sorted, multiple keywords
    #[test]
    fn extract_refs_multiple_keywords_deduped_sorted() {
        let refs = extract_refs("Closes #12 and fixes #3, resolves #12");
        assert_eq!(refs, vec![3, 12]);
    }

    // Case 2: extract_refs — no closing keyword → empty
    #[test]
    fn extract_refs_no_closing_keyword_is_empty() {
        let refs = extract_refs("see #9 for context");
        assert_eq!(refs, Vec::<u64>::new());
    }

    // Case 3: extract_refs — case-insensitive, deduped
    #[test]
    fn extract_refs_case_insensitive_deduped() {
        let refs = extract_refs("FIXED #7\nCloses #7");
        assert_eq!(refs, vec![7]);
    }

    // Case 4: parse_remote — github.com SSH SCP style → host None
    #[test]
    fn parse_remote_github_ssh_public() {
        let result = parse_remote("git@github.com:cameronsjo/cadence-hooks.git");
        assert_eq!(result, Some((None, "cameronsjo/cadence-hooks".to_string())));
    }

    // Case 5: parse_remote — enterprise GitHub HTTPS → host Some
    #[test]
    fn parse_remote_enterprise_https() {
        let result = parse_remote("https://gecgithub01.walmart.com/c0s013l/foo.git");
        assert_eq!(
            result,
            Some((
                Some("gecgithub01.walmart.com".to_string()),
                "c0s013l/foo".to_string()
            ))
        );
    }

    // Case 6: parse_remote — dots in repo name must be preserved
    #[test]
    fn parse_remote_dots_in_repo_name() {
        let result = parse_remote("git@github.com:owner/repo.with.dots.git");
        // host_and_repo_from_url strips .git, then takes first two path segments
        // For SCP: path = "owner/repo.with.dots.git", after strip: "owner/repo.with.dots"
        // splitn(3, '/') → ["owner", "repo.with.dots"] — dots preserved ✓
        assert_eq!(result, Some((None, "owner/repo.with.dots".to_string())));
    }

    // Case 7: parse_remote — local path → None
    #[test]
    fn parse_remote_local_path_is_none() {
        let result = parse_remote("/local/path");
        assert_eq!(result, None);
    }

    // Case 8: pr_number_from_create_stdout — extracts from URL
    #[test]
    fn pr_number_from_create_stdout_extracts_number() {
        let stdout = "https://github.com/o/r/pull/42";
        assert_eq!(pr_number_from_create_stdout(stdout), Some(42));
    }

    // Case 9: pr_number_from_merge_cmd — number present
    #[test]
    fn pr_number_from_merge_cmd_with_number() {
        assert_eq!(
            pr_number_from_merge_cmd("gh pr merge 17 --squash"),
            Some(17)
        );
    }

    // Case 10: pr_number_from_merge_cmd — no number → None
    #[test]
    fn pr_number_from_merge_cmd_no_number_is_none() {
        assert_eq!(pr_number_from_merge_cmd("gh pr merge --squash"), None);
    }

    // -----------------------------------------------------------------------
    // Fake I/O implementations for shell-flow tests
    // -----------------------------------------------------------------------

    /// In-memory `gh` runner for tests.
    ///
    /// Stores issue states and records calls made to `gh issue close`.
    struct FakeGh {
        /// Maps issue number → state string ("OPEN" | "CLOSED")
        issue_states: HashMap<u64, String>,
        /// PR body to return for `gh pr view <n> --json body,mergeCommit`
        pr_body: String,
        /// PR number to return for bare `gh pr view --json number`
        pr_number: Option<u64>,
        /// merge commit OID
        merge_commit_oid: String,
        /// Captures `gh issue close` calls: (issue_number, comment)
        close_calls: RefCell<Vec<(u64, String)>>,
        /// Captures `gh pr view <n> --json body` calls
        body_calls: RefCell<Vec<u64>>,
    }

    impl FakeGh {
        fn new() -> Self {
            Self {
                issue_states: HashMap::new(),
                pr_body: String::new(),
                pr_number: None,
                merge_commit_oid: "abc1234def".to_string(),
                close_calls: RefCell::new(Vec::new()),
                body_calls: RefCell::new(Vec::new()),
            }
        }

        fn with_issue(mut self, num: u64, state: &str) -> Self {
            self.issue_states.insert(num, state.to_string());
            self
        }

        fn with_pr_body(mut self, body: &str) -> Self {
            self.pr_body = body.to_string();
            self
        }

        fn with_merge_commit(mut self, oid: &str) -> Self {
            self.merge_commit_oid = oid.to_string();
            self
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            // Match: gh issue view <N> --json state -q .state -R <slug>
            if args.len() >= 4
                && args[0] == "issue"
                && args[1] == "view"
                && let Ok(num) = args[2].parse::<u64>()
            {
                // Check for state vs close subcommand
                if args.contains(&"state") {
                    return self.issue_states.get(&num).cloned();
                }
            }

            // Match: gh issue close <N> -R <slug> --comment <text>
            if args.len() >= 2
                && args[0] == "issue"
                && args[1] == "close"
                && let Ok(num) = args[2].parse::<u64>()
            {
                // Find comment after --comment flag
                let comment = args
                    .windows(2)
                    .find(|w| w[0] == "--comment")
                    .map(|w| w[1].to_string())
                    .unwrap_or_default();
                self.close_calls.borrow_mut().push((num, comment));
                return Some("closed".to_string());
            }

            // Match: gh pr view ... (handle_create, handle_merge, or bare current-branch lookup)
            if args.len() >= 4 && args[0] == "pr" && args[1] == "view" {
                match args[2].parse::<u64>() {
                    Ok(num) => {
                        // Determine which --json field set was requested
                        let json_fields = args.windows(2).find(|w| w[0] == "--json").map(|w| w[1]);

                        match json_fields {
                            Some("body") => {
                                // body-only fetch (handle_create)
                                self.body_calls.borrow_mut().push(num);
                                let json = serde_json::json!({"body": self.pr_body});
                                return Some(json.to_string());
                            }
                            Some("body,mergeCommit") => {
                                // body + mergeCommit fetch (handle_merge)
                                let json = serde_json::json!({
                                    "body": self.pr_body,
                                    "mergeCommit": {"oid": self.merge_commit_oid}
                                });
                                return Some(json.to_string());
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // Bare `gh pr view --json number -q .number` (no PR number in args)
                        if args.contains(&"number") {
                            return self.pr_number.map(|n| n.to_string());
                        }
                    }
                }
            }

            None
        }
    }

    /// No-op clock for tests — records sleep calls.
    struct FakeClock {
        sleep_calls: RefCell<Vec<u64>>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                sleep_calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Clock for FakeClock {
        fn sleep_secs(&self, secs: u64) {
            self.sleep_calls.borrow_mut().push(secs);
        }
    }

    // -----------------------------------------------------------------------
    // Shell-flow tests (cases 11–18)
    // -----------------------------------------------------------------------

    // Case 11: create, body refs #5 (OPEN) → no warning message
    #[test]
    fn create_body_refs_open_issue_no_warnings() {
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5");

        let msg = handle_create("owner/repo", "https://github.com/owner/repo/pull/1", &gh);

        assert_eq!(msg, None, "happy path should produce no warning");
        assert!(gh.close_calls.borrow().is_empty());
        assert_eq!(*gh.body_calls.borrow(), vec![1u64]);
    }

    // Case 12: create, body refs #5 (CLOSED) → warning names the issue and reason
    #[test]
    fn create_body_refs_closed_issue_emits_warning() {
        let gh = FakeGh::new()
            .with_issue(5, "CLOSED")
            .with_pr_body("Closes #5");

        let msg = handle_create("owner/repo", "https://github.com/owner/repo/pull/1", &gh)
            .expect("closed ref should produce a warning");

        assert!(msg.contains("#5"), "warning should name the issue: {msg}");
        assert!(
            msg.contains("already CLOSED"),
            "warning should explain auto-close cannot re-fire: {msg}"
        );
        assert!(
            msg.contains("PR #1"),
            "warning should cite the PR number: {msg}"
        );
        // Warnings only, no mutation
        assert!(gh.close_calls.borrow().is_empty());
    }

    // Case 13: create, body refs #99 (missing) → warns "not found"
    #[test]
    fn create_body_refs_missing_issue_emits_warning() {
        let gh = FakeGh::new()
            // issue 99 not in map → gh returns None → Missing state
            .with_pr_body("Closes #99");

        let msg = handle_create("owner/repo", "https://github.com/owner/repo/pull/1", &gh)
            .expect("missing ref should produce a warning");

        assert!(
            msg.contains("#99") && msg.contains("not found"),
            "warning should name the missing issue: {msg}"
        );
        assert!(gh.close_calls.borrow().is_empty());
    }

    // Case 14: create, body has no refs → no warning, no issue-state calls
    #[test]
    fn create_body_no_refs_returns_early() {
        let gh = FakeGh::new().with_pr_body("This PR is purely cosmetic.");

        let msg = handle_create("owner/repo", "https://github.com/owner/repo/pull/1", &gh);

        assert_eq!(msg, None);
        assert!(gh.close_calls.borrow().is_empty());
        // No issue state calls because refs list is empty
        assert_eq!(*gh.body_calls.borrow(), vec![1u64]);
    }

    // Case 15: merge #8, body refs #5 OPEN → closes #5 with correct comment
    #[test]
    fn merge_open_issue_gets_closed_with_commit_citation() {
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge("owner/repo", "gh pr merge 8 --squash", &gh, &clock, 0)
            .expect("closing a straggler should produce a summary");

        assert!(
            msg.contains("closed 1 straggler") && msg.contains("#5"),
            "summary should count and name closed issues: {msg}"
        );

        let calls = gh.close_calls.borrow();
        assert_eq!(calls.len(), 1, "should close issue #5");
        let (num, comment) = &calls[0];
        assert_eq!(*num, 5);
        assert!(
            comment.contains("PR #8"),
            "comment should cite PR number: {comment}"
        );
        assert!(
            comment.contains("abc1234"),
            "comment should cite short commit SHA: {comment}"
        );
    }

    // Case 16: merge #8, body refs #5 already CLOSED → no close call
    #[test]
    fn merge_already_closed_issue_skipped() {
        let gh = FakeGh::new()
            .with_issue(5, "CLOSED")
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge("owner/repo", "gh pr merge 8 --squash", &gh, &clock, 0);

        assert_eq!(msg, None, "nothing closed → no summary message");
        assert!(
            gh.close_calls.borrow().is_empty(),
            "should not close already-closed issue"
        );
    }

    // Case 17: merge, no PR number resolvable → return early, no sleep
    #[test]
    fn merge_no_pr_number_returns_early_no_sleep() {
        let gh = FakeGh::new(); // pr_number is None by default

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            "gh pr merge --squash", // no number in cmd
            &gh,
            &clock,
            10,
        );

        assert_eq!(msg, None);
        // No sleep should have been called because we return before sleeping
        assert!(
            clock.sleep_calls.borrow().is_empty(),
            "should not sleep when PR number unresolvable"
        );
        assert!(gh.close_calls.borrow().is_empty());
    }

    // Case 18: cmd is neither create nor merge → Check::run allows, no handler invoked
    // (Tested via the Check trait — we verify allow() is returned for unrelated commands)
    #[test]
    fn unrelated_command_returns_allow() {
        let input = make_bash("git status");
        // We can't call VerifyPrAutoclose::run here because it hits git remote.
        // Instead test the logic path: if cmd doesn't contain "gh pr create" or "gh pr merge",
        // neither handler is invoked. We verify this via pr_number_from_create_stdout
        // and pr_number_from_merge_cmd returning None for unrelated commands.
        assert_eq!(pr_number_from_create_stdout("git status output"), None);
        assert_eq!(pr_number_from_merge_cmd("git status"), None);

        // Additionally verify the Check returns allow (the guard is the top-level command check)
        // This will attempt git remote; if not in a git repo → allow
        let result = VerifyPrAutoclose.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // -----------------------------------------------------------------------
    // Additional pure-helper edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn extract_refs_all_variants() {
        let text = "close #1 closed #2 closes #3 fix #4 fixed #5 fixes #6 resolve #7 resolved #8 resolves #9";
        let refs = extract_refs(text);
        assert_eq!(refs, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn extract_refs_empty_string() {
        assert_eq!(extract_refs(""), Vec::<u64>::new());
    }

    #[test]
    fn pr_number_from_create_stdout_no_url_is_none() {
        assert_eq!(pr_number_from_create_stdout("Created pull request"), None);
    }

    #[test]
    fn pr_number_from_merge_cmd_flags_only() {
        // --squash and --delete-branch are flags, not a number
        assert_eq!(
            pr_number_from_merge_cmd("gh pr merge --squash --delete-branch"),
            None
        );
    }

    #[test]
    fn parse_remote_github_https() {
        let result = parse_remote("https://github.com/cameronsjo/cadence-hooks.git");
        assert_eq!(result, Some((None, "cameronsjo/cadence-hooks".to_string())));
    }

    #[test]
    fn parse_issue_state_open() {
        assert_eq!(
            parse_issue_state(Some("OPEN".to_string())),
            IssueState::Open
        );
    }

    #[test]
    fn parse_issue_state_closed() {
        assert_eq!(
            parse_issue_state(Some("CLOSED".to_string())),
            IssueState::Closed
        );
    }

    #[test]
    fn parse_issue_state_none_is_missing() {
        assert_eq!(parse_issue_state(None), IssueState::Missing);
    }

    #[test]
    fn parse_issue_state_unknown_is_missing() {
        assert_eq!(
            parse_issue_state(Some("DELETED".to_string())),
            IssueState::Missing
        );
    }

    // Verify make_bash_post_tool_use builder works
    #[test]
    fn post_tool_use_builder_carries_stdout() {
        let input =
            make_bash_post_tool_use("gh pr create ...", "https://github.com/owner/repo/pull/42");
        assert_eq!(input.command(), Some("gh pr create ..."));
        assert_eq!(
            input.tool_response_stdout(),
            Some("https://github.com/owner/repo/pull/42")
        );
    }
}
