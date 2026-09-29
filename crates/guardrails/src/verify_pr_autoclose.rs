//! Advisory check: warn about broken issue refs on `gh pr create`; close
//! straggler issues on `gh pr merge` that GitHub's auto-close didn't fire for.
//!
//! PostToolUse Bash hook — **always exit 0** (never blocks). Side-effecting:
//! `handle_merge` may close open issues via `gh issue close`.
//!
//! Config knob: `GH_AUTOCLOSE_WAIT_SECONDS` (default `10`), the maximum wait.
//! The merge flow waits in two phases: after [`EARLY_CHECK_SECS`] it checks
//! the referenced issues and returns when GitHub has already closed them all;
//! otherwise it sleeps the rest of the wait and checks again.

use cadence_hooks_core::shell::{
    GH_DEFAULT_HOST, PrSelector, command_segments, command_word, forge_host, gh_pr_subcommand,
    git_command, host_and_repo_from_url, pr_flip_segments, pr_selector, pr_url_parts,
    repo_value_names_remote, ship_target, tokenize,
};
use cadence_hooks_core::time::{now_unix_seconds, rfc3339_unix_seconds};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// How long after `mergedAt` the merge flow still acts. A `gh pr merge` on a
/// PR merged longer ago than this is a re-run, not the merge itself.
const MERGE_RECENCY_SECS: i64 = 10 * 60;

/// Seconds into the merge wait at which referenced issues are first checked.
///
/// GitHub's auto-close landed 1-2 s after merge in every measured case, so a
/// check at 2 s usually finds every ref closed already. The early check exits
/// only when every ref reads CLOSED; otherwise the flow sleeps the remainder,
/// so the total sleep still equals `wait_secs`.
const EARLY_CHECK_SECS: u64 = 2;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

// Closing-keyword detection is shared with warn_pr_issue_link via issue_refs.
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

/// The PR `gh pr create` reports creating: `(host, "owner/repo", number)`,
/// read from the whitespace-separated words of its stdout that are whole PR
/// URLs ([`pr_url_parts`]). `None` when there is none, or when stdout holds
/// more than one distinct PR URL (a compound command, or output that quotes
/// another PR), since which one was created cannot be told. Repeats of one URL
/// count once; the last is taken.
///
/// The repo comes from the URL, never from `origin` (cadence-hooks#759). A PR
/// opened from a fork with an explicit target lands in the upstream repo, and
/// its number means a different PR, or nothing, in the fork `origin` points
/// at. Reading it there reported refs from another PR's body and that repo's
/// issue states as this PR's.
pub fn pr_from_create_stdout(stdout: &str) -> Option<(String, String, u64)> {
    let mut found: Option<(String, String, u64)> = None;
    for word in stdout.split_whitespace() {
        let Some((host, owner, repo, number)) = pr_url_parts(word) else {
            continue;
        };
        let pr = (
            host.to_ascii_lowercase(),
            format!("{owner}/{repo}").to_ascii_lowercase(),
            number,
        );
        if found.as_ref().is_some_and(|seen| *seen != pr) {
            return None;
        }
        found = Some(pr);
    }
    found
}

/// The PR a `gh pr merge` command acts on, resolved against `origin`
/// (cadence-hooks#759, merge half).
#[derive(Debug, PartialEq, Eq)]
pub enum MergeTarget {
    /// No `gh pr merge` segment.
    NotAMerge,
    /// No selector and no repo override: the PR of the cwd's branch in
    /// origin's repo.
    CurrentBranch,
    /// This PR number, in origin's repo.
    Number(u64),
    /// The command points somewhere this check cannot confirm is origin's
    /// repo, or its PR cannot be read. The merge flow stays silent.
    Unsure,
}

/// Resolve which PR `cmd` merges, and whether it is in origin's repo.
///
/// `origin_host` is origin's forge host ([`forge_host`]) and `origin_slug` its
/// lowercased `owner/repo`. The segment is found by the shared
/// [`pr_flip_segments`] matcher, and its repo and PR are read with
/// [`ship_target`] and [`pr_selector`], so every `-R`/`--repo` spelling, an
/// inline `GH_REPO=`/`GH_HOST=`, and a PR URL are seen. The comparison with
/// origin is the shared [`repo_value_names_remote`]; a bare `OWNER/REPO`
/// means gh's default host unless an inline `GH_HOST=` names another.
///
/// Anything short of a confirmed match is [`MergeTarget::Unsure`]: a repo or
/// URL naming another repo or host, a repo flag with no selector (gh refuses
/// it), a branch or other selector this check cannot map to a number, an
/// unreadable selector, or more than one merge in the command. The merge
/// flow closes issues, so it must never act on a guessed repo. An exported
/// `GH_REPO`/`GH_HOST` leaves no token and is not seen.
///
/// **Allowlist on the whole command** (cadence-hooks#1070 review I2): every
/// segment must be a plain `gh pr <sub>` invocation, `gh` as its first word
/// with nothing in front of it. Anything else anywhere in the command (a
/// `cd`/`pushd`, an `export`/`declare`/bare `GH_REPO=` assignment, an inline
/// assignment or prefix on `gh` itself, a subshell or group, a wrapper, any
/// other command) is [`MergeTarget::Unsure`], because each can move the merge
/// to another directory or repo without a token in the merge segment. So is a
/// `--help`/`-h` in the merge segment, which merges nothing.
pub fn merge_target(cmd: &str, origin_host: &str, origin_slug: &str) -> MergeTarget {
    let segments = command_segments(cmd);
    let plain_gh_pr = |segment: &String| {
        let mut raw = tokenize(segment);
        match raw.first() {
            Some(first) if command_word(first).as_ref() == "gh" => raw[0] = "gh".to_string(),
            _ => return false,
        }
        gh_pr_subcommand(&raw).is_some()
    };
    if segments.is_empty() {
        return MergeTarget::NotAMerge;
    }
    if !segments.iter().all(plain_gh_pr) {
        return if pr_flip_segments(cmd)
            .iter()
            .any(|tokens| gh_pr_subcommand(tokens) == Some("merge"))
        {
            MergeTarget::Unsure
        } else {
            MergeTarget::NotAMerge
        };
    }
    let merges: Vec<Vec<String>> = pr_flip_segments(cmd)
        .into_iter()
        .filter(|tokens| gh_pr_subcommand(tokens) == Some("merge"))
        .collect();
    let tokens = match merges.as_slice() {
        [] => return MergeTarget::NotAMerge,
        [tokens] => tokens,
        _ => return MergeTarget::Unsure,
    };
    // pflag prints help for `-h` anywhere in a short-flag cluster (`-dh`,
    // `-sdh`), and merges nothing.
    let asks_for_help = |t: &String| {
        t == "--help"
            || (t.starts_with('-') && !t.starts_with("--") && !t.contains('=') && t.contains('h'))
    };
    if tokens.iter().any(asks_for_help) {
        return MergeTarget::Unsure;
    }
    let names_origin = |value: &str, implied: Option<&str>| {
        repo_value_names_remote(value, implied, origin_host, origin_slug)
    };
    let ship = ship_target(tokens);
    if let Some(host) = &ship.host
        && forge_host(host.to_ascii_lowercase()) != origin_host
    {
        return MergeTarget::Unsure;
    }
    let implied = ship.host.as_deref().unwrap_or(GH_DEFAULT_HOST);
    if !ship
        .repos
        .iter()
        .all(|value| names_origin(value, Some(implied)))
    {
        return MergeTarget::Unsure;
    }
    match pr_selector(tokens) {
        PrSelector::None if ship.repos.is_empty() => MergeTarget::CurrentBranch,
        PrSelector::Number(n) => MergeTarget::Number(n),
        PrSelector::Url {
            host,
            owner,
            repo,
            number,
        } if names_origin(&format!("{host}/{owner}/{repo}"), None) => MergeTarget::Number(number),
        _ => MergeTarget::Unsure,
    }
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
    /// The current time, in seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
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
        // Success with empty stdout is still success — `gh issue close` writes
        // its confirmation to stderr, so an empty stdout must not read as failure.
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

/// Production clock: delegates to `std::thread::sleep`.
pub struct RealClock;

impl Clock for RealClock {
    fn sleep_secs(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    fn now_unix(&self) -> i64 {
        now_unix_seconds()
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
/// message for any ref that is CLOSED (auto-close can't re-fire) or could not
/// be read. Returns `None` on the happy path (all refs OPEN, or no refs).
/// The caller routes the message through `CheckResult::nudge` so Claude sees it.
///
/// The PR and its repo come from the URL `gh pr create` printed
/// ([`pr_from_create_stdout`]). `origin_host` is the host the runner's
/// requests go to (`None` for github.com). When the URL names another host,
/// or stdout carries no PR URL, the PR cannot be read with confidence and
/// this stays silent rather than report on some other PR (cadence-hooks#759).
pub fn handle_create(origin_host: Option<&str>, stdout: &str, gh: &dyn GhRunner) -> Option<String> {
    let (host, slug, pr_num) = pr_from_create_stdout(stdout)?;
    if host != origin_host.unwrap_or("github.com").to_ascii_lowercase() {
        return None;
    }
    let slug = slug.as_str();

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

    // Parse body from JSON: {"body":"..."} — use serde_json for correctness.
    // A response that is not JSON is not a body we can trust: stay silent.
    let body: String = serde_json::from_str::<serde_json::Value>(&body_json)
        .ok()?
        .get("body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();

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
                // `Missing` is also what a failed `gh` call reads as, so the
                // message says the ref could not be read, not that it is gone.
                warnings.push(format!(
                    "  - #{issue} could not be read in {slug} (not found, or the lookup failed)"
                ));
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
/// Reads the merged PR's body and, only when it references issues, waits for
/// GitHub to auto-close them (sleeps injected via `clock`). The wait has two
/// phases: after [`EARLY_CHECK_SECS`] the refs are checked (stopping at the
/// first one not CLOSED), and if all read CLOSED the function returns `None`
/// without sleeping further. Otherwise it sleeps the rest of `wait_secs` and
/// checks each ref again; any still OPEN is closed via `gh issue close` with a
/// commit-citing comment. When `wait_secs`
/// is at most [`EARLY_CHECK_SECS`] there is no early phase, only one sleep of
/// `wait_secs` (none at 0). Returns a summary message naming the closed
/// issues, or `None` when there was nothing to do. The caller routes the
/// message through `CheckResult::nudge` so Claude sees it.
///
/// `origin_host` is origin's host (`None` for github.com). The PR is resolved
/// by [`merge_target`]; a merge it cannot confirm is in origin's repo makes
/// no `gh` call at all.
pub fn handle_merge(
    slug: &str,
    origin_host: Option<&str>,
    cmd: &str,
    gh: &dyn GhRunner,
    clock: &dyn Clock,
    wait_secs: u64,
) -> Option<String> {
    let origin_host = forge_host(origin_host.unwrap_or(GH_DEFAULT_HOST).to_ascii_lowercase());
    let pr_num = match merge_target(cmd, &origin_host, &slug.to_ascii_lowercase()) {
        MergeTarget::NotAMerge | MergeTarget::Unsure => return None,
        MergeTarget::Number(n) => n,
        MergeTarget::CurrentBranch => {
            let raw = gh.run(&[
                "pr", "view", "--json", "number", "-q", ".number", "-R", slug,
            ]);
            raw.and_then(|s| s.parse::<u64>().ok())?
        }
    };

    // Fetch body + mergeCommit first — the merged PR's body doesn't change,
    // so there's no need to wait before reading it.
    let pr_json = gh.run(&[
        "pr",
        "view",
        &pr_num.to_string(),
        "--json",
        "body,mergeCommit,state,mergedAt",
        "-R",
        slug,
    ])?;

    let value: serde_json::Value = serde_json::from_str(&pr_json).ok()?;

    // Act only on a PR GitHub reports as merged (#1004). This hook runs after
    // every `gh pr merge`, including one that failed (a draft, a red required
    // check, a ruleset refusal), only queued auto-merge, or entered a merge
    // queue. Closing the PR's
    // issues then marks unfinished work done, with nothing to announce it.
    // A missing or unreadable field counts as not merged.
    //
    // The merge must also be recent (cadence-hooks#1070 review N1): re-running
    // `gh pr merge` on a PR merged long ago reads MERGED too, and closing its
    // issues then would close ones reopened since.
    let merged = value.get("state").and_then(serde_json::Value::as_str) == Some("MERGED")
        && value
            .get("mergedAt")
            .and_then(serde_json::Value::as_str)
            .and_then(rfc3339_unix_seconds)
            // Symmetric, so a clock running behind cannot make an old merge
            // look recent.
            .is_some_and(|at| {
                (-MERGE_RECENCY_SECS..=MERGE_RECENCY_SECS).contains(&(clock.now_unix() - at))
            });
    if !merged {
        return None;
    }

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

    // Only now pay the auto-close wait: there are refs to verify, and GitHub
    // needs time to fire its own auto-close before we check issue states.
    // Check early, and skip the rest of the wait only when every ref is
    // already CLOSED. `Missing` (which a `gh` failure also returns) never
    // counts as closed, so a failed read falls through to the full wait.
    let early = EARLY_CHECK_SECS.min(wait_secs);
    if early > 0 && early < wait_secs {
        clock.sleep_secs(early);
        let all_closed = refs
            .iter()
            .all(|issue| fetch_issue_state(gh, *issue, slug) == IssueState::Closed);
        if all_closed {
            return None;
        }
        clock.sleep_secs(wait_secs - early);
    } else if wait_secs > 0 {
        clock.sleep_secs(wait_secs);
    }

    let short_sha = if merge_sha.len() >= 7 {
        &merge_sha[..7]
    } else {
        merge_sha
    };

    let mut closed: Vec<String> = Vec::new();

    // One `gh issue view` per ref. Refs per PR are typically 1-2 and this path
    // already waited `wait_secs` — batching via GraphQL isn't worth the extra
    // I/O-seam complexity.
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
            handle_create(gh.gh_host.as_deref(), stdout, &gh)
        } else if cmd.contains("gh pr merge") {
            handle_merge(&slug, gh.gh_host.as_deref(), cmd, &gh, &clock, wait_secs)
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
    use std::collections::{HashMap, VecDeque};

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
        let result = parse_remote("https://ghe.example.com/u123456/foo.git");
        assert_eq!(
            result,
            Some((
                Some("ghe.example.com".to_string()),
                "u123456/foo".to_string()
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

    // Case 8: pr_from_create_stdout — reads host, repo, and number from the URL
    #[test]
    fn pr_from_create_stdout_extracts_the_pr() {
        let stdout = "https://github.com/o/r/pull/42";
        assert_eq!(
            pr_from_create_stdout(stdout),
            Some(("github.com".to_string(), "o/r".to_string(), 42))
        );
        let noisy = "Creating pull request for me:feat into main in up/proj\n\nhttps://github.com/up/proj/pull/21\n";
        assert_eq!(
            pr_from_create_stdout(noisy),
            Some(("github.com".to_string(), "up/proj".to_string(), 21))
        );
    }

    // Case 9: merge_target — a number in origin's repo
    #[test]
    fn merge_target_reads_a_number_in_origin() {
        for cmd in [
            "gh pr merge 17 --squash",
            "gh pr merge --squash 17",
            "gh pr merge 17 -R owner/repo",
            "gh -R github.com/Owner/Repo pr merge 17",
            "gh pr merge https://github.com/owner/repo/pull/17",
            "gh pr -R owner/repo merge 17",
            "gh pr checks 17 && gh pr merge 17",
            "/opt/homebrew/bin/gh pr merge 17",
        ] {
            assert_eq!(
                merge_target(cmd, "github.com", "owner/repo"),
                MergeTarget::Number(17),
                "{cmd}"
            );
        }
    }

    // Case 10: merge_target — no selector is the current branch
    #[test]
    fn merge_target_no_selector_is_the_current_branch() {
        assert_eq!(
            merge_target(
                "gh pr merge --squash --delete-branch",
                "github.com",
                "owner/repo"
            ),
            MergeTarget::CurrentBranch
        );
    }

    // cadence-hooks#759: anything not confirmed as origin's repo is unsure.
    #[test]
    fn merge_target_is_unsure_off_origin_or_unreadable() {
        for cmd in [
            "gh pr merge 16 -R other/repo",
            "gh -R other/repo pr merge 16",
            "gh pr merge 16 --repo=other/repo",
            "GH_REPO=other/repo gh pr merge 16",
            "GH_HOST=ghe.example.com gh pr merge 16",
            "gh pr merge 16 -R ghe.example.com/owner/repo",
            "gh pr merge https://github.com/other/repo/pull/16",
            "gh pr merge -R owner/repo",
            "gh pr merge feat/branch",
            "gh pr merge 5 && gh pr merge 6",
            "gh pr -R other/repo merge 16",
            // cadence-hooks#1070 review I2: anything around the merge that
            // can move it.
            "cd ../other && gh pr merge 5",
            "(cd /x; gh pr merge 5)",
            "pushd /x && gh pr merge 5",
            "export GH_REPO=other/repo; gh pr merge 5",
            "declare -x GH_REPO=other/repo; gh pr merge 5",
            "GH_REPO=other/repo; gh pr merge 5",
            "GH_TOKEN=x gh pr merge 5",
            "env gh pr merge 5",
            "{ gh pr merge 5; }",
            "sh -c 'gh pr merge 5'",
            "git push && gh pr merge 5",
            "gh pr merge 5 | tee log",
            "gh pr merge 5 $(cd /x)",
            // review N1: help merges nothing.
            "gh pr merge 5 --help",
            "gh pr merge -h",
            "gh pr merge 5 -dh",
            "gh pr merge 5 -hd",
            "gh pr merge 5 -sdh",
            // Delta review: a second positional hides where gh points.
            "gh pr merge 5 --subject -R other/repo",
            "gh pr merge 5 -b -R other/repo",
            "gh pr merge 5 --body-file -R other/repo",
            "gh pr merge 5 -- -R other/repo",
        ] {
            assert_eq!(
                merge_target(cmd, "github.com", "owner/repo"),
                MergeTarget::Unsure,
                "{cmd}"
            );
        }
        assert_eq!(
            merge_target("git status", "github.com", "owner/repo"),
            MergeTarget::NotAMerge
        );
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
        /// Per-issue sequence of `gh issue view` results, consumed in order;
        /// the last value repeats. `None` simulates a `gh` failure. Checked
        /// before `issue_states`.
        issue_state_seq: RefCell<HashMap<u64, VecDeque<Option<String>>>>,
        /// PR body to return for the merge-path `gh pr view <n>`
        pr_body: String,
        /// PR number to return for bare `gh pr view --json number`
        pr_number: Option<u64>,
        /// merge commit OID
        merge_commit_oid: String,
        /// `state` for the merge-path `gh pr view` ("MERGED" | "OPEN" | …)
        pr_state: String,
        /// `mergedAt` for the merge-path `gh pr view`; `None` renders as null
        merged_at: Option<String>,
        /// Captures `gh issue close` calls: (issue_number, comment)
        close_calls: RefCell<Vec<(u64, String)>>,
        /// Captures `gh pr view <n> --json body` calls
        body_calls: RefCell<Vec<u64>>,
        /// The `-R` value of every call, in order.
        repo_args: RefCell<Vec<String>>,
    }

    impl FakeGh {
        fn new() -> Self {
            Self {
                issue_states: HashMap::new(),
                issue_state_seq: RefCell::new(HashMap::new()),
                pr_body: String::new(),
                pr_number: None,
                merge_commit_oid: "abc1234def".to_string(),
                pr_state: "MERGED".to_string(),
                merged_at: Some("2026-09-25T00:00:00Z".to_string()),
                close_calls: RefCell::new(Vec::new()),
                body_calls: RefCell::new(Vec::new()),
                repo_args: RefCell::new(Vec::new()),
            }
        }

        fn with_issue(mut self, num: u64, state: &str) -> Self {
            self.issue_states.insert(num, state.to_string());
            self
        }

        /// Script successive `gh issue view` results for one issue. `None`
        /// simulates a `gh` failure; the last value repeats once reached.
        fn with_issue_seq(self, num: u64, states: &[Option<&str>]) -> Self {
            let seq = states.iter().map(|s| s.map(str::to_string)).collect();
            self.issue_state_seq.borrow_mut().insert(num, seq);
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

        /// The PR as GitHub reports it after a merge that did not happen.
        fn with_pr_state(mut self, state: &str, merged_at: Option<&str>) -> Self {
            self.pr_state = state.to_string();
            self.merged_at = merged_at.map(str::to_string);
            self
        }
    }

    impl GhRunner for FakeGh {
        fn run(&self, args: &[&str]) -> Option<String> {
            if let Some(w) = args.windows(2).find(|w| w[0] == "-R") {
                self.repo_args.borrow_mut().push(w[1].to_string());
            }
            // Match: gh issue view <N> --json state -q .state -R <slug>
            if args.len() >= 4
                && args[0] == "issue"
                && args[1] == "view"
                && let Ok(num) = args[2].parse::<u64>()
            {
                // Check for state vs close subcommand
                if args.contains(&"state") {
                    if let Some(seq) = self.issue_state_seq.borrow_mut().get_mut(&num) {
                        return if seq.len() > 1 {
                            seq.pop_front().flatten()
                        } else {
                            seq.front().cloned().flatten()
                        };
                    }
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
                            Some("body,mergeCommit,state,mergedAt") => {
                                // merge-path fetch (handle_merge)
                                let json = serde_json::json!({
                                    "body": self.pr_body,
                                    "mergeCommit": {"oid": self.merge_commit_oid},
                                    "state": self.pr_state,
                                    "mergedAt": self.merged_at,
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
        now: i64,
    }

    impl FakeClock {
        /// One minute after FakeGh's default `mergedAt`.
        fn new() -> Self {
            Self {
                sleep_calls: RefCell::new(Vec::new()),
                now: rfc3339_unix_seconds("2026-09-25T00:01:00Z").unwrap(),
            }
        }

        fn at(now: &str) -> Self {
            Self {
                now: rfc3339_unix_seconds(now).unwrap(),
                ..Self::new()
            }
        }
    }

    impl Clock for FakeClock {
        fn sleep_secs(&self, secs: u64) {
            self.sleep_calls.borrow_mut().push(secs);
        }

        fn now_unix(&self) -> i64 {
            self.now
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

        let msg = handle_create(None, "https://github.com/owner/repo/pull/1", &gh);

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

        let msg = handle_create(None, "https://github.com/owner/repo/pull/1", &gh)
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

        let msg = handle_create(None, "https://github.com/owner/repo/pull/1", &gh)
            .expect("missing ref should produce a warning");

        assert!(
            msg.contains("#99") && msg.contains("not found"),
            "warning should name the missing issue: {msg}"
        );
        assert!(gh.close_calls.borrow().is_empty());
    }

    // cadence-hooks#759: a PR opened on the upstream from a fork checkout is
    // read in the upstream, not in the fork `origin` points at.
    #[test]
    fn create_reads_the_pr_and_issues_in_the_repo_the_url_names() {
        let gh = FakeGh::new()
            .with_issue(20, "OPEN")
            .with_pr_body("Closes #20");
        let msg = handle_create(None, "https://github.com/upstream/proj/pull/22", &gh);
        assert_eq!(msg, None);
        assert_eq!(*gh.body_calls.borrow(), vec![22u64]);
        let repos = gh.repo_args.borrow();
        assert!(!repos.is_empty());
        assert!(repos.iter().all(|r| r == "upstream/proj"), "{repos:?}");
    }

    #[test]
    fn create_on_another_host_than_origin_is_silent() {
        let gh = FakeGh::new().with_pr_body("Closes #5");
        assert_eq!(
            handle_create(None, "https://ghe.example.com/o/r/pull/1", &gh),
            None
        );
        assert_eq!(
            handle_create(
                Some("ghe.example.com"),
                "https://github.com/o/r/pull/1",
                &gh
            ),
            None
        );
        assert!(gh.repo_args.borrow().is_empty(), "no call may be made");
        // The matching enterprise host is still read.
        let gh = FakeGh::new()
            .with_issue(5, "CLOSED")
            .with_pr_body("Closes #5");
        assert!(
            handle_create(
                Some("ghe.example.com"),
                "https://ghe.example.com/o/r/pull/1",
                &gh
            )
            .is_some()
        );
    }

    #[test]
    fn create_without_a_pr_url_is_silent() {
        let gh = FakeGh::new().with_pr_body("Closes #5");
        assert_eq!(handle_create(None, "pull request created", &gh), None);
        assert!(gh.repo_args.borrow().is_empty(), "no call may be made");
    }

    #[test]
    fn create_prose_without_a_closing_keyword_is_not_a_ref() {
        // "Supersedes #20" is prose: it closes nothing, so it is never checked.
        let gh = FakeGh::new()
            .with_issue(20, "CLOSED")
            .with_pr_body("Supersedes #20");
        assert_eq!(
            handle_create(None, "https://github.com/o/r/pull/22", &gh),
            None
        );
    }

    #[test]
    fn create_with_an_unparseable_body_is_silent() {
        struct RawGh;
        impl GhRunner for RawGh {
            fn run(&self, args: &[&str]) -> Option<String> {
                match args.first() {
                    Some(&"pr") => Some("Closes #5".to_string()),
                    Some(&"issue") => Some("CLOSED".to_string()),
                    _ => None,
                }
            }
        }
        assert_eq!(
            handle_create(None, "https://github.com/o/r/pull/1", &RawGh),
            None
        );
    }

    // Case 14: create, body has no refs → no warning, no issue-state calls
    #[test]
    fn create_body_no_refs_returns_early() {
        let gh = FakeGh::new().with_pr_body("This PR is purely cosmetic.");

        let msg = handle_create(None, "https://github.com/owner/repo/pull/1", &gh);

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
        let msg = handle_merge("owner/repo", None, "gh pr merge 8 --squash", &gh, &clock, 0)
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

    // #1004: a `gh pr merge` that failed (draft, red required check, ruleset)
    // or only queued auto-merge leaves the PR open. Its issues must stay open,
    // and the hook must not even pay the auto-close wait.
    #[test]
    fn merge_that_did_not_merge_closes_nothing() {
        for (state, merged_at) in [
            ("OPEN", None),
            ("CLOSED", None),
            ("OPEN", Some("")),
            // `state` alone is not enough: both fields must agree.
            ("MERGED", None),
            ("", Some("2026-09-25T00:00:00Z")),
        ] {
            let gh = FakeGh::new()
                .with_issue(5, "OPEN")
                .with_pr_body("Closes #5")
                .with_pr_state(state, merged_at);
            let clock = FakeClock::new();

            let msg = handle_merge(
                "owner/repo",
                None,
                "gh pr merge 8 --merge --admin",
                &gh,
                &clock,
                10,
            );

            assert_eq!(msg, None, "state={state:?} mergedAt={merged_at:?}");
            assert!(
                gh.close_calls.borrow().is_empty(),
                "closed an issue for an unmerged PR: state={state:?} mergedAt={merged_at:?}"
            );
            assert!(
                clock.sleep_calls.borrow().is_empty(),
                "no wait for an unmerged PR"
            );
        }
    }

    // cadence-hooks#759: a merge in another repo never reaches `gh`, so no
    // issue in origin's repo can be closed on its behalf.
    #[test]
    fn merge_in_another_repo_makes_no_calls() {
        for cmd in [
            "gh pr merge 16 -R other/repo",
            "gh pr merge https://github.com/other/repo/pull/16",
        ] {
            let gh = FakeGh::new()
                .with_issue(5, "OPEN")
                .with_pr_body("Closes #5");
            let clock = FakeClock::new();
            assert_eq!(handle_merge("owner/repo", None, cmd, &gh, &clock, 10), None);
            assert!(gh.repo_args.borrow().is_empty(), "{cmd}: no gh call");
            assert!(gh.close_calls.borrow().is_empty(), "{cmd}: no close");
            assert!(clock.sleep_calls.borrow().is_empty(), "{cmd}: no wait");
        }
    }

    #[test]
    fn merge_after_a_cd_makes_no_calls() {
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5");
        let clock = FakeClock::new();
        let cmd = "cd ../other && gh pr merge 8";
        assert_eq!(handle_merge("owner/repo", None, cmd, &gh, &clock, 10), None);
        assert!(gh.repo_args.borrow().is_empty(), "no gh call");
    }

    #[test]
    fn a_merge_long_ago_closes_nothing() {
        // cadence-hooks#1070 review N1: re-running a merge on an old merged PR
        // must not close issues reopened since.
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5");
        let clock = FakeClock::at("2026-09-25T01:00:00Z");
        assert_eq!(
            handle_merge("owner/repo", None, "gh pr merge 8", &gh, &clock, 10),
            None
        );
        assert!(gh.close_calls.borrow().is_empty());
        assert!(clock.sleep_calls.borrow().is_empty());
        // A clock running ten minutes and more behind the merge is not recent
        // either.
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5");
        let clock = FakeClock::at("2026-09-24T23:49:00Z");
        assert_eq!(
            handle_merge("owner/repo", None, "gh pr merge 8", &gh, &clock, 10),
            None
        );
        assert!(gh.close_calls.borrow().is_empty());
        // Ten minutes is still recent.
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5");
        let clock = FakeClock::at("2026-09-25T00:10:00Z");
        assert!(handle_merge("owner/repo", None, "gh pr merge 8", &gh, &clock, 0).is_some());
    }

    #[test]
    fn two_distinct_pr_urls_in_create_stdout_are_ambiguous() {
        // cadence-hooks#1070 review N2.
        assert_eq!(
            pr_from_create_stdout("https://github.com/o/r/pull/1\nhttps://github.com/o/r/pull/2"),
            None
        );
        assert_eq!(
            pr_from_create_stdout("https://github.com/o/r/pull/3 https://github.com/o/r/pull/3"),
            Some(("github.com".to_string(), "o/r".to_string(), 3))
        );
    }

    #[test]
    fn merge_in_origin_still_closes_stragglers() {
        for cmd in [
            "gh pr merge 8 --squash",
            "gh pr merge 8 -R owner/repo",
            "gh pr merge https://github.com/owner/repo/pull/8",
        ] {
            let gh = FakeGh::new()
                .with_issue(5, "OPEN")
                .with_pr_body("Closes #5");
            let clock = FakeClock::new();
            let msg = handle_merge("owner/repo", None, cmd, &gh, &clock, 0);
            assert!(msg.is_some_and(|m| m.contains("#5")), "{cmd}");
            assert_eq!(gh.close_calls.borrow().len(), 1, "{cmd}");
            assert!(
                gh.repo_args.borrow().iter().all(|r| r == "owner/repo"),
                "{cmd}"
            );
        }
    }

    // Case 16: merge #8, body refs #5 already CLOSED → no close call
    #[test]
    fn merge_already_closed_issue_skipped() {
        let gh = FakeGh::new()
            .with_issue(5, "CLOSED")
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge("owner/repo", None, "gh pr merge 8 --squash", &gh, &clock, 0);

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
            None,
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

    // A merge whose PR body has no closing-keyword refs has nothing to verify —
    // the auto-close wait must not be paid (it stalls the session for wait_secs).
    #[test]
    fn merge_body_without_refs_skips_sleep() {
        let gh = FakeGh::new()
            .with_pr_body("routine maintenance, no issue references")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            None,
            "gh pr merge 9 --squash",
            &gh,
            &clock,
            10,
        );

        assert_eq!(msg, None);
        assert!(
            clock.sleep_calls.borrow().is_empty(),
            "no refs to verify — the auto-close wait should be skipped"
        );
        assert!(gh.close_calls.borrow().is_empty());
    }

    // GitHub already closed every ref by the early check → skip the rest of
    // the wait and close nothing.
    #[test]
    fn merge_all_refs_closed_at_early_check_skips_remaining_wait() {
        let gh = FakeGh::new()
            .with_issue(5, "CLOSED")
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            None,
            "gh pr merge 8 --squash",
            &gh,
            &clock,
            10,
        );

        assert_eq!(msg, None);
        assert_eq!(*clock.sleep_calls.borrow(), vec![2u64]);
        assert!(gh.close_calls.borrow().is_empty());
    }

    // A ref still OPEN at the early check and at the deadline → the full wait
    // is paid in two sleeps and the hook closes it.
    #[test]
    fn merge_ref_open_through_deadline_sleeps_full_wait_and_closes() {
        let gh = FakeGh::new()
            .with_issue_seq(5, &[Some("OPEN"), Some("OPEN")])
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            None,
            "gh pr merge 8 --squash",
            &gh,
            &clock,
            10,
        );

        assert!(msg.is_some_and(|m| m.contains("#5")));
        assert_eq!(*clock.sleep_calls.borrow(), vec![2u64, 8]);
        let calls = gh.close_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 5);
    }

    // GitHub closes the ref between the early check and the deadline → the
    // hook must not close it a second time.
    #[test]
    fn merge_ref_closes_after_early_check_is_not_closed_by_hook() {
        let gh = FakeGh::new()
            .with_issue_seq(5, &[Some("OPEN"), Some("CLOSED")])
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            None,
            "gh pr merge 8 --squash",
            &gh,
            &clock,
            10,
        );

        assert_eq!(msg, None);
        assert_eq!(*clock.sleep_calls.borrow(), vec![2u64, 8]);
        assert!(gh.close_calls.borrow().is_empty());
    }

    // A `gh` failure at the early check reads as Missing, not Closed → no
    // early exit; the full wait runs and the still-OPEN ref is closed.
    #[test]
    fn merge_missing_at_early_check_does_not_exit_early() {
        let gh = FakeGh::new()
            .with_issue_seq(5, &[None, Some("OPEN")])
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge(
            "owner/repo",
            None,
            "gh pr merge 8 --squash",
            &gh,
            &clock,
            10,
        );

        assert!(msg.is_some_and(|m| m.contains("#5")));
        assert_eq!(*clock.sleep_calls.borrow(), vec![2u64, 8]);
        assert_eq!(gh.close_calls.borrow().len(), 1);
    }

    // A wait no longer than the early check has no early phase → one sleep of
    // the whole wait, then the normal check.
    #[test]
    fn merge_wait_below_early_check_uses_single_sleep() {
        let gh = FakeGh::new()
            .with_issue(5, "OPEN")
            .with_pr_body("Closes #5")
            .with_merge_commit("abc1234def456");

        let clock = FakeClock::new();
        let msg = handle_merge("owner/repo", None, "gh pr merge 8 --squash", &gh, &clock, 1);

        assert!(msg.is_some_and(|m| m.contains("#5")));
        assert_eq!(*clock.sleep_calls.borrow(), vec![1u64]);
        assert_eq!(gh.close_calls.borrow().len(), 1);
    }

    // Case 18: cmd is neither create nor merge → Check::run allows, no handler invoked
    // (Tested via the Check trait — we verify allow() is returned for unrelated commands)
    #[test]
    fn unrelated_command_returns_allow() {
        let input = make_bash("git status");
        // We can't call VerifyPrAutoclose::run here because it hits git remote.
        // Instead test the logic path: if cmd doesn't contain "gh pr create" or "gh pr merge",
        // neither handler is invoked. We verify this via pr_number_from_create_stdout
        // and merge_target reading no merge in unrelated commands.
        assert_eq!(pr_from_create_stdout("git status output"), None);
        assert_eq!(
            merge_target("git status", "github.com", "o/r"),
            MergeTarget::NotAMerge
        );

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
    fn pr_from_create_stdout_no_url_is_none() {
        assert_eq!(pr_from_create_stdout("Created pull request"), None);
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
