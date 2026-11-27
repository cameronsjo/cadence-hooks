//! Block a `gh pr merge` when forgectl's last snapshot of the PR says the
//! merge is not safe yet (cadence-ecosystem ADR-0046, amendment 2026-11-27).
//!
//! The facts come from `forgectl events state <owner/repo#N> --json`, which
//! the forgectl poller keeps: the PR's head, the check rollup at that head,
//! the cadence-review markers at that head (the operator's own login only),
//! and the CITL label. The guard blocks only on a fact it read:
//!
//! - checks at the head are not `SUCCESS` (a PR with no checks has none to fail);
//! - no cadence-review marker counts at the head, or one says `crit` > 0;
//! - the PR carries `CITL` (its last step needs the operator's hands);
//! - `--match-head-commit` names a SHA other than the PR's head.
//!
//! Confirm tier: the first attempt blocks and names each fact, and an
//! identical retry passes once (recorded as `confirmed`).
//!
//! **Allows, per ADR-0046 rule 3**, whenever a fact cannot be read: a merge
//! the shared matcher cannot pin to one PR in origin's github.com repo
//! ([`merge_target`]), `--auto` (GitHub waits for required checks itself),
//! no forgectl on PATH, a snapshot older than [`STALE_SECS`], or a PR that is
//! not open. When forgectl answers but has no fresh snapshot, the allow
//! carries a nudge that names the command that would let the guard check.

use cadence_hooks_core::shell::{gh_pr_subcommand, git_command, pr_flip_segments};
use cadence_hooks_core::time::{now_unix_seconds, rfc3339_unix_seconds};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde::Deserialize;

use crate::bounded_tool::run_tool;
use crate::verify_pr_autoclose::{MergeTarget, merge_target, parse_remote};

/// A snapshot older than this is not read as a fact: checks may have gone
/// green since. The poller runs every 90 seconds by default.
pub const STALE_SECS: i64 = 10 * 60;

/// Blocks `gh pr merge` on facts forgectl read about the PR.
pub struct GuardGhMerge;

/// The part of `forgectl events state --json` this guard reads.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub repo: String,
    pub number: u64,
    pub state: String,
    #[serde(default)]
    pub head: Option<String>,
    #[serde(default)]
    pub checks: Option<String>,
    #[serde(default)]
    pub review: Option<Review>,
    #[serde(default)]
    pub citl: bool,
    pub polled_at: String,
}

/// cadence-review markers at the head, as forgectl sums them.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Review {
    pub at_head: u32,
    pub crit: u32,
    #[serde(default)]
    pub imp: u32,
}

/// What the guard concluded from a snapshot.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every fact read is fine, or the PR is not open.
    Clear,
    /// Facts that make the merge unsafe, one line each.
    Unsafe(Vec<String>),
    /// The snapshot cannot be used: why.
    Unknown(String),
}

fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Judge one snapshot. Pure: `now` is unix seconds.
pub fn judge(snap: &Snapshot, match_head: Option<&str>, now: i64) -> Verdict {
    let Some(at) = rfc3339_unix_seconds(&snap.polled_at) else {
        return Verdict::Unknown("forgectl's snapshot has no readable time".into());
    };
    let age = now - at;
    if !(-60..=STALE_SECS).contains(&age) {
        return Verdict::Unknown(format!(
            "forgectl's snapshot is {} minutes old",
            age.max(0) / 60
        ));
    }
    if snap.state != "OPEN" {
        return Verdict::Clear;
    }
    let head = snap.head.as_deref().filter(|h| is_sha(h));
    let mut problems = Vec::new();
    if let (Some(want), Some(head)) = (match_head, head)
        && !want.eq_ignore_ascii_case(head)
    {
        problems.push(format!(
            "the head moved: --match-head-commit names {}, the PR is at {}",
            short(want),
            short(head)
        ));
    }
    match snap.checks.as_deref() {
        None | Some("SUCCESS") => {}
        Some(other @ ("FAILURE" | "ERROR" | "PENDING" | "EXPECTED")) => {
            problems.push(format!("checks at the head are {other}"));
        }
        Some(_) => {
            return Verdict::Unknown("forgectl's snapshot has an unknown check state".into());
        }
    }
    match &snap.review {
        Some(r) if r.at_head > 0 && r.crit > 0 => {
            problems.push(format!(
                "the review at the head found crit={} imp={}",
                r.crit, r.imp
            ));
        }
        Some(r) if r.at_head > 0 => {}
        _ => problems.push("no cadence-review marker from your login counts at the head".into()),
    }
    if snap.citl {
        problems.push("the PR carries CITL: its last step is the operator's".into());
    }
    if problems.is_empty() {
        Verdict::Clear
    } else {
        Verdict::Unsafe(problems)
    }
}

fn short(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

/// The merge segment's `--match-head-commit` value and whether it asks for
/// `--auto` (or `--disable-auto`).
fn merge_flags(command: &str) -> (Option<String>, bool) {
    let mut head = None;
    let mut auto = false;
    for tokens in pr_flip_segments(command) {
        if gh_pr_subcommand(&tokens) != Some("merge") {
            continue;
        }
        let mut it = tokens.iter();
        while let Some(t) = it.next() {
            if t == "--auto" || t == "--disable-auto" {
                auto = true;
            } else if t == "--match-head-commit" {
                head = it.next().cloned();
            } else if let Some(v) = t.strip_prefix("--match-head-commit=") {
                head = Some(v.to_string());
            }
        }
    }
    (head, auto)
}

/// Parse forgectl's answer. `None` when it is not a snapshot of `want`.
pub fn parse_snapshot(stdout: &str, want_repo: &str, want_number: u64) -> Option<Snapshot> {
    let snap: Snapshot = serde_json::from_str(stdout).ok()?;
    (snap.repo.eq_ignore_ascii_case(want_repo) && snap.number == want_number).then_some(snap)
}

fn block_message(pr: &str, problems: &[String]) -> String {
    let mut msg =
        format!("guard-gh-merge: forgectl's last read of {pr} says this merge is not safe yet:");
    for p in problems {
        msg.push_str("\n- ");
        msg.push_str(p);
    }
    msg.push_str(
        "\nFix what it names and wait for the next poll (`forgectl events state` shows it), or \
         stop and tell the operator in chat.",
    );
    msg
}

impl Check for GuardGhMerge {
    fn name(&self) -> &str {
        "guard-gh-merge"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let (match_head, auto) = merge_flags(command);
        if auto {
            return CheckResult::allow();
        }
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let Some(dir) = cadence_hooks_core::target_repo::command_repo_dir(command, cwd) else {
            return CheckResult::allow();
        };
        let Some(remote) = git_command(&dir, &["remote", "get-url", "origin"]) else {
            return CheckResult::allow();
        };
        // github.com only: forgectl's poller reads nothing else.
        let Some((None, slug)) = parse_remote(&remote) else {
            return CheckResult::allow();
        };
        let number = match merge_target(command, "github.com", &slug.to_ascii_lowercase()) {
            MergeTarget::Number(n) => n,
            _ => return CheckResult::allow(),
        };
        let pr = format!("{slug}#{number}");
        let Some(stdout) = run_tool(
            "forgectl",
            &["events", "state", &pr, "--json"],
            std::path::Path::new(&dir),
            &[],
        ) else {
            // No forgectl, no snapshot (exit 3), or a timeout: nothing read.
            return CheckResult::allow();
        };
        let verdict = match parse_snapshot(&stdout, &slug, number) {
            Some(snap) => judge(&snap, match_head.as_deref(), now_unix_seconds()),
            None => Verdict::Unknown("forgectl's answer did not parse".into()),
        };
        match verdict {
            Verdict::Clear => CheckResult::allow(),
            Verdict::Unknown(why) => CheckResult::nudge(format!(
                "guard-gh-merge: {why}, so checks and review at the head were not checked before \
                 this merge. Run `forgectl events poll --once`, then merge again."
            )),
            Verdict::Unsafe(problems) => cadence_hooks_core::confirm::confirm_block(
                input,
                Check::name(self),
                &format!(
                    "{pr}\u{1f}{}",
                    cadence_hooks_core::confirm::whole_command_action(command)
                ),
                &block_message(&pr, &problems),
                cadence_hooks_core::confirm::Retry::SameCommand,
                None,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLLED: &str = "2026-11-27T12:00:00Z";
    /// A minute after the poll.
    const NOW: i64 = 1_795_780_800 + 60;

    fn snap() -> Snapshot {
        Snapshot {
            repo: "o/r".into(),
            number: 7,
            state: "OPEN".into(),
            head: Some(HEAD.into()),
            checks: Some("SUCCESS".into()),
            review: Some(Review {
                at_head: 1,
                crit: 0,
                imp: 2,
            }),
            citl: false,
            polled_at: POLLED.into(),
        }
    }

    fn problems(v: Verdict) -> Vec<String> {
        match v {
            Verdict::Unsafe(p) => p,
            other => panic!("expected Unsafe, got {other:?}"),
        }
    }

    #[test]
    fn the_fixed_clock_is_a_minute_after_the_poll() {
        assert_eq!(rfc3339_unix_seconds(POLLED), Some(NOW - 60));
    }

    #[test]
    fn green_reviewed_pr_is_clear() {
        assert_eq!(judge(&snap(), None, NOW), Verdict::Clear);
        assert_eq!(judge(&snap(), Some(HEAD), NOW), Verdict::Clear);
    }

    #[test]
    fn each_unsafe_fact_is_named() {
        let mut s = snap();
        s.checks = Some("FAILURE".into());
        assert_eq!(
            problems(judge(&s, None, NOW)),
            ["checks at the head are FAILURE"]
        );

        let mut s = snap();
        s.review = None;
        assert!(problems(judge(&s, None, NOW))[0].contains("no cadence-review marker"));

        let mut s = snap();
        s.review = Some(Review {
            at_head: 0,
            crit: 0,
            imp: 0,
        });
        assert!(problems(judge(&s, None, NOW))[0].contains("no cadence-review marker"));

        let mut s = snap();
        s.review = Some(Review {
            at_head: 2,
            crit: 1,
            imp: 0,
        });
        assert_eq!(
            problems(judge(&s, None, NOW)),
            ["the review at the head found crit=1 imp=0"]
        );

        let mut s = snap();
        s.citl = true;
        assert!(problems(judge(&s, None, NOW))[0].contains("CITL"));

        let moved = "b".repeat(40);
        assert!(problems(judge(&snap(), Some(&moved), NOW))[0].starts_with("the head moved"));
    }

    #[test]
    fn no_checks_is_not_a_failure() {
        let mut s = snap();
        s.checks = None;
        assert_eq!(judge(&s, None, NOW), Verdict::Clear);
    }

    #[test]
    fn stale_or_unreadable_snapshot_is_unknown_not_a_block() {
        let mut s = snap();
        s.checks = Some("FAILURE".into());
        assert!(matches!(
            judge(&s, None, NOW - 60 + STALE_SECS + 1),
            Verdict::Unknown(_)
        ));
        s.polled_at = "yesterday".into();
        assert!(matches!(judge(&s, None, NOW), Verdict::Unknown(_)));
        let mut s = snap();
        s.checks = Some("GREEN".into());
        assert!(matches!(judge(&s, None, NOW), Verdict::Unknown(_)));
    }

    #[test]
    fn closed_or_merged_pr_is_clear() {
        let mut s = snap();
        s.state = "MERGED".into();
        s.checks = Some("FAILURE".into());
        assert_eq!(judge(&s, None, NOW), Verdict::Clear);
    }

    #[test]
    fn parse_snapshot_checks_which_pr_it_is() {
        let json = format!(
            r#"{{"repo":"O/R","number":7,"state":"OPEN","draft":false,"head":"{HEAD}","checks":"SUCCESS","review":{{"at_head":1,"stale":0,"crit":0,"imp":0}},"citl":false,"merge_methods":["merge"],"polled_at":"2026-11-27T12:00:00Z"}}"#
        );
        assert!(parse_snapshot(&json, "o/r", 7).is_some());
        assert!(parse_snapshot(&json, "o/r", 8).is_none());
        assert!(parse_snapshot(&json, "o/other", 7).is_none());
        assert!(parse_snapshot("not json", "o/r", 7).is_none());
    }

    #[test]
    fn merge_flags_reads_head_and_auto() {
        assert_eq!(
            merge_flags(&format!("gh pr merge 7 --merge --match-head-commit {HEAD}")),
            (Some(HEAD.to_string()), false)
        );
        assert_eq!(
            merge_flags(&format!("gh pr merge 7 --match-head-commit={HEAD}")),
            (Some(HEAD.to_string()), false)
        );
        assert_eq!(merge_flags("gh pr merge 7 --auto --squash"), (None, true));
        assert_eq!(merge_flags("gh pr view 7"), (None, false));
    }

    #[test]
    fn block_message_lists_every_fact() {
        let msg = block_message("o/r#7", &["a".into(), "b".into()]);
        assert!(msg.starts_with("guard-gh-merge: forgectl's last read of o/r#7"));
        assert!(msg.contains("\n- a\n- b\n"));
    }

    #[test]
    fn non_merge_commands_allow() {
        use cadence_hooks_core::Outcome;
        use cadence_hooks_core::test_builders::make_bash;
        for cmd in ["git status", "gh pr view 7", "gh pr merge 7 --auto --merge"] {
            assert_eq!(
                GuardGhMerge.run(&make_bash(cmd)).outcome,
                Outcome::Allow,
                "{cmd}"
            );
        }
    }
}
