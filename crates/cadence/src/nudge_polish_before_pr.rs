//! Gate `/polish` before creating a pull request.
//!
//! Fires on `gh pr create`. Polish is mandatory before a PR, so this check is
//! transcript-aware: it scans the session transcript for a real
//! [cadence-forge:polish](https://github.com/cameronsjo/cadence-forge) Skill
//! invocation and routes a 3-way, fail-open outcome:
//!
//! - transcript **shows** a polish Skill run → **allow** (silent — no nag after
//!   a real polish run);
//! - transcript is readable with **no** polish run → **block** (an evidenced
//!   skip — the teeth);
//! - no transcript / unreadable / parse error → **nudge** (ADR-0001 fail-open;
//!   never block on our own missing data).
//!
//! `/polish` runs a branch-scoped pass over the changes vs `origin/main` —
//! simplify, logging, tests, docs, security, and code review. Skill, agent,
//! command, and rule markdown (and CLAUDE.md) are behavior, not documentation,
//! so they are in scope; literal documentation (prose about the system) routes
//! to `/polish docs`. A skip is legitimate only for a trivial one-liner or a
//! branch already taken through `/polish` — and the model may not self-approve
//! one: it surfaces the decision to Cameron. (The subcommand id stays
//! `nudge-polish-before-pr` for wiring stability even though it now can block.)

use cadence_hooks_core::shell::is_gh_pr_create;
use cadence_hooks_core::transcript::{
    subagent_transcripts_have_polish_run, transcript_has_polish_run,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;

/// Gates `/polish` (cadence-forge:polish) before opening a PR — conditional on
/// transcript evidence of a real polish run.
pub struct NudgePolishBeforePr;

impl Check for NudgePolishBeforePr {
    fn name(&self) -> &str {
        "nudge-polish-before-pr"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        // Read the session transcript when the payload names one and it is
        // readable. A missing path, a non-file, or a read error all collapse to
        // `None`, and `decide` then fails open to a nudge — we never block on
        // our own missing data (ADR-0001).
        let tp = input
            .transcript_path()
            .filter(|p| Path::new(p).is_file());
        let transcript = tp.and_then(|p| std::fs::read_to_string(p).ok());
        // Polish run inside a *subagent* lives in a child transcript the parent
        // scan above never sees (#247). Only scan those children on the path
        // that would otherwise block — a gh-pr-create whose parent transcript is
        // readable, non-empty, and shows no polish — so the common allow/nudge
        // paths pay no directory-walk cost.
        let subagent_polish = match transcript.as_deref() {
            Some(t)
                if is_gh_pr_create(command)
                    && !t.trim().is_empty()
                    && !transcript_has_polish_run(t) =>
            {
                tp.map(Path::new)
                    .is_some_and(subagent_transcripts_have_polish_run)
            }
            _ => false,
        };
        decide(command, transcript.as_deref(), subagent_polish)
    }
}

/// The pure 3-way conditional — no I/O, so the gate logic is unit-tested
/// without the filesystem. `run()` reads the transcript and hands the content
/// (or `None`) in.
///
/// - non-`gh pr create` → allow.
/// - `gh pr create` + transcript showing a polish Skill run → allow (silent).
/// - `gh pr create` + parent shows no polish but a subagent did → allow (delegated flow, #247).
/// - `gh pr create` + readable, **non-empty** transcript without a polish run → block.
/// - `gh pr create` + `None` / empty / whitespace-only transcript → nudge (fail-open floor).
///
/// `subagent_polish` is the caller's pre-computed verdict on whether a child
/// subagent transcript shows polish; it is kept out of `decide` so this stays
/// pure (no I/O) and unit-testable.
fn decide(command: &str, transcript: Option<&str>, subagent_polish: bool) -> CheckResult {
    if !is_gh_pr_create(command) {
        return CheckResult::allow();
    }
    match transcript {
        // No transcript — fail open to the soft nudge, never block.
        None => CheckResult::nudge(nudge_message()),
        // An empty or whitespace-only readable transcript is "no evidence", not
        // an evidenced skip — a 0-byte / not-yet-flushed file must fail open too,
        // never block on our own missing data (ADR-0001).
        Some(t) if t.trim().is_empty() => CheckResult::nudge(nudge_message()),
        // Polish actually ran — silent allow. Kills the nag-after-polish noise.
        Some(t) if transcript_has_polish_run(t) => CheckResult::allow(),
        // Parent shows no polish, but a subagent of this session ran it — the
        // delegated-flow case (#247). Silent allow, same as a parent-side run.
        Some(_) if subagent_polish => CheckResult::allow(),
        // Readable, non-empty transcript with no polish run — an evidenced skip.
        // The teeth.
        Some(_) => CheckResult::block(block_message()),
    }
}

/// The loophole-closing clauses both the block and the nudge carry, so the
/// "it's just markdown" and "TDD/attune already covered it" skips can't survive
/// either path.
const SCOPE_CLAUSES: &str = "Skill / agent / command / rule markdown and \
    CLAUDE.md are behavior, not documentation — IN scope; only *literal* docs \
    (prose about the system) route to `/polish docs`. Planning, TDD, attune, or \
    a code-review precede polish — they don't replace it.";

/// Today's soft nudge — the fail-open message when there is no transcript
/// evidence either way. Allow + warn; the model proceeds.
fn nudge_message() -> String {
    format!(
        "Before opening this PR, consider `/polish` (cadence-forge:polish) — a \
         branch-scoped pass vs `origin/main`: simplify, logging, tests, docs, \
         security, code review. {SCOPE_CLAUSES} Skip ONLY if it's a trivial \
         one-liner or already went through `/polish`. If you skip, say so and \
         why — don't skip silently."
    )
}

/// The block message — fires when the transcript proves polish was skipped.
/// Reassigns authority: the model runs `/polish`, or if it believes the skip is
/// legitimate it stops and surfaces the decision to Cameron. It deliberately
/// does not advertise a self-serve bypass token.
fn block_message() -> String {
    format!(
        "Polish was NOT run on this branch — the session transcript shows no \
         `cadence-forge:polish` Skill invocation, and polish is mandatory before \
         opening a PR. Run `/polish` now, then retry `gh pr create`. \
         {SCOPE_CLAUSES} If you believe this skip is legitimate — a trivial \
         one-liner, or polish performed outside a Skill call — you may NOT \
         self-approve it: stop and surface the decision to Cameron, who decides."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{Outcome, test_builders::make_bash};

    #[test]
    fn gh_pr_create_nudges() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr create --title test"));
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"), "message should mention /polish");
        // Loophole guard: the nudge MUST keep telling the model that skill /
        // agent / command / rule markdown is behavior, not documentation — that
        // clause is what stops the "it's just markdown, skip polish" skip.
        assert!(
            msg.contains("behavior, not documentation"),
            "message should name behavioral markdown as in scope"
        );
        // Loophole guard: planning / TDD / attune / review must not read as a
        // polish-equivalent — the skip is only trivial-one-liner or already-polished.
        assert!(
            msg.contains("they don't replace it"),
            "message should deny that upstream process substitutes for polish"
        );
        // Loophole guard: a skip must be surfaced, never silent — so the user
        // can veto a rationalized skip.
        assert!(
            msg.contains("don't skip silently"),
            "message should require the model to state why it is skipping"
        );
    }

    // --- decide(): the pure 3-way conditional (no filesystem) ---

    /// A transcript line carrying a real `cadence-forge:polish` Skill invocation.
    fn polish_transcript() -> &'static str {
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Skill","input":{"skill":"cadence-forge:polish"}}]}}"#
    }

    /// A readable transcript with NO polish Skill run — only prose. The evidenced
    /// skip the block path is meant to catch.
    fn no_polish_transcript() -> &'static str {
        r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"opening the PR now"}]}}"#
    }

    #[test]
    fn decide_pr_create_with_polish_run_allows_silently() {
        // Polish actually ran → silent allow. This is the noise-kill: today the
        // nudge fires even after a real polish run.
        let result = decide("gh pr create --title test", Some(polish_transcript()), false);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(
            result.message.is_none(),
            "a real polish run must allow silently, no nag"
        );
    }

    #[test]
    fn decide_pr_create_without_polish_run_blocks() {
        // The teeth: a readable transcript with no polish Skill run is an
        // evidenced skip → hard block.
        let result = decide(
            "gh pr create --title test",
            Some(no_polish_transcript()),
            false,
        );
        assert_eq!(result.outcome, Outcome::Block);
        let msg = result.message.unwrap_or_default();
        // The block carries the same loophole-closing clauses the nudge does.
        assert!(
            msg.contains("behavior, not documentation"),
            "block must keep the behavioral-markdown clause: {msg}"
        );
        assert!(
            msg.contains("they don't replace it"),
            "block must deny upstream-process substitution: {msg}"
        );
        // It states polish was NOT run...
        assert!(
            msg.to_lowercase().contains("not run"),
            "block must state polish was not run: {msg}"
        );
        // ...directs the model to run /polish...
        assert!(msg.contains("/polish"), "block must name the remedy: {msg}");
        // ...and reassigns authority: the model may not self-approve a skip, it
        // surfaces the decision to Cameron.
        assert!(
            msg.contains("Cameron"),
            "block must name Cameron as the decider: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("surface"),
            "block must tell the model to surface the decision: {msg}"
        );
        // The block must NOT advertise a self-serve bypass — that would re-hand
        // the model a one-line loophole.
        assert!(
            !msg.contains("CADENCE_BYPASS"),
            "block must not promote a self-serve skip token: {msg}"
        );
    }

    #[test]
    fn decide_pr_create_empty_transcript_nudges() {
        // Fail-open: an empty or whitespace-only readable transcript is "no
        // evidence", not an evidenced skip — it must nudge, never block. Guards
        // the 0-byte / not-yet-flushed file case (security review finding 1).
        assert_eq!(
            decide("gh pr create --title x", Some(""), false).outcome,
            Outcome::Nudge
        );
        assert_eq!(
            decide("gh pr create --title x", Some("   \n\t  "), false).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn decide_pr_create_no_transcript_nudges() {
        // Fail-open floor (ADR-0001): no transcript evidence → today's soft
        // nudge, never a block. Preserves the pre-teeth behavior exactly.
        let result = decide("gh pr create --title test", None, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"));
        assert!(msg.contains("behavior, not documentation"));
        assert!(msg.contains("they don't replace it"));
        assert!(msg.contains("don't skip silently"));
    }

    #[test]
    fn decide_non_pr_create_allows_regardless_of_transcript() {
        // The matcher only scopes the process spawn; decide() still guards
        // against a non-create gh command slipping through.
        assert_eq!(
            decide("gh pr list", Some(no_polish_transcript()), false).outcome,
            Outcome::Allow
        );
        assert_eq!(decide("git commit -m x", None, false).outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_create_with_heredoc_body_nudges() {
        let cmd = "gh pr create --title test --body \"$(cat <<'EOF'\n## Summary\nfoo\nEOF\n)\"";
        let result = NudgePolishBeforePr.run(&make_bash(cmd));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_list_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr list"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr view 123"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_review_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh pr review 123 --approve"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_issue_create_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("gh issue create --title test"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn git_command_allowed() {
        let result = NudgePolishBeforePr.run(&make_bash("git commit -m 'gh pr create'"));
        // Token detection: "gh pr create" appears as substring inside a single-quoted
        // arg but split_whitespace yields ["git", "commit", "-m", "'gh", "pr", "create'"].
        // The window check requires exact "gh", "pr", "create" — quoted tokens fail.
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = NudgePolishBeforePr.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn branch_name_with_pr_create_substring_allowed() {
        // Branch named gh-pr-create-experiments shouldn't fire.
        let result = NudgePolishBeforePr.run(&make_bash("git checkout gh-pr-create-experiments"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- the delegated-flow case (#247) ---

    #[test]
    fn decide_pr_create_subagent_polish_allows() {
        // Parent transcript shows no polish, but a subagent did (subagent_polish
        // = true) → allow, not block. This is the delegated-PR-flow fix: polish
        // run inside a child satisfies the gate.
        let result = decide(
            "gh pr create --title test",
            Some(no_polish_transcript()),
            true,
        );
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(
            result.message.is_none(),
            "a subagent polish run must allow silently, same as a parent run"
        );
    }

    #[test]
    fn run_allows_when_only_subagent_polished() {
        // End-to-end through `run()`: a real gh-pr-create payload whose parent
        // transcript shows no polish, but a sibling `<stem>/subagents/agent-*.jsonl`
        // does → Allow. Proves run() reads the child transcripts, not just decide().
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("sess.jsonl");
        std::fs::write(&parent, no_polish_transcript()).unwrap();
        let subagents = tmp.path().join("sess").join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();
        std::fs::write(subagents.join("agent-a1.jsonl"), polish_transcript()).unwrap();

        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                command: Some("gh pr create --title test".into()),
                ..Default::default()
            }),
            transcript_path: Some(parent.to_str().unwrap().into()),
            ..Default::default()
        };
        assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Allow);
    }
}
