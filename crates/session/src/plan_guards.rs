//! Deterministic living-plan guards — the mid-execution and PR-boundary
//! nudges the lifecycle shipped without (cadence-hooks#429, the
//! living-plan-guards plan's Task 3; evidence that prose alone fails:
//! cadence#942).
//!
//! Two advisory checks, both bound to the plan doc for the CURRENT branch:
//!
//! - **`nudge-plan-tick` (PostToolUse:Bash).** After a successful `git
//!   commit` in a repo whose current branch has an in-flight plan doc that
//!   neither the last three commits nor the working tree touched, nudge once
//!   per session to tick the plan. cadence-rules § Plan Execution asks for
//!   ticks "as work lands" — not on every commit — so the guard tolerates a
//!   three-commit gap and fires at most once per session (friction canon:
//!   spend friction only where it is load-bearing).
//! - **`warn-plan-ready-flip` (PreToolUse:Bash).** `gh pr ready` / `gh pr
//!   merge` while the branch's plan still reads `status: in-flight` or
//!   carries unticked checkboxes ⇒ warn. The PR-ready flip is one of the
//!   three consumption points where the index must reconcile against ground
//!   truth (ADR-0038); this is its deterministic backstop.
//!
//! Both warn, never block (friction canon), and fail open on every internal
//! failure (ADR-0001): no cwd, no repo, no plan, an unreadable file, or a
//! failed git spawn all degrade to a silent allow. Plan frontmatter is
//! untrusted committed text — everything rendered into a nudge is either
//! static or passes [`crate::identity::sanitize_field`].

use crate::plan_scan::{self, InFlightPlan};
use cadence_hooks_core::markers;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;

/// Cap on bytes read from a plan body when counting checkboxes — the same
/// generous bound `persist_plan` applies to idempotency reads.
const PLAN_BODY_READ_CAP_BYTES: u64 = 1024 * 1024;

/// How many recent commits may omit the plan file before the tick nudge
/// fires. One commit rarely warrants a tick; three commits of silence is the
/// "work landed, index went stale" signal ADR-0038's read-time repair exists
/// for.
const TICK_NUDGE_COMMIT_WINDOW: &str = "-3";

/// Session-marker kind for the once-per-session tick-nudge dedupe.
const TICK_NUDGE_MARKER_KIND: &str = "plan-tick-nudge";

/// Nudge after a successful commit that left the branch's in-flight plan
/// untouched (advisory, once per session).
pub struct NudgePlanTick;

impl Check for NudgePlanTick {
    fn name(&self) -> &str {
        "nudge-plan-tick"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        run_nudge_plan_tick(input)
    }
}

/// Warn on `gh pr ready` / `gh pr merge` while the branch's plan is
/// unreconciled (advisory).
pub struct WarnPlanReadyFlip;

impl Check for WarnPlanReadyFlip {
    fn name(&self) -> &str {
        "warn-plan-ready-flip"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        run_warn_plan_ready_flip(input)
    }
}

pub fn run_nudge_plan_tick(input: &HookInput) -> CheckResult {
    // Cheap prefilter: the wiring's `if:` already narrows to git commits, but
    // the binary re-verifies — a hook wired broadly must not nudge on
    // arbitrary Bash.
    let Some(command) = input.command() else {
        return CheckResult::allow();
    };
    if !command.contains("commit") {
        return CheckResult::allow();
    }
    // The success signal is git's own commit summary line (`[branch abc1234]
    // subject`) in stdout — Bash tool responses carry no exit code, and an
    // aborted commit (hook rejection, empty index) prints no such line, so
    // this doubles as the "commit actually landed" gate the plan requires.
    let Some(stdout) = input.tool_response_stdout() else {
        return CheckResult::allow();
    };
    if !commit_summary_present(stdout) {
        return CheckResult::allow();
    }
    let Some(cwd) = input.cwd.as_deref() else {
        return CheckResult::allow();
    };
    let Some(repo_root) = crate::registry::repo_root(cwd) else {
        return CheckResult::allow();
    };

    // Once per session per repo: a second qualifying commit in the same
    // session stays silent — the operator heard the nudge already.
    let marker = markers::session_marker(input, TICK_NUDGE_MARKER_KIND, repo_root.to_str());
    if marker.exists() {
        return CheckResult::allow();
    }

    let Some(plan) = plan_for_current_branch(&repo_root) else {
        return CheckResult::allow();
    };
    let root_str = repo_root.to_string_lossy();

    // The plan was touched recently, or is dirty in the working tree (the
    // operator is mid-edit) — either way the index is being maintained.
    if recent_commits_touch(&root_str, &plan.rel_path)
        || working_tree_touches(&root_str, &plan.rel_path)
    {
        return CheckResult::allow();
    }

    // Claim the marker BEFORE emitting so a fan-out double-fire can't nudge
    // twice; a failed write degrades to a possible repeat nudge, never a miss.
    let _ = markers::write_marker(&marker, "nudged\n");
    let rel = crate::identity::sanitize_field(&plan.rel_path, crate::identity::MAX_FIELD_DISPLAY);
    CheckResult::nudge(format!(
        "living plan untouched: the last commits didn't tick {rel} — tick completed boxes and \
         bump its updated:/next: (the commit that lands work is the commit that touches the \
         plan; cadence-rules § Plan Execution). Once per session; already-reconciled plans \
         never see this."
    ))
}

pub fn run_warn_plan_ready_flip(input: &HookInput) -> CheckResult {
    let Some(command) = input.command() else {
        return CheckResult::allow();
    };
    if !(command.contains("pr ready") || command.contains("pr merge")) {
        return CheckResult::allow();
    }
    let Some(cwd) = input.cwd.as_deref() else {
        return CheckResult::allow();
    };
    let Some(repo_root) = crate::registry::repo_root(cwd) else {
        return CheckResult::allow();
    };
    let Some(plan) = plan_for_current_branch(&repo_root) else {
        return CheckResult::allow();
    };

    let unticked = unticked_boxes(&plan.path);
    let in_flight = plan.status == "in-flight";
    if !in_flight && unticked == 0 {
        return CheckResult::allow();
    }

    let rel = crate::identity::sanitize_field(&plan.rel_path, crate::identity::MAX_FIELD_DISPLAY);
    let status = crate::identity::sanitize_field(&plan.status, crate::identity::MAX_FIELD_DISPLAY);
    let boxes = match unticked {
        0 => String::new(),
        n => format!(" and {n} unticked checkbox(es)"),
    };
    CheckResult::nudge(format!(
        "ready-flip check: {rel} still shows status: {status}{boxes} — the PR-ready flip is a \
         reconcile point (ADR-0038): tick what shipped, set status:/next:, commit the plan, \
         then flip. Advisory only."
    ))
}

/// The in-flight plan doc bound to the repo's current branch, if any. Binding
/// is exact `branch:` equality — a plan carrying a stale or absent `branch:`
/// is a silent no-fire (the guard must not guess), and shared-main repos
/// match naturally because both sides read `main`. First match wins in
/// `plan_scan`'s deterministic path order.
fn plan_for_current_branch(repo_root: &Path) -> Option<InFlightPlan> {
    let branch =
        cadence_hooks_core::gitstate::GitState::resolve(repo_root).and_then(|gs| gs.branch)?;
    plan_scan::in_flight_plans(repo_root)
        .into_iter()
        .find(|plan| plan.branch.as_deref() == Some(branch.as_str()))
}

/// Does git's commit summary line (`[branch abc1234] subject`) appear in
/// `stdout`? Matched structurally — a line starting with `[`, whose bracketed
/// head ends with a space-separated hex run of ≥7 chars — rather than by
/// substring, so quoted prose about commits can't satisfy it.
fn commit_summary_present(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix('[') else {
            return false;
        };
        let Some(head) = rest.split(']').next() else {
            return false;
        };
        head.rsplit(' ')
            .next()
            .is_some_and(|tail| tail.len() >= 7 && tail.chars().all(|c| c.is_ascii_hexdigit()))
    })
}

/// Did any of the last [`TICK_NUDGE_COMMIT_WINDOW`] commits touch
/// `rel_path`? A failed spawn reads as "touched" — fail-open means never
/// nudging on missing evidence.
fn recent_commits_touch(repo_root: &str, rel_path: &str) -> bool {
    let Some(out) = cadence_hooks_core::shell::git_command(
        repo_root,
        &["log", TICK_NUDGE_COMMIT_WINDOW, "--format=", "--name-only"],
    ) else {
        return true;
    };
    out.lines().any(|line| line.trim() == rel_path)
}

/// Is `rel_path` modified or untracked in the working tree? Empty status
/// output maps to `None` in `git_command` (its empty-stdout-is-failure
/// convention), which correctly reads as "not dirty" here; a genuinely failed
/// spawn also reads "not dirty", which at worst yields one extra advisory
/// nudge — the cheaper failure direction for a nudge.
fn working_tree_touches(repo_root: &str, rel_path: &str) -> bool {
    cadence_hooks_core::shell::git_command(
        repo_root,
        &[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            rel_path,
        ],
    )
    .is_some_and(|out| !out.trim().is_empty())
}

/// Count of unticked `- [ ]` checkboxes in the plan body, bounded by
/// [`PLAN_BODY_READ_CAP_BYTES`]. Any read failure counts as zero — the guard
/// then decides on `status:` alone rather than inventing boxes.
fn unticked_boxes(path: &Path) -> usize {
    use std::io::Read as _;
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    let mut buf = Vec::new();
    if file
        .take(PLAN_BODY_READ_CAP_BYTES)
        .read_to_end(&mut buf)
        .is_err()
    {
        return 0;
    }
    let content = String::from_utf8_lossy(&buf);
    content
        .lines()
        .filter(|line| line.trim_start().starts_with("- [ ]"))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{ToolInput, ToolResponse};
    use std::fs;
    use tempfile::TempDir;

    fn init_repo(dir: &Path) {
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
    }

    fn commit_all(dir: &Path, msg: &str) {
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        };
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", msg]);
    }

    fn write_plan(dir: &Path, name: &str, status: &str, branch: &str, body: &str) {
        let plans = dir.join("docs/plans");
        fs::create_dir_all(&plans).unwrap();
        fs::write(
            plans.join(name),
            format!("---\nstatus: \"{status}\"\nbranch: \"{branch}\"\n---\n\n{body}"),
        )
        .unwrap();
    }

    fn bash_input(session_id: &str, cwd: &Path, command: &str, stdout: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            session_id: Some(session_id.into()),
            cwd: Some(cwd.to_string_lossy().into_owned()),
            tool_input: Some(ToolInput {
                command: Some(command.into()),
                ..Default::default()
            }),
            tool_response: Some(ToolResponse {
                stdout: Some(stdout.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // --- commit_summary_present ---

    #[test]
    fn commit_summary_matches_real_git_output_only() {
        assert!(commit_summary_present(
            "[main abc1234] fix: the thing\n 1 file changed"
        ));
        assert!(commit_summary_present("[feat/x-1 962e444f] long subject\n"));
        // Prose about commits, an aborted commit, and empty output all fail.
        assert!(!commit_summary_present("run git commit to save your work"));
        assert!(!commit_summary_present(
            "error: pre-commit hook failed\nAborting commit"
        ));
        assert!(!commit_summary_present(""));
        // A bracketed line whose tail is not hex is not a summary.
        assert!(!commit_summary_present("[warn] something happened"));
    }

    // --- nudge-plan-tick ---

    #[test]
    fn tick_nudge_fires_once_when_commits_skip_the_plan() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [ ] build\n",
        );
        commit_all(tmp.path(), "plan lands");
        // Three commits that never touch the plan again.
        for i in 0..3 {
            fs::write(tmp.path().join(format!("f{i}.txt")), "x").unwrap();
            commit_all(tmp.path(), "work");
        }

        let input = bash_input(
            "tick-session",
            tmp.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        let r = run_nudge_plan_tick(&input);
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("2026-08-11-guards.md"));

        // Second qualifying commit in the same session: marker holds, silent.
        let r2 = run_nudge_plan_tick(&input);
        assert_eq!(r2.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn tick_nudge_stays_silent_when_the_plan_rode_a_recent_commit() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [x] build\n",
        );
        commit_all(tmp.path(), "plan lands (touches the plan)");

        let input = bash_input(
            "tick-session-2",
            tmp.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn tick_nudge_no_fires_on_failed_commit_wrong_branch_and_no_plan() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "some-other-branch",
            "# G\n\n- [ ] build\n",
        );
        commit_all(tmp.path(), "plan lands");
        for i in 0..3 {
            fs::write(tmp.path().join(format!("f{i}.txt")), "x").unwrap();
            commit_all(tmp.path(), "work");
        }

        // Aborted commit: no summary line in stdout.
        let aborted = bash_input(
            "tick-session-3",
            tmp.path(),
            "git commit -m work",
            "error: pre-commit hook failed\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&aborted).outcome,
            cadence_hooks_core::Outcome::Allow
        );

        // Branch mismatch (plan bound to another branch): silent.
        let ok = bash_input(
            "tick-session-3",
            tmp.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&ok).outcome,
            cadence_hooks_core::Outcome::Allow
        );

        // Non-git cwd: silent.
        let non_git = TempDir::new().unwrap();
        let stray = bash_input(
            "tick-session-3",
            non_git.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&stray).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn tick_nudge_stays_silent_while_the_plan_is_dirty_in_the_tree() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [ ] build\n",
        );
        commit_all(tmp.path(), "plan lands");
        for i in 0..3 {
            fs::write(tmp.path().join(format!("f{i}.txt")), "x").unwrap();
            commit_all(tmp.path(), "work");
        }
        // The operator is mid-edit on the plan: dirty file, no nudge.
        let plan_path = tmp.path().join("docs/plans/2026-08-11-guards.md");
        let mut content = fs::read_to_string(&plan_path).unwrap();
        content.push_str("\n- [x] ticked locally\n");
        fs::write(&plan_path, content).unwrap();

        let input = bash_input(
            "tick-session-4",
            tmp.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- warn-plan-ready-flip ---

    #[test]
    fn ready_flip_warns_on_in_flight_plan_with_unticked_boxes() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [ ] build\n- [ ] wire\n- [x] done\n",
        );
        commit_all(tmp.path(), "plan lands");

        let input = bash_input("flip-session", tmp.path(), "gh pr ready 42", "");
        let r = run_warn_plan_ready_flip(&input);
        assert_eq!(r.outcome, cadence_hooks_core::Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("2 unticked"));
        assert!(msg.contains("status: in-flight"));
    }

    #[test]
    fn ready_flip_silent_when_plan_is_done_and_fully_ticked() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "done",
            "main",
            "# G\n\n- [x] build\n",
        );
        commit_all(tmp.path(), "plan lands");

        let input = bash_input("flip-session-2", tmp.path(), "gh pr merge 42 --squash", "");
        assert_eq!(
            run_warn_plan_ready_flip(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn ready_flip_silent_on_unrelated_commands_and_no_plan() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        // No commit needed: branch resolution reads HEAD's symbolic ref, and
        // the guard must be silent here regardless.

        // No plan at all.
        let input = bash_input("flip-session-3", tmp.path(), "gh pr ready 42", "");
        assert_eq!(
            run_warn_plan_ready_flip(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
        // Unrelated command never reaches the scan.
        let other = bash_input("flip-session-3", tmp.path(), "gh pr view 42", "");
        assert_eq!(
            run_warn_plan_ready_flip(&other).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }
}
