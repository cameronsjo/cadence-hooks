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
//!
//! A third check, the one guard here that can block:
//!
//! - **`lint-plan-shape` (PreToolUse:ExitPlanMode).** The call-side
//!   plan-shape gate (the plan-shape-gate plan, 2026-08-23). A top-level
//!   `ExitPlanMode` whose plan carries no settled `Panel:` line is blocked
//!   before the operator ever sees it — the persist-time lint
//!   (cadence-hooks#675) runs at PostToolUse, after approval, so it could not
//!   catch a harness-template plan (Context/Changes/Verification, no panel,
//!   no alternatives, no checkbox tasks) presented unasked. The block names
//!   only the static stanza names and the in-band escape
//!   (`Panel: none — <reason>`); a settled `Panel:` line with other stanzas
//!   missing draws one nudge sentence instead. Subagent-originated calls
//!   (`agent_id` on the payload) allow silently — a planner subagent
//!   produces a pre-panel draft by design — and every internal failure (no
//!   plan text obtainable, unreadable plan-store file) allows (ADR-0001).
//!   The gate enforces the artifact's *shape*, not that attune ran or that
//!   the operator asked; those stay prose-governed.

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

/// Block `ExitPlanMode` on a plan with no settled `Panel:` line; nudge on
/// other missing template stanzas (the one blocking plan guard).
pub struct LintPlanShape;

impl Check for LintPlanShape {
    fn name(&self) -> &str {
        "lint-plan-shape"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Same defense-in-depth as `persist-plan-approval`: this fires on
        // every top-level ExitPlanMode, and a panic here must allow, never
        // block (ADR-0001).
        std::panic::catch_unwind(|| run_lint_plan_shape(input))
            .unwrap_or_else(|_| CheckResult::allow())
    }
}

/// The in-band escape the block names: one line the operator (or Claude, on
/// the operator's say-so) adds to the plan to assert no panel ran. Static
/// text — the block message never carries matched plan content
/// (cameronsjo/cadence-hooks#715).
const PANEL_ESCAPE_TEMPLATE: &str = "Panel: none — <reason>";

pub fn run_lint_plan_shape(input: &HookInput) -> CheckResult {
    if input.tool_name() != Some("ExitPlanMode") {
        return CheckResult::allow();
    }
    // A subagent-originated call: attune's planner-subagent path and the
    // harness's own Plan agent produce pre-panel drafts by design, and the
    // top-level session is the one that presents. (On claude-code 2.1.241 a
    // subagent cannot call ExitPlanMode at all — this arm is defensive.)
    if input.agent_id().is_some() {
        return CheckResult::allow();
    }
    let Some(plan) = plan_text(input) else {
        return CheckResult::allow();
    };
    judge_plan_shape(&plan)
}

/// The plan text to judge: the call-side inline `tool_input.plan` first (what
/// the 2.1.241 PreToolUse payload carries — Task 0 of the plan-shape-gate
/// plan), else a bounded, containment-checked read of the harness plan-store
/// file named by `planFilePath` (the same reader `persist_plan` trusts).
/// `None` when neither yields text — fail open.
fn plan_text(input: &HookInput) -> Option<String> {
    if let Some(inline) = input.tool_input_plan().filter(|p| !p.trim().is_empty()) {
        return Some(inline.to_string());
    }
    input
        .plan_file_path()
        .and_then(crate::persist_plan::read_plan_store_file)
}

/// The pure decision: block on an unsettled `Panel:` line (naming every
/// missing stanza plus both escapes), nudge on a settled line with other
/// stanzas missing, allow on a template-shaped plan.
fn judge_plan_shape(plan: &str) -> CheckResult {
    let missing = plan_scan::missing_stanzas(plan);
    if missing.is_empty() {
        return CheckResult::allow();
    }
    if missing.contains(&plan_scan::PANEL_STANZA) {
        return CheckResult::block(format!(
            "plan-shape gate: this plan lacks {} — mandatory stanzas of {}. \
             Add the `Panel:` line (a panel that ran: `Panel: <seats> ran — N findings, \
             M folded in, K declined`; none ran: `{PANEL_ESCAPE_TEMPLATE}`) and re-call \
             ExitPlanMode, or leave plan mode with shift-tab. The gate checks the \
             artifact's shape only; attune's panel and the operator's ask to see the \
             plan are still yours to honor.",
            missing.join(", "),
            plan_scan::TEMPLATE_POINTER
        ));
    }
    CheckResult::nudge(format!(
        "plan-shape gate: plan lacks {} — {}.",
        missing.join(", "),
        plan_scan::TEMPLATE_POINTER
    ))
}

pub fn run_nudge_plan_tick(input: &HookInput) -> CheckResult {
    // Structural gate, not a substring (security review of this change): a
    // bare `contains("commit")` is satisfied by `cat docs/commit-policy.md`,
    // whose stdout a repo-controlled file could shape into a fake summary
    // line — spending the once-per-session marker and silencing the real
    // nudge. `is_git_commit` parses the command as a git-commit invocation.
    let Some(command) = input.command() else {
        return CheckResult::allow();
    };
    if !cadence_hooks_metrics::common::is_git_commit(command) {
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

    // Atomic claim (`create_new`) BEFORE emitting, so a concurrent double-fire
    // can't nudge twice — the `exists()` above is only the cheap short-circuit;
    // this is the real gate (code review of this change: exists-then-write is
    // a TOCTOU the doc must not oversell). A failed claim from a race means
    // the sibling spoke; any other failure degrades to a possible repeat
    // nudge, never a miss.
    if !claim_marker(&marker) {
        return CheckResult::allow();
    }
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
    if !is_pr_flip_command(command) {
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
/// Is `command` a `gh pr ready` / `gh pr merge` invocation? Token-window
/// scan over the shell tokenizer's output rather than a substring (security
/// review of this change): `echo "gh pr merge"` tokenizes the quoted text
/// into ONE token, so prose about the command never matches, while flags
/// after the verb (`gh pr merge 42 --squash`) don't disturb the window.
fn is_pr_flip_command(command: &str) -> bool {
    let tokens = cadence_hooks_core::shell::tokenize(command);
    tokens.windows(3).enumerate().any(|(i, w)| {
        if cadence_hooks_core::shell::basename(&w[0]) != "gh" || w[1] != "pr" {
            return false;
        }
        match w[2].as_str() {
            // `--undo` flips the PR back to DRAFT — it un-ships, the retreat
            // FROM the reconcile point this guard names, so the unticked-box
            // nudge is noise. Shared predicate with the ship anchor
            // (cadence-hooks#773/#774): it skips redirect targets and
            // here-string words, which the shell eats before gh sees them.
            "ready" => {
                !cadence_hooks_core::shell::carries_undo_flag(tokens.get(i + 3..).unwrap_or(&[]))
            }
            "merge" => true,
            _ => false,
        }
    })
}

/// Atomically claim `path` with `create_new`: `true` means this invocation
/// owns the claim; `AlreadyExists` means a sibling got there first; any other
/// failure (unwritable marker dir) claims anyway — for an advisory nudge the
/// cheap failure is a repeat, never a miss.
fn claim_marker(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => true,
    }
}

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

/// Count of unticked checkboxes in the plan body, bounded by
/// [`PLAN_BODY_READ_CAP_BYTES`] and counted by the shared fence-aware reader
/// ([`plan_scan::checkbox_counts`] — fenced examples never count). Any read
/// failure counts as zero — the guard then decides on `status:` alone rather
/// than inventing boxes.
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
    let (unticked, _) = plan_scan::checkbox_counts(&String::from_utf8_lossy(&buf));
    unticked
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{Outcome, ToolInput, ToolResponse};
    use std::fs;
    use tempfile::TempDir;

    // --- judge_plan_shape message pins ---

    #[test]
    fn plan_shape_block_message_names_stanzas_and_template_home() {
        let r = judge_plan_shape("# T\n\nprose only\n");
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        assert!(msg.contains("plan-shape gate: this plan lacks "));
        assert!(msg.contains("a settled Panel: line"));
        assert!(
            msg.contains("the plan template: `cadence:arrange` `references/plan-template.md`"),
            "the block names the template's home: {msg}"
        );
    }

    #[test]
    fn plan_shape_nudge_message_names_stanzas_and_template_home() {
        // Panel settled, everything else missing → nudge, never block.
        let r = judge_plan_shape("# T\n\nPanel: none — trivial change\n\nprose\n");
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("plan-shape gate: plan lacks "));
        assert!(msg.contains("an Alternatives-declined stanza"));
        assert!(msg.contains("a ## Global Constraints section"));
        assert!(msg.contains("an ## Orchestrator block with a Driver: line"));
        assert!(msg.contains("a ## Tasks section"));
        assert!(msg.contains("checkbox tasks"));
        assert!(
            msg.contains("the plan template: `cadence:arrange` `references/plan-template.md`."),
            "the nudge names the template's home: {msg}"
        );
    }

    #[test]
    fn plan_shape_template_shaped_plan_allows() {
        let r = judge_plan_shape(plan_scan::TEMPLATE_SHAPED_PLAN);
        assert_eq!(r.outcome, Outcome::Allow);
    }

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
    fn ready_flip_silent_on_ready_undo() {
        // `gh pr ready --undo` flips the PR BACK to draft — it un-ships, the
        // exact retreat from the reconcile point this guard names, so the
        // unticked-box nudge is noise (cadence-hooks#774, sibling of #773).
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [ ] build\n- [ ] wire\n",
        );
        commit_all(tmp.path(), "plan lands");

        for cmd in ["gh pr ready --undo", "gh pr ready 42 --undo"] {
            let input = bash_input("flip-undo-session", tmp.path(), cmd, "");
            assert_eq!(
                run_warn_plan_ready_flip(&input).outcome,
                cadence_hooks_core::Outcome::Allow,
                "{cmd} un-ships and must not nudge"
            );
        }
    }

    #[test]
    fn ready_flip_warns_when_undo_is_a_redirect_target() {
        // The shell eats a redirect target and a here-string word — gh never
        // sees the flag, so these are real ready flips and still owe the nudge.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "in-flight",
            "main",
            "# G\n\n- [ ] build\n- [ ] wire\n",
        );
        commit_all(tmp.path(), "plan lands");

        for (session, cmd) in [
            ("flip-redirect-1", "gh pr ready 42 > --undo"),
            ("flip-redirect-2", "gh pr ready 42 <<< --undo"),
        ] {
            let input = bash_input(session, tmp.path(), cmd, "");
            assert_eq!(
                run_warn_plan_ready_flip(&input).outcome,
                cadence_hooks_core::Outcome::Nudge,
                "{cmd} is a real ready flip"
            );
        }
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
        // Prose ABOUT the command is one quoted token — never a match
        // (security review: the substring prefilter drew warnings here).
        let prose = bash_input("flip-session-3", tmp.path(), "echo \"gh pr merge\"", "");
        assert_eq!(
            run_warn_plan_ready_flip(&prose).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn ready_flip_ignores_fenced_checkbox_examples() {
        // The shared reader's fence discipline: a plan documenting checklist
        // syntax in a fenced example, real checklist fully ticked → silent
        // when status is done (the polish code-review arm's Critical).
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        write_plan(
            tmp.path(),
            "2026-08-11-guards.md",
            "done",
            "main",
            "# G\n\n- [x] build\n\n```\n- [ ] fenced example, not a task\n```\n",
        );
        commit_all(tmp.path(), "plan lands");
        let input = bash_input("flip-session-4", tmp.path(), "gh pr ready 42", "");
        assert_eq!(
            run_warn_plan_ready_flip(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn tick_nudge_requires_a_structural_git_commit_command() {
        // A non-commit command whose stdout carries a fake summary line (a
        // repo-controlled file's contents) must neither nudge nor burn the
        // once-per-session marker (security review: the Important finding).
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
        let spoof = bash_input(
            "tick-session-5",
            tmp.path(),
            "cat docs/commit-policy.md",
            "[main abc1234] looks like a commit\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&spoof).outcome,
            cadence_hooks_core::Outcome::Allow
        );
        // The marker was NOT burned: a real commit right after still nudges.
        let real = bash_input(
            "tick-session-5",
            tmp.path(),
            "git commit -m work",
            "[main abc1234] work\n",
        );
        assert_eq!(
            run_nudge_plan_tick(&real).outcome,
            cadence_hooks_core::Outcome::Nudge
        );
    }
}
