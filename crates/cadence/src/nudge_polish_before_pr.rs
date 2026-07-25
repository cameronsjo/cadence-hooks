//! Gate `/polish` before branch work ships for review.
//!
//! Fires on the **ship moment** — `gh pr ready` (leaving draft) or a **non-draft**
//! `gh pr create` (the legacy direct flow). A `--draft` create is deliberately
//! NOT an anchor: entry posture (cadence#278) opens a draft PR at worktree entry,
//! at zero diff, where polish is meaningless — nudging there fires once per branch
//! with nothing to polish, then never again (#297). `gh pr merge` is also excluded
//! (an orchestrator often runs it from `main`/another cwd, so the branch
//! mis-resolves and false-nudges).
//!
//! Polish is mandatory before a PR ships, so this check reads a **branch-scoped
//! marker** the polish skill records when it completes (`cadence-hooks cadence
//! record-polish`), keyed on `(repo_root, branch)`. It routes a 2-way, fail-open
//! outcome:
//!
//! - a polish marker exists for the PR's branch → **allow** (silent — no nag
//!   after a real polish run);
//! - no marker for this branch (or the repo/branch can't be resolved) → **nudge**
//!   (ADR-0001 fail-open; CP1 never blocks on our own missing data).
//!
//! This replaces the earlier session-transcript scan, which false-blocked a
//! `/polish` slash-command (no `Skill` `tool_use` block to find, #154) and was
//! branch-blind — a polish on branch A satisfied a PR on branch B (#146). The
//! marker is invocation-agnostic (Skill call, slash-command, or a delegated
//! subagent all end by recording it) and branch-scoped by key construction — so
//! whoever runs the ship command on the branch resolves the same marker a
//! completed `/polish` wrote, session-independently.
//!
//! `/polish` runs a branch-scoped pass over the changes vs `origin/main` —
//! simplify, logging, tests, docs, security, and code review. Skill, agent,
//! command, and rule markdown (and CLAUDE.md) are behavior, not documentation,
//! so they are in scope; literal documentation (prose about the system) routes
//! to `/polish docs`. A skip is legitimate only for a trivial one-liner or a
//! branch already taken through `/polish`.
//!
//! CP1 is nudge-only during rollout (the marker restores reliable *detection*);
//! CP2 escalates the absent-marker nudge to a block once the skill's marker
//! write has propagated.

use cadence_hooks_core::markers::polish_marker_present;
use cadence_hooks_core::shell::is_polish_ship_anchor;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Gates `/polish` (cadence-forge:polish) before opening a PR — conditional on a
/// branch-scoped polish marker recorded by a completed polish pass.
pub struct NudgePolishBeforePr;

impl Check for NudgePolishBeforePr {
    fn name(&self) -> &str {
        "nudge-polish-before-pr"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        // Only a ship anchor (`gh pr ready` / non-draft `gh pr create`) pays the
        // git-resolution cost; every other command short-circuits to allow
        // inside `decide`.
        let marker_present =
            is_polish_ship_anchor(command) && polish_marker_present(command, input.cwd.as_deref());
        decide(command, marker_present)
    }
}

/// The pure 2-way conditional — no I/O, so the gate logic is unit-tested without
/// the filesystem. `run()` resolves the marker and hands the boolean in.
///
/// - non-ship-anchor (incl. a `--draft` create and `gh pr merge`) → allow.
/// - ship anchor + a branch-scoped polish marker present → allow (silent).
/// - ship anchor + no marker (or unresolved repo/branch/cwd) → nudge
///   (fail-open floor, ADR-0001 — CP1 never blocks).
fn decide(command: &str, marker_present: bool) -> CheckResult {
    if !is_polish_ship_anchor(command) {
        return CheckResult::allow();
    }
    if marker_present {
        // Polish recorded a marker for this branch — silent allow. Kills the
        // nag-after-polish noise and honors every invocation shape.
        CheckResult::allow()
    } else {
        // No marker for this branch — fail open to the soft nudge, never block.
        CheckResult::nudge(nudge_message())
    }
}

/// The loophole-closing clauses the nudge carries, so the "it's just markdown"
/// and "TDD/attune already covered it" skips can't survive it.
const SCOPE_CLAUSES: &str = "Skill / agent / command / rule markdown and \
    CLAUDE.md are behavior, not documentation — IN scope; only *literal* docs \
    route to `/polish docs`. Planning, TDD, attune, or a code-review precede \
    polish — they don't replace it.";

/// The soft nudge — fires when no polish marker exists for the PR's branch.
/// Allow + warn; the model proceeds (CP1 fail-open floor, ADR-0001).
fn nudge_message() -> String {
    format!(
        "No polish recorded for this branch — run `/polish` (cadence-forge:polish) \
         before this PR ships: a branch-scoped quality pass vs `origin/main`; it \
         records the marker when it completes. {SCOPE_CLAUSES} Skip ONLY for a \
         trivial one-liner or an already-polished branch — say so and why, don't \
         skip silently."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::with_marker_dir;
    use cadence_hooks_core::gitstate::GitState;
    use cadence_hooks_core::markers::{polish_marker, write_marker};
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};
    use cadence_hooks_core::{Outcome, ToolInput};
    use std::process::Command;

    fn nudge_msg_has_loophole_clauses(msg: &str) {
        // The nudge MUST keep telling the model that skill / agent / command /
        // rule markdown is behavior — the clause that stops "it's just markdown".
        assert!(
            msg.contains("behavior, not documentation"),
            "message should name behavioral markdown as in scope: {msg}"
        );
        // Planning / TDD / attune / review must not read as polish-equivalent.
        assert!(
            msg.contains("they don't replace it"),
            "message should deny that upstream process substitutes for polish: {msg}"
        );
        // A skip must be surfaced, never silent — so the user can veto it.
        assert!(
            msg.contains("don't skip silently"),
            "message should require the model to state why it is skipping: {msg}"
        );
    }

    #[test]
    fn gh_pr_create_nudges() {
        // No cwd → marker unresolved → fail-open nudge.
        let result = NudgePolishBeforePr.run(&make_bash("gh pr create --title test"));
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"), "message should mention /polish");
        nudge_msg_has_loophole_clauses(&msg);
    }

    // --- decide(): the pure 2-way conditional (no filesystem) ---

    #[test]
    fn decide_pr_create_with_marker_allows_silently() {
        // A branch-scoped marker present → silent allow. #154 regression: this
        // holds with NO transcript involvement — a slash-command polish that
        // recorded a marker is honored.
        let result = decide("gh pr create --title test", true);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(
            result.message.is_none(),
            "a recorded polish must allow silently, no nag"
        );
    }

    #[test]
    fn decide_pr_create_without_marker_nudges() {
        // #146 RED (pure): no marker → nudge, never block. CP1 is fail-open.
        let result = decide("gh pr create --title x", false);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"));
        nudge_msg_has_loophole_clauses(&msg);
    }

    #[test]
    fn decide_non_ship_anchor_allows_regardless_of_marker() {
        // The matcher only scopes the process spawn; decide() still guards
        // against a non-anchor gh command slipping through.
        assert_eq!(decide("gh pr list", false).outcome, Outcome::Allow);
        assert_eq!(decide("git commit -m x", true).outcome, Outcome::Allow);
        // `gh pr merge` is excluded — it must not nudge even without a marker.
        assert_eq!(decide("gh pr merge 12", false).outcome, Outcome::Allow);
    }

    #[test]
    fn decide_draft_create_allows_regardless_of_marker() {
        // A `--draft` create is not the ship moment (#297) — an entry-posture
        // draft opens at zero diff, so it must allow even with no marker.
        assert_eq!(
            decide("gh pr create --draft", false).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh pr create -d --title x", false).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_pr_ready_routes_like_create() {
        // `gh pr ready` (leaves draft) is the ship anchor: no marker → nudge,
        // marker present → silent allow.
        let nudge = decide("gh pr ready 12", false);
        assert_eq!(nudge.outcome, Outcome::Nudge);
        nudge_msg_has_loophole_clauses(&nudge.message.unwrap_or_default());
        let allow = decide("gh pr ready 12", true);
        assert_eq!(allow.outcome, Outcome::Allow);
        assert!(allow.message.is_none());
    }

    // --- integration through run() with a real temp git repo (#146 fixture) ---

    /// Init a git repo in a fresh tempdir, checked out on `branch` (no commit
    /// needed — an unborn HEAD still resolves a branch name via [`GitState`],
    /// and the gate only reads the common dir + current branch). Returns the
    /// tempdir and the git-resolved `git_common_dir` (canonicalized, so it
    /// matches what `run()` resolves — critical on macOS where `/tmp` →
    /// `/private/tmp` — and the same key `polish_marker_present` now uses,
    /// cadence-hooks#324).
    fn init_repo_on_branch(branch: &str) -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["checkout", "-q", "-b", branch]);
        let state = GitState::resolve(tmp.path()).expect("temp repo resolves git state");
        let root = state.git_common_dir.to_string_lossy().into_owned();
        (tmp, root)
    }

    #[test]
    fn run_different_branch_marker_does_not_satisfy() {
        // #146 RED (integration): repo is on branch B, but the only marker is for
        // branch A → the different-branch marker must NOT satisfy → Nudge.
        let (tmp, root) = init_repo_on_branch("branch-b");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "branch-a"), "{}").unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Nudge);
        });
    }

    #[test]
    fn run_same_branch_marker_allows_silently() {
        // #146 GREEN companion: a marker for the *current* branch satisfies →
        // Allow, silent. Also the #154 regression end-to-end: no transcript at
        // all is involved, purely the marker.
        let (tmp, root) = init_repo_on_branch("feat/thing");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/thing"), "{}").unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(
                result.message.is_none(),
                "a recorded polish allows silently"
            );
        });
    }

    #[test]
    fn run_no_marker_in_real_repo_nudges() {
        // Fail-open: a resolvable repo/branch but no marker → Nudge, never Block.
        // run() reads marker_dir() (env) via polish_marker_present, so hold
        // ENV_LOCK against concurrent with_marker_dir writers (#369), off the
        // real per-user dir (#302).
        let (tmp, _root) = init_repo_on_branch("feat/unmarked");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
        });
    }

    #[test]
    fn run_pr_ready_same_branch_marker_allows_silently() {
        // The ship anchor end-to-end: `gh pr ready` on a branch whose marker
        // exists → silent allow, resolved the same way a create would be.
        let (tmp, root) = init_repo_on_branch("feat/ready");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/ready"), "{}").unwrap();

            let input = make_bash_with_cwd("gh pr ready 12", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(
                result.message.is_none(),
                "a recorded polish allows silently"
            );
        });
    }

    #[test]
    fn run_pr_ready_no_marker_nudges() {
        // `gh pr ready` with no marker for the branch → fail-open nudge.
        // Under ENV_LOCK (#369/#302), same as the create-side sibling above.
        let (tmp, _root) = init_repo_on_branch("feat/ready-unmarked");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let input = make_bash_with_cwd("gh pr ready 12", tmp.path().to_str().unwrap());
            assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Nudge);
        });
    }

    #[test]
    fn run_draft_create_allows_even_without_marker() {
        // A `--draft` create in a resolvable repo with no marker still allows —
        // the anchor skips drafts before any marker resolution (#297).
        let (tmp, _root) = init_repo_on_branch("feat/draft");
        let input = make_bash_with_cwd(
            "gh pr create --draft --title x",
            tmp.path().to_str().unwrap(),
        );
        assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_unresolved_cwd_nudges_never_blocks() {
        // No cwd at all → marker unresolved → fail-open nudge (never Block).
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(ToolInput {
                command: Some("gh pr create --title x".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Nudge);
    }

    // --- worktree-stable keying (cadence-hooks#324) ---

    /// `git -C primary <args>`, asserting success. Shared by the worktree
    /// fixtures below.
    fn git_in(dir: &std::path::Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?} failed"
        );
    }

    /// A primary checkout with one commit — `git worktree add` refuses an
    /// unborn branch, unlike [`init_repo_on_branch`]'s marker-only fixtures.
    fn init_primary_with_commit(primary: &std::path::Path) {
        std::fs::create_dir_all(primary).unwrap();
        git_in(primary, &["init", "-q", "-b", "main"]);
        git_in(primary, &["config", "user.email", "t@t"]);
        git_in(primary, &["config", "user.name", "t"]);
        git_in(primary, &["commit", "-q", "--allow-empty", "-m", "init"]);
    }

    #[test]
    fn run_worktree_marker_satisfies_primary_ship_command() {
        // #324: a marker recorded from a linked worktree must satisfy the ship
        // command run from the primary checkout, once the primary is on the
        // same branch — the common-dir key is shared across both checkouts.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);
        let wt = tmp.path().join("wt");
        git_in(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                wt.to_str().unwrap(),
                "-b",
                "feat/thing",
            ],
        );

        let wt_state = GitState::resolve(&wt).expect("worktree resolves");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&wt_state.git_common_dir.to_string_lossy(), "feat/thing"),
                "{}",
            )
            .unwrap();

            git_in(
                &primary,
                &["worktree", "remove", "--force", wt.to_str().unwrap()],
            );
            git_in(&primary, &["checkout", "-q", "feat/thing"]);

            let input = make_bash_with_cwd("gh pr create --title x", primary.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "a worktree-recorded marker must satisfy the primary checkout on the same branch"
            );
        });
    }

    #[test]
    fn run_primary_marker_satisfies_worktree_ship_command() {
        // #324 inverse: a marker recorded from the PRIMARY checkout must
        // satisfy a ship command run from a linked WORKTREE on the same branch.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);
        git_in(&primary, &["checkout", "-q", "-b", "feat/y"]);

        let primary_state = GitState::resolve(&primary).expect("primary resolves");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&primary_state.git_common_dir.to_string_lossy(), "feat/y"),
                "{}",
            )
            .unwrap();

            // Free `feat/y` from the primary so a worktree can check it out.
            git_in(&primary, &["checkout", "-q", "main"]);
            let wt = tmp.path().join("wt");
            git_in(
                &primary,
                &["worktree", "add", "-q", wt.to_str().unwrap(), "feat/y"],
            );

            let input = make_bash_with_cwd("gh pr create --title x", wt.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "a primary-recorded marker must satisfy a linked worktree on the same branch"
            );
        });
    }

    #[test]
    fn run_worktree_marker_does_not_satisfy_different_branch() {
        // The common-dir re-key must not loosen branch scoping: a marker
        // recorded from a worktree on branch A must still miss when the ship
        // command runs on a different branch, even in the same repo.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);
        let wt = tmp.path().join("wt");
        git_in(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                wt.to_str().unwrap(),
                "-b",
                "feat/a",
            ],
        );

        let wt_state = GitState::resolve(&wt).expect("worktree resolves");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&wt_state.git_common_dir.to_string_lossy(), "feat/a"),
                "{}",
            )
            .unwrap();

            // Primary stays on `main` — a different branch from the marker.
            let input = make_bash_with_cwd("gh pr create --title x", primary.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Nudge,
                "a marker for a different branch must not satisfy the ship command"
            );
        });
    }

    #[test]
    fn run_newline_separated_cd_to_worktree_satisfies_gate() {
        // #394/#368 regression. The filed hypothesis blamed writer/reader key
        // divergence; the real defect was the READER's cwd resolver swallowing
        // the newline into the `cd` target, so the ship command resolved to a
        // nonexistent directory and never found the (correct) marker.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);
        let wt = tmp.path().join("wt");
        git_in(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                wt.to_str().unwrap(),
                "-b",
                "feat/newline",
            ],
        );

        let wt_state = GitState::resolve(&wt).expect("worktree resolves");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&wt_state.git_common_dir.to_string_lossy(), "feat/newline"),
                "{}",
            )
            .unwrap();

            // cwd is the PRIMARY (still on `main`) — only the `cd` redirects to
            // the worktree, so the newline handling is the whole test.
            let command = format!("cd {}\ngh pr create --title x", wt.to_str().unwrap());
            let input = make_bash_with_cwd(&command, primary.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "a newline-separated `cd` into a marked worktree must satisfy the gate"
            );
        });
    }

    #[test]
    fn run_subshell_cd_to_worktree_satisfies_gate() {
        // Same defect, subshell shape: `( cd <wt> && gh pr create )` after a
        // newline. The group opener must not hide the `cd` command word.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);
        let wt = tmp.path().join("wt");
        git_in(
            &primary,
            &[
                "worktree",
                "add",
                "-q",
                wt.to_str().unwrap(),
                "-b",
                "feat/subshell",
            ],
        );

        let wt_state = GitState::resolve(&wt).expect("worktree resolves");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&wt_state.git_common_dir.to_string_lossy(), "feat/subshell"),
                "{}",
            )
            .unwrap();

            let command = format!(
                "echo x\n( cd {} && gh pr create --title x )",
                wt.to_str().unwrap()
            );
            let input = make_bash_with_cwd(&command, primary.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "a subshell `cd` into a marked worktree must satisfy the gate"
            );
        });
    }

    // --- preserved matcher tests (is_polish_ship_anchor) ---

    #[test]
    fn gh_pr_create_with_heredoc_body_nudges() {
        let cmd = "gh pr create --title test --body \"$(cat <<'EOF'\n## Summary\nfoo\nEOF\n)\"";
        let result = NudgePolishBeforePr.run(&make_bash(cmd));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_list_allowed() {
        assert_eq!(
            NudgePolishBeforePr.run(&make_bash("gh pr list")).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn gh_pr_view_allowed() {
        assert_eq!(
            NudgePolishBeforePr
                .run(&make_bash("gh pr view 123"))
                .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn gh_pr_review_allowed() {
        assert_eq!(
            NudgePolishBeforePr
                .run(&make_bash("gh pr review 123 --approve"))
                .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn gh_issue_create_allowed() {
        assert_eq!(
            NudgePolishBeforePr
                .run(&make_bash("gh issue create --title test"))
                .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn git_command_allowed() {
        // "gh pr create" appears only inside a single-quoted arg, so the token
        // window never lines up → not a gh-pr-create.
        assert_eq!(
            NudgePolishBeforePr
                .run(&make_bash("git commit -m 'gh pr create'"))
                .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(NudgePolishBeforePr.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn branch_name_with_pr_create_substring_allowed() {
        // Branch named gh-pr-create-experiments shouldn't fire.
        assert_eq!(
            NudgePolishBeforePr
                .run(&make_bash("git checkout gh-pr-create-experiments"))
                .outcome,
            Outcome::Allow
        );
    }
}
