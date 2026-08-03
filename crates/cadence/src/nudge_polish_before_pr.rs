//! Gate `/polish` before branch work ships for review.
//!
//! Fires on the **ship moment** — `gh pr ready` (leaving draft), a **non-draft**
//! `gh pr create` (the legacy direct flow), or a **bare** `gh pr merge`. A
//! `--draft` create is deliberately NOT an anchor: entry posture (cadence#278)
//! opens a draft PR at worktree entry, at zero diff, where polish is meaningless
//! — nudging there fires once per branch with nothing to polish, then never
//! again (#297).
//!
//! Merge is the anchor set's **last resort**, added because a draft-first branch
//! could go draft → ready → merged with nothing ever firing when the ready-flip
//! happened in the web UI, which no Bash hook can see (#325). It is admitted
//! only in the spelling whose target this check can actually resolve: gh selects
//! "the pull request that belongs to the current branch" when given no argument,
//! so a bare merge is about the cwd's branch. A merge naming a number, URL, or
//! branch — or retargeted at another repository by any of `--repo`/`-R` in
//! either position, the attached `-Rowner/r` form, or an inline `GH_REPO=`
//! assignment — stays excluded. That is the orchestrator shape merge was
//! excluded for originally: merging from `main` or another cwd requires naming
//! the PR.
//!
//! Two routes still hide a selector from the check, both nudge-only: an
//! *exported* `GH_REPO` leaves no token in the command string, and a token
//! written after a `&`-bearing redirect lands in a different segment
//! (`gh pr merge 2>&1 12`). Enumerated at
//! [`cadence_hooks_core::shell::is_polish_ship_anchor`] rather than papered
//! over — the anchor is the best reading of the command text, not a proof about
//! what gh will do.
//!
//! The web-UI ready-flip remains unclosable here by construction — a browser
//! click passes through no hooked Bash call at all.
//!
//! Polish is mandatory before a PR ships, so this check reads a **branch-scoped
//! marker** the polish skill records when it completes (`cadence-hooks cadence
//! record-polish`), keyed on `(repo_root, branch)`. It routes a fail-open
//! outcome:
//!
//! - a polish marker exists for the PR's branch → **allow** (silent — no nag
//!   after a real polish run) — unless the marker's own record affirmatively
//!   says the **security arm did not run** (an `arms` roster entry
//!   `security=skipped`, or a `scope: docs` pass, which never dispatches it)
//!   *and* the branch's diff vs `origin/main` touches code by polish's own
//!   definition → a distinct **security nudge** (cadence-hooks#467). An absent
//!   roster is *unknown, never skipped* — every legacy roster-less marker keeps
//!   allowing;
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

use cadence_hooks_core::branch_diff::{branch_touches_code, changed_files};
use cadence_hooks_core::markers::{polish_marker_present, read_polish_marker};
use cadence_hooks_core::shell::{is_polish_ship_anchor, parse_work_dir};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// What the branch-scoped polish marker says, as far as the gate can read it
/// (cadence-hooks#467).
///
/// `security_ran: None` is *unknown* — a legacy roster-less marker, an
/// unparseable body, or a degraded (non-private) marker dir — and unknown
/// keeps allowing: the presence bool alone carries the verdict, exactly the
/// pre-#467 behavior. Only an affirmative `Some(false)` (an explicit
/// `security=skipped` roster entry, or a `scope: docs` pass, which never
/// dispatches the security arm) can escalate to the security nudge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerState {
    /// No polish marker for this branch (or repo/branch/cwd unresolved).
    Absent,
    /// A marker exists; `security_ran` per the roster/scope, `None` = unknown.
    Present { security_ran: Option<bool> },
}

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
        // Only a ship anchor (`gh pr ready`, a non-draft `gh pr create`, or a
        // bare `gh pr merge`) pays the git-resolution cost; every other command
        // short-circuits to allow inside `decide`.
        let cwd = input.cwd.as_deref();
        let marker = if is_polish_ship_anchor(command) && polish_marker_present(command, cwd) {
            MarkerState::Present {
                security_ran: read_polish_marker(command, cwd).and_then(|r| r.security_ran()),
            }
        } else {
            MarkerState::Absent
        };
        // The diff subprocess is ordered LAST and runs only when the roster
        // affirmatively says security was skipped — the common full-polish
        // path (and every absent/unknown case) never pays for it. A timed-out
        // or unspawnable git yields no evidence (`None`), which reads as
        // "does not touch code" → allow (ADR-0001).
        let touches_code = matches!(
            marker,
            MarkerState::Present {
                security_ran: Some(false)
            }
        ) && cwd.is_some_and(|cwd| {
            let dir = parse_work_dir(command, cwd);
            changed_files(&dir).is_some_and(|files| branch_touches_code(&files))
        });
        decide(command, marker, touches_code)
    }
}

/// The pure conditional — no I/O, so the gate logic is unit-tested without the
/// filesystem. `run()` resolves the marker and the branch diff, and hands both
/// in.
///
/// - non-ship-anchor (incl. a `--draft` create, and a `gh pr merge` that names
///   a PR or overrides the repo) → allow.
/// - ship anchor + no marker (or unresolved repo/branch/cwd) → nudge
///   (fail-open floor, ADR-0001 — CP1 never blocks).
/// - ship anchor + marker whose roster affirmatively says the security arm did
///   not run, on a branch that touches code (polish's own definition — the
///   caller computes it) → the security nudge (#467).
/// - ship anchor + any other marker (security ran, or unknown — the legacy
///   roster-less shape the whole estate carries) → allow (silent).
fn decide(command: &str, marker: MarkerState, branch_touches_code: bool) -> CheckResult {
    if !is_polish_ship_anchor(command) {
        return CheckResult::allow();
    }
    match marker {
        MarkerState::Absent => CheckResult::nudge(nudge_message()),
        MarkerState::Present {
            security_ran: Some(false),
        } if branch_touches_code => CheckResult::nudge(security_nudge_message()),
        // Polish recorded a marker for this branch, and nothing affirmatively
        // says the security arm was skipped on a code branch — silent allow.
        MarkerState::Present { .. } => CheckResult::allow(),
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

/// The #467 escalation: a polish DID run and record, but its roster says the
/// security arm did not — and the branch touches code. Distinct from the
/// no-marker nudge so the reader knows which gap to close (the arm, not the
/// whole pass). Advisory, fail-open (ADR-0001), like everything here.
fn security_nudge_message() -> String {
    format!(
        "Polish ran on this branch, but its record says the SECURITY arm did not \
         (an explicit security=skipped, or a docs-scoped pass) — and this branch's \
         diff vs origin/main touches code. Run the security arm before this PR \
         ships: dispatch `cadence-forge:security-reviewer` (Opus) against the \
         branch diff, then re-run `cadence-hooks cadence record-polish` with \
         `--arm security=ran`. {SCOPE_CLAUSES}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::gitstate::GitState;
    use cadence_hooks_core::markers::{polish_marker, write_marker};
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd, with_marker_dir};
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

    // --- decide(): the pure conditional (no filesystem) ---

    /// The legacy shape: a marker exists, roster unknown. Pre-#467 behavior
    /// must hold for it everywhere a bare `true` used to.
    const PRESENT_UNKNOWN: MarkerState = MarkerState::Present { security_ran: None };
    const PRESENT_SECURITY_RAN: MarkerState = MarkerState::Present {
        security_ran: Some(true),
    };
    const PRESENT_SECURITY_SKIPPED: MarkerState = MarkerState::Present {
        security_ran: Some(false),
    };

    #[test]
    fn decide_security_skipped_on_code_branch_nudges_distinctly() {
        // #467 RED: a recorded polish whose roster says the security arm did
        // not run, on a branch touching code, must nudge — with the security
        // message, not the no-polish one.
        let result = decide("gh pr create --title x", PRESENT_SECURITY_SKIPPED, true);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("SECURITY arm"),
            "the escalation must name the security arm: {msg}"
        );
        assert!(
            msg.contains("--arm security=ran"),
            "the escalation must name the re-record step: {msg}"
        );
        assert!(
            !msg.contains("No polish recorded"),
            "must not present as the no-polish nudge: {msg}"
        );
    }

    #[test]
    fn decide_security_skipped_on_docs_only_branch_allows() {
        // #467 positive control (silent side): a docs-scoped polish on a
        // branch whose diff touches no code is exactly right — no nudge.
        let result = decide("gh pr create --title x", PRESENT_SECURITY_SKIPPED, false);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_security_ran_allows_regardless_of_code() {
        assert_eq!(
            decide("gh pr create --title x", PRESENT_SECURITY_RAN, true).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_legacy_roster_less_marker_allows_on_code_branch() {
        // #467 RED: absent roster = UNKNOWN, not skipped — the whole estate
        // carries roster-less markers, and every one must keep allowing even
        // on a code branch.
        let result = decide("gh pr create --title x", PRESENT_UNKNOWN, true);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_pr_create_with_marker_allows_silently() {
        // A branch-scoped marker present → silent allow. #154 regression: this
        // holds with NO transcript involvement — a slash-command polish that
        // recorded a marker is honored.
        let result = decide("gh pr create --title test", PRESENT_UNKNOWN, false);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(
            result.message.is_none(),
            "a recorded polish must allow silently, no nag"
        );
    }

    #[test]
    fn decide_pr_create_without_marker_nudges() {
        // #146 RED (pure): no marker → nudge, never block. CP1 is fail-open.
        let result = decide("gh pr create --title x", MarkerState::Absent, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("/polish"));
        nudge_msg_has_loophole_clauses(&msg);
    }

    #[test]
    fn decide_non_ship_anchor_allows_regardless_of_marker() {
        // The matcher only scopes the process spawn; decide() still guards
        // against a non-anchor gh command slipping through.
        assert_eq!(
            decide("gh pr list", MarkerState::Absent, false).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("git commit -m x", PRESENT_UNKNOWN, false).outcome,
            Outcome::Allow
        );
        // A merge that NAMES a PR is excluded — it is the orchestrator shape,
        // run from another cwd, where the branch would mis-resolve (#325). A
        // bare merge is a ship anchor and nudges; pinned just below.
        assert_eq!(
            decide("gh pr merge 12", MarkerState::Absent, false).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh --repo owner/r pr merge", MarkerState::Absent, false).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh pr merge --squash", MarkerState::Absent, false).outcome,
            Outcome::Nudge
        );
        // ...and stays silent once the branch carries a marker.
        assert_eq!(
            decide("gh pr merge --squash", PRESENT_UNKNOWN, false).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_draft_create_allows_regardless_of_marker() {
        // A `--draft` create is not the ship moment (#297) — an entry-posture
        // draft opens at zero diff, so it must allow even with no marker.
        assert_eq!(
            decide("gh pr create --draft", MarkerState::Absent, false).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh pr create -d --title x", MarkerState::Absent, false).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_pr_ready_routes_like_create() {
        // `gh pr ready` (leaves draft) is the ship anchor: no marker → nudge,
        // marker present → silent allow.
        let nudge = decide("gh pr ready 12", MarkerState::Absent, false);
        assert_eq!(nudge.outcome, Outcome::Nudge);
        nudge_msg_has_loophole_clauses(&nudge.message.unwrap_or_default());
        let allow = decide("gh pr ready 12", PRESENT_UNKNOWN, false);
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

    // --- #467: security-arm roster, end to end through run() ---

    /// [`init_repo_on_branch`] plus: a base commit mirrored to a synthetic
    /// `origin/main` remote-tracking ref (merge-base needs only the ref, not a
    /// remote), then `files` committed on the feature branch.
    fn init_repo_with_origin_and_files(
        branch: &str,
        files: &[&str],
    ) -> (tempfile::TempDir, String) {
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
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "init"]);
        git(&["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git(&["checkout", "-q", "-b", branch]);
        for f in files {
            let path = tmp.path().join(f);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "x\n").unwrap();
            git(&["add", f]);
        }
        if !files.is_empty() {
            git(&["commit", "-q", "-m", "branch work"]);
        }
        let state = GitState::resolve(tmp.path()).expect("temp repo resolves git state");
        let root = state.git_common_dir.to_string_lossy().into_owned();
        (tmp, root)
    }

    #[test]
    fn run_docs_marker_on_code_branch_fires_security_nudge() {
        // #467 RED (integration, positive control — FIRES): a docs-scoped
        // marker means the security arm never ran; the branch touches a
        // skill SKILL.md (code by polish's own definition) → security nudge.
        let (tmp, root) =
            init_repo_with_origin_and_files("feat/code", &["skills/arrange/SKILL.md"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/code"), r#"{"scope":"docs"}"#).unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Nudge,
                "docs marker + code branch must nudge"
            );
            assert!(
                result.message.unwrap_or_default().contains("SECURITY arm"),
                "must be the security escalation, not the no-polish nudge"
            );
        });
    }

    #[test]
    fn run_docs_marker_on_docs_only_branch_stays_silent() {
        // #467 positive control (SILENT): docs-scoped marker + a branch whose
        // diff is literal docs only → allow, no message.
        let (tmp, root) = init_repo_with_origin_and_files("feat/docs", &["docs/notes.md"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/docs"), r#"{"scope":"docs"}"#).unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(result.message.is_none());
        });
    }

    #[test]
    fn run_legacy_roster_less_marker_stays_silent_on_code_branch() {
        // #467 positive control (SILENT): the estate's existing markers carry
        // no roster and no scope worth reading ("{}") — unknown must keep
        // allowing on a code branch, exactly the pre-#467 behavior.
        let (tmp, root) = init_repo_with_origin_and_files("feat/legacy", &["src/main.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/legacy"), "{}").unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(result.message.is_none());
        });
    }

    #[test]
    fn run_security_skipped_roster_on_code_branch_fires() {
        // #467: the explicit-roster form of the docs-marker case — a full-scope
        // marker whose roster says security=skipped, code branch → nudge.
        let (tmp, root) = init_repo_with_origin_and_files("feat/roster", &["src/lib.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&root, "feat/roster"),
                r#"{"scope":"full","arms":{"security":"skipped"}}"#,
            )
            .unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            assert!(result.message.unwrap_or_default().contains("SECURITY arm"));
        });
    }

    #[test]
    fn run_garbled_marker_content_stays_silent() {
        // #467: untrusted marker content — unparseable JSON degrades to
        // unknown (never a panic, never a nudge); presence carries the allow.
        let (tmp, root) = init_repo_with_origin_and_files("feat/garbled", &["src/lib.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/garbled"), "not json {{{").unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
        });
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
            //
            // The `cd` target is spelled RELATIVE deliberately, so this test
            // pins the newline handling on every platform.
            //
            // `resolve_cd_target` treats a target as absolute only when it
            // starts with `/` — it never consults `looks_absolute`, so a
            // Windows drive path (`C:\…` or `C:/…`, either slash) takes the
            // relative branch and gets joined onto cwd. An absolute-path
            // fixture would therefore resolve to nothing on Windows and the
            // gate would nudge, failing for a reason that has nothing to do
            // with the newline. A relative target goes down the same code path
            // on both platforms, and the bare-path class still has to stop at
            // the newline for it to resolve — which is the property under test.
            let command = "cd ../wt\ngh pr create --title x";
            let input = make_bash_with_cwd(command, primary.to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Allow,
                "a newline-separated `cd` into a marked worktree must satisfy the gate"
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
