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
//!   (ADR-0001 fail-open; CP1 never blocks on our own missing data);
//! - a marker older than
//!   [`cadence_hooks_core::markers::POLISH_MARKER_TTL_DAYS`] → treated as
//!   absent → **nudge**, naming the expiry so it doesn't read as a false
//!   positive on a branch that visibly was polished (cadence-hooks#775).
//!
//! - a marker whose content was **read** and names no arm roster at all, on a
//!   branch that touches code → the **unknown-roster nudge** (cadence-hooks#775
//!   item 6): a pass ran and recorded nothing about its arms, so the ask is the
//!   record, not the work. A marker whose content could not be read (degraded
//!   dir, garbled JSON) stays on the presence-alone path — that discrimination
//!   is the whole of item 6;
//! - a marker whose attestation says the security arm ran, but names a model
//!   family that is not Opus, on a branch that touches code → the
//!   **wrong-family nudge** (cadence-hooks#775 item 1). An *unattested*
//!   `security=ran` stays silent — every marker the estate carries today is
//!   unattested, so escalating those is a rollout nag, not a finding.
//!
//! One **annotation** rides the otherwise-silent allow, as exit-0 context
//! rather than an escalation (cadence-hooks#775): a degraded — non-private —
//! marker directory, which silently disables the roster read on that machine.
//!
//! A `head_sha` reader was built and reviewed back out: `record-polish` runs at
//! polish's wrap-up, *before* the operator commits, so HEAD differs from the
//! recorded SHA on every honest polish → commit → ship path, and ancestry
//! cannot discriminate an honest advance from stale cover. SHA binding belongs
//! in the deferred attestation design (item 1 on cadence-hooks#775), where the
//! record side can capture post-polish intent.
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
use cadence_hooks_core::markers::{
    POLISH_MARKER_TTL_DAYS, marker_dir, marker_dir_is_private, polish_marker_present,
    read_polish_marker,
};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerState {
    /// No polish marker for this branch (or repo/branch/cwd unresolved).
    Absent,
    /// A marker exists but its `recorded_at` is past
    /// [`cadence_hooks_core::markers::POLISH_MARKER_TTL_DAYS`] — treated as
    /// unknown, i.e. as if absent, because nothing sweeps the marker family and
    /// a recycled branch name would otherwise inherit its predecessor's record
    /// (cadence-hooks#775).
    Expired,
    /// A marker exists; `security_ran` per the roster/scope, `None` = unknown.
    ///
    /// `security_model` is the attested model family for the security arm
    /// (cadence-hooks#775 item 1), `None` on every unattested marker — which is
    /// every marker the estate carries today, and which stays silent.
    ///
    /// `roster_read` discriminates the two ways `security_ran` reaches `None`
    /// (cadence-hooks#775 item 6): `true` means the marker's content was
    /// genuinely read and simply names no roster — a question the recorder can
    /// answer, so the gate asks; `false` means the content could not be read at
    /// all (a degraded marker dir, garbled JSON, an unreadable file), which
    /// stays on the presence-alone path because there is nothing to ask about.
    Present {
        security_ran: Option<bool>,
        security_model: Option<String>,
        roster_read: bool,
    },
}

/// The one model family that satisfies the security arm's independent-review
/// requirement (Usage Principle U9 — security judgment does not economize).
///
/// Closed on the READ side only: the record side records what actually ran,
/// whatever it was. A recorded family outside this set is what the gate
/// escalates on.
const SATISFYING_SECURITY_FAMILY: &str = "opus";

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
        let present = is_polish_ship_anchor(command) && polish_marker_present(command, cwd);
        let record = if present {
            read_polish_marker(command, cwd)
        } else {
            None
        };
        let marker = match (present, &record) {
            (false, _) => MarkerState::Absent,
            (true, Some(record)) if record.is_expired() => MarkerState::Expired,
            (true, record) => MarkerState::Present {
                security_ran: record.as_ref().and_then(|r| r.security_ran()),
                security_model: record.as_ref().and_then(attested_security_family),
                // Exactly `record.is_some()`: a degraded dir, garbled JSON, and
                // an unreadable file all yield `None` here and stay on the
                // presence-alone path (#775 item 6).
                roster_read: record.is_some(),
            },
        };
        // Advisory annotations ride the otherwise-silent allow — they never
        // escalate a verdict (ADR-0001).
        let mut annotations = Vec::new();
        if present {
            // #775 item 7: a non-private marker dir makes `read_polish_marker`
            // return `None` while presence still passes, so the whole roster
            // mechanism dies with no signal. Only the dir path is named — never
            // its contents.
            if !marker_dir_is_private() {
                annotations.push(degraded_dir_annotation(&marker_dir().display().to_string()));
            }
        }
        // The diff subprocess is ordered LAST and runs only when the roster
        // affirmatively says security was skipped — the common full-polish
        // path (and every absent/unknown case) never pays for it. A timed-out
        // or unspawnable git yields no evidence (`None`), which reads as
        // "does not touch code" → allow (ADR-0001).
        let touches_code = consumes_branch_diff(&marker)
            && cwd.is_some_and(|cwd| {
                let dir = parse_work_dir(command, cwd);
                changed_files(&dir).is_some_and(|files| branch_touches_code(&files))
            });
        decide(command, marker, touches_code, &annotations)
    }
}

/// The attested model family for the **security** arm, or `None` when the
/// marker attests nothing for it (cadence-hooks#775 item 1).
///
/// Every marker the estate carries today is unattested, so `None` is the
/// overwhelming common case and it keeps allowing — the gate escalates only on
/// an affirmative family that fails the requirement.
fn attested_security_family(record: &cadence_hooks_core::markers::PolishRecord) -> Option<String> {
    record.attest.as_ref()?.get("security")?.model.clone()
}

/// Does this marker state consume the branch diff?
///
/// The diff subprocess is the only expensive thing this check does, so it runs
/// only for the states whose verdict actually turns on it — the common
/// full-polish path and every absent/unknown case never pay for it.
fn consumes_branch_diff(marker: &MarkerState) -> bool {
    match marker {
        MarkerState::Present {
            security_ran: Some(false),
            ..
        } => true,
        MarkerState::Present {
            security_ran: Some(true),
            security_model: Some(family),
            ..
        } => family != SATISFYING_SECURITY_FAMILY,
        MarkerState::Present {
            security_ran: None,
            roster_read: true,
            ..
        } => true,
        _ => false,
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
/// - ship anchor + a marker past the TTL → nudge, naming the expiry (#775).
/// - ship anchor + a marker attesting a non-Opus family for a security arm
///   that ran, on a branch that touches code → the wrong-family nudge (#775
///   item 1).
/// - ship anchor + a marker whose content was READ and names no roster, on a
///   branch that touches code → the unknown-roster nudge (#775 item 6).
/// - ship anchor + any other marker (security ran, or unknown because the
///   content could not be read at all) → allow (silent), carrying
///   `annotations` as exit-0 context when the caller resolved any.
///
/// **The match order IS the precedence, and it is total**: absent → expired →
/// security-skipped → wrong-family → unknown-roster → allow (+annotations).
/// Each verdict names a strictly more specific gap than the one after it, so a
/// marker that qualifies for two reports the sharper one.
fn decide(
    command: &str,
    marker: MarkerState,
    branch_touches_code: bool,
    annotations: &[String],
) -> CheckResult {
    if !is_polish_ship_anchor(command) {
        return CheckResult::allow();
    }
    match marker {
        MarkerState::Absent => CheckResult::nudge(nudge_message()),
        MarkerState::Expired => CheckResult::nudge(expired_nudge_message()),
        MarkerState::Present {
            security_ran: Some(false),
            ..
        } if branch_touches_code => CheckResult::nudge(security_nudge_message()),
        // The security arm ran, and the marker names the family that ran it —
        // and it is not one that satisfies the independent-review requirement
        // (#775 item 1). An UNattested `ran` falls through to the allow below:
        // every legacy marker is unattested, so escalating those would be a
        // rollout nag rather than a finding.
        MarkerState::Present {
            security_ran: Some(true),
            security_model: Some(family),
            ..
        } if family != SATISFYING_SECURITY_FAMILY && branch_touches_code => {
            CheckResult::nudge(wrong_family_nudge_message(&family))
        }
        // The marker's content WAS read and names no roster at all (#775 item
        // 6) — a question the recorder can answer, unlike a marker whose
        // content could not be read, which falls through to the allow below.
        MarkerState::Present {
            security_ran: None,
            roster_read: true,
            ..
        } if branch_touches_code => CheckResult::nudge(unknown_roster_nudge_message()),
        // Polish recorded a marker for this branch, and nothing affirmatively
        // says the security arm was skipped on a code branch — allow, silent
        // unless an advisory annotation has something to add.
        MarkerState::Present { .. } if annotations.is_empty() => CheckResult::allow(),
        MarkerState::Present { .. } => CheckResult::nudge(annotations.join(" ")),
    }
}

/// The #775-item-7 annotation: the marker directory failed its `0700`
/// hardening, so marker *content* is not trusted and the arm roster is not
/// consulted at all — presence alone carries the verdict.
///
/// Names the directory path and nothing else: no marker contents, no file
/// listing. Advisory; the gate stays fail-open either way.
fn degraded_dir_annotation(dir: &str) -> String {
    format!(
        "Note: the polish marker directory ({dir}) is not the hardened per-user one, so marker \
         CONTENT is not trusted — the arm roster (e.g. security=skipped) is not being read on \
         this machine, and presence alone decides. Advisory only."
    )
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

/// The #775 TTL nudge: a marker exists for this branch but is older than
/// [`POLISH_MARKER_TTL_DAYS`], so it is treated as no marker at all. The reason
/// is named, because otherwise a nudge on a branch that visibly *was* polished
/// reads as a false positive.
fn expired_nudge_message() -> String {
    format!(
        "The polish marker for this branch is older than {POLISH_MARKER_TTL_DAYS} days, so it no \
         longer counts — nothing sweeps these markers, and a recycled branch name inherits its \
         predecessor's record. {}",
        nudge_message()
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

/// The #775-item-6 nudge: the marker's content was read and names no arm
/// roster at all, on a branch that touches code.
///
/// Distinct from the security nudge (which knows the arm was skipped) and from
/// the no-polish nudge (which knows nothing ran): here a pass *did* run and
/// simply recorded nothing about its arms, so the ask is the record, not the
/// work.
fn unknown_roster_nudge_message() -> String {
    format!(
        "Polish recorded a marker for this branch but no arm roster, so nothing says whether the \
         security arm ran — and this branch's diff vs origin/main touches code. Re-record the \
         roster: `cadence-hooks cadence record-polish --arm security=ran|skipped --arm tests=… \
         --arm simplify=…` (add `--arm-model security=opus` to attest which family ran it). \
         {SCOPE_CLAUSES}"
    )
}

/// The #775-item-1 escalation: the security arm ran and the marker attests
/// *which family ran it*, and that family is not the one the requirement names.
///
/// `family` is charset-bounded by the record side (`[A-Za-z0-9_-]`, ≤64 bytes),
/// so it is safe to echo into this message — that bound is exactly what this
/// interpolation depends on.
fn wrong_family_nudge_message(family: &str) -> String {
    format!(
        "Polish recorded the SECURITY arm as run by model family `{family}` — which does not \
         satisfy the independent Opus-family requirement for security judgment (Usage Principle \
         U9: security judgment does not economize), and this branch's diff vs origin/main touches \
         code. Re-run the arm with an Opus-family reviewer: dispatch \
         `cadence-forge:security-reviewer` against the branch diff, then re-record with \
         `--arm security=ran --arm-model security=opus`. {SCOPE_CLAUSES}"
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
    const PRESENT_UNKNOWN: MarkerState = MarkerState::Present {
        security_ran: None,
        security_model: None,
        roster_read: false,
    };
    const PRESENT_SECURITY_RAN: MarkerState = MarkerState::Present {
        security_ran: Some(true),
        security_model: None,
        roster_read: true,
    };
    const PRESENT_SECURITY_SKIPPED: MarkerState = MarkerState::Present {
        security_ran: Some(false),
        security_model: None,
        roster_read: true,
    };

    #[test]
    fn decide_security_skipped_on_code_branch_nudges_distinctly() {
        // #467 RED: a recorded polish whose roster says the security arm did
        // not run, on a branch touching code, must nudge — with the security
        // message, not the no-polish one.
        let result = decide(
            "gh pr create --title x",
            PRESENT_SECURITY_SKIPPED,
            true,
            &[],
        );
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
        let result = decide(
            "gh pr create --title x",
            PRESENT_SECURITY_SKIPPED,
            false,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_security_ran_allows_regardless_of_code() {
        assert_eq!(
            decide("gh pr create --title x", PRESENT_SECURITY_RAN, true, &[]).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_legacy_roster_less_marker_allows_on_code_branch() {
        // #467 RED: absent roster = UNKNOWN, not skipped — the whole estate
        // carries roster-less markers, and every one must keep allowing even
        // on a code branch.
        let result = decide("gh pr create --title x", PRESENT_UNKNOWN, true, &[]);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_pr_create_with_marker_allows_silently() {
        // A branch-scoped marker present → silent allow. #154 regression: this
        // holds with NO transcript involvement — a slash-command polish that
        // recorded a marker is honored.
        let result = decide("gh pr create --title test", PRESENT_UNKNOWN, false, &[]);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(
            result.message.is_none(),
            "a recorded polish must allow silently, no nag"
        );
    }

    #[test]
    fn decide_pr_create_without_marker_nudges() {
        // #146 RED (pure): no marker → nudge, never block. CP1 is fail-open.
        let result = decide("gh pr create --title x", MarkerState::Absent, false, &[]);
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
            decide("gh pr list", MarkerState::Absent, false, &[]).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("git commit -m x", PRESENT_UNKNOWN, false, &[]).outcome,
            Outcome::Allow
        );
        // A merge that NAMES a PR is excluded — it is the orchestrator shape,
        // run from another cwd, where the branch would mis-resolve (#325). A
        // bare merge is a ship anchor and nudges; pinned just below.
        assert_eq!(
            decide("gh pr merge 12", MarkerState::Absent, false, &[]).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide(
                "gh --repo owner/r pr merge",
                MarkerState::Absent,
                false,
                &[]
            )
            .outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh pr merge --squash", MarkerState::Absent, false, &[]).outcome,
            Outcome::Nudge
        );
        // ...and stays silent once the branch carries a marker.
        assert_eq!(
            decide("gh pr merge --squash", PRESENT_UNKNOWN, false, &[]).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_draft_create_allows_regardless_of_marker() {
        // A `--draft` create is not the ship moment (#297) — an entry-posture
        // draft opens at zero diff, so it must allow even with no marker.
        assert_eq!(
            decide("gh pr create --draft", MarkerState::Absent, false, &[]).outcome,
            Outcome::Allow
        );
        assert_eq!(
            decide("gh pr create -d --title x", MarkerState::Absent, false, &[]).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn decide_pr_ready_routes_like_create() {
        // `gh pr ready` (leaves draft) is the ship anchor: no marker → nudge,
        // marker present → silent allow.
        let nudge = decide("gh pr ready 12", MarkerState::Absent, false, &[]);
        assert_eq!(nudge.outcome, Outcome::Nudge);
        nudge_msg_has_loophole_clauses(&nudge.message.unwrap_or_default());
        let allow = decide("gh pr ready 12", PRESENT_UNKNOWN, false, &[]);
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
    fn run_read_roster_less_marker_nudges_to_record_the_roster_on_code_branch() {
        // SANCTIONED FLIP (#775 item 6). This test was
        // `run_legacy_roster_less_marker_stays_silent_on_code_branch` and
        // encoded the pre-item-6 ruling: a readable roster-less marker allowed
        // silently, because presence alone carried the verdict and #467 could
        // not tell "no roster recorded" from "roster not readable".
        //
        // Item 6 draws that line: the content here IS read, so an absent
        // roster is a question the recorder can answer, and the gate asks.
        // A marker whose content cannot be read (garbled JSON, degraded dir)
        // still stays on the presence-alone path — pinned by
        // `run_garbled_marker_content_stays_silent` and
        // `run_degraded_marker_dir_announces_itself`.
        let (tmp, root) = init_repo_with_origin_and_files("feat/legacy", &["src/main.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(&polish_marker(&root, "feat/legacy"), "{}").unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            assert!(
                result
                    .message
                    .unwrap_or_default()
                    .contains("--arm security="),
                "the nudge must show the record command shape"
            );
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

    // --- #775 item 6: the unknown-roster nudge ---

    /// A marker whose content WAS read and carries no roster — the case item 6
    /// discriminates from a marker whose content could not be read at all.
    const PRESENT_ROSTER_READ_UNKNOWN: MarkerState = MarkerState::Present {
        security_ran: None,
        security_model: None,
        roster_read: true,
    };

    #[test]
    fn decide_read_roster_less_marker_nudges_to_record_the_roster() {
        // #775 item 6 RED: presence alone used to carry the allow, so a marker
        // recorded with no `--arm` at all was indistinguishable from a full
        // pass. Once the content is genuinely READ, an absent roster is a
        // question the recorder can answer — ask for it.
        let result = decide(
            "gh pr create --title x",
            PRESENT_ROSTER_READ_UNKNOWN,
            true,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("--arm security="),
            "the nudge must show the record command shape: {msg}"
        );
        assert!(
            !msg.contains("No polish recorded"),
            "must not present as the no-polish nudge: {msg}"
        );
    }

    #[test]
    fn decide_unread_roster_less_marker_stays_silent_on_a_code_branch() {
        // The discrimination itself: a marker whose content could NOT be read
        // (degraded dir, garbled JSON, unreadable file) stays on the
        // presence-alone path — there is no roster question to ask.
        let result = decide("gh pr create --title x", PRESENT_UNKNOWN, true, &[]);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_read_roster_less_marker_on_docs_only_branch_stays_silent() {
        let result = decide(
            "gh pr create --title x",
            PRESENT_ROSTER_READ_UNKNOWN,
            false,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn run_security_ran_roster_on_code_branch_is_unchanged_by_the_roster_nudge() {
        // Positive control: a marker that DOES carry a roster is untouched by
        // item 6 — silent, as before.
        let (tmp, root) = init_repo_with_origin_and_files("feat/roster-ran", &["src/lib.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&root, "feat/roster-ran"),
                r#"{"scope":"full","arms":{"security":"ran"}}"#,
            )
            .unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(result.message.is_none());
        });
    }

    // --- #775 item 1: the wrong-family gate ---

    /// `security=ran` with an attested model family beside it.
    fn present_security_ran_by(family: &str) -> MarkerState {
        MarkerState::Present {
            security_ran: Some(true),
            security_model: Some(family.to_string()),
            roster_read: true,
        }
    }

    #[test]
    fn decide_non_opus_attested_security_family_nudges_and_names_it() {
        // #775 item 1 RED: the recorded pass names a family that does not
        // satisfy the independent Opus-family requirement (U9) — say so, and
        // name the family, so the reader knows which gap to close.
        let result = decide(
            "gh pr create --title x",
            present_security_ran_by("sonnet"),
            true,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("sonnet"),
            "the nudge must name the recorded family: {msg}"
        );
        assert!(
            msg.contains("Opus"),
            "the nudge must name the requirement it fails: {msg}"
        );
        assert!(
            !msg.contains("No polish recorded"),
            "must not present as the no-polish nudge: {msg}"
        );
    }

    #[test]
    fn decide_opus_attested_security_family_stays_silent() {
        let result = decide(
            "gh pr create --title x",
            present_security_ran_by("opus"),
            true,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_unattested_security_ran_stays_silent() {
        // PINS the no-transitional-nudge ruling (#775): an UNattested
        // `security=ran` is today's behavior and stays silent. Every marker in
        // the estate is unattested, so nudging them all would be a rollout
        // nag, not a finding. Escalating unattested `ran` is a dated follow-up
        // issue, deliberately not this change.
        let result = decide("gh pr create --title x", PRESENT_SECURITY_RAN, true, &[]);
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn decide_non_opus_attested_family_on_docs_only_branch_stays_silent() {
        // Same shape as every other escalation here: no code in the diff, no
        // nudge.
        let result = decide(
            "gh pr create --title x",
            present_security_ran_by("sonnet"),
            false,
            &[],
        );
        assert_eq!(result.outcome, Outcome::Allow);
        assert!(result.message.is_none());
    }

    #[test]
    fn run_non_opus_attested_marker_on_code_branch_fires() {
        // Integration: the attestation rides a real marker, and the gate reads
        // it the same way it reads the roster.
        let (tmp, root) = init_repo_with_origin_and_files("feat/wrong-family", &["src/lib.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&root, "feat/wrong-family"),
                r#"{"scope":"full","arms":{"security":"ran"},
                    "attest":{"security":{"model":"sonnet"}}}"#,
            )
            .unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            assert!(result.message.unwrap_or_default().contains("sonnet"));
        });
    }

    #[test]
    fn run_degraded_marker_dir_does_not_read_the_attestation() {
        // #775 item 7 regression: content is untrusted on a non-private marker
        // dir, so the attestation is not read at all — the degrade annotation
        // is the only message, never the wrong-family nudge.
        let (tmp, root) = init_repo_with_origin_and_files("feat/degraded-attest", &["src/lib.rs"]);
        let base = tempfile::tempdir().unwrap();
        with_marker_dir(base.path(), || {
            let hashed = marker_dir();
            let _ = std::fs::remove_dir_all(&hashed);
            std::fs::write(&hashed, "").unwrap();
            assert!(
                !marker_dir_is_private(),
                "precondition: this must be the degraded path"
            );

            write_marker(
                &polish_marker(&root, "feat/degraded-attest"),
                r#"{"scope":"full","arms":{"security":"ran"},
                    "attest":{"security":{"model":"sonnet"}}}"#,
            )
            .unwrap();
            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let msg = NudgePolishBeforePr.run(&input).message.unwrap_or_default();
            assert!(
                !msg.contains("sonnet"),
                "a degraded dir must not read the attestation: {msg}"
            );
        });
    }

    #[test]
    fn run_ignores_the_diff_digest_field_entirely() {
        // PINS the no-gate-reader ruling (#775 item 2): `diff_digest` is
        // record-side provenance, like `head_sha`. Nothing here reads it, so a
        // marker carrying one — or carrying a hostile-looking one — decides
        // exactly as the same marker without it. Making the gate compare a
        // digest would re-open the head_sha trap: polish records BEFORE the
        // operator commits, so the tree legitimately moves afterward.
        let (tmp, root) = init_repo_with_origin_and_files("feat/digest-blind", &["src/lib.rs"]);
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let path = polish_marker(&root, "feat/digest-blind");
            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());

            write_marker(&path, r#"{"scope":"full","arms":{"security":"ran"}}"#).unwrap();
            let without = NudgePolishBeforePr.run(&input).outcome;

            write_marker(
                &path,
                r#"{"scope":"full","arms":{"security":"ran"},
                    "diff_digest":{"base":"deadbeef","digest":"sha256:0000","files":99}}"#,
            )
            .unwrap();
            assert_eq!(NudgePolishBeforePr.run(&input).outcome, without);

            write_marker(
                &path,
                r#"{"scope":"full","arms":{"security":"ran"},"diff_digest":"skipped"}"#,
            )
            .unwrap();
            assert_eq!(NudgePolishBeforePr.run(&input).outcome, without);
        });
    }

    // --- #775 item 7: annotations ride the allow path ---

    #[test]
    fn decide_annotations_ride_the_allow_path_without_escalating() {
        // An annotation is exit-0 context on an otherwise-silent allow — never
        // the polish nudge, never a block.
        let result = decide(
            "gh pr create --title x",
            PRESENT_UNKNOWN,
            false,
            &["the marker directory is not the hardened per-user one".to_string()],
        );
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("not the hardened per-user one"));
        assert!(
            !msg.contains("No polish recorded"),
            "an annotation must not present as the no-polish nudge: {msg}"
        );
        // Positive control: no annotations → the silent allow, unchanged.
        let silent = decide("gh pr create --title x", PRESENT_UNKNOWN, false, &[]);
        assert_eq!(silent.outcome, Outcome::Allow);
        assert!(silent.message.is_none());
    }

    // --- #775 item 5: marker TTL ---

    #[test]
    fn decide_expired_marker_nudges_and_names_the_ttl() {
        let result = decide("gh pr create --title x", MarkerState::Expired, false, &[]);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("30 days"),
            "the flipped verdict must name its reason: {msg}"
        );
        nudge_msg_has_loophole_clauses(&msg);
    }

    #[test]
    fn run_marker_older_than_the_ttl_nudges() {
        // #775 RED: a recycled branch name inherits its predecessor's marker,
        // and nothing sweeps the family — the TTL is the only expiry.
        let (tmp, root) = init_repo_on_branch("feat/recycled");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&root, "feat/recycled"),
                r#"{"scope":"full","recorded_at":"2020-01-01T00:00:00Z"}"#,
            )
            .unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            assert!(result.message.unwrap_or_default().contains("30 days"));
        });
    }

    #[test]
    fn run_marker_within_the_ttl_stays_silent() {
        // Positive control: a marker stamped now allows silently.
        let (tmp, root) = init_repo_on_branch("feat/fresh-marker");
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            write_marker(
                &polish_marker(&root, "feat/fresh-marker"),
                &format!(
                    r#"{{"scope":"full","recorded_at":"{}"}}"#,
                    cadence_hooks_core::time::utc_timestamp()
                ),
            )
            .unwrap();

            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Allow);
            assert!(result.message.is_none());
        });
    }

    // --- #775 item 7: the roster degrade announces itself ---

    #[test]
    fn run_degraded_marker_dir_announces_itself() {
        // #775 RED: on a non-private marker dir `read_polish_record` returns
        // None while presence still passes, so the roster mechanism dies
        // silently — every gate read degrades with no signal at all.
        let (tmp, root) = init_repo_on_branch("feat/degraded-dir");
        let base = tempfile::tempdir().unwrap();
        // Occupy the per-user hashed subdir with a regular file so
        // `create_dir_all` fails and `marker_dir()` falls open to `base` — a
        // real, writable directory, so the marker itself still lands.
        with_marker_dir(base.path(), || {
            let hashed = marker_dir();
            let _ = std::fs::remove_dir_all(&hashed);
            std::fs::write(&hashed, "").unwrap();
            assert!(
                !marker_dir_is_private(),
                "precondition: this must be the degraded path"
            );

            write_marker(&polish_marker(&root, "feat/degraded-dir"), "{}").unwrap();
            let input = make_bash_with_cwd("gh pr create --title x", tmp.path().to_str().unwrap());
            let result = NudgePolishBeforePr.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap_or_default();
            assert!(
                msg.contains(&marker_dir().display().to_string()),
                "the degrade must name the marker dir: {msg}"
            );
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
