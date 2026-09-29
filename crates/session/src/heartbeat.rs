//! `session heartbeat` — PostToolUse logger.
//!
//! On every (wired) tool call: refreshes this session's registry file mtime
//! (the liveness signal), updates the last-observed branch, and sweeps stale
//! peer lanes (#155). The triggering command decides whether THIS session
//! deliberately switched branches: only a self-switch moves the drift baseline
//! (`declared_branch`); a peer moving shared HEAD updates the observed branch
//! but leaves the baseline, so the divergence stays detectable at commit time
//! (#70). Implemented as a [`Logger`] — never blocks, never errors.

use crate::guard;
use crate::identity;
use crate::registry;
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::{Logger, MetricsInput};

/// Touch this session's registry file (mtime = heartbeat).
pub struct Heartbeat;

impl Logger for Heartbeat {
    fn name(&self) -> &str {
        "heartbeat"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(sid) = input
            .session_id
            .as_deref()
            .filter(|s| identity::is_safe_session_id(s))
        else {
            return;
        };
        let Some(cwd) = input.cwd.as_deref() else {
            return;
        };
        let Some(dir) = registry::sessions_dir(cwd) else {
            return;
        };
        let branch = git_command(cwd, &["branch", "--show-current"]);
        let stale_secs = registry::stale_minutes() * 60;
        run_heartbeat(
            &dir,
            Some(registry::global_sessions_dir().as_path()),
            sid,
            branch,
            input.command(),
            stale_secs,
        );
    }
}

/// Testable core: upsert the session's record, refreshing mtime and the
/// last-observed branch. `command` is the triggering tool's Bash command, if
/// any; the drift baseline (`declared_branch`) moves only when it is THIS
/// session's own `git checkout`/`switch`.
///
/// The RAW command is handed to [`guard::is_branch_switch`] — NOT pre-stripped
/// of quotes. That parser strips heredoc bodies and requires `git` to lead a
/// segment, so prose like `echo git checkout x` (and heredoc bodies) cannot
/// re-anchor the baseline, while a quoted branch argument (`git checkout
/// 'feat/x'`) is still recognized. Pre-`strip_quotes` would erase the argument
/// and miss a real switch, then falsely flag the next commit as drift (#70).
///
/// A `git -C <other> checkout` switches a DIFFERENT working tree, so it is
/// excluded via [`guard::redirects_to_other_tree`] — re-anchoring cwd's
/// baseline off another repo's switch would suppress drift (#70/R2). This
/// stricter `-C` rule is heartbeat-only; the guard nudge stays permissive.
///
/// After refreshing self, the heartbeat also sweeps stale peers (#155). Before
/// this, `sweep_stale` had exactly one production trigger — SessionStart — so a
/// long-lived session that swept once at its own start never reaped a peer that
/// went stale afterward, and forks/subagents (no SessionStart) never swept at
/// all. Dead lanes then accumulated (17 of 17 unreaped) while `session status`
/// kept classifying them `[STALE]` on demand. The heartbeat is the only
/// high-frequency signal every live session emits, so reaping here prunes dead
/// peers within ~one heartbeat of their crossing the threshold, independent of
/// any fresh SessionStart.
pub fn run_heartbeat(
    dir: &std::path::Path,
    global_dir: Option<&std::path::Path>,
    session_id: &str,
    branch: Option<String>,
    command: Option<&str>,
    stale_secs: u64,
) {
    let is_self_switch = command
        .map(|c| guard::is_branch_switch(c) && !guard::redirects_to_other_tree(c))
        .unwrap_or(false);
    // touch_own FIRST (mirrors `run_start`): writing our record refreshes our
    // own mtime to ~now, so a session that went quiet past the threshold can
    // never sweep its own aged file in the call below (#69). The own-sid
    // exclusion in `sweep_stale` is then defense-in-depth — our file is fresh
    // regardless.
    let _ = registry::touch_own(dir, global_dir, session_id, branch, is_self_switch);
    registry::sweep_stale(dir, stale_secs, session_id, "heartbeat");
    // Sweep the mirror on the same beat, on the DEFAULT threshold rather than
    // this session's override. Without this, a crashed session's mirror record
    // (no SessionEnd fires) is reaped only at some other session's next
    // SessionStart — so the CHANGELOG's parity claim would hold per function
    // and not per call site, which is the kind of gap that reads as covered.
    if let Some(global) = global_dir {
        registry::sweep_stale(
            global,
            registry::default_stale_secs(),
            session_id,
            "heartbeat",
        );
    }
}

/// Throttled liveness refresh for callers already running on every tool call.
///
/// The per-call `session heartbeat` hook was unwired (cameronsjo/cadence-hooks#902)
/// to save a process spawn per tool call. Its liveness job did not move with it:
/// only `session guard`, on git checkout/switch/add/commit, still touched the
/// record, so a session busy with anything else read as stale after
/// [`registry::stale_minutes`] and the `doctor --prune --apply` gate deleted
/// version dirs under it. This restores the refresh without a spawn by riding
/// the `persist-plan-approval` process that already runs on every `PostToolUse`.
///
/// The throttle reads the machine-wide mirror record, whose path needs no git:
/// when it is younger than [`beat_interval_secs`], the call is one `stat` and
/// returns. Only a due beat resolves the repo and runs [`run_heartbeat`]
/// (local and mirror write, branch probe, stale sweep). Returns whether it
/// wrote. Never errors.
///
/// Not covered: a session idle at the prompt (no tool calls), a cwd outside
/// any git repo (no registry dir), and a session with `persist-plan-approval`
/// switched off by `CADENCE_BYPASS=1` or `CADENCE_DISABLE`.
pub fn beat_if_due(session_id: Option<&str>, cwd: Option<&str>) -> bool {
    let Some(sid) = session_id.filter(|s| identity::is_safe_session_id(s)) else {
        return false;
    };
    let Some(cwd) = cwd else {
        return false;
    };
    let global = registry::global_sessions_dir();
    let mirror = global.join(identity::filename(sid));
    if !is_due(&mirror, beat_interval_secs(), std::time::SystemTime::now()) {
        return false;
    }
    let Some(dir) = registry::sessions_dir(cwd) else {
        return false;
    };
    let branch = git_command(cwd, &["branch", "--show-current"]);
    run_heartbeat(
        &dir,
        Some(global.as_path()),
        sid,
        branch,
        None,
        registry::stale_minutes() * 60,
    );
    true
}

/// A third of the smaller of this session's stale window and the default one.
/// Peers sweep the mirror on the default window whatever this session's
/// override, so a beat interval past a third of it could let a peer reap this
/// session's mirror record between beats.
fn beat_interval_secs() -> u64 {
    (registry::stale_minutes() * 60).min(registry::default_stale_secs()) / 3
}

/// Whether the record at `path` needs a refresh: absent, unreadable, dated in
/// the future (readers treat that as maximally stale), or at least
/// `interval_secs` old.
fn is_due(path: &std::path::Path, interval_secs: u64, now: std::time::SystemTime) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
        return true;
    };
    now.duration_since(modified)
        .map_or(true, |age| age.as_secs() >= interval_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SessionRecord;
    use tempfile::TempDir;

    #[test]
    fn heartbeat_non_switch_updates_observed_branch_but_not_baseline() {
        // Reframed from the bug-codifying `heartbeat_refreshes_existing_record`,
        // which asserted the heartbeat overwriting the recorded branch was
        // correct. It is not: a non-switch heartbeat (a peer moved shared HEAD,
        // then this session ran e.g. `cargo build`) must refresh the *observed*
        // branch for display, but must NOT move the drift baseline — otherwise
        // the peer's checkout is absorbed and the divergence vanishes at commit
        // (#70).
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            None,
            "self-session",
            Some("feat/peer-moved".into()),
            Some("cargo build"),
            600,
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.branch.as_deref(),
            Some("feat/peer-moved"),
            "observed branch refreshed for display"
        );
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("main"),
            "drift baseline unchanged on a non-switch — #70 fix"
        );
    }

    #[test]
    fn heartbeat_self_checkout_updates_declared_baseline() {
        // A self-switch (this session's own `git checkout`/`switch`) re-baselines
        // the drift reference to where it now intends to commit, so a later
        // commit on that branch is not falsely flagged as drift.
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            None,
            "self-session",
            Some("feat/mine".into()),
            Some("git checkout -b feat/mine"),
            600,
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(back.branch.as_deref(), Some("feat/mine"));
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("feat/mine"),
            "self-switch re-baselines the drift reference"
        );
    }

    #[test]
    fn heartbeat_quoted_checkout_updates_declared_baseline() {
        // A self-switch whose branch argument is QUOTED is still a real switch.
        // The raw command reaches is_branch_switch (no pre-strip_quotes), so the
        // baseline re-anchors and a later commit on that branch is not falsely
        // flagged as drift (code-review C1).
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            None,
            "self-session",
            Some("feat/mine".into()),
            Some("git checkout 'feat/mine'"),
            600,
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("feat/mine"),
            "quoted-branch switch re-baselines (raw command parsed, arg not stripped)"
        );
    }

    #[test]
    fn heartbeat_prose_git_checkout_does_not_rebaseline() {
        // Security #70/I1: a non-switch command that merely MENTIONS a checkout
        // (a peer moved HEAD, then this session echoed/wrote git-workflow prose)
        // must NOT re-anchor the baseline — otherwise the peer's branch is
        // absorbed and drift vanishes at commit. `git` is not leading here.
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        // Peer moved HEAD to feat/peer; this session only echoes prose about it.
        run_heartbeat(
            tmp.path(),
            None,
            "self-session",
            Some("feat/peer".into()),
            Some("echo run git checkout feat/peer to reproduce"),
            600,
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.branch.as_deref(),
            Some("feat/peer"),
            "observed branch still refreshes for display"
        );
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("main"),
            "baseline unchanged — prose `git checkout` is not a self-switch (#70/I1)"
        );
    }

    #[test]
    fn heartbeat_dash_c_checkout_does_not_rebaseline() {
        // Security #70/R2: `git -C <other> checkout` switches a DIFFERENT working
        // tree. The heartbeat reads cwd's HEAD (here a peer moved it to
        // feat/peer); re-anchoring the baseline off another repo's switch would
        // suppress drift. The baseline must stay put.
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();

        run_heartbeat(
            tmp.path(),
            None,
            "self-session",
            Some("feat/peer".into()),
            Some("git -C ../other-plugin checkout main"),
            600,
        );

        let back = registry::read_own(tmp.path(), "self-session").unwrap();
        assert_eq!(
            back.declared_branch.as_deref(),
            Some("main"),
            "baseline unchanged — a -C switch targets another tree (#70/R2)"
        );
    }

    #[test]
    fn heartbeat_creates_record_when_missing() {
        // A heartbeat firing before `session start` (partial plugin wiring)
        // must still register the session.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("sessions");
        run_heartbeat(
            &dir,
            None,
            "unregistered-session",
            Some("main".into()),
            None,
            600,
        );
        let back = registry::read_own(&dir, "unregistered-session").unwrap();
        // A pre-start heartbeat seeds the drift baseline from live HEAD — this
        // is the invariant run_drift relies on (code-review N4).
        assert_eq!(back.declared_branch.as_deref(), Some("main"));
    }

    #[test]
    fn heartbeat_sweeps_stale_peer_keeps_self_and_live() {
        // #155: the staleness CLASSIFIER (read_peers) and the REAPER
        // (sweep_stale) share one threshold and one mtime helper, so at any
        // instant they cannot disagree on a file — yet 17 of 17 stale lanes
        // accumulated unreaped. The failing predicate was the sweep's TRIGGER
        // SET, not its comparison: sweep_stale fired ONLY from `session start`,
        // never from the high-frequency heartbeat. A long-lived session that
        // swept once at its own start never reaps a peer that goes stale
        // afterward, and forks/subagents never fire SessionStart at all. Wiring
        // the sweep into the heartbeat closes it: any live, active session
        // prunes dead peers within ~one heartbeat of their crossing the
        // threshold. This asserts the TRIGGER — a unit test of sweep_stale
        // alone already passes (`sweep_removes_stale_keeps_fresh`).
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();

        // A peer registers, then ages past the (zero-second) threshold.
        let dead = SessionRecord {
            session_id: "dead-sess".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(dir, &dead).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // A second peer registers fresh (age 0) right before our heartbeat.
        let live = SessionRecord {
            session_id: "live-sess".into(),
            branch: Some("main".into()),
            declared_branch: Some("main".into()),
            ..Default::default()
        };
        registry::write_record(dir, &live).unwrap();

        // Our heartbeat fires with a zero-second staleness threshold: any
        // measurable age (whole seconds) is stale. Reaping fires log_sweep
        // (#259) — scratch-dir-scoped so this doesn't race the sweep-telemetry
        // tests in `registry` over the process-global CADENCE_METRICS_DIR.
        registry::test_metrics_env::with_scratch_metrics_dir(|| {
            run_heartbeat(dir, None, "self-session", Some("main".into()), None, 0);
        });

        assert!(
            registry::find_own(dir, "dead-sess").is_none(),
            "stale peer reaped on heartbeat"
        );
        assert!(
            registry::find_own(dir, "live-sess").is_some(),
            "fresh peer kept"
        );
        assert!(
            registry::find_own(dir, "self-session").is_some(),
            "self registered & kept"
        );
    }

    #[test]
    fn heartbeat_sweeps_all_stale_peers_in_one_pass() {
        // #155 was "17 of 17 unreaped" — many dead lanes accumulating, not one.
        // A single heartbeat must reap EVERY stale peer in one pass, not just
        // the first (sweep_stale loops with no early return; this pins it).
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        for (_name, sid) in [("dead-a", "sess-a"), ("dead-b", "sess-b")] {
            let rec = SessionRecord {
                session_id: sid.into(),
                branch: Some("main".into()),
                declared_branch: Some("main".into()),
                ..Default::default()
            };
            registry::write_record(dir, &rec).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Reaping fires log_sweep (#259) — scratch-dir-scoped, see the
        // sibling test above.
        registry::test_metrics_env::with_scratch_metrics_dir(|| {
            run_heartbeat(dir, None, "self-session", Some("main".into()), None, 0);
        });

        assert!(
            registry::find_own(dir, "sess-a").is_none(),
            "first stale peer reaped"
        );
        assert!(
            registry::find_own(dir, "sess-b").is_none(),
            "second stale peer reaped"
        );
        assert!(
            registry::find_own(dir, "self-session").is_some(),
            "self registered & kept"
        );
    }

    #[test]
    fn heartbeat_makes_stale_record_live_again() {
        let tmp = TempDir::new().unwrap();
        let rec = SessionRecord {
            session_id: "self-session".into(),
            ..Default::default()
        };
        registry::write_record(tmp.path(), &rec).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Before heartbeat: stale at a zero-second threshold (any age counts).
        let peers = registry::read_peers(tmp.path(), "other", 0);
        assert!(peers[0].stale);

        run_heartbeat(tmp.path(), None, "self-session", None, None, 600);

        let peers = registry::read_peers(tmp.path(), "other", 0);
        assert!(!peers[0].stale, "heartbeat resets liveness");
    }

    // ── beat_if_due / is_due (cameronsjo/cadence-hooks#902) ─────────────────

    #[test]
    fn is_due_when_no_record_exists() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(is_due(
            &tmp.path().join("none.json"),
            600,
            std::time::SystemTime::now()
        ));
    }

    #[test]
    fn is_due_only_after_the_interval() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("r.json");
        std::fs::write(&path, "{}").unwrap();
        let now = std::time::SystemTime::now();
        assert!(!is_due(&path, 600, now), "a fresh record is not due");
        let later = now + std::time::Duration::from_secs(600);
        assert!(is_due(&path, 600, later), "at the interval it is due");
    }

    /// Readers treat a future mtime as maximally stale, so it must be due, or
    /// the session stays invisible until a peer reaps its record.
    #[test]
    fn a_future_mtime_is_due() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("r.json");
        std::fs::write(&path, "{}").unwrap();
        let now = std::time::SystemTime::now();
        let past = now - std::time::Duration::from_secs(86_400);
        assert!(is_due(&path, 600, past), "record dated after `now` is due");
    }

    #[test]
    fn the_beat_interval_stays_under_a_third_of_the_default_window() {
        assert!(beat_interval_secs() <= registry::default_stale_secs() / 3);
    }
}
