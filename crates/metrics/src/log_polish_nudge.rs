//! `PostToolUse:Bash` — when a polish **ship anchor** runs (`gh pr ready`, a
//! non-draft `gh pr create`, or a bare `gh pr merge`), append one line to
//! `<metrics_dir>/polish_nudges.jsonl` recording the nudge-fire and whether
//! `/polish` ran earlier this session.
//!
//! This is the deterministic denominator for the polish-nudge efficacy
//! measurement (claude-configurations#151): every ship anchor *is* a nudged PR
//! (it fires `nudge-polish-before-pr`), so the same origin-aware
//! [`polish_ship_anchor_for_origin`] predicate gates both — a draft create
//! nudges nowhere, so it is logged nowhere either (#297), and a `gh pr merge
//! -R` naming the cwd's OWN repo is a real ship anchor on both sides
//! (cadence-hooks#881), never a denominator gap between the two. Each row
//! carries the anchor **kind**, because a draft-first branch now trips `ready`
//! and again at `merge` (#325) and the two rows would otherwise read as two
//! separate ships; dedup on `(repo, branch)` or split by `anchor` before
//! computing a rate. `polished` is a best-effort transcript scan for a
//! `cadence-forge:polish` Skill invocation earlier in the session — a row with
//! `polished: false` is a deterministic *skip candidate*. Distinguishing a
//! rationalized skip from a legitimate one stays a transcript/prose judgment;
//! this logger only makes the rate queryable without re-mining every transcript.
//!
//! Silent no-op on any failure — never blocks (it is a [`Logger`]).

use crate::common;
use cadence_hooks_core::markers::{polish_marker_present, resolve_ship_target};
use cadence_hooks_core::shell::{
    git_command, merge_anchor_repo_targets, origin_triple, parse_work_dir,
    polish_ship_segments_for_origin,
};
use cadence_hooks_core::transcript::{
    subagent_transcripts_have_polish_run, transcript_has_polish_run,
};
use cadence_hooks_core::{Logger, MetricsInput};
use serde_json::{Value, json};
use std::io::Write;

/// Appends a nudge-fire line to `polish_nudges.jsonl`.
pub struct LogPolishNudge;

impl Logger for LogPolishNudge {
    fn name(&self) -> &str {
        "log-polish-nudge"
    }

    fn run(&self, input: &MetricsInput) {
        let Some(command) = input.command() else {
            return;
        };
        // The denominator is defined as "every PR that fired the nudge", so the
        // gate MUST be the same predicate the nudge uses — origin-aware, so a
        // `gh pr merge -R` naming the cwd's own repo counts here exactly when
        // it nudges (cadence-hooks#881). The `git remote get-url origin` spawn
        // is paid only when `merge_anchor_repo_targets` says a merge segment
        // could still anchor pending that origin match; every other shape
        // (create, ready, a bare merge, an unrelated command) never pays for
        // it. The anchor KIND rides along on the row: a draft-first branch now
        // trips `ready` and again at `merge` (#325), and without the kind
        // those two rows read as two separate ships of the same branch.
        let origin = input
            .cwd
            .as_deref()
            .filter(|_| merge_anchor_repo_targets(command).is_some())
            .map(|cwd| parse_work_dir(command, cwd))
            .and_then(|dir| git_command(&dir, &["remote", "get-url", "origin"]))
            // The same host mapping the #995 resolver applies to every remote
            // (an SSH alias, `ssh.github.com`), so both compare sites agree.
            .and_then(|url| origin_triple(&url));
        // One pass over the segments gives both the anchor kind (the first
        // anchoring segment's, as `polish_ship_anchor_for_origin` reports it)
        // and every segment's target.
        let segments = polish_ship_segments_for_origin(command, origin.as_deref());
        let Some(anchor) = segments.first().map(|segment| segment.anchor) else {
            return;
        };
        // Skip malformed payloads (mirrors the other loggers); session_id is
        // recorded as a JSON value, never used in a path, so this is hygiene.
        if !input
            .session_id
            .as_deref()
            .is_some_and(common::is_safe_session_id)
        {
            return;
        }

        // Did `/polish` run earlier this session? Best-effort — a missing or
        // unreadable transcript yields `false` (an honest "no evidence of
        // polish"), never a panic. Scans the parent transcript *and* this
        // session's subagent transcripts, so a delegated polish run is recorded
        // honestly rather than logged as `polished: false` (#247).
        let polished = input
            .transcript_path
            .as_deref()
            .filter(|p| std::path::Path::new(p).is_file())
            .map(|p| {
                let parent_polished = std::fs::read_to_string(p)
                    .map(|t| transcript_has_polish_run(&t))
                    .unwrap_or(false);
                parent_polished || subagent_transcripts_have_polish_run(std::path::Path::new(p))
            })
            .unwrap_or(false);

        // The branch-scoped marker signal the pre-PR gate actually acts on —
        // the same segments, [`resolve_ship_target`], and
        // [`polish_marker_present`] the gate uses, so the metric can never
        // disagree with the gate (#177). Recorded alongside `polished` (the
        // transcript scan) so scan-vs-marker drift is measurable. The target
        // kind rides along (cadence-hooks#995): a `cannot_check` row is a ship
        // the gate could not look up, which is not the same as a nudged skip.
        let work_dir = input.cwd.as_deref().map(|cwd| parse_work_dir(command, cwd));
        let lookups: Vec<(&'static str, bool)> = segments
            .iter()
            .map(|segment| {
                let target = resolve_ship_target(&segment.target, work_dir.as_deref());
                (target.kind(), polish_marker_present(&target))
            })
            .collect();
        let marker = combine_marker_lookups(&lookups);

        let dir = common::metrics_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join("polish_nudges.jsonl");

        let record = build_polish_nudge_record(
            &common::utc_timestamp(),
            input,
            &common::branch(input.cwd.as_deref()),
            &common::repo_basename(input.cwd.as_deref()),
            polished,
            marker,
            anchor,
        );

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Single `write_all` of record + newline so concurrent appends from
            // other sessions can't interleave (mirrors log_commit).
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// What the gate's marker lookup found: whether a marker exists, and which
/// kind of target it was looked up for (`local`, `cannot_check`, `unknown`).
struct MarkerSignal<'a> {
    present: bool,
    target: &'a str,
}

/// One row for a command whose anchoring segments were each looked up
/// (`(target kind, marker present)` per segment, cadence-hooks#995).
///
/// - `markerPresent` is true only when **every** segment's marker is
///   present. The gate nudges when any segment's is missing, so a row that
///   said `true` there would disagree with the gate (#177).
/// - `markerTarget` is the least-resolved kind across segments:
///   `cannot_check`, then `unknown`, then `local`. A command with one
///   cannot-check ship is not a clean local lookup, so it is not counted as
///   one.
fn combine_marker_lookups(lookups: &[(&'static str, bool)]) -> MarkerSignal<'static> {
    let present = !lookups.is_empty() && lookups.iter().all(|(_, present)| *present);
    let target = ["cannot_check", "unknown"]
        .into_iter()
        .find(|kind| lookups.iter().any(|(k, _)| k == kind))
        .unwrap_or("local");
    MarkerSignal { present, target }
}

/// Build the `polish_nudges.jsonl` record. Pure — no I/O.
fn build_polish_nudge_record(
    ts: &str,
    input: &MetricsInput,
    branch: &str,
    repo: &str,
    polished: bool,
    marker: MarkerSignal<'_>,
    anchor: &str,
) -> Value {
    json!({
        "ts": ts,
        "anchor": anchor,
        "sessionId": input.session_id,
        "transcriptPath": input.transcript_path,
        "branch": branch,
        "repo": repo,
        "polished": polished,
        "markerPresent": marker.present,
        "markerTarget": marker.target,
        "agentId": input.agent_id,
        "parentSessionId": input.parent_session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_log_polish_nudge() {
        assert_eq!(LogPolishNudge.name(), "log-polish-nudge");
    }

    fn sample_input() -> MetricsInput {
        MetricsInput {
            session_id: Some("s1".into()),
            transcript_path: Some("/tmp/t.jsonl".into()),
            agent_id: Some("a1".into()),
            ..Default::default()
        }
    }

    #[test]
    fn record_has_full_schema() {
        let rec = build_polish_nudge_record(
            "2026-06-21T00:00:00Z",
            &sample_input(),
            "feat/x",
            "myrepo",
            false,
            MarkerSignal {
                present: false,
                target: "local",
            },
            "ready",
        );
        assert_eq!(rec["ts"], "2026-06-21T00:00:00Z");
        // The anchor kind is what keeps the ledger interpretable once one
        // branch can trip two anchors (#325) — a row without it cannot be told
        // apart from a second genuine ship of the same branch.
        assert_eq!(rec["anchor"], "ready");
        assert_eq!(rec["sessionId"], "s1");
        assert_eq!(rec["transcriptPath"], "/tmp/t.jsonl");
        assert_eq!(rec["branch"], "feat/x");
        assert_eq!(rec["repo"], "myrepo");
        assert_eq!(rec["polished"], false);
        // The branch-scoped marker signal, recorded alongside `polished`.
        assert_eq!(rec["markerPresent"], false);
        assert_eq!(rec["markerTarget"], "local");
        assert_eq!(rec["agentId"], "a1");
        // Main-thread field absent → null, not omitted.
        assert!(rec["parentSessionId"].is_null());
    }

    #[test]
    fn record_marks_polished_true() {
        let rec = build_polish_nudge_record(
            "ts",
            &sample_input(),
            "feat/x",
            "myrepo",
            true,
            MarkerSignal {
                present: false,
                target: "local",
            },
            "create",
        );
        assert_eq!(rec["polished"], true);
        assert_eq!(rec["markerPresent"], false);
    }

    #[test]
    fn record_marks_marker_present_true() {
        // `markerPresent` serializes both signals independently of `polished`.
        let rec = build_polish_nudge_record(
            "ts",
            &sample_input(),
            "feat/x",
            "myrepo",
            false,
            MarkerSignal {
                present: true,
                target: "local",
            },
            "create",
        );
        assert_eq!(rec["markerPresent"], true);
        assert_eq!(rec["polished"], false);
    }

    #[test]
    fn combine_marker_lookups_reports_the_worst_segment() {
        let one = combine_marker_lookups(&[("local", true)]);
        assert!(one.present);
        assert_eq!(one.target, "local");
        // Any missing marker makes the row a miss, as it makes the gate nudge.
        let mixed = combine_marker_lookups(&[("local", true), ("local", false)]);
        assert!(!mixed.present);
        assert_eq!(mixed.target, "local");
        // The least-resolved kind wins: cannot_check, then unknown, then local.
        let worst =
            combine_marker_lookups(&[("local", true), ("unknown", false), ("cannot_check", false)]);
        assert_eq!(worst.target, "cannot_check");
        assert_eq!(
            combine_marker_lookups(&[("local", true), ("unknown", false)]).target,
            "unknown"
        );
        assert!(!combine_marker_lookups(&[]).present);
    }

    /// Run `f` with `CADENCE_METRICS_DIR` set to `dir`, under the crate's one
    /// env lock (`common::ENV_LOCK`), restoring the variable even if `f`
    /// panics.
    fn with_metrics_dir(dir: &std::path::Path, f: impl FnOnce()) {
        let _guard = common::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test crate-wide
        // via `common::ENV_LOCK`.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        // SAFETY: the same lock is still held.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    fn git_in(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    }

    fn logged_rows(metrics: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(metrics.join("polish_nudges.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn run_logs_the_same_target_the_gate_resolves() {
        // #177 on the logger side (#995): a `--head` ship from `main` whose
        // only marker is for the head's worktree branch must log a present,
        // local marker; a foreign `-R` must log `cannot_check`.
        use cadence_hooks_core::ToolInput;
        use cadence_hooks_core::gitstate::GitState;
        use cadence_hooks_core::markers::{polish_marker, write_marker};
        use cadence_hooks_core::test_builders::with_marker_dir;

        let repo = tempfile::tempdir().unwrap();
        git_in(repo.path(), &["init", "-q", "-b", "main"]);
        git_in(repo.path(), &["config", "user.email", "t@t"]);
        git_in(repo.path(), &["config", "user.name", "t"]);
        git_in(
            repo.path(),
            &["commit", "-q", "--allow-empty", "-m", "init"],
        );
        git_in(
            repo.path(),
            &["remote", "add", "origin", "https://github.com/own/repo.git"],
        );
        git_in(repo.path(), &["branch", "feat/x"]);
        let wt_parent = tempfile::tempdir().unwrap();
        let wt = wt_parent.path().join("wt");
        git_in(
            repo.path(),
            &["worktree", "add", "-q", wt.to_str().unwrap(), "feat/x"],
        );
        let root = GitState::resolve(repo.path())
            .unwrap()
            .git_common_dir
            .to_string_lossy()
            .into_owned();

        let input = |command: &str| MetricsInput {
            session_id: Some("s1".into()),
            cwd: Some(repo.path().to_str().unwrap().to_string()),
            tool_input: Some(ToolInput {
                command: Some(command.into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let metrics = tempfile::tempdir().unwrap();
        let markers = tempfile::tempdir().unwrap();
        with_metrics_dir(metrics.path(), || {
            with_marker_dir(markers.path(), || {
                write_marker(&polish_marker(&root, "feat/x"), "{}").unwrap();
                LogPolishNudge.run(&input("gh pr create --head feat/x -t a"));
                LogPolishNudge.run(&input("gh pr create -R other/r -t a"));
            });
        });

        let rows = logged_rows(metrics.path());
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["markerTarget"], "local");
        assert_eq!(rows[0]["markerPresent"], true);
        assert_eq!(rows[1]["markerTarget"], "cannot_check");
        assert_eq!(rows[1]["markerPresent"], false);
    }

    #[test]
    fn run_logs_an_own_repo_merge_with_an_ssh_alias_origin() {
        // #995 round 2: the logger builds the origin the same way as the
        // gate, so an own-repo `-R` merge with an SSH-alias origin is a
        // logged ship, as it is a nudged one.
        use cadence_hooks_core::ToolInput;
        use cadence_hooks_core::test_builders::with_marker_dir;
        let repo = tempfile::tempdir().unwrap();
        git_in(repo.path(), &["init", "-q", "-b", "feat/x"]);
        git_in(
            repo.path(),
            &["remote", "add", "origin", "git@github-work:own/repo.git"],
        );
        let input = MetricsInput {
            session_id: Some("s1".into()),
            cwd: Some(repo.path().to_str().unwrap().to_string()),
            tool_input: Some(ToolInput {
                command: Some("gh pr merge -R own/repo".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        // The merge resolves a Local target, so keep the marker lookup off
        // the real per-user dir and under the shared lock (#302, #369).
        let metrics = tempfile::tempdir().unwrap();
        let markers = tempfile::tempdir().unwrap();
        with_metrics_dir(metrics.path(), || {
            with_marker_dir(markers.path(), || LogPolishNudge.run(&input));
        });
        let rows = logged_rows(metrics.path());
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["anchor"], "merge");
    }

    #[test]
    fn record_carries_a_cannot_check_target() {
        // #995: a ship the gate could not look up must not read as a nudged
        // skip in the ledger.
        let rec = build_polish_nudge_record(
            "ts",
            &sample_input(),
            "main",
            "myrepo",
            false,
            MarkerSignal {
                present: false,
                target: "cannot_check",
            },
            "create",
        );
        assert_eq!(rec["markerTarget"], "cannot_check");
        assert_eq!(rec["markerPresent"], false);
    }
}
