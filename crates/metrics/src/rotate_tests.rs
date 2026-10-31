use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const NOW: i64 = 1_793_000_000; // 2026-10-26T…Z, a fixed clock for retention.
const UUID: &str = "0f8b6a2e-1c3d-4e5f-8a9b-0c1d2e3f4a5b";

fn stamp_at(unix: i64) -> String {
    let ts = jiff::Timestamp::from_second(unix).unwrap();
    common::compact_stamp(&ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn days_ago(days: i64) -> String {
    stamp_at(NOW - days * 86_400)
}

fn denial(i: usize, session: Option<&str>) -> String {
    let session = session.map_or(Value::Null, |s| Value::String(s.to_string()));
    json!({
        "ts": format!("2026-01-{:02}T00:00:{:02}Z", i % 28 + 1, i % 60),
        "hook": format!("h{}", i % 3),
        "repo": "r",
        "decision": "deny",
        "sessionId": session,
        "i": i,
    })
    .to_string()
}

fn write_segment(dir: &Path, stem: &str, stamp: &str, seq: u32, rows: &[String]) -> String {
    let path = common::ledger_segment_path(&dir.join(format!("{stem}.jsonl")), stamp, seq);
    let mut body = rows.join("\n");
    body.push('\n');
    std::fs::write(&path, body).unwrap();
    file_name(&path)
}

fn opts(fault: Fault<'_>) -> RotateOptions<'_> {
    RotateOptions {
        now: NOW,
        deadline: None,
        fault,
    }
}

fn lines_of(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect()
}

/// Every ledger row on disk, raw (no dedupe): each archive member, each
/// segment and live file of the named stems. Sorted, so a row stored twice
/// counts twice.
fn raw_rows(dir: &Path, stems: &[&str]) -> Vec<String> {
    let mut rows = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir.join(ARCHIVE_DIR)) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".jsonl.gz")
                && stems.iter().any(|s| name.starts_with(&format!("{s}.")))
            {
                rows.extend(lines_of(
                    &gunzip_all(&std::fs::read(entry.path()).unwrap()).unwrap(),
                ));
            }
        }
    }
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_ledger = stems.iter().any(|s| {
            name == format!("{s}.jsonl")
                || common::split_segment_name(&name).is_some_and(|(stem, _, _)| stem == *s)
        });
        if is_ledger {
            rows.extend(lines_of(&std::fs::read(entry.path()).unwrap()));
        }
    }
    rows.sort();
    rows
}

fn cat_rows(dir: &Path, ledger: &str, since: Option<&str>, test_rows: bool) -> Vec<String> {
    let mut out = Vec::new();
    crate::ledger_cat::cat(dir, ledger, since, test_rows, &mut out).unwrap();
    lines_of(&out)
}

fn rollup_segments(dir: &Path) -> Vec<String> {
    let mut segs: Vec<String> = common::read_ledger(&dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP))
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["segment"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    segs.sort();
    segs.dedup();
    segs
}

fn temp_files(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for d in [dir.to_path_buf(), dir.join(ARCHIVE_DIR), dir.join("state")] {
        if let Ok(entries) = std::fs::read_dir(&d) {
            found.extend(
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.ends_with(".tmp")),
            );
        }
    }
    found
}

fn fail_at(step: Step) -> impl Fn(Step) -> std::io::Result<()> {
    let fired = AtomicBool::new(false);
    move |s| {
        if s == step && !fired.swap(true, Ordering::SeqCst) {
            Err(std::io::Error::other(format!("injected kill after {s:?}")))
        } else {
            Ok(())
        }
    }
}

// --- pure decisions --------------------------------------------------------

#[test]
fn retention_windows_by_ledger() {
    assert_eq!(retention_days("denials"), 90);
    for stem in NEVER_DROP_LEDGERS {
        assert_eq!(retention_days(stem), 180, "{stem}");
    }
    assert_eq!(retention_days("some-unlisted-ledger"), 180);
    assert!(!past_retention("denials", &days_ago(89), NOW));
    assert!(past_retention("denials", &days_ago(91), NOW));
    assert!(!past_retention("commits", &days_ago(179), NOW));
    assert!(past_retention("commits", &days_ago(181), NOW));
    assert!(!past_retention("denials", "not-a-stamp", NOW));
}

#[test]
fn archive_names_follow_the_segment_month() {
    assert_eq!(
        archive_name("denials", "20260103T000000Z"),
        "denials.2026-01.jsonl.gz"
    );
    assert_eq!(
        archive_month("denials", "denials.2026-01.jsonl.gz").as_deref(),
        Some("2026-01")
    );
    assert_eq!(archive_month("denials", TESTROWS_ARCHIVE), None);
    assert_eq!(
        archive_month("denials", "plan-links.2026-01.jsonl.gz"),
        None
    );
}

#[test]
fn test_rows_are_rows_without_a_uuid_session() {
    assert!(!is_test_row(&denial(1, Some(UUID))));
    assert!(!is_test_row(&denial(1, Some(&UUID.to_uppercase()))));
    assert!(is_test_row(&denial(1, Some("sess-1"))));
    assert!(is_test_row(&denial(1, None)));
    assert!(is_test_row(r#"{"hook":"h"}"#));
    assert!(!is_test_row("not json"), "an unreadable line is kept");
}

#[test]
fn rollup_counts_by_day_hook_repo_decision() {
    let rows = [
        r#"{"ts":"2026-01-01T01:00:00Z","hook":"a","repo":"r","decision":"deny"}"#,
        r#"{"ts":"2026-01-01T02:00:00Z","hook":"a","repo":"r","decision":"deny"}"#,
        r#"{"ts":"2026-01-02T01:00:00Z","hook":"a","repo":"r","decision":"ask"}"#,
        "garbage",
    ]
    .join("\n");
    let out = denial_rollup_rows(rows.as_bytes(), "denials.x.jsonl");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0]["day"], "2026-01-01");
    assert_eq!(out[0]["count"], 2);
    assert_eq!(out[1]["decision"], "ask");
    assert!(out.iter().all(|r| r["segment"] == "denials.x.jsonl"));
}

#[test]
fn gzip_members_round_trip_and_concatenate() {
    let a = gzip_member(b"one\ntwo\n").unwrap();
    let b = gzip_member(b"three\n").unwrap();
    let empty = gzip_member(b"").unwrap();
    let joined = [a, empty, b].concat();
    assert_eq!(gunzip_all(&joined).unwrap(), b"one\ntwo\nthree\n");
}

// --- archive run -----------------------------------------------------------

#[test]
fn retention_boundaries_archive_only_segments_past_their_window() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut expect_archived = Vec::new();
    let mut expect_kept = Vec::new();
    for (stem, window) in [("denials", 90), ("commits", 180), ("skills", 180)] {
        let rows = vec![denial(1, Some(UUID))];
        expect_kept.push(write_segment(dir, stem, &days_ago(window - 1), 0, &rows));
        expect_archived.push(write_segment(dir, stem, &days_ago(window + 1), 0, &rows));
    }
    let before = raw_rows(dir, &["denials", "commits", "skills"]);
    let report = rotate(dir, &opts(&no_fault)).unwrap();
    let mut archived: Vec<String> = report.archived.iter().map(|(s, _, _)| s.clone()).collect();
    archived.sort();
    expect_archived.sort();
    assert_eq!(archived, expect_archived);
    for name in &expect_kept {
        assert!(dir.join(name).is_file(), "{name} is inside its window");
    }
    for name in &expect_archived {
        assert!(!dir.join(name).exists(), "{name} moved to the archive");
    }
    assert_eq!(raw_rows(dir, &["denials", "commits", "skills"]), before);
    assert!(dir.join("state").join(LAST_SUCCESS_FILE).is_file());
    assert!(dir.join("state").join(MANIFEST_FILE).metadata().is_err());
}

#[test]
fn a_second_run_is_a_no_op() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    for seq in 0..3 {
        let rows: Vec<String> = (0..5)
            .map(|i| denial(i + seq as usize * 10, Some(UUID)))
            .collect();
        write_segment(dir, "denials", &days_ago(120), seq, &rows);
    }
    let before = raw_rows(dir, &["denials"]);
    let first = rotate(dir, &opts(&no_fault)).unwrap();
    assert_eq!(first.archived.len(), 3);
    let archive = std::fs::read(
        dir.join(ARCHIVE_DIR)
            .join(archive_name("denials", &days_ago(120))),
    )
    .unwrap();
    let rollup = std::fs::read(dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP)).unwrap();

    let second = rotate(dir, &opts(&no_fault)).unwrap();
    assert!(second.archived.is_empty());
    assert!(!second.recovered);
    assert_eq!(raw_rows(dir, &["denials"]), before);
    assert_eq!(
        std::fs::read(
            dir.join(ARCHIVE_DIR)
                .join(archive_name("denials", &days_ago(120)))
        )
        .unwrap(),
        archive
    );
    assert_eq!(
        std::fs::read(dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP)).unwrap(),
        rollup
    );
}

/// A kill after each manifest step, then a clean run: every row ends up
/// stored exactly once, every segment is rolled up exactly once, and nothing
/// is left half done.
#[test]
fn a_kill_at_each_step_loses_and_duplicates_nothing() {
    for step in [
        Step::AfterRollup,
        Step::AfterManifest,
        Step::AfterArchiveTemp,
        Step::AfterArchiveRename,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let mut names = Vec::new();
        for seq in 0..2 {
            let rows: Vec<String> = (0..4).map(|i| denial(i + seq * 10, Some(UUID))).collect();
            names.push(write_segment(
                dir,
                "denials",
                &days_ago(100),
                seq as u32,
                &rows,
            ));
        }
        let before = raw_rows(dir, &["denials"]);
        let fault = fail_at(step);
        assert!(
            rotate(dir, &opts(&fault)).is_err(),
            "{step:?}: the kill surfaces"
        );
        assert!(
            !dir.join("state").join(LAST_SUCCESS_FILE).exists(),
            "{step:?}: no success marker after a failed run"
        );
        // While the manifest is pending, `cat` still prints each row once.
        let mut cat = cat_rows(dir, "denials", None, false);
        cat.sort();
        assert_eq!(cat, before, "{step:?}: cat dedupes the half-done move");

        let report = rotate(dir, &opts(&no_fault)).unwrap();
        assert_eq!(
            raw_rows(dir, &["denials"]),
            before,
            "{step:?}: row multiset"
        );
        assert_eq!(
            rollup_segments(dir),
            names,
            "{step:?}: each segment rolled up once"
        );
        let rollup_total: u64 = common::read_ledger(&dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP))
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["count"]
                    .as_u64()
                    .unwrap()
            })
            .sum();
        assert_eq!(rollup_total, 8, "{step:?}: rollup counts each row once");
        assert!(names.iter().all(|n| !dir.join(n).exists()), "{step:?}");
        assert!(
            dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
            "{step:?}"
        );
        assert!(
            temp_files(dir).is_empty(),
            "{step:?}: {:?}",
            temp_files(dir)
        );
        let expect_recovered = !matches!(step, Step::AfterRollup);
        assert_eq!(report.recovered, expect_recovered, "{step:?}");
    }
}

#[test]
fn the_time_budget_stops_between_segments_and_withholds_the_success_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let report = rotate(
        dir,
        &RotateOptions {
            now: NOW,
            deadline: Some(Instant::now()),
            fault: &no_fault,
        },
    )
    .unwrap();
    assert!(report.partial);
    assert!(report.archived.is_empty());
    assert!(!dir.join("state").join(LAST_SUCCESS_FILE).exists());
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn a_held_lock_skips_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let name = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    ensure_private_dir(&dir.join("state")).unwrap();
    let _held = try_lock(&dir.join("state")).unwrap().unwrap();
    let report = rotate(dir, &opts(&no_fault)).unwrap();
    assert!(report.skipped);
    assert!(dir.join(&name).is_file());
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn a_failure_is_a_failopen_row_and_a_non_zero_exit() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let outside = tempfile::tempdir().unwrap();
    write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), dir.join(ARCHIVE_DIR)).unwrap();
    assert_eq!(run_rotate_cli(dir), 1);
    let failopen = std::fs::read_to_string(dir.join("failopen.jsonl")).unwrap();
    let row: Value = serde_json::from_str(failopen.lines().next().unwrap()).unwrap();
    assert_eq!(row["reason"], FAILOPEN_REASON);
    assert_eq!(row["subcommand"], "rotate");
    assert_eq!(
        std::fs::read_dir(outside.path()).unwrap().count(),
        0,
        "nothing written through the symlinked archive dir"
    );
}

#[test]
fn a_concurrent_appender_during_rotate_loses_no_row() {
    let _guard = common::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    for seq in 0..20 {
        let rows: Vec<String> = (0..50).map(|i| denial(i + seq * 100, Some(UUID))).collect();
        write_segment(&dir, "denials", &days_ago(200), seq as u32, &rows);
    }
    let before = raw_rows(&dir, &["denials"]);
    // SAFETY: serialized against every other env-mutating test crate-wide via `common::ENV_LOCK`.
    unsafe { std::env::set_var("CADENCE_METRICS_DIR", &dir) };
    let appended = append_concurrently(&dir, || {
        let report = rotate(&dir, &opts(&no_fault)).unwrap();
        assert_eq!(report.archived.len(), 20);
    });
    // SAFETY: as above.
    unsafe { std::env::remove_var("CADENCE_METRICS_DIR") };
    let mut expect = before;
    expect.extend(appended);
    expect.sort();
    assert_eq!(raw_rows(&dir, &["denials"]), expect);
}

/// Append denial rows through the real `log_denial` path from two threads
/// while `during` runs, half from a UUID session and half from a test session.
/// Returns every appended line. The caller holds `ENV_LOCK` with
/// `CADENCE_METRICS_DIR` pointing at `dir`.
fn append_concurrently(dir: &Path, during: impl FnOnce()) -> Vec<String> {
    use cadence_hooks_core::{HookEvent, HookInput, Outcome};
    let stop = Arc::new(AtomicBool::new(false));
    let written = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = [UUID, "sess-test"]
        .into_iter()
        .map(|session| {
            let stop = Arc::clone(&stop);
            let written = Arc::clone(&written);
            std::thread::spawn(move || {
                let input = HookInput {
                    session_id: Some(session.to_string()),
                    cwd: Some("/".into()),
                    ..Default::default()
                };
                let mut n = 0;
                while !stop.load(Ordering::SeqCst) || n < 5 {
                    crate::log_denial::log_denial(
                        &format!("appender-{n}"),
                        HookEvent::PreToolUse,
                        &input,
                        &[Outcome::Block],
                    );
                    n += 1;
                    written.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    while written.load(Ordering::SeqCst) < 4 {
        std::thread::yield_now();
    }
    during();
    stop.store(true, Ordering::SeqCst);
    for h in handles {
        h.join().unwrap();
    }
    // Everything the appenders wrote carries an `appender-` hook name; read
    // it back from wherever it landed.
    let all = raw_rows(dir, &["denials"]);
    let rows: Vec<String> = all
        .into_iter()
        .filter(|l| l.contains("\"appender-"))
        .collect();
    assert_eq!(
        rows.len(),
        written.load(Ordering::SeqCst),
        "every append is on disk once"
    );
    rows
}

// --- session-state sweep ---------------------------------------------------

#[cfg(unix)]
fn age(path: &Path, days: u64) {
    let t =
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(NOW).unwrap() - days * 86_400);
    let file = std::fs::File::open(path).unwrap();
    file.set_modified(t).unwrap();
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn stale_session_dirs_are_swept_and_symlinks_are_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("keep"), "x").unwrap();
    age(&victim.join("keep"), 30);
    age(&victim, 30);

    // Stale and fresh real session dirs.
    for (parent, session, days) in [
        ("subagents", "old1", 8),
        ("bypass", "old2", 30),
        ("commits", "old3", 9),
        ("subagents", "fresh", 6),
    ] {
        let d = state.join(parent).join(session);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("m"), "x").unwrap();
        age(&d.join("m"), days);
        age(&d, days);
    }
    // A stale dir with one fresh marker inside is not stale.
    let mixed = state.join("bypass").join("mixed");
    std::fs::create_dir_all(&mixed).unwrap();
    std::fs::write(mixed.join("old"), "x").unwrap();
    std::fs::write(mixed.join("new"), "x").unwrap();
    age(&mixed.join("old"), 30);
    age(&mixed, 30);
    // An unsafe name is never touched.
    let unsafe_dir = state.join("bypass").join("bad.name");
    std::fs::create_dir_all(&unsafe_dir).unwrap();
    age(&unsafe_dir, 30);
    #[cfg(unix)]
    {
        // A symlinked session dir and a symlinked parent point outside.
        std::os::unix::fs::symlink(&victim, state.join("bypass").join("linked")).unwrap();
        let other = tempfile::tempdir().unwrap();
        let old = other.path().join("old9");
        std::fs::create_dir_all(&old).unwrap();
        age(&old, 30);
        std::fs::remove_dir_all(state.join("commits")).unwrap();
        std::os::unix::fs::symlink(other.path(), state.join("commits")).unwrap();
        let (removed, errors) = sweep_session_state(&state, NOW);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(removed, 2, "old1 and old2");
        assert!(old.is_dir(), "a symlinked parent is not walked");
        assert!(
            victim.join("keep").is_file(),
            "a symlinked session dir is not followed"
        );
        assert!(
            state
                .join("bypass")
                .join("linked")
                .symlink_metadata()
                .is_ok()
        );
    }
    assert!(!state.join("subagents/old1").exists());
    assert!(!state.join("bypass/old2").exists());
    assert!(state.join("subagents/fresh").is_dir());
    assert!(mixed.is_dir());
    assert!(unsafe_dir.is_dir());
}

// --- modes -----------------------------------------------------------------

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
#[test]
fn created_files_are_0600_and_dirs_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some("t"))],
    );
    rotate(dir, &opts(&no_fault)).unwrap();
    std::fs::write(dir.join("denials.jsonl"), format!("{}\n", denial(3, None))).unwrap();
    let q = quarantine(
        dir,
        &QuarantineOptions {
            dry_run: false,
            grace: Duration::ZERO,
            fault: &no_fault,
        },
    )
    .unwrap();
    for d in [ARCHIVE_DIR, ROLLUPS_DIR, "state"] {
        assert_eq!(mode(&dir.join(d)), 0o700, "{d}");
    }
    let files = [
        dir.join(ARCHIVE_DIR)
            .join(archive_name("denials", &days_ago(100))),
        dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE),
        dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP),
        dir.join("state").join(LOCK_FILE),
        dir.join("state").join(LAST_SUCCESS_FILE),
        dir.join("state").join(q.record.unwrap()),
    ];
    for f in files {
        assert_eq!(mode(&f), 0o600, "{}", f.display());
    }
}

// --- daily SessionStart run ------------------------------------------------

#[test]
fn the_session_start_run_happens_once_a_day() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    run_daily_at_session_start(dir);
    let marker = dir.join("state").join(DAILY_MARKER_FILE);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        common::today_utc()
    );
    assert!(dir.join("state").join(LAST_SUCCESS_FILE).is_file());
    std::fs::remove_file(dir.join("state").join(LAST_SUCCESS_FILE)).unwrap();
    run_daily_at_session_start(dir);
    assert!(
        !dir.join("state").join(LAST_SUCCESS_FILE).exists(),
        "a second SessionStart the same day does not run again"
    );
}

#[test]
fn the_session_start_run_fails_open() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(dir.join(ARCHIVE_DIR), "a file where the archive dir goes").unwrap();
    write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    run_daily_at_session_start(dir);
    let failopen = std::fs::read_to_string(dir.join("failopen.jsonl")).unwrap();
    assert!(failopen.contains(FAILOPEN_REASON), "{failopen}");
}

// --- cat -------------------------------------------------------------------

#[test]
fn cat_prints_archives_then_segments_then_live() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // Two months archived out of order of creation.
    write_segment(
        dir,
        "denials",
        "20260215T000000Z",
        0,
        &["{\"n\":2}".to_string()],
    );
    write_segment(
        dir,
        "denials",
        "20260115T000000Z",
        0,
        &["{\"n\":1}".to_string()],
    );
    rotate(dir, &opts(&no_fault)).unwrap();
    write_segment(dir, "denials", &days_ago(10), 0, &["{\"n\":3}".to_string()]);
    write_segment(dir, "denials", &days_ago(5), 0, &["{\"n\":4}".to_string()]);
    std::fs::write(dir.join("denials.jsonl"), "{\"n\":5}").unwrap(); // no trailing newline
    // Another ledger's archive and the test-row archive stay out.
    write_segment(
        dir,
        "commits",
        "20260115T000000Z",
        0,
        &["{\"c\":1}".to_string()],
    );
    rotate(dir, &opts(&no_fault)).unwrap();
    assert_eq!(
        cat_rows(dir, "denials", None, false),
        [
            "{\"n\":1}",
            "{\"n\":2}",
            "{\"n\":3}",
            "{\"n\":4}",
            "{\"n\":5}"
        ]
    );
    assert_eq!(cat_rows(dir, "commits", None, false), ["{\"c\":1}"]);
}

#[test]
fn cat_since_filters_rows_by_ts() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write_segment(
        dir,
        "denials",
        "20260115T000000Z",
        0,
        &[
            r#"{"ts":"2026-01-10T00:00:00Z","n":1}"#.to_string(),
            r#"{"ts":"2026-01-14T00:00:00Z","n":2}"#.to_string(),
        ],
    );
    std::fs::write(
        dir.join("denials.jsonl"),
        "{\"n\":\"no ts\"}\n{\"ts\":\"2026-02-01T00:00:00Z\",\"n\":3}\n",
    )
    .unwrap();
    let since = crate::ledger_cat::parse_since("2026-01-12").unwrap();
    assert_eq!(
        cat_rows(dir, "denials", Some(&since), false),
        [
            r#"{"ts":"2026-01-14T00:00:00Z","n":2}"#,
            r#"{"ts":"2026-02-01T00:00:00Z","n":3}"#
        ]
    );
}

// --- quarantine ------------------------------------------------------------

#[cfg(unix)]
fn qopts(dry_run: bool, fault: Fault<'_>) -> QuarantineOptions<'_> {
    QuarantineOptions {
        dry_run,
        grace: Duration::from_millis(20),
        fault,
    }
}

/// Two segments and a live file, mixing UUID and test rows.
#[cfg(unix)]
fn seed_quarantine(dir: &Path) -> Vec<String> {
    write_segment(
        dir,
        "denials",
        &days_ago(20),
        0,
        &[
            denial(1, Some(UUID)),
            denial(2, Some("sess-1")),
            denial(3, None),
        ],
    );
    write_segment(
        dir,
        "denials",
        &days_ago(10),
        0,
        &[denial(4, Some(UUID)), denial(5, Some(UUID))],
    );
    std::fs::write(
        dir.join("denials.jsonl"),
        format!("{}\n{}\n", denial(6, Some("t")), denial(7, Some(UUID))),
    )
    .unwrap();
    raw_rows(dir, &["denials"])
}

#[cfg(unix)]
fn no_test_rows_outside_the_archive(dir: &Path) -> bool {
    let live = dir.join("denials.jsonl");
    common::read_ledger(&live)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.contains("\"appender-"))
        .all(|l| !is_test_row(l))
}

#[cfg(unix)]
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(p.display().to_string(), std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn quarantine_dry_run_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    seed_quarantine(dir);
    let before = snapshot(dir);
    let report = quarantine(dir, &qopts(true, &no_fault)).unwrap();
    assert_eq!(report.files.iter().map(|f| f.test_rows).sum::<u64>(), 3);
    assert_eq!(snapshot(dir), before);
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn quarantine_moves_test_rows_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let before = seed_quarantine(dir);
    let segments_before = common::ledger_segments(&dir.join("denials.jsonl"));
    let first = quarantine(dir, &qopts(false, &no_fault)).unwrap();
    assert_eq!(first.files.iter().map(|f| f.test_rows).sum::<u64>(), 3);
    assert!(
        first.live_moved_to.is_some(),
        "the live file held a test row"
    );
    assert!(
        !dir.join("denials.jsonl").exists(),
        "no live file is rewritten; it moved aside"
    );
    assert!(no_test_rows_outside_the_archive(dir));
    assert_eq!(raw_rows(dir, &["denials"]), before);
    // Kept rows keep their segment names, so stamp order is unchanged.
    for seg in &segments_before {
        assert!(seg.is_file(), "{}", seg.display());
    }
    let record: Value = serde_json::from_slice(
        &std::fs::read(dir.join("state").join(first.record.as_ref().unwrap())).unwrap(),
    )
    .unwrap();
    assert!(record["host"].as_str().is_some_and(|h| !h.is_empty()));
    assert!(
        record["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["sha256"].as_str().unwrap().len() == 64)
    );

    let archive = std::fs::read(dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE)).unwrap();
    let second = quarantine(dir, &qopts(false, &no_fault)).unwrap();
    assert_eq!(second.files.iter().map(|f| f.test_rows).sum::<u64>(), 0);
    assert!(second.record.is_none());
    assert_eq!(
        std::fs::read(dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE)).unwrap(),
        archive
    );
    assert_eq!(raw_rows(dir, &["denials"]), before);
    // `cat` hides the test rows unless asked.
    assert_eq!(cat_rows(dir, "denials", None, false).len(), 4);
    assert_eq!(cat_rows(dir, "denials", None, true).len(), 7);
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn a_kill_at_each_quarantine_step_loses_and_duplicates_nothing() {
    for step in [
        Step::AfterManifest,
        Step::AfterArchiveTemp,
        Step::AfterArchiveRename,
        Step::AfterKeptTemp,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let before = seed_quarantine(dir);
        let fault = fail_at(step);
        assert!(quarantine(dir, &qopts(false, &fault)).is_err(), "{step:?}");
        let mut cat = cat_rows(dir, "denials", None, true);
        cat.sort();
        assert_eq!(cat, before, "{step:?}: cat prints each row once mid-move");

        quarantine(dir, &qopts(false, &no_fault)).unwrap();
        assert_eq!(
            raw_rows(dir, &["denials"]),
            before,
            "{step:?}: row multiset"
        );
        assert!(no_test_rows_outside_the_archive(dir), "{step:?}");
        assert!(
            dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
            "{step:?}"
        );
        assert!(
            temp_files(dir).is_empty(),
            "{step:?}: {:?}",
            temp_files(dir)
        );
    }
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn a_concurrent_appender_during_quarantine_loses_no_row() {
    let _guard = common::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let before = seed_quarantine(&dir);
    // SAFETY: serialized against every other env-mutating test crate-wide via `common::ENV_LOCK`.
    unsafe { std::env::set_var("CADENCE_METRICS_DIR", &dir) };
    let appended = append_concurrently(&dir, || {
        quarantine(&dir, &qopts(false, &no_fault)).unwrap();
    });
    // SAFETY: as above.
    unsafe { std::env::remove_var("CADENCE_METRICS_DIR") };
    let mut expect = before;
    expect.extend(appended);
    expect.sort();
    assert_eq!(raw_rows(&dir, &["denials"]), expect);
    assert!(no_test_rows_outside_the_archive(&dir));
}

// Unix only: needs flock, symlinks, or the live-file move.
#[cfg(unix)]
#[test]
fn a_late_append_into_the_quarantined_segment_is_kept() {
    // The append lands after the read: recovery keeps it after the kept rows.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let name = write_segment(
        dir,
        "denials",
        &days_ago(5),
        0,
        &[denial(1, Some(UUID)), denial(2, Some("t"))],
    );
    let late = denial(3, Some(UUID));
    let path = dir.join(&name);
    let fault = |s: Step| {
        if s == Step::AfterArchiveRename {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path)?;
            f.write_all(format!("{late}\n").as_bytes())?;
        }
        Ok(())
    };
    let mut before = vec![denial(1, Some(UUID)), denial(2, Some("t")), late.clone()];
    before.sort();
    quarantine(dir, &qopts(false, &fault)).unwrap();
    assert_eq!(raw_rows(dir, &["denials"]), before);
    assert_eq!(
        lines_of(&std::fs::read(&path).unwrap()),
        [denial(1, Some(UUID)), late]
    );
}
