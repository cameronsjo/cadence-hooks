use super::*;
use std::collections::BTreeSet;
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

/// Mark `dir` as quarantined, so `denials` segments may be archived (the
/// gate itself is tested in `denials_wait_for_the_quarantine`).
fn quarantined(dir: &Path) {
    ensure_private_dir(&dir.join("state")).unwrap();
    std::fs::write(dir.join("state").join("quarantine-2000-01-01.json"), "{}").unwrap();
}

fn opts(fault: Fault<'_>) -> RotateOptions<'_> {
    RotateOptions {
        now: NOW,
        deadline: None,
        max_segment_bytes: None,
        fault,
    }
}

/// One clean run that must not skip: a skipped run would make every later
/// assertion name the wrong property.
fn run_ok(dir: &Path) -> RotateReport {
    let report = rotate(dir, &opts(&no_fault)).unwrap();
    assert!(!report.skipped, "expected a run, found the lock held");
    report
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
    fail_at_nth(step, 1)
}

/// Fail at the `nth` time `step` is reached (1-based), once.
fn fail_at_nth(step: Step, nth: usize) -> impl Fn(Step) -> std::io::Result<()> {
    let seen = AtomicUsize::new(0);
    move |s| {
        if s == step && seen.fetch_add(1, Ordering::SeqCst) + 1 == nth {
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
    let out = denial_rollup_rows(rows.as_bytes(), "denials.x.jsonl", "abc", 7);
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
    quarantined(dir);
    let mut expect_archived = Vec::new();
    let mut expect_kept = Vec::new();
    for (stem, window) in [("denials", 90), ("commits", 180), ("skills", 180)] {
        let rows = vec![denial(1, Some(UUID))];
        expect_kept.push(write_segment(dir, stem, &days_ago(window - 1), 0, &rows));
        expect_archived.push(write_segment(dir, stem, &days_ago(window + 1), 0, &rows));
    }
    let before = raw_rows(dir, &["denials", "commits", "skills"]);
    let report = run_ok(dir);
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
    quarantined(dir);
    for seq in 0..3 {
        let rows: Vec<String> = (0..5)
            .map(|i| denial(i + seq as usize * 10, Some(UUID)))
            .collect();
        write_segment(dir, "denials", &days_ago(120), seq, &rows);
    }
    let before = raw_rows(dir, &["denials"]);
    let first = run_ok(dir);
    assert_eq!(first.archived.len(), 3);
    let archive = std::fs::read(
        dir.join(ARCHIVE_DIR)
            .join(archive_name("denials", &days_ago(120))),
    )
    .unwrap();
    let rollup = std::fs::read(dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP)).unwrap();

    let second = run_ok(dir);
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
    // `nth` 2 kills the move of the second segment of the same month, so the
    // archive already holds a member (`archive_len_before > 0`).
    let cases = [
        Step::AfterRollup,
        Step::AfterManifest,
        Step::AfterArchiveTemp,
        Step::AfterArchiveRename,
        Step::AfterSourceDone,
    ]
    .into_iter()
    .flat_map(|step| [(step, 1), (step, 2)]);
    for (step, nth) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        quarantined(dir);
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
        let fault = fail_at_nth(step, nth);
        assert!(
            rotate(dir, &opts(&fault)).is_err(),
            "{step:?}: the kill surfaces"
        );
        if nth == 2 {
            let len = std::fs::metadata(
                dir.join(ARCHIVE_DIR)
                    .join(archive_name("denials", &days_ago(100))),
            )
            .unwrap()
            .len();
            assert!(len > 0, "{step:?}: the first segment is already archived");
        }
        assert!(
            !dir.join("state").join(LAST_SUCCESS_FILE).exists(),
            "{step:?}: no success marker after a failed run"
        );
        // While the manifest is pending, `cat` still prints each row once.
        let mut cat = cat_rows(dir, "denials", None, false);
        cat.sort();
        assert_eq!(cat, before, "{step:?}: cat dedupes the half-done move");

        let report = run_ok(dir);
        assert_eq!(
            raw_rows(dir, &["denials"]),
            before,
            "{step:?} #{nth}: row multiset"
        );
        assert_eq!(
            rollup_segments(dir),
            names,
            "{step:?} #{nth}: each segment rolled up once"
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
    quarantined(dir);
    write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let report = rotate(
        dir,
        &RotateOptions {
            now: NOW,
            deadline: Some(Instant::now()),
            max_segment_bytes: None,
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
    quarantined(dir);
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
    quarantined(dir);
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
    quarantined(&dir);
    for seq in 0..20 {
        let rows: Vec<String> = (0..50).map(|i| denial(i + seq * 100, Some(UUID))).collect();
        write_segment(&dir, "denials", &days_ago(200), seq as u32, &rows);
    }
    let before = raw_rows(&dir, &["denials"]);
    // SAFETY: serialized against every other env-mutating test crate-wide via `common::ENV_LOCK`.
    unsafe { std::env::set_var("CADENCE_METRICS_DIR", &dir) };
    let appended = append_concurrently(&dir, || {
        let report = run_ok(&dir);
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
    quarantined(dir);
    write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some("t"))],
    );
    run_ok(dir);
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
    quarantined(dir);
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
    quarantined(dir);
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
    quarantined(dir);
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
    run_ok(dir);
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
    run_ok(dir);
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
    quarantined(dir);
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
    quarantined(dir);
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
    quarantined(dir);
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
    assert!(
        second.record.is_some(),
        "a run that moved nothing still records itself"
    );
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
        Step::AfterFinalRecorded,
        Step::AfterKeptTemp,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let before = seed_quarantine(dir);
        let fault = fail_at(step);
        assert!(quarantine(dir, &qopts(false, &fault)).is_err(), "{step:?}");
        assert!(
            !quarantine_has_run(dir),
            "{step:?}: a failed quarantine leaves the gate closed"
        );
        let mut cat = cat_rows(dir, "denials", None, true);
        cat.sort();
        assert_eq!(cat, before, "{step:?}: cat prints each row once mid-move");

        quarantine(dir, &qopts(false, &no_fault)).unwrap();
        assert!(
            quarantine_has_run(dir),
            "{step:?}: the completing run opens it"
        );
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
    quarantined(&dir);
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
    quarantined(dir);
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

// --- review hardening (cameronsjo/cadence-hooks#1600) -----------------------

/// A child spawned by another thread shares the lock's open file description
/// until it execs, so a bare non-blocking `flock` sometimes looked held with no
/// other run alive (91 of 3000 tries in a probe). `try_lock` retries past that.
#[test]
fn a_concurrent_spawn_does_not_make_the_lock_look_held() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let spawned = Arc::new(AtomicUsize::new(0));
    let spawner = {
        let (stop, spawned) = (Arc::clone(&stop), Arc::clone(&spawned));
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let _ = std::process::Command::new("/usr/bin/true").status();
                spawned.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    while spawned.load(Ordering::SeqCst) < 5 {
        std::thread::yield_now();
    }
    // Keep taking and dropping the lock across a few hundred spawns.
    let until = spawned.load(Ordering::SeqCst) + 300;
    let (mut tries, mut skipped) = (0, 0);
    while spawned.load(Ordering::SeqCst) < until {
        tries += 1;
        if try_lock(&state).unwrap().is_none() {
            skipped += 1;
        }
    }
    stop.store(true, Ordering::SeqCst);
    spawner.join().unwrap();
    assert_eq!(
        skipped, 0,
        "the lock looked held with no run alive ({skipped} of {tries})"
    );
}

fn truncated_gzip() -> Vec<u8> {
    let member = gzip_member(format!("{}\n", denial(9, Some(UUID))).as_bytes()).unwrap();
    member[..member.len() - 6].to_vec()
}

#[test]
fn a_damaged_archive_stops_the_move_and_keeps_the_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let stamp = days_ago(100);
    let name = write_segment(dir, "denials", &stamp, 0, &[denial(1, Some(UUID))]);
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    let archive = dir.join(ARCHIVE_DIR).join(archive_name("denials", &stamp));
    std::fs::write(&archive, truncated_gzip()).unwrap();
    let damaged = std::fs::read(&archive).unwrap();

    assert_eq!(run_rotate_cli(dir), 1);
    assert!(dir.join(&name).is_file(), "the segment stays");
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        damaged,
        "the archive is untouched"
    );
    assert!(dir.join("state").join(MANIFEST_FILE).metadata().is_err());
    assert!(temp_files(dir).is_empty(), "{:?}", temp_files(dir));
    let failopen = std::fs::read_to_string(dir.join("failopen.jsonl")).unwrap();
    assert!(
        failopen.contains(FAILOPEN_REASON) && failopen.contains("damaged"),
        "{failopen}"
    );
}

/// One damaged archive holds back only its own segments: another ledger's
/// segment past retention still archives in the same run, which still
/// reports the damage and writes no success marker.
#[test]
fn a_damaged_archive_holds_back_only_its_own_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let stamp = days_ago(100);
    let held = write_segment(dir, "denials", &stamp, 0, &[denial(1, Some(UUID))]);
    let other = write_segment(dir, "hooks", &days_ago(200), 0, &["{\"n\":1}".to_string()]);
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(archive_name("denials", &stamp)),
        truncated_gzip(),
    )
    .unwrap();

    assert_eq!(run_rotate_cli(dir), 1, "the damage is still reported");
    assert!(
        dir.join(&held).is_file(),
        "the damaged archive's segment stays"
    );
    assert!(
        !dir.join(&other).exists(),
        "another ledger's segment still archives"
    );
    assert!(!dir.join("state").join(LAST_SUCCESS_FILE).exists());
}

/// `cat` reports a damaged archive and still prints every other row.
#[test]
fn cat_skips_a_damaged_archive_and_prints_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    std::fs::write(
        dir.join(ARCHIVE_DIR).join("denials.2026-01.jsonl.gz"),
        truncated_gzip(),
    )
    .unwrap();
    write_segment(dir, "denials", &days_ago(5), 0, &["{\"n\":2}".to_string()]);
    std::fs::write(dir.join("denials.jsonl"), "{\"n\":3}\n").unwrap();
    let mut out = Vec::new();
    let result = crate::ledger_cat::cat(dir, "denials", None, false, &mut out);
    assert!(result.is_err(), "the damage makes the read fail");
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("{\"n\":2}") && text.contains("{\"n\":3}"),
        "{text}"
    );
}

#[test]
fn a_damaged_test_row_archive_stops_the_quarantine() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let name = write_segment(dir, "denials", &days_ago(5), 0, &[denial(1, Some("t"))]);
    let before = std::fs::read(dir.join(&name)).unwrap();
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE),
        truncated_gzip(),
    )
    .unwrap();
    assert!(quarantine(dir, &qopts(false, &no_fault)).is_err());
    assert_eq!(std::fs::read(dir.join(&name)).unwrap(), before);
    assert!(dir.join("state").join(MANIFEST_FILE).metadata().is_err());
}

/// A writer that runs `rotate` on `dir` at its first write, the moment `cat`
/// is between reading archives and segments.
struct RotateMidCat<'a> {
    dir: &'a Path,
    report: Option<RotateReport>,
    out: Vec<u8>,
}

impl Write for RotateMidCat<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.report.is_none() {
            self.report = Some(rotate(self.dir, &opts(&no_fault)).unwrap());
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_rotate_during_cat_skips_and_every_row_prints_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    // One row archived already, so `cat` writes during the archive phase;
    // a second segment of the same month is past retention and still waiting.
    let stamp = days_ago(100);
    write_segment(dir, "denials", &stamp, 0, &[denial(1, Some(UUID))]);
    run_ok(dir);
    write_segment(dir, "denials", &stamp, 1, &[denial(2, Some(UUID))]);
    let mut sink = RotateMidCat {
        dir,
        report: None,
        out: Vec::new(),
    };
    crate::ledger_cat::cat(dir, "denials", None, false, &mut sink).unwrap();
    assert!(
        sink.report.as_ref().is_some_and(|r| r.skipped),
        "rotate must skip while cat holds the shared lock: {:?}",
        sink.report
    );
    let mut printed = lines_of(&sink.out);
    printed.sort();
    let mut expect = vec![denial(1, Some(UUID)), denial(2, Some(UUID))];
    expect.sort();
    assert_eq!(printed, expect);
}

#[test]
fn cat_waits_for_a_running_rotate() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    quarantined(&dir);
    write_segment(&dir, "denials", &days_ago(10), 0, &[denial(1, Some(UUID))]);
    ensure_private_dir(&dir.join("state")).unwrap();
    let held = try_lock(&dir.join("state")).unwrap().unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let (dir, done) = (dir.clone(), Arc::clone(&done));
        std::thread::spawn(move || {
            let rows = cat_rows(&dir, "denials", None, false);
            done.store(true, Ordering::SeqCst);
            rows
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !done.load(Ordering::SeqCst),
        "cat read while rotate held the lock"
    );
    drop(held);
    assert_eq!(reader.join().unwrap(), [denial(1, Some(UUID))]);
}

#[test]
fn the_session_start_bound_defers_big_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let small = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let rows: Vec<String> = (0..40).map(|i| denial(i, Some(UUID))).collect();
    let big = write_segment(dir, "denials", &days_ago(100), 1, &rows);
    let report = rotate(
        dir,
        &RotateOptions {
            now: NOW,
            deadline: None,
            max_segment_bytes: Some(1024),
            fault: &no_fault,
        },
    )
    .unwrap();
    assert!(!report.skipped);
    assert_eq!(report.deferred, 1);
    assert!(report.partial);
    assert!(!dir.join(&small).exists(), "the small segment moved");
    assert!(dir.join(&big).is_file(), "the big one waits for a hand run");
    assert!(!dir.join("state").join(LAST_SUCCESS_FILE).exists());
    run_ok(dir);
    assert!(!dir.join(&big).exists(), "the CLI run has no bound");
}

/// An ordinary segment is the live file just past the cap, so the SessionStart
/// bound must let it through; only a ledger that outgrew the cap before
/// rotation existed (the upgrade's one big segment) is deferred.
#[test]
fn the_session_start_bound_passes_ordinary_segments() {
    let cap = common::DEFAULT_LEDGER_MAX_BYTES;
    let ordinary = cap + 64 * 1024;
    let legacy = 50 * 1024 * 1024;
    assert!(
        ordinary <= session_start_bound(Some(cap)),
        "an ordinary segment passes"
    );
    assert!(
        legacy > session_start_bound(Some(cap)),
        "a 50 MiB legacy segment waits"
    );
    assert_eq!(
        session_start_bound(None),
        2 * cap,
        "rotation off uses the default cap"
    );
    assert_eq!(
        session_start_bound(Some(4 * cap)),
        8 * cap,
        "the bound follows a raised cap"
    );
}

#[test]
fn a_manifest_naming_an_outside_archive_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let name = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let outside = dir.join("victim.tmp");
    std::fs::write(&outside, "keep").unwrap();
    ensure_private_dir(&dir.join("state")).unwrap();
    let manifest = Manifest {
        op: "archive".to_string(),
        segment: name.clone(),
        archive: "/../../victim".to_string(),
        rows: 1,
        sha256: String::new(),
        source_len: 1,
        archived_sha256: String::new(),
        archive_len_before: 0,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    assert!(!manifest_names_ok(&manifest));
    write_manifest(&dir.join("state"), &manifest).unwrap();
    assert!(rotate(dir, &opts(&no_fault)).is_err());
    assert!(outside.is_file(), "nothing outside archive/ is touched");
    assert!(dir.join(&name).is_file());
}

#[test]
fn archive_holds_stops_decoding_past_the_segment_size() {
    let tmp = tempfile::tempdir().unwrap();
    let archive_dir = tmp.path();
    let big = vec![b'x'; 3 * 1024 * 1024];
    std::fs::write(
        archive_dir.join("denials.2026-01.jsonl.gz"),
        gzip_member(&big).unwrap(),
    )
    .unwrap();
    let manifest = Manifest {
        op: "archive".to_string(),
        segment: "denials.20260115T000000Z-000.jsonl".to_string(),
        archive: "denials.2026-01.jsonl.gz".to_string(),
        rows: 1,
        sha256: String::new(),
        source_len: 10,
        archived_sha256: sha256_hex(&big),
        archive_len_before: 0,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    assert!(!archive_holds(archive_dir, &manifest).unwrap());
    let fits = Manifest {
        source_len: big.len() as u64,
        ..manifest
    };
    assert!(
        archive_holds(archive_dir, &fits).unwrap(),
        "positive control"
    );
}

#[test]
fn a_rollup_append_never_joins_a_partial_line() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    ensure_private_dir(&dir.join(ROLLUPS_DIR)).unwrap();
    let rollup = dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP);
    std::fs::write(&rollup, r#"{"day":"2026-01-01","count":1,"segm"#).unwrap();
    write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    run_ok(dir);
    let text = std::fs::read_to_string(&rollup).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(serde_json::from_str::<Value>(lines[1]).is_ok(), "{text}");
}

#[test]
fn cat_since_compares_instants_not_spellings() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    std::fs::write(
        dir.join("denials.jsonl"),
        concat!(
            r#"{"ts":"2026-01-12T00:00:00.500Z","n":1}"#,
            "\n",
            r#"{"ts":"2026-01-12T00:00:00+00:00","n":2}"#,
            "\n",
            r#"{"ts":"2026-01-11T23:59:59Z","n":3}"#,
            "\n",
        ),
    )
    .unwrap();
    let since = crate::ledger_cat::parse_since("2026-01-12").unwrap();
    assert_eq!(cat_rows(dir, "denials", Some(&since), false).len(), 2);
}

// --- round 3 (cameronsjo/cadence-hooks#1600) -------------------------------

#[test]
fn denials_wait_for_the_quarantine() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let denials = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let commits = write_segment(dir, "commits", &days_ago(200), 0, &[denial(2, Some(UUID))]);

    let before = run_ok(dir);
    assert_eq!(before.awaiting_quarantine, 1);
    assert!(before.partial);
    assert!(
        dir.join(&denials).is_file(),
        "denials waits for the quarantine"
    );
    assert!(
        !dir.join(&commits).exists(),
        "other ledgers are not held back"
    );
    assert!(!dir.join("state").join(LAST_SUCCESS_FILE).exists());

    // A quarantine that moves nothing still writes its record and opens the gate.
    let q = quarantine(dir, &qopts(false, &no_fault)).unwrap();
    assert_eq!(q.files.iter().map(|f| f.test_rows).sum::<u64>(), 0);
    assert!(q.record.is_some());
    assert!(quarantine_has_run(dir));

    let after = run_ok(dir);
    assert_eq!(after.awaiting_quarantine, 0);
    assert!(!dir.join(&denials).exists(), "archived once quarantined");
    assert!(dir.join("state").join(LAST_SUCCESS_FILE).is_file());
}

/// The salvage commands in `salvage_hint`, run for real on a truncated
/// three-member archive: the two intact members survive, no partial row is
/// kept, and the archive takes new members again.
#[test]
fn the_salvage_recipe_keeps_the_intact_members() {
    let have = |tool: &str| {
        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !(have("gzip") && have("perl")) {
        eprintln!("skipping: gzip or perl is not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    let stamp = days_ago(100);
    let name = archive_name("denials", &stamp);
    let rows =
        |r: std::ops::Range<usize>| -> Vec<String> { r.map(|i| denial(i, Some(UUID))).collect() };
    let member =
        |rows: &[String]| gzip_member(format!("{}\n", rows.join("\n")).as_bytes()).unwrap();
    let (a, b, c) = (rows(0..3), rows(3..6), rows(6..2000));
    let third = member(&c);
    let damaged = [member(&a), member(&b), third[..third.len() / 2].to_vec()].concat();
    std::fs::write(dir.join(ARCHIVE_DIR).join(&name), &damaged).unwrap();
    let seg = write_segment(dir, "denials", &stamp, 0, &[denial(5000, Some(UUID))]);
    let err = rotate(dir, &opts(&no_fault)).unwrap_err();
    assert!(
        err.contains("gzip -dc"),
        "the error carries the recipe: {err}"
    );

    // Run exactly the commands the hint names.
    let commands = salvage_commands(&dir.join(ARCHIVE_DIR), &name);
    assert!(salvage_hint(&dir.join(ARCHIVE_DIR), &name).contains(&commands));
    let status = std::process::Command::new("sh")
        .args(["-c", &commands])
        .status()
        .unwrap();
    assert!(status.success(), "{commands}");

    let salvaged =
        lines_of(&gunzip_all(&std::fs::read(dir.join(ARCHIVE_DIR).join(&name)).unwrap()).unwrap());
    let all: BTreeSet<String> = a.iter().chain(&b).chain(&c).cloned().collect();
    for row in a.iter().chain(&b) {
        assert!(salvaged.contains(row), "intact row lost: {row}");
    }
    assert!(
        salvaged.iter().all(|r| all.contains(r)),
        "no partial or invented row"
    );
    assert_eq!(mode(&dir.join(ARCHIVE_DIR).join(&name)), 0o600);

    run_ok(dir);
    assert!(
        !dir.join(&seg).exists(),
        "the archive takes new members again"
    );
    let printed = cat_rows(dir, "denials", None, false);
    assert!(printed.contains(&denial(5000, Some(UUID))));
    assert!(printed.contains(&a[0]));
}

/// Reset a test's chmod so the temp dir can be removed.
struct Chmod(PathBuf, u32);

impl Drop for Chmod {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

/// Permission tests mean nothing as root, which ignores file modes.
fn running_as_root() -> bool {
    // SAFETY: `geteuid` takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn chmod(path: &Path, mode: u32) -> Chmod {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    Chmod(path.to_path_buf(), 0o700)
}

#[test]
fn cat_reports_an_unreadable_archive_dir() {
    if running_as_root() {
        eprintln!("skipping: root ignores file modes");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    std::fs::write(
        dir.join("denials.jsonl"),
        format!("{}\n", denial(1, Some(UUID))),
    )
    .unwrap();
    let _reset = chmod(&dir.join(ARCHIVE_DIR), 0o000);
    let mut out = Vec::new();
    let err = crate::ledger_cat::cat(dir, "denials", None, false, &mut out).unwrap_err();
    assert!(err.to_string().contains(ARCHIVE_DIR), "{err}");
}

#[test]
fn cat_read_errors_name_the_file() {
    if running_as_root() {
        eprintln!("skipping: root ignores file modes");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let seg = write_segment(dir, "denials", &days_ago(5), 0, &[denial(1, Some(UUID))]);
    let reset = chmod(&dir.join(&seg), 0o000);
    let mut out = Vec::new();
    let err = crate::ledger_cat::cat(dir, "denials", None, false, &mut out).unwrap_err();
    assert!(err.to_string().contains(&seg), "{err}");
    drop(reset);
}

#[test]
fn cat_reads_unlocked_when_the_lock_cannot_be_made() {
    if running_as_root() {
        eprintln!("skipping: root ignores file modes");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(
        dir.join("denials.jsonl"),
        format!("{}\n", denial(1, Some(UUID))),
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    // No lock file and a read-only state/: it cannot be created.
    let reset = chmod(&dir.join("state"), 0o500);
    assert_eq!(
        cat_rows(dir, "denials", None, false),
        [denial(1, Some(UUID))]
    );
    drop(reset);
    // An existing lock file the reader cannot write is still locked read-only.
    std::fs::write(dir.join("state").join(LOCK_FILE), "").unwrap();
    let _file = chmod(&dir.join("state").join(LOCK_FILE), 0o400);
    let _dir = chmod(&dir.join("state"), 0o500);
    assert!(lock_shared(&dir.join("state")).unwrap().is_some());
    assert_eq!(
        cat_rows(dir, "denials", None, false),
        [denial(1, Some(UUID))]
    );
}

#[test]
fn a_forged_quarantine_manifest_on_another_ledger_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // A `sessions` segment whose rows would all count as test rows.
    let rows = [
        r#"{"sessionId":null,"n":1}"#.to_string(),
        r#"{"n":2}"#.to_string(),
    ];
    let seg = write_segment(dir, "sessions", &days_ago(5), 0, &rows);
    let bytes = std::fs::read(dir.join(&seg)).unwrap();
    // A test-row archive whose only member matches what the manifest claims.
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    let content = normalized(&bytes);
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE),
        gzip_member(&content).unwrap(),
    )
    .unwrap();
    let manifest = Manifest {
        op: "quarantine".to_string(),
        segment: seg.clone(),
        archive: TESTROWS_ARCHIVE.to_string(),
        rows: row_count(&content),
        sha256: sha256_hex(&bytes),
        source_len: bytes.len() as u64,
        archived_sha256: sha256_hex(&content),
        archive_len_before: 0,
        kept_sha256: Some(sha256_hex(b"")),
        final_sha256: None,
        final_len: None,
    };
    assert!(
        archive_holds(&dir.join(ARCHIVE_DIR), &manifest).unwrap(),
        "the forgery is otherwise complete"
    );
    assert!(!manifest_names_ok(&manifest));
    ensure_private_dir(&dir.join("state")).unwrap();
    write_manifest(&dir.join("state"), &manifest).unwrap();
    assert!(rotate(dir, &opts(&no_fault)).is_err());
    assert_eq!(
        std::fs::read(dir.join(&seg)).unwrap(),
        bytes,
        "no row deleted"
    );
    // An archive op must name its segment's own month archive.
    let cross = Manifest {
        op: "archive".to_string(),
        archive: "denials.2026-01.jsonl.gz".to_string(),
        ..manifest
    };
    assert!(!manifest_names_ok(&cross));
}

// --- round 4 (cameronsjo/cadence-hooks#1600) -------------------------------

fn bash_ok(script: &str, cwd: &Path) -> bool {
    std::process::Command::new("bash")
        .args(["-c", script])
        .current_dir(cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn every_file_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out
}

/// A hostile archive name (a quote, a substitution, a space, a leading `-`)
/// stays one inert word in the salvage commands.
#[test]
fn salvage_commands_quote_a_hostile_name() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let archive_dir = root.join("archive dir");
    let elsewhere = root.join("elsewhere");
    std::fs::create_dir_all(&archive_dir).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let name = "-r a'b $(touch PWNED) `touch PWNED2`.2026-01.jsonl.gz";
    let member = gzip_member(b"{\"n\":1}\n").unwrap();
    std::fs::write(archive_dir.join(name), &member).unwrap();
    let commands = salvage_commands(&archive_dir, name);

    let syntax = std::process::Command::new("bash")
        .args(["-n", "-c", &commands])
        .status()
        .unwrap();
    assert!(syntax.success(), "bash -n rejects: {commands}");
    assert!(bash_ok(&commands, &elsewhere), "{commands}");

    let files = every_file_under(root);
    assert!(
        files.iter().all(|f| !f.to_string_lossy().contains("PWNED")
            || f.file_name()
                .is_some_and(|n| n.to_string_lossy().contains("$(touch PWNED)"))),
        "a substitution ran: {files:?}"
    );
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing written outside"
    );
    let damaged = archive_dir.join(format!("{name}.damaged"));
    assert_eq!(
        std::fs::read(&damaged).unwrap(),
        member,
        "moved aside as one file"
    );
    assert_eq!(
        gunzip_all(&std::fs::read(archive_dir.join(name)).unwrap()).unwrap(),
        b"{\"n\":1}\n"
    );
    assert!(
        files
            .iter()
            .all(|f| f.starts_with(&archive_dir) || f == &archive_dir || f == &elsewhere)
    );
}

#[test]
fn a_second_salvage_never_replaces_the_first_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let archive_dir = tmp.path();
    let name = "denials.2026-01.jsonl.gz";
    let damaged_bytes = truncated_gzip();
    std::fs::write(archive_dir.join(name), &damaged_bytes).unwrap();
    let commands = salvage_commands(archive_dir, name);
    assert!(bash_ok(&commands, archive_dir), "first run");
    let aside = archive_dir.join(format!("{name}.damaged"));
    assert_eq!(std::fs::read(&aside).unwrap(), damaged_bytes);
    // The salvaged archive is damaged again; a rerun must stop.
    std::fs::write(archive_dir.join(name), b"not gzip").unwrap();
    assert!(!bash_ok(&commands, archive_dir), "the rerun stops non-zero");
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        damaged_bytes,
        "first copy untouched"
    );
    assert_eq!(std::fs::read(archive_dir.join(name)).unwrap(), b"not gzip");
}

#[test]
fn an_archive_manifest_must_name_its_own_month() {
    let seg = "denials.20260115T000000Z-000.jsonl".to_string();
    let base = Manifest {
        op: "archive".to_string(),
        segment: seg,
        archive: "denials.2026-01.jsonl.gz".to_string(),
        rows: 0,
        sha256: String::new(),
        source_len: 0,
        archived_sha256: String::new(),
        archive_len_before: 0,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    assert!(manifest_names_ok(&base));
    let wrong_month = Manifest {
        archive: "denials.2026-02.jsonl.gz".to_string(),
        ..base
    };
    assert!(!manifest_names_ok(&wrong_month));
}

/// A manifest whose archive tail is real but is not this segment's content is
/// refused and the segment kept: recovery checks the tail against the segment.
#[test]
fn recovery_checks_the_archive_tail_against_the_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let stamp = days_ago(100);
    let seg = write_segment(dir, "denials", &stamp, 0, &[denial(1, Some(UUID))]);
    let bytes = std::fs::read(dir.join(&seg)).unwrap();
    let other = format!("{}\n", denial(2, Some(UUID))).into_bytes();
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    let archive = archive_name("denials", &stamp);
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(&archive),
        gzip_member(&other).unwrap(),
    )
    .unwrap();
    let manifest = Manifest {
        op: "archive".to_string(),
        segment: seg.clone(),
        archive,
        rows: 1,
        sha256: sha256_hex(&bytes),
        source_len: bytes.len() as u64,
        archived_sha256: sha256_hex(&other),
        archive_len_before: 0,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    assert!(manifest_names_ok(&manifest));
    assert!(archive_holds(&dir.join(ARCHIVE_DIR), &manifest).unwrap());
    write_manifest(&dir.join("state"), &manifest).unwrap();
    assert!(rotate(dir, &opts(&no_fault)).is_err());
    assert_eq!(
        std::fs::read(dir.join(&seg)).unwrap(),
        bytes,
        "segment kept"
    );
    // `cat` judges the manifest the way recovery does, so the segment's row
    // still prints, once.
    let printed = cat_rows(dir, "denials", None, false);
    let ones = printed
        .iter()
        .filter(|r| **r == denial(1, Some(UUID)))
        .count();
    assert_eq!(ones, 1, "{printed:?}");
}

#[test]
fn a_fifo_lock_file_does_not_hang_cat() {
    if running_as_root() {
        eprintln!("skipping: root ignores file modes");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    std::fs::write(
        dir.join("denials.jsonl"),
        format!("{}\n", denial(1, Some(UUID))),
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let fifo = std::ffi::CString::new(dir.join("state").join(LOCK_FILE).to_str().unwrap()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o444) }, 0);
    let _dir = chmod(&dir.join("state"), 0o500);
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = dir.clone();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = tx
            .send(crate::ledger_cat::cat(&reader, "denials", None, false, &mut out).map(|()| out));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cat hung on a FIFO lock file");
    let err = result.unwrap_err();
    assert!(err.to_string().contains(LOCK_FILE), "{err}");
}

// --- round 5 (cameronsjo/cadence-hooks#1600) -------------------------------

/// A row appended to a segment after its archive read, with the move killed
/// after the archive rename: recovery keeps only the new row in the segment,
/// and `cat` prints every row once both before and after.
#[test]
fn a_late_append_after_the_archive_read_is_kept_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    let fault = fail_at(Step::AfterArchiveRename);
    assert!(rotate(dir, &opts(&fault)).is_err());
    let late = denial(3, Some(UUID));
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(&seg))
            .unwrap();
        f.write_all(format!("{late}\n").as_bytes()).unwrap();
    }
    let mut expect = vec![denial(1, Some(UUID)), denial(2, Some(UUID)), late.clone()];
    expect.sort();
    let mut mid = cat_rows(dir, "denials", None, false);
    mid.sort();
    assert_eq!(mid, expect, "mid-move: every row once");

    assert!(recover(dir, &no_fault).unwrap(), "a manifest was pending");
    assert_eq!(
        lines_of(&std::fs::read(dir.join(&seg)).unwrap()),
        std::slice::from_ref(&late),
        "recovery keeps only the row appended after the read"
    );
    assert!(
        dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
        "manifest cleared"
    );
    run_ok(dir);
    // Recovery left only the new row in the segment, which is still past
    // retention, so the same run archived it as a second member.
    assert!(!dir.join(&seg).exists());
    let mut after = cat_rows(dir, "denials", None, false);
    after.sort();
    assert_eq!(after, expect);
    assert_eq!(raw_rows(dir, &["denials"]), expect, "stored once");
}

/// A quarantine manifest whose test-row member is real but holds other rows
/// strips nothing.
#[test]
fn a_forged_quarantine_manifest_on_denials_strips_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let rows = [denial(1, Some(UUID)), denial(2, Some("t")), denial(3, None)];
    let seg = write_segment(dir, "denials", &days_ago(5), 0, &rows);
    let bytes = std::fs::read(dir.join(&seg)).unwrap();
    let (kept, _) = split_test_rows(&normalized(&bytes));
    let other = format!("{}\n", denial(9, Some("other"))).into_bytes();
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE),
        gzip_member(&other).unwrap(),
    )
    .unwrap();
    let manifest = Manifest {
        op: "quarantine".to_string(),
        segment: seg.clone(),
        archive: TESTROWS_ARCHIVE.to_string(),
        rows: 1,
        sha256: sha256_hex(&bytes),
        source_len: bytes.len() as u64,
        archived_sha256: sha256_hex(&other),
        archive_len_before: 0,
        kept_sha256: Some(sha256_hex(&kept)),
        final_sha256: None,
        final_len: None,
    };
    assert!(manifest_names_ok(&manifest));
    assert!(archive_holds(&dir.join(ARCHIVE_DIR), &manifest).unwrap());
    ensure_private_dir(&dir.join("state")).unwrap();
    write_manifest(&dir.join("state"), &manifest).unwrap();
    assert!(rotate(dir, &opts(&no_fault)).is_err());
    assert_eq!(
        std::fs::read(dir.join(&seg)).unwrap(),
        bytes,
        "no row stripped"
    );
    let mut printed = cat_rows(dir, "denials", None, false);
    printed.sort();
    let mut expect = rows.to_vec();
    expect.sort();
    assert_eq!(printed, expect, "cat prints every row");
}

#[test]
fn no_salvage_commands_for_a_name_that_displays_differently() {
    let tmp = tempfile::tempdir().unwrap();
    let hidden = "denials\u{200B}.2026-01.jsonl.gz";
    let shown = common::display_safe(&salvage_hint(tmp.path(), hidden));
    assert!(!shown.contains("mv "), "{shown}");
    assert!(shown.contains("invisible or control characters"), "{shown}");
    let plain = common::display_safe(&salvage_hint(tmp.path(), "denials.2026-01.jsonl.gz"));
    assert!(plain.contains("mv "), "positive control: {plain}");
}

#[test]
fn a_fifo_lock_file_fails_rotate_without_hanging() {
    if running_as_root() {
        eprintln!("skipping: root ignores file modes");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let fifo = std::ffi::CString::new(dir.join("state").join(LOCK_FILE).to_str().unwrap()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(rotate(&dir, &opts(&no_fault)));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("rotate hung on a FIFO lock file");
    let err = result.unwrap_err();
    assert!(err.contains("regular file"), "{err}");
}

// --- round 6 (cameronsjo/cadence-hooks#1600) -------------------------------

fn append_row(path: &Path, row: &str) {
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(row.as_bytes()).unwrap();
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// A move killed after the archive rename, a row appended, then recovery
/// itself killed at each of its own steps (record, temp, replace): `cat`
/// prints every row once at each point, and the next run finishes and clears
/// the manifest. Archive op.
#[test]
fn a_kill_inside_recovery_never_wedges_an_archive_move() {
    for step in [
        Step::AfterFinalRecorded,
        Step::AfterKeptTemp,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        quarantined(dir);
        let seg = write_segment(
            dir,
            "denials",
            &days_ago(100),
            0,
            &[denial(1, Some(UUID)), denial(2, Some(UUID))],
        );
        assert!(rotate(dir, &opts(&fail_at(Step::AfterArchiveRename))).is_err());
        append_row(&dir.join(&seg), &format!("{}\n", denial(3, Some(UUID))));
        let all = sorted(vec![
            denial(1, Some(UUID)),
            denial(2, Some(UUID)),
            denial(3, Some(UUID)),
        ]);

        assert!(
            rotate(dir, &opts(&fail_at(step))).is_err(),
            "{step:?}: recovery killed"
        );
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, false)),
            all,
            "{step:?}: cat mid-recovery"
        );

        run_ok(dir);
        assert!(
            dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
            "{step:?}: cleared"
        );
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, false)),
            all,
            "{step:?}: cat after"
        );
        assert_eq!(raw_rows(dir, &["denials"]), all, "{step:?}: stored once");
    }
}

/// The same for a quarantine, read through `cat` both with and without
/// `--include-test-rows` while the move is pending.
#[test]
fn a_kill_inside_recovery_never_wedges_a_quarantine() {
    for step in [
        Step::AfterFinalRecorded,
        Step::AfterKeptTemp,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let rows = [denial(1, Some(UUID)), denial(2, Some("t")), denial(3, None)];
        let seg = write_segment(dir, "denials", &days_ago(5), 0, &rows);
        assert!(quarantine(dir, &qopts(false, &fail_at(Step::AfterArchiveRename))).is_err());
        let late = denial(4, Some(UUID));
        append_row(&dir.join(&seg), &format!("{late}\n"));
        let all = sorted(vec![
            rows[0].clone(),
            rows[1].clone(),
            rows[2].clone(),
            late.clone(),
        ]);
        let real = sorted(vec![rows[0].clone(), late.clone()]);
        // Pending with a late append, before recovery runs.
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, true)),
            all,
            "pending, with test rows"
        );
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, false)),
            real,
            "pending, without"
        );

        assert!(
            quarantine(dir, &qopts(false, &fail_at(step))).is_err(),
            "{step:?}: recovery killed"
        );
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, true)),
            all,
            "{step:?}: with test rows"
        );
        assert_eq!(
            sorted(cat_rows(dir, "denials", None, false)),
            real,
            "{step:?}: without"
        );

        quarantine(dir, &qopts(false, &no_fault)).unwrap();
        assert!(
            dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
            "{step:?}: cleared"
        );
        assert_eq!(raw_rows(dir, &["denials"]), all, "{step:?}: stored once");
        assert_eq!(
            sorted(lines_of(&std::fs::read(dir.join(&seg)).unwrap())),
            real,
            "{step:?}"
        );
    }
}

/// A segment read while its last row is half written: only whole rows move,
/// and once the writer finishes, the row is whole, parses, and is in one place.
#[test]
fn a_torn_last_row_stays_whole_through_an_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let torn = denial(3, Some(UUID));
    let (head, rest) = torn.split_at(torn.len() / 2);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    append_row(&dir.join(&seg), head);
    let path = dir.join(&seg);
    let fault = |s: Step| {
        if s == Step::AfterArchiveRename {
            append_row(&path, &format!("{rest}\n"));
        }
        Ok(())
    };
    run_with(dir, &fault);
    let in_segment = lines_of(&std::fs::read(&path).unwrap());
    assert_eq!(
        in_segment,
        std::slice::from_ref(&torn),
        "the finished row stays, whole"
    );
    assert!(serde_json::from_str::<Value>(&in_segment[0]).is_ok());
    let all = sorted(vec![denial(1, Some(UUID)), denial(2, Some(UUID)), torn]);
    assert_eq!(sorted(cat_rows(dir, "denials", None, false)), all);
    assert_eq!(raw_rows(dir, &["denials"]), all);
}

#[test]
fn a_torn_last_row_stays_whole_through_a_quarantine() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let torn = denial(3, Some(UUID));
    let (head, rest) = torn.split_at(torn.len() / 2);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(5),
        0,
        &[denial(1, Some(UUID)), denial(2, Some("t"))],
    );
    let path = dir.join(&seg);
    append_row(&path, head);
    let fault = |s: Step| {
        if s == Step::AfterArchiveRename {
            append_row(&path, &format!("{rest}\n"));
        }
        Ok(())
    };
    quarantine(dir, &qopts(false, &fault)).unwrap();
    let in_segment = lines_of(&std::fs::read(&path).unwrap());
    assert_eq!(in_segment, [denial(1, Some(UUID)), torn.clone()]);
    assert!(
        in_segment
            .iter()
            .all(|l| serde_json::from_str::<Value>(l).is_ok())
    );
    assert_eq!(
        raw_rows(dir, &["denials"]),
        sorted(vec![denial(1, Some(UUID)), denial(2, Some("t")), torn])
    );
}

fn run_with(dir: &Path, fault: Fault<'_>) -> RotateReport {
    let report = rotate(
        dir,
        &RotateOptions {
            now: NOW,
            deadline: None,
            max_segment_bytes: None,
            fault,
        },
    )
    .unwrap();
    assert!(!report.skipped);
    report
}

/// A prefix that ends mid-row with bytes after it: an archive that closed the
/// torn row with a newline keeps the bytes after it as their own fragment; a
/// quarantine (which never closes a row) is unproven.
#[test]
fn a_split_row_is_kept_after_a_closed_archive_and_unproven_otherwise() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let stamp = days_ago(100);
    let row = denial(1, Some(UUID));
    let seg = write_segment(dir, "denials", &stamp, 0, std::slice::from_ref(&row));
    let bytes = std::fs::read(dir.join(&seg)).unwrap();
    let cut = bytes.len() / 2;
    let prefix = &bytes[..cut];
    ensure_private_dir(&dir.join(ARCHIVE_DIR)).unwrap();
    let archive = archive_name("denials", &stamp);
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(&archive),
        gzip_member(&normalized(prefix)).unwrap(),
    )
    .unwrap();
    let closed = Manifest {
        op: "archive".to_string(),
        segment: seg.clone(),
        archive,
        rows: 1,
        sha256: sha256_hex(prefix),
        source_len: cut as u64,
        archived_sha256: sha256_hex(&normalized(prefix)),
        archive_len_before: 0,
        kept_sha256: None,
        final_sha256: None,
        final_len: None,
    };
    assert_eq!(
        move_state(&dir.join(ARCHIVE_DIR), &closed, Some(&bytes)).unwrap(),
        MoveState::Pending {
            remaining: bytes[cut..].to_vec()
        }
    );

    let member = b"{\"x\":1}\n";
    std::fs::write(
        dir.join(ARCHIVE_DIR).join(TESTROWS_ARCHIVE),
        gzip_member(member).unwrap(),
    )
    .unwrap();
    let quarantine = Manifest {
        op: "quarantine".to_string(),
        archive: TESTROWS_ARCHIVE.to_string(),
        archived_sha256: sha256_hex(member),
        kept_sha256: Some(String::new()),
        ..closed
    };
    assert!(matches!(
        move_state(&dir.join(ARCHIVE_DIR), &quarantine, Some(&bytes)).unwrap(),
        MoveState::Unproven(_)
    ));
}

/// A row appended between the forward read and the delete stays.
#[test]
fn a_row_appended_during_an_archive_move_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let path = dir.join(&seg);
    let late = denial(2, Some(UUID));
    let fault = |s: Step| {
        if s == Step::AfterArchiveRename {
            append_row(&path, &format!("{late}\n"));
        }
        Ok(())
    };
    run_with(dir, &fault);
    assert_eq!(
        lines_of(&std::fs::read(&path).unwrap()),
        std::slice::from_ref(&late)
    );
    assert_eq!(
        raw_rows(dir, &["denials"]),
        sorted(vec![denial(1, Some(UUID)), late])
    );
}

#[test]
fn no_salvage_commands_for_a_directory_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let dir = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/arch\xffive"));
    let hint = salvage_hint(dir, "denials.2026-01.jsonl.gz");
    assert!(!hint.contains("mv "), "{hint}");
    assert!(hint.contains("not UTF-8"), "{hint}");
}

// --- round 7 (cameronsjo/cadence-hooks#1600) -------------------------------

fn age_file(path: &Path, secs: u64) {
    let t = SystemTime::now() - Duration::from_secs(secs);
    std::fs::File::options()
        .append(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

/// A segment past retention whose last bytes never got a newline (a hook
/// killed mid-write, or a final row written without one) is archived whole in
/// one run, not left behind forever.
#[test]
fn an_old_segment_ending_mid_row_is_archived_whole() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let torn = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    append_row(&dir.join(&torn), r#"{"partial"#);
    let no_newline = write_segment(dir, "commits", &days_ago(200), 0, &[denial(2, Some(UUID))]);
    append_row(&dir.join(&no_newline), &denial(3, Some(UUID)));
    age_file(&dir.join(&torn), 3600);
    age_file(&dir.join(&no_newline), 3600);

    let report = run_ok(dir);
    assert_eq!(report.archived.len(), 2);
    assert!(!dir.join(&torn).exists(), "the torn segment is gone");
    assert!(!dir.join(&no_newline).exists());
    assert!(dir.join("state").join(LAST_SUCCESS_FILE).is_file());
    let printed = cat_rows(dir, "denials", None, false);
    assert_eq!(
        printed.iter().filter(|r| *r == r#"{"partial"#).count(),
        1,
        "{printed:?}"
    );
    assert_eq!(printed.len(), 2);
    assert_eq!(
        sorted(cat_rows(dir, "commits", None, false)),
        sorted(vec![denial(2, Some(UUID)), denial(3, Some(UUID))])
    );
    assert!(
        run_ok(dir).archived.is_empty(),
        "nothing left for a later run"
    );
}

/// Rows left behind by one move and archived by the next are rolled up once,
/// so the rollup counts equal the rows archived.
#[test]
fn a_segment_moved_twice_rolls_up_each_row_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    let path = dir.join(&seg);
    let fault = |s: Step| {
        if s == Step::AfterArchiveRename {
            append_row(&path, &format!("{}\n", denial(3, Some(UUID))));
        }
        Ok(())
    };
    run_with(dir, &fault);
    assert!(path.is_file(), "the appended row stayed behind");
    run_ok(dir);
    assert!(!path.exists(), "the second move archived it");
    let total: u64 = common::read_ledger(&dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP))
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["count"]
                .as_u64()
                .unwrap()
        })
        .sum();
    assert_eq!(total, 3, "every archived row is counted once");
}

/// The quarantine's counts come from the bytes it moves, not a torn last row
/// it leaves behind.
#[test]
fn quarantine_counts_only_the_rows_it_moves() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(5),
        0,
        &[denial(1, Some(UUID)), denial(2, Some("t"))],
    );
    // A whole test row with no newline yet: held back on a fresh file.
    append_row(&dir.join(&seg), &denial(3, Some("t")));
    let read_before = std::fs::read(dir.join(&seg)).unwrap();
    let report = quarantine(dir, &qopts(false, &no_fault)).unwrap();
    let file = report.files.iter().find(|f| f.file == seg).unwrap();
    assert_eq!(file.test_rows, 1, "{file:?}");
    assert_eq!(file.rows_before, 2, "{file:?}");
    // The whole file as read, torn tail included, not just the moved bytes.
    assert_eq!(file.sha256, sha256_hex(&read_before));
}

// --- round 8 (cameronsjo/cadence-hooks#1600) -------------------------------

fn rollup_total(dir: &Path) -> u64 {
    common::read_ledger(&dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP))
        .unwrap_or_default()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["count"]
                .as_u64()
                .unwrap()
        })
        .sum()
}

/// An old `denials` segment ending in a fragment, aged past the torn-row hold.
fn old_torn(dir: &Path) -> PathBuf {
    quarantined(dir);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    let path = dir.join(&seg);
    append_row(&path, r#"{"partial"#);
    age_file(&path, 3600);
    path
}

/// The reviewer's crash walk: an old torn segment killed at each step; `cat`
/// prints the three rows once mid-move, and a clean run ends with the three
/// rows stored once and two rows rolled up (the fragment does not parse).
#[test]
fn an_old_torn_segment_survives_a_kill_at_each_step() {
    for step in [
        Step::AfterRollup,
        Step::AfterManifest,
        Step::AfterArchiveTemp,
        Step::AfterArchiveRename,
        Step::AfterSourceDone,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        old_torn(dir);
        assert!(rotate(dir, &opts(&fail_at(step))).is_err(), "{step:?}");
        let mid = cat_rows(dir, "denials", None, false);
        assert_eq!(mid.len(), 3, "{step:?}: {mid:?}");
        assert_eq!(
            mid.iter().filter(|r| *r == r#"{"partial"#).count(),
            1,
            "{step:?}"
        );
        run_ok(dir);
        assert!(
            dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
            "{step:?}"
        );
        assert_eq!(raw_rows(dir, &["denials"]).len(), 3, "{step:?}");
        assert_eq!(rollup_total(dir), 2, "{step:?}: rollup");
    }
}

/// A writer that still holds an old torn segment finishes its row after the
/// read: the archive keeps the fragment as it was read (closed with a
/// newline), the completion stays in the segment as its own fragment, and the
/// run completes.
#[test]
fn an_old_fragment_finished_after_the_read_stays_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let path = old_torn(dir);
    let fault = |s: Step| {
        if s == Step::AfterManifest {
            append_row(&path, "\"}\n");
        }
        Ok(())
    };
    run_with(dir, &fault);
    assert!(
        dir.join("state").join(MANIFEST_FILE).metadata().is_err(),
        "manifest cleared"
    );
    assert_eq!(lines_of(&std::fs::read(&path).unwrap()), ["\"}"]);
    let printed = cat_rows(dir, "denials", None, false);
    assert_eq!(
        printed.iter().filter(|r| *r == r#"{"partial"#).count(),
        1,
        "{printed:?}"
    );
    assert_eq!(
        printed.iter().filter(|r| *r == "\"}").count(),
        1,
        "{printed:?}"
    );
    assert_eq!(printed.len(), 4, "{printed:?}");
    // The completion is a whole line of its own, so the next run archives it.
    run_ok(dir);
    assert!(!path.exists());
    let after = cat_rows(dir, "denials", None, false);
    assert_eq!(sorted(after), sorted(printed));
}

/// A kill after the rollup, then an append, then a clean run: the rollup
/// counts equal the rows archived.
#[test]
fn a_rollup_retry_after_an_append_counts_each_row_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    let path = dir.join(&seg);
    assert!(rotate(dir, &opts(&fail_at(Step::AfterRollup))).is_err());
    append_row(&path, &format!("{}\n", denial(3, Some(UUID))));
    run_ok(dir);
    assert_eq!(raw_rows(dir, &["denials"]).len(), 3);
    assert_eq!(rollup_total(dir), 3);
}

/// A first attempt on a fresh torn segment (fragment held back) killed after
/// its rollup, retried once the segment is old (fragment taken): the two rows
/// are rolled up once.
#[test]
fn a_rollup_retry_from_the_recent_to_the_old_branch_counts_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(
        dir,
        "denials",
        &days_ago(100),
        0,
        &[denial(1, Some(UUID)), denial(2, Some(UUID))],
    );
    let path = dir.join(&seg);
    append_row(&path, r#"{"partial"#);
    assert!(rotate(dir, &opts(&fail_at(Step::AfterRollup))).is_err());
    assert_eq!(rollup_total(dir), 2);
    age_file(&path, 3600);
    run_ok(dir);
    assert!(!path.exists());
    assert_eq!(raw_rows(dir, &["denials"]).len(), 3);
    assert_eq!(rollup_total(dir), 2, "no row counted twice");
}

/// The reverse: an old-branch attempt killed after its rollup, the fragment
/// then finished by its writer (fresh again): still counted once.
#[test]
fn a_rollup_retry_from_the_old_to_the_recent_branch_counts_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let path = old_torn(dir);
    assert!(rotate(dir, &opts(&fail_at(Step::AfterRollup))).is_err());
    assert_eq!(rollup_total(dir), 2);
    append_row(&path, "\"}\n");
    run_ok(dir);
    assert_eq!(rollup_total(dir), 2, "the two parsed rows once");
}

/// A row from an earlier build with no moved range means the segment was
/// rolled up in full.
#[test]
fn a_rollup_row_without_a_range_covers_the_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    ensure_private_dir(&dir.join(ROLLUPS_DIR)).unwrap();
    std::fs::write(
        dir.join(ROLLUPS_DIR).join(DENIALS_ROLLUP),
        format!("{}\n", json!({"day":"2026-01-02","hook":"h1","repo":"r","decision":"deny","count":1,"segment":seg})),
    )
    .unwrap();
    run_ok(dir);
    assert_eq!(rollup_total(dir), 1);
}

#[test]
fn a_far_future_mtime_does_not_hold_a_fragment_forever() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    quarantined(dir);
    let seg = write_segment(dir, "denials", &days_ago(100), 0, &[denial(1, Some(UUID))]);
    let path = dir.join(&seg);
    append_row(&path, r#"{"partial"#);
    std::fs::File::options()
        .append(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(365 * 86_400))
        .unwrap();
    run_ok(dir);
    assert!(!path.exists(), "archived whole in one run");
}
