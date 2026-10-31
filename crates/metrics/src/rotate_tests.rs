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
