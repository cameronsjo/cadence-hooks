//! Closing stdout early must not be reported as an internal error.
//!
//! Rust ignores `SIGPIPE` before `main`, so a write to a closed pipe returns
//! `EPIPE` and `println!` unwraps it into a panic. For this binary that panic
//! also writes a `"reason":"panic"` row into `failopen.jsonl`, which `doctor`
//! then reports as a bug to file an issue about — the tool manufacturing its
//! own findings from `cadence-hooks list | head -1`.
//!
//! `main` restores the default disposition, so the process is killed by
//! `SIGPIPE` (signal 13) instead. These tests pin the quiet exit for two
//! independent writers, and pin that the quiet exit did not also silence real
//! panics.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// Run `cadence-hooks <args>` with stdout wired to a pipe whose read end is
/// **already closed**, and return `(status, stderr, failopen_rows)`.
///
/// Closing the read end before the child is spawned is what makes this
/// deterministic. Spawning with `Stdio::piped()` and dropping the handle races
/// the child: `list` emits about 8 KiB, which fits in the pipe buffer, so a
/// child that wins the race completes every write and the test passes for the
/// wrong reason.
fn run_with_closed_stdout(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    run_with_closed_stdout_env(args, &[], None)
}

/// [`run_with_closed_stdout`] with extra environment and a working directory
/// for the child — for a command such as `doctor` that reads the user's home,
/// config directory, and the checkout it runs in, and so must be pointed at a
/// temp dir to stay hermetic.
fn run_with_closed_stdout_env(
    args: &[&str],
    envs: &[(&str, &std::path::Path)],
    current_dir: Option<&std::path::Path>,
) -> (std::process::ExitStatus, String, String) {
    let tmp = tempfile::tempdir().expect("create a temp metrics dir");

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array of `c_int`, the only thing
    // `pipe(2)` writes through this pointer.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe(2) failed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // SAFETY: `write_fd` is a fresh fd from `pipe(2)` that nothing else owns;
    // `Stdio` takes ownership and closes it.
    let child_stdout = unsafe { Stdio::from_raw_fd(write_fd) };
    // SAFETY: same, for the read end — closed right here, before the spawn
    // below, and never wrapped in an owning type.
    unsafe { libc::close(read_fd) };

    let mut command = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }
    let mut child = command
        .args(args)
        .env("CADENCE_METRICS_DIR", tmp.path())
        .envs(envs.iter().copied())
        .stdout(child_stdout)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cadence-hooks");

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr was piped")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait for cadence-hooks");

    let failopen = std::fs::read_to_string(tmp.path().join("failopen.jsonl")).unwrap_or_default();
    (status, stderr, failopen)
}

#[test]
fn closed_stdout_kills_by_sigpipe_instead_of_panicking() {
    let (status, stderr, failopen) = run_with_closed_stdout(&["list"]);

    assert!(
        !stderr.contains("internal error (panic)"),
        "a closed stdout is not an internal error, but stderr said:\n{stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "a closed stdout must exit silently, but stderr said:\n{stderr}"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGPIPE),
        "expected death by SIGPIPE (shells report 141); got status {status:?} with stderr:\n{stderr}"
    );
    assert_eq!(
        status.code(),
        None,
        "a signalled process has no exit code; got {:?}",
        status.code()
    );
    assert!(
        failopen.is_empty(),
        "a closed stdout must not write a failopen row — those are what doctor \
         reports as bugs to file. Ledger contained:\n{failopen}"
    );
}

/// The same for `manifest`, a second, independent stdout writer. One passing
/// command would only prove that one command's writes were fixed; the point of
/// changing the process disposition rather than the write sites is that every
/// writer is covered.
#[test]
fn closed_stdout_covers_other_writers_too() {
    let (status, stderr, failopen) = run_with_closed_stdout(&["manifest"]);

    assert!(
        !stderr.contains("internal error (panic)"),
        "manifest reported an internal error on a closed stdout:\n{stderr}"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGPIPE),
        "expected death by SIGPIPE; got status {status:?} with stderr:\n{stderr}"
    );
    assert!(
        failopen.is_empty(),
        "manifest wrote a failopen row for a closed stdout:\n{failopen}"
    );
}

/// `doctor | head -1` was the shape that produced the last recorded panic rows
/// (cadence-hooks#956), so it gets its own pin. `doctor` reads the user's home,
/// the Claude config directory, and the checkout it runs in, so all three
/// point at an empty temp dir. Ambient `CADENCE_*` variables still pass
/// through; they cannot change whether a closed stdout kills the process.
#[test]
fn closed_stdout_covers_doctor() {
    let home = tempfile::tempdir().expect("create a temp home");
    let (status, stderr, failopen) = run_with_closed_stdout_env(
        &["doctor"],
        &[("HOME", home.path()), ("CLAUDE_CONFIG_DIR", home.path())],
        Some(home.path()),
    );

    assert!(
        !stderr.contains("internal error (panic)"),
        "doctor reported an internal error on a closed stdout:\n{stderr}"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGPIPE),
        "expected death by SIGPIPE; got status {status:?} with stderr:\n{stderr}"
    );
    assert!(
        failopen.is_empty(),
        "doctor wrote a failopen row for a closed stdout:\n{failopen}"
    );
}

/// The quiet exit must be scoped to the closed pipe, not to panics generally.
///
/// A fix that simply stopped reporting panics would pass both tests above and
/// be far worse than the bug. This arms the synthetic dispatch panic
/// (`CADENCE_TEST_PANIC`, owned by `failopen_telemetry.rs`) with stdout wired to
/// a closed pipe, and requires the panic to be as loud as ever: the stderr
/// notice, and a genuine `"reason":"panic"` row in the ledger.
///
/// **This is a control, not a red-green pin.** It stays green under a revert of
/// either half of the fix, because the panic fires in dispatch before anything
/// writes to stdout, so the closed pipe is never touched. What it guards against
/// is a *future* change that silences panic reporting to make the two tests
/// above pass. It does not cover a stdout write and a panic interleaving; no
/// reachable path in this binary panics after a partial stdout write, so there
/// is nothing to arm.
///
/// # What is not covered, and why
///
/// A write error that is neither a closed pipe nor a panic — `ENOSPC` on a full
/// disk, `EIO` on failing hardware — has no portable stand-in, so it is not
/// staged here. Two things bound that gap. The change is a `SIGPIPE`
/// disposition, and the kernel raises `SIGPIPE` only for a pipe or socket whose
/// read end is closed; every other errno still comes back as an `Err` from the
/// write, exactly as before. And the obvious stand-in is a trap rather than a
/// gap: pointing stdout at a read-only fd yields `EBADF`, which the standard
/// library has always reported to the caller as a successful write
/// (`handle_ebadf` in `std::io::stdio`), so a test built on it would assert a
/// silence that predates this change by years.
#[test]
fn a_genuine_panic_is_still_loud_with_stdout_closed() {
    let tmp = tempfile::tempdir().expect("create a temp metrics dir");

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array of `c_int`.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe(2) failed");
    // SAFETY: fresh fds from `pipe(2)`; `Stdio` takes ownership of the write end
    // and the read end is closed here and never used.
    let child_stdout = unsafe { Stdio::from_raw_fd(fds[1]) };
    // SAFETY: as above.
    unsafe { libc::close(fds[0]) };

    let mut child = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["cadence", "terminology"])
        .env("CADENCE_METRICS_DIR", tmp.path())
        .env("CADENCE_TEST_PANIC", "1")
        .stdin(Stdio::piped())
        .stdout(child_stdout)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cadence-hooks");

    // The hook reads a payload from stdin before dispatch reaches the panic.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(b"{}");
    }

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr was piped")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait for cadence-hooks");

    assert!(
        stderr.contains("internal error (panic)"),
        "a genuine panic must stay loud whatever stdout is; status {status:?}, stderr:\n{stderr}"
    );

    let failopen = std::fs::read_to_string(tmp.path().join("failopen.jsonl")).unwrap_or_default();
    assert!(
        failopen.contains(r#""reason":"panic""#),
        "a genuine panic must still be recorded; ledger:\n{failopen}"
    );
    assert!(
        failopen.contains("CADENCE_TEST_PANIC"),
        "the recorded row must be the synthetic panic, not a stray broken-pipe \
         row: {failopen}"
    );
}

/// `try` writes a payload to a hook's stdin, and that pipe is one `try` owns
/// both ends of — so the process-wide `SIG_DFL` must not apply to it.
///
/// A hook that exits before reading (bypassed, disabled) closes the pipe, which
/// `try` has always handled by discarding the write error. Under a bare
/// `SIG_DFL` the same case kills `try` itself with signal 13, mid-diagnostic,
/// printing nothing. A payload larger than the pipe buffer makes that
/// deterministic: `write_all` blocks until the child exits, then gets `EPIPE`.
#[test]
fn try_survives_a_hook_that_closes_its_stdin() {
    let tmp = tempfile::tempdir().expect("create a temp dir");
    let payload = tmp.path().join("big-payload.json");
    // Well past any platform's pipe buffer, so the write cannot complete before
    // the child exits.
    let command = "echo ".to_string() + &"x".repeat(300_000);
    let json = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    std::fs::write(&payload, json.to_string()).expect("write the payload");

    // `CADENCE_BYPASS=1` exits the *child* immediately (`try` itself is exempt),
    // which is the early-close case without any timing dependence.
    let output = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["try", "cadence", "terminology"])
        .arg("--payload")
        .arg(&payload)
        .env("CADENCE_BYPASS", "1")
        .env_remove("CADENCE_DISABLE")
        .env("CADENCE_METRICS_DIR", tmp.path())
        .output()
        .expect("run cadence-hooks try");

    assert_eq!(
        output.status.signal(),
        None,
        "try must not be killed by a signal when a hook closes its stdin; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "try reports the bypassed hook's own exit 0; got {:?} with stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
