//! `SIGPIPE` disposition for the CLI process.
//!
//! Rust's runtime sets `SIGPIPE` to `SIG_IGN` before calling `main`. Every
//! write to a pipe whose reader has gone away then returns `EPIPE` instead of
//! killing the process, and `println!`/`writeln!` turn that `Err` into a
//! panic:
//!
//! ```text
//! $ cadence-hooks list | head -1
//! cadence-hooks: internal error (panic). This hook will not block your operation.
//! failed printing to stdout: Broken pipe (os error 32)
//! ```
//!
//! That is a bug on three counts: `head`, `grep -q`, and any consumer that
//! stops early are ordinary uses of a CLI; the panic hook records the run as a
//! `"reason":"panic"` row in `failopen.jsonl`, so `doctor` then reports the
//! tool's own normal operation as a defect to file an issue about; and the
//! message accuses a check of an internal error when nothing went wrong.
//!
//! # Why the disposition and not the write sites
//!
//! The alternative fix is to match `ErrorKind::BrokenPipe` at each stdout
//! write. This binary has several hundred `println!` calls across `doctor`,
//! `list`, `manifest`, `try`, `configure`, `metrics`, and every check that
//! emits hook JSON — plus whatever the next one adds. A per-site fix is a list
//! that is never finished, and each new writer is silently wrong until someone
//! notices. Restoring the default disposition fixes every writer in the
//! process at once, including writers inside dependencies.
//!
//! # What this changes
//!
//! A write to a closed pipe now terminates the process with `SIGPIPE` (signal
//! 13; shells report it as exit status 141) instead of returning `EPIPE`. That
//! is the standard Unix CLI contract — `cat`, `sort`, `grep`, and `yes` all
//! die this way — but it is a behavior change: the process no longer runs its
//! remaining code after a truncated write, and no destructor runs. Nothing in
//! this binary defers state-changing work to a destructor; the metrics and
//! denial ledgers are appended and flushed at their call sites.
//!
//! Real write failures stay loud. `SIGPIPE` is raised only for a pipe or
//! socket whose read end is closed. A full disk (`ENOSPC`), an I/O error
//! (`EIO`), or a closed regular file still returns `Err` from the write, still
//! panics through `main`'s panic hook, and still writes a genuine
//! `"reason":"panic"` failopen row. The fix removes the false ones and keeps
//! the true ones.
//!
//! # Windows
//!
//! Windows has no `SIGPIPE`. A write to a pipe whose reader has exited fails
//! with `ERROR_NO_DATA`/`ERROR_BROKEN_PIPE`, which reaches `println!` as
//! `ErrorKind::BrokenPipe` and panics exactly as it did on Unix — so the
//! released Windows binary still has this bug, and everything here is a no-op
//! there. The fix does not port: there is no process-wide disposition to
//! restore, and the alternatives are matching on a localized OS error string in
//! the panic hook or handling `BrokenPipe` at every write site. Tracked in
//! cameronsjo/cadence-hooks#980 rather than guessed at here.

/// Restore `SIGPIPE` to its default disposition (`SIG_DFL`).
///
/// Call once, first thing in `main`, before anything can write to stdout. A
/// no-op off Unix, where there is no such signal.
#[cfg(unix)]
pub(crate) fn restore_default() {
    // SAFETY: `signal(2)` with `SIG_DFL` is async-signal-safe and valid for
    // `SIGPIPE`. Called from `main` before any thread is spawned, so there is
    // no concurrent reader of the disposition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
pub(crate) fn restore_default() {}

/// Ignore `SIGPIPE` for as long as this value is alive, restoring `SIG_DFL` on
/// drop.
///
/// The process-wide `SIG_DFL` above is right for stdout, where a closed pipe
/// means the operator's consumer quit and this process has nothing left to do.
/// It is wrong for a pipe **this process owns both ends of**: `cadence-hooks
/// try` spawns a hook and writes the payload to its stdin, and a hook that
/// exits before reading (a bypassed one, say) closes that pipe. That is a
/// normal outcome `try` already handles by discarding the write error — under
/// `SIG_DFL` it would instead kill `try` itself, mid-diagnostic, with no
/// output.
///
/// Scope this around such a write and keep it as narrow as possible; `Drop`
/// puts `SIG_DFL` back.
pub(crate) struct IgnoreGuard {
    _private: (),
}

impl IgnoreGuard {
    pub(crate) fn new() -> Self {
        #[cfg(unix)]
        // SAFETY: same contract as `restore_default`.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        Self { _private: () }
    }
}

impl Drop for IgnoreGuard {
    fn drop(&mut self) {
        restore_default();
    }
}
