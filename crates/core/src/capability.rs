//! Is a given CLI available on this machine?
//!
//! Two consumers with nothing else in common share these primitives, which is
//! why they live in `core` rather than beside either one: `doctor` warns about
//! a CLI an installed hook shells to but PATH cannot resolve, and the secret
//! guards tailor a block message to whether the tool they would recommend is
//! actually installed.
//!
//! **Every probe here is infallible, bounded, and fails to `false`.** An unset,
//! unreadable, or hostile `PATH` yields "absent", never an error and never a
//! panic — a guard calls into this module while deciding what to *say*, long
//! after it has decided to block, so a fault here must not be able to change an
//! outcome or crash the hook. [`forgectl_present`] adds a deadline for the same
//! reason: `stat` on a stalled mount does not fail, it hangs, and a hang in
//! message composition swallows a block that was already decided.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

/// True when `name` resolves on the current `PATH`.
///
/// A plain PATH walk rather than shelling to `which`/`command -v`: this check
/// exists precisely because a CLI may be absent, and asking a subprocess to
/// answer that question adds a second dependency to the dependency check.
pub fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable_at(&dir.join(name)))
}

/// The full path that `std::process::Command` can run for `name`, found on
/// the current `PATH`.
///
/// A binary hook that shells to a CLI runs this path, not the bare name, and
/// `doctor` asks the same function whether that CLI is installed, so the two
/// cannot disagree. The bare name would not do on Windows: `Command::new`
/// searches `PATH` for `name.exe` only, while Node's global installs ship
/// `name.cmd`. Given a full `.cmd` or `.bat` path, std runs it through
/// `cmd.exe` and escapes the arguments, or returns an error when it cannot.
///
/// Narrower than [`on_path`], which answers for the shell: on Windows an
/// extensionless file (npm's `sh` shim) runs under Git Bash but not under
/// `Command`, so it does not count here.
pub fn resolve_on_path(name: &str) -> Option<PathBuf> {
    resolve_in(name, &std::env::var_os("PATH")?)
}

/// [`resolve_on_path`] against an explicit `PATH` value, so a test can use a
/// temp dir without touching the process environment.
pub fn resolve_in(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path).find_map(|dir| runnable_at(&dir.join(name)))
}

#[cfg(unix)]
fn runnable_at(candidate: &Path) -> Option<PathBuf> {
    is_executable_at(candidate).then(|| candidate.to_path_buf())
}

/// `candidate` plus the first `PATHEXT` suffix that `CreateProcess` (via std)
/// can start, else `candidate` itself when it already names such a file.
#[cfg(windows)]
fn runnable_at(candidate: &Path) -> Option<PathBuf> {
    let pathext = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSF;.MSC".to_string());
    let with_ext = pathext
        .split(';')
        .filter(|&ext| spawnable(ext))
        .map(|ext| {
            let mut p = candidate.as_os_str().to_os_string();
            p.push(ext);
            PathBuf::from(p)
        })
        .find(|p| p.is_file());
    with_ext.or_else(|| {
        let ext = candidate.extension()?.to_str()?;
        (spawnable(&format!(".{ext}")) && candidate.is_file()).then(|| candidate.to_path_buf())
    })
}

/// True for an extension `CreateProcess` (via std) can start: `.vbs`, `.js`
/// and the rest of `PATHEXT` need a host program, so `Command` cannot.
#[cfg(windows)]
fn spawnable(ext: &str) -> bool {
    [".com", ".exe", ".bat", ".cmd"]
        .iter()
        .any(|s| s.eq_ignore_ascii_case(ext))
}

/// True when `candidate` is something the shell could actually exec.
///
/// On unix that means the executable bit, not merely `is_file()`: a stray
/// `chmod 644` placeholder earlier on PATH would otherwise read as present
/// while the shell fails to run it — the check would report health where there
/// is none.
#[cfg(unix)]
pub fn is_executable_at(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(candidate)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// True when `candidate`, or `candidate` plus any `PATHEXT` suffix, is a file.
///
/// Windows resolves an extensionless name through `PATHEXT`, and the default
/// list is not just `.exe`. Node's global installs ship `.cmd` shims —
/// `prettier.cmd`, `eslint.cmd`, `markdownlint-cli2.cmd` — so hardcoding `.exe`
/// would report a large share of the CLIs hooks actually shell to as missing.
/// No executable-bit concept applies here; presence is the whole test.
#[cfg(windows)]
pub fn is_executable_at(candidate: &Path) -> bool {
    if candidate.is_file() {
        return true;
    }
    let pathext = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSF;.MSC".to_string());
    pathext.split(';').filter(|e| !e.is_empty()).any(|ext| {
        let mut with_ext = candidate.as_os_str().to_os_string();
        with_ext.push(ext);
        Path::new(&with_ext).is_file()
    })
}

/// How long the `forgectl` probe may take before the answer defaults to
/// "absent". A local PATH walk is microseconds; anything near this bound is a
/// stalled mount, not a slow disk.
const PROBE_BUDGET: Duration = Duration::from_millis(250);

/// Is `forgectl` installed on this machine?
///
/// Cached for the life of the process: a hook is a short-lived one-shot, PATH
/// cannot change under it, and the guards that call this may ask more than
/// once while composing a message.
///
/// **Bounded, because infallible is not the same as terminating.** [`on_path`]
/// calls `stat` on every `PATH` entry, and one entry on a dead NFS or autofs
/// mount blocks that syscall indefinitely — with the walk inline, the hook
/// would never exit, the harness timeout would fire, and a block the guard had
/// ALREADY DECIDED would never be delivered. So the walk runs on its own
/// thread against a deadline and the caller takes "absent" when the budget
/// runs out: a message without a suggestion, rather than a lost block. The
/// stalled thread is abandoned, which is safe precisely because a hook is a
/// one-shot process that is about to exit.
pub fn forgectl_present() -> bool {
    static PRESENT: OnceLock<bool> = OnceLock::new();
    *PRESENT.get_or_init(|| bounded(|| on_path("forgectl"), PROBE_BUDGET))
}

/// Run `work` with a deadline, answering `false` if it has not returned in
/// `budget` — or if it could not be started, or panicked.
///
/// Not `shell::run_bounded_with`, and not the `deadline` module: both bound a
/// **subprocess** — they spawn, poll `try_wait`, and kill. There is no process
/// here to kill. The work is an in-process `stat` loop, and the only way to
/// stop waiting on a blocking syscall without a process to signal is to stop
/// waiting on the *thread* running it. The budget is local and small for the
/// same reason: this is a message-composition probe, not a git spawn, so it
/// does not draw on the shared hook budget those helpers divide up.
///
/// **`Builder::spawn`, not `thread::spawn`**, which unwraps the OS result and
/// panics when thread creation fails (`EAGAIN` under fd or thread exhaustion).
/// The caller's panic hook converts an unwind to exit **1**, so that panic
/// would turn an already-decided block into a non-blocking error — the precise
/// outcome this module promises cannot happen. A spawn failure is just
/// "absent".
///
/// Generic over `work` so a test can bound something that will not answer;
/// a zero budget cannot test the timeout arm, because the work may finish and
/// queue its value before the receiver ever waits.
fn bounded<F>(work: F, budget: Duration) -> bool
where
    F: FnOnce() -> bool + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    // A send into a dropped channel is an ordinary `Err` here, not a panic —
    // the receiver having timed out is the expected outcome, not a fault. A
    // panic *inside* the thread drops `tx`, which the receiver reads as
    // `Disconnected` and answers `false`.
    if std::thread::Builder::new()
        .spawn(move || {
            let _ = tx.send(work());
        })
        .is_err()
    {
        return false;
    }
    rx.recv_timeout(budget).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_executable_file_is_not_a_cli() {
        let dir = tempfile::tempdir().unwrap();
        let inert = dir.path().join("cadence-capability-probe");
        std::fs::write(&inert, "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&inert, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                !is_executable_at(&inert),
                "a mode-644 file is not something the shell can exec"
            );
            std::fs::set_permissions(&inert, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(is_executable_at(&inert), "a mode-755 file is a CLI");
        }

        assert!(!is_executable_at(&dir.path().join("no-such-file")));
    }

    #[test]
    fn an_absent_name_does_not_resolve() {
        // Names a binary nobody ships, so the walk must come back false
        // whatever this machine's PATH holds. The control against a probe that
        // could not go the other way is `forgectl_present`'s live answer, which
        // differs by machine — assert only the direction that is machine-
        // independent.
        assert!(!on_path("cadence-hooks-no-such-binary-8f3a1c"));
    }

    #[test]
    fn resolve_in_returns_the_full_path_command_can_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().as_os_str();
        assert_eq!(resolve_in("cadence-resolve-probe", path), None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tool = dir.path().join("cadence-resolve-probe");
            std::fs::write(&tool, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(resolve_in("cadence-resolve-probe", path), None);
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(resolve_in("cadence-resolve-probe", path), Some(tool));
        }
        #[cfg(windows)]
        {
            let cmd = dir.path().join("cadence-resolve-probe.cmd");
            std::fs::write(&cmd, "@echo off\n").unwrap();
            assert_eq!(
                lowercase(resolve_in("cadence-resolve-probe", path)),
                lowercase(Some(cmd))
            );
        }
    }

    /// The suffix comes from `PATHEXT`, which is upper case (`.CMD`), and the
    /// file system ignores case, so compare paths without it.
    #[cfg(windows)]
    fn lowercase(path: Option<PathBuf>) -> Option<String> {
        path.map(|p| p.to_string_lossy().to_lowercase())
    }

    #[cfg(windows)]
    #[test]
    fn resolve_in_picks_an_npm_cmd_shim_over_its_sh_and_ps1_siblings() {
        // npm writes `name` (sh), `name.cmd` and `name.ps1`. `Command` cannot
        // start the sh or ps1 file, and `Command::new("name")` looks only for
        // `name.exe`, so the hook must be handed the `.cmd` path.
        let dir = tempfile::tempdir().unwrap();
        for file in ["markdownlint", "markdownlint.cmd", "markdownlint.ps1"] {
            std::fs::write(dir.path().join(file), "").unwrap();
        }
        assert_eq!(
            lowercase(resolve_in("markdownlint", dir.path().as_os_str())),
            lowercase(Some(dir.path().join("markdownlint.cmd")))
        );
        std::fs::remove_file(dir.path().join("markdownlint.cmd")).unwrap();
        assert_eq!(resolve_in("markdownlint", dir.path().as_os_str()), None);
    }

    #[test]
    fn work_that_outruns_its_budget_answers_absent() {
        // Stands in for the stalled mount a test cannot create: work that
        // will not answer inside the budget. NOT a zero budget — the work
        // could finish and queue its value before the receiver ever waits,
        // which makes a zero-budget assertion a race rather than a probe of
        // the timeout arm.
        assert!(!bounded(
            || {
                std::thread::sleep(Duration::from_millis(500));
                true
            },
            Duration::from_millis(10)
        ));
    }

    #[test]
    fn work_inside_its_budget_answers_truthfully() {
        // The control: without it, the test above would pass on a `bounded`
        // that had simply been hardcoded to `false`.
        assert!(bounded(|| true, Duration::from_secs(5)));
        assert!(!bounded(|| false, Duration::from_secs(5)));
    }

    #[test]
    fn a_panicking_probe_answers_absent_rather_than_unwinding() {
        // A panic in the thread drops the sender; the receiver reads
        // `Disconnected` and answers absent. It must not reach the caller,
        // whose panic hook would convert it to a non-blocking exit 1.
        assert!(!bounded(
            || panic!("probe exploded"),
            Duration::from_secs(5)
        ));
    }
}
