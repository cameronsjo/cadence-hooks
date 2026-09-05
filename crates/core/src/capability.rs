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

use std::path::Path;
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
    *PRESENT.get_or_init(|| bounded_on_path("forgectl", PROBE_BUDGET))
}

/// [`on_path`] with a deadline: `false` if it has not answered in `budget`.
///
/// Not `shell::run_bounded_with`, and not the `deadline` module: both bound a
/// **subprocess** — they spawn, poll `try_wait`, and kill. There is no process
/// here to kill. `on_path` is an in-process `stat` loop, and the only way to
/// stop waiting on a blocking syscall without a process to signal is to stop
/// waiting on the *thread* running it. The budget is local and small for the
/// same reason: this is a message-composition probe, not a git spawn, so it
/// does not draw on the shared hook budget those helpers divide up.
fn bounded_on_path(name: &'static str, budget: Duration) -> bool {
    let (tx, rx) = mpsc::channel();
    // A send into a dropped channel is an ordinary `Err` here, not a panic —
    // the receiver having timed out is the expected outcome, not a fault.
    std::thread::spawn(move || {
        let _ = tx.send(on_path(name));
    });
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
    fn presence_is_stable_within_a_process() {
        assert_eq!(forgectl_present(), forgectl_present());
    }

    #[test]
    fn an_exhausted_budget_answers_absent() {
        // A zero budget cannot be met, so this asserts the timeout arm itself
        // rather than the walk — the arm that stands in for a stalled mount,
        // which a test cannot create. The control is the same probe with a
        // real budget, which must be able to answer either way.
        assert!(!bounded_on_path("sh", Duration::ZERO));
        let _ = bounded_on_path("sh", Duration::from_millis(250));
    }
}
