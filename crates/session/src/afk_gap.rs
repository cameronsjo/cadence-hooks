//! `session nudge-afk-gap` — UserPromptSubmit, **opt-in** (cadence-hooks#480).
//!
//! A session resumed after hours reads as one continuous conversation, so the
//! model carries stale premises forward: branch state, peer sessions, "just
//! pushed" claims. When the user submits a prompt after a long idle gap, this
//! hook injects one short line ("6 hours later…") so the model re-grounds.
//!
//! **Opt-in:** a clean no-op — no output, no file read or write — unless
//! `CADENCE_AFK_GAP` is truthy (`1`/`true`/`yes`). The threshold is
//! `CADENCE_AFK_GAP_MINUTES` (default 240, i.e. 4h); zero or unparsable
//! values fall back to the default.
//!
//! **State:** one private stamp per session, `<metrics_dir>/state/<sid>.afk-gap`
//! (the per-session state dir `log-session-start` and `snapshot` already use),
//! holding the Unix seconds of the last prompt. Written `0600` in a `0700`
//! directory on first creation.
//!
//! **Last activity** is the later of that stamp and the mtime of the session's
//! machine-wide registry mirror, which tool calls refresh through
//! `persist-plan-approval`'s throttled heartbeat. Without the mirror a long
//! autonomous run (prompt, five hours of tool calls, reply) would read as five
//! idle hours. A session outside a git repo has no mirror and falls back to the
//! prompt stamp alone.
//!
//! **Gated on state:** the first prompt a session is seen with records a stamp
//! and says nothing — there is no prior activity to measure from. A missing,
//! unreadable, or future-dated stamp is likewise silent. Every failure allows
//! (ADR-0001).

use crate::identity;
use crate::registry;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Enables the hook when truthy.
pub const ENABLE_VAR: &str = "CADENCE_AFK_GAP";
/// Overrides the idle threshold, in minutes.
pub const MINUTES_VAR: &str = "CADENCE_AFK_GAP_MINUTES";
/// Default threshold: 4 hours (the #480 ruling).
pub const DEFAULT_GAP_MINUTES: u64 = 240;

/// The stamp file's suffix under the per-session state dir.
const STAMP_SUFFIX: &str = "afk-gap";

/// Pure: whether the enable flag is set.
pub fn enabled_from(value: Option<&str>) -> bool {
    cadence_hooks_core::worktree::is_truthy(value)
}

/// Pure: the threshold in seconds from the minutes override.
pub fn threshold_secs_from(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&m| m > 0)
        .unwrap_or(DEFAULT_GAP_MINUTES)
        .saturating_mul(60)
}

/// Pure: the gap rendered as `6 hours` / `1 hour` / `45 minutes`.
fn gap_phrase(secs: u64) -> String {
    let hours = secs / 3600;
    if hours >= 1 {
        let unit = if hours == 1 { "hour" } else { "hours" };
        return format!("{hours} {unit}");
    }
    let minutes = (secs / 60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!("{minutes} {unit}")
}

/// Pure: the one line to inject, or `None` below the threshold.
///
/// `last_prompt` gates the whole thing: without a prior prompt this session
/// there is nothing to measure from. `last_tool` (the registry mirror's mtime)
/// only ever moves last activity later, never earlier. A last activity in the
/// future (clock skew, a restored stamp) is silent.
pub fn gap_line(
    last_prompt: Option<u64>,
    last_tool: Option<u64>,
    now: u64,
    threshold_secs: u64,
) -> Option<String> {
    let last = last_prompt?.max(last_tool.unwrap_or(0));
    let gap = now.checked_sub(last)?;
    if gap < threshold_secs {
        return None;
    }
    Some(format!(
        "{} later… This session sat idle since its last activity; re-check git state, \
         peer sessions, and earlier claims before relying on them.",
        gap_phrase(gap)
    ))
}

/// The stamp path for `session_id` under `state_dir`.
fn stamp_path(state_dir: &Path, session_id: &str) -> std::path::PathBuf {
    state_dir.join(format!("{session_id}.{STAMP_SUFFIX}"))
}

/// Read a stamp: Unix seconds as ASCII. Anything else reads as absent.
fn read_stamp(path: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.trim().parse::<u64>().ok()
}

/// A file's mtime in Unix seconds; `None` when absent or unreadable.
fn mtime_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    modified
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Create `dir` (and parents) owner-only on Unix. Existing directories keep
/// their mode.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Replace `path` with `contents`, owner-only (`0600`) on Unix: a fresh
/// `create_new` temp beside it (refuses a pre-planted symlink), then an atomic
/// rename (never follows a symlink at the target). A reader never sees a
/// half-written stamp.
pub(crate) fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let open = || {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&tmp)
    };
    let mut file = match open() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            open()?
        }
        Err(e) => return Err(e),
    };
    if let Err(e) = file.write_all(contents) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Testable core: read the previous stamp and the mirror mtime, record `now`,
/// and return the line to inject, if any. The stamp write is best-effort and
/// happens whether or not a line is returned.
pub fn observe_prompt(
    state_dir: &Path,
    mirror: Option<&Path>,
    session_id: &str,
    now: u64,
    threshold_secs: u64,
) -> Option<String> {
    let stamp = stamp_path(state_dir, session_id);
    let last_prompt = read_stamp(&stamp);
    let last_tool = mirror.and_then(mtime_secs);
    let _ = write_private(&stamp, now.to_string().as_bytes());
    gap_line(last_prompt, last_tool, now, threshold_secs)
}

/// Opt-in AFK gap marker on UserPromptSubmit.
pub struct NudgeAfkGap;

impl Check for NudgeAfkGap {
    fn name(&self) -> &str {
        "nudge-afk-gap"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Opt-in first: disabled means no I/O at all, not merely no output.
        if !enabled_from(std::env::var(ENABLE_VAR).ok().as_deref()) {
            return CheckResult::allow();
        }
        let Some(sid) = input
            .session_id()
            .filter(|s| identity::is_safe_session_id(s))
        else {
            return CheckResult::allow();
        };
        let threshold = threshold_secs_from(std::env::var(MINUTES_VAR).ok().as_deref());
        let mirror = registry::global_sessions_dir().join(identity::filename(sid));
        match observe_prompt(
            &cadence_hooks_metrics::common::state_dir(),
            Some(&mirror),
            sid,
            identity::now_epoch(),
            threshold,
        ) {
            Some(line) => CheckResult::nudge(line),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;

    #[test]
    fn enable_flag_table() {
        for (value, want) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("false"), false),
            (Some("no"), false),
            (Some("1"), true),
            (Some("true"), true),
            (Some(" YES "), true),
        ] {
            assert_eq!(enabled_from(value), want, "{value:?}");
        }
    }

    #[test]
    fn threshold_table() {
        for (value, want) in [
            (None, 4 * H),
            (Some(""), 4 * H),
            (Some("0"), 4 * H),
            (Some("-5"), 4 * H),
            (Some("abc"), 4 * H),
            (Some("90"), 90 * 60),
            (Some(" 360 "), 6 * H),
        ] {
            assert_eq!(threshold_secs_from(value), want, "{value:?}");
        }
    }

    #[test]
    fn gap_line_table() {
        let now = 100 * H;
        let t = 4 * H;
        // (last_prompt, last_tool, expected prefix or None)
        let cases: &[(Option<u64>, Option<u64>, Option<&str>)] = &[
            // First prompt this session: silent, whatever the mirror says.
            (None, None, None),
            (None, Some(now - 10 * H), None),
            // Below the threshold.
            (Some(now - 3 * H), None, None),
            (Some(now - t + 1), None, None),
            // At and above the threshold.
            (Some(now - t), None, Some("4 hours later…")),
            (Some(now - 6 * H - 59 * 60), None, Some("6 hours later…")),
            // Recent tool activity after an old prompt: not idle.
            (Some(now - 6 * H), Some(now - 60), None),
            // Tool activity older than the prompt never moves it earlier.
            (
                Some(now - 5 * H),
                Some(now - 50 * H),
                Some("5 hours later…"),
            ),
            // Future-dated activity (clock skew): silent.
            (Some(now + 10), None, None),
            (Some(now - 6 * H), Some(now + 10), None),
        ];
        for (prompt, tool, want) in cases {
            let got = gap_line(*prompt, *tool, now, t);
            match want {
                None => assert!(got.is_none(), "{prompt:?}/{tool:?} -> {got:?}"),
                Some(prefix) => {
                    let line = got.unwrap_or_else(|| panic!("{prompt:?}/{tool:?} -> None"));
                    assert!(line.starts_with(prefix), "{line}");
                }
            }
        }
    }

    #[test]
    fn gap_line_is_one_short_line() {
        let line = gap_line(Some(0), None, 30 * H, 4 * H).unwrap();
        assert!(!line.contains('\n'), "{line}");
        assert!(
            line.chars().count() <= 160,
            "{} chars",
            line.chars().count()
        );
    }

    #[test]
    fn gap_phrase_table() {
        for (secs, want) in [
            (30, "1 minute"),
            (60, "1 minute"),
            (45 * 60, "45 minutes"),
            (H, "1 hour"),
            (2 * H - 1, "1 hour"),
            (26 * H, "26 hours"),
        ] {
            assert_eq!(gap_phrase(secs), want, "{secs}");
        }
    }

    #[test]
    fn observe_prompt_records_then_measures() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let t = 4 * H;
        // First prompt: silent, stamp written.
        assert!(observe_prompt(&state, None, "sid-1", 10 * H, t).is_none());
        assert_eq!(read_stamp(&stamp_path(&state, "sid-1")), Some(10 * H));
        // Next prompt one hour later: silent, stamp moves.
        assert!(observe_prompt(&state, None, "sid-1", 11 * H, t).is_none());
        // Six hours later: the marker, and the stamp moves again.
        let line = observe_prompt(&state, None, "sid-1", 17 * H, t).unwrap();
        assert!(line.starts_with("6 hours later…"), "{line}");
        assert_eq!(read_stamp(&stamp_path(&state, "sid-1")), Some(17 * H));
        // Another session's stamp is its own.
        assert!(observe_prompt(&state, None, "sid-2", 40 * H, t).is_none());
    }

    #[test]
    fn observe_prompt_treats_a_corrupt_stamp_as_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().to_path_buf();
        std::fs::write(stamp_path(&state, "sid"), "not a number").unwrap();
        assert!(observe_prompt(&state, None, "sid", 99 * H, 4 * H).is_none());
        assert_eq!(read_stamp(&stamp_path(&state, "sid")), Some(99 * H));
    }

    #[test]
    fn observe_prompt_reads_the_mirror_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let mirror = tmp.path().join("mirror.json");
        std::fs::write(&mirror, "{}").unwrap();
        let now = identity::now_epoch();
        write_private(
            &stamp_path(&state, "sid"),
            (now - 6 * H).to_string().as_bytes(),
        )
        .unwrap();
        // The mirror was just written, so the session was active moments ago.
        assert!(observe_prompt(&state, Some(&mirror), "sid", now, 4 * H).is_none());
    }

    #[test]
    fn observe_prompt_survives_an_unwritable_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular file where the directory should be: every write fails.
        let blocker = tmp.path().join("state");
        std::fs::write(&blocker, "").unwrap();
        assert!(observe_prompt(&blocker, None, "sid", 10 * H, 4 * H).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn stamp_and_dir_are_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("fresh").join("state");
        observe_prompt(&state, None, "sid", 10 * H, 4 * H);
        let file_mode = std::fs::metadata(stamp_path(&state, "sid"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn stamp_write_does_not_follow_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let target = tmp.path().join("victim");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, stamp_path(&state, "sid")).unwrap();
        observe_prompt(&state, None, "sid", 10 * H, 4 * H);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    /// End to end through `Check::run`, per enable-flag value: a disabled
    /// hook emits nothing AND touches nothing; an enabled one records on the
    /// first prompt and marks the gap on a prompt after an aged stamp.
    #[test]
    fn run_is_inert_unless_enabled() {
        let input = cadence_hooks_core::test_builders::make_user_prompt_submit(
            "afk-run-sid",
            "hi",
            "/tmp",
            "/tmp/t.jsonl",
        );
        for (flag, enabled) in [(None, false), (Some("0"), false), (Some("1"), true)] {
            let tmp = tempfile::tempdir().unwrap();
            let metrics = tmp.path().to_str().unwrap().to_string();
            let stamp = stamp_path(&tmp.path().join("state"), "afk-run-sid");
            crate::registry::test_metrics_env::with_env_vars(
                &[
                    (ENABLE_VAR, flag),
                    (MINUTES_VAR, None),
                    ("CADENCE_METRICS_DIR", Some(&metrics)),
                ],
                || {
                    let first = NudgeAfkGap.run(&input);
                    assert!(first.message.is_none(), "{flag:?}: first prompt spoke");
                    assert_eq!(stamp.exists(), enabled, "{flag:?}: stamp presence");
                    if !enabled {
                        assert!(
                            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
                            "{flag:?}: a disabled hook wrote into the metrics dir"
                        );
                        return;
                    }
                    let aged = identity::now_epoch() - 5 * H;
                    write_private(&stamp, aged.to_string().as_bytes()).unwrap();
                    let second = NudgeAfkGap.run(&input);
                    let msg = second.message.expect("enabled hook should mark the gap");
                    assert!(msg.starts_with("5 hours later…"), "{msg}");
                },
            );
        }
    }
}
