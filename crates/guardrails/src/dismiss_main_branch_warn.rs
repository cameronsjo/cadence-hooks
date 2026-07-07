//! Per-session snooze for the `warn-main-branch` hook (#135).
//!
//! Exposes:
//! - `is_snoozed_now(input, repo_root)` — used by `warn-main-branch` to skip its nudge
//! - `run_dismiss(duration_str)` — the `dismiss-main-branch-warn` subcommand entry point
//!
//! The snooze is **session-scoped**: each session dismisses the nudge for itself,
//! and that consent does not transfer to peer sessions sharing the checkout. The
//! marker lives in the private per-user marker dir (via
//! [`cadence_hooks_core::markers::session_marker`], kind `main-branch-snooze`),
//! keyed on the session id + repo hash, and holds a single Unix epoch-seconds
//! expiry line. The 24h cap is enforced on **read** as well as write (clamped to
//! `mtime + 24h`), so a tampered far-future body can't outlive the window.
//!
//! The legacy `<repo_root>/.git/cadence-hooks/main-branch-snoozed-until` location
//! is no longer read or written by the snooze logic; [`marker_path`] is retained
//! only as the distinctness reference the `dismiss-enforce-worktree` snooze pins
//! against (its marker must differ from this one). Stale legacy files are
//! orphaned harmlessly.

use crate::snooze_meta::{self, DismissArmed, SnoozeMeta};
use cadence_hooks_core::HookInput;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNOOZE_DIR: &str = ".git/cadence-hooks";
const SNOOZE_FILE: &str = "main-branch-snoozed-until";
/// Cap to keep the safety guarantee meaningful — a stale snooze lingering for
/// weeks would silently disable the warning long after the user forgot it
/// existed. 24h forces the user to renew if they really want it.
const MAX_SNOOZE_SECONDS: u64 = 24 * 60 * 60;

/// Parse a duration string like `30m`, `2h`, `1d`, or `45s`.
///
/// Returns `None` for malformed input or non-positive values. Bare numbers
/// (no unit) are rejected — the unit is required so users don't get bitten
/// by ambiguity (`30` could plausibly be seconds or minutes).
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Split before the final *character* — a byte index panics mid-char when
    // the value ends in a multibyte char (e.g. `--for 5€`).
    let (num_part, unit) = s.split_at(s.char_indices().last().map(|(i, _)| i)?);
    let n: u64 = num_part.parse().ok()?;
    if n == 0 {
        return None;
    }
    let secs_per_unit: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    n.checked_mul(secs_per_unit).map(Duration::from_secs)
}

/// Legacy `.git/`-relative marker path, retained ONLY as the distinctness
/// reference the `dismiss-enforce-worktree` snooze pins against (its marker must
/// differ from the main-branch one). The session-scoped snooze no longer reads
/// or writes here — see [`session_snooze_marker`].
pub fn marker_path(repo_root: &Path) -> PathBuf {
    repo_root.join(SNOOZE_DIR).join(SNOOZE_FILE)
}

/// The session-scoped snooze marker: private per-user dir, keyed on the session
/// id + repo hash. Both writer (`run_dismiss`) and reader ([`is_snoozed_now`])
/// resolve it through this one helper so the paths always agree.
fn session_snooze_marker(input: &HookInput, repo_root: &Path) -> PathBuf {
    cadence_hooks_core::markers::session_marker(
        input,
        "main-branch-snooze",
        Some(&repo_root.to_string_lossy()),
    )
}

/// Read the provenance sidecar for this session's active snooze of `repo_root`.
/// `None` when the sidecar is missing/unreadable (a snooze armed before this
/// feature, or a fail-open sidecar write) — the guard then attributes the bypass
/// with a `None` reason and still allows. Resolved through the same session
/// marker as the read path, so the key always agrees.
pub fn read_meta(input: &HookInput, repo_root: &Path) -> Option<SnoozeMeta> {
    let sidecar = snooze_meta::sidecar_for(&session_snooze_marker(input, repo_root));
    SnoozeMeta::read(&sidecar)
}

/// Pure: is the session snooze active, with the parsed expiry **clamped** to
/// `mtime_epoch + MAX_SNOOZE_SECONDS`? The 24h cap is thereby enforced on read,
/// not just at write time — a marker whose body was tampered to a far-future
/// epoch still expires 24h after it was last written (the second half of #135).
fn is_snoozed_clamped(marker_contents: &str, mtime_epoch: u64, now_epoch: u64) -> bool {
    let Some(parsed) = marker_contents.trim().parse::<u64>().ok() else {
        return false;
    };
    let cap = mtime_epoch.saturating_add(MAX_SNOOZE_SECONDS);
    parsed.min(cap) > now_epoch
}

/// A file's mtime as Unix epoch seconds, `None` when unreadable.
fn file_mtime_epoch(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The Claude Code session id for the dismiss CLI, from `CLAUDE_CODE_SESSION_ID`
/// (exported into the Bash tool environment). Empty/unset → `None`.
///
/// `pub(crate)` so the sibling `dismiss-enforce-worktree` snooze records the same
/// arming session in its provenance sidecar.
pub(crate) fn session_id_from_env() -> Option<String> {
    std::env::var("CLAUDE_CODE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Locate the current repo root via `git rev-parse --show-toplevel`.
/// Returns None if not in a git repo or git is unavailable.
fn repo_root() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read this session's snooze marker for `repo_root` and decide if it's still
/// active. Used by `warn-main-branch` before evaluating its own logic.
///
/// Session-scoped (#135): a peer session's snooze never suppresses this
/// session's nudge. The caller resolves `repo_root` via the same `git -C` query
/// that drove branch detection, so the snooze key matches the marker write even
/// when the hook fires inside a nested repo. The parsed expiry is clamped to
/// `mtime + 24h` on read, so a tampered body can't outlive the cap.
pub fn is_snoozed_now(input: &HookInput, repo_root: &Path) -> bool {
    let path = session_snooze_marker(input, repo_root);
    let Ok(contents) = fs::read_to_string(&path) else {
        return false;
    };
    let mtime = file_mtime_epoch(&path).unwrap_or(0);
    is_snoozed_clamped(&contents, mtime, now_epoch())
}

/// The dismiss mechanism name recorded in bypass provenance.
const MECHANISM: &str = "dismiss-main-branch-warn";

/// Perform the `dismiss-main-branch-warn` action: validate, gate on `--reason`,
/// write the session-scoped snooze marker **and** its provenance sidecar (both
/// in the private marker dir, symlink-safe). Returns [`DismissArmed`] for the
/// binary to log + confirm.
///
/// Prints every error to stderr and returns `Err(())` (the binary exits 1) — no
/// session id, missing repo, invalid duration, over-cap, or a missing `--reason`
/// for a snooze longer than 1h. On success prints nothing and returns `Ok`.
///
/// The load-bearing marker stays exactly `{until}\n`; provenance rides in the
/// sibling sidecar. The sidecar write is best-effort — a failure warns but does
/// not fail the snooze (ADR-0001).
///
/// The `Err` is unit on purpose: this function prints every error to stderr
/// itself, so the caller only needs pass/fail to pick an exit code.
#[allow(clippy::result_unit_err)]
pub fn perform_dismiss(duration_str: &str, reason: Option<&str>) -> Result<DismissArmed, ()> {
    let duration = match parse_duration(duration_str) {
        Some(d) => d,
        None => {
            eprintln!(
                "cadence-hooks: invalid duration '{duration_str}'\n   \
                 Expected: <number><s|m|h|d>, e.g. `30m`, `2h`, `1d`"
            );
            return Err(());
        }
    };

    let secs = duration.as_secs();
    if secs > MAX_SNOOZE_SECONDS {
        eprintln!(
            "cadence-hooks: snooze duration capped at 24h (got {duration_str})\n   \
             Re-run with a smaller window, or run again later to renew."
        );
        return Err(());
    }

    // Reason gate: required over 1h, nudged at or under.
    let nudge = match snooze_meta::reason_gate(secs, reason, MECHANISM, duration_str) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("{msg}");
            return Err(());
        }
    };

    // The snooze is session-scoped, so it needs the session id at write time.
    let Some(session_id) = session_id_from_env() else {
        eprintln!(
            "cadence-hooks: no Claude Code session id\n   \
             Run dismiss-main-branch-warn inside a Claude Code session \
             (or export CLAUDE_CODE_SESSION_ID)."
        );
        return Err(());
    };

    let Some(root) = repo_root() else {
        eprintln!(
            "cadence-hooks: not inside a git repository\n   \
             dismiss-main-branch-warn must be run from within the repo you want to silence."
        );
        return Err(());
    };

    let input = HookInput {
        session_id: Some(session_id.clone()),
        ..Default::default()
    };
    let path = session_snooze_marker(&input, &root);

    let armed_at = now_epoch();
    let until = armed_at.saturating_add(secs);
    if let Err(e) = cadence_hooks_core::markers::write_marker(&path, &format!("{until}\n")) {
        eprintln!("cadence-hooks: could not write {}: {e}", path.display());
        return Err(());
    }

    // Provenance sidecar — best-effort, symlink-safe like the marker.
    let reason = snooze_meta::normalize_reason(reason);
    let meta = SnoozeMeta {
        reason: reason.clone(),
        session_id: Some(session_id.clone()),
        armed_at: Some(armed_at as i64),
        expires_at: Some(until as i64),
    };
    let sidecar = snooze_meta::sidecar_for(&path);
    if let Err(e) = cadence_hooks_core::markers::write_marker(&sidecar, &meta.to_json()) {
        eprintln!(
            "cadence-hooks: note — snooze set, but provenance sidecar could not be written: {e}"
        );
    }

    let mut confirmation = format!(
        "warn-main-branch silenced for this session for {duration_str} in {} (until epoch {until})",
        root.display()
    );
    if let Some(n) = nudge {
        confirmation.push_str("\n   ");
        confirmation.push_str(&n);
    }

    Ok(DismissArmed {
        guard_hook: "warn-main-branch",
        mechanism: MECHANISM,
        reason,
        session_id: Some(session_id),
        repo_root: Some(root.to_string_lossy().into_owned()),
        armed_at: armed_at as i64,
        expires_at: until as i64,
        confirmation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_duration ---

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86400)));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("45s"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn parse_duration_rejects_bare_number() {
        assert_eq!(parse_duration("30"), None);
    }

    #[test]
    fn parse_duration_rejects_unknown_unit() {
        assert_eq!(parse_duration("30y"), None);
    }

    #[test]
    fn parse_duration_rejects_multibyte_unit() {
        // A multibyte final char must reject, not panic — `5€`'s len-1 is not
        // a char boundary, so a byte-index split_at would panic mid-char.
        assert_eq!(parse_duration("5€"), None);
    }

    #[test]
    fn parse_duration_rejects_zero() {
        // Zero would write a marker that's instantly expired — useless and
        // confusing. Reject it so users get an error instead of silence.
        assert_eq!(parse_duration("0m"), None);
    }

    #[test]
    fn parse_duration_rejects_empty() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("   "), None);
    }

    #[test]
    fn parse_duration_rejects_negative() {
        // u64 parse rejects the leading `-`, so this is a no-op assertion that
        // documents the contract: only positive values are accepted.
        assert_eq!(parse_duration("-30m"), None);
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  30m  "), Some(Duration::from_secs(1800)));
    }

    // --- marker_path ---

    #[test]
    fn marker_path_is_under_dot_git() {
        // Legacy path retained as the enforce-worktree distinctness reference.
        let p = marker_path(Path::new("/tmp/repo"));
        assert_eq!(
            p,
            Path::new("/tmp/repo/.git/cadence-hooks/main-branch-snoozed-until")
        );
    }

    // --- session-scoped snooze (#135) ---

    fn input_with_session(sid: &str) -> HookInput {
        HookInput {
            session_id: Some(sid.into()),
            ..Default::default()
        }
    }

    #[test]
    fn snooze_is_session_scoped() {
        // A snooze set by session A must not silence the nudge for peer session B
        // sharing the same checkout — consent doesn't transfer (#135).
        let repo = Path::new("/tmp/cp0-snooze-scope-repo");
        let input_a = input_with_session("snooze-scope-a");
        let input_b = input_with_session("snooze-scope-b");
        let path_a = session_snooze_marker(&input_a, repo);
        let until = now_epoch() + 3600;
        cadence_hooks_core::markers::write_marker(&path_a, &format!("{until}\n")).unwrap();

        assert!(is_snoozed_now(&input_a, repo), "A's own snooze is active");
        assert!(
            !is_snoozed_now(&input_b, repo),
            "B is not snoozed by A's marker"
        );

        let _ = fs::remove_file(&path_a);
    }

    #[test]
    fn read_path_clamps_expiry_to_cap() {
        // A body tampered to a far-future epoch (year ~2100) is snoozed right
        // after write, but the 24h read clamp expires it once we pass mtime+24h.
        let mtime = 1_000_000_000;
        let far_future = "4102444800"; // ~2100-01-01
        assert!(
            is_snoozed_clamped(far_future, mtime, mtime + 60),
            "fresh far-future marker reads as snoozed within the cap"
        );
        assert!(
            !is_snoozed_clamped(far_future, mtime, mtime + MAX_SNOOZE_SECONDS + 1),
            "past mtime + 24h the clamp expires it despite the 2100 body"
        );
    }

    #[test]
    fn clamp_allows_normal_snooze_within_cap() {
        // A within-cap 1h snooze behaves normally: active until its own expiry.
        let mtime = 1_000_000_000;
        let until = mtime + 3600;
        assert!(is_snoozed_clamped(&until.to_string(), mtime, mtime + 60));
        assert!(!is_snoozed_clamped(&until.to_string(), mtime, until + 1));
    }

    #[test]
    fn clamp_rejects_unparseable() {
        assert!(!is_snoozed_clamped(
            "not-a-number",
            1_000_000_000,
            1_000_000_000
        ));
        assert!(!is_snoozed_clamped("", 1_000_000_000, 1_000_000_000));
    }
}
