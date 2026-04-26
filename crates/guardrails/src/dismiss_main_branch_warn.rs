//! Per-repo snooze for the `warn-main-branch` hook.
//!
//! Exposes:
//! - `is_snoozed_now(repo_root)` — used by `warn-main-branch` to skip its nudge
//! - `run_dismiss(duration_str)` — the `dismiss-main-branch-warn` subcommand entry point
//!
//! The marker file lives at `<repo_root>/.git/cadence-hooks/main-branch-snoozed-until`
//! and contains a single Unix epoch-seconds line. `.git/` is gitignored by
//! default, so the marker never accidentally gets committed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
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
    let (num_part, unit) = s.split_at(s.len() - 1);
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

/// Marker file path for a given repo root.
pub fn marker_path(repo_root: &Path) -> PathBuf {
    repo_root.join(SNOOZE_DIR).join(SNOOZE_FILE)
}

/// Pure: given the marker contents and current epoch, is the snooze active?
fn is_snoozed_at(marker_contents: &str, now_epoch: u64) -> bool {
    let parsed: Option<u64> = marker_contents.trim().parse().ok();
    matches!(parsed, Some(until) if until > now_epoch)
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

/// Convenience: read the marker for the current repo and decide if it's still
/// active. Used by `warn-main-branch` before evaluating its own logic.
pub fn is_snoozed_now() -> bool {
    let Some(root) = repo_root() else {
        return false;
    };
    let path = marker_path(&root);
    let Ok(contents) = fs::read_to_string(&path) else {
        return false;
    };
    is_snoozed_at(&contents, now_epoch())
}

/// Entry point for the `dismiss-main-branch-warn` subcommand.
///
/// Writes `<repo_root>/.git/cadence-hooks/main-branch-snoozed-until` with the
/// epoch seconds when the snooze expires, then prints a confirmation. Exits 1
/// on failure (missing repo, invalid duration, write error). Stays at exit 0
/// on success — this is a user-facing CLI, not a hook.
pub fn run_dismiss(duration_str: &str) -> ! {
    let duration = match parse_duration(duration_str) {
        Some(d) => d,
        None => {
            eprintln!(
                "cadence-hooks: invalid duration '{duration_str}'\n   \
                 Expected: <number><s|m|h|d>, e.g. `30m`, `2h`, `1d`"
            );
            process::exit(1);
        }
    };

    let secs = duration.as_secs();
    if secs > MAX_SNOOZE_SECONDS {
        eprintln!(
            "cadence-hooks: snooze duration capped at 24h (got {duration_str})\n   \
             Re-run with a smaller window, or run again later to renew."
        );
        process::exit(1);
    }

    let Some(root) = repo_root() else {
        eprintln!(
            "cadence-hooks: not inside a git repository\n   \
             dismiss-main-branch-warn must be run from within the repo you want to silence."
        );
        process::exit(1);
    };

    let path = marker_path(&root);
    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("cadence-hooks: could not create {}: {e}", parent.display());
        process::exit(1);
    }

    let until = now_epoch().saturating_add(secs);
    if let Err(e) = fs::write(&path, format!("{until}\n")) {
        eprintln!("cadence-hooks: could not write {}: {e}", path.display());
        process::exit(1);
    }

    println!(
        "warn-main-branch silenced for {duration_str} in {} (until epoch {until})",
        root.display()
    );
    process::exit(0);
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

    // --- is_snoozed_at (pure decision) ---

    #[test]
    fn snoozed_when_marker_in_future() {
        assert!(is_snoozed_at("2000000000", 1_000_000_000));
    }

    #[test]
    fn not_snoozed_when_marker_in_past() {
        assert!(!is_snoozed_at("100", 1_000_000_000));
    }

    #[test]
    fn not_snoozed_when_marker_equal_to_now() {
        // Exactly-equal counts as expired — the snooze window is exclusive at
        // its upper bound, otherwise a zero-duration snooze would briefly fire.
        assert!(!is_snoozed_at("1000", 1000));
    }

    #[test]
    fn not_snoozed_when_marker_unparseable() {
        assert!(!is_snoozed_at("not-a-number", 1_000_000_000));
        assert!(!is_snoozed_at("", 1_000_000_000));
    }

    #[test]
    fn snoozed_tolerates_trailing_newline() {
        assert!(is_snoozed_at("2000000000\n", 1_000_000_000));
    }

    // --- marker_path ---

    #[test]
    fn marker_path_is_under_dot_git() {
        let p = marker_path(Path::new("/tmp/repo"));
        assert_eq!(
            p,
            Path::new("/tmp/repo/.git/cadence-hooks/main-branch-snoozed-until")
        );
    }
}
