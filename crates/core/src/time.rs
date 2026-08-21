//! Portable current-time formatting.
//!
//! The bash hooks — and their first Rust port — shelled out to `date -u
//! +%FORMAT` to avoid pulling a date/time crate into the workspace. That
//! breaks on native Windows: `cmd`'s `date` builtin does not understand
//! `+FORMAT`, and a `cd`-less `date` prompts interactively. Worse, the cron
//! nudge needs *local* time plus a timezone abbreviation and weekday, which the
//! standard library cannot produce (it exposes UTC instants only).
//!
//! So one canonical timestamp source lives here, backed by [`jiff`]. It is the
//! single place that knows how to render the current time, replacing four
//! separate `date` shell-outs across the workspace.

use jiff::{Timestamp, Zoned};

/// Current UTC timestamp, ISO 8601 second precision (`2026-06-05T13:59:56Z`).
///
/// The canonical machine timestamp for ledger/metrics records. Always 20 chars,
/// always ends in `Z`. The format string is static and valid, so formatting
/// cannot fail — there is no empty-string fallback to worry about (unlike the
/// `date` shell-out it replaces, which returned `""` when `date` was missing).
pub fn utc_timestamp() -> String {
    Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Current LOCAL calendar date, `%Y-%m-%d` (e.g. `2026-07-20`).
///
/// Distinct from [`utc_timestamp`]: filenames that carry a date (e.g. the
/// `docs/plans/YYYY-MM-DD-<slug>.md` convention `session persist-plan-approval` writes
/// into) use the author's local calendar day, matching every hand-authored
/// plan file — a UTC-derived date would occasionally be a day off from what
/// the session experienced. `Zoned::now()` resolves the system time zone,
/// falling back to UTC if the platform cannot report one (never panicking).
pub fn local_date() -> String {
    jiff::Zoned::now().strftime("%Y-%m-%d").to_string()
}

/// Human-facing current-datetime context for the cron-scheduling nudge.
///
/// CronCreate pins to exact calendar dates in the user's **local** time, so the
/// agent needs the local wall clock, its timezone abbreviation, and the
/// weekday — not just a UTC instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronDatetime {
    /// Local time with timezone abbreviation, e.g. `2026-06-05 08:59:56 CDT`.
    pub local: String,
    /// The same instant in UTC, e.g. `2026-06-05 13:59:56 UTC`.
    pub utc: String,
    /// Full local weekday name, e.g. `Friday`.
    pub weekday: String,
}

/// Build the current [`CronDatetime`] from the system clock and time zone.
///
/// `Zoned::now()` resolves the system time zone (falling back to UTC if the
/// platform cannot report one — never panicking), so `%Z`/`%A` always render.
pub fn cron_datetime() -> CronDatetime {
    let now = Zoned::now();
    CronDatetime {
        local: now.strftime("%Y-%m-%d %H:%M:%S %Z").to_string(),
        utc: now
            .timestamp()
            .strftime("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        weekday: now.strftime("%A").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_timestamp_has_iso_shape() {
        let ts = utc_timestamp();
        // e.g. 2026-05-19T00:51:45Z — 20 chars, ends in Z.
        assert!(ts.ends_with('Z'), "timestamp should end in Z: {ts}");
        assert_eq!(ts.len(), 20, "ISO second-precision UTC is 20 chars: {ts}");
    }

    #[test]
    fn utc_timestamp_is_never_empty() {
        // Unlike the `date` shell-out it replaces, jiff cannot fail here.
        assert!(!utc_timestamp().is_empty());
    }

    #[test]
    fn local_date_has_iso_date_shape() {
        let d = local_date();
        // e.g. 2026-07-20 — 10 chars, two dashes.
        assert_eq!(d.len(), 10, "ISO calendar date is 10 chars: {d}");
        assert_eq!(d.matches('-').count(), 2, "two dashes: {d}");
    }

    #[test]
    fn cron_datetime_fields_are_populated() {
        let dt = cron_datetime();
        assert!(!dt.local.is_empty(), "local should render: {dt:?}");
        assert!(dt.utc.ends_with("UTC"), "utc should end in UTC: {}", dt.utc);
        assert!(
            dt.utc.starts_with(|c: char| c.is_ascii_digit()),
            "utc should start with the year: {}",
            dt.utc
        );
        // Weekday is a non-empty alphabetic name on every locale jiff supports.
        assert!(
            dt.weekday.chars().all(|c| c.is_alphabetic()) && !dt.weekday.is_empty(),
            "weekday should be an alphabetic name: {}",
            dt.weekday
        );
    }
}
