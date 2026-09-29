//! Claude Code cloud sessions (`CLAUDE_CODE_REMOTE=true`).
//!
//! A cloud VM is a fresh clone with no local `~/.claude` state, so a few hooks
//! change behavior there: the binary's dispatch consults each registry entry's
//! remote policy, `enforcement-status` reports ARMED/INERT, and
//! `warn-commit-provenance` stamps a fixed `Machine:` value. This module owns
//! the one predicate they share (cameronsjo/cadence-hooks#1197).

/// The env var Claude Code sets in a cloud session.
pub const REMOTE_VAR: &str = "CLAUDE_CODE_REMOTE";

/// The `Machine:` value a cloud session stamps: a hostname digest is
/// meaningless in a throwaway VM.
pub const CLOUD_MACHINE: &str = "cloud";

/// True when `value` is exactly `true`. Anything else, including `1` or `TRUE`,
/// is not a cloud session, mirroring how Claude Code sets it.
#[must_use]
pub fn is_remote_from(value: Option<&str>) -> bool {
    value == Some("true")
}

/// True when the process env says this is a cloud session.
#[must_use]
pub fn is_remote() -> bool {
    is_remote_from(std::env::var(REMOTE_VAR).ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_string_true_is_remote() {
        assert!(is_remote_from(Some("true")));
        for v in [
            None,
            Some(""),
            Some("1"),
            Some("TRUE"),
            Some("false"),
            Some(" true"),
        ] {
            assert!(!is_remote_from(v), "{v:?}");
        }
    }
}
