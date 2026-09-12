//! The single resolver for the two enforcement switches, `CADENCE_BYPASS` and
//! `CADENCE_DISABLE`.
//!
//! # Why this lives in `core` and not in the binary
//!
//! Before cameronsjo/cadence-hooks#567 the resolution was written out four
//! times — the `list` display, the blanket bypass in `main`, the selective
//! disable in `main`, and `guard-rm-liveness`'s own copy in the `guardrails`
//! crate. The liveness check is the one component whose job is to report that
//! `guard-rm` has been switched off, and it could only observe that state by
//! re-implementing the parse, because the enforcement logic lived in `main`
//! where a library crate cannot reach it.
//!
//! That made the duplication load-bearing in an asymmetric way: if one copy
//! ever accepted a form another rejected, the binary could skip a guard while
//! the check reported healthy. The failure mode is not "two copies disagree",
//! it is **false reassurance from the detector**. Living in `core` lets every
//! consumer — binary and library alike — call the same function.
//!
//! # Precedence
//!
//! Resolution is a fixed three-step ladder. The first rule that matches wins.
//!
//! | # | Condition | Result | Does the hook run? |
//! |---|-----------|--------|--------------------|
//! | 1 | `CADENCE_BYPASS` is exactly `1` | [`BypassState::Bypassed`] | no |
//! | 2 | the hook's name is listed in `CADENCE_DISABLE` **and** the hook is in [`PROTECTED_GUARDS`] | [`BypassState::DisableRefused`] | yes — loudly |
//! | 3 | the hook's name is listed in `CADENCE_DISABLE` | [`BypassState::Disabled`] | no |
//! | — | otherwise | [`BypassState::Enforced`] | yes |
//!
//! `CADENCE_BYPASS` outranks `CADENCE_DISABLE` because it is the loud,
//! per-session maintenance escape: it announces itself on stderr and cannot be
//! left switched on in a settings file the way `CADENCE_DISABLE` can. Rule 2
//! sits ahead of rule 3 so that no value of the silent, persistent variable can
//! neuter a guard that prevents irreversible harm (#89).
//!
//! # Scoping
//!
//! - `CADENCE_BYPASS` is **process-wide**: it takes no hook name and switches
//!   off every enforcement path at once. The binary exempts its CLI and
//!   diagnostic subcommands from it by argv position (`is_bypass_exempt` in
//!   `main`) — that is a question about *commands*, not about this resolution,
//!   so it stays in the binary.
//! - `CADENCE_DISABLE` is **per hook name**: a comma-separated list matched
//!   against the canonical registry name, exactly, case-sensitively, after
//!   trimming surrounding whitespace from each entry. Empty entries are
//!   ignored, so `a,,b` and `a, b` both name `a` and `b`.
//!
//! # Unknown values fail toward ENFORCED
//!
//! Every ambiguous input resolves to the hook still running:
//!
//! - `CADENCE_BYPASS` set to anything other than the exact string `1` —
//!   `true`, `yes`, `0`, `01`, ` 1`, the empty string — is **not** a bypass.
//!   The variable is a switch with one on-position, not a truthiness test, so a
//!   value nobody defined can never silently disarm the binary.
//! - A `CADENCE_DISABLE` entry that matches no registered hook disables
//!   nothing. A near-miss (`Guard-Rm`, `guard_rm`, `guard-rm-liveness` when
//!   `guard-rm` was meant) is a near-miss, not a fuzzy match.
//! - Either variable holding non-UTF-8 bytes reads as unset.
//!
//! The direction is deliberate and is the whole point of the extraction:
//! failing the other way would mean a typo could switch a guard off, and the
//! operator would have no way to tell that from an intended disable.

/// Guards that prevent irreversible harm — secret exposure, data loss,
/// destructive git/gh/remote/vault operations. `CADENCE_DISABLE` (silent,
/// persistent, settable in settings.json `env`) must not be able to neuter
/// these; only the loud, per-session `CADENCE_BYPASS` can (#89).
pub const PROTECTED_GUARDS: &[&str] = &[
    "prevent-secret-leaks",
    "prevent-secret-writes",
    // Carries the fail-closed identity tier. Protection is per-guard, so this
    // also strips CADENCE_DISABLE from the same guard's *advisory* tiers —
    // accepted deliberately (ruled 2026-08-03): the alternative was splitting
    // one guard in two, and the remaining levers for a noisy nudge are the
    // per-repo allowlist and originAudience, both config edits. Without this
    // line, one environment variable silently disarms the leak protection.
    "redact-external-content",
    "git-safety",
    "guard-push-remote",
    "guard-gh-dangerous",
    "guard-gh-write",
    "guard-op-vault-scan",
    "guard-sops-decrypt",
    "guard-browser-device",
    "guard-dotfiles",
    "guard-read-model",
    "trash-guard",
];

/// The blanket, per-session maintenance escape.
pub const BYPASS_VAR: &str = "CADENCE_BYPASS";

/// The selective, per-hook-name disable list.
pub const DISABLE_VAR: &str = "CADENCE_DISABLE";

/// The one value of [`BYPASS_VAR`] that engages the bypass.
pub const BYPASS_ON: &str = "1";

/// Whether a named hook is enforcing, and which switch decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassState {
    /// Nothing switched this hook off. It runs.
    Enforced,
    /// `CADENCE_BYPASS=1` — every hook is off for this session.
    Bypassed,
    /// Named in `CADENCE_DISABLE` and not protected. The hook is skipped.
    Disabled,
    /// Named in `CADENCE_DISABLE` but protected, so the request is refused and
    /// the hook runs anyway. Distinct from [`BypassState::Enforced`] because
    /// the operator asked for something that did not happen, and every surface
    /// owes them that fact rather than silently agreeing or silently refusing.
    DisableRefused,
}

impl BypassState {
    /// Whether the hook actually runs.
    ///
    /// `DisableRefused` is enforcing: the refusal is the point.
    #[must_use]
    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforced | Self::DisableRefused)
    }

    /// Whether an operator asked for this hook to be off, however it resolved.
    ///
    /// True for a refused disable as well as an honoured one — the ask is what
    /// a report about suppression is about, and a surface that only counted
    /// honoured asks would go silent exactly when someone tried to disarm a
    /// protected guard.
    #[must_use]
    pub fn suppression_requested(self) -> bool {
        !matches!(self, Self::Enforced)
    }

    /// The switch that produced this state, as `VAR=value`, for operator-facing
    /// output. `None` when nothing was asked.
    ///
    /// Borrows `hook_name` because the `CADENCE_DISABLE` forms name the hook.
    #[must_use]
    pub fn switch(self, hook_name: &str) -> Option<String> {
        match self {
            Self::Enforced => None,
            Self::Bypassed => Some(format!("{BYPASS_VAR}={BYPASS_ON}")),
            Self::Disabled | Self::DisableRefused => Some(format!("{DISABLE_VAR}={hook_name}")),
        }
    }

    /// A short, stable token for logs and structured fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Bypassed => "bypassed",
            Self::Disabled => "disabled",
            Self::DisableRefused => "disable-refused",
        }
    }

    /// The parenthetical `cadence-hooks list` appends to a hook's row.
    ///
    /// Empty for an enforcing, unasked-for hook so the common row stays clean.
    #[must_use]
    pub fn list_suffix(self) -> &'static str {
        match self {
            Self::Enforced => "",
            Self::Bypassed | Self::Disabled => " (disabled)",
            Self::DisableRefused => " (protected — disable refused)",
        }
    }
}

/// Whether `CADENCE_DISABLE` may not switch this hook off.
#[must_use]
pub fn is_protected(hook_name: &str) -> bool {
    PROTECTED_GUARDS.contains(&hook_name)
}

/// The hook names a raw `CADENCE_DISABLE` value asks to switch off.
///
/// Entries are trimmed and empties dropped, so `" a , , b "` yields `a`, `b`.
/// Names are returned as written — resolution, not validation: a name matching
/// no registered hook is still an ask, and a caller that wants to report
/// unknown names needs to see them.
pub fn disable_list(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Whether a raw `CADENCE_BYPASS` value engages the blanket bypass.
///
/// Exact equality with [`BYPASS_ON`]. See the module docs on unknown values.
#[must_use]
pub fn bypass_engaged_from(bypass: Option<&str>) -> bool {
    bypass == Some(BYPASS_ON)
}

/// Whether the live environment engages the blanket bypass.
#[must_use]
pub fn bypass_engaged() -> bool {
    bypass_engaged_from(std::env::var(BYPASS_VAR).ok().as_deref())
}

/// Resolve one hook's state from explicit variable values.
///
/// Pure — the whole precedence ladder is decided here, with no environment
/// read, so the table in the module docs is testable row by row. [`resolve`] is
/// the thin environment-reading wrapper.
///
/// `None` means the variable is unset; a variable holding non-UTF-8 bytes is
/// the caller's `None` too, since it cannot name a hook or equal `1`.
#[must_use]
pub fn resolve_from(bypass: Option<&str>, disable: Option<&str>, hook_name: &str) -> BypassState {
    if bypass_engaged_from(bypass) {
        return BypassState::Bypassed;
    }
    let named = disable
        .map(|raw| disable_list(raw).any(|entry| entry == hook_name))
        .unwrap_or(false);
    if !named {
        return BypassState::Enforced;
    }
    if is_protected(hook_name) {
        BypassState::DisableRefused
    } else {
        BypassState::Disabled
    }
}

/// Resolve one hook's state from the live environment.
#[must_use]
pub fn resolve(hook_name: &str) -> BypassState {
    let bypass = std::env::var(BYPASS_VAR).ok();
    let disable = std::env::var(DISABLE_VAR).ok();
    resolve_from(bypass.as_deref(), disable.as_deref(), hook_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A protected guard and an unprotected one, so the table below can say
    /// which column it is exercising without repeating the const.
    const PROTECTED: &str = "git-safety";
    const UNPROTECTED: &str = "guard-rm";

    #[test]
    fn protected_sample_hooks_are_classified_as_the_table_assumes() {
        // Self-guarding fixture: if `guard-rm` is ever promoted into
        // PROTECTED_GUARDS, every `Disabled` row below would silently start
        // asserting the wrong branch. This fails first and names why.
        assert!(is_protected(PROTECTED), "{PROTECTED} must be protected");
        assert!(
            !is_protected(UNPROTECTED),
            "{UNPROTECTED} must be unprotected — if it was promoted into \
             PROTECTED_GUARDS, pick a different UNPROTECTED fixture here"
        );
    }

    /// Every row of the precedence table in the module docs, plus the
    /// unknown-value rows. `(bypass, disable, hook, expected)`.
    #[test]
    fn precedence_table() {
        let rows: &[(Option<&str>, Option<&str>, &str, BypassState)] = &[
            // Row 4 (the default): nothing set.
            (None, None, UNPROTECTED, BypassState::Enforced),
            (None, None, PROTECTED, BypassState::Enforced),
            // Row 1: the blanket bypass, and that it outranks both of row 2/3.
            (Some("1"), None, UNPROTECTED, BypassState::Bypassed),
            (
                Some("1"),
                Some(UNPROTECTED),
                UNPROTECTED,
                BypassState::Bypassed,
            ),
            (Some("1"), Some(PROTECTED), PROTECTED, BypassState::Bypassed),
            // Row 2: a protected guard named in the disable list still runs.
            (
                None,
                Some(PROTECTED),
                PROTECTED,
                BypassState::DisableRefused,
            ),
            // Row 3: an unprotected hook named in the disable list is skipped.
            (None, Some(UNPROTECTED), UNPROTECTED, BypassState::Disabled),
            // List parsing: trimming, empty entries, multiple names.
            (
                None,
                Some(&format!(" {UNPROTECTED} , warn-main-branch ")),
                UNPROTECTED,
                BypassState::Disabled,
            ),
            (
                None,
                Some(&format!("a,,{UNPROTECTED},")),
                UNPROTECTED,
                BypassState::Disabled,
            ),
            // A populated list naming other hooks leaves this one enforcing.
            (
                None,
                Some("warn-main-branch,line-endings"),
                UNPROTECTED,
                BypassState::Enforced,
            ),
            // Unknown CADENCE_BYPASS values fail toward ENFORCED.
            (Some("0"), None, UNPROTECTED, BypassState::Enforced),
            (Some(""), None, UNPROTECTED, BypassState::Enforced),
            (Some("true"), None, UNPROTECTED, BypassState::Enforced),
            (Some("yes"), None, UNPROTECTED, BypassState::Enforced),
            (Some("01"), None, UNPROTECTED, BypassState::Enforced),
            (Some(" 1"), None, UNPROTECTED, BypassState::Enforced),
            (Some("1 "), None, UNPROTECTED, BypassState::Enforced),
            (Some("11"), None, UNPROTECTED, BypassState::Enforced),
            // Unknown CADENCE_DISABLE entries fail toward ENFORCED — no
            // case-folding, no separator fuzzing, no prefix matching.
            (None, Some(""), UNPROTECTED, BypassState::Enforced),
            (None, Some(","), UNPROTECTED, BypassState::Enforced),
            (None, Some("  "), UNPROTECTED, BypassState::Enforced),
            (None, Some("Guard-Rm"), UNPROTECTED, BypassState::Enforced),
            (None, Some("GUARD-RM"), UNPROTECTED, BypassState::Enforced),
            (None, Some("guard_rm"), UNPROTECTED, BypassState::Enforced),
            (
                None,
                Some("guard-rm-liveness"),
                UNPROTECTED,
                BypassState::Enforced,
            ),
            (None, Some("guard"), UNPROTECTED, BypassState::Enforced),
            (None, Some("*"), UNPROTECTED, BypassState::Enforced),
            (None, Some("all"), UNPROTECTED, BypassState::Enforced),
        ];

        for (bypass, disable, hook, expected) in rows {
            let got = resolve_from(*bypass, *disable, hook);
            assert_eq!(
                got, *expected,
                "resolve_from(bypass={bypass:?}, disable={disable:?}, hook={hook:?})"
            );
        }
    }

    /// The four previously-divergent call sites, replayed against the one
    /// resolver. Before #567 the `list` summary line and `guard-rm-liveness`
    /// were protection-blind while the `list` per-hook row and the enforcement
    /// path were not, so `CADENCE_DISABLE=git-safety` produced two different
    /// answers to "is git-safety disabled?" in one binary.
    #[test]
    fn protected_guard_named_in_the_disable_list_reads_the_same_everywhere() {
        let state = resolve_from(None, Some(PROTECTED), PROTECTED);

        // The enforcement answer: the guard still runs.
        assert!(state.is_enforcing());
        // The `list` row answer: refused, not disabled.
        assert_eq!(state.list_suffix(), " (protected — disable refused)");
        // The summary/report answer: an ask happened and it was refused —
        // never rendered as a plain "disabled", which is what the old
        // `list` footer did.
        assert!(state.suppression_requested());
        assert_ne!(state.as_str(), "disabled");
        assert_eq!(state.as_str(), "disable-refused");
        // The liveness answer: it names a switch, and the switch names the
        // variable that was set.
        assert_eq!(
            state.switch(PROTECTED).as_deref(),
            Some("CADENCE_DISABLE=git-safety")
        );
    }

    #[test]
    fn an_unprotected_disable_is_honoured_everywhere() {
        let state = resolve_from(None, Some(UNPROTECTED), UNPROTECTED);
        assert!(!state.is_enforcing());
        assert_eq!(state.list_suffix(), " (disabled)");
        assert_eq!(state.as_str(), "disabled");
        assert_eq!(
            state.switch(UNPROTECTED).as_deref(),
            Some("CADENCE_DISABLE=guard-rm")
        );
    }

    #[test]
    fn a_blanket_bypass_names_its_own_variable_not_the_hook() {
        let state = resolve_from(Some("1"), None, PROTECTED);
        assert!(!state.is_enforcing());
        assert_eq!(state.switch(PROTECTED).as_deref(), Some("CADENCE_BYPASS=1"));
        assert_eq!(state.as_str(), "bypassed");
    }

    #[test]
    fn enforced_names_no_switch_and_renders_no_suffix() {
        let state = resolve_from(None, None, UNPROTECTED);
        assert!(state.is_enforcing());
        assert!(!state.suppression_requested());
        assert_eq!(state.switch(UNPROTECTED), None);
        assert_eq!(state.list_suffix(), "");
    }

    #[test]
    fn every_protected_guard_refuses_its_own_disable() {
        for guard in PROTECTED_GUARDS {
            let state = resolve_from(None, Some(guard), guard);
            assert_eq!(
                state,
                BypassState::DisableRefused,
                "{guard} is in PROTECTED_GUARDS but resolved to {state:?}"
            );
            assert!(state.is_enforcing(), "{guard} must still run");
        }
    }

    #[test]
    fn every_protected_guard_still_yields_to_the_blanket_bypass() {
        // The loud switch is the documented escape for maintenance. If this
        // ever fails, `CADENCE_BYPASS` has stopped being a complete escape and
        // the docs promising one are wrong.
        for guard in PROTECTED_GUARDS {
            assert_eq!(
                resolve_from(Some("1"), None, guard),
                BypassState::Bypassed,
                "{guard} did not yield to CADENCE_BYPASS=1"
            );
        }
    }

    #[test]
    fn disable_list_trims_and_drops_empties() {
        let parsed: Vec<&str> = disable_list(" a , , b,,  , c ").collect();
        assert_eq!(parsed, vec!["a", "b", "c"]);
        assert_eq!(disable_list("").count(), 0);
        assert_eq!(disable_list("   ").count(), 0);
        assert_eq!(disable_list(",,,").count(), 0);
    }

    #[test]
    fn bypass_is_an_exact_switch_not_a_truthiness_test() {
        assert!(bypass_engaged_from(Some("1")));
        for value in ["", "0", "01", "1 ", " 1", "true", "TRUE", "yes", "on", "2"] {
            assert!(
                !bypass_engaged_from(Some(value)),
                "CADENCE_BYPASS={value:?} must not engage the bypass"
            );
        }
        assert!(!bypass_engaged_from(None));
    }
}
