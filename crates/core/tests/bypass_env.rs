//! The environment-reading half of `cadence_hooks_core::bypass`.
//!
//! `resolve` and `bypass_engaged` are thin wrappers over the pure
//! `resolve_from` / `bypass_engaged_from`, and the crate's unit tests cover the
//! pure half exhaustively. What they cannot cover is the wiring: that `resolve`
//! reads **both** variables, reads the *right* one into each argument, and that
//! a non-UTF-8 value reads as unset rather than panicking or matching.
//!
//! # Why a separate test binary
//!
//! These tests mutate process-global environment. The crate's unit tests run in
//! the same process as each other, and adding a fifth env-mutating helper
//! inside `crates/core/src` would put a second, uncoordinated lock on variables
//! another helper already guards — the exact shape cadence-hooks#446 was filed
//! on. An integration test is its own binary and its own process, so it cannot
//! race the unit tests at all, and one local lock is enough to serialize the
//! tests in *this* file against each other.

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

use cadence_hooks_core::bypass::{BYPASS_VAR, BypassState, DISABLE_VAR, bypass_engaged, resolve};

/// The one lock over the two variables this file touches. Every test in this
/// binary takes it; nothing outside this binary can see these variables.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Set or clear both variables. `None` removes.
///
/// # Safety
///
/// Callers hold [`ENV_LOCK`] and this binary runs no other threads that read
/// the environment.
fn set_env(bypass: Option<&str>, disable: Option<&str>) {
    // SAFETY: every caller in this binary holds ENV_LOCK for the whole test, so
    // no other thread in this process reads or writes these two variables
    // concurrently. The variables are local to this binary — no unit test in
    // `crates/core/src` touches them — so no uncoordinated second lock exists.
    unsafe {
        match bypass {
            Some(v) => std::env::set_var(BYPASS_VAR, v),
            None => std::env::remove_var(BYPASS_VAR),
        }
        match disable {
            Some(v) => std::env::set_var(DISABLE_VAR, v),
            None => std::env::remove_var(DISABLE_VAR),
        }
    }
}

const PROTECTED: &str = "git-safety";
const UNPROTECTED: &str = "guard-rm";

/// All four outcomes, through the real environment rather than the pure
/// resolver — the wiring `resolve_from`'s own tests cannot see. A `resolve`
/// that read `CADENCE_BYPASS` into the `disable` slot, or never read the
/// second variable at all, passes every pure test and fails here.
#[test]
fn resolve_reads_both_variables_from_the_live_environment() {
    let _guard = lock();

    set_env(None, None);
    assert_eq!(resolve(UNPROTECTED), BypassState::Enforced);
    assert_eq!(resolve(PROTECTED), BypassState::Enforced);

    set_env(Some("1"), None);
    assert_eq!(resolve(UNPROTECTED), BypassState::Bypassed);

    set_env(None, Some(UNPROTECTED));
    assert_eq!(
        resolve(UNPROTECTED),
        BypassState::Disabled,
        "CADENCE_DISABLE was not read from the environment"
    );

    set_env(None, Some(PROTECTED));
    assert_eq!(resolve(PROTECTED), BypassState::DisableRefused);

    // Both set at once: the bypass outranks the disable, read live.
    set_env(Some("1"), Some(PROTECTED));
    assert_eq!(resolve(PROTECTED), BypassState::Bypassed);

    set_env(None, None);
}

#[test]
fn bypass_engaged_reads_the_live_environment() {
    let _guard = lock();

    set_env(Some("1"), None);
    assert!(bypass_engaged(), "CADENCE_BYPASS=1 must engage");

    for value in ["0", "", " 1", "true"] {
        set_env(Some(value), None);
        assert!(
            !bypass_engaged(),
            "CADENCE_BYPASS={value:?} must not engage the bypass"
        );
    }

    set_env(None, None);
    assert!(!bypass_engaged(), "an unset variable must not engage");
}

/// A variable holding bytes that are not valid UTF-8 reads as **unset**, per
/// the module's documented fail-toward-enforced direction.
///
/// Each half carries a positive control asserting the value really is present
/// and really is un-decodable before the resolver is called — without it, a
/// platform that rejected the `set_var` would leave the variable absent and
/// this test would pass having probed nothing.
#[cfg(unix)]
mod non_utf8 {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn invalid_utf8() -> OsString {
        OsString::from_vec(vec![0xff, 0xfe])
    }

    fn assert_present_and_undecodable(name: &str) {
        let value = std::env::var_os(name);
        assert!(value.is_some(), "{name} did not get set — nothing to probe");
        assert!(
            value.unwrap().to_str().is_none(),
            "{name} decoded as UTF-8 — the fixture is not exercising the non-UTF-8 path"
        );
    }

    /// A non-UTF-8 `CADENCE_BYPASS` reads as unset, and — the load-bearing half
    /// — the *other* variable is still read. A resolver that bailed on the
    /// undecodable value would report `Enforced` here and look correct.
    #[test]
    fn a_non_utf8_bypass_reads_as_unset_without_masking_the_disable_list() {
        let _guard = lock();
        set_env(None, Some(UNPROTECTED));
        // SAFETY: ENV_LOCK is held; see `set_env`.
        unsafe { std::env::set_var(BYPASS_VAR, invalid_utf8()) };
        assert_present_and_undecodable(BYPASS_VAR);

        assert_eq!(
            resolve(UNPROTECTED),
            BypassState::Disabled,
            "a non-UTF-8 CADENCE_BYPASS must read as unset, and CADENCE_DISABLE must still be read"
        );
        assert!(
            !bypass_engaged(),
            "undecodable bytes are not the string \"1\""
        );

        set_env(None, None);
    }

    #[test]
    fn a_non_utf8_disable_list_reads_as_unset() {
        let _guard = lock();
        set_env(None, None);
        // SAFETY: ENV_LOCK is held; see `set_env`.
        unsafe { std::env::set_var(DISABLE_VAR, invalid_utf8()) };
        assert_present_and_undecodable(DISABLE_VAR);

        assert_eq!(
            resolve(UNPROTECTED),
            BypassState::Enforced,
            "a non-UTF-8 CADENCE_DISABLE names no hook, so the hook must still run"
        );
        assert_eq!(resolve(PROTECTED), BypassState::Enforced);
        assert!(!bypass_engaged());

        set_env(None, None);
    }
}
