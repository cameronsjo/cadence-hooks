//! Shared test-only helpers for this crate's marker-writing tests (#302).
//!
//! `nudge_polish_before_pr` and `record_polish` both write real `polish_marker`
//! files in their tests. Without an override they land in the real per-user
//! [`cadence_hooks_core::markers::marker_dir`] and never get cleaned up.

use std::path::Path;
use std::sync::Mutex;

/// Crate-wide serialization lock for tests that mutate `CADENCE_MARKER_DIR`.
///
/// The var is process-global, so every test in this crate that sets it must
/// hold this one lock — a per-module lock only serializes within its own
/// module and lets `nudge_polish_before_pr`'s tests race `record_polish`'s.
/// Mirrors the metrics crate's `common::ENV_LOCK`
/// (`crates/metrics/src/common.rs`).
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with `CADENCE_MARKER_DIR` set to `dir`, serialized against every
/// other marker-dir-mutating test in this crate via [`ENV_LOCK`].
pub(crate) fn with_marker_dir<F: FnOnce()>(dir: &Path, f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // SAFETY: serialized against every other marker-dir-mutating test in this
    // crate via ENV_LOCK.
    unsafe {
        std::env::set_var("CADENCE_MARKER_DIR", dir);
    }
    f();
    // SAFETY: serialized against every other marker-dir-mutating test in this
    // crate via ENV_LOCK.
    unsafe {
        std::env::remove_var("CADENCE_MARKER_DIR");
    }
}
