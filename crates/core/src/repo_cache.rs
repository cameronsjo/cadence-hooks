//! Opt-in per-process read cache for `cadence-hooks group`.
//!
//! A `group` invocation evaluates several checks against one immutable hook
//! payload in a single short-lived process and then exits. Multiple checks
//! (and the metrics audit tail) repeatedly resolve `find_git_root`,
//! [`GitState::resolve`], and `<root>/.claude/cadence.json` for the same
//! `cwd` or target path.
//!
//! **Disabled by default.** Unit tests, `doctor`, `configure`, and standalone
//! hooks never pay lock overhead or risk seeing stale filesystem state across
//! mutations. Only `dispatch::run_logged_group` calls [`enable`] once before
//! running members.
//!
//! **Lock discipline.** Lookups and inserts take a short mutex lock; all
//! filesystem I/O and parsing run *outside* the lock so worker threads never
//! serialize on I/O and a panic during resolution cannot poison the cache.
//! If a lock is ever poisoned, the cache fails open and recomputes directly
//! (ADR-0001).

use crate::gitstate::GitState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static ENABLED: AtomicBool = AtomicBool::new(false);

struct CacheStore {
    git_roots: Mutex<HashMap<String, Option<PathBuf>>>,
    git_states: Mutex<HashMap<PathBuf, Option<GitState>>>,
    cadence_json: Mutex<HashMap<PathBuf, Option<Arc<serde_json::Value>>>>,
}

impl CacheStore {
    fn new() -> Self {
        Self {
            git_roots: Mutex::new(HashMap::new()),
            git_states: Mutex::new(HashMap::new()),
            cadence_json: Mutex::new(HashMap::new()),
        }
    }
}

static STORE: OnceLock<CacheStore> = OnceLock::new();

fn store() -> &'static CacheStore {
    STORE.get_or_init(CacheStore::new)
}

/// Enable the per-process repo-context cache for the remainder of this process.
///
/// Intended exclusively for `cadence-hooks group`, where the process evaluates
/// read-only checks against one payload and exits.
pub fn enable() {
    ENABLED.store(true, Ordering::Release);
}

/// Returns `true` if the per-process repo-context cache is currently active.
#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Look up or compute `find_git_root(start)`.
pub(crate) fn find_git_root(
    start: &str,
    compute: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    if !is_enabled() {
        return compute();
    }
    let map = &store().git_roots;
    if let Ok(guard) = map.lock()
        && let Some(cached) = guard.get(start)
    {
        return cached.clone();
    }
    let value = compute();
    if let Ok(mut guard) = map.lock() {
        guard.insert(start.to_owned(), value.clone());
    }
    value
}

/// Look up or compute `GitState::resolve(start)`.
pub(crate) fn git_state(
    start: &Path,
    compute: impl FnOnce() -> Option<GitState>,
) -> Option<GitState> {
    if !is_enabled() {
        return compute();
    }
    let map = &store().git_states;
    if let Ok(guard) = map.lock()
        && let Some(cached) = guard.get(start)
    {
        return cached.clone();
    }
    let value = compute();
    if let Ok(mut guard) = map.lock() {
        guard.insert(start.to_path_buf(), value.clone());
    }
    value
}

/// Look up or compute the parsed `<root>/.claude/cadence.json` document.
pub(crate) fn cadence_json(
    root: &Path,
    compute: impl FnOnce() -> Option<serde_json::Value>,
) -> Option<Arc<serde_json::Value>> {
    if !is_enabled() {
        return compute().map(Arc::new);
    }
    let map = &store().cadence_json;
    if let Ok(guard) = map.lock()
        && let Some(cached) = guard.get(root)
    {
        return cached.clone();
    }
    let value = compute().map(Arc::new);
    if let Ok(mut guard) = map.lock() {
        guard.insert(root.to_path_buf(), value.clone());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn disabled_by_default_runs_compute_every_time() {
        // Never mutate global `ENABLED` in unit tests so parallel tests stay
        // isolated; assert the default state and verify the uncached path.
        assert!(!is_enabled());
        let calls = Cell::new(0usize);
        let a = find_git_root("/nonexistent/repo_cache_test", || {
            calls.set(calls.get() + 1);
            None
        });
        let b = find_git_root("/nonexistent/repo_cache_test", || {
            calls.set(calls.get() + 1);
            None
        });
        assert_eq!(a, None);
        assert_eq!(b, None);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn cache_store_caches_present_and_absent_entries() {
        let store = CacheStore::new();
        {
            let mut roots = store.git_roots.lock().unwrap();
            roots.insert("/tmp/a".to_string(), Some(PathBuf::from("/tmp/a")));
            roots.insert("/tmp/none".to_string(), None);
        }
        let roots = store.git_roots.lock().unwrap();
        assert_eq!(roots.get("/tmp/a"), Some(&Some(PathBuf::from("/tmp/a"))));
        assert_eq!(roots.get("/tmp/none"), Some(&None));
        assert_eq!(roots.get("/tmp/miss"), None);
    }
}
