//! H1 — `SessionStart` nudge. Injects the self-representation contract via
//! `hookSpecificOutput.additionalContext` so the model writes a candidate to the
//! per-session staging file. Best-effort by definition: a nudge cannot force
//! genuine introspection, only invite it.

use crate::config::{self, Config};
use crate::persona::{ledger_contains, render_contract};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::fs;
use std::time::{Duration, SystemTime};

/// Inject the contract on session start (startup/clear only).
pub struct PersonaNudge;

impl Check for PersonaNudge {
    fn name(&self) -> &str {
        "persona-nudge"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        run_nudge(input, &Config::load())
    }
}

/// Testable core: takes an explicit [`Config`] so tests can target a tempdir.
pub fn run_nudge(input: &HookInput, cfg: &Config) -> CheckResult {
    // Fire only on the configured sources (default: startup | clear). On resume
    // and compact, emit nothing — prevents a duplicate record per session.
    let Some(source) = input.source() else {
        return CheckResult::allow();
    };
    if !cfg.nudge_on_sources.iter().any(|s| s == source) {
        return CheckResult::allow();
    }

    let Some(sid) = input.session_id().filter(|s| config::is_safe_session_id(s)) else {
        return CheckResult::allow();
    };

    // Cheap local housekeeping: clear staging files from crashed sessions.
    sweep_stale(cfg);

    // Belt-and-suspenders dedupe: if this session already landed in the ledger,
    // don't nudge again (the gate also dedupes at promotion).
    if let Ok(contents) = fs::read_to_string(&cfg.ledger_path)
        && ledger_contains(&contents, sid)
    {
        return CheckResult::allow();
    }

    let _ = fs::create_dir_all(&cfg.staging_dir);
    let staging_path = cfg.staging_dir.join(format!("{sid}.json"));
    let contract = render_contract(&staging_path.to_string_lossy(), &cfg.limits);
    CheckResult::nudge(contract)
}

/// Delete staging `.json` files older than `cfg.stale_hours`.
fn sweep_stale(cfg: &Config) {
    let Ok(entries) = fs::read_dir(&cfg.staging_dir) else {
        return;
    };
    let max_age = Duration::from_secs(cfg.stale_hours.saturating_mul(3600));
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && let Ok(age) = now.duration_since(modified)
            && age > max_age
        {
            let _ = fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_session;
    use tempfile::TempDir;

    fn test_cfg() -> (TempDir, Config) {
        let tmp = TempDir::new().unwrap();
        let cfg = Config::with_root(tmp.path());
        (tmp, cfg)
    }

    #[test]
    fn resume_source_allows_silently() {
        let (_tmp, cfg) = test_cfg();
        let r = run_nudge(&make_session("s1", "resume"), &cfg);
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(r.message.is_none());
    }

    #[test]
    fn compact_source_allows() {
        let (_tmp, cfg) = test_cfg();
        assert_eq!(
            run_nudge(&make_session("s1", "compact"), &cfg).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn startup_nudges_with_contract() {
        let (_tmp, cfg) = test_cfg();
        let r = run_nudge(&make_session("sess-xyz", "startup"), &cfg);
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("sess-xyz.json"), "contract names staging path");
        assert!(cfg.staging_dir.exists(), "staging dir created");
    }

    #[test]
    fn clear_source_also_nudges() {
        let (_tmp, cfg) = test_cfg();
        assert_eq!(
            run_nudge(&make_session("s2", "clear"), &cfg).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn unsafe_session_id_allows() {
        let (_tmp, cfg) = test_cfg();
        let r = run_nudge(&make_session("../escape", "startup"), &cfg);
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn no_source_allows() {
        let (_tmp, cfg) = test_cfg();
        let input = HookInput {
            session_id: Some("s1".into()),
            ..Default::default()
        };
        assert_eq!(run_nudge(&input, &cfg).outcome, Outcome::Allow);
    }

    #[test]
    fn already_in_ledger_skips() {
        let (_tmp, cfg) = test_cfg();
        if let Some(parent) = cfg.ledger_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&cfg.ledger_path, "{\"session_id\":\"seen\",\"form\":{}}\n").unwrap();
        let r = run_nudge(&make_session("seen", "startup"), &cfg);
        assert_eq!(r.outcome, Outcome::Allow, "dedupe against ledger");
    }

    #[test]
    fn sweep_removes_old_staging() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.stale_hours = 0; // anything older than now
        fs::create_dir_all(&cfg.staging_dir).unwrap();
        let stale = cfg.staging_dir.join("old.json");
        fs::write(&stale, "{}").unwrap();
        // age 0 means `age > 0s` is true for any elapsed time; sweep on nudge.
        std::thread::sleep(std::time::Duration::from_millis(5));
        run_nudge(&make_session("fresh", "startup"), &cfg);
        assert!(!stale.exists(), "stale staging file should be swept");
    }
}
