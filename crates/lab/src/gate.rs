//! H2 — `PostToolUse(Write)` gate. Validates a staging candidate and either
//! feeds itemized corrections back (re-prompt loop) or promotes the record into
//! the append-only ledger. The ledger only ever receives hook-written, validated
//! records, so the fact that `PostToolUse` fires *after* the write is harmless:
//! a blocked staging write is not the ledger.

use crate::config::{self, CheekMode, Config};
use crate::persona::{
    build_record, detect_cheek, ledger_contains, rotate_lines, utc_timestamp, validate_tier1,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Validate a staging candidate and promote or re-prompt.
pub struct PersonaGate;

impl Check for PersonaGate {
    fn name(&self) -> &str {
        "persona-gate"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        run_gate(input, &Config::load())
    }
}

/// Testable core: takes an explicit [`Config`] so tests can target a tempdir.
pub fn run_gate(input: &HookInput, cfg: &Config) -> CheckResult {
    // Path-filter: every Write fires this hook; only staging writes are ours.
    let Some(path) = input.file_path() else {
        return CheckResult::allow();
    };
    if !config::is_within(&path, &cfg.staging_dir) {
        return CheckResult::allow();
    }

    // The written bytes: prefer the Write payload (authoritative, no FS race),
    // fall back to reading the file off disk.
    let raw = match input.content() {
        Some(c) => c.to_string(),
        None => match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                return CheckResult::loop_block(
                    "staging file could not be read; write it again with the Write tool",
                );
            }
        },
    };

    let candidate: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            return CheckResult::loop_block(
                "staging file is not valid JSON; write a single JSON object",
            );
        }
    };

    // session_id is the staging filename stem — the trusted source, not the body.
    let sid = session_id_from_path(&path);

    // --- Tier 1 (deterministic) ---
    let mut errors = validate_tier1(&candidate, &cfg.limits);
    if candidate.get("flags").is_some() {
        errors.push("remove `flags`; it is system-written, not yours to set".into());
    }
    if !errors.is_empty() {
        // Retry cap: after N blocks for this session, force-accept instead of
        // nagging forever (a self-image the model genuinely can't compress).
        let count = bump_block_count(cfg, &sid);
        if count > cfg.max_blocks {
            return promote(
                cfg,
                &candidate,
                &sid,
                input.cwd.as_deref(),
                &["forced-accept".into()],
                &path,
            );
        }
        return CheckResult::loop_block(itemize(&errors));
    }

    // --- Tier 2 (cheek heuristic) ---
    let findings = detect_cheek(&candidate);
    if !findings.is_empty() && cfg.cheek_mode == CheekMode::Block {
        return CheckResult::loop_block(format!(
            "Reads as performed, not reported. Rewrite plainly:\n{}",
            itemize(&findings)
        ));
    }
    // warn mode (default): findings become system-written flags, still promote.
    promote(
        cfg,
        &candidate,
        &sid,
        input.cwd.as_deref(),
        &findings,
        &path,
    )
}

/// Append the validated record to the ledger, then delete staging. Idempotent on
/// `session_id` — a second promotion is an allow-noop, no duplicate line.
fn promote(
    cfg: &Config,
    candidate: &Value,
    session_id: &str,
    cwd: Option<&str>,
    flags: &[String],
    staging_path: &str,
) -> CheckResult {
    if let Ok(contents) = fs::read_to_string(&cfg.ledger_path)
        && ledger_contains(&contents, session_id)
    {
        cleanup(cfg, session_id, staging_path);
        return CheckResult::allow();
    }

    if let Some(parent) = cfg.ledger_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let record = build_record(candidate, session_id, &utc_timestamp(), cwd, flags);
    // Build the whole line and write it in one `write_all` so concurrent appends
    // from other sessions can't interleave a record with its trailing newline.
    // No flock — mirrors the metrics logger; each line is independent.
    let mut line = record.to_string();
    line.push('\n');
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.ledger_path)
        && file.write_all(line.as_bytes()).is_ok()
    {
        let _ = file.sync_all();
    }

    rotate_ledger(cfg);
    cleanup(cfg, session_id, staging_path);
    CheckResult::allow()
}

/// Bound the ledger to `cfg.ledger_max_entries` after an append. Fail-open
/// throughout — a rotation error must leave the already-appended ledger intact
/// and never block. Lives only on this PostToolUse promote path, never in the
/// SessionStart nudge. (#137)
///
/// Not concurrency-safe: this is a read-modify-write-rename with no lock (by
/// design — mirrors the lock-free append above; a `flock` here would fight
/// that). A session appending between our read and rename can have its record
/// clobbered by our rename. Low blast radius on a self-representation ledger
/// (ADR-0001 fail-open) and self-corrects: the clobbered session re-nudges and
/// re-promotes on its next SessionStart.
fn rotate_ledger(cfg: &Config) {
    if cfg.ledger_max_entries == 0 {
        return;
    }
    let Ok(contents) = fs::read_to_string(&cfg.ledger_path) else {
        return;
    };
    let Some(rotated) = rotate_lines(&contents, cfg.ledger_max_entries) else {
        return;
    };
    // Atomic rewrite: write to a sibling temp path, then rename over the ledger,
    // so a crash mid-write never leaves a truncated ledger.
    let tmp_path = cfg.ledger_path.with_extension("jsonl.tmp");
    if fs::write(&tmp_path, rotated).is_ok() {
        let _ = fs::rename(&tmp_path, &cfg.ledger_path);
    }
}

/// Remove the staging candidate and its block-count sidecar.
fn cleanup(cfg: &Config, session_id: &str, staging_path: &str) {
    let _ = fs::remove_file(staging_path);
    let _ = fs::remove_file(block_count_path(cfg, session_id));
}

fn block_count_path(cfg: &Config, session_id: &str) -> PathBuf {
    cfg.staging_dir.join(format!("{session_id}.blocks"))
}

/// Increment and persist the per-session block counter; returns the new count.
fn bump_block_count(cfg: &Config, session_id: &str) -> u32 {
    let path = block_count_path(cfg, session_id);
    let next = fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
        + 1;
    let _ = fs::create_dir_all(&cfg.staging_dir);
    let _ = fs::write(&path, next.to_string());
    next
}

fn session_id_from_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Format errors as a feedback list the model reads and self-corrects from.
fn itemize(errors: &[String]) -> String {
    let mut s =
        String::from("Your self-representation was not accepted. Fix these and write it again:\n");
    for e in errors {
        s.push_str("- ");
        s.push_str(e);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_write;
    use serde_json::json;
    use tempfile::TempDir;

    fn valid_json() -> String {
        json!({
            "form": {
                "kind": "compass",
                "descriptor": "a brass pocket compass",
                "distinguishing_feature": "needle that settles slowly"
            },
            "qualities": ["steady", "exact"],
            "stance": "Orienting carefully before committing to a direction.",
            "color": "amber",
            "texture": "metallic",
            "confidence": 0.5
        })
        .to_string()
    }

    /// Build a Config rooted at a fresh tempdir, with the staging dir created.
    fn test_cfg() -> (TempDir, Config) {
        let tmp = TempDir::new().unwrap();
        let cfg = Config::with_root(tmp.path());
        fs::create_dir_all(&cfg.staging_dir).unwrap();
        (tmp, cfg)
    }

    fn staging_path(cfg: &Config, sid: &str) -> String {
        cfg.staging_dir
            .join(format!("{sid}.json"))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn non_staging_path_allows() {
        let (_tmp, cfg) = test_cfg();
        let input = make_write("/some/other/file.json", &valid_json());
        assert_eq!(run_gate(&input, &cfg).outcome, Outcome::Allow);
    }

    #[test]
    fn invalid_json_loop_blocks() {
        let (_tmp, cfg) = test_cfg();
        let input = make_write(&staging_path(&cfg, "s1"), "not json {");
        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::LoopBlock);
        assert!(r.message.unwrap().contains("not valid JSON"));
    }

    #[test]
    fn valid_candidate_promotes_and_deletes_staging() {
        let (_tmp, cfg) = test_cfg();
        let sp = staging_path(&cfg, "sess-good");
        fs::write(&sp, valid_json()).unwrap();
        let input = make_write(&sp, &valid_json());

        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::Allow);

        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        assert_eq!(ledger.lines().count(), 1);
        let rec: Value = serde_json::from_str(ledger.lines().next().unwrap()).unwrap();
        assert_eq!(rec["session_id"], "sess-good");
        assert_eq!(rec["form"]["kind"], "compass");
        assert!(rec["flags"].as_array().unwrap().is_empty());
        assert!(!Path::new(&sp).exists(), "staging should be deleted");
    }

    #[test]
    fn too_many_qualities_loop_blocks_itemized() {
        let (_tmp, cfg) = test_cfg();
        let mut c: Value = serde_json::from_str(&valid_json()).unwrap();
        c["qualities"] = json!(["a", "b", "c", "d", "e"]);
        let input = make_write(&staging_path(&cfg, "s2"), &c.to_string());
        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::LoopBlock);
        assert!(r.message.unwrap().contains("qualities has 5 items"));
        assert!(!cfg.ledger_path.exists(), "nothing should be appended");
    }

    #[test]
    fn model_supplied_flags_loop_blocks() {
        let (_tmp, cfg) = test_cfg();
        let mut c: Value = serde_json::from_str(&valid_json()).unwrap();
        c["flags"] = json!(["clever"]);
        let input = make_write(&staging_path(&cfg, "s3"), &c.to_string());
        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::LoopBlock);
        assert!(r.message.unwrap().contains("remove `flags`"));
    }

    #[test]
    fn duplicate_session_is_allow_noop() {
        let (_tmp, cfg) = test_cfg();
        let sp = staging_path(&cfg, "dup");
        // Pre-seed the ledger with this session.
        fs::write(&cfg.ledger_path, "{\"session_id\":\"dup\",\"form\":{}}\n").unwrap();
        fs::write(&sp, valid_json()).unwrap();
        let input = make_write(&sp, &valid_json());

        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::Allow);
        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        assert_eq!(ledger.lines().count(), 1, "no duplicate line");
        assert!(!Path::new(&sp).exists(), "staging cleaned even on dedupe");
    }

    #[test]
    fn warn_mode_promotes_with_cheek_flags() {
        let (_tmp, cfg) = test_cfg();
        let mut c: Value = serde_json::from_str(&valid_json()).unwrap();
        c["stance"] = json!("Diving in with everything I've got today!");
        let sp = staging_path(&cfg, "cheeky");
        fs::write(&sp, c.to_string()).unwrap();
        let input = make_write(&sp, &c.to_string());

        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::Allow, "warn mode promotes");
        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        let rec: Value = serde_json::from_str(ledger.lines().next().unwrap()).unwrap();
        let flags = rec["flags"].as_array().unwrap();
        assert!(
            flags
                .iter()
                .any(|f| f.as_str().unwrap().contains("exclamation")),
            "cheek finding should be flagged: {flags:?}"
        );
    }

    #[test]
    fn block_mode_rejects_cheek() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.cheek_mode = CheekMode::Block;
        let mut c: Value = serde_json::from_str(&valid_json()).unwrap();
        c["stance"] = json!("Well, here we are again, ready to perform.");
        let input = make_write(&staging_path(&cfg, "b1"), &c.to_string());
        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::LoopBlock);
        assert!(r.message.unwrap().contains("performed"));
    }

    #[test]
    fn retry_cap_forces_accept() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.max_blocks = 1;
        let mut c: Value = serde_json::from_str(&valid_json()).unwrap();
        c["qualities"] = json!(["a", "b", "c", "d", "e"]); // always invalid
        let sp = staging_path(&cfg, "stubborn");
        let input = make_write(&sp, &c.to_string());

        // First two attempts loop-block (count 1, then would be 2 > 1).
        assert_eq!(run_gate(&input, &cfg).outcome, Outcome::LoopBlock); // count 1, 1 > 1 false
        let r = run_gate(&input, &cfg); // count 2, 2 > 1 true → force-accept
        assert_eq!(r.outcome, Outcome::Allow);

        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        let rec: Value = serde_json::from_str(ledger.lines().next().unwrap()).unwrap();
        assert_eq!(rec["flags"][0], "forced-accept");
        // block-count sidecar cleaned up on accept.
        assert!(!block_count_path(&cfg, "stubborn").exists());
    }

    // --- rotation (#137) ---

    fn seed_ledger(cfg: &Config, session_ids: &[&str]) {
        if let Some(parent) = cfg.ledger_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut contents = String::new();
        for sid in session_ids {
            contents.push_str(&format!("{{\"session_id\":\"{sid}\",\"form\":{{}}}}\n"));
        }
        fs::write(&cfg.ledger_path, contents).unwrap();
    }

    #[test]
    fn promote_rotates_when_over_cap() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.ledger_max_entries = 3;
        seed_ledger(&cfg, &["s1", "s2", "s3"]);

        let sp = staging_path(&cfg, "s4");
        let input = make_write(&sp, &valid_json());
        let r = run_gate(&input, &cfg);
        assert_eq!(r.outcome, Outcome::Allow);

        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        assert_eq!(ledger.lines().count(), 3, "trimmed to cap");
        assert!(!ledger.contains("\"session_id\":\"s1\""), "oldest dropped");
        assert!(ledger.contains("\"session_id\":\"s4\""), "newest present");
    }

    #[test]
    fn rotation_disabled_when_zero() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.ledger_max_entries = 0;
        seed_ledger(&cfg, &["s1", "s2", "s3"]);

        let sp = staging_path(&cfg, "s4");
        let input = make_write(&sp, &valid_json());
        run_gate(&input, &cfg);

        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        assert_eq!(ledger.lines().count(), 4, "nothing trimmed when disabled");
    }

    #[test]
    fn promote_trims_legacy_over_cap_ledger() {
        // A ledger seeded before rotation shipped can already be over cap; the
        // first promote after upgrading must trim it back down.
        let (_tmp, mut cfg) = test_cfg();
        cfg.ledger_max_entries = 2;
        seed_ledger(&cfg, &["s1", "s2", "s3", "s4", "s5"]);

        let sp = staging_path(&cfg, "s6");
        let input = make_write(&sp, &valid_json());
        run_gate(&input, &cfg);

        let ledger = fs::read_to_string(&cfg.ledger_path).unwrap();
        assert_eq!(ledger.lines().count(), 2, "trimmed to cap");
        for line in ledger.lines() {
            assert!(
                serde_json::from_str::<Value>(line).is_ok(),
                "every retained line must be valid JSON: {line}"
            );
        }
        assert!(ledger.contains("\"session_id\":\"s6\""), "newest present");
    }
}
