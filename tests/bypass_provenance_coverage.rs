//! Keeps bypass provenance complete as a class (cadence-hooks#223).
//!
//! Every escape-hatch environment variable that shipped source reads as a string
//! literal must be classified here, either as a bypass that records provenance
//! (`allow_bypassed` / `with_bypass` in the named guard file) or as a switch that
//! is deliberately not a bypass, with the reason. A new escape hatch that is in
//! neither list fails `every_escape_hatch_is_classified`, so it cannot ship
//! without a provenance decision.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Escape hatches that record a `bypasses.jsonl` row: `(variable, guard files)`.
/// Each file must carry the literal AND a provenance call.
const RECORDING: &[(&str, &[&str])] = &[
    (
        "CADENCE_ALLOW_MAIN",
        &["crates/guardrails/src/enforce_worktree.rs"],
    ),
    (
        "CADENCE_NO_ENFORCE_WORKTREE",
        &["crates/guardrails/src/enforce_worktree.rs"],
    ),
    (
        "CADENCE_ALLOW_SENSITIVE_TERMS",
        &["crates/cadence/src/redact_external_content.rs"],
    ),
    (
        "CADENCE_ALLOW_SECRET_PUSH",
        &["crates/cadence/src/prevent_secret_push.rs"],
    ),
    (
        "CADENCE_ALLOW_SOPS_DECRYPT",
        &["crates/guardrails/src/guard_sops_decrypt.rs"],
    ),
    (
        "CADENCE_ALLOW_SUBAGENT_FROM_MAIN",
        &["crates/guardrails/src/warn_subagent_worktree.rs"],
    ),
    (
        "CADENCE_ALLOW_BRANCH_INTENT",
        &["crates/session/src/branch_intent.rs"],
    ),
    (
        "CADENCE_NO_OUTRO_BACKSTOP",
        &["crates/session/src/backstop.rs"],
    ),
    (
        "CADENCE_SKIP_OVERSHARE_AUDIT",
        &["crates/cadence/src/warn_overshare.rs"],
    ),
    (
        "CADENCE_GOING_PUBLIC_IGNORE",
        &["crates/guardrails/src/warn_going_public.rs"],
    ),
    (
        "CADENCE_ALLOW_CRITICAL_GRADE",
        &["crates/guardrails/src/guard_critical_grade.rs"],
    ),
    (
        "CADENCE_BODY_BUDGET_PR",
        &["crates/guardrails/src/guard_body_budget.rs"],
    ),
    (
        "CADENCE_BODY_BUDGET_COMMENT",
        &["crates/guardrails/src/guard_body_budget.rs"],
    ),
    (
        "CADENCE_BODY_BUDGET_ISSUE",
        &["crates/guardrails/src/guard_body_budget.rs"],
    ),
];

/// Switches that look like escape hatches but are not bypasses, with why.
const NOT_A_BYPASS: &[(&str, &str)] = &[
    (
        "CADENCE_NO_PERSIST_PLAN",
        "opts out of an advisory write, not out of a block (documented on persist_plan_opted_out)",
    ),
    (
        "CADENCE_NO_DAILY_GATE",
        "removes a once-a-day gate, so it produces MORE nudges, never fewer",
    ),
    (
        "CADENCE_NO_FEEDBACK_FOOTER",
        "hides a cosmetic footer line; no verdict changes",
    ),
    (
        "CADENCE_BODY_BUDGET_MODE",
        "flips the guard between nudge and block; not an exemption",
    ),
];

/// The process-wide gates are recorded in `src/main.rs`, not through a guard.
const GLOBAL_GATE_FILE: &str = "src/main.rs";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_escape_hatch(name: &str) -> bool {
    name.starts_with("CADENCE_ALLOW_")
        || name.starts_with("CADENCE_NO_")
        || name.starts_with("CADENCE_SKIP_")
        || name.starts_with("CADENCE_BODY_BUDGET_")
        || (name.starts_with("CADENCE_") && name.ends_with("_IGNORE"))
}

/// Every escape-hatch name that appears as the start of a string literal in
/// shipped source (`crates/*/src`, `src`).
fn shipped_escape_hatches() -> BTreeSet<String> {
    let mut files = Vec::new();
    rs_files(&root().join("src"), &mut files);
    if let Ok(rd) = std::fs::read_dir(root().join("crates")) {
        for c in rd.flatten() {
            rs_files(&c.path().join("src"), &mut files);
        }
    }
    let mut found = BTreeSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for (i, _) in text.match_indices("\"CADENCE_") {
            let name: String = text[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            // Only a whole-literal name (`"CADENCE_X"`) — not a prefix inside prose.
            if text[i + 1 + name.len()..].starts_with('"') && is_escape_hatch(&name) {
                found.insert(name);
            }
        }
    }
    found
}

#[test]
fn every_escape_hatch_is_classified() {
    let known: BTreeSet<&str> = RECORDING
        .iter()
        .map(|(v, _)| *v)
        .chain(NOT_A_BYPASS.iter().map(|(v, _)| *v))
        .collect();
    let unclassified: Vec<String> = shipped_escape_hatches()
        .into_iter()
        .filter(|v| !known.contains(v.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "escape-hatch env var(s) with no provenance decision: {unclassified:?}. Tag the guard's \
         allow path with `CheckResult::allow_bypassed(BypassProvenance::env_switch(..))` and add \
         it to RECORDING, or add it to NOT_A_BYPASS with the reason."
    );
}

#[test]
fn no_stale_classification() {
    // A classified name the source no longer reads is dead weight that would
    // hide the next real omission behind a familiar name.
    let live = shipped_escape_hatches();
    for (v, _) in RECORDING {
        assert!(live.contains(*v), "{v} is in RECORDING but no longer read");
    }
    for (v, why) in NOT_A_BYPASS {
        assert!(
            live.contains(*v),
            "{v} is in NOT_A_BYPASS but no longer read"
        );
        assert!(!why.is_empty());
    }
}

#[test]
fn every_recording_guard_carries_a_provenance_call() {
    for (var, files) in RECORDING {
        for f in *files {
            let text = std::fs::read_to_string(root().join(f))
                .unwrap_or_else(|e| panic!("{f} unreadable: {e}"));
            assert!(
                text.contains(&format!("\"{var}")),
                "{f} does not read {var}"
            );
            assert!(
                text.contains("allow_bypassed(")
                    || text.contains(".with_bypass(")
                    || text.contains("BypassProvenance"),
                "{f} reads {var} but never builds bypass provenance"
            );
        }
    }
}

#[test]
fn global_gates_record_at_their_own_site() {
    let text = std::fs::read_to_string(root().join(GLOBAL_GATE_FILE)).unwrap();
    for kind in ["BypassKind::GlobalBypass", "BypassKind::GlobalDisable"] {
        assert!(
            text.contains(kind),
            "{GLOBAL_GATE_FILE} never records {kind}"
        );
    }
}
