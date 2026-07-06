//! Shared sidecar for the `dismiss-*` snooze markers: the *provenance* a bare
//! epoch marker can't hold — who armed it, why, and when.
//!
//! The load-bearing marker files stay exactly `{epoch}\n` (so the guards'
//! first-line parse is unchanged). Each dismiss command writes a **sibling**
//! JSON file alongside its marker holding `{reason, session_id, armed_at,
//! expires_at}`; the guard reads it back when a snooze is active to attribute
//! *why* it allowed. A missing sidecar (an older marker, or a fail-open write)
//! degrades to reason/session `None` — never an error, never a block (ADR-0001).
//!
//! Built on `serde_json::Value` rather than derived serde so the guardrails
//! crate needs no `serde` derive dependency.

use std::path::Path;

/// A dismissal longer than this **requires** a `--reason`: a repo-wide (or
/// long-lived) bypass that outlives an hour should say why it exists, so the
/// provenance record isn't a bare "someone lowered the guard". Shorter snoozes
/// only get a nudge.
pub const REASON_REQUIRED_ABOVE_SECS: u64 = 3600;

/// Normalize a `--reason`: trim, and treat empty as absent.
pub fn normalize_reason(reason: Option<&str>) -> Option<String> {
    reason
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The reason gate for a `dismiss-*` command, pure so it's unit-testable.
///
/// - Reason supplied → `Ok(None)` (proceed, nothing to add).
/// - No reason, snooze **over** [`REASON_REQUIRED_ABOVE_SECS`] → `Err(msg)`: the
///   caller prints `msg` to stderr and exits non-zero, teaching the `--reason` form.
/// - No reason, snooze **at or under** the threshold → `Ok(Some(nudge))`: proceed,
///   but the caller appends `nudge` so the habit is taught at the point of friction.
pub fn reason_gate(
    secs: u64,
    reason: Option<&str>,
    dismiss_cmd: &str,
    duration_str: &str,
) -> Result<Option<String>, String> {
    if normalize_reason(reason).is_some() {
        return Ok(None);
    }
    if secs > REASON_REQUIRED_ABOVE_SECS {
        return Err(format!(
            "cadence-hooks: --reason is required for a dismissal longer than 1h (got {duration_str})\n   \
             A guard lowered for more than an hour should record why — it's repo-visible provenance.\n   \
             Re-run with a reason, e.g.:\n   \
             cadence-hooks guardrails {dismiss_cmd} --for {duration_str} --reason \"<why>\""
        ));
    }
    Ok(Some(format!(
        "note: no --reason recorded for this dismissal. Add one so the bypass is attributable:\n   \
         cadence-hooks guardrails {dismiss_cmd} --for {duration_str} --reason \"<why>\""
    )))
}

/// A successful `dismiss-*` outcome, handed back to the binary so it can record
/// the `bypass_armed` event (the binary owns the metrics writer — the seam that
/// keeps the guardrails crate metrics-free) and print the confirmation.
///
/// Plain data only — no metrics types — so it never couples guardrails to the
/// metrics crate. The binary unpacks these fields into a `BypassEvent::armed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DismissArmed {
    /// Canonical guard name the dismissal applies to (`enforce-worktree`, …).
    pub guard_hook: &'static str,
    /// The dismiss mechanism (`dismiss-enforce-worktree`, …).
    pub mechanism: &'static str,
    /// User-authored `--reason`, when supplied.
    pub reason: Option<String>,
    /// Session that armed the dismissal, when known.
    pub session_id: Option<String>,
    /// Repo root the dismissal was written for (for the record's repo basename).
    pub repo_root: Option<String>,
    /// Unix epoch seconds the dismissal was armed.
    pub armed_at: i64,
    /// Unix epoch seconds the dismissal expires.
    pub expires_at: i64,
    /// The confirmation line for the binary to print to stdout.
    pub confirmation: String,
}

/// The provenance recorded beside a snooze marker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnoozeMeta {
    /// User-authored `--reason`, when supplied.
    pub reason: Option<String>,
    /// Session that armed the snooze (`CLAUDE_CODE_SESSION_ID`), when known.
    pub session_id: Option<String>,
    /// Unix epoch seconds when the snooze was armed.
    pub armed_at: Option<i64>,
    /// Unix epoch seconds when the snooze expires.
    pub expires_at: Option<i64>,
}

impl SnoozeMeta {
    /// Serialize to the sidecar's JSON body. `null` for any absent field, so the
    /// shape is stable whether or not a reason was authored.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "reason": self.reason,
            "session_id": self.session_id,
            "armed_at": self.armed_at,
            "expires_at": self.expires_at,
        })
        .to_string()
    }

    /// Parse a sidecar body. Tolerant: unknown/absent keys map to `None`; a
    /// malformed body yields `None` (the caller treats a missing/garbage sidecar
    /// as "no provenance" and still allows).
    pub fn from_json(contents: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(contents).ok()?;
        Some(Self {
            reason: v.get("reason").and_then(|x| x.as_str()).map(String::from),
            session_id: v
                .get("session_id")
                .and_then(|x| x.as_str())
                .map(String::from),
            armed_at: v.get("armed_at").and_then(serde_json::Value::as_i64),
            expires_at: v.get("expires_at").and_then(serde_json::Value::as_i64),
        })
    }

    /// Read and parse the sidecar at `path`. `None` when the file is absent or
    /// unreadable (older marker, or fail-open write) — never an error.
    pub fn read(path: &Path) -> Option<Self> {
        let contents = std::fs::read_to_string(path).ok()?;
        Self::from_json(&contents)
    }
}

/// The provenance sidecar path for a snooze marker: a same-directory sibling
/// whose file name is the marker's plus a `.meta.json` suffix (e.g.
/// `enforce-worktree-snoozed-until` → `enforce-worktree-snoozed-until.meta.json`).
/// Appending — rather than rewriting the marker's suffix — keeps both files in
/// the same directory (the git common dir or the private marker dir) and can
/// never collide with the marker's own name.
pub fn sidecar_for(marker: &Path) -> std::path::PathBuf {
    let mut name = marker
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "marker".to_string());
    name.push_str(".meta.json");
    marker.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_full_meta() {
        let meta = SnoozeMeta {
            reason: Some("dogfooding vault symlink".into()),
            session_id: Some("sess-1".into()),
            armed_at: Some(1_700_000_000),
            expires_at: Some(1_700_003_600),
        };
        let parsed = SnoozeMeta::from_json(&meta.to_json()).expect("parses");
        assert_eq!(parsed, meta);
    }

    #[test]
    fn round_trips_reasonless_meta() {
        // No reason (a short snooze): reason serializes to null and reads back None.
        let meta = SnoozeMeta {
            reason: None,
            session_id: Some("sess-2".into()),
            armed_at: Some(100),
            expires_at: Some(200),
        };
        let json = meta.to_json();
        assert!(
            json.contains("\"reason\":null"),
            "reason is explicit null: {json}"
        );
        assert_eq!(SnoozeMeta::from_json(&json), Some(meta));
    }

    #[test]
    fn malformed_body_is_none() {
        assert_eq!(SnoozeMeta::from_json("not json"), None);
        assert_eq!(SnoozeMeta::from_json(""), None);
    }

    #[test]
    fn missing_keys_map_to_none() {
        // An empty object (or a partial one) is valid — absent fields are None.
        let parsed = SnoozeMeta::from_json("{}").expect("empty object parses");
        assert_eq!(parsed, SnoozeMeta::default());
    }

    #[test]
    fn read_missing_file_is_none() {
        assert_eq!(SnoozeMeta::read(Path::new("/nonexistent/meta.json")), None);
    }

    // --- reason gate ---

    #[test]
    fn reason_supplied_proceeds_without_nudge() {
        // Any length + a reason → Ok(None): proceed, nothing to teach.
        assert_eq!(
            reason_gate(
                7200,
                Some("plan doc on main"),
                "dismiss-enforce-worktree",
                "2h"
            ),
            Ok(None)
        );
        assert_eq!(
            reason_gate(60, Some("quick fix"), "dismiss-enforce-worktree", "1m"),
            Ok(None)
        );
    }

    #[test]
    fn long_without_reason_errors() {
        // Over 1h without a reason → Err teaching the --reason form.
        let err = reason_gate(3601, None, "dismiss-enforce-worktree", "3601s").unwrap_err();
        assert!(err.contains("--reason is required"), "{err}");
        assert!(
            err.contains("dismiss-enforce-worktree --for 3601s --reason"),
            "{err}"
        );
    }

    #[test]
    fn empty_reason_counts_as_absent() {
        // A whitespace-only reason doesn't satisfy the long-snooze requirement.
        assert!(reason_gate(7200, Some("   "), "dismiss-enforce-worktree", "2h").is_err());
    }

    #[test]
    fn short_without_reason_nudges_but_proceeds() {
        // At or under 1h without a reason → Ok(Some(nudge)): proceed + teach.
        let nudge = reason_gate(3600, None, "dismiss-main-branch-warn", "1h")
            .expect("boundary is allowed")
            .expect("carries a nudge");
        assert!(nudge.contains("no --reason recorded"), "{nudge}");
        assert!(
            nudge.contains("dismiss-main-branch-warn --for 1h --reason"),
            "{nudge}"
        );
    }

    #[test]
    fn threshold_boundary_is_inclusive_for_nudge() {
        // Exactly 3600s is "at the threshold" → nudge, not error. 3601s errors.
        assert!(reason_gate(3600, None, "x", "1h").unwrap().is_some());
        assert!(reason_gate(3601, None, "x", "3601s").is_err());
    }

    #[test]
    fn normalize_reason_trims_and_empties() {
        assert_eq!(normalize_reason(Some("  why  ")), Some("why".to_string()));
        assert_eq!(normalize_reason(Some("   ")), None);
        assert_eq!(normalize_reason(Some("")), None);
        assert_eq!(normalize_reason(None), None);
    }

    #[test]
    fn sidecar_is_marker_sibling() {
        let marker = Path::new("/repo/.git/cadence-hooks/enforce-worktree-snoozed-until");
        assert_eq!(
            sidecar_for(marker),
            Path::new("/repo/.git/cadence-hooks/enforce-worktree-snoozed-until.meta.json")
        );
    }
}
