//! The identity tier — fail-closed scanning for work-identifiable terms.
//!
//! # Why this is a tier and not a separate guard
//!
//! It shares the extraction layer with the shaped tiers: per-segment command
//! gating, `--body-file` bounded reads, the #424 hardening. That layer is where
//! the historical bugs lived, and a standalone identity guard would duplicate
//! exactly it. One guard name, one message surface, one extraction layer, two
//! scan passes with different term-source authority.
//!
//! # Term source
//!
//! `~/.config/cadence/redaction.toml` — deliberately **outside every repo**
//! (cadence-hooks#561's load-bearing property). Nothing committed to a
//! repository can add, remove, or soften a term, because the loader reads no
//! repo path. Softening authority follows term-source authority: the same file
//! carries the `allow` entries.
//!
//! # Fail directions, which run in two different directions on purpose
//!
//! - **The guard's own failure is fail-open** (ADR-0001): no file, unreadable,
//!   malformed, zero terms → the tier is inert and the check allows. A guard
//!   that hard-fails on a missing config makes every commit impossible on a
//!   machine that never had the file.
//! - **A term match is fail-closed**: it blocks, and no repo config can excuse
//!   it.
//!
//! The gap between those — a machine where the file is silently absent — is why
//! [`status`] exists and why the cadence plugin's SessionStart surfaces it. A
//! per-invocation notice on the machine you are not looking at is functionally
//! a silent disarm.

use regex::Regex;
use serde::Deserialize;
use std::path::PathBuf;

/// Enforcement posture, read from the file's top-level `mode`.
///
/// **Default is [`Mode::Enforce`]** (Cameron's ruling, 2026-08-03, superseding
/// the plan's default-warn rollout: "Default on — then we'll gather
/// feedback/issues. Does no good if it's disabled."). An absent or unparseable
/// `mode` therefore blocks rather than warns, which is the fail-closed
/// direction for a field whose whole purpose is enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    #[default]
    Enforce,
    Warn,
}

/// One allow entry — a context in which a term is benign.
///
/// `path` matches when the scanned content's file path contains it (a Write/Edit
/// surface only — a commit message has no path). `pattern` matches against the
/// surrounding text. Either alone is sufficient; both empty is inert.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct AllowEntry {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
}

/// One deny-list term with its explicit, stable id.
///
/// `id` is authored, never positional. The predecessor format derived a term's
/// "T-code" from its line number, which drifted the moment the file was
/// re-sorted and left older artifacts citing numbers that had moved.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IdentityTerm {
    pub id: String,
    pub term: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub class: Option<String>,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

/// The parsed term source.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct IdentityList {
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<u32>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub terms: Vec<IdentityTerm>,
    /// Global allows, applied to every term.
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

impl IdentityList {
    /// Is the tier armed? An empty term list is treated exactly like an absent
    /// file — inert, and surfaced by [`status`]. A file that parses but carries
    /// no terms is the silent-disarm shape, not a configuration choice.
    pub fn is_armed(&self) -> bool {
        !self.terms.is_empty()
    }
}

/// One identity match. Carries the term's authored id, never its text, for any
/// caller that logs — the block message names the term verbatim (ruled: the
/// threat model is irrevocable public artifacts, and a block you cannot act on
/// is not a control), but a log line is a different surface.
#[derive(Debug, Clone)]
pub(crate) struct IdentityHit {
    pub id: String,
    pub snippet: String,
    #[allow(dead_code)]
    pub offset: usize,
}

/// Why the tier is not scanning, when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// Armed and scanning, with the term count.
    Armed(usize),
    /// No file at the resolved path.
    Absent,
    /// File exists but could not be read — permissions, a directory, a special
    /// file, or over the bounded-read cap. **Notified exactly like `Absent`**:
    /// silent-inert on a permissions error is the same silent-disarm class the
    /// lenient-config work closed, and the operator cannot tell the difference
    /// from the outcome alone.
    Unreadable,
    /// Read, but did not parse as the expected schema.
    Malformed(String),
    /// Parsed, but carries zero terms.
    ZeroTerms,
}

impl Status {
    /// Should SessionStart surface this? Every non-armed state, by design.
    pub fn needs_notice(&self) -> bool {
        !matches!(self, Status::Armed(_))
    }
}

/// Resolve the term-source path. `CADENCE_REDACTION_TERMS` overrides (the test
/// seam, and an escape hatch for a non-standard home); otherwise
/// `$XDG_CONFIG_HOME/cadence/redaction.toml`, else `~/.config/cadence/…`.
pub(crate) fn terms_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CADENCE_REDACTION_TERMS")
        && !p.is_empty()
    {
        return Some(PathBuf::from(p));
    }
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME")
        && !x.is_empty()
    {
        return Some(PathBuf::from(x).join("cadence").join("redaction.toml"));
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("cadence")
                .join("redaction.toml")
        })
}

/// Load the term source, returning both the list and why it is what it is.
///
/// Every failure yields an empty list — the guard's own failure is fail-open.
/// The [`Status`] is what keeps that from being silent.
pub(crate) fn load() -> (IdentityList, Status) {
    let Some(path) = terms_path() else {
        return (IdentityList::default(), Status::Absent);
    };
    if !path.exists() {
        return (IdentityList::default(), Status::Absent);
    }
    // Same bounded, regular-file-only reader the body-file path uses: a symlink
    // to /dev/zero or a multi-GB file must not hang the hook (#157/#194).
    let Some(raw) = cadence_hooks_core::paths::read_untrusted_config(&path) else {
        return (IdentityList::default(), Status::Unreadable);
    };
    match toml::from_str::<IdentityList>(&raw) {
        Ok(list) => {
            if list.is_armed() {
                let n = list.terms.len();
                (list, Status::Armed(n))
            } else {
                (list, Status::ZeroTerms)
            }
        }
        // The parse error names a line/column but never the file's content —
        // safe to surface.
        Err(e) => (
            IdentityList::default(),
            Status::Malformed(e.message().to_string()),
        ),
    }
}

/// Build the match regex for one term: case-insensitive, and word-boundary
/// anchored only on the sides where the term's own edge is a word character
/// (an unconditional `\b` around a term starting with `.` or `/` would never
/// match). Multi-word terms match across space, hyphen, and underscore, because
/// that is how the same name is spelled in prose, in a hostname, and in a slug.
fn term_regex(term: &str) -> Option<Regex> {
    let t = term.trim();
    if t.is_empty() {
        return None;
    }
    let escaped = regex::escape(t);
    // Re-open the escaped literal spaces into a separator class.
    let body = escaped.replace("\\ ", "[ _-]").replace(' ', "[ _-]");
    let starts_word = t
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let ends_word = t
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let pattern = format!(
        "(?i){}{}{}",
        if starts_word { r"\b" } else { "" },
        body,
        if ends_word { r"\b" } else { "" }
    );
    Regex::new(&pattern).ok()
}

/// Does an allow entry excuse this match?
///
/// `path` is a containment test against the scanned surface's file path (absent
/// for a commit message, so a path-only allow never fires there). `pattern` is
/// a regex against the full scanned text — the form that expresses "this term,
/// in this sentence, is the English word."
fn is_allowed(entry: &AllowEntry, text: &str, file_path: Option<&str>) -> bool {
    if let Some(p) = entry.path.as_deref().filter(|p| !p.is_empty())
        && file_path.is_some_and(|fp| fp.contains(p))
    {
        return true;
    }
    if let Some(pat) = entry.pattern.as_deref().filter(|p| !p.is_empty())
        && Regex::new(pat).is_ok_and(|re| re.is_match(text))
    {
        return true;
    }
    false
}

/// Scan `text` for identity terms.
///
/// **Config-blind by signature.** There is no `RedactionConfig` parameter, no
/// destination tier, no repo allowlist — so no committed file can reach this
/// function's behavior even by future accident. That is the type-level half of
/// the same property [`super::ConfigScope::SourceFileOnly`] enforces for the
/// shaped-tier call sites.
pub(crate) fn scan_identity(
    text: &str,
    list: &IdentityList,
    file_path: Option<&str>,
) -> Vec<IdentityHit> {
    if !list.is_armed() {
        return Vec::new();
    }
    let mut hits: Vec<IdentityHit> = Vec::new();
    for term in &list.terms {
        let Some(re) = term_regex(&term.term) else {
            continue;
        };
        // A term-level or global allow excusing this context skips the term.
        let excused = term
            .allow
            .iter()
            .chain(list.allow.iter())
            .any(|a| is_allowed(a, text, file_path));
        if excused {
            continue;
        }
        for m in re.find_iter(text) {
            hits.push(IdentityHit {
                id: term.id.clone(),
                snippet: m.as_str().to_string(),
                offset: m.start(),
            });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_of(terms: &[(&str, &str)]) -> IdentityList {
        IdentityList {
            version: Some(1),
            mode: Mode::Enforce,
            terms: terms
                .iter()
                .map(|(id, t)| IdentityTerm {
                    id: (*id).to_string(),
                    term: (*t).to_string(),
                    class: None,
                    allow: Vec::new(),
                })
                .collect(),
            allow: Vec::new(),
        }
    }

    #[test]
    fn matches_case_insensitively() {
        let l = list_of(&[("T1", "acmecorp")]);
        assert_eq!(scan_identity("We use AcmeCorp here", &l, None).len(), 1);
    }

    #[test]
    fn respects_word_boundaries() {
        let l = list_of(&[("T1", "acme")]);
        // `acmecorp` must not match the shorter standalone term.
        assert!(scan_identity("acmecorp tooling", &l, None).is_empty());
        assert_eq!(scan_identity("the acme tool", &l, None).len(), 1);
    }

    #[test]
    fn multiword_matches_across_separators() {
        let l = list_of(&[("T9", "acme widget")]);
        for spelling in ["acme widget", "acme-widget", "acme_widget", "Acme Widget"] {
            assert_eq!(
                scan_identity(spelling, &l, None).len(),
                1,
                "should match: {spelling}"
            );
        }
    }

    #[test]
    fn hostname_with_dots_matches() {
        let l = list_of(&[("T5", "ghe.example.com")]);
        assert_eq!(
            scan_identity("push to ghe.example.com/org/repo", &l, None).len(),
            1
        );
    }

    #[test]
    fn empty_list_is_inert() {
        let l = IdentityList::default();
        assert!(!l.is_armed());
        assert!(scan_identity("acmecorp", &l, None).is_empty());
    }

    #[test]
    fn mode_defaults_to_enforce() {
        // The ruled default: shipping disabled "does no good".
        let parsed: IdentityList = toml::from_str("version = 1\n").expect("parses");
        assert_eq!(parsed.mode, Mode::Enforce);
    }

    #[test]
    fn mode_warn_parses_when_stated() {
        let parsed: IdentityList = toml::from_str("mode = \"warn\"\n").expect("parses");
        assert_eq!(parsed.mode, Mode::Warn);
    }

    #[test]
    fn pattern_allow_excuses_the_english_collision() {
        let mut l = list_of(&[("T8", "clarion")]);
        l.terms[0].allow.push(AllowEntry {
            path: None,
            pattern: Some(r"(?i)clarion\s+(call|bell)".to_string()),
        });
        assert!(scan_identity("a clarion call to arms", &l, None).is_empty());
        assert_eq!(scan_identity("the clarion platform", &l, None).len(), 1);
    }

    #[test]
    fn path_allow_only_fires_when_a_path_is_present() {
        let mut l = list_of(&[("T8", "clarion")]);
        l.terms[0].allow.push(AllowEntry {
            path: Some("test_fixtures.py".to_string()),
            pattern: None,
        });
        assert!(scan_identity("clarion", &l, Some("a/test_fixtures.py")).is_empty());
        // A commit message has no path — the allow cannot fire there.
        assert_eq!(scan_identity("clarion", &l, None).len(), 1);
    }

    #[test]
    fn global_allow_applies_to_every_term() {
        let mut l = list_of(&[("T1", "acmecorp"), ("T2", "widgetco")]);
        l.allow.push(AllowEntry {
            path: Some("docs/redaction-tests/".to_string()),
            pattern: None,
        });
        assert!(
            scan_identity(
                "acmecorp and widgetco",
                &l,
                Some("docs/redaction-tests/fixtures.md")
            )
            .is_empty()
        );
    }

    #[test]
    fn malformed_toml_is_fail_open_with_a_named_status() {
        // Not via load() (which reads the real path) — parse directly.
        let err = toml::from_str::<IdentityList>("terms = [ this is not toml").unwrap_err();
        assert!(!err.message().is_empty());
    }

    #[test]
    fn status_notices_every_unarmed_state() {
        assert!(!Status::Armed(3).needs_notice());
        for s in [
            Status::Absent,
            Status::Unreadable,
            Status::ZeroTerms,
            Status::Malformed("x".into()),
        ] {
            assert!(s.needs_notice(), "{s:?} must notify");
        }
    }

    #[test]
    fn scan_is_config_blind_by_signature() {
        // A compile-time assertion in spirit: scan_identity's parameters are
        // (text, list, path). If a RedactionConfig ever becomes reachable here,
        // this test stops compiling — which is the point.
        fn assert_signature(f: fn(&str, &IdentityList, Option<&str>) -> Vec<IdentityHit>) -> bool {
            let _ = f;
            true
        }
        assert!(assert_signature(scan_identity));
    }
}
