//! Per-nudge suppression config: the `nudges` map of `.claude/cadence.json`
//! (cameronsjo/cadence-hooks#216, schema frozen by ADR-0002 §3).
//!
//! ```jsonc
//! {
//!   "version": 1,
//!   "feedbackFooter": false,
//!   "nudges": {
//!     "backstop-warn":  { "suppress": true },
//!     "warn-overshare": { "suppress": ["docs/**", "*.md"] }
//!   }
//! }
//! ```
//!
//! Keys are registry hook names. `suppress` is `true` (every call) or a list of
//! globs matched against the tool call's file path. This module owns only the
//! *shape* and the *match*; which hooks may be named at all (`suppressible` on
//! the registry, never a protected guard) is decided by the binary, at dispatch
//! and in `doctor`, because the registry lives there.
//!
//! **Every failure direction here is toward MORE nudging.** A malformed file,
//! entry, or glob yields no suppression, never extra suppression (ADR-0001:
//! the loader fails open and `doctor` reports what was ignored).
//!
//! **Path globs need a path.** A glob list matches only a call that carries a
//! file path inside the repo root; a Bash-shaped nudge has none, so only
//! `suppress: true` can silence it. Ambiguity keeps the nudge.

use std::path::Path;

use glob::{MatchOptions, Pattern};
use serde::Deserialize;

use crate::config::{CADENCE_CONFIG_REL, SectionLoad, load_cadence_section_lenient, parse_jsonc};
use crate::paths::read_untrusted_config;

/// The `nudges` section: hook name to rule.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(transparent)]
pub struct NudgesConfig {
    rules: std::collections::BTreeMap<String, NudgeRule>,
}

/// One nudge's rule.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct NudgeRule {
    /// Absent or `false` suppresses nothing.
    #[serde(default)]
    pub suppress: Suppress,
}

/// `true` for every call, or a glob list scoped by file path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Suppress {
    All(bool),
    Paths(Vec<String>),
}

impl Default for Suppress {
    fn default() -> Self {
        Suppress::All(false)
    }
}

/// Glob options for `/`-bearing patterns: `*` stops at `/`, `**` crosses it
/// (gitignore-style), matching the terminology exemptions.
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Match one glob. A pattern containing `/` is matched against the repo-relative
/// path; a bare pattern against the basename. An uncompilable pattern never
/// matches.
pub fn glob_match(pattern: &str, rel_path: &str) -> bool {
    let Ok(pat) = Pattern::new(pattern) else {
        return false;
    };
    if pattern.contains('/') {
        pat.matches_with(rel_path, MATCH_OPTIONS)
    } else {
        pat.matches(rel_path.rsplit('/').next().unwrap_or(rel_path))
    }
}

/// `file` relative to `root`, lexically normalized. `None` when the file is
/// outside the root (a path glob then never matches).
pub fn repo_relative(root: &Path, file: &str) -> Option<String> {
    let file = crate::pathclass::normalize(file);
    let root = crate::pathclass::normalize(&root.to_string_lossy());
    if !file.starts_with('/') {
        return (!file.is_empty()).then_some(file);
    }
    let rest = file.strip_prefix(root.as_str())?.strip_prefix('/')?;
    (!rest.is_empty()).then(|| rest.to_string())
}

impl NudgesConfig {
    /// Every configured `(hook name, rule)`, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &NudgeRule)> {
        self.rules.iter().map(|(name, rule)| (name.as_str(), rule))
    }

    /// Whether this config asks to silence `hook` for a call on `rel_path`.
    ///
    /// Says nothing about whether the hook MAY be silenced; the caller gates
    /// that on the registry.
    pub fn suppresses(&self, hook: &str, rel_path: Option<&str>) -> bool {
        match self.rules.get(hook).map(|rule| &rule.suppress) {
            Some(Suppress::All(all)) => *all,
            Some(Suppress::Paths(globs)) => {
                rel_path.is_some_and(|path| globs.iter().any(|g| glob_match(g, path)))
            }
            None => false,
        }
    }
}

/// Load the `nudges` section leniently: a malformed entry is dropped and named
/// in `warnings`, the rest apply.
pub fn load_nudges(root: &Path) -> SectionLoad<NudgesConfig> {
    load_cadence_section_lenient(root, "nudges")
}

/// The top-level `feedbackFooter` boolean, `None` when the file, key, or value
/// shape is absent or wrong (the default: footer on).
pub fn feedback_footer_setting(root: &Path) -> Option<bool> {
    let content = read_untrusted_config(&root.join(CADENCE_CONFIG_REL))?;
    parse_jsonc(&content)?.get("feedbackFooter")?.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(json: &str) -> NudgesConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn suppresses_table() {
        let c = cfg(r#"{
            "all": {"suppress": true},
            "off": {"suppress": false},
            "unset": {},
            "docs": {"suppress": ["docs/**", "*.md"]},
            "empty": {"suppress": []},
            "badglob": {"suppress": ["[unclosed"]}
        }"#);
        let rows: &[(&str, Option<&str>, bool)] = &[
            ("all", None, true),
            ("all", Some("src/a.rs"), true),
            ("off", Some("docs/a.md"), false),
            ("unset", Some("docs/a.md"), false),
            ("missing", Some("docs/a.md"), false),
            ("docs", Some("docs/a/b.txt"), true),
            ("docs", Some("README.md"), true),
            ("docs", Some("src/lib/README.md"), true),
            ("docs", Some("src/a.rs"), false),
            ("docs", Some("mydocs/a.txt"), false),
            // a path glob needs a path: no path, no suppression
            ("docs", None, false),
            ("empty", Some("docs/a.md"), false),
            ("badglob", Some("[unclosed"), false),
        ];
        for (hook, path, want) in rows {
            assert_eq!(c.suppresses(hook, *path), *want, "{hook} {path:?}");
        }
    }

    #[test]
    fn glob_star_stops_at_separator_and_doublestar_crosses() {
        assert!(glob_match("docs/*", "docs/a.md"));
        assert!(!glob_match("docs/*", "docs/x/a.md"));
        assert!(glob_match("docs/**", "docs/x/y/a.md"));
        assert!(!glob_match("DOCS/**", "docs/a.md"));
    }

    #[test]
    fn repo_relative_table() {
        let root = Path::new("/repo");
        let rows: &[(&str, Option<&str>)] = &[
            ("/repo/docs/a.md", Some("docs/a.md")),
            ("/repo/docs/../src/a.rs", Some("src/a.rs")),
            ("docs/a.md", Some("docs/a.md")),
            ("/elsewhere/docs/a.md", None),
            ("/repository/a.md", None),
            ("/repo", None),
            // a traversal out of the root cannot spoof a docs path
            ("/repo/../etc/docs/a.md", None),
        ];
        for (file, want) in rows {
            assert_eq!(repo_relative(root, file).as_deref(), *want, "{file}");
        }
    }

    fn write_cfg(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/cadence.json"), body).unwrap();
        dir
    }

    #[test]
    fn load_drops_a_malformed_entry_and_names_it() {
        let dir = write_cfg(
            r#"{"nudges": {"good": {"suppress": true}, "bad": {"suppress": "yes"}, "worse": 3}}"#,
        );
        let load = load_nudges(dir.path());
        assert!(load.config.suppresses("good", None));
        assert!(!load.config.suppresses("bad", None));
        assert!(!load.config.suppresses("worse", None));
        assert!(load.warnings.iter().any(|w| w.contains("nudges.bad")));
        assert!(load.warnings.iter().any(|w| w.contains("nudges.worse")));
    }

    #[test]
    fn load_fails_open_on_every_broken_shape() {
        for body in ["{not json", "[]", r#"{"nudges": []}"#, r#"{"nudges": 4}"#, ""] {
            let dir = write_cfg(body);
            let load = load_nudges(dir.path());
            assert!(!load.config.suppresses("good", None), "{body}");
        }
        let empty = tempfile::tempdir().unwrap();
        assert!(!load_nudges(empty.path()).config.suppresses("good", None));
    }

    #[test]
    fn feedback_footer_setting_reads_only_a_bool() {
        for (body, want) in [
            (r#"{"feedbackFooter": false}"#, Some(false)),
            (r#"{"feedbackFooter": true}"#, Some(true)),
            (r#"{"feedbackFooter": "no"}"#, None),
            (r#"{"feedbackFooter": 0}"#, None),
            (r#"{}"#, None),
            ("{broken", None),
        ] {
            let dir = write_cfg(body);
            assert_eq!(feedback_footer_setting(dir.path()), want, "{body}");
        }
    }
}
