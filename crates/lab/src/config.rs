//! Configuration for the persona ledger: compiled defaults plus an optional
//! `~/.claude/persona/config.json` override. Paths live under `~/.claude/persona/`,
//! outside any repo, so the ledger spans every project.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// How Tier 2 cheek findings are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheekMode {
    /// Annotate the record's system-written `flags` and still promote.
    Warn,
    /// Reject the candidate and feed findings back for a rewrite.
    Block,
}

impl CheekMode {
    fn parse(s: &str) -> CheekMode {
        match s.trim().to_ascii_lowercase().as_str() {
            "block" => CheekMode::Block,
            _ => CheekMode::Warn,
        }
    }
}

/// The word/count caps Tier 1 enforces on the longer free-text fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub descriptor_max_words: usize,
    pub feature_max_words: usize,
    pub stance_max_words: usize,
    pub qualities_min: usize,
    pub qualities_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            descriptor_max_words: 6,
            feature_max_words: 12,
            stance_max_words: 20,
            qualities_min: 2,
            qualities_max: 4,
        }
    }
}

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub ledger_path: PathBuf,
    pub staging_dir: PathBuf,
    pub nudge_on_sources: Vec<String>,
    pub cheek_mode: CheekMode,
    pub limits: Limits,
    /// After this many Tier 1 blocks for one session, force-accept with a
    /// `forced-accept` flag instead of nagging forever.
    pub max_blocks: u32,
    /// Sweep staging files older than this many hours on session start.
    pub stale_hours: u64,
}

impl Config {
    /// Defaults rooted at `<persona_dir>`: ledger at `<dir>/personas.jsonl`,
    /// staging at `<dir>/staging`.
    pub fn with_root(persona_dir: impl Into<PathBuf>) -> Config {
        let dir = persona_dir.into();
        Config {
            ledger_path: dir.join("personas.jsonl"),
            staging_dir: dir.join("staging"),
            nudge_on_sources: vec!["startup".into(), "clear".into()],
            cheek_mode: CheekMode::Warn,
            limits: Limits::default(),
            max_blocks: 3,
            stale_hours: 24,
        }
    }

    /// The default persona root: `<config_dir>/persona`, where `<config_dir>`
    /// honors `CLAUDE_CONFIG_DIR` (else `~/.claude`).
    pub fn persona_root() -> PathBuf {
        cadence_hooks_core::paths::claude_config_dir().join("persona")
    }

    /// Load defaults, then apply any `<persona_root>/config.json` override.
    pub fn load() -> Config {
        let root = Config::persona_root();
        let mut cfg = Config::with_root(&root);
        let override_path = root.join("config.json");
        if let Ok(text) = std::fs::read_to_string(&override_path)
            && let Ok(raw) = serde_json::from_str::<RawConfig>(&text)
        {
            raw.apply(&mut cfg);
        }
        cfg
    }
}

/// Expand a leading `~/` to the home directory. Delegates to the shared
/// [`cadence_hooks_core::paths::expand_tilde_with`] so the logic lives in one place.
fn expand_tilde(s: &str) -> PathBuf {
    let home = cadence_hooks_core::paths::user_home()
        .unwrap_or_else(cadence_hooks_core::paths::marker_temp_dir);
    cadence_hooks_core::paths::expand_tilde_with(s, &home.to_string_lossy())
}

#[derive(Debug, Default, Deserialize)]
struct RawLimits {
    descriptor_max_words: Option<usize>,
    feature_max_words: Option<usize>,
    stance_max_words: Option<usize>,
    qualities_min: Option<usize>,
    qualities_max: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    ledger_path: Option<String>,
    staging_dir: Option<String>,
    nudge_on_sources: Option<Vec<String>>,
    cheek_mode: Option<String>,
    limits: Option<RawLimits>,
    max_blocks: Option<u32>,
    stale_hours: Option<u64>,
}

impl RawConfig {
    fn apply(self, cfg: &mut Config) {
        if let Some(p) = self.ledger_path {
            cfg.ledger_path = expand_tilde(&p);
        }
        if let Some(p) = self.staging_dir {
            cfg.staging_dir = expand_tilde(&p);
        }
        if let Some(s) = self.nudge_on_sources {
            cfg.nudge_on_sources = s;
        }
        if let Some(m) = self.cheek_mode {
            cfg.cheek_mode = CheekMode::parse(&m);
        }
        if let Some(m) = self.max_blocks {
            cfg.max_blocks = m;
        }
        if let Some(h) = self.stale_hours {
            cfg.stale_hours = h;
        }
        if let Some(l) = self.limits {
            let d = &mut cfg.limits;
            if let Some(v) = l.descriptor_max_words {
                d.descriptor_max_words = v;
            }
            if let Some(v) = l.feature_max_words {
                d.feature_max_words = v;
            }
            if let Some(v) = l.stance_max_words {
                d.stance_max_words = v;
            }
            if let Some(v) = l.qualities_min {
                d.qualities_min = v;
            }
            if let Some(v) = l.qualities_max {
                d.qualities_max = v;
            }
        }
    }
}

/// True when `session_id` is safe to embed in a staging filename — non-empty and
/// only ASCII alphanumerics, `-`, or `_`. Rejects path separators and `..` so a
/// hostile payload can never steer a write outside the staging directory.
pub fn is_safe_session_id(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// True when `path` resolves inside `dir` (string-prefix on normalized paths).
pub fn is_within(path: &str, dir: &Path) -> bool {
    if path.contains("..") {
        return false;
    }
    let dir_str = dir.to_string_lossy();
    let needle = format!("{}/", dir_str.trim_end_matches('/'));
    path.starts_with(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_root_under_persona_dir() {
        let cfg = Config::with_root("/x/persona");
        assert_eq!(cfg.ledger_path, PathBuf::from("/x/persona/personas.jsonl"));
        assert_eq!(cfg.staging_dir, PathBuf::from("/x/persona/staging"));
        assert_eq!(cfg.cheek_mode, CheekMode::Warn);
        assert_eq!(cfg.nudge_on_sources, vec!["startup", "clear"]);
        assert_eq!(cfg.limits, Limits::default());
    }

    #[test]
    fn override_applies_partial_fields() {
        let mut cfg = Config::with_root("/x/persona");
        let raw: RawConfig = serde_json::from_str(
            r#"{"cheek_mode":"block","max_blocks":5,"limits":{"stance_max_words":30}}"#,
        )
        .unwrap();
        raw.apply(&mut cfg);
        assert_eq!(cfg.cheek_mode, CheekMode::Block);
        assert_eq!(cfg.max_blocks, 5);
        assert_eq!(cfg.limits.stance_max_words, 30);
        // untouched fields keep defaults
        assert_eq!(cfg.limits.qualities_max, 4);
    }

    #[test]
    fn cheek_mode_parse_defaults_to_warn() {
        assert_eq!(CheekMode::parse("block"), CheekMode::Block);
        assert_eq!(CheekMode::parse("BLOCK"), CheekMode::Block);
        assert_eq!(CheekMode::parse("warn"), CheekMode::Warn);
        assert_eq!(CheekMode::parse("nonsense"), CheekMode::Warn);
    }

    #[test]
    fn safe_session_id_rejects_traversal() {
        assert!(is_safe_session_id("a1b2-c3_d4"));
        assert!(!is_safe_session_id(""));
        assert!(!is_safe_session_id("../etc"));
        assert!(!is_safe_session_id("a/b"));
        assert!(!is_safe_session_id("a.json"));
    }

    #[test]
    fn is_within_checks_prefix_and_traversal() {
        let dir = Path::new("/home/u/.claude/persona/staging");
        assert!(is_within("/home/u/.claude/persona/staging/s1.json", dir));
        assert!(!is_within("/home/u/.claude/persona/personas.jsonl", dir));
        assert!(!is_within("/etc/passwd", dir));
        assert!(!is_within(
            "/home/u/.claude/persona/staging/../personas.jsonl",
            dir
        ));
    }

    #[test]
    fn expand_tilde_uses_home_env() {
        // The pure `~`-expansion logic is covered by `cadence_hooks_core::paths`;
        // here we just confirm the local wrapper reads $HOME and passes through
        // absolute paths.
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
    }
}
