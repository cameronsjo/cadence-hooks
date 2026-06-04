//! Resolving Claude Code's global config directory.
//!
//! Claude Code honors a `CLAUDE_CONFIG_DIR` environment variable that relocates
//! its entire global config/state tree (default `~/.claude`). Hooks are **not**
//! handed a config-dir env var at runtime, so any code that resolves a global
//! path must read the variable itself.
//!
//! The variable's value may be a comma-separated list of directories; for the
//! purpose of *writing* state (metrics, persona ledger, insights) we take the
//! first non-empty entry. The pure [`resolve_config_dir`] form keeps the logic
//! unit-testable without touching process env (which is process-global and
//! races parallel tests), mirroring the `expand_tilde`/`expand_tilde_with`
//! split elsewhere in the workspace.

use std::path::PathBuf;

/// Claude Code's global config dir, honoring `CLAUDE_CONFIG_DIR` (else `~/.claude`).
pub fn claude_config_dir() -> PathBuf {
    let cfg = std::env::var("CLAUDE_CONFIG_DIR").ok();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    resolve_config_dir(cfg.as_deref(), &home)
}

/// Pure form: first non-empty comma entry of `config_dir`, `~`-expanded;
/// else `<home>/.claude`.
pub fn resolve_config_dir(config_dir: Option<&str>, home: &str) -> PathBuf {
    if let Some(first) = config_dir.and_then(|raw| {
        raw.split(',')
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(str::to_owned)
    }) {
        return expand_tilde_with(&first, home);
    }
    PathBuf::from(home).join(".claude")
}

/// Replace a leading `~/` (or a bare `~`) with `home`; pass other paths through.
pub fn expand_tilde_with(s: &str, home: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        PathBuf::from(home).join(rest)
    } else if s == "~" {
        PathBuf::from(home)
    } else {
        PathBuf::from(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_falls_back_to_home_dot_claude() {
        assert_eq!(
            resolve_config_dir(None, "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn empty_string_falls_back_to_home_dot_claude() {
        assert_eq!(
            resolve_config_dir(Some(""), "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn single_absolute_path() {
        assert_eq!(
            resolve_config_dir(Some("/custom/claude"), "/home/test"),
            PathBuf::from("/custom/claude")
        );
    }

    #[test]
    fn tilde_prefixed_path_expands() {
        assert_eq!(
            resolve_config_dir(Some("~/work-claude"), "/home/test"),
            PathBuf::from("/home/test/work-claude")
        );
    }

    #[test]
    fn comma_list_takes_first_entry() {
        assert_eq!(
            resolve_config_dir(Some("/first,/second,/third"), "/home/test"),
            PathBuf::from("/first")
        );
    }

    #[test]
    fn leading_empty_comma_entry_is_skipped() {
        assert_eq!(
            resolve_config_dir(Some(",/real"), "/home/test"),
            PathBuf::from("/real")
        );
    }

    #[test]
    fn whitespace_around_entries_is_trimmed() {
        assert_eq!(
            resolve_config_dir(Some("  /spaced  ,  /other  "), "/home/test"),
            PathBuf::from("/spaced")
        );
    }

    #[test]
    fn all_empty_entries_fall_back() {
        assert_eq!(
            resolve_config_dir(Some(" , , "), "/home/test"),
            PathBuf::from("/home/test/.claude")
        );
    }

    #[test]
    fn expand_tilde_with_handles_prefix_bare_and_absolute() {
        assert_eq!(
            expand_tilde_with("~/x/y", "/home/test"),
            PathBuf::from("/home/test/x/y")
        );
        assert_eq!(
            expand_tilde_with("~", "/home/test"),
            PathBuf::from("/home/test")
        );
        assert_eq!(
            expand_tilde_with("/abs/path", "/home/test"),
            PathBuf::from("/abs/path")
        );
    }
}
