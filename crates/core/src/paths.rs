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

/// The current user's home directory, portably.
///
/// Tries `HOME` (unix, and set by most shells on Windows too), then the native
/// Windows pair `USERPROFILE` and `HOMEDRIVE`+`HOMEPATH`. Returns `None` only
/// when none of these are set — callers decide their own fallback (a temp dir,
/// an empty string) rather than baking in a unix-only `/tmp`.
pub fn user_home() -> Option<PathBuf> {
    resolve_home(
        non_empty_var("HOME").as_deref(),
        non_empty_var("USERPROFILE").as_deref(),
        non_empty_var("HOMEDRIVE").as_deref(),
        non_empty_var("HOMEPATH").as_deref(),
    )
}

/// Pure form of [`user_home`]: pick the home directory from the candidate env
/// values in precedence order (`HOME` → `USERPROFILE` → `HOMEDRIVE`+`HOMEPATH`).
/// Kept env-free so the precedence is unit-testable without mutating
/// process-global state, mirroring the [`resolve_config_dir`] split.
pub fn resolve_home(
    home: Option<&str>,
    userprofile: Option<&str>,
    homedrive: Option<&str>,
    homepath: Option<&str>,
) -> Option<PathBuf> {
    if let Some(home) = home {
        return Some(PathBuf::from(home));
    }
    if let Some(profile) = userprofile {
        return Some(PathBuf::from(profile));
    }
    match (homedrive, homepath) {
        (Some(drive), Some(path)) => Some(PathBuf::from(format!("{drive}{path}"))),
        _ => None,
    }
}

/// The system temp directory, portably (`%TEMP%` on Windows, `/tmp` on unix).
///
/// Wraps [`std::env::temp_dir`] so marker/state files land in a writable
/// per-platform location instead of a hardcoded `/tmp` that does not exist on
/// native Windows.
pub fn marker_temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Read an environment variable, treating empty as unset.
fn non_empty_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Claude Code's global config dir, honoring `CLAUDE_CONFIG_DIR` (else `~/.claude`).
pub fn claude_config_dir() -> PathBuf {
    let cfg = std::env::var("CLAUDE_CONFIG_DIR").ok();
    let home = user_home().unwrap_or_else(marker_temp_dir);
    resolve_config_dir(cfg.as_deref(), &home.to_string_lossy())
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
    fn resolve_home_prefers_home() {
        assert_eq!(
            resolve_home(
                Some("/home/u"),
                Some(r"C:\Users\u"),
                Some("C:"),
                Some(r"\Users\u")
            ),
            Some(PathBuf::from("/home/u"))
        );
    }

    #[test]
    fn resolve_home_falls_back_to_userprofile() {
        assert_eq!(
            resolve_home(None, Some(r"C:\Users\u"), Some("C:"), Some(r"\Users\u")),
            Some(PathBuf::from(r"C:\Users\u"))
        );
    }

    #[test]
    fn resolve_home_joins_homedrive_and_homepath() {
        assert_eq!(
            resolve_home(None, None, Some("C:"), Some(r"\Users\u")),
            Some(PathBuf::from(r"C:\Users\u"))
        );
    }

    #[test]
    fn resolve_home_none_when_all_absent() {
        assert_eq!(resolve_home(None, None, None, None), None);
    }

    #[test]
    fn resolve_home_needs_both_homedrive_and_homepath() {
        assert_eq!(resolve_home(None, None, Some("C:"), None), None);
        assert_eq!(resolve_home(None, None, None, Some(r"\Users\u")), None);
    }

    #[test]
    fn marker_temp_dir_is_absolute() {
        // std::env::temp_dir is always an absolute, existing-or-creatable path
        // on every supported platform; we only assert it is non-empty/absolute.
        assert!(marker_temp_dir().is_absolute());
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
