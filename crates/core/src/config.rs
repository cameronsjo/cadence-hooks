//! Configuration parsing utilities for environment variables.

/// Parse a space-or-comma-separated environment variable into a list of values.
///
/// Accepts any combination of whitespace and commas as delimiters.
/// This is intentionally lenient — LLMs tend to generate comma-separated
/// values where Unix convention expects space-separated, so we accept both.
///
/// # Examples
///
/// ```
/// use cadence_hooks_core::config::parse_env_list;
///
/// assert_eq!(parse_env_list("a b c"), vec!["a", "b", "c"]);
/// assert_eq!(parse_env_list("a,b,c"), vec!["a", "b", "c"]);
/// assert_eq!(parse_env_list("a, b, c"), vec!["a", "b", "c"]);
/// assert_eq!(parse_env_list(""), Vec::<String>::new());
/// ```
pub fn parse_env_list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Read an environment variable and parse it as a space-or-comma-separated list.
pub fn env_list(var: &str) -> Vec<String> {
    parse_env_list(&std::env::var(var).unwrap_or_default())
}

/// A parsed allowlist entry supporting four formats:
///
/// | Entry | Interpretation |
/// |---|---|
/// | `cameron` | bare owner — matches `{default_host}/cameron/*` |
/// | `git.sjo.lol/cameron` | host/owner — matches `git.sjo.lol/cameron/*` |
/// | `cameronsjo/cadence` | owner/repo — matches `{default_host}/cameronsjo/cadence` |
/// | `git.sjo.lol/cameron/cadence` | exact host/owner/repo |
///
/// Disambiguation: when an entry has exactly one `/`, the first segment
/// containing a `.` means host/owner; no dot means owner/repo.
/// Git forge usernames never contain dots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub host: Option<String>,
    pub owner: String,
    pub repo: Option<String>,
}

/// Read `GH_HOST` env var, falling back to `github.com`.
pub fn default_host() -> String {
    std::env::var("GH_HOST")
        .unwrap_or_else(|_| "github.com".to_string())
        .to_lowercase()
}

/// Parse a single allowlist entry string into an [`AllowEntry`].
pub fn parse_allow_entry(entry: &str) -> AllowEntry {
    let parts: Vec<&str> = entry.splitn(3, '/').collect();
    match parts.len() {
        1 => AllowEntry {
            host: None,
            owner: parts[0].to_string(),
            repo: None,
        },
        2 => {
            if parts[0].contains('.') {
                // host/owner
                AllowEntry {
                    host: Some(parts[0].to_lowercase()),
                    owner: parts[1].to_string(),
                    repo: None,
                }
            } else {
                // owner/repo
                AllowEntry {
                    host: None,
                    owner: parts[0].to_string(),
                    repo: Some(parts[1].to_string()),
                }
            }
        }
        _ => {
            // host/owner/repo
            AllowEntry {
                host: Some(parts[0].to_lowercase()),
                owner: parts[1].to_string(),
                repo: Some(parts[2].to_string()),
            }
        }
    }
}

/// Parse a space-or-comma-separated env var value into a list of [`AllowEntry`].
pub fn parse_allow_entries(value: &str) -> Vec<AllowEntry> {
    parse_env_list(value)
        .into_iter()
        .map(|s| parse_allow_entry(&s))
        .collect()
}

/// Read an env var and parse it into a list of [`AllowEntry`].
pub fn env_allow_entries(var: &str) -> Vec<AllowEntry> {
    parse_allow_entries(&std::env::var(var).unwrap_or_default())
}

/// Check if a `(host, owner, repo)` triple is allowed by either the owner
/// or repo allowlists. Bare entries (no host) match against `default_host`.
pub fn is_allowed(
    host: &str,
    owner: &str,
    repo: &str,
    owner_entries: &[AllowEntry],
    repo_entries: &[AllowEntry],
) -> bool {
    let default = default_host();
    let host_lower = host.to_lowercase();

    // Check repo entries first (more specific)
    for entry in repo_entries {
        let entry_host = entry.host.as_deref().unwrap_or(&default);
        if entry_host == host_lower && entry.owner == owner && entry.repo.as_deref() == Some(repo) {
            return true;
        }
    }

    // Check owner entries
    for entry in owner_entries {
        let entry_host = entry.host.as_deref().unwrap_or(&default);
        if entry_host == host_lower && entry.owner == owner {
            // If entry has a repo constraint, it must match
            if let Some(entry_repo) = &entry.repo {
                if entry_repo != repo {
                    continue;
                }
            }
            return true;
        }
    }

    false
}

/// Format an [`AllowEntry`] for display in block messages.
impl std::fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(host) = &self.host {
            write!(f, "{host}/")?;
        }
        write!(f, "{}", self.owner)?;
        if let Some(repo) = &self.repo {
            write!(f, "/{repo}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_separated() {
        assert_eq!(parse_env_list("alice bob"), vec!["alice", "bob"]);
    }

    #[test]
    fn comma_separated() {
        assert_eq!(parse_env_list("alice,bob"), vec!["alice", "bob"]);
    }

    #[test]
    fn comma_space_separated() {
        assert_eq!(parse_env_list("alice, bob"), vec!["alice", "bob"]);
    }

    #[test]
    fn mixed_delimiters() {
        assert_eq!(
            parse_env_list("alice bob,charlie, dave"),
            vec!["alice", "bob", "charlie", "dave"]
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(parse_env_list(""), Vec::<String>::new());
    }

    #[test]
    fn only_delimiters() {
        assert_eq!(parse_env_list(", , ,"), Vec::<String>::new());
    }

    #[test]
    fn single_value() {
        assert_eq!(parse_env_list("alice"), vec!["alice"]);
    }

    #[test]
    fn trailing_comma() {
        assert_eq!(parse_env_list("alice,bob,"), vec!["alice", "bob"]);
    }

    #[test]
    fn tabs_and_newlines() {
        assert_eq!(
            parse_env_list("alice\tbob\ncharlie"),
            vec!["alice", "bob", "charlie"]
        );
    }

    // --- parse_allow_entry ---

    #[test]
    fn parse_bare_owner() {
        assert_eq!(
            parse_allow_entry("cameron"),
            AllowEntry {
                host: None,
                owner: "cameron".to_string(),
                repo: None,
            }
        );
    }

    #[test]
    fn parse_host_owner() {
        assert_eq!(
            parse_allow_entry("git.sjo.lol/cameron"),
            AllowEntry {
                host: Some("git.sjo.lol".to_string()),
                owner: "cameron".to_string(),
                repo: None,
            }
        );
    }

    #[test]
    fn parse_owner_repo() {
        assert_eq!(
            parse_allow_entry("cameronsjo/cadence"),
            AllowEntry {
                host: None,
                owner: "cameronsjo".to_string(),
                repo: Some("cadence".to_string()),
            }
        );
    }

    #[test]
    fn parse_host_owner_repo() {
        assert_eq!(
            parse_allow_entry("git.sjo.lol/cameron/cadence"),
            AllowEntry {
                host: Some("git.sjo.lol".to_string()),
                owner: "cameron".to_string(),
                repo: Some("cadence".to_string()),
            }
        );
    }

    #[test]
    fn parse_host_normalizes_case() {
        let entry = parse_allow_entry("GitHub.COM/owner");
        assert_eq!(entry.host, Some("github.com".to_string()));
    }

    // --- parse_allow_entries ---

    #[test]
    fn parse_entries_mixed() {
        let entries = parse_allow_entries("cameronsjo git.sjo.lol/cameron");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].owner, "cameronsjo");
        assert!(entries[0].host.is_none());
        assert_eq!(entries[1].host, Some("git.sjo.lol".to_string()));
        assert_eq!(entries[1].owner, "cameron");
    }

    // --- is_allowed ---

    #[test]
    fn allowed_bare_owner_default_host() {
        let owners = vec![parse_allow_entry("cameronsjo")];
        assert!(is_allowed("github.com", "cameronsjo", "repo", &owners, &[]));
    }

    #[test]
    fn blocked_bare_owner_wrong_host() {
        let owners = vec![parse_allow_entry("cameronsjo")];
        assert!(!is_allowed(
            "git.sjo.lol",
            "cameronsjo",
            "repo",
            &owners,
            &[]
        ));
    }

    #[test]
    fn allowed_host_owner() {
        let owners = vec![parse_allow_entry("git.sjo.lol/cameron")];
        assert!(is_allowed(
            "git.sjo.lol",
            "cameron",
            "anything",
            &owners,
            &[]
        ));
    }

    #[test]
    fn blocked_host_owner_wrong_host() {
        let owners = vec![parse_allow_entry("git.sjo.lol/cameron")];
        assert!(!is_allowed(
            "github.com",
            "cameron",
            "anything",
            &owners,
            &[]
        ));
    }

    #[test]
    fn allowed_owner_repo() {
        let repos = vec![parse_allow_entry("external/shared-repo")];
        assert!(is_allowed(
            "github.com",
            "external",
            "shared-repo",
            &[],
            &repos
        ));
    }

    #[test]
    fn blocked_owner_repo_wrong_repo() {
        let repos = vec![parse_allow_entry("external/shared-repo")];
        assert!(!is_allowed(
            "github.com",
            "external",
            "other-repo",
            &[],
            &repos
        ));
    }

    #[test]
    fn allowed_host_owner_repo_exact() {
        let repos = vec![parse_allow_entry("git.sjo.lol/cameron/cadence")];
        assert!(is_allowed("git.sjo.lol", "cameron", "cadence", &[], &repos));
    }

    #[test]
    fn blocked_host_owner_repo_wrong_host() {
        let repos = vec![parse_allow_entry("git.sjo.lol/cameron/cadence")];
        assert!(!is_allowed("github.com", "cameron", "cadence", &[], &repos));
    }

    #[test]
    fn allowed_mixed_owners_and_repos() {
        let owners = parse_allow_entries("cameronsjo git.sjo.lol/cameron");
        let repos = parse_allow_entries("external/shared-repo");
        // github.com/cameronsjo/anything → allowed
        assert!(is_allowed("github.com", "cameronsjo", "x", &owners, &repos));
        // git.sjo.lol/cameron/anything → allowed
        assert!(is_allowed("git.sjo.lol", "cameron", "y", &owners, &repos));
        // github.com/external/shared-repo → allowed via repos
        assert!(is_allowed(
            "github.com",
            "external",
            "shared-repo",
            &owners,
            &repos
        ));
        // git.sjo.lol/cameronsjo/x → blocked (bare cameronsjo only matches github.com)
        assert!(!is_allowed(
            "git.sjo.lol",
            "cameronsjo",
            "x",
            &owners,
            &repos
        ));
        // github.com/cameron/x → blocked (cameron only matches git.sjo.lol)
        assert!(!is_allowed("github.com", "cameron", "x", &owners, &repos));
    }

    #[test]
    fn is_allowed_case_insensitive_host() {
        let owners = vec![parse_allow_entry("git.sjo.lol/cameron")];
        assert!(is_allowed("GIT.SJO.LOL", "cameron", "repo", &owners, &[]));
    }

    // --- Display ---

    #[test]
    fn display_bare_owner() {
        assert_eq!(parse_allow_entry("cameron").to_string(), "cameron");
    }

    #[test]
    fn display_host_owner() {
        assert_eq!(
            parse_allow_entry("git.sjo.lol/cameron").to_string(),
            "git.sjo.lol/cameron"
        );
    }

    #[test]
    fn display_owner_repo() {
        assert_eq!(
            parse_allow_entry("cameronsjo/cadence").to_string(),
            "cameronsjo/cadence"
        );
    }

    #[test]
    fn display_host_owner_repo() {
        assert_eq!(
            parse_allow_entry("git.sjo.lol/cameron/cadence").to_string(),
            "git.sjo.lol/cameron/cadence"
        );
    }
}
