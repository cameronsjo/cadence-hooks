//! Configuration parsing utilities for environment variables.

use std::path::Path;

use serde::de::DeserializeOwned;

use crate::paths::read_untrusted_config;

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
/// | `gitea.internal/cameron` | host/owner — matches `gitea.internal/cameron/*` |
/// | `cameronsjo/cadence` | owner/repo — matches `{default_host}/cameronsjo/cadence` |
/// | `gitea.internal/cameron/cadence` | exact host/owner/repo |
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

/// Read `CADENCE_EXTRA_HOSTS` env var as a list of additional hosts that bare
/// allowlist entries (e.g., `cameron` rather than `git.sjo.lol/cameron`) should
/// match in addition to [`default_host`].
///
/// Use this for self-hosted forges where you reuse the same username across
/// hosts you control (Gitea, Forgejo, GitLab CE, Bitbucket Server). It does
/// not widen host-qualified entries — `git.sjo.lol/cameron` still matches
/// only that host.
pub fn env_extra_hosts() -> Vec<String> {
    env_list("CADENCE_EXTRA_HOSTS")
        .into_iter()
        .map(|h| h.to_lowercase())
        .collect()
}

/// Parse a single allowlist entry string into an [`AllowEntry`].
pub fn parse_allow_entry(entry: &str) -> AllowEntry {
    let parts: Vec<&str> = entry.splitn(3, '/').collect();
    match parts.len() {
        1 => AllowEntry {
            host: None,
            owner: parts[0].to_lowercase(),
            repo: None,
        },
        2 => {
            if parts[0].contains('.') {
                // host/owner
                AllowEntry {
                    host: Some(parts[0].to_lowercase()),
                    owner: parts[1].to_lowercase(),
                    repo: None,
                }
            } else {
                // owner/repo
                AllowEntry {
                    host: None,
                    owner: parts[0].to_lowercase(),
                    repo: Some(parts[1].to_lowercase()),
                }
            }
        }
        _ => {
            // host/owner/repo
            AllowEntry {
                host: Some(parts[0].to_lowercase()),
                owner: parts[1].to_lowercase(),
                repo: Some(parts[2].to_lowercase()),
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
/// or repo allowlists. Bare entries (no host) match against [`default_host`].
///
/// Use [`is_allowed_with_extra_hosts`] when you need bare entries to also
/// match self-hosted forges (Gitea, Forgejo, GitLab CE, Bitbucket Server).
pub fn is_allowed(
    host: &str,
    owner: &str,
    repo: &str,
    owner_entries: &[AllowEntry],
    repo_entries: &[AllowEntry],
) -> bool {
    is_allowed_with_extra_hosts(host, owner, repo, owner_entries, repo_entries, &[])
}

/// Like [`is_allowed`], but bare allowlist entries (e.g., `cameron`) also
/// match any host in `extra_hosts` in addition to [`default_host`].
///
/// Host-qualified entries (`gitea.internal/cameron`) are unaffected — they
/// continue to match only their declared host. `extra_hosts` is normalized
/// to lowercase internally, so callers may pass mixed-case values safely.
pub fn is_allowed_with_extra_hosts(
    host: &str,
    owner: &str,
    repo: &str,
    owner_entries: &[AllowEntry],
    repo_entries: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    let default = default_host();
    let host_lower = host.to_lowercase();
    let owner_lower = owner.to_lowercase();
    let repo_lower = repo.to_lowercase();
    let extra_hosts_lower: Vec<String> = extra_hosts.iter().map(|h| h.to_lowercase()).collect();

    let host_matches_bare_entry = |entry_host: Option<&str>| -> bool {
        match entry_host {
            Some(h) => h == host_lower,
            None => host_lower == default || extra_hosts_lower.iter().any(|h| h == &host_lower),
        }
    };

    // Check repo entries first (more specific)
    for entry in repo_entries {
        if host_matches_bare_entry(entry.host.as_deref())
            && entry.owner == owner_lower
            && entry.repo.as_deref() == Some(repo_lower.as_str())
        {
            return true;
        }
    }

    // Check owner entries
    for entry in owner_entries {
        if host_matches_bare_entry(entry.host.as_deref()) && entry.owner == owner_lower {
            // If entry has a repo constraint, it must match
            if let Some(entry_repo) = &entry.repo
                && *entry_repo != repo_lower
            {
                continue;
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

/// Read `env.<key>` from a repo's tracked Claude settings, honoring Claude
/// Code's precedence: `.claude/settings.local.json` overrides
/// `.claude/settings.json`. Returns the value of the first file where the key
/// is *present as a scalar* (string/bool/number, coerced to string). Missing
/// files, absent keys, malformed JSON, and non-scalar values (null/array/
/// object) all declare nothing and fall through — a settings-read failure can
/// only ever yield `None`, never an error, never a panic (ADR-0001).
///
/// Reads via [`crate::paths::read_untrusted_config`] (regular-file check + 1
/// MiB cap, #157/#194) so a settings path that is a symlink to `/dev/zero` or
/// a FIFO cannot hang the hook.
///
/// Seed primitive for the guard-family settings-resolution generalization
/// tracked in cameronsjo/cadence-hooks#164; `src/configure.rs`'s
/// `read_disabled_hooks` is a candidate for later consolidation onto it — NOT
/// done here.
pub fn repo_env_flag(repo_root: &Path, key: &str) -> Option<String> {
    let claude_dir = repo_root.join(".claude");
    for name in ["settings.local.json", "settings.json"] {
        let Some(content) = read_untrusted_config(&claude_dir.join(name)) else {
            continue;
        };
        // Tolerate a leading UTF-8 BOM. Editors and hand-authoring often prepend
        // one; serde_json rejects it as an unexpected character at column 1,
        // which would silently drop a *declared* CADENCE_ALLOW_MAIN and
        // false-block a by-design-main repo (cadence-hooks#239 F10). We strip
        // only the BOM — JSONC comments/trailing commas stay a strict-parse
        // reject (no lenient-parser dependency here).
        let content = content.strip_prefix('\u{feff}').unwrap_or(&content);
        let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
            continue;
        };
        let Some(val) = json.get("env").and_then(|env| env.get(key)) else {
            continue;
        };
        match val {
            serde_json::Value::String(s) => return Some(s.clone()),
            serde_json::Value::Bool(b) => return Some(b.to_string()),
            serde_json::Value::Number(n) => return Some(n.to_string()),
            _ => continue, // null/array/object — not a declared scalar
        }
    }
    None
}

/// The single per-repo guard config file, relative to the git root.
///
/// One namespaced `.claude/cadence.json` replaces the family of per-guard
/// `.claude/*.json` files (cadence-hooks#153). Each guard reads its own
/// top-level section via [`load_cadence_section`]; unknown sections are
/// ignored (permissive, fail-open), so a `version` envelope plus reserved
/// keys (`nudges`, #216) can be hand-authored ahead of the loader that reads
/// them.
pub const CADENCE_CONFIG_REL: &str = ".claude/cadence.json";

/// Load one guard's section from `<root>/.claude/cadence.json`, deserialized
/// into the guard's own `T` (each guard keeps its existing `*Config` struct —
/// no type moves across crates).
///
/// Fail-open at every step, mirroring the per-guard loaders it replaces: a
/// missing file, an unreadable/oversized/special file (via
/// [`read_untrusted_config`]'s 1 MiB cap + regular-file check), non-UTF-8, a
/// top-level JSON parse failure, an absent `section`, or a section that does
/// not shape-match `T` all yield `T::default()` (ADR-0001 — a guard's own
/// config-read failure must never block the user).
///
/// The file is read and parsed once per call. Each guard invokes this with its
/// own `section` name (`"terminology"`, `"redaction"`), so a repo that reads N
/// sections re-reads the file N times per tool event — acceptable at N≈2 with a
/// 1 MiB cap, and it keeps each guard's read independent and fail-open.
pub fn load_cadence_section<T: Default + DeserializeOwned>(root: &Path, section: &str) -> T {
    let path = root.join(CADENCE_CONFIG_REL);
    let Some(content) = read_untrusted_config(&path) else {
        return T::default();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return T::default();
    };
    value
        .get(section)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
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
            parse_allow_entry("gitea.internal/cameron"),
            AllowEntry {
                host: Some("gitea.internal".to_string()),
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
            parse_allow_entry("gitea.internal/cameron/cadence"),
            AllowEntry {
                host: Some("gitea.internal".to_string()),
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

    #[test]
    fn parse_owner_normalizes_case() {
        let entry = parse_allow_entry("CameronSjo");
        assert_eq!(entry.owner, "cameronsjo");
    }

    #[test]
    fn parse_owner_repo_normalizes_case() {
        let entry = parse_allow_entry("CameronSjo/Cadence");
        assert_eq!(entry.owner, "cameronsjo");
        assert_eq!(entry.repo, Some("cadence".to_string()));
    }

    #[test]
    fn parse_host_owner_repo_normalizes_all() {
        let entry = parse_allow_entry("GitHub.COM/CameronSjo/Cadence");
        assert_eq!(entry.host, Some("github.com".to_string()));
        assert_eq!(entry.owner, "cameronsjo");
        assert_eq!(entry.repo, Some("cadence".to_string()));
    }

    // --- parse_allow_entries ---

    #[test]
    fn parse_entries_mixed() {
        let entries = parse_allow_entries("cameronsjo gitea.internal/cameron");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].owner, "cameronsjo");
        assert!(entries[0].host.is_none());
        assert_eq!(entries[1].host, Some("gitea.internal".to_string()));
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
            "gitea.internal",
            "cameronsjo",
            "repo",
            &owners,
            &[]
        ));
    }

    #[test]
    fn allowed_host_owner() {
        let owners = vec![parse_allow_entry("gitea.internal/cameron")];
        assert!(is_allowed(
            "gitea.internal",
            "cameron",
            "anything",
            &owners,
            &[]
        ));
    }

    #[test]
    fn blocked_host_owner_wrong_host() {
        let owners = vec![parse_allow_entry("gitea.internal/cameron")];
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
        let repos = vec![parse_allow_entry("gitea.internal/cameron/cadence")];
        assert!(is_allowed(
            "gitea.internal",
            "cameron",
            "cadence",
            &[],
            &repos
        ));
    }

    #[test]
    fn blocked_host_owner_repo_wrong_host() {
        let repos = vec![parse_allow_entry("gitea.internal/cameron/cadence")];
        assert!(!is_allowed("github.com", "cameron", "cadence", &[], &repos));
    }

    #[test]
    fn allowed_mixed_owners_and_repos() {
        let owners = parse_allow_entries("cameronsjo gitea.internal/cameron");
        let repos = parse_allow_entries("external/shared-repo");
        // github.com/cameronsjo/anything → allowed
        assert!(is_allowed("github.com", "cameronsjo", "x", &owners, &repos));
        // gitea.internal/cameron/anything → allowed
        assert!(is_allowed(
            "gitea.internal",
            "cameron",
            "y",
            &owners,
            &repos
        ));
        // github.com/external/shared-repo → allowed via repos
        assert!(is_allowed(
            "github.com",
            "external",
            "shared-repo",
            &owners,
            &repos
        ));
        // gitea.internal/cameronsjo/x → blocked (bare cameronsjo only matches github.com)
        assert!(!is_allowed(
            "gitea.internal",
            "cameronsjo",
            "x",
            &owners,
            &repos
        ));
        // github.com/cameron/x → blocked (cameron only matches gitea.internal)
        assert!(!is_allowed("github.com", "cameron", "x", &owners, &repos));
    }

    #[test]
    fn is_allowed_case_insensitive_host() {
        let owners = vec![parse_allow_entry("gitea.internal/cameron")];
        assert!(is_allowed(
            "GITEA.INTERNAL",
            "cameron",
            "repo",
            &owners,
            &[]
        ));
    }

    #[test]
    fn is_allowed_case_insensitive_owner() {
        let owners = vec![parse_allow_entry("cameronsjo")];
        assert!(is_allowed("github.com", "CameronSjo", "repo", &owners, &[]));
    }

    #[test]
    fn is_allowed_case_insensitive_repo() {
        let repos = vec![parse_allow_entry("external/Shared-Repo")];
        assert!(is_allowed(
            "github.com",
            "External",
            "shared-repo",
            &[],
            &repos
        ));
    }

    // --- is_allowed_with_extra_hosts ---

    #[test]
    fn extra_hosts_matches_bare_owner_on_self_hosted_forge() {
        // Repro for cadence-hooks#15: bare `cameron` should match git.sjo.lol
        // when that host is in CADENCE_EXTRA_HOSTS.
        let owners = parse_allow_entries("cameron");
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(is_allowed_with_extra_hosts(
            "git.sjo.lol",
            "cameron",
            "runelite-plugins",
            &owners,
            &[],
            &extras,
        ));
    }

    #[test]
    fn extra_hosts_does_not_widen_qualified_entries() {
        // Host-qualified entries stay scoped to their declared host even when
        // extra_hosts is populated. Otherwise a `github.com/cameron` entry
        // could leak into self-hosted matching, defeating the safety property.
        let owners = parse_allow_entries("github.com/cameron");
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(!is_allowed_with_extra_hosts(
            "git.sjo.lol",
            "cameron",
            "repo",
            &owners,
            &[],
            &extras,
        ));
    }

    #[test]
    fn extra_hosts_preserves_default_host_match() {
        // Bare entries continue to match default_host even with extras present.
        let owners = parse_allow_entries("cameron");
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(is_allowed_with_extra_hosts(
            "github.com",
            "cameron",
            "repo",
            &owners,
            &[],
            &extras,
        ));
    }

    #[test]
    fn empty_extra_hosts_preserves_old_safety_property() {
        // Regression guard for `owner_check_host_mismatch_blocked` semantics:
        // with no extras, bare owner must NOT match a non-default host.
        let owners = parse_allow_entries("cameron");
        assert!(!is_allowed_with_extra_hosts(
            "git.sjo.lol",
            "cameron",
            "repo",
            &owners,
            &[],
            &[],
        ));
    }

    #[test]
    fn extra_hosts_does_not_match_unlisted_host() {
        // Only hosts in extra_hosts unlock; others stay blocked.
        let owners = parse_allow_entries("cameron");
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(!is_allowed_with_extra_hosts(
            "evil.example",
            "cameron",
            "repo",
            &owners,
            &[],
            &extras,
        ));
    }

    #[test]
    fn extra_hosts_case_insensitive() {
        // The function must tolerate mixed-case extra_hosts values from
        // callers that don't go through env_extra_hosts() for normalization.
        let owners = parse_allow_entries("cameron");
        let extras = vec!["Git.SJO.Lol".to_string()];
        assert!(is_allowed_with_extra_hosts(
            "git.sjo.lol",
            "cameron",
            "repo",
            &owners,
            &[],
            &extras,
        ));
    }

    #[test]
    fn extra_hosts_with_bare_repo_entry() {
        // Bare owner/repo entries (`external/shared-repo`) also widen to extras.
        let repos = parse_allow_entries("cameron/runelite-plugins");
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(is_allowed_with_extra_hosts(
            "git.sjo.lol",
            "cameron",
            "runelite-plugins",
            &[],
            &repos,
            &extras,
        ));
    }

    // --- Display ---

    #[test]
    fn display_bare_owner() {
        assert_eq!(parse_allow_entry("cameron").to_string(), "cameron");
    }

    #[test]
    fn display_host_owner() {
        assert_eq!(
            parse_allow_entry("gitea.internal/cameron").to_string(),
            "gitea.internal/cameron"
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
            parse_allow_entry("gitea.internal/cameron/cadence").to_string(),
            "gitea.internal/cameron/cadence"
        );
    }

    // --- repo_env_flag ---

    fn write_settings(dir: &std::path::Path, name: &str, body: &str) {
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join(name), body).unwrap();
    }

    #[test]
    fn repo_env_flag_shared_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_local_overrides_shared() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.local.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"false"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_local_overrides_shared_reverse() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.local.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"false"}}"#,
        );
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("false".to_string())
        );
    }

    #[test]
    fn repo_env_flag_local_present_but_key_absent_falls_through() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(tmp.path(), "settings.local.json", r#"{"env":{}}"#);
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_malformed_local_falls_through_to_shared() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(tmp.path(), "settings.local.json", "{not valid json");
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_neither_file_exists_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"), None);
    }

    #[test]
    fn repo_env_flag_env_absent_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(tmp.path(), "settings.json", r#"{"other":"stuff"}"#);
        assert_eq!(repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"), None);
    }

    #[test]
    fn repo_env_flag_null_value_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":null}}"#,
        );
        assert_eq!(repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"), None);
    }

    #[test]
    fn repo_env_flag_null_in_local_falls_through_to_shared() {
        // An explicit `null` in local is a non-scalar, so it declares nothing
        // and falls through to shared — it is NOT treated as "locally cleared,
        // stop here" (which would wrongly return None despite a truthy shared
        // value).
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.local.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":null}}"#,
        );
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_bool_value_coerces_to_string() {
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":true}}"#,
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_tolerates_leading_bom() {
        // A settings.json saved with a leading UTF-8 BOM (EF BB BF) must not
        // silently drop a declared exemption (cadence-hooks#239 F10).
        let tmp = tempfile::tempdir().unwrap();
        write_settings(
            tmp.path(),
            "settings.json",
            "\u{feff}{\"env\":{\"CADENCE_ALLOW_MAIN\":\"true\"}}",
        );
        assert_eq!(
            repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"),
            Some("true".to_string())
        );
    }

    #[test]
    fn repo_env_flag_directory_at_settings_path_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(claude_dir.join("settings.json")).unwrap();
        assert_eq!(repo_env_flag(tmp.path(), "CADENCE_ALLOW_MAIN"), None);
    }

    // --- load_cadence_section ---

    #[derive(Debug, Default, PartialEq, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SampleSection {
        #[serde(default)]
        exemptions: Vec<String>,
        #[serde(default)]
        origin_audience: Option<String>,
    }

    /// Write `body` to `<root>/.claude/cadence.json`.
    fn write_cadence_config(dir: &std::path::Path, body: &str) {
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("cadence.json"), body).unwrap();
    }

    #[test]
    fn load_cadence_section_missing_file_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }

    #[test]
    fn load_cadence_section_reads_present_section() {
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(
            tmp.path(),
            r#"{"version":1,"terminology":{"exemptions":["a.yml","b.yml"]}}"#,
        );
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got.exemptions, vec!["a.yml", "b.yml"]);
    }

    #[test]
    fn load_cadence_section_reads_only_its_own_section() {
        // Two guards share the file; each reads only its slice.
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(
            tmp.path(),
            r#"{"terminology":{"exemptions":["t.yml"]},"redaction":{"originAudience":"public"}}"#,
        );
        let term: SampleSection = load_cadence_section(tmp.path(), "terminology");
        let redact: SampleSection = load_cadence_section(tmp.path(), "redaction");
        assert_eq!(term.exemptions, vec!["t.yml"]);
        assert!(term.origin_audience.is_none());
        assert_eq!(redact.origin_audience.as_deref(), Some("public"));
        assert!(redact.exemptions.is_empty());
    }

    #[test]
    fn load_cadence_section_absent_section_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(tmp.path(), r#"{"version":1,"redaction":{}}"#);
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }

    #[test]
    fn load_cadence_section_unknown_top_level_keys_ignored() {
        // The reserved #216 `nudges` key may be hand-authored early; a guard
        // reading its own section must tolerate keys it doesn't understand.
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(
            tmp.path(),
            r#"{"version":1,"nudges":{"backstop-warn":{"suppress":true}},"terminology":{"exemptions":["x.yml"]}}"#,
        );
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got.exemptions, vec!["x.yml"]);
    }

    #[test]
    fn load_cadence_section_malformed_json_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(tmp.path(), "{not valid json");
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }

    #[test]
    fn load_cadence_section_wrong_shape_is_default() {
        // The section is present but not the shape `T` expects — fail-open to
        // default rather than propagating a deserialize error.
        let tmp = tempfile::tempdir().unwrap();
        write_cadence_config(
            tmp.path(),
            r#"{"terminology":{"exemptions":"not-an-array"}}"#,
        );
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }

    #[test]
    fn load_cadence_section_directory_at_config_path_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(claude_dir.join("cadence.json")).unwrap();
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }

    #[cfg(unix)]
    #[test]
    fn load_cadence_section_special_file_is_default() {
        // A cadence.json symlinked to an endless special file is rejected on
        // stat by read_untrusted_config — no unbounded read, fail-open.
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::os::unix::fs::symlink("/dev/zero", claude_dir.join("cadence.json")).unwrap();
        let got: SampleSection = load_cadence_section(tmp.path(), "terminology");
        assert_eq!(got, SampleSection::default());
    }
}
