//! Shared secret file patterns for the secret guards.
//!
//! Both `prevent_secret_leaks` and `prevent_secret_writes` use these
//! constants and functions to classify files as blocked, ambiguous, or safe.

/// Safe template suffixes that are always allowed.
pub const SAFE_SUFFIXES: &[&str] = &[
    ".example",
    ".template",
    ".sample",
    ".defaults",
    ".test",
    ".ci",
    ".pub",
];

/// Files that must never be read or written by Claude Code.
pub const BLOCKED_FILENAMES: &[&str] = &[
    ".env",
    ".envrc",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.secret",
    ".env.keys",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".pgpass",
];

/// File extensions that must never be read or written (unambiguous secrets).
pub const BLOCKED_EXTENSIONS: &[&str] = &["key", "p12", "pfx", "keystore", "jks"];

/// File suffix patterns that must never be read or written.
pub const BLOCKED_SUFFIXES: &[&str] = &["-key.pem", "_key.pem", ".private.pem"];

/// Path fragments indicating secrets.
///
/// Parent-dir-qualified so the generic basenames `credentials` and `config`
/// only block inside their credential directories — a bare `credentials` /
/// `config` filename would over-block every repo (#77).
pub const BLOCKED_PATH_FRAGMENTS: &[&str] = &[
    ".docker/config.json",
    "gcloud-credentials.json",
    ".aws/credentials",
    ".kube/config",
];

/// Ambiguous patterns (warn, not block).
pub const WARN_EXTENSIONS: &[&str] = &["pem", "p8"];

/// Check if a filename is a safe template (e.g., `.env.example`).
pub fn is_safe_template(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    SAFE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Check if a filename matches blocked patterns (definite secrets).
pub fn is_blocked(filename: &str, path: &str) -> bool {
    let lower = filename.to_lowercase();

    // The whole `.env` family — not just the handful in BLOCKED_FILENAMES — so
    // the tool path agrees with the Bash path's predicate (#64).
    if is_env_family_secret(&lower) {
        return true;
    }

    if BLOCKED_FILENAMES.iter().any(|&p| lower == p) {
        return true;
    }

    if BLOCKED_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return true;
    }

    if let Some(ext) = lower.rsplit('.').next()
        && BLOCKED_EXTENSIONS.contains(&ext)
    {
        return true;
    }

    if lower.starts_with("service-account") && lower.ends_with(".json") {
        return true;
    }

    let lower_path = path.to_lowercase();
    BLOCKED_PATH_FRAGMENTS
        .iter()
        .any(|frag| lower_path.contains(frag))
}

/// Check if a filename is ambiguous (warn, not block).
pub fn is_ambiguous(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        return WARN_EXTENSIONS.contains(&ext);
    }
    false
}

/// True if a lowercased path component is a dangerous `.env`-family secret:
/// `.env`, `.envrc`, or `.env.<x>` where `<x>` is non-empty and the component
/// does not end in a [`SAFE_SUFFIXES`] template suffix (`.env.example`, etc.).
///
/// Shared by [`is_blocked`] (the Read/Grep/Write/Edit tool paths) and
/// [`is_dangerous_env_token`] (the Bash path) so the tool and shell guards
/// classify the whole family by one predicate instead of `is_blocked`'s exact
/// `BLOCKED_FILENAMES` membership — which missed `.env.prod`, `.env.dev`,
/// `.env.development.local`, … and let the tools read what the shell blocked
/// (#64). Callers pass an already-lowercased basename/component.
pub(crate) fn is_env_family_secret(component: &str) -> bool {
    if component == ".env" || component == ".envrc" {
        return true;
    }

    match component.strip_prefix(".env.") {
        Some(rest) if !rest.is_empty() => !SAFE_SUFFIXES.iter().any(|s| component.ends_with(s)),
        _ => false,
    }
}

/// True if a shell token resolves to a dangerous `.env`-family file.
///
/// Component-matched, not substring: the token's final path component must
/// be `.env`, `.envrc`, or `.env.<something>` — minus [`SAFE_SUFFIXES`] — so
/// `settings.environment`, `.environment`, and `my.envelope.txt` stay clean
/// (closes the #86 substring false-block class for both secret guards).
/// Strips one leading `@` (the curl/httpie upload-operand idiom `@.env`) and
/// trailing `)` (subshell close) before classifying via [`is_env_family_secret`].
pub fn is_dangerous_env_token(token: &str) -> bool {
    let lower = token.to_lowercase();
    let trimmed = lower.strip_prefix('@').unwrap_or(&lower);
    let trimmed = trimmed.trim_end_matches(')');
    let component = trimmed.rsplit('/').next().unwrap_or(trimmed);

    is_env_family_secret(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_templates_detected() {
        assert!(is_safe_template(".env.example"));
        assert!(is_safe_template("config.template"));
        assert!(is_safe_template("cert.pub"));
        assert!(!is_safe_template(".env"));
    }

    #[test]
    fn blocked_filenames_detected() {
        assert!(is_blocked(".env", "/project/.env"));
        assert!(is_blocked(".env.local", "/project/.env.local"));
        assert!(is_blocked("credentials.json", "/project/credentials.json"));
        assert!(is_blocked("id_rsa", "/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn env_family_secret_detected() {
        // Bare members.
        assert!(is_env_family_secret(".env"));
        assert!(is_env_family_secret(".envrc"));
        // #64: family members absent from BLOCKED_FILENAMES.
        assert!(is_env_family_secret(".env.prod"));
        assert!(is_env_family_secret(".env.dev"));
        assert!(is_env_family_secret(".env.development.local"));
        assert!(is_env_family_secret(".env.docker"));
        // Safe template suffixes stay allowed.
        assert!(!is_env_family_secret(".env.example"));
        assert!(!is_env_family_secret(".env.test"));
        // Lookalikes that aren't the family.
        assert!(!is_env_family_secret(".environment"));
        assert!(!is_env_family_secret("settings.environment"));
    }

    #[test]
    fn blocked_env_family_gap_closed() {
        // #64: these are NOT in BLOCKED_FILENAMES but the Bash path already
        // blocked them via is_dangerous_env_token — is_blocked now agrees.
        assert!(is_blocked(".env.prod", "/project/.env.prod"));
        assert!(is_blocked(".env.dev", "/project/.env.dev"));
        assert!(is_blocked(
            ".env.development.local",
            "/project/.env.development.local"
        ));
        // Safe templates still allowed through is_blocked.
        assert!(!is_blocked(".env.example", "/project/.env.example"));
        assert!(!is_blocked(".env.test", "/project/.env.test"));
    }

    #[test]
    fn blocked_extensions_detected() {
        assert!(is_blocked("server.key", "/etc/ssl/server.key"));
        assert!(is_blocked("cert.p12", "/etc/ssl/cert.p12"));
        assert!(is_blocked("app.keystore", "/project/app.keystore"));
    }

    #[test]
    fn blocked_suffixes_detected() {
        assert!(is_blocked("server-key.pem", "/etc/ssl/server-key.pem"));
        assert!(is_blocked("server_key.pem", "/etc/ssl/server_key.pem"));
        assert!(is_blocked(
            "server.private.pem",
            "/etc/ssl/server.private.pem"
        ));
    }

    #[test]
    fn blocked_path_fragments_detected() {
        assert!(is_blocked("config.json", "/home/user/.docker/config.json"));
        assert!(is_blocked(
            "gcloud-credentials.json",
            "/project/gcloud-credentials.json"
        ));
    }

    #[test]
    fn service_account_detected() {
        assert!(is_blocked(
            "service-account-prod.json",
            "/project/service-account-prod.json"
        ));
    }

    #[test]
    fn normal_files_allowed() {
        assert!(!is_blocked("main.rs", "/project/src/main.rs"));
        assert!(!is_blocked("config.toml", "/project/config.toml"));
    }

    #[test]
    fn ambiguous_extensions_detected() {
        assert!(is_ambiguous("cert.pem"));
        assert!(is_ambiguous("signing.p8"));
        assert!(!is_ambiguous("main.rs"));
        assert!(!is_ambiguous("Makefile"));
    }

    #[test]
    fn case_insensitive() {
        assert!(is_blocked(".ENV", "/project/.ENV"));
        assert!(is_safe_template(".ENV.EXAMPLE"));
    }

    #[test]
    fn envrc_blocked_on_tool_side() {
        // #119: .envrc is dangerous on the Bash side but was wide open to
        // Read/Grep/Write/Edit — the tool-side block needs the filename listed.
        assert!(is_blocked(".envrc", "/project/.envrc"));
        // Safe-template check runs first in the guards, so .envrc.example is
        // still allowed.
        assert!(is_safe_template(".envrc.example"));
    }

    #[test]
    fn aws_kube_credential_stores_blocked_by_fragment() {
        // #77: high-value plaintext credential stores reachable only by path —
        // matched as parent-dir-qualified fragments, not bare basenames.
        assert!(is_blocked("credentials", "/home/user/.aws/credentials"));
        assert!(is_blocked("config", "/home/user/.kube/config"));
        // Fragment form also covers adjacent variants in the same dir.
        assert!(is_blocked(
            "credentials.bak",
            "/home/user/.aws/credentials.bak"
        ));
    }

    #[test]
    fn plaintext_credential_dotfiles_blocked() {
        // #77: exact-filename plaintext credential stores (git token store,
        // Postgres password file).
        assert!(is_blocked(
            ".git-credentials",
            "/home/user/.git-credentials"
        ));
        assert!(is_blocked(".pgpass", "/home/user/.pgpass"));
    }

    #[test]
    fn bare_config_and_credentials_not_overblocked() {
        // #77 guard: the generic basenames are fragments (parent-dir-qualified),
        // so benign `config`/`credentials` files outside the credential dirs
        // stay readable — proves no bare filename was added.
        assert!(!is_blocked("config", "/project/config"));
        assert!(!is_blocked("config", "/project/src/config"));
        assert!(!is_blocked("credentials", "/project/credentials"));
    }

    #[test]
    fn dangerous_env_tokens_detected() {
        assert!(is_dangerous_env_token(".env"));
        assert!(is_dangerous_env_token(".envrc"));
        assert!(is_dangerous_env_token(".env.local"));
        assert!(is_dangerous_env_token(".env.production"));
        assert!(is_dangerous_env_token("@.env"));
        assert!(is_dangerous_env_token("/app/.env"));
        assert!(is_dangerous_env_token(".env)"));
        assert!(is_dangerous_env_token(".ENV"));
    }

    #[test]
    fn clean_env_lookalike_tokens_pass() {
        assert!(!is_dangerous_env_token("settings.environment"));
        assert!(!is_dangerous_env_token(".environment"));
        assert!(!is_dangerous_env_token("my.envelope.txt"));
        assert!(!is_dangerous_env_token(".env.example"));
        assert!(!is_dangerous_env_token(".env.test"));
        assert!(!is_dangerous_env_token(".env.template"));
        assert!(!is_dangerous_env_token("env"));
        assert!(!is_dangerous_env_token("-env"));
        assert!(!is_dangerous_env_token("feat/allow-main-branch-env"));
    }
}
