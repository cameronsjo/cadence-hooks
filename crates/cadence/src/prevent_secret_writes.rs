use claude_hooks_core::{Check, CheckResult, HookInput};

/// Safe template suffixes that are always allowed.
const SAFE_SUFFIXES: &[&str] = &[
    ".example", ".template", ".sample", ".defaults", ".test", ".ci", ".pub",
];

/// Files that must never be written by Claude Code.
const BLOCKED_FILENAMES: &[&str] = &[
    ".env",
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
];

/// File extensions that must never be written (unambiguous secrets).
const BLOCKED_EXTENSIONS: &[&str] = &["key", "p12", "pfx", "keystore", "jks"];

/// File patterns that must never be written (with glob-like matching).
const BLOCKED_SUFFIXES: &[&str] = &["-key.pem", "_key.pem", ".private.pem"];

/// Path fragments that indicate secrets.
const BLOCKED_PATH_FRAGMENTS: &[&str] = &[".docker/config.json", "gcloud-credentials.json"];

/// Ambiguous patterns that warn but don't block.
const WARN_EXTENSIONS: &[&str] = &["pem", "p8"];

/// Check if a filename is a safe template.
fn is_safe_template(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    SAFE_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// Check if a filename matches blocked patterns.
fn is_blocked(filename: &str, path: &str) -> bool {
    let lower = filename.to_lowercase();

    if BLOCKED_FILENAMES.iter().any(|&p| lower == p) {
        return true;
    }

    if BLOCKED_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix)) {
        return true;
    }

    if let Some(ext) = lower.rsplit('.').next() {
        if BLOCKED_EXTENSIONS.contains(&ext) {
            return true;
        }
    }

    if lower.starts_with("service-account") && lower.ends_with(".json") {
        return true;
    }

    BLOCKED_PATH_FRAGMENTS.iter().any(|frag| path.contains(frag))
}

/// Check if a filename is ambiguous (warn, not block).
fn is_ambiguous(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        return WARN_EXTENSIONS.contains(&ext);
    }
    false
}

/// Check if a bash command targets .env files destructively.
fn bash_targets_env_file(command: &str) -> bool {
    // Match: > .env, >> .env, rm .env, rm -f .env
    let lower = command.to_lowercase();

    let has_env_target = lower.contains(".env");
    if !has_env_target {
        return false;
    }

    // Check it's not targeting a safe template
    if SAFE_SUFFIXES.iter().any(|s| lower.contains(s)) {
        return false;
    }

    // Redirect or rm targeting .env
    lower.contains("> .env") || lower.contains(">> .env") || lower.contains("rm ")
}

pub struct SecretWritesGuard;

impl Check for SecretWritesGuard {
    fn name(&self) -> &str {
        "prevent-secret-writes"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let tool = input.tool_name().unwrap_or("");

        match tool {
            "Write" | "Edit" => {
                let Some(path) = input.file_path() else {
                    return CheckResult::allow();
                };
                let filename = path.rsplit('/').next().unwrap_or(path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, path) {
                    return CheckResult::block(format!(
                        "🚫 BLOCKED: '{filename}' is a protected file (secrets/credentials). \
                         Modify manually outside Claude Code."
                    ));
                }

                if is_ambiguous(filename) {
                    return CheckResult::warn(format!(
                        "⚠️  '{filename}' may contain private key material. \
                         Approve only if you know this is a public cert."
                    ));
                }

                CheckResult::allow()
            }
            "Bash" => {
                let Some(command) = input.command() else {
                    return CheckResult::allow();
                };

                if bash_targets_env_file(command) {
                    return CheckResult::block(
                        "🚫 BLOCKED: Bash command would modify/delete a .env file. \
                         Modify manually outside Claude Code.",
                    );
                }

                CheckResult::allow()
            }
            _ => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files_blocked() {
        assert!(is_blocked(".env", "/project/.env"));
        assert!(is_blocked(".env.local", "/project/.env.local"));
        assert!(is_blocked(".env.production", "/project/.env.production"));
    }

    #[test]
    fn key_files_blocked() {
        assert!(is_blocked("server.key", "/etc/ssl/server.key"));
        assert!(is_blocked("server-key.pem", "/etc/ssl/server-key.pem"));
        assert!(is_blocked("id_rsa", "/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn safe_templates_allowed() {
        assert!(is_safe_template(".env.example"));
        assert!(is_safe_template("config.template"));
        assert!(is_safe_template("cert.pub"));
        assert!(!is_safe_template(".env"));
    }

    #[test]
    fn ambiguous_pem_warned() {
        assert!(is_ambiguous("cert.pem"));
        assert!(is_ambiguous("signing.p8"));
        assert!(!is_ambiguous("main.rs"));
    }

    #[test]
    fn normal_files_allowed() {
        assert!(!is_blocked("main.rs", "/project/src/main.rs"));
        assert!(!is_blocked("config.toml", "/project/config.toml"));
    }

    #[test]
    fn bash_env_redirect_blocked() {
        assert!(bash_targets_env_file("echo SECRET > .env"));
        assert!(bash_targets_env_file("rm -f .env.local"));
    }

    #[test]
    fn bash_env_template_allowed() {
        assert!(!bash_targets_env_file("cat .env.example"));
    }
}
