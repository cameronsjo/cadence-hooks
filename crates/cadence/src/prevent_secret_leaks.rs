use claude_hooks_core::{Check, CheckResult, HookInput};

/// Safe template suffixes that are always allowed to read.
const SAFE_SUFFIXES: &[&str] = &[
    ".example", ".template", ".sample", ".defaults", ".test", ".ci", ".pub",
];

/// Files that must never be read into context.
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

/// File extensions that must never be read.
const BLOCKED_EXTENSIONS: &[&str] = &["key", "p12", "pfx", "keystore", "jks"];

/// File patterns that must never be read.
const BLOCKED_SUFFIXES: &[&str] = &["-key.pem", "_key.pem", ".private.pem"];

/// Path fragments indicating secrets.
const BLOCKED_PATH_FRAGMENTS: &[&str] = &[".docker/config.json", "gcloud-credentials.json"];

/// Ambiguous patterns (warn, not block).
const WARN_EXTENSIONS: &[&str] = &["pem", "p8"];

fn is_safe_template(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    SAFE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

fn is_blocked(filename: &str, path: &str) -> bool {
    let lower = filename.to_lowercase();

    if BLOCKED_FILENAMES.iter().any(|&p| lower == p) {
        return true;
    }

    if BLOCKED_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
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

fn is_ambiguous(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        return WARN_EXTENSIONS.contains(&ext);
    }
    false
}

/// Check if a bash command would dump secrets to stdout.
fn bash_leaks_secrets(command: &str) -> Option<CheckResult> {
    let lower = command.to_lowercase();

    // Block: cat/head/tail .env files
    if lower.contains(".env") {
        let reads_env = ["cat ", "head ", "tail ", "less ", "more ", "bat "]
            .iter()
            .any(|cmd| lower.contains(cmd));

        if reads_env && !SAFE_SUFFIXES.iter().any(|s| lower.contains(s)) {
            return Some(CheckResult::block(
                "🚫 BLOCKED: Command would read .env file contents into context. \
                 Secrets are available to commands via direnv — run programs directly."
            ));
        }

        // Block: source .env
        if lower.contains("source") || lower.contains(". ") {
            if !SAFE_SUFFIXES.iter().any(|s| lower.contains(s)) {
                return Some(CheckResult::block(
                    "🚫 BLOCKED: Command would source .env file, exposing secrets. \
                     Secrets are available via direnv — run programs directly."
                ));
            }
        }
    }

    // Warn: env dump commands (match as standalone commands, not substrings)
    let env_dumps = [" env", "env ", "printenv", "export -p", "declare -x"];
    for dump in &env_dumps {
        if lower.contains(dump) || lower == "env" {
            return Some(CheckResult::warn(
                "⚠️  Command would dump environment variables, which may include secrets. \
                 Run programs that use env vars directly instead."
            ));
        }
    }

    // Warn: echo/printf of secret env vars
    if (lower.contains("echo") || lower.contains("printf"))
        && ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"]
            .iter()
            .any(|s| command.contains(s))
    {
        return Some(CheckResult::warn(
            "⚠️  Command may print a secret environment variable. \
             Run programs that use env vars directly instead."
        ));
    }

    None
}

pub struct SecretLeaksGuard;

impl Check for SecretLeaksGuard {
    fn name(&self) -> &str {
        "prevent-secret-leaks"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let tool = input.tool_name().unwrap_or("");

        match tool {
            "Read" => {
                let Some(path) = input.file_path() else {
                    return CheckResult::allow();
                };
                let filename = path.rsplit('/').next().unwrap_or(path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, path) {
                    return CheckResult::block(format!(
                        "🚫 BLOCKED (Read): '{filename}' contains secrets. \
                         Use direnv or shell env to make secrets available."
                    ));
                }

                if is_ambiguous(filename) {
                    return CheckResult::warn(format!(
                        "⚠️  (Read) '{filename}' may contain private key material. \
                         Approve only if you know this is a public cert."
                    ));
                }

                CheckResult::allow()
            }
            "Grep" => {
                let Some(path) = input.file_path() else {
                    return CheckResult::allow();
                };
                let filename = path.rsplit('/').next().unwrap_or(path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, path) {
                    return CheckResult::block(format!(
                        "🚫 BLOCKED (Grep): '{filename}' contains secrets. \
                         Use direnv or shell env to make secrets available."
                    ));
                }

                CheckResult::allow()
            }
            "Bash" => {
                let Some(command) = input.command() else {
                    return CheckResult::allow();
                };

                bash_leaks_secrets(command).unwrap_or_else(CheckResult::allow)
            }
            _ => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_read_input(path: &str) -> HookInput {
        HookInput {
            tool_name: Some("Read".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    fn make_bash_input(command: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some(command.into()),
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn read_env_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.example"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_normal_file_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/src/main.rs"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cat_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_cat_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env.example"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_dump_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printenv"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }
}
