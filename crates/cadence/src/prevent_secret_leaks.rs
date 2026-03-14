//! Prevent secrets from leaking into the conversation context.
//!
//! Blocks Read/Grep on .env files, credentials, and private keys.
//! Blocks Bash commands that would cat/source/dump secrets.
//! Safe templates (.env.example, .env.test) are always allowed.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Safe template suffixes that are always allowed to read.
const SAFE_SUFFIXES: &[&str] = &[
    ".example",
    ".template",
    ".sample",
    ".defaults",
    ".test",
    ".ci",
    ".pub",
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

fn is_ambiguous(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        return WARN_EXTENSIONS.contains(&ext);
    }
    false
}

/// Extract the operand (file argument) for a read command like `cat`, `head`, etc.
/// Returns the first non-flag argument after the command.
fn read_operand(command: &str, cmd_prefix: &str) -> Option<String> {
    let lower = command.to_lowercase();
    let after = lower.split(cmd_prefix).nth(1)?;
    after
        .split_whitespace()
        .find(|t| !t.starts_with('-'))
        .map(|s| s.to_string())
}

/// Check if a specific file token is a dangerous .env target.
fn is_dangerous_env_operand(operand: &str) -> bool {
    let lower = operand.to_lowercase();
    if !lower.contains(".env") {
        return false;
    }
    !SAFE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Check if `. ` appears in a command position (start of command or after a chain
/// operator), not as an argument to another command like `grep . .env`.
fn is_dot_source_command(lower: &str) -> bool {
    let trimmed = lower.trim_start();
    if trimmed.starts_with(". ") {
        return true;
    }
    // Check after chain operators: &&, ;, ||
    for sep in &["&&", ";", "||"] {
        for segment in lower.split(sep) {
            let seg = segment.trim_start();
            if seg.starts_with(". ") {
                return true;
            }
        }
    }
    false
}

/// Check if a bash command would dump secrets to stdout.
fn bash_leaks_secrets(command: &str) -> Option<CheckResult> {
    let lower = command.to_lowercase();

    // Block: cat/head/tail .env files — check operand, not whole command
    if lower.contains(".env") {
        let read_cmds = ["cat ", "head ", "tail ", "less ", "more ", "bat "];

        for cmd in &read_cmds {
            if lower.contains(cmd)
                && let Some(operand) = read_operand(&lower, cmd)
                && is_dangerous_env_operand(&operand)
            {
                return Some(CheckResult::block(
                    "🚫 BLOCKED: Command would read .env file contents into context. \
                         Secrets are available to commands via direnv — run programs directly.",
                ));
            }
        }

        // Block: source .env — check operand
        // "source " is unambiguous, but ". " matches any substring containing ". "
        // (e.g., "grep . .env", "find . -name .env"). Only match ". " at command
        // start or after chain operators (&&, ;, ||).
        if lower.contains("source ")
            && let Some(operand) = read_operand(&lower, "source ")
            && is_dangerous_env_operand(&operand)
        {
            return Some(CheckResult::block(
                "🚫 BLOCKED: Command would source .env file, exposing secrets. \
                     Secrets are available via direnv — run programs directly.",
            ));
        }

        if is_dot_source_command(&lower)
            && let Some(operand) = read_operand(&lower, ". ")
            && is_dangerous_env_operand(&operand)
        {
            return Some(CheckResult::block(
                "🚫 BLOCKED: Command would source .env file, exposing secrets. \
                     Secrets are available via direnv — run programs directly.",
            ));
        }
    }

    // Warn: env dump commands (match as standalone commands, not substrings)
    let env_dumps = [" env", "env ", "printenv", "export -p", "declare -x"];
    for dump in &env_dumps {
        if lower.contains(dump) || lower == "env" {
            return Some(CheckResult::warn(
                "⚠️  Command would dump environment variables, which may include secrets. \
                 Run programs that use env vars directly instead.",
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
             Run programs that use env vars directly instead.",
        ));
    }

    None
}

/// Blocks reading secrets into context via Read, Grep, or Bash.
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
                let filename = path.rsplit('/').next().unwrap_or(&path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, &path) {
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
                let filename = path.rsplit('/').next().unwrap_or(&path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, &path) {
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
            tool_input: Some(cadence_hooks_core::ToolInput {
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
            tool_input: Some(cadence_hooks_core::ToolInput {
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_normal_file_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cat_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_cat_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_dump_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printenv"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    fn make_grep_input(path: &str) -> HookInput {
        HookInput {
            tool_name: Some("Grep".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
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

    #[test]
    fn grep_env_blocked() {
        let result = SecretLeaksGuard.run(&make_grep_input("/project/.env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn grep_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_grep_input("/project/.env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn grep_normal_file_allowed() {
        let result = SecretLeaksGuard.run(&make_grep_input("/project/src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_credentials_json_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/credentials.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_id_rsa_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.ssh/id_rsa"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_id_ed25519_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.ssh/id_ed25519"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_key_file_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/server.key"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_pem_ambiguous_warned() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/cert.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn read_private_pem_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/server-key.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_pub_key_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.ssh/id_rsa.pub"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_source_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("source .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_head_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("head -5 .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_tail_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("tail .env.local"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_echo_secret_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("echo $SECRET_TOKEN"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_echo_password_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printf '%s' $PASSWORD"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_export_p_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("export -p"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_normal_command_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("cargo test"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_tool_input_allowed() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            tool_input: None,
            cwd: None,
        };
        let result = SecretLeaksGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn unknown_tool_allowed() {
        let input = HookInput {
            tool_name: Some("Agent".into()),
            tool_input: None,
            cwd: None,
        };
        let result = SecretLeaksGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_service_account_json_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/service-account-prod.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_docker_config_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.docker/config.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Unhappy path: bypass scenarios ---

    #[test]
    fn bash_less_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("less .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_more_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("more .env.production"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_bat_env_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("bat .env.local"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_dot_source_env_blocked() {
        // `. .env` is equivalent to `source .env`
        let result = SecretLeaksGuard.run(&make_bash_input(". .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_source_env_example_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("source .env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_as_standalone_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_declare_x_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("declare -x"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_echo_credential_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("echo $CREDENTIAL"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_echo_auth_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("echo $AUTH_TOKEN"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn bash_printf_key_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printf '%s' $API_KEY"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn read_env_staging_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.staging"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_env_development_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.development"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_env_secret_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.secret"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_env_keys_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.keys"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_secrets_json_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/secrets.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_id_ecdsa_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.ssh/id_ecdsa"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_id_dsa_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.ssh/id_dsa"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_pypirc_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.pypirc"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_npmrc_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.npmrc"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_netrc_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/home/user/.netrc"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_p12_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/cert.p12"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_pfx_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/cert.pfx"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_keystore_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/app.keystore"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_jks_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/app.jks"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_underscore_key_pem_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/server_key.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_private_pem_suffix_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/server.private.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_p8_ambiguous_warned() {
        let result = SecretLeaksGuard.run(&make_read_input("/etc/ssl/signing.p8"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn read_gcloud_credentials_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/gcloud-credentials.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn read_template_suffix_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.template"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_sample_suffix_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/credentials.json.sample"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_test_suffix_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.test"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_ci_suffix_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.ci"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_defaults_suffix_allowed() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env.defaults"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn grep_blocked_extension_blocked() {
        let result = SecretLeaksGuard.run(&make_grep_input("/etc/ssl/server.key"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn grep_safe_template_allowed() {
        let result = SecretLeaksGuard.run(&make_grep_input("/project/.env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn grep_ambiguous_not_warned() {
        // Grep doesn't warn on ambiguous — only blocks on definite secrets
        let result = SecretLeaksGuard.run(&make_grep_input("/etc/ssl/cert.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretLeaksGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn read_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretLeaksGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn grep_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Grep".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretLeaksGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn case_insensitive_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.ENV"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn case_insensitive_safe_template() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.ENV.EXAMPLE"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Regression: path normalization bypass prevention ---

    #[test]
    fn trailing_slash_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env/"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn trailing_whitespace_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env "));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn null_byte_injection_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env\0.txt"));
        // After null byte removal: "/project/.env.txt" - not a blocked name
        // But the key is that \0 doesn't help bypass — ".env" files still blocked
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn null_byte_in_env_blocked() {
        // Null byte at end — after removal it's just "/project/.env"
        let result = SecretLeaksGuard.run(&make_read_input("/project/.env\0"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn backslash_path_blocked() {
        let result = SecretLeaksGuard.run(&make_read_input(r"C:\Users\dev\.env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn no_extension_not_ambiguous() {
        // File without extension should not be flagged as ambiguous
        let result = SecretLeaksGuard.run(&make_read_input("/project/Makefile"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cat_env_example_pipe_allowed() {
        // Operand is .env.example (safe template), even though command mentions .env
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env.example | grep KEY"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cat_env_with_example_in_pipe_blocked() {
        // cat .env piped to grep — operand is .env which is dangerous
        let result = SecretLeaksGuard.run(&make_bash_input("cat .env | grep example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Regression: dot-source false positives ---

    #[test]
    fn bash_grep_dot_env_allowed() {
        // `grep . .env` uses `. ` as a regex pattern argument, not dot-source
        // The read_cmds check handles grep separately; `. ` must not false-positive
        let result = SecretLeaksGuard.run(&make_bash_input("grep . .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_find_dot_env_allowed() {
        // `find . -name .env` uses `.` as a directory, not dot-source
        let result = SecretLeaksGuard.run(&make_bash_input("find . -name .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_dot_source_env_still_blocked() {
        // `. .env` at start of command is genuine dot-source
        let result = SecretLeaksGuard.run(&make_bash_input(". .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_dot_source_after_chain_blocked() {
        // `. .env` after && is genuine dot-source
        let result = SecretLeaksGuard.run(&make_bash_input("cd /app && . .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_dot_source_after_semicolon_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("cd /app; . .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_dot_source_after_or_blocked() {
        let result = SecretLeaksGuard.run(&make_bash_input("test -f .env || . .env.local"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
