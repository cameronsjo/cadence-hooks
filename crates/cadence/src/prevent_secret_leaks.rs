//! Prevent secrets from leaking into the conversation context.
//!
//! Blocks Read/Grep on .env files, credentials, and private keys.
//! Blocks Bash commands that would cat/source/dump secrets.
//! Safe templates (.env.example, .env.test) are always allowed.

use crate::secret_patterns::{SAFE_SUFFIXES, is_ambiguous, is_blocked, is_safe_template};
use cadence_hooks_core::{Check, CheckResult, HookInput};

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

/// Split `s` on shell chain operators (`;`, `|`, `&`) that occur outside of
/// quoted strings. Tracks single-quote, double-quote, and backslash-escape
/// state so a separator inside `"..."` or `'...'` does NOT split a segment.
///
/// Heredoc bodies are NOT handled explicitly — but the common case
/// `"$(cat <<EOF ... EOF)"` is protected by the surrounding double quotes.
/// Bare heredocs outside any quote are an out-of-scope edge case; if they
/// ever become a real source of false positives, lift to a real shell
/// tokenizer.
fn split_chain_operators(s: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for (i, &b) in bytes.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && !in_single {
            escape = true;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if !in_single && !in_double && (b == b';' || b == b'|' || b == b'&') {
            segments.push(&s[start..i]);
            start = i + 1;
        }
    }
    segments.push(&s[start..]);
    segments
}

/// Check if a command token sequence appears as the first executed command
/// of any segment when split on chain operators (`&&`, `||`, `;`, `|`)
/// outside quotes.
///
/// `cmd` is a slice of tokens that must match in order at the start of a
/// segment — e.g., `&["env"]` matches `env`, `env -i bash`, `cd /tmp && env`,
/// but not `gh env`, `direnv env`, or `grep env_dump`. `&["export", "-p"]`
/// matches `export -p` but not `export FOO=bar`.
///
/// Quote-aware splitting prevents substring/heredoc false positives like
/// `gh issue create --body "$(cat <<EOF ... env ... EOF)"` or
/// `git commit -m "docs: foo; env usage"`.
fn is_executed_command(lower: &str, cmd: &[&str]) -> bool {
    for segment in split_chain_operators(lower) {
        let mut tokens = segment.split_whitespace();
        match cmd {
            [a] if tokens.next() == Some(a) => return true,
            [a, b] if tokens.next() == Some(a) && tokens.next() == Some(b) => return true,
            _ => {}
        }
    }
    false
}

/// Check if `. ` appears in a command position (start of command or after a
/// chain operator), not as an argument to another command like
/// `grep . .env`. Quote-aware so `. ` inside a quoted string doesn't fire.
fn is_dot_source_command(lower: &str) -> bool {
    for segment in split_chain_operators(lower) {
        if segment.trim_start().starts_with(". ") {
            return true;
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

    // Warn: env dump commands. Must appear as the executed command at the
    // start of a segment (or after a chain operator), not as a substring of
    // an argument, path, or compound binary name like `direnv`/`envoy`/`gh env`.
    let env_dump_commands: &[&[&str]] = &[
        &["env"],
        &["printenv"],
        &["export", "-p"],
        &["declare", "-x"],
    ];
    for cmd in env_dump_commands {
        if is_executed_command(&lower, cmd) {
            return Some(CheckResult::nudge(
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
        return Some(CheckResult::nudge(
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
                    return CheckResult::nudge(format!(
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

    use cadence_hooks_core::test_builders::make_bash as make_bash_input;

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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_echo_password_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printf '%s' $PASSWORD"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_export_p_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("export -p"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_declare_x_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("declare -x"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_echo_credential_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("echo $CREDENTIAL"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_echo_auth_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("echo $AUTH_TOKEN"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_printf_key_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("printf '%s' $API_KEY"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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

    // --- Regression: env-dump heuristic must position-check, not substring-match ---
    // The previous `" env"` / `"env "` substring patterns false-positived on any
    // command containing `env` as a substring — `gh env list`, `direnv env`,
    // `grep env_dump`, `find . -name 'env*'`, body files with `env` in the path,
    // and heredoc bodies that merely mention env vars. See cadence-hooks#25.

    #[test]
    fn bash_gh_env_subcommand_allowed() {
        // `env` is a subcommand of gh, not the executed command
        let result = SecretLeaksGuard.run(&make_bash_input("gh env list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_aws_vault_env_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("aws-vault env dev"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_direnv_env_allowed() {
        // `direnv` shares an `env` substring but is a different binary
        let result = SecretLeaksGuard.run(&make_bash_input("direnv env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_grep_env_substring_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("grep env_dump src/lib.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_find_env_pattern_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("find . -name 'env*'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_envoy_command_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input("envoy run --config envoy.yaml"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_body_file_with_env_in_path_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input(
            "gh issue create --body-file /tmp/issue-env-dump-fp.md",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_commit_message_mentioning_env_allowed() {
        let result = SecretLeaksGuard.run(&make_bash_input(
            "git commit -m 'docs: explain env-var handling in readme'",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_export_with_value_allowed() {
        // `export FOO=bar` sets an env var — different from `export -p` which dumps
        let result = SecretLeaksGuard.run(&make_bash_input("export FOO=bar"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_with_args_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("env -i bash"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_env_in_pipeline_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("env | grep PATH"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_env_after_chain_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("cd /tmp && env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_env_after_semicolon_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("cd /tmp; env > out.sh"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_export_p_in_pipeline_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("export -p | sort"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn bash_declare_x_after_chain_warned() {
        let result = SecretLeaksGuard.run(&make_bash_input("set -a && declare -x"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    // --- quote-aware splitter false-positive guards ---
    //
    // Separators inside quoted strings must NOT split the segment. Otherwise
    // a commit message, issue body, or heredoc that legitimately mentions
    // `env` after a `;` or `|` re-fires the substring class this PR removed.

    #[test]
    fn bash_semicolon_inside_double_quotes_does_not_split() {
        // CodeRabbit's case: `;` inside the message would naively split into
        // a segment starting with `env`. Quote-aware splitter keeps it whole.
        let result = SecretLeaksGuard.run(&make_bash_input(
            "git commit -m \"docs: foo; env usage notes\"",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_pipe_inside_double_quotes_does_not_split() {
        let result = SecretLeaksGuard.run(&make_bash_input(
            "git commit -m \"refactor: pipe | env tokens\"",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_inside_heredoc_in_command_substitution_allowed() {
        // The heredoc body is inside the outer `"$(...)"`, so quote-aware
        // splitting protects the whole substitution from being broken up.
        let result = SecretLeaksGuard.run(&make_bash_input(
            "gh issue create --body \"$(cat <<EOF\nrun programs that use env vars\nEOF\n)\"",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_branch_name_ending_in_env_allowed() {
        // cadence-hooks#22: branch names that happen to end with `-env`
        // tripped the previous substring matcher via the trailing `&` from
        // `2>&1` or similar.
        let result = SecretLeaksGuard.run(&make_bash_input(
            "git push -u origin feat/allow-main-branch-env 2>&1",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
