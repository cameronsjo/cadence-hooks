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

    #[test]
    fn bash_append_env_blocked() {
        assert!(bash_targets_env_file("echo SECRET >> .env"));
    }

    #[test]
    fn bash_rm_env_no_flag_blocked() {
        assert!(bash_targets_env_file("rm .env"));
    }

    #[test]
    fn service_account_json_blocked() {
        assert!(is_blocked(
            "service-account-prod.json",
            "/project/service-account-prod.json"
        ));
    }

    #[test]
    fn docker_config_path_blocked() {
        assert!(is_blocked(
            "config.json",
            "/home/user/.docker/config.json"
        ));
    }

    #[test]
    fn p12_extension_blocked() {
        assert!(is_blocked("cert.p12", "/etc/ssl/cert.p12"));
    }

    #[test]
    fn pfx_extension_blocked() {
        assert!(is_blocked("cert.pfx", "/etc/ssl/cert.pfx"));
    }

    #[test]
    fn keystore_extension_blocked() {
        assert!(is_blocked("app.keystore", "/project/app.keystore"));
    }

    #[test]
    fn npmrc_blocked() {
        assert!(is_blocked(".npmrc", "/home/user/.npmrc"));
    }

    #[test]
    fn netrc_blocked() {
        assert!(is_blocked(".netrc", "/home/user/.netrc"));
    }

    #[test]
    fn private_pem_suffix_blocked() {
        assert!(is_blocked("server.private.pem", "/etc/ssl/server.private.pem"));
    }

    #[test]
    fn underscore_key_pem_blocked() {
        assert!(is_blocked("server_key.pem", "/etc/ssl/server_key.pem"));
    }

    #[test]
    fn case_insensitivity_blocked() {
        assert!(is_blocked(".ENV", "/project/.ENV"));
    }

    #[test]
    fn case_insensitivity_safe() {
        assert!(is_safe_template(".ENV.EXAMPLE"));
    }

    #[test]
    fn no_extension_not_ambiguous() {
        assert!(!is_ambiguous("Makefile"));
    }

    // Full Check::run() integration tests

    fn make_write_input(path: &str) -> HookInput {
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: Some("content".into()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    fn make_edit_input(path: &str) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: None,
                new_string: Some("new".into()),
                old_string: Some("old".into()),
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
    fn write_env_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.env.local"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_env_example_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.example"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_pem_warned() {
        let result = SecretWritesGuard.run(&make_write_input("/etc/ssl/cert.pem"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn write_normal_file_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/src/main.rs"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_redirect_blocked_via_run() {
        let result = SecretWritesGuard.run(&make_bash_input("echo KEY=val > .env"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_normal_command_allowed_via_run() {
        let result = SecretWritesGuard.run(&make_bash_input("cargo build"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn unknown_tool_allowed() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("/project/.env".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_tool_input_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: bypass scenarios ---

    #[test]
    fn bash_tee_env_not_detected() {
        // Known gap: tee/cp/dd bypass not detected by current implementation
        let result = SecretWritesGuard.run(&make_bash_input("echo SECRET | tee .env"));
        // tee doesn't use > or rm, so it won't be caught
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cp_env_not_detected() {
        // Known gap: cp bypass
        let result = SecretWritesGuard.run(&make_bash_input("cp source.txt .env"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_redirect_env_staging_blocked() {
        assert!(bash_targets_env_file("echo KEY=val > .env.staging"));
    }

    #[test]
    fn bash_rm_rf_env_blocked() {
        assert!(bash_targets_env_file("rm -rf .env"));
    }

    #[test]
    fn edit_key_file_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input("/etc/ssl/server.key"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_private_pem_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input("/etc/ssl/server-key.pem"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_id_rsa_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/home/user/.ssh/id_rsa"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_credentials_json_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/credentials.json"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_secrets_json_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/secrets.json"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_jks_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/app.jks"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_p8_warned() {
        let result = SecretWritesGuard.run(&make_write_input("/etc/ssl/signing.p8"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn write_gcloud_credentials_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/gcloud-credentials.json"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_service_account_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/service-account.json"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_example_allowed() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.env.example"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn edit_env_template_allowed() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.env.template"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_env_test_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.test"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_env_ci_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.ci"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_pub_key_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/home/user/.ssh/id_rsa.pub"));
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: Some("content".into()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_template_redirect_allowed() {
        assert!(!bash_targets_env_file("echo KEY=val > .env.example"));
    }

    #[test]
    fn bash_no_env_in_command_allowed() {
        assert!(!bash_targets_env_file("echo hello > output.txt"));
    }
}
