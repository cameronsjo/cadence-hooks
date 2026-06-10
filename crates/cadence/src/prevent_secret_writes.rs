//! Prevent writing or deleting secret files.
//!
//! Blocks Write/Edit on .env files, credentials, private keys, and keystores.
//! Blocks Bash commands that redirect to or `rm` secret files.
//! Safe templates (.env.example, .env.test) are always allowed.

use crate::secret_patterns::{SAFE_SUFFIXES, is_ambiguous, is_blocked, is_safe_template};
use cadence_hooks_core::shell::command_segments;
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Extract every redirect target in a command segment — the filename after each
/// `>`, `>>`, `>|`, `2>`, `&>`, etc. Quote-aware: a `>` inside `'…'`/`"…"` is
/// literal text, not a redirect (so `echo "a > b" > c` targets only `c`). This
/// catches stderr, clobber, glued (`>file`), and multiple redirects in one
/// segment — the old single-`>` scan saw only the first.
fn redirect_targets(segment: &str) -> Vec<String> {
    let chars: Vec<char> = segment.chars().collect();
    let mut targets = Vec::new();
    let mut i = 0;
    let mut quote: Option<char> = None;

    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                i += 1;
            }
            '>' => {
                i += 1;
                // Consume a doubled `>>` (append) or `>|` (clobber).
                if i < chars.len() && (chars[i] == '>' || chars[i] == '|') {
                    i += 1;
                }
                // Skip whitespace between the operator and the filename.
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                // Collect the target token, honoring a quoted filename.
                let mut target = String::new();
                while i < chars.len() {
                    let tc = chars[i];
                    if tc == '\'' || tc == '"' {
                        i += 1;
                        while i < chars.len() && chars[i] != tc {
                            target.push(chars[i]);
                            i += 1;
                        }
                        if i < chars.len() {
                            i += 1; // closing quote
                        }
                        continue;
                    }
                    if tc.is_whitespace() || matches!(tc, '>' | '<' | '|' | ';' | '&') {
                        break;
                    }
                    target.push(tc);
                    i += 1;
                }
                if !target.is_empty() {
                    targets.push(target);
                }
            }
            _ => i += 1,
        }
    }

    targets
}

/// Extract rm targets from a command (tokens after rm that aren't flags).
fn rm_targets(command: &str) -> Vec<&str> {
    let mut targets = Vec::new();
    let mut in_rm = false;
    for token in command.split_whitespace() {
        if token == "rm" {
            in_rm = true;
            continue;
        }
        if in_rm {
            if token.starts_with('-') {
                continue;
            }
            targets.push(token);
        }
    }
    targets
}

/// Check if a specific file token is a dangerous .env target.
fn is_dangerous_env_target(target: &str) -> bool {
    let lower = target.to_lowercase();
    if !lower.contains(".env") {
        return false;
    }
    !SAFE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Check if a bash command targets .env files destructively.
fn bash_targets_env_file(command: &str) -> bool {
    // Quick reject: nothing to guard if no `.env` token appears anywhere.
    if !command.to_lowercase().contains(".env") {
        return false;
    }

    // Judge each command segment independently so a benign first redirect can't
    // shield a dangerous one later in the chain, and a write hidden in
    // `sh -c '…'` is still seen. `is_dangerous_env_target` lowercases per token.
    for segment in command_segments(command) {
        for target in redirect_targets(&segment) {
            if is_dangerous_env_target(&target) {
                return true;
            }
        }
        for target in rm_targets(&segment) {
            if is_dangerous_env_target(target) {
                return true;
            }
        }
    }

    false
}

/// Blocks writing, editing, or deleting secret files via Write, Edit, or Bash.
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
                let filename = path.rsplit('/').next().unwrap_or(&path);

                if is_safe_template(filename) {
                    return CheckResult::allow();
                }

                if is_blocked(filename, &path) {
                    return CheckResult::block(format!(
                        "🚫 BLOCKED: '{filename}' is a protected file (secrets/credentials). \
                         Modify manually outside Claude Code."
                    ));
                }

                if is_ambiguous(filename) {
                    return CheckResult::nudge(format!(
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
        assert!(is_blocked("config.json", "/home/user/.docker/config.json"));
    }

    #[test]
    fn docker_config_path_mixed_case_blocked() {
        assert!(is_blocked("config.json", "/home/user/.Docker/config.json"));
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
        assert!(is_blocked(
            "server.private.pem",
            "/etc/ssl/server.private.pem"
        ));
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

    use cadence_hooks_core::test_builders::make_bash as make_bash_input;
    use cadence_hooks_core::test_builders::make_edit as make_edit_input;

    fn make_write_input(path: &str) -> HookInput {
        cadence_hooks_core::test_builders::make_write(path, "content")
    }

    #[test]
    fn write_env_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.env.local", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_env_example_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_pem_warned() {
        let result = SecretWritesGuard.run(&make_write_input("/etc/ssl/cert.pem"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn write_normal_file_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_redirect_blocked_via_run() {
        let result = SecretWritesGuard.run(&make_bash_input("echo KEY=val > .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_normal_command_allowed_via_run() {
        let result = SecretWritesGuard.run(&make_bash_input("cargo build"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn unknown_tool_allowed() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/.env".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_tool_input_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: bypass scenarios ---

    #[test]
    fn bash_tee_env_not_detected() {
        // Known gap: tee/cp/dd bypass not detected by current implementation
        let result = SecretWritesGuard.run(&make_bash_input("echo SECRET | tee .env"));
        // tee doesn't use > or rm, so it won't be caught
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_cp_env_not_detected() {
        // Known gap: cp bypass
        let result = SecretWritesGuard.run(&make_bash_input("cp source.txt .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
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
        let result = SecretWritesGuard.run(&make_edit_input("/etc/ssl/server.key", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_private_pem_blocked() {
        let result =
            SecretWritesGuard.run(&make_edit_input("/etc/ssl/server-key.pem", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_id_rsa_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/home/user/.ssh/id_rsa"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_credentials_json_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/credentials.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_secrets_json_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/secrets.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_jks_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/app.jks"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_p8_warned() {
        let result = SecretWritesGuard.run(&make_write_input("/etc/ssl/signing.p8"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn write_gcloud_credentials_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/gcloud-credentials.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_service_account_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/service-account.json"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_example_allowed() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.env.example", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn edit_env_template_allowed() {
        let result =
            SecretWritesGuard.run(&make_edit_input("/project/.env.template", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_env_test_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.test"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_env_ci_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.ci"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_pub_key_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/home/user/.ssh/id_rsa.pub"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Regression: path normalization bypass prevention ---

    #[test]
    fn write_env_trailing_slash_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env/"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_env_trailing_whitespace_blocked() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.env "));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_backslash_path_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input(r"C:\Users\dev\.env", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
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
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn write_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: Some("content".into()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = SecretWritesGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_env_template_redirect_allowed() {
        assert!(!bash_targets_env_file("echo KEY=val > .env.example"));
    }

    #[test]
    fn bash_redirect_no_space_blocked() {
        assert!(bash_targets_env_file("echo KEY=val>.env"));
    }

    #[test]
    fn bash_append_no_space_blocked() {
        assert!(bash_targets_env_file("echo KEY=val>>.env"));
    }

    #[test]
    fn bash_no_env_in_command_allowed() {
        assert!(!bash_targets_env_file("echo hello > output.txt"));
    }

    #[test]
    fn bash_cat_example_redirect_to_env_blocked() {
        // Safe template in source but dangerous target — must block
        assert!(bash_targets_env_file("cat .env.example > .env"));
    }

    #[test]
    fn bash_cp_example_to_env_not_detected() {
        // cp bypass — known gap (no redirect/rm)
        assert!(!bash_targets_env_file("cp .env.example .env"));
    }

    #[test]
    fn bash_redirect_to_env_example_allowed() {
        // Redirect target is a safe template
        assert!(!bash_targets_env_file("echo KEY=val > .env.example"));
    }

    #[test]
    fn bash_rm_env_example_allowed() {
        // rm target is a safe template
        assert!(!bash_targets_env_file("rm .env.example"));
    }

    // --- #75: per-segment, all-operator redirect scanning ---

    #[test]
    fn chained_benign_then_secret_redirect_blocked() {
        // The bypass: only the first redirect (safe.txt) was inspected.
        assert!(bash_targets_env_file(
            "echo ok > safe.txt && echo SECRET > .env"
        ));
    }

    #[test]
    fn stderr_redirect_to_env_blocked() {
        assert!(bash_targets_env_file("echo SECRET 2> .env"));
    }

    #[test]
    fn clobber_redirect_to_env_blocked() {
        assert!(bash_targets_env_file("echo SECRET >| .env"));
    }

    #[test]
    fn semicolon_chained_secret_redirect_blocked() {
        assert!(bash_targets_env_file("cmd > a.txt; echo S > .env"));
    }

    #[test]
    fn sh_c_wrapped_secret_redirect_blocked() {
        assert!(bash_targets_env_file("sh -c 'echo SECRET > .env'"));
    }

    #[test]
    fn quoted_redirect_text_not_flagged() {
        // The `> .env` inside the quoted string is literal text; only the real
        // `> note.txt` redirect counts — must not block.
        assert!(!bash_targets_env_file(
            r#"echo "redirect > .env in a string" > note.txt"#
        ));
    }

    #[test]
    fn dup_fd_redirect_not_flagged() {
        // `2>&1` duplicates a descriptor — no `.env` file target.
        assert!(!bash_targets_env_file("echo SECRET > out.txt 2>&1"));
    }

    #[test]
    fn chained_secret_redirect_blocks_via_run() {
        let result =
            SecretWritesGuard.run(&make_bash_input("echo ok > safe.txt && echo SECRET > .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
