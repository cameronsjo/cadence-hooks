//! Prevent writing or deleting secret files.
//!
//! Blocks Write/Edit on .env files, credentials, private keys, and keystores.
//! Blocks Bash commands that redirect to a `.env`-family file or hand one to
//! a writer verb (`tee`, `cp`/`mv`/`install`, `dd`, `truncate`, `rm`) (#76).
//! Safe templates (.env.example, .env.test) are always allowed.

use crate::secret_patterns::{is_ambiguous, is_blocked, is_dangerous_env_token, is_safe_template};
use cadence_hooks_core::shell::{command_segments, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Wrapper words that pass their argv through to the real command —
/// `sudo rm .env` must classify as `rm`, not `sudo`.
const COMMAND_WRAPPERS: &[&str] = &["sudo", "command", "nohup", "time", "xargs"];

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

/// Extract write targets created by writer verbs in a segment (#76):
/// `tee` and `rm` — every non-flag token; `cp`/`mv`/`install` — the last
/// non-flag operand, or with `-t <dir>` / `--target-directory=<dir>` the dir
/// value AND every operand (each source materializes under the target dir);
/// `dd` — `of=` values; `truncate` — operands after consuming `-s <size>` /
/// `--size=<n>`. `git rm` is judged as `rm`, and common pass-through
/// wrappers (`sudo rm .env`) are unwrapped.
///
/// Quote-aware via [`tokenize`] (#86): a quoted filename is one clean token,
/// so prose inside quotes (`rm "notes about .env stuff.txt"`, commit
/// messages) never matches — this replaces the old whitespace-split `rm`
/// scanner that saw a bare `.env` token in quoted text.
fn writer_targets(segment: &str) -> Vec<String> {
    let tokens = tokenize(segment);
    let mut start = 0;
    while let Some(first) = tokens.get(start) {
        let word = first.rsplit('/').next().unwrap_or(first);
        if COMMAND_WRAPPERS.contains(&word) {
            start += 1;
            continue;
        }
        break;
    }
    let Some(first) = tokens.get(start) else {
        return Vec::new();
    };
    let mut cmd = first.rsplit('/').next().unwrap_or(first);
    let mut args: &[String] = &tokens[start + 1..];
    if cmd == "git" && args.first().map(String::as_str) == Some("rm") {
        cmd = "rm";
        args = &args[1..];
    }

    match cmd {
        "tee" | "rm" => args
            .iter()
            .filter(|t| !t.starts_with('-'))
            .cloned()
            .collect(),
        "cp" | "mv" | "install" => {
            let mut targets = Vec::new();
            let mut operands: Vec<String> = Vec::new();
            let mut has_target_dir = false;
            let mut i = 0;
            while i < args.len() {
                let t = &args[i];
                if t == "-t" || t == "--target-directory" {
                    has_target_dir = true;
                    if let Some(v) = args.get(i + 1) {
                        targets.push(v.clone());
                    }
                    i += 2;
                    continue;
                }
                if let Some(v) = t.strip_prefix("--target-directory=") {
                    has_target_dir = true;
                    targets.push(v.to_string());
                } else if !t.starts_with('-') {
                    operands.push(t.clone());
                }
                i += 1;
            }
            if has_target_dir {
                targets.append(&mut operands);
            } else if let Some(last) = operands.pop() {
                targets.push(last);
            }
            targets
        }
        "dd" => args
            .iter()
            .filter_map(|t| t.strip_prefix("of="))
            .map(String::from)
            .collect(),
        "truncate" => {
            let mut targets = Vec::new();
            let mut i = 0;
            while i < args.len() {
                let t = &args[i];
                if t == "-s" || t == "--size" {
                    i += 2;
                    continue;
                }
                if !t.starts_with('-') {
                    targets.push(t.clone());
                }
                i += 1;
            }
            targets
        }
        // `find … -delete` and `find … -exec <writer> …` destroy or overwrite
        // each matched file (#118). When such an action is present, every
        // non-flag arg (the `-name`/`-path` pattern, literal paths) is a
        // candidate target; the shared classifier filters to the dangerous
        // `.env`-family ones. A plain `find` or a read action (`-exec cat …`)
        // yields no target — that read is prevent-secret-leaks' concern.
        "find" => {
            if find_writes(args) {
                args.iter()
                    .filter(|t| !t.starts_with('-'))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// True if a `find` invocation deletes or writes its matched files: a
/// `-delete` action, or an exec-family flag whose command is a writer verb.
fn find_writes(args: &[String]) -> bool {
    const EXEC_FLAGS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];
    const WRITER_VERBS: &[&str] = &[
        "rm", "tee", "cp", "mv", "install", "dd", "truncate", "shred", "unlink", "ln",
    ];
    if args.iter().any(|a| a == "-delete") {
        return true;
    }
    args.iter().enumerate().any(|(i, a)| {
        EXEC_FLAGS.contains(&a.as_str())
            && args
                .get(i + 1)
                .map(|s| s.rsplit('/').next().unwrap_or(s))
                .is_some_and(|w| WRITER_VERBS.contains(&w))
    })
}

/// Check if a bash command targets .env files destructively.
fn bash_targets_env_file(command: &str) -> bool {
    // Quick reject: nothing to guard if no `.env` token appears anywhere.
    if !command.to_lowercase().contains(".env") {
        return false;
    }

    // Judge each command segment independently so a benign first redirect can't
    // shield a dangerous one later in the chain, and a write hidden in
    // `sh -c '…'` is still seen. Targets are judged by the shared
    // component-based classifier, so `settings.environment` stays clean (#86).
    for segment in command_segments(command) {
        if redirect_targets(&segment)
            .iter()
            .chain(writer_targets(&segment).iter())
            .any(|t| is_dangerous_env_token(t))
        {
            return true;
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
                        "🚫 BLOCKED: prevent-secret-writes: command would write or delete a .env file\n\
                         Found: a redirect or writer verb (tee, cp/mv/install, dd, truncate, rm) targeting a .env-family file\n\
                         Fix: modify .env files manually outside Claude Code.\n\
                         Allowed: safe templates (.env.example, .env.test, …) and non-.env targets.",
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
    fn write_envrc_blocked() {
        // #119: tool-side parity — Write/Edit on .envrc were wide open.
        let result = SecretWritesGuard.run(&make_write_input("/project/.envrc"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_envrc_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input("/project/.envrc", "old", "new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn write_envrc_example_allowed() {
        let result = SecretWritesGuard.run(&make_write_input("/project/.envrc.example"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
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
    fn write_env_prod_blocked() {
        // #64: .env.prod is not in BLOCKED_FILENAMES — Write let it through
        // while the Bash path blocked the same family. Now both block.
        let result = SecretWritesGuard.run(&make_write_input("/project/.env.prod"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_env_development_local_blocked() {
        let result = SecretWritesGuard.run(&make_edit_input(
            "/project/.env.development.local",
            "old",
            "new",
        ));
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

    // --- #76: writer verbs beyond redirects and rm ---

    #[test]
    fn bash_tee_env_blocked() {
        // Was a documented known gap (`bash_tee_env_not_detected`).
        let result = SecretWritesGuard.run(&make_bash_input("echo SECRET | tee .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_cp_env_blocked() {
        // Was a documented known gap (`bash_cp_env_not_detected`).
        let result = SecretWritesGuard.run(&make_bash_input("cp source.txt .env"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_tee_append_env_blocked() {
        assert!(bash_targets_env_file("echo SECRET | tee -a .env"));
    }

    #[test]
    fn bash_mv_to_env_blocked() {
        assert!(bash_targets_env_file("mv tmp.txt .env"));
    }

    #[test]
    fn bash_dd_of_env_blocked() {
        assert!(bash_targets_env_file("dd if=/dev/zero of=.env"));
    }

    #[test]
    fn bash_truncate_env_blocked() {
        assert!(bash_targets_env_file("truncate -s 0 .env"));
    }

    #[test]
    fn bash_install_to_env_blocked() {
        assert!(bash_targets_env_file("install tmp .env"));
    }

    #[test]
    fn bash_cp_target_directory_env_source_blocked() {
        // `-t <dir>` makes every operand a source; copying .env anywhere
        // materializes a new .env. Both spellings.
        assert!(bash_targets_env_file("cp -t /etc .env"));
        assert!(bash_targets_env_file("cp --target-directory=/etc .env"));
    }

    #[test]
    fn bash_chained_tee_env_blocked() {
        assert!(bash_targets_env_file(
            "echo ok > safe.txt && echo S | tee .env"
        ));
    }

    #[test]
    fn bash_sh_c_cp_env_blocked() {
        assert!(bash_targets_env_file("sh -c 'cp x .env'"));
    }

    #[test]
    fn bash_cp_env_backup_blocked() {
        // `.env.backup` is not a safe template.
        assert!(bash_targets_env_file("cp x .env.backup"));
    }

    #[test]
    fn bash_git_rm_env_blocked() {
        // `git rm .env` deletes through git — preserved from the old scanner.
        assert!(bash_targets_env_file("git rm .env"));
    }

    #[test]
    fn bash_sudo_rm_env_blocked() {
        // The old scanner caught `rm` anywhere in the segment; the wrapper
        // strip keeps `sudo rm` (and friends) covered under the new
        // command-word model.
        assert!(bash_targets_env_file("sudo rm .env"));
        assert!(bash_targets_env_file("sudo tee .env"));
    }

    // --- #86: component-matched targets, quote-aware rm ---

    #[test]
    fn bash_rm_settings_environment_allowed() {
        // Substring `.env` gate false-blocked `settings.environment`.
        assert!(!bash_targets_env_file("rm settings.environment"));
    }

    #[test]
    fn bash_redirect_settings_environment_allowed() {
        assert!(!bash_targets_env_file("echo done > settings.environment"));
    }

    #[test]
    fn bash_rm_quoted_filename_with_env_words_allowed() {
        // The quoted filename is ONE token; `.env` inside it is prose, and the
        // component classifier sees `stuff.txt`, not `.env`.
        assert!(!bash_targets_env_file(r#"rm "notes about .env stuff.txt""#));
    }

    #[test]
    fn bash_cp_example_to_env_test_allowed() {
        // Destination is a safe template.
        assert!(!bash_targets_env_file("cp .env.example .env.test"));
    }

    #[test]
    fn bash_cp_env_to_clean_dest_allowed() {
        // Destination is clean — this guard judges writes. The *read* of the
        // .env source is prevent-secret-leaks' block (cross-guard split).
        assert!(!bash_targets_env_file("cp .env /tmp/notes.txt"));
    }

    #[test]
    fn bash_rm_then_env_prose_allowed() {
        // Wave-1 regression armor: the prose mention is not an rm target.
        assert!(!bash_targets_env_file(
            r#"rm tmp.log && echo "see the .env file in docs""#
        ));
    }

    #[test]
    fn bash_commit_message_quoting_redirect_allowed() {
        // Wave-1 regression armor: quoted `> .env` is literal text.
        assert!(!bash_targets_env_file(
            r#"git commit -m "redirect output with > .env carefully""#
        ));
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
    fn bash_cp_example_to_env_blocked() {
        // Was a documented known gap: safe-template source, dangerous dest.
        assert!(bash_targets_env_file("cp .env.example .env"));
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

    // --- #116: expansion modeling ---

    #[test]
    fn bash_substitution_rm_env_blocked() {
        // The substitution body executes — the rm inside it is real.
        let result = SecretWritesGuard.run(&make_bash_input("echo $(rm .env)"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_heredoc_prose_redirect_mention_allowed() {
        // Heredoc prose mentioning a redirect to .env is text, not a write.
        let result = SecretWritesGuard.run(&make_bash_input(
            "cat > guide.md <<'EOF'\nnever run: echo x > .env\nEOF",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- #118: find -delete / -exec writer escapes ---

    #[test]
    fn bash_find_delete_env_blocked() {
        assert!(bash_targets_env_file("find . -name .env -delete"));
    }

    #[test]
    fn bash_find_exec_rm_env_blocked() {
        assert!(bash_targets_env_file("find . -name .env -exec rm {} \\;"));
    }

    #[test]
    fn bash_find_execdir_tee_env_blocked() {
        assert!(bash_targets_env_file(
            "find /app -name .env -execdir tee {} \\;"
        ));
    }

    #[test]
    fn bash_find_exec_cat_env_allowed_for_writes() {
        // A read via find-exec is prevent-secret-leaks' concern, not writes.
        assert!(!bash_targets_env_file("find . -name .env -exec cat {} \\;"));
    }

    #[test]
    fn bash_find_name_env_no_action_allowed() {
        assert!(!bash_targets_env_file("find . -name .env"));
    }

    #[test]
    fn bash_find_delete_non_env_allowed() {
        assert!(!bash_targets_env_file("find . -name '*.tmp' -delete"));
    }

    #[test]
    fn bash_find_delete_env_example_allowed() {
        // Safe template — deleting it is not a secret write.
        assert!(!bash_targets_env_file("find . -name .env.example -delete"));
    }
}
