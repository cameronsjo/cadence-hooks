//! Redirect `rm` commands inside an Obsidian vault to `.trash/`.
//!
//! Obsidian has a built-in `.trash/` recycle bin. Deleting vault files with
//! `rm` bypasses it and loses recoverability. This guard blocks `rm` inside
//! the vault directory and suggests `mv` to `.trash/` instead.

use cadence_hooks_core::{Check, CheckResult, HookInput, normalize_path};

/// True when a normalized path is absolute — POSIX (`/foo`) or a Windows
/// drive-absolute path (`C:/foo`, after `normalize_path` turns `\` into `/`).
/// Used to distinguish an explicit path argument from a flag (`-rf`) or a
/// bare relative name.
fn looks_absolute(p: &str) -> bool {
    if p.starts_with('/') {
        return true;
    }
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/'
}

/// Check if an rm command targets the Obsidian vault.
fn check_rm_in_vault(command: &str, cwd: &str, vault: &str) -> CheckResult {
    if !command.contains("rm") {
        return CheckResult::allow();
    }

    // Normalize both sides before the prefix test: the vault root comes from
    // `OBSIDIAN_VAULT` (which on Windows may carry backslashes) while `cwd` and
    // the command's path args come from the hook payload. Without normalizing
    // both, a `C:\vault` env value never matches a `C:/vault` hook path.
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");

    let mut in_vault = cwd == vault || cwd.starts_with(&vault_prefix);

    if !in_vault {
        for part in command.split_whitespace() {
            let part = normalize_path(part);
            if looks_absolute(&part) && (part == vault || part.starts_with(&vault_prefix)) {
                in_vault = true;
                break;
            }
        }
    }

    if !in_vault {
        return CheckResult::allow();
    }

    CheckResult::block(format!(
        "🚫 Obsidian vault detected. Do not use rm to delete vault files.\n\n\
         .trash/ is Obsidian's built-in recycle bin. Move files there instead:\n  \
         mkdir -p {vault}/.trash && mv <file> {vault}/.trash/\n\n\
         This preserves recoverability within Obsidian."
    ))
}

/// Blocks `rm` inside an Obsidian vault and suggests `.trash/` instead.
pub struct ObsidianTrashGuard;

impl Check for ObsidianTrashGuard {
    fn name(&self) -> &str {
        "obsidian-trash-guard"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        let vault = match std::env::var("OBSIDIAN_VAULT") {
            Ok(v) if !v.is_empty() => v,
            _ => return CheckResult::allow(),
        };

        let cwd = input.cwd.as_deref().unwrap_or("/");
        check_rm_in_vault(command, cwd, &vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_rm_command_allowed() {
        let result = check_rm_in_vault("ls -la", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_outside_vault_allowed() {
        let result = check_rm_in_vault("rm temp.txt", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_inside_vault_blocked() {
        let result = check_rm_in_vault("rm note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_explicit_vault_path_blocked() {
        let result = check_rm_in_vault("rm /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_rf_inside_vault_blocked() {
        let result = check_rm_in_vault("rm -rf old-notes/", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_multiple_files_in_vault_blocked() {
        let result = check_rm_in_vault("rm a.md b.md c.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_as_substring_not_matched() {
        // /vault2 should not match /vault
        let result = check_rm_in_vault("rm file.md", "/vault2/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_rm_with_vault_path_allowed() {
        let result = check_rm_in_vault("cat /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_contains_vault_path() {
        let result = check_rm_in_vault("rm note.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("/vault/.trash/"));
    }

    // ObsidianTrashGuard::run() tests (needs OBSIDIAN_VAULT env var)
    #[test]
    fn run_no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = ObsidianTrashGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn rm_at_vault_root_blocked() {
        let result = check_rm_in_vault("rm old-note.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_deeply_nested_in_vault_blocked() {
        let result = check_rm_in_vault("rm file.md", "/vault/a/b/c/d", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_glob_in_vault_blocked() {
        let result = check_rm_in_vault("rm *.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_with_trailing_slash() {
        let result = check_rm_in_vault("rm note.md", "/vault/notes", "/vault/");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_trailing_slash_normalized() {
        // Trailing slash on vault is stripped before comparison
        let result = check_rm_in_vault("rm note.md", "/vault", "/vault/");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_vault_matches_forward_slash_cwd() {
        // OBSIDIAN_VAULT with Windows backslashes must match a forward-slash
        // cwd from the hook payload once both sides are normalized.
        let result = check_rm_in_vault("rm note.md", "C:/vault/notes", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_command_path_matches_vault() {
        // A Windows drive-absolute command arg (`C:\vault\...`) normalizes to
        // `C:/vault/...` and is recognized as an explicit path, so an `rm`
        // targeting the vault from an outside cwd is blocked.
        let result = check_rm_in_vault(r"rm C:\vault\notes\todo.md", "C:/home", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_drive_path_outside_vault_allowed() {
        // A drive-absolute path that isn't the vault must not false-match.
        let result = check_rm_in_vault(r"rm C:\other\file.md", "C:/home", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mv_in_vault_allowed() {
        // mv is not rm — should be allowed
        let result = check_rm_in_vault("mv old.md new.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_vault_path_deeply_nested() {
        let result = check_rm_in_vault("rm /vault/a/b/c.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_vault_path_but_wrong_prefix() {
        // /vault-backup is not /vault
        let result = check_rm_in_vault("rm /vault-backup/note.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn relative_path_in_non_vault_cwd_allowed() {
        let result = check_rm_in_vault("rm note.md", "/home/user/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_suggests_trash() {
        let result = check_rm_in_vault("rm note.md", "/my-vault", "/my-vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(".trash"));
        assert!(msg.contains("/my-vault/.trash/"));
    }
}
