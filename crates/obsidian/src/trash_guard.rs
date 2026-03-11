use claude_hooks_core::{Check, CheckResult, HookInput};

/// Check if an rm command targets the Obsidian vault.
fn check_rm_in_vault(command: &str, cwd: &str, vault: &str) -> CheckResult {
    if !command.contains("rm") {
        return CheckResult::allow();
    }

    let vault_prefix = if vault.ends_with('/') {
        vault.to_string()
    } else {
        format!("{vault}/")
    };

    let mut in_vault = cwd == vault || cwd.starts_with(&vault_prefix);

    if !in_vault {
        for part in command.split_whitespace() {
            if part.starts_with('/') && (part == vault || part.starts_with(&vault_prefix)) {
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
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_outside_vault_allowed() {
        let result = check_rm_in_vault("rm temp.txt", "/home/user", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_inside_vault_blocked() {
        let result = check_rm_in_vault("rm note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_explicit_vault_path_blocked() {
        let result = check_rm_in_vault("rm /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_rf_inside_vault_blocked() {
        let result = check_rm_in_vault("rm -rf old-notes/", "/vault", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_multiple_files_in_vault_blocked() {
        let result = check_rm_in_vault("rm a.md b.md c.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_as_substring_not_matched() {
        // /vault2 should not match /vault
        let result = check_rm_in_vault("rm file.md", "/vault2/notes", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_rm_with_vault_path_allowed() {
        let result = check_rm_in_vault("cat /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_contains_vault_path() {
        let result = check_rm_in_vault("rm note.md", "/vault", "/vault");
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
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
        };
        let result = ObsidianTrashGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }
}
