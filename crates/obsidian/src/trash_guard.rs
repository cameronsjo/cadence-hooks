//! Redirect destructive commands inside an Obsidian vault to `.trash/`.
//!
//! Obsidian has a built-in `.trash/` recycle bin. Deleting or truncating vault
//! files with `rm`, `unlink`, `shred`, `truncate`, or `find … -delete` bypasses
//! it and loses recoverability. This guard blocks those commands inside the
//! vault directory and suggests `mv` to `.trash/` instead.

use cadence_hooks_core::shell::tokenize;
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

/// Last path segment of a token — `/usr/bin/shred` → `shred`, `shred` → `shred`.
/// Lets a path-qualified verb (`/bin/unlink`) match the same as a bare one,
/// mirroring how the `rm` substring branch already catches `/bin/rm`. A plain
/// filename token is its own basename, so `shredder.md` ≠ `shred` still holds.
fn basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// Destructive-command gate: shapes that delete or zero a vault file,
/// bypassing Obsidian's `.trash/`. `rm` keeps its original loose substring
/// match; the added verbs match on the token's basename so a path-qualified
/// invocation (`/bin/unlink`) is caught while a path merely *containing* the
/// word (`shredder.md`, `unlinked.md`) is not.
fn is_destructive(command: &str) -> bool {
    if command.contains("rm") {
        return true;
    }
    let tokens = tokenize(command);
    if tokens
        .iter()
        .any(|t| matches!(basename(t), "unlink" | "shred" | "truncate"))
    {
        return true;
    }
    // `find … -delete` — `find` alone is read-only; only `-delete` destroys.
    // (`find … -exec rm …` is already caught by the `rm` branch above.)
    if tokens.iter().any(|t| basename(t) == "find") && tokens.iter().any(|t| t == "-delete") {
        return true;
    }
    false
}

/// Check if a destructive command targets the Obsidian vault.
fn check_destructive_in_vault(command: &str, cwd: &str, vault: &str) -> CheckResult {
    if !is_destructive(command) {
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
        // Quote-aware tokenize (not split_whitespace): a vault path with spaces
        // must be quoted (`"…/Field Reports/old.md"`), and split_whitespace both
        // shreds it across tokens and leaves a leading `"` that defeats
        // `looks_absolute`. tokenize keeps a quoted path in one token and strips
        // the quotes, so the absolute/in-vault test sees the real path (#82).
        for part in tokenize(command) {
            let part = normalize_path(&part);
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
        "🚫 Obsidian vault detected. This deletes or truncates vault files, \
         bypassing recoverability.\n\n\
         .trash/ is Obsidian's built-in recycle bin. Move files there instead:\n  \
         mkdir -p {vault}/.trash && mv <file> {vault}/.trash/\n\n\
         This preserves recoverability within Obsidian."
    ))
}

/// Blocks destructive commands (rm, unlink, shred, truncate, or find -delete)
/// inside an Obsidian vault and suggests `.trash/` instead.
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
        check_destructive_in_vault(command, cwd, &vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_rm_command_allowed() {
        let result = check_destructive_in_vault("ls -la", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_outside_vault_allowed() {
        let result = check_destructive_in_vault("rm temp.txt", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_inside_vault_blocked() {
        let result = check_destructive_in_vault("rm note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault("rm /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_double_quoted_vault_path_blocked() {
        // #82: a leading `"` must not defeat looks_absolute.
        let result =
            check_destructive_in_vault("rm \"/vault/notes/todo.md\"", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_blocked() {
        let result =
            check_destructive_in_vault("rm '/vault/notes/todo.md'", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_double_quoted_vault_path_with_spaces_blocked() {
        // #82 headline repro: a spaced vault path must be quoted; split_whitespace
        // shredded it across tokens and the guard never saw the absolute path.
        let result = check_destructive_in_vault(
            "rm \"/vault/Field Reports/old.md\"",
            "/home/user",
            "/vault",
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_with_spaces_blocked() {
        let result =
            check_destructive_in_vault("rm '/vault/Field Reports/old.md'", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_with_spaces_allowed() {
        // Regression: a genuinely out-of-vault quoted spaced path stays Allow.
        let result = check_destructive_in_vault(
            "rm \"/home/user/Field Reports/old.md\"",
            "/home/user",
            "/vault",
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_allowed() {
        let result = check_destructive_in_vault("rm '/other/note.md'", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_rf_inside_vault_blocked() {
        let result = check_destructive_in_vault("rm -rf old-notes/", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_multiple_files_in_vault_blocked() {
        let result = check_destructive_in_vault("rm a.md b.md c.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_as_substring_not_matched() {
        // /vault2 should not match /vault
        let result = check_destructive_in_vault("rm file.md", "/vault2/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_rm_with_vault_path_allowed() {
        let result = check_destructive_in_vault("cat /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_contains_vault_path() {
        let result = check_destructive_in_vault("rm note.md", "/vault", "/vault");
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
        let result = check_destructive_in_vault("rm old-note.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_deeply_nested_in_vault_blocked() {
        let result = check_destructive_in_vault("rm file.md", "/vault/a/b/c/d", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_glob_in_vault_blocked() {
        let result = check_destructive_in_vault("rm *.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_with_trailing_slash() {
        let result = check_destructive_in_vault("rm note.md", "/vault/notes", "/vault/");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_trailing_slash_normalized() {
        // Trailing slash on vault is stripped before comparison
        let result = check_destructive_in_vault("rm note.md", "/vault", "/vault/");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_vault_matches_forward_slash_cwd() {
        // OBSIDIAN_VAULT with Windows backslashes must match a forward-slash
        // cwd from the hook payload once both sides are normalized.
        let result = check_destructive_in_vault("rm note.md", "C:/vault/notes", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_command_path_matches_vault() {
        // A Windows drive-absolute command arg (`C:\vault\...`) normalizes to
        // `C:/vault/...` and is recognized as an explicit path, so an `rm`
        // targeting the vault from an outside cwd is blocked.
        let result =
            check_destructive_in_vault(r"rm C:\vault\notes\todo.md", "C:/home", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_drive_path_outside_vault_allowed() {
        // A drive-absolute path that isn't the vault must not false-match.
        let result = check_destructive_in_vault(r"rm C:\other\file.md", "C:/home", r"C:\vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mv_in_vault_allowed() {
        // mv is not rm — should be allowed
        let result = check_destructive_in_vault("mv old.md new.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_vault_path_deeply_nested() {
        let result = check_destructive_in_vault("rm /vault/a/b/c.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_vault_path_but_wrong_prefix() {
        // /vault-backup is not /vault
        let result = check_destructive_in_vault("rm /vault-backup/note.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn relative_path_in_non_vault_cwd_allowed() {
        let result = check_destructive_in_vault("rm note.md", "/home/user/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_suggests_trash() {
        let result = check_destructive_in_vault("rm note.md", "/my-vault", "/my-vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(".trash"));
        assert!(msg.contains("/my-vault/.trash/"));
    }

    // --- Non-`rm` destructive verbs (#136) ---

    #[test]
    fn unlink_inside_vault_blocked() {
        let result = check_destructive_in_vault("unlink note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_explicit_vault_path_blocked() {
        let result =
            check_destructive_in_vault("unlink /vault/notes/todo.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_outside_vault_allowed() {
        let result = check_destructive_in_vault("unlink /tmp/x.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn shred_inside_vault_blocked() {
        let result = check_destructive_in_vault("shred -u note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_outside_vault_allowed() {
        let result = check_destructive_in_vault("shred -u /tmp/x.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn truncate_inside_vault_blocked() {
        let result = check_destructive_in_vault("truncate -s 0 note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_outside_vault_allowed() {
        let result = check_destructive_in_vault("truncate -s 0 /tmp/x.md", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_delete_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("find . -name '*.md' -delete", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_delete_explicit_vault_path_blocked() {
        let result =
            check_destructive_in_vault("find /vault -name '*.md' -delete", "/home/user", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_without_delete_in_vault_allowed() {
        // Critical false-positive guard: `find` alone is read-only.
        let result = check_destructive_in_vault("find . -name '*.md'", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_exec_rm_inside_vault_blocked() {
        // `find … -exec rm …` is caught by the `rm` substring branch.
        let result = check_destructive_in_vault(
            "find . -name '*.md' -exec rm {} +",
            "/vault/notes",
            "/vault",
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Path-qualified verbs: basename match (#136 security follow-up) ---

    #[test]
    fn unlink_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault("/bin/unlink note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_path_qualified_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("/usr/bin/shred -u note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_path_qualified_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("/usr/bin/truncate -s 0 note.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_path_qualified_delete_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("/usr/bin/find . -delete", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shredder_filename_not_matched() {
        // No destructive verb — `shredder.md` is a bare filename token whose
        // basename is itself, so it must not match the `shred` verb.
        let result = check_destructive_in_vault("cat shredder.md", "/vault/notes", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
