//! Redirect destructive commands inside an Obsidian vault to `.trash/`.
//!
//! Obsidian has a built-in `.trash/` recycle bin. Deleting or truncating vault
//! files with `rm`, `unlink`, `shred`, `truncate`, or `find … -delete` bypasses
//! it and loses recoverability. This guard blocks those commands inside the
//! vault directory and suggests `mv` to `.trash/` instead.

use cadence_hooks_core::shell::{
    clobber_redirect_targets, command_segments, command_word, looks_absolute, strip_group_wrappers,
    tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput, normalize_path};

/// Destructive-command gate: shapes that delete or zero a vault file,
/// bypassing Obsidian's `.trash/`. `rm` keeps its original loose substring
/// match; the added verbs match on the token's basename so a path-qualified
/// invocation (`/bin/unlink`) is caught while a path merely *containing* the
/// word (`shredder.md`, `unlinked.md`) is not.
fn is_destructive(command: &str) -> bool {
    for segment in command_segments(command) {
        let tokens = tokenize(strip_group_wrappers(&segment));
        if tokens.iter().any(|token| {
            matches!(
                command_word(token).as_ref(),
                "rm" | "unlink" | "shred" | "truncate"
            )
        }) {
            return true;
        }
        // `find … -delete` — `find` alone is read-only; only `-delete`
        // destroys. (`find … -exec rm …` is caught by the writer scan above.)
        if tokens
            .iter()
            .any(|token| command_word(token).as_ref() == "find")
            && tokens.iter().any(|token| token == "-delete")
        {
            return true;
        }
    }
    false
}

/// Filesystem existence probe for the redirect-truncation check. Injected so
/// the guard stays a pure function over fake paths in tests (#192): a `>`
/// redirect truncates only a file that ALREADY exists — distinguishing
/// truncate from benign new-file creation needs one stat at check time.
pub trait FileMeta {
    /// True iff `path` names an existing file (symlinks resolved by the real
    /// impl; the fake decides its own semantics).
    fn exists(&self, path: &str) -> bool;
}

/// Production impl over `std::fs`. Uses `symlink_metadata(...).is_ok()` — a
/// broken symlink still "exists" as a dir entry a `>` would clobber.
pub struct RealFs;
impl FileMeta for RealFs {
    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }
}

/// Split an absolute path into its root prefix (`"/"` or a Windows drive
/// prefix like `"C:/"`) and the segment body after it. Empty prefix means the
/// path wasn't recognized as absolute (shouldn't happen for callers here,
/// since `resolve_in_vault` always joins onto an absolute `cwd`/`vault`).
fn split_absolute_prefix(path: &str) -> (&str, &str) {
    if let Some(rest) = path.strip_prefix('/') {
        return ("/", rest);
    }
    let b = path.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/' {
        return (&path[..3], &path[3..]);
    }
    ("", path)
}

/// Lexically collapse `.`/`..` segments in an absolute path — a string
/// operation, not a filesystem canonicalization, since a redirect target may
/// not exist yet. `..` pops the last real segment; a `..` with nothing to pop
/// (already at root) is dropped rather than climbing above root. This runs
/// BEFORE the vault-prefix membership test so a climb like
/// `cwd=/home/user, target=../../vault/note.md` resolves to `/vault/note.md`
/// instead of string-testing a literal `/home/user/../../vault/note.md`,
/// which would never match the `/vault/` prefix even though the shell lands
/// inside the vault (#192 F4/F7).
fn collapse_dots(path: &str) -> String {
    let (prefix, body) = split_absolute_prefix(path);
    let mut segments: Vec<&str> = Vec::new();
    for seg in body.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("{prefix}{}", segments.join("/"))
}

/// Resolve a redirect target against `cwd`, returning its normalized,
/// dot-collapsed absolute path when that path falls inside `vault` (both
/// already normalized by the caller). A relative target resolves under
/// `cwd`, matching shell redirect semantics; an absolute target is checked
/// directly. `..`/`.` segments are lexically collapsed before the
/// vault-prefix test (#192 F4) — otherwise a climb-back-in (`../../vault/x`)
/// or climb-out (`../../../etc/passwd`) mis-resolves against the raw string.
/// Returns `None` when the collapsed path is outside the vault.
fn resolve_in_vault(target: &str, cwd: &str, vault: &str, vault_prefix: &str) -> Option<String> {
    let target = normalize_path(target);
    let resolved = if looks_absolute(&target) {
        target
    } else {
        normalize_path(&format!("{cwd}/{target}"))
    };
    let resolved = collapse_dots(&resolved);
    if resolved == vault || resolved.starts_with(vault_prefix) {
        Some(resolved)
    } else {
        None
    }
}

/// Check if a destructive command targets the Obsidian vault, or if a
/// clobber (`>`, `>|`) redirect would truncate an existing vault file.
fn check_destructive_in_vault(
    command: &str,
    cwd: &str,
    vault: &str,
    meta: &dyn FileMeta,
) -> CheckResult {
    // Normalize both sides before the prefix test: the vault root comes from
    // `OBSIDIAN_VAULT` (which on Windows may carry backslashes) while `cwd` and
    // the command's path args come from the hook payload. Without normalizing
    // both, a `C:\vault` env value never matches a `C:/vault` hook path.
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");

    if is_destructive(command) {
        let mut in_vault = cwd == vault || cwd.starts_with(&vault_prefix);

        if !in_vault {
            // Quote-aware tokenize (not split_whitespace): a vault path with
            // spaces must be quoted (`"…/Field Reports/old.md"`), and
            // split_whitespace both shreds it across tokens and leaves a
            // leading `"` that defeats `looks_absolute`. tokenize keeps a
            // quoted path in one token and strips the quotes, so the
            // absolute/in-vault test sees the real path (#82).
            for part in tokenize(command) {
                let part = normalize_path(&part);
                if looks_absolute(&part) && (part == vault || part.starts_with(&vault_prefix)) {
                    in_vault = true;
                    break;
                }
            }
        }

        if in_vault {
            return CheckResult::block(format!(
                "🚫 Obsidian vault detected. This deletes or truncates vault files, \
                 bypassing recoverability.\n\n\
                 .trash/ is Obsidian's built-in recycle bin. Move files there instead:\n  \
                 mkdir -p {vault}/.trash && mv <file> {vault}/.trash/\n\n\
                 This preserves recoverability within Obsidian."
            ));
        }
    }

    // A `>`/`>|` redirect truncates its target the moment the shell opens it
    // for writing — even when the command that follows never runs. `>>`
    // (append) and a target that doesn't exist yet (new-file creation) are
    // not destructive, so only an existing vault file behind a clobber
    // redirect is blocked (#192). `command_segments` (not `split_segments`)
    // so a redirect hidden inside a `sh -c`/`bash -c` wrapper or a `$(…)`/
    // backtick substitution is also seen — the sibling secret-writes guard
    // uses the same wrapper-unwrapping splitter for the same reason.
    for segment in command_segments(command) {
        for target in clobber_redirect_targets(&segment) {
            if let Some(resolved) = resolve_in_vault(&target, &cwd, &vault, &vault_prefix)
                && meta.exists(&resolved)
            {
                return CheckResult::block(format!(
                    "🚫 Obsidian vault detected. This `>` redirect truncates an existing vault \
                     file, bypassing recoverability.\n\n\
                     .trash/ is Obsidian's built-in recycle bin. Move the file there before \
                     overwriting it:\n  \
                     mkdir -p {vault}/.trash && mv {resolved} {vault}/.trash/\n\n\
                     Use `>>` to append, or target a new filename, to keep existing content."
                ));
            }
        }
    }

    CheckResult::allow()
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
        check_destructive_in_vault(command, cwd, &vault, &RealFs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Fake existence probe for redirect-truncation tests: reports a path as
    /// existing iff it was explicitly seeded, so tests never touch real disk.
    #[derive(Default)]
    struct FakeFs(HashSet<String>);

    impl FakeFs {
        fn with(paths: &[&str]) -> Self {
            FakeFs(paths.iter().map(|s| s.to_string()).collect())
        }
    }

    impl FileMeta for FakeFs {
        fn exists(&self, path: &str) -> bool {
            self.0.contains(path)
        }
    }

    #[test]
    fn non_rm_command_allowed() {
        let result = check_destructive_in_vault("ls -la", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_outside_vault_allowed() {
        let result =
            check_destructive_in_vault("rm temp.txt", "/home/user", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn case_folded_rm_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("RM note.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "rm /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_double_quoted_vault_path_blocked() {
        // #82: a leading `"` must not defeat looks_absolute.
        let result = check_destructive_in_vault(
            "rm \"/vault/notes/todo.md\"",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "rm '/vault/notes/todo.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
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
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_single_quoted_vault_path_with_spaces_blocked() {
        let result = check_destructive_in_vault(
            "rm '/vault/Field Reports/old.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_with_spaces_allowed() {
        // Regression: a genuinely out-of-vault quoted spaced path stays Allow.
        let result = check_destructive_in_vault(
            "rm \"/home/user/Field Reports/old.md\"",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_quoted_out_of_vault_path_allowed() {
        let result = check_destructive_in_vault(
            "rm '/other/note.md'",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn rm_rf_inside_vault_blocked() {
        let result =
            check_destructive_in_vault("rm -rf old-notes/", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_multiple_files_in_vault_blocked() {
        let result = check_destructive_in_vault(
            "rm a.md b.md c.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_as_substring_not_matched() {
        // /vault2 should not match /vault
        let result =
            check_destructive_in_vault("rm file.md", "/vault2/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn non_rm_with_vault_path_allowed() {
        let result = check_destructive_in_vault(
            "cat /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_contains_vault_path() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault", "/vault", &FakeFs::default());
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
        let result =
            check_destructive_in_vault("rm old-note.md", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_deeply_nested_in_vault_blocked() {
        let result = check_destructive_in_vault(
            "rm file.md",
            "/vault/a/b/c/d",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_glob_in_vault_blocked() {
        let result =
            check_destructive_in_vault("rm *.md", "/vault/notes", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_with_trailing_slash() {
        let result =
            check_destructive_in_vault("rm note.md", "/vault/notes", "/vault/", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn vault_trailing_slash_normalized() {
        // Trailing slash on vault is stripped before comparison
        let result =
            check_destructive_in_vault("rm note.md", "/vault", "/vault/", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_vault_matches_forward_slash_cwd() {
        // OBSIDIAN_VAULT with Windows backslashes must match a forward-slash
        // cwd from the hook payload once both sides are normalized.
        let result = check_destructive_in_vault(
            "rm note.md",
            "C:/vault/notes",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_backslash_command_path_matches_vault() {
        // A Windows drive-absolute command arg (`C:\vault\...`) normalizes to
        // `C:/vault/...` and is recognized as an explicit path, so an `rm`
        // targeting the vault from an outside cwd is blocked.
        let result = check_destructive_in_vault(
            r"rm C:\vault\notes\todo.md",
            "C:/home",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn windows_drive_path_outside_vault_allowed() {
        // A drive-absolute path that isn't the vault must not false-match.
        let result = check_destructive_in_vault(
            r"rm C:\other\file.md",
            "C:/home",
            r"C:\vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mv_in_vault_allowed() {
        // mv is not rm — should be allowed
        let result =
            check_destructive_in_vault("mv old.md new.md", "/vault", "/vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn explicit_vault_path_deeply_nested() {
        let result = check_destructive_in_vault(
            "rm /vault/a/b/c.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rm_with_vault_path_but_wrong_prefix() {
        // /vault-backup is not /vault
        let result = check_destructive_in_vault(
            "rm /vault-backup/note.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn relative_path_in_non_vault_cwd_allowed() {
        let result = check_destructive_in_vault(
            "rm note.md",
            "/home/user/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_suggests_trash() {
        let result =
            check_destructive_in_vault("rm note.md", "/my-vault", "/my-vault", &FakeFs::default());
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(".trash"));
        assert!(msg.contains("/my-vault/.trash/"));
    }

    // --- Non-`rm` destructive verbs (#136) ---

    #[test]
    fn unlink_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "unlink note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "unlink /vault/notes/todo.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unlink_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "unlink /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn shred_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "shred -u note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "shred -u /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn truncate_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "truncate -s 0 note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_outside_vault_allowed() {
        let result = check_destructive_in_vault(
            "truncate -s 0 /tmp/x.md",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_delete_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "find . -name '*.md' -delete",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_delete_explicit_vault_path_blocked() {
        let result = check_destructive_in_vault(
            "find /vault -name '*.md' -delete",
            "/home/user",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_without_delete_in_vault_allowed() {
        // Critical false-positive guard: `find` alone is read-only.
        let result = check_destructive_in_vault(
            "find . -name '*.md'",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn find_exec_rm_inside_vault_blocked() {
        // `find … -exec rm …` is caught by the `rm` substring branch.
        let result = check_destructive_in_vault(
            "find . -name '*.md' -exec rm {} +",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Path-qualified verbs: basename match (#136 security follow-up) ---

    #[test]
    fn unlink_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/bin/unlink note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shred_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/shred -u note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn truncate_path_qualified_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/truncate -s 0 note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn find_path_qualified_delete_inside_vault_blocked() {
        let result = check_destructive_in_vault(
            "/usr/bin/find . -delete",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn shredder_filename_not_matched() {
        // No destructive verb — `shredder.md` is a bare filename token whose
        // basename is itself, so it must not match the `shred` verb.
        let result = check_destructive_in_vault(
            "cat shredder.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Clobber-redirect truncation of existing vault files (#192) ---

    #[test]
    fn truncate_redirect_existing_vault_file_blocked() {
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault("echo hi > note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn create_redirect_new_vault_file_allowed() {
        // Same command, but the target doesn't exist yet — new-file creation
        // is not a truncation.
        let result = check_destructive_in_vault(
            "echo hi > note.md",
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn append_redirect_vault_file_allowed() {
        // `>>` never clobbers, regardless of existence.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result =
            check_destructive_in_vault("echo hi >> note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn colon_truncate_existing_vault_file_blocked() {
        // `:` is a no-op builtin, not a destructive verb — the redirect
        // branch is what catches this, independent of `is_destructive`.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault(": > note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn redirect_out_of_vault_allowed() {
        let fs = FakeFs::with(&["/tmp/x.md"]);
        let result =
            check_destructive_in_vault("echo hi > /tmp/x.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn quoted_redirect_in_prose_allowed() {
        // The `>` inside the quoted commit message is literal text, not a
        // redirect operator — no target is extracted at all.
        let result = check_destructive_in_vault(
            r#"git commit -m "use > carefully""#,
            "/vault/notes",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn redirect_explicit_vault_path_from_outside_blocked() {
        let fs = FakeFs::with(&["/vault/note.md"]);
        let result = check_destructive_in_vault("echo hi > /vault/note.md", "/home", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Redirect-guard bypass hardening (security review #192 follow-up) ---

    #[test]
    fn sh_c_wrapped_redirect_into_existing_vault_file_blocked() {
        // F1: the redirect loop must see inside a `sh -c`/`bash -c` wrapper,
        // not just the literal top-level segment.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result =
            check_destructive_in_vault("sh -c 'echo x > note.md'", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn backslash_escaped_space_target_blocked() {
        // F2: Obsidian filenames routinely contain spaces; a backslash-escaped
        // space must not truncate the target early.
        let fs = FakeFs::with(&["/vault/notes/Daily Note.md"]);
        let result =
            check_destructive_in_vault(r"echo x > Daily\ Note.md", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn glued_paren_subshell_truncate_blocked() {
        // F3: a glued closing paren from subshell grouping must not survive
        // into the resolved target and dodge the existence check.
        let fs = FakeFs::with(&["/vault/notes/note.md"]);
        let result = check_destructive_in_vault("(: > note.md)", "/vault/notes", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn dotdot_climb_into_vault_from_outside_blocked() {
        // F4: a `..` climb that lands back inside the vault must be caught
        // even though the raw joined string never has the `/vault/` prefix.
        let fs = FakeFs::with(&["/vault/note.md"]);
        let result =
            check_destructive_in_vault("echo x > ../../vault/note.md", "/home/user", "/vault", &fs);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn dotdot_out_of_vault_allowed() {
        // F7 companion: a `..` climb that lands OUTSIDE the vault (even
        // though the raw string mis-resolves as in-vault before collapsing)
        // must stay Allow.
        let result = check_destructive_in_vault(
            "echo x > ../../../etc/passwd",
            "/vault",
            "/vault",
            &FakeFs::default(),
        );
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
