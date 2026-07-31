//! Redirect destructive commands and file-tool deletions inside an Obsidian
//! vault to `.trash/`.
//!
//! Obsidian has a built-in `.trash/` recycle bin. Deleting or truncating vault
//! files with `rm`, `unlink`, `shred`, `truncate`, or `find … -delete` bypasses
//! it and loses recoverability. This guard blocks those commands inside the
//! vault directory and suggests `mv` to `.trash/` instead.

use cadence_hooks_core::shell::{
    child_scripts, clobber_redirect_targets, command_segments, command_word, looks_absolute,
    skip_runner_flags, skip_transparent_prefixes, strip_group_wrappers, strip_leading_keywords,
    tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput, normalize_path};

/// Verbs that delete or zero the file they are handed.
const DESTRUCTIVE_VERBS: &[&str] = &["rm", "unlink", "shred", "truncate"];

/// `find` actions that name a second executable position.
const EXEC_ACTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// How far the scan follows a command that runs another command it carries as
/// an operand (`eval …`, `find … -exec sh -c '…'`). Bounded for the same
/// reason `command_segments` bounds wrapper nesting: a self-referential
/// spelling must not recurse without end.
const MAX_NESTED_DEPTH: usize = 3;

/// Destructive-command gate: shapes that delete or zero a vault file,
/// bypassing Obsidian's `.trash/`. Verbs are matched only where the shell runs
/// an executable: the segment head (after shell keywords, transparent
/// wrappers, and a command runner's own flags), a `find` exec-family action, or
/// an operand a command re-executes (`eval`, `find … -exec sh -c`). A
/// path-qualified invocation (`/bin/unlink`) is caught, while prose or a
/// filename argument such as `echo RM` or `shredder.md` is not.
fn is_destructive(command: &str) -> bool {
    is_destructive_at(command, 0)
}

/// Worker for [`is_destructive`]; `depth` bounds the re-executed-operand walk.
fn is_destructive_at(command: &str, depth: usize) -> bool {
    for segment in command_segments(command) {
        let tokens = tokenize(strip_group_wrappers(&segment));
        // Keywords first: `for f in *.md; do rm $f; done` segments as
        // `do rm $f`, so without this the head word is `do` and the `rm`
        // behind it is never examined.
        let mut argv = skip_transparent_prefixes(strip_leading_keywords(&tokens));
        // `sudo` and `xargs` run the command that follows their OWN options.
        // Skipping those options (rather than bailing on the first `-`) is what
        // keeps `sudo -u me rm note.md` and the canonical
        // `find … -print0 | xargs -0 rm` idiom in view.
        while let Some(first) = argv.first() {
            let runner = command_word(first).into_owned();
            if !matches!(runner.as_str(), "sudo" | "xargs") {
                break;
            }
            let Some(rest) = skip_runner_flags(&runner, &argv[1..]) else {
                break;
            };
            // Each pass consumes at least the runner itself, so this ends.
            argv = skip_transparent_prefixes(rest);
        }
        let Some(first) = argv.first() else {
            continue;
        };
        let verb = command_word(first);
        if DESTRUCTIVE_VERBS.contains(&verb.as_ref()) {
            return true;
        }
        // `git rm` is judged as `rm` — it deletes the working-tree file the
        // same way. Same alias, same case-SENSITIVE subcommand spelling, as
        // `prevent_secret_writes::writer_targets`.
        if verb == "git" && argv.get(1).map(String::as_str) == Some("rm") {
            return true;
        }
        // `eval` re-executes its operand, so scan that operand as a command in
        // its own right — the head word of the segment is `eval`, and the verb
        // it runs is invisible to a head test.
        if verb == "eval"
            && depth < MAX_NESTED_DEPTH
            && argv.len() > 1
            && is_destructive_at(&argv[1..].join(" "), depth + 1)
        {
            return true;
        }
        // `find … -delete` — `find` alone is read-only; only `-delete`
        // destroys. Exec-family actions name another executable position, so
        // inspect the word immediately after the action rather than every
        // operand in the segment.
        if verb == "find" {
            if argv.iter().any(|token| token == "-delete") {
                return true;
            }
            if argv.windows(2).any(|pair| {
                EXEC_ACTIONS.contains(&pair[0].as_str())
                    && DESTRUCTIVE_VERBS.contains(&command_word(&pair[1]).as_ref())
            }) {
                return true;
            }
            // An exec action can name a shell instead of the verb itself
            // (`-exec sh -c 'rm …'`). `command_segments` only unwraps a
            // wrapper at the segment head, so the nested script is expanded
            // here, from the action's own argument list.
            if depth < MAX_NESTED_DEPTH {
                for (i, token) in argv.iter().enumerate() {
                    if !EXEC_ACTIONS.contains(&token.as_str()) {
                        continue;
                    }
                    if child_scripts(&argv[i + 1..], "")
                        .iter()
                        .any(|script| is_destructive_at(script, depth + 1))
                    {
                        return true;
                    }
                }
            }
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

/// Judge a harness deletion primitive that named a path directly — a normalized
/// Codex `apply_patch` `*** Delete File:`, which carries `operation: "delete"`
/// and no command for the command scanner to read.
///
/// **`rename-source` is deliberately not routed here.** `normalized_inputs` tags
/// the source half of `*** Update File: X` + `*** Move to: Y` (and an
/// `mcp__*move*`/`*rename*` call) as `"rename-source"`, and a move empties `X`
/// much as a delete does — but the block below *prescribes a move* ("Move it
/// into <vault>/.trash/"), and under Codex that remedy is spelled as exactly
/// such a rename, whose source is the in-vault path that just blocked. Judging
/// renames as deletions would leave a Codex session unable to comply with the
/// message it was just shown. `mv` is likewise outside the command scanner's
/// verb set on the Bash route, so the two harnesses agree. Same call, same
/// reasoning, and the fuller derivation as `guard_rm::judge_delete_path`; pinned
/// by `normalized_patch_rename_inside_vault_is_not_a_delete`.
fn check_delete_in_vault(path: &str, cwd: &str, vault: &str) -> CheckResult {
    let vault = normalize_path(vault);
    let cwd = normalize_path(cwd);
    let vault_prefix = format!("{vault}/");
    if let Some(resolved) = resolve_in_vault(path, &cwd, &vault, &vault_prefix) {
        return CheckResult::block(format!(
            "🚫 Obsidian vault detected. This file operation deletes a vault file, \
             bypassing recoverability.\n\n\
             Move it into {vault}/.trash/ instead of deleting {resolved}."
        ));
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
        let vault = match std::env::var("OBSIDIAN_VAULT") {
            Ok(v) if !v.is_empty() => v,
            _ => return CheckResult::allow(),
        };

        let cwd = input.cwd.as_deref().unwrap_or("/");
        if input.operation() == Some("delete")
            && let Some(path) = input.file_path()
        {
            let result = check_delete_in_vault(&path, cwd, &vault);
            if result.outcome == cadence_hooks_core::Outcome::Block {
                return result;
            }
        }

        input.command().map_or_else(CheckResult::allow, |command| {
            check_destructive_in_vault(command, cwd, &vault, &RealFs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_vault_env(f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let previous = std::env::var_os("OBSIDIAN_VAULT");
        // SAFETY: every OBSIDIAN_VAULT mutation in this crate is serialized by
        // ENV_LOCK and restored before the lock is released.
        unsafe { std::env::set_var("OBSIDIAN_VAULT", "/vault") };
        f();
        match previous {
            Some(value) => unsafe { std::env::set_var("OBSIDIAN_VAULT", value) },
            None => unsafe { std::env::remove_var("OBSIDIAN_VAULT") },
        }
    }

    fn make_bash_with_cwd(command: &str, cwd: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                command: Some(command.into()),
                ..Default::default()
            }),
            cwd: Some(cwd.into()),
            ..Default::default()
        }
    }

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
    fn case_folded_rm_runs_through_the_guard_entry_point() {
        with_vault_env(|| {
            let result = ObsidianTrashGuard.run(&make_bash_with_cwd("RM note.md", "/vault/notes"));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        });
    }

    /// Drive a command through the guard's real entry point and report the
    /// outcome, so the differential table below tests what a hook payload
    /// actually reaches rather than a helper's internals.
    fn outcome_in_vault(command: &str) -> cadence_hooks_core::Outcome {
        let mut outcome = cadence_hooks_core::Outcome::Allow;
        with_vault_env(|| {
            outcome = ObsidianTrashGuard
                .run(&make_bash_with_cwd(command, "/vault/notes"))
                .outcome;
        });
        outcome
    }

    // --- Non-head deletion shapes (#528 security review C1) ---
    //
    // Every command here was measured deleting a real file through `bash`, and
    // every one was BLOCK before this guard moved to a segment-head scan. They
    // are driven through `Check::run` because the regression lived in the
    // path from payload to verdict, not in any single helper.

    #[test]
    fn git_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("git rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn sudo_with_user_flag_rm_inside_vault_blocked() {
        // A flag on the peel prefix must not abort the peel.
        assert_eq!(
            outcome_in_vault("sudo -u me rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn sudo_with_long_flag_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("sudo --preserve-env rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn xargs_null_delimited_rm_inside_vault_blocked() {
        // The canonical safe-for-spaces delete idiom.
        assert_eq!(
            outcome_in_vault("find . -name '*.md' -print0 | xargs -0 rm"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn xargs_with_glued_value_flag_rm_inside_vault_blocked() {
        // `-n1` glues its value to the flag; `-n 1` spells it as the next word.
        assert_eq!(
            outcome_in_vault("xargs -n1 rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
        assert_eq!(
            outcome_in_vault("xargs -n 1 rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn for_loop_body_rm_inside_vault_blocked() {
        // `do` occupies the segment head; the `rm` is behind it.
        assert_eq!(
            outcome_in_vault("for f in *.md; do rm $f; done"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn while_loop_body_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("while read f; do rm $f; done < list"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn if_branch_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault("if true; then rm note.md; fi"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn eval_operand_rm_inside_vault_blocked() {
        // `eval` re-executes its operand, quoted or not.
        assert_eq!(
            outcome_in_vault("eval rm note.md"),
            cadence_hooks_core::Outcome::Block
        );
        assert_eq!(
            outcome_in_vault("eval \"rm note.md\""),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn find_exec_nested_shell_rm_inside_vault_blocked() {
        assert_eq!(
            outcome_in_vault(r"find . -name x -exec sh -c 'rm note.md' \;"),
            cadence_hooks_core::Outcome::Block
        );
    }

    // --- Controls: false positives the head scan correctly removed ---
    //
    // These BLOCKED under the old whole-command `contains("rm")` scan and must
    // stay ALLOW. They pin the fix in the other direction: restoring the shapes
    // above must not restore the substring detector with them.

    #[test]
    fn npm_run_format_in_vault_stays_allowed() {
        assert_eq!(
            outcome_in_vault("npm run format"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn terraform_destroy_in_vault_stays_allowed() {
        assert_eq!(
            outcome_in_vault("terraform destroy"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn keyword_and_runner_peels_do_not_invent_verbs() {
        // Controls for the three new peels: a keyword with a harmless body, a
        // runner whose command is not destructive, and a `git` subcommand that
        // is not `rm` (case-sensitively — `git RM` is not a subcommand).
        for command in [
            "for f in *.md; do cat $f; done",
            "sudo -u me ls",
            "xargs -0 grep note",
            "git status",
            "git RM note.md",
            "eval ls",
            "find . -name x -exec sh -c 'cat note.md' \\;",
        ] {
            assert_eq!(
                outcome_in_vault(command),
                cadence_hooks_core::Outcome::Allow,
                "{command} must stay allowed"
            );
        }
    }

    #[test]
    fn destructive_word_as_an_argument_is_allowed() {
        with_vault_env(|| {
            let result =
                ObsidianTrashGuard.run(&make_bash_with_cwd("echo RM note.md", "/vault/notes"));
            assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
        });
    }

    #[test]
    fn normalized_patch_delete_inside_vault_is_blocked() {
        let result = check_delete_in_vault("note.md", "/vault", "/vault");
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    /// A patch RENAME is a move, and this guard's own remedy is a move — see
    /// `check_delete_in_vault`'s doc comment. Pinned so the exclusion is an
    /// asserted boundary rather than an undocumented gap.
    #[test]
    fn normalized_patch_rename_inside_vault_is_not_a_delete() {
        let patch = "*** Begin Patch\n*** Update File: /vault/note.md\n\
                     *** Move to: /vault/.trash/note.md\n@@\n-old\n+new\n*** End Patch";
        let payload = serde_json::json!({
            "tool_name": "apply_patch",
            "cwd": "/vault",
            "tool_input": patch,
        })
        .to_string();
        let input = HookInput::from_json(&payload).expect("parse patch payload");
        let targets = input.normalized_inputs().expect("normalize patch");

        // The fact the exclusion rests on: the source half is `rename-source`,
        // so the `operation() == Some("delete")` route is never entered.
        assert_eq!(targets[0].operation(), Some("rename-source"));
        assert_ne!(
            targets[0].operation(),
            Some("delete"),
            "a move must not be tagged as a deletion"
        );

        // Control: the delete spelling of the same vault path still blocks, so
        // this pins a scope boundary rather than a hole in the delete route.
        assert_eq!(
            check_delete_in_vault("/vault/note.md", "/vault", "/vault").outcome,
            cadence_hooks_core::Outcome::Block
        );
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
        // `find … -exec rm …` names a second executable position.
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
