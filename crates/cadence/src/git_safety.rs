//! Block or warn on dangerous git operations.
//!
//! Force-push to main/master, `reset --hard`, `clean -f`, and similar
//! destructive commands are blocked. Less dangerous operations like
//! `rebase`, `reset`, and `branch -d` trigger warnings.
//!
//! Commands are normalized before matching: extra whitespace is collapsed
//! and git global flags (`-C`, `--no-pager`, `--git-dir`, `--work-tree`,
//! `--no-optional-locks`) are stripped so that flag injection and
//! whitespace padding cannot bypass detection.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Protected branch names that trigger blocks instead of warnings.
const PROTECTED_BRANCHES: &[&str] = &["main", "master"];

/// Git global options that appear between `git` and the subcommand.
/// These take a following argument that must also be stripped.
const GIT_GLOBAL_FLAGS_WITH_ARG: &[&str] = &["-C", "--git-dir", "--work-tree"];

/// Git global options that are standalone (no following argument).
const GIT_GLOBAL_FLAGS_STANDALONE: &[&str] = &["--no-pager", "--no-optional-locks", "--bare"];

/// Normalize a git command string for reliable matching.
///
/// 1. Collapse all runs of whitespace to single spaces and trim.
/// 2. Strip git global options that appear between `git` and the subcommand
///    (`-C <path>`, `--git-dir=<path>`, `--work-tree=<path>`, `--no-pager`,
///    `--no-optional-locks`, `--bare`).
///
/// Returns the normalized string lowercased.
fn normalize_git_command(command: &str) -> String {
    let lower = command.to_lowercase();
    // Collapse whitespace
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let mut result: Vec<&str> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    let mut seen_git = false;
    let mut seen_subcommand = false;

    while i < tokens.len() {
        let token = tokens[i];

        // Pass through everything before `git`
        if !seen_git {
            result.push(token);
            if token == "git" {
                seen_git = true;
            }
            i += 1;
            continue;
        }

        // After `git` but before the subcommand, strip global flags
        if !seen_subcommand {
            // Check for `--flag=value` forms
            let is_eq_flag = GIT_GLOBAL_FLAGS_WITH_ARG
                .iter()
                .any(|f| token.starts_with(&format!("{}=", f.to_lowercase())));
            if is_eq_flag {
                i += 1;
                continue;
            }

            // Check for `--flag value` forms (flag with separate arg)
            let is_sep_flag = GIT_GLOBAL_FLAGS_WITH_ARG
                .iter()
                .any(|f| token == f.to_lowercase());
            if is_sep_flag {
                i += 2; // skip flag and its argument
                continue;
            }

            // Check for standalone flags
            let is_standalone = GIT_GLOBAL_FLAGS_STANDALONE
                .iter()
                .any(|f| token == f.to_lowercase());
            if is_standalone {
                i += 1;
                continue;
            }

            // This token is the subcommand (or a regular arg)
            seen_subcommand = true;
        }

        result.push(token);
        i += 1;
    }

    result.join(" ")
}

/// Check whether a short flag cluster (e.g., `-fu`, `-xfd`) contains a
/// specific flag character.
fn short_flags_contain(token: &str, flag: char) -> bool {
    token.starts_with('-') && !token.starts_with("--") && token[1..].contains(flag)
}

/// Return true if `branch` matches a protected branch name as a standalone
/// argument (not as a substring of another word).
fn is_protected_branch(branch: &str) -> bool {
    PROTECTED_BRANCHES.contains(&branch)
}

/// Return true if a token is a refspec targeting a protected branch.
/// Matches patterns like `HEAD:main`, `HEAD:refs/heads/main`, `abc123:master`.
fn is_refspec_to_protected_branch(token: &str) -> bool {
    if let Some((_src, dst)) = token.split_once(':') {
        // Handle refs/heads/main
        let branch = dst.strip_prefix("refs/heads/").unwrap_or(dst);
        is_protected_branch(branch)
    } else {
        false
    }
}

/// Return true if a token is a colon-prefixed delete refspec for a protected
/// branch (e.g., `:main`, `:refs/heads/master`).
fn is_delete_refspec_for_protected_branch(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix(':') {
        let branch = rest.strip_prefix("refs/heads/").unwrap_or(rest);
        !branch.is_empty() && is_protected_branch(branch)
    } else {
        false
    }
}

/// Check if a command is an alias definition (should not be blocked).
fn is_alias_definition(command: &str) -> bool {
    let trimmed = command.trim_start();
    trimmed.starts_with("alias ") || trimmed.starts_with("git config") && command.contains("alias.")
}

/// Blocks destructive git commands and warns on history-modifying operations.
pub struct GitSafetyGuard;

impl GitSafetyGuard {
    /// Check the normalized tokens for blocked operations.
    /// Returns `Some(reason)` if blocked, `None` if not.
    fn check_blocked(&self, normalized: &str, tokens: &[&str]) -> Option<String> {
        // Find the git subcommand position
        let git_pos = tokens.iter().position(|t| *t == "git")?;
        let sub_pos = git_pos + 1;
        if sub_pos >= tokens.len() {
            return None;
        }
        let subcommand = tokens[sub_pos];
        let args = &tokens[sub_pos + 1..];

        match subcommand {
            "push" => self.check_push_blocked(args),
            "reset" => self.check_reset_blocked(args),
            "checkout" => self.check_checkout_blocked(args),
            "clean" => self.check_clean_blocked(args),
            "reflog" => self.check_reflog_blocked(normalized),
            "gc" => self.check_gc_blocked(normalized),
            "branch" => self.check_branch_blocked(args),
            "rebase" => self.check_rebase_blocked(args),
            _ => None,
        }
    }

    fn check_push_blocked(&self, args: &[&str]) -> Option<String> {
        let has_force = args.iter().any(|a| {
            *a == "--force"
                || *a == "--force-with-lease"
                || *a == "-f"
                || short_flags_contain(a, 'f')
        });
        let has_delete = args.iter().any(|a| *a == "--delete" || *a == "-d");

        // Check for force push to protected branch
        if has_force {
            // Check if any arg is a protected branch name
            let targets_protected = args
                .iter()
                .any(|a| is_protected_branch(a) || is_refspec_to_protected_branch(a));
            if targets_protected {
                return Some("Force push to protected branch".into());
            }
        }

        // Check for push --delete of protected branch
        if has_delete {
            let targets_protected = args.iter().any(|a| is_protected_branch(a));
            if targets_protected {
                return Some("Delete of protected branch via push --delete".into());
            }
        }

        // Check for colon-prefixed delete refspec (:main, :refs/heads/main)
        let has_delete_refspec = args
            .iter()
            .any(|a| is_delete_refspec_for_protected_branch(a));
        if has_delete_refspec {
            return Some("Delete of protected branch via colon refspec".into());
        }

        // Check for refspec targeting protected branch (HEAD:main, etc.)
        // even without --force (this is a push that overwrites a protected branch)
        let has_protected_refspec = args.iter().any(|a| is_refspec_to_protected_branch(a));
        if has_protected_refspec && has_force {
            return Some("Force push via refspec to protected branch".into());
        }

        None
    }

    fn check_reset_blocked(&self, args: &[&str]) -> Option<String> {
        if args.contains(&"--hard") {
            return Some("git reset --hard".into());
        }
        None
    }

    fn check_checkout_blocked(&self, args: &[&str]) -> Option<String> {
        // Block "git checkout -- ." but not "git checkout -- src/file.rs"
        if args.contains(&"--") && args.contains(&".") {
            return Some("git checkout -- . (discards all changes)".into());
        }
        None
    }

    fn check_clean_blocked(&self, args: &[&str]) -> Option<String> {
        // git clean is dangerous when it has -f/--force (required to actually delete)
        let has_force = args
            .iter()
            .any(|a| *a == "--force" || *a == "-f" || short_flags_contain(a, 'f'));
        if has_force {
            return Some("git clean with force flag".into());
        }
        None
    }

    fn check_reflog_blocked(&self, normalized: &str) -> Option<String> {
        if normalized.contains("expire") && normalized.contains("--expire=") {
            return Some("git reflog expire".into());
        }
        None
    }

    fn check_gc_blocked(&self, normalized: &str) -> Option<String> {
        if normalized.contains("--prune=now") {
            return Some("git gc --prune=now".into());
        }
        None
    }

    fn check_branch_blocked(&self, args: &[&str]) -> Option<String> {
        let has_delete = args
            .iter()
            .any(|a| *a == "-d" || *a == "--delete" || short_flags_contain(a, 'd'));
        if has_delete {
            let targets_protected = args.iter().any(|a| is_protected_branch(a));
            if targets_protected {
                return Some("Delete protected branch".into());
            }
        }
        None
    }

    fn check_rebase_blocked(&self, args: &[&str]) -> Option<String> {
        // Check if any non-flag argument is exactly a protected branch name
        let targets_protected = args
            .iter()
            .any(|a| !a.starts_with('-') && is_protected_branch(a));
        if targets_protected {
            return Some("Rebase onto protected branch".into());
        }
        None
    }

    /// Check the normalized tokens for warned operations.
    /// Returns `Some(message)` if warned, `None` if not.
    fn check_warned(&self, tokens: &[&str]) -> Option<String> {
        let git_pos = tokens.iter().position(|t| *t == "git")?;
        let sub_pos = git_pos + 1;
        if sub_pos >= tokens.len() {
            return None;
        }
        let subcommand = tokens[sub_pos];
        let args = &tokens[sub_pos + 1..];

        match subcommand {
            "push" => {
                let has_force = args.iter().any(|a| {
                    *a == "--force"
                        || *a == "--force-with-lease"
                        || *a == "-f"
                        || short_flags_contain(a, 'f')
                });
                if has_force {
                    return Some("Force push (non-protected branch)".into());
                }
                None
            }
            "reset" => Some("git reset (may lose uncommitted work)".into()),
            "rebase" => Some("git rebase (rewrites history)".into()),
            "commit" => {
                if args.contains(&"--amend") {
                    return Some("git commit --amend (rewrites last commit)".into());
                }
                None
            }
            "stash" => {
                if args.contains(&"drop") || args.contains(&"clear") {
                    return Some("git stash drop/clear (may lose stashed work)".into());
                }
                None
            }
            "branch" => {
                let has_delete = args
                    .iter()
                    .any(|a| *a == "-d" || *a == "--delete" || short_flags_contain(a, 'd'));
                if has_delete {
                    return Some("git branch delete".into());
                }
                None
            }
            "remote" => {
                if args.contains(&"remove") || args.contains(&"rm") {
                    return Some("git remote remove".into());
                }
                None
            }
            _ => None,
        }
    }
}

impl Check for GitSafetyGuard {
    fn name(&self) -> &str {
        "git-safety"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        let lower = command.to_lowercase();

        if !lower.contains("git") {
            return CheckResult::allow();
        }

        // Skip alias definitions to avoid false positives
        if is_alias_definition(command) {
            return CheckResult::allow();
        }

        let normalized = normalize_git_command(command);
        let tokens: Vec<&str> = normalized.split_whitespace().collect();

        // Check absolute blocks first
        if let Some(_reason) = self.check_blocked(&normalized, &tokens) {
            return CheckResult::block(format!(
                "BLOCKED: Dangerous git operation detected.\n\n\
                 Command: {command}\n\n\
                 This operation could cause data loss or rewrite shared history.\n\
                 If you really need to do this, run it manually outside Claude Code."
            ));
        }

        // Check warnings
        if let Some(_reason) = self.check_warned(&tokens) {
            return CheckResult::warn(format!(
                "Git operation may modify history or lose work: {command}"
            ));
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---------------------------------------------------------------
    // normalize_git_command tests
    // ---------------------------------------------------------------

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(
            normalize_git_command("git  push  --force  origin  main"),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_no_pager() {
        assert_eq!(
            normalize_git_command("git --no-pager push --force origin main"),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_c_flag() {
        assert_eq!(
            normalize_git_command("git -C /some/path push --force origin main"),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_git_dir_eq() {
        assert_eq!(
            normalize_git_command("git --git-dir=/foo/.git push --force origin main"),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_work_tree() {
        assert_eq!(
            normalize_git_command("git --work-tree /foo push --force origin main"),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_no_optional_locks() {
        assert_eq!(
            normalize_git_command("git --no-optional-locks status"),
            "git status"
        );
    }

    #[test]
    fn normalize_strips_multiple_global_flags() {
        assert_eq!(
            normalize_git_command(
                "git --no-pager -C /repo --git-dir=/repo/.git push -f origin main"
            ),
            "git push -f origin main"
        );
    }

    // ---------------------------------------------------------------
    // Basic allow/block/warn (existing tests, preserved)
    // ---------------------------------------------------------------

    #[test]
    fn normal_git_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin feature-branch"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn force_push_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn amend_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git commit --amend"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn force_push_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn non_git_command_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("ls -la"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
        };
        let result = GitSafetyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn force_push_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_short_flag_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -f origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn checkout_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout -- ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_fd_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean -fd"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_f_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean -f"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn branch_delete_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn branch_delete_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn reflog_expire_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git reflog expire --expire=now --all"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn gc_prune_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git gc --prune=now"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn stash_drop_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git stash drop"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn stash_clear_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git stash clear"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn branch_delete_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D my-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn remote_remove_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git remote remove upstream"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn normal_push_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn normal_commit_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git commit -m 'feat: add thing'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn embedded_in_chain_detected() {
        let result = GitSafetyGuard.run(&make_bash_input("cd /tmp && git reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_flag_after_remote_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin main --force"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_short_flag_after_remote_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin main -f"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_master_short_flag_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -f origin master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_master_flag_after_remote_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin master --force"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_master_short_after_remote_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin master -f"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_df_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean -df"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_master_interactive_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase -i master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn case_insensitive_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("GIT PUSH --FORCE ORIGIN MAIN"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn reset_soft_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git reset HEAD~1"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn rebase_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase feature-branch"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn remote_rm_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git remote rm origin"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn branch_delete_uppercase_d_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn branch_delete_master_uppercase_d_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn branch_delete_long_form_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch --delete main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn branch_delete_long_form_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch --delete master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn reflog_expire_in_chain_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git reflog expire --expire=now --all && git gc --prune=now",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn git_log_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git log --oneline -10"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_diff_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git diff HEAD~1"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_fetch_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git fetch origin"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_pull_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git pull origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_add_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git add src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn blocked_precedes_warn() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn checkout_specific_file_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout -- src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn branch_delete_long_form_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch --delete my-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Bug fix #1: Extra whitespace bypass
    // ---------------------------------------------------------------

    #[test]
    fn extra_whitespace_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git  push  --force  origin  main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn extra_whitespace_reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git   reset   --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn extra_whitespace_clean_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git  clean  -fd"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // Bug fix #2: Git global flags bypass
    // ---------------------------------------------------------------

    #[test]
    fn no_pager_force_push_blocked() {
        let result =
            GitSafetyGuard.run(&make_bash_input("git --no-pager push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn c_flag_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git -C /some/path push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn git_dir_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --git-dir=/foo/.git push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn work_tree_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --work-tree /foo push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn no_optional_locks_reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git --no-optional-locks reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn multiple_global_flags_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --no-pager -C /repo --git-dir=/repo/.git push -f origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // Bug fix #3: git clean flag reordering
    // ---------------------------------------------------------------

    #[test]
    fn clean_xfd_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean -xfd"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_d_f_separate_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean -d -f"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_force_long_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean --force"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_force_d_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git clean --force -d"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_dry_run_allowed() {
        // git clean -n (dry run) without -f should be allowed
        let result = GitSafetyGuard.run(&make_bash_input("git clean -n"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // Bug fix #4: Combined short flags
    // ---------------------------------------------------------------

    #[test]
    fn push_fu_combined_flag_blocked() {
        // -fu = --force + -u (set upstream)
        let result = GitSafetyGuard.run(&make_bash_input("git push -fu origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_uf_combined_flag_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -uf origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_fu_feature_warned() {
        // Force push to non-protected branch: warn, not block
        let result = GitSafetyGuard.run(&make_bash_input("git push -fu origin feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Bug fix #5: Force push to non-origin remotes
    // ---------------------------------------------------------------

    #[test]
    fn force_push_upstream_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force upstream main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_custom_remote_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -f gitlab master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_upstream_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force upstream feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Bug fix #6: Remote branch deletion
    // ---------------------------------------------------------------

    #[test]
    fn push_delete_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --delete origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_delete_d_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -d origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_colon_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin :main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_colon_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin :master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_colon_refs_heads_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin :refs/heads/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_delete_feature_allowed() {
        // Deleting a feature branch is not blocked
        let result = GitSafetyGuard.run(&make_bash_input("git push --delete origin feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn push_colon_feature_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin :feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // Bug fix #7: Refspec push detection
    // ---------------------------------------------------------------

    #[test]
    fn push_force_head_colon_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin HEAD:main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_force_head_colon_refs_heads_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git push --force origin HEAD:refs/heads/main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_force_sha_colon_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push -f origin abc123:master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_force_refspec_feature_warned() {
        // Force push refspec to non-protected branch: warn
        let result = GitSafetyGuard.run(&make_bash_input("git push -f origin HEAD:feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Bug fix #8: False positive on alias definitions
    // ---------------------------------------------------------------

    #[test]
    fn alias_definition_containing_force_push_allowed() {
        let result =
            GitSafetyGuard.run(&make_bash_input("alias gfp='git push --force origin main'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn git_config_alias_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git config --global alias.fp 'push --force origin main'",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // Bug fix #9: False positive on branch names containing "main"
    // ---------------------------------------------------------------

    #[test]
    fn rebase_maintain_state_not_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase feat/maintain-state"));
        // Should be warned (rebase) but NOT blocked (maintain != main)
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn rebase_domain_main_not_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase fix/domain-maintenance"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn rebase_mainly_not_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase mainly-refactor"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn branch_delete_main_feature_warned_not_blocked() {
        // "main-feature" is not "main"
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D main-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    #[test]
    fn force_push_maintain_warned_not_blocked() {
        // "maintain" is not "main"
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin maintain"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Regression: force-with-lease to protected branch blocked
    // ---------------------------------------------------------------

    #[test]
    fn force_with_lease_main_blocked() {
        let result =
            GitSafetyGuard.run(&make_bash_input("git push --force-with-lease origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_with_lease_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git push --force-with-lease origin feature",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Warn);
    }

    // ---------------------------------------------------------------
    // Combined bypass: global flags + whitespace + reordering
    // ---------------------------------------------------------------

    #[test]
    fn global_flags_whitespace_reorder_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git  --no-pager  -C /repo  push  origin  main  --force",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
