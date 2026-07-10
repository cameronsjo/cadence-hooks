//! Block or warn on dangerous git operations.
//!
//! Force-push to main/master, `reset --hard`, `clean -f`, and similar
//! destructive commands are blocked. Less dangerous operations like
//! `rebase`, `reset`, and `branch -d` trigger warnings.
//!
//! Commands are normalized before matching: extra whitespace is collapsed
//! and git global flags between `git` and the subcommand are stripped so
//! that flag injection and whitespace padding cannot bypass detection. Any
//! unrecognized `-`-prefixed token in that position is skipped too — the
//! subcommand is the first non-flag token, so an unlisted global flag
//! (`-p`, `--literal-pathspecs`) cannot hide the subcommand (#72).

use cadence_hooks_core::shell::{command_segments, parse_work_dir, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Protected branch names that trigger blocks instead of warnings.
const PROTECTED_BRANCHES: &[&str] = &["main", "master"];

/// Git global options between `git` and the subcommand that take a
/// following argument which must also be stripped. Tokens are lowercased
/// before matching, so `-C <path>` and `-c <key>=<value>` collapse into one
/// entry — both consume exactly one argument, so the collision is harmless.
/// `--namespace`, `--super-prefix`, `--config-env`, and `--attr-source` are
/// git's remaining enumerable separate-arg globals (#117); only a truly
/// unknown future separate-arg flag remains a documented gap.
const GIT_GLOBAL_FLAGS_WITH_ARG: &[&str] = &[
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
];

/// Pathspecs that discard every change in the working tree when handed to
/// `git checkout` / `git restore` (#73).
const DISCARD_ALL_PATHSPECS: &[&str] = &[".", "./", ":/"];

/// True if a token is the `git` command word — either bare `git` or a path
/// ending in `/git` (e.g. `/usr/bin/git`, `./git`). Closes the absolute/relative
/// path-git evasion: matching only the exact token `git` let `/usr/bin/git push
/// --force` slip the normalizer.
fn is_git_word(token: &str) -> bool {
    token == "git" || token.ends_with("/git")
}

/// Normalize a single command segment into matchable tokens.
///
/// 1. Quote-aware tokenization ([`tokenize`]): a quoted flag like `"--force"`
///    becomes a clean `--force` token, while a whole command quoted as an
///    argument stays one token and can never masquerade as the git command word.
/// 2. Strip git global options that appear between `git` and the subcommand:
///    known value-carrying flags (`-C <path>`, `-c <key>=<value>`,
///    `--git-dir <path>`, `--work-tree <path>`) consume their argument, and
///    every other `-`-prefixed token is skipped, so the subcommand is the
///    first non-flag token (#72).
///
/// Returns the lowercased token list. The caller must judge these tokens
/// directly (not a re-joined string), or a quoted span with internal spaces
/// would re-fragment and defeat the quote-awareness.
fn normalize_git_command(command: &str) -> Vec<String> {
    let tokens = tokenize(&command.to_lowercase());
    let mut result: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    let mut seen_git = false;
    let mut seen_subcommand = false;

    while i < tokens.len() {
        let token = tokens[i].as_str();

        // Pass through everything before `git`
        if !seen_git {
            result.push(token.to_string());
            if is_git_word(token) {
                seen_git = true;
            }
            i += 1;
            continue;
        }

        // After `git` but before the subcommand, strip global flags. Known
        // value-carrying flags consume their separate argument; every other
        // `-`-prefixed token (including `--flag=value` forms) is skipped, so
        // the subcommand is the first non-flag token (#72). The named
        // separate-arg globals (`--namespace`, `--super-prefix`, `--config-env`,
        // `--attr-source`) are now enumerated and consumed too (#117). Known
        // gap: a truly UNLISTED future flag with a separate argument still
        // mis-takes the argument as the subcommand and allows — the same
        // outcome as before this rewrite, never worse.
        if !seen_subcommand {
            let is_sep_flag = GIT_GLOBAL_FLAGS_WITH_ARG.contains(&token);
            if is_sep_flag {
                i += 2; // skip flag and its argument
                continue;
            }

            if token.starts_with('-') {
                i += 1;
                continue;
            }

            // This token is the subcommand
            seen_subcommand = true;
        }

        result.push(token.to_string());
        i += 1;
    }

    result
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

/// True if a push argument is a force flag, including value-carrying forms
/// like `--force-with-lease=origin/main` that exact-token matching missed (#71).
fn is_force_flag(token: &str) -> bool {
    token == "-f"
        || short_flags_contain(token, 'f')
        || matches!(
            token.split('=').next(),
            Some("--force" | "--force-with-lease")
        )
}

/// Strip a `refs/heads/` prefix from a standalone push target so fully
/// qualified refs (`refs/heads/main`) match protected branch names (#71).
fn push_target_branch(token: &str) -> &str {
    token.strip_prefix("refs/heads/").unwrap_or(token)
}

/// A restore touches the worktree unless it is staged-only: `--staged` (long
/// form) present with no worktree marker (`--worktree`, or `w` in a short
/// cluster). Lowercased tokens collide `-S` (staged) with `-s` (source), so
/// the short staged spelling does NOT earn the exemption — `git restore -S .`
/// over-blocks by design; `--staged` is the allowed spelling (#73).
fn restore_touches_worktree(args: &[&str]) -> bool {
    let staged_long = args.contains(&"--staged");
    let worktree_marker = args
        .iter()
        .any(|a| *a == "--worktree" || short_flags_contain(a, 'w'));
    !staged_long || worktree_marker
}

/// True when a segment force-pushes a bare `head` token — the only shape
/// that needs the current branch resolved (#71).
fn force_pushes_bare_head(tokens: &[&str]) -> bool {
    let Some(git_pos) = tokens.iter().position(|t| is_git_word(t)) else {
        return false;
    };
    if tokens.get(git_pos + 1).copied() != Some("push") {
        return false;
    }
    let args = &tokens[git_pos + 2..];
    args.iter().any(|a| is_force_flag(a)) && args.contains(&"head")
}

/// Current-branch resolution for bare-`HEAD` force pushes.
///
/// `Unresolvable` (git answered, no branch — e.g. not a repo) stays a block:
/// that fail-safe is deliberate. `TimedOut` (the probe hit the #271 subprocess
/// deadline) must NOT block — a slow host is the guard's own infrastructure
/// failing, and converting that into a false block on routine
/// feature-branch force pushes is the regression this distinction prevents.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BranchResolution {
    Branch(String),
    Unresolvable,
    TimedOut,
}

/// Resolve the current branch in the command's effective directory,
/// lowercased to match normalized tokens.
fn resolve_current_branch(input: &HookInput, command: &str) -> BranchResolution {
    let cwd_fallback = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| ".".to_string());
    let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
    let work_dir = parse_work_dir(command, cwd);
    match cadence_hooks_core::shell::git_command_detailed(
        &work_dir,
        &["rev-parse", "--abbrev-ref", "HEAD"],
    ) {
        cadence_hooks_core::shell::GitQuery::Value(branch) => {
            BranchResolution::Branch(branch.to_lowercase())
        }
        cadence_hooks_core::shell::GitQuery::Failed => BranchResolution::Unresolvable,
        cadence_hooks_core::shell::GitQuery::TimedOut => BranchResolution::TimedOut,
    }
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
    ///
    /// `current_branch` is the resolved branch for bare-`HEAD` force pushes;
    /// the caller resolves it lazily (`None` = no such segment, so no
    /// resolution was attempted).
    fn check_blocked(
        &self,
        normalized: &str,
        tokens: &[&str],
        current_branch: Option<&BranchResolution>,
    ) -> Option<String> {
        // Find the git subcommand position
        let git_pos = tokens.iter().position(|t| is_git_word(t))?;
        let sub_pos = git_pos + 1;
        if sub_pos >= tokens.len() {
            return None;
        }
        let subcommand = tokens[sub_pos];
        let args = &tokens[sub_pos + 1..];

        match subcommand {
            "push" => self.check_push_blocked(args, current_branch),
            "reset" => self.check_reset_blocked(args),
            "checkout" => self.check_checkout_blocked(args),
            "restore" => self.check_restore_blocked(args),
            "clean" => self.check_clean_blocked(args),
            "reflog" => self.check_reflog_blocked(normalized),
            "gc" => self.check_gc_blocked(normalized),
            "branch" => self.check_branch_blocked(args),
            "rebase" => self.check_rebase_blocked(args),
            sub @ ("filter-branch" | "filter-repo") => {
                // Mass history rewrite — no benign form; same family as the
                // reflog-expire / gc --prune blocks (#84).
                Some(format!("git {sub} (mass history rewrite)"))
            }
            "update-ref" => self.check_update_ref_blocked(args),
            _ => None,
        }
    }

    fn check_push_blocked(
        &self,
        args: &[&str],
        current_branch: Option<&BranchResolution>,
    ) -> Option<String> {
        // `--mirror` overwrites EVERY remote ref and deletes remote refs absent
        // locally — protected branches included, no per-branch targeting (#84).
        if args.contains(&"--mirror") {
            return Some("Mirror push (overwrites/deletes all remote refs)".into());
        }

        let has_force = args.iter().any(|a| is_force_flag(a));
        let has_delete = args.iter().any(|a| *a == "--delete" || *a == "-d");

        // Check for force push to protected branch
        if has_force {
            // Check if any arg is a protected branch name
            let targets_protected = args.iter().any(|a| {
                is_protected_branch(push_target_branch(a)) || is_refspec_to_protected_branch(a)
            });
            if targets_protected {
                return Some("Force push to protected branch".into());
            }

            // A bare `HEAD` target pushes the current branch (#71). Block when
            // it resolves to a protected branch, and when git answers but the
            // branch cannot be determined (fail safe — a push from a non-repo
            // dir fails anyway). A resolution that hit the #271 subprocess
            // deadline is the guard's OWN failure — never a block (ADR-0001);
            // it degrades to the fall-through and is recorded loudly as a
            // suppressed fail-closed block. A resolved feature branch falls
            // through to the routine force-push nudge: `git push --force
            // origin HEAD` on a feature branch is normal rebase workflow and
            // is never statically blocked.
            if args.contains(&"head") {
                match current_branch {
                    Some(BranchResolution::Branch(branch)) if is_protected_branch(branch) => {
                        return Some("Force push of HEAD while on protected branch".into());
                    }
                    Some(BranchResolution::Branch(_)) => {}
                    Some(BranchResolution::TimedOut) => {
                        cadence_hooks_core::deadline::note_suppressed_block();
                    }
                    Some(BranchResolution::Unresolvable) | None => {
                        return Some("Force push of HEAD with unresolvable current branch".into());
                    }
                }
            }
        }

        // Check for push --delete of protected branch
        if has_delete {
            let targets_protected = args
                .iter()
                .any(|a| is_protected_branch(push_target_branch(a)));
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

    fn check_update_ref_blocked(&self, args: &[&str]) -> Option<String> {
        // `--stdin` batch mode reads the ref commands from stdin, which the guard
        // cannot see — the block path can't judge it, so check_warned nudges.
        if args.contains(&"--stdin") {
            return None;
        }
        let has_delete = args.iter().any(|a| *a == "-d" || *a == "--delete");
        // The ref operand is the first non-flag token — but `-m`/`--message`
        // takes a reflog-reason value that is itself a non-flag token, so a naive
        // first-non-flag scan picks the reason and the protected-ref check never
        // fires (review H1). Skip the value of `-m`/`--message`; every other
        // update-ref flag is boolean.
        let mut skip_next = false;
        let ref_operand = args.iter().find(|a| {
            if skip_next {
                skip_next = false;
                return false;
            }
            if **a == "-m" || **a == "--message" {
                skip_next = true;
                return false;
            }
            !a.starts_with('-')
        });
        let targets_protected = ref_operand
            .map(|r| is_protected_branch(push_target_branch(r)))
            .unwrap_or(false);

        if targets_protected {
            return Some(if has_delete {
                "Delete of protected branch via update-ref".into()
            } else {
                // Repointing a protected ref to an arbitrary commit can silently
                // drop commits (no merge check) — as destructive as force-push.
                "Repoint of protected branch via update-ref".into()
            });
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
        // `git checkout .` / `./` / `:/` discards every uncommitted change,
        // with or without `--` (#73). Named-pathspec discards after `--`
        // (`git checkout -- src/file.rs`) nudge in check_warned instead of
        // blocking (#117); bare `git checkout <name>` without `--` stays out of
        // scope — checkout's positional grammar makes a named pathspec
        // ambiguous with a branch name.
        if args.iter().any(|a| DISCARD_ALL_PATHSPECS.contains(a)) {
            return Some("git checkout of all pathspecs (discards all changes)".into());
        }
        None
    }

    fn check_restore_blocked(&self, args: &[&str]) -> Option<String> {
        // `git restore .` discards every uncommitted worktree change (#73).
        // Staged-only restores (`--staged` with no worktree marker) touch the
        // index, not the worktree, and are never blocked.
        if restore_touches_worktree(args) && args.iter().any(|a| DISCARD_ALL_PATHSPECS.contains(a))
        {
            return Some("git restore of all pathspecs (discards all changes)".into());
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
        // `--onto <newbase>` names a rebase DESTINATION, not a ref being
        // rewritten — replaying commits onto main never modifies main, so the
        // single token following `--onto` is exempt (#74, a documented
        // stacked-PR restack workflow). A protected branch named anywhere else
        // still relocates/rewrites a protected ref and stays blocked: plain
        // `git rebase main`, or `main`/`master` as the rewritten <branch> in
        // `git rebase --onto X Y main`.
        let onto_newbase = args.iter().position(|a| *a == "--onto").map(|i| i + 1);
        let targets_protected = args
            .iter()
            .enumerate()
            .any(|(i, a)| Some(i) != onto_newbase && !a.starts_with('-') && is_protected_branch(a));
        if targets_protected {
            return Some("Rebase onto protected branch".into());
        }
        None
    }

    /// Check the normalized tokens for warned operations.
    /// Returns `Some(message)` if warned, `None` if not.
    fn check_warned(&self, tokens: &[&str]) -> Option<String> {
        let git_pos = tokens.iter().position(|t| is_git_word(t))?;
        let sub_pos = git_pos + 1;
        if sub_pos >= tokens.len() {
            return None;
        }
        let subcommand = tokens[sub_pos];
        let args = &tokens[sub_pos + 1..];

        match subcommand {
            "push" => {
                let has_force = args.iter().any(|a| is_force_flag(a));
                if has_force {
                    return Some("Force push (non-protected branch)".into());
                }
                None
            }
            "restore" => {
                // Worktree-touching restore of named pathspecs overwrites
                // local edits to those files — nudge (#73). Discard-all forms
                // block in check_restore_blocked before this runs.
                if restore_touches_worktree(args)
                    && args
                        .iter()
                        .any(|a| !a.starts_with('-') && !DISCARD_ALL_PATHSPECS.contains(a))
                {
                    return Some("git restore (overwrites local changes to named paths)".into());
                }
                None
            }
            "checkout" => {
                // `git checkout [-<ref>] -- <named paths>` overwrites local
                // edits to those files — the same operation as `git restore`,
                // so it nudges too (#117). Everything after `--` is a pathspec,
                // so this form is unambiguous (unlike bare `git checkout <name>`,
                // which stays out of scope). Discard-all pathspecs (`. ./ :/`)
                // block in check_checkout_blocked before this runs.
                if let Some(dd) = args.iter().position(|a| *a == "--")
                    && args[dd + 1..]
                        .iter()
                        .any(|a| !DISCARD_ALL_PATHSPECS.contains(a))
                {
                    return Some("git checkout (overwrites local changes to named paths)".into());
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
            "update-ref" => {
                // `--stdin` batch edits carry their refs on stdin (invisible to
                // the guard, and a protected delete/repoint could hide there) —
                // surface it rather than silently allow (review M1). Checked
                // before `-d` so the more-informative "refs not verifiable"
                // message wins when both are present (`update-ref -d --stdin`).
                if args.contains(&"--stdin") {
                    return Some(
                        "git update-ref --stdin (batch ref edits; refs not verifiable here)".into(),
                    );
                }
                // A non-protected ref delete (protected deletes already block in
                // check_update_ref_blocked) has no safety net — nudge (#84).
                if args.iter().any(|a| *a == "-d" || *a == "--delete") {
                    return Some("git update-ref -d (deletes a ref with no safety net)".into());
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

        if !command.to_lowercase().contains("git") {
            return CheckResult::allow();
        }

        // Judge each command segment independently so a benign first command
        // (`git status &&`, `cd x &&`) can't shield a destructive sibling, and
        // a command hidden in `sh -c '…'` is still seen. Block precedence: any
        // segment blocks → block; else any warns → nudge.
        let mut should_warn = false;
        // Current-branch resolution for bare-HEAD force pushes (#71): lazy
        // (only when such a segment appears) and memoized across segments.
        let mut resolved_branch: Option<BranchResolution> = None;
        for segment in command_segments(command) {
            // Per-segment alias check: a `git config alias.x …` segment is
            // exempt, but a destructive sibling in the same chain is not.
            if is_alias_definition(&segment) {
                continue;
            }

            let norm_tokens = normalize_git_command(&segment);
            let tokens: Vec<&str> = norm_tokens.iter().map(String::as_str).collect();
            // Joined form is only for the substring-based reflog/gc checks; the
            // git-word match runs on the span-preserved token list above.
            let normalized = tokens.join(" ");

            let current_branch = if force_pushes_bare_head(&tokens) {
                Some(
                    &*resolved_branch.get_or_insert_with(|| resolve_current_branch(input, command)),
                )
            } else {
                None
            };

            if let Some(found) = self.check_blocked(&normalized, &tokens, current_branch) {
                return CheckResult::block(format!(
                    "BLOCKED: git-safety: dangerous git operation\n\
                     Found: {found} in `{command}`\n\
                     Fix: this can cause data loss or rewrite shared history — \
                     if it is genuinely needed, ask the user to run it manually \
                     outside Claude Code."
                ));
            }

            if self.check_warned(&tokens).is_some() {
                should_warn = true;
            }
        }

        if should_warn {
            return CheckResult::nudge(format!(
                "Git operation may modify history or lose work: {command}"
            ));
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_bash as make_bash_input, make_bash_with_cwd};

    // ---------------------------------------------------------------
    // normalize_git_command tests
    // ---------------------------------------------------------------

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(
            normalize_git_command("git  push  --force  origin  main").join(" "),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_no_pager() {
        assert_eq!(
            normalize_git_command("git --no-pager push --force origin main").join(" "),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_c_flag() {
        assert_eq!(
            normalize_git_command("git -C /some/path push --force origin main").join(" "),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_git_dir_eq() {
        assert_eq!(
            normalize_git_command("git --git-dir=/foo/.git push --force origin main").join(" "),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_work_tree() {
        assert_eq!(
            normalize_git_command("git --work-tree /foo push --force origin main").join(" "),
            "git push --force origin main"
        );
    }

    #[test]
    fn normalize_strips_no_optional_locks() {
        assert_eq!(
            normalize_git_command("git --no-optional-locks status").join(" "),
            "git status"
        );
    }

    #[test]
    fn normalize_strips_multiple_global_flags() {
        assert_eq!(
            normalize_git_command(
                "git --no-pager -C /repo --git-dir=/repo/.git push -f origin main"
            )
            .join(" "),
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
    fn rebase_onto_main_destination_allowed() {
        // #74: `--onto main` names main as the DESTINATION (never rewritten);
        // the rewritten ref is `feature`. Must not hard-block (rebase still
        // nudges as a history-rewriting op).
        let result =
            GitSafetyGuard.run(&make_bash_input("git rebase --onto main feature~3 feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn rebase_onto_main_newbase_only_allowed() {
        // `--onto main` with no upstream/branch rebases the CURRENT branch onto
        // main — main is still only the destination, so it is not blocked.
        let result = GitSafetyGuard.run(&make_bash_input("git rebase --onto main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn rebase_onto_with_main_as_branch_blocked() {
        // #74 regression: main as the trailing <branch> IS rewritten — stays blocked.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git rebase --onto refactor feature~3 main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_onto_main_with_master_branch_blocked() {
        // #74 regression: only the token after --onto is exempt; master as
        // <branch> is rewritten and stays blocked.
        let result = GitSafetyGuard.run(&make_bash_input("git rebase --onto main feature master"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn rebase_onto_with_main_upstream_blocked() {
        // #74: main as <upstream> is not rewritten, but the minimal fix keeps
        // this blocked (a deliberate, documented over-block — not a hole).
        let result = GitSafetyGuard.run(&make_bash_input("git rebase --onto HEAD~2 main feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn amend_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git commit --amend"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn force_push_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
            ..Default::default()
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn stash_clear_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git stash clear"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn branch_delete_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D my-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn remote_remove_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git remote remove upstream"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn rebase_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase feature-branch"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn remote_rm_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git remote rm origin"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
    fn checkout_named_pathspec_warned() {
        // `git checkout -- <named path>` overwrites local edits to that file —
        // the same operation as `git restore`, so it nudges too (#117).
        let result = GitSafetyGuard.run(&make_bash_input("git checkout -- src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn branch_delete_long_form_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git branch --delete my-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn rebase_domain_main_not_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase fix/domain-maintenance"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn rebase_mainly_not_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git rebase mainly-refactor"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn branch_delete_main_feature_warned_not_blocked() {
        // "main-feature" is not "main"
        let result = GitSafetyGuard.run(&make_bash_input("git branch -D main-feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn force_push_maintain_warned_not_blocked() {
        // "maintain" is not "main"
        let result = GitSafetyGuard.run(&make_bash_input("git push --force origin maintain"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
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

    // ---------------------------------------------------------------
    // #61: chained command — only the first git was inspected
    // ---------------------------------------------------------------

    #[test]
    fn benign_first_then_force_push_main_blocked() {
        // The bypass: `git status` is benign, so the force-push slipped through.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git status && git push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn benign_first_then_reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("ls && git reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_main_after_semicolon_blocked() {
        let result =
            GitSafetyGuard.run(&make_bash_input("echo done; git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_push_main_after_pipe_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("true | git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // #63: quote-aware tokenization — path/escaped git and quoted flags
    // ---------------------------------------------------------------

    #[test]
    fn absolute_path_git_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("/usr/bin/git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn relative_path_git_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("./git push --force origin main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn quoted_force_flag_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(r#"git push "--force" origin main"#));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn sh_c_wrapped_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("sh -c 'git push --force origin main'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // #62: alias check exempted the whole command line
    // ---------------------------------------------------------------

    #[test]
    fn alias_config_then_force_push_blocked() {
        // The config-alias segment is exempt, but the chained force-push is not.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git config alias.fp 'push --force' && git push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // False-block guards: quoted-as-argument commands must stay allowed
    // ---------------------------------------------------------------

    #[test]
    fn echo_of_force_push_string_allowed() {
        // `git` lives inside a quoted argument to echo — not a git command.
        let result = GitSafetyGuard.run(&make_bash_input(r#"echo "git push --force origin main""#));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn echo_single_quoted_git_then_ls_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "echo 'use git push --force carefully' && ls",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn commit_message_with_reset_hard_text_allowed() {
        // `reset --hard` and `;` are inside the commit message — not commands.
        let result = GitSafetyGuard.run(&make_bash_input(
            r#"git commit -m "wip; reset --hard test""#,
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // #71: force-flag and protected-target precision
    // ---------------------------------------------------------------

    #[test]
    fn force_with_lease_eq_main_blocked() {
        // `--force-with-lease=<ref>` is a force flag; exact-token matching missed it.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git push --force-with-lease=origin/main origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn force_with_lease_eq_feature_warned() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git push --force-with-lease=origin/feature origin feature",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn force_push_refs_heads_main_blocked() {
        // Fully qualified ref names must match protected branch names.
        let result =
            GitSafetyGuard.run(&make_bash_input("git push --force origin refs/heads/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_delete_refs_heads_main_blocked() {
        let result =
            GitSafetyGuard.run(&make_bash_input("git push --delete origin refs/heads/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_refs_heads_main_without_force_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git push origin refs/heads/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bare_head_force_push_on_protected_branch_blocked_unit() {
        // Injected resolution: current branch is protected → block.
        let args = ["--force", "origin", "head"];
        assert!(
            GitSafetyGuard
                .check_push_blocked(&args, Some("main"))
                .is_some()
        );
    }

    #[test]
    fn bare_head_force_push_unresolvable_blocked_unit() {
        // Injected resolution: branch unknown → fail safe, block.
        let args = ["--force", "origin", "head"];
        assert!(GitSafetyGuard.check_push_blocked(&args, None).is_some());
    }

    #[test]
    fn bare_head_force_push_on_feature_branch_falls_to_nudge_unit() {
        // Routine rebase workflow: force-push of HEAD on a feature branch is
        // never statically blocked — it falls through to the force nudge.
        let args = ["--force", "origin", "head"];
        assert!(
            GitSafetyGuard
                .check_push_blocked(&args, Some("my-feature"))
                .is_none()
        );
    }

    #[test]
    fn force_push_bare_head_outside_repo_blocked() {
        // Unresolvable current branch fails safe: blocked. (A push from a
        // non-repo dir fails anyway, so the block costs nothing.)
        let result = GitSafetyGuard.run(&make_bash_with_cwd(
            "git push --force origin HEAD",
            "/nonexistent/definitely-not-a-repo",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // #72: unlisted git global flags must not hide the subcommand
    // ---------------------------------------------------------------

    #[test]
    fn p_flag_reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git -p reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn literal_pathspecs_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --literal-pathspecs push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn no_replace_objects_clean_fd_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git --no-replace-objects clean -fd"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn c_config_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git -c http.sslverify=false push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn c_config_reset_hard_blocked() {
        // `-c key=value` must consume its separate argument, or `foo=bar`
        // would be taken as the subcommand and `reset --hard` would escape.
        let result = GitSafetyGuard.run(&make_bash_input("git -c foo=bar reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn namespace_flag_force_push_blocked() {
        // `--namespace ns` is a global flag taking a separate argument;
        // consuming it exposes the real subcommand (`push --force`) (#117).
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --namespace ns push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn config_env_flag_force_push_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git --config-env name=GIT_AUTHOR push --force origin main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn attr_source_flag_reset_hard_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git --attr-source HEAD reset --hard"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn super_prefix_flag_clean_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git --super-prefix x clean -fd"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // ---------------------------------------------------------------
    // #73: checkout/restore discard-all handlers
    // ---------------------------------------------------------------

    #[test]
    fn checkout_bare_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn checkout_dot_slash_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout ./"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn checkout_head_dashdash_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout HEAD -- ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn stash_then_checkout_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git stash && git checkout ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git restore ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_root_pathspec_blocked() {
        // `:/` is the repo-root pathspec — discards everything from anywhere.
        let result = GitSafetyGuard.run(&make_bash_input("git restore :/"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_worktree_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git restore --worktree ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_staged_worktree_dot_blocked() {
        // --staged does not exempt when --worktree is also present.
        let result = GitSafetyGuard.run(&make_bash_input("git restore --staged --worktree ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_source_dot_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git restore -s HEAD~1 ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn restore_named_path_warned() {
        // Worktree-touching restore of named paths overwrites local edits — nudge.
        let result = GitSafetyGuard.run(&make_bash_input("git restore src/main.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn restore_staged_dot_allowed() {
        // Staged-only restore touches the index, not the worktree.
        let result = GitSafetyGuard.run(&make_bash_input("git restore --staged ."));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn restore_staged_named_path_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git restore --staged src/file.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn checkout_branch_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout feature-branch"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn checkout_new_branch_allowed() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout -b new"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn checkout_main_allowed() {
        // Branch switching is not a discard — out of scope for this guard.
        let result = GitSafetyGuard.run(&make_bash_input("git checkout main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // #117: checkout `--` named-pathspec discards nudge
    // ---------------------------------------------------------------

    #[test]
    fn checkout_ref_named_pathspec_warned() {
        // Everything after `--` is a pathspec, so a leading ref is unambiguous.
        let result = GitSafetyGuard.run(&make_bash_input("git checkout main -- path/file.rs"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn checkout_head_named_dir_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout HEAD -- src/"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn checkout_multiple_named_pathspecs_warned() {
        let result = GitSafetyGuard.run(&make_bash_input("git checkout feature -- a.txt b.txt"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn checkout_dashdash_nothing_after_allowed() {
        // `--` with no pathspec following is not a discard — out of scope.
        let result = GitSafetyGuard.run(&make_bash_input("git checkout --"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // ---------------------------------------------------------------
    // #84: history-rewrite + remote-destructive subcommands/flags
    // ---------------------------------------------------------------

    #[test]
    fn filter_branch_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git filter-branch --tree-filter 'rm -f secrets.txt' HEAD",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn filter_repo_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git filter-repo --path secrets --invert-paths",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn filter_branch_in_chain_blocked() {
        // Per-segment: a benign first command must not shield the rewrite.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git status && git filter-branch --force --all",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_delete_main_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git update-ref -d refs/heads/main"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_delete_long_form_master_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input(
            "git update-ref --delete refs/heads/master",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_repoint_main_blocked() {
        // Repointing a protected ref can silently drop commits (no merge check).
        let result = GitSafetyGuard.run(&make_bash_input("git update-ref refs/heads/main abc1234"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn push_mirror_blocked() {
        let result = GitSafetyGuard.run(&make_bash_input("git push --mirror origin"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_delete_feature_warned() {
        // Non-protected ref delete: no merge safety net → nudge.
        let result = GitSafetyGuard.run(&make_bash_input("git update-ref -d refs/heads/feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn update_ref_repoint_feature_allowed() {
        // Benign plumbing on a non-protected ref is unaffected.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git update-ref refs/heads/feature abc1234",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn push_without_mirror_allowed() {
        // Regression: a normal push without --mirror is unaffected.
        let result = GitSafetyGuard.run(&make_bash_input("git push origin feature"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn update_ref_reflog_message_then_protected_repoint_blocked() {
        // Review H1: `-m <reason>` carries a non-flag value; the operand scan
        // must skip it and still find the protected ref.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git update-ref -m cleanup refs/heads/main abc1234",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_message_then_protected_delete_blocked() {
        // Review H1: the `-m … -d` form must not downgrade Block → Nudge.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git update-ref -m cleanup -d refs/heads/main",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn update_ref_message_then_feature_allowed() {
        // Review H1 regression: the reason string must not be mistaken for the
        // ref — a non-protected ref stays allowed.
        let result = GitSafetyGuard.run(&make_bash_input(
            "git update-ref -m reason refs/heads/feature abc1234",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn update_ref_stdin_warned() {
        // Review M1: batch refs are invisible — surface, don't silently allow.
        let result = GitSafetyGuard.run(&make_bash_input("git update-ref --stdin"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }
}
