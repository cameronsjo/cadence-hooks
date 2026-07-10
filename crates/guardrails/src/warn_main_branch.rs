//! Warn when editing on the main branch without a feature branch.
//!
//! Fires once per session (tracked via a temp-file marker) to nudge the
//! user toward creating a feature branch before making changes.
//!
//! Three ways to silence:
//! - **Per-repo, time-bounded**: `cadence-hooks guardrails dismiss-main-branch-warn --for <duration>`
//!   — see [`crate::dismiss_main_branch_warn`]. Caps at 24h.
//! - **Per-repo, permanent**: set `CADENCE_ALLOW_MAIN=true` in
//!   `<repo>/.claude/settings.json`'s `env` block. For repos where main IS
//!   the working branch by design (personal scratchpads, dotfiles, vaults).
//! - **User-global, permanent**: same env var in `~/.claude/settings.json`.
//!
//! Edits inside any `.claude/` directory are exempt automatically — worktrees
//! under `.claude/worktrees/` (always on an intentional feature branch) and the
//! user's `~/.claude/` config and memory tree. Plan documents under `docs/plans/`
//! are exempt too: cadence mandates copying approved plans there on the default
//! branch. That work is never the branch-worthy product change the warning targets.

use crate::dismiss_main_branch_warn;
pub(crate) use cadence_hooks_core::worktree::{is_claude_managed_dir, is_plan_doc_dir};
use cadence_hooks_core::{BypassKind, BypassProvenance, Check, CheckResult, HookInput, Outcome};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the directory to pass to `git -C` for a given hook input.
///
/// When the hook fires for an Edit/Write, returns the parent directory of
/// the edited file. `git -C <dir>` walks upward to find `.git`, so this
/// routes branch detection to the file's enclosing repo — even when CWD
/// belongs to an outer parent repo (the nested-repo case).
///
/// Relative `file_path` values are joined against `input.cwd` so we resolve
/// against the hook event's CWD, not the hook process's CWD. For Bash hooks
/// (no file path), falls back to `input.cwd` then `.` so we still target the
/// session's working directory rather than wherever the hook process started.
pub(crate) fn git_dir_for_input(input: &HookInput) -> PathBuf {
    let cwd = input
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let Some(file_path) = input.file_path() else {
        return cwd;
    };

    let path = Path::new(&file_path);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    resolved
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or(cwd)
}

// `is_claude_managed_dir` and `is_plan_doc_dir` moved to
// `cadence_hooks_core::worktree` (cadence-hooks#236) so `enforce_worktree`
// and `session::start`'s posture line share the exact same carve-out
// predicate — re-imported above.

/// Returns true if the branch name is a default branch (`main` or `master`).
fn is_default_branch(branch: &str) -> bool {
    branch == "main" || branch == "master"
}

/// Returns true if `CADENCE_ALLOW_MAIN` env var is set to a truthy value.
///
/// Truthy: `"1"`, `"true"`, `"yes"` (case-insensitive). Anything else (unset,
/// empty, `"0"`, `"false"`) is falsy. Set in `.claude/settings.json` env
/// block — project or user-global — to permanently opt a repo out of the
/// main-branch warning.
fn is_main_allowed() -> bool {
    is_main_allowed_value(std::env::var("CADENCE_ALLOW_MAIN").ok().as_deref())
}

/// Pure: classify a `CADENCE_ALLOW_MAIN` value as truthy or falsy.
fn is_main_allowed_value(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Pure decision: should we warn about editing on this branch?
///
/// Returns `Nudge` if on a default branch, not already warned this session,
/// not currently snoozed, and not permanently allowed via env var.
fn should_warn(branch: &str, already_warned: bool, snoozed: bool, allowed: bool) -> CheckResult {
    if !is_default_branch(branch) {
        return CheckResult::allow();
    }

    if allowed || snoozed || already_warned {
        return CheckResult::allow();
    }

    CheckResult::nudge(format!(
        "You're editing files directly on '{branch}'. \
         Ask the user: should this work be on a feature branch instead?\n\
         To silence for this session: cadence-hooks guardrails dismiss-main-branch-warn --for 2h\n\
         To silence permanently for this repo: set CADENCE_ALLOW_MAIN=true in .claude/settings.json"
    ))
}

/// Warns once per session when the current branch is `main` or `master`.
pub struct WarnMainBranch;

impl WarnMainBranch {
    /// Build the per-session marker path scoped to a specific repo root.
    ///
    /// Delegates to the shared [`cadence_hooks_core::markers::session_marker`]
    /// primitive: keyed on the Claude Code session id (stable across a session's
    /// many separate hook processes — the pre-CP0 `PPID`→pid scheme re-warned
    /// every edit because `PPID` is never exported, #133) and the repo-root hash,
    /// under the private 0700 marker dir.
    fn marker_path(input: &HookInput, repo_root: &str) -> PathBuf {
        cadence_hooks_core::markers::session_marker(input, "main-branch-warned", Some(repo_root))
    }
}

impl Check for WarnMainBranch {
    fn name(&self) -> &str {
        "warn-main-branch"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let dir = git_dir_for_input(input);

        // Edits inside a `.claude/` directory are tooling, config, or worktree
        // work, and plan docs under `docs/plans/` are mandated on the default
        // branch — never the branch-worthy product change this warns about. Skip
        // the warning (and the git spawns below) entirely. (issues #33, #35, #226)
        if is_claude_managed_dir(&dir) || is_plan_doc_dir(&dir) {
            return CheckResult::allow();
        }

        let dir_arg = dir.to_string_lossy();

        // Branch detection scoped to the edited file's repo, not CWD's repo.
        // `git -C` walks upward to find `.git`, picking the nearest enclosing
        // repository — which is what we want when editing inside a nested
        // checkout from a session whose CWD is the outer parent.
        let mut branch_cmd = Command::new("git");
        branch_cmd.args(["-C", &dir_arg, "symbolic-ref", "--short", "HEAD"]);
        let branch = match cadence_hooks_core::shell::run_git_bounded(&mut branch_cmd) {
            cadence_hooks_core::shell::GitSpawn::Completed(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        // Repo root for marker — same source as the branch query so the
        // once-per-session suppression actually keys off the same repo.
        let mut root_cmd = Command::new("git");
        root_cmd.args(["-C", &dir_arg, "rev-parse", "--show-toplevel"]);
        let repo_root = match cadence_hooks_core::shell::run_git_bounded(&mut root_cmd) {
            cadence_hooks_core::shell::GitSpawn::Completed(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => return CheckResult::allow(),
        };

        let marker = Self::marker_path(input, &repo_root);
        let already_warned = marker.exists();
        let snoozed = dismiss_main_branch_warn::is_snoozed_now(input, Path::new(&repo_root));
        let allowed = is_main_allowed();

        let result = should_warn(&branch, already_warned, snoozed, allowed);

        if result.outcome == Outcome::Nudge {
            let _ = cadence_hooks_core::markers::write_marker(&marker, "");
            return result;
        }

        // The nudge was suppressed. Attribute it to an active dismissal when that
        // is *why* it went quiet — a default branch, not already warned this
        // session, and snoozed. A permanent `CADENCE_ALLOW_MAIN` allow is the
        // by-design config for main-mode repos (dotfiles, vaults), not a bypass
        // worth a line per edit, so it stays a bare allow.
        if snoozed && is_default_branch(&branch) && !already_warned {
            let meta = dismiss_main_branch_warn::read_meta(input, Path::new(&repo_root));
            return CheckResult::allow_bypassed(BypassProvenance {
                kind: BypassKind::Dismissal,
                mechanism: "dismiss-main-branch-warn".to_string(),
                reason: meta.as_ref().and_then(|m| m.reason.clone()),
                expires_at: meta.as_ref().and_then(|m| m.expires_at),
                armed_by_session: meta.and_then(|m| m.session_id),
            });
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_branch_warns() {
        let result = should_warn("main", false, false, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("main")
        );
    }

    #[test]
    fn master_branch_warns() {
        let result = should_warn("master", false, false, false);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    #[test]
    fn feature_branch_allows() {
        let result = should_warn("feat/new-feature", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn develop_branch_allows() {
        let result = should_warn("develop", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_allows() {
        let result = should_warn("main", true, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn already_warned_master_allows() {
        let result = should_warn("master", true, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_branch_allows() {
        let result = should_warn("", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn is_default_branch_main() {
        assert!(is_default_branch("main"));
    }

    #[test]
    fn is_default_branch_master() {
        assert!(is_default_branch("master"));
    }

    #[test]
    fn is_default_branch_feature() {
        assert!(!is_default_branch("feat/something"));
    }

    #[test]
    fn is_default_branch_not_substring() {
        assert!(!is_default_branch("main-backup"));
        assert!(!is_default_branch("hotfix/master-fix"));
    }

    // --- edge case hardening ---

    #[test]
    fn release_branch_allows() {
        let result = should_warn("release/1.0", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_contains_branch() {
        let result = should_warn("master", false, false, false);
        assert!(
            result
                .message
                .as_deref()
                .expect("nudge should have a message")
                .contains("master")
        );
    }

    // --- Regression: nested-repo branch resolution (issue #26) ---
    // When CWD is an outer repo and the edited file is in a nested inner repo,
    // branch resolution must follow the file path, not CWD. Using `git -C
    // <file_parent>` lets git walk upward to find the nearest .git.

    fn make_edit_input(file_path: Option<&str>) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: file_path.map(Into::into),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        }
    }

    #[test]
    fn git_dir_uses_file_parent_for_nested_path() {
        let input = make_edit_input(Some("/tmp/outer/inner/file.txt"));
        assert_eq!(
            git_dir_for_input(&input),
            PathBuf::from("/tmp/outer/inner"),
            "git -C target should be the directory containing the edited file"
        );
    }

    #[test]
    fn git_dir_falls_back_to_cwd_for_bash() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("git status".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        assert_eq!(
            git_dir_for_input(&input),
            PathBuf::from("."),
            "Bash hooks have no file path; should fall back to CWD"
        );
    }

    #[test]
    fn git_dir_falls_back_for_bare_filename() {
        // Path with no parent (or empty parent) should fall back to CWD
        // rather than passing an empty string to `git -C`.
        let input = make_edit_input(Some("file.txt"));
        assert_eq!(git_dir_for_input(&input), PathBuf::from("."));
    }

    #[test]
    fn git_dir_handles_no_tool_input() {
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(git_dir_for_input(&input), PathBuf::from("."));
    }

    fn input_with_session(sid: &str) -> HookInput {
        HookInput {
            session_id: Some(sid.into()),
            ..Default::default()
        }
    }

    #[test]
    fn marker_path_differs_per_repo() {
        // Two different repo roots should produce distinct marker paths
        // so a snooze in one repo doesn't suppress warnings in another.
        let input = input_with_session("sid");
        let a = WarnMainBranch::marker_path(&input, "/tmp/repo-a");
        let b = WarnMainBranch::marker_path(&input, "/tmp/repo-b");
        assert_ne!(a, b, "marker path must include a repo-specific hash");
    }

    #[test]
    fn marker_path_stable_for_same_repo() {
        // Same repo root and session, called twice, should produce the same
        // marker path so suppression works.
        let input = input_with_session("sid");
        let a = WarnMainBranch::marker_path(&input, "/tmp/repo");
        let b = WarnMainBranch::marker_path(&input, "/tmp/repo");
        assert_eq!(a, b);
    }

    #[test]
    fn marker_path_differs_per_session() {
        // The #133 fix: the marker is keyed on the session id, so two sessions
        // in the same repo each get their own once-per-session nudge.
        let a = WarnMainBranch::marker_path(&input_with_session("sid-a"), "/tmp/repo");
        let b = WarnMainBranch::marker_path(&input_with_session("sid-b"), "/tmp/repo");
        assert_ne!(a, b, "marker must be session-scoped");
    }

    #[test]
    fn main_with_prefix_allows() {
        // "fix/main-page" is not the main branch
        let result = should_warn("fix/main-page", false, false, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- snooze (issue #16) ---

    #[test]
    fn snoozed_main_allows() {
        // Active snooze suppresses the nudge even on a fresh session.
        let result = should_warn("main", false, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn snoozed_master_allows() {
        let result = should_warn("master", false, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn snoozed_takes_precedence_over_already_warned() {
        // Both flags set is still allow — order doesn't matter.
        let result = should_warn("main", true, true, false);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_mentions_dismiss_command() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("dismiss-main-branch-warn"),
            "warn message should hint at the dismiss command: {msg}"
        );
    }

    // --- permanent allow via CADENCE_ALLOW_MAIN ---

    #[test]
    fn allowed_main_allows() {
        let result = should_warn("main", false, false, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn allowed_master_allows() {
        let result = should_warn("master", false, false, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn allowed_overrides_warned_and_snoozed() {
        // Permanent allow trumps every other input. A repo opted out via
        // CADENCE_ALLOW_MAIN should never see the warning, regardless of
        // session state.
        let result = should_warn("main", true, true, true);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_mentions_permanent_allow() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("CADENCE_ALLOW_MAIN"),
            "warn message should mention the permanent opt-out: {msg}"
        );
    }

    #[test]
    fn warn_message_uses_2h_default_duration() {
        let result = should_warn("main", false, false, false);
        let msg = result
            .message
            .as_deref()
            .expect("nudge should have a message");
        assert!(
            msg.contains("--for 2h"),
            "warn message should suggest 2h default snooze: {msg}"
        );
    }

    // --- is_main_allowed_value (pure) ---

    #[test]
    fn allowed_value_unset_is_false() {
        assert!(!is_main_allowed_value(None));
    }

    #[test]
    fn allowed_value_empty_is_false() {
        assert!(!is_main_allowed_value(Some("")));
        assert!(!is_main_allowed_value(Some("   ")));
    }

    #[test]
    fn allowed_value_falsy_strings() {
        assert!(!is_main_allowed_value(Some("0")));
        assert!(!is_main_allowed_value(Some("false")));
        assert!(!is_main_allowed_value(Some("no")));
        assert!(!is_main_allowed_value(Some("off")));
    }

    #[test]
    fn allowed_value_truthy_strings() {
        assert!(is_main_allowed_value(Some("1")));
        assert!(is_main_allowed_value(Some("true")));
        assert!(is_main_allowed_value(Some("yes")));
    }

    #[test]
    fn allowed_value_case_insensitive() {
        assert!(is_main_allowed_value(Some("TRUE")));
        assert!(is_main_allowed_value(Some("True")));
        assert!(is_main_allowed_value(Some("YES")));
    }

    #[test]
    fn allowed_value_trims_whitespace() {
        assert!(is_main_allowed_value(Some("  true  ")));
        assert!(is_main_allowed_value(Some("\t1\n")));
    }

    // --- .claude/ directory carve-out (issues #33, #35) ---

    #[test]
    fn claude_worktree_dir_is_managed() {
        // #33 scenarios 1 & 2: a worktree path is exempt regardless of the
        // branch it sits on (feat-foo or main).
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/.claude/worktrees/feat-foo"
        )));
    }

    #[test]
    fn claude_worktree_nested_repo_is_managed() {
        // #33 scenario 4: a nested-repo worktree layout still matches because
        // the `.claude` component appears anywhere in the path.
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/inner/.claude/worktrees/x/crates/guardrails/src"
        )));
    }

    #[test]
    fn home_claude_memory_dir_is_managed() {
        // #35: the auto-written memory tree under ~/.claude is exempt even
        // though ~/.claude is itself a git repo that can sit on main.
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/.claude/projects/some-proj/memory"
        )));
    }

    #[test]
    fn plain_repo_dir_is_not_managed() {
        // #33 scenario 3: a normal checkout still gets the warning on main.
        assert!(!is_claude_managed_dir(Path::new("/Users/x/repo/src")));
    }

    #[test]
    fn claude_lookalike_dirs_are_not_managed() {
        // Exact-component match: names that merely contain "claude" are not a
        // `.claude` segment and must still warn.
        assert!(!is_claude_managed_dir(Path::new("/Users/x/repo/myclaude")));
        assert!(!is_claude_managed_dir(Path::new(
            "/Users/x/.claude-old/foo"
        )));
    }

    #[test]
    fn relative_dot_dir_is_not_managed() {
        // The Bash fallback resolves to ".", which has no `.claude` component.
        assert!(!is_claude_managed_dir(Path::new(".")));
    }

    #[test]
    fn claude_parentdir_escape_still_warns() {
        // #152: a crafted `..` that escapes the `.claude` segment must not spoof
        // the carve-out — the normalized dir is `.../src`, so it still warns.
        assert!(!is_claude_managed_dir(Path::new(
            "/Users/x/repo/.claude/../src"
        )));
    }

    #[test]
    fn claude_curdir_segment_still_managed() {
        // A `.` segment inside a `.claude` path is a no-op and stays exempt.
        assert!(is_claude_managed_dir(Path::new(
            "/Users/x/repo/.claude/./worktrees/f"
        )));
    }

    // --- docs/plans carve-out (#226) ---
    // Approved plans are copied to docs/plans/ on the default branch by design
    // (cadence's plan-execution rule mandates it), so plan-doc authoring there
    // is not the branch-worthy product change this warning targets.

    #[test]
    fn docs_plans_dir_is_plan_doc() {
        assert!(is_plan_doc_dir(Path::new("/Users/x/repo/docs/plans")));
    }

    #[test]
    fn nested_under_docs_plans_is_plan_doc() {
        // A subdirectory beneath docs/plans/ (e.g. an archive folder) still counts.
        assert!(is_plan_doc_dir(Path::new(
            "/Users/x/repo/docs/plans/2026/q2"
        )));
    }

    #[test]
    fn plan_doc_dir_requires_docs_parent() {
        // A bare `plans/` without an immediate `docs/` parent is not exempt —
        // a product `plans/` dir must still warn on main.
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/plans")));
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/src/plans")));
    }

    #[test]
    fn docs_without_plans_is_not_plan_doc() {
        // Other docs subdirs (adr, architecture) are process/product docs that
        // should still warn on main.
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/docs")));
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/docs/adr")));
    }

    #[test]
    fn plan_doc_lookalike_dirs_are_not_exempt() {
        // Exact-component match: `mydocs/plans` or `docs-old/plans` are not the
        // canonical docs/plans path.
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/mydocs/plans")));
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/docs-old/plans")));
    }

    #[test]
    fn plan_doc_dir_components_must_be_consecutive() {
        // `docs/` then a different dir then `plans/` is not the canonical path.
        assert!(!is_plan_doc_dir(Path::new("/Users/x/repo/docs/foo/plans")));
    }

    #[test]
    fn plan_doc_parentdir_escape_still_warns() {
        // #152: `docs/plans/../../src` normalizes to `.../src`, so a crafted `..`
        // escaping the plan-doc carve-out must still warn for a real product file.
        assert!(!is_plan_doc_dir(Path::new(
            "/Users/x/repo/docs/plans/../../src"
        )));
    }

    #[test]
    fn plan_doc_curdir_segment_still_exempt() {
        // A `.` segment inside docs/plans is a no-op and stays exempt.
        assert!(is_plan_doc_dir(Path::new("/Users/x/repo/docs/plans/./q2")));
    }

    #[test]
    fn plan_doc_leading_parentdir_relative_still_exempt() {
        // A leading `..` with no preceding component to pop leaves `docs/plans`
        // intact, so a relative plan-doc path stays exempt.
        assert!(is_plan_doc_dir(Path::new("../docs/plans")));
    }

    // --- bypass attribution via run() (real repo on main) ---
    //
    // The `should_warn` tests above cover the pure decision; these exercise the
    // full `run()` path where a suppressed nudge is (or isn't) attributed to an
    // active dismissal. A real git repo on `main` is needed because run() shells
    // out for branch + toplevel.

    /// Init a git repo checked out on `main` in a fresh tempdir; return the
    /// tempdir plus the git-resolved (canonical) repo root.
    fn init_repo_on_main() -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(tmp.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(tmp.path().join("f.txt"), "x").unwrap();
        git(&["add", "f.txt"]);
        git(&["commit", "-q", "-m", "init"]);
        let root = cadence_hooks_core::shell::git_command(
            &tmp.path().to_string_lossy(),
            &["rev-parse", "--show-toplevel"],
        )
        .expect("temp repo resolves a toplevel");
        (tmp, root)
    }

    fn edit_input_in(repo: &Path, session: &str) -> HookInput {
        HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(repo.join("src.rs").to_string_lossy().into_owned()),
                new_string: Some("x".into()),
                old_string: Some("y".into()),
                ..Default::default()
            }),
            cwd: Some(repo.to_string_lossy().into_owned()),
            session_id: Some(session.into()),
            ..Default::default()
        }
    }

    /// Write the session-scoped snooze marker + provenance sidecar the guard
    /// reads, keyed on the same `(input, repo_root)` as the reader.
    fn arm_snooze(input: &HookInput, repo_root: &str, reason: Option<&str>) {
        let marker = cadence_hooks_core::markers::session_marker(
            input,
            "main-branch-snooze",
            Some(repo_root),
        );
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        cadence_hooks_core::markers::write_marker(&marker, &format!("{until}\n")).unwrap();
        let sidecar = crate::snooze_meta::sidecar_for(&marker);
        let meta = crate::snooze_meta::SnoozeMeta {
            reason: reason.map(str::to_string),
            session_id: input.session_id().map(str::to_string),
            armed_at: Some(1),
            expires_at: Some(until as i64),
        };
        cadence_hooks_core::markers::write_marker(&sidecar, &meta.to_json()).unwrap();
    }

    #[test]
    fn snooze_suppressed_nudge_attributes_dismissal() {
        let (tmp, root) = init_repo_on_main();
        let input = edit_input_in(tmp.path(), "warn-bypass-a");
        arm_snooze(&input, &root, Some("wrap-up edits on dotfiles"));

        let r = WarnMainBranch.run(&input);
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "active snooze suppresses the nudge"
        );
        let prov = r.bypass.expect("suppressed nudge carries provenance");
        assert_eq!(prov.kind, BypassKind::Dismissal);
        assert_eq!(prov.mechanism, "dismiss-main-branch-warn");
        assert_eq!(prov.reason.as_deref(), Some("wrap-up edits on dotfiles"));
        assert_eq!(prov.armed_by_session.as_deref(), Some("warn-bypass-a"));
    }

    #[test]
    fn snooze_without_sidecar_attributes_dismissal_with_none_reason() {
        // A snooze armed before the sidecar existed still attributes a Dismissal,
        // just with no reason/session (the guard tolerates a missing sidecar).
        let (tmp, root) = init_repo_on_main();
        let input = edit_input_in(tmp.path(), "warn-bypass-legacy");
        let marker =
            cadence_hooks_core::markers::session_marker(&input, "main-branch-snooze", Some(&root));
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        cadence_hooks_core::markers::write_marker(&marker, &format!("{until}\n")).unwrap();

        let r = WarnMainBranch.run(&input);
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("still attributes a dismissal");
        assert_eq!(prov.kind, BypassKind::Dismissal);
        assert_eq!(prov.reason, None, "missing sidecar → no reason");
        assert_eq!(prov.armed_by_session, None);
    }

    #[test]
    fn already_warned_allow_carries_no_bypass() {
        // Once the session has been warned, a later edit is a plain dedup allow —
        // NOT a bypass — even if a snooze is also present. The `!already_warned`
        // guard on attribution must hold.
        let (tmp, root) = init_repo_on_main();
        let input = edit_input_in(tmp.path(), "warn-bypass-warned");
        arm_snooze(&input, &root, Some("some reason"));
        // Pre-plant the once-per-session "warned" marker.
        let warned =
            cadence_hooks_core::markers::session_marker(&input, "main-branch-warned", Some(&root));
        cadence_hooks_core::markers::write_marker(&warned, "").unwrap();

        let r = WarnMainBranch.run(&input);
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            r.bypass.is_none(),
            "an already-warned dedup allow is not a bypass"
        );
    }

    #[test]
    fn feature_branch_edit_carries_no_bypass() {
        // Off a default branch there's nothing to bypass — bare allow.
        let (tmp, _root) = init_repo_on_main();
        Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["checkout", "-q", "-b", "feat/x"])
            .output()
            .unwrap();
        let input = edit_input_in(tmp.path(), "warn-bypass-feat");
        let r = WarnMainBranch.run(&input);
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(r.bypass.is_none(), "feature-branch allow is not a bypass");
    }
}
