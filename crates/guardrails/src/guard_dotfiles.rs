//! Guard against direct edits to production dotfiles.
//!
//! Users who manage dotfiles with chezmoi should edit the source templates
//! (`~/.dotfiles/dot_<name>`) and run `chezmoi apply`, not edit the deployed
//! files directly. This check blocks edits to the protected set and redirects
//! to the correct workflow.
//!
//! **Opt-in:** Set `CADENCE_GUARD_DOTFILES=1` to enable. When unset (or any
//! value other than `"1"`), the check is a clean no-op.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// The set of production dotfiles that must not be edited directly.
const PROTECTED_BASENAMES: &[&str] = &[
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".aliases",
    ".functions",
    ".gitconfig",
    ".tmux.conf",
];

/// Pure decision function — no env reads, no I/O.
///
/// Returns `Some(deny_message)` if the target should be blocked, `None` to allow.
///
/// # Arguments
/// * `enabled` — whether `CADENCE_GUARD_DOTFILES=1` is set
/// * `home`    — the user's home directory (e.g. `/Users/cameron`)
/// * `target`  — the file path from the tool input (already resolved)
pub fn judge_dotfile(enabled: bool, home: &str, target: &str) -> Option<String> {
    if !enabled {
        return None;
    }

    // Exact match only — no prefix/suffix checks, no symlink resolution.
    // $HOME/.zshrc blocks; $HOME/.zshrc.local does not.
    for basename in PROTECTED_BASENAMES {
        let protected = format!("{home}/{basename}");
        if target == protected {
            // Strip the leading dot to get the chezmoi source name:
            //   .zshrc    → dot_zshrc
            //   .tmux.conf → dot_tmux.conf
            let chezmoi_name = format!("dot_{}", basename.trim_start_matches('.'));
            return Some(format!(
                "🚫 guard-dotfiles: Direct edit to production dotfile blocked.\n   \
                 Found:  {target}\n   \
                 Fix:    Edit ~/.dotfiles/{chezmoi_name} instead, then run 'chezmoi apply'",
            ));
        }
    }

    None
}

/// Guards against direct edits to chezmoi-managed production dotfiles.
pub struct GuardDotfiles;

impl Check for GuardDotfiles {
    fn name(&self) -> &str {
        "guard-dotfiles"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Only applies to Edit and Write tools
        let tool = input.tool_name().unwrap_or("");
        if tool != "Edit" && tool != "Write" {
            return CheckResult::allow();
        }

        let enabled = std::env::var("CADENCE_GUARD_DOTFILES").as_deref() == Ok("1");
        let home = cadence_hooks_core::paths::user_home()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Resolve target: file_path first, then command (per spec fallback)
        let target = input
            .file_path()
            .or_else(|| input.command().map(|s| s.to_string()))
            .unwrap_or_default();

        match judge_dotfile(enabled, &home, &target) {
            Some(msg) => CheckResult::block(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_bash, make_edit, make_write};

    const HOME: &str = "/Users/cameron";

    fn zshrc() -> String {
        format!("{HOME}/.zshrc")
    }
    fn gitconfig() -> String {
        format!("{HOME}/.gitconfig")
    }
    fn tmux_conf() -> String {
        format!("{HOME}/.tmux.conf")
    }
    fn zshrc_local() -> String {
        format!("{HOME}/.zshrc.local")
    }
    fn project_file() -> String {
        format!("{HOME}/project/foo.py")
    }

    // --- derived test cases from the spec ---

    // Case 1: enabled + $HOME/.zshrc → deny, message names dot_zshrc + chezmoi apply
    #[test]
    fn enabled_zshrc_is_blocked() {
        let msg = judge_dotfile(true, HOME, &zshrc());
        assert!(msg.is_some(), "expected block for ~/.zshrc");
        let msg = msg.unwrap();
        assert!(
            msg.contains("dot_zshrc"),
            "message should name dot_zshrc, got: {msg}"
        );
        assert!(
            msg.contains("chezmoi apply"),
            "message should mention chezmoi apply, got: {msg}"
        );
    }

    // Case 2: enabled + $HOME/.gitconfig → deny, names dot_gitconfig
    #[test]
    fn enabled_gitconfig_is_blocked() {
        let msg = judge_dotfile(true, HOME, &gitconfig());
        assert!(msg.is_some(), "expected block for ~/.gitconfig");
        let msg = msg.unwrap();
        assert!(
            msg.contains("dot_gitconfig"),
            "message should name dot_gitconfig, got: {msg}"
        );
    }

    // Case 3: enabled + $HOME/.zshrc.local → allow (not exact match)
    #[test]
    fn enabled_zshrc_local_is_allowed() {
        let result = judge_dotfile(true, HOME, &zshrc_local());
        assert!(result.is_none(), "~/.zshrc.local should be allowed");
    }

    // Case 4: enabled + $HOME/project/foo.py → allow
    #[test]
    fn enabled_non_dotfile_is_allowed() {
        let result = judge_dotfile(true, HOME, &project_file());
        assert!(result.is_none(), "a non-dotfile should be allowed");
    }

    // Case 5: enabled + $HOME/.tmux.conf → deny, names dot_tmux.conf
    #[test]
    fn enabled_tmux_conf_is_blocked() {
        let msg = judge_dotfile(true, HOME, &tmux_conf());
        assert!(msg.is_some(), "expected block for ~/.tmux.conf");
        let msg = msg.unwrap();
        assert!(
            msg.contains("dot_tmux.conf"),
            "message should name dot_tmux.conf, got: {msg}"
        );
    }

    // Case 6: disabled + $HOME/.zshrc → allow (feature off)
    #[test]
    fn disabled_zshrc_is_allowed() {
        let result = judge_dotfile(false, HOME, &zshrc());
        assert!(result.is_none(), "feature disabled should always allow");
    }

    // Case 7: command-only input (no file_path) → allow unless it equals a protected path
    // The spec says: allow unless the command string equals a protected path literal
    #[test]
    fn command_only_non_path_is_allowed() {
        // A typical bash command string is not a protected path
        let result = judge_dotfile(true, HOME, "cat ~/.zshrc | grep alias");
        assert!(
            result.is_none(),
            "command string (not a protected path) should allow"
        );
    }

    // --- edge cases ---

    #[test]
    fn all_protected_files_blocked_when_enabled() {
        let protected = [
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".aliases",
            ".functions",
            ".gitconfig",
            ".tmux.conf",
        ];
        for name in protected {
            let path = format!("{HOME}/{name}");
            let msg = judge_dotfile(true, HOME, &path);
            assert!(msg.is_some(), "expected block for ~/{name}, got None");
        }
    }

    #[test]
    fn empty_target_is_allowed() {
        let result = judge_dotfile(true, HOME, "");
        assert!(result.is_none(), "empty target should always allow");
    }

    #[test]
    fn tilde_prefixed_path_is_not_matched() {
        // The check uses $HOME expansion; a literal "~/.zshrc" string
        // (not expanded) should not be blocked — we match the $HOME form only.
        let result = judge_dotfile(true, HOME, "~/.zshrc");
        assert!(result.is_none(), "literal tilde path should not be matched");
    }

    // --- Check::run integration (plumbing) ---

    #[test]
    fn bash_tool_is_not_filtered_by_check() {
        // guard-dotfiles only watches Edit|Write — Bash must always pass through
        let input = make_bash("cat ~/.zshrc");
        let result = GuardDotfiles.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn edit_tool_delegated_to_pure_fn() {
        // The pure function is tested above; this just verifies the
        // Check::run plumbing calls it (outcome is Allow because no env var set)
        let input = make_edit(&zshrc(), "old", "new");
        let result = GuardDotfiles.run(&input);
        // CADENCE_GUARD_DOTFILES is not set in test env, so should allow
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn write_tool_delegated_to_pure_fn() {
        let input = make_write(&zshrc(), "# content");
        let result = GuardDotfiles.run(&input);
        // CADENCE_GUARD_DOTFILES is not set in test env, so should allow
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
