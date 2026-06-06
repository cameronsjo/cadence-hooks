//! Nudge to audit about-to-ship content for personal-context overshare.
//!
//! Fires on commit/push/PR/issue Bash commands and on Write/Edit to
//! `docs/field-reports/` paths. The hook does the path triage; the model
//! does the content judgment from the nudge text.
//!
//! Skips:
//! - `CADENCE_SKIP_OVERSHARE_AUDIT=1` — session-scoped bypass for repos
//!   that legitimately hold personal context.
//! - Write/Edit under `$OBSIDIAN_VAULT` — the vault is the safe destination
//!   for personal context, not a public repo.
//! - Write/Edit to retro paths (`docs/blog/*retro*`) — retros are blog
//!   source material and intentionally personal.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Bash token sequences that surface about-to-ship content.
const BASH_TWO_TOKEN_TRIGGERS: &[[&str; 2]] = &[["git", "push"], ["git", "commit"]];

const BASH_THREE_TOKEN_TRIGGERS: &[[&str; 3]] = &[
    ["gh", "pr", "create"],
    ["gh", "pr", "edit"],
    ["gh", "issue", "create"],
    ["gh", "issue", "comment"],
];

const FIELD_REPORTS_MARKER: &str = "/docs/field-reports/";
const BLOG_MARKER: &str = "/docs/blog/";
const RETRO_TOKEN: &str = "retro";

/// Nudges the model to audit about-to-ship content for overshare before
/// commits, pushes, PRs/issues, or field-report writes ship.
pub struct WarnOvershare;

impl Check for WarnOvershare {
    fn name(&self) -> &str {
        "warn-overshare"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let bypass = std::env::var("CADENCE_SKIP_OVERSHARE_AUDIT").ok();
        let vault = std::env::var("OBSIDIAN_VAULT").ok();
        run_with_env(input, bypass.as_deref(), vault.as_deref())
    }
}

/// Core decision logic with env values passed in.
///
/// Split out from `Check::run` so unit tests exercise the decision tree
/// without mutating process env (unsafe in Rust 2024) or serializing tests.
fn run_with_env(input: &HookInput, bypass: Option<&str>, vault: Option<&str>) -> CheckResult {
    if is_bypass_set(bypass) {
        return CheckResult::allow();
    }

    match input.tool_name() {
        Some("Bash") => {
            let Some(command) = input.command() else {
                return CheckResult::allow();
            };
            if is_bash_overshare_trigger(command) {
                CheckResult::nudge(nudge_text())
            } else {
                CheckResult::allow()
            }
        }
        Some("Write" | "Edit" | "MultiEdit") => {
            let Some(path) = input.file_path() else {
                return CheckResult::allow();
            };
            if path_is_exempt(&path, vault) {
                return CheckResult::allow();
            }
            if path.contains(FIELD_REPORTS_MARKER) {
                CheckResult::nudge(nudge_text())
            } else {
                CheckResult::allow()
            }
        }
        _ => CheckResult::allow(),
    }
}

fn is_bypass_set(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

/// True when `command` contains any of the six trigger token sequences.
///
/// Token-based to avoid substring false positives (e.g. a branch name
/// containing the literal `git-push` or quoted `git push` inside an echo).
fn is_bash_overshare_trigger(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    let two_hit = tokens.windows(2).any(|w| {
        BASH_TWO_TOKEN_TRIGGERS
            .iter()
            .any(|t| w[0] == t[0] && w[1] == t[1])
    });
    if two_hit {
        return true;
    }

    tokens.windows(3).any(|w| {
        BASH_THREE_TOKEN_TRIGGERS
            .iter()
            .any(|t| w[0] == t[0] && w[1] == t[1] && w[2] == t[2])
    })
}

/// True when `path` is under the Obsidian vault or matches a retro path.
///
/// Vault paths are the safe destination for personal context; retros
/// (docs/blog/*retro*) feed blog articles and are intentionally personal.
fn path_is_exempt(path: &str, vault: Option<&str>) -> bool {
    if let Some(v) = vault
        && !v.is_empty()
        && path.starts_with(v)
    {
        return true;
    }
    is_retro_path(path)
}

fn is_retro_path(path: &str) -> bool {
    if !path.contains(BLOG_MARKER) {
        return false;
    }
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename.contains(RETRO_TOKEN)
}

fn nudge_text() -> String {
    "Before this commit/push/PR/issue ships, audit the about-to-ship content \
     (commit message, PR/issue body, changed files) for overshare:\n\n  \
     - disabilities, neurodivergence, health\n  \
     - relationships, family, personal life\n  \
     - non-technical biographical detail\n\n\
     Keep the technical why/when/how. If anything is ambiguous, surface it \
     to the user before continuing.\n\n\
     If personal context is needed, route it to the Obsidian vault \
     ($OBSIDIAN_VAULT) instead of a public repo.\n\n\
     Exempt from audit: retros (docs/blog/*retrospective*) and vault paths.\n\n\
     Silence for this session: CADENCE_SKIP_OVERSHARE_AUDIT=1"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::{
        HookInput, Outcome,
        test_builders::{make_bash, make_edit, make_write},
    };

    fn run(input: &HookInput) -> CheckResult {
        run_with_env(input, None, None)
    }

    fn run_bypassed(input: &HookInput) -> CheckResult {
        run_with_env(input, Some("1"), None)
    }

    fn run_with_vault(input: &HookInput, vault: &str) -> CheckResult {
        run_with_env(input, None, Some(vault))
    }

    // --- Guard clauses ---

    #[test]
    fn unmatched_tool_allows() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            ..Default::default()
        };
        assert_eq!(run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn no_tool_name_allows() {
        let input = HookInput::default();
        assert_eq!(run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn bash_without_command_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        assert_eq!(run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn write_without_path_allows() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            ..Default::default()
        };
        assert_eq!(run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_bash_command_allows() {
        assert_eq!(run(&make_bash("ls -la")).outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_write_path_allows() {
        let result = run(&make_write("src/main.rs", "fn main() {}"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- Bash happy path: each trigger fires ---

    #[test]
    fn git_push_nudges() {
        let result = run(&make_bash("git push origin main"));
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap_or_default().contains("overshare"));
    }

    #[test]
    fn git_commit_nudges() {
        let result = run(&make_bash("git commit -m 'add feature'"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn gh_pr_create_nudges() {
        assert_eq!(
            run(&make_bash("gh pr create --title test")).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn gh_pr_edit_nudges() {
        assert_eq!(
            run(&make_bash("gh pr edit 42 --body new")).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn gh_issue_create_nudges() {
        assert_eq!(
            run(&make_bash("gh issue create --title test")).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn gh_issue_comment_nudges() {
        assert_eq!(
            run(&make_bash("gh issue comment 1 --body hi")).outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn bypass_silences_bash_trigger() {
        assert_eq!(
            run_bypassed(&make_bash("git push origin main")).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn bypass_only_when_value_is_one() {
        // Only literal "1" bypasses — any other value still nudges.
        let result = run_with_env(&make_bash("git push origin main"), Some("true"), None);
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- Write/Edit happy path ---

    #[test]
    fn field_report_write_nudges() {
        let result = run(&make_write(
            "/Users/c/proj/docs/field-reports/foo.md",
            "report content",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn field_report_edit_nudges() {
        let result = run(&make_edit(
            "/Users/c/proj/docs/field-reports/foo.md",
            "old",
            "new",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn bypass_silences_field_report_write() {
        let result = run_bypassed(&make_write(
            "/Users/c/proj/docs/field-reports/foo.md",
            "report",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn vault_path_skips_audit() {
        let result = run_with_vault(
            &make_write("/Users/c/vault/docs/field-reports/foo.md", "report"),
            "/Users/c/vault",
        );
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_vault_env_does_not_skip() {
        // Empty OBSIDIAN_VAULT would match every path with starts_with("");
        // we explicitly guard against that.
        let result = run_with_vault(
            &make_write("/Users/c/proj/docs/field-reports/foo.md", "report"),
            "",
        );
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn retrospective_blog_path_skips_audit() {
        let result = run(&make_write(
            "/Users/c/proj/docs/blog/2026-06-02-foo-retrospective.md",
            "blog post",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn retro_blog_path_skips_audit() {
        let result = run(&make_write(
            "/Users/c/proj/docs/blog/2026-06-05-foo-retro.md",
            "blog post",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn non_retro_blog_path_allows() {
        // A blog post NOT a retro doesn't match the field-report trigger
        // either, so it allows.
        let result = run(&make_write(
            "/Users/c/proj/docs/blog/2026-06-01-announcement.md",
            "blog post",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- Edge cases ---

    #[test]
    fn quoted_git_push_in_echo_allowed() {
        // split_whitespace on `echo 'git push'` yields tokens including the
        // quote characters, so the literal tokens "git" and "push" don't
        // appear adjacent — the window check correctly returns false.
        let result = run(&make_bash("echo 'git push' >> notes.txt"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn branch_name_with_substring_allowed() {
        let result = run(&make_bash("git checkout feature/git-push-experiments"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        assert_eq!(run(&make_bash("gh pr view 42")).outcome, Outcome::Allow);
    }

    #[test]
    fn gh_pr_list_allowed() {
        assert_eq!(run(&make_bash("gh pr list")).outcome, Outcome::Allow);
    }

    #[test]
    fn gh_issue_view_allowed() {
        assert_eq!(run(&make_bash("gh issue view 1")).outcome, Outcome::Allow);
    }

    #[test]
    fn git_status_allowed() {
        assert_eq!(run(&make_bash("git status")).outcome, Outcome::Allow);
    }

    #[test]
    fn compound_command_with_git_commit_nudges() {
        // `cd foo && git commit ...` should still trigger.
        let result = run(&make_bash("cd foo && git commit -m bar"));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- Helpers ---

    #[test]
    fn is_retro_path_matches_retrospective() {
        assert!(is_retro_path(
            "/a/docs/blog/2026-01-01-foo-retrospective.md"
        ));
    }

    #[test]
    fn is_retro_path_matches_retro() {
        assert!(is_retro_path("/a/docs/blog/2026-01-01-retro.md"));
    }

    #[test]
    fn is_retro_path_requires_blog_dir() {
        assert!(!is_retro_path("/a/docs/notes/2026-01-01-retro.md"));
    }

    #[test]
    fn is_retro_path_requires_token_in_filename() {
        assert!(!is_retro_path("/a/docs/blog/2026-01-01-announcement.md"));
    }
}
