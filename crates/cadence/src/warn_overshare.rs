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
//!
//! The prior retro-path exemption (`docs/blog/*retro*`) was removed in
//! cadence-hooks#329: `cadence:retro` relocated its output out of the repo
//! (vault primary, gitignored fallback), so retro paths no longer have a
//! sanctioned repo destination to exempt.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Bash token sequences that surface about-to-ship content but are NOT
/// external-posting verbs the shared [`EXTERNAL_POST`] gate covers. Only
/// `git push` qualifies — the former `git commit` and four `gh` sequences
/// were strict subsets of the gate and were pruned when it was adopted
/// (#385): a second hand-kept list is exactly the drift this change kills.
///
/// [`EXTERNAL_POST`]: crate::redact_external_content::EXTERNAL_POST
const BASH_TWO_TOKEN_TRIGGERS: &[[&str; 2]] = &[["git", "push"]];

const FIELD_REPORTS_MARKER: &str = "/docs/field-reports/";

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

    match input.normalized_tool_name() {
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

/// True when `command` carries `git push`, or any segment matches the redact
/// engine's [`EXTERNAL_POST`] gate (cadence-hooks#385: overshare's hand-kept
/// six-command list missed `gh pr comment`, `gh pr review`, `gh issue edit`,
/// `gh release/gist/discussion`, and `tea` — every one an external-posting
/// surface the leak scanner already gated). One gate, two consumers: a new
/// posting verb added there is covered here for free.
///
/// Precision caveat, accepted: quote-stripping each segment keeps a QUOTED
/// mention (`echo 'docs: gh pr comment usage'`) from tripping, but an
/// unquoted prose mention (`echo run gh pr comment 5 later`) still nudges —
/// same over-trigger the old token arm had for `echo git commit foo`. This
/// is an advisory nudge; false-fire costs a line of noise, and the extraction
/// step that gives the redact hook full mention-immunity has no meaning here
/// (there is no body to extract — the command shape IS the signal).
fn is_bash_overshare_trigger(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    let push_hit = tokens.windows(2).any(|w| {
        BASH_TWO_TOKEN_TRIGGERS
            .iter()
            .any(|t| w[0] == t[0] && w[1] == t[1])
    });
    if push_hit {
        return true;
    }

    use cadence_hooks_core::shell::{command_segments, strip_quotes};
    command_segments(command)
        .iter()
        .any(|seg| crate::redact_external_content::EXTERNAL_POST.is_match(&strip_quotes(seg)))
}

/// True when `path` is under the Obsidian vault.
///
/// Vault paths are the safe destination for personal context.
fn path_is_exempt(path: &str, vault: Option<&str>) -> bool {
    matches!(vault, Some(v) if !v.is_empty() && path.starts_with(v))
}

fn nudge_text() -> String {
    "Pre-ship audit: scan the outgoing content (commit message, PR/issue body, changed files) \
     for personal overshare — health/neurodivergence, relationships/family, non-technical \
     biography. Keep the technical why/how; anything ambiguous, surface to the user first. \
     Personal context routes to the Obsidian vault ($OBSIDIAN_VAULT), never a public repo. \
     Exempt: vault paths. Silence for this session: CADENCE_SKIP_OVERSHARE_AUDIT=1"
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

    // --- EXTERNAL_POST-gated surfaces (#385): every posting verb the leak
    // scanner gates now nudges here too. ---

    #[test]
    fn external_post_surfaces_nudge() {
        for cmd in [
            "gh pr comment 7 --body text",
            "gh pr review 7 --approve --body lgtm",
            "gh issue edit 9 --body updated",
            "gh release create v1.0 --notes text",
            "gh gist create notes.md --desc d",
            "gh discussion create --title t --body b",
            "gh issue reopen 4 --comment back",
            "tea pr create --title t --description d",
            "tea issue comment 3 hello",
            "cd subdir && gh pr comment 1 --body compound",
        ] {
            assert_eq!(
                run(&make_bash(cmd)).outcome,
                Outcome::Nudge,
                "expected nudge for: {cmd}"
            );
        }
    }

    #[test]
    fn quoted_mention_of_posting_verb_does_not_nudge() {
        // The EXTERNAL_POST arm quote-strips each segment, mirroring the
        // redact gate — a QUOTED mention of a posting command is prose.
        assert_eq!(
            run(&make_bash("echo 'docs: gh pr comment usage'")).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn unquoted_mention_still_nudges_accepted_imprecision() {
        // Pins the documented precision caveat: an UNQUOTED prose mention
        // trips the gate (same over-trigger the old token arm had for
        // `echo git commit foo`). Advisory nudge — accepted cost, and this
        // test is the tripwire if anyone later claims full mention-immunity.
        assert_eq!(
            run(&make_bash("echo run gh pr comment 5 later")).outcome,
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
    fn retrospective_blog_path_allows_via_default_fallthrough() {
        // No longer an exemption (cadence-hooks#329) — this allows because
        // it isn't a field-report path, same as any other non-field-report,
        // non-vault Write/Edit target.
        let result = run(&make_write(
            "/Users/c/proj/docs/blog/2026-06-02-foo-retrospective.md",
            "blog post",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn retro_blog_path_allows_via_default_fallthrough() {
        // No longer an exemption (cadence-hooks#329) — this allows because
        // it isn't a field-report path, same as any other non-field-report,
        // non-vault Write/Edit target.
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

    #[test]
    fn retro_named_path_under_field_reports_marker_nudges() {
        // Highest-signal case: a path that would have matched the (now
        // removed) retro exemption AND the field-reports marker. With the
        // exemption gone this must fall through to the field-report check
        // and nudge, not exempt-allow. (cadence-hooks#329)
        let result = run(&make_write(
            "/Users/c/proj/docs/blog/notes/docs/field-reports/foo-retro.md",
            "report content",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
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
}
