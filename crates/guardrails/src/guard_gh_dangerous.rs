//! Block irreversible `gh` operations.
//!
//! `gh repo delete` is permanently destructive with no undo. This guard
//! blocks it in direct invocations and inside shell exec wrappers (`bash -c`),
//! plus the equivalent REST API form (`gh api -X DELETE repos/<owner>/<repo>`).
//!
//! Note: guard-gh-write judges by *ownership* (is the target repo yours?); this
//! guard enforces *irreversibility* — a repo delete is blocked even for a repo
//! you own, because there is no undo.

use cadence_hooks_core::shell::{
    command_segments, contains_ignoring_ascii_case, fold_verb, strip_quotes, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

static GH_REPO_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?i:gh)\s+repo\s+delete\b").expect("pattern should compile"));

/// Matches an API path at EXACTLY owner/repo depth: `repos/<owner>/<repo>`,
/// with an optional leading or trailing slash. Sub-resource paths
/// (`repos/o/r/issues/1`, `repos/o/r/git/refs/heads/x`) deliberately do not
/// match — those DELETEs remove a sub-resource, not the repository itself.
static API_REPO_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/?repos/[^/]+/[^/]+/?$").expect("pattern should compile"));

/// True when a shell command ends inside a single- or double-quoted run.
///
/// This is deliberately narrower than tokenization: it exists only to keep a
/// malformed quote from erasing a destructive command from the conservative
/// fallback below. Backslashes escape the next character outside single
/// quotes; inside single quotes they are literal, matching shell quote rules.
fn has_unmatched_quote(command: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                }
            }
            Some('"') => {
                if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quote = None;
                }
            }
            None => match ch {
                '\\' => escaped = true,
                '\'' | '"' => quote = Some(ch),
                _ => {}
            },
            _ => unreachable!("quote state is limited to shell delimiters"),
        }
    }
    quote.is_some()
}

/// True when `tokens` carry an HTTP DELETE method flag in any Cobra spelling:
/// the adjacent pair `-X delete` / `--method delete`, or a single token
/// `-x=delete` / `--method=delete` / `-xdelete`. Value comparison is
/// case-insensitive (tokens are lowercased before matching).
fn has_delete_method(tokens: &[String]) -> bool {
    for (i, tok) in tokens.iter().enumerate() {
        let lower = tok.to_ascii_lowercase();
        // Single-token forms: `-X=DELETE`, `--method=DELETE`, `-XDELETE`.
        if lower == "-x=delete" || lower == "--method=delete" || lower == "-xdelete" {
            return true;
        }
        // Adjacent-pair forms: flag token followed by a `delete` value token.
        if (lower == "-x" || lower == "--method")
            && let Some(next) = tokens.get(i + 1)
            && next.eq_ignore_ascii_case("delete")
        {
            return true;
        }
    }
    false
}

/// Blocks `gh repo delete` and other irreversible GitHub CLI operations.
pub struct GhDangerousGuard;

impl Check for GhDangerousGuard {
    fn name(&self) -> &str {
        "guard-gh-dangerous"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Pre-filter on a folded copy, then match on the ORIGINAL text. The
        // fold belongs here and not in the patterns' nouns: `GH` is a spelling
        // the shell runs, `REPO DELETE` is not (cadence-hooks#488). A
        // lowercase-only `contains` here silently defeated the folded patterns
        // below — the fast path rejected the command before they ever ran.
        if !contains_ignoring_ascii_case(command, "gh") {
            return CheckResult::allow();
        }

        // Judge each executable segment, including shell-wrapper bodies,
        // independently. Stripping quotes from the whole command let an
        // unrelated unmatched apostrophe consume every later segment and hide
        // a repo deletion (#509). Per-segment stripping retains the prose
        // exemption without giving one well-formed quoted argument authority
        // over a different segment.
        let segments = command_segments(command);
        for segment in &segments {
            let stripped = strip_quotes(segment);
            if let Some(m) = GH_REPO_DELETE.find(&stripped) {
                return CheckResult::block(crate::messages::repo_delete_blocked_message(
                    m.as_str().trim(),
                ));
            }
        }
        // A malformed unmatched quote can still prevent the segmenter from
        // exposing later operators. Such a command is not executable as
        // written, so fail conservatively when its raw text names the exact
        // irreversible operation. Balanced quoted prose never enters this arm.
        if has_unmatched_quote(command)
            && let Some(m) = GH_REPO_DELETE.find(command)
        {
            return CheckResult::block(crate::messages::repo_delete_blocked_message(
                m.as_str().trim(),
            ));
        }

        // The REST API form `gh api -X DELETE repos/<owner>/<repo>`.
        // The subcommand-form regex above never sees this shape, so tokenize
        // every executable segment (chains and `sh -c` wrappers expanded) and
        // block iff it is a `gh api` DELETE targeting an exact owner/repo path.
        for segment in segments {
            let tokens = tokenize(&segment);
            let Some(first) = tokens.first() else {
                continue;
            };
            // Command word: basename so `/opt/homebrew/bin/gh` still counts,
            // ASCII folded so `GH`/`/opt/homebrew/bin/GH` do too (#488). The
            // `api` subcommand stays case-sensitive — gh rejects `API`.
            let cmd_word = fold_verb(first.rsplit('/').next().unwrap_or(first));
            if cmd_word != "gh" || tokens.get(1).map(String::as_str) != Some("api") {
                continue;
            }
            if has_delete_method(&tokens) && tokens.iter().any(|t| API_REPO_PATH.is_match(t)) {
                return CheckResult::block(crate::messages::repo_delete_blocked_message(
                    segment.trim(),
                ));
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn direct_repo_delete_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_in_exec_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("bash -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn unrelated_unmatched_apostrophe_cannot_hide_repo_delete() {
        let result = GhDangerousGuard.run(&make_bash("echo it's && gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn clean_chain_repo_delete_control_still_blocks() {
        let result = GhDangerousGuard.run(&make_bash("echo its && gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn quoted_repo_delete_prose_stays_allowed() {
        let result = GhDangerousGuard.run(&make_bash("echo \"gh repo delete is dangerous\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn case_folded_verbs_still_blocked() {
        // cadence-hooks#488: a case-insensitive volume runs `GH` as `gh` and
        // `BASH` as `bash`, but both verb gates here are raw-text regexes that
        // matched only the lowercase spelling — a silent Allow on a repo
        // deletion, the most destructive command this guard exists to stop.
        for cmd in [
            "GH repo delete my-repo --yes",
            "Gh repo delete my-repo --yes",
            "BASH -c \"GH repo delete my-repo --yes\"",
        ] {
            assert_eq!(
                GhDangerousGuard.run(&make_bash(cmd)).outcome,
                cadence_hooks_core::Outcome::Block,
                "{cmd}"
            );
        }
        // Only the verb folds: gh rejects a capitalized subcommand, so folding
        // past the verb would match text the shell could never run.
        assert_eq!(
            GhDangerousGuard
                .run(&make_bash("gh REPO DELETE my-repo --yes"))
                .outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn repo_delete_in_quotes_not_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo \"don't gh repo delete anything\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn normal_gh_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh pr list"));
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
        let result = GhDangerousGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn zsh_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("zsh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn sh_wrapper_blocked() {
        let result = GhDangerousGuard.run(&make_bash("sh -c \"gh repo delete my-repo --yes\""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Unhappy path: evasion scenarios ---

    #[test]
    fn repo_delete_in_single_quotes_not_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo 'gh repo delete is dangerous'"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn repo_delete_with_confirm_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete my-repo --confirm"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_full_path_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh repo delete owner/my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn gh_repo_list_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo list"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_create_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo create my-new-repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn gh_repo_view_allowed() {
        let result = GhDangerousGuard.run(&make_bash("gh repo view owner/repo"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn repo_delete_in_chain_blocked() {
        let result = GhDangerousGuard.run(&make_bash("echo done && gh repo delete my-repo --yes"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn no_tool_name_allowed() {
        let input = HookInput {
            tool_name: None,
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("gh repo delete".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = GhDangerousGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- edge case hardening ---

    #[test]
    fn empty_command_allowed() {
        let result = GhDangerousGuard.run(&make_bash(""));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn whitespace_only_allowed() {
        let result = GhDangerousGuard.run(&make_bash("   "));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn word_boundary_hyphenated_allowed() {
        // "gh-repo-delete" is hyphenated, not "gh repo delete"
        let result = GhDangerousGuard.run(&make_bash("gh-repo-delete something"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn exec_wrapper_without_c_flag_still_blocked() {
        // Pass 1 catches "gh repo delete" anywhere in the stripped command,
        // regardless of whether it's inside an exec wrapper
        let result = GhDangerousGuard.run(&make_bash("bash script.sh gh repo delete"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn repo_delete_with_extra_spaces_blocked() {
        let result = GhDangerousGuard.run(&make_bash("gh  repo  delete  my-repo"));
        // Extra spaces between words — regex uses \s+ so this still matches
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- #88: API-form repo delete (gh api -X DELETE repos/owner/repo) ---

    fn outcome(cmd: &str) -> cadence_hooks_core::Outcome {
        GhDangerousGuard.run(&make_bash(cmd)).outcome
    }

    #[test]
    fn api_delete_owned_repo_blocked() {
        // The #88 repro: an API-form delete of a repo you own is still
        // irreversible, so it blocks regardless of ownership.
        assert_eq!(
            outcome("gh api -X DELETE repos/cameronsjo/some-owned-repo"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_method_delete_blocked() {
        assert_eq!(
            outcome("gh api --method DELETE repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_lowercase_value_blocked() {
        assert_eq!(
            outcome("gh api -X delete repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_equals_form_blocked() {
        assert_eq!(
            outcome("gh api -X=DELETE repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_attached_form_blocked() {
        assert_eq!(
            outcome("gh api -XDELETE repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_path_before_method_blocked() {
        assert_eq!(
            outcome("gh api repos/o/r -X DELETE"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_leading_slash_blocked() {
        assert_eq!(
            outcome("gh api -X DELETE /repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_chained_blocked() {
        assert_eq!(
            outcome("echo ok && gh api -X DELETE repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_sh_wrapper_blocked() {
        assert_eq!(
            outcome("sh -c 'gh api -X DELETE repos/o/r'"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn api_delete_full_path_gh_blocked() {
        assert_eq!(
            outcome("/opt/homebrew/bin/gh api -X DELETE repos/o/r"),
            cadence_hooks_core::Outcome::Block
        );
    }

    // --- #88: overmatch traps (these MUST stay allowed) ---

    #[test]
    fn api_delete_subresource_allowed() {
        // Deleting an issue comment is a sub-resource delete, not a repo delete.
        assert_eq!(
            outcome("gh api -X DELETE repos/o/r/issues/comments/1"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn api_delete_deep_ref_allowed() {
        assert_eq!(
            outcome("gh api -X DELETE repos/o/r/git/refs/heads/x"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn api_get_repo_allowed() {
        assert_eq!(
            outcome("gh api repos/o/r"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn api_post_issues_allowed() {
        assert_eq!(
            outcome("gh api -X POST repos/o/r/issues"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn api_delete_quoted_prose_allowed() {
        // The echo segment's command word isn't gh — quoted prose must not block.
        assert_eq!(
            outcome("echo \"gh api -X DELETE repos/o/r\""),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn api_delete_user_starred_allowed() {
        // Not owner/repo depth under repos/ — `user/starred/o/r` is a different path.
        assert_eq!(
            outcome("gh api -X DELETE user/starred/o/r"),
            cadence_hooks_core::Outcome::Allow
        );
    }
}
