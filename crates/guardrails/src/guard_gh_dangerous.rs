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

static EXEC_WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?i:bash|sh|zsh)\s+-c\b").expect("pattern should compile"));

/// Command words that read a script from stdin. A heredoc fed to one of these
/// is the *program*, not data — the distinction [`has_shell_fed_heredoc`] turns
/// on.
const SHELL_CONSUMERS: [&str; 7] = ["bash", "sh", "zsh", "dash", "ksh", "source", "."];

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
            // Only the two delimiters above are ever stored, but a guard that
            // panics is a fail-OPEN in a harness that reads exit codes — so
            // this arm returns rather than aborting the check.
            Some(_) => {}
        }
    }
    quote.is_some()
}

/// True when `command` introduces a heredoc whose consumer is a shell — i.e.
/// the body [`command_segments`] discarded is a script that gets executed.
///
/// Heredoc-stripping exists because a body is normally DATA (`cat <<EOF` …
/// `EOF` writes prose to a file and bash never runs it). That premise inverts
/// when a shell reads the body: `bash <<EOF` … `EOF` executes every line. The
/// segmenter cannot tell the two apart, so the per-segment passes below never
/// see the script; this predicate re-arms the conservative fallback for the
/// executable case only.
///
/// Like the rest of this file's fallback machinery, it is a **raw-string scan,
/// not a shell parse**: a shell name on a body line that itself looks like an
/// introducer counts. That direction is fail-CLOSED, and the arm it gates also
/// requires the raw text to name `gh repo delete`, so the cost of a miscall is
/// one blocked command naming an irreversible operation.
fn has_shell_fed_heredoc(command: &str) -> bool {
    // The shell joins backslash-newline continuations before it reads a
    // heredoc introducer, so `bash \` + newline + `<<EOF` is one logical line.
    let joined = command.replace("\\\n", " ");
    joined
        .lines()
        .any(|line| introduces_heredoc(line) && invokes_shell(line))
}

/// True when `line` carries a heredoc introducer (`<<WORD`, `<<-WORD`,
/// `<<'WORD'`) outside quotes. `<<<` is a here-string, not a heredoc, and a
/// `<<` inside quotes is literal text.
fn introduces_heredoc(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '<' && chars.get(i + 1) == Some(&'<') => {
                if chars.get(i + 2) == Some(&'<') {
                    i += 3;
                    continue;
                }
                return true;
            }
            None => {}
        }
        i += 1;
    }
    false
}

/// True when `line` names a shell as a command word. Quoted runs are masked
/// first: a shell name that appears only inside quotes is an argument or
/// prose, not the heredoc's consumer.
fn invokes_shell(line: &str) -> bool {
    let mut masked = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                }
                masked.push(' ');
            }
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                masked.push(' ');
            }
            None => masked.push(ch),
        }
    }
    masked.split_whitespace().any(|word| {
        let base = word.rsplit('/').next().unwrap_or(word);
        SHELL_CONSUMERS.contains(&fold_verb(base).as_ref())
    })
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
        // Coarse wrapper pass, kept ALONGSIDE the per-segment loop rather than
        // replaced by it. `command_segments` expands a wrapper only when it can
        // classify every prefix flag it must peel past, and it deliberately
        // refuses to guess (`shell.rs`, `skip_expansion_prefixes`) — so
        // `sudo -u root bash -c '<delete>'`, `stdbuf -o0 bash -c '…'` and
        // `xargs -I{} bash -c '…'` never reach the loop as segments even though
        // bash executes the delete. That refusal is only safe because this
        // coarser pass catches them anyway: a literal `bash -c` in the
        // quote-stripped text plus `gh repo delete` in the raw text is enough,
        // no peeling required (security review, PR #527). It only ever adds
        // blocks; its one known false positive is
        // `bash -c 'echo hi' '<delete>'`, where the extra argument becomes `$1`
        // and never runs — the accepted price for an irreversible operation.
        let stripped_command = strip_quotes(command);
        if EXEC_WRAPPER.is_match(&stripped_command)
            && let Some(m) = GH_REPO_DELETE.find(command)
        {
            return CheckResult::block(crate::messages::repo_delete_blocked_message(
                m.as_str().trim(),
            ));
        }

        // Conservative fallback for the two ways the segmenter can drop text
        // the shell would still execute:
        //   * an unmatched quote keeps it from exposing later operators — such
        //     a command is not executable as written, so failing closed costs
        //     nothing;
        //   * a heredoc fed to a shell is a script, not the data that
        //     heredoc-stripping exists to discard.
        // Both arms additionally require the raw text to name the exact
        // irreversible operation. Balanced quoted prose and `cat <<EOF` bodies
        // never enter here.
        if (has_unmatched_quote(command) || has_shell_fed_heredoc(command))
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

    // --- #527 security review: the two coverage gaps the per-segment rewrite
    // opened. Every input below was confirmed to invoke `gh repo delete` under
    // real bash with a logging `gh` stub, so these are measurements, not
    // conjecture.

    #[test]
    fn wrapper_behind_unpeelable_prefix_blocked() {
        // `command_segments` refuses to peel past a prefix flag it cannot
        // classify, by design — so none of these reach the per-segment loop as
        // a segment. The coarse `bash -c` pass is what catches them, which is
        // why deleting it was a regression rather than a simplification.
        for cmd in [
            "sudo -u root bash -c 'gh repo delete o/r --yes'",
            "sudo --user=root bash -c 'gh repo delete o/r --yes'",
            "sudo -H -u root bash -c 'gh repo delete o/r --yes'",
            "sudo -u root sh -c 'gh repo delete o/r --yes'",
            "stdbuf -o0 bash -c 'gh repo delete o/r --yes'",
            "nice -n 5 bash -c 'gh repo delete o/r --yes'",
            "echo x | xargs -I{} bash -c 'gh repo delete o/r --yes'",
            "find . -maxdepth 0 -exec bash -c 'gh repo delete o/r --yes' \\;",
            "timeout 5 bash -c 'gh repo delete o/r --yes'",
            "env -i bash -c 'gh repo delete o/r --yes'",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn shell_fed_heredoc_script_blocked() {
        // The segmenter strips heredoc bodies because a body is normally data.
        // When a shell reads the body it is the program, and the stripped text
        // is exactly the delete.
        for cmd in [
            "bash <<EOF\ngh repo delete o/r --yes\nEOF",
            "bash -s <<EOF\ngh repo delete o/r --yes\nEOF",
            "bash -e <<EOF\ngh repo delete o/r --yes\nEOF",
            "bash <<-EOF\n\tgh repo delete o/r --yes\nEOF",
            "bash <<'EOF'\ngh repo delete o/r --yes\nEOF",
            "sh <<EOF\ngh repo delete o/r --yes\nEOF",
            "sh -s <<EOF\ngh repo delete o/r --yes\nEOF",
            "sudo -u root bash <<EOF\ngh repo delete o/r --yes\nEOF",
            ". /dev/stdin <<EOF\ngh repo delete o/r --yes\nEOF",
            "bash -c 'bash <<EOF\ngh repo delete o/r --yes\nEOF'",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn data_heredoc_body_stays_allowed() {
        // The control that keeps the arm above from being a blanket
        // re-inspection of every heredoc: `cat` writes the body out, bash never
        // runs it. This is the case heredoc-stripping exists for.
        for cmd in [
            "cat <<EOF\ngh repo delete o/r --yes\nEOF",
            "cat > notes.md <<'EOF'\nnever gh repo delete anything\nEOF",
            "tee notes.md <<EOF\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn segmenter_only_improvements_stay_allowed() {
        // Prose, comments, and split verbs that main blocked and the
        // per-segment pass correctly releases — they must survive the restored
        // wrapper pass, which is why it is gated on a literal `bash -c`.
        for cmd in [
            "echo hi # gh repo delete o/r --yes",
            "echo \"gh repo delete is dangerous\"",
            "gh repo\ndelete o/r --yes",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn exec_wrapper_extra_argument_is_a_known_false_block() {
        // `bash -c SCRIPT ARG…` binds the extra arguments to `$0`/`$1`, so this
        // one never executes the delete. The coarse wrapper pass blocks it
        // anyway — the false positive main already paid for, kept deliberately
        // rather than traded for the ten real bypasses above. Recorded as a
        // test so the disposition is visible instead of implied.
        assert_eq!(
            outcome("bash -c 'echo hi' 'gh repo delete o/r --yes'"),
            cadence_hooks_core::Outcome::Block
        );
    }
}
