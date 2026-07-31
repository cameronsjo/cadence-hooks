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
    command_segments, command_word, contains_ignoring_ascii_case, fold_verb, heredoc_introducers,
    logical_lines, strip_comments, strip_heredoc_bodies, strip_quotes, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

static GH_REPO_DELETE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?i:gh)\s+repo\s+delete\b").expect("pattern should compile"));

/// The shells this guard recognizes by name — **the single inventory**, shared
/// by [`EXEC_WRAPPER`] and [`SHELL_CONSUMERS`] so the two passes cannot drift.
/// They previously disagreed (`bash|sh|zsh` beside a seven-name list) with
/// nothing explaining why, and the shorter list was the accidental one:
/// `csh <<EOF` and `fish -c` execute a script just as `bash` does.
const SHELLS: [&str; 9] = [
    "bash", "sh", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "fish",
];

/// Builtins that read a script from stdin without being a shell themselves.
/// They belong in [`SHELL_CONSUMERS`] but NOT in [`EXEC_WRAPPER`] — that is the
/// one real asymmetry between the two passes, and it is a fact about the
/// commands: `source` and `.` take a file operand, never `-c`.
const STDIN_SOURCE_BUILTINS: [&str; 2] = ["source", "."];

/// `<shell> -c` in any recognized spelling. Matched against quote-stripped
/// text by the coarse wrapper pass.
static EXEC_WRAPPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"\b(?i:{})\s+-c\b", SHELLS.join("|"))).expect("pattern should compile")
});

/// True when `word` names a command that executes whatever it reads on stdin.
/// A heredoc fed to one of these is the *program*, not data — the distinction
/// [`has_shell_fed_heredoc`] turns on.
fn is_shell_consumer(word: &str) -> bool {
    // Path-qualified and case-folded via the shared primitive, so
    // `/bin/bash` and `BASH` resolve like a bare `bash` (#488).
    let resolved = command_word(word);
    SHELLS.contains(&resolved.as_ref()) || STDIN_SOURCE_BUILTINS.contains(&resolved.as_ref())
}

/// True when `word` is a bare variable expansion (`$SHELL`, `${SHELL}`) — a
/// command word whose value this guard cannot know.
///
/// `$SHELL <<EOF` is a portable idiom, not obfuscation, so an unresolvable name
/// counts as a shell rather than as a non-shell. The direction is fail-CLOSED
/// and the cost is bounded: the arm this feeds also requires the raw text to
/// name `gh repo delete`. A word that merely CONTAINS an expansion
/// (`$HOME/notes.md`) is not one — that is a path operand, and treating it as
/// unknowable would block ordinary `cat <<EOF > $HOME/notes.md` writes.
fn is_opaque_command_word(word: &str) -> bool {
    let inner = match word.strip_prefix("${").and_then(|w| w.strip_suffix('}')) {
        Some(inner) => inner,
        None => match word.strip_prefix('$') {
            Some(inner) => inner,
            None => return false,
        },
    };
    !inner.is_empty()
        && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !inner.starts_with(|c: char| c.is_ascii_digit())
}

/// Matches an API path at EXACTLY owner/repo depth: `repos/<owner>/<repo>`,
/// with an optional leading or trailing slash. Sub-resource paths
/// (`repos/o/r/issues/1`, `repos/o/r/git/refs/heads/x`) deliberately do not
/// match — those DELETEs remove a sub-resource, not the repository itself.
static API_REPO_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/?repos/[^/]+/[^/]+/?$").expect("pattern should compile"));

/// True when a shell command ends inside a single- or double-quoted run **in a
/// position the shell parses as quoting**.
///
/// Heredoc bodies and comments are removed first, because an apostrophe there
/// is ordinary text. Scanning the raw command instead blocked three shapes bash
/// runs cleanly — a `Don't` inside a `<<'EOF'` body, an `it's` inside an
/// expanding body, and a `don't` in a trailing comment — each of which is
/// plausible while documenting a `gh repo delete` procedure
/// (cadence-hooks#543).
///
/// What survives that narrowing is genuinely unbalanced shell syntax. Such a
/// command is not executable as written, so failing closed on it costs nothing.
///
/// Deliberately narrower than tokenization otherwise: it exists only to keep a
/// malformed quote from erasing a destructive command from the conservative
/// fallback below. It does, however, distinguish all three quoting kinds the
/// shell has — see [`QuoteRun`]. Folding `$'…'` into `'…'` is not a harmless
/// simplification: it makes an escaped apostrophe close the run early, so a
/// balanced command reads as unbalanced and the fallback blocks prose the
/// shell runs cleanly.
fn has_unmatched_quote(command: &str) -> bool {
    let command = strip_comments(&strip_heredoc_bodies(command));
    ends_inside_quote(&command)
}

/// Which kind of quoted run the scan is inside.
///
/// Mirrors `core::shell`'s private `Quote`, variant for variant, because the
/// three kinds close on different rules and collapsing any two of them is a
/// boundary the shell does not have. Kept local rather than promoted into
/// `core::shell`: that file is concurrently gaining helpers on a sibling
/// branch, and one shared scan is worth its own change rather than a conflict
/// resolved under time pressure. Consolidating the three quote-tracking
/// implementations in this repo is tracked separately.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteRun {
    /// `'…'` — fully literal; the first `'` closes (POSIX). A backslash inside
    /// is an ordinary character.
    Posix,
    /// `$'…'` — bash ANSI-C; `\` escapes whatever follows, **including `'`**.
    /// Treating this as [`QuoteRun::Posix`] made a well-formed
    /// `$'it\'s dangerous'` read as unbalanced, so the conservative fallback
    /// fired on prose bash runs cleanly.
    AnsiC,
    /// `"…"` — `\` escapes `"` and `\`; other backslashes stay literal.
    Double,
}

/// The raw quote-state scan [`has_unmatched_quote`] runs on its narrowed view.
fn ends_inside_quote(command: &str) -> bool {
    let mut quote: Option<QuoteRun> = None;
    let mut escaped = false;
    // A `'` opens an ANSI-C run only when the shell just read a `$` outside
    // any quoting; anywhere else it opens a POSIX run.
    let mut dollar_pending = false;
    for ch in command.chars() {
        if escaped {
            escaped = false;
            dollar_pending = false;
            continue;
        }
        match quote {
            Some(QuoteRun::Posix) => {
                if ch == '\'' {
                    quote = None;
                }
            }
            Some(QuoteRun::AnsiC) => {
                if ch == '\\' {
                    escaped = true;
                } else if ch == '\'' {
                    quote = None;
                }
            }
            Some(QuoteRun::Double) => {
                if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quote = None;
                }
            }
            None => match ch {
                '\\' => escaped = true,
                '\'' => {
                    quote = Some(if dollar_pending {
                        QuoteRun::AnsiC
                    } else {
                        QuoteRun::Posix
                    });
                }
                '"' => quote = Some(QuoteRun::Double),
                _ => {}
            },
        }
        dollar_pending = ch == '$' && quote.is_none();
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
/// It is a **name scan over the introducing line, not an execution model**: any
/// shell named anywhere on that line counts, because a heredoc can be piped to
/// one (`cat <<EOF | bash`) as readily as fed to one directly. That direction is
/// fail-CLOSED, and the arm it gates also requires the raw text to name
/// `gh repo delete`, so the cost of a miscall is one blocked command naming an
/// irreversible operation.
///
/// **Built on the shared `core::shell` primitives, deliberately.** The first
/// version of this predicate hand-rolled its own line joining, introducer
/// detection and word splitting, and each of the three grew a soft edge that
/// let a shell-fed heredoc through — `bash<<EOF`, `bash <\` ⏎ `<EOF`, and
/// `$SHELL <<EOF` were all missed (cadence-hooks#543). The parsing now comes
/// from the same functions the segmenter uses, so the two cannot disagree.
fn has_shell_fed_heredoc(command: &str) -> bool {
    logical_lines(command)
        .iter()
        .any(|line| line_feeds_a_shell(line))
}

/// True when one logical line both introduces a heredoc and names a shell
/// outside the introducer.
fn line_feeds_a_shell(line: &str) -> bool {
    // A commented-out introducer introduces nothing, and a shell named inside
    // a comment consumes nothing: `cat <<EOF # run under bash` is one `cat`.
    let line = strip_comments(line);
    let introducers = heredoc_introducers(&line);
    if introducers.is_empty() {
        return false;
    }
    // Blank the introducer constructs before reading command words. The
    // delimiter word is a terminator, not a command — `cat <<bash` names no
    // shell — and a command word glued to the operator only separates once the
    // operator is gone (`bash<<EOF`).
    let mut masked: String = line.clone();
    for introducer in introducers {
        masked.replace_range(
            introducer.start..introducer.end,
            &" ".repeat(introducer.end - introducer.start),
        );
    }
    // `strip_quotes` DROPS quoted runs, the same masking Pass 1 and Pass 2 in
    // this file rely on: a shell name that appears only inside quotes is prose
    // or an argument, so `grep 'bash' <<EOF` names no consumer. Splitting on
    // shell metacharacters as well as whitespace is what makes `{ bash; }` and
    // `cat <<EOF | bash` yield the word `bash`.
    //
    // Braces are NOT separators: bash requires a blank after `{` and a
    // terminator before `}`, so `;` and whitespace already cut a group open,
    // while splitting on `{`/`}` would shred `${SHELL}` into `$` and `SHELL`
    // and lose the one shape [`is_opaque_command_word`] exists to catch.
    strip_quotes(&masked)
        .split(|c: char| c.is_whitespace() || ";&|<>()`".contains(c))
        .any(|word| !word.is_empty() && (is_shell_consumer(word) || is_opaque_command_word(word)))
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
        //   * an unmatched quote keeps it from exposing later operators —
        //     measured over a view with comments and heredoc bodies removed,
        //     since an apostrophe in either is literal text in a command bash
        //     runs cleanly (#543); what is left is unbalanced syntax the shell
        //     refuses, so failing closed costs nothing;
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

    /// A bash ANSI-C string escapes its own delimiter, so `$'it\'s'` is
    /// balanced and bash runs it. Scanning it under POSIX single-quote rules
    /// closed the run at the escaped apostrophe, left the real closing quote
    /// opening a second unterminated run, and fired the conservative fallback
    /// on prose — measured Allow on main and Block on this branch before the
    /// scan learned the third quoting kind.
    #[test]
    fn ansi_c_escaped_quote_prose_stays_allowed() {
        let result = GhDangerousGuard.run(&make_bash(
            r"echo $'gh repo delete: it\'s dangerous, don\'t'",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    /// Prose entirely inside an ANSI-C run, with the operation named at the
    /// start rather than mid-string, so the fix is pinned independently of
    /// where the escaped apostrophes fall.
    #[test]
    fn ansi_c_escaped_quote_prose_allows_regardless_of_position() {
        let result = GhDangerousGuard.run(&make_bash(
            r"echo $'talk about gh repo delete here: don\'t'",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    /// An ANSI-C string earlier in the command must not buy an exemption for a
    /// LATER segment that names the operation in bare, unquoted words.
    ///
    /// Worth pinning because this shape reads like a regression and is not one.
    /// It measures Allow on `main` — but only because main's whole-command
    /// quote collapse erased the second segment outright, which is the #509
    /// defect this guard is being fixed for. The Block here is the fix working,
    /// not the ANSI-C scan over-reaching: unquoted `gh repo delete` matches the
    /// per-segment pass on its own, with no quoting involved at all.
    #[test]
    fn ansi_c_string_does_not_exempt_bare_words_in_a_later_segment() {
        let result = GhDangerousGuard.run(&make_bash(
            r"echo $'it\'s fine' && echo gh repo delete discussion",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    /// Control in the dangerous direction: an ANSI-C run must not become a
    /// place to hide a real deletion. A genuinely unbalanced `$'` still fires
    /// the fallback, and an ANSI-C string sitting beside a live `gh repo
    /// delete` must still block.
    #[test]
    fn ansi_c_string_cannot_shelter_a_live_repo_delete() {
        let result = GhDangerousGuard.run(&make_bash(
            r"echo $'it\'s fine' && gh repo delete my-repo --yes",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
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
            // Glued and continuation-spliced spellings of the same DATA
            // heredocs — the fix for the shell-fed cases must not drag these
            // in with them.
            "cat<<EOF\ngh repo delete o/r --yes\nEOF",
            "cat <\\\n<EOF\ngh repo delete o/r --yes\nEOF",
            "wc -l <<EOF\ngh repo delete o/r --yes\nEOF",
            // A redirect target naming a variable is a path operand, not an
            // unresolvable command word.
            "cat <<EOF > $HOME/notes.md\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
    }

    // --- cadence-hooks#543: the three soft edges of the first
    // `has_shell_fed_heredoc`, each measured Block-on-main → Allow-on-branch and
    // each confirmed to invoke `gh repo delete` under real bash with a logging
    // `gh` stub before it was fixed.

    #[test]
    fn shell_name_glued_to_heredoc_introducer_blocked() {
        // A whitespace scan never saw `bash<<EOF` as the word `bash`. Nothing
        // about that spelling is obfuscation — `cat<<EOF` is ordinary shell.
        for cmd in [
            "bash<<EOF\ngh repo delete o/r --yes\nEOF",
            "sh<<EOF\ngh repo delete o/r --yes\nEOF",
            "bash<<-EOF\n\tgh repo delete o/r --yes\nEOF",
            "/bin/bash<<EOF\ngh repo delete o/r --yes\nEOF",
            "{ bash; } <<EOF\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn continuation_spliced_shell_fed_heredoc_blocked() {
        // The shell REMOVES both characters of a backslash-newline. Joining
        // with a space instead read `<` + `<` as `< <` and split a command word
        // in half; `logical_lines` joins the way the shell does.
        for cmd in [
            "bash <\\\n<EOF\ngh repo delete o/r --yes\nEOF",
            "sh <\\\n<EOF\ngh repo delete o/r --yes\nEOF",
            "bash <\\\n<-EOF\n\tgh repo delete o/r --yes\nEOF",
            "bas\\\nh <<EOF\ngh repo delete o/r --yes\nEOF",
            "b\\\nash <<EOF\ngh repo delete o/r --yes\nEOF",
            "s\\\nh <<EOF\ngh repo delete o/r --yes\nEOF",
            // The shape the original comment was written for, which blocked
            // either way — kept so a future join change cannot quietly drop it.
            "bash \\\n<<EOF\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn shell_missing_from_inventory_or_named_by_variable_blocked() {
        // `$SHELL <<EOF` is a portable idiom, and the csh family executes a
        // script exactly as bash does. The inventory omitted both.
        for cmd in [
            "csh <<EOF\ngh repo delete o/r --yes\nEOF",
            "tcsh <<EOF\ngh repo delete o/r --yes\nEOF",
            "/bin/csh <<EOF\ngh repo delete o/r --yes\nEOF",
            "fish <<EOF\ngh repo delete o/r --yes\nEOF",
            "ash <<EOF\ngh repo delete o/r --yes\nEOF",
            "$SHELL <<EOF\ngh repo delete o/r --yes\nEOF",
            "${SHELL} <<EOF\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn bare_dot_operand_is_a_known_false_block() {
        // `.` is the source builtin AND an ordinary path operand, and this
        // predicate reads command words positionally-blind on purpose (a
        // heredoc can be piped to a consumer anywhere on the line). So
        // `docker build -f - .` reads as naming a source builtin. Blocked on
        // main and on this branch alike — recorded so the disposition is
        // visible rather than implied, since the cost is one blocked command
        // that names an irreversible operation in its own text.
        assert_eq!(
            outcome("docker build -f - . <<EOF\ngh repo delete o/r --yes\nEOF"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn heredoc_piped_to_a_shell_blocked() {
        // The consumer need not be the command the heredoc is attached to:
        // `cat` reads the body and the pipe hands it to bash, which runs it.
        assert_eq!(
            outcome("cat <<EOF | bash\ngh repo delete o/r --yes\nEOF"),
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn exec_wrapper_covers_the_same_shell_inventory() {
        // `EXEC_WRAPPER` and `SHELL_CONSUMERS` are now derived from one list.
        // They previously disagreed (`bash|sh|zsh` beside a seven-name array)
        // with nothing explaining why, and these executed unblocked.
        for shell in ["dash", "ksh", "ash", "csh", "tcsh", "fish"] {
            let cmd = format!("{shell} -c 'gh repo delete o/r --yes'");
            assert_eq!(outcome(&cmd), cadence_hooks_core::Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn heredoc_delimiter_word_is_not_a_consumer() {
        // The terminator is a word the shell matches against, never a command.
        // Both spellings write data through `cat`.
        for cmd in [
            "cat <<bash\ngh repo delete o/r --yes\nbash",
            "cat << bash\ngh repo delete o/r --yes\nbash",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn shell_named_only_in_quotes_or_a_comment_is_not_a_consumer() {
        // A shell name that is an argument, a pattern, or comment text consumes
        // nothing — the over-block side of the predicate.
        for cmd in [
            "grep 'bash' <<EOF\ngh repo delete o/r --yes\nEOF",
            "sed 's/bash//' <<EOF\ngh repo delete o/r --yes\nEOF",
            "cat <<EOF # run under bash\ngh repo delete o/r --yes\nEOF",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn apostrophe_a_shell_reads_as_literal_text_does_not_fail_closed() {
        // cadence-hooks#543: the unmatched-quote arm's stated justification —
        // "not executable as written, so failing closed costs nothing" — was
        // false for an apostrophe inside a heredoc body or a comment. Bash runs
        // all three cleanly and deletes nothing, and documenting a
        // `gh repo delete` procedure this way is plausible work in this repo.
        for cmd in [
            "cat > README.md <<'EOF'\nDon't run gh repo delete\nEOF",
            "cat <<EOF\nit's risky: gh repo delete\nEOF",
            "echo ok # don't gh repo delete",
        ] {
            assert_eq!(outcome(cmd), cadence_hooks_core::Outcome::Allow, "{cmd}");
        }
        // The narrowing must not reach the arm's actual target: an apostrophe
        // in COMMAND text is still unbalanced syntax hiding a real delete.
        assert_eq!(
            outcome("echo it's && gh repo delete my-repo --yes"),
            cadence_hooks_core::Outcome::Block
        );
        // Nor the heredoc arm sitting beside it: a shell is reading this body,
        // so the quoted prose inside it is a script line, not documentation.
        assert_eq!(
            outcome("bash <<EOF\necho \"gh repo delete is dangerous\"\nEOF"),
            cadence_hooks_core::Outcome::Block
        );
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
