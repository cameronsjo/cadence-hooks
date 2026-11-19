//! Nudge to audit about-to-ship content for personal-context overshare.
//!
//! Fires on push/PR/issue/post Bash commands and on Write/Edit to
//! `docs/field-reports/` paths. The hook does the path triage; the model
//! does the content judgment from the nudge text.
//!
//! A `git commit` alone never fires (cadence-hooks#1636): a commit leaves the
//! machine only when it is pushed, and the push reminds. A command that holds a
//! commit and also a push or a post still fires, for the push or the post. One
//! exception remains: the word-pair arm of the push trigger reads the two words
//! `git push` side by side anywhere in the command, so a commit message that
//! spells them fires, as it did before.
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

use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput, Outcome};

const FIELD_REPORTS_MARKER: &str = "/docs/field-reports/";

/// Nudges the model to audit about-to-ship content for overshare before
/// pushes, posts (PRs, issues, comments, releases), or field-report writes ship.
pub struct WarnOvershare;

impl Check for WarnOvershare {
    fn name(&self) -> &str {
        "warn-overshare"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let bypass = std::env::var(BYPASS_ENV).ok();
        let vault = std::env::var("OBSIDIAN_VAULT").ok();
        run_with_env(input, bypass.as_deref(), vault.as_deref())
    }
}

/// Core decision logic with env values passed in.
///
/// Split out from `Check::run` so unit tests exercise the decision tree
/// without mutating process env (unsafe in Rust 2024) or serializing tests.
fn run_with_env(input: &HookInput, bypass: Option<&str>, vault: Option<&str>) -> CheckResult {
    let result = assess(input, vault);
    // The bypass only counts as ridden when the nudge would have fired
    // (cadence-hooks#223): an unrelated tool call under a standing
    // `CADENCE_SKIP_OVERSHARE_AUDIT=1` is not a bypass event.
    if is_bypass_set(bypass) {
        return if result.outcome == Outcome::Allow {
            CheckResult::allow()
        } else {
            CheckResult::allow_bypassed(BypassProvenance::env_switch(BYPASS_ENV))
        };
    }
    result
}

const BYPASS_ENV: &str = "CADENCE_SKIP_OVERSHARE_AUDIT";

/// The decision with no bypass consulted.
fn assess(input: &HookInput, vault: Option<&str>) -> CheckResult {
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

/// The characters trimmed from both ends of a word before the word-pair arm
/// compares it: a quote, a backtick, a parenthesis and a semicolon. They are
/// what touches `git` or `push` when the pair sits inside a quoted remote
/// command (`ssh host 'git push'`), a group or a statement (`(git push)`,
/// `git push;`). Nothing else is trimmed, so `git push-hook`, `git pushd` and
/// `--push` stay different words.
const WORD_EDGE_PUNCTUATION: &[char] = &['\'', '"', '`', '(', ')', ';'];

/// The word-pair arm of the push trigger: the two words `git` and `push` stand
/// side by side in the whitespace-split command, ignoring a quote, backtick,
/// parenthesis or semicolon touching either of them. It reads a push wherever
/// the words appear: in a quoted remote command, behind a runner the parsed
/// reader does not know (`ssh host git push`, `docker exec c git push`,
/// `parallel git push ::: a b`), in a heredoc body. It reads nothing that
/// keeps a git global option between the words, or never spells them (a make
/// target, a script file). The price is a reminder on text that is not a push:
/// an `echo git push`, a quoted `'git push'`, a commit message that spells the
/// pair.
fn carries_git_push_word_pair(command: &str) -> bool {
    let words: Vec<&str> = command
        .split_whitespace()
        .map(|word| word.trim_matches(WORD_EDGE_PUNCTUATION))
        .collect();
    words
        .windows(2)
        .any(|pair| pair[0] == "git" && pair[1] == "push")
}

/// True when `command` carries a push, or any segment matches the redact
/// engine's posting gate minus `git commit`,
/// [`is_external_post_beyond_commit`].
///
/// The push has two arms, and both stay (cadence-hooks#1636). The word pair
/// ([`carries_git_push_word_pair`]) is `main`'s match, widened to ignore a
/// quote, backtick, parenthesis or semicolon touching a word, so a push that
/// reminded on `main` still reminds, and so does one inside a quoted remote
/// command. The parsed reader (`git_push_segments`, the one the push guards
/// use, run on each segment `command_segments` yields) adds what the word pair
/// cannot see: a git global option between the words (`git -C dir push`,
/// `git -c k=v push`), a push fused to `|` or `&&` (`git push|cat`), and one
/// inside a command substitution (`$(git push)`). The two overlap on the rest
/// (`git push;`, a subshell, a `sh -c` script, an `eval`). With the commit
/// trigger gone nothing else catches a push, so a missed push is a missed
/// reminder. The shared reader itself is not widened: it serves blocking
/// guards, and this nudge must not change them.
///
/// The post arm is the redact engine's gate (cadence-hooks#385: overshare's
/// hand-kept six-command list missed `gh pr comment`, `gh pr review`,
/// `gh issue edit`, `gh release/gist/discussion` and `tea`, every one an
/// external-posting surface the leak scanner already gated). One gate, two
/// consumers: a new posting verb added there is covered here for free. The
/// commit arm is the one thing left out: a commit that is never pushed or
/// posted publishes nothing, and the push or post reminds.
///
/// [`is_external_post_beyond_commit`]: crate::redact_external_content::is_external_post_beyond_commit
///
/// Precision caveat, accepted: quote-stripping each segment keeps a QUOTED
/// mention (`echo 'docs: gh pr comment usage'`) from tripping, but an unquoted
/// prose mention (`echo run gh pr comment 5 later`) still nudges. This is an
/// advisory nudge; a false fire costs a line of noise, and the extraction step
/// that gives the redact hook full mention-immunity has no meaning here (there
/// is no body to extract; the command shape IS the signal).
fn is_bash_overshare_trigger(command: &str) -> bool {
    use cadence_hooks_core::shell::command_segments;

    if carries_git_push_word_pair(command) {
        return true;
    }

    let segments = command_segments(command);
    carries_parsed_git_push(&segments)
        || segments.iter().any(|seg| {
            crate::redact_external_content::is_external_post_beyond_commit(seg)
                && !crate::redact_external_content::api_posts_no_prose(seg)
        })
}

/// The parsed arm of the push trigger: the shared push reader finds a `git`
/// invocation whose subcommand is `push` in any of the segments
/// `command_segments` yields (so inside `sh -c`, `eval` and substitutions too).
fn carries_parsed_git_push(segments: &[String]) -> bool {
    use cadence_hooks_core::shell::git_push_segments;

    segments
        .iter()
        .any(|seg| !git_push_segments(seg).is_empty())
}

/// True when `path` is under the Obsidian vault.
///
/// Vault paths are the safe destination for personal context.
fn path_is_exempt(path: &str, vault: Option<&str>) -> bool {
    matches!(vault, Some(v) if !v.is_empty() && path.starts_with(v))
}

fn nudge_text() -> String {
    "Pre-ship audit: check what is leaving (message, body, files) for personal overshare: \
     health, relationships, non-technical biography. Keep the technical why; ask the user if \
     unsure. Personal context goes to the Obsidian vault, not a repo. Skip this session: \
     CADENCE_SKIP_OVERSHARE_AUDIT=1"
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

    #[test]
    fn bypass_records_provenance_only_when_the_nudge_would_have_fired() {
        let fired = run_bypassed(&make_bash("git push origin main"));
        assert_eq!(fired.outcome, Outcome::Allow);
        let prov = fired.bypass.expect("a ridden bypass records provenance");
        assert_eq!(prov.mechanism, "CADENCE_SKIP_OVERSHARE_AUDIT");
        assert_eq!(prov.kind, cadence_hooks_core::BypassKind::EnvSwitch);
        assert!(run_bypassed(&make_bash("ls")).bypass.is_none());
        assert!(run(&make_bash("git push origin main")).bypass.is_none());
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
    fn git_commit_alone_is_silent() {
        // Was `git_commit_nudges`: a commit stays on the machine until a push
        // (cadence-hooks#1636), and the push reminds.
        let result = run(&make_bash("git commit -m 'add feature'"));
        assert_eq!(result.outcome, Outcome::Allow);
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
    fn gh_api_writes_repo_edits_and_merges_nudge_reads_do_not() {
        // The identity-tier widening took the shared gate to `gh api` writes that
        // carry text, `gh repo create/edit` and `gh pr merge`; the nudge
        // follows it, and a read stays silent.
        let cases: &[(&str, Outcome)] = &[
            ("gh api repos/o/r/issues -f body=x", Outcome::Nudge),
            (
                "gh api -X PATCH repos/o/r/pulls/2 -f title=x",
                Outcome::Nudge,
            ),
            ("gh api graphql -f query='mutation { x }'", Outcome::Nudge),
            ("gh repo create o/r -d text --public", Outcome::Nudge),
            ("gh pr merge 3 --subject s", Outcome::Nudge),
            ("gh api repos/o/r", Outcome::Allow),
            // Render-only and state-only requests post no prose
            // (cadence-hooks#1172); a prose field, wherever it sits, does.
            ("gh api /markdown -f text=x", Outcome::Allow),
            ("gh api markdown -f text=x -f mode=gfm", Outcome::Allow),
            ("gh api /markdown/raw -f text=x", Outcome::Allow),
            (
                "gh api -X PATCH repos/o/r/issues/2 -f state=closed",
                Outcome::Allow,
            ),
            (
                "gh api -X PATCH repos/o/r/pulls/2 -f state=closed -f base=main",
                Outcome::Allow,
            ),
            (
                "gh api -X PUT repos/o/r/issues/2/labels -f 'labels[]=bug'",
                Outcome::Allow,
            ),
            (
                "gh api -X PATCH repos/o/r/issues/2 -f state=closed -f body=x",
                Outcome::Nudge,
            ),
            (
                "gh api repos/o/r/issues/2/comments -f body=x",
                Outcome::Nudge,
            ),
            (
                "gh api -X PATCH repos/o/r/pulls/2 -f state=closed -F body=@f.md",
                Outcome::Nudge,
            ),
            (
                "gh api -X PATCH repos/o/r/gists/1 -f description=x",
                Outcome::Nudge,
            ),
            ("gh api -X POST repos/o/r/issues -f title=x", Outcome::Nudge),
            (
                "gh api -X PUT repos/o/r/contents/f.md -f message=x -f content=Zm9v",
                Outcome::Nudge,
            ),
            (
                "gh api -X PUT 'repos/o/r/contents/f.md' -f 'commit[message]=x'",
                Outcome::Nudge,
            ),
            (
                "gh api -X PATCH 'repos/o/r/issues/2?title=x'",
                Outcome::Nudge,
            ),
            ("gh api repos/o/r/issues --input req.json", Outcome::Nudge),
            ("gh api -X POST markdown/other -f text=x", Outcome::Nudge),
            (
                "gh api -X POST repos/o/r/markdown -f text=x",
                Outcome::Nudge,
            ),
            (
                "gh api -X PATCH repos/o/r/issues/2 -f state=closed; gh pr create -t x",
                Outcome::Nudge,
            ),
            (
                "gh api -X POST graphql -f query='mutation { x }'",
                Outcome::Nudge,
            ),
            ("gh api graphql -f query='query { x }'", Outcome::Allow),
        ];
        for (cmd, want) in cases {
            assert_eq!(run(&make_bash(cmd)).outcome, *want, "{cmd}");
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
    fn quoted_git_push_in_echo_now_reminds_accepted_imprecision() {
        // Was `quoted_git_push_in_echo_allowed`. The word-pair arm ignores a
        // quote touching either word, so that a quoted remote command
        // (`ssh host 'git push'`) is read as a push; the same trim makes the
        // quoted text `echo 'git push'` read as one too. The parsed reader
        // alone would stay silent here (the quoted text is one argument of
        // `echo`). An advisory reminder on text that is not a push is the
        // accepted price of reading the quoted remote command.
        let result = run(&make_bash("echo 'git push' >> notes.txt"));
        assert_eq!(result.outcome, Outcome::Nudge);
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
    fn compound_command_with_git_commit_alone_is_silent() {
        // Was `compound_command_with_git_commit_nudges`: `cd foo && git commit`
        // holds no push and no post (cadence-hooks#1636).
        let result = run(&make_bash("cd foo && git commit -m bar"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- A commit never reminds; the push or post in the same command does
    // (cadence-hooks#1636) ---

    #[test]
    fn a_commit_only_command_is_silent_unless_its_text_spells_git_push() {
        for cmd in [
            "git commit",
            "git commit -m x",
            "git commit -m 'add feature'",
            "git commit -m \"two words\"",
            "git commit -F msg.txt -- a.rs b.rs",
            "git commit --amend --no-edit",
            "git commit -am 'wip'",
            "cd other && git commit -m x",
            "cd other; git commit -m x",
            "git add -A && git commit -m x",
            "git add a.rs && git commit -m x && git status",
            "git -C other commit -m x",
            "git -c user.name=x commit -m x",
            "git --git-dir=other/.git commit -m x",
            "git --work-tree=other commit -m x",
            "git commit -m \"$(cat msg.txt)\"",
            "git commit -m \"$(printf '%s' x)\"",
            "git commit -m \"`cat msg.txt`\"",
            "git commit -m \"a \\\"b\\\"\"",
            "git commit -F - <<'EOF'\nmsg\nEOF",
            "git commit -m \"$(cat <<'EOF'\nsubject\n\nbody\nEOF\n)\"",
            "git commit -m x > out.txt",
            "git commit -m x # note",
            "git commit -m x | tee out.txt",
            "git commit -m x || true",
            "git commit -m x; git status",
            "git commit -m x &",
            "git commit -m $MSG",
            "FOO=1 git commit -m x",
            "env FOO=1 git commit -m x",
            "command git commit -m x",
            "(git commit -m x)",
            "git \"commit\" -m x",
            // `push` as an argument of a commit: silent here, though `main`
            // reminded them through its commit trigger.
            "git commit -m push",
            "git commit -m 'push'",
        ] {
            assert_eq!(run(&make_bash(cmd)).outcome, Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn text_that_spells_git_push_still_reminds_accepted_imprecision() {
        // The word-pair arm is `main`'s match, kept beside the parsed reader
        // (cadence-hooks#1636), so the two words `git push` side by side read as
        // a push wherever they sit, as on `main`: in a commit message, after an
        // `echo`, in a comment. The only way a commit-only command can still
        // fire; a tripwire if anyone later claims the commit exemption is
        // absolute or removes the over-trigger without meaning to.
        for cmd in [
            "git commit -m \"fix: git push hangs on a big pack\"",
            "git commit -m 'fix: git push hangs on a big pack'",
            "git commit -m \"$(cat <<'EOF'\nfix: git push hangs\n\nbody\nEOF\n)\"",
            "echo git push",
            "echo run git push later",
            "git commit -m x # git push",
            // A quote touching a word is trimmed, so quoted text reads as a push.
            "git commit -m \"git push\"",
            "echo 'git push'",
            "echo \"git push\" >> notes.txt",
            "grep -rn 'git push' docs",
            "bash -c 'echo \"git push\"'",
        ] {
            assert_eq!(run(&make_bash(cmd)).outcome, Outcome::Nudge, "{cmd}");
        }
        // Control: a message that does not spell the pair stays silent.
        assert_eq!(
            run(&make_bash(
                "git commit -m \"fix: pushing hangs on a big pack\""
            ))
            .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn each_arm_of_the_push_trigger_carries_pushes_the_other_misses() {
        use cadence_hooks_core::shell::command_segments;
        let parsed = |cmd: &str| carries_parsed_git_push(&command_segments(cmd));
        // Only the parsed reader sees these: a git global option sits between
        // the two words, or `push` is fused to something the trim leaves alone.
        for cmd in [
            "git -C dir push",
            "git -c k=v push",
            "git --no-pager push",
            "git push|cat",
            "git push&&true",
            "echo $(git push)",
        ] {
            assert!(parsed(cmd), "parsed arm: {cmd}");
            assert!(!carries_git_push_word_pair(cmd), "word pair: {cmd}");
        }
        // Only the word pair sees these: the parsed reader does not know the
        // runner, the quoted remote command or the heredoc body.
        for cmd in [
            "time -p git push",
            "ssh host git push",
            "ssh host 'cd /srv/r && git push origin main'",
            "docker exec c git push",
            "parallel git push ::: a b",
            "bash <<'EOF'\ngit push\nEOF",
            "echo git push",
            "ssh host 'git push'",
            "ssh host \"git push origin main\"",
            "ssh host '(cd /srv/r && git push)'",
            "ssh host 'git push; git status'",
            "ruby -e 'system \"git push\"'",
            "echo 'git push'",
        ] {
            assert!(carries_git_push_word_pair(cmd), "word pair: {cmd}");
            assert!(!parsed(cmd), "parsed arm: {cmd}");
        }
    }

    #[test]
    fn the_parsed_reader_still_reads_the_pushes_both_arms_share() {
        use cadence_hooks_core::shell::command_segments;
        // The word pair reads these too, so the combined tests would pass if the
        // parsed reader regressed on them; pin the reader on its own.
        for cmd in [
            "git push;",
            "(git push)",
            "{ git push; }",
            "(cd x && git commit -m y && git push)",
            "if true; then git push; fi",
            "bash -c 'git push'",
            "eval 'git push'",
            "echo `git push`",
        ] {
            assert!(
                carries_parsed_git_push(&command_segments(cmd)),
                "parsed arm: {cmd}"
            );
        }
    }

    #[test]
    fn the_word_pair_trims_only_quotes_backticks_parentheses_and_semicolons() {
        // Touching punctuation off the list keeps a word a different word.
        for cmd in [
            "git push-hook",
            "git pushd",
            "git stash push",
            "git remote set-url --push origin u",
            "git push|cat",
            "git push&&true",
            "git push,",
            "git -C d push",
        ] {
            assert!(!carries_git_push_word_pair(cmd), "must not match: {cmd}");
        }
        for cmd in [
            "git push",
            "'git push'",
            "\"git push\"",
            "`git push`",
            "(git push)",
            "git push;",
            "('git push';)",
        ] {
            assert!(carries_git_push_word_pair(cmd), "must match: {cmd}");
        }
    }

    /// Pushes the hook knowingly does not recognise: the documented boundary of
    /// the word-pair arm. Each keeps a git global option between `git` and
    /// `push` behind a runner the parsed reader does not know, glue the first
    /// word to a statement inside a quote (`'cd r;git push'`), or never spell
    /// the two words (a make target, a script file). `main` reminded none of
    /// them on its own, only through a commit in the same command; with the
    /// commit trigger gone they are silent, alone and after a commit.
    const NOT_RECOGNISED_PUSHES: &[&str] = &[
        "docker exec c git -C d push",
        "ssh host git -C d push",
        "time -p git -C d push",
        "parallel git -C {} push ::: a b",
        "bash <<'EOF'\ngit -C d push\nEOF",
        "make push",
        "ssh host 'cd r;git push'",
    ];

    #[test]
    fn a_push_the_hook_knowingly_does_not_recognise_stays_silent() {
        for cmd in NOT_RECOGNISED_PUSHES {
            assert_eq!(run(&make_bash(cmd)).outcome, Outcome::Allow, "alone: {cmd}");
            let with_commit = format!("git commit -m x && {cmd}");
            assert_eq!(
                run(&make_bash(&with_commit)).outcome,
                Outcome::Allow,
                "after a commit: {with_commit}"
            );
        }
    }

    /// Every spelling of a push the hook must read. The parsed reader's: git's
    /// global options between `git` and `push`, `push` ending at a separator or
    /// a `)`, a push inside a subshell, a group, a `sh -c` script, an `eval` or a
    /// substitution, and the runner prefixes it peels. The word pair's, which
    /// `main` matched and the parsed reader does not read: a runner it does not
    /// know, a quoted remote command, a heredoc body.
    const PUSH_FORMS: &[&str] = &[
        "git push",
        "git push origin main",
        "git push --force-with-lease origin feat/x",
        "git -C dir push",
        "git -C dir push origin main",
        "git -c k=v push",
        "git -c color.ui=false push origin main",
        "git --git-dir=x push",
        "git --git-dir x push",
        "git --work-tree=x push",
        "git --no-pager push",
        "git --no-pager -C dir push origin main",
        "git\tpush origin main",
        "git push;",
        "git push; git status",
        "(git push)",
        "git push&&true",
        "git push && git status",
        "git push|cat",
        "git push || true",
        "git push\ngit status",
        "git push &",
        "(cd x && git commit -m y && git push)",
        "{ git push; }",
        "{ cd x && git push; }",
        "cd sub && git push",
        "sudo git push",
        "env FOO=1 git push",
        "command git push",
        "time git push",
        "if true; then git push; fi",
        "for d in a b; do git -C $d push; done",
        "git commit -m x&&git push",
        "bash -c 'git push'",
        "bash -c 'cd repo && git push origin main'",
        "sh -c \"git -C d push\"",
        "bash -lc 'cd ~/repo && git push origin main'",
        "eval 'git push'",
        "echo $(git push)",
        "echo `git push`",
        "time -p git push",
        "ssh host git push",
        "ssh host 'cd /srv/r && git push origin main'",
        "docker exec c git push",
        "parallel git push ::: a b",
        "bash <<'EOF'\ngit push\nEOF",
        "ssh host 'git push'",
        "ssh host \"git push origin main\"",
        "ssh host '(cd /srv/r && git push)'",
        "ssh host 'git push; git status'",
        "ruby -e 'system \"git push\"'",
    ];

    #[test]
    fn every_spelling_of_a_push_reminds_alone_and_after_a_commit() {
        for form in PUSH_FORMS {
            assert_eq!(
                run(&make_bash(form)).outcome,
                Outcome::Nudge,
                "alone: {form}"
            );
            let with_commit = format!("git commit -m x && {form}");
            assert_eq!(
                run(&make_bash(&with_commit)).outcome,
                Outcome::Nudge,
                "after a commit: {with_commit}"
            );
        }
    }

    #[test]
    fn a_word_that_is_not_the_push_subcommand_stays_silent() {
        for cmd in [
            "git push-something",
            "git push-something origin",
            "git pushd",
            "git pusher",
            "git stash push",
            "git stash push -m wip",
            "git log push",
            "git log --oneline push..HEAD",
            "git branch push",
            "git checkout push",
            "git remote set-url --push origin https://example.test/r.git",
            "git config remote.pushDefault origin",
            "git config --get remote.origin.push",
            "git -C dir stash push",
            "git -c k=v log push",
            "git pull && git push-hook-test",
            "bash -c 'git stash push'",
        ] {
            assert_eq!(run(&make_bash(cmd)).outcome, Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn a_commit_with_a_push_or_a_post_reminds() {
        for cmd in [
            "git commit -m x && git push",
            "git commit -m x && git push origin HEAD",
            "git add -A && git commit -m x && git push -u origin feat/x",
            "cd other && git commit -m x && git push",
            "git commit -m x; git push",
            "git commit -m x\ngit push",
            "git push && git commit -m x",
            "git commit -m x && gh pr create --title t --body b",
            "git commit -m x && gh pr comment 3 --body b",
            "git commit -m x && gh issue create --title t",
            "git commit -m x && gh pr edit 3 --body b",
            "git commit -m x && gh release create v1 --notes n",
            "git commit -m x && gh api repos/o/r/issues -f body=x",
            "git commit -m x && tea pr create --title t",
            "git commit -m \"$(cat msg.txt)\" && git push",
        ] {
            assert_eq!(run(&make_bash(cmd)).outcome, Outcome::Nudge, "{cmd}");
        }
    }

    #[test]
    fn the_reminder_keeps_its_prefix_and_its_skip_switch_and_stays_short() {
        let text = nudge_text();
        assert!(text.starts_with("Pre-ship audit:"));
        assert!(text.contains("overshare"));
        assert!(text.contains(BYPASS_ENV));
        assert!(text.chars().count() < 300, "{} chars", text.chars().count());
    }

    #[test]
    fn the_reminder_names_the_categories_the_spec_requires() {
        // openspec/specs/external-content: the reminder asks the model to check
        // for health, relationships and non-technical biography. A later
        // shortening must not drop one unnoticed.
        let text = nudge_text();
        for word in ["health", "relationships", "non-technical biography"] {
            assert!(text.contains(word), "reminder lost {word:?}: {text}");
        }
    }
}
