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

use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput, Outcome, markers};

/// Bash token sequences that surface about-to-ship content but are NOT
/// external-posting verbs the shared [`is_external_post`] gate covers. Only
/// `git push` qualifies — the former `git commit` and four `gh` sequences
/// were strict subsets of the gate and were pruned when it was adopted
/// (#385): a second hand-kept list is exactly the drift this change kills.
///
/// [`is_external_post`]: crate::redact_external_content::is_external_post
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
        let bypass = std::env::var(BYPASS_ENV).ok();
        let vault = std::env::var("OBSIDIAN_VAULT").ok();
        run_quiet_period(input, bypass.as_deref(), vault.as_deref())
    }
}

/// Marker kind for the commit quiet period. One session-wide marker, no repo or
/// agent part in the key, so it can only ever silence a later plain commit.
const COMMIT_MARKER_KIND: &str = "overshare-commit-warned";

/// [`run_with_env`] plus the quiet period for a plain `git commit`
/// (cadence-hooks#1636): the first one in a session reminds, later ones in the
/// same session are silent. Nothing else is ever silenced: a push, a post, a
/// file edit and every commit that is not the exact plain form remind each time.
///
/// This only reads the marker. It is written by [`record_delivered`], which the
/// dispatcher calls once the reminder has actually been emitted, so a reminder
/// that repo configuration suppresses, or that a sibling process already
/// delivered, never uses up the session's one reminder.
fn run_quiet_period(input: &HookInput, bypass: Option<&str>, vault: Option<&str>) -> CheckResult {
    let result = run_with_env(input, bypass, vault);
    if result.outcome != Outcome::Nudge {
        return result;
    }
    match quiet_marker(input) {
        Some(marker) if marker.exists() => CheckResult::allow(),
        _ => result,
    }
}

/// Record that this payload's reminder was delivered, so later plain commits in
/// the session are silent. A no-op for everything but a plain `git commit` that
/// [`quiet_marker`] accepts. Called by the dispatcher after it emits a
/// `warn-overshare` nudge (never after a suppressed or deduplicated one); a
/// failed write leaves the reminder in place (ADR-0001).
pub fn record_delivered(input: &HookInput) {
    if let Some(marker) = quiet_marker(input) {
        let _ = markers::write_marker(&marker, "");
    }
}

/// The quiet-period marker for `input`, or `None` when this payload takes no
/// part in the quiet period and must always remind: not a Bash call, not a plain
/// commit, no usable session id, or a marker directory that is not private.
///
/// Fails toward reminding (ADR-0001).
fn quiet_marker(input: &HookInput) -> Option<std::path::PathBuf> {
    if input.normalized_tool_name() != Some("Bash") || !input.command().is_some_and(is_plain_commit)
    {
        return None;
    }
    // `session_marker` falls back to a per-process id when the payload carries
    // none, which would never match twice: require a real, non-empty id.
    if !input.session_id().is_some_and(|sid| !sid.is_empty()) {
        return None;
    }
    // A shared (unhardened) marker directory lets a co-tenant pre-plant the
    // marker and mute the reminder; degrade toward reminding, as `claim_today`.
    if !markers::marker_dir_is_private() {
        return None;
    }
    Some(markers::session_marker(input, COMMIT_MARKER_KIND, None))
}

/// True only when the whole command is one plain `git commit` invocation: the
/// text starts with `git commit` (so no global option, `cd`, variable prefix or
/// wrapper comes before the subcommand) and every argument after it is built
/// from an allowlist: bare words of `[A-Za-z0-9_./=:@+,%-]`, single-quoted text,
/// and double-quoted text with no `$`, backtick, backslash or `!`. Whitespace
/// between words is a space or tab. Anything else (a newline outside quotes, a
/// `;`, `&`, `|`, `<`, `>`, `(`, `$`, a glob, a comment) makes it not plain, so a
/// chain, a pipe, a substitution, a heredoc and a redirect all keep reminding.
///
/// This is an allowlist of one shape, not a list of shapes to exclude: a form
/// nobody thought of is not plain.
fn is_plain_commit(command: &str) -> bool {
    let Some(rest) = command.trim().strip_prefix("git commit") else {
        return false;
    };
    // `git commit-tree`, `git committer`: the subcommand name must end here.
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return false;
    }
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {}
            '\'' => {
                if !chars.by_ref().any(|q| q == '\'') {
                    return false;
                }
            }
            '"' => loop {
                match chars.next() {
                    Some('"') => break,
                    Some('$' | '`' | '\\' | '!') | None => return false,
                    Some(_) => {}
                }
            },
            c if is_bare_word_char(c) => {}
            _ => return false,
        }
    }
    true
}

fn is_bare_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '.' | '/' | '=' | ':' | '@' | '+' | ',' | '%' | '-')
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

/// True when `command` carries `git push`, or any segment matches the redact
/// engine's [`is_external_post`] gate (cadence-hooks#385: overshare's hand-kept
/// six-command list missed `gh pr comment`, `gh pr review`, `gh issue edit`,
/// `gh release/gist/discussion`, and `tea` — every one an external-posting
/// surface the leak scanner already gated). One gate, two consumers: a new
/// posting verb added there is covered here for free.
///
/// [`is_external_post`]: crate::redact_external_content::is_external_post
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

    use cadence_hooks_core::shell::command_segments;
    command_segments(command).iter().any(|seg| {
        crate::redact_external_content::is_external_post(seg)
            && !crate::redact_external_content::api_posts_no_prose(seg)
    })
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

    // --- Commit quiet period (cadence-hooks#1636) ---

    fn in_session(command: &str, sid: &str) -> HookInput {
        HookInput {
            session_id: Some(sid.into()),
            ..make_bash(command)
        }
    }

    /// Run `f` with a scratch marker directory, so no test touches the real one.
    fn quiet<T>(f: impl FnOnce() -> T) -> T {
        let dir = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(dir.path(), f)
    }

    /// The check's verdict, then the dispatcher's step for an emitted reminder:
    /// a delivered nudge spends the quiet period.
    fn outcome(input: &HookInput) -> Outcome {
        let result = run_quiet_period(input, None, None);
        if result.outcome == Outcome::Nudge {
            record_delivered(input);
        }
        result.outcome
    }

    /// Spend the session's one commit reminder, as the first plain commit does.
    fn spend_commit_reminder(sid: &str) {
        assert_eq!(
            outcome(&in_session("git commit -m 'first'", sid)),
            Outcome::Nudge
        );
        assert_eq!(
            outcome(&in_session("git commit -m 'second'", sid)),
            Outcome::Allow,
            "the quiet period must be live before the rows that must not use it"
        );
    }

    #[test]
    fn first_plain_commit_reminds_and_later_ones_are_silent() {
        for (n, cmd) in [
            "git commit",
            "git commit -m 'x'",
            "git commit -m \"two words\"",
            "git commit -F msg.txt -- a.rs b.rs",
            "git commit --amend --no-edit",
            "git commit -m 'a; b && c | d $(e)'",
            "git commit --message=\"x y\"",
            "  git commit -m x\n",
        ]
        .iter()
        .enumerate()
        {
            quiet(|| {
                let sid = format!("sid-plain-{n}");
                assert_eq!(
                    outcome(&in_session(cmd, &sid)),
                    Outcome::Nudge,
                    "first: {cmd}"
                );
                assert_eq!(
                    outcome(&in_session(cmd, &sid)),
                    Outcome::Allow,
                    "second: {cmd}"
                );
                assert_eq!(
                    outcome(&in_session(cmd, &sid)),
                    Outcome::Allow,
                    "third: {cmd}"
                );
            });
        }
    }

    #[test]
    fn a_commit_that_is_not_the_exact_plain_form_reminds_every_time() {
        for cmd in [
            "git -C other commit -m x",
            "git -c user.name=x commit -m x",
            "git --git-dir=other/.git commit -m x",
            "git --work-tree=other commit -m x",
            "cd other && git commit -m x",
            "cd other; git commit -m x",
            "git commit -m x && git push",
            "git commit -m x && gh pr create --title t",
            "git commit -m x; git status",
            "git commit -m x | tee out.txt",
            "git commit -m x || true",
            "git commit -m \"$(cat msg.txt)\"",
            "git commit -m \"$(printf '%s' x)\"",
            "git commit -m \"`cat msg.txt`\"",
            "git commit -m \"a \\\"b\\\"\"",
            "git commit -F - <<'EOF'\nmsg\nEOF",
            "git commit -m x > out.txt",
            "git commit -m x # note",
            "git commit -m x\ngit push",
            "git add -A && git commit -m x",
            "FOO=1 git commit -m x",
            "env FOO=1 git commit -m x",
            "command git commit -m x",
            "(git commit -m x)",
            "git commit -m x &",
            "git commit -a *.rs",
            "git commit -m $MSG",
        ] {
            quiet(|| {
                let sid = "sid-notplain";
                spend_commit_reminder(sid);
                assert_eq!(
                    outcome(&in_session(cmd, sid)),
                    Outcome::Nudge,
                    "first: {cmd}"
                );
                assert_eq!(
                    outcome(&in_session(cmd, sid)),
                    Outcome::Nudge,
                    "second: {cmd}"
                );
            });
        }
    }

    #[test]
    fn a_commit_chained_with_a_push_or_post_reminds_even_before_the_quiet_period_is_spent() {
        quiet(|| {
            for _ in 0..3 {
                assert_eq!(
                    outcome(&in_session("git commit -m x && git push origin HEAD", "s")),
                    Outcome::Nudge
                );
            }
            // The chained forms never wrote the marker, so the first plain commit still reminds.
            assert_eq!(outcome(&in_session("git commit -m x", "s")), Outcome::Nudge);
        });
    }

    #[test]
    fn a_push_or_post_reminds_every_time_after_a_silenced_commit() {
        for cmd in [
            "git push",
            "git push origin main",
            "git push --force-with-lease origin feat/x",
            "gh pr create --title t --body b",
            "gh pr edit 3 --body b",
            "gh pr comment 3 --body b",
            "gh pr review 3 --comment --body b",
            "gh pr merge 3 --squash",
            "gh issue create --title t --body b",
            "gh issue comment 3 --body b",
            "gh issue edit 3 --body b",
            "gh release create v1 --notes n",
            "gh gist create f.md",
            "gh api repos/o/r/issues -f body=x",
            "gh api repos/o/r/issues/3/comments -f body=x",
            "gh repo create o/r --public",
            "gh repo edit o/r -d text",
            "tea pr create --title t",
            "cd other && gh pr comment 1 --body b",
            "gh pr create -R other/repo --title t",
        ] {
            quiet(|| {
                let sid = "sid-posts";
                spend_commit_reminder(sid);
                for round in 1..=3 {
                    assert_eq!(
                        outcome(&in_session(cmd, sid)),
                        Outcome::Nudge,
                        "round {round}: {cmd}"
                    );
                }
            });
        }
    }

    #[test]
    fn a_field_report_edit_reminds_every_time_after_a_silenced_commit() {
        quiet(|| {
            spend_commit_reminder("sid-edit");
            for _ in 0..3 {
                for input in [
                    make_write("/p/docs/field-reports/a.md", "x"),
                    make_edit("/p/docs/field-reports/a.md", "o", "n"),
                ] {
                    let input = HookInput {
                        session_id: Some("sid-edit".into()),
                        ..input
                    };
                    assert_eq!(outcome(&input), Outcome::Nudge);
                }
            }
        });
    }

    #[test]
    fn a_push_before_the_first_commit_does_not_spend_the_quiet_period() {
        quiet(|| {
            for _ in 0..3 {
                assert_eq!(
                    outcome(&in_session("git push", "sid-order")),
                    Outcome::Nudge
                );
            }
            assert_eq!(
                outcome(&in_session("git commit -m x", "sid-order")),
                Outcome::Nudge
            );
        });
    }

    #[test]
    fn a_missing_or_empty_session_id_reminds_every_time() {
        quiet(|| {
            for _ in 0..3 {
                assert_eq!(outcome(&make_bash("git commit -m x")), Outcome::Nudge);
                assert_eq!(outcome(&in_session("git commit -m x", "")), Outcome::Nudge);
            }
        });
    }

    #[test]
    fn a_different_session_id_reminds_again() {
        quiet(|| {
            spend_commit_reminder("sid-one");
            assert_eq!(
                outcome(&in_session("git commit -m x", "sid-two")),
                Outcome::Nudge
            );
            assert_eq!(
                outcome(&in_session("git commit -m x", "sid-two")),
                Outcome::Allow
            );
            assert_eq!(
                outcome(&in_session("git commit -m x", "sid-one")),
                Outcome::Allow
            );
        });
    }

    #[test]
    fn the_skip_switch_still_allows_and_does_not_spend_the_quiet_period() {
        quiet(|| {
            let input = in_session("git commit -m x", "sid-skip");
            let ridden = run_quiet_period(&input, Some("1"), None);
            assert_eq!(ridden.outcome, Outcome::Allow);
            assert!(ridden.bypass.is_some());
            assert_eq!(
                outcome(&input),
                Outcome::Nudge,
                "the bypassed call wrote no marker"
            );
        });
    }

    #[test]
    fn a_marker_of_another_kind_does_not_silence_the_commit_reminder() {
        // The marker kind is this hook's own: a `warn-main-branch`-style marker for the
        // same session and no repo must not silence the commit reminder.
        quiet(|| {
            let input = in_session("git commit -m x", "sid-kind");
            let other = markers::session_marker(&input, "some-other-warned", None);
            markers::write_marker(&other, "").unwrap();
            assert_eq!(outcome(&input), Outcome::Nudge);
        });
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
    fn a_reminder_that_is_not_delivered_does_not_spend_the_quiet_period() {
        quiet(|| {
            let input = in_session("git commit -m x", "sid-undelivered");
            // The check nudged, but the dispatcher never emitted it (repo
            // configuration suppressed it, or a sibling delivered it).
            for _ in 0..3 {
                assert_eq!(run_quiet_period(&input, None, None).outcome, Outcome::Nudge);
            }
            // Delivering it for any other payload spends nothing for this one.
            record_delivered(&in_session("git push", "sid-undelivered"));
            record_delivered(&in_session(
                "git commit -m x && git push",
                "sid-undelivered",
            ));
            record_delivered(&in_session("git -C o commit -m x", "sid-undelivered"));
            record_delivered(&in_session("git commit -m x", "another-session"));
            assert_eq!(run_quiet_period(&input, None, None).outcome, Outcome::Nudge);
            record_delivered(&input);
            assert_eq!(run_quiet_period(&input, None, None).outcome, Outcome::Allow);
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_directory_that_is_not_private_reminds_every_time() {
        // A symlink squatting the per-user directory makes the hardening step
        // refuse it, so the marker directory falls back to the shared base. The
        // symlink API is unix-only here; the refusal itself is platform-neutral.
        quiet(|| {
            let private = markers::marker_dir();
            assert!(markers::marker_dir_is_private(), "control: private first");
            std::fs::remove_dir_all(&private).unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(elsewhere.path(), &private).unwrap();
            assert!(!markers::marker_dir_is_private(), "precondition");
            let input = in_session("git commit -m x", "sid-shared-dir");
            for _ in 0..3 {
                assert_eq!(outcome(&input), Outcome::Nudge);
            }
            let would_be = markers::session_marker(&input, COMMIT_MARKER_KIND, None);
            assert!(
                !would_be.exists(),
                "nothing may be planted in the shared base"
            );
        });
    }

    #[test]
    fn a_marker_that_cannot_be_written_reminds_every_time() {
        quiet(|| {
            let input = in_session("git commit -m x", "sid-unwritable");
            let marker = markers::session_marker(&input, COMMIT_MARKER_KIND, None);
            // `write_marker` stages through `.<name>.<pid>.tmp`; a directory
            // squatting that name makes the staged write fail on every platform.
            let name = marker.file_name().unwrap().to_string_lossy().into_owned();
            let staged = marker
                .parent()
                .unwrap()
                .join(format!(".{name}.{}.tmp", std::process::id()));
            std::fs::create_dir(staged).unwrap();
            assert!(markers::write_marker(&marker, "").is_err(), "precondition");
            for _ in 0..3 {
                assert_eq!(outcome(&input), Outcome::Nudge);
            }
            assert!(!marker.exists());
            // Control: the same setup goes quiet for a session whose staged
            // name is not squatted, so the nudges above come from the failed
            // write and not from some other reason this payload never qualifies.
            spend_commit_reminder("sid-writable");
        });
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

    #[test]
    fn is_plain_commit_accepts_one_shape() {
        for cmd in ["git commit", "git commit -m x", "git commit -m 'a b' -- f"] {
            assert!(is_plain_commit(cmd), "{cmd}");
        }
        for cmd in [
            "git commit-tree abc",
            "git committer",
            "git  -C x commit",
            "git",
            "",
            "git status",
            "echo git commit",
            "git commit -m 'unterminated",
            "git commit -m \"unterminated",
        ] {
            assert!(!is_plain_commit(cmd), "{cmd}");
        }
    }
}
