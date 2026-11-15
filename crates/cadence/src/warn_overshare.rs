//! Nudge to audit about-to-ship content for personal-context overshare.
//!
//! Fires on commit/push/PR/issue Bash commands and on Write/Edit to
//! `docs/field-reports/` paths. The hook does the path triage; the model
//! does the content judgment from the nudge text. It nudges at most once per
//! session per agent per target (a session marker keyed on the target repo and
//! the `agent_id`), since the text is the same every time (cadence-hooks#1443).
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
        let result = run_with_env(input, bypass.as_deref(), vault.as_deref());
        if result.outcome != Outcome::Nudge {
            return result;
        }
        match marker_paths(input) {
            Some(markers) => once_per_session(result, &markers),
            None => result,
        }
    }
}

/// Marker kind for a Bash commit, push or post.
const BASH_MARKER_KIND: &str = "overshare-warned-bash";
/// Marker kind for a field-report Write or Edit, kept apart from the Bash one
/// so a reminder spent on an edit does not silence the later push.
const WRITE_MARKER_KIND: &str = "overshare-warned-write";

/// The session markers that stand for "this agent was already reminded about
/// this target" (cadence-hooks#1443), or `None` when the input names a target
/// the existing readers do not resolve exactly, so it nudges every time.
///
/// Each key is one target plus the payload's `agent_id`: a subagent carries
/// its parent's `session_id`, and the reminder has to reach the context that
/// writes the outgoing text, so each agent gets its own first nudge.
///
/// Targets, read from disk and existing argv readers only (no `git` process,
/// no new parsing):
/// - Write/Edit: the git root above the edited file's directory.
/// - Bash with no target named: the git root above `cwd`.
/// - `gh` with a literal `-R`/`--repo` that [`gh_repo_flags`] resolves: that
///   slug.
/// - Ungated: a leading `cd` that moves the work dir, `git` with any global
///   option (`-C`, `--git-dir`, `-c`, ...), a `gh` repo flag that is not one
///   literal slug, and every `tea` post.
///
/// [`gh_repo_flags`]: cadence_hooks_core::shell::gh_repo_flags
fn marker_paths(input: &HookInput) -> Option<Vec<std::path::PathBuf>> {
    let agent = input.agent_id.as_deref().unwrap_or_default();
    let key = |kind: &str, target: &str| {
        cadence_hooks_core::markers::session_marker(
            input,
            kind,
            Some(&format!("{target}\u{1f}{agent}")),
        )
    };
    let dir = cadence_hooks_core::worktree::git_dir_for_input(input);
    let dir = dir.to_string_lossy().into_owned();
    let root = cadence_hooks_core::paths::find_git_root(&dir)
        .map(|root| root.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.clone());
    let Some(command) = input.command() else {
        return Some(vec![key(WRITE_MARKER_KIND, &root)]);
    };
    bash_targets(command, &dir).map(|targets| {
        targets
            .iter()
            .map(|target| match target {
                Target::Cwd => key(BASH_MARKER_KIND, &root),
                Target::GhRepo(slug) => key(BASH_MARKER_KIND, &format!("gh:{slug}")),
            })
            .collect()
    })
}

/// Where a Bash post goes, as far as the existing readers say exactly.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// The repo `cwd` is in.
    Cwd,
    /// A literal `gh -R owner/repo` (lowercased).
    GhRepo(String),
}

/// The targets of `command`'s posting segments, or `None` when one names a
/// target not resolved exactly. See [`marker_paths`].
fn bash_targets(command: &str, cwd: &str) -> Option<Vec<Target>> {
    use cadence_hooks_core::shell::{
        GhRepoFlag, command_segments, command_word, executable_tokens, gh_repo_flags,
        parse_work_dir, peel_command_runners, skip_git_global_options,
    };
    if parse_work_dir(command, cwd) != cwd {
        return None;
    }
    let mut targets = Vec::new();
    for segment in command_segments(command) {
        let tokens = executable_tokens(&segment);
        let argv = peel_command_runners(&tokens);
        let Some(head) = argv.first() else { continue };
        let target = match command_word(head).as_ref() {
            "git" if skip_git_global_options(&argv[1..]).len() + 1 == argv.len() => Target::Cwd,
            "git" | "tea" => return None,
            "gh" => match gh_repo_flags(argv).resolve() {
                GhRepoFlag::Absent => Target::Cwd,
                GhRepoFlag::Target(slug) if !slug.contains(['$', '`']) => {
                    Target::GhRepo(slug.to_ascii_lowercase())
                }
                _ => return None,
            },
            _ => continue,
        };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.is_empty() {
        targets.push(Target::Cwd);
    }
    Some(targets)
}

/// Let `nudge` through unless every marker in `markers` is already recorded
/// this session, and record them all. The audit text is the same on every
/// firing, so one reminder per agent per target carries it (cadence-hooks#1443).
/// A marker that cannot be written lets the next firing nudge again: fail open
/// toward the reminder, never away from it.
///
/// Known limit: the marker is written when this check returns the nudge, not
/// when the model receives it. If another guard blocks the same call, the
/// retry in that session gets no reminder. It also outlives a compaction or
/// `/clear` under the same session id.
fn once_per_session(nudge: CheckResult, markers: &[std::path::PathBuf]) -> CheckResult {
    if markers.iter().all(|marker| marker.exists()) {
        return CheckResult::allow();
    }
    for marker in markers {
        let _ = cadence_hooks_core::markers::write_marker(marker, "");
    }
    nudge
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

    // --- Once per agent per target (cadence-hooks#1443) ---

    /// A Bash payload with a fixed session, agent and cwd.
    fn bash_at(command: &str, cwd: &std::path::Path, sid: &str, agent: Option<&str>) -> HookInput {
        HookInput {
            cwd: Some(cwd.to_string_lossy().into_owned()),
            session_id: Some(sid.into()),
            agent_id: agent.map(Into::into),
            ..make_bash(command)
        }
    }

    /// A scratch dir holding two git roots, `a` (with `a/sub`) and `b`.
    fn two_repos() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("scratch dir");
        for repo in ["a/.git", "a/sub", "b/.git"] {
            std::fs::create_dir_all(dir.path().join(repo)).unwrap();
        }
        dir
    }

    #[test]
    fn nudge_fires_once_per_marker_then_allows() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let markers = [dir.path().join("m1"), dir.path().join("m2")];
        let nudge = || CheckResult::nudge(nudge_text());
        let first = once_per_session(nudge(), &markers);
        assert_eq!(first.outcome, Outcome::Nudge);
        assert!(
            markers.iter().all(|m| m.exists()),
            "the first firing records every marker"
        );
        let second = once_per_session(nudge(), &markers);
        assert_eq!(second.outcome, Outcome::Allow);
        assert!(second.message.is_none());
        // One unseen target is enough to nudge again.
        let third = once_per_session(nudge(), &[markers[0].clone(), dir.path().join("m3")]);
        assert_eq!(third.outcome, Outcome::Nudge);
    }

    #[test]
    fn marker_is_keyed_per_repo_session_agent_and_trigger() {
        let dir = two_repos();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let key = |input: &HookInput| marker_paths(input).expect("gated");
        let root = key(&bash_at("git push", &a, "s1", None));
        assert_eq!(
            root,
            key(&bash_at("git push", &a.join("sub"), "s1", None)),
            "same repo"
        );
        assert_ne!(
            root,
            key(&bash_at("git push", &b, "s1", None)),
            "another repo"
        );
        assert_ne!(
            root,
            key(&bash_at("git push", &a, "s2", None)),
            "another session"
        );
        assert_ne!(
            root,
            key(&bash_at("git push", &a, "s1", Some("ag1"))),
            "another agent"
        );
        let write = HookInput {
            session_id: Some("s1".into()),
            ..make_write(&a.join("docs/field-reports/x.md").to_string_lossy(), "x")
        };
        assert_ne!(
            root,
            key(&write),
            "a field-report edit does not spend the push reminder"
        );
    }

    #[test]
    fn a_named_target_keys_on_the_target_or_skips_the_gate() {
        let dir = two_repos();
        let a = dir.path().join("a");
        let key = |command: &str| marker_paths(&bash_at(command, &a, "s1", None));
        let cwd_key = key("gh issue create --title x --body-file b.md").expect("gated");
        let public = key("gh issue create -R owner/public --title x --body-file b.md")
            .expect("a literal -R slug is read exactly");
        assert_ne!(cwd_key, public, "-R names another repo's key");
        assert_eq!(
            public,
            key("gh -R Owner/Public issue create --title x").expect("gated")
        );
        for command in [
            "git -C ../b push",
            "git -C ../b commit -m x",
            "cd ../b && git push",
            "gh issue create -R \"$REPO\" --title x",
            "tea pr create --title x",
        ] {
            assert!(
                key(command).is_none(),
                "{command}: an unresolved target nudges every time"
            );
        }
    }

    /// The real check, end to end: nudge, then silence for the same agent and
    /// target, then a nudge for another target or agent.
    #[test]
    fn run_nudges_once_per_agent_and_target() {
        let dir = two_repos();
        let markers = tempfile::tempdir().expect("marker dir");
        let a = dir.path().join("a");
        cadence_hooks_core::test_builders::with_marker_dir(markers.path(), || {
            let run = |command: &str, agent: Option<&str>| {
                WarnOvershare
                    .run(&bash_at(command, &a, "s1", agent))
                    .outcome
            };
            assert_eq!(run("git push origin x", None), Outcome::Nudge);
            assert_eq!(run("git commit -m y", None), Outcome::Allow);
            assert_eq!(run("git push origin z", Some("ag1")), Outcome::Nudge);
            assert_eq!(
                run("gh pr create -R owner/public --title t", None),
                Outcome::Nudge
            );
            assert_eq!(
                run("gh pr comment 5 -R owner/public --body b", None),
                Outcome::Allow
            );
            assert_eq!(run("git -C ../b commit -m x", None), Outcome::Nudge);
            assert_eq!(run("git -C ../b commit -m x", None), Outcome::Nudge);
            assert_eq!(run("git status", None), Outcome::Allow);
            // A call that does not nudge spends no reminder.
            assert_eq!(run("git status", Some("ag2")), Outcome::Allow);
            assert_eq!(run("git push origin q", Some("ag2")), Outcome::Nudge);
        });
    }
}
