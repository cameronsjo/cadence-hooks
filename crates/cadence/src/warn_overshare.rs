//! Nudge to audit about-to-ship content for personal-context overshare.
//!
//! Fires on commit/push/PR/issue Bash commands and on Write/Edit to
//! `docs/field-reports/` paths. The hook does the path triage; the model
//! does the content judgment from the nudge text. It nudges at most once per
//! session per agent per target for an allowlisted commit, push or `gh` post
//! (a session marker keyed on the target and the `agent_id`), and every time
//! for anything else, since the text is the same every time (cadence-hooks#1443).
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
/// this target" (cadence-hooks#1443), or `None` to nudge every time.
///
/// Each key is one target plus the payload's `agent_id`: a subagent carries
/// its parent's `session_id`, and the reminder has to reach the context that
/// writes the outgoing text, so each agent gets its own first nudge.
///
/// A Write or Edit is keyed on the git root above the edited file. A Bash
/// command is gated only when every posting segment is on the short allowlist
/// in [`allowlisted_target`]; anything else nudges every time, so a post to a
/// repo other than the one keyed can never be silenced by that repo's marker.
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
        .unwrap_or(dir);
    let Some(command) = input.command() else {
        return Some(vec![key(WRITE_MARKER_KIND, &root)]);
    };
    bash_targets(command).map(|targets| {
        targets
            .iter()
            .map(|target| match target {
                Target::Cwd => key(BASH_MARKER_KIND, &root),
                Target::GhRepo(slug) => key(BASH_MARKER_KIND, &format!("gh:{slug}")),
            })
            .collect()
    })
}

/// Where an allowlisted Bash post goes.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// The repo `cwd` is in.
    Cwd,
    /// A literal `gh -R owner/repo` / `--repo owner/repo` (lowercased).
    GhRepo(String),
}

/// The targets of `command`'s posting segments when every one is on the
/// allowlist, else `None`. A command that mentions `cd ` or `pushd ` anywhere
/// is never gated, since either may move where a later segment runs.
fn bash_targets(command: &str) -> Option<Vec<Target>> {
    use cadence_hooks_core::shell::{command_segments, executable_tokens};
    if command.contains("cd ") || command.contains("pushd ") {
        return None;
    }
    let mut targets = Vec::new();
    for segment in command_segments(command) {
        let argv = executable_tokens(&segment);
        let posts = segment_posts(&segment, &argv);
        if !posts {
            continue;
        }
        let target = allowlisted_target(&argv)?;
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    // A trigger no segment accounts for is not on the allowlist.
    (!targets.is_empty()).then_some(targets)
}

/// Does this segment carry a trigger (a posting verb, or `git push`)?
fn segment_posts(segment: &str, argv: &[String]) -> bool {
    let push = argv.windows(2).any(|w| w[0] == "git" && w[1] == "push");
    push || (crate::redact_external_content::is_external_post(segment)
        && !crate::redact_external_content::api_posts_no_prose(segment))
}

/// The allowlist, by plain token tests on the segment's argv (no runner
/// peeling, so `env`, `sudo` or a `VAR=` prefix is never on it):
/// - `git commit …` with no global option before `commit`: the cwd repo.
/// - `git push …` with no global option and no argument that looks like a URL
///   or path: the cwd repo.
/// - `gh <group> <verb> …` (not `api`, not `gist`) with no argument containing
///   `://` or `github.com/`: a literal `-R`/`--repo owner/repo` slug, or the
///   cwd repo when there is no repo flag.
fn allowlisted_target(argv: &[String]) -> Option<Target> {
    let looks_like_location = |arg: &String| {
        arg.contains("://")
            || ["git@", "/", "./", "../", "~"]
                .iter()
                .any(|prefix| arg.starts_with(prefix))
    };
    match argv.first().map(String::as_str)? {
        "git" => match argv.get(1).map(String::as_str)? {
            "commit" => Some(Target::Cwd),
            "push" if !argv[2..].iter().any(looks_like_location) => Some(Target::Cwd),
            _ => None,
        },
        "gh" => {
            if argv
                .iter()
                .any(|arg| arg.contains("://") || arg.contains("github.com/"))
            {
                return None;
            }
            let mut slugs = Vec::new();
            let mut words = Vec::new();
            let mut i = 1;
            while let Some(arg) = argv.get(i) {
                let value = match arg.as_str() {
                    "-R" | "--repo" => {
                        i += 1;
                        Some(argv.get(i)?.clone())
                    }
                    a if a.starts_with("--repo=") => Some(a["--repo=".len()..].to_string()),
                    a if a.starts_with("-R") => Some(a[2..].to_string()),
                    _ => None,
                };
                match value {
                    Some(v) => slugs.push(v),
                    None if !arg.starts_with('-') && words.len() < 2 => words.push(arg.as_str()),
                    None => {}
                }
                i += 1;
            }
            if matches!(words.first(), None | Some(&"api") | Some(&"gist")) {
                return None;
            }
            match slugs.as_slice() {
                [] => Some(Target::Cwd),
                [slug] if is_literal_slug(slug) => Some(Target::GhRepo(slug.to_ascii_lowercase())),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `owner/repo`: exactly one `/`, both halves non-empty and made of the
/// characters GitHub allows.
fn is_literal_slug(slug: &str) -> bool {
    let ok = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    matches!(slug.split_once('/'), Some((owner, repo)) if ok(owner) && ok(repo))
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

    /// Each allowlisted form, through the real check: the first call nudges,
    /// the same form again for the same agent and target is silent.
    #[test]
    fn allowlisted_forms_nudge_once() {
        let dir = two_repos();
        let a = dir.path().join("a");
        for (sid, command) in [
            ("c1", "git commit -m 'fix: thing'"),
            ("c2", "git add -A && git commit -m x"),
            ("p1", "git push origin feature"),
            ("p2", "git push -u origin HEAD:refs/heads/x"),
            ("g1", "gh pr create --draft --title t --body-file b.md"),
            ("g2", "gh issue comment 5 --body-file c.md"),
            (
                "r1",
                "gh issue create -R owner/public --title t --body-file b.md",
            ),
            ("r2", "gh --repo owner/public pr comment 5 --body-file c.md"),
        ] {
            let markers = tempfile::tempdir().expect("marker dir");
            cadence_hooks_core::test_builders::with_marker_dir(markers.path(), || {
                let run = || WarnOvershare.run(&bash_at(command, &a, sid, None)).outcome;
                assert_eq!(run(), Outcome::Nudge, "{command}: first call");
                assert_eq!(run(), Outcome::Allow, "{command}: second call");
            });
        }
    }

    /// Every form off the allowlist nudges every time, even after a nudge in
    /// the same session and cwd repo (security review on PR 1629).
    #[test]
    fn forms_off_the_allowlist_nudge_every_time() {
        let dir = two_repos();
        let a = dir.path().join("a");
        let markers = tempfile::tempdir().expect("marker dir");
        cadence_hooks_core::test_builders::with_marker_dir(markers.path(), || {
            let run = |command: &str| WarnOvershare.run(&bash_at(command, &a, "s1", None)).outcome;
            assert_eq!(run("git commit -m first"), Outcome::Nudge);
            assert_eq!(run("gh pr create --title t"), Outcome::Allow);
            for command in [
                "gh api repos/owner/other/issues/5/comments -f body=hello",
                "gh pr comment https://github.com/owner/other2/pull/5 --body hi",
                "GH_REPO=owner/other3 gh issue create --title t --body b",
                "gh gist create --public notes.md --desc d",
                "pushd ../b && git push",
                "cd ../b && git push",
                "git push https://github.com/owner/other4.git HEAD",
                "git push git@github.com:owner/other5.git HEAD",
                "git push ../b main",
                "git -C ../b commit -m x",
                "gh issue create -R \"$REPO\" --title x",
                "tea pr create --title x",
                "env git commit -m x",
            ] {
                assert_eq!(run(command), Outcome::Nudge, "{command}: first");
                assert_eq!(run(command), Outcome::Nudge, "{command}: second");
            }
        });
    }

    /// Keys differ per agent and per `-R` slug, and a call that does not
    /// nudge spends no reminder.
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
            assert_eq!(run("git status", None), Outcome::Allow);
            assert_eq!(run("git status", Some("ag2")), Outcome::Allow);
            assert_eq!(run("git push origin q", Some("ag2")), Outcome::Nudge);
        });
    }
}
