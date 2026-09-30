//! `guardrails inject-gh-write-context` — PreToolUse hook.
//!
//! Re-states the gh-write allowlist + `-R owner/repo` rule (rendered by
//! [`gh_context`](super::gh_context)) at the moment it applies. It began as the
//! just-in-time twin of a SessionStart injector (`inject-gh-context`): session
//! start is far from the write — by the time a `gh pr create` is composed that
//! context may be many turns, or a compaction, behind, and the write lands
//! without `-R`, silently targeting whatever cwd's git remote happens to be.
//! cameronsjo/cadence#658 retired the SessionStart half; this is the one that
//! stayed.
//!
//! Fires only on the shapes that need it: a segment that actually invokes `gh`,
//! runs a write sub-command, and names no explicit target. Reads never fire
//! (they need no `-R`), and a write that already carries `-R`, an
//! `/repos/owner/repo` API path, or a positional repo argument is left alone —
//! the advice would be noise.
//!
//! **Deliberately un-deduped.** Repeating on every bare write is the mechanism,
//! not a defect: the case this exists to catch is a model that lost the
//! SessionStart context, so suppressing the repeat would silence the fire that
//! matters most. Nudges are exit 0, so the cost of a repeat is a line of
//! context, never a blocked command.
//!
//! It also carries one retargeted-write nudge (cameronsjo/cadence-hooks#150): a
//! body posted with `-R other/repo` that holds a bare `#N` (see
//! [`crate::issue_refs::cross_repo_bare_ref_nudge`]). No new wiring: this hook
//! already sees every gh write.
//!
//! Enforcement still lives in [`guard_gh_write`](super::guard_gh_write); this
//! check only advises, and reuses that guard's write-detection and
//! target-detection so the nudge and the block cannot drift apart.

use cadence_hooks_core::shell::command_segments;
use cadence_hooks_core::{Check, CheckResult, HookInput};

use crate::gh_context::render_from_env;
use crate::guard_gh_write::{is_write_command, segment_invokes_gh, segment_lacks_explicit_target};
use crate::issue_refs::{cross_repo_bare_ref_nudge, origin_slug_of};

/// Re-inject the gh allowlist + `-R` rule just before an untargeted gh write.
pub struct InjectGhWriteContext;

impl Check for InjectGhWriteContext {
    fn name(&self) -> &str {
        "inject-gh-write-context"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        let needs_context = command_segments(command).into_iter().any(|segment| {
            segment_invokes_gh(&segment)
                && is_write_command(&segment)
                && segment_lacks_explicit_target(&segment)
        });

        // The retargeted twin (cameronsjo/cadence-hooks#150): a write that DOES
        // name `-R other/repo` whose body carries a bare `#N`. Local only.
        let base_dir = input.cwd.as_deref().unwrap_or(".");
        // "This checkout's repo" is the one `gh` runs in — the cwd after a
        // leading `cd` chain, so `cd <nested> && gh … -R <nested's slug>` from
        // a meta-repo session compares against the nested repo's origin, not
        // the meta-repo's (cameronsjo/cadence-hooks#225). A `cd` no repo can
        // be named for yields no origin, and the advisory stays quiet.
        let bare_ref = cross_repo_bare_ref_nudge(command, base_dir, &|| {
            cadence_hooks_core::target_repo::command_repo_dir(command, base_dir)
                .and_then(|dir| origin_slug_of(&dir))
        });

        match (needs_context, bare_ref) {
            (false, None) => CheckResult::allow(),
            (true, None) => CheckResult::nudge(render_from_env()),
            (false, Some(msg)) => CheckResult::nudge(msg),
            (true, Some(msg)) => CheckResult::nudge(format!("{}\n{msg}", render_from_env())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    fn outcome(command: &str) -> Outcome {
        InjectGhWriteContext.run(&make_bash(command)).outcome
    }

    // --- guard clauses: nothing to advise on ---

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(InjectGhWriteContext.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        assert_eq!(outcome("git status"), Outcome::Allow);
    }

    // --- reads need no `-R`, so they never fire ---

    #[test]
    fn gh_pr_list_allowed() {
        assert_eq!(outcome("gh pr list"), Outcome::Allow);
    }

    #[test]
    fn gh_pr_view_allowed() {
        assert_eq!(outcome("gh pr view 5 --json mergedAt"), Outcome::Allow);
    }

    // --- untargeted writes nudge ---

    #[test]
    fn gh_pr_create_without_target_nudges() {
        assert_eq!(outcome("gh pr create --title x"), Outcome::Nudge);
    }

    #[test]
    fn case_folded_gh_pr_create_nudges() {
        assert_eq!(outcome("GH pr create --title x"), Outcome::Nudge);
    }

    #[test]
    fn case_fold_does_not_fold_gh_subcommands() {
        assert_eq!(outcome("GH PR create --title x"), Outcome::Allow);
    }

    #[test]
    fn gh_issue_comment_without_target_nudges() {
        assert_eq!(outcome("gh issue comment 5 --body x"), Outcome::Nudge);
    }

    #[test]
    fn gh_release_create_without_target_nudges() {
        assert_eq!(outcome("gh release create v1"), Outcome::Nudge);
    }

    #[test]
    fn gh_api_write_without_repo_flag_nudges() {
        // The path names a repo, but `gh api repos/o/r` is a bare path with no
        // leading slash — API_REPOS matches it, so this shape is targeted.
        // Use a non-repo endpoint to exercise the untargeted API write.
        assert_eq!(outcome("gh api user/repos -X POST"), Outcome::Nudge);
    }

    #[test]
    fn gh_pr_merge_without_target_nudges() {
        assert_eq!(outcome("gh pr merge 5 --squash"), Outcome::Nudge);
    }

    // --- the segment walk, which is why this reads command_segments at all ---

    #[test]
    fn untargeted_write_in_a_later_segment_nudges() {
        assert_eq!(
            outcome("cd /repo && gh pr create --title x"),
            Outcome::Nudge
        );
    }

    #[test]
    fn one_targeted_segment_does_not_excuse_an_untargeted_one() {
        // Per-segment, not whole-command: a `-R` anywhere in the line would
        // otherwise silence the advice for a sibling write that has none.
        assert_eq!(
            outcome("gh pr create -R o/r --title x && gh issue comment 5 --body y"),
            Outcome::Nudge
        );
    }

    #[test]
    fn every_segment_targeted_allowed() {
        assert_eq!(
            outcome("gh pr create -R o/r --title x && gh issue comment 5 -R o/r --body y"),
            Outcome::Allow
        );
    }

    #[test]
    fn nudge_message_carries_the_dash_r_rule() {
        let msg = InjectGhWriteContext
            .run(&make_bash("gh pr create --title x"))
            .message
            .expect("nudge always carries a message");
        assert!(
            msg.contains("`-R owner/repo`"),
            "nudge should carry the -R rule verbatim from render_context: {msg}"
        );
    }

    // --- explicit targets are left alone, in all four `-R` spellings ---

    #[test]
    fn separated_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create -R o/r --title x"), Outcome::Allow);
    }

    #[test]
    fn attached_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create -Ro/r --title x"), Outcome::Allow);
    }

    #[test]
    fn equals_joined_repo_flag_allowed() {
        assert_eq!(outcome("gh pr create --repo=o/r --title x"), Outcome::Allow);
    }

    #[test]
    fn long_repo_flag_allowed() {
        assert_eq!(
            outcome("gh issue comment 5 --repo o/r --body x"),
            Outcome::Allow
        );
    }

    #[test]
    fn api_repos_path_allowed() {
        assert_eq!(outcome("gh api repos/o/r -X POST"), Outcome::Allow);
    }

    // --- positional-target shapes are left alone ---

    #[test]
    fn gh_repo_create_positional_allowed() {
        assert_eq!(outcome("gh repo create o/name"), Outcome::Allow);
    }

    #[test]
    fn gh_repo_fork_positional_allowed() {
        assert_eq!(outcome("gh repo fork o/r"), Outcome::Allow);
    }

    #[test]
    fn gh_gist_create_allowed() {
        // Gists have no repo target at all — `-R` would be meaningless.
        assert_eq!(outcome("gh gist create f"), Outcome::Allow);
    }

    // --- regression pin: prose is not an invocation (#212) ---

    #[test]
    fn gh_write_quoted_in_a_commit_message_allowed() {
        assert_eq!(
            outcome(r#"git commit -m "document the gh pr create flow""#),
            Outcome::Allow
        );
    }

    #[test]
    fn check_name_matches_subcommand() {
        assert_eq!(InjectGhWriteContext.name(), "inject-gh-write-context");
    }

    // --- retargeted body with a bare #N (#150) ---

    /// A checkout whose `origin` is `cameronsjo/cadence-hooks`.
    fn checkout() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/cameronsjo/cadence-hooks.git",
        ]);
        dir
    }

    fn in_checkout(command: &str, dir: &std::path::Path) -> CheckResult {
        InjectGhWriteContext.run(&cadence_hooks_core::test_builders::make_bash_with_cwd(
            command,
            dir.to_str().unwrap(),
        ))
    }

    #[test]
    fn retargeted_body_with_a_bare_ref_nudges_and_the_rest_stay_silent() {
        let repo = checkout();
        // (command, nudges)
        let table = [
            (
                "gh issue create -R cameronsjo/cadence --title t --body 'see #42'",
                true,
            ),
            (
                "gh issue comment 5 -R cameronsjo/cadence --body 'dup of #7 and #9'",
                true,
            ),
            (
                "gh pr create --repo cameronsjo/cadence -t t -b 'Closes #12'",
                true,
            ),
            // Qualified refs are fine.
            (
                "gh issue create -R cameronsjo/cadence -t t -b 'see cameronsjo/cadence-hooks#42'",
                false,
            ),
            // No bare ref at all, or only inside code, or a hex colour / entity.
            (
                "gh issue create -R cameronsjo/cadence -t t -b 'no refs'",
                false,
            ),
            (
                "gh issue create -R cameronsjo/cadence -t t -b 'run `make #42`'",
                false,
            ),
            (
                "gh issue create -R cameronsjo/cadence -t t -b 'colour #123456 and &#39;'",
                false,
            ),
            // -R names the checkout's own repo (any case): bare #N resolves right.
            (
                "gh issue create -R cameronsjo/cadence-hooks -t t -b 'see #42'",
                false,
            ),
            (
                "gh issue create -R CameronSjo/Cadence-Hooks -t t -b 'see #42'",
                false,
            ),
            // Reads never fire.
            ("gh issue view 5 -R cameronsjo/cadence", false),
            ("gh pr list -R cameronsjo/cadence --search '#42'", false),
        ];
        for (command, nudges) in table {
            let r = in_checkout(command, repo.path());
            assert_eq!(r.outcome == Outcome::Nudge, nudges, "{command}");
            if nudges {
                let msg = r.message.unwrap_or_default();
                assert!(msg.contains("owner/repo#N"), "{msg}");
                assert!(msg.contains("cameronsjo/cadence"), "{msg}");
            }
        }
    }

    #[test]
    fn an_unreadable_origin_keeps_the_retargeted_nudge_silent() {
        let dir = tempfile::tempdir().unwrap();
        let r = in_checkout(
            "gh issue create -R cameronsjo/cadence -t t -b 'see #42'",
            dir.path(),
        );
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn bare_refs_reads_prose_only() {
        use crate::issue_refs::bare_refs;
        for (body, want) in [
            ("see #5 and #3, again #5", vec![3, 5]),
            ("a/b#7 and a-b#8 and x#9", vec![]),
            ("```\n#4\n```\nafter #6", vec![6]),
            ("# Heading\n#123456 colour", vec![]),
            ("(#12) [#13]", vec![12, 13]),
        ] {
            assert_eq!(bare_refs(body), want, "{body:?}");
        }
    }

    #[test]
    fn bare_ref_origin_is_the_repo_a_leading_cd_moves_into() {
        use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
        let s = Scratch::new(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/inject-gh-write-context-scratch"),
            "meta-cd",
        );
        let meta = s.path().join("meta");
        let nested = meta.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        init_repo(&meta);
        std::fs::write(meta.join(".gitignore"), "nested/\n").unwrap();
        git_in(&meta, &["add", ".gitignore"]);
        git_in(&meta, &["commit", "-q", "-m", "ignore"]);
        init_repo(&nested);
        for (dir, slug) in [(&meta, "meta"), (&nested, "nested")] {
            let url = format!("https://github.com/o/{slug}.git");
            git_in(dir, &["remote", "add", "origin", &url]);
        }
        // (label, command, nudges) — all run from the meta-repo cwd.
        let table = [
            (
                "cd nested, posting to the nested repo itself: its own refs",
                "cd nested && gh issue comment 5 -R o/nested --body 'see #7'",
                false,
            ),
            (
                "cd nested, posting to the meta repo: a cross-repo bare ref",
                "cd nested && gh issue comment 5 -R o/meta --body 'see #7'",
                true,
            ),
            (
                "no cd, posting to the meta repo (unchanged)",
                "gh issue comment 5 -R o/meta --body 'see #7'",
                false,
            ),
            (
                "no cd, posting to the nested repo (unchanged)",
                "gh issue comment 5 -R o/nested --body 'see #7'",
                true,
            ),
            (
                "cd into a missing dir: no origin can be named, quiet",
                "cd nested/no-such && gh issue comment 5 -R o/nested --body 'see #7'",
                false,
            ),
        ];
        for (label, command, nudges) in table {
            let outcome = in_checkout(command, &meta).outcome;
            let want = if nudges {
                Outcome::Nudge
            } else {
                Outcome::Allow
            };
            assert_eq!(outcome, want, "{label}");
        }
    }
}
