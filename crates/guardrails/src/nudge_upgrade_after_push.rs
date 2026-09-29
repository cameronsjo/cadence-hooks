//! Nudge to schedule a Homebrew upgrade after pushing cadence-hooks to main.
//!
//! Fires as a PostToolUse hook on `git push`. Detects whether the push
//! originated from the `cameronsjo/cadence-hooks` repo and targeted the
//! main branch. If so, emits a nudge telling Claude to schedule a deferred
//! `brew upgrade` via CronCreate (one-shot, ~4 minutes out) to allow CI
//! time to build and publish the new beta release.
//!
//! The pushes come from [`push_invocations`], the shell walk the push guards
//! share, not from a substring search. A substring search fired on any command
//! whose TEXT said `git push … main`: a heredoc body, an `echo`, a commit
//! message (cameronsjo/cadence-hooks#893). This is a nudge, so every ambiguity
//! resolves toward silence.

use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::push::{PushInvocation, push_invocations};
use cadence_hooks_core::shell::{git_command, host_and_repo_from_url};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;

const TARGET_REPO: &str = "cameronsjo/cadence-hooks";

fn is_main(name: &str) -> bool {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    name == "main" || name == "master"
}

/// Whether this push publishes to the main branch.
///
/// A named refspec is judged by the branch it writes on the remote: its
/// destination, or its source when it names none (`git push origin main`).
/// A bare `git push` publishes the current branch, read from `work_dir`
/// (pure-filesystem HEAD read, cadence-hooks#164; a detached HEAD is not main).
/// A dry run and a delete publish nothing.
fn is_push_to_main(push: &PushInvocation) -> bool {
    if push.dry_run {
        return false;
    }
    push.refspecs.iter().filter(|r| !r.is_delete).any(|r| {
        if r.implicit {
            return GitState::resolve(Path::new(&push.work_dir))
                .and_then(|s| s.branch)
                .is_some_and(|b| is_main(&b));
        }
        r.destination
            .as_deref()
            .or(r.source.as_deref())
            .is_some_and(is_main)
    })
}

/// Whether `work_dir`'s `origin` is the cadence-hooks repo.
fn is_cadence_hooks_checkout(work_dir: &str) -> bool {
    let Some(remote_url) = git_command(work_dir, &["remote", "get-url", "origin"]) else {
        return false;
    };
    let Some((_host, repo_path)) = host_and_repo_from_url(&remote_url) else {
        return false;
    };
    // Normalize: strip .git suffix, compare case-insensitively
    repo_path.trim_end_matches(".git").to_lowercase() == TARGET_REPO
}

/// Nudge Claude to schedule a deferred brew upgrade after pushing cadence-hooks.
pub struct NudgeUpgradeAfterPush;

impl Check for NudgeUpgradeAfterPush {
    fn name(&self) -> &str {
        "nudge-upgrade-after-push"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Cheap prefilter before the shell walk.
        if !command.contains("push") {
            return CheckResult::allow();
        }

        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);

        let pushed_main = push_invocations(command, cwd)
            .iter()
            .any(|push| is_push_to_main(push) && is_cadence_hooks_checkout(&push.work_dir));
        if !pushed_main {
            return CheckResult::allow();
        }

        CheckResult::nudge(
            "cadence-hooks was just pushed to main. \
             CI will build a new beta release in ~2 minutes, then auto-update the Homebrew tap.\n\n\
             Schedule a deferred brew upgrade: use CronCreate with recurring: false, \
             ~4 minutes from now, prompt: \
             \"Run: ${CLAUDE_PLUGIN_ROOT}/hooks/upgrade-cadence-hooks.sh \
             (where CLAUDE_PLUGIN_ROOT is the git-guardrails plugin root). \
             This watches the CI run and upgrades cadence-hooks-beta via Homebrew. \
             Report the result to the user.\"\n\n\
             Tell the user you're scheduling the upgrade.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};
    use cadence_hooks_core::{HookInput, Outcome};

    /// The cadence-hooks repo root, derived portably from this crate's manifest
    /// dir (`<root>/crates/guardrails` → `<root>`). Uses `Path::ancestors` rather
    /// than `rsplit_once("/crates")`, which misses the backslash-joined
    /// `CARGO_MANIFEST_DIR` on Windows and falls back to the wrong directory.
    fn repo_root() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn no_command_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn non_push_command_allows() {
        let result = NudgeUpgradeAfterPush.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn push_from_other_repo_allows() {
        // Use /tmp as CWD — not a git repo, so remote lookup returns None → allow
        let input = make_bash_with_cwd("git push origin main", "/tmp");
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- is_push_to_main tests ---

    /// Does `command`, run in `cwd`, push to main? Any push counts.
    fn pushes_main(command: &str, cwd: &str) -> bool {
        push_invocations(command, cwd).iter().any(is_push_to_main)
    }

    #[test]
    fn is_push_to_main_explicit_refspec() {
        assert!(pushes_main("git push origin main", "/tmp"));
        assert!(pushes_main("git push origin main:main", "/tmp"));
    }

    #[test]
    fn is_push_to_main_master_branch() {
        assert!(pushes_main("git push origin master", "/tmp"));
        assert!(pushes_main("git push origin master:master", "/tmp"));
    }

    #[test]
    fn is_push_to_main_feature_branch() {
        assert!(!pushes_main("git push origin feature/foo", "/tmp"));
    }

    #[test]
    fn is_push_to_main_tag_push() {
        assert!(!pushes_main("git push origin v1.0.0", "/tmp"));
    }

    #[test]
    fn is_push_to_main_with_flags() {
        assert!(pushes_main("git push --force origin main", "/tmp"));
        assert!(pushes_main("git push -u origin main", "/tmp"));
    }

    #[test]
    fn is_push_to_main_chained_command() {
        assert!(pushes_main("git push origin main && echo done", "/tmp"));
    }

    #[test]
    fn is_push_to_main_bare_push_nonexistent_dir() {
        // Bare push in a dir with no HEAD to read — not main.
        assert!(!pushes_main("git push origin", "/tmp/nonexistent"));
    }

    #[test]
    fn is_push_to_main_judges_the_remote_side() {
        // `feat:main` writes main on the remote; `main:feat` does not.
        assert!(pushes_main("git push origin feat:main", "/tmp"));
        assert!(pushes_main("git push origin HEAD:refs/heads/main", "/tmp"));
        assert!(!pushes_main("git push origin main:feat", "/tmp"));
    }

    #[test]
    fn is_push_to_main_ignores_dry_runs_and_deletes() {
        assert!(!pushes_main("git push --dry-run origin main", "/tmp"));
        assert!(!pushes_main("git push origin --delete main", "/tmp"));
    }

    #[test]
    fn is_push_to_main_follows_dash_c() {
        assert!(pushes_main("git -C /elsewhere push origin main", "/tmp"));
    }

    /// cameronsjo/cadence-hooks#893: the words `git push origin main` in text
    /// that no shell runs as a push are not a push.
    #[test]
    fn push_words_in_prose_are_not_a_push() {
        for command in [
            "python3 - <<'EOF'\n# later: git push origin main\nEOF",
            "cat > notes.md <<EOF\nthen git push origin main\nEOF",
            "echo 'git push origin main'",
            "printf '%s\\n' \"git push origin main\"",
            "git commit -m 'docs: explain git push origin main'",
        ] {
            assert!(
                !pushes_main(command, "/tmp"),
                "no push to main runs here: {command:?}"
            );
        }
    }

    // --- Check::run() integration: repo detection ---

    #[test]
    fn push_from_cadence_hooks_repo_nudges() {
        // Stable regardless of the enclosing checkout's origin (#254).
        let repo = crate::github_origin_repo();
        let input = make_bash_with_cwd("git push origin main", &repo.path().to_string_lossy());
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(
            result.outcome,
            Outcome::Nudge,
            "should nudge for cadence-hooks repo"
        );
        assert!(
            result.message.is_some(),
            "nudge should include scheduling instructions"
        );
    }

    #[test]
    fn push_from_cadence_hooks_feature_branch_allows() {
        let input = make_bash_with_cwd("git push origin feature/test", &repo_root());
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(
            result.outcome,
            Outcome::Allow,
            "should not nudge for non-main branch"
        );
    }

    #[test]
    fn push_from_other_repo_with_explicit_cwd_allows() {
        // git-guardrails is a sibling repo — different remote
        let cwd = format!("{}/../../git-guardrails", env!("CARGO_MANIFEST_DIR"));
        let input = make_bash_with_cwd("git push origin main", &cwd);
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(
            result.outcome,
            Outcome::Allow,
            "should not nudge for non-cadence-hooks repo"
        );
    }

    // Unix-only: exercises POSIX bash `cd <absolute-path>` resolution through
    // parse_work_dir. A native Windows repo path (`D:\...`) is not a `/`-rooted
    // bash absolute path, so it cannot drive this code path — and in production
    // Claude's Bash tool on Windows is Git Bash, where cd targets are `/d/...`
    // mounts, not native paths. parse_work_dir's parsing itself is covered
    // portably by the unit tests in core::shell.
    #[cfg(not(windows))]
    #[test]
    fn push_with_cd_to_cadence_hooks_nudges() {
        let repo = crate::github_origin_repo();
        let path = repo.path().to_string_lossy();
        let cmd = format!("cd {path} && git push origin main");
        let input = make_bash_with_cwd(&cmd, "/tmp");
        let result = NudgeUpgradeAfterPush.run(&input);
        assert_eq!(
            result.outcome,
            Outcome::Nudge,
            "cd + push should detect cadence-hooks repo via parse_work_dir"
        );
    }

    /// The #893 shape end to end: a heredoc whose body reads like a push to
    /// main, run from the cadence-hooks repo while it sits on main, is silent.
    #[test]
    fn heredoc_mentioning_a_push_to_main_allows() {
        let repo = crate::github_origin_repo();
        let cwd = repo.path().to_string_lossy();
        // Control: a real push from the same checkout nudges.
        let control = make_bash_with_cwd("git push origin main", &cwd);
        assert_eq!(NudgeUpgradeAfterPush.run(&control).outcome, Outcome::Nudge);

        let cmd = "python3 - <<'EOF'\nimport pathlib\n# after review: git push origin main\nEOF";
        let input = make_bash_with_cwd(cmd, &cwd);
        assert_eq!(
            NudgeUpgradeAfterPush.run(&input).outcome,
            Outcome::Allow,
            "a heredoc body is text, not a push"
        );
    }
}
