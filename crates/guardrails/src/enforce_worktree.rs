//! `enforce-worktree` — block mutations in a primary checkout of a branch-mode repo.
//!
//! The invariant this enforces: **every session works in its own worktree on its
//! own branch, or in a repo where `main` is the working branch by design**
//! (dotfiles, vaults — marked with `CADENCE_ALLOW_MAIN`). Sessions in separate
//! worktrees cannot collide on checkout state, which is what lets the advisory
//! multi-session coordination layer (cadence-canon) retire — see
//! claude-configurations ADR-0030.
//!
//! Blocks (exit 2) when a file mutation (`Edit`/`Write`/`MultiEdit`) or a Bash
//! `git commit` targets the **primary checkout** (`.git` is a directory) of a
//! branch-mode repo. A linked worktree's `.git` is a file, so worktrees pass
//! untouched — that is the point.
//!
//! Exemptions (→ allow):
//! - `CADENCE_ALLOW_MAIN` truthy — the existing main-only-repo marker; a repo
//!   that works on `main` by design has no worktree discipline to enforce.
//! - `CADENCE_NO_ENFORCE_WORKTREE` truthy — user-global kill switch for the
//!   proving period; rollback without uninstalling.
//! - Repo root under a temp directory (`/tmp`, `/private/tmp`, `$TMPDIR`) —
//!   scratch and fixture repos are not the long-lived checkouts this guards.
//! - Paths inside a `.claude/` directory or under `docs/plans/` — same
//!   carve-outs as `warn-main-branch` (issues #33, #35, #226).
//! - Active snooze via `cadence-hooks guardrails dismiss-enforce-worktree
//!   --for <duration>` — the one-off escape (e.g. committing a plan doc on the
//!   default branch).
//! - Not a git repo, or git unavailable — fail open (ADR-0001).
//!
//! Known misses, accepted by design (this is a discipline guard, not a security
//! boundary): file mutations via bash (`sed -i`, redirects) are not inspected —
//! the `git commit` arm is the persistence backstop; `git --work-tree=…` /
//! `--git-dir=…` commit forms and commits wrapped in `sh -c '…'` skip the check
//! (the target tree cannot be cheaply resolved — ambiguity fails open).
//! Env-prefixed forms (`VAR=x git commit`) are missed too — the leading word
//! isn't `git` — and a `GIT_DIR=`/`GIT_WORK_TREE=` prefix can even invert the
//! target (a rare false block when committing into a worktree *from* the
//! primary via env); both accepted as exotic. A
//! `git -C <path> commit` IS resolved against `<path>`, so committing into the
//! primary from elsewhere still blocks, and committing into a worktree from
//! the primary does not — and so is a leading `cd <path> && git commit` (or a
//! chain of `cd`s), resolved with `~` expansion, quoted paths, and multiple
//! `cd`s accumulating, always assuming a `cd` succeeds even when followed by
//! `||` (a hard security boundary cannot reuse `parse_work_dir`'s nudge-only
//! `cd` heuristic, which treats a `cd` before `||` as a no-op — see
//! [`git_commit_targets`] for why that heuristic is unsafe here; issues #213,
//! #224).

use crate::dismiss_enforce_worktree;
use crate::warn_main_branch::{git_dir_for_input, is_claude_managed_dir, is_plan_doc_dir};
use crate::warn_subagent_worktree::is_primary_checkout;
use cadence_hooks_core::shell::{resolve_cd_target, split_segments_with_ops, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Pure: classify a truthy env value (`1`/`true`/`yes`, trimmed,
/// case-insensitive). Mirrors `warn_main_branch::is_main_allowed_value`.
fn is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Environment inputs resolved once per invocation, injected into the
/// assessment so tests can pin them without touching process env.
struct EnvConfig {
    /// `CADENCE_ALLOW_MAIN` — repo works on main by design (dotfiles, vaults).
    allow_main: bool,
    /// `CADENCE_NO_ENFORCE_WORKTREE` — user-global kill switch.
    kill_switch: bool,
    /// `$TMPDIR`, for the scratch-repo exemption.
    tmpdir: Option<String>,
}

impl EnvConfig {
    fn from_env() -> Self {
        let truthy = |var: &str| is_truthy(std::env::var(var).ok().as_deref());
        Self {
            allow_main: truthy("CADENCE_ALLOW_MAIN"),
            kill_switch: truthy("CADENCE_NO_ENFORCE_WORKTREE"),
            tmpdir: std::env::var("TMPDIR").ok(),
        }
    }
}

/// Pure: is `repo_root` inside a temp tree? `tmpdir` is the `$TMPDIR` value,
/// when set. Scratch/fixture repos live here; enforcing worktree discipline on
/// them would only produce noise.
fn is_temp_root(repo_root: &Path, tmpdir: Option<&str>) -> bool {
    let fixed = repo_root.starts_with("/tmp") || repo_root.starts_with("/private/tmp");
    let via_env = tmpdir
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "/")
        .is_some_and(|t| {
            // `repo_root` comes from `git rev-parse --show-toplevel`, which
            // canonicalizes (`/private/var/…` on macOS) while `$TMPDIR` does
            // not (`/var/folders/…`) — compare against the canonicalized
            // tmpdir too, or the exemption never fires on macOS.
            repo_root.starts_with(t)
                || std::fs::canonicalize(t)
                    .is_ok_and(|c| c != Path::new("/") && repo_root.starts_with(&c))
        });
    fixed || via_env
}

/// A resolved commit target directory (absolute, or built by joining `cwd`
/// with the accumulated `cd`s and/or a `-C` redirect — see
/// [`git_commit_targets`]).
type CommitTarget = String;

/// Pure: walk `command` segment by segment (heredoc bodies stripped, quotes
/// respected — see [`split_segments_with_ops`]), tracking the effective
/// working directory through any `cd` prefix, and for each segment whose
/// **leading** word is `git` and whose subcommand is `commit`, return where
/// that commit lands.
///
/// A `cd <path>` segment updates the tracked directory the same way
/// `parse_work_dir` does for other guards: `~` expands and relative targets
/// accumulate onto the running directory. Unlike `parse_work_dir` (which
/// feeds soft nudges on six other guards and is out of scope here), a `cd`
/// immediately followed by `||` still updates the tracked directory
/// unconditionally — this path gates a hard security boundary, and bash's
/// `||`/`&&` share equal precedence and left-associate, so `cd <dir> || true
/// && git commit` runs the commit *inside* `<dir>` whenever the `cd`
/// succeeds. Treating that `cd` as a no-op (matching `parse_work_dir`'s
/// nudge-oriented heuristic) would let a commit into a different primary
/// checkout slip through judged against the pre-cd cwd — a silent guard
/// bypass, not a false block (issue-review finding on #213/#224's fix). The
/// safe assumption for this boundary is that the `cd` succeeds — but only
/// when its target can actually be read: `cd`'s own option flags (`-P`,
/// `-L`, `--`) are skipped to find the real path argument, and a bare `-`
/// (go to `$OLDPWD`), an unexpanded shell variable (`$VAR`), or no path
/// argument at all (bare `cd`, or all flags with nothing after) are treated
/// as unresolvable — the pre-cd directory is kept for subsequent segments
/// rather than building a bogus path string from a misread flag or an
/// unexpandable token, which would resolve to no repo and fail open exactly
/// like a genuinely nonexistent directory (issue-review finding on this same
/// fix: `cd -P . && git commit` from a primary checkout previously misread
/// `-P` as the target, producing a path that resolves to no repo, and thus
/// Allowed a commit the cd-blind pre-fix code correctly blocked). An
/// occasional false block on a `cd` that actually fails is acceptable, and a
/// `cd` into a nonexistent directory still resolves to Allow downstream
/// (`repo_root_for` finds no repo there — ADR-0001), matching real bash's
/// behavior of the `|| exit`/`|| return` idiom never reaching the commit at
/// all. A `git -C <path> commit` still overrides the tracked directory for
/// that one segment, exactly as before (issue #213's fix generalizes rather
/// than replaces `-C` handling); a relative `-C <path>` resolves against the
/// tracked directory rather than the raw process cwd, since that is what the
/// shell would actually do if a prior `cd` already moved it. Segments using
/// `--work-tree`/`--git-dir` are skipped entirely — the target tree is
/// ambiguous, and ambiguity fails open. `-c <key>=<val>` pairs are walked over
/// (value consumed) so the subcommand is still found behind inline config.
///
/// The leading-word discipline mirrors `is_branch_switch` in the session
/// crate: a `git commit` quoted in prose or a heredoc body is not this session
/// committing.
fn git_commit_targets(command: &str, cwd: &str) -> Vec<CommitTarget> {
    let mut targets = Vec::new();
    let mut effective_dir = cwd.to_string();

    for (segment, _next_op) in split_segments_with_ops(command) {
        let tokens = tokenize(&segment);
        if tokens.first().map(String::as_str) == Some("cd") {
            // Always assume the cd succeeds — see the doc comment above for
            // why this path cannot reuse parse_work_dir's `|| means no-op`
            // heuristic. But only trust a target this resolver can actually
            // read: skip cd's own option flags (`-P`, `-L`, `--`) to find the
            // real path argument, and treat a bare `-` (go to $OLDPWD), an
            // unexpanded shell variable (`$VAR`), or no path argument at all
            // (bare `cd`, or all flags with nothing after) as unresolvable —
            // keep the pre-cd directory for subsequent segments rather than
            // building a bogus path string that resolves to no repo and
            // fails open downstream (`assess_dir`'s ADR-0001 Allow is correct
            // for "not a repo", not for "the cd's real target was never
            // examined").
            let mut idx = 1;
            while tokens
                .get(idx)
                .is_some_and(|t| t == "--" || (t.starts_with('-') && t != "-"))
            {
                idx += 1;
            }
            if let Some(target) = tokens.get(idx)
                && target != "-"
                && !target.starts_with('$')
            {
                effective_dir = resolve_cd_target(target, &effective_dir);
            }
            continue;
        }

        let ws_tokens: Vec<&str> = segment.split_whitespace().collect();
        if ws_tokens.first() != Some(&"git") {
            continue;
        }
        // Walk git's own global flags to find the subcommand, capturing a
        // `-C <path>` redirect on the way.
        let mut redirect: Option<&str> = None;
        let mut ambiguous = false;
        let mut idx = 1;
        while idx < ws_tokens.len()
            && (ws_tokens[idx].starts_with('-')
                || ws_tokens[idx - 1] == "-C"
                || ws_tokens[idx - 1] == "-c")
        {
            let t = ws_tokens[idx];
            if ws_tokens[idx - 1] == "-C" {
                redirect = Some(t);
            } else if t == "--work-tree"
                || t == "--git-dir"
                || t.starts_with("--work-tree=")
                || t.starts_with("--git-dir=")
            {
                ambiguous = true;
            }
            idx += 1;
        }
        if ambiguous {
            continue;
        }
        if ws_tokens.get(idx) == Some(&"commit") {
            let target = match redirect {
                Some(path) if Path::new(path).is_absolute() => path.to_string(),
                Some(path) => format!("{effective_dir}/{path}"),
                None => effective_dir.clone(),
            };
            targets.push(target);
        }
    }
    targets
}

/// Pure decision, all environment resolved by the caller.
fn should_block(
    is_primary: bool,
    allowed_main: bool,
    kill_switch: bool,
    temp_root: bool,
    snoozed: bool,
) -> bool {
    is_primary && !allowed_main && !kill_switch && !temp_root && !snoozed
}

/// The block message: names the checkout and every escape hatch. When
/// `origin_repo` names a *different* repo than `repo_root` — a `cd <dir> &&
/// git commit` (or a `-C <dir>`) that redirected the target elsewhere from
/// where the shell started — an extra line acknowledges the redirect, so the
/// block reads as "this command targets repo X" rather than misattributing
/// the policy to the repo the shell happened to start in (issue #224).
fn block_message(repo_root: &str, origin_repo: Option<&str>) -> String {
    let mut msg = format!(
        "Blocked: `{repo_root}` is a primary checkout — feature work belongs in a worktree, \
         not the shared primary tree.\n\
         Create one: `git worktree add .claude/worktrees/<slug> -b feat/<slug>` \
         (or EnterWorktree / `/worktree create feat <slug>`), then work there.\n\
         One-off exception: `cadence-hooks guardrails dismiss-enforce-worktree --for 30m`\n\
         Repo works on main by design (dotfiles, vaults)? Set CADENCE_ALLOW_MAIN=true in \
         .claude/settings.json's env block.\n\
         Disable everywhere: CADENCE_NO_ENFORCE_WORKTREE=1"
    );
    if let Some(origin) = origin_repo
        && origin != repo_root
    {
        msg.push_str(&format!(
            "\nThis command targets `{repo_root}` (via `cd`/`-C`), judged against that repo — \
             not `{origin}`, where the shell started."
        ));
    }
    msg
}

/// Resolve the repo root enclosing `dir`, if any.
fn repo_root_for(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["-C", &dir.to_string_lossy(), "rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if root.is_empty() { None } else { Some(root) }
}

/// Evaluate one candidate directory: allow, or block with the message.
/// `origin_repo`, when set, names the repo the command's cwd started in — used
/// only to decide whether the block message needs to acknowledge a `cd`/`-C`
/// redirect to a *different* repo (issue #224); `None` for the Edit/Write arm,
/// where there is no such redirect to name.
fn assess_dir(dir: &Path, cfg: &EnvConfig, origin_repo: Option<&str>) -> CheckResult {
    if is_claude_managed_dir(dir) || is_plan_doc_dir(dir) {
        return CheckResult::allow();
    }
    let Some(repo_root) = repo_root_for(dir) else {
        // Not a git repo (or a bare container dir) — nothing to enforce.
        return CheckResult::allow();
    };
    let blocked = should_block(
        is_primary_checkout(&repo_root),
        cfg.allow_main,
        cfg.kill_switch,
        is_temp_root(Path::new(&repo_root), cfg.tmpdir.as_deref()),
        dismiss_enforce_worktree::is_snoozed_now(Path::new(&repo_root)),
    );
    if blocked {
        CheckResult::block(block_message(&repo_root, origin_repo))
    } else {
        CheckResult::allow()
    }
}

/// Testable core: assess the hook input under the given environment.
fn run_enforce(input: &HookInput, cfg: &EnvConfig) -> CheckResult {
    match input.tool_name() {
        Some("Edit") | Some("Write") | Some("MultiEdit") => {
            if input.file_path().is_none() {
                // No target file — nothing to assess, fail open.
                return CheckResult::allow();
            }
            assess_dir(&git_dir_for_input(input), cfg, None)
        }
        Some("Bash") => {
            let Some(command) = input.command() else {
                return CheckResult::allow();
            };
            let cwd = input.cwd.as_deref().unwrap_or(".");
            // Resolved once per invocation: the repo the shell started in,
            // used only to decide whether a redirect crossed repo boundaries.
            let cwd_repo_root = repo_root_for(Path::new(cwd));
            for target in git_commit_targets(command, cwd) {
                let dir = PathBuf::from(&target);
                let result = assess_dir(&dir, cfg, cwd_repo_root.as_deref());
                if result.outcome != Outcome::Allow {
                    return result;
                }
            }
            CheckResult::allow()
        }
        _ => CheckResult::allow(),
    }
}

/// Block mutations in a primary checkout of a branch-mode repo.
pub struct EnforceWorktree;

impl Check for EnforceWorktree {
    fn name(&self) -> &str {
        "enforce-worktree"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        run_enforce(input, &EnvConfig::from_env())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::{make_bash, make_edit};

    fn cfg(allow_main: bool, kill_switch: bool) -> EnvConfig {
        EnvConfig {
            allow_main,
            kill_switch,
            tmpdir: None,
        }
    }

    // --- should_block (pure decision) ---

    #[test]
    fn primary_branch_mode_blocks() {
        assert!(should_block(true, false, false, false, false));
    }

    #[test]
    fn worktree_allows() {
        assert!(!should_block(false, false, false, false, false));
    }

    #[test]
    fn allow_main_repo_allows() {
        // Dotfiles/vaults: main is the working branch by design.
        assert!(!should_block(true, true, false, false, false));
    }

    #[test]
    fn kill_switch_allows() {
        assert!(!should_block(true, false, true, false, false));
    }

    #[test]
    fn temp_root_allows() {
        assert!(!should_block(true, false, false, true, false));
    }

    #[test]
    fn snoozed_allows() {
        assert!(!should_block(true, false, false, false, true));
    }

    // --- is_truthy ---

    #[test]
    fn truthy_values() {
        assert!(is_truthy(Some("1")));
        assert!(is_truthy(Some("true")));
        assert!(is_truthy(Some("YES")));
        assert!(is_truthy(Some("  true  ")));
    }

    #[test]
    fn falsy_values() {
        assert!(!is_truthy(None));
        assert!(!is_truthy(Some("")));
        assert!(!is_truthy(Some("0")));
        assert!(!is_truthy(Some("false")));
        assert!(!is_truthy(Some("off")));
    }

    // --- is_temp_root ---

    #[test]
    fn tmp_roots_are_temp() {
        assert!(is_temp_root(Path::new("/tmp/scratch-repo"), None));
        assert!(is_temp_root(Path::new("/private/tmp/fixture"), None));
    }

    #[test]
    fn tmpdir_env_root_is_temp() {
        assert!(is_temp_root(
            Path::new("/var/folders/xy/T/repo"),
            Some("/var/folders/xy/T")
        ));
    }

    #[test]
    fn home_repo_is_not_temp() {
        assert!(!is_temp_root(Path::new("/Users/dev/Projects/repo"), None));
        // A degenerate `$TMPDIR=/` must not exempt everything.
        assert!(!is_temp_root(
            Path::new("/Users/dev/Projects/repo"),
            Some("/")
        ));
        assert!(!is_temp_root(
            Path::new("/Users/dev/Projects/repo"),
            Some("")
        ));
    }

    #[test]
    fn temp_lookalike_is_not_temp() {
        // Path-component boundary: /tmpfoo is not under /tmp.
        assert!(!is_temp_root(Path::new("/tmpfoo/repo"), None));
    }

    #[test]
    #[cfg(unix)]
    fn tmpdir_env_canonicalization_mismatch_is_temp() {
        // macOS: `git rev-parse --show-toplevel` canonicalizes
        // (`/private/var/…`) while `$TMPDIR` stays `/var/folders/…` — the
        // exemption must fire anyway. Simulated with a symlinked tmpdir under
        // the non-temp scratch root (`Scratch` is defined with the
        // end-to-end tests below).
        let scratch = Scratch::new("tmpdir-canon");
        let real = scratch.0.join("real");
        let link = scratch.0.join("link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let repo_root = std::fs::canonicalize(&real).unwrap().join("repo");
        assert!(is_temp_root(&repo_root, Some(link.to_str().unwrap())));
    }

    // --- git_commit_targets (pure parsing) ---

    #[test]
    fn plain_commit_targets_cwd() {
        assert_eq!(
            git_commit_targets("git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn commit_with_flags_targets_cwd() {
        assert_eq!(
            git_commit_targets("git commit --amend --no-edit", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn dash_c_commit_targets_redirect() {
        assert_eq!(
            git_commit_targets("git -C /some/worktree commit -m 'x'", "/cwd"),
            vec!["/some/worktree".to_string()]
        );
    }

    #[test]
    fn inline_config_commit_targets_cwd() {
        // `git -c key=val commit` — the -c value must be consumed, not end
        // the flag walk (else the commit is silently missed).
        assert_eq!(
            git_commit_targets("git -c user.email=x@y.z commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("git -c commit.gpgsign=false -C /wt commit -m 'x'", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn chained_commit_found() {
        assert_eq!(
            git_commit_targets(
                "git add src/main.rs && git commit -m 'x' && git push",
                "/cwd"
            ),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn non_commit_git_ignored() {
        assert!(git_commit_targets("git status", "/cwd").is_empty());
        assert!(git_commit_targets("git add -A", "/cwd").is_empty());
        assert!(git_commit_targets("git push origin main", "/cwd").is_empty());
    }

    #[test]
    fn non_leading_git_ignored() {
        // Prose and echoes are not this session committing.
        assert!(git_commit_targets("echo git commit -m 'x'", "/cwd").is_empty());
    }

    #[test]
    fn heredoc_body_commit_ignored() {
        // split_segments strips heredoc bodies — a commit mentioned in a
        // document being written is not a commit being run.
        assert!(
            git_commit_targets(
                "cat > notes.md <<'EOF'\nrun: git commit -m fix\nEOF",
                "/cwd"
            )
            .is_empty()
        );
    }

    #[test]
    fn work_tree_form_is_skipped() {
        // Ambiguous target tree → fail open, documented miss.
        assert!(git_commit_targets("git --work-tree=/other commit -m 'x'", "/cwd").is_empty());
        assert!(git_commit_targets("git --git-dir=/o/.git commit -m 'x'", "/cwd").is_empty());
    }

    #[test]
    fn multiple_commits_all_reported() {
        assert_eq!(
            git_commit_targets("git -C /a commit -m x; git commit -m y", "/cwd"),
            vec!["/a".to_string(), "/cwd".to_string()]
        );
    }

    // --- git_commit_targets: cd-prefix resolution (issues #213, #224) ---

    #[test]
    fn cd_redirects_commit_target() {
        assert_eq!(
            git_commit_targets("cd /wt && git commit -m 'x'", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn cd_quoted_path_redirects() {
        assert_eq!(
            git_commit_targets(r#"cd "/path with space" && git commit -m 'x'"#, "/cwd"),
            vec!["/path with space".to_string()]
        );
        assert_eq!(
            git_commit_targets("cd '/path with space' && git commit -m 'x'", "/cwd"),
            vec!["/path with space".to_string()]
        );
    }

    #[test]
    fn cd_tilde_redirects() {
        let targets = git_commit_targets("cd ~/x && git commit -m 'x'", "/cwd");
        assert_eq!(targets.len(), 1);
        assert!(targets[0].contains("x"), "tilde not expanded: {targets:?}");
        assert!(
            !targets[0].starts_with("/cwd"),
            "tilde target should not fall back to cwd: {targets:?}"
        );
    }

    #[test]
    fn chained_cd_accumulates() {
        assert_eq!(
            git_commit_targets("cd a && cd b && git commit -m 'x'", "/cwd"),
            vec!["/cwd/a/b".to_string()]
        );
    }

    #[test]
    fn cd_before_or_still_redirects_assuming_success() {
        // Issue-review finding: `parse_work_dir`'s "cd before `||` is a
        // no-op" heuristic is unsafe here. bash's `||`/`&&` are equal
        // precedence and left-associate, so `cd x || true && git commit`
        // (and, per this test, `cd x || exit; git commit`) commits *inside*
        // `x` whenever the cd succeeds — this path must assume success and
        // always redirect, or a cd into a different primary checkout would
        // slip through judged against the pre-cd cwd.
        assert_eq!(
            git_commit_targets("cd x || exit; git commit -m 'x'", "/cwd"),
            vec!["/cwd/x".to_string()]
        );
    }

    #[test]
    fn cd_nonexistent_dir_still_resolves_a_target_string() {
        // A `cd` into a directory that doesn't exist still updates the
        // tracked path (assume-success is unconditional) — the resulting
        // target simply won't resolve to a repo downstream (fail-open,
        // ADR-0001), which lands on the same practical outcome as real bash
        // never reaching the commit (the `|| exit` idiom fires instead).
        assert_eq!(
            git_commit_targets("cd ./does-not-exist-xyz || exit; git commit -m 'x'", "/cwd"),
            vec!["/cwd/./does-not-exist-xyz".to_string()]
        );
    }

    #[test]
    fn cd_then_multiple_commits_both_redirected() {
        assert_eq!(
            git_commit_targets("cd /wt && git commit -m a && git commit -m b", "/cwd"),
            vec!["/wt".to_string(), "/wt".to_string()]
        );
    }

    #[test]
    fn cd_flag_tokens_skipped_to_find_real_target() {
        // Issue-review finding on this fix: `cd`'s own option flags must not
        // be misread as the path argument.
        assert_eq!(
            git_commit_targets("cd -P . && git commit -m 'x'", "/cwd"),
            vec!["/cwd/.".to_string()]
        );
        assert_eq!(
            git_commit_targets("cd -- . && git commit -m 'x'", "/cwd"),
            vec!["/cwd/.".to_string()]
        );
    }

    #[test]
    fn cd_unexpanded_variable_keeps_pre_cd_dir() {
        // `cd $DIR` — an unexpanded shell variable cannot be resolved here;
        // keep the pre-cd directory rather than building a bogus path.
        assert_eq!(
            git_commit_targets("cd $DIR && git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn cd_dash_previous_dir_keeps_pre_cd_dir() {
        // `cd -` (go to $OLDPWD) is unknowable at guard-eval time.
        assert_eq!(
            git_commit_targets("cd - && git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn bare_cd_keeps_pre_cd_dir() {
        assert_eq!(
            git_commit_targets("cd; git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn dash_c_still_overrides_cd() {
        // An explicit `-C` on a segment wins over whatever `cd` accumulated.
        assert_eq!(
            git_commit_targets("cd /wt && git -C /other commit -m 'x'", "/cwd"),
            vec!["/other".to_string()]
        );
    }

    // --- block message ---

    #[test]
    fn message_names_every_escape_hatch() {
        let msg = block_message("/Users/dev/repo", None);
        assert!(msg.contains("/Users/dev/repo"));
        assert!(msg.contains("git worktree add"));
        assert!(msg.contains("dismiss-enforce-worktree"));
        assert!(msg.contains("CADENCE_ALLOW_MAIN"));
        assert!(msg.contains("CADENCE_NO_ENFORCE_WORKTREE"));
    }

    #[test]
    fn message_omits_redirect_note_when_same_repo() {
        let msg = block_message("/Users/dev/repo", Some("/Users/dev/repo"));
        assert!(!msg.contains("where the shell started"));
    }

    #[test]
    fn message_names_redirect_when_origin_differs() {
        let msg = block_message("/Users/dev/mono", Some("/Users/dev/meta"));
        assert!(msg.contains("targets `/Users/dev/mono`"));
        assert!(msg.contains("/Users/dev/meta"));
        assert!(msg.contains("where the shell started"));
    }

    // --- end-to-end against real repos ---
    //
    // The scratch root lives under the workspace `target/` dir, NOT a tempdir:
    // the temp-root exemption would otherwise mask the block path entirely.

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/enforce-worktree-scratch")
                .join(format!("{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed in {dir:?}");
    }

    fn init_repo(dir: &Path) {
        git_in(dir, &["init", "-q", "-b", "main"]);
        git_in(dir, &["config", "user.email", "t@t"]);
        git_in(dir, &["config", "user.name", "t"]);
        std::fs::write(dir.join("f.txt"), "x").unwrap();
        git_in(dir, &["add", "f.txt"]);
        git_in(dir, &["commit", "-q", "-m", "init"]);
    }

    /// Primary repo + linked worktree under a non-temp scratch root.
    fn primary_and_worktree(scratch: &Scratch) -> (PathBuf, PathBuf) {
        let primary = scratch.0.join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        let wt = scratch.0.join("wt");
        git_in(
            &primary,
            &["worktree", "add", &wt.to_string_lossy(), "-b", "feat/x"],
        );
        (primary, wt)
    }

    #[test]
    fn edit_in_primary_blocks_and_in_worktree_allows() {
        let scratch = Scratch::new("edit");
        let (primary, wt) = primary_and_worktree(&scratch);

        let file = primary.join("src.rs");
        let input = make_edit(&file.to_string_lossy(), "a", "b");
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "primary checkout must block");
        let msg = r.message.unwrap();
        assert!(msg.contains("worktree"), "fix named in message: {msg}");

        let file = wt.join("src.rs");
        let input = make_edit(&file.to_string_lossy(), "a", "b");
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "linked worktree must pass");
    }

    #[test]
    fn allow_main_and_kill_switch_exempt_primary() {
        let scratch = Scratch::new("env");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let file = primary.join("src.rs");
        let input = make_edit(&file.to_string_lossy(), "a", "b");

        let r = run_enforce(&input, &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow, "CADENCE_ALLOW_MAIN exempts");
        let r = run_enforce(&input, &cfg(false, true));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "CADENCE_NO_ENFORCE_WORKTREE exempts"
        );
    }

    #[test]
    fn claude_dir_and_plan_docs_exempt_in_primary() {
        let scratch = Scratch::new("carveouts");
        let (primary, _wt) = primary_and_worktree(&scratch);

        for sub in [".claude/worktrees/x/src.rs", "docs/plans/2026-07-02-p.md"] {
            let file = primary.join(sub);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            let input = make_edit(&file.to_string_lossy(), "a", "b");
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Allow, "carve-out for {sub}");
        }
    }

    #[test]
    fn snooze_marker_exempts_primary() {
        let scratch = Scratch::new("snooze");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let marker = dismiss_enforce_worktree::marker_path_for(&primary).unwrap();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        std::fs::write(&marker, format!("{until}\n")).unwrap();

        let file = primary.join("src.rs");
        let input = make_edit(&file.to_string_lossy(), "a", "b");
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "active snooze exempts");
    }

    #[test]
    fn commit_in_primary_blocks_and_in_worktree_allows() {
        let scratch = Scratch::new("commit");
        let (primary, wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "commit in primary must block");

        let mut input = make_bash("git add f.txt && git commit -m 'x'");
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "commit in worktree must pass");

        // `git -C <worktree> commit` from the primary resolves to the worktree.
        let mut input = make_bash(&format!("git -C {} commit -m 'x'", wt.to_string_lossy()));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "-C redirect into a worktree must pass"
        );

        // …and the reverse still blocks.
        let mut input = make_bash(&format!(
            "git -C {} commit -m 'x'",
            primary.to_string_lossy()
        ));
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "-C redirect into the primary must block"
        );
    }

    #[test]
    fn cd_into_worktree_allows_commit() {
        // The bug this fixes (issue #213): `cd <worktree> && git commit`, run
        // from a primary checkout's cwd, targets the worktree exactly like the
        // already-honored `git -C <worktree> commit` does.
        let scratch = Scratch::new("cd-wt");
        let (primary, wt) = primary_and_worktree(&scratch);

        let mut input = make_bash(&format!("cd {} && git commit -m 'x'", wt.to_string_lossy()));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "cd into a worktree then commit must pass"
        );
    }

    #[test]
    fn cd_into_other_primary_blocks_and_names_target_repo() {
        // Issue #224: the target repo of a `cd <dir> && git commit` may be a
        // different primary checkout than the one the shell started in — it
        // must still be judged (and named) against the target, not the origin.
        let scratch = Scratch::new("cd-other-primary");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.0.join("other-repo");
        std::fs::create_dir(&other_primary).unwrap();
        init_repo(&other_primary);

        let mut input = make_bash(&format!(
            "cd {} && git commit -m 'x'",
            other_primary.to_string_lossy()
        ));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "cd into a different primary checkout must still block"
        );
        let msg = r.message.unwrap();
        // `repo_root_for` resolves through `git rev-parse --show-toplevel`,
        // which canonicalizes the path — compare against that, not the
        // literal (possibly `..`-relative) `other_primary` we built it from.
        let other_primary_canon = std::fs::canonicalize(&other_primary).unwrap();
        assert!(
            msg.contains(&other_primary_canon.to_string_lossy().to_string()),
            "message names the target repo: {msg}"
        );
        assert!(
            msg.contains("where the shell started"),
            "message acknowledges the cd redirect: {msg}"
        );
    }

    #[test]
    fn cd_before_or_true_still_blocks_other_primary() {
        // Issue-review finding on the #213/#224 fix: `cd <dir> || true &&
        // git commit` commits *inside* `<dir>` whenever the cd succeeds
        // (bash's `||`/`&&` are equal precedence and left-associate) — a
        // pure-string unit test can't catch this, since the bypass only
        // shows up once a real fixture repo is judged. cwd is the *worktree*
        // (allowed to commit on its own), so a bypass here would slip an
        // other-primary commit through as if it were the worktree.
        let scratch = Scratch::new("cd-or-true");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.0.join("other-repo");
        std::fs::create_dir(&other_primary).unwrap();
        init_repo(&other_primary);

        let mut input = make_bash(&format!(
            "cd {} || true && git commit -m 'x'",
            other_primary.to_string_lossy()
        ));
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "cd-into-other-primary via `|| true &&` must still block, not slip through as the worktree cwd"
        );
        let msg = r.message.unwrap();
        let other_primary_canon = std::fs::canonicalize(&other_primary).unwrap();
        assert!(
            msg.contains(&other_primary_canon.to_string_lossy().to_string()),
            "message names the target repo: {msg}"
        );
    }

    #[test]
    fn cd_dash_p_flag_still_blocks_from_primary() {
        // Issue-review finding 2 (PR #226 review): the cd handler took
        // tokens.get(1) unconditionally as the target, without skipping cd's
        // own option flags — `cd -P .` misread "-P" as the target, producing
        // a bogus "<primary>/-P" path that resolves to no repo (fail-open
        // Allow), a regression this fix introduced relative to the pre-fix
        // cd-blind code (which judged cwd=primary and correctly blocked).
        let scratch = Scratch::new("cd-dash-p");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd -P . && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_double_dash_flag_still_blocks_from_primary() {
        let scratch = Scratch::new("cd-double-dash");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd -- . && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_unexpanded_variable_target_blocks_judged_against_pre_cd_dir() {
        // `cd $DIR` — an unresolvable shell variable must not produce a
        // bogus "<primary>/$DIR" path that dodges repo detection; the pre-cd
        // directory (the primary) is judged instead.
        let scratch = Scratch::new("cd-dollar-var");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd $DIR && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_dash_previous_dir_target_blocks_judged_against_pre_cd_dir() {
        // `cd -` (go to $OLDPWD) is unknowable at guard-eval time; the pre-cd
        // directory is judged instead of a bogus "<primary>/-" path.
        let scratch = Scratch::new("cd-dash");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd - && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_nonexistent_or_exit_fails_open_sanely() {
        // `cd <nonexistent> || exit; git commit` — in real bash the cd fails
        // (no such directory), `|| exit` fires, and the commit never runs at
        // all. The guard resolves the (nonexistent, hence repo-less)
        // directory and fails open to Allow (ADR-0001) — same practical
        // outcome, different reason, still sane.
        let scratch = Scratch::new("cd-nonexistent");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd ./does-not-exist-xyz || exit; git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn dismiss_repo_flag_snoozes_target_not_cwd() {
        // Mirrors what `dismiss-enforce-worktree --repo <other_primary>` writes
        // (run_dismiss exits the process, so it isn't unit-testable directly —
        // same pattern as `snooze_marker_exempts_primary` above). Confirms the
        // guard reads the snooze off the *target* repo, so a dismiss keyed to
        // the target (not the shell's cwd) is what actually unblocks it.
        let scratch = Scratch::new("dismiss-repo");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.0.join("other-repo");
        std::fs::create_dir(&other_primary).unwrap();
        init_repo(&other_primary);

        let mut input = make_bash(&format!(
            "cd {} && git commit -m 'x'",
            other_primary.to_string_lossy()
        ));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "blocked before the dismiss");

        let marker = dismiss_enforce_worktree::marker_path_for(&other_primary).unwrap();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        std::fs::write(&marker, format!("{until}\n")).unwrap();

        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "snoozing the target repo (not the shell's cwd) unblocks the redirected commit"
        );
    }

    #[test]
    fn missing_dir_fails_open() {
        // A directory git cannot resolve (nonexistent path) → no repo root →
        // allow. ADR-0001: the guard's own failure never blocks.
        assert!(repo_root_for(Path::new("/nonexistent-enforce-worktree")).is_none());
        let input = make_edit("/nonexistent-enforce-worktree/f.rs", "a", "b");
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // --- tool gating ---

    #[test]
    fn read_tool_allows() {
        let input = HookInput {
            tool_name: Some("Read".into()),
            ..Default::default()
        };
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn edit_without_file_path_allows() {
        let input = HookInput {
            tool_name: Some("Edit".into()),
            ..Default::default()
        };
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn bash_without_commit_allows() {
        let mut input = make_bash("git status && cargo test");
        input.cwd = Some("/".into());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
    }
}
