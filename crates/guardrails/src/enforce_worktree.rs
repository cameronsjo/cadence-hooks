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
//! the primary does not.

use crate::dismiss_enforce_worktree;
use crate::warn_main_branch::{git_dir_for_input, is_claude_managed_dir, is_plan_doc_dir};
use crate::warn_subagent_worktree::is_primary_checkout;
use cadence_hooks_core::shell::split_segments;
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

/// The per-segment commit target: `-C <path>` when the commit redirects there,
/// `None` for the current directory.
type CommitTarget = Option<String>;

/// Pure: for each `&&`/`;`/`|`-separated segment (heredoc bodies stripped by
/// [`split_segments`]) whose **leading** word is `git` and whose subcommand is
/// `commit`, return where that commit lands: `Some(path)` for `git -C <path>
/// commit`, `None` for the cwd. Segments using `--work-tree`/`--git-dir` are
/// skipped entirely — the target tree is ambiguous, and ambiguity fails open.
/// `-c <key>=<val>` pairs are walked over (value consumed) so the subcommand
/// is still found behind inline config.
///
/// The leading-word discipline mirrors `is_branch_switch` in the session
/// crate: a `git commit` quoted in prose or a heredoc body is not this session
/// committing.
fn git_commit_targets(command: &str) -> Vec<CommitTarget> {
    let mut targets = Vec::new();
    for segment in split_segments(command) {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        if tokens.first() != Some(&"git") {
            continue;
        }
        // Walk git's own global flags to find the subcommand, capturing a
        // `-C <path>` redirect on the way.
        let mut redirect: Option<&str> = None;
        let mut ambiguous = false;
        let mut idx = 1;
        while idx < tokens.len()
            && (tokens[idx].starts_with('-') || tokens[idx - 1] == "-C" || tokens[idx - 1] == "-c")
        {
            let t = tokens[idx];
            if tokens[idx - 1] == "-C" {
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
        if tokens.get(idx) == Some(&"commit") {
            targets.push(redirect.map(String::from));
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

/// The block message: names the checkout and every escape hatch.
fn block_message(repo_root: &str) -> String {
    format!(
        "Blocked: `{repo_root}` is a primary checkout — feature work belongs in a worktree, \
         not the shared primary tree.\n\
         Create one: `git worktree add .claude/worktrees/<slug> -b feat/<slug>` \
         (or EnterWorktree / `/worktree create feat <slug>`), then work there.\n\
         One-off exception: `cadence-hooks guardrails dismiss-enforce-worktree --for 30m`\n\
         Repo works on main by design (dotfiles, vaults)? Set CADENCE_ALLOW_MAIN=true in \
         .claude/settings.json's env block.\n\
         Disable everywhere: CADENCE_NO_ENFORCE_WORKTREE=1"
    )
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
fn assess_dir(dir: &Path, cfg: &EnvConfig) -> CheckResult {
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
        CheckResult::block(block_message(&repo_root))
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
            assess_dir(&git_dir_for_input(input), cfg)
        }
        Some("Bash") => {
            let Some(command) = input.command() else {
                return CheckResult::allow();
            };
            let cwd = input
                .cwd
                .as_deref()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            for target in git_commit_targets(command) {
                let dir = match target {
                    Some(path) => {
                        let p = PathBuf::from(&path);
                        if p.is_absolute() { p } else { cwd.join(p) }
                    }
                    None => cwd.clone(),
                };
                let result = assess_dir(&dir, cfg);
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
        assert_eq!(git_commit_targets("git commit -m 'x'"), vec![None]);
    }

    #[test]
    fn commit_with_flags_targets_cwd() {
        assert_eq!(
            git_commit_targets("git commit --amend --no-edit"),
            vec![None]
        );
    }

    #[test]
    fn dash_c_commit_targets_redirect() {
        assert_eq!(
            git_commit_targets("git -C /some/worktree commit -m 'x'"),
            vec![Some("/some/worktree".to_string())]
        );
    }

    #[test]
    fn inline_config_commit_targets_cwd() {
        // `git -c key=val commit` — the -c value must be consumed, not end
        // the flag walk (else the commit is silently missed).
        assert_eq!(
            git_commit_targets("git -c user.email=x@y.z commit -m 'x'"),
            vec![None]
        );
        assert_eq!(
            git_commit_targets("git -c commit.gpgsign=false -C /wt commit -m 'x'"),
            vec![Some("/wt".to_string())]
        );
    }

    #[test]
    fn chained_commit_found() {
        assert_eq!(
            git_commit_targets("git add src/main.rs && git commit -m 'x' && git push"),
            vec![None]
        );
    }

    #[test]
    fn non_commit_git_ignored() {
        assert!(git_commit_targets("git status").is_empty());
        assert!(git_commit_targets("git add -A").is_empty());
        assert!(git_commit_targets("git push origin main").is_empty());
    }

    #[test]
    fn non_leading_git_ignored() {
        // Prose and echoes are not this session committing.
        assert!(git_commit_targets("echo git commit -m 'x'").is_empty());
    }

    #[test]
    fn heredoc_body_commit_ignored() {
        // split_segments strips heredoc bodies — a commit mentioned in a
        // document being written is not a commit being run.
        assert!(
            git_commit_targets("cat > notes.md <<'EOF'\nrun: git commit -m fix\nEOF").is_empty()
        );
    }

    #[test]
    fn work_tree_form_is_skipped() {
        // Ambiguous target tree → fail open, documented miss.
        assert!(git_commit_targets("git --work-tree=/other commit -m 'x'").is_empty());
        assert!(git_commit_targets("git --git-dir=/o/.git commit -m 'x'").is_empty());
    }

    #[test]
    fn multiple_commits_all_reported() {
        assert_eq!(
            git_commit_targets("git -C /a commit -m x; git commit -m y"),
            vec![Some("/a".to_string()), None]
        );
    }

    // --- block message ---

    #[test]
    fn message_names_every_escape_hatch() {
        let msg = block_message("/Users/dev/repo");
        assert!(msg.contains("/Users/dev/repo"));
        assert!(msg.contains("git worktree add"));
        assert!(msg.contains("dismiss-enforce-worktree"));
        assert!(msg.contains("CADENCE_ALLOW_MAIN"));
        assert!(msg.contains("CADENCE_NO_ENFORCE_WORKTREE"));
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
