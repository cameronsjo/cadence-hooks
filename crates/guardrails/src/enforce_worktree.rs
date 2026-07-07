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
//! The two arms differ in *scope* by design (#238). The **Edit/Write arm** only
//! enforces on the session's **own** checkout — the target file's repo must be
//! the same repo the session's cwd is in. A write into any *other* repo (a note
//! into an Obsidian vault, a field report into `~/Documents`, a file dropped in
//! a sibling repo) is a foreign artifact-drop, not feature work in the session's
//! own shared tree, so it is out of scope and allowed. The **`git commit` arm**
//! is deliberately *not* so scoped: it judges every commit target, so
//! *persisting* into a foreign primary still blocks (issue #224) even where
//! *writing* a file there does not. The asymmetry is intentional — a stray write
//! is cheap and reversible; a commit onto another checkout's `main` is the
//! collision this guard exists to stop.
//!
//! Exemptions (→ allow):
//! - `CADENCE_ALLOW_MAIN` truthy — the existing main-only-repo marker; a repo
//!   that works on `main` by design has no worktree discipline to enforce.
//!   Resolved two ways: process env (session-wide), or — when process env
//!   doesn't set it — the resolved **target** repo's own tracked Claude
//!   settings (`.claude/settings.local.json` overriding `.claude/settings.json`'s
//!   `env` block), so a cross-repo mutation into a by-design-main repo is
//!   exempt without that repo being the session root. Absent/unparsable/
//!   non-scalar settings declare nothing and fall through — never a panic or
//!   an inverted verdict (ADR-0001).
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
//! `--git-dir=…` commit forms skip the check (the target tree cannot be cheaply
//! resolved — ambiguity fails open). Commits inside `sh -c '…'` wrappers,
//! `$(…)`/backtick substitutions, and behind `env`/`VAR=value` prefixes ARE
//! seen (#228) — any run of transparent-prefix or assignment words ahead of a
//! wrapper (`env exec sh -c '…'`) is stripped before the wrapper detection
//! runs, but a prefix's own *option flags* are never parsed, so `nice -n 10 …`
//! / `env -i …` in front of a wrapper or commit remain misses (a flag could
//! bind a value we'd misread).
//! A `GIT_DIR=`/`GIT_WORK_TREE=` env prefix can invert the target (a rare false
//! block when committing into a worktree *from* the primary via env); accepted
//! as exotic. A
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
use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, child_scripts, resolve_cd_target, split_segments_with_ops, tokenize,
};
use cadence_hooks_core::worktree::{is_primary_checkout, is_temp_root, is_truthy, should_block};
use cadence_hooks_core::{BypassKind, BypassProvenance, Check, CheckResult, HookInput, Outcome};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Per-invocation memo of the repo-declared `CADENCE_ALLOW_MAIN` exemption,
/// keyed by resolved repo root so a command touching one repo twice reads its
/// settings files once. Constructed fresh per hook invocation — no
/// cross-invocation cache.
#[derive(Default)]
struct RepoAllowMain(HashMap<String, bool>);

impl RepoAllowMain {
    /// Does `repo_root`'s own tracked Claude settings declare
    /// `CADENCE_ALLOW_MAIN` truthy? Memoized; a read failure caches `false`.
    fn is_allowed(&mut self, repo_root: &str) -> bool {
        if let Some(&cached) = self.0.get(repo_root) {
            return cached;
        }
        let declared =
            cadence_hooks_core::config::repo_env_flag(Path::new(repo_root), "CADENCE_ALLOW_MAIN")
                .as_deref()
                .map(|v| is_truthy(Some(v)))
                .unwrap_or(false);
        self.0.insert(repo_root.to_string(), declared);
        declared
    }
}

// `is_temp_root` moved to `cadence_hooks_core::worktree` (cadence-hooks#236)
// so the enforce-worktree block decision and `session::start`'s posture
// line share one definition — re-imported above.

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
/// committing. Wrapper scripts (`sh -c '…'`) and `$(…)`/backtick substitution
/// bodies DO execute, though — each segment's child scripts are recursed into
/// with the directory in effect at that segment, in their own `cd` scope (see
/// [`collect_commit_targets`], issue #228).
///
/// Both the `cd` and `git` arms share one **quote-aware** token stream from
/// `tokenize`. The pre-fix git arm used quote-blind `split_whitespace`, so a
/// quoted `-C "/spaced/path"` or `-c key="a b"` value split mid-token and the
/// `commit` subcommand was never found — a real bypass and an asymmetry with
/// the `cd` arm (#239 F5/F9, issue #230). Each segment is also stripped of
/// shell grouping (`(`/`{` … `)`/`}`) and transparent command prefixes
/// (`command`/`exec`/`time`/…) so `(git commit)`, `{ git commit; }`, and
/// `command git commit` are detected rather than slipping past the leading-word
/// gate (#239 F4).
fn strip_group_wrappers(segment: &str) -> &str {
    segment
        .trim()
        .trim_start_matches(['(', '{', ' ', '\t'])
        .trim_end_matches([')', '}', ';', ' ', '\t'])
}

/// Skip transparent command prefixes that run their argument as the command, so
/// `command git commit` / `time git commit` still surface `git` as the leading
/// word. Only skips a prefix when the following token is not an option, so a
/// prefix's own flags are never misparsed (`nice -n 10 git commit` and
/// `env -i git commit` stay documented misses rather than risking a wrong
/// resolution). Leading `VAR=value` assignment words are skipped too — bash
/// runs `VAR=value git commit` (and `env VAR=value git commit`) with the rest
/// as the command, so an assignment word must not eat the leading-word gate
/// (issue #228).
fn skip_transparent_prefixes(tokens: &[String]) -> &[String] {
    const TRANSPARENT: &[&str] = &["command", "builtin", "exec", "time", "nice", "nohup", "env"];
    let mut start = 0;
    while start + 1 < tokens.len() {
        let tok = tokens[start].as_str();
        if (TRANSPARENT.contains(&tok) && !tokens[start + 1].starts_with('-'))
            || is_assignment_word(tok)
        {
            start += 1;
        } else {
            break;
        }
    }
    &tokens[start..]
}

/// A leading `NAME=value` shell assignment word: a valid variable name
/// (`[A-Za-z_][A-Za-z0-9_]*`) followed by `=`. Anything else — paths, flags,
/// `==` comparisons — is not skipped, so this can only widen the leading-word
/// gate past words the shell itself treats as environment prefixes.
fn is_assignment_word(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, _)) if !name.is_empty() => {
            name.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// A shell path is absolute if git will treat it as absolute: a leading `/`
/// (POSIX / WSL / Git-Bash shell paths — `Path::is_absolute` is false for these
/// on Windows, no drive letter) OR a platform-absolute path (native `C:\…`).
/// These are shell paths a command string carries, not OS paths, so the
/// decision is made on the string first, falling back to the platform's own
/// notion of absolute for native-Windows drive paths (issue #235).
fn is_shell_absolute(path: &str) -> bool {
    path.starts_with('/') || Path::new(path).is_absolute()
}

fn git_commit_targets(command: &str, cwd: &str) -> Vec<CommitTarget> {
    let mut targets = Vec::new();
    collect_commit_targets(command, cwd, 0, &mut targets);
    targets
}

/// Recursive worker for [`git_commit_targets`]: walks one script's segments
/// tracking `effective_dir` across them, and recurses into each segment's
/// child scripts — a `sh -c '<script>'` wrapper's script, `$(…)`/backtick
/// substitution bodies — with the directory in effect *at that segment* but a
/// fresh scope (issue #228). The scoping is load-bearing both ways: a child
/// inherits the parent's cwd at spawn (so `cd /wt && sh -c 'git commit'`
/// resolves to `/wt`), while a child's own `cd` never leaks back into this
/// script's tracking (a flat `command_segments` view would splice
/// `$(cd /x)`'s `cd` into the parent stream and misjudge — from a primary
/// checkout, silently ALLOW — a commit the real shell still runs in the
/// parent's cwd). Depth shares [`MAX_WRAPPER_DEPTH`] with
/// `command_segments`'s own expansion budget.
fn collect_commit_targets(script: &str, cwd: &str, depth: usize, targets: &mut Vec<CommitTarget>) {
    let mut effective_dir = cwd.to_string();

    for (segment, _next_op) in split_segments_with_ops(script) {
        // Group-strip first (subshell/brace wrappers), then tokenize once —
        // quote-aware, shared by every arm (#239 F4/F5/F9).
        let segment = strip_group_wrappers(&segment);
        let tokens = tokenize(segment);

        // Strip transparent prefixes / assignment words up front so BOTH the
        // child-script extraction (a wrapper behind `exec`/`env`/`VAR=x`, e.g.
        // `env GIT_AUTHOR_NAME=x bash -c 'git commit'`) and the git
        // leading-word gate below see the real command word — the two
        // transparency mechanisms must compose (#228 review finding 1). The
        // `cd` arm keeps the raw tokens: `cd` is a builtin, never run behind
        // `env`/`exec`.
        let argv = skip_transparent_prefixes(&tokens);

        // Child scripts execute with the directory in effect HERE — a
        // substitution is evaluated before its own segment runs, and a
        // wrapper inherits the cwd accumulated so far — in their own scope.
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, segment) {
                collect_commit_targets(&child, &effective_dir, depth + 1, targets);
            }
        }

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

        // `argv` is the prefix-/assignment-stripped view computed above
        // (`command`/`env`/`VAR=x git commit` → leading `git`); require it
        // (#239 F4, #228).
        if argv.first().map(String::as_str) != Some("git") {
            continue;
        }
        // Walk git's own global flags to find the subcommand, capturing a
        // `-C <path>` redirect on the way. Indices are into the quote-aware
        // token stream, so a spaced quoted `-C`/`-c` value stays one token.
        // git globals that take a SEPARATE value token — the value must be
        // consumed or the walk stops on it and never reaches `commit`, failing
        // open (CodeRabbit, PR #241). `-C`/`-c` are here too (redirect / inline
        // config); the `--work-tree`/`--git-dir` value forms are caught by the
        // ambiguity check below and skip the whole segment.
        const VALUE_GLOBALS: &[&str] = &[
            "-C",
            "-c",
            "--namespace",
            "--super-prefix",
            "--config-env",
            "--attr-source",
        ];
        let mut redirect: Option<&str> = None;
        let mut ambiguous = false;
        let mut idx = 1;
        while idx < argv.len()
            && (argv[idx].starts_with('-') || VALUE_GLOBALS.contains(&argv[idx - 1].as_str()))
        {
            let t = argv[idx].as_str();
            if argv[idx - 1] == "-C" {
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
        if argv.get(idx).map(String::as_str) == Some("commit") {
            let target = match redirect {
                Some(path) if is_shell_absolute(path) => path.to_string(),
                Some(path) => format!("{effective_dir}/{path}"),
                None => effective_dir.clone(),
            };
            targets.push(target);
        }
    }
}

// `should_block` moved to `cadence_hooks_core::worktree` (cadence-hooks#236)
// — re-imported above; this IS the same function `would_block_here` calls.

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
         One-off exception: `cadence-hooks guardrails dismiss-enforce-worktree --for 30m` \
         (add `--reason \"<why>\"` — required over 1h; it's recorded in the repo-visible bypass log)\n\
         Repo works on main by design (dotfiles, vaults)? Set CADENCE_ALLOW_MAIN=true in \
         `{repo_root}/.claude/settings.json`'s env block — the guard reads it from the target \
         repo directly.\n\
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

/// Ascend from `dir` to the nearest ancestor that exists on disk. A `Write` can
/// name a file in a not-yet-created subtree, so the file's parent dir may not
/// exist yet — and `git rev-parse` needs a real directory to resolve the repo,
/// so an unresolvable parent would fail open (`repo_root_for` → `None`) and let
/// a new-module write into the primary slip past the Edit arm (#239 F1). This
/// walks up until it hits an existing directory. A `dir` that already exists is
/// returned unchanged, so the common path is a single `exists()` stat and no
/// behavior changes for edits to existing files.
fn nearest_existing_ancestor(dir: &Path) -> PathBuf {
    let mut cur = dir;
    loop {
        if cur.exists() {
            return cur.to_path_buf();
        }
        match cur.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
            _ => return dir.to_path_buf(),
        }
    }
}

/// The absolute git common dir enclosing `dir`, via
/// `git rev-parse --path-format=absolute --git-common-dir`. Unlike the toplevel
/// (`repo_root_for`), this is shared across every worktree of one repo (#179),
/// so it is the right identity for "the session's own repo" in the Edit/Write
/// scoping (#238). `None` when `dir` isn't in a git repo or git is unavailable —
/// callers fail open (ADR-0001).
fn git_common_dir(dir: &Path) -> Option<String> {
    cadence_hooks_core::shell::git_command(
        &dir.to_string_lossy(),
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
}

/// Evaluate one candidate directory: allow, or block with the message.
/// `origin_repo`, when set, names the repo the command's cwd started in — used
/// only to decide whether the block message needs to acknowledge a `cd`/`-C`
/// redirect to a *different* repo (issue #224); `None` for the Edit/Write arm,
/// where there is no such redirect to name.
///
/// The `.claude/` and `docs/plans/` carve-outs are **not** applied here — they
/// are the Edit/Write arm's concern (the *file being edited* is Claude-managed
/// state or an approved plan doc). Applying them in this shared assessor leaked
/// the carve-out onto the commit arm, where `dir` is a commit *target*, so
/// `cd .claude && git commit` / `cd docs/plans && git commit` punched a
/// disk-free hole in the block and even defeated the #224 cross-repo guard
/// (#239 F6/F7). The sanctioned plan-doc-commit-on-`main` path is the `dismiss`
/// snooze, so the commit arm needs no carve-out of its own.
fn assess_dir(
    dir: &Path,
    cfg: &EnvConfig,
    origin_repo: Option<&str>,
    repo_allow: &mut RepoAllowMain,
) -> CheckResult {
    let Some(repo_root) = repo_root_for(dir) else {
        // Not a git repo (or a bare container dir) — nothing to enforce.
        return CheckResult::allow();
    };
    let is_primary = is_primary_checkout(&repo_root);
    let temp_root = is_temp_root(Path::new(&repo_root), cfg.tmpdir.as_deref());
    let snoozed = dismiss_enforce_worktree::is_snoozed_now(Path::new(&repo_root));
    let repo_declared = is_primary && !cfg.allow_main && repo_allow.is_allowed(&repo_root);
    let allowed_main = cfg.allow_main || repo_declared;
    let blocked = should_block(
        is_primary,
        allowed_main,
        cfg.kill_switch,
        temp_root,
        snoozed,
    );
    if blocked {
        return CheckResult::block(block_message(&repo_root, origin_repo));
    }

    // Allowed. Attribute *why* only when the guard WOULD have blocked absent a
    // bypass — a primary checkout that isn't a temp root. A worktree, a temp
    // repo, or a carve-out is a normal allow with no bypass. Priority: an active
    // dismissal, then the env switches (snooze is the more deliberate act).
    //
    // This DELIBERATELY differs from `warn-main-branch`, which tags only the
    // snooze and leaves `CADENCE_ALLOW_MAIN` a bare allow. The asymmetry is by
    // guard *severity*: enforce is a hard **block** on a shared primary checkout,
    // and the guard can't tell a by-design main-mode repo (dotfiles/vault) from
    // a session that set `CADENCE_ALLOW_MAIN`/`CADENCE_NO_ENFORCE_WORKTREE`
    // specifically to disable enforcement — the bypass log is exactly where you'd
    // look to answer "who lowered the hard block here", so a standing env switch
    // is worth a line even if repetitive. warn's nudge is advisory, so the same
    // static config there is noise, not signal. The deferred read-side surfacing
    // aggregates the repetition.
    if is_primary && !temp_root {
        if snoozed {
            let meta = dismiss_enforce_worktree::read_meta(Path::new(&repo_root));
            return CheckResult::allow_bypassed(BypassProvenance {
                kind: BypassKind::Dismissal,
                mechanism: "dismiss-enforce-worktree".to_string(),
                reason: meta.as_ref().and_then(|m| m.reason.clone()),
                expires_at: meta.as_ref().and_then(|m| m.expires_at),
                armed_by_session: meta.and_then(|m| m.session_id),
            });
        }
        if cfg.allow_main {
            return CheckResult::allow_bypassed(env_switch("CADENCE_ALLOW_MAIN"));
        }
        if repo_declared {
            return CheckResult::allow_bypassed(env_switch("CADENCE_ALLOW_MAIN (repo settings)"));
        }
        if cfg.kill_switch {
            return CheckResult::allow_bypassed(env_switch("CADENCE_NO_ENFORCE_WORKTREE"));
        }
    }
    CheckResult::allow()
}

/// Build an env-switch bypass provenance (no reason/expiry/session — an env var
/// carries none of those).
fn env_switch(var: &str) -> BypassProvenance {
    BypassProvenance {
        kind: BypassKind::EnvSwitch,
        mechanism: var.to_string(),
        reason: None,
        expires_at: None,
        armed_by_session: None,
    }
}

/// Testable core: assess the hook input under the given environment.
fn run_enforce(input: &HookInput, cfg: &EnvConfig) -> CheckResult {
    let mut repo_allow = RepoAllowMain::default();
    match input.tool_name() {
        Some("Edit") | Some("Write") | Some("MultiEdit") => {
            if input.file_path().is_none() {
                // No target file — nothing to assess, fail open.
                return CheckResult::allow();
            }
            // Worktree discipline is about the checkout the SESSION is working
            // in. A mutation into a repo *other* than the one the session sits
            // in is a foreign artifact-drop — a field report into an Obsidian
            // vault, a note into `~/Documents`, a file into a sibling repo —
            // not feature work in the session's own shared tree, so it is out
            // of scope for this guard. Enforce only when the target file is in
            // the session's own repo (compared by git common dir below); a
            // different repo, or a target/cwd git can't resolve to a repo,
            // falls through to allow. The Edit/Write arm is deliberately more
            // permissive than the git-commit arm: the commit arm keeps its own
            // cross-repo guard, so *persisting* into a foreign primary still
            // blocks (#224) even though *writing* a file there does not.
            // Charter is fail-open (ADR-0001) — a missed nudge is cheap, a
            // false block is friction — so scoping an over-broad arm is
            // aligned. `input.cwd` is always sent by Claude Code. (#238)
            let target_dir = git_dir_for_input(input);
            // Carve-outs live HERE, on the Edit/Write arm, not in the shared
            // `assess_dir` (which the commit arm also calls): the *file being
            // edited* being Claude-managed state or an approved plan doc is what
            // the carve-out is for. Checked on the lexical target path, before
            // the ancestor ascent, so a new file under `.claude/` or
            // `docs/plans/` is still exempt even when its dir doesn't exist yet.
            if is_claude_managed_dir(&target_dir) || is_plan_doc_dir(&target_dir) {
                return CheckResult::allow();
            }
            // A Write may name a file in a not-yet-created subtree, whose parent
            // dir git can't resolve — ascend to the nearest existing ancestor so
            // a new dir in the session's OWN primary is still judged rather than
            // silently allowed (#239 F1). Existing dirs are returned unchanged.
            let target_dir = nearest_existing_ancestor(&target_dir);
            let cwd = input.cwd.as_deref().unwrap_or(".");
            // "Same checkout" is compared by **git common dir**, not toplevel: a
            // repo and each of its linked worktrees share one common dir (#179)
            // but have distinct toplevels. Comparing toplevels would wrongly
            // treat a write into the session's OWN primary tree from one of its
            // worktrees as foreign — the exact ADR-0030 collision the guard
            // exists to stop. Comparing common dirs keeps a cross-*repo* write
            // foreign (a vault, a sibling repo — different common dir) while
            // still enforcing on any tree of the session's own repo.
            match (git_common_dir(&target_dir), git_common_dir(Path::new(cwd))) {
                (Some(target_repo), Some(cwd_repo)) if target_repo == cwd_repo => {
                    assess_dir(&target_dir, cfg, None, &mut repo_allow)
                }
                _ => CheckResult::allow(),
            }
        }
        Some("Bash") => {
            let Some(command) = input.command() else {
                return CheckResult::allow();
            };
            let cwd = input.cwd.as_deref().unwrap_or(".");
            // Resolved once per invocation: the repo the shell started in,
            // used only to decide whether a redirect crossed repo boundaries.
            let cwd_repo_root = repo_root_for(Path::new(cwd));
            // A block on any commit target wins immediately. Otherwise preserve
            // the first *bypassed* allow's provenance: assess_dir returns an
            // Allow-with-bypass for a snooze / env switch / repo-declared
            // exemption on a primary checkout, and the bypass log's `used`
            // event depends on that provenance surviving back to `run_check`.
            // The pre-fix loop returned only non-Allow results and fell through
            // to a bare `allow()`, silently dropping the bypass — so a `git
            // commit` ridden through a dismissal or CADENCE_ALLOW_MAIN was never
            // recorded (every existing provenance test drove the Edit arm, so
            // this Bash-arm gap went unseen until the repo-settings case).
            let mut bypassed: Option<CheckResult> = None;
            // Dedup identical targets so a pathological command (`git commit;`
            // ×N) can't fan out into N synchronous `git rev-parse` spawns and
            // stall the hook — each distinct target is assessed once (#239 F11).
            let mut seen: HashSet<String> = HashSet::new();
            for target in git_commit_targets(command, cwd) {
                if !seen.insert(target.clone()) {
                    continue;
                }
                let dir = PathBuf::from(&target);
                let result = assess_dir(&dir, cfg, cwd_repo_root.as_deref(), &mut repo_allow);
                if result.outcome != Outcome::Allow {
                    return result;
                }
                if result.bypass.is_some() && bypassed.is_none() {
                    bypassed = Some(result);
                }
            }
            bypassed.unwrap_or_else(CheckResult::allow)
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

    /// An Edit whose session cwd is `session_dir`. The Edit/Write arm scopes
    /// enforcement to the session's own checkout (#238): it enforces only when
    /// the target file's repo is the same repo the session sits in. So a test
    /// that exercises the block/exemption path must place the session *inside*
    /// the repo under test — otherwise the write is judged "foreign" and always
    /// allowed. `make_edit` alone leaves cwd unset (→ the test runner's cwd,
    /// a *different* repo), which would false-allow every would-be block.
    fn edit_in(session_dir: &Path, file: &Path) -> HookInput {
        let mut input = make_edit(&file.to_string_lossy(), "a", "b");
        input.cwd = Some(session_dir.to_string_lossy().into_owned());
        input
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

    #[cfg(windows)]
    #[test]
    fn native_windows_drive_path_commit_targets_redirect() {
        // A native Windows drive path is absolute via `Path::is_absolute`'s own
        // arm of `is_shell_absolute` (no leading `/` needed) — proves the
        // `#[cfg(unix)]`-gated fixtures above aren't the only Windows coverage
        // for this branch (issue #235).
        assert_eq!(
            git_commit_targets(r"git -C C:\repo\wt commit -m x", r"C:\cwd"),
            vec![r"C:\repo\wt".to_string()]
        );
    }

    // --- git_commit_targets: grouping / prefixes / quoting (#239 F4/F5/F9) ---

    #[test]
    fn subshell_and_brace_group_commit_detected() {
        // F4: shell grouping around a commit no longer hides it.
        assert_eq!(
            git_commit_targets("(git commit -m x)", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("( git commit -m x )", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("{ git commit -m x; }", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn subshell_cd_then_commit_resolves_target() {
        // F4: `(cd <dir> && git commit)` — the `(cd` no longer hides the cd, so
        // the commit resolves to the cd target rather than the shell's cwd.
        assert_eq!(
            git_commit_targets("(cd /wt && git commit -m x)", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn transparent_prefix_commit_detected() {
        // F4: command/exec/time run their argument as the command.
        for cmd in [
            "command git commit -m x",
            "exec git commit -m x",
            "time git commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "prefix not seen through: {cmd}"
            );
        }
    }

    #[test]
    fn transparent_prefix_with_option_is_a_miss_not_a_misparse() {
        // `nice -n 10 git commit` — we don't parse the prefix's own flags, so
        // this stays a documented miss (empty), never a wrong target.
        assert!(git_commit_targets("nice -n 10 git commit -m x", "/cwd").is_empty());
    }

    #[test]
    fn quoted_dash_c_path_with_space_detected() {
        // F5 / issue #230: quote-aware tokenize keeps the spaced -C path one
        // token, so the redirect resolves and the commit is found.
        assert_eq!(
            git_commit_targets(r#"git -C "/path with space" commit -m x"#, "/cwd"),
            vec!["/path with space".to_string()]
        );
    }

    #[test]
    fn quoted_inline_config_space_value_detected() {
        // F9: a spaced -c value no longer splits the token stream and hides the
        // `commit` subcommand.
        assert_eq!(
            git_commit_targets(r#"git -c user.name="A B" commit -m x"#, "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn separate_value_git_globals_do_not_hide_commit() {
        // CodeRabbit (PR #241): a git global taking a SEPARATE value token must
        // be consumed, or the walk stops on the value and never sees `commit`.
        assert_eq!(
            git_commit_targets("git --namespace ns commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("git --attr-source HEAD commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        // …and a -C redirect still resolves when mixed with a value-global.
        assert_eq!(
            git_commit_targets("git --namespace ns -C /wt commit -m x", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    // --- git_commit_targets: wrapper & substitution expansion (#228, #230) ---

    #[test]
    fn shell_c_wrapper_commit_detected() {
        // Issue #228: a `sh -c '<script>'` wrapper executes its script — the
        // commit inside must be seen, not hidden behind the wrapper's leading
        // word.
        for cmd in [
            "sh -c 'git commit -m x'",
            r#"bash -c "git commit -m x""#,
            "zsh -c 'git commit -m x'",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "wrapper not seen through: {cmd}"
            );
        }
    }

    #[test]
    fn shell_c_wrapper_cd_redirects_inside_wrapper() {
        // The wrapper script's own `cd` redirects commits inside that script.
        assert_eq!(
            git_commit_targets("sh -c 'cd /wt && git commit -m x'", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn wrapper_cd_does_not_leak_to_outer_segments() {
        // A wrapper is a child process: its `cd` never moves the parent
        // shell's cwd, so the outer commit still targets the original cwd. A
        // flat expansion (command_segments-style) would splice the child's
        // `cd /elsewhere` into the parent stream and misjudge — or, from a
        // primary checkout, silently ALLOW — the outer commit.
        assert_eq!(
            git_commit_targets("sh -c 'cd /elsewhere' && git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn outer_cd_flows_into_wrapper() {
        // A wrapper inherits the parent's working directory at spawn.
        assert_eq!(
            git_commit_targets("cd /wt && sh -c 'git commit -m x'", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn substitution_commit_detected() {
        // `$(…)`/backtick bodies execute — a commit inside one is real.
        assert_eq!(
            git_commit_targets(r#"echo "$(git commit -m x)""#, "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("echo `git commit -m x`", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn substitution_cd_does_not_poison_outer_target() {
        // A substitution runs in a subshell: `$(cd /elsewhere)` must not move
        // the tracked directory for the segments that follow it — the real
        // commit below runs in /cwd, and judging it against /elsewhere would
        // be a silent bypass primitive from any primary checkout.
        assert_eq!(
            git_commit_targets(r#"echo "$(cd /elsewhere)" && git commit -m x"#, "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn single_quoted_substitution_not_expanded() {
        // Single quotes suppress substitution — nothing executes in there.
        assert!(git_commit_targets("echo '$(git commit -m x)'", "/cwd").is_empty());
    }

    #[test]
    fn nested_wrappers_bounded_still_detected() {
        assert_eq!(
            git_commit_targets(r#"sh -c "sh -c 'git commit -m x'""#, "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn wrapper_without_commit_stays_empty() {
        assert!(git_commit_targets("sh -c 'echo not a commit'", "/cwd").is_empty());
        assert!(git_commit_targets(r#"echo "$(git rev-parse HEAD)""#, "/cwd").is_empty());
    }

    #[test]
    fn env_prefix_commit_detected() {
        // Issue #228 (env facet): `env` runs its argument as the command, with
        // or without leading VAR=value assignment words.
        assert_eq!(
            git_commit_targets("env git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("env GIT_AUTHOR_NAME=x git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn assignment_prefix_commit_detected() {
        // bash itself allows `VAR=value cmd` — the assignment word must not
        // eat the leading-word gate.
        assert_eq!(
            git_commit_targets("GIT_AUTHOR_NAME=x git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn env_with_option_flag_is_a_miss_not_a_misparse() {
        // `env -i git commit` — we don't parse env's own flags; documented
        // miss (empty), never a wrong target. Mirrors `nice -n 10`.
        assert!(git_commit_targets("env -i git commit -m x", "/cwd").is_empty());
    }

    #[test]
    fn transparent_prefix_before_wrapper_composes() {
        // #228 review finding 1: a transparent prefix or assignment word in
        // front of a `sh -c '…'` wrapper must not reopen the boundary — the
        // two transparency mechanisms compose. Each commits into /cwd.
        for cmd in [
            "exec sh -c 'git commit -m x'",
            "command sh -c 'git commit -m x'",
            "env sh -c 'git commit -m x'",
            "env GIT_AUTHOR_NAME=x bash -c 'git commit -m x'",
            "GIT_AUTHOR_NAME=x sh -c 'git commit -m x'",
            "time bash -c 'git commit -m x'",
            "nohup zsh -c 'git commit -m x'",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "prefix+wrapper not composed: {cmd}"
            );
        }
    }

    #[test]
    fn prefixed_wrapper_cd_still_redirects() {
        // The composed path still tracks the wrapper script's own cd.
        assert_eq!(
            git_commit_targets("env exec sh -c 'cd /wt && git commit -m x'", "/cwd"),
            vec!["/wt".to_string()]
        );
    }

    #[test]
    fn wrapper_and_trailing_substitution_both_seen() {
        // #228 review finding 2: `child_scripts` unions the wrapper script
        // with substitution bodies, so a commit in a substitution alongside a
        // wrapper (which the outer shell runs in the parent before spawning
        // the wrapper) is not dropped.
        assert_eq!(
            git_commit_targets(r#"bash -c 'true' "$(git commit -m x)""#, "/cwd"),
            vec!["/cwd".to_string()]
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

    /// Write a repo-scoped Claude settings file declaring `env` values, for
    /// exercising `CADENCE_ALLOW_MAIN`'s target-repo-settings resolution.
    fn write_settings(repo: &Path, name: &str, body: &str) {
        let dir = repo.join(".claude");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
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
        let input = edit_in(&primary, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "primary checkout must block");
        let msg = r.message.unwrap();
        assert!(msg.contains("worktree"), "fix named in message: {msg}");

        let file = wt.join("src.rs");
        let input = edit_in(&wt, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "linked worktree must pass");
    }

    #[test]
    fn allow_main_and_kill_switch_exempt_primary() {
        let scratch = Scratch::new("env");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let file = primary.join("src.rs");
        let input = edit_in(&primary, &file);

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
            let input = edit_in(&primary, &file);
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Allow, "carve-out for {sub}");
        }
    }

    #[test]
    fn snooze_marker_exempts_primary_and_attributes_dismissal() {
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
        // Provenance sidecar written by the dismiss command.
        let sidecar = dismiss_enforce_worktree::meta_path_for(&primary).unwrap();
        std::fs::write(
            &sidecar,
            crate::snooze_meta::SnoozeMeta {
                reason: Some("dogfooding vault symlink".into()),
                session_id: Some("sess-1".into()),
                armed_at: Some(1),
                expires_at: Some(until as i64),
            }
            .to_json(),
        )
        .unwrap();

        let file = primary.join("src.rs");
        let input = edit_in(&primary, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "active snooze exempts");
        let prov = r.bypass.expect("snooze allow carries provenance");
        assert_eq!(prov.kind, BypassKind::Dismissal);
        assert_eq!(prov.mechanism, "dismiss-enforce-worktree");
        assert_eq!(prov.reason.as_deref(), Some("dogfooding vault symlink"));
        assert_eq!(prov.armed_by_session.as_deref(), Some("sess-1"));
    }

    #[test]
    fn snooze_without_sidecar_allows_with_none_reason() {
        // An older marker armed before the sidecar existed: the guard still
        // allows and attributes a Dismissal, just with no reason/session.
        let scratch = Scratch::new("snooze-legacy");
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
        let input = edit_in(&primary, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("snooze still attributes a dismissal");
        assert_eq!(prov.kind, BypassKind::Dismissal);
        assert_eq!(prov.reason, None, "missing sidecar → no reason");
        assert_eq!(prov.armed_by_session, None);
    }

    #[test]
    fn env_switch_allow_attributes_env_switch() {
        // CADENCE_ALLOW_MAIN / CADENCE_NO_ENFORCE_WORKTREE suppress the block on a
        // primary checkout — the allow must carry an EnvSwitch bypass naming which.
        let scratch = Scratch::new("env-bypass");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let file = primary.join("src.rs");
        let input = edit_in(&primary, &file);

        let r = run_enforce(&input, &cfg(true, false));
        let prov = r.bypass.expect("allow_main carries provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN");
        assert_eq!(prov.reason, None);

        let r = run_enforce(&input, &cfg(false, true));
        let prov = r.bypass.expect("kill switch carries provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_NO_ENFORCE_WORKTREE");
    }

    #[test]
    fn worktree_allow_carries_no_bypass() {
        // A normal worktree edit is fine on its own — no guard was stepped
        // outside of, so the allow stays bare (no bypasses.jsonl line).
        let scratch = Scratch::new("wt-nobypass");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let file = wt.join("src.rs");
        let input = edit_in(&wt, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(r.bypass.is_none(), "normal worktree allow is not a bypass");
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

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
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

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
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

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
    #[test]
    fn dismiss_repo_flag_snoozes_target_not_cwd() {
        // Mirrors what `dismiss-enforce-worktree --repo <other_primary>` writes
        // (perform_dismiss's success path writes into the process cwd's repo, so
        // the --repo targeting isn't unit-testable directly — same pattern as
        // `snooze_marker_exempts_primary` above). Confirms the
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

    // --- repo-scoped CADENCE_ALLOW_MAIN (cameronsjo/cadence-hooks#232) ---

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
    #[test]
    fn cross_repo_commit_reads_target_repos_own_settings() {
        // Headline repro: shell rooted in primary A, mutation targets a
        // SEPARATE primary B that declares CADENCE_ALLOW_MAIN in its own
        // .claude/settings.json — the exemption must travel with the target,
        // not the shell's cwd.
        let scratch = Scratch::new("cross-repo-allow-main");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let primary_b = scratch.0.join("declares-allow-main");
        std::fs::create_dir(&primary_b).unwrap();
        init_repo(&primary_b);
        write_settings(
            &primary_b,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );

        // `git -C <B> commit` with cwd=A.
        let mut input = make_bash(&format!(
            "git -C {} commit -m 'x'",
            primary_b.to_string_lossy()
        ));
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "-C into declaring repo B allows");
        let prov = r.bypass.expect("repo-declared allow carries provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN (repo settings)");

        // `cd <B> && git commit` with cwd=A.
        let mut input = make_bash(&format!(
            "cd {} && git commit -m 'x'",
            primary_b.to_string_lossy()
        ));
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "cd into declaring repo B allows");
        let prov = r.bypass.expect("repo-declared allow carries provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN (repo settings)");
    }

    #[test]
    fn bash_commit_bypass_provenance_survives_the_arm() {
        // Regression: the Bash arm returned only non-Allow results and fell
        // through to a bare allow(), dropping the bypass on an allowed commit —
        // so a `git commit` ridden through an env switch was never recorded in
        // bypasses.jsonl. Exercised here via CADENCE_ALLOW_MAIN (process env),
        // independent of the repo-settings mechanism, to lock the general fix.
        let scratch = Scratch::new("bash-bypass-prov");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("Bash-arm bypassed allow keeps provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN");
    }

    #[test]
    fn same_repo_edit_honors_repo_declared_allow_main() {
        let scratch = Scratch::new("same-repo-allow-main");
        let primary = scratch.0.join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );

        let file = primary.join("src.rs");
        let input = edit_in(&primary, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("repo-declared allow carries provenance");
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN (repo settings)");
    }

    #[test]
    fn repo_settings_precedence_and_falsy_cases() {
        let scratch = Scratch::new("allow-main-precedence");

        // local false + shared true → Block (local wins, and it's falsy).
        let primary = scratch.0.join("local-false-shared-true");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.local.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"false"}}"#,
        );
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "local falsy wins over shared truthy"
        );

        // local true alone → Allow.
        let primary = scratch.0.join("local-true-alone");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.local.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "local truthy alone allows");

        // shared falsy only ("false") → Block.
        let primary = scratch.0.join("shared-false");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"false"}}"#,
        );
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "shared falsy 'false' blocks");

        // shared falsy only ("0") → Block.
        let primary = scratch.0.join("shared-zero");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"0"}}"#,
        );
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "shared falsy '0' blocks");

        // malformed JSON in settings.json → Block, and must not panic.
        let primary = scratch.0.join("malformed-json");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(&primary, "settings.json", "{not valid json");
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "malformed settings JSON blocks, no panic"
        );
    }

    #[test]
    fn process_env_allow_main_wins_over_falsy_repo_settings() {
        // Repo settings falsy, but process env CADENCE_ALLOW_MAIN is truthy —
        // the env override is the session-wide short-circuit and precedes the
        // repo-settings lookup entirely, so the mechanism string stays the
        // BARE "CADENCE_ALLOW_MAIN", not the repo-settings variant.
        let scratch = Scratch::new("env-wins-over-repo-falsy");
        let primary = scratch.0.join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"false"}}"#,
        );

        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("env override carries provenance");
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN");
    }

    #[test]
    fn process_env_allow_main_wins_over_truthy_repo_settings() {
        // Both process env and repo settings declare truthy — the `!cfg.allow_main`
        // short-circuit means the repo-settings lookup never runs, so the
        // mechanism stays the BARE "CADENCE_ALLOW_MAIN" (not the repo-settings
        // variant). Locks that the env arm precedes the repo-declared arm.
        let scratch = Scratch::new("env-wins-over-repo-truthy");
        let primary = scratch.0.join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        write_settings(
            &primary,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );

        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("env override carries provenance");
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN");
    }

    #[test]
    fn repo_allow_main_memo_is_deterministic_within_invocation_and_per_repo() {
        let scratch = Scratch::new("repo-allow-memo");
        let declaring = scratch.0.join("declares");
        std::fs::create_dir(&declaring).unwrap();
        init_repo(&declaring);
        write_settings(
            &declaring,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        let declaring_root = repo_root_for(&declaring).unwrap();

        let plain = scratch.0.join("plain");
        std::fs::create_dir(&plain).unwrap();
        init_repo(&plain);
        let plain_root = repo_root_for(&plain).unwrap();

        let mut memo = RepoAllowMain::default();
        assert!(
            memo.is_allowed(&declaring_root),
            "declaring repo reads true"
        );

        // Delete the settings file after the first read — a re-read within
        // the same invocation must still return the memoized value.
        std::fs::remove_file(Path::new(&declaring_root).join(".claude/settings.json")).unwrap();
        assert!(
            memo.is_allowed(&declaring_root),
            "memoized within the invocation despite the file vanishing"
        );

        assert!(
            !memo.is_allowed(&plain_root),
            "a distinct repo root with no settings stays independent and false"
        );
    }

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
    #[test]
    fn cross_repo_block_message_names_target_repos_settings_path() {
        let scratch = Scratch::new("cross-repo-block-message");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let primary_b = scratch.0.join("non-declaring");
        std::fs::create_dir(&primary_b).unwrap();
        init_repo(&primary_b);

        let mut input = make_bash(&format!(
            "cd {} && git commit -m 'x'",
            primary_b.to_string_lossy()
        ));
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        let primary_b_canon = std::fs::canonicalize(&primary_b).unwrap();
        let expected = format!(
            "{}/.claude/settings.json",
            primary_b_canon.to_string_lossy()
        );
        assert!(
            msg.contains(&expected),
            "message names the target repo's settings path: {msg}"
        );
    }

    // --- #238: Edit/Write enforcement scoped to the session's own checkout ---

    #[test]
    fn foreign_repo_write_allows_even_into_a_primary_on_main() {
        // The headline fix: the session sits in primary A, but the Write targets
        // a SEPARATE primary B on main (an Obsidian vault, a sibling repo, a
        // notes dir). B has no CADENCE_ALLOW_MAIN. Pre-#238 the arm judged only
        // B and blocked; now a foreign-location write is out of scope → allow.
        let scratch = Scratch::new("foreign-write");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let foreign = scratch.0.join("foreign-repo");
        std::fs::create_dir(&foreign).unwrap();
        init_repo(&foreign);

        let input = edit_in(&primary_a, &foreign.join("note.md"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a write into a repo other than the session's own is a foreign drop"
        );
        assert!(r.bypass.is_none(), "a foreign allow is not a bypass");
    }

    #[test]
    fn write_into_parent_repo_from_foreign_cwd_allows() {
        // Branch 5: the target file has no `.git` of its own, so repo_root_for
        // walks UP to an enclosing parent repo (a note under `~/Documents`, say).
        // When the session isn't in that parent, it's still a foreign write →
        // allow (pre-#238 this blocked, naming the parent).
        let scratch = Scratch::new("foreign-parent");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let parent = scratch.0.join("parent-repo");
        std::fs::create_dir(&parent).unwrap();
        init_repo(&parent);
        let deep = parent.join("notes/sub");
        std::fs::create_dir_all(&deep).unwrap();

        let input = edit_in(&primary_a, &deep.join("note.md"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a write into a dir enclosed by a foreign parent repo allows"
        );
    }

    #[test]
    fn own_repo_write_still_blocks_after_scoping() {
        // Regression: the core case is preserved — the session in primary A
        // editing A's OWN tree still blocks (edit_in sets cwd = that primary).
        let scratch = Scratch::new("own-repo-block");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let input = edit_in(&primary_a, &primary_a.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "editing your OWN primary checkout still blocks"
        );
    }

    #[test]
    fn edit_into_own_primary_from_a_worktree_blocks() {
        // Scoping is by git common dir, not toplevel: a session sitting in a
        // worktree of repo R, writing into R's OWN primary tree, is the same
        // repo (shared common dir) — not a foreign drop — so it still blocks
        // (the ADR-0030 collision). Comparing toplevels (distinct per worktree)
        // would have wrongly allowed this.
        let scratch = Scratch::new("wt-into-primary");
        let (primary, wt) = primary_and_worktree(&scratch);
        let input = edit_in(&wt, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "writing into your own primary from a worktree still blocks"
        );
    }

    #[test]
    fn edit_into_a_worktree_from_the_primary_allows() {
        // The mirror: writing into a linked worktree from the primary session
        // is the same repo, but the target is a worktree (not a primary), so
        // `is_primary_checkout` lets it through.
        let scratch = Scratch::new("primary-into-wt");
        let (primary, wt) = primary_and_worktree(&scratch);
        let input = edit_in(&primary, &wt.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "writing into a worktree from the primary is fine (target isn't primary)"
        );
    }

    #[test]
    fn cwd_not_in_any_repo_write_into_primary_allows() {
        // Session cwd is a plain non-git dir; the target lands in a primary on
        // main. There is no "session repo" to match → foreign → allow.
        let scratch = Scratch::new("cwd-no-repo");
        let non_repo = scratch.0.join("plain");
        std::fs::create_dir(&non_repo).unwrap();
        let target = scratch.0.join("target-repo");
        std::fs::create_dir(&target).unwrap();
        init_repo(&target);

        let input = edit_in(&non_repo, &target.join("f.md"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "no session repo to match → foreign → allow"
        );
    }

    #[test]
    fn scoping_does_not_relax_the_commit_arm_cross_repo_block() {
        // The Edit/Write scoping is deliberately arm-local: committing into a
        // DIFFERENT primary checkout than the session's cwd still blocks (#224),
        // so persistence into a foreign primary is unaffected by #238.
        let scratch = Scratch::new("scope-commit-unchanged");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.0.join("other-repo");
        std::fs::create_dir(&other_primary).unwrap();
        init_repo(&other_primary);

        let mut input = make_bash(&format!(
            "git -C {} commit -m 'x'",
            other_primary.to_string_lossy()
        ));
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "a commit into a foreign primary still blocks — commit arm is untouched"
        );
    }

    // --- #239: adversarial hardening ---

    #[test]
    fn new_subdir_write_in_own_primary_blocks() {
        // F1: a Write creating a file in a not-yet-existent subdir of the
        // session's own primary must still block. The parent dir doesn't exist
        // yet, so the pre-fix `repo_root_for` failed open; ascending to the
        // nearest existing ancestor (the repo root) judges it correctly.
        let scratch = Scratch::new("new-subdir");
        let (primary, _wt) = primary_and_worktree(&scratch);
        // `primary/newmod` deliberately does NOT exist.
        let input = edit_in(&primary, &primary.join("newmod/lib.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "creating a new module dir in your own primary still blocks"
        );
    }

    #[cfg(unix)]
    // unix-shaped fixture: builds POSIX command strings through an
    // escape-unaware tokenizer; native-Windows path coverage is
    // native_windows_drive_path_commit_targets_redirect.
    #[test]
    fn commit_with_cwd_under_claude_or_plans_in_primary_still_blocks() {
        // F6/F7: the `.claude`/`docs/plans` carve-out is Edit-arm-only now. A
        // commit whose target dir lexically contains those segments no longer
        // rides through — the commit isn't scoped to those files, so a repo-wide
        // change would otherwise slip onto main disk-free.
        let scratch = Scratch::new("commit-carveout");
        let (primary, _wt) = primary_and_worktree(&scratch);
        std::fs::create_dir_all(primary.join(".claude")).unwrap();
        std::fs::create_dir_all(primary.join("docs/plans")).unwrap();

        for sub in [".claude", "docs/plans"] {
            let mut input = make_bash(&format!(
                "cd {} && git commit -m x",
                primary.join(sub).to_string_lossy()
            ));
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "commit with cwd under {sub} must block — carve-out is Edit-arm-only"
            );
        }
    }

    #[test]
    fn repeated_commit_in_worktree_dedups_and_allows() {
        // F11: repeated identical commit targets are assessed once. A worktree
        // cwd (allow) exercises the full loop — no early block short-circuits it
        // — so all three `git commit` segments resolve to the one worktree
        // target and collapse to a single assessment.
        let scratch = Scratch::new("dedup-wt");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("git commit -m x; git commit -m x; git commit -m x");
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "worktree commits allow; repeated targets deduped"
        );
    }
}
