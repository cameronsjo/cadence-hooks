//! `enforce-worktree` — block mutations in a primary checkout of a branch-mode repo.
//!
//! The invariant this enforces: **every session works in its own worktree on its
//! own branch, or in a repo where `main` is the working branch by design**
//! (dotfiles, vaults — marked with `CADENCE_ALLOW_MAIN`). Sessions in separate
//! worktrees cannot collide on checkout state, which is what let the advisory
//! multi-session coordination layer retire as a separate plugin in 2026-09
//! (cadence-ecosystem ADR-0030 Phase 2 executed) — its hooks now ride the
//! always-on `cadence` plugin. See claude-configurations ADR-0030.
//!
//! Blocks (exit 2) when a file mutation (`Edit`/`Write`/`MultiEdit`) or a Bash
//! `git commit` targets the **primary checkout** (`.git` is a directory) of a
//! branch-mode repo. A linked worktree's `.git` is a file, so worktrees pass
//! untouched — that is the point.
//!
//! **Nudges** (exit 0, #234) — the one advisory tier — when a Bash command runs
//! a *subprocess tree-mutation* in the session's own primary checkout without a
//! `git commit`: a package-manager manifest mutator (`uv add`, `cargo add`,
//! `pip/npm/pnpm/poetry/yarn install|add`, …), a direct file mutator (`sed -i`,
//! `tee`), or a `>`/`>>` redirect into a tracked file. These writes accumulate
//! in the shared tree and aren't caught until the eventual `git commit`/`Write`
//! tripwire, so the nudge raises coverage of that class from silent-allow →
//! advisory. It never blocks (cannot weaken an existing block), is scoped to the
//! session's OWN checkout like the Edit/Write arm, honors every exemption below,
//! and — per the composition contract — is evaluated **only after** the commit
//! (block) channel finds no block, so `uv add && git commit` into the primary
//! still BLOCKS rather than double-firing a nudge. It reuses the
//! `dismiss-enforce-worktree` snooze (no separate dismiss key — D2).
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
//! - **Commitless (unborn-HEAD) primary checkout** — a repo with zero commits
//!   reachable from any ref (a fresh `git init`, before its first commit)
//!   cannot be worktree'd (`git worktree add -b` needs a commit to branch
//!   from), so the block's own remedy is impossible and the bootstrap commit
//!   MUST land here (#309). Keyed on "any commit anywhere" (`rev-list --all`),
//!   NOT the current HEAD — a `git checkout --orphan` / `git update-ref -d
//!   HEAD` established repo still has commits and still blocks. The exemption
//!   evaporates at the first commit.
//! - Not a git repo, or git unavailable — fail open (ADR-0001).
//!
//! Known misses, accepted by design (this is a discipline guard, not a security
//! boundary). Subprocess manifest/redirect mutations now **nudge** (#234) — they
//! are no longer a silent miss — but the nudge's own coverage is a curated
//! floor, not a fence. Named v1 misses of the mutation-nudge channel, each
//! degrading to the pre-#234 silent-allow (never a weakened block):
//! - **Any file target that does not yet exist on disk** — the gate that stops
//!   `git diff > report.txt` from claiming to mutate tracked content (#377)
//!   cannot tell a scratch report from a brand-new SOURCE file, because both are
//!   equally absent at hook time. So a first write of `src/newmod/lib.rs` (or
//!   `tee src/new_config.toml`) into the primary is silent, even though that is
//!   exactly the "writes accumulate unseen until commit" case the nudge names.
//!   Separating them needs a git query per target, which the #271 probe budget
//!   rules out. Existing files — including dangling symlinks, hence
//!   `symlink_metadata` rather than `exists` — still nudge.
//! - **Non-enumerated mutator verbs** — `cp`/`mv`/`install` into a tracked path,
//!   `dd of=…`, `truncate`, `patch`, `ed`/`ex`, `perl -i`, `awk -i inplace`,
//!   `python -c 'open(p,"w")'`, and the git tree-mutators `git apply|restore|
//!   rm|mv|stash pop` (not commit boundaries, so the commit flag-walk never
//!   matches them). The package-manager/`sed`/`tee`/redirect list is a floor;
//!   widening it is follow-up.
//! - **Relative `$VAR`/`$(…)`/backtick-pathed targets** — `cat > "$OUT"`,
//!   `> "$(…)"`, `` > `cmd` ``: the scoped walk carries no assignment/
//!   substitution expansion (that lives only on the flat `command_segments`
//!   view, the #228 bypass class this predicate MUST NOT use), so the
//!   target's true location is unknown and the nudge is **silently skipped**
//!   for that target rather than guessed (#362). Prior to #362 this joined
//!   the literal token onto the effective dir instead (`<cwd>/$OUT`), which
//!   over-fired whenever the cwd was in-primary — e.g. a `$SCRATCH`-style
//!   redirect into a legitimate out-of-tree `/tmp` scratch path was
//!   misjudged as in-primary. Advisory-only, so the silent miss is the
//!   accepted trade (a missed nudge is cheap; a false one is friction). An
//!   *absolute* target with an embedded substitution (`/tmp/$SESSION/f`) is
//!   unaffected — it resolves via the absolute-path branch before expansion
//!   would matter.
//! - **Unreadable runner options** — `sudo -D <dir> <mutator>` and other
//!   runner options core's grammar does not model stop the peel, so the
//!   mutator is never reached (the commit arm calls such a commit unreadable).
//! - **Depth past the wrapper budget** — a mutator in a 4th `sh -c`/`$(…)` level
//!   is not reached (shares [`MAX_WRAPPER_DEPTH`]).
//! - **`sed -i` with multiple files / no file** — only the trailing operand is
//!   taken as the target; a bare `sed -i 's/…/…/'` (no file) is degenerate.
//! - **A mutation nudge is suppressed when the same command also carries a
//!   bypassed `git commit` allow** (a snooze/env exemption on any commit target
//!   in the command) — the bypass-log record takes precedence, and the same
//!   exemption suppresses the mutation in that repo anyway.
//!
//! Commit-channel (block) targets, and what still misses. Every form that
//! *names* a tree is now resolved rather than skipped (#378): `--work-tree=…` /
//! `--git-dir=…` and their separate-value spellings, a `GIT_WORK_TREE=` /
//! `GIT_DIR=` env prefix, and `git -C <path>` — including repeated `-C`s, which
//! accumulate the way git documents them. Precedence runs `--work-tree` →
//! `--git-dir` → `-C` → the segment's dir, with an explicit flag outranking its
//! own env var. So committing into the primary from elsewhere blocks by every
//! one of those spellings, committing into a worktree *from* the primary does
//! not (the env-prefix inversion that used to be an accepted false block is
//! gone), and an unresolvable value still fails open in [`assess_dir`].
//! A `cd` is followed only in a PLAIN command ([`is_plain_shape`]): segments
//! joined by `&&`, `;`, newlines and pipes between non-`cd` commands, with no
//! subshell, group, substitution, compound keyword, `eval`/`source`/`alias`,
//! variable-assigning builtin, or redirection beyond `/dev/null`, `2>&1` and
//! input files. [`walk_plain`] walks it in order, keeping the few directories
//! the shell may be in (a `cd` into a missing directory, or one behind `&&`
//! after another command, may not have run). A `cd` behind `builtin`,
//! `command`, `time`, `!`, a redirection or an assignment word is a `cd`
//! (#1057). Every other command takes [`union_scan`]: each commit is judged
//! from the session cwd and every directory any `cd` in it names, and a `cd`
//! it cannot read blocks the commit from a worktree too (#1058, #346).
//!
//! Commits inside `sh -c '…'` wrappers, `$(…)`/backtick substitutions, and
//! behind `env`/`VAR=value` prefixes ARE seen (#228) — any run of
//! transparent-prefix or assignment words ahead of a wrapper
//! (`env exec sh -c '…'`) is stripped before the wrapper detection runs, and a
//! `GIT_WORK_TREE=`/`GIT_DIR=` prefix is inherited by the wrapper's child the
//! way the shell exports it. A command runner's own options are walked with
//! core's grammar (`nice -n 10`, `timeout 5`, `sudo -u me`, `stdbuf -o0`,
//! `xargs -0`, and `env`'s own parse), and a runner option it cannot read makes
//! the commit unreadable (cadence-hooks#1111). A `GIT_DIR`/`GIT_WORK_TREE`
//! value exported anywhere in the command (`export`, `declare -x`, a bare
//! assignment later exported or under `set -a`) reaches every commit that does
//! not set its own ([`git_exports`]), and a heredoc a shell runs (`cat <<EOF |
//! sh`, `bash <<EOF`, `eval "$(cat <<EOF …)"`) is walked as a child script
//! ([`interpreted_heredoc_bodies`]) (cadence-hooks#1113). Misses that remain,
//! all deliberate: `xargs`-fed arguments are not reconstructed (a `{}` target
//! is unreadable); wrappers past [`MAX_WRAPPER_DEPTH`] are not descended; a
//! script written to a file and then run, or a heredoc captured into a
//! variable and run later, is not followed.
//!
//! Two deliberate divergences from the shell, both erring toward *seeing more*
//! of a command rather than less, since a miss is the dangerous direction here:
//! a git env prefix is inherited into `$(…)`/backtick substitution bodies even
//! though bash applies an assignment prefix only *after* expansion (so a real
//! substitution does not see it); and `..` is folded lexically by
//! [`lexical_normalize`], which differs from real resolution when a path
//! component is a symlink — that only ever keeps a target the exclusion would
//! have dropped, never the reverse.
//!
//! Every target above is resolved SOLELY from the payload `cwd` — the guard
//! reads no session state and no process cwd. A dispatched subagent inherits the
//! orchestrator's cwd, so a verdict naming the orchestrator's repo when the work
//! "feels" like it is happening elsewhere is correct attribution of where the
//! command would actually run, not misattribution (#377).

use crate::dismiss_enforce_worktree;
use crate::messages::WORKTREE_CREATE_RECIPE;
use cadence_hooks_core::display::{MAX_PATH_DISPLAY, sanitize_field};
use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::shell::{
    MAX_WRAPPER_DEPTH, MarkedToken, basename, child_scripts, command_word, expand_leading_home,
    heredoc_introducers, installs_trap_action, is_assignment_word, is_transparent_prefix_word,
    looks_absolute, redirect_operator_span, redirect_targets, resolve_cd_target, skip_runner_flags,
    skip_transparent_prefixes, split_segments_with_ops, split_segments_with_ops_joining_redirects,
    strip_compound_heads, strip_heredoc_bodies, tokenize, tokenize_marked, unescape_word,
};
// Carve-out predicates and `git_dir_for_input` come straight from
// `core::worktree` — no longer borrowed from `warn_main_branch` (cadence-hooks#164).
use cadence_hooks_core::worktree::{
    git_dir_for_input, is_claude_managed_dir, is_plan_doc_dir, is_primary_checkout, is_temp_root,
    is_truthy, should_block,
};
use cadence_hooks_core::{BypassKind, BypassProvenance, Check, CheckResult, HookInput, Outcome};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Environment inputs resolved once per invocation, injected into the
/// assessment so tests can pin them without touching process env.
struct EnvConfig {
    /// `CADENCE_ALLOW_MAIN` — repo works on main by design (dotfiles, vaults).
    allow_main: bool,
    /// `CADENCE_NO_ENFORCE_WORKTREE` — user-global kill switch.
    kill_switch: bool,
    /// `$TMPDIR`, for the scratch-repo exemption.
    tmpdir: Option<String>,
    /// The user's home directory, so a `$TMPDIR` that swallows it is refused
    /// the scratch exemption rather than exempting the whole checkout tree
    /// (cadence-hooks#569).
    home: String,
}

impl EnvConfig {
    fn from_env() -> Self {
        let truthy = |var: &str| is_truthy(std::env::var(var).ok().as_deref());
        Self {
            allow_main: truthy("CADENCE_ALLOW_MAIN"),
            kill_switch: truthy("CADENCE_NO_ENFORCE_WORKTREE"),
            tmpdir: std::env::var("TMPDIR").ok(),
            home: cadence_hooks_core::paths::user_home_lossy_or_default(),
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

/// Per-invocation memo of the [`GitState`] resolution this guard repeats, keyed
/// by directory, so one invocation never re-walks the same tree. Constructed
/// fresh per hook invocation — no cross-invocation cache (mirrors
/// [`RepoAllowMain`]).
///
/// `GitState` replaces the prior `git rev-parse --show-toplevel` /
/// `--git-common-dir` subprocess probes entirely (cadence-hooks#164): repo
/// root, shared common dir, and primary-vs-worktree now come from a filesystem
/// walk, so `enforce-worktree` spawns **zero** `git` for identity and is immune
/// to a slow/hanging `.git` (the residual #271 exposure). The `common_dir` /
/// `repo_root` accessors keep their string return types — `GitState`
/// canonicalizes both to the same `--path-format=absolute` form the old probes
/// returned, so every call site (same-repo scoping, snooze marker, block
/// message) is byte-for-byte unchanged. A nonexistent `dir` resolves to `None`,
/// matching git's `-C` failure (cadence-hooks#299).
#[derive(Default)]
struct GitProbe {
    states: HashMap<PathBuf, Option<GitState>>,
    /// Memo of the "repo has zero commits anywhere" probe, keyed by the dir
    /// passed in. `true` = commitless (unborn-HEAD bootstrap). Populated lazily
    /// on the would-block path only (see [`GitProbe::is_commitless`]).
    commitless: HashMap<PathBuf, bool>,
}

impl GitProbe {
    /// Memoized [`GitState::resolve`].
    fn state(&mut self, dir: &Path) -> Option<GitState> {
        self.states
            .entry(dir.to_path_buf())
            .or_insert_with(|| GitState::resolve(dir))
            .clone()
    }

    /// The shared git common dir (canonical), or `None` when `dir` isn't a repo.
    fn common_dir(&mut self, dir: &Path) -> Option<String> {
        self.state(dir)
            .map(|s| s.git_common_dir.to_string_lossy().into_owned())
    }

    /// The repo root (canonical), or `None` when `dir` isn't a repo.
    fn repo_root(&mut self, dir: &Path) -> Option<String> {
        self.state(dir)
            .map(|s| s.repo_root.to_string_lossy().into_owned())
    }

    /// Does the repo at `dir` have **zero commits reachable from any ref**?
    /// Memoized (mirrors [`common_dir`]/[`repo_root`]). This is the bootstrap
    /// exemption's predicate (#309): a genuinely commitless repo can't be
    /// worktree'd — `git worktree add -b <b>` needs a commit to branch from —
    /// so the guard's own remedy is impossible and its first commit MUST land
    /// in the primary checkout.
    ///
    /// The predicate keys on "any commit anywhere" (`rev-list --all`), **not**
    /// the current HEAD: a `git checkout --orphan` / `git update-ref -d HEAD`
    /// established repo has an unborn *current* HEAD but its commits survive on
    /// other refs, so a worktree IS still possible there — exempting it would
    /// reopen the ADR-0030 collision the guard exists to stop. `--count -n1`
    /// caps the walk at one commit, so this is O(1), not a full-graph count
    /// (#271 latency discipline).
    ///
    /// **Fails closed.** Only an affirmative `Value("0")` is the exempt signal.
    /// [`git_command_detailed`](cadence_hooks_core::shell::git_command_detailed)
    /// collapses success-with-empty-output into `Failed`, so a non-empty
    /// `Value` is the sole outcome distinguishable from a probe error; a commits
    /// -exist `Value(non-"0")`, a spawn failure / nonzero exit (`Failed`), and a
    /// deadline `TimedOut` all return `false` → the block stands. (Using the
    /// plain `git_command` `Option` wrapper would fold a slow-`.git` `TimedOut`
    /// into the same `None` as unborn and flip an established-repo block to an
    /// allow — this is the third git spawn under the shared #271 deadline, the
    /// most likely to be starved.)
    fn is_commitless(&mut self, dir: &Path) -> bool {
        if let Some(&cached) = self.commitless.get(dir) {
            return cached;
        }
        let commitless = matches!(
            cadence_hooks_core::shell::git_command_detailed(
                &dir.to_string_lossy(),
                &["rev-list", "--count", "-n1", "--all"],
            ),
            cadence_hooks_core::shell::GitQuery::Value(ref v) if v == "0"
        );
        self.commitless.insert(dir.to_path_buf(), commitless);
        commitless
    }
}

/// A resolved commit target directory (absolute, or built by joining `cwd`
/// with the accumulated `cd`s and/or a `-C` redirect — see
/// [`git_commit_targets`]).
type CommitTarget = String;

/// A resolved subprocess-mutation location surfaced by the same scoped walk
/// (see [`scan_targets`]). The variant records whether the path is a
/// **directory** (a package-manager verb's effective cwd) or a **file** (a
/// `sed -i`/`tee`/redirect target) — the distinction is load-bearing in
/// [`mutation_nudge`], which must resolve a *file* to its parent directory
/// before any `git` probe (a `git -C <file> rev-parse` errors "Not a
/// directory", which silently dropped the nudge for the already-existing
/// tracked file the feature targets — security-review FIX 1). Assessed for a
/// **nudge** (never a block) only when it lands in the session's own primary
/// checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationTarget {
    /// A package-manager verb runs in this directory (already a directory).
    Dir(String),
    /// A file mutator (`sed -i`, `tee`) or redirect writes this file path;
    /// resolve to its parent directory before probing git.
    File(String),
}

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
/// bodies DO execute, though — the union path recurses into each segment's
/// child scripts (see [`union_scan`], issue #228).
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
/// True when `tokens[idx]` is a leading word the real command runs *through* —
/// a transparent prefix whose next token is not the prefix's own flag, or an
/// assignment word.
///
/// Extracted because TWO walks cross this same leading region:
/// [`skip_transparent_prefixes`], which skips it, and [`git_env_overrides`],
/// which reads the git vars out of it first. Duplicating the predicate would let
/// them disagree about where the region ends, and a walk that stopped early
/// would silently miss an override — so they share one definition.
///
/// **The membership half now really is one definition.** It was a local
/// `TRANSPARENT.contains(&tok)` on the raw, unfolded token while core's copy
/// learned to fold (#488) and then to unescape (#237) — so the claim above was
/// false in exactly the way it warns about, twice. `\exec GIT_DIR=/other git
/// commit` moved from *never inspected* to *inspected with the redirect
/// invisible*: the leading-word gate reached the commit while this walk stopped
/// at index 0 and returned `(None, None)`, judging the commit against the
/// session cwd. From a primary checkout that is a false BLOCK on a commit git
/// performs elsewhere. Both sides call
/// [`cadence_hooks_core::shell::names_transparent_prefix`] now, and a test pins
/// that the two walks stop at the same index.
///
/// Total over any index: an out-of-range `idx` is `false`, and a trailing prefix
/// with nothing after it is not a prefix word (there is no command for it to run
/// through). Both callers already bound `idx + 1`, so this is belt-and-braces —
/// but a panic in a guard is a hard block by another name, which ADR-0001's
/// fail-open posture forbids.
fn is_prefix_word(tokens: &[String], idx: usize) -> bool {
    is_transparent_prefix_word(tokens, idx)
}

/// Read `GIT_WORK_TREE=`/`GIT_DIR=` out of the leading assignment words that
/// [`skip_transparent_prefixes`] otherwise discards, returning the values
/// **RAW** as `(work_tree, git_dir)`.
///
/// `GIT_DIR=… GIT_WORK_TREE=… git commit` names a target tree just as plainly as
/// `--work-tree` does, and the walk was throwing that away — a bypass from a
/// worktree into the primary, and the mirror-image false block the module header
/// used to accept as exotic (#378). Walks the same leading region as
/// [`skip_transparent_prefixes`], over the shared [`is_prefix_word`] predicate
/// (assignment words and transparent prefixes may interleave:
/// `env GIT_DIR=… command git commit`), and stops at the command word.
///
/// **Raw, not resolved, and that is load-bearing.** This walk runs over the raw
/// token stream, before the global-flag walk has seen `-C` — and git applies the
/// `-C` chdir BEFORE repository setup, so a relative env value is relative to
/// the POST-`-C` directory. Resolving here against the pre-`-C` dir while the
/// env value outranks the `-C` redirect turned `GIT_WORK_TREE=. git -C <primary>
/// commit` into an Allow: the guard resolved the session's own worktree while
/// git committed into the primary. [`commit_targets_of`] resolves these against
/// the same post-`-C` base the explicit flags use, which also keeps both call
/// sites in sync by construction (security review, #378).
///
/// The walk continues through an `env` with options, as
/// [`peel_with_chdirs`] does: `env -i` drops both values inherited from
/// before it, `env -u GIT_DIR` drops that one, and an assignment after the
/// options (`env -i GIT_DIR=<p>/.git git commit`) is read (cadence-hooks#1100).
fn git_env_overrides(tokens: &[String]) -> (Option<&str>, Option<&str>) {
    let (mut work_tree, mut git_dir) = (None, None);
    let mut idx = 0;
    while idx + 1 < tokens.len() {
        if is_prefix_word(tokens, idx) {
            let tok = tokens[idx].as_str();
            if let Some(v) = tok.strip_prefix("GIT_WORK_TREE=") {
                work_tree = Some(v);
            } else if let Some(v) = tok.strip_prefix("GIT_DIR=") {
                git_dir = Some(v);
            }
            idx += 1;
            continue;
        }
        // A command runner passes the environment through to its command
        // (`sudo GIT_DIR=<p>/.git git commit` even sets it): walk its options
        // as [`peel_heads`] does (cadence-hooks#1111).
        let runner = command_word(&tokens[idx]);
        if RUNNERS.contains(&runner.as_ref()) {
            let Some(rest) = skip_runner_flags(&runner, &tokens[idx + 1..]) else {
                break;
            };
            idx = tokens.len() - rest.len();
            continue;
        }
        if !is_env_with_options(&tokens[idx..]) {
            break;
        }
        let Some(flags) = parse_env_flags(&tokens[idx + 1..]) else {
            break;
        };
        if flags.clears {
            (work_tree, git_dir) = (None, None);
        }
        for name in &flags.unsets {
            match name.as_str() {
                "GIT_WORK_TREE" => work_tree = None,
                "GIT_DIR" => git_dir = None,
                _ => {}
            }
        }
        idx += 1 + flags.consumed;
    }
    (work_tree, git_dir)
}

/// Fold `.`, `..`, `//`, and a trailing slash out of a path **lexically** — no
/// filesystem access, so it is safe on paths that do not exist and cannot
/// surprise a caller by resolving `/var` to `/private/var`.
///
/// This is the fix for the whole class of raw-string decisions in this module.
/// `GitState::resolve` canonicalizes, so **assessment** was always immune to
/// spelling; every decision made on the raw target string — the linked-worktree
/// exclusion below, the in-chain dismiss-map key, the dedup key — was not. That
/// asymmetry is the defect. `<primary>/.git/worktrees/..` IS `<primary>/.git`,
/// but `Path::components()` preserves `..`, so the exclusion matched it and
/// dropped the primary's own git dir — the guard's headline control evaded by
/// appending two characters (security review, #378).
///
/// Folding `..` lexically differs from real resolution when a component is a
/// symlink. That is the safe direction here: it only ever causes a target to be
/// KEPT rather than excluded, and the kept target is then assessed by
/// [`GitState`], which canonicalizes properly.
///
/// A Windows drive-absolute prefix (`C:/…` or `C:\…`) is folded too, and is
/// what closes the guard's Windows fail-open (cadence-hooks#377/#378): every
/// commit target this module emits is run through this fold via
/// [`normalize_target`], and on Windows those raw targets are real native
/// paths (a hook's `cwd`, or a `-C`/`--git-dir` value carrying the drive
/// letter), not the pure forward-slash "shell path" the fold used to assume.
/// Splitting on `/` alone left a `C:\…` prefix as ONE opaque segment — not
/// recognized as absolute, and not decomposed into its real components — so a
/// literal `..` elsewhere in the same string (this crate's own test fixture
/// paths carry one, joined via `Path::join("../../target/…")`) popped that
/// whole opaque prefix instead of its last real component, discarding the
/// drive letter entirely and turning an absolute target into a relative
/// fragment that resolved to no repo. [`GitState`] then found nothing at the
/// corrupted path and the guard failed open (`Allow`) on a commit that landed
/// in the primary checkout.
fn lexical_normalize(path: &str) -> String {
    // A pure STRING fold — deliberately NOT a `Path`/`PathBuf` round-trip,
    // which would re-join with the PLATFORM separator and normalize a target
    // to a spelling the rest of the module (and the dismiss map keyed on
    // these strings) doesn't produce. `resolve_cd_target` carries the same
    // warning about `PathBuf::join` for the same reason.
    //
    // The Windows drive prefix, if any, is captured separately from the body:
    // folding must never let a `..` pop past it (`C:\foo\..\bar` is `C:\bar`,
    // never a bare `\bar` that silently drops the drive), and it is lowercased
    // on the way out — NTFS/ReFS are case-insensitive, so `C:\Primary` and
    // `c:\primary` must fold to the same string or the in-chain dismiss map's
    // string-equality lookup stops matching one of the two spellings.
    let bytes = path.as_bytes();
    // Borrowed, not lowercased here — the whole result is lowercased once on
    // the way out below, so lowercasing this slice too would just be a
    // discarded allocation.
    let windows_drive = (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\'))
        .then(|| &path[..1]);
    let body_src = windows_drive.map_or(path, |_| &path[3..]);
    let absolute = windows_drive.is_some() || body_src.starts_with('/');
    // Backslash is only ever a separator once a Windows drive prefix has
    // already identified the string as a native Windows path — a bare POSIX
    // path may legally contain a literal `\` in a filename, so splitting on
    // it unconditionally would corrupt that spelling instead of folding it.
    let separators: &[char] = if windows_drive.is_some() {
        &['/', '\\']
    } else {
        &['/']
    };
    let mut out: Vec<&str> = Vec::new();
    for segment in body_src.split(separators) {
        match segment {
            // An empty segment is a `//` collapse or a trailing slash.
            "" | "." => {}
            ".." => match out.last() {
                // Only a real name can be popped. A leading run of `..` in a
                // relative path must survive, so `..` never pops a `..`.
                Some(&last) if last != ".." => {
                    out.pop();
                }
                // `/..` (or a drive root's `..`) is the root itself.
                _ if absolute => {}
                _ => out.push(".."),
            },
            name => out.push(name),
        }
    }
    let body = out.join("/");
    let folded = match (absolute, body.is_empty()) {
        (true, _) => format!("/{body}"),
        // Nothing survived a relative fold (`a/..`) — leave the caller's
        // spelling alone rather than inventing a `.`; `GitState` resolves it.
        (false, true) => return path.to_string(),
        (false, false) => body,
    };
    match windows_drive {
        // Lowercase the WHOLE path, not just the drive letter: NTFS/ReFS is
        // case-insensitive throughout, not only on the drive, so `C:\Primary`
        // and `c:\primary` must fold to one identical key.
        Some(drive) => format!("{drive}:{folded}").to_ascii_lowercase(),
        None => folded,
    }
}

/// Normalize a commit or dismiss target so every spelling of one repository
/// produces ONE key.
///
/// Applied **symmetrically** to both sides of the in-chain dismiss map. That
/// symmetry is what matters: the map is keyed by string, so a `--repo <p>/`
/// dismissing a `--work-tree=<p>` commit only matches if both go through here.
/// A `<repo>/.git` value collapses to `<repo>` for the same reason; a bare
/// repository's own directory (`/srv/thing.git`) is not `.git` and survives.
fn normalize_target(path: &str) -> String {
    let normalized = lexical_normalize(path);
    match Path::new(&normalized) {
        p if p.file_name().is_some_and(|n| n == ".git") => p
            .parent()
            .filter(|q| !q.as_os_str().is_empty())
            .map(|q| q.to_string_lossy().into_owned())
            .unwrap_or(normalized),
        _ => normalized,
    }
}

/// True when a `--git-dir`/`GIT_DIR` value names a LINKED worktree's admin
/// directory (`<primary>/.git/worktrees/<name>`) rather than a repository's own
/// git dir.
///
/// Such a path must not be emitted as a commit target: git resolves it to the
/// linked worktree, but a naive walk up from it lands on the primary checkout
/// and would false-block the legitimate spelling for committing into a worktree
/// (security review, #378).
///
/// The check is lexical, so it runs on a [`lexical_normalize`]d path — see there
/// for the `..` evasion that motivated it.
fn is_linked_worktree_admin_dir(path: &str) -> bool {
    let normalized = lexical_normalize(path);
    let names: Vec<&str> = Path::new(&normalized)
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    names
        .windows(2)
        .any(|w| w[0] == ".git" && w[1] == "worktrees")
}

// `is_assignment_word` is no longer imported here. `is_prefix_word` needed
// exactly the predicate `skip_transparent_prefixes` uses, and assembling it
// locally out of shared parts still left room to drift — which it did, twice, at
// the membership half (cadence-hooks#488, then #237). The whole predicate now
// lives in core as `is_transparent_prefix_word`, so there is nothing left here
// to assemble.

/// A shell path is absolute if git will treat it as absolute: a leading `/`
/// (POSIX / WSL / Git-Bash shell paths) OR a Windows drive path, spelled with
/// either separator (`C:/…` or `C:\…` — issue #235).
///
/// [`looks_absolute`] makes this decision from the STRING alone, so it agrees
/// on a `C:\…` target whether this binary is compiled for Windows or not — the
/// prior form relied on `Path::is_absolute`, which is only drive-letter-aware
/// when compiled for Windows, so the same `C:\…` target read absolute on a
/// Windows build and relative everywhere else. That platform split is exactly
/// what let a Windows-native target fall through to a relative join and
/// resolve to nowhere (the guard's Windows fail-open, cadence-hooks#377/#378);
/// it also meant this decision could only be tested on a Windows runner.
/// `Path::is_absolute` stays as a belt-and-braces fallback for a native
/// Windows form the string check doesn't cover (e.g. a UNC `\\server\share`).
fn is_shell_absolute(path: &str) -> bool {
    looks_absolute(path) || Path::new(path).is_absolute()
}

/// Walk `command` once, returning both output channels: the `git commit`
/// targets (block channel) and the subprocess-mutation locations (nudge
/// channel). One walk, two channels — the block channel is evaluated first in
/// [`run_enforce`] so a `uv add && git commit` into the primary blocks (commit
/// wins) and never *also* nudges.
///
/// Two paths (cadence-hooks#1058). A PLAIN command — one whose shape is on the
/// [`is_plain_shape`] allowlist — is walked in order by [`walk_plain`], which
/// tracks the few directories the shell may be in. Every other command takes
/// the fail-closed [`union_scan`]: each commit is judged from the session cwd
/// AND every directory any `cd` in the command names, and a `cd` it cannot
/// read is reported so [`run_enforce`] can block it from a worktree. Four
/// rounds of modelling bash scoping (subshells, `case`, backgrounded lists,
/// `OLDPWD`) each opened new holes; the allowlist is the same structure that
/// closed #1018.
///
/// `on_disk` is true in production; see [`CdEnv`].
#[cfg(test)]
fn scan_targets(command: &str, cwd: &str, on_disk: bool) -> Scan {
    let home = dollar_home(command);
    let env = CdEnv::for_command(command, home.as_deref(), on_disk);
    let plain = plain_of(command, cwd, env);
    scan_prepared(command, cwd, env, plain.as_ref())
}

/// [`scan_targets`] over an already computed [`plain_of`] — [`run_enforce`]
/// computes it once for both this and the in-chain dismiss scan, since the
/// segmenter's cost grows with the command's line continuations.
fn scan_prepared(command: &str, cwd: &str, env: CdEnv<'_>, plain: Option<&Plain>) -> Scan {
    let mut out = scan_either_path(command, cwd, env, plain);
    // A commit whose checkout cannot be read may land anywhere, the session
    // cwd included: judge it there too, as an unreadable `cd` is judged.
    if out.unreadable.is_some() {
        let here = normalize_target(cwd);
        if !out.commits.contains(&here) {
            out.commits.push(here);
        }
    }
    out
}

/// [`scan_prepared`]'s two paths.
fn scan_either_path(command: &str, cwd: &str, env: CdEnv<'_>, plain: Option<&Plain>) -> Scan {
    if let Some(plain) = plain {
        let mut out = Scan::default();
        let walked = walk_plain(plain, cwd, env, |seg| {
            if seg.is_cd {
                return;
            }
            let (argv, work_tree, git_dir) = plain_command(&seg.words);
            for dir in seg.dirs {
                detect_mutations(argv, seg.segment, &dir.pwd, &mut out.mutations);
                out.commits.extend(commit_targets_of(
                    argv,
                    &dir.pwd,
                    work_tree,
                    git_dir,
                    env,
                    &mut out.unreadable,
                ));
            }
        });
        if walked.is_some() {
            return out;
        }
    }
    // Scan the carved text when the raw scan accepted it: a carve-out's body
    // is inert, and its placeholder marks where a substitution's output
    // lands (`cd "$(cat <<'EOF' …)"`), which the union path treats as unreadable.
    let carved = plain_carve(command)
        .map(|(text, _)| text)
        .filter(|text| text.contains(CARVED));
    let mut out = union_scan(carved.as_deref().unwrap_or(command), cwd, env);
    if carved.is_some() {
        merge_scan(&mut out, union_scan(command, cwd, env));
    }
    match interpreted_heredoc_bodies(command) {
        Some(bodies) if !bodies.is_empty() => {
            merge_scan(&mut out, union_scan_bodies(command, &bodies, cwd, env));
        }
        Some(_) => {}
        None if command.contains("commit") => {
            out.unresolved_cd
                .get_or_insert_with(|| "… (too many heredocs run by a shell)".to_string());
            let here = normalize_target(cwd);
            if !out.commits.contains(&here) {
                out.commits.push(here);
            }
        }
        None => {}
    }
    if command_heredocs_suspect(command) {
        // Core may have stripped lines bash runs as heredoc body: read every
        // line as code too, with no heredoc stripping (#1084) — except the
        // lines of a body whose delimiter was read plainly, which bash reads
        // as data (cadence-hooks#1101).
        let delims = substitution_heredoc_delims(command);
        let bodies = plain_carve_bodies(command)
            .map(|carve| carve.confident_bodies())
            .unwrap_or_default();
        let mut at = 0;
        let lines = command
            .split('\n')
            .map(|line| {
                let start = at;
                at += line.len() + 1;
                if bodies.iter().any(|body| body.contains(&start)) {
                    Cow::Borrowed("")
                } else {
                    split_early_heredoc_end(line, delims.as_deref().unwrap_or(&[]))
                }
            })
            .collect::<Vec<_>>()
            .join(" ; ");
        merge_scan(&mut out, union_scan(&lines, cwd, env));
        // And quote-blind: a quote on a line bash reads as heredoc body
        // (`<<"E\"F"` then `E"F`) throws the joined reading's quote state off
        // for every later line, hiding what bash runs there. Dropping quotes
        // and escapes can only make more text read as code.
        let bare: String = lines
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | '\\'))
            .collect();
        merge_scan(&mut out, union_scan(&bare, cwd, env));
        if delims.is_none() && command.contains("commit") {
            // Where a substitution heredoc ends cannot be read, so neither can
            // what runs after it: judge a commit from the session cwd, and
            // block it from a worktree as an unreadable cd would.
            out.unresolved_cd
                .get_or_insert_with(|| "… (unreadable heredoc in a substitution)".to_string());
            if !out.commits.iter().any(|c| c == cwd) {
                out.commits.push(cwd.to_string());
            }
        }
    }
    out
}

/// Fold a second union scan of the same command into `out`.
fn merge_scan(out: &mut Scan, extra: Scan) {
    for target in extra.commits {
        if !out.commits.contains(&target) {
            out.commits.push(target);
        }
    }
    for target in extra.mutations {
        if !out.mutations.contains(&target) {
            out.mutations.push(target);
        }
    }
    out.unresolved_cd = out.unresolved_cd.take().or(extra.unresolved_cd);
    out.unresolved_commit = out.unresolved_commit.take().or(extra.unresolved_commit);
    out.unreadable = out.unreadable.take().or(extra.unreadable);
    out.union_cd_dirs.extend(extra.union_cd_dirs);
}

/// Test stand-in for the on-disk probes: every path exists, so the parser
/// tests can name fictional directories.
fn assume_exists(_: &str) -> bool {
    true
}

/// Test-only view of the commit channel (production reads both channels via
/// [`scan_targets`]); the many commit-parsing tests exercise it directly.
#[cfg(test)]
fn git_commit_targets(command: &str, cwd: &str) -> Vec<CommitTarget> {
    scan_targets(command, cwd, false).commits
}

/// Test-only view of the mutation channel (production reads both channels via
/// [`scan_targets`]).
#[cfg(test)]
fn mutation_targets(command: &str, cwd: &str) -> Vec<MutationTarget> {
    scan_targets(command, cwd, false).mutations
}

/// A package-manager subcommand that mutates a manifest/lockfile in its cwd:
/// `uv add|remove|sync`, `cargo add|rm`, `pip install`, `npm install|i|add`,
/// `pnpm add|install`, `poetry add`, `yarn add`. Coarse v1 taxonomy — the cwd
/// being the primary checkout is the sole trigger, no path resolution (a
/// package manager writes its manifest relative to cwd). `python -m pip …`,
/// `sudo`-wrapped forms, and unlisted managers are named accepted misses.
///
/// The verb goes through [`command_word`], not a bare `basename`: `\npm
/// install` / `\cargo add` produced no mutation target at all — the same
/// silent-ALLOW shape as #450's commit gate, one function over. This arm feeds
/// [`mutation_nudge`], which is **advisory** (exit 0), so the cost of the miss
/// was a lost nudge rather than a bypassed block — unlike the commit gate.
fn is_package_mutation(argv: &[String]) -> bool {
    let Some(cmd) = argv.first() else {
        return false;
    };
    let sub = argv.get(1).map(String::as_str);
    matches!(
        (command_word(cmd).as_ref(), sub),
        ("uv", Some("add" | "remove" | "sync"))
            | ("cargo", Some("add" | "rm"))
            | ("pip" | "pip3", Some("install"))
            | ("npm", Some("install" | "i" | "add"))
            | ("pnpm", Some("add" | "install"))
            | ("poetry", Some("add"))
            | ("yarn", Some("add"))
    )
}

/// Target files of a direct in-place mutator verb with a resolvable target:
/// `sed -i <file>` (requires an in-place flag; the file is the trailing
/// operand — multiple files catch only the last) and `tee <file>` (every
/// non-flag operand). Other tree mutators (`cp`/`mv`/`dd`/`patch`/`perl -i`/
/// `git apply|restore|rm|mv`/…) are named accepted misses — not enumerated.
///
/// Verb via [`command_word`] for the same reason [`is_package_mutation`] uses
/// it: `\sed -i Cargo.toml` is a real in-place mutation, and matching on a bare
/// `basename` collected nothing (#450 review). Advisory like that sibling —
/// these targets feed [`mutation_nudge`], not the block arm.
fn file_mutation_targets(argv: &[String]) -> Vec<String> {
    let Some(cmd) = argv.first() else {
        return Vec::new();
    };
    match command_word(cmd).as_ref() {
        "sed" => {
            let in_place = argv.iter().any(|t| {
                t == "-i"
                    || t.starts_with("-i")
                    || t == "--in-place"
                    || t.starts_with("--in-place=")
            });
            if !in_place {
                return Vec::new();
            }
            // sed's non-flag operands are `[script, file...]`, so a file target
            // exists only when there are >= 2 of them (script + at least one
            // file). A bare `sed -i 's/a/b/'` has a single non-flag operand —
            // the SCRIPT, which is not a file — so it is a true no-file
            // degenerate miss (edits nothing), not a target. With >= 2, the
            // file is the trailing operand (multiple files: only the last is
            // taken — a named accepted miss).
            let operands: Vec<&String> = argv
                .iter()
                .skip(1)
                .filter(|t| !t.starts_with('-'))
                .collect();
            if operands.len() >= 2 {
                operands.last().map(|s| (*s).clone()).into_iter().collect()
            } else {
                Vec::new()
            }
        }
        "tee" => argv
            .iter()
            .skip(1)
            .filter(|t| !t.starts_with('-'))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// Resolve a mutator's target path against the segment's effective dir, the
/// same way the commit arm resolves a `-C` redirect: an absolute path (POSIX or
/// Windows-drive via [`is_shell_absolute`]) or a `~`-path stands alone; a
/// relative path joins onto the effective dir. `None` when the token is a
/// **relative, unexpanded shell substitution** — a variable reference
/// (`$VAR/…`, `$(…)/…`) or a backtick command substitution (`` `cmd`/… ``) —
/// the scoped walk carries no assignment/substitution expansion (widening to
/// the flat `command_segments` view is rejected; it's the #228 bypass
/// primitive), so this token's true location is unknown. Joining it onto
/// `effective_dir` would fabricate an in-primary path regardless of what the
/// substitution actually resolves to at runtime — e.g. `cat > "$SCRATCH/f"`
/// where `$SCRATCH` holds an out-of-tree `/tmp` scratch path still gets
/// treated as `<effective_dir>/$SCRATCH/f`, an in-primary false positive
/// (#362; the identical shape reproduces for a bare backtick-led target like
/// `` `date +%s`.log ``, since [`redirect_targets`] returns that token's
/// leading backtick unchanged). Skipping resolution is the safer default for
/// an advisory-only nudge: a false silent-miss is cheap, a false nudge on a
/// legitimate out-of-tree write is friction. An *absolute* target with an
/// embedded substitution (`/tmp/$SESSION/f`) is unaffected — it stands alone
/// via [`is_shell_absolute`] before this branch and resolves (with the
/// substitution segment literal) same as before.
fn resolve_mutation_target(path: &str, effective_dir: &str) -> Option<String> {
    if path.starts_with('~') {
        Some(resolve_cd_target(path, effective_dir))
    } else if is_shell_absolute(path) {
        Some(path.to_string())
    } else if path.starts_with('$') || path.starts_with('`') {
        None
    } else {
        Some(format!("{effective_dir}/{path}"))
    }
}

/// Per-segment mutation detection (#234) — the nudge channel of the scoped
/// walk. Runs on every non-`cd` segment: package-manager manifest mutators
/// (keyed on the effective cwd), direct file mutators (`sed -i`/`tee`), and
/// redirect targets (`>`, `>>`, `>|`, `2>`, … via the shared core parser). All
/// targets are advisory — the primary-checkout scoping, suppression, and
/// block-first ordering live in [`run_enforce`]/[`mutation_nudge`].
fn detect_mutations(
    argv: &[String],
    segment: &str,
    effective_dir: &str,
    mutations: &mut Vec<MutationTarget>,
) {
    if is_package_mutation(argv) {
        mutations.push(MutationTarget::Dir(effective_dir.to_string()));
    }
    for target in file_mutation_targets(argv) {
        if let Some(resolved) = resolve_mutation_target(&target, effective_dir) {
            mutations.push(MutationTarget::File(resolved));
        }
    }
    for target in redirect_targets(segment) {
        if let Some(resolved) = resolve_mutation_target(&target, effective_dir) {
            mutations.push(MutationTarget::File(resolved));
        }
    }
}

/// What one walk found: the block channel, the nudge channel, and — on the
/// union path only — the first `cd` whose target it could not read, and the
/// directories its `cd`s name (for the block message's `git -C` suggestion).
#[derive(Default)]
struct Scan {
    commits: Vec<CommitTarget>,
    mutations: Vec<MutationTarget>,
    unresolved_cd: Option<String>,
    /// The first commit segment whose shape a substitution decides.
    unresolved_commit: Option<String>,
    /// The block message for the first commit whose checkout cannot be read
    /// for another reason: a directory value [`chdir_landing`] cannot read,
    /// a commit in a `trap` action, or one behind an `env` whose options
    /// cannot be read. The session cwd is judged too ([`scan_prepared`]).
    unreadable: Option<String>,
    union_cd_dirs: Vec<String>,
}

/// The words a segment's command runs with: every unquoted redirection (and a
/// bare operator's target) removed, then a leading `!` and `time [-p]` — both
/// reserved words that run the command after them — peeled.
fn command_tokens(marked: &[MarkedToken]) -> Vec<String> {
    let mut words: Vec<String> = Vec::with_capacity(marked.len());
    let mut i = 0;
    while let Some(t) = marked.get(i) {
        if is_unquoted_redirect(t) {
            i += if is_bare_redirect(&t.text) { 2 } else { 1 };
            continue;
        }
        words.push(t.text.clone());
        i += 1;
    }
    let mut start = 0;
    loop {
        match words.get(start).map(String::as_str) {
            Some("!") => start += 1,
            Some("time") => {
                start += 1;
                if words.get(start).map(String::as_str) == Some("-p") {
                    start += 1;
                }
            }
            _ => break,
        }
    }
    words.split_off(start.min(words.len()))
}

/// Asks the filesystem (or a test stand-in) whether a path exists.
type PathProbe = fn(&str) -> bool;

/// What a walk needs from outside the command to resolve a `cd`.
///
/// `dir_exists` and `file_exists` are injected rather than hard-wired so the
/// many parser tests can keep naming fictional directories (`/wt`, `/cwd`).
/// Production always builds it with `on_disk`.
#[derive(Clone, Copy)]
struct CdEnv<'a> {
    /// The home a `$HOME` target expands against ([`dollar_home`]).
    home: Option<&'a str>,
    dir_exists: PathProbe,
    file_exists: PathProbe,
    /// The command may switch cd to physical resolution (`set -P`, `set -o
    /// physical`): a lexical `..` is then unreadable on the union path.
    physical: bool,
    /// Where a path really is, symlinks followed, or `None` when it does not
    /// exist: the directory `git -C` and `env -C` actually `chdir` into.
    canonical: CanonicalProbe,
    /// A `~` may be read as the process home: the command cannot be shown to
    /// rebind HOME ([`tilde_is_home`]). Always true outside [`CdEnv::for_command`].
    tilde: bool,
    /// `GIT_DIR`/`GIT_WORK_TREE` values the command exports to every later
    /// command ([`GitExports`]); set by the union path only.
    exports: Option<&'a GitExports>,
}

impl<'a> CdEnv<'a> {
    /// [`CdEnv::new`] for `command`: a `~` in it reads as the process home
    /// only when [`tilde_is_home`] says nothing in it rebinds HOME.
    fn for_command(command: &str, home: Option<&'a str>, on_disk: bool) -> Self {
        CdEnv {
            tilde: home.is_some() || tilde_is_home(command),
            ..CdEnv::new(home, on_disk)
        }
    }

    /// A walk's environment: the real filesystem when `on_disk` (always, in
    /// production), else every path exists.
    fn new(home: Option<&'a str>, on_disk: bool) -> Self {
        let (dir_exists, file_exists): (PathProbe, PathProbe) = if on_disk {
            (is_dir_on_disk, is_path_on_disk)
        } else {
            (assume_exists, assume_exists)
        };
        let canonical: CanonicalProbe = if on_disk {
            canonical_on_disk
        } else {
            assume_canonical
        };
        CdEnv {
            home,
            dir_exists,
            file_exists,
            physical: false,
            canonical,
            tilde: true,
            exports: None,
        }
    }
}

/// Does `path` name a directory a `cd` can land in? A pure metadata stat, no
/// git spawn (#271).
fn is_dir_on_disk(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// Does `path` exist at all (an input redirection's file)?
fn is_path_on_disk(path: &str) -> bool {
    Path::new(path).exists()
}

/// Resolves a path the way a `chdir` does: every symlink followed.
type CanonicalProbe = fn(&str) -> Option<String>;

/// The real path of `path`, or `None` when it does not exist.
fn canonical_on_disk(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Test stand-in for [`canonical_on_disk`]: no symlinks, so every path is its
/// lexical normalization.
fn assume_canonical(path: &str) -> Option<String> {
    Some(lexical_normalize(path))
}

// ---------------------------------------------------------------------------
// The plain path.
// ---------------------------------------------------------------------------

/// Heads that make a command non-plain: compound-command keywords, anything
/// that runs text as commands or changes what `cd` is (`eval`, `source`, `.`,
/// `enable`, `alias`, `trap`), anything that assigns shell variables `cd`
/// reads (`export`, `read`, `let`, …), and the other directory changers.
const NON_PLAIN_HEADS: &[&str] = &[
    "case",
    "esac",
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "while",
    "until",
    "for",
    "select",
    "do",
    "done",
    "function",
    "coproc",
    "[[",
    "eval",
    "source",
    ".",
    "enable",
    "alias",
    "unalias",
    "trap",
    "exec",
    "export",
    "declare",
    "typeset",
    "local",
    "readonly",
    "read",
    "mapfile",
    "readarray",
    "let",
    "unset",
    "getopts",
    "shopt",
    "pushd",
    "popd",
    "set",
];

/// Redirections a plain command may carry. Anything else — a file target, a
/// descriptor dup other than `2>&1`, `{fd}` forms, a here-string — is not
/// plain. Input from an existing file is allowed separately.
const PLAIN_REDIRECTS: &[&str] = &[
    ">/dev/null",
    "1>/dev/null",
    "2>/dev/null",
    "&>/dev/null",
    ">>/dev/null",
    "2>&1",
];

/// A plain command, analysed once: its segments, with each carved-out message
/// already replaced by [`CARVED`].
struct Plain {
    segments: Vec<(String, Option<&'static str>)>,
}

/// The command as a [`Plain`] when its shape is plain, else `None`.
fn plain_of(command: &str, cwd: &str, env: CdEnv<'_>) -> Option<Plain> {
    // A heredoc a shell runs is code the plain walk would read as data.
    if interpreted_heredoc_bodies(command).is_none_or(|bodies| !bodies.is_empty()) {
        return None;
    }
    let carve = plain_carve_bodies(command)?;
    if heredoc_reading_suspect(command, &carve) {
        return None;
    }
    let segments = split_segments_with_ops_joining_redirects(&carve.text);
    plain_segments_ok(&segments, cwd, env).then_some(Plain { segments })
}

/// Could core's heredoc reading disagree with bash's here? Core's
/// `heredoc_introducers` did not model escapes (cadence-hooks#1084), so an
/// escaped `\<`, or an escaped quote anywhere near a `<<`, could make it read a
/// heredoc (or a delimiter) bash does not see — and strip, as body, lines bash
/// runs. It reads them with the shared quote model now (#813, #1116); the
/// escape shapes stay suspect here as a second, independent reading. Also
/// suspect:
/// `plain_carve`'s own heredoc count differing from core's on the same text.
/// A suspect command is never plain, and the union path also reads it line by
/// line with no heredoc stripping at all ([`scan_prepared`]).
///
/// Escapes are looked for outside the bodies [`plain_carve`] read with a
/// plainly spelled delimiter: body text is data to bash, and core, which
/// matches a body's end line by line, never reads a quote in one
/// (cadence-hooks#1101). A delimiter with an escape or an inner quote in it
/// is not plainly spelled, so its body still counts.
fn heredoc_reading_suspect(command: &str, carve: &Carve) -> bool {
    if escapes_hide_a_heredoc(&outside_ranges(command, &carve.confident_bodies())) {
        return true;
    }
    let carved = carve.text.as_str();
    if !carved.contains("<<") {
        return carve.heredocs != 0;
    }
    let core_heredocs: usize = strip_heredoc_bodies(carved)
        .split('\n')
        .map(|line| heredoc_introducers(line).len())
        .sum();
    core_heredocs != carve.heredocs
}

impl Carve {
    /// Every body read with a plainly spelled delimiter, in command order.
    fn confident_bodies(&self) -> Vec<Range<usize>> {
        let mut all: Vec<Range<usize>> = self
            .message_bodies
            .iter()
            .chain(&self.heredoc_bodies)
            .cloned()
            .collect();
        all.sort_by_key(|r| r.start);
        all
    }
}

/// `text` with the (sorted, disjoint) byte `ranges` removed.
fn outside_ranges(text: &str, ranges: &[Range<usize>]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    for range in ranges {
        out.push_str(&text[from..range.start]);
        from = range.end;
    }
    out.push_str(&text[from..]);
    out
}

/// An escaped `<` anywhere, or an escaped quote anywhere in a command with a
/// `<<`: the shapes core's escape-blind heredoc reading gets wrong (#1084).
/// An escaped quote inside a delimiter word (`<<"E\"F"`) changes the
/// delimiter as much as one before the operator changes where it starts.
fn escapes_hide_a_heredoc(command: &str) -> bool {
    command.contains("\\<")
        || (command.contains("<<") && (command.contains("\\'") || command.contains("\\\"")))
}

/// [`heredoc_reading_suspect`] from the raw command alone. A command
/// [`plain_carve`] refuses has no heredoc count to compare, so only the
/// escape shapes count.
fn command_heredocs_suspect(command: &str) -> bool {
    if substitution_heredoc_ends_early(command) {
        return true;
    }
    match plain_carve_bodies(command) {
        Some(carve) => heredoc_reading_suspect(command, &carve),
        // A continued line near a heredoc may split its delimiter (`EO\`
        // then `F`), which core's heredoc reading does not join.
        None => escapes_hide_a_heredoc(command) || continuation_splits_a_delimiter(command),
    }
}

/// The most distinct delimiters [`substitution_heredoc_delims`] collects;
/// past it the delimiters are unreadable.
const MAX_SUBSTITUTION_DELIMS: usize = 16;

/// The delimiters of the heredocs a command opens after a `$(`, each with the
/// byte its body can begin at. Read from the raw command with no quoting
/// model: every `<<` anywhere after the first `$(`. `None` when one cannot be
/// read, or past [`MAX_SUBSTITUTION_DELIMS`] distinct ones.
fn substitution_heredoc_delims(command: &str) -> Option<Vec<(String, usize)>> {
    let mut delims: Vec<(String, usize)> = Vec::new();
    let Some(first_open) = command.find("$(") else {
        return Some(delims);
    };
    for (at, _) in command[first_open..].match_indices("<<") {
        let at = first_open + at;
        if command[at..].starts_with("<<<") || command[..at].ends_with('<') {
            continue;
        }
        let (heredoc, _) = parse_heredoc_operator(&command[at..])?;
        // The first opener of a delimiter has the earliest body: keep it.
        if delims.iter().any(|(d, _)| *d == heredoc.delim) {
            continue;
        }
        if delims.len() == MAX_SUBSTITUTION_DELIMS {
            return None;
        }
        let body = command[at..]
            .find('\n')
            .map_or(command.len(), |n| at + n + 1);
        delims.push((heredoc.delim, body));
    }
    Some(delims)
}

/// Could a heredoc opened after a `$(` end early, at a body line bash 5.2
/// reads as its end plus code ([`ends_a_substitution_heredoc`])? Core strips
/// such a line and the ones after it as body, so the union path must also
/// read the command line by line. Unreadable delimiters are suspect.
fn substitution_heredoc_ends_early(command: &str) -> bool {
    let Some(delims) = substitution_heredoc_delims(command) else {
        return true;
    };
    delims.iter().any(|(delim, from)| {
        command[*from..]
            .split('\n')
            .any(|line| ends_a_substitution_heredoc(line.trim_start_matches('\t'), delim))
    })
}

/// `line` for the line-by-line reading: when bash could end a substitution
/// heredoc on it ([`ends_a_substitution_heredoc`]), the code after each
/// matching delimiter is appended as a command of its own — `EOFcd /p)` reads
/// as `EOFcd /p) ; cd /p)` — since the tokenizer would otherwise glue it to
/// the delimiter as one word.
fn split_early_heredoc_end<'l>(line: &'l str, delims: &[(String, usize)]) -> Cow<'l, str> {
    let bare = line.trim_start_matches('\t');
    let mut out = Cow::Borrowed(line);
    for (delim, _) in delims {
        if ends_a_substitution_heredoc(bare, delim) {
            let owned = out.to_mut();
            owned.push_str(" ; ");
            owned.push_str(&bare[delim.len()..]);
        }
    }
    out
}

/// Is `text` on the plain-shape allowlist? ([`plain_carve`] and
/// [`plain_segments_ok`] together.)
#[cfg(test)]
fn is_plain_shape(text: &str, cwd: &str, env: CdEnv<'_>) -> bool {
    plain_of(text, cwd, env).is_some()
}

/// The segment half of the plain-shape allowlist:
///
/// - segments are joined only by `&&`, `;`, a newline, or a `|` between two
///   commands that are not `cd`s — no `||`, no `&`;
/// - each segment is free of active expansion and grouping
///   ([`has_active_expansion_or_grouping`]) — checked again here on the
///   segments the core splitter produced after it stripped heredoc bodies and
///   comments, so a disagreement with [`plain_carve`]'s own reading of them can
///   only refuse;
/// - no head in [`NON_PLAIN_HEADS`], no `printf -v`, and no segment that only
///   assigns;
/// - every redirection is in [`PLAIN_REDIRECTS`], is a heredoc, or reads an
///   existing file.
///
/// Every `cd` must also resolve, which [`walk_plain`] checks as it goes.
fn plain_segments_ok(
    segments: &[(String, Option<&'static str>)],
    cwd: &str,
    env: CdEnv<'_>,
) -> bool {
    let is_cd: Vec<bool> = segments
        .iter()
        .map(|(raw, _)| cd_word(&tokenize_marked(raw)).is_some())
        .collect();
    for (i, (raw, op)) in segments.iter().enumerate() {
        if matches!(op, Some("||" | "&")) || has_active_expansion_or_grouping(raw) {
            return false;
        }
        let piped_out = *op == Some("|");
        let piped_in = i > 0 && segments[i - 1].1 == Some("|");
        if (piped_out && (is_cd[i] || is_cd.get(i + 1) == Some(&true))) || (piped_in && is_cd[i]) {
            return false;
        }
        let marked = tokenize_marked(raw);
        if !redirects_are_plain(&marked, cwd, env) {
            return false;
        }
        let words = command_tokens(&marked);
        if !carve_outs_are_messages(raw, &words) {
            return false;
        }
        if words.is_empty() {
            continue;
        }
        if !is_cd[i] && words.iter().all(|w| is_assignment_word(w)) {
            return false;
        }
        if is_cd[i] && cd_is_physical(&marked) {
            return false;
        }
        let (argv, chdirs) = peel_with_chdirs(&words);
        // `env -C <dir>` moves only the command it runs, and an `env` whose
        // options cannot be read may run anything anywhere: the union path
        // judges both (cadence-hooks#1100).
        if !chdirs.is_empty() || is_unreadable_runner(argv) {
            return false;
        }
        let Some(head) = argv.first().map(|h| unescape_word(h)) else {
            continue;
        };
        // A builtin `cd` the cd-word finder did not see (`command -- cd …`)
        // cannot be followed.
        if (!is_cd[i] && runs_builtin_cd(&words))
            || NON_PLAIN_HEADS.contains(&head.as_ref())
            || (head == "printf" && argv.iter().any(|w| w == "-v"))
        {
            return false;
        }
    }
    true
}

/// `words` past transparent prefixes and every `command [flags…]` or
/// `builtin [--]` — the same peel [`cd_word`] applies, so a head behind them
/// (`command -p eval …`, `builtin -- source …`) is checked as the head it is.
fn peel_command_prefixes(words: &[String]) -> &[String] {
    peel_with_chdirs(words).0
}

/// [`peel_command_prefixes`], plus the `-C`/`--chdir` values of every `env`
/// peeled on the way, in order. An `env` with options is peeled too
/// ([`parse_env_flags`]): `env -i git commit` and `env -C <dir> git commit`
/// hid the commit behind a head of `env` (cadence-hooks#1100). One whose
/// options cannot be read stays the head ([`is_env_with_options`]).
fn peel_with_chdirs(words: &[String]) -> (&[String], Vec<String>) {
    peel_heads(words, true)
}

/// The peel behind [`peel_with_chdirs`]. With `runners`, a modelled command
/// runner (`sudo`, `nice`, `timeout`, `stdbuf`, `xargs`) is peeled through
/// its own options by core's [`skip_runner_flags`], the walk
/// [`peel_command_runners`](cadence_hooks_core::shell::peel_command_runners)
/// uses, so `nice -n 5 git commit` resolves to the commit it runs
/// (cadence-hooks#1111). One whose options cannot be read stays the head
/// ([`is_unreadable_runner`]). Without `runners` only the transparent
/// prefixes, `command`, `builtin` and `env` are peeled — the dismiss
/// recognizer's narrower view, so a runner never widens that escape hatch.
fn peel_heads(words: &[String], runners: bool) -> (&[String], Vec<String>) {
    let mut argv = skip_transparent_prefixes(words);
    let mut chdirs = Vec::new();
    loop {
        let Some(head) = argv.first() else {
            return (argv, chdirs);
        };
        match unescape_word(head).as_ref() {
            "command" => {
                let Some(rest) = command_runs(&argv[1..]) else {
                    return (argv, chdirs);
                };
                argv = rest;
            }
            "builtin" => {
                argv = &argv[1..];
                if argv.first().is_some_and(|w| w == "--") {
                    argv = &argv[1..];
                }
            }
            _ if is_env_with_options(argv) => {
                let Some(flags) = parse_env_flags(&argv[1..]) else {
                    return (argv, chdirs);
                };
                argv = &argv[1 + flags.consumed..];
                chdirs.extend(flags.chdirs);
            }
            word if runners && RUNNERS.contains(&command_word(word).as_ref()) => {
                let runner = command_word(word).into_owned();
                let Some(rest) = skip_runner_flags(&runner, &argv[1..]) else {
                    return (argv, chdirs);
                };
                argv = rest;
            }
            _ => return (argv, chdirs),
        }
        argv = skip_transparent_prefixes(argv);
    }
}

/// The command runners [`peel_heads`] walks with core's grammar: core's
/// `COMMAND_RUNNERS` without `env`, whose options this module parses itself
/// ([`parse_env_flags`]) to collect its `-C` directories and unsets.
const RUNNERS: &[&str] = &["sudo", "xargs", "nice", "stdbuf", "timeout"];

/// A command runner left at the head after [`peel_with_chdirs`] with words
/// behind it: its options could not be read (`sudo -D <dir>`, `timeout
/// --weird`), so the command behind it, and where it runs, are unknown
/// (cadence-hooks#1111). An `env` whose options cannot be read is the same
/// case ([`is_env_with_options`]).
fn is_unreadable_runner(argv: &[String]) -> bool {
    is_env_with_options(argv)
        || (argv.len() > 1
            && argv
                .first()
                .is_some_and(|w| RUNNERS.contains(&command_word(w).as_ref())))
}

/// The words after `command`'s own flags when `command` runs its argument
/// (`-p`, `--`), or `None` for a query (`-v`, `-V`), which runs nothing.
fn command_runs(after: &[String]) -> Option<&[String]> {
    let mut rest = after;
    while let Some(flag) = rest.first().map(|w| unescape_word(w)) {
        if !flag.starts_with('-') {
            break;
        }
        if flag != "--" && flag.contains(['v', 'V']) {
            return None;
        }
        rest = &rest[1..];
        if flag == "--" {
            break;
        }
    }
    Some(rest)
}

/// Does this segment run the `cd` BUILTIN — past assignment words and any
/// `command [flags…]` / `builtin [--]`? `env cd`, `exec cd` and `nohup cd` run
/// an external `cd`, which cannot move the shell.
fn runs_builtin_cd(words: &[String]) -> bool {
    let mut rest = words;
    while rest.first().is_some_and(|w| is_assignment_word(w)) {
        rest = &rest[1..];
    }
    loop {
        let Some(head) = rest.first() else {
            return false;
        };
        match unescape_word(head).as_ref() {
            "command" => match command_runs(&rest[1..]) {
                Some(after) => rest = after,
                None => return false,
            },
            "builtin" => {
                rest = &rest[1..];
                if rest.first().is_some_and(|w| w == "--") {
                    rest = &rest[1..];
                }
            }
            word => return word == "cd",
        }
    }
}

/// Does the `cd` in `marked` carry `-P`? A physical cd resolves `..` through a
/// symlink's target, which a lexical walk cannot.
fn cd_is_physical(marked: &[MarkedToken]) -> bool {
    let Some(cd) = cd_word(marked) else {
        return false;
    };
    marked[cd.index + 1..]
        .iter()
        .map(|t| t.text.as_str())
        .take_while(|t| t.starts_with('-') && *t != "-" && *t != "--")
        .any(|t| t.contains('P'))
}

/// The placeholder [`plain_carve`] puts where a carved-out message was. It
/// holds control characters, which the raw scan refuses in input, so it can
/// only ever be a carve-out.
const CARVED: &str = "\u{1}MSG\u{1}";

/// Is every carved-out message in this segment a message argument?
///
/// A carve-out is plain only as the value of `-m`/`--message`/`-F`/`--file`
/// (or their `=` and attached forms) on a `git commit`, `git tag` or
/// `git merge`, or of `--body`/`--title` (`-b`/`-t`) on `gh`. Anywhere else —
/// a `cd` target, the command word, a subcommand, a `-C` value, a
/// `GIT_DIR=` prefix, a redirection target — its text would decide where
/// the command runs, and the placeholder hides it (cadence-hooks#1058
/// review F1).
fn carve_outs_are_messages(raw: &str, words: &[String]) -> bool {
    let total = raw.matches(CARVED).count();
    if total == 0 {
        return true;
    }
    let argv = peel_command_prefixes(words);
    let Some(verb) = argv.first().map(|w| command_word(w)) else {
        return false;
    };
    let is_value_of = |j: usize, flags: &[&str]| {
        argv[j] == CARVED && j > 0 && flags.contains(&argv[j - 1].as_str())
    };
    let is_attached =
        |j: usize, flags: &[&str]| flags.iter().any(|f| argv[j] == format!("{f}{CARVED}"));
    let mut allowed = 0;
    match verb.as_ref() {
        "git" => {
            let mut idx = 1;
            while let Some(t) = argv.get(idx).map(|t| unescape_word(t)) {
                if !t.starts_with('-') {
                    break;
                }
                idx += if GIT_VALUE_GLOBALS.contains(&t.as_ref()) {
                    2
                } else {
                    1
                };
            }
            let sub = argv.get(idx).map(|t| unescape_word(t).into_owned());
            if matches!(sub.as_deref(), Some("commit" | "tag" | "merge")) {
                for j in idx + 1..argv.len() {
                    if is_value_of(j, &["-m", "--message", "-F", "--file"])
                        || is_attached(j, &["--message=", "--file=", "-m", "-F"])
                    {
                        allowed += 1;
                    }
                }
            }
        }
        "gh" => {
            for j in 1..argv.len() {
                if is_value_of(j, &["--body", "--title", "-b", "-t"])
                    || is_attached(j, &["--body=", "--title="])
                {
                    allowed += 1;
                }
            }
        }
        _ => {}
    }
    allowed == total
}

/// git's global options that take a SEPARATE value word.
const GIT_VALUE_GLOBALS: &[&str] = &[
    "-C",
    "-c",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
    "--work-tree",
    "--git-dir",
];

/// Does `text` carry an expansion or grouping the plain walk does not model?
/// Quote-aware: inside `'…'` nothing is active; inside `"…"` substitutions
/// and parameter expansions still are. An unterminated quote counts as yes.
fn has_active_expansion_or_grouping(text: &str) -> bool {
    let text = text.replace("${HOME}", "$HOME");
    let chars: Vec<char> = text.chars().collect();
    let mut single = false;
    let mut double = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if single {
            if c == '\'' {
                single = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\\' => {
                i += 2;
                continue;
            }
            '`' => return true,
            '$' if matches!(next, Some('(' | '[' | '{')) => return true,
            '$' if next == Some('\'') && !double => return true,
            '"' => double = !double,
            '\'' if !double => single = true,
            '(' | ')' | '{' | '}' if !double => return true,
            _ => {}
        }
        i += 1;
    }
    single || double
}

/// Is every redirection in `marked` plain (see [`PLAIN_REDIRECTS`])?
fn redirects_are_plain(marked: &[MarkedToken], cwd: &str, env: CdEnv<'_>) -> bool {
    let mut i = 0;
    while let Some(t) = marked.get(i) {
        if !is_unquoted_redirect(t) {
            i += 1;
            continue;
        }
        let bare = is_bare_redirect(&t.text);
        let target = if bare {
            marked.get(i + 1).map(|n| n.text.as_str())
        } else {
            None
        };
        i += if bare { 2 } else { 1 };
        let spelled = format!("{}{}", t.text, target.unwrap_or(""));
        if PLAIN_REDIRECTS.contains(&spelled.as_str()) {
            continue;
        }
        // A heredoc: [`plain_carve`] has already refused an unquoted-delimiter
        // body that expands anything.
        if spelled.starts_with("<<") && !spelled.starts_with("<<<") {
            continue;
        }
        if let Some(path) = spelled.strip_prefix('<')
            && !path.starts_with(['<', '&', '>'])
            && !path.is_empty()
            && !path.contains(['$', '`', '*', '?', '[', '{', '~'])
            && (env.file_exists)(&resolve_cd_target(path, cwd))
        {
            continue;
        }
        return false;
    }
    true
}

/// The raw half of the plain-shape allowlist: `command` with each live
/// `$(cat <<'DELIM' … DELIM)` commit-message substitution replaced by the
/// [`CARVED`] placeholder — plus the number of heredocs it read — or `None`
/// when the raw text is not plain. The rules below apply to text the shell
/// tokenizes; a carve-out's body and a heredoc body are inert data and are
/// only checked for what an unquoted delimiter would expand
/// (cadence-hooks#1058 review F3).
///
/// One left-to-right scan that tracks what bash tracks — single and double
/// quotes, backslash escapes, `#` comments, and heredoc bodies — so a
/// substitution is only recognized where bash would run it. A `$(` in live
/// context must be exactly a carve-out ([`heredoc_substitution_body`]), else
/// the command is not plain and the scan stops there. Text in single quotes,
/// in a comment or in a heredoc body is never matched as an opener: matching
/// the opener as bare text let a carve-out swallow commands bash runs
/// (cadence-hooks#1058 review). Also refused here:
///
/// - any control character other than newline and tab, and any Unicode
///   whitespace other than space and tab: bash splits words on space and tab
///   only, while the tokenizer splits on all Unicode whitespace, so a `\r`,
///   NBSP, VT or FF would be read as a boundary bash does not have;
/// - backticks, `$[`, `${…}` other than `${HOME}`, `$'…'`, and unquoted
///   grouping characters — the checks [`plain_segments_ok`] repeats per
///   segment;
/// - an unquoted-delimiter heredoc whose body expands a substitution or a
///   parameter.
///
/// Linear in the command: each carve-out is measured once and skipped, and
/// the first opener that is not one ends the scan.
fn plain_carve(command: &str) -> Option<(String, usize)> {
    plain_carve_bodies(command).map(|carve| (carve.text, carve.heredocs))
}

/// [`plain_carve`]'s reading, with where its heredoc bodies are.
struct Carve {
    text: String,
    heredocs: usize,
    /// The byte ranges, in the original command, of each carve-out's body.
    message_bodies: Vec<Range<usize>>,
    /// The same for each other heredoc whose delimiter word is plainly
    /// spelled ([`Heredoc::confident`]).
    heredoc_bodies: Vec<Range<usize>>,
}

/// [`plain_carve`], recording its body ranges ([`Carve`]).
fn plain_carve_bodies(command: &str) -> Option<Carve> {
    let bytes = command.as_bytes();
    let mut message_bodies = Vec::new();
    let mut heredoc_bodies = Vec::new();
    let mut out = String::with_capacity(command.len());
    let mut i = 0;
    let mut single = false;
    let mut double = false;
    // At the start of a word: where a `#` begins a comment.
    let mut word_start = true;
    // Heredocs whose bodies begin after the current line.
    let mut pending: Vec<Heredoc> = Vec::new();
    let mut heredocs = 0;
    while let Some(c) = command[i..].chars().next() {
        let width = c.len_utf8();
        if is_foreign_blank(c) {
            return None;
        }
        if single {
            out.push(c);
            if c == '\'' {
                single = false;
            }
            i += width;
            continue;
        }
        let next = bytes.get(i + 1).copied();
        match c {
            '\\' => {
                out.push(c);
                i += 1;
                if let Some(escaped) = command[i..].chars().next() {
                    if is_foreign_blank(escaped) {
                        return None;
                    }
                    out.push(escaped);
                    i += escaped.len_utf8();
                }
                word_start = false;
                continue;
            }
            '#' if !double && word_start => {
                // A comment runs to the end of the line and is inert.
                let end = command[i..].find('\n').map_or(command.len(), |n| i + n);
                if command[i..end].chars().any(is_foreign_blank) {
                    return None;
                }
                out.push_str(&command[i..end]);
                i = end;
                continue;
            }
            '$' if next == Some(b'(') => {
                const OPEN: &str = "$(cat <<";
                let (len, body) = command[i..]
                    .strip_prefix(OPEN)
                    .and_then(heredoc_substitution_body)?;
                let at = i + OPEN.len();
                message_bodies.push(at + body.start..at + body.end);
                out.push_str(CARVED);
                i += OPEN.len() + len;
                word_start = false;
                continue;
            }
            '$' if command[i..].starts_with("${HOME}") => {
                out.push_str("${HOME}");
                i += "${HOME}".len();
                word_start = false;
                continue;
            }
            '$' if matches!(next, Some(b'[' | b'{')) => return None,
            '$' if next == Some(b'\'') && !double => return None,
            '`' => return None,
            '(' | ')' | '{' | '}' if !double => return None,
            '"' => double = !double,
            '\'' if !double => single = true,
            '<' if !double && next == Some(b'<') && bytes.get(i + 2) != Some(&b'<') => {
                let (heredoc, consumed) = parse_heredoc_operator(&command[i..])?;
                out.push_str(&command[i..i + consumed]);
                pending.push(heredoc);
                heredocs += 1;
                i += consumed;
                word_start = false;
                continue;
            }
            '\n' if !double => {
                out.push('\n');
                i += 1;
                for heredoc in std::mem::take(&mut pending) {
                    let body_len = heredoc_body_len(&command[i..], &heredoc)?;
                    if heredoc.confident {
                        heredoc_bodies.push(i..i + body_len);
                    }
                    out.push_str(&command[i..i + body_len]);
                    i += body_len;
                }
                word_start = true;
                continue;
            }
            _ => {}
        }
        out.push(c);
        word_start = !double && matches!(c, ' ' | '\t' | ';' | '&' | '|');
        i += width;
    }
    (!single && !double).then_some(Carve {
        text: out,
        heredocs,
        message_bodies,
        heredoc_bodies,
    })
}

/// A character bash does not treat as the tokenizer does: a control character
/// other than newline and tab, or Unicode whitespace other than space and tab.
fn is_foreign_blank(c: char) -> bool {
    c != '\n' && c != '\t' && (c.is_control() || (c.is_whitespace() && c != ' '))
}

/// A heredoc waiting for its body: the delimiter, whether `<<-` strips leading
/// tabs, and whether the delimiter was quoted (a quoted one makes the body
/// inert).
struct Heredoc {
    delim: String,
    strip_tabs: bool,
    quoted: bool,
    /// The delimiter word is a plain name, bare or in one pair of quotes
    /// (`EOF`, `'EOF'`, `"EOF"`): no escape or inner quote can make bash read
    /// a different delimiter than this parse does (`<<"E\"F"` ends at `E"F`,
    /// cadence-hooks#1101).
    confident: bool,
}

/// Parse the heredoc operator at the start of `text` (`<<` or `<<-`, blanks,
/// then the delimiter word), returning it and the bytes consumed. `None` for
/// an empty or expanding delimiter.
fn parse_heredoc_operator(text: &str) -> Option<(Heredoc, usize)> {
    let mut at = 2;
    let strip_tabs = text[at..].starts_with('-');
    if strip_tabs {
        at += 1;
    }
    at += text[at..].len() - text[at..].trim_start_matches([' ', '\t']).len();
    let rest = &text[at..];
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '<' | '>' | '(' | ')'))
        .unwrap_or(rest.len());
    let word = &rest[..end];
    if word.contains(['$', '`']) {
        return None;
    }
    let quoted = word.contains(['\'', '"', '\\']);
    let inner = [('\'', '\''), ('"', '"')]
        .iter()
        .find_map(|(open, close)| word.strip_prefix(*open)?.strip_suffix(*close))
        .unwrap_or(word);
    let confident = !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    let delim: String = word
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    if delim.is_empty() {
        return None;
    }
    Some((
        Heredoc {
            delim,
            strip_tabs,
            quoted,
            confident,
        },
        at + end,
    ))
}

/// The byte length of a heredoc body starting at `text`, through its
/// delimiter line or to the end. `None` when an unquoted-delimiter body
/// expands a substitution or a parameter.
fn heredoc_body_len(text: &str, heredoc: &Heredoc) -> Option<usize> {
    let mut offset = 0;
    let mut joins = ContinuationJoin::default();
    for line in text.split_inclusive('\n') {
        offset += line.len();
        let bare = line.strip_suffix('\n').unwrap_or(line);
        let bare = if heredoc.strip_tabs {
            bare.trim_start_matches('\t')
        } else {
            bare
        };
        if bare == heredoc.delim {
            // A delimiter line that a continuation joins onto the line before
            // it is not a delimiter: bash reads `x\` ⏎ `EOF` as `xEOF` and the
            // body runs on (cameronsjo/cadence-hooks#1122).
            if !heredoc.quoted && joins.joins_text() {
                return None;
            }
            return Some(offset);
        }
        if !heredoc.quoted
            && (line.contains("$(")
                || line.contains('`')
                || line.contains("${")
                || joins.splits(bare, &heredoc.delim))
        {
            return None;
        }
    }
    Some(offset)
}

/// Backslash-newline joining in an unquoted-delimiter heredoc body. Bash
/// joins a line ending in an unescaped backslash onto the next BEFORE it
/// compares the line with the delimiter, so `EO\` then `F` ends the body at
/// `EOF` and runs the lines after it (cadence-hooks#1113 item 5).
#[derive(Default)]
struct ContinuationJoin {
    /// The logical line built so far from continued physical lines, while it
    /// is still no longer than the delimiter.
    pending: Option<String>,
    /// A continued logical line has already outgrown the delimiter.
    overlong: bool,
}

impl ContinuationJoin {
    /// A continuation from the previous physical line is still joining, so
    /// the next line is not a line of its own.
    fn joining(&self) -> bool {
        self.pending.is_some() || self.overlong
    }

    /// A continuation is joining TEXT onto the next line, so a next line that
    /// reads as the delimiter is not one to bash: `x\` ⏎ `EOF` is `xEOF`. A
    /// bare `\` ⏎ `EOF` joins nothing, and that line still ends the body.
    fn joins_text(&self) -> bool {
        self.overlong || self.pending.as_deref().is_some_and(|p| !p.is_empty())
    }

    /// Feed one physical body line: true when it completes a logical line
    /// that spans a continuation and equals `delim`.
    fn splits(&mut self, bare: &str, delim: &str) -> bool {
        let continued = ends_in_continuation(bare);
        let piece = if continued {
            &bare[..bare.len() - 1]
        } else {
            bare
        };
        let joining = self.joining();
        if !joining && !continued {
            return false;
        }
        if !self.overlong {
            let pending = self.pending.get_or_insert_with(String::new);
            pending.push_str(piece);
            if pending.len() > delim.len() {
                self.pending = None;
                self.overlong = true;
            }
        }
        if continued {
            return false;
        }
        let split = !self.overlong && self.pending.as_deref() == Some(delim);
        self.pending = None;
        self.overlong = false;
        split
    }
}

/// Does a backslash-newline in an unquoted heredoc body in `command` join two
/// lines into its delimiter ([`ContinuationJoin`])? Read quote-blind, line
/// by line, like [`interpreted_heredoc_bodies`].
fn continuation_splits_a_delimiter(command: &str) -> bool {
    if !command.contains("<<") || !command.contains("\\\n") {
        return false;
    }
    let lines: Vec<&str> = command.split('\n').collect();
    let mut i = 0;
    while let Some(line) = lines.get(i) {
        i += 1;
        let Some(heredocs) = heredocs_on_line(line) else {
            return true;
        };
        for (heredoc, _) in heredocs {
            let mut joins = ContinuationJoin::default();
            while let Some(next) = lines.get(i) {
                i += 1;
                let bare = if heredoc.strip_tabs {
                    next.trim_start_matches('\t')
                } else {
                    next
                };
                if bare == heredoc.delim {
                    // The reverse of a split delimiter: a continuation joins
                    // this delimiter line onto the one before (`x\` ⏎ `EOF`
                    // is `xEOF`), so bash's body runs on past where a line
                    // reading ends it (cameronsjo/cadence-hooks#1122).
                    if !heredoc.quoted && joins.joins_text() {
                        return true;
                    }
                    break;
                }
                if !heredoc.quoted && joins.splits(bare, &heredoc.delim) {
                    return true;
                }
            }
        }
    }
    false
}

/// Does `line` end in an unescaped backslash? In an unquoted-delimiter
/// heredoc body that joins the next line onto it before bash compares the
/// line with the delimiter, so `EO\` then `F` ends the body at `EOF` and runs
/// the lines after it (cadence-hooks#1113 item 5).
fn ends_in_continuation(line: &str) -> bool {
    (line.len() - line.trim_end_matches('\\').len()) % 2 == 1
}

/// For the text after `$(cat <<`, the length through the substitution's
/// closing `)` when it is exactly: an optional `-`, blanks, a quoted
/// delimiter `'DELIM'` or `"DELIM"` of word characters, the end of the line,
/// a body, a line that is exactly `DELIM` (after leading tabs, for `<<-`), and
/// then only blanks and the `)`.
///
/// A body line that starts with the delimiter and has a `)` anywhere after it
/// refuses ([`ends_a_substitution_heredoc`]): inside a command substitution
/// bash 5.2 also ends the heredoc there and runs the rest of the line as code,
/// so what this would read as body, bash runs (cadence-hooks#1058 review). A
/// line like `DELIMX` with no `)` is ordinary body text. The
/// delimiter line is matched exactly — a trailing `\r` is not trimmed, and is
/// refused anyway by [`plain_carve`].
#[cfg(test)]
fn heredoc_substitution_len(after_open: &str) -> Option<usize> {
    heredoc_substitution_body(after_open).map(|(len, _)| len)
}

/// [`heredoc_substitution_len`], with the byte range of the body in
/// `after_open`: from the line after the delimiter word through the closing
/// delimiter line.
fn heredoc_substitution_body(after_open: &str) -> Option<(usize, Range<usize>)> {
    let mut at = 0;
    let dash = after_open.starts_with('-');
    if dash {
        at += 1;
    }
    at += after_open[at..].len() - after_open[at..].trim_start_matches([' ', '\t']).len();
    let rest = &after_open[at..];
    let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let close = rest[1..].find(quote)? + 1;
    let delim = &rest[1..close];
    if delim.is_empty() || !delim.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let after_delim = &rest[close + 1..];
    let newline = after_delim.find('\n')?;
    if !after_delim[..newline].trim_matches([' ', '\t']).is_empty() {
        return None;
    }
    let body = &after_delim[newline + 1..];
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        let bare = if dash {
            bare.trim_start_matches('\t')
        } else {
            bare
        };
        offset += line.len();
        if bare == delim {
            let tail = &body[offset..];
            let blanks = tail.len() - tail.trim_start_matches([' ', '\t', '\n']).len();
            if !tail[blanks..].starts_with(')') {
                return None;
            }
            let body_start = at + close + 1 + newline + 1;
            return Some((
                body_start + offset + blanks + 1,
                body_start..body_start + offset,
            ));
        }
        if ends_a_substitution_heredoc(bare, delim) {
            return None;
        }
    }
    None
}

/// Could bash end a heredoc inside `$(…)` at this body line? Bash 5.2 ends it
/// at any line that STARTS WITH the delimiter and has a `)` anywhere after it
/// — `EOF)`, `EOF cd /p)`, `EOFecho x)` — and runs the rest of the line as
/// code. Deliberately wider than bash's exact rule: a false positive only
/// refuses a carve-out.
fn ends_a_substitution_heredoc(line: &str, delim: &str) -> bool {
    line.strip_prefix(delim)
        .is_some_and(|rest| rest.contains(')'))
}

/// The argv a plain segment's command runs, and its `GIT_WORK_TREE=` /
/// `GIT_DIR=` prefix values.
fn plain_command(words: &[String]) -> (&[String], Option<&str>, Option<&str>) {
    let (work_tree, git_dir) = git_env_overrides(words);
    (peel_command_prefixes(words), work_tree, git_dir)
}

/// The most directories the plain walk tracks at once; past it the command is
/// treated as not plain.
const MAX_CD_CANDIDATES: usize = 4;

/// One directory the shell may be in.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ShellDir {
    pwd: String,
    /// Where `cd -` goes from here (`None` before any `cd` in this walk).
    oldpwd: Option<String>,
}

impl ShellDir {
    fn at(pwd: &str) -> Self {
        ShellDir {
            pwd: pwd.to_string(),
            oldpwd: None,
        }
    }

    /// The shell after a `cd` from here into `pwd`.
    fn moved_to(&self, pwd: String) -> Self {
        ShellDir {
            pwd,
            oldpwd: Some(self.pwd.clone()),
        }
    }
}

/// The directories a plain walk may be in, and the fallbacks: where the shell
/// is if a `cd` earlier in the current `&&` chain failed or never ran. A
/// failed link skips the rest of an `&&` chain, so the fallbacks join the
/// candidates where the chain ends (`;` or a newline).
struct CdScope<'a> {
    dirs: Vec<ShellDir>,
    fallback: Vec<ShellDir>,
    env: CdEnv<'a>,
}

/// One segment of a plain command, as [`walk_plain`] hands it to a visitor.
struct PlainSeg<'s> {
    /// Every directory the shell may be in when the segment runs.
    dirs: &'s [ShellDir],
    segment: &'s str,
    /// The command's words: redirections dropped, `!`/`time` peeled.
    words: Vec<String>,
    next_op: Option<&'static str>,
    is_cd: bool,
}

impl<'a> CdScope<'a> {
    fn new(cwd: &str, env: CdEnv<'a>) -> Self {
        CdScope {
            dirs: vec![ShellDir::at(cwd)],
            fallback: Vec::new(),
            env,
        }
    }

    /// Replace the candidates with `ordered`, deduplicated by directory (two
    /// that disagree on `OLDPWD` merge with it unknown). `None` past
    /// [`MAX_CD_CANDIDATES`].
    fn put(&mut self, ordered: Vec<ShellDir>) -> Option<()> {
        let mut dirs: Vec<ShellDir> = Vec::new();
        for dir in ordered {
            if let Some(known) = dirs.iter_mut().find(|d| d.pwd == dir.pwd) {
                if known.oldpwd != dir.oldpwd {
                    known.oldpwd = None;
                }
                continue;
            }
            dirs.push(dir);
        }
        if dirs.len() > MAX_CD_CANDIDATES {
            return None;
        }
        self.dirs = dirs;
        Some(())
    }

    /// Merge the fallbacks into the candidates.
    fn settle(&mut self) -> Option<()> {
        let mut ordered = std::mem::take(&mut self.fallback);
        ordered.append(&mut self.dirs);
        self.put(ordered)
    }

    /// Apply the `cd` at `cd` in `tokens` to every candidate: it lands, or —
    /// when its target is not an existing directory — it may fail, and the
    /// pre-cd directory becomes a fallback. `after_and` marks a cd reached
    /// through `&&` behind another command, which runs only if that command
    /// succeeded, so its pre-cd directories become fallbacks too. `None` when
    /// a target cannot be read ([`cd_landing`]) or the fallbacks pass
    /// [`MAX_CD_CANDIDATES`]: the command is not plain.
    fn apply_cd(&mut self, tokens: &[MarkedToken], cd: CdWord, after_and: bool) -> Option<()> {
        let before = std::mem::take(&mut self.dirs);
        let mut moved = Vec::new();
        let mut failed = Vec::new();
        for here in &before {
            let (dir, exists) = cd_landing(cd_target(tokens, cd, here, self.env)?, self.env)?;
            if !exists {
                failed.push(here.clone());
            }
            moved.push(here.moved_to(dir));
        }
        if after_and {
            failed.extend(before);
        }
        self.put(moved)?;
        for dir in failed {
            if !self.fallback.contains(&dir) {
                self.fallback.push(dir);
            }
        }
        (self.fallback.len() <= MAX_CD_CANDIDATES).then_some(())
    }
}

/// Where a logical `cd` to the joined path `raw` lands: its lexical
/// normalization, and whether that is an existing directory. `None` when the
/// normalization is not a directory but `raw` is: bash's `cd` then falls back
/// to the PHYSICAL path, which follows a symlink before its `..` (`link/../x`
/// with `link -> /p/sub` lands in `/p/x`), and a lexical walk cannot say where
/// that is.
///
/// Storing the normalized path, never `raw`, also keeps a long run of
/// `cd sub && cd ..` from growing the path each walk stats (#1058 review).
fn cd_landing(raw: String, env: CdEnv<'_>) -> Option<(String, bool)> {
    let dir = lexical_normalize(&raw);
    let exists = (env.dir_exists)(&dir);
    // The lexical target is missing today, but a `..` through a symlink
    // already points elsewhere: if the command creates that directory first
    // (`mkdir -p link/../nd && cd link/../nd`), bash's physical fallback
    // lands there (cadence-hooks#1113 item 2).
    if !exists && dir != raw && ((env.dir_exists)(&raw) || dotdot_diverges(&raw, env)) {
        return None;
    }
    Some((dir, exists))
}

/// Walk a plain command's segments in order, calling `visit` for each BEFORE
/// its own `cd` (if it is one) takes effect. `None` when the command turns out
/// not to be plain after all: a `cd` it cannot read, a wrapper or
/// substitution that runs a child script (`sh -c '…'`), or more than
/// [`MAX_CD_CANDIDATES`] directories — the caller then takes the union path.
fn walk_plain(
    plain: &Plain,
    cwd: &str,
    env: CdEnv<'_>,
    mut visit: impl FnMut(PlainSeg<'_>),
) -> Option<()> {
    let mut scope = CdScope::new(cwd, env);
    let mut prev_op: Option<&str> = None;
    let mut prev_was_cd = false;
    for (raw, next_op) in &plain.segments {
        let next_op = *next_op;
        let segment = raw.trim();
        let marked = tokenize_marked(segment);
        let cd = cd_word(&marked);
        let words = command_tokens(&marked);
        if cd.is_none() && !child_scripts(skip_transparent_prefixes(&words), segment).is_empty() {
            return None;
        }
        visit(PlainSeg {
            dirs: &scope.dirs,
            segment,
            words,
            next_op,
            is_cd: cd.is_some(),
        });
        if let Some(cd) = cd {
            scope.apply_cd(&marked, cd, prev_op == Some("&&") && !prev_was_cd)?;
        }
        if !matches!(next_op, Some("&&" | "|")) {
            scope.settle()?;
        }
        prev_op = next_op;
        prev_was_cd = cd.is_some();
    }
    Some(())
}

// ---------------------------------------------------------------------------
// The union path.
// ---------------------------------------------------------------------------

/// The most directories the union path collects; past it a `cd` is reported
/// as unresolved.
const MAX_UNION_DIRS: usize = 16;

/// Command words that run their standard input, a file operand, or a `-c`
/// string as shell code: a heredoc fed to one is a script, not data.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "busybox", "source", ".",
    "eval",
];

/// The most interpreted heredoc bodies [`interpreted_heredoc_bodies`] returns.
const MAX_INTERPRETED_BODIES: usize = 16;

/// The bodies of the heredocs in `command` that a shell runs as code
/// (cadence-hooks#1113 item 1): `cat <<'EOF' | sh`, `bash <<'EOF'`,
/// `source /dev/stdin <<'EOF'`, `eval "$(cat <<'EOF' … )"`,
/// `bash -c "$(cat <<'EOF' … )"`. Each is walked as a child script by
/// [`union_scan_bodies`]. `None` past [`MAX_INTERPRETED_BODIES`] bodies or
/// [`MAX_HEREDOC_OPERATORS`] operators.
///
/// Read line by line with no quoting model, so a `<<` inside a quoted string
/// can be read as a heredoc too: that only ever turns data into code, which
/// can add a target and never drop one.
fn interpreted_heredoc_bodies(command: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    collect_interpreted_bodies(command, 0, &mut out)?;
    Some(out)
}

/// [`interpreted_heredoc_bodies`] into `out`, and the bodies inside each
/// body a shell runs, to [`MAX_WRAPPER_DEPTH`] levels (a body that is itself
/// `cat <<B | sh` is code again one level down).
fn collect_interpreted_bodies(command: &str, depth: usize, out: &mut Vec<String>) -> Option<()> {
    if !command.contains("<<") {
        return Some(());
    }
    let first = out.len();
    let lines: Vec<&str> = command.split('\n').collect();
    let mut i = 0;
    let mut operators = 0;
    while let Some(line) = lines.get(i) {
        i += 1;
        let heredocs = heredocs_on_line(line)?;
        operators += heredocs.len();
        if operators > MAX_HEREDOC_OPERATORS {
            return None;
        }
        for (heredoc, interpreted) in heredocs {
            let mut body = String::new();
            while let Some(next) = lines.get(i) {
                i += 1;
                let bare = if heredoc.strip_tabs {
                    next.trim_start_matches('\t')
                } else {
                    next
                };
                if bare == heredoc.delim {
                    break;
                }
                if interpreted {
                    body.push_str(next);
                    body.push('\n');
                }
            }
            if interpreted {
                if out.len() == MAX_INTERPRETED_BODIES {
                    return None;
                }
                out.push(body);
            }
        }
    }
    for k in first..out.len() {
        if !out[k].contains("<<") {
            continue;
        }
        if depth + 1 >= MAX_WRAPPER_DEPTH {
            // Deeper still: unreadable.
            return None;
        }
        let body = out[k].clone();
        collect_interpreted_bodies(&body, depth + 1, out)?;
    }
    Some(())
}

/// Every heredoc operator on `line`, in order, and whether a shell runs its
/// body ([`heredoc_is_interpreted`]).
fn heredocs_on_line(line: &str) -> Option<Vec<(Heredoc, bool)>> {
    let mut out = Vec::new();
    if !line.contains("<<") {
        return Some(out);
    }
    // Where every command boundary on the line is, found once: each
    // operator's reading then costs a binary search, not a rescan.
    let bounds: Vec<usize> = line
        .match_indices(HEREDOC_BOUNDARY)
        .map(|(at, _)| at)
        .collect();
    let bytes = line.as_bytes();
    let pipes: Vec<usize> = bounds
        .iter()
        .copied()
        .filter(|&b| {
            bytes[b] == b'|' && bytes.get(b + 1) != Some(&b'|') && (b == 0 || bytes[b - 1] != b'|')
        })
        .collect();
    let mut from = 0;
    while let Some(found) = line[from..].find("<<") {
        if out.len() == MAX_HEREDOC_OPERATORS {
            return None;
        }
        let at = from + found;
        from = at + 2;
        if line[at..].starts_with("<<<") {
            from = at + 3;
            continue;
        }
        if line[..at].ends_with('<') {
            continue;
        }
        let Some((heredoc, consumed)) = parse_heredoc_operator(&line[at..]) else {
            continue;
        };
        let interpreted = heredoc_is_interpreted(line, at, at + consumed, &bounds, &pipes);
        out.push((heredoc, interpreted));
        from = at + consumed;
    }
    Some(out)
}

/// The characters [`heredoc_is_interpreted`] reads as command boundaries.
const HEREDOC_BOUNDARY: &[char] = &['|', ';', '&', '(', ')', '`', '{', '}'];

/// Is the heredoc whose operator spans `start..end` of `line` run as code?
/// Yes when its own command, a command enclosing it through a `$(`, `<(`,
/// backtick or group, or a command it is piped into is one of
/// [`INTERPRETERS`]. Quote-blind, like its caller. `bounds` holds the byte
/// offset of every [`HEREDOC_BOUNDARY`] character on the line, in order, and
/// `pipes` those that are a pipe (`|` or `|&`, not `||`).
fn heredoc_is_interpreted(
    line: &str,
    start: usize,
    end: usize,
    bounds: &[usize],
    pipes: &[usize],
) -> bool {
    // Its own command, then each command enclosing it. A `;`, `&`, `|` or a
    // closing `)`/`}` before it ends the command it belongs to.
    let mut upto = start;
    for _ in 0..MAX_HEREDOC_NESTING {
        let k = bounds.partition_point(|&b| b < upto);
        let Some(&b) = k.checked_sub(1).and_then(|k| bounds.get(k)) else {
            if head_is_interpreter(&line[..upto]) {
                return true;
            }
            break;
        };
        if head_is_interpreter(&line[b + 1..upto]) {
            return true;
        }
        if !matches!(line.as_bytes()[b], b'(' | b'`' | b'{') {
            break;
        }
        upto = b;
    }
    // Every command a pipe later on its line feeds. Not only the heredoc's
    // own pipeline: a group or subshell around it (`{ cat <<EOF; } | sh`,
    // `(cat <<EOF) | sh`) pipes its output on, so every stage counts, which
    // can only read more bodies as code.
    let bytes = line.as_bytes();
    let first = pipes.partition_point(|&b| b < end);
    for (stage_no, &b) in pipes[first..].iter().enumerate() {
        if stage_no == MAX_HEREDOC_NESTING {
            // Too many to follow: read the body as code, which can only add
            // a target.
            return true;
        }
        // `|&` pipes stderr too.
        let from = if bytes.get(b + 1) == Some(&b'&') {
            b + 2
        } else {
            b + 1
        };
        let k = bounds.partition_point(|&x| x < from);
        let stop = bounds.get(k).copied().unwrap_or(line.len());
        let stage = &line[from..stop];
        // A pipe at the end of the line continues after the heredoc body,
        // on a line this reading does not follow.
        if stage.trim().is_empty() && stop == line.len() {
            return true;
        }
        if head_is_interpreter(stage) {
            return true;
        }
    }
    false
}

/// How many enclosing commands, or pipe stages, [`heredoc_is_interpreted`]
/// reads before it treats the body as code.
const MAX_HEREDOC_NESTING: usize = 16;

/// The most heredoc operators [`interpreted_heredoc_bodies`] reads; past it
/// the command's heredocs are unreadable.
const MAX_HEREDOC_OPERATORS: usize = 256;

/// Does this quote-blind command text run one of [`INTERPRETERS`], past
/// assignment words, transparent prefixes and command runners?
fn head_is_interpreter(text: &str) -> bool {
    const MAX_WORDS: usize = 64;
    // Only the front of the text can hold the command word; a longer run of
    // words the peel cannot pass is read as a shell.
    const MAX_BYTES: usize = 4096;
    let mut cut = text.len().min(MAX_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let words: Vec<String> = text[..cut]
        .split_whitespace()
        .map(|w| w.trim_start_matches(['"', '\'']))
        .filter(|w| !w.is_empty() && !w.starts_with(['<', '>']))
        .map(|w| {
            w.chars()
                .filter(|c| !matches!(c, '"' | '\''))
                .collect::<String>()
        })
        .skip_while(|w| is_assignment_word(w))
        .take(MAX_WORDS + 1)
        .collect();
    match peel_command_prefixes(&words).first() {
        // A command word an expansion or substitution decides (`| $SHELL`,
        // `| $(which sh)`) may be a shell.
        Some(w) if w.starts_with(['$', '`']) => true,
        Some(w) => INTERPRETERS.contains(&command_word(w).as_ref()),
        None => words.len() > MAX_WORDS || cut < text.len(),
    }
}

/// The union path's reading of the heredoc bodies a shell runs
/// ([`interpreted_heredoc_bodies`]): each is a child script, run from any
/// directory the command reaches, so its `cd`s join the command's and its
/// commits are judged from all of them.
fn union_scan_bodies(command: &str, bodies: &[String], cwd: &str, env: CdEnv<'_>) -> Scan {
    let env = union_env(command, env);
    let child = CdEnv { home: None, ..env };
    let mut dirs = vec![cwd.to_string()];
    let mut unresolved = None;
    union_dirs(command, 0, env, &mut dirs, &mut unresolved);
    for body in bodies {
        union_dirs(body, 1, child, &mut dirs, &mut unresolved);
    }
    let mut out = Scan {
        unresolved_cd: unresolved,
        union_cd_dirs: dirs[1..].to_vec(),
        ..Scan::default()
    };
    for body in bodies {
        let exports = git_exports(body);
        let env = CdEnv {
            exports: Some(&exports),
            ..child
        };
        union_commits(body, 1, &dirs, (None, None), env, &mut out);
    }
    out
}

/// `GIT_DIR`/`GIT_WORK_TREE` values a command hands to its later commands
/// through the environment rather than as a prefix (cadence-hooks#1113 item
/// 4): `export GIT_DIR=<p>/.git; git commit`, `GIT_DIR=<p>/.git; export
/// GIT_DIR; git commit`, `declare -x …`, or an assignment after `set -a`.
/// Read over the whole command, in no order, like the union path's `cd`s.
#[derive(Default, Debug)]
struct GitExports {
    work_trees: Vec<String>,
    git_dirs: Vec<String>,
    /// The first place a git variable gets a value the walk cannot see
    /// (`read GIT_DIR`, `printf -v GIT_DIR …`), or too many values.
    unreadable: Option<String>,
}

/// The most exported values [`git_exports`] keeps; past it the exports are
/// unreadable.
const MAX_GIT_EXPORTS: usize = 8;

/// Builtins whose operands are `NAME[=VALUE]` words.
const DECLARING_WORDS: &[&str] = &["export", "declare", "typeset", "local", "readonly"];

/// Collect [`GitExports`] from `command` and its child scripts.
fn git_exports(command: &str) -> GitExports {
    #[derive(Default)]
    struct Seen {
        assigned: Vec<(String, String)>,
        exported: Vec<(String, String)>,
        named: HashSet<String>,
        allexport: bool,
        unreadable: Option<String>,
    }
    fn is_git_var(name: &str) -> bool {
        matches!(name, "GIT_DIR" | "GIT_WORK_TREE")
    }
    fn walk(script: &str, depth: usize, seen: &mut Seen) {
        for (segment, marked) in union_segments(script) {
            let words = command_tokens(&marked);
            let heads = strip_compound_heads(&words);
            let argv = peel_command_prefixes(heads);
            let head = argv.first().map(|w| unescape_word(w).into_owned());
            if !heads.is_empty() && heads.iter().all(|w| is_assignment_word(w)) {
                for word in heads {
                    if let Some((name, value)) = word.split_once('=')
                        && is_git_var(name)
                    {
                        seen.assigned.push((name.to_string(), value.to_string()));
                    }
                }
            } else if let Some(head) = head.as_deref()
                && DECLARING_WORDS.contains(&head)
            {
                let flags: Vec<&String> = argv[1..]
                    .iter()
                    .take_while(|w| w.starts_with('-') && *w != "--")
                    .collect();
                let exporting = head == "export"
                    || (head != "readonly" && flags.iter().any(|f| f[1..].contains('x')));
                for word in &argv[1 + flags.len()..] {
                    let word = unescape_word(word);
                    let (name, value) = match word.split_once('=') {
                        Some((name, value)) => (name, Some(value)),
                        None => (word.as_ref(), None),
                    };
                    // A name built by an expansion (`export ${v}_DIR=…`)
                    // may be a git variable.
                    if name.contains(['$', '`', '{']) && seen.unreadable.is_none() {
                        seen.unreadable = Some(segment.clone());
                    }
                    if !is_git_var(name) {
                        continue;
                    }
                    match (value, exporting) {
                        (Some(v), true) => seen.exported.push((name.into(), v.into())),
                        (Some(v), false) => seen.assigned.push((name.into(), v.into())),
                        (None, true) => {
                            seen.named.insert(name.to_string());
                        }
                        (None, false) => {}
                    }
                }
            } else if head.as_deref() == Some("set") {
                seen.allexport |= argv[1..].iter().any(|w| {
                    (w.starts_with('-') && !w.starts_with("--") && w.contains('a'))
                        || w == "allexport"
                });
            } else if head.as_deref() != Some("unset")
                && argv.iter().skip(1).any(|w| {
                    let w = unescape_word(w);
                    is_git_var(w.split(['=', '[']).next().unwrap_or(""))
                })
                && seen.unreadable.is_none()
            {
                // `read GIT_DIR`, `printf -v GIT_DIR …`, `mapfile`, `let`,
                // `for GIT_DIR in …`: a value the walk cannot see.
                seen.unreadable = Some(segment.clone());
            }
            if depth < MAX_WRAPPER_DEPTH {
                for child in child_scripts(argv, &segment) {
                    walk(&child, depth + 1, seen);
                }
            }
        }
    }
    // Nothing to find unless a git variable's name is spelled, after quote
    // and escape removal (`export G\IT_DIR=…` exports `GIT_DIR`), or could
    // be built by an expansion.
    let bare: String = command
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    if !["GIT", "_DIR", "_TREE", "$", "`", "{"]
        .iter()
        .any(|needle| bare.contains(needle))
    {
        return GitExports::default();
    }
    let mut seen = Seen::default();
    walk(command, 0, &mut seen);
    let mut out = GitExports {
        unreadable: seen.unreadable,
        ..GitExports::default()
    };
    let assigned = seen
        .assigned
        .into_iter()
        .filter(|(name, _)| seen.allexport || seen.named.contains(name));
    for (name, value) in seen.exported.into_iter().chain(assigned) {
        let list = if name == "GIT_DIR" {
            &mut out.git_dirs
        } else {
            &mut out.work_trees
        };
        if !list.contains(&value) {
            list.push(value);
        }
    }
    if out.git_dirs.len() + out.work_trees.len() > MAX_GIT_EXPORTS {
        out.unreadable
            .get_or_insert_with(|| "… (too many exported git variables)".to_string());
    }
    out
}

/// The fail-closed scan for a command that is not plain.
///
/// Every commit, found anywhere (inside `if`/`for` bodies, subshells,
/// `sh -c` wrappers and substitutions), is judged from EVERY directory in the
/// union of the session cwd and each directory a `cd` or `pushd` anywhere in
/// the command names ([`union_dirs`]). Its `-C`, `--git-dir` and `--work-tree`
/// values resolve from each of those. [`run_enforce`] blocks if any target is
/// a primary checkout — and, when a `cd` could not be read, whenever the
/// session cwd is a linked worktree, since that cd may lead anywhere.
fn union_scan(command: &str, cwd: &str, env: CdEnv<'_>) -> Scan {
    let exports = git_exports(command);
    let env = CdEnv {
        exports: Some(&exports),
        ..union_env(command, env)
    };
    let mut dirs = vec![cwd.to_string()];
    let mut unresolved = None;
    union_dirs(command, 0, env, &mut dirs, &mut unresolved);
    let mut out = Scan {
        unresolved_cd: unresolved,
        union_cd_dirs: dirs[1..].to_vec(),
        ..Scan::default()
    };
    union_commits(command, 0, &dirs, (None, None), env, &mut out);
    if let Some(what) = &exports.unreadable
        && !out.commits.is_empty()
        && out.unreadable.is_none()
    {
        out.unreadable = Some(unreadable_commit_message(
            what,
            "sets GIT_DIR or GIT_WORK_TREE to a value the guard cannot read",
        ));
    }
    out
}

/// `env` for the union path: physical when any word of the command is `set`,
/// which may turn on `set -P` / `set -o physical` for every later `cd`.
fn union_env<'a>(command: &str, env: CdEnv<'a>) -> CdEnv<'a> {
    CdEnv {
        physical: env.physical || tokenize(command).iter().any(|t| unescape_word(t) == "set"),
        ..env
    }
}

/// The segments of `script` as the union path reads them: cut at every
/// operator, group punctuation stripped, tokenized.
fn union_segments(script: &str) -> Vec<(String, Vec<MarkedToken>)> {
    split_segments_with_ops(script)
        .into_iter()
        .map(|(raw, _)| {
            let segment = strip_group_punctuation(&raw).to_string();
            let marked = tokenize_marked(&segment);
            (segment, marked)
        })
        .collect()
}

/// Collect, lexically, every directory a `cd`/`pushd` in `script` (and its
/// child scripts) names, resolving a relative one from every directory known
/// so far. The first one it cannot read — or a `popd`, an `eval`/`source`/`.`,
/// or a set past [`MAX_UNION_DIRS`] — goes to `unresolved`.
fn union_dirs(
    script: &str,
    depth: usize,
    env: CdEnv<'_>,
    dirs: &mut Vec<String>,
    unresolved: &mut Option<String>,
) {
    let note = |what: String, unresolved: &mut Option<String>| {
        if unresolved.is_none() {
            *unresolved = Some(what);
        }
    };
    for (segment, marked) in union_segments(script) {
        let words = command_tokens(&marked);
        let (argv, chdirs) = peel_with_chdirs(strip_compound_heads(&words));
        if let Some(head) = argv.first()
            && matches!(unescape_word(head).as_ref(), "eval" | "source" | ".")
        {
            note(head.clone(), unresolved);
        }
        // `env -C <dir>` runs its command in `<dir>` (cadence-hooks#1100):
        // collect it as a `cd` names a directory, from every one known.
        if chdirs.len() > MAX_UNION_DIRS {
            // Each hop joins onto the last, so a long chain is quadratic.
            note("… (too many `env -C` directories)".to_string(), unresolved);
        } else if !chdirs.is_empty() && unresolved.is_none() {
            for base in dirs.clone() {
                let landed = chdirs.iter().try_fold(base, |here, value| {
                    chdir_landing(value, &here, env).map(|d| lexical_normalize(&d))
                });
                match landed {
                    Some(dir) if dirs.len() < MAX_UNION_DIRS => {
                        let dir = normalize_target(&dir);
                        if !dirs.contains(&dir) {
                            dirs.push(dir);
                        }
                    }
                    Some(_) => {
                        note("… (too many directories)".to_string(), unresolved);
                        break;
                    }
                    None => {
                        note(format!("(env -C) {}", chdirs.join(" ")), unresolved);
                        break;
                    }
                }
            }
        }
        for (i, t) in marked.iter().enumerate() {
            let word = unescape_word(&t.text);
            let word = word.rsplit(['(', '`']).next().unwrap_or("");
            match word {
                "cd" | "pushd" => {
                    let rebinds = marked[..i].iter().any(|t| {
                        t.text
                            .split_once('=')
                            .is_some_and(|(name, _)| CD_READS.contains(&name))
                            && is_assignment_word(&t.text)
                    });
                    let cd = CdWord { index: i, rebinds };
                    // A physical cd resolves `..` through a symlink's target,
                    // which a lexical join cannot follow.
                    let after = &marked[i + 1..];
                    let physical = env.physical
                        || after
                            .iter()
                            .map(|t| t.text.as_str())
                            .take_while(|t| t.starts_with('-') && *t != "-" && *t != "--")
                            .any(|t| t.contains('P'));
                    if physical && after.iter().any(|t| t.text.split('/').any(|c| c == "..")) {
                        let rest: Vec<&str> = after.iter().map(|t| t.text.as_str()).collect();
                        note(rest.join(" "), unresolved);
                        continue;
                    }
                    let known = dirs.clone();
                    for base in &known {
                        let target = cd_target(&marked, cd, &ShellDir::at(base), env);
                        // Only the first unresolved cd is reported, so once
                        // one is, skip the stats that could only find another.
                        let target = match target {
                            Some(raw) if unresolved.is_none() => {
                                cd_landing(raw.clone(), env).map(|_| raw)
                            }
                            other => other,
                        };
                        match target {
                            Some(dir) if dirs.len() < MAX_UNION_DIRS => {
                                let dir = normalize_target(&dir);
                                if !dirs.contains(&dir) {
                                    dirs.push(dir);
                                }
                            }
                            Some(_) => {
                                note("… (too many directories)".to_string(), unresolved);
                                break;
                            }
                            None => {
                                let rest: Vec<&str> =
                                    marked[i + 1..].iter().map(|t| t.text.as_str()).collect();
                                note(rest.join(" "), unresolved);
                                break;
                            }
                        }
                    }
                }
                "popd" => note("popd".to_string(), unresolved),
                _ => {}
            }
        }
        if depth < MAX_WRAPPER_DEPTH {
            for child in child_scripts(argv, &segment) {
                union_dirs(
                    &child,
                    depth + 1,
                    CdEnv { home: None, ..env },
                    dirs,
                    unresolved,
                );
            }
        }
    }
}

/// Every commit in `script` (and its child scripts), judged from each of
/// `dirs`. `inherited_env` carries a `GIT_WORK_TREE=`/`GIT_DIR=` prefix into a
/// wrapper's child, as the shell exports it (#378).
///
/// A commit in a `trap` action is judged from every directory and reported
/// as unreadable: the action runs when the signal fires, in whatever
/// directory the shell has reached by then, so a `cd` inside it resolves from
/// a directory this walk has not collected yet (`trap 'cd <p> && git commit'
/// EXIT; cd ..` from a worktree beside `<p>`) — the same refusal core's push
/// walk makes (cadence-hooks#1091). So is a commit behind an `env` whose
/// options cannot be read.
fn union_commits(
    script: &str,
    depth: usize,
    dirs: &[String],
    inherited_env: (Option<&str>, Option<&str>),
    env: CdEnv<'_>,
    out: &mut Scan,
) {
    for (segment, marked) in union_segments(script) {
        let words = command_tokens(&marked);
        let heads = strip_compound_heads(&words);
        let argv = peel_command_prefixes(heads);
        let (work_tree, git_dir) = git_env_overrides(heads);
        let work_tree = work_tree.or(inherited_env.0);
        let git_dir = git_dir.or(inherited_env.1);
        if depth < MAX_WRAPPER_DEPTH {
            let deferred = installs_trap_action(&words);
            let child_env = CdEnv { home: None, ..env };
            for child in child_scripts(argv, &segment) {
                if !deferred {
                    union_commits(
                        &child,
                        depth + 1,
                        dirs,
                        (work_tree, git_dir),
                        child_env,
                        out,
                    );
                    continue;
                }
                let mut trapped = Scan::default();
                union_commits(
                    &child,
                    depth + 1,
                    dirs,
                    (work_tree, git_dir),
                    child_env,
                    &mut trapped,
                );
                if !trapped.commits.is_empty() && out.unreadable.is_none() {
                    out.unreadable = Some(unreadable_commit_message(
                        &segment,
                        "commits in a `trap` action, which runs in whatever directory the \
                         shell has reached when the signal fires",
                    ));
                    out.commits.extend(dirs.iter().map(|d| normalize_target(d)));
                }
                merge_scan(out, trapped);
            }
        }
        if cd_word(&marked).is_some() {
            continue;
        }
        if is_unreadable_runner(argv)
            && argv.iter().any(|w| w.contains("commit"))
            && out.unreadable.is_none()
        {
            out.unreadable = Some(unreadable_commit_message(
                &segment,
                "may run a git commit behind command-runner options the guard cannot read",
            ));
            out.commits.extend(dirs.iter().map(|d| normalize_target(d)));
        }
        let mut found = false;
        for dir in dirs {
            detect_mutations(argv, &segment, dir, &mut out.mutations);
            let targets =
                commit_targets_of(argv, dir, work_tree, git_dir, env, &mut out.unreadable);
            found |= !targets.is_empty();
            out.commits.extend(targets);
            // An exported `GIT_DIR`/`GIT_WORK_TREE` reaches every commit that
            // does not set its own (cadence-hooks#1113 item 4).
            let exports = env.exports.filter(|_| found);
            for value in exports.map_or(&[][..], |e| &e.work_trees[..]) {
                if work_tree.is_none() {
                    out.commits.extend(commit_targets_of(
                        argv,
                        dir,
                        Some(value),
                        git_dir,
                        env,
                        &mut out.unreadable,
                    ));
                }
            }
            for value in exports.map_or(&[][..], |e| &e.git_dirs[..]) {
                if git_dir.is_none() {
                    out.commits.extend(commit_targets_of(
                        argv,
                        dir,
                        work_tree,
                        Some(value),
                        env,
                        &mut out.unreadable,
                    ));
                }
            }
        }
        // A commit whose command word, subcommand or target comes from a
        // substitution cannot be placed: judge it from every directory and
        // report it, which blocks it from a worktree too (#1058 review F1).
        if substituted_commit(argv, heads, found) {
            if out.unresolved_commit.is_none() {
                out.unresolved_commit = Some(segment.clone());
            }
            out.commits.extend(dirs.iter().map(|d| normalize_target(d)));
        }
    }
}

/// Does a word come out of a command substitution (`$(…)`, a backtick, or a
/// carved-out message placeholder)?
fn is_substituted(word: &str) -> bool {
    word.contains("$(") || word.contains('`') || word.contains(CARVED)
}

/// Could this segment be a `git commit` whose shape a substitution decides —
/// a substituted command word followed by `commit`, a substituted git
/// subcommand, or a commit (`found`) whose global option or `GIT_DIR=` /
/// `GIT_WORK_TREE=` prefix is substituted?
fn substituted_commit(argv: &[String], heads: &[String], found: bool) -> bool {
    let Some(verb) = argv.first() else {
        return false;
    };
    if is_substituted(verb) {
        return argv[1..].iter().any(|w| unescape_word(w) == "commit");
    }
    if command_word(verb) != "git" {
        return false;
    }
    let mut idx = 1;
    let mut global_substituted = false;
    while let Some(t) = argv.get(idx) {
        let flag = unescape_word(t);
        if !flag.starts_with('-') {
            break;
        }
        global_substituted |= is_substituted(t);
        if GIT_VALUE_GLOBALS.contains(&flag.as_ref()) {
            global_substituted |= argv.get(idx + 1).is_some_and(|v| is_substituted(v));
            idx += 2;
        } else {
            idx += 1;
        }
    }
    if argv.get(idx).is_some_and(|sub| is_substituted(sub)) {
        return true;
    }
    let env_substituted = heads.iter().take_while(|w| is_assignment_word(w)).any(|w| {
        (w.starts_with("GIT_DIR=") || w.starts_with("GIT_WORK_TREE=")) && is_substituted(w)
    });
    found && (global_substituted || env_substituted)
}

/// Core's `strip_group_wrappers`, except that a leading `{` is group syntax only
/// when a blank follows it: `{fd}>/dev/null git commit` starts with a
/// named-descriptor redirection, and stripping its `{` left `fd}>/dev/null` as
/// the command word, which hid the commit.
fn strip_group_punctuation(raw: &str) -> &str {
    let mut rest = raw.trim();
    loop {
        let trimmed = rest.trim_start_matches(['(', ' ', '\t']);
        let trimmed = match trimmed.strip_prefix('{') {
            Some(after) if after.starts_with([' ', '\t']) || after.is_empty() => after,
            _ => trimmed,
        };
        if trimmed.len() == rest.len() {
            break;
        }
        rest = trimmed;
    }
    rest.trim_end_matches([')', '}', ';', ' ', '\t'])
}

/// Variables whose value a `cd` reads: an assignment to one in front of the
/// cd (`CDPATH=/x cd sub`) changes where it lands, so such a cd is left
/// unresolved.
const CD_READS: &[&str] = &["CDPATH", "HOME", "OLDPWD", "PWD"];

/// Where the `cd` word sits in a segment, and whether a prefix assignment
/// rebinds a variable the cd reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CdWord {
    index: usize,
    rebinds: bool,
}

/// Find the `cd` a segment runs in the CURRENT shell, or `None`.
///
/// bash and zsh change the shell's directory for `cd` behind any of:
///
/// - the reserved words `!` and `time` (with `time -p`), written plainly —
///   `\time` is the external binary, which runs an external `cd`;
/// - assignment words (`FOO=1 cd /x`), with the `NAME=` part unquoted — a
///   quoted `"FOO=1"` is a command name and the cd never runs;
/// - redirections (`>/dev/null cd /x`);
/// - `builtin`, `command` and `command -p`, escaped or not.
///
/// `env cd`, `exec cd`, `nohup cd` and `sudo cd` are NOT a cd: each runs an
/// external `cd` binary in a child process, which cannot move this shell
/// (cadence-hooks#1057). Matching `cd` itself goes through quote and escape
/// removal, as the shell does, so `\cd` and `"cd"` are the builtin.
fn cd_word(tokens: &[MarkedToken]) -> Option<CdWord> {
    let fully_unquoted = |t: &MarkedToken| t.unquoted_prefix_len == t.text.len();
    let mut i = 0;
    while let Some(t) = tokens.get(i).filter(|t| fully_unquoted(t)) {
        match t.text.as_str() {
            "!" => i += 1,
            "time" => {
                i += 1;
                if tokens.get(i).is_some_and(|t| t.text == "-p") {
                    i += 1;
                }
            }
            _ => break,
        }
    }
    let mut rebinds = false;
    while let Some(t) = tokens.get(i) {
        if is_unquoted_redirect(t) {
            i += if is_bare_redirect(&t.text) { 2 } else { 1 };
        } else if let Some((name, _)) = t.text.split_once('=')
            && is_assignment_word(&t.text)
            && t.unquoted_prefix_len > name.len()
        {
            rebinds |= CD_READS.contains(&name);
            i += 1;
        } else {
            break;
        }
    }
    while let Some(t) = tokens.get(i) {
        match unescape_word(&t.text).as_ref() {
            "builtin" => i += 1,
            "command" => {
                i += 1;
                if tokens.get(i).is_some_and(|t| t.text == "-p") {
                    i += 1;
                }
            }
            _ => break,
        }
    }
    (unescape_word(&tokens.get(i)?.text) == "cd").then_some(CdWord { index: i, rebinds })
}

/// A redirection whose operator is unquoted — `'>x'` is a literal argument.
///
/// Unquoted through the whole OPERATOR — the descriptor and the `<`/`>` —
/// not just its first byte: `2'>'x` is a file name (review I-c).
fn is_unquoted_redirect(t: &MarkedToken) -> bool {
    redirect_operator_span(&t.text).is_some_and(|(len, _)| t.unquoted_prefix_len >= len)
}

/// A redirection operator with no target attached (`>`, `2>`, `&>`, `<&`):
/// its target is the next token.
fn is_bare_redirect(text: &str) -> bool {
    text.ends_with(['>', '<', '&']) && !text.ends_with(">&-") && !text.ends_with("<&-")
}

/// The lexical directory the `cd` at `cd` names from `here`, or `None` when it
/// cannot be read.
///
/// Unreadable: no target (bare `cd`, which goes to HOME), more than one (bash
/// fails with "too many arguments"; zsh substitutes in `$PWD`), an option
/// other than `-L`/`-P`/`-e`/`-@`/`--`; a cd behind an assignment to a
/// variable it reads ([`CD_READS`]); `cd -` with no earlier cd in this walk (the
/// shell's `$OLDPWD` is unknown); any shell variable other than a leading
/// `$HOME`/`${HOME}`, and a `$HOME` target when `dollar_home` is `None` (see
/// [`dollar_home`]); a command substitution, a glob, a brace or a paren; a
/// `~user`/`~+`/`~-` tilde form, and a quoted `"~/…"`.
///
/// A leading `$HOME` / `${HOME}` expands against `dollar_home` — only when
/// bash would expand it (`'$HOME/x'` is a literal directory, and
/// [`expand_leading_home`] declines it). Before this, a
/// `cd "$HOME/…/worktree" && git commit` from another repo's primary was judged
/// against that primary and blocked, while the same target spelled `~/…`
/// passed (cadence-hooks#1018). An unquoted `~` / `~/…` keeps its long-standing
/// resolution against the process home, unconditionally.
fn cd_target(
    tokens: &[MarkedToken],
    cd: CdWord,
    here: &ShellDir,
    env: CdEnv<'_>,
) -> Option<String> {
    if cd.rebinds {
        return None;
    }
    // The operands the cd builtin sees: redirections are the shell's, not
    // cd's, so `cd /x 2>/dev/null` still has one operand.
    let mut operands: Vec<&MarkedToken> = Vec::new();
    let mut i = cd.index + 1;
    while let Some(t) = tokens.get(i) {
        if is_unquoted_redirect(t) {
            i += if is_bare_redirect(&t.text) { 2 } else { 1 };
            continue;
        }
        operands.push(t);
        i += 1;
    }
    let mut rest = operands.as_slice();
    while let Some((first, tail)) = rest.split_first() {
        let text = first.text.as_str();
        if text == "--" {
            rest = tail;
            break;
        }
        if text.len() > 1
            && text
                .strip_prefix('-')
                .is_some_and(|flags| flags.chars().all(|c| matches!(c, 'L' | 'P' | 'e' | '@')))
        {
            rest = tail;
            continue;
        }
        break;
    }
    let [target] = rest else {
        return None;
    };
    let text = target.text.as_str();
    let landed = if text == "-" {
        // `cd -` is `cd "$OLDPWD"`: a relative value is relative to here.
        resolve_cd_target(here.oldpwd.as_deref()?, &here.pwd)
    } else {
        let (literal, spelled) = if text.starts_with('$') {
            let expanded = expand_leading_home(target, env.home?)?;
            let after_home = text
                .strip_prefix("${HOME}")
                .or_else(|| text.strip_prefix("$HOME"))
                .unwrap_or(text);
            (after_home, expanded)
        } else {
            (text, text.to_string())
        };
        if literal.contains(['$', '`', '*', '?', '[', '{', '(', ')']) || literal.contains(CARVED) {
            return None;
        }
        if let Some(after_tilde) = text.strip_prefix('~') {
            // A `~` after the command may have rebound HOME lands wherever
            // HOME then points (cadence-hooks#1113 item 3).
            if !env.tilde {
                return None;
            }
            // Only `~` and `~/…`, with the tilde (and its slash) unquoted, mean
            // "HOME" to bash. `~user` names another account's home, which the
            // plain HOME substitution in `resolve_cd_target` would mangle into
            // `<home>user/…`: a path that names no repo and fails open.
            let unquoted_tilde = if after_tilde.is_empty() {
                target.unquoted_prefix_len >= 1
            } else {
                after_tilde.starts_with('/') && target.unquoted_prefix_len >= 2
            };
            if !unquoted_tilde {
                return None;
            }
        }
        resolve_cd_target(&spelled, &here.pwd)
    };
    Some(landed)
}

/// Builtins that assign a variable by a NAME operand, or evaluate one
/// arithmetically (`test -v 'a[HOME=7]'`, `(( … ))`): with an expansion in the
/// command, the name they assign can be built from parts that never spell
/// `HOME` (`export ${v}ME=/p`). `eval`, `source` and `.` are absent because
/// the union path already treats any `cd` in such a command as unreadable.
const NAME_ASSIGNING_WORDS: &[&str] = &[
    "declare",
    "typeset",
    "local",
    "export",
    "readonly",
    "read",
    "printf",
    "mapfile",
    "readarray",
    "let",
    "getopts",
    "unset",
    "test",
    "[",
    "[[",
];

/// Can a `~` in `command` be read as the process home? False when the command
/// may rebind HOME before the `~` expands (cadence-hooks#1113 item 3):
/// `HOME=<p>; git -C ~ commit` and `export HOME=<p>; cd ~ && git commit`
/// commit in `<p>`. Deliberately wider than [`dollar_home`]'s allowlist, which
/// would make every `~` in an ordinary command unreadable: a rebinding must
/// either spell `HOME` (after quote and escape removal, and not as a `$HOME`
/// read) or build a name through an expansion handed to a
/// [`NAME_ASSIGNING_WORDS`] builtin, and both refuse here.
fn tilde_is_home(command: &str) -> bool {
    let bare: String = command
        .replace("${HOME}", "")
        .replace("$HOME", "")
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    if bare.contains("HOME") {
        return false;
    }
    let expands = bare.contains(['$', '`', '{']);
    !(expands
        && (bare.contains("((")
            || bare
                .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
                .any(|w| NAME_ASSIGNING_WORDS.contains(&w))))
}

/// Command words that cannot rebind HOME in the shell running the command —
/// the allowlist behind [`dollar_home`]. Kept deliberately small: every entry
/// is a builtin or external command that takes no variable NAME as an operand
/// and evaluates no argument arithmetically.
///
/// - `cd`, `pwd`: take a path and `-L`/`-P`/`-e`/`-@` flags only (a `CDPATH`
///   lookup changes where cd lands, never HOME).
/// - `echo`, `true`: print or ignore their arguments.
/// - `git`, `ls`: external processes, which cannot write the parent shell's
///   variables (`git -c alias.x='!…'` runs in git's own child).
///
/// `test` and `[` are deliberately ABSENT: `test -v 'a[HOME=7]'` makes bash
/// evaluate the array subscript arithmetically, which assigns HOME in the
/// running shell (gate-2 delta review).
const HOME_SAFE_WORDS: &[&str] = &["cd", "git", "ls", "echo", "pwd", "true"];

/// The home a `$HOME` cd target in this top-level `command` expands against,
/// or `None` when the guard cannot show the command leaves HOME alone.
///
/// Bash expands `$HOME` against whatever HOME holds when the cd runs, and a
/// command can rebind it first in more ways than any denylist enumerates —
/// brace expansion (`export {HO,}ME=…`), a function body, `read`/`mapfile`,
/// arithmetic, `eval`, a child shell that starts with no HOME at all (`env -i
/// bash -c …`). Judging `<process home>/…` for such a command would let it
/// steer the guard onto a directory it never enters. So this is an ALLOWLIST:
/// the process home is used only when
///
/// - every top-level segment (heredoc bodies aside) starts with a
///   [`HOME_SAFE_WORDS`] command word — so no assignment word, `export`,
///   `read`, `eval`, `source`, wrapper shell, or function call;
/// - nothing outside quotes is a `(`, `)`, `{`, or `}` — no subshell,
///   function definition, brace expansion, or arithmetic command;
/// - nowhere, quoted or not and heredoc bodies included, is there a `$(`, a
///   backtick, a `$[`, a `${` other than a plain `${HOME}`, or a `$'…'`
///   string — each expands (or, for `$'…'`, quotes) in ways this scan does not
///   model.
///
/// Anything else leaves every `$HOME` target unresolved: the pre-cd directory
/// is kept, which is the behavior before `$HOME` expansion existed. Child
/// scripts never get a home at all — [`union_dirs`] passes `None` down —
/// since a child shell's HOME is whatever its launcher left it (cadence-hooks#1018).
fn dollar_home(command: &str) -> Option<String> {
    if !command_leaves_home_alone(command) {
        return None;
    }
    let home = cadence_hooks_core::paths::user_home_lossy_or_default();
    (!home.is_empty()).then_some(home)
}

/// The allowlist test behind [`dollar_home`].
fn command_leaves_home_alone(command: &str) -> bool {
    let rest = command.replace("${HOME}", "");
    if ["$(", "`", "$[", "${", "$'"]
        .iter()
        .any(|needle| rest.contains(needle))
    {
        return false;
    }
    let script = strip_heredoc_bodies(&rest);
    if has_unquoted_grouping(&script) {
        return false;
    }
    split_segments_with_ops(&script)
        .iter()
        .map(|(segment, _)| tokenize(segment))
        .filter(|tokens| !tokens.is_empty())
        .all(|tokens| HOME_SAFE_WORDS.contains(&tokens[0].as_str()))
}

/// Does `script` carry a `(`, `)`, `{`, or `}` outside quotes? An unterminated
/// quote counts as yes. Only `'…'` and `"…"` are tracked — the caller has
/// already refused any `$'…'`, the one quoting form whose escapes differ.
fn has_unquoted_grouping(script: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut chars = script.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '\\' if !single => {
                chars.next();
            }
            '(' | ')' | '{' | '}' if !single && !double => return true,
            _ => {}
        }
    }
    single || double
}

/// Resolve a git path operand against a base directory, with the same shell
/// semantics the `cd` arm uses: an absolute path stands alone (including a
/// native `C:\…`), `~` expands, anything else joins onto `base`.
fn resolve_git_path(path: &str, base: &str) -> String {
    if is_shell_absolute(path) {
        path.to_string()
    } else {
        resolve_cd_target(path, base)
    }
}

/// Where a directory value that git or `env` `chdir`s into — a `git -C`,
/// `--work-tree`, `--git-dir` or `GIT_DIR=`/`GIT_WORK_TREE=` value, or an
/// `env -C` — lands from `base`, or `None` when the guard cannot read it.
///
/// Unreadable (cadence-hooks#1056, #1100):
///
/// - a shell expansion the guard does not perform: any `$` other than a
///   leading `$HOME`/`${HOME}` expanded against [`CdEnv::home`] (only set for
///   a command shown to leave HOME alone, see [`dollar_home`]), a backtick, a
///   substitution placeholder, a glob, a brace or a paren. Joining `$VAR`
///   onto `base` named a directory that holds no repo, so the commit behind it
///   was allowed wherever `$VAR` pointed;
/// - a `~user`/`~+`/`~-` tilde form, which the plain HOME substitution would
///   mangle into a path naming no repo;
/// - a path with a `..` whose real location differs from its lexical folding.
///   A `chdir` resolves each symlink before the `..` after it, so
///   `git -C link/../x` with `link -> <p>/sub` runs in `<p>/x` while the
///   lexical reading says `<base>/x`. A value naming no existing directory is
///   not unreadable: git and `env` fail on it, and nothing runs.
///
/// A value that is not a `$HOME` path is judged as the raw text, even where
/// bash would not expand it (`'$V'`): that can only block.
fn chdir_landing(value: &str, base: &str, env: CdEnv<'_>) -> Option<String> {
    let home_rest = value
        .strip_prefix("${HOME}")
        .or_else(|| value.strip_prefix("$HOME"))
        .filter(|rest| rest.is_empty() || rest.starts_with('/'));
    let expanded = match (home_rest, env.home) {
        (Some(rest), Some(home)) => Cow::Owned(format!("{home}{rest}")),
        _ => Cow::Borrowed(value),
    };
    if expanded.contains(['$', '`', '*', '?', '[', '{', '(', ')']) || expanded.contains(CARVED) {
        return None;
    }
    if let Some(after_tilde) = expanded.strip_prefix('~')
        && (!env.tilde || !(after_tilde.is_empty() || after_tilde.starts_with('/')))
    {
        return None;
    }
    let joined = resolve_git_path(&expanded, base);
    if dotdot_diverges(&joined, env) {
        return None;
    }
    Some(joined)
}

/// The most path components [`dotdot_diverges`] resolves; a longer path with
/// a `..` in it is treated as diverging (unreadable), since each component
/// costs a `canonicalize`.
const MAX_PHYSICAL_COMPONENTS: usize = 128;

/// Does a `chdir` into `joined` land somewhere other than its lexical
/// folding? A `chdir` resolves each symlink before the `..` after it, so
/// `link/../x` with `link -> <p>/sub` lands in `<p>/x`.
///
/// Both sides go through [`physical_landing`], which resolves the longest
/// prefix that exists today and folds the rest lexically. That is what closes
/// a target created later in the same command (cadence-hooks#1113 item 2):
/// `mkdir link/../nd && git -C link/../nd commit` names no directory at hook
/// time, so comparing two `canonicalize` calls found nothing to compare, while
/// the prefix `link/..` already resolves into the primary.
fn dotdot_diverges(joined: &str, env: CdEnv<'_>) -> bool {
    if !joined.split(['/', '\\']).any(|c| c == "..") {
        return false;
    }
    if joined.split('/').count() > MAX_PHYSICAL_COMPONENTS {
        return true;
    }
    physical_landing(joined, env) != physical_landing(&lexical_normalize(joined), env)
}

/// Where `path` really is: the real path of its longest existing prefix, with
/// the components past it folded on lexically (they do not exist yet, so a
/// command that creates them creates plain directories). `None` when no
/// prefix resolves at all.
fn physical_landing(path: &str, env: CdEnv<'_>) -> Option<String> {
    let mut prefix = match path.trim_end_matches('/') {
        "" if path.starts_with('/') => "/",
        trimmed => trimmed,
    };
    let mut rest: Vec<&str> = Vec::new();
    loop {
        if prefix.is_empty() {
            return None;
        }
        if let Some(real) = (env.canonical)(prefix) {
            if rest.is_empty() {
                return Some(real);
            }
            rest.reverse();
            return Some(lexical_normalize(&format!("{real}/{}", rest.join("/"))));
        }
        let (head, last) = prefix.rsplit_once('/')?;
        rest.push(last);
        prefix = if head.is_empty() && path.starts_with('/') {
            "/"
        } else {
            head
        };
    }
}

/// What an `env` invocation's own options do before it runs its command.
#[derive(Debug, Default, PartialEq, Eq)]
struct EnvFlags {
    /// The option words, `--` included.
    consumed: usize,
    /// `-C`/`--chdir` values, in order, raw.
    chdirs: Vec<String>,
    /// `-i`, `-` or `--ignore-environment`: the command inherits no variables.
    clears: bool,
    /// `-u`/`--unset` names.
    unsets: Vec<String>,
}

/// Parse the options after an `env` word — GNU's and BSD's shared set (see
/// core's `ENV_VALUE_SHORT_FLAGS`), plus `-` for `-i`. `None` for an option
/// it does not model (`-S`, `--argv0`, a signal option), or when no command
/// follows the options.
fn parse_env_flags(after: &[String]) -> Option<EnvFlags> {
    let mut flags = EnvFlags::default();
    let mut i = 0;
    loop {
        let tok = unescape_word(after.get(i)?);
        if !tok.starts_with('-') {
            break;
        }
        i += 1;
        match tok.as_ref() {
            "--" => break,
            "-" | "--ignore-environment" => flags.clears = true,
            "--null" | "--debug" => {}
            long if long.starts_with("--") => {
                let (name, glued) = match long.split_once('=') {
                    Some((name, value)) => (name, Some(value.to_string())),
                    None => (long, None),
                };
                let value = match glued {
                    Some(value) => value,
                    None => {
                        i += 1;
                        after.get(i - 1)?.clone()
                    }
                };
                match name {
                    "--chdir" => flags.chdirs.push(value),
                    "--unset" => flags.unsets.push(value),
                    _ => return None,
                }
            }
            short => {
                for (pos, c) in short[1..].char_indices() {
                    match c {
                        'i' => flags.clears = true,
                        '0' | 'v' => {}
                        'u' | 'C' | 'P' => {
                            let glued = &short[1 + pos + 1..];
                            let value = if glued.is_empty() {
                                i += 1;
                                after.get(i - 1)?.clone()
                            } else {
                                glued.to_string()
                            };
                            match c {
                                'C' => flags.chdirs.push(value),
                                'u' => flags.unsets.push(value),
                                _ => {}
                            }
                            break;
                        }
                        _ => return None,
                    }
                }
            }
        }
    }
    after.get(i)?;
    flags.consumed = i;
    Some(flags)
}

/// Is `word` an `env` command word?
fn is_env_word(word: &str) -> bool {
    command_word(word) == "env"
}

/// An `env` followed by an option. Left at the head after
/// [`peel_with_chdirs`], it is one whose options [`parse_env_flags`] cannot
/// read: the command behind it, and where it runs, are unknown.
fn is_env_with_options(argv: &[String]) -> bool {
    argv.first().is_some_and(|w| is_env_word(w))
        && argv
            .get(1)
            .is_some_and(|w| unescape_word(w).starts_with('-'))
}

/// The block message for a commit whose checkout the guard cannot read for a
/// reason other than a `cd` or a substitution (see [`Scan::unreadable`]).
fn unreadable_commit_message(what: &str, why: &str) -> String {
    let what = sanitize_field(&what.replace(CARVED, "$(…)"), MAX_PATH_DISPLAY);
    format!(
        "Blocked: `{what}` {why}, so enforce-worktree cannot tell which checkout this commit \
         lands in — it may be a primary checkout.\nName the path literally, e.g. \
         `git -C <path> commit`."
    )
}

/// The most `git -C` hops [`commit_targets_of`] reads; past it the target is
/// unreadable.
const MAX_DASH_C_HOPS: usize = 16;

/// If `argv` (already prefix-/assignment-stripped) is a `git … commit …`
/// invocation, return every directory the commit lands in — the `effective_dir`,
/// or the trees named by `--work-tree`, `--git-dir`, and a `-C <path>` redirect
/// resolved against it. Empty when the segment is not a git-commit.
///
/// Walks git's own global flags to find the subcommand, capturing the redirects
/// on the way. Indices are into the quote-aware token stream, so a spaced quoted
/// `-C`/`-c` value stays one token. git globals that take a SEPARATE value token
/// must be consumed or the walk stops on the value and never reaches `commit`,
/// failing open (CodeRabbit, PR #241) — which is why `--work-tree`/`--git-dir`
/// are listed there too, both spellings landing in the same capture.
///
/// Three resolution rules, all matching git's own:
///
/// - **`-C` accumulates.** git documents each subsequent non-absolute
///   `-C <path>` as relative to the preceding one, so the running redirect is
///   the base for the next.
/// - **`--work-tree` and `--git-dir` are BOTH emitted; `-C` or `effective_dir`
///   is the fallback when neither is named.** They are not ranked against each
///   other, because they name two different things a commit mutates — the tree
///   it reads and the repository whose HEAD and index it advances — and either
///   one landing in a primary checkout is the harm. A `<repo>/.git` value is
///   normalized to `<repo>` — not because [`GitState`] needs it (it resolves
///   either) but because the in-chain dismiss map is keyed by the raw target
///   string, so the two spellings of one repo must converge or a dismissed
///   chain half-matches and blocks. One naming a linked worktree's admin dir is
///   dropped by [`is_linked_worktree_admin_dir`] to avoid a false block.
/// - **An explicit flag outranks the `GIT_WORK_TREE=`/`GIT_DIR=` env prefix**
///   (`env_work_tree`/`env_git_dir`, already resolved by the caller), as it does
///   in git.
///
/// These were previously an `ambiguous` early return — a MISS dressed as a
/// fail-open, since the targets resolve fine (#378). An unresolvable value still
/// fails open downstream: [`assess_dir`] Allows when [`GitState`] finds no repo.
///
/// The leading word is matched through [`command_word`], so a path-qualified
/// (`/usr/bin/git commit`), alias-escaped (`\git commit`), or Windows
/// (`C:\Program Files\Git\cmd\git.exe commit`) spelling is recognized as the
/// commit it is. An exact-string compare against `"git"` missed every one of
/// them and yielded no target at all — no target means no block, so the
/// narrowness was purely a bypass of a block-capable gate rather than a verdict
/// anything depended on (#450). These are ordinary habits: a script invoking
/// git by absolute path, and the standard way to sidestep a `git` alias.
///
/// [`command_word`] is shared with [`is_package_mutation`] and
/// [`file_mutation_targets`], which had the same gap — the normalization lives
/// in exactly one place so a new verb gate cannot silently reopen the bypass by
/// forgetting a step.
///
/// Every directory value goes through [`chdir_landing`]. One it cannot read —
/// a `$VAR`, a glob, a `..` through a symlink — is still emitted as its
/// lexical reading, and the first is described in `unreadable`, which
/// [`run_enforce`] blocks from a linked worktree and [`scan_prepared`] answers
/// by judging the session cwd too (cadence-hooks#1056, #1100).
fn commit_targets_of(
    argv: &[String],
    effective_dir: &str,
    env_work_tree: Option<&str>,
    env_git_dir: Option<&str>,
    env: CdEnv<'_>,
    unreadable: &mut Option<String>,
) -> Vec<CommitTarget> {
    let Some(verb) = argv.first() else {
        return Vec::new();
    };
    if command_word(verb) != "git" {
        return Vec::new();
    }
    const VALUE_GLOBALS: &[&str] = &[
        "-C",
        "-c",
        "--namespace",
        "--super-prefix",
        "--config-env",
        "--attr-source",
        "--work-tree",
        "--git-dir",
    ];
    let mut redirect: Option<String> = None;
    let mut work_tree: Option<Cow<'_, str>> = None;
    let mut git_dir: Option<Cow<'_, str>> = None;
    let mut unread: Option<String> = None;
    let mut hops = 0;
    let mut idx = 1;
    while let Some(t) = argv.get(idx).map(String::as_str) {
        // The FLAG is read the way git receives it, after the shell's escape
        // removal (`-\C` is `-C`); a value stays raw, as in core's push walk,
        // so an unresolvable one fails closed rather than inventing a path.
        let flag = unescape_word(t);
        if !flag.starts_with('-') {
            break;
        }
        // A value word is consumed WITH its flag, in one step, so it is never
        // re-read as a flag on the next pass (cadence-hooks#885). Deciding that
        // by looking BACK at the previous token instead misread a value that
        // spells a global: in `git -c -C commit` the `-C` is `-c`'s value, but
        // the look-back walk then read `commit` as `-C`'s value and never
        // reached the subcommand. The same fix as core's push walk
        // (`git_globals`). It also keeps `git -c --work-tree=/x commit` from
        // resolving a tree git never touches: that string is `-c`'s value.
        if VALUE_GLOBALS.contains(&flag.as_ref()) {
            if let Some(value) = argv.get(idx + 1).map(String::as_str) {
                match flag.as_ref() {
                    // `-C` compounds: resolve this hop against the previous one.
                    "-C" => {
                        let base = redirect.as_deref().unwrap_or(effective_dir);
                        // Folded once read: each hop joins onto a short path,
                        // and a readable hop's folding IS where git lands.
                        // Once one hop is unreadable the target is anyway;
                        // skip the stats that could only find another. Past
                        // MAX_DASH_C_HOPS the chain is unreadable too: each
                        // hop reads the path the last one built.
                        hops += 1;
                        if unread.is_some() {
                            // The target is already unreadable; this hop
                            // cannot make it readable again.
                            idx += 2;
                            continue;
                        }
                        let landed = if hops > MAX_DASH_C_HOPS {
                            unread = Some(format!("-C … ({hops} directories)"));
                            None
                        } else {
                            chdir_landing(value, base, env)
                        };
                        let hop = landed.unwrap_or_else(|| {
                            unread.get_or_insert_with(|| format!("-C {value}"));
                            resolve_git_path(value, base)
                        });
                        redirect = Some(lexical_normalize(&hop));
                    }
                    "--work-tree" => work_tree = Some(Cow::Borrowed(value)),
                    "--git-dir" => git_dir = Some(Cow::Borrowed(value)),
                    _ => {}
                }
            }
            idx += 2;
            continue;
        }
        // The `=` forms are read off the UNESCAPED flag too: `--git-d\ir=<p>`
        // is `--git-dir=<p>` to git (cadence-hooks#1058 review I4).
        if let Some(v) = cow_strip_prefix(&flag, "--work-tree=") {
            work_tree = Some(v);
        } else if let Some(v) = cow_strip_prefix(&flag, "--git-dir=") {
            git_dir = Some(v);
        }
        idx += 1;
    }
    if argv.get(idx).map(|w| unescape_word(w)).as_deref() != Some("commit") {
        return Vec::new();
    }
    // Every relative value — flag OR env — resolves against the cwd git is
    // already standing in: the accumulated `-C` when there was one, else the
    // segment's dir. git applies the `-C` chdir before repository setup, so
    // resolving the env values anywhere else is the bypass described on
    // [`git_env_overrides`].
    let base = redirect.as_deref().unwrap_or(effective_dir);
    // Per-flag precedence: each explicit flag overrides only its OWN env var,
    // exactly as git does, so `--git-dir=X` with `GIT_WORK_TREE=Y` still reads
    // its tree from Y.
    let mut resolve = |p: &str, name: &str| {
        chdir_landing(p, base, env).unwrap_or_else(|| {
            unread.get_or_insert_with(|| format!("{name} {p}"));
            resolve_git_path(p, base)
        })
    };
    let resolved_work_tree = work_tree
        .as_deref()
        .or(env_work_tree)
        .map(|p| resolve(p, "--work-tree"));
    let resolved_git_dir = git_dir
        .as_deref()
        .or(env_git_dir)
        .map(|p| resolve(p, "--git-dir"));
    if let Some(what) = unread
        && unreadable.is_none()
    {
        *unreadable = Some(unreadable_commit_message(
            &format!("git {what} commit"),
            "names a directory the guard cannot resolve (a shell variable, a glob, or a `..` \
             through a symlink)",
        ));
    }

    // BOTH are emitted, because they name two different things git mutates and
    // either one landing in a primary checkout is the harm this guard exists to
    // stop. `--git-dir=<primary>/.git --work-tree=<elsewhere> commit` writes the
    // tree read from `<elsewhere>` but advances the PRIMARY's HEAD and index —
    // collapsing to a single work-tree-wins target allowed exactly that
    // (security review, #378). The caller assesses each target independently and
    // dedups, so two targets cost at most one extra probe.
    //
    // EVERY emitted target goes through [`normalize_target`], including the
    // fallback — the in-chain dismiss map is keyed by these strings, so one
    // un-normalized path is enough to make a licensed chain half-match and
    // block (security review, #378).
    let mut targets: Vec<CommitTarget> = Vec::new();
    if let Some(wt) = resolved_work_tree {
        targets.push(normalize_target(&wt));
    }
    if let Some(gd) = resolved_git_dir.filter(|p| !is_linked_worktree_admin_dir(p)) {
        let gd = normalize_target(&gd);
        if !targets.contains(&gd) {
            targets.push(gd);
        }
    }
    if targets.is_empty() {
        targets.push(normalize_target(
            &redirect.unwrap_or_else(|| effective_dir.to_string()),
        ));
    }
    targets
}

/// `word` with `prefix` removed, borrowing from the original argv word when
/// `word` borrows from it.
fn cow_strip_prefix<'a>(word: &Cow<'a, str>, prefix: &str) -> Option<Cow<'a, str>> {
    match word {
        Cow::Borrowed(w) => {
            let w: &'a str = w;
            w.strip_prefix(prefix).map(Cow::Borrowed)
        }
        Cow::Owned(w) => w.strip_prefix(prefix).map(|v| Cow::Owned(v.to_string())),
    }
}

/// Scan `command`'s **top-level** segments for a leading in-chain
/// `dismiss-enforce-worktree` that licenses a same-repo `git commit` ordered
/// after it — the #323 loosening. Returns a map from resolved commit-target dir
/// to the dismiss's parsed `--reason` (for the synthesized bypass provenance).
///
/// Two guardrails keep this strict:
///
/// - **Top-level only.** A dismiss is honored only when it is the segment's own
///   command (leading token is the `cadence-hooks` binary) — a dismiss buried
///   in a `$(…)` substitution or `sh -c '…'` wrapper is NOT honored, because
///   that dismiss does not actually run before this same command's commit. This
///   walk therefore never recurses into child scripts for a dismiss (unlike
///   [`union_commits`], which it uses to find commits).
/// - **`&&` chain only (GATE RIDER).** The dismiss's snooze only exists at the
///   commit's runtime if every connector between them is `&&`. A `;`/`||` (or
///   `|`/`&`/newline) breaks the chain — the dismiss might fail and the commit
///   still run — so the active dismiss set is cleared on any non-`&&` connector,
///   and such a commit still BLOCKS (fail closed).
#[cfg(test)]
fn inchain_dismissed_commits(
    command: &str,
    cwd: &str,
    on_disk: bool,
) -> HashMap<CommitTarget, Option<String>> {
    let home = dollar_home(command);
    let env = CdEnv::for_command(command, home.as_deref(), on_disk);
    let plain = plain_of(command, cwd, env);
    inchain_dismissed_prepared(command, cwd, env, plain.as_ref())
}

/// [`inchain_dismissed_commits`] over an already computed [`plain_of`].
fn inchain_dismissed_prepared(
    command: &str,
    cwd: &str,
    env: CdEnv<'_>,
    plain: Option<&Plain>,
) -> HashMap<CommitTarget, Option<String>> {
    let mut dismissed: HashMap<CommitTarget, Option<String>> = HashMap::new();
    // Repos with an active leading dismiss in the CURRENT unbroken `&&` chain:
    // target dir → parsed `--reason`. Cleared whenever a non-`&&` connector
    // breaks the chain.
    let mut active: HashMap<CommitTarget, Option<String>> = HashMap::new();
    // A PLAIN command is walked as the block channel walks it. A non-plain
    // command licenses an in-chain commit only when it names no directory at
    // all — no `cd`/`pushd`, nothing unreadable — so every commit in it runs
    // in the session cwd, as the union path judges it (#1058).
    let Some(plain) = plain else {
        if command_heredocs_suspect(command) {
            return dismissed;
        }
        return inchain_dismissed_without_cd(command, cwd, env);
    };
    // The SAME walk and the same per-segment commit resolution the block
    // channel uses ([`scan_targets`]), so the dismiss map, keyed by resolved
    // target strings, matches the targets it is checked against (#378).
    let walked = walk_plain(plain, cwd, env, |seg| {
        let (argv, work_tree, git_dir) = plain_command(&seg.words);
        // A dismiss is recognized without peeling command runners: the
        // escape hatch stays exactly as wide as before cadence-hooks#1111.
        let dismiss = peel_heads(&seg.words, false).0;
        if seg.is_cd {
            // Moved by the walk itself.
        } else if is_dismiss_enforce_segment(dismiss) {
            let argv = dismiss;
            // The dismiss runs in ONE of the candidate directories. It is
            // armed only when every candidate names the same repo, so an
            // ambiguous cd never licenses a commit it cannot be shown to
            // share a repo with (fail closed).
            let mut repos: Vec<CommitTarget> = seg
                .dirs
                .iter()
                .map(|d| dismiss_target_dir(argv, &d.pwd))
                .collect();
            repos.sort();
            repos.dedup();
            if let [repo] = repos.as_slice() {
                active.insert(
                    repo.clone(),
                    crate::snooze_meta::normalize_reason(flag_value(argv, "--reason").as_deref()),
                );
            }
        } else {
            for dir in seg.dirs {
                for target in commit_targets_of(argv, &dir.pwd, work_tree, git_dir, env, &mut None)
                {
                    if let Some(reason) = active.get(&target) {
                        dismissed.entry(target).or_insert_with(|| reason.clone());
                    }
                }
            }
        }

        // GATE RIDER: only an `&&` connector preserves the active dismiss set
        // into the next segment.
        if seg.next_op != Some("&&") {
            active.clear();
        }
    });
    if walked.is_none() {
        // Plain in shape but not in fact (a wrapper, an unreadable cd): the
        // block channel took the union path, so this does too.
        return inchain_dismissed_without_cd(command, cwd, env);
    }
    dismissed
}

/// [`inchain_dismissed_commits`] for a non-plain command that changes no
/// directory: the top-level `&&` chain, with commits found the way
/// [`union_commits`] finds them — including inside a wrapper's child, which is
/// how `dismiss && GIT_WORK_TREE=<p> sh -c 'git commit'` stays licensed (#378).
/// A dismiss inside a wrapper is still not honored: only a top-level segment's
/// own command can arm one.
fn inchain_dismissed_without_cd(
    command: &str,
    cwd: &str,
    env: CdEnv<'_>,
) -> HashMap<CommitTarget, Option<String>> {
    let mut dismissed: HashMap<CommitTarget, Option<String>> = HashMap::new();
    let mut dirs = vec![cwd.to_string()];
    let mut unresolved = None;
    union_dirs(
        command,
        0,
        union_env(command, env),
        &mut dirs,
        &mut unresolved,
    );
    if dirs.len() != 1 || unresolved.is_some() {
        return dismissed;
    }
    let mut active: HashMap<CommitTarget, Option<String>> = HashMap::new();
    for (raw, next_op) in split_segments_with_ops(command) {
        let segment = strip_group_punctuation(&raw);
        let words = command_tokens(&tokenize_marked(segment));
        let argv = peel_heads(strip_compound_heads(&words), false).0;
        if is_dismiss_enforce_segment(argv) {
            active.insert(
                dismiss_target_dir(argv, cwd),
                crate::snooze_meta::normalize_reason(flag_value(argv, "--reason").as_deref()),
            );
        } else {
            let mut found = Scan::default();
            union_commits(segment, 0, &dirs, (None, None), env, &mut found);
            for target in found.commits {
                if let Some(reason) = active.get(&target) {
                    dismissed.entry(target).or_insert_with(|| reason.clone());
                }
            }
        }
        if next_op != Some("&&") {
            active.clear();
        }
    }
    dismissed
}

/// True when `argv` (prefix-stripped) is a `cadence-hooks guardrails
/// dismiss-enforce-worktree …` invocation whose leading token IS the
/// `cadence-hooks` binary (by basename) — so a dismiss wrapped in `$(…)` or
/// `sh -c '…'`, where the binary word is not the segment's own command, is not
/// matched (top-level only, #323).
/// Deliberately on a bare [`basename`] rather than [`command_word`], unlike the
/// verb gates above. This one recognizes a *bypass*, so the two directions
/// invert: a missed spelling here refuses a dismissal the operator meant to
/// perform (annoying, and it fails toward blocking), while a *widened* one
/// widens the escape hatch itself. The verb gates widen toward more blocking
/// and want every spelling; this gate does not.
fn is_dismiss_enforce_segment(argv: &[String]) -> bool {
    argv.first().map(|c| basename(c)) == Some("cadence-hooks")
        && argv
            .windows(2)
            .any(|w| w[0] == "guardrails" && w[1] == "dismiss-enforce-worktree")
}

/// The repo dir a `dismiss-enforce-worktree` segment targets: its `--repo`
/// value resolved against `effective_dir` when present (mirroring
/// [`commit_target_of`]'s `-C` resolution so the two produce matching target
/// strings for the same repo), else `effective_dir` itself.
fn dismiss_target_dir(argv: &[String], effective_dir: &str) -> CommitTarget {
    // Through the SAME [`normalize_target`] the commit side uses. This is the
    // other half of the dismiss map's key: a `--repo <p>/` or `--repo <p>/.git`
    // must land on the same string a `--work-tree=<p>` commit produces, or the
    // user's own dismiss stops licensing the commit it was run for — and the
    // block then points at the dismiss they already ran (security review, #378).
    let raw = match flag_value(argv, "--repo") {
        Some(repo) if is_shell_absolute(&repo) => repo,
        Some(repo) => format!("{effective_dir}/{repo}"),
        None => effective_dir.to_string(),
    };
    normalize_target(&raw)
}

/// Value of a `--flag <value>` or `--flag=<value>` option in `argv`, if present.
fn flag_value(argv: &[String], flag: &str) -> Option<String> {
    let eq_prefix = format!("{flag}=");
    let mut it = argv.iter();
    while let Some(tok) = it.next() {
        if tok == flag {
            return it.next().cloned();
        }
        if let Some(v) = tok.strip_prefix(&eq_prefix) {
            return Some(v.to_string());
        }
    }
    None
}

// `should_block` moved to `cadence_hooks_core::worktree` (cadence-hooks#236)
// — re-imported above; this IS the same function `would_block_here` calls.

/// The block message: names the checkout and every escape hatch. When
/// `origin_repo` names a *different* repo than `repo_root` — a `cd <dir> &&
/// git commit` (or a `-C <dir>`) that redirected the target elsewhere from
/// where the shell started — an extra line acknowledges the redirect, so the
/// block reads as "this command targets repo X" rather than misattributing
/// the policy to the repo the shell happened to start in (issue #224).
///
/// The dismiss it suggests carries `--repo <repo_root>` whenever the judged
/// repo is not the one the shell starts in (or the shell starts in no repo).
/// A dismiss is keyed on the repo it runs in, so the bare command, run from
/// the session cwd, snoozed THAT repo, printed a success line naming it, and
/// left this block standing (cadence-hooks#758).
fn block_message(repo_root: &str, origin_repo: Option<&str>) -> String {
    let repo_flag = if origin_repo == Some(repo_root) {
        String::new()
    } else {
        format!(" --repo {}", shell_single_quote(repo_root))
    };
    let mut msg = format!(
        "Blocked: `{repo_root}` is a primary checkout — feature work belongs in a worktree.\n\
         Create one: {WORKTREE_CREATE_RECIPE}, then work there.\n\
         One-off exception: `cadence-hooks guardrails dismiss-enforce-worktree --for 30m\
         {repo_flag} --reason \"<why>\"` (reason required over 1h; logged in the repo-visible \
         bypass log).\n\
         Main-by-design repo? Set CADENCE_ALLOW_MAIN=true in the target repo's \
         .claude/settings.json env block. Disable everywhere: CADENCE_NO_ENFORCE_WORKTREE=1.\n\
         If the change must stay on this checkout's current branch (peer-coordinated work on a \
         shared branch), a worktree cannot duplicate it — the dismiss above is the sanctioned \
         path, not a workaround."
    );
    if let Some(origin) = origin_repo
        && origin != repo_root
    {
        msg.push_str(&format!(
            "\nJudged against `{repo_root}` (the repo this command targets via cd/-C), \
             not `{origin}`."
        ));
    }
    msg
}

/// The block message for a non-plain command from a linked worktree whose
/// `cd` the guard cannot read: the cd may lead into any checkout.
fn unresolved_cd_block_message(target: &str) -> String {
    let target = sanitize_field(target, MAX_PATH_DISPLAY);
    format!(
        "Blocked: `cd {target}` could not be resolved, so enforce-worktree cannot tell \
         which checkout this commit lands in — it may be a primary checkout.\n\
         Name the path literally in a plain `cd <path> && git commit`, or use \
         `git -C <path> commit`."
    )
}

/// The block message for a non-plain command from a linked worktree whose
/// commit's command word, subcommand or target comes from a substitution.
fn substituted_commit_block_message(segment: &str) -> String {
    let segment = sanitize_field(&segment.replace(CARVED, "$(…)"), MAX_PATH_DISPLAY);
    format!(
        "Blocked: `{segment}` builds a git commit's command or target from a substitution, \
         so enforce-worktree cannot tell which checkout it lands in — it may be a primary \
         checkout.\nName the path literally, e.g. `git -C <path> commit`."
    )
}

/// Quote `s` as one shell word for a command the block message suggests: bare
/// when it holds only characters no shell treats specially, else single-quoted
/// with each `'` spelled `'\''`.
fn shell_single_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ':' | ',')
        });
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Append a hint to a Bash-arm block when the command carried a `cd` whose
/// target the union path could not read — so the block, judged
/// from the directory before that cd, says why instead of looking like it
/// ignored the cd (cadence-hooks#1018). Message-only: the verdict is untouched,
/// and from a primary checkout an unreadable cd keeps blocking — letting it
/// through would be a bypass.
fn with_unresolved_cd_hint(mut result: CheckResult, unresolved: Option<&str>) -> CheckResult {
    if let (Some(target), Some(message)) = (
        unresolved.filter(|t| !t.is_empty()),
        result.message.as_mut(),
    ) {
        let target = sanitize_field(target, MAX_PATH_DISPLAY);
        message.push_str(&format!(
            "\nNote: `cd {target}` could not be resolved (a shell variable, a glob, `cd -`, \
             or `$HOME` in a command the guard cannot confirm leaves HOME alone), so the \
             commit was judged from every directory the command could be in. If it really \
             lands elsewhere, name the path literally or use `git -C <path> commit`."
        ));
    }
    result
}

/// On a union-path block, name a linked worktree one of the command's `cd`s
/// leads into, and the spelling that commits there in any shape: the command
/// could not be followed step by step, so its `cd` into the worktree does not
/// clear the session cwd (cadence-hooks#1058).
fn with_union_worktree_hint(
    mut result: CheckResult,
    union_cd_dirs: &[String],
    probe: &mut GitProbe,
) -> CheckResult {
    let worktree = union_cd_dirs.iter().find_map(|dir| {
        probe
            .repo_root(Path::new(dir))
            .filter(|root| !is_primary_checkout(root))
    });
    if let (Some(root), Some(message)) = (worktree, result.message.as_mut()) {
        let root = sanitize_field(&root, MAX_PATH_DISPLAY);
        message.push_str(&format!(
            "\nThis command's shape can't be followed step by step (a subshell, `||`, `&`, a \
             file redirection, a substitution, …), so the commit was judged from every \
             directory it could be in, including the session cwd. To commit in the worktree, \
             run `git -C {} commit …`.",
            shell_single_quote(&root)
        ));
    }
    result
}

/// Ascend from `dir` to the nearest ancestor that exists on disk. A `Write` can
/// name a file in a not-yet-created subtree, so the file's parent dir may not
/// exist yet — and [`GitState::resolve`] returns `None` for a nonexistent path
/// (cadence-hooks#299), so an unresolved parent would fail open and let a
/// new-module write into the primary slip past the Edit arm (#239 F1). This
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
    probe: &mut GitProbe,
) -> CheckResult {
    let Some(repo_root) = probe.repo_root(dir) else {
        // Not a git repo (or a bare container dir), or the probe timed out
        // (#271) — both fail open, deliberately: enforce-worktree is a
        // workflow-discipline guard, and a missed nudge is cheaper than a
        // false block (ADR-0001).
        return CheckResult::allow();
    };
    // The snooze marker lives under the shared git common dir; resolve it
    // through the probe (the Edit/Write arm already asked this exact question
    // for its same-repo scoping, so that path is a memo hit) and hand the
    // resolved dir to the marker reads below — pure filesystem from here,
    // no further git spawns (#271: Edit/Write 4-5 spawns → 3).
    let Some(common_dir) = probe.common_dir(dir) else {
        // The root resolved but the common dir didn't — in practice the probe
        // hit the #271 deadline. Snooze state is unreadable, and blocking
        // could false-block through an active dismissal: the guard's own
        // infrastructure failure never blocks (ADR-0001).
        return CheckResult::allow();
    };
    let common_dir = PathBuf::from(common_dir);
    let is_primary = is_primary_checkout(&repo_root);
    let temp_root = is_temp_root(
        Path::new(&repo_root),
        cfg.tmpdir.as_deref(),
        Some(&cfg.home),
    );
    let snoozed = cadence_hooks_core::worktree::is_snoozed_in_common_dir(&common_dir);
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
        // Bootstrap exemption (#309): a repo with zero commits *anywhere*
        // cannot be worktree'd — `git worktree add -b <b>` needs a commit to
        // branch from — so the block's own remedy is mechanically impossible
        // and the first/bootstrap commit MUST land in this primary checkout.
        // The exemption evaporates the moment the repo has its first commit.
        //
        // Probed lazily, only on this would-block path (no extra git spawn in
        // the common worktree/temp/snoozed case — #271), and keyed on "any
        // commit exists" (`rev-list --all`), NOT the current HEAD: an
        // orphan-HEAD / HEAD-deleted established repo still has commits and
        // still blocks. Fails closed — only an affirmative `Value("0")`
        // exempts; a probe error/timeout keeps the block (see
        // [`GitProbe::is_commitless`]).
        //
        // Plain `allow()` (not `allow_bypassed`): like the temp-root carve-out,
        // the guard's *premise* doesn't hold here — this is not a user-armed
        // bypass, so it writes no bypass-log entry.
        if probe.is_commitless(Path::new(&repo_root)) {
            return CheckResult::allow();
        }
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
            let meta = dismiss_enforce_worktree::read_meta_in(&common_dir);
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

/// The subprocess-mutation nudge (#234) — enforce-worktree's first nudge
/// branch. For each mutation location surfaced by the walk, fire ONLY when it
/// lands in the session's OWN primary checkout: reuse the Edit/Write arm's
/// git-common-dir equality scoping (#238) and the `.claude/`/`docs/plans/`
/// carve-outs, and gate on [`assess_dir`] returning a Block there. Routing
/// through `assess_dir` folds every existing suppression for free (process/repo
/// `CADENCE_ALLOW_MAIN`, the `CADENCE_NO_ENFORCE_WORKTREE` kill switch,
/// temp-root, and the active `dismiss-enforce-worktree` snooze) — an Allow
/// (exempt, or the target isn't a primary checkout) yields no nudge. Advisory
/// (exit 0): it never blocks, so it cannot weaken any existing block, and it
/// reuses the enforce-worktree snooze rather than adding a dismiss key (D2).
fn mutation_nudge(
    mutation_targets: &[MutationTarget],
    cwd: &str,
    cfg: &EnvConfig,
    repo_allow: &mut RepoAllowMain,
    probe: &mut GitProbe,
) -> Option<CheckResult> {
    // Scope to the session's own repo (like #238): resolve the cwd's common dir
    // once. A session not in any repo has no own checkout to protect → no nudge.
    let cwd_common = probe.common_dir(Path::new(cwd))?;
    let mut seen: HashSet<String> = HashSet::new();
    for target in mutation_targets {
        // Resolve to the directory to assess. A `File` target is resolved to
        // its PARENT directory first — exactly as the Edit/Write arm does via
        // `git_dir_for_input`'s `.parent()` — because a `git -C <file>
        // rev-parse` errors "Not a directory" and `nearest_existing_ancestor`
        // returns an existing file unchanged (its own `exists()` short-circuits
        // the ascent), so probing the raw file path silently dropped the nudge
        // for an already-existing tracked file (security-review FIX 1). A `Dir`
        // target (a package-manager verb's cwd) is already a directory — taking
        // its parent would wrongly hop to the enclosing dir, so it is used as-is.
        // A `File` target that does not exist yet is not a mutation of tracked
        // tree content — it is a brand-new scratch file, report, or log, and
        // nudging on it told the reporter their command "mutates tracked files"
        // when it created one (#377). Gated BEFORE the `.parent()` ascent, which
        // would otherwise hand a nonexistent path to the containing directory and
        // nudge identically to an existing tracked file. A pure metadata probe —
        // no git spawn, honoring the #271 probe discipline. `Dir` targets (a
        // package-manager verb's cwd) keep nudging: the install mutates whatever
        // is already there.
        //
        // `symlink_metadata`, not `exists()`: the latter follows the link and
        // reports false for a DANGLING symlink, so a redirect onto a tracked but
        // broken symlink would be silenced (security review). This gate cannot
        // separate a scratch `report.txt` from a brand-new SOURCE file — both are
        // equally absent — so a first write of `src/newmod/lib.rs` in the primary
        // is now silent too; that widened miss is enumerated in the module header.
        if let MutationTarget::File(f) = target
            && std::fs::symlink_metadata(f).is_err()
        {
            continue;
        }
        let assess_path: PathBuf = match target {
            MutationTarget::Dir(d) => PathBuf::from(d),
            MutationTarget::File(f) => Path::new(f)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(f)),
        };
        if !seen.insert(assess_path.to_string_lossy().into_owned()) {
            continue;
        }
        // Same `.claude/`/`docs/plans/` carve-outs as the Edit/Write arm — a
        // mutation into Claude-managed state or an approved plan doc is exempt.
        // Checked on the containing dir, matching the Edit arm (which checks the
        // file's `git_dir_for_input` parent), so a `.claude/`-component path is
        // still caught.
        if is_claude_managed_dir(&assess_path) || is_plan_doc_dir(&assess_path) {
            continue;
        }
        // A redirect/verb target may name a file in a not-yet-created subtree;
        // ascend to the nearest existing dir so repo resolution works (mirrors
        // the Edit arm, which runs `nearest_existing_ancestor` after `.parent()`).
        let dir = nearest_existing_ancestor(&assess_path);
        // Same repo as the session? (git common dir equality, #238/#179.) A
        // mutation into a foreign repo or a temp dir git can't resolve is out
        // of scope, exactly like a foreign Edit/Write drop.
        match probe.common_dir(&dir) {
            Some(target_common) if target_common == cwd_common => {}
            _ => continue,
        }
        // Would a mutation here BLOCK? assess_dir folds every suppression; a
        // Block means an un-exempted primary checkout → nudge. `origin_repo` is
        // None — there is no cross-repo redirect to attribute in the message.
        if assess_dir(&dir, cfg, None, repo_allow, probe).outcome == Outcome::Block {
            let repo = probe
                .repo_root(&dir)
                .unwrap_or_else(|| dir.to_string_lossy().into_owned());
            // The path comes out of the user's command, so it goes through the
            // same display sanitizer every other untrusted field in this binary
            // uses — a filename carrying a newline must not be able to forge an
            // extra line in the guard's own advisory (security review).
            let path = match target {
                MutationTarget::Dir(d) => d,
                MutationTarget::File(f) => f,
            };
            let path = sanitize_field(path, MAX_PATH_DISPLAY);
            return Some(CheckResult::nudge(mutation_nudge_message(&repo, &path)));
        }
    }
    None
}

/// The nudge message: names the PATH it resolved and the checkout that path
/// lands in, then the accumulate-before-tripwire rationale, the worktree fix,
/// and the shared-snooze escape (the nudge reuses the enforce-worktree snooze —
/// no separate dismiss key, per D2).
///
/// Naming the path is load-bearing. The message used to assert "mutates tracked
/// files in the primary checkout `<repo>`" and name only the repo, so a reader
/// who could not see which path the walk had picked read it as the guard
/// misidentifying their cwd (#377). It also no longer claims the target is
/// *tracked* — the walk never asks git that, and the nudge fires on untracked
/// paths in a tracked tree too.
fn mutation_nudge_message(repo_root: &str, path: &str) -> String {
    format!(
        "enforce-worktree: this command mutates `{path}` in the primary checkout \
         `{repo_root}` via a subprocess (package install, `sed -i`, or a redirect) — writes \
         accumulate unseen until commit. Prefer a worktree: {WORKTREE_CREATE_RECIPE}. \
         Silence for 30m: `cadence-hooks guardrails dismiss-enforce-worktree --for 30m`"
    )
}

/// Testable core: assess the hook input under the given environment.
fn run_enforce(input: &HookInput, cfg: &EnvConfig) -> CheckResult {
    let mut repo_allow = RepoAllowMain::default();
    let mut probe = GitProbe::default();
    match input.normalized_tool_name() {
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
            match (
                probe.common_dir(&target_dir),
                probe.common_dir(Path::new(cwd)),
            ) {
                (Some(target_repo), Some(cwd_repo)) if target_repo == cwd_repo => {
                    assess_dir(&target_dir, cfg, None, &mut repo_allow, &mut probe)
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
            let cwd_repo_root = probe.repo_root(Path::new(cwd));
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
            // One walk, two channels (#234): commit targets (block) and
            // subprocess-mutation locations (nudge). The commit channel is
            // evaluated FIRST — the composition contract is block-first: a
            // `uv add && git commit` into the primary must BLOCK (commit wins),
            // never double-fire a nudge.
            // The plain-shape analysis runs once, for both walks below.
            let home = dollar_home(command);
            let env = CdEnv::for_command(command, home.as_deref(), true);
            let plain = plain_of(command, cwd, env);
            let Scan {
                commits: commit_targets,
                mutations: mutation_targets,
                unresolved_cd,
                unresolved_commit,
                unreadable,
                union_cd_dirs,
            } = scan_prepared(command, cwd, env, plain.as_ref());
            // A leading `&&`-chained `dismiss-enforce-worktree` for the SAME
            // repo licenses a commit ordered after it (#323): the dismiss will
            // have armed the snooze before the commit runs, so honoring it here
            // keeps the hook's decision consistent with what the shell will
            // actually do. Top-level only, `&&`-chain only (see
            // [`inchain_dismissed_commits`]); the map is keyed by the same
            // resolved target strings the commit channel produces.
            let dismissed = inchain_dismissed_prepared(command, cwd, env, plain.as_ref());
            // Dedup identical targets so a pathological command (`git commit;`
            // ×N) can't fan out into N synchronous `git rev-parse` spawns and
            // stall the hook — each distinct target is assessed once (#239 F11).
            let mut seen: HashSet<String> = HashSet::new();
            let has_commit = !commit_targets.is_empty();
            for target in commit_targets {
                if !seen.insert(target.clone()) {
                    continue;
                }
                let dir = PathBuf::from(&target);
                let result = assess_dir(
                    &dir,
                    cfg,
                    cwd_repo_root.as_deref(),
                    &mut repo_allow,
                    &mut probe,
                );
                if result.outcome != Outcome::Allow {
                    // A leading in-chain dismiss for this same repo converts the
                    // block into a recorded bypass — never a bare allow, so the
                    // bypass-log `used` event fires (#323).
                    if let Some(reason) = dismissed.get(&target) {
                        if bypassed.is_none() {
                            bypassed = Some(CheckResult::allow_bypassed(BypassProvenance {
                                kind: BypassKind::Dismissal,
                                mechanism: "dismiss-enforce-worktree (in-chain)".to_string(),
                                reason: reason.clone(),
                                expires_at: None,
                                armed_by_session: None,
                            }));
                        }
                        continue;
                    }
                    let result = with_unresolved_cd_hint(result, unresolved_cd.as_deref());
                    return with_union_worktree_hint(result, &union_cd_dirs, &mut probe);
                }
                if result.bypass.is_some() && bypassed.is_none() {
                    bypassed = Some(result);
                }
            }
            // A non-plain command whose `cd` the guard cannot read may commit
            // anywhere. From a primary the session cwd is already a target and
            // blocked above; from a linked worktree it blocks here — the
            // unresolved cd could lead into a primary (#346, #1058).
            let unreadable = match (unresolved_cd.as_deref(), unresolved_commit.as_deref()) {
                (Some(target), _) => Some(unresolved_cd_block_message(target)),
                (None, Some(segment)) => Some(substituted_commit_block_message(segment)),
                (None, None) => unreadable,
            };
            if has_commit
                && let Some(message) = unreadable
                && probe
                    .repo_root(Path::new(cwd))
                    .is_some_and(|root| !is_primary_checkout(&root))
            {
                return with_union_worktree_hint(
                    CheckResult::block(message),
                    &union_cd_dirs,
                    &mut probe,
                );
            }
            // No commit blocked. The mutation nudge fires ONLY IF no commit
            // rode a bypass either — a snooze/env exemption on any commit in the
            // command also suppresses the mutation in the same repo, so a
            // bypassed-commit allow implies a suppressed nudge; deferring to it
            // preserves the bypass-log record (a Nudge carries no provenance).
            // enforce-worktree's first nudge branch.
            if bypassed.is_none()
                && let Some(nudge) =
                    mutation_nudge(&mutation_targets, cwd, cfg, &mut repo_allow, &mut probe)
            {
                return nudge;
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
    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use cadence_hooks_core::test_builders::{make_bash, make_edit};

    /// This crate's own `target/`-relative scratch root — `env!` resolves at
    /// THIS call site, so the promoted `Scratch` still lands fixtures under
    /// `crates/guardrails/../../target/`, exactly where the pre-promotion
    /// in-crate helper put them.
    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/enforce-worktree-scratch")
    }

    /// Thin wrapper binding [`Scratch::new`] to this crate's own
    /// `scratch_root()`, so every call site below reads exactly as it did
    /// before the promotion (`scratch("tag")`) instead of repeating
    /// `Scratch::new(&scratch_root(), "tag")` at each of them.
    fn scratch(tag: &str) -> Scratch {
        Scratch::new(&scratch_root(), tag)
    }

    /// The two walks that cross the leading prefix region MUST stop at the same
    /// index — the property [`is_prefix_word`]'s own doc comment asserts, and
    /// the one nothing pinned.
    ///
    /// `is_prefix_word` was a local copy of core's `TRANSPARENT` membership test
    /// on the RAW, unfolded token. Core's copy learned to fold (#488) and then
    /// to unescape (#237), and each widening moved the two apart silently:
    /// `\exec GIT_DIR=/other git commit` went from *never inspected* (the
    /// leading-word gate stopped at `\exec`) to *inspected with the redirect
    /// invisible* — `git_env_overrides` stopped at index 0 and returned
    /// `(None, None)`, so the commit was judged against the session cwd. From a
    /// primary checkout that is a false BLOCK on a commit git sends elsewhere.
    #[test]
    fn both_prefix_walks_stop_at_the_same_index() {
        for command in [
            "exec GIT_DIR=/other git commit -m x",
            "\\exec GIT_DIR=/other git commit -m x",
            "\\env GIT_DIR=/other git commit -m x",
            "EXEC GIT_DIR=/other git commit -m x",
            "\\time GIT_WORK_TREE=/other git commit -m x",
        ] {
            let tokens: Vec<String> =
                cadence_hooks_core::shell::executable_tokens(command).to_vec();
            let argv = skip_transparent_prefixes(&tokens);
            let peeled = tokens.len() - argv.len();
            let mut idx = 0;
            while idx + 1 < tokens.len() && is_prefix_word(&tokens, idx) {
                idx += 1;
            }
            assert_eq!(
                idx, peeled,
                "{command:?}: the two walks disagree about where the prefix region ends"
            );
            // And the override the env walk exists to read must be in hand.
            let (work_tree, git_dir) = git_env_overrides(&tokens);
            assert!(
                work_tree.is_some() || git_dir.is_some(),
                "{command:?}: the redirect went unseen"
            );
        }
    }

    /// An empty `home` disables the #569 swallowed-home rule, which is what
    /// keeps these cases testing what they were written to test. Read a pass
    /// here as evidence about the exemption under test and nothing else — the
    /// rule itself is covered where it lives, in `core::worktree`'s
    /// `tmpdir_*_home_is_not_a_temp_root` tests.
    fn cfg(allow_main: bool, kill_switch: bool) -> EnvConfig {
        EnvConfig {
            allow_main,
            kill_switch,
            tmpdir: None,
            home: String::new(),
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
        assert!(is_temp_root(Path::new("/tmp/scratch-repo"), None, None));
        assert!(is_temp_root(Path::new("/private/tmp/fixture"), None, None));
    }

    #[test]
    fn tmpdir_env_root_is_temp() {
        assert!(is_temp_root(
            Path::new("/var/folders/xy/T/repo"),
            Some("/var/folders/xy/T"),
            None
        ));
    }

    #[test]
    fn home_repo_is_not_temp() {
        assert!(!is_temp_root(
            Path::new("/Users/dev/Projects/repo"),
            None,
            None
        ));
        // A degenerate `$TMPDIR=/` must not exempt everything.
        assert!(!is_temp_root(
            Path::new("/Users/dev/Projects/repo"),
            Some("/"),
            None
        ));
        assert!(!is_temp_root(
            Path::new("/Users/dev/Projects/repo"),
            Some(""),
            None
        ));
    }

    #[test]
    fn temp_lookalike_is_not_temp() {
        // Path-component boundary: /tmpfoo is not under /tmp.
        assert!(!is_temp_root(Path::new("/tmpfoo/repo"), None, None));
    }

    #[test]
    #[cfg(unix)]
    fn tmpdir_env_canonicalization_mismatch_is_temp() {
        // macOS: `git rev-parse --show-toplevel` canonicalizes
        // (`/private/var/…`) while `$TMPDIR` stays `/var/folders/…` — the
        // exemption must fire anyway. Simulated with a symlinked tmpdir under
        // the non-temp scratch root (`Scratch` is imported from
        // `cadence_hooks_core::git_fixtures` at the top of this module).
        let scratch = scratch("tmpdir-canon");
        let real = scratch.path().join("real");
        let link = scratch.path().join("link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let repo_root = std::fs::canonicalize(&real).unwrap().join("repo");
        assert!(is_temp_root(&repo_root, Some(link.to_str().unwrap()), None));
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
    fn case_folded_git_verbs_are_commits() {
        // cadence-hooks#488: on a case-insensitive volume the shell runs `GIT
        // commit` as a real commit, but the gate compared against the literal
        // `git` and produced NO target — and no target means no block, so this
        // was a silent bypass of the one commit gate that has no settings-rule
        // mitigation behind it. Measured Allow before the fold.
        for spelling in [
            "GIT commit -m 'x'",
            "Git commit -m 'x'",
            "/usr/bin/GIT commit -m 'x'",
            "\\GIT commit -m 'x'",
        ] {
            assert_eq!(
                git_commit_targets(spelling, "/cwd"),
                vec!["/cwd".to_string()],
                "{spelling}"
            );
        }
        // The fold composes with the flag walk rather than replacing it: an
        // uppercase `-C` is git's own flag and stays case-SENSITIVE, because
        // folding a whole command string is what regressed `-C`/`-P`/`-S` in
        // #489. Only the verb folds.
        assert_eq!(
            git_commit_targets("GIT -C /some/worktree commit -m 'x'", "/cwd"),
            vec!["/some/worktree".to_string()]
        );
    }

    #[test]
    fn case_folded_non_commit_git_still_ignored() {
        // Folding the verb must not manufacture a target where the SUBCOMMAND
        // is not a commit — the subcommand is matched separately and is not
        // folded, since `git COMMIT` is not a command git accepts.
        assert!(git_commit_targets("GIT status", "/cwd").is_empty());
        assert!(git_commit_targets("GIT push origin main", "/cwd").is_empty());
        assert!(git_commit_targets("git COMMIT -m 'x'", "/cwd").is_empty());
        // Prose is still prose.
        assert!(git_commit_targets("echo GIT commit -m 'x'", "/cwd").is_empty());
    }

    #[test]
    fn non_leading_git_ignored() {
        // Prose and echoes are not this session committing.
        assert!(git_commit_targets("echo git commit -m 'x'", "/cwd").is_empty());
    }

    #[test]
    fn path_qualified_and_escaped_git_verbs_are_commits() {
        // #450's measured table. The first two ran a real commit and resolved
        // to Allow, because the leading word was compared to the literal
        // string `git`: `/usr/bin/git` is an ordinary scripted spelling and
        // `\git` is the standard way past a `git` alias. `command`/`env` were
        // already covered — the gap was the verb's own spelling, not the
        // prefix.
        for cmd in [
            "git commit -m x",          // positive control
            "/usr/bin/git commit -m x", // was ALLOW
            r"\git commit -m x",        // was ALLOW
            "./git commit -m x",        // was ALLOW
            "command git commit -m x",  // already BLOCK
            "env git commit -m x",      // already BLOCK
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "spelling should resolve a commit target: {cmd}"
            );
        }
    }

    #[test]
    fn double_backslash_git_is_not_a_git_verb() {
        // Exactly ONE leading backslash comes off (`strip_prefix`, never
        // `trim_start_matches`): the shell strips one and looks up `\git`, a
        // different command. A repeating strip would collapse this to `git`
        // and invent a commit — the bug caught in #442's review.
        assert!(git_commit_targets(r"\\git commit -m x", "/cwd").is_empty());
    }

    #[test]
    fn windows_git_spellings_are_commits() {
        // The CHANGELOG for #450 claimed parity with the file's other verb
        // classifiers; `basename` splits on `/` only and never dropped `.exe`,
        // so both Windows spellings fell through to ALLOW — the same silent
        // bypass the issue is about. This guard already treats Windows paths as
        // a live fail-open class (#377/#378), so they are not hypothetical.
        for cmd in [
            "git.exe commit -m x",
            "C:/tools/git.exe commit -m x",
            "C:\\tools\\git.exe commit -m x",
            "/c/git/cmd/git.exe commit -m x",
            "\"/c/Program Files/Git/cmd/git.exe\" commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "windows spelling should resolve a commit target: {cmd}"
            );
        }
        // Accepted miss, and it is the TOKENIZER's, not the verb classifier's:
        // a backslash-escaped space splits `/c/Program\ Files/…` into two
        // tokens, so the command word is `/c/Program\` before `command_word`
        // ever runs. The quoted spelling above is the one that survives
        // tokenization, and it resolves. Teaching `tokenize` about escaped
        // spaces would move a primitive several block-capable guards share.
        assert!(
            git_commit_targets("/c/Program\\ Files/Git/cmd/git.exe commit -m x", "/cwd").is_empty()
        );
    }

    #[test]
    fn escaped_package_and_file_mutators_are_seen() {
        // #450 was only half closed: the commit gate got the normalization and
        // the sibling mutation gates did not, so `\npm install` and
        // `\sed -i <file>` produced no mutation target at all — the identical
        // silent-ALLOW shape, one function over. All three now share
        // `command_word`.
        for cmd in [
            "\\npm install",
            "\\cargo add serde",
            "/usr/local/bin/npm install",
        ] {
            assert!(
                !mutation_targets(cmd, "/cwd").is_empty(),
                "escaped/path-qualified package mutation should register: {cmd}"
            );
        }
        assert!(
            !mutation_targets("\\sed -i '' s/a/b/ f.txt", "/cwd").is_empty(),
            "escaped in-place sed should register a mutation target"
        );
        // Negative control: the widening must not invent mutations.
        assert!(mutation_targets("\\\\npm install", "/cwd").is_empty());
        assert!(mutation_targets("npmx install", "/cwd").is_empty());
    }

    #[test]
    fn git_lookalike_verbs_are_not_commits() {
        // Basename matching must not widen past the verb itself: a longer name
        // ending in `git`, or a path whose DIRECTORY is named git, is not git.
        for cmd in [
            "legit commit -m x",
            "gitk commit -m x",
            "/opt/git/bin/hub commit -m x",
        ] {
            assert!(
                git_commit_targets(cmd, "/cwd").is_empty(),
                "not a git commit: {cmd}"
            );
        }
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
    fn work_tree_form_resolves_its_named_tree() {
        // Was `work_tree_form_is_skipped`, asserting the empty result the
        // `ambiguous` early return produced. That was never real ambiguity —
        // both flags name a resolvable tree, and skipping them was a bypass
        // (#378). They now resolve; a value naming no repo still fails open
        // downstream in `assess_dir`, not here.
        assert_eq!(
            git_commit_targets("git --work-tree=/other commit -m 'x'", "/cwd"),
            vec!["/other".to_string()]
        );
        assert_eq!(
            git_commit_targets("git --git-dir=/o/.git commit -m 'x'", "/cwd"),
            vec!["/o".to_string()],
            "a `<repo>/.git` value normalizes to `<repo>` so the two spellings of \
             one repo share a dismiss-map key"
        );
        // Relative values resolve against the segment's dir, like `-C` does.
        assert_eq!(
            git_commit_targets("git --work-tree=sub commit -m 'x'", "/cwd"),
            vec!["/cwd/sub".to_string()]
        );
        // BOTH are emitted when both are named — they are two different things
        // the commit mutates (the tree it reads, the repo whose HEAD advances),
        // and collapsing to one let a git-dir naming the primary slip through.
        // The git-dir is normalized `<repo>/.git` → `<repo>`.
        assert_eq!(
            git_commit_targets(
                "git --git-dir=/o/.git --work-tree=/other commit -m 'x'",
                "/cwd"
            ),
            vec!["/other".to_string(), "/o".to_string()]
        );
        // Two spellings of the SAME repo collapse to one target, so an in-chain
        // dismiss keyed on that repo matches every target the commit produces.
        assert_eq!(
            git_commit_targets(
                "git --git-dir=/other/.git --work-tree=/other commit -m 'x'",
                "/cwd"
            ),
            vec!["/other".to_string()]
        );
        // A bare repo's dir is not `<repo>/.git` and must not be stripped.
        assert_eq!(
            git_commit_targets("git --git-dir=/srv/thing.git commit -m 'x'", "/cwd"),
            vec!["/srv/thing.git".to_string()]
        );
        // A git-dir naming a LINKED worktree's admin dir is dropped, not
        // emitted: walking up from it lands on the primary and would false-block
        // the legitimate spelling.
        assert_eq!(
            git_commit_targets(
                "git --git-dir=/p/.git/worktrees/a --work-tree=/wt commit -m 'x'",
                "/cwd"
            ),
            vec!["/wt".to_string()]
        );
        // ...but a path that merely PASSES THROUGH `.git/worktrees` and resolves
        // back to the primary's own git dir must NOT be dropped. This exclusion
        // is a lexical check, and `Path::components()` preserves `..`, so every
        // spelling below matched it and dropped the primary — the guard's
        // headline control evaded by appending two characters. Each of these IS
        // `/p/.git`, hence `/p` (security review, #378).
        for cmd in [
            "git --git-dir=/p/.git/worktrees/.. commit -m 'x'",
            "git --git-dir=/p/.git/worktrees/a/../.. commit -m 'x'",
            "git --git-dir=/p/.git/worktrees/./.. commit -m 'x'",
            "git --git-dir=/p/.git//worktrees/.. commit -m 'x'",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/p".to_string()],
                "a path through .git/worktrees that resolves to the primary is not excluded: {cmd}"
            );
        }
        // Code-review finding: a token that is the VALUE of a preceding global
        // must not be re-read as a flag. `-c` consumes the next token as its
        // config string, so this names no tree and resolves to the cwd.
        assert_eq!(
            git_commit_targets("git -c --work-tree=/other commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
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
        // for this branch (issue #235). The target is normalized (lowercased,
        // forward-slash-joined) rather than passed through verbatim — every
        // emitted target goes through `normalize_target`, and on a Windows
        // build that now folds a drive-absolute path the same way
        // `lexical_normalize_folds_windows_drive_paths` proves on every
        // platform (cadence-hooks#377/#378).
        assert_eq!(
            git_commit_targets(r"git -C C:\repo\wt commit -m x", r"C:\cwd"),
            vec!["c:/repo/wt".to_string()]
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
        // A subshell is not plain (#1058): the union path judges the commit
        // from the session cwd and the cd target alike.
        assert_eq!(
            sorted_targets("(cd /wt && git commit -m x)", "/cwd"),
            vec!["/cwd", "/wt"]
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
        // `nice -n 10 git commit` — the runner's own flags are walked now
        // (cadence-hooks#1111), so the commit is seen where it runs, never
        // at a misread target.
        assert_eq!(
            git_commit_targets("nice -n 10 git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
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
        // A wrapper is not plain (#1058): the union path keeps both.
        assert_eq!(
            sorted_targets("sh -c 'cd /wt && git commit -m x'", "/cwd"),
            vec!["/cwd", "/wt"]
        );
    }

    #[test]
    fn wrapper_cd_does_not_leak_to_outer_segments() {
        // A wrapper is a child process: its `cd` never moves the parent
        // shell's cwd, so the outer commit still targets the original cwd. A
        // flat expansion (command_segments-style) would splice the child's
        // `cd /elsewhere` into the parent stream and misjudge — or, from a
        // primary checkout, silently ALLOW — the outer commit.
        // Not plain (#1058): the union path keeps the real cwd, and judges
        // the wrapper's target too.
        assert_eq!(
            sorted_targets("sh -c 'cd /elsewhere' && git commit -m x", "/cwd"),
            vec!["/cwd", "/elsewhere"]
        );
    }

    #[test]
    fn outer_cd_flows_into_wrapper() {
        // A wrapper inherits the parent's working directory at spawn.
        // Not plain (#1058): the union path keeps both.
        assert_eq!(
            sorted_targets("cd /wt && sh -c 'git commit -m x'", "/cwd"),
            vec!["/cwd", "/wt"]
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
        // Not plain (#1058): the real cwd stays a target.
        assert_eq!(
            sorted_targets(r#"echo "$(cd /elsewhere)" && git commit -m x"#, "/cwd"),
            vec!["/cwd", "/elsewhere"]
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
    fn env_with_options_commit_detected() {
        // cadence-hooks#1100: env's own options are parsed now, so the commit
        // behind them is found. `env -C <dir>` is a directory change, which
        // the union path collects.
        for cmd in [
            "env -i git commit -m x",
            "env -u FOO git commit -m x",
            "env -0v -- git commit -m x",
            "env - git commit -m x",
            "env --ignore-environment --unset=FOO git commit -m x",
            "/usr/bin/env -i GIT_AUTHOR_NAME=x git commit -m x",
        ] {
            assert_eq!(git_commit_targets(cmd, "/cwd"), vec!["/cwd"], "{cmd}");
        }
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
            sorted_targets("env exec sh -c 'cd /wt && git commit -m x'", "/cwd"),
            vec!["/cwd", "/wt"]
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
        // `||` is not plain (#1058): the union path judges both.
        assert_eq!(
            sorted_targets("cd x || exit; git commit -m 'x'", "/cwd"),
            vec!["/cwd", "/cwd/x"]
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
            sorted_targets("cd ./does-not-exist-xyz || exit; git commit -m 'x'", "/cwd"),
            vec!["/cwd", "/cwd/does-not-exist-xyz"]
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
        // be misread as the path argument. (The trailing `.` folds away in
        // `normalize_target` — same directory, one spelling.)
        assert_eq!(
            git_commit_targets("cd -P . && git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("cd -- . && git commit -m 'x'", "/cwd"),
            vec!["/cwd".to_string()]
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

    // --- #1018: `$HOME` in a cd target ---

    /// The process home, raw. Compare resolved targets against
    /// `normalize_target` of a path built from it: on Windows the resolver
    /// lowercases the drive and folds separators (`C:\Users\x` → `c:/users/x`).
    fn process_home() -> String {
        cadence_hooks_core::paths::user_home_lossy_or_default()
    }

    #[test]
    fn cd_dollar_home_expands_like_tilde() {
        // Issue #1018 row 1: `cd "$HOME/…"` fell back to the starting cwd while
        // the same target spelled `~/…` resolved. Every spelling bash expands
        // must land on the same directory the tilde form does.
        let home = process_home();
        let tilde = git_commit_targets("cd ~/src/repo-b && git commit -m x", "/cwd");
        assert_eq!(tilde, vec![normalize_target(&format!("{home}/src/repo-b"))]);
        for cmd in [
            r#"cd "$HOME/src/repo-b" && git commit -m x"#,
            "cd $HOME/src/repo-b && git commit -m x",
            r#"cd "${HOME}/src/repo-b" && git commit -m x"#,
            r#"cd "${HOME}"/src/repo-b && git commit -m x"#,
        ] {
            assert_eq!(git_commit_targets(cmd, "/cwd"), tilde, "{cmd}");
        }
        // `cd -P` is not plain (physical resolution): the union path judges
        // the session cwd too.
        let targets = git_commit_targets(r#"cd -P "$HOME/src/repo-b" && git commit -m x"#, "/cwd");
        assert!(targets.contains(&tilde[0]), "{targets:?}");
        assert_eq!(
            git_commit_targets(r#"cd "$HOME" && git commit -m x"#, "/cwd"),
            vec![normalize_target(&home)],
        );
    }

    #[test]
    fn cd_single_quoted_dollar_home_is_literal_and_stays_unresolved() {
        // `'$HOME/x'` is a literal directory named `$HOME` to bash — it must
        // never expand. The quote-stripped token text is byte-identical to the
        // double-quoted form, so this pins the quoting-context check.
        for cmd in [
            "cd '$HOME/src/repo-b' && git commit -m x",
            "cd $'$HOME/src/repo-b' && git commit -m x",
            r#"cd "$"HOME/src/repo-b && git commit -m x"#,
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn cd_dollar_home_lookalikes_stay_unresolved() {
        // Only the whole name `HOME` followed by `/` or the end is expanded;
        // anything else is another variable or an operator form this resolver
        // does not model, and keeps the pre-cd directory.
        for cmd in [
            "cd $HOMEDIR/x && git commit -m x",
            r#"cd "${HOME:-/y}/x" && git commit -m x"#,
            r#"cd "$HOME.bak" && git commit -m x"#,
            r#"cd "$SOMEVAR/x" && git commit -m x"#,
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    /// Every command in this list could leave HOME holding something other
    /// than the process home when its cd runs — or hands the cd to a child
    /// shell with its own HOME — so `$HOME` there must stay unresolved.
    const HOME_UNSAFE_PREFIXES: &[&str] = &[
        "HOME=/elsewhere; ",
        "HOME=/elsewhere && ",
        "export HOME=/elsewhere && ",
        "declare -x HOME=/elsewhere; ",
        "read -r HOME < f; ",
        "unset HOME; ",
        r#"export "H"OME=/elsewhere; "#,
        r"HO\ME=/elsewhere; ",
        r#"eval "HO""ME=/elsewhere"; "#,
        r#"n=HO; declare "${n}ME=/elsewhere"; "#,
        r#"n=HO; (( ${n}ME = 1 )); "#,
        "source ./env.sh && ",
        ". ./env.sh && ",
        // Gate-2 review Criticals: brace expansion builds the name `HOME`
        // with no `HOME` substring and no `$` anywhere in the segment.
        "export {HO,}ME=/elsewhere && ",
        "declare -x {HO,}ME=/elsewhere; ",
        "read {HO,}ME <<< /elsewhere; ",
        "mapfile -t {HO,}ME <<< /elsewhere; ",
        "f(){ export {HO,}ME=/elsewhere; }; f && ",
        "export FOO=1 && ",
        "MY_HOME=/x; ",
        "echo $(true) && ",
        "echo `true` && ",
        "echo ${X:=1} && ",
        "echo $[1] && ",
        "echo $'x' && ",
        "(true) && ",
        "{ true; } && ",
        "echo {a,b} && ",
        // Gate-2 delta review Critical: `test -v` evaluates an array
        // subscript arithmetically, assigning HOME in the running shell.
        "test -v 'a[HOME=7]'; ",
        "test -v a[HOME=7]; ",
        "[ -v 'a[HOME=7]' ]; ",
        "test -v 'a[HOME=7]' || ",
        "test -v 'a[HOME=7]' && ",
        "test -d .git && ",
    ];

    #[test]
    fn dollar_home_outside_the_allowlist_stays_unresolved() {
        // `$HOME` expands against the process home only for a command the
        // allowlist can show leaves HOME alone. Anything else keeps the pre-cd
        // directory — the pre-#1018 fail-closed fallback — so no rebinding
        // spelling, known or not, can steer the guard onto a directory the
        // command never enters.
        for prefix in HOME_UNSAFE_PREFIXES {
            for target in [r#""$HOME/wt""#, "${HOME}/wt"] {
                let cmd = format!("{prefix}cd {target} && git commit -m x");
                assert_eq!(
                    git_commit_targets(&cmd, "/cwd"),
                    vec!["/cwd".to_string()],
                    "{cmd}"
                );
            }
        }
        // A prefix assignment on the cd itself: bash expands `$HOME` BEFORE the
        // assignment applies, and this walk does not treat an assignment-led
        // segment as a cd at all — either way the process home is never
        // substituted for the rebound one.
        assert_eq!(
            git_commit_targets(
                r#"HOME=/elsewhere cd "$HOME/wt" && git commit -m x"#,
                "/cwd"
            ),
            vec!["/cwd".to_string()]
        );
    }

    #[test]
    fn dollar_home_in_a_child_shell_stays_unresolved() {
        // A child shell's HOME is whatever its launcher left it: `env -i`
        // clears it (bash then lands in `/wt`), `sudo`/`su` swap it. The child
        // never inherits the process home, even though the child's own script
        // would pass the allowlist on its own; the child starts from the
        // directory in effect at the wrapper, as every wrapped cd does.
        for cmd in [
            r#"env -i bash -c 'cd "$HOME/wt" && git commit -m x'"#,
            r#"sudo bash -c 'cd "$HOME/wt" && git commit -m x'"#,
            r#"bash -c 'cd "$HOME/wt" && git commit -m x'"#,
            r#"sh -c 'cd ${HOME}/wt && git commit -m x'"#,
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn tilde_keeps_its_process_home_resolution_outside_the_allowlist() {
        // Deliberate asymmetry: the allowlist gates `$HOME` only. `~/…` keeps
        // the resolution it always had in a command that cannot rebind HOME
        // ([`tilde_is_home`]). The prefix makes the command non-plain
        // (#1058), so the session cwd is judged too.
        let want = normalize_target(&format!("{}/wt", process_home()));
        let cmd = "export FOO=1 && cd ~/wt && git commit -m x";
        let targets = git_commit_targets(cmd, "/cwd");
        assert!(targets.contains(&want), "{cmd}: {targets:?}");
        assert!(targets.contains(&"/cwd".to_string()), "{cmd}: {targets:?}");
        // After HOME is rebound, `~` lands wherever HOME points: unreadable
        // (cadence-hooks#1113 item 3).
        let cmd = "HOME=/elsewhere; cd ~/wt && git commit -m x";
        let scan = scan_targets(cmd, "/cwd", false);
        assert!(!scan.commits.contains(&want), "{cmd}: {:?}", scan.commits);
        assert!(scan.unresolved_cd.is_some(), "{cmd}");
    }

    #[test]
    fn home_allowlist_accepts_the_ordinary_shapes() {
        // Positive controls: the ordinary shapes the fix exists for must
        // resolve, or the allowlist silently undoes it — a conventional-commit
        // message's quoted parens and a heredoc body's included.
        let want = vec![normalize_target(&format!("{}/wt", process_home()))];
        for cmd in [
            r#"cd "$HOME/wt" && git add . && git commit -m x"#,
            r#"cd "$HOME/wt" && git commit -m "fix(scope): thing {1}""#,
            r#"cd "${HOME}/wt" && echo "$HOME" && pwd && ls && git commit -m x"#,
            r#"cd $HOME/wt && true && git commit -m x"#,
            "cd \"$HOME/wt\" && git commit -F - <<'EOF'\nfix(scope): body (with parens)\nEOF",
        ] {
            assert!(command_leaves_home_alone(cmd), "{cmd}");
            assert_eq!(git_commit_targets(cmd, "/cwd"), want, "{cmd}");
        }
        // An unquoted heredoc body still expands `$((…))` in the current shell,
        // so a substitution there disqualifies even though the body is data.
        assert!(!command_leaves_home_alone(
            "cd \"$HOME/wt\" && git commit -F - <<EOF\n$((HOME=1))\nEOF"
        ));
    }

    #[test]
    fn cd_tilde_other_user_and_quoted_tilde_stay_unresolved() {
        // `~user/…` names another account's home: substituting the process
        // home would build a path that names no repo (fail-open). A quoted
        // `"~/…"` is a cwd-relative `./~/…` to bash — a directory that almost
        // never exists, so the cd fails and the commit runs in the pre-cd
        // directory; joining it instead would fail open on the nonexistent
        // path. Both keep the pre-cd directory (fail-closed from a primary).
        for cmd in [
            "cd ~bob/src/repo && git commit -m x",
            "cd ~+/x && git commit -m x",
            r#"cd "~/src/repo" && git commit -m x"#,
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn inchain_dismiss_resolves_dollar_home_cd_like_the_commit_walk() {
        // Parity: the dismiss map is keyed by the resolved target string, so
        // the in-chain scan's cd must resolve `$HOME` exactly as the commit
        // walk does, or `cd "$HOME/…" && dismiss && git commit` half-matches.
        // `cadence-hooks` is outside the HOME allowlist, so here both walks
        // must agree on leaving the `$HOME` cd unresolved.
        let cmd = r#"cd "$HOME/src/repo" && cadence-hooks guardrails dismiss-enforce-worktree --for 30m && git commit -m x"#;
        // An unreadable cd makes the command non-plain (#1058), and a
        // non-plain command with an unreadable cd licenses nothing: the
        // dismiss may have run in a directory the guard cannot name.
        let dismissed = inchain_dismissed_commits(cmd, "/cwd", false);
        let targets = git_commit_targets(cmd, "/cwd");
        assert_eq!(targets, vec!["/cwd".to_string()]);
        assert!(dismissed.is_empty(), "{dismissed:?}");
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
        // The can't-worktree coordination case names the dismiss as sanctioned
        // (#313) — not a workaround.
        assert!(msg.contains("peer-coordinated work on a shared branch"));
        assert!(msg.contains("the dismiss above is the sanctioned path"));
    }

    #[test]
    fn message_omits_redirect_note_when_same_repo() {
        let msg = block_message("/Users/dev/repo", Some("/Users/dev/repo"));
        assert!(!msg.contains("Judged against"));
    }

    #[test]
    fn message_names_redirect_when_origin_differs() {
        let msg = block_message("/Users/dev/mono", Some("/Users/dev/meta"));
        assert!(msg.contains("Judged against `/Users/dev/mono`"));
        assert!(msg.contains("/Users/dev/meta"));
        assert!(msg.contains("not `/Users/dev/meta`"));
    }

    // --- end-to-end against real repos ---
    //
    // Fixtures below are built on the promoted `Scratch` (imported above from
    // `cadence_hooks_core::git_fixtures`) via this module's own `scratch()`
    // wrapper — see that type's doc for why it's `target/`-rooted rather than
    // a tempdir.

    /// Write a repo-scoped Claude settings file declaring `env` values, for
    /// exercising `CADENCE_ALLOW_MAIN`'s target-repo-settings resolution.
    fn write_settings(repo: &Path, name: &str, body: &str) {
        let dir = repo.join(".claude");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    /// Primary repo + linked worktree under a non-temp scratch root.
    fn primary_and_worktree(scratch: &Scratch) -> (PathBuf, PathBuf) {
        let primary = scratch.path().join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        let wt = scratch.path().join("wt");
        git_in(
            &primary,
            &["worktree", "add", &wt.to_string_lossy(), "-b", "feat/x"],
        );
        (primary, wt)
    }

    #[test]
    fn edit_in_primary_blocks_and_in_worktree_allows() {
        let scratch = scratch("edit");
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
        let scratch = scratch("env");
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
        let scratch = scratch("carveouts");
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
        let scratch = scratch("snooze");
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
        let scratch = scratch("snooze-legacy");
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
        let scratch = scratch("env-bypass");
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
        let scratch = scratch("wt-nobypass");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let file = wt.join("src.rs");
        let input = edit_in(&wt, &file);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(r.bypass.is_none(), "normal worktree allow is not a bypass");
    }

    #[test]
    fn commit_in_primary_blocks_and_in_worktree_allows() {
        let scratch = scratch("commit");
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
        let scratch = scratch("cd-wt");
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
        let scratch = scratch("cd-other-primary");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.path().join("other-repo");
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
            msg.contains("Judged against"),
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
        let scratch = scratch("cd-or-true");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.path().join("other-repo");
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
        let scratch = scratch("cd-dash-p");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd -P . && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_double_dash_flag_still_blocks_from_primary() {
        let scratch = scratch("cd-double-dash");
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
        let scratch = scratch("cd-dollar-var");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd $DIR && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    /// `path` spelled through `$HOME` (`$HOME/../..<path>`), so a live fixture
    /// anywhere on disk can be reached by a `$HOME`-led cd target.
    #[cfg(unix)]
    fn via_dollar_home(path: &Path) -> String {
        let home = process_home();
        let ups = Path::new(&home)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count();
        format!("$HOME{}{}", "/..".repeat(ups), path.to_string_lossy())
    }

    #[cfg(unix)]
    #[test]
    fn cd_dollar_home_into_worktree_from_other_primary_allows() {
        // Issue #1018 row 1, live: the session starts in repo A's primary and
        // commits into repo B's worktree through a `$HOME`-led cd. Pre-fix the
        // cd was unresolved, repo A's primary was judged, and it blocked.
        let scratch = scratch("home-cd-wt");
        let (_primary, wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.path().join("other-repo");
        std::fs::create_dir(&other_primary).unwrap();
        init_repo(&other_primary);

        for cmd in [
            format!(r#"cd "{}" && git commit -m x"#, via_dollar_home(&wt)),
            format!(
                "cd {} && git commit -m x",
                via_dollar_home(&wt).replacen("$HOME", "${HOME}", 1)
            ),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(other_primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Allow, "{cmd}: {:?}", r.message);
        }
    }

    #[cfg(unix)]
    #[test]
    fn cd_dollar_home_into_primary_from_worktree_blocks() {
        // The other direction, and the one that matters for the guard: before
        // #1018 a `$HOME`-led cd from a worktree cwd was unresolved, so the
        // worktree was judged and a commit into a primary slipped through.
        let scratch = scratch("home-cd-primary");
        let (primary, wt) = primary_and_worktree(&scratch);

        let cmd = format!(r#"cd "{}" && git commit -m x"#, via_dollar_home(&primary));
        let mut input = make_bash(&cmd);
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "{cmd}");
    }

    #[cfg(unix)]
    #[test]
    fn cd_single_quoted_dollar_home_blocks_from_primary() {
        // `'$HOME/…'` is literal to bash; it must not expand into the worktree
        // and allow. It stays unresolved, so the primary is judged.
        let scratch = scratch("home-cd-squote");
        let (primary, wt) = primary_and_worktree(&scratch);

        let cmd = format!("cd '{}' && git commit -m x", via_dollar_home(&wt));
        let mut input = make_bash(&cmd);
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "{cmd}");
    }

    #[cfg(unix)]
    #[test]
    fn cd_dollar_home_after_home_rebind_blocks_from_primary() {
        // Live form of the allowlist: a command that could rebind HOME — or
        // hands the cd to a child shell — gets no process-home expansion, so the
        // `$HOME` cd stays unresolved and the primary it started in is judged.
        // Includes the gate-2 review Criticals (brace-built names, a function
        // body, `env -i`/`sudo` child shells), each of which committed into the
        // primary before the allowlist replaced the rebind denylist.
        let scratch = scratch("home-cd-rebind");
        let (primary, wt) = primary_and_worktree(&scratch);
        let target = via_dollar_home(&wt);

        for cmd in [
            format!(r#"HOME=/elsewhere; cd "{target}" && git commit -m x"#),
            format!(r#"export HOME=/elsewhere && cd "{target}" && git commit -m x"#),
            format!(r#"HOME=/elsewhere cd "{target}" && git commit -m x"#),
            format!(r#"export {{HO,}}ME=/elsewhere && cd "{target}" && git commit -m x"#),
            format!(r#"declare -x {{HO,}}ME=/elsewhere; cd "{target}" && git commit -m x"#),
            format!(r#"read {{HO,}}ME <<< /elsewhere; cd "{target}" && git commit -m x"#),
            format!(r#"mapfile -t {{HO,}}ME <<< /elsewhere; cd "{target}" && git commit -m x"#),
            format!(
                r#"f(){{ export {{HO,}}ME=/elsewhere; }}; f && cd "{target}" && git commit -m x"#
            ),
            format!(r#"env -i bash -c 'cd "{target}" && git commit -m x'"#),
            format!(r#"sudo bash -c 'cd "{target}" && git commit -m x'"#),
            format!(r#"test -v 'a[HOME=7]'; cd "{target}" && git commit -m x"#),
            format!(r#"test -v a[HOME=7]; cd "{target}" && git commit -m x"#),
            format!(r#"[ -v 'a[HOME=7]' ]; cd "{target}" && git commit -m x"#),
            format!(r#"test -v 'a[HOME=7]' || cd "{target}" && git commit -m x"#),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn unresolved_cd_block_names_the_target_and_the_literal_path_remedy() {
        // From a primary, an unreadable cd keeps blocking (letting it through would be a
        // bypass), but the block says which cd it could not read instead of
        // looking like it ignored it.
        let scratch = scratch("cd-unresolved-hint");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash(r#"cd "$SOMEVAR/x" && git commit -m x"#);
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        assert!(
            msg.contains("`cd $SOMEVAR/x` could not be resolved"),
            "{msg}"
        );
        assert!(msg.contains("git -C <path> commit"), "{msg}");

        // A block with no unreadable cd carries no such note.
        let mut input = make_bash("git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert!(!r.message.unwrap().contains("could not be resolved"));
    }

    #[test]
    fn cd_dash_previous_dir_target_blocks_judged_against_pre_cd_dir() {
        // `cd -` (go to $OLDPWD) is unknowable at guard-eval time; the pre-cd
        // directory is judged instead of a bogus "<primary>/-" path.
        let scratch = scratch("cd-dash");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd - && git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
    }

    #[test]
    fn cd_nonexistent_or_exit_takes_the_union_path() {
        // `cd <nonexistent> || exit; git commit` — in real bash the cd fails
        // (no such directory), `|| exit` fires, and the commit never runs at
        // all. `||` is not plain (#1058), and the union path does not model
        // `exit`, so the session cwd — a primary here — blocks. The `|| exit`
        // carve-out was one of the round-4 holes (`|| (exit)`, `|| return`).
        let scratch = scratch("cd-nonexistent");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("cd ./does-not-exist-xyz || exit; git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        let mut input = make_bash("cd ./does-not-exist-xyz || true; git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Block
        );
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
        let scratch = scratch("dismiss-repo");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.path().join("other-repo");
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
        // A nonexistent path → GitState resolves no repo → allow. ADR-0001:
        // the guard's own failure never blocks.
        assert!(GitState::resolve(Path::new("/nonexistent-enforce-worktree")).is_none());
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
        let scratch = scratch("cross-repo-allow-main");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let primary_b = scratch.path().join("declares-allow-main");
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
        let scratch = scratch("bash-bypass-prov");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("git commit -m 'x'");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow);
        let prov = r.bypass.expect("Bash-arm bypassed allow keeps provenance");
        assert_eq!(prov.kind, BypassKind::EnvSwitch);
        assert_eq!(prov.mechanism, "CADENCE_ALLOW_MAIN");
    }

    // --- #323: leading in-chain dismiss ---

    #[test]
    fn leading_inchain_dismiss_same_repo_allows_commit() {
        // `dismiss && git commit` in the same primary: the dismiss arms the
        // snooze before the commit runs, so the commit is allowed — and recorded
        // as an in-chain Dismissal bypass, never a bare allow.
        let scratch = scratch("inchain-same");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash(
            "cadence-hooks guardrails dismiss-enforce-worktree --for 30m \
             --reason \"peer coordination\" && git commit -m x",
        );
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "leading &&-chained in-chain dismiss allows the same-repo commit"
        );
        let prov = r.bypass.expect("in-chain dismiss records a bypass");
        assert_eq!(prov.kind, BypassKind::Dismissal);
        assert_eq!(prov.mechanism, "dismiss-enforce-worktree (in-chain)");
        assert_eq!(prov.reason.as_deref(), Some("peer coordination"));
    }

    #[test]
    fn inchain_dismiss_semicolon_connector_still_blocks() {
        // GATE RIDER: a `;` between the dismiss and the commit means the dismiss
        // might have failed at runtime with the commit still running — so the
        // snooze is not guaranteed to exist. Fail closed: still BLOCK.
        let scratch = scratch("inchain-semicolon");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash(
            "cadence-hooks guardrails dismiss-enforce-worktree --for 30m --reason x ; \
             git commit -m y",
        );
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "a `;` connector breaks the chain — commit still blocks"
        );
    }

    #[test]
    fn inchain_dismiss_different_repo_still_blocks() {
        // A dismiss `--repo B` does not license a commit landing in A.
        let scratch = scratch("inchain-diff-repo");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let primary_b = scratch.path().join("other");
        std::fs::create_dir(&primary_b).unwrap();
        init_repo(&primary_b);

        let mut input = make_bash(&format!(
            "cadence-hooks guardrails dismiss-enforce-worktree --for 30m --reason x --repo {} \
             && git commit -m y",
            primary_b.to_string_lossy()
        ));
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "dismiss for repo B does not license a commit into repo A"
        );
    }

    #[test]
    fn dismiss_after_commit_still_blocks() {
        // Order matters: a dismiss AFTER the commit cannot have armed the snooze
        // in time — the commit still blocks.
        let scratch = scratch("inchain-after");
        let (primary, _wt) = primary_and_worktree(&scratch);

        let mut input = make_bash(
            "git commit -m y && cadence-hooks guardrails dismiss-enforce-worktree \
             --for 30m --reason x",
        );
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "a dismiss ordered after the commit does not license it"
        );
    }

    #[test]
    fn dismiss_in_subshell_still_blocks() {
        // Top-level only: a dismiss buried in a `sh -c '…'` wrapper or a `$(…)`
        // substitution is not the segment's own command and does not license a
        // top-level commit.
        let scratch = scratch("inchain-subshell");
        let (primary, _wt) = primary_and_worktree(&scratch);

        for cmd in [
            "sh -c 'cadence-hooks guardrails dismiss-enforce-worktree --for 30m --reason x' \
             && git commit -m y",
            "$(cadence-hooks guardrails dismiss-enforce-worktree --for 30m --reason x) \
             && git commit -m y",
        ] {
            let mut input = make_bash(cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a dismiss in a subshell does not license the commit: {cmd}"
            );
        }
    }

    // --- #304: nested-repo commit-target attribution ---

    #[test]
    fn nested_primary_commit_attributes_to_nested_repo_not_parent() {
        // Regression lock: a `git commit` with cwd inside a NESTED independent
        // primary repo (its own `.git`, initialized inside another repo's tree)
        // must resolve to the nested repo — the block names it, not the
        // enclosing parent.
        let scratch = scratch("nested-attribution");
        let parent = scratch.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        init_repo(&parent);
        let child = parent.join("child");
        std::fs::create_dir(&child).unwrap();
        init_repo(&child);

        let mut input = make_bash("git commit -m x");
        input.cwd = Some(child.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "the nested primary blocks");
        let msg = r.message.unwrap();
        // The blocked repo is the nested `child`, not the enclosing `parent`.
        // `child`'s path is `…/parent/child`, so a "parent` is a primary"
        // phrasing can only appear if the block misattributes to the parent.
        assert!(
            msg.contains("child` is a primary checkout"),
            "block names the nested repo: {msg}"
        );
        assert!(
            !msg.contains("parent` is a primary checkout"),
            "block must not misattribute to the enclosing parent: {msg}"
        );
    }

    #[test]
    fn same_repo_edit_honors_repo_declared_allow_main() {
        let scratch = scratch("same-repo-allow-main");
        let primary = scratch.path().join("repo");
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
        let scratch = scratch("allow-main-precedence");

        // local false + shared true → Block (local wins, and it's falsy).
        let primary = scratch.path().join("local-false-shared-true");
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
        let primary = scratch.path().join("local-true-alone");
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
        let primary = scratch.path().join("shared-false");
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
        let primary = scratch.path().join("shared-zero");
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
        let primary = scratch.path().join("malformed-json");
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
        let scratch = scratch("env-wins-over-repo-falsy");
        let primary = scratch.path().join("repo");
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
        let scratch = scratch("env-wins-over-repo-truthy");
        let primary = scratch.path().join("repo");
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
        let scratch = scratch("repo-allow-memo");
        let declaring = scratch.path().join("declares");
        std::fs::create_dir(&declaring).unwrap();
        init_repo(&declaring);
        write_settings(
            &declaring,
            "settings.json",
            r#"{"env":{"CADENCE_ALLOW_MAIN":"true"}}"#,
        );
        let declaring_root = GitState::resolve(&declaring)
            .unwrap()
            .repo_root
            .to_string_lossy()
            .into_owned();

        let plain = scratch.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        init_repo(&plain);
        let plain_root = GitState::resolve(&plain)
            .unwrap()
            .repo_root
            .to_string_lossy()
            .into_owned();

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
        let scratch = scratch("cross-repo-block-message");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let primary_b = scratch.path().join("non-declaring");
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
        assert!(
            msg.contains(&primary_b_canon.to_string_lossy().to_string()),
            "message names the target repo: {msg}"
        );
        assert!(
            msg.contains("the target repo's .claude/settings.json"),
            "message points the CADENCE_ALLOW_MAIN fix at the target repo, not the origin: {msg}"
        );
    }

    // --- #238: Edit/Write enforcement scoped to the session's own checkout ---

    #[test]
    fn foreign_repo_write_allows_even_into_a_primary_on_main() {
        // The headline fix: the session sits in primary A, but the Write targets
        // a SEPARATE primary B on main (an Obsidian vault, a sibling repo, a
        // notes dir). B has no CADENCE_ALLOW_MAIN. Pre-#238 the arm judged only
        // B and blocked; now a foreign-location write is out of scope → allow.
        let scratch = scratch("foreign-write");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let foreign = scratch.path().join("foreign-repo");
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
        let scratch = scratch("foreign-parent");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let parent = scratch.path().join("parent-repo");
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
        let scratch = scratch("own-repo-block");
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
        let scratch = scratch("wt-into-primary");
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
        let scratch = scratch("primary-into-wt");
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
        let scratch = scratch("cwd-no-repo");
        let non_repo = scratch.path().join("plain");
        std::fs::create_dir(&non_repo).unwrap();
        let target = scratch.path().join("target-repo");
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
        let scratch = scratch("scope-commit-unchanged");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let other_primary = scratch.path().join("other-repo");
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
        let scratch = scratch("new-subdir");
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
        let scratch = scratch("commit-carveout");
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
        let scratch = scratch("dedup-wt");
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

    // --- #234: subprocess-mutation detection (pure parsing) ---

    #[test]
    fn package_manager_mutation_targets_cwd() {
        // A package-manager manifest mutator: cwd is the sole trigger, so the
        // representative mutation location is the effective cwd.
        assert_eq!(
            mutation_targets("uv add serde", "/cwd"),
            vec![MutationTarget::Dir("/cwd".to_string())]
        );
        for cmd in [
            "cargo add serde",
            "cargo rm serde",
            "pip install requests",
            "npm install",
            "npm i lodash",
            "npm add lodash",
            "pnpm add react",
            "poetry add httpx",
            "yarn add left-pad",
            "uv sync",
            "uv remove serde",
        ] {
            assert_eq!(
                mutation_targets(cmd, "/cwd"),
                vec![MutationTarget::Dir("/cwd".to_string())],
                "package mutator not detected: {cmd}"
            );
        }
    }

    #[test]
    fn package_manager_read_only_subcommands_are_not_mutations() {
        // Read-only / non-mutating package-manager verbs must stay silent.
        for cmd in [
            "cargo build",
            "cargo test",
            "npm run build",
            "npm ls",
            "pip list",
            "uv pip list",
            "yarn install", // yarn install (no add) is not in the v1 list
        ] {
            assert!(
                mutation_targets(cmd, "/cwd").is_empty(),
                "false mutation on read-only verb: {cmd}"
            );
        }
    }

    #[test]
    fn sed_in_place_targets_the_file() {
        assert_eq!(
            mutation_targets("sed -i s/a/b/ src/foo.rs", "/cwd"),
            vec![MutationTarget::File("/cwd/src/foo.rs".to_string())]
        );
        // `-i.bak` (suffix form) still counts as in-place.
        assert_eq!(
            mutation_targets("sed -i.bak 's/a/b/' src/foo.rs", "/cwd"),
            vec![MutationTarget::File("/cwd/src/foo.rs".to_string())]
        );
        // An absolute target stands alone.
        assert_eq!(
            mutation_targets("sed -i s/a/b/ /abs/foo.rs", "/cwd"),
            vec![MutationTarget::File("/abs/foo.rs".to_string())]
        );
    }

    #[test]
    fn sed_without_in_place_is_not_a_mutation() {
        // No `-i` → sed writes to stdout, not the file.
        assert!(mutation_targets("sed s/a/b/ src/foo.rs", "/cwd").is_empty());
    }

    #[test]
    fn sed_in_place_without_file_operand_is_not_a_mutation() {
        // Code-review finding: a bare `sed -i 's/a/b/'` with NO file operand
        // edits nothing — its sole non-flag operand is the SCRIPT, not a file.
        // A file target exists only with >= 2 non-flag operands (script + file).
        assert!(mutation_targets("sed -i s/a/b/", "/cwd").is_empty());
        assert!(mutation_targets("sed -i 's/a/b/'", "/cwd").is_empty());
        assert!(mutation_targets("sed -i.bak 's/a/b/'", "/cwd").is_empty());
        // …but the script + file form still yields the file (unchanged).
        assert_eq!(
            mutation_targets("sed -i s/a/b/ foo.rs", "/cwd"),
            vec![MutationTarget::File("/cwd/foo.rs".to_string())]
        );
    }

    #[test]
    fn tee_targets_every_operand() {
        assert_eq!(
            mutation_targets("tee out.txt", "/cwd"),
            vec![MutationTarget::File("/cwd/out.txt".to_string())]
        );
        // `-a` (append) still mutates; flags are skipped.
        assert_eq!(
            mutation_targets("tee -a out.txt", "/cwd"),
            vec![MutationTarget::File("/cwd/out.txt".to_string())]
        );
    }

    #[test]
    fn redirect_clobber_and_append_both_detected() {
        // Both `>` and `>>` are covered in v1 (proves append coverage via the
        // shared core `redirect_targets`, not the clobber-only parser).
        assert_eq!(
            mutation_targets("echo x > src/tracked.txt", "/cwd"),
            vec![MutationTarget::File("/cwd/src/tracked.txt".to_string())]
        );
        assert_eq!(
            mutation_targets("echo x >> src/tracked.txt", "/cwd"),
            vec![MutationTarget::File("/cwd/src/tracked.txt".to_string())]
        );
    }

    #[test]
    fn read_only_and_commit_segments_yield_no_mutation() {
        // A plain read, and a `git commit` (the block channel, not a mutation),
        // contribute nothing to the mutation channel.
        assert!(mutation_targets("cat src/foo.rs", "/cwd").is_empty());
        assert!(mutation_targets("git status", "/cwd").is_empty());
        assert!(mutation_targets("git commit -m x", "/cwd").is_empty());
    }

    #[test]
    fn relative_dollar_var_redirect_target_is_skipped_not_joined_to_cwd() {
        // #362: a relative `$VAR`-pathed redirect target is unresolvable — do
        // NOT join it onto the effective dir (that fabricates a false
        // in-primary location regardless of what the variable holds at
        // runtime).
        assert!(mutation_targets("cat > \"$SCRATCH/f\"", "/cwd").is_empty());
        assert!(mutation_targets("echo x > $OUT", "/cwd").is_empty());
        assert!(mutation_targets("tee \"$OUT\"", "/cwd").is_empty());
        assert!(mutation_targets("sed -i s/a/b/ \"$OUT\"", "/cwd").is_empty());
    }

    #[test]
    fn relative_backtick_redirect_target_is_skipped_not_joined_to_cwd() {
        // #362 code-review follow-up: a bare backtick-led target is the same
        // unresolvable shape as `$VAR` — `redirect_targets`/`tokenize` return
        // a leading backtick unchanged (backtick isn't in either parser's
        // break/quote set), so without this it would fall into the `else`
        // branch and get joined onto the effective dir exactly like the
        // original bug. No whitespace inside the backticks — `redirect_targets`
        // stops target collection at the first whitespace regardless of
        // quoting, so a whitespace-bearing substitution body would truncate
        // before the backtick-handling in this fix is even exercised.
        assert!(mutation_targets("cat > `whoami`.log", "/cwd").is_empty());
        assert!(mutation_targets("sed -i s/a/b/ `pwd`/f", "/cwd").is_empty());
    }

    #[test]
    fn absolute_dollar_var_component_target_still_resolves() {
        // An absolute target is unaffected by the #362 fix even when a LATER
        // path segment contains an unexpanded variable — the absolute-path
        // branch is checked first and the token (variable segment literal) is
        // used as-is, same as before.
        assert_eq!(
            mutation_targets("cat > /tmp/$SESSION/f", "/cwd"),
            vec![MutationTarget::File("/tmp/$SESSION/f".to_string())]
        );
    }

    #[test]
    fn cd_scopes_mutation_target_like_commit() {
        // A leading `cd` moves the effective dir for the mutation, exactly as
        // for a commit — reusing the same scoped walk.
        assert_eq!(
            mutation_targets("cd /wt && uv add serde", "/cwd"),
            vec![MutationTarget::Dir("/wt".to_string())]
        );
        // A file redirection is not plain (#1058): the union path nudges
        // for both directories.
        assert_eq!(
            mutation_targets("cd /wt && echo x > f", "/cwd"),
            vec![
                MutationTarget::File("/cwd/f".to_string()),
                MutationTarget::File("/wt/f".to_string())
            ]
        );
    }

    #[test]
    fn wrapper_cd_does_not_leak_to_outer_mutation() {
        // #228-safe scoping: a child `sh -c 'cd /elsewhere'` never moves the
        // parent's effective dir, so the outer redirect still targets cwd —
        // the mutation channel inherits the commit channel's cd isolation.
        // The real cwd stays a target on the union path.
        assert!(
            mutation_targets("sh -c 'cd /elsewhere' && echo x > f", "/cwd")
                .contains(&MutationTarget::File("/cwd/f".to_string()))
        );
    }

    #[test]
    fn mutation_inside_sh_c_wrapper_detected() {
        // A mutation inside a `sh -c '…'` wrapper executes — the child-script
        // recursion surfaces it, scoped to the wrapper's inherited cwd.
        assert_eq!(
            mutation_targets("sh -c 'uv add serde'", "/cwd"),
            vec![MutationTarget::Dir("/cwd".to_string())]
        );
        assert_eq!(
            mutation_targets("cd /wt && sh -c 'echo x > f'", "/cwd"),
            vec![
                MutationTarget::File("/cwd/f".to_string()),
                MutationTarget::File("/wt/f".to_string())
            ]
        );
    }

    // --- #234: subprocess-mutation nudge (end-to-end against real repos) ---

    #[test]
    fn package_mutation_in_primary_nudges_and_in_worktree_is_silent() {
        let scratch = scratch("mut-uv");
        let (primary, wt) = primary_and_worktree(&scratch);

        let mut input = make_bash("uv add serde");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Nudge,
            "uv add in the primary checkout nudges"
        );
        assert!(
            r.message.unwrap().contains("worktree"),
            "nudge names the worktree fix"
        );

        // The same in a linked worktree is not a primary checkout → silent.
        let mut input = make_bash("uv add serde");
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "uv add in a worktree is fine — not a primary checkout"
        );
    }

    #[test]
    fn sed_in_place_in_primary_nudges() {
        let scratch = scratch("mut-sed");
        let (primary, _wt) = primary_and_worktree(&scratch);
        // Same fixture gap as `redirect_into_primary_nudges_clobber_and_append`:
        // `src/foo.rs` was never created, so this asserted a nudge on a path
        // `sed -i` could not have edited. The #377 exists-gate flips that to
        // Allow. Create the file the test is about.
        std::fs::create_dir_all(primary.join("src")).unwrap();
        std::fs::write(primary.join("src/foo.rs"), "fn main() {}\n").unwrap();
        git_in(&primary, &["add", "src/foo.rs"]);
        git_in(&primary, &["commit", "-q", "-m", "add src/foo.rs"]);
        let mut input = make_bash("sed -i s/a/b/ src/foo.rs");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Nudge, "sed -i in the primary nudges");
    }

    #[test]
    fn sed_in_place_without_file_in_primary_is_silent() {
        // Code-review finding: `sed -i 's/a/b/'` with no file operand mutates
        // nothing, so it must not nudge even in the primary checkout.
        let scratch = scratch("mut-sed-nofile");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("sed -i s/a/b/");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "bare sed -i (no file operand) mutates nothing → silent"
        );
    }

    #[test]
    fn existing_tracked_file_mutations_in_primary_nudge() {
        // Security-review FIX 1: the headline case — a mutator into a file that
        // ALREADY EXISTS (the tracked file the feature is FOR). Pre-fix, feeding
        // the raw file path to `nearest_existing_ancestor` returned the FILE
        // (its own exists() short-circuits the ascent), then `git -C <file>
        // rev-parse` failed "Not a directory" → common_dir None → silent Allow.
        // The fix takes the file's `.parent()` first, mirroring `git_dir_for_input`.
        let scratch = scratch("mut-existing");
        let (primary, _wt) = primary_and_worktree(&scratch);
        // `f.txt` is committed by init_repo; add a committed nested file too.
        std::fs::create_dir_all(primary.join("src")).unwrap();
        std::fs::write(primary.join("src/foo.rs"), "fn main() {}\n").unwrap();
        git_in(&primary, &["add", "src/foo.rs"]);
        git_in(&primary, &["commit", "-q", "-m", "add src/foo.rs"]);

        for cmd in [
            "sed -i s/a/b/ src/foo.rs", // existing nested file
            "echo x > src/foo.rs",      // clobber an existing file
            "echo x >> f.txt",          // append to an existing root file
            "tee f.txt",                // tee onto an existing file
        ] {
            let mut input = make_bash(cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Nudge,
                "mutating an EXISTING tracked file must nudge: {cmd}"
            );
        }
    }

    #[test]
    fn scratch_var_redirect_in_primary_does_not_nudge() {
        // #362 end-to-end repro: a `$SCRATCH`-style heredoc redirect into a
        // legitimate out-of-tree scratch path, from a primary checkout, must
        // NOT nudge — the guard cannot know where `$SCRATCH` actually points,
        // and assuming worst-case (in-primary) was the false positive.
        let scratch = scratch("mut-scratch-var");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash(
            "SCRATCH=/tmp/scratch\ncat > \"$SCRATCH/payload.json\" <<'JSON'\n{}\nJSON\ncat \"$SCRATCH/payload.json\"",
        );
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "an unresolvable $VAR redirect target must not be assumed in-primary"
        );
    }

    #[test]
    fn redirect_into_primary_nudges_clobber_and_append() {
        let scratch = scratch("mut-redirect");
        let (primary, _wt) = primary_and_worktree(&scratch);
        // The fixture must match the test's NAME: `src/tracked.txt` has to
        // actually be a tracked file. It never was, so the assertions below
        // passed on a nonexistent path — and the #377 exists-gate flips exactly
        // that case to Allow. Creating the file restores the test's intent
        // (a redirect clobbering real tree content nudges) instead of weakening
        // the assertion to match the bug.
        std::fs::create_dir_all(primary.join("src")).unwrap();
        std::fs::write(primary.join("src/tracked.txt"), "orig\n").unwrap();
        git_in(&primary, &["add", "src/tracked.txt"]);
        git_in(&primary, &["commit", "-q", "-m", "add src/tracked.txt"]);

        let mut input = make_bash("echo x > src/tracked.txt");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Nudge, "clobber redirect nudges");

        let mut input = make_bash("echo x >> src/tracked.txt");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Nudge,
            "append redirect nudges too (>> covered in v1)"
        );
    }

    #[test]
    fn brand_new_redirect_target_does_not_nudge() {
        // #377: a redirect that CREATES a file — a scratch report, a log, a
        // JSON dump — mutates no tracked tree content, so the advisory channel
        // must stay silent. Pre-fix it nudged identically to a clobber of a
        // tracked file, and the message's "mutates tracked files in the primary
        // checkout `<repo>`" (naming only the repo) read as the guard having
        // misidentified the cwd. The `existing_tracked_file_mutations_in_primary_nudge`
        // test above is the other half of this contract: the loosening stops here.
        let scratch = scratch("mut-brand-new");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("git diff > report.txt");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a redirect creating a brand-new file mutates nothing tracked → silent"
        );
    }

    #[test]
    fn mutation_nudge_message_names_the_path() {
        // #377's second defect: the message named only the repo, so a reader
        // could not tell WHICH path the walk had resolved — the whole reason the
        // reporter inferred a wrong-cwd bug. It must name the path, and it must
        // not claim the target is "tracked" (the walk never asks git that).
        let scratch = scratch("mut-msg-path");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("echo x >> f.txt");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains("f.txt"), "message names the path: {msg}");
        assert!(
            !msg.contains("tracked files"),
            "message drops the unverified `tracked` claim: {msg}"
        );
    }

    #[test]
    fn work_tree_flag_commit_into_primary_blocks() {
        // #378: `--work-tree` names the checkout being mutated as plainly as a
        // `-C` does. It used to set the `ambiguous` flag and skip the check —
        // a MISS dressed as a fail-open, and a real bypass from a worktree.
        let scratch = scratch("cw-work-tree");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        for cmd in [
            format!("git --work-tree={p} commit -m x"),
            format!("git --work-tree {p} commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "--work-tree into the primary must block: {cmd}"
            );
        }
    }

    #[test]
    fn git_dir_flag_commit_into_primary_blocks() {
        // Same bypass via `--git-dir`. No `.git`-stripping is needed: GitState
        // resolves `<repo>/.git` back to `<repo>`.
        let scratch = scratch("cw-git-dir");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        for cmd in [
            format!("git --git-dir={p}/.git commit -m x"),
            format!("git --git-dir {p}/.git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "--git-dir into the primary must block: {cmd}"
            );
        }
    }

    #[test]
    fn git_env_prefix_commit_into_primary_blocks() {
        // The env spelling of the same redirect. `skip_transparent_prefixes`
        // discards assignment words so the leading-word gate sees `git` (#228);
        // `git_env_overrides` now reads the two that name a tree before they go.
        let scratch = scratch("cw-git-env");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        for cmd in [
            format!("GIT_DIR={p}/.git GIT_WORK_TREE={p} git commit -m x"),
            format!("GIT_WORK_TREE={p} git commit -m x"),
            format!("GIT_DIR={p}/.git git commit -m x"),
            // Interleaved with a transparent prefix and an unrelated assignment.
            format!("env FOO=1 GIT_WORK_TREE={p} command git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a git env prefix naming the primary must block: {cmd}"
            );
        }
    }

    #[test]
    fn explicit_flags_outrank_git_env_prefix() {
        // git's own precedence: an explicit flag overrides its OWN env var.
        // Pins that ordering AND proves the tightening did not create a false
        // block — GIT_WORK_TREE names the primary, but the explicit flag wins
        // and the commit really lands in the worktree, so it must be allowed.
        //
        // Deliberately no `GIT_DIR` here. An earlier version of this test set
        // GIT_DIR=<primary>/.git alongside and still asserted Allow, which was
        // wrong: with the repo dir pointed at the primary, that commit advances
        // the PRIMARY's HEAD and index. `git_dir_naming_primary_blocks_even_with_a_work_tree`
        // below now pins that case as a Block (security review, #378).
        let scratch = scratch("cw-env-precedence");
        let (primary, wt) = primary_and_worktree(&scratch);
        let (p, w) = (primary.to_string_lossy(), wt.to_string_lossy());
        let cmd = format!("GIT_WORK_TREE={p} git --work-tree={w} commit -m x");
        let mut input = make_bash(&cmd);
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "an explicit --work-tree outranks GIT_WORK_TREE: {cmd}"
        );
    }

    #[test]
    fn git_dir_naming_primary_blocks_even_with_a_work_tree() {
        // A commit reads its tree from --work-tree but advances HEAD and the
        // index in --git-dir's repository. Ranking work-tree above git-dir and
        // returning ONE target dropped the git-dir entirely, so this mutated the
        // primary and Allowed. Both targets are emitted now.
        let scratch = scratch("cw-gitdir-both");
        let (primary, wt) = primary_and_worktree(&scratch);
        let (p, w) = (primary.to_string_lossy(), wt.to_string_lossy());
        for cmd in [
            format!("git --git-dir={p}/.git --work-tree={w} commit -m x"),
            format!("GIT_DIR={p}/.git git --work-tree={w} commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a git-dir naming the primary must block regardless of work-tree: {cmd}"
            );
        }
    }

    #[test]
    fn relative_git_env_resolves_after_the_dash_c_chdir() {
        // THE regression this pass exists to catch. git applies the `-C` chdir
        // BEFORE repository setup, so a relative env value is relative to the
        // POST-`-C` directory. Resolving it against the pre-`-C` dir while it
        // outranked the `-C` redirect made this Allow while git committed into
        // the primary — a bypass the branch itself introduced, and one every
        // absolute-path env test missed (security review, #378).
        let scratch = scratch("cw-rel-env");
        let (primary, wt) = primary_and_worktree(&scratch);
        let (p, w) = (primary.to_string_lossy(), wt.to_string_lossy());

        for cmd in [
            format!("GIT_WORK_TREE=. git -C {p} commit -m x"),
            format!("GIT_DIR=.git git -C {p} commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a relative git env var resolves against the -C target: {cmd}"
            );
        }

        // Mirror direction — the false block. From the primary, `-C <worktree>`
        // with a relative env value lands in the worktree, so it must allow.
        for cmd in [
            format!("GIT_WORK_TREE=. git -C {w} commit -m x"),
            format!("GIT_DIR=.git git -C {w} commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "a relative env value under -C <worktree> is not a primary commit: {cmd}"
            );
        }
    }

    #[test]
    fn inchain_dismiss_covers_every_target_a_commit_emits() {
        // Emitting BOTH a work-tree and a git-dir target reopened the parity
        // hazard from the other side: the dismiss map is keyed by target string,
        // so a chain dismissing `<repo>` matched the work-tree target and missed
        // the `<repo>/.git` one, and the undismissed half blocked a chain the
        // user had explicitly licensed. Normalizing `<repo>/.git` → `<repo>`
        // collapses them; this pins that a dismiss still covers the commit.
        let scratch = scratch("cw-dismiss-parity");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        let dismiss =
            format!("cadence-hooks guardrails dismiss-enforce-worktree --for 30m --repo {p}");

        for tail in [
            format!("GIT_WORK_TREE={p} GIT_DIR={p}/.git git commit -m x"),
            format!("git --git-dir={p}/.git --work-tree={p} commit -m x"),
        ] {
            let mut input = make_bash(&format!("{dismiss} && {tail}"));
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "an in-chain dismiss must cover every target the commit emits: {tail}"
            );

            // GATE RIDER intact: a `;` breaks the chain and it blocks again.
            let mut input = make_bash(&format!("{dismiss} ; {tail}"));
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a non-&& connector still fails closed: {tail}"
            );
        }
    }

    #[test]
    fn dot_dot_through_worktrees_admin_dir_still_blocks() {
        // End-to-end form of the exclusion evasion: `<primary>/.git/worktrees/..`
        // IS `<primary>/.git`, and with no --work-tree git takes the cwd as the
        // tree — so this commits the worktree's files onto the PRIMARY's branch.
        // The exclusion dropped the git-dir target and the walk fell through to
        // the session's own worktree, yielding Allow.
        let scratch = scratch("cw-dotdot-evade");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        for cmd in [
            format!("git --git-dir={p}/.git/worktrees/.. commit -m x"),
            format!("git --git-dir={p}/.git/worktrees/./.. commit -m x"),
            format!("GIT_DIR={p}/.git/worktrees/.. git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a `..` through the worktrees dir resolves to the primary: {cmd}"
            );
        }

        // The exclusion itself still works — a REAL linked-worktree admin dir
        // must stay dropped, or this fix trades a bypass for a false block.
        let admin = format!("{p}/.git/worktrees/feat-x");
        let cmd = format!(
            "git --git-dir={admin} --work-tree={} commit -m x",
            wt.to_string_lossy()
        );
        let mut input = make_bash(&cmd);
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a genuine linked-worktree admin dir is still not the primary: {cmd}"
        );
    }

    #[test]
    fn lexical_normalize_folds_without_touching_the_filesystem() {
        assert_eq!(lexical_normalize("/p/.git/worktrees/.."), "/p/.git");
        assert_eq!(lexical_normalize("/p/.git//worktrees/../.."), "/p");
        assert_eq!(lexical_normalize("/p/./sub/"), "/p/sub");
        assert_eq!(lexical_normalize("/p/"), "/p");
        // `/..` is `/`, not an escape above the root.
        assert_eq!(lexical_normalize("/.."), "/");
        // A leading run of `..` in a RELATIVE path has nothing to pop and must
        // survive, or the path would silently change meaning.
        assert_eq!(lexical_normalize("../sibling"), "../sibling");
        // `..` never pops a `..`.
        assert_eq!(lexical_normalize("../../x"), "../../x");
        // Nothing survives a relative fold — the caller's spelling is kept
        // rather than invented into a `.`.
        assert_eq!(lexical_normalize("a/.."), "a/..");
        // `<repo>/.git` collapses; a bare repo's own dir does not.
        assert_eq!(normalize_target("/p/.git"), "/p");
        assert_eq!(normalize_target("/p/.git/"), "/p");
        assert_eq!(normalize_target("/srv/thing.git"), "/srv/thing.git");
        // SEPARATOR INVARIANT. Every target here is a shell path, so the fold
        // must emit `/` on every platform. Collecting into a `PathBuf` re-joins
        // with the platform separator and returned `\p\.git` on Windows, which
        // silently stopped every normalized target matching the un-normalized
        // ones — the dismiss map is keyed on these strings. Asserted rather
        // than left to a doc comment, because the failure is invisible on the
        // developer's own machine.
        for spelling in [
            "/p/.git/worktrees/..",
            "/p/./sub/",
            "/p//q/../r",
            "../sibling",
        ] {
            let folded = lexical_normalize(spelling);
            assert!(
                !folded.contains('\\'),
                "fold must stay a shell path on every platform: {spelling} -> {folded}"
            );
        }
    }

    #[test]
    fn lexical_normalize_folds_windows_drive_paths() {
        // Platform-INDEPENDENT: the fold decides absoluteness and splits
        // segments from the STRING alone, so these assert the same result on
        // macOS/Linux CI as on a real Windows runner — the Windows fail-open
        // (cadence-hooks#377/#378) was only reproducible on Windows before
        // this fix, because `absolute` used to be a bare `path.starts_with('/')`
        // and splitting ran on `/` alone, both blind to a `C:\…` prefix.
        assert_eq!(
            lexical_normalize("C:\\p\\.git\\worktrees\\.."),
            "c:/p/.git",
            "a `..` through the worktrees dir must fold on a Windows path too"
        );
        // Drive letter is lowercased — NTFS/ReFS is case-insensitive, so two
        // spellings of the same path must fold to the same string or the
        // in-chain dismiss map's equality lookup silently stops matching one.
        assert_eq!(
            lexical_normalize("C:\\Primary\\.git"),
            lexical_normalize("c:\\primary\\.git"),
        );
        // A `..` right after the drive root stays at the root, mirroring
        // POSIX `/..` == `/`.
        assert_eq!(lexical_normalize("C:\\.."), "c:/");
        // The exact shape this crate's own Windows CI fixture produces:
        // `Path::join("../../target/…")` on `CARGO_MANIFEST_DIR` embeds a
        // real `..` inside an otherwise backslash-separated native path. The
        // drive letter must survive the fold — the pre-fix code treated the
        // whole `D:\a\...\guardrails\..` prefix as ONE opaque segment (no `/`
        // in it), so the following literal `..` popped that entire prefix,
        // including the drive letter, producing a relative fragment that
        // resolved to no repo and let every enforce-worktree test on Windows
        // read Allow instead of Block.
        assert_eq!(
            lexical_normalize(
                "D:\\a\\cadence-hooks\\cadence-hooks\\crates\\guardrails\\../../target/enforce-worktree-scratch\\commit-1\\repo"
            ),
            "d:/a/cadence-hooks/cadence-hooks/target/enforce-worktree-scratch/commit-1/repo",
        );
        // A POSIX path carrying a literal backslash in a filename (legal on
        // POSIX filesystems) must NOT be treated as a separator — that
        // splitting is scoped to paths a Windows drive prefix already
        // identified as native Windows.
        assert_eq!(lexical_normalize("/tmp/weird\\name"), "/tmp/weird\\name");
    }

    #[test]
    fn is_shell_absolute_recognizes_windows_drive_paths_on_every_platform() {
        // Was `Path::new(path).is_absolute()` on the fallback branch, which is
        // only drive-letter-aware when this binary is compiled for Windows —
        // so the same assertion passed on a Windows runner and failed
        // everywhere else. `looks_absolute` makes the primary check
        // string-based, so it holds on every platform.
        assert!(is_shell_absolute("C:\\Users\\x"));
        assert!(is_shell_absolute("C:/Users/x"));
        assert!(is_shell_absolute("/posix/path"));
        assert!(!is_shell_absolute("relative\\path"));
    }

    #[test]
    fn git_commit_targets_folds_a_windows_dash_c_redirect() {
        // End-to-end through the real parsing chain (`commit_targets_of` ->
        // `resolve_git_path` -> `normalize_target` -> `lexical_normalize`) with
        // a Windows-native `-C` value, mirroring what a `-C D:\…` typed at a
        // native (non-Git-Bash) Windows shell looks like on the wire.
        assert_eq!(
            git_commit_targets("git -C D:\\wt commit -m 'x'", "/cwd"),
            vec!["d:/wt".to_string()]
        );
        // The commit fallback target (no explicit flag) is the raw `cwd` —
        // exactly the shape of the FIRST assertion in
        // `commit_in_primary_blocks_and_in_worktree_allows`, the simplest of
        // the 26 tests the Windows fail-open broke.
        assert_eq!(
            git_commit_targets("git commit -m 'x'", "C:\\primary"),
            vec!["c:/primary".to_string()]
        );
    }

    #[test]
    fn dismiss_reaches_targets_only_the_full_walk_can_see() {
        // The dismiss walk used to re-implement commit detection, so it stopped
        // matching the moment `collect_targets` learned something it hadn't —
        // here, inheriting a git env prefix into a wrapper's child. The user's
        // own dismiss then failed to license the commit it was run for, and the
        // block pointed at the dismiss they had just executed.
        let scratch = scratch("cw-dismiss-reach");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        let dismiss =
            format!("cadence-hooks guardrails dismiss-enforce-worktree --for 30m --repo {p}");

        for tail in [
            format!("GIT_WORK_TREE={p} sh -c 'git commit -m x'"),
            format!("git --work-tree={p}/ commit -m x"),
            format!("git --git-dir={p}/.git commit -m x"),
        ] {
            let mut input = make_bash(&format!("{dismiss} && {tail}"));
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "a dismiss must license every target the commit walk can see: {tail}"
            );
        }

        // A `--repo` spelled as the repo's git dir keys the same repository.
        let cmd = format!(
            "cadence-hooks guardrails dismiss-enforce-worktree --for 30m --repo {p}/.git \
             && git --git-dir={p}/.git commit -m x"
        );
        let mut input = make_bash(&cmd);
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "--repo <p>/.git keys <p>: {cmd}");

        // A dismiss buried in a WRAPPER is still not honored — commit detection
        // recurses, dismiss detection deliberately does not.
        let cmd = format!("sh -c '{dismiss}' && git --work-tree={p} commit -m x");
        let mut input = make_bash(&cmd);
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "a dismiss inside a wrapper does not arm the snooze: {cmd}"
        );

        // And a dismiss for a DIFFERENT repo must not license this one.
        let other = scratch.path().join("other");
        std::fs::create_dir(&other).unwrap();
        init_repo(&other);
        let cmd = format!(
            "cadence-hooks guardrails dismiss-enforce-worktree --for 30m --repo {} \
             && git --work-tree={p} commit -m x",
            other.to_string_lossy()
        );
        let mut input = make_bash(&cmd);
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "a dismiss for another repo does not over-license: {cmd}"
        );
    }

    #[test]
    fn git_env_prefix_is_inherited_by_a_wrapper_child() {
        // The shell exports an assignment-word prefix into the child, so
        // `GIT_WORK_TREE=<primary> sh -c 'git commit'` really does commit into
        // the primary. The per-segment capture never reached the child script
        // recursion (security review, #378).
        let scratch = scratch("cw-env-child");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();
        for cmd in [
            format!("GIT_WORK_TREE={p} sh -c 'git commit -m x'"),
            format!("GIT_DIR={p}/.git bash -c 'git commit -m x'"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Block,
                "a git env prefix reaches the wrapper's child: {cmd}"
            );
        }
    }

    #[test]
    fn repeated_dash_c_accumulates_like_git() {
        // git documents each subsequent non-absolute `-C <path>` as relative to
        // the preceding one. The walk used to OVERWRITE, so `-C <primary> -C .`
        // resolved against the session cwd (the worktree) and allowed.
        let scratch = scratch("cw-multi-c");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy();

        let targets = git_commit_targets(
            &format!("git -C {p} -C . commit -m x"),
            &wt.to_string_lossy(),
        );
        assert_eq!(
            targets,
            vec![lexical_normalize(&p)],
            "the second -C resolves against the first, not the session cwd"
        );
        assert_ne!(
            targets,
            vec![lexical_normalize(&wt.to_string_lossy())],
            "and specifically NOT against the session cwd"
        );

        let mut input = make_bash(&format!("git -C {p} -C . commit -m x"));
        input.cwd = Some(wt.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block, "accumulated -C lands in primary");
    }

    #[test]
    fn work_tree_pointing_at_a_worktree_from_primary_allows() {
        // THE false-block guard on this tightening. Sitting in the primary and
        // committing into a linked worktree by flag is exactly what the guard
        // wants people to do — it must not block, by any of the four spellings.
        let scratch = scratch("cw-false-block");
        let (primary, wt) = primary_and_worktree(&scratch);
        let w = wt.to_string_lossy();
        for cmd in [
            format!("git --work-tree={w} commit -m x"),
            format!("git --work-tree {w} commit -m x"),
            format!("git --git-dir={w}/.git commit -m x"),
            format!("GIT_WORK_TREE={w} git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "committing into a worktree FROM the primary must not block: {cmd}"
            );
        }
    }

    #[test]
    fn unresolvable_work_tree_fails_open() {
        // ADR-0001: the guard resolves the named tree instead of skipping, but a
        // value that names no repo still Allows — `assess_dir` fails open when
        // GitState finds nothing there. Resolving is not the same as guessing.
        let scratch = scratch("cw-unresolvable");
        let (_primary, wt) = primary_and_worktree(&scratch);
        for cmd in [
            "git --work-tree=/nonexistent/x commit -m x",
            "git --git-dir=/nonexistent/x/.git commit -m x",
        ] {
            let mut input = make_bash(cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "an unresolvable target fails open: {cmd}"
            );
        }
    }

    #[test]
    fn redirect_into_temp_is_silent() {
        // A redirect whose target is outside the session's repo (a `/tmp`
        // scratch file) is out of scope — no nudge.
        let scratch = scratch("mut-redirect-temp");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("echo x > /tmp/scratch-234-probe");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a redirect into /tmp is a foreign target → silent"
        );
    }

    #[test]
    fn mutation_then_commit_in_primary_still_blocks_no_double_fire() {
        // Composition contract: block-first. `uv add && git commit` into the
        // primary BLOCKS on the commit — the mutation nudge never fires.
        let scratch = scratch("mut-and-commit");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("uv add serde && git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "commit wins — block-first, no nudge double-fire"
        );
    }

    #[test]
    fn foreign_repo_mutation_is_silent() {
        // A mutation whose effective cwd resolves into a DIFFERENT repo than the
        // session's own is a foreign drop → silent, mirroring the Edit/Write arm.
        let scratch = scratch("mut-foreign");
        let (primary_a, _wt) = primary_and_worktree(&scratch);
        let foreign = scratch.path().join("foreign-repo");
        std::fs::create_dir(&foreign).unwrap();
        init_repo(&foreign);

        // Relative `cd` (not the absolute fixture path): a Windows fixture path
        // interpolated here is `C:\…\foreign-repo`, whose backslashes bash
        // treats as escapes, so the `cd` silently fails on Git Bash and the
        // mutation resolves back in the session's own repo → false nudge on
        // windows-latest. `../foreign-repo` is separator-agnostic and resolves
        // against the effective cwd (`primary_a` == `<scratch>/repo`) → the
        // sibling `<scratch>/foreign-repo` on every platform.
        let mut input = make_bash("cd ../foreign-repo && uv add serde");
        input.cwd = Some(primary_a.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a mutation in a foreign repo is out of scope → silent"
        );
    }

    #[test]
    fn mutation_suppressions_silence_the_nudge() {
        let scratch = scratch("mut-suppress");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let bash_uv = |dir: &Path| {
            let mut input = make_bash("uv add serde");
            input.cwd = Some(dir.to_string_lossy().into_owned());
            input
        };

        // CADENCE_ALLOW_MAIN → silent.
        let r = run_enforce(&bash_uv(&primary), &cfg(true, false));
        assert_eq!(r.outcome, Outcome::Allow, "CADENCE_ALLOW_MAIN silences");

        // CADENCE_NO_ENFORCE_WORKTREE kill switch → silent.
        let r = run_enforce(&bash_uv(&primary), &cfg(false, true));
        assert_eq!(r.outcome, Outcome::Allow, "kill switch silences");

        // Active snooze → silent.
        let marker = dismiss_enforce_worktree::marker_path_for(&primary).unwrap();
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        std::fs::write(&marker, format!("{until}\n")).unwrap();
        let r = run_enforce(&bash_uv(&primary), &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Allow, "active snooze silences");
    }

    #[test]
    fn read_only_command_in_primary_is_silent() {
        let scratch = scratch("mut-readonly");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("cat src/foo.rs && git status");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "a read-only command never nudges"
        );
    }

    // --- #309: bootstrap-commit exemption (unborn HEAD) ---

    /// A fresh `git init`'d repo on a feature branch with **no commit yet** —
    /// the bootstrap / unborn-HEAD state. `.git` is a directory so
    /// `is_primary_checkout` is true, but `rev-list --all` counts zero, so the
    /// block's own remedy (`git worktree add -b <b>`) is impossible.
    fn init_commitless_repo(dir: &Path) {
        git_in(dir, &["init", "-q", "-b", "feat/x"]);
        git_in(dir, &["config", "user.email", "t@t"]);
        git_in(dir, &["config", "user.name", "t"]);
    }

    #[test]
    fn commitless_primary_exempts_edit_commit_and_mutation_arms() {
        // The fix: a commitless (unborn-HEAD) primary is exempt on ALL THREE
        // arms — one carve-out in `assess_dir` covers Edit/Write, the Bash
        // commit channel, and the mutation-nudge channel.
        let scratch = scratch("bootstrap-exempt");
        let repo = scratch.path().join("fresh");
        std::fs::create_dir(&repo).unwrap();
        init_commitless_repo(&repo);

        // (a) Edit arm — editing the first file in the bootstrap checkout.
        let input = edit_in(&repo, &repo.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "Edit in a commitless primary is exempt"
        );
        assert!(
            r.bypass.is_none(),
            "the bootstrap exemption is a plain allow, not a bypass-log entry"
        );

        // (b) Bash commit arm — the bootstrap `git commit` MUST land here.
        let mut input = make_bash("git add -A && git commit -m init");
        input.cwd = Some(repo.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Allow,
            "the bootstrap commit in a commitless primary is exempt"
        );
        assert!(r.bypass.is_none(), "commit-arm exemption is a plain allow");

        // (c) Mutation-nudge arm — a subprocess mutation in a commitless
        //     primary produces NO nudge (a fresh repo also can't worktree a
        //     pre-commit `sed -i`/redirect/`uv add`).
        for cmd in [
            "uv add serde",
            "sed -i s/a/b/ src/foo.rs",
            "echo x > src/tracked.txt",
        ] {
            let mut input = make_bash(cmd);
            input.cwd = Some(repo.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(
                r.outcome,
                Outcome::Allow,
                "mutation nudge is suppressed in a commitless primary: {cmd}"
            );
        }
    }

    #[test]
    fn one_commit_ends_the_bootstrap_exemption() {
        // Narrowness control: the exemption is specific to commitless, not a
        // blanket allow — the very first commit re-arms the block.
        let scratch = scratch("bootstrap-narrow");
        let repo = scratch.path().join("fresh");
        std::fs::create_dir(&repo).unwrap();
        init_commitless_repo(&repo);

        let input = edit_in(&repo, &repo.join("src.rs"));
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Allow,
            "commitless → exempt"
        );

        // Land the first commit; the exemption must evaporate.
        std::fs::write(repo.join("f.txt"), "x").unwrap();
        git_in(&repo, &["add", "f.txt"]);
        git_in(&repo, &["commit", "-q", "-m", "init"]);
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "the first commit re-arms the block — exemption is commitless-only"
        );
    }

    #[test]
    fn orphan_head_established_repo_still_blocks() {
        // Security regression (the load-bearing case): a repo WITH commits
        // forced to unborn-HEAD via `git checkout --orphan` still has its
        // commits reachable from the original branch, so a worktree IS still
        // possible — the block MUST stand. The predicate keys on "any commit
        // anywhere", not the current HEAD.
        let scratch = scratch("bootstrap-orphan");
        let primary = scratch.path().join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        git_in(&primary, &["checkout", "-q", "--orphan", "tmp-orphan"]);

        // Bash commit arm.
        let mut input = make_bash("git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "orphan-HEAD with reachable commits still blocks (commit arm)"
        );

        // Edit arm.
        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "orphan-HEAD with reachable commits still blocks (edit arm)"
        );
    }

    #[test]
    fn head_deleted_established_repo_still_blocks() {
        // The `git update-ref -d HEAD` sibling of the orphan case: HEAD's own
        // ref is deleted (current HEAD unborn) but a surviving `other` ref
        // still holds the commit → a worktree is possible off `other` → the
        // block MUST stand.
        let scratch = scratch("bootstrap-updateref");
        let primary = scratch.path().join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        git_in(&primary, &["branch", "other"]); // second ref keeps the commit
        git_in(&primary, &["update-ref", "-d", "HEAD"]); // delete HEAD's branch → unborn HEAD

        let mut input = make_bash("git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "HEAD-deleted repo with a surviving ref still blocks"
        );
    }

    #[test]
    fn detached_head_primary_still_blocks() {
        // Detached-HEAD control: commits exist and HEAD resolves to a sha
        // (`Value(<sha>)`), so the repo is NOT commitless — proves the
        // exemption keys on *zero commits*, not on any HEAD-resolution quirk.
        let scratch = scratch("bootstrap-detached");
        let primary = scratch.path().join("repo");
        std::fs::create_dir(&primary).unwrap();
        init_repo(&primary);
        git_in(&primary, &["checkout", "-q", "--detach", "HEAD"]);

        let input = edit_in(&primary, &primary.join("src.rs"));
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(
            r.outcome,
            Outcome::Block,
            "detached-HEAD primary (commits exist) still blocks"
        );
    }

    #[test]
    fn is_commitless_probe_true_only_for_zero_commits() {
        // Probe unit: true for a fresh `git init`; false after a commit; false
        // on an established repo forced to orphan-HEAD (commits still exist).
        // Each fixture uses a fresh `GitProbe` so the memo never masks the
        // per-repo answer.
        let scratch = scratch("bootstrap-probe");

        let fresh = scratch.path().join("fresh");
        std::fs::create_dir(&fresh).unwrap();
        init_commitless_repo(&fresh);
        assert!(
            GitProbe::default().is_commitless(&fresh),
            "a fresh git init is commitless"
        );

        let committed = scratch.path().join("committed");
        std::fs::create_dir(&committed).unwrap();
        init_repo(&committed);
        assert!(
            !GitProbe::default().is_commitless(&committed),
            "a committed repo is not commitless"
        );

        let orphan = scratch.path().join("orphan");
        std::fs::create_dir(&orphan).unwrap();
        init_repo(&orphan);
        git_in(&orphan, &["checkout", "-q", "--orphan", "tmp-orphan"]);
        assert!(
            !GitProbe::default().is_commitless(&orphan),
            "orphan-HEAD established repo is NOT commitless (commits survive on other refs)"
        );
    }

    // --- cd recognition and cd outcome (#1057, #1058) ---

    #[test]
    fn cd_behind_builtin_command_assignment_or_keyword_is_a_cd() {
        // Each of these moves the shell running the command (measured under
        // bash), so a commit after it runs in `/wt` (cadence-hooks#1057).
        for cmd in [
            "builtin cd /wt && git commit -m x",
            "command cd /wt && git commit -m x",
            "command -p cd /wt && git commit -m x",
            "command builtin cd /wt && git commit -m x",
            r"bu\iltin cd /wt && git commit -m x",
            "FOO=1 cd /wt && git commit -m x",
            "FOO=1 BAR=2 builtin cd /wt && git commit -m x",
            r"\cd /wt && git commit -m x",
            r#""cd" /wt && git commit -m x"#,
            "time cd /wt && git commit -m x",
            "time -p cd /wt && git commit -m x",
            "! cd /wt; git commit -m x",
            ">/dev/null cd /wt && git commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/wt".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn external_or_quoted_prefix_cd_is_not_a_cd() {
        // An external `cd` binary runs in a child process and cannot move
        // this shell; a quoted assignment or keyword is a command NAME, so the
        // cd behind it never runs (cadence-hooks#1057).
        for cmd in [
            "env cd /wt; git commit -m x",
            "exec cd /wt; git commit -m x",
            "nohup cd /wt; git commit -m x",
            "sudo cd /wt; git commit -m x",
            r"\time cd /wt; git commit -m x",
            "command -v cd /wt; git commit -m x",
            "echo cd /wt; git commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
        // A quoted `time` or assignment in front is a command NAME too, but
        // the plain gate reads the words unquoted and cannot tell, so these
        // take the union path — the session cwd is still judged.
        for cmd in [
            r#""time" cd /wt; git commit -m x"#,
            r#""FOO=1" cd /wt; git commit -m x"#,
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
    }

    #[test]
    fn cd_behind_an_assignment_to_a_variable_cd_reads_is_unresolved() {
        for cmd in [
            "CDPATH=/elsewhere cd wt; git commit -m x",
            "HOME=/elsewhere cd ~; git commit -m x",
            "OLDPWD=/elsewhere cd -; git commit -m x",
            "PWD=/elsewhere cd ..; git commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn subshell_cd_does_not_persist_past_the_subshell() {
        // Subshells, groups and substitutions are not plain (#1058): the union
        // path judges the session cwd and every cd target.
        for (cmd, want) in [
            ("(cd /wt); git commit -m x", vec!["/cwd", "/wt"]),
            ("(cd /wt && true); git commit -m x", vec!["/cwd", "/wt"]),
            ("( (cd /wt); git commit -m x )", vec!["/cwd", "/wt"]),
            (
                "(cd /wt; (cd /a); git commit -m x)",
                vec!["/a", "/cwd", "/wt"],
            ),
            ("(cd /wt && git commit -m x)", vec!["/cwd", "/wt"]),
            ("{ cd /wt; }; git commit -m x", vec!["/cwd", "/wt"]),
            ("echo $(cd /wt; pwd); git commit -m x", vec!["/cwd", "/wt"]),
            (
                "git -C \"$(cd /wt; pwd)\" log; git commit -m x",
                vec!["/cwd", "/wt"],
            ),
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), want, "{cmd}");
        }
    }

    #[test]
    fn cd_dash_returns_to_the_dir_the_last_cd_left() {
        for (cmd, want) in [
            ("cd /wt && cd - && git commit -m x", vec!["/cwd"]),
            ("cd /a && cd /b && cd - && git commit -m x", vec!["/a"]),
            ("cd /a && cd - && cd - && git commit -m x", vec!["/a"]),
            // Before any cd here, `$OLDPWD` is the session's: unreadable, so
            // not plain — and the union path reports it.
            ("cd - && git commit -m x", vec!["/cwd"]),
            ("(cd /a); cd - && git commit -m x", vec!["/a", "/cwd"]),
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), want, "{cmd}");
        }
        assert!(
            scan_targets("cd - && git commit -m x", "/cwd", false)
                .unresolved_cd
                .is_some()
        );
    }

    #[test]
    fn glob_brace_and_expansion_cd_targets_are_unresolved() {
        for cmd in [
            "cd /w[t] && git commit -m x",
            "cd /w* && git commit -m x",
            "cd /w? && git commit -m x",
            "cd /{wt,x} && git commit -m x",
            "cd /wt$SUFFIX && git commit -m x",
            "cd /wt`true` && git commit -m x",
            "cd ~/w* && git commit -m x",
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec!["/cwd".to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn cd_operand_count_options_and_redirections() {
        for (cmd, want) in [
            // bash: "too many arguments"; zsh: substitution in $PWD.
            ("cd /wt extra; git commit -m x", "/cwd"),
            ("cd -x /wt; git commit -m x", "/cwd"),
            ("cd -L -- /wt && git commit -m x", "/wt"),
            ("cd /wt 2>/dev/null && git commit -m x", "/wt"),
            ("cd /wt > /dev/null 2>&1 && git commit -m x", "/wt"),
            ("cd /wt 2>&1 && git commit -m x", "/wt"),
            ("cd /wt &>/dev/null && git commit -m x", "/wt"),
            ("cd >/dev/null /wt && git commit -m x", "/wt"),
        ] {
            assert_eq!(
                git_commit_targets(cmd, "/cwd"),
                vec![want.to_string()],
                "{cmd}"
            );
        }
    }

    #[test]
    fn pipeline_and_background_cd_do_not_persist() {
        // Not plain (#1058): the union path judges both.
        for cmd in [
            "cd /wt | true; git commit -m x",
            "cd /wt |& cat; git commit -m x",
            "cd /wt & git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
    }

    #[test]
    fn a_pipeline_last_cd_keeps_both_directories() {
        // zsh runs the last element in the current shell; bash forks it.
        assert_eq!(
            git_commit_targets("true | cd /wt; git commit -m x", "/cwd"),
            vec!["/cwd".to_string(), "/wt".to_string()]
        );
    }

    #[test]
    fn cd_into_a_missing_directory_keeps_both_outcomes() {
        let scratch = scratch("cd-missing-parse");
        let here = scratch.path().join("here");
        let there = scratch.path().join("there");
        std::fs::create_dir(&here).unwrap();
        std::fs::create_dir(&there).unwrap();
        let here_s = here.to_string_lossy().into_owned();
        let there_s = there.to_string_lossy().into_owned();
        let missing = scratch
            .path()
            .join("missing")
            .to_string_lossy()
            .into_owned();

        let on_disk = |cmd: &str| scan_targets(cmd, &here_s, true).commits;
        // `;` runs the commit whether or not the cd worked.
        assert_eq!(
            on_disk(&format!("cd {missing}; git commit -m x")),
            vec![here_s.clone(), missing.clone()]
        );
        assert_eq!(
            on_disk(&format!("cd {missing} || git commit -m x")),
            vec![here_s.clone(), missing.clone()]
        );
        // `&&` runs it only if the cd worked — the lexical target, which is
        // what `git worktree add <p> && cd <p> && git commit` needs (review I3).
        assert_eq!(
            on_disk(&format!("cd {missing} && git commit -m x")),
            vec![missing.clone()]
        );
        // ...until the chain ends: a failed cd skipped it, and `;` goes on.
        assert_eq!(
            on_disk(&format!("cd {missing} && true; git commit -m x")),
            vec![here_s.clone(), missing.clone()]
        );
        assert_eq!(
            on_disk(&format!("cd {there_s}; git commit -m x")),
            vec![there_s.clone()]
        );
        // A failed cd sets no OLDPWD: `cd -` can still mean `here`.
        let targets = on_disk(&format!(
            "cd {there_s}; cd {missing}; cd - ; git commit -m x"
        ));
        assert!(targets.contains(&here_s), "{targets:?}");
    }

    #[test]
    fn inchain_dismiss_follows_cd_dash_and_subshells_like_the_commit_walk() {
        // Parity: the dismiss map is keyed by the resolved target string.
        for cmd in [
            "cd /wt && cd - && cadence-hooks guardrails dismiss-enforce-worktree --for 30m && git commit -m x",
            "builtin cd /wt && cadence-hooks guardrails dismiss-enforce-worktree --for 30m && git commit -m x",
        ] {
            let targets = git_commit_targets(cmd, "/cwd");
            let dismissed = inchain_dismissed_commits(cmd, "/cwd", false);
            assert_eq!(targets.len(), 1, "{cmd}");
            assert!(dismissed.contains_key(&targets[0]), "{cmd}: {dismissed:?}");
        }
        // A non-plain command that changes directory licenses nothing.
        let cmd = "(cd /wt) && cadence-hooks guardrails dismiss-enforce-worktree --for 30m \
                   && git commit -m x";
        assert!(inchain_dismissed_commits(cmd, "/cwd", false).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cd_that_does_not_take_effect_blocks_a_commit_from_the_primary() {
        // Each row is allowed on the #1018 base while bash commits in the
        // primary checkout (cadence-hooks#1058).
        let scratch = scratch("cd-no-effect-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let wt = wt.to_string_lossy().into_owned();
        let missing = scratch
            .path()
            .join("missing")
            .to_string_lossy()
            .into_owned();
        let parent = scratch.path().to_string_lossy().into_owned();
        for cmd in [
            format!("(cd {wt}); git commit -m x"),
            format!("cd {wt} && cd - && git commit -m x"),
            format!("cd {parent}/[r]epo && git commit -m x"),
            format!("cd {missing}; git commit -m x"),
            format!("cd {wt} | true; git commit -m x"),
            format!("cd {wt} extra; git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
        }
        // The cd that does take effect still reaches the worktree.
        let mut input = make_bash(&format!("cd {wt} && git commit -m x"));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Allow
        );
    }

    #[cfg(unix)]
    #[test]
    fn prefixed_cd_from_a_worktree_into_the_primary_blocks() {
        let scratch = scratch("cd-prefix-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        for cmd in [
            format!("builtin cd {p} && git commit -m x"),
            format!("command cd {p} && git commit -m x"),
            format!("FOO=1 cd {p} && git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
        }
        // `env cd` runs an external cd: the commit stays in the worktree.
        let mut input = make_bash(&format!("env cd {p}; git commit -m x"));
        input.cwd = Some(wt.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn missing_dir_cd_block_names_the_target() {
        // A plain cd into a missing directory keeps the pre-cd directory as
        // a fallback past `;`, so the commit is judged at the primary.
        let scratch = scratch("cd-missing-hint");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let mut input = make_bash("cd ./no-such-dir; git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        assert!(r.message.unwrap().contains("is a primary checkout"));
    }

    // --- git global walk (#885) ---

    #[test]
    fn a_global_value_spelling_another_global_does_not_swallow_the_subcommand() {
        // `-C` here is `-c`'s value; the look-back walk read `commit` as the
        // value of that `-C` and never reached the subcommand.
        assert_eq!(
            git_commit_targets("git -c -C commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("git -c --git-dir commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        // Ordinary spellings are unchanged.
        assert_eq!(
            git_commit_targets("git -c a=b -C /x commit -m x", "/cwd"),
            vec!["/x".to_string()]
        );
    }

    #[test]
    fn escaped_git_global_and_subcommand_are_read_as_git_reads_them() {
        assert_eq!(
            git_commit_targets(r"git -\C /x commit -m x", "/cwd"),
            vec!["/x".to_string()]
        );
        assert_eq!(
            git_commit_targets(r"git \commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
    }

    // --- dismiss scope (#758) ---

    #[test]
    fn message_dismiss_names_the_judged_repo_when_it_differs() {
        let msg = block_message("/Users/dev/mono", Some("/Users/dev/meta"));
        assert!(
            msg.contains("dismiss-enforce-worktree --for 30m --repo /Users/dev/mono --reason"),
            "{msg}"
        );
        // No session repo to run the dismiss from: name the target too.
        let msg = block_message("/Users/dev/mono", None);
        assert!(msg.contains("--repo /Users/dev/mono"), "{msg}");
        // Same repo: the bare dismiss already lands there.
        let msg = block_message("/Users/dev/repo", Some("/Users/dev/repo"));
        assert!(!msg.contains("--repo"), "{msg}");
        assert!(
            msg.contains("dismiss-enforce-worktree --for 30m --reason"),
            "{msg}"
        );
        // A path the shell would split or expand is quoted.
        let msg = block_message("/Users/dev/my repo's", Some("/x"));
        assert!(msg.contains(r"--repo '/Users/dev/my repo'\''s'"), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn redirected_block_suggests_a_dismiss_that_clears_it() {
        let scratch = scratch("dismiss-scope");
        let (primary, _wt) = primary_and_worktree(&scratch);
        let other = scratch.path().join("other");
        std::fs::create_dir(&other).unwrap();
        init_repo(&other);
        let p = primary.to_string_lossy().into_owned();
        let mut input = make_bash(&format!("git -C {p} commit -m x"));
        input.cwd = Some(other.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        let root = GitProbe::default().repo_root(&primary).unwrap();
        assert!(
            msg.contains(&format!("--repo {}", shell_single_quote(&root))),
            "{msg}"
        );
    }

    // --- gate-2 review of the cd walk (#1058 review) ---

    #[test]
    fn a_case_pattern_paren_does_not_close_the_enclosing_subshell() {
        // C1 (round 2): a `case` is not plain; the union path judges every cd
        // target, so the commit inside the subshell is judged at /p.
        for cmd in [
            "(cd /p; case a in a) true;; esac; git commit -m x)",
            "(cd /p && case a in a) true;; esac && git commit -m x)",
            "(cd /p; x=$(case a in a) echo y;; esac); git commit -m x)",
            "(cd /p; case a in (a) true;; b|c) false;; esac; git commit -m x)",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/p"], "{cmd}");
        }
        assert_eq!(
            sorted_targets(
                "(cd /wt; case a in a) true;; esac); git commit -m x",
                "/cwd"
            ),
            vec!["/cwd", "/wt"]
        );
    }

    #[test]
    fn an_unattributable_close_keeps_both_directories() {
        // `case` with no `in`: the `)` might close the subshell or not.
        let targets = git_commit_targets("(cd /wt; case); git commit -m x", "/cwd");
        assert!(targets.contains(&"/cwd".to_string()), "{targets:?}");
    }

    #[test]
    fn a_redirection_ampersand_is_not_a_background_ampersand() {
        // `&` is not plain; `&>/dev/null` and `2>&1` are.
        for (cmd, want) in [
            ("cd /wt 2>&1 & git commit -m x", vec!["/cwd", "/wt"]),
            (
                "cd /wt >/dev/null 2>&1 & git commit -m x",
                vec!["/cwd", "/wt"],
            ),
            ("cd /wt & >/dev/null git commit -m x", vec!["/cwd", "/wt"]),
            ("cd /wt &>/dev/null && git commit -m x", vec!["/wt"]),
            ("cd /wt 2>&1 && git commit -m x", vec!["/wt"]),
            ("cd /wt >&2 && git commit -m x", vec!["/cwd", "/wt"]),
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), want, "{cmd}");
        }
    }

    #[test]
    fn a_redirection_before_the_command_word_does_not_hide_a_commit() {
        assert_eq!(
            git_commit_targets(">/dev/null git commit -m x", "/cwd"),
            vec!["/cwd".to_string()]
        );
        assert_eq!(
            git_commit_targets("2>/dev/null GIT_DIR=/p/.git git commit -m x", "/cwd"),
            vec!["/p".to_string()]
        );
    }

    #[test]
    fn a_segment_that_may_rebind_oldpwd_keeps_both_cd_dash_outcomes() {
        // I2/C3: a segment that may assign OLDPWD is not plain; the union path
        // cannot read the `cd -` after it and reports it, which blocks from a
        // worktree. An external command cannot assign it, so the plain walk
        // still resolves `cd -` across one.
        for cmd in [
            "cd /a; OLDPWD=/p; cd -; git commit -m x",
            "cd /a; export OLDPWD=/p; cd -; git commit -m x",
            "cd /a; echo $((OLDPWD=1)); cd -; git commit -m x",
            "cd /a; read OLDPWD <<< /p; cd -; git commit -m x",
        ] {
            let scan = scan_targets(cmd, "/cwd", false);
            assert!(scan.unresolved_cd.is_some(), "{cmd}");
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/a", "/cwd"], "{cmd}");
        }
        for cmd in [
            "cd /a && make -v && cd - && git commit -m x",
            "cd /a && cat /dev/null && cd - && git commit -m x",
            "cd /a && echo $OLDPWD && cd - && git commit -m x",
            "cd /a; git status; cd -; git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd"], "{cmd}");
        }
    }

    #[test]
    fn escaped_equals_form_git_flags_are_read_as_git_reads_them() {
        // I4.
        assert_eq!(
            git_commit_targets(r"git --git-d\ir=/p/.git commit -m x", "/cwd"),
            vec!["/p".to_string()]
        );
        assert_eq!(
            git_commit_targets(r"git --work-t\ree=/p commit -m x", "/cwd"),
            vec!["/p".to_string()]
        );
    }

    #[test]
    fn a_cd_with_a_redirection_that_may_fail_keeps_both_directories() {
        // I6: bash skips a builtin whose redirection fails.
        let scratch = scratch("cd-redirect-parse");
        let here = scratch.path().join("here");
        let there = scratch.path().join("there");
        std::fs::create_dir(&here).unwrap();
        std::fs::create_dir(&there).unwrap();
        let input = scratch.path().join("input");
        std::fs::write(&input, "x").unwrap();
        let here_s = here.to_string_lossy().into_owned();
        let there_s = there.to_string_lossy().into_owned();
        let input_s = input.to_string_lossy().into_owned();
        let on_disk = |cmd: &str| scan_targets(cmd, &here_s, true).commits;
        for cmd in [
            format!(">/nonexistent/f cd {there_s}; git commit -m x"),
            format!("cd {there_s} > /nonexistent/f; git commit -m x"),
            format!("cd {there_s} < /nonexistent; git commit -m x"),
            format!("cd {there_s} >$LOG; git commit -m x"),
        ] {
            assert_eq!(
                on_disk(&cmd),
                vec![here_s.clone(), there_s.clone()],
                "{cmd}"
            );
        }
        // Not plain either: a close, a here-string.
        for cmd in [
            format!("cd {there_s} >&-; git commit -m x"),
            format!("cd {there_s} <<< x; git commit -m x"),
        ] {
            assert_eq!(
                on_disk(&cmd),
                vec![here_s.clone(), there_s.clone()],
                "{cmd}"
            );
        }
        // Plain: `/dev/null`, `2>&1`, an existing input file.
        for cmd in [
            format!("cd {there_s} >/dev/null; git commit -m x"),
            format!("cd {there_s} 2>&1; git commit -m x"),
            format!("cd {there_s} < {input_s}; git commit -m x"),
        ] {
            assert_eq!(on_disk(&cmd), vec![there_s.clone()], "{cmd}");
        }
    }

    #[test]
    fn a_plain_cd_in_a_script_that_redefines_cd_is_unresolved() {
        // N3 (round 2): a definition, alias or `enable` is not plain; the
        // union path judges the session cwd too.
        for cmd in [
            r#"cd() { builtin cd "$@"; }; cd /wt && git commit -m x"#,
            "function cd { :; }; cd /wt && git commit -m x",
            "alias cd=pwd; cd /wt && git commit -m x",
            "enable -n cd; cd /wt && git commit -m x",
            "cd() { :; }; builtin cd /wt && git commit -m x",
            "cd() { :; }; command cd /wt && git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
    }

    #[test]
    fn many_ambiguous_cds_take_the_union_path() {
        // No overflow special case any more: a `|` into a `cd` is not plain,
        // so every `cd` target is judged, with the session cwd.
        let cmd = "cd /s && true | cd /a; true | cd /b; true | cd /c; true | cd /d; \
                   git commit -m x";
        let scan = scan_targets(cmd, "/cwd", false);
        for dir in ["/cwd", "/s", "/a", "/b", "/c", "/d"] {
            assert!(
                scan.commits.contains(&dir.to_string()),
                "{dir}: {:?}",
                scan.commits
            );
        }
        assert_eq!(scan.unresolved_cd, None);
    }

    #[test]
    fn an_ambiguous_directory_does_not_arm_an_in_chain_dismiss() {
        let cmd = "true | cd /wt; cadence-hooks guardrails dismiss-enforce-worktree --for 30m \
                   && git commit -m x";
        assert!(inchain_dismissed_commits(cmd, "/cwd", false).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn creating_a_directory_then_committing_in_it_is_not_blocked() {
        // I3: the block's own recipe, and its cousins, from the primary. The
        // target does not exist when the hook runs.
        let scratch = scratch("cd-created-dir-e2e");
        let (primary, _wt) = primary_and_worktree(&scratch);
        for cmd in [
            "git worktree add .claude/worktrees/x -b feat/x && cd .claude/worktrees/x && git commit -m x",
            "git clone https://example.invalid/y.git yy && cd yy && git commit -m x",
            "mkdir d && cd d && git init && git commit -m x",
        ] {
            let mut input = make_bash(cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Allow,
                "{cmd}"
            );
        }
        // A `;` after the missing cd still runs the commit in the primary.
        let mut input = make_bash("cd ./not-yet; git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Block
        );
    }

    #[cfg(unix)]
    #[test]
    fn review_repros_from_a_worktree_into_the_primary_block() {
        let scratch = scratch("cd-review-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        for cmd in [
            format!("(cd {p}; case a in a) true;; esac; git commit -m x)"),
            format!("(cd {p} && case a in a) true;; esac && git commit -m x)"),
            format!(r"git --git-d\ir={p}/.git commit -m x"),
            format!(r"git --work-t\ree={p} commit -m x"),
            format!("true | cd {p}; git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Block,
                "{cmd}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn review_repros_from_the_primary_block() {
        let scratch = scratch("cd-review-primary-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let w = wt.to_string_lossy().into_owned();
        for cmd in [
            format!("cd {w} 2>&1 & git commit -m x"),
            format!("cd {w} >/dev/null 2>&1 & git commit -m x"),
            format!("cd {w} & >/dev/null git commit -m x"),
            format!(">/nonexistent/f cd {w}; git commit -m x"),
            format!("cd {w} > /nonexistent/f; git commit -m x"),
            format!("cd {w} < /nonexistent; git commit -m x"),
            format!("true | cd {w}; git commit -m x"),
            format!("alias cd=pwd; cd {w} && git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Block,
                "{cmd}"
            );
        }
    }

    // --- delta review of the candidate walk (#1058 delta review) ---

    /// The commit targets of `cmd` from `cwd`, sorted, as `&str`s.
    fn sorted_targets(cmd: &str, cwd: &str) -> Vec<String> {
        let mut got = git_commit_targets(cmd, cwd);
        got.sort();
        got.dedup();
        got
    }

    #[test]
    fn an_overflow_keeps_the_directories_the_shell_may_stay_in() {
        // C1: the pipeline hops take the union path, which keeps them all.
        let scan = scan_targets(
            "true | cd /p; true | cd /x1; true | cd /x2; true | cd /x3; git commit -m x",
            "/w",
            false,
        );
        assert!(
            scan.commits.contains(&"/p".to_string()),
            "{:?}",
            scan.commits
        );
        assert!(
            scan.commits.contains(&"/w".to_string()),
            "{:?}",
            scan.commits
        );
    }

    #[test]
    fn brace_array_parameter_and_backtick_words_do_not_open_a_case() {
        // C2 (round 3): none of these is plain; the union path keeps the real
        // cwd whatever the words look like.
        for cmd in [
            "(cd /wt; echo {case,in}); git commit -m x",
            "(cd /wt; git log --grep={case,in}); git commit -m x",
            "(cd /wt; echo ${case} in); git commit -m x",
            "(cd /wt; a=(case in)); git commit -m x",
            "(cd /wt; echo `echo` case in); git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
    }

    #[test]
    fn a_dup_of_an_unopened_descriptor_may_fail() {
        // C4 (round 3): only `2>&1` and `/dev/null` targets are plain; any
        // other dup takes the union path, which keeps the pre-cd directory.
        for cmd in [
            "cd /p; cd /w 2>&3; git commit -m x",
            "cd /p; cd /w <&3; git commit -m x",
            "cd /p; cd /w 2>&4-; git commit -m x",
            "cd /p; cd /w >&-; git commit -m x",
            "cd /p; cd /w {fd}>/dev/null; git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/w"), vec!["/p", "/w"], "{cmd}");
        }
        assert_eq!(
            sorted_targets("cd /p; cd /w 2>&1; git commit -m x", "/w"),
            vec!["/w"]
        );
    }

    #[test]
    fn a_negated_or_timed_commit_is_seen() {
        // C5.
        for cmd in [
            "! >/dev/null git commit -m x",
            "! git commit -m x",
            "time -p git commit -m x",
            "! time git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd"], "{cmd}");
        }
    }

    #[test]
    fn a_cd_behind_a_conditional_keeps_the_pre_cd_directories() {
        // I1.
        for (cmd, cwd, want) in [
            ("cd /p || cd /w; git commit -m x", "/w", vec!["/p", "/w"]),
            ("false && cd /w; git commit -m x", "/p", vec!["/p", "/w"]),
            ("true || cd /w && git commit -m x", "/p", vec!["/p", "/w"]),
            (
                "cd /p && false && cd /w; git commit -m x",
                "/w",
                vec!["/p", "/w"],
            ),
            // Inside the `&&` chain only the cd's success reaches the commit.
            ("true && cd /w && git commit -m x", "/p", vec!["/w"]),
        ] {
            assert_eq!(sorted_targets(cmd, cwd), want, "{cmd}");
        }
    }

    #[test]
    fn a_backgrounded_and_or_list_is_undone() {
        // I2 (round 3): `&` is not plain; the union path keeps the real cwd.
        for cmd in [
            "cd /wt && true & git commit -m x",
            "cd /wt && true | cat & git commit -m x",
            "cd /wt && (true) & git commit -m x",
            "(cd /wt; true) & git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
        assert_eq!(
            sorted_targets("cd /wt && true; git commit -m x", "/cwd"),
            vec!["/wt"]
        );
    }

    #[test]
    fn an_unresolved_cd_forgets_oldpwd() {
        // I3 (round 3): an unreadable cd is not plain; the union path reports it.
        let cmd = "cd /a && cd $X && cd - && git commit -m x";
        assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/a", "/cwd"]);
        assert!(scan_targets(cmd, "/cwd", false).unresolved_cd.is_some());
    }

    #[test]
    fn redirections_anywhere_in_the_command_are_not_its_words() {
        // I4.
        for cmd in [
            "{fd}>/dev/null git commit -m x",
            "git >/dev/null commit -m x",
            "git 2>&1 commit -m x",
            "git -C /p 2>/dev/null commit -m x",
        ] {
            let want = if cmd.contains("/p") { "/p" } else { "/cwd" };
            assert_eq!(sorted_targets(cmd, "/cwd"), vec![want], "{cmd}");
        }
    }

    #[test]
    fn any_enable_or_source_may_redefine_cd() {
        // I5 (round 3): not plain; the session cwd is judged too, and
        // `source`/`.` are reported as unreadable.
        for cmd in [
            "enable -n c{d,x}; cd /wt && git commit -m x",
            "enable -n ${X:-cd}; cd /wt && git commit -m x",
            "X=cd; enable -n $X; cd /wt && git commit -m x",
            r#"source /dev/stdin <<<"cd(){ :; }"; cd /wt && git commit -m x"#,
            ". ./env.sh; cd /wt && git commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), vec!["/cwd", "/wt"], "{cmd}");
        }
        assert_eq!(
            sorted_targets("git add .; cd /wt && git commit -m x", "/cwd"),
            vec!["/wt"]
        );
    }

    #[test]
    fn a_pipe_does_not_settle_the_chain() {
        // Nit: `| tail` inside the chain let the missing-dir fallback in.
        let scratch = scratch("pipe-settle");
        let here = scratch.path().join("here");
        std::fs::create_dir(&here).unwrap();
        let here_s = here.to_string_lossy().into_owned();
        let target = here
            .join(".claude/worktrees/x")
            .to_string_lossy()
            .into_owned();
        let cmd = "git worktree add .claude/worktrees/x -b feat/x && cd .claude/worktrees/x \
                   && npm test 2>&1 | tail -3 && git commit -m x";
        assert_eq!(scan_targets(cmd, &here_s, true).commits, vec![target]);
    }

    #[cfg(unix)]
    #[test]
    fn delta_repros_from_a_worktree_into_the_primary_block() {
        let scratch = scratch("cd-delta-wt-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        let w = wt.to_string_lossy().into_owned();
        let nx = scratch.path().join("nx").to_string_lossy().into_owned();
        for cmd in [
            format!("cd {p}; cd {nx}1; cd {nx}2; cd {nx}3; cd {nx}4; git commit -m x"),
            format!(
                "true | cd {p}; true | cd {nx}1; true | cd {nx}2; true | cd {nx}3; \
                 git commit -m x"
            ),
            format!("cd {p}; cd {w} 2>&3; git commit -m x"),
            format!("cd {p} || cd {w}; git commit -m x"),
            format!("cd {p} && false && cd {w}; git commit -m x"),
            format!("cd {w}/..; OLDPWD={p}; cd {w}; OLDPWD={p}; cd -; git commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(w.clone());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Block,
                "{cmd}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn delta_repros_from_the_primary_block() {
        let scratch = scratch("cd-delta-primary-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let w = wt.to_string_lossy().into_owned();
        for cmd in [
            format!("(cd {w}; echo {{case,in}}); git commit -m x"),
            format!("cd {w} && make -v >/dev/null && cd - && git commit -m x"),
            format!("cd {w}; cat /dev/null; cd -; git commit -m x"),
            "! >/dev/null git commit -m x".to_string(),
            format!("false && cd {w}; git commit -m x"),
            format!("true || cd {w} && git commit -m x"),
            format!("cd {w} && true & git commit -m x"),
            format!("cd {w} && true | cat & git commit -m x"),
            "{fd}>/dev/null git commit -m x".to_string(),
            "git >/dev/null commit -m x".to_string(),
            format!("enable -n c{{d,x}}; cd {w} && git commit -m x"),
            format!(r#"source /dev/stdin <<<"cd(){{ :; }}"; cd {w} && git commit -m x"#),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Block,
                "{cmd}"
            );
        }
        // The worktree recipe with a piped test step still passes.
        let mut input = make_bash(
            "git worktree add .claude/worktrees/x -b feat/x && cd .claude/worktrees/x \
             && npm test 2>&1 | tail -3 && git commit -m x",
        );
        input.cwd = Some(primary.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Allow
        );
    }

    // --- plain-shape allowlist (#1058, round 5) ---

    #[test]
    fn the_plain_shape_allowlist() {
        let env = CdEnv::new(None, false);
        for cmd in [
            "git commit -m x",
            "cd /wt && git commit -m x",
            "cd sub; git add . && git commit -m x",
            "npm test 2>&1 | tail -3 && git commit -m x",
            "cd /wt >/dev/null 2>&1 && git commit -m x",
            "git commit -m \"fix(scope): {x}\"",
            "git commit -m 'a $(b) `c`'",
            "git commit -F - <<'EOF'\nbody $(x)\nEOF",
            "builtin cd /wt && git commit -m x",
            "cd \"$HOME/wt\" && git commit -m x",
        ] {
            assert!(is_plain_shape(cmd, "/cwd", env), "{cmd}");
        }
        for cmd in [
            "cd /wt || true; git commit -m x",
            "cd /wt & git commit -m x",
            "true | cd /wt; git commit -m x",
            "cd /wt | cat; git commit -m x",
            "(cd /wt); git commit -m x",
            "{ cd /wt; }; git commit -m x",
            "git commit -m \"$(date)\"",
            "git commit -m `date`",
            "echo ${X:-y}; git commit -m x",
            "if true; then git commit -m x; fi",
            "for f in a; do git commit -m x; done",
            "case a in a) git commit -m x;; esac",
            "eval 'cd /p'; git commit -m x",
            "source ./x; git commit -m x",
            "enable -n cd; git commit -m x",
            "alias cd=pwd; git commit -m x",
            "trap 'cd /p' DEBUG; git commit -m x",
            "export X=1; git commit -m x",
            "OLDPWD=/p; git commit -m x",
            "read X; git commit -m x",
            "printf -v X y; git commit -m x",
            "pushd /p; git commit -m x",
            "cd /wt > out.log; git commit -m x",
            "cd /wt 2>&3; git commit -m x",
            "{fd}>/dev/null git commit -m x",
            "git commit -m x <<< y",
        ] {
            assert!(!is_plain_shape(cmd, "/cwd", env), "{cmd}");
        }
    }

    #[test]
    fn a_quoted_delimiter_heredoc_message_is_carved_out() {
        let carved = |cmd: &str| plain_carve(cmd).map(|(text, _)| text);
        let want = Some(format!("git commit -m \"{CARVED}\""));
        let cmd = "git commit -m \"$(cat <<'EOF'\nfix(x): y\n\nbody `z`\nEOF\n)\"";
        assert_eq!(carved(cmd), want);
        let dashed = "git commit -m \"$(cat <<-\"EOF\"\n\tbody\n\tEOF\n)\"";
        assert_eq!(carved(dashed), want);
        // Blanks after `<<` are accepted.
        let spaced = "git commit -m \"$(cat << 'EOF'\nbody\nEOF\n)\"";
        assert_eq!(carved(spaced), want);
        // A body line that only starts with the delimiter is body text (F5).
        let prefixed = "git commit -m \"$(cat <<'EOF'\nEOFX\nEOF  \nEOF\n)\"";
        assert_eq!(carved(prefixed), want);
        assert_eq!(carved("git commit -m \"$(cat <<'EOF'\nm\nEOF )\n)\""), None);
        // An unquoted delimiter expands its body; text after the delimiter
        // runs; neither is carved out.
        for cmd in [
            "git commit -m \"$(cat <<EOF\n$(cd /p)\nEOF\n)\"",
            "git commit -m \"$(cat <<'EOF'\nx\nEOF\ncd /p)\"",
            "git commit -m \"$(cat <<'EOF'\nx\n)\"",
        ] {
            assert_eq!(plain_carve(cmd), None, "{cmd:?}");
        }
    }

    #[test]
    fn a_commit_in_a_compound_command_is_seen() {
        // I-d: compound heads used to hide the commit from every channel.
        for (cmd, want) in [
            ("if true; then git commit -m x; fi", vec!["/cwd"]),
            ("for f in a; do git commit -m x; done", vec!["/cwd"]),
            ("while false; do git commit -m x; done", vec!["/cwd"]),
            ("if true; then git -C /p commit -m x; fi", vec!["/p"]),
            (
                "for f in a; do cd /p; git commit -m x; done",
                vec!["/cwd", "/p"],
            ),
        ] {
            assert_eq!(sorted_targets(cmd, "/cwd"), want, "{cmd}");
        }
    }

    #[test]
    fn round_five_repros_take_the_union_path() {
        for (cmd, cwd, want) in [
            // N1
            (
                "false || cd /w/d1; false || cd /x; false || cd /y; false || cd /p; git commit -m x",
                "/w",
                vec!["/p", "/w", "/w/d1", "/x", "/y"],
            ),
            // N2
            (
                "cd /w/nx || (exit); git commit -m x",
                "/p",
                vec!["/p", "/w/nx"],
            ),
            (
                "cd /w/nx || return; git commit -m x",
                "/p",
                vec!["/p", "/w/nx"],
            ),
            // N3
            (
                "echo then case x in; (cd /w); git commit -m x",
                "/p",
                vec!["/p", "/w"],
            ),
            // N4
            (
                "(cd /p; case $(echo a) in a) true;; esac; git commit -m x)",
                "/w",
                vec!["/p", "/w"],
            ),
            (
                "(cd /p; case `echo a` in a) true;; esac; git commit -m x)",
                "/w",
                vec!["/p", "/w"],
            ),
            // N5
            (
                "cd /w && { true & }; git commit -m x",
                "/p",
                vec!["/p", "/w"],
            ),
            (
                "cd /p && { true & }; git commit -m x",
                "/w",
                vec!["/p", "/w"],
            ),
            (
                "{ cd /w && true; } & git commit -m x",
                "/p",
                vec!["/p", "/w"],
            ),
        ] {
            assert_eq!(sorted_targets(cmd, cwd), want, "{cmd}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_cd_in_a_non_plain_command_blocks_from_a_worktree() {
        // The #346/N2 decision, taken fail-closed for non-plain commands.
        let scratch = scratch("union-unresolved-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        for cmd in [
            "cd \"$X\" && git commit -m x".to_string(),
            format!("cd {p}/.. ; OLDPWD={p}; cd -; git commit -m x"),
            "cd - && git commit -m x".to_string(),
            "eval \"$CMD\"; git commit -m x".to_string(),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(wt.to_string_lossy().into_owned());
            let r = run_enforce(&input, &cfg(false, false));
            assert_eq!(r.outcome, Outcome::Block, "{cmd}");
            assert!(
                r.message.unwrap().contains("could not be resolved"),
                "{cmd}"
            );
        }
        // Without a commit there is nothing to block.
        let mut input = make_bash("cd \"$X\" && ls");
        input.cwd = Some(wt.to_string_lossy().into_owned());
        assert_eq!(
            run_enforce(&input, &cfg(false, false)).outcome,
            Outcome::Allow
        );
    }

    #[cfg(unix)]
    #[test]
    fn round_five_repros_block_end_to_end() {
        let scratch = scratch("round-five-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        let w = wt.to_string_lossy().into_owned();
        let from_w = [
            format!("false || cd {w}; false || cd /tmp; false || cd {p}; git commit -m x"),
            format!("(cd {p}; case $(echo a) in a) true;; esac; git commit -m x)"),
            format!("(cd {p}; case `echo a` in a) true;; esac; git commit -m x)"),
            format!("cd {p} && {{ true & }}; git commit -m x"),
            format!("if true; then git -C {p} commit -m x; fi"),
            format!("for f in a; do cd {p}; git commit -m x; done"),
        ];
        let from_p = [
            format!("cd {w}/nx || (exit); git commit -m x"),
            format!("cd {w}/nx || return; git commit -m x"),
            format!("echo then case x in; (cd {w}); git commit -m x"),
            format!("cd {w} && {{ true & }}; git commit -m x"),
            "if true; then git commit -m x; fi".to_string(),
        ];
        for (cmds, cwd) in [(&from_w[..], &w), (&from_p[..], &p)] {
            for cmd in cmds {
                let mut input = make_bash(cmd);
                input.cwd = Some(cwd.clone());
                assert_eq!(
                    run_enforce(&input, &cfg(false, false)).outcome,
                    Outcome::Block,
                    "{cmd}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_everyday_shapes_still_pass() {
        let scratch = scratch("everyday-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(wt.join("sub")).unwrap();
        let p = primary.to_string_lossy().into_owned();
        let w = wt.to_string_lossy().into_owned();
        let from_p = [
            "git worktree add .claude/worktrees/x -b feat/x && cd .claude/worktrees/x \
             && git commit -m x"
                .to_string(),
            format!("cd {w} && git commit -m x"),
            format!("cd {w} && git commit -m \"$(cat <<'EOF'\nfix(x): y (z)\n\nbody\nEOF\n)\""),
        ];
        let from_w = [
            "cd sub && git commit -m x".to_string(),
            "npm test 2>&1 | tail -3 && git commit -m x".to_string(),
            "git commit -F - <<'EOF'\nmsg $(x)\nEOF".to_string(),
            "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"".to_string(),
            "(cd sub && make) && git commit -m x".to_string(),
            format!("git -C {w} commit -m x"),
        ];
        for (cmds, cwd) in [(&from_p[..], &p), (&from_w[..], &w)] {
            for cmd in cmds {
                let mut input = make_bash(cmd);
                input.cwd = Some(cwd.clone());
                assert_eq!(
                    run_enforce(&input, &cfg(false, false)).outcome,
                    Outcome::Allow,
                    "{cmd}"
                );
            }
        }
    }

    // --- round-5 Important repros (I-a, I-b, I-c) ---

    #[test]
    fn a_negated_or_timed_case_and_a_paren_default_take_the_union_path() {
        // I-a / I-b: each hid a keyword or a paren from the old scoping walk.
        for cmd in [
            "(! case a in a) true;; esac; cd /w); git commit -m x",
            "(time -p case a in a) true;; esac; cd /w); git commit -m x",
            "(cd /w; echo ${x:-(}); git commit -m x",
        ] {
            assert!(!is_plain_shape(cmd, "/p", CdEnv::new(None, false)), "{cmd}");
            assert_eq!(sorted_targets(cmd, "/p"), vec!["/p", "/w"], "{cmd}");
        }
    }

    #[test]
    fn a_quoted_redirect_character_is_part_of_a_word() {
        // I-c: `2'>'x` is a file name. Read as a redirection it was dropped,
        // and `commit` became `-C`'s value, so no commit was seen at all.
        for cmd in [
            "git -C 2'>'x commit -m x",
            "mkdir -p 2'>'x; git -C 2'>'x commit -m x",
            "(git -C 2'>'x commit -m x)",
            "git -C 2\">\"x commit -m x",
        ] {
            assert_eq!(sorted_targets(cmd, "/p"), vec!["/p/2>x"], "{cmd}");
        }
        // The unquoted operator is still a redirection.
        assert_eq!(
            sorted_targets("git -C /w 2>x commit -m x", "/p"),
            vec!["/w"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn round_five_important_repros_block_end_to_end() {
        let scratch = scratch("round-five-important-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let w = wt.to_string_lossy().into_owned();
        let p = primary.to_string_lossy().into_owned();
        // The directory and link exist when the hook runs, as they do on any
        // re-run; a path the command itself creates is not judged (see the
        // let-through list).
        std::fs::create_dir(primary.join("2>x")).unwrap();
        std::os::unix::fs::symlink(&primary, wt.join("2>p")).unwrap();
        let from_p = [
            format!("(! case a in a) true;; esac; cd {w}); git commit -m x"),
            format!("(time -p case a in a) true;; esac; cd {w}); git commit -m x"),
            format!("(cd {w}; echo ${{x:-(}}); git commit -m x"),
            "mkdir -p 2'>'x; git -C 2'>'x commit -m x".to_string(),
        ];
        let from_w = [
            format!("ln -sfn {p} 2'>'p; git -C 2'>'p commit -m x"),
            format!("ln -sfn {p} 2'>'p && (git -C 2'>'p commit -m x)"),
        ];
        for (cmds, cwd) in [(&from_p[..], &p), (&from_w[..], &w)] {
            for cmd in cmds {
                let mut input = make_bash(cmd);
                input.cwd = Some(cwd.clone());
                assert_eq!(
                    run_enforce(&input, &cfg(false, false)).outcome,
                    Outcome::Block,
                    "{cmd}"
                );
            }
        }
    }

    // --- rule-7 carve-out conformance (#1058 spec review) ---

    #[test]
    fn a_carve_out_opener_is_only_matched_where_bash_runs_it() {
        // 1: an opener in single quotes, after a comment, or in an unquoted
        // outer heredoc body used to swallow the commands after it.
        let in_single_quotes =
            "echo 'x $(cat <<\"EOF\"\n'; cd /p; git commit -m x; echo '\nEOF\n)'";
        assert_eq!(sorted_targets(in_single_quotes, "/w"), vec!["/p"]);
        let after_comment = "true # $(cat <<'EOF'\ncd /p; git commit -m x\nEOF\n)";
        assert!(sorted_targets(after_comment, "/w").contains(&"/p".to_string()));
        let in_heredoc_body = "cat <<X\n$(cat <<'EOF'\nX\ncd /p; git commit -m x\nEOF\n)";
        assert!(sorted_targets(in_heredoc_body, "/w").contains(&"/p".to_string()));
        // A quoted outer heredoc body is inert, carve-out text and all.
        assert!(plain_carve("cat <<'X'\n$(cat <<'EOF'\nX\ngit commit -m x").is_some());
    }

    #[test]
    fn a_line_that_starts_with_the_delimiter_ends_the_carve_out() {
        // 2: inside `$(…)` bash ends the heredoc at `EOF)` too.
        let cmd = "git commit -m \"$(cat <<'EOF'\nmsg\nEOF)\"; cd /p; git commit -m y\nEOF\n)\"";
        assert_eq!(plain_carve(cmd), None);
        assert!(sorted_targets(cmd, "/w").contains(&"/p".to_string()));
        // The delimiter line is matched exactly: `EOF\r` is not `EOF`.
        assert_eq!(
            plain_carve("git commit -m \"$(cat <<'EOF'\nm\nEOF\r\n)\""),
            None
        );
    }

    #[test]
    fn a_blank_bash_does_not_split_on_is_not_plain() {
        // 3: the tokenizer splits on all Unicode whitespace, bash on space and
        // tab only.
        let env = CdEnv::new(None, false);
        for blank in ['\r', '\u{a0}', '\u{b}', '\u{c}', '\u{2003}', '\u{0}'] {
            let cmd = format!("cd /w{blank}; git commit -m x");
            assert!(!is_plain_shape(&cmd, "/p", env), "{cmd:?}");
            assert!(
                sorted_targets(&cmd, "/p").contains(&"/p".to_string()),
                "{cmd:?}"
            );
        }
        assert!(!is_plain_shape("cd /w\r\ngit commit -m x", "/p", env));
        assert!(is_plain_shape("cd /w\n\tgit commit -m x", "/p", env));
    }

    #[cfg(unix)]
    #[test]
    fn a_union_block_names_the_worktree_and_git_dash_c() {
        // 4.
        let scratch = scratch("union-hint-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        let w = wt.to_string_lossy().into_owned();
        let mut input = make_bash(&format!("(cd {w} && git commit -m x)"));
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let r = run_enforce(&input, &cfg(false, false));
        assert_eq!(r.outcome, Outcome::Block);
        let msg = r.message.unwrap();
        assert!(msg.contains("can't be followed step by step"), "{msg}");
        assert!(msg.contains("git -C "), "{msg}");
        // …and that spelling passes in every shape.
        for cmd in [
            format!("git -C {w} commit -m x"),
            format!("true || git -C {w} commit -m x"),
            format!("(git -C {w} commit -m x)"),
            format!("git -C {w} commit -m x > /tmp/log.txt"),
            format!("cd /tmp && git -C {w} commit -m x"),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(primary.to_string_lossy().into_owned());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Allow,
                "{cmd}"
            );
        }
        // A plain block carries no such line.
        let mut input = make_bash("git commit -m x");
        input.cwd = Some(primary.to_string_lossy().into_owned());
        let msg = run_enforce(&input, &cfg(false, false)).message.unwrap();
        assert!(!msg.contains("step by step"), "{msg}");
    }

    #[test]
    fn an_unterminated_carve_out_times_ten_thousand_is_linear() {
        // The first opener that is not a carve-out ends the scan.
        let cmd = "git commit -m \"$(cat <<'EOF'\n".repeat(10_000);
        let started = std::time::Instant::now();
        assert_eq!(plain_carve(&cmd), None);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        // And ten thousand GOOD ones are one pass.
        let good = "git commit -m \"$(cat <<'EOF'\nm\nEOF\n)\"\n".repeat(10_000);
        let started = std::time::Instant::now();
        assert!(plain_carve(&good).is_some());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn eight_thousand_continuations_split_once_per_walk() {
        // The segmenter is quadratic in backslash-newlines (core, filed
        // separately); the plain analysis splits once and both walks reuse it.
        let cmd = format!("{}git commit -m x", "true && \\\n".repeat(8_000));
        let env = CdEnv::new(None, false);
        let started = std::time::Instant::now();
        let plain = plain_of(&cmd, "/w", env);
        let once = started.elapsed();
        assert!(plain.is_some());
        let started = std::time::Instant::now();
        let scan = scan_prepared(&cmd, "/w", env, plain.as_ref());
        let _ = inchain_dismissed_prepared(&cmd, "/w", env, plain.as_ref());
        let walks = started.elapsed();
        assert_eq!(scan.commits, vec!["/w".to_string()]);
        // Both walks together cost no more than a few splits' worth.
        assert!(
            walks < once * 3 + std::time::Duration::from_millis(200),
            "{walks:?} vs {once:?}"
        );
    }

    // --- plain-gate re-check (#1058 spec re-check) ---

    #[test]
    fn a_carve_out_is_plain_only_as_a_message_argument() {
        // F1.
        let env = CdEnv::new(None, false);
        let c = "$(cat <<'EOF'\n/p\nEOF\n)";
        for cmd in [
            format!("git commit -m \"{c}\""),
            format!("git commit --message=\"{c}\""),
            format!("git commit -F \"{c}\""),
            format!("git -C /w commit -m \"{c}\""),
            format!("git tag -a v1 -m \"{c}\""),
            format!("git merge --no-ff -m \"{c}\" feat"),
            format!("gh pr create --title x --body \"{c}\""),
            format!("gh pr create --title=\"{c}\" --body x"),
        ] {
            assert!(is_plain_shape(&cmd, "/w", env), "{cmd}");
        }
        for cmd in [
            format!("cd \"{c}\" && git commit -m x"),
            format!("\"{c}\" commit -m x"),
            format!("git \"{c}\" -m x"),
            format!("git -C \"{c}\" commit -m x"),
            format!("GIT_DIR=\"{c}/.git\" git commit -m x"),
            format!("git --git-dir=\"{c}/.git\" commit -m x"),
            format!("echo \"{c}\"; git commit -m x"),
            format!("git log -m \"{c}\"; git commit -m x"),
            format!("git commit -m \"x{c}\""),
            format!("git commit -m x > \"{c}\""),
        ] {
            assert!(!is_plain_shape(&cmd, "/w", env), "{cmd}");
        }
        // The union path treats the substituted target as unreadable.
        for cmd in [
            format!("cd \"{c}\" && git commit -m x"),
            format!("\"{c}\" commit -m x"),
            format!("git \"{c}\" -m x"),
            format!("git -C \"{c}\" commit -m x"),
            format!("GIT_DIR=\"{c}/.git\" git commit -m x"),
            format!("git --git-dir=\"{c}/.git\" commit -m x"),
        ] {
            let scan = scan_targets(&cmd, "/w", false);
            assert!(
                scan.unresolved_cd.is_some() || scan.unresolved_commit.is_some(),
                "{cmd}"
            );
            assert!(
                scan.commits.contains(&"/w".to_string()),
                "{cmd}: {:?}",
                scan.commits
            );
        }
    }

    #[test]
    fn command_and_builtin_prefixes_do_not_hide_a_non_plain_head() {
        // F2.
        let env = CdEnv::new(None, false);
        for cmd in [
            "command -p eval 'cd /p'; git commit -m x",
            "command -p source ./s.sh; git commit -m x",
            "command -p . ./s.sh; git commit -m x",
            "command -p pushd /p; git commit -m x",
            "command -- eval 'cd /p'; git commit -m x",
            "builtin -- eval 'cd /p'; git commit -m x",
            "command -- cd /p; git commit -m x",
        ] {
            assert!(!is_plain_shape(cmd, "/w", env), "{cmd}");
            let scan = scan_targets(cmd, "/w", false);
            assert!(
                scan.unresolved_cd.is_some() || scan.commits.contains(&"/p".to_string()),
                "{cmd}: {:?}",
                scan.commits
            );
        }
        // A query runs nothing, and `command -p git commit` is still a commit.
        assert!(is_plain_shape(
            "command -v eval; git commit -m x",
            "/w",
            env
        ));
        assert_eq!(
            sorted_targets("command -p git commit -m x", "/w"),
            vec!["/w"]
        );
    }

    #[test]
    fn an_escaped_heredoc_introducer_is_read_line_by_line() {
        // F4: core's heredoc reading is escape-blind (#1084).
        let env = CdEnv::new(None, false);
        for cmd in [
            "echo \\<<EOF\ngit commit -m x\nEOF",
            "x\\<<EOF\ngit commit -m x\nEOF",
            "\\<<'EOF'\ngit commit -m x\nEOF",
            "echo \\' '<<EOF'\ngit commit -m x\nEOF",
        ] {
            assert!(!is_plain_shape(cmd, "/p", env), "{cmd:?}");
            assert_eq!(sorted_targets(cmd, "/p"), vec!["/p"], "{cmd:?}");
        }
        // An ordinary heredoc is still plain, and its body is data.
        assert!(is_plain_shape(
            "git commit -F - <<'EOF'\ngit commit\nEOF",
            "/p",
            env
        ));
    }

    #[test]
    fn a_physical_cd_is_not_plain() {
        let env = CdEnv::new(None, false);
        for cmd in [
            "cd -P link/.. && git commit -m x",
            "cd -LP link/.. && git commit -m x",
            "set -P; cd link/..; git commit -m x",
            "set -o physical; cd link/..; git commit -m x",
        ] {
            assert!(!is_plain_shape(cmd, "/w", env), "{cmd}");
            assert!(
                scan_targets(cmd, "/w", false).unresolved_cd.is_some(),
                "{cmd}"
            );
        }
        assert!(is_plain_shape("cd link/.. && git commit -m x", "/w", env));
    }

    #[cfg(unix)]
    #[test]
    fn plain_gate_recheck_repros_block_end_to_end() {
        let scratch = scratch("plain-gate-recheck-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(primary.join("sub")).unwrap();
        std::os::unix::fs::symlink(primary.join("sub"), wt.join("link")).unwrap();
        let p = primary.to_string_lossy().into_owned();
        std::fs::write(wt.join("s.sh"), format!("cd {p}\n")).unwrap();
        let w = wt.to_string_lossy().into_owned();
        let c = format!("$(cat <<'EOF'\n{p}\nEOF\n)");
        let from_w = [
            format!("cd \"{c}\" && git commit -m x"),
            format!("git -C \"{c}\" commit -m x"),
            format!("GIT_DIR=\"{c}/.git\" git commit -m x"),
            format!("command -p eval 'cd {p}'; git commit -m x"),
            "command -p source ./s.sh; git commit -m x".to_string(),
            "command -p . ./s.sh; git commit -m x".to_string(),
            format!("command -p pushd {p}; git commit -m x"),
            format!("builtin -- eval 'cd {p}'; git commit -m x"),
            "cd -P link/.. && git commit -m x".to_string(),
            "set -P; cd link/..; git commit -m x".to_string(),
        ];
        let from_p = [
            "echo \\<<EOF\ngit commit -m x\nEOF".to_string(),
            "\\<<'EOF'\ngit commit -m x\nEOF".to_string(),
            "echo \\' '<<EOF'\ngit commit -m x\nEOF".to_string(),
        ];
        for (cmds, cwd) in [(&from_w[..], &w), (&from_p[..], &p)] {
            for cmd in cmds {
                let mut input = make_bash(cmd);
                input.cwd = Some(cwd.clone());
                assert_eq!(
                    run_enforce(&input, &cfg(false, false)).outcome,
                    Outcome::Block,
                    "{cmd:?}"
                );
            }
        }
        // Still allowed from the worktree.
        for cmd in [
            "cd link/.. && git commit -m x".to_string(),
            "git commit -m \"$(cat <<'EOF'\nEOFX\nmsg\nEOF\n)\"".to_string(),
            "git commit -F - <<'EOF'\nmsg\nEOF".to_string(),
        ] {
            let mut input = make_bash(&cmd);
            input.cwd = Some(w.clone());
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Allow,
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn a_substitution_heredoc_ends_at_a_line_starting_with_its_delimiter() {
        // B1 (spec review, bash 5.2): inside `$(…)` a heredoc ends at any line
        // that starts with the delimiter and has a `)` after it, and bash runs
        // the rest of that line as code.
        for body in [
            "'EOF'\nEOF cd /p && git commit -m y)\nEOF\n)",
            "'EOF'\nEOFecho x)\nEOF\n)",
            "'EOF'\nEOF)\nEOF\n)",
            "-'EOF'\n\tEOF x)\nEOF\n)",
        ] {
            assert_eq!(heredoc_substitution_len(body), None, "{body:?}");
        }
        // A delimiter-prefixed line with no `)` is still body text.
        assert!(heredoc_substitution_len("'EOF'\nEOFX\nEOF\n)").is_some());
        let env = CdEnv::new(None, false);
        for cmd in [
            "git commit -m \"$(cat <<'EOF'\nEOF cd /p && git commit -m y)\nEOF\n)\"",
            "x=$(cat <<'EOF'\nEOF cd /p && git commit -m y)\nEOF\n); git commit -m x",
            "git commit -m $(cat <<'EOF'\nEOF)\ncd /p && git commit -m y\nEOF\n)",
            "git commit -m \"$(cat <<'EOF'\nEOFcd /p && git commit -m y)\nEOF\n)\"",
        ] {
            assert!(!is_plain_shape(cmd, "/w", env), "{cmd:?}");
            assert!(command_heredocs_suspect(cmd), "{cmd:?}");
            assert!(
                sorted_targets(cmd, "/w").contains(&"/p".to_string()),
                "{cmd:?}"
            );
        }
        // A commit glued to the delimiter is found from the primary too.
        let glued = "x=$(cat <<'EOF'\nEOFgit commit -m y)\nEOF\n)";
        assert_eq!(sorted_targets(glued, "/p"), vec!["/p"]);
        // Past MAX_SUBSTITUTION_DELIMS the delimiters are unreadable: the
        // commit is judged from the session cwd and the scan is unresolved.
        let many: String = (0..=MAX_SUBSTITUTION_DELIMS)
            .map(|i| format!("x=$(cat <<'E{i}'\nE{i}\n)\n"))
            .collect();
        let hidden = format!("{many}y=$(cat <<'E0'\nE0cd /p && git commit -m y)\nE0\n)");
        assert_eq!(substitution_heredoc_delims(&hidden), None);
        let scan = scan_targets(&hidden, "/w", false);
        assert!(scan.unresolved_cd.is_some());
        assert!(scan.commits.contains(&"/w".to_string()));
        // A compact `EOF)` close still reads the message as data.
        let compact = "git commit -m \"$(cat <<'EOF'\nmsg\nEOF)\"";
        assert_eq!(sorted_targets(compact, "/w"), vec!["/w"]);
        assert!(scan_targets(compact, "/w", false).unresolved_cd.is_none());
        // The standard message carve-out is still plain and not suspect.
        let standard = "git commit -m \"$(cat <<'EOF'\nmsg (with parens)\nEOF\n)\"";
        assert!(is_plain_shape(standard, "/w", env));
        assert!(!command_heredocs_suspect(standard));
        assert_eq!(sorted_targets(standard, "/w"), vec!["/w"]);
    }

    #[test]
    fn an_escaped_quote_anywhere_with_a_heredoc_is_read_line_by_line() {
        // B3: an escaped quote inside the delimiter word (`<<"E\"F"` ends at
        // `E"F`), not only before the operator.
        let env = CdEnv::new(None, false);
        for cmd in [
            "cat <<\"E\\\"F\"\nE\"F\ncd /p\nEF\ngit commit -m x",
            // The body line's quote would also swallow every later line in
            // the joined reading.
            "cat <<\"E\\\"F\"\nE\"F\necho \"abc\n\" ; cd /p ; git commit -m x",
            "cat <<'E\\'F'\nE\\F\ncd /p\ngit commit -m x",
        ] {
            assert!(escapes_hide_a_heredoc(cmd), "{cmd:?}");
            assert!(!is_plain_shape(cmd, "/w", env), "{cmd:?}");
            assert!(
                sorted_targets(cmd, "/w").contains(&"/p".to_string()),
                "{cmd:?}"
            );
        }
        assert!(!escapes_hide_a_heredoc("echo \\\"x\\\" && git commit -m x"));
    }

    #[test]
    fn a_long_cd_chain_keeps_the_walked_path_bounded() {
        // PERF (#1058 review): the walk stored the unnormalized path, which
        // grew with every cd and was stat'ed each time — quadratic, and a 4 s
        // fail-open deadline away from a bypass.
        let unit = "cd sub && cd .. && ";
        let cmd = format!("{}git commit -m x", unit.repeat(100 * 1024 / unit.len()));
        let env = CdEnv::new(None, false);
        let plain = plain_of(&cmd, "/w", env).expect("plain");
        let mut longest = 0;
        let started = std::time::Instant::now();
        let walked = walk_plain(&plain, "/w", env, |seg| {
            for dir in seg.dirs {
                longest = longest.max(dir.pwd.len());
            }
        });
        assert!(walked.is_some());
        assert!(longest <= "/w/sub".len(), "{longest}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(sorted_targets(&cmd, "/w"), vec!["/w"]);
    }

    #[test]
    fn too_many_cd_fallbacks_are_not_plain() {
        // Each `cd` behind `true &&` adds its pre-cd directory as a fallback;
        // past MAX_CD_CANDIDATES the walk gives up to the union path.
        let cmd = "true && cd /a && true && cd /b && true && cd /c && true && cd /d \
                   && true && cd /e && git commit -m x";
        let env = CdEnv::new(None, false);
        let plain = plain_of(cmd, "/w", env).expect("plain shape");
        assert!(walk_plain(&plain, "/w", env, |_| {}).is_none());
        let got = sorted_targets(cmd, "/w");
        for dir in ["/w", "/a", "/e"] {
            assert!(got.contains(&dir.to_string()), "{dir}: {got:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn spec_conformance_repros_block_end_to_end() {
        let scratch = scratch("spec-conformance-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(primary.join("sub")).unwrap();
        std::fs::create_dir(primary.join("sub2")).unwrap();
        std::os::unix::fs::symlink(primary.join("sub"), wt.join("link")).unwrap();
        let p = primary.to_string_lossy().into_owned();
        let w = wt.to_string_lossy().into_owned();
        let from_w = [
            // B1
            format!("git commit -m \"$(cat <<'EOF'\nEOF cd {p} && git commit -m y)\nEOF\n)\""),
            format!("x=$(cat <<'EOF'\nEOF cd {p} && git commit -m y)\nEOF\n); git commit -m x"),
            format!("git commit -m $(cat <<'EOF'\nEOF)\ncd {p} && git commit -m y\nEOF\n)"),
            format!("git commit -m \"$(cat <<'EOF'\nEOFcd {p} && git commit -m y)\nEOF\n)\""),
            // B2: `link/..` is logically W, but W/sub2 and W/.git (a file in a
            // worktree) are not directories, so bash's cd goes physical.
            "cd link/../sub2 && git commit -m x".to_string(),
            "cd link/../sub2; git commit -m x".to_string(),
            "cd link/../.git && cd .. && git commit -m x".to_string(),
            // B3
            format!("cat <<\"E\\\"F\"\nE\"F\ncd {p}\nEF\ngit commit -m x"),
            format!("cat <<\"E\\\"F\"\nE\"F\necho \"abc\n\" ; cd {p} ; git commit -m x"),
        ];
        let from_p = [
            "cat <<\"E\\\"F\"\nE\"F\necho \"abc\n\" ; git commit -m x".to_string(),
            "x=$(cat <<'EOF'\nEOFgit commit -m y)\nEOF\n)".to_string(),
        ];
        for (cmds, cwd) in [(&from_w[..], &w), (&from_p[..], &p)] {
            for cmd in cmds {
                let mut input = make_bash(cmd);
                input.cwd = Some(cwd.clone());
                assert_eq!(
                    run_enforce(&input, &cfg(false, false)).outcome,
                    Outcome::Block,
                    "{cmd:?}"
                );
            }
        }
        let allowed = [
            (
                w.clone(),
                "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"".to_string(),
            ),
            (
                p.clone(),
                format!("cd {w} && git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\""),
            ),
            (w.clone(), "cd link/.. && git commit -m x".to_string()),
            (w.clone(), "cd sub && cd .. && git commit -m x".to_string()),
        ];
        for (cwd, cmd) in allowed {
            let mut input = make_bash(&cmd);
            input.cwd = Some(cwd);
            assert_eq!(
                run_enforce(&input, &cfg(false, false)).outcome,
                Outcome::Allow,
                "{cmd:?}"
            );
        }
    }

    /// Run `cmd` from `cwd` through the whole Bash arm.
    fn outcome_from(cwd: &Path, cmd: &str) -> Outcome {
        let mut input = make_bash(cmd);
        input.cwd = Some(cwd.to_string_lossy().into_owned());
        run_enforce(&input, &cfg(false, false)).outcome
    }

    #[test]
    fn a_cd_into_a_missing_directory_leaves_the_commit_in_the_primary() {
        // cadence-hooks#1102: bash's `cd` fails on a missing target and the
        // shell stays put, so a commit reached through `;`, a newline or `||`
        // runs in the primary. Behind `&&` it never runs.
        let scratch = scratch("missing-cd-1102");
        let (primary, wt) = primary_and_worktree(&scratch);
        let p = primary.to_string_lossy().into_owned();
        for cmd in [
            "cd nonexist; git commit -m x".to_string(),
            "cd \"}\"; git commit -m x".to_string(),
            "cd \\}; git commit -m x".to_string(),
            "cd }; git commit -m x".to_string(),
            "cd nonexist\ngit commit -m x".to_string(),
            "cd nonexist || true; git commit -m x".to_string(),
            "cd nonexist || git commit -m x".to_string(),
            format!("cd {p}/nonexist; git commit -m x"),
        ] {
            assert_eq!(outcome_from(&primary, &cmd), Outcome::Block, "{cmd:?}");
        }
        assert_eq!(
            outcome_from(&primary, "cd nonexist && git commit -m x"),
            Outcome::Allow
        );
        // From the worktree, into the primary and then a failed cd.
        for cmd in [
            format!("cd {p} && cd nonexist; git commit -m x"),
            format!("cd {p}; cd nonexist\ngit commit -m x"),
        ] {
            assert_eq!(outcome_from(&wt, &cmd), Outcome::Block, "{cmd:?}");
        }
        assert_eq!(
            outcome_from(&wt, "cd nonexist; git commit -m x"),
            Outcome::Allow
        );
    }

    #[test]
    fn env_options_parse_like_env() {
        let words = |s: &str| tokenize(s);
        let parsed = |s: &str| parse_env_flags(&words(s));
        let flags = parsed("-iC /p -u GIT_DIR --chdir=/q --unset X git commit").unwrap();
        assert_eq!(flags.consumed, 7);
        assert_eq!(flags.chdirs, vec!["/p", "/q"]);
        assert!(flags.clears);
        assert_eq!(flags.unsets, vec!["GIT_DIR", "X"]);
        assert_eq!(parsed("-C/p git").unwrap().chdirs, vec!["/p"]);
        assert_eq!(parsed("--chdir /p git").unwrap().chdirs, vec!["/p"]);
        assert_eq!(parsed("-- git").unwrap().consumed, 1);
        assert!(parsed("- git").unwrap().clears);
        // Unmodelled options, or no command after the options: unreadable.
        for rest in ["-S 'git commit'", "--argv0 x git", "-x git", "-i", "-C /p"] {
            assert_eq!(parsed(rest), None, "{rest}");
        }
        // Every option core's runner peel accepts is read to the same word.
        for rest in [
            "-i git",
            "-u X git",
            "-uX git",
            "-C /p git",
            "-0v git",
            "-P /b git",
        ] {
            let w = words(rest);
            let core = cadence_hooks_core::shell::skip_runner_flags("env", &w).unwrap();
            assert_eq!(parse_env_flags(&w).unwrap().consumed, w.len() - core.len());
        }
    }

    #[test]
    fn env_chdir_is_a_directory_change() {
        // cadence-hooks#1100: `env -C <dir>` runs its command in `<dir>`.
        let env = CdEnv::new(None, false);
        for cmd in [
            "env -C /p git commit -m x",
            "env --chdir=/p git commit -m x",
            "env --chdir /p git commit -m x",
            "env -C/p git commit -m x",
            "env -iC /p git commit -m x",
            "env -C / env -C p git commit -m x",
            "env -C /p sh -c 'git commit -m x'",
        ] {
            assert!(!is_plain_shape(cmd, "/w", env), "{cmd}");
            assert!(
                sorted_targets(cmd, "/w").contains(&"/p".to_string()),
                "{cmd}: {:?}",
                sorted_targets(cmd, "/w")
            );
        }
        // `env -C .. git -C p commit` lands in `/p` from `/w`.
        assert!(sorted_targets("env -C .. git -C p commit", "/w").contains(&"/p".to_string()));
        // An unreadable chdir is an unreadable cd.
        let scan = scan_targets("env -C \"$D\" git commit -m x", "/w", false);
        assert!(scan.unresolved_cd.is_some());
        // An env whose options cannot be read hides nothing.
        let scan = scan_targets("env -S 'git commit -m x'", "/w", false);
        assert!(scan.unreadable.is_some());
        assert!(scan.commits.contains(&"/w".to_string()));
    }

    #[test]
    fn env_clears_and_unsets_drop_inherited_git_overrides() {
        let targets = |cmd: &str| sorted_targets(cmd, "/w");
        assert_eq!(
            targets("GIT_DIR=/p/.git env -i git commit -m x"),
            vec!["/w"]
        );
        assert_eq!(
            targets("GIT_DIR=/p/.git env -u GIT_DIR git commit"),
            vec!["/w"]
        );
        assert_eq!(targets("GIT_DIR=/p/.git env -u FOO git commit"), vec!["/p"]);
        assert_eq!(
            targets("env -i GIT_DIR=/p/.git git commit -m x"),
            vec!["/p"]
        );
        assert_eq!(
            targets("env -u X GIT_WORK_TREE=/p git commit -m x"),
            vec!["/p"]
        );
    }

    #[test]
    fn chdir_landing_reads_only_what_it_can() {
        let env = CdEnv::new(Some("/h"), false);
        let land = |v: &str| chdir_landing(v, "/w", env);
        assert_eq!(land("$HOME/x").as_deref(), Some("/h/x"));
        assert_eq!(land("${HOME}/x").as_deref(), Some("/h/x"));
        assert_eq!(land("$HOME").as_deref(), Some("/h"));
        assert_eq!(land("sub").as_deref(), Some("/w/sub"));
        assert_eq!(land("/p").as_deref(), Some("/p"));
        for value in [
            "$VAR", "$VAR/x", "$HOMEX/x", "a$B", "`pwd`", "x*", "x?", "[ab]", "{a,b}", "~u/x",
            "~+", "~-",
        ] {
            assert_eq!(land(value), None, "{value}");
        }
        // No home to expand against: unreadable.
        let env = CdEnv::new(None, false);
        assert_eq!(chdir_landing("$HOME/x", "/w", env), None);
    }

    #[test]
    fn an_unreadable_git_directory_value_is_unreadable() {
        // cadence-hooks#1056: the value was joined onto the cwd as a literal
        // `$VAR`, naming no repo, and the commit was allowed.
        for cmd in [
            "git -C \"$V\" commit -m x",
            "git -C $V/sub commit -m x",
            "git --work-tree=\"$V\" commit -m x",
            "git --git-dir $V commit -m x",
            "GIT_DIR=$V git commit -m x",
            "git -C 'x*' commit -m x",
            "git -C ~nobody/x commit -m x",
            "cd /a && git -C \"$V\" commit -m x",
        ] {
            let scan = scan_targets(cmd, "/w", false);
            assert!(scan.unreadable.is_some(), "{cmd}");
            assert!(scan.commits.contains(&"/w".to_string()), "{cmd}");
        }
        // A readable value, or no commit, is not.
        for cmd in [
            "git -C sub commit -m x",
            "git -C \"$V\" log",
            "git -C ~/x commit",
        ] {
            assert!(scan_targets(cmd, "/w", false).unreadable.is_none(), "{cmd}");
        }
    }

    #[test]
    fn a_commit_in_a_trap_action_is_unreadable() {
        // cadence-hooks#1091: a trap runs where the shell is when the signal
        // fires, so a `cd` in it resolves from a directory the walk has not
        // collected yet.
        for cmd in [
            "trap 'git commit -m x' EXIT",
            "trap 'cd p && git commit -m x' EXIT; cd ..",
            "trap -- 'git -C p commit' INT; cd /a",
            "sh -c \"trap 'git commit -m x' EXIT\"",
        ] {
            let scan = scan_targets(cmd, "/w", false);
            assert!(scan.unreadable.is_some(), "{cmd}");
            assert!(scan.commits.contains(&"/w".to_string()), "{cmd}");
        }
        for cmd in ["trap 'echo hi' EXIT; git commit -m x", "trap - EXIT"] {
            assert!(scan_targets(cmd, "/w", false).unreadable.is_none(), "{cmd}");
        }
        // An eval'd cd is already an unreadable cd.
        let scan = scan_targets("eval 'cd /p'; git commit -m x", "/w", false);
        assert!(scan.unresolved_cd.is_some());
    }

    #[test]
    fn a_plainly_delimited_heredoc_body_is_not_read_as_code() {
        // cadence-hooks#1101: an escaped quote in a commit-message body made
        // the whole command suspect, and prose mentioning `cd` then read as
        // a `cd`.
        let env = CdEnv::new(None, false);
        for body in [
            "fix: handle \\\"quoted\\\" names\n\nthen cd .. and retry",
            "fix: say \\\"hi\\\"\n\nRun cd $HOME/foo first, or `cd -`.",
            "a \\'b\\' c\ncd /p",
        ] {
            let cmd = format!("git commit -m \"$(cat <<'EOF'\n{body}\nEOF\n)\"");
            assert!(!command_heredocs_suspect(&cmd), "{cmd:?}");
            assert!(is_plain_shape(&cmd, "/w", env), "{cmd:?}");
            assert_eq!(sorted_targets(&cmd, "/w"), vec!["/w"], "{cmd:?}");
            let scan = scan_targets(&cmd, "/w", false);
            assert!(scan.unresolved_cd.is_none(), "{cmd:?}");
        }
        // An escape outside the body keeps the command suspect, but the
        // line-by-line reads skip a plainly delimited body.
        for cmd in [
            "echo \\\"x\\\" && git commit -m \"$(cat <<'EOF'\nthen cd .. and retry\nEOF\n)\"",
            "echo \\\"x\\\"; git commit -F - <<'EOF'\nthen cd .. and retry\nEOF",
            "git commit -F - <<\"EOF\"\nfix \\\"x\\\"\nthen cd .. and retry\nEOF",
        ] {
            let scan = scan_targets(cmd, "/w", false);
            assert!(scan.unresolved_cd.is_none(), "{cmd:?}");
            assert_eq!(sorted_targets(cmd, "/w"), vec!["/w"], "{cmd:?}");
        }
        // A delimiter with an escape or an inner quote is not plainly read.
        for word in ["\"E\\\"F\"", "'E\\'F'", "E\\F", "'E'F'"] {
            let (heredoc, _) = parse_heredoc_operator(&format!("<<{word}\n")).unwrap();
            assert!(!heredoc.confident, "{word}");
        }
        for word in ["EOF", "'EOF'", "\"EOF\"", "END_MSG", "e-o.f"] {
            let (heredoc, _) = parse_heredoc_operator(&format!("<<{word}\n")).unwrap();
            assert!(heredoc.confident, "{word}");
        }
    }

    #[test]
    fn a_long_git_dash_c_chain_keeps_the_redirect_bounded() {
        // Each hop reads the path the last one built; past MAX_DASH_C_HOPS
        // the chain is unreadable instead of quadratic.
        for unit in ["-C sub -C .. ", "-C sub ", "-C link/.. "] {
            let cmd = format!("git {}commit -m x", unit.repeat(200 * 1024 / unit.len()));
            let started = std::time::Instant::now();
            let scan = scan_targets(&cmd, "/w", false);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "{unit}"
            );
            assert!(scan.unreadable.is_some(), "{unit}");
            assert!(scan.commits.contains(&"/w".to_string()), "{unit}");
        }
        let short = format!("git {}commit -m x", "-C sub -C .. ".repeat(8));
        assert_eq!(sorted_targets(&short, "/w"), vec!["/w"]);
        assert!(scan_targets(&short, "/w", false).unreadable.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn ew_followup_repros_block_end_to_end() {
        let scratch = scratch("ew-followups-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(primary.join("sub")).unwrap();
        std::fs::create_dir(primary.join("sub2")).unwrap();
        std::fs::create_dir(wt.join("sub")).unwrap();
        std::os::unix::fs::symlink(primary.join("sub"), wt.join("link")).unwrap();
        let p = primary.to_string_lossy().into_owned();
        let from_w = [
            // #1100 (a): git's chdir is physical.
            "git -C link/../sub2 commit -m x".to_string(),
            "git -C link/.. commit -m x".to_string(),
            "git -C link/../sub commit -m x".to_string(),
            "GIT_DIR=link/../.git git commit -m x".to_string(),
            "git --git-dir=link/../.git commit -m x".to_string(),
            // #1100 (b)
            format!("env -C {p} git commit -m x"),
            format!("env --chdir={p} git commit -m x"),
            format!("env --chdir {p} git commit -m x"),
            format!("env -iC {p} git commit -m x"),
            format!("env -C {p} sh -c 'git commit -m x'"),
            "env -C .. git -C repo commit -m x".to_string(),
            format!("GIT_DIR={p}/.git env -u FOO git commit -m x"),
            // #1091
            "trap 'cd repo && git commit -m x' EXIT; cd ..".to_string(),
            format!("trap 'git commit -m x' EXIT; cd {p}"),
            format!("eval 'cd {p}'; git commit -m x"),
            "eval 'cd ..'; git -C repo commit -m x".to_string(),
            // #1056
            "git -C \"$V\" commit -m x".to_string(),
            "git --work-tree=\"$V\" commit -m x".to_string(),
            "GIT_DIR=$V git commit -m x".to_string(),
            // #1101: the B3 repro still blocks.
            format!("cat <<\"E\\\"F\"\nE\"F\ncd {p}\nEF\ngit commit -m x"),
        ];
        for cmd in &from_w {
            assert_eq!(outcome_from(&wt, cmd), Outcome::Block, "{cmd:?}");
        }
        for cmd in ["git -C \"$V\" commit -m x", "env -i git commit -m x"] {
            assert_eq!(outcome_from(&primary, cmd), Outcome::Block, "{cmd:?}");
        }
        let allowed_from_w = [
            "git -C sub/.. commit -m x",
            "env -i git commit -m x",
            "GIT_DIR=link/../.git env -i git commit -m x",
            "trap 'echo done' EXIT; git commit -m x",
            "git commit -m \"$(cat <<'EOF'\nfix: handle \\\"quoted\\\" names\n\nthen cd .. and retry\nEOF\n)\"",
            "git commit -m \"$(cat <<'EOF'\nfix: say \\\"hi\\\"\n\nRun cd $HOME/foo first, or `cd -`.\nEOF\n)\"",
            "git commit -F - <<'EOF'\nfix \\\"x\\\"\nthen cd .. and retry\nEOF",
        ];
        for cmd in allowed_from_w {
            assert_eq!(outcome_from(&wt, cmd), Outcome::Allow, "{cmd:?}");
        }
        let w = wt.to_string_lossy().into_owned();
        let from_p = format!("cd {w} && git commit -m \"$(cat <<'EOF'\nfix: a \\\"b\\\"\nEOF\n)\"");
        assert_eq!(outcome_from(&primary, &from_p), Outcome::Allow);
    }

    #[cfg(unix)]
    #[test]
    fn the_six_common_flows_still_pass() {
        let scratch = scratch("six-flows");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(wt.join("sub")).unwrap();
        let w = wt.to_string_lossy().into_owned();
        let msg = "\"$(cat <<'EOF'\nfix: x\n\nbody\nEOF\n)\"";
        for (cwd, cmd) in [
            (
                &primary,
                "git worktree add .claude/worktrees/x -b x && cd .claude/worktrees/x && git commit -m x"
                    .to_string(),
            ),
            (&primary, format!("cd {w} && git commit -m {msg}")),
            (&wt, "cd sub && git commit -m x".to_string()),
            (&wt, "npm test 2>&1 | tail -3 && git commit -m x".to_string()),
            (&wt, "(cd sub && make) && git commit -m x".to_string()),
            (&primary, format!("git -C {w} commit -m x")),
        ] {
            assert_eq!(outcome_from(cwd, &cmd), Outcome::Allow, "{cmd:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn runner_and_interpreted_heredoc_repros_block_end_to_end() {
        let scratch = scratch("ew-runners-e2e");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(primary.join("sub")).unwrap();
        std::fs::create_dir(wt.join("sub")).unwrap();
        std::os::unix::fs::symlink(primary.join("sub"), wt.join("link")).unwrap();
        let p = primary.to_string_lossy().into_owned();
        let body = format!("cd {p} && git commit -m x");
        // cadence-hooks#1111: a commit behind a command runner, from P.
        let from_p = [
            "nice -n 5 git commit -m x",
            "timeout 5 git commit -m x",
            "timeout -s KILL 5 git commit -m x",
            "sudo -u root git commit -m x",
            "stdbuf -o0 git commit -m x",
            "nice -n 5 timeout 5 git commit -m x",
            "echo x | xargs git commit -m",
            "command nice -n 5 git commit -m x",
        ];
        for cmd in from_p {
            assert_eq!(outcome_from(&primary, cmd), Outcome::Block, "{cmd:?}");
        }
        let from_w = [
            // #1111
            format!("nice -n 5 git -C {p} commit -m x"),
            format!("timeout 5 git -C {p} commit -m x"),
            format!("sudo GIT_DIR={p}/.git git commit -m x"),
            // A runner option the peel cannot read is unreadable.
            format!("sudo -D {p} git commit -m x"),
            "timeout --weird 5 git commit -m x".to_string(),
            format!("echo {p} | xargs -I{{}} git -C {{}} commit -m x"),
            // #1113 item 1: a heredoc a shell runs.
            format!("cat <<'EOF' | sh\n{body}\nEOF"),
            format!("cat <<'EOF' | tee /dev/null | sh\n{body}\nEOF"),
            format!("cat <<'EOF' |& bash\n{body}\nEOF"),
            format!("cat <<'EOF' | sudo -u root bash -s\n{body}\nEOF"),
            format!("bash <<'EOF'\n{body}\nEOF"),
            format!("sh -s <<EOF\n{body}\nEOF"),
            format!("source /dev/stdin <<'EOF'\n{body}\nEOF"),
            format!(". /dev/stdin <<'EOF'\n{body}\nEOF"),
            format!("eval \"$(cat <<'EOF'\n{body}\nEOF\n)\""),
            format!("bash -c \"$(cat <<'EOF'\n{body}\nEOF\n)\""),
            format!("source <(cat <<'EOF'\n{body}\nEOF\n)"),
            format!("cat <<'EOF' | bash -s\ncd {p}\ngit commit -m x\nEOF"),
            format!("bash <<'EOF'\nexport GIT_DIR={p}/.git\ngit commit -m x\nEOF"),
            format!("{{ cat <<EOF; }} | sh\n{body}\nEOF"),
            format!("cat <<EOF | $SHELL\n{body}\nEOF"),
            format!("cat <<EOF |\n{body}\nEOF\nsh"),
            format!("bash <<A\ncat <<B | sh\n{body}\nB\nA"),
            // #1113 item 2: `..` through a symlink into a directory the
            // command creates.
            "mkdir link/../nd && git -C link/../nd commit -m x".to_string(),
            "mkdir -p link/../nd/deep && git -C link/../nd/deep commit -m x".to_string(),
            "mkdir link/../nd && env -C link/../nd git commit -m x".to_string(),
            "mkdir link/../nd && GIT_WORK_TREE=link/../nd git commit -m x".to_string(),
            "mkdir -p link/../nd && cd link/../nd && git commit -m x".to_string(),
            // #1113 item 3: `~` after HOME is rebound.
            format!("HOME={p}; git -C ~ commit -m x"),
            format!("HOME={p}; cd ~ && git commit -m x"),
            format!("HOME={p} && cd ~/sub && git commit -m x"),
            format!("export HOME={p}; cd ~ && git commit -m x"),
            format!("h=HO; export ${{h}}ME={p}; cd ~ && git commit -m x"),
            // #1113 item 4: an exported git variable.
            format!("export GIT_DIR={p}/.git; git commit -m x"),
            format!("GIT_DIR={p}/.git; export GIT_DIR; git commit -m x"),
            format!("export GIT_WORK_TREE={p} GIT_DIR={p}/.git && git commit -m x"),
            format!("declare -x GIT_DIR={p}/.git; git commit -m x"),
            format!("set -a; GIT_DIR={p}/.git; git commit -m x"),
            "read GIT_DIR; git commit -m x".to_string(),
            "export ${v}_DIR=x; git commit -m x".to_string(),
            // #1113 item 5: a backslash-newline splits the delimiter.
            format!("cat <<EOF >/dev/null\nEO\\\nF\n{body}\nEOF"),
            format!("cat <<EOF\nEO\\\nF\n{body}\nEOF"),
            // #1122: a continuation that destroys a delimiter. Bash reads
            // `xEOF`, so the body runs on to the second `EOF` and the commit
            // after it runs, behind a heredoc opener that is really body text.
            format!("cat <<EOF\nx\\\nEOF\n: <<EOG\nEOF\n{body}\nEOG"),
            format!("cat <<EOF\nx\\\nEOF\ncat <<'EOG'\nEOF\n{body}\nEOG"),
        ];
        for cmd in &from_w {
            assert_eq!(outcome_from(&wt, cmd), Outcome::Block, "{cmd:?}");
        }
        let w = wt.to_string_lossy().into_owned();
        let allowed_from_w = [
            "nice -n 5 git commit -m x".to_string(),
            "timeout 5 git commit -m x".to_string(),
            "stdbuf -oL git commit -m x".to_string(),
            "nice -n 10 cargo test 2>&1 | tail -3 && git commit -m x".to_string(),
            "cat <<'EOF' | sh\necho hi\nEOF\ngit commit -m x".to_string(),
            "git commit -F - <<EOF\nuse bash <<X then cd .. please\nEOF".to_string(),
            "timeout 60 git commit -F - <<'EOF'\nfix: it's (really) done; cd .. and \\\"bash\\\" it\nEOF"
                .to_string(),
            "git commit -m \"$(cat <<'EOF'\nit's got \\\"quotes\\\" and (parens)\ncd .. && bash <<X\nEOF\n)\""
                .to_string(),
            "cat <<EOF >/dev/null\nfoo \\\nbar\nEOF\ngit commit -m x".to_string(),
            "cd ~ && cd sub && git commit -m x".to_string(),
            "export FOO=1 && git commit -m x".to_string(),
            format!("export GIT_DIR={w}/.git && git commit -m x"),
            "GIT_DIR=../repo/.git; git commit -m x".to_string(),
        ];
        for cmd in &allowed_from_w {
            assert_eq!(outcome_from(&wt, cmd), Outcome::Allow, "{cmd:?}");
        }
        for cmd in [
            format!("cd {w} && timeout 5 git commit -m x"),
            format!("cd {w} && sudo -u root git commit -m x"),
        ] {
            assert_eq!(outcome_from(&primary, &cmd), Outcome::Allow, "{cmd:?}");
        }
    }

    #[test]
    fn a_runner_never_widens_the_in_chain_dismiss() {
        // cadence-hooks#1111: runners are peeled to find a commit, but a
        // dismiss behind one is not the command's own, so it licenses nothing.
        let dismiss = "cadence-hooks guardrails dismiss-enforce-worktree --for 30m";
        let bare = format!("{dismiss} && git commit -m x");
        assert!(!inchain_dismissed_commits(&bare, "/cwd", false).is_empty());
        for runner in ["sudo -u root", "nice -n 5", "timeout 5"] {
            for cmd in [
                format!("{runner} {dismiss} && git commit -m x"),
                format!("{runner} {dismiss} && export A=1 && git commit -m x"),
            ] {
                assert!(
                    inchain_dismissed_commits(&cmd, "/cwd", false).is_empty(),
                    "{cmd}"
                );
            }
        }
        // The commit behind a runner is still licensed by a bare dismiss.
        let cmd = format!("{dismiss} && nice -n 5 git commit -m x");
        assert!(!inchain_dismissed_commits(&cmd, "/cwd", false).is_empty());
    }

    #[test]
    fn heredoc_interpretation_reads_the_command_and_its_pipes() {
        for (line, interpreted) in [
            ("cat <<'EOF' | sh", true),
            ("cat <<EOF | tee x | bash -s", true),
            ("cat <<EOF |& bash", true),
            ("cat <<EOF | xargs -0 sh -c", true),
            ("bash <<'EOF'", true),
            ("/bin/zsh -s <<EOF", true),
            ("sudo -u me bash <<EOF", true),
            ("source /dev/stdin <<EOF", true),
            (". /dev/stdin <<EOF", true),
            ("eval \"$(cat <<'EOF'", true),
            ("bash -c \"$(cat <<'EOF'", true),
            ("source <(cat <<'EOF'", true),
            ("x=1 bash <<EOF", true),
            ("{ cat <<EOF; } | sh", true),
            ("(cat <<EOF) | sh", true),
            ("cat <<EOF |", true),
            ("cat <<EOF | $SHELL", true),
            ("cat <<EOF | $(which sh)", true),
            ("cat <<EOF | s\\h", true),
            ("\"$(cat <<'EOF'", true),
            ("x=$(cat <<'EOF'", false),
            ("git commit -m \"$(cat <<'EOF'", false),
            ("git commit -F - <<'EOF'", false),
            ("cd /w && git commit -F - <<'EOF'", false),
            ("bash x.sh; cat <<EOF", false),
            ("cat <<EOF > f && bash f", false),
            ("cat <<EOF || sh", false),
            ("python3 - <<'EOF'", false),
        ] {
            let got = heredocs_on_line(line).unwrap();
            assert_eq!(got.len(), 1, "{line}");
            assert_eq!(got[0].1, interpreted, "{line}");
        }
        let bodies = interpreted_heredoc_bodies(
            "cat <<A | sh\ncd /p\nA\ncat <<B\ncd /q\nB\nbash <<-C\n\tx\n\tC",
        )
        .unwrap();
        assert_eq!(bodies, vec!["cd /p\n".to_string(), "\tx\n".to_string()]);
        // A body a shell runs is read again for heredocs it runs.
        let bodies = interpreted_heredoc_bodies("bash <<A\ncat <<B | sh\ncd /p\nB\nA").unwrap();
        assert_eq!(bodies[1], "cd /p\n");
        let deep = "bash <<A\nbash <<B\nbash <<C\nbash <<D\ncd /p\nD\nC\nB\nA";
        assert!(interpreted_heredoc_bodies(deep).is_none());
    }

    #[test]
    fn a_continued_line_splits_a_heredoc_delimiter() {
        for (body, splits) in [
            ("EO\\\nF\n", true),
            ("E\\\nO\\\nF\n", true),
            // Joined, it is still the delimiter, on the same line.
            ("\\\nEOF\n", false),
            ("EO\\\\\nF\n", false),
            ("aEO\\\nF\n", false),
            ("EOF\\\nx\n", false),
            ("foo \\\nbar\n", false),
            // #1122, the reverse: the continuation joins text onto a line that
            // reads as the delimiter, so bash's body runs on.
            ("x\\\nEOF\n", true),
            ("foo \\\nx\\\nEOF\n", true),
        ] {
            let cmd = format!("cat <<EOF\n{body}git commit -m x\nEOF");
            assert_eq!(continuation_splits_a_delimiter(&cmd), splits, "{body:?}");
            let quoted = format!("cat <<'EOF'\n{body}git commit -m x\nEOF");
            assert!(!continuation_splits_a_delimiter(&quoted), "{body:?}");
        }
    }

    #[test]
    fn a_tilde_reads_as_home_only_when_nothing_rebinds_it() {
        for (cmd, home) in [
            ("cd ~/x && git commit -m x", true),
            ("cd ~ && ls $HOME && git commit -m x", true),
            (
                "cd ~/w && git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"",
                true,
            ),
            ("export FOO=1; cd ~ && git commit", true),
            ("HOME=/p; cd ~", false),
            ("export HOME=/p; cd ~", false),
            ("export \"HO\"ME=/p; cd ~", false),
            ("export H\\OME=/p; cd ~", false),
            ("h=HO; export ${h}ME=/p; cd ~", false),
            ("v=x; printf -v \"$v\" y; cd ~", false),
            ("test -v \"a[${v}=1]\"; cd ~", false),
            ("echo $(( ${v}=1 )); cd ~", false),
        ] {
            assert_eq!(tilde_is_home(cmd), home, "{cmd}");
        }
    }

    #[test]
    fn git_exports_read_every_exporting_shape() {
        let got = |cmd: &str| {
            let e = git_exports(cmd);
            (e.git_dirs, e.work_trees, e.unreadable.is_some())
        };
        let none: Vec<String> = Vec::new();
        for (cmd, dirs, trees, unreadable) in [
            (
                "export GIT_DIR=/p/.git; git commit",
                vec!["/p/.git"],
                vec![],
                false,
            ),
            (
                "GIT_DIR=/p/.git; export GIT_DIR",
                vec!["/p/.git"],
                vec![],
                false,
            ),
            ("export GIT_WORK_TREE=/p", vec![], vec!["/p"], false),
            ("declare -x GIT_DIR=/p", vec!["/p"], vec![], false),
            ("typeset -gx GIT_DIR=/p", vec!["/p"], vec![], false),
            ("set -a; GIT_DIR=/p", vec!["/p"], vec![], false),
            (
                "sh -c 'export GIT_DIR=/p; git commit'",
                vec!["/p"],
                vec![],
                false,
            ),
            ("GIT_DIR=/p; git commit", vec![], vec![], false),
            ("declare GIT_DIR=/p", vec![], vec![], false),
            ("readonly GIT_DIR=/p", vec![], vec![], false),
            ("GIT_DIR=/p git commit", vec![], vec![], false),
            ("read GIT_DIR", vec![], vec![], true),
            ("printf -v GIT_WORK_TREE %s /p", vec![], vec![], true),
            ("export ${v}_DIR=/p", vec![], vec![], true),
            ("unset GIT_DIR", vec![], vec![], false),
        ] {
            let dirs: Vec<String> = dirs.into_iter().map(String::from).collect();
            let trees: Vec<String> = trees.into_iter().map(String::from).collect();
            assert_eq!(got(cmd), (dirs, trees, unreadable), "{cmd}");
        }
        assert_eq!(got("git commit -m x"), (none.clone(), none, false));
    }

    #[test]
    fn runners_peel_to_the_command_and_unreadable_ones_stay_the_head() {
        let words = |s: &str| tokenize(s);
        for (cmd, head) in [
            ("nice -n 5 git commit", "git"),
            ("nice -10 git commit", "git"),
            ("timeout 5 git commit", "git"),
            ("timeout -k 1 -s KILL 5 git commit", "git"),
            ("sudo -u root -E git commit", "git"),
            ("stdbuf -o0 -eL git commit", "git"),
            ("xargs -0 -n1 git commit", "git"),
            ("env -i nice -n 5 sudo git commit", "git"),
            ("sudo -D /p git commit", "sudo"),
            ("timeout --weird 5 git commit", "timeout"),
            ("nice -x git commit", "nice"),
        ] {
            let w = words(cmd);
            let argv = peel_command_prefixes(&w);
            assert_eq!(argv.first().map(String::as_str), Some(head), "{cmd}");
            assert_eq!(is_unreadable_runner(argv), head != "git", "{cmd}");
        }
        // The dismiss view keeps the runner.
        let w = words("sudo cadence-hooks guardrails dismiss-enforce-worktree");
        assert_eq!(peel_heads(&w, false).0[0], "sudo");
        let w = words("sudo -u root GIT_DIR=/p/.git git commit");
        assert_eq!(git_env_overrides(&w), (None, Some("/p/.git")));
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_through_a_symlink_diverges_even_when_the_target_is_missing() {
        let scratch = scratch("dotdot-missing");
        let (primary, wt) = primary_and_worktree(&scratch);
        std::fs::create_dir(primary.join("sub")).unwrap();
        std::fs::create_dir(wt.join("sub")).unwrap();
        std::os::unix::fs::symlink(primary.join("sub"), wt.join("link")).unwrap();
        let env = CdEnv::new(None, true);
        let w = wt.to_string_lossy().into_owned();
        for (rel, diverges) in [
            ("link/../nd", true),
            ("link/../nd/deep/er", true),
            ("link/..", true),
            ("link/../sub", true),
            ("sub/../nd", false),
            ("nd/../sub", false),
            ("link/nd", false),
            ("nd", false),
        ] {
            assert_eq!(
                dotdot_diverges(&format!("{w}/{rel}"), env),
                diverges,
                "{rel}"
            );
        }
        let long = format!("{w}/{}", "sub/".repeat(MAX_PHYSICAL_COMPONENTS) + "..");
        assert!(dotdot_diverges(&long, env));
    }

    #[test]
    fn adversarial_inputs_for_the_1111_and_1113_readings_stay_fast() {
        let n = 200 * 1024;
        let rep = |unit: &str, tail: &str| format!("{}{tail}", unit.repeat(n / unit.len()));
        for cmd in [
            rep("cat <<a | sh\n", "\ngit commit -m x"),
            rep("(", "cat <<a | sh\ncd /x && git commit\na\n"),
            rep("x | ", "cat <<a | sh\ncd /x && git commit\na\n"),
            format!("cat <<a {}", rep("| ", "sh\ncd /x\na\ngit commit -m x")),
            rep("<<a ", "\ngit commit -m x"),
            rep("$(cat <<a ", "\ngit commit -m x"),
            format!(
                "bash <<'E'\n{}",
                rep("cd sub && cd .. && ", "git commit\nE\n")
            ),
            format!("git -C {}", rep("link/../", "sub commit -m x")),
            rep("export GIT_DIR=/p/.git; ", "git commit -m x"),
            rep("GIT_DIR=/a; export GIT_DIR; ", "git commit -m x"),
            rep("HOME=/x; ", "cd ~ && git commit -m x"),
            format!(
                "cat <<EOF\n{}",
                rep("a\\\n", "EO\\\nF\ngit commit -m x\nEOF")
            ),
            rep("nice -n 5 ", "git commit -m x"),
            rep("sudo -u root ", "git commit -m x"),
            rep("bash <<a\ncd /x\na\n", "git commit -m x"),
        ] {
            let started = std::time::Instant::now();
            let _ = scan_targets(&cmd, "/w", false);
            let _ = inchain_dismissed_commits(&cmd, "/w", false);
            // Wall-clock only: 4 s is the hook's budget in the shipped release
            // build. An unoptimized build under a loaded parallel suite hit
            // 4.36 s on one input with no algorithmic change (PR #1118), so
            // debug gets headroom; a return to quadratic work still trips it.
            let limit = std::time::Duration::from_secs(if cfg!(debug_assertions) { 12 } else { 4 });
            assert!(
                started.elapsed() < limit,
                "{:?}: {:?}",
                &cmd[..40],
                started.elapsed()
            );
        }
    }
}
