//! `pathclass` — a shared `path → class` map for the git/branch guard family.
//!
//! Repo-root resolution, path-class membership, and the lexical `..`
//! normalization every carve-out depends on were each re-derived and
//! inconsistently applied across `enforce_worktree`, `warn_main_branch`,
//! `warn_subagent_worktree`, and `guard_rm` — the root gap behind a string of
//! false-positive incidents (cadence-hooks#164). This module is the single,
//! tested notion of "what kind of path is this?" It exposes **facts, not
//! policy**: it returns a [`PathClass`], and each guard keeps its own policy
//! (and its own fail-direction) over that fact.
//!
//! The prototype is `guard_rm`'s `classify_path`/`TargetClass` (shipped 0.53.0),
//! which this generalizes and makes reusable. `guard_rm` is the first consumer.
//!
//! **ALLOW-before-BLOCK ordering is load-bearing.** A scratch target under a
//! protected ancestor — a git worktree under `.claude`, a repo checked out in
//! `/tmp` — must resolve to its allow-granting class *before* an escalating
//! block-class (git-root, home-child) can match. [`classify`] preserves that
//! precedence, mirroring the prototype.
//!
//! **Lexical `..` normalization is folded in** ([`normalize`]) so no carve-out
//! ever matches an uncanonicalized path (cadence-hooks#152) — a crafted
//! `.claude/../src` normalizes to `…/src` and does not spoof the `.claude`
//! carve-out.
//!
//! **v1 scope (cadence-hooks#164 D5): live-consumer classes only.** Ships
//! [`PathClass::Temp`], [`PathClass::ClaudeScratch`], [`PathClass::DocsPlans`],
//! [`PathClass::HomeChild`], [`PathClass::GitRoot`], and the residual
//! [`PathClass::Source`]. The `memory` and `vault` classes are deferred to land
//! with their second consumer — `guard_rm` is their only consumer today, so
//! those stay guard-local (YAGNI) until a second guard needs them.
//!
//! **The `.claude` carve-out is an allowlist of session scratch, not the whole
//! tree.** It once granted the ALLOW class to *any* path under a `.claude`
//! component, which read as "Claude's own working directory" but is false in
//! practice: `~/.claude` holds ~40 entries and a repo's `.claude` holds a dozen,
//! nearly all durable and none of it git-tracked — session transcripts
//! (`projects/`), the `metrics` audit trail, `skills`, `rules`, `hooks`,
//! `agents`, `plugins`, and both memory trees. Only
//! [`CLAUDE_SCRATCH_DIRS`] earn the class now; anything else under `.claude`
//! falls through to the structural classes, so a directory nobody has vetted is
//! ambiguous by default rather than silently disposable.

use crate::normalize_path;
use crate::worktree::path_under_temp_root;
use std::path::Path;

/// The class of a resolved path — a **fact**, never a verdict. Guards map a
/// class to their own allow/block/ask policy; the classifier itself takes no
/// position on what should happen.
///
/// [`classify`] returns exactly one class per path, resolved by a load-bearing
/// precedence (see the module docs): the allow-granting carve-outs
/// ([`Temp`](PathClass::Temp), [`ClaudeScratch`](PathClass::ClaudeScratch)) —
/// the two with a live ALLOW consumer — resolve first, then the structural
/// classes ([`HomeChild`](PathClass::HomeChild), [`GitRoot`](PathClass::GitRoot)),
/// then [`DocsPlans`](PathClass::DocsPlans), then the residual
/// [`Source`](PathClass::Source). `DocsPlans` sits *below* `GitRoot` on purpose:
/// it has no ALLOW consumer yet, so a `docs/plans` path that is also a git root
/// must report the git-root fact (or guard_rm would downgrade a BLOCK to ASK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// Under a temp root (`/tmp`, `/private/tmp`, `$TMPDIR`).
    Temp,
    /// Session scratch inside a `.claude/` directory: strictly *under* one of
    /// the [`CLAUDE_SCRATCH_DIRS`] — a single worktree
    /// (`.claude/worktrees/feat-x`) or a session intro
    /// (`.claude/intros/2026-01-01-foo.md`).
    ///
    /// Two exclusions are deliberate, and both keep a whole-tree delete out of
    /// the ALLOW: the `.claude` dir itself is not this class, and neither is a
    /// scratch dir itself — `.claude/worktrees` is *every* worktree at once,
    /// including whatever is uncommitted in them, which is not the
    /// one-disposable-thing case this class exists for. Both fall through to
    /// the structural classes.
    ClaudeScratch,
    /// Under a `docs/plans/` directory (consecutive `docs` then `plans`
    /// components). Cadence mandates copying approved plans there on the default
    /// branch, so plan-doc work is exempt from the branch-worthy-change guards.
    DocsPlans,
    /// A first-level entry directly under the user's home (`~/Documents`,
    /// `~/.zshrc`) — one component below home.
    HomeChild,
    /// A git repo root (has a `.git` child, per the injected probe) or any path
    /// carrying a `.git` component.
    GitRoot,
    /// Under a `.claude/` directory but **not** session scratch: the durable,
    /// untracked half of the tree — session transcripts, the metrics audit
    /// trail, skills, rules, hooks, agents, plugins, and both memory trees.
    ///
    /// Distinct from [`Source`] on purpose. Both mean "not proven safe", but a
    /// consumer that *softens* its `Source` verdict — guard_rm allows a
    /// single-file delete in the ambiguous middle — must not soften this one: a
    /// lone session transcript is still the only copy of that transcript.
    /// Separating them is what keeps a softening rule from silently re-opening
    /// the subtree the scratch allowlist just closed.
    ///
    /// Sits below the structural classes, so `~/.claude/.git` still reports
    /// [`GitRoot`](PathClass::GitRoot) and `~/.claude` itself still reports
    /// [`HomeChild`](PathClass::HomeChild) — but **above**
    /// [`DocsPlans`](PathClass::DocsPlans), which has no ALLOW consumer and so
    /// reads as the ambiguous middle to guard_rm.
    ClaudeState,
    /// The residual: an ordinary path matching no more-specific class.
    Source,
}

/// Resolved environment context for [`classify`], injected so the classifier
/// stays pure and table-testable (no env reads; the one impure step is
/// `path_under_temp_root`'s `$TMPDIR` canonicalization).
pub struct PathClassContext<'a> {
    /// Home directory, normalized (no trailing slash). Empty disables the
    /// home-child rule.
    pub home: &'a str,
    /// `$TMPDIR`, for the temp-root rule.
    pub tmpdir: Option<&'a str>,
}

/// Normalize `path` for carve-out matching: forward-slash / null / trailing-slash
/// cleanup (via [`normalize_path`]) **plus** lexical resolution of `.` and `..`
/// segments (cadence-hooks#152), so a crafted `foo/.claude/../src` cannot spoof
/// a `.claude` carve-out. Purely lexical — no filesystem access, so it holds for
/// a not-yet-created path — and never walks above the root (a leading `..` with
/// nothing to pop is dropped, matching `worktree::normalized_components`).
pub fn normalize(path: &str) -> String {
    let base = normalize_path(path);
    let leading = base.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in base.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if leading {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Classify `path` into its single most-specific [`PathClass`].
///
/// `path` is normalized internally via [`normalize`] (idempotent, so a caller
/// that already normalized pays only a cheap re-scan). `is_git_root` is injected
/// — the production probe stats `<path>/.git`; tests stub it — so this stays
/// pure. The precedence is load-bearing; see the module and [`PathClass`] docs.
pub fn classify(
    path: &str,
    ctx: &PathClassContext,
    is_git_root: &dyn Fn(&str) -> bool,
) -> PathClass {
    let norm = normalize(path);

    // Allow-granting carve-outs first — `Temp` and `ClaudeScratch` are the only
    // classes with a live ALLOW consumer (guard_rm), so they must out-rank the
    // escalating structural classes: a scratch target under a protected
    // ancestor (a worktree under `.claude`, a repo in `/tmp`) resolves to its
    // allow-class before git-root can match. This ordering is load-bearing and
    // locked by `claude_scratch_wins_over_git_root_probe`.
    if path_under_temp_root(Path::new(&norm), ctx.tmpdir, Some(ctx.home)) {
        return PathClass::Temp;
    }
    if under_claude_scratch(&norm) {
        return PathClass::ClaudeScratch;
    }

    // Structural classes. HomeChild resolves before GitRoot so a home-child that
    // is also a repo root (`~/myrepo` with a `.git`) reports the home-child fact
    // — the prototype's order, preserved so a consumer's message wording holds.
    if is_first_level_home_child(&norm, ctx.home) {
        return PathClass::HomeChild;
    }
    // GitRoot resolves BEFORE DocsPlans, unlike the allow-classes above.
    // `DocsPlans` has no live ALLOW consumer yet (guard_rm treats it as the
    // ambiguous middle, exactly like `Source`), so a path that is *both* under
    // `docs/plans/` and a git root must report the git-root fact — otherwise
    // guard_rm, which has no `DocsPlans` arm, would downgrade a real
    // `.git`-bearing delete target from BLOCK to ASK, breaking the
    // byte-identical contract (a docs/plans path that is also a git repo).
    // Locked by `git_root_under_docs_plans_reports_git_root`.
    if has_git_component(&norm) || is_git_root(&norm) {
        return PathClass::GitRoot;
    }
    // Everything else under `.claude` is durable state. Below the structural
    // classes — so `~/.claude/.git` still reports git-root and `~/.claude`
    // itself still reports home-child — but ABOVE `DocsPlans`, which has no
    // ALLOW consumer and therefore reads as the ambiguous middle to guard_rm.
    // With the order reversed, `~/.claude/docs/plans/x.md` reported `DocsPlans`
    // and rode guard_rm's single-file softening to a silent ALLOW, defeating
    // this class for exactly the subtree it was added to protect.
    if under_claude_dir(&norm) {
        return PathClass::ClaudeState;
    }
    if under_docs_plans(&norm) {
        return PathClass::DocsPlans;
    }

    PathClass::Source
}

/// `.claude` appears as a path component AND is not the final one — the path
/// lives *under* a `.claude` dir rather than being it. The coarse fact;
/// [`under_claude_scratch`] is the narrow allowlist within it.
fn under_claude_dir(norm: &str) -> bool {
    let segs: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    match segs.iter().position(|s| *s == ".claude") {
        Some(pos) => pos + 1 < segs.len(),
        None => false,
    }
}

/// The subdirectories of a `.claude/` root that hold genuine session scratch —
/// content regenerated per session that is never the only copy of anything.
///
/// `worktrees` holds cadence's git worktrees: a worktree is a checkout, and
/// removing one loses nothing its repo does not already have. `intros` holds
/// gitignored session kickoff notes that `cadence:tend` reclaims as routine
/// housekeeping.
///
/// Everything else under `.claude` is durable state and deliberately absent:
/// `projects` (every session transcript), `metrics` (the audit trail these
/// guards write), `skills`, `rules`, `hooks`, `agents`, `commands`, `plugins`,
/// `sessions`, `memory`, and `agent-memory`. None of it is git-tracked, so a
/// delete there is unrecoverable outside a filesystem snapshot.
///
/// This is an **allowlist on purpose**: an unrecognized directory under
/// `.claude` should cost a permission prompt, not a silent delete. Adding an
/// entry here grants a silent ALLOW over that subtree — do it only for content
/// that is provably regenerable.
pub const CLAUDE_SCRATCH_DIRS: &[&str] = &["worktrees", "intros"];

/// The path lives strictly *under* a `.claude/<scratch>/` directory for a
/// recognized [`CLAUDE_SCRATCH_DIRS`] entry. Operates on the `normalize`d form,
/// so a `.` segment is a no-op and a `..` cannot spoof it.
///
/// Requires a component *after* the scratch dir, so the scratch dir itself
/// (`.claude/worktrees`) is excluded — deleting it takes every worktree at once,
/// which is not the single-disposable-item case. Mirrors the `.claude` dir's own
/// exclusion one level down.
///
/// Public because [`classify`] tests `Temp` FIRST, so a scratch path that also
/// lives under a temp root reports [`PathClass::Temp`] and the scratch fact is
/// unreachable from the returned class. `guardrails::guard_rm` needs that fact
/// to keep worktree cleanup allowed while blocking a plain repo under `/tmp`
/// (cadence-hooks#576), and asking here is cheaper and safer than reordering a
/// precedence three tests already lock.
pub fn under_claude_scratch(norm: &str) -> bool {
    let segs: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    let Some(pos) = segs.iter().position(|s| *s == ".claude") else {
        return false;
    };
    let Some(scratch) = segs.get(pos + 1) else {
        return false;
    };
    // `pos + 2 < len` is the "something after the scratch dir" requirement.
    CLAUDE_SCRATCH_DIRS.contains(scratch) && pos + 2 < segs.len()
}

/// Consecutive `docs` then `plans` components appear anywhere in `norm`.
fn under_docs_plans(norm: &str) -> bool {
    let segs: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    segs.windows(2).any(|w| w[0] == "docs" && w[1] == "plans")
}

/// `norm` is a first-level entry directly under `home` (one component below).
fn is_first_level_home_child(norm: &str, home: &str) -> bool {
    if home.is_empty() {
        return false;
    }
    let prefix = format!("{home}/");
    norm.strip_prefix(&prefix)
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

/// Any `/`-separated segment of `norm` is `.git`, compared case-insensitively.
///
/// Case-insensitive volumes (the APFS default) resolve `.GIT` to the real
/// `.git`, so a case-sensitive match let `.GIT` walk past GitRoot protection.
/// Folding only ever promotes a path *into* GitRoot, never out of it, so on a
/// case-sensitive volume the worst outcome is protecting a directory that
/// merely looks like a repo.
fn has_git_component(norm: &str) -> bool {
    norm.split('/').any(|seg| seg.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context with a fixed home and no tmpdir.
    fn ctx(home: &str) -> PathClassContext<'_> {
        PathClassContext { home, tmpdir: None }
    }

    /// Classify with no git roots on disk.
    fn class(path: &str, home: &str) -> PathClass {
        classify(path, &ctx(home), &|_| false)
    }

    // --- normalize (folds in #152's `..` resolution) ---

    #[test]
    fn normalize_resolves_dot_and_parent() {
        assert_eq!(normalize("/a/b/../c"), "/a/c");
        assert_eq!(normalize("/a/./b"), "/a/b");
        assert_eq!(normalize("/a/b/../../c"), "/c");
    }

    #[test]
    fn normalize_collapses_empty_segments_and_trailing() {
        assert_eq!(normalize("/a//b/"), "/a/b");
        assert_eq!(normalize("a/b/"), "a/b");
    }

    #[test]
    fn normalize_leading_parent_has_nothing_to_pop() {
        // A leading `..` with no preceding component is dropped, never escaping
        // above the root — mirrors worktree::normalized_components.
        assert_eq!(normalize("../a/b"), "a/b");
        assert_eq!(normalize("/../a"), "/a");
    }

    #[test]
    fn normalize_backslashes_to_slashes() {
        assert_eq!(normalize(r"C:\Users\x"), "C:/Users/x");
    }

    #[test]
    fn claude_parentdir_escape_is_not_claude_managed() {
        // #152: a `..` escaping the `.claude` segment must not spoof the carve-out.
        assert_eq!(
            class("/Users/x/repo/.claude/../src", "/Users/x"),
            PathClass::Source
        );
    }

    #[test]
    fn docs_plans_parentdir_escape_is_not_plan_doc() {
        assert_eq!(
            class("/Users/x/repo/docs/plans/../../src", "/Users/x"),
            PathClass::Source
        );
    }

    // --- Temp ---

    #[test]
    fn temp_absolute_is_temp() {
        assert_eq!(class("/tmp/scratch", "/Users/x"), PathClass::Temp);
        assert_eq!(class("/private/tmp/y", "/Users/x"), PathClass::Temp);
    }

    #[test]
    fn tmp_lookalike_is_not_temp() {
        assert_eq!(class("/tmpfoo/x", "/Users/x"), PathClass::Source);
    }

    // --- ClaudeScratch (strictly under a recognized scratch dir) ---

    #[test]
    fn under_claude_scratch_dir_is_scratch() {
        assert_eq!(
            class("/srv/repo/.claude/worktrees/x", "/Users/x"),
            PathClass::ClaudeScratch
        );
        assert_eq!(
            class("/srv/repo/.claude/intros/2026-01-01-foo.md", "/Users/x"),
            PathClass::ClaudeScratch
        );
    }

    #[test]
    fn claude_dir_itself_is_not_scratch() {
        // `~/.claude` the dir itself is a home child, not "under .claude".
        assert_eq!(class("/Users/x/.claude", "/Users/x"), PathClass::HomeChild);
    }

    #[test]
    fn scratch_dir_itself_is_not_scratch() {
        // `.claude/worktrees` is EVERY worktree at once — not the single
        // disposable item the class exists for, so it falls through.
        assert_eq!(
            class("/srv/repo/.claude/worktrees", "/Users/x"),
            PathClass::ClaudeState
        );
        assert_eq!(
            class("/srv/repo/.claude/intros", "/Users/x"),
            PathClass::ClaudeState
        );
    }

    #[test]
    fn durable_claude_state_is_not_scratch() {
        // The narrowing (#361 cluster F follow-up): `.claude` holds durable,
        // untracked state that a silent ALLOW would destroy. Each of these was
        // a verified silent-ALLOW hole in guard-rm before the allowlist.
        for path in [
            "/Users/x/.claude/projects",
            "/Users/x/.claude/projects/some-proj/memory/note.md",
            "/Users/x/.claude/metrics",
            "/Users/x/.claude/plugins",
            "/Users/x/.claude/agent-memory",
            "/Users/x/.claude/skills/some-skill",
            "/Users/x/.claude/rules",
            "/Users/x/.claude/hooks",
            "/srv/repo/.claude/agent-memory",
            "/srv/repo/.claude/memory",
        ] {
            assert_eq!(class(path, "/Users/x"), PathClass::ClaudeState, "{path}");
        }
    }

    #[test]
    fn claude_git_dir_reports_git_root() {
        // `~/.claude/.git` (the chezmoi-migration target) used to ride the
        // blanket `.claude` carve-out to ALLOW, masking the git-root fact.
        assert_eq!(
            class("/Users/x/.claude/.git", "/Users/x"),
            PathClass::GitRoot
        );
    }

    #[test]
    fn claude_curdir_segment_still_scratch() {
        assert_eq!(
            class("/srv/repo/.claude/./worktrees/f", "/Users/x"),
            PathClass::ClaudeScratch
        );
    }

    #[test]
    fn claude_lookalike_is_not_scratch() {
        assert_eq!(
            class("/Users/x/repo/myclaude/a", "/Users/x"),
            PathClass::Source
        );
        assert_eq!(
            class("/Users/x/repo/.claude-old/a", "/Users/x"),
            PathClass::Source
        );
    }

    // --- DocsPlans ---

    #[test]
    fn under_docs_plans_is_plan_doc() {
        assert_eq!(
            class("/Users/x/repo/docs/plans/2026/q2", "/Users/x"),
            PathClass::DocsPlans
        );
    }

    #[test]
    fn git_root_under_docs_plans_reports_git_root() {
        // Precedence lock (code-review finding): `DocsPlans` has no ALLOW
        // consumer, so a path that is BOTH under `docs/plans/` and a git root
        // must report GitRoot — otherwise guard_rm (no DocsPlans arm) would
        // downgrade a `.git`-bearing delete target from BLOCK to ASK, breaking
        // the byte-identical contract. Both the literal `.git` component and the
        // injected probe must resolve to GitRoot, not DocsPlans.
        assert_eq!(
            class("/Users/x/repo/docs/plans/.git", "/Users/x"),
            PathClass::GitRoot
        );
        let probe = |p: &str| p == "/Users/x/repo/docs/plans";
        assert_eq!(
            classify("/Users/x/repo/docs/plans", &ctx("/Users/x"), &probe),
            PathClass::GitRoot
        );
    }

    #[test]
    fn docs_plans_must_be_consecutive() {
        assert_eq!(
            class("/Users/x/repo/docs/foo/plans", "/Users/x"),
            PathClass::Source
        );
        assert_eq!(class("/Users/x/repo/plans", "/Users/x"), PathClass::Source);
    }

    #[test]
    fn docs_plans_lookalike_is_not_plan_doc() {
        assert_eq!(
            class("/Users/x/repo/mydocs/plans", "/Users/x"),
            PathClass::Source
        );
        assert_eq!(
            class("/Users/x/repo/docs-old/plans", "/Users/x"),
            PathClass::Source
        );
    }

    // --- HomeChild ---

    #[test]
    fn first_level_home_entry_is_home_child() {
        assert_eq!(
            class("/Users/x/Documents", "/Users/x"),
            PathClass::HomeChild
        );
        assert_eq!(class("/Users/x/.zshrc", "/Users/x"), PathClass::HomeChild);
    }

    #[test]
    fn deep_home_path_is_not_child() {
        assert_eq!(
            class("/Users/x/Documents/notes", "/Users/x"),
            PathClass::Source
        );
    }

    #[test]
    fn home_itself_is_not_home_child() {
        assert_eq!(class("/Users/x", "/Users/x"), PathClass::Source);
    }

    #[test]
    fn empty_home_disables_home_child() {
        assert_eq!(class("/Users/x/Documents", ""), PathClass::Source);
    }

    // --- GitRoot ---

    #[test]
    fn dot_git_component_is_git_root() {
        assert_eq!(class("/a/repo/.git", "/Users/x"), PathClass::GitRoot);
        assert_eq!(class("/a/repo/.git/hooks", "/Users/x"), PathClass::GitRoot);
    }

    /// #657: a case-insensitive volume resolves `.GIT` to the real `.git`, so
    /// the segment match folds case. The negative controls prove the fold did
    /// not widen into substring matching.
    #[test]
    fn dot_git_component_case_variants_are_git_root() {
        assert_eq!(class("/a/repo/.GIT", "/Users/x"), PathClass::GitRoot);
        assert_eq!(class("/a/repo/.Git", "/Users/x"), PathClass::GitRoot);
        assert_eq!(class("/a/repo/.GIT/hooks", "/Users/x"), PathClass::GitRoot);
        assert_eq!(class("/a/repo/.gitx", "/Users/x"), PathClass::Source);
        assert_eq!(class("/a/repo/x.GIT", "/Users/x"), PathClass::Source);
    }

    #[test]
    fn probe_true_is_git_root() {
        let probe = |p: &str| p == "/a/repo";
        assert_eq!(
            classify("/a/repo", &ctx("/Users/x"), &probe),
            PathClass::GitRoot
        );
    }

    #[test]
    fn home_child_that_is_git_root_reports_home_child() {
        // Ordering: HomeChild resolves before GitRoot even when the probe fires,
        // so `~/myrepo` reports the home-child fact (message-order preservation).
        let probe = |_: &str| true;
        assert_eq!(
            classify("/Users/x/myrepo", &ctx("/Users/x"), &probe),
            PathClass::HomeChild
        );
    }

    #[test]
    fn claude_scratch_wins_over_git_root_probe() {
        // A worktree's `.git` is a file → probe would fire, but ClaudeScratch
        // resolves first, so worktree cleanup is not blocked as a git root.
        let probe = |_: &str| true;
        assert_eq!(
            classify("/srv/repo/.claude/worktrees/x", &ctx("/Users/x"), &probe),
            PathClass::ClaudeScratch
        );
    }

    #[test]
    fn durable_claude_state_does_not_win_over_git_root_probe() {
        // The counterpart: narrowing the carve-out means a durable `.claude`
        // subtree that IS a repo now reports the git-root fact instead of
        // shadowing it with an ALLOW class.
        let probe = |p: &str| p == "/Users/x/.claude/plugins/cache/some-plugin";
        assert_eq!(
            classify(
                "/Users/x/.claude/plugins/cache/some-plugin",
                &ctx("/Users/x"),
                &probe
            ),
            PathClass::GitRoot
        );
    }

    // --- Source (residual) ---

    #[test]
    fn arbitrary_path_is_source() {
        assert_eq!(class("/opt/app/cache", "/Users/x"), PathClass::Source);
        assert_eq!(class("srv/project/build", "/Users/x"), PathClass::Source);
    }

    // --- seed corpus (cadence-hooks#164) ---------------------------------
    //
    // The false-positive incident history is this classifier's regression
    // corpus (#164's own framing). Each case below locks the path-class fact
    // an incident turned on, so a future carve-out edit that re-opens one
    // fails here. Incidents that ride a *different* axis are noted, not tested:
    //
    // - #151 (check-idle-return cost/value) — the guard was retired, not
    //   migrated; no path-class fact to lock.
    // - #155 (nudge on an unrelated feature branch) — a GitState *branch* fact,
    //   not a path class; lands with its greenfield consumer.
    // - #158 (guard-gh-write read-vs-write axis) — the deferred operation-kind
    //   classifier, explicitly out of this module's scope.

    #[test]
    fn seed_152_parentdir_escape_defeats_carve_outs() {
        // #152: carve-outs matched path components without canonicalizing `..`.
        // A crafted `..` that escapes the `.claude` / `docs/plans` segment must
        // normalize to the real product path and lose the carve-out.
        assert_eq!(
            class("/Users/x/repo/.claude/../src", "/Users/x"),
            PathClass::Source
        );
        assert_eq!(
            class("/Users/x/repo/docs/plans/../../src", "/Users/x"),
            PathClass::Source
        );
        // …while a benign `.` segment inside the carve-out stays exempt.
        assert_eq!(
            class("/Users/x/repo/.claude/./worktrees/f", "/Users/x"),
            PathClass::ClaudeScratch
        );
    }

    #[test]
    fn seed_33_claude_worktrees_dir_is_scratch() {
        // #33: work under `.claude/worktrees/` is Claude-managed regardless of
        // the branch it sits on. The worktree case is the one the ALLOW-granting
        // class still covers after the allowlist narrowing.
        assert_eq!(
            class("/Users/x/repo/.claude/worktrees/feat-foo", "/Users/x"),
            PathClass::ClaudeScratch
        );
        // A nested-repo worktree layout still matches (`.claude` anywhere).
        assert_eq!(
            class(
                "/Users/x/repo/inner/.claude/worktrees/x/crates/guardrails/src",
                "/Users/x"
            ),
            PathClass::ClaudeScratch
        );
    }

    #[test]
    fn seed_35_memory_tree_is_durable_state_not_scratch() {
        // #35: the auto-written memory tree lives under `~/.claude`. It used to
        // ride the blanket `.claude` component fact into the ALLOW-granting
        // class; the allowlist narrowing puts it back in the residual, because
        // this tree is durable and untracked — the opposite of scratch.
        //
        // This does NOT re-open #35. That incident's live consumer is
        // warn-main-branch, which reads `worktree::is_claude_managed_dir` (the
        // coarse `.claude`-anywhere match, unchanged and separately tested
        // there) — never this classifier. `pathclass` has exactly one consumer,
        // `guard_rm`, and for it the correct fact about the memory tree is
        // "not proven disposable".
        assert_eq!(
            class("/Users/x/.claude/projects/some-proj/memory", "/Users/x"),
            PathClass::ClaudeState
        );
        assert_eq!(
            class(
                "/Users/x/.claude/projects/some-proj/memory/note.md",
                "/Users/x"
            ),
            PathClass::ClaudeState
        );
    }

    #[test]
    fn claude_state_is_distinct_from_source() {
        // The distinction the single-file softening depends on: an ordinary
        // project path and a durable `.claude` path must NOT share a class, or
        // a consumer softening the residual would re-open the subtree the
        // scratch allowlist closed.
        assert_eq!(
            class("/srv/repo/src/main.rs", "/Users/x"),
            PathClass::Source
        );
        assert_eq!(
            class("/Users/x/.claude/projects/proj/session.jsonl", "/Users/x"),
            PathClass::ClaudeState
        );
    }

    #[test]
    fn claude_state_outranks_docs_plans() {
        // `DocsPlans` has no guard-rm arm, so it reads as the ambiguous middle
        // and would ride a softening rule. A plan doc under `.claude` must
        // report the durable-state fact instead.
        assert_eq!(
            class("/Users/x/.claude/docs/plans/2026-07-25-x.md", "/Users/x"),
            PathClass::ClaudeState
        );
        // …while a repo's own docs/plans still reports DocsPlans.
        assert_eq!(
            class("/srv/repo/docs/plans/2026-07-25-x.md", "/Users/x"),
            PathClass::DocsPlans
        );
    }
}
