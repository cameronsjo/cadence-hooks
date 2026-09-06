//! Branch-diff classification for polish-scope gating (cadence-hooks#467).
//!
//! Two pieces, split at the I/O boundary: [`changed_files`] shells out (bounded
//! by the process deadline) to list what a branch changed vs its merge base
//! with `origin/main`; [`branch_touches_code`] is the pure classifier over that
//! list. Callers that gate output on the answer treat a `None` from
//! [`changed_files`] as **no evidence → allow** (ADR-0001): a timed-out or
//! unspawnable git must never manufacture a nudge.
//!
//! The code/docs boundary here is **polish's own**, not `warn_docs_update`'s
//! extension list: the polish gate's scope clauses count skill / agent /
//! command / rule markdown — and `CLAUDE.md` / `SKILL.md` — as *behavior*, so a
//! branch touching only those is a code branch for polish purposes. Reusing a
//! naive `.md == docs` classifier would re-open exactly the loophole the gate's
//! SCOPE_CLAUSES exist to close.

use crate::deadline;
use crate::shell::{GitSpawn, git_command, run_git_bounded};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// The merge base with `origin/main` (falling back to `origin/master`) for the
/// branch checked out at `dir`. The base refs are spelled fully qualified
/// (`refs/remotes/origin/main`) so a hostile local branch literally named
/// `origin/main` cannot shift the diff base.
///
/// `None` when the repo or base ref can't be resolved — including a deadline
/// timeout or spawn failure. Shared by every caller that needs "this branch's
/// base commit vs upstream", so the fallback-ref order lives in exactly one
/// place.
pub fn merge_base_with_origin(dir: &str) -> Option<String> {
    git_command(dir, &["merge-base", "HEAD", "refs/remotes/origin/main"])
        .or_else(|| git_command(dir, &["merge-base", "HEAD", "refs/remotes/origin/master"]))
}

/// Files changed on the branch at `dir`, from the merge base with
/// `origin/main` (falling back to `origin/master`) to `HEAD`.
///
/// `None` when the repo, base ref, or diff can't be resolved — including a
/// deadline timeout or spawn failure. Callers gate on evidence, so `None`
/// means "don't conclude anything" — and a **genuinely empty diff resolves to
/// `Some(vec![])`**, never `None`: the diff subprocess runs raw through
/// [`run_git_bounded`] rather than [`git_command`], whose empty-stdout-is-
/// failure mapping would collapse "confirmed no changes" into "no evidence".
pub fn changed_files(dir: &str) -> Option<Vec<String>> {
    let base = merge_base_with_origin(dir)?;
    // NUL-split via [`git_nul_list`] rather than `.lines()`: a newline-bearing
    // filename would otherwise split into two phantom paths, one of which could
    // manufacture a spurious `*.rs` and flip `branch_touches_code`. The
    // `Some(vec![])`-is-evidence property is preserved — `git_nul_list` maps an
    // empty *successful* listing to `Some(empty)`, never `None`.
    git_nul_list(dir, &["diff", "--name-only", "-z", &base, "HEAD"])
        .map(|paths| paths.into_iter().collect())
}

/// A content digest over what the branch changed **in the working tree**, with
/// the base it was taken against (cadence-hooks#775 item 2).
///
/// Recorded as marker provenance, like `head_sha` — nothing gates on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingTreeDigest {
    /// The merge base the change set was computed against.
    pub base: String,
    /// `sha256:<hex>`, the literal `skipped` when a bound was hit, or the
    /// literal `empty` when the change set held no code paths.
    pub digest: String,
    /// How many code paths — by polish's own definition ([`is_polish_code_path`])
    /// — were in the change set: the post-filter count, not the raw diff size.
    /// Reported even when the digest itself was bounded out.
    pub files: usize,
}

/// Above this many code paths (post-[`is_polish_code_path`] filter), the digest
/// is skipped rather than computed.
pub const MAX_DIGEST_FILES: usize = 1000;

/// Above this many bytes of content, likewise — checked **per file, before the
/// file is read** (cadence-hooks#775 security review), so the budget bounds
/// resident memory rather than merely reporting after the fact. A single entry
/// larger than the remaining budget is bounded out on its metadata alone.
pub const MAX_DIGEST_BYTES: u64 = 64 * 1024 * 1024;

/// Digest the branch's **working-tree** change set vs its merge base with
/// `origin/main`.
///
/// Contrast with [`changed_files`], which lists only what is **committed** on
/// the branch: this one reads the working tree — the tree a polish pass
/// actually reviewed, which at record time is typically uncommitted — and adds
/// untracked files to the set.
///
/// The change set is `git diff --name-only -z <base>` (working tree vs base)
/// unioned with `git ls-files --others --exclude-standard -z`, filtered through
/// [`is_polish_code_path`]. Parsing is NUL-split throughout: a `.lines()` split
/// would turn one newline-bearing filename into two phantom paths.
///
/// Fail-open, in two distinguishable directions (ADR-0001):
///
/// - a bound hit ([`MAX_DIGEST_FILES`] / [`MAX_DIGEST_BYTES`]) → `digest` is
///   the literal `"skipped"` — a real value the reader can see;
/// - an unresolvable base, any subprocess failure, or a spent deadline budget
///   mid-hash → `None`, so the caller omits the field entirely. *Bounded out*
///   and *no evidence* must not collapse into one another.
pub fn working_tree_digest(dir: &str) -> Option<WorkingTreeDigest> {
    digest_bounded(dir, MAX_DIGEST_FILES, MAX_DIGEST_BYTES, hash_budget)
}

/// How long the content-hash loop may run before abandoning the digest.
///
/// `Armed` already has the hook's elapsed time subtracted, so it is what
/// remains from here; `Unarmed` (the CLI path) caps at the full budget;
/// `Disabled` means no bound at all.
///
/// **Read immediately before the loop, never earlier.** `Armed` shrinks as
/// time passes, and `digest_bounded` runs four git subprocesses before it
/// hashes anything. Reading the budget at the top would hand the loop the
/// pre-subprocess allotment, so the subprocess time and the hash time would
/// each fit the budget while their sum overran it — the exact overrun the
/// internal deadline exists to keep inside the external `hooks.json` kill.
fn hash_budget() -> Option<Duration> {
    match deadline::state() {
        deadline::BudgetState::Disabled => None,
        deadline::BudgetState::Armed(remaining) | deadline::BudgetState::Unarmed(remaining) => {
            Some(remaining)
        }
    }
}

/// [`working_tree_digest`] with explicit bounds, so all three bounds — files,
/// bytes, and time — are testable without materializing a thousand files, 64
/// MiB, or a real deadline.
///
/// `hash_budget` is a **closure, not a value**: it is called once, immediately
/// before the hash loop, after every subprocess this function runs. See
/// [`hash_budget`] for why the timing is load-bearing.
fn digest_bounded(
    dir: &str,
    max_files: usize,
    max_bytes: u64,
    hash_budget: impl Fn() -> Option<Duration>,
) -> Option<WorkingTreeDigest> {
    let base = merge_base_with_origin(dir)?;
    // Resolve the repo top-level ONCE and run both change-set subprocesses
    // against it (cadence-hooks#775 C1): `git diff --name-only` yields
    // repo-root-relative paths while `ls-files --others` yields cwd-relative,
    // so from a subdirectory the two disagree and every path joins against the
    // wrong base — the digest then hashes path NAMES only, blind to content.
    // A `--show-toplevel` that can't resolve is an unresolvable base: omit the
    // digest (the no-evidence path), fail-open (ADR-0001).
    let root = git_command(dir, &["rev-parse", "--show-toplevel"])?;
    // `-z` output is never path-quoted, so `core.quotePath=false` would be a
    // no-op here (cadence-hooks#775 N1) — the NUL framing is what carries an
    // odd filename through intact.
    let mut paths: BTreeSet<String> = git_nul_list(&root, &["diff", "--name-only", "-z", &base])?;
    paths.extend(git_nul_list(
        &root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?);
    let paths: Vec<String> = paths
        .into_iter()
        .filter(|path| is_polish_code_path(path))
        .collect();

    let bounded = |digest: String| {
        Some(WorkingTreeDigest {
            base: base.clone(),
            digest,
            files: paths.len(),
        })
    };
    if paths.len() > max_files {
        return bounded("skipped".to_string());
    }
    // An empty code set has no content to attest — record the literal `empty`
    // (cadence-hooks#775 N3), distinct from a real hash and from the `skipped`
    // bound, so the empty-string SHA never reads as provenance.
    if paths.is_empty() {
        return bounded("empty".to_string());
    }

    let root = Path::new(&root);
    let mut frames = Sha256::new();
    let mut remaining = max_bytes;
    // The content-hash loop is the only unbounded work in this function — the
    // two subprocesses above go through the deadline-aware spawn helpers, but
    // reading and hashing up to MAX_DIGEST_FILES files consulted no clock at
    // all. That was tolerable while this ran only on the `record-polish` CLI
    // path; cadence-hooks#874 put it on the hook path, where an external
    // hooks.json timeout would kill the process outright (the pre-#271 silent
    // kill this module exists to prevent).
    //
    // The budget is read HERE, after the four subprocesses above, not at the
    // call site — an `Armed` budget shrinks as those run, and handing the loop
    // a pre-subprocess allotment lets the two phases each fit while their sum
    // overruns. Every early return above this line therefore never reads it.
    let hash_budget = hash_budget();
    let hash_start = Instant::now();
    for path in &paths {
        // Out of budget → `None`, the no-evidence shape. Deliberately NOT
        // `"skipped"`: that is a real recorded value meaning "a declared bound
        // was hit", and writing it here would attest a bound the operator can
        // reason about when what actually happened is that the clock ran out.
        // `None` omits the field, which every consumer already reads as silent.
        if hash_budget.is_some_and(|budget| hash_start.elapsed() >= budget) {
            deadline::note_hit();
            return None;
        }
        // The budget is spent BEFORE the read, not after it: `digest_entry`
        // returns `None` for a regular file whose metadata already exceeds what
        // is left, so no single file is ever pulled whole into memory to find
        // out that it did not fit.
        let Some((entry, size)) = digest_entry(&root.join(path), remaining) else {
            return bounded("skipped".to_string());
        };
        remaining = remaining.saturating_sub(size);
        frames.update(path.as_bytes());
        frames.update(b"\0");
        frames.update(entry.as_bytes());
        frames.update(b"\0");
    }
    bounded(format!("sha256:{:x}", frames.finalize()))
}

/// One change-set entry's frame content, plus the bytes it cost — or `None`
/// when a regular file is larger than `remaining`, the caller's unspent byte
/// budget.
///
/// `symlink_metadata` first, deliberately: following a symlink would hash a
/// file that is not in the diff — possibly not even in the repo. A symlink
/// hashes its **target string**, which is what git stores in the blob anyway.
/// A non-regular path (FIFO, device) and a listed-but-absent one are each
/// framed by a literal rather than hashed, because they mean different things
/// and neither has content to read.
///
/// The size check reads the metadata already in hand and runs **before**
/// `fs::read` (cadence-hooks#775 security review): checking afterwards makes
/// the budget a report rather than a bound, and one hostile or accidental
/// multi-gigabyte file in the change set is read whole first.
fn digest_entry(path: &Path, remaining: u64) -> Option<(String, u64)> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Some(("absent".to_string(), 0));
    };
    if meta.is_symlink() {
        let Ok(target) = std::fs::read_link(path) else {
            return Some(("absent".to_string(), 0));
        };
        return Some((sha256_hex(target.to_string_lossy().as_bytes()), 0));
    }
    if !meta.is_file() {
        return Some(("nonregular".to_string(), 0));
    }
    if meta.len() > remaining {
        return None;
    }
    match std::fs::read(path) {
        Ok(content) => Some((sha256_hex(&content), content.len() as u64)),
        Err(_) => Some(("absent".to_string(), 0)),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Run a `-z`-producing git command and split its stdout on NUL.
///
/// `None` on any failure, timeout, or nonzero exit — an empty *successful*
/// listing is `Some(empty)`, the same evidence distinction [`changed_files`]
/// makes.
fn git_nul_list(dir: &str, args: &[&str]) -> Option<BTreeSet<String>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    match run_git_bounded(&mut cmd) {
        GitSpawn::Completed(output) if output.status.success() => Some(
            String::from_utf8_lossy(&output.stdout)
                .split('\0')
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        GitSpawn::Completed(_) | GitSpawn::SpawnFailed | GitSpawn::TimedOut => None,
    }
}

/// True when any changed file is code under **polish's** definition.
pub fn branch_touches_code(files: &[String]) -> bool {
    files.iter().any(|f| is_polish_code_path(f))
}

/// Polish's code/docs boundary for a single path.
///
/// Markdown is code when it is *behavioral*: named `CLAUDE.md` / `SKILL.md` /
/// `AGENTS.md`, or living under a `skills/`, `agents/`, `commands/`, or
/// `rules/` segment (instructions Claude executes). Every non-markdown file
/// counts as code — config, scripts, and manifests are all in a full polish
/// pass's scope, and this predicate only ever feeds a nudge, so the
/// conservative direction is toward counting.
fn is_polish_code_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if name.ends_with(".md") {
        // Sentinels compared case-insensitively: on a case-insensitive
        // filesystem `claude.md` IS `CLAUDE.md`, and this predicate only
        // feeds a nudge, so counting is the conservative direction.
        return matches!(name.as_str(), "claude.md" | "skill.md" | "agents.md")
            || path
                .split('/')
                .any(|seg| matches!(seg, "skills" | "agents" | "commands" | "rules"));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // --- is_polish_code_path / branch_touches_code (pure) ---

    #[test]
    fn behavioral_markdown_is_code() {
        // #467 RED: a naive `.md == docs` reuse would silently allow the exact
        // branch class the gate's SCOPE_CLAUSES name — skill/agent/rule
        // markdown and CLAUDE.md are behavior.
        assert!(branch_touches_code(&s(&[
            "plugins/cadence/skills/arrange/SKILL.md"
        ])));
        assert!(branch_touches_code(&s(&[
            "plugins/cadence/agents/code-reviewer.md"
        ])));
        assert!(branch_touches_code(&s(&[".claude/commands/ship.md"])));
        assert!(branch_touches_code(&s(&["rules/cadence-rules.md"])));
        assert!(branch_touches_code(&s(&["CLAUDE.md"])));
        assert!(branch_touches_code(&s(&["plugins/x/CLAUDE.md"])));
    }

    #[test]
    fn literal_docs_markdown_is_not_code() {
        assert!(!branch_touches_code(&s(&["README.md"])));
        assert!(!branch_touches_code(&s(&[
            "docs/plans/2026-08-03-thing.md"
        ])));
        assert!(!branch_touches_code(&s(&["CHANGELOG.md"])));
        assert!(!branch_touches_code(&s(&[])));
    }

    #[test]
    fn non_markdown_is_code() {
        assert!(branch_touches_code(&s(&["src/main.rs"])));
        assert!(branch_touches_code(&s(&["hooks/hooks.json"])));
        assert!(branch_touches_code(&s(&["scripts/gen.py"])));
    }

    #[test]
    fn mixed_branch_counts_as_code() {
        assert!(branch_touches_code(&s(&["README.md", "src/lib.rs"])));
    }

    // --- changed_files (I/O, real temp repo with an origin/main ref) ---

    fn git_in(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    }

    /// A repo whose `main` carries one commit, mirrored to a synthetic
    /// `origin/main` remote-tracking ref (no real remote needed — merge-base
    /// only reads the ref), then switched to a feature branch.
    fn init_repo_with_origin_main(files_on_branch: &[&str]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        git_in(dir, &["init", "-q", "-b", "main"]);
        git_in(dir, &["config", "user.email", "t@t"]);
        git_in(dir, &["config", "user.name", "t"]);
        git_in(dir, &["commit", "-q", "--allow-empty", "-m", "init"]);
        git_in(dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git_in(dir, &["checkout", "-q", "-b", "feat/x"]);
        for f in files_on_branch {
            let path = dir.join(f);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "x\n").unwrap();
            git_in(dir, &["add", f]);
        }
        if !files_on_branch.is_empty() {
            git_in(dir, &["commit", "-q", "-m", "branch work"]);
        }
        tmp
    }

    #[test]
    fn changed_files_lists_branch_diff_vs_origin_main() {
        let tmp = init_repo_with_origin_main(&["src/a.rs", "README.md"]);
        let files = changed_files(tmp.path().to_str().unwrap()).expect("diff resolves");
        assert_eq!(files, s(&["README.md", "src/a.rs"]));
    }

    #[test]
    fn changed_files_empty_diff_is_some_empty_not_none() {
        // Review finding (this branch): `git_command` maps empty stdout to
        // Failed, which would collapse "confirmed no changes" into "no
        // evidence". A branch identical to origin/main must resolve to
        // Some(vec![]) — a real verdict — not None.
        let tmp = init_repo_with_origin_main(&[]);
        let files = changed_files(tmp.path().to_str().unwrap())
            .expect("an empty diff is evidence, not a failure");
        assert!(files.is_empty());
    }

    // --- working_tree_digest (cadence-hooks#775 item 2) ---

    /// Write `content` to `dir/name`, creating parents.
    fn write_file(dir: &std::path::Path, name: &str, content: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
    }

    #[test]
    fn working_tree_digest_is_stable_across_committing_the_same_content() {
        // #775 item 2 RED: the digest is over the CONTENT set vs the base, so
        // committing what was already in the working tree changes nothing —
        // the record is provenance about what was reviewed, not about whether
        // it happened to be staged.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "fn a() {}\n");

        let before = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        git_in(dir, &["add", "src/a.rs"]);
        git_in(dir, &["commit", "-q", "-m", "commit the same content"]);
        let after = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");

        assert_eq!(before.digest, after.digest);
        assert_eq!(before.files, 1);
    }

    #[test]
    fn the_hash_budget_is_read_at_the_loop_not_before_the_subprocesses() {
        // cadence-hooks#874 second review: the budget used to be evaluated as
        // an ARGUMENT, before `digest_bounded` ran merge-base, rev-parse, and
        // the two listing subprocesses. An `Armed` budget shrinks while those
        // run, so the loop got the pre-subprocess allotment and the two phases
        // could each fit the budget while their sum overran it.
        //
        // The deadline module's clock and budget are process-global `OnceLock`s
        // with no test setter, so this cannot be driven through a real
        // shrinking budget. Call ORDER is the observable that settles it
        // instead: every early return in `digest_bounded` sits BEFORE the loop,
        // so an empty code set must return without ever asking for a budget. An
        // argument-evaluated budget is asked for unconditionally, so this test
        // is red the moment the read moves back up.
        let calls = std::cell::Cell::new(0);
        let counted = || {
            calls.set(calls.get() + 1);
            None
        };

        // No code paths at all → the `empty` early return, above the loop.
        let tmp = init_repo_with_origin_main(&[]);
        let empty = digest_bounded(
            tmp.path().to_str().unwrap(),
            MAX_DIGEST_FILES,
            MAX_DIGEST_BYTES,
            &counted,
        )
        .expect("digest resolves");
        assert_eq!(empty.digest, "empty", "precondition: the early return");
        assert_eq!(
            calls.get(),
            0,
            "a return above the loop must not read the budget"
        );

        // Positive control: with a file to hash, the loop runs and asks once —
        // otherwise the zero above would prove nothing.
        write_file(tmp.path(), "src/a.rs", "fn a() {}\n");
        let hashed = digest_bounded(
            tmp.path().to_str().unwrap(),
            MAX_DIGEST_FILES,
            MAX_DIGEST_BYTES,
            &counted,
        )
        .expect("digest resolves");
        assert!(hashed.digest.starts_with("sha256:"));
        assert_eq!(calls.get(), 1, "the loop reads the budget exactly once");
    }

    #[test]
    fn a_spent_hash_budget_yields_no_evidence_not_a_skipped_record() {
        // cadence-hooks#874 security review: the content-hash loop now runs on
        // the HOOK path, where it previously ran only on the record-polish CLI
        // path, and it consulted no clock at all. Without a budget check an
        // external hooks.json timeout kills the process outright — the silent
        // external kill the deadline module exists to prevent.
        //
        // A zero budget is spent before the first file, so the loop abandons
        // immediately. The result must be `None` (no evidence — the caller
        // omits the field and the gate stays silent), never a `"skipped"`
        // record: `skipped` is a real recorded value asserting a DECLARED bound
        // was hit, and writing it here would attest a bound the operator can
        // reason about when the clock simply ran out.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "fn a() {}\n");

        // Positive control: the same call with no budget resolves a real hash,
        // so the `None` below is the budget's doing and not a broken fixture.
        let unbounded = digest_bounded(
            dir.to_str().unwrap(),
            MAX_DIGEST_FILES,
            MAX_DIGEST_BYTES,
            || None,
        )
        .expect("digest resolves with no time bound");
        assert!(unbounded.digest.starts_with("sha256:"));

        let spent = digest_bounded(
            dir.to_str().unwrap(),
            MAX_DIGEST_FILES,
            MAX_DIGEST_BYTES,
            || Some(Duration::ZERO),
        );
        assert!(
            spent.is_none(),
            "a spent budget is no evidence, not a bounded-out record: {spent:?}"
        );
    }

    #[test]
    fn a_non_overlapping_merge_up_leaves_the_digest_unchanged() {
        // cadence-hooks#874: the pre-PR gate now COMPARES this digest against a
        // marker's recorded one, so the merge-up invariant stopped being
        // provenance trivia and became load-bearing. Merging an advanced
        // `origin/main` into the branch moves the merge BASE, which the digest
        // is computed against — but the branch's own change set is unchanged,
        // so the digest must not move. Were it to move, every branch that
        // merged main up after polishing would draw the stale-marker nudge.
        //
        // The invariant is CONDITIONAL on the merge not overlapping the
        // branch's change set — the upstream commit here touches a different
        // file. The overlapping case genuinely moves the digest and is pinned
        // by `a_merge_up_that_overlaps_the_branch_change_set_does_move_the_digest`.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "fn a() {}\n");
        git_in(dir, &["add", "src/a.rs"]);
        git_in(dir, &["commit", "-q", "-m", "branch work"]);
        let before = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");

        // Advance `origin/main` with an unrelated commit, then merge it up.
        git_in(dir, &["checkout", "-q", "main"]);
        write_file(dir, "src/upstream.rs", "fn upstream() {}\n");
        git_in(dir, &["add", "src/upstream.rs"]);
        git_in(dir, &["commit", "-q", "-m", "upstream work"]);
        git_in(dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git_in(dir, &["checkout", "-q", "feat/x"]);
        git_in(dir, &["merge", "-q", "--no-edit", "main"]);

        let after = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        assert_ne!(
            before.base, after.base,
            "precondition: the merge-up must have moved the base"
        );
        assert_eq!(
            before.digest, after.digest,
            "a merge-up must not move the digest"
        );
        assert_eq!(after.files, 1, "only the branch's own change set is hashed");
    }

    #[test]
    fn a_merge_up_that_overlaps_the_branch_change_set_does_move_the_digest() {
        // cadence-hooks#874 code review: the merge-up invariant above is
        // CONDITIONAL. It holds only while the merged upstream commits touch no
        // file the branch also changed. When they overlap, git's auto-merge
        // rewrites that file in the working tree, so its content genuinely
        // differs from what polish reviewed — and the digest moves.
        //
        // This is the boundary, pinned rather than hidden: the gate will nudge
        // after such a merge. That is an accepted false positive on an advisory
        // verdict, and it is not even clearly false — the shipping content of a
        // reviewed file really did change.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/shared.rs", "fn branch_side() {}\n");
        git_in(dir, &["add", "src/shared.rs"]);
        git_in(dir, &["commit", "-q", "-m", "branch work"]);
        let before = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");

        // Advance `origin/main` with a commit touching the SAME file, in a
        // non-conflicting region so the auto-merge succeeds.
        git_in(dir, &["checkout", "-q", "main"]);
        write_file(dir, "src/shared.rs", "fn upstream_side() {}\n");
        git_in(dir, &["add", "src/shared.rs"]);
        git_in(dir, &["commit", "-q", "-m", "upstream work"]);
        git_in(dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git_in(dir, &["checkout", "-q", "feat/x"]);
        // Take the upstream side wholesale, so the merge lands without a
        // conflict and the file's content demonstrably changes.
        git_in(dir, &["merge", "-q", "--no-edit", "-X", "theirs", "main"]);

        let after = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        assert_ne!(
            before.digest, after.digest,
            "an OVERLAPPING merge-up rewrites a reviewed file, so the digest moves"
        );
    }

    #[test]
    fn working_tree_digest_changes_on_a_content_edit() {
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "fn a() {}\n");
        let before = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");

        write_file(dir, "src/a.rs", "fn a() { todo!() }\n");
        let after = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        assert_ne!(before.digest, after.digest, "an edit must move the digest");
    }

    #[test]
    fn working_tree_digest_from_a_subdirectory_sees_content() {
        // #775 C1 RED: `git diff --name-only` yields repo-root-relative paths
        // while `ls-files --others` yields cwd-relative, so run from a
        // SUBDIRECTORY the two spaces disagree — every tracked path joined
        // against the subdir resolves to a nonexistent `<subdir>/<repo-rel>`,
        // framed "absent", and the digest hashes path NAMES only (a total
        // content rewrite left it byte-identical). Resolving the repo
        // top-level and joining every path there is what discriminates the two
        // orderings; every other digest test runs from the repo root, so the
        // suite could not see this.
        let tmp = init_repo_with_origin_main(&["sub/a.rs"]);
        let dir = tmp.path();
        let subdir = dir.join("sub");
        let sub = subdir.to_str().unwrap();

        write_file(dir, "sub/a.rs", "fn a() {}\n");
        let before = working_tree_digest(sub).expect("digest resolves from a subdir");

        write_file(dir, "sub/a.rs", "fn a() { todo!() }\n");
        let after = working_tree_digest(sub).expect("digest resolves from a subdir");
        assert_ne!(
            before.digest, after.digest,
            "a content edit must move the digest even when recorded from a subdirectory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn digest_entry_hashes_a_symlink_target_string_not_the_target_file() {
        // A symlink's content IS its target string as far as git is concerned,
        // and following it would read a file outside the diff — possibly
        // outside the repo entirely.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("secret.txt");
        std::fs::write(&target, "the target's contents").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let plain = tmp.path().join("plain");
        std::fs::write(&plain, target.to_string_lossy().as_bytes()).unwrap();

        assert_eq!(
            digest_entry(&link, u64::MAX).unwrap().0,
            digest_entry(&plain, u64::MAX).unwrap().0,
            "a symlink hashes its TARGET STRING, like the blob git would store"
        );
        assert_ne!(
            digest_entry(&link, u64::MAX).unwrap().0,
            digest_entry(&target, u64::MAX).unwrap().0,
            "a symlink must not hash the target file's contents"
        );
    }

    #[cfg(unix)]
    #[test]
    fn digest_entry_frames_nonregular_and_absent_paths() {
        // Neither is hashable, and the two mean different things — a device or
        // FIFO in the diff vs a path git listed that is gone from the tree.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if made {
            assert_eq!(
                digest_entry(&fifo, u64::MAX),
                Some(("nonregular".to_string(), 0))
            );
        }
        assert_eq!(
            digest_entry(&tmp.path().join("not-here"), u64::MAX),
            Some(("absent".to_string(), 0))
        );
    }

    #[test]
    #[cfg(unix)]
    fn working_tree_digest_survives_a_filename_with_spaces_and_quotes() {
        // NUL-split parsing is the whole point: `.lines()` would split a
        // newline-bearing name into two phantom paths, and quotePath escaping
        // would rewrite the name out from under the hash. Unix-only: NTFS
        // forbids `"` in a filename, so the fixture cannot even be created on
        // Windows — the property under test is a POSIX-filesystem property.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a b \"c\".rs", "x\n");
        let digest = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        assert_eq!(digest.files, 1, "the odd name is ONE path, not two");
    }

    #[test]
    fn working_tree_digest_records_empty_for_an_empty_code_set() {
        // #775 N3: an empty change set has no content to attest, so the
        // empty-string SHA must never masquerade as provenance — record the
        // literal `empty`, distinct from a real hash and from the `skipped`
        // bound.
        let tmp = init_repo_with_origin_main(&[]);
        let digest = working_tree_digest(tmp.path().to_str().unwrap()).expect("digest resolves");
        assert_eq!(digest.digest, "empty");
        assert_eq!(digest.files, 0);
    }

    #[test]
    fn working_tree_digest_filters_untracked_paths_by_the_polish_code_definition() {
        // Untracked files join the changed set, through the same code/docs
        // boundary the rest of this module uses.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "x\n");
        let code_only = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");

        write_file(dir, "README.md", "docs\n");
        let with_docs = working_tree_digest(dir.to_str().unwrap()).expect("digest resolves");
        assert_eq!(code_only.digest, with_docs.digest);
        assert_eq!(with_docs.files, 1);
    }

    #[test]
    fn working_tree_digest_records_skipped_when_over_a_bound() {
        // Fail-open, bounded: an enormous change set records the string
        // "skipped" — a real, distinguishable value, not a missing field.
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/a.rs", "aaaa\n");
        write_file(dir, "src/b.rs", "bbbb\n");

        let over_files = digest_bounded(dir.to_str().unwrap(), 1, MAX_DIGEST_BYTES, || None)
            .expect("a bounded-out digest still resolves");
        assert_eq!(over_files.digest, "skipped");
        assert_eq!(over_files.files, 2, "the file count still reports");

        let over_bytes = digest_bounded(dir.to_str().unwrap(), MAX_DIGEST_FILES, 1, || None)
            .expect("still resolves");
        assert_eq!(over_bytes.digest, "skipped");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_over_the_remaining_budget_is_bounded_out_before_it_is_read() {
        // #775 security review (I1) RED: the byte bound was checked AFTER
        // `fs::read` returned, so one huge file was pulled whole into memory
        // before anything said no. The bound is a pre-read check on the file's
        // metadata now.
        //
        // An unreadable file is what discriminates the two orderings: reading
        // it fails, which the old code framed as "absent" (0 bytes) and
        // digested happily; the pre-read check sees its metadata size and
        // records "skipped".
        use std::os::unix::fs::PermissionsExt;
        let tmp = init_repo_with_origin_main(&[]);
        let dir = tmp.path();
        write_file(dir, "src/big.rs", &"x".repeat(4096));
        let big = dir.join("src/big.rs");
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&big).is_ok() {
            // Running as root: the discriminating precondition does not hold.
            return;
        }

        let bounded = digest_bounded(dir.to_str().unwrap(), MAX_DIGEST_FILES, 64, || None)
            .expect("a bounded-out digest still resolves");
        assert_eq!(bounded.digest, "skipped");
        assert_eq!(bounded.files, 1, "the file count still reports");

        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn working_tree_digest_is_none_without_a_resolvable_base() {
        // Bounded-out and no-evidence are different meanings: the caller OMITS
        // the field here, rather than recording "skipped".
        let tmp = tempfile::tempdir().unwrap();
        assert!(working_tree_digest(tmp.path().to_str().unwrap()).is_none());

        let repo = tempfile::tempdir().unwrap();
        git_in(repo.path(), &["init", "-q", "-b", "main"]);
        git_in(repo.path(), &["config", "user.email", "t@t"]);
        git_in(repo.path(), &["config", "user.name", "t"]);
        git_in(
            repo.path(),
            &["commit", "-q", "--allow-empty", "-m", "init"],
        );
        assert!(
            working_tree_digest(repo.path().to_str().unwrap()).is_none(),
            "no origin/main ref → no base → no evidence"
        );
    }

    #[test]
    fn changed_files_none_outside_a_repo() {
        // No evidence, not an empty diff — the caller must allow.
        let tmp = tempfile::tempdir().unwrap();
        assert!(changed_files(tmp.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn changed_files_none_without_origin_ref() {
        // A repo with no origin/main (or master) ref has no base to diff
        // against — evidence absent, never a fabricated empty list.
        let tmp = tempfile::tempdir().unwrap();
        git_in(tmp.path(), &["init", "-q", "-b", "main"]);
        git_in(tmp.path(), &["config", "user.email", "t@t"]);
        git_in(tmp.path(), &["config", "user.name", "t"]);
        git_in(tmp.path(), &["commit", "-q", "--allow-empty", "-m", "init"]);
        assert!(changed_files(tmp.path().to_str().unwrap()).is_none());
    }
}
