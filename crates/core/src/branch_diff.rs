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

use crate::shell::{GitSpawn, git_command, run_git_bounded};
use std::process::Command;

/// Files changed on the branch at `dir`, from the merge base with
/// `origin/main` (falling back to `origin/master`) to `HEAD`. The base refs
/// are spelled fully qualified (`refs/remotes/origin/main`) so a hostile local
/// branch literally named `origin/main` cannot shift the diff base.
///
/// `None` when the repo, base ref, or diff can't be resolved — including a
/// deadline timeout or spawn failure. Callers gate on evidence, so `None`
/// means "don't conclude anything" — and a **genuinely empty diff resolves to
/// `Some(vec![])`**, never `None`: the diff subprocess runs raw through
/// [`run_git_bounded`] rather than [`git_command`], whose empty-stdout-is-
/// failure mapping would collapse "confirmed no changes" into "no evidence".
pub fn changed_files(dir: &str) -> Option<Vec<String>> {
    let base = git_command(dir, &["merge-base", "HEAD", "refs/remotes/origin/main"])
        .or_else(|| git_command(dir, &["merge-base", "HEAD", "refs/remotes/origin/master"]))?;
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(["diff", "--name-only", &base, "HEAD"]);
    match run_git_bounded(&mut cmd) {
        GitSpawn::Completed(output) if output.status.success() => Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
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
