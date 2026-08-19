//! Nudge to add a `CHANGELOG.md` entry alongside a shipped code change.
//!
//! Fires on the same ship anchors as `nudge_polish_before_pr`
//! ([`is_polish_ship_anchor`]) and reuses [`changed_files`] to diff the branch
//! against `origin/main`/`origin/master`. Unlike that check, this one also
//! reads the tree at the merge base to tell a monorepo apart from a
//! single-changelog repo, because the two owe different things:
//!
//! - **Monorepo-class**: any `plugins/*/CHANGELOG.md` is tracked at the merge
//!   base. Every plugin the branch touched owes its OWN `plugins/<name>/
//!   CHANGELOG.md` entry — a root `CHANGELOG.md` edit never satisfies that
//!   (cameronsjo/cadence's `docs/` root CHANGELOG.md is a session-reflection
//!   artifact, not a plugin's).
//! - **Root-class**: no per-plugin changelog is tracked, but a root
//!   `CHANGELOG.md` is. The branch owes one entry there.
//! - **Silent**: no changelog at all is tracked anywhere in the repo (the
//!   meta-repo shape) — nothing to nudge toward, so this exemption falls out
//!   of the class inference for free rather than needing a separate check.
//!
//! `plugins/<name>/{docs,scripts}/` changes are exempted from counting as a
//! plugin touch at exactly depth 2 (defense against `git add -f` sneaking
//! non-runtime cruft past the monorepo's own gitignore, cadence-ecosystem's
//! own convention) — but the same segment name deeper in the tree, e.g.
//! `plugins/<name>/skills/<skill>/scripts/`, is real shipped plugin content
//! and DOES count.
//!
//! Nudge-only (never ask/block) and opt-out only via `CADENCE_DISABLE=
//! warn-changelog-entry` — no new config surface. Any git read failing (no
//! merge base, spawn failure, deadline timeout) fails open to
//! [`CheckResult::allow`] (ADR-0001): a check that cannot establish repo class
//! must never manufacture a nudge from missing evidence.

use cadence_hooks_core::branch_diff::{changed_files, merge_base_with_origin};
use cadence_hooks_core::shell::{GitSpawn, is_polish_ship_anchor, parse_work_dir, run_git_bounded};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::process::Command;

/// A changelog entry the branch owes, inferred from repo class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owed {
    /// `plugins/<name>/CHANGELOG.md` — monorepo-class, one per touched plugin.
    PerPlugin(String),
    /// The repo's root `CHANGELOG.md` — root-class.
    RepoRoot,
}

impl Owed {
    /// The path this obligation names, for the nudge message.
    fn path(&self) -> String {
        match self {
            Owed::PerPlugin(name) => format!("plugins/{name}/CHANGELOG.md"),
            Owed::RepoRoot => "CHANGELOG.md".to_string(),
        }
    }
}

/// Nudges toward a `CHANGELOG.md` entry when a shipped branch touched code
/// but not the changelog its repo class owns.
pub struct WarnChangelogEntry;

impl Check for WarnChangelogEntry {
    fn name(&self) -> &str {
        "warn-changelog-entry"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        if !is_polish_ship_anchor(command) {
            return CheckResult::allow();
        }
        let Some(cwd) = input.cwd.as_deref() else {
            return CheckResult::allow();
        };

        let dir = parse_work_dir(command, cwd);

        let Some(changed) = changed_files(&dir) else {
            return CheckResult::allow();
        };
        let Some(tracked_changelogs) = tracked_changelog_paths(&dir) else {
            return CheckResult::allow();
        };

        let owed = missing_changelogs(&changed, &tracked_changelogs);
        if owed.is_empty() {
            return CheckResult::allow();
        }

        let mut msg = String::from("📓  Code changed but no CHANGELOG.md entry.\n\n");
        msg.push_str("This branch appears to owe an entry in:\n");
        for item in &owed {
            msg.push_str(&format!("  - {}\n", item.path()));
        }
        CheckResult::nudge(msg)
    }
}

/// Every tracked `CHANGELOG.md` path (root or `plugins/*/`) at the merge base
/// with `origin/main` (falling back to `origin/master`).
///
/// `None` when the repo, base ref, or tree read can't be resolved — the same
/// no-evidence contract as [`changed_files`]. A genuinely changelog-free repo
/// resolves to `Some(vec![])`, never `None`.
fn tracked_changelog_paths(dir: &str) -> Option<Vec<String>> {
    let base = merge_base_with_origin(dir)?;

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(["ls-tree", "-r", "--name-only", &base]);
    match run_git_bounded(&mut cmd) {
        GitSpawn::Completed(output) if output.status.success() => Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .filter(|l| l.rsplit('/').next() == Some("CHANGELOG.md"))
                .map(str::to_string)
                .collect(),
        ),
        GitSpawn::Completed(_) | GitSpawn::SpawnFailed | GitSpawn::TimedOut => None,
    }
}

/// True for a tracked `plugins/<name>/CHANGELOG.md` path.
fn is_plugin_changelog(path: &str) -> bool {
    let mut segs = path.split('/');
    matches!(
        (segs.next(), segs.next(), segs.next(), segs.next()),
        (Some("plugins"), Some(name), Some("CHANGELOG.md"), None) if !name.is_empty()
    )
}

/// The plugin a changed path belongs to, or `None` when the path isn't under
/// `plugins/<name>/` at all, or falls under that plugin's `docs/`/`scripts/`
/// at exactly depth 2 (the git-add -f exemption — deeper `scripts`/`docs`
/// segments, e.g. under `skills/<skill>/`, are real shipped content and still
/// count).
fn changed_plugin_name(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() < 2 || segs[0] != "plugins" || segs[1].is_empty() {
        return None;
    }
    if segs.len() >= 3 && matches!(segs[2], "docs" | "scripts") {
        return None;
    }
    Some(segs[1].to_string())
}

/// Pure decision: given a branch's changed files and which `CHANGELOG.md`
/// paths are tracked at the merge base, which changelog entries does the
/// branch owe and hasn't paid?
///
/// No I/O — takes the output of `changed_files` and `tracked_changelog_paths`.
pub fn missing_changelogs(changed: &[String], tracked_changelogs: &[String]) -> Vec<Owed> {
    let is_monorepo_class = tracked_changelogs.iter().any(|p| is_plugin_changelog(p));

    if is_monorepo_class {
        let mut owed = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for f in changed {
            let Some(name) = changed_plugin_name(f) else {
                continue;
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            let expected = format!("plugins/{name}/CHANGELOG.md");
            if !changed.iter().any(|c| c == &expected) {
                owed.push(Owed::PerPlugin(name));
            }
        }
        return owed;
    }

    let has_root_changelog = tracked_changelogs.iter().any(|p| p == "CHANGELOG.md");
    if !has_root_changelog {
        // Meta-repo shape: no changelog anywhere in the tree — nothing owed.
        return Vec::new();
    }

    if changed.is_empty() || changed.iter().any(|f| f == "CHANGELOG.md") {
        return Vec::new();
    }
    vec![Owed::RepoRoot]
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // --- Check::run wiring (I/O smoke — no real git repo needed for these) ---

    #[test]
    fn non_ship_command_allowed() {
        let result = WarnChangelogEntry.run(&make_bash("gh pr create --draft"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnChangelogEntry.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn ship_anchor_without_cwd_allowed() {
        let result = WarnChangelogEntry.run(&make_bash("gh pr create --title x"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- missing_changelogs: pure function tests ---

    #[test]
    fn monorepo_class_plugin_change_without_changelog_fires() {
        let changed = s(&["plugins/cadence/skills/attune/SKILL.md"]);
        let tracked = s(&["plugins/cadence/CHANGELOG.md", "plugins/other/CHANGELOG.md"]);
        let owed = missing_changelogs(&changed, &tracked);
        assert_eq!(owed, vec![Owed::PerPlugin("cadence".to_string())]);
    }

    #[test]
    fn monorepo_class_root_changelog_edit_never_satisfies_plugin_change() {
        // HARD RULE: a root CHANGELOG.md edit is not a plugin's own changelog.
        let changed = s(&["plugins/cadence/skills/attune/SKILL.md", "CHANGELOG.md"]);
        let tracked = s(&["plugins/cadence/CHANGELOG.md"]);
        let owed = missing_changelogs(&changed, &tracked);
        assert_eq!(owed, vec![Owed::PerPlugin("cadence".to_string())]);
    }

    #[test]
    fn monorepo_class_with_plugin_changelog_present_is_silent() {
        let changed = s(&[
            "plugins/cadence/skills/attune/SKILL.md",
            "plugins/cadence/CHANGELOG.md",
        ]);
        let tracked = s(&["plugins/cadence/CHANGELOG.md"]);
        assert!(missing_changelogs(&changed, &tracked).is_empty());
    }

    #[test]
    fn root_class_code_change_without_root_changelog_fires() {
        let changed = s(&["src/main.rs"]);
        let tracked = s(&["CHANGELOG.md"]);
        assert_eq!(missing_changelogs(&changed, &tracked), vec![Owed::RepoRoot]);
    }

    #[test]
    fn root_class_with_root_changelog_edit_is_silent() {
        let changed = s(&["src/main.rs", "CHANGELOG.md"]);
        let tracked = s(&["CHANGELOG.md"]);
        assert!(missing_changelogs(&changed, &tracked).is_empty());
    }

    #[test]
    fn cadence_lab_shape_no_plugin_changelogs_routes_to_root() {
        // cadence-lab: plugin.json-bearing subdirs but no plugins/*/CHANGELOG.md
        // tracked — falls to root-class, not silent.
        let changed = s(&["vibes/plugin.json", "vibes/commands/vibe.md"]);
        let tracked = s(&["CHANGELOG.md"]);
        assert_eq!(missing_changelogs(&changed, &tracked), vec![Owed::RepoRoot]);
    }

    #[test]
    fn meta_repo_shape_no_root_changelog_is_silent() {
        // No CHANGELOG.md anywhere in the tracked tree — the exemption falls
        // out of class inference for free.
        let changed = s(&["docs/plans/2026-08-19-thing.md", "docs/lore/estate.md"]);
        let tracked: Vec<String> = vec![];
        assert!(missing_changelogs(&changed, &tracked).is_empty());
    }

    #[test]
    fn plugin_skills_scripts_at_depth_four_is_not_exempted() {
        // plugins/<name>/skills/<skill>/scripts/ is tracked, shipped content —
        // "scripts" here sits at depth 4, not the depth-2 docs/scripts
        // exemption meant to defend against `git add -f` sneaking non-runtime
        // cruft past the monorepo's own gitignore.
        let changed = s(&["plugins/cadence/skills/attune/scripts/gen.py"]);
        let tracked = s(&["plugins/cadence/CHANGELOG.md"]);
        assert_eq!(
            missing_changelogs(&changed, &tracked),
            vec![Owed::PerPlugin("cadence".to_string())]
        );
    }

    #[test]
    fn plugin_docs_scripts_at_depth_two_is_exempted() {
        let changed = s(&[
            "plugins/cadence/docs/notes.md",
            "plugins/cadence/scripts/gen.py",
        ]);
        let tracked = s(&["plugins/cadence/CHANGELOG.md"]);
        assert!(missing_changelogs(&changed, &tracked).is_empty());
    }

    #[test]
    fn multiple_touched_plugins_each_owe_their_own() {
        let changed = s(&[
            "plugins/cadence/skills/attune/SKILL.md",
            "plugins/cadence-forge/skills/polish/SKILL.md",
            "plugins/cadence-forge/CHANGELOG.md",
        ]);
        let tracked = s(&[
            "plugins/cadence/CHANGELOG.md",
            "plugins/cadence-forge/CHANGELOG.md",
        ]);
        assert_eq!(
            missing_changelogs(&changed, &tracked),
            vec![Owed::PerPlugin("cadence".to_string())]
        );
    }

    #[test]
    fn empty_diff_owes_nothing() {
        let tracked = s(&["CHANGELOG.md"]);
        assert!(missing_changelogs(&[], &tracked).is_empty());
        let tracked_mono = s(&["plugins/cadence/CHANGELOG.md"]);
        assert!(missing_changelogs(&[], &tracked_mono).is_empty());
    }

    // --- is_plugin_changelog / changed_plugin_name edge cases ---

    #[test]
    fn is_plugin_changelog_requires_exact_shape() {
        assert!(is_plugin_changelog("plugins/cadence/CHANGELOG.md"));
        assert!(!is_plugin_changelog("CHANGELOG.md"));
        assert!(!is_plugin_changelog("plugins/cadence/docs/CHANGELOG.md"));
        assert!(!is_plugin_changelog("plugins/CHANGELOG.md"));
    }

    #[test]
    fn changed_plugin_name_non_plugin_path_is_none() {
        assert_eq!(changed_plugin_name("src/main.rs"), None);
        assert_eq!(changed_plugin_name("README.md"), None);
    }
}
