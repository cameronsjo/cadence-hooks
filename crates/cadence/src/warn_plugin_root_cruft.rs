//! Nudge on a write that creates plugin-root `docs/` or `scripts/` content.
//!
//! A marketplace copies each whole plugin directory into the plugin cache with
//! no files-allowlist, so a non-runtime artifact at a plugin root
//! (`plugins/<name>/docs/…`, `plugins/<name>/scripts/…`) ships once per
//! marketplace commit. The cadence monorepo already carries a `.gitignore` rule
//! and a `plugin-runtime-only` CI check; this is the local, pre-commit
//! belt-and-suspenders (cadence-hooks#282).
//!
//! **Scope, per the 2026-08-09 rulings in
//! `docs/plans/2026-07-28-guard-design-decisions.md` §2:**
//!
//! - A cheap **segment pre-filter** runs first and costs no I/O: the path must
//!   contain `plugins/<name>/{docs,scripts}/<something>`, with `docs`/`scripts`
//!   *directly* under the plugin directory. Split on `/`, never a substring or
//!   a `*` glob — a skill-nested `skills/<skill>/scripts/` is a runtime asset
//!   and never matches.
//! - Only a pre-filter hit reads the repo's **marketplace manifest**
//!   (`<root>/.claude-plugin/marketplace.json`, through the capped untrusted
//!   reader), and the target counts only when a `plugins[].source` string names
//!   exactly that plugin directory. No manifest, or a manifest that does not
//!   declare the directory, means this is not a plugin marketplace and the
//!   check stays silent — no folder-shape guessing, no hardcoded repo names.
//! - The plugin **cache** is out of scope.
//!
//! **Nudge tier** per the plan's shared tier policy: exit 0 with the message as
//! additional context. Every read or parse failure allows (ADR-0001).

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};

/// Plugin-root directories that never ship runtime content.
const CRUFT_DIRS: &[&str] = &["docs", "scripts"];

/// Nudges when a write targets a manifest-declared plugin's root `docs/`/`scripts/`.
pub struct WarnPluginRootCruft;

impl Check for WarnPluginRootCruft {
    fn name(&self) -> &str {
        "warn-plugin-root-cruft"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };
        for candidate in candidates(&path) {
            let manifest = candidate
                .repo_root
                .join(".claude-plugin")
                .join("marketplace.json");
            let Some(raw) = cadence_hooks_core::paths::read_untrusted_config(&manifest) else {
                continue;
            };
            if manifest_declares(&raw, &candidate.plugin) {
                return CheckResult::nudge(render(&candidate));
            }
        }
        CheckResult::allow()
    }
}

/// A pre-filter hit: a path shaped like `<repo_root>/plugins/<plugin>/<dir>/…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The directory that would hold `.claude-plugin/marketplace.json`.
    pub repo_root: PathBuf,
    /// The plugin directory name under `plugins/`.
    pub plugin: String,
    /// `docs` or `scripts`.
    pub dir: String,
}

/// The segment pre-filter. Pure: no I/O.
///
/// Every `plugins` segment followed by a name and then `docs`/`scripts` with at
/// least one more segment below it yields a candidate — the innermost first, so
/// a monorepo nested inside another `plugins/` tree is judged against its own
/// manifest. `.`/`..` are resolved before matching, so a traversal cannot move
/// `docs` into or out of the plugin-root position.
pub fn candidates(path: &str) -> Vec<Candidate> {
    let components = normalized_components(path);
    let absolute = path.starts_with('/') || path.starts_with('\\');
    let mut found = Vec::new();
    for i in (0..components.len()).rev() {
        if components[i] != "plugins" || components.len() < i + 4 {
            continue;
        }
        let dir = &components[i + 2];
        if !CRUFT_DIRS.contains(&dir.as_str()) {
            continue;
        }
        let joined = components[..i].join("/");
        let repo_root = if absolute {
            PathBuf::from(format!("/{joined}"))
        } else {
            PathBuf::from(joined)
        };
        found.push(Candidate {
            repo_root,
            plugin: components[i + 1].clone(),
            dir: dir.clone(),
        });
    }
    found
}

fn normalized_components(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for component in raw.replace('\\', "/").split('/') {
        match component {
            "" | "." => {}
            ".." if out.last().is_some_and(|last| last != "..") => {
                out.pop();
            }
            value => out.push(value.to_owned()),
        }
    }
    out
}

/// True when the manifest's `plugins[]` declares a local `source` of exactly
/// `plugins/<plugin>` (`./plugins/<plugin>`, trailing slash tolerated). A
/// non-string source (a remote `github`/`git-subdir` object) names another
/// repo, not a directory here, and never matches. A manifest that fails to
/// parse declares nothing.
pub fn manifest_declares(raw: &str, plugin: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    let Some(plugins) = value.get("plugins").and_then(|p| p.as_array()) else {
        return false;
    };
    let want = format!("plugins/{plugin}");
    plugins
        .iter()
        .filter_map(|p| p.get("source").and_then(|s| s.as_str()))
        .any(|source| {
            let s = source.trim();
            let s = s.strip_prefix("./").unwrap_or(s);
            s.trim_end_matches('/') == want
        })
}

fn render(c: &Candidate) -> String {
    let plugin = cadence_hooks_core::display::sanitize_field(&c.plugin, 80);
    let dir = &c.dir;
    let root = Path::new(&c.repo_root).display().to_string();
    let root = cadence_hooks_core::display::sanitize_field(&root, 200);
    format!(
        "📦  This write creates `plugins/{plugin}/{dir}/` content. The marketplace copies the whole \
         plugin directory into the plugin cache on every marketplace commit, so a plugin-root \
         `{dir}/` ships as cruft — and the repo's `plugin-runtime-only` CI check and \
         `.gitignore` will reject it later.\n\n\
         Put it where it does not ship:\n  \
         - session plans, research, maintenance scripts → the monorepo-root `docs/` or `scripts/` \
         (under {root})\n  \
         - field reports → the vault, never a repo\n  \
         - a runtime asset a SKILL.md or README cites → the plugin's `references/`, or a \
         skill-nested `skills/<skill>/scripts/`\n\n\
         Advisory only."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit, make_write};

    const MANIFEST: &str = r#"{
      "name": "cadence",
      "plugins": [
        {"name": "cadence", "source": "./plugins/cadence"},
        {"name": "cadence-forge", "source": "./plugins/cadence-forge/"},
        {"name": "remote", "source": {"source": "github", "repo": "o/r"}}
      ]
    }"#;

    fn repo_with_manifest(manifest: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let m = dir.path().join(".claude-plugin");
        std::fs::create_dir_all(&m).unwrap();
        std::fs::write(m.join("marketplace.json"), manifest).unwrap();
        dir
    }

    fn outcome_for(root: &Path, rel: &str) -> Outcome {
        let p = root.join(rel);
        WarnPluginRootCruft
            .run(&make_write(p.to_str().unwrap(), "x"))
            .outcome
    }

    #[test]
    fn pre_filter_matches_plugin_root_only() {
        let hits = [
            "/r/plugins/cadence/docs/plan.md",
            "/r/plugins/cadence/scripts/gen.py",
            "/r/plugins/cadence/docs/deep/nested/x.md",
        ];
        for p in hits {
            let c = candidates(p);
            assert_eq!(c.len(), 1, "{p}");
            assert_eq!(c[0].repo_root, PathBuf::from("/r"));
            assert_eq!(c[0].plugin, "cadence");
        }
        let misses = [
            // Skill-nested scripts are runtime assets.
            "/r/plugins/cadence/skills/writing-skills/scripts/gen.py",
            "/r/plugins/cadence/references/docs/x.md",
            // Monorepo-root docs/scripts are the right home.
            "/r/docs/plans/x.md",
            "/r/scripts/x.py",
            // The directory itself, with nothing under it, is not a file write.
            "/r/plugins/cadence/docs",
            // Cache layout: `docs` sits at index 3, not 2.
            "/home/u/.claude/plugins/cache/workbench/cadence/docs/x.md",
            "/r/plugins/docs/x.md",
        ];
        for p in misses {
            assert!(candidates(p).is_empty(), "{p}");
        }
    }

    #[test]
    fn traversal_is_resolved_before_the_segment_test() {
        assert_eq!(
            candidates("/r/plugins/cadence/skills/../docs/x.md").len(),
            1
        );
        assert!(candidates("/r/plugins/cadence/docs/../skills/s/scripts/x.py").is_empty());
    }

    #[test]
    fn manifest_must_declare_the_plugin_directory() {
        assert!(manifest_declares(MANIFEST, "cadence"));
        assert!(manifest_declares(MANIFEST, "cadence-forge"));
        assert!(!manifest_declares(MANIFEST, "remote"));
        assert!(!manifest_declares(MANIFEST, "undeclared"));
        assert!(!manifest_declares("not json", "cadence"));
        assert!(!manifest_declares(r#"{"plugins": "nope"}"#, "cadence"));
    }

    #[test]
    fn nudges_inside_a_declared_marketplace() {
        let repo = repo_with_manifest(MANIFEST);
        let r = repo.path();
        assert_eq!(
            outcome_for(r, "plugins/cadence/docs/plan.md"),
            Outcome::Nudge
        );
        assert_eq!(
            outcome_for(r, "plugins/cadence-forge/scripts/x.sh"),
            Outcome::Nudge
        );
        // Runtime assets and root docs stay silent.
        assert_eq!(
            outcome_for(r, "plugins/cadence/skills/s/scripts/x.sh"),
            Outcome::Allow
        );
        assert_eq!(outcome_for(r, "docs/plans/x.md"), Outcome::Allow);
        // A plugins/ directory the manifest does not declare is not ours to police.
        assert_eq!(outcome_for(r, "plugins/other/docs/x.md"), Outcome::Allow);
    }

    #[test]
    fn edits_and_multi_edits_are_judged_by_path() {
        let repo = repo_with_manifest(MANIFEST);
        let p = repo.path().join("plugins/cadence/docs/x.md");
        let p = p.to_str().unwrap();
        assert_eq!(
            WarnPluginRootCruft.run(&make_edit(p, "a", "b")).outcome,
            Outcome::Nudge
        );
        assert_eq!(
            WarnPluginRootCruft
                .run(&make_multi_edit(p, &[("a", "b")]))
                .outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn a_plugins_shaped_repo_without_a_manifest_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            outcome_for(dir.path(), "plugins/vim-thing/docs/x.md"),
            Outcome::Allow
        );
    }

    #[test]
    fn an_unparseable_manifest_fails_open() {
        let repo = repo_with_manifest("{ not json");
        assert_eq!(
            outcome_for(repo.path(), "plugins/cadence/docs/x.md"),
            Outcome::Allow
        );
    }
}
