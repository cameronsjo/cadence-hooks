//! The generated OpenSpec skills and `/opsx` commands call the pinned CLI
//! (cadence-hooks#1446).
//!
//! `openspec init` and `openspec update` write files that pre-allow a bare
//! `openspec` (`allowed-tools: Bash(openspec:*)`), which would run whatever
//! `openspec` is on PATH, unpinned, with no prompt, for every subcommand.
//! `scripts/openspec-localize.sh` narrows the grant to the wrapper and the
//! subcommands the skills run; this test fails when a regeneration undoes
//! that, and the fix is to rerun the script.

use std::fs;
use std::path::{Path, PathBuf};

/// What `scripts/openspec-localize.sh` writes under each file's frontmatter.
const PINNED_MARKER: &str = "<!-- cadence-hooks: pinned openspec CLI -->";

fn generated_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for skills in [root.join(".claude/skills"), root.join(".agents/skills")] {
        let Ok(entries) = fs::read_dir(&skills) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("openspec-") {
                let skill = entry.path().join("SKILL.md");
                if skill.is_file() {
                    files.push(skill);
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir(root.join(".claude/commands/opsx")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn openspec_skills_use_the_pinned_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = generated_files(root);
    assert!(
        !files.is_empty(),
        "no generated OpenSpec skills found; the guard matched nothing"
    );
    let stale: Vec<String> = files
        .iter()
        .filter(|f| {
            let body = fs::read_to_string(f).unwrap_or_default();
            body.contains("Bash(openspec")
                || body.contains("Bash(scripts/openspec.sh:")
                || !body.contains(PINNED_MARKER)
        })
        .map(|f| f.strip_prefix(root).unwrap_or(f).display().to_string())
        .collect();
    assert!(
        stale.is_empty(),
        "not pointed at the pinned CLI; run scripts/openspec-localize.sh: {stale:?}"
    );
}
