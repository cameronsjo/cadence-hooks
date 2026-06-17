//! Enforce line limits on auto-memory files.
//!
//! MEMORY.md is loaded into every session's context window, so it must stay
//! under 200 lines. Topic files have a softer 300-line guideline.

use cadence_hooks_core::{Check, CheckResult, HookInput};

const MEMORY_HARD_LIMIT: usize = 200;
const MEMORY_SOFT_LIMIT: usize = 180;
const TOPIC_SOFT_LIMIT: usize = 300;

/// Blocks writes that push MEMORY.md past 200 lines, warns as it approaches the limit.
pub struct MemoryGuard;

impl MemoryGuard {
    /// True when `path` is an auto-memory file: under the resolved Claude
    /// config dir's `projects/<slug>/memory/` tree.
    ///
    /// Anchoring here keeps the guard off unrelated project files that merely
    /// have a `memory/` directory (`docs/memory/`, `assets/memory/`) — #93.
    fn is_memory_path(path: &str) -> bool {
        let config_dir = cadence_hooks_core::paths::claude_config_dir();
        Self::is_memory_path_under(path, &config_dir.to_string_lossy())
    }

    /// Pure form of [`Self::is_memory_path`], env-free for unit testing.
    ///
    /// Matches a `memory/` segment rooted at an auto-memory tree — either under
    /// the resolved `<config_dir>/projects/` (honoring a relocated
    /// `CLAUDE_CONFIG_DIR`) or under a default `.claude/projects/` tree. A bare
    /// `…/memory/…` no longer matches.
    fn is_memory_path_under(path: &str, config_dir: &str) -> bool {
        if !path.contains("/memory/") {
            return false;
        }
        let projects_root = format!("{}/projects/", config_dir.trim_end_matches('/'));
        path.starts_with(&projects_root) || path.contains("/.claude/projects/")
    }

    fn is_memory_md(path: &str) -> bool {
        path.ends_with("/MEMORY.md")
    }
}

impl Check for MemoryGuard {
    fn name(&self) -> &str {
        "memory-guard"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        if !Self::is_memory_path(&path) {
            return CheckResult::allow();
        }

        // Measure the *resulting* document, not the edit fragment (#92).
        // effective_content() simulates Edit/MultiEdit against the on-disk file;
        // for Write it's the content as-is. Fall back to the current on-disk
        // file when the payload carries no editable text, and fail open (allow)
        // when neither is available (ADR-0001).
        let content = match input.effective_content() {
            Some(c) => c,
            None => match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return CheckResult::allow(),
            },
        };

        let line_count = content.lines().count();

        if Self::is_memory_md(&path) {
            if line_count > MEMORY_HARD_LIMIT {
                return CheckResult::block(format!(
                    "🚫 MEMORY.md is {line_count} lines (limit: {MEMORY_HARD_LIMIT}).\n\
                     Move details to topic files in the same directory.\n\
                     Keep MEMORY.md as a concise index under {MEMORY_HARD_LIMIT} lines."
                ));
            }
            if line_count >= MEMORY_SOFT_LIMIT {
                return CheckResult::nudge(format!(
                    "⚠️  MEMORY.md is {line_count}/{MEMORY_HARD_LIMIT} lines. \
                     Consider moving details to topic files."
                ));
            }
        } else {
            // Topic file
            if line_count > TOPIC_SOFT_LIMIT {
                return CheckResult::nudge(format!(
                    "⚠️  Topic file is {line_count} lines (soft limit: {TOPIC_SOFT_LIMIT}). \
                     Consider splitting into smaller topic files."
                ));
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(path: &str, lines: usize) -> HookInput {
        let content: String = (0..lines).map(|i| format!("Line {i}\n")).collect();
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: Some(content),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        }
    }

    #[test]
    fn non_memory_path_allowed() {
        let input = make_input("/project/src/main.rs", 500);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn memory_md_under_limit_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 100);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn memory_md_at_soft_limit_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 185);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn memory_md_over_hard_limit_blocks() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 250);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn topic_file_over_soft_limit_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/debugging.md", 350);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn memory_md_exactly_at_hard_limit_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 200);
        let result = MemoryGuard.run(&input);
        // 200 >= MEMORY_SOFT_LIMIT (180), so warns
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn memory_md_exactly_at_soft_limit_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 180);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn memory_md_one_under_soft_limit_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 179);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn memory_md_at_201_blocked() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 201);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn topic_file_at_300_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/debugging.md", 300);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn topic_file_at_301_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/debugging.md", 301);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    #[test]
    fn empty_memory_md_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 0);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn path_with_memory_substring_but_not_dir() {
        // "memory" in filename but not as /memory/ dir segment
        let input = make_input("/project/src/in_memory_cache.rs", 500);
        let result = MemoryGuard.run(&input);
        // Contains "/memory/" check — "in_memory_cache" does NOT contain "/memory/"
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn topic_file_under_limit_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/patterns.md", 100);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn different_memory_path_formats() {
        // Various valid memory paths
        assert!(MemoryGuard::is_memory_path(
            "/home/user/.claude/projects/foo/memory/MEMORY.md"
        ));
        assert!(MemoryGuard::is_memory_path(
            "/home/user/.claude/projects/bar/memory/topic.md"
        ));
        assert!(!MemoryGuard::is_memory_path(
            "/home/user/.claude/projects/foo/src/main.rs"
        ));
    }

    #[test]
    fn is_memory_md_detection() {
        assert!(MemoryGuard::is_memory_md(
            "/home/user/.claude/projects/foo/memory/MEMORY.md"
        ));
        assert!(!MemoryGuard::is_memory_md(
            "/home/user/.claude/projects/foo/memory/topic.md"
        ));
        assert!(!MemoryGuard::is_memory_md(
            "/home/user/.claude/projects/foo/memory/MEMORY.txt"
        ));
    }

    #[test]
    fn single_line_memory_md() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 1);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn large_topic_file() {
        let input = make_input("/home/user/.claude/projects/foo/memory/debugging.md", 1000);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
    }

    // --- #93: path anchored to the auto-memory root (pure, env-free) ---

    #[test]
    fn auto_memory_under_default_claude_matches() {
        assert!(MemoryGuard::is_memory_path_under(
            "/home/user/.claude/projects/foo/memory/MEMORY.md",
            "/home/user/.claude"
        ));
    }

    #[test]
    fn auto_memory_under_relocated_config_dir_matches() {
        // CLAUDE_CONFIG_DIR relocation: config dir not named ".claude".
        assert!(MemoryGuard::is_memory_path_under(
            "/custom/cfg/projects/foo/memory/MEMORY.md",
            "/custom/cfg"
        ));
    }

    #[test]
    fn project_docs_memory_is_not_auto_memory() {
        // #93: a real project file in a docs/memory/ dir must NOT be guarded.
        assert!(!MemoryGuard::is_memory_path_under(
            "/work/repo/docs/memory/MEMORY.md",
            "/home/user/.claude"
        ));
    }

    #[test]
    fn project_assets_memory_topic_is_not_auto_memory() {
        assert!(!MemoryGuard::is_memory_path_under(
            "/work/repo/assets/memory/notes.md",
            "/home/user/.claude"
        ));
    }

    // --- #92: measure the resulting document, not the edit fragment ---

    fn on_disk_memory(lines: usize) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let mem_dir = dir.path().join(".claude/projects/foo/memory");
        std::fs::create_dir_all(&mem_dir).unwrap();
        let path = mem_dir.join("MEMORY.md");
        let body: String = (0..lines).map(|i| format!("Line {i}\n")).collect();
        std::fs::write(&path, &body).unwrap();
        (dir, path.to_str().unwrap().to_string())
    }

    #[test]
    fn edit_pushing_near_limit_file_over_hard_limit_blocks() {
        // 195-line MEMORY.md + an Edit appending 30 lines = 225 → Block.
        // Old code measured the 30-line fragment → Allow (the bypass).
        let (_dir, path) = on_disk_memory(195);
        let appended: String = (0..30).map(|i| format!("New {i}\n")).collect();
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path),
                old_string: Some("Line 194\n".into()),
                new_string: Some(format!("Line 194\n{appended}")),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            MemoryGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn small_edit_to_small_memory_file_allowed() {
        let (_dir, path) = on_disk_memory(50);
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path),
                old_string: Some("Line 0\n".into()),
                new_string: Some("Line 0 edited\n".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            MemoryGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn multi_edit_pushing_file_over_hard_limit_blocks() {
        // content() is None for MultiEdit → old code measured the PRE-edit file
        // (195 → Allow). effective_content() simulates edits[] → Block.
        let (_dir, path) = on_disk_memory(195);
        let grown: String = (0..35).map(|i| format!("Grown {i}\n")).collect();
        let input = HookInput {
            tool_name: Some("MultiEdit".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(path),
                edits: Some(vec![cadence_hooks_core::EditOperation {
                    old_string: Some("Line 100\n".into()),
                    new_string: Some(grown),
                    replace_all: None,
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            MemoryGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }
}
