use claude_hooks_core::{Check, CheckResult, HookInput};

const MEMORY_HARD_LIMIT: usize = 200;
const MEMORY_SOFT_LIMIT: usize = 180;
const TOPIC_SOFT_LIMIT: usize = 300;

pub struct MemoryGuard;

impl MemoryGuard {
    fn is_memory_path(path: &str) -> bool {
        path.contains("/memory/")
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

        if !Self::is_memory_path(path) {
            return CheckResult::allow();
        }

        // Try to get content from the write operation, fall back to reading the file
        let content = match input.content() {
            Some(c) => c.to_string(),
            None => match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return CheckResult::allow(),
            },
        };

        let line_count = content.lines().count();

        if Self::is_memory_md(path) {
            if line_count > MEMORY_HARD_LIMIT {
                return CheckResult::block(format!(
                    "🚫 MEMORY.md is {line_count} lines (limit: {MEMORY_HARD_LIMIT}).\n\
                     Move details to topic files in the same directory.\n\
                     Keep MEMORY.md as a concise index under {MEMORY_HARD_LIMIT} lines."
                ));
            }
            if line_count >= MEMORY_SOFT_LIMIT {
                return CheckResult::warn(format!(
                    "⚠️  MEMORY.md is {line_count}/{MEMORY_HARD_LIMIT} lines. \
                     Consider moving details to topic files."
                ));
            }
        } else {
            // Topic file
            if line_count > TOPIC_SOFT_LIMIT {
                return CheckResult::warn(format!(
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
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: Some(content),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn non_memory_path_allowed() {
        let input = make_input("/project/src/main.rs", 500);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn memory_md_under_limit_allowed() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 100);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn memory_md_at_soft_limit_warns() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 185);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn memory_md_over_hard_limit_blocks() {
        let input = make_input("/home/user/.claude/projects/foo/memory/MEMORY.md", 250);
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn topic_file_over_soft_limit_warns() {
        let input = make_input(
            "/home/user/.claude/projects/foo/memory/debugging.md",
            350,
        );
        let result = MemoryGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }
}
