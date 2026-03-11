use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Markers that require GitHub issue references.
const MARKERS: &[&str] = &[
    "TODO", "FIXME", "HACK", "XXX", "REFACTOR", "BUG", "OPTIMIZE",
];

/// File extensions exempt from orphaned marker checks.
const EXEMPT_EXTENSIONS: &[&str] = &["md", "txt", "json", "yml", "yaml", "toml", "ini", "env"];

/// Path prefixes exempt from orphaned marker checks.
const EXEMPT_PATHS: &[&str] = &["docs/", "documentation/"];

// Matches MARKER followed by colon, without a (#NNN) reference
static ORPHANED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let markers = MARKERS.join("|");
    Regex::new(&format!(r"\b({markers})\s*:")).expect("pattern should compile")
});

// Matches MARKER with proper reference format: MARKER(#NNN):
static REFERENCED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let markers = MARKERS.join("|");
    Regex::new(&format!(r"\b({markers})\(#\d+\):")).expect("pattern should compile")
});

/// Check if a file path is exempt from marker checking.
fn is_exempt(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next()
        && EXEMPT_EXTENSIONS.contains(&ext)
    {
        return true;
    }

    let normalized = path.replace('\\', "/");
    EXEMPT_PATHS
        .iter()
        .any(|prefix| normalized.contains(&format!("/{prefix}")) || normalized.starts_with(prefix))
}

/// Find orphaned markers in content. Returns list of (line_number, line_text) pairs.
pub fn find_orphaned(content: &str) -> Vec<(usize, String)> {
    let mut orphans = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        if ORPHANED_PATTERN.is_match(line) && !REFERENCED_PATTERN.is_match(line) {
            orphans.push((idx + 1, line.trim().to_string()));
        }
    }

    orphans
}

pub struct OrphanedTodoGuard;

impl Check for OrphanedTodoGuard {
    fn name(&self) -> &str {
        "block-orphaned-todos"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

        if let Some(path) = input.file_path()
            && is_exempt(path)
        {
            return CheckResult::allow();
        }

        let orphans = find_orphaned(content);
        if orphans.is_empty() {
            return CheckResult::allow();
        }

        let mut msg = String::new();
        msg.push_str("🚫 BLOCKED: Orphaned code markers detected");
        if let Some(path) = input.file_path() {
            msg.push_str(&format!(" in {path}"));
        }
        msg.push_str("\n\nFound markers without GitHub issue references:\n");

        for (line, text) in &orphans {
            msg.push_str(&format!("  L{line}: {text}\n"));
        }

        msg.push_str("\nRequired format: MARKER(#ISSUE): description\n");

        CheckResult::block(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_marker(kind: &str, has_ref: bool) -> String {
        if has_ref {
            format!("// {kind}(#123): description") // colon after (#NNN) is required
        } else {
            format!("// {kind}: description")
        }
    }

    #[test]
    fn referenced_marker_passes() {
        assert!(find_orphaned(&make_marker("TODO", true)).is_empty());
    }

    #[test]
    fn orphaned_marker_detected() {
        let orphans = find_orphaned(&make_marker("TODO", false));
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, 1);
    }

    #[test]
    fn fixme_without_reference_detected() {
        let orphans = find_orphaned(&make_marker("FIXME", false));
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn exempt_extensions() {
        assert!(is_exempt("docs/README.md"));
        assert!(is_exempt("config.yaml"));
        assert!(is_exempt("data.json"));
        assert!(!is_exempt("src/main.rs"));
    }

    #[test]
    fn exempt_paths() {
        assert!(is_exempt("docs/architecture.txt"));
        assert!(is_exempt("/project/documentation/guide.html"));
        assert!(!is_exempt("src/docs_handler.rs"));
    }

    #[test]
    fn mixed_referenced_and_orphaned() {
        let content = format!(
            "{}\n{}\n{}",
            make_marker("TODO", true),
            make_marker("HACK", false),
            make_marker("BUG", false),
        );
        let orphans = find_orphaned(&content);
        assert_eq!(orphans.len(), 2);
    }

    // All marker types
    #[test]
    fn all_markers_detected_when_orphaned() {
        for marker in MARKERS {
            let orphans = find_orphaned(&make_marker(marker, false));
            assert_eq!(orphans.len(), 1, "marker {marker} should be detected");
        }
    }

    #[test]
    fn all_markers_pass_when_referenced() {
        for marker in MARKERS {
            let orphans = find_orphaned(&make_marker(marker, true));
            assert!(
                orphans.is_empty(),
                "marker {marker} should pass when referenced"
            );
        }
    }

    #[test]
    fn empty_content_passes() {
        assert!(find_orphaned("").is_empty());
    }

    #[test]
    fn no_markers_passes() {
        assert!(find_orphaned("fn main() { println!(\"hello\"); }").is_empty());
    }

    #[test]
    fn line_numbers_accurate() {
        let content = "line 1\nline 2\n// TODO: fix this\nline 4";
        let orphans = find_orphaned(content);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].0, 3);
    }

    // Check::run() integration
    fn make_check_input(path: Option<&str>, content: &str) -> HookInput {
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: path.map(String::from),
                path: None,
                command: None,
                content: Some(content.into()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn run_blocks_orphaned_in_code() {
        let input = make_check_input(Some("src/main.rs"), &make_marker("TODO", false));
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn run_allows_exempt_path() {
        let input = make_check_input(Some("docs/guide.md"), &make_marker("TODO", false));
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_allows_no_content() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("src/main.rs".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_allows_clean_code() {
        let input = make_check_input(Some("src/main.rs"), "fn main() {}");
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn all_exempt_extensions() {
        for ext in EXEMPT_EXTENSIONS {
            assert!(is_exempt(&format!("file.{ext}")), "{ext} should be exempt");
        }
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn marker_in_string_still_detected() {
        // Markers inside string literals are still flagged — no AST awareness
        let content = "let msg = \"TODO: fix this later\";";
        let orphans = find_orphaned(content);
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn marker_without_colon_not_detected() {
        // "TODO fix this" without colon should NOT match
        let orphans = find_orphaned("// TODO fix this");
        assert!(orphans.is_empty());
    }

    #[test]
    fn marker_lowercase_not_detected() {
        // Markers must be uppercase
        let orphans = find_orphaned("// todo: fix this");
        assert!(orphans.is_empty());
    }

    #[test]
    fn marker_with_space_before_colon() {
        // "TODO :" with space before colon
        let orphans = find_orphaned("// TODO : fix this");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn referenced_with_different_issue_number() {
        assert!(find_orphaned("// TODO(#1): first").is_empty());
        assert!(find_orphaned("// TODO(#999): large number").is_empty());
        assert!(find_orphaned("// TODO(#12345): very large").is_empty());
    }

    #[test]
    fn reference_without_colon_detected_as_orphan() {
        // TODO(#123) without trailing colon is NOT a valid reference
        let orphans = find_orphaned("// TODO(#123) missing colon after ref");
        // No colon after marker at all → ORPHANED_PATTERN won't match either
        assert!(orphans.is_empty());
    }

    #[test]
    fn reference_without_colon_but_with_marker_colon() {
        // "TODO: something TODO(#123) something" — has orphaned TODO: but
        // the reference lacks its own colon, so it doesn't cancel the orphan
        let orphans = find_orphaned("// TODO: fix TODO(#123) partial ref");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn marker_at_end_of_line() {
        let orphans = find_orphaned("code(); // FIXME: broken");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn multiple_markers_same_line() {
        // Two markers on one line — only counts as one orphan line
        let orphans = find_orphaned("// TODO: first FIXME: second");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn referenced_and_orphaned_same_line() {
        // Line has TODO(#1): (valid ref) and also FIXME: (orphan)
        // Both ORPHANED and REFERENCED match on the same line → line passes
        let content = "// TODO(#1): referenced FIXME: orphaned";
        let orphans = find_orphaned(content);
        assert!(orphans.is_empty());
    }

    #[test]
    fn exempt_path_with_docs_prefix() {
        assert!(is_exempt("docs/api-guide.html"));
    }

    #[test]
    fn exempt_documentation_path() {
        assert!(is_exempt("/project/documentation/setup.html"));
    }

    #[test]
    fn non_exempt_docs_in_filename() {
        // "docs" in a filename but not as a path segment
        assert!(!is_exempt("src/docs_handler.rs"));
    }

    #[test]
    fn block_message_includes_line_numbers() {
        let input = make_check_input(
            Some("src/lib.rs"),
            "fn foo() {}\n// TODO: fix\nfn bar() {}\n// HACK: workaround\n",
        );
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("L2"));
        assert!(msg.contains("L4"));
    }

    #[test]
    fn run_no_path_with_orphan_blocks() {
        // No path but has orphaned markers — should still block
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: Some(make_marker("TODO", false)),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = OrphanedTodoGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn optimize_marker_detected() {
        let orphans = find_orphaned("// OPTIMIZE: use a HashMap here");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn xxx_marker_detected() {
        let orphans = find_orphaned("// XXX: this needs attention");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn refactor_marker_detected() {
        let orphans = find_orphaned("// REFACTOR: extract method");
        assert_eq!(orphans.len(), 1);
    }

    #[test]
    fn bug_marker_detected() {
        let orphans = find_orphaned("// BUG: off-by-one error");
        assert_eq!(orphans.len(), 1);
    }
}
