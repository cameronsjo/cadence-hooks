use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Markers that require GitHub issue references.
const MARKERS: &[&str] = &["TODO", "FIXME", "HACK", "XXX", "REFACTOR", "BUG", "OPTIMIZE"];

/// File extensions exempt from orphaned marker checks.
const EXEMPT_EXTENSIONS: &[&str] = &["md", "txt", "json", "yml", "yaml", "toml", "ini", "env"];

/// Path prefixes exempt from orphaned marker checks.
const EXEMPT_PATHS: &[&str] = &["docs/", "documentation/"];

// Matches MARKER followed by colon, without a (#NNN) reference
static ORPHANED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let markers = MARKERS.join("|");
    Regex::new(&format!(r"\b({markers})\s*:")).expect("pattern should compile")
});

// Matches MARKER with proper reference format
static REFERENCED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let markers = MARKERS.join("|");
    Regex::new(&format!(r"\b({markers})\(#\d+\)")).expect("pattern should compile")
});

/// Check if a file path is exempt from marker checking.
fn is_exempt(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next() {
        if EXEMPT_EXTENSIONS.contains(&ext) {
            return true;
        }
    }

    let normalized = path.replace('\\', "/");
    EXEMPT_PATHS.iter().any(|prefix| {
        normalized.contains(&format!("/{prefix}")) || normalized.starts_with(prefix)
    })
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

        if let Some(path) = input.file_path() {
            if is_exempt(path) {
                return CheckResult::allow();
            }
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
            format!("// {kind}(#123): description")
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
}
