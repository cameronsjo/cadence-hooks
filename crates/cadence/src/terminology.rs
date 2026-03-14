//! Block inclusive terminology violations in written content.
//!
//! Detects prohibited terms and suggests neutral alternatives.
//! Case-insensitive with word-boundary matching to avoid false positives.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::RegexSet;
use std::sync::LazyLock;

// NOTE: This file contains prohibited terms as detection patterns.
// It must be excluded from the terminology hook's own scanning.

/// Build a prohibited term from parts to avoid triggering the hook on source.
macro_rules! term {
    ($($part:expr),+) => { concat!($($part),+) }
}

/// Blocked terms and their replacements.
const VIOLATIONS: &[(&str, &str)] = &[
    (term!("white", "list"), "allowlist"),
    (term!("black", "list"), "blocklist, denylist"),
    (term!("master", " branch"), "main branch"),
    (term!("master", " node"), "primary node, leader node"),
    (term!("sla", "ve"), "replica, follower, secondary"),
    (
        term!("sanity", " check"),
        "validation check, confidence check, smoke test",
    ),
    (
        term!("dummy", " value"),
        "placeholder value, sample value, mock value",
    ),
    (
        term!("grand", "fathered"),
        "legacy status, exempted, inherited",
    ),
];

static PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<String> = VIOLATIONS
        .iter()
        .map(|(term, _)| format!(r"(?i)\b{}\b", regex::escape(term)))
        .collect();
    RegexSet::new(&patterns).expect("terminology patterns should compile")
});

/// Check content for inclusive terminology violations.
/// Returns vec of (term, suggested_replacement) pairs.
pub fn check_terminology(content: &str) -> Vec<(String, String)> {
    let matches = PATTERNS.matches(content);
    let mut found = Vec::new();

    for idx in matches.iter() {
        let (term, replacement) = VIOLATIONS[idx];
        found.push((term.to_string(), replacement.to_string()));
    }

    found
}

/// Paths that legitimately contain prohibited terms (hook source, test fixtures).
fn is_excluded_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with("claude.md")
        || path.contains("cadence-hooks/")
        || path.contains(".claude/hooks/")
        || path.contains(".claude/rules/")
}

/// Blocks content containing prohibited terminology and suggests alternatives.
pub struct TerminologyGuard;

impl Check for TerminologyGuard {
    fn name(&self) -> &str {
        "terminology-guard"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

        if let Some(ref path) = input.file_path()
            && is_excluded_path(path)
        {
            return CheckResult::allow();
        }

        let violations = check_terminology(content);
        if violations.is_empty() {
            return CheckResult::allow();
        }

        let mut msg = String::new();
        msg.push_str("🚫 BLOCKED: Inclusive terminology violation detected");
        if let Some(ref path) = input.file_path() {
            msg.push_str(&format!(" in {path}"));
        }
        msg.push_str("\n\nFound prohibited terms:\n");

        for (term, _) in &violations {
            msg.push_str(&format!("  - \"{term}\"\n"));
        }

        msg.push_str("\nRequired alternatives:\n");
        for (term, replacement) in &violations {
            msg.push_str(&format!("  {term} → {replacement}\n"));
        }

        CheckResult::block(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_content_passes() {
        assert!(check_terminology("use the allowlist for filtering").is_empty());
    }

    #[test]
    fn detects_prohibited_term() {
        let found = check_terminology(VIOLATIONS[0].0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "allowlist");
    }

    #[test]
    fn case_insensitive_detection() {
        let upper = VIOLATIONS[0].0.to_uppercase();
        let found = check_terminology(&upper);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn multiple_violations_detected() {
        let input = format!("{} and {}", VIOLATIONS[0].0, VIOLATIONS[1].0);
        let found = check_terminology(&input);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn excluded_paths_allowed() {
        assert!(is_excluded_path("/project/CLAUDE.md"));
        assert!(is_excluded_path(
            "/home/dev/cadence-hooks/crates/cadence/src/foo.rs"
        ));
        assert!(is_excluded_path(
            "/home/dev/.claude/hooks/enforcement/foo.sh"
        ));
        assert!(!is_excluded_path("/project/src/main.rs"));
    }

    #[test]
    fn blocks_on_violation_in_normal_file() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/main.rs".into()),
                path: None,
                command: None,
                content: Some(VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Unhappy path: bypass scenarios ---

    #[test]
    fn word_boundary_prevents_substring_match() {
        // "listed" contains "list" but word boundary should prevent match
        assert!(check_terminology("the items are listed here").is_empty());
    }

    #[test]
    fn plural_form_not_detected() {
        // "whitelists" — word boundary \b requires boundary after "t" but "s"
        // continues the word, so the plural form is NOT matched
        let found = check_terminology(&format!("{}s", VIOLATIONS[0].0));
        assert!(found.is_empty());
    }

    #[test]
    fn all_violations_detectable() {
        for (term, _) in VIOLATIONS {
            let found = check_terminology(term);
            assert!(!found.is_empty(), "term '{}' should be detected", term);
        }
    }

    #[test]
    fn empty_content_passes() {
        assert!(check_terminology("").is_empty());
    }

    #[test]
    fn no_content_returns_allow() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/main.rs".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn excluded_path_with_violations_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/rules/terminology.md".into()),
                path: None,
                command: None,
                content: Some(VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_includes_path() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/config.rs".into()),
                path: None,
                command: None,
                content: Some(VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("config.rs"));
    }

    #[test]
    fn mixed_case_detection() {
        // Test mixed case that isn't just all upper or all lower
        let term = VIOLATIONS[0].0;
        let mixed: String = term
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        let found = check_terminology(&mixed);
        assert_eq!(found.len(), 1);
    }

    // --- additional edge cases ---

    #[test]
    fn violation_with_punctuation() {
        // Term followed by punctuation should still match (word boundary at comma)
        let input = format!("{}, which we use daily", VIOLATIONS[0].0);
        let found = check_terminology(&input);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn violation_at_line_start() {
        let input = format!("{} is configured", VIOLATIONS[0].0);
        let found = check_terminology(&input);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn repeated_term_counted_once() {
        // RegexSet reports each pattern once, not per-occurrence
        let input = format!("{} and also {} again", VIOLATIONS[0].0, VIOLATIONS[0].0);
        let found = check_terminology(&input);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn no_path_allows_run() {
        // No file_path but content has violation — should still block
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: Some(VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn multiple_violations_in_run() {
        let content = format!("{} and {}", VIOLATIONS[0].0, VIOLATIONS[1].0);
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/config.rs".into()),
                path: None,
                command: None,
                content: Some(content),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(VIOLATIONS[0].0));
        assert!(msg.contains(VIOLATIONS[1].0));
    }

    #[test]
    fn settings_json_not_excluded() {
        // settings.json is NOT an excluded path
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/settings.json".into()),
                path: None,
                command: None,
                content: Some(VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
