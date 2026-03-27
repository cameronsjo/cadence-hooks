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

/// Blocked terms: (display_term, regex_pattern, replacement).
///
/// Patterns use left word boundary + suffix alternation to catch derived forms
/// (plurals, past tense, gerunds) without false positives from substrings.
/// Tier 1: Hard blocks — almost never legitimate in code/tech writing.
const BLOCK_VIOLATIONS: &[(&str, &str, &str)] = &[
    (
        term!("white", "list"),
        r"(?i)\bwhitelist(s|ed|ing)?\b",
        "allowlist",
    ),
    (
        term!("black", "list"),
        r"(?i)\bblacklist(s|ed|ing)?\b",
        "blocklist, denylist",
    ),
    (
        term!("master", " branch"),
        r"(?i)\bmaster\s+branch(es)?\b",
        "main branch",
    ),
    (
        term!("master", " node"),
        r"(?i)\bmaster\s+node(s)?\b",
        "primary node, leader node",
    ),
    (
        term!("sla", "ve"),
        r"(?i)\bslave(s|d|ry)?\b",
        "replica, follower, secondary",
    ),
    (
        term!("sanity", " check"),
        r"(?i)\bsanity\s+check(s|ing)?\b",
        "validation check, confidence check, smoke test",
    ),
    (
        term!("dummy", " value"),
        r"(?i)\bdummy\s+value(s)?\b",
        "placeholder value, sample value, mock value",
    ),
];

/// Tier 2: Nudges — legitimate in prose, legal, and family contexts.
const NUDGE_VIOLATIONS: &[(&str, &str, &str)] = &[
    (
        term!("grand", "fathered"),
        r"(?i)\bgrandfather(ed|ing)?\b",
        "legacy status, exempted, inherited",
    ),
];

static BLOCK_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<&str> = BLOCK_VIOLATIONS.iter().map(|(_, pattern, _)| *pattern).collect();
    RegexSet::new(&patterns).expect("block terminology patterns should compile")
});

static NUDGE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<&str> = NUDGE_VIOLATIONS.iter().map(|(_, pattern, _)| *pattern).collect();
    RegexSet::new(&patterns).expect("nudge terminology patterns should compile")
});

/// Result of checking content for terminology violations.
pub struct TerminologyResult {
    /// Terms that must be blocked (tier 1).
    pub blocks: Vec<(String, String)>,
    /// Terms that should be nudged (tier 2).
    pub nudges: Vec<(String, String)>,
}

/// Check content for inclusive terminology violations.
/// Returns block-tier and nudge-tier violations separately.
pub fn check_terminology(content: &str) -> TerminologyResult {
    let block_matches = BLOCK_PATTERNS.matches(content);
    let nudge_matches = NUDGE_PATTERNS.matches(content);

    let blocks: Vec<(String, String)> = block_matches
        .iter()
        .map(|idx| {
            let (term, _, replacement) = BLOCK_VIOLATIONS[idx];
            (term.to_string(), replacement.to_string())
        })
        .collect();

    let nudges: Vec<(String, String)> = nudge_matches
        .iter()
        .map(|idx| {
            let (term, _, replacement) = NUDGE_VIOLATIONS[idx];
            (term.to_string(), replacement.to_string())
        })
        .collect();

    TerminologyResult { blocks, nudges }
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

        let result = check_terminology(content);

        // Tier 1: hard block
        if !result.blocks.is_empty() {
            let mut msg = String::new();
            msg.push_str("🚫 BLOCKED: Inclusive terminology violation detected");
            if let Some(ref path) = input.file_path() {
                msg.push_str(&format!(" in {path}"));
            }
            msg.push_str("\n\nFound prohibited terms:\n");

            for (term, _) in &result.blocks {
                msg.push_str(&format!("  - \"{term}\"\n"));
            }

            msg.push_str("\nRequired alternatives:\n");
            for (term, replacement) in &result.blocks {
                msg.push_str(&format!("  {term} → {replacement}\n"));
            }

            return CheckResult::block(msg);
        }

        // Tier 2: nudge (advisory)
        if !result.nudges.is_empty() {
            let mut msg = String::new();
            msg.push_str("⚠️  Terminology nudge");
            if let Some(ref path) = input.file_path() {
                msg.push_str(&format!(" in {path}"));
            }
            msg.push_str(" — consider alternatives if technical context:\n");
            for (term, replacement) in &result.nudges {
                msg.push_str(&format!("  {term} → {replacement}\n"));
            }

            return CheckResult::nudge(msg);
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_content_passes() {
        let r = check_terminology("use the allowlist for filtering"); assert!(r.blocks.is_empty() && r.nudges.is_empty());
    }

    #[test]
    fn detects_prohibited_term() {
        let r = check_terminology(BLOCK_VIOLATIONS[0].0);
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "allowlist");
    }

    #[test]
    fn detects_whitelist_derived_forms() {
        for form in ["whitelists", "whitelisted", "whitelisting"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "allowlist");
        }
    }

    #[test]
    fn detects_blacklist_derived_forms() {
        for form in ["blacklists", "blacklisted", "blacklisting"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "blocklist, denylist");
        }
    }

    #[test]
    fn detects_slave_derived_forms() {
        for form in ["slaves", "slaved", "slavery"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "replica, follower, secondary");
        }
    }

    #[test]
    fn detects_sanity_check_plural() {
        let r = check_terminology("sanity checks");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "validation check, confidence check, smoke test");
    }

    #[test]
    fn detects_sanity_checking() {
        let r = check_terminology("sanity checking");
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn detects_dummy_values_plural() {
        let r = check_terminology("dummy values");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "placeholder value, sample value, mock value");
    }

    #[test]
    fn detects_grandfather_forms_as_nudge() {
        for form in ["grandfather", "grandfathered", "grandfathering"] {
            let r = check_terminology(form);
            assert!(r.blocks.is_empty(), "grandfather should not block");
            assert_eq!(r.nudges.len(), 1, "should nudge on '{form}'");
            assert_eq!(r.nudges[0].1, "legacy status, exempted, inherited");
        }
    }

    #[test]
    fn detects_master_branch_plural() {
        let r = check_terminology("master branches");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "main branch");
    }

    #[test]
    fn detects_master_nodes_plural() {
        let r = check_terminology("master nodes");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "primary node, leader node");
    }

    #[test]
    fn case_insensitive_detection() {
        let upper = BLOCK_VIOLATIONS[0].0.to_uppercase();
        let r = check_terminology(&upper);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn multiple_violations_detected() {
        let input = format!("{} and {}", BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[1].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 2);
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
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
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
        assert!(check_terminology("the items are listed here").blocks.is_empty());
    }

    #[test]
    fn plural_form_detected() {
        let r = check_terminology(&format!("{}s", BLOCK_VIOLATIONS[0].0));
        assert_eq!(r.blocks.len(), 1, "plural form should be detected");
    }

    #[test]
    fn all_violations_detectable() {
        for (term, _, _) in BLOCK_VIOLATIONS.iter().chain(NUDGE_VIOLATIONS.iter()) {
            let r = check_terminology(term);
            assert!(!r.blocks.is_empty() || !r.nudges.is_empty(), "term '{}' should be detected", term);
        }
    }

    #[test]
    fn empty_content_passes() {
        assert!({ let r = check_terminology(""); r.blocks.is_empty() && r.nudges.is_empty() });
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
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
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
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
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
        let term = BLOCK_VIOLATIONS[0].0;
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
        let r = check_terminology(&mixed);
        assert_eq!(r.blocks.len(), 1);
    }

    // --- additional edge cases ---

    #[test]
    fn violation_with_punctuation() {
        // Term followed by punctuation should still match (word boundary at comma)
        let input = format!("{}, which we use daily", BLOCK_VIOLATIONS[0].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn violation_at_line_start() {
        let input = format!("{} is configured", BLOCK_VIOLATIONS[0].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn repeated_term_counted_once() {
        // RegexSet reports each pattern once, not per-occurrence
        let input = format!("{} and also {} again", BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[0].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
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
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
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
        let content = format!("{} and {}", BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[1].0);
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
        assert!(msg.contains(BLOCK_VIOLATIONS[0].0));
        assert!(msg.contains(BLOCK_VIOLATIONS[1].0));
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
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }
}
