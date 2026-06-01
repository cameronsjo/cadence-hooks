//! Shared closing-keyword detection for GitHub issue references.
//!
//! Both `guard_pr_issue_link` (boolean: does the PR body link an issue?) and
//! `verify_pr_autoclose` (extraction: which issues does it close?) recognize
//! the same GitHub closing keywords. One regex serves both so the pattern
//! cannot drift between guards.

use regex::Regex;
use std::sync::LazyLock;

/// Regex for issue-closing keywords followed by a `#<number>` ref.
///
/// Matches: closes, closed, close, fixes, fixed, fix, resolves, resolved, resolve.
/// Case-insensitive; captures the digit string after `#`.
static CLOSING_KW_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Word boundaries keep substring hits ("discloses", "prefixes") from
    // counting as closing keywords.
    Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s+#([0-9]+)\b")
        .expect("pattern should compile")
});

/// True when `text` contains at least one closing-keyword issue reference.
pub fn has_closing_keyword(text: &str) -> bool {
    CLOSING_KW_RE.is_match(text)
}

/// Extract sorted, deduplicated issue numbers from closing-keyword references.
///
/// Finds all `closes #N`, `fixes #N`, `resolves #N` (and inflected variants),
/// case-insensitively. Returns issue numbers sorted ascending with duplicates removed.
pub fn extract_refs(text: &str) -> Vec<u64> {
    let mut nums: Vec<u64> = CLOSING_KW_RE
        .captures_iter(text)
        .filter_map(|cap| cap.get(1)?.as_str().parse::<u64>().ok())
        .collect();
    nums.sort_unstable();
    nums.dedup();
    nums
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_closing_keyword_matches_all_variants() {
        for text in [
            "Closes #1",
            "closed #2",
            "close #3",
            "Fixes #4",
            "fixed #5",
            "fix #6",
            "Resolves #7",
            "resolved #8",
            "resolve #9",
        ] {
            assert!(has_closing_keyword(text), "should match: {text}");
        }
    }

    #[test]
    fn has_closing_keyword_rejects_bare_refs() {
        assert!(!has_closing_keyword("see #9 for context"));
        assert!(!has_closing_keyword("no reference at all"));
    }

    #[test]
    fn does_not_match_keyword_inside_larger_word() {
        // "discloses", "prefixes", "unresolves" contain closing keywords as
        // substrings — they are not closing references.
        assert!(!has_closing_keyword("this discloses #2 publicly"));
        assert!(!has_closing_keyword("prefixes #3 with a dash"));
        assert!(extract_refs("discloses #2 and prefixes #3").is_empty());
    }

    #[test]
    fn extract_refs_and_has_closing_keyword_agree() {
        // The boolean and the extraction views of the same regex must agree.
        let with_refs = "Closes #12 and fixes #3";
        let without = "related to #4";
        assert_eq!(
            has_closing_keyword(with_refs),
            !extract_refs(with_refs).is_empty()
        );
        assert_eq!(
            has_closing_keyword(without),
            !extract_refs(without).is_empty()
        );
    }
}
