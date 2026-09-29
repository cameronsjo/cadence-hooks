//! Shared closing-keyword detection for GitHub issue references.
//!
//! Both `warn_pr_issue_link` (boolean: does the PR body link an issue?) and
//! `verify_pr_autoclose` (extraction: which issues does it close?) recognize
//! the same GitHub closing keywords. One regex serves both so the pattern
//! cannot drift between checks.

use cadence_hooks_core::display::sanitize_field;
use cadence_hooks_core::gh_bodies::extract_bodies;
use cadence_hooks_core::shell::{
    GhRepoFlag, command_segments, command_word, gh_command_path, gh_repo_flags,
    host_and_repo_from_url, parse_gh_repo_value, tokenize,
};
use regex::Regex;
use std::sync::LazyLock;

/// Regex for issue-closing keywords followed by a `#<number>` ref.
///
/// Matches: closes, closed, close, fixes, fixed, fix, resolves, resolved, resolve.
/// Case-insensitive. Captures the digit string after `#` as `num`, and an
/// optional cross-repo `owner/repo` prefix as `repo`. Cross-repo
/// `owner/repo#N` is recognized (URL form and `GH-N` remain out of scope).
static CLOSING_KW_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Word boundaries keep substring hits ("discloses", "prefixes") from
    // counting as closing keywords.
    Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s+(?P<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)?#(?P<num>[0-9]+)\b")
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
        // Same-repo only: a cross-repo `owner/repo#N` number would be closed
        // against the PR's own repo, closing the wrong repo's issue.
        .filter(|cap| cap.name("repo").is_none())
        .filter_map(|cap| cap.name("num")?.as_str().parse::<u64>().ok())
        .collect();
    nums.sort_unstable();
    nums.dedup();
    nums
}

/// Code that is not prose: fenced blocks and inline code spans, where a `#N`
/// is text, not a reference.
static CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```.*?```|`[^`\n]*`").expect("pattern should compile"));

/// A bare `#N`: not glued to a word, path, `#`, `&` (an HTML entity), `.` or `-`
/// before it, so `owner/repo#N` never matches. One to five digits, so a
/// six-digit hex colour (`#123456`) is not read as an issue number.
static BARE_REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\w/#&.\-])#(?P<num>[0-9]{1,5})\b").expect("pattern should compile")
});

/// Sorted, deduplicated bare `#N` references in the prose of `body`
/// (cameronsjo/cadence-hooks#150).
pub fn bare_refs(body: &str) -> Vec<u64> {
    let prose = CODE_RE.replace_all(body, " ");
    let mut nums: Vec<u64> = BARE_REF_RE
        .captures_iter(&prose)
        .filter_map(|cap| cap.name("num")?.as_str().parse().ok())
        .collect();
    nums.sort_unstable();
    nums.dedup();
    nums
}

/// Nudge text when a `gh` issue/PR write is retargeted with `-R <repo>` at a
/// repo other than the checkout's own, and its body carries a bare `#N`.
///
/// A bare `#N` resolves against the repo the body is posted to, so a
/// reference typed for the checkout's repo dangles or, worse, points at an
/// unrelated issue there. Local only (cameronsjo/cadence-hooks#150, option
/// b): no network, no `gh api` — the only outside reading is the checkout's
/// `origin` slug, handed in as `origin_slug` and asked for lazily, so a
/// command with no bare ref pays nothing. An unreadable origin, an unreadable
/// or ambiguous `-R` value, and a `-R` naming the checkout's own repo are all
/// silent: advisory only, and never a guess.
pub fn cross_repo_bare_ref_nudge(
    command: &str,
    base_dir: &str,
    origin_slug: &dyn Fn() -> Option<String>,
) -> Option<String> {
    for segment in command_segments(command) {
        let tokens = tokenize(&segment);
        let Some(start) = tokens.iter().position(|t| command_word(t) == "gh") else {
            continue;
        };
        let argv = &tokens[start..];
        let is_posting = matches!(
            gh_command_path(argv, 2).as_slice(),
            ["issue", "create" | "edit" | "comment"]
                | ["pr", "create" | "edit" | "comment" | "review"]
        );
        if !is_posting {
            continue;
        }
        let GhRepoFlag::Target(value) = gh_repo_flags(argv).resolve() else {
            continue;
        };
        let Some(spec) = parse_gh_repo_value(&value) else {
            continue;
        };
        let target = format!("{}/{}", spec.owner, spec.name);
        let mut refs: Vec<u64> = extract_bodies(&segment, base_dir)
            .iter()
            .flat_map(|body| bare_refs(body))
            .collect();
        refs.sort_unstable();
        refs.dedup();
        if refs.is_empty() {
            continue;
        }
        let Some(origin) = origin_slug() else {
            continue;
        };
        if origin.eq_ignore_ascii_case(&target) {
            continue;
        }
        let shown: Vec<String> = refs.iter().take(5).map(|n| format!("#{n}")).collect();
        let target = sanitize_field(&target, 80);
        return Some(format!(
            "This body is posted to {target}, not to this checkout's repo, but it contains a bare {refs}. \
             A bare `#N` resolves against {target}. If you mean an issue in another repo, write \
             `owner/repo#N` so the reference survives.",
            refs = shown.join(", "),
        ));
    }
    None
}

/// The `owner/repo` slug of `dir`'s `origin` remote, from local git config.
pub fn origin_slug_of(dir: &str) -> Option<String> {
    let url = cadence_hooks_core::shell::git_command(dir, &["remote", "get-url", "origin"])?;
    host_and_repo_from_url(&url).map(|(_host, slug)| slug)
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
    fn has_closing_keyword_matches_cross_repo() {
        assert!(has_closing_keyword("Closes cameronsjo/cadence#308"));
        assert!(has_closing_keyword("Fixes owner/repo#5"));
        assert!(has_closing_keyword("resolves a-b/c.d_e#7"));
    }

    #[test]
    fn extract_refs_skips_cross_repo() {
        assert!(extract_refs("Closes owner/repo#5").is_empty());
        assert_eq!(extract_refs("Closes #3 and closes owner/repo#5"), vec![3]);
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
