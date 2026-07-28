//! Nudge when `gh repo create`/`gh repo edit` telegraphs sensitive content via
//! the repo NAME or `--description`.
//!
//! Fires as a PreToolUse hook on Bash. Content-scans the repo name and its
//! `--description` value against a term set: making (or publicizing) a repo
//! whose name or description reads like a home-media / piracy stack (sonarr,
//! radarr, sabnzbd, …) is a common way private tooling accidentally becomes a
//! public breadcrumb. NUDGES only — never blocks — and fails OPEN (any parse
//! issue allows).
//!
//! ## Term-list safety
//!
//! Only non-sensitive, publicly-known OSS application names ship COMPILED in
//! the binary (see [`DEFAULT_TERMS`] and the `*arr`-family regex). Genuinely
//! sensitive terms — employer names, codenames, personal identifiers — come
//! ONLY from the environment via `CADENCE_GOING_PUBLIC_TERMS`; none are
//! hardcoded here, so the open-source binary carries no private vocabulary.
//! Relieve false positives (e.g. the surnames `starr`/`pfarr` caught by the
//! `*arr` regex) with `CADENCE_GOING_PUBLIC_IGNORE`.

use cadence_hooks_core::config::env_list;
use cadence_hooks_core::shell::{command_segments, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Publicly-known OSS app names that read as a home-media / piracy stack.
///
/// Every entry is a widely-documented open-source project name — safe to ship
/// compiled in an open-source binary. Sensitive/private terms are env-only
/// (`CADENCE_GOING_PUBLIC_TERMS`); do NOT add employer, codename, or personal
/// terms here.
const DEFAULT_TERMS: &[&str] = &[
    "sonarr",
    "radarr",
    "lidarr",
    "readarr",
    "prowlarr",
    "bazarr",
    "jackett",
    "qbittorrent",
    "deluge",
    "transmission",
    "torrent",
    "warez",
    "usenet",
    "nzb",
    "sabnzbd",
    "nzbget",
];

/// The `*arr`-family shape: any 2+-char word ending in `arr` (sonarr, radarr,
/// mcparr, and future `*arr` tools). Word-boundary anchored so it matches whole
/// tokens, not substrings. False positives (surnames like `starr`/`pfarr`) are
/// relieved via `CADENCE_GOING_PUBLIC_IGNORE`.
static ARR_FAMILY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b\w{2,}arr\b").expect("pattern should compile"));

/// Effective term set: [`DEFAULT_TERMS`] ∪ `CADENCE_GOING_PUBLIC_TERMS`, each
/// lowercased. The `*arr` regex is applied separately by [`find_match`].
fn effective_terms() -> Vec<String> {
    let mut terms: Vec<String> = DEFAULT_TERMS.iter().map(|s| s.to_lowercase()).collect();
    terms.extend(
        env_list("CADENCE_GOING_PUBLIC_TERMS")
            .iter()
            .map(|s| s.to_lowercase()),
    );
    terms
}

/// True when `word` (lowercased) matches a `\b<word>\b` boundary in `haystack`
/// (already lowercased). `word` is regex-escaped, so app-name terms with no
/// special chars match literally.
fn word_boundary_match(haystack: &str, word: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(word)))
        .map(|re| re.is_match(haystack))
        .unwrap_or(false)
}

/// Scan `haystack` (repo name + description) for a matching term. Returns the
/// matched term when one hits and is NOT relieved by `ignore`; `None` otherwise.
///
/// Both the concrete term list and the `*arr` regex are subject to `ignore`,
/// applied AFTER matching — so an ignored surname (`starr`) suppresses the
/// regex hit, and an ignored app name suppresses both its concrete and its
/// regex hit.
fn find_match(haystack: &str, terms: &[String], ignore: &[String]) -> Option<String> {
    let haystack = haystack.to_lowercase();
    let ignored = |w: &str| ignore.iter().any(|i| i.eq_ignore_ascii_case(w));

    // Concrete terms first.
    for term in terms {
        if !ignored(term) && word_boundary_match(&haystack, term) {
            return Some(term.clone());
        }
    }

    // Then the *arr family, honoring the same ignore list per matched word.
    for m in ARR_FAMILY.find_iter(&haystack) {
        let word = m.as_str().to_lowercase();
        if !ignored(&word) {
            return Some(word);
        }
    }

    None
}

/// Basename-aware command word: `/opt/homebrew/bin/gh` → `gh`.
fn command_word(tokens: &[String]) -> Option<&str> {
    tokens
        .first()
        .map(|first| first.rsplit('/').next().unwrap_or(first))
}

/// The first positional token immediately after the subcommand (index 3), if it
/// isn't a flag. Mirrors guard_gh_write's positional extraction — a dash-flag in
/// that slot means the command carries no bare name.
fn positional_name(tokens: &[String]) -> Option<&str> {
    tokens
        .get(3)
        .map(String::as_str)
        .filter(|t| !t.starts_with('-'))
}

/// Extract the `--description`/`-d` value across the separate-token
/// (`--description "x"`) and `=`-joined (`--description=x`, `-d=x`) forms.
/// Quote-aware tokenization already strips the surrounding quotes, so a
/// multi-word value arrives as a single token.
fn description_value(tokens: &[String]) -> Option<String> {
    for (i, tok) in tokens.iter().enumerate() {
        if tok == "--description" || tok == "-d" {
            return tokens.get(i + 1).cloned();
        }
        if let Some(rest) = tok.strip_prefix("--description=") {
            return Some(rest.to_string());
        }
        if let Some(rest) = tok.strip_prefix("-d=") {
            return Some(rest.to_string());
        }
    }
    None
}

/// True when the tokens carry `--visibility public` (separate-token) or
/// `--visibility=public` — and NOT `--visibility private`.
fn has_public_visibility(tokens: &[String]) -> bool {
    for (i, tok) in tokens.iter().enumerate() {
        if tok == "--visibility" && tokens.get(i + 1).map(String::as_str) == Some("public") {
            return true;
        }
        if tok == "--visibility=public" {
            return true;
        }
    }
    false
}

/// Nudges on `gh repo create`/`gh repo edit` whose repo name or description
/// telegraphs sensitive content.
pub struct GoingPublicGuard;

impl Check for GoingPublicGuard {
    fn name(&self) -> &str {
        "warn-going-public"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Fast pre-filter: nothing to do without a `gh repo` invocation.
        if !command.contains("gh repo") {
            return CheckResult::allow();
        }

        let terms = effective_terms();
        let ignore = env_list("CADENCE_GOING_PUBLIC_IGNORE");

        // Judge each executable segment independently so a quoted `gh repo
        // create …` inside an `echo` (command word ≠ gh) never fires, while a
        // real invocation later in a chain still does.
        for segment in command_segments(command) {
            let tokens = tokenize(&segment);
            if command_word(&tokens) != Some("gh") {
                continue;
            }
            if tokens.get(1).map(String::as_str) != Some("repo") {
                continue;
            }
            let subcommand = tokens.get(2).map(String::as_str);
            match subcommand {
                // `create` fires on ANY visibility — a private repo can still
                // be flipped public, and the name/description are the tell.
                Some("create") => {}
                // `edit` fires only when the command publicizes the repo.
                Some("edit") if has_public_visibility(&tokens) => {}
                _ => continue,
            }

            // Content-scan the repo name + description.
            let name = positional_name(&tokens).unwrap_or("");
            let description = description_value(&tokens).unwrap_or_default();
            let haystack = format!("{name} {description}");

            if let Some(term) = find_match(&haystack, &terms, &ignore) {
                return CheckResult::nudge(nudge_message(&term));
            }
        }

        CheckResult::allow()
    }
}

fn nudge_message(term: &str) -> String {
    format!(
        "warn-going-public: this repo's name or description contains `{term}`, which may \
         telegraph sensitive content on a public or soon-public repo.\n\
         Consider a neutral name/description, or confirm this exposure is intended.\n\
         If `{term}` is a false positive, add it to CADENCE_GOING_PUBLIC_IGNORE."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_env;
    use cadence_hooks_core::test_builders::make_bash;

    // Tests that mutate CADENCE_GOING_PUBLIC_TERMS / _IGNORE serialize via the
    // crate-shared with_env/CADENCE_ENV_TEST_LOCK so they don't race each
    // other (env is process-global) or the globals mutated elsewhere in this
    // crate (#446).

    fn outcome(cmd: &str) -> cadence_hooks_core::Outcome {
        GoingPublicGuard.run(&make_bash(cmd)).outcome
    }

    // --- create: fires regardless of visibility ---

    #[test]
    fn create_bare_name_match_nudges() {
        assert_eq!(
            outcome("gh repo create sonarr-cfg --public"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn create_fires_on_private() {
        assert_eq!(
            outcome("gh repo create radarr-notes --private"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn create_description_match_nudges() {
        assert_eq!(
            outcome("gh repo create x --description \"a radarr helper\""),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn create_description_equals_form_nudges() {
        assert_eq!(
            outcome("gh repo create x --description=\"a sabnzbd config\""),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn clean_create_allowed() {
        assert_eq!(
            outcome("gh repo create my-widget --public"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- edit: fires only when publicizing ---

    #[test]
    fn edit_visibility_public_nudges() {
        assert_eq!(
            outcome("gh repo edit sonarr --visibility public"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn edit_visibility_equals_public_nudges() {
        assert_eq!(
            outcome("gh repo edit sonarr --visibility=public"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    #[test]
    fn edit_visibility_private_allowed() {
        // Same sensitive name, but a private edit doesn't publicize — allow.
        assert_eq!(
            outcome("gh repo edit sonarr --visibility private"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- no false positives ---

    #[test]
    fn pr_list_allowed() {
        assert_eq!(outcome("gh pr list"), cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn repo_view_allowed() {
        assert_eq!(
            outcome("gh repo view owner/widget"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn repo_delete_allowed() {
        // delete is not create/edit — outside this guard's scope.
        assert_eq!(
            outcome("gh repo delete owner/sonarr --yes"),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        assert_eq!(
            GoingPublicGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    // --- evasion / segmentation ---

    #[test]
    fn quoted_prose_allowed() {
        // The echo segment's command word ≠ gh — quoted prose must not fire.
        assert_eq!(
            outcome("echo \"gh repo create warez\""),
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn chained_create_nudges() {
        assert_eq!(
            outcome("echo ok && gh repo create warez --private"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    // --- *arr family regex ---

    #[test]
    fn arr_family_mcparr_nudges() {
        assert_eq!(
            outcome("gh repo create mcparr --private"),
            cadence_hooks_core::Outcome::Nudge
        );
    }

    // --- IGNORE relief ---

    #[test]
    fn ignore_relieves_concrete_term() {
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", None),
                ("CADENCE_GOING_PUBLIC_IGNORE", Some("sonarr")),
            ],
            || {
                assert_eq!(
                    outcome("gh repo create sonarr-cfg --public"),
                    cadence_hooks_core::Outcome::Allow
                );
            },
        );
    }

    #[test]
    fn ignore_relieves_arr_family_surname() {
        // `starr` matches the *arr regex but is a surname — IGNORE relieves it.
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", None),
                ("CADENCE_GOING_PUBLIC_IGNORE", Some("starr")),
            ],
            || {
                assert_eq!(
                    outcome("gh repo create starr --public"),
                    cadence_hooks_core::Outcome::Allow
                );
            },
        );
    }

    // --- env-supplied custom term ---

    #[test]
    fn custom_env_term_nudges() {
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", Some("skunkworks")),
                ("CADENCE_GOING_PUBLIC_IGNORE", None),
            ],
            || {
                assert_eq!(
                    outcome("gh repo create skunkworks-notes --private"),
                    cadence_hooks_core::Outcome::Nudge
                );
            },
        );
    }

    #[test]
    fn ignore_suppresses_env_term() {
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", Some("skunkworks")),
                ("CADENCE_GOING_PUBLIC_IGNORE", Some("skunkworks")),
            ],
            || {
                assert_eq!(
                    outcome("gh repo create skunkworks-notes --private"),
                    cadence_hooks_core::Outcome::Allow
                );
            },
        );
    }

    // --- nudge message content ---

    #[test]
    fn nudge_names_term_and_off_switch() {
        let msg = nudge_message("radarr");
        assert!(
            msg.contains("radarr"),
            "message should name the matched term"
        );
        assert!(
            msg.contains("CADENCE_GOING_PUBLIC_IGNORE"),
            "message should name the off-switch"
        );
        assert!(!msg.contains("🚫"), "nudge must not read as a block");
    }
}
