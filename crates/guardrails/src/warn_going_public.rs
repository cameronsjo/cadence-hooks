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
//!
//! The work-identifiable terms in `~/.config/cadence/redaction.toml` are read
//! here too (cadence-hooks#793), through `redact-external-content`'s identity
//! matcher rather than a second copy of the list, so a term added there reaches
//! the repo-visibility path without being duplicated into the environment.
//! `CADENCE_GOING_PUBLIC_IGNORE` cannot relieve those — only the term source's
//! own `allow` entries can.

use cadence_hooks_cadence::redact_external_content::TermMatch;
#[cfg(not(test))]
use cadence_hooks_cadence::redact_external_content::identity_matches;
use cadence_hooks_core::config::env_list;
use cadence_hooks_core::display::sanitize_field;
use cadence_hooks_core::shell::{
    command_segments, contains_ignoring_ascii_case, executable_tokens, fold_verb,
    skip_transparent_prefixes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::borrow::Cow;
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

/// Basename-aware command word, ASCII case folded: `/opt/homebrew/bin/GH` →
/// `gh`. The fold is cadence-hooks#488 — a case-insensitive volume resolves
/// `GH` to the `gh` binary and runs it, so the caller's `== "gh"` test silenced
/// the whole check on a spelling that works. Feeds a nudge, the most forgiving
/// direction there is.
fn command_word(tokens: &[String]) -> Option<Cow<'_, str>> {
    tokens
        .first()
        .map(|first| fold_verb(first.rsplit('/').next().unwrap_or(first)))
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
        // Folded, because `GH repo` is a spelling the shell runs — a
        // lowercase-only test here silently defeated the folded command word
        // below by rejecting the command before it ran (cadence-hooks#488).
        if !contains_ignoring_ascii_case(command, "gh repo") {
            return CheckResult::allow();
        }

        let terms = effective_terms();
        let ignore = env_list("CADENCE_GOING_PUBLIC_IGNORE");

        // Judge each executable segment independently so a quoted `gh repo
        // create …` inside an `echo` (command word ≠ gh) never fires, while a
        // real invocation later in a chain still does.
        //
        // The head is read through the shared pre-processing model: group
        // punctuation and reserved words go (`executable_tokens`), then
        // leading `NAME=value` assignment words and transparent prefixes
        // (`skip_transparent_prefixes`). Bash runs `X=1 gh repo create …` as
        // `gh`, and reading the assignment as the command word silenced the
        // check (cameronsjo/cadence-hooks#1171). Skipping more prefixes only
        // exposes more `gh` invocations, the forgiving direction for a nudge.
        //
        // An inline `CADENCE_GOING_PUBLIC_IGNORE=…` prefix is peeled like any
        // other assignment and deliberately NOT read as relief: it reaches the
        // `gh` process, never this hook, and it only "worked" before because
        // it hid the whole segment — the redaction terms the list may never
        // relieve (#793) included. The relief list is the session environment.
        for segment in command_segments(command) {
            let all_tokens = executable_tokens(&segment);
            let tokens = skip_transparent_prefixes(&all_tokens);
            if command_word(tokens).as_deref() != Some("gh") {
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
                Some("edit") if has_public_visibility(tokens) => {}
                _ => continue,
            }

            // Content-scan the repo name + description.
            let name = positional_name(tokens).unwrap_or("");
            let description = description_value(tokens).unwrap_or_default();
            let haystack = format!("{name} {description}");

            if let Some(term) = find_match(&haystack, &terms, &ignore) {
                return CheckResult::nudge(nudge_message(&term));
            }
            // The redaction term source, read through the tier that owns it
            // (cadence-hooks#793). Deliberately NOT relieved by
            // `CADENCE_GOING_PUBLIC_IGNORE`: softening authority follows
            // term-source authority, so only `redaction.toml`'s own `allow`
            // entries can excuse one of its terms.
            if let Some(hit) = identity_matches_for(&haystack).into_iter().next() {
                return CheckResult::nudge(identity_nudge_message(&hit));
            }
        }

        CheckResult::allow()
    }
}

/// Identity-tier matches for `haystack`. Production reads the real term
/// source; a test build reads only the fixture a test installed, so no test
/// ever depends on the operator's own `redaction.toml`.
#[cfg(not(test))]
fn identity_matches_for(haystack: &str) -> Vec<TermMatch> {
    identity_matches(haystack)
}

#[cfg(test)]
thread_local! {
    static IDENTITY_SOURCE: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn identity_matches_for(haystack: &str) -> Vec<TermMatch> {
    IDENTITY_SOURCE.with(|s| match s.borrow().as_deref() {
        Some(path) => {
            cadence_hooks_cadence::redact_external_content::identity_matches_from(haystack, path)
        }
        None => Vec::new(),
    })
}

fn identity_nudge_message(hit: &TermMatch) -> String {
    format!(
        "warn-going-public: this repo's name or description contains `{}` (redaction term \
         [{}]), which identifies work context on a public or soon-public repo.\n\
         Use a neutral name/description. If this context is genuinely benign, add an `allow` \
         entry beside the term in ~/.config/cadence/redaction.toml.",
        sanitize_field(&hit.snippet, 120),
        sanitize_field(&hit.id, 120),
    )
}

fn nudge_message(term: &str) -> String {
    format!(
        "warn-going-public: this repo's name or description contains `{term}`, which may \
         telegraph sensitive content on a public or soon-public repo.\n\
         Consider a neutral name/description, or confirm this exposure is intended.\n\
         If `{term}` is a false positive, add it to CADENCE_GOING_PUBLIC_IGNORE in the \
         session environment (an inline prefix on the command does not reach this hook)."
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

    /// Runs the guard with no env lock. Only for callers already inside
    /// `with_env`, whose mutex is not reentrant.
    fn outcome_unlocked(cmd: &str) -> cadence_hooks_core::Outcome {
        GoingPublicGuard.run(&make_bash(cmd)).outcome
    }

    /// The guard reads `CADENCE_GOING_PUBLIC_TERMS`/`_IGNORE` live, so a
    /// reader must hold the same lock the writers below do, or it can observe
    /// their value mid-test (cameronsjo/cadence-hooks#1112).
    fn outcome(cmd: &str) -> cadence_hooks_core::Outcome {
        let mut out = None;
        crate::with_env(&[], || out = Some(outcome_unlocked(cmd)));
        out.expect("with_env ran the closure")
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
    fn case_folded_gh_verb_still_nudges() {
        // cadence-hooks#488. This guard's local command word is a bare
        // `rsplit('/')`, so a capitalized `GH` — which the shell resolves and
        // runs on a case-insensitive volume — failed the `== "gh"` test and
        // the whole check went silent.
        assert_eq!(
            outcome("GH repo create sonarr-cfg --public"),
            cadence_hooks_core::Outcome::Nudge
        );
        assert_eq!(
            outcome("/opt/homebrew/bin/GH repo create sonarr-cfg --public"),
            cadence_hooks_core::Outcome::Nudge
        );
        // The fold changes case, not shape — a longer word is still not `gh`.
        assert_eq!(
            outcome("GHQ repo create sonarr-cfg --public"),
            cadence_hooks_core::Outcome::Allow
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

    #[test]
    fn a_leading_prefix_does_not_hide_the_create() {
        // cameronsjo/cadence-hooks#1171: bash runs `gh` behind an assignment
        // word or a transparent prefix, so the verdict must match the bare
        // spelling. An assignment word as the command word silenced the guard.
        use cadence_hooks_core::Outcome::{Allow, Nudge};
        let cases: &[(&str, cadence_hooks_core::Outcome)] = &[
            ("X=1 gh repo create sonarr-cfg --public", Nudge),
            ("X=1 Y=2 gh repo create sonarr-cfg --public", Nudge),
            (
                "GH_HOST=github.com gh repo edit o/sonarr --visibility public",
                Nudge,
            ),
            ("env X=1 gh repo create sonarr-cfg --private", Nudge),
            ("command gh repo create sonarr-cfg --private", Nudge),
            ("nohup gh repo create sonarr-cfg --private", Nudge),
            ("if true; then gh repo create sonarr-cfg; fi", Nudge),
            ("{ gh repo create sonarr-cfg; }", Nudge),
            // Controls: the prefix changes nothing about a clean name or a
            // private edit, and an assignment with no command runs no gh.
            ("X=1 gh repo create my-widget --public", Allow),
            ("X=1 gh repo edit o/sonarr --visibility private", Allow),
            ("X='gh repo create sonarr-cfg'", Allow),
        ];
        for (cmd, want) in cases {
            assert_eq!(outcome(cmd), *want, "{cmd}");
        }
    }

    #[test]
    fn an_inline_ignore_prefix_does_not_relieve_the_nudge() {
        // The relief list is the hook process's environment, which the
        // operator sets for the session. An inline `CADENCE_GOING_PUBLIC_IGNORE=`
        // reaches only the `gh` process, never this hook, and it used to
        // "work" only because the assignment word hid the whole segment —
        // including the redaction terms the list may never relieve (#793).
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", None),
                ("CADENCE_GOING_PUBLIC_IGNORE", None),
            ],
            || {
                assert_eq!(
                    outcome_unlocked(
                        "CADENCE_GOING_PUBLIC_IGNORE=sonarr gh repo create sonarr-cfg --public"
                    ),
                    cadence_hooks_core::Outcome::Nudge
                );
            },
        );
        // The documented form — the session environment — still relieves a
        // prefixed command.
        with_env(
            &[
                ("CADENCE_GOING_PUBLIC_TERMS", None),
                ("CADENCE_GOING_PUBLIC_IGNORE", Some("sonarr")),
            ],
            || {
                assert_eq!(
                    outcome_unlocked("X=1 gh repo create sonarr-cfg --public"),
                    cadence_hooks_core::Outcome::Allow
                );
            },
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
                    outcome_unlocked("gh repo create sonarr-cfg --public"),
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
                    outcome_unlocked("gh repo create starr --public"),
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
                    outcome_unlocked("gh repo create skunkworks-notes --private"),
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
                    outcome_unlocked("gh repo create skunkworks-notes --private"),
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

    // ---- redaction.toml terms (cadence-hooks#793) ----

    /// Run `cmd` with `toml` installed as this thread's identity term source.
    fn with_identity_source(toml: &str, cmd: &str) -> CheckResult {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("redaction.toml");
        std::fs::write(&path, toml).unwrap();
        IDENTITY_SOURCE.with(|s| *s.borrow_mut() = Some(path));
        let mut out = None;
        crate::with_env(&[], || out = Some(GoingPublicGuard.run(&make_bash(cmd))));
        IDENTITY_SOURCE.with(|s| *s.borrow_mut() = None);
        out.unwrap()
    }

    const TERMS: &str = r#"
[[terms]]
id = "W1"
term = "zorblax corp"
allow = [{ pattern = "zorblax corp fan club" }]
"#;

    #[test]
    fn a_redaction_term_in_the_name_or_description_nudges() {
        use cadence_hooks_core::Outcome::{Allow, Nudge};
        let cases: &[(&str, cadence_hooks_core::Outcome)] = &[
            // Multi-word terms match across `-`/`_`, as the identity tier does.
            ("gh repo create zorblax-corp-tools --private", Nudge),
            ("gh repo create tools --public -d 'for Zorblax Corp'", Nudge),
            ("gh repo edit o/zorblax_corp --visibility public", Nudge),
            ("X=1 gh repo create zorblax-corp-x --public", Nudge),
            (
                "CADENCE_GOING_PUBLIC_IGNORE=zorblax gh repo create zorblax-corp-x",
                Nudge,
            ),
            // Controls: an edit that does not publicize, an unrelated name,
            // the term source's own allow entry, and a mention in prose.
            ("gh repo edit o/zorblax-corp --description x", Allow),
            ("gh repo create tools --public", Allow),
            ("gh repo create x -d 'zorblax corp fan club'", Allow),
            ("echo gh repo create zorblax-corp", Allow),
        ];
        for (cmd, want) in cases {
            let result = with_identity_source(TERMS, cmd);
            assert_eq!(result.outcome, *want, "{cmd}");
            if *want == Nudge {
                let msg = result.message.unwrap();
                assert!(msg.contains("[W1]"), "{msg}");
            }
        }
    }

    #[test]
    fn the_env_ignore_list_cannot_relieve_a_redaction_term() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("redaction.toml");
        std::fs::write(&path, TERMS).unwrap();
        IDENTITY_SOURCE.with(|s| *s.borrow_mut() = Some(path));
        let mut out = None;
        crate::with_env(
            &[(
                "CADENCE_GOING_PUBLIC_IGNORE",
                Some("zorblax corp,zorblax-corp-tools"),
            )],
            || {
                out = Some(
                    GoingPublicGuard
                        .run(&make_bash("gh repo create zorblax-corp-tools"))
                        .outcome,
                )
            },
        );
        IDENTITY_SOURCE.with(|s| *s.borrow_mut() = None);
        assert_eq!(out, Some(cadence_hooks_core::Outcome::Nudge));
    }

    #[test]
    fn an_absent_or_malformed_term_source_is_inert() {
        for toml in ["", "not = [valid", "version = 1\n"] {
            let result = with_identity_source(toml, "gh repo create zorblax-corp-tools");
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "{toml:?}"
            );
        }
    }
}
