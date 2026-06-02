//! Warn when bare `curl` is used for API calls with custom headers.
//!
//! On machines where `curl` is aliased to `curlie`, JSON-like headers
//! (`Accept: application/json`) make curlie infer POST — producing silent
//! 400s from endpoints expecting GET. The fix is `command curl` (bypasses
//! the alias) or an absolute path. This nudge fires only when custom headers
//! are present; plain downloads behave identically under both tools.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Splits a command into pipeline/chain segments (`|`, `&&`, `||`, `;`).
static SEGMENT_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[|;&]+").expect("pattern should compile"));

/// Nudges to use `command curl` when custom headers are present.
pub struct WarnCurlAlias;

/// Does this segment invoke bare `curl` (unprefixed, non-absolute) with a
/// custom header flag?
fn segment_has_bare_curl_with_headers(segment: &str) -> bool {
    let tokens: Vec<&str> = segment.split_whitespace().collect();

    // Find the first `curl` token that is not preceded by `command`.
    // Absolute paths (/usr/bin/curl) are different tokens and never match.
    let curl_idx = tokens.iter().enumerate().find_map(|(i, tok)| {
        if *tok == "curl" && (i == 0 || tokens[i - 1] != "command") {
            Some(i)
        } else {
            None
        }
    });

    let Some(idx) = curl_idx else {
        return false;
    };

    // Custom header flag anywhere after the curl invocation in this segment.
    tokens[idx + 1..]
        .iter()
        .any(|t| t.starts_with("-H") || *t == "--header" || t.starts_with("--header="))
}

impl Check for WarnCurlAlias {
    fn name(&self) -> &str {
        "warn-curl-alias"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("curl") {
            return CheckResult::allow();
        }

        // Strip quoted strings: prose mentioning curl won't fire, and quoted
        // header *values* disappear while the flags themselves survive.
        let stripped = strip_quotes(command);

        // Check each pipeline/chain segment independently so header flags from
        // other tools (e.g. `grep -H`) never attach to a curl invocation.
        for segment in SEGMENT_SPLIT.split(&stripped) {
            if segment_has_bare_curl_with_headers(segment) {
                return CheckResult::nudge(
                    "This machine aliases `curl` to `curlie`, which infers POST from JSON-like \
                     headers — API calls with custom headers can fail with silent 400s from \
                     endpoints expecting GET. Use `command curl` (or /usr/bin/curl) to bypass \
                     the alias.",
                );
            }
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    // --- guard clause: non-matching commands stay allowed ---

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnCurlAlias.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        let result = WarnCurlAlias.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn command_prefixed_curl_with_headers_allowed() {
        let result = WarnCurlAlias.run(&make_bash(
            "command curl -H 'Accept: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn absolute_path_curl_with_headers_allowed() {
        let result = WarnCurlAlias.run(&make_bash(
            "/usr/bin/curl -H 'Accept: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn bare_curl_without_headers_allowed() {
        // Plain downloads behave identically under curl and curlie
        let result = WarnCurlAlias.run(&make_bash("curl -fsSL https://example.com/install.sh"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn bare_curl_output_flag_allowed() {
        let result = WarnCurlAlias.run(&make_bash(
            "curl -o archive.tar.gz https://example.com/a.tar.gz",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- happy path: bare curl + custom headers nudges ---

    #[test]
    fn bare_curl_with_h_flag_nudges() {
        let result = WarnCurlAlias.run(&make_bash(
            "curl -H 'Accept: application/json' https://api.example.com/items",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn bare_curl_with_header_flag_nudges() {
        let result = WarnCurlAlias.run(&make_bash(
            "curl --header 'Content-Type: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn bare_curl_with_headers_in_pipe_nudges() {
        let result = WarnCurlAlias.run(&make_bash(
            "curl -sS -H 'Authorization: Bearer tok' https://api.example.com | jq '.items'",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn bare_curl_in_chain_nudges() {
        let result = WarnCurlAlias.run(&make_bash(
            "cd /tmp && curl -H 'Accept: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    #[test]
    fn attached_h_flag_nudges() {
        // -H with the value attached (no space)
        let result = WarnCurlAlias.run(&make_bash(
            "curl -H'Accept: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
    }

    // --- nudge message quality ---

    #[test]
    fn nudge_message_mentions_command_curl() {
        let result = WarnCurlAlias.run(&make_bash(
            "curl -H 'Accept: application/json' https://api.example.com",
        ));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("command curl"),
            "nudge should give the fix: {msg}"
        );
        assert!(
            msg.contains("curlie"),
            "nudge should explain the alias cause: {msg}"
        );
    }

    // --- edge cases ---

    #[test]
    fn quoted_prose_mentioning_curl_allowed() {
        let result = WarnCurlAlias.run(&make_bash("echo 'use curl -H for custom headers'"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_command_allowed() {
        let result = WarnCurlAlias.run(&make_bash(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn curl_substring_in_word_allowed() {
        // "curling" contains "curl" but is not the curl command
        let result = WarnCurlAlias.run(&make_bash("echo curling -H is a sport"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn command_prefix_in_chain_allowed() {
        // command-prefixed in second segment of a chain
        let result = WarnCurlAlias.run(&make_bash(
            "cd /tmp && command curl -H 'Accept: application/json' https://api.example.com",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
