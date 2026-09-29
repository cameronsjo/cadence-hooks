//! Nudge when `gh pr create` / `gh issue create` carries a long inline body.
//!
//! Three skills carry the same control in prose: an external body is composed
//! to a file and posted with `--body-file`, never inline in the command. The
//! file is the redaction review moment — a body inlined as `--body "…"` (or a
//! `--body "$(cat <<EOF … EOF)"` heredoc) skips it, which is how an unredacted
//! body once shipped (cadence-hooks#611).
//!
//! A `PreToolUse` check on Bash. For every `gh pr create` / `gh issue create`
//! segment of the command, it takes the **last** body flag (the one `gh` uses,
//! via [`guard_body_budget::last_body_flag`]) and nudges when that flag is an
//! inline `--body`/`-b` whose value is longer than [`INLINE_BODY_MAX_CHARS`].
//! A short inline body (`--body "Fixes the typo."`) stays silent — the
//! threshold is what keeps one-liners cheap. A `--body-file`/`-F` body is the
//! sanctioned path and is never judged.
//!
//! Segment detection reuses the body-budget guard's pre-processing
//! ([`executable_tokens`] + [`skip_transparent_prefixes`]), so `command gh`,
//! `env X=1 gh`, `if …; then gh …` and chained commands resolve the same way
//! there as here.
//!
//! **Out of scope:** the issue's second half — direct `flux` invocations with an
//! inline card body — targets the flux kanban board, which was retired on
//! 2026-08-07 together with the `cadence-kanban` plugin and its `flux-card.sh`
//! helper, so there is no sanctioned path left to steer toward.
//!
//! Warn only — exit 0 with the message as additional context. No I/O at all.
//!
//! [`guard_body_budget::last_body_flag`]: crate::guard_body_budget::last_body_flag

use crate::guard_body_budget::{BodyArg, last_body_flag};
use cadence_hooks_core::shell::{
    command_segments, command_word, executable_tokens, skip_transparent_prefixes,
    strip_group_wrappers,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// An inline body longer than this (in characters) is nudged toward `--body-file`.
pub const INLINE_BODY_MAX_CHARS: usize = 200;

/// The `(noun, verb)` pairs that create an external item with a body.
const CREATE_SUBCOMMANDS: &[(&str, &str)] = &[("pr", "create"), ("issue", "create")];

/// Nudges when a `gh … create` posts a long body inline instead of via a file.
pub struct WarnInlineBody;

impl Check for WarnInlineBody {
    fn name(&self) -> &str {
        "warn-inline-body"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        match longest_inline_body(command) {
            Some(hit) => CheckResult::nudge(render(&hit)),
            None => CheckResult::allow(),
        }
    }
}

/// One over-threshold inline body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineBody {
    /// `pr` or `issue`.
    pub noun: String,
    /// The body's length in characters.
    pub chars: usize,
}

/// Every `gh pr create` / `gh issue create` segment of `command`, with its noun.
/// Pure: no I/O.
pub fn create_segments(command: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    // Cheap reject before the shell model runs on every Bash command.
    if !command.contains("create") {
        return found;
    }
    for segment in command_segments(command) {
        let stripped = strip_group_wrappers(&segment);
        let tokens = executable_tokens(stripped);
        let rest = skip_transparent_prefixes(&tokens);
        let is_gh = rest
            .first()
            .is_some_and(|first| command_word(first).as_ref() == "gh");
        if !is_gh {
            continue;
        }
        let (Some(noun), Some(verb)) = (rest.get(1), rest.get(2)) else {
            continue;
        };
        if CREATE_SUBCOMMANDS
            .iter()
            .any(|(n, v)| n == noun && v == verb)
        {
            found.push((noun.clone(), stripped.to_string()));
        }
    }
    found
}

/// The longest over-threshold inline body across every create segment, if any.
/// Pure: no I/O.
pub fn longest_inline_body(command: &str) -> Option<InlineBody> {
    create_segments(command)
        .into_iter()
        .filter_map(|(noun, segment)| match last_body_flag(&segment) {
            Some(BodyArg::Inline(body)) => {
                let chars = body.chars().count();
                (chars > INLINE_BODY_MAX_CHARS).then_some(InlineBody { noun, chars })
            }
            _ => None,
        })
        .max_by_key(|hit| hit.chars)
}

fn render(hit: &InlineBody) -> String {
    let what = if hit.noun == "pr" { "PR" } else { "issue" };
    format!(
        "📝  `gh {noun} create` is posting a {chars}-character {what} body inline \
         (threshold: {INLINE_BODY_MAX_CHARS}).\n\n\
         Compose external bodies to a file and pass `--body-file <path>` instead. The file is \
         the redaction review moment — an inline `--body` (including a `\"$(cat <<EOF …)\"` \
         heredoc) skips it and publishes whatever the command string holds. Write the body \
         to a private scratch path, review it, then post it.\n\n\
         Advisory only.",
        noun = hit.noun,
        chars = hit.chars,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    fn long() -> String {
        "word ".repeat(60)
    }

    fn outcome(cmd: &str) -> Outcome {
        WarnInlineBody.run(&make_bash(cmd)).outcome
    }

    #[test]
    fn long_inline_body_nudges_on_pr_and_issue_create() {
        let body = long();
        for cmd in [
            format!("gh pr create --title t --body \"{body}\""),
            format!("gh issue create -R o/r --title t --body '{body}'"),
            format!("gh pr create --title t -b \"{body}\""),
            format!("gh pr create --title t --body=\"{body}\""),
            format!("cd /repo && gh pr create --title t --body \"{body}\""),
            format!("command gh issue create --body \"{body}\""),
            format!("env GH_REPO=o/r gh issue create --body \"{body}\""),
        ] {
            assert_eq!(outcome(&cmd), Outcome::Nudge, "{cmd}");
        }
    }

    #[test]
    fn heredoc_substitution_counts_as_inline() {
        let body = long();
        let cmd = format!("gh pr create --title t --body \"$(cat <<'EOF'\n{body}\nEOF\n)\"");
        assert_eq!(outcome(&cmd), Outcome::Nudge);
    }

    #[test]
    fn short_inline_body_is_silent() {
        assert_eq!(
            outcome("gh pr create --title t --body \"Fixes the typo.\""),
            Outcome::Allow
        );
        let at_threshold = "x".repeat(INLINE_BODY_MAX_CHARS);
        assert_eq!(
            outcome(&format!("gh issue create --body \"{at_threshold}\"")),
            Outcome::Allow
        );
    }

    #[test]
    fn body_file_is_the_sanctioned_path() {
        assert_eq!(
            outcome("gh pr create --title t --body-file /tmp/w/body.md"),
            Outcome::Allow
        );
        assert_eq!(outcome("gh issue create -F body.md"), Outcome::Allow);
        // gh uses the LAST body flag: a trailing --body-file wins over an inline one.
        let cmd = format!("gh pr create --body \"{}\" --body-file b.md", long());
        assert_eq!(outcome(&cmd), Outcome::Allow);
    }

    #[test]
    fn other_subcommands_are_out_of_scope() {
        let body = long();
        for cmd in [
            format!("gh pr comment 12 --body \"{body}\""),
            format!("gh pr edit 12 --body \"{body}\""),
            format!("gh issue comment 12 --body \"{body}\""),
            format!("echo \"gh pr create --body {body}\""),
            "gh pr create --fill".to_string(),
            "git status".to_string(),
        ] {
            assert_eq!(outcome(&cmd), Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn every_create_segment_is_checked() {
        // The long body is in the SECOND create; the first is short.
        let cmd = format!(
            "gh issue create --body short && gh pr create --body \"{}\"",
            long()
        );
        let hit = longest_inline_body(&cmd).unwrap();
        assert_eq!(hit.noun, "pr");
        assert_eq!(outcome(&cmd), Outcome::Nudge);
    }

    #[test]
    fn non_bash_payload_allows() {
        let input = cadence_hooks_core::test_builders::make_write("/tmp/x", "y");
        assert_eq!(WarnInlineBody.run(&input).outcome, Outcome::Allow);
    }
}
