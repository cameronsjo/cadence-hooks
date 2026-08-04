//! Nudge when `gh issue create` (or a `gh api .../issues` POST) targets an
//! owned repo that is not a known ecosystem issue tracker.
//!
//! Fires as a PreToolUse hook on Bash. Detects `gh issue create` commands and
//! `gh api` POST calls to `.../repos/OWNER/REPO/issues` endpoints. Nudges
//! (never blocks) when the resolved target is an owned repo that is not among
//! the known ecosystem trackers. Since the 2026-06-30 decentralization, issues
//! route by the component that owns the defect, so the guard checks the target
//! against a *set* of trackers (`cadence`, `cadence-hooks`, `forgectl`,
//! `claude-configurations`) rather than a single canonical repo. Override the
//! set with `CADENCE_ISSUE_TRACKERS` (plural, comma-separated) or the legacy
//! singular `CADENCE_ISSUE_TRACKER`. Unowned repos and third-party projects are
//! silently allowed — the nudge only fires for repos you control.

use cadence_hooks_core::config::{self, default_host, env_allow_entries, env_extra_hosts};
use cadence_hooks_core::shell::{
    contains_ignoring_ascii_case, git_command, host_and_repo_from_url, parse_work_dir, strip_quotes,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

/// Default set of canonical ecosystem issue trackers (2026-06-30 decentralization).
/// Overridable via `CADENCE_ISSUE_TRACKERS` (plural, comma-separated) or the legacy
/// singular `CADENCE_ISSUE_TRACKER`.
const DEFAULT_TRACKERS: &[&str] = &[
    "cameronsjo/cadence",               // 12 cadence plugins
    "cameronsjo/cadence-hooks",         // this binary
    "cameronsjo/forgectl",              // forgectl + claunch
    "cameronsjo/claude-configurations", // meta / orchestration
];

/// Return the effective set of known ecosystem issue trackers (lowercased).
///
/// Precedence: `CADENCE_ISSUE_TRACKERS` (plural, comma-separated — replaces the
/// default set) → the legacy singular `CADENCE_ISSUE_TRACKER` → `DEFAULT_TRACKERS`.
fn trackers() -> Vec<String> {
    if let Ok(v) = std::env::var("CADENCE_ISSUE_TRACKERS") {
        // Parse first, then check: a value that is all commas/whitespace
        // (e.g. ",") is non-empty at the string level but yields no entries.
        // Fall through to the default set rather than returning an empty vec
        // (which would make every owned repo nudge).
        let parsed: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    if let Ok(v) = std::env::var("CADENCE_ISSUE_TRACKER") {
        // Trim before the emptiness check so a whitespace-only value
        // (e.g. " ") behaves as unset instead of a single-space "tracker".
        let t = v.trim();
        if !t.is_empty() {
            return vec![t.to_lowercase()];
        }
    }
    DEFAULT_TRACKERS.iter().map(|s| s.to_lowercase()).collect()
}

/// Matches `gh api /?repos/OWNER/REPO/issues` where `/issues` is the final
/// path segment (no issue number, comments, or other sub-resource after it).
///
/// The four patterns here fold their leading `gh` and nothing else
/// (cadence-hooks#488): `GH` is a spelling the shell runs on a case-insensitive
/// volume, while `api` and the method values are gh's own and stay
/// case-sensitive where gh is. These are deliberate LOCAL copies of
/// `guard_gh_write`'s same-named patterns, so folding one file's set does not
/// reach the other's — each has to be done on its own.
static API_ISSUES_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:gh)\s+api\s[^\n]*/?repos/([^/\s]+/[^/\s]+)/issues(?:\s|$|[?#])")
        .expect("pattern should compile")
});

/// Detects a `gh api` call with an explicit write method flag.
static API_WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:gh)\s+api.*(-X|--method)\s+(?i)(POST|PUT|PATCH|DELETE)")
        .expect("pattern should compile")
});

/// Detects a `gh api` call with field flags (implies a write).
static API_FIELD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:gh)\s+api.*\s(-f[\s\S]|--field[\s=]|-F[\s\S]|--raw-field[\s=])")
        .expect("pattern should compile")
});

/// Matches `gh issue create` with only the VERB folded.
///
/// A plain `contains_ignoring_ascii_case` here folded the whole phrase, so
/// `gh ISSUE CREATE` nudged — but gh rejects a capitalized subcommand, so that
/// fires on text the shell cannot run. `guard_gh_write` refuses to call the
/// same string a write, and two guards disagreeing about one input is the
/// defect. Verb-only keeps the #488 invariant this file's other patterns hold.
static GH_ISSUE_CREATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i:gh)\s+issue\s+create").expect("pattern should compile"));

/// Detects a `gh api` call with `--input` (implies a write).
static API_INPUT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i:gh)\s+api.*\s--input\s").expect("pattern should compile"));

/// Extract a `-R`/`--repo` flag value from a raw command string.
///
/// Handles `-R x`, `-Rx`, `--repo x`, `--repo=x`. Quote-trims values so
/// `--repo "o/r"` resolves to `o/r`.
fn extract_repo_flag(command: &str) -> Option<String> {
    let trim_value = |s: &str| s.trim_matches(|c| c == '"' || c == '\'').to_string();
    let words: Vec<&str> = command.split_whitespace().collect();
    let mut iter = words.iter();
    while let Some(word) = iter.next() {
        if *word == "-R" || *word == "--repo" {
            return iter.next().map(|s| trim_value(s));
        }
        if let Some(repo) = word.strip_prefix("--repo=") {
            return Some(trim_value(repo));
        }
        if let Some(repo) = word.strip_prefix("-R")
            && !repo.is_empty()
            && !repo.starts_with('-')
        {
            return Some(trim_value(repo));
        }
    }
    None
}

/// True when `stripped` (a quote-stripped command) is an issue-create write.
///
/// Matches:
/// - `gh issue create` (after quote-stripping, so quoted occurrences are data)
/// - `gh api .../repos/OWNER/REPO/issues` path with a write method or field flags
fn is_issue_create(stripped: &str) -> bool {
    if GH_ISSUE_CREATE.is_match(stripped) {
        return true;
    }
    API_ISSUES_PATH.is_match(stripped)
        && (API_WRITE_METHOD.is_match(stripped)
            || API_FIELD_FLAGS.is_match(stripped)
            || API_INPUT_FLAG.is_match(stripped))
}

/// Pure judge: returns `Some(owner/repo)` when the command should fire a nudge.
///
/// Nudge gate — returns `Some(target)` only when ALL hold:
/// - The command is an issue-create write (after quote-stripping)
/// - A target `owner/repo` resolves via `-R` flag, API path, or git remote
/// - The target host is the default host (`github.com` unless `GH_HOST` is set)
/// - The target owner is in `CADENCE_ALLOWED_OWNERS`
/// - The target is not among the known ecosystem issue trackers
pub fn judge_issue_target(command: &str, work_dir: &Path) -> Option<String> {
    let stripped = strip_quotes(command);

    if !is_issue_create(&stripped) {
        return None;
    }

    let dh = default_host();
    let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
    let extra_hosts = env_extra_hosts();

    // Resolve host + target repo.
    // Precedence: (a) -R/--repo flag, (b) gh api path, (c) git remote.
    let (host, target) = if let Some(repo) = extract_repo_flag(command) {
        (dh.clone(), repo.to_lowercase())
    } else if let Some(caps) = API_ISSUES_PATH.captures(command) {
        let repo = caps
            .get(1)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();
        (dh.clone(), repo)
    } else {
        let wd = work_dir.to_str().unwrap_or(".");
        let origin_url = git_command(wd, &["remote", "get-url", "origin"])?;
        match host_and_repo_from_url(&origin_url) {
            Some((h, r)) => (h, r.to_lowercase()),
            None => return None,
        }
    };

    // Gate: default host only (gh CLI convention; self-hosted forges are out of scope).
    if host != dh {
        return None;
    }

    // Gate: target must be owned.
    let mut parts = target.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo_name = parts.next().unwrap_or("");
    if !config::is_allowed_with_extra_hosts(
        &host,
        owner,
        repo_name,
        &allowed_owners,
        &[],
        &extra_hosts,
    ) {
        return None;
    }

    // Gate: target must not be a known ecosystem tracker.
    if trackers().iter().any(|t| t == &target) {
        return None;
    }

    Some(target)
}

fn nudge_message(target: &str) -> String {
    format!(
        "warn-issue-tracker: {target} isn't a known cadence ecosystem issue tracker.\n\
         Issues route by the component that owns the defect:\n\
         cadence plugins → cameronsjo/cadence · cadence-hooks → cameronsjo/cadence-hooks ·\n\
         forgectl/claunch → cameronsjo/forgectl · meta/orchestration → cameronsjo/claude-configurations.\n\
         If this filing is deliberate — a genuinely external or new tracker — carry on."
    )
}

/// Nudges when `gh issue create` (or a `gh api .../issues` POST) targets an
/// owned repo that is not among the known ecosystem issue trackers.
pub struct WarnIssueTracker;

impl Check for WarnIssueTracker {
    fn name(&self) -> &str {
        "warn-issue-tracker"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Fast-path: skip commands that can't possibly match. Folded, like
        // the matcher behind it — a lowercase-only pre-filter is a silent veto
        // over a case-folded matcher (cadence-hooks#488). The `API_*` method
        // patterns this guard shares with `guard_gh_write` fold their `gh`, so
        // these two tests must too or the `gh api` arm stays half-folded.
        let stripped = strip_quotes(command);
        if !contains_ignoring_ascii_case(&stripped, "gh issue create")
            && !contains_ignoring_ascii_case(&stripped, "gh api")
        {
            return CheckResult::allow();
        }

        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
        let work_dir_str = parse_work_dir(command, cwd);
        let work_dir = Path::new(&work_dir_str);

        match judge_issue_target(command, work_dir) {
            Some(target) => CheckResult::nudge(nudge_message(&target)),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_bash;
    // make_bash_with_cwd is only used by the non-windows cwd test below; gate the
    // import to match, or clippy's -D unused-imports fails the Windows build.
    use crate::with_env;
    #[cfg(not(windows))]
    use cadence_hooks_core::test_builders::make_bash_with_cwd;
    use std::path::PathBuf;

    // Tests that mutate CADENCE_ALLOWED_OWNERS / CADENCE_ISSUE_TRACKER(S)
    // serialize via the crate-shared with_env/CADENCE_ENV_TEST_LOCK so they
    // don't race each other or the same globals mutated in guard_push_remote
    // / guard_gh_write (#446).

    fn workdir(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    // ---- guard-clause tests — return before reading env vars, no lock needed ----

    // `gh issue list` is a read, not a create — must not match.
    #[test]
    fn issue_list_not_guarded() {
        assert!(
            judge_issue_target("gh issue list -R cameronsjo/workbench", &workdir("/tmp")).is_none()
        );
    }

    // `gh pr create` is a PR, not an issue — must not match.
    #[test]
    fn pr_create_not_guarded() {
        assert!(
            judge_issue_target(
                "gh pr create -R cameronsjo/workbench --title x",
                &workdir("/tmp")
            )
            .is_none()
        );
    }

    // A plain git command has nothing to do with issues.
    #[test]
    fn git_status_not_guarded() {
        assert!(judge_issue_target("git status", &workdir("/tmp")).is_none());
    }

    // "gh issue create" inside a quoted string is data, not a command.
    #[test]
    fn quoted_issue_create_text_not_guarded() {
        assert!(
            judge_issue_target(
                r#"echo "gh issue create needs a canonical repo""#,
                &workdir("/tmp")
            )
            .is_none()
        );
    }

    // `gh api .../issues` without any write method is a GET — not a create.
    #[test]
    fn api_get_issues_not_guarded() {
        assert!(
            judge_issue_target("gh api repos/cameronsjo/workbench/issues", &workdir("/tmp"))
                .is_none()
        );
    }

    // `gh api .../issues` with --jq (read-only flag) and no write method.
    #[test]
    fn api_issues_with_jq_flag_not_guarded() {
        assert!(
            judge_issue_target(
                "gh api repos/cameronsjo/workbench/issues --jq '.[]'",
                &workdir("/tmp")
            )
            .is_none()
        );
    }

    // Sub-resource `/issues/123` is a specific issue, not a create endpoint.
    #[test]
    fn api_issue_sub_resource_not_guarded() {
        assert!(
            judge_issue_target(
                "gh api repos/cameronsjo/workbench/issues/123 -X PATCH -f title=new",
                &workdir("/tmp")
            )
            .is_none()
        );
    }

    // ---- happy-path tests (need CADENCE_ALLOWED_OWNERS) ----

    // `gh issue create -R <owned>` should fire a nudge.
    #[test]
    fn issue_create_with_repo_flag_nudges() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/workbench --title x",
                    &workdir("/tmp"),
                );
                assert_eq!(result, Some("cameronsjo/workbench".to_string()));
            },
        );
    }

    #[test]
    fn case_folded_gh_verb_nudges() {
        // cadence-hooks#488. This guard shares the `API_*` method patterns with
        // `guard_gh_write`, and those fold their `gh` — so its own `gh issue
        // create` / `gh api` tests had to fold too, or the `gh api` arm would
        // be half-folded: the method matched, the invocation didn't.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                for cmd in [
                    "GH issue create -R cameronsjo/workbench --title x",
                    "Gh issue create -R cameronsjo/workbench --title x",
                    "GH api repos/cameronsjo/workbench/issues -X POST -f title=x",
                ] {
                    assert_eq!(
                        judge_issue_target(cmd, &workdir("/tmp")),
                        Some("cameronsjo/workbench".to_string()),
                        "{cmd}"
                    );
                }
            },
        );
    }

    #[test]
    fn only_the_gh_verb_folds_not_the_subcommand() {
        // The fold must stop at the verb. `gh` rejects `ISSUE CREATE`, so a
        // capitalized subcommand names a command the shell cannot run —
        // matching it fires on text that will never execute, which is the
        // shape #489 turned into a net weakening. `guard_gh_write` already
        // refuses to call this string a write; the two guards must agree.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                for cmd in [
                    "gh ISSUE CREATE -R cameronsjo/workbench --title x",
                    "gh issue CREATE -R cameronsjo/workbench --title x",
                    "gh ISSUE create -R cameronsjo/workbench --title x",
                ] {
                    assert_eq!(judge_issue_target(cmd, &workdir("/tmp")), None, "{cmd}");
                }
            },
        );
    }

    // `gh api .../issues -X POST` should fire a nudge for an owned repo.
    #[test]
    fn api_post_issues_nudges() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh api repos/cameronsjo/workbench/issues -X POST -f title=x",
                    &workdir("/tmp"),
                );
                assert_eq!(result, Some("cameronsjo/workbench".to_string()));
            },
        );
    }

    // `gh api .../issues` with field flags (no explicit -X POST) is also a create.
    #[test]
    fn api_issues_field_flags_nudges() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh api repos/cameronsjo/workbench/issues -f title=Bug -f body=Description",
                    &workdir("/tmp"),
                );
                assert_eq!(result, Some("cameronsjo/workbench".to_string()));
            },
        );
    }

    // ---- edge tests ----

    // Filing to the canonical tracker should be silent.
    #[test]
    fn canonical_tracker_not_nudged() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/claude-configurations --title x",
                    &workdir("/tmp"),
                );
                assert!(result.is_none());
            },
        );
    }

    // Filing to an unowned third-party repo should be silent (not our business).
    #[test]
    fn unowned_repo_not_nudged() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R someorg/thirdparty --title x",
                    &workdir("/tmp"),
                );
                assert!(result.is_none());
            },
        );
    }

    // `CADENCE_ISSUE_TRACKER` override changes which target is exempt.
    #[test]
    fn env_override_changes_canonical() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", Some("cameronsjo/workbench")),
            ],
            || {
                // workbench is now the canonical — no nudge.
                let no_nudge = judge_issue_target(
                    "gh issue create -R cameronsjo/workbench --title x",
                    &workdir("/tmp"),
                );
                assert!(
                    no_nudge.is_none(),
                    "canonical override should suppress nudge"
                );

                // claude-configurations is no longer canonical — should nudge.
                let nudge = judge_issue_target(
                    "gh issue create -R cameronsjo/claude-configurations --title x",
                    &workdir("/tmp"),
                );
                assert_eq!(
                    nudge,
                    Some("cameronsjo/claude-configurations".to_string()),
                    "non-canonical owned repo should nudge when override is active"
                );
            },
        );
    }

    // ---- decentralization regression tests (#166) ----
    // Since 2026-06-30 issues route by owning component, so each of these
    // ecosystem trackers must be silent. The pre-#166 single-canonical guard
    // wrongly nudged all three (only claude-configurations was exempt).

    // `cameronsjo/cadence` (the 12 plugins) is a known tracker — no nudge.
    #[test]
    fn cadence_repo_not_nudged() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
                ("CADENCE_ISSUE_TRACKERS", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/cadence --title x",
                    &workdir("/tmp"),
                );
                assert!(result.is_none(), "cadence is a known tracker: {result:?}");
            },
        );
    }

    // `cameronsjo/cadence-hooks` (this binary) is a known tracker — no nudge.
    #[test]
    fn cadence_hooks_repo_not_nudged() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
                ("CADENCE_ISSUE_TRACKERS", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/cadence-hooks --title x",
                    &workdir("/tmp"),
                );
                assert!(
                    result.is_none(),
                    "cadence-hooks is a known tracker: {result:?}"
                );
            },
        );
    }

    // `cameronsjo/forgectl` (forgectl + claunch) is a known tracker — no nudge.
    #[test]
    fn forgectl_repo_not_nudged() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
                ("CADENCE_ISSUE_TRACKERS", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/forgectl --title x",
                    &workdir("/tmp"),
                );
                assert!(result.is_none(), "forgectl is a known tracker: {result:?}");
            },
        );
    }

    // `CADENCE_ISSUE_TRACKERS` (plural) REPLACES the default set: the listed
    // repos go silent and the former defaults (e.g. cadence) now nudge.
    #[test]
    fn plural_env_override_sets_tracker_set() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
                (
                    "CADENCE_ISSUE_TRACKERS",
                    Some("cameronsjo/foo, cameronsjo/bar"),
                ),
            ],
            || {
                // Both listed repos are now known trackers — silent.
                assert!(
                    judge_issue_target(
                        "gh issue create -R cameronsjo/foo --title x",
                        &workdir("/tmp"),
                    )
                    .is_none(),
                    "foo is in the override set — no nudge"
                );
                assert!(
                    judge_issue_target(
                        "gh issue create -R cameronsjo/bar --title x",
                        &workdir("/tmp"),
                    )
                    .is_none(),
                    "bar is in the override set — no nudge"
                );

                // A former default (cadence) is no longer in the set — nudges.
                let nudge = judge_issue_target(
                    "gh issue create -R cameronsjo/cadence --title x",
                    &workdir("/tmp"),
                );
                assert_eq!(
                    nudge,
                    Some("cameronsjo/cadence".to_string()),
                    "plural override replaces the default set, so cadence now nudges"
                );
            },
        );
    }

    // A whitespace-only singular override behaves as unset — the default set
    // still applies, so a known tracker is not spuriously nudged.
    #[test]
    fn whitespace_singular_env_behaves_as_unset() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", Some(" ")),
                ("CADENCE_ISSUE_TRACKERS", None),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/cadence --title x",
                    &workdir("/tmp"),
                );
                assert!(
                    result.is_none(),
                    "whitespace-only singular override should fall back to the default set: {result:?}"
                );
            },
        );
    }

    // A plural override that filters to nothing (all commas/whitespace) falls
    // back to the default set rather than making every owned repo nudge.
    #[test]
    fn empty_plural_env_falls_back_to_default_set() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
                ("CADENCE_ISSUE_TRACKERS", Some(",")),
            ],
            || {
                let result = judge_issue_target(
                    "gh issue create -R cameronsjo/cadence --title x",
                    &workdir("/tmp"),
                );
                assert!(
                    result.is_none(),
                    "empty plural override should fall back to the default set: {result:?}"
                );
            },
        );
    }

    // ---- evasion tests ----

    // "gh issue create" as a quoted data argument to echo must not be treated as a command.
    #[test]
    fn quoted_issue_create_in_echo_not_guarded() {
        assert!(
            judge_issue_target(
                r#"echo "gh issue create -R cameronsjo/workbench --title x""#,
                &workdir("/tmp"),
            )
            .is_none()
        );
    }

    // `gh api .../issues` without a write method is a read — must not trigger.
    #[test]
    fn api_issues_read_without_method_not_guarded() {
        assert!(
            judge_issue_target(
                "gh api repos/cameronsjo/workbench/issues --paginate",
                &workdir("/tmp"),
            )
            .is_none()
        );
    }

    // ---- nudge message format ----
    // These tests call canonical() which reads CADENCE_ISSUE_TRACKER — serialize
    // with CADENCE_ENV_TEST_LOCK (via with_env) and clear the var so
    // concurrent env-mutating tests don't race.

    #[test]
    fn nudge_message_names_the_check() {
        with_env(&[("CADENCE_ISSUE_TRACKER", None)], || {
            let msg = nudge_message("cameronsjo/workbench");
            assert!(
                msg.contains("warn-issue-tracker:"),
                "message should name the check: {msg}"
            );
        });
    }

    #[test]
    fn nudge_message_names_the_target() {
        with_env(&[("CADENCE_ISSUE_TRACKER", None)], || {
            let msg = nudge_message("cameronsjo/workbench");
            assert!(
                msg.contains("cameronsjo/workbench"),
                "message should name the filing target: {msg}"
            );
        });
    }

    #[test]
    fn nudge_message_names_the_canonical() {
        with_env(&[("CADENCE_ISSUE_TRACKER", None)], || {
            let msg = nudge_message("cameronsjo/workbench");
            assert!(
                msg.contains("cameronsjo/claude-configurations"),
                "message should name the canonical tracker: {msg}"
            );
        });
    }

    #[test]
    fn nudge_message_is_advisory_not_blocking() {
        with_env(&[("CADENCE_ISSUE_TRACKER", None)], || {
            let msg = nudge_message("cameronsjo/workbench");
            assert!(!msg.contains("🚫"), "nudge should not contain block emoji");
            assert!(msg.contains("carry on"), "nudge should give user an out");
        });
    }

    // ---- Check::run integration tests ----

    #[test]
    fn check_nudges_owned_non_canonical_repo() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = WarnIssueTracker.run(&make_bash(
                    "gh issue create -R cameronsjo/workbench --title x",
                ));
                assert_eq!(result.outcome, cadence_hooks_core::Outcome::Nudge);
                let msg = result.message.as_deref().unwrap_or("");
                assert!(
                    msg.contains("cameronsjo/workbench"),
                    "nudge message should name target"
                );
                assert!(
                    msg.contains("cameronsjo/claude-configurations"),
                    "nudge message should name canonical"
                );
            },
        );
    }

    #[test]
    fn check_allows_canonical_repo() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = WarnIssueTracker.run(&make_bash(
                    "gh issue create -R cameronsjo/claude-configurations --title x",
                ));
                assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
                assert!(result.message.is_none());
            },
        );
    }

    #[test]
    fn check_allows_unowned_repo() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ISSUE_TRACKER", None),
            ],
            || {
                let result = WarnIssueTracker
                    .run(&make_bash("gh issue create -R someorg/external --title x"));
                assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
            },
        );
    }

    #[test]
    fn check_allows_issue_list() {
        let result = WarnIssueTracker.run(&make_bash("gh issue list -R cameronsjo/workbench"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn check_allows_api_get_issues() {
        let result = WarnIssueTracker.run(&make_bash(
            "gh api repos/cameronsjo/workbench/issues --jq '.[]'",
        ));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn check_allows_no_command() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnIssueTracker.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // CWD-based integration: issue create resolved from git remote in the
    // cadence-hooks worktree. Uses make_bash_with_cwd to supply a real cwd.
    // This exercises the git-remote path through judge_issue_target.
    #[cfg(not(windows))]
    #[test]
    fn check_allows_when_cwd_is_not_a_git_repo() {
        // /tmp has no git remote — unresolvable → allow silently.
        let result = WarnIssueTracker.run(&make_bash_with_cwd("gh issue create --title x", "/tmp"));
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }
}
