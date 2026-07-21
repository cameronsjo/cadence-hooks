//! `guardrails inject-gh-context` — SessionStart hook.
//!
//! Injects the gh-write allowlist + `-R owner/repo` rule into Claude's
//! context at session start (and after compaction). Primes the model with
//! the same context [`guard_gh_write`](super::guard_gh_write) enforces, so
//! writes target the right repo on the first try — recovering Mode A
//! "silent damage" cases where cwd's remote happens to be allowed but
//! isn't the intended write target.
//!
//! Wired by `cadence-canon`'s `hooks.json` on `matcher: startup|resume|compact`.

use std::collections::BTreeSet;

use cadence_hooks_core::config::{AllowEntry, default_host, env_allow_entries, env_extra_hosts};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Inject gh allowlist + `-R` rule on session start.
pub struct InjectGhContext;

impl Check for InjectGhContext {
    fn name(&self) -> &str {
        "inject-gh-context"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        let owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
        let repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
        let extras = env_extra_hosts();
        let default = default_host();
        CheckResult::nudge(render_context(&owners, &repos, &extras, &default))
    }
}

/// Pure renderer: build the SessionStart context message from a parsed
/// allowlist. Exposed for unit testing without env-var fiddling.
///
/// `owner_entries` and `repo_entries` come from two separate env vars
/// (`CADENCE_ALLOWED_OWNERS` / `CADENCE_ALLOWED_REPOS`) but render as one
/// combined "Allowed owners" list — both are [`AllowEntry`] values governing
/// the same allowlist, just entered at different granularity (a bare owner
/// vs an owner/repo pair).
pub fn render_context(
    owner_entries: &[AllowEntry],
    repo_entries: &[AllowEntry],
    extra_hosts: &[String],
    default_host: &str,
) -> String {
    let owners = if owner_entries.is_empty() && repo_entries.is_empty() {
        "none configured — set CADENCE_ALLOWED_OWNERS / CADENCE_ALLOWED_REPOS to enable \
         guard-gh-write enforcement"
            .to_string()
    } else {
        owner_entries
            .iter()
            .chain(repo_entries.iter())
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let default_host_lower = default_host.to_lowercase();

    let mut msg = format!(
        "git-guardrails: gh writes (pr/issue/release/repo/api mutations) are \
         allowlist-policed. Always pass `-R owner/repo` on writes — without it the target is \
         inferred from cwd's git remote, silently wrong in worktrees and off-repo cwds. Reads \
         need no `-R`. Allowed owners: {owners}."
    );
    if default_host_lower != "github.com" {
        msg.push_str(&format!(" Default host: {default_host}."));
    }
    if !extra_hosts.is_empty() {
        msg.push_str(&format!(" Extra hosts: {}.", extra_hosts.join(", ")));
    }

    // `gh` only ever talks to hosts under the default GH_HOST — an allowlist
    // entry or extra host naming any other forge needs routing away from it.
    let non_default_hosts: BTreeSet<String> = owner_entries
        .iter()
        .chain(repo_entries.iter())
        .filter_map(|e| e.host.as_deref())
        .chain(extra_hosts.iter().map(String::as_str))
        .map(str::to_lowercase)
        .filter(|h| *h != default_host_lower)
        .collect();
    if !non_default_hosts.is_empty() {
        let hosts = non_default_hosts.into_iter().collect::<Vec<_>>().join(", ");
        msg.push_str(&format!(
            " Hosts other than {default_host} ({hosts}): gh reaches them only if they run \
             GitHub — pass `-R host/owner/repo`; otherwise use that forge's own CLI/API \
             tooling."
        ));
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::config::parse_allow_entries;

    #[test]
    fn renders_owners_list() {
        let owners = parse_allow_entries("cameronsjo cameron");
        let msg = render_context(&owners, &[], &[], "github.com");
        assert!(msg.contains("Allowed owners: cameronsjo, cameron"));
    }

    #[test]
    fn renders_repos_list() {
        // repo_entries render into the same combined "Allowed owners" list as
        // owner_entries — both are AllowEntry values on one allowlist.
        let repos = parse_allow_entries("external/shared-repo");
        let msg = render_context(&[], &repos, &[], "github.com");
        assert!(msg.contains("Allowed owners: external/shared-repo"));
    }

    #[test]
    fn host_qualified_owner_renders_verbatim() {
        let owners = parse_allow_entries("git.sjo.lol/cameron");
        let msg = render_context(&owners, &[], &[], "github.com");
        assert!(msg.contains("Allowed owners: git.sjo.lol/cameron"));
    }

    #[test]
    fn warns_when_allowlist_empty() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(msg.contains("none configured"));
        assert!(msg.contains("CADENCE_ALLOWED_OWNERS"));
        assert!(msg.contains("CADENCE_ALLOWED_REPOS"));
    }

    #[test]
    fn includes_dash_r_rule() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(msg.contains("`-R owner/repo`"));
    }

    #[test]
    fn explains_reads_work_without_flag() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(msg.contains("Reads"));
        assert!(msg.contains("need no `-R`"));
    }

    #[test]
    fn omits_default_host_line_when_default() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(!msg.contains("Default host:"));
    }

    #[test]
    fn includes_default_host_when_deviating() {
        let msg = render_context(&[], &[], &[], "github.example.com");
        assert!(msg.contains("Default host: github.example.com."));
    }

    #[test]
    fn includes_extra_hosts_when_set() {
        let extras = vec!["git.sjo.lol".to_string()];
        let msg = render_context(&[], &[], &extras, "github.com");
        assert!(msg.contains("Extra hosts: git.sjo.lol"));
    }

    #[test]
    fn omits_extra_hosts_line_when_unset() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(!msg.contains("Extra hosts:"));
    }

    #[test]
    fn routes_away_from_gh_for_host_qualified_owner_entry() {
        let owners = parse_allow_entries("git.sjo.lol/cameron");
        let msg = render_context(&owners, &[], &[], "github.com");
        assert!(msg.contains("Hosts other than github.com (git.sjo.lol)"));
        assert!(msg.contains("`-R host/owner/repo`"));
    }

    #[test]
    fn routes_away_from_gh_for_extra_host() {
        let extras = vec!["git.sjo.lol".to_string()];
        let msg = render_context(&[], &[], &extras, "github.com");
        assert!(msg.contains("Hosts other than github.com (git.sjo.lol)"));
        assert!(msg.contains("forge's own CLI/API tooling"));
    }

    #[test]
    fn omits_routing_sentence_when_no_non_default_hosts() {
        let owners = parse_allow_entries("cameronsjo cameron");
        let msg = render_context(&owners, &[], &[], "github.com");
        assert!(!msg.contains("Hosts other than"));
    }

    #[test]
    fn omits_routing_sentence_when_host_qualified_entry_matches_default() {
        let owners = parse_allow_entries("github.com/cameron");
        let msg = render_context(&owners, &[], &[], "github.com");
        assert!(!msg.contains("Hosts other than"));
    }

    #[test]
    fn routing_sentence_distinct_from_extra_hosts_line() {
        let extras = vec!["git.sjo.lol".to_string()];
        let msg = render_context(&[], &[], &extras, "github.com");
        assert!(msg.contains("Extra hosts: git.sjo.lol."));
        assert!(msg.contains(
            "Hosts other than github.com (git.sjo.lol): gh reaches them only if they run \
             GitHub — pass `-R host/owner/repo`; otherwise use that forge's own CLI/API \
             tooling."
        ));
    }

    #[test]
    fn check_name_matches_subcommand() {
        assert_eq!(InjectGhContext.name(), "inject-gh-context");
    }

    #[test]
    fn check_returns_nudge_with_message() {
        // Hermetic: this check does not read cwd or git state, so HookInput::default
        // is enough. Env vars may or may not be set in the test process; we only
        // assert the shape (Nudge + non-empty message), not the content.
        let input = HookInput::default();
        let result = InjectGhContext.run(&input);
        assert!(matches!(result.outcome, Outcome::Nudge));
        let msg = result.message.expect("nudge always carries a message");
        assert!(msg.contains("git-guardrails"));
        assert!(msg.contains("`-R owner/repo`"));
    }
}
