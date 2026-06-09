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
pub fn render_context(
    owner_entries: &[AllowEntry],
    repo_entries: &[AllowEntry],
    extra_hosts: &[String],
    default_host: &str,
) -> String {
    let mut msg = String::from("git-guardrails (gh writes):\n");
    msg.push_str(
        "- gh writes (pr/issue/release/repo/api -X POST|PUT|PATCH|DELETE) are policed by an allowlist.\n",
    );
    msg.push_str(
        "- Always pass `-R owner/repo` for gh writes. Without it, the target is inferred from cwd's git remote — silently wrong in worktrees and when cwd is not the intended repo.\n",
    );
    msg.push_str("- Reads (`gh pr list`, `gh issue view`, etc.) work without `-R`.\n");

    if owner_entries.is_empty() && repo_entries.is_empty() {
        msg.push_str(
            "- Allowlist is empty (CADENCE_ALLOWED_OWNERS / CADENCE_ALLOWED_REPOS unset). Set these to enable guard-gh-write enforcement.\n",
        );
    } else {
        if !owner_entries.is_empty() {
            let owners: Vec<String> = owner_entries.iter().map(|e| e.to_string()).collect();
            msg.push_str(&format!("- Allowed owners: {}\n", owners.join(", ")));
        }
        if !repo_entries.is_empty() {
            let repos: Vec<String> = repo_entries.iter().map(|e| e.to_string()).collect();
            msg.push_str(&format!("- Allowed repos: {}\n", repos.join(", ")));
        }
    }

    msg.push_str(&format!("- Default host: {default_host}"));
    if !extra_hosts.is_empty() {
        msg.push_str(&format!("; extra hosts: {}", extra_hosts.join(", ")));
    }
    msg.push('\n');
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
        let repos = parse_allow_entries("external/shared-repo");
        let msg = render_context(&[], &repos, &[], "github.com");
        assert!(msg.contains("Allowed repos: external/shared-repo"));
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
        assert!(msg.contains("Allowlist is empty"));
        assert!(!msg.contains("Allowed owners:"));
        assert!(!msg.contains("Allowed repos:"));
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
        assert!(msg.contains("without `-R`"));
    }

    #[test]
    fn includes_default_host() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(msg.contains("Default host: github.com"));
    }

    #[test]
    fn includes_extra_hosts_when_set() {
        let extras = vec!["git.sjo.lol".to_string()];
        let msg = render_context(&[], &[], &extras, "github.com");
        assert!(msg.contains("extra hosts: git.sjo.lol"));
    }

    #[test]
    fn omits_extra_hosts_line_when_unset() {
        let msg = render_context(&[], &[], &[], "github.com");
        assert!(!msg.contains("extra hosts:"));
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
