//! Shared message text for guardrails checks that duplicated wording across
//! call sites (message-tightening audit: cadence-hooks#327).
//!
//! Each item here has 2+ call sites that must read identically — a literal
//! duplicate, not a thematic echo. Consolidating them means a future wording
//! change lands once instead of drifting between copies.

/// The worktree-creation recipe: `enforce_worktree`'s block message, its
/// subprocess-mutation nudge, and `warn_branch_base`'s worktree-first nudge
/// all point here. Includes its own code-span backticks so callers just
/// interpolate it inline.
pub const WORKTREE_CREATE_RECIPE: &str =
    "`git worktree add .claude/worktrees/<slug> -b feat/<slug>` (or EnterWorktree)";

/// Emitted when a `CADENCE_ALLOWED_OWNERS`-gated guard fires with no
/// allowlist configured at all — `guard_push_remote` and `guard_gh_write`
/// share this exact fail-safe message.
pub const NOT_CONFIGURED_MSG: &str = "🚫 git-guardrails: Not configured — run /guardrails-init to set up\n   \
     CADENCE_ALLOWED_OWNERS is not set.";

/// The `gh repo delete is blocked` message, parameterized by the matched
/// command text. `guard_gh_dangerous` has three call sites (direct
/// invocation, exec-wrapper, and the REST API form) that all render this.
pub fn repo_delete_blocked_message(found: &str) -> String {
    format!(
        "🚫 git-guardrails: gh repo delete is blocked\n   \
         Found: `{found}`\n   \
         Fix: delete manually via github.com — this is irreversible"
    )
}
