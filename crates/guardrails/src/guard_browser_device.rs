//! Confirm the target Chrome/device before the first Claude-in-Chrome action.
//!
//! `claude-in-chrome` MCP tools (`navigate`, `computer`, `tabs_context_mcp`, …)
//! land on whichever Chrome the extension last paired with. When multiple
//! Chrome browsers are signed into the same account (e.g. two laptops), an
//! unconfirmed first action can execute on the *wrong physical device* — a
//! side effect that is not cleanly reversible.
//!
//! The MCP server ships `list_connected_browsers` →
//! `select_browser`/`switch_browser` for exactly this, and
//! `list_connected_browsers`'s description *mandates* an `AskUserQuestion`
//! listing every browser — but that mandate is advisory; the model can skip
//! it. This guard makes the handshake enforced: it blocks the **first**
//! claude-in-chrome tool call of a session (exit 2, re-clarify message),
//! writes a per-session marker, and allows every subsequent call.
//!
//! **Policy note (deliberate exception to `developing-guards`).** The
//! block-vs-nudge heuristic would route "a single connected browser makes
//! selection unnecessary" to a nudge. But a nudge is exit 0 — the tool still
//! runs, so its context would arrive *after* the action already hit a device.
//! Stopping *before* the action lands requires exit 2. This is a narrowly
//! scoped confirmation handshake: it fires at most **once per session**, it
//! **fails open** on any error (ADR-0001), and it guards a high-cost,
//! not-cleanly-reversible side effect. It does not verify a device was
//! actually chosen — it trusts the model to act on the message, then opens
//! the gate for the rest of the session.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

/// Fully-qualified prefix shared by every claude-in-chrome MCP tool.
const CHROME_TOOL_PREFIX: &str = "mcp__claude-in-chrome__";

/// The re-clarify message emitted on the first (blocked) call.
const BLOCK_MESSAGE: &str = "BLOCKED: guard-browser-device\n\
Found: First Claude-in-Chrome action this session — target device unconfirmed.\n\
       Multiple Chrome browsers may be paired to this account.\n\
Fix:   1) list_connected_browsers  2) AskUserQuestion listing every connected\n\
       browser (label = display name, deviceId in parens)  3) select_browser with\n\
       the chosen deviceId (or switch_browser to pair interactively).\n\
       Then re-run this tool — it will proceed for the rest of the session.";

/// Block the first Claude-in-Chrome tool call per session until the target
/// device is confirmed.
pub struct GuardBrowserDevice;

impl GuardBrowserDevice {
    /// Per-session marker path.
    ///
    /// Hashes the session id so concurrent sessions don't share the handshake.
    /// Falls back to `PPID` (the Claude Code process — hooks run as separate
    /// children, so `process::id()` changes every invocation) and finally to
    /// `process::id()`, mirroring [`crate::warn_main_branch`]'s scoping.
    fn marker_path(input: &HookInput) -> PathBuf {
        let scope = input.session_id().map(str::to_string).unwrap_or_else(|| {
            std::env::var("PPID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or_else(std::process::id)
                .to_string()
        });

        let mut hasher = DefaultHasher::new();
        scope.hash(&mut hasher);
        let hash = hasher.finish();

        cadence_hooks_core::paths::marker_temp_dir()
            .join(format!(".claude-browser-device-{hash:x}"))
    }
}

impl Check for GuardBrowserDevice {
    fn name(&self) -> &str {
        "guard-browser-device"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Phase 1 — early exit: only claude-in-chrome MCP tools are in scope.
        let is_chrome_tool = input
            .tool_name()
            .is_some_and(|t| t.starts_with(CHROME_TOOL_PREFIX));
        if !is_chrome_tool {
            return CheckResult::allow();
        }

        // Marker present → handshake already done this session → allow.
        let marker = Self::marker_path(input);
        if marker.exists() {
            return CheckResult::allow();
        }

        // First call: record the handshake *before* returning so the marker
        // persists even though we exit 2, then block. A write failure is not a
        // reason to keep blocking — fail open (ADR-0001).
        let _ = std::fs::write(&marker, "");
        CheckResult::block(BLOCK_MESSAGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    /// Build a minimal MCP-tool `HookInput` with a given tool name and a
    /// unique session id so tests don't share marker state.
    fn make_mcp(tool: &str, session: &str) -> HookInput {
        HookInput {
            tool_name: Some(tool.into()),
            session_id: Some(session.into()),
            ..Default::default()
        }
    }

    #[test]
    fn wrong_tool_allows() {
        // A non-chrome tool (Bash) is never in scope, even with no marker.
        let input = make_mcp("Bash", "guard-bd-wrong-tool");
        let result = GuardBrowserDevice.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
        // And it must not create a marker.
        assert!(!GuardBrowserDevice::marker_path(&input).exists());
    }

    #[test]
    fn first_chrome_call_blocks_and_creates_marker() {
        let input = make_mcp("mcp__claude-in-chrome__navigate", "guard-bd-first-call");
        let marker = GuardBrowserDevice::marker_path(&input);
        // Ensure a clean slate, then exercise.
        let _ = std::fs::remove_file(&marker);

        let result = GuardBrowserDevice.run(&input);
        assert_eq!(result.outcome, Outcome::Block);
        assert!(
            result
                .message
                .as_deref()
                .expect("block should carry a message")
                .contains("guard-browser-device")
        );
        assert!(marker.exists(), "first call must write the session marker");

        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn second_chrome_call_allows_with_marker() {
        let input = make_mcp("mcp__claude-in-chrome__computer", "guard-bd-second-call");
        let marker = GuardBrowserDevice::marker_path(&input);

        // First call blocks and writes the marker.
        assert_eq!(GuardBrowserDevice.run(&input).outcome, Outcome::Block);
        assert!(marker.exists());

        // Identical second call sees the marker → allow.
        assert_eq!(GuardBrowserDevice.run(&input).outcome, Outcome::Allow);

        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn marker_path_differs_per_session() {
        let a = GuardBrowserDevice::marker_path(&make_mcp(
            "mcp__claude-in-chrome__navigate",
            "session-a",
        ));
        let b = GuardBrowserDevice::marker_path(&make_mcp(
            "mcp__claude-in-chrome__navigate",
            "session-b",
        ));
        assert_ne!(a, b, "different sessions must not share a marker");
    }
}
