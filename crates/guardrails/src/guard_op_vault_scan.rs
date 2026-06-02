//! Block uninvited 1Password vault enumeration.
//!
//! `op item list` (especially piped to grep/awk) scans the whole vault. In
//! background/auto-mode sessions this trips the auto-mode classifier, and in
//! any session it reads far more secret metadata than a task needs. Single-item
//! reads (`op read op://...`, `op item get <name>`) stay allowed — the guard
//! targets enumeration, not access.

use cadence_hooks_core::shell::strip_quotes;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Matches `op item list` / `op vault list` enumeration commands.
static OP_VAULT_SCAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bop\s+(item|vault)\s+list\b").expect("pattern should compile"));

/// Matches shell exec wrappers that can hide a scan inside quotes.
static EXEC_WRAPPER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(bash|sh|zsh)\s+-c\b").expect("pattern should compile"));

/// Blocks `op item list` vault enumeration; single-item reads are allowed.
pub struct OpVaultScanGuard;

fn block_message(found: &str) -> String {
    format!(
        "🚫 guard-op-vault-scan: 1Password vault enumeration blocked\n   \
         Found: `{found}`\n   \
         Fix: ask the user how to supply the secret (op:// URI, item name, or env var) — \
         vault scans read every item's metadata and trip the auto-mode classifier.\n   \
         Allowed: single-item reads like `op read op://vault/item/field` or `op item get <name>`"
    )
}

impl Check for OpVaultScanGuard {
    fn name(&self) -> &str {
        "guard-op-vault-scan"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("op") {
            return CheckResult::allow();
        }

        // Strip quoted strings so prose mentioning the command doesn't fire.
        let stripped = strip_quotes(command);

        // Pass 1: direct invocation (after stripping quotes)
        if let Some(m) = OP_VAULT_SCAN.find(&stripped) {
            return CheckResult::block(block_message(m.as_str().trim()));
        }

        // Pass 2: inside exec wrappers (bash -c 'op item list')
        if EXEC_WRAPPER.is_match(&stripped)
            && let Some(m) = OP_VAULT_SCAN.find(command)
        {
            return CheckResult::block(block_message(m.as_str().trim()));
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
        let result = OpVaultScanGuard.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn unrelated_command_allowed() {
        let result = OpVaultScanGuard.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn op_read_single_item_allowed() {
        let result =
            OpVaultScanGuard.run(&make_bash("op read op://Private/GitHub Token/credential"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn op_item_get_allowed() {
        let result = OpVaultScanGuard.run(&make_bash(
            "op item get \"GitHub Token\" --fields label=token",
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn op_whoami_allowed() {
        let result = OpVaultScanGuard.run(&make_bash("op whoami"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- happy path: vault enumeration blocked ---

    #[test]
    fn op_item_list_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op item list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_item_list_piped_to_grep_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op item list | grep -i token"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_item_list_with_vault_flag_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op item list --vault Private | grep api"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_item_list_in_exec_wrapper_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("bash -c 'op item list'"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_item_list_in_chain_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("echo start && op item list | head -5"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_vault_list_blocked() {
        // `op vault list` enumerates vaults — same scan class
        let result = OpVaultScanGuard.run(&make_bash("op vault list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    // --- block message quality ---

    #[test]
    fn block_message_tells_claude_to_ask_user() {
        let result = OpVaultScanGuard.run(&make_bash("op item list | grep token"));
        let msg = result.message.unwrap_or_default();
        assert!(
            msg.contains("ask the user"),
            "block message should redirect to asking the user: {msg}"
        );
    }

    // --- edge cases ---

    #[test]
    fn quoted_prose_mentioning_op_item_list_allowed() {
        let result = OpVaultScanGuard.run(&make_bash("echo 'never run op item list uninvited'"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn extra_whitespace_between_tokens_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op  item   list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn empty_command_allowed() {
        let result = OpVaultScanGuard.run(&make_bash(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn hyphenated_lookalike_allowed() {
        // "op-item-list" is a different word, not the op CLI
        let result = OpVaultScanGuard.run(&make_bash("op-item-list --help"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- evasion (documented limitations) ---

    #[test]
    fn variable_expansion_not_caught() {
        // Variable indirection can't be resolved statically — documented gap.
        // The auto-mode classifier remains the backstop for this.
        let result = OpVaultScanGuard.run(&make_bash("$OP_CMD item list"));
        assert_eq!(result.outcome, Outcome::Allow);
    }
}
