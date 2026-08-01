//! Block uninvited 1Password vault enumeration.
//!
//! `op item list` (especially piped to grep/awk) scans the whole vault. In
//! background/auto-mode sessions this trips the auto-mode classifier, and in
//! any session it reads far more secret metadata than a task needs. Single-item
//! reads (`op read op://...`, `op item get <name>`) stay allowed — the guard
//! targets enumeration, not access.
//!
//! Detection is tokenized, not regex-based. A flag-run regex cannot tell that
//! `--format json` is a flag plus its value without enumerating every
//! value-taking flag, so any global flag between `op` and the subcommand
//! (`op --format json item list`, `op --account x item list`, `op --cache item
//! list`, `op --session abc item list`) would evade it — the exact brittleness
//! this guard fixes. Instead, each shell segment is tokenized: if the segment's
//! command word is `op` and an `item`/`vault` token is immediately followed by
//! `list` anywhere after the command word, it's a scan. Intervening flags are
//! just skipped tokens, value-flag or not.

use cadence_hooks_core::shell::{command_segments, command_word, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Blocks `op item list` / `op vault list` vault enumeration; single-item reads
/// are allowed.
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

/// If `segment` is an `op` invocation that enumerates the vault, return the
/// matched keyword (`item` or `vault`) for the block message.
///
/// A scan is: the command word's basename is `op`, and some adjacent pair after
/// the command word is `item`/`vault` immediately followed by `list`. Tokenizing
/// (not regex) is what makes this robust to global flags — every token between
/// `op` and the subcommand is simply skipped, no value-flag enumeration needed.
/// Quoted prose can't fire: an `echo "... op item list"` segment's command word
/// is `echo`, and the quoted run is a single token.
///
/// Documented edges:
/// - `$OP_CMD item list` stays unseen — token 0 is `$OP_CMD`, not `op` (the
///   existing gap test; the auto-mode classifier is the backstop).
/// - `op run -- ./tool item list` would match (no real-world shape — accepted).
fn vault_scan_keyword(segment: &str) -> Option<&'static str> {
    let tokens = tokenize(segment);
    let first = tokens.first()?;
    if command_word(first).as_ref() != "op" {
        return None;
    }
    // Adjacent pairs strictly after the command word (token 0).
    tokens
        .windows(2)
        .skip(1)
        .find_map(|pair| match pair[0].as_str() {
            "item" | "vault" if pair[1] == "list" => {
                Some(if pair[0] == "item" { "item" } else { "vault" })
            }
            _ => None,
        })
}

impl Check for OpVaultScanGuard {
    fn name(&self) -> &str {
        "guard-op-vault-scan"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // `command_segments` splits chains/pipes AND expands shell wrappers
        // (`bash -c '…'`), so the wrapper case is structural — no separate pass.
        for segment in command_segments(command) {
            if let Some(kw) = vault_scan_keyword(&segment) {
                return CheckResult::block(block_message(&format!("op {kw} list")));
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
    fn case_folded_op_item_list_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("OP item list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn case_fold_does_not_fold_op_subcommands() {
        let result = OpVaultScanGuard.run(&make_bash("OP ITEM list"));
        assert_eq!(result.outcome, Outcome::Allow);
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

    // --- #81: global flags between `op` and the subcommand ---

    #[test]
    fn op_global_flag_format_json_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op --format json item list | grep token"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_global_flag_format_equals_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op --format=json item list | grep api"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_global_flag_account_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op --account my.1password.com item list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_global_flag_cache_blocked() {
        let result = OpVaultScanGuard.run(&make_bash("op --cache item list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_global_flag_session_blocked() {
        let result =
            OpVaultScanGuard.run(&make_bash("op --session abc item list | awk '{print $1}'"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn op_absolute_path_blocked() {
        // The command word may be a path; its basename is what's matched.
        let result = OpVaultScanGuard.run(&make_bash("/usr/local/bin/op item list"));
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

    #[test]
    fn op_item_get_named_list_allowed() {
        // An item literally named "list": tokens are [op, item, get, list].
        // The adjacent pairs (item, get) and (get, list) never match
        // item|vault + list, so this single-item read stays allowed.
        let result = OpVaultScanGuard.run(&make_bash("op item get list"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- evasion (documented limitations) ---

    #[test]
    fn variable_expansion_not_caught() {
        // An ENVIRONMENT-sourced variable can't be resolved statically —
        // documented gap. The auto-mode classifier remains the backstop.
        // (A visible same-command assignment IS resolved — next test.)
        let result = OpVaultScanGuard.run(&make_bash("$OP_CMD item list"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- #116: expansion modeling ---

    #[test]
    fn visible_assignment_resolved_blocked() {
        // The assignment is right there in the command string — resolvable.
        let result = OpVaultScanGuard.run(&make_bash("OP_CMD=op; $OP_CMD item list"));
        assert_eq!(result.outcome, Outcome::Block);
    }

    #[test]
    fn scan_inside_substitution_blocked() {
        // `$(…)` executes; hiding the scan inside one changes nothing.
        let result = OpVaultScanGuard.run(&make_bash(r#"echo "$(op item list)""#));
        assert_eq!(result.outcome, Outcome::Block);
    }
}
