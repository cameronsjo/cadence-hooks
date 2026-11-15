//! Retired hooks that plugin wiring may still call.
//!
//! A retired check keeps its subcommand so an older `hooks.json` that still
//! names it exits 0 with no output. An unknown subcommand would instead print
//! the "a plugin expects a newer version of cadence-hooks" notice and exit 1
//! on every matching tool call. Delete a name here, with its clap variant and
//! registry row, once no released plugin pin calls it.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// A hook that has been retired: it always allows and prints nothing.
pub struct Retired(pub &'static str);

impl Check for Retired {
    fn name(&self) -> &str {
        self.0
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn a_retired_hook_allows_silently() {
        for command in [
            "ls -1 | grep config",
            "curl -H 'Accept: application/json' x",
        ] {
            let result = Retired("warn-alias-parsing").run(&make_bash(command));
            assert_eq!(result.outcome, Outcome::Allow, "{command}");
            assert!(result.message.is_none(), "{command}");
        }
    }
}
