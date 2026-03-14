//! Remind to check current datetime before scheduling cron jobs.
//!
//! CronCreate pins to exact calendar dates via 5-field cron expressions.
//! A timer set for "10 minutes from now" at 23:55 will silently expire
//! when the date rolls over at midnight. This guard warns the agent to
//! confirm the current date and time before scheduling.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Warns on CronCreate to prompt datetime awareness.
pub struct WarnCronDatetime;

impl Check for WarnCronDatetime {
    fn name(&self) -> &str {
        "warn-cron-datetime"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let tool = input.tool_name().unwrap_or("");
        if tool == "CronCreate" {
            return CheckResult::warn(
                "⏰ Cron expressions pin to exact calendar dates. \
                 Before scheduling, confirm the current date and time \
                 to avoid timers that silently expire on date rollover.",
            );
        }
        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    fn make_input(tool_name: &str) -> HookInput {
        HookInput {
            tool_name: Some(tool_name.into()),
            tool_input: None,
            cwd: None,
        }
    }

    #[test]
    fn cron_create_warns() {
        let result = WarnCronDatetime.run(&make_input("CronCreate"));
        assert_eq!(result.outcome, Outcome::Warn);
        assert!(
            result
                .message
                .as_deref()
                .unwrap()
                .contains("current date and time")
        );
    }

    #[test]
    fn cron_delete_allowed() {
        let result = WarnCronDatetime.run(&make_input("CronDelete"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn cron_list_allowed() {
        let result = WarnCronDatetime.run(&make_input("CronList"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn bash_allowed() {
        let result = WarnCronDatetime.run(&make_input("Bash"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn no_tool_name_allowed() {
        let input = HookInput {
            tool_name: None,
            tool_input: None,
            cwd: None,
        };
        let result = WarnCronDatetime.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    // --- edge case hardening ---

    #[test]
    fn empty_tool_name_allowed() {
        let result = WarnCronDatetime.run(&make_input(""));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn warn_message_mentions_date_rollover() {
        let result = WarnCronDatetime.run(&make_input("CronCreate"));
        let msg = result.message.unwrap();
        assert!(msg.contains("date"));
        assert!(msg.contains("rollover"));
    }
}
