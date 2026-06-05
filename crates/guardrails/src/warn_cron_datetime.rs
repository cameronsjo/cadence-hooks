//! Inject current datetime before scheduling cron jobs.
//!
//! CronCreate pins to exact calendar dates via 5-field cron expressions.
//! A timer set for "10 minutes from now" at 23:55 will silently expire
//! when the date rolls over at midnight. This nudge injects the current
//! date and time into the transcript so the agent can schedule accurately.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges on CronCreate with current datetime context.
pub struct WarnCronDatetime;

impl Check for WarnCronDatetime {
    fn name(&self) -> &str {
        "warn-cron-datetime"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let tool = input.tool_name().unwrap_or("");
        if tool == "CronCreate" {
            // Local wall clock (with tz + weekday) is the load-bearing field —
            // CronCreate fires in the user's local zone. jiff supplies it
            // portably; the std library exposes UTC instants only.
            let dt = cadence_hooks_core::time::cron_datetime();
            return CheckResult::nudge(format!(
                "Current date/time: {} ({})\n\
                 Day of week: {}",
                dt.local, dt.utc, dt.weekday
            ));
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
            ..Default::default()
        }
    }

    #[test]
    fn cron_create_nudges_with_datetime() {
        let result = WarnCronDatetime.run(&make_input("CronCreate"));
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("Current date/time:"));
        assert!(msg.contains("UTC"));
        assert!(msg.contains("Day of week:"));
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
            ..Default::default()
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
    fn nudge_message_includes_day_of_week() {
        let result = WarnCronDatetime.run(&make_input("CronCreate"));
        let msg = result.message.unwrap();
        assert!(msg.contains("Day of week:"));
    }
}
