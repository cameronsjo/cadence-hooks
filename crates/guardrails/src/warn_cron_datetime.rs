//! Inject current datetime before scheduling cron jobs.
//!
//! CronCreate pins to exact calendar dates via 5-field cron expressions.
//! A timer set for "10 minutes from now" at 23:55 will silently expire
//! when the date rolls over at midnight. This nudge injects the current
//! date and time into the transcript so the agent can schedule accurately.

use std::process::Command;

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Nudges on CronCreate with current datetime context.
pub struct WarnCronDatetime;

/// Run `date` with the given format string, trimming the trailing newline.
fn date_fmt(args: &[&str]) -> String {
    Command::new("date")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

impl Check for WarnCronDatetime {
    fn name(&self) -> &str {
        "warn-cron-datetime"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let tool = input.tool_name().unwrap_or("");
        if tool == "CronCreate" {
            let local = date_fmt(&["+%Y-%m-%d %H:%M:%S %Z"]);
            let utc = date_fmt(&["-u", "+%Y-%m-%d %H:%M:%S UTC"]);
            let day = date_fmt(&["+%A"]);
            return CheckResult::nudge(format!(
                "Current date/time: {local} ({utc})\n\
                 Day of week: {day}"
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
