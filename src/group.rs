//! `cadence-hooks group <namespace>/<hook>...`: run several hook checks against
//! one stdin payload in one process.
//!
//! A hooks.json entry per check means one process launch per check, and on a
//! Write that was a dozen launches for checks that each decide in well under a
//! millisecond. Wiring one `group` entry in their place keeps the checks and
//! drops the launches. The per-check behavior (audit rows, `CADENCE_DISABLE`,
//! panic handling) lives in [`crate::dispatch::run_logged_group`]; this module
//! only turns the member names into checks.
//!
//! Members resolve through the same clap parser and the same
//! [`crate::check_plan`] table a standalone run uses, so `group cadence/x` and
//! `cadence x` cannot dispatch different checks. A member that does not
//! resolve is skipped with a notice and the rest still run, which is what a
//! separate process for an unknown hook did: fail open for that one hook.

use crate::dispatch::{self, GroupMember};
use crate::{Cli, check_plan, hook_name};
use cadence_hooks_core::HookEvent;
use cadence_hooks_core::bypass::{self, BypassState};
use clap::Parser;

/// Why a member spec could not join the group.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rejected {
    /// Not `<namespace>/<hook>`, or no such hook in this build (likely a
    /// plugin that expects a newer binary).
    Unknown,
    /// A logger, a CLI action, or a SessionStart check: `group` runs only
    /// tool-event checks, which take no arguments and report one fixed event.
    NotAToolCheck,
    /// Wired on a different event than the group's first member.
    EventMismatch,
    /// Listed twice.
    Duplicate,
}

/// Resolve `spec` to its canonical name and check, or say why not.
/// `event` is the group's event once the first member fixes it.
pub(crate) fn resolve(
    spec: &str,
    event: Option<HookEvent>,
) -> Result<(&'static str, dispatch::CheckPlan), Rejected> {
    let (namespace, hook) = spec.split_once('/').ok_or(Rejected::Unknown)?;
    if namespace.is_empty() || hook.is_empty() || hook.contains('/') {
        return Err(Rejected::Unknown);
    }
    let cli =
        Cli::try_parse_from(["cadence-hooks", namespace, hook]).map_err(|_| Rejected::Unknown)?;
    let name = hook_name(&cli.command).ok_or(Rejected::NotAToolCheck)?;
    let plan = check_plan(&cli.command).ok_or(Rejected::NotAToolCheck)?;
    if plan.is_payload_event()
        || !matches!(plan.event(), HookEvent::PreToolUse | HookEvent::PostToolUse)
    {
        return Err(Rejected::NotAToolCheck);
    }
    if event.is_some_and(|e| e != plan.event()) {
        return Err(Rejected::EventMismatch);
    }
    Ok((name, plan))
}

/// Resolve every member, apply `CADENCE_DISABLE` per member, and run the group.
pub(crate) fn run(specs: &[String]) -> ! {
    let mut members: Vec<GroupMember> = Vec::new();
    let mut notices: Vec<String> = Vec::new();
    let mut event = None;
    for spec in specs {
        let resolved = resolve(spec, event).and_then(|(name, plan)| {
            if members.iter().any(|m| m.hook == name) {
                Err(Rejected::Duplicate)
            } else {
                Ok((name, plan))
            }
        });
        let (name, plan) = match resolved {
            Ok(resolved) => resolved,
            Err(why) => {
                let notice = rejection_notice(spec, &why);
                eprintln!("{notice}");
                if why == Rejected::Unknown {
                    // The row a standalone run of an unknown hook writes.
                    let (namespace, hook) = spec.split_once('/').unwrap_or((spec, ""));
                    cadence_hooks_metrics::log_failopen(
                        "version_mismatch",
                        Some(namespace),
                        Some(hook),
                        env!("CARGO_PKG_VERSION"),
                        Some("group member"),
                    );
                }
                notices.push(notice);
                continue;
            }
        };
        // The same per-hook switch `main` applies to a standalone run, with the
        // same stderr trace (#89).
        match bypass::resolve(name) {
            BypassState::Disabled => {
                eprintln!("⚠️  cadence-hooks: '{name}' disabled via CADENCE_DISABLE");
                continue;
            }
            BypassState::DisableRefused => eprintln!(
                "⚠️  cadence-hooks: refusing to disable protected guard '{name}' \
                 via CADENCE_DISABLE (it still runs). Use CADENCE_BYPASS=1 for a \
                 blanket maintenance bypass."
            ),
            BypassState::Bypassed | BypassState::Enforced => {}
        }
        event.get_or_insert(plan.event());
        members.push(GroupMember { hook: name, plan });
    }
    dispatch::run_logged_group(members, notices);
}

fn rejection_notice(spec: &str, why: &Rejected) -> String {
    let installed = env!("CARGO_PKG_VERSION");
    match why {
        Rejected::Unknown => format!(
            "cadence-hooks v{installed}: group member '{spec}' is not a known hook \
             (expected <namespace>/<hook>). A plugin may expect a newer cadence-hooks; \
             the other members still ran."
        ),
        Rejected::NotAToolCheck => format!(
            "cadence-hooks: group member '{spec}' is not a tool-event check, so it \
             cannot run in a group; wire it as its own hook."
        ),
        Rejected::EventMismatch => format!(
            "cadence-hooks: group member '{spec}' fires on a different event than \
             the rest of the group; wire it in its own group."
        ),
        Rejected::Duplicate => {
            format!("cadence-hooks: group member '{spec}' is listed twice; it ran once.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_pre_tool_use_check_to_its_canonical_name() {
        let (name, plan) = resolve("cadence/terminology", None).expect("resolves");
        assert_eq!(name, "terminology");
        assert_eq!(plan.event(), HookEvent::PreToolUse);
    }

    #[test]
    fn rejects_malformed_and_unknown_specs() {
        for spec in [
            "terminology",
            "cadence/",
            "/terminology",
            "cadence/terminology/x",
            "cadence/no-such-hook",
            "no-such-ns/terminology",
            "cadence/terminology --flag",
        ] {
            assert_eq!(
                resolve(spec, None).err(),
                Some(Rejected::Unknown),
                "{spec} must not resolve"
            );
        }
    }

    #[test]
    fn rejects_loggers_cli_actions_and_session_checks() {
        for spec in [
            "metrics/snapshot",
            "metrics/grade",
            "guardrails/dismiss-main-branch-warn",
            "session/start",
            "cadence/platform-drift",
            "cadence/model-posture",
        ] {
            assert_eq!(
                resolve(spec, None).err(),
                Some(Rejected::NotAToolCheck),
                "{spec} must not join a group"
            );
        }
    }

    #[test]
    fn rejects_a_member_on_another_event() {
        assert_eq!(
            resolve("guardrails/guard-git-init", Some(HookEvent::PreToolUse)).err(),
            Some(Rejected::EventMismatch)
        );
        assert!(resolve("guardrails/guard-git-init", Some(HookEvent::PostToolUse)).is_ok());
    }

    /// Every registered PreToolUse/PostToolUse hook that is a check resolves.
    /// This is what keeps `check_plan` complete: a check arm left in `main`'s
    /// match instead would fail here.
    #[test]
    fn every_registered_tool_check_can_join_a_group() {
        let loggers = ["snapshot"];
        for hook in crate::registry::HOOKS {
            if !matches!(
                hook.event,
                Some(HookEvent::PreToolUse | HookEvent::PostToolUse)
            ) || loggers.contains(&hook.name)
            {
                continue;
            }
            let spec = format!("{}/{}", hook.namespace, hook.name);
            let (name, _) = resolve(&spec, None)
                .unwrap_or_else(|e| panic!("{spec} should resolve for a group, got {e:?}"));
            assert_eq!(name, hook.name);
        }
    }
}
