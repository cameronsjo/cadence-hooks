//! `obsidian trash-guard-liveness` — SessionStart assertion that
//! [`ObsidianTrashGuard`] can still reach each route it guards (cadence-hooks#797).
//!
//! # Why this exists
//!
//! A control that cannot go red is not a control. `trash-guard` blocks in four
//! independent routes — a deleting verb, a clobbering redirect, a harness
//! delete (`Edit` with `operation: "delete"`), and an empty `Write` — and a
//! change to one of them (a refactor, a peel that stops peeling, a vault-path
//! resolver that stops resolving) leaves the others green. `Allow` is a silent
//! exit 0, so "inspected and allowed" and "never looked" are byte-identical
//! afterwards. This check makes the difference observable once per session, per
//! route, the way the removed `guard-rm-liveness` did for `guard-rm`.
//!
//! # What "dead" means here
//!
//! Silent when `OBSIDIAN_VAULT` is unset or empty: with no vault the guard has
//! nothing to protect and allowing is its contract. With a vault configured it
//! nudges when either
//!
//! - **the vault is not a directory** — the guard compares paths to a vault
//!   that does not exist, so it judges nothing (a typo, an unmounted volume);
//! - **a route diverges from its contract** — each probe below runs the guard's
//!   real judgement code against the configured vault with an in-memory
//!   existence view, and the nudge names which probe returned the wrong verdict.
//!
//! | Probe | Contract |
//! |---|---|
//! | `rm <file>` from the vault, through the hook entry point | Block |
//! | `rm <absolute vault path>` from outside it | Block |
//! | `: > <file>` on an existing vault file | Block |
//! | `Edit` `operation: "delete"` of a vault path, through the entry point | Block |
//! | `Write` of empty content to an existing vault file | Block |
//! | `npm run format` from the vault (control) | Allow |
//! | `Write` of real content to an existing vault file (control) | Allow |
//!
//! Nothing touches the disk: the probe file names a path that need not exist,
//! and the redirect and `Write` routes see it through a fake existence probe.
//!
//! # What it structurally CANNOT see
//!
//! It ships in the same binary and plugin as the guard it watches, so it shares
//! their fate. It cannot report the plugin disabled, the `hooks.json` matcher
//! or `if:` no longer reaching a route (the failure that motivated #797), the
//! binary absent (`run-cadence-hooks.sh` exits 0, fail-open), a hook timeout at
//! the moment of a real delete, or `CADENCE_BYPASS=1` (this hook is not
//! bypass-exempt, so it does not run then; `enforcement-status` reports that
//! switch). It asserts that the *code behind* each route is intact — silence
//! means "the routes classify as contracted", never "deletions are guarded".
//!
//! # No attacker bytes in the output
//!
//! `OBSIDIAN_VAULT` can come from a project's settings file. The nudge names
//! only `&'static str` route labels, never the vault path.
//!
//! Fail open (ADR-0001): this check never blocks. Its worst outcome is a nudge.

use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};

use crate::trash_guard::{FileMeta, judge};

/// Basename of the probe file. Never created.
const PROBE_FILE: &str = "cadence-trash-guard-liveness-probe.md";

/// Existence view in which exactly one path exists.
struct OnlyThis(String);

impl FileMeta for OnlyThis {
    fn exists(&self, path: &str) -> bool {
        path == self.0
    }
}

/// One route probe: a label for the nudge, the verdict the contract fixes, and
/// the verdict the guard actually returned.
struct Probe {
    route: &'static str,
    expected: Outcome,
    actual: Outcome,
}

/// Characters that would need quoting to survive being spliced into a probe
/// command. A vault path with one skips the absolute-path probe rather than
/// reporting a false divergence (the relative probes need no splice).
fn needs_quoting(path: &str) -> bool {
    path.chars()
        .any(|c| c.is_control() || "'\"\\$`".contains(c))
}

/// Build a `PreToolUse` payload through the real parse path, like a hook call.
fn payload(tool: &str, tool_input: serde_json::Value, cwd: &str) -> Result<HookInput, String> {
    HookInput::from_json(
        &serde_json::json!({
            "session_id": "trash-guard-liveness",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": cwd,
        })
        .to_string(),
    )
}

/// Run every probe against `vault`. `Err` names a probe payload that would not
/// build: this check's own bug, reported as such.
fn run_probes(vault: &str) -> Result<Vec<Probe>, String> {
    let normalized = cadence_hooks_core::normalize_path(vault);
    let probe_path = format!("{normalized}/{PROBE_FILE}");
    let meta = OnlyThis(probe_path.clone());
    let mut probes = Vec::new();

    let entry = |input: &HookInput| judge(input, vault, &meta).outcome;
    probes.push(Probe {
        route: "rm verb from inside the vault",
        expected: Outcome::Block,
        actual: entry(&payload(
            "Bash",
            serde_json::json!({ "command": format!("rm {PROBE_FILE}") }),
            &normalized,
        )?),
    });
    probes.push(Probe {
        route: "npm run format from inside the vault (control)",
        expected: Outcome::Allow,
        actual: entry(&payload(
            "Bash",
            serde_json::json!({ "command": "npm run format" }),
            &normalized,
        )?),
    });
    if !needs_quoting(&normalized) {
        probes.push(Probe {
            route: "rm verb naming a vault path from outside the vault",
            expected: Outcome::Block,
            actual: entry(&payload(
                "Bash",
                serde_json::json!({ "command": format!("rm '{probe_path}'") }),
                "/",
            )?),
        });
    }
    probes.push(Probe {
        route: "clobber redirect over an existing vault file",
        expected: Outcome::Block,
        actual: entry(&payload(
            "Bash",
            serde_json::json!({ "command": format!(": > {PROBE_FILE}") }),
            &normalized,
        )?),
    });
    probes.push(Probe {
        route: "harness delete of a vault path",
        expected: Outcome::Block,
        actual: entry(&payload(
            "Edit",
            serde_json::json!({ "file_path": probe_path, "operation": "delete" }),
            "/",
        )?),
    });
    probes.push(Probe {
        route: "empty Write over an existing vault file",
        expected: Outcome::Block,
        actual: entry(&payload(
            "Write",
            serde_json::json!({ "file_path": probe_path, "content": "" }),
            "/",
        )?),
    });
    probes.push(Probe {
        route: "Write of real content over an existing vault file (control)",
        expected: Outcome::Allow,
        actual: entry(&payload(
            "Write",
            serde_json::json!({ "file_path": probe_path, "content": "x" }),
            "/",
        )?),
    });
    Ok(probes)
}

/// The nudge for a vault value, or `None` when the routes are intact.
///
/// Pure over the vault string, so the tests need no process environment.
fn report_for(vault: &str) -> Option<String> {
    if !std::path::Path::new(vault).is_dir() {
        return Some(
            "trash-guard is configured with an OBSIDIAN_VAULT that is not a directory, so it \
             judges no path as inside the vault and vault files are unguarded. Fix or unset \
             OBSIDIAN_VAULT."
                .to_string(),
        );
    }
    let probes = match run_probes(vault) {
        Ok(probes) => probes,
        Err(error) => {
            return Some(format!(
                "trash-guard-liveness could not build its own probe payload ({error}); this \
                 check is broken, trash-guard's state is unknown."
            ));
        }
    };
    divergence_report(&probes)
}

/// The nudge for a probe set, or `None` when every probe met its contract.
fn divergence_report(probes: &[Probe]) -> Option<String> {
    let diverged: Vec<String> = probes
        .iter()
        .filter(|p| p.actual != p.expected)
        .map(|p| {
            format!(
                "{} — expected {:?}, got {:?}",
                p.route, p.expected, p.actual
            )
        })
        .collect();
    if diverged.is_empty() {
        return None;
    }
    Some(format!(
        "trash-guard is not judging vault deletions as contracted — {} of {} liveness probes \
         diverged:\n  {}\n\nTreat deletions and truncations of vault files as unguarded until \
         this is resolved.",
        diverged.len(),
        probes.len(),
        diverged.join("\n  ")
    ))
}

/// Assert at SessionStart that `trash-guard` reaches each of its routes.
pub struct TrashGuardLiveness;

impl Check for TrashGuardLiveness {
    fn name(&self) -> &str {
        "trash-guard-liveness"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        let Ok(vault) = std::env::var("OBSIDIAN_VAULT") else {
            return CheckResult::allow();
        };
        if vault.is_empty() {
            return CheckResult::allow();
        }
        report_for(&vault).map_or_else(CheckResult::allow, CheckResult::nudge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::test_builders::make_session;

    fn scratch_vault(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cadence-tgl-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_healthy_vault_is_silent() {
        let dir = scratch_vault("healthy");
        let report = report_for(&dir.to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(report, None);
    }

    #[test]
    fn every_probe_matches_the_verdict_it_claims() {
        let dir = scratch_vault("probes");
        let probes = run_probes(&dir.to_string_lossy()).expect("probe payloads build");
        std::fs::remove_dir_all(&dir).ok();
        for probe in &probes {
            assert_eq!(probe.actual, probe.expected, "{}", probe.route);
        }
        // A table that lost its Block rows would pass while asserting nothing.
        assert!(
            probes
                .iter()
                .filter(|p| p.expected == Outcome::Block)
                .count()
                >= 5
        );
        assert!(probes.iter().any(|p| p.expected == Outcome::Allow));
    }

    /// Table over vault values: which ones nudge, and that the nudge never
    /// carries the value.
    #[test]
    fn a_vault_that_is_not_a_directory_nudges_without_echoing_it() {
        for vault in [
            "/definitely/not/a/dir-9f3a",
            "/etc/passwd",
            "relative/vault",
        ] {
            let report = report_for(vault).unwrap_or_else(|| panic!("{vault} must nudge"));
            assert!(report.contains("not a directory"), "{vault}: {report}");
            assert!(!report.contains(vault), "{vault} leaked into: {report}");
        }
    }

    #[test]
    fn a_vault_with_shell_special_characters_stays_silent() {
        // Skips the spliced absolute probe instead of reporting a false alarm.
        let dir = scratch_vault("odd 'name");
        let report = report_for(&dir.to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(report, None);
    }

    /// The check is only worth running if a broken route turns it red.
    #[test]
    fn a_diverging_probe_is_named_in_the_nudge() {
        let probes = [
            Probe {
                route: "route one",
                expected: Outcome::Block,
                actual: Outcome::Block,
            },
            Probe {
                route: "route two",
                expected: Outcome::Block,
                actual: Outcome::Allow,
            },
        ];
        let report = divergence_report(&probes).expect("a divergence must nudge");
        assert!(report.contains("1 of 2"), "{report}");
        assert!(
            report.contains("route two — expected Block, got Allow"),
            "{report}"
        );
        assert!(!report.contains("route one"), "{report}");
        assert_eq!(divergence_report(&probes[..1]), None);
    }

    #[test]
    fn needs_quoting_table() {
        for (path, expected) in [
            ("/plain/vault", false),
            ("/with space/vault", false),
            ("/it's/vault", true),
            ("/a\"b", true),
            ("/a$b", true),
            ("/a`b", true),
            ("/a\\b", true),
            ("/a\nb", true),
        ] {
            assert_eq!(needs_quoting(path), expected, "{path}");
        }
    }

    #[test]
    fn run_is_silent_without_a_configured_vault() {
        for value in [None, Some("")] {
            let _guard = crate::trash_guard::ENV_LOCK
                .lock()
                .expect("env lock poisoned");
            let previous = std::env::var_os("OBSIDIAN_VAULT");
            // SAFETY: serialized by the shared lock and restored below.
            unsafe {
                match value {
                    Some(v) => std::env::set_var("OBSIDIAN_VAULT", v),
                    None => std::env::remove_var("OBSIDIAN_VAULT"),
                }
            }
            let outcome = TrashGuardLiveness
                .run(&make_session("s1", "startup"))
                .outcome;
            match previous {
                Some(v) => unsafe { std::env::set_var("OBSIDIAN_VAULT", v) },
                None => unsafe { std::env::remove_var("OBSIDIAN_VAULT") },
            }
            assert_eq!(outcome, Outcome::Allow, "{value:?}");
        }
    }

    #[test]
    fn run_nudges_on_a_configured_but_missing_vault() {
        let _guard = crate::trash_guard::ENV_LOCK
            .lock()
            .expect("env lock poisoned");
        let previous = std::env::var_os("OBSIDIAN_VAULT");
        // SAFETY: serialized by the shared lock and restored below.
        unsafe { std::env::set_var("OBSIDIAN_VAULT", "/definitely/not/a/dir-9f3a") };
        let result = TrashGuardLiveness.run(&make_session("s1", "startup"));
        match previous {
            Some(v) => unsafe { std::env::set_var("OBSIDIAN_VAULT", v) },
            None => unsafe { std::env::remove_var("OBSIDIAN_VAULT") },
        }
        assert_eq!(result.outcome, Outcome::Nudge);
    }
}
