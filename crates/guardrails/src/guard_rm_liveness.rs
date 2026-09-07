//! `guardrails guard-rm-liveness` — SessionStart assertion that [`guard_rm`]
//! is actually arbitrating deletes, rather than merely appearing to.
//!
//! # Why this exists
//!
//! Until 2026-08-03 two blanket `permissions.ask` rows (`Bash(rm -rf:*)`,
//! `Bash(rm -r:*)`) sat under `guard-rm` as a belt: if the guard did not run,
//! the settings row still prompted. Those rows were retired because they had no
//! filesystem awareness — they fired on deletes `guard-rm` had already proven
//! safe. What the operator's `allow`/`deny` blocks contain is a per-machine,
//! per-date snapshot that drifts, so with the belt gone a `guard-rm` that
//! silently fails to run can mean `rm -rf` executes with no prompt anywhere.
//!
//! That failure is invisible by construction: [`Outcome::Allow`] is a silent
//! exit 0 and only denials reach `denials.jsonl`, so "guard-rm inspected this
//! and allowed it" and "guard-rm never ran" are byte-identical after the fact.
//! This check makes the difference observable once per session.
//!
//! # What it asserts — the mechanism, not the absence of errors
//!
//! A healthy-looking session cannot distinguish a working guard from a lucky
//! one, so this check does not report "no errors". It runs [`GuardRm`] against
//! inputs whose verdicts are fixed by contract and compares:
//!
//! | Probe | Contract |
//! |---|---|
//! | an unexpanded `$VAR` operand | [`Outcome::Ask`] — unresolvable |
//! | a `$(…)` substitution operand | [`Outcome::Ask`] — unresolvable |
//! | a path under the temp root | [`Outcome::Allow`] — disposable |
//! | a top-level entry under `$HOME` | [`Outcome::Block`] — protected |
//!
//! A verdict that disagrees means the classifier has regressed, and the nudge
//! names which probe diverged. It separately reports when `guard-rm` is switched
//! off by environment, which is the documented and advertised way to neuter it.
//!
//! None of the four writes to disk. The home probe names a basename that need
//! not exist — the home classification is pure path logic — which is what makes
//! a Block case reachable at all here. It is also the probe that catches a
//! widened `$TMPDIR` swallowing real work; see [`home_block_probe`].
//!
//! # What it deliberately does NOT probe
//!
//! **The git-repo Block path.** Unlike the home case, it needs a real `.git` on
//! disk, and none of the four probes may write one. A tempdir fixture is now
//! classifiable — since #576 an explicit `.git` outranks the temp carve-out, so
//! `rm -rf /tmp/<dir-with-.git>` Blocks rather than allowing — but creating and
//! removing a repo at every SessionStart is a worse hazard than the gap it would
//! close, and a fixture outside the temp roots is worse still.
//!
//! # What it structurally CANNOT see
//!
//! This check ships in the same plugin and the same binary as the guard it
//! watches, so it shares their fate. It cannot report:
//!
//! - `CADENCE_BYPASS=1` — bypasses this check too, before it runs
//! - the plugin disabled, or `hooks.json` wiring missing or inert
//! - the binary absent or stale (`run-cadence-hooks.sh` exits 0, fail-open)
//! - a `guard-rm` hook timeout at the moment of an actual delete
//!
//! Silence from this check therefore means "guard-rm's classifier is intact and
//! not switched off", never "deletes are guarded". A self-check cannot announce
//! its own absence; closing that half needs an observer outside this binary.
//!
//! # No daily gate, deliberately
//!
//! `platform-drift` gates its nudge to once per calendar day (#458) because a
//! version gap persists for days and an identical nudge becomes wallpaper. This
//! check does not: it fires only at SessionStart (already once per session), and
//! what it reports is "your only remaining deletion guard is off or broken" —
//! a state that should be visible every time a session opens, not once and then
//! suppressed for 23 hours.
//!
//! Fail open (ADR-0001): this check never blocks. Its worst outcome is a nudge.

use cadence_hooks_core::{Check, CheckResult, HookInput, Outcome};

use crate::guard_rm::GuardRm;

/// The hook name `CADENCE_DISABLE` matches to switch off the guard this check
/// watches. `guard-rm` is deliberately absent from the binary's
/// `PROTECTED_GUARDS`, so naming it here genuinely neuters it — and its own Ask
/// message advertises the opt-out.
const GUARDED_HOOK: &str = "guard-rm";

/// A probe is one command string plus the verdict `guard-rm` is contracted to
/// return for it. Held as data rather than a sequence of hand-written asserts so
/// the failing probe can be named in the nudge, and so adding a case is a row
/// rather than a new branch.
struct Probe {
    /// The command handed to `guard-rm`, chosen to need no filesystem state.
    command: &'static str,
    /// What a working classifier must return.
    expected: Outcome,
    /// The classification under test, for the nudge text.
    classification: &'static str,
}

/// Probes covering the verdicts reachable without writing to disk.
///
/// The `$VAR` and `$(…)` cases resolve to `Unresolvable` on the operand alone —
/// no `stat`, no `lstat`, no dependence on what exists. The temp case is a path
/// prefix classification, so it holds whether or not the path exists.
const PROBES: &[Probe] = &[
    Probe {
        command: "rm -rf \"$CADENCE_GUARD_RM_LIVENESS_PROBE\"",
        expected: Outcome::Ask,
        classification: "unexpanded variable",
    },
    Probe {
        command: "rm -rf $(printf %s cadence-guard-rm-liveness-probe)",
        expected: Outcome::Ask,
        classification: "command substitution",
    },
    Probe {
        command: "rm -rf /tmp/cadence-guard-rm-liveness-probe",
        expected: Outcome::Allow,
        classification: "temp root",
    },
];

/// Basename for the home-directory Block probe. Never created or deleted — it
/// only has to be a top-level entry under `$HOME` for the path classifier.
const HOME_PROBE_BASENAME: &str = "cadence-guard-rm-liveness-probe";

/// The Block probe: deleting a top-level entry in `$HOME` must be refused.
///
/// This is the one Block case reachable with no filesystem fixture — the home
/// classification is pure path logic, so a non-existent basename classifies the
/// same as a real one. (The git-repo Block case is *not* reachable; see the
/// module header.)
///
/// It is also the probe that catches the widest real degradation: home
/// protection failing while the other three probes still pass, because none of
/// their operands falls under home. The instance it was written for — a
/// `$TMPDIR` pointing at the home directory, which converted that whole subtree
/// to "disposable" and made `rm -rf ~/Documents` a silent Allow — is fixed at
/// the source (cadence-hooks#569: a `$TMPDIR` that is home, or an ancestor of
/// it, is refused the temp carve-out). The probe stays because the failure
/// *class* is what it watches, not that one instance.
///
/// Returns `None` when the home directory cannot be resolved, so the probe is
/// skipped rather than failed — an unresolvable home is this check's own blind
/// spot, not evidence about `guard-rm`.
fn home_block_probe() -> Option<(String, Outcome, &'static str)> {
    let home = cadence_hooks_core::paths::user_home()?;
    // Built through the same resolver `guard-rm` itself uses, so the probe
    // cannot disagree with the guard about where home is.
    let target = home.join(HOME_PROBE_BASENAME);
    Some((
        format!("rm -rf {}", target.display()),
        Outcome::Block,
        "home directory",
    ))
}

/// Build the `PreToolUse` payload `guard-rm` expects for `command`.
///
/// Goes through [`HookInput::from_json`] rather than constructing a `HookInput`
/// literal so the probe traverses the same parse path a real hook invocation
/// does — payload sniffing, the `apply_patch` rewrite, and the derivation
/// behind [`HookInput::normalized_tool_name`], which guards read instead of
/// `tool_name`. A literal would skip all of it and probe a shape production
/// never sees.
fn probe_input(command: &str) -> Result<HookInput, String> {
    let payload = serde_json::json!({
        "session_id": "guard-rm-liveness",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    HookInput::from_json(&payload.to_string())
}

/// Whether `guard-rm` is switched off by environment, and which switch did it.
///
/// Mirrors the binary's own resolution in `main()` — `CADENCE_DISABLE` is a
/// comma-separated list of hook names, `CADENCE_BYPASS=1` is the blanket
/// escape. Duplicated rather than shared because that logic lives in the
/// binary's `main`, not a library crate; the duplication is the reason this
/// check can observe the disable state at all.
///
/// **The duplication is load-bearing, so drift here fails toward false
/// reassurance**: if the binary's parse ever accepts a form this one rejects,
/// the binary skips `guard-rm` while this check reports healthy — the exact
/// outcome the check exists to prevent. Verified identical at time of writing
/// (`split(',')`, `trim`, exact equality; `CADENCE_BYPASS` compared against
/// `"1"`, matching both of `main.rs`'s own copies). Any edit to either side
/// changes both, or extracts one shared resolver into `core`.
///
/// `CADENCE_BYPASS` is checked for completeness of the report, not for
/// coverage: a bypassed session never runs this check either.
fn disabled_by_environment() -> Option<&'static str> {
    if std::env::var("CADENCE_BYPASS").as_deref() == Ok("1") {
        return Some("CADENCE_BYPASS=1");
    }
    let disabled = std::env::var("CADENCE_DISABLE").ok()?;
    disabled
        .split(',')
        .any(|hook| hook.trim() == GUARDED_HOOK)
        .then_some("CADENCE_DISABLE=guard-rm")
}

/// Assert at SessionStart that `guard-rm` is present and classifying correctly.
pub struct GuardRmLiveness;

impl Check for GuardRmLiveness {
    fn name(&self) -> &str {
        "guard-rm-liveness"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        if let Some(switch) = disabled_by_environment() {
            return CheckResult::nudge(format!(
                "guard-rm is switched off ({switch}). It is the only thing gating recursive \
                 deletes — the blanket `rm -rf` / `rm -r` permission prompts were retired in \
                 favor of it, so nothing else will ask before a delete runs. Unset it to \
                 restore the guard."
            ));
        }

        // The static table plus the home Block probe, which is built at runtime
        // because it needs the resolved home directory. A `None` home drops the
        // probe rather than failing it — see `home_block_probe`.
        let cases = PROBES
            .iter()
            .map(|probe| {
                (
                    probe.command.to_string(),
                    probe.expected,
                    probe.classification,
                )
            })
            .chain(home_block_probe());

        // A probe that fails to build is this check's own bug, not evidence
        // about guard-rm — report it as such rather than implying the guard is
        // broken, and never let it read as a clean bill of health either.
        let mut divergences: Vec<String> = Vec::new();
        let mut ran = 0usize;
        for (command, expected, classification) in cases {
            ran += 1;
            let input = match probe_input(&command) {
                Ok(input) => input,
                Err(error) => {
                    divergences.push(format!(
                        "{classification} — guard-rm-liveness could not build its own probe \
                         payload ({error}); this check is broken, guard-rm's state is unknown"
                    ));
                    continue;
                }
            };
            let actual = GuardRm.run(&input).outcome;
            if actual != expected {
                divergences.push(format!(
                    "{classification} — expected {expected:?}, got {actual:?}"
                ));
            }
        }

        if divergences.is_empty() {
            return CheckResult::allow();
        }

        CheckResult::nudge(format!(
            "guard-rm is not classifying deletes as contracted — {} of {} liveness probes \
             diverged:\n  {}\n\nguard-rm is the only thing gating recursive deletes since the \
             blanket `rm -rf` / `rm -r` permission prompts were retired. Treat unexpected \
             deletes as unguarded until this is resolved.",
            divergences.len(),
            ran,
            divergences.join("\n  ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_env;
    use cadence_hooks_core::test_builders::make_session;

    /// Clear both switches so a test asserting the healthy path is not silently
    /// reading an ambient `CADENCE_DISABLE` from the launching session — the
    /// documented confound that makes env-reading checks false-pass.
    fn with_switches_clear(f: impl FnOnce()) {
        with_env(&[("CADENCE_DISABLE", None), ("CADENCE_BYPASS", None)], f);
    }

    #[test]
    fn healthy_guard_is_silent() {
        with_switches_clear(|| {
            assert_eq!(
                GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                Outcome::Allow
            );
        });
    }

    // --- the probes assert the contract, not the current implementation ---

    #[test]
    fn every_probe_matches_the_verdict_it_claims() {
        // The check is only worth running if its expectations are the ones
        // guard-rm actually holds. Asserting each probe individually here means
        // a guard-rm change that alters one of these verdicts fails THIS test
        // with the specific probe named, rather than surfacing as a mysterious
        // nudge in every session after release.
        with_switches_clear(|| {
            for probe in PROBES {
                let input = probe_input(probe.command).expect("probe payload must parse");
                assert_eq!(
                    GuardRm.run(&input).outcome,
                    probe.expected,
                    "probe `{}` ({}) no longer matches guard-rm's verdict",
                    probe.command,
                    probe.classification
                );
            }
        });
    }

    #[test]
    fn home_block_probe_matches_guard_rm() {
        with_switches_clear(|| {
            let (command, expected, _) = home_block_probe().expect("HOME is set under test");
            let input = probe_input(&command).expect("probe payload must parse");
            assert_eq!(GuardRm.run(&input).outcome, expected);
        });
    }

    #[test]
    fn widened_tmpdir_no_longer_disarms_the_home_block() {
        // This probe was added to DETECT the #569 degradation: guard-rm resolved
        // its temp roots partly from $TMPDIR, so pointing TMPDIR at the home
        // directory reclassified that whole subtree as disposable and
        // `rm -rf ~/<anything>` became a silent Allow. #569 fixed it at the
        // source — a $TMPDIR that is home, or an ancestor of it, is refused the
        // temp carve-out — so the check is now correctly SILENT in that state.
        //
        // The probe itself is not obsolete: it still fails loudly if home
        // protection regresses by any other route. This test pins the fix; the
        // probe covers the rest.
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
        let Ok(home) = home else {
            return; // no resolvable home on this platform; the probe self-skips
        };
        with_env(
            &[
                ("TMPDIR", Some(home.as_str())),
                ("CADENCE_DISABLE", None),
                ("CADENCE_BYPASS", None),
            ],
            || {
                let result = GuardRmLiveness.run(&make_session("s1", "startup"));
                assert_eq!(
                    result.outcome,
                    Outcome::Allow,
                    "a TMPDIR that swallows $HOME no longer degrades guard-rm (#569)"
                );
            },
        );
    }

    #[test]
    fn probes_cover_both_reachable_verdicts() {
        // Guards against a future edit quietly dropping the Ask probes and
        // leaving a suite that passes while asserting nothing dangerous.
        assert!(
            PROBES.iter().any(|p| p.expected == Outcome::Ask),
            "an Ask probe is the load-bearing one — an Ask-to-Allow regression is the silent one"
        );
        assert!(PROBES.iter().any(|p| p.expected == Outcome::Allow));
    }

    #[test]
    fn probe_payload_resolves_to_a_bash_command() {
        // Assert the properties guards actually read, not an internal field.
        // `normalized_tool` stays None for a native `Bash` — there is nothing to
        // rewrite — and `normalized_tool_name` falls back to `tool_name`, so
        // asserting the private field would fail while the payload is correct.
        let input = probe_input("rm -rf /tmp/x").expect("probe payload must parse");
        assert_eq!(input.normalized_tool_name(), Some("Bash"));
        assert_eq!(
            input.tool_input.as_ref().and_then(|t| t.command.as_deref()),
            Some("rm -rf /tmp/x"),
            "guard-rm reads the command off tool_input; an empty one would probe nothing \
             and pass for the wrong reason"
        );
    }

    // --- the disable switches ---

    #[test]
    fn disable_naming_guard_rm_nudges() {
        with_env(
            &[
                ("CADENCE_DISABLE", Some("guard-rm")),
                ("CADENCE_BYPASS", None),
            ],
            || {
                let result = GuardRmLiveness.run(&make_session("s1", "startup"));
                assert_eq!(result.outcome, Outcome::Nudge);
                assert!(result.message.unwrap().contains("CADENCE_DISABLE=guard-rm"));
            },
        );
    }

    #[test]
    fn disable_naming_guard_rm_among_others_nudges() {
        // The var is a comma-separated list; matching only an exact whole-value
        // equality would miss the common multi-hook form.
        with_env(
            &[
                (
                    "CADENCE_DISABLE",
                    Some("warn-main-branch, guard-rm ,line-endings"),
                ),
                ("CADENCE_BYPASS", None),
            ],
            || {
                assert_eq!(
                    GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                    Outcome::Nudge
                );
            },
        );
    }

    #[test]
    fn disable_naming_other_hooks_is_silent() {
        // The control: a populated CADENCE_DISABLE that does NOT name guard-rm
        // must stay silent, or the check reports every disabled hook as this one.
        with_env(
            &[
                ("CADENCE_DISABLE", Some("warn-main-branch,line-endings")),
                ("CADENCE_BYPASS", None),
            ],
            || {
                assert_eq!(
                    GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                    Outcome::Allow
                );
            },
        );
    }

    #[test]
    fn disable_substring_of_another_hook_name_is_silent() {
        // `guard-rm-liveness` contains `guard-rm`; a substring match would read
        // disabling THIS check as disabling the guard it watches.
        with_env(
            &[
                ("CADENCE_DISABLE", Some("guard-rm-liveness")),
                ("CADENCE_BYPASS", None),
            ],
            || {
                assert_eq!(
                    GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                    Outcome::Allow
                );
            },
        );
    }

    #[test]
    fn bypass_nudges() {
        with_env(
            &[("CADENCE_BYPASS", Some("1")), ("CADENCE_DISABLE", None)],
            || {
                let result = GuardRmLiveness.run(&make_session("s1", "startup"));
                assert_eq!(result.outcome, Outcome::Nudge);
                assert!(result.message.unwrap().contains("CADENCE_BYPASS=1"));
            },
        );
    }

    #[test]
    fn bypass_set_to_other_values_is_silent() {
        // The binary treats only "1" as bypass; a looser truthiness check here
        // would diverge from the enforcement it is reporting on.
        with_env(
            &[("CADENCE_BYPASS", Some("0")), ("CADENCE_DISABLE", None)],
            || {
                assert_eq!(
                    GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                    Outcome::Allow
                );
            },
        );
    }

    #[test]
    fn never_blocks() {
        // ADR-0001: this check's worst outcome is a nudge, in every state.
        with_env(
            &[
                ("CADENCE_DISABLE", Some("guard-rm")),
                ("CADENCE_BYPASS", None),
            ],
            || {
                assert_ne!(
                    GuardRmLiveness.run(&make_session("s1", "startup")).outcome,
                    Outcome::Block
                );
            },
        );
    }
}
