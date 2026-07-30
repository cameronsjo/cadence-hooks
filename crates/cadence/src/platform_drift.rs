//! `cadence platform-drift` — SessionStart nudge when the installed
//! cadence-hooks binary or Claude Code itself has drifted meaningfully
//! behind a plugin-shipped baseline (`platform-baseline.json`).
//!
//! **Work-machine-safe by design**: no network, no `brew`, no `gh`, no
//! subprocess. The cadence-hooks half compares `env!("CARGO_PKG_VERSION")`
//! against the baseline file alone. The Claude Code half resolves the
//! running platform version from the *transcript* (the last assistant
//! line's top-level `version` field, via
//! [`cadence_hooks_core::transcript::last_assistant_harness_version`]) —
//! never a network call.
//!
//! A cold `source:"startup"` transcript has no assistant line yet, so that
//! half silently skips on fresh-start sessions — an accepted limitation
//! (documented, not a bug): the platform nudge effectively fires on
//! `resume`/`clear`/`compact` sessions. That is acceptable coverage for a
//! weekly-scale nudge (`doctor` picks up the slack for a synchronous check).
//!
//! Fail open throughout (ADR-0001): a missing `--baseline` path, an
//! unreadable or malformed baseline file, or an unparseable version string
//! degrades to silence, never a false nudge.
//!
//! A firing nudge is gated to **once per local calendar day per distinct drift
//! state** via [`cadence_hooks_core::markers::claim_today`] (#458) — a version
//! gap persists for days, and an identical nudge at every SessionStart is how a
//! nudge stops being read. The gate keys on the drift *content*, so bumping the
//! baseline (or resolving one half of the drift) re-fires the same day rather
//! than waiting for tomorrow; `CADENCE_NO_DAILY_GATE` disables it outright.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// The plugin-shipped baseline shape (`plugins/cadence/config/platform-baseline.json`
/// in the cadence monorepo). Reused by `cadence-hooks doctor`'s unconditional
/// status report, so the fields are `pub`.
#[derive(Debug, Deserialize)]
pub struct Baseline {
    pub claude_code: ClaudeCodeBaseline,
    pub cadence_hooks: CadenceHooksBaseline,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeCodeBaseline {
    pub last_swept_version: String,
}

#[derive(Debug, Deserialize)]
pub struct CadenceHooksBaseline {
    pub current_version: String,
}

/// Parse a `MAJOR.MINOR.PATCH` string into a comparable tuple. Malformed
/// input (missing segments, non-numeric major/minor) returns `None` so the
/// caller fails open rather than guessing. The patch segment tolerates a
/// trailing non-digit suffix (e.g. `5-beta`) by taking its leading digits.
fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let mut parts = v.trim().splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_raw = parts.next()?;
    let patch_digits: String = patch_raw.chars().take_while(char::is_ascii_digit).collect();
    if patch_digits.is_empty() {
        return None;
    }
    let patch = patch_digits.parse().ok()?;
    Some((major, minor, patch))
}

/// Escape a version string for use as a term in the daily-gate token.
///
/// The token grammar is `component:running>expected`, comma-joined, and both
/// version strings reaching it are file-supplied: [`parse_semver`] accepts
/// arbitrary trailing bytes past the patch digits, so a crafted
/// `current_version` containing `>` or `,` could otherwise forge the grammar and
/// alias a different drift state's token — suppressing a nudge that should have
/// fired. Percent-escaping the two separators (and the escape character first,
/// so the mapping is injective) makes a forged term impossible to confuse with a
/// real one.
fn token_component(version: &str) -> String {
    version
        .replace('%', "%25")
        .replace(',', "%2C")
        .replace('>', "%3E")
}

/// Gap semantics: nudge when major or minor differ at all, or when the patch
/// delta is >= 5 within the same major.minor. Malformed/unparseable versions
/// never nudge — a parse failure is silence, not a false positive.
fn version_gap(current: &str, baseline: &str) -> bool {
    let Some((c_major, c_minor, c_patch)) = parse_semver(current) else {
        return false;
    };
    let Some((b_major, b_minor, b_patch)) = parse_semver(baseline) else {
        return false;
    };
    if c_major != b_major || c_minor != b_minor {
        return true;
    }
    c_patch.abs_diff(b_patch) >= 5
}

/// Nudge when the installed binary or platform has drifted past the baseline.
pub struct PlatformDrift {
    pub baseline_path: Option<String>,
}

impl Check for PlatformDrift {
    fn name(&self) -> &str {
        "platform-drift"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(baseline_path) = &self.baseline_path else {
            return CheckResult::allow();
        };
        let Ok(content) = fs::read_to_string(baseline_path) else {
            return CheckResult::allow();
        };
        let Ok(baseline) = serde_json::from_str::<Baseline>(&content) else {
            return CheckResult::allow();
        };

        // Each firing half contributes a `(gate token, nudge text)` pair, held
        // together in one vector rather than two parallel ones: the daily gate
        // keys on the joined tokens, so a half that pushed a nudge without its
        // token would make two different drift states share a key and silence
        // one of them — a desync this shape cannot express.
        //
        // The token is a short `component:running>expected` term. A partial
        // upgrade (one half resolved, the other still behind) changes it, so the
        // remaining nudge re-fires the same day rather than waiting for tomorrow.
        let mut findings: Vec<(String, String)> = Vec::new();
        let installed_hooks_version = env!("CARGO_PKG_VERSION");

        if version_gap(
            installed_hooks_version,
            &baseline.cadence_hooks.current_version,
        ) {
            findings.push((
                format!(
                    "hooks:{}>{}",
                    token_component(installed_hooks_version),
                    token_component(&baseline.cadence_hooks.current_version)
                ),
                format!(
                    "cadence-hooks is behind: installed {installed_hooks_version}, plugin baseline expects {} — upgrade with your install method (e.g. `brew upgrade cadence-hooks`)",
                    baseline.cadence_hooks.current_version
                ),
            ));
        }

        if let Some(transcript_path) = input.transcript_path()
            && let Some(transcript) =
                cadence_hooks_core::transcript::read_tail(Path::new(transcript_path))
            && let Some(harness_version) =
                cadence_hooks_core::transcript::last_assistant_harness_version(&transcript)
            && version_gap(&harness_version, &baseline.claude_code.last_swept_version)
        {
            findings.push((
                format!(
                    "cc:{}>{}",
                    token_component(&harness_version),
                    token_component(&baseline.claude_code.last_swept_version)
                ),
                format!(
                    "Claude Code has moved since the last platform sweep: running {harness_version}, last swept {} — consider a platform-adoption sweep",
                    baseline.claude_code.last_swept_version
                ),
            ));
        }

        if findings.is_empty() {
            return CheckResult::allow();
        }

        // A version gap persists for days — every SessionStart would otherwise
        // re-nudge with the identical text until the upgrade lands, which is how
        // a nudge becomes wallpaper (#458). Fire at most once per calendar day
        // per distinct drift state; `CADENCE_NO_DAILY_GATE` disables the gate.
        let token = findings
            .iter()
            .map(|(token, _)| token.as_str())
            .collect::<Vec<_>>()
            .join(",");
        if !cadence_hooks_core::markers::claim_today("platform-drift", &token) {
            return CheckResult::allow();
        }

        let message = findings
            .into_iter()
            .map(|(_, nudge)| nudge)
            .collect::<Vec<_>>()
            .join("\n\n");
        CheckResult::nudge(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_session, with_marker_dir};

    fn write_baseline(dir: &std::path::Path, hooks_version: &str, cc_version: &str) -> String {
        let path = dir.join("platform-baseline.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"claude_code":{{"last_swept_version":"{cc_version}","swept_on":"2026-07-23","sweep_doc":"n/a"}},"cadence_hooks":{{"current_version":"{hooks_version}"}}}}"#
            ),
        )
        .unwrap();
        path.to_str().unwrap().to_string()
    }

    fn write_transcript(dir: &std::path::Path, version: &str) -> String {
        let path = dir.join("transcript.jsonl");
        std::fs::write(
            &path,
            format!(r#"{{"version":"{version}","message":{{"role":"assistant"}}}}"#),
        )
        .unwrap();
        path.to_str().unwrap().to_string()
    }

    // --- parse_semver / version_gap (pure) ---

    #[test]
    fn parse_semver_parses_clean_triples() {
        assert_eq!(parse_semver("2.1.218"), Some((2, 1, 218)));
        assert_eq!(parse_semver("0.66.0"), Some((0, 66, 0)));
    }

    #[test]
    fn parse_semver_tolerates_patch_suffix() {
        assert_eq!(parse_semver("1.2.5-beta"), Some((1, 2, 5)));
    }

    #[test]
    fn parse_semver_none_for_malformed() {
        assert_eq!(parse_semver("not-a-version"), None);
        assert_eq!(parse_semver("2.1"), None);
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("2.x.0"), None);
    }

    #[test]
    fn version_gap_silent_under_five_patch() {
        assert!(!version_gap("0.66.4", "0.66.0"));
    }

    #[test]
    fn version_gap_fires_at_five_patch() {
        assert!(version_gap("0.66.5", "0.66.0"));
    }

    #[test]
    fn version_gap_fires_on_any_minor_crossing() {
        assert!(version_gap("0.67.0", "0.66.9"));
    }

    #[test]
    fn version_gap_fires_on_any_major_crossing() {
        assert!(version_gap("1.0.0", "0.66.0"));
    }

    #[test]
    fn version_gap_silent_when_current_malformed() {
        assert!(!version_gap("bogus", "0.66.0"));
    }

    #[test]
    fn version_gap_silent_when_baseline_malformed() {
        assert!(!version_gap("0.66.0", "bogus"));
    }

    // --- token_component (gate-token escaping) ---

    #[test]
    fn token_component_passes_ordinary_versions_through() {
        assert_eq!(token_component("0.69.0"), "0.69.0");
        assert_eq!(token_component("2.1.218-beta.1"), "2.1.218-beta.1");
    }

    #[test]
    fn token_component_escapes_the_token_separators() {
        assert_eq!(token_component("1.2.3>x"), "1.2.3%3Ex");
        assert_eq!(token_component("1.2.3,x"), "1.2.3%2Cx");
    }

    #[test]
    fn token_component_cannot_forge_another_terms_token() {
        // `parse_semver` tolerates trailing bytes, so a crafted baseline version
        // can carry the grammar's own separators. Escaped, the forgery is
        // distinguishable from the real term it imitates.
        let forged = format!("hooks:0.69.0>{}", token_component("9.9.9,cc:1.0.0>1.0.0"));
        let genuine = "hooks:0.69.0>9.9.9,cc:1.0.0>1.0.0";
        assert_ne!(forged, genuine);
    }

    #[test]
    fn token_component_escaping_is_injective() {
        // The escape character is escaped first, so no two distinct inputs can
        // collide on one output — the property that makes aliasing impossible
        // rather than merely unlikely.
        assert_ne!(token_component("%3E"), token_component(">"));
    }

    // --- Check::run ---
    //
    // Every `run_*` case below is wrapped in `with_marker_dir` against a fresh
    // tempdir. `Check::run` now consults the shared once-per-day gate (#458),
    // which is process-global state: unsandboxed, one nudging test would stamp
    // the real per-user marker and silence the next one, making the suite
    // order-dependent (and, on a second same-day run, red).

    /// Build a baseline claiming a cadence-hooks version 10 patches ahead of
    /// whatever is installed — guaranteed to cross the `>= 5` patch threshold
    /// within the same major.minor by construction, independent of the actual
    /// installed version.
    fn write_hooks_behind_baseline(dir: &std::path::Path, cc_version: &str) -> String {
        let (major, minor, patch) = parse_semver(env!("CARGO_PKG_VERSION")).unwrap();
        write_baseline(dir, &format!("{major}.{minor}.{}", patch + 10), cc_version)
    }

    // --- Check::run — cadence-hooks half ---

    #[test]
    fn run_missing_baseline_path_allows() {
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: None,
            };
            let input = make_session("s1", "startup");
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn run_unreadable_baseline_allows() {
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some("/nonexistent/platform-baseline.json".into()),
            };
            let input = make_session("s1", "startup");
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn run_malformed_baseline_json_allows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform-baseline.json");
        std::fs::write(&path, "not json").unwrap();
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(path.to_str().unwrap().to_string()),
            };
            let input = make_session("s1", "startup");
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn run_cadence_hooks_current_allows() {
        let dir = tempfile::tempdir().unwrap();
        let installed = env!("CARGO_PKG_VERSION");
        let baseline_path = write_baseline(dir.path(), installed, "2.1.218");
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let input = make_session("s1", "startup");
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn run_cadence_hooks_far_behind_nudges() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_hooks_behind_baseline(dir.path(), "2.1.218");
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let input = make_session("s1", "startup");
            let result = check.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            assert!(result.message.unwrap().contains("cadence-hooks is behind"));
        });
    }

    // --- Check::run — Claude Code half: the firing-path test ---
    //
    // A doctored-baseline-in-isolation test can't distinguish "correctly
    // silent" from "dead feature" — this proves the nudge actually FIRES
    // end-to-end against a populated transcript fixture.

    #[test]
    fn run_claude_code_far_ahead_of_baseline_nudges_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_baseline(dir.path(), env!("CARGO_PKG_VERSION"), "2.1.100");
        let transcript_path = write_transcript(dir.path(), "2.1.218");

        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let input = cadence_hooks_core::test_builders::make_session_with_transcript(
                "s1",
                "resume",
                &transcript_path,
            );
            let result = check.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(msg.contains("Claude Code has moved"));
            assert!(msg.contains("2.1.218"));
            assert!(msg.contains("2.1.100"));
        });
    }

    #[test]
    fn run_claude_code_current_no_nudge() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_baseline(dir.path(), env!("CARGO_PKG_VERSION"), "2.1.218");
        let transcript_path = write_transcript(dir.path(), "2.1.218");

        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let input = cadence_hooks_core::test_builders::make_session_with_transcript(
                "s1",
                "resume",
                &transcript_path,
            );
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn run_cold_startup_no_transcript_still_checks_hooks_half() {
        // Documented limitation: a cold startup transcript has no assistant
        // line, so the Claude Code half silently skips — but the
        // cadence-hooks half (self-version, no transcript needed) still
        // fires independently.
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_hooks_behind_baseline(dir.path(), "2.1.218");
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let input = make_session("s1", "startup"); // no transcript_path set
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let result = check.run(&input);
            assert_eq!(result.outcome, Outcome::Nudge);
            let msg = result.message.unwrap();
            assert!(msg.contains("cadence-hooks is behind"));
            assert!(!msg.contains("Claude Code"));
        });
    }

    #[test]
    fn run_transcript_without_assistant_line_skips_claude_code_half() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_baseline(dir.path(), env!("CARGO_PKG_VERSION"), "2.1.100");
        let transcript_path = dir.path().join("empty.jsonl");
        std::fs::write(&transcript_path, r#"{"role":"user","content":"hi"}"#).unwrap();

        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            let input = cadence_hooks_core::test_builders::make_session_with_transcript(
                "s1",
                "startup",
                transcript_path.to_str().unwrap(),
            );
            assert_eq!(check.run(&input).outcome, Outcome::Allow);
        });
    }

    // --- Check::run — the once-per-day gate (#458) ---

    #[test]
    fn run_second_session_same_day_is_silent() {
        // The headline behavior: an unchanged drift state nudges once, then
        // stays quiet for the rest of the calendar day.
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_hooks_behind_baseline(dir.path(), "2.1.218");
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            assert_eq!(
                check.run(&make_session("s1", "startup")).outcome,
                Outcome::Nudge
            );
            assert_eq!(
                check.run(&make_session("s2", "startup")).outcome,
                Outcome::Allow,
                "a second session the same day must be silent"
            );
        });
    }

    #[test]
    fn run_refires_same_day_when_drift_state_changes() {
        // The gate keys on the drift content, not the date: resolving one half
        // while the other stays behind changes the token, so the remaining
        // nudge is reported today rather than tomorrow.
        let dir = tempfile::tempdir().unwrap();
        let marker_dir = tempfile::tempdir().unwrap();
        // Two baselines, so two directories — `write_baseline` always writes
        // `platform-baseline.json` into the directory it is handed.
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let both_behind = write_hooks_behind_baseline(&a, "2.1.100");
        let transcript_path = write_transcript(dir.path(), "2.1.218");
        // Second baseline: cadence-hooks now current, Claude Code still behind.
        let cc_only = write_baseline(&b, env!("CARGO_PKG_VERSION"), "2.1.100");

        with_marker_dir(marker_dir.path(), || {
            let input = cadence_hooks_core::test_builders::make_session_with_transcript(
                "s1",
                "resume",
                &transcript_path,
            );
            let first = PlatformDrift {
                baseline_path: Some(both_behind.clone()),
            };
            assert_eq!(first.run(&input).outcome, Outcome::Nudge);

            let second = PlatformDrift {
                baseline_path: Some(cc_only.clone()),
            };
            let result = second.run(&input);
            assert_eq!(
                result.outcome,
                Outcome::Nudge,
                "a changed drift state must re-fire the same day"
            );
            assert!(result.message.unwrap().contains("Claude Code has moved"));
        });
    }

    #[test]
    fn run_repeats_when_daily_gate_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_hooks_behind_baseline(dir.path(), "2.1.218");
        let marker_dir = tempfile::tempdir().unwrap();
        with_marker_dir(marker_dir.path(), || {
            // SAFETY: `with_marker_dir` holds the one env lock for this whole
            // closure, so this mutation is serialized against every other
            // env-mutating test in the binary.
            unsafe {
                std::env::set_var("CADENCE_NO_DAILY_GATE", "1");
            }
            let check = PlatformDrift {
                baseline_path: Some(baseline_path.clone()),
            };
            assert_eq!(
                check.run(&make_session("s1", "startup")).outcome,
                Outcome::Nudge
            );
            assert_eq!(
                check.run(&make_session("s2", "startup")).outcome,
                Outcome::Nudge,
                "the escape hatch must restore every-session nudging"
            );
            // SAFETY: still inside the env lock held by `with_marker_dir`.
            unsafe {
                std::env::remove_var("CADENCE_NO_DAILY_GATE");
            }
        });
    }
}
