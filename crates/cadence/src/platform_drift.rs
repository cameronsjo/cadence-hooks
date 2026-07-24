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

use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde::Deserialize;
use std::fs;

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

        let mut nudges = Vec::new();
        let installed_hooks_version = env!("CARGO_PKG_VERSION");

        if version_gap(
            installed_hooks_version,
            &baseline.cadence_hooks.current_version,
        ) {
            nudges.push(format!(
                "cadence-hooks is behind: installed {installed_hooks_version}, plugin baseline expects {} — upgrade with your install method (e.g. `brew upgrade cadence-hooks`)",
                baseline.cadence_hooks.current_version
            ));
        }

        if let Some(transcript_path) = input.transcript_path()
            && let Ok(transcript) = fs::read_to_string(transcript_path)
            && let Some(harness_version) =
                cadence_hooks_core::transcript::last_assistant_harness_version(&transcript)
            && version_gap(&harness_version, &baseline.claude_code.last_swept_version)
        {
            nudges.push(format!(
                "Claude Code has moved since the last platform sweep: running {harness_version}, last swept {} — consider a platform-adoption sweep",
                baseline.claude_code.last_swept_version
            ));
        }

        if nudges.is_empty() {
            CheckResult::allow()
        } else {
            CheckResult::nudge(nudges.join("\n\n"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_session;

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

    // --- Check::run — cadence-hooks half ---

    #[test]
    fn run_missing_baseline_path_allows() {
        let check = PlatformDrift {
            baseline_path: None,
        };
        let input = make_session("s1", "startup");
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_unreadable_baseline_allows() {
        let check = PlatformDrift {
            baseline_path: Some("/nonexistent/platform-baseline.json".into()),
        };
        let input = make_session("s1", "startup");
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_malformed_baseline_json_allows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform-baseline.json");
        std::fs::write(&path, "not json").unwrap();
        let check = PlatformDrift {
            baseline_path: Some(path.to_str().unwrap().to_string()),
        };
        let input = make_session("s1", "startup");
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_cadence_hooks_current_allows() {
        let dir = tempfile::tempdir().unwrap();
        let installed = env!("CARGO_PKG_VERSION");
        let baseline_path = write_baseline(dir.path(), installed, "2.1.218");
        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
        };
        let input = make_session("s1", "startup");
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_cadence_hooks_far_behind_nudges() {
        let dir = tempfile::tempdir().unwrap();
        // Baseline claims a version 10 patches ahead of whatever is installed —
        // guaranteed to cross the >=5 patch threshold within the same major.minor
        // by construction, independent of the actual installed version.
        let (major, minor, patch) = parse_semver(env!("CARGO_PKG_VERSION")).unwrap();
        let baseline_path = write_baseline(
            dir.path(),
            &format!("{major}.{minor}.{}", patch + 10),
            "2.1.218",
        );
        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
        };
        let input = make_session("s1", "startup");
        let result = check.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap().contains("cadence-hooks is behind"));
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

        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
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
    }

    #[test]
    fn run_claude_code_current_no_nudge() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_baseline(dir.path(), env!("CARGO_PKG_VERSION"), "2.1.218");
        let transcript_path = write_transcript(dir.path(), "2.1.218");

        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
        };
        let input = cadence_hooks_core::test_builders::make_session_with_transcript(
            "s1",
            "resume",
            &transcript_path,
        );
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn run_cold_startup_no_transcript_still_checks_hooks_half() {
        // Documented limitation: a cold startup transcript has no assistant
        // line, so the Claude Code half silently skips — but the
        // cadence-hooks half (self-version, no transcript needed) still
        // fires independently.
        let dir = tempfile::tempdir().unwrap();
        let (major, minor, patch) = parse_semver(env!("CARGO_PKG_VERSION")).unwrap();
        let baseline_path = write_baseline(
            dir.path(),
            &format!("{major}.{minor}.{}", patch + 10),
            "2.1.218",
        );
        let input = make_session("s1", "startup"); // no transcript_path set
        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
        };
        let result = check.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("cadence-hooks is behind"));
        assert!(!msg.contains("Claude Code"));
    }

    #[test]
    fn run_transcript_without_assistant_line_skips_claude_code_half() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = write_baseline(dir.path(), env!("CARGO_PKG_VERSION"), "2.1.100");
        let transcript_path = dir.path().join("empty.jsonl");
        std::fs::write(&transcript_path, r#"{"role":"user","content":"hi"}"#).unwrap();

        let check = PlatformDrift {
            baseline_path: Some(baseline_path),
        };
        let input = cadence_hooks_core::test_builders::make_session_with_transcript(
            "s1",
            "startup",
            transcript_path.to_str().unwrap(),
        );
        assert_eq!(check.run(&input).outcome, Outcome::Allow);
    }
}
