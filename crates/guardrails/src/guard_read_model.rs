//! Opt-in per-model `Read`/`Grep` guard.
//!
//! Blocks a `Read`/`Grep` when the *current session model* — resolved from the
//! transcript tail — is denied by an env-configured allow/deny policy. Its whole
//! reason to exist is to let a session pin sensitive reads to a capable model
//! (e.g. keep 🔒 security reads on the Opus family): configure the policy and a
//! read attempted under the wrong model is blocked before it runs.
//!
//! **Fail-open by construction.** The guard blocks ONLY on a *positively
//! identified* model that policy denies. Every "we don't know the model" path —
//! guard disabled, no transcript path, an unreadable transcript, or a transcript
//! with no assistant model — defaults to ALLOW, so a missing or empty transcript
//! can never brick reads. `CADENCE_READ_MODEL_GUARD_ON_UNKNOWN=block` flips the
//! unknown-model paths to BLOCK for callers who want strict fail-closed.
//!
//! **Opt-in:** disabled unless `CADENCE_READ_MODEL_GUARD_MODELS` is set.
//!
//! Config (env vars — the codebase has no config file):
//! - `CADENCE_READ_MODEL_GUARD_MODELS` — space/comma list of model tokens
//!   (family keywords like `opus`/`sonnet`/`haiku`, or full ids like
//!   `claude-opus-4-8`). Unset/empty → guard disabled (no-op allow).
//! - `CADENCE_READ_MODEL_GUARD_MODE` — `deny` | `allow` (default `deny`).
//! - `CADENCE_READ_MODEL_GUARD_ON_UNKNOWN` — `block` | `allow` (default `allow`).
//!
//! Matching is a case-insensitive substring of each config token against the
//! resolved model id: `opus` matches `claude-opus-4-8`; a full id matches only
//! itself.

use cadence_hooks_core::{Check, CheckResult, HookInput};

/// Env var: the model token list. Unset/empty disables the guard.
const MODELS_VAR: &str = "CADENCE_READ_MODEL_GUARD_MODELS";
/// Env var: policy direction (`deny` | `allow`), default `deny`.
const MODE_VAR: &str = "CADENCE_READ_MODEL_GUARD_MODE";
/// Env var: unknown-model disposition (`block` | `allow`), default `allow`.
const ON_UNKNOWN_VAR: &str = "CADENCE_READ_MODEL_GUARD_ON_UNKNOWN";

/// Policy direction for the configured model list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Block when the resolved model matches the list (deny-list).
    Deny,
    /// Block when the resolved model does NOT match the list (allow-list).
    Allow,
}

impl Mode {
    /// Parse `CADENCE_READ_MODEL_GUARD_MODE`; anything but `allow` → `Deny`.
    fn from_env_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("allow") {
            Mode::Allow
        } else {
            Mode::Deny
        }
    }
}

/// What to do when no session model can be positively identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnUnknown {
    /// Allow the read (default) — a missing/empty transcript never bricks reads.
    Allow,
    /// Block the read — strict fail-closed for callers who opt in.
    Block,
}

impl OnUnknown {
    /// Parse `CADENCE_READ_MODEL_GUARD_ON_UNKNOWN`; anything but `block` → `Allow`.
    fn from_env_value(value: &str) -> Self {
        if value.eq_ignore_ascii_case("block") {
            OnUnknown::Block
        } else {
            OnUnknown::Allow
        }
    }
}

/// True when any config token is a case-insensitive substring of the model id.
/// `opus` matches `claude-opus-4-8`; the full id `claude-opus-4-8` matches only
/// itself.
fn model_matches(resolved: &str, models: &[String]) -> bool {
    let lowered = resolved.to_lowercase();
    models
        .iter()
        .any(|token| lowered.contains(&token.to_lowercase()))
}

/// Pure policy decision — no env reads, no I/O. `Some(block_message)` blocks;
/// `None` allows. Implements the #144 fail-direction table exactly.
///
/// BLOCK happens ONLY on a positively-identified model that policy denies (a
/// deny-list hit, or an allow-list miss). Every unknown-model path defers to
/// `on_unknown`, which defaults to `Allow`. An empty `models` list is the
/// disabled state — always allow.
pub fn judge(
    resolved_model: Option<&str>,
    mode: Mode,
    models: &[String],
    on_unknown: OnUnknown,
) -> Option<String> {
    // Guard disabled — an empty model list is a no-op allow.
    if models.is_empty() {
        return None;
    }

    let Some(model) = resolved_model else {
        // No positively-identified model → defer to on_unknown (default allow).
        return match on_unknown {
            OnUnknown::Block => Some(unknown_block_message()),
            OnUnknown::Allow => None,
        };
    };

    match (mode, model_matches(model, models)) {
        // deny-list hit → block
        (Mode::Deny, true) => Some(deny_hit_message(model)),
        // deny-list miss → allow
        (Mode::Deny, false) => None,
        // allow-list hit → allow
        (Mode::Allow, true) => None,
        // allow-list miss → block
        (Mode::Allow, false) => Some(allow_miss_message(model)),
    }
}

/// Block message for a deny-list hit (mode=deny, model in list).
fn deny_hit_message(model: &str) -> String {
    format!(
        "🔒 guard-read-model: Read/Grep blocked — session model {model:?} is on the deny-list (rule: deny-hit).\n   \
         Adjust or disable via {MODELS_VAR} / {MODE_VAR}.",
    )
}

/// Block message for an allow-list miss (mode=allow, model not in list).
fn allow_miss_message(model: &str) -> String {
    format!(
        "🔒 guard-read-model: Read/Grep blocked — session model {model:?} is not on the allow-list (rule: allow-miss).\n   \
         Adjust or disable via {MODELS_VAR} / {MODE_VAR}.",
    )
}

/// Block message for the strict unknown-model path (on_unknown=block, no model).
fn unknown_block_message() -> String {
    format!(
        "🔒 guard-read-model: Read/Grep blocked — session model could not be identified and {ON_UNKNOWN_VAR}=block (rule: unknown-block).\n   \
         Disable via {MODELS_VAR}, or set {ON_UNKNOWN_VAR}=allow.",
    )
}

/// Opt-in per-model Read/Grep guard (see the module docs for the policy table).
pub struct GuardReadModel;

impl Check for GuardReadModel {
    fn name(&self) -> &str {
        "guard-read-model"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Only Read/Grep are gated; every other tool passes through.
        let tool = input.normalized_tool_name().unwrap_or("");
        if tool != "Read" && tool != "Grep" {
            return CheckResult::allow();
        }

        // Opt-in: an empty model list disables the guard entirely.
        let models = cadence_hooks_core::config::env_list(MODELS_VAR);
        if models.is_empty() {
            return CheckResult::allow();
        }

        let mode = Mode::from_env_value(&std::env::var(MODE_VAR).unwrap_or_default());
        let on_unknown =
            OnUnknown::from_env_value(&std::env::var(ON_UNKNOWN_VAR).unwrap_or_default());

        // Resolve the current model from the transcript tail. Every failure to
        // read or parse is a fail-open path — routed through `judge(None, …)` →
        // on_unknown (default allow) — so a missing transcript never bricks reads.
        let resolved = input
            .transcript_path()
            .and_then(|path| cadence_hooks_core::transcript::read_tail(std::path::Path::new(path)))
            .and_then(|content| cadence_hooks_core::transcript::last_assistant_model(&content));

        match judge(resolved.as_deref(), mode, &models, on_unknown) {
            Some(msg) => CheckResult::block(msg),
            None => CheckResult::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_bash, make_grep, make_read};

    fn models(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // --- judge: the fail-direction table, every row ---

    #[test]
    fn disabled_empty_models_allows() {
        // Guard disabled (MODELS empty) → allow, regardless of model/mode.
        assert_eq!(
            judge(Some("claude-opus-4-8"), Mode::Deny, &[], OnUnknown::Block),
            None
        );
    }

    #[test]
    fn deny_hit_blocks() {
        // mode=deny, model IN deny-list → BLOCK, message names model + deny-hit.
        let msg = judge(
            Some("claude-opus-4-8"),
            Mode::Deny,
            &models(&["opus"]),
            OnUnknown::Allow,
        );
        let msg = msg.expect("deny-list hit must block");
        assert!(msg.contains("claude-opus-4-8"), "names the model: {msg}");
        assert!(msg.contains("deny-hit"), "names the rule: {msg}");
        assert!(
            msg.contains("CADENCE_READ_MODEL_GUARD_MODELS"),
            "names the disabling env var: {msg}"
        );
    }

    #[test]
    fn deny_miss_allows() {
        // mode=deny, model NOT in deny-list → ALLOW.
        assert_eq!(
            judge(
                Some("claude-sonnet-4-5"),
                Mode::Deny,
                &models(&["opus"]),
                OnUnknown::Allow
            ),
            None
        );
    }

    #[test]
    fn allow_hit_allows() {
        // mode=allow, model IN allow-list → ALLOW.
        assert_eq!(
            judge(
                Some("claude-opus-4-8"),
                Mode::Allow,
                &models(&["opus"]),
                OnUnknown::Allow
            ),
            None
        );
    }

    #[test]
    fn allow_miss_blocks() {
        // mode=allow, model NOT in allow-list → BLOCK, message names allow-miss.
        let msg = judge(
            Some("claude-haiku-4-5"),
            Mode::Allow,
            &models(&["opus"]),
            OnUnknown::Allow,
        );
        let msg = msg.expect("allow-list miss must block");
        assert!(msg.contains("claude-haiku-4-5"), "names the model: {msg}");
        assert!(msg.contains("allow-miss"), "names the rule: {msg}");
        assert!(
            msg.contains("CADENCE_READ_MODEL_GUARD_MODELS"),
            "names the disabling env var: {msg}"
        );
    }

    #[test]
    fn unknown_model_defaults_allow() {
        // resolved None, on_unknown=Allow (default) → ALLOW, both modes.
        assert_eq!(
            judge(None, Mode::Deny, &models(&["opus"]), OnUnknown::Allow),
            None
        );
        assert_eq!(
            judge(None, Mode::Allow, &models(&["opus"]), OnUnknown::Allow),
            None
        );
    }

    #[test]
    fn unknown_model_block_flips_to_block() {
        // resolved None, on_unknown=Block → BLOCK (unknown-block), never on a model.
        let msg = judge(None, Mode::Deny, &models(&["opus"]), OnUnknown::Block);
        let msg = msg.expect("on_unknown=block must block when no model is identified");
        assert!(msg.contains("unknown-block"), "names the rule: {msg}");
        assert!(
            msg.contains("CADENCE_READ_MODEL_GUARD_ON_UNKNOWN"),
            "names the on-unknown env var: {msg}"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        // Config token casing and model casing both fold.
        assert!(
            judge(
                Some("CLAUDE-OPUS-4-8"),
                Mode::Deny,
                &models(&["OpUs"]),
                OnUnknown::Allow
            )
            .is_some(),
            "case-insensitive substring must hit"
        );
    }

    #[test]
    fn family_keyword_matches_full_id() {
        // Family keyword `opus` matches the full id.
        assert!(
            judge(
                Some("claude-opus-4-8"),
                Mode::Deny,
                &models(&["opus"]),
                OnUnknown::Allow
            )
            .is_some()
        );
    }

    #[test]
    fn full_id_matches_only_itself() {
        // A full-id token matches its own id but not a different one.
        assert!(
            judge(
                Some("claude-opus-4-8"),
                Mode::Deny,
                &models(&["claude-opus-4-8"]),
                OnUnknown::Allow
            )
            .is_some(),
            "full id must match itself"
        );
        assert_eq!(
            judge(
                Some("claude-sonnet-4-5"),
                Mode::Deny,
                &models(&["claude-opus-4-8"]),
                OnUnknown::Allow
            ),
            None,
            "full id must not match a different model"
        );
    }

    // --- Mode / OnUnknown parsing ---

    #[test]
    fn mode_parses_allow_else_deny() {
        assert_eq!(Mode::from_env_value("allow"), Mode::Allow);
        assert_eq!(Mode::from_env_value("ALLOW"), Mode::Allow);
        assert_eq!(Mode::from_env_value("deny"), Mode::Deny);
        assert_eq!(Mode::from_env_value(""), Mode::Deny);
        assert_eq!(Mode::from_env_value("garbage"), Mode::Deny);
    }

    #[test]
    fn on_unknown_parses_block_else_allow() {
        assert_eq!(OnUnknown::from_env_value("block"), OnUnknown::Block);
        assert_eq!(OnUnknown::from_env_value("BLOCK"), OnUnknown::Block);
        assert_eq!(OnUnknown::from_env_value("allow"), OnUnknown::Allow);
        assert_eq!(OnUnknown::from_env_value(""), OnUnknown::Allow);
        assert_eq!(OnUnknown::from_env_value("garbage"), OnUnknown::Allow);
    }

    // --- Check::run glue ---
    //
    // run() reads the three CADENCE_READ_MODEL_GUARD_* vars from the
    // process-global environment, so every run()-based test serializes via
    // the crate-shared with_env/CADENCE_ENV_TEST_LOCK and explicitly pins all
    // three (restoring prior values) — this keeps the disabled-guard
    // assertions deterministic even if the ambient env has MODELS set, and
    // free of races with parallel tests (#446).

    use crate::with_env;

    /// Pin all three guard vars — a common base the per-test overrides adjust.
    fn guard_env(
        models: Option<&'static str>,
        mode: Option<&'static str>,
        on_unknown: Option<&'static str>,
    ) -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            (MODELS_VAR, models),
            (MODE_VAR, mode),
            (ON_UNKNOWN_VAR, on_unknown),
        ]
    }

    /// Write a one-line transcript naming `model` and return its temp file.
    fn transcript_with_model(model: &str) -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            format!(r#"{{"message":{{"role":"assistant","model":"{model}"}}}}"#),
        )
        .unwrap();
        tmp
    }

    #[test]
    fn non_read_grep_tool_allows() {
        // A denying policy is set, but Bash is not gated → allow before any env read.
        with_env(&guard_env(Some("opus"), Some("deny"), None), || {
            let input = make_bash("echo hi");
            assert_eq!(GuardReadModel.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn read_with_guard_disabled_allows() {
        // A temp transcript names opus, but MODELS is unset → guard disabled → allow.
        with_env(&guard_env(None, None, None), || {
            let tmp = transcript_with_model("claude-opus-4-8");
            let input = make_read("/tmp/secret", tmp.path().to_str());
            assert_eq!(GuardReadModel.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn read_deny_hit_blocks_end_to_end() {
        // deny opus + a transcript resolving to opus → BLOCK through run().
        with_env(&guard_env(Some("opus"), Some("deny"), None), || {
            let tmp = transcript_with_model("claude-opus-4-8");
            let input = make_read("/tmp/secret", tmp.path().to_str());
            let result = GuardReadModel.run(&input);
            assert_eq!(result.outcome, Outcome::Block, "opus read must be blocked");
            assert!(
                result
                    .message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("claude-opus-4-8")
            );
        });
    }

    #[test]
    fn read_deny_miss_allows_end_to_end() {
        // deny opus + a transcript resolving to sonnet → ALLOW through run().
        with_env(&guard_env(Some("opus"), Some("deny"), None), || {
            let tmp = transcript_with_model("claude-sonnet-4-5");
            let input = make_read("/tmp/ok", tmp.path().to_str());
            assert_eq!(GuardReadModel.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn grep_allow_miss_blocks_end_to_end() {
        // allow-list = opus + a Grep under haiku → BLOCK through run().
        with_env(&guard_env(Some("opus"), Some("allow"), None), || {
            let tmp = transcript_with_model("claude-haiku-4-5");
            let input = make_grep("pattern", tmp.path().to_str());
            let result = GuardReadModel.run(&input);
            assert_eq!(result.outcome, Outcome::Block, "non-allowed grep blocks");
            assert!(
                result
                    .message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("claude-haiku-4-5")
            );
        });
    }

    #[test]
    fn missing_transcript_path_allows_default() {
        // Policy set, but no transcript_path → resolved None → on_unknown default
        // allow: a missing transcript must never brick reads.
        with_env(&guard_env(Some("opus"), Some("deny"), None), || {
            let input = make_read("/tmp/secret", None);
            assert_eq!(GuardReadModel.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn unreadable_transcript_allows_default() {
        // transcript_path points at a nonexistent file → read fails → resolved
        // None → on_unknown default allow (fail-open).
        with_env(&guard_env(Some("opus"), Some("deny"), None), || {
            let input = make_read("/tmp/secret", Some("/no/such/transcript.jsonl"));
            assert_eq!(GuardReadModel.run(&input).outcome, Outcome::Allow);
        });
    }

    #[test]
    fn unknown_model_on_unknown_block_blocks_end_to_end() {
        // No assistant model in the transcript + on_unknown=block → BLOCK.
        with_env(
            &guard_env(Some("opus"), Some("deny"), Some("block")),
            || {
                let tmp = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(tmp.path(), r#"{"message":{"role":"user","content":"hi"}}"#)
                    .unwrap();
                let input = make_read("/tmp/secret", tmp.path().to_str());
                let result = GuardReadModel.run(&input);
                assert_eq!(result.outcome, Outcome::Block);
                assert!(
                    result
                        .message
                        .as_deref()
                        .unwrap_or_default()
                        .contains("unknown-block")
                );
            },
        );
    }
}
