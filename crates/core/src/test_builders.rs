//! Shared test builders for constructing [`HookInput`] values.
//!
//! Gated behind the `test-builders` feature. Add to downstream crates:
//! ```toml
//! [dev-dependencies]
//! cadence-hooks-core = { workspace = true, features = ["test-builders"] }
//! ```
//!
//! Also compiled for this crate's own `#[cfg(test)]` modules without the
//! feature, so [`with_marker_dir`] can be the single marker-dir env helper
//! everywhere — including `markers.rs`'s own tests (#446).

use crate::{EditOperation, HookInput, ToolInput, ToolResponse};
use std::path::Path;

/// The single mutex serializing every test that mutates a process-global env
/// var read by the marker family.
///
/// Test helpers that lock a process-global must be the *only* helper locking it
/// — two uncoordinated mutexes over one global are a race no critical section
/// can fix (#446). Every crate's marker-dir sandboxing goes through
/// [`with_marker_dir`], never a locally-minted sibling lock.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with `CADENCE_MARKER_DIR` set to `dir`, serialized against every
/// other marker-dir-mutating test in the same test binary via [`ENV_LOCK`] —
/// keeps marker-writing tests out of the real per-user production marker
/// directory (#302) and off each other's state (#369).
///
/// **Panic-safe, and restores rather than clears.** A failing wrapped test
/// unwinds, so a bare `set_var` … `f()` … `remove_var` sequence would skip the
/// restore and leak `CADENCE_MARKER_DIR` into every test that ran afterward in
/// the same binary — one red test silently redirecting the rest. `f` therefore
/// runs under `catch_unwind` with the panic resumed after cleanup, and the
/// *prior* value is put back (not merely removed), so a nested or outer
/// override survives. Returning `T` lets a caller pass a value out of the
/// critical section instead of smuggling it through a captured `Cell`.
pub fn with_marker_dir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prior = std::env::var("CADENCE_MARKER_DIR").ok();
    // SAFETY: serialized against every other env-mutating test in this binary
    // via ENV_LOCK; restored below on both the normal and unwinding exit.
    unsafe {
        std::env::set_var("CADENCE_MARKER_DIR", dir);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    // SAFETY: the same lock is still held; this restores the prior state.
    unsafe {
        match prior {
            Some(v) => std::env::set_var("CADENCE_MARKER_DIR", v),
            None => std::env::remove_var("CADENCE_MARKER_DIR"),
        }
    }
    result.unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// Build a `HookInput` for a `Bash` tool invocation.
pub fn make_bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            command: Some(cmd.into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `Bash` tool invocation with a working directory.
pub fn make_bash_with_cwd(cmd: &str, cwd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            command: Some(cmd.into()),
            ..Default::default()
        }),
        cwd: Some(cwd.into()),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `Write` tool invocation.
pub fn make_write(path: &str, content: &str) -> HookInput {
    HookInput {
        tool_name: Some("Write".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            content: Some(content.into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build a `HookInput` for an `Edit` tool invocation.
pub fn make_edit(path: &str, old_string: &str, new_string: &str) -> HookInput {
    HookInput {
        tool_name: Some("Edit".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            old_string: Some(old_string.into()),
            new_string: Some(new_string.into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `MultiEdit` tool invocation.
///
/// Each `(old_string, new_string)` pair becomes one edit operation,
/// applied in order.
pub fn make_multi_edit(path: &str, edits: &[(&str, &str)]) -> HookInput {
    HookInput {
        tool_name: Some("MultiEdit".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            edits: Some(
                edits
                    .iter()
                    .map(|(old, new)| EditOperation {
                        old_string: Some((*old).into()),
                        new_string: Some((*new).into()),
                        replace_all: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build a `HookInput` for a PostToolUse `Bash` invocation with a tool response stdout.
///
/// Used to test PostToolUse checks that inspect the command's output (e.g.
/// `verify-pr-autoclose` which reads the PR URL from `gh pr create` stdout).
pub fn make_bash_post_tool_use(cmd: &str, stdout: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            command: Some(cmd.into()),
            ..Default::default()
        }),
        tool_response: Some(ToolResponse {
            stdout: Some(stdout.into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build a `HookInput` for an `Agent` (subagent dispatch) tool invocation.
///
/// `subagent_type` and `isolation` mirror the Agent tool's input keys — pass
/// `None` to model an omitted field (a fork-yourself dispatch omits
/// `subagent_type`; a no-isolation dispatch omits `isolation`). `cwd` is the
/// spawning session's working directory, which `warn-subagent-worktree`
/// resolves the checkout from.
pub fn make_agent(subagent_type: Option<&str>, isolation: Option<&str>, cwd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Agent".into()),
        tool_input: Some(ToolInput {
            subagent_type: subagent_type.map(Into::into),
            isolation: isolation.map(Into::into),
            ..Default::default()
        }),
        cwd: Some(cwd.into()),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `Read` tool invocation, optionally carrying the
/// session `transcript_path` the read-model guard resolves the model from.
pub fn make_read(path: &str, transcript_path: Option<&str>) -> HookInput {
    HookInput {
        tool_name: Some("Read".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            ..Default::default()
        }),
        transcript_path: transcript_path.map(Into::into),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `Grep` tool invocation, optionally carrying the
/// session `transcript_path`.
///
/// Grep's `pattern` has no dedicated `ToolInput` field, and the read-model guard
/// branches only on `tool_name` + `transcript_path` (never on tool-input
/// content), so the pattern rides in `command` purely to preserve the caller's
/// value.
pub fn make_grep(pattern: &str, transcript_path: Option<&str>) -> HookInput {
    HookInput {
        tool_name: Some("Grep".into()),
        tool_input: Some(ToolInput {
            command: Some(pattern.into()),
            ..Default::default()
        }),
        transcript_path: transcript_path.map(Into::into),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `SessionStart` event with the given session id and
/// source (`startup` | `resume` | `clear` | `compact`).
pub fn make_session(session_id: &str, source: &str) -> HookInput {
    HookInput {
        session_id: Some(session_id.into()),
        source: Some(source.into()),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `SessionStart` event that also carries a
/// transcript path — for checks (like `platform-drift`) that resolve state
/// from the transcript rather than live git/registry state.
pub fn make_session_with_transcript(
    session_id: &str,
    source: &str,
    transcript_path: &str,
) -> HookInput {
    HookInput {
        session_id: Some(session_id.into()),
        source: Some(source.into()),
        transcript_path: Some(transcript_path.into()),
        ..Default::default()
    }
}

/// Build a `HookInput` for a `UserPromptSubmit` event.
pub fn make_user_prompt_submit(
    session_id: &str,
    prompt: &str,
    cwd: &str,
    transcript_path: &str,
) -> HookInput {
    HookInput {
        session_id: Some(session_id.into()),
        prompt: Some(prompt.into()),
        cwd: Some(cwd.into()),
        transcript_path: Some(transcript_path.into()),
        ..Default::default()
    }
}

// Git-fixture builders (`Scratch`, `git_in`, `init_repo`) live in the sibling
// `git_fixtures` module — see there.
