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

/// Assert that `run(n)` costs time linear in `n`, for a flood test whose
/// property is "this input shape does not blow up".
///
/// An absolute wall-clock bound on a flood fails on a loaded runner with the
/// code behaving correctly: a 2.3 s run took 9.6 s on a busy CI box. The
/// ratio between two sizes measured in the same process does not, because
/// load slows both. `run` is timed at `size` and then at four times `size`,
/// and the fastest time seen at each size is compared: linear work takes
/// about 4x as long at the larger size, quadratic work about 16x, so a ratio
/// under [`LINEAR_RATIO_LIMIT`] passes. A round over it is measured again, up
/// to [`LINEAR_ROUNDS`] rounds, so a load burst that lands on one measurement
/// does not decide the verdict; a real quadratic stays over it every round.
///
/// Each larger run is also held to [`FLOOD_HANG_LIMIT`], a hang guard far
/// above a healthy run so runner load cannot trip it.
pub fn assert_scales_linearly(what: &str, size: usize, mut run: impl FnMut(usize)) {
    let mut timed = |n: usize| {
        let started = std::time::Instant::now();
        run(n);
        started.elapsed()
    };
    let mut small = std::time::Duration::MAX;
    let mut large = std::time::Duration::MAX;
    for _ in 0..LINEAR_ROUNDS {
        small = small.min(timed(size));
        let took = timed(4 * size);
        assert!(took < FLOOD_HANG_LIMIT, "{what}: {took:?} at {}", 4 * size);
        large = large.min(took);
        if large.as_secs_f64() < LINEAR_RATIO_LIMIT * small.as_secs_f64() {
            return;
        }
    }
    panic!(
        "{what}: {large:?} at {} vs {small:?} at {size} is over {LINEAR_RATIO_LIMIT}x \
         for 4x the input, so the work grows faster than linearly",
        4 * size
    );
}

/// The most a run at four times the size may cost relative to the base size
/// in [`assert_scales_linearly`]: about 4 is linear and about 16 quadratic.
pub const LINEAR_RATIO_LIMIT: f64 = 8.0;

/// Rounds [`assert_scales_linearly`] measures before it gives a verdict.
pub const LINEAR_ROUNDS: usize = 5;

/// Hang guard for one flood run in [`assert_scales_linearly`].
pub const FLOOD_HANG_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);
