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

/// Whether load-sensitive timing assertions were explicitly requested.
/// Set `CADENCE_TIMING_TESTS=1` for release tests with one test thread.
/// Semantic assertions must run regardless of this setting.
pub fn timing_tests_enabled() -> bool {
    timing_opt_in(std::env::var_os("CADENCE_TIMING_TESTS").as_deref())
}

fn timing_opt_in(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

/// Check an unchanged wall-clock budget only when timing tests are opted in.
#[track_caller]
pub fn assert_elapsed_under(what: &str, elapsed: std::time::Duration, limit: std::time::Duration) {
    assert_elapsed_under_if(
        timing_tests_enabled(),
        what,
        elapsed,
        platform_limit(cfg!(windows), limit),
    );
}

/// Sub-second budgets get this multiple on Windows. Three GitHub-hosted
/// `windows-latest` release runs (cadence-hooks#1416) overran the 500 ms
/// budgets by up to 1.42x (710 ms worst; process spawn and filesystem calls
/// cost more there), so 3x leaves about 2x headroom over the worst sample.
const WINDOWS_SUBSECOND_FACTOR: u32 = 3;

/// Budgets of a second or more guard against a hang or a hook deadline, which
/// platform speed does not move, so they stay as written.
fn platform_limit(windows: bool, limit: std::time::Duration) -> std::time::Duration {
    if windows && limit < std::time::Duration::from_secs(1) {
        limit * WINDOWS_SUBSECOND_FACTOR
    } else {
        limit
    }
}

#[track_caller]
fn assert_elapsed_under_if(
    enabled: bool,
    what: &str,
    elapsed: std::time::Duration,
    limit: std::time::Duration,
) {
    if enabled {
        assert!(
            elapsed < limit,
            "{what}: {elapsed:?} exceeded budget {limit:?} (after any platform scaling)"
        );
    }
}

/// Assert a hook that fails open at `deadline` blocked (exit 2) in time.
///
/// Past the deadline the hook exits 0 by design, so an exit-2 assert on such a
/// run is a wall-clock assert in disguise. Without [`timing_tests_enabled`], a
/// fail-open (exit 0) that took at least `deadline` is load, not a regression,
/// and passes; a crash or other exit code never does; any non-block that finished sooner still fails, as does every
/// non-block when timing is opted in.
#[track_caller]
pub fn assert_blocked_before_deadline(
    what: &str,
    code: Option<i32>,
    took: std::time::Duration,
    deadline: std::time::Duration,
) {
    assert_blocked_before_deadline_if(timing_tests_enabled(), what, code, took, deadline);
}

#[track_caller]
fn assert_blocked_before_deadline_if(
    enabled: bool,
    what: &str,
    code: Option<i32>,
    took: std::time::Duration,
    deadline: std::time::Duration,
) {
    if code == Some(2) || (!enabled && code == Some(0) && took >= deadline) {
        return;
    }
    panic!("{what}: exit {code:?} after {took:?}, expected a block (exit 2) before {deadline:?}");
}

/// Run flood semantics at `size` and four times `size`, and optionally assert
/// that `run(n)` costs time linear in `n`.
///
/// Without [`timing_tests_enabled`], both sizes still run once so assertions
/// inside `run` retain coverage of the original maximum input. With timing
/// enabled, compare the fastest time seen at each size: linear work takes
/// about 4x as long, quadratic work about 16x, so a ratio under
/// [`LINEAR_RATIO_LIMIT`] passes. Retry up to [`LINEAR_ROUNDS`] rounds to reduce
/// sensitivity to load bursts. Ratios still depend on scheduling; opt in using
/// release mode and one test thread on a machine without competing heavy work.
///
/// When opted in, each larger run also retains [`FLOOD_HANG_LIMIT`].
pub fn assert_scales_linearly(what: &str, size: usize, mut run: impl FnMut(usize)) {
    assert_scales_linearly_with_timing(what, size, timing_tests_enabled(), |n| {
        let started = std::time::Instant::now();
        run(n);
        started.elapsed()
    });
}

fn assert_scales_linearly_with_timing(
    what: &str,
    size: usize,
    enabled: bool,
    mut timed: impl FnMut(usize) -> std::time::Duration,
) {
    if !enabled {
        timed(size);
        timed(4 * size);
        return;
    }
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

#[cfg(test)]
mod timing_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::time::Duration;

    #[test]
    fn only_one_explicitly_enables_timing() {
        assert!(!timing_opt_in(None));
        for value in ["", "0", "true", "yes", "01", " 1"] {
            assert!(!timing_opt_in(Some(OsStr::new(value))), "{value:?}");
        }
        assert!(timing_opt_in(Some(OsStr::new("1"))));
    }

    #[test]
    fn elapsed_budget_is_not_enforced_by_default() {
        assert_elapsed_under_if(
            false,
            "loaded runner",
            Duration::MAX,
            Duration::from_secs(5),
        );
    }

    #[test]
    fn public_elapsed_budget_obeys_the_process_opt_in() {
        let result = std::panic::catch_unwind(|| {
            assert_elapsed_under("public gate", Duration::MAX, Duration::from_secs(5));
        });
        assert_eq!(result.is_err(), timing_tests_enabled());
    }

    #[test]
    fn opted_in_elapsed_budget_accepts_time_below_limit() {
        assert_elapsed_under_if(
            true,
            "fast",
            Duration::from_millis(4999),
            Duration::from_secs(5),
        );
    }

    #[test]
    #[should_panic(expected = "exceeded budget")]
    fn opted_in_elapsed_budget_rejects_the_boundary() {
        assert_elapsed_under_if(true, "slow", Duration::from_secs(5), Duration::from_secs(5));
    }

    #[test]
    fn windows_widens_only_subsecond_budgets() {
        let ms = Duration::from_millis;
        assert_eq!(platform_limit(true, ms(500)), ms(1500));
        assert_eq!(
            platform_limit(true, Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            platform_limit(true, Duration::from_secs(4)),
            Duration::from_secs(4)
        );
        assert_eq!(platform_limit(false, ms(500)), ms(500));
    }

    #[test]
    fn a_block_passes_at_any_speed() {
        for enabled in [false, true] {
            assert_blocked_before_deadline_if(
                enabled,
                "block",
                Some(2),
                Duration::MAX,
                Duration::from_secs(4),
            );
        }
    }

    #[test]
    fn a_fail_open_past_the_deadline_is_load_unless_timing_is_opted_in() {
        let (took, deadline) = (Duration::from_secs(5), Duration::from_secs(4));
        assert_blocked_before_deadline_if(false, "loaded", Some(0), took, deadline);
        let strict = std::panic::catch_unwind(|| {
            assert_blocked_before_deadline_if(true, "loaded", Some(0), took, deadline)
        });
        assert!(strict.is_err());
    }

    #[test]
    fn a_crash_past_the_deadline_is_not_load() {
        for code in [Some(1), None] {
            let r = std::panic::catch_unwind(|| {
                assert_blocked_before_deadline_if(
                    false,
                    "crash",
                    code,
                    Duration::from_secs(5),
                    Duration::from_secs(4),
                )
            });
            assert!(r.is_err(), "{code:?}");
        }
    }

    #[test]
    #[should_panic(expected = "expected a block")]
    fn a_fast_non_block_is_a_real_failure() {
        assert_blocked_before_deadline_if(
            false,
            "fast",
            Some(0),
            Duration::from_millis(50),
            Duration::from_secs(4),
        );
    }

    #[test]
    fn default_scaling_runs_both_sizes_without_judging_time() {
        let mut sizes = Vec::new();
        assert_scales_linearly_with_timing("loaded runner", 7, false, |n| {
            sizes.push(n);
            Duration::MAX
        });
        assert_eq!(sizes, [7, 28]);
    }

    #[test]
    #[should_panic(expected = "large input semantic assertion")]
    fn default_scaling_keeps_large_input_assertions() {
        assert_scales_linearly_with_timing("semantics", 7, false, |n| {
            assert_ne!(n, 28, "large input semantic assertion");
            Duration::ZERO
        });
    }

    #[test]
    fn opted_in_scaling_accepts_linear_work() {
        assert_scales_linearly_with_timing("linear", 10, true, |n| Duration::from_millis(n as u64));
    }

    #[test]
    #[should_panic(expected = "work grows faster than linearly")]
    fn opted_in_scaling_rejects_quadratic_work() {
        assert_scales_linearly_with_timing("quadratic", 10, true, |n| {
            Duration::from_millis((n * n) as u64)
        });
    }

    #[test]
    #[should_panic(expected = "hang: 120s at 40")]
    fn opted_in_scaling_keeps_the_hang_budget() {
        assert_scales_linearly_with_timing("hang", 10, true, |_| FLOOD_HANG_LIMIT);
    }
}
