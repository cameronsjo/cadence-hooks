//! Shared helpers for the binary-level integration tests.
//!
//! Include with `mod support;` and build every child through
//! [`cadence_hooks`] rather than `Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))`.
//!
//! Why: the binary resolves `CLAUDE_CONFIG_DIR` (falling back to `~/.claude`)
//! for session-registry heartbeats, the metrics dir when `CADENCE_METRICS_DIR`
//! is unset, and so on. A helper that pins only `CADENCE_METRICS_DIR` still let
//! `persist-plan-approval` write `<config>/cadence/live-sessions/…` and a few
//! ledgers into the developer's real `~/.claude` on every `make ci`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// One fresh, per-test-binary config dir under cargo's target tmp dir (removed
/// and recreated on first use, so runs never accumulate state and `cargo clean`
/// reclaims it). A test that needs its own config dir overrides it with a later
/// `.env("CLAUDE_CONFIG_DIR", …)`, which wins over this default.
fn config_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let exe = std::env::current_exe().ok();
        let stem = exe
            .as_deref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "test".into());
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("claude-config-{stem}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the isolated CLAUDE_CONFIG_DIR");
        dir
    })
}

/// A `cadence-hooks` command that cannot reach the real `~/.claude`:
/// `CLAUDE_CONFIG_DIR` points at an isolated dir and an ambient
/// `CLAUDE_PROJECT_DIR` is dropped.
pub fn cadence_hooks() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env("CLAUDE_CONFIG_DIR", config_dir())
        .env_remove("CLAUDE_PROJECT_DIR")
        // A cloud session exports this; ambient, it would self-disable the hooks
        // these tests exercise (cadence-hooks#1197). Tests that want it set it.
        .env_remove("CLAUDE_CODE_REMOTE");
    cmd
}
