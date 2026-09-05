//! End-to-end: the shipped binary's env-file block text, with `forgectl`
//! removed from the child's `PATH`.
//!
//! The unit tests inject a `detect` stub, so they prove the branch logic but
//! say nothing about the real probe. This spawns the actual binary with a
//! `PATH` of `/usr/bin:/bin` — set on the child `Command` only, never through
//! `std::env::set_var`, which is process-global and races every other test in
//! this binary (the `ENV_LOCK` lesson in this repo's CLAUDE.md).
//!
//! The expected string is HARDCODED here. Importing it from the crate would
//! make this test agree with whatever the constant became.

use std::io::Write;
use std::process::{Command, Stdio};

/// The block text a machine without `forgectl` must still see, byte for byte.
const TODAYS_WRITE_BLOCK: &str = "🚫 BLOCKED: '.env' is a protected file (secrets/credentials). Modify manually outside Claude Code.";

fn run_guard(subcommand: &str, payload: &str, path: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["cadence", subcommand])
        .env("PATH", path)
        // Both confounds this repo documents: an ambient `CADENCE_DISABLE`
        // turns a block into a pass, and `CADENCE_ALLOW_MAIN` exempts
        // unrelated guards. Neither may reach the child.
        .env_remove("CADENCE_DISABLE")
        .env_remove("CADENCE_ALLOW_MAIN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary must be built — `cargo test` alone does not build it");

    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(payload.as_bytes())
        .expect("write payload");

    let out = child.wait_with_output().expect("guard exits");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn an_env_write_block_without_forgectl_keeps_todays_text_and_exit_2() {
    let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":".env","old_string":"a","new_string":"b"}}"#;
    let (code, stderr) = run_guard("prevent-secret-writes", payload, "/usr/bin:/bin");

    assert_eq!(code, 2, "a block is exit 2; stderr was: {stderr}");
    assert!(
        stderr.contains(TODAYS_WRITE_BLOCK),
        "today's text must survive verbatim: {stderr}"
    );
    assert!(
        !stderr.contains("forgectl"),
        "no forgectl on PATH means no forgectl in the message: {stderr}"
    );
}

#[test]
fn a_path_free_environment_still_blocks() {
    // The fail-open-detection arm: an empty PATH cannot resolve anything, and
    // the guard must still deliver its block rather than erroring out.
    let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":".env","old_string":"a","new_string":"b"}}"#;
    let (code, stderr) = run_guard("prevent-secret-writes", payload, "");

    assert_eq!(code, 2, "stderr was: {stderr}");
    assert!(stderr.contains(TODAYS_WRITE_BLOCK), "{stderr}");
    assert!(!stderr.contains("forgectl"), "{stderr}");
}

#[test]
fn a_path_qualified_forgectl_read_blocks() {
    // The B0 hardening, end to end through the shipped dispatch. This exited
    // 0 on 0.89.0.
    let payload =
        r#"{"tool_name":"Bash","tool_input":{"command":"./forgectl env keys --file .env"}}"#;
    let (code, stderr) = run_guard("prevent-secret-leaks", payload, "/usr/bin:/bin");

    assert_eq!(code, 2, "stderr was: {stderr}");
    assert!(
        stderr.contains("prevent-secret-leaks"),
        "the leaks guard owns this shape: {stderr}"
    );
}

#[test]
fn a_real_forgectl_on_path_produces_the_hint() {
    // The other tests here only exercise the PATH-WITHOUT-forgectl arm, and
    // every "hint appears" assertion elsewhere injects a stub detector. Without
    // this, a broken real probe — a failed thread spawn, a PATH-walk
    // regression, an executable-bit check that stopped working — would be
    // silent in CI, and the absent-arm tests above would still pass.
    let dir = tempfile::tempdir().expect("temp dir");
    let fake = dir.path().join("forgectl");
    std::fs::write(&fake, "#!/bin/sh\nexit 0\n").expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");
    }

    // `join_paths`, not a hardcoded `:` — Windows separates PATH entries with
    // `;`, so a colon-joined string arrives there as one nonexistent directory
    // and the probe correctly finds nothing, which reads as a broken guard.
    let joined = std::env::join_paths([dir.path()]).expect("join PATH");
    let path = joined.to_str().expect("PATH is utf-8").to_string();
    let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":".env","old_string":"a","new_string":"b"}}"#;
    let (code, stderr) = run_guard("prevent-secret-writes", payload, &path);

    assert_eq!(code, 2, "the outcome is unchanged by detection: {stderr}");
    assert!(
        stderr.contains(TODAYS_WRITE_BLOCK),
        "the original text is appended to, never replaced: {stderr}"
    );
    assert!(
        stderr.contains("Or: forgectl env set <KEY> --file .env "),
        "a real forgectl on PATH must produce the hint: {stderr}"
    );
}

#[test]
fn a_non_executable_forgectl_on_path_produces_no_hint() {
    // The executable-bit half of the probe, end to end: a mode-644 file the
    // shell could not run must not count as installed.
    let dir = tempfile::tempdir().expect("temp dir");
    let fake = dir.path().join("forgectl");
    std::fs::write(&fake, "#!/bin/sh\nexit 0\n").expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o644))
            .expect("chmod stub");
    }

    // `join_paths`, not a hardcoded `:` — Windows separates PATH entries with
    // `;`, so a colon-joined string arrives there as one nonexistent directory
    // and the probe correctly finds nothing, which reads as a broken guard.
    let joined = std::env::join_paths([dir.path()]).expect("join PATH");
    let path = joined.to_str().expect("PATH is utf-8").to_string();
    let payload = r#"{"tool_name":"Edit","tool_input":{"file_path":".env","old_string":"a","new_string":"b"}}"#;
    let (code, stderr) = run_guard("prevent-secret-writes", payload, &path);

    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains(TODAYS_WRITE_BLOCK), "{stderr}");
    #[cfg(unix)]
    assert!(
        !stderr.contains("forgectl"),
        "a non-executable file is not an installed CLI: {stderr}"
    );
}

#[test]
fn the_bare_forgectl_reader_is_still_allowed() {
    // Control: without this, the test above would pass on a guard that had
    // simply stopped exempting anything at all.
    let payload =
        r#"{"tool_name":"Bash","tool_input":{"command":"forgectl env keys --file .env"}}"#;
    let (code, stderr) = run_guard("prevent-secret-leaks", payload, "/usr/bin:/bin");

    assert_eq!(code, 0, "the bare spelling stays exempt; stderr: {stderr}");
}
