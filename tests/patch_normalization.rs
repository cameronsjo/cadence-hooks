//! End-to-end coverage for `apply_patch` payload normalization.
//!
//! Renamed from `codex_coverage.rs` when the Codex harness adapters were retired
//! (#1040). The *harness detection* went — `is_codex_harness`, the payload sniff,
//! the `Ask`→`Block` conversion, and `dispatch`'s fail-closed arms — and the
//! tests that existed only to pin those went with it.
//!
//! `crates/core/src/patch.rs` stayed. It normalizes an `apply_patch` body into
//! one Claude-shaped input per target, which is what lets `prevent-secret-writes`,
//! `guard-dotfiles`, `guard-rm`, and `trash-guard` judge a patched file at all.
//! `patch.rs` has only 7 unit tests and none spawn the binary, so this file is
//! that path's sole end-to-end coverage — which is why it was split rather than
//! deleted with the rest.
//!
//! No test here sets `CADENCE_HARNESS`. The variable no longer changes any
//! verdict, and leaving it would have implied a posture that no longer exists.

use cadence_hooks_core::{HookInput, MetricsInput};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Spawn the built binary with its metrics root pinned to a throwaway dir.
///
/// Every spawned subcommand may append telemetry, and an unpinned run resolves
/// `metrics_dir()` to the *operator's real* ledger — creating it and writing
/// production-shaped rows there just for running the suite. Every other
/// integration test in this directory pins it; these must too.
fn isolated_cadence_hooks(metrics_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"));
    cmd.env("CADENCE_METRICS_DIR", metrics_dir);
    cmd
}

/// Spawn one hook subcommand with a payload on stdin, in a throwaway metrics
/// dir, and return `(exit code, stderr)`.
///
/// `env` is applied on top; `CADENCE_NO_FEEDBACK_FOOTER` is always set so
/// assertions read the guard's own text rather than the feedback footer.
fn run_hook(args: &[&str], env: &[(&str, &str)], payload: &str) -> (Option<i32>, String) {
    use std::io::Write;
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let markers = tempfile::tempdir().expect("temp marker dir");
    let mut cmd = isolated_cadence_hooks(metrics.path());
    cmd.args(args)
        .env("CADENCE_MARKER_DIR", markers.path())
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1");
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run hook");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `prevent-secret-writes` genuinely adapts to patches: a secret introduced by
/// an `apply_patch` `Add File` is blocked exactly as the plain `Write` is.
#[test]
fn patch_add_file_carrying_a_secret_is_blocked() {
    let secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let patch = format!("*** Begin Patch\n*** Add File: config.env\n+{secret}\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": "/private/tmp",
        "tool_input": {"command": patch},
    })
    .to_string();
    let (code, stderr) = run_hook(&["cadence", "prevent-secret-writes"], &[], &payload);
    assert_eq!(code, Some(2), "a patched-in secret must block: {stderr}");
    assert!(
        !stderr.contains("targets could not be enumerated"),
        "the guard, not patch normalization, must decide the block: {stderr}"
    );

    // Control: the same guard on the same content through a plain Write. If
    // this did not block, the assertion above would prove nothing about the
    // patch route.
    let write = serde_json::json!({
        "tool_name": "Write",
        "cwd": "/private/tmp",
        "tool_input": {"file_path": "config.env", "content": secret},
    })
    .to_string();
    let (code, _) = run_hook(&["cadence", "prevent-secret-writes"], &[], &write);
    assert_eq!(code, Some(2), "control: the plain Write must block too");
}

#[test]
fn adapter_wrapped_benign_patch_reaches_security_critical_guard() {
    let patch = "*** Begin Patch\n*** Add File: harmless.txt\n+ok\n*** End Patch";
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": "/private/tmp",
        "tool_input": {"input": patch},
    })
    .to_string();
    let (code, stderr) = run_hook(&["cadence", "prevent-secret-writes"], &[], &payload);
    assert_eq!(
        code,
        Some(0),
        "a benign patch must reach the guard: {stderr}"
    );
    assert!(
        stderr.is_empty(),
        "a benign patch must stay silent: {stderr}"
    );
}

/// `guard-dotfiles` sees a patch target: an `apply_patch` writing a managed
/// dotfile blocks, because normalization hands the guard a `file_path` it can
/// judge.
///
/// Unix-only, and deliberately so rather than for convenience. `judge_dotfile`
/// builds its comparison path with a forward slash (`{home}/{basename}`), while
/// `patch::clean_path` rewrites `\` to `/` on the way in — so on Windows the two
/// sides disagree (`C:\Users\x/.zshrc` vs `C:/Users/x/.zshrc`) and the guard
/// never matches. That asymmetry is real but out of scope here: the guard exists
/// for chezmoi-managed dotfiles (`~/.dotfiles/dot_zshrc`, `chezmoi apply`), a
/// workflow that does not run on Windows. Gating keeps this test honest about
/// what it covers instead of asserting a platform behaviour nobody ships.
#[test]
#[cfg(unix)]
fn patch_target_reaches_guard_dotfiles() {
    // Not `std::env::var("HOME")` — the guards resolve the home directory
    // through this helper, so the test asks the same way they do.
    let home = cadence_hooks_core::paths::user_home_lossy_or_default();
    let patch =
        format!("*** Begin Patch\n*** Update File: {home}/.zshrc\n@@\n-old\n+new\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": "/private/tmp",
        "tool_input": patch,
    })
    .to_string();
    let (code, stderr) = run_hook(
        &["guardrails", "guard-dotfiles"],
        &[("CADENCE_GUARD_DOTFILES", "1")],
        &payload,
    );
    assert_eq!(code, Some(2), "a patched dotfile must block: {stderr}");

    // Control: with the guard's opt-in unset, the same patch passes — so the
    // block above is guard-dotfiles deciding, not the patch route erroring.
    let (code, _) = run_hook(&["guardrails", "guard-dotfiles"], &[], &payload);
    assert_eq!(code, Some(0));
}

/// A Codex local function call traverses the common PreToolUse path and reaches
/// a security-critical guard — the `nested-function-calls` capability claim,
/// asserted against the binary rather than restated as prose.
#[test]
fn codex_local_function_call_reaches_a_security_critical_guard() {
    // Not `std::env::var("HOME")` — that is unset on Windows, where the home
    // directory comes from USERPROFILE. The guards resolve it through this
    // helper, so the test asks the same way they do.
    let home = cadence_hooks_core::paths::user_home_lossy_or_default();
    let payload = serde_json::json!({
        "tool_name": "exec_command",
        "cwd": "/private/tmp",
        "tool_input": {"cmd": format!("rm -rf {home}/Documents")},
    })
    .to_string();
    let (code, stderr) = run_hook(&["guardrails", "guard-rm"], &[], &payload);
    assert_eq!(
        code,
        Some(2),
        "a Codex local function call must reach guard-rm: {stderr}"
    );
    assert!(stderr.contains("guard-rm"));
}

/// `ObsidianTrashGuard`'s delete-detection branch, driven through the binary.
///
/// The guard's new `operation() == Some("delete")` arm was unit-tested only at
/// the `check_delete_in_vault` helper — the pre-existing-shaped half — so the
/// dispatch wiring this PR actually changed (a patch normalizing into an `Edit`
/// carrying `operation: "delete"`, reaching `run()`) was never exercised end to
/// end.
#[test]
fn patch_delete_inside_a_vault_reaches_the_trash_guard() {
    let vault = tempfile::tempdir().expect("temp vault");
    let vault_path = vault.path().to_string_lossy().into_owned();
    let patch =
        format!("*** Begin Patch\n*** Delete File: {vault_path}/notes/todo.md\n*** End Patch");
    let payload = serde_json::json!({
        "tool_name": "apply_patch",
        "cwd": &vault_path,
        "tool_input": patch,
    })
    .to_string();

    let (code, stderr) = run_hook(
        &["obsidian", "trash-guard"],
        &[("OBSIDIAN_VAULT", vault_path.as_str())],
        &payload,
    );
    assert_eq!(code, Some(2), "a patch delete in the vault must block");
    assert!(
        stderr.contains(".trash"),
        "block must point at the vault's trash: {stderr}"
    );

    // Control: the same patch with no vault configured passes, so the block
    // above is the vault check deciding rather than the route erroring.
    let (code, _) = run_hook(&["obsidian", "trash-guard"], &[], &payload);
    assert_eq!(code, Some(0));
}

#[test]
fn multi_file_patch_normalizes_all_targets() {
    let input = HookInput::from_json(
        r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\n*** Add File: one\n+x\n*** Delete File: two\n*** End Patch"}"#,
    )
    .unwrap();
    let paths = input
        .normalized_inputs()
        .unwrap()
        .into_iter()
        .filter_map(|item| item.file_path())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["one", "two"]);
}

#[test]
fn sandbox_fixture_identifies_symlink_and_traversal_escape_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, "protected").unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let workspace = fs::canonicalize(workspace).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).unwrap();

        // Canonicalized writes through a workspace symlink resolve outside the
        // allowed root. Windows runners do not create this Unix symlink.
        let symlink_target = fs::canonicalize(workspace.join("escape")).unwrap();
        assert!(!symlink_target.starts_with(&workspace));
    }

    // Lexical traversal resolves outside the allowed root on every platform.
    let traversal = fs::canonicalize(workspace.join("../outside")).unwrap();
    assert!(!traversal.starts_with(&workspace));
}

#[test]
fn paired_harness_fixtures_cover_and_normalize_every_route() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut expected_routes = None;
    for harness in ["claude", "codex"] {
        let fixture = fs::read_to_string(
            root.join("tests/fixtures/harness")
                .join(format!("{harness}.jsonl")),
        )
        .unwrap();
        let mut routes = Vec::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let route = row["route"].as_str().unwrap();
            routes.push(route.to_string());
            if route == "malformed" {
                assert!(HookInput::from_json(row["payloadRaw"].as_str().unwrap()).is_err());
                continue;
            }
            let raw = row["payload"].to_string();
            if route == "lifecycle-events" {
                let input = MetricsInput::from_json(&raw).unwrap();
                assert_eq!(input.hook_event_name.as_deref(), Some("SessionEnd"));
                continue;
            }
            let input = HookInput::from_json(&raw).unwrap();
            if harness == "codex" && matches!(route, "shell" | "unified-exec") {
                assert_eq!(input.normalized_tool_name(), Some("Bash"));
                assert!(input.command().is_some());
            }
            if harness == "codex" && route == "subagents" {
                assert_eq!(input.normalized_tool_name(), Some("Agent"));
            }
            if harness == "codex" && route == "mcp-filesystem-write" {
                assert_eq!(input.normalized_tool_name(), Some("Write"));
                assert_eq!(input.operation(), Some("create"));
            }
            if harness == "codex" && route == "mcp-functions" {
                assert_eq!(input.normalized_tool_name(), Some("Read"));
                assert_eq!(input.operation(), Some("read"));
            }
            if harness == "codex" && route == "apply-patch" {
                assert_eq!(input.normalized_inputs().unwrap().len(), 1);
            }
        }
        if let Some(expected) = &expected_routes {
            assert_eq!(&routes, expected);
        } else {
            expected_routes = Some(routes);
        }
    }
}

/// A malformed patch body blocks a security-critical hook, and is never echoed.
///
/// Inherited from `security_critical_malformed_patch_blocks_without_echoing_patch`.
/// The verdict looked Codex-specific and is not: the arm was armed by
/// `tool_name: "apply_patch"` itself, so it fired with no env var set. #1040
/// briefly turned it fail-open; the arm is now unconditional for
/// security-critical hooks, since `patch.rs` and its guards were retained.
#[test]
fn a_malformed_patch_body_blocks_and_is_never_echoed() {
    let payload = r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\nSECRET_VALUE\n*** End Patch"}"#;
    let (code, stderr) = run_hook(&["cadence", "prevent-secret-writes"], &[], payload);

    assert_eq!(
        code,
        Some(2),
        "an unenumerable patch on a security-critical hook must block: {stderr}"
    );
    assert!(
        stderr.contains("targets could not be enumerated"),
        "the diagnostic must name why normalization gave up: {stderr}"
    );
    assert!(
        !stderr.contains("SECRET_VALUE"),
        "the patch body must never be echoed: {stderr}"
    );

    // Control: the same unenumerable patch on a NON-security-critical hook
    // still fails open, so the block above is the criticality check deciding
    // rather than the patch route erroring for everyone.
    let (code, _) = run_hook(&["guardrails", "warn-cron-datetime"], &[], payload);
    assert_eq!(code, Some(0), "a non-critical hook still fails open");
}

/// Conflicting `apply_patch` bodies are rejected without echoing either one.
///
/// Inherited from `conflicting_patch_bodies_fail_closed_without_echoing_them`,
/// and asserting the same verdict for the reason given on the sibling above.
/// Both payload shapes are kept — a conflict nested inside `tool_input` and one
/// hoisted to the top level — because they reach the check by different paths.
#[test]
fn conflicting_patch_bodies_are_rejected_without_echoing_them() {
    let benign = "*** Begin Patch\n*** Add File: benign.txt\n+ok\n*** End Patch";
    let secret = "*** Begin Patch\n*** Add File: secret.env\n+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n*** End Patch";
    let payloads = [
        serde_json::json!({
            "tool_name": "apply_patch",
            "cwd": "/private/tmp",
            "tool_input": {"command": benign, "input": secret},
        }),
        serde_json::json!({
            "tool_name": "apply_patch",
            "cwd": "/private/tmp",
            "tool_input": {"command": benign},
            "input": secret,
        }),
    ];
    for payload in payloads {
        let (code, stderr) = run_hook(
            &["cadence", "prevent-secret-writes"],
            &[],
            &payload.to_string(),
        );
        assert_eq!(
            code,
            Some(2),
            "conflicting bodies block a security-critical hook: {stderr}"
        );
        assert!(
            stderr.contains("apply_patch payload contains conflicting patch bodies"),
            "the diagnostic must name the conflict: {stderr}"
        );
        assert!(!stderr.contains("benign.txt"), "{stderr}");
        assert!(!stderr.contains("secret.env"), "{stderr}");
        assert!(!stderr.contains("AKIAIOSFODNN7EXAMPLE"), "{stderr}");
    }
}
