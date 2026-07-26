use cadence_hooks_core::{HookInput, MetricsInput};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn report() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(
        &fs::read(root.join("docs/codex-compatibility-report.json"))
            .expect("read checked-in compatibility report"),
    )
    .expect("report json")
}

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

fn live_manifest() -> Value {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = isolated_cadence_hooks(metrics.path())
        .args(["manifest", "--format", "json"])
        .output()
        .expect("generate live hook manifest");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).expect("manifest json")
}

#[test]
fn every_registered_hook_has_explicit_compatibility_and_evidence() {
    let value = report();
    let hooks = value["hooks"].as_array().expect("hooks");
    assert!(hooks.len() > 40);
    let report_names = hooks
        .iter()
        .map(|hook| hook["name"].as_str().expect("report hook name").to_string())
        .collect::<BTreeSet<_>>();
    let manifest_names = live_manifest()["hooks"]
        .as_array()
        .expect("manifest hooks")
        .iter()
        .map(|hook| {
            hook["name"]
                .as_str()
                .expect("manifest hook name")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        report_names, manifest_names,
        "checked-in compatibility report must match the live registry"
    );
    for hook in hooks {
        assert!(matches!(
            hook["status"].as_str(),
            Some("native" | "adapted" | "degraded" | "unavailable")
        ));
        assert!(
            hook["evidence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        if hook["status"] == "degraded" {
            assert_ne!(hook["criticality"], "security-critical");
        }
        if hook["applicable"] != false {
            assert!(
                hook["wiring"]
                    .as_array()
                    .is_some_and(|entries| !entries.is_empty()),
                "applicable hook lacks plugin wiring: {}",
                hook["name"]
            );
        }
        if hook["criticality"] == "security-critical" && hook["applicable"] != false {
            assert!(matches!(
                hook["status"].as_str(),
                Some("native" | "adapted")
            ));
        }
    }
}

#[test]
fn every_security_route_has_native_hook_or_sandbox_control() {
    let value = report();
    for capability in value["capabilities"].as_array().expect("capabilities") {
        if capability["criticality"] != "security-critical" || capability["applicable"] == false {
            continue;
        }
        assert!(matches!(
            capability["status"].as_str(),
            Some("native" | "adapted")
        ));
        assert!(
            capability["evidence"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }
}

#[test]
fn security_critical_malformed_patch_blocks_without_echoing_patch() {
    let payload = r#"{"tool_name":"apply_patch","tool_input":"*** Begin Patch\nSECRET_VALUE\n*** End Patch"}"#;
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = isolated_cadence_hooks(metrics.path())
        .args(["cadence", "prevent-secret-writes"])
        .env("CADENCE_HARNESS", "codex")
        .env("CADENCE_NO_FEEDBACK_FOOTER", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(payload.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run guard");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("targets could not be enumerated"));
    assert!(!stderr.contains("SECRET_VALUE"));
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
                assert_eq!(input.tool_name(), Some("Bash"));
                assert!(input.command().is_some());
            }
            if harness == "codex" && route == "subagents" {
                assert_eq!(input.tool_name(), Some("Agent"));
            }
            if harness == "codex" && route == "mcp-filesystem-write" {
                assert_eq!(input.tool_name(), Some("Write"));
                assert_eq!(input.operation(), Some("create"));
            }
            if harness == "codex" && route == "mcp-functions" {
                assert_eq!(input.tool_name(), Some("Read"));
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
