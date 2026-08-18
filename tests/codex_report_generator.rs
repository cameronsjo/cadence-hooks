#![cfg(not(windows))]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_generator(workspace: &Path, output: Option<&Path>, args: &[&str]) -> Output {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join("scripts/generate-codex-report.py"))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_cadence-hooks"))
        .arg("--workspace")
        .arg(workspace)
        .env("CADENCE_METRICS_DIR", metrics.path());
    if let Some(path) = output {
        command.arg("--output").arg(path);
    }
    command.args(args).output().expect("run report generator")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn normal_write_refuses_empty_wiring_without_mutating_output() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace-without-plugins");
    let expected_plugins = workspace.join("cadence/plugins");

    let existing = temp.path().join("existing.json");
    fs::write(&existing, "sentinel\n").expect("write sentinel");
    let output = run_generator(&workspace, Some(&existing), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = stderr(&output);
    assert!(error.contains("no recognized plugin wiring rendered"));
    assert!(error.contains(&expected_plugins.display().to_string()));
    assert!(error.contains("--workspace"));
    assert!(!error.contains("commandHash"));
    assert!(!error.contains("run-cadence-hooks"));
    assert_eq!(fs::read_to_string(&existing).unwrap(), "sentinel\n");

    let absent = temp.path().join("new-parent/report.json");
    let output = run_generator(&workspace, Some(&absent), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!absent.parent().unwrap().exists());

    let zero_byte = temp.path().join("zero-byte.json");
    fs::File::create(&zero_byte).expect("create empty output");
    let output = run_generator(&workspace, Some(&zero_byte), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::metadata(&zero_byte).unwrap().len(), 0);
}

#[test]
fn normal_write_accepts_minimal_recognized_wiring() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    let hooks = workspace.join("cadence/plugins/cadence-guardrails/hooks");
    fs::create_dir_all(&hooks).expect("create plugin fixture");
    let fixture = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "^Edit$",
                "hooks": [{
                    "type": "command",
                    "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" guardrails guard-rm"
                }]
            }]
        }
    });
    fs::write(
        hooks.join("hooks.json"),
        serde_json::to_vec(&fixture).expect("serialize fixture"),
    )
    .expect("write plugin fixture");

    let report = temp.path().join("new-parent/report.json");
    let output = run_generator(&workspace, Some(&report), &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let generated: Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let guard_rm = generated["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hook| hook["name"] == "guard-rm")
        .expect("guard-rm row");
    assert_eq!(guard_rm["wiring"].as_array().unwrap().len(), 1);
}

#[test]
fn stdout_preserves_empty_wiring_for_inspection() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace-without-plugins");
    let ignored_output = temp.path().join("ignored/report.json");
    let output = run_generator(&workspace, Some(&ignored_output), &["--stdout"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!ignored_output.exists());
    let generated: Value = serde_json::from_slice(&output.stdout).expect("stdout report json");
    assert!(
        generated["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|hook| hook["wiring"].as_array().is_some_and(Vec::is_empty))
    );
}

#[test]
fn check_preserves_the_absent_workspace_exemption() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace-without-plugins");
    let checked_in = repo_root().join("docs/codex-compatibility-report.json");
    let output = run_generator(&workspace, Some(&checked_in), &["--check"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("wiring unverified: no plugin checkout beside this repo"));
}

fn write_two_plugin_fixture(workspace: &Path) {
    let guardrails_hooks = workspace.join("cadence/plugins/cadence-guardrails/hooks");
    fs::create_dir_all(&guardrails_hooks).expect("create guardrails plugin fixture");
    fs::write(
        guardrails_hooks.join("hooks.json"),
        serde_json::to_vec(&serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "^Bash$",
                    "hooks": [{
                        "type": "command",
                        "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" guardrails guard-rm"
                    }]
                }]
            }
        }))
        .expect("serialize guardrails fixture"),
    )
    .expect("write guardrails plugin fixture");

    let cadence_hooks = workspace.join("cadence/plugins/cadence/hooks");
    fs::create_dir_all(&cadence_hooks).expect("create cadence plugin fixture");
    fs::write(
        cadence_hooks.join("hooks.json"),
        serde_json::to_vec(&serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "^Write$",
                    "hooks": [{
                        "type": "command",
                        "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" cadence terminology"
                    }]
                }]
            }
        }))
        .expect("serialize cadence fixture"),
    )
    .expect("write cadence plugin fixture");
}

#[test]
fn normal_write_refuses_a_partial_wiring_wipe() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    write_two_plugin_fixture(&workspace);

    let report = temp.path().join("report.json");
    let baseline = run_generator(&workspace, Some(&report), &[]);
    assert!(baseline.status.success(), "{}", stderr(&baseline));
    let original_bytes = fs::read(&report).expect("read baseline report");

    // Drop one plugin's wiring entirely, then regenerate against the same
    // output — the guardrails plugin is now missing from the render while
    // the checked-in report still carries its wiring.
    fs::remove_dir_all(workspace.join("cadence/plugins/cadence-guardrails"))
        .expect("remove guardrails plugin dir");

    let output = run_generator(&workspace, Some(&report), &[]);
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("cadence-guardrails"));
    assert!(error.contains("--retired-plugin"));
    assert_eq!(
        fs::read(&report).expect("read report after refused write"),
        original_bytes,
        "refused write must not touch the output file"
    );
}

#[test]
fn normal_write_accepts_a_legitimate_wiring_edit() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    write_two_plugin_fixture(&workspace);

    let report = temp.path().join("report.json");
    let baseline = run_generator(&workspace, Some(&report), &[]);
    assert!(baseline.status.success(), "{}", stderr(&baseline));

    // Change the guardrails matcher without dropping the plugin's wiring
    // entirely — both plugins still carry wiring, so this is not a wipe.
    fs::write(
        workspace.join("cadence/plugins/cadence-guardrails/hooks/hooks.json"),
        serde_json::to_vec(&serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "^Edit$",
                    "hooks": [{
                        "type": "command",
                        "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" guardrails guard-rm"
                    }]
                }]
            }
        }))
        .expect("serialize edited guardrails fixture"),
    )
    .expect("rewrite guardrails plugin fixture");

    let output = run_generator(&workspace, Some(&report), &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let generated: Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let guard_rm = generated["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hook| hook["name"] == "guard-rm")
        .expect("guard-rm row");
    assert_eq!(guard_rm["wiring"][0]["matcher"].as_str().unwrap(), "^Edit$");
}

#[test]
fn retired_plugin_flag_permits_the_wipe_it_names() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    write_two_plugin_fixture(&workspace);

    let report = temp.path().join("report.json");
    let baseline = run_generator(&workspace, Some(&report), &[]);
    assert!(baseline.status.success(), "{}", stderr(&baseline));

    fs::remove_dir_all(workspace.join("cadence/plugins/cadence-guardrails"))
        .expect("remove guardrails plugin dir");

    let output = run_generator(
        &workspace,
        Some(&report),
        &["--retired-plugin", "cadence-guardrails"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let generated: Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let guard_rm = generated["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hook| hook["name"] == "guard-rm")
        .expect("guard-rm row");
    assert!(guard_rm["wiring"].as_array().unwrap().is_empty());
}

#[test]
fn malformed_plugin_input_does_not_echo_contents_or_mutate_output() {
    let temp = tempfile::tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    let hooks = workspace.join("cadence/plugins/example/hooks");
    fs::create_dir_all(&hooks).expect("create plugin fixture");
    let private_marker = "private-fixture-marker-566";
    fs::write(
        hooks.join("hooks.json"),
        format!("{{\"hooks\": {private_marker}"),
    )
    .expect("write malformed fixture");
    let report = temp.path().join("report.json");
    fs::write(&report, "sentinel\n").expect("write sentinel");

    let output = run_generator(&workspace, Some(&report), &[]);
    assert!(!output.status.success());
    assert!(!stderr(&output).contains(private_marker));
    assert_eq!(fs::read_to_string(&report).unwrap(), "sentinel\n");
}
