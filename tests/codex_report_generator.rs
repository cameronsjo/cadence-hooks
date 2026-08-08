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
