use serde_json::Value;
use std::process::Command;

#[test]
fn manifest_json_exports_complete_registry_and_criticality() {
    let output = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .args(["manifest", "--format", "json"])
        .output()
        .expect("run cadence-hooks manifest");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(value["schemaVersion"], 1);
    let hooks = value["hooks"].as_array().expect("hooks array");
    assert!(hooks.len() > 40);
    let push = hooks
        .iter()
        .find(|row| row["name"] == "guard-push-remote")
        .expect("push guard");
    assert_eq!(push["criticality"], "security-critical");
    assert_eq!(push["protected"], true);
    let rm = hooks
        .iter()
        .find(|row| row["name"] == "guard-rm")
        .expect("rm guard");
    assert_eq!(rm["criticality"], "security-critical");
    assert_eq!(rm["protected"], false);
    assert!(hooks.iter().all(|row| {
        row["plugin"].is_string() && row["event"].is_string() && row["criticality"].is_string()
    }));
}
