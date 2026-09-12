use serde_json::Value;
use std::process::Command;

#[test]
fn manifest_json_exports_complete_registry_and_criticality() {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .env("CADENCE_METRICS_DIR", metrics.path())
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

#[test]
fn manifest_keeps_the_plugin_key_and_fills_it_with_the_clap_namespace() {
    // The emitted key stays `plugin` because the cadence monorepo's
    // `scripts/catalog_lib.py` joins its vendored manifest snapshot on
    // `(plugin, name)` — renaming it there is a cross-repo break, not a
    // cosmetic one. cadence-hooks#884 renamed the Rust field to `namespace`
    // (which is what it always held); this pins the wire name against a
    // follow-up rename carrying through to the JSON.
    //
    // The value assertions are the other half: `session` hooks must report the
    // clap namespace `session`, not the `cadence` plugin that wires them, and
    // no row may report a retired plugin name.
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
        .env("CADENCE_METRICS_DIR", metrics.path())
        .args(["manifest", "--format", "json"])
        .output()
        .expect("run cadence-hooks manifest");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let hooks = value["hooks"].as_array().expect("hooks array");

    let start = hooks
        .iter()
        .find(|row| row["name"] == "start")
        .expect("session start registered");
    assert_eq!(
        start["plugin"], "session",
        "`session start` reports its clap namespace; the cadence plugin wires it"
    );

    const CLAP_NAMESPACES: [&str; 6] = [
        "cadence",
        "guardrails",
        "rules",
        "obsidian",
        "metrics",
        "session",
    ];
    for row in hooks {
        let ns = row["plugin"].as_str().expect("namespace string");
        assert!(
            CLAP_NAMESPACES.contains(&ns),
            "hook '{}' reports namespace '{ns}', which the binary dispatches \
             nothing under — a selection on it would silently match zero hooks",
            row["name"]
        );
    }
}
