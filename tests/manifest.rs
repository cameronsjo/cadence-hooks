mod support;

use serde_json::Value;

#[test]
fn manifest_json_exports_complete_registry_and_criticality() {
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = support::cadence_hooks()
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
    // Security-critical but deliberately unprotected from CADENCE_DISABLE.
    let worktree = hooks
        .iter()
        .find(|row| row["name"] == "enforce-worktree")
        .expect("worktree guard");
    assert_eq!(worktree["criticality"], "security-critical");
    assert_eq!(worktree["protected"], false);
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
    // The value assertion is the other half: `session` hooks must report the
    // clap namespace `session`, not the `cadence` plugin that wires them.
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = support::cadence_hooks()
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
}

#[test]
fn manifest_lists_every_event_of_a_multi_event_hook() {
    // cameronsjo/cadence-hooks#957: `event` stays the primary (catalog_lib
    // joins on it); `events` is the additive full set, empty for a logger.
    let metrics = tempfile::tempdir().expect("temp metrics dir");
    let output = support::cadence_hooks()
        .env("CADENCE_METRICS_DIR", metrics.path())
        .args(["manifest", "--format", "json"])
        .output()
        .expect("run cadence-hooks manifest");
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let hooks = value["hooks"].as_array().expect("hooks array");
    let find = |name: &str| hooks.iter().find(|r| r["name"] == name).expect(name);
    let posture = find("model-posture");
    assert_eq!(posture["event"], "SessionStart");
    assert_eq!(
        posture["events"],
        serde_json::json!(["SessionStart", "PostModelSwitch"])
    );
    assert_eq!(
        find("terminology")["events"],
        serde_json::json!(["PreToolUse"])
    );
    assert_eq!(find("log-commit")["events"], serde_json::json!([]));
}

#[test]
fn list_shows_every_event_of_a_multi_event_hook() {
    let output = support::cadence_hooks()
        .arg("list")
        .output()
        .expect("run cadence-hooks list");
    let text = String::from_utf8_lossy(&output.stdout);
    let row = text
        .lines()
        .find(|l| l.trim_start().starts_with("model-posture"))
        .expect("model-posture row");
    assert!(row.contains("SessionStart,PostModelSwitch"), "{row}");
}
