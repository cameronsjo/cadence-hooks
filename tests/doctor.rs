//! Integration tests for `cadence-hooks doctor`.
//!
//! Build a fixture plugin cache in a tempdir, point doctor at it via
//! `--root`, and assert exit code + stderr/stdout content.

use std::process::Command;
use std::time::{Duration, SystemTime};

fn cadence_hooks() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cadence-hooks"))
}

/// A HOME tempdir carrying an empty plugin cache, so the default (no-`--root`)
/// doctor scan finds zero hooks.json findings and only the telemetry-staleness
/// check can move the exit code.
fn home_with_empty_cache() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude/plugins/cache")).unwrap();
    home
}

/// A doctor command whose default scan is pinned to `home`. Removing
/// `CLAUDE_CONFIG_DIR` is load-bearing: `plugins_dir()` prefers
/// `<CLAUDE_CONFIG_DIR>/plugins` over `$HOME/.claude/plugins`, so an ambient
/// (absolute) value silently bypasses the HOME override and scans the live
/// machine. Metrics is pinned for the same reason — its default resolves
/// through the same config dir.
///
/// Every default-scan test routes through here, so the isolation is total and
/// greppable rather than per-test discipline.
fn doctor_in_home(home: &std::path::Path, metrics: &std::path::Path) -> Command {
    let mut cmd = cadence_hooks();
    cmd.arg("doctor")
        .env("HOME", home)
        .env("CADENCE_METRICS_DIR", metrics)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CADENCE_METRICS_STALE_DAYS");
    cmd
}

/// Create `<root>/<plugin>/hooks/hooks.json` with the given JSON body.
fn write_plugin(root: &std::path::Path, plugin: &str, hooks_json: &str) {
    let dir = root.join(plugin).join("hooks");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hooks.json"), hooks_json).unwrap();
}

/// Create a hooks.json at the REAL Claude Code cache depth:
/// `<root>/<marketplace>/<plugin>/<sha>/hooks/hooks.json`.
fn write_cached_plugin(
    root: &std::path::Path,
    marketplace: &str,
    plugin: &str,
    sha: &str,
    hooks_json: &str,
) {
    let dir = root.join(marketplace).join(plugin).join(sha).join("hooks");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hooks.json"), hooks_json).unwrap();
}

const BUGGY_HOOKS_JSON: &str = r#"{
    "hooks": {
        "PreToolUse": [{
            "hooks": [{ "command": "'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg" }]
        }]
    }
}"#;

// Version-skew fixture: references a subcommand this binary doesn't have.
const SKEW_HOOKS_JSON: &str = r#"{
    "hooks": {
        "PreToolUse": [{
            "hooks": [{ "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" guardrails hook-from-the-future" }]
        }]
    }
}"#;

// ── Real cache layout (marketplace/plugin/sha/hooks/hooks.json) ────────────
//
// The live Claude Code cache nests three levels deep. A doctor that only
// scans <root>/<entry>/hooks/hooks.json reports "clean" against the real
// cache no matter what's in it — the tool's primary invocation is a no-op.

#[test]
fn doctor_scans_real_cache_layout() {
    let tmp = tempfile::tempdir().unwrap();
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "buggy-plugin",
        "ea2f0e05b78d",
        BUGGY_HOOKS_JSON,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "doctor must find the shell-expansion bug at real cache depth.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn doctor_labels_finding_with_plugin_name_not_sha() {
    let tmp = tempfile::tempdir().unwrap();
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "buggy-plugin",
        "ea2f0e05b78d",
        BUGGY_HOOKS_JSON,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("buggy-plugin"),
        "finding label must include the plugin name, not just the SHA dir: {stdout}"
    );
}

// ── Exit-code contract ──────────────────────────────────────────────────────

#[test]
fn doctor_nonexistent_root_exits_two() {
    // A wrong --root is a configuration error. Exit 0 here would let a
    // misconfigured CI gate pass everything forever.
    let output = cadence_hooks()
        .args(["doctor", "--root", "/nonexistent/path/that/cannot/exist"])
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "missing scan root must exit 2 (config error), not 0.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── CADENCE_BYPASS must not silence the doctor ─────────────────────────────

#[test]
fn doctor_runs_under_cadence_bypass() {
    // CADENCE_BYPASS=1 bypasses *enforcement* hooks. Doctor is a diagnostic,
    // not an enforcement path — bypassing it produces false-clean CI runs.
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(tmp.path(), "buggy-plugin", BUGGY_HOOKS_JSON);

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .env("CADENCE_BYPASS", "1")
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "doctor must scan even under CADENCE_BYPASS=1.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── --quiet stdout contract (SessionStart preflight depends on it) ─────────

#[test]
fn doctor_quiet_warnings_print_summary_to_stdout() {
    // The README's SessionStart preflight wiring captures stdout as the skew
    // nudge. Warnings-only in quiet mode MUST emit a non-empty stdout line
    // and exit 0.
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(tmp.path(), "skewed-plugin", SKEW_HOOKS_JSON);

    let output = cadence_hooks()
        .args(["doctor", "--quiet", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "warnings-only in quiet mode exits 0.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "quiet mode with warnings must print a one-line summary to stdout"
    );
    assert!(
        stdout.contains("warning"),
        "summary should describe the plugin warning(s): {stdout}"
    );
}

#[test]
fn doctor_quiet_clean_prints_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "clean-plugin",
        r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "command": "\"${X}\" arg" }]}] }}"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--quiet", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "quiet + clean must print nothing: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn doctor_clean_cache_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "clean-plugin",
        r#"{
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{ "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh\" arg" }]
                }]
            }
        }"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("clean"),
        "expected clean output, got: {stdout}"
    );
}

#[test]
fn doctor_detects_single_quoted_plugin_root() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "buggy-plugin",
        r#"{
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{ "command": "'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg" }]
                }]
            }
        }"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "should exit 2 when shell-expansion errors found. stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("buggy-plugin"),
        "should name the plugin: {stdout}"
    );
    assert!(
        stdout.contains("CLAUDE_PLUGIN_ROOT"),
        "should quote the offending snippet: {stdout}"
    );
    assert!(
        stdout.contains("single-quoted env var"),
        "should explain the diagnosis: {stdout}"
    );
}

#[test]
fn doctor_handles_empty_root_directory() {
    // No plugin subdirs at all — exit 0 with the clean message.
    let tmp = tempfile::tempdir().unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_skips_plugins_without_hooks_json() {
    // Plugin dir exists but has no hooks/hooks.json — doctor just ignores it.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("plugin-without-hooks")).unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_skips_invalid_json() {
    // Garbage JSON shouldn't crash doctor — the plugin loader is the right
    // place to surface JSON syntax errors.
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(tmp.path(), "broken-plugin", "{ not valid json");

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn doctor_finds_violation_across_multiple_plugins() {
    let tmp = tempfile::tempdir().unwrap();
    write_plugin(
        tmp.path(),
        "clean-plugin",
        r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "command": "\"${X}\"" }]}] }}"#,
    );
    write_plugin(
        tmp.path(),
        "buggy-plugin-a",
        r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "command": "'${A}'" }]}] }}"#,
    );
    write_plugin(
        tmp.path(),
        "buggy-plugin-b",
        r#"{ "hooks": { "PostToolUse": [{ "hooks": [{ "command": "'$B'" }]}] }}"#,
    );

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    // Shell-expansion bugs are Severity::Error → exit 2.
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("buggy-plugin-a"));
    assert!(stdout.contains("buggy-plugin-b"));
    assert!(stdout.contains("2 finding"));
}

// ── Manifest-driven default scan (no --root) ───────────────────────────────

#[test]
fn doctor_default_scan_reads_installed_plugins_manifest() {
    // The default invocation (no --root) must scan active installs listed in
    // ~/.claude/plugins/installed_plugins.json — at the real cache depth.
    let tmp = tempfile::tempdir().unwrap();
    let install_path = tmp
        .path()
        .join(".claude/plugins/cache/workbench/buggy-plugin/ea2f0e05b78d");
    std::fs::create_dir_all(install_path.join("hooks")).unwrap();
    std::fs::write(install_path.join("hooks/hooks.json"), BUGGY_HOOKS_JSON).unwrap();

    let manifest = format!(
        r#"{{
  "version": 2,
  "plugins": {{
    "buggy-plugin@workbench": [
      {{ "scope": "user", "installPath": {p}, "version": "ea2f0e05b78d" }}
    ]
  }}
}}"#,
        p = serde_json::to_string(install_path.to_str().unwrap()).unwrap()
    );
    std::fs::write(
        tmp.path().join(".claude/plugins/installed_plugins.json"),
        manifest,
    )
    .unwrap();

    let metrics = tempfile::tempdir().unwrap();
    let output = doctor_in_home(tmp.path(), metrics.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "default scan must read the manifest and find the bug.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("buggy-plugin@workbench"),
        "finding must be labeled with the manifest key: {stdout}"
    );
}

// ── Telemetry staleness surface (default scan only) ────────────────────────

#[test]
fn doctor_default_scan_warns_on_stale_metrics() {
    // A metrics dir whose newest .jsonl is older than the 4-day default must
    // surface as a Warning (exit 1) in the default scan, even with a clean
    // plugin cache.
    let home = home_with_empty_cache();
    let metrics = tempfile::tempdir().unwrap();
    let jsonl = metrics.path().join("subagents.jsonl");
    std::fs::write(&jsonl, "{}\n").unwrap();
    // Backdate the mtime well past the default threshold.
    let old = SystemTime::now() - Duration::from_secs(10 * 86_400);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&jsonl)
        .unwrap()
        .set_modified(old)
        .unwrap();

    let output = doctor_in_home(home.path(), metrics.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stale telemetry is a warning → exit 1.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("telemetry is stale"),
        "diagnosis names staleness: {stdout}"
    );
    assert!(
        stdout.contains("cadence-metrics"),
        "finding is attributed to cadence-metrics: {stdout}"
    );
}

#[test]
fn doctor_default_scan_clean_on_fresh_metrics() {
    // A fresh metrics write (mtime ~now) is well within the threshold → clean.
    let home = home_with_empty_cache();
    let metrics = tempfile::tempdir().unwrap();
    std::fs::write(metrics.path().join("subagents.jsonl"), "{}\n").unwrap();

    let output = doctor_in_home(home.path(), metrics.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "fresh telemetry + clean cache → exit 0.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("clean"),
        "clean run reports clean: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn doctor_root_scan_ignores_stale_metrics_env() {
    // --root is the fixture/CI path: it must NEVER read live telemetry, even when
    // CADENCE_METRICS_DIR points at a genuinely stale dir. Pins the
    // "fixture scans never read live telemetry" guard (staleness skipped under
    // --root) — the counterpart to the default-scan warning above.
    let root = tempfile::tempdir().unwrap(); // empty scan root → clean
    let metrics = tempfile::tempdir().unwrap();
    let jsonl = metrics.path().join("subagents.jsonl");
    std::fs::write(&jsonl, "{}\n").unwrap();
    let old = SystemTime::now() - Duration::from_secs(10 * 86_400);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&jsonl)
        .unwrap()
        .set_modified(old)
        .unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--root"])
        .arg(root.path())
        .env("CADENCE_METRICS_DIR", metrics.path())
        .env_remove("CADENCE_METRICS_STALE_DAYS")
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--root scan must ignore live telemetry staleness → exit 0.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("telemetry is stale"),
        "no staleness finding under --root: {stdout}"
    );
}

// ── doctor --prune / --apply ────────────────────────────────────────────────

/// Write `<root>/installed_plugins.json` (v2 schema) pinning `label` to
/// `install_path` — the `--root`-driven manifest path `doctor --prune` reads
/// when `root_override` is set.
fn write_installed_plugins_manifest(
    root: &std::path::Path,
    label: &str,
    install_path: &std::path::Path,
) {
    let manifest = format!(
        r#"{{
  "version": 2,
  "plugins": {{
    "{label}": [
      {{ "scope": "user", "installPath": {p} }}
    ]
  }}
}}"#,
        p = serde_json::to_string(install_path.to_str().unwrap()).unwrap()
    );
    std::fs::write(root.join("installed_plugins.json"), manifest).unwrap();
}

#[test]
fn doctor_prune_dry_run_lists_orphans_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "my-plugin",
        "pinned-sha",
        BUGGY_HOOKS_JSON,
    );
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "my-plugin",
        "orphan-sha",
        BUGGY_HOOKS_JSON,
    );
    let pinned_path = tmp.path().join("workbench/my-plugin/pinned-sha");
    let orphan_path = tmp.path().join("workbench/my-plugin/orphan-sha");
    write_installed_plugins_manifest(tmp.path(), "my-plugin@workbench", &pinned_path);

    let output = cadence_hooks()
        .args(["doctor", "--prune", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "dry-run prune exits 0.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("orphan-sha"),
        "dry-run must list the orphan path: {stdout}"
    );
    assert!(
        stdout.contains("--apply"),
        "dry-run must mention how to actually remove: {stdout}"
    );
    assert!(orphan_path.exists(), "dry-run must not delete anything");
    assert!(pinned_path.exists());
}

#[test]
fn doctor_prune_apply_removes_orphans() {
    let tmp = tempfile::tempdir().unwrap();
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "my-plugin",
        "pinned-sha",
        BUGGY_HOOKS_JSON,
    );
    write_cached_plugin(
        tmp.path(),
        "workbench",
        "my-plugin",
        "orphan-sha",
        BUGGY_HOOKS_JSON,
    );
    let pinned_path = tmp.path().join("workbench/my-plugin/pinned-sha");
    let orphan_path = tmp.path().join("workbench/my-plugin/orphan-sha");
    write_installed_plugins_manifest(tmp.path(), "my-plugin@workbench", &pinned_path);

    let output = cadence_hooks()
        .args(["doctor", "--prune", "--apply", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "apply prune exits 0.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !orphan_path.exists(),
        "--apply must remove the orphaned version dir"
    );
    assert!(
        pinned_path.exists(),
        "--apply must never touch the pinned version dir"
    );
}

#[test]
fn doctor_prune_apply_never_deletes_outside_root() {
    // A manifest `installPath` that resolves OUTSIDE the `--root` cache must
    // never steer `--prune --apply`'s `remove_dir_all` at anything outside
    // the root. Regression test for the cache-root containment gap.
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    // A "pinned" dir and a would-be-orphan sibling, both OUTSIDE `--root`.
    let pinned_path = outside.path().join("fake-mp/fake-plugin/pinned-sha");
    let decoy_path = outside.path().join("fake-mp/fake-plugin/decoy-sha");
    std::fs::create_dir_all(&pinned_path).unwrap();
    std::fs::create_dir_all(&decoy_path).unwrap();
    std::fs::write(decoy_path.join("keepme"), "must survive").unwrap();

    write_installed_plugins_manifest(tmp.path(), "fake-plugin@fake-mp", &pinned_path);

    let output = cadence_hooks()
        .args(["doctor", "--prune", "--apply", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(0),
        "apply prune with an out-of-root pin still exits 0.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        decoy_path.exists() && decoy_path.join("keepme").exists(),
        "the out-of-root decoy directory must survive --prune --apply"
    );
    assert!(
        pinned_path.exists(),
        "the out-of-root pinned dir must survive too"
    );
}

#[test]
fn doctor_apply_without_prune_is_usage_error() {
    let tmp = tempfile::tempdir().unwrap();

    let output = cadence_hooks()
        .args(["doctor", "--apply", "--root"])
        .arg(tmp.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--apply without --prune is a usage error.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn doctor_default_scan_falls_back_to_cache_walk_without_manifest() {
    // No installed_plugins.json — recursively walk the cache dir instead.
    let tmp = tempfile::tempdir().unwrap();
    let plugin_dir = tmp
        .path()
        .join(".claude/plugins/cache/workbench/buggy-plugin/ea2f0e05b78d/hooks");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(plugin_dir.join("hooks.json"), BUGGY_HOOKS_JSON).unwrap();

    let metrics = tempfile::tempdir().unwrap();
    let output = doctor_in_home(tmp.path(), metrics.path())
        .output()
        .expect("failed to execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "manifest-less fallback must still scan the cache recursively.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ── Marketplace resolution (cameronsjo/cadence-hooks#474) ──────────────────
//
// Reproduces both misdiagnoses from the issue end-to-end through the real
// default scan: a plugin removed from its marketplace upstream (case 1) and
// a directory-sourced marketplace's plugin (case 2). Each test also carries
// a positive control proving doctor still detects the REAL problem it must
// keep detecting — a fix that just went silent everywhere would pass the
// "no more false positive" half and fail the control.

fn write_known_marketplaces(home: &std::path::Path, body: &serde_json::Value) {
    std::fs::create_dir_all(home.join(".claude/plugins")).unwrap();
    std::fs::write(
        home.join(".claude/plugins/known_marketplaces.json"),
        serde_json::to_string(body).unwrap(),
    )
    .unwrap();
}

fn write_installed_plugins_v2(home: &std::path::Path, entries: &[(&str, &std::path::Path)]) {
    let plugins: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(label, install_path)| {
            (
                label.to_string(),
                serde_json::json!([{ "scope": "user", "installPath": install_path.to_str().unwrap() }]),
            )
        })
        .collect();
    std::fs::create_dir_all(home.join(".claude/plugins")).unwrap();
    std::fs::write(
        home.join(".claude/plugins/installed_plugins.json"),
        serde_json::to_string(&serde_json::json!({ "version": 2, "plugins": plugins })).unwrap(),
    )
    .unwrap();
}

#[test]
fn doctor_reports_removed_upstream_plugin_not_binary_skew() {
    // Case 1: a plugin deleted from its marketplace, whose stale cached
    // hooks.json still references a subcommand this binary doesn't know.
    let home = tempfile::tempdir().unwrap();
    let install_location = home.path().join("marketplaces/cadence-lab");
    write_known_marketplaces(
        home.path(),
        &serde_json::json!({
            "cadence-lab": {
                "source": { "source": "github", "repo": "cameronsjo/cadence-lab" },
                "installLocation": install_location.to_str().unwrap(),
            }
        }),
    );
    std::fs::create_dir_all(install_location.join(".claude-plugin")).unwrap();
    std::fs::write(
        install_location.join(".claude-plugin/marketplace.json"),
        r#"{"plugins":[{"name":"vibes","source":"./plugins/vibes"}]}"#,
    )
    .unwrap();

    let removed_install = home
        .path()
        .join(".claude/plugins/cache/cadence-lab/persona/8f4df2542e4a");
    write_cached_plugin_at(&removed_install, SKEW_HOOKS_JSON);
    // Positive control: a plugin still listed in the marketplace, with a
    // genuine version-skew hooks.json — must still be flagged as skew.
    let live_install = home
        .path()
        .join(".claude/plugins/cache/cadence-lab/vibes/abc123");
    write_cached_plugin_at(&live_install, SKEW_HOOKS_JSON);

    write_installed_plugins_v2(
        home.path(),
        &[
            ("persona@cadence-lab", &removed_install),
            ("vibes@cadence-lab", &live_install),
        ],
    );

    let metrics = tempfile::tempdir().unwrap();
    let output = doctor_in_home(home.path(), metrics.path())
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("persona@cadence-lab") && stdout.contains("removed upstream"),
        "the removed plugin must report as removed upstream: {stdout}"
    );
    assert!(
        stdout.contains("vibes@cadence-lab") && stdout.contains("not present in this binary"),
        "the control plugin's real skew must still be reported: {stdout}"
    );
    // The misdiagnosis this issue exists to fix: a removed plugin must never
    // be told to chase a binary upgrade for a retired subcommand.
    let persona_section = stdout
        .split("[persona@cadence-lab]")
        .nth(1)
        .unwrap_or_default();
    let persona_line = persona_section.lines().next().unwrap_or_default();
    assert!(
        !persona_line.contains("not present in this binary"),
        "removed plugin must not be misdiagnosed as binary skew: {stdout}"
    );
}

/// Create `<dir>/hooks/hooks.json` with the given body, at whatever depth
/// `dir` names (the caller controls cache-layout depth).
fn write_cached_plugin_at(dir: &std::path::Path, hooks_json: &str) {
    std::fs::create_dir_all(dir.join("hooks")).unwrap();
    std::fs::write(dir.join("hooks/hooks.json"), hooks_json).unwrap();
}

#[test]
fn doctor_exempts_directory_sourced_plugin_from_cache_dir_check() {
    // Case 2: a directory-sourced marketplace's plugin has a recorded, but
    // never populated, cache installPath — reinstalling it fixes nothing
    // because nothing is broken.
    let home = tempfile::tempdir().unwrap();
    let plugin_source = home.path().join("dev/homelab");
    std::fs::create_dir_all(&plugin_source).unwrap();
    write_known_marketplaces(
        home.path(),
        &serde_json::json!({
            "homelab": {
                "source": { "source": "directory", "path": plugin_source.to_str().unwrap() },
                "installLocation": plugin_source.to_str().unwrap(),
            }
        }),
    );

    // installPath under plugins/cache/ that is never created on disk — the
    // exact #474 case 2 shape.
    let never_populated = home
        .path()
        .join(".claude/plugins/cache/homelab/homelab/1.0.0");
    write_installed_plugins_v2(home.path(), &[("homelab@homelab", &never_populated)]);

    let metrics = tempfile::tempdir().unwrap();
    let output = doctor_in_home(home.path(), metrics.path())
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("pinned cache dir missing"),
        "a directory-sourced plugin's never-populated cache path must not \
         report as broken.\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn doctor_still_flags_missing_cache_dir_for_non_directory_source() {
    // Positive control for the test above: the exemption must not
    // blanket-suppress the missing-dir check for a plugin whose marketplace
    // ISN'T directory-sourced. Same missing-dir shape, no known_marketplaces
    // entry at all — a genuinely broken cache must still report as broken.
    let home = tempfile::tempdir().unwrap();
    let missing = home
        .path()
        .join(".claude/plugins/cache/workbench/some-plugin/deadbeef");
    write_installed_plugins_v2(home.path(), &[("some-plugin@workbench", &missing)]);

    let metrics = tempfile::tempdir().unwrap();
    let output = doctor_in_home(home.path(), metrics.path())
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pinned cache dir missing"),
        "a genuinely broken (non-directory-sourced) cache entry must still \
         report as broken.\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
