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

    let output = cadence_hooks()
        .arg("doctor")
        .env("HOME", tmp.path())
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

    let output = cadence_hooks()
        .arg("doctor")
        .env("HOME", home.path())
        .env("CADENCE_METRICS_DIR", metrics.path())
        .env_remove("CADENCE_METRICS_STALE_DAYS")
        .env_remove("CLAUDE_CONFIG_DIR")
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

    let output = cadence_hooks()
        .arg("doctor")
        .env("HOME", home.path())
        .env("CADENCE_METRICS_DIR", metrics.path())
        .env_remove("CADENCE_METRICS_STALE_DAYS")
        .env_remove("CLAUDE_CONFIG_DIR")
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

    let output = cadence_hooks()
        .arg("doctor")
        .env("HOME", tmp.path())
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
