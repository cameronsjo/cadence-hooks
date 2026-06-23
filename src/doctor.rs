//! Scan installed plugin `hooks.json` files for shell-expansion bugs
//! and subcommand version-skew (issue #39 P1).
//!
//! The single-quoted `${CLAUDE_PLUGIN_ROOT}` pattern survived in production
//! for months because the failure mode is silent: hooks return non-zero,
//! the harness logs "non-blocking", and nothing surfaces to the user.
//! Only `cadence-hooks doctor` exposes it, and most users never run it.
//!
//! This subcommand reads `~/.claude/plugins/installed_plugins.json` and scans
//! each active install's `hooks/hooks.json` (falling back to a recursive walk
//! of `~/.claude/plugins/cache/` when the manifest is absent). It flags known
//! shell-expansion patterns and unknown subcommand references, and exits
//! non-zero when violations are found so it's usable as a CI check or a
//! one-shot diagnostic.

use std::path::{Path, PathBuf};

use crate::registry;

/// Severity of a finding: errors block (shell bugs), warnings advise (version skew).
#[derive(Debug, PartialEq)]
enum Severity {
    /// Shell-expansion bug — the command will silently misbehave.
    Error,
    /// Version skew — subcommand reference unknown to this binary.
    Warning,
}

/// One detected issue in a hook command.
struct Finding {
    severity: Severity,
    plugin: String,
    file: PathBuf,
    line: Option<usize>,
    snippet: String,
    diagnosis: String,
    remediation: String,
}

impl Finding {
    fn print(&self) {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let location = match self.line {
            Some(n) => format!("{}:{n}", self.file.display()),
            None => self.file.display().to_string(),
        };
        // <level> [<plugin>] <file>[:line]: <diagnosis>
        //   command: <snippet>
        //   fix: <remediation>
        println!(
            "{level} [{}] {}: {}\n  command: {}\n  fix: {}",
            self.plugin, location, self.diagnosis, self.snippet, self.remediation
        );
    }
}

/// Single-quoted env-var pattern: `'${SOMETHING}'` or `'$SOMETHING'` won't
/// expand in `/bin/sh`. Returns the matched substring for diagnostics.
fn detect_single_quoted_envvar(command: &str) -> Option<&str> {
    // Walk the string and look for `'$` that opens a single-quoted region
    // containing an env-var expansion. We don't try to be a real shell
    // parser — just match the most common failure pattern.
    let bytes = command.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\'' && bytes[i + 1] == b'$' {
            // Find the closing single quote.
            if let Some(close_offset) = command[i + 1..].find('\'') {
                let end = i + 1 + close_offset + 1;
                let span = &command[i..end];
                // Only flag if the dollar sign is followed by a var-name char
                // or an open brace (the actual expansion form). `$5 charge`
                // and similar literals should not fire.
                let after_dollar = bytes.get(i + 2).copied();
                let is_expansion = match after_dollar {
                    Some(b'{') | Some(b'_') => true,
                    Some(c) => c.is_ascii_alphabetic(),
                    None => false,
                };
                if is_expansion {
                    return Some(span);
                }
            }
        }
        i += 1;
    }
    None
}

/// Extracted `(namespace, subcommand)` from a hook command string.
/// Returns `None` when the command doesn't invoke cadence-hooks or
/// doesn't yield at least two non-flag tokens after the dispatcher.
///
/// Handles all invocation forms:
/// - `"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" ns sub ...`
/// - `'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' ns sub ...`
/// - `${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh ns sub ...`
/// - `cadence-hooks ns sub ...`
/// - `/opt/homebrew/bin/cadence-hooks ns sub ...`
fn extract_invocation(command: &str) -> Option<(String, String)> {
    // Tokenise on whitespace. For each token, strip outer quotes and check
    // if the basename is our dispatcher or binary name.
    let tokens: Vec<&str> = command.split_whitespace().collect();

    let dispatcher_idx = tokens.iter().position(|tok| {
        // Strip one layer of surrounding quotes (single or double).
        let tok = tok.trim_matches(|c| c == '\'' || c == '"');
        // Take the basename (after the last '/').
        let basename = tok.rsplit('/').next().unwrap_or(tok);
        basename == "run-cadence-hooks.sh" || basename == "cadence-hooks"
    })?;

    // The two tokens immediately after the dispatcher (skip flags starting with '-').
    // Strip outer quotes from each so a quoted namespace/subcommand doesn't
    // produce a spurious registry mismatch.
    let after = &tokens[dispatcher_idx + 1..];
    let mut non_flags = after
        .iter()
        .map(|t| t.trim_matches(|c| c == '\'' || c == '"'))
        .filter(|t| !t.starts_with('-'));

    let namespace = non_flags.next()?.to_string();
    let subcommand = non_flags.next()?.to_string();

    Some((namespace, subcommand))
}

/// Diagnosis for a version-skew finding.
#[derive(Debug, PartialEq)]
struct SkewDiagnosis {
    diagnosis: String,
    remediation: String,
}

/// How this binary was installed — picks the truthful upgrade path.
///
/// `doctor` runs at SessionStart and must not make a network call, so it can't
/// know whether the Homebrew tap is already current. Instead of recommending an
/// unconditional `brew upgrade` (a silent no-op when the tap already ships the
/// installed version — claude-configurations #223), it names the channel this
/// binary came from and always offers the source path as the "already current"
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallChannel {
    Homebrew,
    Cargo,
    Unknown,
}

const RELEASES_URL: &str = "https://github.com/cameronsjo/cadence-hooks/releases/latest";
const CARGO_INSTALL: &str = "cargo install --git https://github.com/cameronsjo/cadence-hooks.git";

/// Classify an executable path into an install channel. Pure, for testing.
fn classify_channel(exe_path: &str) -> InstallChannel {
    if exe_path.contains("/Cellar/")
        || exe_path.contains("/homebrew/")
        || exe_path.contains("linuxbrew")
    {
        InstallChannel::Homebrew
    } else if exe_path.contains("/.cargo/") {
        InstallChannel::Cargo
    } else {
        InstallChannel::Unknown
    }
}

/// Best-effort detection of how the running binary was installed.
/// Falls back to [`InstallChannel::Unknown`] when the path is unreadable.
fn install_channel() -> InstallChannel {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(classify_channel))
        .unwrap_or(InstallChannel::Unknown)
}

/// The full skew remediation for a finding, honest for this install channel.
/// Homebrew still names `brew upgrade` (the normal path) but never as the *sole*
/// remedy — the source fallback covers the "tap already current" no-op case.
fn upgrade_remediation(channel: InstallChannel) -> String {
    match channel {
        InstallChannel::Homebrew => format!(
            "brew upgrade cadence-hooks — if it reports up-to-date, the plugin \
             references an unreleased build: install from source ({CARGO_INSTALL}) \
             or downgrade the plugin"
        ),
        InstallChannel::Cargo => format!("{CARGO_INSTALL} (or downgrade the plugin)"),
        InstallChannel::Unknown => format!(
            "update to the latest release ({RELEASES_URL}) or {CARGO_INSTALL} \
             (or downgrade the plugin)"
        ),
    }
}

/// One-line upgrade hint for the quiet SessionStart banner. Defers channel
/// detail to `cadence-hooks doctor` rather than asserting a possibly-no-op
/// command.
fn upgrade_hint_short(channel: InstallChannel) -> &'static str {
    match channel {
        InstallChannel::Homebrew => {
            "run 'brew upgrade cadence-hooks' (or 'cadence-hooks doctor' if already up-to-date)"
        }
        InstallChannel::Cargo | InstallChannel::Unknown => {
            "run 'cadence-hooks doctor' for upgrade steps"
        }
    }
}

/// Judge an invocation against the registry.
/// Returns `None` when the pair is known-good.
/// Returns `Some(SkewDiagnosis)` for a namespace mismatch or unknown subcommand.
fn judge_invocation(
    namespace: &str,
    subcommand: &str,
    channel: InstallChannel,
) -> Option<SkewDiagnosis> {
    if registry::is_known(namespace, subcommand) {
        return None;
    }

    let version = env!("CARGO_PKG_VERSION");

    if let Some(actual_ns) = registry::namespace_of(subcommand) {
        // The subcommand exists but under a different namespace.
        Some(SkewDiagnosis {
            diagnosis: format!(
                "subcommand '{subcommand}' is in namespace '{actual_ns}', not '{namespace}'"
            ),
            remediation: format!("fix the hooks.json entry to: {actual_ns} {subcommand}"),
        })
    } else {
        // Fully unknown — version skew. The remediation names the upgrade path
        // for *this* binary's install channel, not an unconditional
        // `brew upgrade` that no-ops when the tap is already current (#223).
        Some(SkewDiagnosis {
            diagnosis: format!(
                "subcommand '{namespace} {subcommand}' is not present in this binary (v{version})"
            ),
            remediation: upgrade_remediation(channel),
        })
    }
}

/// Find the 1-based line number of `needle` in `haystack`.
/// Best-effort: returns `None` when not found.
///
/// The needle is a serde-decoded command string; the haystack is raw JSON
/// text where inner quotes and backslashes are escaped. Search for the
/// JSON-encoded form so commands containing quotes (the dominant real form)
/// still resolve to a line. Needles without special characters encode to
/// themselves, so plain-text haystacks keep working.
fn find_line_number(haystack: &str, needle: &str) -> Option<usize> {
    let encoded = serde_json::to_string(needle).ok()?;
    // Strip the surrounding quotes the encoder adds.
    let encoded_inner = &encoded[1..encoded.len() - 1];
    haystack
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(encoded_inner))
        .map(|(i, _)| i + 1)
}

/// Walk a `hooks.json` blob's hook commands and collect findings.
fn scan_hooks_json(
    plugin: &str,
    path: &Path,
    raw: &str,
    json: &serde_json::Value,
    channel: InstallChannel,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Some(hooks_obj) = json.get("hooks").and_then(|v| v.as_object()) else {
        return findings;
    };

    for matchers in hooks_obj.values() {
        let Some(matchers) = matchers.as_array() else {
            continue;
        };
        for matcher_block in matchers {
            let Some(hooks) = matcher_block.get("hooks").and_then(|v| v.as_array()) else {
                continue;
            };
            for hook in hooks {
                let Some(cmd) = hook.get("command").and_then(|v| v.as_str()) else {
                    continue;
                };

                // Check 1: shell-expansion bug (Error).
                if let Some(span) = detect_single_quoted_envvar(cmd) {
                    findings.push(Finding {
                        severity: Severity::Error,
                        plugin: plugin.to_string(),
                        file: path.to_path_buf(),
                        line: find_line_number(raw, cmd),
                        snippet: span.to_string(),
                        diagnosis: "single-quoted env var won't expand in /bin/sh".to_string(),
                        remediation:
                            "switch the single quotes around the expansion to double quotes"
                                .to_string(),
                    });
                }

                // Check 2: subcommand cross-reference (Warning).
                if let Some((ns, sub)) = extract_invocation(cmd)
                    && let Some(diag) = judge_invocation(&ns, &sub, channel)
                {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        plugin: plugin.to_string(),
                        file: path.to_path_buf(),
                        line: find_line_number(raw, cmd),
                        snippet: cmd.to_string(),
                        diagnosis: diag.diagnosis,
                        remediation: diag.remediation,
                    });
                }
            }
        }
    }

    findings
}

/// Claude Code's plugins directory.
///
/// Prefers `<config_dir>/plugins` (honoring `CLAUDE_CONFIG_DIR`), but it is
/// unverified whether Claude Code's plugin loader relocates `plugins/` along
/// with the rest of the config tree — it may keep it at `~/.claude` regardless.
/// So when the config-dir variant does not exist, fall back to
/// `$HOME/.claude/plugins`. This stays correct under either loader behavior.
fn plugins_dir() -> Option<PathBuf> {
    let config_variant = cadence_hooks_core::paths::claude_config_dir().join("plugins");
    if config_variant.exists() {
        return Some(config_variant);
    }
    let home = cadence_hooks_core::paths::user_home()?;
    Some(home.join(".claude/plugins"))
}

/// Read active plugin install paths from `installed_plugins.json` (v2 schema).
///
/// Returns `(label, install_path)` pairs, where the label is the manifest key
/// (`<plugin>@<marketplace>`). Returns `None` when the manifest is missing or
/// unparseable — callers fall back to a recursive cache scan.
///
/// Reading the manifest (rather than walking the cache) matters: the cache
/// never garbage-collects, so stale plugin versions sit beside active ones.
/// Scanning them would report skew in code that no longer runs.
fn manifest_install_paths(manifest: &Path) -> Option<Vec<(String, PathBuf)>> {
    let content = std::fs::read_to_string(manifest).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let plugins = json.get("plugins")?.as_object()?;

    let mut out = Vec::new();
    for (key, installs) in plugins {
        let Some(installs) = installs.as_array() else {
            continue;
        };
        for install in installs {
            let Some(path) = install.get("installPath").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push((key.clone(), PathBuf::from(path)));
        }
    }
    Some(out)
}

/// Scan a single plugin install dir's `hooks/hooks.json`, if present.
fn scan_plugin_dir(label: &str, plugin_dir: &Path, channel: InstallChannel) -> Vec<Finding> {
    let hooks_path = plugin_dir.join("hooks/hooks.json");
    let Ok(content) = std::fs::read_to_string(&hooks_path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        // Invalid JSON is its own bug, but not the one this check exists
        // to catch. The plugin loader will surface it.
        return Vec::new();
    };
    scan_hooks_json(label, &hooks_path, &content, &json, channel)
}

/// Recursively discover `hooks/hooks.json` files under `root` and scan each.
///
/// Handles any nesting depth: a flat layout (`<root>/<plugin>/hooks/`) and the
/// real Claude Code cache layout (`<root>/<marketplace>/<plugin>/<sha>/hooks/`)
/// both work. Plugin labels are the directory path from `root` to the dir
/// containing `hooks/`, so findings stay attributable at any depth.
fn scan_root(root: &Path, channel: InstallChannel) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    // Real cache layouts are 3 levels deep (marketplace/plugin/sha); allow
    // headroom while bounding the walk against pathological trees.
    const MAX_DEPTH: usize = 6;

    while let Some(dir) = stack.pop() {
        let depth = dir
            .strip_prefix(root)
            .map(|p| p.components().count())
            .unwrap_or(0);
        if depth > MAX_DEPTH {
            continue;
        }

        if dir.join("hooks/hooks.json").is_file() {
            let label = dir
                .strip_prefix(root)
                .ok()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| dir.display().to_string());
            findings.extend(scan_plugin_dir(&label, &dir, channel));
            // A plugin dir doesn't nest further plugins beneath it.
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // Recurse into real directories only — symlinks could cycle.
            let is_symlink = entry.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if !is_symlink && entry.path().is_dir() {
                stack.push(entry.path());
            }
        }
    }

    findings
}

/// Entry point for the `doctor` subcommand. Returns the process exit code.
///
/// Exit codes:
///   0  clean
///   1  warnings only (version skew)
///   2  errors — shell-expansion bugs (regardless of warnings), or internal /
///      configuration errors (unset `$HOME`, nonexistent scan root)
///
/// `root_override` lets tests redirect the scan; in normal use it's `None`
/// and the scan is driven by `~/.claude/plugins/installed_plugins.json`
/// (active installs only), falling back to a recursive walk of
/// `~/.claude/plugins/cache` when the manifest is absent.
///
/// `quiet=true` is suitable for SessionStart preflight wiring:
///   - Clean: no output, exit 0
///   - Warnings only: ONE summary line to stdout, exit 0
///   - Errors (with or without warnings): one line to stderr, exit 2 — the
///     warning summary is suppressed; errors take precedence
///
/// Stream split in quiet mode is deliberate: warnings go to stdout (a caller
/// capturing stdout gets the skew nudge to inject), errors go to stderr (a
/// caller redirecting stderr to /dev/null still fails on the exit code).
pub fn run(root_override: Option<&Path>, quiet: bool) -> u8 {
    // Resolve the install channel once — it's process-invariant, so the scan
    // below shouldn't re-probe current_exe() per hook entry.
    let channel = install_channel();
    let (findings, scanned) = match root_override {
        Some(root) => {
            if !root.exists() {
                // Configuration error, not "clean" — exit 2 so a misconfigured
                // CI gate can never silently pass everything.
                eprintln!(
                    "cadence-hooks doctor: scan root does not exist: {}",
                    root.display()
                );
                return 2;
            }
            (scan_root(root, channel), root.display().to_string())
        }
        None => {
            let Some(plugins) = plugins_dir() else {
                // Internal error, not version skew — exit 2 so callers never
                // misread it as "warnings present".
                eprintln!("cadence-hooks doctor: $HOME not set; cannot locate plugin cache");
                return 2;
            };

            match manifest_install_paths(&plugins.join("installed_plugins.json")) {
                Some(installs) => {
                    let scanned = format!("{} installed plugin(s)", installs.len());
                    let findings = installs
                        .iter()
                        .flat_map(|(label, dir)| scan_plugin_dir(label, dir, channel))
                        .collect();
                    (findings, scanned)
                }
                None => {
                    // No readable manifest — recursively scan the cache instead.
                    let cache = plugins.join("cache");
                    if !cache.exists() {
                        eprintln!(
                            "cadence-hooks doctor: no installed-plugins manifest and no plugin cache under {}",
                            plugins.display()
                        );
                        return 2;
                    }
                    (scan_root(&cache, channel), cache.display().to_string())
                }
            }
        }
    };

    let (errors, warnings): (Vec<&Finding>, Vec<&Finding>) =
        findings.iter().partition(|f| f.severity == Severity::Error);

    if quiet {
        if errors.is_empty() && warnings.is_empty() {
            return 0;
        }
        if !errors.is_empty() {
            eprintln!(
                "cadence-hooks doctor: {} shell-expansion error(s) found — run 'cadence-hooks doctor' for details",
                errors.len()
            );
            return 2;
        }
        // Warnings only in quiet mode: one summary line to stdout, exit 0.
        let version = env!("CARGO_PKG_VERSION");
        println!(
            "cadence-hooks {version} is missing {} subcommand(s) referenced by installed plugins — {}",
            warnings.len(),
            upgrade_hint_short(channel)
        );
        return 0;
    }

    // Default (verbose) mode.
    if findings.is_empty() {
        println!("cadence-hooks doctor: clean ({scanned} scanned)");
        return 0;
    }

    println!(
        "cadence-hooks doctor: {} finding(s) in {scanned}:\n",
        findings.len()
    );

    // Errors first, then warnings.
    for finding in errors.iter().chain(warnings.iter()) {
        finding.print();
        println!();
    }

    let n_err = errors.len();
    let n_warn = warnings.len();
    println!("cadence-hooks doctor: {n_err} error(s), {n_warn} warning(s)");

    if n_err > 0 { 2 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── extract_invocation table tests ──────────────────────────────────────

    #[test]
    fn detects_single_quoted_braced_envvar() {
        let cmd = r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg"#;
        let span = detect_single_quoted_envvar(cmd).expect("should detect");
        assert!(span.starts_with("'${CLAUDE_PLUGIN_ROOT}"), "span: {span}");
        assert!(span.ends_with('\''), "span: {span}");
    }

    #[test]
    fn detects_single_quoted_bare_envvar() {
        let cmd = r#"'$CLAUDE_PLUGIN_ROOT' arg"#;
        let span = detect_single_quoted_envvar(cmd).expect("should detect");
        assert!(span.contains("CLAUDE_PLUGIN_ROOT"), "span: {span}");
    }

    #[test]
    fn does_not_flag_double_quoted_envvar() {
        let cmd = r#""${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" arg"#;
        assert_eq!(detect_single_quoted_envvar(cmd), None);
    }

    #[test]
    fn does_not_flag_unquoted_envvar() {
        let cmd = "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh arg";
        assert_eq!(detect_single_quoted_envvar(cmd), None);
    }

    #[test]
    fn does_not_flag_literal_dollar_in_single_quotes() {
        let cmd = "echo '$5 charge'";
        assert_eq!(detect_single_quoted_envvar(cmd), None);
    }

    // ── extract_invocation table tests ──────────────────────────────────────

    #[test]
    fn extract_invocation_quoted_namespace_and_subcommand() {
        // Quoted namespace/subcommand tokens must be unquoted before the
        // registry lookup, or doctor emits a spurious mismatch warning.
        let cmd = r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" "cadence" 'terminology'"#;
        assert_eq!(
            extract_invocation(cmd),
            Some(("cadence".into(), "terminology".into()))
        );
    }

    #[test]
    fn extract_invocation_double_quoted_wrapper() {
        let cmd = r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-gh-write"#;
        assert_eq!(
            extract_invocation(cmd),
            Some(("guardrails".into(), "guard-gh-write".into()))
        );
    }

    #[test]
    fn extract_invocation_single_quoted_wrapper() {
        // Single-quoted — still parse; expansion bug is reported separately.
        let cmd = r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' cadence terminology"#;
        assert_eq!(
            extract_invocation(cmd),
            Some(("cadence".into(), "terminology".into()))
        );
    }

    #[test]
    fn extract_invocation_unquoted_wrapper() {
        let cmd = "${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh metrics snapshot";
        assert_eq!(
            extract_invocation(cmd),
            Some(("metrics".into(), "snapshot".into()))
        );
    }

    #[test]
    fn extract_invocation_direct_binary() {
        let cmd = "cadence-hooks guardrails guard-push-remote";
        assert_eq!(
            extract_invocation(cmd),
            Some(("guardrails".into(), "guard-push-remote".into()))
        );
    }

    #[test]
    fn extract_invocation_absolute_path_binary() {
        let cmd = "/opt/homebrew/bin/cadence-hooks rules security-patterns";
        assert_eq!(
            extract_invocation(cmd),
            Some(("rules".into(), "security-patterns".into()))
        );
    }

    #[test]
    fn extract_invocation_trailing_args_ignored() {
        let cmd = "/opt/homebrew/bin/cadence-hooks metrics log-commit --prices /x.json";
        assert_eq!(
            extract_invocation(cmd),
            Some(("metrics".into(), "log-commit".into()))
        );
    }

    #[test]
    fn extract_invocation_none_for_unrelated_command() {
        assert_eq!(extract_invocation("echo hello world"), None);
        assert_eq!(extract_invocation("git push origin main"), None);
    }

    #[test]
    fn extract_invocation_none_for_single_token_invocation() {
        // cadence-hooks list — only one arg, no subcommand pair
        assert_eq!(extract_invocation("cadence-hooks list"), None);
    }

    // ── find_line_number tests ───────────────────────────────────────────────

    #[test]
    fn find_line_number_handles_json_escaped_quotes() {
        // The needle is the serde-decoded command; the haystack is raw JSON
        // where inner double quotes are backslash-escaped. The dominant real
        // command form ("${CLAUDE_PLUGIN_ROOT}/..." ns sub) contains quotes,
        // so a literal substring search never matches it.
        let raw = r#"{
  "hooks": {
    "PreToolUse": [{
      "hooks": [{ "command": "\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" guardrails guard-push-remote" }]
    }]
  }
}"#;
        let decoded =
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#;
        assert_eq!(find_line_number(raw, decoded), Some(4));
    }

    #[test]
    fn find_line_number_still_matches_unquoted_needle() {
        let raw = "line one\nline two has needle\nline three";
        assert_eq!(find_line_number(raw, "needle"), Some(2));
    }

    // ── manifest-driven scan (installed_plugins.json) ────────────────────────

    #[test]
    fn manifest_install_paths_reads_v2_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let install_dir = tmp.path().join("cache/workbench/cadence-guardrails/abc123");
        fs::create_dir_all(&install_dir).unwrap();

        let manifest = tmp.path().join("installed_plugins.json");
        let manifest_json = format!(
            r#"{{
  "version": 2,
  "plugins": {{
    "cadence-guardrails@workbench": [
      {{
        "scope": "user",
        "installPath": {install_path},
        "version": "abc123"
      }}
    ]
  }}
}}"#,
            install_path = serde_json::to_string(install_dir.to_str().unwrap()).unwrap()
        );
        fs::write(&manifest, manifest_json).unwrap();

        let paths = manifest_install_paths(&manifest).expect("should parse v2 manifest");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].0, "cadence-guardrails@workbench");
        assert_eq!(paths[0].1, install_dir);
    }

    #[test]
    fn manifest_install_paths_none_for_missing_file() {
        assert!(manifest_install_paths(Path::new("/nonexistent/manifest.json")).is_none());
    }

    #[test]
    fn manifest_install_paths_none_for_invalid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("installed_plugins.json");
        fs::write(&manifest, "{ not json").unwrap();
        assert!(manifest_install_paths(&manifest).is_none());
    }

    // ── judge_invocation tests ───────────────────────────────────────────────

    #[test]
    fn judge_invocation_known_pair_is_clean() {
        let c = InstallChannel::Unknown;
        assert_eq!(judge_invocation("guardrails", "guard-push-remote", c), None);
        assert_eq!(judge_invocation("cadence", "terminology", c), None);
        assert_eq!(judge_invocation("metrics", "log-commit", c), None);
    }

    #[test]
    fn judge_invocation_wrong_namespace_gives_mismatch_diagnosis() {
        // guard-push-remote is guardrails, not cadence
        let diag = judge_invocation("cadence", "guard-push-remote", InstallChannel::Unknown)
            .expect("should find mismatch");
        assert!(
            diag.diagnosis.contains("guardrails"),
            "diagnosis: {}",
            diag.diagnosis
        );
        assert!(
            diag.remediation.contains("guardrails guard-push-remote"),
            "remediation: {}",
            diag.remediation
        );
    }

    #[test]
    fn judge_invocation_unknown_gives_skew_diagnosis() {
        let diag = judge_invocation("cadence", "totally-made-up-hook", InstallChannel::Homebrew)
            .expect("should find skew");
        assert!(
            diag.diagnosis.contains("not present in this binary"),
            "diagnosis: {}",
            diag.diagnosis
        );
        // Homebrew channel names brew but also the source fallback for the
        // tap-already-current no-op case (#223).
        assert!(
            diag.remediation.contains("brew upgrade"),
            "remediation: {}",
            diag.remediation
        );
        assert!(
            diag.remediation.contains("cargo install"),
            "should offer source fallback: {}",
            diag.remediation
        );
    }

    #[test]
    fn judge_invocation_unknown_cargo_channel_omits_brew() {
        let diag = judge_invocation("cadence", "totally-made-up-hook", InstallChannel::Cargo)
            .expect("should find skew");
        assert!(
            diag.remediation.contains("cargo install"),
            "remediation: {}",
            diag.remediation
        );
        assert!(
            !diag.remediation.contains("brew"),
            "cargo-installed binary must not be told to brew upgrade: {}",
            diag.remediation
        );
    }

    // ── install-channel classification ───────────────────────────────────────

    #[test]
    fn classify_channel_detects_homebrew() {
        assert_eq!(
            classify_channel("/opt/homebrew/bin/cadence-hooks"),
            InstallChannel::Homebrew
        );
        assert_eq!(
            classify_channel("/opt/homebrew/Cellar/cadence-hooks/0.39.0/bin/cadence-hooks"),
            InstallChannel::Homebrew
        );
        assert_eq!(
            classify_channel("/home/linuxbrew/.linuxbrew/bin/cadence-hooks"),
            InstallChannel::Homebrew
        );
    }

    #[test]
    fn classify_channel_detects_cargo() {
        assert_eq!(
            classify_channel("/Users/x/.cargo/bin/cadence-hooks"),
            InstallChannel::Cargo
        );
    }

    #[test]
    fn classify_channel_unknown_for_other_paths() {
        assert_eq!(
            classify_channel("/usr/local/bin/cadence-hooks"),
            InstallChannel::Unknown
        );
        assert_eq!(
            classify_channel("/Users/x/proj/target/debug/cadence-hooks"),
            InstallChannel::Unknown
        );
    }

    #[test]
    fn upgrade_remediation_homebrew_names_brew_and_source_fallback() {
        let r = upgrade_remediation(InstallChannel::Homebrew);
        assert!(r.contains("brew upgrade"), "{r}");
        assert!(
            r.contains("cargo install"),
            "should offer source fallback: {r}"
        );
        assert!(r.contains("downgrade the plugin"), "{r}");
    }

    #[test]
    fn upgrade_remediation_cargo_omits_brew() {
        let r = upgrade_remediation(InstallChannel::Cargo);
        assert!(r.contains("cargo install"), "{r}");
        assert!(!r.contains("brew"), "{r}");
    }

    #[test]
    fn upgrade_remediation_unknown_points_at_releases_not_brew() {
        let r = upgrade_remediation(InstallChannel::Unknown);
        assert!(r.contains("releases"), "{r}");
        assert!(
            !r.contains("brew upgrade"),
            "unknown channel must not assert a possibly-no-op brew upgrade: {r}"
        );
    }

    #[test]
    fn upgrade_hint_short_homebrew_mentions_doctor_fallback() {
        let h = upgrade_hint_short(InstallChannel::Homebrew);
        assert!(h.contains("brew upgrade"), "{h}");
        assert!(h.contains("doctor"), "{h}");
    }

    #[test]
    fn upgrade_hint_short_non_brew_defers_to_doctor() {
        let h = upgrade_hint_short(InstallChannel::Cargo);
        assert!(h.contains("doctor"), "{h}");
        assert!(!h.contains("brew"), "{h}");
    }

    // ── integration tests via run(Some(tmpdir), ...) ─────────────────────────

    /// Build a minimal hooks.json under a temp plugin dir structure.
    /// Returns the TempDir guard (dropped = cleaned up).
    fn write_fixture(commands: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("test-plugin/hooks");
        fs::create_dir_all(&plugin_dir).unwrap();

        let hooks_entries: String = commands
            .iter()
            .map(|cmd| {
                format!(
                    r#"{{
          "type": "command",
          "command": {cmd_json}
        }}"#,
                    cmd_json = serde_json::to_string(cmd).unwrap()
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        let json = format!(
            r#"{{
  "hooks": {{
    "PreToolUse": [
      {{
        "matcher": "*",
        "hooks": [
          {}
        ]
      }}
    ]
  }}
}}"#,
            hooks_entries
        );

        fs::write(plugin_dir.join("hooks.json"), &json).unwrap();
        root
    }

    #[test]
    fn integration_clean_hooks_json_exits_0() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), false), 0);
    }

    #[test]
    fn integration_unknown_subcommand_exits_1() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        ]);
        assert_eq!(run(Some(root.path()), false), 1);
    }

    #[test]
    fn integration_shell_expansion_bug_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), false), 2);
    }

    #[test]
    fn integration_both_skew_and_expansion_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' cadence no-such-hook"#,
        ]);
        // Single-quoted (Error) + unknown sub (Warning) → exit 2
        assert_eq!(run(Some(root.path()), false), 2);
    }

    #[test]
    fn integration_quiet_warnings_only_exits_0_stdout_nonempty() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        ]);
        // Capture stdout is not trivial in unit tests; we verify exit code here.
        // The output assertion is covered by manually running the binary.
        assert_eq!(run(Some(root.path()), true), 0);
    }

    #[test]
    fn integration_quiet_errors_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), true), 2);
    }

    #[test]
    fn integration_quiet_clean_exits_0() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), true), 0);
    }
}
