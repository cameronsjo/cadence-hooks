//! Scan installed plugin `hooks.json` files for shell-expansion bugs
//! and subcommand version-skew (issue #39 P1).
//!
//! The single-quoted `${CLAUDE_PLUGIN_ROOT}` pattern survived in production
//! for months because the failure mode is silent: hooks return non-zero,
//! the harness logs "non-blocking", and nothing surfaces to the user.
//! Only `cadence-hooks doctor` exposes it, and most users never run it.
//!
//! This subcommand walks `~/.claude/plugins/cache/*/hooks/hooks.json`,
//! flags known shell-expansion patterns and unknown subcommand references,
//! and exits non-zero when violations are found so it's usable as a CI
//! check or a one-shot diagnostic.

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
    let after = &tokens[dispatcher_idx + 1..];
    let mut non_flags = after.iter().filter(|t| !t.starts_with('-'));

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

/// Judge an invocation against the registry.
/// Returns `None` when the pair is known-good.
/// Returns `Some(SkewDiagnosis)` for a namespace mismatch or unknown subcommand.
fn judge_invocation(namespace: &str, subcommand: &str) -> Option<SkewDiagnosis> {
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
        // Fully unknown — version skew.
        Some(SkewDiagnosis {
            diagnosis: format!(
                "subcommand '{namespace} {subcommand}' is not present in this binary (v{version})"
            ),
            remediation: "brew upgrade cadence-hooks (or downgrade the plugin)".to_string(),
        })
    }
}

/// Find the 1-based line number of `needle` in `haystack`.
/// Best-effort: returns `None` when not found.
fn find_line_number(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(needle))
        .map(|(i, _)| i + 1)
}

/// Walk a `hooks.json` blob's hook commands and collect findings.
fn scan_hooks_json(plugin: &str, path: &Path, raw: &str, json: &serde_json::Value) -> Vec<Finding> {
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
                    && let Some(diag) = judge_invocation(&ns, &sub)
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

/// Default scan root: Claude Code's installed-plugin cache.
fn default_root() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".claude/plugins/cache"))
}

/// Discover plugin dirs under `root` and scan each one's `hooks/hooks.json`.
fn scan_root(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let Ok(entries) = std::fs::read_dir(root) else {
        return findings;
    };

    for entry in entries.flatten() {
        let plugin_dir = entry.path();
        if !plugin_dir.is_dir() {
            continue;
        }
        let plugin_name = plugin_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        let hooks_path = plugin_dir.join("hooks/hooks.json");
        if !hooks_path.exists() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&hooks_path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
            // Invalid JSON is its own bug, but not the one this check exists
            // to catch. The plugin loader will surface it.
            continue;
        };
        findings.extend(scan_hooks_json(&plugin_name, &hooks_path, &content, &json));
    }

    findings
}

/// Entry point for the `doctor` subcommand. Returns the process exit code.
///
/// Exit codes:
///   0  clean
///   1  warnings only (version skew)
///   2  errors present (shell-expansion bugs), regardless of warnings
///
/// `root_override` lets tests redirect the scan; in normal use it's `None`
/// and we fall back to `$HOME/.claude/plugins/cache`.
///
/// `quiet=true` is suitable for SessionStart preflight wiring:
///   - Clean: no output, exit 0
///   - Warnings only: ONE summary line to stdout, exit 0
///   - Errors: one line to stderr, exit 2
pub fn run(root_override: Option<&Path>, quiet: bool) -> u8 {
    let root = match root_override {
        Some(p) => p.to_path_buf(),
        None => match default_root() {
            Some(p) => p,
            None => {
                eprintln!("cadence-hooks doctor: $HOME not set; cannot locate plugin cache");
                return 1;
            }
        },
    };

    if !root.exists() {
        eprintln!(
            "cadence-hooks doctor: scan root does not exist: {}",
            root.display()
        );
        return 0;
    }

    let findings = scan_root(&root);

    let errors: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();
    let warnings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .collect();

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
            "cadence-hooks {version} is missing {} subcommand(s) referenced by installed plugins — run 'brew upgrade cadence-hooks'",
            warnings.len()
        );
        return 0;
    }

    // Default (verbose) mode.
    if findings.is_empty() {
        println!("cadence-hooks doctor: clean ({} scanned)", root.display());
        return 0;
    }

    println!(
        "cadence-hooks doctor: {} finding(s) under {}:\n",
        findings.len(),
        root.display()
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

    // ── judge_invocation tests ───────────────────────────────────────────────

    #[test]
    fn judge_invocation_known_pair_is_clean() {
        assert_eq!(judge_invocation("guardrails", "guard-push-remote"), None);
        assert_eq!(judge_invocation("cadence", "terminology"), None);
        assert_eq!(judge_invocation("metrics", "log-commit"), None);
    }

    #[test]
    fn judge_invocation_wrong_namespace_gives_mismatch_diagnosis() {
        // guard-push-remote is guardrails, not cadence
        let diag = judge_invocation("cadence", "guard-push-remote").expect("should find mismatch");
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
        let diag = judge_invocation("cadence", "totally-made-up-hook").expect("should find skew");
        assert!(
            diag.diagnosis.contains("not present in this binary"),
            "diagnosis: {}",
            diag.diagnosis
        );
        assert!(
            diag.remediation.contains("brew upgrade"),
            "remediation: {}",
            diag.remediation
        );
    }

    // ── integration tests via run(Some(tmpdir), ...) ─────────────────────────

    /// Build a minimal hooks.json under a temp plugin dir structure.
    /// Returns the root dir (caller must keep it alive).
    fn write_fixture(commands: &[(&str, &str)]) -> std::path::PathBuf {
        // Use PID + a counter for a unique-enough subdir.
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cadence-hooks-doctor-test-{}-{}",
            std::process::id(),
            n
        ));
        let plugin_dir = root.join("test-plugin/hooks");
        fs::create_dir_all(&plugin_dir).unwrap();

        let hooks_entries: String = commands
            .iter()
            .map(|(_event, cmd)| {
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
        let root = write_fixture(&[(
            "PreToolUse",
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#,
        )]);
        assert_eq!(run(Some(&root), false), 0);
    }

    #[test]
    fn integration_unknown_subcommand_exits_1() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        )]);
        assert_eq!(run(Some(&root), false), 1);
    }

    #[test]
    fn integration_shell_expansion_bug_exits_2() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        )]);
        assert_eq!(run(Some(&root), false), 2);
    }

    #[test]
    fn integration_both_skew_and_expansion_exits_2() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' cadence no-such-hook"#,
        )]);
        // Single-quoted (Error) + unknown sub (Warning) → exit 2
        assert_eq!(run(Some(&root), false), 2);
    }

    #[test]
    fn integration_quiet_warnings_only_exits_0_stdout_nonempty() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        )]);
        // Capture stdout is not trivial in unit tests; we verify exit code here.
        // The output assertion is covered by manually running the binary.
        assert_eq!(run(Some(&root), true), 0);
    }

    #[test]
    fn integration_quiet_errors_exits_2() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        )]);
        assert_eq!(run(Some(&root), true), 2);
    }

    #[test]
    fn integration_quiet_clean_exits_0() {
        let root = write_fixture(&[(
            "PreToolUse",
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#,
        )]);
        assert_eq!(run(Some(&root), true), 0);
    }
}
