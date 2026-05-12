//! Scan installed plugin `hooks.json` files for shell-expansion bugs.
//!
//! The single-quoted `${CLAUDE_PLUGIN_ROOT}` pattern survived in production
//! for months because the failure mode is silent: hooks return non-zero,
//! the harness logs "non-blocking", and nothing surfaces to the user.
//! Only `claude --doctor` exposes it, and most users never run it.
//!
//! This subcommand walks `~/.claude/plugins/cache/*/hooks/hooks.json`,
//! flags known shell-expansion patterns, and exits non-zero when violations
//! are found so it's usable as a CI check or a one-shot diagnostic.

use std::path::{Path, PathBuf};

/// Default scan root: Claude Code's installed-plugin cache.
fn default_root() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".claude/plugins/cache"))
}

/// One detected issue in a hook command.
struct Finding {
    plugin: String,
    file: PathBuf,
    snippet: String,
    diagnosis: &'static str,
    remediation: &'static str,
}

impl Finding {
    fn print(&self) {
        // <plugin>: <file>: <diagnosis>
        //   command: <snippet>
        //   fix: <remediation>
        println!(
            "{}: {}: {}\n  command: {}\n  fix: {}",
            self.plugin,
            self.file.display(),
            self.diagnosis,
            self.snippet,
            self.remediation
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

/// Walk a `hooks.json` blob's hook commands and collect findings.
fn scan_hooks_json(plugin: &str, path: &Path, json: &serde_json::Value) -> Vec<Finding> {
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
                if let Some(span) = detect_single_quoted_envvar(cmd) {
                    findings.push(Finding {
                        plugin: plugin.to_string(),
                        file: path.to_path_buf(),
                        snippet: span.to_string(),
                        diagnosis: "single-quoted env var won't expand in /bin/sh",
                        remediation: "switch the single quotes around the expansion to double quotes",
                    });
                }
            }
        }
    }

    findings
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
        findings.extend(scan_hooks_json(&plugin_name, &hooks_path, &json));
    }

    findings
}

/// Entry point for the `doctor` subcommand. Returns the process exit code
/// (0 clean, 1 violations found).
///
/// `root_override` lets tests redirect the scan; in normal use it's `None`
/// and we fall back to `$HOME/.claude/plugins/cache`.
pub fn run(root_override: Option<&Path>) -> u8 {
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

    if findings.is_empty() {
        println!("cadence-hooks doctor: clean ({} scanned)", root.display());
        return 0;
    }

    println!(
        "cadence-hooks doctor: {} finding(s) under {}:\n",
        findings.len(),
        root.display()
    );
    for finding in &findings {
        finding.print();
        println!();
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_single_quoted_braced_envvar() {
        let cmd = r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg"#;
        let span = detect_single_quoted_envvar(cmd).expect("should detect");
        // The span covers the whole single-quoted region, not just the var.
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
        // No var name after the dollar — likely a literal price or label.
        let cmd = "echo '$5 charge'";
        assert_eq!(detect_single_quoted_envvar(cmd), None);
    }
}
