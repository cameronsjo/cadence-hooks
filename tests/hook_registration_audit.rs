//! Audit test: cross-references binary subcommands against plugin hooks.json files.
//!
//! Catches drift between what the binary offers and what plugins actually wire up:
//! - Subcommands built but never registered in any hooks.json
//! - hooks.json entries referencing subcommands that don't exist in the binary
//! - Bash-matcher hooks missing an `if` filter (process spawn on every command)
//! - Cross-plugin hooks (plugin X dispatching plugin Y's subcommand)
//! - User-level settings.json duplicating hooks that plugins already provide

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

/// All valid `<plugin> <subcommand>` pairs the binary accepts.
/// Discovered by running `cadence-hooks <plugin> --help` for each plugin group.
fn binary_subcommands() -> BTreeSet<String> {
    let bin = env!("CARGO_BIN_EXE_cadence-hooks");
    let plugins = ["cadence", "guardrails", "rules", "obsidian"];
    let mut commands = BTreeSet::new();

    for plugin in plugins {
        let output = Command::new(bin)
            .args([plugin, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run `{bin} {plugin} --help`: {e}"));

        let stdout = String::from_utf8_lossy(&output.stdout);
        // clap help format: "  <subcommand>  <description>"
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("Usage:")
                || trimmed.starts_with("Options:")
                || trimmed.starts_with("Commands:")
                || trimmed == "help"
                || trimmed.starts_with('-')
            {
                continue;
            }
            if let Some(subcmd) = trimmed.split_whitespace().next() {
                // Skip clap's built-in "help" subcommand
                if subcmd == "help" {
                    continue;
                }
                if subcmd.contains('-') || subcmd.chars().all(|c| c.is_ascii_lowercase()) {
                    commands.insert(format!("{plugin} {subcmd}"));
                }
            }
        }
    }

    assert!(
        commands.len() > 10,
        "expected at least 10 subcommands, found {}: {commands:?}",
        commands.len()
    );
    commands
}

#[derive(Debug)]
struct HookRef {
    /// The full `<plugin> <subcommand>` string (e.g., "guardrails warn-untracked")
    command: String,
    /// The plugin group from the command (e.g., "guardrails")
    plugin: String,
    /// The expected plugin for this directory
    expected_plugin: String,
    /// Whether this hook has a matcher of "Bash"
    is_bash_matcher: bool,
    /// Whether this hook has an `if` filter
    has_if_filter: bool,
}

/// Plugin directories that dispatch to the cadence-hooks binary via run-cadence-hooks.sh.
/// (dir_name, expected_plugin_group)
const BINARY_PLUGIN_DIRS: &[(&str, &str)] = &[
    ("cadence", "cadence"),
    ("git-guardrails", "guardrails"),
];

/// Plugin directories that still use shell script wrappers (not yet migrated to binary).
/// These are tracked so the "all subcommands registered" test knows they exist.
const SHELL_PLUGIN_DIRS: &[(&str, &str)] = &[
    ("rules", "rules"),
    ("cadence-obsidian", "obsidian"),
];

/// Bash-matcher hooks that intentionally inspect every command (no `if` filter).
/// These run broad pattern matching internally and can't be narrowed to a single glob.
const INTENTIONAL_UNFILTERED_BASH_HOOKS: &[&str] = &[
    "cadence git-safety",          // catches force-push, reset --hard, etc.
    "cadence prevent-secret-writes", // catches writes to .env, credentials, etc.
    "cadence prevent-secret-leaks",  // catches reads of secrets
    "cadence warn-docs-update",      // catches gh pr create
];

/// Plugin name -> list of `<plugin> <subcommand>` strings referenced in its hooks.json.
fn hooks_json_references() -> BTreeMap<String, Vec<HookRef>> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cadence-hooks should be inside claude-configurations")
        .to_path_buf();

    let plugin_dirs = BINARY_PLUGIN_DIRS;

    let mut result = BTreeMap::new();

    for (dir_name, expected_plugin) in plugin_dirs {
        let hooks_path = workspace_root.join(dir_name).join("hooks/hooks.json");
        if !hooks_path.exists() {
            continue;
        }

        let content = std::fs::read_to_string(&hooks_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", hooks_path.display()));

        let refs = parse_hooks_json(&content, dir_name, expected_plugin);
        result.insert(dir_name.to_string(), refs);
    }

    assert!(
        !result.is_empty(),
        "no plugin hooks.json files found — is the workspace layout correct?"
    );
    result
}

fn parse_hooks_json(content: &str, _source_dir: &str, expected_plugin: &str) -> Vec<HookRef> {
    let json: serde_json::Value =
        serde_json::from_str(content).expect("hooks.json should be valid JSON");

    let mut refs = Vec::new();

    let Some(hooks_obj) = json.get("hooks").and_then(serde_json::Value::as_object) else {
        return refs;
    };

    for (_event, matchers) in hooks_obj {
        let Some(matchers) = matchers.as_array() else {
            continue;
        };
        for matcher_block in matchers {
            let matcher_str = matcher_block
                .get("matcher")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let is_bash = matcher_str == "Bash";

            let Some(hooks) = matcher_block
                .get("hooks")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for hook in hooks {
                let Some(cmd) = hook.get("command").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(pair) = extract_dispatch(cmd) else {
                    continue;
                };

                let has_if = hook.get("if").and_then(serde_json::Value::as_str).is_some();
                let plugin = pair.split_whitespace().next().unwrap_or("").to_string();

                refs.push(HookRef {
                    command: pair,
                    plugin,
                    expected_plugin: expected_plugin.to_string(),
                    is_bash_matcher: is_bash,
                    has_if_filter: has_if,
                });
            }
        }
    }

    refs
}

/// Extract `<plugin> <subcommand>` from a hook command string like:
/// `'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails warn-untracked`
fn extract_dispatch(command: &str) -> Option<String> {
    if !command.contains("run-cadence-hooks") {
        return None;
    }
    let after = command.split("run-cadence-hooks.sh").last()?;
    let trimmed = after.trim().trim_start_matches('\'').trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Parse user-level settings.json and extract all hook shell script paths and
/// any cadence-hooks binary dispatches registered there.
fn settings_json_hooks() -> (Vec<String>, Vec<String>) {
    let home = std::env::var("HOME").expect("HOME not set");
    let settings_path = PathBuf::from(&home).join(".claude/settings.json");

    if !settings_path.exists() {
        return (Vec::new(), Vec::new());
    }

    let content = std::fs::read_to_string(&settings_path)
        .unwrap_or_else(|e| panic!("failed to read settings.json: {e}"));

    let json: serde_json::Value =
        serde_json::from_str(&content).expect("settings.json should be valid JSON");

    let mut shell_scripts = Vec::new();
    let mut binary_dispatches = Vec::new();

    let Some(hooks_obj) = json.get("hooks").and_then(serde_json::Value::as_object) else {
        return (shell_scripts, binary_dispatches);
    };

    for (_event, matchers) in hooks_obj {
        let Some(matchers) = matchers.as_array() else {
            continue;
        };
        for matcher_block in matchers {
            // settings.json uses either top-level "hooks" array or nested structure
            let hook_entries = if let Some(hooks) = matcher_block
                .get("hooks")
                .and_then(serde_json::Value::as_array)
            {
                hooks.clone()
            } else if matcher_block.get("command").is_some() {
                vec![matcher_block.clone()]
            } else {
                continue;
            };

            for hook in &hook_entries {
                let Some(cmd) = hook.get("command").and_then(serde_json::Value::as_str) else {
                    continue;
                };

                if let Some(dispatch) = extract_dispatch(cmd) {
                    binary_dispatches.push(dispatch);
                } else {
                    shell_scripts.push(cmd.to_string());
                }
            }
        }
    }

    (shell_scripts, binary_dispatches)
}

// ---------- Tests ----------

#[test]
fn all_registered_hooks_exist_in_binary() {
    let binary_cmds = binary_subcommands();
    let all_refs = hooks_json_references();

    let mut missing = Vec::new();
    for (dir, refs) in &all_refs {
        for r in refs {
            if !binary_cmds.contains(&r.command) {
                missing.push(format!("  {dir}/hooks.json -> `{}` (not in binary)", r.command));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "hooks.json references subcommands not in the binary:\n{}",
        missing.join("\n")
    );
}

#[test]
fn all_binary_subcommands_are_registered() {
    let binary_cmds = binary_subcommands();
    let all_refs = hooks_json_references();

    let registered: BTreeSet<String> = all_refs
        .values()
        .flat_map(|refs| refs.iter().map(|r| r.command.clone()))
        .collect();

    // Subcommands for plugins still using shell wrappers are expected to be unregistered.
    // They'll be migrated to binary dispatch later.
    let shell_plugin_groups: BTreeSet<&str> = SHELL_PLUGIN_DIRS
        .iter()
        .map(|(_, group)| *group)
        .collect();

    let unregistered: Vec<&String> = binary_cmds
        .iter()
        .filter(|cmd| !registered.contains(*cmd))
        .filter(|cmd| {
            let group = cmd.split_whitespace().next().unwrap_or("");
            !shell_plugin_groups.contains(group)
        })
        .collect();

    assert!(
        unregistered.is_empty(),
        "binary subcommands not registered in any hooks.json:\n{}\n\n\
         Note: {} plugin(s) still use shell wrappers and are excluded from this check.",
        unregistered
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n"),
        SHELL_PLUGIN_DIRS.len()
    );
}

#[test]
fn no_cross_plugin_hooks() {
    let all_refs = hooks_json_references();

    let mut violations = Vec::new();
    for (dir, refs) in &all_refs {
        for r in refs {
            if r.plugin != r.expected_plugin {
                violations.push(format!(
                    "  {dir}/hooks.json dispatches `{}` (expected `{}` subcommands)",
                    r.command, r.expected_plugin
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "cross-plugin hook dispatch detected:\n{}\n\n\
         Each plugin should only dispatch its own subcommands.\n\
         Move the hook registration to the owning plugin's hooks.json.",
        violations.join("\n")
    );
}

#[test]
fn bash_hooks_have_if_filter() {
    let all_refs = hooks_json_references();

    let allowed: BTreeSet<&str> = INTENTIONAL_UNFILTERED_BASH_HOOKS.iter().copied().collect();

    let mut unfiltered = Vec::new();
    for (dir, refs) in &all_refs {
        for r in refs {
            if r.is_bash_matcher && !r.has_if_filter && !allowed.contains(r.command.as_str()) {
                unfiltered.push(format!(
                    "  {dir}/hooks.json -> `{}` (Bash matcher, no `if` filter)",
                    r.command
                ));
            }
        }
    }

    assert!(
        unfiltered.is_empty(),
        "Bash-matcher hooks without `if` filter spawn a process on every Bash command:\n{}\n\n\
         Either add an `if` field like `\"if\": \"Bash(*git push*)\"`,\n\
         or add to INTENTIONAL_UNFILTERED_BASH_HOOKS if broad matching is required.",
        unfiltered.join("\n")
    );
}

#[test]
fn no_plugin_hooks_duplicated_in_settings_json() {
    let all_refs = hooks_json_references();
    let (shell_scripts, binary_dispatches) = settings_json_hooks();

    // Collect all plugin-registered commands for comparison
    let plugin_commands: BTreeSet<String> = all_refs
        .values()
        .flat_map(|refs| refs.iter().map(|r| r.command.clone()))
        .collect();

    let mut duplicates = Vec::new();

    // Check if settings.json dispatches any cadence-hooks subcommands already in plugins
    for dispatch in &binary_dispatches {
        if plugin_commands.contains(dispatch) {
            duplicates.push(format!(
                "  settings.json dispatches `{dispatch}` (already registered in a plugin)"
            ));
        }
    }

    // Check if settings.json shell scripts overlap with binary subcommands by name.
    // e.g., "nudge-untracked-on-commit.sh" overlaps with "warn-untracked"
    // This is a fuzzy check — flag any shell script whose filename contains a keyword
    // that also appears in a plugin-registered command.
    let plugin_keywords: BTreeSet<&str> = plugin_commands
        .iter()
        .flat_map(|cmd| {
            cmd.split_whitespace()
                .nth(1) // the subcommand part
                .into_iter()
                .flat_map(|s| s.split('-'))
        })
        .filter(|kw| kw.len() > 3) // skip short words like "git", "gh"
        .collect();

    for script in &shell_scripts {
        let filename = script.rsplit('/').next().unwrap_or(script).to_lowercase();
        let matching_keywords: Vec<&&str> = plugin_keywords
            .iter()
            .filter(|kw| filename.contains(**kw))
            .collect();
        if matching_keywords.len() >= 2 {
            duplicates.push(format!(
                "  settings.json has `{script}` (keywords {:?} overlap with plugin hooks)",
                matching_keywords
            ));
        }
    }

    assert!(
        duplicates.is_empty(),
        "settings.json duplicates hooks already provided by plugins:\n{}\n\n\
         Remove from settings.json — plugins handle these via hooks.json.",
        duplicates.join("\n")
    );
}

#[test]
fn settings_json_shell_scripts_exist() {
    let (shell_scripts, _) = settings_json_hooks();
    let home = std::env::var("HOME").expect("HOME not set");

    let mut missing = Vec::new();
    for script in &shell_scripts {
        // Only check paths (contain / or ~), skip bare commands like "bd prime"
        if !script.contains('/') && !script.starts_with('~') {
            continue;
        }
        let expanded = script.replace('~', &home);
        if !PathBuf::from(&expanded).exists() {
            missing.push(format!("  {script} (file not found)"));
        }
    }

    assert!(
        missing.is_empty(),
        "settings.json references shell scripts that don't exist:\n{}",
        missing.join("\n")
    );
}
