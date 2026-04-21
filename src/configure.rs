//! Interactive configuration wizard for per-project hook disabling.
//!
//! Reads/writes `.claude/settings.json` in the project root, merging the
//! `CADENCE_HOOKS_DISABLE` env var into the existing `env` block without
//! clobbering other settings.

use crate::HookEntry;
use dialoguer::MultiSelect;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::{fs, process};

/// Locate `.claude/settings.json` — walk up from CWD to find a git root,
/// then use `<root>/.claude/settings.json`. Falls back to CWD if no git root.
fn find_settings_path() -> PathBuf {
    let start = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Walk up looking for .git directory (project root)
    let mut dir = start.as_path();
    loop {
        if dir.join(".git").exists() {
            return dir.join(".claude/settings.json");
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    // No git root found — use CWD
    start.join(".claude/settings.json")
}

/// Read the current `CADENCE_HOOKS_DISABLE` value from settings.json.
fn read_disabled_hooks(settings_path: &Path) -> Vec<String> {
    let content = match fs::read_to_string(settings_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    json.get("env")
        .and_then(|env| env.get("CADENCE_HOOKS_DISABLE"))
        .and_then(|v| v.as_str())
        .map(|s| {
            s.split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Write the disabled hooks list back to settings.json, merging into existing content.
fn write_disabled_hooks(settings_path: &Path, disabled: &[String]) -> Result<(), String> {
    // Read existing settings or start fresh
    let mut root: Map<String, Value> = if settings_path.exists() {
        let content = fs::read_to_string(settings_path)
            .map_err(|e| format!("Failed to read {}: {e}", settings_path.display()))?;
        match serde_json::from_str(&content) {
            Ok(Value::Object(map)) => map,
            Ok(_) => return Err(format!("{} is not a JSON object", settings_path.display())),
            // Empty or invalid — start fresh
            Err(_) => Map::new(),
        }
    } else {
        Map::new()
    };

    // Get or create the `env` block
    let env = root
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    let env_map = env
        .as_object_mut()
        .ok_or_else(|| format!("`env` in {} is not an object", settings_path.display()))?;

    if disabled.is_empty() {
        env_map.remove("CADENCE_HOOKS_DISABLE");
        // Clean up empty env block
        if env_map.is_empty() {
            root.remove("env");
        }
    } else {
        env_map.insert(
            "CADENCE_HOOKS_DISABLE".to_string(),
            Value::String(disabled.join(",")),
        );
    }

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }

    let output = serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;

    fs::write(settings_path, output + "\n")
        .map_err(|e| format!("Failed to write {}: {e}", settings_path.display()))?;

    Ok(())
}

/// Print current configuration without interactive mode.
fn print_config(settings_path: &Path, hooks: &[HookEntry]) {
    let disabled = read_disabled_hooks(settings_path);

    println!("Settings: {}", settings_path.display());

    if disabled.is_empty() {
        println!("\nAll hooks enabled (no overrides).");
        return;
    }

    println!("\nDisabled hooks:");
    for name in &disabled {
        // Find description from catalog
        let desc = hooks
            .iter()
            .find(|h| h.name == name)
            .map(|h| h.description)
            .unwrap_or("(unknown hook)");
        println!("  {name:<28} {desc}");
    }

    let enabled_count = hooks.len()
        - disabled
            .iter()
            .filter(|d| hooks.iter().any(|h| h.name == d.as_str()))
            .count();
    println!("\n{} of {} hooks active.", enabled_count, hooks.len());
}

/// Run the configure wizard (or --list mode).
pub fn run(list_only: bool, hooks: &[HookEntry]) -> ! {
    let settings_path = find_settings_path();

    if list_only {
        print_config(&settings_path, hooks);
        process::exit(0);
    }

    let currently_disabled = read_disabled_hooks(&settings_path);

    // Build items for the multi-select — only real hooks, no separators.
    // Plugin name is prefixed to each item for visual grouping.
    let mut items: Vec<String> = Vec::new();
    let mut defaults: Vec<bool> = Vec::new();
    let mut hook_names: Vec<&str> = Vec::new();

    for hook in hooks {
        items.push(format!(
            "[{:<10}] {:<28} {}",
            hook.plugin, hook.name, hook.description
        ));
        // Pre-select hooks that are currently DISABLED (user is selecting what to disable)
        defaults.push(currently_disabled.iter().any(|d| d == hook.name));
        hook_names.push(hook.name);
    }

    println!("Configure cadence-hooks for: {}", settings_path.display());
    println!("Select hooks to DISABLE (space to toggle, enter to confirm):\n");

    let selections = match MultiSelect::new()
        .items(&items)
        .defaults(&defaults)
        .interact_opt()
    {
        Ok(Some(sel)) => sel,
        Ok(None) | Err(_) => {
            println!("Cancelled.");
            process::exit(0);
        }
    };

    let new_disabled: Vec<String> = selections
        .into_iter()
        .map(|i| hook_names[i].to_string())
        .collect();

    // Write result
    match write_disabled_hooks(&settings_path, &new_disabled) {
        Ok(()) => {
            if new_disabled.is_empty() {
                println!("\nAll hooks enabled. Removed CADENCE_HOOKS_DISABLE from settings.");
            } else {
                println!(
                    "\nDisabled {} hook(s): {}",
                    new_disabled.len(),
                    new_disabled.join(", ")
                );
                println!("Written to: {}", settings_path.display());
            }
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
