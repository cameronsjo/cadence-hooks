//! Interactive configuration wizard for per-project hook disabling.
//!
//! Reads/writes `.claude/settings.json` in the project root, merging the
//! `CADENCE_DISABLE` env var into the existing `env` block without
//! clobbering other settings.

use crate::HookEntry;
use cadence_hooks_core::bypass;
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

/// Read the raw `CADENCE_DISABLE` string from settings.json, unparsed.
///
/// `None` covers a missing file, unparseable JSON, and a missing or
/// non-string value — every case where settings.json names nothing. Parsing
/// the raw string into hook names is `cadence_hooks_core::bypass::disable_list`'s
/// job, done once inside [`crate::bypass_report::configure_status_lines`], so
/// this surface and the resolver cannot disagree about what counts as an
/// entry.
fn read_settings_disable_raw(settings_path: &Path) -> Option<String> {
    let content = fs::read_to_string(settings_path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    json.get("env")
        .and_then(|env| env.get("CADENCE_DISABLE"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
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
            Err(e) => return Err(format!("Failed to parse {}: {e}", settings_path.display())),
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
        env_map.remove("CADENCE_DISABLE");
        // Clean up empty env block
        if env_map.is_empty() {
            root.remove("env");
        }
    } else {
        env_map.insert(
            "CADENCE_DISABLE".to_string(),
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
///
/// Renders through [`crate::bypass_report::configure_status_lines`], the same
/// module `list` and `doctor` render from, so this surface cannot report a
/// protected guard as disabled while the binary refuses that entry — and cannot
/// echo an unrecognized name from `settings.json` unsanitized.
///
/// Reads both `CADENCE_DISABLE` sources — the settings file and the live
/// session's environment — plus `CADENCE_BYPASS`, so this report describes
/// what the binary actually does in *this* invocation rather than only what
/// is written to disk (cameronsjo/cadence-hooks#929).
fn print_config(settings_path: &Path, hooks: &[HookEntry]) {
    let settings_raw = read_settings_disable_raw(settings_path);
    let env_raw = std::env::var(bypass::DISABLE_VAR).ok();
    let bypass_raw = std::env::var(bypass::BYPASS_VAR).ok();

    println!("Settings: {}", settings_path.display());

    let settings_empty = settings_raw.as_deref().is_none_or(str::is_empty);
    let env_empty = env_raw.as_deref().is_none_or(str::is_empty);
    if !bypass::bypass_engaged_from(bypass_raw.as_deref()) && settings_empty && env_empty {
        println!("\nAll hooks enabled (no overrides).");
        return;
    }

    let (lines, active) = crate::bypass_report::configure_status_lines(
        hooks,
        settings_raw.as_deref(),
        env_raw.as_deref(),
        bypass_raw.as_deref(),
    );
    for line in lines {
        // A heading opens its own block; an indented row stays with the heading
        // above it.
        if line.starts_with("  ") {
            println!("{line}");
        } else {
            println!("\n{line}");
        }
    }

    println!("\n{} of {} hooks active.", active, hooks.len());
}

/// Run the configure wizard (or --list mode).
pub fn run(list_only: bool, hooks: &[HookEntry]) -> ! {
    let settings_path = find_settings_path();

    if list_only {
        print_config(&settings_path, hooks);
        process::exit(0);
    }

    // The wizard writes settings.json only, and pre-selects only what is
    // already written there. Pre-selecting an environment-sourced name too
    // would let one confirm round-trip persist a session variable into a
    // committed file — the one place this fix could do damage — so the
    // environment is deliberately not consulted here.
    let currently_disabled: Vec<String> = read_settings_disable_raw(&settings_path)
        .map(|raw| bypass::disable_list(&raw).map(str::to_string).collect())
        .unwrap_or_default();

    // Build items for the multi-select — only real hooks, no separators.
    // The namespace is prefixed to each item for visual grouping.
    let mut items: Vec<String> = Vec::new();
    let mut defaults: Vec<bool> = Vec::new();
    let mut hook_names: Vec<&str> = Vec::new();

    for hook in hooks {
        items.push(format!(
            "[{:<10}] {:<28} {}",
            hook.namespace, hook.name, hook.description
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
                println!("\nAll hooks enabled. Removed CADENCE_DISABLE from settings.");
            } else {
                println!(
                    "\nDisabled {} hook(s): {}",
                    new_disabled.len(),
                    new_disabled.join(", ")
                );
                println!("Written to: {}", settings_path.display());
                // The wizard offers every registered hook, protected ones
                // included, and persists whatever was picked. CADENCE_DISABLE
                // cannot switch a protected guard off, so without this line the
                // wizard's own confirmation would be the operator's last word
                // on a request the binary refuses at runtime. A notice rather
                // than a filtered list: the selection is still written, and a
                // guard the operator asked about stays visible in the picker.
                let refused: Vec<&str> = new_disabled
                    .iter()
                    .map(String::as_str)
                    .filter(|name| cadence_hooks_core::bypass::is_protected(name))
                    .collect();
                if !refused.is_empty() {
                    let (is_are, it_they, runs) = if refused.len() == 1 {
                        ("is", "it", "runs")
                    } else {
                        ("are", "they", "run")
                    };
                    println!(
                        "Note: {} {is_are} protected — CADENCE_DISABLE is refused there, so \
                         {it_they} still {runs}.",
                        refused.join(", ")
                    );
                }
            }
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
