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
    let plugins = [
        "cadence",
        "guardrails",
        "rules",
        "obsidian",
        "metrics",
        "lab",
        "session",
    ];
    let mut commands = BTreeSet::new();

    for plugin in plugins {
        let output = Command::new(bin)
            .args([plugin, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run `{bin} {plugin} --help`: {e}"));

        let stdout = String::from_utf8_lossy(&output.stdout);
        // clap help layout: about text, "Usage:", then a "Commands:" section,
        // then "Options:". Only lines inside the Commands section name
        // subcommands — the about text can contain hyphenated words (e.g.
        // "Multi-session coordination hooks") that would otherwise parse as
        // subcommand names.
        let mut in_commands = false;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Commands:") {
                in_commands = true;
                continue;
            }
            if !in_commands {
                continue;
            }
            if trimmed.starts_with("Options:") {
                break;
            }
            if trimmed.is_empty() || trimmed.starts_with('-') {
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
    /// The hook event type from hooks.json (e.g., "PreToolUse", "PostToolUse")
    event_type: String,
}

/// Plugin directories that dispatch to the cadence-hooks binary via run-cadence-hooks.sh.
/// (dir_name, expected_plugin_group)
const BINARY_PLUGIN_DIRS: &[(&str, &str)] = &[
    ("cadence", "cadence"),
    ("cadence-canon", "session"),
    ("cadence-guardrails", "guardrails"),
    ("cadence-lab", "lab"),
    ("cadence-metrics", "metrics"),
    ("cadence-rules", "rules"),
];

/// Plugin directories that still use shell script wrappers (not yet migrated to binary).
/// These are tracked so the "all subcommands registered" test knows they exist.
const SHELL_PLUGIN_DIRS: &[(&str, &str)] = &[("cadence-obsidian", "obsidian")];

/// Plugin groups whose consuming plugin repo does not exist yet. Their hook
/// subcommands are expected to be unregistered until the plugin lands —
/// remove the entry in the plugin's wiring PR.
/// (group, tracking_reference)
///
/// Currently empty: cadence-canon landed and wires the `session` group.
const PENDING_PLUGIN_GROUPS: &[(&str, &str)] = &[];

/// Bash-matcher hooks that intentionally inspect every command (no `if` filter).
/// These run broad pattern matching internally and can't be narrowed to a single glob.
const INTENTIONAL_UNFILTERED_BASH_HOOKS: &[&str] = &[
    "cadence git-safety",            // catches force-push, reset --hard, etc.
    "cadence prevent-secret-writes", // catches writes to .env, credentials, etc.
    "cadence prevent-secret-leaks",  // catches reads of secrets
    "cadence warn-docs-update",      // catches gh pr create
];

/// Binary subcommands that are user-facing CLI actions, not hooks. They have
/// no PreToolUse/PostToolUse wiring and should not appear in any hooks.json.
const NON_HOOK_BINARY_SUBCOMMANDS: &[&str] = &[
    // Per-repo snooze writer for warn-main-branch — invoked by hand, not by Claude Code.
    "guardrails dismiss-main-branch-warn",
    // Lane declaration + registry listing — invoked by the coordination skill / user.
    "session declare",
    "session status",
];

/// settings.json shell scripts that trip the keyword-overlap heuristic but are
/// NOT duplicates of plugin hooks. Each entry documents the distinction.
const KNOWN_DISTINCT_SETTINGS_SCRIPTS: &[&str] = &[
    // Blocks git writes inside the *Obsidian* vault working copy. Shares the
    // filename tokens "vault" (with `guardrails guard-op-vault-scan` — a
    // *1Password* vault check) and "writes" (with `cadence
    // prevent-secret-writes`), but duplicates neither.
    "block-vault-git-writes.sh",
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

    result
}

fn parse_hooks_json(content: &str, _source_dir: &str, expected_plugin: &str) -> Vec<HookRef> {
    let json: serde_json::Value =
        serde_json::from_str(content).expect("hooks.json should be valid JSON");

    let mut refs = Vec::new();

    let Some(hooks_obj) = json.get("hooks").and_then(serde_json::Value::as_object) else {
        return refs;
    };

    for (event, matchers) in hooks_obj {
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
                    event_type: event.clone(),
                });
            }
        }
    }

    refs
}

/// Extract `<plugin> <subcommand>` from a hook command string like:
/// `'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails warn-untracked`
/// or `"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails warn-untracked`.
///
/// Strips both single and double trailing shell-quote characters so the
/// audit works regardless of which quoting style the plugin's hooks.json
/// uses around `${CLAUDE_PLUGIN_ROOT}`.
fn extract_dispatch(command: &str) -> Option<String> {
    if !command.contains("run-cadence-hooks") {
        return None;
    }
    let after = command.split("run-cadence-hooks.sh").last()?;
    let trimmed = after.trim().trim_start_matches(['\'', '"']).trim();
    if trimmed.is_empty() {
        return None;
    }
    // Keep only the `<plugin> <subcommand>` identity, dropping any trailing
    // flags/args — e.g. `metrics log-commit --prices "${CLAUDE_PLUGIN_ROOT}/...`
    // normalizes to `metrics log-commit`. The binary's subcommand identity (what
    // `<plugin> --help` enumerates) never includes runtime flags, so a flagged
    // dispatch must compare against the bare pair.
    let identity: Vec<&str> = trimmed.split_whitespace().take(2).collect();
    if identity.len() < 2 {
        return None;
    }
    Some(identity.join(" "))
}

/// Parse user-level settings.json and extract all hook shell script paths and
/// any cadence-hooks binary dispatches registered there.
fn settings_json_hooks() -> (Vec<String>, Vec<String>) {
    // No resolvable home (e.g. a Windows CI runner with no `~/.claude`) means
    // there is nothing registered to audit — no-op rather than panic.
    let Some(home) = cadence_hooks_core::paths::user_home() else {
        return (Vec::new(), Vec::new());
    };
    let settings_path = home.join(".claude/settings.json");

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

/// Skip test when plugin hooks.json files aren't present (e.g., bare CI checkout
/// without sibling plugin directories).
macro_rules! require_plugin_refs {
    ($refs:ident) => {
        let $refs = hooks_json_references();
        if $refs.is_empty() {
            eprintln!(
                "SKIPPED: no plugin hooks.json files found (plugin dirs not alongside workspace)"
            );
            return;
        }
    };
}

#[test]
fn all_registered_hooks_exist_in_binary() {
    let binary_cmds = binary_subcommands();
    require_plugin_refs!(all_refs);

    let mut missing = Vec::new();
    for (dir, refs) in &all_refs {
        for r in refs {
            if !binary_cmds.contains(&r.command) {
                missing.push(format!(
                    "  {dir}/hooks.json -> `{}` (not in binary)",
                    r.command
                ));
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
    require_plugin_refs!(all_refs);

    let registered: BTreeSet<String> = all_refs
        .values()
        .flat_map(|refs| refs.iter().map(|r| r.command.clone()))
        .collect();

    // Subcommands for plugins still using shell wrappers are expected to be unregistered.
    // They'll be migrated to binary dispatch later.
    let shell_plugin_groups: BTreeSet<&str> =
        SHELL_PLUGIN_DIRS.iter().map(|(_, group)| *group).collect();

    // Subcommands for plugins that don't exist yet are also expected to be
    // unregistered — but only while the plugin *directory* is actually absent
    // from the workspace parent. The exemption keys off directory existence
    // (not hooks.json existence) so a checked-out plugin with missing wiring
    // fails the audit instead of hiding behind the exemption. Remove the
    // PENDING_PLUGIN_GROUPS entry in the plugin's wiring PR.
    let workspace_parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cadence-hooks should be inside claude-configurations")
        .to_path_buf();
    let pending_groups: BTreeSet<&str> = PENDING_PLUGIN_GROUPS
        .iter()
        .filter(|(group, _)| {
            !BINARY_PLUGIN_DIRS
                .iter()
                .any(|(dir, g)| g == group && workspace_parent.join(dir).is_dir())
        })
        .map(|(group, _)| *group)
        .collect();

    let unregistered: Vec<&String> = binary_cmds
        .iter()
        .filter(|cmd| !registered.contains(*cmd))
        .filter(|cmd| {
            let group = cmd.split_whitespace().next().unwrap_or("");
            !shell_plugin_groups.contains(group) && !pending_groups.contains(group)
        })
        .filter(|cmd| !NON_HOOK_BINARY_SUBCOMMANDS.contains(&cmd.as_str()))
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
    require_plugin_refs!(all_refs);

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
    require_plugin_refs!(all_refs);

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
    require_plugin_refs!(all_refs);
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
    // e.g., "nudge-untracked-on-commit.sh" overlaps with "warn-untracked" via the
    // keyword `untracked`.
    //
    // Tokenize the filename on word boundaries and require **exact-token** matches
    // against plugin keywords. Substring matching produced false positives where
    // unrelated subcommands shared a stem — e.g. `block-vault-git-writes.sh`
    // matched both `writes` (from `prevent-secret-writes`) and `write` (from
    // `guard-gh-write`) as substrings, even though `write` is not a token in
    // the filename.
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
        if KNOWN_DISTINCT_SETTINGS_SCRIPTS.contains(&filename.as_str()) {
            continue;
        }
        let filename_tokens: BTreeSet<String> = filename
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
        let matching_keywords: Vec<&&str> = plugin_keywords
            .iter()
            .filter(|kw| filename_tokens.contains(**kw))
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

/// Parse main.rs to extract which HookEvent each subcommand uses.
/// Returns a map of "plugin subcommand" -> "PreToolUse" or "PostToolUse".
fn main_rs_event_types() -> BTreeMap<String, String> {
    let main_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let content =
        std::fs::read_to_string(&main_rs).unwrap_or_else(|e| panic!("failed to read main.rs: {e}"));

    let mut result = BTreeMap::new();

    // Find `dispatch::run_logged_check(&module::Check, pre, canonical_hook)` (the
    // logged-dispatch wrapper that records denials) or the legacy
    // `run_check_from_stdin(&..., pre)` form. The event variable (`pre`/`post`/
    // `session`) sits in the same position in both — the trailing `canonical_hook`
    // arg lands beyond the 3-line correlation window, so the event scan is
    // unaffected. We correlate with the match arm above to get the subcommand.
    //
    // Strategy: scan for lines containing the dispatch call, extract the event
    // variable, then look backwards for the enum variant.

    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("run_logged_check") && !line.contains("run_check_from_stdin") {
            continue;
        }

        // Determine event type from the last argument. After rustfmt, the event
        // variable (pre/post) may be on the same line, or up to 2 lines below
        // when the call is split across multiple lines. Collapse whitespace so
        // `,\n                pre,` becomes `, pre,`.
        let window: String = lines[i..std::cmp::min(i + 3, lines.len())]
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let event = if window.contains(", post") || window.contains("post)") {
            "PostToolUse"
        } else if window.contains(", session") || window.contains("session)") {
            "SessionStart"
        } else if window.contains(", pre") || window.contains("pre)") {
            "PreToolUse"
        } else {
            continue;
        };

        // Look backwards for the enum variant (e.g., `GuardrailsCommands::WarnUntracked`)
        for j in (0..=i).rev() {
            let prev = lines[j];
            if prev.contains("Commands::") {
                // Extract the variant name, convert to kebab-case subcommand.
                //
                // rustfmt collapses a single-expression arm onto one line
                // (`CadenceCommands::Terminology => dispatch::run_logged_check(`),
                // so the arm line also carries the `dispatch::run_logged_check`
                // call — `split("::").last()` would grab the call token. Take the
                // identifier immediately after the FIRST `Commands::` instead;
                // this reads the variant cleanly from both the collapsed form and
                // the older `Variant => {` block form.
                let after = prev.split("Commands::").nth(1).unwrap_or("");
                let variant: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let subcmd = to_kebab_case(&variant);

                // Determine plugin group from the Commands enum.
                //
                // Logger-dispatched hooks (metrics, session heartbeat) use
                // run_logger_from_stdin and carry no HookEvent, so they
                // never reach this scan — only Check-dispatched hooks are
                // mapped here.
                let plugin = if prev.contains("CadenceCommands") {
                    "cadence"
                } else if prev.contains("GuardrailsCommands") {
                    "guardrails"
                } else if prev.contains("RulesCommands") {
                    "rules"
                } else if prev.contains("ObsidianCommands") {
                    "obsidian"
                } else if prev.contains("LabCommands") {
                    "lab"
                } else if prev.contains("SessionCommands") {
                    "session"
                } else {
                    continue;
                };

                result.insert(format!("{plugin} {subcmd}"), event.to_string());
                break;
            }
        }
    }

    assert!(
        result.len() > 10,
        "expected at least 10 event type mappings, found {}: {result:?}",
        result.len()
    );
    result
}

/// Convert PascalCase to kebab-case (e.g., "WarnMainBranch" -> "warn-main-branch").
fn to_kebab_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('-');
            }
            result.push(c.to_lowercase().next().unwrap());
        } else {
            result.push(c);
        }
    }
    result
}

#[test]
fn hook_event_types_match_hooks_json() {
    let main_events = main_rs_event_types();
    require_plugin_refs!(all_refs);

    let mut mismatches = Vec::new();
    for refs in all_refs.values() {
        for r in refs {
            if let Some(main_event) = main_events.get(&r.command)
                && main_event != &r.event_type
            {
                mismatches.push(format!(
                    "  `{}`: hooks.json says {} but main.rs passes HookEvent::{}",
                    r.command, r.event_type, main_event
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "Hook event type mismatch between hooks.json and main.rs:\n{}\n\n\
         The HookEvent passed to run_check_from_stdin must match the event key \
         in hooks.json. PreToolUse hooks emit PreToolUse JSON, PostToolUse hooks \
         emit PostToolUse JSON — using the wrong one means additionalContext \
         won't reach the model.",
        mismatches.join("\n")
    );
}

/// Parse the `NS='...'` single-quoted pipe-alternation line out of the
/// sibling plugin's `redact-check.sh`. Matched by the `NS='` prefix, never
/// by line number, so the script can grow unrelated lines above or below it
/// without breaking this parse.
fn parse_redact_check_namespaces(content: &str) -> Vec<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("NS='")
            && let Some(list) = rest.strip_suffix('\'')
        {
            return list.split('|').map(str::to_string).collect();
        }
    }
    Vec::new()
}

#[test]
fn namespace_list_matches_redact_check_sh() {
    // Sibling plugin script that carries a bash-side copy of the same
    // namespace list used to build `redact_external_content::NAMESPACES`.
    // Resolved the same way as the plugin hooks.json siblings above — skip
    // (not fail) when the sibling checkout isn't present, e.g. bare CI.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cadence-hooks should be inside claude-configurations")
        .to_path_buf();
    let script_path =
        workspace_root.join("cadence/plugins/cadence/skills/redaction/scripts/redact-check.sh");

    if !script_path.exists() {
        eprintln!(
            "SKIPPED: sibling redact-check.sh not found at {} (plugin dir not alongside workspace)",
            script_path.display()
        );
        return;
    }

    let content = std::fs::read_to_string(&script_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", script_path.display()));

    let script_namespaces: BTreeSet<String> = parse_redact_check_namespaces(&content)
        .into_iter()
        .collect();
    assert!(
        !script_namespaces.is_empty(),
        "failed to find a `NS='...'` line in {}",
        script_path.display()
    );

    let rust_namespaces: BTreeSet<String> =
        cadence_hooks_cadence::redact_external_content::NAMESPACES
            .iter()
            .map(|s| s.to_string())
            .collect();

    let missing_from_script: Vec<&String> =
        rust_namespaces.difference(&script_namespaces).collect();
    let missing_from_rust: Vec<&String> = script_namespaces.difference(&rust_namespaces).collect();

    assert!(
        missing_from_script.is_empty() && missing_from_rust.is_empty(),
        "namespace list drift between Rust NAMESPACES and {}'s `NS=` line:\n\
         in Rust but missing from redact-check.sh: {:?}\n\
         in redact-check.sh but missing from Rust: {:?}",
        script_path.display(),
        missing_from_script,
        missing_from_rust,
    );
}

#[test]
fn settings_json_shell_scripts_exist() {
    let (shell_scripts, _) = settings_json_hooks();
    // Empty means no registered hooks to verify (no `~/.claude/settings.json`,
    // or no resolvable home on this platform) — nothing to assert.
    if shell_scripts.is_empty() {
        return;
    }
    let home = cadence_hooks_core::paths::user_home()
        .expect("settings_json_hooks returned scripts, so a home dir resolved")
        .to_string_lossy()
        .into_owned();

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
