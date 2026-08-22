//! `configure guardrails` — the git-guardrails identity allowlist.
//!
//! Writes `CADENCE_ALLOWED_OWNERS` (required) and `CADENCE_ALLOWED_REPOS`
//! (optional) into the `env` block of the **user-level** settings.json,
//! migrating the legacy `GIT_GUARDRAILS_ALLOWED_*` keys forward.
//!
//! **This is a different file from the rest of `configure`.** The hook-disable
//! wizard in [`crate::configure`] writes the *project* `.claude/settings.json`
//! (per-repo `CADENCE_DISABLE`); this writes the *user* settings file —
//! `$CLAUDE_CONFIG_DIR/settings.json`, else `~/.claude/settings.json`. The
//! allowlist is machine identity ("which GitHub accounts am I"), not per-repo
//! policy, and a project-local copy would both miss every other checkout and
//! let a cloned repository choose its own allowlist.
//!
//! Ported from the `cadence-guardrails:guardrails-init` plugin skill, which did
//! the same deterministic edit by prose (cameronsjo/cadence-hooks#275).

use dialoguer::{Confirm, Input};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::{fs, process};

/// The env key the guards actually read (`crates/core/src/config.rs`).
pub const OWNERS_KEY: &str = "CADENCE_ALLOWED_OWNERS";
/// Optional companion key for repos owned by someone else.
pub const REPOS_KEY: &str = "CADENCE_ALLOWED_REPOS";
/// Pre-0.8.0 name for [`OWNERS_KEY`]. No longer read by the binary.
pub const LEGACY_OWNERS_KEY: &str = "GIT_GUARDRAILS_ALLOWED_OWNERS";
/// Pre-0.8.0 name for [`REPOS_KEY`]. No longer read by the binary.
pub const LEGACY_REPOS_KEY: &str = "GIT_GUARDRAILS_ALLOWED_REPOS";

/// Path to the user-level settings.json, honoring `CLAUDE_CONFIG_DIR`.
pub fn user_settings_path() -> PathBuf {
    cadence_hooks_core::paths::claude_config_dir().join("settings.json")
}

/// Split an allowlist value into entries the way the guards do — on spaces or
/// commas — trimming blanks and dropping later duplicates.
///
/// Case is preserved here even though `parse_allow_entry` lowercases at match
/// time: the settings file is a human-edited artifact and `CameronSjo` should
/// read back as the user typed it.
pub fn parse_entries(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in raw.split([' ', ',', '\t', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() || out.iter().any(|e| e.eq_ignore_ascii_case(entry)) {
            continue;
        }
        out.push(entry.to_string());
    }
    out
}

/// Reject an allowlist entry that the guards could not match, or that would
/// silently split into two entries once written.
///
/// Accepts the three forms `parse_allow_entry` understands — `owner`,
/// `owner/repo` (or `host/owner`), and `host/owner/repo` — over the character
/// set GitHub allows in a login or repo name, plus `.` and `:` for a host.
/// Validation matters because a bad value does not fail loudly: it becomes a
/// junk allowlist entry that silently never matches, and the user reads the
/// resulting block as a guard bug.
pub fn validate_entry(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("empty entry".to_string());
    }
    let segments: Vec<&str> = entry.split('/').collect();
    if segments.len() > 3 {
        return Err(format!(
            "'{entry}' has too many '/' segments — expected owner, owner/repo, or host/owner/repo"
        ));
    }
    for segment in &segments {
        if segment.is_empty() {
            return Err(format!("'{entry}' has an empty '/' segment"));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return Err(format!(
                "'{entry}' contains characters that are not valid in a GitHub owner, repo, or host name"
            ));
        }
    }
    Ok(())
}

/// Validate every entry, returning the first failure.
pub fn validate_entries(entries: &[String]) -> Result<(), String> {
    entries.iter().try_for_each(|e| validate_entry(e))
}

/// What the settings file currently says about the allowlist.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Current {
    pub owners: Vec<String>,
    pub repos: Vec<String>,
    pub legacy_owners: Vec<String>,
    pub legacy_repos: Vec<String>,
}

impl Current {
    /// True when the legacy keys are still present in the file.
    pub fn has_legacy(&self) -> bool {
        !self.legacy_owners.is_empty() || !self.legacy_repos.is_empty()
    }
}

/// Read the four allowlist keys out of a parsed settings object.
///
/// A non-string value (a number, an array) reads as absent — Claude Code's
/// `env` block only carries strings, and a wrong-typed value is not something
/// this should try to interpret.
pub fn current_from(root: &Map<String, Value>) -> Current {
    let read = |key: &str| -> Vec<String> {
        root.get("env")
            .and_then(|env| env.get(key))
            .and_then(Value::as_str)
            .map(parse_entries)
            .unwrap_or_default()
    };
    Current {
        owners: read(OWNERS_KEY),
        repos: read(REPOS_KEY),
        legacy_owners: read(LEGACY_OWNERS_KEY),
        legacy_repos: read(LEGACY_REPOS_KEY),
    }
}

/// Load a settings file into a JSON object. A missing file yields an empty
/// object; malformed JSON is an error, never a silent overwrite — this is a
/// write path, and clobbering a file we could not parse would destroy settings
/// that have nothing to do with the allowlist.
pub fn load_settings(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str(&content) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(format!(
            "{} is not a JSON object — fix it by hand before configuring guardrails",
            path.display()
        )),
        Err(e) => Err(format!(
            "{} is not valid JSON ({e}) — fix it by hand before configuring guardrails; \
             nothing was written",
            path.display()
        )),
    }
}

/// Merge the allowlist into `root`, returning one human-readable line per
/// change. An empty return means the file already says exactly this.
///
/// Everything outside the four keys is preserved: other `env` entries, and
/// every sibling of `env`.
pub fn apply(
    root: &mut Map<String, Value>,
    owners: &[String],
    repos: &[String],
) -> Result<Vec<String>, String> {
    let before = current_from(root);
    let mut changes = Vec::new();

    let env = root
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    let env = env
        .as_object_mut()
        .ok_or_else(|| "`env` in the settings file is not an object".to_string())?;

    if before.owners != owners {
        changes.push(format!(
            "{OWNERS_KEY}: {} -> {}",
            render_list(&before.owners),
            render_list(owners)
        ));
    }
    env.insert(OWNERS_KEY.to_string(), Value::String(owners.join(" ")));

    if before.repos != repos {
        changes.push(format!(
            "{REPOS_KEY}: {} -> {}",
            render_list(&before.repos),
            render_list(repos)
        ));
    }
    if repos.is_empty() {
        env.remove(REPOS_KEY);
    } else {
        env.insert(REPOS_KEY.to_string(), Value::String(repos.join(" ")));
    }

    for legacy in [LEGACY_OWNERS_KEY, LEGACY_REPOS_KEY] {
        if env.remove(legacy).is_some() {
            changes.push(format!("removed legacy {legacy} (no longer read)"));
        }
    }

    Ok(changes)
}

/// `(none)` for an empty list, space-joined entries otherwise.
fn render_list(entries: &[String]) -> String {
    if entries.is_empty() {
        "(none)".to_string()
    } else {
        entries.join(" ")
    }
}

/// Write the settings object back, creating the config dir if needed.
pub fn save(path: &Path, root: &Map<String, Value>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let output = serde_json::to_string_pretty(&Value::Object(root.clone()))
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    fs::write(path, output + "\n").map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

/// The GitHub login `gh` is authenticated as, or `None` when `gh` is missing,
/// unauthenticated, or answers with something that is not a usable login.
///
/// The only impure step in this module's decision path, kept behind one
/// function so every other path is testable without a `gh` on PATH.
fn detect_github_login() -> Option<String> {
    let output = process::Command::new("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let login = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if login.is_empty() || validate_entry(&login).is_err() {
        return None;
    }
    Some(login)
}

/// Print the current allowlist state and exit 0.
fn show(path: &Path, current: &Current) -> ! {
    println!("Settings: {}", path.display());
    println!("  {OWNERS_KEY:<30} {}", render_list(&current.owners));
    println!("  {REPOS_KEY:<30} {}", render_list(&current.repos));
    if current.has_legacy() {
        println!(
            "\nLegacy keys still present (no longer read by this binary):\n  \
             {LEGACY_OWNERS_KEY} {}\n  {LEGACY_REPOS_KEY} {}",
            render_list(&current.legacy_owners),
            render_list(&current.legacy_repos)
        );
    }
    if current.owners.is_empty() {
        println!(
            "\n{OWNERS_KEY} is unset — the push and gh-write guards block every \
             operation until it is set."
        );
    }
    process::exit(0);
}

/// Ask for a space-separated list, seeded with `default`.
fn prompt_list(prompt: &str, default: &[String]) -> Result<Vec<String>, String> {
    let raw: String = Input::new()
        .with_prompt(prompt)
        .with_initial_text(default.join(" "))
        .allow_empty(true)
        .interact_text()
        .map_err(|e| format!("prompt cancelled: {e}"))?;
    let entries = parse_entries(&raw);
    validate_entries(&entries)?;
    Ok(entries)
}

/// Resolve the owners to write: explicit flags win, then the file's own value,
/// then the migrated legacy value, then the detected `gh` identity.
fn seed_owners(flags: &[String], current: &Current, detected: Option<&str>) -> Vec<String> {
    if !flags.is_empty() {
        return flags.to_vec();
    }
    if !current.owners.is_empty() {
        return current.owners.clone();
    }
    if !current.legacy_owners.is_empty() {
        return current.legacy_owners.clone();
    }
    detected.map(|d| vec![d.to_string()]).unwrap_or_default()
}

/// Same precedence for repos, minus the identity fallback (there is no repo to
/// detect — the default is genuinely none).
fn seed_repos(flags: &[String], current: &Current) -> Vec<String> {
    if !flags.is_empty() {
        return flags.to_vec();
    }
    if !current.repos.is_empty() {
        return current.repos.clone();
    }
    current.legacy_repos.clone()
}

/// Run `configure guardrails`. Never returns.
///
/// `yes` takes whatever the flags and the existing file resolve to and writes
/// it with no prompting — the scriptable path. Without it the resolved values
/// become the prompt defaults.
pub fn run(owner_flags: Vec<String>, repo_flags: Vec<String>, yes: bool, show_only: bool) -> ! {
    let path = user_settings_path();

    let mut root = match load_settings(&path) {
        Ok(root) => root,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };
    let current = current_from(&root);

    if show_only {
        show(&path, &current);
    }

    let owner_flags = parse_entries(&owner_flags.join(" "));
    let repo_flags = parse_entries(&repo_flags.join(" "));
    if let Err(e) = validate_entries(&owner_flags).and_then(|()| validate_entries(&repo_flags)) {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    // Only shell out to `gh` when nothing else can supply an owner — an
    // already-configured machine should not pay for a network call.
    let needs_detect = owner_flags.is_empty() && current.owners.is_empty() && !current.has_legacy();
    let detected = if needs_detect {
        detect_github_login()
    } else {
        None
    };

    let mut owners = seed_owners(&owner_flags, &current, detected.as_deref());
    let mut repos = seed_repos(&repo_flags, &current);

    if !yes {
        // Already-configured re-run: report and offer to stop before prompting.
        if !current.owners.is_empty() {
            println!("Already configured in {}", path.display());
            println!("  {OWNERS_KEY:<30} {}", render_list(&current.owners));
            println!("  {REPOS_KEY:<30} {}", render_list(&current.repos));
            let reconfigure = Confirm::new()
                .with_prompt("Reconfigure?")
                .default(false)
                .interact_opt()
                .unwrap_or(None);
            if reconfigure != Some(true) {
                if current.has_legacy() {
                    println!(
                        "\nNote: legacy {LEGACY_OWNERS_KEY}/{LEGACY_REPOS_KEY} keys are still \
                         present and no longer read. Re-run and choose Reconfigure to remove them."
                    );
                }
                println!("No changes.");
                process::exit(0);
            }
        } else if detected.is_none() && owners.is_empty() {
            println!(
                "Could not detect a GitHub identity ('gh api user' unavailable or \
                 unauthenticated) — enter it below."
            );
        }

        match prompt_list("GitHub users/orgs you own (space-separated)", &owners).and_then(|o| {
            let r = prompt_list(
                "Other owners' repos you have write access to, as owner/repo (blank for none)",
                &repos,
            )?;
            Ok((o, r))
        }) {
            Ok((o, r)) => {
                owners = o;
                repos = r;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    }

    if owners.is_empty() {
        eprintln!(
            "Error: {OWNERS_KEY} would be empty, and the guards block every push and \
             gh write when it is unset.\n\
             Pass --owners <github-user> [more...] or run without --yes to be prompted."
        );
        process::exit(1);
    }

    let changes = match apply(&mut root, &owners, &repos) {
        Ok(changes) => changes,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    if changes.is_empty() {
        println!(
            "Already configured: {OWNERS_KEY}={}, {REPOS_KEY}={}",
            render_list(&owners),
            render_list(&repos)
        );
        println!("Nothing to write ({}).", path.display());
        process::exit(0);
    }

    if let Err(e) = save(&path, &root) {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    println!("Wrote {}", path.display());
    for change in &changes {
        println!("  {change}");
    }
    println!("\nRestart Claude Code for the new env values to take effect.");
    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn owners(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_entries_splits_spaces_and_commas_and_dedupes() {
        assert_eq!(
            parse_entries("  cameronsjo, acme  cameronsjo\tother "),
            owners(&["cameronsjo", "acme", "other"])
        );
        assert!(parse_entries("   ").is_empty());
    }

    #[test]
    fn validate_entry_accepts_the_three_allowlist_forms() {
        for good in [
            "cameronsjo",
            "cameronsjo/repo",
            "git.example.com/owner/repo",
        ] {
            assert!(validate_entry(good).is_ok(), "{good} should be valid");
        }
    }

    #[test]
    fn validate_entry_rejects_junk_that_would_silently_never_match() {
        for bad in ["", "owner/", "a/b/c/d", "own er", "owner;rm -rf /", "$(id)"] {
            assert!(validate_entry(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn fresh_file_gets_both_keys_and_reports_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");

        let mut root = load_settings(&path).unwrap();
        let changes = apply(&mut root, &owners(&["cameronsjo"]), &owners(&["acme/tool"])).unwrap();
        save(&path, &root).unwrap();

        assert_eq!(changes.len(), 2, "owners + repos: {changes:?}");
        let written = load_settings(&path).unwrap();
        let current = current_from(&written);
        assert_eq!(current.owners, owners(&["cameronsjo"]));
        assert_eq!(current.repos, owners(&["acme/tool"]));
    }

    #[test]
    fn existing_settings_are_preserved() {
        let (_dir, path) = settings(
            r#"{
              "model": "opus",
              "env": { "SOMETHING_ELSE": "keep-me", "CADENCE_DISABLE": "guard-rm" }
            }"#,
        );

        let mut root = load_settings(&path).unwrap();
        apply(&mut root, &owners(&["cameronsjo"]), &[]).unwrap();
        save(&path, &root).unwrap();

        let written = load_settings(&path).unwrap();
        assert_eq!(written.get("model").unwrap().as_str(), Some("opus"));
        let env = written.get("env").unwrap().as_object().unwrap();
        assert_eq!(env.get("SOMETHING_ELSE").unwrap().as_str(), Some("keep-me"));
        assert_eq!(
            env.get("CADENCE_DISABLE").unwrap().as_str(),
            Some("guard-rm")
        );
        assert_eq!(env.get(OWNERS_KEY).unwrap().as_str(), Some("cameronsjo"));
        assert!(env.get(REPOS_KEY).is_none(), "empty repos removes the key");
    }

    #[test]
    fn legacy_keys_migrate_forward_and_are_removed() {
        let (_dir, path) = settings(
            r#"{"env": {
              "GIT_GUARDRAILS_ALLOWED_OWNERS": "cameronsjo acme",
              "GIT_GUARDRAILS_ALLOWED_REPOS": "other/tool"
            }}"#,
        );

        let mut root = load_settings(&path).unwrap();
        let current = current_from(&root);
        assert!(current.owners.is_empty(), "only the legacy keys are set");
        assert!(current.has_legacy());

        // The values the wizard would carry forward with no flags and no `gh`.
        let carried_owners = seed_owners(&[], &current, None);
        let carried_repos = seed_repos(&[], &current);
        assert_eq!(carried_owners, owners(&["cameronsjo", "acme"]));
        assert_eq!(carried_repos, owners(&["other/tool"]));

        let changes = apply(&mut root, &carried_owners, &carried_repos).unwrap();
        save(&path, &root).unwrap();

        assert_eq!(changes.len(), 4, "2 sets + 2 legacy removals: {changes:?}");
        let written = load_settings(&path).unwrap();
        let env = written.get("env").unwrap().as_object().unwrap();
        assert!(env.get(LEGACY_OWNERS_KEY).is_none());
        assert!(env.get(LEGACY_REPOS_KEY).is_none());
        assert_eq!(
            env.get(OWNERS_KEY).unwrap().as_str(),
            Some("cameronsjo acme")
        );
        assert_eq!(env.get(REPOS_KEY).unwrap().as_str(), Some("other/tool"));
    }

    #[test]
    fn re_running_with_identical_values_reports_no_changes() {
        let (_dir, path) = settings(
            r#"{"env": {"CADENCE_ALLOWED_OWNERS": "cameronsjo", "CADENCE_ALLOWED_REPOS": "acme/tool"}}"#,
        );

        let mut root = load_settings(&path).unwrap();
        let changes = apply(&mut root, &owners(&["cameronsjo"]), &owners(&["acme/tool"])).unwrap();

        assert!(changes.is_empty(), "idempotent re-run: {changes:?}");
    }

    #[test]
    fn malformed_json_errors_without_writing() {
        let (_dir, path) = settings("{ this is not json");
        let before = fs::read_to_string(&path).unwrap();

        let err = load_settings(&path).unwrap_err();

        assert!(err.contains("not valid JSON"), "{err}");
        assert!(err.contains("nothing was written"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn non_object_top_level_errors_rather_than_clobbering() {
        let (_dir, path) = settings("[1, 2, 3]");

        let err = load_settings(&path).unwrap_err();

        assert!(err.contains("not a JSON object"), "{err}");
    }

    #[test]
    fn missing_and_empty_files_start_from_a_blank_object() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            load_settings(&dir.path().join("absent.json"))
                .unwrap()
                .is_empty()
        );

        let (_dir, path) = settings("   \n");
        assert!(load_settings(&path).unwrap().is_empty());
    }

    #[test]
    fn wrong_typed_env_value_reads_as_absent() {
        let (_dir, path) = settings(r#"{"env": {"CADENCE_ALLOWED_OWNERS": ["cameronsjo"]}}"#);

        let current = current_from(&load_settings(&path).unwrap());

        assert!(current.owners.is_empty());
    }

    #[test]
    fn seed_owners_precedence_is_flags_then_file_then_legacy_then_detected() {
        let configured = Current {
            owners: owners(&["from-file"]),
            legacy_owners: owners(&["from-legacy"]),
            ..Current::default()
        };
        let legacy_only = Current {
            legacy_owners: owners(&["from-legacy"]),
            ..Current::default()
        };
        let empty = Current::default();

        assert_eq!(
            seed_owners(&owners(&["from-flag"]), &configured, Some("detected")),
            owners(&["from-flag"])
        );
        assert_eq!(
            seed_owners(&[], &configured, Some("detected")),
            owners(&["from-file"])
        );
        assert_eq!(
            seed_owners(&[], &legacy_only, Some("detected")),
            owners(&["from-legacy"])
        );
        assert_eq!(
            seed_owners(&[], &empty, Some("detected")),
            owners(&["detected"])
        );
        assert!(seed_owners(&[], &empty, None).is_empty());
    }
}
