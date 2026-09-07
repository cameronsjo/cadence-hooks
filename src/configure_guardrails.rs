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

/// Which key an entry is bound for. The two have different legal shapes, and
/// the consumer decides shape by content, so the distinction has to be checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `CADENCE_ALLOWED_OWNERS` — an owner-wide grant, `owner` or `host/owner`.
    Owner,
    /// `CADENCE_ALLOWED_REPOS` — one repo, `owner/repo` or `host/owner/repo`.
    Repo,
}

impl Kind {
    fn flag(self) -> &'static str {
        match self {
            Kind::Owner => "--owners",
            Kind::Repo => "--repos",
        }
    }
}

/// Reject an allowlist entry that the guards could not match, that would
/// silently split into two entries once written, or that resolves to a
/// *different shape* than the key it is bound for.
///
/// The shape check is a **round trip through the consumer**
/// (`cadence_hooks_core::config::parse_allow_entry`), not a re-implementation
/// of its rules — that function decides host-vs-owner on "does the first
/// segment contain a dot", so `foo.bar/tool` reads as host `foo.bar` owner
/// `tool` with no repo, and `github.com` reads as a bare owner literally named
/// `github.com`. Both are values a person would write on purpose and neither
/// can ever match anything; a bare owner also only matches `default_host`, so
/// a dot in one is dead by construction. Validation matters because none of
/// this fails loudly: a junk entry is silently never matched, and the guard
/// block that follows reads as a guard bug rather than as a typo.
pub fn validate_entry(entry: &str, kind: Kind) -> Result<(), String> {
    if entry.is_empty() {
        return Err("empty entry".to_string());
    }
    let segments: Vec<&str> = entry.split('/').collect();
    if segments.len() > 3 {
        return Err(format!(
            "'{entry}' has too many '/' segments — expected owner, owner/repo, or host/owner/repo"
        ));
    }
    // Charset gate first, so the round trip below never sees a control byte or
    // whitespace. This is also what keeps `parse_entries`' splitter (space,
    // comma, tab, newline) equivalent to the consumer's (any whitespace or
    // comma): relaxing this charset re-opens a one-entry-becomes-two hole.
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

    let parsed = cadence_hooks_core::config::parse_allow_entry(entry);

    match (kind, parsed.repo.is_some()) {
        (Kind::Owner, true) => {
            return Err(format!(
                "'{entry}' names a specific repo — pass it to --repos, not --owners"
            ));
        }
        (Kind::Repo, false) => {
            return Err(format!(
                "'{entry}' does not resolve to owner/repo — a first segment containing '.' is \
                 read as a HOST, so this would grant nothing and match nothing. Write it as \
                 owner/repo, or host/owner/repo"
            ));
        }
        _ => {}
    }

    // Per-position charset, now that the positions are known. A GitHub login
    // carries no dot or colon, so one in the owner slot can never match —
    // which is exactly how `github.com` or a trailing-dot typo becomes a dead
    // entry that reads as a guard bug.
    if parsed
        .owner
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    {
        return Err(format!(
            "'{entry}' resolves to owner '{}', which is not a valid GitHub login ('.' and ':' \
             belong in a host segment) — it would match nothing. For a self-hosted forge write \
             host/owner{}",
            parsed.owner,
            if kind == Kind::Repo { "/repo" } else { "" }
        ));
    }
    if let Some(repo) = &parsed.repo
        && repo
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(format!(
            "'{entry}' resolves to repo '{repo}', which is not a valid GitHub repo name"
        ));
    }

    Ok(())
}

/// Validate every entry against `kind`, returning the first failure with the
/// flag named so the message says which list to move the value to.
pub fn validate_entries(entries: &[String], kind: Kind) -> Result<(), String> {
    entries.iter().try_for_each(|e| {
        validate_entry(e, kind).map_err(|msg| format!("{} value {msg}", kind.flag()))
    })
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

/// Write the settings object back **atomically**: serialize to a temp file in
/// the same directory, then rename over the target.
///
/// A plain `fs::write` truncates in place, so an interrupt, a crash, or a full
/// disk mid-write leaves a half-written settings.json — every unrelated setting
/// in it gone. `load_settings` already refuses to clobber a file it could not
/// parse; this is the same promise kept on the write side. The temp file must
/// live in the same directory because `rename` is only atomic within a
/// filesystem.
pub fn save(path: &Path, root: &Map<String, Value>) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;

    let output = serde_json::to_string_pretty(&Value::Object(root.clone()))
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;

    let temp = parent.join(format!(
        ".{}.cadence-hooks-{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("settings"),
        std::process::id()
    ));
    fs::write(&temp, output + "\n")
        .map_err(|e| format!("Failed to write {}: {e}", temp.display()))?;
    fs::rename(&temp, path).map_err(|e| {
        let _ = fs::remove_file(&temp);
        format!("Failed to replace {}: {e}", path.display())
    })
}

/// Re-read the settings file and confirm nobody changed the allowlist while the
/// prompts were open.
///
/// `run` snapshots the whole settings object, then can sit in `dialoguer` for
/// minutes; writing the stale snapshot back would silently revert anything
/// Claude Code's own `/config` (or a second terminal) wrote in that window.
/// Returns the **fresh** object to apply onto, so an unrelated concurrent edit
/// survives; errors when the allowlist keys themselves moved, since merging two
/// intents for the same key is not something this can decide.
fn reload_for_write(path: &Path, snapshot: &Current) -> Result<Map<String, Value>, String> {
    let fresh = load_settings(path)?;
    let now = current_from(&fresh);
    if &now == snapshot {
        return Ok(fresh);
    }
    Err(format!(
        "{} changed while this was waiting for input — its guardrails keys now read \
         {OWNERS_KEY}={}, {REPOS_KEY}={}. Nothing was written; re-run to start from the \
         current values.",
        path.display(),
        render_list(&now.owners),
        render_list(&now.repos)
    ))
}

/// The GitHub login `gh` is authenticated as, or `None` when `gh` is missing,
/// unauthenticated, or answers with something that is not a usable login.
///
/// The only impure step in this module's decision path, kept behind one
/// function so every other path is testable without a `gh` on PATH.
///
/// **Refuses to answer when `GH_HOST` is set.** `gh api user` resolves against
/// `GH_HOST`, so on a self-hosted forge it returns a login from *that*
/// namespace — but a bare entry written here is matched against
/// `config::default_host()`, so internal-forge `alice` would silently become a
/// grant for `github.com/alice`, possibly a different person. That is a
/// widening, not a narrowing, so detection declines and the caller asks.
fn detect_github_login() -> Option<String> {
    if std::env::var_os("GH_HOST").is_some() {
        return None;
    }
    let output = process::Command::new("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let login = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if login.is_empty() || validate_entry(&login, Kind::Owner).is_err() {
        return None;
    }
    Some(login)
}

/// Why identity detection produced nothing, in words the operator can act on.
///
/// `GH_HOST` is called out by name because it is the one case where the fix is
/// not "authenticate `gh`" — the value would have been wrong, not missing.
fn detection_failure_note() -> String {
    if std::env::var_os("GH_HOST").is_some() {
        format!(
            "GH_HOST is set, so `gh api user` would return a login from that forge — and a bare \
             {OWNERS_KEY} entry is matched against github.com, so writing it would grant the \
             wrong account. Name the owner explicitly (use host/owner for the self-hosted one)."
        )
    } else {
        "Could not detect a GitHub identity ('gh api user' unavailable or unauthenticated)."
            .to_string()
    }
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
fn prompt_list(prompt: &str, default: &[String], kind: Kind) -> Result<Vec<String>, String> {
    let raw: String = Input::new()
        .with_prompt(prompt)
        .with_initial_text(default.join(" "))
        .allow_empty(true)
        .interact_text()
        .map_err(|e| format!("prompt cancelled: {e}"))?;
    let entries = parse_entries(&raw);
    validate_entries(&entries, kind)?;
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

    let root = match load_settings(&path) {
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
    if let Err(e) = validate_entries(&owner_flags, Kind::Owner)
        .and_then(|()| validate_entries(&repo_flags, Kind::Repo))
    {
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

    // Whose identity this is, echoed before it can become a grant. `gh api
    // user` resolves against GH_TOKEN, so in a shell carrying a bot or
    // second-account token the answer is a different person than the operator
    // assumes — and under --yes nothing else would ever show it.
    if let Some(login) = &detected {
        println!("Detected GitHub identity via `gh api user`: {login}");
    }

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
            println!("{} Enter it below.", detection_failure_note());
        }

        match prompt_list(
            "GitHub users/orgs you own (space-separated)",
            &owners,
            Kind::Owner,
        )
        .and_then(|o| {
            let r = prompt_list(
                "Other owners' repos you have write access to, as owner/repo (blank for none)",
                &repos,
                Kind::Repo,
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
             Pass --owners <github-user> [more...] or run without --yes to be prompted.\n\
             {}",
            detection_failure_note()
        );
        process::exit(1);
    }

    // Apply onto a FRESH read, not the snapshot taken before the prompts — see
    // `reload_for_write`. Under --yes the window is microseconds and this is
    // nearly free; interactively it is the whole point.
    let mut root = match reload_for_write(&path, &current) {
        Ok(root) => root,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

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
    fn validate_entry_accepts_each_kinds_legal_forms() {
        for good in ["cameronsjo", "git.example.com/owner"] {
            assert!(
                validate_entry(good, Kind::Owner).is_ok(),
                "{good} should be a valid owner entry"
            );
        }
        for good in ["cameronsjo/repo", "git.example.com/owner/repo", "acme/a.js"] {
            assert!(
                validate_entry(good, Kind::Repo).is_ok(),
                "{good} should be a valid repo entry"
            );
        }
    }

    #[test]
    fn validate_entry_rejects_junk_that_would_silently_never_match() {
        for bad in ["", "owner/", "a/b/c/d", "own er", "owner;rm -rf /", "$(id)"] {
            assert!(
                validate_entry(bad, Kind::Owner).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    /// A dotted single-segment owner parses as a bare owner literally named
    /// `github.com`, and a bare owner only matches `default_host` — so it can
    /// never match, and the block it causes reads as a guard bug.
    #[test]
    fn dotted_single_segment_owner_is_rejected_not_written() {
        for dead in ["github.com", "cameronsjo.", "git.sjo.lol"] {
            let Err(err) = validate_entry(dead, Kind::Owner) else {
                panic!("'{dead}' resolves to an owner that can never match — must be rejected");
            };
            assert!(
                err.contains("not a valid GitHub login"),
                "message must say why: {err}"
            );
            assert!(
                err.contains("host/owner"),
                "message must name the fix: {err}"
            );
        }
        // The same string, round-tripped through the consumer, confirms the
        // shape this rejects — the check is not guessing at parse_allow_entry.
        let parsed = cadence_hooks_core::config::parse_allow_entry("github.com");
        assert_eq!(parsed.owner, "github.com");
        assert!(parsed.host.is_none() && parsed.repo.is_none());
    }

    /// `--repos foo.bar/tool` reads as host `foo.bar`, owner `tool`, no repo —
    /// an owner-wide entry on a host that does not exist. The user believes
    /// they named one repo precisely; it matches nothing.
    #[test]
    fn dotted_first_segment_in_repos_is_rejected_not_reinterpreted_as_a_host() {
        let parsed = cadence_hooks_core::config::parse_allow_entry("foo.bar/tool");
        assert_eq!(parsed.host.as_deref(), Some("foo.bar"));
        assert_eq!(parsed.owner, "tool");
        assert!(parsed.repo.is_none(), "no repo — this is the whole problem");

        let err = validate_entry("foo.bar/tool", Kind::Repo).expect_err("must be rejected");
        assert!(err.contains("read as a HOST"), "{err}");
        assert!(err.contains("host/owner/repo"), "names the fix: {err}");

        // Same string is legitimate as an OWNER entry (host/owner), so the
        // rejection is shape-vs-kind, not a blanket ban on the string.
        assert!(validate_entry("foo.bar/tool", Kind::Owner).is_ok());
    }

    #[test]
    fn an_owner_repo_pair_is_rejected_from_the_owners_list() {
        let err = validate_entry("acme/tool", Kind::Owner).expect_err("must be rejected");

        assert!(err.contains("--repos"), "points at the right flag: {err}");
    }

    #[test]
    fn validate_entries_names_the_flag_in_the_message() {
        let err = validate_entries(&owners(&["github.com"]), Kind::Owner).unwrap_err();

        assert!(err.starts_with("--owners value"), "{err}");
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

    /// The snapshot-then-prompt window: a concurrent writer touching an
    /// UNRELATED key must survive, because `run` applies onto the fresh read.
    #[test]
    fn a_concurrent_unrelated_edit_survives_the_write() {
        let (_dir, path) = settings(r#"{"env":{"CADENCE_ALLOWED_OWNERS":"cameronsjo"}}"#);
        let snapshot = current_from(&load_settings(&path).unwrap());

        // Someone else edits the file while the prompts are open.
        fs::write(
            &path,
            r#"{"model":"opus","env":{"CADENCE_ALLOWED_OWNERS":"cameronsjo","OTHER":"new"}}"#,
        )
        .unwrap();

        let mut fresh = reload_for_write(&path, &snapshot).expect("allowlist unchanged — proceed");
        apply(&mut fresh, &owners(&["cameronsjo", "acme"]), &[]).unwrap();
        save(&path, &fresh).unwrap();

        let written = load_settings(&path).unwrap();
        let env = written.get("env").unwrap().as_object().unwrap();
        assert_eq!(
            env.get("OTHER").unwrap().as_str(),
            Some("new"),
            "the concurrent edit must not be reverted"
        );
        assert_eq!(written.get("model").unwrap().as_str(), Some("opus"));
        assert_eq!(
            env.get(OWNERS_KEY).unwrap().as_str(),
            Some("cameronsjo acme")
        );
    }

    /// When the concurrent writer changed the ALLOWLIST itself, two intents
    /// collide and this refuses rather than picking one.
    #[test]
    fn a_concurrent_allowlist_edit_aborts_without_writing() {
        let (_dir, path) = settings(r#"{"env":{"CADENCE_ALLOWED_OWNERS":"cameronsjo"}}"#);
        let snapshot = current_from(&load_settings(&path).unwrap());

        fs::write(
            &path,
            r#"{"env":{"CADENCE_ALLOWED_OWNERS":"someone-else"}}"#,
        )
        .unwrap();
        let before = fs::read_to_string(&path).unwrap();

        let err = reload_for_write(&path, &snapshot).expect_err("must refuse");

        assert!(err.contains("changed while this was waiting"), "{err}");
        assert!(err.contains("Nothing was written"), "{err}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "the file must be untouched"
        );
    }

    #[test]
    fn save_replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        let mut root = Map::new();
        apply(&mut root, &owners(&["cameronsjo"]), &[]).unwrap();
        save(&path, &root).unwrap();

        let strays: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "settings.json")
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
        assert!(load_settings(&path).unwrap().contains_key("env"));
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
