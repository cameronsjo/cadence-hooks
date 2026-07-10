//! `cadence-hooks migrate-config` — convert a repo's legacy per-guard config
//! files into the single namespaced `.claude/cadence.json` (cadence-hooks#153).
//!
//! The unified loader is a hard cut: once installed, only `cadence.json` is
//! read. This subcommand converts a repo in one step — it merges the legacy
//! `.claude/redaction.json` and `.claude/terminology.json` into `cadence.json`
//! under their `redaction` / `terminology` sections, then renames each consumed
//! legacy file to `*.json.migrated` (reversible, leaves a breadcrumb) rather
//! than deleting it.
//!
//! Safety properties:
//! - **Never clobbers.** A section already present in `cadence.json` (a
//!   hand-authored file, or a prior partial run) is left untouched and its
//!   legacy file is NOT renamed — the user reconciles the conflict.
//! - **Idempotent.** After a successful run the legacy files are renamed away,
//!   so a re-run finds nothing to do and reports a no-op.
//! - **Preserves unknown keys.** Existing top-level keys (`version`, a
//!   hand-authored `nudges`, #216) survive the merge — only the two sections
//!   are written.
//! - **Fails loudly on a non-object `cadence.json`.** Rather than destroy
//!   unexpected content, it errors and exits non-zero.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use cadence_hooks_core::paths::{find_git_root, read_untrusted_config};

/// The legacy per-guard config files and the `cadence.json` section each maps
/// to. Order is stable so the summary reads deterministically.
const LEGACY_SECTIONS: &[(&str, &str)] = &[
    ("terminology", "terminology.json"),
    ("redaction", "redaction.json"),
];

/// Why a section was not written during a migration.
#[derive(Debug, PartialEq, Eq)]
enum SkipReason {
    /// No legacy file for this section (nothing to migrate).
    NoLegacy,
    /// `cadence.json` already carries this section — left untouched.
    AlreadyPresent,
    /// The legacy file was unreadable or not valid JSON.
    Unreadable,
}

/// What a migration did, for the summary and for tests.
#[derive(Debug, Default)]
struct MigrateReport {
    /// Sections written into `cadence.json`, in `LEGACY_SECTIONS` order.
    written: Vec<&'static str>,
    /// Sections not written, with why.
    skipped: Vec<(&'static str, SkipReason)>,
    /// Legacy files renamed to `*.json.migrated`.
    renamed: Vec<PathBuf>,
}

impl MigrateReport {
    /// True when the migration changed nothing on disk.
    fn is_noop(&self) -> bool {
        self.written.is_empty() && self.renamed.is_empty()
    }
}

/// Merge legacy config files under `claude_dir` into `claude_dir/cadence.json`.
///
/// Pure of process state (operates on the passed directory), so tests drive it
/// against a tempdir. Returns the report, or an error string when the existing
/// `cadence.json` is not a JSON object (the one case we refuse to proceed on,
/// to avoid destroying unexpected content) or a write/rename fails.
fn migrate_claude_dir(claude_dir: &Path) -> Result<MigrateReport, String> {
    let cadence_path = claude_dir.join("cadence.json");

    // Load the existing cadence.json into a mutable object, or start a fresh
    // one with the version envelope. A present-but-non-object file is a hard
    // stop — we never overwrite content we don't understand.
    let mut root_obj = match read_untrusted_config(&cadence_path) {
        Some(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => {
                return Err(format!(
                    "{} exists but is not a JSON object — fix or remove it before migrating",
                    cadence_path.display()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "{} is not valid JSON ({e}) — fix or remove it before migrating",
                    cadence_path.display()
                ));
            }
        },
        None => {
            // `read_untrusted_config` returns `None` for FOUR states: truly
            // absent, non-regular (symlink/FIFO/dir), oversized (>1 MiB), or
            // non-UTF-8. Only a truly-absent file may start a fresh map — a
            // present-but-unreadable file must NOT be silently overwritten by
            // the merged sections (same "don't destroy content" stance as the
            // non-object refusal above). `symlink_metadata` (no follow) tells
            // the two apart: `Ok` means something is there.
            if std::fs::symlink_metadata(&cadence_path).is_ok() {
                return Err(format!(
                    "{} exists but could not be read (not a regular file, larger \
                     than 1 MiB, or not UTF-8) — fix or remove it before migrating",
                    cadence_path.display()
                ));
            }
            serde_json::Map::new()
        }
    };

    let mut report = MigrateReport::default();
    let mut to_rename: Vec<PathBuf> = Vec::new();

    for (section, legacy_name) in LEGACY_SECTIONS {
        let legacy_path = claude_dir.join(legacy_name);

        let Some(content) = read_untrusted_config(&legacy_path) else {
            report.skipped.push((section, SkipReason::NoLegacy));
            continue;
        };

        if root_obj.contains_key(*section) {
            // A hand-authored (or previously migrated) section wins — do not
            // clobber, and leave the legacy file in place for the user to
            // reconcile.
            report.skipped.push((section, SkipReason::AlreadyPresent));
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            report.skipped.push((section, SkipReason::Unreadable));
            continue;
        };

        root_obj.insert((*section).to_string(), value);
        report.written.push(section);
        to_rename.push(legacy_path);
    }

    if report.written.is_empty() {
        // Nothing consumed — do not touch cadence.json or any legacy file.
        return Ok(report);
    }

    // Stamp the version envelope so a freshly-created file carries it and an
    // older hand-authored one gains it. `serde_json`'s `Map` here is a
    // `BTreeMap` (no `preserve_order` feature), so keys always serialize sorted
    // — `version` lands after the sections regardless of insertion order; this
    // only ensures the key is present, never absent.
    root_obj
        .entry("version".to_string())
        .or_insert(serde_json::Value::from(1));

    // Refuse to write *through* a symlink at cadence.json. `std::fs::write` is a
    // plain `open(O_CREAT|O_TRUNC)` that follows symlinks, so an attacker-planted
    // `.claude/cadence.json -> ~/.claude/settings.json` (untrusted repo content)
    // would land the merged JSON at the link target, outside `.claude/` —
    // creating a file at a dangling target, or truncating a real config file.
    // `read_untrusted_config` guards the READ side only; this is the first write
    // path, so it needs its own check. A regular file (idempotent re-write) or an
    // absent path is fine; `symlink_metadata` does not follow, so it judges the
    // path itself.
    if std::fs::symlink_metadata(&cadence_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!(
            "{} is a symlink — refusing to write through it (remove or replace the link, then re-run)",
            cadence_path.display()
        ));
    }

    let serialized = serde_json::to_string_pretty(&serde_json::Value::Object(root_obj))
        .map_err(|e| format!("failed to serialize {}: {e}", cadence_path.display()))?;
    std::fs::write(&cadence_path, format!("{serialized}\n"))
        .map_err(|e| format!("failed to write {}: {e}", cadence_path.display()))?;

    // Rename consumed legacy files only after the write succeeds, so a failed
    // write never strands the source. If a rename fails mid-loop (disk full,
    // permission denied) after cadence.json is already written, that section is
    // now `AlreadyPresent`, so a re-run non-destructively skips it but never
    // retries the rename — the orphaned legacy file lingers and `doctor` keeps
    // warning until it's removed by hand. Low-probability (same-filesystem
    // rename after a successful write), and non-destructive, so it's surfaced
    // rather than transactionally rolled back.
    for legacy_path in to_rename {
        let migrated = migrated_path(&legacy_path);
        std::fs::rename(&legacy_path, &migrated)
            .map_err(|e| format!("failed to rename {}: {e}", legacy_path.display()))?;
        report.renamed.push(migrated);
    }

    Ok(report)
}

/// `redaction.json` → `redaction.json.migrated`. Appends the suffix rather than
/// replacing the extension so the original name stays legible in the breadcrumb.
fn migrated_path(legacy: &Path) -> PathBuf {
    let mut name = legacy.file_name().unwrap_or_default().to_os_string();
    name.push(".migrated");
    legacy.with_file_name(name)
}

/// Green/dim/reset codes, empty when stdout is not a TTY or `NO_COLOR` is set.
struct Palette {
    green: &'static str,
    yellow: &'static str,
    dim: &'static str,
    reset: &'static str,
}

impl Palette {
    fn detect() -> Self {
        let color = std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        if color {
            Palette {
                green: "\x1b[32m",
                yellow: "\x1b[33m",
                dim: "\x1b[2m",
                reset: "\x1b[0m",
            }
        } else {
            Palette {
                green: "",
                yellow: "",
                dim: "",
                reset: "",
            }
        }
    }
}

/// Human-readable reason text for the summary.
fn skip_text(reason: &SkipReason) -> &'static str {
    match reason {
        SkipReason::NoLegacy => "no legacy file",
        SkipReason::AlreadyPresent => "already present in cadence.json — left untouched",
        SkipReason::Unreadable => "legacy file unreadable or invalid JSON — left in place",
    }
}

/// `migrate-config` entry point. Resolves the git root from the current
/// directory, migrates its `.claude/`, prints a scannable summary to stdout
/// (diagnostics to stderr), and returns the process exit code: 0 on success or
/// a clean no-op, 1 on any error (no git root, unreadable/non-object
/// `cadence.json`, or a write/rename failure).
pub fn run() -> u8 {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());

    let Some(root) = find_git_root(&cwd) else {
        eprintln!(
            "cadence-hooks migrate-config: not inside a git repository (no .git found from {cwd})"
        );
        return 1;
    };

    let claude_dir = root.join(".claude");
    let p = Palette::detect();

    match migrate_claude_dir(&claude_dir) {
        Ok(report) => {
            let cadence_path = claude_dir.join("cadence.json");

            for section in &report.written {
                println!(
                    "{}✓{} wrote '{section}' section to {}",
                    p.green,
                    p.reset,
                    cadence_path.display()
                );
            }
            for path in &report.renamed {
                println!("{}·{} renamed legacy → {}", p.dim, p.reset, path.display());
            }
            for (section, reason) in &report.skipped {
                // A bare "no legacy file" for both sections is the ordinary
                // nothing-to-do case; only surface the actionable skips loudly.
                if matches!(reason, SkipReason::NoLegacy) {
                    continue;
                }
                println!(
                    "{}⚠{} skipped '{section}': {}",
                    p.yellow,
                    p.reset,
                    skip_text(reason)
                );
            }

            if report.is_noop() {
                println!(
                    "{}·{} migrate-config: nothing to migrate — no legacy config found under {}",
                    p.dim,
                    p.reset,
                    claude_dir.display()
                );
            } else {
                println!(
                    "{}✓{} migrate-config: {} section(s) written, {} legacy file(s) renamed",
                    p.green,
                    p.reset,
                    report.written.len(),
                    report.renamed.len()
                );
            }
            0
        }
        Err(msg) => {
            eprintln!("cadence-hooks migrate-config: {msg}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.claude/` dir seeded with the given legacy files (name, body) and an
    /// optional pre-existing `cadence.json` body.
    fn seed(legacy: &[(&str, &str)], cadence: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        for (name, body) in legacy {
            std::fs::write(claude.join(name), body).unwrap();
        }
        if let Some(body) = cadence {
            std::fs::write(claude.join("cadence.json"), body).unwrap();
        }
        dir
    }

    fn read_cadence(dir: &Path) -> serde_json::Value {
        let content = std::fs::read_to_string(dir.join(".claude/cadence.json")).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[test]
    fn migrates_both_files_into_sections() {
        let dir = seed(
            &[
                (
                    "terminology.json",
                    r#"{"exemptions":[{"paths":["a.yml"]}]}"#,
                ),
                (
                    "redaction.json",
                    r#"{"originAudience":"public","allowlist":["cadence"]}"#,
                ),
            ],
            None,
        );
        let report = migrate_claude_dir(&dir.path().join(".claude")).unwrap();
        assert_eq!(report.written, vec!["terminology", "redaction"]);
        assert_eq!(report.renamed.len(), 2);

        let cadence = read_cadence(dir.path());
        assert_eq!(cadence["version"], serde_json::json!(1));
        assert_eq!(
            cadence["terminology"]["exemptions"][0]["paths"][0],
            serde_json::json!("a.yml")
        );
        assert_eq!(
            cadence["redaction"]["originAudience"],
            serde_json::json!("public")
        );

        // Legacy files renamed away.
        let claude = dir.path().join(".claude");
        assert!(!claude.join("terminology.json").exists());
        assert!(!claude.join("redaction.json").exists());
        assert!(claude.join("terminology.json.migrated").exists());
        assert!(claude.join("redaction.json.migrated").exists());
    }

    #[test]
    fn re_run_is_a_noop() {
        let dir = seed(
            &[(
                "terminology.json",
                r#"{"exemptions":[{"paths":["a.yml"]}]}"#,
            )],
            None,
        );
        let claude = dir.path().join(".claude");
        let first = migrate_claude_dir(&claude).unwrap();
        assert_eq!(first.written, vec!["terminology"]);

        let second = migrate_claude_dir(&claude).unwrap();
        assert!(second.is_noop(), "second run must change nothing");
        assert!(second.written.is_empty());
        // cadence.json still has the migrated section.
        assert_eq!(
            read_cadence(dir.path())["terminology"]["exemptions"][0]["paths"][0],
            serde_json::json!("a.yml")
        );
    }

    #[test]
    fn existing_section_is_not_clobbered() {
        // cadence.json already carries a terminology section; a leftover legacy
        // terminology.json must be skipped, not merged, and left in place.
        let dir = seed(
            &[(
                "terminology.json",
                r#"{"exemptions":[{"paths":["legacy.yml"]}]}"#,
            )],
            Some(r#"{"version":1,"terminology":{"exemptions":[{"paths":["kept.yml"]}]}}"#),
        );
        let claude = dir.path().join(".claude");
        let report = migrate_claude_dir(&claude).unwrap();

        assert!(report.written.is_empty());
        assert!(
            report
                .skipped
                .contains(&("terminology", SkipReason::AlreadyPresent))
        );
        // The hand-authored section survived.
        assert_eq!(
            read_cadence(dir.path())["terminology"]["exemptions"][0]["paths"][0],
            serde_json::json!("kept.yml")
        );
        // Legacy file left in place for reconciliation.
        assert!(claude.join("terminology.json").exists());
        assert!(!claude.join("terminology.json.migrated").exists());
    }

    #[test]
    fn no_legacy_files_is_noop_and_writes_nothing() {
        let dir = seed(&[], None);
        let claude = dir.path().join(".claude");
        let report = migrate_claude_dir(&claude).unwrap();
        assert!(report.is_noop());
        assert!(!claude.join("cadence.json").exists());
    }

    #[test]
    fn preserves_unknown_top_level_keys() {
        // A hand-authored reserved `nudges` block (#216) survives the merge.
        let dir = seed(
            &[("redaction.json", r#"{"allowlist":["cadence"]}"#)],
            Some(r#"{"version":1,"nudges":{"backstop-warn":{"suppress":true}}}"#),
        );
        let report = migrate_claude_dir(&dir.path().join(".claude")).unwrap();
        assert_eq!(report.written, vec!["redaction"]);

        let cadence = read_cadence(dir.path());
        assert_eq!(
            cadence["nudges"]["backstop-warn"]["suppress"],
            serde_json::json!(true)
        );
        assert_eq!(
            cadence["redaction"]["allowlist"][0],
            serde_json::json!("cadence")
        );
    }

    #[test]
    fn one_present_one_absent_migrates_only_present() {
        let dir = seed(&[("redaction.json", r#"{"allowlist":["x"]}"#)], None);
        let report = migrate_claude_dir(&dir.path().join(".claude")).unwrap();
        assert_eq!(report.written, vec!["redaction"]);
        assert!(
            report
                .skipped
                .contains(&("terminology", SkipReason::NoLegacy))
        );
    }

    #[test]
    fn malformed_legacy_is_skipped_and_left_in_place() {
        let dir = seed(&[("terminology.json", "{not valid json")], None);
        let claude = dir.path().join(".claude");
        let report = migrate_claude_dir(&claude).unwrap();
        assert!(report.written.is_empty());
        assert!(
            report
                .skipped
                .contains(&("terminology", SkipReason::Unreadable))
        );
        assert!(claude.join("terminology.json").exists());
    }

    #[test]
    fn non_object_cadence_json_errors() {
        let dir = seed(
            &[("redaction.json", r#"{"allowlist":["x"]}"#)],
            Some("[1, 2, 3]"),
        );
        let err = migrate_claude_dir(&dir.path().join(".claude")).unwrap_err();
        assert!(err.contains("not a JSON object"), "{err}");
        // Nothing renamed.
        assert!(dir.path().join(".claude/redaction.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_through_dangling_symlinked_cadence_json() {
        // An attacker-planted cadence.json symlink to a NONEXISTENT target must
        // not let the write create a file there. The read gate rejects the
        // unreadable symlink first (present-but-unreadable → refuse), so the
        // target is never created.
        let dir = seed(&[("redaction.json", r#"{"allowlist":["x"]}"#)], None);
        let claude = dir.path().join(".claude");
        let target = dir.path().join("outside.json");
        std::os::unix::fs::symlink(&target, claude.join("cadence.json")).unwrap();

        assert!(migrate_claude_dir(&claude).is_err());
        assert!(!target.exists(), "must not write through the symlink");
        // Legacy file left in place (refused before the rename).
        assert!(claude.join("redaction.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_cadence_json_pointing_at_existing_object() {
        // A symlink to an existing JSON *object* (e.g. a real settings file):
        // the read follows and parses it, but the pre-write symlink guard still
        // refuses, so the target is never truncated.
        let dir = seed(&[("redaction.json", r#"{"allowlist":["x"]}"#)], None);
        let claude = dir.path().join(".claude");
        let target = dir.path().join("real-settings.json");
        std::fs::write(&target, r#"{"keep":"me"}"#).unwrap();
        std::os::unix::fs::symlink(&target, claude.join("cadence.json")).unwrap();

        let err = migrate_claude_dir(&claude).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        // Target untouched.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            r#"{"keep":"me"}"#
        );
    }

    #[test]
    fn refuses_present_but_unreadable_cadence_json() {
        // A cadence.json that exists but the read gate rejects (here: a
        // directory at the path — non-regular) must NOT be treated as absent and
        // silently overwritten by the merged sections.
        let dir = seed(&[("redaction.json", r#"{"allowlist":["x"]}"#)], None);
        let claude = dir.path().join(".claude");
        std::fs::create_dir(claude.join("cadence.json")).unwrap();

        let err = migrate_claude_dir(&claude).unwrap_err();
        assert!(err.contains("could not be read"), "{err}");
        // Legacy file left in place (refused before any rename).
        assert!(claude.join("redaction.json").exists());
    }

    #[test]
    fn migrated_path_appends_suffix() {
        assert_eq!(
            migrated_path(Path::new("/r/.claude/redaction.json")),
            PathBuf::from("/r/.claude/redaction.json.migrated")
        );
    }
}
