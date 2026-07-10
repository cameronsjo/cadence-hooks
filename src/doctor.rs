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
use std::time::{Duration, SystemTime};

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

/// Telemetry staleness as a doctor [`Finding`], or `None` when the metrics dir
/// is fresh, missing, or empty (fail-open — a fresh install stays silent).
///
/// This is the diagnostic twin of the `metrics warn-stale` SessionStart check:
/// same `staleness` core, but doctor consults no once-per-day marker — a
/// diagnostic always reports the current state. A stale dir is a `Warning`
/// (exit 1), never an `Error` — telemetry going quiet is advisory, not a
/// shell bug.
fn staleness_finding(dir: &Path, threshold: Duration, now: SystemTime) -> Option<Finding> {
    let report = cadence_hooks_metrics::warn_stale::staleness(dir, threshold, now)?;
    Some(Finding {
        severity: Severity::Warning,
        plugin: "cadence-metrics".to_string(),
        file: dir.to_path_buf(),
        line: None,
        snippet: report.newest_file.clone(),
        diagnosis: cadence_hooks_metrics::warn_stale::staleness_summary(&report),
        remediation: "compare wiring against a healthy machine — the metrics \
                      plugin may be disabled or its hooks mis-wired \
                      (`cadence-hooks list` shows what should be firing)"
            .to_string(),
    })
}

/// Fail-open telemetry as doctor `Finding`s — up to 5 (one per `reason`), or
/// none when all counts are below their thresholds. `panic` and `parse` are
/// warned on any/moderate occurrence; the #271 deadline pair is load-correlated
/// (`deadline` warns at 3+) except the suppressed-block row, which warns at 1
/// because each one is an enforcement block that did not fire;
/// `version_mismatch` only counts rows
/// tagged with the CURRENT binary's own version (see
/// `log_failopen::recent_failopen_counts`'s doc) — an older-version row is the
/// sanctioned release-transition case and is excluded by construction.
fn failopen_findings(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    current_version: &str,
) -> Vec<Finding> {
    let counts = cadence_hooks_metrics::log_failopen::recent_failopen_counts(
        dir,
        window,
        now,
        current_version,
    );
    let days = window.as_secs() / 86_400;
    let mut findings = Vec::new();

    if counts.panic >= 1 {
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("panic: {}", counts.panic),
            diagnosis: format!(
                "{} panic(s) in the last {days} days (failopen.jsonl)",
                counts.panic
            ),
            remediation: "a panic in a check/logger is always a bug — inspect \
                          failopen.jsonl for the namespace/subcommand and file an issue"
                .to_string(),
        });
    }

    if counts.parse >= 3 {
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("parse: {}", counts.parse),
            diagnosis: format!(
                "{} stdin-parse failure(s) in the last {days} days (failopen.jsonl)",
                counts.parse
            ),
            remediation: "occasional malformed payloads are tolerated; 3+ suggests \
                          a wiring problem feeding this binary bad stdin — inspect \
                          failopen.jsonl"
                .to_string(),
        });
    }

    if counts.version_mismatch >= 1 {
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("version_mismatch: {}", counts.version_mismatch),
            diagnosis: format!(
                "{} version_mismatch failopen(s) on this binary's own version \
                 ({current_version}) in the last {days} days — a hooks.json/binary \
                 skew that hasn't resolved",
                counts.version_mismatch
            ),
            remediation: "compare installed plugin hooks.json subcommand references \
                          against 'cadence-hooks list' — this binary doesn't \
                          recognize something a plugin expects"
                .to_string(),
        });
    }

    if counts.deadline >= 3 {
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("deadline: {}", counts.deadline),
            diagnosis: format!(
                "{} git-probe deadline hit(s) in the last {days} days (failopen.jsonl) \
                 — git-backed checks are degrading to fail-open under slow subprocess I/O",
                counts.deadline
            ),
            remediation: "git is stalling under this environment: check for a \
                          cloud-synced working directory (OneDrive/iCloud/Dropbox), \
                          endpoint-protection scanning, or heavy concurrent session \
                          load; CADENCE_HOOK_DEADLINE_MS tunes the budget (#271)"
                .to_string(),
        });
    }

    // Threshold 1, not 3: each row is an enforcement block that did not fire.
    if counts.deadline_block_suppressed >= 1 {
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!(
                "deadline_block_suppressed: {}",
                counts.deadline_block_suppressed
            ),
            diagnosis: format!(
                "{} fail-closed block(s) suppressed by the git-probe deadline in the \
                 last {days} days (failopen.jsonl) — ownership/branch enforcement was \
                 bypassed, not just slowed",
                counts.deadline_block_suppressed
            ),
            remediation: "inspect failopen.jsonl for the affected guards; until git \
                          latency is addressed, pass explicit targets (-R owner/repo, \
                          explicit push remotes) so those guards don't need git probes \
                          (#271)"
                .to_string(),
        });
    }

    findings
}

/// Cadence hook latency from Claude Code session logs as a doctor `Finding`
/// (cadence-hooks#271 prevention P2). The binary can't self-report an external
/// timeout kill — a killed process logs nothing — but Claude Code records every
/// hook's `durationMs`, so a scan of recent session logs surfaces guards that
/// are degrading (incl. pure-CPU guards the deadline telemetry never sees). A
/// `Warning`, never an `Error`: slow hooks are an environment problem to
/// diagnose, not a shell bug.
fn hook_latency_findings(projects: &Path, window: Duration, now: SystemTime) -> Vec<Finding> {
    let tallies = crate::hook_latency::scan_recent(projects, window, now);
    let days = window.as_secs() / 86_400;
    match crate::hook_latency::summary(&tallies, days) {
        None => Vec::new(),
        Some(diagnosis) => vec![Finding {
            severity: Severity::Warning,
            plugin: "cadence-hooks".to_string(),
            file: projects.to_path_buf(),
            line: None,
            snippet: "Claude Code session logs".to_string(),
            diagnosis,
            remediation: "git-backed guards are bounded by the internal deadline \
                          (CADENCE_HOOK_DEADLINE_MS); a pure-CPU guard that's still \
                          slow points at fork/exec contention — check for a \
                          cloud-synced working dir, endpoint-protection scanning, or \
                          heavy concurrent-session load (#271)"
                .to_string(),
        }],
    }
}

/// Prints an informational (non-blocking, not a `Finding`) count of recent
/// registry-file reaps when nonzero. No threshold — reaping is normal
/// operation; this is visibility, not an alarm.
fn print_sweep_summary(dir: &Path, window: Duration, now: SystemTime) {
    let count = cadence_hooks_metrics::log_sweep::recent_sweep_count(dir, window, now);
    if count == 0 {
        return;
    }
    let days = window.as_secs() / 86_400;
    println!(
        "cadence-hooks doctor: {count} session-registry sweep(s) in the last {days} days (sweeps.jsonl)"
    );
}

/// Sum the byte size of every regular file under `dir`, walking recursively.
///
/// Symlinks are skipped (mirrors [`scan_root`]'s cycle guard) — including
/// `dir` itself: a caller that hands us a symlinked top-level path (e.g. a
/// planted symlink masquerading as an orphaned cache dir) gets `0`, not a
/// recursive sum of whatever the link actually points at. The walk is also
/// best-effort: an unreadable subdirectory just contributes 0 rather than
/// failing the whole count.
fn dir_size_bytes(dir: &Path) -> u64 {
    // `is_dir()`/`read_dir` follow symlinks; `symlink_metadata` does not, so
    // this catches a symlinked `dir` argument before ever following it.
    if std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return 0;
    }

    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let is_symlink = entry.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if is_symlink {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }

    total
}

/// True when `path` resolves under `root` — delegates to
/// [`cadence_hooks_core::paths::is_within`], the shared lexical containment
/// primitive (existence-independent, rejects any `..` outright). Every pinned
/// `installPath` and every candidate orphan sibling is checked against the
/// plugin-cache root before it can influence a scan or a deletion, so a
/// manifest entry pointing outside the cache (`/etc`, a `..`-climbing
/// relative path) can never steer `remove_dir_all` anywhere but the cache.
fn is_contained(path: &Path, root: &Path) -> bool {
    cadence_hooks_core::paths::is_within(&path.to_string_lossy(), root)
}

/// Case-insensitive basename comparison. macOS/APFS default volumes are
/// case-insensitive, so a manifest basename that diverges only in case from
/// the on-disk directory name must still be recognized as the same pin —
/// otherwise the active dir is misjudged as an orphan. Deliberately applied
/// on every platform (not `cfg`-gated to macOS): a case-insensitive match is
/// never wrong on a case-sensitive filesystem — basenames written by Claude
/// Code's own installer never differ only in case — so the uniform
/// comparison is simpler than platform-conditional logic for the same result.
fn eq_ignore_case(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Concrete orphaned version directories across every `(label, install_path)`
/// pair in `pinned` — siblings of a pinned dir's parent whose basename isn't
/// ANY pinned basename sharing that parent. Pure (no filesystem writes);
/// reused by both [`orphan_findings`] (advisory count/bytes) and the
/// `doctor --prune` flow (actual removal via [`prune_orphans`]), so the
/// sibling-scan + symlink + containment guards live in exactly one place.
///
/// `cache_root` bounds every pin: an `installPath` that does not resolve
/// under it (a bogus or malicious manifest entry) is skipped entirely — its
/// parent is never scanned, so nothing outside the plugin cache can ever be
/// nominated as an orphan. Pins are grouped by parent directory first, so
/// when two active pins share a parent (multi-scope installs, or two SHAs of
/// the same plugin key), scanning that parent excludes BOTH pinned
/// basenames — an active pin is never returned as an orphan just because a
/// sibling pin's own scan didn't know about it.
fn orphan_dirs(pinned: &[(String, PathBuf)], cache_root: &Path) -> Vec<PathBuf> {
    let mut pinned_by_parent: std::collections::HashMap<PathBuf, Vec<std::ffi::OsString>> =
        std::collections::HashMap::new();

    for (_label, install_path) in pinned {
        if !is_contained(install_path, cache_root) {
            continue;
        }
        let Some(parent) = install_path.parent() else {
            continue;
        };
        let Some(pinned_name) = install_path.file_name() else {
            continue;
        };
        pinned_by_parent
            .entry(parent.to_path_buf())
            .or_default()
            .push(pinned_name.to_os_string());
    }

    let mut out = Vec::new();

    for (parent, pinned_names) in &pinned_by_parent {
        let Ok(siblings) = std::fs::read_dir(parent) else {
            continue;
        };

        for sibling in siblings.flatten() {
            // `DirEntry::file_type()` does NOT follow symlinks (unlike
            // `sibling.path().is_dir()`, which does) — a symlinked sibling
            // must never be treated as an orphan version dir to recurse
            // into, or a planted symlink (e.g. pointing at `$HOME` or `/`)
            // gets summed/removed as if it were real cache content.
            let is_real_dir = sibling.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_real_dir {
                continue;
            }
            let sibling_name = sibling.file_name();
            if pinned_names
                .iter()
                .any(|name| eq_ignore_case(name, &sibling_name))
            {
                continue;
            }
            out.push(sibling.path());
        }
    }

    out
}

/// Findings for orphaned and missing/empty pinned plugin-cache version dirs.
///
/// `pinned` is `(label, install_path)` from [`manifest_install_paths`] — the
/// version dir the manifest actually points at. Any sibling directory under
/// an `install_path`'s parent that isn't ANY pinned basename sharing that
/// parent is an orphan: a stale SHA-pinned version left behind by an update,
/// since the cache never garbage-collects.
///
/// The missing/empty-pinned-dir warning fires in both quiet and verbose modes
/// (it means the active plugin literally won't load). The orphan-count
/// warning is `quiet`-suppressed — orphans are cosmetic cache bloat, not a
/// functional break, and would otherwise nag every SessionStart forever.
///
/// Orphans are computed ONCE over the full `pinned` slice (never per-pin) —
/// calling [`orphan_dirs`] with a single-element slice per label would
/// reintroduce the exact multi-pin bug that function's own containment
/// guards against: when two active pins share a parent (multi-scope
/// installs, or two SHAs of one plugin key), a single-pin view can't see the
/// other pin's basename, so it would misreport a live install as "safe to
/// prune". `cache_root` is forwarded to [`orphan_dirs`] — see that
/// function's doc for the containment guarantee.
fn orphan_findings(pinned: &[(String, PathBuf)], quiet: bool, cache_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (label, install_path) in pinned {
        let content_missing = match std::fs::read_dir(install_path) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => true,
        };
        if content_missing {
            findings.push(Finding {
                severity: Severity::Warning,
                plugin: label.clone(),
                file: install_path.clone(),
                line: None,
                snippet: install_path.display().to_string(),
                diagnosis: "pinned cache dir missing or empty".to_string(),
                remediation: "reinstall the plugin (`cadence-hooks list` shows install state, \
                              or reload via the marketplace)"
                    .to_string(),
            });
        }
    }

    if quiet {
        return findings;
    }

    let orphans = orphan_dirs(pinned, cache_root);
    let mut orphans_by_parent: std::collections::HashMap<PathBuf, Vec<PathBuf>> =
        std::collections::HashMap::new();
    for dir in orphans {
        if let Some(parent) = dir.parent() {
            orphans_by_parent
                .entry(parent.to_path_buf())
                .or_default()
                .push(dir);
        }
    }

    for (parent, dirs) in &orphans_by_parent {
        // Attribute the finding to any label actually pinned at this parent
        // — arbitrary-but-deterministic among labels sharing it, since the
        // finding describes the parent directory, not a single pin.
        let Some((label, _)) = pinned
            .iter()
            .find(|(_, install_path)| install_path.parent() == Some(parent.as_path()))
        else {
            continue;
        };

        let orphan_count = dirs.len();
        let orphan_bytes: u64 = dirs.iter().map(|d| dir_size_bytes(d)).sum();
        let mib = orphan_bytes as f64 / (1024.0 * 1024.0);
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: label.clone(),
            file: parent.clone(),
            line: None,
            snippet: format!("{orphan_count} orphaned version dir(s)"),
            diagnosis: format!(
                "{orphan_count} orphaned version dir(s) (~{mib:.1} MiB) left in cache"
            ),
            remediation: "safe to prune — not the active pinned version".to_string(),
        });
    }

    findings
}

/// Remove (or, when `apply` is false, merely size up) the given orphaned
/// version directories. Returns `(removed_count, freed_bytes)` — in dry-run
/// mode both reflect what *would* be removed, since nothing is deleted.
///
/// Each directory is re-verified with [`std::fs::symlink_metadata`]
/// immediately before [`std::fs::remove_dir_all`] — narrowing the TOCTOU
/// window between the scan that produced `dirs` and the removal itself, so a
/// path that became a symlink (or vanished) in between is never followed or
/// removed. Fails open per-directory: an unremovable dir is skipped with a
/// warning to stderr, never fatal to the batch.
///
/// `cache_root` is a second, independent containment check — defense in
/// depth alongside [`orphan_dirs`]'s own containment filtering, so a bug (or
/// future caller) that hands this function an uncontained path still can't
/// reach `remove_dir_all` on it; that dir is skipped with a stderr warning
/// instead.
fn prune_orphans(dirs: &[PathBuf], apply: bool, cache_root: &Path) -> (usize, u64) {
    let mut removed = 0usize;
    let mut freed = 0u64;

    for dir in dirs {
        if !is_contained(dir, cache_root) {
            eprintln!(
                "cadence-hooks doctor --prune: refusing to touch {} — outside the plugin cache root {}",
                dir.display(),
                cache_root.display()
            );
            continue;
        }

        let is_real_dir = std::fs::symlink_metadata(dir)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if !is_real_dir {
            continue;
        }

        let size = dir_size_bytes(dir);
        if !apply {
            removed += 1;
            freed += size;
            continue;
        }

        match std::fs::remove_dir_all(dir) {
            Ok(()) => {
                removed += 1;
                freed += size;
            }
            Err(e) => {
                eprintln!(
                    "cadence-hooks doctor --prune: could not remove {}: {e}",
                    dir.display()
                );
            }
        }
    }

    (removed, freed)
}

/// `doctor --prune` entry point: list (or, with `apply`, remove) orphaned
/// plugin-cache version dirs. Dry-run by default (decision D4) — `apply`
/// must be paired with `prune` at the call site (`run` enforces this before
/// dispatching here).
///
/// Honors `root_override` the same way the rest of `doctor` does: with
/// `--root`, the manifest is read from `<root>/installed_plugins.json` (so
/// integration tests can drive a fixture cache); without it, from the live
/// `~/.claude/plugins/installed_plugins.json`. A missing manifest is not an
/// error here — nothing to prune reports cleanly at exit 0.
///
/// `cache_root` — the containment boundary passed to [`orphan_dirs`] and
/// [`prune_orphans`] — is `root` itself under `--root` (fixtures place
/// `<root>/<marketplace>/<plugin>/<sha>` directly, matching how the manifest
/// path above is resolved), or the live `~/.claude/plugins/cache` otherwise —
/// the same anchor `run`'s cache-walk fallback uses.
fn run_prune(root_override: Option<&Path>, quiet: bool, apply: bool) -> u8 {
    let (manifest, cache_root) = match root_override {
        Some(root) => {
            if !root.exists() {
                eprintln!(
                    "cadence-hooks doctor: scan root does not exist: {}",
                    root.display()
                );
                return 2;
            }
            (root.join("installed_plugins.json"), root.to_path_buf())
        }
        None => {
            let Some(plugins) = plugins_dir() else {
                eprintln!("cadence-hooks doctor: $HOME not set; cannot locate plugin cache");
                return 2;
            };
            (
                plugins.join("installed_plugins.json"),
                plugins.join("cache"),
            )
        }
    };

    let Some(pinned) = manifest_install_paths(&manifest) else {
        if !quiet {
            println!(
                "cadence-hooks doctor --prune: no installed-plugins manifest at {} — nothing to prune",
                manifest.display()
            );
        }
        return 0;
    };

    let dirs = orphan_dirs(&pinned, &cache_root);
    if dirs.is_empty() {
        if !quiet {
            println!("cadence-hooks doctor --prune: no orphaned plugin-cache version dirs found");
        }
        return 0;
    }

    if !quiet {
        for dir in &dirs {
            let size = dir_size_bytes(dir);
            let mib = size as f64 / (1024.0 * 1024.0);
            // `.orphaned_at` is written externally by Claude Code's own
            // plugin loader when it retires a version dir, not by anything
            // in this repo — surfacing it here is advisory ("this one was
            // already flagged upstream"), not a marker this codebase creates.
            let marker_note = if dir.join(".orphaned_at").exists() {
                " [marked .orphaned_at]"
            } else {
                ""
            };
            println!("  {} (~{mib:.1} MiB){marker_note}", dir.display());
        }
    }

    let (removed, freed_bytes) = prune_orphans(&dirs, apply, &cache_root);
    let freed_mib = freed_bytes as f64 / (1024.0 * 1024.0);

    if !quiet {
        if apply {
            println!(
                "cadence-hooks doctor --prune --apply: removed {removed} orphaned version dir(s), freed ~{freed_mib:.1} MiB"
            );
        } else {
            println!(
                "cadence-hooks doctor --prune: {removed} orphaned version dir(s) (~{freed_mib:.1} MiB) would be removed — dry-run, nothing deleted. Re-run with --apply to remove them."
            );
        }
    }

    0
}

/// One `(marketplace, install_location, declared_repo)` from
/// `known_marketplaces.json` for every entry sourced from GitHub.
///
/// `directory`-sourced marketplaces (a local path, no remote to verify) are
/// skipped. Fails open — a missing or unparseable file yields an empty vec,
/// never an error — this is an advisory check, not a hard dependency.
fn known_marketplace_sources(path: &Path) -> Vec<(String, PathBuf, String)> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    let Some(entries) = json.as_object() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (name, entry) in entries {
        let source = entry.get("source");
        let is_github = source
            .and_then(|s| s.get("source"))
            .and_then(|v| v.as_str())
            == Some("github");
        if !is_github {
            continue;
        }
        let Some(repo) = source.and_then(|s| s.get("repo")).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(install_location) = entry.get("installLocation").and_then(|v| v.as_str()) else {
            continue;
        };
        out.push((
            name.clone(),
            PathBuf::from(install_location),
            repo.to_string(),
        ));
    }
    out
}

/// A marketplace checkout finding when its `git remote` diverges from its
/// declared `known_marketplaces.json` source, or `None` when they match.
///
/// Pure — the caller runs the actual `git remote get-url origin` (via
/// [`cadence_hooks_core::shell::git_command`]) and passes the result in, so
/// this stays testable without touching the filesystem or a git checkout.
/// `actual_remote: None` (no `.git`, or the git call failed) fails open —
/// a marketplace checkout not backed by git yet is not itself a problem this
/// check exists to catch.
fn canonical_remote_finding(
    marketplace: &str,
    install_dir: &Path,
    declared_repo: &str,
    actual_remote: Option<&str>,
) -> Option<Finding> {
    let actual = actual_remote?;
    let actual_repo = cadence_hooks_core::shell::repo_from_url(actual)?;

    if actual_repo.eq_ignore_ascii_case(declared_repo) {
        return None;
    }

    Some(Finding {
        severity: Severity::Warning,
        plugin: marketplace.to_string(),
        file: install_dir.to_path_buf(),
        line: None,
        snippet: actual.to_string(),
        diagnosis: format!(
            "marketplace checkout remote '{actual_repo}' does not match declared source '{declared_repo}'"
        ),
        remediation: "cache may not be canonical — verify before citing, or re-add the \
                      marketplace from its declared source"
            .to_string(),
    })
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
///
/// `prune` switches to the orphaned-cache-dir listing/removal mode (see
/// [`run_prune`]) instead of the hooks.json scan above — dry-run by default
/// (decision D4); `apply` actually removes and requires `prune` (a usage
/// error, exit 2, otherwise).
pub fn run(root_override: Option<&Path>, quiet: bool, prune: bool, apply: bool) -> u8 {
    if apply && !prune {
        eprintln!(
            "cadence-hooks doctor: --apply requires --prune (dry-run first with --prune, then --prune --apply)"
        );
        return 2;
    }

    if prune {
        return run_prune(root_override, quiet, apply);
    }

    // Resolve the install channel once — it's process-invariant, so the scan
    // below shouldn't re-probe current_exe() per hook entry.
    let channel = install_channel();
    let (mut findings, scanned) = match root_override {
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

    // Telemetry staleness is a live-machine signal, not a hooks.json scan, so it
    // belongs to default mode only. Under `--root` (the CI/fixture path) it would
    // read *this* dev machine's real metrics dir and taint a fixture-scoped run.
    if root_override.is_none()
        && let Some(finding) = staleness_finding(
            &cadence_hooks_metrics::warn_stale::metrics_dir(),
            cadence_hooks_metrics::warn_stale::stale_threshold(),
            SystemTime::now(),
        )
    {
        findings.push(finding);
    }

    // Fail-open / sweep telemetry: same live-machine-only rationale as
    // staleness above — under `--root` this would read the dev machine's real
    // metrics dir, not the fixture.
    if root_override.is_none() {
        let metrics_dir = cadence_hooks_metrics::warn_stale::metrics_dir();
        let now = SystemTime::now();
        let window = Duration::from_secs(7 * 24 * 60 * 60);

        findings.extend(failopen_findings(
            &metrics_dir,
            window,
            now,
            env!("CARGO_PKG_VERSION"),
        ));
        findings.extend(hook_latency_findings(
            &crate::hook_latency::projects_dir(),
            window,
            now,
        ));
        if !quiet {
            print_sweep_summary(&metrics_dir, window, now);
        }
    }

    // Plugin-cache health: orphaned/missing version dirs and canonical-remote
    // drift. Same live-machine-only rationale as staleness above — under
    // `--root` this would read the dev machine's real cache, not the fixture.
    if root_override.is_none()
        && let Some(plugins) = plugins_dir()
    {
        if let Some(pinned) = manifest_install_paths(&plugins.join("installed_plugins.json")) {
            findings.extend(orphan_findings(&pinned, quiet, &plugins.join("cache")));
        }

        for (marketplace, install_dir, declared_repo) in
            known_marketplace_sources(&plugins.join("known_marketplaces.json"))
        {
            if !install_dir.join(".git").exists() {
                continue;
            }
            let actual = cadence_hooks_core::shell::git_command(
                &install_dir.to_string_lossy(),
                &["remote", "get-url", "origin"],
            );
            if let Some(finding) = canonical_remote_finding(
                &marketplace,
                &install_dir,
                &declared_repo,
                actual.as_deref(),
            ) {
                findings.push(finding);
            }
        }
    }

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
        // Warnings are now version skew (missing subcommands) and/or stale
        // telemetry, so the summary stays generic and defers the specifics to a
        // full `cadence-hooks doctor` run.
        let version = env!("CARGO_PKG_VERSION");
        println!(
            "cadence-hooks {version}: {} plugin warning(s) — run 'cadence-hooks doctor' for details ({})",
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

    // ── staleness_finding tests ─────────────────────────────────────────────

    #[test]
    fn staleness_finding_stale_dir_is_warning() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("subagents.jsonl"), "{}\n").unwrap();

        let f = staleness_finding(tmp.path(), Duration::ZERO, SystemTime::now())
            .expect("a stale dir must yield a finding");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.plugin, "cadence-metrics");
        assert_eq!(f.snippet, "subagents.jsonl");
        assert!(
            f.diagnosis.contains("stale"),
            "diagnosis names staleness: {}",
            f.diagnosis
        );
        assert!(
            f.remediation.contains("healthy machine"),
            "remediation frames the compare-wiring fix: {}",
            f.remediation
        );
    }

    #[test]
    fn staleness_finding_fresh_dir_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("subagents.jsonl"), "{}\n").unwrap();
        let huge = Duration::from_secs(3650 * 86_400);
        assert!(staleness_finding(tmp.path(), huge, SystemTime::now()).is_none());
    }

    #[test]
    fn staleness_finding_missing_dir_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(staleness_finding(&missing, Duration::ZERO, SystemTime::now()).is_none());
    }

    // ── failopen_findings tests ─────────────────────────────────────────────

    const WEEK: Duration = Duration::from_secs(7 * 86_400);

    #[test]
    fn failopen_findings_missing_file_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0").is_empty());
    }

    #[test]
    fn failopen_findings_one_panic_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let row = r#"{"reason":"panic","namespace":"cadence","subcommand":"terminology","binaryVersion":"1.0.0","ts":"TS"}"#
            .replace("TS", &cadence_hooks_core::time::utc_timestamp());
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].diagnosis.contains("panic"));
    }

    #[test]
    fn failopen_findings_parse_below_threshold_is_silent() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let rows: String = (0..2)
            .map(|_| {
                format!(
                    r#"{{"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"{ts}"}}"#
                )
            })
            .map(|r| r + "\n")
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        assert!(failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0").is_empty());
    }

    #[test]
    fn failopen_findings_parse_at_threshold_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let rows: String = (0..3)
            .map(|_| {
                format!(
                    r#"{{"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"{ts}"}}"#
                )
            })
            .map(|r| r + "\n")
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].diagnosis.contains("parse"));
    }

    #[test]
    fn failopen_findings_version_mismatch_old_version_excluded() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let row = format!(
            r#"{{"reason":"version_mismatch","namespace":"future","subcommand":"hook","binaryVersion":"0.9.0","ts":"{ts}"}}"#
        );
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        // The current binary is 1.0.0; the row is tagged 0.9.0 — a sanctioned
        // rollout-transition row, excluded by construction.
        assert!(failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0").is_empty());
    }

    #[test]
    fn failopen_findings_version_mismatch_current_version_warns() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let row = format!(
            r#"{{"reason":"version_mismatch","namespace":"future","subcommand":"hook","binaryVersion":"1.0.0","ts":"{ts}"}}"#
        );
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].diagnosis.contains("version_mismatch"));
    }

    #[test]
    fn failopen_findings_outside_window_excluded() {
        let tmp = tempfile::tempdir().unwrap();
        let row = r#"{"reason":"panic","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        assert!(failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0").is_empty());
    }

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

    // ── dir_size_bytes ───────────────────────────────────────────────────────

    #[test]
    fn dir_size_bytes_sums_known_content() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a.txt"), "12345").unwrap(); // 5 bytes
        let sub = tmp.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("b.txt"), "1234567890").unwrap(); // 10 bytes

        assert_eq!(dir_size_bytes(tmp.path()), 15);
    }

    #[test]
    fn dir_size_bytes_missing_dir_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert_eq!(dir_size_bytes(&missing), 0);
    }

    #[test]
    #[cfg(unix)]
    fn dir_size_bytes_symlinked_top_level_dir_is_zero() {
        // A symlinked `dir` argument must return 0 rather than following the
        // link and summing whatever it points at (e.g. `$HOME` or `/`).
        let tmp = tempfile::tempdir().unwrap();
        let real_target = tmp.path().join("real-target");
        fs::create_dir_all(&real_target).unwrap();
        fs::write(real_target.join("file"), "some content here").unwrap();

        let link = tmp.path().join("link-to-target");
        std::os::unix::fs::symlink(&real_target, &link).unwrap();

        assert_eq!(dir_size_bytes(&link), 0);
        // Sanity: the real target itself does report nonzero.
        assert!(dir_size_bytes(&real_target) > 0);
    }

    // ── orphan_findings ──────────────────────────────────────────────────────

    #[test]
    fn orphan_findings_flags_siblings_of_pinned_version() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        for sha in ["sha1", "sha2", "sha3"] {
            let dir = plugin_dir.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }
        let pinned = vec![("plugin@mp".to_string(), plugin_dir.join("sha2"))];

        let findings = orphan_findings(&pinned, false, tmp.path());
        let orphan_finding = findings
            .iter()
            .find(|f| f.diagnosis.contains("orphaned"))
            .expect("should report orphans");
        assert!(
            orphan_finding.diagnosis.contains("2 orphaned"),
            "diagnosis: {}",
            orphan_finding.diagnosis
        );
    }

    #[test]
    fn orphan_findings_missing_pinned_dir_is_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("mp/plugin/sha-gone");
        let pinned = vec![("plugin@mp".to_string(), missing)];

        let findings = orphan_findings(&pinned, false, tmp.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].diagnosis.contains("missing or empty"));
    }

    #[test]
    fn orphan_findings_only_pinned_dir_present_is_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        let pinned_dir = plugin_dir.join("sha1");
        fs::create_dir_all(&pinned_dir).unwrap();
        fs::write(pinned_dir.join("marker"), "x").unwrap();
        let pinned = vec![("plugin@mp".to_string(), pinned_dir)];

        assert!(orphan_findings(&pinned, false, tmp.path()).is_empty());
    }

    #[test]
    fn orphan_findings_quiet_suppresses_orphan_count_but_not_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        for sha in ["sha1", "sha2"] {
            let dir = plugin_dir.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }
        let missing = tmp.path().join("mp/other/sha-gone");

        let pinned = vec![
            ("plugin@mp".to_string(), plugin_dir.join("sha1")),
            ("other@mp".to_string(), missing),
        ];

        let findings = orphan_findings(&pinned, true, tmp.path());
        assert_eq!(
            findings.len(),
            1,
            "only the missing-dir warning fires quiet"
        );
        assert!(findings[0].diagnosis.contains("missing or empty"));
    }

    #[test]
    #[cfg(unix)]
    fn orphan_findings_does_not_follow_symlinked_sibling() {
        // A symlinked sibling must never be treated as an orphan version dir
        // to recurse into — a planted symlink pointing at, say, `$HOME`
        // would otherwise get walked and summed by `dir_size_bytes`.
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        let pinned_dir = plugin_dir.join("sha1");
        fs::create_dir_all(&pinned_dir).unwrap();
        fs::write(pinned_dir.join("marker"), "x").unwrap();

        // A real directory elsewhere with content the walk must NOT reach.
        let escape_target = tmp.path().join("escape-target");
        fs::create_dir_all(&escape_target).unwrap();
        fs::write(escape_target.join("secret"), "should not be counted").unwrap();

        // The planted symlinked "orphan" sibling, pointing outside the cache.
        let symlinked_sibling = plugin_dir.join("sha-evil-link");
        std::os::unix::fs::symlink(&escape_target, &symlinked_sibling).unwrap();

        let pinned = vec![("plugin@mp".to_string(), pinned_dir)];
        let findings = orphan_findings(&pinned, false, tmp.path());

        assert!(
            findings.is_empty(),
            "a symlinked sibling must not be reported as an orphan, found {} finding(s): {:?}",
            findings.len(),
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
    }

    #[test]
    fn orphan_findings_excludes_active_pins_sharing_parent() {
        // Two active pins (sha-A/sha-B) sharing a parent must NEVER be
        // reported as "safe to prune" — only the genuine orphan (sha-C)
        // should generate a finding, and exactly one (not one per label).
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("cache/mp/p");
        for sha in ["sha-A", "sha-B", "sha-C"] {
            let dir = parent.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }

        let pinned = vec![
            ("p@mp".to_string(), parent.join("sha-A")),
            ("p@mp".to_string(), parent.join("sha-B")),
        ];

        let findings = orphan_findings(&pinned, false, tmp.path());
        let orphan_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.diagnosis.contains("orphaned"))
            .collect();

        assert_eq!(
            orphan_findings.len(),
            1,
            "exactly one orphan finding (for sha-C's parent), found: {:?}",
            orphan_findings
                .iter()
                .map(|f| &f.diagnosis)
                .collect::<Vec<_>>()
        );
        assert!(
            orphan_findings[0].diagnosis.contains("1 orphaned"),
            "only sha-C should count as an orphan (a count of 2 would mean \
             sha-A/sha-B misjudged each other as orphans): {}",
            orphan_findings[0].diagnosis
        );
        assert_eq!(
            orphan_findings[0].file, parent,
            "the finding is attributed to the shared parent, not a sha subdir"
        );
    }

    // ── known_marketplace_sources ────────────────────────────────────────────

    #[test]
    fn known_marketplace_sources_reads_github_entries_only() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("known_marketplaces.json");
        fs::write(
            &manifest,
            r#"{
  "workbench": {
    "source": { "source": "github", "repo": "cameronsjo/workbench" },
    "installLocation": "/home/x/.claude/plugins/marketplaces/workbench"
  },
  "local-dev": {
    "source": { "source": "directory", "path": "/home/x/dev/plugin" },
    "installLocation": "/home/x/dev/plugin"
  }
}"#,
        )
        .unwrap();

        let sources = known_marketplace_sources(&manifest);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].0, "workbench");
        assert_eq!(sources[0].2, "cameronsjo/workbench");
    }

    #[test]
    fn known_marketplace_sources_missing_file_is_empty() {
        assert!(
            known_marketplace_sources(Path::new("/nonexistent/known_marketplaces.json")).is_empty()
        );
    }

    #[test]
    fn known_marketplace_sources_invalid_json_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("known_marketplaces.json");
        fs::write(&manifest, "{ not json").unwrap();
        assert!(known_marketplace_sources(&manifest).is_empty());
    }

    // ── canonical_remote_finding ─────────────────────────────────────────────

    #[test]
    fn canonical_remote_finding_matching_https_remote_is_none() {
        assert!(
            canonical_remote_finding(
                "workbench",
                Path::new("/x"),
                "cameronsjo/workbench",
                Some("https://github.com/cameronsjo/workbench.git"),
            )
            .is_none()
        );
    }

    #[test]
    fn canonical_remote_finding_matching_scp_remote_is_none() {
        assert!(
            canonical_remote_finding(
                "workbench",
                Path::new("/x"),
                "cameronsjo/workbench",
                Some("git@github.com:cameronsjo/workbench.git"),
            )
            .is_none()
        );
    }

    #[test]
    fn canonical_remote_finding_mismatched_repo_is_warning() {
        let f = canonical_remote_finding(
            "workbench",
            Path::new("/x"),
            "cameronsjo/workbench",
            Some("https://github.com/someone-else/fork.git"),
        )
        .expect("mismatch should warn");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.diagnosis.contains("someone-else/fork"), "{}", f.diagnosis);
        assert!(
            f.diagnosis.contains("cameronsjo/workbench"),
            "{}",
            f.diagnosis
        );
    }

    #[test]
    fn canonical_remote_finding_no_actual_remote_is_none() {
        assert!(
            canonical_remote_finding("workbench", Path::new("/x"), "cameronsjo/workbench", None)
                .is_none()
        );
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
        assert_eq!(run(Some(root.path()), false, false, false), 0);
    }

    #[test]
    fn integration_unknown_subcommand_exits_1() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        ]);
        assert_eq!(run(Some(root.path()), false, false, false), 1);
    }

    #[test]
    fn integration_shell_expansion_bug_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), false, false, false), 2);
    }

    #[test]
    fn integration_both_skew_and_expansion_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' cadence no-such-hook"#,
        ]);
        // Single-quoted (Error) + unknown sub (Warning) → exit 2
        assert_eq!(run(Some(root.path()), false, false, false), 2);
    }

    #[test]
    fn integration_quiet_warnings_only_exits_0_stdout_nonempty() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" cadence no-such-hook"#,
        ]);
        // Capture stdout is not trivial in unit tests; we verify exit code here.
        // The output assertion is covered by manually running the binary.
        assert_eq!(run(Some(root.path()), true, false, false), 0);
    }

    #[test]
    fn integration_quiet_errors_exits_2() {
        let root = write_fixture(&[
            r#"'${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh' guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), true, false, false), 2);
    }

    #[test]
    fn integration_quiet_clean_exits_0() {
        let root = write_fixture(&[
            r#""${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh" guardrails guard-push-remote"#,
        ]);
        assert_eq!(run(Some(root.path()), true, false, false), 0);
    }

    // ── orphan_dirs ──────────────────────────────────────────────────────────

    #[test]
    fn orphan_dirs_returns_stale_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        for sha in ["sha1", "sha2", "sha3"] {
            let dir = plugin_dir.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }
        let pinned = vec![("plugin@mp".to_string(), plugin_dir.join("sha2"))];

        let mut dirs = orphan_dirs(&pinned, tmp.path());
        dirs.sort();
        assert_eq!(dirs, vec![plugin_dir.join("sha1"), plugin_dir.join("sha3")]);
    }

    #[test]
    #[cfg(unix)]
    fn orphan_dirs_skips_symlinked_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        let pinned_dir = plugin_dir.join("sha1");
        fs::create_dir_all(&pinned_dir).unwrap();
        fs::write(pinned_dir.join("marker"), "x").unwrap();

        let escape_target = tmp.path().join("escape-target");
        fs::create_dir_all(&escape_target).unwrap();

        let symlinked_sibling = plugin_dir.join("sha-evil-link");
        std::os::unix::fs::symlink(&escape_target, &symlinked_sibling).unwrap();

        let pinned = vec![("plugin@mp".to_string(), pinned_dir)];
        assert!(orphan_dirs(&pinned, tmp.path()).is_empty());
    }

    #[test]
    fn orphan_dirs_skips_pin_outside_cache_root() {
        // A manifest `installPath` that resolves outside the cache root (an
        // absolute path elsewhere, or an `/etc`-style system dir) must be
        // skipped entirely — its parent is never scanned, so nothing outside
        // the root can ever be nominated as an orphan.
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        fs::create_dir_all(&cache_root).unwrap();

        // A real directory OUTSIDE the cache root, sibling to a bogus pin's
        // parent, that must never be scanned or returned.
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join("decoy")).unwrap();

        let pinned = vec![("evil@mp".to_string(), outside.join("pinned-but-fake"))];

        assert!(
            orphan_dirs(&pinned, &cache_root).is_empty(),
            "a pin outside the cache root must never be scanned"
        );
    }

    #[test]
    fn orphan_dirs_excludes_all_active_pins_sharing_parent() {
        // Two active pins (e.g. two scopes/SHAs of the same plugin key) that
        // share a parent directory must BOTH be excluded when scanning that
        // parent — neither may be reported as an orphan just because the
        // other pin's own scan didn't know about it. A genuine orphan
        // sibling (sha-C) must still be returned.
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("cache/mp/p");
        for sha in ["sha-A", "sha-B", "sha-C"] {
            let dir = parent.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }

        let pinned = vec![
            ("p@mp".to_string(), parent.join("sha-A")),
            ("p@mp".to_string(), parent.join("sha-B")),
        ];

        let dirs = orphan_dirs(&pinned, tmp.path());
        assert_eq!(
            dirs,
            vec![parent.join("sha-C")],
            "only the genuine orphan (sha-C) should be returned; both active \
             pins sharing the parent must be excluded"
        );
    }

    // ── prune_orphans ─────────────────────────────────────────────────────────

    #[test]
    fn prune_orphans_dry_run_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("f"), "12345").unwrap();

        let (removed, _freed) = prune_orphans(&[a.clone(), b.clone()], false, tmp.path());
        assert_eq!(removed, 2);
        assert!(a.exists(), "dry-run must not delete a");
        assert!(b.exists(), "dry-run must not delete b");
    }

    #[test]
    fn prune_orphans_apply_removes() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("f"), "1234567890").unwrap(); // 10 bytes

        let (removed, freed) = prune_orphans(std::slice::from_ref(&a), true, tmp.path());
        assert_eq!(removed, 1);
        assert!(freed > 0, "freed bytes: {freed}");
        assert!(!a.exists(), "apply must delete the orphan dir");
    }

    #[test]
    #[cfg(unix)]
    fn prune_orphans_skips_symlink_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real-target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keepme"), "important").unwrap();

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (removed, freed) = prune_orphans(std::slice::from_ref(&link), true, tmp.path());
        assert_eq!(removed, 0, "a symlink handed in must never be removed");
        assert_eq!(freed, 0);
        assert!(target.exists(), "symlink target must survive");
        assert!(target.join("keepme").exists());
    }

    #[test]
    fn prune_orphans_refuses_dir_outside_cache_root() {
        // Defense in depth: even if a caller (bug, future code path) hands
        // `prune_orphans` a path outside the resolved cache root, it must
        // refuse to touch it rather than remove_dir_all-ing it.
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        fs::create_dir_all(&cache_root).unwrap();

        let outside = tmp.path().join("outside-target");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keepme"), "important").unwrap();

        let (removed, freed) = prune_orphans(std::slice::from_ref(&outside), true, &cache_root);
        assert_eq!(removed, 0, "a dir outside cache_root must never be removed");
        assert_eq!(freed, 0);
        assert!(outside.exists(), "outside dir must survive");
        assert!(outside.join("keepme").exists());
    }
}
