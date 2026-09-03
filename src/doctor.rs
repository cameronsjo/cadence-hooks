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

use sha2::{Digest, Sha256};

use crate::registry;
// The session crate's `registry` (peer-session liveness) — aliased because the
// bare name is already taken by the binary's hook-catalog `registry` above.
use cadence_hooks_session::identity as session_identity;
use cadence_hooks_session::registry as session_registry;

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

/// Character ceiling applied to every field [`Finding::render`] sanitizes.
/// `snippet` is a raw `hooks.json` command with no bounded length of its own
/// (cameronsjo/cadence-hooks#440); `diagnosis`/`remediation` can compose
/// prose around an already-`display_safe_bounded`-clamped 200-char error
/// string from `log_failopen` (`MAX_ERROR_CHARS`), so 500 leaves real
/// content intact while still bounding a pathological one.
/// Cap on how many live peers the prune refusal NAMES. The count it reports is
/// the true total; this only bounds the rendered list, so a directory seeded
/// with records cannot flood an operator's terminal.
const MAX_NAMED_PEERS: usize = 10;

const MAX_FINDING_FIELD_CHARS: usize = 500;

impl Finding {
    /// Render this finding for terminal display. Sanitizes every
    /// file-sourced field ONCE, here, rather than at each construction site
    /// (cameronsjo/cadence-hooks#440). A `hooks.json` command snippet, an
    /// `installed_plugins.json` label, or a directory name any of them
    /// interpolated into a diagnosis/remediation string, can all carry ANSI
    /// escapes, C1 controls, or Trojan-Source bidi/Tags primitives — printed
    /// verbatim, those reorder or overwrite the rest of the terminal line.
    /// Per-call-site sanitizing is the wrong shape long-term: every future
    /// check would have to remember, and the one that forgets is invisible
    /// until someone reads the output closely. Pure and side-effect-free so
    /// completeness is testable without capturing real stdout — [`print`]
    /// is the only thing that writes it out, and it is a one-line wrapper,
    /// so no second path can bypass this sanitization.
    ///
    /// **Scope: this covers `Finding` output only.** The `--prune` route,
    /// the other `doctor` print path over third-party-influenced text, is
    /// sanitized separately by [`display_safe_path`] to the same ceiling
    /// (cameronsjo/cadence-hooks#498); a new print site outside both still
    /// has to sanitize itself.
    ///
    /// [`print`]: Finding::print
    fn render(&self) -> String {
        let level = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let location_raw = match self.line {
            Some(n) => format!("{}:{n}", self.file.display()),
            None => self.file.display().to_string(),
        };
        let sanitize = |s: &str| {
            cadence_hooks_metrics::common::display_safe_bounded(s, MAX_FINDING_FIELD_CHARS)
        };
        let plugin = sanitize(&self.plugin);
        let location = sanitize(&location_raw);
        let snippet = sanitize(&self.snippet);
        let diagnosis = sanitize(&self.diagnosis);
        let remediation = sanitize(&self.remediation);
        // <level> [<plugin>] <file>[:line]: <diagnosis>
        //   command: <snippet>
        //   fix: <remediation>
        format!(
            "{level} [{plugin}] {location}: {diagnosis}\n  command: {snippet}\n  fix: {remediation}"
        )
    }

    fn print(&self) {
        println!("{}", self.render());
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

/// Build the once-daily enveloped SessionStart warning nag. Wrapped in a
/// `<cadence-system-message>` envelope and phrased as a `MUST` directive
/// addressed to the hosting session (never the human directly) — the
/// envelope tags are what let a downstream reader (or the session itself)
/// recognize this as machine-directed instruction text rather than a plain
/// status line. The version-skew upgrade hint is appended to the count line
/// only when a skew warning is present — stale-telemetry-only warnings carry
/// no upgrade to suggest.
///
/// Pure and print-free by design: the call site owns the once-daily gate
/// (`cadence_hooks_core::markers::claim_today`, keyed on
/// [`warning_set_token`]) and the actual `println!`, so this shape is
/// unit-testable without touching the marker filesystem.
///
/// **Invariant: no untrusted text.** Everything interpolated here is
/// binary-controlled (the compile-time version, a count, the static upgrade
/// hints). The envelope is trust-elevated instruction text addressed to the
/// hosting session, so interpolating a plugin-controlled `diagnosis` into it
/// would hand plugin metadata a prompt-injection channel — keep specifics in
/// the full `doctor` output, never in the envelope.
///
/// **Known degraded mode:** the gate is content-keyed, not date-keyed, and it
/// is skipped entirely (every call fires) whenever
/// `cadence_hooks_core::markers::marker_dir_is_private` is false — a
/// non-private marker dir (e.g. a world-writable fallback base) means the nag
/// simply repeats every session rather than risk a co-tenant muting it. A
/// `$TMPDIR` reboot that clears the marker dir re-arms the gate the same way:
/// the next session after a reboot sees "first sighting" again even for an
/// unchanged warning set.
fn quiet_warning_envelope(
    version: &str,
    n_warn: usize,
    has_skew: bool,
    channel: InstallChannel,
) -> String {
    let mut count_line = format!("cadence-hooks {version}: {n_warn} plugin warning(s).");
    if has_skew {
        count_line.push_str(&format!(" Version skew: {}.", upgrade_hint_short(channel)));
    }
    format!(
        "<cadence-system-message>\n\
         This appears only on the first session of the day. You MUST run 'cadence-hooks doctor',\n\
         triage, and surface anything actionable to the user in one line before session work ends.\n\
         {count_line}\n\
         </cadence-system-message>"
    )
}

/// Deterministic content token for a warning set: a SHA-256 digest over the
/// running binary's version plus every warning's `diagnosis`, sorted before
/// hashing so the token is order-insensitive — the scan order of `findings`
/// is not part of the identity of "today's warning set". Feeds
/// `cadence_hooks_core::markers::claim_today`'s once-daily gate: the same
/// warning set (same version, same diagnoses) always claims the same slot,
/// while a genuinely different set — a new diagnosis, a dropped one, or a
/// version bump — mints a new token so the gate re-fires the same day instead
/// of waiting until tomorrow (mirrors `warn-stale`'s `verdict_token`
/// precedent, per `claim_today`'s own doc comment).
///
/// **MUST** stay stable across the many separate `cadence-hooks` processes one
/// SessionStart's worth of hooks spans — `std::collections::hash_map::
/// DefaultHasher`/`RandomState` are process-randomized per `HashMap`
/// construction and are unusable here for exactly that reason (this is a
/// distinct concern from `crate::gitstate`'s or `markers::hash_of`'s
/// same-process marker-name hashing, which never needs cross-process
/// stability).
fn warning_set_token(version: &str, diagnoses: &[&str]) -> String {
    // Bag, not set: duplicates are kept deliberately — a warning set gaining or
    // losing a duplicate diagnosis is a genuine change and should re-fire.
    let mut sorted: Vec<&str> = diagnoses.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    // Length-prefix every field instead of joining on a separator: diagnoses
    // interpolate plugin-controlled text, so any in-band delimiter could be
    // embedded to mint a colliding token and mute the day's nag for a
    // different warning set.
    hasher.update((version.len() as u64).to_le_bytes());
    hasher.update(version.as_bytes());
    for d in &sorted {
        hasher.update((d.len() as u64).to_le_bytes());
        hasher.update(d.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
///
/// `report_skew` gates Check 2 (subcommand cross-reference) only — Check 0
/// (missing CLI) and Check 1 (shell-expansion `Error`) always run regardless.
/// `false` is used for a plugin [`marketplace_status`] reports
/// [`MarketplaceStatus::RemovedUpstream`] (cameronsjo/cadence-hooks#474): its
/// stale cached `hooks.json` would otherwise misdiagnose as binary skew, but
/// a shell-expansion bug or an unresolvable CLI dependency in that same file
/// is a real, independent defect this scan must still surface — removed
/// upstream is a reason to suppress the skew warning, not every warning.
fn scan_hooks_json(
    plugin: &str,
    path: &Path,
    raw: &str,
    json: &serde_json::Value,
    channel: InstallChannel,
    report_skew: bool,
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

                // Check 0: a third-party CLI this hook shells to that PATH
                // cannot resolve (#319). Emitted per plugin rather than
                // deduped globally — knowing WHICH hook went inert is the
                // actionable half; a bare "jq is missing" leaves the operator
                // to find the silent no-op themselves.
                findings.extend(missing_cli_findings(
                    cmd,
                    plugin,
                    path,
                    find_line_number(raw, cmd),
                ));

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

                // Check 2: subcommand cross-reference (Warning). Gated by
                // `report_skew` — see this function's doc comment.
                if report_skew
                    && let Some((ns, sub)) = extract_invocation(cmd)
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

/// `<plugins_dir>/cache` — the one place the "cache" join lives. Every
/// plugin-cache consumer in this file should build the path through here
/// (or [`plugins_cache_dir`] below) rather than re-deriving `.join("cache")`
/// independently — a second derivation is how a cache-layout change quietly
/// stops matching one call site while the rest move on (cadence#667).
fn plugins_cache_dir_from(plugins_dir: &Path) -> PathBuf {
    plugins_dir.join("cache")
}

/// Live-machine wrapper: resolves [`plugins_dir`] then joins `cache` via
/// [`plugins_cache_dir_from`]. `None` when `plugins_dir()` can't resolve
/// (`$HOME` unset) — callers report that honestly rather than fabricating
/// a path.
fn plugins_cache_dir() -> Option<PathBuf> {
    Some(plugins_cache_dir_from(&plugins_dir()?))
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

/// Every `enabledPlugins` entry across `settings.json` and
/// `settings.local.json`, keyed by plugin ID (`<plugin>@<marketplace>` — the
/// same key shape `installed_plugins.json` uses, so the two join directly).
/// A local entry wins, matching Claude Code's own settings precedence.
///
/// Returns `None` when no file yields a **non-empty** `enabledPlugins` object.
/// That distinction is load-bearing: an empty map reads as "nothing is enabled"
/// and would warn about every installed hook-shipping plugin at once, so a
/// missing, unparseable, *or empty* settings file must mean *cannot judge*, not
/// *all broken*. An operator with plugins installed and a literally empty
/// `enabledPlugins` is indistinguishable from one whose config has not been
/// written yet, and the second reading is the safe one.
///
/// Membership is keyed on **presence, not value**. The boolean is recorded for
/// callers that want it, but a non-bool value (`{"p@m": "true"}`) still counts
/// as an entry: the question this answers is *did the operator make a decision
/// about this plugin*, and a malformed value is still a decision. Dropping it
/// would make the key read as **absent** and produce exactly the false warning
/// the absent-vs-`false` rule exists to avoid.
///
/// Read through `read_untrusted_config` — a settings file is not this binary's
/// own output, and that reader caps the read and refuses a non-regular file.
fn enabled_plugin_map(config_dir: &Path) -> Option<std::collections::HashMap<String, bool>> {
    let mut map: Option<std::collections::HashMap<String, bool>> = None;
    // Base first, then local — a later insert overwrites, so local wins.
    for name in ["settings.json", "settings.local.json"] {
        let Some(content) =
            cadence_hooks_core::paths::read_untrusted_config(&config_dir.join(name))
        else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(entries) = json.get("enabledPlugins").and_then(|v| v.as_object()) else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        let target = map.get_or_insert_with(std::collections::HashMap::new);
        for (key, value) in entries {
            target.insert(key.clone(), value.as_bool().unwrap_or(false));
        }
    }
    map
}

/// Hook-shipping plugins that are installed but carry **no** `enabledPlugins`
/// entry — so their hooks cannot fire and nothing else reports it (#397).
///
/// This is the self-referential blind spot in one sentence: `warn-stale` is
/// wired *inside* the metrics plugin, so disabling that plugin takes the canary
/// down with the subsystem it watches. The observed cost was a metrics
/// subsystem dark for one to two months on a live machine with no alarm. Doctor
/// is the binary, not a plugin, so it stays up when any plugin is down — which
/// is the only reason this check can see what `warn-stale` structurally cannot.
///
/// **Absent, not `false`.** An explicit `false` is a deliberate choice and stays
/// silent; a missing key is the actual #397 fingerprint (the metrics plugin had
/// no entry at all, unlike the deliberately-disabled plugins beside it).
/// Warning on a deliberate disable would be nagging the operator about their own
/// decision, which is how a real finding gets tuned out.
///
/// Only plugins that actually ship `hooks/hooks.json` are considered — a
/// skills-only plugin being off costs no telemetry and blocks no guard.
fn unenabled_plugin_findings(installs: &[(String, PathBuf)], config_dir: &Path) -> Vec<Finding> {
    let Some(enabled) = enabled_plugin_map(config_dir) else {
        return Vec::new();
    };
    // One finding per plugin, not per install. `manifest_install_paths` emits a
    // row per entry in a plugin's `installs` array, so a plugin with two
    // installed versions would otherwise be reported twice for one decision the
    // operator makes once.
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    installs
        .iter()
        .filter(|(label, _)| !enabled.contains_key(label.as_str()))
        .filter_map(|(label, dir)| {
            let hooks = dir.join("hooks/hooks.json");
            hooks.is_file().then_some((label, hooks))
        })
        // Dedup AFTER the hooks test, never before: an install without a
        // hooks.json must not claim the label and mask a sibling install that
        // has one.
        .filter(|(label, _)| seen.insert(label.as_str()))
        .map(|(label, hooks)| Finding {
            severity: Severity::Warning,
            // The label is an `installed_plugins.json` key — third-party
            // influenced. Every `Finding` field is sanitized once, at the
            // display boundary (`Finding::render`, cameronsjo/cadence-hooks#440),
            // so it is used verbatim here rather than sanitized again at
            // construction.
            plugin: label.clone(),
            file: hooks,
            line: None,
            snippet: format!("{label}: no enabledPlugins entry"),
            diagnosis: format!(
                "{label} is installed and ships hooks, but has no entry in \
                 enabledPlugins — none of its hooks can fire. Any logger or \
                 guard it wires is silently inert, including a staleness \
                 canary wired inside the plugin it watches (#397)"
            ),
            remediation: format!(
                "enable it (`/plugin` → enable {label}) if its hooks should be \
                 running, or set it to false in {} to record the choice — an \
                 explicit false is silent here, a missing key is not",
                config_dir.join("settings.json").display()
            ),
        })
        .collect()
}

/// Scan a single plugin install dir's `hooks/hooks.json`, if present.
/// `report_skew` is forwarded to [`scan_hooks_json`] — see its doc comment.
fn scan_plugin_dir(
    label: &str,
    plugin_dir: &Path,
    channel: InstallChannel,
    report_skew: bool,
) -> Vec<Finding> {
    let hooks_path = plugin_dir.join("hooks/hooks.json");
    let Ok(content) = std::fs::read_to_string(&hooks_path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        // Invalid JSON is its own bug, but not the one this check exists
        // to catch. The plugin loader will surface it.
        return Vec::new();
    };
    scan_hooks_json(label, &hooks_path, &content, &json, channel, report_skew)
}

/// Marketplace resolution status for one installed-plugin label
/// (`<plugin>@<marketplace>`, the `installed_plugins.json` key shape).
///
/// Fails open at every read/parse step — a missing `known_marketplaces.json`,
/// a marketplace key it doesn't recognize, or an unparseable
/// `marketplace.json` all report [`MarketplaceStatus::Resolved`] rather than
/// manufacture a new false claim doctor could not make before this existed.
/// This only ever *adds* a diagnosis (removed-upstream, directory-sourced);
/// it never withholds one the existing skew/cache checks would otherwise
/// emit (cameronsjo/cadence-hooks#474).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarketplaceStatus {
    /// `known_marketplaces.json` sources this marketplace from a local
    /// directory (`"source": "directory"`) — the plugin loads straight from
    /// that path and has no cache dir *by design* (#474 case 2).
    DirectorySourced,
    /// The plugin no longer appears in its github-sourced marketplace's
    /// `marketplace.json` plugin list — removed upstream (#474 case 1).
    RemovedUpstream,
    /// Present in its marketplace, or resolution could not be determined.
    Resolved,
}

/// Parse `known_marketplaces.json` at `path` into its top-level object —
/// shared by [`marketplace_status`] and [`known_marketplace_sources`] so both
/// read the same schema through one place. Two independent parsers of one
/// schema is exactly how they'd drift, and here they'd drift on the
/// `source.source` field #474's diagnosis is keyed off. `None` on a missing
/// file, invalid JSON, or a non-object top level.
fn read_known_marketplaces(path: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.as_object().cloned()
}

/// The `source.source` discriminator string (`"github"`, `"directory"`, ...)
/// for one `known_marketplaces.json` entry, or `None` when absent/malformed.
fn marketplace_source_kind(entry: &serde_json::Value) -> Option<&str> {
    entry.get("source")?.get("source")?.as_str()
}

/// Resolve `label` against `known_marketplaces.json` (and, for a
/// github-sourced marketplace, that marketplace's own `marketplace.json`).
/// See [`MarketplaceStatus`] for the fail-open contract.
fn marketplace_status(label: &str, known_marketplaces: &Path) -> MarketplaceStatus {
    use MarketplaceStatus::{DirectorySourced, RemovedUpstream, Resolved};

    let Some((plugin, marketplace)) = label.split_once('@') else {
        return Resolved;
    };
    let Some(entries) = read_known_marketplaces(known_marketplaces) else {
        return Resolved;
    };
    let Some(entry) = entries.get(marketplace) else {
        return Resolved;
    };

    if marketplace_source_kind(entry) == Some("directory") {
        return DirectorySourced;
    }

    let Some(install_location) = entry.get("installLocation").and_then(|v| v.as_str()) else {
        return Resolved;
    };
    let marketplace_json = Path::new(install_location).join(".claude-plugin/marketplace.json");
    let Ok(mp_content) = std::fs::read_to_string(&marketplace_json) else {
        return Resolved;
    };
    let Ok(mp_json) = serde_json::from_str::<serde_json::Value>(&mp_content) else {
        return Resolved;
    };
    let Some(plugins) = mp_json.get("plugins").and_then(|v| v.as_array()) else {
        return Resolved;
    };

    let present = plugins
        .iter()
        .any(|p| p.get("name").and_then(|v| v.as_str()) == Some(plugin));
    if present { Resolved } else { RemovedUpstream }
}

/// A `Warning` when an installed plugin no longer appears in its
/// marketplace's plugin list — removed upstream, not a binary or cache
/// problem (cameronsjo/cadence-hooks#474 case 1). Replaces the hooks.json
/// skew scan for this plugin entirely: scanning a removed plugin's stale
/// cached hooks.json for subcommand skew reports "not present in this
/// binary" and points the operator at `cargo install --git` to chase
/// subcommands that were intentionally retired — the exact misdiagnosis
/// this finding exists to prevent.
fn removed_upstream_finding(label: &str, install_dir: &Path) -> Finding {
    let marketplace = label.split_once('@').map(|(_, m)| m).unwrap_or(label);
    Finding {
        severity: Severity::Warning,
        plugin: label.to_string(),
        file: install_dir.to_path_buf(),
        line: None,
        snippet: format!("not listed in {marketplace}'s marketplace.json"),
        diagnosis: format!(
            "{label} is installed but no longer appears in the '{marketplace}' \
             marketplace's plugin list — it was removed upstream"
        ),
        remediation: format!(
            "drop the stale entry for {label} from installed_plugins.json (or \
             run /plugin and let Claude Code reconcile it) — this is not a \
             binary or cache problem, so upgrading or reinstalling won't help"
        ),
    }
}

/// Findings from the manifest-driven hooks.json scan across every active
/// install. A plugin still resolved against its marketplace gets the normal
/// scan (skew included). A plugin [`marketplace_status`] reports
/// [`MarketplaceStatus::RemovedUpstream`] gets [`removed_upstream_finding`]
/// **plus** the still-scanned Check 0/Check 1 findings (missing CLI,
/// shell-expansion `Error`s) — only the skew warning is suppressed. Those two
/// checks are independent defects a removed plugin's stale `hooks.json` can
/// still carry, and dropping them let a plugin's own publisher silence
/// doctor's still-firing findings simply by delisting the plugin
/// (cameronsjo/cadence-hooks#474).
fn manifest_scan_findings(
    installs: &[(String, PathBuf)],
    channel: InstallChannel,
    known_marketplaces: &Path,
) -> Vec<Finding> {
    installs
        .iter()
        .flat_map(
            |(label, dir)| match marketplace_status(label, known_marketplaces) {
                MarketplaceStatus::RemovedUpstream => {
                    let mut findings = scan_plugin_dir(label, dir, channel, false);
                    findings.push(removed_upstream_finding(label, dir));
                    findings
                }
                MarketplaceStatus::DirectorySourced | MarketplaceStatus::Resolved => {
                    scan_plugin_dir(label, dir, channel, true)
                }
            },
        )
        .collect()
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
            findings.extend(scan_plugin_dir(&label, &dir, channel, true));
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

/// Telemetry staleness or per-stream flatline as a doctor [`Finding`], or
/// `None` when the watched telemetry is healthy, missing, or empty (fail-open —
/// a fresh install stays silent).
///
/// This is the diagnostic twin of the `metrics warn-stale` SessionStart check:
/// same `telemetry_verdict` core, but doctor consults no once-per-day marker —
/// a diagnostic always reports the current state. Always a `Warning` (exit 1),
/// never an `Error` — telemetry going quiet is advisory, not a shell bug.
fn telemetry_finding(
    dir: &Path,
    extra: &[PathBuf],
    threshold: Duration,
    now: SystemTime,
) -> Option<Finding> {
    use cadence_hooks_metrics::warn_stale::Verdict;
    let verdict = cadence_hooks_metrics::warn_stale::telemetry_verdict(dir, extra, threshold, now)?;
    // The snippet is the finding's identity line, so it names what actually
    // went quiet: the newest file for a whole-subsystem stall, the dead streams
    // for a flatline.
    let snippet = match &verdict {
        Verdict::Stale(report) => report.newest_file.clone(),
        Verdict::Flatline(report) => report
            .streams
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    };
    Some(Finding {
        severity: Severity::Warning,
        plugin: "cadence-metrics".to_string(),
        file: dir.to_path_buf(),
        line: None,
        snippet,
        diagnosis: cadence_hooks_metrics::warn_stale::verdict_summary(&verdict),
        remediation: "compare wiring against a healthy machine — the metrics \
                      plugin may be disabled or its hooks mis-wired \
                      (`cadence-hooks list` shows what should be firing)"
            .to_string(),
    })
}

/// Wrap `s` in single quotes for safe inclusion in a rendered shell command,
/// escaping any embedded single quote via the POSIX `'\''` idiom (close, emit
/// an escaped quote, reopen).
///
/// **Single quotes, not double.** Inside double quotes a shell still expands
/// `$`, backticks and `\`, and a `"` ends the string outright — so a
/// double-quoted path is safe against *spaces* and nothing else. Every
/// interpolated value here is env-derived (`CADENCE_METRICS_DIR`,
/// `CLAUDE_CONFIG_DIR`) and Claude Code injects env vars from a project's
/// checked-in `.claude/settings.json`, so a cloned repository can choose it.
/// The operator then runs `doctor` and pastes what it prints — which is exactly
/// the affordance these remediations added. Inside single quotes nothing is
/// special but `'` itself, which this escapes; a literal newline stays inside
/// the quotes as data rather than becoming a command separator.
///
/// Use this for **every** value interpolated into a command a human is invited
/// to run. Plain diagnostic prose that merely names a path does not need it —
/// nobody executes a sentence.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A copy-pasteable command that lists the recent `failopen.jsonl` rows for one
/// `reason`. Replaces the bare "inspect failopen.jsonl" guidance, which named a
/// file but not a way to read it (cameronsjo/cadence-hooks#398).
///
/// `reason` is always a hardcoded literal from this module; the path is not, so
/// it goes through [`shell_single_quote`]. `grep` matches the serialized
/// key/value pair verbatim, since `serde_json` writes compact JSON with no
/// inner spaces.
fn failopen_inspect_cmd(dir: &Path, reason: &str) -> String {
    let path = shell_single_quote(&format!("{}/failopen.jsonl", dir.display()));
    format!(r#"grep '"reason":"{reason}"' {path} | tail -5"#)
}

/// Fail-open telemetry as doctor `Finding`s — up to 5 (one per `reason`), or
/// none when all counts are below their thresholds. `panic` and `parse` are
/// warned on any/moderate occurrence; the #271 deadline pair is load-correlated
/// (`deadline` warns at 3+) except the suppressed-block row, which warns at 1
/// because each one is an enforcement block that did not fire;
/// `version_mismatch` only counts rows
/// tagged with the CURRENT binary's own version (see
/// `log_failopen::counts_from`'s doc) — an older-version row is the
/// sanctioned release-transition case and is excluded by construction.
///
/// Counts and the `parse`/`panic` recency come from a single
/// `recent_failopen_report` read. Both of those findings name the last recorded
/// `error` — the field that makes the "inspect failopen.jsonl" guidance
/// answerable (cameronsjo/cadence-hooks#398); rows written before that field
/// existed simply omit the clause. The `parse` finding additionally carries
/// recency + version context: when it last fired, on which binary version,
/// and how many of the windowed rows are on the CURRENT version. Its *count*
/// stays window-wide — unlike `version_mismatch`, a bad-stdin wiring problem is
/// not version-specific, so filtering the count would under-report a live one —
/// but zero on the current version disambiguates a burst whose fix already
/// shipped (aging out of the 7-day window) from an ongoing feed problem, which
/// the bare count could not.
/// Words that occupy command position while the thing that actually has to
/// exist is their ARGUMENT. [`referenced_clis`] walks past these.
///
/// `time` is here and also deliberately absent from [`NOT_A_PATH_LOOKUP`]:
/// stock macOS ships no `/usr/bin/time`, so treating it as a CLI would emit a
/// bogus "missing CLI: time" on every such machine.
const TRANSPARENT_PREFIXES: &[&str] = &[
    "sudo", "env", "time", "nice", "nohup", "command", "builtin", "exec", "stdbuf",
];

/// Shell builtins and control words that occupy command position but are never
/// a PATH lookup. Anything here is skipped by [`referenced_clis`].
const NOT_A_PATH_LOOKUP: &[&str] = &[
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "return", "exit", "cd", "echo", "test", "true", "false", "set", "unset", "export",
    "local", "read", "shift", "eval", "exec", "source", ".", "[", "[[", ":",
];

/// External CLI names referenced in command position across `commands`.
///
/// Command position only — a bare word that is the first token of a segment. A
/// word appearing as an ARGUMENT (`--formatter markdownlint`) is not something
/// the hook shells to, and flagging it would produce noise the operator learns
/// to ignore, which is exactly how a real missing dependency gets skipped.
///
/// Skipped by construction: shell builtins ([`NOT_A_PATH_LOOKUP`]), anything
/// containing `/` (a path, resolved without PATH), anything containing `$` (an
/// unexpanded variable this cannot resolve), and assignment words.
fn referenced_clis(command: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for segment in cadence_hooks_core::shell::command_segments(command) {
        // Grouping punctuation first: a subshell like `(mytool --version)` is
        // one segment, and its first token is the garbage string `(mytool` —
        // which is never on PATH, so it would report a permanently-missing CLI
        // that does not exist while never checking the real command word.
        let segment = segment
            .trim_start_matches(['(', '{', ' ', '\t'])
            .trim_end_matches([')', '}', ';', ' ', '\t']);
        let tokens = cadence_hooks_core::shell::tokenize(segment);

        // Then transparent prefixes. `sudo mytool` / `env FOO=x mytool` /
        // `nice -n 10 mytool` otherwise name the PREFIX as the referenced CLI
        // and never see `mytool` — a false negative in exactly the case this
        // check exists for. `sudo` is included here though the guard-side
        // equivalent excludes it: this asks "will this hook run", and under
        // `sudo` the thing that must exist is the argument.
        let mut idx = 0;
        while let Some(word) = tokens.get(idx) {
            if TRANSPARENT_PREFIXES.contains(&word.as_str()) {
                idx += 1;
                // Skip the prefix's own flags and any assignment words it
                // carries, so `env FOO=x mytool` and `nice -n 10 mytool` both
                // land on `mytool`.
                while tokens
                    .get(idx)
                    .is_some_and(|t| t.starts_with('-') || t.contains('='))
                {
                    idx += 1;
                    // A flag taking a separate value (`nice -n 10`) consumes
                    // the value too; a numeric follower is that value.
                    if tokens.get(idx).is_some_and(|t| t.parse::<i64>().is_ok()) {
                        idx += 1;
                    }
                }
            } else {
                break;
            }
        }

        let Some(word) = tokens.get(idx) else {
            continue;
        };
        if word.contains('/')
            || word.contains('$')
            || word.contains('=')
            || word.is_empty()
            || NOT_A_PATH_LOOKUP.contains(&word.as_str())
        {
            continue;
        }
        out.insert(word.clone());
    }
    out
}

/// True when `name` resolves on the current `PATH`.
///
/// A plain PATH walk rather than shelling to `which`/`command -v`: this check
/// exists precisely because a CLI may be absent, and asking a subprocess to
/// answer that question adds a second dependency to the dependency check.
fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable_at(&dir.join(name)))
}

/// True when `candidate` is something the shell could actually exec.
///
/// On unix that means the executable bit, not merely `is_file()`: a stray
/// `chmod 644` placeholder earlier on PATH would otherwise read as present
/// while the shell fails to run it — the check would report health where there
/// is none.
#[cfg(unix)]
fn is_executable_at(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(candidate)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// True when `candidate`, or `candidate` plus any `PATHEXT` suffix, is a file.
///
/// Windows resolves an extensionless name through `PATHEXT`, and the default
/// list is not just `.exe`. Node's global installs ship `.cmd` shims —
/// `prettier.cmd`, `eslint.cmd`, `markdownlint-cli2.cmd` — so hardcoding `.exe`
/// would report a large share of the CLIs hooks actually shell to as missing.
/// No executable-bit concept applies here; presence is the whole test.
#[cfg(windows)]
fn is_executable_at(candidate: &Path) -> bool {
    if candidate.is_file() {
        return true;
    }
    let pathext = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSF;.MSC".to_string());
    pathext.split(';').filter(|e| !e.is_empty()).any(|ext| {
        let mut with_ext = candidate.as_os_str().to_os_string();
        with_ext.push(ext);
        Path::new(&with_ext).is_file()
    })
}

/// Warn once per CLI that an installed hook shells to but PATH cannot resolve.
///
/// The dependency-level sibling of the wrapper-level fail-open in #69. A hook
/// that shells to a third-party CLI and fails open when it is absent becomes a
/// **silent no-op**: no error, no nudge, just a pass — so a guardrail the
/// operator believes is enforcing is quietly inert (#319).
///
/// Setup-time, not per-invocation: the failure mode is a machine that never had
/// the CLI, so paying a PATH walk on every tool call would be pure overhead.
/// `doctor` catches it once.
///
/// Warning, not Error, and deliberately not fatal: this reads a *heuristic*
/// command-word extraction over arbitrary bash, so a false positive is possible
/// and must not be able to fail the run.
fn missing_cli_findings(
    command: &str,
    plugin: &str,
    path: &Path,
    line: Option<usize>,
) -> Vec<Finding> {
    referenced_clis(command)
        .into_iter()
        .filter(|name| !on_path(name))
        .map(|name| Finding {
            severity: Severity::Warning,
            plugin: plugin.to_string(),
            file: path.to_path_buf(),
            line,
            snippet: format!("missing CLI: {name}"),
            diagnosis: format!(
                "an installed hook shells to `{name}`, which PATH cannot \
                 resolve — that hook fails open silently, so a guardrail you \
                 believe is enforcing is inert (no error, no nudge, just a pass)"
            ),
            remediation: format!(
                "install `{name}` or put it on PATH; if the hook is no longer \
                 wanted, remove its entry rather than leaving it inert"
            ),
        })
        .collect()
}

/// Path fragments that mark a cloud-sync provider's local mirror.
///
/// Matched case-insensitively against a path's own components, never as a bare
/// substring — `~/src/dropbox-client` is a project, not a synced tree, and a
/// substring test would flag it. Each entry is a directory NAME a provider
/// creates: macOS iCloud Drive lives under `Library/Mobile Documents`, and
/// modern macOS third-party providers mount under `Library/CloudStorage`.
const CLOUD_SYNC_MARKERS: &[&str] = &[
    "OneDrive",
    "Dropbox",
    "CloudStorage",
    "Mobile Documents",
    "Google Drive",
    "GoogleDrive",
    "pCloud Drive",
    "Sync.com",
];

/// The provider marker in `path`, if any component names one.
///
/// Component-wise and case-insensitive: a provider directory is a real path
/// segment, so testing components avoids the `dropbox-client` false positive a
/// substring search produces, while still catching a nested repo far below the
/// sync root.
///
/// A component matches on exact equality **or** on a `"<marker> - "` prefix.
/// The second form is not a nicety: a Microsoft 365 business or school tenant
/// syncs to a folder named `OneDrive - <Organization>`, which is the dominant
/// real-world shape of the very deployment this check exists to catch, and
/// exact equality alone silently never fires for it. The separator is spelled
/// with surrounding spaces deliberately — a bare `-` boundary would re-admit
/// `dropbox-client`, the exact false positive component matching was chosen to
/// avoid.
fn cloud_sync_marker(path: &Path) -> Option<&'static str> {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .find_map(|segment| {
            CLOUD_SYNC_MARKERS
                .iter()
                .find(|m| {
                    segment.eq_ignore_ascii_case(m)
                        || segment.len() > m.len() + 3
                            && segment[..m.len()].eq_ignore_ascii_case(m)
                            && segment[m.len()..].starts_with(" - ")
                })
                .copied()
        })
}

/// Warn when a directory the guard suite reads on every hook sits inside a
/// cloud-synced tree.
///
/// This names a *cause* the existing `deadline` finding could only tell the
/// operator to go looking for. A synced working directory turns every `.git`
/// stat and read into a network round-trip, which is what drove the #271
/// latency to the point that git-backed checks degraded to fail-open — and it
/// is diagnosable up front from the path alone, months before the latency
/// becomes a P0 (#278).
///
/// Warning, not Error: a synced checkout is slow, not broken, and plenty of
/// people deliberately keep a config dir in one. The point is to name it.
fn cloud_sync_findings(candidates: &[(&str, PathBuf)]) -> Vec<Finding> {
    candidates
        .iter()
        .filter_map(|(label, path)| {
            let provider = cloud_sync_marker(path)?;
            Some(Finding {
                severity: Severity::Warning,
                plugin: "cadence-hooks".to_string(),
                file: path.clone(),
                line: None,
                snippet: format!("{label}: {}", path.display()),
                diagnosis: format!(
                    "the {label} sits inside a {provider} synced tree — every \
                     .git stat and read a guard performs becomes a network \
                     round-trip, which is the precondition that drove git-backed \
                     checks to degrade to fail-open under a deadline (#271)"
                ),
                remediation: format!(
                    "move the {label} outside {provider}, or exclude it from \
                     sync; if it must stay, raise CADENCE_HOOK_DEADLINE_MS and \
                     watch the deadline count in this report"
                ),
            })
        })
        .collect()
}

/// The distribution half of a failopen diagnosis: how many distinct days of the
/// window the reason actually fired on.
///
/// A rolling count alone cannot tell a burst from a drip — 120 rows on one past
/// day and 120 spread across seven read identically, and only the second is the
/// "wiring problem" the remediation text used to assert unconditionally (#404).
/// Rendered only when the window is longer than a day, since `1 of 1 day` says
/// nothing.
fn shape_clause(distinct_days: u64, window_days: u64) -> String {
    match (distinct_days, window_days) {
        (_, w) if w <= 1 => String::new(),
        // Unreachable in practice: `windowed_rows` drops any row without a
        // parseable `ts`, so a `Some(FailopenRecency)` always carries at least
        // one dated row. Kept so the match is total without an `unwrap`-shaped
        // assumption about a helper in another crate.
        (0, _) => String::new(),
        (1, _) => "; all on ONE day".to_string(),
        (d, w) => format!("; spread over {d} of {w} days"),
    }
}

/// Remediation keyed to the shape [`shape_clause`] reports, rather than one
/// sentence asserting a sustained problem regardless of distribution.
///
/// The two shapes want genuinely different next actions: a single-day spike is
/// an episode to correlate against a release or a config change, while a drip
/// across most of the window is a live feed to chase. A count in between says
/// neither confidently, so it says nothing rather than guessing.
///
/// The `>= 5` floor is chosen for the **7-day** window this is called with —
/// "most days of the week". Should the window ever become configurable, derive
/// it from the window length rather than leaving this literal, or the split
/// silently misfires at the new scale.
fn shape_remediation(distinct_days: u64) -> String {
    match distinct_days {
        1 => " Every row landed on a single day — that is an episode, not a \
               steady feed: correlate the date with a release or a config change \
               rather than chasing live wiring."
            .to_string(),
        d if d >= 5 => format!(
            " Rows on {d} separate days is a sustained feed problem, not a \
             one-off burst — chase the wiring."
        ),
        _ => String::new(),
    }
}

fn failopen_findings(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    current_version: &str,
) -> Vec<Finding> {
    // One read of failopen.jsonl yields the per-reason counts plus the recency
    // context for every reason whose finding shows one.
    let (counts, recency) = cadence_hooks_metrics::log_failopen::recent_failopen_report(
        dir,
        window,
        now,
        current_version,
        &["parse", "panic", "version_mismatch"],
    );
    let days = window.as_secs() / 86_400;
    let mut findings = Vec::new();

    if counts.panic >= 1 {
        let last_error = recency
            .get("panic")
            .and_then(|r| r.last_error.as_deref())
            .map(|e| format!("; last error: {e}"))
            .unwrap_or_default();
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("panic: {}", counts.panic),
            diagnosis: format!(
                "{} panic(s) in the last {days} days (failopen.jsonl{last_error})",
                counts.panic
            ),
            remediation: format!(
                "a panic in a check/logger is always a bug — list the rows with \
                 `{}` and file an issue at \
                 https://github.com/cameronsjo/cadence-hooks/issues",
                failopen_inspect_cmd(dir, "panic")
            ),
        });
    }

    if counts.parse >= 3 {
        // Recency + version context so a burst whose fix already shipped reads
        // differently from a live wiring problem — see this fn's doc comment.
        let recency_clause = recency
            .get("parse")
            .map(|r| {
                let current_clause = if r.on_current_version == 0 {
                    format!("none on current {current_version}")
                } else {
                    format!("{} on current {current_version}", r.on_current_version)
                };
                let error_clause = r
                    .last_error
                    .as_deref()
                    .map(|e| format!("; last error: {e}"))
                    .unwrap_or_default();
                format!(
                    "; last: {} on {} — {current_clause}{error_clause}{}",
                    r.last_ts,
                    r.last_version,
                    shape_clause(r.distinct_days, days)
                )
            })
            .unwrap_or_default();
        let shape_remediation = recency
            .get("parse")
            .map(|r| shape_remediation(r.distinct_days))
            .unwrap_or_default();
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("parse: {}", counts.parse),
            diagnosis: format!(
                "{} stdin-parse failure(s) in the last {days} days (failopen.jsonl{recency_clause})",
                counts.parse
            ),
            remediation: format!(
                "occasional malformed payloads are tolerated.{shape_remediation} \
                 No failures on the current binary version usually means the \
                 feed was already fixed — check the CHANGELOG before chasing \
                 wiring. List the rows with `{}`",
                failopen_inspect_cmd(dir, "parse")
            ),
        });
    }

    if counts.version_mismatch >= 1 {
        // Name the invocations, not just the count (#183). The count alone
        // leaves the operator auditing every installed plugin by hand; the
        // pairs turn it into one grep. Absent for rows written before the
        // namespace/subcommand fields existed, so the clause simply drops.
        let missing = recency
            .get("version_mismatch")
            .map(|r| r.subcommands.as_slice())
            .unwrap_or_default();
        let missing_clause = if missing.is_empty() {
            String::new()
        } else {
            format!(" — this binary does not recognize: {}", missing.join(", "))
        };
        let remediation = if missing.is_empty() {
            "compare installed plugin hooks.json subcommand references \
             against 'cadence-hooks list' — this binary doesn't \
             recognize something a plugin expects"
                .to_string()
        } else {
            // EVERY pair, not just the first. The diagnosis names up to four,
            // and an operator following a one-pair grep fixes one inert
            // hooks.json and leaves the rest inert — the multi-pair case is
            // precisely the skew #183 exists to resolve.
            //
            // `-F` with repeated `-e`: fixed strings, so a subcommand carrying
            // a regex metacharacter cannot widen the search to everything, and
            // no alternation needs escaping. The full `namespace subcommand`
            // pair is the needle because that is how a hooks.json line spells
            // the invocation.
            let needles = missing
                .iter()
                .map(|pair| format!("-e {}", shell_single_quote(pair)))
                .collect::<Vec<_>>()
                .join(" ");
            // The RESOLVED cache dir, never a `~/.claude/...` literal.
            // `plugins_dir` honors CLAUDE_CONFIG_DIR precisely because the
            // config dir moves (the `claude-as` profile pattern), and a
            // remediation that greps the wrong tree returns zero hits and reads
            // as "no stale wiring" — a silent false negative inside the one
            // command #183 exists to hand the operator.
            //
            // The two branches quote DIFFERENTLY, on purpose. A resolved path
            // is data, so it is single-quoted. The fallback is a literal
            // authored here whose whole job is to expand — single-quoting it
            // would emit `'~/.claude/plugins/cache'`, and the shell does not
            // expand `~` inside single quotes, so the paste would search a
            // nonexistent relative directory and return zero hits: the same
            // silent "reads as no stale wiring" false negative this branch
            // exists to prevent, just wearing the other face. Double quotes
            // let `$HOME` expand while still surviving a spaced home dir.
            // The fallback is a BARE tilde, not `'~/…'` and not `"$HOME/…"`.
            // Single quotes suppress tilde expansion, so the paste would search
            // a nonexistent relative dir and read as "no stale wiring" — the
            // same false negative this branch exists to prevent. `$HOME` is no
            // better: this branch is reached only when `user_home()` fails,
            // which is precisely when `$HOME` is likely unset in the operator's
            // shell too, expanding to `/.claude/…`. A bare `~` falls back to the
            // passwd entry when `$HOME` is missing, so it is the one form that
            // still resolves here. Safe unquoted: a hardcoded literal with no
            // spaces and no metacharacters.
            let cache = match plugins_cache_dir() {
                Some(dir) => shell_single_quote(&dir.display().to_string()),
                None => "~/.claude/plugins/cache".to_string(),
            };
            format!(
                "grep the installed plugins for the named invocation(s) — \
                 `grep -rlF {needles} {cache}` finds every hooks.json carrying \
                 a named invocation; either upgrade this binary or drop the \
                 stale wiring. `cadence-hooks list` shows what this build \
                 accepts"
            )
        };
        findings.push(Finding {
            severity: Severity::Warning,
            plugin: "cadence-metrics".to_string(),
            file: dir.to_path_buf(),
            line: None,
            snippet: format!("version_mismatch: {}", counts.version_mismatch),
            diagnosis: format!(
                "{} version_mismatch failopen(s) on this binary's own version \
                 ({current_version}) in the last {days} days — a hooks.json/binary \
                 skew that hasn't resolved{missing_clause}",
                counts.version_mismatch
            ),
            remediation,
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

/// Shared with [`platform_drift_status_lines`]'s not-found message, so the two
/// can never independently drift the way two separately-typed literals would
/// (cadence#667): one names where [`find_baseline_in`] actually looked, the
/// other only *describes* that search for the operator, and a second
/// hand-copied literal is exactly how such a description quietly stops
/// matching the real join.
const CADENCE_CACHE_SUBDIR: &str = "workbench/cadence";
/// Shared with [`platform_drift_status_lines`] for the same reason as
/// [`CADENCE_CACHE_SUBDIR`].
const PLATFORM_BASELINE_REL: &str = "config/platform-baseline.json";

/// Find the plugin-shipped platform baseline in the marketplace cache, under
/// `cache_root` (cadence#667, never a hardcoded `~/.claude/plugins/cache`
/// literal): search `<cache_root>/<CADENCE_CACHE_SUBDIR>/*/<PLATFORM_BASELINE_REL>`.
/// Newest pin wins when more than one SHA-pinned copy exists (a mid-update
/// transient, or a stale sibling left behind) — `None` when the cadence
/// plugin's cache directory, or every pin's baseline file, is missing.
/// Pure and testable with a tempdir fixture — no live-machine env dependency;
/// [`print_platform_drift_status`] is the live-machine caller that resolves
/// `cache_root` via [`plugins_cache_dir`] — the same resolver every other
/// plugin-cache consumer in this file goes through (the #183 remediation
/// grep, `run_prune`, `run`'s scan, orphan/remote-drift), so the
/// `CLAUDE_CONFIG_DIR`-set-but-plugins-not-relocated fallback (see
/// [`plugins_dir`]'s own doc comment) stays intact here too.
fn find_baseline_in(cache_root: &Path) -> Option<PathBuf> {
    let cadence_dir = cache_root.join(CADENCE_CACHE_SUBDIR);
    let entries = std::fs::read_dir(&cadence_dir).ok()?;
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let candidate = entry.path().join(PLATFORM_BASELINE_REL);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let is_newer = newest.as_ref().is_none_or(|(t, _)| modified > *t);
        if is_newer {
            newest = Some((modified, candidate));
        }
    }
    newest.map(|(_, path)| path)
}

/// The Claude Code platform version, via a local `claude --version` exec —
/// zero network, same as every other `doctor` data source. `doctor` is a
/// manual, interactive command, so a subprocess here (unlike the SessionStart
/// hook, which resolves the version from the transcript) is acceptable.
fn installed_claude_code_version() -> Option<String> {
    let output = std::process::Command::new("claude")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

/// Pure formatting core: given an explicit baseline path and a pre-resolved
/// Claude Code version, produce the doctor status lines. Unconditional and
/// unthresholded — unlike the SessionStart nudge (which only fires past a
/// gap), `doctor` always shows both current-state lines when a baseline is
/// found, so a `doctor` run never has to guess whether drift-checking ran at
/// all. Testable with a tempdir baseline fixture and an injected version —
/// no live-machine dependency (unlike [`installed_claude_code_version`] and
/// [`print_platform_drift_status`]'s `plugins_cache_dir` resolution, which
/// resolve those inputs).
///
/// `searched_dir` is `Some(cache_root)` — the EXACT same value
/// [`print_platform_drift_status`] passed to [`find_baseline_in`], not an
/// independently reconstructed path (cadence#667) — so the message can never
/// drift from the actual search the way a second copy of the path shape
/// eventually would. `None` means [`plugins_cache_dir`] itself couldn't
/// resolve (`$HOME` unset): the message says so honestly rather than
/// fabricating a path nothing ever searched.
fn platform_drift_status_lines(
    baseline_path: Option<&Path>,
    cc_version: Option<&str>,
    searched_dir: Option<&Path>,
) -> Vec<String> {
    let Some(baseline_path) = baseline_path else {
        return vec![match searched_dir {
            Some(dir) => format!(
                "cadence-hooks doctor: platform baseline not found under {}/{CADENCE_CACHE_SUBDIR}/*/{PLATFORM_BASELINE_REL}",
                dir.display()
            ),
            None => "cadence-hooks doctor: platform baseline not found — could not resolve the \
                      plugin cache dir (`$HOME` unset?)"
                .to_string(),
        }];
    };
    let Ok(content) = std::fs::read_to_string(baseline_path) else {
        return vec![format!(
            "cadence-hooks doctor: platform baseline unreadable: {}",
            baseline_path.display()
        )];
    };
    let Ok(baseline) =
        serde_json::from_str::<cadence_hooks_cadence::platform_drift::Baseline>(&content)
    else {
        return vec![format!(
            "cadence-hooks doctor: platform baseline malformed: {}",
            baseline_path.display()
        )];
    };

    let installed_hooks_version = env!("CARGO_PKG_VERSION");
    let mut lines = vec![format!(
        "cadence-hooks doctor: cadence-hooks {installed_hooks_version} (baseline expects {})",
        baseline.cadence_hooks.current_version
    )];
    lines.push(match cc_version {
        Some(v) => format!(
            "cadence-hooks doctor: Claude Code {v} (last platform sweep: {})",
            baseline.claude_code.last_swept_version
        ),
        None => "cadence-hooks doctor: Claude Code version unavailable (`claude --version` failed)"
            .to_string(),
    });
    lines
}

/// Report cadence-hooks and Claude Code version status against the
/// plugin-shipped baseline — the live-machine wrapper around
/// [`platform_drift_status_lines`]. Resolves the cache root once via
/// [`plugins_cache_dir`] — the same resolver every other plugin-cache
/// consumer in this file goes through — and passes that SAME value to both
/// [`find_baseline_in`] (the actual search) and [`platform_drift_status_lines`]
/// (the message), so the two can never independently drift (cadence#667).
fn print_platform_drift_status() {
    let cache_root = plugins_cache_dir();
    let baseline_path = cache_root.as_deref().and_then(find_baseline_in);
    let cc_version = installed_claude_code_version();
    for line in platform_drift_status_lines(
        baseline_path.as_deref(),
        cc_version.as_deref(),
        cache_root.as_deref(),
    ) {
        println!("{line}");
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
///
/// `known_marketplaces` resolves each `label` via [`marketplace_status`] so a
/// directory-sourced plugin's recorded (but never populated) cache path is
/// exempt from the missing/empty check (#474 case 2).
fn orphan_findings(
    pinned: &[(String, PathBuf)],
    quiet: bool,
    cache_root: &Path,
    known_marketplaces: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (label, install_path) in pinned {
        // A directory-sourced marketplace's plugin loads straight from its
        // declared path and has no cache dir by design (#474 case 2) — the
        // `installPath` the manifest still records under plugins/cache/ is
        // bookkeeping only, and is EXPECTED to be missing/empty. Reporting
        // it as broken sends the operator toward a reinstall that fixes
        // nothing, because nothing is broken.
        if marketplace_status(label, known_marketplaces) == MarketplaceStatus::DirectorySourced {
            continue;
        }

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
            // Name the command that actually does this. The previous text sent
            // readers to `cadence:tend`, which has no plugin-cache handling at
            // all — so the one warning that also carries the safety
            // precondition pointed away from both the tool and the gate
            // (cameronsjo/cadence-hooks#803).
            //
            // Liveness IS enforced: `prune_liveness_gate` refuses `--apply`
            // while any non-stale peer is registered, names them, and offers
            // `CADENCE_DOCTOR_PRUNE_FORCE=1`. What it cannot see is the other
            // half of this line's own precondition — the registry is
            // repo-scoped, so sessions in OTHER checkouts sharing the same
            // global cache are invisible to it (cameronsjo/cadence-hooks#804).
            // That residue is why the text still asks the operator to look
            // across checkouts rather than trusting the refusal alone.
            remediation: "`cadence-hooks doctor --prune` previews; `--prune --apply` removes. \
                 Apply refuses while this repo has live sessions — but the registry is \
                 repo-scoped, so check other checkouts yourself"
                .to_string(),
        });
    }

    findings
}

/// Render an untrusted filesystem path without terminal control sequences.
///
/// Plugin-cache components can derive from third-party marketplace metadata,
/// so prune output has the same terminal-injection boundary as a `Finding`
/// field even though it is printed outside `Finding::render`. Bounded with the
/// same [`MAX_FINDING_FIELD_CHARS`] ceiling, for the same reason `Finding`
/// bounds its own `location` (also a path): filtering constrains the character
/// *set* and not the *length*, and each of the three attacker-influenceable
/// path components can be 255 bytes of chosen text — enough to push the size
/// figure and the `.orphaned_at` marker off the right edge of a non-wrapping
/// pager, where a forged size planted earlier in the name reads as the real one.
fn display_safe_path(path: &Path) -> String {
    cadence_hooks_metrics::common::display_safe_bounded(
        &path.to_string_lossy(),
        MAX_FINDING_FIELD_CHARS,
    )
}

/// Appended to a rendered path whose displayed text is not literally the path
/// on disk. Deliberately prose rather than a substitution character: the note
/// has to survive being read in a captured log by someone who cannot see the
/// original bytes.
const HIDDEN_CHARS_NOTE: &str = " [name contains hidden characters]";

/// Whether sanitizing `path` for display changes its character content — i.e.
/// the rendered string is not the name on disk.
///
/// `display_safe` is a filter: it **deletes** unsafe characters rather than
/// substituting a placeholder, so two distinct directories can render to one
/// identical line. That is the same non-injectivity `filename_safe`'s doc
/// argues against, and it lands here at the worst moment — a deletion listing.
/// Measured cases: a dir named `\u{200b}` + the active pinned SHA renders as
/// the active pin, which prune never touches; a dir whose name is *entirely*
/// strippable renders as its parent plugin directory. Flagging the line cannot
/// restore the bytes, but it tells the operator the string is not the path,
/// which is what a captured `--prune > log` otherwise loses.
///
/// Length is deliberately excluded — [`display_safe_bounded`] marks its own
/// truncation with an ellipsis, so a merely long name is not "hidden".
///
/// [`display_safe_bounded`]: cadence_hooks_metrics::common::display_safe_bounded
fn path_has_hidden_chars(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    cadence_hooks_metrics::common::display_safe(&raw) != raw
}

/// [`display_safe_path`] plus the [`HIDDEN_CHARS_NOTE`] marker when
/// sanitization changed the name. The note sits adjacent to the path it
/// describes rather than at the end of the line, so a message interpolating
/// two paths stays unambiguous about which one was mangled.
fn display_safe_path_flagged(path: &Path) -> String {
    let shown = display_safe_path(path);
    if path_has_hidden_chars(path) {
        format!("{shown}{HIDDEN_CHARS_NOTE}")
    } else {
        shown
    }
}

/// One human-readable `doctor --prune` listing row.
///
/// Kept pure so the separate stdout path has a direct sanitizer regression
/// test rather than relying on `Finding::render` tests that never reach it.
fn render_orphan_dir_line(dir: &Path, size: u64, marked: bool) -> String {
    let mib = size as f64 / (1024.0 * 1024.0);
    let marker_note = if marked { " [marked .orphaned_at]" } else { "" };
    format!(
        "  {} (~{mib:.1} MiB){marker_note}",
        display_safe_path_flagged(dir)
    )
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
                display_safe_path_flagged(dir),
                display_safe_path_flagged(cache_root)
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
                    display_safe_path_flagged(dir)
                );
            }
        }
    }

    (removed, freed)
}

/// Whether `doctor --prune --apply` may proceed, or is blocked because live peer
/// sessions are still running and may be pinned to plugin-cache version dirs
/// that pruning would pull out from under them.
enum PruneGate {
    Proceed,
    Blocked(Vec<String>),
}

/// Decide whether `--prune --apply` may run. Pure over its inputs so it is
/// testable without a live registry.
///
/// `force` overrides everything (the `CADENCE_DOCTOR_PRUNE_FORCE` escape hatch).
/// It blocks when any non-stale peer is registered in EITHER registry, naming
/// them. `own_session_id` is `""` so the invoking session itself counts
/// as a live peer — a prune must not delete dirs the caller is pinned to —
/// matching how `run_status` enumerates peers.
///
/// Reads TWO registries and unions them (cadence-hooks#634). The per-checkout
/// one answers "who else is in this repo"; the cross-checkout mirror
/// (`session_registry::global_sessions_dir`) answers the question this gate
/// actually has, which is "who else on this machine is reading the plugin
/// cache" — a resource no single checkout owns. Gating on the local registry
/// alone was under-protective by construction: the sessions most likely to be
/// pinned to a retired version dir are the long-running ones, and there is no
/// reason those sit in the repo you happen to be pruning from.
///
/// A `None` local dir no longer short-circuits. Not being inside a git
/// repository says nothing about whether other sessions are live, and treating
/// it as "nothing to protect" is exactly the reasoning that made this
/// repo-scoped in the first place — the mirror is still consulted.
///
/// Deduplicated by session id, because a session registers in BOTH and would
/// otherwise be named twice in a refusal that counts what it names.
/// `global_dir` is a PARAMETER, not resolved in here, and that is load-bearing
/// for the tests rather than a style preference. Resolving it internally would
/// make every case read the machine's real cross-checkout registry — a
/// directory that is empty today only because nothing has written it yet, so
/// `prune_liveness_gate_empty_dir_proceeds` and its siblings would pass now and
/// go red on a real machine the moment sessions start mirroring, with CI still
/// green. Injecting it keeps each case hermetic and lets the union itself be
/// asserted.
fn prune_liveness_gate(
    sessions_dir: Option<&Path>,
    global_dir: Option<&Path>,
    stale_secs: u64,
    force: bool,
) -> PruneGate {
    if force {
        return PruneGate::Proceed;
    }

    // Collect by session id, PREFERRING the record that carries a repo.
    //
    // First-wins would take whichever registry we happened to read first — the
    // local one — and during rollout that is exactly the record written by a
    // pre-`repo` binary, while the mirrored one has the field. The refusal
    // would then drop the only part a reader can act on. Which registry a
    // record came from is not the question; whether it can be acted on is.
    let mut by_session: std::collections::BTreeMap<String, (String, Option<String>)> =
        std::collections::BTreeMap::new();

    for dir in sessions_dir.into_iter().chain(global_dir) {
        for peer in session_registry::live_peers(dir, "", stale_secs) {
            let entry = by_session
                .entry(peer.record.session_id.clone())
                .or_insert_with(|| (peer.record.name.clone(), None));
            if entry.1.is_none() && peer.record.repo.is_some() {
                entry.1 = peer.record.repo.clone();
                entry.0 = peer.record.name.clone();
            }
        }
    }

    // SANITIZE both fields. They come from JSON files this process did not
    // write — in a shared directory, from other sessions entirely — and land on
    // an interactive terminal in the refusal for a DESTRUCTIVE command. A `\r`
    // plus crafted text can rewrite the rendered line, e.g. appending "0 live
    // sessions — safe to force", which talks the operator into
    // CADENCE_DOCTOR_PRUNE_FORCE=1 and a remove_dir_all. Every other consumer
    // of these fields already sanitizes; this call site was the lone exception.
    //
    // The list is capped so a seeded directory cannot flood the terminal; the
    // count reported alongside it is the true total.
    let total = by_session.len();
    let mut names: Vec<String> = by_session
        .into_values()
        .take(MAX_NAMED_PEERS)
        .map(|(name, repo)| {
            let name = session_identity::sanitize_field(&name, 40);
            match repo {
                Some(repo) => format!("{name} ({})", session_identity::sanitize_field(&repo, 120)),
                None => name,
            }
        })
        .collect();
    if total > names.len() {
        names.push(format!("and {} more", total - names.len()));
    }

    if names.is_empty() {
        return PruneGate::Proceed;
    }
    PruneGate::Blocked(names)
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
                    display_safe_path(root)
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
                plugins_cache_dir_from(&plugins),
            )
        }
    };

    let Some(pinned) = manifest_install_paths(&manifest) else {
        if !quiet {
            println!(
                "cadence-hooks doctor --prune: no installed-plugins manifest at {} — nothing to prune",
                display_safe_path(&manifest)
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
            // `.orphaned_at` is written externally by Claude Code's own
            // plugin loader when it retires a version dir, not by anything
            // in this repo — surfacing it here is advisory ("this one was
            // already flagged upstream"), not a marker this codebase creates.
            println!(
                "{}",
                render_orphan_dir_line(dir, size, dir.join(".orphaned_at").exists())
            );
        }
    }

    // Refuse to delete while live peer sessions may be pinned to these dirs.
    // Only under default mode (not `--root`), mirroring the legacy-config gating
    // below — `--root` fixtures must stay hermetic and never read live sessions.
    // Dry-run deletes nothing, so the gate only guards the destructive `apply`.
    if root_override.is_none() && apply {
        let stale_secs = session_registry::stale_minutes() * 60;
        let force = matches!(
            std::env::var("CADENCE_DOCTOR_PRUNE_FORCE").as_deref(),
            Ok("1") | Ok("true")
        );
        let sessions_dir = std::env::current_dir()
            .ok()
            .and_then(|cwd| session_registry::sessions_dir(&cwd.to_string_lossy()));
        let global_dir = session_registry::global_sessions_dir();
        if let PruneGate::Blocked(names) = prune_liveness_gate(
            sessions_dir.as_deref(),
            Some(global_dir.as_path()),
            stale_secs,
            force,
        ) {
            eprintln!(
                "cadence-hooks doctor --prune --apply: refusing to prune — {} live session(s) may be pinned to these version dirs: {}. \
                 The gate blocks while any session is REGISTERED, including this one, so /reload-plugins does not clear it: \
                 end those sessions, or wait out the staleness window, then re-run. \
                 Or re-run with CADENCE_DOCTOR_PRUNE_FORCE=1 to prune anyway.",
                names.len(),
                names.join(", ")
            );
            return 0;
        }
    }

    let (removed, freed_bytes) = prune_orphans(&dirs, apply, &cache_root);
    let freed_mib = freed_bytes as f64 / (1024.0 * 1024.0);

    if !quiet {
        if apply {
            println!(
                "cadence-hooks doctor --prune --apply: removed {removed} orphaned version dir(s), freed ~{freed_mib:.1} MiB"
            );
            println!(
                "  If any Claude Code session is currently running, run /reload-plugins in it now."
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
    let Some(entries) = read_known_marketplaces(path) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (name, entry) in &entries {
        if marketplace_source_kind(entry) != Some("github") {
            continue;
        }
        let Some(repo) = entry
            .get("source")
            .and_then(|s| s.get("repo"))
            .and_then(|v| v.as_str())
        else {
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

/// Legacy per-guard config files the unified loader no longer reads
/// (cadence-hooks#153). Presence is a `Warning`, not an `Error`: the repo's
/// softening is silently inert until migrated — the hard cut's non-silent net.
const LEGACY_CONFIG_FILES: &[&str] = &["redaction.json", "terminology.json"];

/// One `Warning` per orphaned legacy config file under `<root>/.claude/`, empty
/// when none is present. Detects any entry at the path (regular file or
/// symlink) via `symlink_metadata` — no read — so a leftover file is surfaced
/// regardless of what it is. Pure; the caller resolves the repo root.
fn legacy_config_findings(root: &Path) -> Vec<Finding> {
    let claude = root.join(".claude");
    LEGACY_CONFIG_FILES
        .iter()
        .filter_map(|name| {
            let path = claude.join(name);
            if std::fs::symlink_metadata(&path).is_err() {
                return None;
            }
            Some(Finding {
                severity: Severity::Warning,
                plugin: "cadence-hooks".to_string(),
                file: path.clone(),
                line: None,
                snippet: (*name).to_string(),
                diagnosis: format!(
                    "legacy guard config '{name}' present but no longer read — \
                     unified into .claude/cadence.json (#153)"
                ),
                remediation: "run 'cadence-hooks migrate-config' to merge it into \
                              .claude/cadence.json (renames the legacy file to \
                              *.json.migrated)"
                    .to_string(),
            })
        })
        .collect()
}

/// A `Warning` when `<root>/.claude/cadence.json` is present but not valid JSON,
/// or `None` when it is absent, unreadable/special (fail-open), or parses.
///
/// Runtime is fail-open — a malformed `cadence.json` silently yields every
/// guard's default config, so its per-repo softening quietly stops applying.
/// This makes that non-silent, without ever failing the run (advisory only).
fn cadence_config_parse_finding(root: &Path) -> Option<Finding> {
    let path = root.join(cadence_hooks_core::config::CADENCE_CONFIG_REL);
    let content = cadence_hooks_core::paths::read_untrusted_config(&path)?;
    // Two distinct failures both leave every guard on its default config: a
    // syntax error, and a syntactically-valid but non-object top level. The
    // latter is silent — `load_cadence_section` reads each section via
    // `value.get(section)`, which yields nothing for an array/number/string,
    // so the section lookup falls through to the default with no error.
    let diagnosis = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(value) if value.is_object() => return None,
        Ok(_) => {
            "`.claude/cadence.json` is present but its top level is not a JSON \
                  object — guards read their section via `value.get(section)`, which \
                  yields nothing for a non-object, so they fall open to default \
                  config and their per-repo softening is silently inert"
        }
        Err(_) => {
            "`.claude/cadence.json` is present but not valid JSON — guards \
                   fall open to default config, so their per-repo softening is \
                   silently inert"
        }
    };
    Some(Finding {
        severity: Severity::Warning,
        plugin: "cadence-hooks".to_string(),
        file: path,
        line: None,
        snippet: "cadence.json".to_string(),
        diagnosis: diagnosis.to_string(),
        remediation: "make `.claude/cadence.json` a valid JSON object; \
                      'cadence-hooks migrate-config' writes a valid file from any \
                      legacy config"
            .to_string(),
    })
}

/// Guardrails identity health from the USER settings.json: is
/// `CADENCE_ALLOWED_OWNERS` set, and are the retired `GIT_GUARDRAILS_ALLOWED_*`
/// keys still lying around (cameronsjo/cadence-hooks#275)?
///
/// Advisory only — a `Warning`, never an `Error`. An unset allowlist is a
/// legitimate state on a machine that has not run `configure guardrails` yet;
/// what makes it worth surfacing is that the failure it produces is a *block*
/// on every push and gh write, which reads as a guard bug rather than as
/// missing configuration.
///
/// Fails open on an unreadable or malformed settings file: this is a config
/// health check, not a JSON validator, and a false finding about a file the
/// binary could not read would be worse than silence (ADR-0001).
fn guardrails_identity_finding(settings_path: &Path) -> Option<Finding> {
    let content = cadence_hooks_core::paths::read_untrusted_config(settings_path)?;
    let root = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => return None,
    };
    let current = crate::configure_guardrails::current_from(&root);

    let diagnosis = match (current.owners.is_empty(), current.has_legacy()) {
        (false, false) => return None,
        (false, true) => format!(
            "`{}` is set, but the retired `{}`/`{}` keys are still present in the \
             env block and are no longer read — they mislead the next person who \
             edits this file",
            crate::configure_guardrails::OWNERS_KEY,
            crate::configure_guardrails::LEGACY_OWNERS_KEY,
            crate::configure_guardrails::LEGACY_REPOS_KEY,
        ),
        (true, true) => format!(
            "only the retired `{}` key is set — this binary reads `{}`, so every \
             `git push` and `gh` write is blocked",
            crate::configure_guardrails::LEGACY_OWNERS_KEY,
            crate::configure_guardrails::OWNERS_KEY,
        ),
        (true, false) => format!(
            "`{}` is unset or empty — the push and gh-write guards block every \
             operation until it names at least one GitHub owner",
            crate::configure_guardrails::OWNERS_KEY,
        ),
    };

    Some(Finding {
        severity: Severity::Warning,
        plugin: "cadence-guardrails".to_string(),
        file: settings_path.to_path_buf(),
        line: None,
        snippet: crate::configure_guardrails::OWNERS_KEY.to_string(),
        diagnosis,
        remediation: "run `cadence-hooks configure guardrails` from a terminal \
                      (it is refused under Claude Code — it edits the push allowlist), \
                      then restart Claude Code"
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
                    let known_marketplaces = plugins.join("known_marketplaces.json");
                    let mut findings =
                        manifest_scan_findings(&installs, channel, &known_marketplaces);
                    // Only reachable from the manifest branch: the enablement
                    // join needs the manifest's `<plugin>@<marketplace>` keys,
                    // which the recursive cache walk cannot reconstruct (its
                    // labels are directory paths).
                    findings.extend(unenabled_plugin_findings(
                        &installs,
                        &cadence_hooks_core::paths::claude_config_dir(),
                    ));
                    (findings, scanned)
                }
                None => {
                    // No readable manifest — recursively scan the cache instead.
                    let cache = plugins_cache_dir_from(&plugins);
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
        && let Some(finding) = telemetry_finding(
            &cadence_hooks_metrics::warn_stale::metrics_dir(),
            &cadence_hooks_metrics::warn_stale::extra_watched_paths(),
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
        // Names the CAUSE the deadline finding above can only tell the operator
        // to go looking for (#278). Gated with the other live-machine reads:
        // under `--root` these would report the dev machine's real dirs, not
        // the fixture.
        let mut sync_candidates: Vec<(&str, PathBuf)> = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            sync_candidates.push(("working directory", cwd));
        }
        // Through the shared resolver, NOT a raw `CLAUDE_CONFIG_DIR` read —
        // the same call `plugins_dir()` makes above. Most operators never set
        // that variable, so reading it directly skipped the DEFAULT config dir
        // entirely: `$HOME/.claude`. That default is exactly what Windows
        // Known Folder Redirection parks inside OneDrive under corporate
        // policy, which is the deployment this check exists to surface.
        sync_candidates.push((
            "Claude config dir",
            cadence_hooks_core::paths::claude_config_dir(),
        ));
        findings.extend(cloud_sync_findings(&sync_candidates));
        // Guardrails identity, from the USER settings.json — the same file
        // `configure guardrails` writes. Live-machine read, so it is gated with
        // the rest of this block; under `--root` there is no user config to
        // inspect.
        if let Some(finding) =
            guardrails_identity_finding(&crate::configure_guardrails::user_settings_path())
        {
            findings.push(finding);
        }
        if !quiet {
            print_sweep_summary(&metrics_dir, window, now);
            print_platform_drift_status();
        }
    }

    // Plugin-cache health: orphaned/missing version dirs and canonical-remote
    // drift. Same live-machine-only rationale as staleness above — under
    // `--root` this would read the dev machine's real cache, not the fixture.
    if root_override.is_none()
        && let Some(plugins) = plugins_dir()
    {
        if let Some(pinned) = manifest_install_paths(&plugins.join("installed_plugins.json")) {
            findings.extend(orphan_findings(
                &pinned,
                quiet,
                &plugins_cache_dir_from(&plugins),
                &plugins.join("known_marketplaces.json"),
            ));
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

    // Repo-local guard-config health: orphaned legacy files (ignored under the
    // #153 hard cut) and a malformed cadence.json. Repo-scoped, so default mode
    // only — under `--root` (the CI/fixture path) there is no "current repo" to
    // inspect, same live-machine-only rationale as the checks above.
    if root_override.is_none()
        && let Ok(cwd) = std::env::current_dir()
        && let Some(repo_root) = cadence_hooks_core::paths::find_git_root(&cwd.to_string_lossy())
    {
        findings.extend(legacy_config_findings(&repo_root));
        if let Some(finding) = cadence_config_parse_finding(&repo_root) {
            findings.push(finding);
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
        // Warnings only in quiet mode: an enveloped nag to stdout, gated to at
        // most once per calendar day per distinct warning set (#632).
        // Warnings are now version skew (missing subcommands) and/or stale
        // telemetry, so the summary stays generic and defers the specifics to a
        // full `cadence-hooks doctor` run.
        let version = env!("CARGO_PKG_VERSION");
        let has_skew = warnings
            .iter()
            .any(|w| w.diagnosis.contains("not present in this binary"));
        let diagnoses: Vec<&str> = warnings.iter().map(|w| w.diagnosis.as_str()).collect();
        let token = warning_set_token(version, &diagnoses);
        if cadence_hooks_core::markers::claim_today("doctor-warnings", &token) {
            println!(
                "{}",
                quiet_warning_envelope(version, warnings.len(), has_skew, channel)
            );
        }
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

    // ── Finding::render sanitization (#440) ─────────────────────────────────

    fn hostile_finding(text: &str) -> Finding {
        Finding {
            severity: Severity::Warning,
            plugin: text.to_string(),
            file: PathBuf::from(text),
            line: None,
            snippet: text.to_string(),
            diagnosis: text.to_string(),
            remediation: text.to_string(),
        }
    }

    #[test]
    fn render_strips_bidi_and_ansi_and_tags_from_every_field() {
        // One hostile string planted in EVERY text-bearing field — plugin,
        // file (via `location`), snippet, diagnosis, remediation — proves
        // completeness: a fix that only sanitized the one call site #438
        // added would leave every other field carrying these bytes straight
        // through to the terminal.
        let hostile = "safe\u{202E}\u{1b}[31mtext\u{E0001}\u{E0041}\u{E007F}\u{200B}";
        let rendered = hostile_finding(hostile).render();

        for bad in [
            '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
            '\u{E0001}',
            '\u{E0041}',
            '\u{E007F}', // Tags block
            '\u{200B}',  // zero-width space
        ] {
            assert!(
                !rendered.contains(bad),
                "rendered output still carries {bad:?}: {rendered:?}"
            );
        }
        assert!(
            !rendered.contains('\u{1b}'),
            "ESC (start of the ANSI sequence) survived: {rendered:?}"
        );
        // A denylist filter, not wholesale deletion of the field — ordinary
        // text on either side of the smuggled characters must still render.
        assert!(rendered.contains("safe"), "{rendered:?}");
        assert!(rendered.contains("text"), "{rendered:?}");
    }

    #[test]
    fn render_bounds_an_unbounded_snippet() {
        // hooks.json places no length ceiling on a command string — the
        // issue's "worth checking... a length ceiling belongs on snippet
        // too" note.
        let long = "x".repeat(MAX_FINDING_FIELD_CHARS + 250);
        let mut finding = hostile_finding("");
        finding.snippet = long.clone();

        let rendered = finding.render();
        assert!(
            rendered.len() < long.len(),
            "an unbounded snippet must be truncated: rendered {} chars from an input of {}",
            rendered.len(),
            long.len()
        );
        assert!(
            rendered.contains('…'),
            "truncation must leave the ellipsis marker: {rendered:?}"
        );
    }

    #[test]
    fn render_leaves_ordinary_unicode_intact() {
        // The filter is a denylist over specific control/format categories,
        // not "non-ASCII" — legitimate Unicode prose in a diagnosis must
        // survive unchanged.
        let mut finding = hostile_finding("plugin@mp");
        finding.diagnosis = "cadence log-commit — naïve 日本語 ✓".to_string();

        let rendered = finding.render();
        assert!(rendered.contains("cadence log-commit — naïve 日本語 ✓"));
    }

    // ── telemetry_finding tests ─────────────────────────────────────────────

    const NO_EXTRA: &[PathBuf] = &[];

    /// Write `name` and backdate its mtime by `days`.
    fn write_aged(dir: &Path, name: &str, days: u64) {
        let path = dir.join(name);
        fs::write(&path, "{}\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))
            .unwrap();
    }

    #[test]
    fn telemetry_finding_stale_dir_is_warning() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("subagents.jsonl"), "{}\n").unwrap();

        let f = telemetry_finding(tmp.path(), NO_EXTRA, Duration::ZERO, SystemTime::now())
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
    fn telemetry_finding_fresh_dir_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("subagents.jsonl"), "{}\n").unwrap();
        let huge = Duration::from_secs(3650 * 86_400);
        assert!(telemetry_finding(tmp.path(), NO_EXTRA, huge, SystemTime::now()).is_none());
    }

    #[test]
    fn telemetry_finding_missing_dir_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(telemetry_finding(&missing, NO_EXTRA, Duration::ZERO, SystemTime::now()).is_none());
    }

    // Doctor's half of #217: a dead stream beside a live one must surface here
    // too, and the snippet must name the DEAD stream — a finding whose identity
    // line named the fresh file would point the reader at the wrong thing.
    #[test]
    fn telemetry_finding_flatline_names_the_dead_stream() {
        let tmp = tempfile::tempdir().unwrap();
        write_aged(tmp.path(), "commits.jsonl", 40);
        write_aged(tmp.path(), "sessions.jsonl", 0);
        let four_days = Duration::from_secs(4 * 86_400);

        let f = telemetry_finding(tmp.path(), NO_EXTRA, four_days, SystemTime::now())
            .expect("a flatlined stream must yield a finding");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.snippet, "commits.jsonl", "snippet names the DEAD stream");
        assert!(
            f.diagnosis.contains("flatlined") && f.diagnosis.contains("sessions.jsonl"),
            "diagnosis contrasts dead against live: {}",
            f.diagnosis
        );
    }

    // ── unenabled_plugin_findings tests (#397) ──────────────────────────────

    /// A plugin install dir that ships a `hooks/hooks.json`.
    fn plugin_with_hooks(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("hooks")).unwrap();
        fs::write(dir.join("hooks/hooks.json"), "{}").unwrap();
        dir
    }

    fn write_settings(config: &Path, body: &str) {
        fs::create_dir_all(config).unwrap();
        fs::write(config.join("settings.json"), body).unwrap();
    }

    // THE #397 REGRESSION TEST. A hook-shipping plugin with no enabledPlugins
    // entry is exactly the fingerprint the audit found: the metrics plugin was
    // absent from the map entirely and its loggers had been inert for months.
    #[test]
    fn absent_enabled_entry_is_a_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"other@workbench":true}}"#);
        let dir = plugin_with_hooks(tmp.path(), "metrics-install");
        let installs = vec![("cadence-metrics@workbench".to_string(), dir)];

        let findings = unenabled_plugin_findings(&installs, &config);
        assert_eq!(findings.len(), 1, "the absent plugin must be reported");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(
            findings[0].diagnosis.contains("cadence-metrics@workbench"),
            "names the plugin: {}",
            findings[0].diagnosis
        );
    }

    // The noise floor for #397: an explicit `false` is the operator's own
    // decision. Warning on it is nagging, and a nagged operator stops reading
    // the finding that matters.
    #[test]
    fn explicit_false_is_silent() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"persona@lab":false}}"#);
        let dir = plugin_with_hooks(tmp.path(), "persona-install");
        let installs = vec![("persona@lab".to_string(), dir)];

        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
    }

    #[test]
    fn enabled_plugin_is_silent() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"live@workbench":true}}"#);
        let dir = plugin_with_hooks(tmp.path(), "live-install");
        let installs = vec![("live@workbench".to_string(), dir)];

        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
    }

    // A plugin with no hooks costs no telemetry and blocks no guard when off.
    // One finding per plugin, not per installed version — the operator makes
    // the enable decision once.
    #[test]
    fn duplicate_installs_report_once() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"unrelated@m":true}}"#);
        let a = plugin_with_hooks(tmp.path(), "v1");
        let b = plugin_with_hooks(tmp.path(), "v2");
        let installs = vec![
            ("dup@workbench".to_string(), a),
            ("dup@workbench".to_string(), b),
        ];

        assert_eq!(unenabled_plugin_findings(&installs, &config).len(), 1);
    }

    // The dedup must not run before the hooks test: a hookless install listed
    // first would otherwise claim the label and hide the install that has one.
    #[test]
    fn hookless_install_does_not_mask_its_hooked_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"unrelated@m":true}}"#);
        let hookless = tmp.path().join("no-hooks");
        fs::create_dir_all(&hookless).unwrap();
        let hooked = plugin_with_hooks(tmp.path(), "has-hooks");
        let installs = vec![
            ("mixed@workbench".to_string(), hookless),
            ("mixed@workbench".to_string(), hooked),
        ];

        assert_eq!(
            unenabled_plugin_findings(&installs, &config).len(),
            1,
            "the hooked install must still be reported"
        );
    }

    #[test]
    fn plugin_without_hooks_is_not_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"unrelated@m":true}}"#);
        let dir = tmp.path().join("skills-only");
        fs::create_dir_all(dir.join("skills")).unwrap();
        let installs = vec![("skills-only@workbench".to_string(), dir)];

        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
    }

    // Cannot-judge must not read as all-broken: with no settings file at all,
    // an empty map would have warned about every installed plugin at once.
    #[test]
    fn missing_settings_reports_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("no-such-config");
        let dir = plugin_with_hooks(tmp.path(), "some-install");
        let installs = vec![("some@workbench".to_string(), dir)];

        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
        assert!(enabled_plugin_map(&config).is_none());
    }

    // Cannot-judge covers EMPTY too, not just missing. A literally empty
    // enabledPlugins is indistinguishable from a config not yet written, and
    // reading it as "nothing is enabled" warns about every hook-shipping plugin
    // at once — the exact failure the None guard exists to prevent.
    #[test]
    fn empty_enabled_plugins_object_is_cannot_judge() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{}}"#);
        let dir = plugin_with_hooks(tmp.path(), "some-install");
        let installs = vec![("some@workbench".to_string(), dir)];

        assert!(enabled_plugin_map(&config).is_none());
        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
    }

    // Presence, not value: a malformed entry is still a decision the operator
    // made. Dropping it would make the key read as ABSENT and fire the very
    // warning the absent-vs-false rule exists to avoid.
    #[test]
    fn non_bool_entry_still_counts_as_present() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(
            &config,
            r#"{"enabledPlugins":{"p@m":"true","other@m":true}}"#,
        );
        let dir = plugin_with_hooks(tmp.path(), "p-install");
        let installs = vec![("p@m".to_string(), dir)];

        assert!(
            unenabled_plugin_findings(&installs, &config).is_empty(),
            "a string-valued entry is present, not absent"
        );
    }

    #[test]
    fn unparseable_settings_reports_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, "{ not json");
        let dir = plugin_with_hooks(tmp.path(), "some-install");
        let installs = vec![("some@workbench".to_string(), dir)];

        assert!(unenabled_plugin_findings(&installs, &config).is_empty());
    }

    // settings.local.json wins, matching Claude Code's own precedence — so a
    // plugin enabled only locally must not be reported as inert.
    #[test]
    fn local_settings_override_base() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        write_settings(&config, r#"{"enabledPlugins":{"p@m":false}}"#);
        fs::write(
            config.join("settings.local.json"),
            r#"{"enabledPlugins":{"p@m":true}}"#,
        )
        .unwrap();

        let map = enabled_plugin_map(&config).expect("both files parse");
        assert_eq!(map.get("p@m"), Some(&true), "local wins over base");
    }

    // A local file alone is enough to judge — the base file need not exist.
    #[test]
    fn local_settings_alone_is_judgeable() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        fs::create_dir_all(&config).unwrap();
        fs::write(
            config.join("settings.local.json"),
            r#"{"enabledPlugins":{"p@m":true}}"#,
        )
        .unwrap();

        assert_eq!(
            enabled_plugin_map(&config).map(|m| m.len()),
            Some(1),
            "local-only settings still yield a map"
        );
    }

    // ── failopen_findings tests ─────────────────────────────────────────────

    const WEEK: Duration = Duration::from_secs(7 * 86_400);

    /// A deterministic `now` two days after the fixed `2026-07-20` rows the
    /// recency tests use — keeps those rows inside the 7-day window without
    /// leaning on the wall clock, which would age the fixed date out and turn
    /// the assertions into a time bomb. `2026-07-22T00:00:00Z` in Unix seconds.
    fn fixed_now_after_the_rows() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_784_678_400)
    }

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
    fn failopen_findings_distinguish_a_burst_from_a_drip_at_the_same_count() {
        // #404: same total, opposite shapes, and the remediation must send the
        // operator somewhere DIFFERENT for each. A one-day spike is an episode
        // to correlate; a spread is the live feed the old text asserted for
        // both.
        let burst_dir = tempfile::tempdir().unwrap();
        let burst: String = (0..6)
            .map(|i| format!(
                "{{\"reason\":\"parse\",\"binaryVersion\":\"0.66.0\",\"ts\":\"2026-07-20T{i:02}:00:00Z\"}}\n"
            ))
            .collect();
        fs::write(burst_dir.path().join("failopen.jsonl"), burst).unwrap();

        let drip_dir = tempfile::tempdir().unwrap();
        let drip: String = (0..6)
            .map(|i| format!(
                "{{\"reason\":\"parse\",\"binaryVersion\":\"0.66.0\",\"ts\":\"2026-07-{:02}T00:00:00Z\"}}\n",
                15 + i
            ))
            .collect();
        fs::write(drip_dir.path().join("failopen.jsonl"), drip).unwrap();

        let b = failopen_findings(burst_dir.path(), WEEK, fixed_now_after_the_rows(), "0.66.0");
        let d = failopen_findings(drip_dir.path(), WEEK, fixed_now_after_the_rows(), "0.66.0");
        assert_eq!(b.len(), 1);
        assert_eq!(d.len(), 1);

        // Identical counts — the snippet proves the totals really do match, so
        // the difference below can only come from the distribution.
        assert_eq!(b[0].snippet, d[0].snippet, "same total");

        assert!(
            b[0].diagnosis.contains("all on ONE day"),
            "{}",
            b[0].diagnosis
        );
        assert!(
            b[0].remediation.contains("episode, not a")
                && !b[0].remediation.contains("sustained feed"),
            "{}",
            b[0].remediation
        );

        assert!(
            d[0].diagnosis.contains("spread over 6 of 7 days"),
            "{}",
            d[0].diagnosis
        );
        assert!(
            d[0].remediation.contains("sustained feed problem")
                && !d[0].remediation.contains("episode, not a"),
            "{}",
            d[0].remediation
        );
    }

    #[test]
    fn cloud_sync_marker_matches_components_not_substrings() {
        // Component-wise is load-bearing. A substring test flags a project
        // NAMED after a provider, and a check that cries wolf on ~/src is one
        // the operator stops reading.
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/OneDrive/repo")),
            Some("OneDrive")
        );
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/Library/Mobile Documents/repo")),
            Some("Mobile Documents")
        );
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/Library/CloudStorage/Box-x/repo")),
            Some("CloudStorage")
        );
        // Case-insensitive: providers vary the casing across platforms.
        assert_eq!(
            cloud_sync_marker(Path::new("/home/x/dropbox/repo")),
            Some("Dropbox")
        );
        // A project merely NAMED after a provider is not a synced tree.
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/src/dropbox-client")),
            None
        );
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/src/my-onedrive-tool")),
            None
        );
        assert_eq!(cloud_sync_marker(Path::new("/Users/x/Projects/repo")), None);
    }

    #[test]
    fn cloud_sync_marker_catches_the_m365_organization_suffix() {
        // A Microsoft 365 business or school tenant syncs to
        // `OneDrive - <Organization>`, which is the DOMINANT real-world shape
        // of the deployment this check exists to catch. Exact-component
        // matching alone never fired for it.
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/OneDrive - Acme Corp/repo")),
            Some("OneDrive")
        );
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/OneDrive - Contoso Ltd/dev/repo")),
            Some("OneDrive")
        );
        // The separator carries surrounding SPACES on purpose: a bare `-`
        // boundary would re-admit the very false positive component matching
        // was chosen to avoid.
        assert_eq!(
            cloud_sync_marker(Path::new("/Users/x/OneDrive-backups")),
            None
        );
    }

    #[test]
    fn cloud_sync_findings_name_the_provider_and_the_directory() {
        let findings = cloud_sync_findings(&[
            ("working directory", PathBuf::from("/Users/x/OneDrive/repo")),
            ("CLAUDE_CONFIG_DIR", PathBuf::from("/Users/x/.claude")),
        ]);
        assert_eq!(findings.len(), 1, "only the synced path is flagged");
        assert_eq!(findings[0].severity, Severity::Warning, "slow, not broken");
        assert!(
            findings[0].diagnosis.contains("OneDrive"),
            "{}",
            findings[0].diagnosis
        );
        assert!(
            findings[0].diagnosis.contains("working directory"),
            "{}",
            findings[0].diagnosis
        );
    }

    #[test]
    fn referenced_clis_takes_command_position_only() {
        // An argument that happens to name a tool is not something the hook
        // shells to; flagging it is the noise that gets a real missing
        // dependency skipped.
        let clis = referenced_clis("markdownlint-cli2 --config x.jsonc");
        assert!(clis.contains("markdownlint-cli2"));
        assert!(!clis.contains("--config"));

        let clis = referenced_clis("prettier --formatter markdownlint");
        assert!(clis.contains("prettier"));
        assert!(!clis.contains("markdownlint"), "argument, not command word");

        // Paths and unexpanded variables resolve without PATH.
        let clis = referenced_clis("\"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh\" guardrails x");
        assert!(clis.is_empty(), "{clis:?}");
        let clis = referenced_clis("/usr/bin/env python3");
        assert!(!clis.contains("/usr/bin/env"), "{clis:?}");

        // Builtins are never a PATH lookup.
        let clis = referenced_clis("cd /tmp && echo hi && exit 0");
        assert!(clis.is_empty(), "{clis:?}");

        // Both sides of a chain are command words.
        let clis = referenced_clis("jq -r .x < f.json | shellcheck -");
        assert!(clis.contains("jq"), "{clis:?}");
    }

    #[test]
    fn referenced_clis_walks_past_transparent_prefixes() {
        // Under a prefix, the thing that must EXIST is the argument. Naming
        // the prefix instead is a false negative in exactly the case this
        // check exists for — a hook silently going inert.
        for command in [
            "sudo mytool --run",
            "env FOO=x mytool --run",
            "nice -n 10 mytool --run",
            "nohup mytool --run",
            "command mytool --run",
            "env FOO=x sudo nice -n 5 mytool",
        ] {
            let clis = referenced_clis(command);
            assert!(clis.contains("mytool"), "{command}: {clis:?}");
            assert!(!clis.contains("sudo"), "{command}: {clis:?}");
            assert!(!clis.contains("env"), "{command}: {clis:?}");
            assert!(!clis.contains("nice"), "{command}: {clis:?}");
        }
        // `time` is a prefix, not a CLI: stock macOS ships no /usr/bin/time,
        // so treating it as one emits a bogus finding on every such machine.
        let clis = referenced_clis("time mytool");
        assert!(clis.contains("mytool"), "{clis:?}");
        assert!(!clis.contains("time"), "{clis:?}");
    }

    #[test]
    fn referenced_clis_strips_group_wrappers() {
        // `(mytool --version)` is ONE segment whose first token is the garbage
        // string `(mytool` — never on PATH, so it would report a permanently
        // missing CLI that does not exist while never checking the real one.
        for command in ["(mytool --version)", "{ mytool --version; }", "( mytool )"] {
            let clis = referenced_clis(command);
            assert!(clis.contains("mytool"), "{command}: {clis:?}");
            assert!(
                !clis
                    .iter()
                    .any(|c| c.starts_with('(') || c.starts_with('{')),
                "{command}: {clis:?}"
            );
        }
    }

    #[test]
    fn on_path_requires_an_executable_bit_not_merely_a_file() {
        // A `chmod 644` placeholder earlier on PATH would otherwise read as
        // present while the shell fails to exec it — reporting health where
        // there is none. Unix-only: Windows has no executable bit, and its
        // resolution goes through PATHEXT instead.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let inert = dir.path().join("cadence-inert-probe");
            fs::write(&inert, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&inert, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                !is_executable_at(&inert),
                "non-executable file is not a CLI"
            );

            fs::set_permissions(&inert, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(is_executable_at(&inert), "executable file is a CLI");
        }
        // Present on both platforms: an absent path is never executable.
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_executable_at(&dir.path().join("no-such-file")));
    }

    #[cfg(windows)]
    #[test]
    fn on_path_resolves_pathext_shims_not_just_exe() {
        // Node's global installs ship `.cmd` shims — `prettier.cmd`,
        // `markdownlint-cli2.cmd` — so resolving only `.exe` would report a
        // large share of the CLIs hooks actually shell to as missing. This
        // runs ONLY on the Windows leg, which is the point: the branch it
        // covers cannot be exercised from the author's machine, and shipping
        // an unexercised platform branch is how a fail-open gets missed.
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("cadence-probe-tool.cmd");
        fs::write(&shim, "@echo off\n").unwrap();
        assert!(
            is_executable_at(&dir.path().join("cadence-probe-tool")),
            "a .cmd shim must resolve for its extensionless name"
        );
        assert!(
            !is_executable_at(&dir.path().join("cadence-probe-absent")),
            "an absent name must not resolve through PATHEXT"
        );
    }

    #[test]
    fn missing_cli_findings_flag_only_what_path_cannot_resolve() {
        // `sh` is on PATH everywhere the suite runs; the invented name is not.
        // Asserting both directions in one test keeps this from passing
        // vacuously if `on_path` ever returned a constant.
        let found = missing_cli_findings(
            "sh -c true && cadence-doctor-no-such-cli-xyz --run",
            "test-plugin",
            Path::new("/x/hooks.json"),
            Some(7),
        );
        let names: Vec<&str> = found.iter().map(|f| f.snippet.as_str()).collect();
        assert!(
            names
                .iter()
                .any(|s| s.contains("cadence-doctor-no-such-cli-xyz")),
            "{names:?}"
        );
        assert!(!names.iter().any(|s| s.contains("sh")), "{names:?}");
        assert_eq!(found[0].plugin, "test-plugin");
        assert_eq!(found[0].line, Some(7));
        assert_eq!(
            found[0].severity,
            Severity::Warning,
            "heuristic extraction must never be able to fail the run"
        );
    }

    #[test]
    fn shape_clause_is_silent_when_it_would_say_nothing() {
        // `1 of 1 day` carries no information, and neither does a middling
        // spread — better silent than confidently wrong about the shape.
        assert_eq!(shape_clause(1, 1), "");
        assert_eq!(shape_clause(0, 7), "");
        assert_eq!(shape_remediation(3), "");
    }

    #[test]
    fn failopen_findings_parse_diagnosis_carries_recency_and_current_version() {
        // A burst on an OLD binary version — the fixed-and-aging-out case. The
        // diagnosis must name the last failure, its version, and that none are
        // on the current binary, so a fixed burst is not read as a live one.
        let tmp = tempfile::tempdir().unwrap();
        let rows: String = (0..3)
            .map(|_| {
                r#"{"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#
                    .to_string()
            })
            .map(|r| r + "\n")
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, fixed_now_after_the_rows(), "0.66.0");
        assert_eq!(findings.len(), 1);
        let diagnosis = &findings[0].diagnosis;
        assert!(
            diagnosis.contains("last: 2026-07-20T20:51:00Z on 0.61.0"),
            "{diagnosis}"
        );
        assert!(diagnosis.contains("none on current 0.66.0"), "{diagnosis}");
        assert!(
            findings[0].remediation.contains("check the CHANGELOG"),
            "{}",
            findings[0].remediation
        );
    }

    #[test]
    fn failopen_findings_parse_diagnosis_counts_current_version_failures() {
        // Same reason, but the failures are on the CURRENT binary — a live feed
        // problem. The current-version clause must report the count, not "none".
        let tmp = tempfile::tempdir().unwrap();
        let rows: String = (0..3)
            .map(|_| {
                r#"{"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"0.66.0","ts":"2026-07-20T20:51:00Z"}"#
                    .to_string()
            })
            .map(|r| r + "\n")
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, fixed_now_after_the_rows(), "0.66.0");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].diagnosis.contains("3 on current 0.66.0"),
            "{}",
            findings[0].diagnosis
        );
    }

    #[test]
    fn failopen_findings_panic_names_the_last_error_and_a_runnable_command() {
        // The #398 complaint in one test: a panic finding that says only "N
        // panic(s)" and "inspect failopen.jsonl" gives an operator nowhere to
        // go. The error text and a copy-pasteable command are the fix.
        let tmp = tempfile::tempdir().unwrap();
        let row = r#"{"schemaVersion":2,"reason":"panic","namespace":"cadence","subcommand":"terminology","binaryVersion":"1.0.0","error":"index out of bounds (at crates/cadence/src/terminology.rs:88)","ts":"TS"}"#
            .replace("TS", &cadence_hooks_core::time::utc_timestamp());
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].diagnosis.contains(
                "last error: index out of bounds (at crates/cadence/src/terminology.rs:88)"
            ),
            "{}",
            findings[0].diagnosis
        );
        assert!(
            findings[0]
                .remediation
                .contains(r#"grep '"reason":"panic"'"#),
            "{}",
            findings[0].remediation
        );
        assert!(
            !findings[0].remediation.contains("inspect failopen.jsonl"),
            "the unactionable phrasing is gone: {}",
            findings[0].remediation
        );
    }

    #[test]
    fn failopen_findings_parse_diagnosis_carries_the_last_error() {
        let tmp = tempfile::tempdir().unwrap();
        let rows: String = (0..3)
            .map(|_| {
                r#"{"schemaVersion":2,"reason":"parse","namespace":"cadence","subcommand":"heartbeat","binaryVersion":"0.66.0","error":"Failed to parse hook JSON: expected value at line 1 column 1","ts":"2026-07-20T20:51:00Z"}"#
                    .to_string()
            })
            .map(|r| r + "\n")
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, fixed_now_after_the_rows(), "0.66.0");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].diagnosis.contains(
                "last error: Failed to parse hook JSON: expected value at line 1 column 1"
            ),
            "{}",
            findings[0].diagnosis
        );
    }

    #[test]
    fn failopen_findings_render_cleanly_for_v1_rows_without_an_error() {
        // BACKWARD COMPAT at the render layer: an operator's existing ledger is
        // entirely v1. The clause is omitted, not filled with a literal "null"
        // or an empty "last error: ".
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let panic_row = format!(
            r#"{{"schemaVersion":1,"reason":"panic","namespace":"cadence","subcommand":"terminology","binaryVersion":"1.0.0","ts":"{ts}"}}"#
        );
        let parse_rows: String = (0..3)
            .map(|_| {
                format!(
                    r#"{{"schemaVersion":1,"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"{ts}"}}"#
                ) + "\n"
            })
            .collect();
        fs::write(
            tmp.path().join("failopen.jsonl"),
            format!("{panic_row}\n{parse_rows}"),
        )
        .unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 2);
        for finding in &findings {
            assert!(
                !finding.diagnosis.contains("last error"),
                "no empty error clause: {}",
                finding.diagnosis
            );
            assert!(
                !finding.diagnosis.contains("null"),
                "no literal null leaks into the diagnosis: {}",
                finding.diagnosis
            );
        }
    }

    /// A metrics dir exercising every character that is live inside double
    /// quotes — command substitution both ways, a quote-closing `"`, a
    /// backslash — plus a `'` to drive the escape idiom itself. The `$(...)`
    /// and backtick bodies are inert `echo`s: if quoting ever regresses, the
    /// shell round-trip below returns "INJECTED"/"ALSO" instead of the literal
    /// and the test fails loudly rather than doing anything.
    const HOSTILE_DIR: &str = r#"/tmp/m$(echo INJECTED)`echo ALSO`"x\y'z w"#;

    #[test]
    fn failopen_inspect_cmd_neutralizes_shell_metacharacters_in_the_path() {
        // Structural half: the path is single-quoted, and the only `'` inside
        // it is the escape idiom.
        let cmd = failopen_inspect_cmd(Path::new(HOSTILE_DIR), "panic");
        assert!(cmd.contains(r#"grep '"reason":"panic"'"#), "{cmd}");
        assert!(
            cmd.contains(r#"'/tmp/m$(echo INJECTED)`echo ALSO`"x\y'\''z w/failopen.jsonl'"#),
            "{cmd}"
        );
    }

    #[test]
    fn shell_single_quote_survives_a_real_shell_round_trip() {
        // Behavioral half, and the one that actually proves inertness: hand the
        // quoted string to `sh` and confirm it parses back to the original
        // bytes. Equality can only hold if no substitution, no quote break, and
        // no backslash escape occurred — a structural assertion alone would
        // still pass against a subtly wrong escape.
        let quoted = shell_single_quote(HOSTILE_DIR);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s' {quoted}"))
            .output()
            .expect("spawn sh");

        assert!(
            out.status.success(),
            "sh rejected the quoted string: {out:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            HOSTILE_DIR,
            "the shell must reproduce the path verbatim — anything else means a \
             metacharacter was live"
        );
        // Explicit about the discriminator: the marker word appears in the
        // literal too, so its presence proves nothing. What proves inertness is
        // that the substitution *syntax* came back as text — had `sh` evaluated
        // it, `$(echo INJECTED)` would have collapsed to `INJECTED`.
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("$(echo INJECTED)"),
            "the substitution syntax must survive uninterpreted"
        );
    }

    #[test]
    fn shell_single_quote_handles_spaces_and_plain_paths() {
        assert_eq!(
            shell_single_quote("/Users/a b/.claude/metrics"),
            "'/Users/a b/.claude/metrics'"
        );
        assert_eq!(shell_single_quote(""), "''");
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

    // #183: the count alone leaves the operator auditing every installed
    // plugin by hand. Name the invocations so it becomes one grep — and dedup
    // them, because a live skew fires the same pair dozens of times.
    #[test]
    fn failopen_findings_version_mismatch_names_the_subcommands() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let rows: String = (0..20)
            .map(|i| {
                let sub = if i % 2 == 0 {
                    "persona-gate"
                } else {
                    "persona-nudge"
                };
                format!(
                    "{{\"reason\":\"version_mismatch\",\"namespace\":\"lab\",\
                     \"subcommand\":\"{sub}\",\"binaryVersion\":\"1.0.0\",\"ts\":\"{ts}\"}}\n"
                )
            })
            .collect();
        fs::write(tmp.path().join("failopen.jsonl"), rows).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        let d = &findings[0].diagnosis;
        assert!(d.contains("lab persona-gate"), "names the invocation: {d}");
        assert!(d.contains("lab persona-nudge"), "names both: {d}");
        // The grep must cover EVERY named pair. A one-pair command leaves the
        // operator fixing one inert hooks.json while the rest stay inert —
        // the multi-pair case is the whole point of #183.
        let r = &findings[0].remediation;
        assert!(r.contains("grep -rlF"), "runnable fixed-string grep: {r}");
        assert!(r.contains("-e 'lab persona-gate'"), "covers the first: {r}");
        assert!(
            r.contains("-e 'lab persona-nudge'"),
            "covers the second: {r}"
        );
    }

    // A row set with no namespace/subcommand (a bare invocation) must degrade
    // to the old generic guidance rather than rendering an empty clause.
    #[test]
    fn failopen_findings_version_mismatch_without_pairs_stays_generic() {
        let tmp = tempfile::tempdir().unwrap();
        let ts = cadence_hooks_core::time::utc_timestamp();
        let row = format!(
            r#"{{"reason":"version_mismatch","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"{ts}"}}"#
        );
        fs::write(tmp.path().join("failopen.jsonl"), format!("{row}\n")).unwrap();

        let findings = failopen_findings(tmp.path(), WEEK, SystemTime::now(), "1.0.0");
        assert_eq!(findings.len(), 1);
        assert!(
            !findings[0].diagnosis.contains("does not recognize"),
            "no dangling clause: {}",
            findings[0].diagnosis
        );
        assert!(findings[0].remediation.contains("cadence-hooks list"));
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

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
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

    /// The remediation must name the command that actually prunes.
    ///
    /// It previously named a skill with no plugin-cache handling of any kind
    /// (cadence-hooks#803), and nothing in the suite could observe that — a
    /// remediation pointing at the wrong tool is invisible in both directions,
    /// so it could rot again with no red anywhere. This is the assertion that
    /// makes the recurrence detectable.
    #[test]
    fn orphan_finding_remediation_names_the_prune_command() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_dir = tmp.path().join("mp/plugin");
        for sha in ["sha1", "sha2"] {
            let dir = plugin_dir.join(sha);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("marker"), "x").unwrap();
        }
        let pinned = vec![("plugin@mp".to_string(), plugin_dir.join("sha2"))];

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
        let orphan_finding = findings
            .iter()
            .find(|f| f.diagnosis.contains("orphaned"))
            .expect("should report orphans");

        assert!(
            orphan_finding
                .remediation
                .contains("cadence-hooks doctor --prune"),
            "remediation must name the command that does the work, got: {}",
            orphan_finding.remediation
        );
        assert!(
            orphan_finding.remediation.contains("--apply"),
            "remediation must distinguish the dry run from the removal, got: {}",
            orphan_finding.remediation
        );
    }

    #[test]
    fn orphan_findings_missing_pinned_dir_is_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("mp/plugin/sha-gone");
        let pinned = vec![("plugin@mp".to_string(), missing)];

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
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

        assert!(
            orphan_findings(
                &pinned,
                false,
                tmp.path(),
                &tmp.path().join("known_marketplaces.json"),
            )
            .is_empty()
        );
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

        let findings = orphan_findings(
            &pinned,
            true,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
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
        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );

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
        // flagged for pruning — only the genuine orphan (sha-C) should
        // generate a finding, and exactly one (not one per label).
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

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
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

    // ── marketplace_status / manifest_scan_findings / orphan exemption (#474) ─

    /// Write `known_marketplaces.json` with the given body — one general
    /// JSON-body writer rather than one helper per source shape, mirroring
    /// `tests/doctor.rs`'s `write_known_marketplaces`.
    fn write_known_marketplaces(root: &Path, body: &serde_json::Value) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("known_marketplaces.json"),
            serde_json::to_string(body).unwrap(),
        )
        .unwrap();
    }

    /// Write a github-sourced marketplace's own `marketplace.json` at
    /// `install_location`, listing `plugin_names`.
    fn write_marketplace_plugin_list(install_location: &Path, plugin_names: &[&str]) {
        let mp_dir = install_location.join(".claude-plugin");
        fs::create_dir_all(&mp_dir).unwrap();
        let plugins: Vec<_> = plugin_names
            .iter()
            .map(|name| serde_json::json!({ "name": name, "source": format!("./plugins/{name}") }))
            .collect();
        fs::write(
            mp_dir.join("marketplace.json"),
            serde_json::to_string(&serde_json::json!({ "plugins": plugins })).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn marketplace_status_directory_sourced() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_path = tmp.path().join("dev/homelab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "homelab": {
                    "source": { "source": "directory", "path": plugin_path.to_str().unwrap() },
                    "installLocation": plugin_path.to_str().unwrap(),
                }
            }),
        );

        assert_eq!(
            marketplace_status(
                "homelab@homelab",
                &tmp.path().join("known_marketplaces.json")
            ),
            MarketplaceStatus::DirectorySourced
        );
    }

    #[test]
    fn marketplace_status_removed_upstream() {
        let tmp = tempfile::tempdir().unwrap();
        let install_location = tmp.path().join("marketplaces/cadence-lab");
        // marketplace.json lists two plugins; "persona" is deliberately absent
        // — mirrors the exact #474 case 1 scenario (a plugin dropped from the
        // marketplace two days before the stale hooks.json warning fired).
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "cadence-lab": {
                    "source": { "source": "github", "repo": "owner/cadence-lab" },
                    "installLocation": install_location.to_str().unwrap(),
                }
            }),
        );
        write_marketplace_plugin_list(&install_location, &["vibes", "macos"]);

        assert_eq!(
            marketplace_status(
                "persona@cadence-lab",
                &tmp.path().join("known_marketplaces.json")
            ),
            MarketplaceStatus::RemovedUpstream
        );
    }

    #[test]
    fn marketplace_status_present_is_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let install_location = tmp.path().join("marketplaces/cadence-lab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "cadence-lab": {
                    "source": { "source": "github", "repo": "owner/cadence-lab" },
                    "installLocation": install_location.to_str().unwrap(),
                }
            }),
        );
        write_marketplace_plugin_list(&install_location, &["vibes", "macos"]);

        // Positive control: a plugin that IS still listed must not be
        // misreported as removed — proves this can discriminate, not just
        // always report RemovedUpstream.
        assert_eq!(
            marketplace_status(
                "vibes@cadence-lab",
                &tmp.path().join("known_marketplaces.json")
            ),
            MarketplaceStatus::Resolved
        );
    }

    #[test]
    fn marketplace_status_fails_open_on_missing_known_marketplaces() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            marketplace_status("p@mp", &tmp.path().join("known_marketplaces.json")),
            MarketplaceStatus::Resolved
        );
    }

    #[test]
    fn marketplace_status_fails_open_on_unrecognized_marketplace_key() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_path = tmp.path().join("dev/x");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "homelab": {
                    "source": { "source": "directory", "path": plugin_path.to_str().unwrap() },
                    "installLocation": plugin_path.to_str().unwrap(),
                }
            }),
        );

        // "other-mp" isn't in known_marketplaces.json at all.
        assert_eq!(
            marketplace_status("p@other-mp", &tmp.path().join("known_marketplaces.json")),
            MarketplaceStatus::Resolved
        );
    }

    #[test]
    fn manifest_scan_findings_reports_removed_upstream_not_skew() {
        let tmp = tempfile::tempdir().unwrap();
        let install_location = tmp.path().join("marketplaces/cadence-lab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "cadence-lab": {
                    "source": { "source": "github", "repo": "owner/cadence-lab" },
                    "installLocation": install_location.to_str().unwrap(),
                }
            }),
        );
        write_marketplace_plugin_list(&install_location, &["vibes", "macos"]);

        // The removed plugin's stale cached hooks.json references a
        // subcommand this binary doesn't know — the exact input that used
        // to misdiagnose as binary skew.
        let plugin_dir = tmp.path().join("cache/cadence-lab/persona/8f4df2542e4a");
        fs::create_dir_all(plugin_dir.join("hooks")).unwrap();
        // The wrapper form (not a bare `cadence-hooks` command word) so this
        // fixture's expected finding count doesn't depend on whether the
        // host running the test happens to have `cadence-hooks` on PATH —
        // Check 0 (missing-CLI) skips any command word containing `$`.
        fs::write(
            plugin_dir.join("hooks/hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" lab persona-nudge"}]}]}}"#,
        )
        .unwrap();

        let installs = vec![("persona@cadence-lab".to_string(), plugin_dir)];
        let findings = manifest_scan_findings(
            &installs,
            InstallChannel::Unknown,
            &tmp.path().join("known_marketplaces.json"),
        );

        assert_eq!(
            findings.len(),
            1,
            "findings: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
        assert!(
            findings[0].diagnosis.contains("removed upstream"),
            "diagnosis: {}",
            findings[0].diagnosis
        );
        assert!(
            !findings[0].diagnosis.contains("not present in this binary"),
            "must not misdiagnose a removed plugin as binary skew: {}",
            findings[0].diagnosis
        );
    }

    #[test]
    fn manifest_scan_findings_still_reports_real_skew() {
        // Positive control for the discrimination itself: a plugin that IS
        // still in its marketplace, with a genuinely unknown subcommand,
        // must still be flagged as skew. A change that stopped ALL skew
        // reporting (rather than just the removed-upstream case) would pass
        // the test above and be silently useless here.
        let tmp = tempfile::tempdir().unwrap();
        let install_location = tmp.path().join("marketplaces/cadence-lab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "cadence-lab": {
                    "source": { "source": "github", "repo": "owner/cadence-lab" },
                    "installLocation": install_location.to_str().unwrap(),
                }
            }),
        );
        write_marketplace_plugin_list(&install_location, &["vibes"]);

        let plugin_dir = tmp.path().join("cache/cadence-lab/vibes/abc123");
        fs::create_dir_all(plugin_dir.join("hooks")).unwrap();
        // Wrapper form — see the sibling test's comment on why not a bare
        // `cadence-hooks` command word.
        fs::write(
            plugin_dir.join("hooks/hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"\"${CLAUDE_PLUGIN_ROOT}/hooks/run-cadence-hooks.sh\" lab hook-from-the-future"}]}]}}"#,
        )
        .unwrap();

        let installs = vec![("vibes@cadence-lab".to_string(), plugin_dir)];
        let findings = manifest_scan_findings(
            &installs,
            InstallChannel::Unknown,
            &tmp.path().join("known_marketplaces.json"),
        );

        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].diagnosis.contains("not present in this binary"),
            "a still-listed plugin's genuine skew must still be reported: {}",
            findings[0].diagnosis
        );
    }

    #[test]
    fn manifest_scan_findings_removed_upstream_still_reports_other_defects() {
        // Coverage-regression control: a removed-upstream plugin's stale
        // hooks.json can carry independent defects (a real shell-expansion
        // bug, an unresolvable CLI dependency) that have nothing to do with
        // whether the plugin is still listed upstream. Suppressing the skew
        // warning must not suppress those too — a plugin's own publisher
        // must not be able to silence doctor's still-firing findings for
        // their own plugin simply by delisting it from their marketplace.
        let tmp = tempfile::tempdir().unwrap();
        let install_location = tmp.path().join("marketplaces/cadence-lab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "cadence-lab": {
                    "source": { "source": "github", "repo": "owner/cadence-lab" },
                    "installLocation": install_location.to_str().unwrap(),
                }
            }),
        );
        write_marketplace_plugin_list(&install_location, &["vibes"]);

        // "persona" is absent from the marketplace's plugin list (removed
        // upstream), and its stale hooks.json carries a real shell-expansion
        // bug alongside the now-irrelevant skew reference.
        let plugin_dir = tmp.path().join("cache/cadence-lab/persona/8f4df2542e4a");
        fs::create_dir_all(plugin_dir.join("hooks")).unwrap();
        fs::write(
            plugin_dir.join("hooks/hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"'${CLAUDE_PLUGIN_ROOT}/hooks/run.sh' arg"}]}]}}"#,
        )
        .unwrap();

        let installs = vec![("persona@cadence-lab".to_string(), plugin_dir)];
        let findings = manifest_scan_findings(
            &installs,
            InstallChannel::Unknown,
            &tmp.path().join("known_marketplaces.json"),
        );

        assert_eq!(
            findings.len(),
            2,
            "expected the removed-upstream finding PLUS the still-independent \
             shell-expansion Error, found: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
        assert!(
            findings
                .iter()
                .any(|f| f.diagnosis.contains("removed upstream")),
            "must still report the removed-upstream finding: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
        assert!(
            findings.iter().any(|f| f.severity == Severity::Error
                && f.diagnosis.contains("won't expand in /bin/sh")),
            "the shell-expansion Error must survive the removed-upstream exemption \
             — it is not a skew problem: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.diagnosis.contains("not present in this binary")),
            "the skew warning is the ONLY thing the removed-upstream exemption \
             should suppress: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
    }

    #[test]
    fn orphan_findings_exempts_directory_sourced_missing_cache_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin_source = tmp.path().join("dev/homelab");
        write_known_marketplaces(
            tmp.path(),
            &serde_json::json!({
                "homelab": {
                    "source": { "source": "directory", "path": plugin_source.to_str().unwrap() },
                    "installLocation": plugin_source.to_str().unwrap(),
                }
            }),
        );

        // The recorded installPath under plugins/cache/ that Claude Code
        // still writes for a directory-sourced plugin, but never
        // populates — the exact #474 case 2 shape.
        let missing_cache_dir = tmp.path().join("cache/homelab/homelab/1.0.0");
        let pinned = vec![("homelab@homelab".to_string(), missing_cache_dir)];

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
        assert!(
            findings.is_empty(),
            "a directory-sourced plugin's never-populated cache path must not \
             report as broken: {:?}",
            findings.iter().map(|f| &f.diagnosis).collect::<Vec<_>>()
        );
    }

    #[test]
    fn orphan_findings_still_flags_missing_cache_dir_for_non_directory_source() {
        // Positive control: the exemption above must not blanket-suppress
        // the missing-dir check. Same missing-dir shape, but this plugin's
        // marketplace is NOT directory-sourced (known_marketplaces.json
        // doesn't even mention it), so the check must still fire — a
        // genuinely broken cache still reports as broken.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("cache/workbench/plugin/sha-gone");
        let pinned = vec![("plugin@workbench".to_string(), missing)];

        let findings = orphan_findings(
            &pinned,
            false,
            tmp.path(),
            &tmp.path().join("known_marketplaces.json"),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].diagnosis.contains("missing or empty"));
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

    // ── quiet_warning_envelope (#306, #632) ─────────────────────────────────

    #[test]
    fn quiet_envelope_carries_tags_must_sentence_and_count_line() {
        let s = quiet_warning_envelope("0.60.0", 2, false, InstallChannel::Unknown);
        assert!(
            s.starts_with("<cadence-system-message>\n"),
            "must open with the envelope tag: {s}"
        );
        assert!(
            s.trim_end().ends_with("</cadence-system-message>"),
            "must close with the envelope tag: {s}"
        );
        assert!(
            s.contains("You MUST run 'cadence-hooks doctor'"),
            "must carry the MUST directive: {s}"
        );
        assert!(
            s.contains("cadence-hooks 0.60.0: 2 plugin warning(s)."),
            "must carry the version/count line: {s}"
        );
    }

    #[test]
    fn quiet_envelope_no_skew_omits_upgrade_hint() {
        let s = quiet_warning_envelope("0.60.0", 1, false, InstallChannel::Homebrew);
        assert!(!s.contains("brew upgrade"), "no upgrade hint expected: {s}");
        assert!(!s.contains("Version skew"), "no skew clause expected: {s}");
    }

    #[test]
    fn quiet_envelope_skew_includes_upgrade_hint() {
        let s = quiet_warning_envelope("0.60.0", 1, true, InstallChannel::Homebrew);
        assert!(s.contains("Version skew"), "skew clause expected: {s}");
        assert!(
            s.contains("brew upgrade cadence-hooks"),
            "Homebrew skew hint expected: {s}"
        );
    }

    // ── warning_set_token (#632) ─────────────────────────────────────────────

    #[test]
    fn warning_set_token_is_order_insensitive() {
        let a = warning_set_token("0.60.0", &["diag-a", "diag-b"]);
        let b = warning_set_token("0.60.0", &["diag-b", "diag-a"]);
        assert_eq!(
            a, b,
            "sort order of the input slice must not change the token"
        );
    }

    #[test]
    fn warning_set_token_changes_when_a_diagnosis_changes() {
        let a = warning_set_token("0.60.0", &["diag-a", "diag-b"]);
        let b = warning_set_token("0.60.0", &["diag-a", "diag-c"]);
        assert_ne!(a, b, "a changed diagnosis must mint a different token");
    }

    #[test]
    fn warning_set_token_changes_when_version_changes() {
        let a = warning_set_token("0.60.0", &["diag-a"]);
        let b = warning_set_token("0.61.0", &["diag-a"]);
        assert_ne!(a, b, "a version bump must mint a different token");
    }

    // ── doctor-warnings daily gate (#632) ────────────────────────────────────

    #[test]
    fn doctor_warnings_gate_suppresses_second_call_with_same_token() {
        // Mirrors the marker-family's own `with_marker_dir` pattern
        // (crates/core/src/markers.rs) so the stamp lands in a fresh private
        // tempdir rather than the real per-user marker directory.
        let marker_tmp = tempfile::tempdir().unwrap();
        cadence_hooks_core::test_builders::with_marker_dir(marker_tmp.path(), || {
            let token = warning_set_token("0.60.0", &["diag-a"]);
            assert!(
                cadence_hooks_core::markers::claim_today("doctor-warnings", &token),
                "first sighting today must fire"
            );
            assert!(
                !cadence_hooks_core::markers::claim_today("doctor-warnings", &token),
                "the same token must be silent for the rest of the day"
            );
        });
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
    fn prune_listing_sanitizes_hostile_cache_dir_path() {
        let path = Path::new("/cache/\u{1b}[31mred\u{1b}[0m/\u{202e}evil\u{e0001}");
        let rendered = render_orphan_dir_line(path, 1024 * 1024, true);

        assert!(rendered.contains("/cache/"));
        assert!(rendered.contains("(~1.0 MiB)"));
        assert!(rendered.contains("[marked .orphaned_at]"));
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\u{e0001}'));
    }

    #[test]
    fn prune_listing_preserves_ordinary_path_text() {
        let rendered =
            render_orphan_dir_line(Path::new("/cache/marketplace/plugin/version"), 0, false);
        assert_eq!(rendered, "  /cache/marketplace/plugin/version (~0.0 MiB)");
    }

    #[test]
    fn prune_listing_keeps_paths_differing_only_by_stripped_char_distinct() {
        // `display_safe` DELETES rather than substitutes, so without a marker
        // these two on-disk directories render to one identical line — at a
        // deletion prompt, where the operator's only record is this listing.
        let plain = render_orphan_dir_line(Path::new("/cache/mp/plugin/08c0313deb23"), 0, false);
        let hostile =
            render_orphan_dir_line(Path::new("/cache/mp/plugin/08c0313deb23\u{200b}"), 0, false);

        assert_ne!(
            plain, hostile,
            "two distinct cache dirs must not render to the same listing line"
        );
        assert!(
            hostile.contains(HIDDEN_CHARS_NOTE),
            "the mangled name must be flagged; got {hostile:?}"
        );
        assert!(
            !plain.contains(HIDDEN_CHARS_NOTE),
            "an ordinary name must carry no flag; got {plain:?}"
        );
        assert!(
            !hostile.contains('\u{200b}'),
            "the zero-width char must still be stripped from the output"
        );
    }

    #[test]
    fn prune_listing_flags_a_wholly_strippable_name() {
        // Renders as the bare parent plugin dir, so the line would otherwise
        // read as though the whole plugin were being removed.
        let rendered = render_orphan_dir_line(
            Path::new("/cache/mp/plugin/\u{200b}\u{200b}\u{feff}"),
            1024 * 1024,
            false,
        );

        assert!(
            rendered.contains(HIDDEN_CHARS_NOTE),
            "an entirely-invisible name must be flagged; got {rendered:?}"
        );
        assert_ne!(
            rendered,
            render_orphan_dir_line(Path::new("/cache/mp/plugin/"), 1024 * 1024, false),
            "must not render identically to its own parent directory"
        );
    }

    #[test]
    fn prune_listing_bounds_an_overlong_path() {
        let long = "x".repeat(MAX_FINDING_FIELD_CHARS + 250);
        let rendered = render_orphan_dir_line(
            &PathBuf::from(format!("/cache/mp/plugin/{long}")),
            1024,
            false,
        );

        // Bounded to the ceiling plus the ellipsis, the two-space indent, and
        // the size suffix — nowhere near the ~700 chars the raw path implies.
        assert!(
            rendered.chars().count() < MAX_FINDING_FIELD_CHARS + 40,
            "line should be bounded, got {} chars",
            rendered.chars().count()
        );
        assert!(rendered.contains('…'), "truncation must be visible");
        assert!(
            rendered.contains("(~0.0 MiB)"),
            "the size figure must survive bounding; got {rendered:?}"
        );
        assert!(
            !rendered.contains(HIDDEN_CHARS_NOTE),
            "length alone is not a hidden character — truncation marks itself"
        );
    }

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

    // ── prune_liveness_gate (#305) ──────────────────────────────────────────

    /// Write a fresh peer record and return its sessions dir.
    fn seed_session(name: &str, session_id: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".claude").join("sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            name: name.into(),
            session_id: session_id.into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            ..Default::default()
        };
        session_registry::write_record(&dir, &rec).unwrap();
        tmp
    }

    #[test]
    fn prune_liveness_gate_forces_through() {
        // force wins even with a live session pinned.
        let tmp = seed_session("forge-anvil", "peer-session");
        let dir = tmp.path().join(".claude").join("sessions");
        assert!(matches!(
            prune_liveness_gate(Some(&dir), None, 600, true),
            PruneGate::Proceed
        ));
    }

    #[test]
    fn prune_liveness_gate_none_dir_proceeds() {
        assert!(matches!(
            prune_liveness_gate(None, None, 600, false),
            PruneGate::Proceed
        ));
    }

    #[test]
    fn prune_liveness_gate_empty_dir_proceeds() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            prune_liveness_gate(Some(tmp.path()), None, 600, false),
            PruneGate::Proceed
        ));
    }

    #[test]
    fn prune_liveness_gate_live_session_blocks_and_names() {
        let tmp = seed_session("forge-anvil", "peer-session");
        let dir = tmp.path().join(".claude").join("sessions");
        // Large stale window so the just-written record counts as live.
        match prune_liveness_gate(Some(&dir), None, 600, false) {
            PruneGate::Blocked(names) => {
                assert!(
                    names.contains(&"forge-anvil".to_string()),
                    "block must name the live session: {names:?}"
                );
            }
            PruneGate::Proceed => panic!("a live session must block the prune"),
        }
    }

    /// The cadence-hooks#634 case: a session live in ANOTHER checkout.
    ///
    /// This is the whole point of the mirror. The local registry is empty — the
    /// operator is pruning from a repo with no peers — while a session is live
    /// somewhere else on the machine, pinned to version dirs the prune would
    /// delete out from under it. The old gate proceeded here.
    ///
    /// It also asserts the refusal names the REPO, because "a session called
    /// forge-anvil is live" is not actionable when the reader cannot tell which
    /// of a dozen checkouts to go release it in.
    #[test]
    fn prune_liveness_gate_blocks_on_a_peer_in_another_checkout() {
        let local = tempfile::tempdir().unwrap();
        let local_dir = local.path().join(".claude").join("sessions");
        std::fs::create_dir_all(&local_dir).unwrap();

        let elsewhere = tempfile::tempdir().unwrap();
        let global_dir = elsewhere.path().join("live-sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            name: "distant-anvil".into(),
            session_id: "other-checkout-session".into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            repo: Some("/Users/x/Projects/other-repo".into()),
            ..Default::default()
        };
        session_registry::write_record(&global_dir, &rec).unwrap();

        // Control: without the mirror this is the old, under-protective answer.
        assert!(
            matches!(
                prune_liveness_gate(Some(&local_dir), None, 600, false),
                PruneGate::Proceed
            ),
            "local registry alone sees nothing — this is the defect"
        );

        match prune_liveness_gate(Some(&local_dir), Some(&global_dir), 600, false) {
            PruneGate::Blocked(names) => {
                assert_eq!(names.len(), 1, "one live peer: {names:?}");
                assert!(
                    names[0].contains("distant-anvil"),
                    "must name the session: {names:?}"
                );
                assert!(
                    names[0].contains("/Users/x/Projects/other-repo"),
                    "must name the repo, or the reader cannot act on it: {names:?}"
                );
            }
            PruneGate::Proceed => panic!("a peer in another checkout must block the prune"),
        }
    }

    /// A session registers in BOTH registries, so the naive union counts it
    /// twice — and the refusal reports a count of what it names, so a duplicate
    /// inflates "2 live session(s)" for one session. Dedupe is by session id,
    /// not by name, because names are generated from the id and two records for
    /// one session are the same session however they are spelled.
    #[test]
    fn prune_liveness_gate_counts_a_session_once_across_both_registries() {
        let tmp = seed_session("forge-anvil", "peer-session");
        let local_dir = tmp.path().join(".claude").join("sessions");
        let elsewhere = tempfile::tempdir().unwrap();
        let global_dir = elsewhere.path().join("live-sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            name: "forge-anvil".into(),
            session_id: "peer-session".into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            // Only the MIRROR record carries a repo here, deliberately: a local
            // record written by a pre-`repo` binary paired with a mirrored one
            // that has it is the real state during rollout. Asserting only the
            // count would pass while silently dropping the actionable field.
            repo: Some("/Users/x/Projects/some-repo".into()),
            ..Default::default()
        };
        session_registry::write_record(&global_dir, &rec).unwrap();

        match prune_liveness_gate(Some(&local_dir), Some(&global_dir), 600, false) {
            PruneGate::Blocked(names) => {
                assert_eq!(
                    names.len(),
                    1,
                    "one session mirrored into both registries is still one session: {names:?}"
                );
                assert!(
                    names[0].contains("/Users/x/Projects/some-repo"),
                    "dedupe must keep the record that can be acted on: {names:?}"
                );
            }
            PruneGate::Proceed => panic!("a live session must block the prune"),
        }
    }

    /// A cwd outside any git repository used to short-circuit to Proceed, on
    /// the reasoning that there was "nothing to protect". That reasoning is the
    /// repo-scoped assumption itself: not being in a repo says nothing about
    /// whether other sessions on the machine are live, and the cache they share
    /// is not owned by any checkout.
    #[test]
    fn prune_liveness_gate_consults_the_mirror_with_no_local_registry() {
        let elsewhere = tempfile::tempdir().unwrap();
        let global_dir = elsewhere.path().join("live-sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            name: "distant-anvil".into(),
            session_id: "some-session".into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            ..Default::default()
        };
        session_registry::write_record(&global_dir, &rec).unwrap();

        assert!(
            matches!(
                prune_liveness_gate(None, Some(&global_dir), 600, false),
                PruneGate::Blocked(_)
            ),
            "no local registry must not mean no live sessions"
        );
    }

    /// The escape hatch has to work against the NEW arm too, or an operator
    /// facing a cross-checkout block has no way through at all.
    #[test]
    fn prune_liveness_gate_force_overrides_a_global_peer() {
        let elsewhere = tempfile::tempdir().unwrap();
        let global_dir = elsewhere.path().join("live-sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            name: "distant-anvil".into(),
            session_id: "blocking-session".into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            ..Default::default()
        };
        session_registry::write_record(&global_dir, &rec).unwrap();

        assert!(
            matches!(
                prune_liveness_gate(None, Some(&global_dir), 600, false),
                PruneGate::Blocked(_)
            ),
            "control: without force this blocks"
        );
        assert!(
            matches!(
                prune_liveness_gate(None, Some(&global_dir), 600, true),
                PruneGate::Proceed
            ),
            "force must override the cross-checkout arm too"
        );
    }

    /// Record fields come from JSON this process did not write and land on an
    /// interactive terminal in a DESTRUCTIVE command's refusal. A control
    /// character there can rewrite the rendered line.
    #[test]
    fn prune_refusal_sanitizes_record_fields() {
        let elsewhere = tempfile::tempdir().unwrap();
        let global_dir = elsewhere.path().join("live-sessions");
        let rec = cadence_hooks_session::identity::SessionRecord {
            // Hostile content goes in `repo`, not `name`: the record FILENAME
            // derives from the name, and Windows rejects control characters in
            // filenames, so a hostile name makes the fixture unwritable there
            // rather than testing the renderer. The name exercises the length
            // cap instead — the other half of the same sanitize call.
            name: "x".repeat(200),
            session_id: "hostile-session".into(),
            started: cadence_hooks_session::identity::utc_timestamp(),
            started_epoch: cadence_hooks_session::identity::now_epoch(),
            repo: Some("/repo\r\u{1b}[2K0 live sessions — safe to force".into()),
            ..Default::default()
        };
        session_registry::write_record(&global_dir, &rec).unwrap();

        match prune_liveness_gate(None, Some(&global_dir), 600, false) {
            PruneGate::Blocked(names) => {
                let rendered = names.join(" ");
                assert!(
                    !rendered.contains('\r') && !rendered.contains('\u{1b}'),
                    "control characters must never reach the terminal: {rendered:?}"
                );
                assert!(
                    rendered.len() < 200,
                    "an overlong name must be capped, not rendered whole: {rendered:?}"
                );
            }
            PruneGate::Proceed => panic!("a live session must block the prune"),
        }
    }

    #[test]
    fn prune_liveness_gate_only_stale_proceeds() {
        let tmp = seed_session("forge-anvil", "peer-session");
        let dir = tmp.path().join(".claude").join("sessions");
        // stale_secs = 0: any measurable mtime age makes the peer stale.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(matches!(
            prune_liveness_gate(Some(&dir), None, 0, false),
            PruneGate::Proceed
        ));
    }

    // ── guardrails_identity_finding (#275) ───────────────────────────────────

    /// Write a user-level settings.json body and return its path.
    fn seed_user_settings(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, body).unwrap();
        (dir, path)
    }

    #[test]
    fn guardrails_identity_configured_machine_is_clean() {
        let (_dir, path) = seed_user_settings(r#"{"env":{"CADENCE_ALLOWED_OWNERS":"cameronsjo"}}"#);

        assert!(guardrails_identity_finding(&path).is_none());
    }

    #[test]
    fn guardrails_identity_unset_owners_warns_about_blocked_pushes() {
        let (_dir, path) = seed_user_settings(r#"{"env":{"SOMETHING_ELSE":"x"}}"#);

        let finding = guardrails_identity_finding(&path).expect("unset owners warns");

        assert_eq!(finding.severity, Severity::Warning);
        assert!(
            finding.diagnosis.contains("unset or empty"),
            "{}",
            finding.diagnosis
        );
        assert!(
            finding.remediation.contains("configure guardrails"),
            "names the fix: {}",
            finding.remediation
        );
    }

    #[test]
    fn guardrails_identity_legacy_only_says_every_push_is_blocked() {
        let (_dir, path) =
            seed_user_settings(r#"{"env":{"GIT_GUARDRAILS_ALLOWED_OWNERS":"cameronsjo"}}"#);

        let finding = guardrails_identity_finding(&path).expect("legacy-only warns");

        assert!(
            finding.diagnosis.contains("is blocked"),
            "{}",
            finding.diagnosis
        );
        assert!(
            finding.diagnosis.contains("GIT_GUARDRAILS_ALLOWED_OWNERS"),
            "names the legacy key: {}",
            finding.diagnosis
        );
    }

    #[test]
    fn guardrails_identity_lingering_legacy_alongside_current_warns() {
        let (_dir, path) = seed_user_settings(
            r#"{"env":{
                 "CADENCE_ALLOWED_OWNERS":"cameronsjo",
                 "GIT_GUARDRAILS_ALLOWED_OWNERS":"cameronsjo"
               }}"#,
        );

        let finding = guardrails_identity_finding(&path).expect("lingering legacy warns");

        assert!(
            finding.diagnosis.contains("no longer read"),
            "{}",
            finding.diagnosis
        );
    }

    #[test]
    fn guardrails_identity_fails_open_on_missing_or_malformed_settings() {
        let dir = tempfile::tempdir().unwrap();
        assert!(guardrails_identity_finding(&dir.path().join("absent.json")).is_none());

        let (_dir, path) = seed_user_settings("{ not json");
        assert!(guardrails_identity_finding(&path).is_none());
    }

    // ── legacy_config_findings / cadence_config_parse_finding (#153) ─────────

    fn seed_claude(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        fs::create_dir_all(&claude).unwrap();
        for (name, body) in files {
            fs::write(claude.join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn legacy_config_findings_flags_present_files() {
        let dir = seed_claude(&[("redaction.json", "{}"), ("terminology.json", "{}")]);
        let findings = legacy_config_findings(dir.path());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Warning));
        assert!(
            findings
                .iter()
                .all(|f| f.remediation.contains("migrate-config")),
            "each remediation points at migrate-config"
        );
        let snippets: Vec<&str> = findings.iter().map(|f| f.snippet.as_str()).collect();
        assert!(snippets.contains(&"redaction.json"));
        assert!(snippets.contains(&"terminology.json"));
    }

    #[test]
    fn legacy_config_findings_clean_repo_is_empty() {
        // Only the unified file present → nothing to warn about.
        let dir = seed_claude(&[("cadence.json", r#"{"version":1}"#)]);
        assert!(legacy_config_findings(dir.path()).is_empty());
    }

    #[test]
    fn legacy_config_findings_partial_flags_only_present() {
        let dir = seed_claude(&[("redaction.json", "{}")]);
        let findings = legacy_config_findings(dir.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].snippet, "redaction.json");
    }

    #[test]
    fn cadence_config_parse_finding_malformed_warns() {
        let dir = seed_claude(&[("cadence.json", "{not valid json")]);
        let finding =
            cadence_config_parse_finding(dir.path()).expect("a malformed cadence.json must warn");
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.diagnosis.contains("not valid JSON"));
    }

    #[test]
    fn cadence_config_parse_finding_valid_is_none() {
        let dir = seed_claude(&[(
            "cadence.json",
            r#"{"version":1,"terminology":{"exemptions":[]}}"#,
        )]);
        assert!(cadence_config_parse_finding(dir.path()).is_none());
    }

    #[test]
    fn cadence_config_parse_finding_non_object_warns() {
        // Syntactically-valid JSON whose top level is not an object: every
        // guard's `value.get(section)` yields nothing, so they silently fall
        // open to defaults. Doctor must still warn, and distinguish this from
        // the malformed-JSON case.
        let dir = seed_claude(&[("cadence.json", "[]")]);
        let finding =
            cadence_config_parse_finding(dir.path()).expect("a non-object cadence.json must warn");
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.diagnosis.contains("not a JSON object"));
        assert!(!finding.diagnosis.contains("not valid JSON"));
    }

    #[test]
    fn cadence_config_parse_finding_absent_is_none() {
        let dir = seed_claude(&[]);
        assert!(cadence_config_parse_finding(dir.path()).is_none());
    }

    // ── find_baseline_in tests (cadence#667) ────────────────────────────────

    #[test]
    fn find_baseline_in_finds_baseline_under_the_given_cache_root() {
        // The bug this closes: the platform-baseline lookup used to hardcode
        // `$HOME/.claude/plugins/cache/...` regardless of CLAUDE_CONFIG_DIR.
        // find_baseline_in is the pure core, parameterized on cache_root, so
        // this proves the lookup honors WHATEVER dir it's given — not a
        // literal home path.
        let cache_root = tempfile::tempdir().unwrap();
        let pin_dir = cache_root.path().join("workbench/cadence/some-sha");
        fs::create_dir_all(pin_dir.join("config")).unwrap();
        let baseline_path = write_platform_baseline(&pin_dir.join("config"), "0.70.0", "2.1.218");
        assert_eq!(find_baseline_in(cache_root.path()), Some(baseline_path));
    }

    #[test]
    fn find_baseline_in_a_dir_with_no_cadence_cache_is_none() {
        // Negative control for the above: an unrelated dir (standing in for
        // the pre-fix behavior of searching the WRONG config dir) finds
        // nothing, same as a genuinely absent cache would.
        let unrelated_dir = tempfile::tempdir().unwrap();
        assert!(find_baseline_in(unrelated_dir.path()).is_none());
    }

    #[test]
    fn find_baseline_in_newest_pin_wins_over_a_stale_sibling() {
        let cache_root = tempfile::tempdir().unwrap();
        let cadence_dir = cache_root.path().join("workbench/cadence");
        let old_pin = cadence_dir.join("old-sha/config");
        let new_pin = cadence_dir.join("new-sha/config");
        fs::create_dir_all(&old_pin).unwrap();
        fs::create_dir_all(&new_pin).unwrap();
        write_platform_baseline(&old_pin, "0.60.0", "2.1.200");
        // Ensure a distinguishable mtime ordering regardless of filesystem
        // timestamp resolution.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let newest_path = write_platform_baseline(&new_pin, "0.70.0", "2.1.218");
        assert_eq!(find_baseline_in(cache_root.path()), Some(newest_path));
    }

    #[test]
    fn regression_relocated_config_dir_without_plugins_falls_back_like_plugins_dir_does() {
        // Differential control for the exact regression three review arms
        // independently flagged on this branch: on a profile where
        // CLAUDE_CONFIG_DIR is set but plugins/ was never relocated, the
        // baseline still lives under $HOME/.claude/plugins/cache. The BUGGY
        // pattern re-derives `claude_config_dir().join("plugins/cache")`
        // directly with no existence check and no fallback; the FIXED
        // pattern is plugins_dir()'s own exists()-check-then-fallback,
        // mirrored inline below since plugins_dir() reads real env/HOME and
        // can't be env-mutated safely under a parallel test runner.
        //
        // Both branches run against the SAME on-disk fixture in one test, so
        // this is a true red/green pair rather than two tests that could
        // drift apart: the buggy resolver must return None while the fixed
        // resolver, given the identical fixture, must find the baseline.
        let home_root = tempfile::tempdir().unwrap();
        let config_root = tempfile::tempdir().unwrap(); // CLAUDE_CONFIG_DIR override — carries no plugins/

        let home_plugins_cache = home_root.path().join(".claude/plugins/cache");
        let pin_dir = home_plugins_cache.join("workbench/cadence/some-sha");
        fs::create_dir_all(pin_dir.join("config")).unwrap();
        let baseline_path = write_platform_baseline(&pin_dir.join("config"), "0.70.0", "2.1.218");

        // BUGGY: re-derive directly — no exists() check, no fallback. This
        // is the exact shape of the flagged regression.
        let buggy_cache_root = config_root.path().join("plugins").join("cache");
        assert_eq!(
            find_baseline_in(&buggy_cache_root),
            None,
            "the regression: reports the baseline missing even though it exists at the default location"
        );

        // FIXED: plugins_dir()'s own logic — prefer the config-dir variant,
        // fall back to $HOME/.claude/plugins when that variant doesn't exist.
        let config_variant = config_root.path().join("plugins");
        let fixed_plugins_dir = if config_variant.exists() {
            config_variant
        } else {
            home_root.path().join(".claude/plugins")
        };
        let fixed_cache_root = plugins_cache_dir_from(&fixed_plugins_dir);
        assert_eq!(
            find_baseline_in(&fixed_cache_root),
            Some(baseline_path),
            "the fix: falls back to the default location and finds the baseline"
        );
    }

    // ── platform_drift_status_lines tests ───────────────────────────────────

    fn write_platform_baseline(dir: &Path, hooks_version: &str, cc_version: &str) -> PathBuf {
        let path = dir.join("platform-baseline.json");
        fs::write(
            &path,
            format!(
                r#"{{"claude_code":{{"last_swept_version":"{cc_version}","swept_on":"2026-07-23","sweep_doc":"n/a"}},"cadence_hooks":{{"current_version":"{hooks_version}"}}}}"#
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn platform_drift_status_missing_baseline_is_one_info_line() {
        let lines = platform_drift_status_lines(
            None,
            Some("2.1.218"),
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("baseline not found"));
    }

    #[test]
    fn platform_drift_status_missing_baseline_names_the_resolved_search_dir() {
        // cadence#667: the message must name the dir doctor actually searched
        // (e.g. a resolved CLAUDE_CONFIG_DIR's cache dir), never a hardcoded
        // ~/.claude literal that could point somewhere the code never looked.
        let lines = platform_drift_status_lines(
            None,
            Some("2.1.218"),
            Some(Path::new("/y/.claude-alt/plugins/cache")),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("/y/.claude-alt/plugins/cache/workbench/cadence"));
        assert!(!lines[0].contains("~/.claude"));
    }

    #[test]
    fn platform_drift_status_unresolvable_cache_dir_is_honest_not_fabricated() {
        // cadence#667 (team-lead addendum): when plugins_cache_dir() itself
        // can't resolve, the message must say so rather than construct a
        // path that was never searched.
        let lines = platform_drift_status_lines(None, Some("2.1.218"), None);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("could not resolve"));
        assert!(!lines[0].contains("~/.claude"));
    }

    #[test]
    fn platform_drift_status_unreadable_baseline_is_one_info_line() {
        let lines = platform_drift_status_lines(
            Some(Path::new("/nonexistent/baseline.json")),
            Some("2.1.218"),
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("unreadable"));
    }

    #[test]
    fn platform_drift_status_malformed_baseline_is_one_info_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("platform-baseline.json");
        fs::write(&path, "not json").unwrap();
        let lines = platform_drift_status_lines(
            Some(&path),
            Some("2.1.218"),
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("malformed"));
    }

    #[test]
    fn platform_drift_status_current_baseline_is_two_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_platform_baseline(tmp.path(), env!("CARGO_PKG_VERSION"), "2.1.218");
        let lines = platform_drift_status_lines(
            Some(&path),
            Some("2.1.218"),
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("cadence-hooks"));
        assert!(lines[1].contains("Claude Code"));
    }

    #[test]
    fn platform_drift_status_far_ahead_baseline_is_still_two_lines() {
        // Unthresholded: doctor shows both current-state lines regardless of
        // gap size, unlike the SessionStart nudge's >= 5 threshold.
        let tmp = tempfile::tempdir().unwrap();
        let path = write_platform_baseline(tmp.path(), "0.1.0", "2.0.0");
        let lines = platform_drift_status_lines(
            Some(&path),
            Some("2.1.218"),
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[1].contains("2.1.218"));
        assert!(lines[1].contains("2.0.0"));
    }

    #[test]
    fn platform_drift_status_missing_cc_version_notes_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_platform_baseline(tmp.path(), env!("CARGO_PKG_VERSION"), "2.1.218");
        let lines = platform_drift_status_lines(
            Some(&path),
            None,
            Some(Path::new("/y/.claude/plugins/cache")),
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("unavailable"));
    }
}
