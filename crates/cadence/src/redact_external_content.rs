//! Nudge before internal harness vocabulary leaks into an external post.
//!
//! A PreToolUse **nudge** (never a block) that scans the *body text* of
//! external-posting Bash commands — `gh pr/issue/release/gist/discussion`
//! create/comment/edit, `git commit`, `tea pr/issue` — for vocabulary that is
//! meaningful only inside this harness: skill/plugin IDs (`cadence:attune`),
//! local filesystem paths (`/Users/…`, `~/.claude/…`), marketplace/cache paths,
//! and harness-shaped identifiers (`tool_input`, `tool_response`). When it finds any, it
//! suggests rephrasing before the content ships to a public issue/PR/commit.
//!
//! ## Why a nudge, never a block (developing-guards "block vs nudge")
//!
//! There is a routine, intentional workflow that legitimately mentions these
//! terms in an external post — documenting the harness itself, an issue *about*
//! `cadence:writing-skills`, a commit that renames `tool_input`. The condition
//! is detectable but the policy is advisory, so this is a nudge. The per-repo
//! `.claude/cadence.json` `redaction.allowlist` is the escape hatch for the
//! recurring legitimate case.
//!
//! ## Body extraction is scoped to the posting segment (#424)
//!
//! Gate and extraction run **per segment** ([`command_segments`]), never over
//! the whole command line. A whole-line gate paired with whole-line extraction
//! made one posting segment authorize extraction from every *sibling* segment,
//! so `gh secret set N --body '…' && gh pr comment -b hi` scanned the secret's
//! body (which never posts anywhere) and `gh api x --body-file f && git commit`
//! *read the file* `gh api` named. A file named by a non-posting segment must
//! never be opened, so the per-segment gate has to precede extraction rather
//! than filter its results.
//!
//! Within a matching segment, bodies are pulled from flag VALUES via
//! [`tokenize`] — deliberately not from a further re-split, since [`tokenize`]
//! keeps a quoted value as one token. A heredoc carried in a quoted command
//! substitution — `git commit -m "$(cat <<'EOF' … EOF)"` — survives
//! segmentation intact (the heredoc sits inside quotes, so segment splitting
//! never treats it as a top-level heredoc body) and rides into the `-m` value,
//! so its body lines are still scanned. Only flag values are scanned, so the
//! command words/flags themselves never trip the blocklist.
//!
//! Failure is silent (`allow()`): no recognized body flag, an unreadable
//! `--body-file`, a parse miss, or no hits all proceed without a message. In
//! nudge mode, silent failure beats false positives.

use cadence_hooks_core::shell::{command_segments, strip_quotes, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

/// The three audience tiers, ordered narrow → wide: owned-internal(1) <
/// private-external(2) < public(3). Deserialized where a config field is
/// tier-typed; the ordinal mapping is the single source of truth reused by the
/// two string-keyed ordinal fns below.
///
/// Redaction is `f(content, audience)`: a hit is retained (nudged) only when it
/// crosses to a *wider* audience than the tier where it is native — redact iff
/// destination-tier ordinal `d` > the hit's ceiling ordinal `c`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AudienceTier {
    OwnedInternal,
    PrivateExternal,
    Public,
}

impl AudienceTier {
    /// Position in the narrow→wide order.
    fn ordinal(self) -> u8 {
        match self {
            AudienceTier::OwnedInternal => 1,
            AudienceTier::PrivateExternal => 2,
            AudienceTier::Public => 3,
        }
    }
}

/// Destination-tier ordinal. String-keyed (not `AudienceTier`-typed) so an
/// unknown/typo'd string hits the documented fail-safe instead of failing to
/// deserialize. Unknown → 3 (widest/public) so an unrecognized destination
/// redacts MORE, never less. `always` is a config-only CEILING sentinel, never a
/// valid destination — a stray `originAudience: "always"` must resolve to
/// public(3), never 0, or it would suppress every hit (the total-bypass trap).
fn dest_tier_ord(s: &str) -> u8 {
    match s {
        "owned-internal" => AudienceTier::OwnedInternal.ordinal(),
        "private-external" => AudienceTier::PrivateExternal.ordinal(),
        "public" => AudienceTier::Public.ordinal(),
        _ => 3,
    }
}

/// Ceiling ordinal. Unknown → 1 (owned-internal, the documented default) so a
/// typo'd ceiling (`"owned_internal"`) never widens to public and silently
/// suppresses a hit. Fail-safe for a ceiling is the SMALLER ordinal (redact at
/// more destinations) — the opposite direction from a destination. `always`(0)
/// is a config-only sentinel meaning "redact at every tier".
fn ceiling_ord(s: &str) -> u8 {
    match s {
        "always" => 0,
        "owned-internal" => AudienceTier::OwnedInternal.ordinal(),
        "private-external" => AudienceTier::PrivateExternal.ordinal(),
        "public" => AudienceTier::Public.ordinal(),
        _ => 1,
    }
}

/// Plugin/skill namespaces whose `<ns>:<name>` IDs are harness-internal.
///
/// A `const &[&str]` rather than a frozen regex literal so adding a new plugin
/// is a one-line edit — the [`SKILL_ID`] regex is *derived* from this list at
/// init. `mcp` is both a namespace and a prefix of `cadence-mcp`; the regex
/// builder sorts longest-first so `cadence-mcp:x` is caught as `cadence-mcp:x`,
/// not as `cadence` + leftover or bare `mcp`.
/// `pub` (rather than crate-private) so the cross-sibling namespace-parity
/// audit test (`tests/hook_registration_audit.rs`) can read it directly and
/// diff it against the plugin-side `redact-check.sh` namespace list. Exposed
/// for that in-repo test linkage only — not a supported public API.
#[doc(hidden)]
pub const NAMESPACES: &[&str] = &[
    "cadence",
    "cadence-forge",
    "cadence-groundwork",
    "cadence-voice",
    "cadence-mcp",
    "cadence-obsidian",
    "cadence-palette",
    "cadence-lab",
    "cadence-rules",
    "cadence-guardrails",
    "cadence-canon",
    "cadence-discovery",
    "mcp",
    "core",
];

/// External-posting command gate, matched against the quote-stripped command so
/// a body that merely *mentions* `gh pr create` can't trip it. The flags are
/// how we pull the body; this gate is what scopes the scan to commands that
/// actually publish content. `git commit` is included — commit messages ship to
/// GitHub. Read/label-only variants (`gh pr edit` with no `--body`) extract no
/// body and fall through to `allow()`.
static EXTERNAL_POST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bgh\s+(pr|issue|release|gist|discussion)\s+(create|comment|edit|review|reopen)\b|\bgit\s+commit\b|\btea\s+(pr|issue)\s+(create|comment|edit)\b",
    )
    .expect("external-post pattern should compile")
});

/// Category 1 — skill/plugin IDs (`<ns>:<name>`). Derived from [`NAMESPACES`],
/// longest-first so the most specific namespace wins regardless of the regex
/// engine's alternation-preference semantics. The `[a-z0-9]` immediately after
/// the colon is the prose firewall: `the cadence: of work` (space after colon)
/// never matches; `cadence:attune` does.
static SKILL_ID: LazyLock<Regex> = LazyLock::new(|| {
    let mut ns: Vec<&str> = NAMESPACES.to_vec();
    ns.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let alt = ns.join("|");
    Regex::new(&format!(r"\b({alt}):([a-z0-9][a-z0-9-]*)\b"))
        .expect("skill-id pattern should compile")
});

/// Category 3 — marketplace / plugin-cache locations. Scanned BEFORE the
/// broader local-path category so the more specific `~/.claude/plugins/…` is
/// labelled `marketplace`, not `local-path` (categories 2 and 3 overlap on
/// `~/.claude/…`; offset-dedup keeps the first match, which is this one).
static MARKETPLACE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"~/\.claude/plugins/[^\s'"]*|cache/workbench/[^\s'"]*|raw\.githubusercontent\.com/[^\s'"]*marketplace\.json"#,
    )
    .expect("marketplace-path pattern should compile")
});

/// Category 2 — local filesystem paths. `/Users/…`, the rest of `~/.claude/…`
/// (the plugins subtree is claimed by [`MARKETPLACE_PATH`]), and the
/// `/private/tmp/claude-*` scratch dirs. Character class stops at whitespace and
/// quotes so a path embedded in markdown prose is captured cleanly.
static LOCAL_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"/Users/[^\s'"]+|~/\.claude/[^\s'"]*|/private/tmp/claude-[^\s'"]*"#)
        .expect("local-path pattern should compile")
});

/// Category 4 — harness-shaped identifiers. Word-boundary anchored; `_` is a
/// word char, so prose mentions and code identifiers embedding these tokens
/// (`tool_input_schema`) do NOT match. The bare nouns `harness` and
/// `transcript` were deleted from this class (cadence-hooks#406, #564):
/// zero true positives across the class's life, while the words are mandated
/// domain vocabulary in estate prose. Repos that want them back can add
/// `additionalPatterns` entries with a per-entry `ceiling`.
static HARNESS_NOUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(tool_input|tool_response)\b").expect("harness-noun pattern should compile")
});

/// Per-repo override, read from the `redaction` section of
/// `<git-root>/.claude/cadence.json` (cadence-hooks#153). Missing file,
/// unreadable, invalid JSON, or an absent section all deserialize to the
/// default (empty) config — the check never errors on it (fail-open, ADR-0001).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RedactionConfig {
    /// Tier of THIS surface, used as the scan destination when `CADENCE_AUDIENCE`
    /// is unset. `String` (not `AudienceTier`) so a stray/typo'd value resolves
    /// via [`dest_tier_ord`]'s fail-safe rather than failing the whole config to
    /// deserialize. Omitted → public (widest, safest).
    #[serde(default)]
    origin_audience: Option<String>,
    /// Per-category ceiling overrides, keyed by the emitted category name
    /// (`skill-id`, `local-path`, `marketplace`, `harness-noun`). A category
    /// without an entry uses the default ceiling (`owned-internal`).
    #[serde(default)]
    categories: HashMap<String, CategoryOverride>,
    /// Extra literal/regex patterns to flag, each with the replacement to show.
    #[serde(default)]
    additional_patterns: Vec<AdditionalPattern>,
    /// Tokens that suppress a hit. Colon presence changes what a colon-free
    /// entry means per category — see [`is_allowlisted`] for the full rule:
    /// - **full token** (`cadence:writing-skills`) → suppresses only that exact
    ///   matched snippet, in any category;
    /// - **bare namespace**, for `skill-id` hits (`cadence`, `cadence-forge`,
    ///   `mcp`) → suppresses every skill-id hit whose namespace equals it;
    /// - **bare exact-match**, for any other category (`local-path`,
    ///   `marketplace`, `harness-noun`, `custom`) → suppresses a hit whose
    ///   snippet equals the entry exactly (#318).
    ///
    /// The bare-namespace form lets a repo that legitimately discusses a whole
    /// namespace (the meta-repo dogfooding all cadence skills, say) allow-list it
    /// wholesale instead of enumerating every skill ID.
    #[serde(default)]
    allowlist: Vec<String>,
    /// Deserialized but inert in Phase 2. Reserved for Phase-2b, when it will
    /// gate the `--repo` owner-vs-origin visibility resolution.
    #[serde(default)]
    #[allow(dead_code)]
    resolve_visibility: bool,
}

/// One `categories[<name>]` entry: a per-category ceiling override.
#[derive(Debug, Deserialize)]
struct CategoryOverride {
    /// Ceiling tier for this category; absent resolves to `owned-internal` at
    /// use via [`category_ceiling`].
    #[serde(default)]
    ceiling: Option<String>,
}

/// One `additionalPatterns[]` entry: a project-specific string to flag and the
/// replacement to suggest in the nudge.
#[derive(Debug, Deserialize)]
struct AdditionalPattern {
    pattern: String,
    #[serde(default)]
    replacement: String,
    /// Per-entry ceiling tier; absent resolves to `owned-internal` at use. Opt
    /// into `always` for PII / secrets-adjacent patterns that must redact at
    /// every destination.
    #[serde(default)]
    ceiling: Option<String>,
}

/// A single blocklist hit within one body. `offset` is the match start within
/// that body, used only for cross-category offset dedup.
struct Hit {
    category: &'static str,
    snippet: String,
    offset: usize,
    /// Replacement to surface (set only for `additionalPatterns` hits).
    replacement: Option<String>,
}

/// Flag against this nudge when it dispatches internal harness vocabulary to an
/// external post.
pub struct RedactExternalContent;

impl Check for RedactExternalContent {
    fn name(&self) -> &str {
        "redact-external-content"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // Phase 1 — early exit: only Bash carries a postable command.
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Phase 2 — gate and extract PER SEGMENT (#424). A segment that does
        // not itself publish contributes no body, so its `--body-file` is never
        // opened; only a segment that passes the gate has its flag values read.
        // Quote-strip each segment first so a body merely mentioning `gh pr
        // create` can't self-trip. Silent allow if no segment yields a body.
        let base_dir = resolve_base_dir(input);
        let mut bodies: Vec<String> = Vec::new();
        for segment in command_segments(command) {
            if EXTERNAL_POST.is_match(&strip_quotes(&segment)) {
                bodies.extend(extract_bodies(&segment, &base_dir));
            }
        }
        if bodies.is_empty() {
            return CheckResult::allow();
        }

        // Phase 3 — config (per-repo additional patterns + allowlist + tiers).
        // Lenient (#536): a malformed key is dropped and NAMED, the rest of
        // the section still applies — one bad `categories` shape no longer
        // silently voids a valid `allowlist` beside it.
        let loaded = load_redaction_config(&base_dir);
        let config = loaded.config;

        // Phase 3.5 — resolve the destination-tier ordinal once. `CADENCE_AUDIENCE`
        // wins over the config's `originAudience`; both fall back to public.
        let env_audience = std::env::var("CADENCE_AUDIENCE").ok();
        let d = resolve_dest_tier(env_audience.as_deref(), &config);

        // Phase 4 — scan each body, collect hits (gated on d > ceiling).
        let mut hits: Vec<Hit> = Vec::new();
        for body in &bodies {
            hits.extend(scan_body(body, &config, d));
        }

        // Config warnings ride the nudge channel (exit 0 / stdout → lands in
        // the transcript). A clean scan with a broken config still nudges —
        // otherwise the drop is exactly as silent as the #536 defect was.
        let warnings = loaded.warnings;
        match (hits.is_empty(), warnings.is_empty()) {
            (true, true) => CheckResult::allow(),
            (true, false) => CheckResult::nudge(build_config_warning(&warnings)),
            (false, true) => CheckResult::nudge(build_message(&hits)),
            (false, false) => CheckResult::nudge(format!(
                "{}\n{}",
                build_message(&hits),
                build_config_warning(&warnings)
            )),
        }
    }
}

/// Render config-load warnings as one nudge block. NB this fires on every
/// gated posting command (incl. `git commit`) until the config is fixed —
/// accepted cost: the whole point is that the drop is no longer silent, and
/// the fix is a one-time config edit the message names precisely.
fn build_config_warning(warnings: &[String]) -> String {
    format!(
        "⚠️  redact-external-content: config anomalies in .claude/cadence.json:\n{}",
        cadence_hooks_core::config::render_config_warnings(warnings)
    )
}

/// Resolve the directory to read `.claude/cadence.json` from and to resolve a
/// relative `--body-file` path against: the hook's `cwd`, falling back to the
/// process working directory, then `.`.
fn resolve_base_dir(input: &HookInput) -> String {
    input
        .cwd
        .clone()
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| ".".to_string())
}

/// Extract body text from the flag values of ONE gate-passing segment. Callers
/// must apply the [`EXTERNAL_POST`] gate to the segment first — a file-body flag
/// is read here, so handing this a non-posting segment performs I/O the guard
/// has no business doing (#424).
///
/// Literal-body flags (`--body`/`-b`/`-m`/`--message`, plus their `=`-joined and
/// glued-short forms) contribute their value verbatim. File-body flags
/// (`--body-file`/`-F`) contribute the file's contents read from disk; an
/// unreadable path is silently skipped (fail-open). `tokenize` keeps a quoted
/// value as one token, so a heredoc inside `"$(cat <<EOF … EOF)"` rides into the
/// value intact. `--title`/`-t` is deliberately out of scope (the spec scans
/// bodies only).
fn extract_bodies(segment: &str, base_dir: &str) -> Vec<String> {
    let tokens = tokenize(segment);
    let mut bodies = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        // Separate-token literal body flags.
        if matches!(tok, "--body" | "-b" | "-m" | "--message")
            && let Some(v) = tokens.get(i + 1)
        {
            bodies.push(v.clone());
            i += 2;
            continue;
        }
        // Separate-token file-body flags (value is a path → read it). The flag
        // consumes two tokens whether or not the file reads, so the i-advance
        // stays outside the read-success branch.
        if matches!(tok, "--body-file" | "-F")
            && let Some(p) = tokens.get(i + 1)
        {
            if let Some(content) = read_body_file(p, base_dir) {
                bodies.push(content);
            }
            i += 2;
            continue;
        }
        // `=`-joined long forms.
        if let Some(v) = tok
            .strip_prefix("--body=")
            .or_else(|| tok.strip_prefix("--message="))
        {
            bodies.push(v.to_string());
            i += 1;
            continue;
        }
        if let Some(p) = tok.strip_prefix("--body-file=") {
            if let Some(content) = read_body_file(p, base_dir) {
                bodies.push(content);
            }
            i += 1;
            continue;
        }
        // Glued short forms: `-mMSG`, `-bBODY` (literal), `-FPATH` (file).
        if !tok.starts_with("--") && tok.len() > 2 {
            if let Some(v) = tok.strip_prefix("-m").or_else(|| tok.strip_prefix("-b")) {
                bodies.push(v.to_string());
                i += 1;
                continue;
            }
            if let Some(p) = tok.strip_prefix("-F") {
                if let Some(content) = read_body_file(p, base_dir) {
                    bodies.push(content);
                }
                i += 1;
                continue;
            }
        }
        i += 1;
    }
    bodies
}

/// Read a `--body-file` value from disk, resolving a relative path against
/// `base_dir`. `None` on any error (missing, non-UTF-8, `-` for stdin,
/// non-regular file, oversized) so the caller fails open.
///
/// #194: shares the #157 unbounded-read DoS shape — a symlink to an endless
/// special file (`/dev/zero`, a FIFO) or a multi-GB file could hang or OOM the
/// hook — so this routes through the same bounded, regular-file-only reader.
fn read_body_file(path: &str, base_dir: &str) -> Option<String> {
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(base_dir).join(p)
    };
    cadence_hooks_core::paths::read_untrusted_config(&full)
}

/// Load this guard's `redaction` section from `<git-root>/.claude/cadence.json`
/// (cadence-hooks#153), walking up from `base_dir` to the first ancestor
/// containing a `.git` entry (dir or worktree file). Any failure — no git root,
/// missing/unreadable file, invalid JSON, or an absent section — yields the
/// default (empty) config. The legacy `.claude/redaction.json` is no longer
/// read (hard cut); `cadence-hooks migrate-config` converts a repo and
/// `cadence-hooks doctor` warns on an orphaned legacy file.
fn load_redaction_config(
    base_dir: &str,
) -> cadence_hooks_core::config::SectionLoad<RedactionConfig> {
    let Some(root) = cadence_hooks_core::paths::find_git_root(base_dir) else {
        return cadence_hooks_core::config::SectionLoad {
            config: RedactionConfig::default(),
            warnings: Vec::new(),
        };
    };
    cadence_hooks_core::config::load_cadence_section_lenient(&root, "redaction")
}

/// Resolve the destination-tier ordinal (PURE — env passed as an argument, never
/// read from `std::env` here, so the audience seam is fixture-testable).
/// Resolution order: `CADENCE_AUDIENCE` (via `env_audience`) → config
/// `originAudience` → public(3, widest/safest). Awareness only relaxes on proof.
fn resolve_dest_tier(env_audience: Option<&str>, config: &RedactionConfig) -> u8 {
    // Phase-2b: derive tier from --repo owner vs origin remote owner (local
    // .git/config, no network) as a lower-priority source below env/config.
    if let Some(a) = env_audience {
        dest_tier_ord(a)
    } else if let Some(a) = config.origin_audience.as_deref() {
        dest_tier_ord(a)
    } else {
        3
    }
}

/// Ceiling string for a universal category: the config `.categories` override or
/// the default `owned-internal`. Returned as `&str` for a direct
/// [`ceiling_ord`] call.
fn category_ceiling<'a>(config: &'a RedactionConfig, category: &str) -> &'a str {
    config
        .categories
        .get(category)
        .and_then(|c| c.ceiling.as_deref())
        .unwrap_or("owned-internal")
}

/// Scan one body for blocklist hits, deduped by start offset across categories,
/// gating each hit on the audience rule: retain iff `d > c` (destination tier
/// wider than the hit's ceiling).
///
/// Categories are scanned skill-id → marketplace → local-path → harness →
/// additional; the first to claim a start offset reports it (so a single
/// `~/.claude/plugins/…` offset is reported once, as `marketplace`). An
/// allowlisted hit pins its ceiling to public (never redacted here).
fn scan_body(body: &str, config: &RedactionConfig, d: u8) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    let mut claimed: HashSet<usize> = HashSet::new();

    let universal: [(&'static str, &Regex); 4] = [
        ("skill-id", &SKILL_ID),
        ("marketplace", &MARKETPLACE_PATH),
        ("local-path", &LOCAL_PATH),
        ("harness-noun", &HARNESS_NOUN),
    ];
    for (category, regex) in universal {
        for m in regex.find_iter(body) {
            // Claim the offset when first seen (so a lower-priority category
            // never re-reports it), then decide whether the audience gate keeps
            // it.
            if claimed.insert(m.start()) {
                let hit = Hit {
                    category,
                    snippet: m.as_str().to_string(),
                    offset: m.start(),
                    replacement: None,
                };
                // Allowlisted → ceiling public (never redacts); else the
                // category's configured/default ceiling. Retain iff d > c.
                let ceiling = if is_allowlisted(&hit, &config.allowlist) {
                    "public"
                } else {
                    category_ceiling(config, category)
                };
                if d > ceiling_ord(ceiling) {
                    hits.push(hit);
                }
            }
        }
    }

    // Per-repo additional patterns — each `pattern` is treated as a regex; one
    // that fails to compile is skipped (fail-open). The ceiling is computed once
    // per entry (default owned-internal); a whole pattern is skipped when the
    // gate closes (d <= c).
    for ap in &config.additional_patterns {
        let Ok(re) = Regex::new(&ap.pattern) else {
            continue;
        };
        let c = ceiling_ord(ap.ceiling.as_deref().unwrap_or("owned-internal"));
        if d <= c {
            continue;
        }
        for m in re.find_iter(body) {
            if claimed.insert(m.start()) {
                hits.push(Hit {
                    category: "custom",
                    snippet: m.as_str().to_string(),
                    offset: m.start(),
                    replacement: (!ap.replacement.is_empty()).then(|| ap.replacement.clone()),
                });
            }
        }
    }

    hits.sort_by_key(|h| h.offset);
    hits
}

/// Is `hit` suppressed by the allowlist? An entry with a colon is a **full
/// token** — it suppresses only a hit whose exact snippet equals it (any
/// category). A colon-free entry's meaning depends on the hit's category:
/// for `skill-id` it's a **bare namespace** — suppresses only a hit whose
/// namespace equals it (matched via the `<ns>:` prefix, so `cadence` never
/// swallows `cadence-forge:…`); for every other category (`local-path`,
/// `marketplace`, `harness-noun`, `custom`) a colon-free entry has no
/// namespace structure to prefix-match, so it suppresses a hit whose exact
/// snippet equals it (#318: a repo whose own subject matter uses one of these
/// identifiers as domain vocabulary — e.g. a tool-schema library discussing
/// `tool_input` — can allowlist that literal term without suppressing the
/// whole `harness-noun` category or a different hit like `tool_response`).
fn is_allowlisted(hit: &Hit, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| {
        if entry.contains(':') {
            entry == &hit.snippet
        } else if hit.category == "skill-id" {
            hit.snippet.starts_with(&format!("{entry}:"))
        } else {
            entry == &hit.snippet
        }
    })
}

/// Render the nudge: one `[category] snippet` line per hit, then a one-line
/// rephrasing suggestion.
fn build_message(hits: &[Hit]) -> String {
    let mut out = String::from(
        "⚠️  redact-external-content: this external post mentions internal harness vocabulary — \
         consider rephrasing before it ships:\n",
    );
    for hit in hits {
        out.push_str(&format!("  [{}] {}", hit.category, hit.snippet));
        if let Some(replacement) = &hit.replacement {
            out.push_str(&format!(" → {replacement}"));
        }
        out.push('\n');
    }
    out.push_str(
        "Suggestion: describe the behavior, not the skill/plugin ID; \
         replace local paths with a generic description.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::{make_bash, make_bash_with_cwd};

    fn run(cmd: &str) -> CheckResult {
        RedactExternalContent.run(&make_bash(cmd))
    }

    // --- Guard clause: wrong tool / non-posting commands → allow ---

    #[test]
    fn non_bash_allowed() {
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: None,
            ..Default::default()
        };
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn non_posting_command_allowed() {
        // Not a posting command — even with a skill ID present.
        assert_eq!(
            run("git checkout -b feat/cadence:attune").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn posting_command_no_body_allowed() {
        // `gh pr edit` with no --body extracts nothing.
        assert_eq!(run("gh pr edit 12 --add-label bug").outcome, Outcome::Allow);
    }

    #[test]
    fn clean_body_allowed() {
        assert_eq!(
            run("gh pr create --body \"Fixes the parser crash on empty input\"").outcome,
            Outcome::Allow
        );
    }

    // --- Body forms: each extracts and the skill ID nudges ---

    #[test]
    fn body_long_flag() {
        assert_eq!(
            run("gh pr create --body \"see cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn body_short_flag() {
        assert_eq!(
            run("gh issue create -b \"see cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn body_equals_form() {
        assert_eq!(
            run("gh pr create --body=\"see cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn commit_dash_m() {
        assert_eq!(
            run("git commit -m \"wire cadence:writing-hooks\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn commit_glued_short_m() {
        assert_eq!(
            run("git commit -m\"ran cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn commit_multiple_dash_m() {
        // The leak is in the SECOND -m; both must be scanned.
        assert_eq!(
            run("git commit -m \"clean summary\" -m \"body refs /Users/cameron/secret\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn heredoc_in_substitution() {
        // command_segments would strip this body; tokenize keeps it in the value.
        let cmd = "git commit -m \"$(cat <<'EOF'\nFixed it via cadence:debugging\nEOF\n)\"";
        assert_eq!(run(cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn body_file_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "writeup mentioning cadence:polish here").unwrap();
        let cmd = format!("gh pr create --body-file {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn body_file_short_f_dash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg.txt");
        std::fs::write(&path, "commit body about ~/.claude/settings.json").unwrap();
        let cmd = format!("git commit -F {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn body_file_unreadable_allowed() {
        // Missing file → read fails → no body → allow (fail-open).
        assert_eq!(
            run("gh pr create --body-file /nonexistent/path/body.md").outcome,
            Outcome::Allow
        );
    }

    // --- #194: read_body_file shares the #157 unbounded-read DoS shape ---

    #[cfg(unix)]
    #[test]
    fn body_file_symlink_to_dev_zero_fails_open_and_does_not_hang() {
        // The headline DoS: a `--body-file` symlinked to an endless special
        // file. read_untrusted_config rejects it on stat (not a regular
        // file), before any blocking read — this test must NOT hang.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("evil.md");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        let cmd = format!("gh pr create --body-file {}", link.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    #[cfg(unix)]
    #[test]
    fn body_file_fifo_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo.md");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("spawn mkfifo");
        assert!(status.success(), "mkfifo failed");
        let cmd = format!("gh pr create --body-file {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    #[test]
    fn body_file_oversized_fails_open() {
        // One byte over the 1 MiB cap → rejected, same as read_untrusted_config.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.md");
        std::fs::write(&path, vec![b'x'; (1024 * 1024) + 1]).unwrap();
        let cmd = format!("gh pr create --body-file {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    #[test]
    fn body_file_normal_input_unchanged() {
        // Ordinary body-file content still reads and still gets scanned —
        // the bounded reader doesn't change happy-path behavior.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "writeup mentioning cadence:polish here").unwrap();
        let cmd = format!("gh pr create --body-file {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    // --- #424: gate and extraction are scoped to the matching segment ---

    #[test]
    fn compound_line_does_not_scan_a_non_posting_sibling_body() {
        // PoC 1: the secret's value never posts anywhere, but the sibling
        // `gh pr comment` used to authorize extracting it. The posting segment
        // here is clean, so the only possible hit is the secret's body.
        assert_eq!(
            run("gh secret set NAME --body 'cadence:attune' && gh pr comment 1 -b hello").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn compound_line_does_not_read_a_non_posting_siblings_body_file() {
        // PoC 2: `gh api --body-file` is not a post, so the file it names must
        // never be opened. The fixture is loaded with a hit, so any read flips
        // the outcome to Nudge and fails loudly — this asserts zero file I/O
        // for the non-matching segment. The discriminating control is the test
        // named below, which uses the same fixture shape on a POSTING segment
        // and does nudge — so an Allow here is evidence of no read, not of a
        // scan that could never have hit:
        //   compound_line_reads_the_posting_segments_body_file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canary.md");
        std::fs::write(&path, "tripwire body naming cadence:attune").unwrap();
        let cmd = format!(
            "gh api repos/x --body-file {} && git commit -m hello",
            path.to_str().unwrap()
        );
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    #[test]
    fn compound_line_still_scans_the_posting_segment() {
        // Positive control for both PoCs: scoping must not stop a genuinely
        // posting segment in a compound line from being scanned.
        assert_eq!(
            run("git status && gh pr comment 1 -b 'see cadence:attune'").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn compound_line_reads_the_posting_segments_body_file() {
        // Positive control specifically for the file-read path: the same
        // compound shape as PoC 2, but the file belongs to the posting segment.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "writeup mentioning cadence:polish here").unwrap();
        let cmd = format!(
            "git status && gh pr create --body-file {}",
            path.to_str().unwrap()
        );
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn compound_line_with_two_posting_segments_scans_both() {
        // Scoping is per segment, not first-match — a line where BOTH segments
        // post must surface a hit from each.
        let result =
            run("gh pr comment 1 -b 'see cadence:attune' && git commit -m 'ref /Users/cameron/x'");
        assert_eq!(result.outcome, Outcome::Nudge);
        let message = result.message.as_deref().unwrap();
        assert!(
            message.contains("[skill-id] cadence:attune"),
            "expected the first segment's hit in: {message:?}"
        );
        assert!(
            message.contains("[local-path] /Users/cameron/x"),
            "expected the second segment's hit in: {message:?}"
        );
    }

    #[test]
    fn standalone_non_posting_body_flag_unchanged() {
        // The issue's original premise, kept as a regression: a standalone
        // non-posting command was already clean via the whole-command gate, and
        // must stay clean now that the gate is per segment.
        assert_eq!(
            run("gh secret set NAME --body 'cadence:attune'").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn standalone_non_posting_body_file_is_not_read() {
        // Same premise on the file path: `gh api --body-file` standalone must
        // not open the file it names.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canary.md");
        std::fs::write(&path, "tripwire body naming cadence:attune").unwrap();
        let cmd = format!("gh api repos/x --body-file {}", path.to_str().unwrap());
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    // --- Multi-line posting commands (#475) ---
    //
    // Per-segment scoping is only safe if a segment boundary means what the
    // shell means by it. A backslash-newline is a continuation, not a
    // boundary — cutting there put the posting verb in one segment and its
    // `--body`/`--body-file` in the next, so the gate failed on the segment
    // holding the body and nothing was scanned at all. Every case below is a
    // shape a person writes by hand.

    #[test]
    fn continued_body_file_is_scanned() {
        // The shape `cadence:creating-issue` MANDATES: `--body-file`, flags
        // spread across continuation lines.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "writeup naming cadence:attune").unwrap();
        let cmd = format!(
            "gh issue create --repo cameronsjo/cadence-hooks \\\n  --title \"issue title\" \\\n  --body-file {}",
            path.to_str().unwrap()
        );
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn continued_literal_body_is_scanned() {
        assert_eq!(
            run("gh pr create \\\n  --title t \\\n  --body \"see cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn continued_heredoc_in_substitution_is_scanned() {
        // The `--body "$(cat <<'EOF' … EOF)"` form, reached over a
        // continuation. The heredoc rides inside the quoted value, so
        // segmentation must neither cut at the continuation nor at the body's
        // own newlines.
        let cmd = "gh pr create \\\n  --body \"$(cat <<'EOF'\nRefactored per cadence:attune today.\nEOF\n)\"";
        assert_eq!(run(cmd).outcome, Outcome::Nudge);
    }

    #[test]
    fn continued_body_with_crlf_is_scanned() {
        assert_eq!(
            run("gh pr create \\\r\n  --body \"see cadence:attune\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn bare_newline_between_commands_still_scopes_per_command() {
        // Discriminating control for the four above: a plain newline IS a
        // boundary, so the non-posting neighbour's body stays unscanned. Were
        // continuations handled by simply not splitting on newlines, this
        // would nudge.
        assert_eq!(
            run("gh secret set NAME --body 'cadence:attune'\ngh pr comment 1 -b hello").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn escaped_quote_cannot_launder_a_body_past_the_gate() {
        // `\"` inside `"…"` is content, so the operator after it is still
        // inside the `-m` value and creates no segment boundary. When the
        // splitter disagreed with the tokenizer, the text after the operator
        // became its own non-posting segment and went unscanned.
        for op in ["&&", ";", "|"] {
            let cmd = format!("git commit -m \"he said \\\" {op} cadence:attune here\"");
            assert_eq!(run(&cmd).outcome, Outcome::Nudge, "operator {op}");
        }
    }

    #[test]
    fn later_assignment_does_not_make_the_guard_read_a_file() {
        // The shell expands `$F` before reaching the `||` branch, so this
        // command never names the canary. The guard must not either. The
        // fixture holds a hit, so any read flips the outcome and fails loudly;
        // the discriminating control is the test named below, which reads the
        // same fixture through an assignment that genuinely precedes its use:
        //   preceding_assignment_still_resolves_the_body_file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canary.md");
        std::fs::write(&path, "tripwire body naming cadence:attune").unwrap();
        let cmd = format!(
            "gh pr create --body-file $F || F={}",
            path.to_str().unwrap()
        );
        assert_eq!(run(&cmd).outcome, Outcome::Allow);
    }

    #[test]
    fn preceding_assignment_still_resolves_the_body_file() {
        // Positive control: an assignment BEFORE the use is what the shell
        // would expand, so the guard follows it and reads the file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.md");
        std::fs::write(&path, "writeup naming cadence:attune").unwrap();
        let cmd = format!(
            "F={} && gh pr create --body-file $F",
            path.to_str().unwrap()
        );
        assert_eq!(run(&cmd).outcome, Outcome::Nudge);
    }

    // --- One test per universal category ---

    #[test]
    fn category_skill_id() {
        let result = run("gh issue create --body \"calls cadence-forge:polish\"");
        assert_eq!(result.outcome, Outcome::Nudge);
        // Category tag is `skill-id` (lockstep with the `redaction` section of
        // the unified cadence config schema, schemas/cadence.json in the
        // cadence monorepo).
        assert!(
            result.message.as_deref().unwrap().contains("[skill-id]"),
            "expected the [skill-id] category tag in: {:?}",
            result.message
        );
    }

    #[test]
    fn category_local_path() {
        assert_eq!(
            run("gh pr create --body \"edit /Users/cameron/Projects/x\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn category_marketplace_path() {
        assert_eq!(
            run("gh issue create --body \"in ~/.claude/plugins/cache/workbench\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn category_harness_noun() {
        // Hermetic cwd: the bare `run()` helper resolves base_dir from the
        // process cwd, and THIS repo's own `.claude/cadence.json` allowlists
        // `tool_input`/`tool_response` — a bare-run assertion here would test
        // the host repo's config, not the engine.
        let repo = temp_repo_with_config("{}");
        let cmd = "gh pr create --body \"rename tool_input everywhere\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Nudge);
    }

    #[test]
    fn bare_harness_not_matched() {
        // #406/#564: the bare noun `harness` was deleted from the class —
        // mandated domain vocabulary in estate prose, zero true positives.
        // Hermetic cwd (empty config): a bare `run()` Allow-assertion would
        // also pass if the term were merely allowlisted in the host repo's
        // `.claude/cadence.json`, masking a reverted deletion.
        let repo = temp_repo_with_config("{}");
        let cmd = "gh pr create --body \"the test harness needs work\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn bare_transcript_not_matched() {
        // Deleted alongside `harness` (predecessor defect: #318). Hermetic
        // cwd for the same reason as `bare_harness_not_matched`.
        let repo = temp_repo_with_config("{}");
        let cmd = "gh pr create --body \"parse the transcript correctly\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn cadence_mcp_namespace_caught_specifically() {
        // `cadence-mcp:` must be caught as cadence-mcp, not bare cadence/mcp.
        let result = run("gh pr create --body \"see cadence-mcp:server\"");
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.as_deref().unwrap();
        assert!(
            msg.contains("cadence-mcp:server"),
            "expected the full cadence-mcp:server snippet in: {:?}",
            result.message
        );
        // Emitted under the `skill-id` category (lockstep with the
        // `redaction` section of the unified cadence config schema,
        // schemas/cadence.json in the cadence monorepo).
        assert!(
            msg.contains("[skill-id]"),
            "expected the [skill-id] category tag in: {:?}",
            result.message
        );
    }

    // --- False-positive guards ---

    #[test]
    fn transcription_not_matched() {
        // Harness noun inside a larger word must not fire.
        assert_eq!(
            run("git commit -m \"add audio transcription support\"").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn harnessing_not_matched() {
        assert_eq!(
            run("git commit -m \"harnessing the new API for speed\"").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn colon_in_prose_not_matched() {
        // `cadence:` followed by a space is prose, not a skill ID.
        assert_eq!(
            run("git commit -m \"improve the cadence: of the release train\"").outcome,
            Outcome::Allow
        );
    }

    // --- Per-repo .claude/cadence.json `redaction` section ---

    /// Build a temp git root whose `.claude/cadence.json` carries `section_json`
    /// as its `redaction` section (cadence-hooks#153). `section_json` is the same
    /// object the legacy `redaction.json` held; it is nested under the
    /// `redaction` key of the unified file. A malformed `section_json` stays
    /// malformed once wrapped, so fail-open cases still exercise a broken
    /// document.
    fn temp_repo_with_config(section_json: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(".claude/cadence.json"),
            format!(r#"{{"version":1,"redaction":{section_json}}}"#),
        )
        .unwrap();
        dir
    }

    #[test]
    fn allowlist_suppresses_hit() {
        let repo = temp_repo_with_config(r#"{"allowlist":["cadence:writing-skills"]}"#);
        let cmd = "gh issue create --body \"document cadence:writing-skills\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn allowlist_does_not_suppress_other_skills() {
        // Allowlisting one full token must not suppress a different one.
        let repo = temp_repo_with_config(r#"{"allowlist":["cadence:writing-skills"]}"#);
        let cmd = "gh issue create --body \"see cadence:writing-skills and cadence:attune\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("cadence:attune"));
        assert!(!msg.contains("cadence:writing-skills"));
    }

    #[test]
    fn allowlist_bare_namespace_suppresses_whole_namespace() {
        // Bare `cadence-forge` suppresses every cadence-forge:* id but leaves
        // a different namespace (`cadence:attune`) flagged.
        let repo = temp_repo_with_config(r#"{"allowlist":["cadence-forge"]}"#);
        let cmd = "gh pr create --body \"ran cadence-forge:polish then cadence:attune\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(
            msg.contains("cadence:attune"),
            "other namespace must still flag: {msg}"
        );
        assert!(
            !msg.contains("cadence-forge:polish"),
            "bare namespace must suppress its own: {msg}"
        );
    }

    #[test]
    fn allowlist_bare_namespace_does_not_swallow_longer_prefix() {
        // Bare `cadence` must NOT suppress `cadence-forge:polish` — the `<ns>:`
        // boundary means `cadence:` only matches the `cadence` namespace.
        let repo = temp_repo_with_config(r#"{"allowlist":["cadence"]}"#);
        let cmd = "gh pr create --body \"ran cadence-forge:polish\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(result.message.unwrap().contains("cadence-forge:polish"));
    }

    #[test]
    fn allowlist_bare_term_suppresses_matching_harness_noun() {
        // #318: a bare (non-namespace) allowlist entry that exactly matches a
        // harness-noun hit's own text suppresses that literal term — the
        // repo's own domain vocabulary (e.g. a tool-schema library
        // discussing `tool_input`) shouldn't read as harness leakage.
        let repo = temp_repo_with_config(r#"{"allowlist":["tool_input"]}"#);
        let cmd = "gh pr create --body \"rename tool_input everywhere\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn allowlist_bare_term_does_not_suppress_a_different_harness_noun() {
        // Allowlisting "tool_input" must not blanket-suppress the whole
        // harness-noun category — "tool_response" still flags.
        let repo = temp_repo_with_config(r#"{"allowlist":["tool_input"]}"#);
        let cmd = "gh pr create --body \"the tool_response payload changed\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Nudge);
    }

    #[test]
    fn allowlist_bare_term_suppresses_matching_local_path() {
        // The exact-match rule isn't skill-id/harness-noun-specific — it
        // applies to any non-skill-id category, e.g. a repo-specific path
        // fragment repeatedly flagged as a local-path hit.
        let repo = temp_repo_with_config(r#"{"allowlist":["/Users/alice/x"]}"#);
        let cmd = "gh pr create --body \"edit /Users/alice/x\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn additional_pattern_fires() {
        let repo = temp_repo_with_config(
            r#"{"additionalPatterns":[{"pattern":"ACME-INC","replacement":"[redacted]"}]}"#,
        );
        let cmd = "gh pr create --body \"deployed for ACME-INC today\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("ACME-INC"));
        assert!(msg.contains("[redacted]"), "replacement should show: {msg}");
    }

    #[test]
    fn missing_config_is_fail_open() {
        // A git root with no cadence.json → no custom patterns, universal
        // categories still apply.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let cmd = "gh pr create --body \"plain clean text\"";
        let input = make_bash_with_cwd(cmd, dir.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Allow);
    }

    #[test]
    fn invalid_config_is_fail_open() {
        let repo = temp_repo_with_config("{not valid json");
        // Universal scan still works despite the broken config.
        let cmd = "gh pr create --body \"see cadence:attune\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Nudge);
    }

    #[test]
    fn malformed_key_does_not_void_valid_allowlist() {
        // #536's exact shape: bare strings under additionalPatterns (the
        // struct wants objects) used to void the WHOLE redaction section, so
        // the valid allowlist beside it went inert. Lenient loading drops
        // only the malformed key; the allowlist still suppresses.
        let repo = temp_repo_with_config(
            r#"{"allowlist":["tool_input"],"additionalPatterns":["zorblax"]}"#,
        );
        let cmd = "gh pr create --body \"rename tool_input everywhere\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        // The suppression works (no harness-noun hit), and the drop is named
        // in the transcript instead of silent: outcome is a Nudge carrying
        // the config warning, not a clean Allow.
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.expect("config warning should surface");
        assert!(
            msg.contains("additionalPatterns"),
            "warning must name the dropped key: {msg}"
        );
        assert!(
            !msg.contains("[harness-noun]"),
            "allowlist must still suppress the scan hit: {msg}"
        );
    }

    #[test]
    fn config_warning_rides_along_with_scan_hits() {
        // Broken key + a real hit: one nudge carries both the hit lines and
        // the config-anomaly block.
        let repo = temp_repo_with_config(r#"{"additionalPatterns":["zorblax"]}"#);
        let cmd = "gh pr create --body \"see cadence:attune\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        let result = RedactExternalContent.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap();
        assert!(msg.contains("cadence:attune"));
        assert!(msg.contains("additionalPatterns"));
    }

    #[cfg(unix)]
    #[test]
    fn special_file_config_fails_open_and_does_not_hang() {
        // #157: a `.claude/cadence.json` symlinked to an endless special file
        // (`/dev/zero`) is rejected on stat — the loader falls open to the
        // default config and the universal scan still nudges a skill id, without
        // an unbounded read hanging the hook.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(".claude/cadence.json")).unwrap();
        let cmd = "gh pr create --body \"see cadence:attune\"";
        let input = make_bash_with_cwd(cmd, dir.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Nudge);
    }

    // --- Never blocks ---

    #[test]
    fn never_blocks() {
        // Even a body full of every category stays a nudge.
        let cmd = "gh pr create --body \"cadence:attune /Users/x ~/.claude/plugins/y tool_input\"";
        assert_ne!(run(cmd).outcome, Outcome::Block);
        assert_eq!(run(cmd).outcome, Outcome::Nudge);
    }

    // --- Audience gate (#159): d > c, driven through the pure scan_body /
    // resolve_dest_tier seam rather than process env, mirroring the reference
    // script `redact-check.sh` cases a–i. Ordinals: owned-internal=1,
    // private-external=2, public=3. Cases inlined as Rust tests (rather than a
    // shared JSON/TSV fixture) — the fixture would add setup scope with no
    // parity win here, since Rust and the bash port are separately validated.
    // A cheaper, different property — that the two sides' namespace LISTS
    // (not their full scan behavior) agree — is audited cross-sibling by
    // `tests/hook_registration_audit.rs::namespace_list_matches_redact_check_sh`. ---

    /// Parse a `redaction`-section body into a [`RedactionConfig`].
    fn cfg(json: &str) -> RedactionConfig {
        serde_json::from_str(json).expect("test config should deserialize")
    }

    /// Categories emitted by a scan at destination ordinal `d`, offset-sorted.
    fn cats(body: &str, config: &RedactionConfig, d: u8) -> Vec<&'static str> {
        scan_body(body, config, d)
            .into_iter()
            .map(|h| h.category)
            .collect()
    }

    // One line per universal category, each firing exactly once.
    const BODY_ALL: &str = "Use cadence-forge:polish. File /Users/alice/x. \
         Installed ~/.claude/plugins/cadence-forge/skill.json. The tool_input records.";
    const BODY_SKILL: &str = "Use cadence-forge:polish here.";
    const BODY_SKILL_PATH: &str = "Run cadence-forge:polish on /Users/alice/secret.txt now.";
    const BODY_ACME: &str = "Deploy for ACME-INC today.";
    const BODY_WIDGET: &str = "Partner WIDGET-CO ships it.";

    // --- The two fail-direction traps, asserted directly ---

    #[test]
    fn dest_tier_ord_fail_safe() {
        assert_eq!(dest_tier_ord("owned-internal"), 1);
        assert_eq!(dest_tier_ord("private-external"), 2);
        assert_eq!(dest_tier_ord("public"), 3);
        // `always` is config-only — never a destination — and any unknown string
        // must resolve to public(3, over-redact), never 0.
        assert_eq!(dest_tier_ord("always"), 3, "always must NOT be 0 as a dest");
        assert_eq!(dest_tier_ord("owned_internal"), 3, "typo → public");
        assert_eq!(dest_tier_ord("bogus"), 3);
    }

    #[test]
    fn ceiling_ord_fail_safe() {
        assert_eq!(ceiling_ord("always"), 0);
        assert_eq!(ceiling_ord("owned-internal"), 1);
        assert_eq!(ceiling_ord("private-external"), 2);
        assert_eq!(ceiling_ord("public"), 3);
        // Unknown/typo → owned-internal(1), NOT public — a bad ceiling must not
        // silently widen and suppress a hit.
        assert_eq!(ceiling_ord("owned_internal"), 1, "typo → owned-internal");
        assert_eq!(ceiling_ord("bogus"), 1);
    }

    // === (a) no audience → public → every universal category fires ===========
    #[test]
    fn gate_a_public_flags_all() {
        let config = RedactionConfig::default();
        assert_eq!(
            resolve_dest_tier(None, &config),
            3,
            "no env, no originAudience → public"
        );
        let got = cats(BODY_ALL, &config, 3);
        assert_eq!(
            got,
            vec!["skill-id", "local-path", "marketplace", "harness-noun"]
        );
    }

    // === (b) owned-internal → universal categories suppressed ================
    #[test]
    fn gate_b_owned_internal_suppresses_universal() {
        let config = RedactionConfig::default();
        assert!(
            cats(BODY_ALL, &config, 1).is_empty(),
            "default owned-internal ceiling suppresses every universal hit at d=1"
        );
    }

    // === (c) allowlisted skill-id suppressed at every tier (ceiling public) ==
    #[test]
    fn gate_c_allowlist_suppresses_at_every_tier() {
        let config = cfg(r#"{"allowlist":["cadence-forge"]}"#);
        assert!(cats(BODY_SKILL, &config, 3).is_empty(), "public suppressed");
        assert!(
            cats(BODY_SKILL, &config, 1).is_empty(),
            "owned-internal suppressed"
        );
        // Contrast: without the allowlist, the same skill-id fires at public.
        let bare = RedactionConfig::default();
        assert_eq!(cats(BODY_SKILL, &bare, 3), vec!["skill-id"]);
    }

    // === (d) per-category ceiling: local-path → always fires at owned-internal
    #[test]
    fn gate_d_per_category_ceiling_always() {
        let config = cfg(r#"{"categories":{"local-path":{"ceiling":"always"}}}"#);
        let got = cats(BODY_SKILL_PATH, &config, 1);
        // local-path (ceiling always, 0) fires at d=1; skill-id (default
        // owned-internal, 1) stays suppressed — the override is category-scoped.
        assert_eq!(got, vec!["local-path"]);
    }

    // === (e) custom pattern ceiling ==========================================
    #[test]
    fn gate_e_custom_pattern_ceiling() {
        let always = cfg(
            r#"{"additionalPatterns":[{"pattern":"ACME-INC","replacement":"[x]","ceiling":"always"}]}"#,
        );
        assert_eq!(
            cats(BODY_ACME, &always, 1),
            vec!["custom"],
            "always-ceiling custom fires at owned-internal"
        );
        let default_ceiling = cfg(r#"{"additionalPatterns":[{"pattern":"WIDGET-CO"}]}"#);
        assert_eq!(
            cats(BODY_WIDGET, &default_ceiling, 3),
            vec!["custom"],
            "default-ceiling custom fires at public"
        );
        assert!(
            cats(BODY_WIDGET, &default_ceiling, 1).is_empty(),
            "default-ceiling custom quiet at owned-internal"
        );
    }

    // === (g) private-external (middle tier) ==================================
    #[test]
    fn gate_g_private_external_middle_tier() {
        let bare = RedactionConfig::default();
        assert_eq!(
            cats(BODY_ALL, &bare, 2),
            vec!["skill-id", "local-path", "marketplace", "harness-noun"],
            "universal categories fire at private-external"
        );
        let custom = cfg(r#"{"additionalPatterns":[{"pattern":"WIDGET-CO"}]}"#);
        assert_eq!(
            cats(BODY_WIDGET, &custom, 2),
            vec!["custom"],
            "default-ceiling custom fires at private-external"
        );
        assert!(
            cats(BODY_WIDGET, &custom, 1).is_empty(),
            "same custom stays quiet at owned-internal"
        );
    }

    // === (h) invalid ceiling → owned-internal (not public), both call sites ==
    #[test]
    fn gate_h_invalid_ceiling_falls_to_owned_internal() {
        // Category call site: a typo'd ceiling must still flag at public.
        let cat = cfg(r#"{"categories":{"local-path":{"ceiling":"owned_internal"}}}"#);
        assert!(
            cats(BODY_SKILL_PATH, &cat, 3).contains(&"local-path"),
            "invalid category ceiling must not silently suppress at public"
        );
        // Custom call site: same fail-safe.
        let custom =
            cfg(r#"{"additionalPatterns":[{"pattern":"WIDGET-CO","ceiling":"nonsense"}]}"#);
        assert_eq!(
            cats(BODY_WIDGET, &custom, 3),
            vec!["custom"],
            "invalid custom ceiling must not silently suppress at public"
        );
    }

    // === (i) destination from config originAudience; "always" → public =======
    #[test]
    fn gate_i_origin_audience_resolution() {
        let internal = cfg(r#"{"originAudience":"owned-internal"}"#);
        assert_eq!(resolve_dest_tier(None, &internal), 1);
        assert!(
            cats(BODY_ALL, &internal, resolve_dest_tier(None, &internal)).is_empty(),
            "originAudience owned-internal suppresses the universal categories"
        );
        // The config-only `always` sentinel is NOT a destination — it must fall
        // through to public(3), never suppress every hit (the total-bypass trap).
        let always = cfg(r#"{"originAudience":"always"}"#);
        assert_eq!(
            resolve_dest_tier(None, &always),
            3,
            "originAudience=always resolves to public, not 0"
        );
        assert_eq!(
            cats(BODY_SKILL, &always, resolve_dest_tier(None, &always)),
            vec!["skill-id"]
        );
    }

    // === CADENCE_AUDIENCE env path: gated through the pure helper with an
    // explicit Some(...) arg — no std::env::set_var (process-global, flaky). ===
    #[test]
    fn gate_env_audience_wins_over_config() {
        // env owned-internal overrides a config originAudience of public.
        let config = cfg(r#"{"originAudience":"public"}"#);
        assert_eq!(
            resolve_dest_tier(Some("owned-internal"), &config),
            1,
            "CADENCE_AUDIENCE wins over config originAudience"
        );
        assert!(
            cats(
                BODY_ALL,
                &config,
                resolve_dest_tier(Some("owned-internal"), &config)
            )
            .is_empty()
        );
    }
}
