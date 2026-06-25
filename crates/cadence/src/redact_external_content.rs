//! Nudge before internal harness vocabulary leaks into an external post.
//!
//! A PreToolUse **nudge** (never a block) that scans the *body text* of
//! external-posting Bash commands — `gh pr/issue/release/gist/discussion`
//! create/comment/edit, `git commit`, `tea pr/issue` — for vocabulary that is
//! meaningful only inside this harness: skill/plugin IDs (`cadence:attune`),
//! local filesystem paths (`/Users/…`, `~/.claude/…`), marketplace/cache paths,
//! and bare harness nouns (`harness`, `transcript`, …). When it finds any, it
//! suggests rephrasing before the content ships to a public issue/PR/commit.
//!
//! ## Why a nudge, never a block (developing-guards "block vs nudge")
//!
//! There is a routine, intentional workflow that legitimately mentions these
//! terms in an external post — documenting the harness itself, an issue *about*
//! `cadence:writing-skills`, a commit that renames `tool_input`. The condition
//! is detectable but the policy is advisory, so this is a nudge. The per-repo
//! `.claude/redaction.json` `allowlist` is the escape hatch for the recurring
//! legitimate case.
//!
//! ## Body extraction (not segment-based)
//!
//! Bodies are pulled from flag VALUES via [`tokenize`] over the **raw** command
//! — deliberately NOT via [`split_segments`]/`command_segments`, which strip
//! heredoc bodies as "data" (the exact text we must scan). Because [`tokenize`]
//! keeps a quoted value as one token, a heredoc carried in a quoted command
//! substitution — `git commit -m "$(cat <<'EOF' … EOF)"` — rides into the `-m`
//! value intact, so its body lines are scanned. Only flag values are scanned,
//! so the command words/flags themselves never trip the blocklist.
//!
//! Failure is silent (`allow()`): no recognized body flag, an unreadable
//! `--body-file`, a parse miss, or no hits all proceed without a message. In
//! nudge mode, silent failure beats false positives.

use cadence_hooks_core::shell::{strip_quotes, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

/// Plugin/skill namespaces whose `<ns>:<name>` IDs are harness-internal.
///
/// A `const &[&str]` rather than a frozen regex literal so adding a new plugin
/// is a one-line edit — the [`SKILL_ID`] regex is *derived* from this list at
/// init. `mcp` is both a namespace and a prefix of `cadence-mcp`; the regex
/// builder sorts longest-first so `cadence-mcp:x` is caught as `cadence-mcp:x`,
/// not as `cadence` + leftover or bare `mcp`.
const NAMESPACES: &[&str] = &[
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

/// Category 4 — bare harness nouns. Word-boundary anchored so `transcription`
/// and `harnessing` (and the code identifier `transcript_path`, where `_` is a
/// word char) do NOT match — only the bare nouns do. `harness` is the noisiest
/// term (legit "test harness"); nudge-mode plus the per-repo `allowlist` are the
/// mitigation, not a tighter pattern.
static HARNESS_NOUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(harness|transcript|tool_input|tool_response)\b")
        .expect("harness-noun pattern should compile")
});

/// Per-repo override file, read from `<git-root>/.claude/redaction.json`.
/// Missing, unreadable, or invalid JSON all deserialize to the default (empty)
/// config — the check never errors on it (fail-open, ADR-0001).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RedactionConfig {
    /// Extra literal/regex patterns to flag, each with the replacement to show.
    #[serde(default)]
    additional_patterns: Vec<AdditionalPattern>,
    /// Tokens that suppress a hit. Two forms, by colon presence:
    /// - **full token** (`cadence:writing-skills`) → suppresses only that exact
    ///   matched snippet, in any category;
    /// - **bare namespace** (`cadence`, `cadence-forge`, `mcp`) → suppresses
    ///   every skill-id (category 1) hit whose namespace equals it; never
    ///   touches path/marketplace/harness-noun hits.
    ///
    /// The bare-namespace form lets a repo that legitimately discusses a whole
    /// namespace (the meta-repo dogfooding all cadence skills, say) allow-list it
    /// wholesale instead of enumerating every skill ID.
    #[serde(default)]
    allowlist: Vec<String>,
}

/// One `additionalPatterns[]` entry: a project-specific string to flag and the
/// replacement to suggest in the nudge.
#[derive(Debug, Deserialize)]
struct AdditionalPattern {
    pattern: String,
    #[serde(default)]
    replacement: String,
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

        // Gate: scan only commands that actually publish content. Quote-strip
        // first so a body merely mentioning `gh pr create` can't self-trip.
        if !EXTERNAL_POST.is_match(&strip_quotes(command)) {
            return CheckResult::allow();
        }

        // Phase 2 — pull body text from flag values; silent allow if none.
        let base_dir = resolve_base_dir(input);
        let bodies = extract_bodies(command, &base_dir);
        if bodies.is_empty() {
            return CheckResult::allow();
        }

        // Phase 3 — config (per-repo additional patterns + allowlist).
        let config = load_redaction_config(&base_dir);

        // Phase 4 — scan each body, collect hits.
        let mut hits: Vec<Hit> = Vec::new();
        for body in &bodies {
            hits.extend(scan_body(body, &config));
        }

        if hits.is_empty() {
            CheckResult::allow()
        } else {
            CheckResult::nudge(build_message(&hits))
        }
    }
}

/// Resolve the directory to read `.claude/redaction.json` from and to resolve a
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

/// Extract body text from a posting command's flag values.
///
/// Literal-body flags (`--body`/`-b`/`-m`/`--message`, plus their `=`-joined and
/// glued-short forms) contribute their value verbatim. File-body flags
/// (`--body-file`/`-F`) contribute the file's contents read from disk; an
/// unreadable path is silently skipped (fail-open). `tokenize` keeps a quoted
/// value as one token, so a heredoc inside `"$(cat <<EOF … EOF)"` rides into the
/// value intact. `--title`/`-t` is deliberately out of scope (the spec scans
/// bodies only).
fn extract_bodies(command: &str, base_dir: &str) -> Vec<String> {
    let tokens = tokenize(command);
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
/// `base_dir`. `None` on any error (missing, non-UTF-8, `-` for stdin) so the
/// caller fails open.
fn read_body_file(path: &str, base_dir: &str) -> Option<String> {
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(base_dir).join(p)
    };
    std::fs::read_to_string(full).ok()
}

/// Load `<git-root>/.claude/redaction.json`, walking up from `base_dir` to the
/// first ancestor containing a `.git` entry (dir or worktree file). Any failure
/// — no git root, missing/unreadable file, invalid JSON — yields the default
/// (empty) config.
fn load_redaction_config(base_dir: &str) -> RedactionConfig {
    let Some(root) = cadence_hooks_core::paths::find_git_root(base_dir) else {
        return RedactionConfig::default();
    };
    let path = root.join(".claude/redaction.json");
    let Ok(content) = std::fs::read_to_string(path) else {
        return RedactionConfig::default();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Scan one body for blocklist hits, deduped by start offset across categories,
/// then drop any hit whose exact snippet is allowlisted.
///
/// Categories are scanned skill → marketplace → local-path → harness →
/// additional; the first to claim a start offset reports it (so a single
/// `~/.claude/plugins/…` offset is reported once, as `marketplace`).
fn scan_body(body: &str, config: &RedactionConfig) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    let mut claimed: HashSet<usize> = HashSet::new();

    let universal: [(&'static str, &Regex); 4] = [
        ("skill/plugin", &SKILL_ID),
        ("marketplace", &MARKETPLACE_PATH),
        ("local-path", &LOCAL_PATH),
        ("harness-noun", &HARNESS_NOUN),
    ];
    for (category, regex) in universal {
        for m in regex.find_iter(body) {
            if claimed.insert(m.start()) {
                hits.push(Hit {
                    category,
                    snippet: m.as_str().to_string(),
                    offset: m.start(),
                    replacement: None,
                });
            }
        }
    }

    // Per-repo additional patterns — each `pattern` is treated as a regex; one
    // that fails to compile is skipped (fail-open).
    for ap in &config.additional_patterns {
        let Ok(re) = Regex::new(&ap.pattern) else {
            continue;
        };
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

    // Allowlist suppression (two forms — see [`is_allowlisted`]).
    hits.retain(|h| !is_allowlisted(h, &config.allowlist));

    hits.sort_by_key(|h| h.offset);
    hits
}

/// Is `hit` suppressed by the allowlist? An entry with a colon is a **full
/// token** — it suppresses only a hit whose exact snippet equals it (any
/// category). An entry without a colon is a **bare namespace** — it suppresses
/// only skill-id hits whose namespace equals it (matched via the `<ns>:` prefix,
/// so `cadence` never swallows `cadence-forge:…`); it never touches
/// path/marketplace/harness-noun hits.
fn is_allowlisted(hit: &Hit, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| {
        if entry.contains(':') {
            entry == &hit.snippet
        } else {
            hit.category == "skill/plugin" && hit.snippet.starts_with(&format!("{entry}:"))
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

    // --- One test per universal category ---

    #[test]
    fn category_skill_id() {
        assert_eq!(
            run("gh issue create --body \"calls cadence-forge:polish\"").outcome,
            Outcome::Nudge
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
        assert_eq!(
            run("gh pr create --body \"parse the transcript correctly\"").outcome,
            Outcome::Nudge
        );
    }

    #[test]
    fn cadence_mcp_namespace_caught_specifically() {
        // `cadence-mcp:` must be caught as cadence-mcp, not bare cadence/mcp.
        let result = run("gh pr create --body \"see cadence-mcp:server\"");
        assert_eq!(result.outcome, Outcome::Nudge);
        assert!(
            result
                .message
                .as_deref()
                .unwrap()
                .contains("cadence-mcp:server"),
            "expected the full cadence-mcp:server snippet in: {:?}",
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

    // --- Per-repo .claude/redaction.json ---

    /// Build a temp git root with a `.claude/redaction.json`, returning the root.
    fn temp_repo_with_config(json: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(".claude/redaction.json"), json).unwrap();
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
    fn allowlist_bare_namespace_only_touches_skill_ids() {
        // Bare entries apply ONLY to category 1 — a harness noun matching the
        // entry text is NOT suppressed.
        let repo = temp_repo_with_config(r#"{"allowlist":["transcript"]}"#);
        let cmd = "gh pr create --body \"parse the transcript correctly\"";
        let input = make_bash_with_cwd(cmd, repo.path().to_str().unwrap());
        assert_eq!(RedactExternalContent.run(&input).outcome, Outcome::Nudge);
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
        // A git root with no redaction.json → no custom patterns, universal
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

    // --- Never blocks ---

    #[test]
    fn never_blocks() {
        // Even a body full of every category stays a nudge.
        let cmd = "gh pr create --body \"cadence:attune /Users/x ~/.claude/plugins/y transcript\"";
        assert_ne!(run(cmd).outcome, Outcome::Block);
        assert_eq!(run(cmd).outcome, Outcome::Nudge);
    }
}
