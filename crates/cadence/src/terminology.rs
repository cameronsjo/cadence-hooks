//! Block inclusive terminology violations in written content.
//!
//! Detects prohibited terms and suggests neutral alternatives.
//! Case-insensitive with word-boundary matching to avoid false positives.

use cadence_hooks_core::paths::{find_git_root, is_within, resolve_git_common_dir};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use glob::{MatchOptions, Pattern};
use regex::RegexSet;
use serde::Deserialize;
use std::path::Path;
use std::sync::LazyLock;

// NOTE: This file contains prohibited terms as detection patterns.
// It must be excluded from the terminology hook's own scanning.

/// Build a prohibited term from parts to avoid triggering the hook on source.
macro_rules! term {
    ($($part:expr),+) => { concat!($($part),+) }
}

/// Blocked terms: (display_term, regex_pattern, replacement).
///
/// Patterns use left word boundary + suffix alternation to catch derived forms
/// (plurals, past tense, gerunds) without false positives from substrings.
/// Tier 1: Hard blocks — almost never legitimate in code/tech writing.
const BLOCK_VIOLATIONS: &[(&str, &str, &str)] = &[
    (
        term!("white", "list"),
        r"(?i)\bwhitelist(s|ed|ing)?\b",
        "allowlist",
    ),
    (
        term!("black", "list"),
        r"(?i)\bblacklist(s|ed|ing)?\b",
        "blocklist, denylist",
    ),
    (
        term!("master", " branch"),
        r"(?i)\bmaster\s+branch(es)?\b",
        "main branch",
    ),
    (
        term!("master", " node"),
        r"(?i)\bmaster\s+node(s)?\b",
        "primary node, leader node",
    ),
    (
        term!("sla", "ve"),
        r"(?i)\bslave(s|d|ry)?\b",
        "replica, follower, secondary",
    ),
    (
        term!("sanity", " check"),
        r"(?i)\bsanity\s+check(s|ing)?\b",
        "validation check, confidence check, smoke test",
    ),
    (
        term!("dummy", " value"),
        r"(?i)\bdummy\s+value(s)?\b",
        "placeholder value, sample value, mock value",
    ),
];

/// Tier 2: Nudges — legitimate in prose, legal, and family contexts.
const NUDGE_VIOLATIONS: &[(&str, &str, &str)] = &[(
    term!("grand", "fathered"),
    r"(?i)\bgrandfather(ed|ing)?\b",
    "legacy status, exempted, inherited",
)];

static BLOCK_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<&str> = BLOCK_VIOLATIONS
        .iter()
        .map(|(_, pattern, _)| *pattern)
        .collect();
    RegexSet::new(&patterns).expect("block terminology patterns should compile")
});

static NUDGE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<&str> = NUDGE_VIOLATIONS
        .iter()
        .map(|(_, pattern, _)| *pattern)
        .collect();
    RegexSet::new(&patterns).expect("nudge terminology patterns should compile")
});

/// Result of checking content for terminology violations.
pub struct TerminologyResult {
    /// Terms that must be blocked (tier 1).
    pub blocks: Vec<(String, String)>,
    /// Terms that should be nudged (tier 2).
    pub nudges: Vec<(String, String)>,
}

/// Check content for inclusive terminology violations.
/// Returns block-tier and nudge-tier violations separately.
pub fn check_terminology(content: &str) -> TerminologyResult {
    let block_matches = BLOCK_PATTERNS.matches(content);
    let nudge_matches = NUDGE_PATTERNS.matches(content);

    let blocks: Vec<(String, String)> = block_matches
        .iter()
        .map(|idx| {
            let (term, _, replacement) = BLOCK_VIOLATIONS[idx];
            (term.to_string(), replacement.to_string())
        })
        .collect();

    let nudges: Vec<(String, String)> = nudge_matches
        .iter()
        .map(|idx| {
            let (term, _, replacement) = NUDGE_VIOLATIONS[idx];
            (term.to_string(), replacement.to_string())
        })
        .collect();

    TerminologyResult { blocks, nudges }
}

/// Paths that legitimately contain prohibited terms: this repo's own source,
/// hook scripts, rules files, and CLAUDE.md docs.
///
/// Anchored to `/`-split path *components*, not bare substrings. The old
/// `path.contains("cadence-hooks/")` (and the `.claude/hooks|rules` and
/// `ends_with("claude.md")` arms) handed a terminology free pass to any path
/// that merely *contained* the fragment — an unrelated sibling repo
/// (`legacy-cadence-hooks/`), a scratch dir, or a spoofed segment
/// (`x.claude/hooks/`, `evilclaude.md`) — trivially self-grantable (#91).
/// Component matching closes those over-matches. The `cadence-hooks` arm is
/// further gated on the *active checkout* (`cwd`): a bare `cadence-hooks`
/// component no longer self-grants the exemption — the edit must target a file
/// inside the current checkout, and that checkout must genuinely be the
/// cadence-hooks repo (identified by its primary-checkout dir name via the git
/// common dir). This closes the `mkdir /tmp/cadence-hooks` + doc self-grant (#139).
fn is_excluded_path(path: &str, cwd: Option<&str>) -> bool {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();

    // CLAUDE.md (any case) — basename only, so `evilclaude.md` does not match.
    if components
        .last()
        .is_some_and(|name| name.eq_ignore_ascii_case("claude.md"))
    {
        return true;
    }

    // `cadence-hooks` repo source — only when the edit targets a file inside the
    // ACTIVE checkout and that checkout is genuinely the cadence-hooks repo. The
    // repo is identified by its PRIMARY checkout dir name via the git common dir
    // (`resolve_git_common_dir().parent().file_name()`), so the exemption still
    // works for linked worktrees (whose own dir isn't named cadence-hooks) and
    // rejects unrelated repos merely nested under a cadence-hooks-named ancestor.
    // Every failure path falls through to `false` → the block stands (fail-safe).
    // Canonicalize before naming the primary checkout: a linked worktree's common
    // dir is `<primary>/.git/worktrees/wt/../..`, and `Path::file_name` returns
    // None for a `..`-terminated path — so the raw parent name would miss the
    // worktree case. The dir exists (resolve_git_common_dir verified HEAD), so
    // canonicalize succeeds; every failure path short-circuits to a block.
    if let Some(cwd) = cwd
        && let Some(root) = find_git_root(cwd)
        && is_within(path, &root)
        && let Some(common) = resolve_git_common_dir(&root)
        && let Ok(canon) = std::fs::canonicalize(&common)
        && canon
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == "cadence-hooks")
    {
        return true;
    }

    // Consecutive `.claude` then `hooks`/`rules` components, so `x.claude/hooks`
    // and `foo.claude/rules` (non-boundary, decorated) do not match.
    components
        .windows(2)
        .any(|w| w[0] == ".claude" && (w[1] == "hooks" || w[1] == "rules"))
}

/// Remove violations that were already present in pre-existing content.
///
/// For Edit tool calls, a flagged term that appears in both `old_string` and
/// `new_string` is surrounding context being carried through the edit, not
/// new content — only *introduced* violations should fire.
fn subtract_existing(
    found: Vec<(String, String)>,
    existing: &[(String, String)],
) -> Vec<(String, String)> {
    found
        .into_iter()
        .filter(|item| !existing.contains(item))
        .collect()
}

/// Per-repo terminology exemptions, read from the `terminology` section of
/// `<git-root>/.claude/cadence.json` (cadence-hooks#153).
///
/// Softens the hard block for named files/terms — it can only ever *remove* or
/// *demote* a violation, never add one. Missing file, unreadable, invalid JSON,
/// or an absent section all deserialize to the default (empty) config; the
/// guard never errors on it (fail-open, ADR-0001).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TerminologyConfig {
    #[serde(default)]
    exemptions: Vec<Exemption>,
}

/// One exemption entry: which paths it covers, which flagged terms it exempts,
/// and how much it softens them.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Exemption {
    /// Glob patterns. A pattern containing `/` matches the **repo-relative**
    /// path (`**` spans separators, `*` does not); a bare pattern (no `/`)
    /// matches the **basename** in any directory.
    #[serde(default)]
    paths: Vec<String>,
    /// Flagged terms to exempt, matched case-insensitively against the guard's
    /// display term (e.g. the seven block labels plus the nudge label). Empty or
    /// omitted exempts *all* flagged terms at the matched path; an unknown string
    /// simply never matches.
    #[serde(default)]
    terms: Vec<String>,
    /// `allow` (default) drops the violation silently; `nudge` demotes a Tier-1
    /// block to a Tier-2 advisory so a visible reminder remains.
    #[serde(default)]
    mode: ExemptionMode,
}

/// How an exemption softens a matched violation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExemptionMode {
    /// Drop the violation entirely (silent).
    #[default]
    Allow,
    /// Demote a block to an advisory nudge (exit 0, never blocks).
    Nudge,
}

/// Glob options for `/`-bearing patterns: `*` stops at `/`, `**` crosses it —
/// gitignore-style. Case-sensitive; a leading dot is not treated specially.
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

impl Exemption {
    /// Does this entry cover `rel_path` (repo-relative) / `basename`?
    fn matches_path(&self, rel_path: &str, basename: &str) -> bool {
        self.paths.iter().any(|p| glob_match(p, rel_path, basename))
    }

    /// Does this entry exempt `term`? Empty `terms` exempts every flagged term;
    /// otherwise a case-insensitive match against the display term.
    fn matches_term(&self, term: &str) -> bool {
        self.terms.is_empty() || self.terms.iter().any(|t| t.eq_ignore_ascii_case(term))
    }
}

impl TerminologyConfig {
    /// First exemption (document order) matching both the path and the term.
    fn first_match(&self, rel_path: &str, basename: &str, term: &str) -> Option<&Exemption> {
        self.exemptions
            .iter()
            .find(|e| e.matches_path(rel_path, basename) && e.matches_term(term))
    }
}

/// Match one glob `pattern`. A pattern containing `/` is matched against the
/// repo-relative path (with [`MATCH_OPTIONS`] so `**` spans separators); a bare
/// pattern is matched against the basename. An uncompilable pattern never
/// matches (fail-open).
fn glob_match(pattern: &str, rel_path: &str, basename: &str) -> bool {
    let Ok(pat) = Pattern::new(pattern) else {
        return false;
    };
    if pattern.contains('/') {
        pat.matches_with(rel_path, MATCH_OPTIONS)
    } else {
        pat.matches(basename)
    }
}

/// Load this guard's `terminology` section from the unified
/// `<root>/.claude/cadence.json` (cadence-hooks#153). Missing file, unreadable,
/// invalid JSON, or an absent section all yield the default (empty) config
/// (fail-open, ADR-0001). The legacy `.claude/terminology.json` is no longer
/// read — a hard cut; `cadence-hooks migrate-config` converts a repo and
/// `cadence-hooks doctor` warns on an orphaned legacy file.
fn load_terminology_config(root: &Path) -> TerminologyConfig {
    cadence_hooks_core::config::load_cadence_section(root, "terminology")
}

/// Apply per-repo `.claude/cadence.json` `terminology` softening to the accumulated
/// violations, in place. `allow`-mode exemptions drop a block; `nudge`-mode
/// exemptions demote a block to a nudge; any matching exemption drops a
/// pre-existing nudge (already advisory). The git root is found by walking up
/// from the file's directory; no git root or no exemptions leaves both vectors
/// untouched. Only ever removes or demotes — never adds a violation.
fn apply_exemptions(
    file_path: &str,
    blocks: &mut Vec<(String, String)>,
    nudges: &mut Vec<(String, String)>,
) {
    let start_dir = Path::new(file_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let Some(root) = cadence_hooks_core::paths::find_git_root(&start_dir) else {
        return;
    };
    let config = load_terminology_config(&root);
    if config.exemptions.is_empty() {
        return;
    }

    let rel_path = Path::new(file_path)
        .strip_prefix(&root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| file_path.to_string());
    let basename = Path::new(file_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Pre-existing nudges first: any matching exemption drops them. Run before
    // demotion below so a freshly-demoted block is not immediately re-dropped.
    nudges.retain(|(term, _)| config.first_match(&rel_path, &basename, term).is_none());

    // Blocks: allow drops; nudge demotes (collected, then appended).
    let mut demoted: Vec<(String, String)> = Vec::new();
    blocks.retain(|item| {
        match config
            .first_match(&rel_path, &basename, &item.0)
            .map(|e| e.mode)
        {
            Some(ExemptionMode::Allow) => false,
            Some(ExemptionMode::Nudge) => {
                demoted.push(item.clone());
                false
            }
            None => true,
        }
    });
    for d in demoted {
        if !nudges.contains(&d) {
            nudges.push(d);
        }
    }
}

/// Blocks content containing prohibited terminology and suggests alternatives.
pub struct TerminologyGuard;

impl Check for TerminologyGuard {
    fn name(&self) -> &str {
        "terminology-guard"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        // edit_fragments() yields one (introduced, removed) pair for Write/Edit
        // and one per edits[] element for MultiEdit — so MultiEdit is inspected
        // instead of waved through `content()`'s None early-allow (#83).
        let Some(fragments) = input.edit_fragments() else {
            return CheckResult::allow();
        };

        if let Some(ref path) = input.file_path()
            && is_excluded_path(path, input.cwd.as_deref())
        {
            return CheckResult::allow();
        }

        // Per-edit introduced-vs-existing diff, accumulated and deduped. Only
        // violations *introduced* by this call fire; a term carried through
        // (present in an edit's old_string) is pre-existing context, not new
        // content (#63). Folding per-edit — not over a concatenated document —
        // keeps each edit's subtraction scoped and stops a phrase pattern
        // matching across an edit boundary.
        let mut blocks: Vec<(String, String)> = Vec::new();
        let mut nudges: Vec<(String, String)> = Vec::new();
        for (new_text, old_text) in &fragments {
            let mut found = check_terminology(new_text);
            if !old_text.is_empty() {
                let existing = check_terminology(old_text);
                found.blocks = subtract_existing(found.blocks, &existing.blocks);
                found.nudges = subtract_existing(found.nudges, &existing.nudges);
            }
            for b in found.blocks {
                if !blocks.contains(&b) {
                    blocks.push(b);
                }
            }
            for n in found.nudges {
                if !nudges.contains(&n) {
                    nudges.push(n);
                }
            }
        }

        // Per-repo `.claude/cadence.json` `terminology` softening — only when there's a
        // violation to soften and we know the file path (so a clean edit never
        // touches disk). The hardcoded is_excluded_path() baseline above still
        // applies; this only ever removes or demotes a violation, never adds one.
        if (!blocks.is_empty() || !nudges.is_empty())
            && let Some(ref path) = input.file_path()
        {
            apply_exemptions(path, &mut blocks, &mut nudges);
        }

        // Tier 1: hard block
        if !blocks.is_empty() {
            let mut msg = String::new();
            msg.push_str("🚫 BLOCKED: Inclusive terminology violation detected");
            if let Some(ref path) = input.file_path() {
                msg.push_str(&format!(" in {path}"));
            }
            msg.push_str("\n\nFound prohibited terms:\n");

            for (term, _) in &blocks {
                msg.push_str(&format!("  - \"{term}\"\n"));
            }

            msg.push_str("\nRequired alternatives:\n");
            for (term, replacement) in &blocks {
                msg.push_str(&format!("  {term} → {replacement}\n"));
            }

            return CheckResult::block(msg);
        }

        // Tier 2: nudge (advisory)
        if !nudges.is_empty() {
            let mut msg = String::new();
            msg.push_str("⚠️  Terminology nudge");
            if let Some(ref path) = input.file_path() {
                msg.push_str(&format!(" in {path}"));
            }
            msg.push_str(" — consider alternatives if technical context:\n");
            for (term, replacement) in &nudges {
                msg.push_str(&format!("  {term} → {replacement}\n"));
            }

            return CheckResult::nudge(msg);
        }

        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_content_passes() {
        let r = check_terminology("use the allowlist for filtering");
        assert!(r.blocks.is_empty() && r.nudges.is_empty());
    }

    #[test]
    fn detects_prohibited_term() {
        let r = check_terminology(BLOCK_VIOLATIONS[0].0);
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "allowlist");
    }

    #[test]
    fn detects_whitelist_derived_forms() {
        for form in ["whitelists", "whitelisted", "whitelisting"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "allowlist");
        }
    }

    #[test]
    fn detects_blacklist_derived_forms() {
        for form in ["blacklists", "blacklisted", "blacklisting"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "blocklist, denylist");
        }
    }

    #[test]
    fn detects_slave_derived_forms() {
        for form in ["slaves", "slaved", "slavery"] {
            let r = check_terminology(form);
            assert_eq!(r.blocks.len(), 1, "should detect '{form}'");
            assert_eq!(r.blocks[0].1, "replica, follower, secondary");
        }
    }

    #[test]
    fn detects_sanity_check_plural() {
        let r = check_terminology("sanity checks");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(
            r.blocks[0].1,
            "validation check, confidence check, smoke test"
        );
    }

    #[test]
    fn detects_sanity_checking() {
        let r = check_terminology("sanity checking");
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn detects_dummy_values_plural() {
        let r = check_terminology("dummy values");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "placeholder value, sample value, mock value");
    }

    #[test]
    fn detects_grandfather_forms_as_nudge() {
        for form in ["grandfather", "grandfathered", "grandfathering"] {
            let r = check_terminology(form);
            assert!(r.blocks.is_empty(), "grandfather should not block");
            assert_eq!(r.nudges.len(), 1, "should nudge on '{form}'");
            assert_eq!(r.nudges[0].1, "legacy status, exempted, inherited");
        }
    }

    #[test]
    fn detects_master_branch_plural() {
        let r = check_terminology("master branches");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "main branch");
    }

    #[test]
    fn detects_master_nodes_plural() {
        let r = check_terminology("master nodes");
        assert_eq!(r.blocks.len(), 1);
        assert_eq!(r.blocks[0].1, "primary node, leader node");
    }

    #[test]
    fn case_insensitive_detection() {
        let upper = BLOCK_VIOLATIONS[0].0.to_uppercase();
        let r = check_terminology(&upper);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn multiple_violations_detected() {
        let input = format!("{} and {}", BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[1].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 2);
    }

    #[test]
    fn excluded_paths_allowed() {
        // CLAUDE.md basename and `.claude/hooks` dirs are cwd-independent.
        assert!(is_excluded_path("/project/CLAUDE.md", None));
        assert!(is_excluded_path(
            "/home/dev/.claude/hooks/enforcement/foo.sh",
            None
        ));
        assert!(!is_excluded_path("/project/src/main.rs", None));
    }

    // --- #91: component-anchored exclusion (no substring free pass) ---

    #[test]
    fn sibling_repo_substring_not_excluded() {
        // `legacy-cadence-hooks` contains the substring but is not a component.
        assert!(!is_excluded_path(
            "/home/dev/legacy-cadence-hooks/notes.md",
            None
        ));
    }

    #[test]
    fn spoofed_claude_hooks_segment_not_excluded() {
        assert!(!is_excluded_path("/tmp/x.claude/hooks/y.md", None));
        assert!(!is_excluded_path("/tmp/foo.claude/rules/y.md", None));
    }

    #[test]
    fn evilclaude_basename_not_excluded() {
        assert!(!is_excluded_path("/tmp/evilclaude.md", None));
    }

    #[test]
    fn claude_md_basename_still_excluded() {
        assert!(is_excluded_path("/project/CLAUDE.md", None));
        assert!(is_excluded_path("/project/sub/claude.md", None)); // case-insensitive
    }

    #[test]
    fn dot_claude_dirs_still_excluded() {
        // `.claude/hooks` and `.claude/rules` remain exempt regardless of cwd.
        assert!(is_excluded_path(
            "/home/dev/.claude/hooks/enforcement/x.sh",
            None
        ));
        assert!(is_excluded_path(
            "/home/dev/.claude/rules/terminology.md",
            None
        ));
    }

    // --- #139: cadence-hooks exemption scoped to the active checkout ---
    //
    // The exemption fires only when the edit targets a file inside the current
    // checkout AND that checkout is genuinely the cadence-hooks repo (its primary
    // checkout dir is named `cadence-hooks`). A bare `cadence-hooks` path
    // component no longer self-grants. These drive `TerminologyGuard.run` with a
    // real temp git root so the checkout resolution runs end-to-end.

    /// A temp git root whose checkout dir is literally named `cadence-hooks`,
    /// with a real `.git/HEAD` so `resolve_git_common_dir` classifies it. Returns
    /// the outer TempDir (keep it alive) and the `cadence-hooks` root path.
    fn temp_cadence_hooks_repo() -> (tempfile::TempDir, std::path::PathBuf) {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("cadence-hooks");
        let git = root.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        (outer, root)
    }

    /// A Write HookInput for `target` (created on disk) with `content` and `cwd`.
    fn write_with_cwd(target: &std::path::Path, content: &str, cwd: &str) -> HookInput {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(target.to_string_lossy().into_owned()),
                content: Some(content.into()),
                ..Default::default()
            }),
            cwd: Some(cwd.into()),
            ..Default::default()
        }
    }

    #[test]
    fn exempt_inside_real_cadence_hooks_checkout() {
        // (a) acceptance: a flagged literal in a file inside the real checkout,
        // with cwd = that checkout, is exempt → Allow.
        let (_outer, root) = temp_cadence_hooks_repo();
        let target = root.join("crates/cadence/src/foo.rs");
        let input = write_with_cwd(&target, BLOCK_VIOLATIONS[0].0, &root.to_string_lossy());
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn closed_bypass_cadence_hooks_component_outside_cwd() {
        // (b) acceptance — the exact #139 self-grant: a doc under a
        // `cadence-hooks`-named dir that is NOT inside the active checkout. cwd is
        // an unrelated real git repo → is_within fails → no exemption → Block.
        let unrelated = temp_repo_no_config();
        let elsewhere = tempfile::tempdir().unwrap();
        let bypass_target = elsewhere.path().join("cadence-hooks/x.md");
        let input = write_with_cwd(
            &bypass_target,
            BLOCK_VIOLATIONS[0].0,
            &unrelated.path().to_string_lossy(),
        );
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn no_cwd_cadence_hooks_component_not_exempt() {
        // cwd None + a `cadence-hooks` path component → no checkout to consult →
        // the exemption cannot fire → Block.
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/cadence-hooks/x.md".into()),
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn non_repo_cwd_not_exempt() {
        // cwd is a real dir with no `.git` ancestor → find_git_root None → Block,
        // even though the target carries a `cadence-hooks` component.
        let plain = tempfile::tempdir().unwrap();
        let target = plain.path().join("cadence-hooks/x.md");
        let input = write_with_cwd(
            &target,
            BLOCK_VIOLATIONS[0].0,
            &plain.path().to_string_lossy(),
        );
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn linked_worktree_of_cadence_hooks_still_exempt() {
        // A linked worktree whose OWN dir is not named cadence-hooks resolves to
        // the primary checkout (named cadence-hooks) via the git common dir → the
        // exemption is retained for worktrees.
        let outer = tempfile::tempdir().unwrap();
        let primary_git = outer.path().join("cadence-hooks").join(".git");
        std::fs::create_dir_all(&primary_git).unwrap();
        std::fs::write(primary_git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let admin = primary_git.join("worktrees").join("wt");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(admin.join("HEAD"), "ref: refs/heads/feat\n").unwrap();
        std::fs::write(admin.join("commondir"), "../..\n").unwrap();

        let linked = outer.path().join("wt-feature");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(
            linked.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .unwrap();

        let target = linked.join("crates/cadence/src/foo.rs");
        let input = write_with_cwd(&target, BLOCK_VIOLATIONS[0].0, &linked.to_string_lossy());
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Allow
        );
    }

    #[test]
    fn is_within_rejects_traversal_target_for_exemption() {
        // A `..`-traversal target inside the real checkout is rejected by
        // is_within → the exemption cannot fire → Block (defense in depth).
        let (_outer, root) = temp_cadence_hooks_repo();
        let traversal = format!("{}/../cadence-hooks/x.md", root.to_string_lossy());
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(traversal),
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                ..Default::default()
            }),
            cwd: Some(root.to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn run_blocks_violation_in_sibling_repo() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/legacy-cadence-hooks/notes.md".into()),
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            TerminologyGuard.run(&input).outcome,
            cadence_hooks_core::Outcome::Block
        );
    }

    #[test]
    fn blocks_on_violation_in_normal_file() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/main.rs".into()),
                path: None,
                command: None,
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Unhappy path: bypass scenarios ---

    #[test]
    fn word_boundary_prevents_substring_match() {
        // "listed" contains "list" but word boundary should prevent match
        assert!(
            check_terminology("the items are listed here")
                .blocks
                .is_empty()
        );
    }

    #[test]
    fn plural_form_detected() {
        let r = check_terminology(&format!("{}s", BLOCK_VIOLATIONS[0].0));
        assert_eq!(r.blocks.len(), 1, "plural form should be detected");
    }

    #[test]
    fn all_violations_detectable() {
        for (term, _, _) in BLOCK_VIOLATIONS.iter().chain(NUDGE_VIOLATIONS.iter()) {
            let r = check_terminology(term);
            assert!(
                !r.blocks.is_empty() || !r.nudges.is_empty(),
                "term '{}' should be detected",
                term
            );
        }
    }

    #[test]
    fn empty_content_passes() {
        assert!({
            let r = check_terminology("");
            r.blocks.is_empty() && r.nudges.is_empty()
        });
    }

    #[test]
    fn no_content_returns_allow() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/main.rs".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn excluded_path_with_violations_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/rules/terminology.md".into()),
                path: None,
                command: None,
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn block_message_includes_path() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/config.rs".into()),
                path: None,
                command: None,
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("config.rs"));
    }

    #[test]
    fn mixed_case_detection() {
        // Test mixed case that isn't just all upper or all lower
        let term = BLOCK_VIOLATIONS[0].0;
        let mixed: String = term
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        let r = check_terminology(&mixed);
        assert_eq!(r.blocks.len(), 1);
    }

    // --- additional edge cases ---

    #[test]
    fn violation_with_punctuation() {
        // Term followed by punctuation should still match (word boundary at comma)
        let input = format!("{}, which we use daily", BLOCK_VIOLATIONS[0].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn violation_at_line_start() {
        let input = format!("{} is configured", BLOCK_VIOLATIONS[0].0);
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn repeated_term_counted_once() {
        // RegexSet reports each pattern once, not per-occurrence
        let input = format!(
            "{} and also {} again",
            BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[0].0
        );
        let r = check_terminology(&input);
        assert_eq!(r.blocks.len(), 1);
    }

    #[test]
    fn no_path_allows_run() {
        // No file_path but content has violation — should still block
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: None,
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn multiple_violations_in_run() {
        let content = format!("{} and {}", BLOCK_VIOLATIONS[0].0, BLOCK_VIOLATIONS[1].0);
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/config.rs".into()),
                path: None,
                command: None,
                content: Some(content),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(BLOCK_VIOLATIONS[0].0));
        assert!(msg.contains(BLOCK_VIOLATIONS[1].0));
    }

    #[test]
    fn settings_json_not_excluded() {
        // settings.json is NOT an excluded path
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/home/dev/.claude/settings.json".into()),
                path: None,
                command: None,
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- Edit tool: only introduced violations fire (#63) ---

    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit};

    #[test]
    fn edit_with_preexisting_term_in_context_allowed() {
        // The flagged term appears in both old_string and new_string — it is
        // pre-existing file content carried through the edit, not new content.
        let term = BLOCK_VIOLATIONS[0].0;
        let input = make_edit(
            "/project/src/config.rs",
            &format!("{term} setting\nvalue = 1"),
            &format!("{term} setting\nvalue = 2"),
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn edit_introducing_term_blocks() {
        // The flagged term appears only in new_string — this edit introduces it.
        let term = BLOCK_VIOLATIONS[0].0;
        let input = make_edit(
            "/project/src/config.rs",
            "value = 1",
            &format!("value = 2 // uses the {term}"),
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn edit_with_preexisting_nudge_term_allowed() {
        let term = NUDGE_VIOLATIONS[0].0;
        let input = make_edit(
            "/project/docs/policy.md",
            &format!("{term} clause, v1"),
            &format!("{term} clause, v2"),
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn edit_introducing_one_term_reports_only_that_term() {
        // old context has term A; new content keeps term A and adds term B —
        // only B should be reported.
        let term_a = BLOCK_VIOLATIONS[0].0;
        let term_b = BLOCK_VIOLATIONS[1].0;
        let input = make_edit(
            "/project/src/config.rs",
            &format!("{term_a} config"),
            &format!("{term_a} config and {term_b}"),
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains(term_b));
        assert!(!msg.contains(&format!("\"{term_a}\"")));
    }

    #[test]
    fn write_with_term_still_blocks() {
        // Write behavior is unchanged: no old_string, so every violation fires.
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/project/src/main.rs".into()),
                content: Some(BLOCK_VIOLATIONS[0].0.to_string()),
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    // --- MultiEdit: edits[] folded per-edit, same #63 semantics (#83) ---

    #[test]
    fn multi_edit_introducing_term_blocks() {
        // A MultiEdit whose new_string introduces a prohibited term must block —
        // it would silently pass through content()'s None early-allow before #83.
        let term = BLOCK_VIOLATIONS[0].0;
        let input = make_multi_edit(
            "/project/src/config.rs",
            &[
                ("fn a() {}", "fn a() { /* tidy */ }"),
                ("value = 1", &format!("value = 2 // uses the {term}")),
            ],
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains(term));
    }

    #[test]
    fn multi_edit_carried_through_term_allowed() {
        // Term present in BOTH old and new of one edit = pre-existing context
        // carried through — #63 parity, folded per-edit.
        let term = BLOCK_VIOLATIONS[0].0;
        let input = make_multi_edit(
            "/project/src/config.rs",
            &[(&format!("{term} setting v1"), &format!("{term} setting v2"))],
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn multi_edit_removing_term_not_blamed() {
        // Term only in old_string (the edit REMOVES it) → not falsely blamed.
        let term = BLOCK_VIOLATIONS[0].0;
        let input = make_multi_edit(
            "/project/src/config.rs",
            &[(&format!("use the {term} here"), "use the allowlist here")],
        );
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Per-repo .claude/cadence.json `terminology` exemptions ---
    //
    // The loader reads the `terminology` section of `<git-root>/.claude/cadence.json`
    // from disk (cadence-hooks#153), so these tests build a real temp git root and
    // address the written file by an absolute path inside it. Flagged terms are
    // taken from BLOCK_VIOLATIONS (never spelled as literals) so the config JSON
    // carries no hardcoded term.

    use cadence_hooks_core::Outcome;
    use std::path::PathBuf;

    /// A temp git root whose `.claude/cadence.json` carries `section_json` as its
    /// `terminology` section. `section_json` is the same object the legacy
    /// `terminology.json` held (e.g. `{"exemptions":[…]}`); it is nested under
    /// the `terminology` key of the unified file. A malformed `section_json`
    /// stays malformed once wrapped, so fail-open cases still exercise a broken
    /// document.
    fn temp_repo(section_json: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(".claude/cadence.json"),
            format!(r#"{{"version":1,"terminology":{section_json}}}"#),
        )
        .unwrap();
        dir
    }

    /// A temp git root with NO cadence.json (config-absent baseline).
    fn temp_repo_no_config() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        dir
    }

    /// A Write HookInput targeting `path` (created on disk so a nested `path`'s
    /// directory exists for the relative-path computation) with `content`.
    fn write_at(root: &std::path::Path, rel: &str, content: &str) -> HookInput {
        let full = root.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some(full.to_string_lossy().into_owned()),
                content: Some(content.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn outcome(input: &HookInput) -> Outcome {
        TerminologyGuard.run(input).outcome
    }

    // -- Pure match-logic units (no disk) --

    #[test]
    fn glob_match_basename_pattern_ignores_dir() {
        // A bare pattern matches the basename anywhere in the tree.
        assert!(glob_match(
            "silly-file.yml",
            "a/b/silly-file.yml",
            "silly-file.yml"
        ));
        assert!(glob_match(
            "silly-file.yml",
            "silly-file.yml",
            "silly-file.yml"
        ));
        assert!(!glob_match("silly-file.yml", "a/other.yml", "other.yml"));
    }

    #[test]
    fn glob_match_slash_pattern_is_repo_relative() {
        assert!(glob_match("config/**", "config/acl.yml", "acl.yml"));
        assert!(glob_match("config/**", "config/sub/acl.yml", "acl.yml"));
        assert!(!glob_match("config/**", "other/acl.yml", "acl.yml"));
    }

    #[test]
    fn glob_match_star_does_not_cross_separator() {
        // `*` stops at `/`; `**` is required to span directories.
        assert!(glob_match("config/*.yml", "config/acl.yml", "acl.yml"));
        assert!(!glob_match("config/*.yml", "config/sub/acl.yml", "acl.yml"));
        assert!(glob_match(
            "**/firewall-*.yaml",
            "net/firewall-a.yaml",
            "firewall-a.yaml"
        ));
    }

    #[test]
    fn glob_match_invalid_pattern_never_matches() {
        // An uncompilable glob fails open (matches nothing).
        assert!(!glob_match("[", "x", "x"));
    }

    #[test]
    fn matches_term_is_case_insensitive_and_blanket() {
        let term = BLOCK_VIOLATIONS[0].0;
        let listed = Exemption {
            paths: vec![],
            terms: vec![term.to_uppercase()],
            mode: ExemptionMode::Allow,
        };
        assert!(listed.matches_term(term));
        assert!(!listed.matches_term(BLOCK_VIOLATIONS[1].0));

        let blanket = Exemption {
            paths: vec![],
            terms: vec![],
            mode: ExemptionMode::Allow,
        };
        assert!(blanket.matches_term(term));
        assert!(blanket.matches_term(BLOCK_VIOLATIONS[1].0));
    }

    // -- run() integration (real temp git root) --

    #[test]
    fn no_config_leaves_block_unchanged() {
        // Config absent → a violation in a normal file still blocks.
        let repo = temp_repo_no_config();
        let input = write_at(repo.path(), "src/main.rs", BLOCK_VIOLATIONS[0].0);
        assert_eq!(outcome(&input), Outcome::Block);
    }

    #[test]
    fn allow_exemption_drops_block() {
        let term = BLOCK_VIOLATIONS[0].0;
        let json = format!(r#"{{"exemptions":[{{"paths":["acl.yml"],"terms":["{term}"]}}]}}"#);
        let repo = temp_repo(&json);
        let input = write_at(repo.path(), "acl.yml", term);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn nudge_mode_demotes_block() {
        let term = BLOCK_VIOLATIONS[0].0;
        let json = format!(
            r#"{{"exemptions":[{{"paths":["acl.yml"],"terms":["{term}"],"mode":"nudge"}}]}}"#
        );
        let repo = temp_repo(&json);
        let input = write_at(repo.path(), "acl.yml", term);
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, Outcome::Nudge);
        // The demoted term still surfaces in the advisory message.
        assert!(result.message.unwrap().contains(term));
    }

    #[test]
    fn path_match_but_term_mismatch_still_blocks() {
        // Exempting term A in acl.yml must NOT exempt term B written there.
        let term_a = BLOCK_VIOLATIONS[0].0;
        let term_b = BLOCK_VIOLATIONS[1].0;
        let json = format!(r#"{{"exemptions":[{{"paths":["acl.yml"],"terms":["{term_a}"]}}]}}"#);
        let repo = temp_repo(&json);
        let input = write_at(repo.path(), "acl.yml", &format!("{term_a} then {term_b}"));
        let result = TerminologyGuard.run(&input);
        assert_eq!(result.outcome, Outcome::Block);
        let msg = result.message.unwrap();
        assert!(
            msg.contains(term_b),
            "unexempted term must still block: {msg}"
        );
        assert!(
            !msg.contains(&format!("\"{term_a}\"")),
            "exempted term must be dropped from the block list: {msg}"
        );
    }

    #[test]
    fn blanket_exemption_drops_all_terms() {
        // `terms` omitted → every flagged term at that path is exempt.
        let term_a = BLOCK_VIOLATIONS[0].0;
        let term_b = BLOCK_VIOLATIONS[1].0;
        let repo = temp_repo(r#"{"exemptions":[{"paths":["acl.yml"]}]}"#);
        let input = write_at(repo.path(), "acl.yml", &format!("{term_a} and {term_b}"));
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn basename_pattern_matches_in_subdir() {
        let term = BLOCK_VIOLATIONS[0].0;
        let json =
            format!(r#"{{"exemptions":[{{"paths":["silly-file.yml"],"terms":["{term}"]}}]}}"#);
        let repo = temp_repo(&json);
        let input = write_at(repo.path(), "deep/nested/silly-file.yml", term);
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn slash_pattern_matches_repo_relative_path() {
        let term = BLOCK_VIOLATIONS[0].0;
        let json = format!(r#"{{"exemptions":[{{"paths":["config/**"],"terms":["{term}"]}}]}}"#);
        let repo = temp_repo(&json);
        // Inside config/ → exempt.
        let inside = write_at(repo.path(), "config/acl.yml", term);
        assert_eq!(outcome(&inside), Outcome::Allow);
        // Outside config/ → the same term still blocks.
        let outside = write_at(repo.path(), "other/acl.yml", term);
        assert_eq!(outcome(&outside), Outcome::Block);
    }

    #[test]
    fn first_match_precedence_decides_mode() {
        let term = BLOCK_VIOLATIONS[0].0;
        // allow first, nudge second → first wins → dropped (Allow).
        let allow_first = format!(
            r#"{{"exemptions":[{{"paths":["acl.yml"],"terms":["{term}"]}},{{"paths":["acl.yml"],"terms":["{term}"],"mode":"nudge"}}]}}"#
        );
        let repo = temp_repo(&allow_first);
        assert_eq!(
            outcome(&write_at(repo.path(), "acl.yml", term)),
            Outcome::Allow
        );

        // nudge first, allow second → first wins → demoted (Nudge).
        let nudge_first = format!(
            r#"{{"exemptions":[{{"paths":["acl.yml"],"terms":["{term}"],"mode":"nudge"}},{{"paths":["acl.yml"],"terms":["{term}"]}}]}}"#
        );
        let repo2 = temp_repo(&nudge_first);
        assert_eq!(
            outcome(&write_at(repo2.path(), "acl.yml", term)),
            Outcome::Nudge
        );
    }

    #[test]
    fn invalid_json_fails_open_and_still_blocks() {
        let repo = temp_repo("{not valid json");
        let input = write_at(repo.path(), "acl.yml", BLOCK_VIOLATIONS[0].0);
        assert_eq!(outcome(&input), Outcome::Block);
    }

    #[cfg(unix)]
    #[test]
    fn special_file_config_fails_open_and_does_not_hang() {
        // #157: a `.claude/cadence.json` that is a symlink to an endless
        // special file (`/dev/zero`) must be rejected on stat — the guard falls
        // open to the default (empty) config and a flagged term still blocks,
        // without an unbounded read hanging the hook.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(".claude/cadence.json")).unwrap();
        let input = write_at(dir.path(), "src/main.rs", BLOCK_VIOLATIONS[0].0);
        assert_eq!(outcome(&input), Outcome::Block);
    }

    #[test]
    fn carried_through_term_in_exempt_mismatch_file_still_allowed() {
        // #63 subtract-existing runs before the config pass: a term carried
        // through an Edit (present in both old and new) produces no block, so
        // the gate skips apply_exemptions entirely — Allow regardless of config.
        let term = BLOCK_VIOLATIONS[0].0;
        let repo = temp_repo(r#"{"exemptions":[{"paths":["unrelated.yml"]}]}"#);
        let full = repo.path().join("src/main.rs");
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        let path = full.to_string_lossy().into_owned();
        let input = make_edit(
            &path,
            &format!("{term} setting v1"),
            &format!("{term} setting v2"),
        );
        assert_eq!(outcome(&input), Outcome::Allow);
    }

    #[test]
    fn no_git_root_leaves_block_unchanged() {
        // A file with no ancestor .git → no config possible → block stands.
        let dir = tempfile::tempdir().unwrap();
        let input = write_at(dir.path(), "acl.yml", BLOCK_VIOLATIONS[0].0);
        assert_eq!(outcome(&input), Outcome::Block);
    }

    #[test]
    fn load_terminology_config_missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = load_terminology_config(dir.path());
        assert!(config.exemptions.is_empty());
    }

    #[test]
    fn load_terminology_config_reads_exemptions() {
        let repo = temp_repo(r#"{"exemptions":[{"paths":["a.yml"]},{"paths":["b.yml"]}]}"#);
        let config = load_terminology_config(repo.path());
        assert_eq!(config.exemptions.len(), 2);
    }

    #[test]
    fn find_git_root_walks_up() {
        let repo = temp_repo_no_config();
        let nested = repo.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let found = cadence_hooks_core::paths::find_git_root(&nested.to_string_lossy());
        assert_eq!(found, Some(PathBuf::from(repo.path())));
    }
}
