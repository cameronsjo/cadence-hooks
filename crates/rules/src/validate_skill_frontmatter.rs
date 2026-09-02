//! Validate YAML frontmatter in skill and command markdown files.
//!
//! Checks that `SKILL.md` and command `.md` files have valid frontmatter
//! with required fields, kebab-case names, and no unknown keys.

use cadence_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

const VALID_FIELDS: &[&str] = &[
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
    "argument-hint",
    "arguments",
    "disallowed-tools",
    "disable-model-invocation",
    "user-invocable",
    "model",
    "context",
    "background",
    "agent",
    "hooks",
    "paths",
    "when_to_use",
    "effort",
    "shell",
];

// House strictness: boolean fields take exactly `true` or `false`. The
// platform (Claude Code >= 2.1.218) also accepts yes/no/on/off/1/0 —
// cadence deliberately does not: one spelling keeps the corpus greppable.
const BOOLEAN_FIELDS: &[&str] = &["background", "disable-model-invocation", "user-invocable"];

// Enum fields: value must be exactly one of the listed options (same
// unquoted-only house strictness as BOOLEAN_FIELDS). Sets verified against
// the raw Claude Code docs (code.claude.com/docs/en/skills), not assumed.
const ENUM_FIELDS: &[(&str, &[&str])] = &[
    ("effort", &["low", "medium", "high", "xhigh", "max"]),
    ("shell", &["bash", "powershell"]),
];

// Kebab-case name with NO namespace prefix — a colon is rejected outright.
//
// Claude Code owns the prefix: it builds a skill's invocation id from
// `<plugin>:<directory>` and prepends the prefix itself, so a declared
// `cadence:attune` renders as `/cadence:cadence:attune`. Release 2.1.216
// ("fixed plugin skills with a `name` frontmatter field losing their plugin
// prefix in slash-command autocomplete") is what made the prefix doubling;
// 2.1.218 then made agent markdown reject `:` in a name for the same reason,
// reserving the character for plugin namespacing.
//
// This pattern previously allowed an optional `namespace:` prefix (0.19.0),
// because 2.1.94 had made plugin skills use the frontmatter `name` as the
// invocation name — which made the prefixed form render correctly. That is the
// convention this reverses.
//
// IF THE PLATFORM FLIPS BACK — de-duplication is requested upstream in
// anthropics/claude-code#80631; watch that issue — the order matters:
// relax this pattern and SHIP A RELEASE FIRST, then
// sweep the corpus with `cadence/scripts/skill-names.py --prefixed`. Tightened
// as it stands, this check blocks every edit to a prefixed SKILL.md — including
// the sweep that would undo it. Restoring the old form means re-adding the
// optional trailing group `(:[a-z0-9]+(-[a-z0-9]+)*)?` and the `rsplit_once`
// suffix comparison in `run` below.
static NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").expect("pattern should compile"));

#[derive(Debug, PartialEq)]
enum FileType {
    Skill,
    Command,
    Other,
}

/// Upper bound on a path we will scan. Past this we classify as `Other` rather
/// than walk it: `file_path` is unbounded agent-supplied input, and the scan
/// below pays a `stat` per candidate directory, so an absurd path is a way to
/// stall the hook. Failing open here matches ADR-0001 — a guard that times out
/// protects nobody either.
const MAX_PATH_BYTES: usize = 4096;

/// Split a path into segments, dropping what carries no meaning (`//` and
/// `/./`) and folding `..`, so the classifier sees the directory the write
/// actually lands in.
///
/// `normalize_path` upstream (`crates/core`) only maps `\` to `/`, strips NULs,
/// and trims trailing slashes — it does none of this — so `/repo/.claude//commands/x.md`
/// and `/repo/.claude/./commands/x.md` arrive verbatim. Comparing raw segments
/// would see `""` or `"."` as the parent and miss a real command definition.
///
/// `None` means "do not classify": a relative path, or one past the size bound.
/// Relative paths are refused because the marker probe below resolves against
/// the hook process's cwd, so the same path would classify differently
/// depending on where the process happens to stand.
fn normalized_segments(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') || path.len() > MAX_PATH_BYTES {
        return None;
    }
    let mut segments: Vec<&str> = Vec::new();
    for raw in path.split('/') {
        match raw {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    Some(segments)
}

/// Is `segments` — the directory that holds a `commands/` or `skills/` tree —
/// somewhere Claude Code actually loads definitions from?
///
/// Two shapes, and they are the only two:
///
/// 1. A `.claude/` directory: user (`~/.claude`) or project (`<repo>/.claude`).
/// 2. A plugin root, identified by its sibling `.claude-plugin/` marker. This
///    covers the installed cache (`<cache>/<marketplace>/<plugin>/<sha>/`), the
///    monorepo's `plugins/<plugin>/`, and a standalone plugin repo root alike —
///    all 14 plugins in the cadence monorepo carry the marker, so nothing needs
///    a `plugins/` path-segment rule to be recognised.
///
/// An earlier draft of this fix DID carry that extra rule — accept any
/// `plugins/<name>/commands/` triple — as a fast path to skip the `stat`. It
/// reintroduced the very bug being fixed one directory deeper:
/// `<repo>/docs/plugins/<name>/commands/overview.md` is documentation ABOUT
/// plugins and was hard-blocked by it. The marker covers every real instance,
/// so the fast path bought one `stat` and cost a false block.
///
/// Comparisons are ASCII-case-insensitive because APFS and NTFS are: a write to
/// `/repo/.Claude/commands/x.md` lands in the real `.claude` directory, and a
/// case-sensitive compare would let it skip validation.
///
/// Fails OPEN: an absent or unreadable marker classifies as `Other`, so the
/// guard's own I/O trouble can never block an edit (ADR-0001). The known cost is
/// a missed nudge on a plugin being scaffolded whose `.claude-plugin/` does not
/// exist yet — the cheaper failure, since a guardrail's real price is a false
/// block on legitimate work, not a missed nudge.
fn is_definition_root(segments: &[&str]) -> bool {
    if segments
        .last()
        .is_some_and(|parent| parent.eq_ignore_ascii_case(".claude"))
    {
        return true;
    }
    if segments.is_empty() {
        return false;
    }
    let root = format!("/{}", segments.join("/"));
    std::path::Path::new(&root).join(".claude-plugin").is_dir()
}

/// Does this `.md` hold a slash-command DEFINITION, as opposed to living in any
/// directory a project happened to name `commands`?
///
/// The predicate this replaces was a bare `path.contains("/commands/")`, which
/// swept in ordinary project documentation. `<repo>/docs/commands/*.md` is a
/// natural home for a CLI's per-command-group pages — forgectl keeps nine such
/// files, none of which has or should have YAML frontmatter — and every edit to
/// them was hard-blocked for "missing frontmatter", with no way forward except
/// adding meaningless frontmatter or bypassing the guard
/// (cameronsjo/cadence-hooks#802).
fn is_command_definition(segments: &[&str]) -> bool {
    segments.iter().enumerate().any(|(i, segment)| {
        segment.eq_ignore_ascii_case("commands") && is_definition_root(&segments[..i])
    })
}

fn classify_path(path: &str) -> FileType {
    // The skill arm carries the MIRROR of the bug fixed below: a bare
    // `contains("/skills/")` blocks `<repo>/docs/skills/<x>/SKILL.md`, which is
    // documentation about skills, for the same reason and by the same mechanism.
    // It is deliberately left alone here and filed separately
    // (cameronsjo/cadence-hooks#806).
    //
    // Why not both at once: routing this arm through `is_definition_root` turns
    // ~20 existing fixtures red, because they assert against plugin-skill paths
    // like `/plugins/cadence/skills/my-skill/SKILL.md` that have no marker on
    // disk. Making them pass means either restating them as project skills —
    // which quietly drops the plugin case they exist to cover — or standing up
    // real on-disk plugin roots for each. That is a different change with a
    // different blast radius, and burying it in a guard fix is how a mistake
    // gets in. The two defects are the same class, not the same lifecycle.
    if path.contains("/skills/") && path.ends_with("/SKILL.md") {
        return FileType::Skill;
    }
    let Some(segments) = normalized_segments(path) else {
        return FileType::Other;
    };
    if path.ends_with(".md") && is_command_definition(&segments) {
        FileType::Command
    } else {
        FileType::Other
    }
}

fn extract_frontmatter(content: &str) -> Option<Vec<(String, String)>> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.first() != Some(&"---") {
        return None;
    }

    let end = lines[1..].iter().position(|l| *l == "---")?;
    let fm_lines = &lines[1..=end];

    let mut fields = Vec::new();
    for line in fm_lines {
        // Indented lines are nested keys (e.g. `author:` under `metadata:`) —
        // only top-level keys are validated against VALID_FIELDS. The check
        // must run on the raw line: after `.trim()` every key looks top-level.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            if !key.is_empty() {
                fields.push((key, value));
            }
        }
    }

    Some(fields)
}

/// Extract directory name for a skill path (parent of SKILL.md).
fn skill_dir_name(path: &str) -> Option<&str> {
    let parent = path.strip_suffix("/SKILL.md")?;
    parent.rsplit('/').next()
}

/// Strip a trailing inline YAML comment from a scalar value. Per YAML, `#`
/// opens a comment only when preceded by whitespace — `true  # why` yields
/// `true`, while `true#x` stays intact (it is the value, not a comment).
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && bytes[i - 1].is_ascii_whitespace() {
            return value[..i].trim_end();
        }
    }
    value
}

/// Validates YAML frontmatter in skill and command markdown files.
pub struct ValidateSkillFrontmatter;

impl Check for ValidateSkillFrontmatter {
    fn name(&self) -> &str {
        "validate-skill-frontmatter"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        let file_type = classify_path(&path);
        if file_type == FileType::Other {
            return CheckResult::allow();
        }

        // Validate the document the tool call will *produce*, not the raw tool
        // payload. For Edit/MultiEdit this simulates the edit against the
        // on-disk file — an Edit's new_string is a fragment, not the document.
        // Unreadable/missing file → None → allow (fail open, ADR-0001).
        let Some(content) = input.effective_content() else {
            return CheckResult::allow();
        };

        let Some(fields) = extract_frontmatter(&content) else {
            return CheckResult::block("Frontmatter validation failed: file missing YAML frontmatter (must start with ---)".to_string());
        };

        let mut errors = Vec::new();

        // Check for unknown fields
        for (key, _) in &fields {
            if !VALID_FIELDS.contains(&key.as_str()) {
                errors.push(format!("Unknown frontmatter field: '{key}'"));
            }
        }

        // Boolean fields: exactly `true` or `false` — house strictness, one
        // rule for all three (the platform accepts yes/no/on/off/1/0). A
        // trailing inline comment is not part of the value; quoted values
        // (`"true"`) stay blocked — unquoted is the house spelling.
        for (key, value) in &fields {
            let bare = strip_inline_comment(value);
            if BOOLEAN_FIELDS.contains(&key.as_str()) && bare != "true" && bare != "false" {
                errors.push(format!(
                    "'{key}' must be exactly 'true' or 'false' (got: '{bare}') — the platform accepts yes/no/on/off/1/0, cadence house style does not"
                ));
            }
        }

        // Enum fields: value must exactly match one of the allowed options.
        for (key, value) in &fields {
            let bare = strip_inline_comment(value);
            if let Some((_, allowed)) = ENUM_FIELDS.iter().find(|(k, _)| *k == key.as_str())
                && !allowed.contains(&bare)
            {
                errors.push(format!(
                    "'{key}' must be one of {allowed:?} (got: '{bare}')"
                ));
            }
        }

        match file_type {
            FileType::Skill => {
                let has_name = fields.iter().any(|(k, _)| k == "name");
                let has_desc = fields.iter().any(|(k, _)| k == "description");

                if !has_name {
                    errors.push("Missing required 'name' field".into());
                }
                if !has_desc {
                    errors.push("Missing required 'description' field".into());
                }

                if let Some((_, name_value)) = fields.iter().find(|(k, _)| k == "name") {
                    // Check name format. A colon fails here, which is the whole
                    // point: Claude Code prepends `<plugin>:` itself, so a
                    // declared prefix doubles in the slash menu.
                    if !NAME_PATTERN.is_match(name_value) {
                        errors.push(format!(
                            "name must be the bare skill directory — only lowercase letters, numbers, and hyphens, no 'plugin:' prefix (got: '{name_value}')"
                        ));
                    }

                    // Check the name matches the directory. With colons rejected
                    // above, the declared name IS the skill part, so this is a
                    // direct comparison.
                    if let Some(dir_name) = skill_dir_name(&path)
                        && name_value.as_str() != dir_name
                    {
                        errors.push(format!(
                            "name '{name_value}' must match directory '{dir_name}'"
                        ));
                    }
                }
            }
            FileType::Command => {
                if fields.iter().any(|(k, _)| k == "name") {
                    errors.push(
                        "Remove 'name:' from command files — commands derive name from filename"
                            .into(),
                    );
                }
            }
            FileType::Other => {}
        }

        if errors.is_empty() {
            CheckResult::allow()
        } else {
            CheckResult::block(format!(
                "Frontmatter validation failed: {}",
                errors.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_skill_passes() {
        let content = "---\nname: my-skill\ndescription: A test skill\n---\n# Content";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "name");
    }

    #[test]
    fn missing_frontmatter_detected() {
        let content = "# No frontmatter here";
        assert!(extract_frontmatter(content).is_none());
    }

    #[test]
    fn valid_name_format() {
        assert!(NAME_PATTERN.is_match("my-skill"));
        assert!(NAME_PATTERN.is_match("skill123"));
        assert!(NAME_PATTERN.is_match("add-narrative-logging"));
        assert!(!NAME_PATTERN.is_match("My-Skill"));
        assert!(!NAME_PATTERN.is_match("-leading"));
        assert!(!NAME_PATTERN.is_match("trailing-"));
        assert!(!NAME_PATTERN.is_match("double--hyphen"));
        // A `plugin:` prefix is rejected outright — Claude Code prepends it
        // itself (2.1.216), so declaring it renders `/cadence:cadence:attune`.
        assert!(!NAME_PATTERN.is_match("cadence:attune"));
        assert!(!NAME_PATTERN.is_match("cadence-forge:add-narrative-logging"));
        assert!(!NAME_PATTERN.is_match("cadence-rules:init-all"));
        // Colon edge cases stay rejected for the same reason.
        assert!(!NAME_PATTERN.is_match("cadence:")); // dangling colon
        assert!(!NAME_PATTERN.is_match(":attune")); // leading colon
        assert!(!NAME_PATTERN.is_match("a::b")); // double colon
        assert!(!NAME_PATTERN.is_match("Cadence:attune")); // uppercase namespace
        assert!(!NAME_PATTERN.is_match("cadence:At")); // uppercase suffix
    }

    #[test]
    fn classify_skill_path() {
        assert_eq!(
            classify_path("/plugins/cadence/skills/my-skill/SKILL.md"),
            FileType::Skill
        );
    }

    #[test]
    fn classify_command_path() {
        assert_eq!(
            classify_path("/repo/.claude/commands/my-cmd.md"),
            FileType::Command
        );
    }

    #[test]
    fn classify_dot_claude_command_path() {
        assert_eq!(
            classify_path("/Users/x/.claude/commands/my-cmd.md"),
            FileType::Command
        );
        assert_eq!(
            classify_path("/repo/.claude/commands/nested/my-cmd.md"),
            FileType::Command
        );
    }

    /// The cameronsjo/cadence-hooks#802 regression, pinned.
    ///
    /// `docs/commands/` is ordinary project documentation — a natural home for
    /// a CLI's per-command-group pages, and forgectl keeps nine of them with no
    /// frontmatter by convention. The old bare `contains("/commands/")`
    /// predicate classified every one as a command DEFINITION, so the check
    /// hard-blocked each edit for "missing YAML frontmatter".
    ///
    /// This is the control for the fix: it fails on the old predicate and is
    /// the reason the new one splits on path segments instead of substrings.
    #[test]
    fn docs_commands_dir_is_not_a_command_definition() {
        for path in [
            "/repo/docs/commands/projects-and-review.md",
            "/repo/docs/commands/pr.md",
            "/repo/documentation/commands/index.md",
            "/srv/commands/readme.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Other,
                "{path} is documentation, not a command definition"
            );
        }
    }

    /// A plugin root is identified by its sibling `.claude-plugin/` marker —
    /// the installed-cache and standalone-plugin-repo layouts, neither of which
    /// carries a `plugins/` path segment for the string fast paths to catch.
    ///
    /// The negative half is what keeps the marker load-bearing: the identical
    /// tree WITHOUT `.claude-plugin/` must classify as `Other`, or this test
    /// would pass for a reason that has nothing to do with the marker.
    #[test]
    fn plugin_root_marker_classifies_commands() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("some-plugin");
        let commands = root.join("commands");
        std::fs::create_dir_all(&commands).expect("fixture dirs");
        let cmd_path = commands.join("my-cmd.md");
        let cmd_str = cmd_path.to_str().expect("utf-8 fixture path");

        // No marker yet — indistinguishable from any other `commands` dir.
        assert_eq!(
            classify_path(cmd_str),
            FileType::Other,
            "without .claude-plugin/ this is not a plugin root"
        );

        std::fs::create_dir_all(root.join(".claude-plugin")).expect("marker dir");
        assert_eq!(
            classify_path(cmd_str),
            FileType::Command,
            "the .claude-plugin/ marker is what makes it a plugin root"
        );
    }

    /// The installed-cache shape, which is the reason the marker rule exists —
    /// and which carries a DECOY `plugins` segment at a non-matching offset
    /// (`.../plugins/cache/<marketplace>/<plugin>/<sha>/commands/`).
    ///
    /// An earlier draft accepted any `plugins/<name>/commands/` triple as a fast
    /// path. That rule could not reach this shape (the offsets do not line up)
    /// while it DID reach `docs/plugins/<name>/commands/`, which is exactly
    /// backwards. This test pins the real shape so a future "simplify the
    /// predicate" edit cannot quietly reintroduce the substring form.
    #[test]
    fn installed_cache_shape_with_decoy_plugins_segment() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp
            .path()
            .join("plugins")
            .join("cache")
            .join("workbench")
            .join("cadence-forge")
            .join("960c588950a6-7712fab0");
        std::fs::create_dir_all(root.join("commands")).expect("fixture dirs");
        std::fs::create_dir_all(root.join(".claude-plugin")).expect("marker dir");

        let cmd = root.join("commands").join("polish.md");
        assert_eq!(
            classify_path(cmd.to_str().expect("utf-8")),
            FileType::Command,
            "the installed cache layout is a real command definition location"
        );
    }

    /// Documentation ABOUT plugins is still documentation.
    ///
    /// This is the second half of cadence-hooks#802 and the reason the
    /// `plugins/<name>/commands/` fast path was dropped rather than kept: that
    /// rule reintroduced the identical false block one directory deeper, on a
    /// path shape (`docs/plugins/…`) that is if anything more likely than the
    /// original.
    #[test]
    fn docs_about_plugins_is_not_a_command_definition() {
        for path in [
            "/repo/docs/plugins/my-plugin/commands/overview.md",
            "/repo/node_modules/foo/plugins/bar/commands/doc.md",
            "/repo/plugins/some-plugin/commands/x.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Other,
                "{path} has no .claude-plugin/ marker, so it is not a plugin root"
            );
        }
    }

    /// `normalize_path` upstream does not collapse `//`, resolve `.`/`..`, or
    /// case-fold, so these reach the classifier verbatim — and every one of them
    /// writes to a real `.claude/commands/` file on disk. Comparing raw segments
    /// saw `""`, `"."`, or `".."` as the parent and let a genuine command
    /// definition skip validation entirely.
    #[test]
    fn unnormalized_shapes_still_reach_the_command_arm() {
        for path in [
            "/repo/.claude//commands/x.md",
            "/repo/.claude/./commands/x.md",
            "/repo/.claude/sub/../commands/x.md",
            "/repo/.Claude/commands/x.md",
            "/repo/.claude/COMMANDS/x.md",
        ] {
            assert_eq!(
                classify_path(path),
                FileType::Command,
                "{path} resolves into a real .claude/commands tree"
            );
        }
    }

    /// A relative path would make the marker probe resolve against whatever
    /// directory the hook process is standing in, so the same path could
    /// classify two ways in one session. Refuse rather than answer
    /// inconsistently — and refuse an absurd path rather than walk it.
    #[test]
    fn relative_and_oversized_paths_are_not_classified() {
        assert_eq!(
            classify_path("repo/.claude/commands/x.md"),
            FileType::Other,
            "a relative path has no stable meaning here"
        );
        let huge = format!("/{}/commands/x.md", "a".repeat(MAX_PATH_BYTES));
        assert_eq!(
            classify_path(&huge),
            FileType::Other,
            "past the size bound we decline to scan"
        );
    }

    #[test]
    fn skill_dir_extraction() {
        assert_eq!(
            skill_dir_name("/plugins/skills/my-skill/SKILL.md"),
            Some("my-skill")
        );
    }

    #[test]
    fn skill_dir_name_none_for_non_skill() {
        assert_eq!(skill_dir_name("/plugins/commands/my-cmd.md"), None);
    }

    #[test]
    fn classify_other_path() {
        assert_eq!(classify_path("/project/src/main.rs"), FileType::Other);
    }

    #[test]
    fn empty_frontmatter() {
        let content = "---\n---\n# Content";
        let fields = extract_frontmatter(content).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn frontmatter_with_extra_colons() {
        let content = "---\nname: my-skill\ndescription: A skill: for testing\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].1, "A skill: for testing");
    }

    // Full Check::run() integration tests
    use cadence_hooks_core::test_builders::make_write as make_write_input;

    #[test]
    fn run_other_file_allowed() {
        let input = make_write_input("/project/src/main.rs", "fn main() {}");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_missing_frontmatter_blocks() {
        let input = make_write_input("/plugins/skills/my-skill/SKILL.md", "# No frontmatter");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
    }

    #[test]
    fn run_skill_missing_name_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\ndescription: A test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'name'"));
    }

    #[test]
    fn run_skill_missing_description_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Missing required 'description'")
        );
    }

    #[test]
    fn run_skill_invalid_name_format_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: My-Skill\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("lowercase"));
    }

    #[test]
    fn run_skill_name_dir_mismatch_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: other-name\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
    }

    #[test]
    fn run_skill_namespaced_name_blocks_even_when_suffix_matches() {
        // The plugin:directory form is rejected even though the post-colon
        // suffix equals the directory — this is the form 0.19.0 through
        // 0.63.0 accepted, and the one that renders `/cadence:cadence:my-skill`.
        let input = make_write_input(
            "/plugins/cadence/skills/my-skill/SKILL.md",
            "---\nname: cadence:my-skill\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("bare skill directory"));
    }

    #[test]
    fn run_skill_namespaced_name_suffix_mismatch_blocks() {
        // Still blocks, now for two reasons rather than one: the colon fails
        // the format check AND `cadence:wrong` is not the directory `my-skill`.
        let input = make_write_input(
            "/plugins/cadence/skills/my-skill/SKILL.md",
            "---\nname: cadence:wrong\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
    }

    #[test]
    fn run_skill_bare_name_matching_dir_passes() {
        // The correct form as of Claude Code 2.1.216.
        let input = make_write_input(
            "/plugins/cadence/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_valid_skill_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_command_with_name_field_blocks() {
        let input = make_write_input(
            "/repo/.claude/commands/my-cmd.md",
            "---\nname: my-cmd\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Remove 'name:'"));
    }

    #[test]
    fn run_command_without_name_passes() {
        let input = make_write_input(
            "/repo/.claude/commands/my-cmd.md",
            "---\ndescription: A command\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_unknown_field_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\nunknown-field: value\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Unknown frontmatter field")
        );
    }

    #[test]
    fn run_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_no_content_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: Some("/plugins/skills/my-skill/SKILL.md".into()),
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
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn name_with_numbers_valid() {
        assert!(NAME_PATTERN.is_match("skill-v2"));
        assert!(NAME_PATTERN.is_match("s3-uploader"));
        assert!(NAME_PATTERN.is_match("123"));
    }

    #[test]
    fn name_with_underscores_invalid() {
        assert!(!NAME_PATTERN.is_match("my_skill"));
    }

    #[test]
    fn name_with_spaces_invalid() {
        assert!(!NAME_PATTERN.is_match("my skill"));
    }

    #[test]
    fn name_single_char_valid() {
        assert!(NAME_PATTERN.is_match("a"));
    }

    #[test]
    fn frontmatter_missing_end_delimiter() {
        let content = "---\nname: my-skill\ndescription: test\n# No end delimiter";
        assert!(extract_frontmatter(content).is_none());
    }

    #[test]
    fn frontmatter_nested_keys_excluded() {
        // Indented (nested) keys belong to a parent mapping — they are not
        // top-level fields and must not be validated against VALID_FIELDS.
        let content = "---\nname: my-skill\n  nested: value\ndescription: test\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().all(|(k, _)| k != "nested"));
    }

    #[test]
    fn run_multiple_errors_all_reported() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nunknown1: val\nunknown2: val\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("unknown1"));
        assert!(msg.contains("unknown2"));
        assert!(msg.contains("Missing required 'name'"));
        assert!(msg.contains("Missing required 'description'"));
    }

    // --- Edit/MultiEdit simulation against on-disk files (#60, #63) ---

    use cadence_hooks_core::test_builders::{make_edit, make_multi_edit};

    const VALID_SKILL: &str =
        "---\nname: my-skill\ndescription: A test skill\n---\n# My Skill\n\nBody text here.\n";

    /// Write a valid SKILL.md into a temp dir shaped like a plugin skill tree.
    /// Returns (tempdir guard, absolute SKILL.md path).
    fn on_disk_skill(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("skills/my-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        let path = skill_dir.join("SKILL.md");
        std::fs::write(&path, content).unwrap();
        (dir, path.to_str().unwrap().to_string())
    }

    #[test]
    fn run_body_only_edit_on_valid_skill_allowed() {
        // Regression for #60: a mid-file Edit to a valid SKILL.md must not be
        // blocked just because the edit fragment lacks frontmatter.
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_edit(&path, "Body text here.", "Updated body text.");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_edit_corrupting_frontmatter_blocks() {
        // The false-negative direction: an Edit that breaks the frontmatter of
        // a valid file must still be caught.
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_edit(&path, "name: my-skill", "not a valid key line");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'name'"));
    }

    #[test]
    fn run_multi_edit_body_edit_on_valid_skill_allowed() {
        let (_dir, path) = on_disk_skill(VALID_SKILL);
        let input = make_multi_edit(
            &path,
            &[("# My Skill", "# My Skill v2"), ("Body text", "New body")],
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_edit_on_missing_file_allowed() {
        // Fail open (ADR-0001): if the file can't be read, the edit can't be
        // simulated — allow rather than block on incomplete information.
        let input = make_edit(
            "/nonexistent/plugins/skills/my-skill/SKILL.md",
            "old",
            "new",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_write_with_nested_metadata_allowed() {
        // Regression for #63 (bug 2): nested keys under `metadata:` are not
        // unknown top-level fields.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\nmetadata:\n  author: cameron\n  version: 1.0.0\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn valid_skill_with_optional_fields() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A skill\nmodel: opus\nallowed-tools: Read,Grep\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn valid_skill_with_paths_field() {
        // #227: `paths` is a valid Claude Code conditional-activation field
        // (scopes a skill to activate only when matching files are touched).
        // It must not be rejected as an unknown frontmatter field.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\npaths: src/**/*.rs\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- Background fork skills (Claude Code 2.1.218) + strict booleans ---

    #[test]
    fn run_skill_with_background_true_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ncontext: fork\nbackground: true\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_background_false_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ncontext: fork\nbackground: false\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_background_yes_blocks() {
        // The platform loosened boolean parsing (yes/no/on/off/1/0) in
        // 2.1.218; cadence house style stays strict true/false.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ncontext: fork\nbackground: yes\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_user_invocable_yes_blocks() {
        // One rule for all boolean fields — pre-existing booleans get the
        // same strictness as the new `background` field.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\nuser-invocable: yes\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("'user-invocable' must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_disable_model_invocation_numeric_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ndisable-model-invocation: 1\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("'disable-model-invocation' must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn run_skill_boolean_true_false_still_pass() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\nuser-invocable: false\ndisable-model-invocation: true\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_boolean_with_inline_comment_passes() {
        // A trailing YAML comment is not part of the value — `true  # why`
        // is the boolean true, not a malformed spelling.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ncontext: fork\nbackground: true  # opt out later\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_quoted_boolean_blocks() {
        // Deliberate: `"true"` is a string spelling, not the house boolean.
        // Unquoted true/false is the one greppable form.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\ncontext: fork\nbackground: \"true\"\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("must be exactly 'true' or 'false'")
        );
    }

    #[test]
    fn strip_inline_comment_edges() {
        assert_eq!(strip_inline_comment("true  # opt out later"), "true");
        assert_eq!(strip_inline_comment("true"), "true");
        // `#` without preceding whitespace is part of the value, not a comment.
        assert_eq!(strip_inline_comment("true#x"), "true#x");
        assert_eq!(strip_inline_comment("#leading"), "#leading");
        assert_eq!(strip_inline_comment(""), "");
    }

    #[test]
    fn command_valid_with_description_only() {
        let input = make_write_input(
            "/plugins/commands/deploy.md",
            "---\ndescription: Deploy the app\nallowed-tools: Bash\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn skill_dir_name_deeply_nested() {
        assert_eq!(
            skill_dir_name("/a/b/c/d/skills/deep-skill/SKILL.md"),
            Some("deep-skill")
        );
    }

    #[test]
    fn classify_skill_md_not_in_skills_dir() {
        // SKILL.md but not under /skills/
        assert_eq!(classify_path("/project/SKILL.md"), FileType::Other);
    }

    #[test]
    fn frontmatter_line_without_colon() {
        // A line in frontmatter with no colon
        let content = "---\nname: my-skill\nbroken line\ndescription: test\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2); // broken line is skipped
    }

    // --- Platform sweep: when_to_use, arguments, disallowed-tools, effort, shell ---

    #[test]
    fn run_skill_with_when_to_use_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\nwhen_to_use: Use when doing X\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_arguments_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\narguments: issue branch\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_disallowed_tools_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\ndisallowed-tools: AskUserQuestion\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_with_valid_effort_passes() {
        for level in ["low", "medium", "high", "xhigh", "max"] {
            let content =
                format!("---\nname: my-skill\ndescription: test\neffort: {level}\n---\n# Content");
            let input = make_write_input("/plugins/skills/my-skill/SKILL.md", &content);
            let result = ValidateSkillFrontmatter.run(&input);
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "effort: {level} should pass"
            );
        }
    }

    #[test]
    fn run_skill_with_invalid_effort_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\neffort: extreme\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("'effort' must be one of"));
    }

    #[test]
    fn run_skill_with_valid_shell_passes() {
        for shell in ["bash", "powershell"] {
            let content =
                format!("---\nname: my-skill\ndescription: test\nshell: {shell}\n---\n# Content");
            let input = make_write_input("/plugins/skills/my-skill/SKILL.md", &content);
            let result = ValidateSkillFrontmatter.run(&input);
            assert_eq!(
                result.outcome,
                cadence_hooks_core::Outcome::Allow,
                "shell: {shell} should pass"
            );
        }
    }

    #[test]
    fn run_skill_with_invalid_shell_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\nshell: zsh\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("'shell' must be one of"));
    }

    #[test]
    fn run_skill_unknown_field_still_rejected_alongside_new_fields() {
        // The new fields don't loosen the allowlist — an unrelated unknown
        // key is still rejected.
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\neffort: high\ntotally-made-up: value\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("Unknown frontmatter field: 'totally-made-up'")
        );
    }
}
