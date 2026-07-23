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
    "disable-model-invocation",
    "user-invocable",
    "model",
    "context",
    "background",
    "agent",
    "hooks",
    "paths",
];

// House strictness: boolean fields take exactly `true` or `false`. The
// platform (Claude Code >= 2.1.218) also accepts yes/no/on/off/1/0 —
// cadence deliberately does not: one spelling keeps the corpus greppable.
const BOOLEAN_FIELDS: &[&str] = &["background", "disable-model-invocation", "user-invocable"];

// Kebab-case name, optionally prefixed by a kebab `namespace:` (the
// `plugin:directory` invocation id, e.g. `cadence:attune`). Both sides are
// independently multi-segment kebab; the optional trailing group rejects a
// dangling colon (`cadence:`), a leading colon (`:attune`), and a double
// colon (`a::b`) for free.
static NAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*(:[a-z0-9]+(-[a-z0-9]+)*)?$")
        .expect("pattern should compile")
});

#[derive(Debug, PartialEq)]
enum FileType {
    Skill,
    Command,
    Other,
}

fn classify_path(path: &str) -> FileType {
    if path.contains("/skills/") && path.ends_with("/SKILL.md") {
        FileType::Skill
    } else if path.contains("/commands/") && path.ends_with(".md") {
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
                    // Check name format
                    if !NAME_PATTERN.is_match(name_value) {
                        errors.push(format!(
                            "name must use only lowercase letters, numbers, and hyphens, with an optional 'namespace:' prefix (got: '{name_value}')"
                        ));
                    }

                    // Check the skill part matches the directory. The optional
                    // `namespace:` prefix is permitted but not required, and the
                    // namespace itself is not verified against the plugin name —
                    // deriving the plugin from the path is fragile (source vs
                    // cache) and cadence-hooks must not force the prefix on
                    // non-cadence users. Only the post-colon suffix must match.
                    let skill_part = name_value
                        .rsplit_once(':')
                        .map_or(name_value.as_str(), |(_, s)| s);
                    if let Some(dir_name) = skill_dir_name(&path)
                        && skill_part != dir_name
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
        // Optional `namespace:` prefix (the plugin:directory invocation id).
        assert!(NAME_PATTERN.is_match("cadence:attune"));
        assert!(NAME_PATTERN.is_match("cadence-forge:add-narrative-logging"));
        assert!(NAME_PATTERN.is_match("cadence-rules:init-all"));
        assert!(!NAME_PATTERN.is_match("My-Skill"));
        assert!(!NAME_PATTERN.is_match("-leading"));
        assert!(!NAME_PATTERN.is_match("trailing-"));
        assert!(!NAME_PATTERN.is_match("double--hyphen"));
        // Colon edge cases the optional trailing group must reject.
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
            classify_path("/plugins/cadence/commands/my-cmd.md"),
            FileType::Command
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
    fn run_skill_namespaced_name_matching_dir_passes() {
        // The plugin:directory form is allowed: the post-colon suffix matches
        // the directory, so the prefix is accepted.
        let input = make_write_input(
            "/plugins/cadence/skills/my-skill/SKILL.md",
            "---\nname: cadence:my-skill\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_namespaced_name_suffix_mismatch_blocks() {
        // A prefix does not excuse a mismatched skill part: suffix `wrong`
        // still has to equal the directory `my-skill`.
        let input = make_write_input(
            "/plugins/cadence/skills/my-skill/SKILL.md",
            "---\nname: cadence:wrong\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
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
            "/plugins/commands/my-cmd.md",
            "---\nname: my-cmd\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Remove 'name:'"));
    }

    #[test]
    fn run_command_without_name_passes() {
        let input = make_write_input(
            "/plugins/commands/my-cmd.md",
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
}
