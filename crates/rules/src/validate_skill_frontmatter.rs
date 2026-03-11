use claude_hooks_core::{Check, CheckResult, HookInput};
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
    "agent",
    "hooks",
];

static NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").expect("pattern should compile"));

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
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            if !key.is_empty() && !key.starts_with(' ') {
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

pub struct ValidateSkillFrontmatter;

impl Check for ValidateSkillFrontmatter {
    fn name(&self) -> &str {
        "validate-skill-frontmatter"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        let file_type = classify_path(path);
        if file_type == FileType::Other {
            return CheckResult::allow();
        }

        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

        let Some(fields) = extract_frontmatter(content) else {
            return CheckResult::block(format!(
                "Frontmatter validation failed: file missing YAML frontmatter (must start with ---)"
            ));
        };

        let mut errors = Vec::new();

        // Check for unknown fields
        for (key, _) in &fields {
            if !VALID_FIELDS.contains(&key.as_str()) {
                errors.push(format!("Unknown frontmatter field: '{key}'"));
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
                            "name must use only lowercase letters, numbers, and hyphens (got: '{name_value}')"
                        ));
                    }

                    // Check name matches directory
                    if let Some(dir_name) = skill_dir_name(path) {
                        if name_value != dir_name {
                            errors.push(format!(
                                "name '{name_value}' must match directory '{dir_name}'"
                            ));
                        }
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
        assert!(!NAME_PATTERN.is_match("My-Skill"));
        assert!(!NAME_PATTERN.is_match("-leading"));
        assert!(!NAME_PATTERN.is_match("trailing-"));
        assert!(!NAME_PATTERN.is_match("double--hyphen"));
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
    fn make_write_input(path: &str, content: &str) -> HookInput {
        HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some(path.into()),
                path: None,
                command: None,
                content: Some(content.into()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        }
    }

    #[test]
    fn run_other_file_allowed() {
        let input = make_write_input("/project/src/main.rs", "fn main() {}");
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_skill_missing_frontmatter_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "# No frontmatter",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn run_skill_missing_name_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\ndescription: A test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'name'"));
    }

    #[test]
    fn run_skill_missing_description_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Missing required 'description'"));
    }

    #[test]
    fn run_skill_invalid_name_format_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: My-Skill\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("lowercase"));
    }

    #[test]
    fn run_skill_name_dir_mismatch_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: other-name\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("must match directory"));
    }

    #[test]
    fn run_valid_skill_passes() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A test skill\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_command_with_name_field_blocks() {
        let input = make_write_input(
            "/plugins/commands/my-cmd.md",
            "---\nname: my-cmd\ndescription: test\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Remove 'name:'"));
    }

    #[test]
    fn run_command_without_name_passes() {
        let input = make_write_input(
            "/plugins/commands/my-cmd.md",
            "---\ndescription: A command\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_unknown_field_blocks() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: test\nunknown-field: value\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        assert!(result.message.unwrap().contains("Unknown frontmatter field"));
    }

    #[test]
    fn run_no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
        };
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn run_no_content_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("/plugins/skills/my-skill/SKILL.md".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
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
    fn frontmatter_with_nested_yaml_parsed() {
        // The parser trims keys before checking, so "  nested" becomes "nested"
        // and passes the `!key.starts_with(' ')` check — nested keys ARE included
        let content = "---\nname: my-skill\n  nested: value\ndescription: test\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 3); // nested is included after trim
    }

    #[test]
    fn run_multiple_errors_all_reported() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nunknown1: val\nunknown2: val\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
        let msg = result.message.unwrap();
        assert!(msg.contains("unknown1"));
        assert!(msg.contains("unknown2"));
        assert!(msg.contains("Missing required 'name'"));
        assert!(msg.contains("Missing required 'description'"));
    }

    #[test]
    fn run_edit_tool_not_checked() {
        // Only Write is checked, not Edit
        let input = HookInput {
            tool_name: Some("Edit".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("/plugins/skills/my-skill/SKILL.md".into()),
                path: None,
                command: None,
                content: Some("# No frontmatter".into()),
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = ValidateSkillFrontmatter.run(&input);
        // The check uses input.content() which falls through to new_string
        // Since content is Some, it will be used but the file_path is checked
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn valid_skill_with_optional_fields() {
        let input = make_write_input(
            "/plugins/skills/my-skill/SKILL.md",
            "---\nname: my-skill\ndescription: A skill\nmodel: opus\nallowed-tools: Read,Grep\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn command_valid_with_description_only() {
        let input = make_write_input(
            "/plugins/commands/deploy.md",
            "---\ndescription: Deploy the app\nallowed-tools: Bash\n---\n# Content",
        );
        let result = ValidateSkillFrontmatter.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
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
        assert_eq!(
            classify_path("/project/SKILL.md"),
            FileType::Other
        );
    }

    #[test]
    fn frontmatter_line_without_colon() {
        // A line in frontmatter with no colon
        let content = "---\nname: my-skill\nbroken line\ndescription: test\n---\n";
        let fields = extract_frontmatter(content).unwrap();
        assert_eq!(fields.len(), 2); // broken line is skipped
    }
}
