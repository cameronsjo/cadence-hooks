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
}
