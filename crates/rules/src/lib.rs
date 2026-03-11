//! Hooks for the [rules](https://github.com/cameronsjo/rules) plugin.
//!
//! Structural validation for plugin files and security-aware code scanning.

/// Scan written code for language-specific security anti-patterns.
pub mod check_security_patterns;
/// Validate SKILL.md and command file frontmatter (required fields, name format, known fields).
pub mod validate_skill_frontmatter;
