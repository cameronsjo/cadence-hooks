use claude_hooks_core::{Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

/// Generic env var names that should be prefixed with the tool name.
const GENERIC_VARS: &[&str] = &[
    "DEBUG", "DISABLE", "NO_SPLASH", "PORT", "VERBOSE", "QUIET", "SILENT",
];

/// File extensions that are code (not config/docs).
const CODE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "rb", "go", "rs", "java", "kt", "cs", "swift",
    "c", "cpp", "h", "hpp",
];

static ENV_ACCESS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    let vars = GENERIC_VARS.join("|");
    Regex::new(&format!(
        r#"(?:process\.env\.({vars})|os\.getenv\(\s*["']({vars})["']\)|ENV\[["']({vars})["']\]|std::env::var\(\s*["']({vars})["']\))"#
    ))
    .expect("env var pattern should compile")
});

fn is_code_file(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next() {
        return CODE_EXTENSIONS.contains(&ext);
    }
    false
}

pub struct EnvVarGuard;

impl Check for EnvVarGuard {
    fn name(&self) -> &str {
        "validate-env-vars"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        if !is_code_file(path) {
            return CheckResult::allow();
        }

        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

        let matches: Vec<String> = ENV_ACCESS_PATTERN
            .find_iter(content)
            .map(|m| m.as_str().to_string())
            .collect();

        if matches.is_empty() {
            return CheckResult::allow();
        }

        let filename = path.rsplit('/').next().unwrap_or(path);
        let mut msg = format!(
            "⚠️  Generic environment variable usage detected in {filename}\n\n\
             Found potentially problematic usage:\n"
        );
        for m in &matches {
            msg.push_str(&format!("  {m}\n"));
        }
        msg.push_str(
            "\nUse tool-prefixed names instead:\n\
             ✅ MYAPP_DEBUG, SERVICE_PORT\n\
             ❌ DEBUG, PORT\n",
        );

        CheckResult::warn(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(path: &str, content: &str) -> HookInput {
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
    fn prefixed_env_var_passes() {
        let input = make_input("src/app.ts", "const debug = process.env.MYAPP_DEBUG;");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn generic_env_var_warns() {
        let input = make_input("src/app.ts", "const debug = process.env.DEBUG;");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn non_code_files_skipped() {
        let input = make_input("README.md", "process.env.DEBUG");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn python_env_access_detected() {
        let input = make_input("src/main.py", "os.getenv(\"PORT\")");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn ruby_env_access_detected() {
        let input = make_input("src/app.rb", "ENV['DEBUG']");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn rust_env_var_detected() {
        let input = make_input("src/main.rs", "std::env::var(\"VERBOSE\")");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
    }

    #[test]
    fn no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
        };
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_content_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("src/app.ts".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn is_code_file_detects_extensions() {
        assert!(is_code_file("app.js"));
        assert!(is_code_file("app.tsx"));
        assert!(is_code_file("main.go"));
        assert!(is_code_file("lib.rs"));
        assert!(is_code_file("App.swift"));
        assert!(!is_code_file("config.yaml"));
        assert!(!is_code_file("README.md"));
        assert!(!is_code_file("Makefile"));
    }

    #[test]
    fn multiple_matches_all_reported() {
        let content = "const a = process.env.DEBUG;\nconst b = process.env.PORT;";
        let input = make_input("src/app.ts", content);
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Warn);
        let msg = result.message.unwrap();
        assert!(msg.contains("DEBUG"));
        assert!(msg.contains("PORT"));
    }

    #[test]
    fn prefixed_var_not_matched() {
        let input = make_input("src/app.ts", "process.env.MYAPP_PORT");
        let result = EnvVarGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }
}
