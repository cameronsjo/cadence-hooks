use claude_hooks_core::{Check, CheckResult, HookInput};

pub struct LineEndingsGuard;

impl Check for LineEndingsGuard {
    fn name(&self) -> &str {
        "validate-line-endings"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(path) = input.file_path() else {
            return CheckResult::allow();
        };

        // Only check shell scripts
        if !path.ends_with(".sh") && !path.ends_with(".bash") {
            return CheckResult::allow();
        }

        let Some(content) = input.content() else {
            return CheckResult::allow();
        };

        if content.contains('\r') {
            return CheckResult::block(
                "🚫 BLOCKED: Shell script contains Windows-style CRLF line endings.\n\
                 This causes \"env: bash\\r: No such file or directory\" errors.\n\
                 Use LF line endings for bash scripts.",
            );
        }

        CheckResult::allow()
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
    fn lf_endings_pass() {
        let input = make_input("script.sh", "#!/bin/bash\necho hello\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn crlf_endings_blocked() {
        let input = make_input("script.sh", "#!/bin/bash\r\necho hello\r\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn non_shell_files_skipped() {
        let input = make_input("file.txt", "hello\r\nworld\r\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn bash_extension_checked() {
        let input = make_input("script.bash", "#!/bin/bash\r\necho hello\r\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }

    #[test]
    fn bash_extension_lf_passes() {
        let input = make_input("script.bash", "#!/bin/bash\necho hello\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_path_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: None,
            cwd: None,
        };
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_content_allowed() {
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(claude_hooks_core::ToolInput {
                file_path: Some("script.sh".into()),
                path: None,
                command: None,
                content: None,
                new_string: None,
                old_string: None,
            }),
            cwd: None,
        };
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Allow);
    }

    #[test]
    fn mixed_endings_blocked() {
        let input = make_input("script.sh", "#!/bin/bash\necho hello\r\necho world\n");
        let result = LineEndingsGuard.run(&input);
        assert_eq!(result.outcome, claude_hooks_core::Outcome::Block);
    }
}
