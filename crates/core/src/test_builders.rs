//! Shared test builders for constructing [`HookInput`] values.
//!
//! Gated behind the `test-builders` feature. Add to downstream crates:
//! ```toml
//! [dev-dependencies]
//! cadence-hooks-core = { workspace = true, features = ["test-builders"] }
//! ```

use crate::{HookInput, ToolInput};

/// Build a `HookInput` for a `Bash` tool invocation.
pub fn make_bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            file_path: None,
            path: None,
            command: Some(cmd.into()),
            content: None,
            new_string: None,
            old_string: None,
        }),
        cwd: None,
    }
}

/// Build a `HookInput` for a `Bash` tool invocation with a working directory.
pub fn make_bash_with_cwd(cmd: &str, cwd: &str) -> HookInput {
    HookInput {
        tool_name: Some("Bash".into()),
        tool_input: Some(ToolInput {
            file_path: None,
            path: None,
            command: Some(cmd.into()),
            content: None,
            new_string: None,
            old_string: None,
        }),
        cwd: Some(cwd.into()),
    }
}

/// Build a `HookInput` for a `Write` tool invocation.
pub fn make_write(path: &str, content: &str) -> HookInput {
    HookInput {
        tool_name: Some("Write".into()),
        tool_input: Some(ToolInput {
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

/// Build a `HookInput` for an `Edit` tool invocation.
pub fn make_edit(path: &str) -> HookInput {
    HookInput {
        tool_name: Some("Edit".into()),
        tool_input: Some(ToolInput {
            file_path: Some(path.into()),
            path: None,
            command: None,
            content: None,
            new_string: Some("new".into()),
            old_string: Some("old".into()),
        }),
        cwd: None,
    }
}
