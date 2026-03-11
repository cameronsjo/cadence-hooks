use claude_hooks_core::{Check, CheckResult, HookInput};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const IDLE_THRESHOLD_SECS: u64 = 300; // 5 minutes
const NEW_SESSION_THRESHOLD_SECS: u64 = 28800; // 8 hours

pub struct CheckIdleReturn;

impl CheckIdleReturn {
    fn marker_path() -> Option<PathBuf> {
        let repo_root = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

        let mut hasher = DefaultHasher::new();
        repo_root.hash(&mut hasher);
        let hash = hasher.finish();

        Some(PathBuf::from(format!(
            "/tmp/.claude-last-edit-{hash:x}"
        )))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Check for CheckIdleReturn {
    fn name(&self) -> &str {
        "check-idle-return"
    }

    fn run(&self, _input: &HookInput) -> CheckResult {
        let Some(marker) = Self::marker_path() else {
            return CheckResult::allow();
        };

        let now = Self::now_secs();
        let result;

        if let Ok(contents) = std::fs::read_to_string(&marker) {
            if let Ok(last_ts) = contents.trim().parse::<u64>() {
                let gap = now.saturating_sub(last_ts);

                if (IDLE_THRESHOLD_SECS..NEW_SESSION_THRESHOLD_SECS).contains(&gap) {
                    let mins = gap / 60;
                    result = CheckResult::warn(format!(
                        "It's been {mins}m since your last edit. Before continuing: \
                         check for uncommitted changes worth committing, and consider \
                         saving any learnings to auto memory."
                    ));
                } else {
                    result = CheckResult::allow();
                }
            } else {
                result = CheckResult::allow();
            }
        } else {
            result = CheckResult::allow();
        }

        // Update marker with current timestamp
        let _ = std::fs::write(&marker, now.to_string());

        result
    }
}
