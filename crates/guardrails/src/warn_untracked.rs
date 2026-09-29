//! Warn about untracked files during git commit operations.
//!
//! Shells out to `git ls-files --others --exclude-standard` to detect
//! files that might have been forgotten. Filters out build artifacts.

use cadence_hooks_core::shell::{command_segments, command_word, strip_group_wrappers, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::Path;
use std::process::Command;

/// Build artifact extensions to filter from untracked file warnings.
const BUILD_ARTIFACT_EXTENSIONS: &[&str] = &[
    "log", "tmp", "cache", "pyc", "class", "o", "a", "so", "dylib",
];

/// Parse `git status --porcelain` output and return non-artifact untracked files.
///
/// Filters lines starting with `??`, strips the prefix, and removes files
/// whose extensions match known build artifacts. Pure function — no I/O.
pub fn filter_untracked(porcelain: &str) -> Vec<&str> {
    let untracked: Vec<&str> = porcelain
        .lines()
        .filter(|line| line.starts_with("??"))
        .map(|line| line.trim_start_matches("?? "))
        .collect();

    untracked
        .into_iter()
        .filter(|file| {
            !BUILD_ARTIFACT_EXTENSIONS
                .iter()
                .any(|ext| file.ends_with(&format!(".{ext}")))
        })
        .collect()
}

/// True when any executable segment is `git add` or `git commit`.
///
/// Only the command word folds. Git subcommands remain case-sensitive.
fn is_git_add_or_commit(command: &str) -> bool {
    command_segments(command).into_iter().any(|segment| {
        let tokens = tokenize(strip_group_wrappers(&segment));
        tokens
            .first()
            .is_some_and(|first| command_word(first).as_ref() == "git")
            && matches!(tokens.get(1).map(String::as_str), Some("add" | "commit"))
    })
}

/// True when the command is a plain `git commit` whose commit takes only what
/// is already STAGED: some segment is a `git commit`, none carries `-a`/`--all`
/// (or `-i`/`--include`, `-o`/`--only`, `--`, `--pathspec-from-file`) and none
/// is a `git add` (which may stage the plan first). Anything else could fold a
/// modified plan into the commit, so the plan-tick pre-arm stays silent — an
/// advisory's cheap failure is a miss, never a false warning
/// (cadence-hooks#691).
fn commit_takes_only_staged(command: &str) -> bool {
    let mut commits = false;
    for segment in command_segments(command) {
        let tokens = tokenize(strip_group_wrappers(&segment));
        let is_git = tokens
            .first()
            .is_some_and(|first| command_word(first).as_ref() == "git");
        match (is_git, tokens.get(1).map(String::as_str)) {
            (true, Some("add")) => return false,
            (true, Some("commit")) => {
                commits = true;
                for t in &tokens[2..] {
                    let long = t.starts_with("--");
                    let widens = if long {
                        matches!(t.as_str(), "--all" | "--include" | "--only" | "--")
                            || t.starts_with("--pathspec-from-file")
                    } else {
                        // A short cluster naming a, i or o — including `-m`'s
                        // attached value, which reads as a cluster: ambiguity
                        // resolves to silent.
                        t.starts_with('-')
                            && t.chars().skip(1).any(|c| matches!(c, 'a' | 'i' | 'o'))
                    };
                    if widens {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    commits
}

/// Warns when git commit runs with untracked files that may have been forgotten.
pub struct WarnUntrackedFiles;

impl Check for WarnUntrackedFiles {
    fn name(&self) -> &str {
        "warn-untracked-files"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        // Only trigger on git add/commit
        if !is_git_add_or_commit(command) {
            return CheckResult::allow();
        }

        // Get untracked files from git (respect cwd from hook payload)
        let mut cmd = Command::new("git");
        cmd.args(["status", "--porcelain"]);
        if let Some(dir) = input.cwd.as_deref()
            && Path::new(dir).is_dir()
        {
            cmd.current_dir(dir);
        }
        let output = match cadence_hooks_core::shell::run_git_bounded(&mut cmd) {
            cadence_hooks_core::shell::GitSpawn::Completed(out) if out.status.success() => out,
            // Advisory: a truncated (or failed) `status --porcelain` would
            // otherwise produce a confident, short untracked list.
            cadence_hooks_core::shell::GitSpawn::Completed(_)
            | cadence_hooks_core::shell::GitSpawn::Truncated(_)
            | cadence_hooks_core::shell::GitSpawn::SpawnFailed
            | cadence_hooks_core::shell::GitSpawn::TimedOut => return CheckResult::allow(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let important = filter_untracked(&stdout);

        let mut msg = String::new();
        if !important.is_empty() {
            let count = important.len();
            msg = format!("⚠️  Warning: {count} untracked file(s) detected\n\n");
            msg.push_str("These files may need to be included in your commit:\n");
            for file in &important {
                msg.push_str(&format!("  ?? {file}\n"));
            }
        }

        // The plan-tick pre-arm (cadence-hooks#691): the branch's in-flight
        // plan is modified but unstaged, and this commit takes only the index.
        if commit_takes_only_staged(command)
            && let Some(cwd) = input.cwd.as_deref()
            && let Some(plan) =
                cadence_hooks_session::plan_guards::unstaged_plan_at_commit(cwd, &stdout)
            // `git commit <pathspec>` takes the named paths' working-tree
            // content, and a pathspec is indistinguishable from a flag value
            // here — so a command that names the plan file at all stays silent.
            && !plan.rsplit('/').next().is_some_and(|name| command.contains(name))
        {
            if !msg.is_empty() {
                msg.push('\n');
            }
            msg.push_str(&format!(
                "living plan edited but not staged: {plan} is modified in the working tree and \
                 this commit will not include it. `git add {plan}` first so the tick rides the \
                 work commit instead of a follow-up. Advisory only.\n"
            ));
        }

        if msg.is_empty() {
            return CheckResult::allow();
        }
        CheckResult::nudge(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    // --- filter_untracked: pure function tests ---

    #[test]
    fn parses_untracked_files() {
        let porcelain = "?? src/new_file.rs\n?? README.md\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/new_file.rs", "README.md"]);
    }

    #[test]
    fn ignores_staged_files() {
        let porcelain = "A  src/added.rs\nM  src/modified.rs\n?? untracked.rs\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["untracked.rs"]);
    }

    #[test]
    fn filters_log_artifacts() {
        let porcelain = "?? build.log\n?? src/main.rs\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/main.rs"]);
    }

    #[test]
    fn filters_pyc_artifacts() {
        let porcelain = "?? __pycache__/module.pyc\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn filters_object_files() {
        let porcelain = "?? build/main.o\n?? build/lib.a\n?? build/lib.so\n?? build/lib.dylib\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn filters_tmp_and_cache() {
        let porcelain = "?? session.tmp\n?? data.cache\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    #[test]
    fn keeps_important_files() {
        let porcelain = "?? Cargo.toml\n?? src/lib.rs\n?? .gitignore\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn mixed_artifacts_and_important() {
        let porcelain = "?? src/new.rs\n?? build.log\n?? module.pyc\n?? README.md\n?? temp.tmp\n";
        let result = filter_untracked(porcelain);
        assert_eq!(result, vec!["src/new.rs", "README.md"]);
    }

    #[test]
    fn empty_output() {
        let result = filter_untracked("");
        assert!(result.is_empty());
    }

    #[test]
    fn only_artifacts() {
        let porcelain = "?? a.log\n?? b.tmp\n?? c.cache\n?? d.pyc\n?? e.class\n";
        let result = filter_untracked(porcelain);
        assert!(result.is_empty());
    }

    // --- run() guard clauses ---

    use cadence_hooks_core::test_builders::make_bash;

    #[test]
    fn no_command_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = WarnUntrackedFiles.run(&input);
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn non_git_command_allows() {
        let result = WarnUntrackedFiles.run(&make_bash("ls -la"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn git_status_allows() {
        let result = WarnUntrackedFiles.run(&make_bash("git status"));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn case_folded_git_commit_nudges_end_to_end() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;

        let dir = tempfile::tempdir().unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::write(dir.path().join("new.rs"), "fn main() {}\n").unwrap();

        for command in ["git commit -m x", "GIT commit -m x"] {
            let result =
                WarnUntrackedFiles.run(&make_bash_with_cwd(command, dir.path().to_str().unwrap()));
            assert_eq!(result.outcome, Outcome::Nudge, "{command}");
        }
    }

    // --- commit_takes_only_staged / plan-tick pre-arm (cadence-hooks#691) ---

    #[test]
    fn commit_takes_only_staged_table() {
        let cases = [
            ("git commit -m x", true),
            ("git commit -m \"fix -a thing\"", true),
            ("git commit --amend --no-edit", true),
            ("git commit -a -m x", false),
            ("git commit -am x", false),
            ("git commit --all -m x", false),
            ("git commit -i docs/x.md -m x", false),
            ("git commit --only docs/x.md -m x", false),
            ("git commit -m x -- docs/x.md", false),
            ("git add -A && git commit -m x", false),
            ("git add docs/plans/p.md; git commit -m x", false),
            ("git status", false),
            ("ls", false),
        ];
        for (command, want) in cases {
            assert_eq!(commit_takes_only_staged(command), want, "{command}");
        }
    }

    /// A repo on `feat/x` with a committed in-flight plan bound to it and one
    /// unrelated staged file, so a plain `git commit` has something to take.
    fn plan_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q", "-b", "feat/x"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::create_dir_all(dir.path().join("docs/plans")).unwrap();
        std::fs::write(
            dir.path().join("docs/plans/2026-09-29-p.md"),
            "---\nstatus: in-flight\nbranch: feat/x\n---\n\n- [ ] a\n- [ ] b\n",
        )
        .unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "init"]);
        std::fs::write(dir.path().join("work.rs"), "fn a() {}\n").unwrap();
        git(&["add", "work.rs"]);
        dir
    }

    fn tick_plan(dir: &Path) {
        std::fs::write(
            dir.join("docs/plans/2026-09-29-p.md"),
            "---\nstatus: in-flight\nbranch: feat/x\n---\n\n- [x] a\n- [ ] b\n",
        )
        .unwrap();
    }

    #[test]
    fn dirty_unstaged_plan_at_commit_nudges() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let dir = plan_repo();
        tick_plan(dir.path());
        let result = WarnUntrackedFiles.run(&make_bash_with_cwd(
            "git commit -m x",
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(result.outcome, Outcome::Nudge);
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("docs/plans/2026-09-29-p.md"), "{msg}");
        assert!(msg.contains("not staged"), "{msg}");
    }

    #[test]
    fn plan_pre_arm_stays_silent_when_it_should() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        // (label, setup, command)
        let dir = plan_repo();
        let cwd = dir.path().to_str().unwrap().to_string();
        let run = |cmd: &str| {
            WarnUntrackedFiles
                .run(&make_bash_with_cwd(cmd, &cwd))
                .outcome
        };

        // Clean plan: nothing dirty.
        assert_eq!(run("git commit -m x"), Outcome::Allow, "clean plan");

        tick_plan(dir.path());
        // Commit that folds the working tree in, or names the plan.
        for cmd in [
            "git commit -am x",
            "git commit --all -m x",
            "git add -A && git commit -m x",
            "git commit -m x docs/plans/2026-09-29-p.md",
        ] {
            assert_eq!(run(cmd), Outcome::Allow, "{cmd}");
        }

        // Plan already staged: it rides the commit.
        assert!(
            Command::new("git")
                .args(["add", "docs/plans/2026-09-29-p.md"])
                .current_dir(dir.path())
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(run("git commit -m x"), Outcome::Allow, "staged plan");
    }

    #[test]
    fn dirty_unstaged_plan_for_another_branch_stays_silent() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let dir = plan_repo();
        std::fs::write(
            dir.path().join("docs/plans/2026-09-29-p.md"),
            "---\nstatus: in-flight\nbranch: feat/other\n---\n\n- [x] a\n",
        )
        .unwrap();
        let result = WarnUntrackedFiles.run(&make_bash_with_cwd(
            "git commit -m x",
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(result.outcome, Outcome::Allow);
    }

    #[test]
    fn dirty_unstaged_plan_composes_with_the_untracked_warning() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let dir = plan_repo();
        tick_plan(dir.path());
        std::fs::write(dir.path().join("forgotten.rs"), "\n").unwrap();
        let result = WarnUntrackedFiles.run(&make_bash_with_cwd(
            "git commit -m x",
            dir.path().to_str().unwrap(),
        ));
        let msg = result.message.unwrap_or_default();
        assert!(msg.contains("?? forgotten.rs"), "{msg}");
        assert!(msg.contains("not staged"), "{msg}");
    }
}
