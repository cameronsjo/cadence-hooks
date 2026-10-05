//! Warn about untracked files during git commit operations.
//!
//! Shells out to `git ls-files --others --exclude-standard` to detect
//! files that might have been forgotten. Filters out build artifacts.

use cadence_hooks_core::shell::{command_segments, command_word, strip_group_wrappers, tokenize};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::path::{Path, PathBuf};
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

/// Most untracked names one nudge lists; the rest are counted.
const MAX_LISTED_FILES: usize = 20;
/// Longest single name shown, in characters.
const MAX_FILE_DISPLAY: usize = 200;

/// The canonical root of the repo enclosing `dir` (a file read, no `git`).
fn canonical_repo_root(dir: &str) -> Option<PathBuf> {
    let state = cadence_hooks_core::gitstate::GitState::resolve(Path::new(dir))?;
    std::fs::canonicalize(state.repo_root).ok()
}

/// `git` in `root` with the repo-configured programs a read can trigger
/// switched off: `core.fsmonitor` names a hook git runs on index reads, and
/// the untracked cache would be written back into the repo.
fn hardened_git(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
    ]);
    cmd.current_dir(root);
    cmd
}

/// Stdout of a bounded git run, or `None` on any failure. Advisory: a
/// truncated or failed listing would otherwise produce a confident, short
/// list.
fn run_advisory_git(cmd: &mut Command) -> Option<String> {
    use cadence_hooks_core::shell::{GitSpawn, run_git_bounded};
    match run_git_bounded(cmd) {
        GitSpawn::Completed(out) if out.status.success() => {
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        GitSpawn::Completed(_)
        | GitSpawn::Truncated(_)
        | GitSpawn::SpawnFailed
        | GitSpawn::TimedOut => None,
    }
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

        // Judge the repo the command runs in: the payload cwd after a leading
        // `cd` chain, so `cd <nested> && git commit` from a meta-repo session
        // lists the nested repo's untracked files, not the meta-repo's
        // (cameronsjo/cadence-hooks#225). `command_repo_dir` only ever names
        // the session's own repo or one nested inside its tree, and only for
        // a `cd` that runs unconditionally; anything else leaves the guard
        // quiet — it only advises (ADR-0001).
        let cwd = input.cwd.as_deref();
        let dir = match cwd {
            Some(cwd) => match cadence_hooks_core::target_repo::command_repo_dir(command, cwd) {
                Some(dir) => dir,
                None => return CheckResult::allow(),
            },
            None => ".".to_string(),
        };
        let Some(repo_root) = canonical_repo_root(&dir) else {
            return CheckResult::allow();
        };

        // `ls-files --others` reads the index and the ignore rules without
        // refreshing the index, so no clean filter runs; fsmonitor and the
        // untracked cache are switched off, so no repo-configured program runs
        // either. Run at the root: `ls-files` lists only below its own cwd.
        let mut cmd = hardened_git(&repo_root);
        cmd.args([
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
        ]);
        let Some(listing) = run_advisory_git(&mut cmd) else {
            return CheckResult::allow();
        };
        let porcelain: String = listing.lines().map(|l| format!("?? {l}\n")).collect();
        let important = filter_untracked(&porcelain);

        let mut msg = String::new();
        if !important.is_empty() {
            let count = important.len();
            msg = format!("⚠️  Warning: {count} untracked file(s) detected\n\n");
            msg.push_str("These files may need to be included in your commit:\n");
            // Filenames come from the repo's working tree, so each is one
            // sanitized line and the list is capped.
            for file in important.iter().take(MAX_LISTED_FILES) {
                let file = cadence_hooks_core::display::sanitize_field(file, MAX_FILE_DISPLAY);
                msg.push_str(&format!("  ?? {file}\n"));
            }
            if count > MAX_LISTED_FILES {
                msg.push_str(&format!("  … {} more\n", count - MAX_LISTED_FILES));
            }
        }

        // The plan-tick pre-arm (cadence-hooks#691): the branch's in-flight
        // plan is modified but unstaged, and this commit takes only the index.
        // It needs `git status`, which refreshes the index and so can run a
        // repo's clean filter — so it runs only in the session's own checkout
        // (as it always has), never in a repo a `cd` moved to, and only over
        // `docs/plans`.
        let in_session_checkout = cwd
            .and_then(canonical_repo_root)
            .is_some_and(|session| session == repo_root);
        if in_session_checkout
            && commit_takes_only_staged(command)
            && repo_root.join("docs/plans").is_dir()
            && let Some(status) = run_advisory_git(hardened_git(&repo_root).args([
                "status",
                "--porcelain",
                "--untracked-files=no",
                "--",
                "docs/plans",
            ]))
            && let Some(plan) = cadence_hooks_session::plan_guards::unstaged_plan_at_commit(
                &repo_root.to_string_lossy(),
                &status,
            )
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

    /// Meta-repo `meta/` gitignoring `nested/`, an independent repo. Each has
    /// one untracked file of its own, so a nudge names the repo it judged.
    fn meta_with_nested(
        tag: &str,
    ) -> (
        cadence_hooks_core::git_fixtures::Scratch,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
        let s = Scratch::new(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/warn-untracked-scratch"),
            tag,
        );
        let meta = s.path().join("meta");
        let nested = meta.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        init_repo(&meta);
        std::fs::write(meta.join(".gitignore"), "nested/\n").unwrap();
        git_in(&meta, &["add", ".gitignore"]);
        git_in(&meta, &["commit", "-q", "-m", "ignore"]);
        init_repo(&nested);
        std::fs::write(meta.join("meta_only.rs"), "x").unwrap();
        std::fs::write(nested.join("nested_only.rs"), "x").unwrap();
        (s, meta, nested)
    }

    #[test]
    fn a_leading_cd_is_judged_against_the_repo_it_moves_into() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let (_s, meta, nested) = meta_with_nested("meta-cd");
        let m = meta.to_str().unwrap();
        let n = nested.to_str().unwrap();
        // (label, command, cwd, expected: None = allow, Some(file) = nudge naming it)
        let cases: Vec<(&str, String, &str, Option<&str>)> = vec![
            (
                "meta cwd, cd into the gitignored nested repo",
                "cd nested && git commit -m x".into(),
                m,
                Some("nested_only.rs"),
            ),
            (
                "meta cwd, no cd: the meta repo (unchanged)",
                "git commit -m x".into(),
                m,
                Some("meta_only.rs"),
            ),
            (
                "nested cwd, no cd: the nested repo (unchanged)",
                "git commit -m x".into(),
                n,
                Some("nested_only.rs"),
            ),
            (
                "nested cwd, cd out to the enclosing meta repo: outside the session tree, quiet",
                format!("cd {m} && git add -A"),
                n,
                None,
            ),
            (
                "meta cwd, a cd behind `false &&` may never run: quiet",
                "false && cd nested && git commit -m x".into(),
                m,
                None,
            ),
            (
                "cd into a missing dir: cannot name the repo, quiet",
                "cd nested/no-such && git commit -m x".into(),
                m,
                None,
            ),
        ];
        for (label, command, cwd, want) in cases {
            let result = WarnUntrackedFiles.run(&make_bash_with_cwd(&command, cwd));
            match want {
                None => assert_eq!(result.outcome, Outcome::Allow, "{label}"),
                Some(file) => {
                    assert_eq!(result.outcome, Outcome::Nudge, "{label}");
                    let msg = result.message.unwrap_or_default();
                    assert!(msg.contains(&format!("?? {file}")), "{label}: {msg}");
                    let other = if file == "meta_only.rs" {
                        "nested_only.rs"
                    } else {
                        "meta_only.rs"
                    };
                    assert!(
                        !msg.contains(other),
                        "{label}: judged the wrong repo: {msg}"
                    );
                }
            }
        }
    }

    /// A repo whose own config names a program git would run: `core.fsmonitor`
    /// (runs on an index read), or a clean filter on a modified tracked file
    /// (runs on an index refresh). Either touches `marker` when it runs.
    #[cfg(unix)]
    fn plant_exec_repo(dir: &std::path::Path, marker: &std::path::Path, kind: &str) {
        use cadence_hooks_core::git_fixtures::{git_in, init_repo};
        std::fs::create_dir_all(dir).unwrap();
        init_repo(dir);
        let touch = format!("touch '{}'", marker.display());
        match kind {
            "fsmonitor" => {
                std::fs::write(dir.join("f"), "x").unwrap();
                git_in(
                    dir,
                    &["config", "core.fsmonitor", &format!("{touch}; false")],
                );
            }
            _ => {
                std::fs::write(dir.join(".gitattributes"), "* filter=ev\n").unwrap();
                std::fs::write(dir.join("f"), "x").unwrap();
                git_in(dir, &["add", "."]);
                git_in(dir, &["commit", "-q", "-m", "seed"]);
                git_in(
                    dir,
                    &[
                        "config",
                        "filter.ev.clean",
                        &format!("sh -c \"{touch}; cat\""),
                    ],
                );
                // Stat-dirty, so a refresh would re-clean it.
                std::fs::write(dir.join("f"), "changed").unwrap();
            }
        }
        std::fs::write(dir.join("untracked.rs"), "x").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn no_repo_configured_program_runs_wherever_a_cd_points() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let (s, meta, nested) = meta_with_nested("exec");
        let m = meta.to_str().unwrap();
        // (label, planted repo, kind, command template: {} is the repo path)
        let cases = [
            (
                "fsmonitor repo outside the session",
                "out-fsmon",
                "fsmonitor",
                "cd {} && git commit -m x",
            ),
            (
                "filter repo outside the session",
                "out-filter",
                "filter",
                "cd {} && git commit -m x",
            ),
            (
                "fsmonitor repo behind false &&",
                "out-cond",
                "fsmonitor",
                "false && cd {} && git commit -m x",
            ),
            (
                "fsmonitor repo before ||",
                "out-or",
                "fsmonitor",
                "cd {} || exit; git commit -m x",
            ),
        ];
        for (label, name, kind, template) in cases {
            let marker = s.path().join(format!("{name}.PWNED"));
            let evil = s.path().join(name);
            plant_exec_repo(&evil, &marker, kind);
            let command = template.replace("{}", evil.to_str().unwrap());
            WarnUntrackedFiles.run(&make_bash_with_cwd(&command, m));
            assert!(!marker.exists(), "{label}: a planted program ran");
            // Control: the plant is live — a plain `git status` there fires it.
            Command::new("git")
                .arg("status")
                .current_dir(&evil)
                .output()
                .unwrap();
            assert!(marker.exists(), "{label}: control plant never fired");
        }
        // Inside the session tree the hook does run git — hardened, so neither
        // kind of planted program fires there either.
        for kind in ["fsmonitor", "filter"] {
            let marker = s.path().join(format!("nested-{kind}.PWNED"));
            let inner = nested.join(kind);
            plant_exec_repo(&inner, &marker, kind);
            std::fs::write(nested.join(".gitignore"), "fsmonitor/\nfilter/\n").unwrap();
            let command = format!("cd nested/{kind} && git commit -m x");
            let result = WarnUntrackedFiles.run(&make_bash_with_cwd(&command, m));
            assert!(!marker.exists(), "nested {kind}: a planted program ran");
            assert!(
                result
                    .message
                    .unwrap_or_default()
                    .contains("?? untracked.rs"),
                "nested {kind}: still judged the nested repo"
            );
        }
    }

    #[test]
    fn the_untracked_list_is_capped() {
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let (_s, meta, _nested) = meta_with_nested("cap");
        for i in 0..25 {
            std::fs::write(meta.join(format!("extra_{i:02}.rs")), "x").unwrap();
        }
        let result = WarnUntrackedFiles.run(&make_bash_with_cwd(
            "git commit -m x",
            meta.to_str().unwrap(),
        ));
        let msg = result.message.unwrap_or_default();
        assert_eq!(msg.matches("  ?? ").count(), MAX_LISTED_FILES, "{msg}");
        assert!(msg.contains("26 untracked file(s)"), "{msg}");
        assert!(msg.contains("… 6 more"), "{msg}");
    }
}
