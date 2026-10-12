//! Refuse a local session's push to a cloud session's branch.
//!
//! Under the cloud/local coordination conventions (cameronsjo/cadence-ecosystem
//! `docs/research/2026-10-11-cloud-local-agent-coordination.md`), only cloud
//! sessions push to `claude/*` branches (`claude/project-thread-*`,
//! `claude/gambit-*`, and the rest of the namespace). A local session (one
//! where `CLAUDE_CODE_REMOTE` is not `true`) that pushes there overwrites work
//! a cloud session owns, so `guard-push-remote` runs this check after its
//! ownership verdict (cameronsjo/cadence-hooks#1367).
//!
//! Destinations are read from the same push walk the other push guards use
//! ([`push_locations`]): explicit refspecs, `--delete`, `--all`/`--mirror`,
//! a bare push under `push.default`, and pushes inside child scripts. A
//! destination the command text cannot show (`git push origin "$B"`, a glob
//! refspec, a configured `remote.<name>.push`) fails closed when the
//! repository holds any `claude/*` ref, local or
//! remote-tracking. A repository with no such ref has no cloud branch to
//! overwrite that this clone knows of, so blocking every variable-built push
//! there would cost ordinary scripts a false block for nothing.
//!
//! The escape is `CADENCE_ALLOW_CLOUD_BRANCH_PUSH` (truthy), read from Claude
//! Code's environment like `CADENCE_ALLOW_SOPS_DECRYPT`. It allows and records
//! a bypass row.

use cadence_hooks_core::push::{PushInvocation, push_locations};
use cadence_hooks_core::shell::{GitOutput, git_output_detailed, shell_fed_heredoc_bodies};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, CheckResult};

/// The returnable escape for a deliberate rescue push.
pub(crate) const ESCAPE_ENV: &str = "CADENCE_ALLOW_CLOUD_BRANCH_PUSH";

/// The branch-name prefix only cloud sessions push to.
const CLOUD_PREFIX: &str = "claude/";

/// What one refspec's destination reads as, from the command text alone.
#[derive(Debug, PartialEq, Eq)]
enum Destination {
    /// A literal remote ref name, as written.
    Named(String),
    /// The ref the current branch pushes to: a bare push, `HEAD`, or `@`.
    Current,
    /// Every local branch: `--all`, `--mirror`, or the `:` matching refspec.
    EveryBranch,
    /// The text does not show it: a `$`/backtick expansion, a glob, or a
    /// bare push whose refs come from config (`push.default=matching`,
    /// `remote.<name>.push`).
    Unreadable(String),
}

/// Is `name` a cloud branch (`claude/*`), in any spelling git accepts for a
/// destination under `refs/heads`?
fn is_cloud_ref(name: &str) -> bool {
    let name = name.strip_prefix("refs/").unwrap_or(name);
    let name = name.strip_prefix("heads/").unwrap_or(name);
    name.starts_with(CLOUD_PREFIX)
}

/// The destinations one push names. Pure: reads only the walk's output.
fn destinations(push: &PushInvocation) -> Vec<Destination> {
    let mut out = Vec::new();
    if push.all_or_mirror {
        out.push(Destination::EveryBranch);
    }
    for refspec in &push.refspecs {
        if refspec.implicit {
            // The walk marks a bare push `unresolved` when config or the
            // command decides its refs. A directory change it could not
            // follow sets the same flag; that push still reads as the current
            // branch of the directory the walk tracked, the place
            // guard-push-remote judges it too.
            out.push(if push.unresolved && !push.directory_unverified {
                Destination::Unreadable(refspec.raw.clone())
            } else {
                Destination::Current
            });
            continue;
        }
        // `Refspec::destination` drops the name of a `--delete <ref>`, so read
        // the remote side from the refspec as written.
        let body = refspec.raw.strip_prefix('+').unwrap_or(&refspec.raw);
        let dst = body.split_once(':').map_or(body, |(_, d)| d);
        out.push(if dst.contains(['$', '`', '*', '?', '[']) {
            Destination::Unreadable(refspec.raw.clone())
        } else if dst.is_empty() {
            Destination::EveryBranch
        } else if dst == "HEAD" || dst == "@" {
            Destination::Current
        } else {
            Destination::Named(dst.to_string())
        });
    }
    out
}

/// Cloud-branch refs this repository knows of, split by namespace.
struct CloudRefs {
    local: Vec<String>,
    any: Vec<String>,
}

/// A git probe's answer, reduced to what the verdict needs.
enum Probe<T> {
    Value(T),
    /// git answered that there is nothing here (not a repository, detached
    /// HEAD): git's own push fails or has no branch to send, so allow.
    Nothing,
    /// The guard's own infrastructure failed (timeout, no git): fail open
    /// (ADR-0001) and record the suppressed block.
    Unavailable,
}

fn cloud_refs(work_dir: &str) -> Probe<CloudRefs> {
    match git_output_detailed(
        work_dir,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/claude",
            "refs/remotes",
        ],
    ) {
        GitOutput::Ok(out) => {
            let mut refs = CloudRefs {
                local: Vec::new(),
                any: Vec::new(),
            };
            for name in out.lines() {
                if let Some(branch) = name.strip_prefix("refs/heads/") {
                    if branch.starts_with(CLOUD_PREFIX) {
                        refs.local.push(branch.to_string());
                        refs.any.push(name.to_string());
                    }
                } else if name
                    .strip_prefix("refs/remotes/")
                    .and_then(|rest| rest.split_once('/'))
                    .is_some_and(|(_, branch)| branch.starts_with(CLOUD_PREFIX))
                {
                    refs.any.push(name.to_string());
                }
            }
            Probe::Value(refs)
        }
        GitOutput::Failed => Probe::Nothing,
        GitOutput::Unavailable | GitOutput::TimedOut => Probe::Unavailable,
    }
}

/// What a push of the current branch can update.
enum Current {
    /// The branch's own name (`push.default` `simple`/`current`) and its
    /// upstream (`push.default=upstream`). Reading both is stricter than any
    /// one mode.
    Names(Vec<String>),
    /// `push.default=matching` or a `remote.<name>.push` refspec decides
    /// which refs a bare push sends, so the current branch does not say.
    ConfigDecides,
}

fn current_destinations(work_dir: &str) -> Probe<Current> {
    // `--get-regexp` matches the lowercased key, so `remote.origin.pushurl`
    // stays out: the pattern is anchored after `.push`.
    match git_output_detailed(
        work_dir,
        &[
            "config",
            "--get-regexp",
            r"^(push\.default|remote\..+\.push)$",
        ],
    ) {
        GitOutput::Ok(out) => {
            if out
                .lines()
                .any(|line| !line.starts_with("push.default ") || line.ends_with(" matching"))
            {
                return Probe::Value(Current::ConfigDecides);
            }
        }
        // Exit 1 is "no such key", the normal state.
        GitOutput::Failed => {}
        GitOutput::Unavailable | GitOutput::TimedOut => return Probe::Unavailable,
    }
    let branch = match git_output_detailed(work_dir, &["symbolic-ref", "-q", "--short", "HEAD"]) {
        GitOutput::Ok(b) if !b.is_empty() => b,
        GitOutput::Ok(_) | GitOutput::Failed => return Probe::Nothing,
        GitOutput::Unavailable | GitOutput::TimedOut => return Probe::Unavailable,
    };
    let key = format!("branch.{branch}.merge");
    let mut out = vec![branch];
    match git_output_detailed(work_dir, &["config", "--get", &key]) {
        GitOutput::Ok(merge) if !merge.is_empty() => out.push(merge),
        // Not configured is a normal state: no upstream to add.
        GitOutput::Ok(_) | GitOutput::Failed => {}
        GitOutput::Unavailable | GitOutput::TimedOut => return Probe::Unavailable,
    }
    Probe::Value(Current::Names(out))
}

/// Why a push was refused, for the message.
enum Refusal {
    /// The destination is a cloud branch.
    Destination(String),
    /// The destination cannot be read, and this repository holds cloud-branch refs.
    Unreadable { token: String, known: Vec<String> },
    /// The destination depends on repository state, and the walk cannot say
    /// which repository the push runs in.
    UnknownRepository(String),
}

fn block_message(refusal: &Refusal) -> String {
    let head = "🚫 git-guardrails: push to a cloud session's branch\n   ";
    let what = match refusal {
        Refusal::Destination(name) => format!("Destination: {name}\n   "),
        Refusal::Unreadable { token, known } => format!(
            "Destination cannot be read from the command: `{token}`\n   \
             This repository has cloud branches it could name: {}\n   ",
            known.join(", ")
        ),
        Refusal::UnknownRepository(token) => format!(
            "Destination `{token}` depends on a repository this command does not name \
             readably, so it cannot be checked.\n   "
        ),
    };
    format!(
        "{head}{what}\
         Only cloud sessions push to `{CLOUD_PREFIX}*` branches, and this is a local \
         session (CLAUDE_CODE_REMOTE is not `true`).\n   \
         Instead: leave a review comment on the branch's PR \
         (`gh pr review <n> --comment --body-file <file>`).\n   \
         Deliberate rescue: set {ESCAPE_ENV}=1 in Claude Code's environment (a personal \
         settings \"env\" block, or exported before launching the session). The hook reads \
         Claude Code's environment, not the command's, so an inline \
         `{ESCAPE_ENV}=1 git push …` prefix does nothing."
    )
}

/// More distinct directories than this needing a git probe are refused
/// rather than probed: the count is the command's to choose, and the probes
/// share the hook deadline with the ownership check.
const MAX_PROBED_DIRECTORIES: usize = 8;

/// Per-command judge, caching each directory's probes so a flood of bare
/// pushes in one repository costs one probe set, not one per push.
#[derive(Default)]
struct Judge {
    current: std::collections::HashMap<String, Probe<Current>>,
    refs: std::collections::HashMap<String, Probe<CloudRefs>>,
}

impl Judge {
    fn over_budget(&self, work_dir: &str) -> bool {
        let mut dirs: std::collections::HashSet<&str> =
            self.current.keys().map(String::as_str).collect();
        dirs.extend(self.refs.keys().map(String::as_str));
        !dirs.contains(work_dir) && dirs.len() >= MAX_PROBED_DIRECTORIES
    }

    /// Judge one push. `None` allows it.
    fn push(&mut self, push: &PushInvocation) -> Option<Refusal> {
        if push.dry_run {
            return None;
        }
        for dst in destinations(push) {
            let dst = match dst {
                Destination::Named(name) => {
                    if is_cloud_ref(&name) {
                        return Some(Refusal::Destination(name));
                    }
                    continue;
                }
                other => other,
            };
            if push.repository_unresolved || self.over_budget(&push.work_dir) {
                let token = match &dst {
                    Destination::Unreadable(t) => t.clone(),
                    Destination::EveryBranch => "--all".to_string(),
                    _ => "HEAD".to_string(),
                };
                return Some(Refusal::UnknownRepository(token));
            }
            let dst = match dst {
                Destination::Current => {
                    match self
                        .current
                        .entry(push.work_dir.clone())
                        .or_insert_with(|| current_destinations(&push.work_dir))
                    {
                        Probe::Value(Current::Names(names)) => {
                            if let Some(name) = names.iter().find(|n| is_cloud_ref(n)) {
                                return Some(Refusal::Destination(name.clone()));
                            }
                            continue;
                        }
                        Probe::Value(Current::ConfigDecides) => {
                            Destination::Unreadable("git push (refs set by config)".to_string())
                        }
                        Probe::Nothing => continue,
                        Probe::Unavailable => {
                            cadence_hooks_core::deadline::note_suppressed_block();
                            continue;
                        }
                    }
                }
                other => other,
            };
            let probe = self
                .refs
                .entry(push.work_dir.clone())
                .or_insert_with(|| cloud_refs(&push.work_dir));
            match probe {
                Probe::Value(found) => match dst {
                    Destination::Unreadable(token) if !found.any.is_empty() => {
                        return Some(Refusal::Unreadable {
                            token,
                            known: found.any.clone(),
                        });
                    }
                    Destination::EveryBranch if !found.local.is_empty() => {
                        return Some(Refusal::Destination(found.local[0].clone()));
                    }
                    _ => {}
                },
                Probe::Nothing => {}
                Probe::Unavailable => cadence_hooks_core::deadline::note_suppressed_block(),
            }
        }
        None
    }
}

/// The verdict for the pushes a command runs. `None` allows. `remote` and
/// `escape` are passed in so tests need no env mutation.
///
/// `pushes` is `guard-push-remote`'s own push walk ([`push_locations`] read
/// two ways), reused so a large command is walked once. That walk does not
/// read repository config, so [`current_destinations`] reads the two keys
/// that change what a bare push sends.
pub(crate) fn check(
    command: &str,
    cwd: &str,
    pushes: &[PushInvocation],
    remote: bool,
    escape: Option<&str>,
) -> Option<CheckResult> {
    if remote {
        return None;
    }
    let mut judge = Judge::default();
    let mut refusal = pushes.iter().find_map(|p| judge.push(p));
    // A heredoc a shell reads on stdin is a script too (guard-push-remote
    // reads its pushes the same way). The walk above does not include them.
    if refusal.is_none() {
        refusal = shell_fed_heredoc_bodies(command)
            .iter()
            .flat_map(|body| push_locations(body, cwd))
            .find_map(|p| judge.push(&p));
    }
    let refusal = refusal?;
    // Checked after a refusal is found, so an escape left set does not write
    // a bypass row for every unrelated push.
    if is_truthy(escape) {
        return Some(CheckResult::allow_bypassed(BypassProvenance::env_switch(
            ESCAPE_ENV,
        )));
    }
    Some(CheckResult::block(block_message(&refusal)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
    use cadence_hooks_core::{BypassKind, Outcome};
    use std::path::{Path, PathBuf};

    fn scratch_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cloud-branch-push-scratch")
    }

    /// A repo on `main` with an `origin` remote. No network: nothing pushes.
    fn repo(tag: &str) -> Scratch {
        let s = Scratch::new(&scratch_root(), tag);
        init_repo(s.path());
        git_in(
            s.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/cameronsjo/x.git",
            ],
        );
        s
    }

    fn dir(s: &Scratch) -> &str {
        s.path().to_str().unwrap()
    }

    /// [`check`] over the push walk alone, as `guard-push-remote` hands it
    /// (its second, per-segment reading only adds pushes).
    fn check_cmd(
        command: &str,
        cwd: &str,
        remote: bool,
        escape: Option<&str>,
    ) -> Option<CheckResult> {
        check(command, cwd, &push_locations(command, cwd), remote, escape)
    }

    fn outcome(command: &str, cwd: &str) -> Outcome {
        check_cmd(command, cwd, false, None).map_or(Outcome::Allow, |r| r.outcome)
    }

    // --- the pure reading ---

    #[test]
    fn cloud_ref_spellings() {
        for name in [
            "claude/project-thread-abc",
            "refs/heads/claude/project-thread-abc",
            "heads/claude/project-thread-1",
            "claude/gambit-skill-upkeep",
            "claude/output-styles-wngg07",
        ] {
            assert!(is_cloud_ref(name), "{name}");
        }
        for name in [
            "main",
            "claude",
            "claudette/x",
            "feat/claude/project-thread-1",
            "refs/tags/claude/project-thread-1",
            "refs/remotes/origin/claude/x",
        ] {
            assert!(!is_cloud_ref(name), "{name}");
        }
    }

    // --- literal destinations: no repository state needed ---

    #[test]
    fn literal_cloud_destinations_block() {
        let s = repo("literal");
        for cmd in [
            "git push origin claude/project-thread-abc",
            "git push origin HEAD:claude/project-thread-abc",
            "git push origin feat:refs/heads/claude/project-thread-abc",
            "git push --force origin +main:claude/project-thread-abc",
            "git push origin --delete claude/project-thread-abc",
            "git push origin :claude/project-thread-abc",
            "git push origin HEAD:claude/gambit-skill-upkeep",
            "git -C . push origin main:claude/project-thread-abc",
            "bash -c 'git push origin HEAD:claude/project-thread-abc'",
            "git push -u origin main && git push origin x:claude/project-thread-abc",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn ordinary_pushes_allow() {
        let s = repo("ordinary");
        for cmd in [
            "git push origin main",
            "git push -u origin feat/x",
            "git push origin HEAD:refs/heads/fix/y",
            "git push origin --delete old-branch",
            "git push --tags origin",
            "git push",
            "git push origin \"$BRANCH\"",
            "git push --all origin",
            "echo 'git push origin claude/project-thread-x'",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn dry_run_allows() {
        let s = repo("dry-run");
        assert_eq!(
            outcome("git push -n origin main:claude/project-thread-x", dir(&s)),
            Outcome::Allow
        );
    }

    // --- destinations read from repository state ---

    #[test]
    fn bare_push_from_a_cloud_branch_blocks() {
        let s = repo("bare-thread");
        git_in(
            s.path(),
            &["checkout", "-q", "-b", "claude/project-thread-7"],
        );
        for cmd in [
            "git push",
            "git push origin",
            "git push origin HEAD",
            "git push -u origin @",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn bare_push_whose_upstream_is_a_cloud_branch_blocks() {
        let s = repo("upstream-thread");
        git_in(s.path(), &["checkout", "-q", "-b", "rescue"]);
        git_in(s.path(), &["config", "branch.rescue.remote", "origin"]);
        git_in(
            s.path(),
            &[
                "config",
                "branch.rescue.merge",
                "refs/heads/claude/project-thread-7",
            ],
        );
        assert_eq!(outcome("git push", dir(&s)), Outcome::Block);
    }

    #[test]
    fn push_all_blocks_when_a_local_cloud_branch_exists() {
        let s = repo("all");
        git_in(s.path(), &["branch", "claude/project-thread-7"]);
        assert_eq!(outcome("git push --all origin", dir(&s)), Outcome::Block);
        assert_eq!(outcome("git push origin :", dir(&s)), Outcome::Block);
    }

    #[test]
    fn unreadable_destination_blocks_only_where_cloud_refs_exist() {
        let s = repo("unreadable");
        let cmd = "git push origin \"HEAD:$B\"";
        assert_eq!(outcome(cmd, dir(&s)), Outcome::Allow, "no cloud refs yet");

        // A remote-tracking cloud ref is enough: a fetched cloud branch is
        // exactly what an unreadable destination could overwrite.
        git_in(
            s.path(),
            &[
                "update-ref",
                "refs/remotes/origin/claude/project-thread-7",
                "HEAD",
            ],
        );
        for cmd in [
            cmd,
            "git push origin \"$B\"",
            "git push origin 'refs/heads/*:refs/heads/claude/*'",
            "git push origin \"$(git branch --show-current)\"",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
        assert_eq!(outcome("git push origin main", dir(&s)), Outcome::Allow);
    }

    #[test]
    fn push_default_matching_reads_as_unreadable() {
        let s = repo("matching");
        git_in(s.path(), &["config", "push.default", "matching"]);
        assert_eq!(outcome("git push", dir(&s)), Outcome::Allow);
        git_in(s.path(), &["branch", "claude/project-thread-7"]);
        assert_eq!(outcome("git push", dir(&s)), Outcome::Block);
    }

    #[test]
    fn a_configured_remote_push_refspec_reads_as_unreadable() {
        let s = repo("remote-push-config");
        git_in(
            s.path(),
            &[
                "config",
                "remote.origin.push",
                "refs/heads/main:refs/heads/claude/x",
            ],
        );
        git_in(
            s.path(),
            &["update-ref", "refs/remotes/origin/claude/x", "HEAD"],
        );
        assert_eq!(outcome("git push", dir(&s)), Outcome::Block);
        assert_eq!(outcome("git push origin main", dir(&s)), Outcome::Allow);
    }

    #[test]
    fn a_bare_push_flood_probes_its_directory_once() {
        let s = repo("flood");
        let command = "git push; ".repeat(2000);
        let before = cadence_hooks_core::shell::git_spawn_count();
        assert_eq!(outcome(&command, dir(&s)), Outcome::Allow);
        let spawns = cadence_hooks_core::shell::git_spawn_count() - before;
        assert!(spawns <= 3, "{spawns} git spawns for one directory");
    }

    #[test]
    fn too_many_probed_directories_are_refused() {
        let s = repo("many-dirs");
        let command: String = (0..=MAX_PROBED_DIRECTORIES)
            .map(|i| format!("git -C d{i} push; "))
            .collect();
        assert_eq!(outcome(&command, dir(&s)), Outcome::Block);
        let within: String = (0..MAX_PROBED_DIRECTORIES)
            .map(|i| format!("git -C d{i} push; "))
            .collect();
        assert_eq!(outcome(&within, dir(&s)), Outcome::Allow);
    }

    #[test]
    fn unknown_repository_blocks_a_state_dependent_push() {
        let s = repo("unknown-repo");
        assert_eq!(
            outcome("GIT_DIR=/elsewhere/.git git push", dir(&s)),
            Outcome::Block
        );
        assert_eq!(
            outcome("GIT_DIR=/elsewhere/.git git push origin main", dir(&s)),
            Outcome::Allow,
            "a literal destination needs no repository"
        );
    }

    #[test]
    fn not_a_repository_allows_a_bare_push() {
        let s = Scratch::outside_checkout(&scratch_root(), "not-a-repo");
        assert_eq!(outcome("git push", dir(&s)), Outcome::Allow);
    }

    // --- session kind and escape ---

    #[test]
    fn cloud_sessions_are_exempt() {
        let s = repo("cloud");
        assert!(
            check_cmd(
                "git push origin claude/project-thread-7",
                dir(&s),
                true,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn escape_allows_and_records_a_bypass() {
        let s = repo("escape");
        let r = check_cmd(
            "git push origin claude/project-thread-7",
            dir(&s),
            false,
            Some("1"),
        )
        .expect("a refused push with the escape set returns a verdict");
        assert_eq!(r.outcome, Outcome::Allow);
        let bypass = r.bypass.expect("the escape records a bypass row");
        assert_eq!(bypass.kind, BypassKind::EnvSwitch);
        assert_eq!(bypass.mechanism, ESCAPE_ENV);
    }

    #[test]
    fn escape_does_not_tag_an_unrelated_push() {
        let s = repo("escape-unrelated");
        assert!(check_cmd("git push origin main", dir(&s), false, Some("1")).is_none());
    }

    /// Through `guard-push-remote` itself: an owned remote passes the
    /// ownership check, and the cloud-branch check still blocks.
    #[test]
    fn guard_push_remote_runs_the_check_cmd() {
        use cadence_hooks_core::Check;
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let s = repo("wired");
        let env = [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("CLAUDE_CODE_REMOTE", None),
            (ESCAPE_ENV, None),
        ];
        crate::with_env(&env, || {
            let guard = crate::guard_push_remote::PushRemoteGuard;
            let run = |cmd: &str| guard.run(&make_bash_with_cwd(cmd, dir(&s))).outcome;
            assert_eq!(run("git push origin main"), Outcome::Allow);
            assert_eq!(
                run("git push origin main:claude/project-thread-7"),
                Outcome::Block
            );
        });
        crate::with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CLAUDE_CODE_REMOTE", Some("true")),
            ],
            || {
                let guard = crate::guard_push_remote::PushRemoteGuard;
                let cmd = "git push origin main:claude/project-thread-7";
                assert_eq!(
                    guard.run(&make_bash_with_cwd(cmd, dir(&s))).outcome,
                    Outcome::Allow,
                    "a cloud session may push its own branch"
                );
            },
        );
    }

    #[test]
    fn block_message_names_the_branch_the_alternative_and_the_escape() {
        let s = repo("message");
        let r = check_cmd(
            "git push origin claude/project-thread-7",
            dir(&s),
            false,
            None,
        )
        .unwrap();
        let msg = r.message.unwrap_or_default();
        assert!(msg.contains("claude/project-thread-7"), "{msg}");
        assert!(msg.contains("review comment"), "{msg}");
        assert!(msg.contains(ESCAPE_ENV), "{msg}");
    }
}
