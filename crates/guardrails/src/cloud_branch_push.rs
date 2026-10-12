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
//! ([`push_locations`]): explicit refspecs, `--delete`, a bare push under
//! `push.default` and `remote.<name>.push`, `--all`, and `--mirror`/`--prune`
//! (which delete remote branches the clone has no local copy of), in child
//! scripts and shell-fed heredocs too.
//!
//! A destination the walk cannot read from the text (`git push origin "$B"`,
//! a bare push after a `git checkout` in the same command, a refspec an
//! `xargs` appends) blocks when the command text names a `claude/` ref
//! anywhere, or when the current branch is one. Otherwise it is allowed:
//! almost every working clone has fetched cloud branches, so blocking every
//! variable-built push there would be a false block on ordinary scripts.
//!
//! The escape is `CADENCE_ALLOW_CLOUD_BRANCH_PUSH` (truthy), read from Claude
//! Code's environment like `CADENCE_ALLOW_SOPS_DECRYPT`. It allows and records
//! a bypass row.

use std::collections::HashMap;
use std::sync::LazyLock;

use cadence_hooks_core::push::{PushInvocation, push_locations};
use cadence_hooks_core::shell::{
    GitOutput, git_output_detailed, shell_fed_heredoc_bodies, unescape_word,
};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, CheckResult};
use regex::Regex;

/// The returnable escape for a deliberate rescue push.
pub(crate) const ESCAPE_ENV: &str = "CADENCE_ALLOW_CLOUD_BRANCH_PUSH";

/// The branch-name prefix only cloud sessions push to.
const CLOUD_PREFIX: &str = "claude/";

/// A `claude/` ref named anywhere in the command: `claude/x`, `origin/claude/x`,
/// `refs/heads/claude/x`, `HEAD:claude/x`. A path segment such as
/// `.claude/worktrees` does not count: a word character, `.` or `-` before it
/// makes it part of another name.
static NAMES_CLOUD_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^A-Za-z0-9._-])claude/").expect("pattern should compile"));

/// Substitutions that print the current branch, read as the current branch
/// rather than as an unreadable destination.
const CURRENT_BRANCH_SUBSTITUTIONS: &[&str] = &[
    "$(git branch --show-current)",
    "$(git rev-parse --abbrev-ref HEAD)",
    "$(git symbolic-ref --short HEAD)",
    "`git branch --show-current`",
    "`git rev-parse --abbrev-ref HEAD`",
    "`git symbolic-ref --short HEAD`",
];

/// What one push's destination reads as, from the walk's output alone.
#[derive(Debug, PartialEq, Eq)]
enum Destination {
    /// A literal remote ref name, as written.
    Named(String),
    /// An explicit `HEAD`, `@`, or current-branch substitution: git pushes
    /// it to the current branch's own name.
    CurrentName,
    /// A bare push: `push.default` and `remote.<name>.push` decide.
    Bare,
    /// Every local branch the pattern covers: `--all`, the `:` matching
    /// refspec, a glob.
    EveryBranch,
    /// `--mirror` or `--prune`: remote branches with no local counterpart
    /// are deleted.
    Deletes,
    /// The text does not show it: a `$`/backtick expansion, or a bare push
    /// whose refs the command's own `-c`/`GIT_CONFIG_*` decide.
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
    if push.mirror || push.prune {
        out.push(Destination::Deletes);
    }
    if push.all_or_mirror {
        out.push(Destination::EveryBranch);
    }
    let mut refspecs = push.refspecs.iter();
    while let Some(refspec) = refspecs.next() {
        if refspec.implicit {
            // The walk marks a bare push `unresolved` when the command's own
            // config decides its refs. A directory change it could not follow
            // sets the same flag; that push still reads as a bare push in the
            // directory the walk tracked, where guard-push-remote judges it.
            out.push(if push.unresolved && !push.directory_unverified {
                Destination::Unreadable(refspec.raw.clone())
            } else {
                Destination::Bare
            });
            continue;
        }
        // `git push origin tag <name>` pushes `refs/tags/<name>`.
        if refspec.raw == "tag" {
            refspecs.next();
            continue;
        }
        // `Refspec::destination` drops the name of a `--delete <ref>`, so read
        // the remote side from the refspec as written, then remove the
        // shell's quoting the way it reaches git.
        let body = refspec.raw.strip_prefix('+').unwrap_or(&refspec.raw);
        let raw_dst = body.split_once(':').map_or(body, |(_, d)| d);
        let dst = unescape_word(raw_dst);
        let bare_dst = dst.strip_prefix("refs/heads/").unwrap_or(&dst);
        out.push(if CURRENT_BRANCH_SUBSTITUTIONS.contains(&bare_dst) {
            Destination::CurrentName
        } else if dst.contains(['$', '`']) {
            Destination::Unreadable(refspec.raw.clone())
        } else if dst.is_empty() || (dst.contains(['*', '?', '[']) && !is_cloud_ref(&dst)) {
            Destination::EveryBranch
        } else if dst == "HEAD" || dst == "@" {
            Destination::CurrentName
        } else {
            Destination::Named(dst.into_owned())
        });
    }
    out
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

/// Cloud-branch refs this repository knows of.
struct CloudRefs {
    /// Local branches under `refs/heads/claude/`.
    local: Vec<String>,
    /// Those plus remote-tracking ones (`refs/remotes/<remote>/claude/…`).
    any: Vec<String>,
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
                } else if name.strip_prefix("refs/remotes/").is_some_and(|rest| {
                    // A remote name may itself contain `/`, so any segment
                    // boundary can start the branch.
                    rest.match_indices('/')
                        .any(|(i, _)| rest[i + 1..].starts_with(CLOUD_PREFIX))
                }) {
                    refs.any.push(name.to_string());
                }
            }
            Probe::Value(refs)
        }
        GitOutput::Failed => Probe::Nothing,
        GitOutput::Unavailable | GitOutput::TimedOut => Probe::Unavailable,
    }
}

/// The current branch and the config that decides what a bare push sends.
struct Head {
    branch: String,
    /// `branch.<b>.merge`, pushed to under `push.default=upstream`.
    upstream: Option<String>,
    push_default: Option<String>,
    /// Every `remote.<name>.push` refspec value.
    remote_push: Vec<String>,
}

fn head(work_dir: &str) -> Probe<Head> {
    let mut push_default = None;
    let mut remote_push = Vec::new();
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
            for line in out.lines() {
                let (key, value) = line.split_once(' ').unwrap_or((line, ""));
                if key == "push.default" {
                    push_default = Some(value.to_ascii_lowercase());
                } else {
                    remote_push.push(value.to_string());
                }
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
    let upstream = match git_output_detailed(work_dir, &["config", "--get", &key]) {
        GitOutput::Ok(merge) if !merge.is_empty() => Some(merge),
        // Not configured is a normal state: no upstream.
        GitOutput::Ok(_) | GitOutput::Failed => None,
        GitOutput::Unavailable | GitOutput::TimedOut => return Probe::Unavailable,
    };
    Probe::Value(Head {
        branch,
        upstream,
        push_default,
        remote_push,
    })
}

/// Why a push was refused, for the message.
enum Refusal {
    /// The destination is a cloud branch.
    Destination(String),
    /// The destination cannot be read, and the command names a cloud ref.
    NamedInText(String),
    /// `--mirror`/`--prune` would delete remote cloud branches.
    Deletes(Vec<String>),
    /// The destination depends on repository state, and the walk cannot say
    /// which repository the push runs in.
    UnknownRepository(String),
}

fn block_message(refusal: &Refusal) -> String {
    let head = "🚫 git-guardrails: push to a cloud session's branch\n   ";
    let what = match refusal {
        Refusal::Destination(name) => format!("Destination: {name}\n   "),
        Refusal::NamedInText(token) => format!(
            "Destination `{token}` is decided when the command runs, and the command \
             names a `{CLOUD_PREFIX}` ref. If the push does not go to a cloud branch, \
             run it as its own command, after any branch switch.\n   "
        ),
        Refusal::Deletes(known) => format!(
            "`--mirror`/`--prune` deletes remote branches with no local copy, and this \
             repository knows cloud branches: {}\n   ",
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
struct Judge {
    /// The command names a `claude/` ref somewhere ([`NAMES_CLOUD_REF`]).
    names_cloud_ref: bool,
    heads: HashMap<String, Probe<Head>>,
    refs: HashMap<String, Probe<CloudRefs>>,
}

impl Judge {
    fn new(command: &str) -> Self {
        Self {
            names_cloud_ref: NAMES_CLOUD_REF.is_match(command),
            heads: HashMap::new(),
            refs: HashMap::new(),
        }
    }

    fn over_budget(&self, work_dir: &str) -> bool {
        let mut dirs: std::collections::HashSet<&str> =
            self.heads.keys().map(String::as_str).collect();
        dirs.extend(self.refs.keys().map(String::as_str));
        !dirs.contains(work_dir) && dirs.len() >= MAX_PROBED_DIRECTORIES
    }

    fn head(&mut self, work_dir: &str) -> &Probe<Head> {
        self.heads
            .entry(work_dir.to_string())
            .or_insert_with(|| head(work_dir))
    }

    fn refs(&mut self, work_dir: &str) -> &Probe<CloudRefs> {
        self.refs
            .entry(work_dir.to_string())
            .or_insert_with(|| cloud_refs(work_dir))
    }

    /// Does any local cloud branch exist in `work_dir`?
    fn local_cloud_branch(&mut self, work_dir: &str) -> Option<Refusal> {
        match self.refs(work_dir) {
            Probe::Value(found) => found.local.first().map(|b| Refusal::Destination(b.clone())),
            Probe::Nothing => None,
            Probe::Unavailable => {
                cadence_hooks_core::deadline::note_suppressed_block();
                None
            }
        }
    }

    /// Judge one push. `None` allows it.
    fn push(&mut self, push: &PushInvocation) -> Option<Refusal> {
        if push.dry_run {
            return None;
        }
        let dir = push.work_dir.as_str();
        for dst in destinations(push) {
            if let Destination::Named(name) = &dst {
                if is_cloud_ref(name) {
                    return Some(Refusal::Destination(name.clone()));
                }
                continue;
            }
            // Every other destination is decided when the command runs: a
            // branch switch, a variable, or a runner's appended argument can
            // make it a cloud branch the walk never sees. A `claude/` ref in
            // the text is the one sign of that the text can give.
            if self.names_cloud_ref {
                let token = match &dst {
                    Destination::Unreadable(t) => t.clone(),
                    Destination::EveryBranch | Destination::Deletes => "--all".to_string(),
                    _ => "HEAD".to_string(),
                };
                return Some(Refusal::NamedInText(token));
            }
            if push.repository_unresolved || self.over_budget(dir) {
                let token = match &dst {
                    Destination::Unreadable(t) => t.clone(),
                    Destination::EveryBranch | Destination::Deletes => "--all".to_string(),
                    _ => "HEAD".to_string(),
                };
                return Some(Refusal::UnknownRepository(token));
            }
            let refusal = match dst {
                Destination::Named(_) => None,
                Destination::CurrentName | Destination::Unreadable(_) => match self.head(dir) {
                    // `"$B"` is most often the current branch, so an
                    // unreadable destination is judged as one.
                    Probe::Value(h) if is_cloud_ref(&h.branch) => {
                        Some(Refusal::Destination(h.branch.clone()))
                    }
                    Probe::Value(_) | Probe::Nothing => None,
                    Probe::Unavailable => {
                        cadence_hooks_core::deadline::note_suppressed_block();
                        None
                    }
                },
                Destination::Bare => {
                    let (names, every_branch) = match self.head(dir) {
                        Probe::Value(h) => {
                            if let Some(v) = h.remote_push.iter().find(|v| v.contains(CLOUD_PREFIX))
                            {
                                return Some(Refusal::Destination(v.clone()));
                            }
                            let mut names = vec![h.branch.clone()];
                            if matches!(h.push_default.as_deref(), Some("upstream" | "tracking"))
                                && let Some(up) = &h.upstream
                            {
                                names.push(up.clone());
                            }
                            (
                                names,
                                !h.remote_push.is_empty()
                                    || h.push_default.as_deref() == Some("matching"),
                            )
                        }
                        Probe::Nothing => (Vec::new(), false),
                        Probe::Unavailable => {
                            cadence_hooks_core::deadline::note_suppressed_block();
                            (Vec::new(), false)
                        }
                    };
                    if let Some(name) = names.into_iter().find(|n| is_cloud_ref(n)) {
                        Some(Refusal::Destination(name))
                    } else if every_branch {
                        self.local_cloud_branch(dir)
                    } else {
                        None
                    }
                }
                Destination::EveryBranch => self.local_cloud_branch(dir),
                Destination::Deletes => match self.refs(dir) {
                    Probe::Value(found) if !found.any.is_empty() => {
                        Some(Refusal::Deletes(found.any.clone()))
                    }
                    Probe::Value(_) | Probe::Nothing => None,
                    Probe::Unavailable => {
                        cadence_hooks_core::deadline::note_suppressed_block();
                        None
                    }
                },
            };
            if refusal.is_some() {
                return refusal;
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
/// read repository config, so [`head`] reads the keys that change what a bare
/// push sends.
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
    let mut judge = Judge::new(command);
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

    /// The rescue flow: `git checkout -b rescue origin/claude/…` sets the
    /// upstream to the cloud branch. git pushes `HEAD` to `rescue`, and a
    /// bare push under `simple` refuses the name mismatch, so only
    /// `push.default=upstream` sends it to the cloud branch.
    #[test]
    fn an_upstream_cloud_branch_blocks_only_under_push_default_upstream() {
        let s = repo("upstream-cloud");
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
        for cmd in ["git push", "git push -u origin HEAD", "git push origin @"] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Allow, "{cmd}");
        }
        git_in(s.path(), &["config", "push.default", "upstream"]);
        assert_eq!(outcome("git push", dir(&s)), Outcome::Block);
        assert_eq!(
            outcome("git push -u origin HEAD", dir(&s)),
            Outcome::Allow,
            "an explicit HEAD still goes to the branch's own name"
        );
    }

    #[test]
    fn push_all_blocks_when_a_local_cloud_branch_exists() {
        let s = repo("all");
        git_in(s.path(), &["branch", "claude/project-thread-7"]);
        assert_eq!(outcome("git push --all origin", dir(&s)), Outcome::Block);
        assert_eq!(outcome("git push origin :", dir(&s)), Outcome::Block);
    }

    /// Every working clone has fetched cloud branches, so an unreadable
    /// destination is judged by the text and the current branch, not by
    /// whether cloud refs exist.
    #[test]
    fn unreadable_destinations_in_a_clone_with_fetched_cloud_refs() {
        let s = repo("unreadable");
        git_in(
            s.path(),
            &[
                "update-ref",
                "refs/remotes/origin/claude/project-thread-7",
                "HEAD",
            ],
        );
        for cmd in [
            "git push origin \"$B\"",
            "git push origin \"HEAD:$B\"",
            "git push -u origin \"$(git branch --show-current)\"",
            "BR=$(git branch --show-current); git push -u origin \"$BR\"",
            "git push --no-follow-tags origin \"$SHA:refs/heads/$BRANCH\"",
            "git push --all origin",
            "git push origin main",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Allow, "{cmd}");
        }
        for cmd in [
            "B=claude/project-thread-x; git push origin \"HEAD:$B\"",
            "for b in claude/project-thread-x; do git push origin \"$b\"; done",
            "git push origin 'refs/heads/*:refs/heads/claude/*'",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
        git_in(
            s.path(),
            &["checkout", "-q", "-b", "claude/project-thread-7"],
        );
        for cmd in [
            "git push origin \"$B\"",
            "git push -u origin \"$(git branch --show-current)\"",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
    }

    #[test]
    fn mirror_and_prune_block_where_remote_cloud_branches_are_known() {
        let s = repo("mirror-prune");
        for cmd in ["git push --mirror origin", "git push --all --prune origin"] {
            assert_eq!(
                outcome(cmd, dir(&s)),
                Outcome::Allow,
                "no cloud refs: {cmd}"
            );
        }
        git_in(
            s.path(),
            &[
                "update-ref",
                "refs/remotes/origin/claude/project-thread-7",
                "HEAD",
            ],
        );
        for cmd in [
            "git push --mirror origin",
            "git push --all --prune origin",
            "git push --prune origin 'refs/heads/*:refs/heads/*'",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
        assert_eq!(outcome("git push --all origin", dir(&s)), Outcome::Allow);
    }

    #[test]
    fn a_remote_name_with_a_slash_still_counts_its_cloud_refs() {
        let s = repo("slash-remote");
        git_in(
            s.path(),
            &["update-ref", "refs/remotes/my/fork/claude/x", "HEAD"],
        );
        assert_eq!(
            outcome("git push --mirror my/fork", dir(&s)),
            Outcome::Block
        );
    }

    /// A branch switch, a runner's appended argument, or an alias decides the
    /// destination when the command runs; a `claude/` ref in the text is what
    /// gives it away.
    #[test]
    fn a_cloud_ref_named_beside_a_runtime_destination_blocks() {
        let s = repo("text-names");
        for cmd in [
            "git checkout claude/project-thread-7 && git push",
            "git switch claude/project-thread-7 && git push origin HEAD",
            "git checkout -b claude/project-thread-7 origin/claude/project-thread-7 && git push -f",
            "git branch -r | grep claude/ | sed 's|origin/||' | xargs git push origin --delete",
            "printf 'claude/project-thread-7\\n' | xargs -n1 git push origin --delete",
            "echo claude/project-thread-x | xargs git push origin",
            "git -c alias.p='push origin main:claude/x' p",
            "git -c remote.origin.push=HEAD:refs/heads/claude/x push",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Block, "{cmd}");
        }
        for cmd in [
            "git checkout -b feat/x && git push -u origin HEAD",
            "cd .claude/worktrees/x && git push",
            "git push origin main && echo done",
        ] {
            assert_eq!(outcome(cmd, dir(&s)), Outcome::Allow, "{cmd}");
        }
    }

    #[test]
    fn quoting_and_tag_spellings() {
        let s = repo("spellings");
        assert_eq!(
            outcome("git push origin clau\\de/project-thread-7", dir(&s)),
            Outcome::Block
        );
        assert_eq!(
            outcome("git push origin \"HEAD:claude/project-thread-7\"", dir(&s)),
            Outcome::Block
        );
        assert_eq!(
            outcome("git push origin tag claude/v1", dir(&s)),
            Outcome::Allow,
            "`tag <name>` pushes refs/tags/<name>"
        );
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

    /// An escaped refusal keeps the ownership verdict, nudge included, and
    /// adds its bypass row to it.
    #[test]
    fn the_escape_keeps_the_ownership_verdict() {
        use cadence_hooks_core::Check;
        use cadence_hooks_core::test_builders::make_bash_with_cwd;
        let s = repo("escape-wired");
        let env = [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            ("CLAUDE_CODE_REMOTE", None),
            (ESCAPE_ENV, Some("1")),
        ];
        crate::with_env(&env, || {
            let guard = crate::guard_push_remote::PushRemoteGuard;
            let r = guard.run(&make_bash_with_cwd(
                "git push origin main:claude/project-thread-7",
                dir(&s),
            ));
            assert_eq!(r.outcome, Outcome::Allow);
            assert_eq!(r.bypass.map(|b| b.mechanism).as_deref(), Some(ESCAPE_ENV));
            let r = guard.run(&make_bash_with_cwd(
                "cd \"$D\" && git push origin main:claude/project-thread-7",
                dir(&s),
            ));
            assert_eq!(r.outcome, Outcome::Nudge, "the directory nudge survives");
            assert_eq!(r.bypass.map(|b| b.mechanism).as_deref(), Some(ESCAPE_ENV));
        });
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
