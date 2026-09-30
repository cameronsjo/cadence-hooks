//! Block a `git push` that would publish a secret (cameronsjo/cadence-hooks#890,
//! the guard half of #237).
//!
//! The entry posture makes push a default, unprompted action, which removes the
//! last informal checkpoint between a committed secret and public history.
//! This guard is the mechanical replacement: it scans the commits a push would
//! publish and refuses when one adds a secret-named file or a credential token.
//!
//! **Trigger and range come from core.** [`push_invocations`] finds every push
//! the command runs (wrappers, `-C`, substitutions, refspecs). This module owns
//! only the range and the scan. The range for a named source is
//! `git rev-list <src> --not --remotes` (positive ref BEFORE `--not`: the other
//! order negates the ref too and scans nothing). `--all`/`--mirror` widen to
//! every ref; `--tags` adds every tag, because a tag can pin a commit no branch
//! reaches.
//!
//! **Scan.** One `git log -p -U0 --no-walk` over the outbound commits, so a
//! secret added and then removed inside the range is still seen (a net diff
//! misses it). Merge commits use `--cc`, which shows exactly the content a merge
//! introduces that no parent had. Content goes through
//! [`crate::credential_scan`] (the #1022 token shapes) and
//! [`scan_secret_values`]; names go through [`is_blocked`]. The block message
//! carries short sha, path and pattern name, never the value.
//!
//! **Fails CLOSED, everywhere a push was detected.** Unlike most guards this one
//! never reads "git said nothing useful" as "nothing to push": an unresolved
//! invocation, an unreadable or unsafe source, a failed, unavailable or
//! timed-out git spawn, a range over [`MAX_COMMITS`], a patch over
//! [`MAX_LOG_BYTES`], too many refspecs or tags, an unparseable diff header — all
//! block, and the message says which. Only a genuinely empty range allows.
//!
//! **Bounded.** Every git spawn goes through `run_bounded_capped` (process-group
//! kill, stdout cap, shared hook deadline). The commit cap is applied to git
//! itself (`rev-list -n`), so an entire first-push history is never buffered.
//!
//! **Deliberately allowed** (each documented, none silent):
//! - `--dry-run`/`-n` pushes and pure deletions (nothing is published);
//! - commits already reachable from ANY remote-tracking ref (`--remotes` spans
//!   every remote, so a commit only on a fork is treated as published);
//! - added lines under a `cadence-hooks` path component or a safe-template
//!   name (`.example`, `.sample`, `.template`, `.test`), so fixture keys do not
//!   block a push — the same exemption `prevent-secret-writes` grants;
//! - deleting a secret-named file (removal publishes no content);
//! - secrets outside the corpus (no entropy scan; token *grammar* only).
//!
//! The one escape is [`ESCAPE_ENV`], read from the hook's environment, which
//! allows AND records a bypass row.

use crate::credential_scan;
use crate::secret_patterns::{
    is_blocked, is_safe_template, is_secret_scan_exempt, scan_secret_values,
};
use cadence_hooks_core::deadline::{self, BudgetState};
use cadence_hooks_core::push::{PushInvocation, is_safe_ref, push_invocations};
use cadence_hooks_core::shell::{GitSpawn, run_bounded_capped};
use cadence_hooks_core::worktree::is_truthy;
use cadence_hooks_core::{BypassProvenance, Check, CheckResult, HookInput};
use std::process::Command;
use std::time::Duration;

/// The per-invocation acknowledgement: set truthy in the hook's environment.
const ESCAPE_ENV: &str = "CADENCE_ALLOW_SECRET_PUSH";

/// Most outbound commits scanned; a larger range blocks.
const MAX_COMMITS: usize = 200;
/// Most patch bytes read; a larger patch blocks.
const MAX_LOG_BYTES: usize = 8 << 20;
/// Most refspec sources one push may name before the guard refuses to model it.
const MAX_SOURCES: usize = 16;
/// Most bytes of tag-object text read.
const MAX_TAG_BYTES: usize = 1 << 20;
/// Most findings named in one message.
const MAX_HITS: usize = 5;
/// Ceiling for one spawn, under the shared hook deadline.
const SPAWN_CAP: Duration = Duration::from_millis(2000);

/// Decides, from the ABSOLUTE path, whether the content scan is skipped.
type Exempt = fn(&str) -> bool;

/// One git answer, with the four outcomes kept apart.
enum Git {
    Ok(String),
    /// The stdout cap was reached.
    Capped,
    /// git ran and exited non-zero.
    Failed,
    /// Could not spawn, or the deadline expired.
    Down,
}

fn git(work_dir: &str, args: &[&str], max_stdout: usize) -> Git {
    let timeout = match deadline::state() {
        BudgetState::Armed(left) if left.is_zero() => {
            deadline::note_hit();
            return Git::Down;
        }
        BudgetState::Armed(left) => left.min(SPAWN_CAP),
        BudgetState::Unarmed(cap) => cap.min(SPAWN_CAP),
        BudgetState::Disabled => SPAWN_CAP,
    };
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(work_dir).args(args);
    match run_bounded_capped(&mut cmd, timeout, Some(max_stdout)) {
        GitSpawn::Completed(out) if out.status.success() => {
            Git::Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        GitSpawn::Completed(_) => Git::Failed,
        GitSpawn::Truncated(out) if !out.status.success() => Git::Failed,
        GitSpawn::Truncated(_) => Git::Capped,
        GitSpawn::SpawnFailed | GitSpawn::TimedOut => Git::Down,
    }
}

/// Why the push cannot be allowed.
enum Stop {
    /// The range could not be fully scanned.
    Refused(String),
    /// Findings, newest commit first.
    Found(Vec<Hit>),
}

struct Hit {
    sha: String,
    path: String,
    what: String,
}

/// Printable, bounded rendering of attacker-controlled text.
fn sane(text: &str) -> String {
    text.chars()
        .take(120)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The ref names a push's sources resolve through, plus what else widens it.
struct Range {
    /// Refspec sources, each vetted by [`is_safe_ref`].
    sources: Vec<String>,
    /// `--all`/`--mirror`.
    all: bool,
    /// `--tags`.
    tags: bool,
}

fn range_of(inv: &PushInvocation) -> Result<Option<Range>, Stop> {
    let mut sources: Vec<String> = Vec::new();
    for spec in inv.refspecs.iter().filter(|s| !s.is_delete) {
        let Some(source) = spec.source.as_deref() else {
            return Err(Stop::Refused(format!(
                "could not read the source of refspec `{}`",
                sane(&spec.raw)
            )));
        };
        if !is_safe_ref(source) {
            return Err(Stop::Refused(format!(
                "refspec source `{}` is not a plain ref name (revision expressions and globs \
                 cannot be scanned safely)",
                sane(source)
            )));
        }
        if !sources.iter().any(|s| s == source) {
            sources.push(source.to_string());
        }
    }
    if sources.len() > MAX_SOURCES {
        return Err(Stop::Refused(format!(
            "the push names {} refs, over the {MAX_SOURCES} this guard will model",
            sources.len()
        )));
    }
    if sources.is_empty() && !inv.all_or_mirror && !inv.tags {
        return Ok(None); // nothing but deletions: nothing is published
    }
    Ok(Some(Range {
        sources,
        all: inv.all_or_mirror,
        tags: inv.tags,
    }))
}

/// The outbound commit shas (newest first), capped. Second value: the range
/// held more than [`MAX_COMMITS`].
fn outbound(work_dir: &str, range: &Range) -> Result<(Vec<String>, bool), Stop> {
    let limit = (MAX_COMMITS + 1).to_string();
    let mut args: Vec<&str> = vec!["rev-list", "-n", &limit];
    if range.all {
        args.push("--all");
    } else {
        for s in &range.sources {
            args.push(s);
        }
        if range.tags {
            args.push("--tags");
        }
    }
    args.extend(["--not", "--remotes", "--"]);
    match git(work_dir, &args, (MAX_COMMITS + 2) * 66) {
        Git::Ok(text) => {
            let mut shas: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            let over = shas.len() > MAX_COMMITS;
            shas.truncate(MAX_COMMITS);
            Ok((shas, over))
        }
        Git::Capped => Ok((Vec::new(), true)),
        Git::Failed => Err(Stop::Refused(format!(
            "git could not resolve the outbound range for {}",
            describe(range)
        ))),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out while resolving the outbound range".into(),
        )),
    }
}

fn describe(range: &Range) -> String {
    if range.all {
        "--all/--mirror".to_string()
    } else if range.sources.is_empty() {
        "--tags".to_string()
    } else {
        format!(
            "`{}`",
            range
                .sources
                .iter()
                .map(|s| sane(s))
                .collect::<Vec<_>>()
                .join("`, `")
        )
    }
}

/// Scan text with both corpora; the first pattern name, never the value.
fn scan_text(text: &str) -> Option<String> {
    if let Some(hit) = credential_scan::scan(text).first() {
        return Some(hit.kind.to_string());
    }
    scan_secret_values(text).map(str::to_string)
}

/// The path git printed in a `diff --git a/P b/P` header (no-renames, forced
/// `a/`/`b/` prefixes, so both sides are the same path). `None` when it cannot
/// be read — the caller blocks.
fn header_path(rest: &str) -> Option<String> {
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut end = None;
        let mut escaped = false;
        for (i, c) in quoted.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let inner = &quoted[..end?];
        return inner.strip_prefix("a/").map(unquote);
    }
    let len = rest.len().checked_sub(5)?;
    if len == 0 || len % 2 != 0 {
        return None;
    }
    let path = rest.get(2..2 + len / 2)?;
    (rest.starts_with("a/") && rest.get(2 + len / 2..)? == format!(" b/{path}"))
        .then(|| path.to_string())
}

fn unquote(s: &str) -> String {
    s.replace("\\\"", "\"").replace("\\\\", "\\")
}

/// Path of a combined-diff header (`diff --cc P`), quotes stripped.
fn combined_path(rest: &str) -> String {
    match rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => unquote(inner),
        None => rest.to_string(),
    }
}

#[derive(Default)]
struct FileState {
    path: Option<String>,
    unreadable: bool,
    deleted: bool,
    added: String,
}

/// Judge one commit's patch text (the output of the `git log -p` pass).
fn scan_patch(output: &str, toplevel: &str, exempt: Exempt, hits: &mut Vec<Hit>) {
    let mut sha = String::new();
    let mut file = FileState::default();
    let mut cols = 0usize;
    let mut in_hunk = false;

    let flush = |sha: &str, file: &mut FileState, hits: &mut Vec<Hit>| {
        let f = std::mem::take(file);
        if hits.len() >= MAX_HITS + 1 {
            return;
        }
        if f.unreadable {
            hits.push(Hit {
                sha: sha.to_string(),
                path: "(unreadable diff header)".into(),
                what: "could not read the path, so it could not be scanned".into(),
            });
            return;
        }
        let Some(path) = f.path else { return };
        if f.deleted {
            return;
        }
        let name = path.rsplit('/').next().unwrap_or(&path);
        if !is_safe_template(name) && is_blocked(name, &path) {
            hits.push(Hit {
                sha: sha.to_string(),
                path,
                what: "secret-named file".into(),
            });
            return;
        }
        let absolute = format!("{}/{}", toplevel.trim_end_matches('/'), path);
        if f.added.is_empty() || is_safe_template(name) || exempt(&absolute) {
            return;
        }
        if let Some(what) = scan_text(&f.added) {
            hits.push(Hit {
                sha: sha.to_string(),
                path,
                what,
            });
        }
    };

    for line in output.split('\n') {
        if let Some(rest) = line.strip_prefix('\u{1}') {
            flush(&sha, &mut file, hits);
            sha = rest.chars().take(8).collect();
            in_hunk = false;
        } else if let Some(rest) = line.strip_prefix("diff --git ") {
            flush(&sha, &mut file, hits);
            in_hunk = false;
            match header_path(rest) {
                Some(p) => file.path = Some(p),
                None => file.unreadable = true,
            }
        } else if let Some(rest) = line
            .strip_prefix("diff --cc ")
            .or_else(|| line.strip_prefix("diff --combined "))
        {
            flush(&sha, &mut file, hits);
            in_hunk = false;
            file.path = Some(combined_path(rest));
        } else if !in_hunk && line.starts_with("deleted file mode") {
            file.deleted = true;
        } else if line.starts_with("@@") {
            in_hunk = true;
            cols = line
                .bytes()
                .take_while(|&b| b == b'@')
                .count()
                .saturating_sub(1)
                .max(1);
        } else if in_hunk && !line.starts_with('\\') {
            let Some(marks) = line.get(..cols) else {
                continue;
            };
            if marks.contains('+') {
                file.added.push_str(line.get(cols..).unwrap_or(""));
                file.added.push('\n');
            }
        }
    }
    flush(&sha, &mut file, hits);
}

fn scan_commits(work_dir: &str, shas: &[String], exempt: Exempt) -> Result<Vec<Hit>, Stop> {
    let toplevel = match git(work_dir, &["rev-parse", "--show-toplevel"], 4096) {
        Git::Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        Git::Down => {
            return Err(Stop::Refused(
                "git was unavailable or timed out locating the repository".into(),
            ));
        }
        _ => {
            return Err(Stop::Refused(
                "git could not locate the repository root".into(),
            ));
        }
    };
    let mut args: Vec<&str> = vec![
        "-c",
        "core.quotePath=false",
        "log",
        "-p",
        "-U0",
        "--cc",
        "--no-walk=unsorted",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--text",
        "--no-notes",
        "--no-show-signature",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--format=%x01%H",
    ];
    args.extend(shas.iter().map(String::as_str));
    match git(work_dir, &args, MAX_LOG_BYTES) {
        Git::Ok(text) => {
            let mut hits = Vec::new();
            scan_patch(&text, &toplevel, exempt, &mut hits);
            Ok(hits)
        }
        Git::Capped => Err(Stop::Refused(format!(
            "the outbound patches are too large to scan (over {} MiB)",
            MAX_LOG_BYTES >> 20
        ))),
        Git::Failed => Err(Stop::Refused(
            "git could not read the outbound patches".into(),
        )),
        Git::Down => Err(Stop::Refused(
            "git was unavailable or timed out reading the outbound patches".into(),
        )),
    }
}

/// Annotated-tag objects (their message and signature) the push publishes.
fn scan_tag_objects(work_dir: &str, range: &Range) -> Result<Vec<Hit>, Stop> {
    let patterns: Vec<String> = if range.all || range.tags {
        vec!["refs/tags".to_string()]
    } else {
        range
            .sources
            .iter()
            .flat_map(|s| {
                let full = if s.starts_with("refs/tags/") {
                    s.clone()
                } else {
                    format!("refs/tags/{s}")
                };
                [full]
            })
            .collect()
    };
    let mut args: Vec<&str> = vec![
        "for-each-ref",
        "--format=%01%(objecttype) %(refname)%0a%(contents)",
    ];
    args.extend(patterns.iter().map(String::as_str));
    let text = match git(work_dir, &args, MAX_TAG_BYTES) {
        Git::Ok(t) => t,
        Git::Capped => {
            return Err(Stop::Refused(
                "the tag objects are too large to scan".into(),
            ));
        }
        Git::Failed => return Err(Stop::Refused("git could not read the tags".into())),
        Git::Down => {
            return Err(Stop::Refused(
                "git was unavailable or timed out reading the tags".into(),
            ));
        }
    };
    let mut hits = Vec::new();
    for record in text.split('\u{1}').filter(|r| !r.trim().is_empty()) {
        let (head, body) = record.split_once('\n').unwrap_or((record, ""));
        let Some(name) = head.strip_prefix("tag ") else {
            continue; // a lightweight tag has no object of its own
        };
        if let Some(what) = scan_text(body) {
            hits.push(Hit {
                sha: "tag".into(),
                path: sane(name),
                what,
            });
        }
    }
    Ok(hits)
}

fn judge(command: &str, cwd: &str, exempt: Exempt) -> Result<(), Stop> {
    for inv in push_invocations(command, cwd) {
        if inv.dry_run {
            continue;
        }
        if inv.unresolved {
            return Err(Stop::Refused(
                "could not resolve which repository or refs this push publishes (a directory \
                 change, config override or environment it cannot follow)"
                    .into(),
            ));
        }
        let Some(range) = range_of(&inv)? else {
            continue;
        };
        let (shas, over) = outbound(&inv.work_dir, &range)?;
        let mut hits = if shas.is_empty() {
            Vec::new()
        } else {
            scan_commits(&inv.work_dir, &shas, exempt)?
        };
        if hits.len() <= MAX_HITS {
            hits.extend(scan_tag_objects(&inv.work_dir, &range)?);
        }
        if !hits.is_empty() {
            return Err(Stop::Found(hits));
        }
        if over {
            return Err(Stop::Refused(format!(
                "the range is too large to fully scan (over {MAX_COMMITS} commits; the newest \
                 {MAX_COMMITS} were clean) — push blocked rather than partly scanned"
            )));
        }
    }
    Ok(())
}

fn render(stop: &Stop) -> String {
    const ACK: &str = "If this is a false positive, set CADENCE_ALLOW_SECRET_PUSH=1 in the hook's \
        environment (`.claude/settings.local.json` env block or `~/.claude/settings.json`, \
        never the shared settings; it applies from the next session, an inline `VAR=1 git push` \
        is not read). The allow is recorded as a bypass.";
    match stop {
        Stop::Refused(why) => format!(
            "BLOCKED: git push refused — {why}.\n\
             This guard fails closed: a push it cannot fully scan is not allowed. Narrow the \
             push (push fewer commits or name one branch), or acknowledge it.\n{ACK}"
        ),
        Stop::Found(hits) => {
            let mut out =
                String::from("BLOCKED: this push would publish a secret. Commits carrying one:\n");
            for h in hits.iter().take(MAX_HITS) {
                out.push_str(&format!(
                    "  {}  {}  ({})\n",
                    h.sha,
                    sane(&h.path),
                    sane(&h.what)
                ));
            }
            if hits.len() > MAX_HITS {
                out.push_str("  ...and more\n");
            }
            out.push_str(
                "If the secret is real, rotate it and rewrite the commit before pushing: \
                 removing it in a later commit does not help, the history is what is published.\n",
            );
            out.push_str(ACK);
            out
        }
    }
}

/// PreToolUse Bash guard on `git push`.
pub struct PreventSecretPushGuard;

impl Check for PreventSecretPushGuard {
    fn name(&self) -> &str {
        "prevent-secret-push"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        self.run_with_escape(input, std::env::var(ESCAPE_ENV).ok().as_deref())
    }
}

impl PreventSecretPushGuard {
    /// [`Check::run`] with the escape's value passed in, so tests need no env
    /// mutation.
    fn run_with_escape(&self, input: &HookInput, escape: Option<&str>) -> CheckResult {
        self.run_with(input, escape, is_secret_scan_exempt)
    }

    fn run_with(&self, input: &HookInput, escape: Option<&str>, exempt: Exempt) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let Err(stop) = judge(command, cwd, exempt) else {
            return CheckResult::allow();
        };
        // Evaluated only once the guard WOULD block, so a standing setting does
        // not write a bypass row for every unrelated push.
        if is_truthy(escape) {
            return CheckResult::allow_bypassed(BypassProvenance::env_switch(ESCAPE_ENV));
        }
        CheckResult::block(render(&stop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_patterns::is_secret_scan_exempt;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::git_fixtures::{Scratch, git_in};
    use cadence_hooks_core::test_builders::make_bash_with_cwd;
    use std::path::{Path, PathBuf};

    // Built by concatenation so this file carries no live-shaped literal.
    fn aws_key() -> String {
        format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE")
    }
    fn gh_token() -> String {
        format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
    }

    /// A work repo with a bare `origin` that already holds `main`, so
    /// `refs/remotes/origin/main` exists — the common non-first-push shape.
    struct Fx {
        _scratch: Scratch,
        work: PathBuf,
        remote: PathBuf,
    }

    impl Fx {
        fn new(tag: &str) -> Self {
            let scratch = Scratch::new(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/secretpush-scratch"),
                tag,
            );
            let work = scratch.path().join("work");
            let remote = scratch.path().join("remote.git");
            std::fs::create_dir_all(&work).unwrap();
            std::fs::create_dir_all(&remote).unwrap();
            git_in(&remote, &["init", "-q", "--bare", "-b", "main"]);
            git_in(&work, &["init", "-q", "-b", "main"]);
            git_in(&work, &["config", "user.email", "t@t"]);
            git_in(&work, &["config", "user.name", "t"]);
            git_in(&work, &["config", "commit.gpgsign", "false"]);
            git_in(
                &work,
                &["remote", "add", "origin", remote.to_str().unwrap()],
            );
            let fx = Self {
                _scratch: scratch,
                work,
                remote,
            };
            fx.commit("README.md", "hello\n", "init");
            git_in(&fx.work, &["push", "-q", "origin", "main"]);
            fx
        }

        fn commit(&self, path: &str, body: &str, msg: &str) {
            let full = self.work.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, body).unwrap();
            git_in(&self.work, &["add", "-f", path]);
            git_in(&self.work, &["commit", "-q", "-m", msg]);
        }

        fn git(&self, args: &[&str]) {
            git_in(&self.work, args);
        }

        fn run(&self, command: &str) -> CheckResult {
            self.run_escape(command, None)
        }

        /// The fixture lives under this checkout's `target/`, which itself has a
        /// `cadence-hooks` path component, so the real exemption would cover every
        /// fixture. Tests run with none, except the exemption tests.
        fn run_escape(&self, command: &str, escape: Option<&str>) -> CheckResult {
            let input = make_bash_with_cwd(command, self.work.to_str().unwrap());
            PreventSecretPushGuard.run_with(&input, escape, |_| false)
        }
    }

    fn assert_blocks(r: &CheckResult, needles: &[&str]) {
        assert_eq!(r.outcome, Outcome::Block, "{:?}", r.message);
        let msg = r.message.as_deref().unwrap_or("");
        for n in needles {
            assert!(msg.contains(n), "missing {n:?} in {msg}");
        }
    }

    fn assert_allows(r: &CheckResult) {
        assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.message);
    }

    #[test]
    fn clean_push_and_non_push_commands_allow() {
        let fx = Fx::new("clean");
        fx.commit("src/a.txt", "fine\n", "add a");
        assert_allows(&fx.run("git push origin main"));
        assert_allows(&fx.run("git status"));
        assert_allows(&fx.run("echo git push"));
    }

    #[test]
    fn credential_token_in_outbound_commit_blocks_naming_sha_path_and_kind() {
        let fx = Fx::new("token");
        fx.commit("src/cfg.txt", &format!("key={}\n", aws_key()), "add cfg");
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["src/cfg.txt", "AWS access key id"]);
        assert!(!r.message.as_deref().unwrap().contains(&aws_key()));
    }

    #[test]
    fn github_token_blocks() {
        let fx = Fx::new("ghtoken");
        fx.commit("notes.md", &format!("t {}\n", gh_token()), "notes");
        assert_blocks(&fx.run("git push"), &["notes.md", "GitHub token"]);
    }

    #[test]
    fn secret_named_file_blocks_without_content_match() {
        let fx = Fx::new("named");
        fx.commit(".env", "FOO=bar\n", "add env");
        assert_blocks(
            &fx.run("git push origin main"),
            &[".env", "secret-named file"],
        );
    }

    #[test]
    fn key_material_binary_name_blocks() {
        let fx = Fx::new("p12");
        fx.commit("certs/prod.p12", "\u{0}\u{1}binary", "cert");
        assert_blocks(&fx.run("git push origin main"), &["certs/prod.p12"]);
    }

    #[test]
    fn pushed_secret_added_then_removed_is_still_caught() {
        let fx = Fx::new("addremove");
        fx.commit("a.txt", &format!("{}\n", aws_key()), "add secret");
        fx.commit("a.txt", "clean\n", "remove secret");
        assert_blocks(&fx.run("git push origin main"), &["a.txt"]);
    }

    #[test]
    fn first_push_with_no_remote_tracking_refs_scans_full_history() {
        let fx = Fx::new("first");
        fx.git(&["checkout", "-q", "-b", "feat"]);
        fx.commit("x.txt", &format!("{}\n", aws_key()), "x");
        // Drop every remote-tracking ref: the first push to a new remote.
        fx.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
        assert_blocks(&fx.run("git push -u origin feat"), &["x.txt"]);
    }

    #[test]
    fn already_published_secret_is_not_rescanned() {
        let fx = Fx::new("published");
        fx.commit("a.txt", &format!("{}\n", aws_key()), "old secret");
        fx.git(&["push", "-q", "origin", "main"]);
        fx.commit("b.txt", "clean\n", "clean");
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn push_of_other_branch_scans_that_branch_not_head() {
        let fx = Fx::new("branchb");
        fx.git(&["checkout", "-q", "-b", "branchB"]);
        fx.commit("b.txt", &format!("{}\n", aws_key()), "b");
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push origin branchB"), &["b.txt"]);
        // HEAD (main) itself has nothing outbound.
        assert_allows(&fx.run("git push origin main"));
        assert_blocks(&fx.run("git push origin branchB:remote-b"), &["b.txt"]);
    }

    #[test]
    fn dash_c_redirects_the_scan() {
        let fx = Fx::new("dashc");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        let other = fx._scratch.path().join("elsewhere");
        std::fs::create_dir_all(&other).unwrap();
        let cmd = format!("git -C {} push origin main", fx.work.display());
        let input = make_bash_with_cwd(&cmd, other.to_str().unwrap());
        assert_blocks(
            &PreventSecretPushGuard.run_with(&input, None, |_| false),
            &["s.txt"],
        );
    }

    #[test]
    fn delete_plus_publish_still_scans_the_publish() {
        let fx = Fx::new("delpub");
        fx.git(&["checkout", "-q", "-b", "newbranch"]);
        fx.commit("n.txt", &format!("{}\n", aws_key()), "n");
        assert_blocks(&fx.run("git push origin :dead newbranch"), &["n.txt"]);
        assert_allows(&fx.run("git push origin :dead"));
        assert_allows(&fx.run("git push origin --delete newbranch"));
    }

    #[test]
    fn dry_run_allows() {
        let fx = Fx::new("dry");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        assert_allows(&fx.run("git push --dry-run origin main"));
        assert_allows(&fx.run("git push -n origin main"));
    }

    #[test]
    fn wrapped_push_is_still_scanned() {
        let fx = Fx::new("wrapped");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        assert_blocks(&fx.run("sh -c 'git push origin main'"), &["s.txt"]);
        assert_blocks(&fx.run("echo hi && git push origin main"), &["s.txt"]);
        assert_blocks(&fx.run("echo $(git push origin main)"), &["s.txt"]);
    }

    #[test]
    fn in_repo_fixture_paths_are_exempt_from_the_content_scan() {
        // A repo whose checkout path carries a `cadence-hooks` component, like
        // this one, must be able to push its own fixture keys.
        let fx = Fx::new("exempt");
        // The relative path (`tests/fx.rs`) carries no `cadence-hooks` component;
        // only the ABSOLUTE path does (this checkout's own directory), so the
        // exemption applies only if the guard joins the repo root first.
        fx.commit(
            "tests/fx.rs",
            &format!("const K: &str = \"{}\";\n", aws_key()),
            "fixture",
        );
        let cmd = "git push origin main";
        let input = make_bash_with_cwd(cmd, fx.work.to_str().unwrap());
        assert!(is_secret_scan_exempt(fx.work.to_str().unwrap()));
        assert_allows(&PreventSecretPushGuard.run_with(&input, None, is_secret_scan_exempt));
        // Same content outside a `cadence-hooks` component is blocked.
        let fx2 = Fx::new("exempt2");
        fx2.commit("src/fx.rs", &format!("K=\"{}\"\n", aws_key()), "fixture");
        assert_blocks(&fx2.run(cmd), &["src/fx.rs"]);
    }

    #[test]
    fn safe_template_paths_are_exempt() {
        let fx = Fx::new("template");
        fx.commit("config.example", &format!("k={}\n", aws_key()), "example");
        fx.commit(".env.example", "FOO=\n", "env example");
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn deleting_a_secret_file_is_not_an_add() {
        let fx = Fx::new("delete");
        fx.commit("ok.txt", "x\n", "ok");
        fx.git(&["push", "-q", "origin", "main"]);
        fx.git(&["rm", "-q", "ok.txt"]);
        fx.git(&["commit", "-q", "-m", "rm"]);
        assert_allows(&fx.run("git push origin main"));
    }

    #[test]
    fn over_cap_range_blocks_with_count() {
        let fx = Fx::new("overcap");
        // Bulk-create commits cheaply through fast-import.
        let mut stream = String::new();
        for i in 0..(MAX_COMMITS + 5) {
            stream.push_str(&format!(
                "commit refs/heads/main\ncommitter t <t@t> {} +0000\ndata 1\nc\nfrom refs/heads/main^0\nM 100644 inline f{i}.txt\ndata 2\nx\n\n",
                1_700_000_000 + i
            ));
        }
        let mut child = std::process::Command::new("git")
            .args(["fast-import", "--quiet"])
            .current_dir(&fx.work)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stream.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
        let r = fx.run("git push origin main");
        assert_blocks(&r, &["too large"]);
        assert_blocks(&r, &[ESCAPE_ENV]);
    }

    #[test]
    fn oversized_patch_blocks() {
        let fx = Fx::new("bytes");
        let big = "x".repeat(MAX_LOG_BYTES + 1024);
        fx.commit("big.txt", &big, "big");
        assert_blocks(&fx.run("git push origin main"), &["too large"]);
    }

    #[test]
    fn unresolvable_range_blocks_never_allows() {
        let fx = Fx::new("unresolved");
        // Source ref does not exist: git errors, and error is not "nothing to push".
        assert_blocks(&fx.run("git push origin nosuchbranch"), &["nosuchbranch"]);
        // A source the guard will not hand to git.
        assert_blocks(&fx.run("git push origin HEAD~1:main"), &["HEAD~1"]);
        // A directory the walk cannot follow.
        assert_blocks(
            &fx.run("cd \"$SOMEWHERE\" && git push origin main"),
            &["resolve"],
        );
    }

    #[test]
    fn broken_repository_blocks() {
        let fx = Fx::new("broken");
        std::fs::remove_dir_all(fx.work.join(".git/objects")).unwrap();
        assert_blocks(&fx.run("git push origin main"), &[]);
    }

    #[test]
    fn all_and_mirror_widen_to_every_local_branch() {
        let fx = Fx::new("all");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("side.txt", &format!("{}\n", aws_key()), "side");
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push --all origin"), &["side.txt"]);
        assert_blocks(&fx.run("git push --mirror origin"), &["side.txt"]);
    }

    #[test]
    fn tags_push_scans_off_branch_commits_and_tag_objects() {
        let fx = Fx::new("tags");
        // A commit no branch reaches, pinned only by a tag.
        fx.git(&["checkout", "-q", "--detach"]);
        fx.commit("t.txt", &format!("{}\n", aws_key()), "tagged");
        fx.git(&["tag", "v1"]);
        fx.git(&["checkout", "-q", "main"]);
        assert_blocks(&fx.run("git push --tags origin"), &["t.txt"]);

        // An annotated tag whose MESSAGE carries the secret, on a published commit.
        let fx = Fx::new("tagmsg");
        fx.git(&["tag", "-a", "v2", "-m", &format!("note {}", gh_token())]);
        assert_blocks(&fx.run("git push --tags origin"), &["v2", "GitHub token"]);
        assert_blocks(&fx.run("git push origin v2"), &["v2"]);
    }

    #[test]
    fn evil_merge_content_is_scanned_but_merged_in_history_is_not_double_counted() {
        let fx = Fx::new("merge");
        fx.git(&["checkout", "-q", "-b", "side"]);
        fx.commit("s.txt", "side\n", "side");
        fx.git(&["checkout", "-q", "main"]);
        fx.commit("m.txt", "main\n", "main");
        fx.git(&["merge", "-q", "--no-commit", "--no-ff", "side"]);
        std::fs::write(fx.work.join("m.txt"), format!("{}\n", aws_key())).unwrap();
        fx.git(&["add", "m.txt"]);
        fx.git(&["commit", "-q", "-m", "merge"]);
        assert_blocks(&fx.run("git push origin main"), &["m.txt"]);
    }

    #[test]
    fn gitattributes_binary_marking_does_not_hide_content() {
        let fx = Fx::new("attrs");
        fx.commit(".gitattributes", "*.txt -diff\n", "attrs");
        fx.commit("h.txt", &format!("{}\n", aws_key()), "hidden");
        assert_blocks(&fx.run("git push origin main"), &["h.txt"]);
    }

    #[test]
    fn ack_env_allows_records_provenance_and_needs_a_would_be_block() {
        let fx = Fx::new("ack");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        let r = fx.run_escape("git push origin main", Some("1"));
        assert_eq!(r.outcome, Outcome::Allow);
        let p = r.bypass.expect("provenance recorded");
        assert_eq!(p.mechanism, ESCAPE_ENV);
        // Falsy values do not open it.
        for v in ["", "0", "no"] {
            assert_blocks(&fx.run_escape("git push origin main", Some(v)), &["s.txt"]);
        }
        // Set but nothing to block: no provenance row.
        let clean = Fx::new("ack-clean");
        let r = clean.run_escape("git push origin main", Some("1"));
        assert!(r.bypass.is_none());
    }

    #[test]
    fn many_findings_are_capped_in_the_message() {
        let fx = Fx::new("many");
        for i in 0..8 {
            fx.commit(&format!("k{i}.txt"), &format!("{}\n", aws_key()), "k");
        }
        let r = fx.run("git push origin main");
        assert_eq!(r.outcome, Outcome::Block);
        assert!(r.message.unwrap().contains("more"));
    }

    #[test]
    fn remote_dir_is_untouched_by_scanning() {
        let fx = Fx::new("readonly");
        fx.commit("s.txt", &format!("{}\n", aws_key()), "s");
        let _ = fx.run("git push origin main");
        let out = std::process::Command::new("git")
            .args([
                "-C",
                fx.remote.to_str().unwrap(),
                "rev-list",
                "--all",
                "--count",
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
    }
}
