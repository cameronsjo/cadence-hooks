//! Facts about where content is going, kept out of the scan engine.
//!
//! Three questions the guard asks that the term list cannot answer:
//!
//! - **Is this Write a local scratch script?** ([`is_scratch_code_path`],
//!   cameronsjo/cadence-hooks#1013, #716, #603.)
//! - **Which repo does this command post to?** ([`post_targets`] and the two
//!   verdicts built on it: [`shared_destination`] for `destinations`-scoped
//!   allows, #630, and [`all_owned`] for the harness-vocabulary downgrade,
//!   #684.)
//! - **Does this body carry a wall of pasted output?** ([`longest_fence`],
//!   #974.)
//!
//! Every function fails toward the stricter outcome: an unreadable target is
//! `None`, and a `None` never excuses anything.

use super::is_external_post;
use cadence_hooks_core::config::{self, AllowEntry};
use cadence_hooks_core::gh_bodies::parse_gh_api;
use cadence_hooks_core::shell::{
    GhRepoFlag, command_segments, command_word, executable_tokens, gh_command_path, gh_repo_flags,
    git_command, host_and_repo_from_url, parse_gh_repo_value, peel_command_runners,
    skip_git_global_options, unescape_word,
};
use std::path::{Component, Path, PathBuf};

/// Extensions of files that are code or config a person runs, not prose a
/// person posts. `.txt`, `.md` and extensionless files are deliberately absent:
/// they can be handed to `--body-file`, so they keep the block wherever they
/// live.
const SCRATCH_CODE_EXTENSIONS: &[&str] =
    &["sh", "py", "rs", "js", "ts", "json", "toml", "yaml", "yml"];

/// Temp roots a Write may be exempt under: `/tmp`, its macOS spelling,
/// `$TMPDIR`, and `$CLAUDE_CODE_TMPDIR` (Claude Code's own temp override, which
/// is where the session scratchpad lives when set). The session scratchpad
/// under the default `/tmp/claude-<uid>/…` is already inside `/tmp`; no other
/// scratchpad location under the Claude config dir is detectable, so none is
/// guessed.
fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/tmp"), PathBuf::from("/private/tmp")];
    for var in ["TMPDIR", "CLAUDE_CODE_TMPDIR"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            roots.push(PathBuf::from(v));
        }
    }
    roots
}

/// Is `file_path` a code/config file under a temp root, outside any git work
/// tree? See [`is_scratch_code_path_in`].
pub(super) fn is_scratch_code_path(file_path: Option<&str>) -> bool {
    is_scratch_code_path_in(file_path, &temp_roots())
}

/// The pure form of [`is_scratch_code_path`], roots passed in.
///
/// All of these must hold, or the write is scanned as before:
///
/// - the extension is in [`SCRATCH_CODE_EXTENSIONS`] (case-insensitive);
/// - the path is absolute and carries no `..` component;
/// - it lies under a root, judged after resolving symlinks on the deepest
///   ancestor that exists — a `/tmp/link -> ~/repo` path resolves out of the
///   root and is scanned;
/// - no ancestor of the path is a git work tree: a file in a checkout that
///   happens to live under `/tmp` can be committed, and the post-time scan
///   does not see commits' file content.
pub(super) fn is_scratch_code_path_in(file_path: Option<&str>, roots: &[PathBuf]) -> bool {
    let Some(raw) = file_path.filter(|p| !p.is_empty()) else {
        return false;
    };
    let path = Path::new(raw);
    let ext_ok = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SCRATCH_CODE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()));
    if !ext_ok || !path.is_absolute() {
        return false;
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let resolved = resolve_deepest(path);
    let under_root = roots.iter().any(|root| {
        let root = root.canonicalize().unwrap_or_else(|_| root.clone());
        // A root of `/` (a stray TMPDIR=/) would exempt everything.
        root.parent().is_some() && resolved.starts_with(&root)
    });
    if !under_root {
        return false;
    }
    let dir = resolved.parent().and_then(Path::to_str).unwrap_or("/");
    cadence_hooks_core::paths::find_git_root(dir).is_none()
}

/// Canonicalize the deepest existing ancestor of `path` and re-append the rest.
fn resolve_deepest(path: &Path) -> PathBuf {
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(real) = cur.canonicalize() {
            return tail.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Length of the longest fenced code block in `text`, in content lines.
///
/// CommonMark fences: an opener of three or more backticks or tildes indented
/// at most three spaces; a closer of the same character, at least as long, with
/// nothing else on the line. An unclosed fence runs to the end of the text.
pub(super) fn longest_fence(text: &str) -> usize {
    let mut longest = 0;
    let mut open: Option<(char, usize, usize)> = None; // (char, len, lines so far)
    for line in text.lines() {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let body = line.trim_start_matches(' ');
        let fence = body
            .chars()
            .next()
            .filter(|c| (*c == '`' || *c == '~') && indent <= 3)
            .map(|c| (c, body.chars().take_while(|x| *x == c).count()))
            .filter(|(_, n)| *n >= 3);
        match (&mut open, fence) {
            (Some((c, len, lines)), Some((fc, fl)))
                if fc == *c && fl >= *len && body[fl..].trim().is_empty() =>
            {
                longest = longest.max(*lines);
                open = None;
            }
            (Some((_, _, lines)), _) => *lines += 1,
            (None, Some((fc, fl))) => {
                // A backtick fence's info string may not contain a backtick.
                if fc == '~' || !body[fl..].contains('`') {
                    open = Some((fc, fl, 0));
                }
            }
            (None, None) => {}
        }
    }
    if let Some((_, _, lines)) = open {
        longest = longest.max(lines);
    }
    longest
}

/// One resolved post target: `(host, "owner/repo")`, lowercase.
pub(super) type Target = (String, String);

/// The repo each posting segment of `command` targets, one entry per segment
/// [`is_external_post`] accepts; `None` where it cannot be read with certainty.
///
/// Read with certainty: a `gh pr|issue|release|discussion` verb takes its
/// `-R`/`--repo` (a single agreeing reading), else `GH_REPO`, else the origin
/// of `base_dir`; a plain `git commit` takes that origin. Everything else is
/// `None` — `gh api` (its path names the repo), gists (user-level), `tea`, a
/// `git -C …`, a command that sets `GH_REPO=` inline, a value gh may or may not
/// have used, and a checkout with an `upstream` remote (`gh pr create` there
/// posts to the upstream, not the fork's origin).
pub(super) fn post_targets(command: &str, base_dir: &str) -> Vec<Option<Target>> {
    let mut origin: Option<Option<Target>> = None;
    let mut origin_of = || -> Option<Target> {
        origin
            .get_or_insert_with(|| {
                let remotes = git_command(base_dir, &["remote"])?;
                if remotes.lines().any(|r| r.trim() == "upstream") {
                    return None;
                }
                let url = git_command(base_dir, &["remote", "get-url", "origin"])?;
                let (host, repo) = host_and_repo_from_url(&url)?;
                Some((host.to_ascii_lowercase(), repo.to_ascii_lowercase()))
            })
            .clone()
    };
    let dh = config::default_host();
    let mut out = Vec::new();
    for segment in command_segments(command) {
        if !is_external_post(&segment) {
            continue;
        }
        if segment.contains("GH_REPO") {
            out.push(None);
            continue;
        }
        let tokens = executable_tokens(&segment);
        let argv = peel_command_runners(&tokens);
        let Some(head) = argv.first() else {
            out.push(None);
            continue;
        };
        let target = match command_word(head).as_ref() {
            "gh" if parse_gh_api(argv).is_none() => {
                let path = gh_command_path(argv, 2);
                let group = path.first().map(|g| unescape_word(g).into_owned());
                match group.as_deref() {
                    Some("pr" | "issue" | "release" | "discussion") => {
                        match gh_repo_flags(argv).resolve() {
                            GhRepoFlag::Target(value) => parse_gh_repo_value(&value).map(|spec| {
                                (
                                    spec.host.unwrap_or_else(|| dh.clone()).to_ascii_lowercase(),
                                    format!("{}/{}", spec.owner, spec.name).to_ascii_lowercase(),
                                )
                            }),
                            GhRepoFlag::Absent => match std::env::var("GH_REPO") {
                                Ok(v) if !v.is_empty() => None,
                                _ => origin_of(),
                            },
                            GhRepoFlag::TargetOrAbsent(_) | GhRepoFlag::Ambiguous => None,
                        }
                    }
                    _ => None,
                }
            }
            "git" => {
                let rest = &argv[1..];
                // Any global option (`-C dir`, `--git-dir`, `-c k=v`) changes
                // which repo or config commits use; leave those unresolved.
                let plain = skip_git_global_options(rest).len() == rest.len();
                let commit = rest
                    .first()
                    .is_some_and(|w| unescape_word(w).as_ref() == "commit");
                if plain && commit { origin_of() } else { None }
            }
            _ => None,
        };
        out.push(target);
    }
    out
}

/// The repo every remote of the checkout at `base_dir` points to, lowercase.
/// Empty when `base_dir` is not a checkout or has no readable remote.
pub(super) fn checkout_repos(base_dir: &str) -> Vec<Target> {
    let Some(out) = git_command(base_dir, &["config", "--get-regexp", r"^remote\..*\.url$"]) else {
        return Vec::new();
    };
    out.lines()
        .filter_map(|line| line.split_once(' '))
        .filter_map(|(_, url)| host_and_repo_from_url(url))
        .map(|(host, repo)| (host.to_ascii_lowercase(), repo.to_ascii_lowercase()))
        .collect()
}

/// The first resolved target that is none of the checkout's own repos (`own`,
/// from [`checkout_repos`]), as `owner/repo` — a post that leaves this repo
/// (cameronsjo/cadence-hooks#1245). An unresolved target is not foreign: no
/// `-R` means gh posts to this checkout.
pub(super) fn foreign_target(targets: &[Option<Target>], own: &[Target]) -> Option<String> {
    targets
        .iter()
        .flatten()
        .find(|t| !own.contains(t))
        .map(|(_, slug)| slug.clone())
}

/// The single `owner/repo` every posting segment resolves to on the default
/// host, or `None` when there is no posting segment, any segment is
/// unresolved, the segments disagree, or the host is not the default one. This
/// is what a `destinations`-scoped allow is judged against.
pub(super) fn shared_destination(targets: &[Option<Target>]) -> Option<String> {
    let dh = config::default_host();
    let mut found: Option<&str> = None;
    for t in targets {
        let (host, slug) = t.as_ref()?;
        if *host != dh {
            return None;
        }
        match found {
            Some(prev) if prev != slug => return None,
            _ => found = Some(slug),
        }
    }
    found.map(str::to_string)
}

/// Is every posting segment's target owned by an owner in
/// `CADENCE_ALLOWED_OWNERS` (the same list, host rules and extra hosts the
/// gh-write guards use)? False when there is no posting segment or any target
/// is unresolved — an unknown destination is not an owned one.
pub(super) fn all_owned(targets: &[Option<Target>]) -> bool {
    let owners: Vec<AllowEntry> = config::env_allow_entries("CADENCE_ALLOWED_OWNERS");
    all_owned_with(targets, &owners, &config::env_extra_hosts())
}

/// [`all_owned`] with the allowlist passed in.
pub(super) fn all_owned_with(
    targets: &[Option<Target>],
    owners: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    !targets.is_empty()
        && targets.iter().all(|t| {
            t.as_ref().is_some_and(|(host, slug)| {
                slug.split_once('/').is_some_and(|(owner, repo)| {
                    config::is_allowed_with_extra_hosts(host, owner, repo, owners, &[], extra_hosts)
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn roots() -> Vec<PathBuf> {
        vec![PathBuf::from("/tmp")]
    }

    // Embeds native paths in a POSIX shell string or uses Unix-only temp roots;
    // Windows paths lose their backslashes to shell escaping, as in real bash.
    #[cfg(unix)]
    #[test]
    fn scratch_exemption_table() {
        // (path, exempt?) — code under a temp root is exempt; anything that
        // could be posted, or escapes the root, is not.
        let table: &[(&str, bool)] = &[
            ("/tmp/x/poll.sh", true),
            ("/tmp/repro.py", true),
            ("/tmp/a/b/c.rs", true),
            ("/tmp/a.js", true),
            ("/tmp/a.ts", true),
            ("/tmp/a.json", true),
            ("/tmp/a.toml", true),
            ("/tmp/a.yaml", true),
            ("/tmp/a.yml", true),
            ("/tmp/POLL.SH", true),
            // Prose drafts stay blocked in a temp root: `--body-file` posts them.
            ("/tmp/notes.md", false),
            ("/tmp/notes.txt", false),
            ("/tmp/notes", false),
            ("/tmp/.env", false),
            ("/tmp/notes.sh.md", false),
            // Outside every root.
            ("/home/u/repo/poll.sh", false),
            ("/tmpfoo/poll.sh", false),
            ("poll.sh", false),
            ("./tmp/poll.sh", false),
            // Traversal out of the root.
            ("/tmp/../home/u/poll.sh", false),
            ("/tmp/x/../../etc/poll.sh", false),
            ("", false),
        ];
        for (path, want) in table {
            assert_eq!(
                is_scratch_code_path_in(Some(path), &roots()),
                *want,
                "path: {path:?}"
            );
        }
        assert!(!is_scratch_code_path_in(None, &roots()));
    }

    #[test]
    #[cfg(unix)]
    fn scratch_exemption_refuses_a_symlink_out_of_the_root() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let via_link = link.join("poll.sh");
        let roots = vec![root.path().to_path_buf()];
        assert!(!is_scratch_code_path_in(via_link.to_str(), &roots));
        // Control: the same shape without the escape is exempt.
        let inside = root.path().join("poll.sh");
        assert!(is_scratch_code_path_in(inside.to_str(), &roots));
    }

    #[test]
    fn scratch_exemption_refuses_a_git_work_tree_under_the_root() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let roots = vec![root.path().to_path_buf()];
        assert!(!is_scratch_code_path_in(
            repo.join("scripts/poll.sh").to_str(),
            &roots
        ));
        assert!(is_scratch_code_path_in(
            root.path().join("poll.sh").to_str(),
            &roots
        ));
    }

    #[test]
    fn a_root_of_slash_exempts_nothing() {
        assert!(!is_scratch_code_path_in(
            Some("/home/u/poll.sh"),
            &[PathBuf::from("/")]
        ));
    }

    #[test]
    fn longest_fence_table() {
        let block = |n: usize, fence: &str| format!("{fence}\n{}{fence}\n", "line\n".repeat(n));
        let table: Vec<(String, usize)> = vec![
            ("no fences here\njust prose".into(), 0),
            (block(3, "```"), 3),
            (block(41, "```"), 41),
            (block(41, "~~~"), 41),
            (block(5, "````"), 5),
            // Two blocks: the longest wins.
            (format!("{}\n{}", block(2, "```"), block(7, "```")), 7),
            // A shorter inner fence does not close a longer opener.
            ("````\na\n```\nb\n````\n".into(), 3),
            // A different fence character does not close.
            ("```\na\n~~~\nb\n```\n".into(), 3),
            // Unclosed runs to the end.
            ("```\na\nb\nc".into(), 3),
            // Indented four spaces is code, not a fence.
            (format!("    ```\n{}    ```\n", "line\n".repeat(50)), 0),
            // A backtick info string with a backtick is not a fence.
            ("``` a`b\nx\n```\n".into(), 0),
            // A closer carrying text is content, not a closer.
            ("```\na\n``` trailing\nb\n```\n".into(), 3),
        ];
        for (text, want) in table {
            assert_eq!(longest_fence(&text), want, "text: {text:?}");
        }
    }

    fn t(host: &str, slug: &str) -> Option<Target> {
        Some((host.to_string(), slug.to_string()))
    }

    fn owners(spec: &[&str]) -> Vec<AllowEntry> {
        spec.iter().map(|s| config::parse_allow_entry(s)).collect()
    }

    #[test]
    fn owned_verdict_table() {
        let mine = owners(&["me"]);
        let table: Vec<(Vec<Option<Target>>, bool)> = vec![
            (vec![t("github.com", "me/tool")], true),
            (
                vec![t("github.com", "me/tool"), t("github.com", "me/other")],
                true,
            ),
            (vec![t("github.com", "them/tool")], false),
            // One unowned segment spoils the command.
            (
                vec![t("github.com", "me/tool"), t("github.com", "them/x")],
                false,
            ),
            // Unresolved is not owned.
            (vec![None], false),
            (vec![t("github.com", "me/tool"), None], false),
            // No posting segment at all.
            (vec![], false),
            // Right owner, wrong host.
            (vec![t("evil.example", "me/tool")], false),
        ];
        for (targets, want) in table {
            assert_eq!(
                all_owned_with(&targets, &mine, &[]),
                want,
                "targets: {targets:?}"
            );
        }
        // An empty allowlist owns nothing.
        assert!(!all_owned_with(&[t("github.com", "me/tool")], &[], &[]));
    }

    #[test]
    fn shared_destination_table() {
        let dh = config::default_host();
        let table: Vec<(Vec<Option<Target>>, Option<&str>)> = vec![
            (vec![t(&dh, "a/b")], Some("a/b")),
            (vec![t(&dh, "a/b"), t(&dh, "a/b")], Some("a/b")),
            (vec![t(&dh, "a/b"), t(&dh, "a/c")], None),
            (vec![t(&dh, "a/b"), None], None),
            (vec![None], None),
            (vec![], None),
            (vec![t("other.example", "a/b")], None),
        ];
        for (targets, want) in table {
            assert_eq!(shared_destination(&targets).as_deref(), want, "{targets:?}");
        }
    }

    #[test]
    fn foreign_target_table() {
        let own = vec![
            ("github.com".to_string(), "me/meta".to_string()),
            ("github.com".to_string(), "up/meta".to_string()),
        ];
        let table: Vec<(Vec<Option<Target>>, Option<&str>)> = vec![
            (vec![t("github.com", "me/meta")], None),
            (vec![t("github.com", "up/meta")], None),
            (vec![t("github.com", "me/tool")], Some("me/tool")),
            // Same slug on another host is another repo.
            (vec![t("ghe.example", "me/meta")], Some("me/meta")),
            // Unresolved targets are not foreign.
            (vec![None], None),
            (vec![], None),
            (
                vec![None, t("github.com", "me/meta"), t("github.com", "x/y")],
                Some("x/y"),
            ),
        ];
        for (targets, want) in table {
            assert_eq!(
                foreign_target(&targets, &own).as_deref(),
                want,
                "{targets:?}"
            );
        }
    }

    #[test]
    fn checkout_repos_reads_every_remote() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        assert!(checkout_repos(base).is_empty(), "not a checkout");
        for args in [
            &["init", "-q"][..],
            &["remote", "add", "origin", "https://github.com/Me/Meta.git"],
            &["remote", "add", "upstream", "git@github.com:up/meta.git"],
        ] {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        }
        let mut repos = checkout_repos(base);
        repos.sort();
        assert_eq!(
            repos,
            vec![
                ("github.com".to_string(), "me/meta".to_string()),
                ("github.com".to_string(), "up/meta".to_string()),
            ]
        );
    }

    fn resolve(cmd: &str) -> Vec<Option<Target>> {
        // A base dir that is not a git checkout: origin lookups fail, so only
        // `-R` forms can resolve.
        let dir = tempfile::tempdir().unwrap();
        post_targets(cmd, dir.path().to_str().unwrap())
    }

    #[test]
    fn post_targets_reads_the_repo_flag_with_ghs_grammar() {
        let dh = config::default_host();
        let table: Vec<(&str, Vec<Option<Target>>)> = vec![
            ("gh pr create -R Me/Tool --title x", vec![t(&dh, "me/tool")]),
            (
                "gh issue comment 1 --repo me/tool -b x",
                vec![t(&dh, "me/tool")],
            ),
            ("gh -R me/tool pr create --title x", vec![t(&dh, "me/tool")]),
            // pflag is last-wins for certain readings; a reading another flag
            // may have taken as its value is not trusted.
            ("gh pr create -R a/b -R c/d --title x", vec![t(&dh, "c/d")]),
            ("gh pr create -R a/b --title -Rc/d", vec![None]),
            ("gh pr create --title -Ra/b", vec![None]),
            // No -R and no origin to read: unresolved, never guessed.
            ("gh pr create --title x", vec![None]),
            // gh api names its repo in the path; gists are user-level.
            ("gh api -X POST repos/me/tool/issues -f title=x", vec![None]),
            ("gh gist create f.txt", vec![None]),
            // Inline GH_REPO overrides everything.
            ("GH_REPO=a/b gh pr create -R me/tool --title x", vec![None]),
            // git with a global option changes which repo commits land in.
            ("git -C /elsewhere commit -m x", vec![None]),
            // Not a posting command.
            ("ls -la", vec![]),
        ];
        for (cmd, want) in table {
            assert_eq!(resolve(cmd), want, "cmd: {cmd}");
        }
    }
}
