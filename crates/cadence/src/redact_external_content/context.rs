//! Facts about where content is going, kept out of the scan engine.
//!
//! Three questions the guard asks that the term list cannot answer:
//!
//! - **Can this Write leave the machine by itself?** ([`is_outside_git_tree`],
//!   cameronsjo/cadence#1708, after cameronsjo/cadence-hooks#1013, #716, #603.)
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

/// Is `file_path` a local file outside every git work tree?
///
/// Such a file cannot leave the machine by itself. For code and config the
/// caller skips the identity pass on it (cameronsjo/cadence#1708; this
/// generalizes the temp-root code exemption of #1013, #716, #603); a prose
/// draft keeps the pass ([`is_prose_draft`]), because some posts read a file
/// in ways the post-time scan does not follow.
///
/// All of these must hold, or the write is scanned as before:
///
/// - the path is non-empty, absolute, and carries no `..` component (an MCP
///   write has no path and is always scanned);
/// - no ancestor of the path, judged after resolving symlinks on the deepest
///   ancestor that exists, is a git work tree: a file in a checkout can be
///   committed, and the post-time scan does not see commits' file content.
///
/// The residuals: a later `cp`, `git add` of a copy, or `chezmoi add` can bring
/// the text into a repo with no Edit call, and a bare-repo dotfiles setup
/// (`--git-dir=~/.dotfiles --work-tree=~`) has no `.git` above the files it
/// tracks. The leak-ledger scan is the net for both.
pub(super) fn is_outside_git_tree(file_path: Option<&str>) -> bool {
    let Some(raw) = file_path.filter(|p| !p.is_empty()) else {
        return false;
    };
    let path = Path::new(raw);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let resolved = resolve_deepest(path);
    let dir = resolved.parent().and_then(Path::to_str).unwrap_or("/");
    cadence_hooks_core::paths::find_git_root(dir).is_none()
}

/// Is `file_path` anything but code or config? Prose is what a post reads
/// through `--body "$(cat F)"`, `git commit -m "$(cat F)"` or `cat F | …
/// --body-file -`, none of which the post-time scan follows, so it keeps the
/// Write scan outside a work tree too. Only a name this function knows as
/// code or config is exempt: a dotfile with no other dot (`.zshrc`), or a
/// code or config extension. Everything else, including `.md`, `.msg`, a bare
/// `/tmp/body`, a hidden `.pr-body.md` and a `notes.md.bak`, reads as a draft,
/// as does no path at all.
pub(super) fn is_prose_draft(file_path: Option<&str>) -> bool {
    let Some(name) = file_path
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
    else {
        return true;
    };
    let stem = name.strip_prefix('.').unwrap_or(name);
    let Some((_, ext)) = stem.rsplit_once('.') else {
        // `.zshrc` is config; a bare `body` or `draft` is prose.
        return !name.starts_with('.');
    };
    !CODE_OR_CONFIG_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
}

/// Extensions [`is_prose_draft`] reads as code or config.
const CODE_OR_CONFIG_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "ps1", "py", "rb", "pl", "lua", "js", "mjs", "cjs", "ts", "mts",
    "cts", "jsx", "tsx", "go", "rs", "c", "h", "cc", "cpp", "hpp", "java", "kt", "swift", "cs",
    "php", "sql", "vim", "el", "nix", "toml", "yaml", "yml", "json", "jsonc", "json5", "ini",
    "conf", "cfg", "plist", "xml", "env", "lock", "tmpl", "service", "desktop",
];

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

    #[test]
    fn outside_git_tree_needs_a_plain_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("notes.md");
        assert!(is_outside_git_tree(plain.to_str()));
        assert!(is_outside_git_tree(dir.path().join("a/b/c.toml").to_str()));
        for path in ["", "notes.md", "./tmp/notes.md"] {
            assert!(!is_outside_git_tree(Some(path)), "path: {path:?}");
        }
        let traversal = format!("{}/../notes.md", dir.path().display());
        assert!(!is_outside_git_tree(Some(&traversal)));
        assert!(!is_outside_git_tree(None));
    }

    #[test]
    fn a_file_in_a_git_work_tree_is_not_outside() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        assert!(!is_outside_git_tree(repo.join("notes.md").to_str()));
        assert!(!is_outside_git_tree(repo.join("deep/new/x.sh").to_str()));
        assert!(is_outside_git_tree(root.path().join("notes.md").to_str()));
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_into_a_work_tree_is_not_outside() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("link");
        std::os::unix::fs::symlink(&repo, &link).unwrap();
        assert!(!is_outside_git_tree(link.join("notes.md").to_str()));
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
