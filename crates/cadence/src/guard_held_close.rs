//! Block `gh issue close` when the target is on the HELD ledger
//! (cameronsjo/cadence-hooks#612).
//!
//! `cadence:tend`'s `drain` move never closes a HELD issue — the relicense
//! chain and its dependents — but that protection lived in prose and a
//! report-side `[HELD]` tag, and nothing stopped a raw `gh issue close`. This
//! guard makes it enforcement.
//!
//! **The ledger.** `owner/repo#N` tokens separated by whitespace — the format
//! `backlog-report.sh` already uses. `CADENCE_DRAIN_HELD`, the script's own
//! override, wins when set and non-empty (the script reads it with `:-`, so an
//! empty value means "use the default" there too); otherwise the file named by
//! `--ledger`, where a line starting with `#` is a comment. No ledger, or one
//! with no valid entry, means nothing is held and every close is allowed.
//!
//! **Matching errs toward blocking.** A close is blocked when any candidate
//! issue it could name is on the ledger:
//!
//! - Every operand that reads as an issue — `N`, `#N`, or an
//!   `https://HOST/OWNER/REPO/issues/N` URL — is a candidate, not only the
//!   one gh will treat as the selector. A flag value that happens to be a
//!   held number (`--comment 354`) therefore blocks too; that over-block is
//!   deliberate and costs a reworded command.
//! - A number is matched against every repository the call could mean: each
//!   `-R`/`--repo`/`GH_REPO=` value when the command names one, else every
//!   remote of the checkout the command runs in (gh picks among them). When
//!   no repository can be read at all — no remotes, an unreadable `-R`, a
//!   `GH_HOST=` override — the number is matched against every ledger entry.
//! - A selector that is not a literal (`$n`, a substitution) cannot be read,
//!   so the whole command is searched for a held entry's number in the same
//!   repositories: `for n in 12 354; do gh issue close "$n"; done` blocks.
//!
//! Deliberately let through, each for a stated reason: a non-literal selector
//! whose value never appears in the command text (read from a file or a
//! pipe); `gh issue close` behind a prefix the shared walk does not peel
//! (`xargs`, `sudo`, `timeout`, `env -i`); a gh alias that expands to a close
//! (the alias name is not `issue close` in the command text); and every route
//! that ends or removes an issue without `gh issue close` — `gh issue delete`,
//! `gh issue transfer`, `gh api -X PATCH …/issues/N -f state=closed`, a
//! GraphQL `closeIssue` mutation, and a merged PR's closing keyword. The
//! guard's own failure to read the ledger allows (ADR-0001).

use cadence_hooks_core::shell::{
    GhIssueCall, command_segments, command_segments_with_dirs, gh_issue_calls, git_command,
    parse_work_dir, tokenize,
};
use cadence_hooks_core::{Check, CheckResult, HookInput};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// One ledger entry: owner and repo lowercased (GitHub names are
/// case-insensitive), and the issue number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeldIssue {
    pub owner: String,
    pub repo: String,
    pub number: u64,
}

impl std::fmt::Display for HeldIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}#{}", self.owner, self.repo, self.number)
    }
}

/// A safe owner or repo name: ASCII letters, digits, `.`, `_`, `-`.
fn is_name(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parse one `owner/repo#N` token.
fn parse_entry(token: &str) -> Option<HeldIssue> {
    let (slug, number) = token.split_once('#')?;
    let (owner, repo) = slug.split_once('/')?;
    if !is_name(owner) || !is_name(repo) {
        return None;
    }
    let number = number.parse::<u64>().ok()?;
    Some(HeldIssue {
        owner: owner.to_ascii_lowercase(),
        repo: repo.to_ascii_lowercase(),
        number,
    })
}

/// Parse ledger text: whitespace-separated entries, `#`-led lines are
/// comments, anything that is not an entry is skipped.
pub fn parse_ledger(text: &str) -> Vec<HeldIssue> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .filter_map(parse_entry)
        .collect()
}

/// Which ledger text applies: the env override when non-empty, else the file.
pub fn ledger_text(env_value: Option<&str>, file_text: Option<&str>) -> Option<String> {
    env_value
        .filter(|v| !v.trim().is_empty())
        .or(file_text)
        .map(String::from)
}

/// An `owner/repo` pair, lowercased.
type Slug = (String, String);

/// `owner/repo` or `host/owner/repo` from a `-R`/`GH_REPO` value.
fn slug_of_repo_value(value: &str) -> Option<Slug> {
    let parts: Vec<&str> = value.trim_end_matches(".git").split('/').collect();
    let (owner, repo) = match parts.as_slice() {
        [owner, repo] | [_, owner, repo] => (*owner, *repo),
        _ => return None,
    };
    (is_name(owner) && is_name(repo))
        .then(|| (owner.to_ascii_lowercase(), repo.to_ascii_lowercase()))
}

/// What an operand says about the issue it may name.
enum Candidate {
    Number(u64),
    Url(Slug, u64),
}

/// Strip a case-insensitive `prefix` from `s`.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// Read `N`, `#N`, `+N` (gh's `strconv.Atoi` accepts a leading `+`), or an
/// `http(s)://HOST/OWNER/REPO/issues/N[…]` URL, scheme and path segment
/// matched case-insensitively.
fn candidate(token: &str) -> Option<Candidate> {
    let bare = token.strip_prefix('#').unwrap_or(token);
    let bare = bare.strip_prefix('+').unwrap_or(bare);
    if !bare.is_empty() && bare.bytes().all(|b| b.is_ascii_digit()) {
        return bare.parse().ok().map(Candidate::Number);
    }
    let rest = strip_prefix_ci(token, "https://").or_else(|| strip_prefix_ci(token, "http://"))?;
    let parts: Vec<&str> = rest.split(['/', '?', '#']).collect();
    match parts.as_slice() {
        [_host, owner, repo, issues, number, ..]
            if issues.eq_ignore_ascii_case("issues") && is_name(owner) && is_name(repo) =>
        {
            let n = number.parse().ok()?;
            Some(Candidate::Url(
                (owner.to_ascii_lowercase(), repo.to_ascii_lowercase()),
                n,
            ))
        }
        _ => None,
    }
}

/// True when a token is not a literal the shell hands to gh as-is.
fn is_non_literal(token: &str) -> bool {
    token.contains('$') || token.contains('`')
}

/// Every repo override value among a call's own operands: `-R v`,
/// `--repo v`, `--repo=v`, `-Rv`. The shared walk stops reading repo flags at
/// the first positional, so `gh issue close 354 -R o/r` needs this pass.
/// A trailing flag with no value yields an empty string, which no slug
/// parses, so it widens the match rather than narrowing it.
fn operand_repo_values(operands: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(token) = operands.get(i) {
        if token == "--" {
            break;
        }
        if token == "-R" || token == "--repo" {
            out.push(operands.get(i + 1).cloned().unwrap_or_default());
            i += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--repo=") {
            out.push(v.to_string());
        } else if let Some(v) = token.strip_prefix("-R") {
            out.push(v.to_string());
        }
        i += 1;
    }
    out
}

/// The repositories a numeric selector may belong to. `None` means "cannot
/// say" — match every ledger entry.
fn repos_for(call: &GhIssueCall, cwd_repos: &[Slug]) -> Option<Vec<Slug>> {
    if call.host_overridden {
        return None;
    }
    let mut values = call.repo_targets.clone();
    values.extend(operand_repo_values(&call.operands));
    if call.retargeted || !values.is_empty() {
        let parsed: Option<Vec<Slug>> = values.iter().map(|v| slug_of_repo_value(v)).collect();
        return parsed.filter(|p| !p.is_empty());
    }
    (!cwd_repos.is_empty()).then(|| cwd_repos.to_vec())
}

/// Held entries matching `number` in `repos` (`None`: in any repo).
fn held_number<'a>(
    ledger: &'a [HeldIssue],
    repos: Option<&[Slug]>,
    number: u64,
) -> impl Iterator<Item = &'a HeldIssue> {
    let repos: Option<Vec<Slug>> = repos.map(<[Slug]>::to_vec);
    ledger.iter().filter(move |h| {
        h.number == number
            && repos
                .as_ref()
                .is_none_or(|rs| rs.iter().any(|(o, r)| *o == h.owner && *r == h.repo))
    })
}

/// The held entries one `gh issue close` call could close.
///
/// `full_command` is searched only when a selector is non-literal (see the
/// module docs). `cwd_repos` are the slugs of every remote of the checkout
/// the command runs in.
pub fn held_targets(
    call: &GhIssueCall,
    full_command: &str,
    ledger: &[HeldIssue],
    cwd_repos: &[Slug],
) -> BTreeSet<HeldIssue> {
    let mut hits = BTreeSet::new();
    if call.subcommand != "close" {
        return hits;
    }
    let repos = repos_for(call, cwd_repos);
    let mut non_literal = false;
    for token in &call.operands {
        match candidate(token) {
            Some(Candidate::Number(n)) => {
                hits.extend(held_number(ledger, repos.as_deref(), n).cloned());
            }
            Some(Candidate::Url((owner, repo), n)) => {
                hits.extend(
                    ledger
                        .iter()
                        .filter(|h| h.number == n && h.owner == owner && h.repo == repo)
                        .cloned(),
                );
            }
            None => non_literal |= is_non_literal(token),
        }
    }
    if non_literal {
        for token in command_segments(full_command)
            .iter()
            .flat_map(|segment| tokenize(segment))
        {
            if let Some(Candidate::Number(n)) = candidate(&token) {
                hits.extend(held_number(ledger, repos.as_deref(), n).cloned());
            }
        }
    }
    hits
}

/// The block message for the held entries a close would hit.
fn block_message(hits: &BTreeSet<HeldIssue>) -> String {
    let listed = hits
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "guard-held-close: {listed} is on the HELD ledger and must not be closed. HELD \
         issues (the relicense chain and its dependents) stay open until the operator \
         releases them; `cadence:tend`'s drain treats them read-only. If the hold has \
         genuinely ended, remove the entry from the ledger first (the file this hook is \
         wired with, or `CADENCE_DRAIN_HELD`)."
    )
}

/// Slugs of every remote of the checkout at `work_dir`.
fn remote_slugs(work_dir: &str) -> Vec<Slug> {
    let Some(out) = git_command(work_dir, &["remote", "-v"]) else {
        return Vec::new();
    };
    let mut slugs: Vec<Slug> = out
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(cadence_hooks_core::shell::host_and_repo_from_url)
        .filter_map(|(_host, slug)| slug_of_repo_value(&slug))
        .collect();
    slugs.sort();
    slugs.dedup();
    slugs
}

/// Most distinct directories [`close_repos`] reads remotes in. Each is a git
/// spawn, and a hook that runs past its deadline fails open.
const MAX_CLOSE_DIRS: usize = 16;

/// Slugs of every remote a bare `gh issue close` in `command` may resolve
/// against, or `None` past [`MAX_CLOSE_DIRS`] directories.
///
/// Read in two directories and unioned, so a held number matches in either:
/// the whole-command [`parse_work_dir`] one, and the one each close's own
/// segment runs in ([`command_segments_with_dirs`]). The whole-command scan
/// misses a `cd` on a later line, after a backgrounded command, or in a
/// `{ …; }` group, and lets a subshell's `cd` leak into the parent. The
/// slugs are unioned, and a directory with no readable remote empties the
/// list — [`held_targets`] reads an empty list as "any repository" — so
/// either reading can only add a hit, never remove one.
fn close_repos(command: &str, cwd: &str) -> Option<Vec<Slug>> {
    let mut dirs = vec![parse_work_dir(command, cwd)];
    for (segment, dir) in command_segments_with_dirs(command, cwd) {
        if dirs.iter().any(|seen| *seen == *dir)
            || !gh_issue_calls(&segment)
                .iter()
                .any(|call| call.subcommand == "close")
        {
            continue;
        }
        if dirs.len() == MAX_CLOSE_DIRS {
            return None;
        }
        dirs.push(dir.to_string());
    }
    let mut slugs: Vec<Slug> = Vec::new();
    for dir in &dirs {
        let found = remote_slugs(dir);
        // No remote read means a bare close matches a held number in any
        // repository, the widest reading, so it wins outright.
        if found.is_empty() {
            return Some(Vec::new());
        }
        slugs.extend(found);
    }
    slugs.sort();
    slugs.dedup();
    Some(slugs)
}

/// Blocks `gh issue close` against the HELD ledger.
pub struct GuardHeldClose {
    /// The ledger file named by `--ledger`, if any.
    pub ledger_path: Option<String>,
}

impl Check for GuardHeldClose {
    fn name(&self) -> &str {
        "guard-held-close"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };
        let calls: Vec<GhIssueCall> = gh_issue_calls(command)
            .into_iter()
            .filter(|c| c.subcommand == "close")
            .collect();
        if calls.is_empty() {
            return CheckResult::allow();
        }
        let env_value = std::env::var("CADENCE_DRAIN_HELD").ok();
        let file_text = self
            .ledger_path
            .as_ref()
            .and_then(|p| cadence_hooks_core::paths::read_untrusted_config(&PathBuf::from(p)));
        let Some(text) = ledger_text(env_value.as_deref(), file_text.as_deref()) else {
            return CheckResult::allow();
        };
        let ledger = parse_ledger(&text);
        if ledger.is_empty() {
            return CheckResult::allow();
        }
        let cwd_fallback = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
        let cwd = input.cwd.as_deref().unwrap_or(&cwd_fallback);
        let Some(cwd_repos) = close_repos(command, cwd) else {
            return CheckResult::block(format!(
                "guard-held-close: the `gh issue close` calls in this command run in more \
                 than {MAX_CLOSE_DIRS} directories, too many to check against the HELD \
                 ledger. Run the closes in fewer commands."
            ));
        };
        let hits: BTreeSet<HeldIssue> = calls
            .iter()
            .flat_map(|c| held_targets(c, command, &ledger, &cwd_repos))
            .collect();
        if hits.is_empty() {
            CheckResult::allow()
        } else {
            CheckResult::block(block_message(&hits))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;

    const LEDGER: &str = "# relicense chain\n\
        cameronsjo/cadence#107 cameronsjo/cadence-hooks#127\n\
        cameronsjo/cadence-ecosystem#354 not-an-entry\n";

    fn ledger() -> Vec<HeldIssue> {
        parse_ledger(LEDGER)
    }

    fn slug(s: &str) -> Slug {
        let (o, r) = s.split_once('/').unwrap();
        (o.to_string(), r.to_string())
    }

    fn hits(command: &str, cwd_repos: &[Slug]) -> Vec<String> {
        let ledger = ledger();
        gh_issue_calls(command)
            .iter()
            .flat_map(|c| held_targets(c, command, &ledger, cwd_repos))
            .map(|h| h.to_string())
            .collect()
    }

    #[test]
    fn ledger_parses_entries_and_skips_comments_and_junk() {
        let l = ledger();
        assert_eq!(l.len(), 3);
        assert_eq!(l[2].to_string(), "cameronsjo/cadence-ecosystem#354");
        assert!(parse_ledger("# cameronsjo/cadence#1\n").is_empty());
    }

    #[test]
    fn env_override_wins_only_when_non_empty() {
        assert_eq!(
            ledger_text(Some("a/b#1"), Some("c/d#2")).as_deref(),
            Some("a/b#1")
        );
        assert_eq!(
            ledger_text(Some("  "), Some("c/d#2")).as_deref(),
            Some("c/d#2")
        );
        assert_eq!(ledger_text(None, None), None);
    }

    #[test]
    fn explicit_repo_close_of_a_held_issue_blocks() {
        assert_eq!(
            hits("gh issue close 354 -R cameronsjo/cadence-ecosystem", &[]),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert_eq!(
            hits(
                "gh issue close -R CameronSjo/Cadence-Ecosystem '#354' -c done",
                &[]
            ),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert_eq!(
            hits("GH_REPO=cameronsjo/cadence gh issue close 107", &[]),
            ["cameronsjo/cadence#107"]
        );
        assert_eq!(
            hits("gh -R github.com/cameronsjo/cadence issue close 107", &[]),
            ["cameronsjo/cadence#107"]
        );
    }

    #[test]
    fn plus_signed_numbers_and_uppercase_url_schemes_are_read() {
        assert_eq!(
            hits("gh issue close +354 -R cameronsjo/cadence-ecosystem", &[]),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert_eq!(
            hits(
                "gh issue close HTTPS://GitHub.com/cameronsjo/cadence-ecosystem/Issues/354",
                &[]
            ),
            ["cameronsjo/cadence-ecosystem#354"]
        );
    }

    #[test]
    fn same_number_in_another_repo_is_allowed() {
        assert!(hits("gh issue close 354 -R cameronsjo/cadence", &[]).is_empty());
        assert!(hits("gh issue close 12 -R cameronsjo/cadence-ecosystem", &[]).is_empty());
    }

    #[test]
    fn url_selector_names_its_own_repo() {
        assert_eq!(
            hits(
                "gh issue close https://github.com/cameronsjo/cadence-hooks/issues/127",
                &[]
            ),
            ["cameronsjo/cadence-hooks#127"]
        );
        assert!(hits("gh issue close https://github.com/other/x/issues/127", &[]).is_empty());
    }

    #[test]
    fn cwd_remotes_scope_a_bare_number() {
        let repos = [slug("cameronsjo/cadence-ecosystem")];
        assert_eq!(
            hits("gh issue close 354", &repos),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        let other = [slug("someone/else")];
        assert!(hits("gh issue close 354", &other).is_empty());
    }

    #[test]
    fn unknown_repo_matches_the_number_anywhere_on_the_ledger() {
        assert_eq!(
            hits("gh issue close 354", &[]),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert_eq!(
            hits("gh issue close 354 -R \"$REPO\"", &[slug("someone/else")]),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert_eq!(
            hits(
                "GH_HOST=example.com gh issue close 354 -R someone/else",
                &[]
            ),
            ["cameronsjo/cadence-ecosystem#354"]
        );
    }

    #[test]
    fn a_flag_value_that_is_a_held_number_blocks() {
        assert_eq!(
            hits(
                "gh issue close 12 --comment 354 -R cameronsjo/cadence-ecosystem",
                &[]
            ),
            ["cameronsjo/cadence-ecosystem#354"]
        );
    }

    #[test]
    fn non_literal_selector_searches_the_whole_command() {
        let repos = [slug("cameronsjo/cadence-ecosystem")];
        assert_eq!(
            hits(
                "for n in 12 354; do gh issue close \"$n\" -c stale; done",
                &repos
            ),
            ["cameronsjo/cadence-ecosystem#354"]
        );
        assert!(hits("for n in 12 13; do gh issue close \"$n\"; done", &repos).is_empty());
    }

    #[test]
    fn other_issue_subcommands_are_ignored() {
        assert!(hits("gh issue view 354 -R cameronsjo/cadence-ecosystem", &[]).is_empty());
        assert!(hits("gh issue reopen 354 -R cameronsjo/cadence-ecosystem", &[]).is_empty());
        assert!(hits("echo gh issue close 354", &[]).is_empty());
    }

    #[test]
    fn prefixed_and_compound_spellings_are_seen() {
        assert_eq!(
            hits(
                "cd /tmp && env gh issue close 107 -R cameronsjo/cadence",
                &[]
            ),
            ["cameronsjo/cadence#107"]
        );
        assert_eq!(
            hits(
                "true; /usr/bin/gh issue close 107 -R cameronsjo/cadence",
                &[]
            ),
            ["cameronsjo/cadence#107"]
        );
    }

    #[test]
    fn check_blocks_via_the_ledger_file_and_allows_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.txt");
        std::fs::write(&path, LEDGER).unwrap();
        let input = cadence_hooks_core::test_builders::make_bash_with_cwd(
            "gh issue close 354 -R cameronsjo/cadence-ecosystem",
            dir.path().to_str().unwrap(),
        );
        // `CADENCE_DRAIN_HELD` is read in `run`; these assertions hold only
        // when it is unset, which is the default for the suite.
        if std::env::var("CADENCE_DRAIN_HELD").is_ok_and(|v| !v.trim().is_empty()) {
            return;
        }
        let guard = GuardHeldClose {
            ledger_path: Some(path.to_string_lossy().into_owned()),
        };
        let result = guard.run(&input);
        assert_eq!(result.outcome, Outcome::Block);
        assert!(
            result
                .message
                .unwrap()
                .contains("cameronsjo/cadence-ecosystem#354")
        );
        let no_ledger = GuardHeldClose { ledger_path: None };
        assert_eq!(no_ledger.run(&input).outcome, Outcome::Allow);
        let missing = GuardHeldClose {
            ledger_path: Some(dir.path().join("absent").to_string_lossy().into_owned()),
        };
        assert_eq!(missing.run(&input).outcome, Outcome::Allow);
    }

    /// A hermetic checkout whose `origin` is `url`.
    fn origin_checkout(url: &str) -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        cadence_hooks_core::git_fixtures::init_repo(repo.path());
        cadence_hooks_core::git_fixtures::git_in(repo.path(), &["remote", "add", "origin", url]);
        repo
    }

    /// A bare close is matched against the remotes of the whole-command
    /// directory AND of the directory its own segment runs in. Every row is
    /// `(command, run from the held repo's checkout?, blocks?)`; `{H}` is the
    /// checkout whose origin carries a held number, `{F}` one that does not.
    #[test]
    fn bare_close_is_judged_where_its_own_segment_runs() {
        if std::env::var("CADENCE_DRAIN_HELD").is_ok_and(|v| !v.trim().is_empty()) {
            return;
        }
        let held = origin_checkout("https://github.com/cameronsjo/cadence-ecosystem.git");
        let free = origin_checkout("https://github.com/cameronsjo/free.git");
        let h = held.path().to_str().unwrap();
        let f = free.path().to_str().unwrap();
        let ledger_dir = tempfile::tempdir().unwrap();
        let ledger = ledger_dir.path().join("held.txt");
        std::fs::write(&ledger, LEDGER).unwrap();
        let guard = GuardHeldClose {
            ledger_path: Some(ledger.to_string_lossy().into_owned()),
        };
        for (command, in_held, blocks) in [
            // Allowed on the base.
            ("echo hi\ncd {H}\ngh issue close 354", false, true),
            ("true & cd {H}; gh issue close 354", false, true),
            ("{ cd {H}; }; gh issue close 354", false, true),
            ("(true; cd {F} ); gh issue close 354", true, true),
            // Blocked on the base, and still.
            ("cd {H} && gh issue close 354", false, true),
            ("gh issue close 354", true, true),
            // Controls.
            ("gh issue close 354", false, false),
            ("cd {F} && gh issue close 354", true, false),
            (
                "(cd {H} && gh issue view 354); gh issue close 354",
                false,
                false,
            ),
            // A directory with no readable remote matches any repository in
            // either reading, and still does when the other has a remote.
            ("(true; cd /nonexistent ); gh issue close 354", false, true),
            ("cd /nonexistent | cat; gh issue close 354", false, true),
            ("echo hi\ncd /nonexistent\ngh issue close 354", false, true),
        ] {
            let command = command.replace("{H}", h).replace("{F}", f);
            let cwd = if in_held { h } else { f };
            let input = cadence_hooks_core::test_builders::make_bash_with_cwd(&command, cwd);
            let result = guard.run(&input);
            assert_eq!(
                result.outcome == Outcome::Block,
                blocks,
                "{command} (from {cwd}): {:?}",
                result.message
            );
        }
    }
}
