//! Guard against unintended `gh` write operations.
//!
//! Detects `gh` sub-commands that mutate GitHub state (create, merge, close,
//! comment, edit, delete, etc.) and verifies the target repository belongs to
//! an allowed owner list. Also blocks looped writes and cross-repo mutations.

use cadence_hooks_core::config::{
    self, AllowEntry, default_host, env_allow_entries, env_extra_hosts,
};
use cadence_hooks_core::loop_analysis::{self, LoopAnalysis};
use cadence_hooks_core::shell::{
    LOOP_PATTERN, command_segments, git_command, host_and_repo_from_url, parse_work_dir,
    strip_quotes, tokenize,
};
use cadence_hooks_core::{BlockMetadata, Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

// --- Write detection patterns ---

static WRITE_ACTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"gh\s+(pr|issue|release|label|repo|gist|workflow)\s+(create|merge|close|comment|edit|delete|transfer|archive|rename|review|reopen|ready|lock|unlock|fork|run|enable|disable)"
    ).expect("pattern should compile")
});

static API_WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*(-X|--method)\s+(?i)(POST|PUT|PATCH|DELETE)")
        .expect("pattern should compile")
});

static API_FIELD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+api.*\s(-f[\s\S]|--field[\s=]|-F[\s\S]|--raw-field[\s=])")
        .expect("pattern should compile")
});

static API_INPUT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+api.*\s--input\s").expect("pattern should compile"));

static REPO_SUBCOMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh\s+repo\s+(archive|delete|rename|unarchive|fork|clone|create)\b")
        .expect("pattern should compile")
});

static API_REPOS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/?repos/([^/]+/[^/ ]+)").expect("pattern should compile"));

/// Word-boundary, case-insensitive match for the GraphQL `mutation` keyword —
/// the signal that a `gh api graphql` query writes rather than reads.
static MUTATION_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bmutation\b").expect("pattern should compile"));

static GIST_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+gist\s").expect("pattern should compile"));

static REPO_FORK_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh\s+repo\s+fork\b").expect("pattern should compile"));

fn is_write_command(command: &str) -> bool {
    WRITE_ACTIONS.is_match(command)
        || API_WRITE_METHOD.is_match(command)
        || API_FIELD_FLAGS.is_match(command)
        || API_INPUT_FLAG.is_match(command)
}

/// Extract a `-R`/`--repo` flag value from a raw command string.
///
/// Handles all four gh CLI forms: `-R x`, `-Rx`, `--repo x`, `--repo=x` —
/// mirroring `loop_analysis::extract_repo_flag`, which does the same over
/// parsed AST words. Values keep their quotes trimmed so `--repo "o/r"`
/// resolves to `o/r`.
fn extract_repo_flag_str(command: &str) -> Option<String> {
    let trim_value = |s: &str| s.trim_matches(|c| c == '"' || c == '\'').to_string();
    let words: Vec<&str> = command.split_whitespace().collect();
    let mut iter = words.iter();
    while let Some(word) = iter.next() {
        if *word == "-R" || *word == "--repo" {
            return iter.next().map(|s| trim_value(s));
        }
        if let Some(repo) = word.strip_prefix("--repo=") {
            return Some(trim_value(repo));
        }
        // Compact form: -Rowner/repo (no space). Exclude other dash-prefixed
        // flags by requiring the remainder not start with another dash.
        if let Some(repo) = word.strip_prefix("-R")
            && !repo.is_empty()
            && !repo.starts_with('-')
        {
            return Some(trim_value(repo));
        }
    }
    None
}

/// Resolve target repo from command context.
#[derive(Debug)]
enum RepoResolution {
    /// Fully resolved: host + "owner/repo"
    Resolved { host: String, repo: String },
    /// Fork detected: both origin and upstream remotes present, each with its
    /// own host so ownership can be judged per-remote.
    Fork {
        origin_host: String,
        origin: String,
        upstream_host: String,
        upstream: String,
    },
    /// Cannot determine target
    Unresolvable,
}

fn resolve_target_repo(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
) -> RepoResolution {
    let dh = default_host();

    // 1. Explicit -R / --repo flag (gh CLI always targets GH_HOST or github.com)
    if let Some(repo) = extract_repo_flag_str(command) {
        return RepoResolution::Resolved { host: dh, repo };
    }

    // 2. gh repo <subcommand> <owner/repo> (positional arg)
    if let Some(caps) = REPO_SUBCOMMAND.captures(command) {
        let subcommand = caps.get(1).unwrap().as_str();
        let split_key = format!("gh repo {subcommand}");
        let after = command.split(&split_key).nth(1).unwrap_or("").trim();
        let first_arg = after.split_whitespace().next().unwrap_or("");
        if !first_arg.is_empty() && !first_arg.starts_with('-') {
            if first_arg.contains('/') {
                return RepoResolution::Resolved {
                    host: dh,
                    repo: first_arg.to_string(),
                };
            }
            // Only `create` can infer owner from a bare name (no `/`)
            if subcommand == "create" {
                let default_owner = allowed_owners
                    .iter()
                    .find(|e| e.host.is_none() || e.host.as_deref() == Some(&dh))
                    .map(|e| e.owner.as_str())
                    .unwrap_or("");
                return RepoResolution::Resolved {
                    host: dh,
                    repo: format!("{default_owner}/{first_arg}"),
                };
            }
        }
    }

    // 3. gh api repos/OWNER/REPO
    if let Some(caps) = API_REPOS.captures(command)
        && let Some(repo) = caps.get(1)
    {
        return RepoResolution::Resolved {
            host: dh,
            repo: repo.as_str().to_string(),
        };
    }

    // 4. Git remotes (with fork detection)
    resolve_from_git_remotes(work_dir)
}

/// Resolve a repo purely from a directory's git remotes (fork-aware).
///
/// Shared by single-command resolution (when no explicit target appears in
/// the command) and the deterministic-loop policy (where command-string
/// flags are absent by definition).
fn resolve_from_git_remotes(work_dir: &str) -> RepoResolution {
    if let Some(upstream_url) = git_command(work_dir, &["remote", "get-url", "upstream"]) {
        let origin_url =
            git_command(work_dir, &["remote", "get-url", "origin"]).unwrap_or_default();
        let (origin_host, origin) = host_and_repo_from_url(&origin_url).unwrap_or_default();
        let (upstream_host, upstream) = host_and_repo_from_url(&upstream_url).unwrap_or_default();
        return RepoResolution::Fork {
            origin_host,
            origin,
            upstream_host,
            upstream,
        };
    }

    if let Some(origin_url) = git_command(work_dir, &["remote", "get-url", "origin"]) {
        match host_and_repo_from_url(&origin_url) {
            Some((host, repo)) => return RepoResolution::Resolved { host, repo },
            None => return RepoResolution::Unresolvable,
        }
    }

    RepoResolution::Unresolvable
}

fn is_allowed(
    host: &str,
    repo: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
) -> bool {
    is_allowed_with_extras(host, repo, allowed_owners, allowed_repos, &[])
}

/// Like [`is_allowed`], but bare allowlist entries also match hosts listed in
/// `CADENCE_EXTRA_HOSTS`. Used on paths where the target host comes from git
/// remotes (single-command resolution, fork checks, deterministic loops) —
/// explicit `-R` targets always go to the default host, so they don't need it.
fn is_allowed_with_extras(
    host: &str,
    repo: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    let mut parts = repo.splitn(2, '/');
    let owner = parts.next().unwrap_or("");
    let repo_name = parts.next().unwrap_or("");
    config::is_allowed_with_extra_hosts(
        host,
        owner,
        repo_name,
        allowed_owners,
        allowed_repos,
        extra_hosts,
    )
}

/// Judge a fork (origin + upstream remotes) for write access: allowed iff
/// **both** remotes belong to allowed owners, each checked against its own host.
fn fork_allowed(
    origin_host: &str,
    origin: &str,
    upstream_host: &str,
    upstream: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> bool {
    // Fail closed on unparseable remotes: an empty repo string means we could
    // not extract owner/repo from the remote URL.
    !origin.is_empty()
        && !upstream.is_empty()
        && is_allowed_with_extras(
            origin_host,
            origin,
            allowed_owners,
            allowed_repos,
            extra_hosts,
        )
        && is_allowed_with_extras(
            upstream_host,
            upstream,
            allowed_owners,
            allowed_repos,
            extra_hosts,
        )
}

/// Policy decision for a gh write inside a loop without an explicit `-R` flag.
#[derive(Debug, PartialEq)]
enum LoopWriteDecision {
    /// Deterministic loop in an owned repo — allow.
    Allow,
    /// Block, optionally suggesting the resolved `-R owner/repo` fix.
    Block { suggestion: Option<String> },
}

/// Judge a looped gh write that lacks an explicit `-R` target.
///
/// Relaxed policy (default): allow iff the loop body provably never changes
/// directory AND the cwd resolves to a single owned, non-fork repo. Under
/// those conditions every iteration's gh resolves to the same repo the hook
/// sees — identical trust to a single command.
///
/// Strict policy (`CADENCE_GH_STRICT_LOOPS=1`): always block, but include the
/// resolved repo as a copy-paste `-R` suggestion when available.
fn judge_loop_write(
    strict: bool,
    body_mutates_cwd: Option<bool>,
    cwd_resolution: &RepoResolution,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> LoopWriteDecision {
    // A concrete -R suggestion exists exactly when the cwd resolves to a
    // single owned, non-fork repo. (Empty allowlists can never produce one —
    // the unconfigured fail-safe holds for loops too.)
    let suggestion = match cwd_resolution {
        RepoResolution::Resolved { host, repo }
            if is_allowed_with_extras(host, repo, allowed_owners, allowed_repos, extra_hosts) =>
        {
            Some(repo.clone())
        }
        _ => None,
    };

    // Relaxed: the loop body provably never changes directory, so every
    // iteration's gh resolves to the suggested repo — same trust as a
    // single command. Anything else (strict mode, cd in body, parse
    // failure, fork, unowned/unresolvable cwd) blocks.
    if !strict && body_mutates_cwd == Some(false) && suggestion.is_some() {
        return LoopWriteDecision::Allow;
    }

    LoopWriteDecision::Block { suggestion }
}

/// Render the configured allowlist as a flat Vec of display strings.
/// Owners and repo-scoped entries are interleaved; both prose messages
/// (`disallowed_message`) and structured payloads
/// ([`BlockMetadata::allowed_owners`]) treat them as one displayable set.
fn allowed_display_list(owners: &[AllowEntry], repos: &[AllowEntry]) -> Vec<String> {
    owners
        .iter()
        .chain(repos.iter())
        .map(|e| e.to_string())
        .collect()
}

/// Build the block message for a looped gh write, with a concrete `-R` fix
/// when the cwd resolved to an owned repo.
fn loop_block_message(writes: &[String], suggestion: Option<&str>) -> String {
    let found = if writes.is_empty() {
        "gh write command(s) without -R".to_string()
    } else {
        writes.join(", ")
    };
    let fix_target = suggestion.unwrap_or("owner/repo");
    format!(
        "🚫 git-guardrails: gh write command in loop without explicit -R flag\n   \
         Found: {found}\n   \
         Fix: add `-R {fix_target}` to each command",
    )
}

/// Build the block message for an unresolvable target, naming the directory
/// that failed to resolve and a concrete `-R` example.
fn unresolvable_message(work_dir: &str, example_owner: Option<&str>) -> String {
    let owner = example_owner.unwrap_or("owner");
    format!(
        "⚠️  git-guardrails: Cannot determine target repo for gh write operation\n   \
         Directory: {work_dir}\n   \
         Fix: add `-R {owner}/<repo>` to target a repo explicitly"
    )
}

/// Build the block message for a disallowed target, including a host-scoping
/// hint when the target host is neither the default nor in `CADENCE_EXTRA_HOSTS`.
fn disallowed_message(
    host: &str,
    repo: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> String {
    let all_entries = allowed_display_list(allowed_owners, allowed_repos);

    // Self-hosted-forge users trip over host scoping: bare allowlist entries
    // match the default host only. Tell them how to widen, mirroring
    // guard_push_remote's hint.
    let default = default_host();
    let host_hint = if host != default && !extra_hosts.iter().any(|e| e == host) {
        format!(
            "\n   Host scope: bare entries match `{default}` only — for `{host}`, qualify them (`{host}/<owner>`) or set `CADENCE_EXTRA_HOSTS={host}`"
        )
    } else {
        String::new()
    };

    format!(
        "🚫 git-guardrails: gh write targets repo you don't own\n   \
         Target:  {host}/{repo}\n   \
         Allowed: {}{host_hint}\n\n   \
         DO NOT override with env vars. Instead:\n   \
         1. Confirm the user intends to write to this repo\n   \
         2. Write a shell script the user can execute manually",
        all_entries.join(" ")
    )
}

/// gh api flags whose value is carried in the *following* token (`-X POST`,
/// `-f key=val`, …). Used to skip a flag's value when scanning for the
/// positional api endpoint.
fn api_flag_takes_separate_value(flag: &str) -> bool {
    matches!(
        flag,
        "-X" | "--method"
            | "-f"
            | "--field"
            | "-F"
            | "--raw-field"
            | "-H"
            | "--header"
            | "-q"
            | "--jq"
            | "-t"
            | "--template"
            | "--input"
            | "--hostname"
            | "-p"
            | "--preview"
            | "--cache"
    )
}

/// If `segment` invokes `gh api` (command word `gh` or a `*/gh` basename, first
/// non-flag subcommand `api`), return its endpoint — the first positional token
/// after `api`, skipping flags and their values. `Some("")` for a bare `gh api`
/// with no endpoint; `None` when the segment isn't a `gh api` call.
fn gh_api_endpoint(segment: &str) -> Option<String> {
    let tokens = tokenize(segment);
    let first = tokens.first()?;
    let cmd = first.rsplit('/').next().unwrap_or(first);
    if cmd != "gh" {
        return None;
    }
    // First non-flag token after `gh` must be the `api` subcommand.
    let mut i = 1;
    while i < tokens.len() && tokens[i].starts_with('-') {
        i += 1;
    }
    if tokens.get(i).map(String::as_str) != Some("api") {
        return None;
    }
    i += 1;
    // The endpoint is the first positional after `api`, skipping flag values.
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok.starts_with('-') {
            if api_flag_takes_separate_value(tok) && !tok.contains('=') {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        return Some(tok.clone());
    }
    Some(String::new())
}

/// Extract the value of a `gh api graphql` `query=` field across the
/// `-f`/`--field`/`-F`/`--raw-field` forms (separate-token, compact `-fquery=…`,
/// and `=`-joined `--field=query=…`). Returns the substring after `query=`.
fn graphql_query_value(tokens: &[String]) -> Option<String> {
    let is_field_flag = |t: &str| matches!(t, "-f" | "--field" | "-F" | "--raw-field");
    for (i, tok) in tokens.iter().enumerate() {
        // Separate-token form: `-f query=…`.
        if is_field_flag(tok)
            && let Some(next) = tokens.get(i + 1)
            && let Some(v) = next.strip_prefix("query=")
        {
            return Some(v.to_string());
        }
        // Compact / `=`-joined forms: `-fquery=…`, `-Fquery=…`,
        // `--field=query=…`, `--raw-field=query=…`.
        for prefix in ["-f", "-F", "--field=", "--raw-field="] {
            if let Some(rest) = tok.strip_prefix(prefix)
                && let Some(v) = rest.strip_prefix("query=")
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Classify a `gh api graphql` segment by its `query=` field value:
/// - `Some(true)`  — an inline query containing the word `mutation` (a write)
/// - `Some(false)` — an inline query with no `mutation` keyword (a read)
/// - `None`        — the query is non-inline (`-F query=@file`) or absent, so
///   its kind can't be verified (treat as a write, and name it out)
fn graphql_mutation_status(segment: &str) -> Option<bool> {
    let tokens = tokenize(segment);
    let query = graphql_query_value(&tokens)?;
    // `@file` / `@-` (stdin) references aren't inline — undeterminable.
    if query.starts_with('@') {
        return None;
    }
    Some(MUTATION_WORD.is_match(&query))
}

/// Build the block message for a `gh api` write whose target owner can't be
/// verified (graphql, `orgs/…`, `user/…`, anything that isn't
/// `repos/<owner>/<repo>`). When `undeterminable_query` is set, the GraphQL
/// query was loaded from a file, so its mutation status couldn't be confirmed.
fn api_unverifiable_message(segment: &str, undeterminable_query: bool) -> String {
    let note = if undeterminable_query {
        "\n   Note: the GraphQL query is loaded from a file (`-F query=@…`), so its \
         mutation status can't be verified — treated as a write."
    } else {
        ""
    };
    format!(
        "🚫 git-guardrails: gh api write to an unverifiable target — ownership can't be checked\n   \
         Command: {segment}\n   \
         Fix: use `gh api repos/<owner>/<repo>/…` so ownership is checkable, or ask the user{note}"
    )
}

/// Structured block for an unverifiable `gh api` write (#78). Carries the new
/// `gh-write-api-unverifiable` rule_id and a path-shaped fix (graphql has no
/// `-R`, so the fix steers toward `repos/<owner>/<repo>`).
fn api_unverifiable_block(
    segment: &str,
    undeterminable_query: bool,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
) -> CheckResult {
    CheckResult::block_structured(
        api_unverifiable_message(segment, undeterminable_query),
        BlockMetadata {
            rule_id: "gh-write-api-unverifiable".to_string(),
            fix: "use gh api repos/<owner>/<repo>/… so ownership is checkable, or ask the user"
                .to_string(),
            allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
            severity: "error",
        },
    )
}

/// Resolve and judge a single gh write segment's target. Returns `Some(block)`
/// when the segment targets a repo outside the allowlist (or one that can't be
/// resolved), `None` when it's allowed. Per-segment resolution is what stops a
/// benign first `-R` from covering an unowned write later in the same chain.
fn judge_write_segment(
    segment: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> Option<CheckResult> {
    match resolve_target_repo(segment, work_dir, allowed_owners) {
        RepoResolution::Fork {
            origin_host,
            origin,
            upstream_host,
            upstream,
        } => {
            // Both remotes owned (each judged against its own host) — the write
            // lands somewhere you control either way.
            if fork_allowed(
                &origin_host,
                &origin,
                &upstream_host,
                &upstream,
                allowed_owners,
                allowed_repos,
                extra_hosts,
            ) {
                None
            } else {
                Some(CheckResult::block(format!(
                    "🚫 git-guardrails: Write operation in a fork — specify target with -R\n   \
                     Fork:     {origin_host}/{origin}\n   \
                     Upstream: {upstream_host}/{upstream}\n\n   \
                     Use -R {origin} to target your fork\n   \
                     Use -R {upstream} to target upstream (if intended)"
                )))
            }
        }
        RepoResolution::Unresolvable => {
            // Suggest the first allowed owner so the fix is concrete even when no
            // repo can be inferred from the directory.
            let example_owner = allowed_owners.first().map(|e| e.owner.as_str());
            let owner_for_fix = example_owner.unwrap_or("owner");
            Some(CheckResult::block_structured(
                unresolvable_message(work_dir, example_owner),
                BlockMetadata {
                    rule_id: "gh-write-target-unresolvable".to_string(),
                    fix: format!("-R {owner_for_fix}/<repo>"),
                    allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
                    severity: "error",
                },
            ))
        }
        RepoResolution::Resolved { host, repo } => {
            if is_allowed_with_extras(&host, &repo, allowed_owners, allowed_repos, extra_hosts) {
                None
            } else {
                let example_owner = allowed_owners
                    .first()
                    .map(|e| e.owner.as_str())
                    .unwrap_or("owner");
                // Reuse the repo *name* under an allowed owner so the fix lands
                // on the same project — `evil/cool-tool` becomes
                // `cameronsjo/cool-tool`, not a placeholder.
                let repo_name = repo.split('/').next_back().unwrap_or(repo.as_str());
                Some(CheckResult::block_structured(
                    disallowed_message(&host, &repo, allowed_owners, allowed_repos, extra_hosts),
                    BlockMetadata {
                        rule_id: "gh-write-unauthorized-target".to_string(),
                        fix: format!("-R {example_owner}/{repo_name}"),
                        allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
                        severity: "error",
                    },
                ))
            }
        }
    }
}

/// Guards against unintended `gh` CLI write operations on unauthorized repositories.
pub struct GhWriteGuard;

impl Check for GhWriteGuard {
    fn name(&self) -> &str {
        "guard-gh-write"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let Some(command) = input.command() else {
            return CheckResult::allow();
        };

        if !command.contains("gh") {
            return CheckResult::allow();
        }

        let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
        let allowed_repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
        let extra_hosts = env_extra_hosts();

        // AST-based loop detection with regex fallback
        match loop_analysis::analyze_gh_loops(command) {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                // All gh commands in loops have explicit -R flags — check ownership
                // -R targets are always on the default host (gh CLI convention)
                let dh = default_host();
                let all_owned = cmds.iter().all(|c| {
                    c.explicit_repo
                        .as_ref()
                        .is_some_and(|r| is_allowed(&dh, r, &allowed_owners, &allowed_repos))
                });
                if !all_owned {
                    let targets: Vec<&str> = cmds
                        .iter()
                        .filter_map(|c| c.explicit_repo.as_deref())
                        .collect();
                    let all_entries: Vec<String> = allowed_owners
                        .iter()
                        .chain(allowed_repos.iter())
                        .map(|e| e.to_string())
                        .collect();
                    return CheckResult::block(format!(
                        "🚫 git-guardrails: gh loop targets repo you don't own\n   \
                         Found: {}\n   \
                         Allowed: {}\n   \
                         Fix: use `-R owner/repo` to target an owned repo",
                        targets.join(", "),
                        all_entries.join(" "),
                    ));
                }
                // All targets owned — allow the loop
            }
            LoopAnalysis::MissingTargets(cmds) => {
                // Only block if any looped gh command is a write — read-only
                // commands (gh pr list, gh issue view) are safe without -R.
                let has_write = cmds.iter().any(|c| {
                    let reconstructed = format!("gh {}", c.args.join(" "));
                    is_write_command(&reconstructed)
                });
                if has_write {
                    // Relaxed-when-deterministic policy (#44): a loop whose
                    // body never changes directory, running in an owned
                    // non-fork repo, targets that repo on every iteration —
                    // the same trust extended to single commands. Set
                    // CADENCE_GH_STRICT_LOOPS=1 to restore unconditional
                    // blocking.
                    let strict = std::env::var("CADENCE_GH_STRICT_LOOPS").is_ok_and(|v| v == "1");
                    let cwd = input.cwd.as_deref().unwrap_or(".");
                    let work_dir = parse_work_dir(command, cwd);
                    let decision = judge_loop_write(
                        strict,
                        loop_analysis::loop_bodies_mutate_cwd(command),
                        &resolve_from_git_remotes(&work_dir),
                        &allowed_owners,
                        &allowed_repos,
                        &extra_hosts,
                    );
                    if let LoopWriteDecision::Block { suggestion } = decision {
                        let writes: Vec<String> = cmds
                            .iter()
                            .filter(|c| {
                                let reconstructed = format!("gh {}", c.args.join(" "));
                                c.explicit_repo.is_none() && is_write_command(&reconstructed)
                            })
                            .map(|c| format!("`gh {}`", c.args.join(" ")))
                            .collect();
                        let fix = match suggestion.as_deref() {
                            Some(s) => format!("-R {s}"),
                            None => "-R <owner>/<repo>".to_string(),
                        };
                        return CheckResult::block_structured(
                            loop_block_message(&writes, suggestion.as_deref()),
                            BlockMetadata {
                                rule_id: "gh-write-loop-missing-repo".to_string(),
                                fix,
                                allowed_owners: allowed_display_list(
                                    &allowed_owners,
                                    &allowed_repos,
                                ),
                                severity: "error",
                            },
                        );
                    }
                    // Deterministic loop in owned repo — allow
                }
                // All looped gh commands are read-only — allow
            }
            LoopAnalysis::ParseFailed => {
                // Regex fallback when AST parser can't handle the syntax
                let stripped = strip_quotes(command);
                if LOOP_PATTERN.is_match(&stripped) {
                    return CheckResult::block(
                        "🚫 git-guardrails: gh command in loop — cannot verify targets\n   \
                         Fix: run each gh command individually with `-R owner/repo`",
                    );
                }
            }
            LoopAnalysis::NoLoops => {} // Continue to write detection
        }

        // No loops: judge each command segment independently so a benign first
        // gh write (with its own -R) can't shield an unowned write later in the
        // chain, and a write hidden in `sh -c '…'` is still seen. The first
        // disallowed / unresolvable write segment blocks.
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let work_dir = parse_work_dir(command, cwd);

        for segment in command_segments(command) {
            if !is_write_command(&segment) {
                continue;
            }

            // Fail-safe: block when unconfigured.
            if allowed_owners.is_empty() {
                return CheckResult::block(
                    "🚫 git-guardrails: Not configured — run /guardrails-init to set up\n   \
                     CADENCE_ALLOWED_OWNERS is not set.",
                );
            }

            // Gists are user-scoped; a fork creates under your account.
            if GIST_COMMAND.is_match(&segment) || REPO_FORK_COMMAND.is_match(&segment) {
                continue;
            }

            // #78: `gh api` writes can't all be resolved from the cwd remote.
            // graphql reads are exempt; any non-`repos/<owner>/<repo>` api write
            // is unverifiable — block it rather than trusting the owned checkout.
            if let Some(endpoint) = gh_api_endpoint(&segment) {
                if endpoint == "graphql" {
                    match graphql_mutation_status(&segment) {
                        // Inline read query — no ownership to check, allow.
                        Some(false) => continue,
                        // Mutation (`Some(true)`) or non-inline/undeterminable
                        // (`None`) — both block; the message names the latter.
                        status => {
                            return api_unverifiable_block(
                                &segment,
                                status.is_none(),
                                &allowed_owners,
                                &allowed_repos,
                            );
                        }
                    }
                }
                // Non-graphql api write that isn't `repos/<owner>/<repo>`
                // (graphql is handled above) can't be owner-checked.
                if !API_REPOS.is_match(&segment) {
                    return api_unverifiable_block(
                        &segment,
                        false,
                        &allowed_owners,
                        &allowed_repos,
                    );
                }
                // `repos/<owner>/<repo>` api write — fall through to the
                // existing per-segment ownership check below.
            }

            if let Some(block) = judge_write_segment(
                &segment,
                &work_dir,
                &allowed_owners,
                &allowed_repos,
                &extra_hosts,
            ) {
                return block;
            }
        }

        // No write segments, or every write segment targets an owned repo.
        CheckResult::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::config::parse_allow_entry;
    use cadence_hooks_core::loop_analysis::{LoopAnalysis, analyze_gh_loops};

    fn owners(entries: &[&str]) -> Vec<AllowEntry> {
        entries.iter().map(|e| parse_allow_entry(e)).collect()
    }

    #[test]
    fn detects_pr_create_as_write() {
        assert!(is_write_command("gh pr create --title test"));
    }

    #[test]
    fn detects_api_post_as_write() {
        assert!(is_write_command("gh api repos/foo/bar -X POST"));
    }

    #[test]
    fn pr_list_is_not_write() {
        assert!(!is_write_command("gh pr list"));
    }

    #[test]
    fn repo_flag_extraction() {
        assert_eq!(
            extract_repo_flag_str("gh pr create -R cameronsjo/test --title hi"),
            Some("cameronsjo/test".to_string())
        );
    }

    #[test]
    fn repo_flag_long_form() {
        assert_eq!(
            extract_repo_flag_str("gh issue create --repo cameronsjo/test --title hi"),
            Some("cameronsjo/test".to_string())
        );
    }

    // Write detection patterns
    #[test]
    fn issue_create_is_write() {
        assert!(is_write_command("gh issue create --title test"));
    }

    #[test]
    fn release_create_is_write() {
        assert!(is_write_command("gh release create v1.0.0"));
    }

    #[test]
    fn pr_merge_is_write() {
        assert!(is_write_command("gh pr merge 123"));
    }

    #[test]
    fn pr_close_is_write() {
        assert!(is_write_command("gh pr close 123"));
    }

    #[test]
    fn issue_comment_is_write() {
        assert!(is_write_command("gh issue comment 123 --body 'hello'"));
    }

    #[test]
    fn repo_fork_is_write() {
        assert!(is_write_command("gh repo fork owner/repo"));
    }

    #[test]
    fn api_put_is_write() {
        assert!(is_write_command("gh api repos/foo/bar -X PUT"));
    }

    #[test]
    fn api_delete_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --method DELETE"));
    }

    #[test]
    fn api_with_field_is_write() {
        assert!(is_write_command("gh api repos/foo/bar -f title=test"));
    }

    #[test]
    fn api_with_input_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --input data.json"));
    }

    #[test]
    fn issue_list_is_not_write() {
        assert!(!is_write_command("gh issue list"));
    }

    #[test]
    fn pr_view_is_not_write() {
        assert!(!is_write_command("gh pr view 123"));
    }

    #[test]
    fn api_get_is_not_write() {
        assert!(!is_write_command("gh api repos/foo/bar"));
    }

    // is_allowed
    #[test]
    fn is_allowed_by_owner() {
        assert!(is_allowed(
            "github.com",
            "cameronsjo/repo",
            &owners(&["cameronsjo"]),
            &[],
        ));
    }

    #[test]
    fn is_allowed_by_repo() {
        assert!(is_allowed(
            "github.com",
            "other/repo",
            &[],
            &owners(&["other/repo"]),
        ));
    }

    #[test]
    fn is_not_allowed_unknown() {
        assert!(!is_allowed(
            "github.com",
            "stranger/repo",
            &owners(&["cameronsjo"]),
            &[],
        ));
    }

    #[test]
    fn is_allowed_host_qualified_owner() {
        assert!(is_allowed(
            "gitea.internal",
            "cameron/repo",
            &owners(&["gitea.internal/cameron"]),
            &[],
        ));
    }

    #[test]
    fn is_not_allowed_wrong_host() {
        assert!(!is_allowed(
            "github.com",
            "cameron/repo",
            &owners(&["gitea.internal/cameron"]),
            &[],
        ));
    }

    // --- #44: fork ownership matrix ---

    #[test]
    fn fork_both_owned_allowed() {
        let o = owners(&["cameronsjo", "partner"]);
        assert!(fork_allowed(
            "github.com",
            "cameronsjo/tool",
            "github.com",
            "partner/tool",
            &o,
            &[],
            &[],
        ));
    }

    #[test]
    fn fork_unowned_upstream_blocked() {
        let o = owners(&["cameronsjo"]);
        assert!(!fork_allowed(
            "github.com",
            "cameronsjo/fork",
            "github.com",
            "stranger/orig",
            &o,
            &[],
            &[],
        ));
    }

    #[test]
    fn fork_unowned_origin_blocked() {
        let o = owners(&["cameronsjo"]);
        assert!(!fork_allowed(
            "github.com",
            "stranger/fork",
            "github.com",
            "cameronsjo/orig",
            &o,
            &[],
            &[],
        ));
    }

    #[test]
    fn fork_upstream_other_host_bare_entry_blocked() {
        // Bare owner entries match the default host only — an upstream on a
        // self-hosted forge must not pass through a bare entry.
        let o = owners(&["cameron"]);
        assert!(!fork_allowed(
            "github.com",
            "cameron/fork",
            "gitea.internal",
            "cameron/orig",
            &o,
            &[],
            &[],
        ));
    }

    #[test]
    fn fork_upstream_host_qualified_allowed() {
        let o = owners(&["cameron", "gitea.internal/cameron"]);
        assert!(fork_allowed(
            "github.com",
            "cameron/fork",
            "gitea.internal",
            "cameron/orig",
            &o,
            &[],
            &[],
        ));
    }

    #[test]
    fn fork_extra_hosts_allowed() {
        let o = owners(&["cameron"]);
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(fork_allowed(
            "github.com",
            "cameron/fork",
            "git.sjo.lol",
            "cameron/orig",
            &o,
            &[],
            &extras,
        ));
    }

    #[test]
    fn fork_empty_remote_blocked() {
        // An unparseable remote URL yields an empty repo string — fail closed.
        let o = owners(&["cameronsjo"]);
        assert!(!fork_allowed(
            "github.com",
            "",
            "github.com",
            "cameronsjo/orig",
            &o,
            &[],
            &[],
        ));
    }

    // --- #44: extras-aware single-target check ---

    #[test]
    fn is_allowed_with_extras_gitea() {
        let o = owners(&["cameron"]);
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(is_allowed_with_extras(
            "git.sjo.lol",
            "cameron/repo",
            &o,
            &[],
            &extras,
        ));
    }

    #[test]
    fn is_allowed_with_extras_unlisted_host_blocked() {
        let o = owners(&["cameron"]);
        let extras = vec!["git.sjo.lol".to_string()];
        assert!(!is_allowed_with_extras(
            "evil.example",
            "cameron/repo",
            &o,
            &[],
            &extras,
        ));
    }

    // API repos pattern
    #[test]
    fn api_repos_pattern_matches() {
        let caps = API_REPOS.captures("gh api repos/cameronsjo/test/pulls");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(1).unwrap().as_str(), "cameronsjo/test");
    }

    // --- Unhappy path: edge cases ---

    #[test]
    fn workflow_run_is_write() {
        assert!(is_write_command("gh workflow run deploy.yml"));
    }

    #[test]
    fn workflow_enable_is_write() {
        assert!(is_write_command("gh workflow enable deploy.yml"));
    }

    #[test]
    fn workflow_disable_is_write() {
        assert!(is_write_command("gh workflow disable deploy.yml"));
    }

    #[test]
    fn label_create_is_write() {
        assert!(is_write_command("gh label create bug"));
    }

    #[test]
    fn gist_create_is_write() {
        assert!(is_write_command("gh gist create file.txt"));
    }

    #[test]
    fn issue_edit_is_write() {
        assert!(is_write_command("gh issue edit 123 --title new"));
    }

    #[test]
    fn pr_review_is_write() {
        assert!(is_write_command("gh pr review 123 --approve"));
    }

    #[test]
    fn pr_ready_is_write() {
        assert!(is_write_command("gh pr ready 123"));
    }

    #[test]
    fn issue_reopen_is_write() {
        assert!(is_write_command("gh issue reopen 123"));
    }

    #[test]
    fn issue_lock_is_write() {
        assert!(is_write_command("gh issue lock 123"));
    }

    #[test]
    fn repo_archive_is_write() {
        assert!(is_write_command("gh repo archive owner/repo"));
    }

    #[test]
    fn repo_rename_is_write() {
        assert!(is_write_command("gh repo rename new-name"));
    }

    #[test]
    fn release_delete_is_write() {
        assert!(is_write_command("gh release delete v1.0.0"));
    }

    #[test]
    fn api_patch_is_write() {
        assert!(is_write_command(
            "gh api repos/foo/bar -X PATCH -f title=new"
        ));
    }

    #[test]
    fn api_method_patch_is_write() {
        assert!(is_write_command("gh api repos/foo/bar --method PATCH"));
    }

    #[test]
    fn repo_view_is_not_write() {
        assert!(!is_write_command("gh repo view owner/repo"));
    }

    #[test]
    fn release_list_is_not_write() {
        assert!(!is_write_command("gh release list"));
    }

    #[test]
    fn is_allowed_empty_lists() {
        assert!(!is_allowed("github.com", "owner/repo", &[], &[]));
    }

    #[test]
    fn is_allowed_exact_repo_match() {
        assert!(is_allowed(
            "github.com",
            "external/specific-repo",
            &[],
            &owners(&["external/specific-repo"]),
        ));
    }

    #[test]
    fn is_allowed_owner_and_repo() {
        // Both match — should still return true
        assert!(is_allowed(
            "github.com",
            "cameronsjo/repo",
            &owners(&["cameronsjo"]),
            &owners(&["cameronsjo/repo"]),
        ));
    }

    #[test]
    fn no_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: None,
            cwd: None,
            ..Default::default()
        };
        let result = GhWriteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    #[test]
    fn no_gh_in_command_allowed() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(cadence_hooks_core::ToolInput {
                file_path: None,
                path: None,
                command: Some("ls -la".into()),
                content: None,
                new_string: None,
                old_string: None,
                ..Default::default()
            }),
            cwd: None,
            ..Default::default()
        };
        let result = GhWriteGuard.run(&input);
        assert_eq!(result.outcome, cadence_hooks_core::Outcome::Allow);
    }

    // --- edge case hardening ---

    #[test]
    fn loop_explicit_unowned_blocks() {
        // Loop with -R pointing to unowned repo should block
        let result =
            analyze_gh_loops("for i in 1 2; do gh label create bug -R stranger/repo; done");
        match result {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                assert_eq!(cmds[0].explicit_repo.as_deref(), Some("stranger/repo"));
            }
            other => panic!("expected AllTargetsExplicit, got {other:?}"),
        }
    }

    #[test]
    fn gist_create_detected_as_write() {
        assert!(is_write_command("gh gist create file.txt"));
    }

    #[test]
    fn repo_fork_detected_as_write() {
        assert!(is_write_command("gh repo fork owner/repo"));
    }

    #[test]
    fn api_repos_with_query_params() {
        let caps = API_REPOS.captures("gh api repos/cameronsjo/test/pulls?state=open");
        assert!(caps.is_some());
        assert_eq!(caps.unwrap().get(1).unwrap().as_str(), "cameronsjo/test");
    }

    #[test]
    fn repo_create_without_owner_uses_default() {
        // resolve_target_repo for "gh repo create my-repo" without owner
        // should prepend the first allowed owner
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo("gh repo create my-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/my-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_create_with_owner() {
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo("gh repo create cameronsjo/new-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/new-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_archive_positional_resolves() {
        let allowed = owners(&["cameronsjo"]);
        let resolved =
            resolve_target_repo("gh repo archive cameronsjo/some-repo --yes", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/some-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_delete_positional_resolves() {
        let allowed = owners(&["cameronsjo"]);
        let resolved =
            resolve_target_repo("gh repo delete cameronsjo/old-repo --yes", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/old-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_rename_bare_name_falls_through() {
        // rename takes a bare name (new name), not owner/repo — should NOT resolve
        // from the positional arg. It falls through to git remote resolution instead.
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo("gh repo rename new-name", "/nonexistent", &allowed);
        // With no git remote available, should be Unresolvable
        match resolved {
            RepoResolution::Unresolvable => {}
            other => panic!("expected Unresolvable, got {other:?}"),
        }
    }

    #[test]
    fn repo_unarchive_positional_resolves() {
        let allowed = owners(&["cameronsjo"]);
        let resolved =
            resolve_target_repo("gh repo unarchive cameronsjo/archived-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/archived-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_clone_positional_resolves() {
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo("gh repo clone cameronsjo/my-repo", ".", &allowed);
        match resolved {
            RepoResolution::Resolved { repo, .. } => {
                assert_eq!(repo, "cameronsjo/my-repo");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    // --- #44: repo flag forms (equals and compact) ---

    #[test]
    fn repo_flag_equals_form_resolves() {
        // `--repo=owner/repo` must resolve like `--repo owner/repo` does.
        // work_dir is /nonexistent so a regex miss can only produce Unresolvable.
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo(
            "gh issue create --repo=cameronsjo/test --title hi",
            "/nonexistent",
            &allowed,
        );
        match resolved {
            RepoResolution::Resolved { repo, .. } => assert_eq!(repo, "cameronsjo/test"),
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn repo_flag_compact_form_resolves() {
        // `-Rowner/repo` (no space) must resolve like `-R owner/repo` does.
        let allowed = owners(&["cameronsjo"]);
        let resolved = resolve_target_repo(
            "gh pr create -Rcameronsjo/test --title hi",
            "/nonexistent",
            &allowed,
        );
        match resolved {
            RepoResolution::Resolved { repo, .. } => assert_eq!(repo, "cameronsjo/test"),
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn api_compact_field_flag_detected() {
        // Bug: -fkey=value (no space after -f) evades write detection
        assert!(
            is_write_command("gh api repos/foo/bar -ftitle=test"),
            "compact -f flag should be detected as write"
        );
    }

    #[test]
    fn uppercase_method_not_matched() {
        // "gh pr VIEW" is not a write — "VIEW" not in write actions list
        assert!(!is_write_command("gh pr view 123"));
    }

    #[test]
    fn api_lowercase_post_is_write() {
        assert!(
            is_write_command("gh api repos/stranger/repo -X post"),
            "lowercase HTTP method should be detected as write"
        );
    }

    #[test]
    fn api_mixed_case_delete_is_write() {
        assert!(
            is_write_command("gh api repos/foo/bar --method Delete"),
            "mixed-case HTTP method should be detected as write"
        );
    }

    // --- #44: loop write policy (relaxed-when-deterministic + strict toggle) ---

    fn resolved(repo: &str) -> RepoResolution {
        RepoResolution::Resolved {
            host: "github.com".to_string(),
            repo: repo.to_string(),
        }
    }

    #[test]
    fn relaxed_deterministic_owned_loop_allows() {
        let o = owners(&["cameronsjo"]);
        let decision = judge_loop_write(
            false,
            Some(false),
            &resolved("cameronsjo/repo"),
            &o,
            &[],
            &[],
        );
        assert_eq!(decision, LoopWriteDecision::Allow);
    }

    #[test]
    fn strict_toggle_blocks_with_suggestion() {
        let o = owners(&["cameronsjo"]);
        let decision = judge_loop_write(
            true,
            Some(false),
            &resolved("cameronsjo/repo"),
            &o,
            &[],
            &[],
        );
        assert_eq!(
            decision,
            LoopWriteDecision::Block {
                suggestion: Some("cameronsjo/repo".to_string())
            }
        );
    }

    #[test]
    fn relaxed_cd_in_body_blocks_with_suggestion() {
        // Loop body changes cwd — non-deterministic, block even though cwd is owned.
        let o = owners(&["cameronsjo"]);
        let decision = judge_loop_write(
            false,
            Some(true),
            &resolved("cameronsjo/repo"),
            &o,
            &[],
            &[],
        );
        assert_eq!(
            decision,
            LoopWriteDecision::Block {
                suggestion: Some("cameronsjo/repo".to_string())
            }
        );
    }

    #[test]
    fn relaxed_parse_failure_blocks() {
        let o = owners(&["cameronsjo"]);
        let decision = judge_loop_write(false, None, &resolved("cameronsjo/repo"), &o, &[], &[]);
        assert!(matches!(decision, LoopWriteDecision::Block { .. }));
    }

    #[test]
    fn relaxed_unowned_cwd_blocks_without_suggestion() {
        let o = owners(&["cameronsjo"]);
        let decision =
            judge_loop_write(false, Some(false), &resolved("stranger/repo"), &o, &[], &[]);
        assert_eq!(decision, LoopWriteDecision::Block { suggestion: None });
    }

    #[test]
    fn relaxed_fork_cwd_blocks() {
        let o = owners(&["cameronsjo"]);
        let fork = RepoResolution::Fork {
            origin_host: "github.com".to_string(),
            origin: "cameronsjo/fork".to_string(),
            upstream_host: "github.com".to_string(),
            upstream: "stranger/orig".to_string(),
        };
        let decision = judge_loop_write(false, Some(false), &fork, &o, &[], &[]);
        assert_eq!(decision, LoopWriteDecision::Block { suggestion: None });
    }

    #[test]
    fn relaxed_unresolvable_cwd_blocks() {
        let o = owners(&["cameronsjo"]);
        let decision = judge_loop_write(
            false,
            Some(false),
            &RepoResolution::Unresolvable,
            &o,
            &[],
            &[],
        );
        assert_eq!(decision, LoopWriteDecision::Block { suggestion: None });
    }

    #[test]
    fn relaxed_unconfigured_owners_blocks() {
        // Fail-safe invariant: unset CADENCE_ALLOWED_OWNERS (empty list) blocks
        // even a deterministic loop in a resolvable repo.
        let decision = judge_loop_write(
            false,
            Some(false),
            &resolved("cameronsjo/repo"),
            &[],
            &[],
            &[],
        );
        assert_eq!(decision, LoopWriteDecision::Block { suggestion: None });
    }

    #[test]
    fn relaxed_extra_hosts_owned_loop_allows() {
        // Self-hosted forge cwd, owner allowed via CADENCE_EXTRA_HOSTS.
        let o = owners(&["cameron"]);
        let extras = vec!["git.sjo.lol".to_string()];
        let resolution = RepoResolution::Resolved {
            host: "git.sjo.lol".to_string(),
            repo: "cameron/tools".to_string(),
        };
        let decision = judge_loop_write(false, Some(false), &resolution, &o, &[], &extras);
        assert_eq!(decision, LoopWriteDecision::Allow);
    }

    // --- #44: loop block message ---

    #[test]
    fn loop_block_message_includes_suggestion() {
        let writes = vec!["`gh issue close $i`".to_string()];
        let msg = loop_block_message(&writes, Some("cameronsjo/cadence-hooks"));
        assert!(msg.contains("-R cameronsjo/cadence-hooks"));
        assert!(msg.contains("`gh issue close $i`"));
    }

    #[test]
    fn loop_block_message_generic_without_suggestion() {
        let writes = vec!["`gh pr create`".to_string()];
        let msg = loop_block_message(&writes, None);
        assert!(msg.contains("-R owner/repo"));
    }

    // --- #44: actionable deny messages ---

    #[test]
    fn unresolvable_message_names_directory() {
        let msg = unresolvable_message("/Users/cameron/scratch", Some("cameronsjo"));
        assert!(msg.contains("Directory: /Users/cameron/scratch"));
        assert!(msg.contains("-R cameronsjo/<repo>"));
    }

    #[test]
    fn unresolvable_message_generic_without_owner() {
        let msg = unresolvable_message("/tmp", None);
        assert!(msg.contains("Directory: /tmp"));
        assert!(msg.contains("-R owner/<repo>"));
    }

    #[test]
    fn disallowed_message_includes_host_hint_for_self_hosted() {
        let o = owners(&["cameron"]);
        let msg = disallowed_message("git.sjo.lol", "stranger/repo", &o, &[], &[]);
        assert!(msg.contains("CADENCE_EXTRA_HOSTS=git.sjo.lol"));
        assert!(msg.contains("git.sjo.lol/stranger/repo"));
    }

    #[test]
    fn disallowed_message_no_hint_for_default_host() {
        let o = owners(&["cameronsjo"]);
        let msg = disallowed_message("github.com", "stranger/repo", &o, &[], &[]);
        assert!(!msg.contains("Host scope"));
        assert!(msg.contains("stranger/repo"));
        assert!(msg.contains("cameronsjo"));
    }

    #[test]
    fn disallowed_message_no_hint_when_host_in_extras() {
        let o = owners(&["cameron"]);
        let extras = vec!["git.sjo.lol".to_string()];
        let msg = disallowed_message("git.sjo.lol", "stranger/repo", &o, &[], &extras);
        assert!(!msg.contains("Host scope"));
    }

    // --- CodeRabbit #6: read-only gh loops should not block ---

    #[test]
    fn loop_read_only_gh_not_blocked() {
        // gh pr list in a loop is read-only — should NOT trigger MissingTargets block
        let result = analyze_gh_loops("for r in repo1 repo2; do gh pr list; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                // MissingTargets returned, but guard_gh_write should allow because
                // none of the looped commands are writes
                let has_write = cmds.iter().any(|c| {
                    let reconstructed = format!("gh {}", c.args.join(" "));
                    is_write_command(&reconstructed)
                });
                assert!(
                    !has_write,
                    "read-only gh loop should not be flagged as write"
                );
            }
            LoopAnalysis::NoLoops => panic!("should detect loop"),
            _ => {} // AllTargetsExplicit or ParseFailed are fine
        }
    }

    #[test]
    fn loop_write_gh_without_repo_blocked() {
        // gh pr create in a loop without -R should still block
        let result = analyze_gh_loops("for i in 1 2; do gh pr create --title test; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                let has_write = cmds.iter().any(|c| {
                    let reconstructed = format!("gh {}", c.args.join(" "));
                    is_write_command(&reconstructed)
                });
                assert!(has_write, "write gh loop without -R should be blocked");
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }
    }

    #[test]
    fn loop_mixed_read_write_without_repo_blocked() {
        // gh pr list (read) + gh issue close (write) in a loop — should block
        let result = analyze_gh_loops("for i in 1 2; do gh pr list && gh issue close $i; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                let has_write = cmds.iter().any(|c| {
                    let reconstructed = format!("gh {}", c.args.join(" "));
                    is_write_command(&reconstructed)
                });
                assert!(has_write, "mixed read/write loop should block on the write");
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }
    }

    #[test]
    fn looped_command_preserves_args() {
        // Verify LoopedCommand.args contains the subcommand info
        let result = analyze_gh_loops("for i in 1 2; do gh pr list --state open; done");
        match result {
            LoopAnalysis::MissingTargets(cmds) => {
                assert_eq!(cmds.len(), 1);
                assert!(cmds[0].args.contains(&"pr".to_string()));
                assert!(cmds[0].args.contains(&"list".to_string()));
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }
    }

    // --- BlockMetadata payloads on hard blocks ---

    use cadence_hooks_core::HookInput;

    // GhWriteGuard.run() reads CADENCE_ALLOWED_OWNERS / CADENCE_ALLOWED_REPOS
    // / CADENCE_EXTRA_HOSTS via process-global env vars. Serialize all
    // metadata-shape tests so they don't race each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn input_with(command: &str, cwd: &str) -> HookInput {
        // Build via JSON to avoid private-field gymnastics; the real hook
        // payload arrives through the same deserialization path.
        let json = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": cwd,
        });
        serde_json::from_value(json).expect("HookInput deserializes")
    }

    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prior: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(*k).ok()))
            .collect();
        for (k, v) in vars {
            // SAFETY: serialized via ENV_LOCK; restored below.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, v) in prior {
            // SAFETY: same lock still held; we're restoring the prior state.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn disallowed_target_emits_structured_payload() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                // -R short-circuits resolution to Resolved (no git config required).
                let input = input_with("gh pr create -R evil-corp/cool-tool --title hi", "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
                // Fix preserves the project name and substitutes the allowed owner.
                assert_eq!(meta.fix, "-R cameronsjo/cool-tool");
                assert!(meta.allowed_owners.contains(&"cameronsjo".to_string()));
                assert_eq!(meta.severity, "error");
            },
        );
    }

    #[test]
    fn unresolvable_target_emits_structured_payload() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                // No -R + cwd is /tmp (no git remote) → Unresolvable.
                let input = input_with("gh pr create --title hi", "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
                // Fix names the first allowed owner with a <repo> placeholder.
                assert_eq!(meta.fix, "-R cameronsjo/<repo>");
                assert!(meta.allowed_owners.contains(&"cameronsjo".to_string()));
                assert_eq!(meta.severity, "error");
            },
        );
    }

    #[test]
    fn loop_missing_repo_emits_structured_payload() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
                ("CADENCE_GH_STRICT_LOOPS", Some("1")),
            ],
            || {
                // Strict-loops mode forces a block regardless of cwd resolution,
                // keeping this test hermetic. The relaxed-when-deterministic
                // policy is covered separately.
                let input = input_with("for i in 1 2; do gh pr comment $i --body x; done", "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-loop-missing-repo");
                // No cwd suggestion in /tmp → placeholder.
                assert_eq!(meta.fix, "-R <owner>/<repo>");
                assert_eq!(meta.severity, "error");
            },
        );
    }

    #[test]
    fn legacy_block_paths_leave_metadata_none() {
        // The unconfigured fail-safe (no CADENCE_ALLOWED_OWNERS) blocks via
        // the legacy CheckResult::block path — no structured metadata yet.
        // A follow-up may upgrade it; this guards the current contract.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", None),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                let input = input_with("gh pr create -R x/y --title hi", "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(result.block_metadata.is_none());
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            },
        );
    }

    // --- #67: per-segment target resolution in chained gh commands ---

    #[test]
    fn plain_chain_returns_no_loops() {
        // The per-segment write-detection path lives in the NoLoops branch, so a
        // plain `&&` chain must resolve to NoLoops for it to engage.
        let result = analyze_gh_loops("gh pr comment -R me/a 1 && gh repo delete evil/b");
        assert!(matches!(result, LoopAnalysis::NoLoops));
    }

    #[test]
    fn chained_benign_first_then_unowned_write_blocks() {
        // The bypass: a benign first -R covered the unowned second write.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                let input = input_with(
                    "gh pr comment -R cameronsjo/owned 1 --body hi && gh repo delete evil/unowned --yes",
                    "/tmp",
                );
                let result = GhWriteGuard.run(&input);
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
            },
        );
    }

    #[test]
    fn chained_two_owned_writes_allows() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                let input = input_with(
                    "gh issue comment -R cameronsjo/a 1 --body x && gh issue comment -R cameronsjo/b 2 --body y",
                    "/tmp",
                );
                let result = GhWriteGuard.run(&input);
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
            },
        );
    }

    #[test]
    fn chained_read_then_owned_write_allows() {
        // False-block guard: a read followed by an owned write must pass.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                let input = input_with(
                    "gh pr list && gh issue comment -R cameronsjo/owned 1 --body hi",
                    "/tmp",
                );
                let result = GhWriteGuard.run(&input);
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
            },
        );
    }

    #[test]
    fn sh_c_wrapped_unowned_write_blocks() {
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                let input = input_with("sh -c 'gh repo delete evil/unowned --yes'", "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            },
        );
    }

    // --- #78: unverifiable gh api writes block; graphql reads exempt ---

    // The crate's own dir is an owned checkout (origin = cameronsjo/cadence-hooks),
    // so it exercises the cwd-remote fallback the bypass relied on.
    const OWNED_DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn owners_env() -> [(&'static str, Option<&'static str>); 3] {
        [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
        ]
    }

    #[test]
    fn graphql_mutation_from_owned_dir_blocks() {
        // #78 repro: from an owned checkout the cwd-remote fallback used to
        // resolve graphql to the owned repo and allow ANY mutation. Now blocked.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api graphql -f query='mutation { createRepository(input: {}) { id } }'",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn graphql_mutation_emits_api_unverifiable_rule() {
        // Hermetic (/tmp): the new machinery engages regardless of cwd.
        with_env(&owners_env(), || {
            let input = input_with("gh api graphql -f query='mutation { foo }'", "/tmp");
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
            assert_eq!(
                meta.fix,
                "use gh api repos/<owner>/<repo>/… so ownership is checkable, or ask the user"
            );
            assert_eq!(meta.severity, "error");
        });
    }

    #[test]
    fn api_post_orgs_from_owned_dir_blocks() {
        with_env(&owners_env(), || {
            let input = input_with("gh api -X POST orgs/evil-org/repos -f name=x", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn api_user_repos_from_owned_dir_blocks() {
        with_env(&owners_env(), || {
            let input = input_with("gh api user/repos -f name=x", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn api_delete_notifications_from_owned_dir_blocks() {
        with_env(&owners_env(), || {
            let input = input_with("gh api -X DELETE notifications/threads/123", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn graphql_file_query_is_undeterminable_and_blocks() {
        // `-F query=@file.graphql` — value is not inline, so the kind can't be
        // verified; treated as a write and the message names that out.
        with_env(&owners_env(), || {
            let input = input_with("gh api graphql -F query=@big.graphql", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
            let msg = result.message.expect("block message");
            assert!(
                msg.contains("@") && msg.to_lowercase().contains("file"),
                "message must name the non-inline (@file) query: {msg}"
            );
        });
    }

    #[test]
    fn chained_read_then_graphql_mutation_blocks() {
        // Per-segment: a benign first read can't shield a graphql mutation later.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh pr list && gh api graphql -f query='mutation { x }'",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn graphql_read_query_inline_allows() {
        // False-block guard: a `query { … }` read must pass even with no -R / cwd.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api graphql -f query='query { viewer { login } }'",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_read_shorthand_allows() {
        // Anonymous-operation shorthand `{ … }` is also a read.
        with_env(&owners_env(), || {
            let input = input_with("gh api graphql -f query='{ viewer { login } }'", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn api_repos_owned_pathed_write_allows() {
        // `gh api repos/<owner>/<repo>` keeps the existing ownership check.
        with_env(&owners_env(), || {
            let input = input_with("gh api repos/cameronsjo/x -X POST -f title=t", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn api_get_no_write_flags_allows() {
        with_env(&owners_env(), || {
            for cmd in ["gh api octocat", "gh api repos/o/r"] {
                let input = input_with(cmd, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "GET should allow: {cmd}"
                );
            }
        });
    }

    #[test]
    fn pr_create_owned_fallback_allows() {
        // Non-api gh writes keep the cwd-remote fallback — routine work stays green.
        with_env(&owners_env(), || {
            let input = input_with("gh pr create --title hi", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }
}
