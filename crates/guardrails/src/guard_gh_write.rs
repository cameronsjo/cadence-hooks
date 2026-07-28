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
    LOOP_PATTERN, command_segments, host_and_repo_from_url, parse_work_dir, strip_quotes, tokenize,
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

/// Write subcommands whose noun is absent from [`WRITE_ACTIONS`]' noun group,
/// or whose verb is absent from its shared verb group. Kept SEPARATE (with `\b`
/// anchors) so the new verbs don't leak across the shared alternation — notably
/// so `clone` here never makes `gh repo clone` (a local read) look like a write
/// (#87). `gh ruleset` is read-only in gh (rulesets are written via `gh api`,
/// already covered); account-level `gh ssh-key`/`gpg-key` and `--owner`-scoped
/// `gh project` are deliberately excluded (no `-R` → would mis-target cwd).
static WRITE_ACTIONS_EXTRA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"gh\s+(secret|variable)\s+(set|delete)\b|gh\s+release\s+upload\b|gh\s+label\s+clone\b",
    )
    .expect("pattern should compile")
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

/// `gh repo` verbs whose FIRST positional argument names the target repo.
/// Matched against parsed argv, never the raw command string, so a verb name
/// appearing inside a quoted argument can't donate a target (#463).
///
/// `edit` is here because without it the guard is UNSATISFIABLE (#457):
/// `gh repo edit [<repository>]` has no `-R`/`--repo` flag at all (verified
/// against gh 2.96.0), so the positional was ignored, the target came from the
/// cwd remote — the issue caught it naming a different owner than its own
/// `Fix:` line did — and the block advised a flag the subcommand cannot accept.
/// No spelling of the command and no cwd could clear it.
///
/// Reading the positional relaxes no ownership rule. The verb stays in
/// [`WRITE_ACTIONS`], and the `owner/repo` it names goes through the same
/// allowlist check every other resolved target does, so `gh repo edit
/// evil/repo` still blocks. What changes is only that a target the command
/// spells out replaces a GUESS inferred from the cwd — strictly more accurate
/// on both verdicts.
///
/// A target placed AFTER a flag counts too — see
/// [`gh_repo_positional_target`], which scans past flags rather than reading
/// `argv[3]`. That distinction was itself a bypass: `gh repo edit
/// --enable-issues evil/x` is a valid cobra invocation, and reading only
/// `argv[3]` let the cwd remote answer for it.
const REPO_TARGET_VERBS: &[&str] = &[
    "archive",
    "delete",
    "edit",
    "rename",
    "unarchive",
    "fork",
    "clone",
    "create",
];

/// `owner/repo` from a `gh api` endpoint PATH. Anchored to the start: an
/// unanchored search matched anywhere in the token, which let a query-string
/// decoy stand in for the real target (see [`api_repos_target`]).
static API_REPOS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/?repos/([^/]+/[^/ ]+)").expect("pattern should compile"));

/// Word-boundary match for the lowercase GraphQL `mutation` operation keyword —
/// the signal that a `gh api graphql` query writes rather than reads. Matched
/// case-SENSITIVELY: the operation keyword is lowercase, whereas the *type* name
/// `Mutation` (e.g. an introspection read `__type(name: "Mutation")`) is
/// capitalized and must not be mistaken for a write (#263).
static MUTATION_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bmutation\b").expect("pattern should compile"));

/// GraphQL mutation root fields safe to auto-allow: pure boolean thread metadata
/// on a PR review that carries no attacker-controllable payload.
/// `resolveReviewThread`/`unresolveReviewThread` only toggle a review thread's
/// resolved flag, so they're allowed like reads (#262, #300, #317).
///
/// Deliberately EXCLUDED: `addPullRequestReviewThreadReply` posts
/// attacker-controllable text as the user (its REST equivalent goes through
/// owner-verified `repos/<owner>/<repo>` paths, so it stays checkable there).
/// It's a future maintainer's-call candidate, not an oversight. `addComment` and
/// `addPullRequestReview` are likewise out — any field that writes content stays
/// blocked.
static SAFE_GRAPHQL_MUTATIONS: [&str; 2] = ["resolveReviewThread", "unresolveReviewThread"];

/// True when `command` names a `gh` sub-command that mutates GitHub state.
///
/// `pub(crate)` so [`inject_gh_write_context`](super::inject_gh_write_context)
/// decides "is this a write?" from the same patterns this guard enforces —
/// a second definition would drift the nudge away from the block.
pub(crate) fn is_write_command(command: &str) -> bool {
    if WRITE_ACTIONS.is_match(command) || WRITE_ACTIONS_EXTRA.is_match(command) {
        return true;
    }
    // A spelled-out write method wins outright, before any narrowing below.
    if API_WRITE_METHOD.is_match(command) {
        return true;
    }
    if API_FIELD_FLAGS.is_match(command) || API_INPUT_FLAG.is_match(command) {
        // These flags read as a write only because gh switches an otherwise-GET
        // `gh api` to POST as soon as a parameter is added. An explicit
        // `--method GET` cancels exactly that switch — gh documents it as the
        // way to send the same parameters as a GET query string — so the
        // command issues the identical request as the query-string spelling
        // this guard already allows. Blocking one and allowing the other
        // punished the more explicit form for being explicit (#454).
        //
        // Sound because the narrowing is bounded on every side, and each bound
        // exists because its absence was an actual escape, not a hypothetical:
        //
        // * `WRITE_ACTIONS` is tested above and independently, so nothing here
        //   touches a non-`gh api` write.
        // * `API_WRITE_METHOD` is tested above, so a spaced `-X POST` blocks
        //   regardless of what else the argv contains.
        // * [`api_explicit_method`] requires EVERY method reading to agree.
        //   That unanimity is load-bearing, not belt-and-braces: gh (pflag)
        //   obeys the LAST occurrence, while `API_WRITE_METHOD` matches only
        //   the space-separated spelling — so a first-reading-wins scan would
        //   clear `gh api … -X GET -XPOST -f a=b` as a read while gh POSTs.
        //   Disagreement returns `None` and the command stays a write.
        // * The scan understands the flag STREAM, not just the flag spellings:
        //   it walks shorthand clusters with gh api's table (a method hidden in
        //   `-iXPOST` is a reading) and steps over the values of value-taking
        //   flags (`--jq "-XGET"` is a jq program, not a method). Reading only
        //   the spellings made both of those silent ALLOWs. Anything the table
        //   cannot attribute is ambiguous, which is a write.
        // * It reads parsed argv, so a `-X GET` inside a quoted `--body` or
        //   `-f` value is one token and can never pose as the flag.
        //
        // The residual error is a false BLOCK (`-X POST -X GET`, which gh runs
        // as a GET) — the direction this guard is allowed to err in. `HEAD` is
        // deliberately not included: it is also a read, but no observed command
        // uses it, and every verb added here is one more that must be argued.
        //
        // `graphql` is exempt from the narrowing entirely, because on that
        // endpoint the METHOD does not decide whether the call writes — the
        // query does, and `gh api graphql -X GET -f query='mutation …'` would
        // otherwise read as a GET and skip the mutation classifier altogether.
        // GitHub happens to ignore a query parameter on `GET /graphql` today,
        // but that is server transport behavior, and a guard must not delegate
        // its verdict to it: `--hostname` points the same command at a GHES
        // instance answering on someone else's terms, and an `--input` body
        // transmits on a GET regardless. Let it fall through to the graphql arm.
        if segment_is_graphql(command) {
            return true;
        }
        return api_explicit_method(command).as_deref() != Some("GET");
    }
    false
}

/// What a segment's `gh` invocation says about its `-R`/`--repo` target.
#[derive(Debug, PartialEq)]
pub(crate) enum RepoFlag {
    /// No repo-flag reading anywhere in the invocation.
    Absent,
    /// Every reading agrees on one target.
    Target(String),
    /// Two or more readings disagree, so which one gh obeys depends on a flag
    /// table this guard does not have. Fails closed — see [`repo_flag`].
    Ambiguous,
}

/// Read the `-R`/`--repo` target out of a segment's `gh` invocation.
///
/// Handles all four gh CLI forms: `-R x`, `-Rx`, `--repo x`, `--repo=x` —
/// mirroring `loop_analysis::extract_repo_flag`, which does the same over
/// parsed AST words. Values keep their quotes trimmed so `--repo "o/r"`
/// resolves to `o/r`.
///
/// Reads [`gh_argv`], not the raw string, on both counts that matter. Quoted
/// text is one token, so a `-R owner/repo` spelled inside another flag's value
/// cannot pose as the flag; and the scan starts at the `gh` token, so an
/// `eval "gh … -R evil/target"` wrapper is peeled like every other arm already
/// peels it. Scanning `tokenize` directly left arm 1 the ONLY resolution path
/// blind to `eval`, and a plain unescaped wrapper walked through it (#463).
///
/// **Disagreement fails closed, because "which `-R` wins" is not answerable
/// here.** gh obeys the last *real* repo flag, but a token that merely looks
/// like one may be another flag's value — `--body -Rcameronsjo/allowed` is a
/// body, not a target. Distinguishing them needs gh's per-subcommand flag
/// table: skipping the token after every flag would swallow the real `-R` after
/// a boolean like `--draft`, and skipping after none lets the decoy win. Both
/// mistakes resolve toward ALLOW — dropping the flag falls through to the
/// cwd-remote arm, which passes from an owned checkout. So when readings
/// disagree this reports [`RepoFlag::Ambiguous`] and the caller blocks. Readings
/// that AGREE are not ambiguous, so a repeated or echoed target still resolves.
pub(crate) fn repo_flag(command: &str) -> RepoFlag {
    let Some(words) = gh_argv(command) else {
        return RepoFlag::Absent;
    };
    // No shorthand table: `repo_flag` runs against EVERY gh subcommand, and the
    // per-subcommand tables disagree (`-t` is `--template` under `gh api` and
    // `--title` under `gh pr create`). Passing `None` selects the conservative
    // cluster rule — see [`scan_unanimous_flag`].
    match scan_unanimous_flag(&words, 'R', "--repo", None) {
        FlagScan::Absent => RepoFlag::Absent,
        FlagScan::Single(repo) => RepoFlag::Target(repo),
        FlagScan::Ambiguous => RepoFlag::Ambiguous,
    }
}

/// What scanning an argv for one repeated flag found.
#[derive(Debug, PartialEq)]
enum FlagScan {
    /// No reading of the flag anywhere in the invocation.
    Absent,
    /// Every reading agrees on one value.
    Single(String),
    /// Readings disagree, or a token could not be attributed. Callers MUST fail
    /// closed on this — it is the "I cannot tell" answer, not a value.
    Ambiguous,
}

/// A subcommand's flag grammar, enough to tell a flag's VALUE from the next
/// flag. Supplied only where the table is actually known — see
/// [`scan_unanimous_flag`] for the conservative rule that applies without one.
struct FlagTable {
    /// Shorthand letters that consume a value.
    value_shorts: &'static str,
    /// Shorthand letters that consume nothing.
    bool_shorts: &'static str,
    /// Whether a long flag consumes the FOLLOWING token as its value.
    long_takes_value: fn(&str) -> bool,
}

/// gh `api`'s flag grammar, from `gh api --help` (gh 2.96.0): `-i/--include`
/// is the ONLY boolean shorthand; every other shorthand takes a value.
const GH_API_FLAGS: FlagTable = FlagTable {
    value_shorts: "FfHqtpX",
    bool_shorts: "i",
    long_takes_value: api_flag_takes_separate_value,
};

/// Scan a `gh` argv for every reading of one flag, in all of gh's spellings,
/// and report whether they agree.
///
/// `short` is the shorthand letter (`R`, `X`); `long` the long name
/// (`--repo`, `--method`). Recognized spellings, all of which pflag accepts:
/// `-R v`, `-Rv`, `-R=v`, `--repo v`, `--repo=v` — plus the same forms reached
/// through a **shorthand cluster** (`-iXPOST`), which is the case a
/// four-spelling scan misses.
///
/// **Clusters are why this exists.** pflag walks a single-dash token letter by
/// letter: a boolean letter consumes nothing and the walk continues, while a
/// value-taking letter consumes the rest of the token (or the next argument)
/// as its value. So `gh api … -X GET -iXPOST -f a=b` sets the method TWICE and
/// gh keeps the last — it POSTs — while a scan that only understood `-X POST`
/// and `-XPOST` saw one lone `-X GET` and called the command a read. Verified
/// live against gh 2.96.0: `-iXGET` returns 200 while `-iXBOGUS`, `-iX BOGUS`,
/// and `-iX=BOGUS` all transmit the bogus method.
///
/// **Another flag's VALUE is not a flag.** With a [`FlagTable`], a value-taking
/// flag's value is stepped over — otherwise `--jq "-XGET"` reads as a method
/// reading, and since `--jq`/`--template` are validated only after the request
/// fires, they carry arbitrary attacker-chosen text. That one turned a real
/// org-endpoint POST into a "read" that skipped every gate, needing no
/// knowledge of the operator's config beyond the literal `GET`.
///
/// `table` supplies the subcommand's flag grammar. With one, clusters are
/// walked precisely and long-flag values are skipped. **Without one the
/// conservative rule applies: a cluster whose FIRST letter is `short` is read
/// normally, a cluster containing `short` anywhere else is
/// [`FlagScan::Ambiguous`], and no value is skipped** — because there is no way
/// to know whether an earlier letter, or a preceding long flag, consumed it.
/// Not skipping values is safe in that mode precisely because a stray reading
/// becomes a disagreement, and disagreement blocks. Fails closed by
/// construction: every path that cannot be attributed returns `Ambiguous`, and
/// an unknown letter inside a table-walked cluster does too.
///
/// Values are quote-trimmed; a caller wanting more (case folding) applies it to
/// the returned value.
///
/// **A reading carrying whitespace is discarded rather than counted**, and that
/// holds for both consumers: gh's parser accepts such a value and forwards it,
/// but neither a repo spec nor an HTTP method survives at the other end —
/// GitHub resolves no repo from a name carrying whitespace and trims nothing
/// (verified live across leading, trailing, and tab variants). So the reading
/// can never become a write that LANDS, while counting it WOULD manufacture a
/// disagreement that false-blocks a legitimate command whose `--body` merely
/// quotes `-R owner/repo` as prose.
fn scan_unanimous_flag(
    words: &[String],
    short: char,
    long: &str,
    table: Option<&FlagTable>,
) -> FlagScan {
    let long_eq = format!("{long}=");
    let short_flag = format!("-{short}");
    let trim = |s: &str| s.trim_matches(|c| c == '"' || c == '\'').to_string();
    let mut seen: Vec<String> = Vec::new();
    let mut ambiguous = false;
    let push = |seen: &mut Vec<String>, v: String| {
        if !v.is_empty() && !v.contains(char::is_whitespace) {
            seen.push(v);
        }
    };
    // Start past argv[0] (`gh` itself).
    let mut i = 1;
    while i < words.len() {
        let word = words[i].as_str();
        // `--` ends flag parsing; nothing after it is a flag.
        if word == "--" {
            break;
        }
        if word == long || word == short_flag {
            if let Some(value) = words.get(i + 1) {
                push(&mut seen, trim(value));
                // Skip the value so it cannot also be read as a flag.
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(rest) = word.strip_prefix(long_eq.as_str()) {
            push(&mut seen, trim(rest));
            i += 1;
            continue;
        }
        // Long flag we are not looking for: its value, when separate, is data
        // and must not be scanned as a flag. Only a table can say whether one
        // follows; without a table nothing is skipped, which is safe because a
        // stray reading becomes a disagreement and disagreement blocks.
        if word.starts_with("--") {
            let takes_value = table.is_some_and(|t| (t.long_takes_value)(word));
            i += if takes_value && !word.contains('=') {
                2
            } else {
                1
            };
            continue;
        }
        // Single-dash token: a shorthand cluster.
        if let Some(cluster) = word.strip_prefix('-')
            && !cluster.is_empty()
        {
            match scan_cluster(cluster, short, table, words.get(i + 1)) {
                ClusterScan::None => i += 1,
                ClusterScan::Value(v, consumed_next) => {
                    push(&mut seen, trim(&v));
                    i += if consumed_next { 2 } else { 1 };
                }
                ClusterScan::ConsumedNext => i += 2,
                ClusterScan::Unattributable => {
                    ambiguous = true;
                    i += 1;
                }
            }
            continue;
        }
        i += 1;
    }
    if ambiguous {
        return FlagScan::Ambiguous;
    }
    seen.sort();
    seen.dedup();
    match seen.len() {
        0 => FlagScan::Absent,
        1 => FlagScan::Single(seen.swap_remove(0)),
        _ => FlagScan::Ambiguous,
    }
}

/// What walking one single-dash shorthand cluster yielded.
enum ClusterScan {
    /// No reading of the target letter; the cluster consumed no following token.
    None,
    /// A reading of the target letter. The flag says whether it also consumed
    /// the FOLLOWING argv token as the value.
    Value(String, bool),
    /// No reading, but some other value-taking letter consumed the next token.
    ConsumedNext,
    /// The cluster could not be attributed — caller must fail closed.
    Unattributable,
}

/// Whether a shorthand cluster consumes the FOLLOWING argv token as a value.
///
/// pflag walks the cluster letter by letter; the first value-taking letter
/// claims the rest of the cluster as its value, and only when it is the LAST
/// letter does it reach for the next token. So `-yd desc` consumes `desc`
/// (`-y` boolean, `-d` last and value-taking) while `-ddesc` does not.
/// Checking only the final letter would get `-yd` wrong in the dangerous
/// direction — treating `desc` as the positional target and letting the real
/// one fall through to the cwd remote.
fn cluster_consumes_next(cluster: &str, value_shorts: &str) -> bool {
    let len = cluster.chars().count();
    for (idx, c) in cluster.chars().enumerate() {
        if value_shorts.contains(c) {
            return idx + 1 == len;
        }
    }
    false
}

/// Walk one shorthand cluster the way pflag does, looking for `short`.
fn scan_cluster(
    cluster: &str,
    short: char,
    table: Option<&FlagTable>,
    next: Option<&String>,
) -> ClusterScan {
    let chars: Vec<char> = cluster.chars().collect();
    let Some(FlagTable {
        value_shorts,
        bool_shorts,
        ..
    }) = table
    else {
        // No table. The target letter is readable only in first position,
        // where no earlier letter can have claimed it as a value. Indexed
        // through `first()` rather than `[0]`: this is a hook binary, and a
        // panic here would take the whole check down instead of failing closed.
        if chars.first() == Some(&short) {
            return read_short_value(&chars[1..], next);
        }
        return if chars.contains(&short) {
            ClusterScan::Unattributable
        } else {
            ClusterScan::None
        };
    };
    let mut idx = 0;
    while idx < chars.len() {
        let c = chars[idx];
        if c == short {
            return read_short_value(&chars[idx + 1..], next);
        }
        if value_shorts.contains(c) {
            // This letter eats the rest of the cluster, or the next token.
            return if idx + 1 < chars.len() {
                ClusterScan::None
            } else {
                ClusterScan::ConsumedNext
            };
        }
        if !bool_shorts.contains(c) {
            // A letter the table does not know: it may or may not have eaten
            // the target letter. Refuse to guess.
            return ClusterScan::Unattributable;
        }
        idx += 1;
    }
    ClusterScan::None
}

/// Read a shorthand's value from the cluster remainder after its letter,
/// falling back to the next argv token. Mirrors pflag: `-Xv` and `-X=v` take
/// the remainder, a bare `-X` takes the following argument.
fn read_short_value(rest: &[char], next: Option<&String>) -> ClusterScan {
    if rest.is_empty() {
        return match next {
            Some(v) => ClusterScan::Value(v.clone(), true),
            None => ClusterScan::None,
        };
    }
    let value: String = if rest[0] == '=' {
        rest[1..].iter().collect()
    } else {
        rest.iter().collect()
    };
    if value.is_empty() {
        ClusterScan::None
    } else {
        ClusterScan::Value(value, false)
    }
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
    /// Repo flags disagree, so the target depends on gh's flag table rather
    /// than on anything readable here ([`RepoFlag::Ambiguous`]). Distinct from
    /// `Unresolvable` only in the message — a target WAS spelled out, so "add
    /// `-R`" would be useless advice — and blocks under the same rule id.
    AmbiguousFlags,
    /// Resolution abandoned at the #271 subprocess deadline. Distinct from
    /// `Unresolvable` (git answered; genuinely ambiguous — fail-closed block
    /// stands): a timeout is the guard's own infrastructure failing, which
    /// degrades to a loud fail-open, never a false block (ADR-0001).
    TimedOut,
}

fn resolve_target_repo(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
) -> RepoResolution {
    let dh = default_host();

    // 1. Explicit -R / --repo flag (gh CLI always targets GH_HOST or github.com)
    match repo_flag(command) {
        RepoFlag::Target(repo) => return RepoResolution::Resolved { host: dh, repo },
        RepoFlag::Ambiguous => return RepoResolution::AmbiguousFlags,
        RepoFlag::Absent => {}
    }

    // 2. gh repo <subcommand> <owner/repo> (positional arg)
    if let Some((subcommand, spec_host, first_arg)) = gh_repo_positional_target(command) {
        if first_arg.contains('/') {
            return RepoResolution::Resolved {
                // A `HOST/OWNER/REPO` positional names its own host, and it is
                // judged rather than assumed: `evil-host/cameronsjo/x` carries
                // an allowed-looking owner to a forge the allowlist never
                // named. Bare allowlist entries match the default host only, so
                // the spec blocks unless that host was explicitly allowed.
                host: spec_host.unwrap_or_else(|| dh.clone()),
                repo: first_arg,
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

    // 3. gh api repos/OWNER/REPO — matched against the parsed ENDPOINT, never
    // the whole command: a `repos/owner/repo` string sitting in a `--body`,
    // `--jq`, or commit-message argument used to donate its owner to an
    // unrelated write, resolving a target the command never named (#463).
    if let Some(endpoint) = gh_api_endpoint(command)
        && let Some(repo) = api_repos_target(&endpoint)
    {
        return RepoResolution::Resolved { host: dh, repo };
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
    use cadence_hooks_core::shell::{GitQuery, git_command_detailed};

    // The ownership-deciding `origin` probe runs FIRST: probes share one
    // subprocess budget (#271), and the optional fork refinement must not
    // starve the resolution the verdict actually hangs on.
    let origin_url = match git_command_detailed(work_dir, &["remote", "get-url", "origin"]) {
        GitQuery::Value(url) => Some(url),
        GitQuery::Failed => None,
        GitQuery::TimedOut => return RepoResolution::TimedOut,
    };

    // A timed-out upstream probe cannot degrade to origin-only judgment: in a
    // fork clone, a bare gh write can land on upstream, so judging the fork's
    // owned origin alone would be a wrong-target allow. Timeout anywhere in
    // resolution → TimedOut (loud fail-open at the verdict layer).
    let upstream_url = match git_command_detailed(work_dir, &["remote", "get-url", "upstream"]) {
        GitQuery::Value(url) => Some(url),
        GitQuery::Failed => None,
        GitQuery::TimedOut => return RepoResolution::TimedOut,
    };

    if let Some(upstream_url) = upstream_url {
        let origin_url = origin_url.unwrap_or_default();
        let (origin_host, origin) = host_and_repo_from_url(&origin_url).unwrap_or_default();
        let (upstream_host, upstream) = host_and_repo_from_url(&upstream_url).unwrap_or_default();
        return RepoResolution::Fork {
            origin_host,
            origin,
            upstream_host,
            upstream,
        };
    }

    if let Some(origin_url) = origin_url {
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
    if !strict && body_mutates_cwd == Some(false) {
        if suggestion.is_some() {
            return LoopWriteDecision::Allow;
        }
        // Resolution hit the #271 subprocess deadline — mirror the
        // single-command TimedOut arm: infrastructure failure fails open
        // (loudly), never a false block. Strict mode still blocks above
        // regardless of resolution, so this converts no strict verdict.
        if matches!(cwd_resolution, RepoResolution::TimedOut) {
            cadence_hooks_core::deadline::note_suppressed_block();
            return LoopWriteDecision::Allow;
        }
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
    // Long names are paired with their real short forms: gh api spells these
    // `-F, --field` and `-f, --raw-field`. All four are listed either way, so
    // the ordering carries no behavior — it just has to stop misinforming the
    // next edit that keys off it (#463 review).
    matches!(
        flag,
        "-X" | "--method"
            | "-F"
            | "--field"
            | "-f"
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

/// The argv of a `gh` invocation in `segment`, with `gh` at index 0 — or `None`
/// when the segment invokes no `gh`.
///
/// The single parse every target-resolution arm reads, replacing the raw
/// substring regexes that judged a command by what its *text* contained rather
/// than by what it would *run* (#463). Two properties matter:
///
/// 1. **Quote-aware** (via [`tokenize`]), so `--body "gh repo archive o/r"` is
///    ONE token and its prose can never be resolved as an invocation.
/// 2. **Positional-agnostic** — it scans for the first token that resolves to
///    `gh`, exactly as [`segment_invokes_gh`]'s gate does, rather than
///    demanding `gh` be the command word. That peels the shell keywords
///    `command_segments` leaves attached to a loop-body segment (`do gh api …`,
///    `then gh …`, `! gh …`) and keeps the env-assignment (`GH_TOKEN=x gh …`),
///    transparent-prefix (`sudo`/`env`/`command`/`exec`/`nice`/`timeout gh …`)
///    and argument-position (`xargs gh …`, `find … -exec gh …`) forms that the
///    regexes covered. Requiring the command word would drop those to the
///    cwd-remote fallback — turning a named off-owner target into a guess.
fn gh_argv(segment: &str) -> Option<Vec<String>> {
    gh_argv_depth(segment, 0)
}

fn gh_argv_depth(segment: &str, depth: usize) -> Option<Vec<String>> {
    let tokens = tokenize(segment);
    if let Some(start) = tokens.iter().position(|tok| token_is_gh(tok)) {
        return Some(tokens[start..].to_vec());
    }
    // `eval "<script>"` is the one wrapper `command_segments` does not unwrap,
    // so its argument arrives as a single opaque token. Peel it exactly as
    // `segment_invokes_gh` does, or an `eval`-wrapped write with a named target
    // would silently fall through to the cwd remote.
    if depth < MAX_EVAL_DEPTH
        && tokens
            .first()
            .is_some_and(|t| t.rsplit('/').next().unwrap_or(t) == "eval")
    {
        return gh_argv_depth(&tokens[1..].join(" "), depth + 1);
    }
    None
}

/// True when a `gh api` endpoint addresses the GraphQL API, in any spelling gh
/// accepts.
///
/// Exact string equality against `"graphql"` was not enough, and the gap was
/// live: `/graphql`, `graphql?x=1`, and `https://api.github.com/graphql` all
/// reach the same endpoint while comparing unequal, so each took the GET
/// narrowing and skipped the mutation classifier that `graphql` alone reached.
///
/// Compares the PATH, cut at `?`/`#` before anything else — so a query-string
/// red herring like `repos/<owner>/<repo>?graphql=1` is NOT graphql and still
/// takes the ordinary owner-checked path.
///
/// A URL is reduced to its path component and matched against BOTH endpoint
/// layouts: `/graphql` as github.com serves it, and `/api/graphql` as a GitHub
/// Enterprise Server instance does. Any host counts, which is the fail-closed
/// direction — a non-github host is exactly where "GitHub ignores the query
/// parameter on `GET /graphql`" stops being a safe assumption to rest a verdict
/// on. The `/api/` spelling is accepted only for URL forms: a RELATIVE endpoint
/// is resolved against the API base by gh itself, so there `graphql` is the
/// only spelling, and matching a trailing `/graphql` would swallow
/// `repos/<owner>/graphql` — a real repo named `graphql`, which must stay
/// owner-checked rather than becoming unverifiable.
fn is_graphql_endpoint(endpoint: &str) -> bool {
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    match path.split_once("://") {
        Some((_scheme, rest)) => {
            let path = rest.find('/').map(|idx| &rest[idx..]).unwrap_or("");
            matches!(path, "/graphql" | "/api/graphql")
        }
        None => path.trim_start_matches('/') == "graphql",
    }
}

/// True when `segment` is a `gh api` call against the GraphQL API.
/// The one place the endpoint parse and [`is_graphql_endpoint`] are combined,
/// so the several arms that branch on "is this graphql?" cannot drift apart.
fn segment_is_graphql(segment: &str) -> bool {
    gh_api_endpoint(segment).is_some_and(|e| is_graphql_endpoint(&e))
}

/// The `owner/repo` a `gh api` endpoint targets, or `None` when the endpoint is
/// not a `repos/<owner>/<repo>` path.
///
/// Reads the PATH only — everything before the first `?` or `#`. A query string
/// is attacker-controllable text that gh forwards to the server verbatim; it
/// never changes which endpoint is addressed, so it must never supply the
/// target. Combined with the unanchored `API_REPOS`, it did:
/// `gh api "orgs/evil-org/repos?ref=repos/cameronsjo/allowed" -X POST` matched
/// the decoy in the query, so the unverifiable-write gate stayed silent and the
/// resolver handed back an allowed repo — while gh POSTed to the org endpoint
/// (#463 review).
fn api_repos_target(endpoint: &str) -> Option<String> {
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    API_REPOS
        .captures(path)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Long flags of the `gh repo` verbs in [`REPO_TARGET_VERBS`] that consume a
/// SEPARATE value token, which the positional scan must step over.
///
/// Union across the verbs (gh 2.96.0). Completeness is not required for
/// soundness, only for avoiding false blocks, because the unknown case errs
/// the safe way: an unrecognized long flag is treated as boolean, so the token
/// after it is read as the positional, resolving a target that then faces the
/// allowlist. Mistaking a boolean for value-taking is the dangerous direction —
/// it would step OVER the real positional and fall through to the cwd remote —
/// so `--template` is deliberately ABSENT: it takes a value under
/// `gh repo create` but is boolean under `gh repo edit`, and only the boolean
/// reading is safe when the two disagree.
const REPO_VERB_VALUE_FLAGS: &[&str] = &[
    "--add-topic",
    "--default-branch",
    "--description",
    "--fork-name",
    "--gitignore",
    "--homepage",
    "--license",
    "--org",
    "--remote",
    "--remote-name",
    "--remove-topic",
    "--source",
    "--squash-merge-commit-message",
    "--team",
    "--upstream-remote-name",
    "--visibility",
];

/// Shorthand letters of those verbs that consume a value (`-d` description,
/// `-h` homepage, `-t` team, `-g` gitignore, `-l` license, `-r` remote,
/// `-s` source, `-u` upstream-remote-name). `-p` (`--template` on create) is
/// omitted for the same reason its long form is.
const REPO_VERB_VALUE_SHORTS: &str = "dhtglrsu";

/// The `(verb, target)` of a `gh repo <verb> … <target>` invocation whose
/// positional names the repo, per [`REPO_TARGET_VERBS`]. `None` when the
/// segment isn't that shape, or no positional follows the verb.
///
/// Shared by [`resolve_target_repo`]'s positional arm and
/// [`segment_lacks_explicit_target`] so a new target-naming verb lands in one
/// place and the resolver and the nudge predicate can't drift apart.
///
/// **Scans past flags rather than reading `argv[3]`.** cobra parses flags and
/// positionals interspersed, so `gh repo edit --enable-issues evil/x` names its
/// target just as surely as `gh repo edit evil/x --enable-issues` does. Reading
/// only `argv[3]` saw a flag, declined, and let the cwd remote answer — which
/// ALLOWS the write from any owned checkout. The same held for
/// `gh repo delete --yes evil/x`, `gh repo archive --yes evil/x`, and the `--`
/// terminator form.
///
/// A leading flag does NOT fail closed here: `gh repo edit --enable-issues`
/// with no positional legitimately targets the cwd repo, and blocking it would
/// re-break the case this arm exists to serve. Returning `None` there is
/// correct — resolution falls through to the git-remote arm, as it should.
fn gh_repo_positional_target(segment: &str) -> Option<(String, Option<String>, String)> {
    let argv = gh_argv(segment)?;
    if argv.get(1).map(String::as_str) != Some("repo") {
        return None;
    }
    let verb = argv.get(2)?;
    if !REPO_TARGET_VERBS.contains(&verb.as_str()) {
        return None;
    }
    let mut i = 3;
    while i < argv.len() {
        let word = argv[i].as_str();
        // `--` ends flag parsing; the next token is the positional.
        if word == "--" {
            let target = argv.get(i + 1)?;
            return non_flag_target(verb, target);
        }
        if let Some(name) = word.strip_prefix("--") {
            // `--flag=value` carries its value inline, so nothing to step over.
            if name.contains('=') {
                i += 1;
                continue;
            }
            i += if REPO_VERB_VALUE_FLAGS.contains(&word) {
                2
            } else {
                1
            };
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-')
            && !cluster.is_empty()
        {
            i += if cluster_consumes_next(cluster, REPO_VERB_VALUE_SHORTS) {
                2
            } else {
                1
            };
            continue;
        }
        return non_flag_target(verb, &argv[i]);
    }
    None
}

/// Accept a scanned positional as a target, normalizing the one extra spelling
/// that would otherwise judge the wrong field.
///
/// gh accepts three positional forms (verified against gh 2.96.0, all three
/// resolving to the same repo): `OWNER/REPO`, `HOST/OWNER/REPO`, and a full
/// URL. Downstream ownership splits on the FIRST `/`, so a three-part spec had
/// its HOST judged as the owner — `cameronsjo/evil-corp/x` passed an allowlist
/// containing `cameronsjo` while gh targeted `evil-corp/x`. Dropping the host
/// segment puts the real owner in front of the check.
///
/// **The host segment travels with the split, and is never assumed.** Dropping
/// it silently would only move the bug: `evil-host/cameronsjo/x` yields an
/// allowed-looking OWNER while gh talks to another forge entirely. Returning it
/// lets the caller judge the target against its real host, where a bare
/// allowlist entry matches the default host only — so the same spec blocks
/// unless that host was explicitly allowed.
///
/// A URL form is returned UNCHANGED on purpose, rather than rejected or split.
/// It cannot be normalized safely — the same trap that made the `gh api`
/// endpoint match anchored — and returning `None` would be worse than useless,
/// because resolution would fall through to the cwd remote and ALLOW it from
/// any owned checkout. Handing the raw string to the allowlist fails closed
/// instead: its "owner" is `https:`, which matches nothing.
fn non_flag_target(verb: &str, target: &str) -> Option<(String, Option<String>, String)> {
    if target.is_empty() {
        return None;
    }
    let parts: Vec<&str> = target.split('/').collect();
    if parts.len() == 3 && !target.contains(':') {
        return Some((
            verb.to_string(),
            Some(parts[0].to_string()),
            format!("{}/{}", parts[1], parts[2]),
        ));
    }
    Some((verb.to_string(), None, target.to_string()))
}

/// True when `segment`'s gh invocation targets the user's own account
/// implicitly: any `gh gist` sub-command (gists are user-scoped) or
/// `gh repo fork` (which creates under your account). Both are writes with no
/// `-R` and no positional target, so they're exempt from ownership resolution.
fn gh_write_is_user_scoped(segment: &str) -> bool {
    let Some(argv) = gh_argv(segment) else {
        return false;
    };
    let at = |i: usize| argv.get(i).map(String::as_str);
    at(1) == Some("gist") || (at(1) == Some("repo") && at(2) == Some("fork"))
}

/// If `segment` invokes `gh api` (a `gh` invocation per [`gh_argv`], first
/// non-flag subcommand `api`), return its endpoint — the first positional token
/// after `api`, skipping flags and their values. `Some("")` for a bare `gh api`
/// with no endpoint; `None` when the segment isn't a `gh api` call.
fn gh_api_endpoint(segment: &str) -> Option<String> {
    let tokens = gh_argv(segment)?;
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

/// The HTTP method a `gh api` invocation names explicitly, uppercased — or
/// `None` when no `-X`/`--method` flag appears, when two readings disagree, or
/// when the segment isn't a `gh api` call at all.
///
/// Callers must treat `None` as "gh's implicit rule applies" (GET, or POST once
/// a parameter is added), which is why disagreement collapses into it rather
/// than into a method: falling back to the implicit rule is the fail-closed
/// answer for a `gh api` carrying parameters. See [`is_write_command`] for why
/// unanimity — rather than gh's own last-occurrence-wins rule — is the safe
/// reading here.
///
/// Shares [`scan_unanimous_flag`] with [`repo_flag`] — the flag grammar is the
/// same on both, and keeping one scanner is what stopped them drifting apart
/// (the compact-form whitespace rule lived in only one of the two). This side
/// passes gh `api`'s shorthand table, so a cluster is walked precisely instead
/// of failing closed; only `gh api` is inspected, since a `-X` belonging to
/// another subcommand is not a method.
fn api_explicit_method(segment: &str) -> Option<String> {
    gh_api_endpoint(segment)?;
    let words = gh_argv(segment)?;
    match scan_unanimous_flag(&words, 'X', "--method", Some(&GH_API_FLAGS)) {
        FlagScan::Single(method) => Some(method.to_ascii_uppercase()),
        FlagScan::Absent | FlagScan::Ambiguous => None,
    }
}

/// True when a command segment invokes `gh` as an actual command token — some
/// whitespace-delimited, unquoted token resolves to `gh` (bare, a `*/gh` path,
/// or a backslash-escaped `\gh`). Gates the write-detection scan so a gh-write
/// phrase that appears only *inside a quoted argument* of another command —
/// e.g. a `git commit -m "…gh repo create…"` message, where the quoted text is
/// a single non-`gh` token — is not read as a gh write (#212).
///
/// Any real gh invocation still surfaces a bare `gh` token, so write coverage
/// is unchanged from the raw-substring scan: a command-word gate on the *first*
/// token alone would silently drop writes the shell reaches through an
/// env-assignment (`GH_TOKEN=x gh …`), a transparent prefix (`sudo`/`env`/
/// `command`/`exec`/`nice`/`timeout gh …`), an argument position (`xargs gh …`,
/// `find … -exec gh …`), or a leading redirect — all of which keep `gh` as its
/// own token. So the gate skips only a match whose phrase lives wholly within
/// quotes — a strict subset of what the substring scan caught — which is
/// exactly the #212 false positive and nothing else.
///
/// `eval "<script>"` is the one execution wrapper `command_segments` does not
/// unwrap (unlike `sh -c`), so a gh write in eval's quoted argument would
/// tokenize as a single non-`gh` token and read as prose. When the command
/// word is `eval`, re-tokenize its argument so the wrapped write is still seen;
/// a plain `git commit -m "…gh…"` message is not `eval`, so the #212 prose case
/// stays allowed.
pub(crate) fn segment_invokes_gh(segment: &str) -> bool {
    segment_invokes_gh_depth(segment, 0)
}

/// True when a segment carries no explicit write target — no `-R`/`--repo`
/// flag, and none of the sub-command shapes that name the repo positionally.
///
/// The complement of the first three arms of [`resolve_target_repo`], expressed
/// as a predicate rather than a resolution: the JIT nudge only needs to know
/// *whether* a target was spelled out, not what it resolves to. Kept beside the
/// patterns it reads so a new positional-target shape lands in one file.
///
/// Each clause reads the same parsed argv its resolver arm does, so the
/// complement stays exact: a `repos/<owner>/<repo>` path or a `gh repo archive`
/// phrase that appears only inside a quoted argument names no target for
/// resolution, and must not silence the nudge either (#463).
pub(crate) fn segment_lacks_explicit_target(segment: &str) -> bool {
    repo_flag(segment) == RepoFlag::Absent
        && gh_api_endpoint(segment).is_none_or(|endpoint| api_repos_target(&endpoint).is_none())
        && gh_repo_positional_target(segment).is_none()
        && !gh_write_is_user_scoped(segment)
}

/// `eval` nesting is peeled at most this deep before the argument is treated as
/// opaque — matches `core::shell`'s `MAX_WRAPPER_DEPTH` and bounds the work on
/// a pathological `eval eval eval …` chain (each level re-tokenizes and joins).
const MAX_EVAL_DEPTH: usize = 3;

fn segment_invokes_gh_depth(segment: &str, depth: usize) -> bool {
    let tokens = tokenize(segment);
    if tokens_contain_gh(&tokens) {
        return true;
    }
    if depth < MAX_EVAL_DEPTH
        && tokens
            .first()
            .is_some_and(|t| t.rsplit('/').next().unwrap_or(t) == "eval")
    {
        // tokenize already unquotes eval's argument; re-splitting it surfaces
        // the inner command tokens. Recurse (bounded) so a nested `eval 'eval …'`
        // peels one level at a time.
        let inner = tokens[1..].join(" ");
        return segment_invokes_gh_depth(&inner, depth + 1);
    }
    false
}

/// True when a single token resolves to `gh` (bare, a `*/gh` path, or a
/// backslash-escaped `\gh`).
fn token_is_gh(tok: &str) -> bool {
    let unescaped = tok.strip_prefix('\\').unwrap_or(tok);
    unescaped.rsplit('/').next().unwrap_or(unescaped) == "gh"
}

/// True when any token resolves to `gh`.
fn tokens_contain_gh(tokens: &[String]) -> bool {
    tokens.iter().any(|tok| token_is_gh(tok))
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
    // Classify on the string-stripped body so a `mutation` keyword smuggled
    // inside a string literal (or a `Mutation` type name in an introspection
    // read) can't flip the verdict (#263).
    let stripped = strip_graphql_literals(&query);
    Some(MUTATION_KEYWORD.is_match(&stripped))
}

/// Replace GraphQL string literals — both `"…"` and block `"""…"""`, honoring
/// `\"` escapes — and `#`-to-end-of-line comments with spaces. Neutralizes
/// braces, identifiers, and keywords hiding inside string arguments so the
/// mutation classifier and the root-field extractor see only real query
/// structure (#263). Length is preserved (each consumed char becomes a space)
/// so byte offsets stay aligned for the extractor.
fn strip_graphql_literals(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let mut out = String::with_capacity(query.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '#' {
            // Comment: blank through end of line (the newline itself is kept).
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if c == '"' {
            let is_block = i + 2 < chars.len() && chars[i + 1] == '"' && chars[i + 2] == '"';
            if is_block {
                out.push_str("   ");
                i += 3;
                // Consume until the closing `"""` (or end — unterminated blanks
                // the remainder, which fails the extractor closed).
                while i < chars.len() {
                    // GraphQL's ONLY block-string escape is `\"""` (a literal
                    // triple-quote). It does NOT close the string — consume all
                    // four chars and stay inside. Missing this let a smuggled
                    // root field ride through: an early close turned the real
                    // `}` chars living inside the string into structural braces,
                    // so the extractor closed the selection set early and never
                    // saw the trailing mutation field (#262).
                    if chars[i] == '\\'
                        && i + 3 < chars.len()
                        && chars[i + 1] == '"'
                        && chars[i + 2] == '"'
                        && chars[i + 3] == '"'
                    {
                        out.push_str("    ");
                        i += 4;
                        continue;
                    }
                    if chars[i] == '"'
                        && i + 2 < chars.len()
                        && chars[i + 1] == '"'
                        && chars[i + 2] == '"'
                    {
                        out.push_str("   ");
                        i += 3;
                        break;
                    }
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
            // Regular string, honoring `\"` (and `\\`) escapes.
            out.push(' ');
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    out.push(' ');
                    i += 1;
                    if i < chars.len() {
                        out.push(' ');
                        i += 1;
                    }
                    continue;
                }
                if chars[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(' ');
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn is_graphql_name_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_graphql_name_cont(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Extract the root (top-level) field names of a GraphQL mutation from an
/// already string-stripped query. Returns `None` on ANY structural ambiguity so
/// the caller fails closed:
/// - not exactly one `mutation` operation keyword (a second op could hide a
///   dangerous field),
/// - no selection set, an unbalanced brace/paren, a truncated body, or
/// - an unexpected token at field-head position (fragment `...`, directive `@`,
///   variable `$`, …).
///
/// Aliases resolve to the underlying field (`x: deleteRepository` → `deleteRepository`).
/// Only identifiers at brace-depth 1 / paren-depth 0 are field heads, so argument
/// values and sub-selections never leak into the result.
fn graphql_root_mutation_fields(stripped_query: &str) -> Option<Vec<String>> {
    let mut kw_matches = MUTATION_KEYWORD.find_iter(stripped_query);
    let kw = kw_matches.next()?;
    if kw_matches.next().is_some() {
        return None; // multiple operations — ambiguous, fail closed
    }
    let bytes = stripped_query.as_bytes();

    // Locate the selection-set `{`: the first `{` at paren-depth 0 after the
    // keyword, skipping an optional operation name and `(varDefs)`.
    let mut i = kw.end();
    let mut paren_depth: i32 = 0;
    let mut brace_start: Option<usize> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren_depth += 1,
            b')' => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return None;
                }
            }
            b'{' if paren_depth == 0 => {
                brace_start = Some(i);
                break;
            }
            b'}' if paren_depth == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    let mut i = brace_start?;

    // Walk the selection set, collecting field heads at brace-depth 1 / paren-depth 0.
    let mut fields: Vec<String> = Vec::new();
    let mut brace_depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'{' => {
                brace_depth += 1;
                i += 1;
            }
            b'}' => {
                brace_depth -= 1;
                if brace_depth == 0 {
                    return Some(fields); // closed the mutation selection set
                }
                if brace_depth < 0 {
                    return None;
                }
                i += 1;
            }
            b'(' => {
                paren_depth += 1;
                i += 1;
            }
            b')' => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return None;
                }
                i += 1;
            }
            _ if brace_depth != 1 || paren_depth != 0 => {
                // Inside an argument list or a sub-selection — not a field head.
                i += 1;
            }
            _ if c.is_ascii_whitespace() || c == b',' => {
                i += 1;
            }
            b':' => {
                // Alias separator; the real field name follows.
                i += 1;
            }
            _ if is_graphql_name_start(c) => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_graphql_name_cont(bytes[i]) {
                    i += 1;
                }
                let ident = &stripped_query[start..i];
                // Look past whitespace/commas: a following `:` makes this an alias,
                // so the true field name is the next identifier — skip it here.
                let mut j = i;
                while j < bytes.len() && (bytes[j].is_ascii_whitespace() || bytes[j] == b',') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    continue;
                }
                fields.push(ident.to_string());
            }
            _ => return None, // fragment/directive/variable/etc. — ambiguous
        }
    }
    None // ran off the end without closing the selection set
}

/// True when `segment` is a `gh api graphql` mutation whose root fields are ALL
/// in [`SAFE_GRAPHQL_MUTATIONS`]. Inlines the query (a non-inline `@file` query
/// is never safe), strips string/comment literals, requires the `mutation`
/// keyword, and demands the extractor return a non-empty, fully-safe field set.
/// The membership test is a subset check (`all`), never `contains`, so a single
/// unsafe field in a composite mutation blocks the whole segment.
fn graphql_is_safe_mutation(segment: &str) -> bool {
    let tokens = tokenize(segment);
    let Some(query) = graphql_query_value(&tokens) else {
        return false;
    };
    if query.starts_with('@') {
        return false;
    }
    let stripped = strip_graphql_literals(&query);
    if !MUTATION_KEYWORD.is_match(&stripped) {
        return false;
    }
    match graphql_root_mutation_fields(&stripped) {
        Some(fields) => {
            !fields.is_empty()
                && fields
                    .iter()
                    .all(|f| SAFE_GRAPHQL_MUTATIONS.contains(&f.as_str()))
        }
        None => false,
    }
}

/// Build the block message for a `gh api` write whose target owner can't be
/// verified (graphql, `orgs/…`, `user/…`, anything that isn't
/// `repos/<owner>/<repo>`). When `undeterminable_query` is set, the GraphQL
/// query was loaded from a file, so its mutation status couldn't be confirmed.
fn api_unverifiable_message(segment: &str, undeterminable_query: bool) -> String {
    let is_graphql = segment_is_graphql(segment);
    let note = if undeterminable_query {
        "\n   Note: the GraphQL query is loaded from a file (`-F query=@…`), so its \
         mutation status can't be verified — treated as a write."
    } else {
        ""
    };
    // graphql has no `-R`/`repos/<owner>/<repo>` form, so the generic
    // "use gh api repos/…" fix is unsatisfiable there — state the reality (#317).
    let fix = if is_graphql {
        "Fix: `gh api graphql` has no `-R` or `repos/<owner>/<repo>` form to make ownership \
         checkable. `resolveReviewThread`/`unresolveReviewThread` mutations are auto-allowed; \
         any other mutation must be run by the user directly (a command they execute \
         themselves), not by the agent."
    } else {
        "Fix: use `gh api repos/<owner>/<repo>/…` so ownership is checkable, or ask the user"
    };
    format!(
        "🚫 git-guardrails: gh api write to an unverifiable target — ownership can't be checked\n   \
         Command: {segment}\n   \
         {fix}{note}"
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
    // graphql has no -R/repos form, so its structured fix states the reality
    // rather than the unsatisfiable "use gh api repos/…" (#317).
    let fix = if segment_is_graphql(segment) {
        "gh api graphql has no -R/repos form; resolveReviewThread/unresolveReviewThread are auto-allowed — any other mutation must be run by the user directly".to_string()
    } else {
        "use gh api repos/<owner>/<repo>/… so ownership is checkable, or ask the user".to_string()
    };
    CheckResult::block_structured(
        api_unverifiable_message(segment, undeterminable_query),
        BlockMetadata {
            rule_id: "gh-write-api-unverifiable".to_string(),
            fix,
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
        // The resolution probes hit the #271 subprocess deadline: the guard's
        // own infrastructure failed, which never blocks (ADR-0001). The
        // suppressed fail-closed block is recorded so telemetry distinguishes
        // "slow git" from "an ownership block was bypassed".
        RepoResolution::TimedOut => {
            cadence_hooks_core::deadline::note_suppressed_block();
            None
        }
        // Repo flags disagree. A target WAS spelled out, so the unresolvable
        // arm's "add -R" advice would be wrong; say which readings conflict and
        // let the operator pick. Same rule id — an ambiguous target IS an
        // unresolvable one, and downstream consumers keyed on the id shouldn't
        // have to learn a new one to keep blocking.
        RepoResolution::AmbiguousFlags => Some(CheckResult::block_structured(
            format!(
                "🚫 git-guardrails: gh write names more than one target repo\n   \
                 Command: {segment}\n   \
                 Which one gh honors depends on whether a later `-R`-shaped token is a real \
                 flag or another flag's value — this guard cannot tell, so it will not guess.\n   \
                 Fix: leave exactly one `-R owner/repo`. Quoting the other argument will NOT \
                 help — quotes are stripped before this check — so reword it, or put a space \
                 after the dash prefix (`-R owner/repo` inside prose is ignored)."
            ),
            BlockMetadata {
                rule_id: "gh-write-target-unresolvable".to_string(),
                fix: "leave exactly one -R owner/repo".to_string(),
                allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
                severity: "error",
            },
        )),
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
                // Only writes are ownership-gated; reads (gh pr view, issue list) are
                // owner-independent and safe against any repo — mirror the MissingTargets
                // branch, which already gates on is_write_command (#158). -R targets are
                // always on the default host (gh CLI convention).
                let dh = default_host();
                // debt: `c.args` is lossy — core's `suffix_words` keeps only Word
                // items, so an assignment-shaped suffix (`-f query=…`, `-f name=x`)
                // is dropped and `gh api graphql -f query=<mutation>` reconstructs
                // as `gh api graphql -f`, which `is_write_command` reads as a read.
                // This loop gate is therefore blind to `gh api` payloads. Fixing
                // core alone would hard-block looped graphql READS (re-creating
                // #353 one layer up), so it must land with a graphql-aware wrapper
                // here — #471. Mitigated today by the per-segment pass below, which
                // judges these correctly now that `gh_argv` peels the `do` keyword.
                let unowned_write_targets: Vec<&str> = cmds
                    .iter()
                    .filter(|c| {
                        let reconstructed = format!("gh {}", c.args.join(" "));
                        is_write_command(&reconstructed)
                    })
                    .filter(|c| {
                        !c.explicit_repo
                            .as_ref()
                            .is_some_and(|r| is_allowed(&dh, r, &allowed_owners, &allowed_repos))
                    })
                    .filter_map(|c| c.explicit_repo.as_deref())
                    .collect();
                if !unowned_write_targets.is_empty() {
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
                        unowned_write_targets.join(", "),
                        all_entries.join(" "),
                    ));
                }
                // All write targets owned (or the loop is read-only) — allow the loop
            }
            LoopAnalysis::MissingTargets(cmds) => {
                // Only block if any looped gh command is a write — read-only
                // commands (gh pr list, gh issue view) are safe without -R.
                //
                // debt: same lossy `c.args` reconstruction as the arm above — a
                // looped `gh api … -f key=value` loses its payload and reads as a
                // non-write here, so `has_write` is false and this gate declines
                // to judge it. Pairs with a core `suffix_words` fix, #471.
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
                        // debt: the same lossy `c.args` reconstruction (#471) —
                        // here it only shapes the message's "Found:" list, so a
                        // dropped `-f key=value` suffix omits a command from the
                        // listing rather than changing the verdict.
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
            if !segment_invokes_gh(&segment) {
                continue;
            }

            if !is_write_command(&segment) {
                continue;
            }

            // Fail-safe: block when unconfigured.
            if allowed_owners.is_empty() {
                return CheckResult::block(crate::messages::NOT_CONFIGURED_MSG);
            }

            // Gists are user-scoped; a fork creates under your account.
            if gh_write_is_user_scoped(&segment) {
                continue;
            }

            // #78: `gh api` writes can't all be resolved from the cwd remote.
            // graphql reads are exempt; any non-`repos/<owner>/<repo>` api write
            // is unverifiable — block it rather than trusting the owned checkout.
            if let Some(endpoint) = gh_api_endpoint(&segment) {
                if is_graphql_endpoint(&endpoint) {
                    match graphql_mutation_status(&segment) {
                        // Inline read query — no ownership to check, allow.
                        Some(false) => continue,
                        // Bounded, content-free thread-metadata mutation
                        // (resolve/unresolveReviewThread) — allow like a read.
                        _ if graphql_is_safe_mutation(&segment) => continue,
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
                //
                // Read the parsed ENDPOINT, not the raw segment, for the same
                // reason `resolve_target_repo`'s arm 3 does — and this gate is
                // the one that actually decides. Matching the raw text let a
                // `repos/<owner>/<repo>` string in any argument value suppress
                // the block: `gh api orgs/evil/repos -X POST -H "ref:
                // repos/owner/allowed for docs"` writes to an org endpoint no
                // owner check can reach, yet the header's path satisfied the
                // pattern, so the segment fell through to the cwd remote and
                // was allowed from any owned checkout (#463 review).
                if api_repos_target(&endpoint).is_none() {
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

    /// The resolved target of an unambiguous repo flag — test sugar so the
    /// single-target cases stay readable. Cases that care about `Absent` vs
    /// `Ambiguous` match on [`RepoFlag`] directly.
    fn repo_flag_value(command: &str) -> Option<String> {
        match repo_flag(command) {
            RepoFlag::Target(repo) => Some(repo),
            _ => None,
        }
    }

    #[test]
    fn repo_flag_extraction() {
        assert_eq!(
            repo_flag_value("gh pr create -R cameronsjo/test --title hi"),
            Some("cameronsjo/test".to_string())
        );
    }

    #[test]
    fn repo_flag_long_form() {
        assert_eq!(
            repo_flag_value("gh issue create --repo cameronsjo/test --title hi"),
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

    // API repos pattern. Reads the parsed ENDPOINT, not the whole command:
    // API_REPOS is anchored now, because matching raw command text anywhere was
    // the #463 bug. The behavior asserted is unchanged — a `repos/<owner>/<repo>`
    // endpoint still resolves to `owner/repo`.
    #[test]
    fn api_repos_pattern_matches() {
        assert_eq!(
            api_repos_target("repos/cameronsjo/test/pulls"),
            Some("cameronsjo/test".to_string())
        );
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

    // --- #87: write-verb/noun coverage gap ---
    #[test]
    fn release_upload_is_write() {
        assert!(is_write_command("gh release upload v1.0.0 dist.zip"));
    }
    #[test]
    fn release_delete_asset_is_write() {
        assert!(is_write_command("gh release delete-asset v1.0.0 dist.zip"));
    }
    #[test]
    fn secret_set_is_write() {
        assert!(is_write_command("gh secret set TOKEN"));
    }
    #[test]
    fn secret_delete_is_write() {
        assert!(is_write_command("gh secret delete TOKEN"));
    }
    #[test]
    fn variable_set_is_write() {
        assert!(is_write_command("gh variable set NAME --body v"));
    }
    #[test]
    fn variable_delete_is_write() {
        assert!(is_write_command("gh variable delete NAME"));
    }
    #[test]
    fn label_clone_is_write() {
        assert!(is_write_command("gh label clone source/repo"));
    }
    #[test]
    fn secret_list_is_not_write() {
        assert!(!is_write_command("gh secret list"));
    }
    #[test]
    fn variable_get_is_not_write() {
        assert!(!is_write_command("gh variable get NAME"));
    }
    #[test]
    fn variable_list_is_not_write() {
        assert!(!is_write_command("gh variable list"));
    }
    #[test]
    fn release_download_is_not_write() {
        assert!(!is_write_command("gh release download v1.0.0"));
    }
    #[test]
    fn repo_clone_is_not_write() {
        // Regression: shared-verb bleed — `clone` must not flag the local read.
        assert!(!is_write_command("gh repo clone cameronsjo/cadence-hooks"));
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
        // Same intent, now stronger: the query is STRIPPED before matching
        // rather than merely tolerated, so a real target still resolves while a
        // `repos/…` decoy planted in the query supplies nothing (#463 review).
        assert_eq!(
            api_repos_target("repos/cameronsjo/test/pulls?state=open"),
            Some("cameronsjo/test".to_string())
        );
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

    use crate::with_env;
    use cadence_hooks_core::HookInput;

    // GhWriteGuard.run() reads CADENCE_ALLOWED_OWNERS / CADENCE_ALLOWED_REPOS
    // / CADENCE_EXTRA_HOSTS via process-global env vars. Serialize all
    // metadata-shape tests via the crate-shared with_env/CADENCE_ENV_TEST_LOCK
    // so they don't race each other or the same globals mutated in
    // guard_push_remote / warn_issue_tracker (#446).

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

    // --- #212: gh-write phrases inside non-gh command segments must not block ---

    #[test]
    fn git_commit_message_describing_gh_write_allowed() {
        with_env(&owners_env_212(), || {
            let input = input_with(
                r#"git commit -m "feat: warn-going-public blocks gh repo create --visibility public""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn git_commit_message_gh_pr_create_allowed() {
        with_env(&owners_env_212(), || {
            let input = input_with(
                r#"git commit -m "docs: explain when gh pr create is blocked""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn sh_c_gh_write_still_blocked() {
        // Regression guard for the unwrap path: `sh -c '…'` surfaces the inner
        // gh script as its own segment, still detected as a gh write.
        with_env(&owners_env_212(), || {
            let input = input_with("sh -c 'gh repo delete evil/unowned --yes'", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn bare_gh_write_still_blocked() {
        with_env(&owners_env_212(), || {
            let input = input_with("gh repo create evil/x --public", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    // A first-token command-word gate skipped every one of these real,
    // executable gh writes to an unowned repo; the invocation gate blocks them.
    #[test]
    fn env_prefixed_gh_write_still_blocked() {
        with_env(&owners_env_212(), || {
            let input = input_with("GH_TOKEN=x gh repo create evil/x --public", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn sudo_prefixed_gh_write_still_blocked() {
        with_env(&owners_env_212(), || {
            let input = input_with("sudo gh repo delete evil/x --yes", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn xargs_gh_write_still_blocked() {
        with_env(&owners_env_212(), || {
            let input = input_with("xargs gh repo delete evil/x --yes", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn backslash_gh_write_still_blocked() {
        with_env(&owners_env_212(), || {
            let input = input_with(r"\gh repo create evil/x --public", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn eval_gh_write_still_blocked() {
        // `command_segments` does not unwrap `eval`, so its quoted gh write
        // would read as prose without the eval-aware branch in the gate.
        with_env(&owners_env_212(), || {
            let input = input_with(r#"eval "gh repo delete evil/x --yes""#, "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    fn owners_env_212() -> [(&'static str, Option<&'static str>); 3] {
        [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
        ]
    }

    #[test]
    fn segment_invokes_gh_bare() {
        assert!(segment_invokes_gh("gh pr create --title test"));
    }

    #[test]
    fn segment_invokes_gh_absolute_path() {
        assert!(segment_invokes_gh("/usr/bin/gh pr create --title test"));
    }

    #[test]
    fn segment_invokes_gh_false_for_commit_message() {
        // The gh phrase lives wholly inside the quoted message, which tokenizes
        // as a single non-`gh` token — the #212 false positive.
        assert!(!segment_invokes_gh(
            r#"git commit -m "gh repo create evil/x""#
        ));
    }

    #[test]
    fn segment_invokes_gh_false_for_quoted_gh_in_echo() {
        assert!(!segment_invokes_gh(r#"echo "gh pr create""#));
    }

    // A first-token gate silently dropped every one of these real gh writes;
    // they all keep `gh` as its own token, so the invocation gate still fires.
    #[test]
    fn segment_invokes_gh_true_behind_env_assignment() {
        assert!(segment_invokes_gh(
            "GH_TOKEN=x gh repo create evil/x --public"
        ));
    }

    #[test]
    fn segment_invokes_gh_true_behind_transparent_prefix() {
        assert!(segment_invokes_gh("sudo gh repo delete evil/x --yes"));
        assert!(segment_invokes_gh("env gh repo create evil/x --public"));
        assert!(segment_invokes_gh("command gh repo delete evil/x --yes"));
    }

    #[test]
    fn segment_invokes_gh_true_as_xargs_argument() {
        assert!(segment_invokes_gh("xargs gh repo delete --yes"));
    }

    #[test]
    fn segment_invokes_gh_true_backslash_escaped() {
        assert!(segment_invokes_gh(r"\gh repo create evil/x --public"));
    }

    #[test]
    fn segment_invokes_gh_true_inside_eval() {
        assert!(segment_invokes_gh(r#"eval "gh repo delete evil/x --yes""#));
    }

    #[test]
    fn segment_invokes_gh_false_for_eval_without_gh() {
        assert!(!segment_invokes_gh(r#"eval "echo done""#));
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
            // graphql fix states the reality (no -R/repos form) rather than the
            // unsatisfiable generic remediation (#317).
            assert_eq!(
                meta.fix,
                "gh api graphql has no -R/repos form; resolveReviewThread/unresolveReviewThread are auto-allowed — any other mutation must be run by the user directly"
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
    fn release_upload_unowned_target_blocks() {
        // #87: a newly-covered write to a non-owned repo is now ownership-checked.
        with_env(&owners_env(), || {
            let input = input_with("gh release upload v1 x.zip -R evil/unowned", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            assert_eq!(
                result.block_metadata.unwrap().rule_id,
                "gh-write-unauthorized-target"
            );
        });
    }

    #[test]
    fn secret_set_owned_target_allows() {
        with_env(&owners_env(), || {
            let input = input_with("gh secret set TOKEN -R cameronsjo/x", "/tmp");
            assert!(matches!(
                GhWriteGuard.run(&input).outcome,
                cadence_hooks_core::Outcome::Allow
            ));
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

    // --- #158: explicit-target reads in loops must not be ownership-gated ---

    #[test]
    fn loop_all_explicit_read_unowned_allows() {
        // #158: a loop of explicit-target READS to an unowned repo must PASS —
        // reads are owner-independent (was false-blocked by the arm's blanket
        // ownership check over every command).
        with_env(&owners_env(), || {
            let input = input_with(
                "for q in a b; do gh issue list --repo anthropics/claude-code --limit 8; done",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn loop_all_explicit_write_unowned_blocks() {
        // Regression: an explicit-target WRITE loop to an unowned repo still BLOCKS.
        with_env(&owners_env(), || {
            let input = input_with(
                "for i in 1 2; do gh issue close $i -R stranger/repo; done",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn loop_all_explicit_write_owned_allows() {
        // An explicit-target WRITE loop to an owned repo passes.
        with_env(&owners_env(), || {
            let input = input_with(
                "for i in 1 2; do gh issue close $i -R cameronsjo/repo; done",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn loop_all_explicit_mixed_read_unowned_write_owned_allows() {
        // Precision: an unowned READ + an owned WRITE in the same loop allows —
        // ownership is judged only on the write.
        with_env(&owners_env(), || {
            let input = input_with(
                "for i in 1 2; do gh pr view $i -R anthropics/claude-code && gh issue close $i -R cameronsjo/repo; done",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // --- #262/#263/#300/#317: graphql safe-mutation allowlist + string-stripped classifier ---

    #[test]
    fn graphql_resolve_review_thread_allows() {
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: "T"}) { thread { id } } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_unresolve_review_thread_allows() {
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { unresolveReviewThread(input: {threadId: "T"}) { thread { id } } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_resolve_review_thread_multiline_allows() {
        // Whitespace/newlines between the keyword, selection set, and fields
        // must not defeat the extractor.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api graphql -f query='mutation {\n  resolveReviewThread(input: {threadId: \"T\"}) {\n    thread { id }\n  }\n}'",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_aliased_safe_field_allows() {
        // `alias: field` resolves to the underlying safe field.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { foo: resolveReviewThread(input: {threadId: "T"}) { thread { id } } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_introspection_mutation_typename_read_allows() {
        // #263 regression: a read whose string arg is the `Mutation` type name
        // must not be misread as a write. Case-sensitive keyword + literal
        // stripping both defend this.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='query { __type(name: "Mutation") { fields { name } } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_dangerous_mutations_block() {
        // Security regression: destructive/content-writing mutations stay blocked.
        with_env(&owners_env(), || {
            for q in [
                "mutation { deleteRepository(input: {repositoryId: \"R\"}) { clientMutationId } }",
                "mutation { createRepository(input: {name: \"x\"}) { repository { id } } }",
                "mutation { mergePullRequest(input: {pullRequestId: \"P\"}) { pullRequest { merged } } }",
                "mutation { createRelease(input: {repositoryId: \"R\", tagName: \"v1\"}) { release { id } } }",
                "mutation { createRef(input: {repositoryId: \"R\", name: \"refs/heads/x\", oid: \"o\"}) { ref { id } } }",
                // Deliberately excluded from the allowlist — posts user text.
                "mutation { addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: \"T\", body: \"hi\"}) { comment { id } } }",
            ] {
                let cmd = format!("gh api graphql -f query='{q}'");
                let input = input_with(&cmd, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "must block: {q}"
                );
                assert_eq!(
                    result.block_metadata.expect("structured block").rule_id,
                    "gh-write-api-unverifiable"
                );
            }
        });
    }

    #[test]
    fn graphql_composite_safe_plus_dangerous_blocks() {
        // Subset check, not `contains`: one unsafe root field blocks the whole
        // segment even alongside a safe one.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: "T"}) { thread { id } } deleteRepository(input: {repositoryId: "R"}) { clientMutationId } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn graphql_alias_disguised_dangerous_blocks() {
        // An alias must not launder a dangerous field past the allowlist.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { x: deleteRepository(input: {repositoryId: "R"}) { clientMutationId } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn graphql_string_injected_dangerous_blocks() {
        // A dangerous field hidden inside a string argument is neutralized by
        // literal stripping; the real root field (`addComment`) is unsafe → block.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { addComment(input: {body: "}} deleteRepository(input:{"}) { clientMutationId } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn graphql_chained_read_then_dangerous_mutation_blocks() {
        // Per-segment: a benign first read can't shield a dangerous mutation.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh pr list && gh api graphql -f query='mutation { deleteRepository(input: {repositoryId: "R"}) { clientMutationId } }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn graphql_block_string_escaped_triple_quote_rider_blocks() {
        // SECURITY REGRESSION (#262): a `\"""` escaped triple-quote keeps the
        // block string open past the `}` chars smuggled inside it. Without
        // honoring the escape the stripper closed early, the real `}`s read as
        // structure, the extractor closed the selection set before the trailing
        // field, and `deleteRepository` rode through as a safe
        // `resolveReviewThread`. Must BLOCK.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { resolveReviewThread(input:{threadId:"""X\"""} } } """}) {clientMutationId} deleteRepository(input:{repositoryId:"NODE_ID"}) {clientMutationId} }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(
                matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                "smuggled deleteRepository must not ride through as a safe mutation"
            );
            assert_eq!(
                result.block_metadata.expect("structured block").rule_id,
                "gh-write-api-unverifiable"
            );
        });
    }

    #[test]
    fn graphql_block_string_escaped_triple_quote_legit_allows() {
        // A genuine `\"""` inside a string value, with no smuggled field, must
        // still ALLOW — the escape is honored in both directions, not blanket-blocked.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { resolveReviewThread(input:{threadId:"""has \""" a literal triple-quote"""}) {clientMutationId} }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_block_string_bare_brace_no_escape_allows() {
        // A normal block string containing a bare `}` (no escape) with a single
        // safe root field must still ALLOW — the escape fix didn't over-tighten.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api graphql -f query='mutation { resolveReviewThread(input:{threadId:"""note } with brace"""}) {clientMutationId} }'"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn graphql_file_query_names_file_reason() {
        // `-F query=@file` is undeterminable → block, and the message names the
        // @file reason (the safe-mutation path can't rescue a non-inline query).
        with_env(&owners_env(), || {
            let input = input_with("gh api graphql -F query=@bulk.graphql", "/tmp");
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
            let msg = result.message.expect("block message");
            assert!(
                msg.contains('@') && msg.to_lowercase().contains("file"),
                "message must name the @file reason: {msg}"
            );
        });
    }

    // --- unit: strip_graphql_literals ---

    #[test]
    fn strip_blanks_string_content_including_braces() {
        let out = strip_graphql_literals(r#"mutation { addComment(input: {body: "}} evil"}) }"#);
        assert!(
            !out.contains("evil"),
            "string content must be blanked: {out}"
        );
        assert!(out.contains("mutation") && out.contains("addComment"));
    }

    #[test]
    fn strip_blanks_block_string_content() {
        let out = strip_graphql_literals(r#"f(note: """danger }} deleteRepository""")"#);
        assert!(!out.contains("deleteRepository"));
        assert!(!out.contains("danger"));
        assert!(out.contains("note"));
    }

    #[test]
    fn strip_blanks_comment_to_eol() {
        let out = strip_graphql_literals("mutation { # deleteRepository\n resolveReviewThread }");
        assert!(!out.contains("deleteRepository"));
        assert!(out.contains("resolveReviewThread"));
    }

    #[test]
    fn strip_honors_escaped_quote() {
        // The escaped `\"` does not close the string, so the `}` stays inside and
        // is blanked — it must not leak to the top level.
        let out = strip_graphql_literals(r#"a "x \" }" b"#);
        assert!(
            !out.contains('}'),
            "escaped quote must not close the string early: {out}"
        );
    }

    // --- unit: graphql_root_mutation_fields ---

    #[test]
    fn root_fields_single_safe() {
        assert_eq!(
            graphql_root_mutation_fields(
                "mutation { resolveReviewThread(input: {}) { thread { id } } }"
            ),
            Some(vec!["resolveReviewThread".to_string()])
        );
    }

    #[test]
    fn root_fields_alias_resolves_to_field() {
        assert_eq!(
            graphql_root_mutation_fields(
                "mutation { x: deleteRepository(input: {}) { clientMutationId } }"
            ),
            Some(vec!["deleteRepository".to_string()])
        );
    }

    #[test]
    fn root_fields_composite_collects_all() {
        assert_eq!(
            graphql_root_mutation_fields(
                "mutation { resolveReviewThread(input: {}) { thread { id } } deleteRepository(input: {}) { clientMutationId } }"
            ),
            Some(vec![
                "resolveReviewThread".to_string(),
                "deleteRepository".to_string()
            ])
        );
    }

    #[test]
    fn root_fields_skips_nested_and_args() {
        // Argument identifiers and sub-selection fields must not appear as roots.
        assert_eq!(
            graphql_root_mutation_fields(
                "mutation { resolveReviewThread(input: {threadId: 1}) { thread { id } } }"
            ),
            Some(vec!["resolveReviewThread".to_string()])
        );
    }

    #[test]
    fn root_fields_none_on_truncated() {
        assert_eq!(
            graphql_root_mutation_fields("mutation { resolveReviewThread(input: {"),
            None
        );
    }

    #[test]
    fn root_fields_none_on_multiple_operations() {
        assert_eq!(
            graphql_root_mutation_fields("mutation A { x } mutation B { y }"),
            None
        );
    }

    #[test]
    fn root_fields_none_on_no_selection_set() {
        assert_eq!(graphql_root_mutation_fields("mutation"), None);
    }

    #[test]
    fn root_fields_none_on_fragment_spread() {
        // A fragment spread at field-head is a structure we don't model — fail closed.
        assert_eq!(graphql_root_mutation_fields("mutation { ...Frag }"), None);
    }

    // --- unit: graphql_is_safe_mutation ---

    #[test]
    fn is_safe_mutation_true_for_resolve() {
        assert!(graphql_is_safe_mutation(
            r#"gh api graphql -f query='mutation { resolveReviewThread(input: {}) { thread { id } } }'"#
        ));
    }

    #[test]
    fn is_safe_mutation_false_for_file_query() {
        assert!(!graphql_is_safe_mutation(
            "gh api graphql -F query=@big.graphql"
        ));
    }

    #[test]
    fn is_safe_mutation_false_for_read() {
        assert!(!graphql_is_safe_mutation(
            r#"gh api graphql -f query='query { viewer { login } }'"#
        ));
    }

    #[test]
    fn is_safe_mutation_false_for_composite() {
        assert!(!graphql_is_safe_mutation(
            r#"gh api graphql -f query='mutation { resolveReviewThread(input: {}) { thread { id } } deleteRepository(input: {}) { clientMutationId } }'"#
        ));
    }

    // --- #463 / #353: targets resolve from parsed argv, never the raw string ---

    // unit: gh_argv

    #[test]
    fn gh_argv_peels_the_loop_body_keyword() {
        // `command_segments` splits `for …; do gh …; done` on the `;`, leaving
        // `do` welded to the body segment. Every arm that demanded `gh` be the
        // command word went blind here (#353).
        assert_eq!(
            gh_argv("do gh api graphql -f query=x"),
            Some(vec![
                "gh".to_string(),
                "api".to_string(),
                "graphql".to_string(),
                "-f".to_string(),
                "query=x".to_string(),
            ])
        );
    }

    #[test]
    fn gh_argv_keeps_quoted_prose_in_one_token() {
        // The `gh repo archive …` phrase lives inside --body's VALUE, so it is a
        // single token: argv[1] stays `issue` and no positional target exists.
        let argv = gh_argv(r#"gh issue comment 42 --body "gh repo archive cameronsjo/allowed""#)
            .expect("gh invocation");
        assert_eq!(argv[1], "issue");
        assert_eq!(argv.len(), 6);
    }

    #[test]
    fn gh_argv_none_when_gh_appears_only_in_prose() {
        assert_eq!(gh_argv(r#"git commit -m "mentions gh repo create""#), None);
    }

    #[test]
    fn gh_argv_peels_eval_wrapper() {
        let argv = gh_argv(r#"eval "gh repo delete evil/repo""#).expect("gh invocation");
        assert_eq!(argv[1], "repo");
        assert_eq!(argv[3], "evil/repo");
    }

    // e2e: prose can no longer donate a target (the false-ALLOW half of #463)

    #[test]
    fn repos_path_in_body_no_longer_donates_a_target() {
        // Arm 3 used to run API_REPOS over the WHOLE segment, so this resolved
        // to cameronsjo/allowed, passed the allowlist, and returned before the
        // git-remote arm ran — gh then wrote to the never-checked cwd remote.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh issue comment 42 --body "moved to repos/cameronsjo/allowed""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    #[test]
    fn repo_flag_in_body_no_longer_donates_a_target() {
        // Arm 1 whitespace-split, so a bare `-R owner/repo` inside a quoted
        // --body read as the flag itself.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh issue comment 42 --body "use -R cameronsjo/allowed""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    #[test]
    fn repo_subcommand_in_body_no_longer_donates_a_target() {
        // Arm 2's REPO_SUBCOMMAND regex matched anywhere in the segment.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh issue comment 42 --body "then gh repo archive cameronsjo/allowed""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    #[test]
    fn gist_phrase_in_body_no_longer_exempts_the_write() {
        // The user-scoped exemption used a `gh\s+gist\s` substring, so the word
        // "gh gist" in a PR body skipped ownership resolution entirely.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh pr create --title t --body "see gh gist for logs""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    // e2e regression: the REAL user-scoped writes stay exempt

    #[test]
    fn real_gist_create_still_allowed_from_unowned_cwd() {
        with_env(&owners_env(), || {
            let input = input_with("gh gist create x.md", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn real_repo_fork_still_allowed_from_unowned_cwd() {
        with_env(&owners_env(), || {
            let input = input_with("gh repo fork otherowner/repo", "/tmp");
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // e2e: #353 — a loop body's `do` keyword no longer hides gh api from the
    // per-segment judgment

    #[test]
    fn looped_graphql_read_is_allowed() {
        // The `do` prefix made gh_api_endpoint return None, so the graphql arm
        // never ran and a READ fell through to cwd resolution — an unowned cwd
        // then blocked it as unresolvable.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"for n in 1 2; do gh api graphql -f query="query { viewer { login } }"; done"#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn looped_graphql_mutation_blocks_from_owned_dir() {
        // The mirror image: from an OWNED cwd the same blindness resolved the
        // mutation to the owned repo and allowed it — #78's bypass, restored by
        // wrapping the call in a loop.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"for n in 1 2; do gh api graphql -f query="mutation { addComment(input: {}) { id } }"; done"#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn looped_api_post_to_orgs_blocks_from_owned_dir() {
        with_env(&owners_env(), || {
            let input = input_with(
                "for n in 1 2; do gh api -X POST orgs/evil/repos; done",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn looped_api_field_write_to_orgs_blocks_from_owned_dir() {
        with_env(&owners_env(), || {
            let input = input_with(
                "for n in 1 2; do gh api orgs/evil/repos -f name=x; done",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn loop_gate_never_sees_the_gh_api_payload() {
        // Pins the #471 debt the three `debt:` markers name, and refutes #353's
        // own diagnosis: its suggested fix — apply the graphql downgrade at the
        // three loop call sites — would be INERT, because `is_write_command`
        // never returns true there to be downgraded. Core's `suffix_words`
        // keeps only Word items, so `-f query=…` is dropped and the command
        // reconstructs as a bare `gh api graphql -f`, which matches no write
        // pattern. The real verdict comes from the per-segment pass instead.
        let cmd = r#"for n in 1 2; do gh api graphql -f query="mutation { addComment(input: {}) { id } }"; done"#;
        match analyze_gh_loops(cmd) {
            LoopAnalysis::MissingTargets(cmds) => {
                let reconstructed = format!("gh {}", cmds[0].args.join(" "));
                assert_eq!(reconstructed, "gh api graphql -f");
                assert!(
                    !is_write_command(&reconstructed),
                    "loop gate sees a mutation as a read — the payload was dropped"
                );
            }
            other => panic!("expected MissingTargets, got {other:?}"),
        }
    }

    // --- #463 review: quote-escape divergence and the raw-segment api gate ---

    #[test]
    fn escaped_quote_decoy_flag_does_not_shield_the_real_target() {
        // A real shell keeps --body as ONE argument and passes `-R evil/target`.
        // `tokenize` used to close on the `\"`, exposing a decoy
        // `-R cameronsjo/allowed` BEFORE the real flag; first-match resolution
        // then cleared the write while gh targeted evil/target.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh issue comment 42 --body "see \"gist for -R cameronsjo/allowed\" notes" -R evil/target"#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn escaped_quote_outside_quoting_does_not_swallow_the_real_target() {
        // `x\"` is the literal word `x"`. Reading the escaped quote as an
        // opener swallowed the rest of the command — including the real
        // `-R evil/target` — into one phantom quoted token, so NO target
        // resolved and an owned cwd allowed the write.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh issue comment 42 --body x\" -R evil/target"#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn repos_path_in_a_header_value_does_not_suppress_the_api_block() {
        // The api-unverifiable gate matched API_REPOS against the RAW segment,
        // so a `repos/<owner>/<repo>` string in ANY argument value satisfied it.
        // The real endpoint is an org write no owner check can reach.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api orgs/evil-org/repos -X POST -f name=pwned -H "ref: repos/cameronsjo/allowed for docs""#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn legitimate_repos_api_write_still_reaches_the_ownership_check() {
        // Positive control for the gate above: a real `repos/<owner>/<repo>`
        // endpoint must still fall through to ownership resolution and pass.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api repos/cameronsjo/cadence-hooks/issues -X POST -f title=x",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // --- #463 review round 2: ANSI-C quoting, last-flag-wins, query decoys ---

    #[test]
    fn ansi_c_escaped_quote_does_not_swallow_the_real_target() {
        // `$'…'` honors `\'`, unlike plain `'…'`. Closing on the escaped quote
        // let the real closing `'` reopen a phantom string that ate the rest of
        // the command — `-R evil/target` included — so nothing resolved and an
        // owned cwd allowed the write. This BLOCKED before the tokenize switch.
        with_env(&owners_env(), || {
            let input = input_with(r"gh issue create --title $'a\'b' -R evil/target", OWNED_DIR);
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn ansi_c_decoy_flag_does_not_shield_the_real_target() {
        // The decoy twin of the above: the phantom re-open exposes an allowed
        // `-R` that the shell never passes as a flag at all.
        with_env(&owners_env(), || {
            let input = input_with(
                r"gh issue comment 42 --title $'a\'b -R cameronsjo/allowed' -R evil/target",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn ansi_c_quoting_in_a_benign_title_still_parses() {
        // Positive control: `$'…'` is ordinary in a commit-style title, and the
        // new quote mode must not turn a legitimate write into a false block.
        with_env(&owners_env(), || {
            let input = input_with(
                r"gh issue create --title $'it\'s ready' -R cameronsjo/cadence-hooks",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn disagreeing_repo_flags_block() {
        // Was `last_repo_flag_wins_over_a_benign_leading_one`. Still BLOCKS —
        // the security outcome is unchanged — but the reason moved: taking the
        // last reading is itself exploitable when the last token is another
        // flag's VALUE, so disagreement now fails closed instead of picking a
        // side. Hence the unresolvable rule id rather than unauthorized-target.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh issue comment 42 -R cameronsjo/allowed -R evil/target --body x",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    #[test]
    fn disagreement_is_detected_across_all_four_spellings() {
        // Was `last_repo_flag_wins_across_all_four_spellings`, asserting
        // `Some("b/second")`. Every form gh accepts must still be READ — the
        // change is only in what happens when two readings disagree.
        for command in [
            "gh pr create -R a/first --repo b/second",
            "gh pr create --repo=a/first -Rb/second",
            "gh pr create -Ra/first --repo=b/second",
        ] {
            assert_eq!(repo_flag(command), RepoFlag::Ambiguous, "{command}");
        }
    }

    #[test]
    fn repeated_agreeing_repo_flags_still_resolve() {
        // Agreement is not ambiguity: naming the same target twice, in any
        // spelling, must still resolve rather than fail closed.
        assert_eq!(
            repo_flag("gh pr create -R cameronsjo/x --repo=cameronsjo/x"),
            RepoFlag::Target("cameronsjo/x".to_string())
        );
    }

    #[test]
    fn single_repo_flag_still_allows() {
        // Positive control: one allowed target still resolves.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh issue comment 42 -R cameronsjo/cadence-hooks --body x",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn query_string_decoy_does_not_supply_the_api_target() {
        // API_REPOS searched the whole endpoint token, so a `repos/owner/repo`
        // in the QUERY satisfied the unverifiable gate and then resolved as the
        // target — while gh POSTs to the org path before the `?`.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"gh api "orgs/evil-org/repos?ref=repos/cameronsjo/allowed" -X POST -f n=1"#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn api_repos_target_reads_the_path_only() {
        assert_eq!(
            api_repos_target("repos/cameronsjo/cadence-hooks/issues"),
            Some("cameronsjo/cadence-hooks".to_string())
        );
        // A real target keeps resolving when a query string follows it.
        assert_eq!(
            api_repos_target("repos/cameronsjo/cadence-hooks/issues?state=open"),
            Some("cameronsjo/cadence-hooks".to_string())
        );
        // Decoys in the query and fragment supply nothing.
        assert_eq!(
            api_repos_target("orgs/evil-org/repos?ref=repos/cameronsjo/allowed"),
            None
        );
        assert_eq!(
            api_repos_target("orgs/evil-org/repos#repos/cameronsjo/allowed"),
            None
        );
        // Anchored: the path must START with the repos/ segment.
        assert_eq!(api_repos_target("user/repos/cameronsjo/allowed"), None);
    }

    #[test]
    fn legitimate_repos_write_with_a_query_string_still_allows() {
        // Positive control for the anchoring: a real repos/ endpoint carrying a
        // query must still reach — and pass — the ownership check.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api repos/cameronsjo/cadence-hooks/issues?state=open -X POST -f title=x",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // --- #463 review round 3: value-shaped decoys and the eval-blind arm 1 ---

    #[test]
    fn a_flag_value_shaped_like_a_repo_flag_cannot_override_the_real_target() {
        // gh consumes each of these later tokens as the PRECEDING flag's value
        // and keeps the first real -R. Taking the last reading handed the write
        // to the decoy's allowed owner while gh targeted evil/target.
        for command in [
            "gh issue create -R evil/target --body -Rcameronsjo/allowed",
            r#"gh issue create -R evil/target --body "-Rcameronsjo/allowed""#,
            r#"gh issue create -R evil/target --body "--repo=cameronsjo/allowed""#,
            r#"gh pr create --repo evil/target --title "-Rcameronsjo/allowed""#,
        ] {
            with_env(&owners_env(), || {
                let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{command}"
                );
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-target-unresolvable", "{command}");
            });
        }
    }

    #[test]
    fn a_boolean_flag_does_not_swallow_the_real_repo_flag() {
        // The mirror hazard: "skip the token after every flag" would consume
        // `-R` as --draft's value, resolve nothing, and fall through to the
        // cwd-remote arm — an ALLOW from an owned checkout. The real target
        // must still be read.
        assert_eq!(
            repo_flag("gh pr create --draft -R evil/target"),
            RepoFlag::Target("evil/target".to_string())
        );
    }

    #[test]
    fn spaced_repo_prose_in_a_body_does_not_manufacture_ambiguity() {
        // A spec carrying whitespace resolves to no repo at GitHub, so it can
        // never become a write that lands and must not conflict with the real
        // flag. The second case is the exact remedy the ambiguity block message
        // advises — "put a space after the dash prefix" — so the advice is
        // pinned here rather than merely asserted in prose.
        for command in [
            r#"gh issue comment 42 --body "-R starts my text" -R cameronsjo/cadence-hooks"#,
            r#"gh issue comment 42 --body "-R cameronsjo/allowed" -R cameronsjo/cadence-hooks"#,
        ] {
            with_env(&owners_env(), || {
                let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            });
        }
    }

    #[test]
    fn eval_wrapped_repo_flag_is_resolved_by_arm_one() {
        // Arm 1 read `tokenize` directly, making it the ONE resolution path
        // blind to eval: a plain unescaped wrapper resolved nothing and an
        // owned cwd allowed the write. Nested eval is peeled too, bounded by
        // MAX_EVAL_DEPTH.
        for command in [
            r#"eval "gh issue create --title x -R evil/target""#,
            r#"eval "eval 'gh issue create --title x -R evil/target'""#,
        ] {
            with_env(&owners_env(), || {
                let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{command}"
                );
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            });
        }
    }

    #[test]
    fn eval_wrapped_positional_and_api_targets_already_blocked() {
        // Controls for the arm-1 fix: arms 2 and 3 route through gh_argv and
        // peeled eval correctly all along. They must keep blocking, so the fix
        // is shown to close a gap rather than shift one.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                r#"eval "gh repo delete evil/target""#,
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                r#"eval "gh api orgs/evil-org/repos -X POST -f name=x""#,
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn eval_wrapped_owned_write_still_allows() {
        // Positive control: peeling eval must not turn a legitimate wrapped
        // write into a block.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                r#"eval "gh issue create --title x -R cameronsjo/cadence-hooks""#,
                OWNED_DIR,
            ));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn looped_safe_graphql_mutation_stays_allowed() {
        // Now that the loop body is judged, the safe-mutation exemption must
        // still apply through it — otherwise the fix converts a working review
        // workflow into a hard block.
        with_env(&owners_env(), || {
            let input = input_with(
                r#"for n in 1 2; do gh api graphql -f query="mutation { resolveReviewThread(input: {}) { thread { id } } }"; done"#,
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // --- #454: an explicit `-X GET` is a read, not a write ---

    /// The command from the issue: an explicit GET carrying `-f` fields, which
    /// gh sends as a query string. Blocked before; a read now.
    const ISSUE_454_CMD: &str =
        "gh api -X GET search/issues -f q=commenter:cameronsjo -f per_page=1 --jq .total_count";

    #[test]
    fn explicit_get_with_fields_is_not_a_write() {
        assert!(!is_write_command(ISSUE_454_CMD));
    }

    #[test]
    fn explicit_get_is_read_across_all_spellings() {
        for cmd in [
            "gh api -X GET search/issues -f q=x",
            "gh api --method GET search/issues -f q=x",
            "gh api -XGET search/issues -f q=x",
            "gh api -X=GET search/issues -f q=x",
            "gh api --method=GET search/issues -f q=x",
        ] {
            assert!(!is_write_command(cmd), "should read as a GET: {cmd}");
        }
    }

    #[test]
    fn explicit_get_is_case_insensitive() {
        // `API_WRITE_METHOD` matches POST/PUT/PATCH/DELETE case-insensitively;
        // the read side is symmetric. A lowercase `get` is forwarded verbatim
        // and rejected by GitHub, so it cannot become a write either way.
        assert!(!is_write_command("gh api -X get search/issues -f q=x"));
    }

    #[test]
    fn explicit_get_also_covers_the_input_flag() {
        // `--input` sits in the same narrowed branch as the field flags; a GET
        // carrying a body is still a GET. Pinned so the behavior is chosen
        // rather than incidental.
        assert!(!is_write_command(
            "gh api -X GET repos/cameronsjo/x --input body.json"
        ));
    }

    // Negative controls: the write side must survive the narrowing.

    #[test]
    fn fields_without_an_explicit_method_stay_a_write() {
        // gh switches to POST as soon as a parameter is added — the whole
        // reason the field flags read as a write.
        assert!(is_write_command("gh api repos/cameronsjo/x -f name=y"));
    }

    #[test]
    fn explicit_post_stays_a_write() {
        assert!(is_write_command("gh api -X POST repos/cameronsjo/x -f a=b"));
    }

    #[test]
    fn disagreeing_methods_stay_a_write() {
        // The hole unanimity closes. gh (pflag) obeys the LAST occurrence and
        // `API_WRITE_METHOD` matches only the spaced spelling, so a
        // first-reading-wins scan would clear each of these as a GET while gh
        // performs the write.
        for cmd in [
            "gh api repos/cameronsjo/x -X GET -XPOST -f a=b",
            "gh api repos/cameronsjo/x -X GET --method=POST -f a=b",
            "gh api repos/cameronsjo/x -X GET -X=DELETE -f a=b",
            // Spelled to DODGE `API_WRITE_METHOD`, which matches only a
            // space-separated `-X PATCH`. The earlier `-XGET -X PATCH` form
            // was a false witness: the regex caught it before the unanimity
            // rule was ever consulted, so it passed without exercising the
            // property it claimed to pin.
            "gh api repos/cameronsjo/x -XGET -X=PATCH -f a=b",
        ] {
            assert!(is_write_command(cmd), "must stay a write: {cmd}");
        }
        // The dodge is the point — prove the regex really is silent here, or
        // the case silently stops testing unanimity again.
        assert!(!API_WRITE_METHOD.is_match("gh api repos/cameronsjo/x -XGET -X=PATCH -f a=b"));
    }

    // --- Shorthand clusters: pflag walks a single-dash token letter by letter ---

    #[test]
    fn a_method_inside_a_shorthand_cluster_is_a_write() {
        // `-i` is gh api's only boolean shorthand, so pflag keeps walking and
        // `X` sets the method — gh honors the LAST one and POSTs. Verified
        // live against gh 2.96.0: `-iXGET` returns 200 while `-iXBOGUS`,
        // `-iX BOGUS` and `-iX=BOGUS` all transmit the bogus method.
        for cmd in [
            "gh api repos/evil-corp/x/issues -X GET -iXPOST -f title=pwned",
            "gh api repos/evil-corp/x/issues -X GET -iX POST -f title=pwned",
            "gh api repos/evil-corp/x/issues -X GET -iX=POST -f title=pwned",
            "gh api repos/evil-corp/x/issues -X GET -iiX POST -f title=pwned",
            "gh api repos/evil-corp/x/issues -X GET -iXPOST --input body.json",
        ] {
            assert!(is_write_command(cmd), "cluster must stay a write: {cmd}");
        }
    }

    #[test]
    fn a_boolean_cluster_without_the_method_letter_still_reads() {
        // Positive control: `-i` alone must not disturb the GET narrowing, or
        // the cluster fix would just re-block legitimate reads.
        assert!(!is_write_command("gh api -i -X GET search/issues -f q=x"));
        assert!(!is_write_command("gh api -i -XGET search/issues -f q=x"));
        assert!(!is_write_command("gh api -iXGET search/issues -f q=x"));
    }

    #[test]
    fn an_unknown_cluster_letter_fails_closed() {
        // The table cannot say whether an unknown letter consumed the `X`, so
        // the scan refuses to call it a read.
        assert!(is_write_command("gh api repos/cameronsjo/x -zXGET -f a=b"));
    }

    #[test]
    fn a_value_flags_value_is_not_read_as_a_method() {
        // `--jq` and `-t` values are validated only AFTER the request fires, so
        // they carry arbitrary text. Reading one as a method turned a real org
        // POST into a "read", which skipped every gate — fail-safe, user-scoped,
        // unverifiable, and allowlist alike — with no ownership check at all.
        // This needs no knowledge of the operator's config, just the literal
        // "GET".
        for cmd in [
            r#"gh api orgs/evil-org/repos -f name=pwned --jq "-XGET""#,
            r#"gh api orgs/evil-org/repos -f name=pwned -q "-XGET""#,
            r#"gh api orgs/evil-org/repos -f name=pwned -t "-XGET""#,
            r#"gh api orgs/evil-org/repos -f name=pwned --template "-XGET""#,
        ] {
            assert!(is_write_command(cmd), "decoy must stay a write: {cmd}");
        }
    }

    #[test]
    fn the_org_post_decoy_still_blocks_end_to_end() {
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                r#"gh api orgs/evil-org/repos -f name=pwned --jq "-XGET""#,
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn a_repo_flag_inside_a_shorthand_cluster_does_not_slip_through() {
        // The same cluster grammar, on the OTHER scanner — and a live bypass
        // predating this branch. `-d` is `gh pr create`'s `--draft` boolean, so
        // `-dR evil/x` sets the repo. With no per-subcommand table available
        // here the scan cannot attribute the letter, so it fails closed rather
        // than dropping the flag and letting the cwd remote answer.
        for cmd in [
            "gh pr create -dR evil-corp/x --title t --body b",
            "gh pr create -dR=evil-corp/x --title t",
            "gh pr create -dR evil-corp/x --title t",
        ] {
            with_env(&owners_env(), || {
                let result = GhWriteGuard.run(&input_with(cmd, OWNED_DIR));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "cluster must not resolve away: {cmd}"
                );
            });
        }
    }

    #[test]
    fn an_ordinary_repo_flag_still_resolves() {
        // Positive control for the cluster rule: the plain spellings, where the
        // target letter leads, must keep working.
        assert_allows("gh pr create -R cameronsjo/cadence-hooks --title t");
        assert_allows("gh pr create -Rcameronsjo/cadence-hooks --title t");
        assert_allows("gh pr create --repo=cameronsjo/cadence-hooks --title t");
    }

    // --- graphql is never decided by the method ---

    #[test]
    fn an_explicit_get_does_not_skip_the_graphql_classifier() {
        // On graphql the QUERY decides, not the method. Narrowing on `-X GET`
        // would hand the verdict to server transport behavior — and
        // `--hostname` repoints the same command at a GHES instance.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh api graphql -X GET -f query='mutation { createRepository(input: {}) { id } }'",
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    #[test]
    fn graphql_is_recognized_in_every_spelling_gh_accepts() {
        for endpoint in [
            "graphql",
            "/graphql",
            "graphql?x=1",
            "https://api.github.com/graphql",
            "https://api.github.com/graphql?x=1",
            // Any host counts — a non-github host is exactly where "GitHub
            // ignores the query param on GET" stops holding. GHES serves the
            // API under /api/.
            "https://ghes.example.com/api/graphql",
            "https://ghes.example.com/graphql",
        ] {
            assert!(
                is_graphql_endpoint(endpoint),
                "should be graphql: {endpoint}"
            );
        }
        for endpoint in [
            // A query-string red herring: cutting at `?` happens before the
            // comparison, so this keeps the ordinary owner-checked path.
            "repos/cameronsjo/x?graphql=1",
            // A real repo NAMED graphql stays owner-checked. This is why the
            // relative form matches only the exact word, never a trailing
            // `/graphql`.
            "repos/cameronsjo/graphql",
            "https://api.github.com/repos/cameronsjo/graphql",
            "orgs/evil/repos#graphql",
            "search/issues",
        ] {
            assert!(
                !is_graphql_endpoint(endpoint),
                "should NOT be graphql: {endpoint}"
            );
        }
    }

    #[test]
    fn every_graphql_spelling_reaches_the_mutation_classifier() {
        // Exact equality against "graphql" let three spellings of the same
        // endpoint take the GET narrowing and skip the classifier entirely.
        const MUT: &str = "mutation { createRepository(input: {}) { id } }";
        for cmd in [
            format!("gh api graphql -X GET -f query='{MUT}'"),
            format!("gh api /graphql -X GET -f query='{MUT}'"),
            format!("gh api 'graphql?x=1' -X GET -f query='{MUT}'"),
            format!("gh api https://api.github.com/graphql -X GET -f query='{MUT}'"),
        ] {
            with_env(&owners_env(), || {
                let result = GhWriteGuard.run(&input_with(&cmd, OWNED_DIR));
                let meta = result
                    .block_metadata
                    .unwrap_or_else(|| panic!("expected a structured block: {cmd}"));
                assert_eq!(meta.rule_id, "gh-write-api-unverifiable", "for: {cmd}");
            });
        }
    }

    #[test]
    fn a_graphql_red_herring_endpoint_is_not_exempted() {
        // `?graphql=1` must not buy the graphql treatment — the segment still
        // resolves `repos/<owner>/<repo>` and faces the allowlist.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh api 'repos/evil-corp/x?graphql=1' -X POST -f name=pwned",
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn a_graphql_read_with_an_explicit_get_still_allows() {
        // Positive control: routing graphql past the narrowing must not start
        // blocking graphql READS, which is #353 all over again.
        assert_allows("gh api graphql -X GET -f query='query { viewer { login } }'");
        assert_allows(
            "gh api graphql -X GET -f query='mutation { resolveReviewThread(input: {}) { thread { id } } }'",
        );
    }

    #[test]
    fn a_quoted_get_method_cannot_pose_as_the_flag() {
        // Reads argv, so a method flag inside another flag's value is one
        // token and never a reading of its own.
        assert!(is_write_command(
            r#"gh api repos/cameronsjo/x -f body="-X GET" -f name=y"#
        ));
        assert!(is_write_command(
            r#"gh api repos/cameronsjo/x --field note="--method GET" -f n=1"#
        ));
    }

    #[test]
    fn explicit_get_does_not_relax_a_non_api_write() {
        // `WRITE_ACTIONS` is tested independently of the narrowing.
        assert!(is_write_command(
            "gh issue create -R cameronsjo/x --title t --body -X GET"
        ));
    }

    #[test]
    fn api_explicit_method_ignores_non_api_subcommands() {
        // A `-X` belonging to some other gh subcommand is not a method.
        assert_eq!(api_explicit_method("gh pr create -X GET --title t"), None);
        assert_eq!(api_explicit_method("gh api -X GET x"), Some("GET".into()));
    }

    #[test]
    fn issue_454_repro_allows_from_an_owned_dir() {
        // End-to-end: the reported command blocked as
        // `gh-write-api-unverifiable` because `search/issues` names no
        // owner/repo. As a read it never reaches that gate.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(ISSUE_454_CMD, OWNED_DIR));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn issue_454_repro_allows_from_an_unowned_dir() {
        // Reads are owner-independent, so the fix must not depend on the cwd
        // resolving to an owned repo.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(ISSUE_454_CMD, "/tmp"));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn the_adjacent_search_write_still_blocks() {
        // Same unverifiable endpoint, one flag different: still a write, still
        // blocked. This is the control proving the fix narrowed the method
        // decision rather than the endpoint gate.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh api -X POST search/issues -f q=x",
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
    }

    // --- #457: `gh repo edit` names its target positionally ---

    #[test]
    fn repo_edit_is_still_a_write() {
        assert!(is_write_command(
            "gh repo edit cameronsjo/x --enable-issues"
        ));
    }

    #[test]
    fn repo_edit_positional_names_the_target() {
        assert_eq!(
            gh_repo_positional_target("gh repo edit cameronsjo/cli-capture --enable-issues"),
            Some((
                "edit".to_string(),
                None,
                "cameronsjo/cli-capture".to_string()
            ))
        );
    }

    #[test]
    fn issue_457_repro_allows_from_an_unowned_dir() {
        // The reported shape: an owned repo named positionally, from a checkout
        // whose origin belongs to someone else. `gh repo edit` has no
        // `-R`/`--repo` flag, so the block's advised fix was unsatisfiable and
        // no cwd could clear it. /tmp stands in for "cwd does not resolve to
        // the target" without depending on a fixture remote.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh repo edit cameronsjo/cli-capture --enable-issues",
                "/tmp",
            ));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn repo_edit_of_an_unowned_target_still_blocks() {
        // The other direction, and a false ALLOW closed on the way: from an
        // owned checkout the cwd remote used to answer for this command, so an
        // off-owner `gh repo edit` resolved to the OWNED repo and passed. The
        // positional now decides, and ownership is judged against the repo the
        // command actually names.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh repo edit evil-corp/cool-tool --enable-issues",
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn repo_edit_without_a_positional_still_falls_back_to_the_cwd() {
        // `gh repo edit --enable-issues` edits the cwd's repo, so resolution
        // must still reach the git-remote arm — the positional arm declines
        // rather than reading a flag as a target.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with("gh repo edit --enable-issues", "/tmp"));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable");
        });
    }

    #[test]
    fn repo_edit_positional_silences_the_bare_write_nudge() {
        // The nudge advises `-R owner/repo`, which `gh repo edit` cannot
        // accept. Now that the positional counts as an explicit target, the
        // complement predicate agrees and the advice is withheld.
        assert!(!segment_lacks_explicit_target(
            "gh repo edit cameronsjo/cli-capture --enable-issues"
        ));
    }

    /// Assert a command blocks as an unowned target from an OWNED checkout —
    /// the direction that matters, since the cwd remote would otherwise answer
    /// and allow it.
    fn assert_blocks_unowned(command: &str) {
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
            let meta = result
                .block_metadata
                .unwrap_or_else(|| panic!("expected a structured block: {command}"));
            assert_eq!(
                meta.rule_id, "gh-write-unauthorized-target",
                "wrong rule for: {command}"
            );
        });
    }

    /// Assert a command is allowed from an OWNED checkout.
    fn assert_allows(command: &str) {
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
            assert!(
                matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                "expected ALLOW: {command}"
            );
        });
    }

    #[test]
    fn repo_verb_target_after_a_flag_still_resolves() {
        // cobra parses flags and positionals interspersed, so each of these
        // names its target as surely as the repo-first spelling does. Reading
        // only argv[3] saw a flag, declined, and let the cwd remote answer —
        // allowing a write to a repo the operator does not own.
        for cmd in [
            "gh repo edit --enable-issues evil-corp/cool-tool",
            "gh repo delete --yes evil-corp/cool-tool",
            "gh repo archive --yes evil-corp/cool-tool",
            "gh repo edit -- evil-corp/cool-tool",
            "gh repo edit -d desc evil-corp/cool-tool",
            "gh repo edit --description desc evil-corp/cool-tool",
        ] {
            assert_blocks_unowned(cmd);
        }
    }

    #[test]
    fn repo_edit_without_a_positional_still_targets_the_cwd() {
        // Positive control for the scan above: a LEADING flag must not fail
        // closed. `gh repo edit --enable-issues` legitimately edits the cwd
        // repo, and blocking it would re-break the case the arm exists for.
        assert_allows("gh repo edit --enable-issues");
        // A value-taking flag's value is stepped over, so a description that
        // merely looks like a repo spec is not read as the target.
        assert_allows("gh repo edit --description some/thing");
        assert_allows("gh repo edit -d some/thing");
    }

    #[test]
    fn repo_edit_of_an_owned_target_after_a_flag_allows() {
        assert_allows("gh repo edit --description x cameronsjo/cli-capture");
    }

    #[test]
    fn a_value_short_that_is_not_first_in_a_cluster_still_eats_its_value() {
        // pflag's first value-taking letter claims the rest of the cluster, and
        // reaches for the next token only when it is LAST. Checking just the
        // final letter is not the same rule, and gets `-cd desc` wrong in the
        // dangerous direction — reading `desc` as the target and letting the
        // real positional fall through to the cwd remote.
        assert!(cluster_consumes_next("d", REPO_VERB_VALUE_SHORTS));
        assert!(cluster_consumes_next("cd", REPO_VERB_VALUE_SHORTS));
        assert!(!cluster_consumes_next("ddesc", REPO_VERB_VALUE_SHORTS));
        assert!(!cluster_consumes_next("d=desc", REPO_VERB_VALUE_SHORTS));
        assert!(!cluster_consumes_next("c", REPO_VERB_VALUE_SHORTS));
        // End to end: the target after such a cluster is still resolved.
        assert_blocks_unowned("gh repo create -cd desc evil-corp/cool-tool");
    }

    #[test]
    fn repo_positional_host_segment_is_not_judged_as_the_owner() {
        // gh accepts HOST/OWNER/REPO, but ownership splits on the FIRST slash,
        // so the host used to be judged as the owner — an allowed-looking host
        // cleared a write to an unowned repo.
        assert_blocks_unowned("gh repo edit cameronsjo/evil-corp/cool-tool");
        assert_allows("gh repo edit github.com/cameronsjo/cli-capture");
    }

    #[test]
    fn repo_positional_host_is_judged_not_assumed() {
        // The other half, and the one a naive "drop the host segment" fix would
        // open: an allowed OWNER behind an unnamed HOST. Bare allowlist entries
        // match the default host only, so this must block even though
        // `cameronsjo` is allowed — gh would be talking to another forge.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                "gh repo edit evil-host.example/cameronsjo/cool-tool",
                OWNED_DIR,
            ));
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
        // Explicitly allowing that host lets the same spec through, which is
        // what proves the host is being CHECKED rather than merely rejected.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", Some("evil-host.example")),
            ],
            || {
                let result = GhWriteGuard.run(&input_with(
                    "gh repo edit evil-host.example/cameronsjo/cool-tool",
                    OWNED_DIR,
                ));
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
            },
        );
    }

    #[test]
    fn repo_positional_url_form_fails_closed() {
        // A URL cannot be normalized safely — a host segment could carry an
        // allowed-looking owner — so it goes to the allowlist unchanged, where
        // its "owner" (`https:`) matches nothing.
        assert_blocks_unowned("gh repo edit https://evil.example/cameronsjo/cool-tool");
    }

    #[test]
    fn gh_repo_edit_rejects_a_bare_name() {
        // Documents a REFUTED concern rather than a fix: `gh repo edit` is not
        // like `gh repo view`. Verified against gh 2.96.0 — a bare name is
        // rejected outright ("expected the \"[HOST/]OWNER/REPO\" format"), so
        // there is no bare-name spelling of `gh repo edit` for the guard to
        // resolve, and no unsatisfiable shape hiding behind one. Only `create`
        // infers an owner from a bare name, which the resolver already
        // special-cases.
        assert_eq!(
            gh_repo_positional_target("gh repo edit somename --enable-issues"),
            Some(("edit".to_string(), None, "somename".to_string()))
        );
        // No slash → the resolver declines to invent an owner for `edit` and
        // falls through to the cwd remote, which is the owned repo here.
        assert_allows("gh repo edit somename --enable-issues");
    }

    #[test]
    fn repo_edit_verb_in_quoted_prose_still_donates_no_target() {
        // #463's invariant must hold for the newly-added verb too.
        assert_eq!(
            gh_repo_positional_target(
                r#"gh issue create -R cameronsjo/x --body "run gh repo edit evil/target""#
            ),
            None
        );
    }
}
