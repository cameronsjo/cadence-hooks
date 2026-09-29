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
    COMMAND_RUNNERS, CommandWordVariables, GhRepoFlag, LOOP_PATTERN, TRANSPARENT,
    brace_expansion_overflows, carries_substitution, command_segments, command_segments_with_dirs,
    command_word, contains_ignoring_ascii_case, gh_canonical_verb, gh_command_path, gh_repo_flags,
    host_and_repo_from_url, may_spell_word, parse_gh_repo_value, parse_work_dir, requote_words,
    strip_quotes, tokenize,
};
use cadence_hooks_core::{BlockMetadata, Check, CheckResult, HookInput};
use regex::Regex;
use std::sync::LazyLock;

// --- Write detection patterns ---

// The leading `gh` is matched case-INSENSITIVELY, and nothing else in these
// patterns is (cadence-hooks#488). On a case-insensitive volume the shell
// resolves `GH` to the `gh` binary and runs the write; write detection is a raw
// TEXT regex, so a literal lowercase `gh` here meant `GH pr create` never
// reached the ownership decision — a silent Allow, measured against the built
// binary. Folding `token_is_gh` alone does not close it: this test runs first.
//
// The nouns and subcommand verbs stay case-sensitive on purpose. gh itself
// rejects `gh PR CREATE`, so folding them would match text the shell could
// never run — the shape of #489's regression, where case-folding past the verb
// broke `-C`/`-P`/`-S` and net-weakened a guard. Fold the verb, only the verb.
static WRITE_ACTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i:gh)\s+(pr|issue|release|label|repo|gist|workflow)\s+(create|merge|close|comment|edit|delete|transfer|archive|rename|review|reopen|ready|lock|unlock|fork|run|enable|disable)"
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
        r"(?i:gh)\s+(secret|variable)\s+(set|delete)\b|(?i:gh)\s+release\s+upload\b|(?i:gh)\s+label\s+clone\b",
    )
    .expect("pattern should compile")
});

static API_WRITE_METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:gh)\s+api.*(-X|--method)\s+(?i)(POST|PUT|PATCH|DELETE)")
        .expect("pattern should compile")
});

static API_FIELD_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i:gh)\s+api.*\s(-f[\s\S]|--field[\s=]|-F[\s\S]|--raw-field[\s=])")
        .expect("pattern should compile")
});

static API_INPUT_FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i:gh)\s+api.*\s--input\s").expect("pattern should compile"));

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
    if argv_names_write(command) {
        return true;
    }
    // A spelled-out write method wins outright, before any narrowing below.
    if API_WRITE_METHOD.is_match(command) {
        return true;
    }
    // The same method read from the flag stream: the attached spellings
    // (`-XDELETE`, `--method=DELETE`) the spaced regex above cannot see, and a
    // method the shell builds at run time (cadence-hooks#1139).
    if api_method_forces_write(command) {
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

/// True when the command group and verb of the segment's gh invocation, found
/// the way cobra finds them ([`gh_command_path`]), name a write.
///
/// The text regexes above demand `gh <group> <verb>` be adjacent, but cobra
/// takes the persistent `-R` anywhere before the verb: `gh -R evil/x issue
/// create` and `gh pr -R evil/x create` both write, and neither matched
/// (cadence-hooks#1077). Reading the parsed argv also sees what the shell
/// actually runs after brace expansion — `gh {pr,} create`, `{gh,} pr create`
/// — which the raw text never spells (cadence-hooks#1115). The group and verb
/// are matched against the SAME patterns, rebuilt as `gh <group> <verb>`, so
/// the two routes cannot disagree about which verbs write. Only ever adds
/// writes: the text regexes still run first.
///
/// Every token that resolves to `gh` is tried as the start of the invocation,
/// not just the first: in `sudo -u gh gh -R evil/x pr create` the first `gh`
/// is sudo's user name.
fn argv_names_write(segment: &str) -> bool {
    let Some((tokens, start)) = gh_command_tokens(segment) else {
        return false;
    };
    (start..tokens.len())
        .filter(|&at| token_is_gh(&tokens[at]))
        .any(|at| {
            let [group, verb] = gh_command_path(&tokens[at..], 2)[..] else {
                return false;
            };
            let canonical = format!("gh {group} {verb}");
            WRITE_ACTIONS.is_match(&canonical) || WRITE_ACTIONS_EXTRA.is_match(&canonical)
        })
}

/// What a segment's `gh` invocation says about its `-R`/`--repo` target.
#[derive(Debug, PartialEq)]
pub(crate) enum RepoFlag {
    /// No repo-flag reading anywhere in the invocation.
    Absent,
    /// Every reading agrees on one target, and at least one is certainly a
    /// real flag.
    Target(String),
    /// Every reading agrees on one target, but each may be another flag's
    /// value (`--body -Ro/r`) or be reset by `-R ''`, so gh may use no
    /// override at all. Both the value and the fallback are judged.
    TargetOrAbsent(String),
    /// Two or more readings disagree, so which one gh obeys depends on a flag
    /// table this guard does not have. Fails closed — see [`repo_flag`].
    Ambiguous,
}

/// Read the `-R`/`--repo` target out of a segment's `gh` invocation.
///
/// The grammar is the shared one ([`gh_repo_flags`], cadence-hooks#937): every
/// spelling pflag accepts (`-R x`, `-Rx`, `-R=x`, `--repo x`, `--repo=x`), in
/// any position before `--` — before the command group as readily as after the
/// verb — so this guard, `loop_analysis`, and `warn-issue-tracker` cannot
/// disagree about which repo a command names.
///
/// Reads [`gh_argv`], not the raw string, on both counts that matter. Quoted
/// text is one token, so a `-R owner/repo` spelled inside another flag's value
/// cannot pose as the flag; and the scan starts at the `gh` token, so an
/// `eval "gh … -R evil/target"` wrapper is peeled like every other arm already
/// peels it (#463).
///
/// **Certain readings resolve last-wins, as pflag does; uncertain ones fail
/// closed.** A token that merely looks like a repo flag may be another flag's
/// value — `--body -Rcameronsjo/allowed` is a body, not a target — and
/// telling them apart needs gh's per-subcommand flag table, with both wrong
/// guesses resolving toward ALLOW. So an uncertain reading after the last
/// certain one that names another repo is [`RepoFlag::Ambiguous`] (the caller
/// blocks), and a lone reading that may be a value is
/// [`RepoFlag::TargetOrAbsent`], which judges the cwd fallback too — without
/// that, `--body -Rcameronsjo/x` from an unowned checkout was judged as the
/// owned decoy while gh wrote to the checkout's own repo (cadence-hooks#1069).
/// A `--` ends the flags only where no earlier flag can take it as its value.
pub(crate) fn repo_flag(command: &str) -> RepoFlag {
    let Some(words) = gh_argv(command) else {
        return RepoFlag::Absent;
    };
    match gh_repo_flags(&words).resolve() {
        GhRepoFlag::Absent => RepoFlag::Absent,
        GhRepoFlag::Target(repo) => RepoFlag::Target(repo),
        GhRepoFlag::TargetOrAbsent(repo) => RepoFlag::TargetOrAbsent(repo),
        GhRepoFlag::Ambiguous => RepoFlag::Ambiguous,
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
        // A substitution's blanks are in the source, not the value gh gets.
        if !v.is_empty() && (!v.contains(char::is_whitespace) || carries_substitution(&v)) {
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
            i += long_flag_stride(word, takes_value);
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

/// How many argv tokens one `--long` flag occupies.
///
/// A long flag reaches for the FOLLOWING token only when the grammar says it
/// takes a value AND that value is not already carried inline after `=`. Every
/// boolean long occupies exactly one token.
///
/// **Every scanner in this file must answer `--long` here, before its shorthand
/// arm — that ordering is load-bearing, not tidiness.** A long flag that falls
/// through to a shorthand arm has only its leading `-` stripped, so `--silent`
/// is walked as the cluster `-silent`; its trailing `t` is a value shorthand in
/// [`GH_API_FLAGS`], so a boolean swallows the next token. When that token is a
/// real `--hostname`, the guard never sees the host the write is sent to and
/// falls back to the assumed-owned default — the #476 fail-open, respelled.
fn long_flag_stride(word: &str, takes_value: bool) -> usize {
    if takes_value && !word.contains('=') {
        2
    } else {
        1
    }
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
    /// A `-R`/`--repo`/`GH_REPO` value gh would not read as a URL or
    /// `[HOST/]OWNER/REPO` — or that this guard cannot promise to split the
    /// way gh does ([`parse_gh_repo_value`]). Blocks: a target that cannot be
    /// read cannot be judged owned (cadence-hooks#937).
    UnreadableFlag(String),
    /// Resolution abandoned at the #271 subprocess deadline. Distinct from
    /// `Unresolvable` (git answered; genuinely ambiguous — fail-closed block
    /// stands): a timeout is the guard's own infrastructure failing, which
    /// degrades to a loud fail-open, never a false block (ADR-0001).
    TimedOut,
}

/// The flag grammar to apply while hunting for `--hostname` in one gh argv.
///
/// `--hostname` is a **global** gh flag, so host resolution runs over every
/// subcommand — but [`GH_API_FLAGS`] describes `gh api` and nothing else.
/// Applying it wholesale misreads booleans that merely share a letter:
/// `gh pr create -f` is `--fill` and `gh release create -p` is `--prerelease`,
/// neither of which consumes the following token (verified against gh 2.96.0's
/// own `--help`). Skipping one anyway swallows a literal `--hostname` that
/// follows it, so the guard never sees the host the write is actually sent to,
/// falls back to the assumed-owned default, and ALLOWS the write — the exact
/// #476 failure the host resolution exists to close.
///
/// **The two error directions are not symmetric, and that decides the default.**
/// Skipping a token gh does NOT skip loses the real `--hostname` and fails
/// OPEN. Not skipping a token gh DOES skip can read some flag's value as the
/// host — which resolves a wrong, near-certainly non-default host that no bare
/// allowlist entry matches, and fails CLOSED. So an unknown subcommand skips
/// LESS, not more: no table at all.
///
/// A per-subcommand table written from memory would be wrong somewhere and
/// reintroduce the fail-open direction under a new name, so the only grammar
/// used is the one this file verified against `gh api --help`, applied only to
/// `api`. The shared repo-flag parser ([`gh_repo_flags`]) likewise uses no
/// per-subcommand table, for the same reason.
fn host_scan_flags(argv: &[String]) -> Option<&'static FlagTable> {
    gh_api_subcommand_index(argv).map(|_| &GH_API_FLAGS)
}

/// The index of the `api` subcommand in a gh argv (with `gh` itself at index
/// 0), or `None` when the invocation names some other subcommand.
///
/// Leading single-dash tokens are stepped over without consulting any table —
/// which is what makes this usable *before* a table has been chosen. A global
/// flag's value therefore reads as the subcommand position (`gh --hostname h
/// api …` sees `h`), so the answer is "not api": the fail-closed direction for
/// both callers.
fn gh_api_subcommand_index(argv: &[String]) -> Option<usize> {
    let mut index = 1;
    while index < argv.len() && argv[index].starts_with('-') {
        index += 1;
    }
    (argv.get(index).map(String::as_str) == Some("api")).then_some(index)
}

/// Stand-in host for a `GH_HOST` this guard could not resolve (#548). It matches
/// no allowlist entry — bare entries match only the default host and
/// `CADENCE_EXTRA_HOSTS`, and no hostname contains a space — so a write judged
/// against it always blocks.
const UNRESOLVED_GH_HOST: &str = "<unresolved $GH_HOST>";

/// Shell keywords [`command_segments`] can leave in front of a segment's
/// command word (`then export GH_HOST=…`).
const SEGMENT_KEYWORDS: &[&str] = &[
    "then", "do", "else", "elif", "if", "while", "until", "!", "{", "time",
];

/// Commands that can set or export a shell variable in the CURRENT shell other
/// than through a plain `export NAME=value`. A `GH_HOST` mention under any of
/// them is not modeled, so it resolves to [`UNRESOLVED_GH_HOST`].
const VAR_SETTING_BUILTINS: &[&str] = &[
    "read",
    "printf",
    "source",
    ".",
    "set",
    "mapfile",
    "readarray",
    "let",
    "getopts",
    ":",
    "exec",
];

/// Builtins that write a variable named by an operand rather than by a
/// `NAME=value` word — see [`indirect_name_operands`].
const NAME_OPERAND_BUILTINS: &[&str] = &["read", "printf", "mapfile", "readarray", "getopts"];

/// The operands of a [`NAME_OPERAND_BUILTINS`] invocation that name the
/// variable it writes. Values of value-taking options are stepped over so a
/// `read -p "Host: "` prompt is not mistaken for a name.
fn indirect_name_operands(builtin: &str, args: &[String]) -> Vec<String> {
    // Redirections are not operands: drop `<<<word`, `2>/dev/null`, and a bare
    // operator together with its target.
    let mut kept = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let body = arg.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
        if body.starts_with(['<', '>']) {
            let operator_only = body.chars().all(|c| matches!(c, '<' | '>' | '&' | '|'));
            i += if operator_only { 2 } else { 1 };
            continue;
        }
        kept.push(arg.clone());
        i += 1;
    }
    let args = &kept[..];
    let mut names = Vec::new();
    match builtin {
        "printf" => {
            let mut i = 0;
            while i < args.len() {
                if args[i] == "-v" {
                    if let Some(name) = args.get(i + 1) {
                        names.push(name.clone());
                    }
                    i += 2;
                } else if let Some(name) = args[i].strip_prefix("-v") {
                    names.push(name.to_string());
                    i += 1;
                } else {
                    break;
                }
            }
        }
        "getopts" => {
            if let Some(name) = args.iter().filter(|a| !a.starts_with('-')).nth(1) {
                names.push(name.clone());
            }
        }
        _ => {
            // read / mapfile / readarray: options, then name operands.
            let (value_opts, name_opts) = if builtin == "read" {
                ("dinNptu", "a")
            } else {
                ("dnOsuCc", "")
            };
            let mut i = 0;
            while i < args.len() {
                let arg = &args[i];
                if arg == "--" {
                    names.extend(args[i + 1..].iter().cloned());
                    break;
                }
                if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
                    let last = cluster.chars().last().unwrap_or(' ');
                    if value_opts.contains(last) || name_opts.contains(last) {
                        if name_opts.contains(last)
                            && let Some(name) = args.get(i + 1)
                        {
                            names.push(name.clone());
                        }
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                names.push(arg.clone());
                i += 1;
            }
        }
    }
    names
}

/// Builtins that declare a variable from `NAME[=value]` arguments. Each argument
/// is judged by its NAME, not by whether the text mentions `GH_HOST`: the shell
/// expands the word before the builtin reads it, so `export GH_HOS${X}T=evil`
/// sets `GH_HOST` while never spelling it (#548 review).
const DECLARING_BUILTINS: &[&str] = &["export", "declare", "typeset", "readonly", "local"];

/// An assignment to `GH_HOST` inside a parameter or arithmetic expansion —
/// `${GH_HOST=…}`, `${GH_HOST:=…}`, `$(( GH_HOST = … ))`, `(( GH_HOST += … ))`.
/// The only way a command that is not a declaring builtin can leave `GH_HOST`
/// changed behind it; a mere mention (`rg GH_HOST`, a commit message) cannot.
static GH_HOST_EXPANSION_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| expansion_assignment_pattern("GH_HOST"));

/// [`GH_HOST_EXPANSION_ASSIGNMENT`] for `GH_REPO` (cadence-hooks#1129).
static GH_REPO_EXPANSION_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| expansion_assignment_pattern("GH_REPO"));

fn expansion_assignment_pattern(name: &str) -> Regex {
    Regex::new(&format!(
        r"\$\{{{name}:?=|\(\([^)]*\b{name}\s*(?:<<|>>|[-+*/%&|^])?=(?:[^=]|$)"
    ))
    .expect("pattern should compile")
}

/// Stand-in `GH_REPO` for one this guard could not resolve (cadence-hooks#1129).
/// It carries a `$`, so a write judged against it is the unexpanded-expansion
/// block — never owned.
const UNRESOLVED_GH_REPO: &str = "$GH_REPO";

/// The `GH_HOST` values a gh process may inherit at a point in one command,
/// tracked across its segments (#548).
///
/// An inline `GH_HOST=h gh …` was already read by [`gh_command_host`], but an
/// `export GH_HOST=h` in an EARLIER segment reaches the child just the same,
/// and the guard used to judge that write against the hook's own host.
///
/// Transitions ADD a candidate rather than replace one. The walk runs over the
/// flattened [`command_segments`] list, which drops the operators between
/// segments, so it cannot tell whether an `export` or `unset` actually ran:
/// `export GH_HOST=evil; false && unset GH_HOST; gh …` still reaches `evil`.
/// A write is judged against every candidate and must be owned on each — the
/// set only ever grows, so every imprecision here costs a false block, never a
/// wrong-host allow.
///
/// What is modeled precisely: `export GH_HOST=<literal>`, `unset [-v]
/// GH_HOST` (when the hook process had no `GH_HOST` to fall back to), and a
/// bare `GH_HOST=<literal>` — which reaches gh only once the variable is
/// exported (an earlier `export`, `set -a`, or a `GH_HOST` the shell already
/// inherited), so `GH_HOST=x; gh …` alone stays exactly as before. Anything
/// else that can set it adds [`UNRESOLVED_GH_HOST`]: a declaring builtin
/// (`declare -x`, `readonly`, …) naming it, or naming ANY variable whose name
/// is not a plain literal (`export GH_HOS${X}T=…`, `GH_HOS{T,}`); an expansion
/// in the value; `export -n`; a `GH_HOST` mention under `eval`, `read`,
/// `printf` and the like; and an assignment inside `${…}` or `$((…))`.
///
/// A segment that invokes gh is never observed — a child process cannot change
/// the parent shell's environment, and its arguments are prose as often as not
/// (`--title "fix GH_HOST export"`). A plain mention by any other command
/// (`rg GH_HOST`, `git commit -m "…GH_HOST…"`) changes nothing either.
///
/// Not modeled, and so unchanged: a file that is `source`d, whose contents
/// this guard never sees.
///
/// **The same walk tracks `GH_REPO`** (cadence-hooks#1129): an
/// `export GH_REPO=evil/x` earlier in the command retargets every later
/// un-flagged gh write exactly as the inline `GH_REPO=evil/x gh …` does. Built
/// with [`Self::for_repo`], a candidate is a repo value, and the empty string
/// stands for "no `GH_REPO`" — gh then resolves the target itself.
#[derive(Debug)]
struct GhHostEnv {
    /// The variable tracked: `GH_HOST` or `GH_REPO`.
    var: &'static str,
    candidates: Vec<String>,
    /// `GH_HOST` carries the export attribute, so a bare assignment reaches gh.
    exported: bool,
    /// `set -a` was seen: every bare assignment is exported.
    allexport: bool,
    /// The hook process (and so the shell) inherited a `GH_HOST`.
    inherited: bool,
    /// The whole command, raw — heredoc bodies included, which the segment
    /// list strips. Read only for a `source`/`.` fed by a heredoc.
    raw_command: String,
}

impl GhHostEnv {
    fn from_process() -> Self {
        Self::tracking("GH_HOST")
    }

    fn tracking(var: &'static str) -> Self {
        let inherited = std::env::var_os(var).is_some();
        let initial = if var == "GH_HOST" {
            default_host()
        } else {
            // gh reads an inherited GH_REPO too; an empty one is unset.
            std::env::var(var).unwrap_or_default()
        };
        Self {
            var,
            candidates: vec![initial],
            exported: inherited,
            allexport: false,
            inherited,
            raw_command: String::new(),
        }
    }

    /// [`Self::from_process`] for judging `command`, whose raw text a heredoc
    /// fed to `source` is read from.
    fn for_command(command: &str) -> Self {
        Self {
            raw_command: command.to_string(),
            ..Self::from_process()
        }
    }

    /// The `GH_REPO` form of [`Self::for_command`].
    fn for_repo(command: &str) -> Self {
        Self {
            raw_command: command.to_string(),
            ..Self::tracking("GH_REPO")
        }
    }

    fn is_host(&self) -> bool {
        self.var == "GH_HOST"
    }

    /// Does `word` name the tracked variable other than by a plain read?
    fn mentions(&self, word: &str) -> bool {
        mentions_var(word, self.var)
    }

    /// The candidate after `unset`: the process default host, or no repo.
    fn unset_value(&self) -> String {
        if self.is_host() {
            default_host()
        } else {
            String::new()
        }
    }

    fn candidates(&self) -> &[String] {
        &self.candidates
    }

    fn add(&mut self, host: String) {
        if !self.candidates.contains(&host) {
            self.candidates.push(host);
        }
    }

    fn add_unresolved(&mut self) {
        let marker = if self.is_host() {
            UNRESOLVED_GH_HOST
        } else {
            UNRESOLVED_GH_REPO
        };
        self.add(marker.to_string());
    }

    /// Add the host a `GH_HOST=<value>` assignment names — or the unresolved
    /// stand-in for an empty value or one still carrying an expansion.
    fn add_assigned(&mut self, value: &str) {
        if value.is_empty() || value.contains('$') || value.contains('`') {
            self.add_unresolved();
        } else if self.is_host() {
            self.add(value.to_ascii_lowercase());
        } else {
            self.add(value.to_string());
        }
    }

    fn observe(&mut self, segment: &str) {
        self.observe_depth(segment, 0);
    }

    /// A `GH_HOST` assigned in front of a command that runs gh one level
    /// down — `GH_HOST=h bash -c "gh …"`, `env GH_HOST=h sh -c '…'`. The
    /// segment list hands the inner gh over as its own segment, without the
    /// prefix, so the host the child inherits has to be recorded here
    /// (cadence-hooks#1077). Only the leading words are read — assignments,
    /// command runners and their options — up to the command they run, so a
    /// `GH_HOST=…` that is merely an argument (`echo GH_HOST=x`) counts for
    /// nothing. A name that is not a plain literal may expand to `GH_HOST`,
    /// so it is unresolved, as [`gh_command_host`] treats it.
    ///
    /// Recorded for every later gh segment of the command, not just the
    /// wrapper's own: over-inclusive, which can only add a host to judge.
    fn observe_wrapper_prefix(&mut self, segment: &str) {
        if !contains_ignoring_ascii_case(segment, "gh") {
            return;
        }
        let tokens = tokenize(segment);
        let mut hosts: Vec<Option<&str>> = Vec::new();
        let mut command_at = tokens.len();
        for (at, token) in tokens.iter().enumerate() {
            let is_runner = COMMAND_RUNNERS.contains(&command_word(token).as_ref());
            if is_runner || token.starts_with('-') || SEGMENT_KEYWORDS.contains(&token.as_str()) {
                continue;
            }
            match token.split_once('=') {
                Some((name, value)) if name == self.var => hosts.push(Some(value)),
                Some((name, _)) if !is_literal_identifier(name) => hosts.push(None),
                Some(_) => {}
                None => {
                    command_at = at;
                    break;
                }
            }
        }
        // Only a command that goes on to run gh: `GH_HOST=h make docs` sets
        // the host for `make` alone.
        if !tokens[command_at..]
            .iter()
            .any(|token| contains_ignoring_ascii_case(token, "gh"))
        {
            return;
        }
        for host in hosts {
            match host {
                Some(value) => self.add_assigned(value),
                None => self.add_unresolved(),
            }
        }
    }

    fn observe_depth(&mut self, segment: &str, depth: usize) {
        if observes_nothing(segment, self.var) {
            return;
        }
        let tokens = tokenize(segment);
        let normalized = strip_compound_openers(&tokens);
        let mut words: &[String] = &normalized;
        while words
            .first()
            .is_some_and(|w| SEGMENT_KEYWORDS.contains(&w.as_str()))
        {
            words = &words[1..];
        }
        let assignments = words.iter().take_while(|w| is_shell_assignment(w)).count();
        let (prefix, mut rest) = words.split_at(assignments);
        // `builtin export …` / `command export …` run the same builtin, as do
        // `command -p …` and either with `--`. `command -v`/`-V` only look a
        // name up and run nothing, so such a segment changes nothing.
        while let Some(wrapper) = rest.first().map(|w| w.replace('\\', ""))
            && matches!(wrapper.as_str(), "builtin" | "command")
        {
            let mut next = 1;
            while let Some(option) = rest.get(next) {
                if option == "--" {
                    next += 1;
                    break;
                }
                let Some(flags) = option.strip_prefix('-').filter(|f| !f.is_empty()) else {
                    break;
                };
                if wrapper != "command" {
                    break;
                }
                if flags.contains(['v', 'V']) {
                    return;
                }
                if !flags.chars().all(|c| c == 'p') {
                    break;
                }
                next += 1;
            }
            match rest.get(next) {
                Some(word) if !word.starts_with('-') => rest = &rest[next..],
                _ => break,
            }
        }
        // Backslashes in a command word only suppress alias expansion: `\trap`
        // and `t\rap` are both `trap`.
        let command_word = rest
            .first()
            .map(|w| w.rsplit('/').next().unwrap_or(w).replace('\\', ""));
        let command = command_word.as_deref();

        // FAIL CLOSED where the command position was not understood: a
        // subshell, function body or case arm this normalization missed still
        // runs its builtin in some shell, so a declaring or name-writing
        // builtin ANYWHERE in the segment, next to a `GH_HOST` mention or a
        // non-literal `NAME=`, is unresolved (#1073 live review).
        let understood = command.is_some_and(|c| {
            DECLARING_BUILTINS.contains(&c)
                || NAME_OPERAND_BUILTINS.contains(&c)
                || c == "unset"
                || c == "eval"
                || c == "trap"
        });
        if !understood
            && tokens.iter().any(|t| {
                let word = t.trim_start_matches(['(', '{']);
                DECLARING_BUILTINS.contains(&word)
                    || NAME_OPERAND_BUILTINS.contains(&word)
                    || word == "unset"
            })
            && tokens.iter().any(|t| {
                self.mentions(t)
                    || (!t.starts_with('-')
                        && t.split_once('=').is_some_and(|(name, _)| {
                            // `[ "$m" = export ]`: a bare `=` names nothing.
                            !name.is_empty() && !is_literal_identifier(name)
                        }))
            })
        {
            self.add_unresolved();
        }

        // `source`/`.` fed by a heredoc or stdin runs text the segment list
        // never shows (#1073 live review).
        if matches!(command, Some("source" | "."))
            && sources_inline_text(segment)
            && (self.raw_command.contains(self.var)
                || RAW_NONLITERAL_DECLARATION.is_match(&self.raw_command))
        {
            self.add_unresolved();
        }

        if command == Some("set")
            && rest[1..].iter().any(|w| {
                w == "allexport" || (w.starts_with('-') && !w.starts_with("--") && w.contains('a'))
            })
        {
            self.allexport = true;
        }

        if let Some(name) = command.filter(|c| DECLARING_BUILTINS.contains(c)) {
            if prefix.iter().any(|w| self.mentions(w)) {
                self.add_unresolved();
            }
            self.observe_declaration(name, &rest[1..]);
            return;
        }
        // `eval` runs its words in THIS shell, so an export inside it counts.
        // Past the nesting cap its words go unread, so the host is unknown
        // (#1073 review I-d).
        if command == Some("eval") {
            // A tool-init substitution (`$(ssh-agent -s)`, `$(brew shellenv)`)
            // prints exports and hooks but never a `GH_HOST` or `GH_REPO`
            // (cameronsjo/cadence-hooks#1172); its exact head only, and only
            // when nothing in the command could have replaced the tool.
            let operands: Vec<&String> = rest[1..]
                .iter()
                .skip_while(|word| word.as_str() == "--")
                .collect();
            let plain_tool_init = !segment.contains(['\'', '\\'])
                && cadence_hooks_core::shell::eval_is_tool_init(&operands)
                && !cadence_hooks_core::push::may_redefine_known_commands(&self.raw_command);
            if !plain_tool_init {
                self.observe_nested(&rest[1..].join(" "), depth);
            }
        }
        // A `trap` action runs later in this shell, so it is read like an
        // `eval` string (#1073 review). `trap -p`, `trap -l` and `trap - SIG`
        // run nothing.
        if command == Some("trap") {
            // After `--` a leading dash is part of the action, and only an
            // action of exactly `-` (reset) runs nothing. Without `--`, a
            // leading dash is an option (`-p`, `-l`) or that same reset.
            let action = match rest[1..].split_first() {
                Some((first, tail)) if first == "--" => tail.first().filter(|a| *a != "-"),
                Some((first, _)) => Some(first).filter(|a| !a.starts_with('-')),
                None => None,
            };
            if let Some(action) = action {
                self.observe_nested(action, depth);
            }
        }
        if let Some(name) = command.filter(|c| NAME_OPERAND_BUILTINS.contains(c))
            && indirect_name_operands(name, &rest[1..])
                .iter()
                .any(|operand| !is_literal_identifier(operand) || operand == self.var)
        {
            // `printf -v GH_HOS${X}T …`, `read GH_HOS${X}T` (#1073 review I-c).
            self.add_unresolved();
        }

        match command {
            // Assignments only: shell variables, which reach gh only once
            // exported.
            None => {
                if !(self.exported || self.allexport) {
                    return;
                }
                for word in prefix {
                    if let Some(value) = word
                        .strip_prefix(self.var)
                        .and_then(|rest| rest.strip_prefix('='))
                    {
                        self.add_assigned(value);
                    } else if mentions_gh_host(word) {
                        self.add_unresolved();
                    }
                }
            }
            Some("unset") => {
                let args = &rest[1..];
                if !tokens.iter().any(|t| self.mentions(t)) {
                    return;
                }
                let unsets = args.iter().any(|w| w == self.var);
                if prefix.iter().any(|w| self.mentions(w))
                    || args.iter().any(|w| w.starts_with('-') && w != "-v")
                    || args.iter().any(|w| w != self.var && self.mentions(w))
                {
                    self.add_unresolved();
                } else if unsets {
                    // gh then falls back to its own configured default, which
                    // is the process default only when there was no inherited
                    // `GH_HOST` for the hook to have read instead.
                    if self.inherited {
                        self.add_unresolved();
                    } else {
                        self.add(self.unset_value());
                    }
                }
            }
            Some(name) if name == "eval" || VAR_SETTING_BUILTINS.contains(&name) => {
                if tokens.iter().any(|t| self.mentions(t)) {
                    self.add_unresolved();
                }
            }
            // Any other command: a prefix assignment lives only for that
            // command, and a mention is only a mention — just an assignment
            // inside an expansion can leave something behind.
            Some(_) => {
                let expansion_assignment = if self.is_host() {
                    &GH_HOST_EXPANSION_ASSIGNMENT
                } else {
                    &GH_REPO_EXPANSION_ASSIGNMENT
                };
                if expansion_assignment.is_match(segment) {
                    self.add_unresolved();
                }
            }
        }
    }

    /// Observe a script this shell will run from a string (`eval`, a `trap`
    /// action). Past [`MAX_EVAL_DEPTH`] its words go unread, and a command word
    /// built by an expansion (`eval "$(…)"`, `eval "$X"`) is text this walk
    /// never sees — both are unresolved.
    fn observe_nested(&mut self, script: &str, depth: usize) {
        if depth >= MAX_EVAL_DEPTH {
            self.add_unresolved();
            return;
        }
        for inner in command_segments(script) {
            if segment_invokes_gh(&inner) {
                continue;
            }
            if command_word_is_dynamic(&inner) {
                self.add_unresolved();
                continue;
            }
            self.observe_depth(&inner, depth + 1);
        }
    }

    /// One `export`/`declare`/`typeset`/`readonly`/`local` invocation's
    /// arguments. See [`DECLARING_BUILTINS`].
    fn observe_declaration(&mut self, builtin: &str, args: &[String]) {
        let unexport = builtin == "export" && args.iter().any(|w| w == "-n");
        // A nameref (`declare -n r=GH_HOST`) makes every later write to `r` a
        // write to its target, which no later segment spells. Any nameref, or
        // any value naming GH_HOST, is unresolved (#1073 review I-c).
        let nameref = builtin != "export"
            && args
                .iter()
                .any(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('n'));
        if nameref
            || (builtin != "export"
                && args
                    .iter()
                    .any(|w| w.split_once('=').is_some_and(|(_, v)| v.contains(self.var))))
        {
            self.add_unresolved();
        }
        for word in args {
            if word.starts_with('-') || word.starts_with('+') {
                continue;
            }
            let name = word.split_once('=').map_or(word.as_str(), |(n, _)| n);
            if !is_literal_identifier(name) {
                // `GH_HOS${X}T`, `GH_HOS{T,}`, a backtick, a stray quote: the
                // name is only known once the shell expands it.
                self.add_unresolved();
                continue;
            }
            if name.strip_suffix('+').unwrap_or(name) != self.var {
                continue;
            }
            if builtin != "export" || unexport {
                // Not modeled: declare/typeset/readonly/local attributes and
                // `export -n` un-exporting.
                self.add_unresolved();
                continue;
            }
            self.exported = true;
            match word
                .strip_prefix(self.var)
                .and_then(|rest| rest.strip_prefix('='))
            {
                Some(value) => self.add_assigned(value),
                // `export GH_HOST` exports whatever the shell variable holds;
                // `GH_HOST+=…` appends to it.
                None => self.add_unresolved(),
            }
        }
    }
}

/// A plain shell identifier (`[A-Za-z_][A-Za-z0-9_]*`), optionally with the
/// trailing `+` of a `NAME+=` append. Anything else — `$`, a backslash, `{`, a
/// backtick, a quote — means the shell decides the name, not the text.
fn is_literal_identifier(name: &str) -> bool {
    let name = name.strip_suffix('+').unwrap_or(name);
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Tokens with the openers of a compound command removed, so the builtin
/// inside is found at command position: a leading `(` (`(export …`), a
/// function definition head (`name()`, `name(){`, `name ( ) {`,
/// `function name {`), and a case arm's pattern (`case x in x)`, `y)`).
fn strip_compound_openers(tokens: &[String]) -> Vec<String> {
    // A cursor rather than removing from the front: a segment of thousands of
    // `case x in x)` openers shifted the whole vector once per opener, and a
    // 200 KB flood spent half a second here.
    let mut words: Vec<String> = tokens.to_vec();
    let mut at = 0;
    loop {
        let Some(first) = words.get(at).cloned() else {
            return words.split_off(at.min(words.len()));
        };
        let rest = &words[at..];
        if first == "(" || first == "{" || first == "()" {
            at += 1;
        } else if let Some(tail) = first.strip_prefix('(').filter(|r| !r.starts_with('(')) {
            words[at] = tail.to_string();
        } else if first == "function" && rest.len() > 1 {
            at += 2;
        } else if let Some((name, _)) = first.split_once("()")
            && is_literal_identifier(&name.replace('-', "_"))
        {
            let tail = first[name.len() + 2..].trim_start_matches('{').to_string();
            if tail.is_empty() {
                at += 1;
            } else {
                words[at] = tail;
            }
        } else if rest.get(1).is_some_and(|w| w == "()" || w == "(){")
            && is_literal_identifier(&first.replace('-', "_"))
        {
            at += 2;
        } else if first == "case" {
            match rest.iter().position(|w| w.ends_with(')')) {
                Some(end) => at += end + 1,
                None => return words.split_off(at),
            }
        } else if first.len() > 1 && first.ends_with(')') && !first.contains("$(") {
            // A later case arm: `y) export …`.
            at += 1;
        } else {
            return words.split_off(at);
        }
    }
}

/// True when a segment's command word is produced by an expansion (`$X`,
/// `$(…)`, a backtick), after compound openers, keywords and assignments.
fn command_word_is_dynamic(segment: &str) -> bool {
    let normalized = strip_compound_openers(&tokenize(segment));
    normalized
        .iter()
        .skip_while(|w| SEGMENT_KEYWORDS.contains(&w.as_str()))
        .find(|w| !is_shell_assignment(w))
        .is_some_and(|w| w.contains('$') || w.contains('`'))
}

/// True when a `source`/`.` segment reads its script from text in the command
/// itself: a heredoc or here-string, stdin, or a process substitution.
fn sources_inline_text(segment: &str) -> bool {
    segment.contains("<<") || segment.contains("/dev/stdin") || segment.contains("<(")
}

/// A declaring builtin naming a variable the shell builds at expansion time,
/// anywhere in raw text (a heredoc body): `export GH_HOS''T=…`,
/// `declare -x GH_HOS${X}T=…`.
static RAW_NONLITERAL_DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:export|declare|typeset|readonly|local)\s+(?:[-+]\S*\s+)*[^\s=]*[$`{'"\\][^\s=]*="#,
    )
    .expect("pattern should compile")
});

/// `NAME=value` / `NAME+=value` in command-word position.
fn is_shell_assignment(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(name, _)| is_literal_identifier(name))
}

/// True when `word` names the `GH_HOST` variable in any way other than a plain
/// read (`$GH_HOST`, `${GH_HOST}`). Longer names that merely contain it
/// (`MY_GH_HOST`, `GH_HOSTNAME`) do not count.
fn mentions_gh_host(word: &str) -> bool {
    mentions_var(word, "GH_HOST")
}

/// [`mentions_gh_host`] for any variable name.
/// Can [`GhHostEnv::observe_depth`] skip `segment` outright? Only when it is
/// plain words — no quoting, escape, expansion, `=` or brace expansion that
/// could spell something else once tokenized — none of which mentions `var`
/// or names a builtin the observation reads. Every arm of the observation
/// needs one of those, so such a segment leaves the state as it was; skipping
/// its tokenization keeps a flood of plain commands cheap.
fn observes_nothing(segment: &str, var: &str) -> bool {
    if segment.contains(var)
        || !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" \t\n_./:@%+-;|&(){}".contains(&b))
    {
        return false;
    }
    !segment
        .split(|c: char| !(c.is_ascii_alphanumeric() || "_.-".contains(c)))
        .any(|word| {
            DECLARING_BUILTINS.contains(&word)
                || NAME_OPERAND_BUILTINS.contains(&word)
                || VAR_SETTING_BUILTINS.contains(&word)
                || matches!(
                    word,
                    "unset" | "set" | "source" | "." | "eval" | "trap" | "builtin" | "command"
                )
        })
}

fn mentions_var(word: &str, name: &str) -> bool {
    let bytes = word.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(offset) = word[from..].find(name) {
        let start = from + offset;
        let end = start + name.len();
        from = end;
        if (start > 0 && ident(bytes[start - 1])) || bytes.get(end).is_some_and(|&b| ident(b)) {
            continue;
        }
        if start >= 1 && bytes[start - 1] == b'$' {
            continue;
        }
        if start >= 2 && &bytes[start - 2..start] == b"${" && bytes.get(end) == Some(&b'}') {
            continue;
        }
        return true;
    }
    false
}

/// Resolve the host selected for one `gh` invocation.
///
/// `default_host()` sees the hook process environment, not an assignment that
/// belongs to the command being judged. gh also lets an explicit
/// `--hostname` override `GH_HOST`; ownership resolution must use the same
/// precedence or it can approve an owner on github.com while the write is sent
/// to another forge (#476).
///
/// Which tokens are stepped over as some other flag's value is decided by
/// [`host_scan_flags`], per subcommand — never by `gh api`'s grammar wholesale.
///
/// `env_host` is the `GH_HOST` the gh process inherits — the hook's own
/// default, or what an `export` earlier in the same command left behind (#548,
/// see [`GhHostEnv`]). Inline and `--hostname` selections outrank it.
fn gh_command_host(command: &str, env_host: &str) -> String {
    let fallback = env_host.to_string();
    let Some((tokens, gh_index)) = gh_command_tokens(command) else {
        return fallback;
    };
    let table = host_scan_flags(&tokens[gh_index..]);

    // A prefix word whose NAME is not a plain literal (`env GH_HOS${X}T=h gh`)
    // may expand to `GH_HOST=h`, so it resolves to no known host (#548).
    // `env -S`/`--split-string` re-splits one string into assignments and a
    // command, so its host is not readable from these tokens either.
    let prefix_words = &tokens[..gh_index];
    let split_string = prefix_words
        .iter()
        .any(|t| t.rsplit('/').next() == Some("env"))
        && prefix_words.iter().any(|t| {
            t.starts_with("--split-string")
                || (t.starts_with('-') && !t.starts_with("--") && t.contains('S'))
        });
    let obfuscated_prefix = split_string
        || prefix_words.iter().any(|token| {
            token
                .split_once('=')
                .is_some_and(|(name, _)| !name.starts_with('-') && !is_literal_identifier(name))
        });
    let inline_host = if obfuscated_prefix {
        Some(UNRESOLVED_GH_HOST.to_string())
    } else {
        tokens[..gh_index]
            .iter()
            .filter_map(|token| token.strip_prefix("GH_HOST="))
            .rfind(|host| !host.is_empty())
            .map(str::to_ascii_lowercase)
    };

    let mut flag_host = None;
    let mut index = gh_index + 1;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            break;
        }
        if token == "--hostname" {
            if let Some(host) = tokens.get(index + 1).filter(|host| !host.is_empty()) {
                flag_host = Some(host.to_ascii_lowercase());
                index += 2;
                continue;
            }
        } else if let Some(host) = token
            .strip_prefix("--hostname=")
            .filter(|host| !host.is_empty())
        {
            flag_host = Some(host.to_ascii_lowercase());
        } else if token.starts_with("--") {
            // Any other long flag. A value-taking one owns the following token
            // even when that value is the literal `--hostname`; a boolean long
            // owns nothing. Answering `--` HERE is what keeps `--silent` out of
            // the shorthand arm below — see [`long_flag_stride`].
            index += long_flag_stride(token, table.is_some_and(|t| (t.long_takes_value)(token)));
            continue;
        } else if let Some(cluster) = token.strip_prefix('-')
            && table.is_some_and(|t| cluster_consumes_next(cluster, t.value_shorts))
        {
            index += 2;
            continue;
        }
        index += 1;
    }

    flag_host.or(inline_host).unwrap_or(fallback)
}

#[cfg(test)]
fn resolve_target_repo(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
) -> RepoResolution {
    resolve_target_repo_on(command, work_dir, allowed_owners, &default_host())
}

/// The first of [`resolve_target_repos_on`]'s resolutions — the one the
/// command's own spelling names first.
#[cfg(test)]
fn resolve_target_repo_on(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    env_host: &str,
) -> RepoResolution {
    resolve_target_repos_on(command, work_dir, allowed_owners, env_host, "")
        .into_iter()
        .next()
        .unwrap_or(RepoResolution::Unresolvable)
}

/// Every repo gh may write to for one segment, with the inherited `GH_HOST`
/// supplied by the caller — see [`gh_command_host`]. The write must be owned
/// on EVERY one: more than one appears only where the command text cannot
/// say which of them gh picks.
///
/// - A `-R` whose readings agree but may each be another flag's value
///   ([`RepoFlag::TargetOrAbsent`]) adds the fallback the command would take
///   without it (cadence-hooks#1069).
/// - An inline `GH_REPO=` adds its value: gh reads it wherever `-R` is absent
///   or empty, and this guard cannot tell which subcommands honor it.
/// - Without one, an `env_repo` the gh process inherits — exported earlier in
///   the command, see [`GhHostEnv::for_repo`] — adds its value the same way
///   (cadence-hooks#1129). Empty means none.
fn resolve_target_repos_on(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    env_host: &str,
    env_repo: &str,
) -> Vec<RepoResolution> {
    let dh = gh_command_host(command, env_host);

    // 1. Explicit -R / --repo flag.
    let mut resolutions = match repo_flag(command) {
        RepoFlag::Target(repo) => return vec![flag_value_resolution(&repo, &dh)],
        RepoFlag::Ambiguous => return vec![RepoResolution::AmbiguousFlags],
        RepoFlag::TargetOrAbsent(repo) => vec![flag_value_resolution(&repo, &dh)],
        RepoFlag::Absent => Vec::new(),
    };
    if let Some(repo) = inline_gh_repo(command) {
        resolutions.push(flag_value_resolution(&repo, &dh));
    } else if !env_repo.is_empty() {
        resolutions.push(flag_value_resolution(env_repo, &dh));
    }
    resolutions.push(resolve_unflagged_target(
        command,
        work_dir,
        allowed_owners,
        &dh,
    ));
    resolutions
}

/// Judge-ready form of one `-R`/`--repo`/`GH_REPO` value, split the way gh
/// splits it ([`parse_gh_repo_value`]): a bare `OWNER/REPO` lands on the
/// command's host `dh`, while a URL or `HOST/OWNER/REPO` names its own —
/// so `-R github.com/cameronsjo/x` is `cameronsjo/x` on github.com, not a
/// repo owned by `github.com` (cadence-hooks#1077), and
/// `-R https://evil.example/cameronsjo/x` is judged on `evil.example`.
///
/// A value carrying a shell expansion keeps its raw text, so the
/// unexpanded-expansion block names it (#757); any other value gh would not
/// split is [`RepoResolution::UnreadableFlag`].
fn flag_value_resolution(value: &str, dh: &str) -> RepoResolution {
    match parse_gh_repo_value(value) {
        Some(spec) => RepoResolution::Resolved {
            host: spec.host.unwrap_or_else(|| dh.to_string()),
            repo: format!("{}/{}", spec.owner, spec.name),
        },
        None if repo_has_unexpanded_expansion(value) => RepoResolution::Resolved {
            host: dh.to_string(),
            repo: value.to_string(),
        },
        None => RepoResolution::UnreadableFlag(value.to_string()),
    }
}

/// True when an explicit `-R` value names a repo owned on the host it lands
/// on — the loop gate's form of [`flag_value_resolution`]. An unreadable
/// value is not owned.
fn flag_value_is_owned(
    value: &str,
    dh: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
) -> bool {
    match flag_value_resolution(value, dh) {
        RepoResolution::Resolved { host, repo } => {
            is_allowed(&host, &repo, allowed_owners, allowed_repos)
        }
        _ => false,
    }
}

/// The last non-empty `GH_REPO=` in the assignment prefix of the segment's gh
/// invocation. gh treats an empty one as unset.
fn inline_gh_repo(command: &str) -> Option<String> {
    let (tokens, gh_index) = gh_command_tokens(command)?;
    tokens[..gh_index]
        .iter()
        .filter_map(|token| token.strip_prefix("GH_REPO="))
        .rfind(|value| !value.is_empty())
        .map(str::to_string)
}

/// Where a write goes when no `-R` names its target: a `gh repo` positional,
/// a `gh api repos/…` endpoint, or the checkout's git remotes.
fn resolve_unflagged_target(
    command: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    dh: &str,
) -> RepoResolution {
    // 2. gh repo <subcommand> <owner/repo> (positional arg)
    if let Some((subcommand, spec_host, first_arg)) = gh_repo_positional_target(command) {
        if first_arg.contains('/') {
            return RepoResolution::Resolved {
                // A `HOST/OWNER/REPO` positional names its own host, and it is
                // judged rather than assumed: `evil-host/cameronsjo/x` carries
                // an allowed-looking owner to a forge the allowlist never
                // named. Bare allowlist entries match the default host only, so
                // the spec blocks unless that host was explicitly allowed.
                host: spec_host.unwrap_or_else(|| dh.to_string()),
                repo: first_arg,
            };
        }
        // Only `create` can infer owner from a bare name (no `/`)
        if subcommand == "create" {
            let default_owner = allowed_owners
                .iter()
                .find(|e| e.host.is_none() || e.host.as_deref() == Some(dh))
                .map(|e| e.owner.as_str())
                .unwrap_or("");
            return RepoResolution::Resolved {
                host: dh.to_string(),
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
        return RepoResolution::Resolved {
            host: dh.to_string(),
            repo,
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
fn looped_write_block_message(writes: &[String], suggestion: Option<&str>) -> String {
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
    let host_hint = if host == UNRESOLVED_GH_HOST {
        "\n   Host: this command may set `GH_HOST` to a value this guard cannot read (a \
         declaring builtin such as `declare -x`, an expanded variable name or value, or an \
         assignment inside `${…}`/`$((…))`) — name the host on the gh command itself \
         (`--hostname <host>`)"
            .to_string()
    } else if host != default && !extra_hosts.iter().any(|e| e == host) {
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
pub(crate) fn gh_argv(segment: &str) -> Option<Vec<String>> {
    let (tokens, start) = gh_command_tokens(segment)?;
    Some(tokens[start..].to_vec())
}

/// Tokenize the shell layer that directly invokes `gh`, retaining its prefix.
///
/// Keeping the prefix lets host resolution see an inline `GH_HOST` assignment;
/// peeling `eval` here keeps that assignment and the argv on the same bounded,
/// quote-aware path as every other target-resolution arm.
fn gh_command_tokens(segment: &str) -> Option<(Vec<String>, usize)> {
    gh_command_tokens_depth(segment, 0)
}

fn gh_command_tokens_depth(segment: &str, depth: usize) -> Option<(Vec<String>, usize)> {
    let tokens = tokenize(segment);
    if let Some(start) = tokens.iter().position(|tok| token_is_gh(tok)) {
        return Some((tokens, start));
    }
    if depth < MAX_EVAL_DEPTH
        && tokens
            .first()
            .is_some_and(|t| t.rsplit('/').next().unwrap_or(t) == "eval")
    {
        return gh_command_tokens_depth(&tokens[1..].join(" "), depth + 1);
    }
    if depth < MAX_EVAL_DEPTH
        && let Some(script) = env_split_string_script(&tokens)
    {
        return gh_command_tokens_depth(&script, depth + 1);
    }
    None
}

/// The command an `env -S '<string>'` (`--split-string`) runs, as one string
/// to re-tokenize: GNU env splits the string into words and runs them as if
/// they had been written in its place, so `env -S 'gh issue create -R evil/x'`
/// is that gh invocation — while [`tokenize`] keeps the quoted string as ONE
/// token no `gh` test ever matches (cadence-hooks#1077). Assignments written
/// before the option reach the command too, so they are carried in front of
/// the string, where [`gh_command_host`] reads an inline `GH_HOST`.
///
/// `None` unless the segment's command word is `env` and one of its options
/// is `-S`. The option walk mirrors GNU env: `-u`/`-C` (and their long forms
/// without `=`) take the next token; `S` in a short cluster takes the rest of
/// the cluster or the next token; the first word that is neither an option
/// nor an assignment ends the options.
fn env_split_string_script(tokens: &[String]) -> Option<String> {
    // Any `NAME=…` word counts as an assignment here, literal name or not:
    // carried forward, a non-literal one (`GH_HOS${X}T=…`) is exactly what
    // [`gh_command_host`] resolves to an unknown host.
    let assignment = |t: &str| !t.starts_with('-') && t.contains('=');
    // `env` may sit behind other runners (`sudo -u me env -S …`, `timeout 5
    // env -S …`); their own options are not modelled here, which can only
    // unwrap more, never less.
    let first = tokens.iter().find(|t| !assignment(t))?;
    let head = command_word(first);
    if head != "env"
        && !COMMAND_RUNNERS.contains(&head.as_ref())
        && !TRANSPARENT.contains(&head.as_ref())
    {
        return None;
    }
    let env_at = tokens.iter().position(|t| command_word(t) == "env")?;
    let options = &tokens[env_at + 1..];
    let mut assignments: Vec<&str> = tokens[..env_at]
        .iter()
        .map(String::as_str)
        .filter(|t| assignment(t))
        .collect();
    let mut i = 0;
    while let Some(token) = options.get(i) {
        let script = if let Some(long) = token.strip_prefix("--") {
            match long.split_once('=') {
                Some(("split-string", value)) => Some((value.to_string(), i + 1)),
                None if long == "split-string" => {
                    options.get(i + 1).map(|value| (value.clone(), i + 2))
                }
                None if matches!(long, "unset" | "chdir") => {
                    i += 2;
                    continue;
                }
                _ => None,
            }
        } else if let Some(cluster) = token.strip_prefix('-').filter(|c| !c.is_empty()) {
            match cluster.find(['S', 'u', 'C']) {
                Some(at) if cluster[at..].starts_with('S') => {
                    let attached = &cluster[at + 1..];
                    if attached.is_empty() {
                        options.get(i + 1).map(|value| (value.clone(), i + 2))
                    } else {
                        Some((attached.to_string(), i + 1))
                    }
                }
                Some(at) if cluster.len() == at + 1 => {
                    i += 2;
                    continue;
                }
                _ => None,
            }
        } else if assignment(token) {
            assignments.push(token);
            i += 1;
            continue;
        } else {
            return None;
        };
        if let Some((script, next)) = script {
            let mut words = assignments.join(" ");
            words.push(' ');
            words.push_str(&script);
            for word in &options[next..] {
                words.push(' ');
                words.push_str(word);
            }
            return Some(words);
        }
        i += 1;
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
    // `gh repo new` is `gh repo create` (cadence-hooks#996).
    let verb = gh_canonical_verb("repo", argv.get(2)?).to_string();
    let verb = &verb;
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
        if word.starts_with("--") {
            // `--flag=value` carries its value inline, so nothing to step over.
            i += long_flag_stride(word, REPO_VERB_VALUE_FLAGS.contains(&word));
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
    // First non-flag token after `gh` must be the `api` subcommand — the same
    // rule [`host_scan_flags`] gates gh api's flag table on, shared so the two
    // cannot drift into disagreeing about which commands are `api`.
    let mut i = gh_api_subcommand_index(&tokens)? + 1;
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
/// Reads through [`scan_unanimous_flag`], which passes gh `api`'s shorthand
/// table, so a cluster is walked precisely instead of failing closed; only
/// `gh api` is inspected, since a `-X` belonging to another subcommand is not
/// a method. (`-R` no longer shares this scanner: it reads through the shared
/// [`gh_repo_flags`], cadence-hooks#937.)
fn api_explicit_method(segment: &str) -> Option<String> {
    gh_api_endpoint(segment)?;
    let words = gh_argv(segment)?;
    match scan_unanimous_flag(&words, 'X', "--method", Some(&GH_API_FLAGS)) {
        FlagScan::Single(method) => Some(method.to_ascii_uppercase()),
        FlagScan::Absent | FlagScan::Ambiguous => None,
    }
}

/// True when a `gh api` segment's `-X`/`--method` readings make it a write
/// on their own, whatever parameters it carries (cadence-hooks#1139):
///
/// - a write verb in any spelling pflag accepts — `-XDELETE` and
///   `--method=DELETE` never matched [`API_WRITE_METHOD`], which wants a
///   blank after the flag, so a parameterless one read as a GET;
/// - a value carrying `$` or a backtick — `-X $(echo DELETE)`, `-X "$M"` —
///   which only the shell knows. Treating it as a GET judged no target at all;
///   as a write, the target is judged;
/// - readings that disagree or cannot be attributed ([`FlagScan::Ambiguous`]),
///   the "I cannot tell" answer every caller of the scan fails closed on.
///
/// A literal non-write method (`GET`, `HEAD`, a typo) stays with the implicit
/// rule [`is_write_command`] applies below.
fn api_method_forces_write(segment: &str) -> bool {
    if gh_api_endpoint(segment).is_none() {
        return false;
    }
    let Some(words) = gh_argv(segment) else {
        return false;
    };
    match scan_unanimous_flag(&words, 'X', "--method", Some(&GH_API_FLAGS)) {
        FlagScan::Absent => false,
        FlagScan::Ambiguous => true,
        FlagScan::Single(method) => {
            method.contains(['$', '`'])
                || matches!(
                    method.to_ascii_uppercase().as_str(),
                    "POST" | "PUT" | "PATCH" | "DELETE"
                )
        }
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
    // Plain words only — no quoting, escape, expansion or brace group that
    // could spell `gh` once tokenized — and no `gh` in any case: no token,
    // and no `eval`/`env -S` script inside it, can resolve to `gh`.
    if segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" \t\n_./:@%+-;|&()".contains(&b))
        && !contains_ignoring_ascii_case(segment, "gh")
    {
        return false;
    }
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
    if depth < MAX_EVAL_DEPTH
        && let Some(script) = env_split_string_script(&tokens)
    {
        return segment_invokes_gh_depth(&script, depth + 1);
    }
    false
}

/// True when a single token resolves to `gh` (bare, a `*/gh` path, a
/// backslash-escaped `\gh`, or a Windows `gh.exe`).
///
/// Through the shared [`command_word`] rather than a local strip-then-split:
/// the local order missed `/opt/\gh`, so the token was never found, the target
/// fell back to the cwd remote (owned), and a write to a non-owned repo
/// silently ALLOWED. Measured ALLOW→BLOCK (cadence-hooks#450 review — one of
/// four divergent copies of this normalization, now one).
///
/// `gh.exe issue create` is a detected write too: the raw-TEXT regex misses it
/// (`gh` is followed by `.exe`, not whitespace), but [`argv_names_write`] reads
/// the parsed argv, where this function resolves it (cadence-hooks#1077).
fn token_is_gh(tok: &str) -> bool {
    command_word(tok) == "gh"
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

/// Top-level REST endpoints that name no owner or repository at all, so no
/// `repos/<owner>/<repo>` spelling of them exists. Used only to word the block:
/// the guard still refuses the write, but the "use `repos/<owner>/<repo>/…`"
/// fix is unsatisfiable for these and must not be offered (#971).
const REPOLESS_API_ROOTS: &[&str] = &["markdown", "rate_limit", "meta", "emojis", "zen", "octocat"];

/// The first path segment of a relative `gh api` endpoint when it is one of
/// [`REPOLESS_API_ROOTS`]. Reads the path only, like [`api_repos_target`]; a
/// URL-form endpoint returns `None` and keeps the generic wording.
fn repoless_api_root(segment: &str) -> Option<&'static str> {
    let endpoint = gh_api_endpoint(segment)?;
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    if path.contains("://") {
        return None;
    }
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    REPOLESS_API_ROOTS
        .iter()
        .copied()
        .find(|root| *root == first)
}

/// The endpoint path of a `gh api` segment when it addresses the authenticated
/// user's own account (`user/…`), with gh's first-class command for that
/// resource when one exists. Relative endpoints only, like
/// [`repoless_api_root`].
///
/// Account resources have no `repos/<owner>/<repo>` form, so the generic fix
/// dead-ended there (#756). The block itself stands — no owner is in the path —
/// but the hint names what does work. `gh ssh-key` and `gh gpg-key` are
/// account-level and deliberately outside this guard's write patterns (see
/// [`WRITE_ACTIONS_EXTRA`]); only the two resources whose commands are known to
/// cover the same keys are mapped, and every other `user/…` path gets the plain
/// "ask the user" branch.
fn account_scoped_api(segment: &str) -> Option<Option<&'static str>> {
    let endpoint = gh_api_endpoint(segment)?;
    let path = endpoint.split(['?', '#']).next().unwrap_or("");
    if path.contains("://") {
        return None;
    }
    let mut parts = path.trim_start_matches('/').split('/');
    if parts.next() != Some("user") {
        return None;
    }
    Some(match parts.next() {
        Some("keys") => Some("`gh ssh-key add` / `gh ssh-key delete <id>`"),
        Some("gpg_keys") => Some("`gh gpg-key add` / `gh gpg-key delete <key-id>`"),
        _ => None,
    })
}

/// The fix line for an account-scoped `gh api` write — see [`account_scoped_api`].
fn account_scoped_fix(alternative: Option<&str>) -> String {
    match alternative {
        Some(cmd) => format!(
            "account resources have no repos/<owner>/<repo> form; use gh's own command for this \
             resource ({cmd}), or ask the user"
        ),
        None => "account resources have no repos/<owner>/<repo> form; ask the user to run the \
                 command themselves"
            .to_string(),
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
    if let Some(root) = repoless_api_root(segment) {
        return format!(
            "🚫 git-guardrails: gh api write to `/{root}`, an endpoint with no owner or repo \
             in its path — there is no ownership to check\n   \
             Command: {segment}\n   \
             Fix: `/{root}` has no `repos/<owner>/<repo>` form, so this guard cannot clear it. \
             Do the work locally, or ask the user to run the command themselves.{note}"
        );
    }
    if let Some(alternative) = account_scoped_api(segment) {
        return format!(
            "🚫 git-guardrails: gh api write to an account-scoped `user/…` endpoint — no owner in \
             its path, so ownership can't be checked\n   \
             Command: {segment}\n   \
             Fix: {}{note}",
            account_scoped_fix(alternative)
        );
    }
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
    let fix = if let Some(root) = repoless_api_root(segment) {
        format!(
            "/{root} has no owner or repo in its path, so no repos/<owner>/<repo> form exists; do the work locally or ask the user to run it"
        )
    } else if let Some(alternative) = account_scoped_api(segment) {
        account_scoped_fix(alternative)
    } else if segment_is_graphql(segment) {
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

/// [`looped_write_kind`] for one loop-analysis command.
fn looped_command_kind(c: &loop_analysis::LoopedCommand) -> LoopedWriteKind {
    looped_write_kind(&format!("gh {}", c.args.join(" ")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoopedWriteKind {
    ReadOrAllowed,
    RepoWrite,
    ApiUnverifiable { undeterminable_query: bool },
}

/// Classify the reconstructed argv retained by loop analysis.
///
/// API calls without a repository-shaped endpoint cannot use `-R`, so they
/// must not fall into the generic missing-target block. In particular,
/// GraphQL reads and the two safe thread-metadata mutations remain allowed,
/// while other mutations use the same unverifiable-API verdict as the
/// per-segment path.
fn looped_write_kind(command: &str) -> LoopedWriteKind {
    if !is_write_command(command) {
        return LoopedWriteKind::ReadOrAllowed;
    }
    let Some(endpoint) = gh_api_endpoint(command) else {
        return LoopedWriteKind::RepoWrite;
    };
    if is_graphql_endpoint(&endpoint) {
        let status = graphql_mutation_status(command);
        if status == Some(false) || graphql_is_safe_mutation(command) {
            return LoopedWriteKind::ReadOrAllowed;
        }
        return LoopedWriteKind::ApiUnverifiable {
            undeterminable_query: status.is_none(),
        };
    }
    if api_repos_target(&endpoint).is_none() {
        return LoopedWriteKind::ApiUnverifiable {
            undeterminable_query: false,
        };
    }
    LoopedWriteKind::RepoWrite
}

/// True when a resolved `owner/repo` still carries shell expansion syntax
/// (`$1`, `${R}`, `$(…)`, a backtick) — a value only the running shell knows.
fn repo_has_unexpanded_expansion(repo: &str) -> bool {
    repo.contains('$') || repo.contains('`')
}

/// Build the block message for a gh write in a fork whose remotes are not both
/// owned. Each remote is `(host, owner/repo, owned)`.
///
/// Only an OWNED remote is offered as a `-R` fix. Suggesting `-R <upstream>`
/// for an upstream off the allowlist sent the operator straight into this
/// guard's own unowned-target block (#1032), so an unowned remote instead gets
/// the path that actually works: the user runs that write themselves.
fn fork_block_message(origin: (&str, &str, bool), upstream: (&str, &str, bool)) -> String {
    let (origin_host, origin_repo, origin_owned) = origin;
    let (upstream_host, upstream_repo, upstream_owned) = upstream;
    let line = |label: &str, repo: &str, owned: bool| {
        if repo.is_empty() {
            format!("The {label} remote URL could not be parsed, so it cannot be targeted here")
        } else if owned {
            format!("Use -R {repo} to target {label}")
        } else {
            format!(
                "{repo} is not on your allowlist, so `-R {repo}` is blocked too — if the user \
                 intends to write to {label}, write the command for them to run themselves"
            )
        }
    };
    format!(
        "🚫 git-guardrails: Write operation in a fork — specify target with -R\n   \
         Fork:     {origin_host}/{origin_repo}\n   \
         Upstream: {upstream_host}/{upstream_repo}\n\n   \
         {}\n   \
         {}",
        line("your fork", origin_repo, origin_owned),
        line("upstream", upstream_repo, upstream_owned),
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
    env_host: &str,
    env_repo: &str,
) -> Option<CheckResult> {
    resolve_target_repos_on(segment, work_dir, allowed_owners, env_host, env_repo)
        .into_iter()
        .find_map(|resolution| {
            judge_resolution(
                resolution,
                segment,
                work_dir,
                allowed_owners,
                allowed_repos,
                extra_hosts,
            )
        })
}

/// The verdict on one repo a write segment may land on.
fn judge_resolution(
    resolution: RepoResolution,
    segment: &str,
    work_dir: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
) -> Option<CheckResult> {
    match resolution {
        RepoResolution::UnreadableFlag(value) => Some(CheckResult::block_structured(
            format!(
                "🚫 git-guardrails: gh write names a target repo this guard cannot read\n   \
                 Command: {segment}\n   \
                 Target:  {value}\n   \
                 gh reads a repo as a URL or `[HOST/]OWNER/REPO`; this value is neither, or \
                 is spelled in a way this guard cannot split exactly as gh does, so it cannot \
                 be checked for ownership.\n   \
                 Fix: spell the target as `-R owner/repo`"
            ),
            BlockMetadata {
                rule_id: "gh-write-target-unresolvable".to_string(),
                fix: "spell the target as -R owner/repo".to_string(),
                allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
                severity: "error",
            },
        )),
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
                let owned = |host: &str, repo: &str| {
                    !repo.is_empty()
                        && is_allowed_with_extras(
                            host,
                            repo,
                            allowed_owners,
                            allowed_repos,
                            extra_hosts,
                        )
                };
                Some(CheckResult::block(fork_block_message(
                    (&origin_host, &origin, owned(&origin_host, &origin)),
                    (&upstream_host, &upstream, owned(&upstream_host, &upstream)),
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
            } else if repo_has_unexpanded_expansion(&repo) {
                // The target is a shell expansion this guard never sees the
                // value of, so it is UNRESOLVABLE, not unowned — and the
                // unowned template's `-R <owner>/<name>` fix would graft an
                // owner the caller never chose onto `$1` (#757).
                Some(CheckResult::block_structured(
                    format!(
                        "⚠️  git-guardrails: Cannot determine target repo for gh write operation\n   \
                         Target:  {repo} (an unexpanded shell expansion — its value is only known \
                         when the shell runs)\n   \
                         Fix: pass the target as a literal `-R owner/repo`"
                    ),
                    BlockMetadata {
                        rule_id: "gh-write-target-unresolvable".to_string(),
                        fix: "pass the target as a literal -R owner/repo".to_string(),
                        allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
                        severity: "error",
                    },
                ))
            } else {
                let example_owner = allowed_owners
                    .first()
                    .map(|e| e.owner.as_str())
                    .unwrap_or("owner");
                // Reuse the repo *name* under an allowed owner so the fix lands
                // on the same project — `evil/cool-tool` becomes
                // `cameronsjo/cool-tool`, not a placeholder.
                let repo_name = repo.split('/').next_back().unwrap_or(repo.as_str());
                // An unresolved GH_HOST is not fixed by any `-R` (#548).
                let fix = if host == UNRESOLVED_GH_HOST {
                    "name the host on the gh command itself (--hostname <host>)".to_string()
                } else {
                    format!("-R {example_owner}/{repo_name}")
                };
                Some(CheckResult::block_structured(
                    disallowed_message(&host, &repo, allowed_owners, allowed_repos, extra_hosts),
                    BlockMetadata {
                        rule_id: "gh-write-unauthorized-target".to_string(),
                        fix,
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

        // Pre-filter on a folded copy, then judge the ORIGINAL text below. A
        // lowercase-only `contains` here silently defeated the folded verb
        // patterns and `token_is_gh` — the fast path returned Allow on `GH pr
        // create` before either ran (cadence-hooks#488). The fold stops at this
        // filter: nouns, subcommand verbs, flags, and `-R owner/repo` operands
        // are all still matched case-sensitively downstream.
        // Nor may it be stricter than the shell's word building: `$'\x67h'`
        // and `g''h` run `gh` from text without the substring (#1103).
        if !may_spell_word(command, "gh") {
            return CheckResult::allow();
        }

        // Nesting past what the shell parser is fed is unreadable here, and
        // at ~900 levels it used to overflow the stack and abort — a noisy
        // fail-open (PR #1118 review). Fail closed instead.
        if loop_analysis::group_nesting_depth(command) > loop_analysis::MAX_PARSE_NESTING {
            return CheckResult::block(format!(
                "🚫 git-guardrails: command nests groups more than {} levels deep — \
                 too deep to verify its gh targets\n   \
                 Fix: flatten the command, or run each gh command on its own",
                loop_analysis::MAX_PARSE_NESTING
            ));
        }

        // A word whose brace expansion is past what the tokenizer models is
        // left whole, so the gh invocation it spells (`gh {pr,}{…}… create`)
        // is invisible to every reading below. Refuse rather than judge a
        // command this guard cannot see (cadence-hooks#1115).
        if let Some(segment) = command_segments(command).into_iter().find(|segment| {
            segment.contains('{')
                && contains_ignoring_ascii_case(segment, "gh")
                && brace_expansion_overflows(segment)
        }) {
            let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
            let allowed_repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
            return CheckResult::block_structured(
                format!(
                    "🚫 git-guardrails: gh command uses a brace expansion too large to read\n   \
                     Command: {segment}\n   \
                     Fix: spell the gh command out without the brace expansion"
                ),
                BlockMetadata {
                    rule_id: "gh-write-target-unresolvable".to_string(),
                    fix: "spell the gh command out without the brace expansion".to_string(),
                    allowed_owners: allowed_display_list(&allowed_owners, &allowed_repos),
                    severity: "error",
                },
            );
        }

        let allowed_owners = env_allow_entries("CADENCE_ALLOWED_OWNERS");
        let allowed_repos = env_allow_entries("CADENCE_ALLOWED_REPOS");
        let extra_hosts = env_extra_hosts();

        // AST-based loop detection with regex fallback. A loop needs one of
        // its reserved words spelled out in the text — they cannot come from
        // an expansion — and so does the fallback pattern, so a command with
        // none of them skips the parse: every answer it could give is
        // `NoLoops` or a fallback that does not match.
        static LOOP_WORD: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?:^|[^A-Za-z0-9_])(?:for|while|until|select)(?:[^A-Za-z0-9_]|$)")
                .expect("pattern should compile")
        });
        let may_loop = LOOP_WORD.is_match(command);
        let analysis = if may_loop {
            loop_analysis::analyze_gh_loops(command)
        } else {
            LoopAnalysis::NoLoops
        };
        match analysis {
            LoopAnalysis::AllTargetsExplicit(cmds) => {
                // Only writes are ownership-gated; reads (gh pr view, issue list) are
                // owner-independent and safe against any repo — mirror the MissingTargets
                // branch, which already gates on write kind (#158). -R targets are
                // always on the default host (gh CLI convention).
                for c in &cmds {
                    if let LoopedWriteKind::ApiUnverifiable {
                        undeterminable_query,
                    } = looped_command_kind(c)
                    {
                        return api_unverifiable_block(
                            &format!("gh {}", c.args.join(" ")),
                            undeterminable_query,
                            &allowed_owners,
                            &allowed_repos,
                        );
                    }
                }
                let dh = default_host();
                let unowned_write_targets: Vec<&str> = cmds
                    .iter()
                    .filter(|c| looped_command_kind(c) == LoopedWriteKind::RepoWrite)
                    .filter(|c| {
                        !c.explicit_repo.as_ref().is_some_and(|r| {
                            flag_value_is_owned(r, &dh, &allowed_owners, &allowed_repos)
                        })
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
                for c in &cmds {
                    if let LoopedWriteKind::ApiUnverifiable {
                        undeterminable_query,
                    } = looped_command_kind(c)
                    {
                        return api_unverifiable_block(
                            &format!("gh {}", c.args.join(" ")),
                            undeterminable_query,
                            &allowed_owners,
                            &allowed_repos,
                        );
                    }
                }
                let has_write = cmds
                    .iter()
                    .any(|c| looped_command_kind(c) == LoopedWriteKind::RepoWrite);
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
                                c.explicit_repo.is_none()
                                    && looped_command_kind(c) == LoopedWriteKind::RepoWrite
                            })
                            .map(|c| format!("`gh {}`", c.args.join(" ")))
                            .collect();
                        let fix = match suggestion.as_deref() {
                            Some(s) => format!("-R {s}"),
                            None => "-R <owner>/<repo>".to_string(),
                        };
                        return CheckResult::block_structured(
                            looped_write_block_message(&writes, suggestion.as_deref()),
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
        //
        // Each write is judged in two directories and the sharpest verdict
        // wins: the whole-command `parse_work_dir` one this guard always used,
        // and the one its own segment runs in (`segment_work_dirs`). The
        // whole-command scan cannot see a `cd` on a later line
        // (`echo hi⏎cd <unowned>⏎gh pr create`), after a backgrounded
        // command, or in a `{ …; }` group, and it lets a subshell's `cd`
        // leak into the parent; the per-segment walk follows each of those.
        // Judging both means neither reading can lose a block the other
        // finds (cameronsjo/cadence-hooks#1137).
        let cwd = input.cwd.as_deref().unwrap_or(".");
        let work_dir = parse_work_dir(command, cwd);
        let whole = || {
            let dir: std::rc::Rc<str> = std::rc::Rc::from(work_dir.as_str());
            command_segments(command)
                .into_iter()
                .map(|segment| (segment, dir.clone()))
                .collect()
        };
        let own = || command_segments_with_dirs(command, cwd);
        let mut judged = WriteJudgments::default();
        let readings: [&dyn Fn() -> Reading; 2] = [&whole, &own];
        for reading in readings {
            if let Some(block) = judge_write_segments(
                command,
                reading(),
                &work_dir,
                &allowed_owners,
                &allowed_repos,
                &extra_hosts,
                &mut judged,
            ) {
                return block;
            }
        }

        // No write segments, or every write segment targets an owned repo.
        CheckResult::allow()
    }
}

/// Most distinct directories besides the whole-command one that
/// [`judge_write_segments`] judges writes in. Each costs git probes, and a
/// hook that runs past its deadline fails open, so a flood of `cd`s to
/// distinct directories each followed by a write would otherwise buy an
/// allow. Past the cap the command blocks: no legitimate command writes
/// from this many checkouts at once.
const MAX_SEGMENT_DIRS: usize = 16;

/// One reading of a command: each segment with the directory it is judged in.
type Reading = Vec<(String, std::rc::Rc<str>)>;

/// What [`judge_write_segments`] has already judged across both readings.
#[derive(Default)]
struct WriteJudgments {
    /// (segment, directory, inherited host, inherited repo) already judged.
    seen: std::collections::HashSet<[String; 4]>,
    /// Distinct directories besides the whole-command one judged so far.
    dirs: Vec<std::rc::Rc<str>>,
}

/// The block for a command whose writes run in more than
/// [`MAX_SEGMENT_DIRS`] directories.
fn too_many_dirs_block(
    segment: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
) -> CheckResult {
    CheckResult::block_structured(
        format!(
            "🚫 git-guardrails: gh writes run in more than {MAX_SEGMENT_DIRS} directories\n   \
             Command: {segment}\n   \
             Each directory's repo is looked up to check ownership, and this many cannot be \
             checked in time.\n   \
             Fix: run the gh writes in fewer commands, or name each target with `-R owner/repo`"
        ),
        BlockMetadata {
            rule_id: "gh-write-target-unresolvable".to_string(),
            fix: "run the gh writes in fewer commands".to_string(),
            allowed_owners: allowed_display_list(allowed_owners, allowed_repos),
            severity: "error",
        },
    )
}

/// Judge every write among `segments`, each in the directory paired with it,
/// in order; the first disallowed or unresolvable write blocks.
///
/// `segments` is one reading of `command`: every [`command_segments`] segment
/// in the whole-command directory, or each in the directory its own segment
/// runs in ([`command_segments_with_dirs`]). The `GH_HOST`/`GH_REPO` a write
/// inherits is tracked along the reading's own order.
fn judge_write_segments(
    command: &str,
    segments: Reading,
    whole_dir: &str,
    allowed_owners: &[AllowEntry],
    allowed_repos: &[AllowEntry],
    extra_hosts: &[String],
    judged: &mut WriteJudgments,
) -> Option<CheckResult> {
    let mut gh_host_env = GhHostEnv::for_command(command);
    let mut gh_repo_env = GhHostEnv::for_repo(command);
    // The segment observed last. Observation only ever adds a candidate or
    // sets a flag, so observing the same text again at once changes nothing —
    // and a segment that may run in several directories arrives once per
    // directory, back to back, as does every `f` of an `f; f; …` flood.
    let mut observed: Option<String> = None;
    // `G=gh; $G pr create` runs gh: read a variable command word as the `gh`
    // the same command assigned it. Unreadable or unassigned stays as written.
    let mut word_variables = CommandWordVariables::for_command(command);
    for (segment, dir) in segments {
        let segment = word_variables.resolve_gh(&segment).unwrap_or(segment);
        // Before the gate: an `export GH_HOST=…` segment invokes no gh, but
        // it decides which host every later gh write reaches (#548). A gh
        // segment is a child process and cannot change it.
        // A shell started with `BASH_ENV=`/`ENV=` sources that file first,
        // so anything it runs may inherit a GH_HOST this guard never sees.
        if tokenize(&segment)
            .iter()
            .any(|t| t.starts_with("BASH_ENV=") || t.starts_with("ENV="))
        {
            gh_host_env.add_unresolved();
            gh_repo_env.add_unresolved();
        }
        if !segment_invokes_gh(&segment) {
            if observed.as_deref() != Some(segment.as_str()) {
                gh_host_env.observe_wrapper_prefix(&segment);
                gh_host_env.observe(&segment);
                gh_repo_env.observe_wrapper_prefix(&segment);
                gh_repo_env.observe(&segment);
                observed = Some(segment);
            }
            continue;
        }
        observed = None;

        // The write patterns are raw-text regexes, so the decoded words
        // are judged too: `gh $'issue' create` and `'gh' issue create` run
        // the write while no raw `gh issue create` exists (#1103).
        if !is_write_command(&segment) && !is_write_command(&requote_words(&segment)) {
            continue;
        }

        // Fail-safe: block when unconfigured.
        if allowed_owners.is_empty() {
            return Some(CheckResult::block(crate::messages::NOT_CONFIGURED_MSG));
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
                        return Some(api_unverifiable_block(
                            &segment,
                            status.is_none(),
                            allowed_owners,
                            allowed_repos,
                        ));
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
                return Some(api_unverifiable_block(
                    &segment,
                    false,
                    allowed_owners,
                    allowed_repos,
                ));
            }
            // `repos/<owner>/<repo>` api write — fall through to the
            // existing per-segment ownership check below.
        }

        // Judged once per host gh may have inherited: an earlier export
        // that might not have run (`false && export …`) leaves more than
        // one, and the write must be owned on every one of them (#548).
        // The same for an inherited `GH_REPO` (cadence-hooks#1129).
        if &*dir != whole_dir && !judged.dirs.contains(&dir) {
            if judged.dirs.len() == MAX_SEGMENT_DIRS {
                return Some(too_many_dirs_block(&segment, allowed_owners, allowed_repos));
            }
            judged.dirs.push(dir.clone());
        }
        for env_host in gh_host_env.candidates() {
            for env_repo in gh_repo_env.candidates() {
                // A repeat of a judged (segment, directory, host, repo) can
                // only repeat its verdict; skip its git probes.
                let key = [&segment, &*dir, env_host, env_repo].map(str::to_string);
                if !judged.seen.insert(key) {
                    continue;
                }
                if let Some(block) = judge_write_segment(
                    &segment,
                    &dir,
                    allowed_owners,
                    allowed_repos,
                    extra_hosts,
                    env_host,
                    env_repo,
                ) {
                    return Some(block);
                }
            }
        }
    }
    None
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
    fn token_is_gh_uses_the_shared_command_word() {
        // The spellings the local strip-then-split missed. `/opt/\gh` is the
        // one that changed a verdict: the token went unfound, the target fell
        // back to the cwd remote, and an off-owner write silently ALLOWED
        // (measured ALLOW→BLOCK, #450 review).
        for tok in [
            "gh",
            "/usr/bin/gh",
            "\\gh",
            "/opt/\\gh",
            "gh.exe",
            "C:\\bin\\gh.exe",
        ] {
            assert!(token_is_gh(tok), "should resolve to gh: {tok}");
        }
        for tok in ["ghi", "github", "\\\\gh", "/opt/gh/bin/hub", "ghq"] {
            assert!(!token_is_gh(tok), "should NOT resolve to gh: {tok}");
        }
    }

    #[test]
    fn token_is_gh_folds_ascii_case() {
        // cadence-hooks#488: a case-insensitive volume runs `GH` as `gh`, so
        // the write detector missed every capitalized spelling.
        for tok in ["GH", "Gh", "/usr/bin/GH", "\\GH", "GH.EXE"] {
            assert!(token_is_gh(tok), "should resolve to gh: {tok}");
        }
        for tok in ["GHI", "GITHUB", "\\\\GH", "GHQ"] {
            assert!(!token_is_gh(tok), "should NOT resolve to gh: {tok}");
        }
    }

    #[test]
    fn write_detection_folds_the_gh_verb_only() {
        // `token_is_gh` folding is necessary but NOT sufficient: write
        // detection is a raw-TEXT regex, and its `gh` was a literal lowercase
        // one, so `GH pr create` never reached the ownership decision at all
        // (measured ALLOW against the built binary, cadence-hooks#488).
        assert!(is_write_command("GH pr create --title x"));
        assert!(is_write_command("Gh issue comment 1 --body x"));
        assert!(is_write_command("GH secret set FOO"));
        // Only the VERB folds. gh's own nouns and subcommand verbs stay
        // case-SENSITIVE because gh itself rejects them capitalized — folding
        // the whole pattern would match text the shell could never run, which
        // is the #489 mistake in regex form.
        assert!(!is_write_command("gh PR CREATE --title x"));
        assert!(!is_write_command("gh pr CREATE --title x"));
        // Longer words starting with the verb are still not the verb.
        assert!(!is_write_command("GHQ pr create --title x"));
    }

    #[test]
    fn exe_spelling_is_a_detected_write() {
        // Was a recorded gap (#450): the raw-TEXT regex does not match
        // `gh.exe issue create`. Write detection now also reads the parsed argv
        // (cadence-hooks#1077), where `token_is_gh` resolves `gh.exe`.
        assert!(is_write_command("gh.exe issue create --title x"));
        assert!(is_write_command("gh issue create --title x"));
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            assert!(is_allowed(
                "github.com",
                "cameronsjo/repo",
                &owners(&["cameronsjo"]),
                &[],
            ));
        });
    }

    #[test]
    fn is_allowed_by_repo() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            assert!(is_allowed(
                "github.com",
                "other/repo",
                &[],
                &owners(&["other/repo"]),
            ));
        });
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
    }

    #[test]
    fn fork_extra_hosts_allowed() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            assert!(is_allowed(
                "github.com",
                "external/specific-repo",
                &[],
                &owners(&["external/specific-repo"]),
            ));
        });
    }

    #[test]
    fn is_allowed_owner_and_repo() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            // Both match — should still return true
            assert!(is_allowed(
                "github.com",
                "cameronsjo/repo",
                &owners(&["cameronsjo"]),
                &owners(&["cameronsjo/repo"]),
            ));
        });
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
    }

    #[test]
    fn strict_toggle_blocks_with_suggestion() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
    }

    #[test]
    fn relaxed_cd_in_body_blocks_with_suggestion() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
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
        });
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
    fn looped_write_block_message_includes_suggestion() {
        let writes = vec!["`gh issue close $i`".to_string()];
        let msg = looped_write_block_message(&writes, Some("cameronsjo/cadence-hooks"));
        assert!(msg.contains("-R cameronsjo/cadence-hooks"));
        assert!(msg.contains("`gh issue close $i`"));
    }

    #[test]
    fn looped_write_block_message_generic_without_suggestion() {
        let writes = vec!["`gh pr create`".to_string()];
        let msg = looped_write_block_message(&writes, None);
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
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            let o = owners(&["cameron"]);
            let msg = disallowed_message("git.sjo.lol", "stranger/repo", &o, &[], &[]);
            assert!(msg.contains("CADENCE_EXTRA_HOSTS=git.sjo.lol"));
            assert!(msg.contains("git.sjo.lol/stranger/repo"));
        });
    }

    #[test]
    fn disallowed_message_no_hint_for_default_host() {
        // GH_HOST moves the default host; read it under the env lock so a
        // concurrent GH_HOST mutator cannot change it mid-test (#938).
        with_env(&[("GH_HOST", None)], || {
            let o = owners(&["cameronsjo"]);
            let msg = disallowed_message("github.com", "stranger/repo", &o, &[], &[]);
            assert!(!msg.contains("Host scope"));
            assert!(msg.contains("stranger/repo"));
            assert!(msg.contains("cameronsjo"));
        });
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
                    looped_write_kind(&reconstructed) == LoopedWriteKind::RepoWrite
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
                    looped_write_kind(&reconstructed) == LoopedWriteKind::RepoWrite
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
                    looped_write_kind(&reconstructed) == LoopedWriteKind::RepoWrite
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
    fn api_method_read_from_the_flag_stream_decides_the_write() {
        // cadence-hooks#1139: every BLOCK row was ALLOW on main — the attached
        // spellings and a method built by the shell read as a GET, so the
        // unowned target was never judged.
        with_env(
            &[
                ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", None),
            ],
            || {
                use cadence_hooks_core::Outcome::{Allow, Block};
                for (command, want) in [
                    ("gh api -X $(echo DELETE) repos/someoneelse/r", Block),
                    ("gh api --method `echo PUT x` repos/someoneelse/r", Block),
                    ("gh api -X \"$M\" repos/someoneelse/r", Block),
                    ("gh api -X ${M} repos/someoneelse/r", Block),
                    ("gh api --method=$(echo DELETE) repos/someoneelse/r", Block),
                    ("gh api -X$(echo DELETE) repos/someoneelse/r", Block),
                    ("gh api -X DEL$(echo ETE) repos/someoneelse/r", Block),
                    ("gh api -XDELETE repos/someoneelse/r", Block),
                    ("gh api -XPUT repos/someoneelse/r/topics", Block),
                    ("gh api --method=DELETE repos/someoneelse/r", Block),
                    ("gh api -XGET -XDELETE repos/someoneelse/r", Block),
                    // Controls: an owned target, and reads.
                    ("gh api -X $(echo DELETE) repos/cameronsjo/r", Allow),
                    ("gh api -XDELETE repos/cameronsjo/r", Allow),
                    ("gh api repos/someoneelse/r", Allow),
                    ("gh api -X GET repos/someoneelse/r", Allow),
                    ("gh api -XGET repos/someoneelse/r", Allow),
                    ("gh api --method=GET repos/someoneelse/r", Allow),
                    ("gh api -X HEAD repos/someoneelse/r", Allow),
                    ("gh api --jq .x repos/someoneelse/r", Allow),
                ] {
                    let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                    assert_eq!(result.outcome, want, "{command}");
                }
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

    #[test]
    fn case_folded_gh_write_blocked_end_to_end() {
        // The unit-level `is_write_command` / `token_is_gh` folds are not
        // enough on their own: this guard opens with a `contains("gh")` fast
        // path, and while that was lowercase-only it returned Allow on `GH pr
        // create` before either fold could run (cadence-hooks#488, measured
        // ALLOW against the built binary even with both unit tests green).
        // Asserting through `run` is what makes the pre-filter part of the
        // contract instead of an invisible upstream veto.
        with_env(&owners_env_212(), || {
            for cmd in [
                "GH repo create evil/x --public",
                "Gh repo create evil/x --public",
                "/usr/bin/GH repo create evil/x --public",
            ] {
                let result = GhWriteGuard.run(&input_with(cmd, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{cmd}"
                );
            }
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

    fn owners_env_212() -> [(&'static str, Option<&'static str>); 5] {
        [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            // GH_HOST moves the default host a bare allowlist entry matches,
            // so pin it under the same lock as the rest (#938).
            ("GH_HOST", None),
            // An inherited GH_REPO retargets every un-flagged write (#1129).
            ("GH_REPO", None),
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

    fn owners_env() -> [(&'static str, Option<&'static str>); 5] {
        [
            ("CADENCE_ALLOWED_OWNERS", Some("cameronsjo")),
            ("CADENCE_ALLOWED_REPOS", None),
            ("CADENCE_EXTRA_HOSTS", None),
            // GH_HOST moves the default host a bare allowlist entry matches,
            // so pin it under the same lock as the rest (#938).
            ("GH_HOST", None),
            // An inherited GH_REPO retargets every un-flagged write (#1129).
            ("GH_REPO", None),
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
    fn repoless_endpoint_write_blocks_without_the_unsatisfiable_repos_hint() {
        // #971: `/markdown` has no owner, so the `repos/<owner>/<repo>` fix can
        // never apply. The write still blocks; only the wording changes.
        with_env(&owners_env(), || {
            for command in [
                "gh api /markdown --input /tmp/notes.md",
                "gh api markdown/raw -X POST --input notes.md",
                "gh api rate_limit -f x=1",
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "still blocks: {command}"
                );
                let msg = result.message.clone().unwrap_or_default();
                assert!(msg.contains("no owner or repo"), "{command}: {msg}");
                assert!(!msg.contains("use `gh api repos/"), "{command}: {msg}");
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
                assert!(!meta.fix.contains("use gh api repos/"), "{}", meta.fix);
            }
            // An owner-scoped non-repo endpoint keeps the generic wording.
            let result = GhWriteGuard.run(&input_with("gh api orgs/acme/teams -X POST", "/tmp"));
            let msg = result.message.clone().unwrap_or_default();
            assert!(msg.contains("use `gh api repos/"), "{msg}");
            // A repo named `markdown` is not the endpoint.
            assert_eq!(
                repoless_api_root("gh api repos/evil/markdown -X POST"),
                None
            );
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
    fn api_hostname_flag_is_part_of_ownership_resolution() {
        with_env(&owners_env(), || {
            for command in [
                "gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f title=t",
                "gh api --hostname=evil.example.com repos/cameronsjo/x -X POST -f title=t",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    #[test]
    fn inline_gh_host_is_part_of_ownership_resolution() {
        with_env(&owners_env(), || {
            let input = input_with(
                "GH_HOST=evil.example.com gh api repos/cameronsjo/x -X POST -f title=t",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn hostname_flag_overrides_inline_gh_host() {
        with_env(&owners_env(), || {
            let input = input_with(
                "GH_HOST=github.com gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f title=t",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn explicitly_allowed_host_and_owner_still_allow() {
        with_env(
            &[
                (
                    "CADENCE_ALLOWED_OWNERS",
                    Some("evil.example.com/cameronsjo"),
                ),
                ("CADENCE_ALLOWED_REPOS", None),
                ("CADENCE_EXTRA_HOSTS", Some("evil.example.com")),
            ],
            || {
                let input = input_with(
                    "gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f title=t",
                    "/tmp",
                );
                let result = GhWriteGuard.run(&input);
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
            },
        );
    }

    #[test]
    fn eval_wrapped_hostname_is_part_of_ownership_resolution() {
        with_env(&owners_env(), || {
            let input = input_with(
                r#"eval "gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f title=t""#,
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-unauthorized-target");
        });
    }

    #[test]
    fn command_host_comparison_folds_ascii_case() {
        with_env(&owners_env(), || {
            for command in [
                "GH_HOST=GitHub.com gh api repos/cameronsjo/x -X POST -f title=t",
                "gh api --hostname GitHub.com repos/cameronsjo/x -X POST -f title=t",
                "GH_HOST=GitHub.com gh repo create x --public",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn flag_value_cannot_pose_as_hostname_selector() {
        with_env(&owners_env(), || {
            let input = input_with(
                "gh api repos/cameronsjo/x -X POST --jq --hostname --template '{{.x}}'",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn boolean_short_sharing_an_api_letter_cannot_swallow_hostname() {
        // #532 review repro. `gh api`'s shorthand table was applied to EVERY
        // subcommand, so a boolean short that merely shares a letter with a
        // value-taking `gh api` one skipped the following token. Both of these
        // are booleans in their own subcommand (gh 2.96.0 `--help`): `pr create
        // -f` is `--fill`, `release create -p` is `--prerelease`. gh therefore
        // reads the `--hostname` that follows and sends the write to
        // evil.example.com — while the guard, having skipped it, resolved the
        // assumed-owned default host and ALLOWED.
        with_env(&owners_env(), || {
            for command in [
                "gh pr create -R cameronsjo/x -f --hostname evil.example.com --title t --body b",
                "gh release create v1 -R cameronsjo/x -p --hostname evil.example.com --title t",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn boolean_long_ending_in_an_api_value_letter_cannot_swallow_hostname() {
        // #532 second review repro. The host scan fell from the long-flag table
        // straight into the shorthand arm, where `strip_prefix('-')` leaves
        // `--silent` as the cluster `-silent`. Its LAST letter `t` is a value
        // shorthand in `gh api`, so the boolean skipped the following token —
        // the real `--hostname`. gh sends the write to evil.example.com while
        // the guard resolves the assumed-owned default and ALLOWS. `--silent`
        // and `--slurp` are booleans in gh 2.96.0's own `gh api --help`
        // (`--silent  Do not print the response body`); their trailing `t`/`p`
        // are the whole cause, and `--silent` on a write is routine.
        with_env(&owners_env(), || {
            for command in [
                "gh api --silent --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api --slurp --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api --silent --hostname=evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api --slurp --hostname=evil.example.com repos/cameronsjo/x -X POST -f a=b",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    #[test]
    fn api_hostname_resolves_after_every_boolean_spelling() {
        // Controls isolating the cause to the trailing letter rather than to
        // long flags generally. `--paginate` and `--verbose` end in `e` and
        // always resolved; `-i` is `gh api`'s sole boolean shorthand; the bare
        // form has no preceding flag at all. All must still reach the host.
        with_env(&owners_env(), || {
            for command in [
                "gh api --paginate --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api --verbose --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api -i --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
                "gh api --hostname evil.example.com repos/cameronsjo/x -X POST -f a=b",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    #[test]
    fn api_value_taking_longs_still_skip_their_values() {
        // The other half of the control: short-circuiting `--` must not cost
        // the table its value-taking longs. Each carries a literal
        // `--hostname` as its value, so a scanner that stopped stepping over
        // it would read a host and false-block. All resolve the owned default
        // and allow. The `=` spelling carries its value inline, so the token
        // after it is a real flag — and there the guard must NOT step over it.
        with_env(&owners_env(), || {
            for command in [
                "gh api repos/cameronsjo/x -X POST --jq --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST --template --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST --header --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST --cache --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST --field --hostname -f a=b",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn inline_long_value_does_not_hide_the_hostname_that_follows() {
        // `--jq=.x` carries its value inline, so the NEXT token is a real flag.
        // A stride that skipped one anyway would swallow the `--hostname` and
        // fail open exactly as the cluster misread did.
        with_env(&owners_env(), || {
            for command in [
                "gh api repos/cameronsjo/x -X POST --jq=.x --hostname evil.example.com -f a=b",
                "gh api repos/cameronsjo/x -X POST --template={{.x}} --hostname evil.example.com -f a=b",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    #[test]
    fn api_value_taking_shorts_still_skip_their_values() {
        // The control on the gate: `api` genuinely has that grammar, so every
        // value-taking shorthand must still step over its value rather than
        // let it read as a host. Each command carries the flag under test with
        // a literal `--hostname` as its value; all must resolve the owned
        // default host and allow.
        with_env(&owners_env(), || {
            for command in [
                "gh api repos/cameronsjo/x -X POST -F --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST -f --hostname -F a=b",
                "gh api repos/cameronsjo/x -X POST -H --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST -q --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST -t --hostname -f a=b",
                "gh api repos/cameronsjo/x -X POST -p --hostname -f a=b",
                "gh api repos/cameronsjo/x -f a=b -X --hostname",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn owned_default_host_without_hostname_flag_still_allows() {
        // The no-table default must not manufacture a host out of ordinary
        // write flags — including the very shorts the gate stopped skipping.
        with_env(&owners_env(), || {
            for command in [
                "gh pr create -R cameronsjo/x -f",
                "gh pr create -R cameronsjo/x --title t --body b",
                "gh release create v1 -R cameronsjo/x -p --title t",
                "gh issue create -R cameronsjo/x --title t --body b",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn non_api_hostname_resolves_in_both_spellings() {
        // Separate and equals forms, on subcommands the api table never
        // described — the resolution the gate must preserve.
        with_env(&owners_env(), || {
            for command in [
                "gh pr create -R cameronsjo/x --hostname evil.example.com --title t",
                "gh pr create -R cameronsjo/x --hostname=evil.example.com --title t",
                "gh release create v1 -R cameronsjo/x --hostname evil.example.com",
                "gh issue create -R cameronsjo/x --hostname=evil.example.com --title t",
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                let meta = result.block_metadata.expect("structured block");
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    #[test]
    fn quoted_prose_cannot_pose_as_a_hostname_selector() {
        // Tokenization is quote-aware, so a `--body`/`--title` value carrying
        // the SEPARATE spelling is ONE token equalling neither `--hostname`
        // nor a `--hostname=` prefix. This is what lets the no-table default
        // skip nothing without false-blocking prose.
        with_env(&owners_env(), || {
            for command in [
                r#"gh pr create -R cameronsjo/x --title t --body "--hostname evil.example.com""#,
                r#"gh issue create -R cameronsjo/x --body b --title "see --hostname evil.example.com""#,
            ] {
                let input = input_with(command, "/tmp");
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    #[test]
    fn equals_form_as_a_flag_value_fails_closed() {
        // The residual cost of skipping nothing, recorded rather than wished
        // away. `tokenize` strips quotes, so a value that is EXACTLY
        // `--hostname=<host>` is indistinguishable from the flag itself, and
        // without a table for this subcommand the guard will not guess that
        // `--title` consumed it. gh reads it as the title; the guard reads a
        // host and blocks. That is the FAIL-CLOSED direction — a false block on
        // a contrived title, never a write let through to an unnamed forge —
        // and it is the direction the no-table default is chosen for.
        with_env(&owners_env(), || {
            let input = input_with(
                "gh issue create -R cameronsjo/x --title --hostname=evil.example.com --body b",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
        });
    }

    #[test]
    fn inline_gh_host_assignment_is_not_trusted() {
        // The process-`GH_HOST` half of this check lives in
        // `tests/gh_host_env.rs`, in a child process. Setting `GH_HOST` here
        // raced every unit test that reads `default_host()` without the env
        // lock, and flipped their bare-owner verdicts mid-run.
        with_env(&owners_env(), || {
            let input = input_with(
                "GH_HOST=evil.example.com gh pr create -R cameronsjo/x -f --title t",
                "/tmp",
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
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
        // Non-api gh writes keep the cwd-remote fallback. Use a hermetic
        // GitHub origin rather than inheriting the enclosing clone's remote.
        with_env(&owners_env(), || {
            let repo = crate::github_origin_repo();
            let input = input_with("gh pr create --title hi", &repo.path().to_string_lossy());
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn substituted_repo_flag_in_an_owned_checkout_does_not_fall_back_to_the_cwd() {
        // cadence-hooks#1106: the tokenizer keeps `$(cat target)` whole, so the
        // value carries a blank. Dropping blank-bearing values as prose fell
        // back to the owned cwd repo and allowed a write whose target only the
        // shell knows. The quoted spelling had the same hole already.
        with_env(&owners_env(), || {
            let repo = crate::github_origin_repo();
            for command in [
                "gh issue close 1 -R $(cat target)",
                "gh issue close 1 -R `cat target`",
                "gh issue close 1 -R \"$(cat target)\"",
                "gh issue close 1 --repo=$(cat t x)",
            ] {
                let input = input_with(command, &repo.path().to_string_lossy());
                let result = GhWriteGuard.run(&input);
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{command}"
                );
            }
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
    fn looped_graphql_mutation_uses_api_unverifiable_verdict() {
        with_env(&owners_env(), || {
            let input = input_with(
                "for n in 1 2; do gh api graphql -f query=mutation{x}; done",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
            assert!(
                !result
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains("missing explicit repo"))
            );
        });
    }

    #[test]
    fn looped_graphql_read_stays_allowed() {
        with_env(&owners_env(), || {
            let input = input_with(
                "for n in 1 2; do gh api graphql -f query=query{viewer{login}}; done",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    #[test]
    fn looped_non_repo_api_field_write_uses_api_unverifiable_verdict() {
        with_env(&owners_env(), || {
            let input = input_with(
                "for n in 1 2; do gh api orgs/evil/repos -f name=x; done",
                OWNED_DIR,
            );
            let result = GhWriteGuard.run(&input);
            let meta = result.block_metadata.expect("structured block");
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        });
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
    fn repeated_repo_flags_resolve_last_wins_only_when_certain() {
        // Was `disagreeing_repo_flags_block`. Taking the last reading is
        // exploitable only when that reading may be another flag's VALUE. A
        // reading after a positional or an attached value cannot be, so certain
        // readings resolve last-wins exactly as pflag does (#1128 review); an
        // uncertain one after the last certain one still fails closed.
        with_env(&owners_env(), || {
            for (command, rule) in [
                (
                    "gh issue comment 42 -R cameronsjo/allowed -R evil/target --body x",
                    Some("gh-write-unauthorized-target"),
                ),
                (
                    "gh issue comment 42 -R evil/target -R cameronsjo/allowed --body x",
                    None,
                ),
                (
                    "gh issue comment 42 -R evil/target --body -Rcameronsjo/allowed",
                    Some("gh-write-target-unresolvable"),
                ),
            ] {
                let result = GhWriteGuard.run(&input_with(command, OWNED_DIR));
                let got = result.block_metadata.map(|meta| meta.rule_id);
                assert_eq!(got.as_deref(), rule, "{command}");
            }
        });
    }

    #[test]
    fn certain_readings_resolve_last_wins_across_all_four_spellings() {
        // Every form gh accepts is READ, and certain readings resolve last-wins.
        for command in [
            "gh pr create -R a/first --repo b/second",
            "gh pr create --repo=a/first -Rb/second",
            "gh pr create -Ra/first --repo=b/second",
        ] {
            assert_eq!(
                repo_flag(command),
                RepoFlag::Target("b/second".to_string()),
                "{command}"
            );
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

    // --- #756: account-scoped `gh api` writes name a form that works ---

    fn block_in_tmp(command: &str) -> (String, BlockMetadata) {
        let mut out = None;
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(command, "/tmp"));
            assert!(
                matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                "expected BLOCK: {command}"
            );
            let meta = result
                .block_metadata
                .unwrap_or_else(|| panic!("expected a structured block: {command}"));
            out = Some((result.message.unwrap_or_default(), meta));
        });
        out.expect("closure ran")
    }

    #[test]
    fn account_scoped_api_write_names_the_first_class_command() {
        for (command, expected) in [
            ("gh api -X DELETE user/keys/147472709", "gh ssh-key delete"),
            ("gh api -X DELETE /user/gpg_keys/12", "gh gpg-key delete"),
        ] {
            let (message, meta) = block_in_tmp(command);
            assert_eq!(meta.rule_id, "gh-write-api-unverifiable", "{command}");
            assert!(meta.fix.contains(expected), "fix: {}", meta.fix);
            assert!(message.contains(expected), "message: {message}");
            // The dead-end advice must be gone: no repos form exists here.
            assert!(
                !message.contains("use `gh api repos/"),
                "message: {message}"
            );
        }
    }

    #[test]
    fn unmapped_account_scoped_api_write_asks_the_user() {
        let (message, meta) = block_in_tmp("gh api -X POST user/emails -f email=a@b.c");
        assert_eq!(meta.rule_id, "gh-write-api-unverifiable");
        assert!(meta.fix.contains("ask the user"), "fix: {}", meta.fix);
        assert!(!message.contains("gh ssh-key"), "message: {message}");
        assert!(
            !message.contains("use `gh api repos/"),
            "message: {message}"
        );
    }

    #[test]
    fn non_user_unverifiable_api_write_keeps_the_repos_hint() {
        // `users/<name>` and `orgs/…` are not the caller's account; the
        // generic wording stands for them.
        for command in [
            "gh api -X POST orgs/evil/repos -f name=x",
            "gh api -X PUT users/someone/following",
        ] {
            let (message, _) = block_in_tmp(command);
            assert!(
                message.contains("use `gh api repos/"),
                "{command}: {message}"
            );
        }
    }

    // --- #757: an unexpanded `--repo` value is unresolvable, not unowned ---

    #[test]
    fn unexpanded_repo_flag_blocks_without_grafting_an_owner() {
        for command in [
            r#"gh issue comment "$2" --repo "$1" --body-file "$3""#,
            r#"gh pr create -R "${TARGET}" --title t"#,
            "gh issue close 1 -R `cat target`",
        ] {
            let (message, meta) = block_in_tmp(command);
            assert_eq!(meta.rule_id, "gh-write-target-unresolvable", "{command}");
            assert!(!meta.fix.contains("cameronsjo/"), "fix: {}", meta.fix);
            assert!(!message.contains("don't own"), "message: {message}");
            assert!(
                message.contains("literal `-R owner/repo`"),
                "message: {message}"
            );
        }
    }

    #[test]
    fn expansion_under_a_literal_owned_owner_is_still_judged_by_owner() {
        // The owner is spelled out and owned, so the verdict is unchanged.
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(
                r#"gh issue comment 1 --repo cameronsjo/"$1" --body x"#,
                "/tmp",
            ));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    // --- #1032: the fork block offers `-R` only for an owned remote ---

    #[test]
    fn fork_message_does_not_offer_an_unowned_upstream() {
        let message = fork_block_message(
            ("github.com", "cameronsjo/x", true),
            ("github.com", "other/x", false),
        );
        assert!(message.contains("Use -R cameronsjo/x to target your fork"));
        assert!(!message.contains("Use -R other/x"), "{message}");
        assert!(message.contains("run themselves"), "{message}");
    }

    #[test]
    fn fork_message_offers_whichever_remote_is_owned() {
        let message = fork_block_message(
            ("github.com", "other/x", false),
            ("github.com", "cameronsjo/x", true),
        );
        assert!(message.contains("Use -R cameronsjo/x to target upstream"));
        assert!(!message.contains("Use -R other/x"), "{message}");
        let unparsed = fork_block_message(("", "", false), ("github.com", "other/x", false));
        assert!(!unparsed.contains("Use -R"), "{unparsed}");
        assert!(unparsed.contains("could not be parsed"), "{unparsed}");
    }

    #[test]
    fn fork_block_from_a_real_checkout_omits_the_unowned_upstream_fix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .output()
                .expect("git runs")
                .status;
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/cameronsjo/x.git",
        ]);
        git(&[
            "remote",
            "add",
            "upstream",
            "https://github.com/other/x.git",
        ]);
        let cwd = dir.path().to_str().expect("utf-8 path");
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with("gh pr create --title t", cwd));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let message = result.message.unwrap_or_default();
            assert!(message.contains("Write operation in a fork"), "{message}");
            assert!(message.contains("Use -R cameronsjo/x"), "{message}");
            assert!(!message.contains("Use -R other/x"), "{message}");
        });
    }

    // --- #868: a `--help` token never makes a gh write a read ---

    #[test]
    fn help_does_not_cover_a_real_write_beside_it() {
        with_env(&owners_env(), || {
            for command in [
                "for i in 1 2; do gh issue create --title x; done",
                "for i in 1 2; do gh issue create --help; gh issue create --title x; done",
                "gh issue create --help; gh issue create --title x",
                "for i in 1 2; do gh issue create --title --help; done",
                "gh issue create --title --help",
                // #868 review C1: xargs appends stdin after the help token, and
                // pflag's last `--help=false` wins.
                "echo --help=false --title t | xargs gh issue create --help",
                "xargs -a /tmp/args gh issue create --help",
                "for i in 1 2; do echo --help=false --title t | xargs gh issue create --help; done",
                // Any wrapper, and any pipe right-hand side, is refused.
                "echo x | gh issue create --help",
                "env gh issue create --help",
                "find . -exec gh issue create --help ;",
                // #868 review C2: `-h` is `--homepage` for `gh repo edit`.
                "gh repo edit -h -h",
                "for i in 1 2; do gh repo edit -h -h; done",
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "expected BLOCK: {command}"
                );
            }
        });
    }

    // --- #548: an exported GH_HOST reaches gh ---

    #[test]
    fn exported_gh_host_is_judged_as_the_write_host() {
        with_env(&owners_env(), || {
            for command in [
                "export GH_HOST=evil.example.com && gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=evil.example.com && gh api repos/cameronsjo/x -X POST -f a=b",
                "export GH_HOST=evil.example.com; gh release create v1 -R cameronsjo/x",
                "cd /tmp && export GH_HOST=evil.example.com && gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=evil.example.com; for i in 1 2; do gh issue create -R cameronsjo/x --title t; done",
                "if true; then export GH_HOST=evil.example.com; fi; gh pr create -R cameronsjo/x --title t",
                "H=evil.example.com; export GH_HOST=$H; gh pr create -R cameronsjo/x --title t",
                "sh -c 'export GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t'",
                // Whether a later reset ran is unknowable, so the export stays a
                // candidate.
                "export GH_HOST=evil.example.com; false && unset GH_HOST; gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=evil.example.com; export GH_HOST=github.com; gh pr create -R cameronsjo/x --title t",
                // Exported, so a later bare assignment reaches gh too.
                "export GH_HOST=a.example; GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "set -a; GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                // `eval` runs its words in this shell.
                "eval 'export GH_HOST=evil.example.com'; gh pr create -R cameronsjo/x --title t",
                "command export GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                // Brace expansion builds the name, and the tokenizer now expands
                // it as bash does (cadence-hooks#1096): `GH_HOS{T,}=x` exports
                // `GH_HOST=x` and `GH_HOS=x`, so the host resolves outright
                // rather than as unknown.
                "export GH_HOS{T,}=evil.example.com; gh pr create -R cameronsjo/x --title t",
                // Locale quoting is a plain string in the C locale, so bash
                // exports `GH_HOST=evil.example.com` here and the tokenizer now
                // reads it that way: the host resolves outright.
                r#"export GH_HOS$"T"=evil.example.com; gh pr create -R cameronsjo/x --title t"#,
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                let meta = result
                    .block_metadata
                    .unwrap_or_else(|| panic!("expected a structured block: {command}"));
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    /// cadence-hooks#1129: a `GH_REPO` exported earlier in the command — or set
    /// on a wrapper whose child runs gh — retargets an un-flagged write the
    /// same way the inline `GH_REPO=` prefix does. Every row runs from an owned
    /// checkout: `(command, blocks?)`.
    #[test]
    fn exported_gh_repo_is_judged_like_an_inline_one() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let cwd = owned.path().to_string_lossy().to_string();
        with_env(&owners_env(), || {
            for (command, blocks) in [
                ("export GH_REPO=evil/x; gh issue create -t t -b b", true),
                ("export GH_REPO=evil/x && gh issue create -t t -b b", true),
                ("declare -x GH_REPO=evil/x; gh issue create -t t -b b", true),
                ("set -a; GH_REPO=evil/x; gh issue create -t t -b b", true),
                (
                    "GH_REPO=evil/x; export GH_REPO; gh issue create -t t -b b",
                    true,
                ),
                (
                    "eval 'export GH_REPO=evil/x'; gh issue create -t t -b b",
                    true,
                ),
                ("export GH_REP${X}O=evil/x; gh issue create -t t -b b", true),
                ("export GH_REPO=$R; gh issue create -t t -b b", true),
                ("GH_REPO=evil/x bash -c 'gh issue create -t t -b b'", true),
                ("env GH_REPO=evil/x sh -c 'gh pr create -t t -b b'", true),
                // The set only grows: a later `unset` may not have run.
                (
                    "export GH_REPO=evil/x; unset GH_REPO; gh issue create -t t -b b",
                    true,
                ),
                // Controls. An owned value, a flag that outranks the variable,
                // a bare assignment never exported, and a read.
                (
                    "export GH_REPO=cameronsjo/x; gh issue create -t t -b b",
                    false,
                ),
                (
                    "export GH_REPO=evil/x; gh issue create -R cameronsjo/x -t t -b b",
                    false,
                ),
                ("GH_REPO=evil/x; gh issue create -t t -b b", false),
                ("export GH_REPO=evil/x; gh pr view 5", false),
                ("gh issue create -t t -b b", false),
            ] {
                let result = GhWriteGuard.run(&input_with(command, &cwd));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{command}: {:?}",
                    result.message
                );
            }
        });
    }

    /// A hermetic checkout whose `origin` is `url`.
    fn origin_checkout(url: &str) -> tempfile::TempDir {
        let repo = tempfile::tempdir().expect("create git fixture");
        cadence_hooks_core::git_fixtures::init_repo(repo.path());
        cadence_hooks_core::git_fixtures::git_in(repo.path(), &["remote", "add", "origin", url]);
        repo
    }

    /// How gh's target repo is read (cadence-hooks#1077, #1069, #937, #1115):
    /// every row is `(command, run from the owned checkout?, blocks?)`.
    #[test]
    fn gh_target_repo_is_read_with_gh_grammar() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        with_env(&owners_env(), || {
            for (command, in_owned, blocks) in [
                // #1077 4a: `-R` before the group, or between group and verb.
                ("gh -R evil/x issue create --title x", true, true),
                ("gh --repo evil/x issue create --title x", true, true),
                ("gh --repo=evil/x pr create --title x", true, true),
                ("gh -Revil/x pr create --title x", true, true),
                ("gh pr -R evil/x create --title x", true, true),
                // #996: gh's cobra aliases write exactly as their verbs do.
                ("gh pr new -R evil/x -t a -b b", true, true),
                ("gh pr new -t a -b b", false, true),
                ("gh pr new -R cameronsjo/x -t a -b b", true, false),
                ("gh pr -R evil/x new -t a", true, true),
                ("gh issue new -R evil/x -t a", true, true),
                ("gh repo new evil/y --private", true, true),
                ("gh repo new y --private", true, false),
                ("gh release new v1 -R evil/x", true, true),
                ("gh secret remove X -R evil/x", true, true),
                ("gh variable remove X -R evil/x", true, true),
                ("gh pr ls -R evil/x", true, false),
                ("gh pr co 12 -R evil/x", true, false),
                ("gh -R cameronsjo/y issue create --title x", true, false),
                ("gh -R evil/x issue view 1", true, false),
                // #1077 I3: a GH_HOST on the command that wraps gh.
                (
                    "GH_HOST=evil.com bash -c \"gh pr create -R cameronsjo/x -t t\"",
                    true,
                    true,
                ),
                (
                    "env GH_HOST=evil.com sh -c 'gh pr create -R cameronsjo/x -t t'",
                    true,
                    true,
                ),
                (
                    "GH_HOST=evil.com timeout 5 bash -c 'gh pr create -R cameronsjo/x -t t'",
                    true,
                    true,
                ),
                (
                    "GH_HOST=github.com bash -c 'gh pr create -R cameronsjo/x -t t'",
                    true,
                    false,
                ),
                // #1077 comment: `env -S` runs its string as a command.
                ("env -S 'gh issue create -R evil/x -t a -b b'", true, true),
                (
                    "env --split-string='gh issue create -R evil/x -t a'",
                    true,
                    true,
                ),
                (
                    "env -S 'GH_HOST=evil.com gh issue create -R cameronsjo/x -t a'",
                    true,
                    true,
                ),
                (
                    "env -S 'gh issue create -R cameronsjo/x -t a -b b'",
                    true,
                    false,
                ),
                (
                    "timeout 5 env -S 'gh issue create -R evil/x -t a'",
                    true,
                    true,
                ),
                ("sudo -u gh gh -R evil/x pr create -t t", true, true),
                // #1077 comment + #937: host-qualified and URL values name
                // their own host.
                (
                    "gh issue create -R github.com/cameronsjo/x -t t",
                    true,
                    false,
                ),
                (
                    "gh issue create -R https://github.com/cameronsjo/x -t t",
                    true,
                    false,
                ),
                (
                    "gh issue create -R git@github.com:cameronsjo/x.git -t t",
                    true,
                    false,
                ),
                (
                    "gh issue create -R evil.example/cameronsjo/x -t t",
                    true,
                    true,
                ),
                (
                    "gh issue create -R https://github.com/evil/x -t t",
                    true,
                    true,
                ),
                (
                    "gh issue create -R https://github.com:x@evil.example/cameronsjo/x -t t",
                    true,
                    true,
                ),
                // #1037: gh reads no scp host from this; it goes to evil.example.
                (
                    "gh issue create -R github.com:x@evil.example/cameronsjo/x -t t",
                    true,
                    true,
                ),
                // #937: a value gh would refuse, or that cannot be split
                // exactly as gh does, fails closed.
                ("gh issue create -R cameronsjo -t t", true, true),
                ("gh issue create -R cameronsjo/x/y/z -t t", true, true),
                (
                    "gh issue create -R https://github.com/%63ameronsjo/x -t t",
                    true,
                    true,
                ),
                // #1069: a `-R`-shaped decoy in another flag's value.
                ("gh issue create -t t --body -Rcameronsjo/x", false, true),
                ("gh issue create -t -Rcameronsjo/x -b b", false, true),
                ("gh issue create -R cameronsjo/x -R '' -t t", false, true),
                (
                    "gh issue create -R cameronsjo/x -t t --body 'see -R evil/x'",
                    true,
                    false,
                ),
                (
                    "gh issue create -R evil/x -t t --body 'see -R cameronsjo/x'",
                    true,
                    true,
                ),
                ("gh issue create -R cameronsjo/x -t t", false, false),
                ("gh pr merge --squash -R cameronsjo/x", false, false),
                // #1128 review: pflag hands `--` to a value-taking flag, so
                // it ends the flags only when no flag before it can take it.
                ("gh issue create -b -- -R stranger/y -t t", true, true),
                ("gh issue create --title -- -R stranger/y", true, true),
                ("gh issue create -t -- --repo stranger/y", true, true),
                ("gh pr merge 5 --body -- -R stranger/y", true, true),
                (
                    "gh -R cameronsjo/x issue create -b -- -R stranger/y",
                    false,
                    true,
                ),
                (
                    "gh -R cameronsjo/x issue create -b -- -R stranger/y",
                    true,
                    true,
                ),
                (
                    "gh issue create -R cameronsjo/x -t t -- -R stranger/y",
                    false,
                    false,
                ),
                // Certain readings resolve last-wins, as pflag does.
                (
                    "gh issue create -R stranger/y -R cameronsjo/x -t t",
                    false,
                    false,
                ),
                (
                    "gh issue create -R cameronsjo/x -R stranger/y -t t",
                    true,
                    true,
                ),
                // #1115: the brace-expanded argv is what runs.
                ("gh {pr,} create -R evil/x -t t", true, true),
                ("{gh,} pr create -R evil/x -t t", true, true),
                ("gh pr {create,} -R evil/x -t t", true, true),
                ("gh {pr,} view 1 -R evil/x", true, false),
                // An inline GH_REPO is where gh goes when `-R` is absent.
                ("GH_REPO=evil/x gh issue create -t t", true, true),
                ("GH_REPO=cameronsjo/y gh issue create -t t", true, false),
                // Loops judge a URL-shaped explicit target by what it names.
                (
                    "for i in 1 2; do gh issue comment $i -R https://github.com/cameronsjo/x -b b; done",
                    true,
                    false,
                ),
                (
                    "for i in 1 2; do gh issue comment $i -R https://github.com/evil/x -b b; done",
                    true,
                    true,
                ),
            ] {
                let cwd = if in_owned {
                    owned.path()
                } else {
                    unowned.path()
                };
                let result = GhWriteGuard.run(&input_with(command, cwd.to_str().unwrap()));
                let blocked = matches!(result.outcome, cadence_hooks_core::Outcome::Block);
                assert_eq!(blocked, blocks, "{command}: {:?}", result.message);
            }
        });
    }

    #[test]
    fn a_gh_segment_with_an_unreadable_brace_expansion_blocks() {
        with_env(&owners_env(), || {
            let command = format!("gh {}pr create -R cameronsjo/x -t t", "{a,b}".repeat(65));
            let result = GhWriteGuard.run(&input_with(&command, OWNED_DIR));
            assert!(result.block_metadata.is_some(), "expected a block");
            // A flood elsewhere in the command does not touch a gh read.
            let command = format!("echo {}; gh pr view 1", "{a,b}".repeat(65));
            let result = GhWriteGuard.run(&input_with(&command, OWNED_DIR));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Allow));
        });
    }

    /// The per-owner guard's perf bound on the new argv readings.
    #[test]
    fn adversarial_repo_flag_floods_stay_fast() {
        with_env(&owners_env(), || {
            for command in [
                format!(
                    "gh issue create{} -R evil/x",
                    " --body -Rcameronsjo/x".repeat(8_000)
                ),
                format!("gh{} issue create -R evil/x", " -R".repeat(60_000)),
                format!("env -S 'gh issue create{}' -R evil/x", " -t".repeat(60_000)),
            ] {
                let started = std::time::Instant::now();
                let result = GhWriteGuard.run(&input_with(&command, "/tmp"));
                assert!(!matches!(
                    result.outcome,
                    cadence_hooks_core::Outcome::Allow
                ));
                assert!(started.elapsed() < std::time::Duration::from_secs(4));
            }
        });
    }

    #[test]
    fn a_brace_flood_before_a_gh_write_still_blocks_promptly() {
        // cadence-hooks#1096 review: a flood of `{1..4096}` words, each
        // re-expanded as the guard re-tokenizes every segment, ran guards past
        // their hook timeouts (a timeout fails open). The thread brace budget
        // bounds the work; the dangerous tail must still block, promptly. The
        // bound is generous for a debug build — release runs in tens of ms.
        with_env(&owners_env(), || {
            let command = format!(
                "{}gh pr create -R evil/x --title t",
                "echo {1..4096}; ".repeat(200 * 64)
            );
            let started = std::time::Instant::now();
            let result = GhWriteGuard.run(&input_with(&command, "/tmp"));
            assert!(result.block_metadata.is_some(), "expected a block");
            assert!(started.elapsed() < std::time::Duration::from_secs(4));
        });
    }

    #[test]
    fn unmodeled_gh_host_changes_resolve_to_an_unknown_host() {
        with_env(&owners_env(), || {
            for command in [
                "export GH_HOST; gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=$UNSET_ELSEWHERE; gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=; gh pr create -R cameronsjo/x --title t",
                "export -n GH_HOST; gh pr create -R cameronsjo/x --title t",
                "declare -x GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                ": ${GH_HOST:=evil.example.com}; gh pr create -R cameronsjo/x --title t",
                "export GH_HOST+=.evil; gh pr create -R cameronsjo/x --title t",
                ": $((GH_HOST=1)); gh pr create -R cameronsjo/x --title t",
                "(( GH_HOST += 1 )); gh pr create -R cameronsjo/x --title t",
                // #548 review I2: a name the shell builds at expansion time.
                "export GH_HOS${X}T=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "export GH_HOS`printf T`=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "declare -x GH_HOS${X}T=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "typeset -x GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "builtin export GH_HOS${X}T=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "env GH_HOS${X}T=evil.example.com gh pr create -R cameronsjo/x --title t",
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                let message = result.message.clone().unwrap_or_default();
                let meta = result
                    .block_metadata
                    .unwrap_or_else(|| panic!("expected a structured block: {command}"));
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
                assert!(message.contains(UNRESOLVED_GH_HOST), "{command}: {message}");
                assert!(meta.fix.contains("--hostname"), "{command}: {}", meta.fix);
            }
        });
    }

    #[test]
    fn gh_host_forms_that_never_reach_gh_are_unchanged() {
        with_env(&owners_env(), || {
            for command in [
                // A bare assignment is a shell variable gh never sees.
                "GH_HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                "export GH_HOST=github.com && gh pr create -R cameronsjo/x --title t",
                // The command's own selection outranks the inherited one.
                "export GH_HOST=evil.example.com && gh pr create --hostname github.com -R cameronsjo/x --title t",
                "export GH_HOST=evil.example.com && GH_HOST=github.com gh pr create -R cameronsjo/x --title t",
                // Reads, and names that merely contain GH_HOST.
                "echo $GH_HOST ${GH_HOST}; gh pr create -R cameronsjo/x --title t",
                "export MY_GH_HOST=evil GH_HOSTNAME=evil; gh pr create -R cameronsjo/x --title t",
                // Scoped to the one non-gh command it prefixes.
                "GH_HOST=evil.example.com make docs; gh pr create -R cameronsjo/x --title t",
                // A read is not a write, whatever the host.
                "export GH_HOST=evil.example.com && gh pr view 1 -R cameronsjo/x",
                // #548 review I1: a mention is only a mention. A gh segment is
                // a child process, and prose names the variable all the time.
                r#"gh pr create -R cameronsjo/x --title "fix GH_HOST export""#,
                r#"gh issue comment 1 -R cameronsjo/x --body "export GH_HOST=evil" && gh pr create -R cameronsjo/x --title t"#,
                "rg GH_HOST && gh pr create -R cameronsjo/x --title t",
                r#"git commit -m "document GH_HOST"; gh pr create -R cameronsjo/x --title t"#,
                "grep -rn 'GH_HOST=' docs; gh pr create -R cameronsjo/x --title t",
                "declare -x OTHER=1; readonly LIMIT=3; gh pr create -R cameronsjo/x --title t",
                "export -p; gh pr create -R cameronsjo/x --title t",
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "expected ALLOW: {command}"
                );
            }
        });
    }

    #[test]
    fn gh_host_env_accumulates_candidates() {
        with_env(&owners_env(), || {
            let mut env = GhHostEnv::from_process();
            assert_eq!(env.candidates(), ["github.com"]);
            env.observe("export GH_HOST=Evil.Example.com");
            assert_eq!(env.candidates(), ["github.com", "evil.example.com"]);
            env.observe("unset GH_HOST");
            assert_eq!(env.candidates(), ["github.com", "evil.example.com"]);
            env.observe("declare -x GH_HOST=x");
            assert_eq!(
                env.candidates(),
                ["github.com", "evil.example.com", UNRESOLVED_GH_HOST]
            );
        });
    }

    #[test]
    fn mentions_gh_host_ignores_reads_and_longer_names() {
        for yes in [
            "GH_HOST",
            "GH_HOST=x",
            "${GH_HOST:=x}",
            "GH_HOST+=x",
            "${GH_HOST=x}",
        ] {
            assert!(mentions_gh_host(yes), "{yes}");
        }
        for no in [
            "$GH_HOST",
            "${GH_HOST}",
            "MY_GH_HOST=x",
            "GH_HOSTNAME",
            "x$GH_HOST/y",
        ] {
            assert!(!mentions_gh_host(no), "{no}");
        }
    }

    #[test]
    fn escaped_gh_host_names_still_block() {
        // #548 review I2. Quote removal turns `GH_\HOST` into `GH_HOST`, as the
        // shell does before `export` reads it — so these resolve either to
        // `evil.example.com` or to the unresolved host. Both block.
        with_env(&owners_env(), || {
            for command in [
                r"export GH_\HOST=evil.example.com; gh pr create -R cameronsjo/x --title t",
                r"export GH_HOS\T=evil.example.com; gh pr create -R cameronsjo/x --title t",
                r#"export "GH_HOST"=evil.example.com; gh pr create -R cameronsjo/x --title t"#,
                r"env GH_\HOST=evil.example.com gh pr create -R cameronsjo/x --title t",
            ] {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                let meta = result
                    .block_metadata
                    .unwrap_or_else(|| panic!("expected a structured block: {command}"));
                assert_eq!(meta.rule_id, "gh-write-unauthorized-target", "{command}");
            }
        });
    }

    // --- #1073 review: help invocations stay writes; GH_HOST edge forms ---

    /// Run one delta case, recording a mismatch instead of panicking so a
    /// test reports every failing case at once.
    fn run_case(bad: &mut Vec<String>, command: &str, block: bool) {
        let mut blocked = false;
        with_env(&owners_env(), || {
            let result = GhWriteGuard.run(&input_with(command, "/tmp"));
            blocked = matches!(result.outcome, cadence_hooks_core::Outcome::Block);
        });
        if blocked != block {
            bad.push(format!("expected block={block}: {command}"));
        }
    }

    #[test]
    fn looped_help_with_a_substitution_or_pipe_blocks() {
        let mut bad = Vec::new();
        run_case(
            &mut bad,
            r#"for i in 1 2; do NAME="$(gh issue create -R evil/x -t t)" gh issue create --help; done"#,
            true,
        );
        run_case(
            &mut bad,
            "for i in 1 2; do echo --help=false | gh issue create --help; done",
            true,
        );
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn help_with_a_substituting_prefix_blocks() {
        let mut bad = Vec::new();
        for command in [
            r#"NAME="$(gh issue create -R evil/x -t t)" gh issue create --help"#,
            "NAME=`gh issue create -R evil/x -t t` gh issue create --help",
            r#"for i in 1; do NAME="$(gh issue create -t t)" gh issue create --help; done"#,
            "NAME=<(gh issue create -t t) gh issue create --help",
        ] {
            run_case(&mut bad, command, true);
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn namerefs_and_indirect_gh_host_names_block() {
        let mut bad = Vec::new();
        for command in [
            "declare -n r=GH_HOST; r=evil.example.com; export GH_HOST; gh pr create -R cameronsjo/x -t t",
            "declare -n r=GH_HOST; r=evil.example.com; gh pr create -R cameronsjo/x -t t",
            "typeset -n r=GH_HOST; r=evil.example.com; export r; gh pr create -R cameronsjo/x -t t",
            "declare X=GH_HOST; declare -n r=$X; export r=evil.example.com; gh pr create -R cameronsjo/x -t t",
            // An owned host exported first, so only the indirect write can
            // make these block.
            "export GH_HOST=github.com; printf -v GH_HOS${X}T evil; gh pr create -R cameronsjo/x -t t",
            "export GH_HOST=github.com; read GH_HOS${X}T <<<evil; gh pr create -R cameronsjo/x -t t",
            "export GH_HOST=github.com; mapfile -t GH_HOS${X}T <<<evil; gh pr create -R cameronsjo/x -t t",
            "export GH_HOST=github.com; getopts ab GH_HOS${X}T; gh pr create -R cameronsjo/x -t t",
            "export GH_HOST=github.com; declare -n r=GH_HOST; r=evil.example.com; gh pr create -R cameronsjo/x -t t",
            "export GH_HOST=github.com; local -n r=GH_HOST; gh pr create -R cameronsjo/x -t t",
            "printf -v GH_HOS${X}T evil; gh pr create -R cameronsjo/x -t t",
            "read GH_HOS${X}T <<<evil; gh pr create -R cameronsjo/x -t t",
            "mapfile -t GH_HOS${X}T <<<evil; gh pr create -R cameronsjo/x -t t",
            "getopts ab GH_HOS${X}T; gh pr create -R cameronsjo/x -t t",
        ] {
            run_case(&mut bad, command, true);
        }
        // A literal, unrelated name is still nothing.
        run_case(
            &mut bad,
            "printf -v OUT '%s' x; read LINE <<<y; read -r -p 'Host name: ' H < /dev/tty; mapfile -t LINES < f; gh pr create -R cameronsjo/x -t t",
            false,
        );
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn eval_past_the_depth_cap_is_unresolved() {
        let mut bad = Vec::new();
        run_case(
            &mut bad,
            r#"eval "eval \"eval \\\"eval export GH_HOST=evil.example.com\\\"\""; gh pr create -R cameronsjo/x -t t"#,
            true,
        );
        run_case(
            &mut bad,
            "eval eval eval eval export GH_HOST=evil.example.com; gh pr create -R cameronsjo/x -t t",
            true,
        );
        run_case(
            &mut bad,
            "eval eval eval eval export GH_HOS${X}T=evil.example.com; gh pr create -R cameronsjo/x -t t",
            true,
        );
        run_case(
            &mut bad,
            "eval eval eval eval eval export GH_HOS${X}T=evil.example.com; gh pr create -R cameronsjo/x -t t",
            true,
        );
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn help_behind_steering_prefixes_or_gh_shadows_blocks() {
        let mut bad = Vec::new();
        for command in [
            "GH_HOST=evil gh issue create --help",
            "GH_PAGER=x gh issue create --help",
            "PAGER=x gh issue create --help",
            "BROWSER=x gh issue create --help",
            "EDITOR=x gh issue create --help",
            "VISUAL=x gh issue create --help",
            "alias gh='gh issue create -t t -b b #'; gh issue create --help",
            "gh() { command gh issue create -t t -b b; }; gh issue create --help",
            "function gh { command gh issue create -t t; }; gh issue create --help",
        ] {
            run_case(&mut bad, command, true);
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn piped_help_blocks_beside_a_bare_one() {
        let mut bad = Vec::new();
        // The same text in a pipe right-hand side must not borrow the
        // top-level segment's exemption.
        run_case(
            &mut bad,
            "gh issue create --help; echo x | gh issue create --help",
            true,
        );
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn gh_host_set_inside_compound_commands_blocks() {
        let mut bad = Vec::new();
        for command in [
            "(export GH_HOST=evil.com; gh issue create -R cameronsjo/x -t a -b b)",
            "( export GH_HOST=evil.com; gh issue create -R cameronsjo/x -t a -b b )",
            "setit(){ export GH_HOST=evil.com; }; setit; gh issue create -R cameronsjo/x -t a -b b",
            "setit() { export GH_HOST=evil.com; }; setit; gh issue create -R cameronsjo/x -t a -b b",
            "function setit { export GH_HOST=evil.com; }; setit; gh issue create -R cameronsjo/x -t a -b b",
            "f(){ local -x GH_HOST=evil.com; gh issue create -R cameronsjo/x -t a -b b; }; f",
            "case x in x) export GH_HOST=evil.com;; esac; gh issue create -R cameronsjo/x -t a -b b",
            "case x in y) true;; x) export GH_HOST=evil.com;; esac; gh issue create -R cameronsjo/x -t a -b b",
            "(export GH_HOS${X}T=evil.com); gh issue create -R cameronsjo/x -t a -b b",
            // #5: a trap body runs later from a string.
            "trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap 'export GH_HOS''T=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            // #6: a heredoc fed to source.
            "source /dev/stdin <<EOF\nexport GH_HOST=evil.com\nEOF\ngh issue create -R cameronsjo/x -t a -b b",
            ". /dev/stdin <<'EOF'\nexport GH_HOS''T=evil.com\nEOF\ngh issue create -R cameronsjo/x -t a -b b",
            "source <(echo export GH_HOST=evil.com); gh issue create -R cameronsjo/x -t a -b b",
            // #7: env -S and a sourced-at-start shell env file.
            "env -S 'GH_HOST=evil.com' gh issue create -R cameronsjo/x -t a -b b",
            "env --split-string='GH_HOST=evil.com' gh issue create -R cameronsjo/x -t a -b b",
            "BASH_ENV=/tmp/e bash -c 'gh issue create -R cameronsjo/x -t a -b b'",
            "ENV=/tmp/e sh -c 'gh issue create -R cameronsjo/x -t a -b b'",
        ] {
            run_case(&mut bad, command, true);
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn common_shell_setup_still_allows_an_owned_write() {
        let mut bad = Vec::new();
        for command in [
            "export PATH=\"$HOME/bin:$PATH\"; gh issue create -R cameronsjo/x -t a -b b",
            "read -r x; gh issue create -R cameronsjo/x -t a -b b",
            "set -euo pipefail; gh issue create -R cameronsjo/x -t a -b b",
            "printf -v OUT '%s' x; gh issue create -R cameronsjo/x -t a -b b",
            "(cd /tmp && export FOO=1); gh issue create -R cameronsjo/x -t a -b b",
            "f(){ local n=1; echo $n; }; f; gh issue create -R cameronsjo/x -t a -b b",
            "case $1 in a) export MODE=a;; esac; gh issue create -R cameronsjo/x -t a -b b",
            "source .venv/bin/activate && gh issue create -R cameronsjo/x -t a -b b",
            "while read -r line; do echo \"$line\"; done < f; gh issue create -R cameronsjo/x -t a -b b",
            "env FOO=1 gh issue create -R cameronsjo/x -t a -b b",
        ] {
            run_case(&mut bad, command, false);
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn trap_actions_and_eval_expansions_are_read() {
        let mut bad = Vec::new();
        for command in [
            // I-1: a trap inside a subshell.
            "(trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b)",
            // I-2: a backslash-escaped trap.
            "\\trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap 'export GH_HOS''T=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap -- 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap \"$CMD\" DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            // Narrow review I-1: after `--`, a leading dash is the action.
            "trap -- '-x; export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "trap -- '- ; export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            // Narrow review I-2: `--` after builtin/command, backslashes inside.
            "command -- trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "builtin -- trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "t\\rap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "e\\val 'export GH_HOST=evil.com'; gh issue create -R cameronsjo/x -t a -b b",
            "command -- eval 'export GH_HOST=evil.com'; gh issue create -R cameronsjo/x -t a -b b",
            "command -p trap 'export GH_HOST=evil.com' DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            "command -p eval 'export GH_HOST=evil.com'; gh issue create -R cameronsjo/x -t a -b b",
            "command -p -- export GH_HOST=evil.com; gh issue create -R cameronsjo/x -t a -b b",
            // N-2: a function named as the action.
            "f(){ export GH_HOST=evil.com; }; trap f DEBUG; gh issue create -R cameronsjo/x -t a -b b",
            // I-3: eval of an expansion.
            "eval \"$(printf 'export GH_HOS%s=evil.com' T)\"; gh issue create -R cameronsjo/x -t a -b b",
            "eval \"$X\"; gh issue create -R cameronsjo/x -t a -b b",
            "eval `cat f`; gh issue create -R cameronsjo/x -t a -b b",
        ] {
            run_case(&mut bad, command, true);
        }
        for command in [
            "tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; gh issue comment 1 -R cameronsjo/x --body-file \"$tmp\"",
            "trap cleanup EXIT; gh issue create -R cameronsjo/x -t a -b b",
            "trap - EXIT; trap -p; gh issue create -R cameronsjo/x -t a -b b",
            "trap -- - EXIT; trap -l; gh issue create -R cameronsjo/x -t a -b b",
            "command -- echo hi; gh issue create -R cameronsjo/x -t a -b b",
            "command -v gh; gh issue comment 1 -R cameronsjo/x --body b",
            "command -V export; gh issue comment 1 -R cameronsjo/x --body b",
            "grep -rn trap src; gh issue create -R cameronsjo/x -t a -b b",
            "eval 'echo hi'; gh issue create -R cameronsjo/x -t a -b b",
            // N-1: a bare `=` in a test is no assignment.
            "if [ \"$m\" = export ]; then echo y; fi; gh issue comment 1 -R cameronsjo/x --body b",
        ] {
            run_case(&mut bad, command, false);
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    #[test]
    fn quoted_or_escaped_words_still_reach_the_write_check() {
        // cadence-hooks#1103.
        with_env(&owners_env_212(), || {
            let blocked = [
                "gh $'issue' create -R stranger/repo -t x -b y",
                "gh issue $'create' -R stranger/repo -t x -b y",
                r"$'\x67h' issue create -R stranger/repo -t x -b y",
                "'gh' issue create -R stranger/repo -t x -b y",
                "g''h issue create -R stranger/repo -t x -b y",
                "gh $'repo' delete stranger/repo --yes",
            ];
            for command in blocked {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    "{command}"
                );
            }
            let allowed = [
                "git commit -m 'gh issue create -R stranger/repo'",
                "gh $'issue' list -R stranger/repo",
            ];
            for command in allowed {
                let result = GhWriteGuard.run(&input_with(command, "/tmp"));
                assert!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Allow),
                    "{command}"
                );
            }
        });
    }

    /// PR #1118 review: padded prefixes that once turned a size bound into a
    /// literal `$NAME` — the expansion budget, the name count, and (for `D`
    /// itself) a value longer than the stored-value limit.
    fn padded_prefixes_1118() -> Vec<String> {
        vec![
            String::new(),
            format!("P={}; : {}; ", "a".repeat(4096), vec!["$P"; 256].join(" ")),
            (0..300).map(|n| format!("V{n}=v{n}; ")).collect(),
        ]
    }

    #[test]
    fn padded_assignment_prefix_cannot_hide_a_write() {
        with_env(&owners_env_212(), || {
            for prefix in padded_prefixes_1118() {
                let command = format!("{prefix}R=repo; gh $R delete x/y --yes");
                let result = GhWriteGuard.run(&input_with(&command, "/tmp"));
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            }
        });
    }

    #[test]
    fn deep_group_nesting_fails_closed_instead_of_overflowing() {
        // PR #1118 review: ~900 levels of `{ (` overflowed the parser's stack
        // and aborted the hook, a noisy fail-open.
        with_env(&owners_env_212(), || {
            let nest =
                |k: usize, inner: &str| format!("{}{inner}{}", "{ ( ".repeat(k), " ) }".repeat(k));
            let cases = [
                // Nothing here can spell `gh`: the fast path skips it, so it
                // never reaches the parser at all.
                (nest(1000, "echo $HOME"), false),
                (nest(1000, "echo $(date)"), true),
                (nest(1000, "gh repo delete x/y --yes"), true),
                (nest(3, "gh repo delete x/y --yes"), true),
                (nest(3, "gh pr list"), false),
            ];
            for (command, blocks) in cases {
                let result = GhWriteGuard.run(&input_with(&command, "/tmp"));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{}",
                    &command[..command.len().min(40)]
                );
            }
        });
    }

    /// PR #1118 review: 5000 levels (~50 KB) of `{ (` around `inner`, in the
    /// three spellings bash runs as groups.
    fn deep_nests_1118(inner: &str) -> Vec<String> {
        let k = 5000;
        vec![
            format!("{}{inner}{}", "{ ( ".repeat(k), " ) }".repeat(k)),
            format!("{}{inner}{}", "{(".repeat(k), ")}".repeat(k)),
            format!("{}{inner}{}", "{ ".repeat(k), "; }".repeat(k)),
        ]
    }

    /// Release is the shipped profile; the debug bound only catches a return
    /// to quadratic work (seconds per shape), not normal debug slowness.
    fn nest_time_limit_1118() -> std::time::Duration {
        std::time::Duration::from_secs_f64(if cfg!(debug_assertions) { 10.0 } else { 0.5 })
    }

    #[test]
    fn deep_group_nesting_write_blocks_in_time() {
        with_env(&owners_env_212(), || {
            for command in deep_nests_1118("gh repo delete x/y --yes") {
                let start = std::time::Instant::now();
                let result = GhWriteGuard.run(&input_with(&command, "/tmp"));
                assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
                assert!(
                    start.elapsed() < nest_time_limit_1118(),
                    "{:?}",
                    start.elapsed()
                );
            }
        });
    }

    /// Each gh write is judged in the whole-command `parse_work_dir`
    /// directory AND the directory its own segment runs in, and the sharpest
    /// verdict wins. Every row is `(command, run from the owned checkout?,
    /// blocks?)`; `{O}`/`{U}` are the owned/unowned checkouts. The bash
    /// behavior each bypass row relies on was checked with a `pwd` canary.
    #[test]
    fn gh_write_is_judged_where_its_own_segment_runs() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        let o = owned.path().to_str().unwrap();
        let u = unowned.path().to_str().unwrap();
        with_env(&owners_env(), || {
            for (command, in_owned, blocks) in [
                // Allowed on the base: `parse_work_dir` sees no `cd` on a
                // later line, after a background `&`, or in a brace group.
                ("echo hi\ncd {U}\ngh pr create -t x", true, true),
                ("true & cd {U}; gh pr create -t x", true, true),
                ("{ cd {U}; }; gh pr create -t x", true, true),
                ("echo hi\ncd {U}\ngh issue comment 1 -b x", true, true),
                (
                    "echo hi\ncd {U}\nfor i in 1; do gh pr create -t x; done",
                    true,
                    true,
                ),
                // Allowed on the base: the subshell's `cd` leaked into the
                // parent, so the write was judged in the owned checkout.
                ("(true; cd {O} ); gh pr create -t x", false, true),
                ("(true; cd {O}; true); gh pr create -t x", false, true),
                // Blocked on the base, and still: the whole-command reading
                // is kept, so no block is lost.
                ("cd {U} && gh pr create -t x", true, true),
                ("cd {U} | cat; gh pr create -t x", true, true),
                ("true || cd {U}\ngh pr create -t x", true, true),
                ("gh pr create -t x", false, true),
                // Controls.
                ("cd {O} && gh pr create -t x", false, false),
                ("cd {O} && gh pr create -t x", true, false),
                ("cd {O}\ngh pr create -t x", false, false),
                ("gh pr create -t x", true, false),
                ("(cd {U} && gh pr view 1); gh pr create -t x", true, false),
                ("(cd {U}); gh pr create -t x", true, false),
                ("echo x | { cd {U}; }; gh pr create -t x", true, false),
                ("{ cd {U}; } & gh pr create -t x", true, false),
                (
                    "echo hi\ncd {U}\ngh pr create -R cameronsjo/x -t x",
                    true,
                    false,
                ),
            ] {
                let command = command.replace("{O}", o).replace("{U}", u);
                let cwd = if in_owned { o } else { u };
                let result = GhWriteGuard.run(&input_with(&command, cwd));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{command} (from {cwd}): {:?}",
                    result.message
                );
            }
        });
    }

    /// A `gh` named through a variable is judged as `gh`
    /// (cameronsjo/cadence-hooks#1171). Every row is `(command, run from the
    /// owned checkout?, blocks?)`; the unowned checkout blocks a bare write.
    /// A variable never assigned, or assigned something unreadable, is the
    /// accepted gap and stays allowed.
    #[test]
    fn a_variable_command_word_is_judged_as_the_gh_it_was_assigned() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        let o = owned.path().to_str().unwrap();
        let u = unowned.path().to_str().unwrap();
        with_env(&owners_env(), || {
            for (command, in_owned, blocks) in [
                ("G=gh; $G pr create -t x", false, true),
                ("G=gh; \"$G\" pr create -t x", false, true),
                ("G=gh; ${G} pr create -t x", false, true),
                ("G=gh; \"${G}\" pr create -t x", false, true),
                ("export G=gh; $G pr create -t x", false, true),
                ("G=/usr/bin/gh; $G pr create -t x", false, true),
                ("G='gh'; $G pr create -t x", false, true),
                ("G=gh\n$G pr create -t x", false, true),
                ("G=gh; { $G pr create -t x; }", false, true),
                ("G=gh; X=1 $G pr create -t x", false, true),
                ("G=gh; $G -R evil/x pr create -t x", true, true),
                ("G=gh; $G issue comment 1 -b x", false, true),
                ("G=ls; G=gh; $G pr create -t x", false, true),
                ("sh -c 'G=gh; $G pr create -t x'", false, true),
                // Controls: owned target, read-only verb, not gh.
                ("G=gh; $G pr create -t x", true, false),
                ("G=gh; $G pr create -R cameronsjo/x -t x", false, false),
                ("G=gh; $G pr view 1", false, false),
                ("G=ls; $G pr create -t x", false, false),
                // The accepted gap: never assigned, or unreadable.
                ("$G pr create -t x", false, false),
                ("G=$(which gh); $G pr create -t x", false, false),
                ("G=\"g$H\"; $G pr create -t x", false, false),
                ("read G; $G pr create -t x", false, false),
            ] {
                let command = command.replace("{O}", o).replace("{U}", u);
                let cwd = if in_owned { o } else { u };
                let result = GhWriteGuard.run(&input_with(&command, cwd));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{command} (from {cwd}): {:?}",
                    result.message
                );
            }
        });
    }

    /// A relative `cd` target searches `CDPATH`, so where the write runs is
    /// unknown and it blocks (cameronsjo/cadence-hooks#1171). `CDPATH` is
    /// pinned in the same lock as the owner allowlist. Rows are `(CDPATH in
    /// the hook env, command, blocks?)`, run from the owned checkout.
    #[test]
    fn a_cd_that_cdpath_may_redirect_blocks_the_write_after_it() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let o = owned.path().to_str().unwrap();
        for (cdpath, command, blocks) in [
            (Some("/elsewhere"), "cd sub && gh pr create -t x", true),
            (Some("/elsewhere"), "cd sub\ngh pr create -t x", true),
            (Some("/elsewhere"), "pushd sub; gh pr create -t x", true),
            (None, "CDPATH=/e; cd sub; gh pr create -t x", true),
            (None, "export CDPATH=/e; cd sub; gh pr create -t x", true),
            (None, "CDPATH=/e cd sub; gh pr create -t x", true),
            // Not searched: `.` and absolute (`..`, `./…`, `../…` are pinned in
            // the walk's own table).
            (Some("/elsewhere"), "cd . && gh pr create -t x", false),
            (
                Some("/elsewhere"),
                "cd /nope && gh pr create -R cameronsjo/x -t x",
                false,
            ),
            // Unset or empty CDPATH: unchanged.
            (None, "cd sub && gh pr create -R cameronsjo/x -t x", false),
            (
                Some(""),
                "cd sub && gh pr create -R cameronsjo/x -t x",
                false,
            ),
            // A write that names its target is not moved by the cd.
            (
                Some("/elsewhere"),
                "cd sub && gh pr create -R cameronsjo/x -t x",
                false,
            ),
        ] {
            let mut env = owners_env().to_vec();
            env.push(("CDPATH", cdpath));
            with_env(&env, || {
                let result = GhWriteGuard.run(&input_with(command, o));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "CDPATH={cdpath:?} {command}: {:?}",
                    result.message
                );
            });
        }
    }

    /// Over-blocks the operator ruled FIX (cameronsjo/cadence-hooks#1172):
    /// `cd "$(git rev-parse --show-toplevel)"`, a tool-init `eval`, and a
    /// `pushd`/`popd` pair. Every row is `(command, run from the owned
    /// checkout?, blocks?)`; each allow has a twin that really runs in the
    /// unowned checkout (or reads something else) and still blocks.
    #[test]
    fn known_shapes_that_stay_in_the_checkout_are_not_unresolvable() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        let o = owned.path().to_str().unwrap();
        let u = unowned.path().to_str().unwrap();
        std::fs::create_dir(owned.path().join("sub")).unwrap();
        std::fs::create_dir(unowned.path().join("sub")).unwrap();
        let osub = format!("{o}/sub");
        let usub = format!("{u}/sub");
        with_env(&owners_env(), || {
            for (command, cwd, blocks) in [
                // 1. The repo root of the directory it runs in.
                (
                    "cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    false,
                ),
                (
                    "cd $(git rev-parse --show-toplevel) && gh pr create -t x",
                    &osub,
                    false,
                ),
                (
                    "cd \"$(git -C {O} rev-parse --show-toplevel)\" && gh pr create -t x",
                    &usub,
                    false,
                ),
                (
                    "pushd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    false,
                ),
                // Twins: the root of the unowned checkout, a suffix, another
                // query, a literal directory name, a replaced `git`.
                (
                    "cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &usub,
                    true,
                ),
                (
                    "cd \"$(git -C {U} rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "cd \"$(git rev-parse --show-toplevel)/../{UB}\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "cd \"$(git rev-parse --git-dir)\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "cd '$(git rev-parse --show-toplevel)' && gh pr create -t x",
                    &usub,
                    true,
                ),
                (
                    "git() { echo {U}; }; cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "PATH=/x:$PATH; cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "GIT_DIR={U}/.git cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "cd \"$(git rev-parse --show-toplevel)\" && gh pr create -t x",
                    &"/nonexistent-dir".to_string(),
                    true,
                ),
                // 2. Tool-init evals run nothing that moves.
                ("eval \"$(ssh-agent -s)\"; gh pr create -t x", &osub, false),
                (
                    "eval \"$(direnv hook bash)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                ("eval \"$(brew shellenv)\"; gh pr create -t x", &osub, false),
                (
                    "eval \"$(/opt/homebrew/bin/brew shellenv)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                ("eval \"$(pyenv init -)\"; gh pr create -t x", &osub, false),
                ("eval \"$(rbenv init -)\"; gh pr create -t x", &osub, false),
                (
                    "eval \"$(starship init bash)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                (
                    "eval \"$(zoxide init bash)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                (
                    "eval \"$(fnm env --use-on-cd)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                (
                    "eval \"$(mise activate bash)\"; gh pr create -t x",
                    &osub,
                    false,
                ),
                ("eval $(ssh-agent -s) && gh pr create -t x", &osub, false),
                // Twins: another eval, a second command, a redefined tool, a
                // `cd`-defining flag, a direnv export, an unowned cwd.
                ("eval \"$(cat x)\"; gh pr create -t x", &osub, true),
                (
                    "eval \"$(direnv export bash)\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "eval \"$(ssh-agent -s; cd {U})\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "eval \"$(zoxide init bash --cmd cd)\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "eval \"$(mise activate bash; cd {U})\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "eval \"$(brew shellenv)\" cd {U}; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "brew() { echo cd {U}; }; eval \"$(brew shellenv)\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "starship() { echo cd {U}; }; eval \"$(starship init bash)\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                (
                    "PATH=/x:$PATH; eval \"$(fnm env)\"; gh pr create -t x",
                    &osub,
                    true,
                ),
                ("eval '$(ssh-agent -s)'; gh pr create -t x", &osub, true),
                ("eval \"$(ssh-agent -s)\"; gh pr create -t x", &usub, true),
                // 4. `popd` returns to where the matching `pushd` left.
                (
                    "pushd sub && make && popd && gh pr create -t x",
                    &o.to_string(),
                    false,
                ),
                (
                    "pushd {U} && make && popd && gh pr create -t x",
                    &o.to_string(),
                    false,
                ),
                (
                    "pushd {U} >/dev/null; popd >/dev/null; gh pr create -t x",
                    &o.to_string(),
                    false,
                ),
                (
                    "pushd {U}; pushd {O}; popd; popd; gh pr create -t x",
                    &o.to_string(),
                    false,
                ),
                // Twins: still inside, an unmatched or unreadable `popd`, a
                // `popd` that only ran in a subshell, a maybe-run `pushd`, a
                // cleared stack, a rotated stack.
                ("pushd {U} && gh pr create -t x", &o.to_string(), true),
                (
                    "pushd {U}; pushd {O}; popd; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                ("popd && gh pr create -t x", &o.to_string(), true),
                (
                    "pushd sub && popd && popd && gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                ("pushd {U}; (popd); gh pr create -t x", &o.to_string(), true),
                (
                    "pushd {U}; popd -n; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                (
                    "pushd {U}; popd +1; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                (
                    "pushd {U}; dirs -c; popd; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                (
                    "pushd {U}; pushd; popd; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                (
                    "if true; then pushd {U}; fi; popd; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                ("(pushd {U}); popd; gh pr create -t x", &o.to_string(), true),
                (
                    "pushd {U} | cat; popd; gh pr create -t x",
                    &o.to_string(),
                    true,
                ),
                (
                    "pushd sub && make && popd && gh pr create -t x",
                    &u.to_string(),
                    true,
                ),
            ] {
                let command = command
                    .replace("{O}", o)
                    .replace("{U}", u)
                    .replace("{UB}", u.rsplit('/').next().unwrap());
                let result = GhWriteGuard.run(&input_with(&command, cwd));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{command} (from {cwd}): {:?}",
                    result.message
                );
            }
        });
    }

    /// The fast paths decline only segments the full reading declines too.
    #[test]
    fn plain_segment_fast_paths_agree_with_the_full_reading() {
        for (segment, invokes_gh) in [
            ("f", false),
            ("cd /a/b && make -j4", false),
            ("GH pr create", true),
            ("/usr/bin/gh pr create", true),
            ("eval gh pr create", true),
            ("env -S gh pr create", true),
            ("g\\h pr create", true),
            ("'g'h pr create", true),
            ("{g,x}h pr create", true),
            ("echo gh", true),
        ] {
            assert_eq!(segment_invokes_gh(segment), invokes_gh, "{segment}");
        }
        for (segment, skipped) in [
            ("f", true),
            ("cd /a && make", true),
            ("export GH_HOST=x", false),
            ("GH_HOST=x", false),
            ("set -a", false),
            ("source ./env", false),
            (". ./env", false),
            ("read h", false),
            ("ex\\port GH_HOST=x", false),
            ("'export' X", false),
            ("eval x", false),
            ("trap x EXIT", false),
            ("builtin export X", false),
        ] {
            assert_eq!(observes_nothing(segment, "GH_HOST"), skipped, "{segment}");
        }
    }

    /// A 200 KB flood of plain function calls before a write is judged well
    /// inside the hook deadline, which fails open.
    #[test]
    fn a_function_call_flood_before_a_write_blocks_promptly() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        let o = owned.path().to_str().unwrap();
        let u = unowned.path().to_str().unwrap();
        with_env(&owners_env(), || {
            let command = format!(
                "f() {{ cd {u}; }}; {}gh pr create -t x",
                "f; ".repeat(70_000)
            );
            let started = std::time::Instant::now();
            let result = GhWriteGuard.run(&input_with(&command, o));
            assert!(matches!(result.outcome, cadence_hooks_core::Outcome::Block));
            let limit = if cfg!(debug_assertions) { 8.0 } else { 0.5 };
            assert!(
                started.elapsed().as_secs_f64() < limit,
                "{:?}",
                started.elapsed()
            );
        });
    }

    /// Directory changes neither reading followed: a function body, `pushd`,
    /// `eval`, `builtin cd`, and a `cd` inside a compound. From an owned
    /// checkout each ran the write in the unowned one (checked with a real
    /// `bash` `pwd` canary) and was allowed.
    #[test]
    fn gh_write_follows_every_directory_change_form() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let unowned = origin_checkout("https://github.com/evil/x.git");
        let o = owned.path().to_str().unwrap();
        let u = unowned.path().to_str().unwrap();
        with_env(&owners_env(), || {
            for (command, blocks) in [
                // Allowed on the base.
                ("f() { cd {U}; }; f; gh pr create -t x", true),
                ("f() {\ncd {U}\n}\nf\ngh pr create -t x", true),
                ("function f { cd {U}; }; f; gh pr create -t x", true),
                ("f() { cd {U}; }; f && gh pr create -t x", true),
                ("g() { f; }; f() { cd {U}; }; g; gh pr create -t x", true),
                ("cd() { builtin cd {U}; }; cd {O}; gh pr create -t x", true),
                ("f() { gh pr create -t x; }; (cd {U}; f)", true),
                ("pushd {U}; gh pr create -t x", true),
                ("pushd {U} >/dev/null; gh pr create -t x", true),
                ("eval 'cd {U}'; gh pr create -t x", true),
                ("eval cd {U}; gh pr create -t x", true),
                ("builtin cd {U}; gh pr create -t x", true),
                ("command cd {U}; gh pr create -t x", true),
                ("\\cd {U}; gh pr create -t x", true),
                ("X=1 cd {U}; gh pr create -t x", true),
                ("! cd {U}; gh pr create -t x", true),
                ("time cd {U}; gh pr create -t x", true),
                ("if true; then cd {U}; fi; gh pr create -t x", true),
                ("if cd {U}; then true; fi; gh pr create -t x", true),
                ("{ if true; then cd {U}; fi; }; gh pr create -t x", true),
                (
                    "while true; do cd {U}; break; done; gh pr create -t x",
                    true,
                ),
                ("for d in {U}; do cd $d; done; gh pr create -t x", true),
                ("case x in x) cd {U};; esac; gh pr create -t x", true),
                ("c=cd; $c {U}; gh pr create -t x", true),
                ("trap 'cd {U}' DEBUG; gh pr create -t x", true),
                // Unreadable: the shell is somewhere this walk cannot name.
                ("cd {U}; popd; gh pr create -t x", true),
                ("eval \"$S\"; gh pr create -t x", true),
                // Controls: the same forms into the owned checkout, or
                // forms that move nothing.
                ("cd {O} && gh pr create -t x", false),
                ("f() { echo; }; f; gh pr create -t x", false),
                ("if true; then echo; fi; gh pr create -t x", false),
                ("f() { cd {O}; }; f; gh pr create -t x", false),
                ("pushd {O} >/dev/null && gh pr create -t x && popd", false),
                ("eval 'cd {O}'; gh pr create -t x", false),
                ("builtin cd {O}; gh pr create -t x", false),
                ("if true; then cd {O}; fi; gh pr create -t x", false),
                (
                    "while true; do cd {O}; break; done; gh pr create -t x",
                    false,
                ),
                ("f() (cd {U}); f; gh pr create -t x", false),
                ("f() { cd {U}; }; f | cat; gh pr create -t x", false),
                ("(f() { cd {U}; }; f); gh pr create -t x", false),
                ("f() { cd {U}; gh pr create -t x; }; echo", false),
                ("for f in a b; do echo $f; done; gh pr create -t x", false),
                (
                    "case x in y) echo;; *) echo;; esac; gh pr create -t x",
                    false,
                ),
                ("eval 'echo hi'; gh pr create -t x", false),
                ("trap 'rm -f x' EXIT; gh pr create -t x", false),
            ] {
                let command = command.replace("{O}", o).replace("{U}", u);
                let result = GhWriteGuard.run(&input_with(&command, o));
                assert_eq!(
                    matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                    blocks,
                    "{command}: {:?}",
                    result.message
                );
            }
        });
    }

    /// A flood of writes, each after a `cd` to a distinct directory, blocks
    /// past [`MAX_SEGMENT_DIRS`] rather than spending a git lookup on each
    /// and running past the hook deadline.
    #[test]
    fn writes_in_too_many_directories_block() {
        let owned = origin_checkout("https://github.com/cameronsjo/x.git");
        let o = owned.path().to_str().unwrap();
        for i in 0..=MAX_SEGMENT_DIRS {
            std::fs::create_dir(owned.path().join(format!("d{i}"))).unwrap();
        }
        with_env(&owners_env(), || {
            // Every directory is inside the owned checkout, so each write
            // alone is allowed: only the count blocks.
            let within: String = (0..MAX_SEGMENT_DIRS)
                .map(|i| format!("echo\ncd {o}/d{i}\ngh pr create -t x\n"))
                .collect();
            let allowed = GhWriteGuard.run(&input_with(&within, o));
            assert!(
                !matches!(allowed.outcome, cadence_hooks_core::Outcome::Block),
                "{:?}",
                allowed.message
            );
            let past = format!("{within}echo\ncd {o}/d{MAX_SEGMENT_DIRS}\ngh pr create -t x");
            let result = GhWriteGuard.run(&input_with(&past, o));
            assert!(
                matches!(result.outcome, cadence_hooks_core::Outcome::Block),
                "{:?}",
                result.message
            );
            assert!(
                result
                    .message
                    .as_deref()
                    .is_some_and(|m| m.contains("directories")),
                "{:?}",
                result.message
            );
        });
    }
}
