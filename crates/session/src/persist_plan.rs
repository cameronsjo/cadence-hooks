//! `session persist-plan` — UserPromptSubmit hook (cadence#505).
//!
//! Cameron's standard plan-approval path is "approve-and-clear": the parent
//! transcript records `ExitPlanMode` as rejected (`[Request interrupted by
//! user for tool use]`), and the harness injects a fresh user prompt
//! `Implement the following plan:\n\n<full plan markdown>` — killing the
//! post-approval turn a conversational "save the plan" rule would have relied
//! on. This hook intercepts that injected prompt deterministically: every
//! `UserPromptSubmit` payload is checked against an exact prefix gate, and on
//! match the plan body is extracted, written to `docs/plans/` (idempotent by
//! body hash), linked to its approving transcript when resolvable, and named
//! in a context line so the session verifies placement and commits it.
//!
//! Never blocks (ADR-0001): every failure path — no prompt, no match, no
//! `cwd`, not a git repo, unsafe session id, exhausted suffix ladder — exits
//! silently via `CheckResult::allow()`. A hook bug must not eat a user prompt.

use crate::identity;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The exact, case-sensitive prefix the harness's approve-and-clear
/// re-injection carries. A hand-typed prompt with the same prefix is an
/// accepted false positive — persisting a plan the user asked to implement is
/// benign (see the plan doc's Approach step 0).
const PLAN_PREFIX: &str = "Implement the following plan:";

/// Prefix of the trailing suffix line the harness appends after the plan
/// body. Two live variants share this prefix ("...consider using the Agent
/// tool..." and the older "...using TeamCreate..."), and future drift is
/// covered by matching on the prefix rather than the full line.
const SUFFIX_LINE_PREFIX: &str = "If this plan can be broken down";

/// Prefix of a second trailing paragraph the harness may inject BETWEEN the
/// plan body and [`SUFFIX_LINE_PREFIX`] — a pointer back at the transcript
/// ("...before exiting plan mode..."). Live-verified 2026-07-20 (see the plan
/// doc's execution addendum): without stripping this too, the persisted body
/// glues harness text onto every plan AND the parent-transcript hash match
/// (Approach step 4) systematically misses, since `ExitPlanMode`'s raw
/// `input.plan` never carries either paragraph. Stripped by the same
/// trailing-line-prefix mechanism as `SUFFIX_LINE_PREFIX` — a line matching
/// EITHER prefix pops.
const POINTER_PARAGRAPH_PREFIX: &str = "If you need specific details from before exiting plan mode";

/// Cap on the generated slug's length (before the date prefix).
const MAX_SLUG_LEN: usize = 60;

/// Slug used when the plan body carries no ATX heading.
const DEFAULT_SLUG: &str = "approved-plan";

/// Numeric suffixes tried after the bare stem, before the short-id fallback.
/// Combined with the bare stem this is 9 total candidates ("all nine
/// suffixes taken" in the plan doc), after which [`fallback_path`] is tried.
const NUMERIC_SUFFIXES: std::ops::RangeInclusive<u32> = 2..=9;

/// The provenance line label carrying the plan body's hash. Shared by the
/// writer ([`provenance_block`]) and the reader ([`file_matches_body`]) so the
/// two can never drift apart: since the reader now falls back to recomputing
/// the body when no such line is found, a label mismatch would no longer be a
/// visible no-match — it would silently reclassify every document this hook
/// wrote as one it didn't.
const PROVENANCE_HASH_LABEL: &str = "Plan-body-SHA256:";

/// Cap on a candidate document's size before [`file_matches_body`] declines to
/// consider it a re-fire. Plan docs run single-digit KB; anything past 1 MiB is
/// not a plan this hook wrote.
const IDEMPOTENCY_MAX_FILE_BYTES: u64 = 1024 * 1024;

/// How many lines past an opening `---` [`strip_leading_frontmatter`] will scan
/// for the closing fence. Real backfill frontmatter runs ~12 lines; the bound
/// keeps a body that merely opens with a thematic break from consuming the
/// whole document looking for a fence that was never there.
const FRONTMATTER_SCAN_MAX_LINES: usize = 100;

/// How far back a sibling transcript may sit and still be scanned for the
/// approving `ExitPlanMode` call.
const PARENT_SCAN_MAX_AGE: Duration = Duration::from_secs(48 * 3600);

/// How many of the newest sibling transcripts are scanned.
const PARENT_SCAN_MAX_FILES: usize = 20;

/// Cap on a sibling transcript's size before it's skipped entirely. Real
/// transcripts run single-digit MB; 32 MiB is generous headroom against a
/// pathological file consuming the scan's time — outside any deadline budget
/// (this scan is a plain `Check`, not a git-spawning probe).
const PARENT_SCAN_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// Schema version stamped on every `plan-links.jsonl` row. A new stream
/// (cadence#238 convention) — does not share `cadence_hooks_metrics::common`'s
/// existing version constants; this one lives with its own writer.
const PLAN_LINKS_SCHEMA_VERSION: u32 = 1;

/// Persist an approved plan whose post-approval turn was wiped.
pub struct PersistPlan;

impl Check for PersistPlan {
    fn name(&self) -> &str {
        "persist-plan"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        let utc_now = cadence_hooks_core::time::utc_timestamp();
        let local_date = cadence_hooks_core::time::local_date();
        // Narrow defense-in-depth: `PersistPlan` fires on every
        // UserPromptSubmit (every turn), so a bug here must not eat a user
        // prompt — a panic degrades to a silent allow rather than propagating.
        //
        // The broader dispatch-layer guard now exists and works
        // (cameronsjo/cadence-hooks#349: `src/dispatch.rs` brackets
        // `decide_check` with `PANIC_GUARDED` so the global panic hook yields
        // the unwind instead of exiting the process). This one is kept anyway:
        // it costs nothing, it covers the highest-frequency hook in the tree,
        // and an allow here is a *quieter* degradation than dispatch's — no
        // stderr breadcrumb, no failopen row for a hook that fires on every
        // single turn.
        std::panic::catch_unwind(|| run_persist_plan(input, &utc_now, &local_date, &host))
            .unwrap_or_else(|_| CheckResult::allow())
    }
}

/// Testable core: the UTC timestamp, local date, and hostname are injected so
/// tests exercise real runtime semantics (no frozen-clock steering) while
/// staying deterministic on everything else.
pub fn run_persist_plan(
    input: &HookInput,
    utc_now: &str,
    local_date: &str,
    host: &str,
) -> CheckResult {
    let Some(prompt) = input.prompt() else {
        return CheckResult::allow();
    };
    let Some(rest) = prompt.strip_prefix(PLAN_PREFIX) else {
        return CheckResult::allow();
    };
    let body = strip_trailing_suffix_lines_and_trim(rest);
    if body.is_empty() {
        return CheckResult::allow();
    }
    let Some(cwd) = input.cwd.as_deref() else {
        return CheckResult::allow();
    };
    let Some(repo_root) = crate::registry::repo_root(cwd) else {
        return CheckResult::allow();
    };
    // A crafted/malformed session id must never become a path component (the
    // short-id fallback embeds it) — same discipline as `session start`.
    let Some(session_id) = input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
    else {
        return CheckResult::allow();
    };

    let body_hash = sha256_hex(body.as_bytes());
    let slug = slugify(&body);
    let plans_dir = repo_root.join("docs").join("plans");
    if fs::create_dir_all(&plans_dir).is_err() {
        return CheckResult::allow();
    }
    let stem = format!("{local_date}-{slug}");

    let parent = input
        .transcript_path()
        .and_then(|tp| find_parent(Path::new(tp), &body_hash, SystemTime::now()));
    let parent_session_id = parent.as_ref().map(|p| p.session_id.as_str());
    let parent_name = parent_session_id.map(identity::generate_name);
    let own_name = identity::generate_name(session_id);
    let machine_digest = crate::provenance::machine_digest(host);

    let approving_parent = parent
        .as_ref()
        .zip(parent_name.as_deref())
        .map(|(p, name)| ApprovingParent {
            name,
            session_id: p.session_id.as_str(),
            model: p.model.as_deref(),
            harness_version: p.harness_version.as_deref(),
        });

    let provenance = provenance_block(
        approving_parent,
        &own_name,
        session_id,
        &machine_digest,
        utc_now,
        &body_hash,
    );
    let document = format!("{body}\n\n---\n\n{provenance}");

    let path = match claim_target(&plans_dir, &stem, session_id, &body_hash, &document) {
        Claim::Wrote(path) | Claim::AlreadyPersisted(path) => path,
        Claim::GiveUp => return CheckResult::allow(),
    };

    // Normalized to forward slashes (the core crate's own convention — see
    // `cadence_hooks_core::normalize_path`) so the linkage row's `plan_path`
    // is a stable, cross-platform value for consumers, regardless of the
    // native separator `PathBuf::to_string_lossy` would otherwise render on
    // Windows.
    let plan_path_rel = cadence_hooks_core::normalize_path(
        &path
            .strip_prefix(&repo_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned()),
    );
    append_plan_links_row(&plan_links_row(
        utc_now,
        parent_session_id,
        session_id,
        host,
        &repo_root.to_string_lossy(),
        &plan_path_rel,
        &body_hash,
    ));

    let parent_label = parent_name.as_deref().unwrap_or("unknown");
    CheckResult::nudge(format!(
        "Approved plan persisted to {} (approved in {parent_label}). Verify placement, then \
         commit it (explicit-path git add) before implementation.",
        path.display()
    ))
}

// ---------------------------------------------------------------------------
// Extraction: prefix gate, suffix strip, trim (Approach step 1)
// ---------------------------------------------------------------------------

/// Strip trailing lines whose trimmed text starts with [`SUFFIX_LINE_PREFIX`]
/// or [`POINTER_PARAGRAPH_PREFIX`], interleaved with trailing blank lines
/// (either prefix, or a blank line, can follow either in any order), then
/// trim leading blank lines. A single unified pass so trailing whitespace
/// around either paragraph never leaves a stray blank line or an unstripped
/// paragraph behind. Only a TRAILING line is ever popped — a line matching
/// either prefix mid-body (the plan text legitimately discussing these
/// strings) is never touched, since the loop only ever inspects `lines.last()`.
///
/// Assumes each paragraph is exactly one physical line (no hard-wrap) in the
/// transcript/prompt text — true for both known harness templates today. If a
/// future template hard-wraps either paragraph across multiple physical
/// lines, only that paragraph's FIRST line carries the pinned prefix, so the
/// strip stops at its LAST (unprefixed) line and silently leaves the whole
/// paragraph glued onto the body — no error, but a smaller instance of the
/// same drift this mechanism exists to catch.
fn strip_trailing_suffix_lines_and_trim(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    loop {
        match lines.last() {
            Some(last) if last.trim().is_empty() => {
                lines.pop();
            }
            Some(last)
                if last.trim_start().starts_with(SUFFIX_LINE_PREFIX)
                    || last.trim_start().starts_with(POINTER_PARAGRAPH_PREFIX) =>
            {
                lines.pop();
            }
            _ => break,
        }
    }
    // Slice off the leading-blank run in one pass rather than repeated
    // `remove(0)` (O(n) per call, O(n²) overall) — a crafted prompt with a
    // huge leading-blank run must not turn this hook into a self-inflicted
    // timeout.
    let first_non_blank = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .unwrap_or(lines.len());
    lines[first_non_blank..].join("\n")
}

/// SHA-256 of `bytes`, lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Target resolution: slug (Approach step 2)
// ---------------------------------------------------------------------------

/// The first ATX heading's text (`#` through `######`, then a space), or
/// `None` when `line` is not a heading.
fn heading_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|&c| c == '#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    trimmed[hashes..].strip_prefix(' ').map(str::trim)
}

/// Slug from the plan body's first heading: lowercase, `[a-z0-9-]` only,
/// dashes collapsed, capped at [`MAX_SLUG_LEN`]. Every non-ASCII-alphanumeric
/// character (including any `..`/`/` traversal attempt or non-ASCII unicode)
/// collapses to a single dash — never passed through — so the result is
/// always a single sanitized path component. `None`/empty heading → the
/// [`DEFAULT_SLUG`].
fn slugify(body: &str) -> String {
    let Some(heading) = body.lines().find_map(heading_text) else {
        return DEFAULT_SLUG.to_string();
    };
    let mut slug = String::new();
    let mut last_was_dash = true; // suppress a leading dash
    for ch in heading.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_lowercase() || lower.is_ascii_digit() {
            slug.push(lower);
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug.truncate(MAX_SLUG_LEN);
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        DEFAULT_SLUG.to_string()
    } else {
        slug
    }
}

// ---------------------------------------------------------------------------
// Idempotency + suffix ladder (Approach step 3)
// ---------------------------------------------------------------------------

/// Outcome of trying to claim a write target.
enum Claim {
    /// A fresh file was created and the document written.
    Wrote(PathBuf),
    /// An existing file already carries this exact body hash — a re-fire.
    AlreadyPersisted(PathBuf),
    /// Every candidate was occupied by a different plan, or a non-recoverable
    /// I/O error occurred. Never overwrite — give up silently (fail-open).
    GiveUp,
}

/// The bare stem path plus its 8 numeric-suffix siblings — 9 candidates,
/// "all nine suffixes" in the plan doc's Approach step 3.
fn numbered_candidates(dir: &Path, stem: &str) -> Vec<PathBuf> {
    let mut paths = vec![dir.join(format!("{stem}.md"))];
    paths.extend(NUMERIC_SUFFIXES.map(|n| dir.join(format!("{stem}-{n}.md"))));
    paths
}

/// Final fallback once every numbered candidate is occupied by a different
/// plan: suffixed with the child session's short id — unique per session, so
/// bounded without a further ladder.
fn fallback_path(dir: &Path, stem: &str, session_id: &str) -> PathBuf {
    dir.join(format!("{stem}-{}.md", identity::short_id(session_id)))
}

/// Strip a leading YAML frontmatter block, returning the document body.
///
/// Engages ONLY when the very first line is exactly `---` (after trimming),
/// then scans forward at most [`FRONTMATTER_SCAN_MAX_LINES`] lines for the
/// closing fence. **No closing fence in the window → the input is returned
/// unchanged**, so a plan body that opens with a thematic break can at worst
/// produce a hash mismatch (which ladders, the pre-existing behavior) and
/// never a false match.
fn strip_leading_frontmatter(doc: &str) -> &str {
    let mut lines = doc.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return doc;
    };
    if first.trim() != "---" {
        return doc;
    }
    let mut offset = first.len();
    for line in lines.take(FRONTMATTER_SCAN_MAX_LINES) {
        offset += line.len();
        if line.trim() == "---" {
            return &doc[offset..];
        }
    }
    doc
}

/// Does the document at `path` carry the plan body `body_hash` identifies?
///
/// Two sources answer that, in order, from a single capped read:
///
/// 1. The LAST `Plan-body-SHA256:` provenance line. The real provenance block
///    is always appended at the end of the document (see [`provenance_block`]),
///    so anchoring on the last occurrence — not the first — means a plan body
///    that itself embeds a decoy line of that exact shape can never spoof the
///    check. When such a line exists it is authoritative: a mismatch ladders,
///    it does not fall through to a recompute.
/// 2. No provenance line at all — a document this hook did not write, such as a
///    backfilled plan carrying only frontmatter (cadence-hooks#399). The body
///    is then recomputed the way [`run_persist_plan`] computes it: strip
///    leading frontmatter, strip the trailing harness suffix lines and trim,
///    hash.
///
/// Only an equality returns `true`; every ambiguity (unreadable, over
/// [`IDEMPOTENCY_MAX_FILE_BYTES`], hash differs) returns `false` and lets the
/// suffix ladder run. The conversion is therefore **one-way**: a document that
/// previously read as "no marker, no match" may now match, but a document that
/// already matched by provenance line can never stop matching — with one
/// boundary case, stated so the invariant is not read as broader than it is.
/// The old reader was uncapped, so a provenance-carrying file that later grows
/// past [`IDEMPOTENCY_MAX_FILE_BYTES`] flips from match to no-match, and
/// ladders. Nothing here reaches that: this hook writes a plan exactly once
/// through `create_new` and never appends, and the measured corpus tops out
/// near 37 KiB against a 1 MiB cap. It would take external growth of a
/// document this hook already wrote, which is a laddered sibling rather than a
/// lost one.
fn file_matches_body(path: &Path, body_hash: &str) -> bool {
    use std::io::Read as _;

    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut content = String::new();
    // Cap the read itself rather than stat-then-read: a file over the cap is
    // not a plan this hook wrote, and must not become an unbounded read.
    if file
        .take(IDEMPOTENCY_MAX_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .is_err()
        || content.len() as u64 > IDEMPOTENCY_MAX_FILE_BYTES
    {
        return false;
    }

    if let Some(recorded) = content
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(PROVENANCE_HASH_LABEL).map(str::trim))
    {
        return recorded == body_hash;
    }

    let body = strip_trailing_suffix_lines_and_trim(strip_leading_frontmatter(&content));
    sha256_hex(body.as_bytes()) == body_hash
}

/// Try each candidate in order with `create_new` (O_EXCL): a fresh path wins
/// outright; an occupied path is re-checked by
/// [`file_matches_body`] — a match is a re-fire (idempotent skip), a mismatch
/// tries the next candidate. Never overwrites anything.
fn claim_target(
    dir: &Path,
    stem: &str,
    session_id: &str,
    body_hash: &str,
    document: &str,
) -> Claim {
    let mut candidates = numbered_candidates(dir, stem);
    candidates.push(fallback_path(dir, stem, session_id));

    for path in candidates {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                if file.write_all(document.as_bytes()).is_ok() {
                    return Claim::Wrote(path);
                }
                let _ = fs::remove_file(&path);
                return Claim::GiveUp;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if file_matches_body(&path, body_hash) {
                    return Claim::AlreadyPersisted(path);
                }
                // Different plan at this path — try the next suffix.
            }
            Err(_) => return Claim::GiveUp,
        }
    }
    Claim::GiveUp
}

// ---------------------------------------------------------------------------
// Provenance: parent resolution (Approach step 4)
// ---------------------------------------------------------------------------

/// The parent transcript's approving turn, resolved by [`find_parent`]: the
/// matched sibling's session id plus the fields the `Approved in:` line's
/// bracket segment needs. `model`/`harness_version` are `None` when the
/// matched line doesn't carry them — the bracket segment is then omitted
/// entirely (see [`provenance_block`]) rather than rendered empty.
#[derive(Debug, PartialEq, Eq)]
struct ParentTuple {
    session_id: String,
    model: Option<String>,
    harness_version: Option<String>,
}

/// One transcript line's `ExitPlanMode` tool_use match: the plan text plus
/// the approving turn's model (`message.model`) and harness version
/// (top-level `version`), when this line is an assistant message carrying an
/// `ExitPlanMode` call. Mirrors
/// `cadence_hooks_core::transcript::line_is_polish_skill_use`'s traversal.
struct ExitPlanModeMatch {
    plan_text: String,
    model: Option<String>,
    harness_version: Option<String>,
}

fn exit_plan_mode_match(line: &str) -> Option<ExitPlanModeMatch> {
    let value: Value = serde_json::from_str(line).ok()?;
    let message = value.get("message")?;
    let content = message.get("content")?.as_array()?;
    let plan_text = content.iter().find_map(|block| {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            return None;
        }
        if block.get("name").and_then(Value::as_str) != Some("ExitPlanMode") {
            return None;
        }
        block
            .get("input")?
            .get("plan")?
            .as_str()
            .map(str::to_string)
    })?;
    let model = message
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string);
    let harness_version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(ExitPlanModeMatch {
        plan_text,
        model,
        harness_version,
    })
}

/// Scan `transcript_path`'s sibling directory for the transcript whose
/// `ExitPlanMode` plan text — normalized by the same suffix-strip-and-trim
/// applied to the injected prompt — hashes to `target_hash`. Newest-first,
/// bounded to [`PARENT_SCAN_MAX_FILES`] siblings no older than
/// [`PARENT_SCAN_MAX_AGE`] and no larger than [`PARENT_SCAN_MAX_FILE_BYTES`],
/// streamed line-by-line (never loading a whole sibling into memory) with a
/// substring pre-filter on each line before any JSON parse. `now` is the
/// caller's `SystemTime::now()`, threaded through for testability without a
/// frozen clock. Returns a [`ParentTuple`] on the first exact match — never a
/// fuzzy guess — and only when the sibling's file stem passes
/// [`identity::is_safe_session_id`]; a match against a hostile-named sibling
/// is treated as no-match (`unknown`), since the returned id flows raw into
/// the provenance text and the linkage row.
fn find_parent(transcript_path: &Path, target_hash: &str, now: SystemTime) -> Option<ParentTuple> {
    let dir = transcript_path.parent()?;
    let mut candidates: Vec<(SystemTime, PathBuf)> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                return None;
            }
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            if meta.len() > PARENT_SCAN_MAX_FILE_BYTES {
                return None;
            }
            let mtime = meta.modified().ok()?;
            let age = now.duration_since(mtime).ok()?;
            if age > PARENT_SCAN_MAX_AGE {
                return None;
            }
            Some((mtime, path))
        })
        .collect();
    candidates.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    candidates.truncate(PARENT_SCAN_MAX_FILES);

    for (_, path) in candidates {
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                continue;
            };
            if !line.contains("ExitPlanMode") {
                continue;
            }
            let Some(exit_plan) = exit_plan_mode_match(&line) else {
                continue;
            };
            let normalized = strip_trailing_suffix_lines_and_trim(&exit_plan.plan_text);
            if sha256_hex(normalized.as_bytes()) == target_hash {
                let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
                return stem
                    .filter(|s| identity::is_safe_session_id(s))
                    .map(|session_id| ParentTuple {
                        session_id,
                        model: exit_plan.model,
                        harness_version: exit_plan.harness_version,
                    });
            }
        }
    }
    None
}

/// The `Approved in:`/model+harness bracket segment, e.g. `" [claude-fable-5,
/// claude-code 2.1.214]"` — rendered with its own leading space so the
/// caller can splice it directly after the `(id)` segment. `None` when
/// neither field is present, so the caller omits the bracket entirely rather
/// than printing an empty or dangling one; when only one field is present,
/// the bracket carries just that field (still never empty).
fn model_harness_bracket(model: Option<&str>, harness_version: Option<&str>) -> Option<String> {
    match (model, harness_version) {
        (Some(m), Some(v)) => Some(format!(" [{m}, claude-code {v}]")),
        (Some(m), None) => Some(format!(" [{m}]")),
        (None, Some(v)) => Some(format!(" [claude-code {v}]")),
        (None, None) => None,
    }
}

/// The approving parent's rendered fields for [`provenance_block`]'s
/// `Approved in:` line — bundled to keep the render function's arity under
/// clippy's `too_many_arguments` threshold. `name` is the parent's generated
/// display name (`identity::generate_name`), computed by the caller since
/// [`find_parent`] only resolves the raw [`ParentTuple`].
struct ApprovingParent<'a> {
    name: &'a str,
    session_id: &'a str,
    model: Option<&'a str>,
    harness_version: Option<&'a str>,
}

/// Render the provenance block appended to every persisted plan.
///
/// `machine_digest` is the salted, truncated digest from
/// [`crate::provenance::machine_digest`] — never the raw hostname (cadence#248
/// fixes the doctrine violation of a bare hostname in a committed artifact).
/// It appears on both lines: transcripts are machine-local, so a resolved
/// parent is same-machine by construction. The executing-session line never
/// carries model/harness — on a same-session wipe it would be identical to
/// the parent's, and on a fresh pickup it's simply unknown.
fn provenance_block(
    parent: Option<ApprovingParent>,
    own_name: &str,
    own_session_id: &str,
    machine_digest: &str,
    utc_now: &str,
    body_hash: &str,
) -> String {
    let approved_in = match parent {
        Some(p) => {
            let bracket = model_harness_bracket(p.model, p.harness_version).unwrap_or_default();
            let name = p.name;
            let sid = p.session_id;
            format!("Approved in: {name} ({sid}){bracket} @ {machine_digest}")
        }
        None => "Approved in: unknown".to_string(),
    };
    format!(
        "{approved_in}\nExecuting session: {own_name} ({own_session_id}) @ {machine_digest}\n\
         Persisted: {utc_now}\n{PROVENANCE_HASH_LABEL} {body_hash}\n"
    )
}

// ---------------------------------------------------------------------------
// Linkage row (Approach step 5)
// ---------------------------------------------------------------------------

fn plan_links_row(
    utc_now: &str,
    parent_session_id: Option<&str>,
    child_session_id: &str,
    host: &str,
    repo: &str,
    plan_path: &str,
    body_hash: &str,
) -> Value {
    serde_json::json!({
        "schemaVersion": PLAN_LINKS_SCHEMA_VERSION,
        "ts": utc_now,
        "parent_session_id": parent_session_id,
        "child_session_id": child_session_id,
        "host": host,
        "repo": repo,
        "plan_path": plan_path,
        "body_sha256": body_hash,
    })
}

/// Append one row to `<metrics_dir>/plan-links.jsonl`. Fully fail-open
/// (ADR-0001): a missing dir it can't create, or a failed open/write,
/// degrades to a no-op.
fn append_plan_links_row(row: &Value) {
    let dir = cadence_hooks_metrics::metrics_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("plan-links.jsonl");
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        // One `write_all` of the record + newline (POSIX O_APPEND makes this
        // single small write atomic), so a concurrent append from another
        // session can't interleave a record with its trailing newline — same
        // assumption as the crate's other metrics writers (e.g. `log_failopen`).
        let mut line = row.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::Outcome;
    use cadence_hooks_core::test_builders::make_user_prompt_submit;
    use tempfile::TempDir;

    // --- extraction: prefix gate ---

    #[test]
    fn non_matching_prefix_is_none() {
        let input = HookInput {
            prompt: Some("just a regular question".into()),
            ..Default::default()
        };
        let r = run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn prefix_match_is_case_sensitive() {
        let input = HookInput {
            prompt: Some("implement the following plan:\n\n# X\n\nbody".into()),
            ..Default::default()
        };
        let r = run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow, "lowercase prefix must not match");
    }

    #[test]
    fn no_prompt_allows() {
        let input = HookInput::default();
        let r = run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    // --- extraction: suffix strip + trim ---

    #[test]
    fn suffix_strip_current_variant() {
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\nIf this plan can be broken down into discrete units of \
             work, consider using the Agent tool to dispatch them.",
        );
        assert_eq!(body, "# Title\n\nbody text");
    }

    #[test]
    fn suffix_strip_old_variant() {
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\nIf this plan can be broken down into discrete units of \
             work, consider using TeamCreate to dispatch them.",
        );
        assert_eq!(body, "# Title\n\nbody text");
    }

    #[test]
    fn suffix_strip_absent_is_noop_besides_trim() {
        let body = strip_trailing_suffix_lines_and_trim("\n\n# Title\n\nbody text\n\n");
        assert_eq!(body, "# Title\n\nbody text");
    }

    #[test]
    fn suffix_strip_drifted_text_still_matches_prefix() {
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\nIf this plan can be broken down some entirely new way \
             nobody has written yet.",
        );
        assert_eq!(body, "# Title\n\nbody text");
    }

    #[test]
    fn suffix_strip_handles_trailing_blank_after_suffix_line() {
        // A trailing blank line AFTER the suffix line must not defeat the strip.
        let body = strip_trailing_suffix_lines_and_trim(
            "# Title\n\nbody\n\nIf this plan can be broken down further.\n\n",
        );
        assert_eq!(body, "# Title\n\nbody");
    }

    #[test]
    fn suffix_strip_strips_both_paragraphs_in_template_order() {
        // Real harness template order: plan body, blank, the transcript-pointer
        // paragraph, blank, the breakdown-line suffix.
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\n\
             If you need specific details from before exiting plan mode, review the \
             transcript.\n\n\
             If this plan can be broken down into discrete units of work, consider using the \
             Agent tool to dispatch them.",
        );
        assert_eq!(
            body, "# Title\n\nbody text",
            "both trailing paragraphs strip down to the bare plan body"
        );
    }

    #[test]
    fn suffix_strip_pointer_paragraph_alone() {
        // The pointer paragraph can appear without the breakdown-line suffix.
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\n\
             If you need specific details from before exiting plan mode, review the \
             transcript.",
        );
        assert_eq!(body, "# Title\n\nbody text");
    }

    #[test]
    fn suffix_strip_mid_body_occurrence_of_either_prefix_survives() {
        // Plan text that legitimately discusses these exact strings mid-body
        // (not as the trailing line) must NOT be stripped — only a genuinely
        // trailing line pops.
        let body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nIf this plan can be broken down, do X first.\n\n\
             If you need specific details from before exiting plan mode, ask.\n\n\
             final body line",
        );
        assert_eq!(
            body,
            "# Title\n\nIf this plan can be broken down, do X first.\n\n\
             If you need specific details from before exiting plan mode, ask.\n\n\
             final body line",
            "mid-body lines matching either prefix are not trailing — never stripped"
        );
    }

    #[test]
    fn suffix_strip_handles_large_leading_blank_run() {
        // Correctness of the O(n) leading-blank slice (replacing the O(n²)
        // `remove(0)` loop) against a large run — a crafted prompt could carry
        // thousands of leading blank lines.
        let mut text = "\n".repeat(5000);
        text.push_str("# Title\n\nbody text");
        let body = strip_trailing_suffix_lines_and_trim(&text);
        assert_eq!(body, "# Title\n\nbody text");
    }

    // --- slug ---

    #[test]
    fn slug_from_heading() {
        assert_eq!(slugify("# Fix the Bug in Widget"), "fix-the-bug-in-widget");
    }

    #[test]
    fn slug_rejects_traversal_characters() {
        let s = slugify("# ../../etc/passwd plan");
        assert!(!s.contains(".."), "no traversal survives: {s}");
        assert!(!s.contains('/'), "no separator survives: {s}");
    }

    #[test]
    fn slug_handles_unicode_heading() {
        let s = slugify("# Café Über Naïve plan");
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "unicode collapses to ascii+dash: {s}"
        );
        assert!(!s.is_empty());
    }

    #[test]
    fn slug_no_heading_uses_default() {
        assert_eq!(slugify("just some prose, no heading"), DEFAULT_SLUG);
    }

    #[test]
    fn slug_empty_body_uses_default() {
        assert_eq!(slugify(""), DEFAULT_SLUG);
    }

    #[test]
    fn slug_caps_at_max_len() {
        let long_heading = format!("# {}", "word ".repeat(40));
        let s = slugify(&long_heading);
        assert!(s.len() <= MAX_SLUG_LEN, "slug capped: {} chars", s.len());
    }

    #[test]
    fn slug_deep_heading_level_recognized() {
        assert_eq!(slugify("###### Deep Heading"), "deep-heading");
    }

    #[test]
    fn slug_heading_level_beyond_six_is_not_a_heading() {
        // 7 hashes is not a valid ATX heading — falls through to the default.
        assert_eq!(slugify("####### Not A Heading"), DEFAULT_SLUG);
    }

    // --- idempotency / suffix ladder ---

    fn doc_with_hash(hash: &str) -> String {
        format!("body\n\n---\n\nPlan-body-SHA256: {hash}\n")
    }

    #[test]
    fn claim_target_writes_fresh_file() {
        let tmp = TempDir::new().unwrap();
        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-a",
            "content-a",
        );
        match claim {
            Claim::Wrote(path) => {
                assert_eq!(path, tmp.path().join("2026-07-20-x.md"));
                assert_eq!(fs::read_to_string(&path).unwrap(), "content-a");
            }
            _ => panic!("expected a fresh write"),
        }
    }

    #[test]
    fn claim_target_re_fire_is_idempotent_skip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("2026-07-20-x.md");
        fs::write(&path, doc_with_hash("hash-a")).unwrap();

        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-a",
            "content-a",
        );
        match claim {
            Claim::AlreadyPersisted(p) => assert_eq!(p, path),
            _ => panic!("expected an idempotent skip"),
        }
        // Never overwritten.
        assert_eq!(fs::read_to_string(&path).unwrap(), doc_with_hash("hash-a"));
    }

    #[test]
    fn claim_target_differing_body_uses_next_suffix() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("2026-07-20-x.md"), doc_with_hash("hash-a")).unwrap();

        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-b",
            "content-b",
        );
        match claim {
            Claim::Wrote(path) => assert_eq!(path, tmp.path().join("2026-07-20-x-2.md")),
            _ => panic!("expected the -2 suffix to be claimed"),
        }
    }

    #[test]
    fn claim_target_race_already_exists_falls_through_to_hash_check() {
        // Simulates the AlreadyExists race: the base path is occupied by the
        // time we get to it, but carries our OWN hash — same as a re-fire.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("2026-07-20-x.md"), doc_with_hash("hash-a")).unwrap();
        let claim = claim_target(tmp.path(), "2026-07-20-x", "sid12345", "hash-a", "ignored");
        assert!(matches!(claim, Claim::AlreadyPersisted(_)));
    }

    #[test]
    fn claim_target_exhausted_ladder_falls_back_to_short_id() {
        let tmp = TempDir::new().unwrap();
        for path in numbered_candidates(tmp.path(), "2026-07-20-x") {
            fs::write(path, doc_with_hash("occupied-by-someone-else")).unwrap();
        }
        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-new",
            "content-new",
        );
        match claim {
            Claim::Wrote(path) => {
                assert_eq!(path, fallback_path(tmp.path(), "2026-07-20-x", "sid12345"));
            }
            _ => panic!("expected the short-id fallback to be claimed"),
        }
    }

    #[test]
    fn claim_target_exhausted_ladder_and_fallback_hash_matches_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        for path in numbered_candidates(tmp.path(), "2026-07-20-x") {
            fs::write(path, doc_with_hash("occupied-by-someone-else")).unwrap();
        }
        let fallback = fallback_path(tmp.path(), "2026-07-20-x", "sid12345");
        fs::write(&fallback, doc_with_hash("hash-new")).unwrap();

        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-new",
            "ignored",
        );
        match claim {
            Claim::AlreadyPersisted(path) => assert_eq!(path, fallback),
            _ => panic!("expected the fallback re-fire to be idempotent"),
        }
    }

    #[test]
    fn claim_target_never_overwrites_a_mismatched_fallback() {
        let tmp = TempDir::new().unwrap();
        for path in numbered_candidates(tmp.path(), "2026-07-20-x") {
            fs::write(path, doc_with_hash("occupied-by-someone-else")).unwrap();
        }
        let fallback = fallback_path(tmp.path(), "2026-07-20-x", "sid12345");
        fs::write(&fallback, doc_with_hash("someone-elses-hash")).unwrap();

        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            "hash-new",
            "ignored",
        );
        assert!(
            matches!(claim, Claim::GiveUp),
            "no further ladder beyond the fallback — must give up, never overwrite"
        );
        assert_eq!(
            fs::read_to_string(&fallback).unwrap(),
            doc_with_hash("someone-elses-hash"),
            "the mismatched fallback file must be untouched"
        );
    }

    #[test]
    fn file_matches_body_anchors_on_last_occurrence_not_a_decoy() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        fs::write(
            &path,
            "Body text mentioning Plan-body-SHA256: decoy-value\n\n---\n\nPlan-body-SHA256: \
             real-value\n",
        )
        .unwrap();
        assert!(file_matches_body(&path, "real-value"));
        assert!(
            !file_matches_body(&path, "decoy-value"),
            "the decoy must never satisfy the check"
        );
    }

    #[test]
    fn file_matches_body_decoy_at_line_start_does_not_spoof() {
        // The sibling decoy tests embed the decoy MID-line, where `strip_prefix`
        // rejects it on its own — so neither actually exercises the `.rev()`
        // last-occurrence anchor they are named for. Only a decoy at the START
        // of a line reaches `strip_prefix`, making this the single case where
        // the anchor is load-bearing. It matters more since cadence-hooks#399:
        // the anchor now also decides whether the recompute fallback runs.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        fs::write(
            &path,
            "Plan-body-SHA256: decoy-value\n\n# Title\n\nbody\n\n---\n\nPlan-body-SHA256: \
             real-value\n",
        )
        .unwrap();
        assert!(file_matches_body(&path, "real-value"));
        assert!(
            !file_matches_body(&path, "decoy-value"),
            "a decoy at line start must not spoof the check — the LAST line anchors"
        );
    }

    #[test]
    fn file_matches_body_recomputes_when_no_hash_line() {
        // A document this hook did not write — backfill frontmatter, no
        // provenance block. The body must still be recognized (cadence-hooks#399).
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nbody text";
        fs::write(
            &path,
            format!("---\ndate: 2026-07-11\nsource_plan: whatever.md\n---\n\n{body}\n"),
        )
        .unwrap();
        assert!(file_matches_body(&path, &sha256_hex(body.as_bytes())));
    }

    #[test]
    fn file_matches_body_recompute_ignores_trailing_harness_suffix() {
        // Some backfilled docs kept the harness's trailing suffix line. The
        // recompute runs the same strip the live path runs, so it still matches.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nbody text";
        fs::write(
            &path,
            format!(
                "---\ndate: 2026-07-11\n---\n\n{body}\n\n{SUFFIX_LINE_PREFIX} into discrete \
                 tasks, consider using the Agent tool.\n"
            ),
        )
        .unwrap();
        assert!(file_matches_body(&path, &sha256_hex(body.as_bytes())));
    }

    #[test]
    fn file_matches_body_different_body_without_hash_line_still_ladders() {
        // The safety invariant: a recompute may only ever CONFIRM a match. A
        // different body under identical frontmatter must not be swallowed.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        fs::write(
            &path,
            "---\ndate: 2026-07-11\n---\n\n# Title\n\nsomeone else's plan\n",
        )
        .unwrap();
        assert!(!file_matches_body(
            &path,
            &sha256_hex(b"# Title\n\nbody text")
        ));
    }

    #[test]
    fn strip_leading_frontmatter_leaves_a_thematic_break_body_alone() {
        // A body opening with a thematic break and no closing fence in the
        // window is returned unchanged — at worst a mismatch, never a false match.
        let doc = "---\n\n# Title\n\nbody text\n";
        assert_eq!(strip_leading_frontmatter(doc), doc);

        let mut long = String::from("---\n");
        for n in 0..(FRONTMATTER_SCAN_MAX_LINES + 5) {
            long.push_str(&format!("line {n}\n"));
        }
        long.push_str("---\n");
        assert_eq!(
            strip_leading_frontmatter(&long),
            long,
            "a closing fence beyond the scan window does not engage the strip"
        );
    }

    #[test]
    fn file_matches_body_oversized_file_is_not_a_match() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let mut content = doc_with_hash("hash-a");
        content.push_str(&"x".repeat((IDEMPOTENCY_MAX_FILE_BYTES as usize) + 1));
        fs::write(&path, content).unwrap();
        assert!(
            !file_matches_body(&path, "hash-a"),
            "past the cap the document is not considered a re-fire"
        );
    }

    #[test]
    fn claim_target_backfilled_frontmatter_doc_is_idempotent_skip() {
        // The regression that IS cadence-hooks#399: before the recompute, a
        // backfilled plan (frontmatter, no provenance block) could never be
        // recognized, so every re-fire laddered to `-2` — permanently.
        let tmp = TempDir::new().unwrap();
        let body = "# Title\n\nbody text";
        let body_hash = sha256_hex(body.as_bytes());
        let base = tmp.path().join("2026-07-20-x.md");
        fs::write(
            &base,
            format!("---\ndate: 2026-07-20\nsource_plan: whatever.md\n---\n\n{body}\n"),
        )
        .unwrap();

        let claim = claim_target(
            tmp.path(),
            "2026-07-20-x",
            "sid12345",
            &body_hash,
            "ignored",
        );
        match claim {
            Claim::AlreadyPersisted(path) => assert_eq!(path, base),
            _ => panic!("a backfilled doc holding this exact body is a re-fire, not a new plan"),
        }
        assert!(
            !tmp.path().join("2026-07-20-x-2.md").exists(),
            "the ladder must not fire"
        );
    }

    #[test]
    fn claim_target_re_fire_is_idempotent_despite_a_decoy_hash_line_in_the_body() {
        // A plan body that itself embeds a decoy `Plan-body-SHA256:`-shaped
        // line (e.g. quoting this very provenance format) must not defeat the
        // idempotency check — only the LAST such line (the real provenance
        // block, appended at the end) anchors the hash.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("2026-07-20-x.md");
        fs::write(
            &path,
            "body discussing Plan-body-SHA256: decoy-hash-in-body\n\n---\n\nPlan-body-SHA256: \
             hash-a\n",
        )
        .unwrap();

        let claim = claim_target(tmp.path(), "2026-07-20-x", "sid12345", "hash-a", "ignored");
        assert!(
            matches!(claim, Claim::AlreadyPersisted(_)),
            "must anchor on the LAST hash line, not the decoy"
        );
    }

    // --- provenance: parent resolution ---

    /// `model`/`harness_version` model the assistant line's `message.model`
    /// and top-level `version` — both `None` reproduces the older transcript
    /// shape that carries neither.
    fn exit_plan_mode_line(
        plan: &str,
        model: Option<&str>,
        harness_version: Option<&str>,
    ) -> String {
        let mut message = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "tool_use", "name": "ExitPlanMode", "input": {"plan": plan}}]
        });
        if let Some(m) = model {
            message["model"] = serde_json::json!(m);
        }
        let mut line = serde_json::json!({ "message": message });
        if let Some(v) = harness_version {
            line["version"] = serde_json::json!(v);
        }
        line.to_string()
    }

    #[test]
    fn find_parent_exact_hash_match() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(&sibling, exit_plan_mode_line(plan_text, None, None)).unwrap();

        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found,
            Some(ParentTuple {
                session_id: "parent-session-id".to_string(),
                model: None,
                harness_version: None,
            })
        );
    }

    #[test]
    fn find_parent_extracts_model_and_harness_version_from_matched_line() {
        // Real transcripts stamp the approving assistant line with both
        // `message.model` and a top-level `version` — verified live against
        // an actual ExitPlanMode transcript line (2026-07-20). A fixture
        // carrying neither would pass this assertion vacuously, so both
        // fields must be populated here.
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(
            &sibling,
            exit_plan_mode_line(plan_text, Some("claude-fable-5"), Some("2.1.214")),
        )
        .unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found,
            Some(ParentTuple {
                session_id: "parent-session-id".to_string(),
                model: Some("claude-fable-5".to_string()),
                harness_version: Some("2.1.214".to_string()),
            })
        );
    }

    #[test]
    fn find_parent_missing_model_and_harness_version_is_gracefully_none() {
        // Older transcript lines (or a stripped-down fixture) may carry
        // neither field — the tuple must still resolve, with both absent.
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(&sibling, exit_plan_mode_line(plan_text, None, None)).unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now()).expect("parent must be found");
        assert_eq!(found.model, None);
        assert_eq!(found.harness_version, None);
    }

    #[test]
    fn find_parent_same_file_wipe_resolves_to_self() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, exit_plan_mode_line(plan_text, None, None)).unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found.map(|p| p.session_id).as_deref(),
            Some("own-session-id"),
            "same-file wipe: parent resolves to the executing session itself"
        );
    }

    #[test]
    fn find_parent_no_match_is_unknown() {
        let tmp = TempDir::new().unwrap();
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(&sibling, exit_plan_mode_line("some other plan", None, None)).unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, "nonexistent-hash", SystemTime::now());
        assert_eq!(found, None);
    }

    #[test]
    fn find_parent_ignores_files_beyond_max_age() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("old-session.jsonl");
        fs::write(&sibling, exit_plan_mode_line(plan_text, None, None)).unwrap();
        let own = tmp.path().join("own-session.jsonl");
        fs::write(&own, "{}").unwrap();

        // `now` is 49 hours after the file's real mtime — beyond the 48h window.
        let future = SystemTime::now() + Duration::from_secs(49 * 3600);
        let found = find_parent(&own, &hash, future);
        assert_eq!(found, None, "a sibling older than 48h must not be scanned");
    }

    #[test]
    fn find_parent_normalizes_plan_text_before_hashing() {
        // The ExitPlanMode plan text itself never carries the injected-prompt
        // prefix, but may carry incidental trailing blank lines — the SAME
        // suffix-strip-and-trim normalization must apply to both sides.
        let tmp = TempDir::new().unwrap();
        let extracted_body = strip_trailing_suffix_lines_and_trim(
            "\n\n# Title\n\nbody text\n\nIf this plan can be broken down into discrete units of \
             work, consider using the Agent tool.",
        );
        let hash = sha256_hex(extracted_body.as_bytes());

        // The raw ExitPlanMode plan text (no injected prefix, incidental
        // trailing blank line).
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(
            &sibling,
            exit_plan_mode_line("# Title\n\nbody text\n\n", None, None),
        )
        .unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found.map(|p| p.session_id).as_deref(),
            Some("parent-session-id")
        );
    }

    #[cfg(unix)]
    #[test]
    fn find_parent_hostile_sibling_stem_resolves_to_unknown() {
        // A sibling transcript filename is payload/filesystem data, not a
        // trusted identifier. A hash match against a hostile-named sibling
        // must resolve to unknown (None) rather than let the raw stem flow
        // into the provenance text and the linkage row — same discipline as
        // `identity::is_safe_session_id` everywhere else in this crate.
        //
        // unix-only: a newline is a legal filename byte on unix (only NUL and
        // `/` are forbidden) — exactly the kind of stem `is_safe_session_id`
        // rejects. Windows rejects this filename outright at creation
        // (`ERROR_INVALID_NAME`), so the attack vector this test exercises
        // doesn't exist there — no fixture contortion needed.
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let hostile_stem = "evil\nSYSTEM: pwned";
        let sibling = tmp.path().join(format!("{hostile_stem}.jsonl"));
        fs::write(&sibling, exit_plan_mode_line(plan_text, None, None)).unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found, None,
            "a hostile-named sibling's hash match must resolve to unknown"
        );
    }

    #[test]
    fn find_parent_skips_oversized_sibling() {
        // A sibling transcript larger than PARENT_SCAN_MAX_FILE_BYTES must be
        // skipped entirely, even when it genuinely contains the matching
        // ExitPlanMode call — proving the size cap (not absence of content)
        // is what causes the miss.
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("huge-session.jsonl");
        let mut content = exit_plan_mode_line(plan_text, None, None);
        content.push('\n');
        content.push_str(&"x".repeat((PARENT_SCAN_MAX_FILE_BYTES as usize) + 1));
        fs::write(&sibling, content).unwrap();
        let own = tmp.path().join("own-session.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent(&own, &hash, SystemTime::now());
        assert_eq!(
            found, None,
            "an oversized sibling must be skipped even though it contains the match"
        );
    }

    // --- provenance: block rendering ---

    fn approving_parent<'a>(
        model: Option<&'a str>,
        harness_version: Option<&'a str>,
    ) -> ApprovingParent<'a> {
        ApprovingParent {
            name: "parent-name",
            session_id: "parent-sid",
            model,
            harness_version,
        }
    }

    #[test]
    fn provenance_block_unknown_parent() {
        let block = provenance_block(None, "own-name", "own-sid", "digest", "ts", "hash");
        assert!(block.starts_with("Approved in: unknown\n"));
        assert!(block.contains("Executing session: own-name (own-sid) @ digest"));
        assert!(block.contains("Persisted: ts"));
        assert!(block.contains("Plan-body-SHA256: hash"));
    }

    #[test]
    fn provenance_block_found_parent_with_model_and_harness() {
        let parent = approving_parent(Some("claude-fable-5"), Some("2.1.214"));
        let block = provenance_block(Some(parent), "own-name", "own-sid", "digest", "ts", "hash");
        assert!(block.starts_with(
            "Approved in: parent-name (parent-sid) [claude-fable-5, claude-code 2.1.214] @ digest\n"
        ));
        // The executing-session line never carries model/harness — only name + id.
        assert!(block.contains("Executing session: own-name (own-sid) @ digest"));
    }

    #[test]
    fn provenance_block_found_parent_without_model_or_harness_omits_bracket() {
        // Neither field resolved (e.g. an older transcript format) — the
        // bracket segment must be omitted entirely, never rendered empty.
        let parent = approving_parent(None, None);
        let block = provenance_block(Some(parent), "own-name", "own-sid", "digest", "ts", "hash");
        assert!(block.starts_with("Approved in: parent-name (parent-sid) @ digest\n"));
        assert!(!block.contains('['), "no dangling/empty bracket: {block}");
    }

    #[test]
    fn provenance_block_found_parent_with_model_only() {
        let parent = approving_parent(Some("claude-fable-5"), None);
        let block = provenance_block(Some(parent), "own-name", "own-sid", "digest", "ts", "hash");
        assert!(
            block.starts_with("Approved in: parent-name (parent-sid) [claude-fable-5] @ digest\n")
        );
    }

    #[test]
    fn provenance_block_found_parent_with_harness_only() {
        let parent = approving_parent(None, Some("2.1.214"));
        let block = provenance_block(Some(parent), "own-name", "own-sid", "digest", "ts", "hash");
        assert!(
            block.starts_with(
                "Approved in: parent-name (parent-sid) [claude-code 2.1.214] @ digest\n"
            )
        );
    }

    // --- linkage row schema ---

    #[test]
    fn plan_links_row_has_expected_schema() {
        let row = plan_links_row(
            "2026-07-20T00:00:00Z",
            Some("parent-sid"),
            "child-sid",
            "host",
            "/repo",
            "docs/plans/2026-07-20-x.md",
            "hash",
        );
        assert_eq!(row["schemaVersion"], 1);
        assert_eq!(row["ts"], "2026-07-20T00:00:00Z");
        assert_eq!(row["parent_session_id"], "parent-sid");
        assert_eq!(row["child_session_id"], "child-sid");
        assert_eq!(row["host"], "host");
        assert_eq!(row["repo"], "/repo");
        assert_eq!(row["plan_path"], "docs/plans/2026-07-20-x.md");
        assert_eq!(row["body_sha256"], "hash");
    }

    #[test]
    fn plan_links_row_nulls_parent_when_unknown() {
        let row = plan_links_row(
            "2026-07-20T00:00:00Z",
            None,
            "child-sid",
            "host",
            "/repo",
            "docs/plans/2026-07-20-x.md",
            "hash",
        );
        assert!(row["parent_session_id"].is_null());
    }

    // --- end-to-end (tempdir git repo) ---

    fn init_repo(dir: &Path) {
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
    }

    #[test]
    fn end_to_end_fresh_write_produces_nudge_and_linkage_row() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        let prompt = "Implement the following plan:\n\n# Fix the Widget\n\nDo the thing.\n\n\
                      If this plan can be broken down into discrete units of work, consider \
                      using the Agent tool to dispatch them.";
        let input = make_user_prompt_submit(
            "child-session-id",
            prompt,
            &cwd,
            &tmp.path().join("child-session-id.jsonl").to_string_lossy(),
        );

        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        // The nudge embeds `path.display()`, which renders the platform's
        // native separator (backslash on Windows) — normalize before
        // asserting on the forward-slash-relative fragment.
        let normalized_msg = cadence_hooks_core::normalize_path(&msg);
        assert!(normalized_msg.contains("docs/plans/2026-07-20-fix-the-widget.md"));
        assert!(msg.contains("approved in unknown"));

        let written =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();
        assert!(written.starts_with("# Fix the Widget"));
        assert!(!written.contains("If this plan can be broken down"));
        assert!(written.contains("Executing session:"));
        assert!(written.contains("Plan-body-SHA256:"));
        // Doctrine fix (cadence#248): the committed block carries the salted
        // digest, never the raw hostname.
        assert!(
            !written.contains("test-host"),
            "the raw hostname must never reach the committed provenance block"
        );
        assert!(written.contains(&crate::provenance::machine_digest("test-host")));

        let links = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        assert!(links.contains("\"child_session_id\":\"child-session-id\""));
        assert!(links.contains("\"parent_session_id\":null"));
        // plan_path is forward-slash-normalized regardless of platform — a
        // stable schema value for consumers, not the native separator.
        assert!(links.contains("\"plan_path\":\"docs/plans/2026-07-20-fix-the-widget.md\""));
        // Local-only metrics KEEP the bare hostname — only the committed doc
        // block is salted (cadence#248).
        assert!(links.contains("\"host\":\"test-host\""));
    }

    #[test]
    fn end_to_end_re_fire_skips_write_but_still_nudges() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        let prompt = "Implement the following plan:\n\n# Fix the Widget\n\nDo the thing.";
        let input = make_user_prompt_submit(
            "child-session-id",
            prompt,
            &cwd,
            &tmp.path().join("child-session-id.jsonl").to_string_lossy(),
        );

        with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host");
        });
        let first_write =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();

        // Re-fire: same prompt, later timestamp (compaction/resume replay).
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-07-20T01:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "re-fire still nudges");
        let second_write =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();
        assert_eq!(
            first_write, second_write,
            "the file must never be rewritten"
        );
    }

    #[test]
    fn no_cwd_allows() {
        let input = HookInput {
            prompt: Some("Implement the following plan:\n\n# X\n\nbody".into()),
            session_id: Some("sid".into()),
            ..Default::default()
        };
        let r = run_persist_plan(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn non_git_repo_cwd_allows() {
        let tmp = TempDir::new().unwrap();
        let input = HookInput {
            prompt: Some("Implement the following plan:\n\n# X\n\nbody".into()),
            session_id: Some("sid".into()),
            cwd: Some(tmp.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        let r = run_persist_plan(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn unsafe_session_id_allows() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let input = HookInput {
            prompt: Some("Implement the following plan:\n\n# X\n\nbody".into()),
            session_id: Some("../escape".into()),
            cwd: Some(tmp.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        let r = run_persist_plan(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(!tmp.path().join("docs").exists(), "nothing written");
    }

    /// Crate-wide serialization lock for the `CADENCE_METRICS_DIR` env-mutating
    /// tests, mirroring `cadence_hooks_metrics::common::ENV_LOCK`'s pattern —
    /// this crate has its own env-mutating tests, so its own lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_metrics_dir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other test in this module via ENV_LOCK.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        let result = f();
        // SAFETY: serialized against every other test in this module via ENV_LOCK.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
        result
    }
}
