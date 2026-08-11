//! `session persist-plan` (UserPromptSubmit) and `session persist-plan-approval`
//! (PostToolUse:ExitPlanMode) — persist an approved plan whose approving turn
//! would otherwise leave no durable trace (cadence#505, cadence-hooks#396).
//!
//! Two distinct gaps, two triggers, one shared persist core:
//!
//! - **Cross-session wipe (`PersistPlan`, UserPromptSubmit).** Cameron's
//!   "approve-and-clear" path: the parent transcript records `ExitPlanMode` as
//!   rejected (`[Request interrupted by user for tool use]`), and the harness
//!   injects a fresh user prompt `Implement the following plan:\n\n<full plan
//!   markdown>` into a NEW session — killing the post-approval turn a
//!   conversational "save the plan" rule would have relied on. This hook
//!   intercepts that injected prompt deterministically via an exact prefix gate.
//! - **Same-session approval (`PersistPlanApproval`, PostToolUse).** No wipe
//!   occurs — the harness stays in the same session and injects no prompt at
//!   all, so `PersistPlan`'s prefix gate structurally never fires
//!   (cadence-hooks#396). Live probe (2026-07-25, cadence-hooks#396 comment
//!   5080816947) established that `PostToolUse:ExitPlanMode` DOES fire here,
//!   carrying the plan text in `tool_response.plan` — `tool_input.plan` is
//!   EMPTY on this path.
//!
//! Both triggers normalize to the same body-hash-idempotent write through
//! [`persist_and_nudge`]: `claim_target`'s `O_EXCL` collision ladder, a shared
//! frontmatter render ([`render_document`]), and one `plan-links.jsonl` row
//! format. Both also run the plan text through
//! [`strip_trailing_suffix_lines_and_trim`] before hashing (Design 18's
//! cross-trigger normalization) — only [`PLAN_PREFIX`] stripping is
//! UserPromptSubmit-exclusive, since `PersistPlanApproval` never sees an
//! injected prompt to strip a prefix from in the first place.
//!
//! Never blocks (ADR-0001): every failure path — no prompt/no plan text, no
//! match, no `cwd`, not a git repo, unsafe session id, exhausted suffix ladder,
//! a subagent-context approval — exits silently via `CheckResult::allow()`. A
//! hook bug must not eat a user prompt or a same-session approval.

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
/// systematically misses, since `ExitPlanMode`'s raw `input.plan` never
/// carries either paragraph. Stripped by the same trailing-line-prefix
/// mechanism as `SUFFIX_LINE_PREFIX` — a line matching EITHER prefix pops.
const POINTER_PARAGRAPH_PREFIX: &str = "If you need specific details from before exiting plan mode";

/// Cap on the generated slug's length (before the date prefix).
const MAX_SLUG_LEN: usize = 60;

/// Slug used when the plan body carries no ATX heading.
const DEFAULT_SLUG: &str = "approved-plan";

/// Numeric suffixes tried after the bare stem, before the short-id fallback.
/// Combined with the bare stem this is 9 total candidates ("all nine
/// suffixes taken" in the plan doc), after which [`fallback_path`] is tried.
const NUMERIC_SUFFIXES: std::ops::RangeInclusive<u32> = 2..=9;

/// The frontmatter key carrying the plan body's hash — the tier-1 idempotency
/// anchor for every document this hook persists from birth (Design 18,
/// cadence-hooks#396's plan). Parsed only from the LEADING frontmatter block
/// ([`leading_frontmatter_block`]), never a whole-document scan: the body now
/// grows by design (checkbox ticks, appended `## Deviations`/`## Learnings`
/// sections) and may itself quote this exact key, so anchoring anywhere but
/// the bounded frontmatter prefix would let a body-authored decoy — or a
/// legitimately mutated body — spoof or defeat the match.
const FRONTMATTER_HASH_KEY: &str = "body_sha256:";

/// The legacy provenance line label carrying the plan body's hash, from the
/// plain-trailer format this hook wrote before frontmatter emission
/// (cadence-hooks#396). Only a TIER-2 fallback now — see [`file_matches_body`] —
/// kept so plan docs already on disk in the old format stay recognized as
/// re-fires rather than laddering into a duplicate `-2` file.
const PROVENANCE_HASH_LABEL: &str = "Plan-body-SHA256:";

/// Cap on a candidate document's size before [`file_matches_body`] declines to
/// consider it a re-fire. A living plan now grows by design over its
/// lifecycle (frontmatter status flips, ticked checklists, `## Deviations`/
/// `## Learnings` entries) — this cap is a defensive bound against a
/// pathological file, not a signal that growth itself is unexpected. It
/// remains generous against the measured corpus (single-digit KB to ~37 KiB):
/// this hook itself still writes a plan exactly once through `create_new` and
/// never appends, so ordinary growth is always EXTERNAL (another edit to a
/// file this hook already wrote) — a laddered sibling on the rare doc that
/// clears the cap, never a silently lost match.
const IDEMPOTENCY_MAX_FILE_BYTES: u64 = 1024 * 1024;

/// How many lines past an opening `---` [`frontmatter_extent`] will scan for
/// the closing fence. Real frontmatter runs well under this; the bound keeps
/// a body that merely opens with a thematic break from consuming the whole
/// document looking for a fence that was never there.
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
/// existing version constants; this one lives with its own writer. Bumped to
/// 2 (cameronsjo/cadence-hooks#396 review): `host` now carries the salted
/// [`crate::provenance::machine_digest`] instead of the raw hostname (matching
/// the committed frontmatter's own field two functions up), and `repo` is
/// dropped — `plan_path` is already repo-relative, so `repo` was a second,
/// separately-drifting way to say the same thing; confirmed no consumer
/// (`reconstruct-journey.py`) reads either field before dropping it.
const PLAN_LINKS_SCHEMA_VERSION: u32 = 2;

/// Persist an approved plan whose post-approval turn was wiped
/// (approve-and-clear, cross-session).
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

/// Persist an approved plan on same-session approval — no wipe, no injected
/// prompt, so [`PersistPlan`]'s prefix gate never fires (cadence-hooks#396).
pub struct PersistPlanApproval;

impl Check for PersistPlanApproval {
    fn name(&self) -> &str {
        "persist-plan-approval"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        let utc_now = cadence_hooks_core::time::utc_timestamp();
        let local_date = cadence_hooks_core::time::local_date();
        // Same narrow defense-in-depth as `PersistPlan` above: this fires on
        // every `ExitPlanMode` call, and a bug here must not eat the approval.
        std::panic::catch_unwind(|| run_persist_plan_approval(input, &utc_now, &local_date, &host))
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
    // Two ways the plan text arrives (cadence-hooks#672): the classic
    // prefix-carrying injected prompt, or — since the harness stopped routing
    // its auto-continuation injection through UserPromptSubmit at all — a
    // LATER, ordinary prompt whose transcript head carries the injected
    // `planContent` entry. The late path normalizes through the same
    // prefix-strip + suffix-strip so all three triggers hash byte-identical
    // bodies (Design 18).
    let (body, via_late_scan) = match prompt.strip_prefix(PLAN_PREFIX) {
        Some(rest) => (strip_trailing_suffix_lines_and_trim(rest), false),
        None => match input
            .transcript_path()
            .and_then(|tp| injected_plan_from_transcript(Path::new(tp)))
        {
            Some(injected) => {
                let rest = injected.strip_prefix(PLAN_PREFIX).unwrap_or(&injected);
                (strip_trailing_suffix_lines_and_trim(rest), true)
            }
            None => return CheckResult::allow(),
        },
    };
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
    let Some((repo_root, plans_dir)) = canonical_plans_dir(&repo_root) else {
        return CheckResult::allow();
    };
    // The late path re-fires on EVERY subsequent prompt of the session, and
    // the persist date may differ from the approval date — so the same-stem
    // claim ladder alone cannot recognize an earlier persist under an earlier
    // date. A dir-wide hash check closes that: any existing plan doc carrying
    // this body hash makes the late scan a silent idempotent skip. The
    // prefix path keeps its original semantics (one injection, one date).
    if via_late_scan && plans_dir_contains_hash(&plans_dir, &body_hash) {
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

    // The EXECUTING session's own transcript is structurally empty at this
    // point on a cross-session approve-and-clear wipe: the wipe IS a new
    // session, so its transcript has no assistant turn yet — `resolve_model`/
    // `resolve_harness` against it return `None`. Fall back to the APPROVING
    // parent's already-resolved model/harness (from the same scan that
    // resolved `approved_in`) rather than leaving the frontmatter fields
    // permanently unresolved on this trigger's most common path
    // (cameronsjo/cadence-hooks#396 review).
    let transcript_content = input
        .transcript_path()
        .and_then(|tp| cadence_hooks_core::transcript::read_tail(Path::new(tp)));
    let model = crate::warn_commit_provenance::resolve_model(transcript_content.as_deref())
        .or_else(|| parent.as_ref().and_then(|p| p.model.clone()));
    let harness = crate::warn_commit_provenance::resolve_harness(transcript_content.as_deref())
        .or_else(|| parent.as_ref().and_then(|p| p.harness_version.clone()));
    let branch = current_branch(cwd);

    let approved_in = parent_session_id
        .zip(parent_name.as_deref())
        .map(|(sid, name)| (name, sid));

    let fields = FrontmatterFields {
        updated: local_date,
        branch: branch.as_deref(),
        body_hash: &body_hash,
        own_name: &own_name,
        own_session_id: session_id,
        model: model.as_deref(),
        harness: harness.as_deref(),
        machine_digest: &machine_digest,
        approved_in,
    };
    let document = render_document(&fields, &body);

    let approved_label = parent_name.as_deref().unwrap_or("unknown");
    persist_and_nudge(
        &plans_dir,
        &stem,
        session_id,
        &body_hash,
        &document,
        utc_now,
        parent_session_id,
        session_id,
        &machine_digest,
        &repo_root,
        approved_label,
        &body,
    )
}

/// Testable core for the PostToolUse trigger. Same injected clock/host
/// discipline as [`run_persist_plan`].
pub fn run_persist_plan_approval(
    input: &HookInput,
    utc_now: &str,
    local_date: &str,
    host: &str,
) -> CheckResult {
    if input.tool_name() != Some("ExitPlanMode") {
        return CheckResult::allow();
    }
    // A subagent's own plan approval doesn't persist — only a top-level
    // session's approval does (the plan doc's Task 1 step 2). Deliberately
    // fail-CLOSED here, the opposite of this hook's usual fail-open posture:
    // persist only when `is_agent` is the EXPLICIT `Some(false)` AND
    // `agent_id` is absent. An absent/unrecognized `is_agent` (a future
    // payload-shape drift, or a stripped-down fixture) must not persist —
    // treating it as "not a subagent" would forge `approved_in` attribution
    // for a plan the top-level session never actually saw approved
    // (cameronsjo/cadence-hooks#396 review).
    let is_top_level_approval = input.tool_response.as_ref().and_then(|tr| tr.is_agent)
        == Some(false)
        && input.agent_id().is_none();
    if !is_top_level_approval {
        return CheckResult::allow();
    }
    // Plan source fallback chain (cadence-hooks#672): the 2.1.220-era probe
    // found the plan ONLY in `tool_response.plan`; the current harness also
    // fills `tool_input.plan` at call time and names the plan-store copy in
    // `planFilePath`. Response first (the historically reliable,
    // approval-side field), then the call-side text, then a bounded read of
    // the plan-store file — so a future harness that drops either inline
    // field degrades to the next source instead of a silent no-op.
    let raw_plan = match input
        .tool_response_plan()
        .or_else(|| input.tool_input_plan())
    {
        Some(inline) => inline.to_string(),
        None => match input.plan_file_path().and_then(read_plan_store_file) {
            Some(stored) => stored,
            None => return CheckResult::allow(),
        },
    };
    // Same normalization `run_persist_plan` applies to its extracted body
    // (Design 18): both triggers must hash byte-identical text so a plan
    // approved through either path is recognized as the same re-fire.
    let body = strip_trailing_suffix_lines_and_trim(&raw_plan);
    if body.is_empty() {
        return CheckResult::allow();
    }
    let Some(cwd) = input.cwd.as_deref() else {
        return CheckResult::allow();
    };
    let Some(repo_root) = crate::registry::repo_root(cwd) else {
        return CheckResult::allow();
    };
    let Some(session_id) = input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
    else {
        return CheckResult::allow();
    };

    let body_hash = sha256_hex(body.as_bytes());
    let slug = slugify(&body);
    let Some((repo_root, plans_dir)) = canonical_plans_dir(&repo_root) else {
        return CheckResult::allow();
    };
    let stem = format!("{local_date}-{slug}");

    let own_name = identity::generate_name(session_id);
    let machine_digest = crate::provenance::machine_digest(host);
    // Same-session approval: unlike `run_persist_plan`'s cross-session wipe,
    // the executing transcript here HAS just recorded the approving turn (no
    // wipe occurred), so it's a reliable model/harness source with no
    // sibling-transcript fallback needed.
    let transcript_content = input
        .transcript_path()
        .and_then(|tp| cadence_hooks_core::transcript::read_tail(Path::new(tp)));
    let model = crate::warn_commit_provenance::resolve_model(transcript_content.as_deref());
    let harness = crate::warn_commit_provenance::resolve_harness(transcript_content.as_deref());
    let branch = current_branch(cwd);

    let fields = FrontmatterFields {
        updated: local_date,
        branch: branch.as_deref(),
        body_hash: &body_hash,
        own_name: &own_name,
        own_session_id: session_id,
        model: model.as_deref(),
        harness: harness.as_deref(),
        machine_digest: &machine_digest,
        // Same-session approval: the approving identity IS the executing
        // session — no sibling-transcript scan needed (Design record item 2).
        approved_in: Some((own_name.as_str(), session_id)),
    };
    let document = render_document(&fields, &body);

    persist_and_nudge(
        &plans_dir,
        &stem,
        session_id,
        &body_hash,
        &document,
        utc_now,
        Some(session_id),
        session_id,
        &machine_digest,
        &repo_root,
        &own_name,
        &body,
    )
}

/// The current checked-out branch of the repo containing `cwd`, or `None`
/// when unresolvable (no git repo, detached HEAD, unreadable `HEAD` file).
/// Pure filesystem resolution ([`cadence_hooks_core::gitstate`]) — no `git`
/// subprocess spawn on this every-turn/every-approval hot path.
fn current_branch(cwd: &str) -> Option<String> {
    cadence_hooks_core::gitstate::GitState::resolve(Path::new(cwd)).and_then(|gs| gs.branch)
}

/// Resolve `<repo_root>/docs/plans`, creating it if needed, and return its
/// canonical path alongside the canonical `repo_root` — but only when the
/// canonical plans dir actually nests under the canonical repo root. `None`
/// on any I/O failure, or when it DOESN'T nest: a `docs/plans` (or an
/// ancestor, e.g. a symlinked `docs/`) pointing outside the checkout would
/// otherwise let a plan write escape the repo entirely (cameronsjo/cadence-hooks#396
/// review) — the same "never trust a path without checking where it actually
/// resolves" discipline `GitState::resolve` applies to `.git`. Both returned
/// paths are canonical, so a caller using them for the write target and the
/// `plan_path` prefix-strip stays internally consistent.
fn canonical_plans_dir(repo_root: &Path) -> Option<(PathBuf, PathBuf)> {
    let plans_dir = repo_root.join("docs").join("plans");
    fs::create_dir_all(&plans_dir).ok()?;
    let canonical_repo_root = repo_root.canonicalize().ok()?;
    let canonical_plans_dir = plans_dir.canonicalize().ok()?;
    canonical_plans_dir
        .starts_with(&canonical_repo_root)
        .then_some((canonical_repo_root, canonical_plans_dir))
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

/// Bounded read of the harness plan-store file named by an `ExitPlanMode`
/// payload's `filePath`/`planFilePath` — the last-resort plan source in
/// [`run_persist_plan_approval`]'s fallback chain (cadence-hooks#672).
/// `None` on any I/O failure, a non-regular target, or a file over
/// [`IDEMPOTENCY_MAX_FILE_BYTES`] — every ambiguity degrades to "no plan"
/// (ADR-0001), never a partial read persisted as if complete.
fn read_plan_store_file(path: &str) -> Option<String> {
    use std::io::Read as _;
    let path = Path::new(path);
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let mut content = String::new();
    file.take(IDEMPOTENCY_MAX_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .ok()?;
    if content.len() as u64 > IDEMPOTENCY_MAX_FILE_BYTES || content.trim().is_empty() {
        return None;
    }
    Some(content)
}

/// How much of the transcript's HEAD [`injected_plan_from_transcript`] will
/// read looking for the auto-continuation entry. The injection is the very
/// first user entry of a fresh post-`/clear` session, so it sits well inside
/// this window even under large SessionStart context; a bounded head read
/// (not [`cadence_hooks_core::transcript::read_tail`]) because a long session
/// pushes the head OUT of any tail window while the entry never moves.
const INJECTED_PLAN_SCAN_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Line cap for the same scan — the entry sits in the first handful of lines;
/// the cap keeps a pathological many-tiny-lines file from turning the
/// byte bound into a line-count problem.
const INJECTED_PLAN_SCAN_MAX_LINES: usize = 200;

/// The harness's auto-continuation plan injection from the transcript head,
/// if present: a top-level `type: "user"` entry carrying non-empty
/// `planContent` (the BARE plan body — the prefix/suffix chrome lives only in
/// the message text) and not marked `isSidechain` (a subagent's plan is not
/// this session's to persist). First match wins; a fresh post-`/clear`
/// session carries at most one. Live payload shape: cadence-hooks#672
/// (session beffcf50, claude-code 2.1.227).
fn injected_plan_from_transcript(transcript_path: &Path) -> Option<String> {
    use std::io::Read as _;
    let file = fs::File::open(transcript_path).ok()?;
    let reader = BufReader::new(file.take(INJECTED_PLAN_SCAN_MAX_BYTES));
    for line in reader.lines().take(INJECTED_PLAN_SCAN_MAX_LINES) {
        let Ok(line) = line else { return None };
        // Substring pre-filter before any JSON parse — same discipline as
        // `find_parent`'s sibling scan.
        if !line.contains("\"planContent\"") {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("user") {
            continue;
        }
        if value.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(plan) = value
            .get("planContent")
            .and_then(Value::as_str)
            .filter(|p| !p.trim().is_empty())
        {
            return Some(plan.to_string());
        }
    }
    None
}

/// Cap on how many `docs/plans` entries [`plans_dir_contains_hash`] will
/// check. The measured corpus tops out in the low hundreds; the cap bounds a
/// pathological directory without ever silently skipping a real one below it.
const DIR_HASH_SCAN_MAX_FILES: usize = 512;

/// Does any markdown document in `plans_dir` already carry `body_hash`?
/// Per-file work is [`file_matches_body`]'s bounded read. Fail-open: an
/// unreadable dir reads as "no match" and lets the claim ladder — which
/// dedupes within the same stem — take over.
fn plans_dir_contains_hash(plans_dir: &Path, body_hash: &str) -> bool {
    let Ok(entries) = fs::read_dir(plans_dir) else {
        return false;
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "md"))
        .take(DIR_HASH_SCAN_MAX_FILES)
        .any(|e| file_matches_body(&e.path(), body_hash))
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

/// Byte offsets of a leading YAML frontmatter block: `(content_start,
/// content_end, body_start)` — `content_start..content_end` is the raw text
/// between the two `---` fences (no fence lines themselves), `body_start` is
/// where the document's body begins (just past the closing fence line).
///
/// Engages ONLY when the very first line is exactly `---` (after trimming),
/// then scans forward at most [`FRONTMATTER_SCAN_MAX_LINES`] lines for the
/// closing fence. **No closing fence in the window → `None`**, so a plan body
/// that opens with a thematic break can at worst produce a hash mismatch
/// (which ladders, the pre-existing behavior) and never a false match.
fn frontmatter_extent(doc: &str) -> Option<(usize, usize, usize)> {
    let mut lines = doc.split_inclusive('\n');
    let first = lines.next()?;
    if first.trim() != "---" {
        return None;
    }
    let content_start = first.len();
    let mut offset = content_start;
    for line in lines.take(FRONTMATTER_SCAN_MAX_LINES) {
        if line.trim() == "---" {
            return Some((content_start, offset, offset + line.len()));
        }
        offset += line.len();
    }
    None
}

/// Strip a leading YAML frontmatter block, returning the document body.
/// A thin wrapper over [`frontmatter_extent`] — see its doc for engagement
/// rules. Returns `doc` unchanged when no block is found.
fn strip_leading_frontmatter(doc: &str) -> &str {
    match frontmatter_extent(doc) {
        Some((_, _, body_start)) => &doc[body_start..],
        None => doc,
    }
}

/// The raw text of a leading YAML frontmatter block (between the fences,
/// exclusive), or `None` when the document doesn't open with one. Thin
/// wrapper over [`frontmatter_extent`] sharing its single scan implementation
/// with [`strip_leading_frontmatter`].
///
/// `pub(crate)`: [`crate::plan_scan`] reuses this exact bounded scan to read
/// `docs/plans/*.md` frontmatter at `session start` — the same
/// first-fence/[`FRONTMATTER_SCAN_MAX_LINES`]-window discipline this hook
/// already relies on for idempotency, so the two readers can never disagree
/// on where a plan's frontmatter ends (Design 2's "one schema, one scanner").
pub(crate) fn leading_frontmatter_block(doc: &str) -> Option<&str> {
    frontmatter_extent(doc).map(|(start, end, _)| &doc[start..end])
}

/// Does the document at `path` carry the plan body `body_hash` identifies?
///
/// Three sources answer that, tried in order, from a single capped read:
///
/// 1. The parsed LEADING frontmatter block's [`FRONTMATTER_HASH_KEY`]
///    (`body_sha256:`) — the format every document persisted since
///    cadence-hooks#396 carries from birth. Bounded to the frontmatter
///    prefix, never a whole-document scan: a living plan's body grows by
///    design (ticked checkboxes, appended `## Deviations`/`## Learnings`),
///    and may itself quote this exact key — anchoring anywhere else would let
///    a body-authored decoy spoof the match, OR let a legitimately mutated
///    body wrongly defeat it (Design 18).
/// 2. No frontmatter key (a document predating cadence-hooks#396, or a
///    backfilled plan carrying only ad-hoc frontmatter) — the LAST
///    `Plan-body-SHA256:` legacy trailer line, if present. Anchored on the
///    last occurrence, not the first, so a plan body that itself embeds a
///    decoy line of that exact shape can never spoof the check.
/// 3. Neither marker — a document neither trigger wrote, such as a backfilled
///    plan carrying only frontmatter with no hash key (cadence-hooks#399). The
///    body is recomputed the way both triggers compute it: strip leading
///    frontmatter, strip the trailing harness suffix lines and trim, hash.
///
/// Only an equality returns `true`; every ambiguity (unreadable, over
/// [`IDEMPOTENCY_MAX_FILE_BYTES`], hash differs) returns `false` and lets the
/// suffix ladder run.
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

    if let Some(recorded) = leading_frontmatter_block(&content).and_then(|fm| {
        fm.lines()
            .find_map(|l| l.strip_prefix(FRONTMATTER_HASH_KEY))
    }) {
        return yaml_unquote(recorded.trim()) == body_hash;
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

/// The `ExitPlanMode` plan text on one transcript line, plus the approving
/// turn's model (`message.model`) and harness version (top-level `version`),
/// if `line` is an assistant message carrying that tool call. `model`/
/// `harness_version` are `None` when the matched line doesn't carry them.
/// Mirrors `cadence_hooks_core::transcript::line_is_polish_skill_use`'s
/// traversal.
///
/// Restored (cameronsjo/cadence-hooks#396 review): the executing session's
/// own transcript is structurally empty at the moment `run_persist_plan`
/// runs on a cross-session approve-and-clear wipe (the wipe IS a new,
/// just-started session — its transcript has no assistant turn yet), so
/// `crate::warn_commit_provenance::resolve_model`/`resolve_harness` against
/// it always return `None` there. The APPROVING parent's transcript — the one
/// this scan already walks to resolve `approved_in` — is the only source that
/// reliably carries a populated `model`/`version` for that path.
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

/// The approving sibling transcript [`find_parent`] resolves: its session id,
/// plus the approving turn's model/harness version — the fallback source for
/// [`FrontmatterFields::model`]/`harness` on a cross-session wipe (see
/// [`ExitPlanModeMatch`]'s doc for why the executing transcript can't supply
/// them there).
#[derive(Debug, PartialEq, Eq)]
struct ParentMatch {
    session_id: String,
    model: Option<String>,
    harness_version: Option<String>,
}

/// Scan `transcript_path`'s sibling directory for the transcript whose
/// `ExitPlanMode` plan text — normalized by the same suffix-strip-and-trim
/// applied to the injected prompt — hashes to `target_hash`. Newest-first,
/// bounded to [`PARENT_SCAN_MAX_FILES`] siblings no older than
/// [`PARENT_SCAN_MAX_AGE`] and no larger than [`PARENT_SCAN_MAX_FILE_BYTES`],
/// streamed line-by-line (never loading a whole sibling into memory) with a
/// substring pre-filter on each line before any JSON parse. `now` is the
/// caller's `SystemTime::now()`, threaded through for testability without a
/// frozen clock. Returns the matched sibling's session id on the first exact
/// match — never a fuzzy guess — and only when its file stem passes
/// [`identity::is_safe_session_id`]; a match against a hostile-named sibling
/// is treated as no-match (`unknown`), since the returned id flows raw into
/// the provenance text and the linkage row.
fn find_parent(transcript_path: &Path, target_hash: &str, now: SystemTime) -> Option<ParentMatch> {
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
                let session_id = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .filter(|s| identity::is_safe_session_id(s))?;
                return Some(ParentMatch {
                    session_id,
                    model: exit_plan.model,
                    harness_version: exit_plan.harness_version,
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Frontmatter (Design 2 / Design 18) + shared persist tail (Approach step 5)
// ---------------------------------------------------------------------------

/// Fields resolved for a newly persisted plan's frontmatter — the
/// execution-zone metadata a resume/scan/outro reconciliation reads (the
/// plan-as-living-document lifecycle's Design record item 2). An unresolved
/// optional field is OMITTED from the render entirely, never written as a
/// placeholder (`unknown`, an empty string) — silence, not a guess.
struct FrontmatterFields<'a> {
    /// Local date this document was (first) persisted — `updated:`.
    updated: &'a str,
    /// The cwd's current checked-out branch, if resolvable.
    branch: Option<&'a str>,
    /// The plan body's SHA-256 hex digest — the tier-1 idempotency anchor.
    body_hash: &'a str,
    /// The executing session's generated display name.
    own_name: &'a str,
    /// The executing session's id.
    own_session_id: &'a str,
    /// The executing session's model, resolved from its own transcript tail.
    model: Option<&'a str>,
    /// The executing session's harness version (transcript tail, or the
    /// `AI_AGENT` env fallback).
    harness: Option<&'a str>,
    /// Salted, truncated machine digest (never the raw hostname).
    machine_digest: &'a str,
    /// The approving session's `(name, session_id)` — identical to
    /// `(own_name, own_session_id)` on same-session approval, the
    /// `find_parent`-resolved sibling on a cross-session approve-and-clear
    /// wipe, or `None` when no approving parent was found.
    approved_in: Option<(&'a str, &'a str)>,
}

/// Render `s` as a double-quoted YAML scalar: `\` escaped first, then `"` —
/// order matters, so quote-escaping never re-escapes a backslash the first
/// pass just introduced. Every frontmatter value goes through this
/// (cameronsjo/cadence-hooks#396 review): uniform quoting means a reader never
/// needs per-field heuristics for which lines are quoted, and it defuses any
/// transcript-sourced free-text value (model, harness, branch) that happens
/// to embed a literal `"` or `\` from breaking the block's YAML shape.
fn yaml_quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Reverse of [`yaml_quote`]: strip a well-formed double-quoted YAML scalar's
/// surrounding quotes and unescape `\"`/`\\`. A value that ISN'T
/// double-quoted (a hand-edited frontmatter line, or a doc from before this
/// fold started quoting) passes through unchanged — this hook always emits
/// quoted values now, but the idempotency reader must not choke on an older
/// or hand-edited file.
///
/// `pub(crate)`: [`crate::plan_scan`] reuses this exact unescaper for the
/// same double-quoted values at `session start` — one implementation of
/// `yaml_quote`'s reader half, not two that could drift apart on escaping
/// order.
pub(crate) fn yaml_unquote(s: &str) -> String {
    let Some(inner) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return s.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Render the frontmatter block for a newly persisted plan.
///
/// `status: "in-flight"` is a fixed constant: this hook only ever fires at
/// the moment a plan is approved, so a freshly persisted document is never
/// anything else. Reserved keys the living-plan lifecycle owns for a later
/// consumer — `next`, `pr`, `card`, `blocked` — are never emitted here (Task 1
/// step 3 of the plan-as-living-document lifecycle plan); a session or the
/// scanner fills those in on a later touch.
///
/// Free-text fields sourced from the transcript (`model`, `harness`) or the
/// filesystem (`branch`) are passed through [`identity::sanitize_field`] —
/// the same discipline `warn_commit_provenance`'s nudge applies to the same
/// two fields — before interpolation, since none of the three come from a
/// value this crate itself generated or validated. Every value, sanitized or
/// not, is then [`yaml_quote`]d.
fn render_frontmatter(f: &FrontmatterFields) -> String {
    let mut lines = vec![
        "---".to_string(),
        format!("status: {}", yaml_quote("in-flight")),
        format!("updated: {}", yaml_quote(f.updated)),
    ];
    if let Some(b) = f.branch {
        lines.push(format!(
            "branch: {}",
            yaml_quote(&identity::sanitize_field(b, identity::MAX_FIELD_DISPLAY))
        ));
    }
    lines.push(format!(
        "{FRONTMATTER_HASH_KEY} {}",
        yaml_quote(f.body_hash)
    ));
    lines.push(format!("session: {}", yaml_quote(f.own_name)));
    lines.push(format!("session_id: {}", yaml_quote(f.own_session_id)));
    if let Some(m) = f.model {
        lines.push(format!(
            "model: {}",
            yaml_quote(&identity::sanitize_field(m, identity::MAX_FIELD_DISPLAY))
        ));
    }
    if let Some(h) = f.harness {
        lines.push(format!(
            "harness: {}",
            yaml_quote(&format!(
                "claude-code {}",
                identity::sanitize_field(h, identity::MAX_FIELD_DISPLAY)
            ))
        ));
    }
    lines.push(format!("machine: {}", yaml_quote(f.machine_digest)));
    if let Some((name, sid)) = f.approved_in {
        lines.push(format!("approved_in: {}", yaml_quote(name)));
        lines.push(format!("approved_session_id: {}", yaml_quote(sid)));
    }
    lines.push("---".to_string());
    lines.join("\n")
}

/// The full document written to disk: frontmatter, a blank line, then the
/// plan body, trailing-newline terminated.
fn render_document(f: &FrontmatterFields, body: &str) -> String {
    format!("{}\n\n{body}\n", render_frontmatter(f))
}

/// The one static sentence appended to the persistence nudge when the
/// approved plan carries no settled `Panel:` line (cameronsjo/cadence-hooks#623).
/// Static by design: committed plan content is untrusted input, so the nudge
/// never echoes any of it — detection is artifact-anchored (the line lives in
/// the plan document, surviving the approve-and-clear session boundary that
/// killed session-scoped markers, cameronsjo/cadence#578) and warn-tier only
/// (a nudge needs no trust root, unlike the gate cameronsjo/cadence#392
/// rejected).
const PANEL_GATE_NUDGE: &str = "panel gate: this plan carries no settled Panel: line — run the \
     plan-review panel before implementing, fold findings, or write \"Panel: none — <reason>\" \
     (cadence:attune → plan-review-panel).";

/// True when the plan body carries a settled `Panel:` line — anchored at line
/// start, in exactly one of the plan template's two settled forms:
///
/// - `Panel: <seats> ran — <counts…>` (a panel ran; both sides non-empty)
/// - `Panel: none — <reason>` (the absence assertion; non-empty reason)
///
/// The separator tolerates what a human actually types: em dash (the
/// template's canonical form), en dash, `--`, or a plain hyphen — a
/// hand-written `Panel: none - reason` states the settled fact unambiguously,
/// and hardcoding U+2014 would fire a false nudge on it (code review of this
/// change).
///
/// Anything else — no `Panel:` line at all, a `Panel: pending…` placeholder,
/// or a `## Panel review` heading with no settled line — is unsettled. The
/// line-start anchor plus the required `Panel: ` prefix means a `## Panel`
/// heading can never false-match.
///
/// **First match in document order decides** — the `Driver:` stamp's
/// discipline (plan-pipeline-conventions §4/§5): the plan template's `## Panel`
/// stanza precedes the task body, so the stanza's own line is judged, and a
/// quoted `Panel: … ran — …` example later in the body can neither satisfy
/// the gate (the accidental-forgery hole a whole-body `any()` scan would
/// open) nor contradict the stanza. Lines inside fenced code blocks
/// (``` / ~~~ toggles, indentation-tolerant) and block quotes (`>`) are
/// skipped before the first-match rule applies — a fenced or quoted example
/// in a plan with no stanza at all must not mint a settled verdict (security
/// review of this change; same class as the quoted-example hole above). The
/// fence tracker is deliberately naive — it toggles without matching fence
/// lengths — which errs toward skipping ambiguous lines: on a malformed
/// document the failure mode is a spurious nudge (fail-loud), never a
/// suppressed one. Detection only; the caller appends the static
/// [`PANEL_GATE_NUDGE`], never any matched text.
fn panel_line_settled(body: &str) -> bool {
    let mut in_fence = false;
    let Some(rest) = body.lines().find_map(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            return None;
        }
        if in_fence || line.starts_with('>') {
            return None;
        }
        line.strip_prefix("Panel: ")
    }) else {
        return false;
    };
    // Dash tolerance: `--` must be tried before `-` or the second hyphen
    // leaks into the text it precedes.
    fn strip_dash(s: &str) -> Option<&str> {
        let s = s.trim_start();
        ["—", "–", "--", "-"].iter().find_map(|d| s.strip_prefix(d))
    }
    if let Some(after_none) = rest.strip_prefix("none") {
        return strip_dash(after_none).is_some_and(|reason| !reason.trim().is_empty());
    }
    if let Some((seats, tail)) = rest.split_once(" ran ") {
        return !seats.trim().is_empty()
            && strip_dash(tail).is_some_and(|counts| !counts.trim().is_empty());
    }
    false
}

/// The shared tail both triggers converge on once each has resolved its own
/// body/session/approval fields: claim a target, append the linkage row,
/// render the nudge. Never overwrites anything (see [`claim_target`]).
#[allow(clippy::too_many_arguments)]
fn persist_and_nudge(
    plans_dir: &Path,
    stem: &str,
    session_id: &str,
    body_hash: &str,
    document: &str,
    utc_now: &str,
    parent_session_id: Option<&str>,
    child_session_id: &str,
    machine_digest: &str,
    repo_root: &Path,
    approved_label: &str,
    plan_body: &str,
) -> CheckResult {
    let path = match claim_target(plans_dir, stem, session_id, body_hash, document) {
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
            .strip_prefix(repo_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned()),
    );
    append_plan_links_row(&plan_links_row(
        utc_now,
        parent_session_id,
        child_session_id,
        machine_digest,
        &plan_path_rel,
        body_hash,
    ));

    let mut nudge = format!(
        "Approved plan persisted to {} (approved in {approved_label}). Verify placement, then \
         commit it (explicit-path git add) before implementation.",
        path.display()
    );
    // Evaluated only after the claim succeeded: the persistence write must
    // never depend on the detector — a future panic here eats one nudge's
    // sentence, never the persist (security review of this change).
    if !panel_line_settled(plan_body) {
        nudge.push(' ');
        nudge.push_str(PANEL_GATE_NUDGE);
    }
    CheckResult::nudge(nudge)
}

// ---------------------------------------------------------------------------
// Linkage row (Approach step 5)
// ---------------------------------------------------------------------------

/// Schema v2 (cameronsjo/cadence-hooks#396 review; v1 carried a raw `host`
/// hostname and a separate `repo` field). `machine` is the salted
/// [`crate::provenance::machine_digest`] — the same doctrine fix (cadence#248)
/// the committed frontmatter already applies, now consistent across BOTH the
/// committed artifact and this local-only telemetry stream. `repo` is
/// dropped: `plan_path` is already repo-relative, so `repo` was a second,
/// independently-drifting way to say the same thing. Confirmed no consumer
/// (`reconstruct-journey.py`, which reads only `parent_session_id`,
/// `body_sha256`, and `plan_path`) depends on either the old `host` or `repo`
/// fields before making this change.
fn plan_links_row(
    utc_now: &str,
    parent_session_id: Option<&str>,
    child_session_id: &str,
    machine_digest: &str,
    plan_path: &str,
    body_hash: &str,
) -> Value {
    serde_json::json!({
        "schemaVersion": PLAN_LINKS_SCHEMA_VERSION,
        "ts": utc_now,
        "parent_session_id": parent_session_id,
        "child_session_id": child_session_id,
        "machine": machine_digest,
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
    use cadence_hooks_core::{ToolInput, ToolResponse};
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
        // the anchor is load-bearing.
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
        // A document neither trigger wrote — backfill frontmatter, no
        // hash key and no legacy trailer. The body must still be recognized
        // (cadence-hooks#399).
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

    // --- idempotency: frontmatter tier-1 anchor (Design 18) ---

    fn frontmatter_doc_with_hash(hash: &str, body: &str) -> String {
        format!("---\nstatus: in-flight\nbody_sha256: {hash}\n---\n\n{body}\n")
    }

    #[test]
    fn file_matches_body_frontmatter_key_is_tier_one() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nbody text";
        let hash = sha256_hex(body.as_bytes());
        fs::write(&path, frontmatter_doc_with_hash(&hash, body)).unwrap();
        assert!(file_matches_body(&path, &hash));
        assert!(!file_matches_body(&path, "some-other-hash"));
    }

    #[test]
    fn file_matches_body_frontmatter_key_matches_the_actual_quoted_emission() {
        // `frontmatter_doc_with_hash` above uses a bare (unquoted) value —
        // proving backward-compat with hand-edited/pre-quoting frontmatter.
        // This test uses the value shape `render_frontmatter` ACTUALLY emits
        // (double-quoted, cameronsjo/cadence-hooks#396 review) end to end.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nbody text";
        let hash = sha256_hex(body.as_bytes());
        let doc = format!(
            "---\nstatus: \"in-flight\"\nbody_sha256: {}\n---\n\n{body}\n",
            yaml_quote(&hash)
        );
        fs::write(&path, doc).unwrap();
        assert!(file_matches_body(&path, &hash));
    }

    #[test]
    fn file_matches_body_frontmatter_tier_wins_over_a_differing_legacy_trailer() {
        // A file carrying BOTH a frontmatter `body_sha256` key AND a
        // differing legacy `Plan-body-SHA256:` trailer line — the frontmatter
        // tier must win unconditionally, never fall through to consider the
        // trailer (cameronsjo/cadence-hooks#396 review). This shape shouldn't
        // arise from either trigger's own writes, but the precedence must
        // hold regardless of how such a file came to exist (hand-edit, a
        // future migration script, etc.).
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nbody text";
        let frontmatter_hash = sha256_hex(body.as_bytes());
        let legacy_hash = "a-completely-different-legacy-hash";
        let doc = format!(
            "---\nstatus: \"in-flight\"\nbody_sha256: {}\n---\n\n{body}\n\n---\n\nPlan-body-SHA256: {legacy_hash}\n",
            yaml_quote(&frontmatter_hash)
        );
        fs::write(&path, doc).unwrap();

        assert!(
            file_matches_body(&path, &frontmatter_hash),
            "the frontmatter hash must match despite the differing trailer"
        );
        assert!(
            !file_matches_body(&path, legacy_hash),
            "the legacy trailer's hash must NOT match — tier 1 wins unconditionally, tier 2 is never consulted"
        );
    }

    #[test]
    fn file_matches_body_recognizes_mutated_body_via_frontmatter_key() {
        // The exact Design-18 scenario: a plan persisted once, then its BODY
        // is mutated in place (checkbox ticked, a `## Deviations` entry
        // appended) while the frontmatter block is left untouched. A re-fire
        // of the SAME original approval must still recognize this as the plan
        // it already wrote — recomputing against the current (mutated) body
        // would wrongly ladder to a `-2` duplicate.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let original_body = "# Title\n\n- [ ] Task one";
        let hash = sha256_hex(original_body.as_bytes());
        fs::write(&path, frontmatter_doc_with_hash(&hash, original_body)).unwrap();

        let mutated = format!(
            "---\nstatus: in-flight\nbody_sha256: {hash}\n---\n\n# Title\n\n- [x] Task one\n\n\
             ## Deviations\n\nnone\n"
        );
        fs::write(&path, mutated).unwrap();

        assert!(
            file_matches_body(&path, &hash),
            "the frontmatter key must anchor the match even though the body mutated"
        );
    }

    #[test]
    fn file_matches_body_frontmatter_key_not_spoofed_by_body_decoy() {
        // A body that itself quotes `body_sha256:` (e.g. explaining this exact
        // mechanism) must not be read as the frontmatter key — only the
        // bounded LEADING frontmatter block is ever scanned for it.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.md");
        let body = "# Title\n\nThe idempotency reader parses a leading `body_sha256: decoy` key.";
        let hash = sha256_hex(body.as_bytes());
        fs::write(&path, frontmatter_doc_with_hash(&hash, body)).unwrap();
        assert!(
            file_matches_body(&path, &hash),
            "the real frontmatter key still matches"
        );
        assert!(
            !file_matches_body(&path, "decoy"),
            "a body-authored decoy key must never spoof the match"
        );
    }

    #[test]
    fn leading_frontmatter_block_returns_none_without_a_fence() {
        assert_eq!(leading_frontmatter_block("# Title\n\nbody"), None);
    }

    // --- canonical_plans_dir: symlink-escape guard ---

    #[test]
    fn canonical_plans_dir_resolves_normally_when_nested() {
        let repo = TempDir::new().unwrap();
        let (canonical_repo, canonical_plans) =
            canonical_plans_dir(repo.path()).expect("plans dir resolves under a plain repo root");
        assert!(canonical_plans.starts_with(&canonical_repo));
        assert!(
            canonical_plans.ends_with("docs/plans") || canonical_plans.ends_with("docs\\plans")
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_plans_dir_refuses_a_symlinked_docs_escaping_the_repo() {
        // A `docs/` symlink pointing outside the checkout (planted by a
        // malicious commit, or a stray dev-machine symlink) must not let a
        // plan write escape the repo root entirely (cameronsjo/cadence-hooks#396
        // review).
        let repo = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("docs")).unwrap();

        assert!(
            canonical_plans_dir(repo.path()).is_none(),
            "a docs/ symlink escaping the repo root must be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_persist_plan_never_writes_through_a_symlinked_docs_escaping_the_repo() {
        // End-to-end: the same escape attempt must never reach a write, not
        // just fail the unit-level helper in isolation.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("docs")).unwrap();
        let cwd = tmp.path().to_string_lossy().into_owned();

        let input = make_user_prompt_submit(
            "sid12345",
            "Implement the following plan:\n\n# X\n\nbody",
            &cwd,
            &tmp.path().join("sid12345.jsonl").to_string_lossy(),
        );
        let r = run_persist_plan(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !outside
                .path()
                .join("plans")
                .join("2026-07-20-x.md")
                .exists(),
            "nothing must be written outside the repo via the symlinked docs/"
        );
    }

    // --- cross-trigger hash normalization (Design 18) ---

    #[test]
    fn cross_trigger_normalization_hashes_match() {
        // The UserPromptSubmit path strips PLAN_PREFIX then normalizes; the
        // PostToolUse path consumes `tool_response.plan` raw and normalizes
        // the SAME way. Both must land on byte-identical text so a plan
        // approved through either path hashes the same.
        let prompt = format!(
            "{PLAN_PREFIX}\n\n# Title\n\nbody text\n\nIf this plan can be broken down into \
             discrete units of work, consider using the Agent tool to dispatch them."
        );
        let user_prompt_submit_body =
            strip_trailing_suffix_lines_and_trim(prompt.strip_prefix(PLAN_PREFIX).unwrap());

        // ExitPlanMode's own tool_input.plan never carries the harness prefix
        // or suffix — but may carry an incidental trailing blank line.
        let raw_exit_plan_mode_text = "# Title\n\nbody text\n\n";
        let post_tool_use_body = strip_trailing_suffix_lines_and_trim(raw_exit_plan_mode_text);

        assert_eq!(user_prompt_submit_body, post_tool_use_body);
        assert_eq!(
            sha256_hex(user_prompt_submit_body.as_bytes()),
            sha256_hex(post_tool_use_body.as_bytes())
        );
    }

    // --- frontmatter rendering ---

    fn base_fields<'a>(body_hash: &'a str, machine_digest: &'a str) -> FrontmatterFields<'a> {
        FrontmatterFields {
            updated: "2026-07-25",
            branch: None,
            body_hash,
            own_name: "own-name",
            own_session_id: "own-sid",
            model: None,
            harness: None,
            machine_digest,
            approved_in: None,
        }
    }

    #[test]
    fn render_frontmatter_omits_unresolved_optional_fields() {
        let fields = base_fields("hash", "digest");
        let fm = render_frontmatter(&fields);
        assert!(fm.starts_with("---\nstatus: \"in-flight\"\nupdated: \"2026-07-25\"\n"));
        assert!(fm.contains("body_sha256: \"hash\""));
        assert!(fm.contains("session: \"own-name\""));
        assert!(fm.contains("session_id: \"own-sid\""));
        assert!(fm.contains("machine: \"digest\""));
        assert!(fm.ends_with("---"));
        assert!(
            !fm.contains("branch:"),
            "unresolved branch is omitted: {fm}"
        );
        assert!(!fm.contains("model:"), "unresolved model is omitted: {fm}");
        assert!(
            !fm.contains("harness:"),
            "unresolved harness is omitted: {fm}"
        );
        assert!(
            !fm.contains("approved_in:"),
            "unresolved approved_in is omitted: {fm}"
        );
        assert!(!fm.contains("next:"), "next: is reserved, never emitted");
        assert!(!fm.contains("pr:"), "pr: is reserved, never emitted");
        assert!(!fm.contains("card:"), "card: is reserved, never emitted");
        assert!(
            !fm.contains("blocked:"),
            "blocked: is reserved, never emitted"
        );
    }

    #[test]
    fn render_frontmatter_includes_every_resolved_field() {
        let mut fields = base_fields("hash", "digest");
        fields.branch = Some("feat/x");
        fields.model = Some("claude-fable-5");
        fields.harness = Some("2.1.220");
        fields.approved_in = Some(("parent-name", "parent-sid"));
        let fm = render_frontmatter(&fields);
        assert!(fm.contains("branch: \"feat/x\""));
        assert!(fm.contains("model: \"claude-fable-5\""));
        assert!(fm.contains("harness: \"claude-code 2.1.220\""));
        assert!(fm.contains("approved_in: \"parent-name\""));
        assert!(fm.contains("approved_session_id: \"parent-sid\""));
    }

    #[test]
    fn render_frontmatter_escapes_quotes_and_backslashes_in_free_text_fields() {
        // Transcript-sourced free text (model/harness/branch) is not
        // validated by this hook — a value embedding a literal `"` or `\`
        // must not break the block's YAML shape (cameronsjo/cadence-hooks#396
        // review).
        let mut fields = base_fields("hash", "digest");
        fields.model = Some(r#"weird"model\name"#);
        let fm = render_frontmatter(&fields);
        assert!(
            fm.contains(r#"model: "weird\"model\\name""#),
            "quotes and backslashes escaped in emission: {fm}"
        );
    }

    #[test]
    fn render_document_places_body_after_the_closing_fence() {
        let fields = base_fields("hash", "digest");
        let doc = render_document(&fields, "# Title\n\nbody text");
        let (frontmatter, body) = doc
            .split_once("---\n\n")
            .expect("closing fence + blank line");
        assert!(frontmatter.starts_with("---\nstatus: \"in-flight\""));
        assert_eq!(body, "# Title\n\nbody text\n");
    }

    #[test]
    fn yaml_quote_and_unquote_round_trip() {
        for value in ["plain", r#"has "quotes""#, r"has\backslash", ""] {
            assert_eq!(yaml_unquote(&yaml_quote(value)), value);
        }
    }

    #[test]
    fn yaml_unquote_passes_through_an_unquoted_value() {
        // Backward compatibility: a hand-edited or pre-quoting-era
        // frontmatter value isn't wrapped in quotes at all.
        assert_eq!(yaml_unquote("bare-value"), "bare-value");
    }

    // --- provenance: parent resolution ---

    /// `model`/`harness_version` model the assistant line's `message.model`
    /// and top-level `version` — both `None` reproduces an older transcript
    /// shape carrying neither.
    fn exit_plan_mode_line(
        plan: &str,
        model: Option<&str>,
        harness_version: Option<&str>,
    ) -> String {
        let mut message = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "tool_use", "name": "ExitPlanMode", "input": {"plan": plan}}],
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
            Some(ParentMatch {
                session_id: "parent-session-id".to_string(),
                model: None,
                harness_version: None,
            })
        );
    }

    #[test]
    fn find_parent_extracts_model_and_harness_version_from_matched_line() {
        // Real transcripts stamp the approving assistant line with both
        // `message.model` and a top-level `version` — this is the sole
        // source `run_persist_plan` falls back to when the EXECUTING
        // session's own (structurally empty, on a cross-session wipe)
        // transcript resolves neither (cameronsjo/cadence-hooks#396 review).
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
            Some(ParentMatch {
                session_id: "parent-session-id".to_string(),
                model: Some("claude-fable-5".to_string()),
                harness_version: Some("2.1.214".to_string()),
            })
        );
    }

    #[test]
    fn find_parent_missing_model_and_harness_version_is_gracefully_none() {
        // Older transcript lines (or a stripped-down fixture) may carry
        // neither field — the match must still resolve, with both absent.
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

    // --- linkage row schema ---

    #[test]
    fn plan_links_row_has_expected_schema() {
        let row = plan_links_row(
            "2026-07-20T00:00:00Z",
            Some("parent-sid"),
            "child-sid",
            "digest",
            "docs/plans/2026-07-20-x.md",
            "hash",
        );
        assert_eq!(row["schemaVersion"], 2);
        assert_eq!(row["ts"], "2026-07-20T00:00:00Z");
        assert_eq!(row["parent_session_id"], "parent-sid");
        assert_eq!(row["child_session_id"], "child-sid");
        assert_eq!(row["machine"], "digest");
        assert_eq!(row["plan_path"], "docs/plans/2026-07-20-x.md");
        assert_eq!(row["body_sha256"], "hash");
        assert!(
            row.get("host").is_none() && row.get("repo").is_none(),
            "v2 drops both the raw host and the repo field: {row}"
        );
    }

    #[test]
    fn plan_links_row_nulls_parent_when_unknown() {
        let row = plan_links_row(
            "2026-07-20T00:00:00Z",
            None,
            "child-sid",
            "digest",
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

    /// Reuse [`crate::registry::test_metrics_env::with_metrics_dir`] rather
    /// than a second, independently-locked `CADENCE_METRICS_DIR` mutator.
    ///
    /// This module used to define its own `ENV_LOCK`/`with_metrics_dir` pair
    /// under the premise "this crate has its own env-mutating tests, so its
    /// own lock" — true, but `registry.rs`'s `test_metrics_env` module (used
    /// by `start.rs`'s tests, e.g. `stale_peer_does_not_trigger_disclosure`
    /// via `with_scratch_metrics_dir`) ALSO mutates this exact process-global
    /// env var, through a *different* mutex. Two uncoordinated locks over one
    /// global is a race regardless of how careful either lock's own critical
    /// section is: `cargo test`'s default parallelism can run a test from
    /// each module on separate threads at once, and one thread's
    /// `set_var`/`remove_var` can interleave with the other's window. Rare
    /// enough not to fire locally, but real — it surfaced as this test's
    /// `plan-links.jsonl` read hitting `NotFound` on Windows CI once this
    /// crate's test count grew (cadence-hooks#437). One shared lock closes it
    /// by construction; both modules' tests now serialize against the same
    /// mutex.
    use crate::registry::test_metrics_env::with_metrics_dir;

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
        assert!(written.starts_with("---\nstatus: \"in-flight\"\n"));
        assert!(written.contains("# Fix the Widget"));
        assert!(!written.contains("If this plan can be broken down"));
        assert!(written.contains("session_id: \"child-session-id\""));
        assert!(written.contains("body_sha256:"));
        assert!(
            !written.contains("approved_in:"),
            "no parent resolved — approved_in must be omitted, never written as 'unknown'"
        );
        // Doctrine fix (cadence#248): the committed block carries the salted
        // digest, never the raw hostname.
        assert!(
            !written.contains("test-host"),
            "the raw hostname must never reach the committed frontmatter"
        );
        assert!(written.contains(&crate::provenance::machine_digest("test-host")));

        let links = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        assert!(links.contains("\"child_session_id\":\"child-session-id\""));
        assert!(links.contains("\"parent_session_id\":null"));
        // plan_path is forward-slash-normalized regardless of platform — a
        // stable schema value for consumers, not the native separator.
        assert!(links.contains("\"plan_path\":\"docs/plans/2026-07-20-fix-the-widget.md\""));
        // Schema v2 (cameronsjo/cadence-hooks#396 review): the local-only
        // linkage row now ALSO carries the salted digest — matching the
        // committed frontmatter's own `machine` field — never the raw
        // hostname, and no separate `repo` field.
        assert!(links.contains(&format!(
            "\"machine\":\"{}\"",
            crate::provenance::machine_digest("test-host")
        )));
        assert!(!links.contains("test-host"));
        assert!(!links.contains("\"host\""));
        assert!(!links.contains("\"repo\""));
    }

    // --- late persist: the injected plan entry (cadence-hooks#672) ---

    /// A minimal transcript whose head carries the harness's auto-continuation
    /// plan injection — the entry shape live-captured from session beffcf50
    /// (cadence-hooks#672): `type: "user"`, top-level `planContent` with the
    /// BARE plan body, `origin.kind: "auto-continuation"`, and a message text
    /// that carries the prefix + suffix chrome the hook must never persist.
    fn write_injected_transcript(path: &Path, plan_body: &str) {
        let msg_text = format!(
            "Implement the following plan:\n\n{plan_body}\n\nIf this plan can be broken down \
             into discrete units of work, consider using the Agent tool to dispatch them."
        );
        let injected = serde_json::json!({
            "type": "user",
            "isSidechain": false,
            "origin": {"kind": "auto-continuation"},
            "planContent": plan_body,
            "message": {"role": "user", "content": msg_text},
        });
        let ordinary = serde_json::json!({
            "type": "assistant",
            "message": {"role": "assistant", "content": []},
        });
        fs::write(path, format!("{injected}\n{ordinary}\n")).unwrap();
    }

    #[test]
    fn late_persist_recovers_the_injected_plan_on_a_prefixless_prompt() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript = tmp.path().join("child-session-id.jsonl");
        write_injected_transcript(&transcript, "# Fix the Widget\n\nDo the thing.");

        let input = make_user_prompt_submit(
            "child-session-id",
            "sounds good, keep going",
            &cwd,
            &transcript.to_string_lossy(),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "late persist must fire");
        let written =
            fs::read_to_string(tmp.path().join("docs/plans/2026-08-11-fix-the-widget.md")).unwrap();
        assert!(written.contains("# Fix the Widget"));
        assert!(
            !written.contains("Implement the following plan:"),
            "the persisted body is the bare plan, never the prompt chrome"
        );
        assert!(!written.contains("If this plan can be broken down"));
    }

    #[test]
    fn late_persist_normalizes_to_the_same_hash_as_the_prefix_path() {
        // The prefix path and the late path must hash byte-identical bodies
        // (Design 18 extended to the third trigger): persist via the prefix
        // path first, then a prefixless prompt over the injected transcript
        // must be a silent idempotent skip — no second file, no second nudge.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript = tmp.path().join("child-session-id.jsonl");
        write_injected_transcript(&transcript, "# Fix the Widget\n\nDo the thing.");

        let prefixed = make_user_prompt_submit(
            "child-session-id",
            "Implement the following plan:\n\n# Fix the Widget\n\nDo the thing.",
            &cwd,
            &transcript.to_string_lossy(),
        );
        let r1 = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&prefixed, "2026-08-10T00:00:00Z", "2026-08-10", "test-host")
        });
        assert_eq!(r1.outcome, Outcome::Nudge);

        let prefixless = make_user_prompt_submit(
            "child-session-id",
            "carry on",
            &cwd,
            &transcript.to_string_lossy(),
        );
        // A LATER local date: the stems differ, so only a hash-level dedupe
        // across the whole plans dir — not the same-stem claim ladder — can
        // recognize the re-fire.
        let r2 = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(
                &prefixless,
                "2026-08-11T00:00:00Z",
                "2026-08-11",
                "test-host",
            )
        });
        assert_eq!(
            r2.outcome,
            Outcome::Allow,
            "already-persisted plan (different date stem) must be a silent skip"
        );
        assert!(
            !tmp.path()
                .join("docs/plans/2026-08-11-fix-the-widget.md")
                .exists(),
            "no duplicate file under the later date"
        );
    }

    #[test]
    fn late_persist_ignores_sidechain_and_plain_user_entries() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript = tmp.path().join("child-session-id.jsonl");
        // A sidechain injection (a subagent's plan) and an ordinary user entry
        // with no planContent — neither may trigger a persist.
        let sidechain = serde_json::json!({
            "type": "user", "isSidechain": true,
            "planContent": "# Subagent Plan\n\nnope.",
            "message": {"role": "user", "content": "x"},
        });
        let plain = serde_json::json!({
            "type": "user", "isSidechain": false,
            "message": {"role": "user", "content": "just chatting"},
        });
        fs::write(&transcript, format!("{sidechain}\n{plain}\n")).unwrap();

        let input = make_user_prompt_submit(
            "child-session-id",
            "hello",
            &cwd,
            &transcript.to_string_lossy(),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path().join("docs/plans").exists() || {
                fs::read_dir(tmp.path().join("docs/plans")).unwrap().count() == 0
            }
        );
    }

    // --- approval arm: plan source fallback chain (cadence-hooks#672) ---

    #[test]
    fn approval_falls_back_to_tool_input_plan() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        let input = HookInput {
            tool_name: Some("ExitPlanMode".into()),
            tool_input: Some(ToolInput {
                plan: Some("# Call Side Plan\n\nbody.".into()),
                ..Default::default()
            }),
            tool_response: Some(ToolResponse {
                is_agent: Some(false),
                ..Default::default()
            }),
            cwd: Some(cwd),
            session_id: Some("approving-session".into()),
            ..Default::default()
        };
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "tool_input.plan must persist");
        assert!(
            tmp.path()
                .join("docs/plans/2026-08-11-call-side-plan.md")
                .exists()
        );
    }

    #[test]
    fn approval_falls_back_to_the_plan_store_file() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let store = tmp.path().join("store-plan.md");
        fs::write(&store, "# Stored Plan\n\nbody from the plan store.").unwrap();

        let input = HookInput {
            tool_name: Some("ExitPlanMode".into()),
            tool_response: Some(ToolResponse {
                is_agent: Some(false),
                file_path: Some(store.to_string_lossy().into_owned()),
                ..Default::default()
            }),
            cwd: Some(cwd),
            session_id: Some("approving-session".into()),
            ..Default::default()
        };
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "planFilePath read must persist");
        assert!(
            tmp.path()
                .join("docs/plans/2026-08-11-stored-plan.md")
                .exists()
        );
    }

    #[test]
    fn approval_prefers_tool_response_plan_over_the_fallbacks() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        let input = HookInput {
            tool_name: Some("ExitPlanMode".into()),
            tool_input: Some(ToolInput {
                plan: Some("# Call Side Plan\n\nstale draft.".into()),
                ..Default::default()
            }),
            tool_response: Some(ToolResponse {
                is_agent: Some(false),
                plan: Some("# Response Plan\n\napproved text.".into()),
                ..Default::default()
            }),
            cwd: Some(cwd),
            session_id: Some("approving-session".into()),
            ..Default::default()
        };
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        assert!(
            tmp.path()
                .join("docs/plans/2026-08-11-response-plan.md")
                .exists()
        );
        assert!(
            !tmp.path()
                .join("docs/plans/2026-08-11-call-side-plan.md")
                .exists()
        );
    }

    #[test]
    fn panel_line_settled_accepts_both_settled_forms_only() {
        // Settled: the ran form and the absence assertion.
        assert!(panel_line_settled(
            "# T\n\nPanel: plan-reviewer ×2 ran — 3 findings, 2 folded in, 1 declined\n\nbody"
        ));
        assert!(panel_line_settled(
            "# T\n\nPanel: none — raw-draft bypass per operator ask\n"
        ));
        // Unsettled: absent, pending-shaped, empty reason/counts, heading-only.
        assert!(!panel_line_settled("# T\n\nno panel line at all\n"));
        assert!(!panel_line_settled(
            "# T\n\nPanel: pending — seats not yet run\n"
        ));
        assert!(!panel_line_settled("# T\n\nPanel: none — \n"));
        assert!(!panel_line_settled("# T\n\nPanel:  ran — 3 findings\n"));
        assert!(!panel_line_settled(
            "# T\n\n## Panel review — findings declined\n\n- none declined\n"
        ));
        // Anchored at line start: an indented or mid-line mention never matches.
        assert!(!panel_line_settled("# T\n\n  Panel: x ran — y\n"));
        assert!(!panel_line_settled(
            "# T\n\nsee Panel: x ran — y for details\n"
        ));
        // First match in document order decides (the Driver: stamp's
        // discipline): a settled-looking quoted example AFTER an unsettled
        // stanza line never satisfies the gate…
        assert!(!panel_line_settled(
            "# T\n\nPanel: pending — seats queued\n\nExample: write\nPanel: x ran — 1 finding\n"
        ));
        // …and a later unsettled mention never contradicts a settled stanza.
        assert!(panel_line_settled(
            "# T\n\nPanel: reviewer ran — 2 findings, 2 folded in, 0 declined\n\n\
             Quoted form:\nPanel: pending — never do this\n"
        ));
        // Dash tolerance: a hand-typed hyphen, double hyphen, or en dash
        // states the settled fact as unambiguously as the template's em dash.
        assert!(panel_line_settled(
            "# T\n\nPanel: none - raw-draft bypass\n"
        ));
        assert!(panel_line_settled(
            "# T\n\nPanel: 2 reviewers ran - 3 findings, all folded in\n"
        ));
        assert!(panel_line_settled(
            "# T\n\nPanel: none -- operator bypass\n"
        ));
        assert!(panel_line_settled(
            "# T\n\nPanel: reviewer ran – 1 finding\n"
        ));
        // …but the dash is still required, and an empty ran-tail is unsettled.
        assert!(!panel_line_settled("# T\n\nPanel: none reason given\n"));
        assert!(!panel_line_settled("# T\n\nPanel: x ran — \n"));
        assert!(!panel_line_settled("# T\n\nPanel: x ran 3 findings\n"));
        // Fenced and block-quoted examples never mint a settled verdict for a
        // plan with no stanza at all (security review of this change).
        assert!(!panel_line_settled(
            "# Add a Panel: stanza\n\n```markdown\nPanel: reviewer ran — 3 findings\n```\n\n\
             Approach: …\n"
        ));
        assert!(!panel_line_settled(
            "# T\n\n> Panel: reviewer ran — 3 findings\n\nbody\n"
        ));
        // A real stanza after a closed fence still settles.
        assert!(panel_line_settled(
            "# T\n\n```\nexample\n```\n\nPanel: reviewer ran — 1 finding, folded\n"
        ));
    }

    #[test]
    fn end_to_end_prompt_path_unpaneled_plan_appends_static_panel_sentence() {
        // The UserPromptSubmit trigger extracts its body differently
        // (PLAN_PREFIX strip vs the ExitPlanMode tool response), so the
        // sentence wiring is asserted on this path too, both directions.
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
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        assert!(r.message.unwrap().contains(PANEL_GATE_NUDGE));

        let prompt_settled = "Implement the following plan:\n\n# Fix the Sprocket\n\n\
                              Panel: reviewer ran — 1 finding, folded\n\nDo the thing.";
        let input = make_user_prompt_submit(
            "child-session-id",
            prompt_settled,
            &cwd,
            &tmp.path().join("child-session-id.jsonl").to_string_lossy(),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        assert!(!r.message.unwrap().contains("panel gate:"));
    }

    #[test]
    fn end_to_end_approval_unpaneled_plan_appends_static_panel_sentence() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        // `pending`-shaped line: present but unsettled — the nudge must fire,
        // and must never echo the plan's own text (untrusted input).
        let plan = "# Fix the Widget\n\nPanel: pending — awaiting seat dispatch\n\nDo the thing.";
        let input = exit_plan_mode_post_tool_use(
            "sid",
            plan,
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(
            msg.contains(PANEL_GATE_NUDGE),
            "unsettled Panel: line must append the static panel sentence: {msg}"
        );
        assert!(
            !msg.contains("awaiting seat dispatch"),
            "the nudge must never echo plan text: {msg}"
        );
    }

    #[test]
    fn end_to_end_approval_settled_panel_line_gets_no_panel_sentence() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        let plan = "# Fix the Widget\n\n\
                    Panel: plan-reviewer ×2 ran — 3 findings, 2 folded in, 1 declined\n\n\
                    Do the thing.";
        let input = exit_plan_mode_post_tool_use(
            "sid",
            plan,
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(
            !msg.contains("panel gate:"),
            "a settled Panel: line must not trigger the panel sentence: {msg}"
        );
        // The absence assertion is equally settled.
        let plan_none = "# Fix the Sprocket\n\nPanel: none — raw-draft bypass per ask\n\nBody.";
        let input = exit_plan_mode_post_tool_use(
            "sid2",
            plan_none,
            &cwd,
            &tmp.path().join("t2.jsonl").to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        assert!(!r.message.unwrap().contains("panel gate:"));
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
    fn end_to_end_model_and_harness_fall_back_to_the_approving_parent_transcript() {
        // The regression this fold fixes (cameronsjo/cadence-hooks#396
        // review): on approve-and-clear, the EXECUTING session's own
        // transcript is structurally empty at this point — no assistant turn
        // has landed there yet — so resolving model/harness against it always
        // returns `None`. The APPROVING parent's transcript (the one
        // `find_parent` already walks to resolve `approved_in`) is the
        // fallback source, and it DOES carry a populated `model`/`version`.
        //
        // `resolve_harness` has ITS OWN internal `AI_AGENT` env fallback
        // (legitimate in production — Claude Code sets it for every hook
        // subprocess), which would otherwise mask the parent-fallback this
        // test targets with whatever value happens to be ambient on the
        // machine running `cargo test`. Pin it to `None` for the duration so
        // only the parent-transcript fallback can supply a value, via the
        // SAME lock `warn_commit_provenance`'s own AI_AGENT tests use (a
        // second, independently-locked mutator of this process-global var
        // would itself be a race, not an isolation fix).
        crate::warn_commit_provenance::with_ai_agent_env(None, || {
            let tmp = TempDir::new().unwrap();
            init_repo(tmp.path());
            let cwd = tmp.path().to_string_lossy().into_owned();
            let metrics_dir = TempDir::new().unwrap();

            let plan_text = "# Fix the Widget\n\nDo the thing.";
            let parent_transcript = tmp.path().join("parent-session-id.jsonl");
            fs::write(
                &parent_transcript,
                exit_plan_mode_line(plan_text, Some("claude-fable-5"), Some("2.1.214")),
            )
            .unwrap();

            // Realistic shape: a fresh, just-started child session's
            // transcript has no assistant turn yet at UserPromptSubmit time.
            let child_transcript = tmp.path().join("child-session-id.jsonl");
            fs::write(&child_transcript, "").unwrap();

            let prompt = format!("Implement the following plan:\n\n{plan_text}");
            let input = make_user_prompt_submit(
                "child-session-id",
                &prompt,
                &cwd,
                &child_transcript.to_string_lossy(),
            );

            with_metrics_dir(metrics_dir.path(), || {
                run_persist_plan(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host");
            });

            let written =
                fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md"))
                    .unwrap();
            assert!(
                written.contains("model: \"claude-fable-5\""),
                "model falls back to the approving parent's transcript: {written}"
            );
            assert!(
                written.contains("harness: \"claude-code 2.1.214\""),
                "harness falls back to the approving parent's transcript: {written}"
            );
        });
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

    // --- PersistPlanApproval: same-session PostToolUse trigger ---

    fn exit_plan_mode_post_tool_use(
        session_id: &str,
        plan: &str,
        cwd: &str,
        transcript_path: &str,
        is_agent: Option<bool>,
    ) -> HookInput {
        HookInput {
            tool_name: Some("ExitPlanMode".into()),
            tool_input: Some(ToolInput::default()),
            tool_response: Some(ToolResponse {
                plan: Some(plan.into()),
                is_agent,
                ..Default::default()
            }),
            session_id: Some(session_id.into()),
            cwd: Some(cwd.into()),
            transcript_path: Some(transcript_path.into()),
            ..Default::default()
        }
    }

    #[test]
    fn approval_non_exit_plan_mode_tool_allows() {
        let input = HookInput {
            tool_name: Some("Bash".into()),
            tool_response: Some(ToolResponse {
                plan: Some("# X\n\nbody".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn approval_no_tool_response_plan_allows() {
        let input = HookInput {
            tool_name: Some("ExitPlanMode".into()),
            ..Default::default()
        };
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn approval_subagent_context_allows() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let input = exit_plan_mode_post_tool_use(
            "sub-session-id",
            "# X\n\nbody",
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            Some(true),
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path().join("docs").exists(),
            "a subagent's own plan approval must not persist"
        );
    }

    #[test]
    fn approval_absent_is_agent_does_not_persist() {
        // Fail-CLOSED (cameronsjo/cadence-hooks#396 review): an ABSENT
        // `is_agent` — a future payload-shape drift, or a stripped-down
        // fixture — must not be read as "not a subagent". Only the EXPLICIT
        // `Some(false)` clears the gate.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let input = exit_plan_mode_post_tool_use(
            "sid",
            "# X\n\nbody",
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            None,
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path().join("docs").exists(),
            "an absent is_agent must not be treated as a top-level approval"
        );
    }

    #[test]
    fn approval_agent_id_present_does_not_persist_even_with_is_agent_false() {
        // The gate is `is_agent == Some(false) AND agent_id.is_none()` — both
        // conditions, not either. A payload carrying `isAgent: false` but
        // also an `agent_id` (a shape this hook has never observed, but must
        // not trust blindly) must still skip.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let mut input = exit_plan_mode_post_tool_use(
            "sid",
            "# X\n\nbody",
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            Some(false),
        );
        input.agent_id = Some("agent-1".into());
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(!tmp.path().join("docs").exists());
    }

    #[test]
    fn approval_gate_pins_the_is_agent_wire_field_name() {
        // Regression pin: `isAgent` (camelCase) is the exact field name
        // Claude Code's payload uses — live-verified on cadence-hooks#396. A
        // rename in either direction (this struct's `#[serde(rename)]`, or a
        // hypothetical future payload-shape change) would silently break the
        // fail-closed gate above without this test noticing via the
        // Rust-struct-literal tests alone.
        // Extra `#` in the raw-string delimiter: the payload's plan text
        // embeds a literal `"#` (a quote immediately followed by an ATX
        // heading marker), which would otherwise close a `r#"..."#` raw
        // string early.
        let json = r##"{"tool_name":"ExitPlanMode","session_id":"sid","cwd":"/tmp",
            "tool_response":{"plan":"# X\n\nbody","isAgent":false}}"##;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(
            input.tool_response.as_ref().and_then(|tr| tr.is_agent),
            Some(false),
            "isAgent must deserialize into ToolResponse::is_agent"
        );
    }

    #[test]
    fn approval_no_cwd_allows() {
        let input = HookInput {
            tool_name: Some("ExitPlanMode".into()),
            tool_response: Some(ToolResponse {
                plan: Some("# X\n\nbody".into()),
                ..Default::default()
            }),
            session_id: Some("sid".into()),
            ..Default::default()
        };
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn approval_non_git_repo_cwd_allows() {
        let tmp = TempDir::new().unwrap();
        let input = exit_plan_mode_post_tool_use(
            "sid",
            "# X\n\nbody",
            &tmp.path().to_string_lossy(),
            &tmp.path().join("t.jsonl").to_string_lossy(),
            None,
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn approval_unsafe_session_id_allows() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let input = exit_plan_mode_post_tool_use(
            "../escape",
            "# X\n\nbody",
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            None,
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(!tmp.path().join("docs").exists(), "nothing written");
    }

    #[test]
    fn approval_empty_plan_text_allows() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let input = exit_plan_mode_post_tool_use(
            "sid",
            "   \n\n  ",
            &cwd,
            &tmp.path().join("t.jsonl").to_string_lossy(),
            None,
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn end_to_end_same_session_approval_persists_with_frontmatter() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript_path = tmp.path().join("own-session-id.jsonl");
        fs::write(&transcript_path, "{}").unwrap();

        let input = exit_plan_mode_post_tool_use(
            "own-session-id",
            "# Fix the Widget\n\nDo the thing.",
            &cwd,
            &transcript_path.to_string_lossy(),
            Some(false),
        );

        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let msg = r.message.unwrap();
        assert!(msg.contains(&format!(
            "approved in {}",
            identity::generate_name("own-session-id")
        )));

        let written =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();
        assert!(written.starts_with("---\nstatus: \"in-flight\"\n"));
        assert!(written.contains("# Fix the Widget"));
        assert!(written.contains("session_id: \"own-session-id\""));
        assert!(written.contains(&format!(
            "approved_in: \"{}\"",
            identity::generate_name("own-session-id")
        )));
        assert!(written.contains("approved_session_id: \"own-session-id\""));
        assert!(written.contains(&crate::provenance::machine_digest("test-host")));

        let links = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        assert!(links.contains("\"parent_session_id\":\"own-session-id\""));
        assert!(links.contains("\"child_session_id\":\"own-session-id\""));
        assert!(links.contains(&format!(
            "\"machine\":\"{}\"",
            crate::provenance::machine_digest("test-host")
        )));
    }

    #[test]
    fn approval_double_fire_is_idempotent_skip_no_dash_two_file() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript_path = tmp.path().join("own-session-id.jsonl");
        fs::write(&transcript_path, "{}").unwrap();

        let input = exit_plan_mode_post_tool_use(
            "own-session-id",
            "# Fix the Widget\n\nDo the thing.",
            &cwd,
            &transcript_path.to_string_lossy(),
            Some(false),
        );

        with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host");
        });
        let first_write =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();

        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T01:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "re-fire still nudges");
        assert!(
            !tmp.path()
                .join("docs/plans/2026-07-20-fix-the-widget-2.md")
                .exists(),
            "double-fire of the same approval must not ladder to a duplicate file"
        );
        let second_write =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();
        assert_eq!(
            first_write, second_write,
            "the file must never be rewritten"
        );
    }
}
