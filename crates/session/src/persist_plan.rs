//! `session persist-plan-approval` (PostToolUse) — persist an approved plan
//! whose approving turn would otherwise leave no durable trace (cadence#505,
//! cadence-hooks#396).
//!
//! Two recognition paths behind one PostToolUse wiring:
//!
//! 1. **Same-session approval** (`tool_name == ExitPlanMode`). Live probe
//!    (2026-07-25, cadence-hooks#396 comment 5080816947) established that
//!    `PostToolUse:ExitPlanMode` fires on a same-session approval carrying
//!    the plan text in `tool_response.plan`; the current harness also fills
//!    `tool_input.plan` and names the plan-store copy in `planFilePath`
//!    (cadence-hooks#672), so the source chain is response → input → store
//!    file.
//! 2. **Approve-and-clear** (any other tool). The harness's
//!    approve-and-clear path never completes the `ExitPlanMode` call — it
//!    DENIES the tool (recorded as "User rejected tool use") and launches a
//!    fresh session whose first user message is `Implement the following
//!    plan:\n\n<plan>` (verified against the 2.1.243 bundle and the
//!    2026-08-24 silver-fugue → brisk-scale approval), and no
//!    UserPromptSubmit fires for that injected message. So path 1 never sees
//!    it. This arm runs on the child session's PostToolUse events: once per
//!    session (a [`cadence_hooks_core::markers::session_marker`]) it reads
//!    the transcript HEAD, and when the session's first user message is the
//!    injected implement-prompt it persists that plan, attributing
//!    `approved_in` to the parent session named by the prompt's
//!    transcript-pointer paragraph.
//!
//! A previous UserPromptSubmit-driven arm (`session persist-plan`) covered
//! approve-and-clear by re-scanning EVERY prompt and re-persisting. It held
//! the RAW approved text — stale the moment a plan starts living (ticked
//! boxes, a settled `Panel:`, `## Deviations`, `status:`) — and so every
//! later fire wrote or stamped that stale copy where a consumer reads first:
//! raw duplicate siblings (cadence-hooks#703, #724, #729), a second
//! frontmatter block over a ticked plan (#738), writes into the primary
//! checkout (#739). Three rounds of "is this plan already on disk"
//! recognition heuristics could not keep up with a document that drifts away
//! from every hash by design, so the arm was removed in 0.82.0 rather than
//! fixed a fourth time — which killed ALL approve-and-clear coverage (the
//! regression this arm repairs). Path 2 differs from that arm in the two
//! ways that made it unmaintainable: it fires from the FIRST transcript rows
//! (text still byte-identical to the approval, so the hash-idempotency tiers
//! hold), and the session marker bounds it to one scan per session — never a
//! per-prompt re-recognition of a document that has started living.
//!
//! The write is body-hash-idempotent through [`persist_and_nudge`]:
//! `claim_target`'s `O_EXCL` collision ladder, the frontmatter render
//! ([`render_document`] — which MERGES into a plan's own leading frontmatter
//! rather than stacking a second block, #738), and one `plan-links.jsonl` row.
//! The plan text runs through [`strip_trailing_suffix_lines_and_trim`] before
//! hashing so a harness-appended suffix never changes the body's identity.
//!
//! `CADENCE_NO_PERSIST_PLAN` (any non-empty value, process env or the repo's
//! `.claude/settings*.json` `env` block — the `CADENCE_ALLOW_MAIN` precedent)
//! opts a repo or a session out of the persist entirely (cadence-hooks#692);
//! the four plan guards and the SessionStart plan scanner are not covered by
//! this flag.
//!
//! Never blocks (ADR-0001): every failure path — no plan text, no `cwd`, not
//! a git repo, unsafe session id, exhausted suffix ladder, a subagent-context
//! approval — exits silently via `CheckResult::allow()`. A hook bug must not
//! eat a same-session approval.

use crate::identity;
use crate::plan_scan::visible_lines;
use cadence_hooks_core::{Check, CheckResult, HookInput};
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

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

/// Prefix of the first user message an approve-and-clear launch injects into
/// the child session — `Implement the following plan:\n\n<plan>` in the
/// 2.1.243 bundle (`initialMessage` template, `clearContext:!0` branch).
/// Matched on the prefix so template drift after the colon never blinds the
/// arm.
const INJECTED_PLAN_PREFIX: &str = "Implement the following plan:";

/// Marker kind bounding the injected-prompt scan to once per session — see
/// [`run_injected_plan_persist`].
const INJECTED_SCAN_MARKER_KIND: &str = "persist-plan-injected";

/// Bound on the transcript HEAD read the injected-prompt arm performs. The
/// injected prompt is among the first rows; 1 MiB (the plan-store cap's
/// sibling) covers any real plan plus the handful of preceding
/// SessionStart-attachment rows many times over.
const INJECTED_HEAD_READ_MAX_BYTES: u64 = 1024 * 1024;

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

/// Schema version stamped on every `plan-links.jsonl` row. A new stream
/// (cadence#238 convention) — does not share `cadence_hooks_metrics::common`'s
/// existing version constants; this one lives with its own writer. Bumped to
/// 2 (cameronsjo/cadence-hooks#396 review): `host` now carries the salted
/// [`crate::provenance::machine_digest`] instead of the raw hostname (matching
/// the committed frontmatter's own field two functions up), and `repo` is
/// dropped — `plan_path` is already repo-relative, so `repo` was a second,
/// separately-drifting way to say the same thing; confirmed no consumer
/// (`reconstruct-journey.py`) reads either field before dropping it. Bumped to
/// 3 (model-guard "stronger prose, not teeth"): `recommended_model` carries
/// the plan's parsed [`Tier`] (see [`recommended_tier`]) — OMITTED from the
/// row, never written null, when the plan carries no recognized `Driver:`
/// anchor, so a consumer distinguishes "no driver recorded" from an explicit
/// empty value without a schema-version branch.
const PLAN_LINKS_SCHEMA_VERSION: u32 = 3;

/// Persist an approved plan at approval time (cadence-hooks#396) — the one
/// writer since the UserPromptSubmit re-scan arm was removed (2026-08-20).
pub struct PersistPlanApproval;

impl Check for PersistPlanApproval {
    fn name(&self) -> &str {
        "persist-plan-approval"
    }

    fn run(&self, input: &HookInput) -> CheckResult {
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        let utc_now = cadence_hooks_core::time::utc_timestamp();
        let local_date = cadence_hooks_core::time::local_date();
        // Narrow defense-in-depth on top of the dispatch-layer panic guard
        // (cameronsjo/cadence-hooks#349): this fires on every PostToolUse
        // call, and a bug here must not eat the approval (or the tool call).
        std::panic::catch_unwind(|| {
            if input.tool_name() == Some("ExitPlanMode") {
                run_persist_plan_approval(input, &utc_now, &local_date, &host)
            } else {
                run_injected_plan_persist(input, &utc_now, &local_date, &host)
            }
        })
        .unwrap_or_else(|_| CheckResult::allow())
    }
}

/// Testable core for the PostToolUse trigger — clock and host are injected so
/// tests pin the rendered frontmatter and the plan-links row byte-for-byte.
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
    // Strip the harness-appended suffix paragraphs before hashing (Design 18)
    // so a re-fire of the same approval hashes byte-identical.
    let body = strip_trailing_suffix_lines_and_trim(&raw_plan);
    if body.is_empty() {
        return CheckResult::allow();
    }
    // Same-session approval: the approving identity IS the executing session
    // — no sibling-transcript scan needed (Design record item 2).
    persist_plan_body(input, utc_now, local_date, host, &body, input.session_id())
}

/// The injected-prompt arm — approve-and-clear coverage (module doc path 2).
///
/// Fires on every non-`ExitPlanMode` PostToolUse, but does real work at most
/// once per session: a definitive verdict about the transcript's first user
/// message — injected implement-prompt or not — writes a session marker that
/// short-circuits every later fire. A head read that finds NO user row yet
/// (the harness appends the injected prompt to the transcript only after
/// SessionStart settles, so a very early fire can race it) leaves the marker
/// unwritten and retries on the next tool call.
///
/// Same fail-open posture as the approval arm: a subagent context, an unsafe
/// session id, an unreadable transcript, or any persist-pipeline failure
/// degrades to `CheckResult::allow()`.
pub fn run_injected_plan_persist(
    input: &HookInput,
    utc_now: &str,
    local_date: &str,
    host: &str,
) -> CheckResult {
    // A subagent's PostToolUse stream never persists — its transcript head is
    // its task prompt, which an orchestrator can legitimately open with plan
    // text; only the top-level session's injected prompt is an approval.
    if input.agent_id().is_some() {
        return CheckResult::allow();
    }
    if input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
        .is_none()
    {
        return CheckResult::allow();
    }
    let marker =
        cadence_hooks_core::markers::session_marker(input, INJECTED_SCAN_MARKER_KIND, None);
    if marker.exists() {
        return CheckResult::allow();
    }
    let Some(transcript_path) = input.transcript_path() else {
        return CheckResult::allow();
    };
    let Some(head) = cadence_hooks_core::transcript::read_head_bounded(
        Path::new(transcript_path),
        INJECTED_HEAD_READ_MAX_BYTES,
    ) else {
        return CheckResult::allow();
    };
    let raw_plan = match injected_first_prompt(&head) {
        // No user row in the head yet — not a verdict; retry on a later fire.
        InjectedScan::NoUserRowYet => return CheckResult::allow(),
        InjectedScan::NotInjected => {
            let _ = cadence_hooks_core::markers::write_marker(&marker, "");
            return CheckResult::allow();
        }
        InjectedScan::Plan(raw) => raw,
    };
    // Definitive verdict: bound the scan to this one fire even if the persist
    // below declines (opt-out, no repo, hash already on disk) — those are
    // stable conditions a retry would only re-litigate every tool call.
    let _ = cadence_hooks_core::markers::write_marker(&marker, "");

    let body = strip_trailing_suffix_lines_and_trim(&raw_plan);
    if body.is_empty() {
        return CheckResult::allow();
    }
    let approving = parent_session_id_from_pointer(&raw_plan);
    persist_plan_body(
        input,
        utc_now,
        local_date,
        host,
        &body,
        approving.as_deref(),
    )
}

/// Verdict of one bounded scan of a transcript head for the injected
/// implement-prompt — see [`injected_first_prompt`].
enum InjectedScan {
    /// The head carries no user row at all yet — scan again later.
    NoUserRowYet,
    /// The first user message exists and is NOT the injected implement-prompt.
    NotInjected,
    /// The first user message is the injected implement-prompt; the payload is
    /// its full text (prefix stripped, harness suffix paragraphs still on).
    Plan(String),
}

/// Resolve the transcript's first main-chain user message and classify it
/// against [`INJECTED_PLAN_PREFIX`].
///
/// Rows are newline-delimited JSON; anything unparseable, sidechain
/// (`isSidechain: true`), or non-`user` is skipped. The first user row whose
/// `message.content` yields text decides — string content directly, array
/// content via its first `{"type":"text"}` item (both shapes are live). A
/// first user row with no text at all (e.g. a bare tool-result row after a
/// resume) reads as [`InjectedScan::NotInjected`]: whatever this session is,
/// its first message is not the injected approval.
fn injected_first_prompt(head: &str) -> InjectedScan {
    for line in head.lines() {
        let Ok(row) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if row.get("type").and_then(Value::as_str) != Some("user") {
            continue;
        }
        if row.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let content = row.get("message").and_then(|m| m.get("content"));
        let text = match content {
            Some(Value::String(s)) => Some(s.as_str()),
            Some(Value::Array(items)) => items
                .iter()
                .find(|item| item.get("type").and_then(Value::as_str) == Some("text"))
                .and_then(|item| item.get("text"))
                .and_then(Value::as_str),
            _ => None,
        };
        return match text {
            Some(text) => match text.strip_prefix(INJECTED_PLAN_PREFIX) {
                Some(rest) => InjectedScan::Plan(rest.to_string()),
                None => InjectedScan::NotInjected,
            },
            None => InjectedScan::NotInjected,
        };
    }
    InjectedScan::NoUserRowYet
}

/// The approving (parent) session id, parsed from the injected prompt's
/// transcript-pointer paragraph — "…read the full transcript at:
/// `<dir>/<session-id>.jsonl`". `None` when the paragraph is absent or its
/// final path component's stem fails [`identity::is_safe_session_id`] — the
/// persist then simply omits `approved_in:` (silence, not a guess).
fn parent_session_id_from_pointer(raw_plan: &str) -> Option<String> {
    let pointer = raw_plan
        .lines()
        .find(|l| l.trim_start().starts_with(POINTER_PARAGRAPH_PREFIX))?;
    let jsonl = pointer
        .split_whitespace()
        .rev()
        .find(|token| token.ends_with(".jsonl"))?;
    let stem = Path::new(jsonl).file_stem()?.to_str()?;
    identity::is_safe_session_id(stem).then(|| stem.to_string())
}

/// Shared persist tail for both recognition paths: resolve the repo, render
/// the frontmatter, write once, append the plan-links row, nudge.
/// `approving_session_id` names the session whose operator approved the plan
/// — the executing session itself on a same-session approval, the parent on
/// an approve-and-clear pickup, `None` when unknown (then `approved_in:` is
/// omitted and the row carries a null parent).
fn persist_plan_body(
    input: &HookInput,
    utc_now: &str,
    local_date: &str,
    host: &str,
    body: &str,
    approving_session_id: Option<&str>,
) -> CheckResult {
    let Some(cwd) = input.cwd.as_deref() else {
        return CheckResult::allow();
    };
    let Some(repo_root) = crate::registry::repo_root(cwd) else {
        return CheckResult::allow();
    };
    // Opt-out (cadence-hooks#692): checked right after `repo_root` resolves
    // so the repo-level `.claude/settings*.json` flag can be read, and before
    // any plans-dir resolution or write.
    if persist_plan_opted_out(&repo_root) {
        return CheckResult::allow();
    }
    let Some(session_id) = input
        .session_id()
        .filter(|s| identity::is_safe_session_id(s))
    else {
        return CheckResult::allow();
    };

    let body_hash = sha256_hex(body.as_bytes());
    let slug = slugify(body);
    let Some((repo_root, plans_dir)) = canonical_plans_dir(&repo_root) else {
        return CheckResult::allow();
    };
    let stem = format!("{local_date}-{slug}");

    let own_name = identity::generate_name(session_id);
    let machine_digest = crate::provenance::machine_digest(host);
    // The executing transcript is a reliable model/harness source on both
    // paths: same-session it has just recorded the approving turn, and on an
    // approve-and-clear pickup the child session's own rows carry its model
    // and harness — which are what `model:`/`harness:` describe (the
    // executing session, not the approving one).
    let transcript_content = input
        .transcript_path()
        .and_then(|tp| cadence_hooks_core::transcript::read_tail(Path::new(tp)));
    let model = crate::warn_commit_provenance::resolve_model(transcript_content.as_deref());
    let harness = crate::warn_commit_provenance::resolve_harness(transcript_content.as_deref());
    let branch = current_branch(cwd);

    let approving = approving_session_id.filter(|s| identity::is_safe_session_id(s));
    let approving_name = approving.map(identity::generate_name);
    let approved_in = match (approving_name.as_deref(), approving) {
        (Some(name), Some(id)) => Some((name, id)),
        _ => None,
    };
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
    let document = render_document(&fields, body);

    persist_and_nudge(
        &plans_dir,
        &stem,
        session_id,
        &body_hash,
        &document,
        utc_now,
        approving,
        session_id,
        &machine_digest,
        &repo_root,
        approving_name.as_deref().unwrap_or("an earlier session"),
        body,
        recommended_tier(body),
    )
}

/// Has this repo or session opted out of the persist (cadence-hooks#692)?
/// `CADENCE_NO_PERSIST_PLAN` with any non-empty value — the `CADENCE_NO_*`
/// family's convention (`CADENCE_NO_OUTRO_BACKSTOP`, `CADENCE_NO_FEEDBACK_FOOTER`),
/// so `"0"`/`"false"` DO opt out; unset or empty to re-enable — read from the
/// process environment first and then from the repo's
/// `.claude/settings.local.json` / `.claude/settings.json` `env` block, the
/// same two sources and the same untrusted-config reader `CADENCE_ALLOW_MAIN`
/// uses. Advisory tier: no `PROTECTED_GUARDS` treatment, no audit row on the
/// skip — the flag is the operator's own choice about an advisory write, not
/// a bypass of a block.
fn persist_plan_opted_out(repo_root: &Path) -> bool {
    std::env::var("CADENCE_NO_PERSIST_PLAN").is_ok_and(|v| !v.is_empty())
        || cadence_hooks_core::config::repo_env_flag(repo_root, "CADENCE_NO_PERSIST_PLAN")
            .is_some_and(|v| !v.is_empty())
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
///
/// The payload path is UNTRUSTED (security review of this change): the field
/// travels in `tool_input`, which the model populates, so without containment
/// this is an arbitrary-local-file read whose content lands in the repo under
/// a "commit it" nudge — a secret-exfiltration sink. The path is therefore
/// accepted only when it canonicalizes to a `.md` file nested under the
/// harness plan store (`<config_dir>/plans`, per
/// [`cadence_hooks_core::paths::claude_config_dir`]) — the one directory the
/// legitimate `planFilePath` ever names.
///
/// `None` on any I/O failure, a non-regular or out-of-store target, or a file
/// over [`IDEMPOTENCY_MAX_FILE_BYTES`] — every ambiguity degrades to "no
/// plan" (ADR-0001), never a partial or out-of-boundary read persisted as if
/// legitimate.
pub(crate) fn read_plan_store_file(path: &str) -> Option<String> {
    let root = cadence_hooks_core::paths::claude_config_dir().join("plans");
    read_plan_store_file_within(path, &root)
}

/// Testable core of [`read_plan_store_file`]: the containment root is
/// injected so tests never mutate `CLAUDE_CONFIG_DIR` (a process-global other
/// tests read concurrently).
fn read_plan_store_file_within(path: &str, plan_store_root: &Path) -> Option<String> {
    use std::io::Read as _;
    let path = Path::new(path);
    if path.extension().is_none_or(|ext| ext != "md") {
        return None;
    }
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    // Canonicalize BOTH sides and require nesting — the same discipline as
    // `canonical_plans_dir`. Canonicalizing the whole final path (not
    // dir-then-basename) is what defeats a symlinked final component.
    let canonical = path.canonicalize().ok()?;
    let canonical_root = plan_store_root.canonicalize().ok()?;
    if !canonical.starts_with(&canonical_root) {
        return None;
    }
    let file = fs::File::open(&canonical).ok()?;
    let mut content = String::new();
    file.take(IDEMPOTENCY_MAX_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .ok()?;
    if content.len() as u64 > IDEMPOTENCY_MAX_FILE_BYTES || content.trim().is_empty() {
        return None;
    }
    Some(content)
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
/// Bounded read of `path`, capped at [`IDEMPOTENCY_MAX_FILE_BYTES`] — shared
/// by [`file_matches_body`] and [`file_has_approved_session_id`], which
/// otherwise duplicated the identical open-take-read-and-size-check
/// sequence. Caps the read itself rather than stat-then-read: a file over the
/// cap is not a plan this hook wrote, and must not become an unbounded read.
/// `None` on any open/read failure or an oversized file.
fn read_capped_at_idempotency_limit(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let file = fs::File::open(path).ok()?;
    let mut content = String::new();
    if file
        .take(IDEMPOTENCY_MAX_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .is_err()
        || content.len() as u64 > IDEMPOTENCY_MAX_FILE_BYTES
    {
        return None;
    }
    Some(content)
}

fn file_matches_body(path: &Path, body_hash: &str) -> bool {
    let Some(content) = read_capped_at_idempotency_limit(path) else {
        return false;
    };

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
    /// The approving session's `(name, session_id)` — on same-session
    /// approval identical to `(own_name, own_session_id)`; `None` only when
    /// no approving session is known.
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
    let mut lines = vec!["---".to_string()];
    lines.extend(hook_frontmatter_lines(f, &[]));
    lines.push("---".to_string());
    lines.join("\n")
}

/// The hook-owned frontmatter lines (no fences). `plan_keys` names the keys
/// the plan's OWN leading block already carries — [`render_document`] passes
/// them so a living plan's recorded `status`/`updated`/`branch` wins over the
/// hook's birth defaults (cadence-hooks#738). The identity keys
/// (`body_sha256`, `session`, `session_id`, `model`, `harness`, `machine`,
/// `approved_in`, `approved_session_id`) are always emitted: they are this
/// persist's provenance, not plan state.
fn hook_frontmatter_lines(f: &FrontmatterFields, plan_keys: &[&str]) -> Vec<String> {
    let owned = |key: &str| plan_keys.contains(&key);
    let mut lines = Vec::new();
    if !owned("status") {
        lines.push(format!("status: {}", yaml_quote("in-flight")));
    }
    if !owned("updated") {
        lines.push(format!("updated: {}", yaml_quote(f.updated)));
    }
    if !owned("branch")
        && let Some(b) = f.branch
    {
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
    lines
}

/// The frontmatter keys this hook owns: the persist's provenance, which a
/// plan's own block must never be able to pre-empt. [`render_document`] drops
/// any plan line declaring one of these (and emits its own lines FIRST), so
/// a first-match line reader (`file_matches_body`, `plan_scan`) and a
/// last-wins YAML parser agree on the provenance of the written file.
const HOOK_OWNED_KEYS: [&str; 8] = [
    "body_sha256",
    "session",
    "session_id",
    "model",
    "harness",
    "machine",
    "approved_in",
    "approved_session_id",
];

/// The bare `key` of a `key:` line at column 0, or `None` for anything else
/// (an indented/nested key, a comment, a continuation line, prose). Byte-level,
/// deliberately: a plan's frontmatter block is untrusted content, and this is
/// the ONLY interpretation [`render_document`] makes of it — which hook
/// defaults to suppress, and which plan lines to drop as hook-owned.
fn plan_line_key(line: &str) -> Option<&str> {
    let (key, _) = line.split_once(':')?;
    (!key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then_some(key)
}

/// The top-level keys a plan's own frontmatter block declares — see
/// [`plan_line_key`] for what counts.
fn plan_frontmatter_keys(block: &str) -> Vec<&str> {
    block.lines().filter_map(plan_line_key).collect()
}

/// The full document written to disk, trailing-newline terminated.
///
/// A body with no leading frontmatter gets the hook's block, a blank line,
/// then the body. A body that already OPENS with its own `---` block (a plan
/// authored from the template carries `status:`/`next:`/`branch:` from birth)
/// gets ONE merged block (cadence-hooks#738): the hook-owned lines FIRST —
/// with `status`/`updated`/`branch` suppressed when the plan's block already
/// declares them — then the plan's own lines copied byte-for-byte, minus any
/// line declaring a [`HOOK_OWNED_KEYS`] key; the body resumes after the
/// plan's closing fence. Stacking a second block on top left SessionStart/
/// outro reading the hook's `status: "in-flight"` / `branch:` forever,
/// however far the plan had moved on.
///
/// The plan block is untrusted content. It is never parsed beyond
/// [`frontmatter_extent`]'s fence scan and [`plan_line_key`]'s column-0 key
/// read; hook-first ordering plus the hook-owned-key drop is what keeps a
/// plan from pre-empting the provenance keys (a plan declaring its own
/// `body_sha256:`/`approved_session_id:` would otherwise win a first-match
/// read), and from swallowing them into a malformed scalar of its own (an
/// unterminated quote or a `...` document-end marker on a plan line can only
/// damage what FOLLOWS it — now only the plan's own lines). Lines are
/// re-joined with `\n`, so a CRLF-authored block comes out LF (`str::lines`
/// strips the `\r`) — deliberate, the rest of the file is LF too.
fn render_document(f: &FrontmatterFields, body: &str) -> String {
    let Some((start, end, body_start)) = frontmatter_extent(body) else {
        return format!("{}\n\n{body}\n", render_frontmatter(f));
    };
    let plan_block = &body[start..end];
    let plan_keys = plan_frontmatter_keys(plan_block);
    let mut lines = vec!["---".to_string()];
    lines.extend(hook_frontmatter_lines(f, &plan_keys));
    lines.extend(
        plan_block
            .lines()
            .filter(|line| !plan_line_key(line).is_some_and(|k| HOOK_OWNED_KEYS.contains(&k)))
            .map(str::to_string),
    );
    lines.push("---".to_string());
    let rest = body[body_start..].trim_start_matches(['\r', '\n']);
    format!("{}\n\n{rest}\n", lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Driver tier (model-guard, cameronsjo/cadence-hooks — "stronger prose, not
// teeth"): the hook can never know the LIVE model at pickup (probed
// 2026-08-14: no `model` field on UserPromptSubmit, no structural `model` in
// the transcript before the first assistant turn), but it CAN deterministically
// parse the plan's own recorded intent — the `## Orchestrator` block's
// `Driver:` line. Each party carries its half: this parser records the tier,
// [`persist_and_nudge`] instructs Claude to compare it against the live
// model, and Claude alone completes the comparison.
// ---------------------------------------------------------------------------

/// The plan's recorded Driver tier — a closed enum, deliberately. This is the
/// injection wall: [`Tier::as_str`]'s canonical lowercase name is the ONLY
/// text [`recommended_tier`]'s callers ever render (the plan-links row, the
/// nudge directive) — never the matched source text, which is untrusted plan
/// content (same discipline as the format-gate line's stanza names below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Fable,
    Opus,
    Sonnet,
    Haiku,
}

impl Tier {
    /// The canonical lowercase family name — the sole text this enum ever
    /// contributes to rendered output.
    fn as_str(self) -> &'static str {
        match self {
            Tier::Fable => "fable",
            Tier::Opus => "opus",
            Tier::Sonnet => "sonnet",
            Tier::Haiku => "haiku",
        }
    }
}

/// Every recognized family, in a fixed order used only for the earliest-match
/// scan in [`find_drivable_token`] — priority BETWEEN anchors is decided by
/// [`recommended_tier`], not by this array's order.
const FAMILIES: [(&str, Tier); 4] = [
    ("fable", Tier::Fable),
    ("opus", Tier::Opus),
    ("sonnet", Tier::Sonnet),
    ("haiku", Tier::Haiku),
];

/// Drop every inline-code span (`` `...` ``) from `line`, non-nested. Used
/// only by [`find_drivable_token`]'s unanchored substring search, so a
/// paragraph merely discussing the syntax (`` `sonnet-drivable` ``) can never
/// forge a real match. Pairing is positional (`split('`').step_by(2)` keeps
/// even-indexed segments): with an EVEN backtick count each odd-indexed
/// segment is a genuine code span, correctly dropped; with an ODD count the
/// trailing segment — everything after the final, unpaired backtick — is
/// also dropped as if it were code. Conservative for this module's one
/// caller (an over-stripped candidate simply fails to match, never forges
/// one), but not a general-purpose inline-code stripper: callers needing
/// exact span semantics should not reuse this.
fn strip_inline_code(line: &str) -> String {
    line.split('`').step_by(2).collect::<Vec<_>>().join(" ")
}

/// Case-insensitive "does `s` begin with the whole family token `name`"
/// check, returning the tier and the remainder past the token when it does.
/// "Whole token" is the load-bearing word: the char immediately after the
/// token must be absent, whitespace, or one of the tail-introducing marks
/// tolerated elsewhere in this module (`*` \` `:` `,` `.` `(` and the dash
/// family) — never an alphanumeric or `/`. This is what makes a multi-family
/// value like `Opus/Fable` fail every family's boundary check and fall
/// through to `None` (conservative, per the plan's pinned rule), while
/// `sonnet — needs Opus fallback` still matches `sonnet` cleanly.
fn match_family_prefix(s: &str) -> Option<(Tier, &str)> {
    let lower = s.to_ascii_lowercase();
    for (name, tier) in FAMILIES {
        if let Some(after) = lower.strip_prefix(name) {
            let real_after = &s[s.len() - after.len()..];
            let boundary_ok = real_after
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '/'));
            if boundary_ok {
                return Some((tier, real_after));
            }
        }
    }
    None
}

/// Extract a `Tier` from a `Driver:`-style value, e.g. `**sonnet**`,
/// `` `sonnet` ``, or `sonnet — needs Opus fallback`. Formatting (`**`,
/// backticks) around the value is stripped before matching; anything after
/// the whole token (an em/en-dash tail, a trailing colon or comma) is
/// ignored by [`match_family_prefix`]'s boundary check.
fn extract_family_value(rest: &str) -> Option<Tier> {
    let trimmed = rest.trim().trim_matches(|c: char| c == '*' || c == '`');
    match_family_prefix(trimmed.trim_start()).map(|(tier, _)| tier)
}

/// `path`, made relative to `repo_root` and forward-slash normalized (the
/// core crate's own convention — see [`cadence_hooks_core::normalize_path`])
/// — so a value written to `plan-links.jsonl`'s `plan_path` field is stable
/// and cross-platform, regardless of the native separator
/// `PathBuf::to_string_lossy` would otherwise render on Windows. Shared by
/// [`persist_and_nudge`] and the dir-scan-skip repair so the two `plan_path`
/// derivations can never drift onto different values for the same row.
fn repo_relative(path: &Path, repo_root: &Path) -> String {
    cadence_hooks_core::normalize_path(
        &path
            .strip_prefix(repo_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned()),
    )
}

/// Is `line` exactly a level-2 `## Orchestrator` heading (surrounding
/// whitespace and a trailing marker like `## Orchestrator ⏳` tolerated via
/// [`str::trim`], but not a mere prefix)? A bare `starts_with("## Orchestrator")`
/// would also open on `## OrchestratorNotes` or `## Orchestrator2` — this
/// requires the heading TEXT to equal `"Orchestrator"` after the `## ` marker.
fn is_orchestrator_heading(line: &str) -> bool {
    line.trim_start().strip_prefix("## ").map(str::trim) == Some("Orchestrator")
}

/// The `## Orchestrator` block's lines — from just past the line-start
/// heading through (but not including) the next line-start `## ` heading, or
/// EOF. Headings inside fenced code or block quotes never open or close a
/// block ([`visible_lines`]'s discipline). On more than one `## Orchestrator`
/// heading, the FIRST wins.
fn orchestrator_block(body: &str) -> Option<Vec<&str>> {
    let mut lines = visible_lines(body).skip_while(|line| !is_orchestrator_heading(line));
    lines.next()?; // the heading line itself, consumed but not part of the block
    Some(lines.take_while(|line| !line.starts_with("## ")).collect())
}

/// Priority 1: a line-start `**Driver:**` or `Driver:` line inside the
/// `## Orchestrator` block (`plan-template.md`'s canonical form). NOT
/// inline-code-stripped: [`strip_inline_code`] is reserved for
/// [`find_drivable_token`]'s unanchored substring search — applying it here
/// would also erase a legitimately backtick-wrapped VALUE (`` **Driver:**
/// `sonnet` ``, [`extract_family_value`]'s own documented syntax), and it is
/// unneeded for decoy exclusion: a decoy anchor quoted in backticks (`` `**
/// Driver:** Sonnet` `` or a mid-sentence `` `Driver: sonnet` `` mention)
/// cannot satisfy the line-start `strip_prefix` below in the first place,
/// since a leading backtick byte breaks the literal match.
fn find_driver_line(block: &[&str]) -> Option<Tier> {
    block.iter().find_map(|line| {
        let rest = line
            .strip_prefix("**Driver:**")
            .or_else(|| line.strip_prefix("Driver:"))?;
        extract_family_value(rest)
    })
}

/// Priority 2: the prose token `<family>-drivable` (case-insensitive)
/// anywhere in the `## Orchestrator` block, inline-code-stripped (unlike
/// [`find_driver_line`] — this search is NOT line-start-anchored, so a
/// backtick-quoted mention like `` `sonnet-drivable` `` needs the strip to
/// stay excluded); the earliest match in document order wins (first matching
/// line, leftmost token on that line). BOTH boundaries checked — left, so a
/// compound like `non-sonnet-drivable` cannot false-match `sonnet-drivable`;
/// right, so `opus-drivability` (a real word continuing past the token)
/// cannot false-match `opus-drivable` — same "whole token" discipline as
/// [`match_family_prefix`]'s boundary check. A decoy earlier on the line that
/// fails either boundary check is not retried against a later, valid
/// occurrence of the same family term on that line — conservative, matching
/// this module's "ambiguous → skip" bias.
fn find_drivable_token(block: &[&str]) -> Option<Tier> {
    block.iter().find_map(|line| {
        let stripped = strip_inline_code(line);
        let lower = stripped.to_ascii_lowercase();
        FAMILIES
            .iter()
            .filter_map(|(name, tier)| {
                let needle = format!("{name}-drivable");
                let idx = lower.find(&needle)?;
                let left_ok = lower[..idx]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '-'));
                let right_ok = lower[idx + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric());
                (left_ok && right_ok).then_some((idx, *tier))
            })
            .min_by_key(|(idx, _)| *idx)
            .map(|(_, tier)| tier)
    })
}

/// Priority 3 (legacy fallback): a line-start `recommended_model:` line
/// appearing before the first line-start `## ` heading. Scanning stops at
/// the first such heading; nothing past it is a legacy header field. Not
/// inline-code-stripped — same reasoning as [`find_driver_line`] (line-start
/// anchored, so a decoy can't reach it, and stripping would eat a
/// legitimately backtick-wrapped value).
fn legacy_recommended_model(body: &str) -> Option<Tier> {
    visible_lines(body)
        .take_while(|line| !line.starts_with("## "))
        .find_map(|line| extract_family_value(line.strip_prefix("recommended_model:")?))
}

/// Parse the plan's recommended Driver tier from its body, per the pinned
/// priority order. `None` when nothing settles it — including a
/// recognized-but-invalid capture — never a guess.
fn recommended_tier(body: &str) -> Option<Tier> {
    if let Some(block) = orchestrator_block(body)
        && let Some(tier) = find_driver_line(&block).or_else(|| find_drivable_token(&block))
    {
        return Some(tier);
    }
    legacy_recommended_model(body)
}

/// The model-check directive, verbatim from the plan doc — the ONLY text
/// [`Tier`] contributes to it is [`Tier::as_str`]'s canonical name. Shared by
/// [`persist_and_nudge`] and the dir-scan-skip repair so the two nudge sites
/// can never drift onto different wording for the same instruction.
fn model_check_directive(tier: Tier) -> String {
    let t = tier.as_str();
    format!(
        "This plan's recommended driver is {t}: dispatch workers at {t} or hand the session \
         down; if you are about to execute inline, compare {t} against your running model \
         (the \"You are powered by\" line) and on a tier mismatch pause and ask before the \
         first implementation step."
    )
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
    recommended_tier: Option<Tier>,
) -> CheckResult {
    let path = match claim_target(plans_dir, stem, session_id, body_hash, document) {
        Claim::Wrote(path) | Claim::AlreadyPersisted(path) => path,
        Claim::GiveUp => return CheckResult::allow(),
    };

    let plan_path_rel = repo_relative(&path, repo_root);
    append_plan_links_row(&plan_links_row(
        utc_now,
        parent_session_id,
        child_session_id,
        machine_digest,
        &plan_path_rel,
        body_hash,
        recommended_tier.map(Tier::as_str),
    ));

    let mut nudge = format!(
        "Approved plan persisted to {} (approved in {approved_label}).",
        path.display()
    );
    // The model-check directive lands between the persist confirmation and
    // the format-gate sentences — only when a tier was actually parsed
    // (see [`recommended_tier`]); the hook has no way to know the LIVE
    // model at pickup, so it hands Claude the comparison to complete.
    if let Some(tier) = recommended_tier {
        nudge.push(' ');
        nudge.push_str(&model_check_directive(tier));
    }
    nudge.push(' ');
    nudge.push_str(
        "Verify placement, then commit it (explicit-path git add) before implementation.",
    );
    // Evaluated only after the claim succeeded: the persistence write must
    // never depend on the detectors — a future panic here eats the format-gate
    // line, never the persist (security review of this change). One composed
    // line naming only the missing stanzas (cameronsjo/cadence-hooks#715) —
    // never any matched plan text, only these static stanza names.
    let missing_stanzas = crate::plan_scan::missing_stanzas(plan_body);
    if !missing_stanzas.is_empty() {
        nudge.push(' ');
        nudge.push_str(&format!(
            "format gate: plan lacks {} — see the plan template.",
            missing_stanzas.join(", ")
        ));
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
///
/// Schema pin (cadence-hooks#690/#699): `body_sha256` is idempotency-critical
/// — [`machine_already_persisted`] keys the row-keyed re-fire suppression on
/// it, across a live stream that mixes v1 and v2 rows — and MUST never be
/// dropped or renamed. `child_session_id` is no longer consulted for
/// idempotency (#699 dropped the session conjunct) but stays pinned for
/// journey reconstruction, which reads it alongside `parent_session_id`.
/// `recommended_model` (schema v3) is OMITTED from the row — never written
/// null — when `None`, so its mere presence is the signal a consumer checks,
/// rather than a presence-plus-null-check.
fn plan_links_row(
    utc_now: &str,
    parent_session_id: Option<&str>,
    child_session_id: &str,
    machine_digest: &str,
    plan_path: &str,
    body_hash: &str,
    recommended_model: Option<&str>,
) -> Value {
    let mut row = serde_json::json!({
        "schemaVersion": PLAN_LINKS_SCHEMA_VERSION,
        "ts": utc_now,
        "parent_session_id": parent_session_id,
        "child_session_id": child_session_id,
        "machine": machine_digest,
        "plan_path": plan_path,
        "body_sha256": body_hash,
    });
    if let Some(tier) = recommended_model {
        // `Value`'s `IndexMut<&str>` inserts a missing key on assignment, so
        // this alone gets the omit-when-`None`/never-null result without an
        // `as_object_mut` unwrap.
        row["recommended_model"] = Value::from(tier);
    }
    row
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
    use cadence_hooks_core::{ToolInput, ToolResponse};
    use tempfile::TempDir;

    // --- extraction: prefix gate ---

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
    fn approval_never_writes_through_a_symlinked_docs_escaping_the_repo() {
        // End-to-end: the same escape attempt must never reach a write, not
        // just fail the unit-level helper in isolation.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let outside = TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("docs")).unwrap();
        let cwd = tmp.path().to_string_lossy().into_owned();

        let input = exit_plan_mode_post_tool_use(
            "sid12345",
            "# X\n\nbody",
            &cwd,
            &tmp.path().join("sid12345.jsonl").to_string_lossy(),
            Some(false),
        );
        let r = run_persist_plan_approval(&input, "ts", "2026-07-20", "host");
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
    fn render_document_merges_into_a_plan_s_own_frontmatter_block() {
        // cadence-hooks#738: a template-authored plan already opens with its
        // own block; the hook must MERGE, never stack a second block on top.
        let fields = base_fields("hash", "digest");
        let body =
            "---\nstatus: done\nnext: \"ship it\"\nbranch: feat/x\n---\n\n# Title\n\nbody text";
        let doc = render_document(&fields, body);
        assert_eq!(
            doc.matches("\n---\n").count(),
            1,
            "exactly one closing fence (one block), got:\n{doc}"
        );
        // Hook-owned lines first (`updated` was absent from the plan's block,
        // so the hook supplies it; `status`/`branch` are the plan's), then the
        // plan's own lines verbatim, then the one closing fence.
        assert!(doc.starts_with("---\nupdated: \"2026-07-25\"\nbody_sha256: \"hash\"\n"));
        assert!(doc.contains("\nsession_id: \"own-sid\"\n"));
        assert_eq!(doc.matches("\nstatus:").count(), 1, "{doc}");
        assert!(!doc.contains("status: \"in-flight\""));
        assert_eq!(doc.matches("\nbranch:").count(), 1);
        let (frontmatter, rest) = doc
            .split_once("---\n\n")
            .expect("closing fence + blank line");
        assert!(
            frontmatter.ends_with(
                "\nmachine: \"digest\"\nstatus: done\nnext: \"ship it\"\nbranch: feat/x\n"
            )
        );
        assert_eq!(rest, "# Title\n\nbody text\n");
    }

    #[test]
    fn render_document_merge_copies_plan_keys_verbatim_without_interpreting_them() {
        // Untrusted content: odd but well-formed lines pass through unchanged,
        // and only a column-0 `ident:` suppresses a hook default.
        let fields = base_fields("hash", "digest");
        let body = "---\n  status: nested-is-not-top-level\n# status: a comment\nweird key: \"x\"\n---\nbody";
        let doc = render_document(&fields, body);
        assert!(doc.contains("\n  status: nested-is-not-top-level\n"));
        assert!(doc.contains("\n# status: a comment\n"));
        assert!(doc.contains("\nweird key: \"x\"\n"));
        // None of those count as the plan declaring `status`, so the hook's
        // default is still emitted — exactly once.
        assert_eq!(doc.matches("\nstatus: \"in-flight\"\n").count(), 1);
        assert_eq!(doc.matches("\n---\n").count(), 1);
        assert!(doc.ends_with("---\n\nbody\n"));
    }

    #[test]
    fn render_document_merge_drops_plan_lines_that_claim_hook_owned_keys() {
        // A plan block declaring the hook's provenance keys must not be able
        // to forge them: its lines are dropped, the hook's come first, and
        // each hook-owned key appears exactly once with the hook's value.
        let fields = base_fields("real-hash", "real-digest");
        let body = "---\nbody_sha256: \"forged\"\nsession_id: \"forged-sid\"\n\
                    approved_session_id: \"forged-approver\"\nmachine: \"forged-machine\"\n\
                    status: done\n---\n\nbody";
        let doc = render_document(&fields, body);
        assert!(!doc.contains("forged"), "{doc}");
        for key in HOOK_OWNED_KEYS {
            let count = doc.matches(&format!("\n{key}:")).count();
            assert!(count <= 1, "{key} appears {count} times:\n{doc}");
        }
        assert!(doc.contains("\nbody_sha256: \"real-hash\"\n"));
        assert!(doc.contains("\nsession_id: \"own-sid\"\n"));
        assert!(doc.contains("\nmachine: \"real-digest\"\n"));
        // The plan's non-owned key survives, after the hook's lines.
        let (frontmatter, _) = doc.split_once("---\n\n").unwrap();
        assert!(frontmatter.ends_with("\nstatus: done\n"));
        assert!(!doc.contains("status: \"in-flight\""));
        assert_eq!(doc.matches("\n---\n").count(), 1);
    }

    #[test]
    fn render_document_merge_keeps_hook_keys_ahead_of_a_malformed_plan_line() {
        // An unterminated quote on the plan's last line can only swallow what
        // follows it — and nothing hook-owned follows it any more.
        let fields = base_fields("hash", "digest");
        let doc = render_document(&fields, "---\ntitle: \"unterminated\n---\nbody");
        let (frontmatter, _) = doc.split_once("---\n\n").unwrap();
        let hook_at = frontmatter.find("\nbody_sha256:").unwrap();
        let plan_at = frontmatter.find("\ntitle:").unwrap();
        assert!(hook_at < plan_at, "{doc}");
        assert!(frontmatter.ends_with("\ntitle: \"unterminated\n"));
    }

    #[test]
    fn render_document_without_a_closing_fence_is_not_a_frontmatter_block() {
        // A body that merely starts with `---` and never closes it is prose;
        // the hook's block is prepended as usual.
        let fields = base_fields("hash", "digest");
        let doc = render_document(&fields, "---\nnot a block\n\n# Title");
        assert!(doc.starts_with("---\nstatus: \"in-flight\"\n"));
        assert!(doc.contains("---\n\n---\nnot a block\n\n# Title\n"));
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

    #[test]
    fn recommended_tier_priority_1_bold_driver_line() {
        let body = "## Orchestrator\n\n**Driver:** Sonnet — fully spec'd, no escalation.";
        assert_eq!(recommended_tier(body), Some(Tier::Sonnet));
    }

    #[test]
    fn recommended_tier_priority_1_plain_driver_line() {
        let body = "## Orchestrator\n\nDriver: opus\n";
        assert_eq!(recommended_tier(body), Some(Tier::Opus));
    }

    #[test]
    fn recommended_tier_priority_2_drivable_prose_token() {
        // The pinned checkout-freshness Orchestrator block, verbatim (R4
        // fixture note): no `Driver:` line, only the priority-2 prose token.
        let body = "## Orchestrator\n\nBoth parts are tightly specced and Sonnet-drivable as \
             fresh implementer dispatches from the committed plan (bash script per contract; \
             Rust part follows an existing append pattern with a named seam). Driver \
             announcement at approval.";
        assert_eq!(recommended_tier(body), Some(Tier::Sonnet));
    }

    #[test]
    fn recommended_tier_priority_3_legacy_recommended_model() {
        let body = "recommended_model: fable\n\n## Goal\n\nDo the thing.";
        assert_eq!(recommended_tier(body), Some(Tier::Fable));
    }

    #[test]
    fn recommended_tier_legacy_field_ignored_past_first_heading() {
        // `recommended_model:` is a legacy HEADER field — nothing past the
        // first `## ` heading is in scope for priority 3.
        let body = "## Goal\n\nrecommended_model: fable\n";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_priority_order_driver_line_wins_over_prose_token() {
        let body = "## Orchestrator\n\n**Driver:** Opus — escalated.\n\nHaiku-drivable as a \
             fallback if budget tightens.";
        assert_eq!(recommended_tier(body), Some(Tier::Opus));
    }

    #[test]
    fn recommended_tier_backtick_decoy_excluded() {
        let body = "## Orchestrator\n\nThis plan does not use the `Driver: sonnet` syntax \
             anywhere in its body.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_fenced_code_decoy_excluded() {
        let body = "## Orchestrator\n\n```\nDriver: sonnet\n```\n";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_conflicting_anchors_priority_order_wins() {
        let body = "recommended_model: haiku\n\n## Orchestrator\n\n**Driver:** Opus — the \
             newer, higher-priority anchor.";
        assert_eq!(recommended_tier(body), Some(Tier::Opus));
    }

    #[test]
    fn recommended_tier_em_dash_tail_tolerated() {
        let body = "## Orchestrator\n\nDriver: sonnet — fully spec'd against a named file.";
        assert_eq!(recommended_tier(body), Some(Tier::Sonnet));
    }

    #[test]
    fn recommended_tier_multi_family_value_is_none() {
        let body = "## Orchestrator\n\n**Driver:** Opus/Fable — undecided.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_absent_is_none() {
        let body = "## Goal\n\nDo the thing.\n\n## Approach\n\n1. Step one.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_backtick_wrapped_value_still_matches() {
        // Regression: strip_inline_code used to run over the whole line
        // before the Driver: prefix match, which silently ate a legitimately
        // backtick-wrapped VALUE — the exact syntax extract_family_value's
        // own doc comment documents as supported.
        let body = "## Orchestrator\n\n**Driver:** `sonnet`";
        assert_eq!(recommended_tier(body), Some(Tier::Sonnet));
    }

    #[test]
    fn recommended_tier_priority2_hyphen_compound_no_false_match() {
        // Regression: find_drivable_token had no left word-boundary check,
        // so "non-sonnet-drivable" false-matched "sonnet-drivable".
        let body = "## Orchestrator\n\nThis work is NOT non-sonnet-drivable; it needs escalation.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_priority2_right_boundary_no_false_match() {
        // Regression: find_drivable_token had no right word-boundary check,
        // so "opus-drivability" (a real word continuing past the token)
        // false-matched "opus-drivable".
        let body = "## Orchestrator\n\nThis section is barely opus-drivability at this stage.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_priority2_backtick_decoy_excluded() {
        let body = "## Orchestrator\n\nThis plan does not use the `sonnet-drivable` token \
             anywhere in its body.";
        assert_eq!(recommended_tier(body), None);
    }

    #[test]
    fn recommended_tier_orchestrator_heading_must_match_exactly() {
        // Regression: orchestrator_block's opening check was a bare
        // starts_with("## Orchestrator"), so "## OrchestratorNotes" opened
        // the block too — this plan's real Orchestrator section (if any)
        // never appears, so the Driver: line under the imposter heading must
        // NOT be picked up.
        let body = "## OrchestratorNotes\n\n**Driver:** Sonnet";
        assert_eq!(recommended_tier(body), None);
    }

    // --- nudge composition ---

    #[test]
    fn nudge_includes_directive_between_persist_sentence_and_format_gates_when_some() {
        let tmp = TempDir::new().unwrap();
        let plans_dir = tmp.path().join("docs/plans");
        fs::create_dir_all(&plans_dir).unwrap();
        let body = "## Orchestrator\n\n**Driver:** Sonnet — fully spec'd.";
        let r = persist_and_nudge(
            &plans_dir,
            "2026-08-16-x",
            "session-id",
            "hash",
            "document text",
            "2026-08-16T00:00:00Z",
            None,
            "session-id",
            "digest",
            tmp.path(),
            "unknown",
            body,
            recommended_tier(body),
        );
        let msg = r.message.unwrap();
        let persisted_idx = msg.find("Approved plan persisted to").unwrap();
        let directive_idx = msg
            .find("This plan's recommended driver is sonnet")
            .expect("directive must be present when tier is Some");
        let verify_idx = msg.find("Verify placement,").unwrap();
        assert!(
            persisted_idx < directive_idx && directive_idx < verify_idx,
            "directive must land between the persist sentence and the format gates: {msg}"
        );
    }

    #[test]
    fn nudge_omits_directive_when_tier_is_none() {
        let tmp = TempDir::new().unwrap();
        let plans_dir = tmp.path().join("docs/plans");
        fs::create_dir_all(&plans_dir).unwrap();
        let body = "## Goal\n\nDo the thing.";
        let r = persist_and_nudge(
            &plans_dir,
            "2026-08-16-x",
            "session-id",
            "hash",
            "document text",
            "2026-08-16T00:00:00Z",
            None,
            "session-id",
            "digest",
            tmp.path(),
            "unknown",
            body,
            recommended_tier(body),
        );
        let msg = r.message.unwrap();
        assert!(
            !msg.contains("recommended driver"),
            "no directive text when no tier was parsed: {msg}"
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
            Some("sonnet"),
        );
        assert_eq!(row["schemaVersion"], 3);
        assert_eq!(row["ts"], "2026-07-20T00:00:00Z");
        assert_eq!(row["parent_session_id"], "parent-sid");
        assert_eq!(row["child_session_id"], "child-sid");
        assert_eq!(row["machine"], "digest");
        assert_eq!(row["plan_path"], "docs/plans/2026-07-20-x.md");
        assert_eq!(row["body_sha256"], "hash");
        assert_eq!(row["recommended_model"], "sonnet");
        assert!(
            row.get("host").is_none() && row.get("repo").is_none(),
            "v3 still drops both the raw host and the repo field: {row}"
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
            None,
        );
        assert!(row["parent_session_id"].is_null());
    }

    #[test]
    fn plan_links_row_omits_recommended_model_when_none() {
        // Deliberately NOT the null convention `parent_session_id` uses above
        // — `recommended_model` (schema v3) is OMITTED, never written null,
        // when the plan carries no recognized `Driver:` anchor.
        let row = plan_links_row(
            "2026-07-20T00:00:00Z",
            Some("parent-sid"),
            "child-sid",
            "digest",
            "docs/plans/2026-07-20-x.md",
            "hash",
            None,
        );
        assert!(
            row.get("recommended_model").is_none(),
            "recommended_model must be omitted, not null, when unrecognized: {row}"
        );
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
    fn plan_store_read_accepts_only_md_nested_under_the_store_root() {
        let store = TempDir::new().unwrap();
        let root = store.path();
        let inside = root.join("my-plan.md");
        fs::write(&inside, "# Stored Plan\n\nbody from the plan store.").unwrap();

        // In-store .md — the one accepted shape.
        let got = read_plan_store_file_within(&inside.to_string_lossy(), root).unwrap();
        assert!(got.contains("# Stored Plan"));

        // Outside the store root — rejected even as a real, readable .md.
        // This is the arbitrary-local-file-read sink the containment closes:
        // a payload naming a secret outside the plan store must read as
        // "no plan", never as content to persist.
        let outside_dir = TempDir::new().unwrap();
        let outside = outside_dir.path().join("secrets.md");
        fs::write(&outside, "SECRET").unwrap();
        assert_eq!(
            read_plan_store_file_within(&outside.to_string_lossy(), root),
            None
        );

        // Wrong extension in-store — rejected.
        let key = root.join("id_ed25519");
        fs::write(&key, "PRIVATE KEY").unwrap();
        assert_eq!(
            read_plan_store_file_within(&key.to_string_lossy(), root),
            None
        );

        // A symlinked .md in-store pointing outside — rejected: the whole
        // final path canonicalizes before the nesting check.
        #[cfg(unix)]
        {
            let link = root.join("escape.md");
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            assert_eq!(
                read_plan_store_file_within(&link.to_string_lossy(), root),
                None
            );
        }
    }

    #[test]
    fn approval_plan_store_path_outside_the_store_never_persists() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        // A real, readable markdown file — but not under the harness plan
        // store, so the fallback chain must end in a silent allow.
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
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path()
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
    fn format_gate_sentences_ride_the_persist_nudge() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();

        // A harness-template-shaped plan: no Panel, no Alternatives, no boxes.
        let bare = exit_plan_mode_post_tool_use(
            "fmt-session",
            "# Bare Plan\n\nContext prose only.",
            &cwd,
            &tmp.path().join("fmt-session.jsonl").to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&bare, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        let msg = r.message.unwrap();
        // One composed format-gate line naming every missing stanza
        // (cameronsjo/cadence-hooks#715) — never three separate sentences.
        assert!(msg.contains("format gate: plan lacks "));
        assert!(msg.contains("a settled Panel: line"));
        assert!(msg.contains("an Alternatives-declined stanza"));
        assert!(msg.contains("checkbox tasks"));
        assert!(msg.contains("see the plan template."));
        assert_eq!(
            msg.matches("format gate:").count(),
            1,
            "one composed line, not one per stanza: {msg}"
        );

        // A template-conforming plan gets the plain persist nudge only.
        let full = exit_plan_mode_post_tool_use(
            "fmt-session-2",
            "# Full Plan\n\nPanel: reviewer ran — 1 finding, \
             1 folded in, 0 declined\n\n## Alternatives declined\n\n- none proposed — single \
             obvious approach\n\n- [ ] build it\n",
            &cwd,
            &tmp.path().join("fmt-session-2.jsonl").to_string_lossy(),
            Some(false),
        );
        let r2 = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&full, "2026-08-11T00:00:00Z", "2026-08-11", "test-host")
        });
        let msg2 = r2.message.unwrap();
        assert!(!msg2.contains("format gate:"));
        assert!(!msg2.contains("panel gate:"));
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
            msg.contains("format gate: plan lacks a settled Panel: line"),
            "unsettled Panel: line must name the missing stanza: {msg}"
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
            !msg.contains("a settled Panel: line"),
            "a settled Panel: line must not appear among the missing stanzas: {msg}"
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
        assert!(!r.message.unwrap().contains("a settled Panel: line"));
    }

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
    fn end_to_end_approval_merges_a_template_plan_s_frontmatter_into_one_block() {
        // cadence-hooks#738 end to end: the written file carries ONE block
        // whose `status:` is the plan's, and the SessionStart scanner's
        // reader (`leading_frontmatter_block`) sees the plan's keys.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript_path = tmp.path().join("merge-sid.jsonl");
        fs::write(&transcript_path, "{}").unwrap();

        let input = exit_plan_mode_post_tool_use(
            "merge-sid",
            "---\nstatus: in-flight\nnext: \"Phase 2\"\nbranch: main\n---\n\n# Merge Me\n\n- [x] done",
            &cwd,
            &transcript_path.to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let written =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-merge-me.md")).unwrap();
        assert_eq!(
            written.matches("\n---\n").count(),
            1,
            "one block:\n{written}"
        );
        let block = leading_frontmatter_block(&written).expect("leading block");
        assert!(block.starts_with("updated: \"2026-07-20\"\nbody_sha256: \""));
        assert!(block.ends_with("\nstatus: in-flight\nnext: \"Phase 2\"\nbranch: main\n"));
        assert!(block.contains("approved_session_id: \"merge-sid\""));
        assert_eq!(block.matches("status:").count(), 1);
        assert_eq!(block.matches("branch:").count(), 1);
        assert!(written.ends_with("---\n\n# Merge Me\n\n- [x] done\n"));
    }

    #[test]
    fn approval_opt_out_via_process_env_writes_nothing() {
        // cadence-hooks#692: any non-empty CADENCE_NO_PERSIST_PLAN skips the
        // persist (no file, no row), exit-clean allow.
        // Every approval test in this module reads the process env for the
        // flag, and the ones asserting a persist run inside `with_metrics_dir`,
        // which takes `METRICS_ENV_LOCK` — so holding that same lock across
        // the set/unset here is what keeps a concurrently running sibling
        // from observing the flag. `CADENCE_METRICS_DIR` is set by hand for
        // the same reason (calling `with_metrics_dir` would self-deadlock).
        let _guard = crate::registry::test_metrics_env::METRICS_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript_path = tmp.path().join("optout-sid.jsonl");
        fs::write(&transcript_path, "{}").unwrap();
        let input = exit_plan_mode_post_tool_use(
            "optout-sid",
            "# Opt Out\n\nbody",
            &cwd,
            &transcript_path.to_string_lossy(),
            Some(false),
        );
        let prev_metrics = std::env::var_os("CADENCE_METRICS_DIR");
        // SAFETY: serialized on METRICS_ENV_LOCK above, like `with_metrics_dir`.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", metrics_dir.path());
            std::env::set_var("CADENCE_NO_PERSIST_PLAN", "1");
        }
        let r =
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host");
        unsafe { std::env::remove_var("CADENCE_NO_PERSIST_PLAN") };
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path().join("docs/plans").exists(),
            "no plans dir, no file"
        );
        assert!(!metrics_dir.path().join("plan-links.jsonl").exists());

        // Control: the same payload without the flag persists.
        let r2 =
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host");
        unsafe {
            match prev_metrics {
                Some(v) => std::env::set_var("CADENCE_METRICS_DIR", v),
                None => std::env::remove_var("CADENCE_METRICS_DIR"),
            }
        }
        assert_eq!(r2.outcome, Outcome::Nudge);
        assert!(tmp.path().join("docs/plans/2026-07-20-opt-out.md").exists());
    }

    #[test]
    fn approval_opt_out_via_repo_settings_env_block_writes_nothing() {
        // Repo-level flag only — no process env mutation, so no lock needed.
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        fs::write(
            tmp.path().join(".claude/settings.json"),
            r#"{"env":{"CADENCE_NO_PERSIST_PLAN":"1"}}"#,
        )
        .unwrap();
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript_path = tmp.path().join("optout2.jsonl");
        fs::write(&transcript_path, "{}").unwrap();
        let input = exit_plan_mode_post_tool_use(
            "optout2",
            "# Opt Out Two\n\nbody",
            &cwd,
            &transcript_path.to_string_lossy(),
            Some(false),
        );
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(!tmp.path().join("docs/plans").exists());
        // An EMPTY value is not an opt-out.
        fs::write(
            tmp.path().join(".claude/settings.json"),
            r#"{"env":{"CADENCE_NO_PERSIST_PLAN":""}}"#,
        )
        .unwrap();
        let r2 = with_metrics_dir(metrics_dir.path(), || {
            run_persist_plan_approval(&input, "2026-07-20T00:00:00Z", "2026-07-20", "test-host")
        });
        assert_eq!(r2.outcome, Outcome::Nudge);
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

    // --- injected-prompt arm (approve-and-clear coverage) ---

    /// A transcript whose rows mirror the live approve-and-clear shape: a few
    /// non-user rows first, then the first user row carrying `text` as string
    /// content.
    fn write_child_transcript(dir: &Path, first_user_text: &str) -> PathBuf {
        let path = dir.join("child-transcript.jsonl");
        let user_row = serde_json::json!({
            "type": "user",
            "message": {"role": "user", "content": first_user_text},
        });
        let content = format!(
            "{}\n{}\n{}\n",
            r#"{"type":"mode","mode":"normal"}"#,
            r#"{"type":"attachment","attachment":{"type":"hook_success","hookName":"SessionStart:clear"}}"#,
            user_row,
        );
        fs::write(&path, content).unwrap();
        path
    }

    /// The injected prompt as the harness composes it: prefix, plan body,
    /// pointer paragraph naming the parent transcript, breakdown suffix.
    fn injected_prompt(parent_id: &str) -> String {
        format!(
            "Implement the following plan:\n\n# Injected Plan\n\nDo the injected thing.\n\n\
             If you need specific details from before exiting plan mode (like exact code \
             snippets), read the full transcript at: /Users/x/.claude/projects/p/{parent_id}.jsonl\n\n\
             If this plan can be broken down into discrete units of work, consider using the \
             Agent tool to dispatch them."
        )
    }

    /// Session ids must be unique per test INVOCATION, not just per test:
    /// the injected arm's session marker lives in the stable marker temp dir
    /// and survives across `cargo test` runs, so a reused id inherits a
    /// marker an earlier run wrote and every persist assertion reads Allow.
    fn unique_session_id(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{tag}-{}-{nanos}", std::process::id())
    }

    fn injected_input(cwd: &str, transcript: &Path, session_id: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            cwd: Some(cwd.into()),
            session_id: Some(session_id.into()),
            transcript_path: Some(transcript.to_string_lossy().into_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn injected_arm_persists_the_implement_prompt_plan() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let parent_id = "11111111-2222-3333-4444-555555555501";
        let transcript = write_child_transcript(tmp.path(), &injected_prompt(parent_id));
        let sid = unique_session_id("child-e2e");
        let input = injected_input(&cwd, &transcript, &sid);

        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge, "injected plan must persist");
        let doc =
            fs::read_to_string(tmp.path().join("docs/plans/2026-08-25-injected-plan.md")).unwrap();
        let parent_name = identity::generate_name(parent_id);
        assert!(
            doc.contains(&format!("approved_in: \"{parent_name}\"")),
            "approved_in must name the PARENT session, not the child: {doc}"
        );
        assert!(
            doc.contains(&format!("approved_session_id: \"{parent_id}\"")),
            "approved_session_id must carry the parent id: {doc}"
        );
        assert!(
            doc.ends_with("Do the injected thing.\n"),
            "harness suffix paragraphs must be stripped: {doc}"
        );
        let rows = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        // Select THIS persist's row by child id rather than assuming file
        // position — the metrics env var is process-global, and a row from a
        // concurrently-running test landing in this dir must not fail the
        // assertion about OUR row.
        let own: Vec<Value> = rows
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|r: &Value| r["child_session_id"] == sid.as_str())
            .collect();
        assert_eq!(own.len(), 1, "one row for this persist; file: {rows}");
        assert_eq!(own[0]["parent_session_id"], parent_id, "file: {rows}");
    }

    #[test]
    fn injected_arm_marker_bounds_the_scan_to_once_per_session() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        // First fire: an ordinary greeting — definitive NotInjected.
        let transcript = write_child_transcript(tmp.path(), "good morning");
        let sid = unique_session_id("child-marker");
        let input = injected_input(&cwd, &transcript, &sid);
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow);

        // Second fire: even if the transcript now LOOKS injected (it can't in
        // reality — the first row is immutable — but this pins the marker
        // short-circuit), nothing persists.
        let transcript = write_child_transcript(
            tmp.path(),
            &injected_prompt("11111111-2222-3333-4444-555555555502"),
        );
        let input = injected_input(&cwd, &transcript, &sid);
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow, "marker must short-circuit");
        assert!(
            !tmp.path()
                .join("docs/plans/2026-08-25-injected-plan.md")
                .exists(),
            "a NotInjected verdict is final for the session"
        );
    }

    #[test]
    fn injected_arm_no_user_row_yet_leaves_no_marker_and_retries() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        // Head with no user row at all — the SessionStart race window.
        let transcript = tmp.path().join("child-transcript.jsonl");
        fs::write(&transcript, "{\"type\":\"mode\",\"mode\":\"normal\"}\n").unwrap();
        let sid = unique_session_id("child-race");
        let input = injected_input(&cwd, &transcript, &sid);
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow);

        // The prompt lands; the NEXT fire must still be able to persist.
        let transcript = write_child_transcript(
            tmp.path(),
            &injected_prompt("11111111-2222-3333-4444-555555555503"),
        );
        let input = injected_input(&cwd, &transcript, &sid);
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(
            r.outcome,
            Outcome::Nudge,
            "no-user-row must not burn the marker"
        );
        assert!(
            tmp.path()
                .join("docs/plans/2026-08-25-injected-plan.md")
                .exists()
        );
    }

    #[test]
    fn injected_arm_subagent_context_never_persists() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript = write_child_transcript(
            tmp.path(),
            &injected_prompt("11111111-2222-3333-4444-555555555504"),
        );
        let sid = unique_session_id("child-agent");
        let mut input = injected_input(&cwd, &transcript, &sid);
        input.agent_id = Some("a1".into());
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Allow);
        assert!(
            !tmp.path()
                .join("docs/plans/2026-08-25-injected-plan.md")
                .exists(),
            "a subagent's task prompt is not an approval"
        );
    }

    #[test]
    fn injected_arm_without_pointer_omits_approved_in() {
        let tmp = TempDir::new().unwrap();
        init_repo(tmp.path());
        let cwd = tmp.path().to_string_lossy().into_owned();
        let metrics_dir = TempDir::new().unwrap();
        let transcript = write_child_transcript(
            tmp.path(),
            "Implement the following plan:\n\n# Pointerless Plan\n\nJust the body.",
        );
        let sid = unique_session_id("child-noptr");
        let input = injected_input(&cwd, &transcript, &sid);
        let r = with_metrics_dir(metrics_dir.path(), || {
            run_injected_plan_persist(&input, "2026-08-25T00:00:00Z", "2026-08-25", "test-host")
        });
        assert_eq!(r.outcome, Outcome::Nudge);
        let doc = fs::read_to_string(tmp.path().join("docs/plans/2026-08-25-pointerless-plan.md"))
            .unwrap();
        assert!(
            !doc.contains("approved_in:"),
            "unknown approver must be omitted, never guessed: {doc}"
        );
        let rows = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        let row: Value = serde_json::from_str(rows.lines().next().unwrap()).unwrap();
        assert_eq!(row["parent_session_id"], Value::Null);
    }

    // --- injected_first_prompt / parent pointer (pure) ---

    #[test]
    fn injected_scan_array_content_reads_first_text_item() {
        let head = concat!(
            "{\"type\":\"attachment\"}\n",
            "{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\
             \"text\":\"Implement the following plan:\\n\\n# A\\n\\nb\"}]}}\n",
        );
        match injected_first_prompt(head) {
            InjectedScan::Plan(rest) => assert!(rest.contains("# A")),
            _ => panic!("array-shaped content must classify as Plan"),
        }
    }

    #[test]
    fn injected_scan_skips_sidechain_user_rows() {
        let head = concat!(
            "{\"type\":\"user\",\"isSidechain\":true,\"message\":{\"content\":\
             \"Implement the following plan:\\n\\nsub-task\"}}\n",
            "{\"type\":\"user\",\"message\":{\"content\":\"good morning\"}}\n",
        );
        assert!(
            matches!(injected_first_prompt(head), InjectedScan::NotInjected),
            "a sidechain row must not decide the verdict"
        );
    }

    #[test]
    fn injected_scan_first_user_row_without_text_is_not_injected() {
        let head = "{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"tool_result\"}]}}\n";
        assert!(matches!(
            injected_first_prompt(head),
            InjectedScan::NotInjected
        ));
    }

    #[test]
    fn parent_pointer_parses_the_transcript_stem() {
        let raw = injected_prompt("11111111-2222-3333-4444-555555555505");
        assert_eq!(
            parent_session_id_from_pointer(&raw).as_deref(),
            Some("11111111-2222-3333-4444-555555555505")
        );
    }

    #[test]
    fn parent_pointer_rejects_an_unsafe_stem() {
        let raw = "If you need specific details from before exiting plan mode, read the full \
                   transcript at: /tmp/$(evil).jsonl";
        assert_eq!(parent_session_id_from_pointer(raw), None);
    }
}
