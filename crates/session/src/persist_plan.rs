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
use std::io::Write as _;
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

/// Cap on the generated slug's length (before the date prefix).
const MAX_SLUG_LEN: usize = 60;

/// Slug used when the plan body carries no ATX heading.
const DEFAULT_SLUG: &str = "approved-plan";

/// Numeric suffixes tried after the bare stem, before the short-id fallback.
/// Combined with the bare stem this is 9 total candidates ("all nine
/// suffixes taken" in the plan doc), after which [`fallback_path`] is tried.
const NUMERIC_SUFFIXES: std::ops::RangeInclusive<u32> = 2..=9;

/// How far back a sibling transcript may sit and still be scanned for the
/// approving `ExitPlanMode` call.
const PARENT_SCAN_MAX_AGE: Duration = Duration::from_secs(48 * 3600);

/// How many of the newest sibling transcripts are scanned.
const PARENT_SCAN_MAX_FILES: usize = 20;

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
        run_persist_plan(
            input,
            &cadence_hooks_core::time::utc_timestamp(),
            &cadence_hooks_core::time::local_date(),
            &host,
        )
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

    let parent_session_id = input
        .transcript_path()
        .and_then(|tp| find_parent_session_id(Path::new(tp), &body_hash, SystemTime::now()));
    let parent_name = parent_session_id.as_deref().map(identity::generate_name);
    let own_name = identity::generate_name(session_id);

    let provenance = provenance_block(
        parent_name.as_deref(),
        parent_session_id.as_deref(),
        &own_name,
        session_id,
        host,
        utc_now,
        &body_hash,
    );
    let document = format!("{body}\n\n---\n\n{provenance}");

    let path = match claim_target(&plans_dir, &stem, session_id, &body_hash, &document) {
        Claim::Wrote(path) | Claim::AlreadyPersisted(path) => path,
        Claim::GiveUp => return CheckResult::allow(),
    };

    let plan_path_rel = path
        .strip_prefix(&repo_root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned());
    append_plan_links_row(&plan_links_row(
        utc_now,
        parent_session_id.as_deref(),
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

/// Strip trailing lines whose trimmed text starts with [`SUFFIX_LINE_PREFIX`],
/// interleaved with trailing blank lines (either can follow the other), then
/// trim leading blank lines. A single unified pass so trailing whitespace
/// around the suffix line never leaves a stray blank line or an unstripped
/// suffix behind.
fn strip_trailing_suffix_lines_and_trim(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    loop {
        match lines.last() {
            Some(last) if last.trim().is_empty() => {
                lines.pop();
            }
            Some(last) if last.trim_start().starts_with(SUFFIX_LINE_PREFIX) => {
                lines.pop();
            }
            _ => break,
        }
    }
    while let Some(first) = lines.first() {
        if first.trim().is_empty() {
            lines.remove(0);
        } else {
            break;
        }
    }
    lines.join("\n")
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

/// Read `path` and return the value of its `Plan-body-SHA256:` provenance
/// line, if present.
fn file_body_hash(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        line.strip_prefix("Plan-body-SHA256:")
            .map(|rest| rest.trim().to_string())
    })
}

/// Try each candidate in order with `create_new` (O_EXCL): a fresh path wins
/// outright; an occupied path is re-checked by hash — a match is a re-fire
/// (idempotent skip), a mismatch tries the next candidate. Never overwrites
/// anything.
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
                if file_body_hash(&path).as_deref() == Some(body_hash) {
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

/// A transcript line's `ExitPlanMode` tool_use plan text, if this line is an
/// assistant message carrying one. Mirrors
/// `cadence_hooks_core::transcript::line_is_polish_skill_use`'s traversal.
fn exit_plan_mode_text(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    let content = value.get("message")?.get("content")?.as_array()?;
    content.iter().find_map(|block| {
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
    })
}

/// Scan `transcript_path`'s sibling directory for the transcript whose
/// `ExitPlanMode` plan text — normalized by the same suffix-strip-and-trim
/// applied to the injected prompt — hashes to `target_hash`. Newest-first,
/// bounded to [`PARENT_SCAN_MAX_FILES`] siblings no older than
/// [`PARENT_SCAN_MAX_AGE`], substring-pre-filtered before any JSON parse.
/// `now` is the caller's `SystemTime::now()`, threaded through for testability
/// without a frozen clock. Returns the session id (the sibling's file stem) on
/// the first exact match — never a fuzzy guess.
fn find_parent_session_id(
    transcript_path: &Path,
    target_hash: &str,
    now: SystemTime,
) -> Option<String> {
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
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if !content.contains("ExitPlanMode") {
            continue;
        }
        for line in content.lines() {
            if !line.contains("ExitPlanMode") {
                continue;
            }
            let Some(plan_text) = exit_plan_mode_text(line) else {
                continue;
            };
            let normalized = strip_trailing_suffix_lines_and_trim(&plan_text);
            if sha256_hex(normalized.as_bytes()) == target_hash {
                return path.file_stem().map(|s| s.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Render the provenance block appended to every persisted plan.
fn provenance_block(
    parent_name: Option<&str>,
    parent_session_id: Option<&str>,
    own_name: &str,
    own_session_id: &str,
    host: &str,
    utc_now: &str,
    body_hash: &str,
) -> String {
    let approved_in = match (parent_name, parent_session_id) {
        (Some(name), Some(sid)) => format!("Approved in: {name} ({sid}) @ {host}"),
        _ => "Approved in: unknown".to_string(),
    };
    format!(
        "{approved_in}\nExecuting session: {own_name} ({own_session_id}) @ {host}\n\
         Persisted: {utc_now}\nPlan-body-SHA256: {body_hash}\n"
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

    // --- provenance: parent resolution ---

    fn exit_plan_mode_line(plan: &str) -> String {
        serde_json::json!({
            "message": {
                "role": "assistant",
                "content": [{"type": "tool_use", "name": "ExitPlanMode", "input": {"plan": plan}}]
            }
        })
        .to_string()
    }

    #[test]
    fn find_parent_exact_hash_match() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(&sibling, exit_plan_mode_line(plan_text)).unwrap();

        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent_session_id(&own, &hash, SystemTime::now());
        assert_eq!(found.as_deref(), Some("parent-session-id"));
    }

    #[test]
    fn find_parent_same_file_wipe_resolves_to_self() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody text";
        let hash = sha256_hex(plan_text.as_bytes());
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, exit_plan_mode_line(plan_text)).unwrap();

        let found = find_parent_session_id(&own, &hash, SystemTime::now());
        assert_eq!(
            found.as_deref(),
            Some("own-session-id"),
            "same-file wipe: parent resolves to the executing session itself"
        );
    }

    #[test]
    fn find_parent_no_match_is_unknown() {
        let tmp = TempDir::new().unwrap();
        let sibling = tmp.path().join("parent-session-id.jsonl");
        fs::write(&sibling, exit_plan_mode_line("some other plan")).unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent_session_id(&own, "nonexistent-hash", SystemTime::now());
        assert_eq!(found, None);
    }

    #[test]
    fn find_parent_ignores_files_beyond_max_age() {
        let tmp = TempDir::new().unwrap();
        let plan_text = "# Title\n\nbody";
        let hash = sha256_hex(plan_text.as_bytes());
        let sibling = tmp.path().join("old-session.jsonl");
        fs::write(&sibling, exit_plan_mode_line(plan_text)).unwrap();
        let own = tmp.path().join("own-session.jsonl");
        fs::write(&own, "{}").unwrap();

        // `now` is 49 hours after the file's real mtime — beyond the 48h window.
        let future = SystemTime::now() + Duration::from_secs(49 * 3600);
        let found = find_parent_session_id(&own, &hash, future);
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
        fs::write(&sibling, exit_plan_mode_line("# Title\n\nbody text\n\n")).unwrap();
        let own = tmp.path().join("own-session-id.jsonl");
        fs::write(&own, "{}").unwrap();

        let found = find_parent_session_id(&own, &hash, SystemTime::now());
        assert_eq!(found.as_deref(), Some("parent-session-id"));
    }

    #[test]
    fn provenance_block_unknown_parent() {
        let block = provenance_block(None, None, "own-name", "own-sid", "host", "ts", "hash");
        assert!(block.starts_with("Approved in: unknown\n"));
        assert!(block.contains("Executing session: own-name (own-sid) @ host"));
        assert!(block.contains("Persisted: ts"));
        assert!(block.contains("Plan-body-SHA256: hash"));
    }

    #[test]
    fn provenance_block_found_parent() {
        let block = provenance_block(
            Some("parent-name"),
            Some("parent-sid"),
            "own-name",
            "own-sid",
            "host",
            "ts",
            "hash",
        );
        assert!(block.starts_with("Approved in: parent-name (parent-sid) @ host\n"));
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
        assert!(msg.contains("docs/plans/2026-07-20-fix-the-widget.md"));
        assert!(msg.contains("approved in unknown"));

        let written =
            fs::read_to_string(tmp.path().join("docs/plans/2026-07-20-fix-the-widget.md")).unwrap();
        assert!(written.starts_with("# Fix the Widget"));
        assert!(!written.contains("If this plan can be broken down"));
        assert!(written.contains("Executing session:"));
        assert!(written.contains("Plan-body-SHA256:"));

        let links = fs::read_to_string(metrics_dir.path().join("plan-links.jsonl")).unwrap();
        assert!(links.contains("\"child_session_id\":\"child-session-id\""));
        assert!(links.contains("\"parent_session_id\":null"));
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
