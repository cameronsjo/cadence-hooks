//! `docs/plans/*.md` frontmatter scan for the `session start` disclosure
//! (cadence-hooks#429, the living-plan lifecycle plan's Task 2).
//!
//! A resuming session (an auth-swap restart, `/clear`, a fresh checkout) has
//! no memory of what was in flight. The plan corpus already carries that
//! state in frontmatter (persisted by [`crate::persist_plan`]) — this module
//! reads it back at `SessionStart` so the disclosure names the plan, its
//! `next:` step, and where the work lives, without a single GitHub call.
//!
//! Reuses [`crate::persist_plan::leading_frontmatter_block`] — the same
//! bounded first-fence scan `persist_plan` uses for idempotency — rather than
//! a new YAML dependency or a second scan implementation. No key outside
//! `status`/`next`/`branch`/`pr` is read; `card` and `blocked` (reason text)
//! are reserved by Design 2 but have no consumer yet.
//!
//! **Opt-out by absence (Design 3), not retrofit support**: a file with no
//! frontmatter, or frontmatter without a `status:` key — every plan predating
//! cadence-hooks#396, and the 2026-07-24 retrofit batch that only added
//! `date`/`session`/`session_id`/`model`/... — is silently skipped. This
//! module never bulk-adopts those documents; a plan gains a `status:` key
//! only when [`crate::persist_plan`] or a hand-edit puts one there.
//!
//! Fails open throughout (ADR-0001): an unreadable directory, an unreadable
//! file, or a malformed frontmatter block is skipped, never surfaced as an
//! error — a bug here must not break `session start`.

use std::fs;
use std::path::{Path, PathBuf};

/// Cap on bytes read from each candidate before frontmatter parsing. Real
/// frontmatter is bounded to `persist_plan::FRONTMATTER_SCAN_MAX_LINES` (100)
/// lines; 64 KiB is generous headroom even for very long `next:` lines,
/// while keeping a large plan body (checklists, `## Deviations`/`## Learnings`
/// prose) from being pulled fully into memory for every file in a large
/// `docs/plans/` directory — the "bound total work" requirement for a
/// 250-file directory.
const PLAN_SCAN_READ_CAP_BYTES: u64 = 64 * 1024;

/// Cap on the rendered `next:` clause. Truncated on a char boundary with an
/// ellipsis, never mid-codepoint.
const NEXT_TRUNCATE_MAX_CHARS: usize = 100;

/// The frontmatter facts this scanner cares about — a strict subset of
/// Design 2's schema. `status` is required to reach this struct at all (see
/// [`parse_frontmatter_facts`]); the rest are `None` when absent or reduced
/// to a placeholder (`—`, `-`, empty).
#[derive(Debug, PartialEq, Eq)]
struct PlanFacts {
    status: String,
    next: Option<String>,
    branch: Option<String>,
    pr: Option<String>,
}

/// Scan `<repo_root>/docs/plans/*.md` and render a disclosure block for every
/// plan whose `status:` is `in-flight` or `blocked`. `None` when the
/// directory doesn't exist, is unreadable, or no plan matches — the "zero
/// matching plans = silence" contract at `session start`.
pub fn scan_in_flight_plans(repo_root: &Path) -> Option<String> {
    let plans_dir = repo_root.join("docs").join("plans");
    let mut paths = list_markdown_files(&plans_dir)?;
    paths.sort();

    let lines: Vec<String> = paths
        .iter()
        .filter_map(|path| {
            let slug = path.file_stem()?.to_str()?;
            let content = read_capped(path)?;
            let facts = parse_frontmatter_facts(&content)?;
            matches_in_flight_or_blocked(&facts.status).then(|| render_plan_line(slug, &facts))
        })
        .collect();

    if lines.is_empty() {
        return None;
    }
    Some(render_block(&lines))
}

/// `.md` files directly inside `dir`, unsorted. `None` when `dir` doesn't
/// exist or can't be listed — fails open rather than surfacing an I/O error.
fn list_markdown_files(dir: &Path) -> Option<Vec<PathBuf>> {
    let entries = fs::read_dir(dir).ok()?;
    Some(
        entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
            .collect(),
    )
}

/// Read at most [`PLAN_SCAN_READ_CAP_BYTES`] of `path`. `None` on any I/O or
/// UTF-8 error (a torn read at the byte cap included) — fails open, skipping
/// the file rather than aborting the scan.
fn read_capped(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let file = fs::File::open(path).ok()?;
    let mut content = String::new();
    file.take(PLAN_SCAN_READ_CAP_BYTES)
        .read_to_string(&mut content)
        .ok()?;
    Some(content)
}

/// Parse the four tracked keys from `content`'s leading frontmatter block.
/// `None` for every skip case (Design 3's opt-out): no leading frontmatter at
/// all, or frontmatter present but carrying no `status:` key. Never reads
/// `content` past the bounded frontmatter block
/// [`crate::persist_plan::leading_frontmatter_block`] already returns.
fn parse_frontmatter_facts(content: &str) -> Option<PlanFacts> {
    let block = crate::persist_plan::leading_frontmatter_block(content)?;
    let status = unquote(frontmatter_value(block, "status")?);
    let next = frontmatter_value(block, "next")
        .map(unquote)
        .filter(|s| !s.is_empty());
    let branch = frontmatter_value(block, "branch")
        .map(unquote)
        .filter(|s| is_present(s));
    let pr = frontmatter_value(block, "pr")
        .map(unquote)
        .filter(|s| is_present(s));
    Some(PlanFacts {
        status,
        next,
        branch,
        pr,
    })
}

/// The trimmed, still-quoted value of the first line in `block` starting
/// with `<key>:`, or `None` when the key is absent. A top-level scalar key
/// appears at most once in real frontmatter, so first-match is unambiguous.
fn frontmatter_value<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    block
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(prefix.as_str()))
        .map(str::trim)
}

/// Strip one layer of matching double or single quotes from a frontmatter
/// scalar (`"a value"` / `'a value'` → `a value`). Values that aren't quoted
/// pass through unchanged — this is a plain scalar unquote, not a YAML
/// escape decoder (no key this scanner reads embeds an escaped quote).
fn unquote(value: &str) -> String {
    let v = value.trim();
    let mut chars = v.chars();
    match (chars.next(), chars.next_back()) {
        (Some('"'), Some('"')) | (Some('\''), Some('\'')) if v.len() >= 2 => {
            chars.as_str().to_string()
        }
        _ => v.to_string(),
    }
}

/// True unless `value` is empty or the plan template's "not yet set"
/// placeholder (`—` em dash, or a bare `-`) — the shape `branch:`/`pr:` carry
/// before a branch exists or a PR opens (see the plan doc's own
/// `pr: —` frontmatter).
fn is_present(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && v != "—" && v != "-"
}

/// The two statuses this disclosure surfaces. `planned`, `done`, `abandoned`,
/// and any unrecognized value are silently excluded — a coarse guard read as
/// live literal comparison, no enum parse, matching Design 2's decision to
/// keep the schema a superset of free text rather than a strict enum.
fn matches_in_flight_or_blocked(status: &str) -> bool {
    status == "in-flight" || status == "blocked"
}

/// Truncate `next` to [`NEXT_TRUNCATE_MAX_CHARS`] chars (char-boundary safe),
/// appending an ellipsis when truncated.
fn truncate_next(next: &str) -> String {
    let mut chars = next.chars();
    let head: String = chars.by_ref().take(NEXT_TRUNCATE_MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// Render one plan's disclosure line: the slug, the (truncated) `next:`
/// clause when present, a `(branch: ..., pr: ...)` parenthetical for whatever
/// of the two is present, and a `[blocked]` marker — status is surfaced only
/// for `blocked`; `in-flight` is the assumed default carried by the block
/// header, per the spec's "status when blocked" rule.
fn render_plan_line(slug: &str, facts: &PlanFacts) -> String {
    let mut line = format!("- {slug}");
    if let Some(next) = &facts.next {
        line.push_str(&format!(" — next: \"{}\"", truncate_next(next)));
    }
    let mut paren = Vec::new();
    if let Some(branch) = &facts.branch {
        paren.push(format!("branch: {branch}"));
    }
    if let Some(pr) = &facts.pr {
        paren.push(format!("pr: {pr}"));
    }
    if !paren.is_empty() {
        line.push_str(&format!(" ({})", paren.join(", ")));
    }
    if facts.status == "blocked" {
        line.push_str(" [blocked]");
    }
    line
}

/// Assemble the full disclosure block: a count header, one bullet per plan,
/// then the reconcile nudge (Design 7 / Design 11 — the plan file is an
/// index, never trusted blind).
fn render_block(lines: &[String]) -> String {
    let n = lines.len();
    let header = format!(
        "{n} in-flight plan{} in docs/plans/:",
        if n == 1 { "" } else { "s" }
    );
    format!(
        "{header}\n{}\nThe plan file is an index — verify it against the branch log before \
         trusting it.",
        lines.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn plans_dir(tmp: &TempDir) -> PathBuf {
        let dir = tmp.path().join("docs").join("plans");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_plan(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).unwrap();
    }

    // --- parse_frontmatter_facts: the opt-out proof (Design 3) ---
    //
    // These name the skip explicitly — a panel reviewer previously misread an
    // earlier fixture shaped like this as retrofit *support*. It proves the
    // opposite: legacy and retrofit files carry no `status:` key and are
    // therefore invisible to this scanner, by design.

    #[test]
    fn legacy_plain_trailer_file_has_no_frontmatter_and_is_skipped() {
        // Pre-cadence-hooks#396 shape: no leading `---` at all, just a body
        // (possibly with an old `Plan-body-SHA256:` trailer further down).
        let doc = "# Fix the widget\n\nSome body text.\n\nPlan-body-SHA256: deadbeef\n";
        assert_eq!(parse_frontmatter_facts(doc), None);
    }

    #[test]
    fn retrofit_frontmatter_without_status_key_is_skipped_not_supported() {
        // The 2026-07-24 retrofit batch: frontmatter present, but only the
        // provenance keys (date/session/session_id/model/harness/machine) —
        // no `status:`. This is the exact opt-out-by-absence case (Design 3):
        // the mixed-dir test below asserts this file is SKIPPED, proving the
        // opt-out, not proving retrofit adoption.
        let doc = "---\ndate: 2026-07-24\nsession: quiet-loom\nsession_id: abc123\n\
                   model: claude-sonnet-5\nharness: claude-code 2.1.200\nmachine: deadbeef\n---\n\n\
                   # Some plan\n\nbody\n";
        assert_eq!(parse_frontmatter_facts(doc), None);
    }

    #[test]
    fn no_leading_frontmatter_at_all_is_skipped() {
        assert_eq!(parse_frontmatter_facts("# Title\n\nbody\n"), None);
    }

    #[test]
    fn malformed_frontmatter_no_closing_fence_fails_open() {
        // Opens with `---` but never closes within the scan window — the
        // shared `leading_frontmatter_block` returns `None`, so this scanner
        // skips it exactly like "no frontmatter", never panics or blocks.
        let doc = "---\nstatus: in-flight\n\n# no closing fence anywhere in this file\n";
        assert_eq!(parse_frontmatter_facts(doc), None);
    }

    #[test]
    fn unrecognized_status_value_is_parsed_but_excluded_downstream() {
        let doc = "---\nstatus: done\nnext: \"ship it\"\n---\n\nbody\n";
        let facts = parse_frontmatter_facts(doc).expect("frontmatter present, status key present");
        assert_eq!(facts.status, "done");
        assert!(!matches_in_flight_or_blocked(&facts.status));
    }

    #[test]
    fn in_flight_status_parses_all_four_keys() {
        let doc = "---\nstatus: in-flight\nnext: \"Task 2 — ship it\"\nbranch: feat/x\npr: 432\n\
                   updated: 2026-07-25\n---\n\n# Title\n\nbody\n";
        let facts = parse_frontmatter_facts(doc).unwrap();
        assert_eq!(facts.status, "in-flight");
        assert_eq!(facts.next.as_deref(), Some("Task 2 — ship it"));
        assert_eq!(facts.branch.as_deref(), Some("feat/x"));
        assert_eq!(facts.pr.as_deref(), Some("432"));
    }

    #[test]
    fn blocked_status_parses() {
        let doc = "---\nstatus: blocked\nnext: \"waiting on #396\"\n---\n\nbody\n";
        let facts = parse_frontmatter_facts(doc).unwrap();
        assert_eq!(facts.status, "blocked");
    }

    #[test]
    fn placeholder_pr_and_branch_are_treated_as_absent() {
        let doc = "---\nstatus: in-flight\nnext: \"x\"\nbranch: —\npr: —\n---\n\nbody\n";
        let facts = parse_frontmatter_facts(doc).unwrap();
        assert_eq!(
            facts.branch, None,
            "em-dash placeholder is absence, not a value"
        );
        assert_eq!(facts.pr, None);
    }

    #[test]
    fn unquoted_next_value_parses_without_quotes() {
        let doc = "---\nstatus: in-flight\nnext: ship it\n---\n\nbody\n";
        let facts = parse_frontmatter_facts(doc).unwrap();
        assert_eq!(facts.next.as_deref(), Some("ship it"));
    }

    #[test]
    fn a_body_thematic_break_after_the_real_fence_is_never_read_as_a_fence() {
        // The frontmatter block ends at the FIRST closing `---`; a later
        // `---` in the body (a markdown horizontal rule) must never be
        // mistaken for reopening frontmatter, and its surrounding text must
        // never leak into the parsed facts.
        let doc = "---\nstatus: in-flight\nnext: \"real next\"\n---\n\n\
                   # Title\n\nintro\n\n---\n\nstatus: NOT-A-REAL-KEY\nnext: DECOY\n\nmore body\n";
        let facts = parse_frontmatter_facts(doc).unwrap();
        assert_eq!(facts.status, "in-flight");
        assert_eq!(
            facts.next.as_deref(),
            Some("real next"),
            "decoy body text ignored"
        );
    }

    // --- truncate_next ---

    #[test]
    fn truncate_next_leaves_short_text_alone() {
        assert_eq!(truncate_next("short"), "short");
    }

    #[test]
    fn truncate_next_caps_and_appends_ellipsis() {
        let long = "x".repeat(150);
        let truncated = truncate_next(&long);
        assert_eq!(truncated.chars().count(), NEXT_TRUNCATE_MAX_CHARS + 1);
        assert!(truncated.ends_with('…'));
    }

    // --- render_plan_line / render_block: the format IS the interface ---

    #[test]
    fn render_plan_line_full_fields() {
        let facts = PlanFacts {
            status: "in-flight".to_string(),
            next: Some("ship it".to_string()),
            branch: Some("feat/x".to_string()),
            pr: Some("432".to_string()),
        };
        assert_eq!(
            render_plan_line("2026-07-25-my-plan", &facts),
            "- 2026-07-25-my-plan — next: \"ship it\" (branch: feat/x, pr: 432)"
        );
    }

    #[test]
    fn render_plan_line_blocked_gets_marker() {
        let facts = PlanFacts {
            status: "blocked".to_string(),
            next: Some("waiting on #396".to_string()),
            branch: None,
            pr: None,
        };
        assert_eq!(
            render_plan_line("2026-07-25-blocked-plan", &facts),
            "- 2026-07-25-blocked-plan — next: \"waiting on #396\" [blocked]"
        );
    }

    #[test]
    fn render_plan_line_omits_absent_fields() {
        let facts = PlanFacts {
            status: "in-flight".to_string(),
            next: None,
            branch: None,
            pr: None,
        };
        assert_eq!(render_plan_line("bare-plan", &facts), "- bare-plan");
    }

    #[test]
    fn render_block_singular_header() {
        let block = render_block(&["- a".to_string()]);
        assert_eq!(
            block,
            "1 in-flight plan in docs/plans/:\n- a\nThe plan file is an index — verify it \
             against the branch log before trusting it."
        );
    }

    #[test]
    fn render_block_plural_header() {
        let block = render_block(&["- a".to_string(), "- b".to_string()]);
        assert!(block.starts_with("2 in-flight plans in docs/plans/:\n"));
    }

    // --- scan_in_flight_plans: end to end ---

    #[test]
    fn zero_matching_plans_is_silent() {
        let tmp = TempDir::new().unwrap();
        let dir = plans_dir(&tmp);
        write_plan(
            &dir,
            "2026-07-01-done.md",
            "---\nstatus: done\n---\n\nbody\n",
        );
        write_plan(
            &dir,
            "2026-07-02-planned.md",
            "---\nstatus: planned\n---\n\nbody\n",
        );
        assert_eq!(scan_in_flight_plans(tmp.path()), None);
    }

    #[test]
    fn no_docs_plans_directory_is_silent() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(scan_in_flight_plans(tmp.path()), None);
    }

    #[test]
    fn mixed_directory_asserts_legacy_and_retrofit_files_are_skipped() {
        // The opt-out proof, end to end: a legacy no-frontmatter file and a
        // retrofit status-less file sit alongside one real in-flight plan.
        // Only the in-flight plan is emitted — this asserts the SKIP of the
        // other two, not that they're "supported" in some lesser form.
        let tmp = TempDir::new().unwrap();
        let dir = plans_dir(&tmp);
        write_plan(
            &dir,
            "2026-06-01-legacy.md",
            "# Old plan\n\nno frontmatter at all.\n\nPlan-body-SHA256: deadbeef\n",
        );
        write_plan(
            &dir,
            "2026-07-24-retrofit.md",
            "---\ndate: 2026-07-24\nsession: quiet-loom\nsession_id: abc\n---\n\n# Retrofit\n\nbody\n",
        );
        write_plan(
            &dir,
            "2026-07-25-real-plan.md",
            "---\nstatus: in-flight\nnext: \"ship the thing\"\nbranch: feat/x\npr: —\n\
             updated: 2026-07-25\n---\n\n# Real plan\n\nbody\n",
        );
        let block = scan_in_flight_plans(tmp.path()).expect("one in-flight plan");
        assert_eq!(
            block,
            "1 in-flight plan in docs/plans/:\n\
             - 2026-07-25-real-plan — next: \"ship the thing\" (branch: feat/x)\n\
             The plan file is an index — verify it against the branch log before trusting it."
        );
    }

    #[test]
    fn malformed_frontmatter_file_does_not_break_the_scan_of_siblings() {
        let tmp = TempDir::new().unwrap();
        let dir = plans_dir(&tmp);
        write_plan(
            &dir,
            "2026-07-01-malformed.md",
            "---\nstatus: in-flight\nno closing fence\n",
        );
        write_plan(
            &dir,
            "2026-07-02-good.md",
            "---\nstatus: in-flight\nnext: \"fine\"\n---\n\nbody\n",
        );
        let block = scan_in_flight_plans(tmp.path()).unwrap();
        assert!(block.contains("2026-07-02-good"));
        assert!(!block.contains("2026-07-01-malformed"));
    }

    #[test]
    fn multiple_in_flight_and_blocked_plans_both_appear_sorted() {
        let tmp = TempDir::new().unwrap();
        let dir = plans_dir(&tmp);
        write_plan(
            &dir,
            "2026-07-02-second.md",
            "---\nstatus: blocked\nnext: \"waiting\"\n---\n\nbody\n",
        );
        write_plan(
            &dir,
            "2026-07-01-first.md",
            "---\nstatus: in-flight\nnext: \"go\"\n---\n\nbody\n",
        );
        let block = scan_in_flight_plans(tmp.path()).unwrap();
        assert!(block.starts_with("2 in-flight plans in docs/plans/:"));
        let first_pos = block.find("2026-07-01-first").unwrap();
        let second_pos = block.find("2026-07-02-second").unwrap();
        assert!(first_pos < second_pos, "sorted by filename: {block}");
        assert!(block.contains("[blocked]"));
    }
}
