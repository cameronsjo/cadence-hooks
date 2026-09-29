//! CLI actions: `session declare`, `session status`, and `session plans`.
//!
//! These are user/skill-facing commands, not hooks — they read no stdin
//! payload and are exempt from hooks.json wiring (like
//! `guardrails dismiss-main-branch-warn`). A coordination convenience must not
//! fail a script that calls it, so each succeeds on every answer it can give —
//! including "no sessions registered" and "no plans in flight", which are real
//! answers.
//!
//! Exit codes, one per command:
//!
//! - `session declare` — always **0**. A fire-and-forget write whose failure a
//!   caller has nothing to do about; it reports the problem on stdout.
//! - `session status` — **0** for any answer it can give, **1** outside a git
//!   repository, with the message on stderr. There is no registry to read
//!   there, so the question could not be asked at all, and a parser needs to
//!   tell that apart from an empty registry.
//! - `session plans` — **0** for any answer it can give, **2** outside a git
//!   repository, with the scanned root on stderr. Same distinction as
//!   `status`, a different code, so a caller running both can tell which one
//!   could not answer.

use crate::identity;
use crate::registry;

/// Priority order for resolving a session id: explicit flag, then
/// `CLAUDE_SESSION_ID`, then `CLAUDE_CODE_SESSION_ID` (#366: a shell Claude
/// Code spawns via its Bash tool does not carry `CLAUDE_SESSION_ID`, but does
/// carry `CLAUDE_CODE_SESSION_ID` — without this fallback, `session declare`
/// run from the Bash tool can't self-identify at all). Pure — env values
/// passed as arguments, never read from `std::env` here, so the ordering is
/// fixture-testable without mutating process-global env (mirrors
/// `redact_external_content::resolve_dest_tier`'s seam).
///
/// Each candidate is validated BEFORE selection, not after: an `.or().or()`
/// chain followed by a single trailing `.filter()` would pick the first
/// *present* candidate regardless of safety, then reject the whole result if
/// that one candidate is unsafe — never falling through to a later, safe
/// candidate. `find` validates in priority order instead, so an unsafe
/// `CLAUDE_SESSION_ID` correctly falls through to a safe
/// `CLAUDE_CODE_SESSION_ID` rather than failing the whole resolution.
fn resolve_session_id_from(
    flag: Option<String>,
    claude_session_id: Option<String>,
    claude_code_session_id: Option<String>,
) -> Option<String> {
    [flag, claude_session_id, claude_code_session_id]
        .into_iter()
        .flatten()
        .find(|s| identity::is_safe_session_id(s))
}

/// Resolve this session's id from the real environment. See
/// [`resolve_session_id_from`] for the priority order and rationale.
fn resolve_session_id(flag: Option<String>) -> Option<String> {
    resolve_session_id_from(
        flag,
        std::env::var("CLAUDE_SESSION_ID").ok(),
        std::env::var("CLAUDE_CODE_SESSION_ID").ok(),
    )
}

/// Apply a declaration to a record. Pure — fully testable.
///
/// Omitted fields are preserved; provided-but-blank values are explicit
/// clears:
/// - `intent: None` → preserve; `Some("  ")` → clear; `Some(text)` → set
///   (trimmed)
/// - `touching` empty (flag never passed) → preserve; entries that normalize
///   to nothing (all blank) → clear; otherwise → set (trimmed, blanks
///   dropped)
fn apply_declaration(
    record: &mut identity::SessionRecord,
    intent: Option<String>,
    touching: Vec<String>,
) {
    match intent {
        Some(s) if s.trim().is_empty() => record.intent = None,
        Some(s) => record.intent = Some(s.trim().to_string()),
        None => {}
    }
    if !touching.is_empty() {
        record.touching = touching
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
}

/// `session declare --intent <...> --touching <...>` — update this session's
/// lane declaration so peers can assess collision risk.
pub fn run_declare(intent: Option<String>, touching: Vec<String>, session_id: Option<String>) {
    let Some(sid) = resolve_session_id(session_id) else {
        println!(
            "session declare: no session id. Pass --session-id or run inside Claude Code \
             (CLAUDE_SESSION_ID or CLAUDE_CODE_SESSION_ID)."
        );
        return;
    };
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(dir) = registry::sessions_dir(&cwd) else {
        println!("session declare: not inside a git repository — no registry to declare in.");
        return;
    };

    // Upsert: keep existing fields, apply the declaration.
    let mut record = registry::read_own(&dir, &sid).unwrap_or_else(|| identity::SessionRecord {
        name: identity::short_id(&sid).to_string(),
        session_id: sid.clone(),
        started: identity::utc_timestamp(),
        started_epoch: identity::now_epoch(),
        ..Default::default()
    });
    apply_declaration(&mut record, intent, touching);
    // `declare` can CREATE a record from scratch (the `unwrap_or_else` above),
    // so a session that registers only this way — SessionStart unwired, or an
    // id passed in from a Bash tool — would be live locally and invisible to
    // the cross-checkout mirror, which is precisely the state that lets a prune
    // delete dirs it is pinned to. Best-effort, after the local write's result
    // is what the caller sees (cadence-hooks#634).
    record.repo = registry::repo_root_of_registry(&dir)
        .map(|p| p.to_string_lossy().into_owned())
        .or(record.repo);
    let local = registry::write_record(&dir, &record);
    let _ = registry::write_record(&registry::global_sessions_dir(), &record);
    match local {
        Ok(()) => {
            // The record may have been seeded by another process — sanitize
            // everything echoed back, same discipline as the hook paths.
            let lanes: Vec<String> = record
                .touching
                .iter()
                .take(identity::MAX_LANES)
                .map(|t| identity::sanitize_field(t, identity::MAX_FIELD_DISPLAY))
                .collect();
            println!(
                "Declared: {} working on {}{}",
                identity::sanitize_field(identity::short_id(&record.session_id), 8),
                record
                    .intent
                    .as_deref()
                    .map(|i| identity::sanitize_field(i, identity::MAX_FIELD_DISPLAY))
                    .unwrap_or_else(|| "(no intent)".to_string()),
                if lanes.is_empty() {
                    String::new()
                } else {
                    format!(", touching {}", lanes.join(", "))
                }
            );
        }
        Err(e) => println!("session declare: could not write registry: {e}"),
    }
}

/// Render one `session status` row for `peer`, marking it ` (you)` when its
/// record is the caller's. Pure — the whole display contract in one testable
/// function.
///
/// The short id leads the row and is SANITIZED: `session_id` is peer-written
/// JSON and [`identity::short_id`] truncates without filtering, so 8 bytes is
/// room for a `\r` plus forged text on a terminal line a human acts on.
/// Ownership is decided on the FULL id — a peer sharing this session's 8-char
/// prefix must not wear the ` (you)` marker.
fn status_row(peer: &registry::Peer, own_session_id: Option<&str>) -> String {
    let r = &peer.record;
    let mine = own_session_id.is_some_and(|own| own == r.session_id);
    let mut out = format!(
        "  {:<10} branch={:<30} active {}{}{}",
        identity::sanitize_field(identity::short_id(&r.session_id), 8),
        r.branch
            .as_deref()
            .map(|b| identity::sanitize_field(b, identity::MAX_FIELD_DISPLAY))
            .unwrap_or_else(|| "-".to_string()),
        identity::relative_age(peer.idle_secs),
        if peer.stale { "  [STALE]" } else { "" },
        if mine { "  (you)" } else { "" }
    );
    if let Some(intent) = &r.intent {
        out.push_str(&format!(
            "\n  {:<10} intent: {}",
            "",
            identity::sanitize_field(intent, identity::MAX_FIELD_DISPLAY)
        ));
    }
    if !r.touching.is_empty() {
        let lanes: Vec<String> = r
            .touching
            .iter()
            .take(identity::MAX_LANES)
            .map(|t| identity::sanitize_field(t, identity::MAX_FIELD_DISPLAY))
            .collect();
        out.push_str(&format!("\n  {:<10} touching: {}", "", lanes.join(", ")));
    }
    out
}

/// Every per-checkout registry belonging to the repository `cwd` is in: the
/// checkout `cwd` resolves to FIRST, then each other worktree `git worktree
/// list` names, in its order (cameronsjo/cadence-hooks#845).
///
/// A worktree has its own `.claude/sessions`, so reading only the cwd's one
/// shows a branch-mode repo exactly the sessions that are, by policy, not doing
/// the work. The second field is `false` when the worktree list could not be
/// read: the caller must then say it scanned only this checkout, never let a
/// short list pass for a complete one. Bare entries have no checkout and are
/// skipped; duplicates (the same directory reached by two spellings) collapse
/// on the canonical path.
fn repo_registries(cwd: &str, own_dir: std::path::PathBuf) -> (Vec<std::path::PathBuf>, bool) {
    use cadence_hooks_core::shell::{GitOutput, git_output_detailed};
    let key = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own_root = registry::repo_root_of_registry(&own_dir);
    let mut dirs = vec![own_dir];
    let mut seen: Vec<std::path::PathBuf> = own_root.iter().map(|r| key(r)).collect();
    let porcelain = match git_output_detailed(cwd, &["worktree", "list", "--porcelain", "-z"]) {
        GitOutput::Ok(text) => text,
        _ => return (dirs, false),
    };
    for entry in crate::unpushed_worktrees::parse_worktree_list(&porcelain) {
        if entry.bare || entry.path.is_empty() {
            continue;
        }
        let root = std::path::PathBuf::from(&entry.path);
        let k = key(&root);
        if seen.contains(&k) {
            continue;
        }
        seen.push(k);
        dirs.push(root.join(".claude").join("sessions"));
    }
    (dirs, true)
}

/// Pure: the stdout text `session status` prints for already-read registries.
///
/// `sections` is every registry scanned, the caller's own checkout first. Only
/// registries holding a record get a heading — ten empty worktree registries
/// would bury the one that matters — but the footer counts every one scanned,
/// so an empty or short list reads as "none in these N registries" rather than
/// "none anywhere" (cameronsjo/cadence-hooks#845). `worktrees_listed` false
/// means sibling worktrees could not be enumerated, and the footer says so.
fn status_text(
    sections: &[(std::path::PathBuf, Vec<registry::Peer>)],
    own_session_id: Option<&str>,
    worktrees_listed: bool,
) -> String {
    let mut out = String::new();
    for (dir, peers) in sections.iter().filter(|(_, p)| !p.is_empty()) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("Sessions in {}:\n\n", dir.display()));
        for peer in peers {
            out.push_str(&status_row(peer, own_session_id));
            out.push('\n');
        }
    }
    let own_dir = sections
        .first()
        .map(|(d, _)| d.display().to_string())
        .unwrap_or_default();
    if out.is_empty() {
        out.push_str(&format!("No sessions registered in {own_dir}\n"));
    } else {
        out.push('\n');
    }
    let siblings = sections.len().saturating_sub(1);
    if worktrees_listed {
        out.push_str(&format!(
            "Scanned {} registr{}: this checkout and {siblings} sibling worktree{}.",
            sections.len(),
            if sections.len() == 1 { "y" } else { "ies" },
            if siblings == 1 { "" } else { "s" },
        ));
    } else {
        out.push_str(&format!(
            "Scanned only this checkout's registry ({own_dir}): the worktree list could not be read, so sessions in sibling worktrees are not shown."
        ));
    }
    out
}

/// `session status` — list live and stale sessions in every registry of this
/// repository: the checkout you are in and each of its worktrees (#845).
/// Returns the process exit code.
///
/// Exit 1 with the message on STDERR when there is no registry to read (not a
/// git repository): a caller that pipes this into a parser needs to tell "no
/// sessions" from "the question could not be asked". An empty registry is a
/// real answer and stays on stdout at exit 0.
pub fn run_status() -> u8 {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(dir) = registry::sessions_dir(&cwd) else {
        eprintln!("session status: not inside a git repository.");
        return 1;
    };
    let stale_secs = registry::stale_minutes() * 60;
    let (dirs, worktrees_listed) = repo_registries(&cwd, dir);
    // Pass an id no real session can have so every entry is listed.
    let sections: Vec<_> = dirs
        .into_iter()
        .map(|d| {
            let peers = registry::read_peers(&d, "", stale_secs);
            (d, peers)
        })
        .collect();
    let own = resolve_session_id(None);
    println!(
        "{}",
        status_text(&sections, own.as_deref(), worktrees_listed)
    );
    0
}

/// Pure: the stdout text `session plans` prints for an already-resolved repo
/// root. The empty answer names the directory it scanned — without that,
/// "nothing in flight" is indistinguishable from "you are in the wrong repo".
/// A scan that hit problems and found nothing prints nothing: "no in-flight
/// plans" would be a claim the scan cannot back.
fn plans_text(repo_root: &std::path::Path, scan: &crate::plan_scan::PlansReport) -> String {
    match &scan.report {
        Some(report) => report.clone(),
        None if scan.problems.is_empty() => format!(
            "no in-flight plans under {}",
            repo_root.join("docs").join("plans").display()
        ),
        None => String::new(),
    }
}

/// Pure: the stderr text for a partial scan, or `None` when it was complete.
fn plans_problems_text(
    repo_root: &std::path::Path,
    scan: &crate::plan_scan::PlansReport,
) -> Option<String> {
    if scan.problems.is_empty() {
        return None;
    }
    let mut out = format!(
        "session plans: the scan of {} was incomplete; plans in these entries are missing from the list:",
        repo_root.join("docs").join("plans").display()
    );
    for problem in &scan.problems {
        out.push_str("\n  ");
        out.push_str(problem);
    }
    Some(out)
}

/// `session plans` — the tier-2 view of the SessionStart plan pointer: every
/// in-flight and blocked plan in this repo, with its next step, branch, and PR.
/// Returns the process exit code.
///
/// Read-only, and a plain print rather than a dispatched check: it reads no
/// stdin payload, writes no metrics, and has no outcome for the hook contract
/// to carry. Zero plans is a real answer and exits 0. Exit **2** when the scan
/// could not be run at all (no git repository here), or when it could not
/// list, stat or read an entry in `docs/plans/` (cameronsjo/cadence-hooks#968),
/// with the scanned root and each failed entry on stderr — a parser needs to
/// tell an empty or complete list from a question never fully asked. Whatever
/// the partial scan did find still prints on stdout.
pub fn run_plans() -> u8 {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let Some(root) = registry::repo_root(&cwd) else {
        eprintln!("session plans: not inside a git repository. Scanned root: {cwd}");
        return 2;
    };
    let scan = crate::plan_scan::plans_report(&root);
    let text = plans_text(&root, &scan);
    if !text.is_empty() {
        println!("{text}");
    }
    if let Some(problems) = plans_problems_text(&root, &scan) {
        eprintln!("{problems}");
        return 2;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- session plans: the tier-2 view of the SessionStart plan pointer ---

    fn write_plan(root: &std::path::Path, name: &str, body: &str) {
        let dir = root.join("docs").join("plans");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn plans_text_lists_each_plan() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_plan(
            tmp.path(),
            "2026-09-19-a.md",
            "---\nstatus: in-flight\nnext: \"ship it\"\nbranch: feat/x\npr: 12\n---\n\nbody\n",
        );
        let out = plans_text(tmp.path(), &crate::plan_scan::plans_report(tmp.path()));
        assert!(out.starts_with("1 in-flight plan in docs/plans/:"), "{out}");
        assert!(out.contains("2026-09-19-a"), "{out}");
        assert!(out.contains("next: \"ship it\""), "{out}");
        assert!(out.contains("branch: feat/x"), "{out}");
        assert!(out.contains("pr: 12"), "{out}");
    }

    #[test]
    fn plans_text_names_the_scanned_root_when_nothing_is_in_flight() {
        // The empty answer is a real answer, and it has to say *where* it
        // looked — otherwise "no plans" is indistinguishable from "wrong repo".
        let tmp = tempfile::TempDir::new().unwrap();
        let out = plans_text(tmp.path(), &crate::plan_scan::plans_report(tmp.path()));
        assert!(out.starts_with("no in-flight plans under "), "{out}");
        // Built with `join`, not a literal: the separator is `\` on Windows.
        let scanned = std::path::Path::new("docs").join("plans");
        assert!(out.contains(&scanned.display().to_string()), "{out}");
    }

    #[test]
    fn plans_text_skips_finished_plans() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_plan(
            tmp.path(),
            "2026-09-01-done.md",
            "---\nstatus: done\n---\n\nbody\n",
        );
        assert!(
            plans_text(tmp.path(), &crate::plan_scan::plans_report(tmp.path()))
                .starts_with("no in-flight plans under ")
        );
    }

    #[test]
    fn a_partial_scan_names_the_root_and_each_entry_on_stderr() {
        let tmp = tempfile::TempDir::new().unwrap();
        let scan = crate::plan_scan::PlansReport {
            report: None,
            problems: vec!["docs/plans/x.md: denied".into()],
        };
        // Nothing found plus problems: no "no in-flight plans" claim.
        assert_eq!(plans_text(tmp.path(), &scan), "");
        let err = plans_problems_text(tmp.path(), &scan).expect("problems reported");
        let scanned = tmp.path().join("docs").join("plans");
        assert!(err.contains(&scanned.display().to_string()), "{err}");
        assert!(err.contains("docs/plans/x.md: denied"), "{err}");

        let clean = crate::plan_scan::PlansReport::default();
        assert!(plans_problems_text(tmp.path(), &clean).is_none());
    }

    #[test]
    fn resolve_session_id_prefers_flag() {
        let resolved = resolve_session_id(Some("from-flag".into()));
        assert_eq!(resolved.as_deref(), Some("from-flag"));
    }

    #[test]
    fn resolve_session_id_from_rejects_unsafe_flag_with_no_fallback() {
        // Via the pure seam with explicit None env args, not the real
        // resolve_session_id(Some("../escape".into())): with the #366 fix,
        // an unsafe flag now correctly falls through to a real
        // CLAUDE_CODE_SESSION_ID when this test process actually has one set
        // (true whenever this suite runs inside a live Claude Code session),
        // so asserting None through the impure entry point would be
        // environment-dependent rather than a property of the resolver.
        assert!(resolve_session_id_from(Some("../escape".into()), None, None).is_none());
    }

    // --- #366: CLAUDE_CODE_SESSION_ID fallback, via the pure seam ---

    #[test]
    fn resolve_session_id_from_prefers_flag_over_both_env_vars() {
        let resolved = resolve_session_id_from(
            Some("from-flag".into()),
            Some("from-claude-session-id".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-flag"));
    }

    #[test]
    fn resolve_session_id_from_prefers_claude_session_id_over_claude_code_session_id() {
        let resolved = resolve_session_id_from(
            None,
            Some("from-claude-session-id".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-session-id"));
    }

    #[test]
    fn resolve_session_id_from_falls_back_to_claude_code_session_id() {
        // The reported bug: a Bash-tool-spawned subshell has no
        // CLAUDE_SESSION_ID, only CLAUDE_CODE_SESSION_ID — declare must
        // still self-identify from it.
        let resolved =
            resolve_session_id_from(None, None, Some("from-claude-code-session-id".into()));
        assert_eq!(resolved.as_deref(), Some("from-claude-code-session-id"));
    }

    #[test]
    fn resolve_session_id_from_none_when_all_absent() {
        assert!(resolve_session_id_from(None, None, None).is_none());
    }

    #[test]
    fn resolve_session_id_from_rejects_unsafe_claude_code_session_id() {
        assert!(resolve_session_id_from(None, None, Some("../escape".into())).is_none());
    }

    #[test]
    fn resolve_session_id_from_unsafe_claude_session_id_falls_through_to_safe_claude_code_session_id()
     {
        // The critical case: an unsafe higher-priority candidate must not
        // fail the whole resolution when a safe lower-priority one exists —
        // each candidate is validated before selection, not after.
        let resolved = resolve_session_id_from(
            None,
            Some("../escape".into()),
            Some("from-claude-code-session-id".into()),
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-code-session-id"));
    }

    #[test]
    fn resolve_session_id_from_unsafe_flag_falls_through_to_safe_claude_session_id() {
        let resolved = resolve_session_id_from(
            Some("../escape".into()),
            Some("from-claude-session-id".into()),
            None,
        );
        assert_eq!(resolved.as_deref(), Some("from-claude-session-id"));
    }

    // --- status rows ---

    fn status_peer(session_id: &str, branch: Option<&str>) -> registry::Peer {
        registry::Peer {
            record: identity::SessionRecord {
                name: identity::short_id(session_id).into(),
                session_id: session_id.into(),
                branch: branch.map(str::to_string),
                ..Default::default()
            },
            idle_secs: 120,
            age_secs: 2400,
            stale: false,
        }
    }

    // --- status across worktrees (#845) ---

    #[test]
    fn status_text_lists_a_sibling_worktree_session_and_counts_every_registry() {
        let sections = vec![
            (
                PathBuf::from("/repo/.claude/sessions"),
                vec![status_peer("aaaaaaaa-1", Some("main"))],
            ),
            (PathBuf::from("/repo/wt/a/.claude/sessions"), vec![]),
            (
                PathBuf::from("/repo/wt/b/.claude/sessions"),
                vec![status_peer("bbbbbbbb-2", Some("feat/b"))],
            ),
        ];
        let text = status_text(&sections, None, true);
        assert!(
            text.contains("Sessions in /repo/.claude/sessions:"),
            "{text}"
        );
        assert!(
            text.contains("Sessions in /repo/wt/b/.claude/sessions:"),
            "{text}"
        );
        assert!(
            text.contains("bbbbbbbb"),
            "the worktree session must be listed: {text}"
        );
        assert!(
            !text.contains("/repo/wt/a/"),
            "an empty registry gets no heading: {text}"
        );
        assert!(
            text.contains("Scanned 3 registries: this checkout and 2 sibling worktrees."),
            "{text}"
        );
    }

    #[test]
    fn status_text_names_what_it_did_not_scan_when_the_worktree_list_failed() {
        let sections = vec![(PathBuf::from("/repo/.claude/sessions"), vec![])];
        let text = status_text(&sections, None, false);
        assert!(
            text.starts_with("No sessions registered in /repo/.claude/sessions"),
            "{text}"
        );
        assert!(
            text.contains("Scanned only this checkout's registry"),
            "{text}"
        );
        assert!(text.contains("sibling worktrees are not shown"), "{text}");
    }

    #[test]
    fn status_text_empty_everywhere_still_says_how_many_registries_it_read() {
        let sections = vec![
            (PathBuf::from("/repo/.claude/sessions"), vec![]),
            (PathBuf::from("/repo/wt/a/.claude/sessions"), vec![]),
        ];
        let text = status_text(&sections, None, true);
        assert!(
            text.starts_with("No sessions registered in /repo/.claude/sessions"),
            "{text}"
        );
        assert!(
            text.contains("Scanned 2 registries: this checkout and 1 sibling worktree."),
            "{text}"
        );
    }

    fn registries_scratch_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/status-registries-scratch")
    }

    fn canon(p: &std::path::Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }

    /// The #845 shape end to end: a primary checkout and a linked worktree, each
    /// with its own registry. From EITHER side, both registries are scanned,
    /// the caller's own first, and no directory appears twice.
    #[test]
    fn repo_registries_unions_the_primary_checkout_and_every_worktree() {
        use cadence_hooks_core::git_fixtures::{Scratch, git_in, init_repo};
        let scratch = Scratch::new(&registries_scratch_root(), "union");
        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo);
        let wt = scratch.path().join("wt-a");
        git_in(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "feat/a",
                &wt.to_string_lossy(),
                "main",
            ],
        );

        let from_primary = repo.to_string_lossy().to_string();
        let own = registry::sessions_dir(&from_primary).unwrap();
        let (dirs, listed) = repo_registries(&from_primary, own);
        assert!(listed);
        let got: Vec<PathBuf> = dirs
            .iter()
            .map(|d| canon(d.parent().unwrap().parent().unwrap()))
            .collect();
        assert_eq!(got, vec![canon(&repo), canon(&wt)]);

        let from_wt = wt.to_string_lossy().to_string();
        let own = registry::sessions_dir(&from_wt).unwrap();
        let (dirs, listed) = repo_registries(&from_wt, own);
        assert!(listed);
        let got: Vec<PathBuf> = dirs
            .iter()
            .map(|d| canon(d.parent().unwrap().parent().unwrap()))
            .collect();
        assert_eq!(
            got,
            vec![canon(&wt), canon(&repo)],
            "own checkout first, sibling next"
        );
    }

    #[test]
    fn repo_registries_reports_an_unlisted_scan_outside_a_repo() {
        let dir = std::env::temp_dir();
        let own = PathBuf::from("/nowhere/.claude/sessions");
        // `git worktree list` fails outside a repository: only the own dir, flagged.
        let (dirs, listed) = repo_registries(
            &dir.join("definitely-not-a-dir-845").to_string_lossy(),
            own.clone(),
        );
        assert_eq!(dirs, vec![own]);
        assert!(!listed);
    }

    #[test]
    fn status_row_leads_with_the_short_id_and_no_name_column() {
        let row = status_row(&status_peer("e4739a12-1111", Some("feat/x")), None);
        assert!(row.trim_start().starts_with("e4739a12"), "{row}");
        assert!(row.contains("branch=feat/x"), "{row}");
        assert!(!row.contains("(you)"), "another session is not you: {row}");
    }

    #[test]
    fn status_row_marks_the_callers_own_row() {
        let peer = status_peer("e4739a12-1111", None);
        assert!(
            status_row(&peer, Some("e4739a12-1111")).contains("(you)"),
            "the caller's own row is marked"
        );
        // #90: a peer sharing the 8-char prefix is a DIFFERENT session.
        assert!(
            !status_row(&peer, Some("e4739a12-2222")).contains("(you)"),
            "ownership is the full id, never the short one"
        );
    }

    #[test]
    fn status_row_renders_no_control_byte_from_a_crafted_session_id() {
        // A hand-planted registry file chooses `session_id` freely, and
        // `short_id` truncates without filtering — 8 bytes is room for a \r
        // plus forged text on a line a human reads and acts on.
        for hostile in ["\rSAFE: 0 live sessions", "\u{1b}[2K0 live sessions"] {
            let row = status_row(&status_peer(hostile, None), None);
            assert!(
                !row.contains('\r') && !row.contains('\u{1b}'),
                "no control byte survives: {row:?}"
            );
        }
    }

    // --- declaration semantics ---

    fn declared_record() -> identity::SessionRecord {
        identity::SessionRecord {
            name: "quiet-loom".into(),
            session_id: "s1".into(),
            intent: Some("cadence-hooks#52".into()),
            touching: vec!["crates/guardrails/".into()],
            ..Default::default()
        }
    }

    #[test]
    fn omitted_fields_are_preserved() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, None, Vec::new());
        assert_eq!(rec.intent.as_deref(), Some("cadence-hooks#52"));
        assert_eq!(rec.touching, vec!["crates/guardrails/"]);
    }

    #[test]
    fn provided_fields_are_set_and_trimmed() {
        let mut rec = declared_record();
        apply_declaration(
            &mut rec,
            Some("  cadence-hooks#54  ".into()),
            vec!["  crates/session/  ".into()],
        );
        assert_eq!(rec.intent.as_deref(), Some("cadence-hooks#54"));
        assert_eq!(rec.touching, vec!["crates/session/"]);
    }

    #[test]
    fn blank_intent_is_explicit_clear() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, Some("   ".into()), Vec::new());
        assert!(rec.intent.is_none(), "blank intent clears");
        assert!(!rec.touching.is_empty(), "touching untouched");
    }

    #[test]
    fn all_blank_touching_is_explicit_clear() {
        let mut rec = declared_record();
        apply_declaration(&mut rec, None, vec!["  ".into(), "".into()]);
        assert!(rec.touching.is_empty(), "all-blank list clears lanes");
        assert!(rec.intent.is_some(), "intent untouched");
    }

    #[test]
    fn blank_touching_entries_are_dropped() {
        let mut rec = declared_record();
        apply_declaration(
            &mut rec,
            None,
            vec!["crates/session/".into(), "   ".into(), "src/".into()],
        );
        assert_eq!(rec.touching, vec!["crates/session/", "src/"]);
    }

    // Note: the run_declare/run_status I/O paths are exercised end-to-end by
    // the plugin smoke test; here they'd require mutating process-global
    // state (env, cwd) which races parallel tests. The env-var fallback
    // priority itself is covered above via the pure resolve_session_id_from
    // seam, which needs no env mutation.
}
