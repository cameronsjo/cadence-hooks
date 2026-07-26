//! Append-only telemetry for the binary's fail-open paths (panic, stdin-parse
//! failure, clap version-skew) to `<metrics_dir>/failopen.jsonl` — this JSONL
//! stream keeps these previously-silent degradations consistent with the
//! existing denial/timing/bypass rail on `<metrics_dir>/`; wiring these
//! streams into a fuller OTLP-based observability stack is a named follow-up,
//! not this change.

use crate::common;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Schema version stamped on every `failopen.jsonl` row. A new stream
/// (cadence#238 convention) — does not share `common`'s existing version
/// constants.
///
/// **v2** (cameronsjo/cadence-hooks#398) added the `error` field. v1 rows stay
/// readable: every reader reaches `error` through `Value::get`, so an absent
/// field yields `None` exactly as an explicit `null` does. No migration.
const FAILOPEN_SCHEMA_VERSION: u32 = 2;

/// Ceiling, in characters, on a recorded `error` string. Long enough for a
/// serde line/column message or a panic payload plus its source location,
/// short enough that a runaway message can't bloat the append-only ledger.
const MAX_ERROR_CHARS: usize = 200;

/// Build the `failopen.jsonl` record. Pure — no I/O.
///
/// `error` is the diagnostic the degradation site already holds — the parser's
/// message, the panic payload — sanitized on the way in so the stored ledger is
/// clean at rest rather than only at display time.
fn build_failopen_record(
    reason: &str,
    namespace: Option<&str>,
    subcommand: Option<&str>,
    binary_version: &str,
    error: Option<&str>,
) -> Value {
    json!({
        "schemaVersion": FAILOPEN_SCHEMA_VERSION,
        "reason": reason,
        "namespace": namespace,
        "subcommand": subcommand,
        "binaryVersion": binary_version,
        "error": error.map(sanitize_error),
        "ts": common::utc_timestamp(),
    })
}

/// Append one fail-open event to `<metrics_dir>/failopen.jsonl`.
///
/// `reason` names the degradation (`"panic"` | `"parse"` | `"version_mismatch"`),
/// `namespace` / `subcommand` are the CLI position that triggered it when known
/// (`None` when the call site can't determine one — e.g. the global panic
/// hook has no `Check`/`Logger` in scope), and `binary_version` is this
/// process's own `CARGO_PKG_VERSION` — plain log metadata distinguishing this
/// row from any session-level version stamp.
///
/// `error` is the diagnostic the call site already holds and used to discard —
/// the serde message, the panic payload and its location, the clap error kind.
/// It is what makes `doctor`'s "inspect failopen.jsonl" guidance answerable
/// (cameronsjo/cadence-hooks#398). Pass `None` where no error text exists (the
/// deadline rows describe a timeout, not a failure with a message). Call sites
/// pass only their own generated text, never the offending stdin — the
/// no-payload privacy posture is unchanged.
///
/// Fully fail-open (ADR-0001): a missing dir it can't create, or a failed open
/// / write, degrades to a no-op — the caller's exit path is untouched.
pub fn log_failopen(
    reason: &str,
    namespace: Option<&str>,
    subcommand: Option<&str>,
    binary_version: &str,
    error: Option<&str>,
) {
    let record = build_failopen_record(reason, namespace, subcommand, binary_version, error);

    let dir = common::metrics_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("failopen.jsonl");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // One `write_all` of the record + newline, so a concurrent append from
        // another session can't interleave a record with its trailing newline.
        let mut line = record.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// Fail-open row counts within a time window, grouped by `reason`.
///
/// `version_mismatch` is pre-filtered (by [`counts_from`]) to rows whose
/// `binaryVersion` equals the caller's `current_version` — see that function's
/// doc for why.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct FailopenCounts {
    pub panic: u64,
    pub parse: u64,
    pub version_mismatch: u64,
    /// Git probes hit the #271 in-process deadline; guards degraded to their
    /// ordinary fail-open arms. Load-correlated, like `parse`.
    pub deadline: u64,
    /// A fail-closed guard arm downgraded its block to allow because its probe
    /// timed out — enforcement was actually bypassed, the sharpest row here.
    pub deadline_block_suppressed: u64,
}

/// How many distinct `namespace subcommand` pairs a recency clause names before
/// it stops. A skew is nearly always one or two invocations repeated; past a
/// handful the line stops being a diagnosis and starts being a dump, and the
/// operator has enough to grep with either way.
const MAX_SUBCOMMANDS: usize = 4;

/// Ceiling, in characters, on each half of a `namespace subcommand` pair.
/// Unlike `error`, these fields are written to the ledger uncapped, and a
/// plugin can invoke this binary with argv-sized tokens — so the read side
/// bounds them before they reach a printed line or a paste-me command.
const MAX_PAIR_HALF_CHARS: usize = 48;

/// Recency + version context for one `reason`'s windowed rows — the fields
/// doctor needs to tell a *fixed* fail-open burst from a *live* one. Counting
/// stays window-wide (a wiring problem is not version-specific, so filtering
/// the count the way `version_mismatch` does would under-report a live issue);
/// this rides alongside the count instead. It names when the reason last fired,
/// on which binary version, and how many of the windowed rows carry the CURRENT
/// binary's version. Zero on the current version is the tell that the feed was
/// already fixed in a shipped release and the burst is just aging out of the
/// 7-day window.
#[derive(Debug, PartialEq, Eq)]
pub struct FailopenRecency {
    /// The most recent windowed row's `ts` for this reason.
    pub last_ts: String,
    /// The `binaryVersion` on that most recent row (`"unknown"` if it was
    /// absent — every row written by this binary stamps one).
    pub last_version: String,
    /// How many of this reason's windowed rows carry `current_version`.
    pub on_current_version: u64,
    /// How many DISTINCT calendar days this reason fired on, within the window.
    /// The shape signal a total cannot carry: at the same count, `1` is a burst
    /// to correlate with a release or config change, and a number approaching
    /// the window length is a sustained feed problem (#404).
    pub distinct_days: u64,
    /// The `error` string on that most recent row, when it has one. `None` for
    /// a v1 row (written before the field existed), for a reason that records
    /// no error text (the deadline pair), and for a row whose `error` is an
    /// explicit JSON null — all three are the same "no diagnostic here" to a
    /// reader, so they collapse deliberately.
    pub last_error: Option<String>,
    /// Distinct `"<namespace> <subcommand>"` pairs among the windowed rows
    /// **on the current version**, sorted, capped at `MAX_SUBCOMMANDS` (a
    /// private constant, so it is named rather than intra-doc linked — the
    /// link would not resolve in published docs).
    ///
    /// This is what turns a `version_mismatch` count into an actionable
    /// finding (#183): the count says a plugin expects something this binary
    /// lacks, and this says *which invocation*, so the operator greps one
    /// hooks.json instead of auditing every installed plugin by hand. The
    /// current-version filter matches [`Self::on_current_version`] — a pair
    /// that only ever failed on an older binary is the sanctioned
    /// release-transition case, not a live wiring problem.
    ///
    /// Empty when no windowed row on the current version records a pair (a
    /// bare `cadence-hooks` invocation logs neither).
    pub subcommands: Vec<String>,
}

/// The `failopen.jsonl` rows matching `reason` within the window — the single
/// filter both counting and recency read, so their row sets are structurally
/// the same rather than two prose-aligned re-implementations. Pure — operates
/// on file contents, no I/O.
///
/// `ts` is compared lexicographically against `cutoff` — valid because both
/// are the same fixed-width ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) shape, which sorts
/// identically to chronological order. Unparsable rows and rows missing
/// `reason` or `ts` are skipped.
fn windowed_rows<'a>(
    jsonl: &'a str,
    cutoff: &'a str,
    reason: &'a str,
) -> impl Iterator<Item = Value> + 'a {
    jsonl
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(move |v| v.get("reason").and_then(Value::as_str) == Some(reason))
        .filter(move |v| {
            v.get("ts")
                .and_then(Value::as_str)
                .is_some_and(|ts| ts >= cutoff)
        })
}

/// Count [`windowed_rows`] for `reason`, optionally narrowing to an exact
/// `binaryVersion` match (`version_filter`). Pure — no I/O.
fn count_recent(jsonl: &str, cutoff: &str, reason: &str, version_filter: Option<&str>) -> u64 {
    windowed_rows(jsonl, cutoff, reason)
        .filter(|v| match version_filter {
            Some(want) => v.get("binaryVersion").and_then(Value::as_str) == Some(want),
            None => true,
        })
        .count() as u64
}

/// Lexicographically-comparable ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) lower bound for
/// `window` before `now` — the cutoff every row's `ts` is compared against, by
/// both counting and recency. Its fixed-width shape sorts identically to
/// chronological order, so a plain string compare is a valid time compare.
fn window_cutoff(now: SystemTime, window: Duration) -> String {
    let cutoff_ts =
        jiff::Timestamp::try_from(now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH))
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    cutoff_ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Counts grouped by `reason` over already-read `failopen.jsonl` `contents`.
/// Pure — no I/O.
///
/// `version_mismatch` counts ONLY rows whose `binaryVersion` equals
/// `current_version` (the caller's own running binary version) — this is the
/// deliberate reconciliation for a sanctioned new-hooks.json+old-binary release
/// transition: a `version_mismatch` row logged by an *older* binary hitting a
/// subcommand a newer hooks.json expects (or vice versa) is expected noise
/// during a rollout and must not alarm. A recurrence tagged with the CURRENT
/// binary's own version means the skew didn't resolve, which is what's worth
/// surfacing. `panic`/`parse` counts are NOT version-filtered — any occurrence
/// on any version is worth counting.
fn counts_from(contents: &str, cutoff: &str, current_version: &str) -> FailopenCounts {
    FailopenCounts {
        panic: count_recent(contents, cutoff, "panic", None),
        parse: count_recent(contents, cutoff, "parse", None),
        version_mismatch: count_recent(contents, cutoff, "version_mismatch", Some(current_version)),
        // Deadline rows are environment-correlated (slow disk, load), not
        // version-correlated — count across versions, like panic/parse.
        deadline: count_recent(contents, cutoff, "deadline", None),
        deadline_block_suppressed: count_recent(
            contents,
            cutoff,
            "deadline_block_suppressed",
            None,
        ),
    }
}

/// Per-reason counts plus recency + version context for each of
/// `recency_reasons`, from a single read of `<dir>/failopen.jsonl`. Doctor's
/// `parse` and `panic` findings each need both the count and the recency
/// clause, so folding them into one reader parses the file once — the counts
/// and every recency derive from the same [`windowed_rows`] pass, not several
/// independent reads.
///
/// Returns a map keyed by reason rather than a positional `Vec`, so a caller
/// asking for two reasons cannot mis-attribute one's recency to the other. A
/// reason with no rows in the window is simply absent from the map.
///
/// Fail-open: a missing/unreadable file yields `(FailopenCounts::default(), an
/// empty map)` rather than erroring. Doctor visibility only — never gates
/// anything.
pub fn recent_failopen_report(
    dir: &Path,
    window: Duration,
    now: SystemTime,
    current_version: &str,
    recency_reasons: &[&str],
) -> (FailopenCounts, HashMap<String, FailopenRecency>) {
    let Ok(contents) = std::fs::read_to_string(dir.join("failopen.jsonl")) else {
        return (FailopenCounts::default(), HashMap::new());
    };
    let cutoff = window_cutoff(now, window);
    let counts = counts_from(&contents, &cutoff, current_version);
    let recency = recency_reasons
        .iter()
        .filter_map(|reason| {
            recency_from(&contents, &cutoff, reason, current_version)
                .map(|r| ((*reason).to_string(), r))
        })
        .collect();
    (counts, recency)
}

/// The write-side sanitizer for the `error` field: [`common::display_safe`]
/// plus a length ceiling. Applied when the record is *built*, so an oversized
/// or escape-bearing message never reaches the ledger; the read side still
/// sanitizes, since a hand-edited file can hold anything.
fn sanitize_error(s: &str) -> String {
    common::display_safe_bounded(s, MAX_ERROR_CHARS)
}

/// Pure recency computation over `failopen.jsonl` contents. Reads the same
/// [`windowed_rows`] `count_recent` counts — so the recency row set *is* the
/// counted set, not a parallel re-derivation — then reports the max-`ts` row's
/// timestamp and version plus the current-version row count. `None` when no row
/// matches.
fn recency_from(
    jsonl: &str,
    cutoff: &str,
    reason: &str,
    current_version: &str,
) -> Option<FailopenRecency> {
    let rows: Vec<Value> = windowed_rows(jsonl, cutoff, reason).collect();

    // Comparator form, not `max_by_key`: the key borrows from the row, which a
    // `-> B` key closure can't outlive. On a `ts` tie (two rows in the same
    // second, plausible under a burst) `max_by` keeps the later row in file
    // order — an arbitrary but deterministic winner, which is all a recency
    // display needs.
    let last = rows.iter().max_by(|a, b| {
        let ta = a.get("ts").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("ts").and_then(Value::as_str).unwrap_or("");
        ta.cmp(tb)
    })?;
    // display_safe: these land verbatim in a terminal-printed doctor diagnosis.
    // The values are this binary's own `ts`/`binaryVersion`, so only a
    // hand-tampered failopen.jsonl could smuggle ANSI/control bytes through —
    // strip them as defense-in-depth against escape-sequence injection.
    let last_ts = common::display_safe(last.get("ts").and_then(Value::as_str)?);
    let last_version = common::display_safe(
        last.get("binaryVersion")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    );
    // Absent (v1 row), JSON null, or non-string all collapse to `None` — a
    // reader has no diagnostic in any of the three cases.
    let last_error = last
        .get("error")
        .and_then(Value::as_str)
        .map(common::display_safe)
        .filter(|e| !e.is_empty());
    let on_current_version = rows
        .iter()
        .filter(|v| v.get("binaryVersion").and_then(Value::as_str) == Some(current_version))
        .count() as u64;
    // The DATE prefix of the fixed-width `%Y-%m-%dT%H:%M:%SZ` stamp. A count of
    // distinct days is the shape signal a bare total cannot carry: 120 rows on
    // one day is an episode to correlate with a release or a config change,
    // 120 across seven is the sustained wiring problem the remediation text
    // used to assert unconditionally (#404). Rows whose `ts` is missing or too
    // short are skipped rather than folded into a bogus day.
    let distinct_days = rows
        .iter()
        .filter_map(|v| v.get("ts").and_then(Value::as_str))
        .filter_map(|ts| ts.get(..10))
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    // A `BTreeSet` both dedups and sorts: a skew that fires 96 times names the
    // two or three invocations behind it, not 96 lines.
    //
    // BOUNDED DURING INSERTION, not after. Collecting every distinct pair and
    // then `take`-ing four lets a ledger with attacker-chosen cardinality (a
    // unique subcommand per invocation) size the set — and `failopen.jsonl` is
    // never rotated. Popping the largest once over capacity keeps the same
    // alphabetically-first four at O(MAX_SUBCOMMANDS) resident.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in rows
        .iter()
        .filter(|v| v.get("binaryVersion").and_then(Value::as_str) == Some(current_version))
    {
        // Both halves are validated INDEPENDENTLY. A combined-string emptiness
        // test passes `namespace: ""` with `subcommand: "hook"`, which renders
        // as a leading-space " hook" — a malformed row dressed up as an
        // actionable invocation.
        //
        // Bounded, not just filtered: `display_safe` constrains the character
        // SET but not the length, and these fields are written uncapped (unlike
        // `error`), so an argv-sized token would otherwise flood the printed
        // line and the paste-me command built from it.
        let Some(ns) = row.get("namespace").and_then(Value::as_str) else {
            continue;
        };
        let Some(sub) = row.get("subcommand").and_then(Value::as_str) else {
            continue;
        };
        let ns = common::display_safe_bounded(ns, MAX_PAIR_HALF_CHARS);
        let sub = common::display_safe_bounded(sub, MAX_PAIR_HALF_CHARS);
        let (ns, sub) = (ns.trim(), sub.trim());
        if ns.is_empty() || sub.is_empty() {
            continue;
        }
        seen.insert(format!("{ns} {sub}"));
        if seen.len() > MAX_SUBCOMMANDS {
            seen.pop_last();
        }
    }
    let subcommands: Vec<String> = seen.into_iter().collect();

    Some(FailopenRecency {
        last_ts,
        last_version,
        on_current_version,
        distinct_days,
        last_error,
        subcommands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ENV_LOCK;

    // --- record shape ---

    #[test]
    fn record_has_expected_fields_for_panic() {
        let rec = build_failopen_record(
            "panic",
            Some("cadence"),
            Some("terminology"),
            "1.2.3",
            Some("boom (at src/lib.rs:42)"),
        );
        assert_eq!(rec["schemaVersion"], 2);
        assert_eq!(rec["reason"], "panic");
        assert_eq!(rec["namespace"], "cadence");
        assert_eq!(rec["subcommand"], "terminology");
        assert_eq!(rec["binaryVersion"], "1.2.3");
        assert_eq!(rec["error"], "boom (at src/lib.rs:42)");
        assert!(rec["ts"].is_string());
    }

    #[test]
    fn record_has_expected_fields_for_parse() {
        let rec = build_failopen_record(
            "parse",
            Some("metrics"),
            Some("log-subagent"),
            "0.50.0",
            Some("Failed to parse hook JSON: expected value at line 1 column 1"),
        );
        assert_eq!(rec["reason"], "parse");
        assert_eq!(rec["namespace"], "metrics");
        assert_eq!(rec["subcommand"], "log-subagent");
        assert_eq!(rec["binaryVersion"], "0.50.0");
        assert_eq!(
            rec["error"],
            "Failed to parse hook JSON: expected value at line 1 column 1"
        );
    }

    #[test]
    fn record_has_expected_fields_for_version_mismatch() {
        let rec = build_failopen_record(
            "version_mismatch",
            Some("future-plugin"),
            Some("some-hook"),
            "0.50.0",
            Some("InvalidSubcommand"),
        );
        assert_eq!(rec["reason"], "version_mismatch");
        assert_eq!(rec["namespace"], "future-plugin");
        assert_eq!(rec["subcommand"], "some-hook");
        assert_eq!(rec["error"], "InvalidSubcommand");
    }

    #[test]
    fn record_nulls_namespace_and_subcommand_when_unknown() {
        let rec = build_failopen_record("panic", None, None, "0.50.0", None);
        assert_eq!(rec["reason"], "panic");
        assert!(rec["namespace"].is_null());
        assert!(rec["subcommand"].is_null());
        assert_eq!(rec["binaryVersion"], "0.50.0");
    }

    #[test]
    fn record_nulls_error_when_the_site_has_none() {
        // The deadline rows: a timeout, not a failure with a message. The key
        // is present and explicitly null rather than absent, so a reader never
        // has to distinguish "v1 row" from "v2 row with nothing to say".
        let rec = build_failopen_record(
            "deadline",
            Some("cadence"),
            Some("terminology"),
            "1.2.3",
            None,
        );
        assert!(rec["error"].is_null());
        assert!(
            rec.as_object()
                .expect("record is an object")
                .contains_key("error"),
            "the key is emitted even when null: {rec}"
        );
    }

    // --- sanitize_error (pure) ---

    #[test]
    fn sanitize_error_strips_control_bytes() {
        let dirty = "Failed to parse\n\thook JSON:\u{1b}[31m expected value";
        assert_eq!(
            sanitize_error(dirty),
            "Failed to parsehook JSON:[31m expected value"
        );
    }

    #[test]
    fn sanitize_error_truncates_on_a_char_boundary() {
        // Every char is 3 bytes, so a naive `&s[..MAX_ERROR_CHARS]` byte slice
        // would land mid-codepoint and panic — inside the writer that records
        // panics, of all places.
        let multibyte = "☃".repeat(MAX_ERROR_CHARS + 50);
        let out = sanitize_error(&multibyte);
        assert_eq!(
            out.chars().count(),
            MAX_ERROR_CHARS + 1,
            "truncated to the ceiling plus the ellipsis marker"
        );
        assert!(out.ends_with('…'), "truncation is marked: {out}");
        assert!(out.starts_with('☃'));
    }

    #[test]
    fn sanitize_error_leaves_a_short_message_intact() {
        assert_eq!(sanitize_error("InvalidSubcommand"), "InvalidSubcommand");
    }

    #[test]
    fn sanitize_error_strips_bidi_overrides_and_isolates() {
        // Trojan Source: U+202E reorders everything after it when rendered, so
        // a stored error could scramble the doctor finding line it lands in.
        // These are Cf, not Cc, so `is_control` alone passes them through.
        let spoof = "panic at \u{202E}gnp.eliforp\u{202C} end";
        assert_eq!(sanitize_error(spoof), "panic at gnp.eliforp end");

        let isolated = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e";
        assert_eq!(sanitize_error(isolated), "abcde");
    }

    #[test]
    fn sanitize_error_strips_zero_width_and_separators() {
        assert_eq!(
            sanitize_error("a\u{200B}b\u{FEFF}c\u{2028}d\u{2029}e\u{00AD}f"),
            "abcdef"
        );
    }

    #[test]
    fn display_safe_strips_the_same_families_on_read() {
        // The read side shares the filter, so a hand-edited ledger written
        // before this landed is neutralized at render time too.
        assert_eq!(
            common::display_safe("0.61.0\u{202E}X\u{1b}[31m"),
            "0.61.0X[31m"
        );
    }

    #[test]
    fn display_safe_strips_the_tags_block() {
        // The Unicode Tags block is the primitive that matters for the
        // agent-context sink specifically: U+E0001 plus U+E0020–U+E007F encode
        // arbitrary ASCII that renders as NOTHING yet survives into
        // additionalContext and through most tokenizers. It is Cf, so
        // `is_control` passes it and no bidi-shaped range catches it — a filter
        // that stops at the famous bidi overrides protects a terminal and
        // leaves the agent wide open.
        //
        // "hi" smuggled as tag characters, wrapped in a visible carrier.
        let smuggled = "ok\u{E0001}\u{E0068}\u{E0069}\u{E007F}!";
        assert_eq!(common::display_safe(smuggled), "ok!");
    }

    #[test]
    fn display_safe_strips_the_remaining_cf_blocks() {
        // The enumeration is maintained against the whole Cf category, not just
        // the blocks that happen to be notorious.
        for c in [
            '\u{0890}',  // Arabic pound mark
            '\u{206A}',  // deprecated: inhibit symmetric swapping
            '\u{110BD}', // Kaithi number sign
            '\u{13430}', // Egyptian hieroglyph vertical joiner
            '\u{1BCA0}', // shorthand format letter overlap
            '\u{1D173}', // musical symbol begin beam
        ] {
            assert_eq!(
                common::display_safe(&format!("a{c}b")),
                "ab",
                "U+{:04X} must be stripped",
                c as u32
            );
        }
    }

    #[test]
    fn display_safe_keeps_ordinary_text_intact() {
        // The filter must not become so broad it mangles a real diagnostic.
        assert_eq!(
            common::display_safe("cadence log-commit — naïve 日本語 ✓"),
            "cadence log-commit — naïve 日本語 ✓"
        );
    }

    #[test]
    fn sanitize_error_keeps_ordinary_non_ascii() {
        // The filter targets display-affecting characters, not non-ASCII —
        // an accented or CJK panic message must survive intact.
        assert_eq!(
            sanitize_error("échec du café 日本語"),
            "échec du café 日本語"
        );
    }

    // --- log_failopen end-to-end (tempdir) ---

    fn with_metrics_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::set_var("CADENCE_METRICS_DIR", dir);
        }
        f();
        // SAFETY: serialized against every other env-mutating test via ENV_LOCK.
        unsafe {
            std::env::remove_var("CADENCE_METRICS_DIR");
        }
    }

    fn read_lines(dir: &std::path::Path) -> Vec<Value> {
        let path = dir.join("failopen.jsonl");
        match std::fs::read_to_string(&path) {
            Ok(contents) => contents
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
                .collect(),
            Err(_) => vec![],
        }
    }

    #[test]
    fn log_failopen_writes_one_line() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen(
                "parse",
                Some("cadence"),
                Some("terminology"),
                "1.2.3",
                Some("Failed to parse hook JSON: expected value at line 1 column 1"),
            );
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["reason"], "parse");
        assert_eq!(rows[0]["namespace"], "cadence");
        assert_eq!(rows[0]["subcommand"], "terminology");
        assert_eq!(rows[0]["binaryVersion"], "1.2.3");
        assert_eq!(
            rows[0]["error"],
            "Failed to parse hook JSON: expected value at line 1 column 1"
        );
    }

    #[test]
    fn log_failopen_writes_null_fields_when_none() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", None, None, "0.50.0", None);
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["reason"], "panic");
        assert!(rows[0]["namespace"].is_null());
        assert!(rows[0]["subcommand"].is_null());
        assert!(rows[0]["error"].is_null());
    }

    #[test]
    fn log_failopen_sanitizes_the_error_on_write() {
        // The ledger is clean at rest, not merely at display time — a control
        // byte never reaches the file.
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", None, None, "0.50.0", Some("boom\n\u{1b}[31mred"));
        });
        let rows = read_lines(tmp.path());
        assert_eq!(rows[0]["error"], "boom[31mred");
    }

    // --- count_recent (pure) ---

    fn sample_jsonl() -> String {
        [
            r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"version_mismatch","binaryVersion":"0.9.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"version_mismatch","binaryVersion":"1.0.0","ts":"2026-07-08T00:00:00Z"}"#,
            r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#,
            "not json at all",
        ]
        .join("\n")
    }

    #[test]
    fn count_recent_filters_by_reason_and_window() {
        let jsonl = sample_jsonl();
        let cutoff = "2026-07-01T00:00:00Z";
        assert_eq!(count_recent(&jsonl, cutoff, "panic", None), 1);
        assert_eq!(count_recent(&jsonl, cutoff, "parse", None), 2);
        assert_eq!(count_recent("", cutoff, "panic", None), 0);
    }

    #[test]
    fn count_recent_version_filter_scopes_version_mismatch() {
        let jsonl = sample_jsonl();
        let cutoff = "2026-07-01T00:00:00Z";
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("1.0.0")),
            1
        );
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("0.9.0")),
            1
        );
        assert_eq!(
            count_recent(&jsonl, cutoff, "version_mismatch", Some("2.0.0")),
            0
        );
        assert_eq!(count_recent(&jsonl, cutoff, "version_mismatch", None), 2);
    }

    #[test]
    fn count_recent_garbage_lines_skipped_not_panicking() {
        assert_eq!(
            count_recent("not json\n{}\n", "2026-01-01T00:00:00Z", "panic", None),
            0
        );
    }

    // --- recent_failopen_report end-to-end (tempdir) ---

    #[test]
    fn recent_failopen_report_missing_file_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        let (counts, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            &["parse"],
        );
        assert_eq!(counts, FailopenCounts::default());
        assert!(recency.is_empty());
    }

    #[test]
    fn recent_failopen_report_groups_by_reason_and_current_version() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("panic", Some("cadence"), Some("terminology"), "1.0.0", None);
            log_failopen("parse", Some("cadence"), Some("terminology"), "1.0.0", None);
            // Old-version mismatch: the sanctioned rollout transition — excluded.
            log_failopen(
                "version_mismatch",
                Some("future"),
                Some("hook"),
                "0.9.0",
                None,
            );
            // Current-version mismatch: didn't resolve — counted.
            log_failopen(
                "version_mismatch",
                Some("future"),
                Some("hook"),
                "1.0.0",
                None,
            );
        });
        let (counts, _) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            &["parse"],
        );
        assert_eq!(
            counts,
            FailopenCounts {
                panic: 1,
                parse: 1,
                version_mismatch: 1,
                deadline: 0,
                deadline_block_suppressed: 0,
            }
        );
    }

    // --- recency (pure + end-to-end) ---

    #[test]
    fn recency_subcommands_dedup_sort_and_cap() {
        // Six distinct pairs, each repeated — the shape a live skew produces.
        // The clause must dedup, sort, and stop at MAX_SUBCOMMANDS rather than
        // dumping every pair into a terminal line.
        let rows: String = (0..6)
            .flat_map(|i| {
                (0..3).map(move |_| {
                    format!(
                        r#"{{"reason":"version_mismatch","namespace":"ns","subcommand":"sub{i}","binaryVersion":"1.0.0","ts":"2026-07-25T00:00:0{i}Z"}}"#
                    )
                })
            })
            .map(|r| r + "\n")
            .collect();

        let r = recency_from(&rows, "2026-07-01T00:00:00Z", "version_mismatch", "1.0.0")
            .expect("rows are in window");
        assert_eq!(
            r.subcommands,
            vec!["ns sub0", "ns sub1", "ns sub2", "ns sub3"],
            "deduped, sorted, capped at {MAX_SUBCOMMANDS}"
        );
    }

    #[test]
    fn recency_subcommands_exclude_other_versions() {
        // The current-version filter matches `on_current_version`: a pair that
        // only ever failed on an older binary is the sanctioned
        // release-transition case, not a live wiring problem.
        let rows = concat!(
            r#"{"reason":"version_mismatch","namespace":"ns","subcommand":"old","binaryVersion":"0.9.0","ts":"2026-07-25T00:00:00Z"}"#,
            "\n",
            r#"{"reason":"version_mismatch","namespace":"ns","subcommand":"live","binaryVersion":"1.0.0","ts":"2026-07-25T00:00:01Z"}"#,
            "\n",
        );

        let r = recency_from(rows, "2026-07-01T00:00:00Z", "version_mismatch", "1.0.0")
            .expect("rows are in window");
        assert_eq!(r.subcommands, vec!["ns live"]);
    }

    #[test]
    fn recency_subcommands_reject_half_empty_pairs() {
        // An empty namespace with a real subcommand renders as " hook" — a
        // malformed row dressed up as an actionable invocation. Each half is
        // validated on its own, so neither shape survives.
        let rows = concat!(
            r#"{"reason":"version_mismatch","namespace":"","subcommand":"hook","binaryVersion":"1.0.0","ts":"2026-07-25T00:00:00Z"}"#,
            "\n",
            r#"{"reason":"version_mismatch","namespace":"ns","subcommand":"   ","binaryVersion":"1.0.0","ts":"2026-07-25T00:00:01Z"}"#,
            "\n",
            r#"{"reason":"version_mismatch","namespace":"ns","subcommand":"real","binaryVersion":"1.0.0","ts":"2026-07-25T00:00:02Z"}"#,
            "\n",
        );

        let r = recency_from(rows, "2026-07-01T00:00:00Z", "version_mismatch", "1.0.0")
            .expect("rows are in window");
        assert_eq!(r.subcommands, vec!["ns real"]);
    }

    #[test]
    fn recency_subcommands_empty_without_pairs() {
        // A bare `cadence-hooks` invocation logs neither field — the clause
        // must degrade to empty, not to a half-rendered pair.
        let rows = concat!(
            r#"{"reason":"parse","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"2026-07-25T00:00:00Z"}"#,
            "\n",
        );

        let r =
            recency_from(rows, "2026-07-01T00:00:00Z", "parse", "1.0.0").expect("row is in window");
        assert!(r.subcommands.is_empty());
    }

    #[test]
    fn recency_from_counts_distinct_days_not_rows() {
        // The whole point of #404: an identical TOTAL must read differently
        // depending on how it is distributed. Same count, same last_ts — only
        // the day spread separates a burst from a drip.
        let burst: Vec<String> = (0..12)
            .map(|i| {
                format!(
                    r#"{{"reason":"parse","binaryVersion":"0.67.0","ts":"2026-07-19T{i:02}:00:00Z"}}"#
                )
            })
            .collect();
        let drip: Vec<String> = (0..12)
            .map(|i| {
                format!(
                    r#"{{"reason":"parse","binaryVersion":"0.67.0","ts":"2026-07-{:02}T00:00:00Z"}}"#,
                    14 + i % 6
                )
            })
            .collect();

        let b = recency_from(&burst.join("\n"), "2026-07-01T00:00:00Z", "parse", "0.67.0").unwrap();
        let d = recency_from(&drip.join("\n"), "2026-07-01T00:00:00Z", "parse", "0.67.0").unwrap();

        assert_eq!(b.on_current_version, 12, "same total");
        assert_eq!(d.on_current_version, 12, "same total");
        assert_eq!(b.distinct_days, 1, "twelve rows, all on 2026-07-19");
        assert_eq!(d.distinct_days, 6, "twelve rows across six dates");
    }

    #[test]
    fn recency_from_skips_rows_whose_ts_cannot_carry_a_date() {
        // A malformed `ts` must not fold into a bogus day and inflate the
        // spread — that would read as a drip and send the operator chasing
        // live wiring.
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.67.0","ts":"2026-07-19T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.67.0","ts":"2026-07-19T01:00:00Z"}"#,
        ]
        .join("\n");
        let r = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.67.0").unwrap();
        assert_eq!(r.distinct_days, 1);
    }

    #[test]
    fn recency_from_reports_last_row_and_current_version_count() {
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-18T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.66.0","ts":"2026-07-19T00:00:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        // Max-ts row is the 0.61.0 one at 20:51, even though it is not last in
        // file order — recency picks by timestamp, not position.
        assert_eq!(recency.last_ts, "2026-07-20T20:51:00Z");
        assert_eq!(recency.last_version, "0.61.0");
        assert_eq!(recency.on_current_version, 1);
    }

    #[test]
    fn recency_from_none_on_current_version_is_the_fixed_burst_signal() {
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-18T00:00:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.on_current_version, 0);
        assert_eq!(recency.last_version, "0.61.0");
    }

    #[test]
    fn recency_from_ts_tie_keeps_later_file_order_row() {
        // Two rows in the same second — the documented `max_by` tie rule keeps
        // the later one in file order.
        let jsonl = [
            r#"{"reason":"parse","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#,
            r#"{"reason":"parse","binaryVersion":"0.62.0","ts":"2026-07-20T20:51:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "0.62.0");
    }

    #[test]
    fn recency_from_no_matching_rows_is_none() {
        let jsonl = r#"{"reason":"panic","binaryVersion":"1.0.0","ts":"2026-07-20T00:00:00Z"}"#;
        assert!(recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "1.0.0").is_none());
    }

    #[test]
    fn recency_from_excludes_rows_outside_window() {
        let jsonl = r#"{"reason":"parse","binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        assert!(recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "1.0.0").is_none());
    }

    #[test]
    fn recency_from_missing_binary_version_reports_unknown() {
        let jsonl = r#"{"reason":"parse","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "unknown");
        assert_eq!(recency.on_current_version, 0);
    }

    #[test]
    fn recency_from_reads_the_error_off_a_v2_row() {
        let jsonl = [
            r#"{"schemaVersion":2,"reason":"parse","binaryVersion":"0.68.0","error":"stale","ts":"2026-07-18T00:00:00Z"}"#,
            r#"{"schemaVersion":2,"reason":"parse","binaryVersion":"0.68.0","error":"Failed to parse hook JSON: expected value at line 1 column 1","ts":"2026-07-20T20:51:00Z"}"#,
        ]
        .join("\n");
        let recency = recency_from(&jsonl, "2026-07-01T00:00:00Z", "parse", "0.68.0").unwrap();
        // The error comes off the max-ts row, not the first or last in file order.
        assert_eq!(
            recency.last_error.as_deref(),
            Some("Failed to parse hook JSON: expected value at line 1 column 1")
        );
    }

    #[test]
    fn recency_from_v1_row_without_error_is_none_not_a_panic() {
        // BACKWARD COMPAT: every row in an operator's existing ledger predates
        // the `error` field. Reading one must yield `None` and keep every other
        // field working — a v1 ledger is not a migration event.
        let v1 = r#"{"schemaVersion":1,"reason":"parse","namespace":"cadence","subcommand":"heartbeat","binaryVersion":"0.61.0","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(v1, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_error, None);
        assert_eq!(recency.last_ts, "2026-07-20T20:51:00Z");
        assert_eq!(recency.last_version, "0.61.0");
    }

    #[test]
    fn recency_from_explicit_null_error_is_none() {
        // A v2 row from a site with nothing to report (the deadline pair) reads
        // the same as a v1 row — both mean "no diagnostic here".
        let jsonl = r#"{"schemaVersion":2,"reason":"deadline","binaryVersion":"0.68.0","error":null,"ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "deadline", "0.68.0").unwrap();
        assert_eq!(recency.last_error, None);
    }

    #[test]
    fn recency_from_strips_control_bytes_from_the_error() {
        // Sanitizing on write covers rows this binary produced; a hand-edited
        // ledger can still hold anything, so the read side strips too.
        let jsonl = r#"{"reason":"panic","binaryVersion":"0.68.0","error":"boom\u001b[31mX","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "panic", "0.68.0").unwrap();
        assert_eq!(recency.last_error.as_deref(), Some("boom[31mX"));
    }

    #[test]
    fn recency_from_strips_control_bytes_from_display_fields() {
        // A hand-tampered row smuggling an ANSI escape (JSON \u001b) into
        // binaryVersion — the ESC byte is stripped, leaving the sequence's inert
        // tail as plain text rather than a terminal color command.
        let jsonl =
            r#"{"reason":"parse","binaryVersion":"0.61.0\u001b[31mX","ts":"2026-07-20T20:51:00Z"}"#;
        let recency = recency_from(jsonl, "2026-07-01T00:00:00Z", "parse", "0.66.0").unwrap();
        assert_eq!(recency.last_version, "0.61.0[31mX");
    }

    #[test]
    fn recent_failopen_report_recency_reads_written_rows() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen(
                "parse",
                Some("cadence"),
                Some("heartbeat"),
                "0.61.0",
                Some("Failed to parse hook JSON: EOF while parsing a value"),
            );
        });
        let (_, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "0.66.0",
            &["parse"],
        );
        let recency = recency.get("parse").expect("parse recency present");
        assert_eq!(recency.last_version, "0.61.0");
        assert_eq!(recency.on_current_version, 0);
        assert_eq!(
            recency.last_error.as_deref(),
            Some("Failed to parse hook JSON: EOF while parsing a value")
        );
    }

    #[test]
    fn recent_failopen_report_keys_recency_by_reason() {
        // Two reasons in one read: each recency must attach to its own reason,
        // which a keyed map guarantees and a positional list would not.
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen(
                "parse",
                Some("cadence"),
                Some("heartbeat"),
                "1.0.0",
                Some("bad stdin"),
            );
            log_failopen(
                "panic",
                Some("cadence"),
                Some("terminology"),
                "1.0.0",
                Some("boom"),
            );
        });
        let (_, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            &["parse", "panic"],
        );
        assert_eq!(recency.len(), 2);
        assert_eq!(recency["parse"].last_error.as_deref(), Some("bad stdin"));
        assert_eq!(recency["panic"].last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn recent_failopen_report_omits_a_reason_with_no_rows() {
        let tmp = tempfile::tempdir().unwrap();
        with_metrics_dir(tmp.path(), || {
            log_failopen("parse", Some("cadence"), Some("heartbeat"), "1.0.0", None);
        });
        let (_, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            &["parse", "panic"],
        );
        assert!(recency.contains_key("parse"));
        assert!(!recency.contains_key("panic"));
    }

    #[test]
    fn recent_failopen_report_excludes_outside_window() {
        let tmp = tempfile::tempdir().unwrap();
        let old_row = r#"{"schemaVersion":1,"reason":"panic","namespace":null,"subcommand":null,"binaryVersion":"1.0.0","ts":"2000-01-01T00:00:00Z"}"#;
        std::fs::write(tmp.path().join("failopen.jsonl"), format!("{old_row}\n")).unwrap();
        let (counts, recency) = recent_failopen_report(
            tmp.path(),
            Duration::from_secs(7 * 86_400),
            SystemTime::now(),
            "1.0.0",
            &["parse"],
        );
        assert_eq!(counts, FailopenCounts::default());
        assert!(recency.is_empty());
    }
}
