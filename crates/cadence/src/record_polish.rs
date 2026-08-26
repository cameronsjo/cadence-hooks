//! Record that `/polish` (cadence-forge:polish) ran on this branch.
//!
//! A **CLI action**, not a hook: the polish skill's Wrap-up shells out to
//! `cadence-hooks cadence record-polish` after a completed pass, which writes a
//! branch-scoped marker under the private [`markers::marker_dir`]. The pre-PR
//! gate ([`crate::nudge_polish_before_pr`]) then reads that marker instead of
//! scanning the session transcript.
//!
//! The marker key is `(repo_root, branch)` (see [`markers::polish_marker`]),
//! where `repo_root` is the canonicalized `git rev-parse --git-common-dir`
//! (cadence-hooks#324) — stable across every worktree of a repo, not
//! `--show-toplevel` (a linked worktree's own path). Detection is therefore
//! invocation-agnostic (Skill call, `/polish` slash-command, or a delegated
//! subagent all end by running this), worktree-agnostic (recording from a
//! worktree satisfies a ship command run from the primary checkout, and vice
//! versa), and branch-scoped (a marker for branch A cannot satisfy a PR on
//! branch B).
//!
//! Advisory, always — this must never fail the user's polish pass. Every
//! *environment* error path (not a repo, detached HEAD, unwritable marker dir)
//! prints one stderr line and exits 0 (ADR-0001). A **usage** error — today
//! only an invalid `--scope` — exits 2 and records nothing, matching the
//! `redact-scan` CLI convention (cadence-hooks#775): the caller mis-spelled the
//! record, and storing it anyway lands a marker the gate silently misreads.

use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::markers::{
    ArmAttestation, polish_marker, read_polish_record, write_marker,
};
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::time::utc_timestamp;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// The canonical marker key for a directory: the canonicalized
/// `git_common_dir` from [`GitState::resolve`]. `None` when `dir` is not inside
/// a git repository.
fn repo_key(dir: &str) -> Option<String> {
    GitState::resolve(std::path::Path::new(dir))
        .map(|state| state.git_common_dir.to_string_lossy().into_owned())
}

/// Resolve `repo_root`, `branch`, and `head_sha` from `dir`, letting explicit
/// overrides stand in so tests need no real repository.
///
/// `repo_root` and `branch` come from [`GitState::resolve`] — a pure
/// filesystem walk keyed on the canonicalized `git_common_dir`, matching the
/// read side ([`cadence_hooks_core::markers::polish_marker_present`]) so a
/// worktree and its primary checkout key to the same marker. `head_sha` is
/// still resolved via a `git` shell-out: it's provenance metadata, not part of
/// the key, and best-effort — a repo with no commits yet has no `HEAD`, so it
/// resolves to `None` and the field is recorded as an empty string rather than
/// failing the record. `repo_root` and `branch` are the load-bearing key; when
/// either can't be resolved the caller degrades to a no-op (exit 0).
///
/// An explicit `repo_root` is resolved through that same canonicalization
/// rather than used verbatim (cadence-hooks#417), so the flag can only ever
/// *locate* the repo — never *redefine* the key. Passing the linked worktree
/// you happen to be standing in is the most natural thing to do and was
/// precisely the value that broke: it wrote a marker under the worktree's own
/// path, which the ship gate — keyed on the common dir — can never read. The
/// failure was silent and delayed, surfacing later as a polish nudge on a
/// branch that genuinely had been polished.
///
/// When the path resolves to no repository at all the literal value stands,
/// which is what keeps the test override (a bogus dir plus an explicit branch,
/// resolving without touching git) working. A path *inside* a repo resolves
/// upward to that repo — locating by any path under it is the affordance, so
/// only a path under no repo falls through to the literal.
///
/// An explicit `repo_root` re-bases the **whole** resolution, not just the repo
/// half: `branch` and `head_sha` are read from that same checkout rather than
/// from `dir`. Splitting them is a live mis-record, and #417 is what made it
/// reachable — before it, an explicit root produced a key nothing read, so the
/// asymmetry was inert. With the repo half correct and the branch half still
/// coming from the caller's cwd, an orchestrator recording on a worker's behalf
/// (`record-polish --repo-root <worker worktree>`, no `--branch`, run from a
/// checkout sitting on `main`) would write a marker keyed to the worker's repo
/// but the *orchestrator's* branch: the polished branch keeps getting nudged,
/// and `main` is silently credited with a polish it never had. That is exactly
/// the case the flag exists for, so the two halves must move together.
fn resolve(
    dir: &str,
    repo_root: Option<String>,
    branch: Option<String>,
) -> Option<(String, String, String)> {
    let base = repo_root.as_deref().unwrap_or(dir).to_string();
    let git_state = || GitState::resolve(std::path::Path::new(&base));
    let repo_root = repo_root
        .map(|explicit| {
            repo_key(&explicit).unwrap_or_else(|| {
                // Say so. The whole failure #417 exists to kill is a success
                // verdict over a key nothing will read, and the literal
                // fallback is the one surviving path that can still produce
                // one — a typo'd root keys the typo, and a relative root keys
                // the bare string, which collides across repos.
                eprintln!(
                    "cadence-hooks record-polish: --repo-root {explicit} is not a git \
                     repository — any marker will use that literal key, which the \
                     pre-PR gate will not match unless it was given the same literal."
                );
                explicit
            })
        })
        .or_else(|| git_state().map(|state| state.git_common_dir.to_string_lossy().into_owned()))?;
    let branch = branch.or_else(|| git_state().and_then(|state| state.branch))?;
    // Polish does not commit (SKILL.md), so this is the pre-polish base SHA — a
    // provenance breadcrumb for CP2, never an exact-match key. Empty when the
    // repo has no HEAD yet.
    let head_sha = git_command(&base, &["rev-parse", "HEAD"]).unwrap_or_default();
    Some((repo_root, branch, head_sha))
}

/// Parse repeatable `--arm name=state` values into the roster, dropping (and
/// naming, on stderr, Debug-escaped) any value that is not `name=state` with
/// both halves in `[A-Za-z0-9_-]+` — fail-open, the rest of the record still
/// lands (ADR-0001). The charset bound is what keeps the roster safe to echo:
/// the verdict line and the marker JSON both carry these strings, so ANSI or
/// control bytes never survive to either surface.
fn parse_arms(raw: &[String]) -> Vec<(String, String)> {
    parse_keyed(raw, "--arm", is_arm_token, "state", |_, _| {})
}

/// The longest an arm name, state, or attested model family may be. Names and
/// states were unbounded until cadence-hooks#775 — a megabyte of `[A-Za-z0-9]`
/// passed the charset check and rode the marker JSON and the verdict line.
const MAX_TOKEN_BYTES: usize = 64;

/// The longest an attested report path may be — generous for a real path, and
/// still a bound (cadence-hooks#775). The path is provenance only: never
/// opened, never echoed as content.
const MAX_REPORT_BYTES: usize = 512;

/// The `--arm` charset: `[A-Za-z0-9_-]+`, at most [`MAX_TOKEN_BYTES`]. This is
/// what keeps every recorded token safe to echo — the verdict line and the
/// marker JSON both carry them, so ANSI or control bytes never survive to
/// either surface.
fn is_arm_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOKEN_BYTES
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A report path: printable ASCII (0x20–0x7E) only, at most
/// [`MAX_REPORT_BYTES`]. Spaces are legal in a path, control bytes are not, and
/// non-ASCII is rejected rather than transcoded — a rejected path costs a
/// stderr note, a smuggled one rides every future read of the marker.
fn is_report_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_REPORT_BYTES && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Parse repeatable `name=value` flags, dropping (and naming, on stderr,
/// Debug-escaped) anything whose name is not an arm token or whose value fails
/// `value_ok` — fail-open, the rest of the record still lands (ADR-0001).
///
/// `note` runs on each accepted pair, for the one advisory a value can carry
/// without being rejected (a report path that does not exist yet).
fn parse_keyed(
    raw: &[String],
    flag: &str,
    value_ok: fn(&str) -> bool,
    value_label: &str,
    note: fn(&str, &str),
) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((name, value)) if is_arm_token(name.trim()) && value_ok(value.trim()) => {
                note(name.trim(), value.trim());
                Some((name.trim().to_string(), value.trim().to_string()))
            }
            _ => {
                eprintln!(
                    "cadence-hooks record-polish: ignoring malformed {flag} {entry:?} \
                     (expected name={value_label}, name in [A-Za-z0-9_-] \
                     and at most {MAX_TOKEN_BYTES} bytes)"
                );
                None
            }
        })
        .collect()
}

/// Parse repeatable `--arm-model name=family` values (cadence-hooks#775).
///
/// The family is **recorded, not validated against a closed set** — the point
/// is to record what actually ran. Only the *gate's* satisfying set is closed
/// (`opus`), and that lives on the read side.
fn parse_arm_model(raw: &[String]) -> Vec<(String, String)> {
    parse_keyed(raw, "--arm-model", is_arm_token, "family", |_, _| {})
}

/// Parse repeatable `--arm-report name=path` values (cadence-hooks#775).
///
/// A path that does not exist at record time is *noted* on stderr and recorded
/// anyway: the record may legitimately precede the write, and no code ever
/// opens the path or echoes its contents.
fn parse_arm_report(raw: &[String]) -> Vec<(String, String)> {
    parse_keyed(raw, "--arm-report", is_report_path, "path", |name, path| {
        if !Path::new(path).exists() {
            eprintln!(
                "cadence-hooks record-polish: --arm-report {name}={path:?} does not exist \
                 — recording the path anyway (provenance only; it is never read)."
            );
        }
    })
}

/// Merge the prior attestation map with this invocation's, under the binding
/// rule that makes `attest.NAME` trustworthy: **an attestation describes the
/// run stated beside it** (cadence-hooks#775).
///
/// Two directions, both required for that invariant:
///
/// - an attestation for `NAME` is kept only when this same invocation states
///   `--arm NAME=…` — a bare `--arm-model`/`--arm-report` drops with a note;
/// - an incoming `--arm NAME=…` drops any *prior* attestation for `NAME`, so a
///   re-run that reports no model cannot inherit the previous run's.
///
/// `fresh` clears the map entirely, matching [`merge_arms`].
fn merge_attest(
    existing: Option<&BTreeMap<String, ArmAttestation>>,
    incoming_arms: &[(String, String)],
    models: Vec<(String, String)>,
    reports: Vec<(String, String)>,
    fresh: bool,
) -> BTreeMap<String, ArmAttestation> {
    let mut merged = if fresh {
        BTreeMap::new()
    } else {
        existing.cloned().unwrap_or_default()
    };
    for (name, _) in incoming_arms {
        merged.remove(name);
    }
    let stated = |name: &str| incoming_arms.iter().any(|(arm, _)| arm == name);
    for (flag, pairs) in [("--arm-model", models), ("--arm-report", reports)] {
        for (name, value) in pairs {
            if !stated(&name) {
                eprintln!(
                    "cadence-hooks record-polish: ignoring {flag} {name}={value:?} — no \
                     matching --arm {name}=<state> in this invocation, and an attestation \
                     only ever describes the run stated beside it."
                );
                continue;
            }
            let entry = merged.entry(name).or_default();
            if flag == "--arm-model" {
                entry.model = Some(value);
            } else {
                entry.report = Some(value);
            }
        }
    }
    merged
}

/// The closed set `--scope` accepts, and the only values the gate can read:
/// `docs` settles the security arm ([`cadence_hooks_core::markers::PolishRecord::security_ran`]),
/// `full`/`code` leave it to the roster. Anything else recorded as free text is
/// a silent near-miss — `Docs` reads as *unknown*, not as a docs pass — so the
/// value is rejected rather than stored (cadence-hooks#775).
const VALID_SCOPES: [&str; 3] = ["full", "code", "docs"];

/// Resolve `--scope` against [`VALID_SCOPES`], defaulting to `full`.
///
/// `Err` carries the rejected value **Debug-escaped**, matching [`parse_arms`]:
/// the raw string would otherwise reach the terminal through the error line,
/// which is the ANSI/control-byte surface the arm charset bound was added to
/// close.
fn validate_scope(scope: Option<&str>) -> Result<String, String> {
    match scope {
        None => Ok("full".to_string()),
        Some(value) if VALID_SCOPES.contains(&value) => Ok(value.to_string()),
        Some(value) => Err(format!("{value:?}")),
    }
}

/// Merge a trusted prior roster with the incoming delta. Existing names survive;
/// incoming entries override in argument order, preserving last-value-wins.
///
/// `fresh` is the clearing spelling (cadence-hooks#775): it drops the prior
/// roster entirely, so the record carries exactly the stated arms and an
/// omitted arm is genuinely *absent* — which the gate reads as unknown rather
/// than inheriting a stale `security=ran`.
fn merge_arms(
    existing: Option<&BTreeMap<String, String>>,
    incoming: Vec<(String, String)>,
    fresh: bool,
) -> Vec<(String, String)> {
    let mut merged = if fresh {
        BTreeMap::new()
    } else {
        existing.cloned().unwrap_or_default()
    };
    for (name, state) in incoming {
        merged.insert(name, state);
    }
    merged.into_iter().collect()
}

/// Build the marker payload. Presence is what CP1 gates on; the fields are
/// stored now so CP2's freshness/scope escalation needs no format change.
/// The `arms` roster (cadence-hooks#467) is **additive and optional**: absent
/// on a roster-less record, so legacy readers and legacy markers both keep
/// working — an absent roster reads as *unknown*, never as *skipped*.
///
/// The `attest` map (cadence-hooks#775) is additive and optional the same way:
/// `"attest": {"security": {"model": "opus", "report": "…"}}`, absent when the
/// invocation attested nothing. Either half may be absent — a partial
/// attestation is legal.
///
/// `fresh` leaves a breadcrumb: `"fresh": true` when the record cleared a prior
/// roster, absent otherwise (cadence-hooks#775 review). Without it, a `--fresh`
/// record that erased a `security=skipped` is byte-indistinguishable from a
/// legacy roster-less marker, so an audit cannot tell a *cleared* roster from
/// one that never existed. No reader gates on it — it is provenance only.
fn marker_content(
    branch: &str,
    head_sha: &str,
    scope: &str,
    arms: &[(String, String)],
    attest: &BTreeMap<String, ArmAttestation>,
    fresh: bool,
) -> String {
    let mut v = json!({
        "branch": branch,
        "head_sha": head_sha,
        "recorded_at": utc_timestamp(),
        "scope": scope,
    });
    if !arms.is_empty() {
        let roster: serde_json::Map<String, serde_json::Value> = arms
            .iter()
            .map(|(name, state)| (name.clone(), json!(state)))
            .collect();
        v["arms"] = serde_json::Value::Object(roster);
    }
    if !attest.is_empty() {
        let entries: serde_json::Map<String, serde_json::Value> = attest
            .iter()
            .map(|(name, a)| {
                let mut entry = serde_json::Map::new();
                if let Some(model) = &a.model {
                    entry.insert("model".to_string(), json!(model));
                }
                if let Some(report) = &a.report {
                    entry.insert("report".to_string(), json!(report));
                }
                (name.clone(), serde_json::Value::Object(entry))
            })
            .collect();
        v["attest"] = serde_json::Value::Object(entries);
    }
    if fresh {
        v["fresh"] = json!(true);
    }
    v.to_string()
}

/// One-line success verdict: the marker path (the payload a caller probes to
/// confirm the pre-PR gate is satisfied) plus the (repo@branch, scope) key —
/// and the arm roster when one was recorded, so the caller sees what the gate
/// will see.
fn record_verdict(
    repo_root: &str,
    branch: &str,
    scope: &str,
    arms: &[(String, String)],
    path: &Path,
) -> String {
    let roster = if arms.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = arms.iter().map(|(n, s)| format!("{n}={s}")).collect();
        format!(" arms={}", list.join(","))
    };
    format!(
        "recorded polish marker: {} ({repo_root}@{branch} scope={scope}{roster})",
        path.display()
    )
}

/// Write the branch-scoped polish marker, resolving repo/branch/HEAD from the
/// current directory unless overridden. Returns the process exit code.
///
/// Fail-open on *environment*: any missing context or write error prints one
/// stderr line and returns 0 — a CLI action must never fail the polish pass it
/// is recording (ADR-0001).
///
/// **Usage errors are the one exception** (exit 2, the `redact-scan` CLI
/// convention): an invalid `--scope` is the caller mis-spelling the record, not
/// the environment degrading, and recording it anyway would land a marker whose
/// scope the gate silently reads as unknown (cadence-hooks#775).
pub fn run_record(
    repo_root: Option<String>,
    branch: Option<String>,
    scope: Option<String>,
    arm: Vec<String>,
    arm_model: Vec<String>,
    arm_report: Vec<String>,
    fresh: bool,
) -> u8 {
    // Validated BEFORE any resolution or write — mirrors `redact-scan`, whose
    // `--audience` check precedes even `--init`.
    let scope = match validate_scope(scope.as_deref()) {
        Ok(scope) => scope,
        Err(rejected) => {
            eprintln!(
                "cadence-hooks record-polish: invalid --scope {rejected} (expected {}) \
                 — no marker recorded.",
                VALID_SCOPES.join("|")
            );
            return 2;
        }
    };

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| ".".to_string());

    let Some((repo_root, branch, head_sha)) = resolve(&cwd, repo_root, branch) else {
        eprintln!(
            "cadence-hooks record-polish: could not resolve repo root / branch \
             (not a git repo, or detached HEAD) — no marker recorded."
        );
        return 0;
    };

    let incoming_arms = parse_arms(&arm);
    let prior = read_polish_record(&repo_root, &branch);
    let attest = merge_attest(
        prior.as_ref().and_then(|record| record.attest.as_ref()),
        &incoming_arms,
        parse_arm_model(&arm_model),
        parse_arm_report(&arm_report),
        fresh,
    );
    let arms = merge_arms(
        prior.as_ref().and_then(|record| record.arms.as_ref()),
        incoming_arms,
        fresh,
    );
    let content = marker_content(&branch, &head_sha, &scope, &arms, &attest, fresh);
    let path = polish_marker(&repo_root, &branch);
    match write_marker(&path, &content) {
        Ok(()) => println!(
            "{}",
            record_verdict(&repo_root, &branch, &scope, &arms, &path)
        ),
        Err(e) => eprintln!(
            "cadence-hooks record-polish: marker write failed ({e}) — pre-PR gate may re-nudge."
        ),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::markers::polish_marker;
    use cadence_hooks_core::test_builders::with_marker_dir;

    #[test]
    fn marker_content_is_parseable_json_with_all_fields() {
        let content = marker_content("feat/x", "abc123", "full", &[], &BTreeMap::new(), false);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["branch"], "feat/x");
        assert_eq!(v["head_sha"], "abc123");
        assert_eq!(v["scope"], "full");
        // recorded_at is an ISO-8601 UTC instant (jiff `utc_timestamp`).
        let ts = v["recorded_at"].as_str().unwrap();
        assert!(ts.ends_with('Z'), "recorded_at should be UTC: {ts}");
        // #467: a roster-less record carries NO arms key at all — absent, not
        // empty — so legacy-shaped markers stay the common case on disk.
        assert!(v.get("arms").is_none(), "no --arm flags → no arms key");
    }

    #[test]
    fn marker_content_serializes_supplied_arm_roster() {
        // #467 RED: the roster rides an additive "arms" object.
        let arms = vec![
            ("security".to_string(), "ran".to_string()),
            ("tests".to_string(), "skipped".to_string()),
        ];
        let content = marker_content("feat/x", "abc123", "code", &arms, &BTreeMap::new(), false);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["arms"]["security"], "ran");
        assert_eq!(v["arms"]["tests"], "skipped");
        assert_eq!(v["scope"], "code", "existing fields unchanged");
    }

    #[test]
    fn parse_arms_accepts_name_state_and_drops_malformed() {
        let raw = vec![
            "security=ran".to_string(),
            "bogus".to_string(),
            "=x".to_string(),
            "docs=skipped".to_string(),
        ];
        let arms = parse_arms(&raw);
        assert_eq!(
            arms,
            vec![
                ("security".to_string(), "ran".to_string()),
                ("docs".to_string(), "skipped".to_string()),
            ],
            "malformed entries drop without failing the record"
        );
    }

    #[test]
    fn record_verdict_names_path_repo_branch_and_scope() {
        let path = polish_marker("/tmp/repo", "feat/x");
        let verdict = record_verdict("/tmp/repo", "feat/x", "full", &[], &path);
        assert!(verdict.contains(&path.display().to_string()));
        assert!(verdict.contains("/tmp/repo@feat/x"));
        assert!(verdict.contains("scope=full"));
        assert!(!verdict.contains("arms="), "no roster → no arms clause");
    }

    #[test]
    fn record_verdict_names_the_roster_when_present() {
        // #467: the verdict shows the caller what the gate will see.
        let path = polish_marker("/tmp/repo", "feat/x");
        let arms = vec![("security".to_string(), "skipped".to_string())];
        let verdict = record_verdict("/tmp/repo", "feat/x", "code", &arms, &path);
        assert!(verdict.contains("arms=security=skipped"), "{verdict}");
    }

    // --- --scope validation (cadence-hooks#775 item 4) ---

    #[test]
    fn validate_scope_accepts_the_closed_set_and_defaults_to_full() {
        assert_eq!(validate_scope(None).unwrap(), "full");
        assert_eq!(validate_scope(Some("full")).unwrap(), "full");
        assert_eq!(validate_scope(Some("code")).unwrap(), "code");
        assert_eq!(validate_scope(Some("docs")).unwrap(), "docs");
    }

    #[test]
    fn validate_scope_rejects_anything_outside_the_closed_set() {
        // #775 RED: `--scope Docs` used to sail through as free text and
        // defeat the docs settle in `PolishRecord::security_ran` — the gate
        // reads `docs` exactly, so a near-miss recorded as "unknown".
        assert!(validate_scope(Some("Docs")).is_err());
        assert!(validate_scope(Some("")).is_err());
        assert!(validate_scope(Some("full code")).is_err());
        // ...and the ANSI/control-byte surface the verdict line would echo.
        assert!(validate_scope(Some("full\u{1b}[31m")).is_err());
    }

    #[test]
    fn run_record_rejects_an_invalid_scope_as_a_usage_error_and_writes_nothing() {
        // #775 RED: a usage error (exit 2, the `redact-scan` CLI convention),
        // and NO marker — a rejected scope must not land a record whose
        // roster the gate would then trust.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-bad-scope-repo";
            let branch = "feat/record-polish-bad-scope";
            let path = polish_marker(repo, branch);

            let code = run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("Docs".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            assert_eq!(code, 2, "an invalid --scope is a usage error");
            assert!(
                !path.exists(),
                "no marker may be written for a rejected scope"
            );
        });
    }

    #[test]
    fn run_record_accepts_every_valid_scope() {
        // Positive control for the rejection above: each member of the closed
        // set still records, exit 0.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            for scope in ["full", "code", "docs"] {
                let repo = "/tmp/record-polish-valid-scope-repo";
                let branch = format!("feat/record-polish-scope-{scope}");
                let code = run_record(
                    Some(repo.into()),
                    Some(branch.clone()),
                    Some(scope.into()),
                    vec![],
                    vec![],
                    vec![],
                    false,
                );
                assert_eq!(code, 0, "{scope} must be accepted");
                let content = std::fs::read_to_string(polish_marker(repo, &branch)).unwrap();
                let v: serde_json::Value = serde_json::from_str(&content).unwrap();
                assert_eq!(v["scope"], scope);
            }
        });
    }

    // --- --fresh: the clearing spelling (cadence-hooks#775 item 3) ---

    #[test]
    fn merge_arms_fresh_records_exactly_the_stated_roster() {
        // #775 RED: without a clearing spelling, a stale `security=ran` can
        // only be overridden by an explicit `security=skipped`.
        let prior: BTreeMap<String, String> = [
            ("security".to_string(), "ran".to_string()),
            ("tests".to_string(), "ran".to_string()),
        ]
        .into_iter()
        .collect();
        let incoming = vec![("tests".to_string(), "ran".to_string())];

        let fresh = merge_arms(Some(&prior), incoming.clone(), true);
        assert_eq!(fresh, vec![("tests".to_string(), "ran".to_string())]);

        // Positive control: the DEFAULT is still additive.
        let merged = merge_arms(Some(&prior), incoming, false);
        assert_eq!(
            merged,
            vec![
                ("security".to_string(), "ran".to_string()),
                ("tests".to_string(), "ran".to_string()),
            ]
        );
    }

    #[test]
    fn run_record_fresh_drops_an_omitted_prior_arm() {
        // #775: an omitted arm under --fresh is genuinely ABSENT, so the gate
        // reads it as unknown rather than inheriting the prior "ran".
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-fresh-repo";
            let branch = "feat/record-polish-fresh";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into(), "tests=ran".into()],
                vec![],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["tests=ran".into()],
                vec![],
                vec![],
                true,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["arms"]["tests"], "ran");
            assert!(
                v["arms"].get("security").is_none(),
                "--fresh must record exactly the stated roster: {content}"
            );
        });
    }

    #[test]
    fn fresh_record_carries_a_breadcrumb_and_the_default_does_not() {
        // #775 review: a `--fresh` record that erased a prior
        // `security=skipped` is otherwise byte-indistinguishable from a legacy
        // roster-less marker, so an audit cannot tell a CLEARED roster from one
        // that never existed. Provenance only — no reader gates on it.
        let fresh: serde_json::Value = serde_json::from_str(&marker_content(
            "feat/x",
            "abc123",
            "full",
            &[],
            &BTreeMap::new(),
            true,
        ))
        .unwrap();
        assert_eq!(fresh["fresh"], true);

        let default: serde_json::Value = serde_json::from_str(&marker_content(
            "feat/x",
            "abc123",
            "full",
            &[],
            &BTreeMap::new(),
            false,
        ))
        .unwrap();
        assert!(
            default.get("fresh").is_none(),
            "the additive default must carry no breadcrumb: {default}"
        );
    }

    #[test]
    fn run_record_fresh_breadcrumb_round_trips_and_the_gate_ignores_it() {
        // The breadcrumb rides the written marker, and adding it changes no
        // gate behavior: the record still reads back with its roster intact.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-breadcrumb-repo";
            let branch = "feat/record-polish-breadcrumb";

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                true,
            );

            let content = std::fs::read_to_string(polish_marker(repo, branch)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["fresh"], true);

            let record = read_polish_record(repo, branch).expect("marker reads");
            assert_eq!(
                record.security_ran(),
                Some(true),
                "the breadcrumb must not disturb the roster the gate reads"
            );
        });
    }

    #[test]
    fn run_record_fresh_with_no_arms_leaves_no_roster() {
        // The full clearing case: `--fresh` with no `--arm` at all wipes the
        // roster, so every arm reads as unknown.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-fresh-empty-repo";
            let branch = "feat/record-polish-fresh-empty";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                true,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(
                v.get("arms").is_none(),
                "no roster survives --fresh: {content}"
            );
        });
    }

    // --- attestation flags (cadence-hooks#775 item 1) ---

    #[test]
    fn parse_arm_model_accepts_the_arm_charset_and_drops_everything_else() {
        // #775 item 1 RED: the family is recorded, not validated against a
        // closed set — what ran is provenance. The charset bound is what keeps
        // it safe to echo into the verdict line and the marker JSON.
        let raw = vec![
            "security=opus".to_string(),
            "tests=sonnet-4_5".to_string(),
            "bogus".to_string(),
            "security=".to_string(),
            "security=opus\u{1b}[31m".to_string(),
            format!("security={}", "o".repeat(65)),
            format!("{}=opus", "n".repeat(65)),
        ];
        assert_eq!(
            parse_arm_model(&raw),
            vec![
                ("security".to_string(), "opus".to_string()),
                ("tests".to_string(), "sonnet-4_5".to_string()),
            ],
            "malformed, over-long, and control-byte values drop without failing the record"
        );
    }

    #[test]
    fn parse_arm_report_accepts_printable_ascii_paths_only() {
        // The path is provenance — never opened, never echoed as content — but
        // it DOES ride the marker JSON and the verdict line, so it is bounded
        // to printable ASCII and 512 bytes.
        let raw = vec![
            "security=/tmp/security review.md".to_string(),
            "tests=/tmp/t.md\u{7f}".to_string(),
            "docs=/tmp/caf\u{e9}.md".to_string(),
            "simplify=/tmp/a\nb.md".to_string(),
            format!("lint=/tmp/{}.md", "p".repeat(512)),
        ];
        assert_eq!(
            parse_arm_report(&raw),
            vec![(
                "security".to_string(),
                "/tmp/security review.md".to_string()
            )],
            "non-printable, non-ASCII, and over-long paths drop"
        );
    }

    #[test]
    fn parse_arms_caps_name_and_state_at_64_bytes() {
        // Arm names and states were unbounded — capped in the same pass, same
        // drop-and-continue behavior as every other malformed value.
        let raw = vec![
            "security=ran".to_string(),
            format!("{}=ran", "n".repeat(65)),
            format!("security={}", "s".repeat(65)),
            format!("{}={}", "n".repeat(64), "s".repeat(64)),
        ];
        let arms = parse_arms(&raw);
        assert_eq!(
            arms,
            vec![
                ("security".to_string(), "ran".to_string()),
                ("n".repeat(64), "s".repeat(64)),
            ]
        );
    }

    #[test]
    fn marker_content_serializes_the_attest_map_and_omits_an_empty_one() {
        let attest: BTreeMap<String, ArmAttestation> = [(
            "security".to_string(),
            ArmAttestation {
                model: Some("opus".to_string()),
                report: Some("/tmp/x.md".to_string()),
            },
        )]
        .into_iter()
        .collect();
        let arms = vec![("security".to_string(), "ran".to_string())];
        let content = marker_content("feat/x", "abc123", "full", &arms, &attest, false);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["attest"]["security"]["model"], "opus");
        assert_eq!(v["attest"]["security"]["report"], "/tmp/x.md");

        let bare = marker_content("feat/x", "abc123", "full", &arms, &BTreeMap::new(), false);
        let v: serde_json::Value = serde_json::from_str(&bare).unwrap();
        assert!(
            v.get("attest").is_none(),
            "no attestation → no attest key: {bare}"
        );
    }

    #[test]
    fn run_record_drops_attest_with_no_matching_arm_in_the_same_invocation() {
        // The binding invariant: `attest.NAME` always describes the run stated
        // beside it, so a bare `--arm-model` with no `--arm NAME=…` in the same
        // invocation records nothing.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-unbound-repo";
            let branch = "feat/record-polish-attest-unbound";

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["tests=ran".into()],
                vec!["security=opus".into()],
                vec!["security=/tmp/x.md".into()],
                false,
            );

            let content = std::fs::read_to_string(polish_marker(repo, branch)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(
                v.get("attest").is_none(),
                "an attest with no matching --arm in the same invocation must drop: {content}"
            );
        });
    }

    #[test]
    fn run_record_restating_an_arm_without_attest_drops_the_prior_attest() {
        // The other half of the binding: a re-run that states `--arm
        // security=ran` with no attestation must not inherit the previous
        // run's attestation — the map would then describe a run that never
        // reported one.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-restate-repo";
            let branch = "feat/record-polish-attest-restate";

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into(), "tests=ran".into()],
                vec!["security=opus".into(), "tests=sonnet".into()],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(polish_marker(repo, branch)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(
                v["attest"].get("security").is_none(),
                "a restated arm drops its prior attestation: {content}"
            );
            assert_eq!(
                v["attest"]["tests"]["model"], "sonnet",
                "an untouched arm keeps its attestation: {content}"
            );
        });
    }

    #[test]
    fn run_record_fresh_clears_the_attest_map_too() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-fresh-repo";
            let branch = "feat/record-polish-attest-fresh";

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec!["security=opus".into()],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["tests=ran".into()],
                vec![],
                vec![],
                true,
            );

            let content = std::fs::read_to_string(polish_marker(repo, branch)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(
                v.get("attest").is_none(),
                "--fresh clears the arms map AND the attest map: {content}"
            );
        });
    }

    #[test]
    fn run_record_round_trips_a_bound_attestation_through_the_marker() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-roundtrip-repo";
            let branch = "feat/record-polish-attest-roundtrip";
            let report = marker_tmp.path().join("security-review.md");
            std::fs::write(&report, "findings").unwrap();

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec!["security=opus".into()],
                vec![format!("security={}", report.display())],
                false,
            );

            let record = read_polish_record(repo, branch).expect("marker reads");
            let attest = record.attest.expect("attest round-trips");
            assert_eq!(attest["security"].model.as_deref(), Some("opus"));
            assert_eq!(
                attest["security"].report.as_deref(),
                Some(report.display().to_string().as_str())
            );
        });
    }

    #[test]
    fn run_record_records_a_report_path_that_does_not_exist() {
        // A missing report file is a stderr note, never a rejection — the path
        // is provenance, and no code ever opens it.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-missing-repo";
            let branch = "feat/record-polish-attest-missing";

            let code = run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec!["security=/tmp/definitely-not-here-775.md".into()],
                false,
            );

            assert_eq!(code, 0, "a missing report must not fail the record");
            let record = read_polish_record(repo, branch).expect("marker reads");
            assert_eq!(
                record.attest.unwrap()["security"].report.as_deref(),
                Some("/tmp/definitely-not-here-775.md")
            );
        });
    }

    #[test]
    fn resolve_uses_explicit_overrides_without_touching_git() {
        // Explicit repo_root + branch supply both halves of the KEY without a
        // repository, so a bogus dir still resolves — the property the write
        // test below relies on. (`head_sha` still shells out, now against the
        // flag's value rather than `dir`; it is provenance, not key material,
        // and fails to empty here.) A non-repo `repo_root` is NOT a path #417
        // canonicalizes: there is no repo to resolve it against, so the literal
        // value stands.
        let resolved = resolve(
            "/nonexistent/not-a-repo",
            Some("/tmp/repo".into()),
            Some("main".into()),
        );
        let (repo_root, branch, _head) = resolved.expect("overrides resolve");
        assert_eq!(repo_root, "/tmp/repo");
        assert_eq!(branch, "main");
    }

    #[test]
    fn run_record_writes_marker_at_expected_path_with_parseable_content() {
        // Both `polish_marker` calls below resolve `marker_dir()` from the same
        // (overridden) environment, so the recomputed path matches what
        // `run_record` actually wrote — isolated to a tempdir so this never
        // lands in the real per-user marker directory (#302).
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-test-repo";
            let branch = "feat/record-polish-y";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("code".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            assert!(path.is_file(), "marker should exist at {path:?}");
            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["branch"], branch);
            assert_eq!(v["scope"], "code");
            // #467: the roster round-trips through the written marker.
            assert_eq!(v["arms"]["security"], "ran");
        });
    }

    #[test]
    fn run_record_merges_new_arms_into_existing_roster() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-merge-test-repo";
            let branch = "feat/record-polish-merge";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec![
                    "tests=ran".into(),
                    "security=skipped".into(),
                    "simplify=ran".into(),
                ],
                vec![],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["arms"]["tests"], "ran");
            assert_eq!(v["arms"]["simplify"], "ran");
            assert_eq!(v["arms"]["security"], "ran");
        });
    }

    #[test]
    fn run_record_with_no_new_arms_preserves_existing_roster_and_refreshes_scope() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-no-arm-test-repo";
            let branch = "feat/record-polish-no-arm";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["tests=ran".into()],
                vec![],
                vec![],
                false,
            );
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("docs".into()),
                vec![],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["arms"]["tests"], "ran");
            assert_eq!(v["scope"], "docs");
        });
    }

    #[test]
    fn run_record_without_arms_omits_roster_for_new_marker() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-rosterless-test-repo";
            let branch = "feat/record-polish-rosterless";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert!(v.get("arms").is_none());
        });
    }

    #[test]
    fn run_record_replaces_malformed_prior_marker_with_current_record() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-malformed-test-repo";
            let branch = "feat/record-polish-malformed";
            let path = polish_marker(repo, branch);
            write_marker(&path, "]]not json").unwrap();

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("code".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["scope"], "code");
            assert_eq!(v["arms"]["security"], "ran");
        });
    }

    #[test]
    fn run_record_duplicate_incoming_names_keep_last_value() {
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-duplicate-test-repo";
            let branch = "feat/record-polish-duplicate";
            let path = polish_marker(repo, branch);

            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["security=skipped".into(), "security=ran".into()],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["arms"]["security"], "ran");
        });
    }

    #[test]
    fn run_record_degrades_to_noop_when_repo_unresolved() {
        // No overrides, and `cargo test`'s cwd IS this real git checkout, so
        // `resolve` actually succeeds here (unlike the name implies) and
        // `run_record` really does write a marker — isolate it (#302), same as
        // every other write-path test in this module.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            run_record(
                None,
                None,
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
        });
    }

    // --- worktree-stable keying (cadence-hooks#324) ---

    /// Init a primary checkout with one commit (a real commit is required —
    /// `git worktree add` refuses an unborn branch), plus a `git` closure bound
    /// to that checkout.
    fn init_primary_with_commit(primary: &std::path::Path) {
        std::fs::create_dir_all(primary).unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(primary)
                .args(args)
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "init"]);
    }

    #[test]
    fn worktree_record_satisfies_primary_check_same_branch() {
        // RED (#324): a polish recorded from a LINKED WORKTREE must satisfy a
        // ship command run from the PRIMARY checkout on the same branch — the
        // marker key must be common-dir-based, not `--show-toplevel`-based
        // (a worktree's toplevel is its own path, not the shared repo).
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);

        let wt = tmp.path().join("wt");
        let git = |args: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&primary)
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "git {args:?} failed"
            );
        };
        git(&[
            "worktree",
            "add",
            "-q",
            wt.to_str().unwrap(),
            "-b",
            "feat/thing",
        ]);

        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            // Record from the WORKTREE path — the record side's own resolution.
            let wt_str = wt.to_str().unwrap().to_string();
            let (repo_root, branch, head_sha) =
                resolve(&wt_str, None, None).expect("worktree resolves repo/branch");
            assert_eq!(branch, "feat/thing");
            let content = marker_content(&branch, &head_sha, "full", &[], &BTreeMap::new(), false);
            write_marker(&polish_marker(&repo_root, &branch), &content).unwrap();

            // Free the branch from the worktree and check it out on the primary —
            // the realistic sequel to "finished the worktree, shipping from primary".
            git(&["worktree", "remove", "--force", wt.to_str().unwrap()]);
            git(&["checkout", "-q", "feat/thing"]);

            assert!(
                cadence_hooks_core::markers::polish_marker_present(
                    "gh pr create --title x",
                    Some(primary.to_str().unwrap()),
                ),
                "a polish marker recorded from a linked worktree must satisfy a ship \
                 command run from the primary checkout on the same branch"
            );
        });
    }

    #[test]
    fn explicit_repo_root_keys_the_same_marker_the_ship_gate_reads() {
        // RED (#417): `--repo-root` used to be the marker key VERBATIM, while
        // the default path keyed on the canonicalized `git_common_dir`. Passing
        // the linked worktree you are standing in — the most natural value —
        // therefore wrote a marker the ship gate could never read, and the
        // failure surfaced later as a nudge on a branch that HAD been polished.
        //
        // Resolving the flag through the same canonicalization makes it able to
        // locate the repo but not redefine the key, so all three spellings
        // below must produce one key: the worktree path, the primary path, and
        // no flag at all.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary");
        init_primary_with_commit(&primary);

        let wt = tmp.path().join("wt");
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&primary)
                .args([
                    "worktree",
                    "add",
                    "-q",
                    wt.to_str().unwrap(),
                    "-b",
                    "feat/x"
                ])
                .output()
                .unwrap()
                .status
                .success(),
            "git worktree add failed"
        );

        let wt_str = wt.to_str().unwrap().to_string();
        let primary_str = primary.to_str().unwrap().to_string();

        let key =
            |dir: &str, explicit: Option<String>| resolve(dir, explicit, None).expect("resolves").0;

        let via_flag_from_worktree = key(&primary_str, Some(wt_str.clone()));
        let via_flag_from_primary = key(&wt_str, Some(primary_str.clone()));
        let via_cwd = key(&wt_str, None);

        assert_eq!(
            via_flag_from_worktree, via_cwd,
            "--repo-root pointing at a linked worktree must key the same marker \
             the default cwd resolution writes"
        );
        assert_eq!(
            via_flag_from_primary, via_cwd,
            "--repo-root pointing at the primary checkout must key the same marker too"
        );

        // An explicit root re-bases the BRANCH too (security review, #417).
        // With `--repo-root <worktree>` and no `--branch`, the branch must come
        // from that worktree — not from the caller's cwd, which here is the
        // primary sitting on `main`. Splitting them credits `main` with a
        // polish it never had while the polished branch keeps getting nudged.
        let (_, branch_from_flag, _) =
            resolve(&primary_str, Some(wt_str.clone()), None).expect("resolves");
        assert_eq!(
            branch_from_flag, "feat/x",
            "--repo-root must re-base the branch resolution, not just the repo key"
        );

        // And the end-to-end property that actually matters: a marker recorded
        // with `--repo-root <worktree>` satisfies a ship run from the primary.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let (repo_root, branch, head_sha) =
                resolve(&primary_str, Some(wt_str.clone()), Some("feat/x".into()))
                    .expect("resolves");
            write_marker(
                &polish_marker(&repo_root, &branch),
                &marker_content(&branch, &head_sha, "code", &[], &BTreeMap::new(), false),
            )
            .unwrap();

            assert!(
                cadence_hooks_core::markers::polish_marker_present(
                    "gh pr create --title x",
                    Some(&wt_str),
                ),
                "a marker recorded via --repo-root must be readable by the ship gate"
            );
        });
    }
}
