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
//! Exit codes say whether a marker exists, because that is the only fact a
//! caller can act on (cadence-hooks#801):
//!
//! - **0** — a marker was written.
//! - **1** — the environment prevented the record (not a git repo, detached
//!   `HEAD`, marker write failed). Nothing was written.
//! - **2** — a usage error: a `--scope` outside the closed set, or a `--branch`
//!   git itself would refuse.
//!
//! One case deliberately still exits **0** without a usable key: an explicit
//! `--repo-root` naming no git repository, *together with* an explicit
//! `--branch`. Both halves are then caller-supplied literals, so nothing is
//! unresolved and a marker really is written — over a literal key the pre-PR
//! gate matches only if it is handed the same literal (cadence-hooks#417). That
//! is the test-override affordance the suite depends on, and the command warns
//! on stderr when it takes that path. With `--branch` omitted the same root is
//! a [`Unresolved::NotARepo`] and exits 1.
//!
//! Non-zero is safe here because this is a **CLI action, not a hook**: no tool
//! call is gated on this exit, so ADR-0001's "a guard's failure must never block
//! the user" does not apply. Exiting 0 having recorded nothing was the defect —
//! it made `record-polish || handle` inert and left the gate nudging a branch
//! the operator believed was recorded. The usage arm matches the `redact-scan`
//! CLI convention (cadence-hooks#775): the caller mis-spelled the record, and
//! storing it anyway lands a marker the gate silently misreads.

use cadence_hooks_core::branch_diff::{WorkingTreeDigest, working_tree_digest};
use cadence_hooks_core::gitstate::GitState;
use cadence_hooks_core::markers::{
    ArmAttestation, MAX_REPORT_BYTES, MAX_TOKEN_BYTES, is_arm_token, is_report_path, polish_marker,
    read_polish_record, write_marker,
};
use cadence_hooks_core::shell::git_command;
use cadence_hooks_core::time::utc_timestamp;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// Why [`resolve`] could not produce a marker key. The two conditions have
/// different fixes and the single conflated message (cadence-hooks#801) sent a
/// reader checking whether they were in a git repo at all.
#[derive(Debug, PartialEq, Eq)]
enum Unresolved {
    NotARepo,
    DetachedHead,
}

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
/// either can't be resolved this returns [`Unresolved`] naming which one, and
/// the caller records nothing and exits 1 (cadence-hooks#801).
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
) -> Result<(String, String, String), Unresolved> {
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
                // Debug-escaped, like every other value this module echoes: a
                // `--repo-root` is caller-supplied free text, and a filesystem
                // path can carry newlines and control bytes.
                eprintln!(
                    "cadence-hooks record-polish: --repo-root {explicit:?} is not a git \
                     repository — any marker will use that literal key, which the \
                     pre-PR gate will not match unless it was given the same literal."
                );
                explicit
            })
        })
        .or_else(|| git_state().map(|state| state.git_common_dir.to_string_lossy().into_owned()))
        .ok_or(Unresolved::NotARepo)?;
    // Spelled out rather than chained: the earlier `?` over an `Option`
    // collapsed "no repo" and "repo, but no branch" into one verdict, and the
    // two have different fixes (cadence-hooks#801). The inner `None` arm is
    // load-bearing — `--repo-root <non-repo>` with no `--branch` is a
    // `NotARepo`, not a detached `HEAD`.
    let branch = match branch {
        Some(explicit) => explicit,
        None => match git_state() {
            Some(state) => state.branch.ok_or(Unresolved::DetachedHead)?,
            None => return Err(Unresolved::NotARepo),
        },
    };
    // Polish does not commit (SKILL.md), so this is the pre-polish base SHA — a
    // provenance breadcrumb for CP2, never an exact-match key. Empty when the
    // repo has no HEAD yet. Read last, so a resolution that will not produce a
    // marker never spawns a `git` process whose result is discarded.
    let head_sha = git_command(&base, &["rev-parse", "HEAD"]).unwrap_or_default();
    Ok((repo_root, branch, head_sha))
}

/// Parse repeatable `--arm name=state` values into the roster, dropping (and
/// naming, on stderr, Debug-escaped) any value that is not `name=state` with
/// both halves in `[A-Za-z0-9_-]+` — fail-open, the rest of the record still
/// lands (ADR-0001). The charset bound is what keeps the roster safe to echo:
/// the verdict line and the marker JSON both carry these strings, so ANSI or
/// control bytes never survive to either surface.
fn parse_arms(raw: &[String]) -> Vec<(String, String)> {
    parse_keyed(raw, "--arm", is_arm_token)
}

/// The value-constraint clause a malformed-`{flag}` diagnostic names — **per
/// flag** (cadence-hooks#775 I4): `--arm-report`'s value rule (printable ASCII,
/// ≤[`MAX_REPORT_BYTES`] bytes) differs from the arm/arm-model rule
/// ([A-Za-z0-9_-], ≤[`MAX_TOKEN_BYTES`] bytes), and the earlier single shared
/// message told an operator whose 600-byte or non-ASCII path dropped that the
/// limit was 64 bytes. Each clause restores the worked example the
/// generalization had dropped.
fn keyed_value_constraint(flag: &str) -> String {
    match flag {
        "--arm-report" => format!(
            "name=path, name in [A-Za-z0-9_-] and at most {MAX_TOKEN_BYTES} bytes, \
             path printable ASCII and at most {MAX_REPORT_BYTES} bytes, \
             e.g. security=/tmp/review.md"
        ),
        "--arm-model" => format!(
            "name=family, both in [A-Za-z0-9_-] and at most {MAX_TOKEN_BYTES} bytes, \
             e.g. security=opus"
        ),
        _ => format!(
            "name=state, both in [A-Za-z0-9_-] and at most {MAX_TOKEN_BYTES} bytes, \
             e.g. security=ran"
        ),
    }
}

/// Parse repeatable `name=value` flags, dropping (and naming, on stderr,
/// Debug-escaped) anything whose name is not an arm token or whose value fails
/// `value_ok` — fail-open, the rest of the record still lands (ADR-0001). The
/// diagnostic names the *flag's own* value constraint via
/// [`keyed_value_constraint`].
fn parse_keyed(raw: &[String], flag: &str, value_ok: fn(&str) -> bool) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((name, value)) if is_arm_token(name.trim()) && value_ok(value.trim()) => {
                Some((name.trim().to_string(), value.trim().to_string()))
            }
            _ => {
                eprintln!(
                    "cadence-hooks record-polish: ignoring malformed {flag} {entry:?} (expected {})",
                    keyed_value_constraint(flag)
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
    parse_keyed(raw, "--arm-model", is_arm_token)
}

/// Parse repeatable `--arm-report name=path` values (cadence-hooks#775).
///
/// The path is recorded verbatim, existence unexamined: the record may
/// legitimately precede the report's write, and no code ever opens the path or
/// echoes its contents. An earlier `.exists()` probe printed a distinguishable
/// stderr note for an absent path — a filesystem-existence oracle in the agent
/// transcript, load-bearing for nothing, removed in the #775 security review.
fn parse_arm_report(raw: &[String]) -> Vec<(String, String)> {
    parse_keyed(raw, "--arm-report", is_report_path)
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
    // A typed setter per flag rather than an `if flag == "--arm-model"` string
    // compare (cadence-hooks#775 N5): a mistyped flag can no longer silently
    // route every model into `report`.
    type Setter = fn(&mut ArmAttestation, String);
    let mut apply = |flag: &str, pairs: Vec<(String, String)>, set: Setter| {
        for (name, value) in pairs {
            if !stated(&name) {
                eprintln!(
                    "cadence-hooks record-polish: ignoring {flag} {name}={value:?} — no \
                     matching --arm {name}=<state> in this invocation, and an attestation \
                     only ever describes the run stated beside it."
                );
                continue;
            }
            set(merged.entry(name).or_default(), value);
        }
    };
    apply("--arm-model", models, |entry, value| {
        entry.model = Some(value)
    });
    apply("--arm-report", reports, |entry, value| {
        entry.report = Some(value)
    });
    // Prune all-`None` entries (cadence-hooks#775 N4): `read_attest` keeps an
    // entry whose model/report both failed validation, and carrying it forward
    // would serialize `"attest":{"security":{}}`, which reads to an auditor as
    // "an attestation was attempted". An empty entry is no attestation.
    merged.retain(|_, a| a.model.is_some() || a.report.is_some());
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
    digest: Option<&WorkingTreeDigest>,
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
    if let Some(digest) = digest {
        v["diff_digest"] = json!({
            "base": digest.base,
            "digest": digest.digest,
            "files": digest.files,
        });
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
///
/// `repo_root` **and** `branch` are Debug-escaped, matching the rest of this
/// module: both are caller-supplied free text (a `--repo-root` path, a
/// `--branch` name), and either can carry newlines and control bytes.
/// `branch` was the one raw value here until cadence-hooks#801 — a newline in
/// it forged a second `recorded polish marker:` line, which is the exact string
/// a caller greps for when the exit code cannot be trusted.
///
/// The marker **path** is deliberately left unescaped. It is not caller-supplied
/// through a flag: its filename is a hash, and its directory comes from the
/// operator's own `CADENCE_MARKER_DIR`, so the only way to get a control byte
/// into it is to put one in your own environment. It is also the one field
/// callers consume programmatically — a probe reads this path to confirm the
/// gate is satisfied — and escaping it would change that contract for a value
/// no untrusted party controls.
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
        "recorded polish marker: {} ({repo_root:?}@{branch:?} scope={scope}{roster})",
        path.display()
    )
}

/// Write the branch-scoped polish marker, resolving repo/branch/HEAD from the
/// current directory unless overridden. Returns the process exit code.
///
/// **0** when a marker was written; **1** when the environment prevented the
/// record (not a repo, detached `HEAD`, write failed) and nothing was written;
/// **2** on a usage error — an invalid `--scope`, or a `--branch` carrying
/// control characters. See the module docs for why non-zero is safe here.
///
/// A usage error is the caller mis-spelling the record rather than the
/// environment degrading, and recording it anyway would land a marker the gate
/// silently misreads (cadence-hooks#775).
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

    // A branch git itself would refuse keys a marker no `polish_marker_present`
    // lookup can ever produce — the cadence-hooks#417 failure (a success verdict
    // over a key nothing will read), reached through a different flag. Bounded
    // to control characters and the empty string on purpose: a full mirror of
    // git's ref grammar would be a maintained duplicate whose every wrong rule
    // is a false block on the mechanism the whole polish gate depends on.
    //
    // `is_ascii_control`, not `is_control`, so this matches git exactly and
    // refuses nothing git would accept. Measured 2026-09-04: git refuses C0
    // (`git check-ref-format --branch $'ev\033il'`) and DEL, but ACCEPTS the C1
    // block — `git branch` really creates a branch containing U+0085 or U+009B,
    // which Unicode `Cc` (`is_control`) would have false-blocked.
    //
    // Rejecting C1 is not needed for terminal safety, which is the tempting
    // reason to widen it: the verdict line Debug-escapes the branch, and
    // `{:?}` renders U+009B as `\u{9b}`, so CSI never reaches a terminal
    // whether this arm refuses it or not. Escaping is the containment; this
    // arm exists only to refuse a key no `polish_marker_present` lookup can
    // ever match.
    if let Some(value) = branch.as_deref()
        && (value.is_empty() || value.chars().any(|c| c.is_ascii_control()))
    {
        eprintln!(
            "cadence-hooks record-polish: invalid --branch {value:?} (a branch name \
             carries no control characters — git refuses one itself) — no marker recorded."
        );
        return 2;
    }

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| ".".to_string());

    // The checkout the digest is taken from is the same one `resolve` reads —
    // an explicit `--repo-root` re-bases the whole resolution (#417), and a
    // digest of the *caller's* tree beside another checkout's branch would be
    // provenance about the wrong thing.
    let work_dir = repo_root.clone().unwrap_or_else(|| cwd.clone());

    // `work_dir` is the directory resolution actually reads (it honors
    // `--repo-root`), Debug-escaped for the same reason `repo_root` is above.
    let (repo_root, branch, head_sha) = match resolve(&cwd, repo_root, branch) {
        Ok(resolved) => resolved,
        Err(Unresolved::DetachedHead) => {
            eprintln!(
                "cadence-hooks record-polish: HEAD is detached in {work_dir:?} — the polish \
                 marker is keyed on (repo, branch) and a detached HEAD has no branch to key \
                 it on. No marker recorded. Re-attach (git checkout <branch>) or pass \
                 --branch <name>."
            );
            return 1;
        }
        Err(Unresolved::NotARepo) => {
            eprintln!(
                "cadence-hooks record-polish: {work_dir:?} is not inside a git repository \
                 — no marker recorded."
            );
            return 1;
        }
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
    // The gate READS this (cadence-hooks#874) — unlike `head_sha`, which stays
    // reader-less because it is pre-polish by construction: polish never
    // commits, so HEAD moves on every honest polish → commit → ship path.
    // The digest does not move there. It is invariant across committing
    // polish's own fixes and across merging an advanced `origin/main` up (the
    // base moves, the digest does not), and it moves on a real new commit
    // touching code — which is the case the gate reports.
    let digest = working_tree_digest(&work_dir);
    let content = marker_content(
        &branch,
        &head_sha,
        &scope,
        &arms,
        &attest,
        digest.as_ref(),
        fresh,
    );
    let path = polish_marker(&repo_root, &branch);
    match write_marker(&path, &content) {
        Ok(()) => {
            println!(
                "{}",
                record_verdict(&repo_root, &branch, &scope, &arms, &path)
            );
            0
        }
        Err(e) => {
            eprintln!(
                // Deliberately does NOT promise a nudge: a marker from an
                // earlier pass on this same (repo, branch) may still be on
                // disk, in which case the gate reads *that* one and stays
                // quiet. All this invocation can honestly claim is that its
                // own record did not land.
                "cadence-hooks record-polish: marker write failed ({e}) — this record did \
                 not land; any marker from an earlier pass on this branch may still be \
                 present."
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cadence_hooks_core::markers::polish_marker;
    use cadence_hooks_core::test_builders::with_marker_dir;

    #[test]
    fn marker_content_is_parseable_json_with_all_fields() {
        let content = marker_content(
            "feat/x",
            "abc123",
            "full",
            &[],
            &BTreeMap::new(),
            None,
            false,
        );
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
        let content = marker_content(
            "feat/x",
            "abc123",
            "code",
            &arms,
            &BTreeMap::new(),
            None,
            false,
        );
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["arms"]["security"], "ran");
        assert_eq!(v["arms"]["tests"], "skipped");
        assert_eq!(v["scope"], "code", "existing fields unchanged");
    }

    #[test]
    fn keyed_value_constraint_states_the_right_limit_per_flag() {
        // #775 I4 RED: one shared message named the arm/arm-model rule for all
        // three flags, so an operator whose 600-byte or non-ASCII
        // `--arm-report` path dropped was told the limit was 64 bytes and
        // [A-Za-z0-9_-]. The report clause must name its own constraint, and
        // each clause restores a worked example.
        let report = keyed_value_constraint("--arm-report");
        assert!(report.contains("printable ASCII"), "{report}");
        assert!(
            report.contains(&MAX_REPORT_BYTES.to_string()),
            "the report clause must name the 512-byte limit: {report}"
        );
        assert!(
            report.contains("security=/tmp/review.md"),
            "restores the report example: {report}"
        );

        let arm = keyed_value_constraint("--arm");
        assert!(
            arm.contains(&MAX_TOKEN_BYTES.to_string()),
            "the arm clause names the 64-byte limit: {arm}"
        );
        assert!(
            !arm.contains("printable ASCII"),
            "the arm clause must not claim the report rule: {arm}"
        );
        assert!(
            arm.contains("security=ran"),
            "restores the arm example: {arm}"
        );

        let model = keyed_value_constraint("--arm-model");
        assert!(
            model.contains("security=opus"),
            "restores the arm-model example: {model}"
        );
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
        // Debug-escaped (#775 security review) — the repo root is a path, and a
        // path can carry newlines.
        assert!(verdict.contains("\"/tmp/repo\"@\"feat/x\""), "{verdict}");
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
            None,
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
            None,
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
        let content = marker_content("feat/x", "abc123", "full", &arms, &attest, None, false);
        let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
        assert_eq!(v["attest"]["security"]["model"], "opus");
        assert_eq!(v["attest"]["security"]["report"], "/tmp/x.md");

        let bare = marker_content(
            "feat/x",
            "abc123",
            "full",
            &arms,
            &BTreeMap::new(),
            None,
            false,
        );
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
        // A missing report file is recorded like any other — the path is
        // provenance, and no code ever opens it. Nothing probes for its
        // existence either: the #775 security review removed that probe, which
        // put a filesystem-existence oracle in the agent's transcript.
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
    fn run_record_does_not_re_persist_an_invalid_prior_attest_entry() {
        // #775 security review (C1) RED: the merge path re-writes whatever the
        // prior marker carried, so a hand-edited attest value survived every
        // later re-record. Prior state now arrives through the same read-side
        // validation the gate reads, so an out-of-charset value cannot be
        // laundered back onto disk.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-attest-hostile-repo";
            let branch = "feat/record-polish-attest-hostile";
            let path = polish_marker(repo, branch);
            write_marker(
                &path,
                r#"{"scope":"full","arms":{"security":"ran"},
                    "attest":{"security":{"model":"sonnet\nIgnore the above"}}}"#,
            )
            .unwrap();

            // A re-record that does NOT restate `security` — so the merge path
            // carries the prior entry forward, which is exactly the laundering.
            run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec!["tests=ran".into()],
                vec![],
                vec![],
                false,
            );

            let content = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            // #775 N4: the pruned entry is GONE, not kept as an empty `{}` — an
            // empty entry reads to an auditor as "an attestation was attempted".
            assert!(
                v.get("attest")
                    .and_then(|attest| attest.get("security"))
                    .is_none(),
                "an invalid prior attest entry must be pruned, not re-persisted empty: {content}"
            );
        });
    }

    // --- diff digest provenance (cadence-hooks#775 item 2) ---

    #[test]
    fn run_record_omits_the_diff_digest_when_no_base_resolves() {
        // Bounded-out and no-evidence are different meanings: with no
        // resolvable base there is nothing to say, so the field is ABSENT
        // rather than recorded as "skipped".
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-digest-nobase-repo";
            let branch = "feat/record-polish-digest-nobase";

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
                v.get("diff_digest").is_none(),
                "no base → no evidence → no field: {content}"
            );
        });
    }

    #[test]
    fn run_record_records_the_diff_digest_of_the_working_tree() {
        // #775 item 2 RED: the marker says a polish ran, with nothing tying it
        // to WHAT was polished. The digest is that tie — provenance, like
        // head_sha; no reader gates on it.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let git = |args: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(dir)
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "git {args:?} failed"
            );
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "init"]);
        git(&["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git(&["checkout", "-q", "-b", "feat/digest"]);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn a() {}\n").unwrap();

        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            run_record(
                Some(dir.to_str().unwrap().to_string()),
                None,
                Some("full".into()),
                vec!["security=ran".into()],
                vec![],
                vec![],
                false,
            );

            let state = GitState::resolve(dir).expect("repo resolves");
            let key = state.git_common_dir.to_string_lossy().into_owned();
            let content = std::fs::read_to_string(polish_marker(&key, "feat/digest")).unwrap();
            let v: serde_json::Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["diff_digest"]["files"], 1);
            assert!(
                v["diff_digest"]["digest"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:"),
                "{content}"
            );
            assert!(
                !v["diff_digest"]["base"].as_str().unwrap().is_empty(),
                "the base commit is recorded beside the digest: {content}"
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
    fn run_record_records_from_an_attached_checkout() {
        // Replaces `run_record_degrades_to_noop_when_repo_unresolved`
        // (cadence-hooks#801), which asserted nothing and read its branch from
        // the *ambient* cwd. That made it environment-dependent in the worst
        // direction: CI checks out a detached HEAD, so on CI it silently
        // exercised the `DetachedHead` arm while claiming to cover the happy
        // path — and any assertion added to it would have gone red there.
        // This builds its own attached checkout, so the branch it resolves is
        // one the test created.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        init_primary_with_commit(&repo);

        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let code = run_record(
                Some(repo.to_string_lossy().into_owned()),
                None,
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 0, "an attached checkout records");
            // Also the positive control for `marker_dir_has_any_file`: the
            // "no marker was written" assertions elsewhere in this section are
            // only worth anything if this helper can return `true` at all.
            assert!(
                marker_dir_has_any_file(marker_tmp.path()),
                "a successful record must leave a file the helper can see"
            );
        });
    }

    // --- exiting non-zero when nothing was recorded (cadence-hooks#801) ---

    #[test]
    fn resolve_distinguishes_a_detached_head_from_a_non_repo() {
        // RED (#801): does not compile against the old `Option` return — the
        // two conditions shared one `None` and one stderr line, so a reader
        // with a detached HEAD went checking whether they were in a repo.
        assert_eq!(
            resolve("/nonexistent/not-a-repo-801", None, None),
            Err(Unresolved::NotARepo)
        );

        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        init_primary_with_commit(&repo);
        detach_head(&repo);
        let repo_str = repo.to_string_lossy().into_owned();
        assert_eq!(
            resolve(&repo_str, None, None),
            Err(Unresolved::DetachedHead)
        );
    }

    #[test]
    fn resolve_reports_not_a_repo_for_an_explicit_non_repo_root() {
        // The inner `None` arm of the three-way match: `--repo-root <non-repo>`
        // with no `--branch` is a missing repository, not a detached HEAD.
        assert_eq!(
            resolve(
                "/nonexistent/cwd-801",
                Some("/nonexistent/explicit-801".into()),
                None
            ),
            Err(Unresolved::NotARepo)
        );
    }

    #[test]
    fn run_record_exits_non_zero_and_records_nothing_on_a_detached_head() {
        // RED (#801 case B): returned 0 with an empty stdout and no marker, so
        // `record-polish || handle` was inert and the caller believed the
        // polish was recorded.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        init_primary_with_commit(&repo);
        detach_head(&repo);

        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let code = run_record(
                Some(repo.to_string_lossy().into_owned()),
                None,
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 1, "a detached HEAD records nothing, so it is not 0");
            assert!(
                !marker_dir_has_any_file(marker_tmp.path()),
                "no marker may be written for a detached HEAD"
            );
        });
    }

    #[test]
    fn record_verdict_debug_escapes_the_branch() {
        // RED (#801 case E): the raw ESC survived to stdout — `cat -v` showed
        // `@evil^[[31mRED` — while every other value on the line was escaped.
        let branch = "evil\u{1b}[31m";
        let path = polish_marker("/tmp/repo", branch);
        let verdict = record_verdict("/tmp/repo", branch, "full", &[], &path);
        assert!(
            !verdict.contains('\u{1b}'),
            "no raw control byte may reach the terminal: {verdict:?}"
        );
        assert!(
            verdict.contains("\\u{1b}"),
            "the branch must appear Debug-escaped: {verdict:?}"
        );
    }

    #[test]
    fn run_record_rejects_a_control_byte_branch_as_a_usage_error() {
        // RED (#801 case G): exited 0 and wrote a marker, while the newline
        // forged a second `recorded polish marker:` line on stdout — the exact
        // string the issue records callers grepping for.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let branch = "a\nrecorded polish marker: fake";
            let code = run_record(
                Some("/tmp/record-polish-801-forge".into()),
                Some(branch.into()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 2, "a branch git itself refuses is a usage error");
            assert!(
                !marker_dir_has_any_file(marker_tmp.path()),
                "no marker may be written under any key for a rejected --branch"
            );
        });
    }

    #[test]
    fn run_record_rejects_an_empty_branch_as_a_usage_error() {
        // The other half of the same arm: an empty `--branch` keys a marker no
        // lookup can produce, the #417 failure through a different flag.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let code = run_record(
                Some("/tmp/record-polish-801-empty".into()),
                Some(String::new()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 2, "an empty --branch is a usage error");
            assert!(!marker_dir_has_any_file(marker_tmp.path()));
        });
    }

    #[test]
    fn run_record_accepts_a_c1_branch_because_git_does() {
        // The false-block control for the arm above: the rejection is
        // `is_ascii_control`, not Unicode `Cc`. Measured 2026-09-04 — git
        // really creates a branch containing U+0085, so refusing one here
        // would break a legitimate record. Terminal safety does not depend on
        // this arm: the verdict Debug-escapes the branch either way, which the
        // second assertion pins.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-801-c1";
            let branch = "feat/ev\u{85}il";
            let code = run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 0, "a C1 branch is git-legal and must record");
            assert!(polish_marker(repo, branch).is_file());

            let verdict = record_verdict(repo, branch, "full", &[], &polish_marker(repo, branch));
            assert!(
                !verdict.contains('\u{85}'),
                "escaping, not the charset bound, is what keeps C1 off the terminal: {verdict:?}"
            );
        });
    }

    #[test]
    fn run_record_exits_non_zero_when_the_marker_write_fails() {
        // RED (#801): the write-failure arm fell through to a bare `0`, so a
        // failed write reported success exactly as the detached-HEAD path did.
        let marker_tmp = tempfile::tempdir().unwrap();
        with_marker_dir(marker_tmp.path(), || {
            let repo = "/tmp/record-polish-801-writefail";
            let branch = "feat/record-polish-801";
            // A directory at the marker's own path: `write_marker`'s rename
            // cannot replace it, so the write fails without any permission or
            // filesystem trickery.
            let path = polish_marker(repo, branch);
            std::fs::create_dir_all(&path).unwrap();

            let code = run_record(
                Some(repo.into()),
                Some(branch.into()),
                Some("full".into()),
                vec![],
                vec![],
                vec![],
                false,
            );
            assert_eq!(code, 1, "a failed write recorded nothing, so it is not 0");
            assert!(path.is_dir(), "the blocker must still be what it was");
        });
    }

    /// Put an existing checkout on a detached `HEAD`.
    fn detach_head(repo: &std::path::Path) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["checkout", "-q", "--detach", "HEAD"])
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git checkout --detach failed");
    }

    /// Whether any regular file exists anywhere under the marker directory —
    /// the assertion "no marker was written under *any* key", which a single
    /// recomputed path cannot make.
    ///
    /// Panics rather than returning `false` on an unreadable directory: a
    /// swallowed read error would make every "no marker was written" assertion
    /// pass for the wrong reason, which is the fallback-instead-of-assertion
    /// shape these tests exist to rule out.
    fn marker_dir_has_any_file(dir: &std::path::Path) -> bool {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("marker dir {dir:?} must be readable to assert on it: {e}"));
        entries.flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                marker_dir_has_any_file(&path)
            } else {
                true
            }
        })
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
            let content = marker_content(
                &branch,
                &head_sha,
                "full",
                &[],
                &BTreeMap::new(),
                None,
                false,
            );
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
                &marker_content(
                    &branch,
                    &head_sha,
                    "code",
                    &[],
                    &BTreeMap::new(),
                    None,
                    false,
                ),
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
