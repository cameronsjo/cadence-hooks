//! The confirm tier: block the first attempt at an action, pass a deliberate
//! second one (cameronsjo/cadence-hooks#1658).
//!
//! A guard in this tier asks "are you sure?" instead of stopping the session.
//! The first attempt blocks with the guard's reason and a line saying a second
//! attempt will pass. The next attempt at the same action, from the same
//! session and agent, within [`CONFIRM_TTL`], passes once and is recorded in
//! `bypasses.jsonl` with kind `confirmed`. The threat model is a cooperative
//! model making an honest mistake (cadence-ecosystem ADR-0046): a retry is the
//! decision the tier asks for, so nothing here resists a model that retries on
//! purpose. What it does prevent is a pass reaching anything that did not make
//! the decision: another session, another agent, or a different action.
//!
//! # The key
//!
//! `hook`, `session_id`, `agent_id` (empty on the main thread) and a
//! normalized action the guard supplies, joined with U+001F and hashed with
//! SHA-256. The digest names the marker file and is repeated inside it, so a
//! file left under another key never counts. The action takes one of two
//! forms, and [`Retry`] tells the armed line which:
//!
//! - what the guard read ([`Retry::SameAction`]): an `enforce-worktree` Edit
//!   or Write keys on the judged repo and the file, which the payload names
//!   directly;
//! - the whole command, normalized only for spaces and tabs
//!   ([`whole_command_action`], [`Retry::SameCommand`]), beside what the
//!   guard read: `guard-op-vault-scan`, `guard-held-close`, and an
//!   `enforce-worktree` Bash commit. An earlier segment (an `export`, a
//!   sign-in, a link) can change the target without changing what the guard
//!   reads, so no list of selectors is complete (cameronsjo/cadence-hooks
//!   #1659 rounds 1, 2 and review 4).
//!
//! # One tool call, several processes
//!
//! A hook wired twice under one matcher spawns two processes for one tool
//! call, and both read the marker. The marker therefore records the
//! `tool_use_id` of the call that wrote it, in one of two states:
//!
//! - `pending`: the call that blocked. A process of the same call sees its own
//!   id and blocks too, leaving the marker alone; a process of a later call
//!   passes and rewrites it as `consumed` by that call.
//! - `consumed`: the call that passed. A process of the same call passes too
//!   (it is the same retry); any later call arms a new `pending` and blocks.
//!
//! Every write is idempotent for the processes of one call, so sibling races
//! end in the same verdict for all of them. Single use falls out of the second
//! state: after a pass, the next different call blocks again.
//!
//! The verdict is shared; the ledger row is not. Two processes of the passing
//! call can both read `pending` and both write `consumed`, so the one that
//! records the pass is picked by an exclusive create of a claim file named for
//! the key and the call (`confirm-<digest>.row-<call digest>`). The winner
//! returns [`Gate::Passed`], every other process [`Gate::PassedSibling`]. The
//! next armed attempt removes the spent claim, so at most one claim file stays
//! per key. One window is left: a sibling of the passing call that is still
//! running after the next call has armed (and so removed the claim) records a
//! second row. Hooks of one tool call finish before the next call starts, so
//! this needs a sibling delayed past a whole tool call.
//!
//! # What a row does not say
//!
//! Each hook decides in its own process (or as one member of a `group`), so a
//! confirm-tier guard cannot see what the other hooks on the same tool call
//! decide. A `confirmed` row therefore means this guard let the action
//! through, not that the action ran: another hook can still block the call,
//! and the confirmation is spent either way.
//!
//! # Fail directions
//!
//! A pass needs a recorded decision, so every doubt blocks, and every block
//! that cannot be confirmed says so, so the model is never told to retry into
//! a wall:
//!
//! | Condition | Verdict | Message |
//! |---|---|---|
//! | No `session_id` | block | a retry will block too |
//! | No `tool_use_id` | block | a retry will block too |
//! | Marker directory not private (fell back to the shared temp dir) | block, marker never read or written | a retry will block too |
//! | Marker unreadable, a symlink, malformed, another key, expired, or stamped in the future | treated as absent: a new `pending` is written | retry passes |
//! | `pending` or `consumed` write fails | block | a retry will block too |
//!
//! A failed write is the case that could loop: the model is told to retry,
//! the retry finds no marker, and blocks again with the same promise. The
//! message instead names the failure and points at the guard's other route or
//! the operator, and no write failure ever produces a pass.

use crate::markers::{create_exclusive, private_marker_dir, write_marker};
use crate::{BypassKind, BypassProvenance, CheckResult, HookInput};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a blocked attempt stays confirmable.
pub const CONFIRM_TTL: Duration = Duration::from_secs(10 * 60);

/// How far in the future a marker stamp may sit (clock adjustments between
/// two hook processes) before it reads as invalid.
const FUTURE_SKEW_SECS: i64 = 60;

/// The bypass mechanism recorded for a confirmed pass.
pub const MECHANISM: &str = "confirm-retry";

/// First line of every confirm marker.
const HEADER: &str = "cadence-confirm v1";

/// The line a hard block adds where its own escape needs the operator's hands
/// at a computer (cameronsjo/cadence-hooks#1658 part 3).
pub const OPERATOR_HANDOFF: &str = "If the operator is away from a keyboard (on a phone, \
     say), do not wait on that step: stop, and tell them in chat what was blocked, why, and \
     what they can approve.";

/// Why a block cannot be confirmed this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// The payload carried no `session_id`, so a pass could not be kept to it.
    NoSession,
    /// The payload carried no `tool_use_id`, so a retry cannot be told from a
    /// sibling process of the blocked call.
    NoToolCallId,
    /// The marker directory fell back to a shared, writable one.
    SharedMarkerDir,
    /// The marker could not be written.
    WriteFailed,
}

impl Unavailable {
    /// The clause the block message carries.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoSession => "this payload has no session id to keep a confirmation to",
            Self::NoToolCallId => "this payload has no tool-call id to tell a retry apart",
            Self::SharedMarkerDir => {
                "the confirmation would sit in a shared directory, which cadence-hooks does not trust"
            }
            Self::WriteFailed => "the confirmation could not be recorded",
        }
    }
}

/// What one attempt at a confirm-tier action gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// A deliberate second attempt: allow, and record this provenance.
    Passed(BypassProvenance),
    /// Another process of the tool call that already passed (a guard wired
    /// twice under one matcher): allow, and record nothing, so one
    /// confirmation writes one ledger row.
    PassedSibling,
    /// A first attempt (or a sibling process of one): block, and say a retry
    /// will pass.
    Armed,
    /// Block, and say a retry will block too.
    Unavailable(Unavailable),
}

/// The marker states (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Pending,
    Consumed,
}

impl State {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
        }
    }
}

/// A parsed marker: its state, the tool call that wrote it, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    state: State,
    call: String,
    at: i64,
}

/// What the pure decision tells the I/O wrapper to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Rewrite the marker as consumed by this call, then pass.
    Pass,
    /// A sibling process of the blocked call: block, write nothing.
    SameCall,
    /// Write a new pending marker for this call, then block.
    Arm,
}

/// The key digest for one action. Pure.
fn key_digest(hook: &str, session: &str, agent: &str, action: &str) -> String {
    use sha2::{Digest, Sha256};
    let key = [hook, session, agent, action].join("\u{1f}");
    format!("{:x}", Sha256::digest(key.as_bytes()))
}

/// Parse marker text. `None` for anything that is not a well-formed record
/// under `digest`. Pure.
fn parse_record(text: &str, digest: &str) -> Option<Record> {
    let mut lines = text.lines();
    if lines.next()? != HEADER || lines.next()? != digest {
        return None;
    }
    let state = match lines.next()? {
        "pending" => State::Pending,
        "consumed" => State::Consumed,
        _ => return None,
    };
    let call = lines.next()?.to_string();
    let at = lines.next()?.parse::<i64>().ok()?;
    if call.is_empty() || lines.next().is_some() {
        return None;
    }
    Some(Record { state, call, at })
}

/// Render a marker. Pure.
fn render_record(digest: &str, record: &Record) -> String {
    format!(
        "{HEADER}\n{digest}\n{}\n{}\n{}\n",
        record.state.as_str(),
        record.call,
        record.at
    )
}

/// The decision for one attempt, given what the marker held. Pure.
fn decide(record: Option<&Record>, call: &str, now: i64, ttl_secs: i64) -> Step {
    let Some(record) = record else {
        return Step::Arm;
    };
    let fresh = record.at <= now + FUTURE_SKEW_SECS && now - record.at <= ttl_secs;
    if !fresh {
        return Step::Arm;
    }
    match (&record.state, record.call == call) {
        (State::Pending, true) => Step::SameCall,
        (State::Pending, false) => Step::Pass,
        (State::Consumed, true) => Step::Pass,
        (State::Consumed, false) => Step::Arm,
    }
}

/// Read a marker without following a symlink. Anything but a readable regular
/// file is `None`.
fn read_marker(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// The marker path for a key digest in the private marker directory.
fn marker_path(dir: &Path, digest: &str) -> PathBuf {
    dir.join(format!("confirm-{digest}"))
}

/// The file whose exclusive creation decides which process of `call` writes
/// the ledger row for a confirmation under `digest`. The call id is hashed so
/// the name holds only hex whatever the id's characters.
fn row_claim_path(dir: &Path, digest: &str, call: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let call_digest = format!("{:x}", Sha256::digest(call.as_bytes()));
    dir.join(format!("confirm-{digest}.row-{}", &call_digest[..16]))
}

/// A tool-call id the record format can carry: non-empty, with no whitespace
/// or control character (the record is line-based, so a newline in the id
/// would leave a marker that never parses and a retry that never pairs).
fn usable_call_id(id: &str) -> bool {
    !id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Judge one attempt at `action` for `hook`, reading and writing its marker.
///
/// `action` is the guard's normalized form of what it blocked; two attempts
/// pair up only when it is identical.
#[must_use]
pub fn gate(input: &HookInput, hook: &str, action: &str) -> Gate {
    gate_at(input, hook, action, crate::time::now_unix_seconds())
}

/// [`gate`] at a given clock reading, so tests can pin expiry.
#[must_use]
pub fn gate_at(input: &HookInput, hook: &str, action: &str, now: i64) -> Gate {
    gate_with(input, hook, action, now, write_marker)
}

/// [`gate_at`] with the marker writer injected, so a test can fail a write.
fn gate_with(
    input: &HookInput,
    hook: &str,
    action: &str,
    now: i64,
    write_file: impl Fn(&Path, &str) -> std::io::Result<()>,
) -> Gate {
    let Some(session) = input.session_id().filter(|s| !s.is_empty()) else {
        return Gate::Unavailable(Unavailable::NoSession);
    };
    let Some(call) = input.tool_use_id().filter(|id| usable_call_id(id)) else {
        return Gate::Unavailable(Unavailable::NoToolCallId);
    };
    let Some(dir) = private_marker_dir() else {
        return Gate::Unavailable(Unavailable::SharedMarkerDir);
    };
    let agent = input.agent_id().unwrap_or_default();
    let digest = key_digest(hook, session, agent, action);
    let path = marker_path(&dir, &digest);
    let read = || read_marker(&path).and_then(|text| parse_record(&text, &digest));
    let record = read();
    let ttl = i64::try_from(CONFIRM_TTL.as_secs()).unwrap_or(i64::MAX);
    let write = |state: State| {
        let record = Record {
            state,
            call: call.to_string(),
            at: now,
        };
        write_file(&path, &render_record(&digest, &record))
    };
    match decide(record.as_ref(), call, now, ttl) {
        Step::SameCall => Gate::Armed,
        Step::Arm => {
            // The previous confirmation's row claim is spent: clear it so the
            // directory holds at most one per key. Best effort; a leftover
            // claim names an old call and never matches a new one.
            if let Some(old) = record.as_ref().filter(|r| r.state == State::Consumed) {
                let _ = std::fs::remove_file(row_claim_path(&dir, &digest, &old.call));
            }
            match write(State::Pending) {
                Ok(()) => Gate::Armed,
                Err(_) => Gate::Unavailable(Unavailable::WriteFailed),
            }
        }
        Step::Pass => {
            let consumed_by_this_call = |r: &Option<Record>| {
                r.as_ref()
                    .is_some_and(|r| r.state == State::Consumed && r.call == call)
            };
            // A failed consumption write still passes when a sibling of this
            // call landed the same record first; otherwise it blocks.
            if !consumed_by_this_call(&record)
                && write(State::Consumed).is_err()
                && !consumed_by_this_call(&read())
            {
                return Gate::Unavailable(Unavailable::WriteFailed);
            }
            // Every process of this call passes; exactly one records it. Two
            // siblings can both read `pending` and both write `consumed`, so
            // the marker alone cannot pick one: the claim's exclusive create
            // does. A claim that fails for any reason but a sibling holding it
            // still records the row, since a pass with no row is the worse
            // failure for an audit log.
            if matches!(
                create_exclusive(&row_claim_path(&dir, &digest, call)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists
            ) {
                return Gate::PassedSibling;
            }
            Gate::Passed(BypassProvenance {
                kind: BypassKind::Confirmed,
                mechanism: MECHANISM.to_string(),
                reason: None,
                expires_at: None,
                armed_by_session: Some(session.to_string()),
            })
        }
    }
}

/// Move the stamp of `input`'s confirm marker for `action` back by `secs`, so
/// a guard's tests can expire a blocked attempt. `false` when there is no
/// well-formed marker to move.
#[cfg(any(test, feature = "test-builders"))]
pub fn backdate_for_tests(input: &HookInput, hook: &str, action: &str, secs: i64) -> bool {
    let (Some(session), Some(dir)) = (input.session_id(), private_marker_dir()) else {
        return false;
    };
    let digest = key_digest(hook, session, input.agent_id().unwrap_or_default(), action);
    let path = marker_path(&dir, &digest);
    let Some(mut record) = read_marker(&path).and_then(|t| parse_record(&t, &digest)) else {
        return false;
    };
    record.at -= secs;
    write_marker(&path, &render_record(&digest, &record)).is_ok()
}

/// The line an armed block carries. `pass_effect`, when given, is a sentence
/// naming what the pass does beyond letting this one action through; a guard
/// whose pass reaches further than the one action must give it, since the
/// default closing sentence says the pass reaches nothing else.
#[must_use]
pub fn armed_note(retry: Retry, pass_effect: Option<&str>) -> String {
    let minutes = CONFIRM_TTL.as_secs() / 60;
    let (again, exact) = match retry {
        Retry::SameAction => ("the same action again", "this exact action"),
        Retry::SameCommand => (
            "the identical command again (extra spaces or tabs between words are ignored)",
            "this exact command",
        ),
    };
    let opening = format!(
        "Are you sure? If you have checked and this is what the operator asked for, run \
         {again}: the second attempt passes and is recorded in the bypass log."
    );
    match pass_effect {
        None => format!(
            "{opening} It counts only for this session and agent, for {exact}, once, within \
             {minutes} minutes."
        ),
        Some(effect) => format!(
            "{opening} Only a retry from this session and agent, of {exact}, within {minutes} \
             minutes, confirms it. {effect}"
        ),
    }
}

/// What a retry must repeat to pair with the blocked attempt, which decides
/// how the armed line tells the model to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// The action the guard read (a file, a commit in a repo): the command
    /// text around it may change.
    SameAction,
    /// The whole command, as [`whole_command_action`] normalizes it.
    SameCommand,
}

/// The whole command as a confirm-tier action: every segment, with each run
/// of spaces and tabs collapsed to one space and the ends trimmed. Nothing
/// else is normalized, so anything a command could use to choose its target
/// (an earlier `export`, a sign-in, a flag, a prefix) is part of the key
/// without the guard having to recognize it. Spaces inside quotes collapse
/// too, so `"My  Vault"` pairs with `"My Vault"`: two targets whose names
/// differ only by inner spacing are not a mistake a cooperative model makes.
/// Adding a space where there was none (`a|b` against `a | b`) is a new key.
#[must_use]
pub fn whole_command_action(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut in_blank = false;
    for c in command.trim().chars() {
        if c == ' ' || c == '\t' {
            if !in_blank {
                out.push(' ');
            }
            in_blank = true;
        } else {
            out.push(c);
            in_blank = false;
        }
    }
    out
}

/// The line a block carries when it cannot be confirmed.
#[must_use]
pub fn unavailable_note(why: Unavailable) -> String {
    format!(
        "A second attempt will be blocked too: {}. Take the route above, or stop and tell the \
         operator in chat what was blocked and why.",
        why.reason()
    )
}

/// Run the confirm gate for a block the guard has already decided.
///
/// `message` is the guard's own block text. A pass returns an allow carrying
/// the `confirmed` provenance; otherwise the block gains the armed or the
/// unavailable line.
#[must_use]
pub fn confirm_block(
    input: &HookInput,
    hook: &str,
    action: &str,
    message: &str,
    retry: Retry,
    pass_effect: Option<&str>,
) -> CheckResult {
    match gate(input, hook, action) {
        Gate::Passed(provenance) => CheckResult::allow_bypassed(provenance),
        Gate::PassedSibling => CheckResult::allow(),
        Gate::Armed => CheckResult::block(format!("{message}\n{}", armed_note(retry, pass_effect))),
        Gate::Unavailable(why) => {
            CheckResult::block(format!("{message}\n{}", unavailable_note(why)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outcome;
    // Used only by the unix-only shared-marker-dir test.
    #[cfg(unix)]
    use crate::markers::{marker_dir, marker_dir_is_private};
    use crate::test_builders::{make_bash, with_marker_dir};

    const TTL: i64 = 600;

    fn rec(state: State, call: &str, at: i64) -> Record {
        Record {
            state,
            call: call.to_string(),
            at,
        }
    }

    fn input(session: Option<&str>, agent: Option<&str>, call: Option<&str>) -> HookInput {
        let mut input = make_bash("op item list");
        input.session_id = session.map(String::from);
        input.agent_id = agent.map(String::from);
        input.tool_use_id = call.map(String::from);
        input
    }

    // --- the pure decision ---

    #[test]
    fn no_marker_arms() {
        assert_eq!(decide(None, "t1", 1000, TTL), Step::Arm);
    }

    #[test]
    fn pending_from_the_same_call_blocks_without_a_write() {
        let r = rec(State::Pending, "t1", 1000);
        assert_eq!(decide(Some(&r), "t1", 1001, TTL), Step::SameCall);
    }

    #[test]
    fn pending_from_another_call_passes() {
        let r = rec(State::Pending, "t1", 1000);
        assert_eq!(decide(Some(&r), "t2", 1001, TTL), Step::Pass);
    }

    #[test]
    fn consumed_passes_its_own_call_and_arms_any_other() {
        let r = rec(State::Consumed, "t2", 1000);
        assert_eq!(decide(Some(&r), "t2", 1001, TTL), Step::Pass);
        assert_eq!(decide(Some(&r), "t3", 1001, TTL), Step::Arm);
    }

    #[test]
    fn expired_or_future_marker_arms() {
        let r = rec(State::Pending, "t1", 1000);
        assert_eq!(decide(Some(&r), "t2", 1000 + TTL + 1, TTL), Step::Arm);
        assert_eq!(decide(Some(&r), "t2", 1000 + TTL, TTL), Step::Pass);
        let future = rec(State::Pending, "t1", 1000 + FUTURE_SKEW_SECS + 1);
        assert_eq!(decide(Some(&future), "t2", 1000, TTL), Step::Arm);
    }

    #[test]
    fn records_round_trip_and_reject_another_key_or_junk() {
        let r = rec(State::Consumed, "toolu_1", 42);
        let text = render_record("abc", &r);
        assert_eq!(parse_record(&text, "abc"), Some(r));
        assert_eq!(parse_record(&text, "abd"), None);
        assert_eq!(parse_record("", "abc"), None);
        assert_eq!(parse_record(&text.replace("consumed", "done"), "abc"), None);
        assert_eq!(parse_record(&format!("{text}extra\n"), "abc"), None);
    }

    #[test]
    fn key_digest_separates_every_part() {
        let base = key_digest("h", "s", "a", "x");
        assert_ne!(base, key_digest("h2", "s", "a", "x"));
        assert_ne!(base, key_digest("h", "s2", "a", "x"));
        assert_ne!(base, key_digest("h", "s", "", "x"));
        assert_ne!(base, key_digest("h", "s", "a", "y"));
        // The separator keeps a shifted split from colliding.
        assert_ne!(
            key_digest("h", "s", "ab", "c"),
            key_digest("h", "s", "a", "bc")
        );
    }

    // --- the gate against a real marker directory ---

    #[test]
    fn first_blocks_second_passes_once_third_blocks() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = |call| input(Some("s1"), None, Some(call));
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            // A sibling process of the blocked call blocks too.
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            let passed = gate_at(&a("t2"), "h", "x", 1001);
            let Gate::Passed(p) = passed else {
                panic!("second attempt should pass: {passed:?}");
            };
            assert_eq!(p.kind, BypassKind::Confirmed);
            assert_eq!(p.mechanism, MECHANISM);
            assert_eq!(p.armed_by_session.as_deref(), Some("s1"));
            // A sibling of the passing call passes too, recording nothing.
            assert_eq!(gate_at(&a("t2"), "h", "x", 1001), Gate::PassedSibling);
            // The pass is single use.
            assert_eq!(gate_at(&a("t3"), "h", "x", 1002), Gate::Armed);
            assert!(matches!(gate_at(&a("t4"), "h", "x", 1003), Gate::Passed(_)));
        });
    }

    #[test]
    fn another_session_agent_or_action_does_not_inherit() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            assert_eq!(
                gate_at(&input(Some("s1"), None, Some("t1")), "h", "x", 1000),
                Gate::Armed
            );
            assert_eq!(
                gate_at(&input(Some("s2"), None, Some("t2")), "h", "x", 1001),
                Gate::Armed,
                "another session"
            );
            assert_eq!(
                gate_at(&input(Some("s1"), Some("ag"), Some("t3")), "h", "x", 1001),
                Gate::Armed,
                "a subagent sharing the session id"
            );
            assert_eq!(
                gate_at(&input(Some("s1"), None, Some("t4")), "h", "y", 1001),
                Gate::Armed,
                "a different action"
            );
            assert_eq!(
                gate_at(&input(Some("s1"), None, Some("t5")), "h2", "x", 1001),
                Gate::Armed,
                "another hook"
            );
            assert!(matches!(
                gate_at(&input(Some("s1"), None, Some("t6")), "h", "x", 1002),
                Gate::Passed(_)
            ));
        });
    }

    #[test]
    fn expired_attempt_blocks_and_rearms() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = |call| input(Some("s1"), None, Some(call));
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            assert_eq!(gate_at(&a("t2"), "h", "x", 1000 + TTL + 1), Gate::Armed);
            assert!(matches!(
                gate_at(&a("t3"), "h", "x", 1000 + TTL + 2),
                Gate::Passed(_)
            ));
        });
    }

    #[test]
    fn no_session_or_call_id_is_unavailable_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            assert_eq!(
                gate_at(&input(None, None, Some("t1")), "h", "x", 1000),
                Gate::Unavailable(Unavailable::NoSession)
            );
            assert_eq!(
                gate_at(&input(Some(""), None, Some("t1")), "h", "x", 1000),
                Gate::Unavailable(Unavailable::NoSession)
            );
            assert_eq!(
                gate_at(&input(Some("s1"), None, None), "h", "x", 1000),
                Gate::Unavailable(Unavailable::NoToolCallId)
            );
            assert_eq!(
                gate_at(&input(Some("s1"), None, Some("")), "h", "x", 1000),
                Gate::Unavailable(Unavailable::NoToolCallId)
            );
            let confirm_files = walk_confirm_files(dir.path());
            assert!(confirm_files.is_empty(), "{confirm_files:?}");
        });
    }

    #[test]
    fn a_planted_symlink_or_junk_never_passes() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = input(Some("s1"), None, Some("t2"));
            let digest = key_digest("h", "s1", "", "x");
            let path = marker_path(&private_marker_dir().unwrap(), &digest);
            // Junk under the right name.
            std::fs::write(&path, "pending\n").unwrap();
            assert_eq!(gate_at(&a, "h", "x", 1000), Gate::Armed);
            // A well-formed pending record for another key.
            let other = render_record("0000", &rec(State::Pending, "t1", 1000));
            std::fs::write(&path, other).unwrap();
            assert_eq!(gate_at(&a, "h", "x", 1000), Gate::Armed);
            #[cfg(unix)]
            {
                let target = dir.path().join("target");
                std::fs::write(
                    &target,
                    render_record(&digest, &rec(State::Pending, "t1", 1000)),
                )
                .unwrap();
                std::fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
                assert_eq!(gate_at(&a, "h", "x", 1000), Gate::Armed);
                // The link was replaced, never followed.
                assert!(
                    !std::fs::symlink_metadata(&path)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_marker_dir_is_unavailable_and_never_read() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            // Squat the private subdir's name with a symlink, so marker_dir()
            // falls back to the shared base.
            let private = marker_dir();
            std::fs::remove_dir(&private).unwrap();
            let elsewhere = dir.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &private).unwrap();
            assert!(!marker_dir_is_private());
            // A well-formed pending record planted in the shared base.
            let digest = key_digest("h", "s1", "", "x");
            std::fs::write(
                dir.path().join(format!("confirm-{digest}")),
                render_record(&digest, &rec(State::Pending, "t1", 1000)),
            )
            .unwrap();
            assert_eq!(
                gate_at(&input(Some("s1"), None, Some("t2")), "h", "x", 1001),
                Gate::Unavailable(Unavailable::SharedMarkerDir)
            );
        });
    }

    #[test]
    fn a_failed_write_is_unavailable_never_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = |call| input(Some("s1"), None, Some(call));
            let fail = |_: &Path, _: &str| Err(std::io::Error::other("disk full"));
            // The first attempt cannot record its pending marker.
            assert_eq!(
                gate_with(&a("t1"), "h", "x", 1000, fail),
                Gate::Unavailable(Unavailable::WriteFailed)
            );
            // A recorded first attempt, then a retry that cannot record its
            // consumption: no pass.
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            assert_eq!(
                gate_with(&a("t2"), "h", "x", 1001, fail),
                Gate::Unavailable(Unavailable::WriteFailed)
            );
            // The pending marker is untouched, so a working retry still passes.
            assert!(matches!(gate_at(&a("t3"), "h", "x", 1002), Gate::Passed(_)));
        });
    }

    #[test]
    fn a_sibling_whose_write_fails_agrees_with_the_one_that_passed() {
        // Two processes of call t2 read `pending t1`; one records the pass,
        // the other's write fails. It re-reads, sees t2's consumption, and
        // allows instead of telling the model a retry will be blocked.
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = |call| input(Some("s1"), None, Some(call));
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            let digest = key_digest("h", "s1", "", "x");
            let path = marker_path(&private_marker_dir().unwrap(), &digest);
            // The sibling runs to completion inside this process's write,
            // then this process's own write fails.
            let sibling_wins = |_: &Path, _: &str| {
                assert!(matches!(gate_at(&a("t2"), "h", "x", 1001), Gate::Passed(_)));
                Err(std::io::Error::other("lost the race"))
            };
            assert_eq!(
                gate_with(&a("t2"), "h", "x", 1001, sibling_wins),
                Gate::PassedSibling
            );
            let winner = render_record(&digest, &rec(State::Consumed, "t2", 1001));
            assert_eq!(read_marker(&path).as_deref(), Some(winner.as_str()));
        });
    }

    #[test]
    fn two_siblings_that_both_read_pending_record_one_pass() {
        // Both processes of call t2 read `pending t1` before either writes,
        // and both writes succeed. The marker cannot tell them apart; the row
        // claim must, so exactly one returns `Passed` (one ledger row).
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let a = |call| input(Some("s1"), None, Some(call));
            assert_eq!(gate_at(&a("t1"), "h", "x", 1000), Gate::Armed);
            let sibling_first = |p: &Path, c: &str| {
                assert!(matches!(gate_at(&a("t2"), "h", "x", 1001), Gate::Passed(_)));
                write_marker(p, c)
            };
            assert_eq!(
                gate_with(&a("t2"), "h", "x", 1001, sibling_first),
                Gate::PassedSibling
            );
            // The next confirmation clears the spent claim and records again.
            assert_eq!(gate_at(&a("t3"), "h", "x", 1002), Gate::Armed);
            assert!(matches!(gate_at(&a("t4"), "h", "x", 1003), Gate::Passed(_)));
            let claims: Vec<_> = walk_confirm_files(dir.path())
                .into_iter()
                .filter(|p| p.to_string_lossy().contains(".row-"))
                .collect();
            assert_eq!(claims.len(), 1, "{claims:?}");
        });
    }

    #[test]
    fn a_call_id_the_record_cannot_carry_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            for id in ["toolu_1\ntoolu_2", "toolu 1", "toolu_\u{7}"] {
                assert_eq!(
                    gate_at(&input(Some("s1"), None, Some(id)), "h", "x", 1000),
                    Gate::Unavailable(Unavailable::NoToolCallId),
                    "{id:?}"
                );
            }
        });
    }

    #[test]
    fn confirm_block_messages() {
        let dir = tempfile::tempdir().unwrap();
        with_marker_dir(dir.path(), || {
            let first = confirm_block(
                &input(Some("s1"), None, Some("t1")),
                "h",
                "x",
                "BLOCKED: reason",
                Retry::SameAction,
                Some("It also unblocks this checkout."),
            );
            assert_eq!(first.outcome, Outcome::Block);
            let msg = first.message.unwrap();
            assert!(msg.starts_with("BLOCKED: reason\nAre you sure?"), "{msg}");
            assert!(msg.contains("run the same action again"), "{msg}");
            assert!(
                msg.ends_with("confirms it. It also unblocks this checkout."),
                "{msg}"
            );
            // A pass that reaches further never claims to count only here.
            assert!(!msg.contains("counts only"), "{msg}");
            assert!(
                armed_note(Retry::SameAction, None)
                    .contains("It counts only for this session and agent")
            );
            let command = armed_note(Retry::SameCommand, None);
            assert!(
                command.contains("run the identical command again (extra spaces or tabs between words are ignored)"),
                "{command}"
            );
            assert!(
                command.contains("for this exact command, once"),
                "{command}"
            );
            let second = confirm_block(
                &input(Some("s1"), None, Some("t2")),
                "h",
                "x",
                "BLOCKED: reason",
                Retry::SameAction,
                None,
            );
            assert_eq!(second.outcome, Outcome::Allow);
            assert_eq!(second.bypass.unwrap().kind, BypassKind::Confirmed);
            let none = confirm_block(
                &input(None, None, Some("t3")),
                "h",
                "x",
                "BLOCKED: reason",
                Retry::SameAction,
                None,
            );
            assert_eq!(none.outcome, Outcome::Block);
            let msg = none.message.unwrap();
            assert!(
                msg.contains("A second attempt will be blocked too"),
                "{msg}"
            );
            assert!(!msg.contains("Are you sure"), "{msg}");
        });
    }

    #[test]
    fn whole_command_action_collapses_only_spaces_and_tabs() {
        assert_eq!(whole_command_action("  op  item\tlist  "), "op item list");
        assert_eq!(
            whole_command_action("op item list"),
            whole_command_action("op \t item   list")
        );
        // Every other difference is part of the action.
        for other in [
            "export OP_ACCOUNT=b; op item list",
            "op item list --session tok2",
            "op item list | grep api",
            "OP item list",
        ] {
            assert_ne!(whole_command_action(other), "op item list", "{other}");
        }
        // A newline is a command separator, not spacing.
        assert_eq!(whole_command_action("a\n  b"), "a\n b");
    }

    fn walk_confirm_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("confirm-"))
                {
                    out.push(path);
                }
            }
        }
        out
    }
}
