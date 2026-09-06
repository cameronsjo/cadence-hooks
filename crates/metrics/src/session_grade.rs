//! Deterministic session grading — pure functions of a transcript's
//! `timestamp` and `usage` fields, emitted as named flags plus dollars.
//!
//! The contract this implements is
//! `docs/research/2026-09-05-session-grading-metric-spec.md` in
//! `cameronsjo/cadence-ecosystem` (issue #523), and the fixture under
//! `testdata/grading/` is a byte-identical copy of the one reviewed there.
//! Nothing here makes a judgment: it reports wall clock, idle gaps and what a
//! cold restart cost, peak context, compactions, and turn economy. Weighting
//! those into a verdict is a consumer's job.
//!
//! **Why a whole-transcript pass rather than an extension of
//! [`crate::scan_tokens`].** That scanner runs a byte pre-filter and sums a
//! range; grading needs every timestamped record of *any* type sorted into
//! order, including records carrying no `usage` at all. The two have different
//! shapes, so they stay separate modules over the same file.
//!
//! **Prompt text is never deserialized.** [`content_is_string`] is a
//! shape-only visitor: it answers whether `message.content` was a JSON string
//! and discards the value without binding it. That is the same invariant
//! `prompt_content_is_not_deserialized_or_emitted` asserts for
//! [`crate::transcript`].

use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt;

use crate::prices::Prices;

/// A span longer than this between consecutive records is a gap (strictly
/// greater — a span of exactly this length is not one).
pub const GAP_MIN_MS: i64 = 45 * 60 * 1000;

/// The estate's prompt-cache TTL — **one hour**, not Anthropic's 5-minute
/// default. A gap longer than this may have cost a cache rebuild; a gap under
/// it never did.
pub const CACHE_TTL_MS: i64 = 60 * 60 * 1000;

/// Lower bound of the `over500k` context tier.
pub const CONTEXT_TIER_500K: u64 = 500_000;

/// Lower bound of the `over750k` context tier.
pub const CONTEXT_TIER_750K: u64 = 750_000;

/// Default assistant-turns-per-user-prompt above which `flags.grind` is set.
///
/// A parameter rather than a hard constant, and the grading emits the value it
/// ran under as `config.grindTurnsPerPrompt`. A corpus calibration can move the
/// default without silently invalidating an expected file, and a threshold
/// change is visible in every graded record rather than implied by a release
/// number.
pub const DEFAULT_GRIND_TURNS_PER_PROMPT: f64 = 30.0;

/// The model string Claude Code writes for a locally-synthesized assistant
/// record. Such a record carries `usage` but is not a turn.
const SYNTHETIC_MODEL: &str = "<synthetic>";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One transcript line, narrowed to the fields the contract names.
///
/// The contract's field list is an **allowlist** — a maximum, not a minimum.
/// The `cache_creation.ephemeral_*` sub-buckets are in that list and are
/// deliberately *not* parsed here: grading prices a cold restart off the
/// authoritative `cache_creation_input_tokens` scalar and takes context from
/// the three whole-record counts, so neither sub-bucket is reachable from any
/// emitted field. Parsing fewer fields can only reduce what reaches memory.
#[derive(Deserialize)]
struct Record {
    /// Unknown values are accepted — the platform adds record types, and one
    /// it adds next month must not fail a line.
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default, rename = "isSidechain")]
    is_sidechain: Option<bool>,
    #[serde(default, rename = "isMeta")]
    is_meta: Option<bool>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default, rename = "compactMetadata")]
    compact_metadata: Option<CompactMetadata>,
    #[serde(default)]
    message: Option<Message>,
}

#[derive(Deserialize)]
struct CompactMetadata {
    #[serde(default)]
    trigger: Option<String>,
    #[serde(default, rename = "preTokens")]
    pre_tokens: u64,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
    /// Whether `message.content` was a JSON string. Shape only — see
    /// [`content_is_string`]; the value is never bound.
    #[serde(default, deserialize_with = "content_is_string")]
    content: bool,
    /// The same fact as [`Message::content`], pre-derived. A transcript
    /// projected through the contract's `grading-fixture.jq` carries this
    /// boolean instead of the prose it replaced, so a grader that reads only
    /// `content` scores every projected file at zero user prompts.
    #[serde(default, rename = "contentIsString")]
    content_is_string: Option<bool>,
}

#[derive(Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

/// Answer "was this a JSON string?" without binding the value.
///
/// Every arm either returns a bool outright or drains the value through
/// [`serde::de::IgnoredAny`], so no prompt text is ever owned by this process.
/// A plain `Option<Value>` field would have been shorter and would have put the
/// whole prompt in memory.
fn content_is_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};

    struct ShapeOnly;

    impl<'de> Visitor<'de> for ShapeOnly {
        type Value = bool;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value (only its shape is read)")
        }

        fn visit_str<E>(self, _: &str) -> Result<bool, E> {
            Ok(true)
        }
        fn visit_borrowed_str<E>(self, _: &'de str) -> Result<bool, E> {
            Ok(true)
        }
        fn visit_string<E>(self, _: String) -> Result<bool, E> {
            Ok(true)
        }

        fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_unit<E>(self) -> Result<bool, E> {
            Ok(false)
        }
        fn visit_none<E>(self) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_some<D2>(self, d: D2) -> Result<bool, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            d.deserialize_any(ShapeOnly)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<bool, A::Error>
        where
            A: SeqAccess<'de>,
        {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(false)
        }

        fn visit_map<A>(self, mut map: A) -> Result<bool, A::Error>
        where
            A: MapAccess<'de>,
        {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(false)
        }
    }

    deserializer.deserialize_any(ShapeOnly)
}

// ---------------------------------------------------------------------------
// Derived shapes
// ---------------------------------------------------------------------------

/// An assistant turn: `type == "assistant"`, `usage` present, model not
/// `<synthetic>`.
struct Turn {
    ts_ms: i64,
    context: u64,
    cache_creation: u64,
    model: String,
}

/// One surviving record, reduced to what grading reads.
struct Event {
    ts_ms: i64,
    turn: Option<Turn>,
    is_user_prompt: bool,
    compaction: Option<Compaction>,
    is_model_refusal_fallback: bool,
}

struct Compaction {
    trigger: Option<String>,
    pre_tokens: u64,
}

/// One idle span longer than [`GAP_MIN_MS`].
pub struct Gap {
    /// Start of the span, in milliseconds since the Unix epoch.
    pub start_ms: i64,
    /// End of the span, in milliseconds since the Unix epoch.
    pub end_ms: i64,
    /// Span length. Always greater than [`GAP_MIN_MS`].
    pub gap_ms: i64,
    /// Context of the nearest assistant turn at or before the start; `None`
    /// when no turn has run yet.
    pub context_tokens_at_gap: Option<u64>,
    /// What resuming cost, rounded to six places — the emitted figure.
    /// `Some(0.0)` is a *measured* zero: the cache survived, or the gap never
    /// exceeded the TTL. `None` is unmeasurable — no next turn, or its model is
    /// absent from the price table.
    pub cold_restart_usd: Option<f64>,
    /// The same quantity before rounding, kept only to total the session.
    ///
    /// Summing the *rounded* per-gap figures compounds up to half a
    /// micro-dollar of error per gap; summing the exact ones and rounding once
    /// does not. On a four-gap session that is the difference between
    /// `12.936212` and `12.936211`, and the contract's own recorded value for
    /// that session is the latter — see [`SessionGrade::cold_restart_usd_total`].
    pub cold_restart_usd_exact: Option<f64>,
}

/// A graded session. Every field is a pure function of the transcript.
pub struct SessionGrade {
    /// Last timestamped record minus the first.
    pub wall_clock_ms: i64,
    /// Every idle span over [`GAP_MIN_MS`], ordered by start.
    pub gaps: Vec<Gap>,
    /// What every cold restart in this session cost, together.
    ///
    /// Summed from the **unrounded** per-gap values and rounded once, not
    /// summed from the rounded ones. The contract's field table reads "sum of
    /// non-null `coldRestartUsd`, rounded to 6 places", which taken literally
    /// is the other reading — but the real session it records in section 8
    /// totals `12.936211`, which only the sum-then-round produces (the
    /// per-gap-rounded sum is `12.936212`). Its own fixture cannot tell the two
    /// apart, since a single nonzero gap rounds identically either way, which
    /// is how two independent implementations agreed and still left the
    /// ambiguity in the prose. The recorded value wins; the prose is filed for
    /// correction so the `sweep.py` backfill does not implement the other one.
    pub cold_restart_usd_total: f64,
    /// Wall clock minus all gap time.
    pub active_ms: i64,
    /// Largest context observed on any assistant turn.
    pub peak_context_tokens: u64,
    /// `under500k`, `over500k`, or `over750k`.
    pub context_tier: &'static str,
    /// Compaction boundaries bucketed by trigger.
    pub compactions: Compactions,
    /// Count of `model_refusal_fallback` system records.
    pub model_refusal_fallbacks: u64,
    /// Longest prompt-to-prompt span with gap time removed.
    pub longest_turn_ms: i64,
    /// Assistant turns per the definition above.
    pub assistant_turns: u64,
    /// User prompts per the definition above.
    pub user_prompts: u64,
    /// Turns per prompt to one decimal place; `None` with zero prompts.
    pub turns_per_prompt: Option<f64>,
    /// The boolean summary a consumer reads first.
    pub flags: Flags,
    /// The grind threshold this grading ran under.
    pub grind_turns_per_prompt: f64,
}

/// Compaction boundaries bucketed by `compactMetadata.trigger`.
pub struct Compactions {
    /// `trigger == "manual"`.
    pub manual: u64,
    /// `trigger == "auto"`.
    pub auto: u64,
    /// Any other or absent trigger — the bucket a new platform trigger lands
    /// in rather than being dropped.
    pub other: u64,
    /// Largest `preTokens` across all boundaries; `0` when there are none.
    pub max_pre_tokens: u64,
}

/// Boolean summary. Each flag is independent; a session can trip several.
pub struct Flags {
    /// Wall clock over one hour.
    pub long_session: bool,
    /// Any gap at all.
    pub afk_gap: bool,
    /// Any gap longer than the cache TTL — true even when that gap's measured
    /// cost was zero.
    pub cold_restart: bool,
    /// Peak context at or above [`CONTEXT_TIER_500K`].
    pub context_500k: bool,
    /// Peak context at or above [`CONTEXT_TIER_750K`]; implies `context_500k`.
    pub context_750k: bool,
    /// At least one `auto`-triggered compaction.
    pub auto_compacted: bool,
    /// At least one model refusal fallback.
    pub model_fallback: bool,
    /// Turns per prompt above the configured threshold.
    pub grind: bool,
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

/// Grade one transcript at the default grind threshold.
pub fn grade_transcript(transcript: &str, prices: &Prices) -> SessionGrade {
    grade_transcript_with(transcript, prices, DEFAULT_GRIND_TURNS_PER_PROMPT)
}

/// Grade one transcript, naming the grind threshold.
///
/// A line that does not parse is skipped rather than failing the grading — a
/// live transcript is being appended to while this runs, so its final line is
/// routinely half-written.
pub fn grade_transcript_with(
    transcript: &str,
    prices: &Prices,
    grind_turns_per_prompt: f64,
) -> SessionGrade {
    let mut events: Vec<Event> = transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Record>(line).ok())
        .filter(|r| r.is_sidechain != Some(true))
        .filter_map(to_event)
        .collect();

    // Files are not stored in timestamp order.
    events.sort_by_key(|e| e.ts_ms);

    let turns: Vec<&Turn> = events.iter().filter_map(|e| e.turn.as_ref()).collect();
    let prompt_times: Vec<i64> = events
        .iter()
        .filter(|e| e.is_user_prompt)
        .map(|e| e.ts_ms)
        .collect();

    let (first_ms, last_ms) = match (events.first(), events.last()) {
        (Some(f), Some(l)) => (f.ts_ms, l.ts_ms),
        _ => (0, 0),
    };
    let wall_clock_ms = last_ms - first_ms;

    let gaps = find_gaps(&events, &turns, prices);
    let gap_total_ms: i64 = gaps.iter().map(|g| g.gap_ms).sum();
    let cold_restart_usd_total = round_to(
        gaps.iter().filter_map(|g| g.cold_restart_usd_exact).sum(),
        6,
    );

    let peak_context_tokens = turns.iter().map(|t| t.context).max().unwrap_or(0);
    let compactions = tally_compactions(&events);
    let model_refusal_fallbacks = events
        .iter()
        .filter(|e| e.is_model_refusal_fallback)
        .count() as u64;

    let assistant_turns = turns.len() as u64;
    let user_prompts = prompt_times.len() as u64;
    let turns_per_prompt =
        (user_prompts > 0).then(|| round_to(assistant_turns as f64 / user_prompts as f64, 1));

    let gap_spans: Vec<(i64, i64)> = gaps.iter().map(|g| (g.start_ms, g.end_ms)).collect();
    let longest_turn_ms = longest_turn_ms(&prompt_times, last_ms, &gap_spans);

    let context_tier = if peak_context_tokens >= CONTEXT_TIER_750K {
        "over750k"
    } else if peak_context_tokens >= CONTEXT_TIER_500K {
        "over500k"
    } else {
        "under500k"
    };

    let flags = Flags {
        long_session: wall_clock_ms > 60 * 60 * 1000,
        afk_gap: !gaps.is_empty(),
        cold_restart: gaps.iter().any(|g| g.gap_ms > CACHE_TTL_MS),
        context_500k: peak_context_tokens >= CONTEXT_TIER_500K,
        context_750k: peak_context_tokens >= CONTEXT_TIER_750K,
        auto_compacted: compactions.auto > 0,
        model_fallback: model_refusal_fallbacks > 0,
        // Compared against the emitted, rounded value, so the flag and the
        // number a reader sees beside it can never disagree.
        grind: turns_per_prompt.is_some_and(|t| t > grind_turns_per_prompt),
    };

    SessionGrade {
        wall_clock_ms,
        active_ms: wall_clock_ms - gap_total_ms,
        gaps,
        cold_restart_usd_total,
        peak_context_tokens,
        context_tier,
        compactions,
        model_refusal_fallbacks,
        longest_turn_ms,
        assistant_turns,
        user_prompts,
        turns_per_prompt,
        flags,
        grind_turns_per_prompt,
    }
}

/// Reduce a parsed record to an [`Event`], or drop it.
///
/// A record with no parseable `timestamp` is dropped — roughly a quarter of a
/// real transcript is bookkeeping (`last-prompt`, `mode`, `ai-title`,
/// `file-history-*`, `queue-operation`) that carries none.
fn to_event(r: Record) -> Option<Event> {
    let ts_ms = r
        .timestamp
        .as_deref()?
        .parse::<jiff::Timestamp>()
        .ok()?
        .as_millisecond();

    let kind = r.r#type.as_deref().unwrap_or("");
    let subtype = r.subtype.as_deref().unwrap_or("");

    let turn = (kind == "assistant")
        .then(|| {
            let msg = r.message.as_ref()?;
            let usage = msg.usage.as_ref()?;
            let model = msg.model.as_deref()?;
            if model == SYNTHETIC_MODEL {
                return None;
            }
            Some(Turn {
                ts_ms,
                context: usage.input_tokens
                    + usage.cache_read_input_tokens
                    + usage.cache_creation_input_tokens,
                cache_creation: usage.cache_creation_input_tokens,
                model: model.to_string(),
            })
        })
        .flatten();

    let is_user_prompt = kind == "user"
        && r.is_meta != Some(true)
        && r.message
            .as_ref()
            .is_some_and(|m| m.content || m.content_is_string == Some(true));

    let compaction = (kind == "system" && subtype == "compact_boundary").then(|| {
        let meta = r.compact_metadata.as_ref();
        Compaction {
            trigger: meta.and_then(|m| m.trigger.clone()),
            pre_tokens: meta.map_or(0, |m| m.pre_tokens),
        }
    });

    Some(Event {
        ts_ms,
        turn,
        is_user_prompt,
        compaction,
        is_model_refusal_fallback: kind == "system" && subtype == "model_refusal_fallback",
    })
}

/// Every span over [`GAP_MIN_MS`] between consecutive records of **any** type.
///
/// Any-to-any is load-bearing. An earlier draft required the record before the
/// gap to be an assistant turn and missed 25 of 28 real gaps, because a
/// hook-summary record almost always follows a turn.
fn find_gaps(events: &[Event], turns: &[&Turn], prices: &Prices) -> Vec<Gap> {
    events
        .windows(2)
        .filter_map(|w| {
            let gap_ms = w[1].ts_ms - w[0].ts_ms;
            if gap_ms <= GAP_MIN_MS {
                return None;
            }
            let start_ms = w[0].ts_ms;
            let end_ms = w[1].ts_ms;
            let basis = cold_restart_basis(gap_ms, end_ms, turns, prices);
            Some(Gap {
                start_ms,
                end_ms,
                gap_ms,
                // Turns are sorted ascending, so the last one at or before the
                // gap's start is the nearest preceding turn.
                context_tokens_at_gap: turns
                    .iter()
                    .rfind(|t| t.ts_ms <= start_ms)
                    .map(|t| t.context),
                cold_restart_usd: basis.map(|(t, r)| usd_per_mtok(t, r)),
                cold_restart_usd_exact: basis.map(|(t, r)| t as f64 * r / 1_000_000.0),
            })
        })
        .collect()
}

/// What resuming after this gap is charged on: `(tokens, rate spread)`.
///
/// Returns the *basis* rather than a dollar figure because the two consumers
/// need different arithmetic over it — the emitted per-gap value rounds, the
/// session total does not (see [`SessionGrade::cold_restart_usd_total`]) — and
/// rounding first and un-rounding later is not possible.
///
/// `Some` and `None` are different answers and neither substitutes for the
/// other: a gap under the TTL cost a measured nothing, and a gap over the TTL
/// whose next turn reports zero cache creation *also* cost a measured nothing —
/// the cache survived. `None` means the question could not be answered at all:
/// no turn followed, or its model is not in the table.
fn cold_restart_basis(
    gap_ms: i64,
    end_ms: i64,
    turns: &[&Turn],
    prices: &Prices,
) -> Option<(u64, f64)> {
    if gap_ms <= CACHE_TTL_MS {
        return Some((0, 0.0));
    }
    let next = turns.iter().find(|t| t.ts_ms >= end_ms)?;
    let price = prices.get(&next.model)?;
    Some((
        next.cache_creation,
        price.cache_write_1h() - price.cache_read_per_mtok,
    ))
}

/// `tokens x rate / 1e6`, rounded half-away-from-zero to six places.
///
/// The rounding happens on the numerator, before the division — `round(t * r)`
/// rather than `round(t * r / 1e6 * 1e6)`. Both are algebraically the six-place
/// rounding of the same quantity; the second additionally round-trips through a
/// division it then undoes, and that round-trip is not lossless.
///
/// **Measured, because the obvious story is wrong.** The contract's exact-half
/// case — `106,798 x 19.75`, exactly `2,109,260.5` — does *not* separate the two
/// forms: `2_109_260.5 / 1e6 * 1e6` returns exactly `2109260.5`, so both feed
/// [`f64::round`] the identical value and both yield `2.109261`. Mutating this
/// function to the divide-first form leaves the whole fixture green. What does
/// separate them is smaller inputs, where the quotient has no exact `f64`: at
/// this same rate, 102 tokens gives `0.002015` here and `0.002014` after the
/// round-trip. `a_rounding_round_trip_would_change_the_answer` pins that pair,
/// so the choice is guarded by a case that can actually fail.
fn usd_per_mtok(tokens: u64, rate_per_mtok: f64) -> f64 {
    (tokens as f64 * rate_per_mtok).round() / 1_000_000.0
}

/// Round half-away-from-zero to `places` decimals — Rust's native
/// [`f64::round`] behavior, and the contract's, but not Python's builtin.
fn round_to(value: f64, places: u32) -> f64 {
    let scale = 10_f64.powi(places as i32);
    (value * scale).round() / scale
}

fn tally_compactions(events: &[Event]) -> Compactions {
    let mut out = Compactions {
        manual: 0,
        auto: 0,
        other: 0,
        max_pre_tokens: 0,
    };
    for c in events.iter().filter_map(|e| e.compaction.as_ref()) {
        match c.trigger.as_deref() {
            Some("manual") => out.manual += 1,
            Some("auto") => out.auto += 1,
            _ => out.other += 1,
        }
        out.max_pre_tokens = out.max_pre_tokens.max(c.pre_tokens);
    }
    out
}

/// Longest prompt-to-prompt span, with any gap time inside it removed.
///
/// The final span closes at the last timestamped record, so a session with one
/// prompt still has one span. Subtracting gaps is what makes this "how long did
/// one instruction actually run" rather than "how long until the user came
/// back".
fn longest_turn_ms(prompt_times: &[i64], last_ms: i64, gaps: &[(i64, i64)]) -> i64 {
    prompt_times
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = prompt_times.get(i + 1).copied().unwrap_or(last_ms);
            let idle: i64 = gaps
                .iter()
                .map(|&(gs, ge)| (ge.min(end) - gs.max(start)).max(0))
                .sum();
            (end - start - idle).max(0)
        })
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// ISO-8601 UTC with **exactly** three fractional digits, always — including
/// when the milliseconds are zero.
///
/// Pinned because two implementations otherwise produce equal instants and
/// unequal strings: Python's `isoformat` emits six digits, or none at all when
/// the microseconds are zero.
fn iso_millis(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
        .strftime("%Y-%m-%dT%H:%M:%S.%3fZ")
        .to_string()
}

impl SessionGrade {
    /// The grading as camelCase JSON — the shape the contract's expected file
    /// is compared against, and the shape `log-session` nests under `grading`.
    pub fn to_json(&self) -> Value {
        json!({
            "wallClockMs": self.wall_clock_ms,
            "gaps": self.gaps.iter().map(Gap::to_json).collect::<Vec<_>>(),
            "coldRestartUsdTotal": self.cold_restart_usd_total,
            "activeMs": self.active_ms,
            "peakContextTokens": self.peak_context_tokens,
            "contextTier": self.context_tier,
            "compactions": {
                "manual": self.compactions.manual,
                "auto": self.compactions.auto,
                "other": self.compactions.other,
                "maxPreTokens": self.compactions.max_pre_tokens,
            },
            "modelRefusalFallbacks": self.model_refusal_fallbacks,
            "longestTurnMs": self.longest_turn_ms,
            "assistantTurns": self.assistant_turns,
            "userPrompts": self.user_prompts,
            "turnsPerPrompt": self.turns_per_prompt,
            "flags": {
                "longSession": self.flags.long_session,
                "afkGap": self.flags.afk_gap,
                "coldRestart": self.flags.cold_restart,
                "context500k": self.flags.context_500k,
                "context750k": self.flags.context_750k,
                "autoCompacted": self.flags.auto_compacted,
                "modelFallback": self.flags.model_fallback,
                "grind": self.flags.grind,
            },
            "config": {
                "grindTurnsPerPrompt": self.grind_turns_per_prompt,
            },
        })
    }
}

impl Gap {
    fn to_json(&self) -> Value {
        json!({
            "startTs": iso_millis(self.start_ms),
            "endTs": iso_millis(self.end_ms),
            "gapMs": self.gap_ms,
            "contextTokensAtGap": self.context_tokens_at_gap,
            "coldRestartUsd": self.cold_restart_usd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture, byte-identical to the copy reviewed in the contract.
    const FIXTURE: &str = include_str!("../testdata/grading/contract-cases.jsonl");
    /// Its expected grading, likewise.
    const EXPECTED: &str = include_str!("../testdata/grading/contract-cases.expected.json");

    /// The rate table from the contract's section 6 — **not** the embedded
    /// `prices.json`.
    ///
    /// This distinction is load-bearing and easy to get wrong. The fixture's
    /// fourth gap restarts on `claude-haiku-4-5` and expects `null`, meaning
    /// *unpriced*; the shipped table prices that model, so grading the fixture
    /// against the embedded rates yields `0.018998` and fails on a line that
    /// looks like a rounding bug. The contract fixes a three-model table and
    /// the expected file was computed against it.
    fn contract_prices() -> Prices {
        serde_json::from_str(
            r#"{"models":{
                "claude-opus-5":   {"inputPerMTok":5.0, "outputPerMTok":25.0,"cacheWritePerMTok":6.25,"cacheWrite1hPerMTok":10.0,"cacheReadPerMTok":0.5},
                "claude-fable-5-1":{"inputPerMTok":10.0,"outputPerMTok":50.0,"cacheWritePerMTok":12.5,"cacheWrite1hPerMTok":20.0,"cacheReadPerMTok":0.25},
                "claude-sonnet-5": {"inputPerMTok":2.0, "outputPerMTok":10.0,"cacheWritePerMTok":2.5, "cacheWrite1hPerMTok":4.0, "cacheReadPerMTok":0.2}
            }}"#,
        )
        .expect("contract rate table must parse")
    }

    /// Structural equality where numbers compare by **value**, not by serde's
    /// internal representation.
    ///
    /// `serde_json::Value::eq` calls `Number(30)` and `Number(30.0)` unequal —
    /// one is an integer, one a float — and the contract's section 10 names
    /// exactly that pair (`0` vs `0.0`, `23` vs `23.0`) as a formatting
    /// difference to be resolved by comparing parsed values. A plain
    /// `assert_eq!` over `Value` is therefore too strict to express the
    /// contract, and it fails on a grading that is correct.
    fn json_eq_by_value(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
                (Some(x), Some(y)) => x == y,
                _ => x == y,
            },
            (Value::Array(x), Value::Array(y)) => {
                x.len() == y.len() && x.iter().zip(y).all(|(a, b)| json_eq_by_value(a, b))
            }
            (Value::Object(x), Value::Object(y)) => {
                x.len() == y.len()
                    && x.iter()
                        .all(|(k, v)| y.get(k).is_some_and(|w| json_eq_by_value(v, w)))
            }
            _ => a == b,
        }
    }

    /// The acceptance test: the whole grading, compared as parsed JSON.
    #[test]
    fn fixture_grades_exactly_as_the_contract_records() {
        let got = grade_transcript_with(FIXTURE, &contract_prices(), 30.0).to_json();
        let want: Value = serde_json::from_str(EXPECTED).expect("expected file must parse");
        assert!(
            json_eq_by_value(&got, &want),
            "grading diverges from the contract's expected file\n  got:  {got}\n  want: {want}"
        );
    }

    /// The comparison above must be able to fail — a helper that returns true
    /// for everything would make the acceptance test unfalsifiable, and it is
    /// the only thing standing between a wrong grading and a green suite.
    #[test]
    fn the_value_comparison_can_go_red() {
        let base: Value = serde_json::from_str(EXPECTED).expect("expected file must parse");

        assert!(json_eq_by_value(&base, &base), "identical must match");
        assert!(
            json_eq_by_value(&json!({"n": 30}), &json!({"n": 30.0})),
            "int and float of the same value must match"
        );
        assert!(
            !json_eq_by_value(&json!({"n": 30}), &json!({"n": 31})),
            "different numbers must not match"
        );
        assert!(
            !json_eq_by_value(&json!({"n": 0}), &json!({"n": null})),
            "a measured zero must never equal an unmeasurable null"
        );
        assert!(
            !json_eq_by_value(&json!({"a": 1}), &json!({"a": 1, "b": 2})),
            "an extra key must not match"
        );
        assert!(
            !json_eq_by_value(&json!([1, 2]), &json!([2, 1])),
            "array order matters"
        );

        let mut mutated = base.clone();
        mutated["gaps"][1]["coldRestartUsd"] = json!(2.10926);
        assert!(
            !json_eq_by_value(&base, &mutated),
            "the banker's-rounding value must not compare equal to the contract's"
        );
    }

    /// The copied fixture must be the file that was reviewed, byte for byte.
    ///
    /// Byte-identity is all this proves. It is not a leak check — that is
    /// `assert-fixture-keys.sh`, which the contract requires in CI against
    /// this copy.
    #[test]
    fn embedded_fixture_matches_the_reviewed_bytes() {
        assert_eq!(FIXTURE.len(), 3671, "fixture byte length");
        assert_eq!(FIXTURE.lines().count(), 27, "fixture record count");
    }

    /// A live transcript is appended to while this runs, so its last line is
    /// routinely half-written. That must cost one record, never the grading.
    #[test]
    fn a_truncated_final_line_is_skipped_not_an_error() {
        let whole = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:10:00Z"}"#,
        );
        let truncated = format!("{whole}\n{{\"type\":\"assist");

        let grade = grade_transcript(&truncated, &contract_prices());
        assert_eq!(grade.wall_clock_ms, 600_000, "the two intact records grade");
    }

    /// Roughly a quarter of a real transcript carries no timestamp.
    #[test]
    fn records_without_a_parseable_timestamp_are_dropped() {
        let t = concat!(
            r#"{"type":"last-prompt"}"#,
            "\n",
            r#"{"type":"mode","timestamp":"not-a-timestamp"}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.wall_clock_ms, 0, "only one record survives");
        assert!(grade.gaps.is_empty());
    }

    /// The platform adds record types; one it adds next month must not fail a
    /// line, and must still contribute its timestamp.
    #[test]
    fn an_unknown_record_type_still_grades() {
        let t = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"some-type-invented-later","timestamp":"2020-01-01T02:00:00Z","novelField":{"a":1}}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.wall_clock_ms, 7_200_000);
        assert_eq!(grade.gaps.len(), 1, "an unknown type still bounds a gap");
    }

    /// `Some(0.0)` and `None` are different answers. A gap that never exceeded
    /// the TTL cost a measured nothing.
    #[test]
    fn a_gap_over_the_minimum_but_under_the_ttl_costs_a_measured_zero() {
        let t = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2020-01-01T00:46:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":1,"cache_read_input_tokens":2,"cache_creation_input_tokens":900000}}}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.gaps.len(), 1);
        assert_eq!(grade.gaps[0].gap_ms, 2_760_000, "46 minutes");
        assert_eq!(
            grade.gaps[0].cold_restart_usd,
            Some(0.0),
            "under the TTL is a measured zero, never null, however large the write"
        );
        assert!(!grade.flags.cold_restart);
    }

    /// A span of exactly `GAP_MIN_MS` is not a gap; one millisecond more is.
    #[test]
    fn the_gap_minimum_is_strict() {
        let exact = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00.000Z"}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:45:00.000Z"}"#,
        );
        let over = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00.000Z"}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:45:00.001Z"}"#,
        );
        assert!(grade_transcript(exact, &contract_prices()).gaps.is_empty());
        assert_eq!(grade_transcript(over, &contract_prices()).gaps.len(), 1);
    }

    /// An unpriced restart model is unmeasurable, not free.
    #[test]
    fn an_unpriced_restart_model_yields_null_not_zero() {
        let t = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2020-01-01T02:00:00Z","message":{"model":"a-model-nobody-priced","usage":{"input_tokens":1,"cache_read_input_tokens":1,"cache_creation_input_tokens":500000}}}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.gaps.len(), 1);
        assert_eq!(grade.gaps[0].cold_restart_usd, None);
        assert_eq!(
            grade.cold_restart_usd_total, 0.0,
            "an unmeasurable gap contributes nothing to the total"
        );
        assert!(grade.flags.cold_restart, "the gap happened regardless");
    }

    /// A session with one prompt still has one span, closing at the last
    /// timestamped record.
    #[test]
    fn a_single_prompt_session_has_one_span() {
        let t = concat!(
            r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":"do the thing"}}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:10:00Z"}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.user_prompts, 1);
        assert_eq!(grade.longest_turn_ms, 600_000);
    }

    /// Both spellings of "this user record carried a prompt" must count: the
    /// raw `message.content` string, and the `contentIsString` boolean a
    /// projected transcript carries in its place.
    #[test]
    fn a_prompt_counts_in_both_the_raw_and_projected_forms() {
        let raw =
            r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":"hello"}}"#;
        let projected = r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"contentIsString":true}}"#;
        let array_content = r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":[{"type":"tool_result","content":"..."}]}}"#;
        let meta = r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","isMeta":true,"message":{"content":"hello"}}"#;

        let p = contract_prices();
        assert_eq!(grade_transcript(raw, &p).user_prompts, 1, "raw string");
        assert_eq!(
            grade_transcript(projected, &p).user_prompts,
            1,
            "projected boolean"
        );
        assert_eq!(
            grade_transcript(array_content, &p).user_prompts,
            0,
            "a tool-result array is not a prompt"
        );
        assert_eq!(
            grade_transcript(meta, &p).user_prompts,
            0,
            "isMeta excluded"
        );
    }

    /// A `<synthetic>` record carries full `usage` but is not a turn, and an
    /// assistant record with no `usage` is not one either.
    #[test]
    fn synthetic_and_usageless_assistant_records_are_not_turns() {
        let t = concat!(
            r#"{"type":"assistant","timestamp":"2020-01-01T00:00:00Z","message":{"model":"<synthetic>","usage":{"input_tokens":9,"cache_read_input_tokens":9,"cache_creation_input_tokens":9}}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2020-01-01T00:00:01Z","message":{"model":"claude-opus-5"}}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.assistant_turns, 0);
        assert_eq!(grade.peak_context_tokens, 0);
        assert_eq!(grade.context_tier, "under500k");
    }

    /// The exact-half rounding case, isolated from the fixture.
    ///
    /// `106,798 x 19.75` is exactly `2,109,260.5`. Half-away-from-zero rounds
    /// it up; banker's rounding — Python's builtin — rounds it to even and
    /// gives `2.10926`. This pins the *rounding mode*, and nothing else: both
    /// the shipped and the divide-first arithmetic agree here (see
    /// [`usd_per_mtok`]), so it cannot guard the arithmetic.
    #[test]
    fn an_exact_half_rounds_away_from_zero() {
        assert_eq!(usd_per_mtok(106_798, 19.75), 2.109261);
        assert_ne!(
            usd_per_mtok(106_798, 19.75),
            2.10926,
            "banker's rounding would give this"
        );
    }

    /// A second exact half, at the opus spread, where the contract's own
    /// recorded value is wrong.
    ///
    /// `93,161 x 9.5` is exactly `885,029.5`, so the half-away-from-zero
    /// rounding of `0.8850295` is `0.885030`. The contract's section 9 records
    /// `0.885029` for this gap and `6.324216` for that session's total; both
    /// come from dividing before rounding, which loses the exact half — the
    /// same trap section 5 documents and which section 8's session happened to
    /// dodge because its quotient round-trips exactly. Recomputed in exact
    /// decimal arithmetic against the live transcript: `0.885030` and
    /// `6.324217`. Filed for correction; this test is the record.
    #[test]
    fn the_opus_spread_has_its_own_exact_half() {
        assert_eq!(usd_per_mtok(93_161, 9.5), 0.885030);
        assert_ne!(
            usd_per_mtok(93_161, 9.5),
            0.885029,
            "the divide-first answer, which the contract records"
        );
    }

    /// The session total sums the **unrounded** per-gap values and rounds once.
    ///
    /// This is the one place the contract's prose and its own recorded data
    /// disagree. The field table says "sum of non-null `coldRestartUsd`,
    /// rounded to 6 places" — and `coldRestartUsd` is itself defined as
    /// rounded, so read literally the total is a sum of rounded values. But the
    /// real four-gap session the contract records in section 8 totals
    /// `12.936211`, and only sum-then-round produces that; summing the rounded
    /// per-gap figures gives `12.936212`. Verified live against that
    /// transcript: every other field agreed to the millisecond and the cent.
    ///
    /// The contract's fixture cannot arbitrate, because it has exactly one
    /// nonzero gap and one value rounds the same either way. So this test
    /// builds the case the fixture is missing — two gaps whose half-micro-dollar
    /// remainders both round up — and pins the answer the recorded session gives.
    #[test]
    fn the_total_sums_unrounded_values_then_rounds_once() {
        // Gap A restarts on fable-5-1 (spread 19.75) at 106,798 tokens
        //   -> 2.1092605 exact, 2.109261 rounded.
        // Gap B restarts on opus-5 (spread 9.5) at 767,197 tokens
        //   -> 7.2883715 exact, 7.288372 rounded.
        let t = concat!(
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T00:00:00Z"}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2020-01-01T02:00:00Z","message":{"model":"claude-fable-5-1","usage":{"input_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":106798}}}"#,
            "\n",
            r#"{"type":"system","subtype":"informational","timestamp":"2020-01-01T02:00:01Z"}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2020-01-01T05:00:00Z","message":{"model":"claude-opus-5","usage":{"input_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":767197}}}"#,
        );

        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.gaps.len(), 2, "two gaps, both over the TTL");
        assert_eq!(grade.gaps[0].cold_restart_usd, Some(2.109261));
        assert_eq!(grade.gaps[1].cold_restart_usd, Some(7.288372));

        let sum_of_rounded = 2.109261_f64 + 7.288372_f64;
        assert_eq!(
            round_to(sum_of_rounded, 6),
            9.397633,
            "the reading this test exists to rule out"
        );
        assert_eq!(
            grade.cold_restart_usd_total, 9.397632,
            "summing the exact values and rounding once gives one micro-dollar less"
        );
        assert_ne!(
            grade.cold_restart_usd_total,
            round_to(sum_of_rounded, 6),
            "if these ever agree, this test has stopped distinguishing the two readings"
        );
    }

    /// Round on the numerator, not after a division that is then undone.
    ///
    /// This is the case that makes [`usd_per_mtok`]'s arithmetic falsifiable.
    /// Rewriting it as `round(t * r / 1e6 * 1e6) / 1e6` leaves the contract
    /// fixture entirely green — verified by mutation — because the fixture's
    /// quotient happens to round-trip exactly. 102 tokens at the same rate does
    /// not: the round-trip loses a unit in the last place and the dollar figure
    /// comes out a millionth low.
    #[test]
    fn a_rounding_round_trip_would_change_the_answer() {
        let tokens = 102_u64;
        let rate = 19.75_f64;

        assert_eq!(usd_per_mtok(tokens, rate), 0.002015);

        let round_tripped = (tokens as f64 * rate / 1_000_000.0 * 1_000_000.0).round() / 1e6;
        assert_eq!(round_tripped, 0.002014, "the discarded form's answer");
        assert_ne!(
            usd_per_mtok(tokens, rate),
            round_tripped,
            "if these ever agree, this test has stopped guarding anything"
        );
    }

    /// The tier boundaries are inclusive at the bottom, and `over750k` implies
    /// `context500k`.
    #[test]
    fn context_tiers_are_inclusive_at_their_lower_bound() {
        let at = |n: u64| {
            let t = format!(
                r#"{{"type":"assistant","timestamp":"2020-01-01T00:00:00Z","message":{{"model":"claude-opus-5","usage":{{"input_tokens":{n},"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}}}}"#
            );
            grade_transcript(&t, &contract_prices())
        };
        assert_eq!(at(499_999).context_tier, "under500k");
        assert_eq!(at(500_000).context_tier, "over500k");
        assert_eq!(at(749_999).context_tier, "over500k");

        let big = at(750_000);
        assert_eq!(big.context_tier, "over750k");
        assert!(big.flags.context_500k, "over750k implies context500k");
        assert!(big.flags.context_750k);
    }

    /// A trigger the platform invents lands in `other` rather than being
    /// dropped, and `maxPreTokens` is the max across every boundary.
    #[test]
    fn an_unknown_compaction_trigger_lands_in_other() {
        let t = concat!(
            r#"{"type":"system","subtype":"compact_boundary","timestamp":"2020-01-01T00:00:00Z","compactMetadata":{"trigger":"invented-later","preTokens":10}}"#,
            "\n",
            r#"{"type":"system","subtype":"compact_boundary","timestamp":"2020-01-01T00:00:01Z","compactMetadata":{"preTokens":99}}"#,
        );
        let grade = grade_transcript(t, &contract_prices());
        assert_eq!(grade.compactions.other, 2, "unknown and absent both count");
        assert_eq!(grade.compactions.manual, 0);
        assert_eq!(grade.compactions.auto, 0);
        assert_eq!(grade.compactions.max_pre_tokens, 99);
        assert!(!grade.flags.auto_compacted);
    }

    /// An empty transcript grades to zeroes rather than panicking.
    #[test]
    fn an_empty_transcript_grades_to_zero() {
        let grade = grade_transcript("", &contract_prices());
        assert_eq!(grade.wall_clock_ms, 0);
        assert_eq!(grade.active_ms, 0);
        assert_eq!(grade.turns_per_prompt, None);
        assert!(!grade.flags.grind, "no prompts cannot be a grind");
        assert_eq!(grade.longest_turn_ms, 0);
    }

    /// The emitted timestamp always carries exactly three fractional digits,
    /// including when they are zero.
    #[test]
    fn emitted_timestamps_always_carry_three_fractional_digits() {
        assert_eq!(iso_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_millis(1), "1970-01-01T00:00:00.001Z");
        assert_eq!(iso_millis(1_577_836_800_000), "2020-01-01T00:00:00.000Z");
    }

    /// The shape-only visitor must never bind prompt text. Grading a record
    /// whose content is a long string produces the same counts as one whose
    /// content is a short string — the value is not read, only its shape.
    #[test]
    fn prompt_text_is_read_for_shape_only() {
        let long = "x".repeat(50_000);
        let a = format!(
            r#"{{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{{"content":"{long}"}}}}"#
        );
        let b = r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":"x"}}"#;

        let p = contract_prices();
        let ga = grade_transcript(&a, &p);
        let gb = grade_transcript(b, &p);
        assert_eq!(ga.user_prompts, gb.user_prompts);

        // And nothing from the transcript reaches the emitted JSON.
        let emitted = ga.to_json().to_string();
        assert!(
            !emitted.contains("xxxx"),
            "no prompt text may reach an emitted grading record"
        );
    }

    /// The grind flag compares against the emitted, rounded value, so the flag
    /// and the number printed beside it can never disagree.
    #[test]
    fn grind_uses_the_emitted_turns_per_prompt() {
        let mut t = String::from(
            r#"{"type":"user","timestamp":"2020-01-01T00:00:00Z","message":{"content":"go"}}"#,
        );
        for i in 0..31 {
            t.push_str(&format!(
                "\n{{\"type\":\"assistant\",\"timestamp\":\"2020-01-01T00:00:{i:02}Z\",\"message\":{{\"model\":\"claude-opus-5\",\"usage\":{{\"input_tokens\":1,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}}}}"
            ));
        }
        let grade = grade_transcript(&t, &contract_prices());
        assert_eq!(grade.turns_per_prompt, Some(31.0));
        assert!(grade.flags.grind, "31 > 30");

        let lower = grade_transcript_with(&t, &contract_prices(), 40.0);
        assert!(!lower.flags.grind, "the threshold is a parameter");
        assert_eq!(
            lower.to_json()["config"]["grindTurnsPerPrompt"],
            json!(40.0),
            "the grading names the threshold it ran under"
        );
    }
}

// ---------------------------------------------------------------------------
// Transcript resolution
// ---------------------------------------------------------------------------

/// The Claude config root: `CLAUDE_CONFIG_DIR`, else `~/.claude`.
pub fn claude_config_root() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("CLAUDE_CONFIG_DIR")
        && !dir.is_empty()
    {
        return Some(std::path::PathBuf::from(dir));
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| std::path::Path::new(&h).join(".claude"))
}

/// Is this the canonical 8-4-4-4-12 hex UUID shape?
///
/// A shape gate, not a validity check. It runs *before* the value is joined
/// into any path, so a session id can never carry `..`, a separator, or a glob
/// metacharacter into the filesystem walk below.
fn is_uuid_shaped(s: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let mut parts = s.split('-');
    for want in groups {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() != want || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
}

/// Find the transcript for `session_id` under `<root>/projects/*/<uuid>.jsonl`.
///
/// **The project-dir slug is never trusted.** It names the cwd at session
/// birth, not the work — one graded session spanned four cwds and four
/// branches and lives under the slug of a directory it left early. So every
/// project dir is searched and the id is what identifies the file.
///
/// Subagent transcripts sit at `<project>/<session>/subagents/agent-*.jsonl`,
/// strictly deeper than the one level this reads, so they are structurally
/// unreachable here rather than filtered out by name.
///
/// Zero hits and several hits are both errors, and the message names which —
/// silently taking the first of several would grade an arbitrary session and
/// report it as the requested one.
pub fn resolve_session_transcript(
    session_id: &str,
    root: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    if !is_uuid_shaped(session_id) {
        return Err(format!(
            "session id is not a UUID: {session_id:?} (expected 8-4-4-4-12 hex)"
        ));
    }

    let projects = root.join("projects");
    let Ok(entries) = std::fs::read_dir(&projects) else {
        return Err(format!(
            "no project directory to search: {}",
            projects.display()
        ));
    };

    let mut hits: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path().join(format!("{session_id}.jsonl")))
        .filter(|p| p.is_file())
        .collect();
    hits.sort();

    match hits.len() {
        0 => Err(format!(
            "no transcript for session {session_id} under {}",
            projects.display()
        )),
        1 => Ok(hits.remove(0)),
        n => Err(format!(
            "session {session_id} matches {n} transcripts under {} — pass --transcript to choose:\n  {}",
            projects.display(),
            hits.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  ")
        )),
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn seed(root: &std::path::Path, project: &str, name: &str) {
        let dir = root.join("projects").join(project);
        std::fs::create_dir_all(&dir).expect("create project dir");
        std::fs::write(dir.join(name), "{}\n").expect("write transcript");
    }

    const ID: &str = "0e0e5f58-9ca8-4d51-bb3e-1d79a02636ae";

    #[test]
    fn a_non_uuid_session_id_is_refused_before_any_path_is_built() {
        let dir = tempfile::tempdir().expect("tempdir");
        for bad in [
            "../../etc/passwd",
            "not-a-uuid",
            "0e0e5f58-9ca8-4d51-bb3e-1d79a02636a", // one short
            "0e0e5f58-9ca8-4d51-bb3e-1d79a02636aeZ", // one long
            "0e0e5f58_9ca8_4d51_bb3e_1d79a02636ae", // wrong separator
            "0e0e5f58-9ca8-4d51-bb3e-1d79a02636*e", // glob metacharacter
            "",
        ] {
            let err = resolve_session_transcript(bad, dir.path())
                .expect_err("a non-UUID must be refused");
            assert!(err.contains("not a UUID"), "{bad:?} -> {err}");
        }
    }

    #[test]
    fn a_single_hit_resolves_whatever_the_project_slug_says() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(
            dir.path(),
            "-Users-cameron-somewhere-else",
            &format!("{ID}.jsonl"),
        );
        let got = resolve_session_transcript(ID, dir.path()).expect("must resolve");
        assert!(got.ends_with(format!("{ID}.jsonl")));
    }

    #[test]
    fn a_subagent_transcript_is_not_reachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("projects/-p/session-dir/subagents");
        std::fs::create_dir_all(&sub).expect("create subagent dir");
        std::fs::write(sub.join(format!("{ID}.jsonl")), "{}\n").expect("write");
        let err = resolve_session_transcript(ID, dir.path()).expect_err("must not resolve");
        assert!(err.contains("no transcript"), "{err}");
    }

    #[test]
    fn several_hits_are_an_error_naming_every_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed(dir.path(), "-project-a", &format!("{ID}.jsonl"));
        seed(dir.path(), "-project-b", &format!("{ID}.jsonl"));
        let err = resolve_session_transcript(ID, dir.path()).expect_err("ambiguous must fail");
        assert!(err.contains("matches 2 transcripts"), "{err}");
        assert!(
            err.contains("-project-a"),
            "names the first candidate: {err}"
        );
        assert!(
            err.contains("-project-b"),
            "names the second candidate: {err}"
        );
    }

    #[test]
    fn a_missing_projects_directory_is_a_named_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_session_transcript(ID, dir.path()).expect_err("must fail");
        assert!(err.contains("no project directory"), "{err}");
    }
}

// ---------------------------------------------------------------------------
// CLI action
// ---------------------------------------------------------------------------

/// `cadence-hooks metrics grade` — print one transcript's grading as JSON.
///
/// A CLI action, not a hook: it has no `hooks.json` wiring, reads no stdin
/// payload, and is not subject to `CADENCE_DISABLE`. The thin I/O wrapper over
/// [`grade_transcript`]; every decision it makes is which file to read.
///
/// Returns the process exit code: `0` on success, `1` with a reason on stderr
/// when the transcript cannot be identified or read. Unlike a guard, this
/// **fails closed** — printing an empty or partial grading would be read as a
/// measurement, and a cost figure nobody can trace to a file is worse than no
/// figure (ADR-0001 protects a user from a guard's own failure; there is no
/// operation here to avoid blocking).
pub fn run_grade(
    transcript: Option<String>,
    session_id: Option<String>,
    prices_path: Option<String>,
) -> u8 {
    let path = match (transcript, session_id) {
        (Some(p), _) => std::path::PathBuf::from(p),
        (None, id) => {
            let Some(id) = id
                .or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok())
                .filter(|s| !s.is_empty())
            else {
                eprintln!(
                    "metrics grade: no transcript named. Pass --transcript <path> or \
                     --session-id <uuid>, or run inside a session (CLAUDE_CODE_SESSION_ID)."
                );
                return 1;
            };
            let Some(root) = claude_config_root() else {
                eprintln!(
                    "metrics grade: cannot locate the Claude config directory \
                     (set CLAUDE_CONFIG_DIR or HOME), so --session-id cannot be resolved."
                );
                return 1;
            };
            match resolve_session_transcript(&id, &root) {
                Ok(p) => p,
                Err(reason) => {
                    eprintln!("metrics grade: {reason}");
                    return 1;
                }
            }
        }
    };

    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("metrics grade: cannot read {}: {e}", path.display());
            return 1;
        }
    };

    let prices = Prices::load(prices_path.as_deref());
    let grading = grade_transcript(&contents, &prices).to_json();
    match serde_json::to_string_pretty(&grading) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("metrics grade: cannot serialize the grading: {e}");
            1
        }
    }
}

/// Containment gate for the embedded grading fixture.
///
/// The contract requires the reviewed leak gate
/// (`scripts/assert-fixture-keys.sh` in `cameronsjo/cadence-ecosystem`) to run
/// in CI against this copy, and calls that a blocking acceptance criterion. That
/// script is 249 lines of security-critical `jq` and lives in another repo;
/// copying it here would put two copies of one gate on two release cadences,
/// which is how a gate goes quietly stale.
///
/// So this asserts the two properties that make the remote gate's verdict
/// transferable instead:
///
/// 1. **Byte-identity.** The digest below is the reviewed file's. Any edit to
///    the fixture fails here, loudly, naming the digest — so the remote gate's
///    "this file is clean" continues to describe *this* file.
/// 2. **Containment.** Every leaf path in every record is one of the fifteen
///    the contract permits, compared as path *arrays* rather than dot-joined
///    strings — a flat key named `usage.input_tokens` inside `message` renders
///    identically to an allowlisted path when joined, and a fixture carrying
///    1,512 records of leaked prose under exactly that key once passed a gate
///    built that way.
///
/// What this deliberately does **not** carry is the remote gate's prose
/// detector. That gap only matters for a fixture that is not this one, so it is
/// filed as a follow-up rather than reimplemented from prose here — two
/// independent readers rebuilding that gate's sibling from a written
/// description produced three different programs.
#[cfg(test)]
mod fixture_gate {
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    const FIXTURE: &str = include_str!("../testdata/grading/contract-cases.jsonl");

    /// The digest recorded in the contract, section 2.
    const REVIEWED_SHA256: &str =
        "124b7c9e21cde80a4a1ea7f348a63d009c1e706afac0b8078bc00598396db52c";

    /// The fifteen paths the grading record contract permits.
    const ALLOWED: &[&[&str]] = &[
        &["type"],
        &["timestamp"],
        &["isSidechain"],
        &["isMeta"],
        &["subtype"],
        &["compactMetadata", "trigger"],
        &["compactMetadata", "preTokens"],
        &["message", "model"],
        &["message", "contentIsString"],
        &["message", "usage", "input_tokens"],
        &["message", "usage", "output_tokens"],
        &["message", "usage", "cache_read_input_tokens"],
        &["message", "usage", "cache_creation_input_tokens"],
        &[
            "message",
            "usage",
            "cache_creation",
            "ephemeral_1h_input_tokens",
        ],
        &[
            "message",
            "usage",
            "cache_creation",
            "ephemeral_5m_input_tokens",
        ],
    ];

    #[test]
    fn the_fixture_is_byte_identical_to_the_reviewed_copy() {
        let digest = format!("{:x}", Sha256::digest(FIXTURE.as_bytes()));
        assert_eq!(
            digest, REVIEWED_SHA256,
            "the grading fixture has drifted from the copy the contract reviewed; \
             re-copy it from cadence-ecosystem or re-run the leak gate and update \
             the contract's recorded digest"
        );
    }

    /// Collect every leaf path, including `false`- and `null`-valued ones.
    ///
    /// A `paths(scalars)`-style filter cannot see those — the select drops
    /// them — and `isSidechain: false` sits on most records here. A gate blind
    /// to a third of its input is not a gate.
    fn leaves(value: &Value, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    prefix.push(k.clone());
                    leaves(v, prefix, out);
                    prefix.pop();
                }
            }
            Value::Array(items) => {
                // An array under an allowlisted key is still a container the
                // path check must see; index it so the leaf carries a path.
                for (i, v) in items.iter().enumerate() {
                    prefix.push(format!("[{i}]"));
                    leaves(v, prefix, out);
                    prefix.pop();
                }
                if items.is_empty() {
                    out.push(prefix.clone());
                }
            }
            _ => out.push(prefix.clone()),
        }
    }

    #[test]
    fn every_fixture_path_is_one_the_contract_permits() {
        let allowed: Vec<Vec<String>> = ALLOWED
            .iter()
            .map(|p| p.iter().map(|s| (*s).to_string()).collect())
            .collect();

        for (n, line) in FIXTURE.lines().enumerate() {
            let record: Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {e}", n + 1));
            assert!(
                record.is_object(),
                "line {}: a non-object record is skipped by every name-based check",
                n + 1
            );

            let mut found = Vec::new();
            leaves(&record, &mut Vec::new(), &mut found);
            for path in found {
                assert!(
                    allowed.contains(&path),
                    "line {}: path {:?} is not one of the fifteen the contract permits",
                    n + 1,
                    path
                );
            }
        }
    }

    /// The containment check must be able to fail — otherwise it is decoration.
    #[test]
    fn the_containment_check_can_go_red() {
        let allowed: Vec<Vec<String>> = ALLOWED
            .iter()
            .map(|p| p.iter().map(|s| (*s).to_string()).collect())
            .collect();

        // A dotted key impersonating a nested path: byte-identical to an
        // allowlisted path once joined, and a different path as an array.
        let smuggled: Value =
            serde_json::from_str(r#"{"message":{"usage.input_tokens":"leaked prose"}}"#)
                .expect("parses");
        let mut found = Vec::new();
        leaves(&smuggled, &mut Vec::new(), &mut found);
        assert_eq!(found, vec![vec!["message", "usage.input_tokens"]]);
        assert!(
            !allowed.contains(&found[0]),
            "a dotted key must not pass as a nested path"
        );

        // A false-valued leaf must be visible, not silently dropped.
        let falsey: Value =
            serde_json::from_str(r#"{"secretFlag":false,"nested":{"x":null}}"#).expect("parses");
        let mut found = Vec::new();
        leaves(&falsey, &mut Vec::new(), &mut found);
        assert_eq!(found.len(), 2, "false and null leaves must both be seen");
        for path in &found {
            assert!(!allowed.contains(path), "{path:?} must be rejected");
        }

        // An empty container has no scalar leaf; it must still be seen.
        let empty: Value =
            serde_json::from_str(r#"{"message":{"usage":{"iterations":[]}}}"#).expect("parses");
        let mut found = Vec::new();
        leaves(&empty, &mut Vec::new(), &mut found);
        assert_eq!(found, vec![vec!["message", "usage", "iterations"]]);
        assert!(!allowed.contains(&found[0]));
    }
}
