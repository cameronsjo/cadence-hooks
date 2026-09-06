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
    /// What resuming cost. `Some(0.0)` is a *measured* zero — the cache
    /// survived, or the gap never exceeded the TTL. `None` is unmeasurable:
    /// no next turn, or its model is absent from the price table.
    pub cold_restart_usd: Option<f64>,
}

/// A graded session. Every field is a pure function of the transcript.
pub struct SessionGrade {
    /// Last timestamped record minus the first.
    pub wall_clock_ms: i64,
    /// Every idle span over [`GAP_MIN_MS`], ordered by start.
    pub gaps: Vec<Gap>,
    /// Sum of the measurable `cold_restart_usd` values.
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
    let cold_restart_usd_total = round_to(gaps.iter().filter_map(|g| g.cold_restart_usd).sum(), 6);

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
            Some(Gap {
                start_ms,
                end_ms,
                gap_ms,
                context_tokens_at_gap: turns
                    .iter()
                    .filter(|t| t.ts_ms <= start_ms)
                    .next_back()
                    .map(|t| t.context),
                cold_restart_usd: cold_restart_usd(gap_ms, end_ms, turns, prices),
            })
        })
        .collect()
}

/// What the first turn after the gap paid to rebuild its cache.
///
/// `Some(0.0)` and `None` are different answers and neither substitutes for the
/// other: a gap under the TTL cost a measured nothing, and a gap over the TTL
/// whose next turn reports zero cache creation *also* cost a measured nothing —
/// the cache survived. `None` means the question could not be answered.
fn cold_restart_usd(gap_ms: i64, end_ms: i64, turns: &[&Turn], prices: &Prices) -> Option<f64> {
    if gap_ms <= CACHE_TTL_MS {
        return Some(0.0);
    }
    let next = turns.iter().find(|t| t.ts_ms >= end_ms)?;
    let price = prices.get(&next.model)?;
    Some(usd_per_mtok(
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
