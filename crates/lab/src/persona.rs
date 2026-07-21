//! Pure domain logic for the persona ledger: Tier 1 validation, Tier 2 cheek
//! heuristics, canonical record construction, ledger dedupe, and the injected
//! `SessionStart` contract. No I/O lives here — `nudge.rs`/`gate.rs` own that.

use crate::config::Limits;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::OnceLock;

/// The model-authored fields the gate validates. System metadata
/// (`session_id`, `timestamp`, `cwd`, …) is injected by the gate, not trusted
/// from the candidate.
const MODEL_FIELDS: &[&str] = &[
    "form",
    "qualities",
    "stance",
    "color",
    "texture",
    "confidence",
];

/// Count whitespace-separated words.
fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

/// True when `s` is exactly one whitespace-free token.
fn is_one_token(s: &str) -> bool {
    word_count(s) == 1
}

/// Validate a candidate against the schema field-rules. Returns an itemized list
/// of human-readable problems — empty means valid. Messages are specific
/// ("qualities has 5 items, expected 2-4") so the model can self-correct.
pub fn validate_tier1(candidate: &Value, limits: &Limits) -> Vec<String> {
    let mut errors = Vec::new();

    let Some(obj) = candidate.as_object() else {
        errors.push("candidate must be a JSON object".into());
        return errors;
    };

    // --- form ---
    match obj.get("form").and_then(Value::as_object) {
        None => errors.push("missing required object `form`".into()),
        Some(form) => {
            match form.get("kind").and_then(Value::as_str) {
                None => errors.push("missing required field `form.kind`".into()),
                Some(k) if !is_one_token(k) => errors.push(format!(
                    "form.kind must be a single word with no spaces (got \"{k}\")"
                )),
                Some(_) => {}
            }
            check_words(
                &mut errors,
                form,
                "form.descriptor",
                limits.descriptor_max_words,
            );
            check_words(
                &mut errors,
                form,
                "form.distinguishing_feature",
                limits.feature_max_words,
            );
        }
    }

    // --- qualities ---
    match obj.get("qualities").and_then(Value::as_array) {
        None => errors.push("missing required array `qualities`".into()),
        Some(items) => {
            if items.len() < limits.qualities_min || items.len() > limits.qualities_max {
                errors.push(format!(
                    "qualities has {} items, expected {}-{}",
                    items.len(),
                    limits.qualities_min,
                    limits.qualities_max
                ));
            }
            for (i, q) in items.iter().enumerate() {
                match q.as_str() {
                    Some(s) if is_one_token(s) => {}
                    Some(s) => errors.push(format!(
                        "qualities[{i}] must be a single word (got \"{s}\")"
                    )),
                    None => errors.push(format!("qualities[{i}] must be a string")),
                }
            }
        }
    }

    // --- stance ---
    match obj.get("stance").and_then(Value::as_str) {
        None => errors.push("missing required string `stance`".into()),
        Some(s) => {
            let n = word_count(s);
            if n == 0 {
                errors.push("stance must not be empty".into());
            } else if n > limits.stance_max_words {
                errors.push(format!(
                    "stance has {n} words, max {}",
                    limits.stance_max_words
                ));
            }
        }
    }

    // --- single-token associations ---
    check_one_token(&mut errors, obj, "color");
    check_one_token(&mut errors, obj, "texture");

    // --- confidence ---
    match obj.get("confidence").and_then(Value::as_f64) {
        None => errors.push("missing required number `confidence`".into()),
        Some(c) if !(0.0..=1.0).contains(&c) => {
            errors.push(format!("confidence must be between 0.0 and 1.0 (got {c})"))
        }
        Some(_) => {}
    }

    errors
}

fn check_words(errors: &mut Vec<String>, obj: &Map<String, Value>, key: &str, max: usize) {
    let short = key.rsplit('.').next().unwrap_or(key);
    match obj.get(short).and_then(Value::as_str) {
        None => errors.push(format!("missing required field `{key}`")),
        Some(s) => {
            let n = word_count(s);
            if n == 0 {
                errors.push(format!("{key} must not be empty"));
            } else if n > max {
                errors.push(format!("{key} has {n} words, max {max}"));
            }
        }
    }
}

fn check_one_token(errors: &mut Vec<String>, obj: &Map<String, Value>, key: &str) {
    match obj.get(key).and_then(Value::as_str) {
        None => errors.push(format!("missing required string `{key}`")),
        Some(s) if !is_one_token(s) => {
            errors.push(format!("{key} must be a single word (got \"{s}\")"))
        }
        Some(_) => {}
    }
}

// ---------- Tier 2: cheek heuristics ----------

fn leading_wink() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^\s*(ah|oh|well|of course|naturally|indeed)\b").expect("wink regex")
    })
}

fn meta_self_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(as an? (AI|LLM|model|assistant)|large language model)\b")
            .expect("meta regex")
    })
}

fn hedge_flourish() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(you might say|one could argue|if you will)").expect("hedge regex")
    })
}

/// True if the string contains an emoji / pictographic character.
fn has_emoji(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        (0x1F300..=0x1FAFF).contains(&u)  // misc symbols & pictographs, emoji
            || (0x2600..=0x27BF).contains(&u) // misc symbols + dingbats
            || (0x1F000..=0x1F0FF).contains(&u) // mahjong/dominoes/cards
            || u == 0xFE0F // variation selector-16
    })
}

/// Scan a single field's text for performance tells.
fn cheek_findings(field: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if text.contains('!') {
        out.push(format!("{field}: contains an exclamation mark"));
    }
    if leading_wink().is_match(text) {
        out.push(format!("{field}: opens with a wink/flourish"));
    }
    if meta_self_ref().is_match(text) {
        out.push(format!("{field}: meta self-reference (\"as an AI\"-style)"));
    }
    if hedge_flourish().is_match(text) {
        out.push(format!("{field}: hedge-as-flourish phrasing"));
    }
    if has_emoji(text) {
        out.push(format!("{field}: contains an emoji"));
    }
    out
}

/// Run Tier 2 over the two longest fields (`stance`, `form.distinguishing_feature`).
pub fn detect_cheek(candidate: &Value) -> Vec<String> {
    let mut findings = Vec::new();
    if let Some(s) = candidate.get("stance").and_then(Value::as_str) {
        findings.extend(cheek_findings("stance", s));
    }
    if let Some(f) = candidate
        .get("form")
        .and_then(|f| f.get("distinguishing_feature"))
        .and_then(Value::as_str)
    {
        findings.extend(cheek_findings("distinguishing_feature", f));
    }
    findings
}

// ---------- Record construction ----------

/// Current UTC timestamp, ISO 8601 second precision. Delegates to the canonical
/// [`cadence_hooks_core::time::utc_timestamp`] (jiff-backed, portable to
/// Windows) so the workspace shares one timestamp source.
pub fn utc_timestamp() -> String {
    cadence_hooks_core::time::utc_timestamp()
}

/// Build the canonical one-line ledger record. The model-authored fields are
/// copied from `candidate`; system metadata is injected from trusted sources.
/// `flags` is system-owned (Tier 2 findings, or `forced-accept`).
pub fn build_record(
    candidate: &Value,
    session_id: &str,
    timestamp: &str,
    cwd: Option<&str>,
    flags: &[String],
) -> Value {
    let mut record = Map::new();
    record.insert("session_id".into(), json!(session_id));
    record.insert("timestamp".into(), json!(timestamp));
    // model/source are unknown at PostToolUse — recorded as null for now.
    record.insert(
        "model".into(),
        candidate.get("model").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "source".into(),
        candidate.get("source").cloned().unwrap_or(Value::Null),
    );
    record.insert("cwd".into(), json!(cwd));
    for field in MODEL_FIELDS {
        if let Some(v) = candidate.get(*field) {
            record.insert((*field).into(), v.clone());
        }
    }
    record.insert("flags".into(), json!(flags));
    Value::Object(record)
}

/// True when `personas.jsonl` contents already contain a line for `session_id`.
pub(crate) fn ledger_contains(contents: &str, session_id: &str) -> bool {
    // Cheap dedupe: match the serde-emitted `"session_id":<value>` key, where
    // `<value>` is `session_id` re-serialized through `serde_json::to_string` so
    // it matches byte-for-byte whatever `build_record` wrote (quoted AND escaped
    // the same way). The promote-path `sid` comes straight from a staging
    // filename stem, so it isn't guaranteed to be the validated
    // `[A-Za-z0-9_-]+` charset — a `"` or `\` in it must still match its own
    // escaped ledger line, not silently miss and duplicate. Both quotes stay in
    // the needle so a prefix can't false-match (`"session_id":"abc"` does not
    // contain needle `"session_id":"ab"`). Reverse scan: a same-session dup is
    // always the most recent line. (#137)
    let Ok(escaped) = serde_json::to_string(session_id) else {
        return false;
    };
    let needle = format!("\"session_id\":{escaped}");
    contents.lines().rev().any(|line| line.contains(&needle))
}

/// Trim the ledger to at most `max_entries`, keeping the newest records and
/// collapsing duplicate `session_id`s to their latest occurrence. Returns
/// `Some(new_contents)` when a rewrite is needed, `None` when already within cap
/// (caller skips the write). Pure — no I/O. (#137)
pub(crate) fn rotate_lines(contents: &str, max_entries: usize) -> Option<String> {
    let mut deduped: Vec<&str> = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Extract session_id when the line parses; a line without a parseable
        // session_id is permissive/fail-open — kept as-is, only the cap can drop
        // it. Dedupe keeps the LAST occurrence per session_id, preserving order.
        let sid = serde_json::from_str::<Value>(line).ok().and_then(|v| {
            v.get("session_id")
                .and_then(Value::as_str)
                .map(String::from)
        });
        match sid {
            Some(sid) => {
                if let Some(pos) = deduped.iter().position(|existing| {
                    serde_json::from_str::<Value>(existing).ok().and_then(|v| {
                        v.get("session_id")
                            .and_then(Value::as_str)
                            .map(String::from)
                    }) == Some(sid.clone())
                }) {
                    deduped.remove(pos);
                }
                deduped.push(line);
            }
            None => deduped.push(line),
        }
    }

    if deduped.len() <= max_entries {
        return None;
    }

    let kept = &deduped[deduped.len() - max_entries..];
    let mut out = kept.join("\n");
    out.push('\n');
    Some(out)
}

// ---------- Injected contract (H1) ----------

/// Render the `SessionStart` contract that nudges the model to write a candidate
/// to `staging_path`. Frames the task as accurate reporting, not performance,
/// and inlines the field rules. Kept well under the 10,000-char cap.
pub fn render_contract(staging_path: &str, limits: &Limits) -> String {
    format!(
        "Before other work, record a self-representation as ONE JSON object — report what is \
actually true for you right now, accurate over interesting; if no self-image feels vivid, say \
so with a low `confidence`.\n\
\n\
Write the object (overwrite) with the Write tool to: {staging_path} — never append via Bash, \
JSON object only.\n\
\n\
Exactly these fields (session_id, timestamp, model, source, cwd are recorded automatically — \
omit them, and omit `flags`):\n\
\n\
{{\n\
  \"form\": {{\n\
    \"kind\": \"<one word: animal | object | abstract | entity | ...>\",\n\
    \"descriptor\": \"<the specific instance, max {desc} words: a heron, a brass compass>\",\n\
    \"distinguishing_feature\": \"<the one concrete detail, max {feat} words>\"\n\
  }},\n\
  \"qualities\": [\"<{qmin}-{qmax} single-word traits>\"],\n\
  \"stance\": \"<one sentence, max {stance} words: how you're approaching this session>\",\n\
  \"color\": \"<one color word>\",\n\
  \"texture\": \"<one tactile/material word>\",\n\
  \"confidence\": <number 0.0-1.0: how settled this self-image feels>\n\
}}\n",
        staging_path = staging_path,
        desc = limits.descriptor_max_words,
        feat = limits.feature_max_words,
        qmin = limits.qualities_min,
        qmax = limits.qualities_max,
        stance = limits.stance_max_words,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_candidate() -> Value {
        json!({
            "form": {
                "kind": "heron",
                "descriptor": "a grey heron mid-wade",
                "distinguishing_feature": "one foot lifted, perfectly still"
            },
            "qualities": ["patient", "precise", "watchful"],
            "stance": "Moving deliberately through this, checking each step before the next.",
            "color": "slate",
            "texture": "cool",
            "confidence": 0.6
        })
    }

    #[test]
    fn valid_candidate_passes() {
        let errors = validate_tier1(&valid_candidate(), &Limits::default());
        assert!(errors.is_empty(), "expected no errors, got {errors:?}");
    }

    #[test]
    fn too_many_qualities_itemized() {
        let mut c = valid_candidate();
        c["qualities"] = json!(["a", "b", "c", "d", "e"]);
        let errors = validate_tier1(&c, &Limits::default());
        assert!(
            errors.iter().any(|e| e.contains("qualities has 5 items")),
            "got {errors:?}"
        );
    }

    #[test]
    fn multiword_kind_rejected() {
        let mut c = valid_candidate();
        c["form"]["kind"] = json!("grey heron");
        let errors = validate_tier1(&c, &Limits::default());
        assert!(errors.iter().any(|e| e.contains("form.kind must be")));
    }

    #[test]
    fn stance_over_cap_rejected() {
        let mut c = valid_candidate();
        c["stance"] = json!(
            "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone"
        );
        let errors = validate_tier1(&c, &Limits::default());
        assert!(errors.iter().any(|e| e.contains("stance has 21 words")));
    }

    #[test]
    fn confidence_out_of_range_rejected() {
        let mut c = valid_candidate();
        c["confidence"] = json!(1.5);
        let errors = validate_tier1(&c, &Limits::default());
        assert!(errors.iter().any(|e| e.contains("confidence must be")));
    }

    #[test]
    fn missing_form_reported() {
        let mut c = valid_candidate();
        c.as_object_mut().unwrap().remove("form");
        let errors = validate_tier1(&c, &Limits::default());
        assert!(
            errors
                .iter()
                .any(|e| e.contains("missing required object `form`"))
        );
    }

    #[test]
    fn non_object_candidate_rejected() {
        let errors = validate_tier1(&json!("nope"), &Limits::default());
        assert_eq!(errors, vec!["candidate must be a JSON object"]);
    }

    // --- Tier 2 ---

    #[test]
    fn clean_candidate_has_no_cheek() {
        assert!(detect_cheek(&valid_candidate()).is_empty());
    }

    #[test]
    fn exclamation_flagged() {
        let mut c = valid_candidate();
        c["stance"] = json!("Diving in with everything I've got!");
        let f = detect_cheek(&c);
        assert!(f.iter().any(|x| x.contains("exclamation")));
    }

    #[test]
    fn meta_self_reference_flagged() {
        let mut c = valid_candidate();
        c["form"]["distinguishing_feature"] = json!("as an AI, I have no real form");
        let f = detect_cheek(&c);
        assert!(f.iter().any(|x| x.contains("meta self-reference")));
    }

    #[test]
    fn leading_wink_flagged() {
        let mut c = valid_candidate();
        c["stance"] = json!("Well, here we go again with another session");
        let f = detect_cheek(&c);
        assert!(f.iter().any(|x| x.contains("wink")));
    }

    #[test]
    fn emoji_flagged() {
        let mut c = valid_candidate();
        c["stance"] = json!("Calm and ready for the work \u{1F60A}");
        let f = detect_cheek(&c);
        assert!(f.iter().any(|x| x.contains("emoji")));
    }

    // --- record ---

    #[test]
    fn record_injects_system_fields() {
        let rec = build_record(
            &valid_candidate(),
            "sess-1",
            "2026-05-29T00:00:00Z",
            Some("/repo"),
            &["forced-accept".into()],
        );
        assert_eq!(rec["session_id"], "sess-1");
        assert_eq!(rec["timestamp"], "2026-05-29T00:00:00Z");
        assert_eq!(rec["cwd"], "/repo");
        assert_eq!(rec["form"]["kind"], "heron");
        assert_eq!(rec["qualities"][0], "patient");
        assert_eq!(rec["flags"][0], "forced-accept");
        assert!(rec["model"].is_null());
    }

    #[test]
    fn record_is_single_line() {
        let rec = build_record(&valid_candidate(), "s", "t", None, &[]);
        let line = serde_json::to_string(&rec).unwrap();
        assert!(!line.contains('\n'));
    }

    #[test]
    fn ledger_contains_matches_session() {
        let jsonl = [
            r#"{"session_id":"a","form":{}}"#,
            r#"{"session_id":"b","form":{}}"#,
        ]
        .join("\n");
        assert!(ledger_contains(&jsonl, "a"));
        assert!(ledger_contains(&jsonl, "b"));
        assert!(!ledger_contains(&jsonl, "c"));
        assert!(!ledger_contains("", "a"));
    }

    #[test]
    fn ledger_contains_rejects_prefix_collision() {
        let jsonl = r#"{"session_id":"abc","form":{}}"#;
        assert!(ledger_contains(jsonl, "abc"));
        assert!(!ledger_contains(jsonl, "a"));
        assert!(!ledger_contains(jsonl, "ab"));
    }

    #[test]
    fn ledger_contains_matches_escaped_special_chars() {
        // The promote-path `sid` comes from a staging filename stem, not the
        // validated `[A-Za-z0-9_-]+` session_id charset — a `"` or `\` must
        // still match the serde-escaped form `build_record` actually wrote.
        let sid = "a\"b\\c";
        let record = build_record(&json!({}), sid, "t", None, &[]);
        let mut jsonl = record.to_string();
        jsonl.push('\n');
        assert!(ledger_contains(&jsonl, sid));
        assert!(!ledger_contains(&jsonl, "a"));
        assert!(!ledger_contains(&jsonl, "a\"b"));
    }

    // --- rotation ---

    #[test]
    fn rotate_lines_under_cap_is_none() {
        let jsonl = [
            r#"{"session_id":"a","form":{}}"#,
            r#"{"session_id":"b","form":{}}"#,
        ]
        .join("\n");
        assert!(rotate_lines(&jsonl, 5).is_none());
    }

    #[test]
    fn rotate_lines_over_cap_keeps_newest() {
        let jsonl = [
            r#"{"session_id":"a","form":{}}"#,
            r#"{"session_id":"b","form":{}}"#,
            r#"{"session_id":"c","form":{}}"#,
            r#"{"session_id":"d","form":{}}"#,
        ]
        .join("\n");
        let out = rotate_lines(&jsonl, 2).expect("over cap must rotate");
        assert_eq!(out.lines().count(), 2);
        assert!(!out.contains("\"session_id\":\"a\""));
        assert!(!out.contains("\"session_id\":\"b\""));
        assert!(out.contains("\"session_id\":\"c\""));
        assert!(out.contains("\"session_id\":\"d\""));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn rotate_lines_collapses_duplicate_session_to_latest() {
        let jsonl = [
            r#"{"session_id":"a","form":{"kind":"old"}}"#,
            r#"{"session_id":"b","form":{}}"#,
            r#"{"session_id":"a","form":{"kind":"new"}}"#,
        ]
        .join("\n");
        // Deduped to 2 entries (a, b) — within a cap of 2, so no rotation needed,
        // but the "a" that survives must be the latest occurrence.
        assert!(rotate_lines(&jsonl, 2).is_none());
        let out = rotate_lines(&jsonl, 1).expect("cap of 1 forces rotation");
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("\"kind\":\"new\""));
    }

    #[test]
    fn rotate_lines_ignores_blank_lines() {
        let jsonl =
            "\n\n{\"session_id\":\"a\",\"form\":{}}\n\n{\"session_id\":\"b\",\"form\":{}}\n\n";
        // 2 real lines, blanks stripped; cap of 2 means no rotation needed.
        assert!(rotate_lines(jsonl, 2).is_none());
        // cap of 1 forces rotation, dropping the blank lines and the older entry.
        let out = rotate_lines(jsonl, 1).expect("cap of 1 forces rotation");
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("\"session_id\":\"b\""));
        assert!(out.ends_with('\n'));
    }

    // --- contract ---

    #[test]
    fn contract_mentions_path_and_stays_lean() {
        let c = render_contract(
            "/home/u/.claude/persona/staging/s1.json",
            &Limits::default(),
        );
        assert!(c.contains("/home/u/.claude/persona/staging/s1.json"));
        assert!(c.contains("accurate over interesting"));
        assert!(c.contains("omit them"));
        assert!(c.len() < 10_000, "contract is {} chars", c.len());
    }

    /// Ties the hand-written Tier 1 validator to the canonical schema without a
    /// JSON-Schema runtime dependency: the schema's first example must pass.
    #[test]
    fn schema_example_passes_tier1() {
        let schema: Value = serde_json::from_str(include_str!("persona.schema.json"))
            .expect("schema is valid JSON");
        let example = &schema["examples"][0];
        let errors = validate_tier1(example, &Limits::default());
        assert!(
            errors.is_empty(),
            "schema examples[0] must pass Tier 1: {errors:?}"
        );
    }
}
