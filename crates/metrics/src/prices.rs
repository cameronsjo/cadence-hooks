//! Model price table for cost computation.
//!
//! The table is embedded at build time via `include_str!` so the binary always
//! has a usable default, even when no plugin config directory is present. An
//! override may be supplied — `CADENCE_METRICS_PRICES` (env) takes precedence
//! over a `--prices <path>` argument, which takes precedence over the embedded
//! table. A missing or malformed override silently falls back to embedded.

use serde::Deserialize;
use std::collections::HashMap;

/// Per-million-token prices for one model. Field names map to the JSON schema
/// shipped in `prices.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelPrice {
    #[serde(rename = "inputPerMTok")]
    pub input_per_mtok: f64,
    #[serde(rename = "outputPerMTok")]
    pub output_per_mtok: f64,
    /// Rate for a 5-minute (default TTL) cache write.
    #[serde(rename = "cacheWritePerMTok")]
    pub cache_write_per_mtok: f64,
    /// Rate for a 1-hour TTL cache write. Optional so an operator override file
    /// written against the older four-field schema still loads — see
    /// [`ModelPrice::cache_write_1h`] for what absence costs.
    #[serde(rename = "cacheWrite1hPerMTok", default)]
    pub cache_write_1h_per_mtok: Option<f64>,
    #[serde(rename = "cacheReadPerMTok")]
    pub cache_read_per_mtok: f64,
}

impl ModelPrice {
    /// The 1-hour cache-write rate, falling back to `input * 2.0` — Anthropic's
    /// published multiplier — when the table omits it.
    ///
    /// The fallback *invents* a rate: it is right for every model priced on the
    /// standard multiplier and wrong for any model that is not. It exists so an
    /// override file written against the older four-field schema keeps working
    /// rather than silently pricing 1-hour writes at zero. The embedded table
    /// always carries the field explicitly.
    pub fn cache_write_1h(&self) -> f64 {
        self.cache_write_1h_per_mtok
            .unwrap_or(self.input_per_mtok * 2.0)
    }
}

/// The full price table: model name -> prices.
#[derive(Debug, Clone, Deserialize)]
pub struct Prices {
    pub models: HashMap<String, ModelPrice>,
}

/// The default table, compiled into the binary.
const EMBEDDED: &str = include_str!("../prices.json");

impl Prices {
    /// Parse the embedded default table. Panics only if the embedded JSON is
    /// malformed — a build-time invariant, not a runtime condition.
    pub fn embedded() -> Self {
        serde_json::from_str(EMBEDDED).expect("embedded prices.json must be valid")
    }

    /// Resolve the price table, honoring overrides:
    /// `CADENCE_METRICS_PRICES` env > `path` arg > embedded default.
    /// Any unreadable or unparseable override degrades to the embedded table.
    pub fn load(path: Option<&str>) -> Self {
        let override_path = std::env::var("CADENCE_METRICS_PRICES")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| path.map(String::from));

        if let Some(p) = override_path
            && let Ok(contents) = std::fs::read_to_string(&p)
            && let Ok(prices) = serde_json::from_str::<Prices>(&contents)
        {
            return prices;
        }
        Self::embedded()
    }

    /// Look up prices for a model, if present in the table.
    pub fn get(&self, model: &str) -> Option<&ModelPrice> {
        self.models.get(model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_parses() {
        let prices = Prices::embedded();
        assert!(prices.get("claude-opus-4-7").is_some());
    }

    #[test]
    fn embedded_opus_rates_match_schema() {
        let prices = Prices::embedded();
        // Both corrected aliases (#127) are pinned so neither can regress to the
        // old 3x-too-high $15/$75 values.
        for alias in ["claude-opus-4-7", "claude-opus-4-6"] {
            let opus = prices
                .get(alias)
                .unwrap_or_else(|| panic!("{alias} must be priced"));
            assert_eq!(opus.input_per_mtok, 5.0, "{alias} input");
            assert_eq!(opus.output_per_mtok, 25.0, "{alias} output");
            assert_eq!(opus.cache_write_per_mtok, 6.25, "{alias} cache-write");
            assert_eq!(opus.cache_read_per_mtok, 0.5, "{alias} cache-read");
        }
    }

    #[test]
    fn embedded_has_current_opus_and_fable() {
        // #95: the current default models must be priced, not silently $0.
        let prices = Prices::embedded();
        let opus = prices
            .get("claude-opus-4-8")
            .expect("opus-4-8 must be priced");
        assert_eq!(opus.input_per_mtok, 5.0);
        assert_eq!(opus.output_per_mtok, 25.0);
        let fable = prices
            .get("claude-fable-5")
            .expect("fable-5 must be priced");
        assert_eq!(fable.input_per_mtok, 10.0);
        assert_eq!(fable.output_per_mtok, 50.0);
    }

    #[test]
    fn unknown_model_absent() {
        let prices = Prices::embedded();
        assert!(prices.get("gpt-9").is_none());
    }

    #[test]
    fn embedded_prices_current_default_models() {
        // cadence-ecosystem#522: the three model ids appearing across recent
        // transcripts were absent from the table, so every session they ran
        // cost $0 and landed in unpricedModels.
        let prices = Prices::embedded();
        let cases: [(&str, f64, f64, f64, f64, f64); 3] = [
            ("claude-opus-5", 5.0, 25.0, 6.25, 10.0, 0.5),
            ("claude-fable-5-1", 10.0, 50.0, 12.5, 20.0, 0.25),
            ("claude-sonnet-5", 2.0, 10.0, 2.5, 4.0, 0.2),
        ];
        for (model, input, output, write_5m, write_1h, read) in cases {
            let p = prices
                .get(model)
                .unwrap_or_else(|| panic!("{model} must be priced"));
            assert_eq!(p.input_per_mtok, input, "{model} input");
            assert_eq!(p.output_per_mtok, output, "{model} output");
            assert_eq!(p.cache_write_per_mtok, write_5m, "{model} 5m cache-write");
            assert_eq!(p.cache_write_1h(), write_1h, "{model} 1h cache-write");
            assert_eq!(p.cache_read_per_mtok, read, "{model} cache-read");
        }
    }

    #[test]
    fn fable_5_1_cache_read_is_not_a_tenth_of_input() {
        // The 0.025x exception: deriving fable-5-1's cache read from the usual
        // 0.1x multiplier yields $1.00 — wrong by 4x while looking plausible.
        let prices = Prices::embedded();
        let fable = prices
            .get("claude-fable-5-1")
            .expect("fable-5-1 must be priced");
        assert_eq!(fable.cache_read_per_mtok, 0.25);
        assert_ne!(
            fable.cache_read_per_mtok,
            fable.input_per_mtok * 0.1,
            "fable-5-1 cache read must not be derived from the 0.1x multiplier"
        );
    }

    #[test]
    fn every_embedded_model_declares_a_1h_cache_write_rate() {
        // The Option fallback exists for operator override files, not for the
        // embedded table — a missing field here would silently invent a rate.
        for (model, price) in &Prices::embedded().models {
            assert!(
                price.cache_write_1h_per_mtok.is_some(),
                "{model} must declare cacheWrite1hPerMTok explicitly"
            );
        }
    }

    #[test]
    fn load_honors_a_four_field_override_file() {
        // The real guard for making cacheWrite1hPerMTok optional: `load`
        // fails open to the embedded table on any parse error, so a required
        // field would silently discard an override written against the older
        // four-field schema instead of erroring. (override_path_parses calls
        // from_str, never load, so it cannot catch this.)
        // No env is set or cleared here — the `path` argument tier is what is
        // under test. An ambient CADENCE_METRICS_PRICES would outrank it, so
        // name that confound rather than letting it read as a code failure.
        assert!(
            std::env::var("CADENCE_METRICS_PRICES")
                .map(|v| v.is_empty())
                .unwrap_or(true),
            "CADENCE_METRICS_PRICES is set in the environment and outranks the \
             path argument — rerun under `env -u CADENCE_METRICS_PRICES`"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("prices.json");
        std::fs::write(
            &path,
            r#"{"models":{"claude-opus-5":{"inputPerMTok":1.0,"outputPerMTok":2.0,"cacheWritePerMTok":3.0,"cacheReadPerMTok":4.0}}}"#,
        )
        .expect("write override");

        let prices = Prices::load(Some(path.to_str().expect("utf-8 path")));
        let m = prices
            .get("claude-opus-5")
            .expect("override must be honored, not silently replaced by embedded");
        assert_eq!(m.input_per_mtok, 1.0, "override rates must win");
        assert_eq!(m.cache_read_per_mtok, 4.0);
        assert_eq!(m.cache_write_1h_per_mtok, None);
        assert_eq!(m.cache_write_1h(), 2.0, "fallback is input * 2.0");
    }

    #[test]
    fn override_path_parses() {
        let json = r#"{"models":{"test-model":{"inputPerMTok":1.0,"outputPerMTok":2.0,"cacheWritePerMTok":3.0,"cacheReadPerMTok":4.0}}}"#;
        let prices: Prices = serde_json::from_str(json).unwrap();
        let m = prices.get("test-model").unwrap();
        assert_eq!(m.input_per_mtok, 1.0);
        assert_eq!(m.cache_read_per_mtok, 4.0);
    }
}
