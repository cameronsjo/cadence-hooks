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
    #[serde(rename = "cacheWritePerMTok")]
    pub cache_write_per_mtok: f64,
    #[serde(rename = "cacheReadPerMTok")]
    pub cache_read_per_mtok: f64,
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
        let opus = prices.get("claude-opus-4-7").unwrap();
        assert_eq!(opus.input_per_mtok, 15.0);
        assert_eq!(opus.output_per_mtok, 75.0);
        assert_eq!(opus.cache_write_per_mtok, 18.75);
        assert_eq!(opus.cache_read_per_mtok, 1.5);
    }

    #[test]
    fn unknown_model_absent() {
        let prices = Prices::embedded();
        assert!(prices.get("gpt-9").is_none());
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
