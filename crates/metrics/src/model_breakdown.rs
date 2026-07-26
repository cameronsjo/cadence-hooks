//! Shared per-model breakdown builders for cost-bearing JSONL rows.
//!
//! Both `log_commit` (`commits.jsonl`) and `log_session` (`sessions.jsonl`)
//! emit an identical `byModel[]` array and `unpricedModels[]` list. Extracting
//! the two builders here keeps the shapes mechanically identical across loggers
//! — the "verbatim from log-commit" contract — so they cannot drift.

use crate::compute_cost::compute_cost;
use crate::prices::Prices;
use crate::scan_tokens::Tokens;
use serde_json::{Value, json};

/// Per-model token + cost breakdown for the `byModel` field. Each bucket is
/// billed at its own model's rates; buckets whose model is absent from the
/// price table contribute `costUsd: 0.0` (and appear in [`unpriced_models`]).
pub fn by_model_json(by_model: &[(String, Tokens)], prices: &Prices) -> Vec<Value> {
    by_model
        .iter()
        .map(|(model, tokens)| {
            let bucket_cost = compute_cost(tokens, model, prices);
            json!({
                "model": model,
                "tokens": {
                    "input": tokens.input,
                    "cacheCreate": tokens.cache_create,
                    "cacheRead": tokens.cache_read,
                    "output": tokens.output,
                },
                "costUsd": bucket_cost,
            })
        })
        .collect()
}

/// Models absent from the price table (#95). Such a model computes to `$0`
/// silently, so recording it here makes the understated `costUsd` loud in the
/// data — a non-empty array means a reprocessing pass can recompute once the
/// table is patched. Empty in the normal (all-priced) case.
pub fn unpriced_models<'a>(by_model: &'a [(String, Tokens)], prices: &Prices) -> Vec<&'a str> {
    by_model
        .iter()
        .filter(|(model, _)| prices.get(model).is_none())
        .map(|(model, _)| model.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(model: &str) -> Vec<(String, Tokens)> {
        vec![(
            model.into(),
            Tokens {
                input: 100,
                cache_create: 50,
                cache_read: 200,
                output: 30,
            },
        )]
    }

    #[test]
    fn by_model_json_emits_model_tokens_cost() {
        let prices = Prices::embedded();
        let arr = by_model_json(&scan("claude-opus-4-7"), &prices);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["model"], "claude-opus-4-7");
        assert_eq!(arr[0]["tokens"]["input"], 100);
        assert_eq!(arr[0]["tokens"]["cacheCreate"], 50);
        assert_eq!(arr[0]["tokens"]["cacheRead"], 200);
        assert_eq!(arr[0]["tokens"]["output"], 30);
        assert!(arr[0]["costUsd"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn unpriced_models_flags_unknown_and_skips_known() {
        let prices = Prices::embedded();
        assert!(unpriced_models(&scan("claude-opus-4-7"), &prices).is_empty());
        assert_eq!(unpriced_models(&scan("gpt-9"), &prices), vec!["gpt-9"]);
    }
}
