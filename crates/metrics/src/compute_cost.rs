//! Compute USD cost from a token total and a model name.
//!
//! Pure port of `compute-cost.sh`. Unknown models cost `0.0` (the line is still
//! written so the data exists; a reprocessing pass can recompute once the price
//! table is patched). Rounded to 6 decimal places to preserve sub-penny detail.

use crate::prices::Prices;
use crate::scan_tokens::Tokens;

/// Cost in USD for `tokens` billed at `model`'s rates. Returns `0.0` when the
/// model is absent from the price table.
pub fn compute_cost(tokens: &Tokens, model: &str, prices: &Prices) -> f64 {
    let Some(p) = prices.get(model) else {
        return 0.0;
    };

    let raw = tokens.input as f64 * p.input_per_mtok / 1_000_000.0
        + tokens.cache_create as f64 * p.cache_write_per_mtok / 1_000_000.0
        + tokens.cache_read as f64 * p.cache_read_per_mtok / 1_000_000.0
        + tokens.output as f64 * p.output_per_mtok / 1_000_000.0;

    (raw * 1_000_000.0).round() / 1_000_000.0
}

/// Total cost in USD summed across per-model token buckets.
///
/// Each bucket is billed at its own model's rates via [`compute_cost`], so the
/// total is the sum of the *rounded* per-bucket costs — exactly reconcilable
/// with the `byModel` array, which emits those same per-bucket values. Buckets
/// whose model is absent from the price table contribute `$0.0`. The final
/// rounding only cleans up float-addition noise.
pub fn compute_cost_by_model(buckets: &[(String, Tokens)], prices: &Prices) -> f64 {
    let raw: f64 = buckets
        .iter()
        .map(|(model, tokens)| compute_cost(tokens, model, prices))
        .sum();
    (raw * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opus_tokens() -> Tokens {
        Tokens {
            input: 1_000_000,
            cache_create: 0,
            cache_read: 0,
            output: 0,
        }
    }

    #[test]
    fn one_million_input_tokens_opus() {
        let cost = compute_cost(&opus_tokens(), "claude-opus-4-7", &Prices::embedded());
        assert_eq!(cost, 15.0);
    }

    #[test]
    fn mixed_tokens_sum_correctly() {
        let tokens = Tokens {
            input: 1_000_000,
            cache_create: 1_000_000,
            cache_read: 1_000_000,
            output: 1_000_000,
        };
        // 15 + 18.75 + 1.50 + 75 = 110.25
        let cost = compute_cost(&tokens, "claude-opus-4-7", &Prices::embedded());
        assert_eq!(cost, 110.25);
    }

    #[test]
    fn unknown_model_costs_zero() {
        let cost = compute_cost(&opus_tokens(), "gpt-9", &Prices::embedded());
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn rounds_to_six_decimals() {
        // 1 input token on opus = 15 / 1e6 = 0.000015 exactly.
        let tokens = Tokens {
            input: 1,
            ..Default::default()
        };
        let cost = compute_cost(&tokens, "claude-opus-4-7", &Prices::embedded());
        assert_eq!(cost, 0.000015);
    }

    #[test]
    fn zero_tokens_cost_zero() {
        let cost = compute_cost(&Tokens::default(), "claude-opus-4-7", &Prices::embedded());
        assert_eq!(cost, 0.0);
    }

    // --- bucket-aware cost tests ---

    /// Two-model buckets: total cost equals sum of per-model costs.
    #[test]
    fn compute_cost_by_model_two_buckets() {
        let buckets: Vec<(String, Tokens)> = vec![
            (
                "claude-opus-4-7".into(),
                Tokens {
                    input: 1_000_000,
                    cache_create: 0,
                    cache_read: 0,
                    output: 0,
                },
            ),
            (
                "claude-sonnet-4-5".into(),
                Tokens {
                    input: 1_000_000,
                    cache_create: 0,
                    cache_read: 0,
                    output: 0,
                },
            ),
        ];
        let prices = Prices::embedded();
        let total = compute_cost_by_model(&buckets, &prices);
        // opus: 1M input * $15/MTok = $15; sonnet rates differ — just verify structure
        let opus_cost = compute_cost(&buckets[0].1, "claude-opus-4-7", &prices);
        let sonnet_cost = compute_cost(&buckets[1].1, "claude-sonnet-4-5", &prices);
        assert!((total - (opus_cost + sonnet_cost)).abs() < 1e-9);
        // Sanity: total is strictly greater than zero
        assert!(total > 0.0);
    }

    /// Unknown model bucket contributes $0.
    #[test]
    fn compute_cost_by_model_unknown_contributes_zero() {
        let buckets: Vec<(String, Tokens)> = vec![
            (
                "unknown".into(),
                Tokens {
                    input: 1_000_000,
                    cache_create: 0,
                    cache_read: 0,
                    output: 0,
                },
            ),
            (
                "claude-opus-4-7".into(),
                Tokens {
                    input: 1_000_000,
                    cache_create: 0,
                    cache_read: 0,
                    output: 0,
                },
            ),
        ];
        let prices = Prices::embedded();
        let total = compute_cost_by_model(&buckets, &prices);
        let opus_only = compute_cost(&buckets[1].1, "claude-opus-4-7", &prices);
        assert!((total - opus_only).abs() < 1e-9);
    }

    /// Total must reconcile exactly with the sum of per-bucket rounded costs.
    ///
    /// The byModel array emits compute_cost per bucket (each rounded to 6
    /// decimals), so the total must be the sum of those rounded values — not a
    /// single rounding of the raw sum, which can differ when bucket costs land
    /// on a half-micro-dollar boundary.
    #[test]
    fn compute_cost_by_model_reconciles_with_rounded_buckets() {
        use crate::prices::ModelPrice;
        use std::collections::HashMap;

        // Priced so 1 input token costs 1.5 micro-dollars: each bucket rounds
        // up to 0.000002, but the raw sum (3.0 micro-dollars) rounds to
        // 0.000003 — exposing round(sum) vs sum(round) divergence.
        let price = || ModelPrice {
            input_per_mtok: 1.5,
            output_per_mtok: 0.0,
            cache_write_per_mtok: 0.0,
            cache_read_per_mtok: 0.0,
        };
        let prices = Prices {
            models: HashMap::from([
                ("model-a".to_string(), price()),
                ("model-b".to_string(), price()),
            ]),
        };
        let one_input = Tokens {
            input: 1,
            ..Default::default()
        };
        let buckets: Vec<(String, Tokens)> = vec![
            ("model-a".into(), one_input.clone()),
            ("model-b".into(), one_input),
        ];

        let total = compute_cost_by_model(&buckets, &prices);
        let bucket_sum: f64 = buckets
            .iter()
            .map(|(m, t)| compute_cost(t, m, &prices))
            .sum();

        assert_eq!(
            total, bucket_sum,
            "costUsd total must equal the sum of emitted byModel costs"
        );
    }

    /// Single-model bucket total matches the scalar compute_cost result.
    #[test]
    fn compute_cost_by_model_single_bucket_matches_scalar() {
        let tokens = Tokens {
            input: 500_000,
            cache_create: 100_000,
            cache_read: 200_000,
            output: 50_000,
        };
        let buckets: Vec<(String, Tokens)> = vec![("claude-opus-4-7".into(), tokens.clone())];
        let prices = Prices::embedded();
        let by_model = compute_cost_by_model(&buckets, &prices);
        let scalar = compute_cost(&tokens, "claude-opus-4-7", &prices);
        // Both paths must agree to 6 decimal places
        assert!((by_model - scalar).abs() < 1e-9);
    }
}
