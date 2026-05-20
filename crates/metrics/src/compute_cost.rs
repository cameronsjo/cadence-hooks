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
}
