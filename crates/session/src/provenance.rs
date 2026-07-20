//! Shared provenance primitives (cadence#248).
//!
//! A raw hostname is machine-identifying but not something that belongs in a
//! git-committed artifact — it leaks environment topology to anyone who reads
//! the repo's history. Every COMMITTED provenance block (persisted plans,
//! and the `warn-commit-provenance` nudge's computed trailer) uses
//! [`machine_digest`] instead. Local-only telemetry (e.g. `plan-links.jsonl`)
//! is unaffected and keeps the bare hostname — this module exists only for
//! the committed-artifact path.

use sha2::{Digest, Sha256};

/// Salt namespacing this digest away from any other SHA-256 use of the same
/// hostname string. Bumping it (a hypothetical `-v2`) is a deliberate breaking
/// change — every existing committed digest stops matching, which is the
/// point: this value must never silently collide with an unrelated derivation.
const MACHINE_DIGEST_SALT: &str = "cadence-prov-v1";

/// Hex length the digest is truncated to — enough to disambiguate machines in
/// practice (same order as a git short SHA) without publishing the raw input.
const MACHINE_DIGEST_LEN: usize = 12;

/// A salted, truncated SHA-256 hex digest of `hostname`, safe to commit.
///
/// Salting means the digest can't be reversed to the hostname via a generic
/// precomputed table; truncation keeps every committed block's width stable
/// and short. Deterministic — the same hostname always yields the same
/// digest, which is what makes it useful as a provenance field at all.
pub fn machine_digest(hostname: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(MACHINE_DIGEST_SALT.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    hex.chars().take(MACHINE_DIGEST_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known vector: `printf '%s' "sjomba.localcadence-prov-v1" | shasum -a
    /// 256 | cut -c1-12` — pins the exact salt/concatenation/truncation
    /// scheme so a future refactor can't silently drift the output.
    #[test]
    fn known_vector_sjomba_local() {
        assert_eq!(machine_digest("sjomba.local"), "cf6e768835c7");
    }

    #[test]
    fn digest_differs_from_raw_hostname() {
        let host = "sjomba.local";
        assert_ne!(
            machine_digest(host),
            host,
            "the digest must never equal the raw hostname it replaces"
        );
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(
            machine_digest("cameron-m5-mbp"),
            machine_digest("cameron-m5-mbp")
        );
    }

    #[test]
    fn different_hostnames_yield_different_digests() {
        assert_ne!(machine_digest("host-a"), machine_digest("host-b"));
    }

    #[test]
    fn digest_length_is_pinned() {
        assert_eq!(machine_digest("any-host").len(), MACHINE_DIGEST_LEN);
    }
}
