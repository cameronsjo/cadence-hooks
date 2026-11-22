## 1. Guard

- [x] 1.1 `crates/guardrails/src/guard_container_rm.rs`: matcher (runner and perl peel, Docker global options, `rm` / `container rm|remove`), block message naming the containers, confirm gate keyed on the whole command
- [x] 1.2 Reuse `guard-op-vault-scan`'s exec-wrapper peel instead of a second copy

## 2. Registration

- [x] 2.1 clap variant and dispatch (`src/main.rs`), `HOOKS` entry (`src/registry.rs`)
- [x] 2.2 `PENDING_WIRING_HOOKS` entry in `tests/hook_registration_audit.rs` until the `cadence-guardrails` hooks.json wires it
- [x] 2.3 `docs/hooks.md`, `docs/configuration.md`, `CHANGELOG.md` under `[Unreleased]`

## 3. Evidence

- [x] 3.1 Unit tests: first attempt blocks, identical retry passes once, a changed command blocks again, expiry, no session id, the non-removal commands pass
- [x] 3.2 End-to-end test through the binary (`tests/confirm_tier.rs`): exit codes and the `confirmed` row
- [x] 3.3 Staged breaks: each behavior broken once in the working tree and its test seen red
- [x] 3.4 `scripts/confirm-tier-compare.py` against an `origin/main` binary: the only first-attempt moves are the listed container removals
