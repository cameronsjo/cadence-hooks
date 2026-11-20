## Why

Review of cameronsjo/cadence-hooks#1659 (cameronsjo/cadence-hooks#1658) found three gaps in the confirm tier. A confirmation of `op item list` on one 1Password account passed the same listing on another account, because the key held the `--vault` but not the account. Two processes of one hook for the same tool call could both record the pass, writing two `confirmed` rows for one confirmation. And the `enforce-worktree` confirm line said the pass counts only for this session and agent, while the snooze it arms covers every session in the checkout.

## What Changes

- MODIFY `hook-protocol` Confirm tier: exactly one process of the passing call writes the `confirmed` row, picked by an exclusive create of a claim file; the others allow without a row. State that a row means the guard let the action through, not that the call ran, since another hook on the same call can still block it.
- MODIFY `secret-reads` Confirmed vault listing: the key adds the account, from `--account x` / `--account=x`, else an `OP_ACCOUNT=x` word before the command.
- MODIFY `worktree-enforcement` Confirmed retry snoozes enforce-worktree: the confirm line says the retry switches the guard off for the checkout for 30 minutes, for every session working in it, and does not say the pass counts only for this session.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `hook-protocol`: Confirm tier modified; One confirmed row per confirmation added.
- `secret-reads`: Confirmed vault listing modified; Vault listing account added.
- `worktree-enforcement`: Confirmed retry snoozes enforce-worktree.

## Impact

- `crates/core/src/confirm.rs` (row claim, confirm line), `crates/core/src/markers.rs` (`create_exclusive` visible in the crate).
- `crates/guardrails/src/guard_op_vault_scan.rs`, `crates/guardrails/src/enforce_worktree.rs`.
- Marker files `confirm-<sha256>.row-<call digest>` beside each `confirm-<sha256>`; the next armed attempt removes the spent one.
- `scripts/confirm-tier-compare.py` and `scripts/testdata/confirm-tier-commands.txt`: the everyday-command comparison against a base binary.
- `docs/configuration.md`, `CHANGELOG.md`.
