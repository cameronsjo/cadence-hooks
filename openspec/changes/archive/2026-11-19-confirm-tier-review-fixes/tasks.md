## 1. Fixes

- [x] 1.1 `guard-op-vault-scan` keys on the account (`--account`, `--account=`, `OP_ACCOUNT=` prefix)
- [x] 1.2 One `confirmed` row per confirmation: exclusive-create row claim keyed by the marker and the call
- [x] 1.3 `enforce-worktree` confirm line names the checkout-wide 30-minute snooze
- [x] 1.4 `guard-held-close` tests take `CADENCE_DRAIN_HELD` as an argument instead of skipping when the shell sets it

## 2. Evidence

- [x] 2.1 Tests: another account does not pass; no account and an account differ; two concurrent processes of one call write one row
- [x] 2.2 Each fix staged red once
- [x] 2.3 `scripts/confirm-tier-compare.py` checked in and run against an `origin/main` binary

## 3. Docs

- [x] 3.1 `docs/configuration.md`, `CHANGELOG.md` (`docs/hooks.md` links to the configuration page and needed no change)
