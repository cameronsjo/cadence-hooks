## 1. Keys

- [x] 1.1 `core::confirm::whole_command_action` (spaces and tabs collapsed, ends trimmed) and `Retry` (the armed line names the retry that pairs)
- [x] 1.2 `guard-op-vault-scan`: scans beside the whole command; the round-1 account and vault parsing removed as redundant
- [x] 1.3 `guard-held-close`: held entries beside the whole command (probe: an earlier `export GH_REPO` passed as `confirmed`)
- [x] 1.4 `enforce-worktree`: key unchanged (probe: five ways to move a commit all block on the retry)

## 2. Evidence

- [x] 2.1 Tests: each spelling from the finding blocks after a confirm of the plain command; the identical retry passes; a spacing-only difference passes; an earlier `export GH_REPO` blocks for held-close
- [x] 2.2 Staged break: the old scans-only key, red for the spellings
- [x] 2.3 `scripts/confirm-tier-compare.py` hermetic and re-run against an `origin/main` binary

## 3. Docs

- [x] 3.1 `docs/configuration.md`, `CHANGELOG.md`
