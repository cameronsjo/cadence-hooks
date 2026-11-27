## 1. Merge gate

- [x] 1.1 `guard_gh_merge`: snapshot parse, `judge`, flags, block text; confirm tier.
- [x] 1.2 Unit tests for every fact, staleness, a closed PR, a mismatched snapshot, `--auto`.

## 2. Watch

- [x] 2.1 `watch_created_pr`: one github.com URL from stdout, session id check, bounded spawn.
- [x] 2.2 Unit tests.

## 3. Registration

- [x] 3.1 clap variants, `HOOKS` entries, `docs/hooks.md` rows, README count.
- [x] 3.2 `PENDING_WIRING_HOOKS` entries until the cadence monorepo wiring lands.

## 4. Later

- [ ] 4.1 Wire both in cadence-guardrails `hooks.json`; refresh the fixture; drop the pending entries.
- [ ] 4.2 Score the everyday-command corpus at head against `origin/main` (ADR-0046 rule 4) on a machine with the sibling checkouts.
