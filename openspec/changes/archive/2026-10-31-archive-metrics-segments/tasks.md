## 1. Archive

- [x] 1.1 `metrics rotate` with the run lock, retention by segment stamp, and monthly gzip archives
- [x] 1.2 Manifest-protected moves: temp-and-rename archive growth, verify before delete, recovery of a leftover manifest
- [x] 1.3 `denials` daily rollup, idempotent per segment
- [x] 1.4 Stale per-session state sweep that never follows a symlink
- [x] 1.5 `state/rotate.last-success` after a complete run; failures as `metrics_rotate_failed` rows

## 2. Quarantine and reader

- [x] 2.1 `--quarantine-test-rows [--dry-run]`, moving the live file aside first, with the same manifest discipline
- [x] 2.2 `metrics cat` over archives, segments and live, printing a half-moved segment once

## 3. Wiring

- [x] 3.1 Daily SessionStart run inside `log-session-start`, with a 2 s budget, failing open
- [x] 3.2 `doctor` warnings for a stale last success and oversized archives
- [x] 3.3 `CADENCE_BYPASS` exemption for `metrics rotate` and `metrics cat`

## 4. Tests and docs

- [x] 4.1 Retention boundaries, idempotent re-run, a kill at each step, concurrent appenders, gzip round trip, modes, symlinks, `cat` order and dedupe, dry run
- [x] 4.2 Stage the recovery break once and confirm the tests go red
- [x] 4.3 Update `docs/configuration.md` and stage the CHANGELOG.md bullets under [Unreleased]
