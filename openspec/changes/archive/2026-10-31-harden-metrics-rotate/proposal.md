## Why

Two reviews of cameronsjo/cadence-hooks#1600 (the `metrics rotate` change for cameronsjo/cadence-hooks#1590) found gaps. A damaged archive was appended to, so the rows after the damage became unreadable while their segments were deleted. `metrics cat` read without the rotate lock, so a concurrent rotate could print a row 0 or 2 times. The SessionStart run had no bound on one large segment. Off Unix, `rotate` ran with no lock at all.

## What Changes

- `metrics rotate` and `--quarantine-test-rows` refuse to grow an archive that does not decode to the end. The move fails with a `metrics_rotate_failed` row, the segment stays, and the archive is left untouched.
- `metrics cat` holds a shared `flock` on `state/rotate.lock` for the whole read. A rotate that starts meanwhile cannot take its exclusive lock and skips; the SessionStart run stays non-blocking.
- The SessionStart run skips segments over twice the rotation cap (32 MiB at the default cap) and leaves them for a hand run. The day marker is written before the run starts, so a failed or skipped run waits for the next day.
- Off Unix, `metrics rotate` and `--quarantine-test-rows` exit 1 without changing anything, and the SessionStart run does nothing.
- The run lock retries for up to 250 ms. A child process forked by another thread briefly shares the lock, and before the retry that made the lock look held.
- Recovery accepts a manifest only when its `archive` names that ledger's monthly archive or the test-row archive, and it decodes at most the segment length plus 1 MiB when checking an archive member.
- `--since` compares parsed `ts` instants, so fractional seconds and offsets compare correctly.

## Impact

- Code: `crates/metrics/src/rotate.rs`, `crates/metrics/src/ledger_cat.rs`, tests.
