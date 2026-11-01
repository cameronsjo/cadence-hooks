## Why

The seventh review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found two problems:

- An old segment whose last bytes never got a newline was never archived. After the whole rows moved, the fragment stayed in the segment forever, and every later run skipped it.
- The specs, docs and comments overstated what happens to a row a writer finishes during a move.

It also found two smaller problems:

- Rows left behind in a `denials` segment never reached the rollup when a later move archived them.
- The quarantine record could count a row the move did not take.

## What Changes

- A torn last row is held back only while its segment changed within the last minute. An older segment's last row moves with the rest, closed with a newline.
- The wording now says what is true: a writer still holding the file open after the move re-reads it loses its later writes. The exposure is the quarantine's freshly moved live file within its grace wait.
- Rollup rows carry `movedSha256`, and idempotence is keyed on (segment, moved bytes), so a segment moved twice rolls each part up once.
- Quarantine counts come from the bytes that move.

## Impact

- Code: `crates/metrics/src/rotate.rs`, tests.
