## Why

The sixth review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found two problems.

- A crash between recovery's segment rewrite and the manifest removal wedged recovery for good: the segment no longer started with the archived original, so every later run failed as unproven.
- A segment read while its last row was half written had the fragment closed with a newline, splitting one row into two unparseable lines.

It also found that the forward archive path deleted the segment without re-reading it, so a late append could be lost. Separately, a directory that is not UTF-8 displayed lossily in the salvage commands.

## What Changes

- Before a move rewrites a segment, the manifest records the sha256 and length of exactly what the segment will hold (`final_sha256`, `final_len`). A segment that matches that record exactly reads as finished.
- Forward moves take only bytes up to the last newline. A torn last row stays in the segment. A pending move with bytes after a prefix that ends mid-row is unproven.
- Both forward paths finish through the same judgement recovery uses, re-reading the segment, so rows appended since the read stay.
- A directory that is not UTF-8 gets no salvage commands.

## Impact

- Code: `crates/metrics/src/rotate.rs`, tests.
