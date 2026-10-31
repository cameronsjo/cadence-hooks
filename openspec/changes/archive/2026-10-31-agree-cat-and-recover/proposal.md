## Why

The fifth review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found that `metrics cat` and recovery judged a leftover manifest differently. In one state recovery refused the move, but `cat` skipped the segment, so its rows vanished from `cat`.

The round also found three more problems:

- A row appended to a segment after its archive read wedged recovery, and `cat` printed the archived rows twice.
- A quarantine manifest could point at an unrelated test-row member.
- A salvage command built from a name holding invisible characters would, once displayed, name a different file.

## What Changes

- One shared judgement (`move_state`) decides whether a manifest's move is proven complete for its segment. Recovery acts on it and `cat` prints by it. An unproven move leaves the segment printing as it is.
- An archived member must decode to exactly the segment's first `source_len` bytes, normalized. A quarantine member must be exactly those bytes' test rows. Bytes appended after `source_len` stay in the segment, after the kept rows for a quarantine.
- When an archive's name or directory differs once shown through `display_safe`, the message gives no commands, only a rename-by-hand instruction.
- `try_lock`'s refusal of a non-regular lock file is now tested.

## Impact

- Code: `crates/metrics/src/rotate.rs`, `crates/metrics/src/ledger_cat.rs`, tests.
