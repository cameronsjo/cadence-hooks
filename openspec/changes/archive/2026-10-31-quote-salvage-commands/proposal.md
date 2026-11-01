## Why

The fourth review round on cameronsjo/cadence-hooks#1600 (`metrics rotate`, cameronsjo/cadence-hooks#1590) found two problems in the salvage commands:

- They quoted the archive directory but not the archive name, so a name holding `$(…)` or starting with `-` became part of a pasted command.
- A second run replaced the first `.damaged` copy, losing the rows still undecoded in it.

The same round asked for two tighter recovery checks: an `archive` manifest must name its segment's own month, and the archive tail must match the segment's bytes rather than the manifest's own hash.

## What Changes

- Every path in the salvage commands is one single-quoted word, and every name starts with `./`. The chain stops non-zero, moving nothing, when `<name>.damaged` already exists.
- `metrics cat` shows the archive name through `display_safe` in its stderr line.
- An `archive` manifest must name its segment's own monthly archive. Recovery deletes the segment only when the segment's own bytes hash to what the archive tail decodes to.
- Lock files are opened `O_NONBLOCK` and must be regular files, so a FIFO under the lock name cannot hang `metrics cat`.
- `doctor`'s fix names `--quarantine-test-rows` while no quarantine record exists.

## Impact

- Code: `crates/metrics/src/rotate.rs`, `crates/metrics/src/ledger_cat.rs`, `src/doctor.rs`, tests.
