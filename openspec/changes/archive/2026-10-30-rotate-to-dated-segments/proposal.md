## Why

Rotation renamed a ledger past its cap to `<name>.jsonl.1` and replaced any older `.1`, so every ledger, `commits` and `sessions` included, kept at most two generations and lost the rest on each rotation (cameronsjo/cadence-hooks#1585). The ledgers exist to answer questions about history, so a size cap must never cost a row (cameronsjo/cadence#2074).

## What Changes

- A ledger past the cap moves to a dated segment `<name>.<YYYYMMDDTHHMMSSZ>-<NNN>.jsonl` in the same directory, `<NNN>` counting rotations within that second, so names sort in time order. The move never replaces an existing file: it hard-links the live file to the segment name (which fails on an existing name) and then unlinks the live name once the link is confirmed to be the same file (undoing the link if the unlink fails), falling back to a rename onto a name checked free where hard links are unavailable.
- The non-blocking `flock`, the inode check, the fail-open `ledger_rotate_failed` row, and the `0600` mode are unchanged.
- `read_ledger` reads every segment of a ledger in time order and then the live file, and never through a symlink. `read_ledger_since` skips segments stamped before a window (fail-open and sweep counts); `read_ledger_recent` reads the newest segment and live (`log-commit`, `log-session`). `persist-plan-approval`'s bounded `plan-links.jsonl` lookup reads the newest segment's tail and the live tail.
- `doctor`'s large-ledger warning treats an oversized segment as it treated `.1`, and its remediation compresses the segment instead of deleting it.
- Nothing deletes a segment yet. Age-based archiving is cameronsjo/cadence-hooks#1590.

## Impact

- Code: `crates/metrics/src/common.rs`, `crates/session/src/persist_plan.rs`, `src/doctor.rs`, reader tests in `crates/metrics`.
- Readers outside this repo that read only the live file lose nothing on disk but see only rows since the last rotation; they read `<name>.*.jsonl` segments in name order, then the live file.
- `.1` was never in a release, so no `.1` file needs migrating.
