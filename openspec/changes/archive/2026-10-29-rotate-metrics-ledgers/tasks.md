## 1. Rotation

- [x] 1.1 Rotate a ledger to `.1` in `open_ledger` when it is at or past the cap, under a non-blocking `flock` and an inode check
- [x] 1.2 Read the cap from `CADENCE_METRICS_MAX_BYTES` (16 MiB default, `0` off)
- [x] 1.3 Record a rotation error in `failopen.jsonl` without recursing, and still append

## 2. Readers

- [x] 2.1 Add `read_ledger` (`.1` then live) and use it in the fail-open and sweep counts, the bypass summary, `log-commit` and `log-session`
- [x] 2.2 Read the `.1` tail in the `plan-links.jsonl` lookup
- [x] 2.3 Reword `doctor`'s large-ledger warning for rotation

## 3. Tests and docs

- [x] 3.1 Pin the cap, the rename, the readers, the stale-handle case and concurrent appends
- [x] 3.2 Document `CADENCE_METRICS_MAX_BYTES` in `docs/configuration.md`
- [x] 3.3 Stage the CHANGELOG.md bullets under [Unreleased]
