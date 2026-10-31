## 1. Rotation

- [x] 1.1 Rotate to a dated segment that never replaces an existing file, keeping the `flock` and inode check
- [x] 1.2 Make the stamp injectable so the collision and failure paths are tested deterministically

## 2. Readers

- [x] 2.1 `read_ledger` reads every segment in time order, then the live file
- [x] 2.2 `plan-links.jsonl` lookup reads the newest segment's tail
- [x] 2.3 `doctor` recognizes segments and compresses rather than deletes an oversized one

## 3. Tests and docs

- [x] 3.1 Pin segment naming and ordering, repeated rotations, a taken name, concurrent appends across several rotations
- [x] 3.2 Stage the overwrite once and confirm the regression test goes red
- [x] 3.3 Update `docs/configuration.md` and stage the CHANGELOG.md bullet under [Unreleased]
