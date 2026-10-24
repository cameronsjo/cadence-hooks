## 1. Guard

- [x] 1.1 Read a bare `mktemp` substitution as an operand outside the vault in the operand walk, with the call's options and template checked
- [x] 1.2 Pass the segments that make or fill the path: its assignment, the call, a redirect to it, and a `trap` that only deletes variables
- [x] 1.3 Keep the block for `TMPDIR`, a reassignment, an assignment that may not have run, a suffix, and a moving sibling
- [x] 1.4 Pin the allowed and kept shapes, and mutate each check once

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
