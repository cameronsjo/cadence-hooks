## 1. Guard

- [x] 1.1 Read a bare `mktemp` substitution, quoted or not, as an operand that holds no vault file in the operand walk
- [x] 1.2 Pass the segments that make or fill the path: its assignment, the call, a redirect to it, and a `trap` that hands its commands only variables
- [x] 1.3 Keep the block for a reassignment (a bare `*` included), an assignment that may not have run, a suffix, and a sibling that is not inert
- [x] 1.4 Pin the allowed and kept shapes, and mutate each check once

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
