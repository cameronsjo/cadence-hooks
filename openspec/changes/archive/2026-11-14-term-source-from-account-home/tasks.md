## 1. Guard

- [x] 1.1 Resolve the term-source path from `paths::account_home()`, not `HOME`, with a test-only stand-in for the passwd lookup
- [x] 1.2 Block a post when the term source exists but cannot be read; keep an absent, malformed or zero-term source inert
- [x] 1.3 Pin both with tests (seam and a real-binary run with `HOME` pointed at an empty directory) and stage the break back to `HOME`

## 2. Docs

- [x] 2.1 Stage the CHANGELOG.md bullet under [Unreleased]
