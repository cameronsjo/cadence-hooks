## 1. Behavior

- [x] 1.1 Skip `<synthetic>` assistant records in `scan_tokens` after the marker gate (`crates/metrics/src/scan_tokens.rs`)
- [x] 1.2 Write `codeMode` on the `sessions.jsonl` row from the in-memory transcript (`crates/metrics/src/log_session.rs`)

## 2. Tests and docs

- [x] 2.1 Synthetic records with non-zero usage are excluded; a synthetic marker still resolves; a synthetic-only range is empty
- [x] 2.2 `codeMode` true, false, null and subagent cases; the record carries it
- [x] 2.3 Stage the CHANGELOG.md bullets under [Unreleased]
