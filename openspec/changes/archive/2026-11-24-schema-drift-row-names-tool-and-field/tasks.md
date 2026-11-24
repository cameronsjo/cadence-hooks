## 1. Behavior

- [x] 1.1 Return the drifted key and its first mistyped field from `schema_drift` (`crates/core/src/lib.rs`)
- [x] 1.2 Write `toolName` (charset-checked) and `field` on each `schema_drift` row (`src/dispatch.rs`, `crates/metrics/src/log_failopen.rs`)

## 2. Tests and docs

- [x] 2.1 Row tests for a mistyped `tool_input` field, a mistyped `tool_response` field, an unplain tool name, and a matching payload
- [x] 2.2 Stage the CHANGELOG.md bullet under [Unreleased]
