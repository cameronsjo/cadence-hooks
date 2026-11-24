## Why

A `schema_drift` row in `failopen.jsonl` says only `tool_input: object did not match its typed shape` and names the first hook wired on the matcher. `persist-plan-approval` is the one PostToolUse entry with `matcher: "*"`, so every drift on any tool is attributed to it, and nine such rows since 2026-10-14 cannot say which tool or field drifted. The row is core drift telemetry (cameronsjo/cadence-hooks#364) that the security hooks rely on, so it must stay on and become readable.

## What Changes

- Each `schema_drift` row gains `toolName`: the payload's tool name when it is 1 to 64 ASCII letters, digits or `_`, else `"other"`, and `null` when the payload has none.
- Each row gains `field`: the alphabetically first modeled field of `tool_input` or `tool_response` whose value fails its typed shape on its own, or the key itself when only the combination fails (duplicate aliases). Static names only, never values.
- Detection, the once-per-process latch, the `error` text and the hook attribution are unchanged. The row stays `schemaVersion` 2; the fields are additive.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `hook-protocol`: "Schema drift rows name the tool and field" is added.

## Impact

- `crates/core/src/lib.rs` (`schema_drift` returns `SchemaDrift { key, field }`), `crates/metrics/src/log_failopen.rs` (`log_failopen_with`), `src/dispatch.rs` (`log_schema_drift`, `drift_tool_label`).
- Readers of `failopen.jsonl` see two more keys on `schema_drift` rows only.
