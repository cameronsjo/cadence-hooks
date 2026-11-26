## Why

Claude Code's experimental Code Mode runs every tool call from inside one `REPL` script. Hooks still fire for the inner calls, but nothing in the ledgers says a session ran in Code Mode, and Code Mode also turns off Claude Code's own telemetry, so the ledgers are the only record. Code Mode transcripts also carry many locally-synthesized assistant records with `model: "<synthetic>"`; the token scan counted them, so every Code Mode `commits` and `sessions` row listed `<synthetic>` in `byModel` and `unpricedModels` and reported a pricing gap that does not exist (cameronsjo/cadence-hooks#1682).

## What Changes

- `sessions.jsonl` rows gain `codeMode`: `true` when the transcript has a `{"type":"repl-mode","replMode":true}` row, `null` when it has none but contains a `REPL` tool call (the row moved or changed shape), `false` otherwise. Read from the transcript string `log-session` already holds; no second read.
- The transcript token scan adds no tokens and no model bucket for assistant records whose model is `<synthetic>`, so they leave `tokens`, `byModel`, `unpricedModels` and `costUsd` on every row the scan feeds (`commits`, `sessions`, `subagents`, `metrics price`). They still count as scanned and still move `lastMessageId`, so a second commit in the same Code Mode turn, whose range holds only synthetic records, still gets a `commits` row (zero tokens, empty `byModel`, `model` `unknown` where it was `<synthetic>`).
- `TOKEN_RECORD_SCHEMA_VERSION` is unchanged: the field is additive.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `metrics`: "Sessions record Code Mode" and "Synthetic records are not priced" are added.

## Impact

- `crates/metrics/src/log_session.rs`, `crates/metrics/src/scan_tokens.rs`, `crates/metrics/src/session_grade.rs` (`SYNTHETIC_MODEL` shared).
- A `commits` or `sessions` reader that summed `byModel` sees no `<synthetic>` bucket; its tokens were zero in every observed record.
