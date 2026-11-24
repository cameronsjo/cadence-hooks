## ADDED Requirements

### Requirement: Sessions record Code Mode
A `sessions.jsonl` row SHALL carry `codeMode`. It MUST be `true` when the transcript has a row with `type` `repl-mode` and `replMode` `true`, `null` when it has no such row but contains a `REPL` tool call, and `false` otherwise. It MUST be read from the transcript `log-session` already scanned, with no second read.

#### Scenario: Code Mode session
- **WHEN** a session whose transcript holds `{"type":"repl-mode","replMode":true}` ends
- **THEN** its `sessions.jsonl` row has `codeMode` `true`

#### Scenario: Ordinary session
- **WHEN** a session whose transcript has no `repl-mode` row and no `REPL` tool call ends
- **THEN** its row has `codeMode` `false`

#### Scenario: Row format moved
- **WHEN** a transcript has a `REPL` tool call but no `repl-mode` row
- **THEN** the row has `codeMode` `null`

### Requirement: Synthetic records are not priced
The transcript token scan SHALL add nothing to `tokens`, `byModel`, `unpricedModels` or `costUsd` for assistant records whose `model` is `<synthetic>`. Such a record MUST still count as scanned and MAY be `lastMessageId`, so a range holding only synthetic records yields a zero-token row rather than none. A marker naming a synthetic record MUST resolve.

#### Scenario: Code Mode commit
- **WHEN** a commit's range holds priced assistant records and `<synthetic>` records
- **THEN** the `commits.jsonl` row's `unpricedModels` does not list `<synthetic>`

#### Scenario: Second commit in one Code Mode turn
- **WHEN** a commit's range after the previous marker holds only `<synthetic>` records
- **THEN** a `commits.jsonl` row is still written, with zero tokens and an empty `byModel`
