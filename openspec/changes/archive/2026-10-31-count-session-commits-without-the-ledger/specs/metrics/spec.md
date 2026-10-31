## MODIFIED Requirements

### Requirement: Per-session cost
`log-session-start` SHALL, on `SessionStart`, write the UTC time to `state/<session_id>.start`, and on `startup` or `clear` create an empty `state/commits/<session_id>/count`. `log-session` SHALL, on `SessionEnd`, consume the marker, scan the transcript, append a `sessions.jsonl` row with `repo`, `branch`, `reason`, `startTs`, `endTs`, `durationMs`, model costs, the commit count (`count`'s bytes, else `commits.jsonl`), and `grading`. Both MUST ignore other events and unsafe ids.

#### Scenario: Session ends after two commits
- **WHEN** a session with a start marker and two `commits.jsonl` rows ends
- **THEN** its row carries a `durationMs`, a commit count of 2, and a `grading` object, and the start marker is removed

#### Scenario: Counter outranks the ledger
- **WHEN** a session started with a commit counter ends with no commits and the ledger holds rows for its id
- **THEN** its row's commit count is 0 and `state/commits/<session>/` is removed

#### Scenario: Resumed after SessionEnd
- **WHEN** a session that already ended resumes (`source` `resume`) and ends again
- **THEN** no counter was created and its commit count comes from its `commits.jsonl` rows

#### Scenario: No start marker
- **WHEN** a session ends that has no `.start` marker
- **THEN** the row is written with `startTs` and `durationMs` null

#### Scenario: Wrong event
- **WHEN** `log-session` receives a `SessionStart` payload
- **THEN** it writes nothing
