## MODIFIED Requirements

### Requirement: Subagent lifecycle
`log-subagent` SHALL append a `subagents.jsonl` row for each `SubagentStart` and each `SubagentStop` that names an agent type, with `event`, the session, agent, and parent ids, `cwd`, `transcriptPath`, and `durationMs`. A Stop with no payload `durationMs` SHALL take it from the Start. On `SubagentStop` it SHALL add `model`, `tokens`, `byModel`, `unpricedModels`, and `costUsd` from the agent's transcript, `null` when absent.

#### Scenario: Read-only reviewer finishes
- **WHEN** a `SubagentStop` arrives and the agent's transcript has usage
- **THEN** the row carries a numeric `costUsd`

#### Scenario: Agent transcript not flushed
- **WHEN** a `SubagentStop` arrives and the agent's transcript does not exist
- **THEN** the row is written with `costUsd` `null`, not `0`

#### Scenario: Harness side agent
- **WHEN** a `SubagentStop` arrives with an empty or absent agent type
- **THEN** no row is written

#### Scenario: Duration from the Start
- **WHEN** a typed `SubagentStart` and later its `SubagentStop` arrive and the Stop carries no `duration_ms`
- **THEN** the Stop row's `durationMs` is the milliseconds between them and the Start marker is removed

#### Scenario: Unrelated event
- **WHEN** `log-subagent` receives a `SessionEnd` payload
- **THEN** it writes nothing


## ADDED Requirements

### Requirement: Per-session state is cleared at SessionEnd
`log-session` SHALL remove `<state>/subagents/<session>/` and `<state>/bypass/<session>/` at `SessionEnd` for a session id safe in a path, and leave every other session's state alone.

#### Scenario: Session ends with markers
- **WHEN** a session with a pending subagent Start marker and a bypass claim ends
- **THEN** both directories for that session are gone and another session's markers remain
