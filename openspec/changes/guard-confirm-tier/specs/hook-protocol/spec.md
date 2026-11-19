## ADDED Requirements

### Requirement: Confirm tier
A confirm-tier guard SHALL block the first attempt at an action (exit 2) with its reason and a line beginning `Are you sure?`, and SHALL allow the next attempt at the same action from the same `session_id` and `agent_id` within ten minutes, once. The pair is keyed by hook and a normalized action the guard names, never raw command text. A pass MUST write a `bypasses.jsonl` `used` row with kind `confirmed` and mechanism `confirm-retry`.

#### Scenario: Second attempt passes once
- **WHEN** a confirm-tier guard blocks an action in session S1, and S1 attempts the same action again in a new tool call within ten minutes
- **THEN** the second attempt is allowed and `bypasses.jsonl` gains a `used` row with `"kind":"confirmed"`; a third attempt blocks again

#### Scenario: Nothing else inherits the pass
- **WHEN** after a first attempt in S1, another session, a subagent of S1 (same `session_id`, its own `agent_id`), or S1 with a different action makes an attempt
- **THEN** each blocks with the `Are you sure?` line

#### Scenario: Expired attempt
- **WHEN** the retry comes more than ten minutes after the blocked attempt
- **THEN** it blocks and starts a new ten-minute window

#### Scenario: Several processes of one tool call
- **WHEN** a guard wired twice under one matcher runs twice for the blocked call, and twice for the retry
- **THEN** both processes of the blocked call block, both processes of the retry allow, and `bypasses.jsonl` gains one row

### Requirement: Confirm tier fail directions
A confirm-tier block SHALL NOT pass, and SHALL end with `A second attempt will be blocked too:` and the reason, when the payload has no `session_id` or no usable `tool_use_id`, when the marker directory is not private, or when the marker cannot be written. An unreadable, malformed, symlinked, expired or future-stamped marker MUST count as absent, never as a confirmation.

#### Scenario: No session id
- **WHEN** a confirm-tier guard blocks a payload with no `session_id`, and the same payload is sent again
- **THEN** both attempts block with `A second attempt will be blocked too`

#### Scenario: Marker write fails
- **WHEN** the confirmation cannot be recorded
- **THEN** the guard blocks with `the confirmation could not be recorded`, and no attempt passes until a write succeeds

### Requirement: Phone-usable hard blocks
A hard block whose own escape needs the operator at a keyboard SHALL end with the sentence telling the model to stop and tell the operator in chat what was blocked, why, and what they can approve: `git-safety`'s dangerous-operation block, `prevent-secret-writes`' file blocks, `prevent-secret-push`'s found-secret block, `guard-sops-decrypt`, `guard-runbook-scrub`, `guard-gh-dangerous`'s repo delete, and `guard-gh-write`'s URL-argument fix. What these guards block is unchanged.

#### Scenario: Dangerous git operation
- **WHEN** `cadence git-safety` blocks `git reset --hard HEAD~1`
- **THEN** stderr ends with `tell them in chat what was blocked, why, and what they can approve.`
