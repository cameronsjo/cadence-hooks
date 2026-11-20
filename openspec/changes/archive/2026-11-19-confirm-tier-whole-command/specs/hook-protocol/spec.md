## MODIFIED Requirements

### Requirement: Confirm tier
A confirm-tier guard SHALL block the first attempt at an action (exit 2) with its reason and a line beginning `Are you sure?`, and SHALL allow the next attempt at the same action from the same `session_id` and `agent_id` within ten minutes, once. The pair is keyed by hook and an action the guard names: what it read, or the whole command normalized for spacing. A pass MUST write a `bypasses.jsonl` `used` row with kind `confirmed` and mechanism `confirm-retry`.

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

#### Scenario: A whole-command guard names the retry
- **WHEN** a guard keyed on the whole command arms a confirmation
- **THEN** its armed line says to run the identical command again, and that extra spaces or tabs between words are ignored

### Requirement: One confirmed row per confirmation
A confirmation SHALL write exactly one `confirmed` row, however many processes of the hook run for the passing call. The row records that the confirm-tier guard let the action through, not that the call ran: another hook on the same call MAY still block it, and the confirmation is spent either way; for `enforce-worktree` the 30-minute snooze is armed by then too.

#### Scenario: Two processes of the retry at once
- **WHEN** two processes of the retry start together and both read the blocked attempt's marker before either records the pass
- **THEN** both allow, and `bypasses.jsonl` gains one row

#### Scenario: Another hook blocks the confirmed call
- **WHEN** a confirm-tier guard passes a retry and another hook blocks the same tool call
- **THEN** the `confirmed` row stays, and the next attempt at the action blocks with the `Are you sure?` line

#### Scenario: Another hook blocks a confirmed enforce-worktree retry
- **WHEN** `enforce-worktree` passes a confirmed retry and another hook blocks the same tool call
- **THEN** the checkout's 30-minute snooze stays armed
