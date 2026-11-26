## MODIFIED Requirements

### Requirement: Confirmed retry snoozes enforce-worktree
`enforce-worktree`'s primary-checkout block SHALL be in the confirm tier, keyed by the judged repo and the file (Edit, Write) or the whole command (Bash). Its confirm line MUST say the confirmed retry switches enforce-worktree off for that checkout for 30 minutes, for every session working in it, and MUST NOT say the pass counts only for this session. A confirmed retry SHALL allow and write the same snooze marker and sidecar `dismiss-enforce-worktree --for 30m` writes.

#### Scenario: Confirmed edit arms the snooze
- **WHEN** an Edit in a primary checkout blocks in session S1 and S1 retries the same Edit
- **THEN** the retry is allowed with a `confirmed` bypass row, and the checkout's `enforce-worktree-snoozed-until` marker is set 30 minutes ahead

#### Scenario: Later edits ride the snooze
- **WHEN** after a confirmed retry, S1 edits another file in the same checkout
- **THEN** the edit is allowed as a `dismissal` bypass

#### Scenario: Another file before a confirmation
- **WHEN** an Edit of `a.rs` in a primary checkout blocks, and the next attempt edits `b.rs`
- **THEN** the second attempt blocks

#### Scenario: The confirm line names the checkout-wide snooze
- **WHEN** an Edit in a primary checkout blocks with the `Are you sure?` line
- **THEN** the line says the retry switches enforce-worktree off for this checkout for 30 minutes, for every session working in it

## ADDED Requirements

### Requirement: Bash confirmations key on the whole command
For a Bash block, the key SHALL hold the whole command, every segment, with runs of spaces and tabs collapsed and the ends trimmed, beside the judged repo. Only the identical command in the same checkout SHALL pair; any other difference (an added `export`, a `cd`, a link, another commit message) MUST be a new first attempt. The confirm is per command; the snooze a confirmed retry arms is per repository.

#### Scenario: The identical command again
- **WHEN** `git commit -m x` blocks in a primary checkout and the next attempt is `git  commit -m x`
- **THEN** the retry is allowed with a `confirmed` bypass row

#### Scenario: Another commit message
- **WHEN** `git commit -am x` blocks and the next attempt is `git commit -am 'x, reworded'`
- **THEN** the second attempt blocks with the `Are you sure?` line

#### Scenario: A quoted export into another checkout
- **WHEN** `git commit -am x` blocks in primary A and the next attempt is `export GIT_DIR="<B>\.git"; git commit -am x` with B another primary
- **THEN** the second attempt blocks, and A is not snoozed

#### Scenario: A link made in the command
- **WHEN** `git commit -am x` blocks in primary A and the next attempt links a directory under A to primary B and commits through the link
- **THEN** the second attempt blocks, and A is not snoozed
