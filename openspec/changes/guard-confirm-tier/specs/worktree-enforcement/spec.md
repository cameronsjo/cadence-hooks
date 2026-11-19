## ADDED Requirements

### Requirement: Confirmed retry snoozes enforce-worktree
`enforce-worktree`'s primary-checkout block SHALL be in the confirm tier, keyed by the judged repo and the file (Edit, Write) or `git commit` (Bash), and its confirm line MUST say the pass unblocks the checkout for 30 minutes. A confirmed retry SHALL allow and write the same snooze marker and sidecar `dismiss-enforce-worktree --for 30m` writes. A block about a command the guard could not read MUST NOT be in the tier.

#### Scenario: Confirmed edit arms the snooze
- **WHEN** an Edit in a primary checkout blocks in session S1 and S1 retries the same Edit
- **THEN** the retry is allowed with a `confirmed` bypass row, and the checkout's `enforce-worktree-snoozed-until` marker is set 30 minutes ahead

#### Scenario: Later edits ride the snooze
- **WHEN** after a confirmed retry, S1 edits another file in the same checkout
- **THEN** the edit is allowed as a `dismissal` bypass

#### Scenario: Another file before a confirmation
- **WHEN** an Edit of `a.rs` in a primary checkout blocks, and the next attempt edits `b.rs`
- **THEN** the second attempt blocks
