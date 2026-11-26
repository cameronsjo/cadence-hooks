## ADDED Requirements

### Requirement: Confirmed retry snoozes enforce-worktree
`enforce-worktree`'s primary-checkout block SHALL be in the confirm tier, keyed by the judged repo and the file (Edit, Write) or `git commit` (Bash), and its confirm line MUST say the pass unblocks the checkout for 30 minutes. A confirmed retry SHALL allow and write the same snooze marker and sidecar `dismiss-enforce-worktree --for 30m` writes.

#### Scenario: Confirmed edit arms the snooze
- **WHEN** an Edit in a primary checkout blocks in session S1 and S1 retries the same Edit
- **THEN** the retry is allowed with a `confirmed` bypass row, and the checkout's `enforce-worktree-snoozed-until` marker is set 30 minutes ahead

#### Scenario: Later edits ride the snooze
- **WHEN** after a confirmed retry, S1 edits another file in the same checkout
- **THEN** the edit is allowed as a `dismissal` bypass

#### Scenario: Another file before a confirmation
- **WHEN** an Edit of `a.rs` in a primary checkout blocks, and the next attempt edits `b.rs`
- **THEN** the second attempt blocks

### Requirement: Commits enforce-worktree does not confirm
A block about a command the guard could not read, a Bash command committing in more than one primary checkout, and a Bash command holding a commit whose target the guard could not read MUST NOT be confirmable: each attempt blocks with a line saying a retry will be blocked too.

#### Scenario: Commits into two repos
- **WHEN** one Bash command commits in two primary checkouts and is attempted again
- **THEN** every attempt blocks with `commits in more than one checkout` and neither checkout is snoozed

#### Scenario: A commit whose target is unread
- **WHEN** from a primary checkout, `git commit -am x && git -C "$OTHER" commit -am y` is attempted twice
- **THEN** both attempts block with `could not read` and the checkout is not snoozed
