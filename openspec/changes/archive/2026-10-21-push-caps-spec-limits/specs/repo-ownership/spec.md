## ADDED Requirements

### Requirement: Literal `git -C` push loops
A command of at most 4096 bytes that begins with `for` and is one loop over literal words, whose every push is `git -C DIR push REMOTE`, SHALL have each iteration's remote resolved and owner-checked by `guard-push-remote` instead of meeting the loop caps, for up to four directories and eight pushes. A larger loop, or one with anything before it, SHALL be judged as any other loop.

#### Scenario: Five remotes in a literal `git -C` loop
- **WHEN** the command is `for d in d1; do git -C $d push r1 main; git -C $d push r2 main; git -C $d push r3 main; git -C $d push r4 main; git -C $d push r5 main; done` and each remote is owned
- **THEN** the hook exits 0

#### Scenario: Comment before a literal loop
- **WHEN** a `# push all` line comes before the loop in "Five remotes in a literal `git -C` loop"
- **THEN** the hook exits 2 with `too many push-loop remotes to verify`

## MODIFIED Requirements

### Requirement: How many pushes the push guard checks
`guard-push-remote` SHALL block over four non-URL remotes in a loop the parser reads, over four directory and remote pairs outside the command's last directory, or over four directory and remote pairs that `-c` config or an earlier config write names. A literal `git -C` push loop SHALL be checked per iteration instead, as "Literal `git -C` push loops" says.

#### Scenario: Pushes in five directories
- **WHEN** the command is `git -C d1 push origin main && git -C d2 push origin main && git -C d3 push origin main && git -C d4 push origin main && git -C d5 push origin main`
- **THEN** the hook exits 2 with `too many push directories to verify`

#### Scenario: Five remotes in a loop
- **WHEN** the command is `for b in a b; do git push r1 $b; git push r2 $b; git push r3 $b; git push r4 $b; git push r5 $b; done`
- **THEN** the hook exits 2 with `too many push-loop remotes to verify`

#### Scenario: Five config-named remotes
- **WHEN** the command is `git -c remote.pushDefault=r1 push && git -c remote.pushDefault=r2 push && git -c remote.pushDefault=r3 push && git -c remote.pushDefault=r4 push && git -c remote.pushDefault=r5 push` and each remote is owned
- **THEN** the hook exits 2 with `too many push remotes to verify`
