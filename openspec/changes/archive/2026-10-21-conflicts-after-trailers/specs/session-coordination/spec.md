## MODIFIED Requirements

### Requirement: Commit provenance trailer nudge
On a Bash `git commit` whose message it can read and that lacks `Session-Id:`, `session warn-commit-provenance` SHALL nudge once per session with a ready-to-copy `Session-Id:`, `Model:`, `Harness:`, and `Machine:` block, omitting unresolvable lines. `Machine:` MUST be a salted hostname digest, or `cloud` under `CLAUDE_CODE_REMOTE`. An unreadable message, or one with the trailer, MUST draw no provenance nudge. It MUST NOT block.

#### Scenario: Commit without a trailer
- **WHEN** a session runs `git commit -m "fix: x"` for the first time
- **THEN** the hook nudges with a block containing `Session-Id: <this session's id>` and a `Machine:` line that is not the raw hostname

#### Scenario: Second commit in the same session
- **WHEN** the nudge already fired this session and another trailer-less commit runs
- **THEN** the hook exits 0 with no output

#### Scenario: Message from a file
- **WHEN** a session runs `git commit -F msg.txt` and `msg.txt` contains `Session-Id: abc`
- **THEN** the hook exits 0 with no output

## ADDED Requirements

### Requirement: Conflicted-merge commit keeps its conflicts block below the trailers
`session warn-commit-provenance` SHALL nudge on a `git commit --no-edit` that would finish a conflicted merge whose pending message (MERGE_MSG) has a trailer line above git's `# Conflicts:` block, and the nudge SHALL advise amending the landed commit before it is pushed, and only where that commit's message still shows the block. It MUST read only that plain shape and otherwise stay silent, MUST NOT echo the message, MUST NOT block, and MUST NOT use up the once-per-session provenance nudge.

#### Scenario: Finishing a conflicted merge with trailers
- **WHEN** a merge started with a message ending in `Session-Id:` and `Co-Authored-By:` lines stopped on a conflict, and a session runs `git commit --no-edit`
- **THEN** the hook exits 0 with a nudge that says the commit lands with the block below the trailers and names `git commit --amend --no-edit --cleanup=strip`

#### Scenario: The nudge says what strip drops
- **WHEN** the hook nudges for that merge
- **THEN** the nudge says `--cleanup=strip` drops every line that starts with `#`, and names `git commit --amend -F` on a copy of `git log -1 --format=%B` cut at the `# Conflicts:` line for a message that has other such lines

#### Scenario: The nudge advises an amend, not a second commit
- **WHEN** the hook nudges for that merge, which is context with no permission decision, so the commit has landed and MERGE_MSG is gone when the nudge is read
- **THEN** the nudge names no copy of MERGE_MSG and no `git commit --no-edit --cleanup=strip`

#### Scenario: The amend is conditional on HEAD still being the merge
- **WHEN** the hook nudges for that merge, and a later command in the same call may have moved HEAD (a commit, a branch switch, a merge abort), or the commit ran in another worktree
- **THEN** the nudge says to run the amend in the directory the commit ran in, and only if `git log -1 --format=%B` there still shows the `# Conflicts:` block, and otherwise to leave HEAD alone

#### Scenario: The cleanup is already asked for
- **WHEN** the same session runs `git commit --no-edit --cleanup=strip`
- **THEN** the hook adds no conflicts nudge

#### Scenario: An editor opens
- **WHEN** the same session runs `git commit --no-edit --edit`
- **THEN** the hook adds no conflicts nudge

#### Scenario: The command names its own message
- **WHEN** the same session runs `git commit --no-edit -m "Merge feat"`, or `git -C <dir> commit --no-edit`
- **THEN** the hook adds no conflicts nudge

#### Scenario: No trailers above the block
- **WHEN** the merge was started with `-m "fix: resolve the merge"` and a session runs `git commit --no-edit`
- **THEN** the hook adds no conflicts nudge
