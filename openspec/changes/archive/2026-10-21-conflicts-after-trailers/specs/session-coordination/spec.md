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
`session warn-commit-provenance` SHALL nudge, naming `git commit --no-edit --cleanup=strip`, on a `git commit --no-edit` that would finish a conflicted merge whose pending message (MERGE_MSG) has a trailer line above git's `# Conflicts:` block. It MUST read only that plain shape and otherwise stay silent, MUST NOT echo the message, MUST NOT block, and MUST NOT use up the once-per-session provenance nudge.

#### Scenario: Finishing a conflicted merge with trailers
- **WHEN** a merge started with a message ending in `Session-Id:` and `Co-Authored-By:` lines stopped on a conflict, and a session runs `git commit --no-edit`
- **THEN** the hook exits 0 with a nudge naming `git commit --no-edit --cleanup=strip`

#### Scenario: The cleanup is already asked for
- **WHEN** the same session runs `git commit --no-edit --cleanup=strip`
- **THEN** the hook adds no conflicts nudge

#### Scenario: The command names its own message
- **WHEN** the same session runs `git commit --no-edit -m "Merge feat"`, or `git -C <dir> commit --no-edit`
- **THEN** the hook adds no conflicts nudge

#### Scenario: No trailers above the block
- **WHEN** the merge was started with `-m "fix: resolve the merge"` and a session runs `git commit --no-edit`
- **THEN** the hook adds no conflicts nudge
