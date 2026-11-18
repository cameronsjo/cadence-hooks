## MODIFIED Requirements

### Requirement: In-flight plans surfaced at session start
`session start` SHALL add a fixed-size line when the repo's plans folder holds plans with frontmatter `status` `in-flight` or `blocked`, pointing at `cadence-hooks session plans`. Plans without a `status:` key MUST be skipped. The scan MUST be bounded to the newest files, skip symlinks, and say `At least` when cut. A second line SHALL name up to five in-flight plans that are uncommitted. Both MUST appear even when registration fails.

#### Scenario: Resuming into in-flight work
- **WHEN** a session starts in a repo with one in-flight plan in `docs/plans/`
- **THEN** the start nudge contains `1 in-flight plan in docs/plans/` and names `cadence-hooks session plans`

#### Scenario: Plan without a status key
- **WHEN** the only plan in `docs/plans/` has frontmatter with `date:` but no `status:`
- **THEN** no plan line appears

#### Scenario: Untracked plan
- **WHEN** an in-flight plan in `docs/plans/` is untracked
- **THEN** the start nudge contains `Uncommitted living plan(s):` naming it

#### Scenario: Repo declares its own plans folder
- **WHEN** the repo's `.claude/settings.json` `env` block sets `CADENCE_PLANS_DIR` to `Meta/docs/plans` and one blocked plan is there
- **THEN** the start nudge contains `1 in-flight plan in Meta/docs/plans/ (1 blocked)` and no `docs/plans/` folder is created

### Requirement: Plans CLI action
`session plans` SHALL list every in-flight and blocked plan in the repo's plans folder (the one `session start` scans) with its next step, branch, and PR, with no cap on file count. It SHALL exit 0 for any complete answer, including none, and exit 2 outside a git repository or when an entry could not be listed or read, naming the root or each failed entry on stderr while printing what it found. It MUST work under `CADENCE_BYPASS=1`.

#### Scenario: Outside a repository
- **WHEN** `cadence-hooks session plans` runs outside a git repository
- **THEN** it exits 2 with `session plans: not inside a git repository.` and the scanned root on stderr

#### Scenario: No plans in flight
- **WHEN** `cadence-hooks session plans` runs in a repo with no in-flight or blocked plans
- **THEN** it exits 0

#### Scenario: Repo declares its own plans folder
- **WHEN** `CADENCE_PLANS_DIR` is `Meta/docs/plans` and one in-flight plan is there
- **THEN** the list starts `1 in-flight plan in Meta/docs/plans/:` and names it

## ADDED Requirements

### Requirement: Plan readers use the repo's plans folder
The `session start` plan lines, `session plans`, and the plan guards SHALL read the repo settings' `CADENCE_PLANS_DIR` when it passes the persist hook's path check and resolves inside the checkout, else `docs/plans/`. When a configured folder is in use and `docs/plans/` also exists, both SHALL be read, so plans written before the setting finish in place. A reader MUST NOT create a folder, and its output MUST name every folder it read.

#### Scenario: Plans left in docs/plans after the setting
- **WHEN** `CADENCE_PLANS_DIR` is `.claude/plans`, and one in-flight plan is there and one in `docs/plans/`
- **THEN** `session plans` starts `2 in-flight plans in .claude/plans/ and docs/plans/:`

#### Scenario: Refused folder
- **WHEN** `CADENCE_PLANS_DIR` is `../outside` or names a symlink that resolves outside the checkout
- **THEN** the readers scan `docs/plans/`

### Requirement: Plans folder edge cases for readers
A configured folder longer than 120 bytes, or spelled other than as it is on disk (through a symlink, or in another letter case), SHALL fall back to `docs/plans/`. In a linked worktree of the session's repo, the readers SHALL read the session checkout's settings after the worktree's, as the persist hook does. The tick nudge, the ready-flip warning, and the commit-time unstaged-plan check MUST skip a plan git ignores, since their advice is to commit it.

#### Scenario: Gitignored plans folder
- **WHEN** `CADENCE_PLANS_DIR` is a gitignored `.claude/plans` holding the branch's in-flight plan, and three commits land without touching it
- **THEN** `session nudge-plan-tick` exits 0 with no output

#### Scenario: Symlink to docs/plans
- **WHEN** `CADENCE_PLANS_DIR` is `Notes/plans` and `Notes` is a symlink to `docs`
- **THEN** the readers scan only `docs/plans`

#### Scenario: Overlong folder name
- **WHEN** `CADENCE_PLANS_DIR` is a plain-charset value of 1,000 bytes
- **THEN** the readers scan `docs/plans/` and the SessionStart pointer does not contain the value
