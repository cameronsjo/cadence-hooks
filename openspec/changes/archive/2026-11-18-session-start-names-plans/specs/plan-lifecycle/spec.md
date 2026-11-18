## MODIFIED Requirements

### Requirement: In-flight plans surfaced at session start
`session start` SHALL add a bounded block when the plans folder holds `in-flight` or `blocked` plans: the counts and up to three plans (blocked first, then newest) as `session plans` lines, marked as data. When it leaves plans out it SHALL say how many and name `cadence-hooks session plans`. Plans without `status:` MUST be skipped. The scan MUST be bounded, skip symlinks, and say `At least` when cut. A second line SHALL name up to five uncommitted plans. Both MUST survive a failed registration.

#### Scenario: Resuming into in-flight work
- **WHEN** a session starts in a repo with one in-flight plan in `docs/plans/`
- **THEN** the start nudge contains `1 in-flight plan in docs/plans/` and that plan's slug and `next:` step

#### Scenario: More plans than the block names
- **WHEN** a session starts in a repo with six in-flight plans, one of them blocked
- **THEN** the block names the blocked plan and the two newest others, and contains `… 3 more not shown: `cadence-hooks session plans` lists every plan.`

#### Scenario: Plan without a status key
- **WHEN** the only plan in `docs/plans/` has frontmatter with `date:` but no `status:`
- **THEN** no plan line appears

#### Scenario: Untracked plan
- **WHEN** an in-flight plan in `docs/plans/` is untracked
- **THEN** the start nudge contains `Uncommitted living plan(s):` naming it

#### Scenario: Repo declares its own plans folder
- **WHEN** the repo's `.claude/settings.json` `env` block sets `CADENCE_PLANS_DIR` to `Meta/docs/plans` and one blocked plan is there
- **THEN** the start nudge contains `1 in-flight plan in Meta/docs/plans/ (1 blocked)` and no `docs/plans/` folder is created
