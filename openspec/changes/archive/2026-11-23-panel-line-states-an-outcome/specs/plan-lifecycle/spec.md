## MODIFIED Requirements

### Requirement: Plan-shape gate blocks only on the Panel line
On PreToolUse for a top-level `ExitPlanMode`, `session lint-plan-shape` SHALL block (exit 2) when the plan has no settled `Panel:` line (Requirement: Panel line states an outcome). The block reason MUST say the first `Panel:` line is the one judged and name `Panel: <seats> ran — N findings, M folded in, K declined` and `Panel: none — <reason>`; it MUST NOT list other stanzas or carry the presentation reminders. Every other shape MUST be allowed.

#### Scenario: Harness-template plan
- **WHEN** a top-level session calls `ExitPlanMode` with a plan of Context, Changes, and Verification sections and no `Panel:` line
- **THEN** the hook exits 2 with a reason naming `Panel: none — <reason>` and `replace it, don't add another`

#### Scenario: Trivial escape reason
- **WHEN** the plan's only panel line is `Panel: none — n/a`
- **THEN** the hook blocks

#### Scenario: Dash variants accepted
- **WHEN** the plan carries `Panel: none -- docs-only change` and every other stanza
- **THEN** the hook does not block

### Requirement: Plan-shape gate nudges and reminders
Both allow outcomes of `session lint-plan-shape` SHALL carry the reminders `Make sure all your subagents have stopped.` and `Did your operator ask to see the plan?`. A settled plan with other stanzas missing MUST draw a nudge naming them; a template-shaped plan MUST draw one with only the reminders. `## Workarounds` or `## Concessions` SHALL satisfy the workarounds stanza. The gate MUST render only static stanza names, never plan text.

#### Scenario: Template-shaped plan is allowed
- **WHEN** the plan carries `Panel: none — docs-only change, no seat warranted` and every other stanza
- **THEN** the hook exits 0 with a `plan-shape gate:` nudge holding only the two reminders

#### Scenario: Settled panel, missing tasks
- **WHEN** the plan has a settled `Panel:` line but no `## Tasks` section
- **THEN** the hook exits 0 with a nudge naming `a ## Tasks section` as advisory

#### Scenario: Settled panel, no workarounds section
- **WHEN** the plan has every stanza but has neither a `## Workarounds` nor a `## Concessions` heading
- **THEN** the hook exits 0 with a nudge naming `a ## Workarounds section`

## ADDED Requirements

### Requirement: Panel line states an outcome
The first `Panel:` line at line start outside fences, quotes, comments and frontmatter SHALL be judged, with `**Panel:**`, `__Panel:__` and `**Panel: …**` read as `Panel:`. Its value is unsettled when it is trivial (empty, punctuation only, `n/a`, `none`, `tbd`), starts with `pending`, `tbd` or `todo`, carries a template placeholder (`<…>`, `[<`, or wrapped in `[…]`), or is `none`, `skipped` or `skip` with a trivial reason. Any other value MUST settle.

#### Scenario: Pending panel line
- **WHEN** the plan's first panel line is `**Panel: pending**`
- **THEN** the line is unsettled and `lint-plan-shape` blocks

#### Scenario: Unfilled template line
- **WHEN** the plan's first panel line is `Panel: none — [<reason — e.g. x>]`
- **THEN** the line is unsettled and `lint-plan-shape` blocks

#### Scenario: Skipped with a reason
- **WHEN** the plan carries `Panel: skipped — docs-only`
- **THEN** the line settles

#### Scenario: Panel stated without the ran form
- **WHEN** the plan carries `Panel: security-posture-reviewer — 2 HIGH, all folded`
- **THEN** the line settles
