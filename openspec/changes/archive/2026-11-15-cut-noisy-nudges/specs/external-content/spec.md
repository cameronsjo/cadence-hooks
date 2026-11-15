## ADDED Requirements

### Requirement: Overshare audit fires once per agent per target
`warn-overshare` SHALL nudge at most once per session, per agent (`agent_id`), per trigger (Bash, or a field-report Write/Edit), per target. The target of a Write or Edit is the git root above the edited file's directory. The target of a Bash command is the git root above `cwd`, or a literal `gh -R owner/repo` slug. Later matching calls for a target already reminded MUST exit 0 with no output.

#### Scenario: Second push in the same session
- **WHEN** a Bash call runs `git push origin main` after an earlier call by the same agent in the same session and repo already nudged
- **THEN** the hook exits 0 with no output

#### Scenario: Another repo or agent
- **WHEN** the same session then pushes from a different repo, or a subagent with its own `agent_id` pushes from the same repo
- **THEN** the hook nudges again

#### Scenario: A post to another repo by -R
- **WHEN** the same agent, after a nudge in repo A, runs `gh issue create -R owner/public …` from A
- **THEN** the hook nudges once for `owner/public`

### Requirement: Overshare audit nudges every time for an unresolved target
A Bash command that moves its work dir with a leading `cd`, runs `git` with a global option such as `-C`, names a `gh` repo that is not one literal slug, or posts with `tea` MUST nudge every time, since no marker key names its target exactly.

#### Scenario: A commit in another directory
- **WHEN** the same agent runs `git -C ../b commit -m x` twice
- **THEN** the hook nudges both times
