## MODIFIED Requirements

### Requirement: Confirmed HELD close
`guard-held-close`'s HELD-ledger block SHALL be in the confirm tier, keyed by the set of held entries the close would hit beside the whole command, normalized for spaces and tabs. A retry of the same command SHALL pair with the blocked attempt; a close of other held entries, or the same close under an earlier `export GH_REPO=…` or any other difference, MUST NOT. The block for closes across more than 16 directories MUST stay a plain block.

#### Scenario: Retry closes the same held issue
- **WHEN** the ledger holds `cameronsjo/cadence-ecosystem#354`, `gh issue close 354 -R cameronsjo/cadence-ecosystem` blocks in session S1, and S1 runs the same command again
- **THEN** the retry is allowed with a `confirmed` bypass row

#### Scenario: Another held issue
- **WHEN** a close of `cameronsjo/cadence-ecosystem#354` blocks and the next attempt closes held `cameronsjo/cadence#107`
- **THEN** the second attempt blocks

#### Scenario: An earlier export moves the close
- **WHEN** `gh issue close 354 -R cameronsjo/cadence-ecosystem` blocks and the next attempt is `export GH_REPO=cameronsjo/free; gh issue close 354 -R cameronsjo/cadence-ecosystem`
- **THEN** the second attempt blocks with the `Are you sure?` line
