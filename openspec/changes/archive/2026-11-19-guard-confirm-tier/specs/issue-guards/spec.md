## ADDED Requirements

### Requirement: Confirmed HELD close
`guard-held-close`'s HELD-ledger block SHALL be in the confirm tier, keyed by the set of held entries the close would hit. A close of other held entries MUST NOT pair with the blocked attempt. The block for closes across more than 16 directories MUST stay a plain block.

#### Scenario: Retry closes the same held issue
- **WHEN** the ledger holds `cameronsjo/cadence-ecosystem#354`, `gh issue close 354 -R cameronsjo/cadence-ecosystem` blocks in session S1, and S1 retries it with `--comment 'released'`
- **THEN** the retry is allowed with a `confirmed` bypass row

#### Scenario: Another held issue
- **WHEN** a close of `cameronsjo/cadence-ecosystem#354` blocks and the next attempt closes held `cameronsjo/cadence#107`
- **THEN** the second attempt blocks
