## ADDED Requirements

### Requirement: Confirmed vault listing
`guard-op-vault-scan` SHALL be in the confirm tier, keyed by the scans it read: `op item list` or `op vault list`, each with the `--vault` value it names. A retry that differs only outside those (another pipe, `--vault=X` for `--vault X`) SHALL pair with the blocked attempt; a listing of another vault MUST NOT.

#### Scenario: Retry with another pipe
- **WHEN** `op item list` blocks in session S1 and S1 then runs `op item list | grep api`
- **THEN** the second command is allowed with a `confirmed` bypass row

#### Scenario: Another vault
- **WHEN** `op item list --vault Private` blocks and the next attempt is `op item list --vault Work`
- **THEN** the second command blocks
